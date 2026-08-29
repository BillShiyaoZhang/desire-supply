"""Controlled deployment-only bootstrap for synthetic internal OIDC identities.

The program accepts only a byte-exact, digest-pinned manifest containing opaque
UUIDs and keyed digests.  It temporarily authenticates as the dedicated
``iam_sandbox_bootstrap`` database role, invokes one reviewed SECURITY DEFINER
program, and removes that role's credential and sessions before returning.
It never sends SQL that inserts IAM domain rows and it is not imported by the
online API composition.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sys
from typing import Any, Callable, Dict, Mapping, NoReturn, Optional, Sequence, TextIO, Tuple
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo
from psycopg.pq import TransactionStatus

from desire_platform.internal_pilot.deployment_config import (
    DEPLOYMENT_CONFIG_POINTER_ENV,
    InternalSandboxDeploymentConfiguration,
    _read_regular_config_file,
    load_internal_sandbox_deployment_config_pointer,
)
from desire_platform.identity_access.adapters.postgres.migrations import (
    IAM_SCHEMA_HEAD_VERSION,
)

from .migrations import (
    _MIGRATION_ROLES,
    _acquire_provisioning_lock,
    _admin_connection,
    _assert_admin_preflight,
    _release_provisioning_lock,
    DeploymentMigrationConfigurationError,
    DeploymentMigrationError,
    DeploymentMigrationSettings,
    load_settings,
)


BOOTSTRAP_ROLE = "iam_sandbox_bootstrap"
IDENTITY_BOOTSTRAP_MANIFEST_FILE_ENV = (
    "DESIRE_INTERNAL_SANDBOX_IDENTITY_BOOTSTRAP_MANIFEST_FILE"
)
IDENTITY_BOOTSTRAP_MANIFEST_SHA256_ENV = (
    "DESIRE_INTERNAL_SANDBOX_IDENTITY_BOOTSTRAP_MANIFEST_SHA256"
)
IDENTITY_BOOTSTRAP_SCHEMA = "desire-internal-sandbox-identity-bootstrap-v1"
IDENTITY_BOOTSTRAP_SCOPE = "INTERNAL_SANDBOX"
_PROGRAM = "iam_api.manage_internal_sandbox_identity_bootstrap_v6"
_APPLICATION_NAME = "desire-internal-sandbox-identity-bootstrap"
_SESSION_DRAIN_WAIT_MILLISECONDS = 5_000
_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_ACCOUNT_CODE = re.compile(r"[a-z][a-z0-9_]{2,31}\Z")
_SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ROOT_KEYS = frozenset(
    (
        "accounts",
        "bootstrap_id",
        "environment_id",
        "issuer",
        "policy",
        "previous_manifest_sha256",
        "revision",
        "schema_name",
    )
)
_ACCOUNT_KEYS = frozenset(
    (
        "account_code",
        "activation_event_id",
        "contact_point",
        "creator_grant",
        "demand_owner_grant",
        "external_identity",
        "organization_grant",
        "platform_duty_grants",
        "revocation_event_id",
        "user_id",
    )
)
_EXTERNAL_IDENTITY_KEYS = frozenset(
    ("id", "subject_digest_key_id", "subject_digest_sha256")
)
_CONTACT_KEYS = frozenset(
    ("id", "recipient_binding_digest_key_id", "recipient_binding_digest_sha256")
)
_CREATOR_KEYS = frozenset(("grant_id", "invitation_id"))
_DEMAND_OWNER_KEYS = frozenset(
    ("grant_id", "invitation_id", "membership_id", "organization_id")
)
_ORGANIZATION_GRANT_KEYS = frozenset(
    (
        "grant_id",
        "invitation_id",
        "membership_id",
        "organization_id",
        "role_code",
    )
)
_DUTY_KEYS = frozenset(("duty_code", "grant_id"))
_POLICY_KEYS = frozenset(
    (
        "creator_bundle_id",
        "demand_owner_bundle_id",
        "document_id",
        "org_admin_bundle_id",
    )
)
_BOOTSTRAP_DUTIES = frozenset(
    (
        "ACCESS_ADMIN",
        "APPEAL_REVIEWER",
        "FINANCE_OPERATOR",
        "OPERATIONS_REVIEWER",
        "TRUST_OFFICER",
    )
)
_INDEPENDENT_ROLE_SHAPES = {
    "access_admin_01": ((), ("ACCESS_ADMIN",), "ACCESS_ADMIN"),
    "appeal_reviewer_01": ((), ("APPEAL_REVIEWER",), "APPEAL_REVIEWER"),
    "creator_01": ((), (), "CREATOR"),
    "demand_owner_01": (("DEMAND_OWNER",), (), "DEMAND_OWNER"),
    "finance_operator_01": (
        (),
        ("FINANCE_OPERATOR",),
        "FINANCE_OPERATOR",
    ),
    "finance_operator_02": (
        (),
        ("FINANCE_OPERATOR",),
        "FINANCE_OPERATOR",
    ),
    "operations_reviewer_01": (
        (),
        ("OPERATIONS_REVIEWER",),
        "OPERATIONS_REVIEWER",
    ),
    "org_admin_01": (("ORG_ADMIN",), (), "ORG_ADMIN"),
    "trust_officer_01": ((), ("TRUST_OFFICER",), "TRUST_OFFICER"),
    "trust_officer_02": ((), ("TRUST_OFFICER",), "TRUST_OFFICER"),
}
_ALLOWED_DESIRE_ENVIRONMENT = frozenset(
    (
        "DESIRE_DEPLOYMENT_MODE",
        "DESIRE_EXTERNAL_PARTICIPANTS_ENABLED",
        "DESIRE_DATABASE_HOST",
        "DESIRE_DATABASE_NAME",
        "DESIRE_DATABASE_ADMIN_USER",
        "DESIRE_DATABASE_PASSWORD_FILE",
        DEPLOYMENT_CONFIG_POINTER_ENV,
        IDENTITY_BOOTSTRAP_MANIFEST_FILE_ENV,
        IDENTITY_BOOTSTRAP_MANIFEST_SHA256_ENV,
    )
)


class IdentityBootstrapAction(str, Enum):
    APPLY = "APPLY"
    VERIFY = "VERIFY"
    REVOKE_ACCESS = "REVOKE_ACCESS"


class IdentityBootstrapOutcome(str, Enum):
    APPLIED = "APPLIED"
    ROTATED = "ROTATED"
    REPLAYED = "REPLAYED"
    VERIFIED = "VERIFIED"
    REVOKED = "REVOKED"
    ALREADY_REVOKED = "ALREADY_REVOKED"


class IdentityBootstrapError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class IdentityBootstrapConfigurationError(IdentityBootstrapError):
    pass


@dataclass(frozen=True)
class IdentityBootstrapAccount:
    account_code: str
    user_id: UUID
    subject_digest: bytes
    subject_digest_key_id: str
    recipient_binding_digest: bytes
    recipient_binding_digest_key_id: str
    duty_codes: Tuple[str, ...]
    has_demand_owner: bool
    organization_id: Optional[UUID]
    organization_role_codes: Tuple[str, ...]
    effective_role_code: str


@dataclass(frozen=True, repr=False)
class InternalSandboxIdentityManifest:
    canonical_bytes: bytes
    manifest_sha256: bytes
    bootstrap_id: UUID
    revision: int
    previous_manifest_sha256: Optional[bytes]
    issuer: str
    accounts: Tuple[IdentityBootstrapAccount, ...]

    def __repr__(self) -> str:
        return (
            "InternalSandboxIdentityManifest("
            "bootstrap_id=%r, revision=%r, account_count=%r, "
            "manifest_sha256=%r)"
            % (
                self.bootstrap_id,
                self.revision,
                len(self.accounts),
                self.manifest_sha256.hex(),
            )
        )


@dataclass(frozen=True)
class IdentityBootstrapReport:
    action: IdentityBootstrapAction
    outcome: IdentityBootstrapOutcome
    bootstrap_id: UUID
    revision: int
    account_count: int
    manifest_sha256: str


@dataclass(frozen=True)
class IdentityBootstrapInputs:
    settings: DeploymentMigrationSettings
    deployment: InternalSandboxDeploymentConfiguration
    manifest: InternalSandboxIdentityManifest


def parse_internal_sandbox_identity_manifest(
    raw: bytes,
    *,
    expected_sha256: str,
    expected_issuer: Optional[str] = None,
) -> InternalSandboxIdentityManifest:
    """Parse one restricted-canonical, digest-only bootstrap manifest."""

    try:
        if type(raw) is not bytes or not 1 <= len(raw) <= 131_072:
            _configuration_error()
        if not isinstance(expected_sha256, str) or not _SHA256_HEX.fullmatch(
            expected_sha256
        ):
            _configuration_error()
        actual_digest = hashlib.sha256(raw).digest()
        if not hmac.compare_digest(actual_digest.hex(), expected_sha256):
            raise IdentityBootstrapConfigurationError(
                "IDENTITY_BOOTSTRAP_MANIFEST_DIGEST_MISMATCH"
            )
        document = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
        if type(document) is not dict or frozenset(document) != _ROOT_KEYS:
            _configuration_error()
        canonical = json.dumps(
            document,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        if not hmac.compare_digest(raw, canonical):
            raise IdentityBootstrapConfigurationError(
                "IDENTITY_BOOTSTRAP_MANIFEST_NOT_CANONICAL"
            )
        if (
            document["schema_name"] != IDENTITY_BOOTSTRAP_SCHEMA
            or document["environment_id"] != "internal-sandbox"
            or type(document["revision"]) is not int
            or not 1 <= document["revision"] <= 2_147_483_647
        ):
            _configuration_error()
        revision = document["revision"]
        previous = document["previous_manifest_sha256"]
        if revision == 1:
            if previous is not None:
                _configuration_error()
            previous_digest = None
        else:
            previous_digest = _digest(previous)
        issuer = _issuer(document["issuer"])
        if expected_issuer is not None and issuer != expected_issuer:
            raise IdentityBootstrapConfigurationError(
                "IDENTITY_BOOTSTRAP_ISSUER_MISMATCH"
            )
        bootstrap_id = _uuid(document["bootstrap_id"])
        policy = _object(document["policy"], _POLICY_KEYS)
        policy_ids = tuple(_uuid(policy[key]) for key in sorted(_POLICY_KEYS))
        accounts_value = document["accounts"]
        if type(accounts_value) is not list or len(accounts_value) != 10:
            _configuration_error()
        accounts = []
        all_ids = [bootstrap_id]
        all_ids.extend(policy_ids)
        account_codes = set()
        identity_keys = set()
        contact_keys = set()
        demand_owner_count = 0
        organization_ids = []
        organization_role_codes = set()
        duties_seen = set()
        for value in accounts_value:
            account, identifiers = _parse_account(value)
            if account.account_code in account_codes:
                _configuration_error()
            account_codes.add(account.account_code)
            identity_key = (issuer, account.subject_digest)
            if identity_key in identity_keys:
                raise IdentityBootstrapConfigurationError(
                    "IDENTITY_BOOTSTRAP_SUBJECT_DIGEST_COLLISION"
                )
            identity_keys.add(identity_key)
            contact_key = (
                account.recipient_binding_digest_key_id,
                account.recipient_binding_digest,
            )
            if contact_key in contact_keys:
                raise IdentityBootstrapConfigurationError(
                    "IDENTITY_BOOTSTRAP_RECIPIENT_DIGEST_COLLISION"
                )
            contact_keys.add(contact_key)
            demand_owner_count += int(account.has_demand_owner)
            if account.organization_id is not None:
                organization_ids.append(account.organization_id)
                organization_role_codes.update(account.organization_role_codes)
            duties_seen.update(account.duty_codes)
            accounts.append(account)
            all_ids.extend(identifiers)
        if (
            tuple(account.account_code for account in accounts)
            != tuple(sorted(_INDEPENDENT_ROLE_SHAPES))
            or demand_owner_count != 1
            or len(organization_ids) != 2
            or len(set(organization_ids)) != 1
            or organization_role_codes != {"DEMAND_OWNER", "ORG_ADMIN"}
            or duties_seen != _BOOTSTRAP_DUTIES
        ):
            _configuration_error()
        all_ids.append(organization_ids[0])
        if len(all_ids) != len(set(all_ids)):
            raise IdentityBootstrapConfigurationError(
                "IDENTITY_BOOTSTRAP_IDENTIFIER_COLLISION"
            )
        return InternalSandboxIdentityManifest(
            canonical_bytes=raw,
            manifest_sha256=actual_digest,
            bootstrap_id=bootstrap_id,
            revision=revision,
            previous_manifest_sha256=previous_digest,
            issuer=issuer,
            accounts=tuple(accounts),
        )
    except IdentityBootstrapConfigurationError:
        raise
    except (KeyError, TypeError, ValueError, UnicodeError):
        _configuration_error()


def load_identity_bootstrap_inputs(
    environment: Optional[Mapping[str, str]] = None,
    *,
    allowed_secret_root: Path = Path("/run/secrets"),
    read_bytes: Optional[Callable[[str], bytes]] = None,
) -> IdentityBootstrapInputs:
    values = os.environ if environment is None else environment
    try:
        if not isinstance(values, Mapping):
            _configuration_error()
        desire_keys = frozenset(
            key
            for key in values
            if isinstance(key, str) and key.startswith("DESIRE_")
        )
        if desire_keys != _ALLOWED_DESIRE_ENVIRONMENT:
            _configuration_error()
        settings = load_settings(values, allowed_secret_root=allowed_secret_root)
        reader = _read_regular_config_file if read_bytes is None else read_bytes
        deployment = load_internal_sandbox_deployment_config_pointer(
            environment={
                DEPLOYMENT_CONFIG_POINTER_ENV: values[DEPLOYMENT_CONFIG_POINTER_ENV]
            },
            read_bytes=reader,
        )
        if (
            deployment.postgres.host != settings.host
            or deployment.postgres.port != settings.port
            or deployment.postgres.database != settings.database
            or deployment.postgres.transport_security
            != "TRUSTED_CONTAINER_NETWORK"
        ):
            _configuration_error()
        manifest_path = values[IDENTITY_BOOTSTRAP_MANIFEST_FILE_ENV]
        if not isinstance(manifest_path, str) or not manifest_path.startswith("/"):
            _configuration_error()
        raw = reader(manifest_path)
        manifest = parse_internal_sandbox_identity_manifest(
            raw,
            expected_sha256=values[IDENTITY_BOOTSTRAP_MANIFEST_SHA256_ENV],
            expected_issuer=deployment.oidc.issuer,
        )
        return IdentityBootstrapInputs(
            settings=settings,
            deployment=deployment,
            manifest=manifest,
        )
    except IdentityBootstrapConfigurationError:
        raise
    except (DeploymentMigrationConfigurationError, KeyError, OSError, TypeError, ValueError):
        _configuration_error()


def apply_internal_sandbox_identity_bootstrap(
    *,
    settings: DeploymentMigrationSettings,
    manifest: InternalSandboxIdentityManifest,
    system_actor_id: UUID,
    now: datetime,
    dbapi: Any = psycopg,
    password_factory: Callable[[], str] = lambda: secrets.token_urlsafe(48),
) -> IdentityBootstrapReport:
    return _execute(
        action=IdentityBootstrapAction.APPLY,
        settings=settings,
        manifest=manifest,
        system_actor_id=system_actor_id,
        now=now,
        dbapi=dbapi,
        password_factory=password_factory,
    )


def verify_internal_sandbox_identity_bootstrap(
    *,
    settings: DeploymentMigrationSettings,
    manifest: InternalSandboxIdentityManifest,
    system_actor_id: UUID,
    now: datetime,
    dbapi: Any = psycopg,
    password_factory: Callable[[], str] = lambda: secrets.token_urlsafe(48),
) -> IdentityBootstrapReport:
    return _execute(
        action=IdentityBootstrapAction.VERIFY,
        settings=settings,
        manifest=manifest,
        system_actor_id=system_actor_id,
        now=now,
        dbapi=dbapi,
        password_factory=password_factory,
    )


def revoke_internal_sandbox_identity_bootstrap_access(
    *,
    settings: DeploymentMigrationSettings,
    manifest: InternalSandboxIdentityManifest,
    system_actor_id: UUID,
    now: datetime,
    dbapi: Any = psycopg,
    password_factory: Callable[[], str] = lambda: secrets.token_urlsafe(48),
) -> IdentityBootstrapReport:
    return _execute(
        action=IdentityBootstrapAction.REVOKE_ACCESS,
        settings=settings,
        manifest=manifest,
        system_actor_id=system_actor_id,
        now=now,
        dbapi=dbapi,
        password_factory=password_factory,
    )


def _execute(
    *,
    action: IdentityBootstrapAction,
    settings: DeploymentMigrationSettings,
    manifest: InternalSandboxIdentityManifest,
    system_actor_id: UUID,
    now: datetime,
    dbapi: Any,
    password_factory: Callable[[], str],
) -> IdentityBootstrapReport:
    try:
        _validate_execution_inputs(settings, manifest, system_actor_id, now)
        password = password_factory()
        if (
            not isinstance(password, str)
            or not 32 <= len(password.encode("utf-8")) <= 4096
            or any(character in password for character in ("\x00", "\r", "\n"))
            or hmac.compare_digest(password, settings.admin_password)
        ):
            raise IdentityBootstrapConfigurationError(
                "IDENTITY_BOOTSTRAP_PASSWORD_FACTORY_INVALID"
            )
        command_id = uuid4()
        receipt_id = uuid4()
        audit_event_id = uuid4()
        correlation_id = uuid4()
        trace_id = uuid4()
        with _admin_connection(settings, dbapi) as admin:
            _assert_admin_preflight(admin, settings)
            _acquire_provisioning_lock(admin)
            try:
                _verify_iam_catalog(admin)
                _assert_bootstrap_role_contract(
                    admin,
                    require_password_clear=False,
                )
                # Recover a prior crash after temporary credential installation:
                # disable the old password and drain every stale bootstrap
                # backend before installing this invocation's credential.
                _drain_and_clear_bootstrap_role(admin)
                _assert_bootstrap_role_contract(
                    admin,
                    require_password_clear=True,
                )
                _install_bootstrap_password(admin, password)
                try:
                    row = _invoke_fixed_program(
                        settings=settings,
                        password=password,
                        action=action,
                        manifest=manifest,
                        system_actor_id=system_actor_id,
                        command_id=command_id,
                        receipt_id=receipt_id,
                        audit_event_id=audit_event_id,
                        correlation_id=correlation_id,
                        trace_id=trace_id,
                        dbapi=dbapi,
                    )
                finally:
                    _drain_and_clear_bootstrap_role(admin)
                _assert_bootstrap_role_contract(
                    admin,
                    require_password_clear=True,
                )
            finally:
                _release_provisioning_lock(admin)
        try:
            outcome = IdentityBootstrapOutcome(row[0])
        except (IndexError, TypeError, ValueError):
            raise IdentityBootstrapError("IDENTITY_BOOTSTRAP_RESULT_INVALID") from None
        if row[1:] != (manifest.revision, len(manifest.accounts)):
            raise IdentityBootstrapError("IDENTITY_BOOTSTRAP_RESULT_INVALID")
        return IdentityBootstrapReport(
            action=action,
            outcome=outcome,
            bootstrap_id=manifest.bootstrap_id,
            revision=manifest.revision,
            account_count=len(manifest.accounts),
            manifest_sha256=manifest.manifest_sha256.hex(),
        )
    except IdentityBootstrapError:
        raise
    except DeploymentMigrationError as error:
        raise IdentityBootstrapError(error.code) from None
    except BaseException:
        raise IdentityBootstrapError("IDENTITY_BOOTSTRAP_FAILED") from None


def _invoke_fixed_program(
    *,
    settings: DeploymentMigrationSettings,
    password: str,
    action: IdentityBootstrapAction,
    manifest: InternalSandboxIdentityManifest,
    system_actor_id: UUID,
    command_id: UUID,
    receipt_id: UUID,
    audit_event_id: UUID,
    correlation_id: UUID,
    trace_id: UUID,
    dbapi: Any,
) -> Tuple[Any, ...]:
    connection = dbapi.connect(
        make_conninfo(
            host=settings.host,
            port=settings.port,
            dbname=settings.database,
            user=BOOTSTRAP_ROLE,
            password=password,
            connect_timeout=5,
        ),
        autocommit=False,
        application_name=_APPLICATION_NAME,
        connect_timeout=5,
    )
    try:
        facts = connection.execute(
            "SELECT session_user,current_user,current_database(),"
            "current_setting('server_version_num')::integer/10000"
        ).fetchone()
        if facts != (BOOTSTRAP_ROLE, BOOTSTRAP_ROLE, settings.database, 18):
            raise IdentityBootstrapError("IDENTITY_BOOTSTRAP_ROLE_PROOF_FAILED")
        connection.execute(
            "SELECT set_config('app.scope_kind',%s,true),"
            "set_config('app.operation',%s,true),"
            "set_config('app.command_id',%s,true),"
            "set_config('app.manifest_sha256',%s,true)",
            (
                IDENTITY_BOOTSTRAP_SCOPE,
                action.value,
                str(command_id),
                manifest.manifest_sha256.hex(),
            ),
        )
        row = connection.execute(
            "SELECT outcome,revision,account_count FROM " + _PROGRAM + "("
            "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                action.value,
                manifest.canonical_bytes,
                manifest.manifest_sha256,
                command_id,
                receipt_id,
                audit_event_id,
                system_actor_id,
                correlation_id,
                trace_id,
                manifest.bootstrap_id,
            ),
        ).fetchone()
        if row is None:
            raise IdentityBootstrapError("IDENTITY_BOOTSTRAP_RESULT_INVALID")
        connection.commit()
        return tuple(row)
    except BaseException:
        _rollback(connection)
        raise
    finally:
        connection.close()


def _assert_bootstrap_role_contract(
    connection: Any,
    *,
    require_password_clear: bool,
) -> None:
    role = connection.execute(
        "SELECT rolcanlogin,rolinherit,rolsuper,rolcreatedb,rolcreaterole,"
        "rolbypassrls FROM pg_catalog.pg_roles WHERE rolname=%s",
        (BOOTSTRAP_ROLE,),
    ).fetchone()
    membership = connection.execute(
        "SELECT count(*) FROM pg_catalog.pg_auth_members AS membership "
        "JOIN pg_catalog.pg_roles AS member ON member.oid=membership.member "
        "WHERE member.rolname=%s",
        (BOOTSTRAP_ROLE,),
    ).fetchone()
    password = connection.execute(
        "SELECT rolpassword FROM pg_catalog.pg_authid WHERE rolname=%s",
        (BOOTSTRAP_ROLE,),
    ).fetchone()
    migration_passwords = connection.execute(
        "SELECT count(*) FROM pg_catalog.pg_authid "
        "WHERE rolname = ANY(%s) AND rolpassword IS NOT NULL",
        (list(_MIGRATION_ROLES),),
    ).fetchone()
    if (
        role != (True, False, False, False, False, False)
        or membership != (0,)
        or (
            require_password_clear
            and password != (None,)
        )
        or migration_passwords != (0,)
    ):
        raise IdentityBootstrapError("IDENTITY_BOOTSTRAP_ROLE_CONTRACT_MISMATCH")


def _verify_iam_catalog(connection: Any) -> None:
    row = connection.execute(
        "SELECT current_schema_version,schema_head_version,"
        "min_app_compatible_version,max_app_compatible_version "
        "FROM infra.iam_schema_compatibility"
    ).fetchone()
    if row != (IAM_SCHEMA_HEAD_VERSION,) * 4:
        raise IdentityBootstrapError("IDENTITY_BOOTSTRAP_SCHEMA_NOT_READY")


def _install_bootstrap_password(
    connection: Any,
    password: str,
) -> None:
    change_password = getattr(getattr(connection, "pgconn", None), "change_password", None)
    if not callable(change_password):
        raise IdentityBootstrapError("IDENTITY_BOOTSTRAP_ADAPTER_UNAVAILABLE")
    connection.execute("BEGIN")
    transaction_open = True
    try:
        connection.execute("SET LOCAL password_encryption TO 'scram-sha-256'")
        database_now = connection.execute(
            "SELECT transaction_timestamp()"
        ).fetchone()
        if (
            database_now is None
            or len(database_now) != 1
            or not isinstance(database_now[0], datetime)
            or database_now[0].tzinfo is None
        ):
            raise IdentityBootstrapError(
                "IDENTITY_BOOTSTRAP_DATABASE_CLOCK_INVALID"
            )
        change_password(BOOTSTRAP_ROLE.encode("ascii"), password.encode("utf-8"))
        connection.execute(
            sql.SQL("ALTER ROLE {} VALID UNTIL {}").format(
                sql.Identifier(BOOTSTRAP_ROLE),
                sql.Literal(
                    (database_now[0] + timedelta(minutes=5)).strftime(
                        "%Y-%m-%d %H:%M:%S+00"
                    )
                ),
            )
        )
        connection.execute("COMMIT")
        transaction_open = False
    finally:
        if transaction_open:
            _rollback(connection)


def _drain_and_clear_bootstrap_role(connection: Any) -> None:
    error = None
    try:
        for _attempt in range(3):
            rows = connection.execute(
                "SELECT pid FROM pg_catalog.pg_stat_activity "
                "WHERE usename=%s AND pid<>pg_catalog.pg_backend_pid() ORDER BY pid",
                (BOOTSTRAP_ROLE,),
            ).fetchall()
            if not rows:
                break
            for (pid,) in rows:
                if connection.execute(
                    "SELECT pg_catalog.pg_terminate_backend(%s,%s)",
                    (pid, _SESSION_DRAIN_WAIT_MILLISECONDS),
                ).fetchone() != (True,):
                    raise IdentityBootstrapError(
                        "IDENTITY_BOOTSTRAP_SESSION_DRAIN_FAILED"
                    )
        else:
            raise IdentityBootstrapError("IDENTITY_BOOTSTRAP_SESSION_DRAIN_FAILED")
    except BaseException as caught:
        error = caught
    try:
        connection.execute(
            sql.SQL("ALTER ROLE {} PASSWORD NULL VALID UNTIL 'epoch'").format(
                sql.Identifier(BOOTSTRAP_ROLE)
            )
        )
    except BaseException:
        if error is None:
            error = IdentityBootstrapError("IDENTITY_BOOTSTRAP_CREDENTIAL_CLEAR_FAILED")
    if error is not None:
        raise error


def _validate_execution_inputs(
    settings: Any,
    manifest: Any,
    system_actor_id: Any,
    now: Any,
) -> None:
    if (
        not isinstance(settings, DeploymentMigrationSettings)
        or not isinstance(manifest, InternalSandboxIdentityManifest)
        or not isinstance(system_actor_id, UUID)
        or system_actor_id.int == 0
        or not isinstance(now, datetime)
        or now.tzinfo is None
        or now.utcoffset() != timedelta(0)
    ):
        _configuration_error()


def _parse_account(value: Any) -> Tuple[IdentityBootstrapAccount, Tuple[UUID, ...]]:
    account = _object(value, _ACCOUNT_KEYS)
    account_code = account["account_code"]
    if not isinstance(account_code, str) or not _ACCOUNT_CODE.fullmatch(account_code):
        _configuration_error()
    expected_shape = _INDEPENDENT_ROLE_SHAPES.get(account_code)
    if expected_shape is None:
        _configuration_error()
    user_id = _uuid(account["user_id"])
    external = _object(account["external_identity"], _EXTERNAL_IDENTITY_KEYS)
    contact = _object(account["contact_point"], _CONTACT_KEYS)
    creator = _object(account["creator_grant"], _CREATOR_KEYS)
    external_id = _uuid(external["id"])
    contact_id = _uuid(contact["id"])
    creator_invitation_id = _uuid(creator["invitation_id"])
    creator_grant_id = _uuid(creator["grant_id"])
    activation_event_id = _uuid(account["activation_event_id"])
    revocation_event_id = _uuid(account["revocation_event_id"])
    identifiers = [
        user_id,
        external_id,
        contact_id,
        creator_invitation_id,
        creator_grant_id,
        activation_event_id,
        revocation_event_id,
    ]
    demand_value = account["demand_owner_grant"]
    organization_value = account["organization_grant"]
    has_demand_owner = demand_value is not None
    organization_id = None
    organization_role_codes = ()
    if has_demand_owner:
        demand = _object(demand_value, _DEMAND_OWNER_KEYS)
        identifiers.extend(
            _uuid(demand[key])
            for key in ("grant_id", "invitation_id", "membership_id")
        )
        organization_id = _uuid(demand["organization_id"])
        organization_role_codes = ("DEMAND_OWNER",)
    if organization_value is not None:
        organization = _object(
            organization_value,
            _ORGANIZATION_GRANT_KEYS,
        )
        if organization["role_code"] != "ORG_ADMIN":
            _configuration_error()
        identifiers.extend(
            _uuid(organization[key])
            for key in ("grant_id", "invitation_id", "membership_id")
        )
        organization_id = _uuid(organization["organization_id"])
        organization_role_codes = ("ORG_ADMIN",)
    duties_value = account["platform_duty_grants"]
    if type(duties_value) is not list or len(duties_value) > 2:
        _configuration_error()
    duty_codes = []
    for duty_value in duties_value:
        duty = _object(duty_value, _DUTY_KEYS)
        if duty["duty_code"] not in _BOOTSTRAP_DUTIES:
            _configuration_error()
        duty_codes.append(duty["duty_code"])
        identifiers.append(_uuid(duty["grant_id"]))
    if len(duty_codes) != len(set(duty_codes)):
        _configuration_error()
    sorted_duties = tuple(sorted(duty_codes))
    if (organization_role_codes, sorted_duties) != expected_shape[:2]:
        _configuration_error()
    return (
        IdentityBootstrapAccount(
            account_code=account_code,
            user_id=user_id,
            subject_digest=_digest(external["subject_digest_sha256"]),
            subject_digest_key_id=_key_id(external["subject_digest_key_id"]),
            recipient_binding_digest=_digest(
                contact["recipient_binding_digest_sha256"]
            ),
            recipient_binding_digest_key_id=_key_id(
                contact["recipient_binding_digest_key_id"]
            ),
            duty_codes=sorted_duties,
            has_demand_owner=has_demand_owner,
            organization_id=organization_id,
            organization_role_codes=organization_role_codes,
            effective_role_code=expected_shape[2],
        ),
        tuple(identifiers),
    )


def _object(value: Any, keys: frozenset[str]) -> Dict[str, Any]:
    if type(value) is not dict or frozenset(value) != keys:
        _configuration_error()
    return value


def _uuid(value: Any) -> UUID:
    if not isinstance(value, str):
        _configuration_error()
    parsed = UUID(value)
    if parsed.int == 0 or str(parsed) != value:
        _configuration_error()
    return parsed


def _digest(value: Any) -> bytes:
    if not isinstance(value, str) or not _SHA256_HEX.fullmatch(value):
        _configuration_error()
    return bytes.fromhex(value)


def _key_id(value: Any) -> str:
    if not isinstance(value, str) or not _KEY_ID.fullmatch(value):
        _configuration_error()
    return value


def _issuer(value: Any) -> str:
    if not isinstance(value, str) or not 12 <= len(value) <= 2048:
        _configuration_error()
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.query
        or value.endswith("/")
    ):
        _configuration_error()
    return value


def _unique_object(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise IdentityBootstrapConfigurationError(
                "IDENTITY_BOOTSTRAP_MANIFEST_DUPLICATE_KEY"
            )
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> NoReturn:
    _configuration_error()


def _configuration_error() -> NoReturn:
    raise IdentityBootstrapConfigurationError(
        "IDENTITY_BOOTSTRAP_CONFIGURATION_INVALID"
    )


def _rollback(connection: Any) -> None:
    try:
        if connection.info.transaction_status != TransactionStatus.IDLE:
            connection.rollback()
    except BaseException:
        pass


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    environment: Optional[Mapping[str, str]] = None,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    dbapi: Any = psycopg,
) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m desire_platform.deployment.identity_bootstrap"
    )
    parser.add_argument("action", choices=("apply", "verify", "revoke-access"))
    arguments = parser.parse_args(argv)
    try:
        inputs = load_identity_bootstrap_inputs(environment)
        common = {
            "settings": inputs.settings,
            "manifest": inputs.manifest,
            "system_actor_id": inputs.deployment.system_actor_id,
            "now": clock(),
            "dbapi": dbapi,
        }
        if arguments.action == "apply":
            report = apply_internal_sandbox_identity_bootstrap(**common)
        elif arguments.action == "verify":
            report = verify_internal_sandbox_identity_bootstrap(**common)
        else:
            report = revoke_internal_sandbox_identity_bootstrap_access(**common)
    except IdentityBootstrapError as error:
        stderr.write(
            json.dumps(
                {"code": error.code, "status": "BLOCKED"},
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        )
        return 78
    except BaseException:
        stderr.write('{"code":"IDENTITY_BOOTSTRAP_FAILED","status":"BLOCKED"}\n')
        return 78
    stdout.write(
        json.dumps(
            {
                "account_count": report.account_count,
                "action": report.action.value,
                "manifest_sha256": report.manifest_sha256,
                "outcome": report.outcome.value,
                "revision": report.revision,
                "status": "IDENTITY_BOOTSTRAP_READY",
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = (
    "BOOTSTRAP_ROLE",
    "IDENTITY_BOOTSTRAP_MANIFEST_FILE_ENV",
    "IDENTITY_BOOTSTRAP_MANIFEST_SHA256_ENV",
    "IDENTITY_BOOTSTRAP_SCHEMA",
    "IdentityBootstrapAccount",
    "IdentityBootstrapAction",
    "IdentityBootstrapConfigurationError",
    "IdentityBootstrapError",
    "IdentityBootstrapInputs",
    "IdentityBootstrapOutcome",
    "IdentityBootstrapReport",
    "InternalSandboxIdentityManifest",
    "apply_internal_sandbox_identity_bootstrap",
    "load_identity_bootstrap_inputs",
    "main",
    "parse_internal_sandbox_identity_manifest",
    "revoke_internal_sandbox_identity_bootstrap_access",
    "verify_internal_sandbox_identity_bootstrap",
)
