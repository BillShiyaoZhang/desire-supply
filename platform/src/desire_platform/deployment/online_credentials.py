"""Install, verify, or revoke the internal-sandbox online PG credentials.

This deployment-only program is deliberately separate from schema migration.
It reads the exact runtime profiles and secret manifest consumed by the API,
changes only the reviewed LOGIN roles, and never makes an online process a
superuser, migration runner, owner, or member of another database role.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
import hmac
import json
import os
from pathlib import Path
import sys
from typing import Any, Callable, Mapping, NoReturn, Optional, Sequence, TextIO, Tuple

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
from desire_platform.internal_pilot.secrets import (
    FileSecretManifestEntry,
    FilesystemSecretProvider,
    parse_file_secret_manifest,
)
from desire_platform.runtime.config import (
    DatabaseProfile,
    RuntimeConfiguration,
    _validate_runtime_configuration_instance,
    parse_runtime_config,
)

from .migrations import (
    _MIGRATION_ROLES,
    _acquire_provisioning_lock,
    _admin_connection,
    _assert_admin_preflight,
    _release_provisioning_lock,
    _verify_catalogs,
    DeploymentMigrationConfigurationError,
    DeploymentMigrationSettings,
    load_settings,
)


@dataclass(frozen=True)
class OnlineRoleCredentialSpec:
    capability_id: str
    online_role: str


ONLINE_ROLE_CREDENTIAL_SPECS: Tuple[OnlineRoleCredentialSpec, ...] = (
    OnlineRoleCredentialSpec("IAM_APP", "iam_app"),
    OnlineRoleCredentialSpec(
        "IAM_SESSION_AUTHENTICATOR",
        "iam_session_authenticator",
    ),
    OnlineRoleCredentialSpec("IAM_ONBOARDING", "iam_onboarding"),
    OnlineRoleCredentialSpec("PROFILE_APP", "profile_app"),
    OnlineRoleCredentialSpec("DEMAND_SELF", "demand_self"),
    OnlineRoleCredentialSpec("DEMAND_REVIEW", "demand_review"),
    OnlineRoleCredentialSpec("DEMAND_FINANCE", "demand_finance"),
    OnlineRoleCredentialSpec("TRUST_SELF", "trust_self"),
    OnlineRoleCredentialSpec("TRUST_OFFICER", "trust_officer"),
    OnlineRoleCredentialSpec("TRUST_APPEAL", "trust_appeal"),
    OnlineRoleCredentialSpec("TRUST_DECISION", "trust_decision"),
    OnlineRoleCredentialSpec("MATCHING_CREATOR", "matching_creator"),
    OnlineRoleCredentialSpec("MATCHING_SELECTOR", "matching_selector"),
    OnlineRoleCredentialSpec("MATCHING_ASSIGNMENT", "matching_assignment"),
    OnlineRoleCredentialSpec("MATCHING_REVIEW", "matching_review"),
    OnlineRoleCredentialSpec("DEMAND_MATCHING", "demand_matching"),
    OnlineRoleCredentialSpec("PROFILE_MATCHER", "profile_matcher"),
    OnlineRoleCredentialSpec("MATCHING_WORKER", "matching_worker"),
    OnlineRoleCredentialSpec("MATCHING_COORDINATOR", "matching_coordinator"),
)

_ONLINE_ROLES = tuple(spec.online_role for spec in ONLINE_ROLE_CREDENTIAL_SPECS)
_CAPABILITY_IDS = tuple(spec.capability_id for spec in ONLINE_ROLE_CREDENTIAL_SPECS)
_MINIMUM_PASSWORD_BYTES = 32
_SCRAM_PREFIX = "SCRAM-SHA-256$"
_VERIFIER_APPLICATION_NAME = "desire-online-credential-verifier"
_ALLOWED_DESIRE_ENVIRONMENT = frozenset(
    (
        "DESIRE_DEPLOYMENT_MODE",
        "DESIRE_EXTERNAL_PARTICIPANTS_ENABLED",
        "DESIRE_DATABASE_HOST",
        "DESIRE_DATABASE_NAME",
        "DESIRE_DATABASE_ADMIN_USER",
        "DESIRE_DATABASE_PASSWORD_FILE",
        DEPLOYMENT_CONFIG_POINTER_ENV,
    )
)


class OnlineRoleCredentialAction(str, Enum):
    RECONCILE = "RECONCILE"
    VERIFY = "VERIFY"
    REVOKE = "REVOKE"


class OnlineRoleCredentialError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class OnlineRoleCredentialConfigurationError(OnlineRoleCredentialError):
    pass


@dataclass(frozen=True)
class OnlineRoleCredentialReport:
    action: OnlineRoleCredentialAction
    online_roles: Tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.action, OnlineRoleCredentialAction)
            or self.online_roles != _ONLINE_ROLES
        ):
            raise ValueError("online credential report is invalid")


@dataclass(frozen=True)
class OnlineRoleCredentialInputs:
    settings: DeploymentMigrationSettings
    deployment: InternalSandboxDeploymentConfiguration
    runtime_config: RuntimeConfiguration
    manifest_entries: Tuple[FileSecretManifestEntry, ...]
    secret_root: Path


def _configuration_error() -> NoReturn:
    raise OnlineRoleCredentialConfigurationError(
        "DEPLOYMENT_ONLINE_CREDENTIAL_CONFIGURATION_INVALID"
    )


def load_online_role_credential_inputs(
    environment: Optional[Mapping[str, str]] = None,
    *,
    allowed_secret_root: Path = Path("/run/secrets"),
    read_bytes: Optional[Callable[[str], bytes]] = None,
) -> OnlineRoleCredentialInputs:
    """Load the one closed Docker configuration without reading secret values."""

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
        if not callable(reader):
            _configuration_error()
        deployment = load_internal_sandbox_deployment_config_pointer(
            environment={
                DEPLOYMENT_CONFIG_POINTER_ENV: values[DEPLOYMENT_CONFIG_POINTER_ENV]
            },
            read_bytes=reader,
        )
        resolved_secret_root = allowed_secret_root.resolve(strict=True)
        if (
            deployment.postgres.host != settings.host
            or deployment.postgres.port != settings.port
            or deployment.postgres.database != settings.database
            or deployment.postgres.transport_security
            != "TRUSTED_CONTAINER_NETWORK"
            or Path(deployment.secret_root).resolve(strict=True)
            != resolved_secret_root
        ):
            _configuration_error()
        runtime_raw = reader(deployment.runtime_config_path)
        manifest_raw = reader(deployment.secret_manifest_path)
        if type(runtime_raw) is not bytes or type(manifest_raw) is not bytes:
            _configuration_error()
        runtime_config = parse_runtime_config(runtime_raw)
        manifest_entries = parse_file_secret_manifest(manifest_raw)
        _validate_profile_and_manifest_contract(runtime_config, manifest_entries)
        return OnlineRoleCredentialInputs(
            settings=settings,
            deployment=deployment,
            runtime_config=runtime_config,
            manifest_entries=manifest_entries,
            secret_root=resolved_secret_root,
        )
    except OnlineRoleCredentialConfigurationError:
        raise
    except (DeploymentMigrationConfigurationError, OSError, TypeError, ValueError):
        _configuration_error()


def reconcile_online_role_credentials(
    *,
    settings: DeploymentMigrationSettings,
    runtime_config: RuntimeConfiguration,
    manifest_entries: Tuple[FileSecretManifestEntry, ...],
    secret_root: Path,
    now: datetime,
    dbapi: Any = psycopg,
) -> OnlineRoleCredentialReport:
    """Atomically install or rotate every reviewed credential and prove fresh login."""

    carriers = []
    try:
        _validate_settings(settings)
        _require_utc(now)
        profiles = _validate_profile_and_manifest_contract(
            runtime_config,
            manifest_entries,
        )
        provider = FilesystemSecretProvider(
            allowed_root=secret_root,
            entries=manifest_entries,
        )
        for profile in profiles:
            carrier = provider.resolve_credential(profile)
            carriers.append(carrier)
            if not carrier.not_before <= now < carrier.not_after:
                raise OnlineRoleCredentialConfigurationError(
                    "DEPLOYMENT_ONLINE_CREDENTIAL_NOT_ACTIVE"
                )
        _validate_distinct_materials(settings, tuple(carriers))
        _reconcile_database(
            settings=settings,
            profiles=profiles,
            carriers=tuple(carriers),
            dbapi=dbapi,
        )
        return OnlineRoleCredentialReport(
            action=OnlineRoleCredentialAction.RECONCILE,
            online_roles=_ONLINE_ROLES,
        )
    except OnlineRoleCredentialError:
        raise
    except BaseException:
        raise OnlineRoleCredentialError(
            "DEPLOYMENT_ONLINE_CREDENTIAL_RECONCILE_FAILED"
        ) from None
    finally:
        for carrier in carriers:
            carrier.destroy()


def verify_online_role_credentials(
    *,
    settings: DeploymentMigrationSettings,
    runtime_config: RuntimeConfiguration,
    manifest_entries: Tuple[FileSecretManifestEntry, ...],
    secret_root: Path,
    now: datetime,
    dbapi: Any = psycopg,
) -> OnlineRoleCredentialReport:
    """Read and prove the desired credentials without changing role state."""

    carriers = []
    try:
        _validate_settings(settings)
        _require_utc(now)
        profiles = _validate_profile_and_manifest_contract(
            runtime_config,
            manifest_entries,
        )
        provider = FilesystemSecretProvider(
            allowed_root=secret_root,
            entries=manifest_entries,
        )
        for profile in profiles:
            carrier = provider.resolve_credential(profile)
            carriers.append(carrier)
            if not carrier.not_before <= now < carrier.not_after:
                raise OnlineRoleCredentialConfigurationError(
                    "DEPLOYMENT_ONLINE_CREDENTIAL_NOT_ACTIVE"
                )
        _validate_distinct_materials(settings, tuple(carriers))
        with _admin_connection(settings, dbapi) as connection:
            _assert_admin_preflight(connection, settings)
            _acquire_provisioning_lock(connection)
            try:
                _verify_catalogs(connection)
                _assert_role_contract(connection, require_migration_passwords_clear=True)
                _assert_installed_password_facts(
                    connection,
                    tuple(carrier.not_after for carrier in carriers),
                )
            finally:
                _release_provisioning_lock(connection)
        _verify_fresh_logins(settings, profiles, tuple(carriers), dbapi)
        return OnlineRoleCredentialReport(
            action=OnlineRoleCredentialAction.VERIFY,
            online_roles=_ONLINE_ROLES,
        )
    except OnlineRoleCredentialError:
        raise
    except BaseException:
        raise OnlineRoleCredentialError(
            "DEPLOYMENT_ONLINE_CREDENTIAL_VERIFICATION_FAILED"
        ) from None
    finally:
        for carrier in carriers:
            carrier.destroy()


def revoke_online_role_credentials(
    *,
    settings: DeploymentMigrationSettings,
    dbapi: Any = psycopg,
) -> OnlineRoleCredentialReport:
    """Atomically clear all reviewed passwords, then terminate their live sessions."""

    try:
        _validate_settings(settings)
        with _admin_connection(settings, dbapi) as connection:
            _assert_admin_preflight(connection, settings)
            _acquire_provisioning_lock(connection)
            try:
                _assert_role_contract(
                    connection,
                    require_migration_passwords_clear=True,
                )
                connection.execute("BEGIN")
                transaction_open = True
                try:
                    for role in _ONLINE_ROLES:
                        connection.execute(
                            sql.SQL(
                                "ALTER ROLE {} PASSWORD NULL VALID UNTIL 'epoch'"
                            ).format(sql.Identifier(role))
                        )
                    connection.execute("COMMIT")
                    transaction_open = False
                finally:
                    if transaction_open:
                        _rollback(connection)
                _terminate_online_sessions(connection)
                _assert_revoked_password_facts(connection)
            finally:
                _release_provisioning_lock(connection)
        return OnlineRoleCredentialReport(
            action=OnlineRoleCredentialAction.REVOKE,
            online_roles=_ONLINE_ROLES,
        )
    except OnlineRoleCredentialError:
        raise
    except BaseException:
        raise OnlineRoleCredentialError(
            "DEPLOYMENT_ONLINE_CREDENTIAL_REVOKE_FAILED"
        ) from None


def _reconcile_database(
    *,
    settings: DeploymentMigrationSettings,
    profiles: Tuple[DatabaseProfile, ...],
    carriers: Tuple[Any, ...],
    dbapi: Any,
) -> None:
    with _admin_connection(settings, dbapi) as connection:
        _assert_admin_preflight(connection, settings)
        _acquire_provisioning_lock(connection)
        try:
            _verify_catalogs(connection)
            _assert_role_contract(connection, require_migration_passwords_clear=True)
            if _desired_credentials_are_current(
                connection=connection,
                settings=settings,
                profiles=profiles,
                carriers=carriers,
                dbapi=dbapi,
            ):
                # ``reconcile`` is an explicitly disruptive deployment action.
                # Always drain old authenticated backends, including on a retry
                # after a commit acknowledgement or prior drain failure.
                _terminate_online_sessions(connection)
                return
            change_password = getattr(
                getattr(connection, "pgconn", None),
                "change_password",
                None,
            )
            if not callable(change_password):
                raise OnlineRoleCredentialError(
                    "DEPLOYMENT_ONLINE_CREDENTIAL_ADAPTER_UNAVAILABLE"
                )
            connection.execute("BEGIN")
            transaction_open = True
            try:
                connection.execute(
                    "SET LOCAL password_encryption TO 'scram-sha-256'"
                )
                for spec, carrier in zip(ONLINE_ROLE_CREDENTIAL_SPECS, carriers):
                    change_password(
                        spec.online_role.encode("ascii"),
                        carrier.material,
                    )
                    connection.execute(
                        sql.SQL("ALTER ROLE {} VALID UNTIL {}").format(
                            sql.Identifier(spec.online_role),
                            sql.Literal(
                                carrier.not_after.strftime(
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
            _terminate_online_sessions(connection)
            _assert_installed_password_facts(
                connection,
                tuple(carrier.not_after for carrier in carriers),
            )
        finally:
            _release_provisioning_lock(connection)
    _verify_fresh_logins(settings, profiles, carriers, dbapi)


def _desired_credentials_are_current(
    *,
    connection: Any,
    settings: DeploymentMigrationSettings,
    profiles: Tuple[DatabaseProfile, ...],
    carriers: Tuple[Any, ...],
    dbapi: Any,
) -> bool:
    rows = connection.execute(
        "SELECT rolname,rolpassword,rolvaliduntil FROM pg_catalog.pg_authid "
        "WHERE rolname = ANY(%s) ORDER BY rolname",
        (list(_ONLINE_ROLES),),
    ).fetchall()
    by_role = {row[0]: row[1:] for row in rows}
    if len(by_role) != len(_ONLINE_ROLES):
        return False
    for spec, carrier in zip(ONLINE_ROLE_CREDENTIAL_SPECS, carriers):
        facts = by_role.get(spec.online_role)
        if (
            facts is None
            or not isinstance(facts[0], str)
            or not facts[0].startswith(_SCRAM_PREFIX)
            or facts[1] != carrier.not_after
        ):
            return False
    try:
        _verify_fresh_logins(settings, profiles, carriers, dbapi)
    except OnlineRoleCredentialError:
        return False
    return True


def _validate_profile_and_manifest_contract(
    runtime_config: RuntimeConfiguration,
    manifest_entries: Tuple[FileSecretManifestEntry, ...],
) -> Tuple[DatabaseProfile, ...]:
    try:
        _validate_runtime_configuration_instance(runtime_config)
    except BaseException:
        _configuration_error()
    if (
        runtime_config.process.kind != "migration"
        or tuple(runtime_config.process.capability_ids) != _CAPABILITY_IDS
        or len(runtime_config.database_profiles) != len(ONLINE_ROLE_CREDENTIAL_SPECS)
    ):
        _configuration_error()
    profiles = tuple(runtime_config.database_profiles)
    for spec, profile in zip(ONLINE_ROLE_CREDENTIAL_SPECS, profiles):
        if (
            profile.capability_id != spec.capability_id
            or profile.online_role != spec.online_role
        ):
            _configuration_error()
    if (
        not isinstance(manifest_entries, tuple)
        or any(
            not isinstance(entry, FileSecretManifestEntry)
            for entry in manifest_entries
        )
    ):
        _configuration_error()
    credential_entries = tuple(
        entry for entry in manifest_entries if entry.kind == "DATABASE_CREDENTIAL"
    )
    if len(credential_entries) != len(profiles):
        _configuration_error()
    indexed = {entry.credential_ref: entry for entry in credential_entries}
    if len(indexed) != len(credential_entries):
        _configuration_error()
    for spec, profile in zip(ONLINE_ROLE_CREDENTIAL_SPECS, profiles):
        entry = indexed.get(profile.credential_ref)
        if (
            entry is None
            or entry.purpose != "DATABASE_CREDENTIAL:%s" % spec.capability_id
            or entry.status != "ACTIVE"
        ):
            _configuration_error()
    return profiles


def _validate_settings(settings: DeploymentMigrationSettings) -> None:
    if not isinstance(settings, DeploymentMigrationSettings):
        _configuration_error()


def _validate_distinct_materials(
    settings: DeploymentMigrationSettings,
    carriers: Tuple[Any, ...],
) -> None:
    if len(carriers) != len(ONLINE_ROLE_CREDENTIAL_SPECS):
        _configuration_error()
    materials = []
    try:
        admin_material = settings.admin_password.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        _configuration_error()
    for carrier in carriers:
        material = getattr(carrier, "material", None)
        if (
            not isinstance(material, bytearray)
            or not _MINIMUM_PASSWORD_BYTES <= len(material) <= 4_096
            or b"\x00" in material
            or b"\r" in material
            or b"\n" in material
        ):
            _configuration_error()
        candidate = bytes(material)
        try:
            candidate.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            _configuration_error()
        if hmac.compare_digest(candidate, admin_material):
            _configuration_error()
        if any(hmac.compare_digest(candidate, prior) for prior in materials):
            _configuration_error()
        materials.append(candidate)


def _assert_role_contract(
    connection: Any,
    *,
    require_migration_passwords_clear: bool,
) -> None:
    rows = connection.execute(
        "SELECT rolname,rolcanlogin,rolinherit,rolsuper,rolcreatedb,"
        "rolcreaterole,rolbypassrls FROM pg_catalog.pg_roles "
        "WHERE rolname = ANY(%s) ORDER BY rolname",
        (list(_ONLINE_ROLES),),
    ).fetchall()
    expected = sorted(
        (role, True, False, False, False, False, False) for role in _ONLINE_ROLES
    )
    if rows != expected:
        raise OnlineRoleCredentialError(
            "DEPLOYMENT_ONLINE_ROLE_CONTRACT_MISMATCH"
        )
    membership_count = connection.execute(
        "SELECT count(*) FROM pg_catalog.pg_auth_members AS membership "
        "JOIN pg_catalog.pg_roles AS member ON member.oid=membership.member "
        "WHERE member.rolname = ANY(%s)",
        (list(_ONLINE_ROLES),),
    ).fetchone()
    if membership_count != (0,):
        raise OnlineRoleCredentialError(
            "DEPLOYMENT_ONLINE_ROLE_CONTRACT_MISMATCH"
        )
    if require_migration_passwords_clear:
        uncleared = connection.execute(
            "SELECT count(*) FROM pg_catalog.pg_authid "
            "WHERE rolname = ANY(%s) AND rolpassword IS NOT NULL",
            (list(_MIGRATION_ROLES),),
        ).fetchone()
        if uncleared != (0,):
            raise OnlineRoleCredentialError(
                "DEPLOYMENT_MIGRATION_CREDENTIAL_STILL_ACTIVE"
            )


def _assert_installed_password_facts(
    connection: Any,
    expected_not_after: Tuple[datetime, ...],
) -> None:
    rows = connection.execute(
        "SELECT rolname,rolpassword,rolvaliduntil FROM pg_catalog.pg_authid "
        "WHERE rolname = ANY(%s) ORDER BY rolname",
        (list(_ONLINE_ROLES),),
    ).fetchall()
    by_role = {row[0]: row[1:] for row in rows}
    if len(by_role) != len(_ONLINE_ROLES):
        raise OnlineRoleCredentialError(
            "DEPLOYMENT_ONLINE_CREDENTIAL_VERIFICATION_FAILED"
        )
    verifiers = []
    for spec, not_after in zip(ONLINE_ROLE_CREDENTIAL_SPECS, expected_not_after):
        facts = by_role.get(spec.online_role)
        if (
            facts is None
            or not isinstance(facts[0], str)
            or not facts[0].startswith(_SCRAM_PREFIX)
            or facts[1] != not_after
        ):
            raise OnlineRoleCredentialError(
                "DEPLOYMENT_ONLINE_CREDENTIAL_VERIFICATION_FAILED"
            )
        verifiers.append(facts[0])
    if len(set(verifiers)) != len(verifiers):
        raise OnlineRoleCredentialError(
            "DEPLOYMENT_ONLINE_CREDENTIAL_VERIFICATION_FAILED"
        )


def _assert_revoked_password_facts(connection: Any) -> None:
    rows = connection.execute(
        "SELECT rolname,rolpassword FROM pg_catalog.pg_authid "
        "WHERE rolname = ANY(%s) ORDER BY rolname",
        (list(_ONLINE_ROLES),),
    ).fetchall()
    if len(rows) != len(_ONLINE_ROLES) or any(row[1] is not None for row in rows):
        raise OnlineRoleCredentialError(
            "DEPLOYMENT_ONLINE_CREDENTIAL_REVOKE_FAILED"
        )


def _terminate_online_sessions(connection: Any) -> None:
    for _attempt in range(3):
        rows = connection.execute(
            "SELECT pid FROM pg_catalog.pg_stat_activity "
            "WHERE usename = ANY(%s) AND pid <> pg_catalog.pg_backend_pid() "
            "ORDER BY pid",
            (list(_ONLINE_ROLES),),
        ).fetchall()
        if not rows:
            return
        for (pid,) in rows:
            result = connection.execute(
                "SELECT pg_catalog.pg_terminate_backend(%s)",
                (pid,),
            ).fetchone()
            if result != (True,):
                raise OnlineRoleCredentialError(
                    "DEPLOYMENT_ONLINE_CREDENTIAL_SESSION_DRAIN_FAILED"
                )
    raise OnlineRoleCredentialError(
        "DEPLOYMENT_ONLINE_CREDENTIAL_SESSION_DRAIN_FAILED"
    )


def _verify_fresh_logins(
    settings: DeploymentMigrationSettings,
    profiles: Tuple[DatabaseProfile, ...],
    carriers: Tuple[Any, ...],
    dbapi: Any,
) -> None:
    for profile, carrier in zip(profiles, carriers):
        try:
            password = bytes(carrier.material).decode("utf-8", errors="strict")
            connection = dbapi.connect(
                make_conninfo(
                    host=settings.host,
                    port=settings.port,
                    dbname=settings.database,
                    user=profile.online_role,
                    password=password,
                    connect_timeout=5,
                    sslmode="disable",
                ),
                autocommit=True,
                application_name=_VERIFIER_APPLICATION_NAME,
                connect_timeout=5,
            )
            try:
                row = connection.execute(
                    "SELECT session_user,current_user,current_database(),"
                    "current_setting('server_version_num')::integer/10000,"
                    "(SELECT rolcanlogin AND NOT rolinherit AND NOT rolsuper "
                    "AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolbypassrls "
                    "FROM pg_catalog.pg_roles WHERE rolname=current_user)"
                ).fetchone()
                if row != (
                    profile.online_role,
                    profile.online_role,
                    settings.database,
                    18,
                    True,
                ):
                    raise RuntimeError
            finally:
                connection.close()
        except BaseException:
            raise OnlineRoleCredentialError(
                "DEPLOYMENT_ONLINE_CREDENTIAL_VERIFICATION_FAILED"
            ) from None


def _rollback(connection: Any) -> None:
    try:
        if connection.info.transaction_status != TransactionStatus.IDLE:
            connection.execute("ROLLBACK")
    except BaseException:
        pass


def _require_utc(value: Any) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _configuration_error()
    try:
        offset = value.utcoffset()
    except BaseException:
        _configuration_error()
    if offset != timedelta(0):
        _configuration_error()


def _load_admin_and_deployment(
    environment: Mapping[str, str],
    *,
    allowed_secret_root: Path,
    read_bytes: Optional[Callable[[str], bytes]],
) -> Tuple[DeploymentMigrationSettings, InternalSandboxDeploymentConfiguration]:
    inputs = load_online_role_credential_inputs(
        environment,
        allowed_secret_root=allowed_secret_root,
        read_bytes=read_bytes,
    )
    return inputs.settings, inputs.deployment


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
        prog="python -m desire_platform.deployment.online_credentials"
    )
    parser.add_argument("action", choices=("reconcile", "verify", "revoke"))
    arguments = parser.parse_args(argv)
    try:
        inputs = load_online_role_credential_inputs(environment)
        if arguments.action == "reconcile":
            report = reconcile_online_role_credentials(
                settings=inputs.settings,
                runtime_config=inputs.runtime_config,
                manifest_entries=inputs.manifest_entries,
                secret_root=inputs.secret_root,
                now=clock(),
                dbapi=dbapi,
            )
        elif arguments.action == "verify":
            report = verify_online_role_credentials(
                settings=inputs.settings,
                runtime_config=inputs.runtime_config,
                manifest_entries=inputs.manifest_entries,
                secret_root=inputs.secret_root,
                now=clock(),
                dbapi=dbapi,
            )
        else:
            report = revoke_online_role_credentials(
                settings=inputs.settings,
                dbapi=dbapi,
            )
    except OnlineRoleCredentialError as error:
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
        stderr.write(
            '{"code":"DEPLOYMENT_ONLINE_CREDENTIAL_FAILED","status":"BLOCKED"}\n'
        )
        return 78
    stdout.write(
        json.dumps(
            {
                "action": report.action.value,
                "online_role_count": len(report.online_roles),
                "status": "ONLINE_CREDENTIALS_READY",
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
    "ONLINE_ROLE_CREDENTIAL_SPECS",
    "OnlineRoleCredentialAction",
    "OnlineRoleCredentialConfigurationError",
    "OnlineRoleCredentialError",
    "OnlineRoleCredentialInputs",
    "OnlineRoleCredentialReport",
    "OnlineRoleCredentialSpec",
    "load_online_role_credential_inputs",
    "main",
    "reconcile_online_role_credentials",
    "revoke_online_role_credentials",
    "verify_online_role_credentials",
)
