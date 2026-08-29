"""Deployment-only CLI for the digest-pinned INTERNAL_SANDBOX Taxonomy seed.

The program authenticates with the existing deployment administrator, installs
four short-lived role credentials, invokes only reviewed fixed programs, then
removes every temporary credential.  Runtime seed secrets are file-backed and
never accepted inline or written to PostgreSQL in clear text.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
from typing import Any, Callable, Mapping, NoReturn, Optional, Sequence, TextIO

import psycopg
from psycopg import sql

from desire_platform.internal_pilot.synthetic_seed import (
    INTERNAL_SANDBOX_SYNTHETIC_SEED_SHA256,
    InternalSandboxSyntheticSeedPlan,
    load_internal_sandbox_synthetic_seed,
)
from desire_platform.internal_pilot.synthetic_seed_postgres import (
    InternalSandboxSeedRuntimeMaterial,
    InternalSandboxSyntheticSeedPostgresError,
    InternalSandboxTaxonomyPostgresSchemaValidator,
    InternalSandboxTaxonomySeedResult,
    PostgresInternalSandboxTaxonomySeedOrchestrator,
    PsycopgInternalSandboxProfileTaxonomyProjector,
    PsycopgInternalSandboxTaxonomyProvisioner,
)
from desire_platform.taxonomy.adapters.postgres import (
    NoTaxonomyPostgresFaults,
    PsycopgTaxonomyUnitOfWorkFactory,
)

from .migrations import (
    DeploymentMigrationConfigurationError,
    DeploymentMigrationError,
    DeploymentMigrationSettings,
    _acquire_provisioning_lock,
    _admin_connection,
    _assert_admin_preflight,
    _conninfo,
    _release_provisioning_lock,
    _verify_catalogs,
    load_settings,
)


TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE_ENV = (
    "DESIRE_TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE"
)
TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE_ENV = (
    "DESIRE_TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE"
)

_DESIRE_ENVIRONMENT = frozenset(
    (
        "DESIRE_DEPLOYMENT_MODE",
        "DESIRE_EXTERNAL_PARTICIPANTS_ENABLED",
        "DESIRE_DATABASE_HOST",
        "DESIRE_DATABASE_NAME",
        "DESIRE_DATABASE_ADMIN_USER",
        "DESIRE_DATABASE_PASSWORD_FILE",
        TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE_ENV,
        TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE_ENV,
    )
)
_SEED_ROLES = (
    "taxonomy_migration_runner",
    "taxonomy_publisher",
    "taxonomy_consumer",
    "profile_migration_runner",
)
_TEMPORARY_ROLE_CREDENTIAL_LIFETIME = timedelta(minutes=15)


class InternalSandboxTaxonomySeedDeploymentError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class InternalSandboxTaxonomySeedDeploymentConfigurationError(
    InternalSandboxTaxonomySeedDeploymentError
):
    pass


@dataclass(frozen=True, repr=False)
class InternalSandboxTaxonomySeedDeploymentInputs:
    settings: DeploymentMigrationSettings
    runtime: InternalSandboxSeedRuntimeMaterial

    def __repr__(self) -> str:
        return (
            "InternalSandboxTaxonomySeedDeploymentInputs("
            f"settings={self.settings!r}, runtime={self.runtime!r})"
        )


class _RoleConnectionSource:
    def __init__(self, *, dbapi: Any, conninfo: str, application_name: str) -> None:
        self._dbapi = dbapi
        self._conninfo = conninfo
        self._application_name = application_name
        self._closed = False
        self._connections: list[Any] = []

    def checkout(self) -> Any:
        if self._closed:
            raise RuntimeError("seed connection source is closed")
        connection = self._dbapi.connect(
            self._conninfo,
            autocommit=True,
            application_name=self._application_name,
            connect_timeout=5,
            prepare_threshold=None,
        )
        self._connections.append(connection)
        return connection

    def release(self, connection: Any) -> None:
        connection.close()

    def discard(self, connection: Any) -> None:
        connection.close()

    def close(self) -> None:
        self._closed = True
        for connection in self._connections:
            if not connection.closed:
                connection.close()

    def __repr__(self) -> str:
        return "_RoleConnectionSource(conninfo=<redacted>)"


def load_internal_sandbox_taxonomy_seed_deployment_inputs(
    environment: Optional[Mapping[str, str]] = None,
    *,
    allowed_secret_root: Path = Path("/run/secrets"),
) -> InternalSandboxTaxonomySeedDeploymentInputs:
    values = os.environ if environment is None else environment
    try:
        if not isinstance(values, Mapping):
            _configuration_error()
        desire_keys = frozenset(
            key
            for key in values
            if isinstance(key, str) and key.startswith("DESIRE_")
        )
        if desire_keys != _DESIRE_ENVIRONMENT:
            _configuration_error()
        settings = load_settings(values, allowed_secret_root=allowed_secret_root)
        workload_raw = _read_direct_secret(
            values[TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE_ENV],
            allowed_secret_root=allowed_secret_root,
            expected_size=None,
        )
        receipt_key = _read_direct_secret(
            values[TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE_ENV],
            allowed_secret_root=allowed_secret_root,
            expected_size=32,
        )
        workload_credential = workload_raw.decode("ascii", errors="strict")
        runtime = InternalSandboxSeedRuntimeMaterial(
            deployment_mode="INTERNAL_SANDBOX",
            workload_credential_id=workload_credential,
            receipt_hmac_key=receipt_key,
        )
        return InternalSandboxTaxonomySeedDeploymentInputs(
            settings=settings,
            runtime=runtime,
        )
    except InternalSandboxTaxonomySeedDeploymentConfigurationError:
        raise
    except (
        DeploymentMigrationConfigurationError,
        KeyError,
        OSError,
        TypeError,
        UnicodeDecodeError,
        ValueError,
    ):
        _configuration_error()


def apply_internal_sandbox_taxonomy_seed(
    *,
    settings: DeploymentMigrationSettings,
    runtime: InternalSandboxSeedRuntimeMaterial,
    plan: Optional[InternalSandboxSyntheticSeedPlan] = None,
    dbapi: Any = psycopg,
    password_factory: Callable[[], str] = lambda: secrets.token_urlsafe(48),
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> InternalSandboxTaxonomySeedResult:
    """Run the exact offline seed and revoke all four role credentials."""

    if (
        not isinstance(settings, DeploymentMigrationSettings)
        or not isinstance(runtime, InternalSandboxSeedRuntimeMaterial)
        or not callable(password_factory)
        or not callable(now)
    ):
        _configuration_error()
    reviewed_plan = plan or load_internal_sandbox_synthetic_seed()
    try:
        reviewed_plan.require_executable()
        with _admin_connection(settings, dbapi) as admin:
            _assert_admin_preflight(admin, settings)
            _acquire_provisioning_lock(admin)
            locked = True
            cleanup_required = False
            sources: list[_RoleConnectionSource] = []
            try:
                _verify_catalogs(admin)
                _verify_seed_roles(admin)
                cleanup_required = True
                passwords = _install_seed_role_passwords(
                    admin,
                    password_factory=password_factory,
                    expires_at=now() + _TEMPORARY_ROLE_CREDENTIAL_LIFETIME,
                )
                sources = [
                    _role_source(
                        settings=settings,
                        passwords=passwords,
                        role=role,
                        dbapi=dbapi,
                    )
                    for role in _SEED_ROLES
                ]
                by_role = dict(zip(_SEED_ROLES, sources))
                validator = InternalSandboxTaxonomyPostgresSchemaValidator()
                result = PostgresInternalSandboxTaxonomySeedOrchestrator(
                    provisioner=PsycopgInternalSandboxTaxonomyProvisioner(
                        connections=by_role["taxonomy_migration_runner"]
                    ),
                    publisher=PsycopgTaxonomyUnitOfWorkFactory(
                        connections=by_role["taxonomy_publisher"],
                        event_validator=validator,
                        response_validator=validator,
                        fault_injector=NoTaxonomyPostgresFaults(),
                    ),
                    consumer=PsycopgTaxonomyUnitOfWorkFactory(
                        connections=by_role["taxonomy_consumer"],
                        event_validator=validator,
                        response_validator=validator,
                        fault_injector=NoTaxonomyPostgresFaults(),
                    ),
                    profile_projector=(
                        PsycopgInternalSandboxProfileTaxonomyProjector(
                            connections=by_role["profile_migration_runner"]
                        )
                    ),
                ).run(plan=reviewed_plan, runtime=runtime)
                _verify_seed_projection(admin, reviewed_plan, runtime, result)
                return result
            finally:
                for source in sources:
                    source.close()
                try:
                    if cleanup_required:
                        _clear_seed_role_passwords(admin)
                finally:
                    if locked:
                        _release_provisioning_lock(admin)
    except InternalSandboxTaxonomySeedDeploymentError:
        raise
    except (
        DeploymentMigrationError,
        InternalSandboxSyntheticSeedPostgresError,
    ):
        raise InternalSandboxTaxonomySeedDeploymentError(
            "INTERNAL_SANDBOX_TAXONOMY_SEED_BLOCKED"
        ) from None
    except BaseException:
        raise InternalSandboxTaxonomySeedDeploymentError(
            "INTERNAL_SANDBOX_TAXONOMY_SEED_FAILED"
        ) from None


def _read_direct_secret(
    raw_path: Any,
    *,
    allowed_secret_root: Path,
    expected_size: Optional[int],
) -> bytes:
    if not isinstance(raw_path, str) or not raw_path:
        _configuration_error()
    root = allowed_secret_root.resolve(strict=True)
    path = Path(raw_path)
    resolved = path.resolve(strict=True)
    if (
        path.is_symlink()
        or resolved.parent != root
        or not resolved.is_file()
    ):
        _configuration_error()
    raw = resolved.read_bytes()
    if (
        (expected_size is not None and len(raw) != expected_size)
        or (expected_size is None and not 32 <= len(raw) <= 256)
        or (
            expected_size is None
            and (b"\x00" in raw or b"\n" in raw or b"\r" in raw)
        )
        or not any(raw)
    ):
        _configuration_error()
    return raw


def _verify_seed_roles(connection: Any) -> None:
    rows = connection.execute(
        "SELECT rolname,rolcanlogin,rolinherit,rolsuper,rolcreatedb,"
        "rolcreaterole,rolbypassrls FROM pg_catalog.pg_roles "
        "WHERE rolname=ANY(%s) ORDER BY rolname",
        (list(_SEED_ROLES),),
    ).fetchall()
    expected = tuple(
        (role, True, False, False, False, False, False)
        for role in sorted(_SEED_ROLES)
    )
    if tuple(rows) != expected:
        raise InternalSandboxTaxonomySeedDeploymentError(
            "INTERNAL_SANDBOX_TAXONOMY_SEED_ROLE_DRIFT"
        )


def _install_seed_role_passwords(
    connection: Any,
    *,
    password_factory: Callable[[], str],
    expires_at: datetime,
) -> Mapping[str, str]:
    if (
        not isinstance(expires_at, datetime)
        or expires_at.tzinfo is None
        or expires_at.utcoffset() != timedelta(0)
    ):
        _configuration_error()
    passwords: dict[str, str] = {}
    for role in _SEED_ROLES:
        password = password_factory()
        if (
            not isinstance(password, str)
            or len(password) < 32
            or password in passwords.values()
        ):
            _configuration_error()
        connection.execute(
            sql.SQL("ALTER ROLE {} PASSWORD {} VALID UNTIL {}").format(
                sql.Identifier(role),
                sql.Literal(password),
                sql.Literal(expires_at.isoformat().replace("+00:00", "Z")),
            )
        )
        passwords[role] = password
    return passwords


def _clear_seed_role_passwords(connection: Any) -> None:
    failed = False
    for role in _SEED_ROLES:
        try:
            connection.execute(
                sql.SQL("ALTER ROLE {} PASSWORD NULL VALID UNTIL 'infinity'").format(
                    sql.Identifier(role)
                )
            )
        except BaseException:
            failed = True
    if failed:
        raise InternalSandboxTaxonomySeedDeploymentError(
            "INTERNAL_SANDBOX_TAXONOMY_SEED_CREDENTIAL_CLEANUP_FAILED"
        )


def _role_source(
    *,
    settings: DeploymentMigrationSettings,
    passwords: Mapping[str, str],
    role: str,
    dbapi: Any,
) -> _RoleConnectionSource:
    return _RoleConnectionSource(
        dbapi=dbapi,
        conninfo=_conninfo(settings, user=role, password=passwords[role]),
        application_name="desire-internal-sandbox-taxonomy-seed-" + role,
    )


def _verify_seed_projection(
    connection: Any,
    plan: InternalSandboxSyntheticSeedPlan,
    runtime: InternalSandboxSeedRuntimeMaterial,
    result: InternalSandboxTaxonomySeedResult,
) -> None:
    credential_sha256 = hashlib.sha256(
        runtime.workload_credential_id.encode("ascii")
    ).digest()
    facts = connection.execute(
        "SELECT "
        "(SELECT count(*) FROM taxonomy.workload_authorizations "
        " WHERE workload_principal_id=%s AND operation='PublishTaxonomyBundle' "
        " AND credential_sha256=%s AND attestation_sha256=%s "
        " AND status='ACTIVE' AND valid_until=%s),"
        "(SELECT count(*) FROM taxonomy.consumer_authorizations "
        " WHERE authorization_digest=%s AND consumer_code=%s "
        " AND consumer_job_id=%s AND workload_principal_id=%s "
        " AND bundle_id=%s AND release_manifest_sha256=%s "
        " AND credential_sha256=%s AND attestation_sha256=%s "
        " AND valid_until=%s),"
        "(SELECT count(*) FROM taxonomy.bundles "
        " WHERE bundle_id=%s AND release_manifest_sha256=%s "
        " AND status='ACTIVE' AND aggregate_version=1),"
        "(SELECT count(*) FROM taxonomy.current_bundles WHERE bundle_id=%s),"
        "(SELECT count(*) FROM taxonomy.command_receipts "
        " WHERE principal_id=%s AND operation='PublishTaxonomyBundle' "
        " AND status='COMPLETED'),"
        "(SELECT count(*) FROM taxonomy.consumer_inbox "
        " WHERE consumer_code=%s AND status='COMPLETED'),"
        "(SELECT count(*) FROM profile.taxonomy_bundle_markers "
        " WHERE id=%s AND status='ACTIVE' AND bundle_sha256=%s "
        " AND aggregate_version=1),"
        "(SELECT count(*) FROM profile.taxonomy_projection_inbox "
        " WHERE seed_manifest_sha256=%s AND taxonomy_bundle_id=%s "
        " AND release_manifest_sha256=%s AND aggregate_version=1 "
        " AND status='COMPLETED')",
        (
            plan.taxonomy_workload_principal_id,
            credential_sha256,
            bytes.fromhex(plan.taxonomy_workload_attestation_sha256),
            plan.taxonomy_authority_valid_until,
            bytes.fromhex(plan.taxonomy_consumer_authorization_digest),
            plan.taxonomy_profile_consumer_code,
            plan.taxonomy_profile_consumer_job_id,
            plan.taxonomy_workload_principal_id,
            plan.taxonomy_bundle_id,
            bytes.fromhex(plan.taxonomy_release.release_manifest_sha256),
            credential_sha256,
            bytes.fromhex(plan.taxonomy_workload_attestation_sha256),
            plan.taxonomy_authority_valid_until,
            plan.taxonomy_bundle_id,
            bytes.fromhex(plan.taxonomy_release.release_manifest_sha256),
            plan.taxonomy_bundle_id,
            plan.taxonomy_workload_principal_id,
            plan.taxonomy_profile_consumer_code,
            plan.taxonomy_bundle_id,
            bytes.fromhex(plan.taxonomy_release.release_manifest_sha256),
            INTERNAL_SANDBOX_SYNTHETIC_SEED_SHA256,
            plan.taxonomy_bundle_id,
            bytes.fromhex(plan.taxonomy_release.release_manifest_sha256),
        ),
    ).fetchone()
    if (
        not isinstance(result, InternalSandboxTaxonomySeedResult)
        or result.taxonomy_bundle_id != plan.taxonomy_bundle_id
        or facts != (1, 1, 1, 1, 1, 1, 1, 1)
    ):
        raise InternalSandboxTaxonomySeedDeploymentError(
            "INTERNAL_SANDBOX_TAXONOMY_SEED_VERIFICATION_FAILED"
        )


def _configuration_error() -> NoReturn:
    raise InternalSandboxTaxonomySeedDeploymentConfigurationError(
        "INTERNAL_SANDBOX_TAXONOMY_SEED_CONFIGURATION_INVALID"
    )


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    environment: Optional[Mapping[str, str]] = None,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    dbapi: Any = psycopg,
) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m desire_platform.deployment.synthetic_taxonomy_seed"
    )
    parser.add_argument("action", choices=("apply",))
    parser.parse_args(argv)
    try:
        inputs = load_internal_sandbox_taxonomy_seed_deployment_inputs(
            environment
        )
        result = apply_internal_sandbox_taxonomy_seed(
            settings=inputs.settings,
            runtime=inputs.runtime,
            dbapi=dbapi,
        )
    except InternalSandboxTaxonomySeedDeploymentError as error:
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
            '{"code":"INTERNAL_SANDBOX_TAXONOMY_SEED_FAILED",'
            '"status":"BLOCKED"}\n'
        )
        return 78
    stdout.write(
        json.dumps(
            {
                "manifest_sha256": (
                    INTERNAL_SANDBOX_SYNTHETIC_SEED_SHA256.hex()
                ),
                "replayed": result.publication_replayed,
                "status": "INTERNAL_SANDBOX_TAXONOMY_SEED_READY",
                "taxonomy_bundle_id": result.taxonomy_bundle_id,
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
    "InternalSandboxTaxonomySeedDeploymentConfigurationError",
    "InternalSandboxTaxonomySeedDeploymentError",
    "InternalSandboxTaxonomySeedDeploymentInputs",
    "TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE_ENV",
    "TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE_ENV",
    "apply_internal_sandbox_taxonomy_seed",
    "load_internal_sandbox_taxonomy_seed_deployment_inputs",
    "main",
)
