#!/usr/bin/env python3
"""Prepare five private credentials for the local exact-target Matching CLI.

Run only in a one-shot Docker provisioner on the project's private data network.
The administrator secret belongs to this process, never the workflow process.
Only the existing demand_system password/expiry may change; no grants, role
creation, migrations, other passwords, or session termination occur here.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile
from typing import Any, Sequence


SYSTEM_ROLE = "demand_system"
SYSTEM_FILE = "db-demand-system-v1"
SOURCE_FILES = (
    "db-demand-self-v1", "db-trust-decision-v1",
    "key-demand-idempotency-v1", "key-demand-payload-hash-v1",
)
CREDENTIAL_FILES = (SYSTEM_FILE,) + SOURCE_FILES


class WorkflowCredentialError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _directory(path: Path, *, private: bool = False) -> None:
    if not path.is_absolute() or path != path.resolve(strict=True):
        raise WorkflowCredentialError("WORKFLOW_CREDENTIAL_PATH_INVALID")
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or (
        private and stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise WorkflowCredentialError("WORKFLOW_CREDENTIAL_PATH_INVALID")


def _read_secret(path: Path) -> bytes:
    # The directory was already checked. O_NOFOLLOW also closes the final
    # component symlink race; fstat validates the file actually opened.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if (not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or not 32 <= metadata.st_size <= 4096):
            raise WorkflowCredentialError("WORKFLOW_CREDENTIAL_FILE_INVALID")
        value = stream.read(4097)
    if len(value) != metadata.st_size or not value or any(c in value for c in (b"\0", b"\r", b"\n")):
        raise WorkflowCredentialError("WORKFLOW_CREDENTIAL_FILE_INVALID")
    try:
        value.decode("ascii")
    except UnicodeDecodeError:
        raise WorkflowCredentialError("WORKFLOW_CREDENTIAL_FILE_INVALID") from None
    if path.name.startswith("key-") and not 32 <= len(value) <= 64:
        raise WorkflowCredentialError("WORKFLOW_CREDENTIAL_FILE_INVALID")
    return value


def _validate_materials(materials: dict[str, bytes], admin_password: str) -> None:
    values = list(materials.values())
    for index, value in enumerate(values):
        if hmac.compare_digest(value, admin_password.encode("utf-8")) or any(
            hmac.compare_digest(value, prior) for prior in values[:index]
        ):
            raise WorkflowCredentialError("WORKFLOW_CREDENTIAL_MATERIAL_REUSED")


def _publish_directory(output: Path, materials: dict[str, bytes]) -> None:
    """Persist all five files before changing PG, so an uncertain commit retries."""
    staging = Path(tempfile.mkdtemp(prefix=".workflow-secrets-", dir=output.parent))
    try:
        staging.chmod(0o700)
        for name in CREDENTIAL_FILES:
            descriptor = os.open(staging / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(materials[name])
                stream.flush()
                os.fsync(stream.fileno())
        staging_fd = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(staging_fd)
        finally:
            os.close(staging_fd)
        # Cooperating provisioners hold the deployment advisory lock. Never
        # overwrite an existing target, including an empty directory/symlink.
        if output.exists() or output.is_symlink():
            raise WorkflowCredentialError("WORKFLOW_CREDENTIAL_PATH_INVALID")
        staging.rename(output)
        parent_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        if staging.exists():
            for child in staging.iterdir():
                child.unlink()
            staging.rmdir()


def _assert_system_role(connection: Any) -> None:
    role = connection.execute(
        "SELECT rolname,rolcanlogin,rolinherit,rolsuper,rolcreatedb,rolcreaterole,rolbypassrls "
        "FROM pg_catalog.pg_roles WHERE rolname=%s", (SYSTEM_ROLE,),
    ).fetchone()
    if role != (SYSTEM_ROLE, True, False, False, False, False, False):
        raise WorkflowCredentialError("WORKFLOW_SYSTEM_ROLE_DRIFT")
    memberships = connection.execute(
        "SELECT count(*) FROM pg_catalog.pg_auth_members m "
        "JOIN pg_catalog.pg_roles r ON r.oid=m.member WHERE r.rolname=%s",
        (SYSTEM_ROLE,),
    ).fetchone()
    if memberships != (0,):
        raise WorkflowCredentialError("WORKFLOW_SYSTEM_ROLE_DRIFT")


def _password_facts(connection: Any) -> tuple:
    facts = connection.execute(
        "SELECT rolpassword IS NOT NULL,COALESCE(rolpassword LIKE 'SCRAM-SHA-256$%%',false),rolvaliduntil "
        "FROM pg_catalog.pg_authid WHERE rolname=%s", (SYSTEM_ROLE,),
    ).fetchone()
    if not isinstance(facts, tuple) or len(facts) != 3:
        raise WorkflowCredentialError("WORKFLOW_SYSTEM_ROLE_DRIFT")
    return facts


def _verify_login(settings: Any, dbapi: Any, role: str, password: bytes) -> None:
    if role not in {SYSTEM_ROLE, "demand_self", "trust_decision"}:
        raise WorkflowCredentialError("WORKFLOW_SYSTEM_ROLE_DRIFT")
    try:
        with dbapi.connect(host=settings.host, port=settings.port, dbname=settings.database,
                user=role, password=password.decode("ascii"), sslmode="disable",
                autocommit=True, connect_timeout=5,
                application_name="desire-local-workflow-credential-verifier") as connection:
            facts = connection.execute(
                "SELECT session_user,current_user,current_database(),"
                "current_setting('server_version_num')::integer/10000,"
                "rolcanlogin,rolinherit,rolsuper,rolcreatedb,rolcreaterole,rolbypassrls "
                "FROM pg_catalog.pg_roles WHERE rolname=current_user"
            ).fetchone()
            if facts != (role, role, settings.database, 18, True, False, False, False, False, False):
                raise WorkflowCredentialError("WORKFLOW_CREDENTIAL_LOGIN_FAILED")
    except Exception:
        raise WorkflowCredentialError("WORKFLOW_CREDENTIAL_LOGIN_FAILED") from None


def prepare_credentials(*, source_directory: Path, output_directory: Path,
                        settings: Any, now: datetime, dbapi: Any) -> bool:
    """Return True for verified existing credentials; preserve files on DB failure."""
    from desire_platform.deployment.migrations import (
        _acquire_provisioning_lock, _admin_connection, _assert_admin_preflight,
        _release_provisioning_lock, _verify_catalogs,
    )
    if now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise WorkflowCredentialError("WORKFLOW_CONFIGURATION_INVALID")
    _directory(source_directory)
    _directory(output_directory.parent)
    if (not output_directory.is_absolute() or output_directory.name != "workflow-secrets"
            or output_directory.is_symlink()):
        raise WorkflowCredentialError("WORKFLOW_CREDENTIAL_PATH_INVALID")
    source = {name: _read_secret(source_directory / name) for name in SOURCE_FILES}
    with _admin_connection(settings, dbapi) as connection:
        _assert_admin_preflight(connection, settings)
        _acquire_provisioning_lock(connection)
        try:
            _verify_catalogs(connection)
            _assert_system_role(connection)
            facts = _password_facts(connection)
            existed = output_directory.exists()
            if existed:
                _directory(output_directory, private=True)
                if {path.name for path in output_directory.iterdir()} != set(CREDENTIAL_FILES):
                    raise WorkflowCredentialError("WORKFLOW_CREDENTIAL_FILE_INVALID")
                material = {name: _read_secret(output_directory / name) for name in CREDENTIAL_FILES}
                if any(not hmac.compare_digest(material[name], source[name]) for name in SOURCE_FILES):
                    raise WorkflowCredentialError("WORKFLOW_SOURCE_CREDENTIAL_DRIFT")
            else:
                if facts[0]:
                    raise WorkflowCredentialError("WORKFLOW_EXISTING_PASSWORD_UNMANAGED")
                material = {SYSTEM_FILE: secrets.token_urlsafe(36).encode("ascii"), **source}
            _validate_materials(material, settings.admin_password)
            _verify_login(settings, dbapi, "demand_self", material["db-demand-self-v1"])
            _verify_login(settings, dbapi, "trust_decision", material["db-trust-decision-v1"])
            if facts[0]:
                if (facts[1] is not True or not isinstance(facts[2], datetime)
                        or facts[2].tzinfo is None or facts[2] <= now):
                    raise WorkflowCredentialError("WORKFLOW_CREDENTIAL_EXPIRED_OR_INVALID")
                _verify_login(settings, dbapi, SYSTEM_ROLE, material[SYSTEM_FILE])
                return True
            change_password = getattr(getattr(connection, "pgconn", None), "change_password", None)
            if not callable(change_password):
                raise WorkflowCredentialError("WORKFLOW_CREDENTIAL_ADAPTER_UNAVAILABLE")
            if not existed:
                _publish_directory(output_directory, material)
            from psycopg import sql
            expires_at = now.replace(microsecond=0) + timedelta(days=365)
            connection.execute("BEGIN")
            try:
                connection.execute("SET LOCAL password_encryption TO 'scram-sha-256'")
                change_password(SYSTEM_ROLE.encode("ascii"), bytearray(material[SYSTEM_FILE]))
                connection.execute(sql.SQL("ALTER ROLE {} VALID UNTIL {}").format(
                    sql.Identifier(SYSTEM_ROLE), sql.Literal(expires_at.strftime("%Y-%m-%d %H:%M:%S+00"))))
                connection.execute("COMMIT")
            except BaseException:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    pass
                raise
            if _password_facts(connection) != (True, True, expires_at):
                raise WorkflowCredentialError("WORKFLOW_CREDENTIAL_VERIFICATION_FAILED")
            _verify_login(settings, dbapi, SYSTEM_ROLE, material[SYSTEM_FILE])
            return False
        finally:
            _release_provisioning_lock(connection)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True)
    parser.add_argument("--admin-password-file", required=True, type=Path)
    parser.add_argument("--source-secret-directory", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        import psycopg
        from desire_platform.deployment.migrations import load_settings
        settings = load_settings({
            "DESIRE_DEPLOYMENT_MODE": "INTERNAL_SANDBOX",
            "DESIRE_EXTERNAL_PARTICIPANTS_ENABLED": "false",
            "DESIRE_DATABASE_HOST": "db", "DESIRE_DATABASE_NAME": args.database,
            "DESIRE_DATABASE_ADMIN_USER": "postgres",
            "DESIRE_DATABASE_PASSWORD_FILE": str(args.admin_password_file),
        })
        reused = prepare_credentials(source_directory=args.source_secret_directory,
            output_directory=args.output_directory, settings=settings,
            now=datetime.now(timezone.utc), dbapi=psycopg)
        print(json.dumps({"status": "READY", "role": SYSTEM_ROLE, "credential_count": 5, "reused": reused}))
        return 0
    except Exception as error:
        code = error.code if isinstance(error, WorkflowCredentialError) else "WORKFLOW_CREDENTIAL_PREPARATION_FAILED"
        print(json.dumps({"status": "FAILED", "code": code}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
