"""Transactional runner for the independent Creator Profile catalog."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
from typing import Any, Tuple

from .catalog import (
    PROFILE_MIGRATION_LAYOUT,
    PROFILE_REVIEWED_MANIFEST_SHA256,
    ProfileMigrationCatalog,
)


PROFILE_SCHEMA_HEAD_VERSION = PROFILE_MIGRATION_LAYOUT[-1][0]
PROFILE_MIGRATION_LOCK = (1347568966, 1)
PROFILE_REQUIRED_IAM_SCHEMA_VERSION = 46


class ProfileMigrationRunnerError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ProfileContractSources:
    api_contract_bytes: bytes
    event_contract_bytes: bytes
    domain_contract_bytes: bytes


@dataclass(frozen=True)
class ProfileMigrationRunReport:
    applied_versions: Tuple[int, ...]
    skipped_versions: Tuple[int, ...]


class PsycopgCreatorProfileMigrationRunner:
    def __init__(
        self,
        *,
        conninfo: str,
        dbapi: Any,
        runner_version: str,
    ) -> None:
        if not conninfo or not runner_version or len(runner_version) > 96:
            raise ProfileMigrationRunnerError(
                "PROFILE_MIGRATION_CONFIGURATION_INVALID"
            )
        self._conninfo = conninfo
        self._dbapi = dbapi
        self._runner_version = runner_version

    def run(
        self,
        *,
        catalog: ProfileMigrationCatalog,
        contract_sources: ProfileContractSources,
    ) -> ProfileMigrationRunReport:
        if (
            not isinstance(catalog, ProfileMigrationCatalog)
            or not hmac.compare_digest(
                catalog.manifest_sha256,
                PROFILE_REVIEWED_MANIFEST_SHA256,
            )
        ):
            raise ProfileMigrationRunnerError("PROFILE_MIGRATION_REVIEW_REQUIRED")
        connection = self._dbapi.connect(
            self._conninfo,
            autocommit=True,
            application_name="desire-profile-migration-runner",
            connect_timeout=5,
        )
        locked = False
        transaction = False
        try:
            role_row = connection.execute(
                "SELECT session_user,current_user,"
                "current_setting('server_version_num')::integer/10000"
            ).fetchone()
            if role_row != (
                "profile_migration_runner",
                "profile_migration_runner",
                18,
            ):
                raise ProfileMigrationRunnerError(
                    "PROFILE_MIGRATION_PREFLIGHT_FAILED"
                )
            (
                iam_head,
                principal_verifier,
                profile_authority_resolver,
                profile_match_eligibility_resolver,
            ) = connection.execute(
                "SELECT schema_head_version,"
                "EXISTS (SELECT 1 FROM pg_catalog.pg_proc AS procedure "
                "JOIN pg_catalog.pg_namespace AS namespace "
                "ON namespace.oid=procedure.pronamespace "
                "WHERE namespace.nspname='iam_api' "
                "AND procedure.proname='verify_editor_principal_marker_v1' "
                "AND pg_catalog.oidvectortypes(procedure.proargtypes)="
                "'uuid, uuid, bytea'),"
                "EXISTS (SELECT 1 FROM pg_catalog.pg_proc AS procedure "
                "JOIN pg_catalog.pg_namespace AS namespace "
                "ON namespace.oid=procedure.pronamespace "
                "WHERE namespace.nspname='iam_api' "
                "AND procedure.proname="
                "'resolve_profile_self_authority_marker_v1' "
                "AND pg_catalog.oidvectortypes(procedure.proargtypes)="
                "'uuid, uuid, text, uuid'),"
                "EXISTS (SELECT 1 FROM pg_catalog.pg_proc AS procedure "
                "JOIN pg_catalog.pg_namespace AS namespace "
                "ON namespace.oid=procedure.pronamespace "
                "WHERE namespace.nspname='iam_api' "
                "AND procedure.proname="
                "'resolve_profile_match_creator_eligibility_v1' "
                "AND pg_catalog.oidvectortypes(procedure.proargtypes)="
                "'uuid, uuid, uuid, bytea, bytea') "
                "FROM infra.iam_schema_compatibility"
            ).fetchone()
            if (
                iam_head < PROFILE_REQUIRED_IAM_SCHEMA_VERSION
                or principal_verifier is not True
                or profile_authority_resolver is not True
                or profile_match_eligibility_resolver is not True
            ):
                raise ProfileMigrationRunnerError(
                    "PROFILE_MIGRATION_IAM_DEPENDENCY_UNAVAILABLE"
                )
            connection.execute("SET ROLE profile_schema_owner")
            connection.execute(
                "SELECT pg_catalog.pg_advisory_lock(%s,%s)",
                PROFILE_MIGRATION_LOCK,
            )
            locked = True
            schema_exists, ledger_exists = connection.execute(
                "SELECT pg_catalog.to_regnamespace('profile') IS NOT NULL,"
                "pg_catalog.to_regclass('profile.schema_migrations') IS NOT NULL"
            ).fetchone()
            if schema_exists and not ledger_exists:
                raise ProfileMigrationRunnerError("PROFILE_MIGRATION_LEDGER_DRIFT")
            applied_rows = ()
            if ledger_exists:
                applied_rows = tuple(
                    connection.execute(
                        "SELECT version,phase,name,checksum_sha256,manifest_sha256 "
                        "FROM profile.schema_migrations "
                        "WHERE component='profile' ORDER BY version"
                    ).fetchall()
                )
            if len(applied_rows) > len(catalog.artifacts):
                raise ProfileMigrationRunnerError("PROFILE_MIGRATION_LEDGER_DRIFT")
            for row, artifact in zip(applied_rows, catalog.artifacts):
                if row != (
                    artifact.descriptor.version,
                    artifact.descriptor.phase.value,
                    artifact.descriptor.name,
                    artifact.descriptor.checksum_sha256,
                    artifact.descriptor.prefix_manifest_sha256,
                ):
                    raise ProfileMigrationRunnerError(
                        "PROFILE_MIGRATION_LEDGER_DRIFT"
                    )

            applied = []
            for artifact in catalog.artifacts[len(applied_rows) :]:
                descriptor = artifact.descriptor
                connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED")
                transaction = True
                connection.execute(
                    "SELECT pg_catalog.set_config('lock_timeout','5000ms',true)"
                )
                connection.execute(
                    "SELECT pg_catalog.set_config('statement_timeout','30000ms',true)"
                )
                connection.execute(artifact.sql_bytes.decode("utf-8"))
                connection.execute(
                    "INSERT INTO profile.schema_migrations ("
                    "component,version,phase,name,checksum_sha256,manifest_sha256,"
                    "runner_version,applied_at) VALUES ("
                    "'profile',%s,%s,%s,%s,%s,%s,transaction_timestamp())",
                    (
                        descriptor.version,
                        descriptor.phase.value,
                        descriptor.name,
                        descriptor.checksum_sha256,
                        descriptor.prefix_manifest_sha256,
                        self._runner_version,
                    ),
                )
                if descriptor.version == PROFILE_SCHEMA_HEAD_VERSION:
                    connection.execute(
                        "INSERT INTO profile.schema_contracts ("
                        "singleton_key,schema_head_version,"
                        "min_app_compatible_version,max_app_compatible_version,"
                        "api_contract_sha256,event_contract_sha256,"
                        "domain_contract_sha256,migration_manifest_sha256,"
                        "generated_at) VALUES (true,%s,%s,%s,%s,%s,%s,%s,"
                        "transaction_timestamp()) "
                        "ON CONFLICT (singleton_key) DO UPDATE SET "
                        "schema_head_version=EXCLUDED.schema_head_version,"
                        "min_app_compatible_version="
                        "EXCLUDED.min_app_compatible_version,"
                        "max_app_compatible_version="
                        "EXCLUDED.max_app_compatible_version,"
                        "api_contract_sha256=EXCLUDED.api_contract_sha256,"
                        "event_contract_sha256=EXCLUDED.event_contract_sha256,"
                        "domain_contract_sha256=EXCLUDED.domain_contract_sha256,"
                        "migration_manifest_sha256="
                        "EXCLUDED.migration_manifest_sha256,"
                        "generated_at=EXCLUDED.generated_at",
                        (
                            PROFILE_SCHEMA_HEAD_VERSION,
                            PROFILE_SCHEMA_HEAD_VERSION,
                            PROFILE_SCHEMA_HEAD_VERSION,
                            hashlib.sha256(
                                contract_sources.api_contract_bytes
                            ).digest(),
                            hashlib.sha256(
                                contract_sources.event_contract_bytes
                            ).digest(),
                            hashlib.sha256(
                                contract_sources.domain_contract_bytes
                            ).digest(),
                            catalog.manifest_sha256,
                        ),
                    )
                connection.execute("COMMIT")
                transaction = False
                applied.append(descriptor.version)

            compatibility = connection.execute(
                "SELECT component,current_schema_version,schema_head_version,"
                "min_app_compatible_version,max_app_compatible_version,"
                "migration_manifest_sha256 "
                "FROM profile.schema_compatibility"
            ).fetchone()
            if compatibility != (
                "profile",
                PROFILE_SCHEMA_HEAD_VERSION,
                PROFILE_SCHEMA_HEAD_VERSION,
                PROFILE_SCHEMA_HEAD_VERSION,
                PROFILE_SCHEMA_HEAD_VERSION,
                catalog.manifest_sha256,
            ):
                raise ProfileMigrationRunnerError(
                    "PROFILE_MIGRATION_CONTRACT_DRIFT"
                )
            return ProfileMigrationRunReport(
                applied_versions=tuple(applied),
                skipped_versions=tuple(
                    artifact.descriptor.version
                    for artifact in catalog.artifacts[: len(applied_rows)]
                ),
            )
        except BaseException:
            if transaction:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    pass
            raise
        finally:
            if locked:
                try:
                    connection.execute(
                        "SELECT pg_catalog.pg_advisory_unlock(%s,%s)",
                        PROFILE_MIGRATION_LOCK,
                    )
                except BaseException:
                    pass
            try:
                connection.execute("RESET ROLE")
            finally:
                connection.close()
