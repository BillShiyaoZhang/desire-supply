"""Transactional runner for the independent Demand catalog."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
from typing import Any, Tuple

from .catalog import (
    DEMAND_MIGRATION_LAYOUT,
    DEMAND_REVIEWED_MANIFEST_SHA256,
    DemandMigrationCatalog,
)


DEMAND_SCHEMA_HEAD_VERSION = DEMAND_MIGRATION_LAYOUT[-1][0]
DEMAND_MIGRATION_LOCK = (1145392462, 1)
DEMAND_REQUIRED_IAM_SCHEMA_VERSION = 48


class DemandMigrationRunnerError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class DemandContractSources:
    api_contract_bytes: bytes
    event_contract_bytes: bytes
    content_contract_bytes: bytes


@dataclass(frozen=True)
class DemandMigrationSettings:
    conninfo: str
    application_name: str = "desire-demand-migration-runner"

    def __post_init__(self) -> None:
        if (
            not self.conninfo
            or not self.application_name
            or len(self.application_name) > 96
        ):
            raise DemandMigrationRunnerError(
                "DEMAND_MIGRATION_CONFIGURATION_INVALID"
            )


@dataclass(frozen=True)
class DemandMigrationRunReport:
    applied_versions: Tuple[int, ...]
    skipped_versions: Tuple[int, ...]


class PsycopgDemandMigrationDriver:
    def __init__(self, *, settings: DemandMigrationSettings, dbapi: Any) -> None:
        if not isinstance(settings, DemandMigrationSettings) or dbapi is None:
            raise DemandMigrationRunnerError(
                "DEMAND_MIGRATION_CONFIGURATION_INVALID"
            )
        self.settings = settings
        self.dbapi = dbapi

    def connect(self) -> Any:
        return self.dbapi.connect(
            self.settings.conninfo,
            autocommit=True,
            application_name=self.settings.application_name,
            connect_timeout=5,
        )


class DemandMigrationRunner:
    def __init__(
        self,
        *,
        driver: PsycopgDemandMigrationDriver,
        runner_version: str,
    ) -> None:
        if (
            not isinstance(driver, PsycopgDemandMigrationDriver)
            or not runner_version
            or len(runner_version) > 96
        ):
            raise DemandMigrationRunnerError(
                "DEMAND_MIGRATION_CONFIGURATION_INVALID"
            )
        self._driver = driver
        self._runner_version = runner_version

    def run(
        self,
        *,
        catalog: DemandMigrationCatalog,
        contract_sources: DemandContractSources,
    ) -> DemandMigrationRunReport:
        if (
            not isinstance(catalog, DemandMigrationCatalog)
            or not hmac.compare_digest(
                catalog.manifest_sha256,
                DEMAND_REVIEWED_MANIFEST_SHA256,
            )
        ):
            raise DemandMigrationRunnerError("DEMAND_MIGRATION_REVIEW_REQUIRED")
        connection = self._driver.connect()
        locked = False
        transaction = False
        try:
            role_row = connection.execute(
                "SELECT session_user,current_user,"
                "current_setting('server_version_num')::integer/10000"
            ).fetchone()
            if role_row != (
                "demand_migration_runner",
                "demand_migration_runner",
                18,
            ):
                raise DemandMigrationRunnerError(
                    "DEMAND_MIGRATION_PREFLIGHT_FAILED"
                )
            (
                iam_head,
                owner_capability,
                reviewer_capability,
                review_claim_capability,
                review_queue_capability,
                principal_verifier,
                owner_marker_resolver,
                reviewer_marker_resolver,
                trust_reporter_marker_resolver,
                trust_officer_marker_resolver,
                trust_party_conflict_resolver,
                finance_resolution_authority,
            ) = connection.execute(
                "SELECT schema_head_version,"
                "pg_catalog.to_regprocedure("
                "'iam_api.lock_demand_owner_authority_v1(uuid,uuid,uuid,text,uuid,bytea)'"
                ") IS NOT NULL,pg_catalog.to_regprocedure("
                "'iam_api.lock_demand_reviewer_authority_v2(uuid,uuid,uuid,uuid,uuid,text,bytea)'"
                ") IS NOT NULL,pg_catalog.to_regprocedure("
                "'iam_api.lock_demand_review_claim_authority_v1(uuid,uuid,uuid,uuid,bytea)'"
                ") IS NOT NULL,pg_catalog.to_regprocedure("
                "'iam_api.authorize_demand_review_queue_v1(uuid,uuid,bytea)'"
                ") IS NOT NULL,pg_catalog.to_regprocedure("
                "'iam_api.verify_editor_principal_marker_v1(uuid,uuid,bytea)'"
                ") IS NOT NULL,pg_catalog.to_regprocedure("
                "'iam_api.resolve_demand_owner_authority_marker_v1(uuid,uuid,uuid,text,uuid)'"
                ") IS NOT NULL,pg_catalog.to_regprocedure("
                "'iam_api.resolve_demand_reviewer_authority_marker_v2(uuid,uuid,uuid,text,uuid,uuid)'"
                ") IS NOT NULL,pg_catalog.to_regprocedure("
                "'iam_api.resolve_trust_reporter_authority_marker_v1(uuid,uuid,uuid,text,uuid,uuid,bigint)'"
                ") IS NOT NULL,pg_catalog.to_regprocedure("
                "'iam_api.resolve_trust_officer_authority_marker_v1(uuid,uuid,text,uuid,bigint)'"
                ") IS NOT NULL,pg_catalog.to_regprocedure("
                "'iam_api.resolve_trust_party_conflict_facts_v1(uuid,uuid,uuid,text,uuid,bigint,bytea)'"
                ") IS NOT NULL,pg_catalog.to_regprocedure("
                "'iam_api.lock_finance_funding_authority_v2(uuid,uuid,uuid,uuid,uuid,uuid,text,bytea)'"
                ") IS NOT NULL FROM infra.iam_schema_compatibility"
            ).fetchone()
            if (
                iam_head < DEMAND_REQUIRED_IAM_SCHEMA_VERSION
                or owner_capability is not True
                or reviewer_capability is not True
                or review_claim_capability is not True
                or review_queue_capability is not True
                or principal_verifier is not True
                or owner_marker_resolver is not True
                or reviewer_marker_resolver is not True
                or trust_reporter_marker_resolver is not True
                or trust_officer_marker_resolver is not True
                or trust_party_conflict_resolver is not True
                or finance_resolution_authority is not True
            ):
                raise DemandMigrationRunnerError(
                    "DEMAND_MIGRATION_IAM_DEPENDENCY_UNAVAILABLE"
                )
            connection.execute("SET ROLE demand_schema_owner")
            connection.execute(
                "SELECT pg_catalog.pg_advisory_lock(%s,%s)",
                DEMAND_MIGRATION_LOCK,
            )
            locked = True
            schema_exists, ledger_exists = connection.execute(
                "SELECT pg_catalog.to_regnamespace('demand') IS NOT NULL,"
                "pg_catalog.to_regclass('demand_meta.schema_migrations') IS NOT NULL"
            ).fetchone()
            if schema_exists and not ledger_exists:
                raise DemandMigrationRunnerError("DEMAND_MIGRATION_LEDGER_DRIFT")
            applied_rows = ()
            if ledger_exists:
                applied_rows = tuple(
                    connection.execute(
                        "SELECT version,phase,name,checksum_sha256,manifest_sha256 "
                        "FROM demand_meta.schema_migrations "
                        "WHERE component='demand' ORDER BY version"
                    ).fetchall()
                )
            if len(applied_rows) > len(catalog.artifacts):
                raise DemandMigrationRunnerError("DEMAND_MIGRATION_LEDGER_DRIFT")
            for row, artifact in zip(applied_rows, catalog.artifacts):
                if row != (
                    artifact.descriptor.version,
                    artifact.descriptor.phase.value,
                    artifact.descriptor.name,
                    artifact.descriptor.checksum_sha256,
                    artifact.descriptor.prefix_manifest_sha256,
                ):
                    raise DemandMigrationRunnerError(
                        "DEMAND_MIGRATION_LEDGER_DRIFT"
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
                    "INSERT INTO demand_meta.schema_migrations ("
                    "component,version,phase,name,checksum_sha256,manifest_sha256,"
                    "runner_version,applied_at) VALUES ("
                    "'demand',%s,%s,%s,%s,%s,%s,transaction_timestamp())",
                    (
                        descriptor.version,
                        descriptor.phase.value,
                        descriptor.name,
                        descriptor.checksum_sha256,
                        descriptor.prefix_manifest_sha256,
                        self._runner_version,
                    ),
                )
                if descriptor.version == DEMAND_SCHEMA_HEAD_VERSION:
                    connection.execute(
                        "INSERT INTO demand_meta.schema_contracts ("
                        "singleton_key,schema_head_version,"
                        "min_app_compatible_version,max_app_compatible_version,"
                        "required_iam_schema_version,api_contract_sha256,"
                        "event_contract_sha256,content_contract_sha256,"
                        "migration_manifest_sha256,generated_at) VALUES ("
                        "true,%s,%s,%s,%s,%s,%s,%s,%s,transaction_timestamp()) "
                        "ON CONFLICT (singleton_key) DO UPDATE SET "
                        "schema_head_version=EXCLUDED.schema_head_version,"
                        "min_app_compatible_version="
                        "EXCLUDED.min_app_compatible_version,"
                        "max_app_compatible_version="
                        "EXCLUDED.max_app_compatible_version,"
                        "required_iam_schema_version="
                        "EXCLUDED.required_iam_schema_version,"
                        "api_contract_sha256=EXCLUDED.api_contract_sha256,"
                        "event_contract_sha256=EXCLUDED.event_contract_sha256,"
                        "content_contract_sha256="
                        "EXCLUDED.content_contract_sha256,"
                        "migration_manifest_sha256="
                        "EXCLUDED.migration_manifest_sha256,"
                        "generated_at=EXCLUDED.generated_at",
                        (
                            DEMAND_SCHEMA_HEAD_VERSION,
                            DEMAND_SCHEMA_HEAD_VERSION,
                            DEMAND_SCHEMA_HEAD_VERSION,
                            DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
                            hashlib.sha256(contract_sources.api_contract_bytes).digest(),
                            hashlib.sha256(contract_sources.event_contract_bytes).digest(),
                            hashlib.sha256(
                                contract_sources.content_contract_bytes
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
                "required_iam_schema_version,migration_manifest_sha256 "
                "FROM demand.schema_compatibility"
            ).fetchone()
            if compatibility != (
                "demand",
                DEMAND_SCHEMA_HEAD_VERSION,
                DEMAND_SCHEMA_HEAD_VERSION,
                DEMAND_SCHEMA_HEAD_VERSION,
                DEMAND_SCHEMA_HEAD_VERSION,
                DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
                catalog.manifest_sha256,
            ):
                raise DemandMigrationRunnerError(
                    "DEMAND_MIGRATION_CONTRACT_DRIFT"
                )
            return DemandMigrationRunReport(
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
                        DEMAND_MIGRATION_LOCK,
                    )
                except BaseException:
                    pass
            try:
                connection.execute("RESET ROLE")
            finally:
                connection.close()
