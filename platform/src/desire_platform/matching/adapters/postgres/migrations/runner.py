"""Transactional runner for the independent Matching catalog."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
from typing import Any, Tuple

from .catalog import (
    MATCHING_MIGRATION_LAYOUT,
    MATCHING_REVIEWED_MANIFEST_SHA256,
    MatchingMigrationCatalog,
)


MATCHING_SCHEMA_HEAD_VERSION = MATCHING_MIGRATION_LAYOUT[-1][0]
MATCHING_MIGRATION_LOCK = (1296125512, 1)
MATCHING_REQUIRED_IAM_SCHEMA_VERSION = 46
MATCHING_REQUIRED_IAM_COMBINED_CONTRACT_SHA256 = bytes.fromhex(
    "14b0ae7a2ba2db7d6807b9b71080d40ab4b40b4e0e2664c5da0ac14fcb29c84d"
)
MATCHING_REQUIRED_PROFILE_SCHEMA_VERSION = 5
MATCHING_REQUIRED_PROFILE_MANIFEST_SHA256 = bytes.fromhex(
    "005be339b76c61427895ad7e6ddbb685735d7c602d99fc4dafdd08c35c97d4f8"
)
MATCHING_REQUIRED_DEMAND_SCHEMA_VERSION = 15
MATCHING_REQUIRED_DEMAND_IAM_SCHEMA_VERSION = 45
MATCHING_REQUIRED_DEMAND_MANIFEST_SHA256 = bytes.fromhex(
    "32d8587651d05e725a4277e2d253b8e195192f1dabc702dd5208b53fe8143f73"
)
MATCHING_REQUIRED_TRUST_SCHEMA_VERSION = 22
MATCHING_REQUIRED_TRUST_DEMAND_SCHEMA_VERSION = 15
MATCHING_REQUIRED_TRUST_IAM_CONTRACT_SHA256 = (
    MATCHING_REQUIRED_IAM_COMBINED_CONTRACT_SHA256
)
MATCHING_REQUIRED_TRUST_DEMAND_CONTRACT_SHA256 = bytes.fromhex(
    "ea6887891134ffa2f451fed35d469ae1c5195c54649e228f587622d95696dddf"
)
MATCHING_REQUIRED_TRUST_COMBINED_CONTRACT_SHA256 = bytes.fromhex(
    "68f3c3e90088f6d4383e73b3fbc6f77297cee27bc78086db227708bc872613f6"
)
MATCHING_REQUIRED_TRUST_MANIFEST_SHA256 = bytes.fromhex(
    "3fd3089db8139f4e70551f59f8e803fdf2543847d38d08f82f8a050c2dd921e8"
)


class MatchingMigrationRunnerError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class MatchingContractSources:
    api_contract_bytes: bytes
    event_contract_bytes: bytes
    rule_contract_bytes: bytes
    input_manifest_contract_bytes: bytes
    run_input_contract_bytes: bytes
    candidate_contract_bytes: bytes
    disclosure_contract_bytes: bytes

    def __post_init__(self) -> None:
        if any(
            not isinstance(value, bytes) or not value
            for value in (
                self.api_contract_bytes,
                self.event_contract_bytes,
                self.rule_contract_bytes,
                self.input_manifest_contract_bytes,
                self.run_input_contract_bytes,
                self.candidate_contract_bytes,
                self.disclosure_contract_bytes,
            )
        ):
            raise MatchingMigrationRunnerError(
                "MATCHING_MIGRATION_CONFIGURATION_INVALID"
            )


@dataclass(frozen=True)
class MatchingMigrationSettings:
    conninfo: str
    application_name: str = "desire-matching-migration-runner"

    def __post_init__(self) -> None:
        if (
            not self.conninfo
            or not self.application_name
            or len(self.application_name) > 96
        ):
            raise MatchingMigrationRunnerError(
                "MATCHING_MIGRATION_CONFIGURATION_INVALID"
            )


@dataclass(frozen=True)
class MatchingMigrationRunReport:
    applied_versions: Tuple[int, ...]
    skipped_versions: Tuple[int, ...]


class PsycopgMatchingMigrationDriver:
    def __init__(self, *, settings: MatchingMigrationSettings, dbapi: Any) -> None:
        if not isinstance(settings, MatchingMigrationSettings) or dbapi is None:
            raise MatchingMigrationRunnerError(
                "MATCHING_MIGRATION_CONFIGURATION_INVALID"
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


class MatchingMigrationRunner:
    def __init__(
        self,
        *,
        driver: PsycopgMatchingMigrationDriver,
        runner_version: str,
    ) -> None:
        if (
            not isinstance(driver, PsycopgMatchingMigrationDriver)
            or not runner_version
            or len(runner_version) > 96
        ):
            raise MatchingMigrationRunnerError(
                "MATCHING_MIGRATION_CONFIGURATION_INVALID"
            )
        self._driver = driver
        self._runner_version = runner_version

    def run(
        self,
        *,
        catalog: MatchingMigrationCatalog,
        contract_sources: MatchingContractSources,
    ) -> MatchingMigrationRunReport:
        if (
            not isinstance(catalog, MatchingMigrationCatalog)
            or not isinstance(contract_sources, MatchingContractSources)
            or not hmac.compare_digest(
                catalog.manifest_sha256,
                MATCHING_REVIEWED_MANIFEST_SHA256,
            )
        ):
            raise MatchingMigrationRunnerError(
                "MATCHING_MIGRATION_REVIEW_REQUIRED"
            )
        connection = self._driver.connect()
        locked = False
        transaction = False
        try:
            role_row = connection.execute(
                "SELECT session_user,current_user,"
                "current_setting('server_version_num')::integer/10000"
            ).fetchone()
            if role_row != (
                "matching_migration_runner",
                "matching_migration_runner",
                18,
            ):
                raise MatchingMigrationRunnerError(
                    "MATCHING_MIGRATION_PREFLIGHT_FAILED"
                )

            # IAM46 owns the exact creator, selector, and reviewer authority
            # resolvers plus the shared audit/outbox surfaces.
            # The deployment-only runner holds SET membership in schema_owner;
            # no Matching runtime role receives cross-context table access.
            connection.execute("SET ROLE schema_owner")
            dependency_row = connection.execute(
                "SELECT schema_head_version,"
                "pg_catalog.to_regprocedure("
                "'iam_api.verify_editor_principal_marker_v1(uuid,uuid,bytea)'"
                ") IS NOT NULL,"
                "pg_catalog.to_regprocedure("
                "'iam_api.resolve_candidate_selector_opt_in_marker_v1("
                "uuid,uuid,uuid,uuid,uuid,uuid)'"
                ") IS NOT NULL,"
                "pg_catalog.to_regprocedure("
                "'iam_api.resolve_matching_reviewer_authority_marker_v1("
                "uuid,uuid,uuid,uuid,uuid,text,uuid)'"
                ") IS NOT NULL,"
                "pg_catalog.to_regprocedure("
                "'iam_api.resolve_matching_creator_authority_marker_v1("
                "uuid,uuid,text,uuid,uuid)'"
                ") IS NOT NULL,"
                "pg_catalog.to_regclass('audit.audit_events') IS NOT NULL,"
                "pg_catalog.to_regclass('infra.outbox_events') IS NOT NULL "
                "FROM infra.iam_schema_compatibility"
            ).fetchone()
            connection.execute("RESET ROLE")
            if (
                dependency_row is None
                or dependency_row[0] != MATCHING_REQUIRED_IAM_SCHEMA_VERSION
                or dependency_row[1:] != (True,) * 6
            ):
                raise MatchingMigrationRunnerError(
                    "MATCHING_MIGRATION_IAM_DEPENDENCY_UNAVAILABLE"
                )

            connection.execute("SET ROLE matching_schema_owner")
            connection.execute(
                "SELECT pg_catalog.pg_advisory_lock(%s,%s)",
                MATCHING_MIGRATION_LOCK,
            )
            locked = True
            schema_exists, ledger_exists = connection.execute(
                "SELECT pg_catalog.to_regnamespace('matching') IS NOT NULL,"
                "pg_catalog.to_regclass("
                "'matching_meta.schema_migrations') IS NOT NULL"
            ).fetchone()
            if schema_exists and not ledger_exists:
                raise MatchingMigrationRunnerError(
                    "MATCHING_MIGRATION_LEDGER_DRIFT"
                )
            applied_rows = ()
            if ledger_exists:
                applied_rows = tuple(
                    connection.execute(
                        "SELECT version,phase,name,checksum_sha256,"
                        "manifest_sha256 "
                        "FROM matching_meta.schema_migrations "
                        "WHERE component='matching' ORDER BY version"
                    ).fetchall()
                )
            if len(applied_rows) > len(catalog.artifacts):
                raise MatchingMigrationRunnerError(
                    "MATCHING_MIGRATION_LEDGER_DRIFT"
                )
            for row, artifact in zip(applied_rows, catalog.artifacts):
                descriptor = artifact.descriptor
                if row != (
                    descriptor.version,
                    descriptor.phase.value,
                    descriptor.name,
                    descriptor.checksum_sha256,
                    descriptor.prefix_manifest_sha256,
                ):
                    raise MatchingMigrationRunnerError(
                        "MATCHING_MIGRATION_LEDGER_DRIFT"
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
                    "SELECT pg_catalog.set_config("
                    "'statement_timeout','30000ms',true)"
                )
                if descriptor.version == 3:
                    _grant_runtime_dependency_snapshot_access(connection)
                connection.execute(artifact.sql_bytes.decode("utf-8"))
                connection.execute(
                    "INSERT INTO matching_meta.schema_migrations ("
                    "component,version,phase,name,checksum_sha256,"
                    "manifest_sha256,runner_version,applied_at) VALUES ("
                    "'matching',%s,%s,%s,%s,%s,%s,"
                    "transaction_timestamp())",
                    (
                        descriptor.version,
                        descriptor.phase.value,
                        descriptor.name,
                        descriptor.checksum_sha256,
                        descriptor.prefix_manifest_sha256,
                        self._runner_version,
                    ),
                )
                if descriptor.version == MATCHING_SCHEMA_HEAD_VERSION:
                    connection.execute(
                        "INSERT INTO matching_meta.schema_contracts ("
                        "singleton_key,schema_head_version,"
                        "min_app_compatible_version,max_app_compatible_version,"
                        "required_iam_schema_version,api_contract_sha256,"
                        "event_contract_sha256,rule_contract_sha256,"
                        "input_manifest_contract_sha256,"
                        "run_input_contract_sha256,candidate_contract_sha256,"
                        "disclosure_contract_sha256,migration_manifest_sha256,"
                        "generated_at) VALUES ("
                        "true,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,"
                        "transaction_timestamp()) "
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
                        "rule_contract_sha256=EXCLUDED.rule_contract_sha256,"
                        "input_manifest_contract_sha256="
                        "EXCLUDED.input_manifest_contract_sha256,"
                        "run_input_contract_sha256="
                        "EXCLUDED.run_input_contract_sha256,"
                        "candidate_contract_sha256="
                        "EXCLUDED.candidate_contract_sha256,"
                        "disclosure_contract_sha256="
                        "EXCLUDED.disclosure_contract_sha256,"
                        "migration_manifest_sha256="
                        "EXCLUDED.migration_manifest_sha256,"
                        "generated_at=EXCLUDED.generated_at",
                        (
                            MATCHING_SCHEMA_HEAD_VERSION,
                            MATCHING_SCHEMA_HEAD_VERSION,
                            MATCHING_SCHEMA_HEAD_VERSION,
                            MATCHING_REQUIRED_IAM_SCHEMA_VERSION,
                            hashlib.sha256(
                                contract_sources.api_contract_bytes
                            ).digest(),
                            hashlib.sha256(
                                contract_sources.event_contract_bytes
                            ).digest(),
                            hashlib.sha256(
                                contract_sources.rule_contract_bytes
                            ).digest(),
                            hashlib.sha256(
                                contract_sources.input_manifest_contract_bytes
                            ).digest(),
                            hashlib.sha256(
                                contract_sources.run_input_contract_bytes
                            ).digest(),
                            hashlib.sha256(
                                contract_sources.candidate_contract_bytes
                            ).digest(),
                            hashlib.sha256(
                                contract_sources.disclosure_contract_bytes
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
                "FROM matching.schema_compatibility"
            ).fetchone()
            if compatibility != (
                "matching",
                MATCHING_SCHEMA_HEAD_VERSION,
                MATCHING_SCHEMA_HEAD_VERSION,
                MATCHING_SCHEMA_HEAD_VERSION,
                MATCHING_SCHEMA_HEAD_VERSION,
                MATCHING_REQUIRED_IAM_SCHEMA_VERSION,
                catalog.manifest_sha256,
            ):
                raise MatchingMigrationRunnerError(
                    "MATCHING_MIGRATION_CONTRACT_DRIFT"
                )
            return MatchingMigrationRunReport(
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
                        MATCHING_MIGRATION_LOCK,
                    )
                except BaseException:
                    pass
            try:
                connection.execute("RESET ROLE")
            finally:
                connection.close()


def _grant_runtime_dependency_snapshot_access(connection: Any) -> None:
    """Prove exact v3 runtime dependencies and grant only named metadata."""

    grants = (
        (
            "schema_owner",
            "infra",
            "infra.iam_schema_compatibility",
            (
                "component",
                "current_schema_version",
                "schema_head_version",
                "min_app_compatible_version",
                "max_app_compatible_version",
                "combined_contract_sha256",
            ),
            (
                MATCHING_REQUIRED_IAM_SCHEMA_VERSION,
                MATCHING_REQUIRED_IAM_SCHEMA_VERSION,
                MATCHING_REQUIRED_IAM_SCHEMA_VERSION,
                MATCHING_REQUIRED_IAM_SCHEMA_VERSION,
                MATCHING_REQUIRED_IAM_COMBINED_CONTRACT_SHA256,
            ),
            "MATCHING_MIGRATION_IAM_METADATA_UNAVAILABLE",
        ),
        (
            "demand_schema_owner",
            "demand",
            "demand.schema_compatibility",
            (
                "component",
                "current_schema_version",
                "schema_head_version",
                "min_app_compatible_version",
                "max_app_compatible_version",
                "required_iam_schema_version",
                "migration_manifest_sha256",
            ),
            (
                MATCHING_REQUIRED_DEMAND_SCHEMA_VERSION,
                MATCHING_REQUIRED_DEMAND_SCHEMA_VERSION,
                MATCHING_REQUIRED_DEMAND_SCHEMA_VERSION,
                MATCHING_REQUIRED_DEMAND_SCHEMA_VERSION,
                MATCHING_REQUIRED_DEMAND_IAM_SCHEMA_VERSION,
                MATCHING_REQUIRED_DEMAND_MANIFEST_SHA256,
            ),
            "MATCHING_MIGRATION_DEMAND15_DEPENDENCY_UNAVAILABLE",
        ),
        (
            "profile_schema_owner",
            "profile",
            "profile.schema_compatibility",
            (
                "component",
                "current_schema_version",
                "schema_head_version",
                "min_app_compatible_version",
                "max_app_compatible_version",
                "migration_manifest_sha256",
            ),
            (
                MATCHING_REQUIRED_PROFILE_SCHEMA_VERSION,
                MATCHING_REQUIRED_PROFILE_SCHEMA_VERSION,
                MATCHING_REQUIRED_PROFILE_SCHEMA_VERSION,
                MATCHING_REQUIRED_PROFILE_SCHEMA_VERSION,
                MATCHING_REQUIRED_PROFILE_MANIFEST_SHA256,
            ),
            "MATCHING_MIGRATION_PROFILE5_DEPENDENCY_UNAVAILABLE",
        ),
        (
            "trust_schema_owner",
            "trust",
            "trust.schema_compatibility",
            (
                "component",
                "current_schema_version",
                "schema_head_version",
                "min_app_compatible_version",
                "max_app_compatible_version",
                "required_iam_schema_version",
                "required_demand_schema_version",
                "required_iam_contract_sha256",
                "required_demand_contract_sha256",
                "combined_contract_sha256",
                "migration_manifest_sha256",
            ),
            (
                MATCHING_REQUIRED_TRUST_SCHEMA_VERSION,
                MATCHING_REQUIRED_TRUST_SCHEMA_VERSION,
                MATCHING_REQUIRED_TRUST_SCHEMA_VERSION,
                MATCHING_REQUIRED_TRUST_SCHEMA_VERSION,
                MATCHING_REQUIRED_IAM_SCHEMA_VERSION,
                MATCHING_REQUIRED_TRUST_DEMAND_SCHEMA_VERSION,
                MATCHING_REQUIRED_TRUST_IAM_CONTRACT_SHA256,
                MATCHING_REQUIRED_TRUST_DEMAND_CONTRACT_SHA256,
                MATCHING_REQUIRED_TRUST_COMBINED_CONTRACT_SHA256,
                MATCHING_REQUIRED_TRUST_MANIFEST_SHA256,
            ),
            "MATCHING_MIGRATION_TRUST22_DEPENDENCY_UNAVAILABLE",
        ),
    )
    for (
        owner_role,
        schema_name,
        relation_name,
        columns,
        expected,
        error_code,
    ) in grants:
        connection.execute(f"SET ROLE {owner_role}")
        exists = connection.execute(
            "SELECT pg_catalog.to_regclass(%s) IS NOT NULL",
            (relation_name,),
        ).fetchone()
        if exists != (True,):
            raise MatchingMigrationRunnerError(error_code)
        metadata = connection.execute(
            f"SELECT {','.join(columns[1:])} FROM {relation_name} "
            f"WHERE {columns[0]}=%s",
            (relation_name.split('.', 1)[0] if schema_name != "infra" else "iam",),
        ).fetchone()
        if metadata != expected:
            raise MatchingMigrationRunnerError(error_code)
        connection.execute(
            f"GRANT USAGE ON SCHEMA {schema_name} "
            "TO matching_schema_owner"
        )
        connection.execute(
            f"GRANT SELECT ({','.join(columns)}) ON TABLE "
            f"{relation_name} TO matching_schema_owner"
        )
    connection.execute("SET ROLE matching_schema_owner")
