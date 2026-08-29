"""Transactional runner for the independent Trust PostgreSQL catalog."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
from typing import Any, Tuple

from .catalog import (
    TRUST_MIGRATION_LAYOUT,
    TRUST_REVIEWED_MANIFEST_SHA256,
    TrustMigrationCatalog,
)


TRUST_SCHEMA_HEAD_VERSION = TRUST_MIGRATION_LAYOUT[-1][0]
TRUST_MIGRATION_LOCK = (1414678356, 1)
TRUST_REQUIRED_IAM_SCHEMA_VERSION = 46
TRUST_REQUIRED_DEMAND_SCHEMA_VERSION = 15
TRUST_REQUIRED_IAM_CONTRACT_SHA256 = bytes.fromhex(
    "14b0ae7a2ba2db7d6807b9b71080d40ab4b40b4e0e2664c5da0ac14fcb29c84d"
)
TRUST_REQUIRED_DEMAND_CONTRACT_SHA256 = bytes.fromhex(
    "ea6887891134ffa2f451fed35d469ae1c5195c54649e228f587622d95696dddf"
)
TRUST_API_CONTRACT_SHA256 = bytes.fromhex(
    "6647e16e9f8f0ab321ed9985eb2da4e591e2217fdaa43ba663355a4f152f44b2"
)
TRUST_EVENT_CONTRACT_SHA256 = bytes.fromhex(
    "a26c410ca62c6d996fd13148863935729f480ca1a1fd9a44378a96ab13eae582"
)
TRUST_REPORT_CONTRACT_SHA256 = bytes.fromhex(
    "29b0c97a576edf654b5517847c73ce7a059141158182b16008f2cce3ef996278"
)
TRUST_TRIAGE_CONTRACT_SHA256 = bytes.fromhex(
    "de45a368bc75f7523e9135b83f61ab8753581a1e775cffe943c7a70cbe6f3084"
)
TRUST_APPEAL_API_CONTRACT_SHA256 = bytes.fromhex(
    "ad0fd5874ad6d3343c62334805fe51c088df7b9db9215decfda95ee90a836e46"
)
TRUST_APPEAL_EVENT_CONTRACT_SHA256 = bytes.fromhex(
    "7d3916ab89ace8c677da6ba6b6b5a65cfae28b8d91cf0c71fc0b0d9a88a064ba"
)
TRUST_APPEAL_APPLICATION_CONTRACT_SHA256 = bytes.fromhex(
    "3549b053c911da3b5bf5b526c8abfc9e1ef9cdafd1f81e177d43cb412cab8223"
)
TRUST_APPEAL_REVIEW_CONTRACT_SHA256 = bytes.fromhex(
    "08982687c6654d606040c52faedc15a14b7b50e1c5c80db560587bbf3e16f72b"
)
TRUST_REVIEWED_COMBINED_CONTRACT_SHA256 = bytes.fromhex(
    "68f3c3e90088f6d4383e73b3fbc6f77297cee27bc78086db227708bc872613f6"
)
_EXPECTED_DEMAND_API_SHA256 = bytes.fromhex(
    "046561ae51d147e8df3b8fcf0b61f1dd922efe452175e63f128a937e8f11c4ff"
)
_EXPECTED_DEMAND_EVENT_SHA256 = bytes.fromhex(
    "46631be37cb70aea771d2103e1fe39dc39f3f4303239ae1dc6e55fa946d1059c"
)
_EXPECTED_DEMAND_CONTENT_SHA256 = bytes.fromhex(
    "4a3316ca66f58e92d23b946226b235578ad77e247f92f72863aa8f76c5b5c631"
)
_EXPECTED_DEMAND_MANIFEST_SHA256 = bytes.fromhex(
    "32d8587651d05e725a4277e2d253b8e195192f1dabc702dd5208b53fe8143f73"
)
_EXPECTED_DEMAND_REQUIRED_IAM_SCHEMA_VERSION = 45


class TrustMigrationRunnerError(RuntimeError):
    """Stable migration failure without connection or SQL details."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class TrustContractSources:
    api_contract_bytes: bytes
    event_contract_bytes: bytes
    report_contract_bytes: bytes
    triage_contract_bytes: bytes
    appeal_api_contract_bytes: bytes
    appeal_event_contract_bytes: bytes
    appeal_application_contract_bytes: bytes
    appeal_review_contract_bytes: bytes

    def __post_init__(self) -> None:
        if any(
            not isinstance(value, bytes) or not value
            for value in (
                self.api_contract_bytes,
                self.event_contract_bytes,
                self.report_contract_bytes,
                self.triage_contract_bytes,
                self.appeal_api_contract_bytes,
                self.appeal_event_contract_bytes,
                self.appeal_application_contract_bytes,
                self.appeal_review_contract_bytes,
            )
        ):
            raise TrustMigrationRunnerError(
                "TRUST_MIGRATION_CONFIGURATION_INVALID"
            )


@dataclass(frozen=True)
class TrustMigrationSettings:
    conninfo: str
    application_name: str = "desire-trust-migration-runner"

    def __post_init__(self) -> None:
        if (
            not isinstance(self.conninfo, str)
            or not self.conninfo
            or not isinstance(self.application_name, str)
            or not self.application_name
            or len(self.application_name) > 96
        ):
            raise TrustMigrationRunnerError(
                "TRUST_MIGRATION_CONFIGURATION_INVALID"
            )


@dataclass(frozen=True)
class TrustMigrationRunReport:
    applied_versions: Tuple[int, ...]
    skipped_versions: Tuple[int, ...]


class PsycopgTrustMigrationDriver:
    def __init__(self, *, settings: TrustMigrationSettings, dbapi: Any) -> None:
        if not isinstance(settings, TrustMigrationSettings) or dbapi is None:
            raise TrustMigrationRunnerError(
                "TRUST_MIGRATION_CONFIGURATION_INVALID"
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


def combined_contract_sha256(
    *,
    sources: TrustContractSources,
    migration_manifest_sha256: bytes,
) -> bytes:
    if (
        not isinstance(sources, TrustContractSources)
        or not isinstance(migration_manifest_sha256, bytes)
        or len(migration_manifest_sha256) != 32
    ):
        raise TrustMigrationRunnerError(
            "TRUST_MIGRATION_CONFIGURATION_INVALID"
        )
    parts = (
        "desire:trust:combined-contract:v2",
        TRUST_REQUIRED_IAM_CONTRACT_SHA256.hex(),
        TRUST_REQUIRED_DEMAND_CONTRACT_SHA256.hex(),
        hashlib.sha256(sources.api_contract_bytes).hexdigest(),
        hashlib.sha256(sources.event_contract_bytes).hexdigest(),
        hashlib.sha256(sources.report_contract_bytes).hexdigest(),
        hashlib.sha256(sources.triage_contract_bytes).hexdigest(),
        hashlib.sha256(sources.appeal_api_contract_bytes).hexdigest(),
        hashlib.sha256(sources.appeal_event_contract_bytes).hexdigest(),
        hashlib.sha256(sources.appeal_application_contract_bytes).hexdigest(),
        hashlib.sha256(sources.appeal_review_contract_bytes).hexdigest(),
        migration_manifest_sha256.hex(),
    )
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).digest()


class TrustMigrationRunner:
    def __init__(
        self,
        *,
        driver: PsycopgTrustMigrationDriver,
        runner_version: str,
    ) -> None:
        if (
            not isinstance(driver, PsycopgTrustMigrationDriver)
            or not isinstance(runner_version, str)
            or not runner_version
            or len(runner_version) > 96
        ):
            raise TrustMigrationRunnerError(
                "TRUST_MIGRATION_CONFIGURATION_INVALID"
            )
        self._driver = driver
        self._runner_version = runner_version

    def run(
        self,
        *,
        catalog: TrustMigrationCatalog,
        contract_sources: TrustContractSources,
    ) -> TrustMigrationRunReport:
        if (
            not isinstance(catalog, TrustMigrationCatalog)
            or not isinstance(contract_sources, TrustContractSources)
            or not hmac.compare_digest(
                catalog.manifest_sha256,
                TRUST_REVIEWED_MANIFEST_SHA256,
            )
        ):
            raise TrustMigrationRunnerError("TRUST_MIGRATION_REVIEW_REQUIRED")
        contract_hashes = (
            hashlib.sha256(contract_sources.api_contract_bytes).digest(),
            hashlib.sha256(contract_sources.event_contract_bytes).digest(),
            hashlib.sha256(contract_sources.report_contract_bytes).digest(),
            hashlib.sha256(contract_sources.triage_contract_bytes).digest(),
            hashlib.sha256(contract_sources.appeal_api_contract_bytes).digest(),
            hashlib.sha256(contract_sources.appeal_event_contract_bytes).digest(),
            hashlib.sha256(
                contract_sources.appeal_application_contract_bytes
            ).digest(),
            hashlib.sha256(contract_sources.appeal_review_contract_bytes).digest(),
        )
        if contract_hashes != (
            TRUST_API_CONTRACT_SHA256,
            TRUST_EVENT_CONTRACT_SHA256,
            TRUST_REPORT_CONTRACT_SHA256,
            TRUST_TRIAGE_CONTRACT_SHA256,
            TRUST_APPEAL_API_CONTRACT_SHA256,
            TRUST_APPEAL_EVENT_CONTRACT_SHA256,
            TRUST_APPEAL_APPLICATION_CONTRACT_SHA256,
            TRUST_APPEAL_REVIEW_CONTRACT_SHA256,
        ):
            raise TrustMigrationRunnerError("TRUST_MIGRATION_REVIEW_REQUIRED")
        combined = combined_contract_sha256(
            sources=contract_sources,
            migration_manifest_sha256=catalog.manifest_sha256,
        )
        if not hmac.compare_digest(
            combined,
            TRUST_REVIEWED_COMBINED_CONTRACT_SHA256,
        ):
            raise TrustMigrationRunnerError("TRUST_MIGRATION_REVIEW_REQUIRED")
        connection = self._driver.connect()
        locked = False
        transaction = False
        try:
            preflight = connection.execute(
                "SELECT session_user,current_user,"
                "current_setting('server_version_num')::integer/10000"
            ).fetchone()
            if preflight != (
                "trust_migration_runner",
                "trust_migration_runner",
                18,
            ):
                raise TrustMigrationRunnerError(
                    "TRUST_MIGRATION_PREFLIGHT_FAILED"
                )
            iam_dependency = connection.execute(
                "SELECT current_schema_version,schema_head_version,"
                "min_app_compatible_version,max_app_compatible_version,"
                "combined_contract_sha256 "
                "FROM infra.iam_schema_compatibility"
            ).fetchone()
            if iam_dependency != (
                TRUST_REQUIRED_IAM_SCHEMA_VERSION,
                TRUST_REQUIRED_IAM_SCHEMA_VERSION,
                TRUST_REQUIRED_IAM_SCHEMA_VERSION,
                TRUST_REQUIRED_IAM_SCHEMA_VERSION,
                TRUST_REQUIRED_IAM_CONTRACT_SHA256,
            ):
                raise TrustMigrationRunnerError(
                    "TRUST_MIGRATION_IAM_DEPENDENCY_UNAVAILABLE"
                )
            demand_dependency = connection.execute(
                "SELECT component,current_schema_version,schema_head_version,"
                "min_app_compatible_version,max_app_compatible_version,"
                "required_iam_schema_version,api_contract_sha256,"
                "event_contract_sha256,content_contract_sha256,"
                "migration_manifest_sha256,dependency_sha256 "
                "FROM demand.trust_schema_dependency_v1"
            ).fetchone()
            if demand_dependency != (
                "demand",
                TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
                TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
                TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
                TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
                _EXPECTED_DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
                _EXPECTED_DEMAND_API_SHA256,
                _EXPECTED_DEMAND_EVENT_SHA256,
                _EXPECTED_DEMAND_CONTENT_SHA256,
                _EXPECTED_DEMAND_MANIFEST_SHA256,
                TRUST_REQUIRED_DEMAND_CONTRACT_SHA256,
            ):
                raise TrustMigrationRunnerError(
                    "TRUST_MIGRATION_DEMAND_DEPENDENCY_UNAVAILABLE"
                )
            connection.execute("SET ROLE trust_schema_owner")
            capabilities = connection.execute(
                "SELECT pg_catalog.to_regprocedure("
                "'iam_api.resolve_trust_reporter_authority_v1(uuid,uuid,uuid,text)'"
                ") IS NOT NULL,pg_catalog.to_regprocedure("
                "'iam_api.resolve_trust_officer_authority_v1(uuid,uuid,text)'"
                ") IS NOT NULL,pg_catalog.to_regprocedure("
                "'demand_api.resolve_trust_report_target_v1(uuid,uuid,uuid,uuid,uuid,bigint,uuid,uuid,bytea)'"
                ") IS NOT NULL,pg_catalog.to_regprocedure("
                "'demand_api.resolve_trust_officer_conflict_v1(uuid,uuid,text,uuid,bigint,uuid,uuid,uuid,bytea)'"
                ") IS NOT NULL,pg_catalog.to_regprocedure("
                "'iam_api.resolve_appeal_reviewer_authority_v1(uuid,uuid,text)'"
                ") IS NOT NULL,pg_catalog.to_regprocedure("
                "'demand_api.resolve_appeal_applicant_party_v1(uuid,uuid,uuid,uuid,uuid,bigint,uuid,uuid,bytea)'"
                ") IS NOT NULL"
            ).fetchone()
            if capabilities != (True, True, True, True, True, True):
                raise TrustMigrationRunnerError(
                    "TRUST_MIGRATION_DEPENDENCY_CAPABILITY_UNAVAILABLE"
                )

            connection.execute(
                "SELECT pg_catalog.pg_advisory_lock(%s,%s)",
                TRUST_MIGRATION_LOCK,
            )
            locked = True
            schema_exists, ledger_exists = connection.execute(
                "SELECT pg_catalog.to_regnamespace('trust') IS NOT NULL,"
                "pg_catalog.to_regclass('trust_meta.schema_migrations') "
                "IS NOT NULL"
            ).fetchone()
            if schema_exists and not ledger_exists:
                raise TrustMigrationRunnerError("TRUST_MIGRATION_LEDGER_DRIFT")
            applied_rows = ()
            if ledger_exists:
                applied_rows = tuple(
                    connection.execute(
                        "SELECT version,phase,name,checksum_sha256,"
                        "manifest_sha256 FROM trust_meta.schema_migrations "
                        "WHERE component='trust' ORDER BY version"
                    ).fetchall()
                )
            if len(applied_rows) > len(catalog.artifacts):
                raise TrustMigrationRunnerError("TRUST_MIGRATION_LEDGER_DRIFT")
            for row, artifact in zip(applied_rows, catalog.artifacts):
                if row != (
                    artifact.descriptor.version,
                    artifact.descriptor.phase.value,
                    artifact.descriptor.name,
                    artifact.descriptor.checksum_sha256,
                    artifact.descriptor.prefix_manifest_sha256,
                ):
                    raise TrustMigrationRunnerError(
                        "TRUST_MIGRATION_LEDGER_DRIFT"
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
                connection.execute(artifact.sql_bytes.decode("utf-8"))
                connection.execute(
                    "INSERT INTO trust_meta.schema_migrations ("
                    "component,version,phase,name,checksum_sha256,"
                    "manifest_sha256,runner_version,applied_at) VALUES ("
                    "'trust',%s,%s,%s,%s,%s,%s,transaction_timestamp())",
                    (
                        descriptor.version,
                        descriptor.phase.value,
                        descriptor.name,
                        descriptor.checksum_sha256,
                        descriptor.prefix_manifest_sha256,
                        self._runner_version,
                    ),
                )
                if descriptor.version == TRUST_SCHEMA_HEAD_VERSION:
                    connection.execute(
                        "INSERT INTO trust_meta.schema_contracts ("
                        "singleton_key,schema_head_version,"
                        "min_app_compatible_version,max_app_compatible_version,"
                        "required_iam_schema_version,"
                        "required_demand_schema_version,"
                        "required_iam_contract_sha256,"
                        "required_demand_contract_sha256,api_contract_sha256,"
                        "event_contract_sha256,report_contract_sha256,"
                        "triage_contract_sha256,"
                        "appeal_api_contract_sha256,"
                        "appeal_event_contract_sha256,"
                        "appeal_application_contract_sha256,"
                        "appeal_review_contract_sha256,"
                        "combined_contract_sha256,"
                        "migration_manifest_sha256,generated_at) VALUES ("
                        "true,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,"
                        "%s,%s,%s,%s,transaction_timestamp()) "
                        "ON CONFLICT (singleton_key) DO UPDATE SET "
                        "schema_head_version=EXCLUDED.schema_head_version,"
                        "min_app_compatible_version="
                        "EXCLUDED.min_app_compatible_version,"
                        "max_app_compatible_version="
                        "EXCLUDED.max_app_compatible_version,"
                        "required_iam_schema_version="
                        "EXCLUDED.required_iam_schema_version,"
                        "required_demand_schema_version="
                        "EXCLUDED.required_demand_schema_version,"
                        "required_iam_contract_sha256="
                        "EXCLUDED.required_iam_contract_sha256,"
                        "required_demand_contract_sha256="
                        "EXCLUDED.required_demand_contract_sha256,"
                        "api_contract_sha256=EXCLUDED.api_contract_sha256,"
                        "event_contract_sha256="
                        "EXCLUDED.event_contract_sha256,"
                        "report_contract_sha256="
                        "EXCLUDED.report_contract_sha256,"
                        "triage_contract_sha256="
                        "EXCLUDED.triage_contract_sha256,"
                        "appeal_api_contract_sha256="
                        "EXCLUDED.appeal_api_contract_sha256,"
                        "appeal_event_contract_sha256="
                        "EXCLUDED.appeal_event_contract_sha256,"
                        "appeal_application_contract_sha256="
                        "EXCLUDED.appeal_application_contract_sha256,"
                        "appeal_review_contract_sha256="
                        "EXCLUDED.appeal_review_contract_sha256,"
                        "combined_contract_sha256="
                        "EXCLUDED.combined_contract_sha256,"
                        "migration_manifest_sha256="
                        "EXCLUDED.migration_manifest_sha256,"
                        "generated_at=EXCLUDED.generated_at",
                        (
                            TRUST_SCHEMA_HEAD_VERSION,
                            TRUST_SCHEMA_HEAD_VERSION,
                            TRUST_SCHEMA_HEAD_VERSION,
                            TRUST_REQUIRED_IAM_SCHEMA_VERSION,
                            TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
                            TRUST_REQUIRED_IAM_CONTRACT_SHA256,
                            TRUST_REQUIRED_DEMAND_CONTRACT_SHA256,
                            *contract_hashes,
                            combined,
                            catalog.manifest_sha256,
                        ),
                    )
                connection.execute("COMMIT")
                transaction = False
                applied.append(descriptor.version)

            compatibility = connection.execute(
                "SELECT component,current_schema_version,schema_head_version,"
                "min_app_compatible_version,max_app_compatible_version,"
                "required_iam_schema_version,required_demand_schema_version,"
                "required_iam_contract_sha256,"
                "required_demand_contract_sha256,"
                "combined_contract_sha256,migration_manifest_sha256 "
                "FROM trust.schema_compatibility"
            ).fetchone()
            if compatibility != (
                "trust",
                TRUST_SCHEMA_HEAD_VERSION,
                TRUST_SCHEMA_HEAD_VERSION,
                TRUST_SCHEMA_HEAD_VERSION,
                TRUST_SCHEMA_HEAD_VERSION,
                TRUST_REQUIRED_IAM_SCHEMA_VERSION,
                TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
                TRUST_REQUIRED_IAM_CONTRACT_SHA256,
                TRUST_REQUIRED_DEMAND_CONTRACT_SHA256,
                TRUST_REVIEWED_COMBINED_CONTRACT_SHA256,
                catalog.manifest_sha256,
            ):
                raise TrustMigrationRunnerError(
                    "TRUST_MIGRATION_CONTRACT_DRIFT"
                )
            return TrustMigrationRunReport(
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
                        TRUST_MIGRATION_LOCK,
                    )
                except BaseException:
                    pass
            try:
                connection.execute("RESET ROLE")
            finally:
                connection.close()


__all__ = [
    "PsycopgTrustMigrationDriver",
    "TRUST_APPEAL_API_CONTRACT_SHA256",
    "TRUST_APPEAL_APPLICATION_CONTRACT_SHA256",
    "TRUST_APPEAL_EVENT_CONTRACT_SHA256",
    "TRUST_APPEAL_REVIEW_CONTRACT_SHA256",
    "TRUST_API_CONTRACT_SHA256",
    "TRUST_EVENT_CONTRACT_SHA256",
    "TRUST_MIGRATION_LOCK",
    "TRUST_REPORT_CONTRACT_SHA256",
    "TRUST_REQUIRED_DEMAND_CONTRACT_SHA256",
    "TRUST_REQUIRED_DEMAND_SCHEMA_VERSION",
    "TRUST_REQUIRED_IAM_CONTRACT_SHA256",
    "TRUST_REQUIRED_IAM_SCHEMA_VERSION",
    "TRUST_REVIEWED_COMBINED_CONTRACT_SHA256",
    "TRUST_SCHEMA_HEAD_VERSION",
    "TRUST_TRIAGE_CONTRACT_SHA256",
    "TrustContractSources",
    "TrustMigrationRunReport",
    "TrustMigrationRunner",
    "TrustMigrationRunnerError",
    "TrustMigrationSettings",
    "combined_contract_sha256",
]
