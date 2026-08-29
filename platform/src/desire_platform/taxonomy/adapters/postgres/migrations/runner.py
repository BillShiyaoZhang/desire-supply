"""Transactional runner for the independent Taxonomy catalog."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
from typing import Any, Tuple

from .catalog import (
    TAXONOMY_MIGRATION_LAYOUT,
    TAXONOMY_REVIEWED_MANIFEST_SHA256,
    TaxonomyMigrationCatalog,
)


TAXONOMY_SCHEMA_HEAD_VERSION = TAXONOMY_MIGRATION_LAYOUT[-1][0]
TAXONOMY_MIGRATION_LOCK = (1413567309, 1)


class TaxonomyMigrationRunnerError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class TaxonomyContractSources:
    api_contract_bytes: bytes
    event_contract_bytes: bytes
    release_contract_bytes: bytes


@dataclass(frozen=True)
class TaxonomyMigrationRunReport:
    applied_versions: Tuple[int, ...]
    skipped_versions: Tuple[int, ...]


class PsycopgTaxonomyMigrationRunner:
    def __init__(self, *, conninfo: str, dbapi: Any, runner_version: str) -> None:
        if not conninfo or not runner_version or len(runner_version) > 96:
            raise TaxonomyMigrationRunnerError(
                "TAXONOMY_MIGRATION_CONFIGURATION_INVALID"
            )
        self._conninfo = conninfo
        self._dbapi = dbapi
        self._runner_version = runner_version

    def run(
        self,
        *,
        catalog: TaxonomyMigrationCatalog,
        contract_sources: TaxonomyContractSources,
    ) -> TaxonomyMigrationRunReport:
        if not isinstance(catalog, TaxonomyMigrationCatalog) or not hmac.compare_digest(
            catalog.manifest_sha256, TAXONOMY_REVIEWED_MANIFEST_SHA256
        ):
            raise TaxonomyMigrationRunnerError(
                "TAXONOMY_MIGRATION_REVIEW_REQUIRED"
            )
        connection = self._dbapi.connect(
            self._conninfo,
            autocommit=True,
            application_name="desire-taxonomy-migration-runner",
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
                "taxonomy_migration_runner",
                "taxonomy_migration_runner",
                18,
            ):
                raise TaxonomyMigrationRunnerError(
                    "TAXONOMY_MIGRATION_PREFLIGHT_FAILED"
                )
            connection.execute("SET ROLE taxonomy_schema_owner")
            connection.execute(
                "SELECT pg_catalog.pg_advisory_lock(%s,%s)",
                TAXONOMY_MIGRATION_LOCK,
            )
            locked = True
            schema_exists, ledger_exists = connection.execute(
                "SELECT pg_catalog.to_regnamespace('taxonomy') IS NOT NULL,"
                "pg_catalog.to_regclass('taxonomy.schema_migrations') IS NOT NULL"
            ).fetchone()
            if schema_exists and not ledger_exists:
                raise TaxonomyMigrationRunnerError(
                    "TAXONOMY_MIGRATION_LEDGER_DRIFT"
                )
            applied_rows = ()
            if ledger_exists:
                applied_rows = tuple(
                    connection.execute(
                        "SELECT version,phase,name,checksum_sha256,manifest_sha256 "
                        "FROM taxonomy.schema_migrations "
                        "WHERE component='taxonomy' ORDER BY version"
                    ).fetchall()
                )
            if len(applied_rows) > len(catalog.artifacts):
                raise TaxonomyMigrationRunnerError(
                    "TAXONOMY_MIGRATION_LEDGER_DRIFT"
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
                    raise TaxonomyMigrationRunnerError(
                        "TAXONOMY_MIGRATION_LEDGER_DRIFT"
                    )
            applied = []
            for artifact in catalog.artifacts[len(applied_rows):]:
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
                    "INSERT INTO taxonomy.schema_migrations ("
                    "component,version,phase,name,checksum_sha256,manifest_sha256,"
                    "runner_version,applied_at) VALUES ("
                    "'taxonomy',%s,%s,%s,%s,%s,%s,transaction_timestamp())",
                    (
                        descriptor.version,
                        descriptor.phase.value,
                        descriptor.name,
                        descriptor.checksum_sha256,
                        descriptor.prefix_manifest_sha256,
                        self._runner_version,
                    ),
                )
                if descriptor.version == TAXONOMY_SCHEMA_HEAD_VERSION:
                    connection.execute(
                        "INSERT INTO taxonomy.schema_contracts ("
                        "singleton_key,schema_head_version,"
                        "min_app_compatible_version,max_app_compatible_version,"
                        "api_contract_sha256,event_contract_sha256,"
                        "release_contract_sha256,migration_manifest_sha256,"
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
                        "release_contract_sha256="
                        "EXCLUDED.release_contract_sha256,"
                        "migration_manifest_sha256="
                        "EXCLUDED.migration_manifest_sha256,"
                        "generated_at=EXCLUDED.generated_at",
                        (
                            TAXONOMY_SCHEMA_HEAD_VERSION,
                            TAXONOMY_SCHEMA_HEAD_VERSION,
                            TAXONOMY_SCHEMA_HEAD_VERSION,
                            hashlib.sha256(
                                contract_sources.api_contract_bytes
                            ).digest(),
                            hashlib.sha256(
                                contract_sources.event_contract_bytes
                            ).digest(),
                            hashlib.sha256(
                                contract_sources.release_contract_bytes
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
                "migration_manifest_sha256 FROM taxonomy.schema_compatibility"
            ).fetchone()
            if compatibility != (
                "taxonomy",
                TAXONOMY_SCHEMA_HEAD_VERSION,
                TAXONOMY_SCHEMA_HEAD_VERSION,
                TAXONOMY_SCHEMA_HEAD_VERSION,
                TAXONOMY_SCHEMA_HEAD_VERSION,
                catalog.manifest_sha256,
            ):
                raise TaxonomyMigrationRunnerError(
                    "TAXONOMY_MIGRATION_CONTRACT_DRIFT"
                )
            return TaxonomyMigrationRunReport(
                tuple(applied),
                tuple(
                    item.descriptor.version
                    for item in catalog.artifacts[:len(applied_rows)]
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
                        TAXONOMY_MIGRATION_LOCK,
                    )
                except BaseException:
                    pass
            try:
                connection.execute("RESET ROLE")
            finally:
                connection.close()
