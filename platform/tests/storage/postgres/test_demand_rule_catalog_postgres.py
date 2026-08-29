"""Real PostgreSQL 18 acceptance for the Demand rule-catalog dependency."""

from __future__ import annotations

from pathlib import Path
import unittest

import psycopg

from desire_platform.demand.adapters.postgres import PsycopgDemandRuleCatalog
from desire_platform.demand.adapters.postgres.migrations import (
    DemandContractSources,
    DemandMigrationCatalog,
    DemandMigrationRunner,
    DemandMigrationSettings,
    PsycopgDemandMigrationDriver,
)
from desire_platform.demand.ports.commands import DemandRuleCatalogUnavailableError
from desire_platform.identity_access.adapters.postgres.migrations import (
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from desire_platform.internal_pilot.synthetic_seed import (
    load_internal_sandbox_synthetic_seed,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18
from tests.support.demand_postgres_builders import TrackingDemandConnectionSource


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
IAM_MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
DEMAND_MIGRATION_ROOT = (
    PLATFORM_ROOT / "src/desire_platform/demand/adapters/postgres/migrations"
)
ORGANIZATION_ID = "60000000-0000-4000-8000-000000000001"
DEMAND_ID = "61000000-0000-4000-8000-000000000001"


class RealPostgres18DemandRuleCatalogTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()
        cls.database = cls.postgres.create_database()
        cls.iam_catalog = MigrationCatalog.load(IAM_MIGRATION_ROOT)
        cls.iam_report = IamMigrationRunner(
            driver=PsycopgMigrationDriver(
                settings=PsycopgMigrationSettings(
                    conninfo=cls.postgres.conninfo(
                        database=cls.database,
                        user="iam_migration_runner",
                    ),
                    application_name="desire-rule-catalog-pg18",
                ),
                dbapi=psycopg,
            ),
            runner_version="demand-rule-catalog-pg18/1",
        ).run(
            catalog=cls.iam_catalog,
            contract_sources=IamContractSources(
                api_contract_bytes=(
                    PLATFORM_ROOT / "contracts/api/iam-v1.openapi.yaml"
                ).read_bytes(),
                event_contract_bytes=(
                    PLATFORM_ROOT / "contracts/events/iam-v1.schema.json"
                ).read_bytes(),
            ),
        )
        cls.demand_catalog = DemandMigrationCatalog.load(DEMAND_MIGRATION_ROOT)
        cls.demand_report = DemandMigrationRunner(
            driver=PsycopgDemandMigrationDriver(
                settings=DemandMigrationSettings(
                    conninfo=cls.postgres.conninfo(
                        database=cls.database,
                        user="demand_migration_runner",
                    ),
                    application_name="desire-rule-catalog-demand-pg18",
                ),
                dbapi=psycopg,
            ),
            runner_version="demand-rule-catalog-pg18/1",
        ).run(
            catalog=cls.demand_catalog,
            contract_sources=DemandContractSources(
                api_contract_bytes=(
                    PLATFORM_ROOT / "contracts/api/demand-v1.openapi.yaml"
                ).read_bytes(),
                event_contract_bytes=(
                    PLATFORM_ROOT / "contracts/events/demand-v1.schema.json"
                ).read_bytes(),
                content_contract_bytes=(
                    PLATFORM_ROOT
                    / "contracts/domain/demand-content-v1.schema.json"
                ).read_bytes(),
            ),
        )
        if cls.iam_report.applied_versions != tuple(
            artifact.descriptor.version for artifact in cls.iam_catalog.artifacts
        ):
            raise AssertionError("IAM catalog was not applied exactly")
        if cls.demand_report.applied_versions != tuple(
            artifact.descriptor.version for artifact in cls.demand_catalog.artifacts
        ):
            raise AssertionError("Demand catalog was not applied exactly")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.postgres.drop_database(cls.database)
        cls.postgres.stop()

    def setUp(self) -> None:
        self.sources = []

    def tearDown(self) -> None:
        for source in self.sources:
            source.close()

    def _source(self, role: str = "demand_self") -> TrackingDemandConnectionSource:
        source = TrackingDemandConnectionSource(
            self.postgres.conninfo(database=self.database, user=role)
        )
        self.sources.append(source)
        return source

    def test_fresh_catalog_matches_the_reviewed_synthetic_plan_without_business_facts(
        self,
    ) -> None:
        source = self._source()
        catalog = PsycopgDemandRuleCatalog(connections=source)
        requirement = catalog.current_requirement(
            organization_id=ORGANIZATION_ID,
            demand_id=DEMAND_ID,
            operation="SUBMIT_DEMAND",
        )

        plan = load_internal_sandbox_synthetic_seed()
        self.assertIsNone(plan.validate_rule_requirement(requirement))
        self.assertIsNone(catalog.check_readiness(timeout_ms=1_000))
        self.assertEqual(len(source.released), 2)
        self.assertEqual(source.discarded, [])
        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database), autocommit=True
        ) as connection:
            facts = connection.execute(
                "SELECT "
                "(SELECT count(*) FROM demand.receipt_key_policy),"
                "(SELECT count(*) FROM demand.demands),"
                "(SELECT count(*) FROM demand.demand_versions),"
                "(SELECT count(*) FROM demand.demand_funding_markers),"
                "(SELECT count(*) FROM demand.command_receipts)"
            ).fetchone()
        self.assertEqual(facts, (1, 0, 0, 0, 0))

    def test_wrong_runtime_role_and_ungranted_matching_role_fail_closed(self) -> None:
        wrong_source = self._source("demand_review")
        catalog = PsycopgDemandRuleCatalog(connections=wrong_source)
        with self.assertRaises(DemandRuleCatalogUnavailableError):
            catalog.current_requirement(
                organization_id=ORGANIZATION_ID,
                demand_id=DEMAND_ID,
                operation="VERIFY_DEMAND",
            )
        self.assertEqual(wrong_source.released, [])
        self.assertEqual(len(wrong_source.discarded), 1)

        with psycopg.connect(
            self.postgres.conninfo(
                database=self.database,
                user="demand_matching",
            ),
            autocommit=True,
        ) as connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    "SELECT taxonomy_bundle_id "
                    "FROM demand.receipt_key_policy WHERE singleton_key"
                ).fetchone()


if __name__ == "__main__":
    unittest.main()
