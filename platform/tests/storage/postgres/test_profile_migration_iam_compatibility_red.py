"""TDD gate for Profile migrations' narrow IAM compatibility dependency."""

from __future__ import annotations

from pathlib import Path
import unittest

import psycopg

from desire_platform.identity_access.adapters.postgres.migrations import (
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
IAM_MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)


class ProfileMigrationIamCompatibilityRealPostgresRedTest(unittest.TestCase):
    """TEST-PG-IAM-PROFILE-MIGRATION-DEPENDENCY-001."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()
        cls.catalog = MigrationCatalog.load(IAM_MIGRATION_ROOT)
        cls.contract_sources = IamContractSources(
            api_contract_bytes=(
                PLATFORM_ROOT / "contracts/api/iam-v1.openapi.yaml"
            ).read_bytes(),
            event_contract_bytes=(
                PLATFORM_ROOT / "contracts/events/iam-v1.schema.json"
            ).read_bytes(),
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.postgres.stop()

    def setUp(self) -> None:
        self.database = self.postgres.create_database()
        report = IamMigrationRunner(
            driver=PsycopgMigrationDriver(
                settings=PsycopgMigrationSettings(
                    conninfo=self.postgres.conninfo(
                        database=self.database,
                        user="iam_migration_runner",
                    ),
                    application_name="desire-profile-migration-iam-dependency",
                ),
                dbapi=psycopg,
            ),
            runner_version="profile-migration-iam-dependency/1",
        ).run(catalog=self.catalog, contract_sources=self.contract_sources)
        self.assertEqual(
            report.applied_versions,
            tuple(artifact.descriptor.version for artifact in self.catalog.artifacts),
        )

    def tearDown(self) -> None:
        self.postgres.drop_database(self.database)

    def test_profile_runner_reads_only_closed_iam_compatibility_projection(self) -> None:
        with psycopg.connect(
            self.postgres.conninfo(
                database=self.database,
                user="profile_migration_runner",
            ),
            autocommit=False,
        ) as connection:
            compatibility = connection.execute(
                "SELECT current_schema_version,schema_head_version,"
                "min_app_compatible_version,max_app_compatible_version "
                "FROM infra.iam_schema_compatibility"
            ).fetchone()
            head = self.catalog.artifacts[-1].descriptor.version
            self.assertEqual(compatibility, (head, head, head, head))

            for forbidden_query in (
                "SELECT component FROM infra.iam_schema_contracts",
                "SELECT component FROM infra.schema_migrations",
                "SELECT id FROM iam.users LIMIT 1",
            ):
                with self.subTest(query=forbidden_query):
                    connection.rollback()
                    with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                        connection.execute(forbidden_query).fetchone()

            connection.rollback()
            self.assertFalse(
                connection.execute(
                    "SELECT has_schema_privilege(current_user,'iam_api','USAGE')"
                ).fetchone()[0]
            )

        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=True,
        ) as admin:
            self.assertFalse(
                admin.execute(
                    "SELECT has_function_privilege("
                    "'profile_migration_runner',"
                    "'iam_api.resolve_profile_self_authority_marker_v1"
                    "(uuid,uuid,text,uuid)',"
                    "'EXECUTE')"
                ).fetchone()[0]
            )


if __name__ == "__main__":
    unittest.main()
