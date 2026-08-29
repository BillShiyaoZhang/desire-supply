"""Real PostgreSQL 18 RED for the exact current-Session logout program.

IAM36 owns the forward-only SQL.  This test deliberately freezes the function
ABI and its least-privilege execution boundary without registering a migration
from this implementation slice.
"""

from __future__ import annotations

from pathlib import Path
import unittest

import psycopg

from desire_platform.identity_access.adapters.postgres.current_session_logout import (
    CURRENT_SESSION_LOGOUT_FUNCTION_SIGNATURE,
)
from desire_platform.identity_access.adapters.postgres.migrations import (
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)


class CurrentSessionLogoutPostgresSignatureRedTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()
        cls.catalog = MigrationCatalog.load(MIGRATION_ROOT)
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
        driver = PsycopgMigrationDriver(
            settings=PsycopgMigrationSettings(
                conninfo=self.postgres.conninfo(
                    database=self.database,
                    user="iam_migration_runner",
                ),
                application_name="desire-current-session-logout-signature-red",
            ),
            dbapi=psycopg,
        )
        IamMigrationRunner(
            driver=driver,
            runner_version="current-session-logout-signature-red/1",
        ).run(catalog=self.catalog, contract_sources=self.contract_sources)

    def tearDown(self) -> None:
        self.postgres.drop_database(self.database)

    def test_exact_function_signature_security_and_acl(self) -> None:
        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database)
        ) as connection:
            row = connection.execute(
                "SELECT procedure.prosecdef,procedure.provolatile,"
                "procedure.proparallel,procedure.proconfig,"
                "pg_catalog.has_function_privilege('iam_app',%s,'EXECUTE'),"
                "pg_catalog.has_function_privilege('iam_session_authenticator',%s,'EXECUTE'),"
                "NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(COALESCE("
                "procedure.proacl,pg_catalog.acldefault('f',procedure.proowner))) AS acl "
                "WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE') "
                "FROM pg_catalog.pg_proc AS procedure "
                "WHERE procedure.oid=pg_catalog.to_regprocedure(%s)",
                (
                    CURRENT_SESSION_LOGOUT_FUNCTION_SIGNATURE,
                    CURRENT_SESSION_LOGOUT_FUNCTION_SIGNATURE,
                    CURRENT_SESSION_LOGOUT_FUNCTION_SIGNATURE,
                ),
            ).fetchone()

        self.assertIsNotNone(
            row,
            "IAM36 must publish the frozen current-Session logout ABI",
        )
        self.assertEqual(
            row,
            (
                True,
                "v",
                "u",
                ["search_path=pg_catalog, iam, infra, audit, iam_api"],
                True,
                False,
                True,
            ),
        )


if __name__ == "__main__":
    unittest.main()
