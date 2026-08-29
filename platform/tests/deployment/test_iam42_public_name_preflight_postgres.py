"""PostgreSQL 18 evidence for the IAM42 deployment preflight."""

from __future__ import annotations

import unittest

import psycopg

from desire_platform.deployment import migrations
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18


class Iam42PublicNameDeploymentPreflightPostgresTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.postgres.stop()

    def setUp(self) -> None:
        self.database = self.postgres.create_database()

    def tearDown(self) -> None:
        self.postgres.drop_database(self.database)

    def _admin(self):
        return psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=True,
        )

    def test_fresh_valid_and_invalid_legacy_states_are_classified_in_database(
        self,
    ) -> None:
        with self._admin() as connection:
            fresh = migrations._preflight_iam42_public_names(connection)
            self.assertEqual(fresh.relation_state, "ABSENT")
            self.assertEqual(fresh.inspected_organization_count, 0)
            self.assertEqual(fresh.status, "PASSED")

            connection.execute("CREATE SCHEMA iam")
            connection.execute(
                "CREATE TABLE iam.organizations(public_name text)"
            )
            connection.execute(
                "INSERT INTO iam.organizations(public_name) VALUES (%s),(%s)",
                ("Canonical Organization", "Caf\u00e9"),
            )

            valid = migrations._preflight_iam42_public_names(connection)
            self.assertEqual(valid.relation_state, "PRESENT")
            self.assertEqual(valid.inspected_organization_count, 2)
            self.assertEqual(valid.invalid_organization_count, 0)
            self.assertEqual(valid.status, "PASSED")

            connection.execute(
                "INSERT INTO iam.organizations(public_name) "
                "SELECT unnest(%s::text[])",
                (["x" * 161, "e\u0301", " leading", "zero\u200bwidth", None],),
            )
            with self.assertRaises(
                migrations.DeploymentIam42PublicNamePreflightError
            ) as raised:
                migrations._preflight_iam42_public_names(connection)

        report = raised.exception.report
        self.assertEqual(report.relation_state, "PRESENT")
        self.assertEqual(report.inspected_organization_count, 7)
        self.assertEqual(report.invalid_organization_count, 5)
        self.assertEqual(report.length_violation_count, 2)
        self.assertEqual(report.non_nfc_count, 2)
        self.assertEqual(report.edge_whitespace_count, 2)
        self.assertEqual(report.forbidden_codepoint_count, 2)
        self.assertEqual(report.status, "BLOCKED")
        self.assertNotIn("leading", repr(raised.exception))
        self.assertNotIn("zero", repr(raised.exception))


if __name__ == "__main__":
    unittest.main()
