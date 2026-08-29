from __future__ import annotations

from pathlib import Path
import unittest

from desire_platform.deployment import identity_bootstrap
from desire_platform.identity_access.adapters.postgres.migrations import (
    IAM_MIGRATION_LAYOUT,
    IAM_SCHEMA_HEAD_VERSION,
    MigrationPhase,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
FINANCE_IAM_PATH = (
    MIGRATION_ROOT / "0031_expand__finance_funding_authority_and_accounts.sql"
)


class FinanceFundingIamMigrationStaticTest(unittest.TestCase):
    def test_finance_authority_and_accounts_are_forward_only_iam_head(self) -> None:
        self.assertGreaterEqual(IAM_SCHEMA_HEAD_VERSION, 31)
        self.assertEqual(
            IAM_MIGRATION_LAYOUT[31],
            (
                31,
                MigrationPhase.EXPAND,
                "finance_funding_authority_and_accounts",
                "0031_expand__finance_funding_authority_and_accounts.sql",
            ),
        )
        self.assertEqual(
            identity_bootstrap._PROGRAM,
            "iam_api.manage_internal_sandbox_identity_bootstrap_v6",
        )

    def test_iam_sql_closes_finance_authority_and_six_account_graph(self) -> None:
        sql = FINANCE_IAM_PATH.read_text(encoding="utf-8")
        for marker in (
            "manage_internal_sandbox_identity_bootstrap_v3",
            "manage_internal_sandbox_identity_bootstrap_v2",
            "internal_sandbox_independent_role_graph_v3",
            "finance_operator_01",
            "finance_operator_02",
            "FINANCE_OPERATOR",
            "BOOTSTRAP_ROLE_ISOLATION",
            "authorize_finance_funding_queue_v1",
            "lock_finance_funding_authority_v1",
            "FINANCE_FUNDING",
            "CLAIM_FUNDING_REVIEW",
            "CONFIRM_FUNDING_REVIEW",
            "verify_finance_funding_principal_marker_v1",
            "session_user IS DISTINCT FROM 'demand_finance'",
            "SECURITY DEFINER",
            "FOR UPDATE",
            "REVOKE ALL ON FUNCTION",
            "TO demand_schema_owner",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, sql)
        self.assertNotIn("EXECUTE format", sql)
        self.assertNotIn("EXECUTE IMMEDIATE", sql)


if __name__ == "__main__":
    unittest.main()
