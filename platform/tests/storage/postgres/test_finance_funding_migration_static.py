from __future__ import annotations

from pathlib import Path
import unittest

from desire_platform.demand.adapters.postgres.migrations import (
    DEMAND_MIGRATION_LAYOUT,
    DEMAND_SCHEMA_HEAD_VERSION,
    DemandMigrationPhase,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT / "src/desire_platform/demand/adapters/postgres/migrations"
)
FINANCE_PATH = MIGRATION_ROOT / "0006_expand__manual_finance_funding_review.sql"


class FinanceFundingMigrationStaticTest(unittest.TestCase):
    def test_finance_slice_remains_the_frozen_predecessor_to_demand_head(self) -> None:
        self.assertGreaterEqual(DEMAND_SCHEMA_HEAD_VERSION, 8)
        self.assertEqual(
            DEMAND_MIGRATION_LAYOUT[5],
            (
                6,
                DemandMigrationPhase.EXPAND,
                "manual_finance_funding_review",
                "0006_expand__manual_finance_funding_review.sql",
            ),
        )
        self.assertTrue(FINANCE_PATH.is_file())

    def test_finance_sql_is_four_eyes_rls_occ_idempotent_audited_and_outboxed(self) -> None:
        sql = FINANCE_PATH.read_text(encoding="utf-8")
        for marker in (
            "demand.manual_funding_review_cases",
            "demand.manual_funding_review_assignments",
            "demand.manual_funding_confirmations",
            "demand.manual_funding_receipts",
            "ENABLE ROW LEVEL SECURITY",
            "FORCE ROW LEVEL SECURITY",
            "iam_api.authorize_finance_funding_queue_v1",
            "iam_api.lock_finance_funding_authority_v1",
            "expected_review_revision",
            "ON CONFLICT DO NOTHING",
            "finance_funding_idempotency_reused",
            "finance_funding_precondition_failed",
            "count(DISTINCT confirmation.actor_user_id) = 2",
            "sandbox_funds_amount_minor = 0",
            "INTERNAL_SANDBOX_ZERO_FUNDS_V1",
            "NO_REAL_FUNDS_OR_PAYMENT",
            "INSERT INTO demand.demand_funding_markers",
            "INSERT INTO audit.audit_events",
            "INSERT INTO infra.outbox_events",
            "DemandFundingRequested",
            "DemandFunded",
            "SECURITY DEFINER",
            "REVOKE ALL ON FUNCTION",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, sql)
        self.assertNotIn("provider_event", sql.lower())
        self.assertNotIn("payment_operation", sql.lower())
        self.assertNotIn("EXECUTE format", sql)
        self.assertNotIn("EXECUTE IMMEDIATE", sql)


if __name__ == "__main__":
    unittest.main()
