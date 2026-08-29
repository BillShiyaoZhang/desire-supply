from __future__ import annotations

import hashlib
from pathlib import Path
import unittest

from desire_platform.demand.adapters.postgres.migrations import (
    DEMAND_MIGRATION_LAYOUT,
    DEMAND_REVIEWED_MANIFEST_SHA256,
    DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
    DEMAND_SCHEMA_HEAD_VERSION,
    DemandMigrationCatalog,
    DemandMigrationPhase,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT / "src/desire_platform/demand/adapters/postgres/migrations"
)
QUEUE_PATH = MIGRATION_ROOT / "0003_expand__internal_sandbox_review_queue.sql"
HARDENING_PATH = MIGRATION_ROOT / "0004_expand__review_queue_null_hardening.sql"
CLAIM_LOCK_PATH = MIGRATION_ROOT / "0005_expand__review_queue_claim_lock_rls.sql"


class DemandReviewQueueMigrationStaticTest(unittest.TestCase):
    def test_reviewed_forward_only_queue_hardening_is_byte_exact(self) -> None:
        catalog = DemandMigrationCatalog.load(MIGRATION_ROOT)

        self.assertGreaterEqual(DEMAND_SCHEMA_HEAD_VERSION, 5)
        self.assertGreaterEqual(DEMAND_REQUIRED_IAM_SCHEMA_VERSION, 25)
        self.assertEqual(
            DEMAND_MIGRATION_LAYOUT[2:5],
            (
                (
                    3,
                    DemandMigrationPhase.EXPAND,
                    "internal_sandbox_review_queue",
                    "0003_expand__internal_sandbox_review_queue.sql",
                ),
                (
                    4,
                    DemandMigrationPhase.EXPAND,
                    "review_queue_null_hardening",
                    "0004_expand__review_queue_null_hardening.sql",
                ),
                (
                    5,
                    DemandMigrationPhase.EXPAND,
                    "review_queue_claim_lock_rls",
                    "0005_expand__review_queue_claim_lock_rls.sql",
                ),
            ),
        )
        self.assertEqual(
            hashlib.sha256(QUEUE_PATH.read_bytes()).hexdigest(),
            "81c56ca095b4a9a2f09b7e33be91842fe67ea1f183febc2f2cd1a83fe56ebeac",
        )
        self.assertEqual(
            hashlib.sha256(HARDENING_PATH.read_bytes()).hexdigest(),
            "1ffb12e47bc9379dc2b49335da4c8997e3492d946e93028369712a22d9dd22c9",
        )
        self.assertEqual(
            hashlib.sha256(CLAIM_LOCK_PATH.read_bytes()).hexdigest(),
            "c3bf80114deb360209f37b13416a7faf46172c87cdca99a1c351e403f85beeda",
        )
        self.assertEqual(catalog.manifest_sha256, DEMAND_REVIEWED_MANIFEST_SHA256)

    def test_queue_is_fixed_rls_audited_outboxed_and_occ_idempotent(self) -> None:
        sql = QUEUE_PATH.read_text(encoding="utf-8")
        for marker in (
            "demand.review_claim_receipts",
            "ENABLE ROW LEVEL SECURITY",
            "FORCE ROW LEVEL SECURITY",
            "iam_api.authorize_demand_review_queue_v1",
            "iam_api.lock_demand_review_claim_authority_v1",
            "FOR UPDATE",
            "expected_demand_revision",
            "ON CONFLICT DO NOTHING",
            "review_claim_idempotency_reused",
            "review_claim_precondition_failed",
            "INSERT INTO audit.audit_events",
            "INSERT INTO infra.outbox_events",
            "DemandReviewClaimed",
            "SECURITY DEFINER",
            "REVOKE ALL ON FUNCTION",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, sql)
        self.assertNotIn("EXECUTE format", sql)
        self.assertNotIn("EXECUTE IMMEDIATE", sql)

    def test_online_role_cannot_execute_legacy_null_fail_open_functions(self) -> None:
        sql = HARDENING_PATH.read_text(encoding="utf-8")
        for marker in (
            "maximum_items IS NULL",
            "expected_demand_revision IS NULL",
            "exact_idempotency_key_digest IS NULL",
            "exact_payload_hash IS NULL",
            "list_available_demand_reviews_legacy_v1",
            "claim_demand_review_legacy_v1",
            "FROM PUBLIC, demand_review",
            "TO demand_schema_owner",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, sql)

    def test_claim_graph_locks_have_exact_definer_rls_boundary(self) -> None:
        sql = CLAIM_LOCK_PATH.read_text(encoding="utf-8")
        for marker in (
            "CREATE POLICY rls_review_queue_root_lock_definer",
            "CREATE POLICY rls_review_queue_submission_lock_definer",
            "CREATE POLICY rls_review_queue_version_lock_definer",
            "ON demand.demands",
            "ON demand.demand_submissions",
            "ON demand.demand_versions",
            "FOR UPDATE TO demand_schema_owner",
            "session_user = 'demand_review'",
            "app.scope_kind",
            "DEMAND_REVIEW",
            "app.operation",
            "CLAIM_REVIEW",
            "app.organization_id",
            "app.demand_id",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, sql)


if __name__ == "__main__":
    unittest.main()
