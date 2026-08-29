from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest

from desire_platform.identity_access.adapters.postgres.migrations import (
    IAM_MIGRATION_LAYOUT,
    IAM_REVIEWED_MANIFEST_SHA256,
    IAM_SCHEMA_HEAD_VERSION,
    MigrationCatalog,
    MigrationPhase,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
MIGRATION_PATH = (
    MIGRATION_ROOT / "0025_expand__demand_review_duty_authority_v2.sql"
)
EXPECTED_SQL_SHA256 = (
    "34046f3bf0e0569a75a3cdabce3cb277a393253e3a3d16fc6810d507a9954067"
)
EXPECTED_MANIFEST_SHA256 = (
    "b308dd273b3d7bb67f12198b9888204e076ae5edef40c4de1a20c9dee857fa6b"
)


class DemandReviewDutyAuthorityV2StaticTest(unittest.TestCase):
    def test_0025_is_the_reviewed_forward_only_head(self) -> None:
        catalog = MigrationCatalog.load(MIGRATION_ROOT)
        self.assertGreaterEqual(IAM_SCHEMA_HEAD_VERSION, 25)
        self.assertEqual(
            IAM_MIGRATION_LAYOUT[25],
            (
                25,
                MigrationPhase.EXPAND,
                "demand_review_duty_authority_v2",
                "0025_expand__demand_review_duty_authority_v2.sql",
            ),
        )
        self.assertEqual(
            hashlib.sha256(MIGRATION_PATH.read_bytes()).hexdigest(),
            EXPECTED_SQL_SHA256,
        )
        manifest = json.loads((MIGRATION_ROOT / "manifest.json").read_bytes())
        frozen_prefix = json.dumps(
            manifest[:26],
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("ascii") + b"\n"
        self.assertEqual(
            hashlib.sha256(frozen_prefix).hexdigest(),
            EXPECTED_MANIFEST_SHA256,
        )
        self.assertEqual(
            catalog.manifest_sha256,
            IAM_REVIEWED_MANIFEST_SHA256,
        )

    def test_v2_binds_active_duty_and_conflict_separation(self) -> None:
        sql = MIGRATION_PATH.read_text(encoding="utf-8")
        required = (
            "iam_api.authorize_demand_review_queue_v1",
            "iam_api.lock_demand_review_claim_authority_v1",
            "iam_api.resolve_demand_reviewer_authority_marker_v2",
            "iam_api.lock_demand_reviewer_authority_v2",
            "duty.duty_code = 'OPERATIONS_REVIEWER'",
            "duty.revoked_at IS NULL",
            "transaction_timestamp() < duty.expires_at",
            "membership.status = 'ACTIVE'",
            "FOR UPDATE",
            "SECURITY DEFINER",
            "SET search_path = pg_catalog, iam, iam_api",
        )
        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, sql)
        self.assertNotIn("EXECUTE format", sql)
        self.assertNotIn("EXECUTE IMMEDIATE", sql)

    def test_v1_online_execute_is_revoked_instead_of_remaining_a_bypass(self) -> None:
        sql = MIGRATION_PATH.read_text(encoding="utf-8")
        self.assertIn(
            "REVOKE ALL ON FUNCTION iam_api.lock_demand_reviewer_session_v1",
            sql,
        )
        self.assertIn(
            "REVOKE ALL ON FUNCTION "
            "iam_api.resolve_demand_reviewer_authority_marker_v1",
            sql,
        )
        self.assertNotIn(
            "GRANT EXECUTE ON FUNCTION iam_api.lock_demand_reviewer_session_v1",
            sql,
        )


if __name__ == "__main__":
    unittest.main()
