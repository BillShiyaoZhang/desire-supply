"""Static fail-closed contract for IAM40 invitation ENROLLMENT acceptance."""

from __future__ import annotations

from pathlib import Path
import hashlib
import json
import re
import unittest

from desire_platform.identity_access.adapters.postgres.migrations import (
    IAM_MIGRATION_LAYOUT,
    IAM_REVIEWED_MANIFEST_SHA256,
    IAM_SCHEMA_HEAD_VERSION,
    MigrationCatalog,
    MigrationPhase,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations/"
    "0040_expand__invitation_enrollment_acceptance.sql"
)
MIGRATION_ROOT = MIGRATION.parent
IAM40_SQL_SHA256 = (
    "5bf84831502fb295279666a2df5e660f977995bf8c0e8a86f3a321808909cad7"
)
IAM40_MANIFEST_SHA256 = (
    "e9e571dcb16928c21ab26b9dca5cacc299f9cc5427dd18383af87867ccca5c40"
)


class Iam40InvitationEnrollmentAcceptanceStaticTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sql = MIGRATION.read_text(encoding="utf-8")

    def test_iam40_remains_the_frozen_historical_prefix(self) -> None:
        catalog = MigrationCatalog.load(MIGRATION_ROOT)
        descriptor = catalog.artifacts[40].descriptor

        self.assertGreaterEqual(IAM_SCHEMA_HEAD_VERSION, 40)
        self.assertEqual(
            IAM_MIGRATION_LAYOUT[40],
            (
                40,
                MigrationPhase.EXPAND,
                "invitation_enrollment_acceptance",
                MIGRATION.name,
            ),
        )
        self.assertEqual(descriptor.checksum_sha256.hex(), IAM40_SQL_SHA256)
        self.assertEqual(
            hashlib.sha256(MIGRATION.read_bytes()).digest(),
            descriptor.checksum_sha256,
        )
        self.assertEqual(
            catalog.artifacts[39].descriptor.version,
            39,
        )
        entries = json.loads(catalog.manifest_bytes)
        self.assertEqual(entries[40]["sha256"], IAM40_SQL_SHA256)
        self.assertEqual(catalog.manifest_sha256, IAM_REVIEWED_MANIFEST_SHA256)
        self.assertEqual(
            hashlib.sha256(
                json.dumps(
                    entries[:41],
                    ensure_ascii=True,
                    separators=(",", ":"),
                ).encode("ascii")
                + b"\n"
            ).hexdigest(),
            IAM40_MANIFEST_SHA256,
        )

    def test_forward_migration_upgrades_only_the_two_accept_resolvers(self) -> None:
        self.assertIn(
            "CREATE OR REPLACE FUNCTION "
            "iam_api.resolve_accept_receipt_principal_v1",
            self.sql,
        )
        self.assertIn(
            "CREATE OR REPLACE FUNCTION "
            "iam_api.resolve_accept_access_invitation_scope_v1",
            self.sql,
        )
        self.assertNotRegex(
            self.sql,
            re.compile(r"\b(?:CREATE|ALTER|DROP)\s+TABLE\b", re.IGNORECASE),
        )
        self.assertNotIn("0034_expand__", self.sql)
        self.assertNotIn("0035_expand__", self.sql)
        self.assertNotIn("0039_expand__", self.sql)

    def test_receipt_pending_branch_requires_exact_enrollment_proof(self) -> None:
        for required in (
            "user_row.status = 'PENDING_ENROLLMENT'",
            "session_row.rotation_reason <> 'ENROLLMENT'",
            "session_row.verified_for_invitation_id::text",
            "session_row.auth_transaction_id::text",
            "candidate.status = 'SUCCEEDED'",
            "candidate.purpose = 'ENROLLMENT'",
            "candidate.expected_user_id IS NULL",
            "candidate.invitation_id::text = exact_invitation_id",
            "candidate.expected_contact_point_id",
            "= session_row.verified_contact_point_id",
            "transaction_timestamp() < candidate.deadline",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.sql)
        self.assertIn("user_row.status NOT IN ('ACTIVE','PENDING_ENROLLMENT')", self.sql)

    def test_scope_auth_rls_and_two_allowed_shapes_are_exact(self) -> None:
        for required in (
            "CREATE POLICY rls_accept_scope_auth_exact_definer_v2",
            "current_setting('app.auth_transaction_id', true)",
            "current_setting('app.target_invitation_id', true)",
            "predecessor.rotation_reason = 'STEP_UP'",
            "user_row.status = 'ACTIVE'",
            "candidate.purpose = 'STEP_UP'",
            "candidate.expected_user_id = exact_actor_user_id",
            "predecessor.rotation_reason = 'ENROLLMENT'",
            "user_row.status = 'PENDING_ENROLLMENT'",
            "candidate.purpose = 'ENROLLMENT'",
            "candidate.expected_user_id IS NULL",
            "candidate.target_role = 'DEMAND_OWNER'",
            "AND NOT candidate.is_initial_admin",
            "'user_status',user_row.status",
            "candidate.recipient_contact_id",
            "= auth_row.expected_contact_point_id",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.sql)


if __name__ == "__main__":
    unittest.main()
