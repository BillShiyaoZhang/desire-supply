"""Static gates for the independent Matching PostgreSQL catalog."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from desire_platform.matching.adapters.postgres.migrations import (
    MATCHING_MIGRATION_LAYOUT,
    MATCHING_REQUIRED_IAM_SCHEMA_VERSION,
    MATCHING_REVIEWED_MANIFEST_SHA256,
    MATCHING_SCHEMA_HEAD_VERSION,
    MatchingMigrationCatalog,
    MatchingMigrationCatalogError,
    MatchingMigrationDescriptor,
    MatchingMigrationPhase,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/matching/adapters/postgres/migrations"
)


class MatchingMigrationStaticTest(unittest.TestCase):
    def test_catalog_is_reviewed_byte_exact_and_immutable(self) -> None:
        catalog = MatchingMigrationCatalog.load(MIGRATION_ROOT)
        self.assertEqual(MATCHING_SCHEMA_HEAD_VERSION, 3)
        self.assertEqual(MATCHING_REQUIRED_IAM_SCHEMA_VERSION, 46)
        self.assertEqual(
            catalog.manifest_sha256,
            MATCHING_REVIEWED_MANIFEST_SHA256,
        )
        self.assertEqual(
            tuple(item.descriptor.version for item in catalog.artifacts),
            (1, 2, 3),
        )
        self.assertEqual(
            tuple(item.descriptor.checksum_sha256.hex() for item in catalog.artifacts),
            (
                "b4910364f494d519d0f010665b7aa4deda01986925975c8e7c9c39c74102d70b",
                "6e27ad97ab01807e012e6d0043a527ecaf8d0eed4f49ffae3180a7466eb4f516",
                "3f28f26cfca5af93a716aa34403288d644e3eab44c4af258a383b42e82b8b434",
            ),
        )
        descriptor = MatchingMigrationDescriptor(
            component="matching",
            version=1,
            phase=MatchingMigrationPhase.EXPAND,
            name="matching_v1",
            relative_path="0001_expand__matching_v1.sql",
            checksum_sha256=b"x" * 32,
            prefix_manifest_sha256=b"y" * 32,
        )
        with self.assertRaises(FrozenInstanceError):
            descriptor.version = 2

    def test_catalog_rejects_noncanonical_manifest_and_checksum_drift(self) -> None:
        artifacts = MatchingMigrationCatalog.load(MIGRATION_ROOT).artifacts
        entries = [
            {
                "component": item.descriptor.component,
                "version": item.descriptor.version,
                "phase": item.descriptor.phase.value,
                "name": item.descriptor.name,
                "path": item.descriptor.relative_path,
                "sha256": hashlib.sha256(item.sql_bytes).hexdigest(),
            }
            for item in artifacts
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for artifact, entry in zip(artifacts, entries):
                (root / entry["path"]).write_bytes(artifact.sql_bytes)
            (root / "manifest.json").write_bytes(
                json.dumps(entries, indent=2).encode("ascii") + b"\n"
            )
            with self.assertRaises(MatchingMigrationCatalogError) as raised:
                MatchingMigrationCatalog.load(root)
            self.assertEqual(
                raised.exception.code,
                "MATCHING_MIGRATION_MANIFEST_INVALID",
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, (artifact, entry) in enumerate(zip(artifacts, entries)):
                suffix = b"SELECT 1;\n" if index == 0 else b""
                (root / entry["path"]).write_bytes(artifact.sql_bytes + suffix)
            manifest = (
                json.dumps(entries, ensure_ascii=True, separators=(",", ":"))
                .encode("ascii")
                + b"\n"
            )
            (root / "manifest.json").write_bytes(manifest)
            with self.assertRaises(MatchingMigrationCatalogError) as raised:
                MatchingMigrationCatalog.load(root)
            self.assertEqual(
                raised.exception.code,
                "MATCHING_MIGRATION_CHECKSUM_MISMATCH",
            )

    def test_migration_closes_core_relations_constraints_and_roles(self) -> None:
        sql = MatchingMigrationCatalog.load(MIGRATION_ROOT).artifacts[0].sql_bytes.decode(
            "utf-8"
        )
        required_relations = (
            "rule_bundles",
            "rule_selectors",
            "matching_attempts",
            "match_runs",
            "match_run_inputs",
            "match_candidates",
            "invitations",
            "invitation_disclosure_snapshots",
            "invitation_responses",
            "invitation_withdrawals",
            "selections",
            "candidate_selector_assignments",
            "matching_review_assignments",
            "match_jobs",
            "source_inbox",
            "command_receipts",
        )
        for relation in required_relations:
            with self.subTest(relation=relation):
                self.assertIn(f"CREATE TABLE matching.{relation}", sql)
                self.assertIn(
                    f"ALTER TABLE matching.{relation} FORCE ROW LEVEL SECURITY",
                    sql,
                )
        for role in (
            "matching_creator",
            "matching_selector",
            "matching_review",
            "matching_worker",
            "matching_coordinator",
        ):
            self.assertIn(role, sql)
        self.assertNotIn("matching_owner", sql)
        self.assertNotIn("MATCHING_OWNER", sql)
        self.assertNotIn("selection_owner_authorizations", sql)
        self.assertNotIn("CREATE ROLE", sql.upper())
        for constraint in (
            "uq_matching_open_attempt_per_demand",
            "uq_matching_run_attempt_no",
            "uq_matching_eligible_rank",
            "fk_matching_invitation_candidate",
            "uq_matching_open_invitation_per_creator",
            "fk_matching_response_invitation",
            "fk_matching_selection_chosen_invitation",
            "uq_matching_active_candidate_selector",
            "uq_matching_active_job_lease",
        ):
            self.assertIn(constraint, sql)
        self.assertIn("'WITHDRAWN'", sql)
        self.assertIn("CANDIDATE_SELECTOR", sql)
        self.assertIn("CREATE POLICY rls_matching_audit_insert", sql)
        self.assertIn("CREATE POLICY rls_matching_outbox_insert", sql)


if __name__ == "__main__":
    unittest.main()
