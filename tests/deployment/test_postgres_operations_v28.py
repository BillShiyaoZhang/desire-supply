"""Static contracts for current-head v28 PostgreSQL operations assets."""

from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deploy/postgres-backup-restore-v28.sh"
FACTS = ROOT / "deploy/postgres-core-facts-v28.sql"
OVERLAY = ROOT / "deploy/postgres-operations-v28.compose.yaml"
V26_FROZEN = {
    "deploy/postgres-backup-restore-v26.sh":
        "48fe07e4a845738cd620b2584eae984d1a66d2258f6fc2c46b0ee63eaec2d72c",
    "deploy/postgres-core-facts-v26.sql":
        "274cf10f533673a1541f9dd186039153605bc420f847fa14110027bd5650f153",
    "deploy/postgres-operations-v26.compose.yaml":
        "7fc79306fce5feb2d985390ab6e8f6a77955a5ad7d53bb341e25c8ed0df1e041",
}
HEADS = "18|46|46|5|5|15|15|22|22|9|9|2|2"
MATCHING_TABLES = (
    "candidate_selector_assignments",
    "candidate_selector_opt_in_receipts",
    "command_receipts",
    "complete_selection_close_records",
    "complete_selection_records",
    "complete_selection_system_close_records",
    "invitation_disclosure_snapshots",
    "invitation_responses",
    "invitation_withdrawals",
    "invitations",
    "match_candidates",
    "match_jobs",
    "match_run_inputs",
    "match_run_results",
    "match_runs",
    "matching_attempts",
    "matching_review_assignments",
    "review_hold_evidence",
    "reviewer_authority_projections",
    "rule_bundles",
    "rule_selectors",
    "selection_close_intents",
    "selection_completion_jobs",
    "selection_intents",
    "selection_system_close_intents",
    "selections",
    "source_inbox",
)
EXPECTED_OVERLAY = """configs:
  postgres-backup-restore-script:
    file: ./deploy/postgres-backup-restore-v28.sh
  postgres-core-facts-sql:
    file: ./deploy/postgres-core-facts-v28.sql
"""


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class PostgresOperationsV28Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = SCRIPT.read_text(encoding="utf-8")
        cls.facts = FACTS.read_text(encoding="utf-8")

    def test_v28_pins_all_six_schema_components(self) -> None:
        self.assertIn(f"EXPECTED_PINS='{HEADS}'", self.script)
        for marker in (
            "matching.current_schema_version",
            "matching.schema_head_version",
            "matching.required_iam_schema_version",
            "matching_meta.api_contract_sha256",
            "matching_meta.event_contract_sha256",
            "matching_meta.rule_contract_sha256",
            "matching_meta.input_manifest_contract_sha256",
            "matching_meta.run_input_contract_sha256",
            "matching_meta.candidate_contract_sha256",
            "matching_meta.disclosure_contract_sha256",
            "matching.migration_manifest_sha256",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.script)
        self.assertNotIn("__MATCHING_V7_MANIFEST_SHA256__", self.script)
        subprocess.run(["/bin/sh", "-n", SCRIPT], check=True)

    def test_every_matching_v1_v9_table_has_private_count_and_empty_gate(self) -> None:
        self.assertEqual(len(MATCHING_TABLES), 27)
        for table in MATCHING_TABLES:
            qualified = f"matching.{table}"
            with self.subTest(table=table):
                self.assertEqual(self.facts.count(qualified), 1)
                self.assertEqual(self.script.count(qualified), 1)
        for forbidden in (
            "creator_user_id",
            "reviewer_user_id",
            "candidate_id",
            "safe_response_body",
            "canonical_result_bytes",
            "disclosed_amount",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.facts)

    def test_new_profile_and_demand_durable_tables_are_continuity_bound(self) -> None:
        empty_target_tables = (
            "profile.match_capture_batches",
            "profile.match_input_snapshots",
            "profile.derived_match_capture_receipts",
            "profile.derived_match_raw_snapshots",
            "profile.derived_match_input_snapshots",
            "demand.matching_requested_deliveries",
            "demand.matching_delivery_claim_receipts",
            "demand.complete_selection_receipts",
            "demand.close_matching_without_selection_receipts",
        )
        for table in empty_target_tables:
            with self.subTest(table=table):
                self.assertEqual(self.facts.count(table), 1)
                self.assertEqual(self.script.count(table), 1)
        self.assertEqual(self.facts.count("demand.matching_runtime_policy"), 1)
        self.assertNotIn("demand.matching_runtime_policy", self.script)

    def test_v28_overlay_only_rebinds_operations_configs(self) -> None:
        overlay = OVERLAY.read_text(encoding="utf-8")
        self.assertEqual(overlay, EXPECTED_OVERLAY)
        for forbidden in (
            "services:",
            "image:",
            "command:",
            "environment:",
            "volumes:",
            "networks:",
            "secrets:",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, overlay)

    def test_v26_operations_assets_remain_byte_frozen(self) -> None:
        for relative, expected in V26_FROZEN.items():
            with self.subTest(relative=relative):
                self.assertEqual(_sha(ROOT / relative), expected)


if __name__ == "__main__":
    unittest.main()
