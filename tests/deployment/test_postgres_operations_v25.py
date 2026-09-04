"""Static contracts for the current-head v25 PostgreSQL operations assets."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
V15_SCRIPT = ROOT / "deploy/postgres-backup-restore-v15.sh"
V25_SCRIPT = ROOT / "deploy/postgres-backup-restore-v25.sh"
V25_OVERLAY = ROOT / "deploy/postgres-operations-v25.compose.yaml"
V25_FACTS = ROOT / "deploy/postgres-core-facts-v25.sql"
CURRENT_FACTS = ROOT / "deploy/postgres-core-facts.sql"
V28_FACTS = ROOT / "deploy/postgres-core-facts-v30.sql"
V25_FACTS_SHA256 = (
    "0845ec9025efdfc208bab24b1ce3b8f56a8e2e44613eae249a00af349802507e"
)
PRE_V25_NORMALIZED_FACTS_SHA256 = (
    "880f3434f301bf1204e63524bcf93d5ed2716dfe04865883eebcb4b34708d831"
)
V15_PINS = "18|38|38|3|3|10|10|9|9|2|2"
V25_PINS = "18|42|42|3|3|12|12|18|18|2|2"
V15_CONTRACTS = (
    "908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e|"
    "4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa|"
    "7695127a039fa71cddabd62318bea39337e3acbb4b1df66a3557b7a7ae3707b4|"
    "38|10|"
    "908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e|"
    "27ec6b585a9340cbd7119d7a9b46d6098a3881f88ae1be9e00df3713c0107113|"
    "43765a3739716819c1bfc8df9625a3011534ae23aa647bf3bdaea90945e7bef9|"
    "8ef9c2321866e7509bf1a959acf64370fe74abb927635c0434618287a4348171|"
    "74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622"
)
V25_CONTRACTS = (
    "f88bf5f70343edbf06e55c0641b61b58cff27fda48ce00f6489e3f3f80db5a9e|"
    "4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa|"
    "919d62a9b32dc29619a561940f9c79e21700562a0cdd9ef7e9f13a40cea43345|"
    "42|12|"
    "f88bf5f70343edbf06e55c0641b61b58cff27fda48ce00f6489e3f3f80db5a9e|"
    "379b6cb8b05f7da03905e644d158cfb6ad03409f290d33f63ae80183d428f816|"
    "639100c2fd347cdc38e9d9d52686f1a95c17cdcca2fbabe506832d30fad495b1|"
    "0b7028c75c8f137bc4a55a76fe73ea956d0c5ada13031f80794b77c1c9535e19|"
    "74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622"
)
EXPECTED_OVERLAY = """configs:
  postgres-backup-restore-script:
    file: ./deploy/postgres-backup-restore-v25.sh
  postgres-core-facts-sql:
    file: ./deploy/postgres-core-facts-v25.sql
"""
V25_EMPTY_TARGET_TABLES = (
    "iam.external_identities",
    "iam.contact_points",
    "iam.organizations",
    "iam.auth_transactions",
    "iam.session_families",
    "iam.session_security_events",
    "iam.user_role_grants",
    "iam.membership_role_grants",
    "iam.platform_duty_grants",
    "iam.consent_grants",
    "iam.consent_grant_data_categories",
    "iam.consent_withdrawals",
    "infra.command_receipts",
    "infra.iam_sandbox_bootstrap_state",
    "infra.iam_sandbox_bootstrap_accounts",
    "infra.iam_sandbox_bootstrap_runs",
    "infra.iam_sandbox_bootstrap_manifest_bridges",
)
V25_DURABLE_FACT_TABLES = tuple(
    table for table in V25_EMPTY_TARGET_TABLES if table != "iam.user_role_grants"
)
EXCLUDED_CATALOG_TABLES = (
    "iam.policy_selectors",
    "iam.policy_documents",
    "iam.policy_bundles",
    "iam.policy_bundle_documents",
    "iam.consent_offers",
    "iam.consent_offer_data_categories",
    "infra.consumer_principals",
    "infra.iam_receipt_key_policy",
    "infra.schema_migrations",
    "infra.iam_schema_contracts",
)


class PostgresOperationsV25Test(unittest.TestCase):
    def test_v25_script_is_v15_logic_with_reviewed_current_hardening(self) -> None:
        v15 = V15_SCRIPT.read_text(encoding="utf-8")
        v25 = V25_SCRIPT.read_text(encoding="utf-8")

        self.assertIn(f"EXPECTED_PINS='{V15_PINS}'", v15)
        self.assertIn(f"EXPECTED_CONTRACTS='{V15_CONTRACTS}'", v15)
        self.assertIn(f"EXPECTED_PINS='{V25_PINS}'", v25)
        self.assertIn(f"EXPECTED_CONTRACTS='{V25_CONTRACTS}'", v25)
        normalized = v25.replace(V25_PINS, V15_PINS).replace(
            V25_CONTRACTS,
            V15_CONTRACTS,
        )
        required_facts_marker = '        \'"iam_durable_counts"\' \\\n'
        self.assertEqual(normalized.count(required_facts_marker), 1)
        normalized = normalized.replace(required_facts_marker, "", 1)
        for table in V25_EMPTY_TARGET_TABLES:
            with self.subTest(table=table):
                line = f"                (SELECT count(*) FROM {table}) +\n"
                self.assertEqual(normalized.count(line), 1)
                normalized = normalized.replace(line, "", 1)
        for table in EXCLUDED_CATALOG_TABLES:
            with self.subTest(excluded_table=table):
                self.assertNotIn(table, v25)
        self.assertEqual(normalized, v15)
        subprocess.run(["/bin/sh", "-n", V25_SCRIPT], check=True)

    def test_v25_facts_only_add_the_reviewed_durable_count_projection(self) -> None:
        v25 = V25_FACTS.read_text(encoding="utf-8")
        self.assertEqual(
            hashlib.sha256(v25.encode("utf-8")).hexdigest(),
            V25_FACTS_SHA256,
        )
        start_marker = "    'iam_durable_counts', jsonb_build_object(\n"
        end_marker = "    'core_counts', jsonb_build_object(\n"
        self.assertEqual(v25.count(start_marker), 1)
        self.assertEqual(v25.count(end_marker), 1)
        start = v25.index(start_marker)
        end = v25.index(end_marker, start)
        durable_projection = v25[start:end]
        self.assertEqual(
            set(re.findall(r"FROM ([a-z_]+\.[a-z_]+)", durable_projection)),
            set(V25_DURABLE_FACT_TABLES),
        )
        for table in V25_DURABLE_FACT_TABLES:
            with self.subTest(table=table):
                self.assertEqual(durable_projection.count(f"FROM {table}"), 1)
        for table in EXCLUDED_CATALOG_TABLES:
            with self.subTest(excluded_table=table):
                self.assertNotIn(table, durable_projection)
        normalized_pre_v25 = v25[:start] + v25[end:]
        self.assertEqual(
            hashlib.sha256(normalized_pre_v25.encode("utf-8")).hexdigest(),
            PRE_V25_NORMALIZED_FACTS_SHA256,
        )

    def test_unversioned_facts_are_the_current_v30_alias(self) -> None:
        self.assertEqual(CURRENT_FACTS.read_bytes(), V28_FACTS.read_bytes())
        self.assertNotEqual(CURRENT_FACTS.read_bytes(), V25_FACTS.read_bytes())

    def test_v25_overlay_only_rebinds_the_two_operations_configs(self) -> None:
        overlay = V25_OVERLAY.read_text(encoding="utf-8")

        self.assertEqual(overlay, EXPECTED_OVERLAY)
        self.assertEqual(overlay.count("postgres-backup-restore-script:"), 1)
        self.assertEqual(overlay.count("postgres-core-facts-sql:"), 1)
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


if __name__ == "__main__":
    unittest.main()
