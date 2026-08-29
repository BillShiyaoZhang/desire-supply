"""Static contracts for the current-head v26 PostgreSQL operations assets."""

from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
V25_SCRIPT = ROOT / "deploy/postgres-backup-restore-v25.sh"
V26_SCRIPT = ROOT / "deploy/postgres-backup-restore-v26.sh"
V25_FACTS = ROOT / "deploy/postgres-core-facts-v25.sql"
V26_FACTS = ROOT / "deploy/postgres-core-facts-v26.sql"
V26_OVERLAY = ROOT / "deploy/postgres-operations-v26.compose.yaml"
V25_PINS = "18|42|42|3|3|12|12|18|18|2|2"
V26_PINS = "18|43|43|3|3|13|13|19|19|2|2"
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
V26_CONTRACTS = (
    "bb2b025fb26974cf06574117d8e055144d9413c81c035595458c24181f29c72e|"
    "4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa|"
    "5663d8e14bb5fa6a5706828fe443a8c08ac2e62bad3e56403dd45bc6df939b29|"
    "43|13|"
    "bb2b025fb26974cf06574117d8e055144d9413c81c035595458c24181f29c72e|"
    "e3e7a77aeec447cc3035472c5f660c8675238fe260081ce9cedf4dc014b37001|"
    "16913f8503da5e27be72321a3311025bba9a6cf454f8b8b5dad9b4a09ad3417d|"
    "5949f7b630376a59c643f9024210625811606a1a41f90f4bc99ee19dfb99d38c|"
    "74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622"
)
EXPECTED_OVERLAY = """configs:
  postgres-backup-restore-script:
    file: ./deploy/postgres-backup-restore-v26.sh
  postgres-core-facts-sql:
    file: ./deploy/postgres-core-facts-v26.sql
"""
RELEASE_EMPTY_TARGET_LINE = (
    "                (SELECT count(*) FROM "
    "demand.demand_review_assignment_releases) +\n"
)
RELEASE_FACT_BLOCK = """        'demand_review_assignment_releases', (
            SELECT count(*) FROM demand.demand_review_assignment_releases
        ),
"""
FROZEN_V25 = {
    "deploy/postgres-backup-restore-v25.sh": (
        "9aa84d3f7d37704e181a314db873e16fecfad6d770dbc1d12fbb76180d69d1bb"
    ),
    "deploy/postgres-core-facts-v25.sql": (
        "0845ec9025efdfc208bab24b1ce3b8f56a8e2e44613eae249a00af349802507e"
    ),
    "deploy/postgres-operations-v25.compose.yaml": (
        "a98b80de17604349362b813d1224a4f71d886b2d1282f9cbb944cd3b714628a4"
    ),
}


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class PostgresOperationsV26Test(unittest.TestCase):
    def test_v26_script_is_v25_plus_current_pins_and_release_fact_guard(self) -> None:
        v25 = V25_SCRIPT.read_text(encoding="utf-8")
        v26 = V26_SCRIPT.read_text(encoding="utf-8")

        self.assertIn(f"EXPECTED_PINS='{V25_PINS}'", v25)
        self.assertIn(f"EXPECTED_CONTRACTS='{V25_CONTRACTS}'", v25)
        self.assertIn(f"EXPECTED_PINS='{V26_PINS}'", v26)
        self.assertIn(f"EXPECTED_CONTRACTS='{V26_CONTRACTS}'", v26)
        self.assertEqual(v26.count(RELEASE_EMPTY_TARGET_LINE), 1)
        normalized = (
            v26.replace(V26_PINS, V25_PINS)
            .replace(V26_CONTRACTS, V25_CONTRACTS)
            .replace(RELEASE_EMPTY_TARGET_LINE, "", 1)
        )
        self.assertEqual(normalized, v25)
        subprocess.run(["/bin/sh", "-n", V26_SCRIPT], check=True)

    def test_v26_facts_are_v25_plus_one_immutable_release_count(self) -> None:
        v25 = V25_FACTS.read_text(encoding="utf-8")
        v26 = V26_FACTS.read_text(encoding="utf-8")

        self.assertEqual(v26.count(RELEASE_FACT_BLOCK), 1)
        self.assertEqual(v26.replace(RELEASE_FACT_BLOCK, "", 1), v25)

    def test_v26_overlay_only_rebinds_the_two_operations_configs(self) -> None:
        overlay = V26_OVERLAY.read_text(encoding="utf-8")

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

    def test_v25_operations_assets_remain_byte_frozen(self) -> None:
        for relative, expected in FROZEN_V25.items():
            with self.subTest(relative=relative):
                self.assertEqual(_sha(ROOT / relative), expected)


if __name__ == "__main__":
    unittest.main()
