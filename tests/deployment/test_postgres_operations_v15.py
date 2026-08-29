"""Static contracts for the current-head v15 PostgreSQL operations assets."""

from __future__ import annotations

from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
V14_SCRIPT = ROOT / "deploy/postgres-backup-restore-v14.sh"
V15_SCRIPT = ROOT / "deploy/postgres-backup-restore-v15.sh"
V15_OVERLAY = ROOT / "deploy/postgres-operations-v15.compose.yaml"
V14_PINS = "18|38|38|3|3|10|10|8|8|2|2"
V15_PINS = "18|38|38|3|3|10|10|9|9|2|2"
V14_CONTRACTS = (
    "908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e|"
    "4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa|"
    "7695127a039fa71cddabd62318bea39337e3acbb4b1df66a3557b7a7ae3707b4|"
    "38|10|"
    "908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e|"
    "27ec6b585a9340cbd7119d7a9b46d6098a3881f88ae1be9e00df3713c0107113|"
    "8907369e35172587753295403dc101227c21671960539c51364f8e00f1e4978a|"
    "6d5e98529d07f684657820a8a1d405cd243fa8ac26518ecee02a966ccc02d722|"
    "74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622"
)
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
EXPECTED_OVERLAY = """configs:
  postgres-backup-restore-script:
    file: ./deploy/postgres-backup-restore-v15.sh
"""


class PostgresOperationsV15Test(unittest.TestCase):
    def test_v15_script_is_v14_logic_with_only_reviewed_pins_replaced(self) -> None:
        v14 = V14_SCRIPT.read_text(encoding="utf-8")
        v15 = V15_SCRIPT.read_text(encoding="utf-8")

        self.assertIn(f"EXPECTED_PINS='{V14_PINS}'", v14)
        self.assertIn(f"EXPECTED_CONTRACTS='{V14_CONTRACTS}'", v14)
        self.assertIn(f"EXPECTED_PINS='{V15_PINS}'", v15)
        self.assertIn(f"EXPECTED_CONTRACTS='{V15_CONTRACTS}'", v15)
        self.assertEqual(
            v15.replace(V15_PINS, V14_PINS).replace(
                V15_CONTRACTS,
                V14_CONTRACTS,
            ),
            v14,
        )
        subprocess.run(["/bin/sh", "-n", V15_SCRIPT], check=True)

    def test_v15_overlay_only_rebinds_the_operations_script_config(self) -> None:
        overlay = V15_OVERLAY.read_text(encoding="utf-8")

        self.assertEqual(overlay, EXPECTED_OVERLAY)
        self.assertEqual(overlay.count("postgres-backup-restore-script:"), 1)
        self.assertNotIn("services:", overlay)
        self.assertNotIn("image:", overlay)
        self.assertNotIn("command:", overlay)
        self.assertNotIn("environment:", overlay)
        self.assertNotIn("volumes:", overlay)
        self.assertNotIn("networks:", overlay)
        self.assertNotIn("secrets:", overlay)
        self.assertNotIn("postgres-core-facts-sql:", overlay)


if __name__ == "__main__":
    unittest.main()
