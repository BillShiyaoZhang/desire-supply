"""Static contracts for the current-head v14 PostgreSQL operations assets."""

from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
V14_SCRIPT = ROOT / "deploy/postgres-backup-restore-v14.sh"
CURRENT_SCRIPT = ROOT / "deploy/postgres-backup-restore.sh"
V28_SCRIPT = ROOT / "deploy/postgres-backup-restore-v29.sh"
V14_OVERLAY = ROOT / "deploy/postgres-operations-v14.compose.yaml"
V14_SCRIPT_SHA256 = (
    "bb80382bf77aae6995d620106cddb0e5271c089dcaec3a1012759c03561a646a"
)
V13_NORMALIZED_SCRIPT_SHA256 = (
    "d7c630b544763de97e95a1edba50612bfd7bc244cec8c530b335635fd7228f45"
)
V13_PINS = "18|37|37|3|3|10|10|7|7|2|2"
V14_PINS = "18|38|38|3|3|10|10|8|8|2|2"
V13_CONTRACTS = (
    "595d5232153063b0b71a88b3776c737d1fcd5ecaef4a4b832c5e40434929c486|"
    "4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa|"
    "7695127a039fa71cddabd62318bea39337e3acbb4b1df66a3557b7a7ae3707b4|"
    "37|10|"
    "595d5232153063b0b71a88b3776c737d1fcd5ecaef4a4b832c5e40434929c486|"
    "27ec6b585a9340cbd7119d7a9b46d6098a3881f88ae1be9e00df3713c0107113|"
    "ab857f25969d17afe63886afe136cda10814e538517c54c180503b82f5785c1b|"
    "27a51c55bddfcb2a4f1bd16a3160abbb3a417425f14077f4886c3c41c22d5124|"
    "74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622"
)
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
EXPECTED_OVERLAY = """configs:
  postgres-backup-restore-script:
    file: ./deploy/postgres-backup-restore-v14.sh
"""


class PostgresOperationsV14Test(unittest.TestCase):
    def test_v14_script_is_frozen_with_only_reviewed_v13_pins_replaced(self) -> None:
        v14 = V14_SCRIPT.read_text(encoding="utf-8")

        self.assertEqual(
            hashlib.sha256(v14.encode("utf-8")).hexdigest(),
            V14_SCRIPT_SHA256,
        )
        self.assertIn(f"EXPECTED_PINS='{V14_PINS}'", v14)
        self.assertIn(f"EXPECTED_CONTRACTS='{V14_CONTRACTS}'", v14)
        normalized_v13 = v14.replace(V14_PINS, V13_PINS).replace(
            V14_CONTRACTS,
            V13_CONTRACTS,
        )
        self.assertIn(f"EXPECTED_PINS='{V13_PINS}'", normalized_v13)
        self.assertIn(
            f"EXPECTED_CONTRACTS='{V13_CONTRACTS}'",
            normalized_v13,
        )
        self.assertEqual(
            hashlib.sha256(normalized_v13.encode("utf-8")).hexdigest(),
            V13_NORMALIZED_SCRIPT_SHA256,
        )
        subprocess.run(["/bin/sh", "-n", V14_SCRIPT], check=True)

    def test_unversioned_operations_script_is_the_current_v29_alias(self) -> None:
        self.assertEqual(CURRENT_SCRIPT.read_bytes(), V28_SCRIPT.read_bytes())
        self.assertNotEqual(CURRENT_SCRIPT.read_bytes(), V14_SCRIPT.read_bytes())

    def test_v14_overlay_only_rebinds_the_operations_script_config(self) -> None:
        overlay = V14_OVERLAY.read_text(encoding="utf-8")

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
