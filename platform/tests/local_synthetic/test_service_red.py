import tempfile
import unittest
from pathlib import Path

from desire_platform.local_synthetic import LocalSyntheticService


class LocalSyntheticServiceRedTest(unittest.TestCase):
    def test_sqlite_service_exposes_exact_seven_personas(self):
        with tempfile.TemporaryDirectory() as directory:
            service = LocalSyntheticService(str(Path(directory) / "local.sqlite3"))
            self.assertEqual(
                tuple(item["persona_id"] for item in service.list_personas()["personas"]),
                (
                    "creator-chen",
                    "demand-owner",
                    "acceptance-beneficiary",
                    "case-operator",
                    "payment-initiator",
                    "finance-reconciler",
                    "appeal-reviewer",
                ),
            )


if __name__ == "__main__":
    unittest.main()
