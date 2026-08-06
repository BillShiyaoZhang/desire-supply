import unittest

from desire_mvp.config import load_config

from helpers import ROOT


class ConfigTests(unittest.TestCase):
    def test_manifest_pins_every_rule_version(self):
        bundle = load_config(ROOT / "config")
        self.assertEqual(
            bundle.rule_version,
            "taxonomy-v1+matching-v1+budget-v1+reason-codes-v1",
        )
        self.assertAlmostEqual(sum(bundle.matching["weights"].values()), 1.0)


if __name__ == "__main__":
    unittest.main()
