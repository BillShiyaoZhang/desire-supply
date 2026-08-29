"""Static, read-only contract for Demand11 / Trust10 current-head v16."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
VERIFY_PATH = ROOT / "scripts/verify_current_head_v16.py"
RUNBOOK_PATH = ROOT / "docs/operations/current-head-v16.md"


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "verify_current_head_v16_test", VERIFY_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("v16 verifier cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class CurrentHeadV16ContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.verifier = _load_verifier()
        cls.runbook = RUNBOOK_PATH.read_text(encoding="utf-8")

    def test_checked_in_static_current_head_is_closed(self) -> None:
        self.assertEqual(self.verifier.verify_repository(ROOT), ())

    def test_heads_and_dependencies_are_exact(self) -> None:
        for marker in (
            "18|38|38|3|3|11|11|10|10|2|2",
            self.verifier.EXPECTED_CONTRACTS,
            self.verifier.DEMAND_SQL_SHA256,
            self.verifier.TRUST_SQL_SHA256,
            "GET /v1/app/review-history",
            "VIEW_DEMAND_REVIEW_HISTORY",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.runbook)

    def test_mutated_current_head_is_rejected(self) -> None:
        mutated = self.runbook.replace(
            "18|38|38|3|3|11|11|10|10|2|2",
            "18|38|38|3|3|11|11|9|9|2|2",
        )
        self.assertTrue(self.verifier._runbook_failures(mutated))

    def test_verifier_is_read_only_and_runtime_free(self) -> None:
        source = VERIFY_PATH.read_text(encoding="utf-8")
        for forbidden in (
            "import subprocess",
            "from subprocess",
            "os.system",
            "Popen(",
            "subprocess.run",
            "docker.from_env",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn(
            '"status":"CURRENT_HEAD_V16_STATIC_VERIFIED"', source
        )

    def test_v15_pins_remain_historical_not_current_aliases(self) -> None:
        v15 = (ROOT / "scripts/verify_current_head_v15.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("18|38|38|3|3|10|10|9|9|2|2", v15)
        self.assertNotIn("18|38|38|3|3|11|11|10|10|2|2", v15)
        for fixture in (
            "current-head-v15/demand-manifest.json",
            "current-head-v15/trust-manifest.json",
            "current-head-v15/trust-runner-pins.txt",
        ):
            self.assertIn(fixture, v15)

    def test_v16_pins_are_frozen_before_trust11_advances_current_head(self) -> None:
        source = VERIFY_PATH.read_text(encoding="utf-8")
        for fixture in (
            "tests/deployment/fixtures/current-head-v16",
            "demand-manifest.json",
            "trust-manifest.json",
            "trust-runner-pins.txt",
        ):
            self.assertIn(fixture, source)
        self.assertNotIn('(trust_root / "manifest.json", TRUST_MANIFEST_SHA256)', source)
        self.assertNotIn("TRUST_SCHEMA_HEAD_VERSION != 10", source)

    def test_static_publish_claims_no_execution_or_authority(self) -> None:
        self.assertIn("STATIC VERIFIED", self.runbook)
        self.assertIn("NOT EXECUTED", self.runbook)
        self.assertIn('"overall_status":"BLOCKED"', self.runbook)
        self.assertIn('"production_authorized":false', self.runbook)


if __name__ == "__main__":
    unittest.main()
