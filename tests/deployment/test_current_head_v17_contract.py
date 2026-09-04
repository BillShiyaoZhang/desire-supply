"""Static, read-only contract for Demand11 / Trust11 current-head v17."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
VERIFY_PATH = ROOT / "scripts/verify_current_head_v17.py"
RUNBOOK_PATH = ROOT / "docs/operations/current-head-v17.md"


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "verify_current_head_v17_test", VERIFY_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("v17 verifier cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class CurrentHeadV17ContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.verifier = _load_verifier()
        cls.runbook = RUNBOOK_PATH.read_text(encoding="utf-8")

    def test_checked_in_static_current_head_is_closed(self) -> None:
        self.assertEqual(self.verifier.verify_repository(ROOT), ())

    def test_heads_contracts_and_trust11_are_exact(self) -> None:
        for marker in (
            "18|38|38|3|3|11|11|11|11|2|2",
            self.verifier.EXPECTED_CONTRACTS,
            self.verifier.TRUST_API_SHA256,
            self.verifier.TRUST_SQL_SHA256,
            "list_my_completed_case_assignments_v1",
            "VIEW_TRUST_CASE_HISTORY",
            "case_id,decided_at,outcome_code",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.runbook)

    def test_mutated_current_head_is_rejected(self) -> None:
        mutated = self.runbook.replace(
            "18|38|38|3|3|11|11|11|11|2|2",
            "18|38|38|3|3|11|11|10|10|2|2",
            1,
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
        self.assertIn('"status":"CURRENT_HEAD_V17_STATIC_VERIFIED"', source)

    def test_v16_trust10_pins_remain_frozen_not_current_aliases(self) -> None:
        v16 = (ROOT / "scripts/verify_current_head_v16.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("18|38|38|3|3|11|11|10|10|2|2", v16)
        self.assertNotIn("18|38|38|3|3|11|11|11|11|2|2", v16)
        for fixture in (
            "tests/deployment/fixtures/current-head-v16",
            "demand-manifest.json",
            "trust-manifest.json",
            "trust-runner-pins.txt",
        ):
            self.assertIn(fixture, v16)

    def test_v17_pins_are_frozen_before_iam39_and_trust12_advance(self) -> None:
        source = VERIFY_PATH.read_text(encoding="utf-8")
        for fixture in (
            "tests/deployment/fixtures/current-head-v17",
            "demand-manifest.json",
            "trust-manifest.json",
            "trust-runner-pins.txt",
        ):
            self.assertIn(fixture, source)
        self.assertNotIn(
            '(trust_root / "manifest.json", TRUST_MANIFEST_SHA256)', source
        )
        self.assertNotIn(
            'runner = _read(trust_root / "runner.py")', source
        )
        self.assertNotIn("TRUST_SCHEMA_HEAD_VERSION != 11", source)

    def test_history_projection_is_documented_as_party_safe(self) -> None:
        for forbidden in (
            "reporter",
            "owner",
            "organization",
            "demand",
            "report",
            "assignment",
            "evidence",
            "reason/action",
            "note",
            "authority",
        ):
            self.assertIn(forbidden, self.runbook)
        self.assertIn("三个 party-safe 字段", self.runbook)

    def test_static_publish_claims_no_execution_or_authority(self) -> None:
        self.assertIn("STATIC VERIFIED", self.runbook)
        self.assertIn("NOT EXECUTED", self.runbook)
        self.assertIn('"overall_status":"BLOCKED"', self.runbook)
        self.assertIn('"production_authorized":false', self.runbook)

    def test_current_pointer_preserves_history_and_ci_runs_only_v28(self) -> None:
        sidebar = (ROOT / "docs/_sidebar.md").read_text(encoding="utf-8")
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn(
            "[Current-head v17 静态模式头](/operations/current-head-v17.md)",
            sidebar,
        )
        self.assertIn(
            "[Current-head v16 静态模式头](/operations/current-head-v16.md)",
            sidebar,
        )
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v16.py"), 0)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v17.py"), 0)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v23.py"), 0)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v24.py"), 0)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v25.py"), 0)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v26.py"), 0)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v27.py"), 0)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v28.py"), 1)


if __name__ == "__main__":
    unittest.main()
