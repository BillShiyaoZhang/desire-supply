"""Fail-closed static contract for the current-head v15 release assets."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
VERIFY_PATH = ROOT / "scripts" / "verify_current_head_v15.py"
V14_VERIFY_PATH = ROOT / "scripts" / "verify_current_head_v14.py"
RUNBOOK_PATH = ROOT / "docs" / "operations" / "current-head-v15.md"
V14_FIXTURE = (
    ROOT / "tests/deployment/fixtures/current-head-v14/trust-manifest.json"
)
V15_TRUST_FIXTURE = (
    ROOT / "tests/deployment/fixtures/current-head-v15/trust-manifest.json"
)
CURRENT_TRUST_MANIFEST = (
    ROOT
    / "platform/src/desire_platform/trust_safety/adapters/postgres/"
    "migrations/manifest.json"
)


def _load_verifier(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"{name} cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class CurrentHeadV15RunbookTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.verifier = _load_verifier(
            VERIFY_PATH,
            "verify_current_head_v15_test",
        )
        cls.v14_verifier = _load_verifier(
            V14_VERIFY_PATH,
            "verify_current_head_v14_from_v15_test",
        )
        cls.runbook = RUNBOOK_PATH.read_text(encoding="utf-8")

    def test_checked_in_historical_runbook_is_closed(self) -> None:
        self.assertEqual(
            self.verifier._current_head_v15_runbook_failures(self.runbook),
            (),
        )

    def test_heads_contracts_and_coordinates_are_exact(self) -> None:
        expected = (
            "18|38|38|3|3|10|10|9|9|2|2",
            (
                "908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e|"
                "4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa|"
                "7695127a039fa71cddabd62318bea39337e3acbb4b1df66a3557b7a7ae3707b4|"
                "38|10|"
                "908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e|"
                "27ec6b585a9340cbd7119d7a9b46d6098a3881f88ae1be9e00df3713c0107113|"
                "43765a3739716819c1bfc8df9625a3011534ae23aa647bf3bdaea90945e7bef9|"
                "8ef9c2321866e7509bf1a959acf64370fe74abb927635c0434618287a4348171|"
                "74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622"
            ),
            "a9923573365f1023aff3e4aaebb0b7e656c80eab7e721bbf30d9e9b038782f25",
            "6cbab8db4ccbb5c9fe2a5b5af161327289da80a3de4c159407de9f1cb13093db",
            "43765a3739716819c1bfc8df9625a3011534ae23aa647bf3bdaea90945e7bef9",
            "8ef9c2321866e7509bf1a959acf64370fe74abb927635c0434618287a4348171",
            "TRUST_REPORT_CURSOR",
            "key-trust-report-cursor-v1",
            "trust-report-cursor-2026-01",
            "25 个 key carrier = 36 个 secret",
            "e2e-ten-account-v15-iam38-demand10-trust9",
            "internal-sandbox-bundle-iam38-demand10-trust9",
            "release-e2e-ten-account-v15-iam38-demand10-trust9",
            "v15-iam38-profile3-demand10-trust9-taxonomy2-drill01",
        )
        for value in expected:
            with self.subTest(value=value):
                self.assertIn(value, self.runbook)

    def test_each_reviewed_coordinate_or_head_mutation_is_rejected(self) -> None:
        mutations = (
            ("18|38|38|3|3|10|10|9|9|2|2", "18|38|38|3|3|10|10|8|8|2|2"),
            ("e2e-ten-account-v15-iam38-demand10-trust9", "e2e-ten-account-v15-latest"),
            ("internal-sandbox-bundle-iam38-demand10-trust9", "internal-sandbox-bundle-current"),
            ("release-e2e-ten-account-v15-iam38-demand10-trust9", "release-current"),
            ("v15-iam38-profile3-demand10-trust9-taxonomy2-drill01", "backup-current"),
        )
        for old, new in mutations:
            with self.subTest(old=old):
                mutated = self.runbook.replace(old, new)
                self.assertTrue(
                    self.verifier._current_head_v15_runbook_failures(mutated)
                )

    def test_operations_helper_uses_exactly_three_compose_layers(self) -> None:
        helper = self.runbook.partition("compose_v15_operations() {")[2].partition(
            "\n}"
        )[0]
        self.assertTrue(helper)
        self.assertEqual(helper.count('-f "$PWD/'), 3)
        self.assertIn('-f "$PWD/compose.yaml"', helper)
        self.assertIn(
            '-f "$PWD/deploy/postgres-operations.compose.yaml"', helper
        )
        self.assertIn(
            '-f "$PWD/deploy/postgres-operations-v15.compose.yaml"', helper
        )
        self.assertNotIn("compose.ipam.yaml", helper)
        self.assertNotIn("--build", helper)
        self.assertNotIn("--pull", helper)

    def test_verifier_is_read_only_and_does_not_invoke_docker(self) -> None:
        verifier = VERIFY_PATH.read_text(encoding="utf-8")
        for forbidden in (
            "import subprocess",
            "from subprocess",
            "os.system",
            "Popen(",
            "subprocess.run",
            "docker.from_env",
        ):
            self.assertNotIn(forbidden, verifier)
        self.assertIn('"status":"CURRENT_HEAD_V15_STATIC_VERIFIED"', verifier)

    def test_v14_and_v15_gates_use_frozen_bytes_after_current_head_advances(self) -> None:
        fixture_sha = hashlib.sha256(V14_FIXTURE.read_bytes()).hexdigest()
        v15_fixture_sha = hashlib.sha256(V15_TRUST_FIXTURE.read_bytes()).hexdigest()
        current_sha = hashlib.sha256(CURRENT_TRUST_MANIFEST.read_bytes()).hexdigest()
        self.assertEqual(
            fixture_sha,
            "6d5e98529d07f684657820a8a1d405cd243fa8ac26518ecee02a966ccc02d722",
        )
        self.assertEqual(v15_fixture_sha, "8ef9c2321866e7509bf1a959acf64370fe74abb927635c0434618287a4348171")
        self.assertNotEqual(fixture_sha, current_sha)
        self.assertNotEqual(v15_fixture_sha, current_sha)
        v14_runbook = (
            ROOT / "docs/operations/current-head-v14.md"
        ).read_text(encoding="utf-8")
        self.assertEqual(
            self.v14_verifier._current_head_v14_runbook_failures(v14_runbook),
            (),
        )

    def test_ci_keeps_history_out_of_the_live_gate_and_runs_v27(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("python -B scripts/verify_container_stack.py", ci)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v14.py"), 0)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v15.py"), 0)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v23.py"), 0)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v24.py"), 0)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v25.py"), 0)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v26.py"), 0)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v27.py"), 1)

    def test_current_pointers_advance_without_rewriting_v14(self) -> None:
        operations = (ROOT / "docs/operations/run-and-check.md").read_text(
            encoding="utf-8"
        )
        sidebar = (ROOT / "docs/_sidebar.md").read_text(encoding="utf-8")
        v14 = (ROOT / "docs/operations/current-head-v14.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "[Current-head v15 发布资产](/operations/current-head-v15.md)",
            operations,
        )
        self.assertIn(
            "[Current-head v15 发布资产](/operations/current-head-v15.md)",
            sidebar,
        )
        self.assertIn(
            "[Current-head v14 发布资产](/operations/current-head-v14.md)",
            sidebar,
        )
        self.assertIn("18|38|38|3|3|10|10|8|8|2|2", v14)
        self.assertIn("<!-- BEGIN CURRENT_HEAD_V14_CONTRACT -->", v14)

    def test_static_release_does_not_claim_execution_or_authorization(self) -> None:
        self.assertIn("STATIC VERIFIED", self.runbook)
        self.assertIn("NOT EXECUTED", self.runbook)
        self.assertIn("one-shot state: `NOT_CONSUMED`", self.runbook)
        self.assertIn('"claim":"NOT_VERIFIED"', self.runbook)
        self.assertIn('"overall_status":"BLOCKED"', self.runbook)
        self.assertIn('"production_authorized":false', self.runbook)


if __name__ == "__main__":
    unittest.main()
