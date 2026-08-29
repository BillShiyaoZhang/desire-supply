"""Fail-closed static contract for the current-head v14 release assets."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
VERIFY_PATH = ROOT / "scripts" / "verify_current_head_v14.py"
RUNBOOK_PATH = ROOT / "docs" / "operations" / "current-head-v14.md"


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "verify_current_head_v14_test",
        VERIFY_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("v14 verifier cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class CurrentHeadV14RunbookTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.verifier = _load_verifier()
        cls.runbook = RUNBOOK_PATH.read_text(encoding="utf-8")

    def test_checked_in_historical_runbook_is_closed(self) -> None:
        self.assertEqual(
            self.verifier._current_head_v14_runbook_failures(self.runbook),
            (),
        )

    def test_heads_contracts_and_coordinates_are_exact(self) -> None:
        expected = (
            "18|38|38|3|3|10|10|8|8|2|2",
            (
                "908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e|"
                "4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa|"
                "7695127a039fa71cddabd62318bea39337e3acbb4b1df66a3557b7a7ae3707b4|"
                "38|10|"
                "908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e|"
                "27ec6b585a9340cbd7119d7a9b46d6098a3881f88ae1be9e00df3713c0107113|"
                "8907369e35172587753295403dc101227c21671960539c51364f8e00f1e4978a|"
                "6d5e98529d07f684657820a8a1d405cd243fa8ac26518ecee02a966ccc02d722|"
                "74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622"
            ),
            "908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e",
            "4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa",
            "7695127a039fa71cddabd62318bea39337e3acbb4b1df66a3557b7a7ae3707b4",
            "27ec6b585a9340cbd7119d7a9b46d6098a3881f88ae1be9e00df3713c0107113",
            "6d5e98529d07f684657820a8a1d405cd243fa8ac26518ecee02a966ccc02d722",
            "8907369e35172587753295403dc101227c21671960539c51364f8e00f1e4978a",
            "74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622",
            "e2e-ten-account-v14-iam38-demand10-trust8",
            "internal-sandbox-bundle-iam38-demand10-trust8",
            "release-e2e-ten-account-v14-iam38-demand10-trust8",
            "v14-iam38-profile3-demand10-trust8-taxonomy2-drill01",
        )
        for value in expected:
            with self.subTest(value=value):
                self.assertIn(value, self.runbook)

        for old in (
            "e2e-ten-account-v13-iam37-demand10-trust7",
            "internal-sandbox-bundle-iam37-demand10-trust7",
            "release-e2e-ten-account-v13-iam37-demand10-trust7",
        ):
            self.assertNotIn(old, self.runbook)

        for label in (
            "IAM combined contract",
            "Profile manifest",
            "Demand manifest",
            "Trust required IAM schema",
            "Trust required Demand schema",
            "Trust required IAM combined contract",
            "Trust required Demand dependency",
            "Trust combined contract",
            "Trust manifest",
            "Taxonomy manifest",
        ):
            with self.subTest(label=label):
                self.assertIn(label, self.runbook)

    def test_each_reviewed_coordinate_or_head_mutation_is_rejected(self) -> None:
        mutations = (
            ("18|38|38|3|3|10|10|8|8|2|2", "18|38|38|3|3|10|10|7|7|2|2"),
            ("e2e-ten-account-v14-iam38-demand10-trust8", "e2e-ten-account-v14-latest"),
            ("internal-sandbox-bundle-iam38-demand10-trust8", "internal-sandbox-bundle-current"),
            ("release-e2e-ten-account-v14-iam38-demand10-trust8", "release-current"),
            ("v14-iam38-profile3-demand10-trust8-taxonomy2-drill01", "backup-current"),
        )
        for old, new in mutations:
            with self.subTest(old=old):
                mutated = self.runbook.replace(old, new)
                self.assertTrue(
                    self.verifier._current_head_v14_runbook_failures(mutated)
                )

    def test_operations_helper_uses_exactly_three_compose_layers(self) -> None:
        helper = self.runbook.partition("compose_v14_operations() {")[2].partition(
            "\n}"
        )[0]
        self.assertTrue(helper)
        self.assertEqual(helper.count("-f \"$PWD/"), 3)
        self.assertIn('-f "$PWD/compose.yaml"', helper)
        self.assertIn('-f "$PWD/deploy/postgres-operations.compose.yaml"', helper)
        self.assertIn('-f "$PWD/deploy/postgres-operations-v14.compose.yaml"', helper)
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
        self.assertIn('"status":"CURRENT_HEAD_V14_STATIC_VERIFIED"', verifier)

    def test_ci_preserves_legacy_stack_validation_and_runs_only_v27_head_gate(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("python -B scripts/verify_container_stack.py", ci)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v14.py"), 0)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v23.py"), 0)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v24.py"), 0)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v25.py"), 0)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v26.py"), 0)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v27.py"), 1)

    def test_current_pointers_do_not_rewrite_the_frozen_v13_runbook(self) -> None:
        operations = (ROOT / "docs/operations/run-and-check.md").read_text(
            encoding="utf-8"
        )
        private = (
            ROOT / "docs/operations/private-server-internal-sandbox.md"
        ).read_text(encoding="utf-8")
        self.assertIn("[Current-head v14 发布资产](/operations/current-head-v14.md)", operations)
        self.assertIn("private-server-release-candidate-evidence-v2.schema.json", private)
        self.assertIn("private_server_release_candidate_evidence_v2.py", private)
        self.assertIn(
            "### 4.7.1 当前头部 v13 fresh、replay、journey 与 restart（一次性）",
            operations,
        )
        self.assertIn("# BEGIN CURRENT_HEAD_V13_FRESH_RUNBOOK", operations)


if __name__ == "__main__":
    unittest.main()
