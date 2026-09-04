"""Frozen historical contract for IAM42 / Demand12 / Trust18 current-head v24."""

from __future__ import annotations

import hashlib
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
VERIFY_PATH = ROOT / "scripts/verify_current_head_v24.py"
CURRENT_VERIFY_PATH = ROOT / "scripts/verify_current_head_v27.py"
RUNBOOK_PATH = ROOT / "docs/operations/current-head-v24.md"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class CurrentHeadV24ContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runbook = RUNBOOK_PATH.read_text(encoding="utf-8")

    def test_checked_in_v24_publication_assets_remain_byte_frozen(self) -> None:
        frozen = {
            "scripts/verify_current_head_v24.py": (
                "c80a30558111792762f9a4afd44cf4e416fa9c56ebc413402cabc21b684a394a"
            ),
            "docs/operations/current-head-v24.md": (
                "b479dc68c6388bd61c4e65fce4c5300a691af03c73f1ae78eae355e6cb3796c1"
            ),
            "tests/deployment/fixtures/current-head-v24/iam-manifest.json": (
                "9c6e0396867d68ac49260684a9531c592055d62cac20d7ebdfb578c236df025d"
            ),
            "tests/deployment/fixtures/current-head-v24/demand-manifest.json": (
                "919d62a9b32dc29619a561940f9c79e21700562a0cdd9ef7e9f13a40cea43345"
            ),
            "tests/deployment/fixtures/current-head-v24/trust-manifest.json": (
                "0b7028c75c8f137bc4a55a76fe73ea956d0c5ada13031f80794b77c1c9535e19"
            ),
            "tests/deployment/fixtures/current-head-v24/trust-runner-pins.txt": (
                "91b0381051753738e045ff6c019fb30757adfcf588bf3c45bc336c56c74678d0"
            ),
        }
        for relative, expected in frozen.items():
            with self.subTest(relative=relative):
                self.assertEqual(_sha(ROOT / relative), expected)

    def test_v24_heads_and_appeal_history_boundary_remain_documented(self) -> None:
        for marker in (
            "18|42|42|3|3|12|12|18|18|2|2",
            "/v1/app/appeal-review/history",
            "APPEAL_REVIEWER",
            "VIEW_APPEAL_REVIEW_HISTORY",
            "fresh exact terminal detail",
            "terminal_history_discoverable",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.runbook)

    def test_v24_verifier_remains_read_only_runtime_free_history(self) -> None:
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
        self.assertIn('"status":"CURRENT_HEAD_V24_STATIC_VERIFIED"', source)

    def test_v27_live_verifier_pins_v26_history(self) -> None:
        source = CURRENT_VERIFY_PATH.read_text(encoding="utf-8")
        for required in (
            "tests/deployment/fixtures/current-head-v27/schema-pins.json",
            "tests/deployment/fixtures/current-head-v26/trust-manifest.json",
            "5949f7b630376a59c643f9024210625811606a1a41f90f4bc99ee19dfb99d38c",
            "2c51f1df80ca8f3fcdca38c66b7d82fbc9a254744f69ba73ec9b0e54cd6c3f77",
        ):
            self.assertIn(required, source)
        self.assertNotIn("test_current_head_v26_contract.py", source)

    def test_v24_static_claim_never_becomes_execution_or_authority(self) -> None:
        self.assertIn("STATIC VERIFIED", self.runbook)
        self.assertIn("NOT EXECUTED", self.runbook)
        self.assertIn('"overall_status":"BLOCKED"', self.runbook)
        self.assertIn('"production_authorized":false', self.runbook)

    def test_runtime_release_advances_without_relabeling_v24(self) -> None:
        runtime = (ROOT / "scripts/private_server_runtime_release.py").read_text(
            encoding="utf-8"
        )
        schema = (
            ROOT / "deploy/private-server-runtime-release-v1.schema.json"
        ).read_text(encoding="utf-8")
        for marker in (
            '"iam": 48',
            '"profile": 5',
            '"demand": 16',
            '"trust": 24',
            '"matching": 11',
        ):
            self.assertIn(marker, runtime)
        for marker in (
            '"iam": {"const": 48}',
            '"profile": {"const": 5}',
            '"demand": {"const": 16}',
            '"trust": {"const": 24}',
            '"matching": {"const": 11}',
        ):
            self.assertIn(marker, schema)

    def test_current_pointer_and_workflows_keep_v24_as_history(self) -> None:
        sidebar = (ROOT / "docs/_sidebar.md").read_text(encoding="utf-8")
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        release = (
            ROOT / ".github/workflows/private-server-runtime-release.yml"
        ).read_text(encoding="utf-8")
        for marker in (
            "[Current-head v27 静态模式头](/operations/current-head-v27.md)",
            "[Current-head v26 静态模式头](/operations/current-head-v26.md)",
            "[Current-head v25 静态模式头](/operations/current-head-v25.md)",
            "[Current-head v24 静态模式头](/operations/current-head-v24.md)",
        ):
            self.assertIn(marker, sidebar)
        v24 = "python -B scripts/verify_current_head_v24.py"
        v25 = "python -B scripts/verify_current_head_v25.py"
        v26 = "python -B scripts/verify_current_head_v26.py"
        v27 = "python -B scripts/verify_current_head_v27.py"
        v30 = "python -B scripts/verify_current_head_v30.py"
        self.assertEqual(ci.count(v24), 0)
        self.assertEqual(ci.count(v25), 0)
        self.assertEqual(ci.count(v26), 0)
        self.assertEqual(ci.count(v27), 0)
        self.assertEqual(ci.count(v30), 1)
        self.assertEqual(release.count(v24), 0)
        self.assertEqual(release.count(v25), 0)
        self.assertEqual(release.count(v26), 0)
        self.assertEqual(release.count(v27), 0)
        self.assertEqual(release.count(v30), 1)

    def test_operational_summaries_keep_v24_dynamic_evidence_historical(self) -> None:
        operations = "\n".join(
            (ROOT / path).read_text(encoding="utf-8")
            for path in (
                "docs/operations/run-and-check.md",
                "docs/operations/container-deployment.md",
                "docs/operations/local-internal-sandbox-trial.md",
            )
        )
        for required in (
            "### 4.6.6 历史冻结：v24 IAM42/Demand12/Trust18 本地动态证据",
            "### 2.5 历史冻结：v24 IAM42/Demand12/Trust18 本地动态证据",
            "## Frozen v24 local dynamic acceptance evidence",
            "STATIC VERIFIED / NOT PRODUCTION EXECUTED",
            "完整桌面/移动视觉 QA 继续保持未完成",
        ):
            with self.subTest(required=required):
                self.assertIn(required, operations)
        self.assertNotIn("v25 local dynamic acceptance evidence", operations)


if __name__ == "__main__":
    unittest.main()
