"""Frozen historical contract for IAM42 / Demand12 / Trust17 current-head v23."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
VERIFY_PATH = ROOT / "scripts/verify_current_head_v23.py"
CURRENT_VERIFY_PATH = ROOT / "scripts/verify_current_head_v27.py"
RUNBOOK_PATH = ROOT / "docs/operations/current-head-v23.md"


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "verify_current_head_v23_history_test", VERIFY_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("v23 verifier cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class CurrentHeadV23ContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.verifier = _load_verifier()
        cls.runbook = RUNBOOK_PATH.read_text(encoding="utf-8")

    def test_checked_in_v23_publication_assets_remain_byte_frozen(self) -> None:
        frozen = {
            "scripts/verify_current_head_v23.py": (
                "1a1216c2b4ce87933a4f61e121513f028bfd23ed9f7ce12091d6924be195b33c"
            ),
            "docs/operations/current-head-v23.md": (
                "3b44f69854895899d25dc78453e55b2d251ee3a7a20b91e1e17d3c368dc535c6"
            ),
            "tests/deployment/fixtures/current-head-v23/iam-manifest.json": (
                "9c6e0396867d68ac49260684a9531c592055d62cac20d7ebdfb578c236df025d"
            ),
            "tests/deployment/fixtures/current-head-v23/demand-manifest.json": (
                "919d62a9b32dc29619a561940f9c79e21700562a0cdd9ef7e9f13a40cea43345"
            ),
            "tests/deployment/fixtures/current-head-v23/trust-manifest.json": (
                "57c0dd42e18bf3afa7233f9ad673ec3805b325166436a4a1e3021466cd62381f"
            ),
            "tests/deployment/fixtures/current-head-v23/trust-runner-pins.txt": (
                "2c3c1d1c6378c273eb73f5d05ae2f767b841493669f154edbff915dbc37e742a"
            ),
        }
        for relative, expected in frozen.items():
            with self.subTest(relative=relative):
                self.assertEqual(
                    hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
                    expected,
                )

    def test_v23_heads_contracts_and_history_boundary_remain_documented(self) -> None:
        for marker in (
            "18|42|42|3|3|12|12|17|17|2|2",
            self.verifier.EXPECTED_CONTRACTS,
            self.verifier.TRUST_API_SHA256,
            self.verifier.TRUST_SQL_SHA256,
            self.verifier.TRUST_MANIFEST_SHA256,
            self.verifier.TRUST_COMBINED_SHA256,
            "/v1/app/trust/history",
            "trust_terminal_history_discoverable",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.runbook)

    def test_v23_verifier_remains_read_only_runtime_free_history(self) -> None:
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
        self.assertIn('"status":"CURRENT_HEAD_V23_STATIC_VERIFIED"', source)

    def test_v27_live_verifier_pins_v26_history(self) -> None:
        source = CURRENT_VERIFY_PATH.read_text(encoding="utf-8")
        for required in (
            "tests/deployment/fixtures/current-head-v27/schema-pins.json",
            "tests/deployment/fixtures/current-head-v26/iam-manifest.json",
            "7edad01ff151168e4e048848fe770eb0ea199a1034a8119658a1c3bf53205b5e",
            "5663d8e14bb5fa6a5706828fe443a8c08ac2e62bad3e56403dd45bc6df939b29",
        ):
            self.assertIn(required, source)
        self.assertNotIn("test_current_head_v26_contract.py", source)

    def test_v23_static_claim_never_becomes_execution_or_authority(self) -> None:
        self.assertIn("STATIC VERIFIED", self.runbook)
        self.assertIn("NOT EXECUTED", self.runbook)
        self.assertIn('"overall_status":"BLOCKED"', self.runbook)
        self.assertIn('"production_authorized":false', self.runbook)

    def test_runtime_release_advances_without_relabeling_v23(self) -> None:
        runtime = (ROOT / "scripts/private_server_runtime_release.py").read_text(
            encoding="utf-8"
        )
        schema = (
            ROOT / "deploy/private-server-runtime-release-v1.schema.json"
        ).read_text(encoding="utf-8")
        for marker in (
            '"iam": 46',
            '"profile": 5',
            '"demand": 15',
            '"trust": 22',
            '"matching": 9',
        ):
            self.assertIn(marker, runtime)
        for marker in (
            '"iam": {"const": 46}',
            '"profile": {"const": 5}',
            '"demand": {"const": 15}',
            '"trust": {"const": 22}',
            '"matching": {"const": 9}',
        ):
            self.assertIn(marker, schema)
        self.assertIn("Trust17", self.runbook)

    def test_current_pointer_and_workflows_keep_v23_as_history(self) -> None:
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
            "[Current-head v23 静态模式头](/operations/current-head-v23.md)",
        ):
            self.assertIn(marker, sidebar)
        v23 = "python -B scripts/verify_current_head_v23.py"
        v24 = "python -B scripts/verify_current_head_v24.py"
        v25 = "python -B scripts/verify_current_head_v25.py"
        v26 = "python -B scripts/verify_current_head_v26.py"
        v27 = "python -B scripts/verify_current_head_v27.py"
        v28 = "python -B scripts/verify_current_head_v28.py"
        self.assertEqual(ci.count(v23), 0)
        self.assertEqual(ci.count(v24), 0)
        self.assertEqual(ci.count(v25), 0)
        self.assertEqual(ci.count(v26), 0)
        self.assertEqual(ci.count(v27), 0)
        self.assertEqual(ci.count(v28), 1)
        self.assertEqual(release.count(v23), 0)
        self.assertEqual(release.count(v24), 0)
        self.assertEqual(release.count(v25), 0)
        self.assertEqual(release.count(v26), 0)
        self.assertEqual(release.count(v27), 0)
        self.assertEqual(release.count(v28), 1)


if __name__ == "__main__":
    unittest.main()
