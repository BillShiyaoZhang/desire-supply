"""Static, read-only contract for IAM42 / Demand12 / Trust16 current-head v22."""

from __future__ import annotations

import importlib.util
import hashlib
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
VERIFY_PATH = ROOT / "scripts/verify_current_head_v22.py"
CURRENT_VERIFY_PATH = ROOT / "scripts/verify_current_head_v27.py"
RUNBOOK_PATH = ROOT / "docs/operations/current-head-v22.md"


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "verify_current_head_v22_test", VERIFY_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("v22 verifier cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class CurrentHeadV22ContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.verifier = _load_verifier()
        cls.runbook = RUNBOOK_PATH.read_text(encoding="utf-8")

    def test_checked_in_v22_publication_assets_remain_byte_frozen(self) -> None:
        frozen = {
            "scripts/verify_current_head_v22.py": (
                "258f28418be907438d16247148c79506238f363bf7163075d4d9674bfc1a17f0"
            ),
            "docs/operations/current-head-v22.md": (
                "5b2bc6ba4784917f264f89733f13f1fae73a9263c647ed8c016dc7499bac3c65"
            ),
            "tests/deployment/fixtures/current-head-v22/iam-manifest.json": (
                "9c6e0396867d68ac49260684a9531c592055d62cac20d7ebdfb578c236df025d"
            ),
            "tests/deployment/fixtures/current-head-v22/demand-manifest.json": (
                "919d62a9b32dc29619a561940f9c79e21700562a0cdd9ef7e9f13a40cea43345"
            ),
            "tests/deployment/fixtures/current-head-v22/trust-manifest.json": (
                "71b61f666ea9d924a7edae14db1bf3cc20905618d806d0c8e76b94066c07672c"
            ),
            "tests/deployment/fixtures/current-head-v22/trust-runner-pins.txt": (
                "c06f8e25b12d919071029dd50868a07a6c322d17b02c7adbd0632675f211b425"
            ),
        }
        for relative, expected in frozen.items():
            with self.subTest(relative=relative):
                self.assertEqual(
                    hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
                    expected,
                )

    def test_heads_contracts_and_new_migrations_are_exact(self) -> None:
        for marker in (
            "18|42|42|3|3|12|12|16|16|2|2",
            self.verifier.EXPECTED_CONTRACTS,
            self.verifier.IAM_SQL_SHA256,
            self.verifier.IAM_MANIFEST_SHA256,
            self.verifier.IAM_COMBINED_SHA256,
            self.verifier.DEMAND_SQL_SHA256,
            self.verifier.TRUST_API_SHA256,
            self.verifier.TRUST_SQL_SHA256,
            self.verifier.TRUST_MANIFEST_SHA256,
            self.verifier.TRUST_COMBINED_SHA256,
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.runbook)

    def test_mutated_head_snapshot_or_version_boundary_is_rejected(self) -> None:
        for marker, replacement in (
            (
                "18|42|42|3|3|12|12|16|16|2|2",
                "18|42|42|3|3|11|11|15|15|2|2",
            ),
            ("canonical public_name", "normalized organization label"),
            ("six-command idempotency", "per-command idempotency"),
        ):
            with self.subTest(marker=marker):
                mutated = self.runbook.replace(marker, replacement)
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
        self.assertIn('"status":"CURRENT_HEAD_V22_STATIC_VERIFIED"', source)

    def test_fixtures_cover_exact_iam_demand_trust_and_runner_pins(self) -> None:
        source = VERIFY_PATH.read_text(encoding="utf-8")
        for fixture in (
            "tests/deployment/fixtures/current-head-v22",
            "iam-manifest.json",
            "demand-manifest.json",
            "trust-manifest.json",
            "trust-runner-pins.txt",
        ):
            self.assertIn(fixture, source)
        runner = (
            ROOT
            / "tests/deployment/fixtures/current-head-v22/trust-runner-pins.txt"
        ).read_text(encoding="utf-8")
        self.assertIn(self.verifier.IAM_COMBINED_SHA256, runner)

    def test_v27_verifier_owns_the_live_gate_and_pins_v26_history(self) -> None:
        source = CURRENT_VERIFY_PATH.read_text(encoding="utf-8")
        for required in (
            "tests/deployment/fixtures/current-head-v27/schema-pins.json",
            "tests/deployment/fixtures/current-head-v26/iam-manifest.json",
            "7edad01ff151168e4e048848fe770eb0ea199a1034a8119658a1c3bf53205b5e",
            "5663d8e14bb5fa6a5706828fe443a8c08ac2e62bad3e56403dd45bc6df939b29",
        ):
            self.assertIn(required, source)
        self.assertNotIn("test_current_head_v26_contract.py", source)

    def test_public_name_boundary_is_canonical_atomic_and_private(self) -> None:
        for required in (
            "ORG_ADMIN",
            "public-name correction",
            "canonical public_name",
            "six-command idempotency",
            "current ETag",
            "receipt replay",
            "412 PRECONDITION_FAILED",
            "audit/event name privacy",
        ):
            self.assertIn(required, self.runbook)

    def test_finance_history_is_actor_owned_terminal_and_discoverable(self) -> None:
        for required in (
            "FINANCE_OPERATOR",
            "my completed funding reviews",
            "actor-bound cursor",
            "own confirmation or own finding",
            "SECURED / DISCREPANCY / REJECTED",
            "我的已完成资金审查",
        ):
            self.assertIn(required, self.runbook)

    def test_upgrade_preflight_requires_writer_quiescence(self) -> None:
        for required in (
            "REPEATABLE READ READ ONLY",
            "writer quiescence",
            "provisioning advisory lock",
            "IAM42 CHECK",
        ):
            self.assertIn(required, self.runbook)

    def test_v21_remains_frozen_and_does_not_alias_live_v22_assets(self) -> None:
        v21 = (ROOT / "scripts/verify_current_head_v21.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("18|42|42|3|3|11|11|15|15|2|2", v21)
        self.assertNotIn("18|42|42|3|3|12|12|16|16|2|2", v21)
        for fixture in (
            "tests/deployment/fixtures/current-head-v21",
            "iam-manifest.json",
            "demand-manifest.json",
            "trust-manifest.json",
            "trust-runner-pins.txt",
        ):
            self.assertIn(fixture, v21)
        for forbidden in (
            '(iam_root / "manifest.json",',
            '(demand_root / "manifest.json",',
            '(trust_root / "manifest.json",',
            'trust_runner = _read(trust_root / "runner.py")',
        ):
            self.assertNotIn(forbidden, v21)

    def test_static_publish_claims_no_execution_or_authority(self) -> None:
        self.assertIn("STATIC VERIFIED", self.runbook)
        self.assertIn("NOT EXECUTED", self.runbook)
        self.assertIn('"overall_status":"BLOCKED"', self.runbook)
        self.assertIn('"production_authorized":false', self.runbook)

    def test_runtime_release_schema_advances_without_relabeling_v22(self) -> None:
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

    def test_current_pointer_and_workflows_keep_v22_frozen_not_executed(self) -> None:
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
            "[Current-head v22 静态模式头](/operations/current-head-v22.md)",
            "[Current-head v21 静态模式头](/operations/current-head-v21.md)",
            "[Current-head v20 静态模式头](/operations/current-head-v20.md)",
        ):
            self.assertIn(marker, sidebar)
        v20 = "python -B scripts/verify_current_head_v20.py"
        v21 = "python -B scripts/verify_current_head_v21.py"
        v22 = "python -B scripts/verify_current_head_v22.py"
        v23 = "python -B scripts/verify_current_head_v23.py"
        v24 = "python -B scripts/verify_current_head_v24.py"
        v25 = "python -B scripts/verify_current_head_v25.py"
        v26 = "python -B scripts/verify_current_head_v26.py"
        v27 = "python -B scripts/verify_current_head_v27.py"
        v28 = "python -B scripts/verify_current_head_v28.py"
        self.assertEqual(ci.count(v20), 0)
        self.assertEqual(ci.count(v21), 0)
        self.assertEqual(ci.count(v22), 0)
        self.assertEqual(ci.count(v23), 0)
        self.assertEqual(ci.count(v24), 0)
        self.assertEqual(ci.count(v25), 0)
        self.assertEqual(ci.count(v26), 0)
        self.assertEqual(ci.count(v27), 0)
        self.assertEqual(ci.count(v28), 1)
        for version in range(14, 28):
            self.assertNotIn(
                f"python -B scripts/verify_current_head_v{version}.py",
                release,
            )
        self.assertEqual(release.count(v28), 1)

    def test_operational_summaries_do_not_relabel_v22_dynamic_evidence(self) -> None:
        operations = "\n".join(
            (ROOT / path).read_text(encoding="utf-8")
            for path in (
                "docs/operations/run-and-check.md",
                "docs/operations/container-deployment.md",
                "docs/operations/local-internal-sandbox-trial.md",
            )
        )
        for forbidden in (
            "IAM42/Trust15 的 current checkout",
            "current checkout 的 IAM42/Trust15",
            "### 4.6.3 当前 IAM42/Trust15",
            "### 2.2 当前 IAM42/Trust15",
            "current-head v21 上完成",
            "当前合同只见\nv16 页面",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, operations)
        for required in (
            "IAM `0042`",
            "Demand `0012`",
            "Trust `0018`",
            "Trust `0017`",
            "IAM46/Profile5/Demand15/Trust22/Matching3/Taxonomy2 current-head v27",
            "IAM43/Demand13/Trust19 现在只属于冻结 v26",
            "### 2.4 历史：v23 IAM42/Demand12/Trust17",
            "IAM42/Demand12/Trust16",
        ):
            with self.subTest(required=required):
                self.assertIn(required, operations)

        source = CURRENT_VERIFY_PATH.read_text(encoding="utf-8")
        for required in (
            "docs/operations/run-and-check.md",
            "docs/operations/container-deployment.md",
            "current-head-v27-live-operations-pointer-open",
            "current-head-v27-unversioned-operations-pointer-open",
        ):
            self.assertIn(required, source)


if __name__ == "__main__":
    unittest.main()
