"""Static, read-only contract for IAM42 / Demand11 / Trust15 current-head v21."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
VERIFY_PATH = ROOT / "scripts/verify_current_head_v21.py"
RUNBOOK_PATH = ROOT / "docs/operations/current-head-v21.md"


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "verify_current_head_v21_test", VERIFY_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("v21 verifier cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class CurrentHeadV21ContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.verifier = _load_verifier()
        cls.runbook = RUNBOOK_PATH.read_text(encoding="utf-8")

    def test_checked_in_historical_runbook_is_closed(self) -> None:
        self.assertEqual(self.verifier._runbook_failures(self.runbook), ())

    def test_heads_contracts_and_new_migrations_are_exact(self) -> None:
        for marker in (
            "18|42|42|3|3|11|11|15|15|2|2",
            self.verifier.EXPECTED_CONTRACTS,
            self.verifier.IAM_SQL_SHA256,
            self.verifier.IAM_MANIFEST_SHA256,
            self.verifier.IAM_COMBINED_SHA256,
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
                "18|42|42|3|3|11|11|15|15|2|2",
                "18|41|41|3|3|11|11|14|14|2|2",
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
        self.assertIn('"status":"CURRENT_HEAD_V21_STATIC_VERIFIED"', source)

    def test_fixtures_cover_exact_iam_demand_trust_and_runner_pins(self) -> None:
        source = VERIFY_PATH.read_text(encoding="utf-8")
        for fixture in (
            "tests/deployment/fixtures/current-head-v21",
            "iam-manifest.json",
            "demand-manifest.json",
            "trust-manifest.json",
            "trust-runner-pins.txt",
        ):
            self.assertIn(fixture, source)
        runner = (
            ROOT
            / "tests/deployment/fixtures/current-head-v21/trust-runner-pins.txt"
        ).read_text(encoding="utf-8")
        self.assertIn(self.verifier.IAM_COMBINED_SHA256, runner)

    def test_v21_is_frozen_after_the_current_head_advances(self) -> None:
        source = VERIFY_PATH.read_text(encoding="utf-8")
        for required in (
            'fixture_root / "iam-manifest.json"',
            'fixture_root / "demand-manifest.json"',
            'fixture_root / "trust-manifest.json"',
            'fixture_root / "trust-runner-pins.txt"',
            'platform/contracts/api/iam-v1.openapi.yaml',
            'platform/contracts/events/iam-v1.schema.json',
        ):
            self.assertIn(required, source)
        for forbidden in (
            '(iam_root / "manifest.json",',
            '(demand_root / "manifest.json",',
            '(trust_root / "manifest.json",',
            'iam_catalog = _read(iam_root / "catalog.py")',
            'trust_catalog = _read(trust_root / "catalog.py")',
            'trust_runner = _read(trust_root / "runner.py")',
        ):
            self.assertNotIn(forbidden, source)
        self.assertEqual(
            self.verifier._iam_combined(ROOT),
            self.verifier.IAM_COMBINED_SHA256,
        )

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

    def test_v20_remains_frozen_and_does_not_alias_live_v21_assets(self) -> None:
        v20 = (ROOT / "scripts/verify_current_head_v20.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("18|41|41|3|3|11|11|14|14|2|2", v20)
        self.assertNotIn("18|42|42|3|3|11|11|15|15|2|2", v20)
        for fixture in (
            "tests/deployment/fixtures/current-head-v20",
            "iam-manifest.json",
            "demand-manifest.json",
            "trust-manifest.json",
            "trust-runner-pins.txt",
        ):
            self.assertIn(fixture, v20)
        for forbidden in (
            'iam_root / "manifest.json"',
            'trust_root / "manifest.json"',
            'trust_root / "runner.py"',
        ):
            self.assertNotIn(forbidden, v20)

    def test_static_publish_claims_no_execution_or_authority(self) -> None:
        self.assertIn("STATIC VERIFIED", self.runbook)
        self.assertIn("NOT EXECUTED", self.runbook)
        self.assertIn('"overall_status":"BLOCKED"', self.runbook)
        self.assertIn('"production_authorized":false', self.runbook)

    def test_runtime_release_schema_advances_without_relabeling_v21(self) -> None:
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

    def test_current_pointer_and_workflows_keep_v21_as_ci_history(self) -> None:
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


if __name__ == "__main__":
    unittest.main()
