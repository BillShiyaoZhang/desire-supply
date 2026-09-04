"""Static, read-only contract for IAM39 / Demand11 / Trust12 current-head v18."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
VERIFY_PATH = ROOT / "scripts/verify_current_head_v18.py"
RUNBOOK_PATH = ROOT / "docs/operations/current-head-v18.md"


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "verify_current_head_v18_test", VERIFY_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("v18 verifier cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class CurrentHeadV18ContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.verifier = _load_verifier()
        cls.runbook = RUNBOOK_PATH.read_text(encoding="utf-8")

    def test_checked_in_historical_runbook_is_closed(self) -> None:
        self.assertEqual(self.verifier._runbook_failures(self.runbook), ())

    def test_heads_contracts_and_new_migrations_are_exact(self) -> None:
        for marker in (
            "18|39|39|3|3|11|11|12|12|2|2",
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

    def test_mutated_head_or_enrollment_boundary_is_rejected(self) -> None:
        for marker, replacement in (
            (
                "18|39|39|3|3|11|11|12|12|2|2",
                "18|38|38|3|3|11|11|12|12|2|2",
            ),
            ("DEMAND_OWNER", "CREATOR"),
            ("commit acknowledgement", "commit response"),
        ):
            with self.subTest(marker=marker):
                mutated = self.runbook.replace(marker, replacement, 1)
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
        self.assertIn('"status":"CURRENT_HEAD_V18_STATIC_VERIFIED"', source)

    def test_fixtures_cover_exact_iam_demand_trust_and_runner_pins(self) -> None:
        source = VERIFY_PATH.read_text(encoding="utf-8")
        for fixture in (
            "tests/deployment/fixtures/current-head-v18",
            "iam-manifest.json",
            "demand-manifest.json",
            "trust-manifest.json",
            "trust-runner-pins.txt",
        ):
            self.assertIn(fixture, source)
        runner = (
            ROOT
            / "tests/deployment/fixtures/current-head-v18/trust-runner-pins.txt"
        ).read_text(encoding="utf-8")
        self.assertIn(self.verifier.IAM_COMBINED_SHA256, runner)
        source = VERIFY_PATH.read_text(encoding="utf-8")
        for forbidden in (
            "platform/contracts/api/iam-v1.openapi.yaml",
            "platform/contracts/events/iam-v1.schema.json",
        ):
            self.assertNotIn(forbidden, source)

    def test_enrollment_is_invitation_bound_and_authority_free_until_acceptance(self) -> None:
        for required in (
            "DEMAND_OWNER",
            "PENDING_ENROLLMENT",
            "Membership / Role authority",
            "接受邀请之前没有",
            "ORG_ADMIN",
            "普通未知身份登录",
            "HTTP response",
            "commit acknowledgement",
            "fresh Session",
            "不得复制 User、ExternalIdentity、Membership 或 Role",
        ):
            self.assertIn(required, self.runbook)

    def test_v17_files_remain_historical_not_current_aliases(self) -> None:
        v17 = (ROOT / "scripts/verify_current_head_v17.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("18|38|38|3|3|11|11|11|11|2|2", v17)
        self.assertNotIn("18|39|39|3|3|11|11|12|12|2|2", v17)
        for fixture in (
            "tests/deployment/fixtures/current-head-v17",
            "demand-manifest.json",
            "trust-manifest.json",
            "trust-runner-pins.txt",
        ):
            self.assertIn(fixture, v17)

    def test_static_publish_claims_no_execution_or_authority(self) -> None:
        self.assertIn("STATIC VERIFIED", self.runbook)
        self.assertIn("NOT EXECUTED", self.runbook)
        self.assertIn('"overall_status":"BLOCKED"', self.runbook)
        self.assertIn('"production_authorized":false', self.runbook)

    def test_v18_history_and_ci_remain_after_current_pointer_advances(self) -> None:
        sidebar = (ROOT / "docs/_sidebar.md").read_text(encoding="utf-8")
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        release = (
            ROOT / ".github/workflows/private-server-runtime-release.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "[Current-head v18 静态模式头](/operations/current-head-v18.md)",
            sidebar,
        )
        self.assertIn(
            "[Current-head v17 静态模式头](/operations/current-head-v17.md)",
            sidebar,
        )
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v17.py"), 0)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v18.py"), 0)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v19.py"), 0)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v20.py"), 0)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v21.py"), 0)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v22.py"), 0)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v23.py"), 0)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v24.py"), 0)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v25.py"), 0)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v26.py"), 0)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v27.py"), 0)
        self.assertEqual(ci.count("python -B scripts/verify_current_head_v29.py"), 1)
        self.assertEqual(
            release.count("python -B scripts/verify_current_head_v18.py"), 0
        )
        self.assertEqual(
            release.count("python -B scripts/verify_current_head_v19.py"), 0
        )
        self.assertEqual(
            release.count("python -B scripts/verify_current_head_v20.py"), 0
        )
        self.assertEqual(
            release.count("python -B scripts/verify_current_head_v21.py"), 0
        )
        self.assertEqual(
            release.count("python -B scripts/verify_current_head_v22.py"), 0
        )
        self.assertEqual(
            release.count("python -B scripts/verify_current_head_v23.py"), 0
        )
        self.assertEqual(
            release.count("python -B scripts/verify_current_head_v24.py"), 0
        )
        self.assertEqual(
            release.count("python -B scripts/verify_current_head_v25.py"), 0
        )
        self.assertEqual(
            release.count("python -B scripts/verify_current_head_v26.py"), 0
        )
        self.assertEqual(
            release.count("python -B scripts/verify_current_head_v27.py"), 0
        )
        self.assertEqual(
            release.count("python -B scripts/verify_current_head_v29.py"), 1
        )


if __name__ == "__main__":
    unittest.main()
