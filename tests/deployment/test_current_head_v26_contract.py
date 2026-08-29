"""Frozen static contract for the historical IAM43/Demand13/Trust19 v26 head."""

from __future__ import annotations

from contextlib import redirect_stderr
import hashlib
import importlib.util
from io import StringIO
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
VERIFY_PATH = ROOT / "scripts/verify_current_head_v26.py"
RUNBOOK_PATH = ROOT / "docs/operations/current-head-v26.md"


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "verify_current_head_v26_test", VERIFY_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("v26 verifier cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class CurrentHeadV26ContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.verifier = _load_verifier()
        cls.runbook = RUNBOOK_PATH.read_text(encoding="utf-8")

    def test_checked_in_historical_contract_retains_its_closed_pins(self) -> None:
        self.assertEqual(
            self.verifier.HEADS,
            "18|43|43|3|3|13|13|19|19|2|2",
        )
        self.assertEqual(
            self.verifier.SUCCESS,
            '{"status":"CURRENT_HEAD_V26_STATIC_VERIFIED"}',
        )
        self.assertEqual(
            self.runbook.count("<!-- BEGIN CURRENT_HEAD_V26_CONTRACT -->"),
            1,
        )
        self.assertEqual(
            self.runbook.count("<!-- END CURRENT_HEAD_V26_CONTRACT -->"),
            1,
        )

    def test_schema_heads_and_contracts_are_exactly_iam43_demand13_trust19(
        self,
    ) -> None:
        for marker in (
            "18|43|43|3|3|13|13|19|19|2|2",
            self.verifier.EXPECTED_CONTRACTS,
            self.verifier.IAM_SQL_SHA256,
            self.verifier.IAM_MANIFEST_SHA256,
            self.verifier.IAM_COMBINED_SHA256,
            self.verifier.DEMAND_API_SHA256,
            self.verifier.DEMAND_EVENT_SHA256,
            self.verifier.DEMAND_SQL_SHA256,
            self.verifier.DEMAND_MANIFEST_SHA256,
            self.verifier.DEMAND_DEPENDENCY_SHA256,
            self.verifier.TRUST_SQL_SHA256,
            self.verifier.TRUST_MANIFEST_SHA256,
            self.verifier.TRUST_COMBINED_SHA256,
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.runbook)

    def test_release_boundary_is_closed_and_mutations_are_rejected(self) -> None:
        required = (
            "OPERATIONS_REVIEWER",
            "RELEASE_REVIEW_ASSIGNMENT",
            "/v1/app/demands/{demand_id}/review-assignments/{assignment_id}/release",
            "CONFLICT_DECLARED / WORKLOAD_RELEASE",
            "completed receipt recovery",
            "If-Match",
            "Idempotency-Key",
            "CSRF",
            "DemandReviewAssignmentReleased",
            "demand_review_assignment_releases",
            "same reviewer",
            "same submission/version",
            "immediately available",
        )
        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, self.runbook)
        for marker, replacement in (
            ("CONFLICT_DECLARED / WORKLOAD_RELEASE", "FREE_TEXT"),
            ("completed receipt recovery", "write before replay"),
            ("same submission/version", "all future versions"),
            ("review_assignment=null", "review_assignment=ACTIVE"),
            ("DemandReviewAssignmentReleased", "DemandVerified"),
        ):
            with self.subTest(marker=marker):
                mutated = self.runbook.replace(marker, replacement)
                self.assertTrue(self.verifier._runbook_failures(mutated))

    def test_release_facts_cover_empty_target_and_core_facts_exactly_once(
        self,
    ) -> None:
        v25_script = (
            ROOT / "deploy/postgres-backup-restore-v25.sh"
        ).read_text(encoding="utf-8")
        v26_script = (
            ROOT / "deploy/postgres-backup-restore-v26.sh"
        ).read_text(encoding="utf-8")
        v25_facts = (ROOT / "deploy/postgres-core-facts-v25.sql").read_text(
            encoding="utf-8"
        )
        v26_facts = (ROOT / "deploy/postgres-core-facts-v26.sql").read_text(
            encoding="utf-8"
        )
        overlay = (
            ROOT / "deploy/postgres-operations-v26.compose.yaml"
        ).read_text(encoding="utf-8")

        self.assertEqual(
            self.verifier._postgres_operations_v26_failures(
                v25_script,
                v26_script,
                v25_facts,
                v26_facts,
                overlay,
            ),
            (),
        )
        self.assertEqual(
            v26_script.count("FROM demand.demand_review_assignment_releases"),
            1,
        )
        self.assertEqual(
            v26_facts.count("FROM demand.demand_review_assignment_releases"),
            1,
        )

    def test_v26_fixtures_are_exact_frozen_manifest_snapshots(self) -> None:
        fixture_root = ROOT / "tests/deployment/fixtures/current-head-v26"
        expected_versions = {
            "iam-manifest.json": ("iam", tuple(range(44))),
            "demand-manifest.json": ("demand", tuple(range(1, 14))),
            "trust-manifest.json": ("trust", tuple(range(1, 20))),
        }
        for name, (component, versions) in expected_versions.items():
            with self.subTest(name=name):
                fixture = fixture_root / name
                document = json.loads(fixture.read_text(encoding="utf-8"))
                self.assertEqual(
                    tuple(
                        item["version"]
                        for item in document
                        if item["component"] == component
                    ),
                    versions,
                )
        self.assertEqual(
            _sha(fixture_root / "trust-runner-pins.txt"),
            "2c51f1df80ca8f3fcdca38c66b7d82fbc9a254744f69ba73ec9b0e54cd6c3f77",
        )

    def test_v25_evidence_assets_remain_byte_frozen(self) -> None:
        frozen = {
            "scripts/verify_current_head_v25.py": (
                "34a45ff42311d342cafe4d9a6abc8a7453b0012ebb6daf1685bf9bd3e0c6adea"
            ),
            "docs/operations/current-head-v25.md": (
                "c3ddb2cf4a0ea254229cb1d0da38c462e7c0b2b4ac943b14d92594d1cf0f3881"
            ),
            "tests/deployment/fixtures/current-head-v25/iam-manifest.json": (
                "9c6e0396867d68ac49260684a9531c592055d62cac20d7ebdfb578c236df025d"
            ),
            "tests/deployment/fixtures/current-head-v25/demand-manifest.json": (
                "919d62a9b32dc29619a561940f9c79e21700562a0cdd9ef7e9f13a40cea43345"
            ),
            "tests/deployment/fixtures/current-head-v25/trust-manifest.json": (
                "0b7028c75c8f137bc4a55a76fe73ea956d0c5ada13031f80794b77c1c9535e19"
            ),
            "tests/deployment/fixtures/current-head-v25/trust-runner-pins.txt": (
                "91b0381051753738e045ff6c019fb30757adfcf588bf3c45bc336c56c74678d0"
            ),
            "deploy/postgres-backup-restore-v25.sh": (
                "9aa84d3f7d37704e181a314db873e16fecfad6d770dbc1d12fbb76180d69d1bb"
            ),
            "deploy/postgres-core-facts-v25.sql": (
                "0845ec9025efdfc208bab24b1ce3b8f56a8e2e44613eae249a00af349802507e"
            ),
            "deploy/postgres-operations-v25.compose.yaml": (
                "a98b80de17604349362b813d1224a4f71d886b2d1282f9cbb944cd3b714628a4"
            ),
        }
        verifier_source = VERIFY_PATH.read_text(encoding="utf-8")
        for relative, expected in frozen.items():
            with self.subTest(relative=relative):
                self.assertEqual(_sha(ROOT / relative), expected)
                self.assertIn(expected, verifier_source)

    def test_v25_operations_test_tracks_the_v27_live_alias_separately(self) -> None:
        source = (
            ROOT / "tests/deployment/test_postgres_operations_v25.py"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "test_unversioned_facts_are_the_current_v27_alias",
            source,
        )
        self.assertIn("V27_FACTS", source)
        self.assertIn(
            "5296e02cf37a5ffdf54603639202e6f074138706832d811355ded15efe3da383",
            VERIFY_PATH.read_text(encoding="utf-8"),
        )

    def test_v25_historical_contract_now_asserts_v27_live_pointer(self) -> None:
        path = ROOT / "tests/deployment/test_current_head_v25_contract.py"
        source = path.read_text(encoding="utf-8")

        self.assertIn(
            "test_current_pointer_workflows_and_source_readiness_advance_to_v27",
            source,
        )
        self.assertNotIn("self.verifier.verify_repository(ROOT)", source)
        # The frozen v26 verifier still records the exact v25-at-publication
        # test bytes; advancing the live pointer does not rewrite that record.
        self.assertIn(
            "8edf618dfff911143733da477cbc5712d0d1bc570df8f00339d694aa63dd6b08",
            VERIFY_PATH.read_text(encoding="utf-8"),
        )

    def test_static_publish_never_claims_production_execution(self) -> None:
        for marker in (
            "STATIC VERIFIED / NOT PRODUCTION EXECUTED",
            "v25 dynamic evidence",
            "冻结历史",
            '"overall_status":"BLOCKED"',
            '"production_authorized":false',
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.runbook)
        self.assertNotIn("current-v26-checkout-本地合成动态验收", self.runbook)

    def test_verifier_is_read_only_runtime_free_and_argument_closed(self) -> None:
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
        self.assertIn('"status":"CURRENT_HEAD_V26_STATIC_VERIFIED"', source)
        with redirect_stderr(StringIO()):
            self.assertEqual(self.verifier.main(("unexpected",)), 78)

    def test_runtime_release_heads_advance_without_rewriting_v26(self) -> None:
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
            '"matching": 3',
        ):
            self.assertIn(marker, runtime)
        for marker in (
            '"iam": {"const": 46}',
            '"profile": {"const": 5}',
            '"demand": {"const": 15}',
            '"trust": {"const": 22}',
            '"matching": {"const": 3}',
        ):
            self.assertIn(marker, schema)
        self.assertIn("18|43|43|3|3|13|13|19|19|2|2", self.runbook)

    def test_current_pointer_workflows_and_source_readiness_advance_to_v27(
        self,
    ) -> None:
        sidebar = (ROOT / "docs/_sidebar.md").read_text(encoding="utf-8")
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        release = (
            ROOT / ".github/workflows/private-server-runtime-release.yml"
        ).read_text(encoding="utf-8")
        readiness = (
            ROOT / "scripts/check_private_server_source_readiness.py"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "[Current-head v27 静态模式头](/operations/current-head-v27.md)",
            sidebar,
        )
        self.assertIn(
            "[Current-head v26 静态模式头](/operations/current-head-v26.md)",
            sidebar,
        )
        self.assertIn(
            "[Current-head v25 静态模式头](/operations/current-head-v25.md)",
            sidebar,
        )
        v25 = "python -B scripts/verify_current_head_v25.py"
        v26 = "python -B scripts/verify_current_head_v26.py"
        v27 = "python -B scripts/verify_current_head_v27.py"
        self.assertEqual(ci.count(v25), 0)
        self.assertEqual(ci.count(v26), 0)
        self.assertEqual(ci.count(v27), 1)
        self.assertEqual(release.count(v25), 0)
        self.assertEqual(release.count(v26), 0)
        self.assertEqual(release.count(v27), 1)
        for relative in (
            "docs/operations/current-head-v27.md",
            "deploy/postgres-backup-restore-v27.sh",
            "deploy/postgres-core-facts-v27.sql",
            "deploy/postgres-operations-v27.compose.yaml",
            "scripts/verify_current_head_v27.py",
            "tests/deployment/fixtures/current-head-v27/schema-pins.json",
            "tests/deployment/test_current_head_v27_contract.py",
            "tests/deployment/test_postgres_operations_v27.py",
            "docs/operations/current-head-v26.md",
            "deploy/postgres-backup-restore-v26.sh",
            "deploy/postgres-core-facts-v26.sql",
            "deploy/postgres-operations-v26.compose.yaml",
            "scripts/verify_current_head_v26.py",
            "tests/deployment/fixtures/current-head-v26/iam-manifest.json",
            "tests/deployment/fixtures/current-head-v26/demand-manifest.json",
            "tests/deployment/fixtures/current-head-v26/trust-manifest.json",
            "tests/deployment/fixtures/current-head-v26/trust-runner-pins.txt",
            "tests/deployment/test_current_head_v26_contract.py",
            "tests/deployment/test_postgres_operations_v26.py",
        ):
            with self.subTest(relative=relative):
                self.assertIn(relative, readiness)


if __name__ == "__main__":
    unittest.main()
