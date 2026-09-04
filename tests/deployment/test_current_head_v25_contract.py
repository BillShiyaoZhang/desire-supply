"""Frozen historical contract for the unchanged Trust18 current-head v25."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
VERIFY_PATH = ROOT / "scripts/verify_current_head_v25.py"
RUNBOOK_PATH = ROOT / "docs/operations/current-head-v25.md"


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "verify_current_head_v25_test", VERIFY_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("v25 verifier cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class CurrentHeadV25ContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.verifier = _load_verifier()
        cls.runbook = RUNBOOK_PATH.read_text(encoding="utf-8")

    def test_frozen_static_contract_remains_self_consistent(self) -> None:
        self.assertEqual(self.verifier._runbook_failures(self.runbook), ())

    def test_schema_heads_and_domain_contracts_remain_exactly_v24(self) -> None:
        for marker in (
            "18|42|42|3|3|12|12|18|18|2|2",
            self.verifier.EXPECTED_CONTRACTS,
            self.verifier.IAM_MANIFEST_SHA256,
            self.verifier.DEMAND_MANIFEST_SHA256,
            self.verifier.TRUST_APPEAL_API_SHA256,
            self.verifier.TRUST_SQL_SHA256,
            self.verifier.TRUST_MANIFEST_SHA256,
            self.verifier.TRUST_COMBINED_SHA256,
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.runbook)

    def test_mutated_observation_or_logging_boundary_is_rejected(self) -> None:
        for marker, replacement in (
            ("HTTP_BOUNDARY_OBSERVATION_V1", "HTTP_RAW_REQUEST_V1"),
            ("raw path/query/header/body", "raw request coordinates"),
            ("driver=local", "driver=json-file"),
            ("max-size=10m", "max-size=100m"),
            ("DOCKER_LOG_CONFIG", "LOG_CONFIG_HINT"),
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
        self.assertIn('"status":"CURRENT_HEAD_V25_STATIC_VERIFIED"', source)

    def test_v25_fixtures_are_byte_identical_to_v24(self) -> None:
        expected = {
            "iam-manifest.json": (
                "9c6e0396867d68ac49260684a9531c592055d62cac20d7ebdfb578c236df025d"
            ),
            "demand-manifest.json": (
                "919d62a9b32dc29619a561940f9c79e21700562a0cdd9ef7e9f13a40cea43345"
            ),
            "trust-manifest.json": (
                "0b7028c75c8f137bc4a55a76fe73ea956d0c5ada13031f80794b77c1c9535e19"
            ),
            "trust-runner-pins.txt": (
                "91b0381051753738e045ff6c019fb30757adfcf588bf3c45bc336c56c74678d0"
            ),
        }
        for name, digest in expected.items():
            with self.subTest(name=name):
                v24 = ROOT / "tests/deployment/fixtures/current-head-v24" / name
                v25 = ROOT / "tests/deployment/fixtures/current-head-v25" / name
                self.assertEqual(v25.read_bytes(), v24.read_bytes())
                self.assertEqual(_sha(v25), digest)

    def test_http_observation_is_closed_low_cardinality_and_non_reflective(self) -> None:
        source = VERIFY_PATH.read_text(encoding="utf-8")
        for required in (
            "HTTP_OBSERVABILITY_SHA256",
            "HTTP_OBSERVABILITY_TEST_SHA256",
            "HTTP_BOUNDARY_OBSERVATION_V1",
            "ObservedAsgiApplication",
            "test_emits_one_closed_low_cardinality_event_without_request_data",
            "test_unhandled_exception_is_classified_without_reflection",
            "test_observer_failure_never_changes_the_http_result",
            "current-head-v25-http-observation-privacy-open",
            "access_log=False",
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)
        for required in (
            "low-cardinality",
            "raw path/query/header/body",
            "observer failure",
            "access_log=False",
            self.verifier.HTTP_OBSERVABILITY_SHA256,
        ):
            self.assertIn(required, self.runbook)

    def test_docker_logging_is_exact_bounded_and_live_inspected(self) -> None:
        source = VERIFY_PATH.read_text(encoding="utf-8")
        for required in (
            "COMPOSE_SHA256",
            "CONTAINER_VERIFIER_SHA256",
            "LOCAL_MANAGER_SHA256",
            "DOCKER_LOG_CONFIG",
            "test_resolved_services_use_exact_bounded_local_logging",
            "test_resolved_compose_rejects_missing_or_drifted_logging",
            "test_live_security_rejects_capability_and_writable_root_bind",
            "test_bounded_logging_is_exact_and_cannot_be_disabled",
            "test_rejects_missing_or_drifted_bounded_logging",
            "test_resolved_operations_use_exact_bounded_local_logging",
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)
        for required in (
            "driver=local",
            "max-size=10m",
            "max-file=3",
            "compress=true",
            "DOCKER_LOG_CONFIG",
            self.verifier.COMPOSE_SHA256,
            self.verifier.CONTAINER_VERIFIER_SHA256,
        ):
            self.assertIn(required, self.runbook)

    def test_v25_postgres_operations_remain_frozen_pinned_static_assets(self) -> None:
        v15 = (ROOT / "deploy/postgres-backup-restore-v15.sh").read_text(
            encoding="utf-8"
        )
        v25 = (ROOT / "deploy/postgres-backup-restore-v25.sh").read_text(
            encoding="utf-8"
        )
        overlay = (ROOT / "deploy/postgres-operations-v25.compose.yaml").read_text(
            encoding="utf-8"
        )
        v25_facts = (ROOT / "deploy/postgres-core-facts-v25.sql").read_text(
            encoding="utf-8"
        )
        durable_start = v25_facts.index(
            "    'iam_durable_counts', jsonb_build_object(\n"
        )
        core_counts_start = v25_facts.index(
            "    'core_counts', jsonb_build_object(\n",
            durable_start,
        )
        historical_base_facts = (
            v25_facts[:durable_start] + v25_facts[core_counts_start:]
        )
        self.assertEqual(
            self.verifier._postgres_operations_v25_failures(
                v15,
                v25,
                historical_base_facts,
                v25_facts,
                overlay,
            ),
            (),
        )
        for required in (
            "deploy/postgres-backup-restore-v25.sh",
            "deploy/postgres-core-facts-v25.sql",
            "deploy/postgres-operations-v25.compose.yaml",
            "iam_durable_counts",
            "compose_v25_operations",
            "DATABASE_BACKUP_READY",
            "DATABASE_RESTORE_VERIFIED",
            "not comprehensive field-level continuity",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.runbook)
        self.assertIn("STATIC VERIFIED", self.runbook)
        self.assertIn("NOT EXECUTED", self.runbook)

    def test_v24_verifier_runbook_and_fixtures_remain_byte_frozen(self) -> None:
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
        source = VERIFY_PATH.read_text(encoding="utf-8")
        for relative, expected in frozen.items():
            with self.subTest(relative=relative):
                self.assertEqual(_sha(ROOT / relative), expected)
                self.assertIn(expected, source)
        self.assertNotIn("test_current_head_v24_contract.py", source)

    def test_static_publish_does_not_relabel_v24_dynamic_evidence(self) -> None:
        self.assertIn("STATIC VERIFIED", self.runbook)
        self.assertIn("NOT EXECUTED", self.runbook)
        self.assertIn("v24 dynamic evidence", self.runbook)
        self.assertIn("冻结历史", self.runbook)
        self.assertIn('"overall_status":"BLOCKED"', self.runbook)
        self.assertIn('"production_authorized":false', self.runbook)

    def test_checkout_dynamic_evidence_is_separate_deidentified_and_non_authorizing(
        self,
    ) -> None:
        documents = {
            "trial": (
                ROOT / "docs/operations/local-internal-sandbox-trial.md"
            ).read_text(encoding="utf-8"),
            "run": (ROOT / "docs/operations/run-and-check.md").read_text(
                encoding="utf-8"
            ),
            "deployment": (
                ROOT / "docs/operations/container-deployment.md"
            ).read_text(encoding="utf-8"),
        }
        self.assertIn(
            "## Historical v25 checkout local synthetic dynamic acceptance（2026-08-26）",
            documents["trial"],
        )
        self.assertIn(
            "### 4.6.7 历史：v25 checkout 本地合成动态验收（2026-08-26）",
            documents["run"],
        )
        self.assertIn(
            "### 2.6 历史：v25 checkout 本地合成动态证据（2026-08-26）",
            documents["deployment"],
        )
        evidence = "\n".join(documents.values())
        for required in (
            "TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN",
            "PROVIDER_ONLY_INVITED_DEMAND_OWNER_E2E_GREEN",
            "TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN",
            "HTTP_BOUNDARY_OBSERVATION_V1",
            "最终状态为 `STOPPED`",
            "完整桌面/移动视觉 QA 仍未完成",
            "STATIC VERIFIED / NOT PRODUCTION EXECUTED",
            "production_authorized=false",
        ):
            with self.subTest(required=required):
                self.assertIn(required, evidence)
        self.assertIn("sampled recent live API boundary entries", documents["trial"])
        self.assertIn("抽样查看的近期 live API boundary entries", documents["run"])
        self.assertIn(
            "抽样查看的近期 live API boundary entries", documents["deployment"]
        )
        for forbidden in (
            "desire-current-v25-20260826aa",
            "local-current-v25-20260826aa",
            "172.29.132.0/24",
            "desire-current-v25-20260826aa-evidence",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, evidence)
        link_marker = "与本静态合同分开记账的 checkout runtime/source 本地合成验收"
        self.assertIn(link_marker, self.runbook)
        self.assertLess(
            self.runbook.index("<!-- END CURRENT_HEAD_V25_CONTRACT -->"),
            self.runbook.index(link_marker),
        )

    def test_current_pointer_workflows_and_source_readiness_advance_to_v30(self) -> None:
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
        self.assertIn(
            "[Current-head v24 静态模式头](/operations/current-head-v24.md)",
            sidebar,
        )
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
            "docs/operations/current-head-v25.md",
            "deploy/postgres-backup-restore-v25.sh",
            "deploy/postgres-core-facts-v25.sql",
            "deploy/postgres-operations-v25.compose.yaml",
            "scripts/verify_current_head_v25.py",
            "tests/deployment/fixtures/current-head-v25/iam-manifest.json",
            "tests/deployment/fixtures/current-head-v25/demand-manifest.json",
            "tests/deployment/fixtures/current-head-v25/trust-manifest.json",
            "tests/deployment/fixtures/current-head-v25/trust-runner-pins.txt",
            "tests/deployment/test_current_head_v25_contract.py",
            "tests/deployment/test_postgres_operations_v25.py",
        ):
            self.assertIn(relative, readiness)


if __name__ == "__main__":
    unittest.main()
