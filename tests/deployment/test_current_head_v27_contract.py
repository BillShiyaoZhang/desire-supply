"""Static release contract for IAM46/Profile5/Demand15/Trust22/Matching3."""

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
VERIFY_PATH = ROOT / "scripts/verify_current_head_v27.py"
RUNBOOK_PATH = ROOT / "docs/operations/current-head-v27.md"


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "verify_current_head_v27_test", VERIFY_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("v27 verifier cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class CurrentHeadV27ContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.verifier = _load_verifier()
        cls.runbook = RUNBOOK_PATH.read_text(encoding="utf-8")

    def test_exact_six_component_head_and_contract_chain(self) -> None:
        self.assertEqual(
            self.verifier.HEADS,
            "18|46|46|5|5|15|15|22|22|3|3|2|2",
        )
        self.assertEqual(
            self.verifier.SUCCESS,
            '{"status":"CURRENT_HEAD_V27_STATIC_VERIFIED"}',
        )
        for marker in (
            self.verifier.IAM_COMBINED_SHA256,
            self.verifier.PROFILE_MANIFEST_SHA256,
            self.verifier.DEMAND_MANIFEST_SHA256,
            self.verifier.DEMAND_DEPENDENCY_SHA256,
            self.verifier.TRUST_COMBINED_SHA256,
            self.verifier.MATCHING_MANIFEST_SHA256,
            self.verifier.TAXONOMY_MANIFEST_SHA256,
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.verifier.EXPECTED_CONTRACTS)
        self.assertNotIn("__MATCHING_V3_", self.verifier.EXPECTED_CONTRACTS)

    def test_fixture_is_canonical_and_matches_the_historical_manifest_prefix(self) -> None:
        fixture_path = (
            ROOT / "tests/deployment/fixtures/current-head-v27/schema-pins.json"
        )
        fixture_bytes = fixture_path.read_bytes()
        fixture = json.loads(fixture_bytes)
        self.assertEqual(
            fixture_bytes,
            json.dumps(
                fixture,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            + b"\n",
        )
        self.assertEqual(fixture["heads"], self.verifier.HEADS)
        self.assertFalse(fixture["production_authorized"])
        self.assertEqual(fixture["claim"], "STATIC_ONLY")
        self.assertEqual(
            fixture["components"],
            self.verifier.EXPECTED_COMPONENT_PINS,
        )
        for component, (relative, versions, expected) in (
            self.verifier.MANIFESTS.items()
        ):
            with self.subTest(component=component):
                manifest = ROOT / relative / "manifest.json"
                live_document = json.loads(manifest.read_text(encoding="utf-8"))
                if component == "matching":
                    # v27 remains bound to the original v1-v3 bytes. The new
                    # live head must preserve this prefix, not replace its pin.
                    manifest = ROOT / "tests/deployment/fixtures/current-head-v28/matching-v3-manifest.json"
                document = json.loads(manifest.read_text(encoding="utf-8"))
                self.assertEqual(_sha(manifest), expected)
                self.assertEqual(live_document[:len(document)], document)
                self.assertEqual(
                    tuple(item["version"] for item in document),
                    versions,
                )
                for descriptor in document:
                    self.assertEqual(
                        _sha(ROOT / relative / descriptor["path"]),
                        descriptor["sha256"],
                    )

    def test_historical_verifier_rejects_the_newer_live_matching_manifest(self) -> None:
        self.assertEqual(
            self.verifier._manifest_failures(ROOT),
            ("matching-manifest-pin-open",),
        )
        self.assertEqual(self.verifier._historical_prefix_failures(ROOT), ())

    def test_matching_contract_files_are_exactly_pinned(self) -> None:
        for name, relative in self.verifier.MATCHING_CONTRACT_FILES.items():
            with self.subTest(name=name):
                self.assertEqual(
                    _sha(ROOT / relative),
                    self.verifier.MATCHING_CONTRACT_SHA256[name],
                )

    def test_operations_bind_matching_contract_and_all_durable_tables(self) -> None:
        script = (
            ROOT / "deploy/postgres-backup-restore-v27.sh"
        ).read_text(encoding="utf-8")
        facts = (ROOT / "deploy/postgres-core-facts-v27.sql").read_text(
            encoding="utf-8"
        )
        overlay = (
            ROOT / "deploy/postgres-operations-v27.compose.yaml"
        ).read_text(encoding="utf-8")
        self.assertEqual(
            self.verifier._operations_failures(script, facts, overlay),
            (),
        )
        self.assertEqual(len(self.verifier.MATCHING_TABLES), 27)

    def test_runbook_is_static_only_and_contract_marked(self) -> None:
        self.assertEqual(self.verifier._runbook_failures(self.runbook), ())
        self.assertEqual(
            self.runbook.count("<!-- BEGIN CURRENT_HEAD_V27_CONTRACT -->"),
            1,
        )
        self.assertEqual(
            self.runbook.count("<!-- END CURRENT_HEAD_V27_CONTRACT -->"),
            1,
        )
        self.assertIn("STATIC VERIFIED / NOT PRODUCTION EXECUTED", self.runbook)
        self.assertIn('"production_authorized":false', self.runbook)

    def test_v26_release_assets_remain_byte_frozen(self) -> None:
        for relative, expected in self.verifier.FROZEN_V26.items():
            with self.subTest(relative=relative):
                self.assertEqual(_sha(ROOT / relative), expected)

    def test_current_pointer_is_v28_while_v27_and_v26_remain_discoverable(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        release = (
            ROOT / ".github/workflows/private-server-runtime-release.yml"
        ).read_text(encoding="utf-8")
        sidebar = (ROOT / "docs/_sidebar.md").read_text(encoding="utf-8")
        v26 = "python -B scripts/verify_current_head_v26.py"
        v27 = "python -B scripts/verify_current_head_v27.py"
        v28 = "python -B scripts/verify_current_head_v28.py"
        self.assertEqual(ci.count(v26), 0)
        self.assertEqual(ci.count(v27), 0)
        self.assertEqual(ci.count(v28), 1)
        self.assertEqual(release.count(v26), 0)
        self.assertEqual(release.count(v27), 0)
        self.assertEqual(release.count(v28), 1)
        self.assertIn(
            "[Current-head v27 静态模式头](/operations/current-head-v27.md)",
            sidebar,
        )
        self.assertIn(
            "[Current-head v26 静态模式头](/operations/current-head-v26.md)",
            sidebar,
        )

    def test_unversioned_operations_assets_resolve_to_v28(self) -> None:
        self.assertEqual(
            (ROOT / "deploy/postgres-backup-restore.sh").read_bytes(),
            (ROOT / "deploy/postgres-backup-restore-v28.sh").read_bytes(),
        )
        self.assertEqual(
            (ROOT / "deploy/postgres-core-facts.sql").read_bytes(),
            (ROOT / "deploy/postgres-core-facts-v28.sql").read_bytes(),
        )

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
        with redirect_stderr(StringIO()):
            self.assertEqual(self.verifier.main(("unexpected",)), 78)


if __name__ == "__main__":
    unittest.main()
