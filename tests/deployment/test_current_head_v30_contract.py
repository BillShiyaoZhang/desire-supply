"""Static release contract for IAM48/Profile5/Demand16/Trust24/Matching11."""

from __future__ import annotations

from contextlib import redirect_stderr
import hashlib
import importlib.util
from io import StringIO
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
VERIFY_PATH = ROOT / "scripts/verify_current_head_v30.py"
RUNBOOK_PATH = ROOT / "docs/operations/current-head-v30.md"


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "verify_current_head_v30_test", VERIFY_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("v30 verifier cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class CurrentHeadV30ContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.verifier = _load_verifier()
        cls.runbook = RUNBOOK_PATH.read_text(encoding="utf-8")

    def test_exact_six_component_head_and_contract_chain(self) -> None:
        self.assertEqual(
            self.verifier.HEADS,
            "18|48|48|5|5|16|16|24|24|11|11|2|2",
        )
        self.assertEqual(
            self.verifier.SUCCESS,
            '{"status":"CURRENT_HEAD_V30_STATIC_VERIFIED"}',
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
        self.assertNotIn("__MATCHING_V9_", self.verifier.EXPECTED_CONTRACTS)

    def test_fixture_is_canonical_and_matches_live_manifests(self) -> None:
        fixture_path = (
            ROOT / "tests/deployment/fixtures/current-head-v30/schema-pins.json"
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
                document = json.loads(manifest.read_text(encoding="utf-8"))
                self.assertEqual(_sha(manifest), expected)
                self.assertEqual(
                    tuple(item["version"] for item in document),
                    versions,
                )

    def test_all_migration_entries_pin_the_actual_artifact_bytes(self) -> None:
        self.assertEqual(self.verifier._manifest_failures(ROOT), ())
        self.assertEqual(self.verifier._historical_prefix_failures(ROOT), ())

    def test_matching_contract_files_are_exactly_pinned(self) -> None:
        for name, relative in self.verifier.MATCHING_CONTRACT_FILES.items():
            with self.subTest(name=name):
                self.assertEqual(
                    _sha(ROOT / relative),
                    self.verifier.MATCHING_CONTRACT_SHA256[name],
                )

    def test_matching_dependency_repin_cannot_silently_revert_to_trust22(self) -> None:
        relative = (
            "platform/src/desire_platform/matching/adapters/postgres/"
            "migrations/runner.py"
        )
        original_read = self.verifier._read
        for marker, previous in (
            ("MATCHING_REQUIRED_TRUST_SCHEMA_VERSION = 24",
             "MATCHING_REQUIRED_TRUST_SCHEMA_VERSION = 22"),
            (self.verifier.TRUST_COMBINED_SHA256,
             "68f3c3e90088f6d4383e73b3fbc6f77297cee27bc78086db227708bc872613f6"),
            (self.verifier.TRUST_MANIFEST_SHA256,
             "3fd3089db8139f4e70551f59f8e803fdf2543847d38d08f82f8a050c2dd921e8"),
        ):
            def read_with_old_dependency(path):
                value = original_read(path)
                return value.replace(marker, previous) if path == ROOT / relative else value

            with self.subTest(marker=marker), patch.object(
                self.verifier, "_read", side_effect=read_with_old_dependency
            ):
                self.assertIn(
                    "matching-dependency-pin-open",
                    self.verifier.verify_repository(ROOT),
                )

    def test_admin_oversight_dependency_heads_cannot_revert_to_v29(self) -> None:
        cases = (
            ("demand", "DEMAND_REQUIRED_IAM_SCHEMA_VERSION = 48", "DEMAND_REQUIRED_IAM_SCHEMA_VERSION = 47"),
            ("trust_safety", "TRUST_REQUIRED_IAM_SCHEMA_VERSION = 48", "TRUST_REQUIRED_IAM_SCHEMA_VERSION = 47"),
            ("trust_safety", "TRUST_REQUIRED_DEMAND_SCHEMA_VERSION = 16", "TRUST_REQUIRED_DEMAND_SCHEMA_VERSION = 15"),
            ("matching", "MATCHING_REQUIRED_IAM_SCHEMA_VERSION = 48", "MATCHING_REQUIRED_IAM_SCHEMA_VERSION = 47"),
            ("matching", "MATCHING_REQUIRED_TRUST_SCHEMA_VERSION = 24", "MATCHING_REQUIRED_TRUST_SCHEMA_VERSION = 23"),
        )
        original_read = self.verifier._read
        for component, marker, previous in cases:
            target = ROOT / f"platform/src/desire_platform/{component}/adapters/postgres/migrations/runner.py"
            self.assertIn(marker, original_read(target))

            def read_with_old_dependency(path):
                value = original_read(path)
                return value.replace(marker, previous) if path == target else value

            expected = "trust" if component == "trust_safety" else component
            with self.subTest(component=component, marker=marker), patch.object(
                self.verifier, "_read", side_effect=read_with_old_dependency
            ):
                self.assertIn(f"{expected}-dependency-pin-open", self.verifier.verify_repository(ROOT))

    def test_operations_bind_matching_contract_and_all_durable_tables(self) -> None:
        script = (
            ROOT / "deploy/postgres-backup-restore-v30.sh"
        ).read_text(encoding="utf-8")
        facts = (ROOT / "deploy/postgres-core-facts-v30.sql").read_text(
            encoding="utf-8"
        )
        overlay = (
            ROOT / "deploy/postgres-operations-v30.compose.yaml"
        ).read_text(encoding="utf-8")
        self.assertEqual(
            self.verifier._operations_failures(script, facts, overlay),
            (),
        )
        self.assertEqual(len(self.verifier.MATCHING_TABLES), 27)

    def test_runbook_is_static_only_and_contract_marked(self) -> None:
        self.assertEqual(self.verifier._runbook_failures(self.runbook), ())
        self.assertEqual(
            self.runbook.count("<!-- BEGIN CURRENT_HEAD_V30_CONTRACT -->"),
            1,
        )
        self.assertEqual(
            self.runbook.count("<!-- END CURRENT_HEAD_V30_CONTRACT -->"),
            1,
        )
        self.assertIn("STATIC VERIFIED / NOT PRODUCTION EXECUTED", self.runbook)
        self.assertIn('"production_authorized":false', self.runbook)

    def test_v26_release_assets_remain_byte_frozen(self) -> None:
        for relative, expected in self.verifier.FROZEN_V26.items():
            with self.subTest(relative=relative):
                self.assertEqual(_sha(ROOT / relative), expected)

    def test_v27_release_assets_remain_byte_frozen(self) -> None:
        for relative, expected in self.verifier.FROZEN_V27.items():
            with self.subTest(relative=relative):
                self.assertEqual(_sha(ROOT / relative), expected)

    def test_v28_release_assets_remain_byte_frozen(self) -> None:
        for relative, expected in self.verifier.FROZEN_V28.items():
            with self.subTest(relative=relative):
                self.assertEqual(_sha(ROOT / relative), expected)

    def test_v29_release_assets_remain_byte_frozen(self) -> None:
        for relative, expected in self.verifier.FROZEN_V29.items():
            with self.subTest(relative=relative):
                self.assertEqual(_sha(ROOT / relative), expected)

    def test_matching11_release_package_schema_is_exact(self) -> None:
        schema = json.loads((ROOT / "deploy/private-server-runtime-release-v1.schema.json").read_text())
        self.assertEqual(schema["properties"]["schema_heads"]["properties"]["matching"], {"const": 11})
        source = (ROOT / "scripts/private_server_runtime_release.py").read_text()
        self.assertIn('"matching": 11,', source)

    def test_current_pointer_is_v30_while_prior_heads_remain_discoverable(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        release = (
            ROOT / ".github/workflows/private-server-runtime-release.yml"
        ).read_text(encoding="utf-8")
        sidebar = (ROOT / "docs/_sidebar.md").read_text(encoding="utf-8")
        v27 = "python -B scripts/verify_current_head_v27.py"
        v30 = "python -B scripts/verify_current_head_v30.py"
        self.assertEqual(ci.count(v27), 0)
        self.assertEqual(ci.count(v30), 1)
        self.assertEqual(release.count(v27), 0)
        self.assertEqual(release.count(v30), 1)
        for version in (28, 29):
            with self.subTest(version=version):
                command = f"python -B scripts/verify_current_head_v{version}.py"
                self.assertEqual(ci.count(command), 0)
                self.assertEqual(release.count(command), 0)
                self.assertIn(
                    f"[Current-head v{version} 静态模式头](/operations/current-head-v{version}.md)",
                    sidebar,
                )
        self.assertIn(
            "[Current-head v30 静态模式头](/operations/current-head-v30.md)",
            sidebar,
        )
        self.assertIn(
            "[Current-head v27 静态模式头](/operations/current-head-v27.md)",
            sidebar,
        )

    def test_unversioned_operations_assets_resolve_to_v30(self) -> None:
        self.assertEqual(
            (ROOT / "deploy/postgres-backup-restore.sh").read_bytes(),
            (ROOT / "deploy/postgres-backup-restore-v30.sh").read_bytes(),
        )
        self.assertEqual(
            (ROOT / "deploy/postgres-core-facts.sql").read_bytes(),
            (ROOT / "deploy/postgres-core-facts-v30.sql").read_bytes(),
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
