"""The installable artifact is the deployment unit for reviewed static resources."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Optional
import unittest
import zipfile


PLATFORM_ROOT = Path(__file__).resolve().parents[2]
SOURCE_PACKAGE_ROOT = PLATFORM_ROOT / "src/desire_platform"
COMPATIBILITY_CONTRACT_ROOT = PLATFORM_ROOT / "contracts"
CANONICAL_CONTRACT_ROOT = SOURCE_PACKAGE_ROOT / "contracts"
SYNTHETIC_SEED_ROOT = SOURCE_PACKAGE_ROOT / "internal_pilot/fixtures"
MATCHING_ENGINE_RESOURCE_ROOT = SOURCE_PACKAGE_ROOT / "matching/resources"

MIGRATION_ROOTS = {
    "iam": SOURCE_PACKAGE_ROOT
    / "identity_access/adapters/postgres/migrations",
    "profile": SOURCE_PACKAGE_ROOT
    / "creator_profile/adapters/postgres/migrations",
    "demand": SOURCE_PACKAGE_ROOT / "demand/adapters/postgres/migrations",
    "matching": SOURCE_PACKAGE_ROOT / "matching/adapters/postgres/migrations",
    "trust": SOURCE_PACKAGE_ROOT / "trust_safety/adapters/postgres/migrations",
    "taxonomy": SOURCE_PACKAGE_ROOT
    / "taxonomy/adapters/postgres/migrations",
}

MIGRATION_RESOURCE_PATHS = {
    "iam": "identity_access/adapters/postgres/migrations",
    "profile": "creator_profile/adapters/postgres/migrations",
    "demand": "demand/adapters/postgres/migrations",
    "matching": "matching/adapters/postgres/migrations",
    "trust": "trust_safety/adapters/postgres/migrations",
    "taxonomy": "taxonomy/adapters/postgres/migrations",
}

EXPECTED_CONTRACT_PATHS = (
    "api/appeal-v1.openapi.yaml",
    "api/demand-v1.openapi.yaml",
    "api/iam-v1.openapi.yaml",
    "api/matching-v1.openapi.yaml",
    "api/profile-v1.openapi.yaml",
    "api/taxonomy-v1.openapi.yaml",
    "api/trust-v1.openapi.yaml",
    "config/internal-sandbox-deployment-v1.schema.json",
    "config/runtime-config-v1.schema.json",
    "domain/appeal-application-v1.schema.json",
    "domain/appeal-review-v1.schema.json",
    "domain/demand-content-v1.schema.json",
    "domain/invitation-disclosure-v1.schema.json",
    "domain/match-candidate-result-v1.schema.json",
    "domain/match-input-manifest-v1.schema.json",
    "domain/match-run-input-v1.schema.json",
    "domain/matching-rule-release-v1.schema.json",
    "domain/profile-version-v1.schema.json",
    "domain/taxonomy-crosswalk-v1.schema.json",
    "domain/taxonomy-edges-v1.schema.json",
    "domain/taxonomy-labels-v1.schema.json",
    "domain/taxonomy-nodes-v1.schema.json",
    "domain/taxonomy-release-v1.schema.json",
    "domain/trust-report-v1.schema.json",
    "domain/trust-triage-v1.schema.json",
    "events/appeal-v1.schema.json",
    "events/demand-v1.schema.json",
    "events/iam-v1.schema.json",
    "events/matching-v1.schema.json",
    "events/profile-v1.schema.json",
    "events/taxonomy-v1.schema.json",
    "events/trust-v1.schema.json",
)

EXPECTED_MIGRATION_SQL_COUNTS = {
    "iam": 47,
    "profile": 5,
    "demand": 15,
    "matching": 3,
    "trust": 22,
    "taxonomy": 2,
}

EXPECTED_SYNTHETIC_SEED_RESOURCES = {
    "internal_sandbox_seed_v1.json": (
        "418567e441e6be2744dcc2b3b295764fd303d53c4e13922503130e5cd659552d"
    ),
}

EXPECTED_MATCHING_ENGINE_RESOURCES = {
    "deterministic-matcher-v1.engine.json": (
        "d135df512bfa412f4e71de29650001552a094b03ca9f1861264d09a69d95cb1f"
    ),
    "deterministic-matcher-v1.golden.json": (
        "bdcbad0ef4597c6030a49b27c96715a4374e8c2af6714b01efc31249b01b9e48"
    ),
    "internal-sandbox-matching-rule-release-v1.json": (
        "9c2bf8a30055e7c9efa074dec655f85e2657ef4819415b1af7a8dcaaf69fff49"
    ),
}

VERIFIED_BUILD_BACKEND = "setuptools==80.9.0"


RESOURCE_PROBE = r"""
from importlib import resources
import hashlib
import json
import os

from desire_platform.synthetic_oidc import (
    CLIENT_ID,
    ISSUER,
    REDIRECT_URI,
    SYNTHETIC_ACCOUNTS,
)
from desire_platform.synthetic_oidc.__main__ import main as synthetic_oidc_main

expected = json.loads(os.environ["DESIRE_RESOURCE_EXPECTATIONS"])
package_root = resources.files("desire_platform")
contract_root = resources.files("desire_platform.contracts")

def digest(resource):
    assert resource.is_file(), resource
    return hashlib.sha256(resource.read_bytes()).hexdigest()

def contract_files(root, prefix=""):
    found = {}
    for child in root.iterdir():
        relative = prefix + child.name
        if child.is_dir():
            found.update(contract_files(child, relative + "/"))
        elif child.name.endswith((".json", ".yaml")):
            found[relative] = digest(child)
    return found

actual_contracts = contract_files(contract_root)
assert actual_contracts == expected["contracts"], (
    "contract resource mismatch",
    sorted(set(expected["contracts"]) - set(actual_contracts)),
    sorted(set(actual_contracts) - set(expected["contracts"])),
)

for component, expectation in expected["migrations"].items():
    migration_root = package_root.joinpath(
        *expectation["resource_path"].split("/")
    )
    manifest_resource = migration_root.joinpath("manifest.json")
    assert digest(manifest_resource) == expectation["manifest_sha256"]
    manifest = json.loads(manifest_resource.read_text(encoding="utf-8"))
    manifest_sql = {entry["path"]: entry["sha256"] for entry in manifest}
    assert manifest_sql == expectation["sql"]
    actual_sql_names = sorted(
        child.name
        for child in migration_root.iterdir()
        if child.is_file() and child.name.endswith(".sql")
    )
    assert actual_sql_names == sorted(expectation["sql"])
    for filename, expected_digest in expectation["sql"].items():
        assert digest(migration_root.joinpath(filename)) == expected_digest

fixture_root = package_root.joinpath("internal_pilot", "fixtures")
actual_fixtures = {
    child.name: digest(child)
    for child in fixture_root.iterdir()
    if child.is_file() and child.name.endswith(".json")
}
assert actual_fixtures == expected["synthetic_seed_resources"]

matching_engine_root = package_root.joinpath("matching", "resources")
actual_matching_engine_resources = {
    child.name: digest(child)
    for child in matching_engine_root.iterdir()
    if child.is_file() and child.name.endswith(".json")
}
assert actual_matching_engine_resources == expected["matching_engine_resources"]

assert ISSUER == "https://identity.example.test"
assert CLIENT_ID == "desire-internal-sandbox"
assert REDIRECT_URI == "https://pilot.example.test/v1/auth/oidc/callback"
assert tuple(
    (value.account_code, value.subject, value.email)
    for value in SYNTHETIC_ACCOUNTS
) == (
    (
        "access_admin_01",
        "sandbox:access-admin-01",
        "sandbox-access-admin-01@example.test",
    ),
    (
        "appeal_reviewer_01",
        "sandbox:appeal-reviewer-01",
        "sandbox-appeal-reviewer-01@example.test",
    ),
    (
        "creator_01",
        "sandbox:creator-01",
        "sandbox-creator-01@example.test",
    ),
    (
        "demand_owner_01",
        "sandbox:demand-owner-01",
        "sandbox-demand-owner-01@example.test",
    ),
    (
        "finance_operator_01",
        "sandbox:finance-operator-01",
        "sandbox-finance-operator-01@example.test",
    ),
    (
        "finance_operator_02",
        "sandbox:finance-operator-02",
        "sandbox-finance-operator-02@example.test",
    ),
    (
        "operations_reviewer_01",
        "sandbox:operations-reviewer-01",
        "sandbox-operations-reviewer-01@example.test",
    ),
    (
        "org_admin_01",
        "sandbox:org-admin-01",
        "sandbox-org-admin-01@example.test",
    ),
    (
        "trust_officer_01",
        "sandbox:trust-officer-01",
        "sandbox-trust-officer-01@example.test",
    ),
    (
        "trust_officer_02",
        "sandbox:trust-officer-02",
        "sandbox-trust-officer-02@example.test",
    ),
)
assert callable(synthetic_oidc_main)
"""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _resource_expectations() -> dict[str, object]:
    contracts = {
        path.relative_to(COMPATIBILITY_CONTRACT_ROOT).as_posix(): _sha256(path)
        for path in sorted(COMPATIBILITY_CONTRACT_ROOT.rglob("*"))
        if path.is_file() and path.suffix in {".json", ".yaml"}
    }
    migrations: dict[str, object] = {}
    for component, migration_root in MIGRATION_ROOTS.items():
        manifest_path = migration_root / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        migrations[component] = {
            "resource_path": MIGRATION_RESOURCE_PATHS[component],
            "manifest_sha256": _sha256(manifest_path),
            "sql": {entry["path"]: entry["sha256"] for entry in manifest},
        }
    synthetic_seed_resources = {
        path.name: _sha256(path)
        for path in sorted(SYNTHETIC_SEED_ROOT.glob("*.json"))
        if path.is_file()
    }
    matching_engine_resources = {
        path.name: _sha256(path)
        for path in sorted(MATCHING_ENGINE_RESOURCE_ROOT.glob("*.json"))
        if path.is_file()
    }
    return {
        "contracts": contracts,
        "migrations": migrations,
        "synthetic_seed_resources": synthetic_seed_resources,
        "matching_engine_resources": matching_engine_resources,
    }


class DistributionResourcesTest(unittest.TestCase):
    maxDiff = None

    def test_build_backend_is_exactly_pinned_to_the_verified_version(self) -> None:
        pyproject = (PLATFORM_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        build_system, separator, _remainder = pyproject.partition("\n[project]")
        self.assertTrue(separator, "pyproject must contain a [project] section")
        self.assertIn(
            'requires = ["%s"]' % VERIFIED_BUILD_BACKEND,
            build_system,
            "the isolated build backend must not float over time",
        )

    def test_repository_contract_path_is_a_compatibility_link_to_canonical_package_data(
        self,
    ) -> None:
        self.assertTrue(
            COMPATIBILITY_CONTRACT_ROOT.is_symlink(),
            "platform/contracts must not become a second contract truth source",
        )
        self.assertEqual(
            COMPATIBILITY_CONTRACT_ROOT.resolve(strict=True),
            CANONICAL_CONTRACT_ROOT.resolve(strict=True),
        )
        self.assertEqual(
            os.readlink(COMPATIBILITY_CONTRACT_ROOT),
            "src/desire_platform/contracts",
            "the compatibility link must remain relocatable",
        )

        actual_contracts = {
            path.relative_to(CANONICAL_CONTRACT_ROOT).as_posix()
            for path in CANONICAL_CONTRACT_ROOT.rglob("*")
            if path.is_file() and path.suffix in {".json", ".yaml"}
        }
        self.assertEqual(actual_contracts, set(EXPECTED_CONTRACT_PATHS))
        self.assertFalse(
            any(
                path.is_symlink()
                for path in CANONICAL_CONTRACT_ROOT.rglob("*")
                if path.is_file()
            ),
            "canonical contract resources must be regular package files",
        )

    def test_wheel_and_sdist_clean_installs_expose_all_reviewed_resources(self) -> None:
        uv = shutil.which("uv")
        self.assertIsNotNone(uv, "the repository build/test workflow requires uv")
        expectations = _resource_expectations()
        self.assertEqual(
            set(expectations["contracts"]),
            set(EXPECTED_CONTRACT_PATHS),
        )
        self.assertEqual(
            {
                component: len(expectation["sql"])
                for component, expectation in expectations["migrations"].items()
            },
            EXPECTED_MIGRATION_SQL_COUNTS,
        )
        self.assertEqual(
            expectations["synthetic_seed_resources"],
            EXPECTED_SYNTHETIC_SEED_RESOURCES,
        )
        self.assertEqual(
            expectations["matching_engine_resources"],
            EXPECTED_MATCHING_ENGINE_RESOURCES,
        )

        with tempfile.TemporaryDirectory(prefix="desire-platform-package-") as directory:
            temporary_root = Path(directory)
            distribution_root = temporary_root / "dist"
            self._run(
                [
                    uv,
                    "build",
                    "--no-build-logs",
                    "--no-create-gitignore",
                    "--out-dir",
                    str(distribution_root),
                    str(PLATFORM_ROOT),
                ],
                cwd=temporary_root,
            )
            wheel = self._one_artifact(distribution_root, "*.whl")
            sdist = self._one_artifact(distribution_root, "*.tar.gz")
            with zipfile.ZipFile(wheel) as wheel_archive:
                wheel_metadata_path = next(
                    name
                    for name in wheel_archive.namelist()
                    if name.endswith(".dist-info/WHEEL")
                )
                wheel_metadata = wheel_archive.read(wheel_metadata_path).decode("utf-8")
                package_metadata_path = next(
                    name
                    for name in wheel_archive.namelist()
                    if name.endswith(".dist-info/METADATA")
                )
                package_metadata = wheel_archive.read(package_metadata_path).decode(
                    "utf-8"
                )
            self.assertIn(
                "Generator: setuptools (%s)" % VERIFIED_BUILD_BACKEND.split("==", 1)[1],
                wheel_metadata,
            )
            self.assertIn(
                "Requires-Dist: PyYAML==6.0.3\n",
                package_metadata,
                "production OpenAPI validation needs YAML outside the test extra",
            )

            for label, artifact in (("wheel", wheel), ("sdist", sdist)):
                with self.subTest(artifact=label):
                    environment_root = temporary_root / ("venv-" + label)
                    self._run(
                        [
                            uv,
                            "venv",
                            "--python",
                            sys.executable,
                            str(environment_root),
                        ],
                        cwd=temporary_root,
                    )
                    environment_python = environment_root / "bin/python"
                    if os.name == "nt":
                        environment_python = environment_root / "Scripts/python.exe"
                    self._run(
                        [
                            uv,
                            "pip",
                            "install",
                            "--no-deps",
                            "--python",
                            str(environment_python),
                            str(artifact),
                        ],
                        cwd=temporary_root,
                    )
                    probe_environment = os.environ.copy()
                    probe_environment.pop("PYTHONPATH", None)
                    probe_environment.pop("PYTHONHOME", None)
                    probe_environment["DESIRE_RESOURCE_EXPECTATIONS"] = json.dumps(
                        expectations,
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                    self._run(
                        [str(environment_python), "-I", "-c", RESOURCE_PROBE],
                        cwd=temporary_root,
                        env=probe_environment,
                    )

    def _run(
        self,
        command: list[str],
        *,
        cwd: Path,
        env: Optional[dict[str, str]] = None,
    ) -> None:
        effective_environment = (env or os.environ).copy()
        # PEP 517 builds must be isolated from this source checkout.  CI runs
        # tests through uv without PYTHONPATH, while local source-mode test
        # commands commonly set it; leaking that value can shadow stdlib
        # modules (for example ``http``) inside setuptools' build process.
        effective_environment.pop("PYTHONPATH", None)
        effective_environment.pop("PYTHONHOME", None)
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=effective_environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            "command failed: %s\n%s" % (" ".join(command), completed.stdout),
        )

    def _one_artifact(self, root: Path, pattern: str) -> Path:
        artifacts = list(root.glob(pattern))
        self.assertEqual(len(artifacts), 1, "expected exactly one " + pattern)
        return artifacts[0]


if __name__ == "__main__":
    unittest.main()
