#!/usr/bin/env python3
"""Read-only verifier for the current-head v15 publishing assets.

This gate reads checked-in files only. It never calls Docker, consumes a
one-shot coordinate, creates evidence, or upgrades a BLOCKED caller claim.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Iterable


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
HEADS = "18|38|38|3|3|10|10|9|9|2|2"
IAM_COMBINED_SHA256 = (
    "908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e"
)
IAM_MANIFEST_SHA256 = (
    "19102ab51f5f41c05c3abe07ab7c812d8d829508beec2bd7c3a637b4d1f3a331"
)
PROFILE_MANIFEST_SHA256 = (
    "4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa"
)
DEMAND_MANIFEST_SHA256 = (
    "7695127a039fa71cddabd62318bea39337e3acbb4b1df66a3557b7a7ae3707b4"
)
DEMAND_DEPENDENCY_SHA256 = (
    "27ec6b585a9340cbd7119d7a9b46d6098a3881f88ae1be9e00df3713c0107113"
)
TRUST_API_SHA256 = (
    "a9923573365f1023aff3e4aaebb0b7e656c80eab7e721bbf30d9e9b038782f25"
)
TRUST_SQL_SHA256 = (
    "6cbab8db4ccbb5c9fe2a5b5af161327289da80a3de4c159407de9f1cb13093db"
)
TRUST_MANIFEST_SHA256 = (
    "8ef9c2321866e7509bf1a959acf64370fe74abb927635c0434618287a4348171"
)
TRUST_COMBINED_SHA256 = (
    "43765a3739716819c1bfc8df9625a3011534ae23aa647bf3bdaea90945e7bef9"
)
TAXONOMY_MANIFEST_SHA256 = (
    "74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622"
)
IMAGE_TAG = "e2e-ten-account-v15-iam38-demand10-trust9"
BUNDLE_NAME = "internal-sandbox-bundle-iam38-demand10-trust9"
RELEASE_ID = "release-e2e-ten-account-v15-iam38-demand10-trust9"
BACKUP_BASENAME = "v15-iam38-profile3-demand10-trust9-taxonomy2-drill01"
V15_COMPOSE_FILES = (
    "compose.yaml",
    "deploy/postgres-operations.compose.yaml",
    "deploy/postgres-operations-v15.compose.yaml",
)
SUCCESS = '{"status":"CURRENT_HEAD_V15_STATIC_VERIFIED"}'
V14_PINS = "18|38|38|3|3|10|10|8|8|2|2"
V14_TRUST_MANIFEST_SHA256 = (
    "6d5e98529d07f684657820a8a1d405cd243fa8ac26518ecee02a966ccc02d722"
)
V14_TRUST_COMBINED_SHA256 = (
    "8907369e35172587753295403dc101227c21671960539c51364f8e00f1e4978a"
)
V14_EXPECTED_CONTRACTS = (
    f"{IAM_COMBINED_SHA256}|{PROFILE_MANIFEST_SHA256}|"
    f"{DEMAND_MANIFEST_SHA256}|38|10|{IAM_COMBINED_SHA256}|"
    f"{DEMAND_DEPENDENCY_SHA256}|{V14_TRUST_COMBINED_SHA256}|"
    f"{V14_TRUST_MANIFEST_SHA256}|{TAXONOMY_MANIFEST_SHA256}"
)
V15_EXPECTED_CONTRACTS = (
    f"{IAM_COMBINED_SHA256}|{PROFILE_MANIFEST_SHA256}|"
    f"{DEMAND_MANIFEST_SHA256}|38|10|{IAM_COMBINED_SHA256}|"
    f"{DEMAND_DEPENDENCY_SHA256}|{TRUST_COMBINED_SHA256}|"
    f"{TRUST_MANIFEST_SHA256}|{TAXONOMY_MANIFEST_SHA256}"
)
EXPECTED_V15_OVERLAY = """configs:
  postgres-backup-restore-script:
    file: ./deploy/postgres-backup-restore-v15.sh
"""
FROZEN_ASSETS = (
    (
        "platform/src/desire_platform/identity_access/adapters/postgres/"
        "migrations/0038_expand__owned_session_revocation.sql",
        "16f468f6bdb28f92746aac10fec516a9694debc1abe7107aafb1557a3f990fbb",
    ),
    (
        "tests/deployment/fixtures/current-head-v14/iam-manifest.json",
        IAM_MANIFEST_SHA256,
    ),
    (
        "platform/src/desire_platform/creator_profile/adapters/postgres/"
        "migrations/manifest.json",
        PROFILE_MANIFEST_SHA256,
    ),
    (
        "platform/src/desire_platform/demand/adapters/postgres/migrations/"
        "0010_expand__finance_funding_review_resolution.sql",
        "12971bf1143969ef47875aa0d83c39fade0b3dbabfaf892f269dc24078bc9823",
    ),
    (
        "tests/deployment/fixtures/current-head-v15/demand-manifest.json",
        DEMAND_MANIFEST_SHA256,
    ),
    (
        "platform/contracts/api/trust-v1.openapi.yaml",
        TRUST_API_SHA256,
    ),
    (
        "platform/src/desire_platform/trust_safety/adapters/postgres/"
        "migrations/0009_expand__owned_report_discovery.sql",
        TRUST_SQL_SHA256,
    ),
    (
        "tests/deployment/fixtures/current-head-v15/trust-manifest.json",
        TRUST_MANIFEST_SHA256,
    ),
    (
        "platform/src/desire_platform/taxonomy/adapters/postgres/migrations/"
        "manifest.json",
        TAXONOMY_MANIFEST_SHA256,
    ),
    (
        "tests/deployment/fixtures/current-head-v14/trust-manifest.json",
        V14_TRUST_MANIFEST_SHA256,
    ),
    (
        "tests/deployment/fixtures/current-head-v15/trust-runner-pins.txt",
        "d3371e9d708ebca5e765e0fe20145ac170cb66ed00a4e8574c3b7115fc77bfca",
    ),
    (
        "tests/deployment/fixtures/current-head-v13/trust-v1.openapi.yaml",
        "f23f8283ce8334cf48e1c912379451f00efe21382a281c5f5156260ae3a618ed",
    ),
    (
        "tests/deployment/fixtures/current-head-v14/trust-v1.openapi.yaml",
        "f23f8283ce8334cf48e1c912379451f00efe21382a281c5f5156260ae3a618ed",
    ),
    (
        "platform/src/desire_platform/trust_safety/adapters/postgres/"
        "migrations/0008_expand__iam38_demand10_dependency_repin.sql",
        "c15ca1b6ac8a750dc4cd5b1cf815a367d7531ddb9088da9d60ec1a7a99ff241b",
    ),
)


def _read_text(path: Path) -> str:
    try:
        if path.is_symlink() or not path.is_file():
            return ""
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return ""


def _sha256(path: Path) -> str | None:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _unique(values: Iterable[str]) -> tuple[str, ...]:
    result: list[str] = []
    for value in values:
        if value not in result:
            result.append(value)
    return tuple(result)


def _current_head_v15_runbook_failures(runbook: str) -> tuple[str, ...]:
    failures: list[str] = []
    markers = (
        "<!-- BEGIN CURRENT_HEAD_V15_CONTRACT -->",
        "<!-- END CURRENT_HEAD_V15_CONTRACT -->",
    )
    if (
        any(runbook.count(marker) != 1 for marker in markers)
        or runbook.find(markers[0]) >= runbook.find(markers[1])
    ):
        failures.append("current-head-v15-markers-open")
        return tuple(failures)

    required = (
        HEADS,
        IAM_COMBINED_SHA256,
        IAM_MANIFEST_SHA256,
        PROFILE_MANIFEST_SHA256,
        DEMAND_MANIFEST_SHA256,
        DEMAND_DEPENDENCY_SHA256,
        TRUST_API_SHA256,
        TRUST_SQL_SHA256,
        TRUST_MANIFEST_SHA256,
        TRUST_COMBINED_SHA256,
        TAXONOMY_MANIFEST_SHA256,
        V15_EXPECTED_CONTRACTS,
        "Trust required IAM schema",
        "Trust required Demand schema",
        "TRUST_REPORT_CURSOR",
        "key-trust-report-cursor-v1",
        "trust-report-cursor-2026-01",
        "25 个 key carrier = 36 个 secret",
        IMAGE_TAG,
        BUNDLE_NAME,
        RELEASE_ID,
        BACKUP_BASENAME,
        "RUN_CURRENT_HEAD_V15_ONCE",
        "production_authorized=false",
        '"claim":"NOT_VERIFIED"',
        '"overall_status":"BLOCKED"',
        "one-shot state: `NOT_CONSUMED`",
        "STATIC VERIFIED",
        "NOT EXECUTED",
        "python3 -B scripts/verify_current_head_v15.py",
        "deploy/postgres-backup-restore-v15.sh",
        "deploy/postgres-operations-v15.compose.yaml",
        "current-head-v14.md",
    )
    if any(value not in runbook for value in required):
        failures.append("current-head-v15-coordinate-open")

    helper = runbook.partition("compose_v15_operations() {")[2].partition("\n}")[0]
    compose_lines = tuple(f'-f "$PWD/{path}"' for path in V15_COMPOSE_FILES)
    if (
        not helper
        or helper.count('-f "$PWD/') != 3
        or any(helper.count(line) != 1 for line in compose_lines)
        or "compose.ipam.yaml" in helper
        or "--build" in helper
        or "--pull" in helper
    ):
        failures.append("current-head-v15-operations-compose-open")

    if any(
        old in runbook
        for old in (
            "e2e-ten-account-v14-iam38-demand10-trust8",
            "internal-sandbox-bundle-iam38-demand10-trust8",
            "release-e2e-ten-account-v14-iam38-demand10-trust8",
            "v14-iam38-profile3-demand10-trust8-taxonomy2-drill01",
        )
    ):
        failures.append("current-head-v15-stale-coordinate-open")
    return _unique(failures)


def _postgres_operations_v15_failures(
    v14_script: str,
    v15_script: str,
    overlay: str,
) -> tuple[str, ...]:
    failures: list[str] = []
    if overlay != EXPECTED_V15_OVERLAY:
        failures.append("postgres-operations-v15-overlay-open")
    if (
        f"EXPECTED_PINS='{V14_PINS}'" not in v14_script
        or f"EXPECTED_CONTRACTS='{V14_EXPECTED_CONTRACTS}'" not in v14_script
    ):
        failures.append("postgres-operations-v14-history-drifted")
    if (
        f"EXPECTED_PINS='{HEADS}'" not in v15_script
        or f"EXPECTED_CONTRACTS='{V15_EXPECTED_CONTRACTS}'" not in v15_script
    ):
        failures.append("postgres-operations-v15-pins-open")
    normalized = v15_script.replace(HEADS, V14_PINS).replace(
        V15_EXPECTED_CONTRACTS,
        V14_EXPECTED_CONTRACTS,
    )
    if normalized != v14_script:
        failures.append("postgres-operations-v15-clone-drifted")
    return _unique(failures)


def _frozen_asset_failures(root: Path) -> tuple[str, ...]:
    failures: list[str] = []
    for relative_path, expected in FROZEN_ASSETS:
        if _sha256(root / relative_path) != expected:
            failures.append(f"current-head-v15-frozen-asset-mismatch:{relative_path}")

    manifests = (
        (
            "tests/deployment/fixtures/current-head-v14/iam-manifest.json",
            "iam",
            tuple(range(39)),
        ),
        (
            "platform/src/desire_platform/creator_profile/adapters/postgres/"
            "migrations/manifest.json",
            "profile",
            tuple(range(1, 4)),
        ),
        (
            "tests/deployment/fixtures/current-head-v15/demand-manifest.json",
            "demand",
            tuple(range(1, 11)),
        ),
        (
            "tests/deployment/fixtures/current-head-v15/trust-manifest.json",
            "trust",
            tuple(range(1, 10)),
        ),
        (
            "platform/src/desire_platform/taxonomy/adapters/postgres/migrations/"
            "manifest.json",
            "taxonomy",
            tuple(range(1, 3)),
        ),
    )
    for relative_path, component, expected_versions in manifests:
        try:
            value = json.loads(_read_text(root / relative_path))
            versions = tuple(
                item["version"] for item in value if item["component"] == component
            )
        except (KeyError, TypeError, json.JSONDecodeError):
            versions = ()
        if versions != expected_versions:
            failures.append(f"current-head-v15-manifest-shape-open:{component}")

    trust_runner = _read_text(
        root / "tests/deployment/fixtures/current-head-v15/trust-runner-pins.txt"
    )
    for value in (
        "TRUST_REQUIRED_IAM_SCHEMA_VERSION = 38",
        "TRUST_REQUIRED_DEMAND_SCHEMA_VERSION = 10",
        IAM_COMBINED_SHA256,
        DEMAND_DEPENDENCY_SHA256,
        TRUST_API_SHA256,
        TRUST_COMBINED_SHA256,
    ):
        if value not in trust_runner:
            failures.append("current-head-v15-trust-contract-open")
            break
    return _unique(failures)


def _historical_v14_failures(root: Path) -> tuple[str, ...]:
    failures: list[str] = []
    verifier = _read_text(root / "scripts/verify_current_head_v14.py")
    if (
        verifier.count(
            '"tests/deployment/fixtures/current-head-v14/demand-manifest.json"'
        ) < 2
        or
        verifier.count(
            '"tests/deployment/fixtures/current-head-v14/trust-manifest.json"'
        ) < 2
        or "trust_runner =" in verifier
        or '"status":"CURRENT_HEAD_V14_STATIC_VERIFIED"' not in verifier
    ):
        failures.append("current-head-v14-frozen-gate-open")
    if _read_text(root / "docs/operations/current-head-v14.md").count(
        "<!-- BEGIN CURRENT_HEAD_V14_CONTRACT -->"
    ) != 1:
        failures.append("current-head-v14-runbook-open")
    if _read_text(root / "deploy/postgres-operations-v14.compose.yaml") != (
        "configs:\n"
        "  postgres-backup-restore-script:\n"
        "    file: ./deploy/postgres-backup-restore-v14.sh\n"
    ):
        failures.append("postgres-operations-v14-overlay-open")
    return _unique(failures)


def verify_repository(root: Path = REPOSITORY_ROOT) -> tuple[str, ...]:
    root = Path(root)
    failures: list[str] = []
    failures.extend(
        _current_head_v15_runbook_failures(
            _read_text(root / "docs/operations/current-head-v15.md")
        )
    )
    failures.extend(
        _postgres_operations_v15_failures(
            _read_text(root / "deploy/postgres-backup-restore-v14.sh"),
            _read_text(root / "deploy/postgres-backup-restore-v15.sh"),
            _read_text(root / "deploy/postgres-operations-v15.compose.yaml"),
        )
    )
    failures.extend(_frozen_asset_failures(root))
    failures.extend(_historical_v14_failures(root))

    ci = _read_text(root / ".github/workflows/ci.yml")
    if (
        "python -B scripts/verify_container_stack.py" not in ci
        or ci.count("python -B scripts/verify_current_head_v14.py") != 1
        or ci.count("python -B scripts/verify_current_head_v15.py") != 1
    ):
        failures.append("current-head-v15-ci-gate-open")
    sidebar = _read_text(root / "docs/_sidebar.md")
    if (
        "[Current-head v15 发布资产](/operations/current-head-v15.md)" not in sidebar
        or "[Current-head v14 发布资产](/operations/current-head-v14.md)"
        not in sidebar
    ):
        failures.append("current-head-v15-sidebar-open")
    operations = _read_text(root / "docs/operations/run-and-check.md")
    if (
        "[Current-head v15 发布资产](/operations/current-head-v15.md)"
        not in operations
        or "current pointer 不会把它们改写为" not in operations
    ):
        failures.append("current-head-v15-run-and-check-pointer-open")
    return _unique(failures)


def main(argv: tuple[str, ...] | None = None) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    if arguments:
        print(
            '{"failures":["arguments-forbidden"],"status":"BLOCKED"}',
            file=sys.stderr,
        )
        return 78
    failures = verify_repository()
    if failures:
        print(
            json.dumps(
                {"failures": list(failures), "status": "BLOCKED"},
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(SUCCESS)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
