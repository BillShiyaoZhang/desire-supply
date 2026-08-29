#!/usr/bin/env python3
"""Read-only verifier for the current-head v14 publishing assets.

This gate reads checked-in files only.  It never calls Docker, consumes a
one-shot coordinate, creates evidence, or upgrades a BLOCKED caller claim.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Iterable


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
HEADS = "18|38|38|3|3|10|10|8|8|2|2"
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
TRUST_MANIFEST_SHA256 = (
    "6d5e98529d07f684657820a8a1d405cd243fa8ac26518ecee02a966ccc02d722"
)
TRUST_COMBINED_SHA256 = (
    "8907369e35172587753295403dc101227c21671960539c51364f8e00f1e4978a"
)
TAXONOMY_MANIFEST_SHA256 = (
    "74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622"
)
IMAGE_TAG = "e2e-ten-account-v14-iam38-demand10-trust8"
BUNDLE_NAME = "internal-sandbox-bundle-iam38-demand10-trust8"
RELEASE_ID = "release-e2e-ten-account-v14-iam38-demand10-trust8"
BACKUP_BASENAME = (
    "v14-iam38-profile3-demand10-trust8-taxonomy2-drill01"
)
V14_COMPOSE_FILES = (
    "compose.yaml",
    "deploy/postgres-operations.compose.yaml",
    "deploy/postgres-operations-v14.compose.yaml",
)
SUCCESS = '{"status":"CURRENT_HEAD_V14_STATIC_VERIFIED"}'
V13_PINS = "18|37|37|3|3|10|10|7|7|2|2"
V13_EXPECTED_CONTRACTS = (
    "595d5232153063b0b71a88b3776c737d1fcd5ecaef4a4b832c5e40434929c486|"
    "4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa|"
    "7695127a039fa71cddabd62318bea39337e3acbb4b1df66a3557b7a7ae3707b4|"
    "37|10|"
    "595d5232153063b0b71a88b3776c737d1fcd5ecaef4a4b832c5e40434929c486|"
    "27ec6b585a9340cbd7119d7a9b46d6098a3881f88ae1be9e00df3713c0107113|"
    "ab857f25969d17afe63886afe136cda10814e538517c54c180503b82f5785c1b|"
    "27a51c55bddfcb2a4f1bd16a3160abbb3a417425f14077f4886c3c41c22d5124|"
    "74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622"
)
V14_EXPECTED_CONTRACTS = (
    f"{IAM_COMBINED_SHA256}|"
    f"{PROFILE_MANIFEST_SHA256}|"
    f"{DEMAND_MANIFEST_SHA256}|38|10|{IAM_COMBINED_SHA256}|"
    f"{DEMAND_DEPENDENCY_SHA256}|{TRUST_COMBINED_SHA256}|"
    f"{TRUST_MANIFEST_SHA256}|"
    f"{TAXONOMY_MANIFEST_SHA256}"
)
EXPECTED_V14_OVERLAY = """configs:
  postgres-backup-restore-script:
    file: ./deploy/postgres-backup-restore-v14.sh
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
        "platform/src/desire_platform/demand/adapters/postgres/migrations/"
        "0010_expand__finance_funding_review_resolution.sql",
        "12971bf1143969ef47875aa0d83c39fade0b3dbabfaf892f269dc24078bc9823",
    ),
    (
        "tests/deployment/fixtures/current-head-v14/demand-manifest.json",
        DEMAND_MANIFEST_SHA256,
    ),
    (
        "platform/src/desire_platform/trust_safety/adapters/postgres/"
        "migrations/0008_expand__iam38_demand10_dependency_repin.sql",
        "c15ca1b6ac8a750dc4cd5b1cf815a367d7531ddb9088da9d60ec1a7a99ff241b",
    ),
    (
        "tests/deployment/fixtures/current-head-v14/trust-manifest.json",
        TRUST_MANIFEST_SHA256,
    ),
    (
        "tests/deployment/fixtures/current-head-v14/trust-v1.openapi.yaml",
        "f23f8283ce8334cf48e1c912379451f00efe21382a281c5f5156260ae3a618ed",
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


def _current_head_v14_runbook_failures(runbook: str) -> tuple[str, ...]:
    failures: list[str] = []
    markers = (
        "<!-- BEGIN CURRENT_HEAD_V14_CONTRACT -->",
        "<!-- END CURRENT_HEAD_V14_CONTRACT -->",
    )
    if (
        any(runbook.count(marker) != 1 for marker in markers)
        or runbook.find(markers[0]) >= runbook.find(markers[1])
    ):
        failures.append("current-head-v14-markers-open")
        return tuple(failures)

    required = (
        HEADS,
        IAM_COMBINED_SHA256,
        IAM_MANIFEST_SHA256,
        PROFILE_MANIFEST_SHA256,
        DEMAND_MANIFEST_SHA256,
        DEMAND_DEPENDENCY_SHA256,
        TRUST_MANIFEST_SHA256,
        TRUST_COMBINED_SHA256,
        TAXONOMY_MANIFEST_SHA256,
        V14_EXPECTED_CONTRACTS,
        "Trust required IAM schema",
        "Trust required Demand schema",
        IMAGE_TAG,
        BUNDLE_NAME,
        RELEASE_ID,
        BACKUP_BASENAME,
        "RUN_CURRENT_HEAD_V14_ONCE",
        "production_authorized=false",
        '"claim":"NOT_VERIFIED"',
        '"overall_status":"BLOCKED"',
        "one-shot state: `NOT_CONSUMED`",
        "python3 -B scripts/verify_current_head_v14.py",
        "deploy/postgres-backup-restore-v14.sh",
        "deploy/postgres-operations-v14.compose.yaml",
        "private-server-release-candidate-evidence-v2.schema.json",
        "private_server_release_candidate_evidence_v2.py",
    )
    if any(value not in runbook for value in required):
        failures.append("current-head-v14-coordinate-open")

    helper = runbook.partition("compose_v14_operations() {")[2].partition(
        "\n}"
    )[0]
    compose_lines = tuple(f'-f "$PWD/{path}"' for path in V14_COMPOSE_FILES)
    if (
        not helper
        or helper.count('-f "$PWD/') != 3
        or any(helper.count(line) != 1 for line in compose_lines)
        or "compose.ipam.yaml" in helper
        or "--build" in helper
        or "--pull" in helper
    ):
        failures.append("current-head-v14-operations-compose-open")

    if any(
        old in runbook
        for old in (
            "e2e-ten-account-v13-iam37-demand10-trust7",
            "internal-sandbox-bundle-iam37-demand10-trust7",
            "release-e2e-ten-account-v13-iam37-demand10-trust7",
            "trust8_applicant_discovery",
        )
    ):
        failures.append("current-head-v14-stale-coordinate-open")
    return _unique(failures)


def _postgres_operations_v14_failures(
    legacy_script: str,
    v14_script: str,
    overlay: str,
) -> tuple[str, ...]:
    failures: list[str] = []
    if overlay != EXPECTED_V14_OVERLAY:
        failures.append("postgres-operations-v14-overlay-open")
    if (
        f"EXPECTED_PINS='{V13_PINS}'" not in legacy_script
        or f"EXPECTED_CONTRACTS='{V13_EXPECTED_CONTRACTS}'"
        not in legacy_script
    ):
        failures.append("postgres-operations-v13-history-drifted")
    if (
        f"EXPECTED_PINS='{HEADS}'" not in v14_script
        or f"EXPECTED_CONTRACTS='{V14_EXPECTED_CONTRACTS}'" not in v14_script
    ):
        failures.append("postgres-operations-v14-pins-open")
    normalized = v14_script.replace(HEADS, V13_PINS).replace(
        V14_EXPECTED_CONTRACTS,
        V13_EXPECTED_CONTRACTS,
    )
    if normalized != legacy_script:
        failures.append("postgres-operations-v14-clone-drifted")
    return _unique(failures)


def _frozen_asset_failures(root: Path) -> tuple[str, ...]:
    failures: list[str] = []
    for relative_path, expected in FROZEN_ASSETS:
        if _sha256(root / relative_path) != expected:
            failures.append(f"current-head-v14-frozen-asset-mismatch:{relative_path}")

    manifests = (
        (
            "tests/deployment/fixtures/current-head-v14/iam-manifest.json",
            "iam",
            tuple(range(39)),
        ),
        (
            "tests/deployment/fixtures/current-head-v14/demand-manifest.json",
            "demand",
            tuple(range(1, 11)),
        ),
        (
            "tests/deployment/fixtures/current-head-v14/trust-manifest.json",
            "trust",
            tuple(range(1, 9)),
        ),
    )
    for relative_path, component, expected_versions in manifests:
        try:
            value = json.loads(_read_text(root / relative_path))
            versions = tuple(
                item["version"]
                for item in value
                if item["component"] == component
            )
        except (KeyError, TypeError, json.JSONDecodeError):
            versions = ()
        if versions != expected_versions:
            failures.append(f"current-head-v14-manifest-shape-open:{component}")

    return _unique(failures)


def _evidence_v2_failures(root: Path) -> tuple[str, ...]:
    schema_path = (
        root / "deploy/private-server-release-candidate-evidence-v2.schema.json"
    )
    script = _read_text(
        root / "scripts/private_server_release_candidate_evidence_v2.py"
    )
    try:
        schema = json.loads(_read_text(schema_path))
        properties = schema["properties"]
    except (KeyError, TypeError, json.JSONDecodeError):
        return ("release-candidate-evidence-v2-schema-open",)
    if (
        schema.get("additionalProperties") is not False
        or "trust_applicant_discovery_deferral" not in properties
        or "trust8_applicant_discovery" in properties
        or properties.get("overall_status", {}).get("const") != "BLOCKED"
        or properties.get("production_authorized", {}).get("const") is not False
    ):
        return ("release-candidate-evidence-v2-schema-open",)
    required_script_values = (
        "trust_applicant_discovery_deferral",
        "RUN_CURRENT_HEAD_V14_ONCE",
        IAM_MANIFEST_SHA256,
        DEMAND_MANIFEST_SHA256,
        TRUST_MANIFEST_SHA256,
    )
    if (
        not script
        or "trust8_applicant_discovery" in script
        or any(value not in script for value in required_script_values)
    ):
        return ("release-candidate-evidence-v2-script-open",)
    return ()


def verify_repository(root: Path = REPOSITORY_ROOT) -> tuple[str, ...]:
    root = Path(root)
    failures: list[str] = []
    runbook = _read_text(root / "docs/operations/current-head-v14.md")
    failures.extend(_current_head_v14_runbook_failures(runbook))
    failures.extend(
        _postgres_operations_v14_failures(
            _read_text(root / "deploy/postgres-backup-restore.sh"),
            _read_text(root / "deploy/postgres-backup-restore-v14.sh"),
            _read_text(root / "deploy/postgres-operations-v14.compose.yaml"),
        )
    )
    failures.extend(_frozen_asset_failures(root))
    failures.extend(_evidence_v2_failures(root))

    ci = _read_text(root / ".github/workflows/ci.yml")
    if (
        "python -B scripts/verify_container_stack.py" not in ci
        or ci.count("python -B scripts/verify_current_head_v14.py") != 1
    ):
        failures.append("current-head-v14-ci-gate-open")
    sidebar = _read_text(root / "docs/_sidebar.md")
    if "[Current-head v14 发布资产](/operations/current-head-v14.md)" not in sidebar:
        failures.append("current-head-v14-sidebar-open")
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
