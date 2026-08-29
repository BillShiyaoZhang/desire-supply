#!/usr/bin/env python3
"""Read-only verifier for the v27 PostgreSQL/Matching static release head."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Iterable


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SUCCESS = '{"status":"CURRENT_HEAD_V27_STATIC_VERIFIED"}'
HEADS = "18|46|46|5|5|15|15|22|22|3|3|2|2"
IAM_MANIFEST_SHA256 = "faa540929a66eeb7ebfe86ca5e43539ef7dcb10424e792ded14252f27c5850a5"
IAM_COMBINED_SHA256 = "14b0ae7a2ba2db7d6807b9b71080d40ab4b40b4e0e2664c5da0ac14fcb29c84d"
PROFILE_MANIFEST_SHA256 = "005be339b76c61427895ad7e6ddbb685735d7c602d99fc4dafdd08c35c97d4f8"
DEMAND_MANIFEST_SHA256 = "32d8587651d05e725a4277e2d253b8e195192f1dabc702dd5208b53fe8143f73"
DEMAND_DEPENDENCY_SHA256 = "ea6887891134ffa2f451fed35d469ae1c5195c54649e228f587622d95696dddf"
TRUST_MANIFEST_SHA256 = "3fd3089db8139f4e70551f59f8e803fdf2543847d38d08f82f8a050c2dd921e8"
TRUST_COMBINED_SHA256 = "68f3c3e90088f6d4383e73b3fbc6f77297cee27bc78086db227708bc872613f6"
MATCHING_MANIFEST_SHA256 = "b6c4169edcaf4c7cb771fde614ef72c3d90d56b4d2f4d5a0a633f8b634adbf18"
TAXONOMY_MANIFEST_SHA256 = "74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622"
MATCHING_CONTRACT_SHA256 = {
    "api": "bbf292401809ff6b1fdf05fd687d7f337dfb34e193f5340c579dceaba4801e18",
    "event": "ec63cb0733f275eaedc99348427883bb958c6467c5ee49f2a26fb252c0aafb6a",
    "rule": "144337610f3d06b8bfbb324547f3e25ca54ee6c2f821a28f94812aefc01ea4aa",
    "input_manifest": "38c90e5d73f7aff05d7b3dc6263c52a0c50c6769daa3b8ee541dccd58057f970",
    "run_input": "8774cf412ffa82c9acf53e6e7e95af361f84ec8040d02b972f846d57bb395418",
    "candidate": "856f95a2169a095d238277586cfdb171d38104eaaaa03d2df925502e1b919a28",
    "disclosure": "6b8b739a27bbd3894372de8a566133a6991fca22d97da883c87d6ebf601763de",
}
HEAD_SQL_SHA256 = {
    "iam": "0ed672688f219bedecb3953d3fb20f6bc9e2e3e93649e47c3017c64a9c97cacf",
    "profile": "effbecf1c2982304fd1e17b6da7a5d629e485f701692f004cd112865e8ce483a",
    "demand": "d095b37927b0e3b10dfe42b032044736276df830986493b03d1580f3d3a2fa34",
    "trust": "f0eceeb22f1f8832efdfcf9cf96107f0190c23db647b5f312aa2cdb6635143b8",
    "matching": "3f28f26cfca5af93a716aa34403288d644e3eab44c4af258a383b42e82b8b434",
    "taxonomy": "0dd451bfb8939a98e0d1abd0ca4f28be54c0722e2fac076e74a3db8e3ce3b928",
}
EXPECTED_COMPONENT_PINS = {
    "iam": {
        "combined_sha256": IAM_COMBINED_SHA256,
        "head": 46,
        "head_sql_sha256": HEAD_SQL_SHA256["iam"],
        "manifest_sha256": IAM_MANIFEST_SHA256,
    },
    "profile": {
        "head": 5,
        "head_sql_sha256": HEAD_SQL_SHA256["profile"],
        "manifest_sha256": PROFILE_MANIFEST_SHA256,
        "required_iam": 46,
    },
    "demand": {
        "dependency_sha256": DEMAND_DEPENDENCY_SHA256,
        "head": 15,
        "head_sql_sha256": HEAD_SQL_SHA256["demand"],
        "manifest_sha256": DEMAND_MANIFEST_SHA256,
        "required_iam": 45,
    },
    "trust": {
        "combined_sha256": TRUST_COMBINED_SHA256,
        "head": 22,
        "head_sql_sha256": HEAD_SQL_SHA256["trust"],
        "manifest_sha256": TRUST_MANIFEST_SHA256,
        "required_demand": 15,
        "required_demand_sha256": DEMAND_DEPENDENCY_SHA256,
        "required_iam": 46,
        "required_iam_sha256": IAM_COMBINED_SHA256,
    },
    "matching": {
        "api_sha256": MATCHING_CONTRACT_SHA256["api"],
        "candidate_sha256": MATCHING_CONTRACT_SHA256["candidate"],
        "disclosure_sha256": MATCHING_CONTRACT_SHA256["disclosure"],
        "event_sha256": MATCHING_CONTRACT_SHA256["event"],
        "head": 3,
        "head_sql_sha256": HEAD_SQL_SHA256["matching"],
        "input_manifest_sha256": MATCHING_CONTRACT_SHA256["input_manifest"],
        "manifest_sha256": MATCHING_MANIFEST_SHA256,
        "required_iam": 46,
        "rule_sha256": MATCHING_CONTRACT_SHA256["rule"],
        "run_input_sha256": MATCHING_CONTRACT_SHA256["run_input"],
    },
    "taxonomy": {
        "head": 2,
        "head_sql_sha256": HEAD_SQL_SHA256["taxonomy"],
        "manifest_sha256": TAXONOMY_MANIFEST_SHA256,
    },
}
EXPECTED_CONTRACTS = "|".join(
    (
        IAM_COMBINED_SHA256,
        PROFILE_MANIFEST_SHA256,
        "45",
        DEMAND_MANIFEST_SHA256,
        "46",
        "15",
        IAM_COMBINED_SHA256,
        DEMAND_DEPENDENCY_SHA256,
        TRUST_COMBINED_SHA256,
        TRUST_MANIFEST_SHA256,
        "46",
        MATCHING_CONTRACT_SHA256["api"],
        MATCHING_CONTRACT_SHA256["event"],
        MATCHING_CONTRACT_SHA256["rule"],
        MATCHING_CONTRACT_SHA256["input_manifest"],
        MATCHING_CONTRACT_SHA256["run_input"],
        MATCHING_CONTRACT_SHA256["candidate"],
        MATCHING_CONTRACT_SHA256["disclosure"],
        MATCHING_MANIFEST_SHA256,
        TAXONOMY_MANIFEST_SHA256,
    )
)
MATCHING_TABLES = (
    "candidate_selector_assignments",
    "candidate_selector_opt_in_receipts",
    "command_receipts",
    "complete_selection_close_records",
    "complete_selection_records",
    "complete_selection_system_close_records",
    "invitation_disclosure_snapshots",
    "invitation_responses",
    "invitation_withdrawals",
    "invitations",
    "match_candidates",
    "match_jobs",
    "match_run_inputs",
    "match_run_results",
    "match_runs",
    "matching_attempts",
    "matching_review_assignments",
    "review_hold_evidence",
    "reviewer_authority_projections",
    "rule_bundles",
    "rule_selectors",
    "selection_close_intents",
    "selection_completion_jobs",
    "selection_intents",
    "selection_system_close_intents",
    "selections",
    "source_inbox",
)
FROZEN_V26 = {
    "scripts/verify_current_head_v26.py":
        "4fc359fa3f1535d3a32d025a0d6f4b4c07b99eb916cf30f8bc2c0838115c25bf",
    "docs/operations/current-head-v26.md":
        "238216f2756285057a1ee26be100a8f4d90bfee272e5a2c23840f1967083f280",
    "tests/deployment/fixtures/current-head-v26/iam-manifest.json":
        "7edad01ff151168e4e048848fe770eb0ea199a1034a8119658a1c3bf53205b5e",
    "tests/deployment/fixtures/current-head-v26/demand-manifest.json":
        "5663d8e14bb5fa6a5706828fe443a8c08ac2e62bad3e56403dd45bc6df939b29",
    "tests/deployment/fixtures/current-head-v26/trust-manifest.json":
        "5949f7b630376a59c643f9024210625811606a1a41f90f4bc99ee19dfb99d38c",
    "tests/deployment/fixtures/current-head-v26/trust-runner-pins.txt":
        "2c51f1df80ca8f3fcdca38c66b7d82fbc9a254744f69ba73ec9b0e54cd6c3f77",
    "deploy/postgres-backup-restore-v26.sh":
        "48fe07e4a845738cd620b2584eae984d1a66d2258f6fc2c46b0ee63eaec2d72c",
    "deploy/postgres-core-facts-v26.sql":
        "274cf10f533673a1541f9dd186039153605bc420f847fa14110027bd5650f153",
    "deploy/postgres-operations-v26.compose.yaml":
        "7fc79306fce5feb2d985390ab6e8f6a77955a5ad7d53bb341e25c8ed0df1e041",
}
MANIFESTS = {
    "iam": (
        "platform/src/desire_platform/identity_access/adapters/postgres/migrations",
        tuple(range(47)),
        IAM_MANIFEST_SHA256,
    ),
    "profile": (
        "platform/src/desire_platform/creator_profile/adapters/postgres/migrations",
        tuple(range(1, 6)),
        PROFILE_MANIFEST_SHA256,
    ),
    "demand": (
        "platform/src/desire_platform/demand/adapters/postgres/migrations",
        tuple(range(1, 16)),
        DEMAND_MANIFEST_SHA256,
    ),
    "trust": (
        "platform/src/desire_platform/trust_safety/adapters/postgres/migrations",
        tuple(range(1, 23)),
        TRUST_MANIFEST_SHA256,
    ),
    "matching": (
        "platform/src/desire_platform/matching/adapters/postgres/migrations",
        tuple(range(1, 4)),
        MATCHING_MANIFEST_SHA256,
    ),
    "taxonomy": (
        "platform/src/desire_platform/taxonomy/adapters/postgres/migrations",
        tuple(range(1, 3)),
        TAXONOMY_MANIFEST_SHA256,
    ),
}
MATCHING_CONTRACT_FILES = {
    "api": "platform/src/desire_platform/contracts/api/matching-v1.openapi.yaml",
    "event": "platform/src/desire_platform/contracts/events/matching-v1.schema.json",
    "rule": "platform/src/desire_platform/contracts/domain/matching-rule-release-v1.schema.json",
    "input_manifest": "platform/src/desire_platform/contracts/domain/match-input-manifest-v1.schema.json",
    "run_input": "platform/src/desire_platform/contracts/domain/match-run-input-v1.schema.json",
    "candidate": "platform/src/desire_platform/contracts/domain/match-candidate-result-v1.schema.json",
    "disclosure": "platform/src/desire_platform/contracts/domain/invitation-disclosure-v1.schema.json",
}


def _read(path: Path) -> str:
    try:
        if path.is_symlink() or not path.is_file():
            return ""
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return ""


def _bytes(path: Path) -> bytes | None:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        return path.read_bytes()
    except OSError:
        return None


def _sha(path: Path) -> str | None:
    value = _bytes(path)
    return None if value is None else hashlib.sha256(value).hexdigest()


def _unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _json(path: Path) -> object | None:
    try:
        return json.loads(_read(path))
    except json.JSONDecodeError:
        return None


def _manifest_failures(root: Path) -> tuple[str, ...]:
    failures: list[str] = []
    for component, (relative_root, versions, expected_sha) in MANIFESTS.items():
        migration_root = root / relative_root
        manifest_path = migration_root / "manifest.json"
        document = _json(manifest_path)
        if _sha(manifest_path) != expected_sha or not isinstance(document, list):
            failures.append(f"{component}-manifest-pin-open")
            continue
        try:
            actual_versions = tuple(
                item["version"]
                for item in document
                if item["component"] == component
            )
        except (KeyError, TypeError):
            failures.append(f"{component}-manifest-shape-open")
            continue
        if actual_versions != versions or len(document) != len(versions):
            failures.append(f"{component}-manifest-sequence-open")
        for item in document:
            try:
                artifact = migration_root / item["path"]
                if artifact.parent != migration_root or _sha(artifact) != item["sha256"]:
                    failures.append(f"{component}-migration-checksum-open")
                    break
            except (KeyError, TypeError):
                failures.append(f"{component}-manifest-shape-open")
                break
    return _unique(failures)


def _historical_prefix_failures(root: Path) -> tuple[str, ...]:
    failures: list[str] = []
    boundaries = {
        "iam": (
            "platform/src/desire_platform/identity_access/adapters/postgres/migrations/manifest.json",
            "tests/deployment/fixtures/current-head-v26/iam-manifest.json",
        ),
        "demand": (
            "platform/src/desire_platform/demand/adapters/postgres/migrations/manifest.json",
            "tests/deployment/fixtures/current-head-v26/demand-manifest.json",
        ),
        "trust": (
            "platform/src/desire_platform/trust_safety/adapters/postgres/migrations/manifest.json",
            "tests/deployment/fixtures/current-head-v26/trust-manifest.json",
        ),
    }
    for component, (live_path, frozen_path) in boundaries.items():
        live = _json(root / live_path)
        frozen = _json(root / frozen_path)
        if (
            not isinstance(live, list)
            or not isinstance(frozen, list)
            or live[: len(frozen)] != frozen
        ):
            failures.append(f"v26-{component}-migration-prefix-drifted")
    return tuple(failures)


def _operations_failures(script: str, facts: str, overlay: str) -> tuple[str, ...]:
    failures: list[str] = []
    expected_overlay = """configs:
  postgres-backup-restore-script:
    file: ./deploy/postgres-backup-restore-v27.sh
  postgres-core-facts-sql:
    file: ./deploy/postgres-core-facts-v27.sql
"""
    if overlay != expected_overlay:
        failures.append("postgres-operations-v27-overlay-open")
    if f"EXPECTED_PINS='{HEADS}'" not in script:
        failures.append("postgres-operations-v27-heads-open")
    if f"EXPECTED_CONTRACTS='{EXPECTED_CONTRACTS}'" not in script:
        failures.append("postgres-operations-v27-contracts-open")
    for marker in (
        "matching.current_schema_version",
        "matching.schema_head_version",
        "matching.required_iam_schema_version",
        "matching_meta.api_contract_sha256",
        "matching_meta.event_contract_sha256",
        "matching_meta.rule_contract_sha256",
        "matching_meta.input_manifest_contract_sha256",
        "matching_meta.run_input_contract_sha256",
        "matching_meta.candidate_contract_sha256",
        "matching_meta.disclosure_contract_sha256",
        "matching.migration_manifest_sha256",
        '"matching_continuity_counts"',
    ):
        if marker not in script:
            failures.append("postgres-operations-v27-matching-contract-open")
            break
    for table in MATCHING_TABLES:
        qualified = f"matching.{table}"
        if script.count(qualified) != 1 or facts.count(qualified) != 1:
            failures.append("postgres-operations-v27-matching-continuity-open")
            break
    for forbidden in (
        "creator_user_id",
        "reviewer_user_id",
        "candidate_id",
        "safe_response_body",
        "canonical_result_bytes",
    ):
        if forbidden in facts:
            failures.append("postgres-operations-v27-facts-privacy-open")
            break
    return _unique(failures)


def _runbook_failures(value: str) -> tuple[str, ...]:
    begin = "<!-- BEGIN CURRENT_HEAD_V27_CONTRACT -->"
    end = "<!-- END CURRENT_HEAD_V27_CONTRACT -->"
    failures: list[str] = []
    if (
        value.count(begin) != 1
        or value.count(end) != 1
        or value.find(begin) >= value.find(end)
    ):
        failures.append("current-head-v27-markers-open")
    for marker in (
        HEADS,
        IAM_MANIFEST_SHA256,
        IAM_COMBINED_SHA256,
        PROFILE_MANIFEST_SHA256,
        DEMAND_MANIFEST_SHA256,
        DEMAND_DEPENDENCY_SHA256,
        TRUST_MANIFEST_SHA256,
        TRUST_COMBINED_SHA256,
        MATCHING_MANIFEST_SHA256,
        TAXONOMY_MANIFEST_SHA256,
        "Matching v1-v3 的 27 张 durable domain tables",
        "matching_continuity_counts",
        "STATIC VERIFIED / NOT PRODUCTION EXECUTED",
        '"production_authorized":false',
        "postgres-operations-v27.compose.yaml",
        "v27-iam46-profile5-demand15-trust22-matching3-taxonomy2-drill01",
    ):
        if marker not in value:
            failures.append("current-head-v27-runbook-contract-open")
            break
    return _unique(failures)


def verify_repository(root: Path = REPOSITORY_ROOT) -> tuple[str, ...]:
    failures: list[str] = []
    fixture_path = root / "tests/deployment/fixtures/current-head-v27/schema-pins.json"
    fixture_bytes = _bytes(fixture_path)
    fixture = _json(fixture_path)
    if not isinstance(fixture, dict) or fixture_bytes is None:
        failures.append("current-head-v27-fixture-open")
    else:
        canonical = (
            json.dumps(fixture, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
            .encode("ascii")
            + b"\n"
        )
        if fixture_bytes != canonical:
            failures.append("current-head-v27-fixture-canonical-open")
        if (
            fixture.get("heads") != HEADS
            or fixture.get("claim") != "STATIC_ONLY"
            or fixture.get("status") != "NOT_PRODUCTION_EXECUTED"
            or fixture.get("production_authorized") is not False
        ):
            failures.append("current-head-v27-fixture-claim-open")
        if fixture.get("components") != EXPECTED_COMPONENT_PINS:
            failures.append("current-head-v27-fixture-pins-open")

    if "__MATCHING_V3_" in "\n".join(
        (
            MATCHING_MANIFEST_SHA256,
            _read(fixture_path),
            _read(root / "deploy/postgres-backup-restore-v27.sh"),
            _read(root / "docs/operations/current-head-v27.md"),
        )
    ):
        failures.append("current-head-v27-matching-pins-open")

    failures.extend(_manifest_failures(root))
    failures.extend(_historical_prefix_failures(root))
    for relative, expected in FROZEN_V26.items():
        if _sha(root / relative) != expected:
            failures.append(f"current-head-v26-history-drifted:{relative}")

    for name, relative in MATCHING_CONTRACT_FILES.items():
        if _sha(root / relative) != MATCHING_CONTRACT_SHA256[name]:
            failures.append(f"matching-{name}-contract-pin-open")

    runner_sources = {
        "profile": _read(
            root / "platform/src/desire_platform/creator_profile/adapters/postgres/migrations/runner.py"
        ),
        "demand": _read(
            root / "platform/src/desire_platform/demand/adapters/postgres/migrations/runner.py"
        ),
        "trust": _read(
            root / "platform/src/desire_platform/trust_safety/adapters/postgres/migrations/runner.py"
        ),
        "matching": _read(
            root / "platform/src/desire_platform/matching/adapters/postgres/migrations/runner.py"
        ),
    }
    for name, markers in {
        "profile": ("PROFILE_REQUIRED_IAM_SCHEMA_VERSION = 46",),
        "demand": ("DEMAND_REQUIRED_IAM_SCHEMA_VERSION = 45",),
        "trust": (
            "TRUST_REQUIRED_IAM_SCHEMA_VERSION = 46",
            "TRUST_REQUIRED_DEMAND_SCHEMA_VERSION = 15",
            IAM_COMBINED_SHA256,
            DEMAND_DEPENDENCY_SHA256,
            TRUST_COMBINED_SHA256,
        ),
        "matching": ("MATCHING_REQUIRED_IAM_SCHEMA_VERSION = 46",),
    }.items():
        if any(marker not in runner_sources[name] for marker in markers):
            failures.append(f"{name}-dependency-pin-open")

    failures.extend(
        _operations_failures(
            _read(root / "deploy/postgres-backup-restore-v27.sh"),
            _read(root / "deploy/postgres-core-facts-v27.sql"),
            _read(root / "deploy/postgres-operations-v27.compose.yaml"),
        )
    )
    failures.extend(
        _runbook_failures(_read(root / "docs/operations/current-head-v27.md"))
    )

    sidebar = _read(root / "docs/_sidebar.md")
    for marker in (
        "[Current-head v27 静态模式头](/operations/current-head-v27.md)",
        "[Current-head v26 静态模式头](/operations/current-head-v26.md)",
    ):
        if marker not in sidebar:
            failures.append("current-head-v27-sidebar-open")
            break

    invocation_v26 = "python -B scripts/verify_current_head_v26.py"
    invocation_v27 = "python -B scripts/verify_current_head_v27.py"
    for relative in (
        ".github/workflows/ci.yml",
        ".github/workflows/private-server-runtime-release.yml",
    ):
        source = _read(root / relative)
        if source.count(invocation_v26) != 0 or source.count(invocation_v27) != 1:
            failures.append("current-head-v27-workflow-pointer-open")
            break

    readiness = _read(root / "scripts/check_private_server_source_readiness.py")
    for relative in (
        "deploy/postgres-backup-restore.sh",
        "deploy/postgres-core-facts.sql",
        "deploy/postgres-operations.compose.yaml",
        "docs/operations/current-head-v27.md",
        "deploy/postgres-backup-restore-v27.sh",
        "deploy/postgres-core-facts-v27.sql",
        "deploy/postgres-operations-v27.compose.yaml",
        "scripts/verify_current_head_v27.py",
        "tests/deployment/fixtures/current-head-v27/schema-pins.json",
        "tests/deployment/test_current_head_v27_contract.py",
        "tests/deployment/test_postgres_operations_v27.py",
    ):
        if relative not in readiness:
            failures.append("current-head-v27-source-readiness-open")
            break

    operations_summary = "\n".join(
        _read(root / relative)
        for relative in (
            "docs/operations/run-and-check.md",
            "docs/operations/container-deployment.md",
            "docs/operations/private-server-runtime-release.md",
        )
    )
    for marker in (
        "current-head v27",
        "IAM46/Profile5/Demand15/Trust22/Matching3/Taxonomy2",
        "verify_current_head_v27.py",
        "postgres-operations-v27.compose.yaml",
    ):
        if marker not in operations_summary:
            failures.append("current-head-v27-live-operations-pointer-open")
            break

    if (
        _bytes(root / "deploy/postgres-backup-restore.sh")
        != _bytes(root / "deploy/postgres-backup-restore-v27.sh")
        or _bytes(root / "deploy/postgres-core-facts.sql")
        != _bytes(root / "deploy/postgres-core-facts-v27.sql")
    ):
        failures.append("current-head-v27-unversioned-operations-pointer-open")

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
        return 78
    print(SUCCESS)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
