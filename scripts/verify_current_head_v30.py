#!/usr/bin/env python3
"""Read-only verifier for the v30 PostgreSQL/Matching static release head."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Iterable


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SUCCESS = '{"status":"CURRENT_HEAD_V30_STATIC_VERIFIED"}'
HEADS = "18|48|48|5|5|16|16|24|24|11|11|2|2"
IAM_MANIFEST_SHA256 = "5fea6646f1c2dc755a9a0b51adbe7f9c121e0a3b19d7a87f36dd78adff5af551"
IAM_COMBINED_SHA256 = "616cda6eac1e9f853be019f5790584e16826c295be08d10201f947e923a5ba3f"
PROFILE_MANIFEST_SHA256 = "005be339b76c61427895ad7e6ddbb685735d7c602d99fc4dafdd08c35c97d4f8"
DEMAND_MANIFEST_SHA256 = "4802d0ba44c05a059f3dfdbe0911e7be05cfd5d8508c8ced48a0a3f22bc1290f"
DEMAND_DEPENDENCY_SHA256 = "3362a606f35221c61cfb302ee54ce13bea450a44a02b33217606003a89c569ce"
TRUST_MANIFEST_SHA256 = "9574f3df40b95a3b1a0fdfd778a11edc969c27dc7879efca78aa75515cbdef24"
TRUST_COMBINED_SHA256 = "119f603be0862e7f35bc533005e7fef82f7bd6384eb2ab7966b04e75a5dfa199"
MATCHING_MANIFEST_SHA256 = "c7cc2c975f85723a5f4f3c7aa45fe6ebdf6f0fc0df140a06d111aad33eceffbb"
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
    "iam": "cb93aa215e7a062ad36a8ad0c64d64921d7918aead43c4b34a8552cb36acfeaa",
    "profile": "effbecf1c2982304fd1e17b6da7a5d629e485f701692f004cd112865e8ce483a",
    "demand": "bb779b254f8cdf985b3e70f36bc04963ff79c563a649382e2651597b65e4f07a",
    "trust": "9a92b456fa7b09313d985139f372cfd42662f7889fe8c083ec48e0a61b906a77",
    "matching": "f3856143930d9271b85536b37b494455f4b962d5b027030aecc2353742215ec2",
    "taxonomy": "0dd451bfb8939a98e0d1abd0ca4f28be54c0722e2fac076e74a3db8e3ce3b928",
}
EXPECTED_COMPONENT_PINS = {
    "iam": {
        "combined_sha256": IAM_COMBINED_SHA256,
        "head": 48,
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
        "head": 16,
        "head_sql_sha256": HEAD_SQL_SHA256["demand"],
        "manifest_sha256": DEMAND_MANIFEST_SHA256,
        "required_iam": 48,
    },
    "trust": {
        "combined_sha256": TRUST_COMBINED_SHA256,
        "head": 24,
        "head_sql_sha256": HEAD_SQL_SHA256["trust"],
        "manifest_sha256": TRUST_MANIFEST_SHA256,
        "required_demand": 16,
        "required_demand_sha256": DEMAND_DEPENDENCY_SHA256,
        "required_iam": 48,
        "required_iam_sha256": IAM_COMBINED_SHA256,
    },
    "matching": {
        "api_sha256": MATCHING_CONTRACT_SHA256["api"],
        "candidate_sha256": MATCHING_CONTRACT_SHA256["candidate"],
        "disclosure_sha256": MATCHING_CONTRACT_SHA256["disclosure"],
        "event_sha256": MATCHING_CONTRACT_SHA256["event"],
        "head": 11,
        "head_sql_sha256": HEAD_SQL_SHA256["matching"],
        "input_manifest_sha256": MATCHING_CONTRACT_SHA256["input_manifest"],
        "manifest_sha256": MATCHING_MANIFEST_SHA256,
        "required_iam": 48,
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
        "48",
        DEMAND_MANIFEST_SHA256,
        "48",
        "16",
        IAM_COMBINED_SHA256,
        DEMAND_DEPENDENCY_SHA256,
        TRUST_COMBINED_SHA256,
        TRUST_MANIFEST_SHA256,
        "48",
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
FROZEN_V28 = {'scripts/verify_current_head_v28.py': '01045dba7f5fcf3cf2b6633f25f8c886f68a8d1f8d5c0e40004f8992714f9f04', 'docs/operations/current-head-v28.md': '47a8c689e9601b1e88dd492e117692fd93c69dabc4cc35e8a3056d65ab29272d', 'tests/deployment/fixtures/current-head-v28/schema-pins.json': '2e4fb006b30daab03d06272b3811d5f1d75b10506070598373657d1306c5ae96', 'tests/deployment/fixtures/current-head-v28/matching-v3-manifest.json': 'b6c4169edcaf4c7cb771fde614ef72c3d90d56b4d2f4d5a0a633f8b634adbf18', 'deploy/postgres-backup-restore-v28.sh': 'af2fe4105600d439b196b59bb9def07cbe913cc296285bae34f22cfefe8d0f6a', 'deploy/postgres-core-facts-v28.sql': 'e5c1c7514a1db874fd4aaf6e61d6e486782b1d741ff35c00294c785d624c3d53', 'deploy/postgres-operations-v28.compose.yaml': '47567174216d101eddada34c78ca983172ec606b583047dc1855f6998537b0d1', 'tests/deployment/fixtures/current-head-v29/iam-manifest.json': 'faa540929a66eeb7ebfe86ca5e43539ef7dcb10424e792ded14252f27c5850a5', 'tests/deployment/fixtures/current-head-v29/trust-manifest.json': '3fd3089db8139f4e70551f59f8e803fdf2543847d38d08f82f8a050c2dd921e8', 'tests/deployment/fixtures/current-head-v29/matching-manifest.json': 'ff3453c1f86739684dbe255a6ae16a0b5839dacf7ba680b120a50b089aa260e2'}
FROZEN_V27 = {'scripts/verify_current_head_v27.py': '2b6202deb271802009a542edac4e5e12a994519416bc85394e59e7fe9d370b4f', 'docs/operations/current-head-v27.md': '39b5f18aaa8c70f96d9ac30643178248d073bd5d973fe5e35d8932bf998b04c1', 'tests/deployment/fixtures/current-head-v27/schema-pins.json': '94d9d11e40910d1c33802b433d5cbd0ac54f1f048f87235077061811e86fb65f', 'deploy/postgres-backup-restore-v27.sh': '038792a349e66952d2f1de580cb1c5bb66dbf5d6a92ff505e1d6ef6ed90ae8e5', 'deploy/postgres-core-facts-v27.sql': '0ecf5fedbebc7df874f7054ad70357f61ed9ebcc9d4894eb4f6971dd87ebcc45', 'deploy/postgres-operations-v27.compose.yaml': '45d050b0d072989747536eb05662590a161340ca49cde32e2db42fde03a2f68f'}
FROZEN_V26 = {'scripts/verify_current_head_v26.py': '4fc359fa3f1535d3a32d025a0d6f4b4c07b99eb916cf30f8bc2c0838115c25bf', 'docs/operations/current-head-v26.md': '238216f2756285057a1ee26be100a8f4d90bfee272e5a2c23840f1967083f280', 'tests/deployment/fixtures/current-head-v26/iam-manifest.json': '7edad01ff151168e4e048848fe770eb0ea199a1034a8119658a1c3bf53205b5e', 'tests/deployment/fixtures/current-head-v26/demand-manifest.json': '5663d8e14bb5fa6a5706828fe443a8c08ac2e62bad3e56403dd45bc6df939b29', 'tests/deployment/fixtures/current-head-v26/trust-manifest.json': '5949f7b630376a59c643f9024210625811606a1a41f90f4bc99ee19dfb99d38c', 'tests/deployment/fixtures/current-head-v26/trust-runner-pins.txt': '2c51f1df80ca8f3fcdca38c66b7d82fbc9a254744f69ba73ec9b0e54cd6c3f77', 'deploy/postgres-backup-restore-v26.sh': '48fe07e4a845738cd620b2584eae984d1a66d2258f6fc2c46b0ee63eaec2d72c', 'deploy/postgres-core-facts-v26.sql': '274cf10f533673a1541f9dd186039153605bc420f847fa14110027bd5650f153', 'deploy/postgres-operations-v26.compose.yaml': '7fc79306fce5feb2d985390ab6e8f6a77955a5ad7d53bb341e25c8ed0df1e041'}
FROZEN_V29 = {'scripts/verify_current_head_v29.py': '9a611dd89faa3525081f42a0a5372cdd8822ceb80bd926aa0442bb5bd8240f06', 'docs/operations/current-head-v29.md': '97b1d71be631a1fd448a2e9f745cce163dcfbf5986dd2e70bde30c2689575739', 'tests/deployment/fixtures/current-head-v29/schema-pins.json': 'c03dde74103405cb977e6161123fe4eda57db802659e30462d4f9d550739e76b', 'deploy/postgres-backup-restore-v29.sh': '2c4c0fd03ba4198649477f9b791ff5fd29e797f625c8fcd6b349de779e47e886', 'deploy/postgres-core-facts-v29.sql': '61d615cd176ffb03275132fcf55e3ad95c633033f791db81ff1b0717e3d3cc11', 'deploy/postgres-operations-v29.compose.yaml': 'f5a517210a377734e75ee8ba2b7128b76250a6a7afa2103a0d786fcf5ee79ca0', 'tests/deployment/fixtures/current-head-v30/iam-manifest.json': '257c438e1d44b385b47505e04f0eca001b41e5121a7f996f3f7e0d8b81d913da', 'tests/deployment/fixtures/current-head-v30/demand-manifest.json': '32d8587651d05e725a4277e2d253b8e195192f1dabc702dd5208b53fe8143f73', 'tests/deployment/fixtures/current-head-v30/trust-manifest.json': '0576a8872e2c9783e345d521f151b3d6f9bd7e1d9ee125ee1ef3810e01a05e47', 'tests/deployment/fixtures/current-head-v30/matching-manifest.json': '83547a319fb2d1e5cc88131570fc889ac795b0dd30643e9bca565058226f2cb6'}
MANIFESTS = {
    "iam": (
        "platform/src/desire_platform/identity_access/adapters/postgres/migrations",
        tuple(range(49)),
        IAM_MANIFEST_SHA256,
    ),
    "profile": (
        "platform/src/desire_platform/creator_profile/adapters/postgres/migrations",
        tuple(range(1, 6)),
        PROFILE_MANIFEST_SHA256,
    ),
    "demand": (
        "platform/src/desire_platform/demand/adapters/postgres/migrations",
        tuple(range(1, 17)),
        DEMAND_MANIFEST_SHA256,
    ),
    "trust": (
        "platform/src/desire_platform/trust_safety/adapters/postgres/migrations",
        tuple(range(1, 25)),
        TRUST_MANIFEST_SHA256,
    ),
    "matching": (
        "platform/src/desire_platform/matching/adapters/postgres/migrations",
        tuple(range(1, 12)),
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
        "matching": (
            "platform/src/desire_platform/matching/adapters/postgres/migrations/manifest.json",
            "tests/deployment/fixtures/current-head-v30/matching-manifest.json",
        ),
        "iam": (
            "platform/src/desire_platform/identity_access/adapters/postgres/migrations/manifest.json",
            "tests/deployment/fixtures/current-head-v30/iam-manifest.json",
        ),
        "demand": (
            "platform/src/desire_platform/demand/adapters/postgres/migrations/manifest.json",
            "tests/deployment/fixtures/current-head-v30/demand-manifest.json",
        ),
        "trust": (
            "platform/src/desire_platform/trust_safety/adapters/postgres/migrations/manifest.json",
            "tests/deployment/fixtures/current-head-v30/trust-manifest.json",
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
            failures.append(f"frozen-{component}-migration-prefix-drifted")
    if _sha(root / "tests/deployment/fixtures/current-head-v28/matching-v3-manifest.json") != (
        "b6c4169edcaf4c7cb771fde614ef72c3d90d56b4d2f4d5a0a633f8b634adbf18"
    ):
        failures.append("frozen-matching-v3-manifest-drifted")
    if _sha(root / "platform/src/desire_platform/matching/adapters/postgres/migrations/0004_expand__matching_ingest_name_resolution.sql") != (
        "9cd168affafd3d0006a991c803e8d1095b5193da5aea2464648db76b48802c8b"
    ):
        failures.append("frozen-matching4-sql-drifted")
    if _sha(root / "platform/src/desire_platform/matching/adapters/postgres/migrations/0005_expand__matching_coordinator_claim_scope.sql") != (
        "859f003a39317e4b496c4a29d493c0d282bc7e79fcb7736c2cf5700f35fd79c7"
    ):
        failures.append("frozen-matching5-sql-drifted")
    if _sha(root / "platform/src/desire_platform/matching/adapters/postgres/migrations/0006_expand__matching_review_claim_visibility.sql") != (
        "581d9f8e5394f67dba1b659807870c857b84a5ef4464d0197ce7370f611eb499"
    ):
        failures.append("frozen-matching6-sql-drifted")
    if _sha(root / "platform/src/desire_platform/matching/adapters/postgres/migrations/0007_expand__matching_create_invitation_receipt_probe.sql") != (
        "0037718c52ee0d30e6787031ef8a46be7cfddc9847167bb47295c3a0b5b1e649"
    ):
        failures.append("frozen-matching7-sql-drifted")
    if _sha(root / "platform/src/desire_platform/matching/adapters/postgres/migrations/0008_expand__matching_disclosure_utc_timestamp.sql") != (
        "4059c3b2f13bbd5a5a1b51b20becc3fc385a8509dc20f5cd886f6c56585bf8c2"
    ):
        failures.append("frozen-matching8-sql-drifted")
    return tuple(failures)


def _operations_failures(script: str, facts: str, overlay: str) -> tuple[str, ...]:
    failures: list[str] = []
    expected_overlay = """configs:
  postgres-backup-restore-script:
    file: ./deploy/postgres-backup-restore-v30.sh
  postgres-core-facts-sql:
    file: ./deploy/postgres-core-facts-v30.sql
"""
    if overlay != expected_overlay:
        failures.append("postgres-operations-v30-overlay-open")
    if f"EXPECTED_PINS='{HEADS}'" not in script:
        failures.append("postgres-operations-v30-heads-open")
    if f"EXPECTED_CONTRACTS='{EXPECTED_CONTRACTS}'" not in script:
        failures.append("postgres-operations-v30-contracts-open")
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
            failures.append("postgres-operations-v30-matching-contract-open")
            break
    for table in MATCHING_TABLES:
        qualified = f"matching.{table}"
        if script.count(qualified) != 1 or facts.count(qualified) != 1:
            failures.append("postgres-operations-v30-matching-continuity-open")
            break
    for forbidden in (
        "creator_user_id",
        "reviewer_user_id",
        "candidate_id",
        "safe_response_body",
        "canonical_result_bytes",
    ):
        if forbidden in facts:
            failures.append("postgres-operations-v30-facts-privacy-open")
            break
    return _unique(failures)


def _runbook_failures(value: str) -> tuple[str, ...]:
    begin = "<!-- BEGIN CURRENT_HEAD_V30_CONTRACT -->"
    end = "<!-- END CURRENT_HEAD_V30_CONTRACT -->"
    failures: list[str] = []
    if (
        value.count(begin) != 1
        or value.count(end) != 1
        or value.find(begin) >= value.find(end)
    ):
        failures.append("current-head-v30-markers-open")
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
        "Matching v1-v11 的 27 张 durable domain tables",
        "matching_continuity_counts",
        "STATIC VERIFIED / NOT PRODUCTION EXECUTED",
        '"production_authorized":false',
        "postgres-operations-v30.compose.yaml",
        "v30-iam48-profile5-demand16-trust24-matching11-taxonomy2-drill01",
    ):
        if marker not in value:
            failures.append("current-head-v30-runbook-contract-open")
            break
    return _unique(failures)


def verify_repository(root: Path = REPOSITORY_ROOT) -> tuple[str, ...]:
    failures: list[str] = []
    fixture_path = root / "tests/deployment/fixtures/current-head-v30/schema-pins.json"
    fixture_bytes = _bytes(fixture_path)
    fixture = _json(fixture_path)
    if not isinstance(fixture, dict) or fixture_bytes is None:
        failures.append("current-head-v30-fixture-open")
    else:
        canonical = (
            json.dumps(fixture, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
            .encode("ascii")
            + b"\n"
        )
        if fixture_bytes != canonical:
            failures.append("current-head-v30-fixture-canonical-open")
        if (
            fixture.get("heads") != HEADS
            or fixture.get("claim") != "STATIC_ONLY"
            or fixture.get("status") != "NOT_PRODUCTION_EXECUTED"
            or fixture.get("production_authorized") is not False
        ):
            failures.append("current-head-v30-fixture-claim-open")
        if fixture.get("components") != EXPECTED_COMPONENT_PINS:
            failures.append("current-head-v30-fixture-pins-open")

    if "__MATCHING_V4_" in "\n".join(
        (
            MATCHING_MANIFEST_SHA256,
            _read(fixture_path),
            _read(root / "deploy/postgres-backup-restore-v30.sh"),
            _read(root / "docs/operations/current-head-v30.md"),
        )
    ):
        failures.append("current-head-v30-matching-pins-open")

    failures.extend(_manifest_failures(root))
    failures.extend(_historical_prefix_failures(root))
    for relative, expected in {**FROZEN_V26, **FROZEN_V27, **FROZEN_V28, **FROZEN_V29}.items():
        if _sha(root / relative) != expected:
            failures.append(f"frozen-current-head-history-drifted:{relative}")

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
        "demand": ("DEMAND_REQUIRED_IAM_SCHEMA_VERSION = 48",),
        "trust": (
            "TRUST_REQUIRED_IAM_SCHEMA_VERSION = 48",
            "TRUST_REQUIRED_DEMAND_SCHEMA_VERSION = 16",
            IAM_COMBINED_SHA256,
            DEMAND_DEPENDENCY_SHA256,
            TRUST_COMBINED_SHA256,
        ),
        "matching": (
            "MATCHING_REQUIRED_IAM_SCHEMA_VERSION = 48",
            "MATCHING_REQUIRED_TRUST_SCHEMA_VERSION = 24",
            TRUST_COMBINED_SHA256,
            TRUST_MANIFEST_SHA256,
        ),
    }.items():
        if any(marker not in runner_sources[name] for marker in markers):
            failures.append(f"{name}-dependency-pin-open")

    failures.extend(
        _operations_failures(
            _read(root / "deploy/postgres-backup-restore-v30.sh"),
            _read(root / "deploy/postgres-core-facts-v30.sql"),
            _read(root / "deploy/postgres-operations-v30.compose.yaml"),
        )
    )
    failures.extend(
        _runbook_failures(_read(root / "docs/operations/current-head-v30.md"))
    )

    sidebar = _read(root / "docs/_sidebar.md")
    for marker in (
        "[Current-head v30 静态模式头](/operations/current-head-v30.md)",
        "[Current-head v27 静态模式头](/operations/current-head-v27.md)",
    ):
        if marker not in sidebar:
            failures.append("current-head-v30-sidebar-open")
            break

    invocation_v27 = "python -B scripts/verify_current_head_v27.py"
    invocation_v30 = "python -B scripts/verify_current_head_v30.py"
    for relative in (
        ".github/workflows/ci.yml",
        ".github/workflows/private-server-runtime-release.yml",
    ):
        source = _read(root / relative)
        if source.count(invocation_v27) != 0 or source.count(invocation_v30) != 1:
            failures.append("current-head-v30-workflow-pointer-open")
            break

    readiness = _read(root / "scripts/check_private_server_source_readiness.py")
    for relative in (
        "deploy/postgres-backup-restore.sh",
        "deploy/postgres-core-facts.sql",
        "deploy/postgres-operations.compose.yaml",
        "docs/operations/current-head-v30.md",
        "deploy/postgres-backup-restore-v30.sh",
        "deploy/postgres-core-facts-v30.sql",
        "deploy/postgres-operations-v30.compose.yaml",
        "scripts/verify_current_head_v30.py",
        "tests/deployment/fixtures/current-head-v30/schema-pins.json",
        "tests/deployment/fixtures/current-head-v28/matching-v3-manifest.json",
        "tests/deployment/test_current_head_v30_contract.py",
        "tests/deployment/test_postgres_operations_v30.py",
    ):
        if relative not in readiness:
            failures.append("current-head-v30-source-readiness-open")
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
        "current-head v30",
        "IAM48/Profile5/Demand16/Trust24/Matching11/Taxonomy2",
        "verify_current_head_v30.py",
        "postgres-operations-v30.compose.yaml",
    ):
        if marker not in operations_summary:
            failures.append("current-head-v30-live-operations-pointer-open")
            break

    if (
        _bytes(root / "deploy/postgres-backup-restore.sh")
        != _bytes(root / "deploy/postgres-backup-restore-v30.sh")
        or _bytes(root / "deploy/postgres-core-facts.sql")
        != _bytes(root / "deploy/postgres-core-facts-v30.sql")
    ):
        failures.append("current-head-v30-unversioned-operations-pointer-open")

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
