#!/usr/bin/env python3
"""Read-only verifier for the IAM42 / Demand12 / Trust18 static head."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Iterable


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
HEADS = "18|42|42|3|3|12|12|18|18|2|2"
IAM_API_SHA256 = "26ffd8243c0baa2580d21e8878897ed0f13aa61fd9ba468cca8edf1fe277477c"
IAM_EVENT_SHA256 = "6af7e75f738bfeef9aeed0ac8e84da782485c1a42e1c937c9d51e66884bad934"
IAM_MANIFEST_SHA256 = "9c6e0396867d68ac49260684a9531c592055d62cac20d7ebdfb578c236df025d"
IAM_COMBINED_SHA256 = "f88bf5f70343edbf06e55c0641b61b58cff27fda48ce00f6489e3f3f80db5a9e"
IAM_SQL_SHA256 = "1d0c1391f08ba47f0af29d9941634a4f522c0d0c48e0c5747edbed16e4b02f44"
PROFILE_MANIFEST_SHA256 = "4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa"
DEMAND_MANIFEST_SHA256 = "919d62a9b32dc29619a561940f9c79e21700562a0cdd9ef7e9f13a40cea43345"
DEMAND_DEPENDENCY_SHA256 = "379b6cb8b05f7da03905e644d158cfb6ad03409f290d33f63ae80183d428f816"
DEMAND_SQL_SHA256 = "bf76efd70f95a4fa4c49ad43ad03fc9d31e5009bce88364bec851f68b0313280"
TRUST_API_SHA256 = "6647e16e9f8f0ab321ed9985eb2da4e591e2217fdaa43ba663355a4f152f44b2"
TRUST_APPEAL_API_SHA256 = "ad0fd5874ad6d3343c62334805fe51c088df7b9db9215decfda95ee90a836e46"
TRUST_SQL_SHA256 = "8623df4ffbd74f360a67fcc05a2a9d3966269458264b042ae10d6f1fd0784c0e"
TRUST_MANIFEST_SHA256 = "0b7028c75c8f137bc4a55a76fe73ea956d0c5ada13031f80794b77c1c9535e19"
TRUST_COMBINED_SHA256 = "639100c2fd347cdc38e9d9d52686f1a95c17cdcca2fbabe506832d30fad495b1"
TAXONOMY_MANIFEST_SHA256 = "74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622"
HTTP_OBSERVABILITY_SHA256 = "49c06c6882cc2a4fdf8c00922bc77166ad65f39a7f93c0f84b6cf6e104fd99ff"
HTTP_OBSERVABILITY_TEST_SHA256 = "f28bec3d399488c1fd1921210c0f0ba78b1294908d38003f1f28620b5729c59b"
API_COMPOSITION_SHA256 = "629b3f43490386baa9c328a3c002ad1910dfc34186b41febee4e33926e00e25f"
API_COMPOSITION_TEST_SHA256 = "5de0d58517d245145a5b9ec52d27856a588d3eee854653b7457efb24881c31f1"
RUNTIME_ADAPTERS_SHA256 = "9e4d9cb304fe87864d946ad8addf1cff5eefc1ecae767990529b8859eaac720b"
API_SERVER_SHA256 = "9668d5fb24ef9fe1c1c6fcff19cc8e58a433461a372124b5f2e74404faac5fc2"
API_SERVER_TEST_SHA256 = "62d0b29bd701ed0993cdd8cfb0ac0b38b52b432ea66832cd00e95a714dd363cb"
COMPOSE_SHA256 = "0ee95ec9c638ff24e1caa64a50d8088ef6834b10e9654d70ddb65a569d0b9c41"
COMPOSE_DEV_SHA256 = "26794d230babeedc220da1bcbf4decd3b25fa0566ecb0699e53b136cd98b9ad1"
OPERATIONS_COMPOSE_SHA256 = "ef51b6a0c0163c0b46714266b2ed47394fe27077086d0ebe25e137618d96c52b"
REAL_OIDC_COMPOSE_SHA256 = "342f5cc9837d3452254296194e3d7aec62470acf1ea1c934e765ba14e1ef564c"
CONTAINER_VERIFIER_SHA256 = "a6eb67b2f881771c26188a377fa0203a4791676e74059f68f3fcfcde9f524f9d"
LOCAL_MANAGER_SHA256 = "1b8bcaa66dcf26484f6d1332a89895b3d47bb74d997e49908ab463395197fad9"
PRIVATE_COMPOSE_CONTRACT_SHA256 = "d9b154319b0b9c094848e1f6e2732bcbf715665ce03a969f3a549f1ebee19e58"
REAL_OIDC_CONTRACT_SHA256 = "275af01035420b1d81c60610f18c716624dbc1e99d4c18d3b127b6e9f798e957"
CONTAINER_TEST_SHA256 = "d3dc09fbe1334061e21c5d2c5a5afb42b9e833dd0d8144c885c10a55c404ae7f"
PRIVATE_COMPOSE_TEST_SHA256 = "80d1b476c38ef3424ea166066a4073492de66547d7a4fd33f3fbef092c4c54b3"
LOCAL_MANAGER_TEST_SHA256 = "6ab92bd2a874f84289480af43147f406b115c5cfd9aefdf73e0b71d5e2571556"
REAL_OIDC_TEST_SHA256 = "9ef6c57da2d4379c24b489b53eeaf88cc589634ca0f0e8a6210da0df37e5620f"
POSTGRES_OPERATIONS_TEST_SHA256 = "03fff4947a73a044d990a05b6d8fd6dc1c23bd38f864d71b33dc407be8185207"
POSTGRES_OPERATIONS_V25_SCRIPT_SHA256 = (
    "9aa84d3f7d37704e181a314db873e16fecfad6d770dbc1d12fbb76180d69d1bb"
)
POSTGRES_OPERATIONS_V25_FACTS_SHA256 = (
    "0845ec9025efdfc208bab24b1ce3b8f56a8e2e44613eae249a00af349802507e"
)
POSTGRES_OPERATIONS_V25_OVERLAY_SHA256 = (
    "a98b80de17604349362b813d1224a4f71d886b2d1282f9cbb944cd3b714628a4"
)
POSTGRES_OPERATIONS_V25_TEST_SHA256 = (
    "5296e02cf37a5ffdf54603639202e6f074138706832d811355ded15efe3da383"
)
POSTGRES_OPERATIONS_V15_PINS = "18|38|38|3|3|10|10|9|9|2|2"
POSTGRES_OPERATIONS_V15_CONTRACTS = (
    "908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e|"
    "4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa|"
    "7695127a039fa71cddabd62318bea39337e3acbb4b1df66a3557b7a7ae3707b4|"
    "38|10|"
    "908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e|"
    "27ec6b585a9340cbd7119d7a9b46d6098a3881f88ae1be9e00df3713c0107113|"
    "43765a3739716819c1bfc8df9625a3011534ae23aa647bf3bdaea90945e7bef9|"
    "8ef9c2321866e7509bf1a959acf64370fe74abb927635c0434618287a4348171|"
    "74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622"
)
EXPECTED_POSTGRES_OPERATIONS_V25_OVERLAY = """configs:
  postgres-backup-restore-script:
    file: ./deploy/postgres-backup-restore-v25.sh
  postgres-core-facts-sql:
    file: ./deploy/postgres-core-facts-v25.sql
"""
POSTGRES_OPERATIONS_V25_EMPTY_TARGET_TABLES = (
    "iam.external_identities",
    "iam.contact_points",
    "iam.organizations",
    "iam.auth_transactions",
    "iam.session_families",
    "iam.session_security_events",
    "iam.user_role_grants",
    "iam.membership_role_grants",
    "iam.platform_duty_grants",
    "iam.consent_grants",
    "iam.consent_grant_data_categories",
    "iam.consent_withdrawals",
    "infra.command_receipts",
    "infra.iam_sandbox_bootstrap_state",
    "infra.iam_sandbox_bootstrap_accounts",
    "infra.iam_sandbox_bootstrap_runs",
    "infra.iam_sandbox_bootstrap_manifest_bridges",
)
POSTGRES_OPERATIONS_V25_DURABLE_FACT_TABLES = tuple(
    table
    for table in POSTGRES_OPERATIONS_V25_EMPTY_TARGET_TABLES
    if table != "iam.user_role_grants"
)
POSTGRES_OPERATIONS_V25_EXCLUDED_CATALOG_TABLES = (
    "iam.policy_selectors",
    "iam.policy_documents",
    "iam.policy_bundles",
    "iam.policy_bundle_documents",
    "iam.consent_offers",
    "iam.consent_offer_data_categories",
    "infra.consumer_principals",
    "infra.iam_receipt_key_policy",
    "infra.schema_migrations",
    "infra.iam_schema_contracts",
)
EXPECTED_CONTRACTS = "|".join((
    IAM_COMBINED_SHA256,
    PROFILE_MANIFEST_SHA256,
    DEMAND_MANIFEST_SHA256,
    "42",
    "12",
    IAM_COMBINED_SHA256,
    DEMAND_DEPENDENCY_SHA256,
    TRUST_COMBINED_SHA256,
    TRUST_MANIFEST_SHA256,
    TAXONOMY_MANIFEST_SHA256,
))
SUCCESS = '{"status":"CURRENT_HEAD_V25_STATIC_VERIFIED"}'


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


def _manifest_versions(path: Path, component: str) -> tuple[int, ...]:
    try:
        value = json.loads(_read(path))
        return tuple(
            item["version"] for item in value if item["component"] == component
        )
    except (KeyError, TypeError, json.JSONDecodeError):
        return ()


def _iam_combined(root: Path) -> str | None:
    api = _bytes(root / "platform/contracts/api/iam-v1.openapi.yaml")
    event = _bytes(root / "platform/contracts/events/iam-v1.schema.json")
    if api is None or event is None:
        return None
    return hashlib.sha256(
        b"iam-v1-contract"
        + b"\x00"
        + hashlib.sha256(api).digest()
        + hashlib.sha256(event).digest()
        + bytes.fromhex(IAM_MANIFEST_SHA256)
    ).hexdigest()


def _runbook_failures(value: str) -> tuple[str, ...]:
    begin = "<!-- BEGIN CURRENT_HEAD_V25_CONTRACT -->"
    end = "<!-- END CURRENT_HEAD_V25_CONTRACT -->"
    if (
        value.count(begin) != 1
        or value.count(end) != 1
        or value.find(begin) >= value.find(end)
    ):
        return ("current-head-v25-markers-open",)
    required = (
        HEADS,
        EXPECTED_CONTRACTS,
        IAM_SQL_SHA256,
        IAM_MANIFEST_SHA256,
        DEMAND_SQL_SHA256,
        TRUST_SQL_SHA256,
        "ORG_ADMIN",
        "UpdateOrganizationPublicName",
        "public-name correction",
        "canonical public_name",
        "six-command idempotency",
        "If-Match",
        "Idempotency-Key",
        "Cc / Cf / NFC",
        "412 PRECONDITION_FAILED",
        "current ETag",
        "OrganizationPublicNameChanged",
        "audit/event name privacy",
        "anonymous invitation preview",
        "bootstrap v6",
        "custom public_name",
        "receipt replay",
        "FINANCE_OPERATOR",
        "my completed funding reviews",
        "actor-bound cursor",
        "own confirmation or own finding",
        "SECURED / DISCREPANCY / REJECTED",
        "TRUST_OFFICER",
        "/v1/app/trust/history",
        "party-safe",
        "has_more",
        "trust_officer_01",
        "trust_officer_02",
        "trust_terminal_history_discoverable",
        "APPEAL_REVIEWER",
        "/v1/app/appeal-review/history",
        "VIEW_APPEAL_REVIEW_HISTORY",
        "我的已完成申诉复核",
        "fresh exact terminal detail",
        "actor-bound",
        "party-safe",
        "terminal_history_actor_scoped",
        "HTTP_BOUNDARY_OBSERVATION_V1",
        "low-cardinality",
        "raw path/query/header/body",
        "observer failure",
        "access_log=False",
        "driver=local",
        "max-size=10m",
        "max-file=3",
        "compress=true",
        "DOCKER_LOG_CONFIG",
        HTTP_OBSERVABILITY_SHA256,
        COMPOSE_SHA256,
        CONTAINER_VERIFIER_SHA256,
        "writer quiescence",
        "READ ONLY",
        "STATIC VERIFIED",
        "NOT EXECUTED",
        "production_authorized=false",
        "tests/deployment/fixtures/current-head-v25/",
        "tests/deployment/fixtures/current-head-v24/",
        "18|42|42|3|3|12|12|18|18|2|2",
        "current-head-v24.md",
        "python3 -B scripts/verify_current_head_v25.py",
        "deploy/postgres-backup-restore-v25.sh",
        "deploy/postgres-core-facts-v25.sql",
        "deploy/postgres-operations-v25.compose.yaml",
        "iam_durable_counts",
        "compose_v25_operations",
        "v25-iam42-profile3-demand12-trust18-taxonomy2-drill01",
        "DATABASE_BACKUP_READY",
        "DATABASE_RESTORE_VERIFIED",
        "three Compose files",
        "not comprehensive field-level continuity",
    )
    if any(marker not in value for marker in required):
        return ("current-head-v25-contract-open",)
    return ()


def _postgres_operations_v25_failures(
    v15_script: str,
    v25_script: str,
    base_facts: str,
    v25_facts: str,
    overlay: str,
) -> tuple[str, ...]:
    failures: list[str] = []
    if overlay != EXPECTED_POSTGRES_OPERATIONS_V25_OVERLAY:
        failures.append("postgres-operations-v25-overlay-open")
    if (
        f"EXPECTED_PINS='{POSTGRES_OPERATIONS_V15_PINS}'" not in v15_script
        or f"EXPECTED_CONTRACTS='{POSTGRES_OPERATIONS_V15_CONTRACTS}'"
        not in v15_script
    ):
        failures.append("postgres-operations-v15-history-drifted")
    if (
        f"EXPECTED_PINS='{HEADS}'" not in v25_script
        or f"EXPECTED_CONTRACTS='{EXPECTED_CONTRACTS}'" not in v25_script
    ):
        failures.append("postgres-operations-v25-pins-open")
    normalized = v25_script.replace(HEADS, POSTGRES_OPERATIONS_V15_PINS).replace(
        EXPECTED_CONTRACTS,
        POSTGRES_OPERATIONS_V15_CONTRACTS,
    )
    required_facts_marker = '        \'"iam_durable_counts"\' \\\n'
    if normalized.count(required_facts_marker) != 1:
        failures.append("postgres-operations-v25-facts-marker-open")
    else:
        normalized = normalized.replace(required_facts_marker, "", 1)
    for table in POSTGRES_OPERATIONS_V25_EMPTY_TARGET_TABLES:
        line = f"                (SELECT count(*) FROM {table}) +\n"
        if normalized.count(line) != 1:
            failures.append("postgres-operations-v25-empty-target-open")
        else:
            normalized = normalized.replace(line, "", 1)
    if any(
        table in v25_script
        for table in POSTGRES_OPERATIONS_V25_EXCLUDED_CATALOG_TABLES
    ):
        failures.append("postgres-operations-v25-seeded-catalog-open")
    if normalized != v15_script:
        failures.append("postgres-operations-v25-clone-drifted")

    start_marker = "    'iam_durable_counts', jsonb_build_object(\n"
    end_marker = "    'core_counts', jsonb_build_object(\n"
    if v25_facts.count(start_marker) != 1 or v25_facts.count(end_marker) != 1:
        failures.append("postgres-operations-v25-durable-facts-open")
    else:
        start = v25_facts.index(start_marker)
        end = v25_facts.index(end_marker, start)
        durable_projection = v25_facts[start:end]
        relations = set(
            re.findall(r"FROM ([a-z_]+\.[a-z_]+)", durable_projection)
        )
        if relations != set(POSTGRES_OPERATIONS_V25_DURABLE_FACT_TABLES):
            failures.append("postgres-operations-v25-durable-facts-open")
        if any(
            durable_projection.count(f"FROM {table}") != 1
            for table in POSTGRES_OPERATIONS_V25_DURABLE_FACT_TABLES
        ):
            failures.append("postgres-operations-v25-durable-facts-open")
        if any(
            table in durable_projection
            for table in POSTGRES_OPERATIONS_V25_EXCLUDED_CATALOG_TABLES
        ):
            failures.append("postgres-operations-v25-seeded-catalog-open")
        if v25_facts[:start] + v25_facts[end:] != base_facts:
            failures.append("postgres-operations-v25-facts-clone-drifted")
    return _unique(failures)


def verify_repository(root: Path = REPOSITORY_ROOT) -> tuple[str, ...]:
    root = Path(root)
    failures: list[str] = []
    iam_root = (
        root
        / "platform/src/desire_platform/identity_access/adapters/postgres/migrations"
    )
    profile_root = (
        root
        / "platform/src/desire_platform/creator_profile/adapters/postgres/migrations"
    )
    demand_root = (
        root / "platform/src/desire_platform/demand/adapters/postgres/migrations"
    )
    trust_root = (
        root
        / "platform/src/desire_platform/trust_safety/adapters/postgres/migrations"
    )
    taxonomy_root = (
        root / "platform/src/desire_platform/taxonomy/adapters/postgres/migrations"
    )
    fixture_root = root / "tests/deployment/fixtures/current-head-v25"
    v24_root = root / "tests/deployment/fixtures/current-head-v24"
    assets = (
        (fixture_root / "iam-manifest.json", IAM_MANIFEST_SHA256),
        (fixture_root / "demand-manifest.json", DEMAND_MANIFEST_SHA256),
        (fixture_root / "trust-manifest.json", TRUST_MANIFEST_SHA256),
        (
            fixture_root / "trust-runner-pins.txt",
            "91b0381051753738e045ff6c019fb30757adfcf588bf3c45bc336c56c74678d0",
        ),
        (iam_root / "manifest.json", IAM_MANIFEST_SHA256),
        (iam_root / "0042_expand__organization_public_name_management.sql", IAM_SQL_SHA256),
        (profile_root / "manifest.json", PROFILE_MANIFEST_SHA256),
        (demand_root / "manifest.json", DEMAND_MANIFEST_SHA256),
        (demand_root / "0012_expand__finance_funding_terminal_history.sql", DEMAND_SQL_SHA256),
        (trust_root / "manifest.json", TRUST_MANIFEST_SHA256),
        (trust_root / "0018_expand__completed_appeal_review_history.sql", TRUST_SQL_SHA256),
        (taxonomy_root / "manifest.json", TAXONOMY_MANIFEST_SHA256),
        (root / "platform/contracts/api/iam-v1.openapi.yaml", IAM_API_SHA256),
        (root / "platform/contracts/events/iam-v1.schema.json", IAM_EVENT_SHA256),
        (root / "platform/contracts/api/trust-v1.openapi.yaml", TRUST_API_SHA256),
        (
            root / "platform/contracts/api/appeal-v1.openapi.yaml",
            TRUST_APPEAL_API_SHA256,
        ),
        (
            v24_root / "iam-manifest.json",
            IAM_MANIFEST_SHA256,
        ),
        (
            v24_root / "demand-manifest.json",
            "919d62a9b32dc29619a561940f9c79e21700562a0cdd9ef7e9f13a40cea43345",
        ),
        (
            v24_root / "trust-manifest.json",
            "0b7028c75c8f137bc4a55a76fe73ea956d0c5ada13031f80794b77c1c9535e19",
        ),
        (
            v24_root / "trust-runner-pins.txt",
            "91b0381051753738e045ff6c019fb30757adfcf588bf3c45bc336c56c74678d0",
        ),
        (
            root / "scripts/verify_current_head_v24.py",
            "c80a30558111792762f9a4afd44cf4e416fa9c56ebc413402cabc21b684a394a",
        ),
        (
            root / "docs/operations/current-head-v24.md",
            "b479dc68c6388bd61c4e65fce4c5300a691af03c73f1ae78eae355e6cb3796c1",
        ),
        (
            root / "platform/src/desire_platform/http/observability.py",
            HTTP_OBSERVABILITY_SHA256,
        ),
        (
            root / "platform/tests/internal_pilot/test_http_observability_red.py",
            HTTP_OBSERVABILITY_TEST_SHA256,
        ),
        (
            root / "platform/src/desire_platform/internal_pilot/api_composition.py",
            API_COMPOSITION_SHA256,
        ),
        (
            root / "platform/tests/internal_pilot/test_api_composition_red.py",
            API_COMPOSITION_TEST_SHA256,
        ),
        (
            root / "platform/src/desire_platform/internal_pilot/runtime_adapters.py",
            RUNTIME_ADAPTERS_SHA256,
        ),
        (
            root / "platform/src/desire_platform/internal_pilot/api_server.py",
            API_SERVER_SHA256,
        ),
        (
            root / "platform/tests/internal_pilot/test_api_server_red.py",
            API_SERVER_TEST_SHA256,
        ),
        (root / "compose.yaml", COMPOSE_SHA256),
        (root / "compose.dev.yaml", COMPOSE_DEV_SHA256),
        (
            root / "deploy/postgres-operations.compose.yaml",
            OPERATIONS_COMPOSE_SHA256,
        ),
        (
            root / "deploy/private-server-real-oidc.compose.yaml",
            REAL_OIDC_COMPOSE_SHA256,
        ),
        (
            root / "scripts/verify_container_stack.py",
            CONTAINER_VERIFIER_SHA256,
        ),
        (
            root / "scripts/manage_local_internal_sandbox.py",
            LOCAL_MANAGER_SHA256,
        ),
        (
            root / "scripts/private_server_compose_contract.py",
            PRIVATE_COMPOSE_CONTRACT_SHA256,
        ),
        (
            root / "scripts/private_server_real_oidc_compose_contract.py",
            REAL_OIDC_CONTRACT_SHA256,
        ),
        (
            root / "tests/deployment/test_container_stack.py",
            CONTAINER_TEST_SHA256,
        ),
        (
            root / "tests/deployment/test_private_server_compose_contract.py",
            PRIVATE_COMPOSE_TEST_SHA256,
        ),
        (
            root / "tests/deployment/test_local_internal_sandbox_manager.py",
            LOCAL_MANAGER_TEST_SHA256,
        ),
        (
            root / "tests/deployment/test_private_server_real_oidc_compose.py",
            REAL_OIDC_TEST_SHA256,
        ),
        (
            root / "tests/deployment/test_postgres_operations.py",
            POSTGRES_OPERATIONS_TEST_SHA256,
        ),
        (
            root / "deploy/postgres-backup-restore-v25.sh",
            POSTGRES_OPERATIONS_V25_SCRIPT_SHA256,
        ),
        (
            root / "deploy/postgres-core-facts-v25.sql",
            POSTGRES_OPERATIONS_V25_FACTS_SHA256,
        ),
        (
            root / "deploy/postgres-operations-v25.compose.yaml",
            POSTGRES_OPERATIONS_V25_OVERLAY_SHA256,
        ),
        (
            root / "tests/deployment/test_postgres_operations_v25.py",
            POSTGRES_OPERATIONS_V25_TEST_SHA256,
        ),
    )
    for path, expected in assets:
        if _sha(path) != expected:
            failures.append(
                f"current-head-v25-asset-mismatch:{path.relative_to(root)}"
            )

    if _manifest_versions(fixture_root / "iam-manifest.json", "iam") != tuple(
        range(43)
    ):
        failures.append("current-head-v25-iam-sequence-open")
    if _manifest_versions(
        fixture_root / "demand-manifest.json", "demand"
    ) != tuple(range(1, 13)):
        failures.append("current-head-v25-demand-sequence-open")
    if _manifest_versions(
        fixture_root / "trust-manifest.json", "trust"
    ) != tuple(range(1, 19)):
        failures.append("current-head-v25-trust-sequence-open")
    if _iam_combined(root) != IAM_COMBINED_SHA256:
        failures.append("current-head-v25-iam-combined-open")

    failures.extend(
        _postgres_operations_v25_failures(
            _read(root / "deploy/postgres-backup-restore-v15.sh"),
            _read(root / "deploy/postgres-backup-restore-v25.sh"),
            _read(root / "deploy/postgres-core-facts.sql"),
            _read(root / "deploy/postgres-core-facts-v25.sql"),
            _read(root / "deploy/postgres-operations-v25.compose.yaml"),
        )
    )

    iam_catalog = _read(iam_root / "catalog.py")
    trust_catalog = _read(trust_root / "catalog.py")
    trust_runner = _read(trust_root / "runner.py")
    frozen_runner = _read(fixture_root / "trust-runner-pins.txt")
    for source, markers, failure in (
        (
            iam_catalog,
            ("organization_public_name_management", IAM_MANIFEST_SHA256),
            "current-head-v25-iam-catalog-open",
        ),
        (
            _read(demand_root / "catalog.py"),
            ("finance_funding_terminal_history", DEMAND_MANIFEST_SHA256),
            "current-head-v25-demand-catalog-open",
        ),
        (
            trust_catalog,
            ("completed_appeal_review_history", TRUST_MANIFEST_SHA256),
            "current-head-v25-trust-catalog-open",
        ),
        (
            trust_runner,
            (
                "TRUST_REQUIRED_IAM_SCHEMA_VERSION = 42",
                "TRUST_REQUIRED_DEMAND_SCHEMA_VERSION = 12",
                IAM_COMBINED_SHA256,
                DEMAND_DEPENDENCY_SHA256,
                TRUST_API_SHA256,
                TRUST_APPEAL_API_SHA256,
                TRUST_COMBINED_SHA256,
            ),
            "current-head-v25-trust-runner-open",
        ),
        (
            frozen_runner,
            (
                "TRUST_REQUIRED_IAM_SCHEMA_VERSION = 42",
                "TRUST_REQUIRED_DEMAND_SCHEMA_VERSION = 12",
                IAM_COMBINED_SHA256,
                DEMAND_DEPENDENCY_SHA256,
                TRUST_API_SHA256,
                TRUST_APPEAL_API_SHA256,
                TRUST_COMBINED_SHA256,
            ),
            "current-head-v25-frozen-runner-open",
        ),
    ):
        if any(marker not in source for marker in markers):
            failures.append(failure)

    public_name_sql = _read(
        iam_root / "0042_expand__organization_public_name_management.sql"
    )
    migration_static_tests = _read(
        root
        / "platform/tests/storage/postgres/"
        "test_iam42_organization_public_name_migration_static.py"
    )
    postgres_tests = _read(
        root
        / "platform/tests/storage/postgres/"
        "test_iam42_organization_public_name_postgres.py"
    )
    application_tests = _read(
        root / "platform/tests/application/test_organization_profile.py"
    )
    http_tests = _read(
        root / "platform/tests/http/test_iam_http_transport_red.py"
    )
    contract_tests = _read(
        root / "platform/tests/contract/test_iam_contracts.py"
    )
    public_name_adapter = _read(
        root
        / "platform/src/desire_platform/identity_access/adapters/postgres/"
        "organization_public_name.py"
    )
    web_contract_tests = _read(root / "web/tests/org-admin-contract.test.mjs")
    web_ui_tests = _read(root / "web/tests/org-admin-ui.test.mjs")
    e2e_runner = _read(root / "scripts/run_internal_sandbox_e2e.py")
    e2e_tests = _read(root / "tests/deployment/test_four_role_e2e_runner.py")
    for source, markers in (
        (
            public_name_sql,
            (
                "iam.organization_public_name_is_canonical_v1",
                "TO iam_app, iam_onboarding, iam_system",
                "iam_api.execute_organization_admin_v3",
                "uq_org_admin_raw_idempotency_key_v1",
                "UpdateOrganizationPublicName",
                "PUBLIC_NAME_CORRECTION",
                "OrganizationPublicNameChanged",
                "'current_entity_tag'",
                "event_payload := jsonb_build_object",
                "manage_internal_sandbox_identity_bootstrap_v6",
                "saved_names",
                "SECURITY DEFINER",
                "REVOKE ALL ON FUNCTION",
            ),
        ),
        (
            migration_static_tests,
            (
                "test_v3_is_v2_abi_plus_one_final_text_and_closes_v2",
                "test_new_branch_is_atomic_digest_only_and_six_command_unique",
                "test_bootstrap_v6_restores_names_and_is_the_only_callable_head",
            ),
        ),
        (
            postgres_tests,
            (
                "test_db_canonicalizer_matches_closed_application_examples",
                "test_authority_update_replay_occ_and_cross_operation_receipt",
                "test_concurrent_six_command_raw_key_has_one_atomic_winner",
                "test_bootstrap_v6_replay_and_verify_never_overwrite_custom_names",
            ),
        ),
        (
            application_tests,
            (
                "test_public_name_command_is_frozen_closed_and_secret_safe",
                "test_public_name_command_rejects_noncanonical_or_open_inputs",
            ),
        ),
        (
            http_tests,
            (
                "test_public_name_body_is_exact_nfc_and_rejects_unicode_controls",
                "test_typed_stale_precondition_alone_carries_current_etag",
            ),
        ),
        (contract_tests, ("test_public_name_correction_is_one_closed_same_resource_contract", "test_public_name_event_is_invalidation_only")),
        (public_name_adapter, ("PostgresUpdateOrganizationPublicNameHandler", "receipt_candidates", "candidate_payloads")),
        (web_contract_tests, ("organization public names are exact NFC Unicode", "INVALID_ORGANIZATION_PUBLIC_NAME")),
        (web_ui_tests, ("createUpdateOrganizationPublicNameIntent", "status === 412")),
        (e2e_runner, ("_update_organization_public_name_exact_replay", "organization_public_name")),
        (e2e_tests, ("_update_organization_public_name_exact_replay", "organization_public_name")),
    ):
        if any(marker not in source for marker in markers):
            failures.append("current-head-v25-public-name-boundary-open")
            break
    for forbidden in ("DROP TABLE", "TRUNCATE TABLE"):
        if forbidden in public_name_sql.upper():
            failures.append("current-head-v25-forward-only-open")
            break

    history_sql = _read(
        demand_root / "0012_expand__finance_funding_terminal_history.sql"
    )
    history_static_tests = _read(
        root
        / "platform/tests/storage/postgres/"
        "test_demand12_finance_history_migration_static.py"
    )
    finance_postgres_tests = _read(
        root
        / "platform/tests/storage/postgres/test_finance_funding_postgres.py"
    )
    finance_service = _read(
        root / "platform/src/desire_platform/internal_pilot/finance_funding.py"
    )
    finance_http = _read(
        root
        / "platform/src/desire_platform/internal_pilot/editor/http.py"
    )
    finance_asgi = _read(
        root
        / "platform/src/desire_platform/internal_pilot/editor/asgi.py"
    )
    web_app_contract = _read(root / "web/lib/app-contract.mjs")
    web_proxy = _read(root / "web/lib/server-proxy.mjs")
    web_history_panel = _read(
        root / "web/app/finance-funding-history-panel.tsx"
    )
    web_history_tests = _read(
        root / "web/tests/finance-funding-history-contract.test.mjs"
    )
    for source, markers in (
        (
            history_sql,
            (
                "list_manual_funding_review_history_v1",
                "LIST_FUNDING_REVIEWS",
                "LIST_FUNDING_REVIEW_HISTORY",
                "actor_user_id = exact_actor_user_id",
                "status IN ('SECURED', 'DISCREPANCY', 'REJECTED')",
                "ORDER BY assignment.completed_at DESC, review.id DESC",
                "LIMIT maximum_items + 1",
                "TO demand_finance",
            ),
        ),
        (
            history_static_tests,
            (
                "test_demand12_is_byte_exact_current_head",
                "test_history_is_current_duty_actor_owned_terminal_and_keyset_paged",
                "test_history_projection_is_only_the_five_terminal_review_facts",
            ),
        ),
        (
            finance_postgres_tests,
            (
                "test_terminal_history_is_actor_owned_and_keyset_paginated",
                "finding_peer_history",
                "INVALID_CURSOR",
            ),
        ),
        (
            finance_service,
            (
                "class FinanceFundingHistoryItemDto",
                "class FinanceFundingHistoryPageDto",
                "def list_funding_review_history",
                "_encode_finance_funding_history_cursor",
                "_decode_finance_funding_history_cursor",
            ),
        ),
        (
            finance_http + finance_asgi,
            (
                "/v1/app/finance/funding-review-history",
                "list_funding_review_history",
                "_review_history_query",
            ),
        ),
        (
            web_app_contract + web_proxy,
            (
                "parseFinanceFundingHistoryEnvelope",
                "finance-funding-review-history-v1",
                "FINANCE_FUNDING_HISTORY_ROUTE",
                "validateFinanceFundingHistoryProxyResponse",
            ),
        ),
        (
            web_history_panel + web_history_tests,
            (
                "FinanceFundingHistoryPanel",
                "我的已完成资金审查",
                "actor-bound cursor",
                "rechecks a row before opening detail",
            ),
        ),
        (
            e2e_runner + e2e_tests,
            (
                "_finance_history",
                "terminal_history_discoverable",
                "terminal_history_actor_scoped",
                "RESTART_FINANCE_HISTORY",
            ),
        ),
    ):
        if any(marker not in source for marker in markers):
            failures.append("current-head-v25-finance-history-boundary-open")
            break

    trust_history_sql = _read(
        trust_root / "0011_expand__completed_case_assignment_discovery.sql"
    )
    trust17_sql = _read(
        trust_root / "0017_expand__completed_case_history_http_contract.sql"
    )
    trust_api = _read(root / "platform/contracts/api/trust-v1.openapi.yaml")
    trust_http = _read(root / "platform/src/desire_platform/trust_safety/http.py")
    task_discovery = _read(
        root / "platform/src/desire_platform/internal_pilot/task_discovery.py"
    )
    task_discovery_tests = _read(
        root / "platform/tests/internal_pilot/test_task_discovery.py"
    )
    web_trust_contract = _read(root / "web/lib/app-contract.mjs")
    web_trust_proxy = _read(root / "web/lib/server-proxy.mjs")
    web_trust_workbench = _read(root / "web/app/trust-workbench.tsx")
    web_trust_tests = "\n".join(
        _read(root / path)
        for path in (
            "web/tests/current-account-task-discovery.test.mjs",
            "web/tests/trust-case-history-contract.test.mjs",
            "web/tests/trust-ui.test.mjs",
        )
    )
    for source, markers in (
        (
            trust17_sql,
            (
                "Metadata-only publication",
                "schema_head_version = 17",
                TRUST_API_SHA256,
                "TRUST16_SCHEMA_CONTRACT_BASELINE_MISMATCH",
                "migration_manifest_sha256",
            ),
        ),
        (
            trust_history_sql,
            (
                "Actor-bound, party-safe",
                "TRUST_OFFICER",
                "list_my_completed_case_assignments_v1",
                "has_more",
            ),
        ),
        (
            trust_api,
            (
                "/v1/app/trust/history",
                "listMyCompletedTrustAssignments",
                "has_more",
                "Assignment identifiers, actor and duty coordinates",
            ),
        ),
        (
            trust_http,
            (
                "/v1/app/trust/history",
                "MY_COMPLETED_CASE_ASSIGNMENTS",
                "list_my_completed_case_assignments",
                "limit=100",
                "has_more",
            ),
        ),
        (
            task_discovery + task_discovery_tests,
            (
                "VIEW_TRUST_CASE_HISTORY",
                "/v1/app/trust/history",
                "MY_COMPLETED_CASE_ASSIGNMENTS",
                "test_trust_officer_completed_outcome_discovers_only_safe_personal_history",
                "has_more",
            ),
        ),
        (
            web_trust_contract + web_trust_proxy + web_trust_workbench,
            (
                "parseTrustCaseHistoryEnvelope",
                "/v1/app/trust/history",
                "has_more",
                "我的已完成 Trust 案件",
                "服务端还有更早的本人完成记录",
            ),
        ),
        (
            web_trust_tests,
            (
                "VIEW_TRUST_CASE_HISTORY",
                "/v1/app/trust/history",
                "has_more",
                "Trust Officer history is a closed, unique, stably ordered safe projection",
            ),
        ),
        (
            e2e_runner + e2e_tests,
            (
                "_trust_terminal_history",
                "/v1/app/trust/history",
                "trust_officer_01",
                "trust_officer_02",
                "trust_terminal_history_discoverable",
                "terminal_history_actor_scoped",
            ),
        ),
    ):
        if any(marker not in source for marker in markers):
            failures.append("current-head-v25-trust-history-boundary-open")
            break

    trust18_sql = _read(
        trust_root / "0018_expand__completed_appeal_review_history.sql"
    )
    appeal_api = _read(root / "platform/contracts/api/appeal-v1.openapi.yaml")
    appeal_http = _read(
        root / "platform/src/desire_platform/trust_safety/appeal_http.py"
    )
    appeal_static_tests = _read(
        root
        / "platform/tests/storage/postgres/"
        "test_trust_completed_appeal_review_history0018_static.py"
    )
    appeal_pg_tests = _read(
        root
        / "platform/tests/storage/postgres/"
        "test_trust_completed_appeal_review_history0018_pg18.py"
    )
    appeal_http_tests = _read(
        root / "platform/tests/trust_safety/test_appeal_http_red.py"
    )
    web_appeal = "\n".join(
        _read(root / path)
        for path in (
            "web/lib/app-contract.mjs",
            "web/lib/server-proxy.mjs",
            "web/app/appeal-workbench.tsx",
            "web/tests/appeal-contract.test.mjs",
            "web/tests/appeal-ui.test.mjs",
            "web/tests/current-account-task-discovery.test.mjs",
        )
    )
    for source, markers in (
        (
            trust18_sql,
            (
                "schema_head_version = 18",
                "TRUST17_SCHEMA_CONTRACT_BASELINE_MISMATCH",
                TRUST_APPEAL_API_SHA256,
                "list_my_completed_appeal_reviews_v1",
                "read_my_completed_appeal_review_v1",
                "decision.decided_by_user_id = exact_actor_user_id",
                "assignment.reviewer_user_id = exact_actor_user_id",
                "ORDER BY decision.decided_at DESC, decision.appeal_id DESC",
                "LIMIT exact_limit + 1",
                "review_note_recorded",
                "TO trust_appeal",
            ),
        ),
        (
            appeal_api,
            (
                "/v1/app/appeal-review/history:",
                "/v1/app/appeal-review/history/{appeal_id}:",
                "listMyCompletedAppealAssignments",
                "readMyCompletedAppeal",
                "fixed limit of 100",
                "original deciding reviewer",
                "Party-safe terminal decision made by the caller",
            ),
        ),
        (
            appeal_http + appeal_http_tests,
            (
                "LIST_MY_COMPLETED_APPEAL_ASSIGNMENTS",
                "READ_MY_COMPLETED_APPEAL",
                "limit=100",
                "AppealCompletedAssignmentsProjection",
                "AppealCompletedDetailProjection",
                "test_completed_history_rejects_query_body_and_same_timestamp_reverse_order",
            ),
        ),
        (
            appeal_static_tests + appeal_pg_tests,
            (
                "test_trust18_history_is_actor_bound_bounded_and_deterministic",
                "test_trust18_detail_projection_is_exact_and_party_safe",
                "test_two_reviewers_are_isolated_and_ties_are_stable",
                "test_terminal_detail_is_exact_party_safe_and_note_backed",
                "test_wrong_session_revoked_or_expired_duty_and_limits_fail_closed",
                "test_runtime_role_cannot_read_backing_tables_directly",
            ),
        ),
        (
            task_discovery + task_discovery_tests,
            (
                "VIEW_APPEAL_REVIEW_HISTORY",
                "/v1/app/appeal-review/history",
                "TaskClassification.COMPLETED.value",
                "test_appeal_reviewer_completed_history_is_discoverable_and_truncation_is_explicit",
            ),
        ),
        (
            web_appeal,
            (
                "parseAppealReviewHistoryEnvelope",
                "parseAppealReviewTerminalEnvelope",
                "APPEAL_REVIEW_HISTORY_ROUTE",
                "我的已完成申诉复核",
                "fresh 读取终态详情",
                "INVALID_APPEAL_REVIEWER_SNAPSHOT_BINDING",
                "读取失败，不是已验证的空历史",
                "historyItemRefs.current.get(candidate.appeal_id)",
                "VIEW_APPEAL_REVIEW_HISTORY",
            ),
        ),
        (
            e2e_runner + e2e_tests,
            (
                "_appeal_terminal_history",
                "_get_terminal_appeal",
                "/v1/app/appeal-review/history",
                "test_appeal_terminal_history_and_detail_parsers_are_closed",
                '"terminal_history_discoverable": True',
                '"terminal_detail_party_safe": True',
            ),
        ),
    ):
        if any(marker not in source for marker in markers):
            failures.append("current-head-v25-appeal-history-boundary-open")
            break

    http_observability = _read(
        root / "platform/src/desire_platform/http/observability.py"
    )
    http_observability_tests = _read(
        root / "platform/tests/internal_pilot/test_http_observability_red.py"
    )
    runtime_adapters = _read(
        root / "platform/src/desire_platform/internal_pilot/runtime_adapters.py"
    )
    api_composition = _read(
        root / "platform/src/desire_platform/internal_pilot/api_composition.py"
    )
    api_composition_tests = _read(
        root / "platform/tests/internal_pilot/test_api_composition_red.py"
    )
    api_server = _read(
        root / "platform/src/desire_platform/internal_pilot/api_server.py"
    )
    api_server_tests = _read(
        root / "platform/tests/internal_pilot/test_api_server_red.py"
    )
    for source, markers in (
        (
            http_observability,
            (
                "class HttpBoundaryObservation:",
                "class ObservedAsgiApplication:",
                'frozenset(("IAM", "EDITOR", "TRUST", "APPEAL", "UNMATCHED"))',
                'frozenset(("2XX", "3XX", "4XX", "5XX", "NO_RESPONSE"))',
                '"LT_10_MS", "LT_100_MS", "LT_1_S", "LT_10_S", "GTE_10_S", "UNAVAILABLE"',
                "It never receives the ASGI scope",
                "except BaseException:",
                "self._observer(event)",
                "HTTP logs are operational telemetry, never an Audit source",
            ),
        ),
        (
            runtime_adapters,
            (
                "def record_boundary(self, event: HttpBoundaryObservation)",
                '"event_type": "HTTP_BOUNDARY_OBSERVATION_V1"',
                '"component": "INTERNAL_SANDBOX_API"',
                '"latency_bucket": event.latency_bucket',
                '"operation": event.operation',
                '"status_class": event.status_class',
            ),
        ),
        (
            api_composition + api_composition_tests,
            (
                "observed_mux = ObservedAsgiApplication(",
                "observer=dependencies.telemetry.record_boundary",
                "monotonic_seconds=dependencies.runtime_sources.monotonic",
                "self.assertIsInstance(observed, ObservedAsgiApplication)",
                "observed.application._iam_application._transport._telemetry",
            ),
        ),
        (
            api_server + api_server_tests,
            (
                "access_log=False",
                '"access_log": False',
                'log_level="warning"',
                "server_header=False",
            ),
        ),
        (
            http_observability_tests,
            (
                "test_emits_one_closed_low_cardinality_event_without_request_data",
                "test_route_families_methods_and_statuses_are_closed",
                "test_latency_bucket_boundaries_are_closed",
                "test_unhandled_exception_is_classified_without_reflection",
                "test_observer_failure_never_changes_the_http_result",
                "test_lifespan_is_forwarded_without_observation",
                "private-session",
                "private-response",
            ),
        ),
    ):
        if any(marker not in source for marker in markers):
            failures.append("current-head-v25-http-observability-open")
            break
    boundary_start = runtime_adapters.find(
        "    def record_boundary(self, event: HttpBoundaryObservation)"
    )
    boundary_end = runtime_adapters.find("\n    def ", boundary_start + 8)
    boundary_projection = (
        ""
        if boundary_start < 0 or boundary_end < 0
        else runtime_adapters[boundary_start:boundary_end]
    )
    for forbidden in (
        "trace_id",
        "route_template",
        "status_code",
        "error_code",
        "request_size",
        "authenticated",
        "replayed",
        "cookie",
        "authorization",
        "query",
        "body",
        "actor",
        "object_id",
    ):
        if forbidden in boundary_projection:
            failures.append("current-head-v25-http-observation-privacy-open")
            break

    compose = _read(root / "compose.yaml")
    compose_dev = _read(root / "compose.dev.yaml")
    operations_compose = _read(root / "deploy/postgres-operations.compose.yaml")
    real_oidc_compose = _read(root / "deploy/private-server-real-oidc.compose.yaml")
    container_verifier = _read(root / "scripts/verify_container_stack.py")
    local_manager = _read(root / "scripts/manage_local_internal_sandbox.py")
    container_tests = _read(root / "tests/deployment/test_container_stack.py")
    local_manager_tests = _read(
        root / "tests/deployment/test_local_internal_sandbox_manager.py"
    )
    private_contract = _read(root / "scripts/private_server_compose_contract.py")
    private_contract_tests = _read(
        root / "tests/deployment/test_private_server_compose_contract.py"
    )
    real_oidc_contract = _read(
        root / "scripts/private_server_real_oidc_compose_contract.py"
    )
    real_oidc_tests = _read(
        root / "tests/deployment/test_private_server_real_oidc_compose.py"
    )
    postgres_operations_tests = _read(
        root / "tests/deployment/test_postgres_operations.py"
    )
    logging_values = ('driver: local', 'max-size: "10m"', 'max-file: "3"', 'compress: "true"')
    for source in (compose, compose_dev, operations_compose, real_oidc_compose):
        if any(marker not in source for marker in logging_values):
            failures.append("current-head-v25-bounded-compose-logging-open")
            break
    for source, markers in (
        (
            container_verifier + container_tests,
            (
                "BOUNDED_LOGGING",
                "bounded-logging-services-open",
                "bounded-logging-open",
                "test_resolved_services_use_exact_bounded_local_logging",
                '"driver": "local"',
                '"max-size": "10m"',
                '"max-file": "3"',
                '"compress": "true"',
            ),
        ),
        (
            local_manager + local_manager_tests,
            (
                "DOCKER_LOG_CONFIG",
                'host.get("LogConfig") != DOCKER_LOG_CONFIG',
                "test_resolved_compose_rejects_missing_or_drifted_logging",
                "test_live_security_rejects_capability_and_writable_root_bind",
                'document["HostConfig"]["LogConfig"]["Config"]["max-size"] = "100m"',
            ),
        ),
        (
            private_contract + private_contract_tests,
            (
                "BOUNDED_LOGGING",
                "test_bounded_logging_is_exact_and_cannot_be_disabled",
                'update(driver="json-file")',
                '{"max-file": 3}',
                '{"compress": "false"}',
            ),
        ),
        (
            real_oidc_contract + real_oidc_tests,
            (
                '"max-file": "3"',
                '"max-size": "10m"',
                "test_rejects_missing_or_drifted_bounded_logging",
                'update(driver="json-file")',
            ),
        ),
        (
            postgres_operations_tests,
            (
                "test_resolved_operations_use_exact_bounded_local_logging",
                "_assert_exact_bounded_local_logging",
                '"compress": "true"',
            ),
        ),
    ):
        if any(marker not in source for marker in markers):
            failures.append("current-head-v25-bounded-docker-logging-open")
            break

    failures.extend(
        _runbook_failures(_read(root / "docs/operations/current-head-v25.md"))
    )
    sidebar = _read(root / "docs/_sidebar.md")
    for marker in (
        "[Current-head v25 静态模式头](/operations/current-head-v25.md)",
        "[Current-head v24 静态模式头](/operations/current-head-v24.md)",
    ):
        if marker not in sidebar:
            failures.append("current-head-v25-sidebar-open")
            break

    v24_verifier = _read(root / "scripts/verify_current_head_v24.py")
    for marker in (
        "tests/deployment/fixtures/current-head-v24",
        "18|42|42|3|3|12|12|18|18|2|2",
        "919d62a9b32dc29619a561940f9c79e21700562a0cdd9ef7e9f13a40cea43345",
        "0b7028c75c8f137bc4a55a76fe73ea956d0c5ada13031f80794b77c1c9535e19",
    ):
        if marker not in v24_verifier:
            failures.append("current-head-v24-frozen-pins-open")
            break

    ci = _read(root / ".github/workflows/ci.yml")
    release = _read(root / ".github/workflows/private-server-runtime-release.yml")
    v24_invocation = "python -B scripts/verify_current_head_v24.py"
    v25_invocation = "python -B scripts/verify_current_head_v25.py"
    if (
        ci.count(v24_invocation) != 0
        or ci.count(v25_invocation) != 1
        or release.count(v24_invocation) != 0
        or release.count(v25_invocation) != 1
    ):
        failures.append("current-head-v25-workflow-pointer-open")

    operations_summary = "\n".join(
        _read(root / path)
        for path in (
            "docs/operations/run-and-check.md",
            "docs/operations/container-deployment.md",
            "docs/operations/local-internal-sandbox-trial.md",
        )
    )
    for forbidden in (
        "IAM42/Trust15 的 current checkout",
        "current checkout 的 IAM42/Trust15",
        "### 4.6.3 当前 IAM42/Trust15",
        "### 2.2 当前 IAM42/Trust15",
        "current-head v22 上完成",
        "当前合同只见\nv16 页面",
    ):
        if forbidden in operations_summary:
            failures.append("current-head-v25-operations-stale-pointer-open")
            break
    for marker in (
        "IAM `0042`",
        "Demand `0012`",
        "Trust `0018`",
        "IAM42/Demand12/Trust18 current-head v25",
    ):
        if marker not in operations_summary:
            failures.append("current-head-v25-operations-summary-open")
            break
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
