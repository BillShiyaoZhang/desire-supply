#!/usr/bin/env python3
"""Read-only verifier for the IAM42 / Demand12 / Trust16 static head."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Iterable


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
HEADS = "18|42|42|3|3|12|12|16|16|2|2"
IAM_API_SHA256 = "26ffd8243c0baa2580d21e8878897ed0f13aa61fd9ba468cca8edf1fe277477c"
IAM_EVENT_SHA256 = "6af7e75f738bfeef9aeed0ac8e84da782485c1a42e1c937c9d51e66884bad934"
IAM_MANIFEST_SHA256 = "9c6e0396867d68ac49260684a9531c592055d62cac20d7ebdfb578c236df025d"
IAM_COMBINED_SHA256 = "f88bf5f70343edbf06e55c0641b61b58cff27fda48ce00f6489e3f3f80db5a9e"
IAM_SQL_SHA256 = "1d0c1391f08ba47f0af29d9941634a4f522c0d0c48e0c5747edbed16e4b02f44"
PROFILE_MANIFEST_SHA256 = "4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa"
DEMAND_MANIFEST_SHA256 = "919d62a9b32dc29619a561940f9c79e21700562a0cdd9ef7e9f13a40cea43345"
DEMAND_DEPENDENCY_SHA256 = "379b6cb8b05f7da03905e644d158cfb6ad03409f290d33f63ae80183d428f816"
DEMAND_SQL_SHA256 = "bf76efd70f95a4fa4c49ad43ad03fc9d31e5009bce88364bec851f68b0313280"
TRUST_API_SHA256 = "a9923573365f1023aff3e4aaebb0b7e656c80eab7e721bbf30d9e9b038782f25"
TRUST_SQL_SHA256 = "46bd5355dffb1028d11f277b785cc8e03266b49c3d9e5dbe0a5a954b0ecdb08d"
TRUST_MANIFEST_SHA256 = "71b61f666ea9d924a7edae14db1bf3cc20905618d806d0c8e76b94066c07672c"
TRUST_COMBINED_SHA256 = "d1df1117a20361e041a2da24b79a8408c05f4ea949c8a930e3cb3634d2f6a04e"
TAXONOMY_MANIFEST_SHA256 = "74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622"
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
SUCCESS = '{"status":"CURRENT_HEAD_V22_STATIC_VERIFIED"}'


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
    begin = "<!-- BEGIN CURRENT_HEAD_V22_CONTRACT -->"
    end = "<!-- END CURRENT_HEAD_V22_CONTRACT -->"
    if (
        value.count(begin) != 1
        or value.count(end) != 1
        or value.find(begin) >= value.find(end)
    ):
        return ("current-head-v22-markers-open",)
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
        "writer quiescence",
        "READ ONLY",
        "STATIC VERIFIED",
        "NOT EXECUTED",
        "production_authorized=false",
        "tests/deployment/fixtures/current-head-v22/",
        "tests/deployment/fixtures/current-head-v21/",
        "18|42|42|3|3|11|11|15|15|2|2",
        "current-head-v21.md",
        "python3 -B scripts/verify_current_head_v22.py",
    )
    if any(marker not in value for marker in required):
        return ("current-head-v22-contract-open",)
    return ()


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
    fixture_root = root / "tests/deployment/fixtures/current-head-v22"
    v21_root = root / "tests/deployment/fixtures/current-head-v21"
    assets = (
        (fixture_root / "iam-manifest.json", IAM_MANIFEST_SHA256),
        (fixture_root / "demand-manifest.json", DEMAND_MANIFEST_SHA256),
        (fixture_root / "trust-manifest.json", TRUST_MANIFEST_SHA256),
        (
            fixture_root / "trust-runner-pins.txt",
            "c06f8e25b12d919071029dd50868a07a6c322d17b02c7adbd0632675f211b425",
        ),
        (iam_root / "manifest.json", IAM_MANIFEST_SHA256),
        (iam_root / "0042_expand__organization_public_name_management.sql", IAM_SQL_SHA256),
        (profile_root / "manifest.json", PROFILE_MANIFEST_SHA256),
        (demand_root / "manifest.json", DEMAND_MANIFEST_SHA256),
        (demand_root / "0012_expand__finance_funding_terminal_history.sql", DEMAND_SQL_SHA256),
        (trust_root / "manifest.json", TRUST_MANIFEST_SHA256),
        (trust_root / "0016_expand__demand12_dependency_repin.sql", TRUST_SQL_SHA256),
        (taxonomy_root / "manifest.json", TAXONOMY_MANIFEST_SHA256),
        (root / "platform/contracts/api/iam-v1.openapi.yaml", IAM_API_SHA256),
        (root / "platform/contracts/events/iam-v1.schema.json", IAM_EVENT_SHA256),
        (root / "platform/contracts/api/trust-v1.openapi.yaml", TRUST_API_SHA256),
        (
            v21_root / "iam-manifest.json",
            IAM_MANIFEST_SHA256,
        ),
        (
            v21_root / "demand-manifest.json",
            "870f2b9d9862f75f4e7eaf01cc9f1d5f788b72fbf4f7ccf9056dfeff35969898",
        ),
        (
            v21_root / "trust-manifest.json",
            "09a22506690138cf3b9c32e8b9d2bf8acbf31fc8cd80b37c8422bf4a93d2756c",
        ),
        (
            v21_root / "trust-runner-pins.txt",
            "e717585eaea9013309c2a5254363121608b3ec9250bbad4b0557d45d9c1db588",
        ),
    )
    for path, expected in assets:
        if _sha(path) != expected:
            failures.append(
                f"current-head-v22-asset-mismatch:{path.relative_to(root)}"
            )

    if _manifest_versions(fixture_root / "iam-manifest.json", "iam") != tuple(
        range(43)
    ):
        failures.append("current-head-v22-iam-sequence-open")
    if _manifest_versions(
        fixture_root / "demand-manifest.json", "demand"
    ) != tuple(range(1, 13)):
        failures.append("current-head-v22-demand-sequence-open")
    if _manifest_versions(
        fixture_root / "trust-manifest.json", "trust"
    ) != tuple(range(1, 17)):
        failures.append("current-head-v22-trust-sequence-open")
    if _iam_combined(root) != IAM_COMBINED_SHA256:
        failures.append("current-head-v22-iam-combined-open")

    iam_catalog = _read(iam_root / "catalog.py")
    trust_catalog = _read(trust_root / "catalog.py")
    trust_runner = _read(trust_root / "runner.py")
    frozen_runner = _read(fixture_root / "trust-runner-pins.txt")
    for source, markers, failure in (
        (
            iam_catalog,
            ("organization_public_name_management", IAM_MANIFEST_SHA256),
            "current-head-v22-iam-catalog-open",
        ),
        (
            _read(demand_root / "catalog.py"),
            ("finance_funding_terminal_history", DEMAND_MANIFEST_SHA256),
            "current-head-v22-demand-catalog-open",
        ),
        (
            trust_catalog,
            ("demand12_dependency_repin", TRUST_MANIFEST_SHA256),
            "current-head-v22-trust-catalog-open",
        ),
        (
            trust_runner,
            (
                "TRUST_REQUIRED_IAM_SCHEMA_VERSION = 42",
                "TRUST_REQUIRED_DEMAND_SCHEMA_VERSION = 12",
                IAM_COMBINED_SHA256,
                DEMAND_DEPENDENCY_SHA256,
                TRUST_API_SHA256,
                TRUST_COMBINED_SHA256,
            ),
            "current-head-v22-trust-runner-open",
        ),
        (
            frozen_runner,
            (
                "TRUST_REQUIRED_IAM_SCHEMA_VERSION = 42",
                "TRUST_REQUIRED_DEMAND_SCHEMA_VERSION = 12",
                IAM_COMBINED_SHA256,
                DEMAND_DEPENDENCY_SHA256,
                TRUST_API_SHA256,
                TRUST_COMBINED_SHA256,
            ),
            "current-head-v22-frozen-runner-open",
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
            failures.append("current-head-v22-public-name-boundary-open")
            break
    for forbidden in ("DROP TABLE", "TRUNCATE TABLE"):
        if forbidden in public_name_sql.upper():
            failures.append("current-head-v22-forward-only-open")
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
            failures.append("current-head-v22-finance-history-boundary-open")
            break

    failures.extend(
        _runbook_failures(_read(root / "docs/operations/current-head-v22.md"))
    )
    sidebar = _read(root / "docs/_sidebar.md")
    for marker in (
        "[Current-head v22 静态模式头](/operations/current-head-v22.md)",
        "[Current-head v21 静态模式头](/operations/current-head-v21.md)",
    ):
        if marker not in sidebar:
            failures.append("current-head-v22-sidebar-open")
            break

    v21_verifier = _read(root / "scripts/verify_current_head_v21.py")
    for marker in (
        "tests/deployment/fixtures/current-head-v21",
        "18|42|42|3|3|11|11|15|15|2|2",
        "870f2b9d9862f75f4e7eaf01cc9f1d5f788b72fbf4f7ccf9056dfeff35969898",
        "09a22506690138cf3b9c32e8b9d2bf8acbf31fc8cd80b37c8422bf4a93d2756c",
    ):
        if marker not in v21_verifier:
            failures.append("current-head-v21-frozen-pins-open")
            break
    for forbidden in (
        '(iam_root / "manifest.json",',
        '(demand_root / "manifest.json",',
        '(trust_root / "manifest.json",',
        'iam_catalog = _read(iam_root / "catalog.py")',
        'trust_catalog = _read(trust_root / "catalog.py")',
        'trust_runner = _read(trust_root / "runner.py")',
    ):
        if forbidden in v21_verifier:
            failures.append("current-head-v21-live-alias-open")
            break

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
        "current-head v21 上完成",
        "当前合同只见\nv16 页面",
    ):
        if forbidden in operations_summary:
            failures.append("current-head-v22-operations-stale-pointer-open")
            break
    for marker in (
        "IAM `0042`",
        "Demand `0012`",
        "Trust `0016`",
        "IAM42/Demand12/Trust16 current-head v22",
    ):
        if marker not in operations_summary:
            failures.append("current-head-v22-operations-summary-open")
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
