#!/usr/bin/env python3
"""Read-only verifier for the IAM42 / Demand11 / Trust15 static head."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Iterable


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
HEADS = "18|42|42|3|3|11|11|15|15|2|2"
IAM_API_SHA256 = "26ffd8243c0baa2580d21e8878897ed0f13aa61fd9ba468cca8edf1fe277477c"
IAM_EVENT_SHA256 = "6af7e75f738bfeef9aeed0ac8e84da782485c1a42e1c937c9d51e66884bad934"
IAM_MANIFEST_SHA256 = "9c6e0396867d68ac49260684a9531c592055d62cac20d7ebdfb578c236df025d"
IAM_COMBINED_SHA256 = "f88bf5f70343edbf06e55c0641b61b58cff27fda48ce00f6489e3f3f80db5a9e"
IAM_SQL_SHA256 = "1d0c1391f08ba47f0af29d9941634a4f522c0d0c48e0c5747edbed16e4b02f44"
PROFILE_MANIFEST_SHA256 = "4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa"
DEMAND_MANIFEST_SHA256 = "870f2b9d9862f75f4e7eaf01cc9f1d5f788b72fbf4f7ccf9056dfeff35969898"
DEMAND_DEPENDENCY_SHA256 = "cfab70770b908b37aa4865ba2f52d5b8f59492cbc7979867229e006e99cd8d87"
TRUST_API_SHA256 = "a9923573365f1023aff3e4aaebb0b7e656c80eab7e721bbf30d9e9b038782f25"
TRUST_SQL_SHA256 = "253bbd89b53d7cc91eeaddc3cd6fa3a770b53f7640cdb445a032a12d016d3dbd"
TRUST_MANIFEST_SHA256 = "09a22506690138cf3b9c32e8b9d2bf8acbf31fc8cd80b37c8422bf4a93d2756c"
TRUST_COMBINED_SHA256 = "d88bb1f0e5cc9a50e7a3eac5597202a073414c42d780a7b769267ba80c14b0ca"
TAXONOMY_MANIFEST_SHA256 = "74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622"
EXPECTED_CONTRACTS = "|".join((
    IAM_COMBINED_SHA256,
    PROFILE_MANIFEST_SHA256,
    DEMAND_MANIFEST_SHA256,
    "42",
    "11",
    IAM_COMBINED_SHA256,
    DEMAND_DEPENDENCY_SHA256,
    TRUST_COMBINED_SHA256,
    TRUST_MANIFEST_SHA256,
    TAXONOMY_MANIFEST_SHA256,
))
SUCCESS = '{"status":"CURRENT_HEAD_V21_STATIC_VERIFIED"}'


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
    begin = "<!-- BEGIN CURRENT_HEAD_V21_CONTRACT -->"
    end = "<!-- END CURRENT_HEAD_V21_CONTRACT -->"
    if (
        value.count(begin) != 1
        or value.count(end) != 1
        or value.find(begin) >= value.find(end)
    ):
        return ("current-head-v21-markers-open",)
    required = (
        HEADS,
        EXPECTED_CONTRACTS,
        IAM_SQL_SHA256,
        IAM_MANIFEST_SHA256,
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
        "STATIC VERIFIED",
        "NOT EXECUTED",
        "production_authorized=false",
        "tests/deployment/fixtures/current-head-v21/",
        "tests/deployment/fixtures/current-head-v20/",
        "18|41|41|3|3|11|11|14|14|2|2",
        "current-head-v20.md",
        "python3 -B scripts/verify_current_head_v21.py",
    )
    if any(marker not in value for marker in required):
        return ("current-head-v21-contract-open",)
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
    fixture_root = root / "tests/deployment/fixtures/current-head-v21"
    v20_root = root / "tests/deployment/fixtures/current-head-v20"
    assets = (
        (fixture_root / "iam-manifest.json", IAM_MANIFEST_SHA256),
        (fixture_root / "demand-manifest.json", DEMAND_MANIFEST_SHA256),
        (fixture_root / "trust-manifest.json", TRUST_MANIFEST_SHA256),
        (
            fixture_root / "trust-runner-pins.txt",
            "e717585eaea9013309c2a5254363121608b3ec9250bbad4b0557d45d9c1db588",
        ),
        (iam_root / "0042_expand__organization_public_name_management.sql", IAM_SQL_SHA256),
        (profile_root / "manifest.json", PROFILE_MANIFEST_SHA256),
        (trust_root / "0015_expand__iam42_dependency_repin.sql", TRUST_SQL_SHA256),
        (taxonomy_root / "manifest.json", TAXONOMY_MANIFEST_SHA256),
        (root / "platform/contracts/api/iam-v1.openapi.yaml", IAM_API_SHA256),
        (root / "platform/contracts/events/iam-v1.schema.json", IAM_EVENT_SHA256),
        (root / "platform/contracts/api/trust-v1.openapi.yaml", TRUST_API_SHA256),
        (
            v20_root / "iam-manifest.json",
            "dc54ab65fffba8e55cc4dbd82c7c0effe044820a5387952d23893275f5ad74ac",
        ),
        (
            v20_root / "demand-manifest.json",
            DEMAND_MANIFEST_SHA256,
        ),
        (
            v20_root / "trust-manifest.json",
            "7aa1b1533e1e23bdef9233c49aeffe9dbca172ad1d825ccdd0925e8c6a823cca",
        ),
        (
            v20_root / "trust-runner-pins.txt",
            "fe58fe95ece1945fa5a5f68246740be282cde57234e792eb7343cd409402ca5b",
        ),
    )
    for path, expected in assets:
        if _sha(path) != expected:
            failures.append(
                f"current-head-v21-asset-mismatch:{path.relative_to(root)}"
            )

    if _manifest_versions(fixture_root / "iam-manifest.json", "iam") != tuple(
        range(43)
    ):
        failures.append("current-head-v21-iam-sequence-open")
    if _manifest_versions(
        fixture_root / "demand-manifest.json", "demand"
    ) != tuple(range(1, 12)):
        failures.append("current-head-v21-demand-sequence-open")
    if _manifest_versions(
        fixture_root / "trust-manifest.json", "trust"
    ) != tuple(range(1, 16)):
        failures.append("current-head-v21-trust-sequence-open")
    if _iam_combined(root) != IAM_COMBINED_SHA256:
        failures.append("current-head-v21-iam-combined-open")

    frozen_runner = _read(fixture_root / "trust-runner-pins.txt")
    for source, markers, failure in (
        (
            frozen_runner,
            (
                "TRUST_REQUIRED_IAM_SCHEMA_VERSION = 42",
                "TRUST_REQUIRED_DEMAND_SCHEMA_VERSION = 11",
                IAM_COMBINED_SHA256,
                DEMAND_DEPENDENCY_SHA256,
                TRUST_API_SHA256,
                TRUST_COMBINED_SHA256,
            ),
            "current-head-v21-frozen-runner-open",
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
            failures.append("current-head-v21-public-name-boundary-open")
            break
    for forbidden in ("DROP TABLE", "TRUNCATE TABLE"):
        if forbidden in public_name_sql.upper():
            failures.append("current-head-v21-forward-only-open")
            break

    failures.extend(
        _runbook_failures(_read(root / "docs/operations/current-head-v21.md"))
    )
    sidebar = _read(root / "docs/_sidebar.md")
    for marker in (
        "[Current-head v21 静态模式头](/operations/current-head-v21.md)",
        "[Current-head v20 静态模式头](/operations/current-head-v20.md)",
    ):
        if marker not in sidebar:
            failures.append("current-head-v21-sidebar-open")
            break

    v20_verifier = _read(root / "scripts/verify_current_head_v20.py")
    for marker in (
        "tests/deployment/fixtures/current-head-v20",
        "18|41|41|3|3|11|11|14|14|2|2",
        "dc54ab65fffba8e55cc4dbd82c7c0effe044820a5387952d23893275f5ad74ac",
        "7aa1b1533e1e23bdef9233c49aeffe9dbca172ad1d825ccdd0925e8c6a823cca",
    ):
        if marker not in v20_verifier:
            failures.append("current-head-v20-frozen-pins-open")
            break
    for forbidden in (
        'iam_root / "manifest.json"',
        'trust_root / "manifest.json"',
        'iam_root / "catalog.py"',
        'trust_root / "catalog.py"',
        'trust_root / "runner.py"',
    ):
        if forbidden in v20_verifier:
            failures.append("current-head-v20-live-alias-open")
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
