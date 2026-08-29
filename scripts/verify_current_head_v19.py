#!/usr/bin/env python3
"""Read-only verifier for the IAM40 / Demand11 / Trust13 static head."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Iterable


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
HEADS = "18|40|40|3|3|11|11|13|13|2|2"
IAM_MANIFEST_SHA256 = "e9e571dcb16928c21ab26b9dca5cacc299f9cc5427dd18383af87867ccca5c40"
IAM_COMBINED_SHA256 = "981c425483ce3c89e6e376c8bc1fd8269a36499c8fd89890e8feeac5d94a1ae8"
IAM_SQL_SHA256 = "5bf84831502fb295279666a2df5e660f977995bf8c0e8a86f3a321808909cad7"
PROFILE_MANIFEST_SHA256 = "4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa"
DEMAND_MANIFEST_SHA256 = "870f2b9d9862f75f4e7eaf01cc9f1d5f788b72fbf4f7ccf9056dfeff35969898"
DEMAND_DEPENDENCY_SHA256 = "cfab70770b908b37aa4865ba2f52d5b8f59492cbc7979867229e006e99cd8d87"
TRUST_API_SHA256 = "a9923573365f1023aff3e4aaebb0b7e656c80eab7e721bbf30d9e9b038782f25"
TRUST_SQL_SHA256 = "d5d714824f8b20d1bbbcaed2bd0ee7e8f38ef42c5aa749189c7fa6bf407bf00e"
TRUST_MANIFEST_SHA256 = "c438a3fac4d9dea850089b8a14f92ab34a5c5a592b9babcb770860d3ecc513d8"
TRUST_COMBINED_SHA256 = "d843e20a45397931a572688cd86ccef9fe43b92a2577d3c8559d519fb0de2480"
TAXONOMY_MANIFEST_SHA256 = "74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622"
EXPECTED_CONTRACTS = "|".join((
    IAM_COMBINED_SHA256,
    PROFILE_MANIFEST_SHA256,
    DEMAND_MANIFEST_SHA256,
    "40",
    "11",
    IAM_COMBINED_SHA256,
    DEMAND_DEPENDENCY_SHA256,
    TRUST_COMBINED_SHA256,
    TRUST_MANIFEST_SHA256,
    TAXONOMY_MANIFEST_SHA256,
))
SUCCESS = '{"status":"CURRENT_HEAD_V19_STATIC_VERIFIED"}'


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


def _runbook_failures(value: str) -> tuple[str, ...]:
    begin = "<!-- BEGIN CURRENT_HEAD_V19_CONTRACT -->"
    end = "<!-- END CURRENT_HEAD_V19_CONTRACT -->"
    if (
        value.count(begin) != 1
        or value.count(end) != 1
        or value.find(begin) >= value.find(end)
    ):
        return ("current-head-v19-markers-open",)
    required = (
        HEADS,
        EXPECTED_CONTRACTS,
        IAM_SQL_SHA256,
        IAM_MANIFEST_SHA256,
        TRUST_SQL_SHA256,
        "DEMAND_OWNER",
        "PENDING_ENROLLMENT",
        "AcceptAccessInvitation",
        "exact invitation",
        "receipt replay",
        "Session rotation",
        "zero authority",
        "STATIC VERIFIED",
        "NOT EXECUTED",
        "production_authorized=false",
        "tests/deployment/fixtures/current-head-v19/",
        "tests/deployment/fixtures/current-head-v18/",
        "18|39|39|3|3|11|11|12|12|2|2",
        "current-head-v18.md",
        "python3 -B scripts/verify_current_head_v19.py",
    )
    if any(marker not in value for marker in required):
        return ("current-head-v19-contract-open",)
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
    fixture_root = root / "tests/deployment/fixtures/current-head-v19"
    v18_root = root / "tests/deployment/fixtures/current-head-v18"
    assets = (
        (fixture_root / "iam-manifest.json", IAM_MANIFEST_SHA256),
        (fixture_root / "demand-manifest.json", DEMAND_MANIFEST_SHA256),
        (fixture_root / "trust-manifest.json", TRUST_MANIFEST_SHA256),
        (
            fixture_root / "trust-runner-pins.txt",
            "56ad6e288ce788eaef9e37ba5eebe5496f3e253837582f513687ea6cb5f789de",
        ),
        (iam_root / "0040_expand__invitation_enrollment_acceptance.sql", IAM_SQL_SHA256),
        (profile_root / "manifest.json", PROFILE_MANIFEST_SHA256),
        (trust_root / "0013_expand__iam40_dependency_repin.sql", TRUST_SQL_SHA256),
        (taxonomy_root / "manifest.json", TAXONOMY_MANIFEST_SHA256),
        (root / "platform/contracts/api/trust-v1.openapi.yaml", TRUST_API_SHA256),
        (
            v18_root / "iam-manifest.json",
            "a1b8c6973476ca7f3769a258a1950a17b7e17a9a94f9ea7461979f9b6e37f33f",
        ),
        (
            v18_root / "demand-manifest.json",
            DEMAND_MANIFEST_SHA256,
        ),
        (
            v18_root / "trust-manifest.json",
            "5d2172c15c7919d6ea6576ef059e136b123eb523d884febf7b7a5d79b4b43ecc",
        ),
        (
            v18_root / "trust-runner-pins.txt",
            "eb30cb535b88c3026d76d2e642834086ff1aaddafe4dd09313a77fc74e167d5e",
        ),
    )
    for path, expected in assets:
        if _sha(path) != expected:
            failures.append(
                f"current-head-v19-asset-mismatch:{path.relative_to(root)}"
            )

    if _manifest_versions(fixture_root / "iam-manifest.json", "iam") != tuple(
        range(41)
    ):
        failures.append("current-head-v19-iam-sequence-open")
    if _manifest_versions(
        fixture_root / "demand-manifest.json", "demand"
    ) != tuple(range(1, 12)):
        failures.append("current-head-v19-demand-sequence-open")
    if _manifest_versions(
        fixture_root / "trust-manifest.json", "trust"
    ) != tuple(range(1, 14)):
        failures.append("current-head-v19-trust-sequence-open")
    frozen_runner = _read(fixture_root / "trust-runner-pins.txt")
    for source, markers, failure in (
        (
            frozen_runner,
            (
                "TRUST_REQUIRED_IAM_SCHEMA_VERSION = 40",
                "TRUST_REQUIRED_DEMAND_SCHEMA_VERSION = 11",
                IAM_COMBINED_SHA256,
                DEMAND_DEPENDENCY_SHA256,
                TRUST_API_SHA256,
                TRUST_COMBINED_SHA256,
            ),
            "current-head-v19-frozen-runner-open",
        ),
    ):
        if any(marker not in source for marker in markers):
            failures.append(failure)

    acceptance_sql = _read(
        iam_root / "0040_expand__invitation_enrollment_acceptance.sql"
    )
    static_tests = _read(
        root
        / "platform/tests/storage/postgres/"
        "test_iam40_invitation_enrollment_acceptance_static.py"
    )
    acceptance_tests = _read(
        root
        / "platform/tests/storage/postgres/test_accept_access_invitation_uow_red.py"
    )
    for source, markers in (
        (
            acceptance_sql,
            (
                "iam_api.resolve_accept_receipt_principal_v1",
                "iam_api.resolve_accept_access_invitation_scope_v1",
                "user_row.status NOT IN ('ACTIVE','PENDING_ENROLLMENT')",
                "session_row.rotation_reason <> 'ENROLLMENT'",
                "candidate.invitation_id::text = exact_invitation_id",
                "candidate.target_role = 'DEMAND_OWNER'",
                "AND NOT candidate.is_initial_admin",
                "REVOKE ALL ON FUNCTION",
            ),
        ),
        (
            static_tests,
            (
                "test_receipt_pending_branch_requires_exact_enrollment_proof",
                "test_scope_auth_rls_and_two_allowed_shapes_are_exact",
            ),
        ),
        (
            acceptance_tests,
            (
                "test_iam40_exact_pending_enrollment_resolves_and_accepts_membership",
                "test_iam40_pending_enrollment_is_closed_for_every_inexact_shape",
                "test_iam40_preserves_exact_active_step_up_accept_scope",
            ),
        ),
    ):
        if any(marker not in source for marker in markers):
            failures.append("current-head-v19-acceptance-boundary-open")
            break
    for forbidden in ("CREATE TABLE", "ALTER TABLE", "DROP TABLE"):
        if forbidden in acceptance_sql.upper():
            failures.append("current-head-v19-forward-only-open")
            break

    failures.extend(
        _runbook_failures(_read(root / "docs/operations/current-head-v19.md"))
    )
    sidebar = _read(root / "docs/_sidebar.md")
    for marker in (
        "[Current-head v19 静态模式头](/operations/current-head-v19.md)",
        "[Current-head v18 静态模式头](/operations/current-head-v18.md)",
    ):
        if marker not in sidebar:
            failures.append("current-head-v19-sidebar-open")
            break

    v18_verifier = _read(root / "scripts/verify_current_head_v18.py")
    for marker in (
        "tests/deployment/fixtures/current-head-v18",
        "18|39|39|3|3|11|11|12|12|2|2",
        "a1b8c6973476ca7f3769a258a1950a17b7e17a9a94f9ea7461979f9b6e37f33f",
        "5d2172c15c7919d6ea6576ef059e136b123eb523d884febf7b7a5d79b4b43ecc",
    ):
        if marker not in v18_verifier:
            failures.append("current-head-v18-frozen-pins-open")
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
