#!/usr/bin/env python3
"""Read-only verifier for the IAM39 / Demand11 / Trust12 static head."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Iterable


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
HEADS = "18|39|39|3|3|11|11|12|12|2|2"
IAM_MANIFEST_SHA256 = "a1b8c6973476ca7f3769a258a1950a17b7e17a9a94f9ea7461979f9b6e37f33f"
IAM_COMBINED_SHA256 = "fdfb00e353ce823f6ef5695e47ec32443c219387413ade908d502925e5248258"
IAM_SQL_SHA256 = "b3ce89a429f87ff294ebfd5892f1731ca96b46f3bcaccd17711c9f5a9d8ab737"
PROFILE_MANIFEST_SHA256 = "4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa"
DEMAND_MANIFEST_SHA256 = "870f2b9d9862f75f4e7eaf01cc9f1d5f788b72fbf4f7ccf9056dfeff35969898"
DEMAND_DEPENDENCY_SHA256 = "cfab70770b908b37aa4865ba2f52d5b8f59492cbc7979867229e006e99cd8d87"
TRUST_API_SHA256 = "a9923573365f1023aff3e4aaebb0b7e656c80eab7e721bbf30d9e9b038782f25"
TRUST_SQL_SHA256 = "064f9feabd497bafcb410b8f926033775d2645e23438c0439e8ecf9981076a3d"
TRUST_MANIFEST_SHA256 = "5d2172c15c7919d6ea6576ef059e136b123eb523d884febf7b7a5d79b4b43ecc"
TRUST_COMBINED_SHA256 = "3e0af93a1411bc45ca8877f44dbe517f575eb50ce810f11019ea5d583fc4b1aa"
TAXONOMY_MANIFEST_SHA256 = "74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622"
EXPECTED_CONTRACTS = "|".join((
    IAM_COMBINED_SHA256,
    PROFILE_MANIFEST_SHA256,
    DEMAND_MANIFEST_SHA256,
    "39",
    "11",
    IAM_COMBINED_SHA256,
    DEMAND_DEPENDENCY_SHA256,
    TRUST_COMBINED_SHA256,
    TRUST_MANIFEST_SHA256,
    TAXONOMY_MANIFEST_SHA256,
))
SUCCESS = '{"status":"CURRENT_HEAD_V18_STATIC_VERIFIED"}'


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
    begin = "<!-- BEGIN CURRENT_HEAD_V18_CONTRACT -->"
    end = "<!-- END CURRENT_HEAD_V18_CONTRACT -->"
    if (
        value.count(begin) != 1
        or value.count(end) != 1
        or value.find(begin) >= value.find(end)
    ):
        return ("current-head-v18-markers-open",)
    required = (
        HEADS,
        EXPECTED_CONTRACTS,
        IAM_SQL_SHA256,
        IAM_MANIFEST_SHA256,
        TRUST_SQL_SHA256,
        "DEMAND_OWNER",
        "PENDING_ENROLLMENT",
        "Membership / Role authority",
        "ORG_ADMIN",
        "普通未知身份登录",
        "HTTP response",
        "commit acknowledgement",
        "fresh Session",
        "STATIC VERIFIED",
        "NOT EXECUTED",
        "production_authorized=false",
        "tests/deployment/fixtures/current-head-v18/",
        "tests/deployment/fixtures/current-head-v17/",
        "18|38|38|3|3|11|11|11|11|2|2",
        "current-head-v17.md",
        "python3 -B scripts/verify_current_head_v18.py",
    )
    if any(marker not in value for marker in required):
        return ("current-head-v18-contract-open",)
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
    fixture_root = root / "tests/deployment/fixtures/current-head-v18"
    v17_root = root / "tests/deployment/fixtures/current-head-v17"
    assets = (
        (fixture_root / "iam-manifest.json", IAM_MANIFEST_SHA256),
        (fixture_root / "demand-manifest.json", DEMAND_MANIFEST_SHA256),
        (fixture_root / "trust-manifest.json", TRUST_MANIFEST_SHA256),
        (
            fixture_root / "trust-runner-pins.txt",
            "eb30cb535b88c3026d76d2e642834086ff1aaddafe4dd09313a77fc74e167d5e",
        ),
        (iam_root / "0039_expand__invitation_oidc_enrollment.sql", IAM_SQL_SHA256),
        (profile_root / "manifest.json", PROFILE_MANIFEST_SHA256),
        (trust_root / "0012_expand__iam39_dependency_repin.sql", TRUST_SQL_SHA256),
        (taxonomy_root / "manifest.json", TAXONOMY_MANIFEST_SHA256),
        (root / "platform/contracts/api/trust-v1.openapi.yaml", TRUST_API_SHA256),
        (
            v17_root / "demand-manifest.json",
            DEMAND_MANIFEST_SHA256,
        ),
        (
            v17_root / "trust-manifest.json",
            "6b7623d36259e4db00de3ca83a0e0470173a16159432d099c6dc54e51cdcd2e7",
        ),
        (
            v17_root / "trust-runner-pins.txt",
            "df9ab47f7c792c5c41915e330702c7e8e9ea9a208e488891fea22e8a914e7816",
        ),
    )
    for path, expected in assets:
        if _sha(path) != expected:
            failures.append(
                f"current-head-v18-asset-mismatch:{path.relative_to(root)}"
            )

    if _manifest_versions(fixture_root / "iam-manifest.json", "iam") != tuple(
        range(40)
    ):
        failures.append("current-head-v18-iam-sequence-open")
    if _manifest_versions(
        fixture_root / "demand-manifest.json", "demand"
    ) != tuple(range(1, 12)):
        failures.append("current-head-v18-demand-sequence-open")
    if _manifest_versions(
        fixture_root / "trust-manifest.json", "trust"
    ) != tuple(range(1, 13)):
        failures.append("current-head-v18-trust-sequence-open")
    frozen_runner = _read(fixture_root / "trust-runner-pins.txt")
    for source, markers, failure in (
        (
            frozen_runner,
            (
                "TRUST_REQUIRED_IAM_SCHEMA_VERSION = 39",
                "TRUST_REQUIRED_DEMAND_SCHEMA_VERSION = 11",
                IAM_COMBINED_SHA256,
                DEMAND_DEPENDENCY_SHA256,
                TRUST_API_SHA256,
                TRUST_COMBINED_SHA256,
            ),
            "current-head-v18-frozen-runner-open",
        ),
    ):
        if any(marker not in source for marker in markers):
            failures.append(failure)

    enrollment_sql = _read(
        iam_root / "0039_expand__invitation_oidc_enrollment.sql"
    )
    oidc_bundle = _read(
        root
        / "platform/src/desire_platform/identity_access/adapters/postgres/oidc_bundle.py"
    )
    oidc_tests = _read(
        root / "platform/tests/storage/postgres/test_oidc_postgres_uow_red.py"
    )
    bundle_tests = _read(
        root / "platform/tests/authentication/test_postgres_oidc_auth_bundle_red.py"
    )
    web_flow = _read(root / "web/lib/invitation-flow.mjs")
    web_proxy = _read(root / "web/lib/server-proxy.mjs")
    for source, markers in (
        (
            enrollment_sql,
            (
                "invitation_row.target_role = 'DEMAND_OWNER'",
                "status = 'PENDING_ENROLLMENT'",
                "recovered_enrollment",
                "rotation_reason = 'ENROLLMENT'",
                "INSERT INTO iam.sessions",
                "REVOKE ALL ON FUNCTION",
            ),
        ),
        (
            oidc_bundle,
            (
                "Anonymous LOGIN never creates an identity",
                'invitation.get("target_role") != "DEMAND_OWNER"',
                "OidcPostgresPurpose.ENROLLMENT",
                "OidcPostgresPurpose.STEP_UP",
            ),
        ),
        (
            oidc_tests,
            (
                "test_lost_enrollment_response_recovers_same_user_with_fresh_session",
                "test_lost_enrollment_commit_ack_recovers_without_duplicate_identity",
                "test_anonymous_org_admin_enrollment_is_rejected_without_partial_writes",
                "test_presenter_bundle_unknown_identity_is_atomically_rejected_after_one_exchange",
            ),
        ),
        (
            bundle_tests,
            (
                "test_anonymous_invitation_enrollment_creates_only_pending_identity_session",
                "test_anonymous_org_admin_enrollment_stays_closed_but_existing_user_step_up_remains_open",
            ),
        ),
        (
            web_flow,
            (
                'credentials: "same-origin"',
                "fresh HttpOnly OIDC binding cookie",
                "BFF strips any incoming",
            ),
        ),
        (
            web_proxy,
            (
                "const anonymousInvitation = validateOidcAuthorizationBody",
                'if (anonymousInvitation) headers.delete("cookie")',
            ),
        ),
    ):
        if any(marker not in source for marker in markers):
            failures.append("current-head-v18-enrollment-boundary-open")
            break
    for forbidden in (
        "INSERT INTO iam.memberships",
        "INSERT INTO iam.user_role_grants",
        "INSERT INTO iam.membership_role_grants",
    ):
        if forbidden in enrollment_sql:
            failures.append("current-head-v18-enrollment-authority-open")
            break

    failures.extend(
        _runbook_failures(_read(root / "docs/operations/current-head-v18.md"))
    )
    sidebar = _read(root / "docs/_sidebar.md")
    for marker in (
        "[Current-head v18 静态模式头](/operations/current-head-v18.md)",
        "[Current-head v17 静态模式头](/operations/current-head-v17.md)",
    ):
        if marker not in sidebar:
            failures.append("current-head-v18-sidebar-open")
            break

    v17_verifier = _read(root / "scripts/verify_current_head_v17.py")
    for marker in (
        "tests/deployment/fixtures/current-head-v17",
        "18|38|38|3|3|11|11|11|11|2|2",
        "583e4a03efec12b06c75710d0a6ccd7b79be18cb93f4faf58c207d228065c48d",
        "6b7623d36259e4db00de3ca83a0e0470173a16159432d099c6dc54e51cdcd2e7",
    ):
        if marker not in v17_verifier:
            failures.append("current-head-v17-frozen-pins-open")
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
