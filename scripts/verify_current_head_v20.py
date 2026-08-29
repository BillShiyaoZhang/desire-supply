#!/usr/bin/env python3
"""Read-only verifier for the IAM41 / Demand11 / Trust14 static head."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Iterable


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
HEADS = "18|41|41|3|3|11|11|14|14|2|2"
IAM_MANIFEST_SHA256 = "dc54ab65fffba8e55cc4dbd82c7c0effe044820a5387952d23893275f5ad74ac"
IAM_COMBINED_SHA256 = "b46a3a5592eb68af01b3a87cb86fb4970f9678ec54f8beffb3e9c6c926a032dd"
IAM_SQL_SHA256 = "74a2fc9ce455ad737df2086f04af3f0de5b659e3902fb71d6c0007c0e185a415"
PROFILE_MANIFEST_SHA256 = "4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa"
DEMAND_MANIFEST_SHA256 = "870f2b9d9862f75f4e7eaf01cc9f1d5f788b72fbf4f7ccf9056dfeff35969898"
DEMAND_DEPENDENCY_SHA256 = "cfab70770b908b37aa4865ba2f52d5b8f59492cbc7979867229e006e99cd8d87"
TRUST_API_SHA256 = "a9923573365f1023aff3e4aaebb0b7e656c80eab7e721bbf30d9e9b038782f25"
TRUST_SQL_SHA256 = "d65a1823192164fa174875d8e76051549fb4f8ff22fdc97ab742c8d00eb3f4e2"
TRUST_MANIFEST_SHA256 = "7aa1b1533e1e23bdef9233c49aeffe9dbca172ad1d825ccdd0925e8c6a823cca"
TRUST_COMBINED_SHA256 = "f56404d56f8af5dc08ea7cd5e92d2c6f7719c56a3dae3bde89f140b604691980"
TAXONOMY_MANIFEST_SHA256 = "74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622"
EXPECTED_CONTRACTS = "|".join((
    IAM_COMBINED_SHA256,
    PROFILE_MANIFEST_SHA256,
    DEMAND_MANIFEST_SHA256,
    "41",
    "11",
    IAM_COMBINED_SHA256,
    DEMAND_DEPENDENCY_SHA256,
    TRUST_COMBINED_SHA256,
    TRUST_MANIFEST_SHA256,
    TAXONOMY_MANIFEST_SHA256,
))
SUCCESS = '{"status":"CURRENT_HEAD_V20_STATIC_VERIFIED"}'


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
    begin = "<!-- BEGIN CURRENT_HEAD_V20_CONTRACT -->"
    end = "<!-- END CURRENT_HEAD_V20_CONTRACT -->"
    if (
        value.count(begin) != 1
        or value.count(end) != 1
        or value.find(begin) >= value.find(end)
    ):
        return ("current-head-v20-markers-open",)
    required = (
        HEADS,
        EXPECTED_CONTRACTS,
        IAM_SQL_SHA256,
        IAM_MANIFEST_SHA256,
        TRUST_SQL_SHA256,
        "ACTIVE invitee",
        "second authority",
        "full canonical MeDto",
        "aggregate_version",
        "authorization ETag",
        "PENDING_ENROLLMENT",
        "AcceptAccessInvitation",
        "exact invitation",
        "receipt replay",
        "Session rotation",
        "zero authority",
        "STATIC VERIFIED",
        "NOT EXECUTED",
        "production_authorized=false",
        "tests/deployment/fixtures/current-head-v20/",
        "tests/deployment/fixtures/current-head-v19/",
        "18|40|40|3|3|11|11|13|13|2|2",
        "current-head-v19.md",
        "python3 -B scripts/verify_current_head_v20.py",
    )
    if any(marker not in value for marker in required):
        return ("current-head-v20-contract-open",)
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
    fixture_root = root / "tests/deployment/fixtures/current-head-v20"
    v19_root = root / "tests/deployment/fixtures/current-head-v19"
    assets = (
        (fixture_root / "iam-manifest.json", IAM_MANIFEST_SHA256),
        (fixture_root / "demand-manifest.json", DEMAND_MANIFEST_SHA256),
        (fixture_root / "trust-manifest.json", TRUST_MANIFEST_SHA256),
        (
            fixture_root / "trust-runner-pins.txt",
            "fe58fe95ece1945fa5a5f68246740be282cde57234e792eb7343cd409402ca5b",
        ),
        (iam_root / "0041_expand__acceptance_canonical_me_snapshot.sql", IAM_SQL_SHA256),
        (profile_root / "manifest.json", PROFILE_MANIFEST_SHA256),
        (trust_root / "0014_expand__iam41_dependency_repin.sql", TRUST_SQL_SHA256),
        (taxonomy_root / "manifest.json", TAXONOMY_MANIFEST_SHA256),
        (root / "platform/contracts/api/trust-v1.openapi.yaml", TRUST_API_SHA256),
        (
            v19_root / "iam-manifest.json",
            "e9e571dcb16928c21ab26b9dca5cacc299f9cc5427dd18383af87867ccca5c40",
        ),
        (
            v19_root / "demand-manifest.json",
            DEMAND_MANIFEST_SHA256,
        ),
        (
            v19_root / "trust-manifest.json",
            "c438a3fac4d9dea850089b8a14f92ab34a5c5a592b9babcb770860d3ecc513d8",
        ),
        (
            v19_root / "trust-runner-pins.txt",
            "56ad6e288ce788eaef9e37ba5eebe5496f3e253837582f513687ea6cb5f789de",
        ),
    )
    for path, expected in assets:
        if _sha(path) != expected:
            failures.append(
                f"current-head-v20-asset-mismatch:{path.relative_to(root)}"
            )

    if _manifest_versions(fixture_root / "iam-manifest.json", "iam") != tuple(
        range(42)
    ):
        failures.append("current-head-v20-iam-sequence-open")
    if _manifest_versions(
        fixture_root / "demand-manifest.json", "demand"
    ) != tuple(range(1, 12)):
        failures.append("current-head-v20-demand-sequence-open")
    if _manifest_versions(
        fixture_root / "trust-manifest.json", "trust"
    ) != tuple(range(1, 15)):
        failures.append("current-head-v20-trust-sequence-open")
    frozen_runner = _read(fixture_root / "trust-runner-pins.txt")
    for marker in (
        "TRUST_REQUIRED_IAM_SCHEMA_VERSION = 41",
        "TRUST_REQUIRED_DEMAND_SCHEMA_VERSION = 11",
        IAM_COMBINED_SHA256,
        DEMAND_DEPENDENCY_SHA256,
        TRUST_API_SHA256,
        TRUST_COMBINED_SHA256,
    ):
        if marker not in frozen_runner:
            failures.append("current-head-v20-frozen-runner-open")
            break

    snapshot_sql = _read(
        iam_root / "0041_expand__acceptance_canonical_me_snapshot.sql"
    )
    static_tests = _read(
        root
        / "platform/tests/storage/postgres/"
        "test_iam41_acceptance_canonical_me_snapshot_static.py"
    )
    acceptance_adapter = _read(
        root
        / "platform/src/desire_platform/identity_access/adapters/postgres/"
        "accept_access_invitation.py"
    )
    projection_tests = _read(
        root
        / "platform/tests/storage/postgres/"
        "test_accept_access_invitation_response_projection.py"
    )
    uow_tests = _read(
        root
        / "platform/tests/storage/postgres/test_accept_access_invitation_uow_red.py"
    )
    for source, markers in (
        (
            snapshot_sql,
            (
                "iam_api.read_acceptance_me_snapshot_v2()",
                "SECURITY DEFINER",
                "iam_self_summary_reader",
                "session_user = 'iam_onboarding'",
                "current_user = 'iam_self_summary_reader'",
                "receipt.status = 'IN_PROGRESS'",
                "invitation.status = 'ACCEPTED'",
                "accepted_by_user_id",
                "'user_role_grants'",
                "'memberships'",
                "'policies'",
                "REVOKE ALL ON FUNCTION",
            ),
        ),
        (
            static_tests,
            (
                "test_snapshot_context_binds_the_in_progress_receipt_and_post_write_state",
                "test_snapshot_rls_is_actor_scoped_across_the_complete_authority_graph",
                "test_snapshot_shape_matches_the_canonical_me_projector_facts",
            ),
        ),
        (
            acceptance_adapter,
            (
                "AcceptWriteCheckpoint.USER_ACTIVATE_OR_GATE_VERSION",
                "UPDATE iam.users SET aggregate_version=aggregate_version+1",
                '"PolicyRequirementsSatisfied"',
                "SELECT iam_api.read_acceptance_me_snapshot_v2()",
                "project_canonical_me_dto",
            ),
        ),
        (
            projection_tests,
            (
                "test_post_write_snapshot_uses_the_canonical_full_me_projector",
                "test_new_authority_projects_its_satisfied_policy_requirement",
            ),
        ),
        (
            uow_tests,
            (
                "test_active_user_accepts_non_initial_active_organization_invitation",
                'expected_user_version = 3 if fixture.kind == "member" else 2',
                "test_iam40_exact_pending_enrollment_resolves_and_accepts_membership",
                "test_iam40_pending_enrollment_is_closed_for_every_inexact_shape",
            ),
        ),
    ):
        if any(marker not in source for marker in markers):
            failures.append("current-head-v20-acceptance-snapshot-open")
            break
    for forbidden in ("CREATE TABLE", "ALTER TABLE", "DROP TABLE"):
        if forbidden in snapshot_sql.upper():
            failures.append("current-head-v20-forward-only-open")
            break

    failures.extend(
        _runbook_failures(_read(root / "docs/operations/current-head-v20.md"))
    )
    sidebar = _read(root / "docs/_sidebar.md")
    for marker in (
        "[Current-head v20 静态模式头](/operations/current-head-v20.md)",
        "[Current-head v19 静态模式头](/operations/current-head-v19.md)",
    ):
        if marker not in sidebar:
            failures.append("current-head-v20-sidebar-open")
            break

    v19_verifier = _read(root / "scripts/verify_current_head_v19.py")
    for marker in (
        "tests/deployment/fixtures/current-head-v19",
        "18|40|40|3|3|11|11|13|13|2|2",
        "e9e571dcb16928c21ab26b9dca5cacc299f9cc5427dd18383af87867ccca5c40",
        "c438a3fac4d9dea850089b8a14f92ab34a5c5a592b9babcb770860d3ecc513d8",
    ):
        if marker not in v19_verifier:
            failures.append("current-head-v19-frozen-pins-open")
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
