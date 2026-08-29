#!/usr/bin/env python3
"""Read-only verifier for the Demand11 / Trust11 static current head."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Iterable


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
HEADS = "18|38|38|3|3|11|11|11|11|2|2"
IAM_COMBINED_SHA256 = "908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e"
PROFILE_MANIFEST_SHA256 = "4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa"
DEMAND_MANIFEST_SHA256 = "870f2b9d9862f75f4e7eaf01cc9f1d5f788b72fbf4f7ccf9056dfeff35969898"
DEMAND_DEPENDENCY_SHA256 = "cfab70770b908b37aa4865ba2f52d5b8f59492cbc7979867229e006e99cd8d87"
TRUST_API_SHA256 = "a9923573365f1023aff3e4aaebb0b7e656c80eab7e721bbf30d9e9b038782f25"
TRUST_MANIFEST_SHA256 = "6b7623d36259e4db00de3ca83a0e0470173a16159432d099c6dc54e51cdcd2e7"
TRUST_SQL_SHA256 = "6add361aeeca276b6b0a2d3ba4b7f27dd92e57335b076d0b985b5b8a936393ac"
TRUST_COMBINED_SHA256 = "583e4a03efec12b06c75710d0a6ccd7b79be18cb93f4faf58c207d228065c48d"
TAXONOMY_MANIFEST_SHA256 = "74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622"
EXPECTED_CONTRACTS = "|".join((
    IAM_COMBINED_SHA256,
    PROFILE_MANIFEST_SHA256,
    DEMAND_MANIFEST_SHA256,
    "38",
    "11",
    IAM_COMBINED_SHA256,
    DEMAND_DEPENDENCY_SHA256,
    TRUST_COMBINED_SHA256,
    TRUST_MANIFEST_SHA256,
    TAXONOMY_MANIFEST_SHA256,
))
SUCCESS = '{"status":"CURRENT_HEAD_V17_STATIC_VERIFIED"}'


def _read(path: Path) -> str:
    try:
        if path.is_symlink() or not path.is_file():
            return ""
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return ""


def _sha(path: Path) -> str | None:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


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
    begin = "<!-- BEGIN CURRENT_HEAD_V17_CONTRACT -->"
    end = "<!-- END CURRENT_HEAD_V17_CONTRACT -->"
    if (
        value.count(begin) != 1
        or value.count(end) != 1
        or value.find(begin) >= value.find(end)
    ):
        return ("current-head-v17-markers-open",)
    required = (
        HEADS,
        EXPECTED_CONTRACTS,
        TRUST_SQL_SHA256,
        "list_my_completed_case_assignments_v1",
        "VIEW_TRUST_CASE_HISTORY",
        "case_id,decided_at,outcome_code",
        "STATIC VERIFIED",
        "NOT EXECUTED",
        "production_authorized=false",
        "tests/deployment/fixtures/current-head-v17/",
        "tests/deployment/fixtures/current-head-v16/",
        "18|38|38|3|3|11|11|10|10|2|2",
        "current-head-v16.md",
        "python3 -B scripts/verify_current_head_v17.py",
    )
    if any(marker not in value for marker in required):
        return ("current-head-v17-contract-open",)
    return ()


def verify_repository(root: Path = REPOSITORY_ROOT) -> tuple[str, ...]:
    root = Path(root)
    failures: list[str] = []
    trust_root = root / "platform/src/desire_platform/trust_safety/adapters/postgres/migrations"
    v17_root = root / "tests/deployment/fixtures/current-head-v17"
    v16_root = root / "tests/deployment/fixtures/current-head-v16"
    assets = (
        (v17_root / "demand-manifest.json", DEMAND_MANIFEST_SHA256),
        (v17_root / "trust-manifest.json", TRUST_MANIFEST_SHA256),
        (
            v17_root / "trust-runner-pins.txt",
            "df9ab47f7c792c5c41915e330702c7e8e9ea9a208e488891fea22e8a914e7816",
        ),
        (
            trust_root / "0011_expand__completed_case_assignment_discovery.sql",
            TRUST_SQL_SHA256,
        ),
        (
            v16_root / "demand-manifest.json",
            DEMAND_MANIFEST_SHA256,
        ),
        (
            v16_root / "trust-manifest.json",
            "d01be3288358965a07503b08e648be79eaf4a4493dfbf1c9e7f0c6f96c2ea683",
        ),
        (
            v16_root / "trust-runner-pins.txt",
            "44e85d3f2c35e215acfe856d424930964d43650ae0fcf946aa011ec6dfd3df5e",
        ),
    )
    for path, expected in assets:
        if _sha(path) != expected:
            failures.append(f"current-head-v17-asset-mismatch:{path.relative_to(root)}")

    if _manifest_versions(v17_root / "demand-manifest.json", "demand") != tuple(
        range(1, 12)
    ):
        failures.append("current-head-v17-demand-sequence-open")
    if _manifest_versions(v17_root / "trust-manifest.json", "trust") != tuple(
        range(1, 12)
    ):
        failures.append("current-head-v17-trust-sequence-open")
    if _manifest_versions(v16_root / "trust-manifest.json", "trust") != tuple(
        range(1, 11)
    ):
        failures.append("current-head-v16-trust-sequence-open")

    runner = _read(v17_root / "trust-runner-pins.txt")
    for marker in (
        "TRUST_REQUIRED_IAM_SCHEMA_VERSION = 38",
        "TRUST_REQUIRED_DEMAND_SCHEMA_VERSION = 11",
        IAM_COMBINED_SHA256,
        DEMAND_DEPENDENCY_SHA256,
        TRUST_API_SHA256,
        TRUST_COMBINED_SHA256,
    ):
        if marker not in runner:
            failures.append("current-head-v17-trust-runner-open")
            break

    history_sql = _read(
        trust_root / "0011_expand__completed_case_assignment_discovery.sql"
    )
    task_contract = _read(
        root / "platform/src/desire_platform/internal_pilot/task_discovery.py"
    )
    trust_gateway = _read(
        root
        / "platform/src/desire_platform/trust_safety/adapters/postgres/gateway.py"
    )
    web_contract = _read(root / "web/lib/app-contract.mjs")
    for source, markers in (
        (
            history_sql,
            (
                "list_my_completed_case_assignments_v1",
                "TRUST_MY_COMPLETED_ASSIGNMENTS_READ",
                "officer_user_id::text",
                "decided_by_user_id::text",
                "assignment.assignment_id = outcome.decision_assignment_id",
                "assignment.assignment_purpose_code = 'CASE_TRIAGE'",
                "assignment.hold_id IS NULL",
                "REVOKE ALL ON FUNCTION",
            ),
        ),
        (
            task_contract,
            (
                "MY_COMPLETED_CASE_ASSIGNMENTS",
                "list_my_completed_case_assignments",
                "VIEW_TRUST_CASE_HISTORY",
            ),
        ),
        (
            trust_gateway,
            (
                "list_my_completed_case_assignments",
                "trust_api.list_my_completed_case_assignments_v1(%s,%s,%s)",
            ),
        ),
        (web_contract, ("VIEW_TRUST_CASE_HISTORY", "TRUST_CASE_DETAIL")),
    ):
        if any(marker not in source for marker in markers):
            failures.append("current-head-v17-trust-history-open")
            break

    failures.extend(
        _runbook_failures(_read(root / "docs/operations/current-head-v17.md"))
    )
    sidebar = _read(root / "docs/_sidebar.md")
    for marker in (
        "[Current-head v17 静态模式头](/operations/current-head-v17.md)",
        "[Current-head v16 静态模式头](/operations/current-head-v16.md)",
    ):
        if marker not in sidebar:
            failures.append("current-head-v17-sidebar-open")
            break

    v16_verifier = _read(root / "scripts/verify_current_head_v16.py")
    for marker in (
        "tests/deployment/fixtures/current-head-v16",
        "18|38|38|3|3|11|11|10|10|2|2",
        "364f22de931a0d3df11fedcdb20f3eaf84690a6649e99c9683af39b86547b93e",
        "d01be3288358965a07503b08e648be79eaf4a4493dfbf1c9e7f0c6f96c2ea683",
    ):
        if marker not in v16_verifier:
            failures.append("current-head-v16-frozen-pins-open")
            break
    return _unique(failures)


def main(argv: tuple[str, ...] | None = None) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    if arguments:
        print('{"failures":["arguments-forbidden"],"status":"BLOCKED"}', file=sys.stderr)
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
