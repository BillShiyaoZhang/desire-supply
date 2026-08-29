#!/usr/bin/env python3
"""Read-only verifier for the Demand11 / Trust10 static current head."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Iterable


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
HEADS = "18|38|38|3|3|11|11|10|10|2|2"
IAM_COMBINED_SHA256 = "908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e"
PROFILE_MANIFEST_SHA256 = "4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa"
DEMAND_MANIFEST_SHA256 = "870f2b9d9862f75f4e7eaf01cc9f1d5f788b72fbf4f7ccf9056dfeff35969898"
DEMAND_SQL_SHA256 = "b9564fb7a9fbf9b7163a388e06431b4df11a3a01751a927c89c20377a07bcb3a"
DEMAND_DEPENDENCY_SHA256 = "cfab70770b908b37aa4865ba2f52d5b8f59492cbc7979867229e006e99cd8d87"
TRUST_MANIFEST_SHA256 = "d01be3288358965a07503b08e648be79eaf4a4493dfbf1c9e7f0c6f96c2ea683"
TRUST_SQL_SHA256 = "97f7b3bee6772277e19b1239711bc4ea907b4bb5598a8ffd3e2fc82c21e9c2e2"
TRUST_COMBINED_SHA256 = "364f22de931a0d3df11fedcdb20f3eaf84690a6649e99c9683af39b86547b93e"
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
SUCCESS = '{"status":"CURRENT_HEAD_V16_STATIC_VERIFIED"}'


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
    failures: list[str] = []
    begin = "<!-- BEGIN CURRENT_HEAD_V16_CONTRACT -->"
    end = "<!-- END CURRENT_HEAD_V16_CONTRACT -->"
    if value.count(begin) != 1 or value.count(end) != 1 or value.find(begin) >= value.find(end):
        return ("current-head-v16-markers-open",)
    required = (
        HEADS,
        EXPECTED_CONTRACTS,
        DEMAND_SQL_SHA256,
        TRUST_SQL_SHA256,
        "GET /v1/app/review-history",
        "VIEW_DEMAND_REVIEW_HISTORY",
        "reviewed_at DESC, review_id DESC",
        "STATIC VERIFIED",
        "NOT EXECUTED",
        "production_authorized=false",
        "tests/deployment/fixtures/current-head-v15/",
        "18|38|38|3|3|10|10|9|9|2|2",
        "current-head-v15.md",
        "python3 -B scripts/verify_current_head_v16.py",
    )
    if any(item not in value for item in required):
        failures.append("current-head-v16-contract-open")
    return _unique(failures)


def verify_repository(root: Path = REPOSITORY_ROOT) -> tuple[str, ...]:
    root = Path(root)
    failures: list[str] = []
    demand_root = root / "platform/src/desire_platform/demand/adapters/postgres/migrations"
    trust_root = root / "platform/src/desire_platform/trust_safety/adapters/postgres/migrations"
    v16_fixture_root = root / "tests/deployment/fixtures/current-head-v16"
    assets = (
        (v16_fixture_root / "demand-manifest.json", DEMAND_MANIFEST_SHA256),
        (demand_root / "0011_expand__reviewer_terminal_history.sql", DEMAND_SQL_SHA256),
        (v16_fixture_root / "trust-manifest.json", TRUST_MANIFEST_SHA256),
        (trust_root / "0010_expand__demand11_dependency_repin.sql", TRUST_SQL_SHA256),
        (
            v16_fixture_root / "trust-runner-pins.txt",
            "44e85d3f2c35e215acfe856d424930964d43650ae0fcf946aa011ec6dfd3df5e",
        ),
        (
            root / "tests/deployment/fixtures/current-head-v15/demand-manifest.json",
            "7695127a039fa71cddabd62318bea39337e3acbb4b1df66a3557b7a7ae3707b4",
        ),
        (
            root / "tests/deployment/fixtures/current-head-v15/trust-manifest.json",
            "8ef9c2321866e7509bf1a959acf64370fe74abb927635c0434618287a4348171",
        ),
        (
            root / "tests/deployment/fixtures/current-head-v15/trust-runner-pins.txt",
            "d3371e9d708ebca5e765e0fe20145ac170cb66ed00a4e8574c3b7115fc77bfca",
        ),
    )
    for path, expected in assets:
        if _sha(path) != expected:
            failures.append(f"current-head-v16-asset-mismatch:{path.relative_to(root)}")
    if _manifest_versions(
        v16_fixture_root / "demand-manifest.json", "demand"
    ) != tuple(range(1, 12)):
        failures.append("current-head-v16-demand-sequence-open")
    if _manifest_versions(
        v16_fixture_root / "trust-manifest.json", "trust"
    ) != tuple(range(1, 11)):
        failures.append("current-head-v16-trust-sequence-open")

    trust_runner = _read(v16_fixture_root / "trust-runner-pins.txt")
    for marker in (
        "TRUST_REQUIRED_IAM_SCHEMA_VERSION = 38",
        "TRUST_REQUIRED_DEMAND_SCHEMA_VERSION = 11",
        IAM_COMBINED_SHA256,
        DEMAND_DEPENDENCY_SHA256,
        TRUST_COMBINED_SHA256,
    ):
        if marker not in trust_runner:
            failures.append("current-head-v16-trust-runner-open")
            break

    history_sql = _read(demand_root / "0011_expand__reviewer_terminal_history.sql")
    history_contract = _read(
        root / "platform/src/desire_platform/internal_pilot/editor/contracts.py"
    )
    history_http = _read(
        root / "platform/src/desire_platform/internal_pilot/editor/http.py"
    )
    task_contract = _read(
        root / "platform/src/desire_platform/internal_pilot/task_discovery.py"
    )
    web_contract = _read(root / "web/lib/app-contract.mjs")
    for source, markers in (
        (history_sql, ("list_own_demand_review_history_v1", "status = 'COMPLETED'", "reviewer_user_id = exact_actor_user_id")),
        (history_contract, ("EditorReviewHistoryItemDto", "EditorReviewHistoryPageDto")),
        (history_http, ('path == "/v1/app/review-history"', "list_review_history")),
        (task_contract, ("VIEW_DEMAND_REVIEW_HISTORY", 'resource_path="/v1/app/review-history"')),
        (web_contract, ("parseEditorReviewHistoryEnvelope", "DEMAND_REVIEW_HISTORY")),
    ):
        if any(marker not in source for marker in markers):
            failures.append("current-head-v16-review-history-open")
            break

    failures.extend(
        _runbook_failures(_read(root / "docs/operations/current-head-v16.md"))
    )
    sidebar = _read(root / "docs/_sidebar.md")
    if "[Current-head v16 静态模式头](/operations/current-head-v16.md)" not in sidebar:
        failures.append("current-head-v16-sidebar-open")
    v15_verifier = _read(root / "scripts/verify_current_head_v15.py")
    for marker in (
        "tests/deployment/fixtures/current-head-v15/demand-manifest.json",
        "tests/deployment/fixtures/current-head-v15/trust-manifest.json",
        "tests/deployment/fixtures/current-head-v15/trust-runner-pins.txt",
        "18|38|38|3|3|10|10|9|9|2|2",
    ):
        if marker not in v15_verifier:
            failures.append("current-head-v15-frozen-pins-open")
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
