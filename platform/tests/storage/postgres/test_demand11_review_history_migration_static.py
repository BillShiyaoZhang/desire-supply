from __future__ import annotations

import hashlib
from pathlib import Path
import re

from desire_platform.demand.adapters.postgres.migrations import (
    DEMAND_MIGRATION_LAYOUT,
    DemandMigrationCatalog,
    DemandMigrationPhase,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT / "src/desire_platform/demand/adapters/postgres/migrations"
)
MIGRATION = MIGRATION_ROOT / "0011_expand__reviewer_terminal_history.sql"


def test_demand11_is_byte_exact_reviewed_prefix() -> None:
    catalog = DemandMigrationCatalog.load(MIGRATION_ROOT)
    demand11 = catalog.artifacts[10]

    assert DEMAND_MIGRATION_LAYOUT[10] == (
        11,
        DemandMigrationPhase.EXPAND,
        "reviewer_terminal_history",
        MIGRATION.name,
    )
    assert demand11.descriptor.checksum_sha256 == hashlib.sha256(
        MIGRATION.read_bytes()
    ).digest()
    assert demand11.descriptor.checksum_sha256.hex() == (
        "b9564fb7a9fbf9b7163a388e06431b4df11a3a01751a927c89c20377a07bcb3a"
    )
    assert demand11.descriptor.prefix_manifest_sha256.hex() == (
        "870f2b9d9862f75f4e7eaf01cc9f1d5f788b72fbf4f7ccf9056dfeff35969898"
    )


def test_history_function_is_self_terminal_keyset_and_execute_is_role_closed() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    for marker in (
        "session_user IS DISTINCT FROM 'demand_review'",
        "iam_api.authorize_demand_review_queue_v1",
        "PERFORM set_config('app.operation', 'LIST_REVIEW_HISTORY', true)",
        "reviewer_user_id = exact_actor_user_id",
        "assignment.status = 'COMPLETED'",
        "assignment.completed_at IS NOT NULL",
        "review.decision IN ('NEEDS_CHANGES', 'VERIFIED')",
        "review.reviewed_at < cursor_reviewed_at",
        "review.id < cursor_review_id",
        "ORDER BY review.reviewed_at DESC, review.id DESC",
        "LIMIT maximum_items + 1",
        "TO demand_review",
    ):
        assert marker in sql
    assert "GRANT EXECUTE ON FUNCTION demand_api.list_own_demand_review_history_v1" in sql
    assert "EXECUTE format" not in sql
    assert "EXECUTE IMMEDIATE" not in sql


def test_history_return_projection_has_only_the_nine_review_facts() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    match = re.search(
        r"RETURNS TABLE \((.*?)\)\s*LANGUAGE plpgsql",
        sql,
        flags=re.DOTALL,
    )
    assert match is not None
    names = tuple(
        line.strip().split()[0].rstrip(",")
        for line in match.group(1).splitlines()
        if line.strip()
    )
    assert names == (
        "review_id",
        "demand_id",
        "demand_version_id",
        "decision",
        "reason_codes",
        "required_field_codes",
        "budget_health_code",
        "risk_code",
        "reviewed_at",
    )
    assert not set(names).intersection(
        {
            "content",
            "organization_id",
            "owner_user_id",
            "reviewer_user_id",
            "duty_grant_id",
            "authority",
            "raw_hash",
            "note",
        }
    )
