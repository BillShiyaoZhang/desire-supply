from __future__ import annotations

import hashlib
from pathlib import Path
import re

from desire_platform.demand.adapters.postgres.migrations import (
    DEMAND_MIGRATION_LAYOUT,
    DEMAND_REVIEWED_MANIFEST_SHA256,
    DEMAND_SCHEMA_HEAD_VERSION,
    DemandMigrationCatalog,
    DemandMigrationPhase,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT / "src/desire_platform/demand/adapters/postgres/migrations"
)
MIGRATION = MIGRATION_ROOT / "0012_expand__finance_funding_terminal_history.sql"


def test_demand12_remains_the_byte_exact_historical_prefix() -> None:
    catalog = DemandMigrationCatalog.load(MIGRATION_ROOT)
    descriptor = catalog.artifacts[11].descriptor

    assert DEMAND_SCHEMA_HEAD_VERSION >= 12
    assert DEMAND_MIGRATION_LAYOUT[11] == (
        12,
        DemandMigrationPhase.EXPAND,
        "finance_funding_terminal_history",
        MIGRATION.name,
    )
    assert descriptor.checksum_sha256.hex() == (
        "bf76efd70f95a4fa4c49ad43ad03fc9d31e5009bce88364bec851f68b0313280"
    )
    assert hashlib.sha256(MIGRATION.read_bytes()).digest() == (
        descriptor.checksum_sha256
    )
    assert descriptor.prefix_manifest_sha256.hex() == (
        "919d62a9b32dc29619a561940f9c79e21700562a0cdd9ef7e9f13a40cea43345"
    )
    assert catalog.manifest_sha256 == DEMAND_REVIEWED_MANIFEST_SHA256
    assert catalog.manifest_sha256 != descriptor.prefix_manifest_sha256


def test_history_is_current_duty_actor_owned_terminal_and_keyset_paged() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")

    for marker in (
        "session_user IS DISTINCT FROM 'demand_finance'",
        "current_user IS DISTINCT FROM 'demand_schema_owner'",
        "IS DISTINCT FROM 'LIST_FUNDING_REVIEWS'",
        "iam_api.authorize_finance_funding_queue_v1",
        "'app.operation', 'LIST_FUNDING_REVIEW_HISTORY'",
        "assignment.actor_user_id = exact_actor_user_id",
        "assignment.status = 'COMPLETED'",
        "assignment.completed_at IS NOT NULL",
        "review.status IN ('SECURED', 'DISCREPANCY', 'REJECTED')",
        "confirmation.actor_user_id = exact_actor_user_id",
        "finding.actor_user_id = exact_actor_user_id",
        "assignment.completed_at < cursor_completed_at",
        "review.id < cursor_funding_review_id",
        "ORDER BY assignment.completed_at DESC, review.id DESC",
        "LIMIT maximum_items + 1",
        "TO demand_finance",
    ):
        assert marker in sql

    assert sql.count("CREATE POLICY rls_finance_funding_history_") == 4
    assert (
        "GRANT EXECUTE ON FUNCTION "
        "demand_api.list_manual_funding_review_history_v1"
    ) in sql
    assert "TO demand_self" not in sql.split("GRANT EXECUTE ON FUNCTION", 1)[1]
    assert "EXECUTE format" not in sql
    assert "EXECUTE IMMEDIATE" not in sql


def test_history_projection_is_only_the_five_terminal_review_facts() -> None:
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
        "funding_review_id",
        "demand_id",
        "demand_version_id",
        "status",
        "completed_at",
    )
    assert not set(names).intersection(
        {
            "actor_user_id",
            "session_id",
            "organization_id",
            "assignment_id",
            "confirmation_id",
            "finding_id",
            "authority_marker_sha256",
            "evidence_reference_sha256",
            "reason_codes",
            "required_field_codes",
        }
    )
