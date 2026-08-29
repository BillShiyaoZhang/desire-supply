from __future__ import annotations

from pathlib import Path

from desire_platform.demand.adapters.postgres.migrations import (
    DEMAND_MIGRATION_LAYOUT,
    DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
    DEMAND_SCHEMA_HEAD_VERSION,
    DemandMigrationPhase,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION = (
    PLATFORM_ROOT
    / "src/desire_platform/demand/adapters/postgres/migrations"
    / "0007_expand__owner_findings_and_finance_evidence.sql"
)
UOW = PLATFORM_ROOT / "src/desire_platform/demand/adapters/postgres/uow.py"
RULE_CATALOG = (
    PLATFORM_ROOT / "src/desire_platform/demand/adapters/postgres/rule_catalog.py"
)


def test_combined_projection_migration_remains_the_frozen_demand7_prefix() -> None:
    assert DEMAND_SCHEMA_HEAD_VERSION >= 8
    assert DEMAND_REQUIRED_IAM_SCHEMA_VERSION >= 36
    assert DEMAND_MIGRATION_LAYOUT[6] == (
        7,
        DemandMigrationPhase.EXPAND,
        "owner_findings_and_finance_evidence",
        "0007_expand__owner_findings_and_finance_evidence.sql",
    )


def test_writer_preflight_uses_catalog_contract_constants_without_version_literals() -> None:
    source = UOW.read_text(encoding="utf-8")
    assert "from .migrations.runner import (" in source
    assert "DEMAND_REQUIRED_IAM_SCHEMA_VERSION," in source
    assert "DEMAND_SCHEMA_HEAD_VERSION," in source
    assert "18, 6, 6, 6, 6, 31" not in source
    assert '("demand_matching", "demand_matching", 18, 6, 6, 31)' not in source

    catalog_source = RULE_CATALOG.read_text(encoding="utf-8")
    assert "from .migrations.runner import (" in catalog_source
    assert "DEMAND_REQUIRED_IAM_SCHEMA_VERSION," in catalog_source
    assert "DEMAND_SCHEMA_HEAD_VERSION," in catalog_source


def test_owner_findings_projection_is_exact_authorized_and_table_hidden() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    for marker in (
        "demand_api.read_demand_owner_findings_v1",
        "iam_api.resolve_demand_owner_authority_marker_v1",
        "INTO STRICT resolved_authority_marker_sha256",
        "session_user IS DISTINCT FROM 'demand_self'",
        "current_user IS DISTINCT FROM 'demand_schema_owner'",
        "'CREATE', 'CREATE_VERSION', 'SUBMIT', 'CANCEL_OWNER'",
        "rls_demand_owner_findings_root_definer",
        "rls_demand_owner_findings_review_definer",
        "ORDER BY review.reviewed_at, review.id",
        ") TO demand_self;",
    ):
        assert marker in sql
    assert "creator_user_id" not in sql
    assert "lock_demand_owner_authority_v1" not in sql
    assert "GRANT SELECT ON" not in sql


def test_finance_projection_is_immutable_synthetic_and_reauthorized() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    for marker in (
        "demand_api.read_manual_funding_evidence_v1",
        "iam_api.authorize_finance_funding_queue_v1",
        "iam_api.lock_finance_funding_authority_v1",
        "app.funding_review_id",
        "app.assignment_id",
        "review.demand_version_id",
        "version.id = review_row.demand_version_id",
        "planned_budget_minimum_amount_minor",
        "planned_budget_maximum_amount_minor",
        "planned_budget_direct_cost_amount_minor",
        "'NONE'::text",
        "INTERNAL_SANDBOX_ZERO_FUNDS_V1",
        "NO_REAL_FUNDS_OR_PAYMENT",
        ") TO demand_finance;",
    ):
        assert marker in sql
    assert "target_status" not in sql
    assert "target_revision" not in sql
    assert "root.current_version_id" not in sql
    assert "root.aggregate_version" not in sql
    assert "EXECUTE format" not in sql
