from __future__ import annotations

import hashlib
from pathlib import Path

from desire_platform.trust_safety.adapters.postgres.migrations import (
    TRUST_MIGRATION_LAYOUT,
    TRUST_SCHEMA_HEAD_VERSION,
    TrustMigrationCatalog,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/trust_safety/adapters/postgres/migrations"
)
MIGRATION = (
    MIGRATION_ROOT
    / "0011_expand__completed_case_assignment_discovery.sql"
)


def test_trust11_catalog_and_contract_pins_are_exact() -> None:
    catalog = TrustMigrationCatalog.load(MIGRATION_ROOT)

    assert TRUST_SCHEMA_HEAD_VERSION >= 11
    assert TRUST_MIGRATION_LAYOUT[10][2:] == (
        "completed_case_assignment_discovery",
        MIGRATION.name,
    )
    assert hashlib.sha256(MIGRATION.read_bytes()).hexdigest() == (
        "6add361aeeca276b6b0a2d3ba4b7f27dd92e57335b076d0b985b5b8a936393ac"
    )
    assert catalog.artifacts[10].descriptor.prefix_manifest_sha256.hex() == (
        "6b7623d36259e4db00de3ca83a0e0470173a16159432d099c6dc54e51cdcd2e7"
    )


def test_trust11_history_is_actor_bound_and_projection_is_party_safe() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")

    for marker in (
        "CREATE POLICY rls_trust_my_completed_case_assignments_select_v1",
        "CREATE POLICY rls_trust_my_completed_case_roots_select_v1",
        "CREATE POLICY rls_trust_my_completed_case_outcomes_select_v1",
        "CREATE FUNCTION trust_api.list_my_completed_case_assignments_v1(",
        "TRUST_MY_COMPLETED_ASSIGNMENTS_READ",
        "officer_user_id::text",
        "decided_by_user_id::text",
        "assignment.assignment_id = outcome.decision_assignment_id",
        "assignment.assignment_purpose_code = 'CASE_TRIAGE'",
        "assignment.hold_id IS NULL",
        "LIMIT exact_limit + 1",
        "ORDER BY outcome.decided_at DESC, outcome.case_id DESC",
        "ORDER BY decided_at DESC, case_id DESC",
        "'has_more', document.has_more",
        "GRANT EXECUTE ON FUNCTION trust_api.list_my_completed_case_assignments_v1(",
    ):
        assert marker in sql

    projection_start = sql.index("jsonb_build_object(\n                'case_id'")
    projection_end = sql.index(") AS item", projection_start)
    item_projection = sql[projection_start:projection_end]
    assert set(("'case_id'", "'decided_at'", "'outcome_code'")) <= {
        token.strip().split(",")[0]
        for token in item_projection.splitlines()
        if token.strip().startswith("'")
    }
    for forbidden in (
        "reporter_user_id",
        "organization_id",
        "report_id",
        "demand_id",
        "assignment_id",
        "evidence",
        "reason_codes",
        "action_codes",
        "sealed_note",
        "restricted",
    ):
        assert forbidden not in item_projection


def test_trust11_preserves_exact_prior_baseline_and_advances_only_trust_head() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")

    for marker in (
        "schema_head_version = 10",
        "min_app_compatible_version = 10",
        "max_app_compatible_version = 10",
        "schema_head_version = 11",
        "min_app_compatible_version = 11",
        "max_app_compatible_version = 11",
        "required_iam_schema_version = 38",
        "required_demand_schema_version = 11",
        "364f22de931a0d3df11fedcdb20f3eaf84690a6649e99c9683af39b86547b93e",
        "d01be3288358965a07503b08e648be79eaf4a4493dfbf1c9e7f0c6f96c2ea683",
        "desire:trust:combined-contract:v2",
    ):
        assert marker in sql
