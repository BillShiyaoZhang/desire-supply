"""IAM37 REDs for distinct manual-funding review authority operations.

IAM31 remains the frozen CLAIM/CONFIRM ABI.  IAM37 may only extend the
finance context and publish a new exact-resource v2 lock for assignment
release and finding submission.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from desire_platform.identity_access.adapters.postgres.migrations import (
    IAM_MIGRATION_LAYOUT,
    IAM_SCHEMA_HEAD_VERSION,
    MigrationPhase,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
IAM31 = MIGRATION_ROOT / "0031_expand__finance_funding_authority_and_accounts.sql"
IAM36 = MIGRATION_ROOT / "0036_expand__trust_appeal_authority_and_current_logout.sql"
IAM37 = MIGRATION_ROOT / "0037_expand__finance_funding_review_authority_v2.sql"
PRODUCTION_PLAN = (
    PLATFORM_ROOT / "src/desire_platform/internal_pilot/production_plan.py"
)
DEMAND_RUNNER = (
    PLATFORM_ROOT
    / "src/desire_platform/demand/adapters/postgres/migrations/runner.py"
)
TRUST_RUNNER = (
    PLATFORM_ROOT
    / "src/desire_platform/trust_safety/adapters/postgres/migrations/runner.py"
)


def _function_body(sql: str, signature: str) -> str:
    start = sql.index(signature)
    body_start = sql.index("AS $function$", start)
    return sql[body_start : sql.index("$function$;", body_start)]


def test_iam37_is_one_forward_only_head_and_preserves_frozen_bytes() -> None:
    assert hashlib.sha256(IAM31.read_bytes()).hexdigest() == (
        "6997940b66becb5f0740f4e8f27ca1f5aa4939734e65c2f2e8c5f3f0f1bd94f2"
    )
    assert hashlib.sha256(IAM36.read_bytes()).hexdigest() == (
        "e194727b4c70312d2add67cdf0dc4964bbd1cbbcc8b8c3e1778bc9a60126b5c1"
    )
    assert IAM_SCHEMA_HEAD_VERSION >= 37
    assert [item[0] for item in IAM_MIGRATION_LAYOUT[:38]] == list(range(38))
    assert IAM_MIGRATION_LAYOUT[37] == (
        37,
        MigrationPhase.EXPAND,
        "finance_funding_review_authority_v2",
        "0037_expand__finance_funding_review_authority_v2.sql",
    )


def test_iam37_publishes_two_distinct_exact_resource_operations_only() -> None:
    sql = IAM37.read_text(encoding="utf-8")
    context = _function_body(
        sql,
        "CREATE OR REPLACE FUNCTION iam.finance_funding_authority_context_v1()",
    )
    lock = _function_body(
        sql,
        "CREATE FUNCTION iam_api.lock_finance_funding_authority_v2(",
    )

    operations = (
        "RELEASE_FUNDING_REVIEW_ASSIGNMENT",
        "SUBMIT_FUNDING_REVIEW_FINDING",
    )
    for operation in operations:
        assert f"'{operation}'" in context
        assert f"'{operation}'" in lock

    for forbidden_alias in (
        "RELEASE_ASSIGNMENT",
        "SUBMIT_FINDING",
        "REJECT_FUNDING_REVIEW",
        "CONFIRM_FUNDING_REVIEW",
    ):
        assert f"'{forbidden_alias}'" not in lock

    for parameter in (
        "candidate_actor_user_id uuid",
        "candidate_session_id uuid",
        "candidate_organization_id uuid",
        "candidate_demand_id uuid",
        "candidate_funding_review_id uuid",
        "candidate_assignment_id uuid",
        "candidate_operation text",
        "expected_principal_marker_sha256 bytea",
    ):
        assert parameter in sql

    for exact_setting in (
        "app.actor_id",
        "app.session_id",
        "app.organization_id",
        "app.demand_id",
        "app.funding_review_id",
        "app.assignment_id",
        "app.operation",
    ):
        assert exact_setting in lock

    assert "iam-finance-funding-authority-v2|" in lock
    assert lock.index("candidate_funding_review_id::text") < lock.index(
        "candidate_assignment_id::text"
    )
    assert "expected_principal_marker_sha256" in lock
    assert "FOR UPDATE" in lock


def test_iam37_keeps_v1_acl_and_closes_v2_to_schema_owner() -> None:
    iam31 = IAM31.read_text(encoding="utf-8")
    iam37 = IAM37.read_text(encoding="utf-8")
    compact = " ".join(iam37.split())

    assert "CREATE OR REPLACE FUNCTION iam_api.lock_finance_funding_authority_v1" not in iam37
    assert "lock_finance_funding_authority_v1" in iam31
    assert (
        "REVOKE ALL ON FUNCTION iam_api.lock_finance_funding_authority_v2( "
        "uuid, uuid, uuid, uuid, uuid, uuid, text, bytea ) "
        "FROM PUBLIC, demand_finance;"
    ) in compact
    assert (
        "GRANT EXECUTE ON FUNCTION iam_api.lock_finance_funding_authority_v2( "
        "uuid, uuid, uuid, uuid, uuid, uuid, text, bytea ) "
        "TO demand_schema_owner;"
    ) in compact
    assert "GRANT SELECT ON TABLE iam." not in iam37
    assert "EXECUTE format" not in iam37
    assert "EXECUTE IMMEDIATE" not in iam37


def test_iam37_locks_context_owner_namespace_acl_and_proconfig() -> None:
    sql = IAM37.read_text(encoding="utf-8")
    assertions = sql[sql.index("DO $assertions$") :]
    compact = " ".join(assertions.split())

    for required in (
        "namespace.nspname = 'iam'",
        "procedure.proname = 'finance_funding_authority_context_v1'",
        "procedure.pronargs = 0",
        "procedure.prorettype = 'boolean'::pg_catalog.regtype",
        "owner_role.rolname = 'schema_owner'",
        "NOT procedure.prosecdef",
        "procedure.provolatile = 's'",
        "procedure.proparallel = 'u'",
        "ARRAY['search_path=pg_catalog']::text[]",
    ):
        assert required in assertions

    for role, expected in (
        ("schema_owner", "NOT"),
        ("demand_schema_owner", ""),
        ("demand_finance", ""),
    ):
        needle = (
            f"{expected} pg_catalog.has_function_privilege( "
            f"'{role}', 'iam.finance_funding_authority_context_v1()', "
            "'EXECUTE' )"
        ).strip()
        assert needle in compact


def test_iam37_contract_is_retained_while_runtime_heads_advance() -> None:
    production = PRODUCTION_PLAN.read_text(encoding="utf-8")
    demand = DEMAND_RUNNER.read_text(encoding="utf-8")
    trust = TRUST_RUNNER.read_text(encoding="utf-8")

    assert "IAM_SCHEMA_HEAD_VERSION != 47" in production
    assert "DEMAND_REQUIRED_IAM_SCHEMA_VERSION = 45" in demand
    assert "lock_finance_funding_authority_v2" in demand
    assert "TRUST_REQUIRED_IAM_SCHEMA_VERSION = 47" in trust
