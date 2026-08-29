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
IAM36 = MIGRATION_ROOT / "0036_expand__trust_appeal_authority_and_current_logout.sql"
IAM37 = MIGRATION_ROOT / "0037_expand__finance_funding_review_authority_v2.sql"
IAM38 = MIGRATION_ROOT / "0038_expand__owned_session_revocation.sql"
PRODUCTION_PLAN = PLATFORM_ROOT / "src/desire_platform/internal_pilot/production_plan.py"
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


def test_iam38_is_one_forward_head_and_preserves_iam36_37_bytes():
    assert hashlib.sha256(IAM36.read_bytes()).hexdigest() == (
        "e194727b4c70312d2add67cdf0dc4964bbd1cbbcc8b8c3e1778bc9a60126b5c1"
    )
    assert hashlib.sha256(IAM37.read_bytes()).hexdigest() == (
        "60763a06f50332f7b7317a516d9a9f41006b807165b1fccf32cf8f879e666e01"
    )
    assert IAM_SCHEMA_HEAD_VERSION >= 38
    assert [item[0] for item in IAM_MIGRATION_LAYOUT[:39]] == list(range(39))
    assert IAM_MIGRATION_LAYOUT[38] == (
        38,
        MigrationPhase.EXPAND,
        "owned_session_revocation",
        "0038_expand__owned_session_revocation.sql",
    )


def test_iam38_fixed_program_is_exact_target_only_and_never_revokes_family():
    sql = IAM38.read_text(encoding="utf-8")
    body = _function_body(
        sql,
        "CREATE FUNCTION iam_api.revoke_owned_session_v1(",
    )
    for parameter in (
        "exact_actor_user_id uuid",
        "exact_current_session_id uuid",
        "exact_target_session_id uuid",
        "exact_command_id uuid",
    ):
        assert parameter in sql
    assert "target.id = exact_target_session_id" in body
    assert "target.user_id = exact_actor_user_id" in body
    assert "target.family_id = resolved_target_family_id" in body
    assert "UPDATE iam.session_families" not in body
    assert "RevokeReplayedSessionFamily" not in body
    assert "USER_REVOKED_SESSION" in body
    assert "USER_LOGOUT_CURRENT_SESSION" in body
    assert "clear_current_session_cookie" in body
    assert "exact_target_session_id = exact_current_session_id" in body


def test_iam38_owns_target_receipt_audit_outbox_and_closes_acl():
    sql = IAM38.read_text(encoding="utf-8")
    compact = " ".join(sql.split())
    for required in (
        "ALTER TABLE infra.command_receipts",
        "command_name <> 'RevokeSession'",
        "CREATE FUNCTION iam.owned_session_revocation_context_v1()",
        "CREATE POLICY rls_owned_session_revocation_session_select_v1",
        "CREATE POLICY rls_owned_session_revocation_session_update_v1",
        "INSERT INTO infra.command_receipts",
        "INSERT INTO audit.audit_events",
        "INSERT INTO infra.outbox_events",
        "event_type = 'SessionRevoked'",
        "action_code = 'RevokeSession'",
    ):
        assert required in sql
    assert (
        "REVOKE ALL ON FUNCTION iam_api.revoke_owned_session_v1( uuid, uuid, "
        "uuid, uuid, uuid, uuid, uuid, bytea, text, bytea, text, text, "
        "timestamptz, uuid, uuid ) FROM PUBLIC, iam_session_authenticator;"
    ) in compact
    assert (
        "GRANT EXECUTE ON FUNCTION iam_api.revoke_owned_session_v1( uuid, "
        "uuid, uuid, uuid, uuid, uuid, uuid, bytea, text, bytea, text, text, "
        "timestamptz, uuid, uuid ) TO iam_app;"
    ) in compact
    assert "GRANT SELECT ON TABLE iam." not in sql
    assert "EXECUTE format" not in sql
    assert "EXECUTE IMMEDIATE" not in sql


def test_iam38_contract_is_retained_while_runtime_heads_advance():
    production = PRODUCTION_PLAN.read_text(encoding="utf-8")
    demand = DEMAND_RUNNER.read_text(encoding="utf-8")
    trust = TRUST_RUNNER.read_text(encoding="utf-8")
    assert "IAM_SCHEMA_HEAD_VERSION != 46" in production
    assert "DEMAND_REQUIRED_IAM_SCHEMA_VERSION = 45" in demand
    assert "TRUST_REQUIRED_IAM_SCHEMA_VERSION = 46" in trust
