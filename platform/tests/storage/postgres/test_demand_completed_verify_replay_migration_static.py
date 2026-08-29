"""Forward-only Demand0009 boundary for completed VerifyDemand replay."""

from pathlib import Path

from desire_platform.demand.adapters.postgres.migrations import (
    DEMAND_MIGRATION_LAYOUT,
    DemandMigrationCatalog,
    DemandMigrationPhase,
)


ROOT = (
    Path(__file__).resolve().parents[3]
    / "src/desire_platform/demand/adapters/postgres/migrations"
)
MIGRATION = ROOT / "0009_expand__completed_verify_receipt_replay.sql"


def test_demand9_is_reviewed_forward_only_catalog_tail() -> None:
    assert DEMAND_MIGRATION_LAYOUT[8] == (
        9,
        DemandMigrationPhase.EXPAND,
        "completed_verify_receipt_replay",
        "0009_expand__completed_verify_receipt_replay.sql",
    )
    catalog = DemandMigrationCatalog.load(ROOT)
    assert catalog.artifacts[8].sql_bytes == MIGRATION.read_bytes()


def test_demand9_is_invoker_only_and_receipt_identity_miss_is_narrow() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    assert "SECURITY INVOKER" in sql
    assert "SECURITY DEFINER" not in sql
    assert "TO demand_review" in sql
    assert "FROM PUBLIC" in sql
    assert "rls_demand_verify_replay_receipt_discovery" in sql
    assert "receipt_id::text" in sql
    discovery_policy = sql.split(
        "CREATE POLICY rls_demand_verify_replay_receipt_discovery", 1
    )[1].split("CREATE FUNCTION", 1)[0]
    assert "status" not in discovery_policy


def test_demand9_locks_exact_rls_trigger_and_acl_boundaries() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    for fragment in (
        "owner_role.rolname = 'demand_schema_owner'",
        "relation.relrowsecurity",
        "relation.relforcerowsecurity",
        "'demand.command_receipts'::regclass",
        "'demand.receipt_key_policy'::regclass",
        "CREATE POLICY rls_demand_verify_replay_receipt_lock",
        "policy.polcmd = 'w'",
        "pg_get_expr(policy.polwithcheck, policy.polrelid)",
        "trigger.tgenabled = 'O'",
        "trigger.tgtype = 19",
        "count(*) = 2",
        "count(DISTINCT privilege.grantee) = 2",
        "count(DISTINCT privilege.grantor) = 1",
        "NOT privilege.is_grantable",
        "'search_path=pg_catalog, demand, iam_api'",
        "'search_path=pg_catalog, demand'",
        "array_ndims(key_policy.retained_idempotency_key_ids)",
        "array_lower(key_policy.retained_idempotency_key_ids, 1)",
        "cardinality(key_policy.retained_idempotency_key_ids)",
        "array_ndims(key_policy.retained_payload_key_ids)",
        "array_lower(key_policy.retained_payload_key_ids, 1)",
        "cardinality(key_policy.retained_payload_key_ids)",
        "key_id.value IS NULL",
        "count(DISTINCT value) IS DISTINCT FROM count(*)",
    ):
        assert fragment in sql


def test_demand9_validates_current_authority_and_exact_terminal_graph() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    for fragment in (
        "resolve_demand_reviewer_authority_marker_v2",
        "lock_demand_reviewer_authority_v2",
        "existing.status IS DISTINCT FROM 'COMPLETED'",
        "existing.response_http_status IS DISTINCT FROM 200",
        "IS DISTINCT FROM ARRAY['DemandVerified']",
        "root.status = 'VERIFIED'",
        "assignment.status = 'COMPLETED'",
        "assignment.purpose_code = 'DEMAND_REVIEW'",
        "assignment.duty_grant_version >= 1",
        "review_row.decision = 'VERIFIED'",
        "existing.retain_until <= transaction_timestamp()",
        "MESSAGE = 'IDEMPOTENCY_KEY_REUSED'",
    ):
        assert fragment in sql


def test_demand9_closes_database_retained_key_arrays_before_membership() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    policy_block = sql.split("SELECT policy.* INTO STRICT key_policy", 1)[1].split(
        "IF existing.principal_kind", 1
    )[0]
    for purpose in ("idempotency", "payload"):
        array = f"key_policy.retained_{purpose}_key_ids"
        for fragment in (
            f"array_ndims({array})",
            f"array_lower({array}, 1)",
            f"cardinality({array})",
            f"unnest(\n                {array}",
        ):
            assert fragment in policy_block
    assert "key_id.value IS NULL" in policy_block
    assert "count(DISTINCT value) IS DISTINCT FROM count(*)" in policy_block
    assert policy_block.count("WHERE NOT EXISTS (") == 2
    assert "idempotency_key.key_id = payload_key.key_id" in policy_block
    assert "= ANY(key_policy.retained_" not in policy_block
