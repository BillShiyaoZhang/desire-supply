from __future__ import annotations

import hashlib
from pathlib import Path

from desire_platform.trust_safety.adapters.postgres.migrations import (
    TRUST_MIGRATION_LAYOUT,
    TrustMigrationCatalog,
    TrustMigrationPhase,
)


ROOT = Path(__file__).resolve().parents[3]
MIGRATIONS = (
    ROOT / "src/desire_platform/trust_safety/adapters/postgres/migrations"
)
TRUST0006 = MIGRATIONS / "0006_expand__active_assignment_discovery.sql"

FROZEN_SQL_SHA256 = (
    "c4596cd745560fb4ff2e893def82a12da291f3860c363337a5b453afeeff46d4",
    "fee3eb63cc28277762a0a119b3905a3ca13021bae53e015333197f50bc256eb5",
    "b1a8be2bef32686a46dd35f71adc4448521ada9fa6880331f73883dd60f72217",
    "215701b79830951b6ce796bb41109eb67f84ddf080d5c7c3f18e3759823dd025",
    "2401744ef71647d373b7c67a943fc05e4878cf6db01538084201833571818d7b",
)
FROZEN_PREFIX_SHA256 = (
    "9bd2be5ccbf62824569b07505e53902e3775675cdfa684524d0ba503846a2c13",
    "94a1e604044ea60845c44d191cd75c9794cd19731f2b8a52e28547e7172ddf93",
    "141057a29520dd4027570dda20c95e305053bbb2bb6f8d5a145e5e5b2d8e4863",
    "4bd6f0e8367e7853adccc28cf868fda1b3cf00b678c252b1d1ae635b422837a8",
    "8b02df9ea6717265e3d69d22b837c9b5455ebab74cebe0c6a112d15de22b1c04",
)


def test_trust6_is_forward_only_after_the_byte_frozen_trust5_prefix() -> None:
    catalog = TrustMigrationCatalog.load(MIGRATIONS)

    assert TRUST_MIGRATION_LAYOUT[5] == (
        6,
        TrustMigrationPhase.EXPAND,
        "active_assignment_discovery",
        TRUST0006.name,
    )
    assert tuple(
        hashlib.sha256(artifact.sql_bytes).hexdigest()
        for artifact in catalog.artifacts[:5]
    ) == FROZEN_SQL_SHA256
    assert tuple(
        artifact.descriptor.prefix_manifest_sha256.hex()
        for artifact in catalog.artifacts[:5]
    ) == FROZEN_PREFIX_SHA256
    assert catalog.artifacts[5].sql_bytes == TRUST0006.read_bytes()


def test_trust6_exposes_four_fixed_minimal_projection_functions() -> None:
    sql = TRUST0006.read_text(encoding="utf-8")

    for function_name in (
        "list_my_active_case_assignments_v1",
        "read_my_active_case_triage_assignment_v1",
        "read_my_active_hold_release_assignment_v1",
        "list_my_active_appeal_assignments_v1",
    ):
        assert f"CREATE FUNCTION trust_api.{function_name}(" in sql
    assert sql.count("SECURITY DEFINER") == 4
    assert sql.count("RETURNS TABLE (projection jsonb)") == 4
    assert sql.count("exact_limit IS NULL") == 2
    assert sql.count("exact_limit NOT BETWEEN 1 AND 100") == 2
    assert "'READ_ASSIGNED_CASE'" in sql
    assert "'READ_ASSIGNED_APPEAL'" in sql
    assert "FROM iam_api.resolve_trust_officer_authority_v1(" in sql
    assert "FROM trust.resolve_officer_authority_v1(" not in sql
    assert "TRUST_MY_ASSIGNMENTS_READ" in sql
    assert "APPEAL_MY_ASSIGNMENTS_READ" in sql

    # Exact party-safe item keys.  UUIDs needed to resume work are exposed;
    # assignment, actor, duty, organization, demand, source and text facts are not.
    assert "'case_id', assignment.case_id" in sql
    assert "'assignment_purpose', assignment.assignment_purpose_code" in sql
    assert "'assignment_expires_at', assignment.expires_at" in sql
    assert "'hold_id', assignment.hold_id" in sql
    assert "'appeal_id', assignment.appeal_id" in sql
    assert "desire:trust:my-active-case-assignments:v1" in sql
    assert "desire:trust:my-active-appeal-assignments:v1" in sql
    assert "'entity_tag'" in sql
    assert "'items'" in sql

    for forbidden_projection_key in (
        "'assignment_id'",
        "'actor_user_id'",
        "'officer_user_id'",
        "'reviewer_user_id'",
        "'duty_grant_id'",
        "'duty_grant_version'",
        "'authority_marker_sha256'",
        "'organization_id'",
        "'demand_id'",
        "'source_case_id'",
        "'grounds'",
        "'requested_outcome'",
        "'sealed_note_reference'",
        "'ciphertext'",
    ):
        assert forbidden_projection_key not in sql

    hold_reader_start = sql.index(
        "CREATE FUNCTION "
        "trust_api.read_my_active_hold_release_assignment_v1("
    )
    hold_reader_end = sql.index(
        "CREATE FUNCTION trust_api.list_my_active_appeal_assignments_v1(",
        hold_reader_start,
    )
    hold_reader = sql[hold_reader_start:hold_reader_end]
    for exact_key in (
        "'action_codes'",
        "'assignment_expires_at'",
        "'case_id'",
        "'case_status'",
        "'effective_at'",
        "'entity_tag'",
        "'expires_at'",
        "'hold_id'",
        "'hold_status'",
        "'reason_code'",
    ):
        assert hold_reader.count(exact_key) == 1
    for forbidden_key in (
        "'actor_user_id'",
        "'assignment_id'",
        "'authority_marker_sha256'",
        "'demand_id'",
        "'duty_grant_id'",
        "'duty_grant_version'",
        "'officer_user_id'",
        "'organization_id'",
    ):
        assert forbidden_key not in hold_reader
    assert "hold.reason_code IN (" in hold_reader
    assert "'PARTICIPANT_SAFETY_RISK'" in hold_reader
    assert "'RETALIATION_RISK'" in hold_reader


def test_trust6_rls_is_select_only_actor_duty_and_time_bound() -> None:
    sql = TRUST0006.read_text(encoding="utf-8")

    case_root_policy_start = sql.index(
        "CREATE POLICY rls_trust_my_case_roots_select_v1"
    )
    case_root_policy_end = sql.index(
        "CREATE POLICY rls_trust_my_appeal_assignments_select_v1",
        case_root_policy_start,
    )
    case_root_policy = sql[case_root_policy_start:case_root_policy_end]
    case_list_start = sql.index(
        "CREATE FUNCTION trust_api.list_my_active_case_assignments_v1("
    )
    triage_reader_start = sql.index(
        "CREATE FUNCTION "
        "trust_api.read_my_active_case_triage_assignment_v1("
    )
    hold_reader_start = sql.index(
        "CREATE FUNCTION "
        "trust_api.read_my_active_hold_release_assignment_v1("
    )
    case_list = sql[case_list_start:triage_reader_start]
    triage_reader = sql[triage_reader_start:hold_reader_start]

    for relation in (
        "trust.cases",
        "trust.case_assignments",
        "trust.case_assignment_releases",
        "trust.safety_holds",
        "trust.appeals",
        "trust.appeal_review_assignments",
        "trust.appeal_assignment_releases",
    ):
        assert f"ALTER TABLE {relation} ENABLE ROW LEVEL SECURITY" in sql
        assert f"ALTER TABLE {relation} FORCE ROW LEVEL SECURITY" in sql

    for policy in (
        "rls_trust_my_case_roots_select_v1",
        "rls_trust_my_case_assignments_select_v1",
        "rls_trust_my_case_assignment_releases_select_v1",
        "rls_trust_my_case_holds_select_v1",
        "rls_trust_my_appeal_roots_select_v1",
        "rls_trust_my_appeal_assignments_select_v1",
        "rls_trust_my_appeal_assignment_releases_select_v1",
    ):
        assert f"CREATE POLICY {policy}" in sql
    assert sql.count("FOR SELECT TO trust_schema_owner") == 7
    assert "officer_user_id::text" in sql
    assert "reviewer_user_id::text" in sql
    assert "duty_grant_id::text" in sql
    assert "duty_grant_version::text" in sql
    assert sql.count("assigned_at <= transaction_timestamp()") >= 2
    assert sql.count("transaction_timestamp() < expires_at") >= 2
    assert "assignment_purpose_code IN ('CASE_TRIAGE', 'HOLD_RELEASE')" in sql
    # A just-published case remains readable through the exact assignment
    # wrapper for the post-commit refresh.  Discovery itself remains active-only.
    assert "cases.status IN ('TRIAGING', 'IN_REVIEW', 'DECIDED')" in case_root_policy
    assert (
        "case_root.status IN ('TRIAGING', 'IN_REVIEW', 'DECIDED')"
        in triage_reader
    )
    assert "case_root.status IN ('TRIAGING', 'IN_REVIEW')" in case_list
    assert "DECIDED" not in case_list
    assert "case_root.status = 'IN_REVIEW'" in sql
    assert "hold.status = 'ACTIVE'" in sql
    assert "appeal_root.status = 'IN_REVIEW'" in sql
    assert "appeal_root.decision_version_id IS NULL" in sql
    assert "appeal_root.current_assignment_id = assignment.assignment_id" in sql
    assert "assignment.hold_id NULLS FIRST" in sql


def test_trust6_acl_is_closed_and_contract_head_is_repinned() -> None:
    sql = TRUST0006.read_text(encoding="utf-8")

    assert "REVOKE ALL ON FUNCTION trust_api.list_my_active_case_assignments_v1(" in sql
    assert "REVOKE ALL ON FUNCTION trust_api.list_my_active_appeal_assignments_v1(" in sql
    assert (
        "REVOKE ALL ON FUNCTION "
        "trust_api.read_my_active_case_triage_assignment_v1(" in sql
    )
    assert (
        "REVOKE ALL ON FUNCTION "
        "trust_api.read_my_active_hold_release_assignment_v1(" in sql
    )
    assert (
        "REVOKE EXECUTE ON FUNCTION trust_api.read_assigned_case_v1("
        in sql
    )
    assert (
        "GRANT EXECUTE ON FUNCTION trust_api.list_my_active_case_assignments_v1("
        in sql
    )
    assert ") TO trust_officer;" in sql
    assert (
        "GRANT EXECUTE ON FUNCTION trust_api.list_my_active_appeal_assignments_v1("
        in sql
    )
    assert ") TO trust_appeal;" in sql
    assert (
        "GRANT EXECUTE ON FUNCTION "
        "trust_api.read_my_active_case_triage_assignment_v1(" in sql
    )
    assert (
        "GRANT EXECUTE ON FUNCTION "
        "trust_api.read_my_active_hold_release_assignment_v1(" in sql
    )
    assert "TRUST5_SCHEMA_CONTRACT_BASELINE_MISMATCH" in sql
    assert "schema_head_version = 6" in sql
    assert "min_app_compatible_version = 6" in sql
    assert "max_app_compatible_version = 6" in sql
    assert sql.count("DELETE FROM trust_meta.schema_contracts") == 1
    assert "EXECUTE format" not in sql
