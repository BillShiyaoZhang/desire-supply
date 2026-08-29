"""IAM0036 frozen-boundary REDs for Trust, Appeal, and current logout."""

from __future__ import annotations

from pathlib import Path

from desire_platform.identity_access.adapters.postgres.migrations import (
    IAM_MIGRATION_LAYOUT,
    IAM_SCHEMA_HEAD_VERSION,
)


MIGRATION_ROOT = (
    Path(__file__).resolve().parents[3]
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
MIGRATION = MIGRATION_ROOT / "0036_expand__trust_appeal_authority_and_current_logout.sql"


def test_iam36_is_the_only_new_forward_migration_and_head() -> None:
    assert IAM_SCHEMA_HEAD_VERSION >= 36
    assert [item[0] for item in IAM_MIGRATION_LAYOUT[:37]] == list(range(37))
    assert IAM_MIGRATION_LAYOUT[36][2:] == (
        "trust_appeal_authority_and_current_logout",
        "0036_expand__trust_appeal_authority_and_current_logout.sql",
    )


def test_iam36_publishes_only_fixed_narrow_apis() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    for signature in (
        "resolve_trust_reporter_authority_v1",
        "resolve_trust_officer_authority_v1",
        "resolve_appeal_reviewer_authority_v1",
        "resolve_trust_party_conflict_facts_v1",
        "revoke_current_session_v1",
        "manage_internal_sandbox_identity_bootstrap_v5",
    ):
        assert signature in sql
    assert "TRUST_OFFICER" in sql
    assert "APPEAL_REVIEWER" in sql
    assert "trust_officer_01" in sql
    assert "trust_officer_02" in sql
    assert "appeal_reviewer_01" in sql
    assert "USER_LOGOUT_CURRENT_SESSION" in sql
    assert "SessionRevoked" in sql
    assert "REVOKE ALL ON FUNCTION" in sql
    assert "GRANT SELECT ON TABLE iam." not in sql


def test_iam36_freezes_upper_snake_trust_and_appeal_operation_sets() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    reporter_operations = (
        "SUBMIT_REPORT",
        "READ_OWN_REPORT",
        "OPEN_APPEAL",
        "READ_OWN_APPEAL",
        "SAVE_APPEAL_DRAFT",
        "SUBMIT_APPEAL",
    )
    officer_operations = (
        "CLAIM_CASE",
        "RELEASE_CASE_ASSIGNMENT",
        "SAVE_TRIAGE_DRAFT",
        "PUBLISH_TRIAGE",
        "PLACE_HOLD",
        "CLAIM_HOLD_RELEASE",
        "RELEASE_HOLD",
        "PUBLISH_OUTCOME",
        "LIST_CASE_QUEUE",
        "READ_ASSIGNED_CASE",
        "LIST_HOLD_RELEASE_QUEUE",
    )
    reviewer_operations = (
        "LIST_APPEAL_QUEUE",
        "READ_ASSIGNED_APPEAL",
        "CLAIM_APPEAL",
        "RELEASE_APPEAL_ASSIGNMENT",
        "SAVE_APPEAL_REVIEW_DRAFT",
        "DECIDE_APPEAL",
    )
    for operation in reporter_operations + officer_operations + reviewer_operations:
        assert f"'{operation}'" in sql
    for alias in (
        "SubmitSafetyReport",
        "ClaimSafetyCase",
        "RecordInitialDecision",
        "OpenAppeal",
    ):
        assert f"'{alias}'" not in sql


def test_iam36_replaces_family_invariant_without_revoking_family() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    assert "CREATE OR REPLACE FUNCTION iam.enforce_session_family_consistent()" in sql
    assert "active_session_count > 1" in sql
    assert "UPDATE iam.session_families" not in sql
