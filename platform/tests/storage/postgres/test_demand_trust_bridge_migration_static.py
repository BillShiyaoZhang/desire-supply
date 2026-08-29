from __future__ import annotations

import hashlib
from pathlib import Path

from desire_platform.demand.adapters.postgres.migrations import (
    DEMAND_MIGRATION_LAYOUT,
    DEMAND_REVIEWED_MANIFEST_SHA256,
    DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
    DEMAND_SCHEMA_HEAD_VERSION,
    DemandMigrationCatalog,
    DemandMigrationPhase,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT / "src/desire_platform/demand/adapters/postgres/migrations"
)
MIGRATION = MIGRATION_ROOT / "0008_expand__trust_target_and_conflict_bridge.sql"


def test_demand8_is_forward_only_byte_pinned_and_requires_iam36() -> None:
    catalog = DemandMigrationCatalog.load(MIGRATION_ROOT)
    demand8 = catalog.artifacts[7]
    assert DEMAND_SCHEMA_HEAD_VERSION >= 9
    assert DEMAND_REQUIRED_IAM_SCHEMA_VERSION >= 36
    assert DEMAND_MIGRATION_LAYOUT[7] == (
        8,
        DemandMigrationPhase.EXPAND,
        "trust_target_and_conflict_bridge",
        "0008_expand__trust_target_and_conflict_bridge.sql",
    )
    assert demand8.descriptor.checksum_sha256 == hashlib.sha256(
        MIGRATION.read_bytes()
    ).digest()
    assert demand8.descriptor.prefix_manifest_sha256.hex() == (
        "08c87b3817c88e2b6ed5819d1df97b661130eb7133142c42a53708f907782f7a"
    )
    assert catalog.manifest_sha256 == DEMAND_REVIEWED_MANIFEST_SHA256
    for historical in catalog.artifacts[:7]:
        assert historical.descriptor.version <= 7


def test_demand8_exposes_only_three_fixed_secret_safe_programs() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    for marker in (
        "demand_api.resolve_trust_report_target_v1",
        "demand_api.resolve_trust_officer_conflict_v1",
        "demand_api.resolve_appeal_applicant_party_v1",
        "iam_api.resolve_trust_reporter_authority_marker_v1",
        "iam_api.resolve_trust_officer_authority_marker_v1",
        "iam_api.resolve_trust_party_conflict_facts_v1",
        "demand.trust_schema_dependency_v1",
        "desire:demand:trust-schema-dependency:v1",
        "session_user IS DISTINCT FROM 'trust_self'",
        "session_user IS DISTINCT FROM 'trust_officer'",
        "current_user IS DISTINCT FROM 'demand_schema_owner'",
        "SECURITY DEFINER",
        "REVOKE ALL ON FUNCTION",
        "TO trust_self",
        "TO trust_officer",
        "relrowsecurity",
        "relforcerowsecurity",
    ):
        assert marker in sql
    lowered = sql.lower()
    for forbidden in (
        "execute format",
        "execute immediate",
        "grant select on iam.",
        "grant select on demand.demands",
        "grant select on demand.demand_versions",
        "bypassrls",
    ):
        assert forbidden not in lowered


def test_report_projection_is_owner_current_version_and_closed_status_only() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    for marker in (
        "root.creator_user_id = exact_actor_user_id",
        "version_row.id = root.current_version_id",
        "version_row.id = exact_demand_version_id",
        "root.status IN (",
        "'SUBMITTED', 'NEEDS_CHANGES', 'VERIFIED', 'FUNDING_PENDING'",
        "'FUNDED', 'MATCHING', 'MATCHED', 'NO_MATCH'",
        "root.expires_at > transaction_timestamp()",
        "demand-trust-reporter-party-v1|",
        "demand-trust-target-v1|",
        "TARGET_NOT_FOUND",
    ):
        assert marker in sql


def test_conflict_projection_binds_only_boolean_without_participant_identity() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    for marker in (
        "root.creator_user_id = exact_actor_user_id",
        "submission.submitted_by_user_id = exact_actor_user_id",
        "assignment.reviewer_user_id = exact_actor_user_id",
        "review_row.reviewer_user_id = exact_actor_user_id",
        "finance_assignment.actor_user_id = exact_actor_user_id",
        "confirmation.actor_user_id = exact_actor_user_id",
        "organization_membership_conflict",
        "conflict_facts_marker_sha256",
        "demand-trust-officer-conflict-v1|",
        "exact_operation NOT IN ('CLAIM_CASE', 'CLAIM_HOLD_RELEASE')",
        "IS DISTINCT FROM exact_operation",
        "interval '5 minutes'",
    ):
        assert marker in sql
    assert "RETURNS TABLE (\n    officer_user_id uuid" in sql
    assert "conflict_reason" not in sql


def test_appeal_party_probe_returns_only_an_opaque_marker() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    assert "RETURNS TABLE (applicant_party_marker_sha256 bytea)" in sql
    assert "demand-appeal-applicant-party-v1|" in sql
    assert "root.creator_user_id = exact_actor_user_id" in sql
    assert "CREATE TABLE demand.appeal" not in sql


def test_trust_runner_gets_one_combined_demand_dependency_not_base_tables() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    for marker in (
        "api_contract_sha256",
        "event_contract_sha256",
        "content_contract_sha256",
        "migration_manifest_sha256",
        "dependency_sha256",
        "GRANT SELECT ON demand.trust_schema_dependency_v1",
        "TO trust_migration_runner, trust_schema_owner",
    ):
        assert marker in sql
