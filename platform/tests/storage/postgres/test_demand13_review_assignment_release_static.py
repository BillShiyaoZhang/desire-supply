"""Static closure checks for Demand13 reviewer-controlled assignment release."""

from __future__ import annotations

import hashlib
from pathlib import Path

from desire_platform.demand.adapters.postgres.migrations import (
    DEMAND_MIGRATION_LAYOUT,
    DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
    DEMAND_REVIEWED_MANIFEST_SHA256,
    DEMAND_SCHEMA_HEAD_VERSION,
    DemandMigrationCatalog,
    DemandMigrationPhase,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT / "src/desire_platform/demand/adapters/postgres/migrations"
)
MIGRATION = MIGRATION_ROOT / "0013_expand__review_assignment_release.sql"


def test_demand13_remains_registered_and_catalog_is_pinned_to_iam43() -> None:
    catalog = DemandMigrationCatalog.load(MIGRATION_ROOT)
    artifact = catalog.artifacts[12]

    assert DEMAND_SCHEMA_HEAD_VERSION >= 13
    assert DEMAND_REQUIRED_IAM_SCHEMA_VERSION == 45
    assert DEMAND_MIGRATION_LAYOUT[12] == (
        13,
        DemandMigrationPhase.EXPAND,
        "review_assignment_release",
        MIGRATION.name,
    )
    assert artifact.descriptor.version == 13
    assert artifact.descriptor.checksum_sha256 == hashlib.sha256(
        MIGRATION.read_bytes()
    ).digest()
    assert catalog.manifest_sha256 == DEMAND_REVIEWED_MANIFEST_SHA256


def test_release_fact_is_closed_immutable_force_rls_and_role_minimal() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    for marker in (
        "CREATE TABLE demand.demand_review_assignment_releases",
        "assignment_id uuid NOT NULL UNIQUE",
        "reason_code IN ('CONFLICT_DECLARED', 'WORKLOAD_RELEASE')",
        "octet_length(authority_marker_sha256) = 32",
        "trg_demand_review_assignment_release_immutable",
        "BEFORE UPDATE OR DELETE ON demand.demand_review_assignment_releases",
        "GRANT SELECT, INSERT ON demand.demand_review_assignment_releases\nTO demand_review",
        "ALTER TABLE demand.demand_review_assignment_releases ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE demand.demand_review_assignment_releases FORCE ROW LEVEL SECURITY",
        "CREATE POLICY rls_demand_review_release_write",
        "CREATE POLICY rls_demand_review_release_read",
        "= 'RELEASE_REVIEW_ASSIGNMENT'",
        "= 'DEMAND_REVIEW_RELEASE_REPLAY'",
    ):
        assert marker in sql
    assert "GRANT UPDATE" not in sql
    assert "GRANT DELETE" not in sql
    assert "demand_review_assignment_releases\nTO demand_self" not in sql
    assert "demand_review_assignment_releases\nTO demand_finance" not in sql


def test_completed_receipt_replay_is_exact_authority_bound_and_read_only() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    for marker in (
        "CREATE POLICY rls_demand_release_replay_receipt_discovery",
        "CREATE POLICY rls_demand_release_replay_receipt_lock",
        "command_receipts_release_replay_read_only",
        "DEMAND_RELEASE_REPLAY_IS_READ_ONLY",
        "demand_api.read_completed_review_assignment_release_receipt_v1",
        "SECURITY INVOKER",
        "DEMAND_REVIEW_RELEASE_REPLAY",
        "ReleaseDemandReviewAssignment",
        "/v1/operations/demand-review-assignments/",
        "exact_assignment_id::text || '/release'",
        "existing.if_match_version IS DISTINCT FROM exact_if_match_version",
        "existing.response_http_status IS DISTINCT FROM 200",
        "existing.target_version IS DISTINCT FROM exact_if_match_version + 1",
        "existing.result_status IS DISTINCT FROM 'SUBMITTED'",
        "ARRAY['DemandReviewAssignmentReleased']::text[]",
        "MESSAGE = 'IDEMPOTENCY_KEY_REUSED'",
        "MESSAGE = 'COMMAND_OUTCOME_UNKNOWN'",
        "iam_api.resolve_demand_reviewer_authority_marker_v2",
        "iam_api.lock_demand_reviewer_authority_v2",
        "'RELEASE_REVIEW_ASSIGNMENT'",
        "assignment.status = 'REVOKED'",
        "assignment.aggregate_version = 2",
        "release_row.id = exact_receipt_id",
        "release_row.reviewer_user_id = exact_actor_user_id",
        "root.status = 'SUBMITTED'",
        "root.aggregate_version = existing.target_version",
        "root.current_review_id IS NULL",
        "NOT EXISTS (\n            SELECT 1 FROM demand.demand_reviews",
        "REVOKE ALL ON FUNCTION",
        ") TO demand_review",
    ):
        assert marker in sql
    assert "SECURITY DEFINER" not in _replay_function(sql)


def test_conflict_release_excludes_all_same_reviewer_reclaim_paths_only() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    start = sql.index("CREATE POLICY rls_demand_review_release_queue_definer")
    end = sql.index("CREATE POLICY rls_demand_release_replay_receipt_discovery")
    queue_closure = sql[start:end]

    for marker in (
        "CREATE POLICY rls_demand_review_release_queue_definer",
        "reviewer_user_id::text",
        "'LIST_REVIEW_QUEUE'",
        "'RESOLVE_REVIEW_QUEUE_TARGET'",
        "'CLAIM_REVIEW'",
        "CREATE OR REPLACE FUNCTION demand_api.list_available_demand_reviews_v1",
        "CREATE OR REPLACE FUNCTION demand_api.resolve_review_queue_target_v1",
        "release_row.submission_id = root.current_submission_id",
        "release_row.demand_version_id = root.current_version_id",
        "release_row.reviewer_user_id = exact_actor_user_id",
        "CREATE TRIGGER reject_conflicted_review_reclaim",
        "BEFORE INSERT ON demand.demand_review_assignments",
        "CONSTRAINT = 'review_claim_conflict_declared'",
    ):
        assert marker in queue_closure
    assert queue_closure.count("reason_code = 'CONFLICT_DECLARED'") == 3
    assert "reason_code = 'WORKLOAD_RELEASE'" not in queue_closure


def test_replay_inputs_are_bounded_canonical_and_duplicate_key_closed() -> None:
    body = _replay_function(MIGRATION.read_text(encoding="utf-8"))
    for marker in (
        "cardinality(exact_idempotency_key_digest_key_ids) NOT BETWEEN 1 AND 4",
        "cardinality(exact_payload_hash_key_ids) NOT BETWEEN 1 AND 4",
        "array_lower(exact_idempotency_key_digest_key_ids, 1) <> 1",
        "array_lower(exact_payload_hashes, 1) <> 1",
        "count(DISTINCT value) <> count(*)",
        "octet_length(item.value) <> 32",
        "DEMAND_RECEIPT_KEY_POLICY_UNAVAILABLE",
        "DEMAND_RELEASE_RECEIPT_REPLAY_INVALID",
    ):
        assert marker in body


def _replay_function(sql: str) -> str:
    start = sql.index(
        "CREATE FUNCTION demand_api."
        "read_completed_review_assignment_release_receipt_v1("
    )
    end = sql.index("REVOKE ALL ON FUNCTION", start)
    return sql[start:end]
