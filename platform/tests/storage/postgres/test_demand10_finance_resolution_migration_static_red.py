"""Demand10 forward-only static gates for Finance review resolution."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path

from desire_platform.demand.adapters.postgres.migrations import (
    DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
    DEMAND_SCHEMA_HEAD_VERSION,
)


ROOT = Path(__file__).resolve().parents[3]
MIGRATIONS = ROOT / "src/desire_platform/demand/adapters/postgres/migrations"
DEMAND10 = MIGRATIONS / "0010_expand__finance_funding_review_resolution.sql"

FROZEN = {
    "0001_expand__demand_v1.sql": "c352e19a34ce014abb0c52aae9d082d68029a92d55d2489628787bda3f50d59f",
    "0002_expand__editor_target_discovery.sql": "987f50491e5080a9f8abd78c8cf526e3095005b9727eb4b74bd6d9bd6653b3c4",
    "0003_expand__internal_sandbox_review_queue.sql": "81c56ca095b4a9a2f09b7e33be91842fe67ea1f183febc2f2cd1a83fe56ebeac",
    "0004_expand__review_queue_null_hardening.sql": "1ffb12e47bc9379dc2b49335da4c8997e3492d946e93028369712a22d9dd22c9",
    "0005_expand__review_queue_claim_lock_rls.sql": "c3bf80114deb360209f37b13416a7faf46172c87cdca99a1c351e403f85beeda",
    "0006_expand__manual_finance_funding_review.sql": "056c1a6f0aae79ee7d37f7f728dff426ce97ce06d6d1b525b92cc4976ba0fb2d",
    "0007_expand__owner_findings_and_finance_evidence.sql": "2fbab5907eef611a6275e73d2cda76d0495c55893efdb5c9bdedb289b5901c78",
    "0008_expand__trust_target_and_conflict_bridge.sql": "879099065b4e4b32cd1f27bdee10283fc9b565e19a28052ba33a1a81860fafb6",
    "0009_expand__completed_verify_receipt_replay.sql": "71a93b72e54bbf272973c19dbf785cb48aca8f1b0396665f559b7788da557cab",
}


def test_demand10_is_forward_only_and_requires_iam37() -> None:
    assert DEMAND_SCHEMA_HEAD_VERSION >= 10
    assert DEMAND_REQUIRED_IAM_SCHEMA_VERSION >= 37
    assert DEMAND10.is_file()
    for name, digest in FROZEN.items():
        assert sha256((MIGRATIONS / name).read_bytes()).hexdigest() == digest


def test_demand10_closes_history_concurrency_rls_receipts_and_owner_projection() -> None:
    sql = DEMAND10.read_text(encoding="utf-8")
    for marker in (
        "DROP CONSTRAINT uq_manual_funding_case_demand",
        "WHERE status = 'PENDING'",
        "DROP CONSTRAINT uq_manual_funding_assignment_actor",
        "WHERE status = 'ACTIVE'",
        "'RELEASED'",
        "'EXPIRED'",
        "manual_funding_assignment_releases",
        "manual_funding_findings",
        "ReleaseManualFundingReviewAssignment",
        "SubmitManualFundingReviewFinding",
        "RELEASE_FUNDING_REVIEW_ASSIGNMENT",
        "SUBMIT_FUNDING_REVIEW_FINDING",
        "lock_finance_funding_authority_v2",
        "FOR UPDATE",
        "ENABLE ROW LEVEL SECURITY",
        "FORCE ROW LEVEL SECURITY",
        "demand_api.read_demand_owner_findings_v2",
        "NULL::uuid AS assignment_id",
        "COALESCE(confirmation.mine, false)",
        "DISCREPANCY",
        "REJECTED",
        "verified_version_id = NULL",
        "current_review_id",
        "DemandFundingReviewAssignmentReleased",
        "DemandFundingReviewFindingSubmitted",
        "expired_assignment_count",
        "stale_own_assignment_revoked",
        "app.receipt_replayed",
        "app.receipt_id",
        "receipt_replayed := COALESCE(",
        "receipt.safe_response_body->>'assignment_id'",
        "receipt_row.organization_id",
        "receipt_row.canonicalization_version",
        "IS DISTINCT FROM expected_review_revision",
        "case_expires := root_row.expires_at",
        "root_row.expires_at,",
        "jsonb_typeof(",
        "assignment_row.authority_marker_sha256",
        "REVOKE ALL ON FUNCTION",
    ):
        assert marker in sql
    assert "SET status = 'EXPIRED'" in sql
    assert "now_at >= review_row.expires_at" not in sql
    assert "transaction_timestamp() < review.expires_at" not in sql
    assert "AND assignment_id::text\n    AND assignment_id::text" not in sql
    assert sql.count("CREATE FUNCTION demand_api.submit_manual_funding_review_finding_v1(") == 1
    assert "current_review_id = NULL" not in sql
    assert "payout" not in sql.lower()
    assert "provider_event" not in sql.lower()
