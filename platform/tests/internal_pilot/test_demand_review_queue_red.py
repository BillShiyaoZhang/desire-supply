"""RED-first contract for the PostgreSQL-authoritative review queue slice."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib

from desire_platform.internal_pilot.editor import (
    EditorHttpApi,
    EditorPrincipal,
    EditorReviewQueueItemDto,
    HttpRequest,
)


NOW = datetime(2026, 8, 15, 8, 0, tzinfo=timezone.utc)
ACTOR = "d106480d-27fb-503e-b840-fe8f639b9943"
SESSION = "20000000-0000-4000-8000-000000000025"
DEMAND = "30000000-0000-4000-8000-000000000025"
ASSIGNMENT = "40000000-0000-4000-8000-000000000025"
MARKER = hashlib.sha256(b"review-queue-principal").digest()

REVIEWER = EditorPrincipal(
    user_id=ACTOR,
    session_id=SESSION,
    organization_id=None,
    role_codes=("OPERATIONS_REVIEWER",),
    workspace_id=f"platform:{ACTOR}",
    workspace_kind="PLATFORM",
    membership_id=None,
    organization_role_codes=(),
    user_role_codes=("CREATOR",),
    platform_duty_codes=("OPERATIONS_REVIEWER",),
    principal_marker_sha256=MARKER,
)


class _ReviewServiceProbe:
    def __init__(self) -> None:
        self.calls = []
        self.queue_item = EditorReviewQueueItemDto(
            demand_id=DEMAND,
            demand_revision=2,
            demand_version_no=1,
            submitted_at=NOW - timedelta(minutes=5),
            demand_expires_at=NOW + timedelta(days=30),
            etag='"demand-2-review-queue"',
        )

    def list_review_queue(self, *, principal):
        self.calls.append(("list", principal))
        return (self.queue_item,)

    def claim_demand_review(
        self,
        *,
        principal,
        demand_id,
        if_match,
        idempotency_key,
    ):
        self.calls.append(
            ("claim", principal, demand_id, if_match, idempotency_key)
        )
        return {
            "assignment_id": ASSIGNMENT,
            "demand_id": demand_id,
            "status": "ACTIVE",
            "expires_at": NOW + timedelta(minutes=30),
        }

    def verify_demand(
        self,
        *,
        principal,
        demand_id,
        assignment_id,
        if_match,
        budget_health_code,
        risk_code,
        evidence_codes,
        idempotency_key,
    ):
        self.calls.append(
            (
                "verify",
                principal,
                demand_id,
                assignment_id,
                if_match,
                budget_health_code,
                risk_code,
                evidence_codes,
                idempotency_key,
            )
        )
        return {"status": "VERIFIED"}


def test_http_lists_minimal_queue_and_claim_requires_both_preconditions() -> None:
    service = _ReviewServiceProbe()
    api = EditorHttpApi(service=service)

    listed = api.handle(
        request=HttpRequest(
            method="GET", path="/v1/app/review-queue", headers={}, json=None
        ),
        principal=REVIEWER,
    )
    assert listed.status == 200
    assert listed.json == {
        "data": [
            {
                "demand_id": DEMAND,
                "demand_revision": 2,
                "demand_version_no": 1,
                "submitted_at": "2026-08-15T07:55:00+00:00",
                "demand_expires_at": "2026-09-14T08:00:00+00:00",
                "etag": '"demand-2-review-queue"',
            }
        ]
    }
    assert "organization_id" not in listed.json["data"][0]

    missing_etag = api.handle(
        request=HttpRequest(
            method="POST",
            path=f"/v1/app/review-queue/{DEMAND}/claim",
            headers={"Idempotency-Key": "claim-review-0001"},
            json={},
        ),
        principal=REVIEWER,
    )
    assert missing_etag.status == 428
    assert missing_etag.json["error"]["path"] == "/headers/If-Match"

    claimed = api.handle(
        request=HttpRequest(
            method="POST",
            path=f"/v1/app/review-queue/{DEMAND}/claim",
            headers={
                "If-Match": '"demand-2-review-queue"',
                "Idempotency-Key": "claim-review-0001",
            },
            json={},
        ),
        principal=REVIEWER,
    )
    assert claimed.status == 200
    assert claimed.json["data"]["assignment_id"] == ASSIGNMENT
    assert service.calls[-1] == (
        "claim",
        REVIEWER,
        DEMAND,
        '"demand-2-review-queue"',
        "claim-review-0001",
    )


def test_http_verify_accepts_only_closed_structured_evidence() -> None:
    service = _ReviewServiceProbe()
    api = EditorHttpApi(service=service)
    path = (
        f"/v1/app/demands/{DEMAND}/review-assignments/{ASSIGNMENT}/verify"
    )
    invalid = api.handle(
        request=HttpRequest(
            method="POST",
            path=path,
            headers={
                "If-Match": '"demand-2"',
                "Idempotency-Key": "verify-review-0001",
            },
            json={
                "budget_health_code": "HEALTHY",
                "risk_code": "STANDARD",
                "evidence_codes": ["FREE_TEXT_APPROVED"],
            },
        ),
        principal=REVIEWER,
    )
    assert invalid.status == 422
    assert invalid.json["error"] == {
        "code": "INVALID_EVIDENCE_CODE",
        "path": "/evidence_codes/0",
    }

    verified = api.handle(
        request=HttpRequest(
            method="POST",
            path=path,
            headers={
                "If-Match": '"demand-2"',
                "Idempotency-Key": "verify-review-0002",
            },
            json={
                "budget_health_code": "HEALTHY",
                "risk_code": "STANDARD",
                "evidence_codes": [
                    "SCOPE_COMPLETE",
                    "ACCEPTANCE_TESTABLE",
                ],
            },
        ),
        principal=REVIEWER,
    )
    assert verified.status == 200
    assert service.calls[-1][-2] == (
        "SCOPE_COMPLETE",
        "ACCEPTANCE_TESTABLE",
    )


def test_http_verify_rejects_actor_duty_assignment_and_digest_overrides() -> None:
    service = _ReviewServiceProbe()
    api = EditorHttpApi(service=service)
    response = api.handle(
        request=HttpRequest(
            method="POST",
            path=(
                f"/v1/app/demands/{DEMAND}/review-assignments/"
                f"{ASSIGNMENT}/verify"
            ),
            headers={
                "If-Match": '"demand-2"',
                "Idempotency-Key": "verify-review-0003",
            },
            json={
                "budget_health_code": "HEALTHY",
                "risk_code": "STANDARD",
                "evidence_codes": ["SCOPE_COMPLETE"],
                "reviewer_user_id": ACTOR,
                "duty_grant_id": "attacker-duty",
                "evidence_summary_sha256": "00" * 32,
            },
        ),
        principal=REVIEWER,
    )
    assert response.status == 422
    assert response.json["error"] == {
        "code": "UNKNOWN_FIELD",
        "path": "/duty_grant_id",
    }
