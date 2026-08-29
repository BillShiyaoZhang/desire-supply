"""Demand10 RED contract for Finance funding-review resolution."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib

import pytest

from desire_platform.internal_pilot.editor import (
    EditorHttpApi,
    EditorPrincipal,
    HttpRequest,
)
from desire_platform.internal_pilot.finance_funding import (
    FINANCE_FUNDING_ACTIONS,
    FINANCE_FUNDING_FINDING_FIELD_CODES,
    FINANCE_FUNDING_FINDING_REASON_CODES,
    FINANCE_FUNDING_RELEASE_REASON_CODES,
    FinanceFundingReviewDto,
)


NOW = datetime(2026, 8, 19, 12, 0, tzinfo=timezone.utc)
ACTOR = "71000000-0000-4000-8000-000000000001"
SESSION = "72000000-0000-4000-8000-000000000001"
DEMAND = "73000000-0000-4000-8000-000000000001"
VERSION = "74000000-0000-4000-8000-000000000001"
REVIEW = "75000000-0000-4000-8000-000000000001"
ASSIGNMENT = "76000000-0000-4000-8000-000000000001"
MARKER = hashlib.sha256(b"demand10-finance-principal").digest()

FINANCE = EditorPrincipal(
    user_id=ACTOR,
    session_id=SESSION,
    organization_id=None,
    role_codes=("FINANCE_OPERATOR",),
    workspace_id=f"platform:{ACTOR}",
    workspace_kind="PLATFORM",
    membership_id=None,
    organization_role_codes=(),
    user_role_codes=(),
    platform_duty_codes=("FINANCE_OPERATOR",),
    principal_marker_sha256=MARKER,
)


def _review(**changes) -> FinanceFundingReviewDto:
    values = {
        "funding_review_id": REVIEW,
        "demand_id": DEMAND,
        "demand_version_id": VERSION,
        "status": "PENDING",
        "revision": 3,
        "assignment_id": ASSIGNMENT,
        "assignment_expires_at": NOW + timedelta(minutes=30),
        "target_sha256": hashlib.sha256(b"target").hexdigest(),
        "target_content_sha256": hashlib.sha256(b"content").hexdigest(),
        "planned_budget_currency": "CNY",
        "planned_budget_minimum_amount_minor": 100,
        "planned_budget_maximum_amount_minor": 200,
        "planned_budget_direct_cost_amount_minor": 20,
        "evidence_kind": "INTERNAL_SANDBOX_ZERO_FUNDS_V1",
        "evidence_reference_sha256": hashlib.sha256(b"evidence").hexdigest(),
        "sandbox_funds_amount_minor": 0,
        "provider_code": "NONE",
        "payment_operation_code": "NONE",
        "synthetic": True,
        "legal_effect": "NO_REAL_FUNDS_OR_PAYMENT",
        "confirmation_count": 0,
        "required_confirmations": 2,
        "assignment_status": "ACTIVE",
        "confirmation_by_me": False,
        "available_actions": FINANCE_FUNDING_ACTIONS,
        "can_confirm": True,
        "etag": '"funding-review-3"',
        "replayed": False,
    }
    values.update(changes)
    return FinanceFundingReviewDto(**values)


class _FinanceResolutionProbe:
    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []

    def list_funding_reviews(self, *, principal):
        raise AssertionError(principal)

    def claim_funding_review(self, **values):
        raise AssertionError(values)

    def get_funding_review(self, **values):
        raise AssertionError(values)

    def confirm_funding_review(self, **values):
        raise AssertionError(values)

    def release_funding_review_assignment(
        self, *, principal, funding_review_id, if_match, reason_code,
        idempotency_key
    ):
        self.calls.append((
            "release", principal, funding_review_id, if_match, reason_code,
            idempotency_key,
        ))
        return _review(
            revision=4,
            assignment_status="RELEASED",
            available_actions=(),
            can_confirm=False,
            etag='"funding-review-4"',
        )

    def submit_funding_review_finding(
        self, *, principal, funding_review_id, if_match, disposition,
        reason_codes, required_field_codes, idempotency_key
    ):
        self.calls.append((
            "finding", principal, funding_review_id, if_match, disposition,
            reason_codes, required_field_codes, idempotency_key,
        ))
        return _review(
            status=disposition,
            revision=4,
            assignment_status="COMPLETED",
            available_actions=(),
            can_confirm=False,
            etag='"funding-review-4"',
        )


def test_projection_makes_false_can_confirm_unambiguous() -> None:
    active = _review()
    assert active.available_actions == (
        "CONFIRM",
        "RELEASE_ASSIGNMENT",
        "SUBMIT_FINDING",
    )
    assert active.assignment_status == "ACTIVE"
    assert active.confirmation_by_me is False
    assert active.can_confirm is True

    confirmed = _review(
        confirmation_count=1,
        assignment_status="COMPLETED",
        confirmation_by_me=True,
        available_actions=(),
        can_confirm=False,
    )
    assert confirmed.can_confirm is False
    assert confirmed.confirmation_by_me is True
    assert confirmed.assignment_status == "COMPLETED"
    with pytest.raises(ValueError):
        replace(confirmed, can_confirm=True)
    with pytest.raises(ValueError):
        replace(active, available_actions=("CONFIRM",))
    for missing in (
        "assignment_status", "confirmation_by_me", "available_actions"
    ):
        values = dict(active.__dict__)
        values.pop(missing)
        with pytest.raises(TypeError):
            FinanceFundingReviewDto(**values)


def test_http_release_and_finding_routes_are_closed_and_authority_free() -> None:
    probe = _FinanceResolutionProbe()
    api = EditorHttpApi(service=object(), finance_service=probe)

    released = api.handle(
        request=HttpRequest(
            method="POST",
            path=f"/v1/app/finance/funding-reviews/{REVIEW}/assignment/release",
            headers={
                "If-Match": '"funding-review-3"',
                "Idempotency-Key": "release-funding-0001",
            },
            json={"reason_code": "WORKLOAD_RELEASE"},
        ),
        principal=FINANCE,
    )
    assert released.status == 200
    assert released.json["data"]["assignment_status"] == "RELEASED"
    assert probe.calls[-1] == (
        "release", FINANCE, REVIEW, '"funding-review-3"',
        "WORKLOAD_RELEASE", "release-funding-0001",
    )

    found = api.handle(
        request=HttpRequest(
            method="POST",
            path=f"/v1/app/finance/funding-reviews/{REVIEW}/findings",
            headers={
                "If-Match": '"funding-review-3"',
                "Idempotency-Key": "finding-funding-0001",
            },
            json={
                "disposition": "REJECTED",
                "reason_codes": ["BUDGET_PLAN_UNACCEPTABLE"],
                "required_field_codes": ["BUDGET"],
            },
        ),
        principal=FINANCE,
    )
    assert found.status == 200
    assert found.json["data"]["status"] == "REJECTED"
    assert probe.calls[-1] == (
        "finding", FINANCE, REVIEW, '"funding-review-3"', "REJECTED",
        ("BUDGET_PLAN_UNACCEPTABLE",), ("BUDGET",),
        "finding-funding-0001",
    )

    forged = api.handle(
        request=HttpRequest(
            method="POST",
            path=f"/v1/app/finance/funding-reviews/{REVIEW}/findings",
            headers={
                "If-Match": '"funding-review-3"',
                "Idempotency-Key": "finding-funding-0002",
            },
            json={
                "disposition": "CONFIRMED",
                "reason_codes": ["BUDGET_PLAN_UNACCEPTABLE"],
                "required_field_codes": ["BUDGET"],
                "authority": "forged",
            },
        ),
        principal=FINANCE,
    )
    assert forged.status == 422


def test_reason_and_field_taxonomies_are_closed_and_disposition_specific() -> None:
    assert FINANCE_FUNDING_RELEASE_REASON_CODES == (
        "CONFLICT_DECLARED",
        "WORKLOAD_RELEASE",
    )
    assert set(FINANCE_FUNDING_FINDING_FIELD_CODES) == {
        "BUDGET", "DECLARATIONS", "RISK", "SCOPE",
    }
    assert FINANCE_FUNDING_FINDING_REASON_CODES == {
        "DISCREPANCY": (
            "EVIDENCE_REFERENCE_MISMATCH",
            "TARGET_CONTENT_MISMATCH",
        ),
        "REJECTED": (
            "BUDGET_PLAN_UNACCEPTABLE",
            "DECLARATION_CONFLICT",
            "SYNTHETIC_SCOPE_VIOLATION",
        ),
    }
