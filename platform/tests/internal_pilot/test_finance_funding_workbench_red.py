"""RED-first contract for the synthetic-only Finance funding workbench."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import inspect
from uuid import UUID

import pytest

from desire_platform.demand.adapters.postgres.migrations import (
    DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
    DEMAND_SCHEMA_HEAD_VERSION,
)
import desire_platform.internal_pilot.finance_funding as finance_funding
from desire_platform.internal_pilot.editor import (
    EditorHttpApi,
    EditorPrincipal,
    EditorServiceError,
    HttpRequest,
)
from desire_platform.internal_pilot.finance_funding import (
    FINANCE_FUNDING_ATTESTATION_CODES,
    FinanceFundingDomainError,
    FinanceFundingKeys,
    FinanceFundingQueueItemDto,
    FinanceFundingReviewDto,
    FinanceFundingReviewState,
    PsycopgFinanceFundingService,
    _review as project_postgres_review,
)


NOW = datetime(2026, 8, 15, 12, 0, tzinfo=timezone.utc)
ACTOR = "61000000-0000-4000-8000-000000000001"
SESSION = "62000000-0000-4000-8000-000000000001"
DEMAND = "63000000-0000-4000-8000-000000000001"
VERSION = "64000000-0000-4000-8000-000000000001"
CASE = "65000000-0000-4000-8000-000000000001"
ASSIGNMENT = "66000000-0000-4000-8000-000000000001"
TARGET_SHA256 = hashlib.sha256(b"synthetic-zero-funds-target").hexdigest()
EVIDENCE_SHA256 = hashlib.sha256(b"synthetic-funding-evidence").hexdigest()
CONTENT_SHA256 = hashlib.sha256(b"synthetic-demand-content").hexdigest()
MARKER = hashlib.sha256(b"finance-principal").digest()
ATTESTATIONS = (
    "SYNTHETIC_ONLY",
    "ZERO_REAL_FUNDS",
    "NO_PROVIDER_OR_PAYMENT",
    "TARGET_AND_EVIDENCE_MATCH",
)


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

MULTI_DUTY_FINANCE = EditorPrincipal(
    user_id=ACTOR,
    session_id=SESSION,
    organization_id=None,
    role_codes=("ACCESS_ADMIN", "FINANCE_OPERATOR"),
    workspace_id=f"platform:{ACTOR}",
    workspace_kind="PLATFORM",
    membership_id=None,
    organization_role_codes=(),
    user_role_codes=(),
    platform_duty_codes=("ACCESS_ADMIN", "FINANCE_OPERATOR"),
    principal_marker_sha256=MARKER,
)


class _Row:
    def __init__(self, value) -> None:
        self._value = value

    def fetchone(self):
        return self._value


class _FinanceCompatibilityConnection:
    def __init__(self, compatibility) -> None:
        self.compatibility = compatibility

    def execute(self, statement, parameters=None):
        del parameters
        if "session_user,current_user" in statement:
            return _Row(("demand_finance", "demand_finance", 18))
        if "FROM demand.schema_compatibility" in statement:
            return _Row(self.compatibility)
        return _Row(None)


def _queue_item() -> FinanceFundingQueueItemDto:
    return FinanceFundingQueueItemDto(
        demand_id=DEMAND,
        demand_version_id=VERSION,
        demand_revision=3,
        funding_review_id=None,
        review_status="AVAILABLE",
        review_revision=None,
        assigned_to_me=False,
        confirmation_count=0,
        required_confirmations=2,
        expires_at=NOW + timedelta(days=7),
        etag='"demand-3-finance-queue"',
    )


def _review(*, confirmations: int = 0, can_confirm: bool = True) -> FinanceFundingReviewDto:
    return FinanceFundingReviewDto(
        funding_review_id=CASE,
        demand_id=DEMAND,
        demand_version_id=VERSION,
        status="PENDING" if confirmations < 2 else "SECURED",
        revision=1 + confirmations,
        assignment_id=ASSIGNMENT,
        assignment_expires_at=NOW + timedelta(minutes=30),
        target_sha256=TARGET_SHA256,
        target_content_sha256=CONTENT_SHA256,
        planned_budget_currency="CNY",
        planned_budget_minimum_amount_minor=100_000,
        planned_budget_maximum_amount_minor=200_000,
        planned_budget_direct_cost_amount_minor=20_000,
        evidence_kind="INTERNAL_SANDBOX_ZERO_FUNDS_V1",
        evidence_reference_sha256=EVIDENCE_SHA256,
        sandbox_funds_amount_minor=0,
        provider_code="NONE",
        payment_operation_code="NONE",
        synthetic=True,
        legal_effect="NO_REAL_FUNDS_OR_PAYMENT",
        confirmation_count=confirmations,
        required_confirmations=2,
        assignment_status="ACTIVE" if can_confirm else "COMPLETED",
        confirmation_by_me=confirmations > 0 and not can_confirm,
        available_actions=(
            finance_funding.FINANCE_FUNDING_ACTIONS if can_confirm else ()
        ),
        can_confirm=can_confirm,
        etag=f'"funding-review-{1 + confirmations}"',
        replayed=False,
    )


def test_finance_schema_guard_has_no_private_schema_version_copy() -> None:
    source = inspect.getsource(finance_funding)

    assert "FINANCE_FUNDING_DEMAND_SCHEMA_VERSION" not in source
    assert "FINANCE_FUNDING_REQUIRED_IAM_SCHEMA_VERSION" not in source
    assert finance_funding.DEMAND_SCHEMA_HEAD_VERSION == DEMAND_SCHEMA_HEAD_VERSION == 16
    assert (
        finance_funding.DEMAND_REQUIRED_IAM_SCHEMA_VERSION
        == DEMAND_REQUIRED_IAM_SCHEMA_VERSION
        == 48
    )


def test_finance_schema_guard_follows_demand_contract_constants(monkeypatch) -> None:
    schema_head = DEMAND_SCHEMA_HEAD_VERSION + 100
    required_iam = DEMAND_REQUIRED_IAM_SCHEMA_VERSION + 100
    monkeypatch.setattr(
        finance_funding,
        "DEMAND_SCHEMA_HEAD_VERSION",
        schema_head,
        raising=False,
    )
    monkeypatch.setattr(
        finance_funding,
        "DEMAND_REQUIRED_IAM_SCHEMA_VERSION",
        required_iam,
        raising=False,
    )
    connection = _FinanceCompatibilityConnection(
        (
            "demand",
            schema_head,
            schema_head,
            schema_head,
            schema_head,
            required_iam,
        )
    )

    finance_funding._prepare(connection)


class _FinanceProbe:
    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []

    def list_funding_reviews(self, *, principal):
        self.calls.append(("list", principal))
        return (_queue_item(),)

    def claim_funding_review(
        self, *, principal, demand_id, if_match, idempotency_key
    ):
        self.calls.append(
            ("claim", principal, demand_id, if_match, idempotency_key)
        )
        return _review()

    def get_funding_review(self, *, principal, funding_review_id):
        self.calls.append(("detail", principal, funding_review_id))
        return _review()

    def confirm_funding_review(
        self,
        *,
        principal,
        funding_review_id,
        if_match,
        attestation_codes,
        idempotency_key,
    ):
        self.calls.append(
            (
                "confirm",
                principal,
                funding_review_id,
                if_match,
                attestation_codes,
                idempotency_key,
            )
        )
        return _review(confirmations=1, can_confirm=False)

    def release_funding_review_assignment(self, **values):
        self.calls.append(("release", values))
        return _review(can_confirm=False)

    def submit_funding_review_finding(self, **values):
        self.calls.append(("finding", values))
        return _review(can_confirm=False)


class _UnusedFinanceConnections:
    def checkout(self):
        raise AssertionError("authorization-only service must not checkout")

    def release(self, connection):
        raise AssertionError(connection)

    def discard(self, connection):
        raise AssertionError(connection)


class _AuthorizationOnlyFinanceService(PsycopgFinanceFundingService):
    def __init__(self) -> None:
        super().__init__(
            connections=_UnusedFinanceConnections(),
            keys=FinanceFundingKeys(
                id_key=b"i" * 32,
                idempotency_key=b"d" * 32,
                payload_key=b"p" * 32,
            ),
        )
        self.authorized_principal = None

    def _read(self, *, principal, operation, projector, funding_review_id=None):
        del operation, projector, funding_review_id
        self.authorized_principal = principal
        return ()


def test_finance_dtos_are_zero_funds_synthetic_and_closed() -> None:
    assert _queue_item().required_confirmations == 2
    review = _review()
    assert review.synthetic is True
    assert review.sandbox_funds_amount_minor == 0
    assert review.target_content_sha256 == CONTENT_SHA256
    assert review.planned_budget_currency == "CNY"
    assert review.planned_budget_minimum_amount_minor == 100_000
    assert review.planned_budget_maximum_amount_minor == 200_000
    assert review.planned_budget_direct_cost_amount_minor == 20_000
    assert review.provider_code == "NONE"
    assert review.payment_operation_code == "NONE"
    assert review.legal_effect == "NO_REAL_FUNDS_OR_PAYMENT"
    with pytest.raises(ValueError):
        FinanceFundingReviewDto(
            **{
                **review.__dict__,
                "sandbox_funds_amount_minor": 1,
            }
        )
    with pytest.raises(ValueError):
        FinanceFundingReviewDto(
            **{
                **review.__dict__,
                "required_confirmations": 1,
            }
        )
    for changes in (
        {"target_content_sha256": "0" * 63},
        {"planned_budget_currency": "USD"},
        {"planned_budget_minimum_amount_minor": 200_001},
        {"planned_budget_direct_cost_amount_minor": -1},
        {"provider_code": "FORGED_PROVIDER"},
        {"payment_operation_code": "CAPTURE"},
    ):
        with pytest.raises(ValueError):
            FinanceFundingReviewDto(**{**review.__dict__, **changes})


def test_late_receipt_replay_uses_only_historical_core_and_immutable_evidence() -> None:
    historical_core = (
        UUID(CASE),
        UUID(DEMAND),
        UUID(VERSION),
        "PENDING",
        1,
        UUID(ASSIGNMENT),
        NOW + timedelta(minutes=30),
        bytes.fromhex(TARGET_SHA256),
        bytes.fromhex(EVIDENCE_SHA256),
        0,
        "ACTIVE",
        False,
        list(finance_funding.FINANCE_FUNDING_ACTIONS),
        True,
    )
    immutable_evidence = (
        bytes.fromhex(CONTENT_SHA256),
        "CNY",
        100_000,
        200_000,
        20_000,
        0,
        "NONE",
        "NONE",
        "INTERNAL_SANDBOX_ZERO_FUNDS_V1",
        "NO_REAL_FUNDS_OR_PAYMENT",
    )
    first = project_postgres_review(
        historical_core,
        evidence=immutable_evidence,
        replayed=False,
    )
    # A later root may be FUNDED or MATCHING, but neither current-root status
    # nor its aggregate revision is an input to the immutable summary.
    late = project_postgres_review(
        historical_core,
        evidence=immutable_evidence,
        replayed=True,
    )
    assert late == FinanceFundingReviewDto(
        **{**first.__dict__, "replayed": True}
    )
    assert "target_status" not in late.__dict__
    assert "target_revision" not in late.__dict__


def test_domain_requires_two_distinct_assigned_finance_operators() -> None:
    second = "61000000-0000-4000-8000-000000000002"
    state = FinanceFundingReviewState.start(
        funding_review_id=CASE,
        demand_id=DEMAND,
        demand_version_id=VERSION,
        actor_user_id=ACTOR,
    )
    first = state.confirm(
        actor_user_id=ACTOR,
        attestation_codes=FINANCE_FUNDING_ATTESTATION_CODES,
    )
    assert first.status == "PENDING"
    assert first.confirmed_user_ids == (ACTOR,)
    with pytest.raises(FinanceFundingDomainError) as duplicate:
        first.confirm(
            actor_user_id=ACTOR,
            attestation_codes=FINANCE_FUNDING_ATTESTATION_CODES,
        )
    assert duplicate.value.code == "FUNDING_CONFIRMATION_DUPLICATE"
    with pytest.raises(FinanceFundingDomainError) as unassigned:
        first.confirm(
            actor_user_id=second,
            attestation_codes=FINANCE_FUNDING_ATTESTATION_CODES,
        )
    assert unassigned.value.code == "ASSIGNMENT_REQUIRED"
    completed = first.assign(actor_user_id=second).confirm(
        actor_user_id=second,
        attestation_codes=FINANCE_FUNDING_ATTESTATION_CODES,
    )
    assert completed.status == "SECURED"
    assert completed.confirmed_user_ids == (ACTOR, second)


def test_http_exposes_closed_queue_claim_detail_and_confirm_routes() -> None:
    finance = _FinanceProbe()
    api = EditorHttpApi(service=object(), finance_service=finance)

    listed = api.handle(
        request=HttpRequest(
            method="GET",
            path="/v1/app/finance/funding-reviews",
            headers={},
            json={},
        ),
        principal=FINANCE,
    )
    assert listed.status == 200
    assert listed.json == {
        "data": [
            {
                "demand_id": DEMAND,
                "demand_version_id": VERSION,
                "demand_revision": 3,
                "funding_review_id": None,
                "review_status": "AVAILABLE",
                "review_revision": None,
                "assigned_to_me": False,
                "confirmation_count": 0,
                "required_confirmations": 2,
                "expires_at": "2026-08-22T12:00:00+00:00",
                "etag": '"demand-3-finance-queue"',
            }
        ]
    }

    claimed = api.handle(
        request=HttpRequest(
            method="POST",
            path=f"/v1/app/finance/funding-reviews/{DEMAND}/claim",
            headers={
                "If-Match": '"demand-3-finance-queue"',
                "Idempotency-Key": "finance-claim-0001",
            },
            json={},
        ),
        principal=FINANCE,
    )
    assert claimed.status == 200
    assert claimed.headers["ETag"] == '"funding-review-1"'
    assert finance.calls[-1] == (
        "claim",
        FINANCE,
        DEMAND,
        '"demand-3-finance-queue"',
        "finance-claim-0001",
    )

    detail = api.handle(
        request=HttpRequest(
            method="GET",
            path=f"/v1/app/finance/funding-reviews/{CASE}",
            headers={},
            json={},
        ),
        principal=FINANCE,
    )
    assert detail.status == 200
    assert detail.json["data"]["legal_effect"] == "NO_REAL_FUNDS_OR_PAYMENT"
    assert detail.json["data"]["planned_budget_currency"] == "CNY"
    assert detail.json["data"]["planned_budget_maximum_amount_minor"] == 200_000
    assert detail.json["data"]["sandbox_funds_amount_minor"] == 0
    assert detail.json["data"]["provider_code"] == "NONE"
    assert detail.json["data"]["payment_operation_code"] == "NONE"

    confirmed = api.handle(
        request=HttpRequest(
            method="POST",
            path=f"/v1/app/finance/funding-reviews/{CASE}/confirm",
            headers={
                "If-Match": '"funding-review-1"',
                "Idempotency-Key": "finance-confirm-0001",
            },
            json={"attestation_codes": list(ATTESTATIONS)},
        ),
        principal=FINANCE,
    )
    assert confirmed.status == 200
    assert finance.calls[-1] == (
        "confirm",
        FINANCE,
        CASE,
        '"funding-review-1"',
        ATTESTATIONS,
        "finance-confirm-0001",
    )


def test_multi_duty_finance_principal_reaches_http_and_postgres_service() -> None:
    finance = _FinanceProbe()
    api = EditorHttpApi(service=object(), finance_service=finance)

    response = api.handle(
        request=HttpRequest(
            method="GET",
            path="/v1/app/finance/funding-reviews",
            headers={},
            json={},
        ),
        principal=MULTI_DUTY_FINANCE,
    )

    assert response.status == 200
    assert finance.calls == [("list", MULTI_DUTY_FINANCE)]
    postgres = _AuthorizationOnlyFinanceService()
    assert postgres.list_funding_reviews(principal=MULTI_DUTY_FINANCE) == ()
    assert postgres.authorized_principal is MULTI_DUTY_FINANCE


@pytest.mark.parametrize(
    "principal",
    (
        EditorPrincipal(
            user_id=ACTOR,
            session_id=SESSION,
            organization_id=None,
            role_codes=("OPERATIONS_REVIEWER",),
            workspace_id=f"platform:{ACTOR}",
            workspace_kind="PLATFORM",
            platform_duty_codes=("OPERATIONS_REVIEWER",),
            principal_marker_sha256=MARKER,
        ),
        EditorPrincipal(
            user_id=ACTOR,
            session_id=SESSION,
            organization_id=None,
            role_codes=("FINANCE_OPERATOR",),
            workspace_id=f"platform:{ACTOR}",
            workspace_kind="PLATFORM",
            platform_duty_codes=("FINANCE_OPERATOR", "FINANCE_OPERATOR"),
            principal_marker_sha256=MARKER,
        ),
        EditorPrincipal(
            user_id=ACTOR,
            session_id=SESSION,
            organization_id=None,
            role_codes=("FINANCE_OPERATOR", "ROOT"),
            workspace_id=f"platform:{ACTOR}",
            workspace_kind="PLATFORM",
            platform_duty_codes=("FINANCE_OPERATOR", "ROOT"),
            principal_marker_sha256=MARKER,
        ),
        EditorPrincipal(
            user_id=ACTOR,
            session_id=SESSION,
            organization_id=None,
            role_codes=("FINANCE_OPERATOR", "TRUST_OFFICER"),
            workspace_id=f"platform:{ACTOR}",
            workspace_kind="PLATFORM",
            platform_duty_codes=("TRUST_OFFICER", "FINANCE_OPERATOR"),
            principal_marker_sha256=MARKER,
        ),
    ),
    ids=("missing-finance", "duplicate", "unknown", "unordered"),
)
def test_finance_authorization_rejects_non_closed_duty_sets(principal) -> None:
    finance = _FinanceProbe()
    response = EditorHttpApi(
        service=object(), finance_service=finance
    ).handle(
        request=HttpRequest(
            method="GET",
            path="/v1/app/finance/funding-reviews",
            headers={},
            json={},
        ),
        principal=principal,
    )
    assert response.status == 404
    assert response.json["error"]["code"] == "RESOURCE_NOT_FOUND"
    assert finance.calls == []

    postgres = _AuthorizationOnlyFinanceService()
    with pytest.raises(EditorServiceError) as hidden:
        postgres.list_funding_reviews(principal=principal)
    assert (hidden.value.status, hidden.value.code) == (
        404,
        "RESOURCE_NOT_FOUND",
    )
    assert postgres.authorized_principal is None


@pytest.mark.parametrize(
    "body, expected_path",
    (
        ({"actor_id": ACTOR, "attestation_codes": list(ATTESTATIONS)}, "/actor_id"),
        ({"organization_id": DEMAND, "attestation_codes": list(ATTESTATIONS)}, "/organization_id"),
        ({"role": "FINANCE_OPERATOR", "attestation_codes": list(ATTESTATIONS)}, "/role"),
        ({"funded": True, "attestation_codes": list(ATTESTATIONS)}, "/funded"),
        ({"amount_minor": 1, "attestation_codes": list(ATTESTATIONS)}, "/amount_minor"),
        ({"provider": "real", "attestation_codes": list(ATTESTATIONS)}, "/provider"),
    ),
)
def test_http_rejects_authority_money_and_provider_inputs(body, expected_path) -> None:
    api = EditorHttpApi(service=object(), finance_service=_FinanceProbe())
    response = api.handle(
        request=HttpRequest(
            method="POST",
            path=f"/v1/app/finance/funding-reviews/{CASE}/confirm",
            headers={
                "If-Match": '"funding-review-1"',
                "Idempotency-Key": "finance-confirm-0002",
            },
            json=body,
        ),
        principal=FINANCE,
    )
    assert response.status == 422
    assert response.json["error"] == {
        "code": "UNKNOWN_FIELD",
        "path": expected_path,
    }


def test_http_requires_exact_attestations_occ_and_idempotency() -> None:
    api = EditorHttpApi(service=object(), finance_service=_FinanceProbe())
    path = f"/v1/app/finance/funding-reviews/{CASE}/confirm"
    missing_etag = api.handle(
        request=HttpRequest(
            method="POST",
            path=path,
            headers={"Idempotency-Key": "finance-confirm-0003"},
            json={"attestation_codes": list(ATTESTATIONS)},
        ),
        principal=FINANCE,
    )
    assert missing_etag.status == 428
    assert missing_etag.json["error"]["path"] == "/headers/If-Match"

    wrong_codes = api.handle(
        request=HttpRequest(
            method="POST",
            path=path,
            headers={
                "If-Match": '"funding-review-1"',
                "Idempotency-Key": "finance-confirm-0004",
            },
            json={"attestation_codes": ["SYNTHETIC_ONLY"]},
        ),
        principal=FINANCE,
    )
    assert wrong_codes.status == 422
    assert wrong_codes.json["error"] == {
        "code": "INVALID_ATTESTATION_CODES",
        "path": "/attestation_codes",
    }


def test_non_finance_role_is_not_given_a_finance_surface() -> None:
    reviewer = EditorPrincipal(
        user_id=ACTOR,
        session_id=SESSION,
        organization_id=None,
        role_codes=("OPERATIONS_REVIEWER",),
        workspace_id=f"platform:{ACTOR}",
        workspace_kind="PLATFORM",
        membership_id=None,
        organization_role_codes=(),
        user_role_codes=(),
        platform_duty_codes=("OPERATIONS_REVIEWER",),
        principal_marker_sha256=MARKER,
    )
    api = EditorHttpApi(service=object(), finance_service=_FinanceProbe())
    response = api.handle(
        request=HttpRequest(
            method="GET",
            path="/v1/app/finance/funding-reviews",
            headers={},
            json={},
        ),
        principal=reviewer,
    )
    assert response.status == 404
    assert response.json["error"]["code"] == "RESOURCE_NOT_FOUND"
