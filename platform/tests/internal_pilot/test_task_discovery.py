from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest

from desire_platform.internal_pilot.editor import (
    EditorHttpApi,
    EditorPrincipal,
    EditorResourceDto,
    EditorReviewAssignmentDto,
    EditorReviewHistoryItemDto,
    EditorReviewHistoryPageDto,
    EditorReviewQueueItemDto,
    EditorServiceError,
    EditorVersionDto,
    HttpRequest,
)
from desire_platform.internal_pilot.finance_funding import (
    FINANCE_FUNDING_ACTIONS,
    FinanceFundingQueueItemDto,
    FinanceFundingReviewDto,
)
from desire_platform.internal_pilot.task_discovery import (
    CurrentAccountTaskDiscoveryService,
)
from desire_platform.trust_safety.http import TrustHttpProjection
from desire_platform.trust_safety.ports import (
    AppealActiveAssignmentItem,
    AppealActiveAssignmentsProjection,
    AppealCompletedAssignmentItem,
    AppealCompletedAssignmentsProjection,
    AppealApplicationDraftProjection,
    AppealOwnProjection,
    AppealQueueItem,
    AppealQueueProjection,
    AppealSourceProjection,
    AppealSubmittedApplicationProjection,
)


def _id(number: int) -> str:
    return str(UUID(int=number))


NOW = datetime(2026, 8, 25, 8, 0, tzinfo=timezone.utc)
USER_A = _id(1)
USER_B = _id(2)
SESSION_A = _id(3)
SESSION_B = _id(4)
ORGANIZATION_A = _id(5)
ORGANIZATION_B = _id(6)
MEMBERSHIP_A = _id(7)
MEMBERSHIP_B = _id(8)
PROFILE_A = _id(20)
PROFILE_B = _id(21)
DEMAND_A = _id(30)
DEMAND_B = _id(31)
DEMAND_C = _id(32)
DEMAND_VERSION = _id(33)
REVIEW_ASSIGNMENT = _id(34)
REVIEW_HISTORY = _id(35)
FINANCE_REVIEW = _id(40)
FINANCE_ASSIGNMENT = _id(41)
REPORT = _id(50)
TRUST_CASE = _id(51)
TRUST_HOLD = _id(52)
OUTCOME = _id(53)
APPEAL = _id(60)
APPEAL_EVIDENCE = _id(61)
TRUST_ETAG = '"trust-7-0123456789abcdef01234567"'
APPEAL_ETAG = '"appeal-6-0123456789abcdef01234567"'


def _personal(*, user_id: str = USER_A, session_id: str = SESSION_A) -> EditorPrincipal:
    return EditorPrincipal(
        user_id=user_id,
        session_id=session_id,
        organization_id=None,
        role_codes=("CREATOR",),
        workspace_id=f"personal:{user_id}",
        workspace_kind="PERSONAL",
        membership_id=None,
        organization_role_codes=(),
        user_role_codes=("CREATOR",),
        platform_duty_codes=(),
        principal_marker_sha256=b"p" * 32,
    )


def _owner(
    *,
    user_id: str = USER_A,
    session_id: str = SESSION_A,
    organization_id: str = ORGANIZATION_A,
    membership_id: str = MEMBERSHIP_A,
) -> EditorPrincipal:
    return EditorPrincipal(
        user_id=user_id,
        session_id=session_id,
        organization_id=organization_id,
        role_codes=("DEMAND_OWNER",),
        workspace_id=f"org:{organization_id}",
        workspace_kind="ORGANIZATION",
        membership_id=membership_id,
        organization_role_codes=("DEMAND_OWNER",),
        user_role_codes=(),
        platform_duty_codes=(),
        principal_marker_sha256=b"o" * 32,
    )


def _platform(*roles: str) -> EditorPrincipal:
    duties = tuple(sorted(roles))
    return EditorPrincipal(
        user_id=USER_A,
        session_id=SESSION_A,
        organization_id=None,
        role_codes=duties,
        workspace_id=f"platform:{USER_A}",
        workspace_kind="PLATFORM",
        membership_id=None,
        organization_role_codes=(),
        user_role_codes=(),
        platform_duty_codes=duties,
        principal_marker_sha256=b"d" * 32,
    )


def _resource(
    *,
    resource_type: str,
    resource_id: str,
    status: str,
    updated_at: datetime = NOW,
    capabilities: tuple[str, ...] = (),
    review_assignment: EditorReviewAssignmentDto | None = None,
) -> EditorResourceDto:
    version = EditorVersionDto(
        version_id=_id(900 + UUID(resource_id).int),
        version_no=1,
        based_on_version_id=None,
        status="DRAFT" if status == "DRAFT" else "PUBLISHED",
        content={},
        content_sha256="a" * 64,
        taxonomy_bundle_id=_id(999),
        created_at=updated_at,
    )
    return EditorResourceDto(
        resource_type=resource_type,
        object_id=resource_id,
        status=status,
        revision=1,
        etag=f'"{resource_type.lower()}-1"',
        capabilities=capabilities,
        editable_paths=(),
        current_version=None if status == "ARCHIVED" else version,
        versions=(version,),
        review_assignment=review_assignment,
    )


class _Editor:
    def __init__(self) -> None:
        self.profiles_by_user: dict[str, tuple[EditorResourceDto, ...]] = {}
        self.demands_by_scope: dict[
            tuple[str, str | None], tuple[EditorResourceDto, ...]
        ] = {}
        self.review_queue: tuple[EditorReviewQueueItemDto, ...] = ()
        self.review_history = EditorReviewHistoryPageDto(
            schema_version="demand-review-history-v1",
            items=(),
            next_cursor=None,
            has_more=False,
        )
        self.calls: list[tuple[str, EditorPrincipal]] = []

    def list_profiles(self, *, principal):
        self.calls.append(("profiles", principal))
        return self.profiles_by_user.get(principal.user_id, ())

    def list_demands(self, *, principal):
        self.calls.append(("demands", principal))
        return self.demands_by_scope.get(
            (principal.workspace_kind, principal.organization_id),
            (),
        )

    def list_review_queue(self, *, principal):
        self.calls.append(("review_queue", principal))
        return self.review_queue

    def list_review_history(self, *, principal, cursor, limit):
        self.calls.append(("review_history", principal))
        assert (cursor, limit) == (None, 100)
        return self.review_history


def _own_report_projection(
    *,
    status: str = "OPEN",
    outcome: bool = False,
    has_more: bool = False,
) -> TrustHttpProjection:
    outcome_value = None
    if outcome:
        outcome_value = {
            "appeal_deadline": "2026-09-01T08:00:00Z",
            "appeal_eligibility_code": "ELIGIBLE",
            "decided_at": "2026-08-25T09:00:00Z",
            "outcome_code": "PROTECTION_MODIFIED",
            "outcome_version_id": OUTCOME,
        }
    return TrustHttpProjection(
        "OWN_REPORT_LIST",
        {
            "entity_tag": TRUST_ETAG,
            "items": [
                {
                    "category": "WORKFLOW_INTEGRITY",
                    "demand_id": DEMAND_A,
                    "outcome": outcome_value,
                    "report_id": REPORT,
                    "status": status,
                    "submitted_at": "2026-08-25T08:00:00Z",
                }
            ],
            "next_cursor": (
                "a" * 64 + "." + "b" * 43 if has_more else None
            ),
        },
        TRUST_ETAG,
    )


def _empty_trust_projection(kind: str) -> TrustHttpProjection:
    return TrustHttpProjection(
        kind,
        {
            "entity_tag": TRUST_ETAG,
            "items": [],
            **({"next_cursor": None} if kind == "OWN_REPORT_LIST" else {}),
        },
        TRUST_ETAG,
    )


class _Trust:
    def __init__(self) -> None:
        self.own = _empty_trust_projection("OWN_REPORT_LIST")
        self.case_queue = _empty_trust_projection("CASE_QUEUE")
        self.hold_queue = _empty_trust_projection("HOLD_RELEASE_QUEUE")
        self.assignments = _empty_trust_projection(
            "MY_ACTIVE_CASE_ASSIGNMENTS"
        )
        self.completed = TrustHttpProjection(
            "MY_COMPLETED_CASE_ASSIGNMENTS",
            {
                "entity_tag": TRUST_ETAG,
                "has_more": False,
                "items": [],
            },
            TRUST_ETAG,
        )
        self.calls: list[tuple[str, object]] = []

    def list_own_reports(self, *, actor, limit, cursor):
        self.calls.append(("own", actor))
        assert (limit, cursor) == (100, None)
        return self.own

    def list_case_queue(self, *, actor, limit):
        self.calls.append(("case_queue", actor))
        assert limit == 100
        return self.case_queue

    def list_hold_release_queue(self, *, actor, limit):
        self.calls.append(("hold_queue", actor))
        assert limit == 100
        return self.hold_queue

    def list_my_active_case_assignments(self, *, actor, limit):
        self.calls.append(("assignments", actor))
        assert limit == 100
        return self.assignments

    def list_my_completed_case_assignments(self, *, actor, limit):
        self.calls.append(("completed", actor))
        assert limit == 100
        return self.completed


def _appeal_source() -> AppealSourceProjection:
    return AppealSourceProjection(
        outcome_version_id=OUTCOME,
        case_id=TRUST_CASE,
        demand_id=DEMAND_A,
        demand_version_id=DEMAND_VERSION,
        outcome_code="PROTECTION_MODIFIED",
        reason_codes=("POLICY_REQUIREMENT_NOT_MET",),
        action_codes=("VERIFY_DEMAND",),
        evidence_packet_version_id=APPEAL_EVIDENCE,
        evidence_packet_sha256="1" * 64,
        policy_version="trust-case-outcome-v1",
        decided_at=NOW - timedelta(days=1),
        appeal_eligible=True,
        appeal_eligibility_code="ELIGIBLE",
        appeal_deadline=NOW + timedelta(days=7),
        content_sha256="2" * 64,
    )


def _own_appeal(status: str) -> AppealOwnProjection:
    draft = AppealApplicationDraftProjection(
        version=1,
        grounds=("PROCEDURAL_ERROR",),
        requested_outcome="MODIFY_MEASURE",
        statement_recorded=True,
        new_evidence_reference_ids=(),
        edited_at=NOW,
    )
    application = None
    if status != "DRAFT":
        application = AppealSubmittedApplicationProjection(
            grounds=("PROCEDURAL_ERROR",),
            requested_outcome="MODIFY_MEASURE",
            statement_recorded=True,
            new_evidence_reference_ids=(),
            submitted_at=NOW,
        )
    return AppealOwnProjection(
        appeal_id=APPEAL,
        source_outcome_version_id=OUTCOME,
        source_case_id=TRUST_CASE,
        source=_appeal_source(),
        status=status,
        aggregate_version=6,
        application_draft=draft,
        application=application,
        decision=None,
        entity_tag=APPEAL_ETAG,
    )


class _Appeals:
    def __init__(self) -> None:
        self.own: AppealOwnProjection | None = None
        self.queue = AppealQueueProjection(items=(), entity_tag=APPEAL_ETAG)
        self.assignments = AppealActiveAssignmentsProjection(
            items=(), entity_tag=APPEAL_ETAG
        )
        self.completed = AppealCompletedAssignmentsProjection(
            items=(), has_more=False, entity_tag=APPEAL_ETAG
        )
        self.calls: list[tuple[str, object]] = []

    def find_own_appeal_by_source(self, *, actor, source_outcome_version_id):
        self.calls.append(("own", actor))
        assert source_outcome_version_id == OUTCOME
        return self.own

    def list_appeal_queue(self, *, actor, limit):
        self.calls.append(("queue", actor))
        assert limit == 100
        return self.queue

    def list_my_active_appeal_assignments(self, *, actor, limit):
        self.calls.append(("assignments", actor))
        assert limit == 100
        return self.assignments

    def list_my_completed_appeal_assignments(self, *, actor, limit):
        self.calls.append(("completed", actor))
        assert limit == 100
        return self.completed


def _finance_queue_item(
    *,
    status: str,
    demand_id: str = DEMAND_B,
    review_id: str = FINANCE_REVIEW,
    assigned_to_me: bool = False,
) -> FinanceFundingQueueItemDto:
    pending = status == "PENDING"
    return FinanceFundingQueueItemDto(
        demand_id=demand_id,
        demand_version_id=DEMAND_VERSION,
        demand_revision=3,
        funding_review_id=review_id if pending else None,
        review_status=status,
        review_revision=1 if pending else None,
        assigned_to_me=assigned_to_me,
        confirmation_count=0,
        required_confirmations=2,
        expires_at=NOW + timedelta(days=7),
        etag=(
            '"funding-review-1"'
            if pending
            else '"demand-3-finance-queue"'
        ),
    )


def _finance_review() -> FinanceFundingReviewDto:
    return FinanceFundingReviewDto(
        funding_review_id=FINANCE_REVIEW,
        demand_id=DEMAND_B,
        demand_version_id=DEMAND_VERSION,
        status="PENDING",
        revision=1,
        assignment_id=FINANCE_ASSIGNMENT,
        assignment_expires_at=NOW + timedelta(minutes=30),
        target_sha256="3" * 64,
        target_content_sha256="4" * 64,
        planned_budget_currency="CNY",
        planned_budget_minimum_amount_minor=100_000,
        planned_budget_maximum_amount_minor=200_000,
        planned_budget_direct_cost_amount_minor=20_000,
        evidence_kind="INTERNAL_SANDBOX_ZERO_FUNDS_V1",
        evidence_reference_sha256="5" * 64,
        sandbox_funds_amount_minor=0,
        provider_code="NONE",
        payment_operation_code="NONE",
        synthetic=True,
        legal_effect="NO_REAL_FUNDS_OR_PAYMENT",
        confirmation_count=0,
        required_confirmations=2,
        assignment_status="ACTIVE",
        confirmation_by_me=False,
        available_actions=FINANCE_FUNDING_ACTIONS,
        can_confirm=True,
        etag='"funding-review-1"',
        replayed=False,
    )


class _Finance:
    def __init__(self) -> None:
        self.queue: tuple[FinanceFundingQueueItemDto, ...] = ()
        self.details = {FINANCE_REVIEW: _finance_review()}
        self.calls: list[tuple[str, object]] = []

    def list_funding_reviews(self, *, principal):
        self.calls.append(("queue", principal))
        return self.queue

    def get_funding_review(self, *, principal, funding_review_id):
        self.calls.append(("detail", principal))
        return self.details[funding_review_id]


def _service(
    *,
    editor: _Editor | None = None,
    finance: _Finance | None = None,
    trust: _Trust | None = None,
    appeals: _Appeals | None = None,
) -> CurrentAccountTaskDiscoveryService:
    return CurrentAccountTaskDiscoveryService(
        editor_service=editor,
        finance_service=finance,
        trust_projections=trust,
        appeal_projections=appeals,
    )


def test_personal_creator_profile_discovery_is_principal_scoped_and_empty_safe() -> None:
    editor = _Editor()
    editor.profiles_by_user = {
        USER_A: (
            _resource(
                resource_type="CREATOR_PROFILE",
                resource_id=PROFILE_A,
                status="DRAFT",
            ),
        ),
        USER_B: (
            _resource(
                resource_type="CREATOR_PROFILE",
                resource_id=PROFILE_B,
                status="ACTIVE",
            ),
        ),
    }
    service = _service(editor=editor)

    first = service.list_tasks(principal=_personal())
    second = service.list_tasks(
        principal=_personal(user_id=USER_B, session_id=SESSION_B)
    )

    assert [(item.resource_kind, item.resource_id) for item in first.items] == [
        ("CREATOR_PROFILE", PROFILE_A)
    ]
    assert first.items[0].classification == "NEEDS_ACTION"
    assert first.items[0].next_action == "VIEW_CREATOR_PROFILE"
    assert [(item.resource_kind, item.resource_id) for item in second.items] == [
        ("CREATOR_PROFILE", PROFILE_B)
    ]
    assert second.items[0].classification == "WAITING"
    assert second.items[0].next_action == "VIEW_CREATOR_PROFILE"
    assert all(call[1].user_id in {USER_A, USER_B} for call in editor.calls)

    editor.profiles_by_user[USER_A] = ()
    empty = service.list_tasks(principal=_personal())
    assert empty.items == ()
    assert empty.has_more is False


@pytest.mark.parametrize(
    ("status", "classification", "next_action"),
    (
        ("DRAFT", "NEEDS_ACTION", "VIEW_CREATOR_PROFILE"),
        ("ACTIVE", "WAITING", "VIEW_CREATOR_PROFILE"),
        ("PAUSED", "WAITING", "VIEW_CREATOR_PROFILE"),
        ("ARCHIVED", "COMPLETED", "VIEW_CREATOR_PROFILE"),
    ),
)
def test_creator_profile_states_have_closed_non_coercive_mapping(
    status: str,
    classification: str,
    next_action: str,
) -> None:
    editor = _Editor()
    editor.profiles_by_user[USER_A] = (
        _resource(
            resource_type="CREATOR_PROFILE",
            resource_id=PROFILE_A,
            status=status,
        ),
    )

    item = _service(editor=editor).list_tasks(principal=_personal()).items[0]

    assert (item.source_status, item.classification, item.next_action) == (
        status,
        classification,
        next_action,
    )


def test_demand_state_transition_preserves_identity_and_terminal_history() -> None:
    editor = _Editor()
    trust = _Trust()
    appeals = _Appeals()
    service = _service(editor=editor, trust=trust, appeals=appeals)
    scope = ("ORGANIZATION", ORGANIZATION_A)

    observed = []
    for status in ("DRAFT", "SUBMITTED", "MATCHED"):
        editor.demands_by_scope[scope] = (
            _resource(
                resource_type="DEMAND",
                resource_id=DEMAND_A,
                status=status,
            ),
        )
        item = next(
            item
            for item in service.list_tasks(principal=_owner()).items
            if item.resource_kind == "DEMAND"
        )
        observed.append(
            (item.resource_id, item.source_status, item.classification)
        )

    assert observed == [
        (DEMAND_A, "DRAFT", "NEEDS_ACTION"),
        (DEMAND_A, "SUBMITTED", "WAITING"),
        (DEMAND_A, "MATCHED", "COMPLETED"),
    ]


def test_owner_trust_and_appeal_history_remains_discoverable_and_truncation_is_explicit() -> None:
    editor = _Editor()
    trust = _Trust()
    appeals = _Appeals()
    service = _service(editor=editor, trust=trust, appeals=appeals)

    trust.own = _own_report_projection(status="OPEN")
    open_result = service.list_tasks(principal=_owner())
    assert [
        (item.resource_kind, item.source_status, item.classification)
        for item in open_result.items
    ] == [("TRUST_REPORT", "OPEN", "WAITING")]

    trust.own = _own_report_projection(
        status="DECIDED", outcome=True, has_more=True
    )
    appeals.own = _own_appeal("DRAFT")
    decided_result = service.list_tasks(principal=_owner())
    assert decided_result.has_more is True
    assert {
        item.resource_kind: (item.resource_id, item.classification)
        for item in decided_result.items
    } == {
        "APPEAL": (APPEAL, "NEEDS_ACTION"),
        "TRUST_REPORT": (REPORT, "COMPLETED"),
    }

    appeals.own = _own_appeal("WITHDRAWN")
    terminal_result = service.list_tasks(principal=_owner())
    terminal_appeal = next(
        item for item in terminal_result.items if item.resource_kind == "APPEAL"
    )
    assert (
        terminal_appeal.resource_id,
        terminal_appeal.source_status,
        terminal_appeal.classification,
    ) == (APPEAL, "WITHDRAWN", "COMPLETED")
    assert all(call[1].organization_id == ORGANIZATION_A for call in trust.calls)


def test_operations_reviewer_completed_decision_discovers_the_history_action() -> None:
    editor = _Editor()
    editor.review_history = EditorReviewHistoryPageDto(
        schema_version="demand-review-history-v1",
        items=(
            EditorReviewHistoryItemDto(
                review_id=REVIEW_HISTORY,
                demand_id=DEMAND_A,
                demand_version_id=DEMAND_VERSION,
                decision="VERIFIED",
                reason_codes=(),
                required_field_codes=(),
                budget_health_code="HEALTHY",
                risk_code="STANDARD",
                reviewed_at=NOW,
            ),
        ),
        next_cursor="a" * 64 + "." + "b" * 43,
        has_more=True,
    )

    result = _service(editor=editor).list_tasks(
        principal=_platform("OPERATIONS_REVIEWER")
    )

    assert result.has_more is True
    assert len(result.items) == 1
    item = result.items[0]
    assert (
        item.resource_kind,
        item.resource_id,
        item.source_status,
        item.classification,
        item.next_action,
        item.resource_path,
        item.updated_at,
        item.due_at,
    ) == (
        "DEMAND_REVIEW",
        REVIEW_HISTORY,
        "VERIFIED",
        "COMPLETED",
        "VIEW_DEMAND_REVIEW_HISTORY",
        "/v1/app/review-history",
        NOW,
        None,
    )


def test_trust_officer_completed_outcome_discovers_only_safe_personal_history() -> None:
    trust = _Trust()
    trust.completed = TrustHttpProjection(
        "MY_COMPLETED_CASE_ASSIGNMENTS",
        {
            "entity_tag": TRUST_ETAG,
            "has_more": True,
            "items": [
                {
                    "case_id": TRUST_CASE,
                    "decided_at": "2026-08-25T10:00:00+00:00",
                    "outcome_code": "PROTECTION_MAINTAINED",
                }
            ],
        },
        TRUST_ETAG,
    )

    result = _service(trust=trust).list_tasks(
        principal=_platform("TRUST_OFFICER")
    )

    assert result.has_more is True
    assert len(result.items) == 1
    item = result.items[0]
    assert (
        item.resource_kind,
        item.resource_id,
        item.source_status,
        item.classification,
        item.next_action,
        item.resource_path,
        item.updated_at,
        item.due_at,
    ) == (
        "TRUST_CASE",
        TRUST_CASE,
        "PROTECTION_MAINTAINED",
        "COMPLETED",
        "VIEW_TRUST_CASE_HISTORY",
        "/v1/app/trust/history",
        NOW + timedelta(hours=2),
        None,
    )
    assert [name for name, _actor in trust.calls] == [
        "case_queue",
        "hold_queue",
        "assignments",
        "completed",
    ]
    assert all(call[1].organization_id is None for call in trust.calls)

def test_platform_queues_and_assignments_use_only_existing_scoped_projections() -> None:
    principal = _platform(
        "APPEAL_REVIEWER",
        "FINANCE_OPERATOR",
        "OPERATIONS_REVIEWER",
        "TRUST_OFFICER",
    )
    editor = _Editor()
    editor.review_queue = (
        EditorReviewQueueItemDto(
            demand_id=DEMAND_A,
            demand_revision=3,
            demand_version_no=1,
            submitted_at=NOW,
            demand_expires_at=NOW + timedelta(days=7),
            etag='"demand-3-review-queue"',
        ),
    )
    editor.demands_by_scope[("PLATFORM", None)] = (
        _resource(
            resource_type="DEMAND",
            resource_id=DEMAND_A,
            status="SUBMITTED",
            capabilities=("RECORD_FINDINGS",),
            review_assignment=EditorReviewAssignmentDto(
                assignment_id=REVIEW_ASSIGNMENT,
                status="ACTIVE",
                expires_at=NOW + timedelta(hours=1),
            ),
        ),
    )
    finance = _Finance()
    finance.queue = (
        _finance_queue_item(status="AVAILABLE", demand_id=DEMAND_B),
        _finance_queue_item(status="PENDING", assigned_to_me=True),
    )
    trust = _Trust()
    trust.case_queue = TrustHttpProjection(
        "CASE_QUEUE",
        {
            "entity_tag": TRUST_ETAG,
            "items": [
                {
                    "category": "WORKFLOW_INTEGRITY",
                    "case_id": TRUST_CASE,
                    "demand_id": DEMAND_A,
                    "demand_version_id": DEMAND_VERSION,
                    "entity_tag": TRUST_ETAG,
                    "impact_codes": ["WORKFLOW_INTEGRITY_RISK"],
                    "report_id": REPORT,
                    "submitted_at": "2026-08-25T08:00:00+00:00",
                }
            ],
        },
        TRUST_ETAG,
    )
    trust.hold_queue = TrustHttpProjection(
        "HOLD_RELEASE_QUEUE",
        {
            "entity_tag": TRUST_ETAG,
            "items": [
                {
                    "action_codes": ["SUBMIT_DEMAND"],
                    "case_id": TRUST_CASE,
                    "demand_id": DEMAND_A,
                    "demand_version_id": DEMAND_VERSION,
                    "entity_tag": TRUST_ETAG,
                    "expires_at": "2026-08-25T10:00:00+00:00",
                    "hold_id": TRUST_HOLD,
                    "reason_code": "PARTICIPANT_SAFETY_RISK",
                }
            ],
        },
        TRUST_ETAG,
    )
    trust.assignments = TrustHttpProjection(
        "MY_ACTIVE_CASE_ASSIGNMENTS",
        {
            "entity_tag": TRUST_ETAG,
            "items": [
                {
                    "assignment_expires_at": "2026-08-25T09:00:00+00:00",
                    "assignment_purpose": "CASE_TRIAGE",
                    "case_id": TRUST_CASE,
                    "hold_id": None,
                },
                {
                    "assignment_expires_at": "2026-08-25T09:30:00+00:00",
                    "assignment_purpose": "HOLD_RELEASE",
                    "case_id": TRUST_CASE,
                    "hold_id": TRUST_HOLD,
                },
            ],
        },
        TRUST_ETAG,
    )
    appeals = _Appeals()
    appeals.queue = AppealQueueProjection(
        items=(
            AppealQueueItem(
                appeal_id=APPEAL,
                source_outcome_version_id=OUTCOME,
                source_case_id=TRUST_CASE,
                grounds=("PROCEDURAL_ERROR",),
                requested_outcome="MODIFY_MEASURE",
                submitted_at=NOW,
                entity_tag=APPEAL_ETAG,
            ),
        ),
        entity_tag=APPEAL_ETAG,
    )
    appeals.assignments = AppealActiveAssignmentsProjection(
        items=(
            AppealActiveAssignmentItem(
                appeal_id=APPEAL,
                assignment_expires_at=NOW + timedelta(hours=1),
            ),
        ),
        entity_tag=APPEAL_ETAG,
    )

    result = _service(
        editor=editor,
        finance=finance,
        trust=trust,
        appeals=appeals,
    ).list_tasks(principal=principal)

    by_kind = {item.resource_kind: item for item in result.items}
    assert len(result.items) == 6
    assert by_kind["DEMAND_REVIEW"].next_action == "REVIEW_ASSIGNED_DEMAND"
    assert by_kind["TRUST_CASE"].next_action == "REVIEW_ASSIGNED_TRUST_CASE"
    assert (
        by_kind["TRUST_HOLD_RELEASE"].next_action
        == "REVIEW_ASSIGNED_TRUST_HOLD_RELEASE"
    )
    assert by_kind["APPEAL_REVIEW"].next_action == "REVIEW_ASSIGNED_APPEAL"
    finance_items = [
        item
        for item in result.items
        if item.resource_kind == "FINANCE_FUNDING_REVIEW"
    ]
    assert {item.next_action for item in finance_items} == {
        "CLAIM_FINANCE_REVIEW",
        "CONTINUE_FINANCE_REVIEW",
    }
    assert all(item.classification == "NEEDS_ACTION" for item in result.items)
    assert all(call[1] is principal for call in editor.calls + finance.calls)


def test_finance_available_to_pending_changes_resource_coordinate_by_contract() -> None:
    finance = _Finance()
    service = _service(finance=finance)
    principal = _platform("FINANCE_OPERATOR")

    finance.queue = (_finance_queue_item(status="AVAILABLE"),)
    available = service.list_tasks(principal=principal).items[0]
    finance.queue = (_finance_queue_item(status="PENDING"),)
    pending = service.list_tasks(principal=principal).items[0]

    assert (
        available.resource_kind,
        available.resource_id,
        available.source_status,
    ) == ("FINANCE_FUNDING_REVIEW", DEMAND_B, "AVAILABLE")
    assert (
        pending.resource_kind,
        pending.resource_id,
        pending.source_status,
    ) == ("FINANCE_FUNDING_REVIEW", FINANCE_REVIEW, "PENDING")
    assert available.resource_id != pending.resource_id


def test_appeal_reviewer_completed_history_is_discoverable_and_truncation_is_explicit() -> None:
    appeals = _Appeals()
    appeals.completed = AppealCompletedAssignmentsProjection(
        items=(
            AppealCompletedAssignmentItem(
                appeal_id=APPEAL,
                decided_at=NOW,
                decision_code="MODIFY",
            ),
        ),
        has_more=True,
        entity_tag=APPEAL_ETAG,
    )

    result = _service(appeals=appeals).list_tasks(
        principal=_platform("APPEAL_REVIEWER")
    )

    assert result.has_more is True
    assert len(result.items) == 1
    task = result.items[0]
    assert (
        task.classification,
        task.resource_kind,
        task.resource_id,
        task.source_status,
        task.next_action,
        task.resource_path,
        task.updated_at,
        task.due_at,
    ) == (
        "COMPLETED",
        "APPEAL_REVIEW",
        APPEAL,
        "MODIFY",
        "VIEW_APPEAL_REVIEW_HISTORY",
        "/v1/app/appeal-review/history",
        NOW,
        None,
    )


def test_appeal_reviewer_completed_history_overrides_transient_queue_and_assignment() -> None:
    appeals = _Appeals()
    appeals.queue = AppealQueueProjection(
        items=(
            AppealQueueItem(
                appeal_id=APPEAL,
                source_outcome_version_id=OUTCOME,
                source_case_id=TRUST_CASE,
                grounds=("PROCEDURAL_ERROR",),
                requested_outcome="MODIFY_MEASURE",
                submitted_at=NOW - timedelta(minutes=2),
                entity_tag=APPEAL_ETAG,
            ),
        ),
        entity_tag=APPEAL_ETAG,
    )
    appeals.assignments = AppealActiveAssignmentsProjection(
        items=(
            AppealActiveAssignmentItem(
                appeal_id=APPEAL,
                assignment_expires_at=NOW + timedelta(hours=1),
            ),
        ),
        entity_tag=APPEAL_ETAG,
    )
    appeals.completed = AppealCompletedAssignmentsProjection(
        items=(
            AppealCompletedAssignmentItem(
                appeal_id=APPEAL,
                decided_at=NOW,
                decision_code="MODIFY",
            ),
        ),
        has_more=False,
        entity_tag=APPEAL_ETAG,
    )

    result = _service(appeals=appeals).list_tasks(
        principal=_platform("APPEAL_REVIEWER")
    )

    assert len(result.items) == 1
    task = result.items[0]
    assert (
        task.classification,
        task.resource_kind,
        task.resource_id,
        task.source_status,
        task.next_action,
        task.resource_path,
    ) == (
        "COMPLETED",
        "APPEAL_REVIEW",
        APPEAL,
        "MODIFY",
        "VIEW_APPEAL_REVIEW_HISTORY",
        "/v1/app/appeal-review/history",
    )


def test_sorting_is_classification_then_latest_activity_then_stable_key() -> None:
    editor = _Editor()
    editor.demands_by_scope[("ORGANIZATION", ORGANIZATION_A)] = (
        _resource(
            resource_type="DEMAND",
            resource_id=DEMAND_C,
            status="MATCHED",
            updated_at=NOW + timedelta(days=3),
        ),
        _resource(
            resource_type="DEMAND",
            resource_id=DEMAND_A,
            status="DRAFT",
            updated_at=NOW,
        ),
        _resource(
            resource_type="DEMAND",
            resource_id=DEMAND_B,
            status="NEEDS_CHANGES",
            updated_at=NOW + timedelta(days=1),
        ),
        _resource(
            resource_type="DEMAND",
            resource_id=_id(35),
            status="SUBMITTED",
            updated_at=NOW + timedelta(days=2),
        ),
    )

    result = _service(
        editor=editor,
        trust=_Trust(),
        appeals=_Appeals(),
    ).list_tasks(principal=_owner())

    assert [item.resource_id for item in result.items] == [
        DEMAND_B,
        DEMAND_A,
        _id(35),
        DEMAND_C,
    ]
    assert [item.classification for item in result.items] == [
        "NEEDS_ACTION",
        "NEEDS_ACTION",
        "WAITING",
        "COMPLETED",
    ]


def test_route_serializes_closed_dto_and_rejects_caller_filters() -> None:
    principal = _personal()
    editor = _Editor()
    editor.profiles_by_user[USER_A] = (
        _resource(
            resource_type="CREATOR_PROFILE",
            resource_id=PROFILE_A,
            status="DRAFT",
        ),
    )
    task_service = _service(editor=editor)
    api = EditorHttpApi(service=object(), task_service=task_service)

    response = api.handle(
        request=HttpRequest(
            method="GET",
            path="/v1/app/tasks",
            headers={},
            json={},
        ),
        principal=principal,
    )

    assert response.status == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert response.json["data"]["schema_version"] == (
        "current-account-task-discovery-v1"
    )
    assert response.json["data"]["has_more"] is False
    assert set(response.json["data"]["items"][0]) == {
        "classification",
        "resource_kind",
        "resource_id",
        "source_status",
        "next_action",
        "resource_path",
        "updated_at",
        "due_at",
    }

    rejected = api.handle(
        request=HttpRequest(
            method="GET",
            path="/v1/app/tasks",
            headers={},
            json={"organization_id": ORGANIZATION_B},
        ),
        principal=principal,
    )
    assert rejected.status == 422
    assert rejected.json["error"] == {
        "code": "UNKNOWN_FIELD",
        "path": "/organization_id",
    }


def test_source_failure_is_503_and_never_returns_partial_tasks() -> None:
    class _UnavailableEditor:
        @staticmethod
        def list_profiles(*, principal):
            del principal
            raise EditorServiceError(status=404, code="RESOURCE_NOT_FOUND")

    service = _service(editor=_UnavailableEditor())

    with pytest.raises(EditorServiceError) as captured:
        service.list_tasks(principal=_personal())

    assert (captured.value.status, captured.value.code) == (
        503,
        "SERVICE_UNAVAILABLE",
    )


def test_route_without_discovery_dependency_is_fail_closed() -> None:
    response = EditorHttpApi(service=object()).handle(
        request=HttpRequest(
            method="GET",
            path="/v1/app/tasks",
            headers={},
            json={},
        ),
        principal=_personal(),
    )

    assert response.status == 503
    assert response.json == {"error": {"code": "SERVICE_UNAVAILABLE"}}
