from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest

from desire_platform.trust_safety.application import (
    AppealCommandResult,
    ClaimAppealCommand,
    ClaimAppealHandler,
    DecideAppealCommand,
    DecideAppealHandler,
    OpenAppealCommand,
    OpenAppealHandler,
    ReleaseAppealAssignmentCommand,
    ReleaseAppealAssignmentHandler,
    SaveAppealDraftCommand,
    SaveAppealDraftHandler,
    SaveAppealReviewDraftCommand,
    SaveAppealReviewDraftHandler,
    SubmitAppealCommand,
    SubmitAppealHandler,
    TrustActorContext,
)
from desire_platform.trust_safety.domain import AppealStatus
from desire_platform.trust_safety.appeal_http import (
    AppealHttpApplicationDispatcher,
    AppealHttpPresenterBindings,
    AppealHttpRequest,
)
from desire_platform.trust_safety.ports import (
    AppealActiveAssignmentItem,
    AppealActiveAssignmentsProjection,
    AppealApplicationDraftProjection,
    AppealAssignedProjection,
    AppealAssessmentProjection,
    AppealCompletedAssignmentItem,
    AppealCompletedAssignmentsProjection,
    AppealCompletedDetailProjection,
    AppealDecisionProjection,
    AppealOwnProjection,
    AppealQueueItem,
    AppealQueueProjection,
    AppealReviewDraftProjection,
    AppealSourceProjection,
    AppealSubmittedApplicationProjection,
)


NOW = datetime(2026, 8, 19, 8, 0, tzinfo=timezone.utc)


def _id(number: int) -> str:
    return str(UUID(int=number))


USER_ID = _id(1)
SESSION_ID = _id(2)
ORG_ID = _id(3)
APPEAL_ID = _id(4)
OUTCOME_ID = _id(5)
CASE_ID = _id(6)
DEMAND_ID = _id(7)
DEMAND_VERSION_ID = _id(8)
EVIDENCE_ID = _id(9)
ETAG = '"appeal-6-0123456789abcdef01234567"'
IDEMPOTENCY_KEY = "appeal-http-idempotency-0001"
RAW_STATEMENT = "private applicant statement must not reflect"
RAW_REVIEW = "private reviewer note must not reflect"


def _actor(*, applicant: bool) -> TrustActorContext:
    return TrustActorContext(
        actor_user_id=USER_ID,
        session_id=SESSION_ID,
        organization_id=ORG_ID if applicant else None,
        correlation_id=_id(10),
        causation_id=_id(11),
        trace_id=_id(12),
        original_actor_user_id=None,
    )


def _result() -> AppealCommandResult:
    return AppealCommandResult(
        appeal_id=APPEAL_ID,
        appeal_status=AppealStatus.IN_REVIEW,
        aggregate_version=6,
        application_draft_version=1,
        application_version=1,
        review_draft_version=1,
        decision_version_id=None,
        replayed=False,
        event_types=("AppealReviewDraftSaved",),
        completed_at=NOW,
    )


def _fake_handler(handler_type):
    class Fake(handler_type):
        def __init__(self):
            self.calls = []
            self.error_code = None

        def handle(self, *, actor, command):
            self.calls.append((actor, command))
            if self.error_code is not None:
                from desire_platform.trust_safety.application import (
                    AppealApplicationError,
                )

                raise AppealApplicationError(self.error_code)
            return _result()

    return Fake()


def _source() -> AppealSourceProjection:
    return AppealSourceProjection(
        outcome_version_id=OUTCOME_ID,
        case_id=CASE_ID,
        demand_id=DEMAND_ID,
        demand_version_id=DEMAND_VERSION_ID,
        outcome_code="PROTECTION_MODIFIED",
        reason_codes=("POLICY_REQUIREMENT_NOT_MET",),
        action_codes=("VERIFY_DEMAND",),
        evidence_packet_version_id=EVIDENCE_ID,
        evidence_packet_sha256="11" * 32,
        policy_version="trust-case-outcome-v1",
        decided_at=NOW - timedelta(days=1),
        appeal_eligible=True,
        appeal_eligibility_code="ELIGIBLE",
        appeal_deadline=NOW + timedelta(days=7),
        content_sha256="22" * 32,
    )


def _application() -> AppealSubmittedApplicationProjection:
    return AppealSubmittedApplicationProjection(
        grounds=("PROCEDURAL_ERROR",),
        requested_outcome="MODIFY_MEASURE",
        statement_recorded=True,
        new_evidence_reference_ids=(),
        submitted_at=NOW,
    )


def _own(*, status="IN_REVIEW") -> AppealOwnProjection:
    application = _application() if status != "DRAFT" else None
    return AppealOwnProjection(
        appeal_id=APPEAL_ID,
        source_outcome_version_id=OUTCOME_ID,
        source_case_id=CASE_ID,
        source=_source(),
        status=status,
        aggregate_version=6,
        application_draft=AppealApplicationDraftProjection(
            version=1,
            grounds=("PROCEDURAL_ERROR",),
            requested_outcome="MODIFY_MEASURE",
            statement_recorded=True,
            new_evidence_reference_ids=(),
            edited_at=NOW,
        ),
        application=application,
        decision=None,
        entity_tag=ETAG,
    )


class Projections:
    def __init__(self):
        self.calls = []

    def find_own_appeal_by_source(self, *, actor, source_outcome_version_id):
        self.calls.append(("READ_OWN_APPEAL", source_outcome_version_id))
        return _own()

    def read_own_appeal(self, *, actor, appeal_id):
        self.calls.append(("READ_OWN_APPEAL", appeal_id))
        return _own()

    def list_appeal_queue(self, *, actor, limit):
        self.calls.append(("LIST_APPEAL_QUEUE", limit))
        return AppealQueueProjection(
            items=(
                AppealQueueItem(
                    appeal_id=APPEAL_ID,
                    source_outcome_version_id=OUTCOME_ID,
                    source_case_id=CASE_ID,
                    grounds=("PROCEDURAL_ERROR",),
                    requested_outcome="MODIFY_MEASURE",
                    submitted_at=NOW,
                    entity_tag=ETAG,
                ),
            ),
            entity_tag=ETAG,
        )

    def list_my_active_appeal_assignments(self, *, actor, limit):
        self.calls.append(("LIST_MY_ACTIVE_APPEAL_ASSIGNMENTS", limit))
        return AppealActiveAssignmentsProjection(
            items=(
                AppealActiveAssignmentItem(
                    appeal_id=APPEAL_ID,
                    assignment_expires_at=NOW + timedelta(hours=1),
                ),
            ),
            entity_tag=ETAG,
        )

    def read_assigned_appeal(self, *, actor, appeal_id):
        self.calls.append(("READ_ASSIGNED_APPEAL", appeal_id))
        own = _own()
        return AppealAssignedProjection(
            appeal=own,
            source=own.source,
            application=_application(),
            review_draft=AppealReviewDraftProjection(
                version=1,
                assessments=(
                    AppealAssessmentProjection(
                        ground="PROCEDURAL_ERROR",
                        assessment_code="ACCEPTED",
                        finding_codes=("PROCEDURE_MATERIAL_ERROR",),
                        accepted_evidence_reference_ids=(),
                    ),
                ),
                reason_codes=("PROCEDURAL_REVIEW_COMPLETE",),
                remedy_delta_codes=("NARROW_CORRECTIVE_MEASURE",),
                review_note_recorded=True,
                edited_at=NOW,
            ),
            assignment_expires_at=NOW + timedelta(hours=1),
            entity_tag=ETAG,
        )

    def list_my_completed_appeal_assignments(self, *, actor, limit):
        self.calls.append(("LIST_MY_COMPLETED_APPEAL_ASSIGNMENTS", limit))
        return AppealCompletedAssignmentsProjection(
            items=(
                AppealCompletedAssignmentItem(
                    appeal_id=_id(14),
                    decided_at=NOW + timedelta(hours=1),
                    decision_code="AFFIRM",
                ),
                AppealCompletedAssignmentItem(
                    appeal_id=APPEAL_ID,
                    decided_at=NOW,
                    decision_code="MODIFY",
                ),
            ),
            has_more=True,
            entity_tag=ETAG,
        )

    def read_my_completed_appeal(self, *, actor, appeal_id):
        self.calls.append(("READ_MY_COMPLETED_APPEAL", appeal_id))
        return AppealCompletedDetailProjection(
            appeal_id=appeal_id,
            status="DECIDED",
            application=_application(),
            decision=AppealDecisionProjection(
                decision_version_id=_id(15),
                decision_code="MODIFY",
                assessments=(
                    AppealAssessmentProjection(
                        ground="PROCEDURAL_ERROR",
                        assessment_code="ACCEPTED",
                        finding_codes=("PROCEDURE_MATERIAL_ERROR",),
                        accepted_evidence_reference_ids=(),
                    ),
                ),
                reason_codes=("PROCEDURAL_REVIEW_COMPLETE",),
                remedy_delta_codes=("NARROW_CORRECTIVE_MEASURE",),
                policy_version="appeal-decision-v1",
                decided_at=NOW + timedelta(hours=1),
                decision_sha256="33" * 32,
            ),
            review_note_recorded=True,
            entity_tag=ETAG,
        )


def _dispatcher():
    handlers = {
        "open_appeal": _fake_handler(OpenAppealHandler),
        "save_application_draft": _fake_handler(SaveAppealDraftHandler),
        "submit_appeal": _fake_handler(SubmitAppealHandler),
        "claim_appeal": _fake_handler(ClaimAppealHandler),
        "release_assignment": _fake_handler(ReleaseAppealAssignmentHandler),
        "save_review_draft": _fake_handler(SaveAppealReviewDraftHandler),
        "decide_appeal": _fake_handler(DecideAppealHandler),
    }
    projections = Projections()
    bindings = AppealHttpPresenterBindings(
        projections=projections,
        **handlers,
    )
    return AppealHttpApplicationDispatcher(bindings=bindings), handlers, projections


def _request(method, path, body, *, query=None, if_match=True):
    headers = {"idempotency-key": IDEMPOTENCY_KEY}
    if if_match:
        headers["if-match"] = ETAG
    return AppealHttpRequest(
        method=method,
        path=path,
        headers=headers,
        query={} if query is None else query,
        json=body,
    )


WRITE_CASES = (
    ("open_appeal", "POST", "/v1/app/appeals", {"source_outcome_version_id": OUTCOME_ID}, OpenAppealCommand, 201, False),
    ("save_application_draft", "PUT", f"/v1/app/appeals/{APPEAL_ID}/draft", {"applicant_statement": RAW_STATEMENT, "grounds": ["PROCEDURAL_ERROR"], "new_evidence_reference_ids": [], "requested_outcome": "MODIFY_MEASURE"}, SaveAppealDraftCommand, 200, True),
    ("submit_appeal", "POST", f"/v1/app/appeals/{APPEAL_ID}/submit", {"expected_draft_version": 1}, SubmitAppealCommand, 200, True),
    ("claim_appeal", "POST", f"/v1/app/appeal-review/queue/{APPEAL_ID}/claim", {}, ClaimAppealCommand, 201, True),
    ("release_assignment", "POST", f"/v1/app/appeal-review/appeals/{APPEAL_ID}/assignment/release", {"reason_code": "WORKLOAD_RELEASE"}, ReleaseAppealAssignmentCommand, 200, True),
    ("save_review_draft", "PUT", f"/v1/app/appeal-review/appeals/{APPEAL_ID}/review-draft", {"assessments": [{"accepted_evidence_reference_ids": [], "assessment_code": "ACCEPTED", "finding_codes": ["PROCEDURE_MATERIAL_ERROR"], "ground": "PROCEDURAL_ERROR"}], "reason_codes": ["PROCEDURAL_REVIEW_COMPLETE"], "remedy_delta_codes": ["NARROW_CORRECTIVE_MEASURE"], "reviewer_note": RAW_REVIEW}, SaveAppealReviewDraftCommand, 200, True),
    ("decide_appeal", "POST", f"/v1/app/appeal-review/appeals/{APPEAL_ID}/decide", {"decision_code": "MODIFY", "expected_review_draft_version": 1}, DecideAppealCommand, 200, True),
)


@pytest.mark.parametrize(
    "handler_name,method,path,body,command_type,status,if_match", WRITE_CASES
)
def test_seven_write_routes_parse_closed_commands_and_return_receipt_safe_result(
    handler_name, method, path, body, command_type, status, if_match
):
    dispatcher, handlers, _ = _dispatcher()
    response = dispatcher.handle(
        request=_request(method, path, body, if_match=if_match),
        actor=_actor(applicant=path.startswith("/v1/app/appeals")),
    )
    assert response.status == status
    assert response.headers == {"content-type": "application/json"}
    assert set(response.json["data"]) == {
        "aggregate_version",
        "appeal_id",
        "appeal_status",
        "application_draft_version",
        "application_version",
        "completed_at",
        "decision_version_id",
        "event_types",
        "replayed",
        "review_draft_version",
    }
    rendered = repr(response)
    for forbidden in (RAW_STATEMENT, RAW_REVIEW, "assignment_id", "duty_grant"):
        assert forbidden not in rendered
    command = handlers[handler_name].calls[0][1]
    assert isinstance(command, command_type)
    if if_match:
        assert command.expected_appeal_version == 6


@pytest.mark.parametrize(
    "path,query,applicant,expected_call",
    (
        ("/v1/app/appeals", {"source_outcome_version_id": (OUTCOME_ID,)}, True, ("READ_OWN_APPEAL", OUTCOME_ID)),
        (f"/v1/app/appeals/{APPEAL_ID}", {}, True, ("READ_OWN_APPEAL", APPEAL_ID)),
        ("/v1/app/appeal-review/queue", {}, False, ("LIST_APPEAL_QUEUE", 100)),
        ("/v1/app/appeal-review/assignments", {}, False, ("LIST_MY_ACTIVE_APPEAL_ASSIGNMENTS", 100)),
        (f"/v1/app/appeal-review/appeals/{APPEAL_ID}", {}, False, ("READ_ASSIGNED_APPEAL", APPEAL_ID)),
        ("/v1/app/appeal-review/history", {}, False, ("LIST_MY_COMPLETED_APPEAL_ASSIGNMENTS", 100)),
        (f"/v1/app/appeal-review/history/{APPEAL_ID}", {}, False, ("READ_MY_COMPLETED_APPEAL", APPEAL_ID)),
    ),
)
def test_seven_reads_return_only_closed_safe_projections(path, query, applicant, expected_call):
    dispatcher, handlers, projections = _dispatcher()
    response = dispatcher.handle(
        request=AppealHttpRequest(
            method="GET", path=path, headers={}, query=query, json={}
        ),
        actor=_actor(applicant=applicant),
    )
    assert response.status == 200
    assert response.headers["etag"] == ETAG
    serialized = repr(response.json)
    for forbidden in (
        "sealed_",
        "applicant_user_id",
        "reviewer_user_id",
        "duty_grant_id",
        "organization_id",
    ):
        assert forbidden not in serialized
    assert projections.calls == [expected_call]
    assert all(not handler.calls for handler in handlers.values())


def test_completed_history_and_detail_have_exact_terminal_shapes() -> None:
    dispatcher, _, _ = _dispatcher()
    history = dispatcher.handle(
        request=AppealHttpRequest(
            method="GET",
            path="/v1/app/appeal-review/history",
            headers={},
            query={},
            json={},
        ),
        actor=_actor(applicant=False),
    )
    detail = dispatcher.handle(
        request=AppealHttpRequest(
            method="GET",
            path=f"/v1/app/appeal-review/history/{APPEAL_ID}",
            headers={},
            query={},
            json={},
        ),
        actor=_actor(applicant=False),
    )

    assert history.json == {
        "data": {
            "entity_tag": ETAG,
            "has_more": True,
            "items": [
                {
                    "appeal_id": _id(14),
                    "decided_at": "2026-08-19T09:00:00Z",
                    "decision_code": "AFFIRM",
                },
                {
                    "appeal_id": APPEAL_ID,
                    "decided_at": "2026-08-19T08:00:00Z",
                    "decision_code": "MODIFY",
                },
            ],
        }
    }
    data = detail.json["data"]
    assert set(data) == {
        "appeal_id",
        "application",
        "decision",
        "entity_tag",
        "review_note_recorded",
        "status",
    }
    assert data["status"] == "DECIDED"
    assert data["review_note_recorded"] is True
    assert set(data["application"]) == {
        "grounds",
        "new_evidence_reference_ids",
        "requested_outcome",
        "statement_recorded",
        "submitted_at",
    }
    assert set(data["decision"]) == {
        "assessments",
        "decided_at",
        "decision_code",
        "decision_sha256",
        "decision_version_id",
        "policy_version",
        "reason_codes",
        "remedy_delta_codes",
    }


def test_completed_history_rejects_query_body_and_same_timestamp_reverse_order() -> None:
    dispatcher, _, projections = _dispatcher()
    bad_query = AppealHttpRequest(
        method="GET",
        path="/v1/app/appeal-review/history",
        headers={},
        query={"limit": ("1",)},
        json={},
    )
    bad_body = AppealHttpRequest(
        method="GET",
        path="/v1/app/appeal-review/history",
        headers={},
        query={},
        json={"appeal_id": APPEAL_ID},
    )
    for request in (bad_query, bad_body):
        response = dispatcher.handle(
            request=request,
            actor=_actor(applicant=False),
        )
        assert (response.status, response.json) == (
            400,
            {"error": {"code": "INVALID_REQUEST", "path": "/query" if request is bad_query else "/body"}},
        )
    assert projections.calls == []

    with pytest.raises(ValueError, match="APPEAL_READ_PROJECTION_INVALID"):
        AppealCompletedAssignmentsProjection(
            items=(
                AppealCompletedAssignmentItem(
                    appeal_id=APPEAL_ID,
                    decided_at=NOW,
                    decision_code="AFFIRM",
                ),
                AppealCompletedAssignmentItem(
                    appeal_id=_id(14),
                    decided_at=NOW,
                    decision_code="MODIFY",
                ),
            ),
            has_more=False,
            entity_tag=ETAG,
        )
    with pytest.raises(ValueError, match="APPEAL_READ_PROJECTION_INVALID"):
        AppealCompletedAssignmentsProjection(
            items=(),
            has_more=True,
            entity_tag=ETAG,
        )


def test_invalid_query_body_idempotency_and_if_match_are_non_reflective_and_zero_call():
    dispatcher, handlers, _ = _dispatcher()
    requests = (
        AppealHttpRequest(method="GET", path="/v1/app/appeals", headers={}, query={}, json={}),
        _request("POST", f"/v1/app/appeal-review/queue/{APPEAL_ID}/claim", {}, if_match=False),
        AppealHttpRequest(method="POST", path="/v1/app/appeals", headers={"idempotency-key": "short"}, query={}, json={"source_outcome_version_id": OUTCOME_ID}),
        _request("PUT", f"/v1/app/appeals/{APPEAL_ID}/draft", {"applicant_statement": RAW_STATEMENT, "grounds": ["PROCEDURAL_ERROR"], "new_evidence_reference_ids": [], "requested_outcome": "MODIFY_MEASURE", "sealed_statement_reference": "sealed://forbidden"}),
    )
    expected = (
        (400, "INVALID_REQUEST"),
        (428, "PRECONDITION_REQUIRED"),
        (400, "INVALID_IDEMPOTENCY_KEY"),
        (400, "INVALID_REQUEST"),
    )
    for request, wanted in zip(requests, expected):
        response = dispatcher.handle(request=request, actor=_actor(applicant=True))
        assert (response.status, response.json["error"]["code"]) == wanted
        assert RAW_STATEMENT not in repr(response)
    assert all(not handler.calls for handler in handlers.values())


def test_bindings_require_all_exact_handlers_and_seven_projection_methods():
    _, handlers, _ = _dispatcher()
    with pytest.raises(TypeError, match="Appeal HTTP"):
        AppealHttpPresenterBindings(projections=object(), **handlers)


@pytest.mark.parametrize(
    "application_code,status,public_code",
    (
        ("AUTHENTICATION_REQUIRED", 401, "AUTHENTICATION_REQUIRED"),
        ("ACCESS_DENIED", 404, "RESOURCE_NOT_FOUND"),
        ("PRECONDITION_FAILED", 412, "STALE_VERSION"),
        ("IDEMPOTENCY_KEY_REUSED", 409, "IDEMPOTENCY_KEY_REUSED"),
        ("APPEAL_ASSIGNMENT_REQUIRED", 409, "ASSIGNMENT_UNAVAILABLE"),
        ("APPEAL_DEADLINE_PASSED", 409, "APPEAL_STATE_CONFLICT"),
        ("APPEAL_APPLICATION_INVALID", 422, "APPEAL_VALIDATION_FAILED"),
        ("COMMAND_OUTCOME_UNKNOWN", 503, "COMMAND_OUTCOME_UNKNOWN"),
        ("private database diagnostic", 503, "SERVICE_UNAVAILABLE"),
    ),
)
def test_application_errors_map_to_one_non_reflective_public_envelope(
    application_code, status, public_code
):
    dispatcher, handlers, _ = _dispatcher()
    handlers["claim_appeal"].error_code = application_code
    response = dispatcher.handle(
        request=_request(
            "POST",
            f"/v1/app/appeal-review/queue/{APPEAL_ID}/claim",
            {},
        ),
        actor=_actor(applicant=False),
    )
    assert response.status == status
    assert response.json == {"error": {"code": public_code}}
    assert application_code not in repr(response)
