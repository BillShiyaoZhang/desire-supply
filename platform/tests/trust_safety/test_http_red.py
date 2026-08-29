from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any

import pytest

from desire_platform.trust_safety.application import (
    ClaimSafetyCaseCommand,
    ClaimSafetyCaseHandler,
    ClaimSafetyHoldReleaseCommand,
    ClaimSafetyHoldReleaseHandler,
    PlaceSafetyHoldCommand,
    PlaceSafetyHoldHandler,
    PublishTrustOutcomeCommand,
    PublishTrustOutcomeHandler,
    PublishTrustTriageCommand,
    PublishTrustTriageHandler,
    ReleaseSafetyCaseAssignmentCommand,
    ReleaseSafetyCaseAssignmentHandler,
    ReleaseSafetyHoldCommand,
    ReleaseSafetyHoldHandler,
    SaveTrustTriageDraftCommand,
    SaveTrustTriageDraftHandler,
    SubmitSafetyReportCommand,
    SubmitSafetyReportHandler,
    TrustActorContext,
    TrustApplicationError,
    TrustCommandResult,
)
from desire_platform.trust_safety.domain import SafetyCaseStatus
from desire_platform.trust_safety.http import (
    TrustHttpApplicationDispatcher,
    TrustHttpPresenterBindings,
    TrustHttpProjection,
    TrustHttpRequest,
)


USER_ID = "10000000-0000-4000-8000-000000000001"
SESSION_ID = "20000000-0000-4000-8000-000000000001"
ORG_ID = "30000000-0000-4000-8000-000000000001"
CASE_ID = "40000000-0000-4000-8000-000000000001"
SECOND_CASE_ID = "40000000-0000-4000-8000-000000000002"
REPORT_ID = "50000000-0000-4000-8000-000000000001"
HOLD_ID = "60000000-0000-4000-8000-000000000001"
DEMAND_ID = "70000000-0000-4000-8000-000000000001"
DEMAND_VERSION_ID = "80000000-0000-4000-8000-000000000001"
TRACE_ID = "90000000-0000-4000-8000-000000000001"
ETAG = '"trust-7-0123456789abcdef01234567"'
IDEMPOTENCY_KEY = "trust-http-idempotency-0001"
NOW = datetime(2026, 8, 18, 8, 0, tzinfo=timezone.utc)


def _actor(*, reporter: bool) -> TrustActorContext:
    return TrustActorContext(
        actor_user_id=USER_ID,
        session_id=SESSION_ID,
        organization_id=ORG_ID if reporter else None,
        correlation_id=TRACE_ID,
        causation_id=TRACE_ID,
        trace_id=TRACE_ID,
        original_actor_user_id=None,
    )


def _report_projection() -> dict[str, Any]:
    return {
        "demand_id": DEMAND_ID,
        "demand_version_id": DEMAND_VERSION_ID,
        "entity_tag": ETAG,
        "outcome": None,
        "report_id": REPORT_ID,
        "status": "OPEN",
        "submitted_at": "2026-08-18T08:00:00Z",
        "report": {
            "category": "WORKFLOW_INTEGRITY",
            "evidence_reference_ids": [REPORT_ID],
            "impact_codes": ["WORKFLOW_INTEGRITY_RISK"],
            "incident_ended_at": None,
            "incident_started_at": "2026-08-18T07:00:00Z",
            "requested_protection_codes": ["PAUSE_SUBMISSION"],
        },
    }


def _owned_report_list_projection() -> dict[str, Any]:
    return {
        "entity_tag": ETAG,
        "items": [
            {
                "category": "WORKFLOW_INTEGRITY",
                "demand_id": DEMAND_ID,
                "outcome": None,
                "report_id": REPORT_ID,
                "status": "OPEN",
                "submitted_at": "2026-08-18T08:00:00Z",
            }
        ],
        "next_cursor": None,
    }


def _queue_projection() -> dict[str, Any]:
    return {
        "entity_tag": ETAG,
        "items": [
            {
                "category": "WORKFLOW_INTEGRITY",
                "case_id": CASE_ID,
                "demand_id": DEMAND_ID,
                "demand_version_id": DEMAND_VERSION_ID,
                "entity_tag": ETAG,
                "impact_codes": ["WORKFLOW_INTEGRITY_RISK"],
                "report_id": REPORT_ID,
                "submitted_at": "2026-08-18T08:00:00Z",
            }
        ],
    }


def _hold_queue_projection() -> dict[str, Any]:
    return {
        "entity_tag": ETAG,
        "items": [
            {
                "action_codes": ["SUBMIT_DEMAND"],
                "case_id": CASE_ID,
                "demand_id": DEMAND_ID,
                "demand_version_id": DEMAND_VERSION_ID,
                "entity_tag": ETAG,
                "expires_at": "2026-08-18T09:00:00Z",
                "hold_id": HOLD_ID,
                "reason_code": "PARTICIPANT_SAFETY_RISK",
            }
        ],
    }


def _case_projection() -> dict[str, Any]:
    return {
        "active_hold": None,
        "aggregate_version": 7,
        "case_id": CASE_ID,
        "demand_id": DEMAND_ID,
        "demand_version_id": DEMAND_VERSION_ID,
        "entity_tag": ETAG,
        "outcome": None,
        "report": _report_projection()["report"],
        "report_id": REPORT_ID,
        "status": "TRIAGING",
        "triage_draft": {
            "content": {
                "investigation_step_codes": ["CHECK_DEMAND_VERSION"],
                "issue_codes": ["WORKFLOW_INTEGRITY_GAP"],
                "jurisdiction_code": "PLATFORM_INTERNAL",
                "priority_code": "P1",
                "proposed_hold_actions": ["SUBMIT_DEMAND"],
                "proposed_hold_ttl_minutes": 60,
                "sealed_note_reference": "sealed://trust/note_00001",
                "sealed_note_sha256": "a" * 64,
                "severity_code": "HIGH",
            },
            "content_sha256": "b" * 64,
            "saved_at": "2026-08-18T08:00:00Z",
            "triage_version": 3,
        },
    }


def _assigned_hold_release_projection() -> dict[str, Any]:
    return {
        "action_codes": ["SUBMIT_DEMAND"],
        "assignment_expires_at": "2026-08-18T08:30:00Z",
        "case_id": CASE_ID,
        "case_status": "IN_REVIEW",
        "effective_at": "2026-08-18T08:00:00Z",
        "entity_tag": ETAG,
        "expires_at": "2026-08-18T09:00:00Z",
        "hold_id": HOLD_ID,
        "hold_status": "ACTIVE",
        "reason_code": "PARTICIPANT_SAFETY_RISK",
    }


class _FakeHandlerMixin:
    def __init__(self) -> None:
        self.calls: list[tuple[TrustActorContext, Any]] = []
        self.error_code: str | None = None

    def handle(self, *, actor: TrustActorContext, command: Any) -> TrustCommandResult:
        self.calls.append((actor, command))
        if self.error_code is not None:
            raise TrustApplicationError(self.error_code)
        event_type = {
            "submit_report": "TrustReportSubmitted",
            "claim_case": "TrustCaseClaimed",
            "release_assignment": "TrustCaseAssignmentReleased",
            "save_triage": "TrustTriageDraftSaved",
            "publish_triage": "TrustTriagePublished",
            "place_hold": "SafetyHoldPlaced",
            "claim_hold_release": "TrustHoldReleaseClaimed",
            "release_hold": "SafetyHoldReleased",
            "publish_outcome": "TrustCaseOutcomePublished",
        }[self.operation]
        return TrustCommandResult(
            case_id=CASE_ID,
            case_status=SafetyCaseStatus.TRIAGING,
            aggregate_version=8,
            report_id=REPORT_ID,
            assignment_id=None,
            triage_draft_version=3,
            triage_version=None,
            hold_id=HOLD_ID,
            hold_version=1,
            outcome_version_id=None,
            replayed=False,
            event_types=(event_type,),
            completed_at=NOW,
        )


class FakeSubmit(_FakeHandlerMixin, SubmitSafetyReportHandler):
    pass


class FakeClaimCase(_FakeHandlerMixin, ClaimSafetyCaseHandler):
    pass


class FakeReleaseAssignment(_FakeHandlerMixin, ReleaseSafetyCaseAssignmentHandler):
    pass


class FakeSaveTriage(_FakeHandlerMixin, SaveTrustTriageDraftHandler):
    pass


class FakePublishTriage(_FakeHandlerMixin, PublishTrustTriageHandler):
    pass


class FakePlaceHold(_FakeHandlerMixin, PlaceSafetyHoldHandler):
    pass


class FakeClaimHold(_FakeHandlerMixin, ClaimSafetyHoldReleaseHandler):
    pass


class FakeReleaseHold(_FakeHandlerMixin, ReleaseSafetyHoldHandler):
    pass


class FakePublishOutcome(_FakeHandlerMixin, PublishTrustOutcomeHandler):
    pass


class ProjectionPort:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []
        self.owned_report_list = _owned_report_list_projection()

    def list_own_reports(self, *, actor, limit, cursor):
        self.calls.append(("LIST_OWN_REPORTS", (limit, cursor)))
        return TrustHttpProjection(
            "OWN_REPORT_LIST", self.owned_report_list, ETAG
        )

    def read_own_report(self, *, actor, report_id):
        self.calls.append(("READ_OWN_REPORT", report_id))
        return TrustHttpProjection("REPORT", _report_projection(), ETAG)

    def list_case_queue(self, *, actor, limit):
        self.calls.append(("LIST_CASE_QUEUE", limit))
        return TrustHttpProjection("CASE_QUEUE", _queue_projection(), ETAG)

    def list_hold_release_queue(self, *, actor, limit):
        self.calls.append(("LIST_HOLD_RELEASE_QUEUE", limit))
        return TrustHttpProjection(
            "HOLD_RELEASE_QUEUE", _hold_queue_projection(), ETAG
        )

    def list_my_active_case_assignments(self, *, actor, limit):
        self.calls.append(("LIST_MY_ACTIVE_CASE_ASSIGNMENTS", limit))
        return TrustHttpProjection(
            "MY_ACTIVE_CASE_ASSIGNMENTS",
            {
                "entity_tag": ETAG,
                "items": [
                    {
                        "assignment_expires_at": "2026-08-18T12:00:00Z",
                        "assignment_purpose": "CASE_TRIAGE",
                        "case_id": CASE_ID,
                        "hold_id": None,
                    }
                ],
            },
            ETAG,
        )

    def list_my_completed_case_assignments(self, *, actor, limit):
        self.calls.append(("LIST_MY_COMPLETED_CASE_ASSIGNMENTS", limit))
        return TrustHttpProjection(
            "MY_COMPLETED_CASE_ASSIGNMENTS",
            {
                "entity_tag": ETAG,
                "has_more": False,
                "items": [
                    {
                        "case_id": CASE_ID,
                        "decided_at": "2026-08-18T08:00:00Z",
                        "outcome_code": "PROTECTION_MAINTAINED",
                    }
                ],
            },
            ETAG,
        )

    def read_assigned_case(self, *, actor, case_id):
        self.calls.append(("READ_ASSIGNED_CASE", case_id))
        return TrustHttpProjection("CASE", _case_projection(), ETAG)

    def read_assigned_hold_release(self, *, actor, hold_id):
        self.calls.append(("READ_ASSIGNED_HOLD_RELEASE", hold_id))
        return TrustHttpProjection(
            "ASSIGNED_HOLD_RELEASE",
            _assigned_hold_release_projection(),
            ETAG,
        )

def _dispatcher():
    handlers = {
        "submit_report": FakeSubmit(),
        "claim_case": FakeClaimCase(),
        "release_assignment": FakeReleaseAssignment(),
        "save_triage": FakeSaveTriage(),
        "publish_triage": FakePublishTriage(),
        "place_hold": FakePlaceHold(),
        "claim_hold_release": FakeClaimHold(),
        "release_hold": FakeReleaseHold(),
        "publish_outcome": FakePublishOutcome(),
    }
    projections = ProjectionPort()
    bindings = TrustHttpPresenterBindings(
        projections=projections,
        **handlers,
    )
    return TrustHttpApplicationDispatcher(bindings=bindings), handlers, projections


def _request(method: str, path: str, body: Any, *, if_match: bool = True):
    headers = {"idempotency-key": IDEMPOTENCY_KEY}
    if if_match:
        headers["if-match"] = ETAG
    return TrustHttpRequest(method=method, path=path, headers=headers, json=body)


WRITE_CASES = (
    (
        "submit_report",
        "POST",
        "/v1/app/trust/reports",
        {
            "category": "WORKFLOW_INTEGRITY",
            "demand_id": DEMAND_ID,
            "demand_version_id": DEMAND_VERSION_ID,
            "evidence_reference_ids": [REPORT_ID],
            "impact_codes": ["WORKFLOW_INTEGRITY_RISK"],
            "incident_ended_at": None,
            "incident_started_at": "2026-08-18T07:00:00Z",
            "requested_protection_codes": ["PAUSE_SUBMISSION"],
        },
        SubmitSafetyReportCommand,
        201,
        False,
    ),
    ("claim_case", "POST", f"/v1/app/trust/queue/{CASE_ID}/claim", {}, ClaimSafetyCaseCommand, 201, True),
    ("claim_hold_release", "POST", f"/v1/app/trust/hold-release-queue/{HOLD_ID}/claim", {}, ClaimSafetyHoldReleaseCommand, 201, True),
    ("release_assignment", "POST", f"/v1/app/trust/cases/{CASE_ID}/assignment/release", {"reason_code": "WORKLOAD_RELEASE"}, ReleaseSafetyCaseAssignmentCommand, 200, True),
    (
        "save_triage",
        "PUT",
        f"/v1/app/trust/cases/{CASE_ID}/triage-draft",
        {
            "investigation_step_codes": ["CHECK_DEMAND_VERSION"],
            "issue_codes": ["WORKFLOW_INTEGRITY_GAP"],
            "jurisdiction_code": "PLATFORM_INTERNAL",
            "priority_code": "P1",
            "proposed_hold_actions": ["SUBMIT_DEMAND"],
            "proposed_hold_ttl_minutes": 60,
            "restricted_note": "never reflect this note",
            "severity_code": "HIGH",
        },
        SaveTrustTriageDraftCommand,
        200,
        True,
    ),
    ("publish_triage", "POST", f"/v1/app/trust/cases/{CASE_ID}/triage-publish", {"expected_draft_version": 3}, PublishTrustTriageCommand, 200, True),
    ("place_hold", "POST", f"/v1/app/trust/cases/{CASE_ID}/holds", {"action_codes": ["SUBMIT_DEMAND"], "reason_code": "WORKFLOW_INTEGRITY_RISK", "ttl_minutes": 60}, PlaceSafetyHoldCommand, 201, True),
    ("release_hold", "POST", f"/v1/app/trust/holds/{HOLD_ID}/release", {"reason_code": "RISK_MITIGATED"}, ReleaseSafetyHoldCommand, 200, True),
    ("publish_outcome", "POST", f"/v1/app/trust/cases/{CASE_ID}/decisions", {"action_codes": [], "outcome_code": "NO_ACTION", "reason_codes": ["NO_POLICY_BREACH"]}, PublishTrustOutcomeCommand, 201, True),
)


@pytest.mark.parametrize(
    "handler_name,method,path,body,command_type,status,if_match", WRITE_CASES
)
def test_nine_write_routes_parse_closed_commands_and_return_safe_projection(
    handler_name, method, path, body, command_type, status, if_match
):
    dispatcher, handlers, projections = _dispatcher()
    response = dispatcher.handle(
        request=_request(method, path, body, if_match=if_match),
        actor=_actor(reporter=handler_name == "submit_report"),
    )

    assert response.status == status
    assert response.headers == {"content-type": "application/json"}
    assert set(response.json) == {"data"}
    assert set(response.json["data"]) == {
        "aggregate_version",
        "case_id",
        "case_status",
        "completed_at",
        "event_types",
        "hold_id",
        "hold_version",
        "outcome_version_id",
        "report_id",
        "triage_draft_version",
        "triage_version",
        "replayed",
    }
    assert "assignment_id" not in response.json["data"]
    assert "restricted_note" not in repr(response)
    command = handlers[handler_name].calls[0][1]
    assert isinstance(command, command_type)
    assert command.idempotency_key == IDEMPOTENCY_KEY
    if if_match:
        assert getattr(command, "expected_case_version", getattr(command, "expected_hold_version", None)) == 7
    if handler_name == "publish_triage":
        assert command.expected_draft_version == 3
    if handler_name == "save_triage":
        assert command.restricted_note == "never reflect this note"
        assert "never reflect this note" not in repr(command)


def test_triage_code_sets_are_canonicalized_before_production_dispatch() -> None:
    dispatcher, handlers, _ = _dispatcher()
    response = dispatcher.handle(
        request=_request(
            "PUT",
            f"/v1/app/trust/cases/{CASE_ID}/triage-draft",
            {
                "investigation_step_codes": [
                    "CHECK_POLICY_REQUIREMENTS",
                    "CHECK_DEMAND_VERSION",
                ],
                "issue_codes": [
                    "WORKFLOW_INTEGRITY_GAP",
                    "SCOPE_DISCLOSURE_RISK",
                ],
                "jurisdiction_code": "PLATFORM_INTERNAL",
                "priority_code": "P0",
                "proposed_hold_actions": ["VERIFY_DEMAND", "SUBMIT_DEMAND"],
                "proposed_hold_ttl_minutes": 60,
                "restricted_note": "sealed input only",
                "severity_code": "CRITICAL",
            },
        ),
        actor=_actor(reporter=False),
    )

    assert response.status == 200
    command = handlers["save_triage"].calls[0][1]
    assert command.investigation_step_codes == (
        "CHECK_DEMAND_VERSION",
        "CHECK_POLICY_REQUIREMENTS",
    )
    assert command.issue_codes == (
        "SCOPE_DISCLOSURE_RISK",
        "WORKFLOW_INTEGRITY_GAP",
    )
    assert tuple(value.value for value in command.proposed_hold_actions) == (
        "SUBMIT_DEMAND",
        "VERIFY_DEMAND",
    )


@pytest.mark.parametrize(
    "path,reporter,expected_kind,expected_call",
    (
        (f"/v1/app/trust/reports/{REPORT_ID}", True, "report_id", ("READ_OWN_REPORT", REPORT_ID)),
        ("/v1/app/trust/queue", False, "items", ("LIST_CASE_QUEUE", 100)),
        ("/v1/app/trust/hold-release-queue", False, "items", ("LIST_HOLD_RELEASE_QUEUE", 100)),
        ("/v1/app/trust/history", False, "has_more", ("LIST_MY_COMPLETED_CASE_ASSIGNMENTS", 100)),
        (f"/v1/app/trust/cases/{CASE_ID}", False, "case_id", ("READ_ASSIGNED_CASE", CASE_ID)),
        (f"/v1/app/trust/assigned-holds/{HOLD_ID}", False, "hold_id", ("READ_ASSIGNED_HOLD_RELEASE", HOLD_ID)),
    ),
)
def test_read_routes_use_only_the_closed_projection_port(
    path, reporter, expected_kind, expected_call
):
    dispatcher, handlers, projections = _dispatcher()
    response = dispatcher.handle(
        request=TrustHttpRequest(method="GET", path=path, headers={}, json={}),
        actor=_actor(reporter=reporter),
    )

    assert response.status == 200
    assert response.headers["etag"] == ETAG
    assert expected_kind in response.json["data"]
    assert projections.calls == [expected_call]
    assert all(not handler.calls for handler in handlers.values())


@pytest.mark.parametrize(
    "history_request",
    (
        TrustHttpRequest(
            method="GET",
            path="/v1/app/trust/history",
            headers={},
            json={"case_id": CASE_ID},
        ),
        TrustHttpRequest(
            method="GET",
            path="/v1/app/trust/history",
            headers={},
            json={},
            query={"limit": ("1",)},
        ),
    ),
)
def test_completed_assignment_history_requires_empty_query_and_body(
    history_request,
) -> None:
    dispatcher, handlers, projections = _dispatcher()

    response = dispatcher.handle(
        request=history_request,
        actor=_actor(reporter=False),
    )

    assert (response.status, response.json["error"]["code"]) == (
        400,
        "INVALID_REQUEST",
    )
    assert response.json["error"]["path"] in {"/body", "/query"}
    assert projections.calls == []
    assert all(not handler.calls for handler in handlers.values())


def test_completed_assignment_history_ties_require_case_id_descending() -> None:
    history = {
        "entity_tag": ETAG,
        "has_more": False,
        "items": [
            {
                "case_id": SECOND_CASE_ID,
                "decided_at": "2026-08-18T08:00:00Z",
                "outcome_code": "PROTECTION_MAINTAINED",
            },
            {
                "case_id": CASE_ID,
                "decided_at": "2026-08-18T08:00:00Z",
                "outcome_code": "NO_ACTION",
            },
        ],
    }

    projection = TrustHttpProjection(
        "MY_COMPLETED_CASE_ASSIGNMENTS",
        history,
        ETAG,
    )

    assert [item["case_id"] for item in projection.as_json()["items"]] == [
        SECOND_CASE_ID,
        CASE_ID,
    ]
    with pytest.raises(ValueError, match="TRUST_HTTP_PROJECTION_INVALID"):
        TrustHttpProjection(
            "MY_COMPLETED_CASE_ASSIGNMENTS",
            {**history, "items": list(reversed(history["items"]))},
            ETAG,
        )


def test_owned_report_collection_parses_only_closed_pagination_and_minimal_dto() -> None:
    dispatcher, handlers, projections = _dispatcher()
    cursor = "a" * 64 + "." + "b" * 43
    response = dispatcher.handle(
        request=TrustHttpRequest(
            method="GET",
            path="/v1/app/trust/reports",
            headers={},
            json={},
            query={"cursor": (cursor,), "limit": ("1",)},
        ),
        actor=_actor(reporter=True),
    )

    assert response.status == 200
    assert response.headers == {
        "content-type": "application/json",
        "etag": ETAG,
    }
    assert projections.calls == [("LIST_OWN_REPORTS", (1, cursor))]
    assert set(response.json["data"]) == {"entity_tag", "items", "next_cursor"}
    assert set(response.json["data"]["items"][0]) == {
        "category",
        "demand_id",
        "outcome",
        "report_id",
        "status",
        "submitted_at",
    }
    assert all(not handler.calls for handler in handlers.values())


@pytest.mark.parametrize(
    "query",
    (
        {"limit": ("0",)},
        {"limit": ("01",)},
        {"limit": ("20", "21")},
        {"cursor": ("unsigned",)},
        {"actor_user_id": (USER_ID,)},
    ),
)
def test_owned_report_collection_rejects_ambiguous_or_forged_query(query) -> None:
    dispatcher, _, projections = _dispatcher()

    response = dispatcher.handle(
        request=TrustHttpRequest(
            method="GET",
            path="/v1/app/trust/reports",
            headers={},
            json={},
            query=query,
        ),
        actor=_actor(reporter=True),
    )

    assert (response.status, response.json["error"]["code"]) == (
        400,
        "INVALID_REQUEST",
    )
    assert projections.calls == []


def test_owned_report_collection_rejects_sensitive_or_rich_outcome_fields() -> None:
    dispatcher, _, projections = _dispatcher()
    projections.owned_report_list = _owned_report_list_projection()
    projections.owned_report_list["items"][0]["reporter_user_id"] = USER_ID

    response = dispatcher.handle(
        request=TrustHttpRequest(
            method="GET",
            path="/v1/app/trust/reports",
            headers={},
            json={},
        ),
        actor=_actor(reporter=True),
    )

    assert response.status == 503
    assert response.json == {"error": {"code": "SERVICE_UNAVAILABLE"}}


def test_closed_body_idempotency_and_precondition_rejections_do_not_invoke_handlers():
    dispatcher, handlers, _ = _dispatcher()
    bad = (
        TrustHttpRequest(
            method="POST",
            path=f"/v1/app/trust/queue/{CASE_ID}/claim",
            headers={"idempotency-key": IDEMPOTENCY_KEY},
            json={},
        ),
        TrustHttpRequest(
            method="POST",
            path=f"/v1/app/trust/queue/{CASE_ID}/claim",
            headers={"idempotency-key": "short", "if-match": ETAG},
            json={},
        ),
        TrustHttpRequest(
            method="POST",
            path=f"/v1/app/trust/queue/{CASE_ID}/claim",
            headers={"idempotency-key": IDEMPOTENCY_KEY, "if-match": ETAG},
            json={"actor_user_id": USER_ID},
        ),
    )
    expected = (
        (428, "PRECONDITION_REQUIRED"),
        (400, "INVALID_IDEMPOTENCY_KEY"),
        (400, "INVALID_REQUEST"),
    )

    for request, wanted in zip(bad, expected):
        response = dispatcher.handle(request=request, actor=_actor(reporter=False))
        assert (response.status, response.json["error"]["code"]) == wanted
    assert all(not handler.calls for handler in handlers.values())


def test_application_errors_are_uniform_and_restricted_note_never_reflects():
    dispatcher, handlers, _ = _dispatcher()
    handlers["save_triage"].error_code = "TRIAGE_VALIDATION_FAILED"
    _, method, path, body, _, _, if_match = WRITE_CASES[4]
    body = {**body, "restricted_note": "top secret narrative"}

    response = dispatcher.handle(
        request=_request(method, path, body, if_match=if_match),
        actor=_actor(reporter=False),
    )

    assert (response.status, response.json) == (
        422,
        {"error": {"code": "TRUST_VALIDATION_FAILED"}},
    )
    assert "top secret narrative" not in repr(response)


def test_projection_contract_rejects_identity_or_raw_note_fields_and_detaches_input():
    data = _case_projection()
    projection = TrustHttpProjection("CASE", data, ETAG)
    data["assigned_officer_user_id"] = USER_ID
    assert "assigned_officer_user_id" not in projection.as_json()

    unsafe = _case_projection()
    unsafe["triage_draft"]["content"]["restricted_note"] = "raw narrative"
    with pytest.raises(ValueError, match="TRUST_HTTP_PROJECTION_INVALID"):
        TrustHttpProjection("CASE", unsafe, ETAG)

    rich_hold = {**_assigned_hold_release_projection(), "assignment_id": HOLD_ID}
    with pytest.raises(ValueError, match="TRUST_HTTP_PROJECTION_INVALID"):
        TrustHttpProjection("ASSIGNED_HOLD_RELEASE", rich_hold, ETAG)

    decided = {**_case_projection(), "status": "DECIDED"}
    assert TrustHttpProjection("CASE", decided, ETAG).as_json()["status"] == "DECIDED"


def test_bindings_are_closed_and_require_all_nine_handlers_and_projection_methods():
    _, handlers, projections = _dispatcher()
    with pytest.raises(TypeError, match="Trust HTTP"):
        TrustHttpPresenterBindings(
            projections=object(),
            **handlers,
        )
    old_seven_method_projection = SimpleNamespace(
        **{
            name: getattr(projections, name)
            for name in (
                "list_own_reports",
                "read_own_report",
                "list_case_queue",
                "list_hold_release_queue",
                "list_my_active_case_assignments",
                "read_assigned_case",
                "read_assigned_hold_release",
            )
        }
    )
    with pytest.raises(TypeError, match="projection port"):
        TrustHttpPresenterBindings(
            projections=old_seven_method_projection,
            **handlers,
        )
