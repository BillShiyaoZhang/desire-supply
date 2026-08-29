from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import pytest
import yaml

from desire_platform.http.contracts import AuthenticatedHttpActor
from desire_platform.internal_pilot.editor import EditorPrincipal
from desire_platform.internal_pilot.matching_http import (
    MATCHING_OPERATIONAL_HTTP_ROUTES,
    MatchingAsgiApplication,
    is_matching_operational_path,
    resolve_matching_operational_http_route,
)
from desire_platform.internal_pilot.runtime import InternalSandboxApiMux
from desire_platform.matching.application import (
    ChooseCreatorHandler,
    CloseSelectionWithoutChoiceHandler,
    CreateInvitationHandler,
    InvalidateAttemptHandler,
    MatchingActorContext,
    MatchingActorKind,
    MatchingCommandResult,
    PublishInvitationHandler,
    RespondInvitationHandler,
    WithdrawAcceptedInvitationHandler,
)
from desire_platform.matching.http import (
    MATCHING_HTTP_ROUTES,
    MatchingHttpActor,
    MatchingHttpApplicationDispatcher,
    MatchingHttpPresenterBindings,
    MatchingHttpProjection,
    MatchingHttpRequest,
    MatchingHttpResponse,
    is_matching_public_path,
    resolve_matching_http_route,
)


USER_ID = "10000000-0000-4000-8000-000000000001"
SESSION_ID = "20000000-0000-4000-8000-000000000001"
ORG_ID = "30000000-0000-4000-8000-000000000001"
DEMAND_ID = "40000000-0000-4000-8000-000000000001"
ATTEMPT_ID = "50000000-0000-4000-8000-000000000001"
RUN_ID = "60000000-0000-4000-8000-000000000001"
INVITATION_ID = "70000000-0000-4000-8000-000000000001"
SELECTION_ID = "80000000-0000-4000-8000-000000000001"
ASSIGNMENT_ID = "90000000-0000-4000-8000-000000000001"
PROFILE_ID = "a0000000-0000-4000-8000-000000000001"
PROFILE_VERSION_ID = "b0000000-0000-4000-8000-000000000001"
TRACE_ID = "c0000000-0000-4000-8000-000000000001"
NOW = datetime(2026, 8, 26, 10, 0, tzinfo=timezone.utc)
NOW_TEXT = "2026-08-26T10:00:00Z"
EXPIRES_TEXT = "2026-09-02T10:00:00Z"
SHA = "a" * 64
RAW_HANDLE = "matching-session-handle-abcdefghijklmnopqrstuvwxyz-012345"
RAW_CSRF = "matching-csrf-token-abcdefghijklmnopqrstuvwxyz-0123456789"
IDEMPOTENCY_KEY = "matching-http-idempotency-0001"


def async_test(function):
    def run():
        return asyncio.run(function())

    return run


def _disclosure() -> dict:
    value = {
        "schema_version": 1,
        "canonicalization_version": "invitation-disclosure-json-v1",
        "invitation_id": INVITATION_ID,
        "attempt_id": ATTEMPT_ID,
        "demand_id": DEMAND_ID,
        "demand_version_id": "d0000000-0000-4000-8000-000000000001",
        "profile_id": PROFILE_ID,
        "profile_version_id": PROFILE_VERSION_ID,
        "organization_preview": {
            "organization_id": ORG_ID,
            "display_label": "Community Energy Lab",
        },
        "opportunity": {
            "title": "Energy analysis",
            "problem_summary": "Reduce energy waste.",
            "deliverable_summaries": ["Validated plan."],
            "acceptance_summaries": ["Measurable baseline."],
        },
        "offer": {
            "currency": "CNY",
            "minimum_amount_minor": 100_000,
            "maximum_amount_minor": 200_000,
            "schedule_code": "SCHEDULE_FLEXIBLE",
            "duration_weeks": 6,
        },
        "constraints": {
            "region_codes": ["REGION_CN"],
            "language_codes": ["LANGUAGE_ZH"],
            "data_sensitivity_code": "INTERNAL",
            "ai_use_code": "OPTIONAL",
        },
        "expires_at": EXPIRES_TEXT,
        "demand_content_sha256": SHA,
        "profile_content_sha256": SHA,
    }
    canonical = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    value["snapshot_sha256"] = hashlib.sha256(canonical).hexdigest()
    return value


def recipient_invitation(*, status="SENT", version=1, updated_at=NOW_TEXT) -> dict:
    disclosure = _disclosure()
    return {
        "invitation_id": INVITATION_ID,
        "status": status,
        "aggregate_version": version,
        "updated_at": updated_at,
        "expires_at": EXPIRES_TEXT,
        "snapshot_sha256": disclosure["snapshot_sha256"],
        "response_status": status if status in {"ACCEPTED", "DECLINED", "WITHDRAWN"} else None,
        "disclosure": disclosure,
    }


def attempt(*, status="OPEN", version=1, updated_at=NOW_TEXT) -> dict:
    return {
        "attempt_id": ATTEMPT_ID,
        "demand_id": DEMAND_ID,
        "attempt_no": 1,
        "status": status,
        "aggregate_version": version,
        "updated_at": updated_at,
    }


def selection(*, status="OPEN", version=1, updated_at=NOW_TEXT) -> dict:
    chosen = INVITATION_ID if status == "SELECTED" else None
    return {
        "selection_id": SELECTION_ID,
        "attempt_id": ATTEMPT_ID,
        "candidate_selector_assignment_id": ASSIGNMENT_ID,
        "candidate_selector_assignment_version": 3,
        "status": status,
        "aggregate_version": version,
        "updated_at": updated_at,
        "current_invitation_set_sha256": SHA,
        "chosen_invitation_id": chosen,
        "accepted_invitations": [
            {
                "invitation_id": INVITATION_ID,
                "creator_display_handle": "Creator Seven",
                "profile_id": PROFILE_ID,
                "profile_version_id": PROFILE_VERSION_ID,
                "accepted_at": NOW_TEXT,
                "capability_summary": "Verified energy analysis capability.",
            }
        ],
    }


def reviewer_invitation(*, status="CREATED", version=1, updated_at=NOW_TEXT) -> dict:
    return {
        "invitation_id": INVITATION_ID,
        "attempt_id": ATTEMPT_ID,
        "match_run_id": RUN_ID,
        "creator_user_id": USER_ID,
        "status": status,
        "aggregate_version": version,
        "updated_at": updated_at,
        "expires_at": EXPIRES_TEXT,
        "snapshot_sha256": _disclosure()["snapshot_sha256"],
    }


def http_actor(*, kind="PERSONAL") -> MatchingHttpActor:
    if kind == "PERSONAL":
        return MatchingHttpActor(
            actor_user_id=USER_ID,
            session_id=SESSION_ID,
            correlation_id=TRACE_ID,
            causation_id=TRACE_ID,
            trace_id=TRACE_ID,
            original_actor_id=None,
            workspace_id=f"personal:{USER_ID}",
            workspace_kind="PERSONAL",
            organization_id=None,
            role_codes=("CREATOR",),
        )
    if kind == "ORGANIZATION":
        return MatchingHttpActor(
            actor_user_id=USER_ID,
            session_id=SESSION_ID,
            correlation_id=TRACE_ID,
            causation_id=TRACE_ID,
            trace_id=TRACE_ID,
            original_actor_id=None,
            workspace_id=f"org:{ORG_ID}",
            workspace_kind="ORGANIZATION",
            organization_id=ORG_ID,
            role_codes=("DEMAND_OWNER",),
        )
    return MatchingHttpActor(
        actor_user_id=USER_ID,
        session_id=SESSION_ID,
        correlation_id=TRACE_ID,
        causation_id=TRACE_ID,
        trace_id=TRACE_ID,
        original_actor_id=None,
        workspace_id=f"platform:{USER_ID}",
        workspace_kind="PLATFORM",
        organization_id=None,
        role_codes=("OPERATIONS_REVIEWER",),
    )


class CommandActors:
    def __init__(self):
        self.calls = []

    def resolve_actor(self, *, actor, operation_id, path_parameters):
        self.calls.append((actor, operation_id, dict(path_parameters)))
        return MatchingActorContext(
            actor_kind=MatchingActorKind.USER,
            actor_id=actor.actor_user_id,
            session_id=actor.session_id,
            organization_id=path_parameters.get("organization_id", ORG_ID),
            correlation_id=actor.correlation_id,
            causation_id=actor.causation_id,
            trace_id=actor.trace_id,
            original_actor_id=actor.original_actor_id,
            workload_credential_id=None,
        )


class Assignments:
    def __init__(self):
        self.calls = []

    def resolve_assignment_id(self, **facts):
        self.calls.append(facts)
        return ASSIGNMENT_ID


class Projections:
    def __init__(self):
        self.recipient = recipient_invitation()
        self.selection = selection()
        self.reviewer = reviewer_invitation()
        self.attempt = attempt()
        self.calls = []

    def list_recipient_invitations(self, **facts):
        self.calls.append(("list_recipient", facts))
        return MatchingHttpProjection(
            kind="RECIPIENT_INVITATION_LIST",
            data={"items": [self.recipient], "next_cursor": None},
        )

    def read_recipient_invitation(self, **facts):
        self.calls.append(("recipient", facts))
        return MatchingHttpProjection(
            kind="RECIPIENT_INVITATION",
            data=self.recipient,
            entity_tag=f'"v{self.recipient["aggregate_version"]}"',
        )

    def list_demand_attempts(self, **facts):
        self.calls.append(("attempts", facts))
        return MatchingHttpProjection(
            kind="ATTEMPT_LIST",
            data={"items": [self.attempt], "next_cursor": None},
        )

    def read_selection_for_attempt(self, **facts):
        self.calls.append(("selection_for_attempt", facts))
        return MatchingHttpProjection(
            kind="SELECTION",
            data=self.selection,
            entity_tag=f'"v{self.selection["aggregate_version"]}"',
        )

    def read_selection(self, **facts):
        self.calls.append(("selection", facts))
        return MatchingHttpProjection(
            kind="SELECTION",
            data=self.selection,
            entity_tag=f'"v{self.selection["aggregate_version"]}"',
        )

    def read_reviewer_invitation(self, **facts):
        self.calls.append(("reviewer", facts))
        return MatchingHttpProjection(
            kind="REVIEWER_INVITATION",
            data=self.reviewer,
            entity_tag=f'"v{self.reviewer["aggregate_version"]}"',
        )

    def read_attempt(self, **facts):
        self.calls.append(("attempt", facts))
        return MatchingHttpProjection(
            kind="ATTEMPT",
            data=self.attempt,
            entity_tag=f'"v{self.attempt["aggregate_version"]}"',
        )


class RecordingRespond(RespondInvitationHandler):
    def __init__(self, projections):
        self.projections = projections
        self.calls = []
        self.fail_after_dispatch = False

    def handle(self, *, actor, command):
        self.calls.append((actor, command))
        if self.fail_after_dispatch:
            raise RuntimeError("private storage failure")
        self.projections.recipient = recipient_invitation(status="ACCEPTED", version=2)
        return MatchingCommandResult(
            target_id=INVITATION_ID,
            target_status="ACCEPTED",
            aggregate_version=2,
            updated_at=NOW,
            replayed=False,
            event_types=("InvitationAccepted",),
        )


class RecordingChoose(ChooseCreatorHandler):
    def __init__(self, projections):
        self.projections = projections
        self.calls = []

    def handle(self, *, actor, command):
        self.calls.append((actor, command))
        self.projections.selection = selection(status="SELECTED", version=2)
        return MatchingCommandResult(
            target_id=SELECTION_ID,
            target_status="SELECTED",
            aggregate_version=2,
            updated_at=NOW,
            replayed=False,
            event_types=("SelectionIntentRecorded",),
        )


class RecordingCreate(CreateInvitationHandler):
    def __init__(self, projections):
        self.projections = projections
        self.calls = []

    def handle(self, *, actor, command):
        self.calls.append((actor, command))
        return MatchingCommandResult(
            target_id=INVITATION_ID,
            target_status="CREATED",
            aggregate_version=1,
            updated_at=NOW,
            replayed=False,
            event_types=("InvitationCreated",),
        )


def dispatcher():
    projections = Projections()
    respond = RecordingRespond(projections)
    choose = RecordingChoose(projections)
    create = RecordingCreate(projections)
    actors = CommandActors()
    assignments = Assignments()
    value = MatchingHttpApplicationDispatcher(
        bindings=MatchingHttpPresenterBindings(
            respond_invitation=respond,
            withdraw_invitation=WithdrawAcceptedInvitationHandler(),
            choose_creator=choose,
            close_selection=CloseSelectionWithoutChoiceHandler(),
            create_invitation=create,
            publish_invitation=PublishInvitationHandler(),
            invalidate_attempt=InvalidateAttemptHandler(),
            projections=projections,
            command_actors=actors,
            reviewer_assignments=assignments,
        )
    )
    return value, projections, respond, choose, create, actors, assignments


def test_route_catalog_is_exact_and_excludes_worker_and_coordination_commands():
    assert {route.operation_id for route in MATCHING_HTTP_ROUTES} == {
        "listMyMatchingInvitations",
        "getMyMatchingInvitation",
        "acceptMatchingInvitation",
        "declineMatchingInvitation",
        "withdrawMatchingInvitationAcceptance",
        "listDemandMatchingAttempts",
        "getMatchingSelection",
        "chooseMatchingCreator",
        "closeMatchingSelection",
        "createMatchingInvitation",
        "publishMatchingInvitation",
        "invalidateMatchingAttempt",
    }
    assert not is_matching_public_path("/v1/matching/workers/runs/start")
    assert not is_matching_public_path("/v1/selections/complete")
    route, parameters = resolve_matching_http_route(
        "POST", f"/v1/organizations/{ORG_ID}/selections/{SELECTION_ID}/choose"
    )
    assert route.operation_id == "chooseMatchingCreator"
    assert parameters == {"organization_id": ORG_ID, "selection_id": SELECTION_ID}


def test_projection_is_closed_and_rejects_ranking_or_snapshot_drift():
    valid = selection()
    projection = MatchingHttpProjection(
        kind="SELECTION", data=valid, entity_tag='"v1"'
    )
    assert set(projection.as_json()["accepted_invitations"][0]) == {
        "invitation_id",
        "creator_display_handle",
        "profile_id",
        "profile_version_id",
        "accepted_at",
        "capability_summary",
    }
    leaked = selection()
    leaked["accepted_invitations"][0]["rank"] = 1
    with pytest.raises(ValueError, match="MATCHING_HTTP_PROJECTION_INVALID"):
        MatchingHttpProjection(kind="SELECTION", data=leaked, entity_tag='"v1"')
    drifted = recipient_invitation()
    drifted["disclosure"]["offer"]["maximum_amount_minor"] += 1
    with pytest.raises(ValueError, match="MATCHING_HTTP_PROJECTION_INVALID"):
        MatchingHttpProjection(
            kind="RECIPIENT_INVITATION", data=drifted, entity_tag='"v1"'
        )


def test_creator_accept_requires_strong_precondition_and_returns_fresh_projection():
    app, _, respond, _, _, actors, _ = dispatcher()
    body = {"snapshot_sha256": _disclosure()["snapshot_sha256"]}
    response = app.handle(
        request=MatchingHttpRequest(
            method="POST",
            path=f"/v1/me/matching-invitations/{INVITATION_ID}/accept",
            headers={
                "idempotency-key": IDEMPOTENCY_KEY,
                "if-match": '"v1"',
            },
            json_body=body,
        ),
        actor=http_actor(),
    )
    assert (response.status, response.headers["etag"]) == (200, '"v2"')
    assert response.json_body["status"] == "ACCEPTED"
    command = respond.calls[0][1]
    assert command.idempotency_key == IDEMPOTENCY_KEY
    assert command.expected_invitation_version == 1
    assert command.snapshot_sha256 == body["snapshot_sha256"]
    assert actors.calls[0][1] == "acceptMatchingInvitation"

    before = len(respond.calls)
    rejected = app.handle(
        request=MatchingHttpRequest(
            method="POST",
            path=f"/v1/me/matching-invitations/{INVITATION_ID}/accept",
            headers={"idempotency-key": IDEMPOTENCY_KEY},
            json_body=body,
        ),
        actor=http_actor(),
    )
    assert (rejected.status, rejected.json_body["code"]) == (400, "INVALID_REQUEST")
    assert len(respond.calls) == before


def test_uncertain_write_failure_is_closed_as_replayable_unknown_outcome():
    app, _, respond, _, _, _, _ = dispatcher()
    respond.fail_after_dispatch = True
    response = app.handle(
        request=MatchingHttpRequest(
            method="POST",
            path=f"/v1/me/matching-invitations/{INVITATION_ID}/accept",
            headers={"idempotency-key": IDEMPOTENCY_KEY, "if-match": '"v1"'},
            json_body={"snapshot_sha256": _disclosure()["snapshot_sha256"]},
        ),
        actor=http_actor(),
    )
    assert response.status == 503
    assert response.json_body == {
        "code": "COMMAND_OUTCOME_UNKNOWN",
        "message": "The command outcome is not yet known.",
        "trace_id": TRACE_ID,
    }


def test_candidate_selector_command_binds_exact_assignment_and_organization():
    app, _, _, choose, _, _, _ = dispatcher()
    response = app.handle(
        request=MatchingHttpRequest(
            method="POST",
            path=f"/v1/organizations/{ORG_ID}/selections/{SELECTION_ID}/choose",
            headers={"idempotency-key": IDEMPOTENCY_KEY, "if-match": '"v1"'},
            json_body={
                "invitation_id": INVITATION_ID,
                "selection_basis_code": "CAPABILITY_FIT",
                "current_invitation_set_sha256": SHA,
                "candidate_selector_assignment_id": ASSIGNMENT_ID,
                "candidate_selector_assignment_version": 3,
            },
        ),
        actor=http_actor(kind="ORGANIZATION"),
    )
    assert (response.status, response.json_body["status"]) == (200, "SELECTED")
    command = choose.calls[0][1]
    assert (command.assignment_id, command.expected_assignment_version) == (
        ASSIGNMENT_ID,
        3,
    )
    assert choose.calls[0][0].organization_id == ORG_ID
    hidden = app.handle(
        request=MatchingHttpRequest(
            method="GET",
            path=f"/v1/organizations/{ORG_ID}/matching-attempts/{ATTEMPT_ID}/selection",
            headers={},
            json_body={},
        ),
        actor=http_actor(),
    )
    assert (hidden.status, hidden.json_body["code"]) == (404, "RESOURCE_NOT_FOUND")


def test_operations_create_resolves_review_assignment_outside_request_body():
    app, _, _, _, create, _, assignments = dispatcher()
    response = app.handle(
        request=MatchingHttpRequest(
            method="POST",
            path=f"/v1/operations/match-runs/{RUN_ID}/invitations",
            headers={"idempotency-key": IDEMPOTENCY_KEY, "if-match": '"v7"'},
            json_body={
                "match_run_id": RUN_ID,
                "creator_user_id": USER_ID,
                "expires_at": EXPIRES_TEXT,
            },
        ),
        actor=http_actor(kind="PLATFORM"),
    )
    assert (response.status, response.headers["etag"]) == (201, '"v1"')
    command = create.calls[0][1]
    assert (command.assignment_id, command.expected_run_version) == (
        ASSIGNMENT_ID,
        7,
    )
    assert assignments.calls[0]["operation_id"] == "createMatchingInvitation"


class SessionSecurity:
    def __init__(self):
        self.csrf_calls = []

    def authenticate(self, *, raw_session_handle, trace_id):
        assert raw_session_handle == RAW_HANDLE
        return AuthenticatedHttpActor(
            actor_user_id=USER_ID,
            session_id=SESSION_ID,
            correlation_id=trace_id,
            causation_id=trace_id,
            trace_id=trace_id,
            original_actor_id=None,
            auth_time=NOW,
            acr_code="urn:desire:acr:mfa",
            amr_codes=("pwd", "otp"),
        )

    def require_valid(self, **facts):
        self.csrf_calls.append(facts)
        if facts["raw_csrf_token"] != RAW_CSRF:
            raise RuntimeError("invalid")


class PrincipalResolver:
    def resolve(self, *, actor, requested_workspace_id):
        if requested_workspace_id != f"personal:{USER_ID}":
            raise ValueError("hidden")
        return EditorPrincipal(
            user_id=USER_ID,
            session_id=SESSION_ID,
            organization_id=None,
            role_codes=("CREATOR",),
            workspace_id=f"personal:{USER_ID}",
            workspace_kind="PERSONAL",
            user_role_codes=("CREATOR",),
            principal_marker_sha256=b"p" * 32,
        )


class OperationalPrincipalResolver:
    def __init__(self, *, workspace_kind, role_codes):
        self.workspace_kind = workspace_kind
        self.role_codes = tuple(sorted(role_codes))

    def resolve(self, *, actor, requested_workspace_id):
        if self.workspace_kind == "ORGANIZATION":
            expected = f"org:{ORG_ID}"
            organization_id = ORG_ID
            membership_id = ASSIGNMENT_ID
            organization_role_codes = self.role_codes
            platform_duty_codes = ()
        else:
            expected = f"platform:{USER_ID}"
            organization_id = None
            membership_id = None
            organization_role_codes = ()
            platform_duty_codes = self.role_codes
        if requested_workspace_id != expected:
            raise ValueError("hidden")
        return EditorPrincipal(
            user_id=USER_ID,
            session_id=SESSION_ID,
            organization_id=organization_id,
            role_codes=self.role_codes,
            workspace_id=expected,
            workspace_kind=self.workspace_kind,
            membership_id=membership_id,
            organization_role_codes=organization_role_codes,
            platform_duty_codes=platform_duty_codes,
            principal_marker_sha256=b"p" * 32,
        )


class RecordingOperationalService:
    def __init__(self):
        self.calls = []

    def handle(self, *, request, actor):
        self.calls.append((request, actor))
        created = request.path in {
            "/v1/matching/candidate-selector-assignments/claim",
            "/v1/app/matching-review/queue/claim",
        }
        return MatchingHttpResponse(
            status=201 if created else 200,
            headers={"content-type": "application/json", "etag": '"v1"'},
            json_body={"operation": request.path},
        )


async def invoke_asgi(app, *, method="GET", path=None, query=b"", headers=(), body=b""):
    path = path or f"/v1/me/matching-invitations/{INVITATION_ID}"
    messages = [{"type": "http.request", "body": body, "more_body": False}]
    sent = []

    async def receive():
        return messages.pop(0)

    async def send(message):
        sent.append(message)

    await app(
        {
            "type": "http",
            "method": method,
            "scheme": "https",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": query,
            "headers": list(headers),
        },
        receive,
        send,
    )
    return sent[0]["status"], dict(sent[0]["headers"]), json.loads(sent[1]["body"])


@async_test
async def test_asgi_authenticates_selected_creator_workspace_and_enforces_csrf_protocol():
    dispatcher_value, _, respond, _, _, _, _ = dispatcher()
    security = SessionSecurity()
    app = MatchingAsgiApplication(
        dispatcher=dispatcher_value,
        session_security=security,
        principal_resolver=PrincipalResolver(),
        allowed_origins=("https://pilot.example.test",),
        trace_id_source=lambda: TRACE_ID,
    )
    base = (
        (b"cookie", ("__Host-ds_session=" + RAW_HANDLE).encode()),
        (b"x-workspace-id", f"personal:{USER_ID}".encode()),
    )
    status, headers, body = await invoke_asgi(app, headers=base)
    assert (status, body["invitation_id"]) == (200, INVITATION_ID)
    assert headers[b"cache-control"] == b"no-store"
    assert headers[b"x-content-type-options"] == b"nosniff"
    assert headers[b"etag"] == b'"v1"'

    payload = json.dumps(
        {"snapshot_sha256": _disclosure()["snapshot_sha256"]}
    ).encode()
    write_headers = base + (
        (b"origin", b"https://pilot.example.test"),
        (b"x-csrf-token", RAW_CSRF.encode()),
        (b"idempotency-key", IDEMPOTENCY_KEY.encode()),
        (b"if-match", b'"v1"'),
        (b"content-type", b"application/json"),
        (b"content-length", str(len(payload)).encode()),
    )
    status, headers, body = await invoke_asgi(
        app,
        method="POST",
        path=f"/v1/me/matching-invitations/{INVITATION_ID}/accept",
        headers=write_headers,
        body=payload,
    )
    assert (status, body["status"], headers[b"etag"]) == (200, "ACCEPTED", b'"v2"')
    assert security.csrf_calls[0]["operation_id"] == "acceptMatchingInvitation"
    before = len(respond.calls)
    malformed = b'{"snapshot_sha256":"' + SHA.encode() + b'","snapshot_sha256":"' + SHA.encode() + b'"}'
    bad_headers = tuple(
        (name, str(len(malformed)).encode()) if name == b"content-length" else (name, value)
        for name, value in write_headers
    )
    rejected, _, error = await invoke_asgi(
        app,
        method="POST",
        path=f"/v1/me/matching-invitations/{INVITATION_ID}/accept",
        headers=bad_headers,
        body=malformed,
    )
    assert (rejected, error["code"]) == (400, "INVALID_REQUEST")
    assert len(respond.calls) == before


def test_operational_route_catalog_is_exact_and_method_closed():
    assert {(route.method, route.path, route.operation_id) for route in MATCHING_OPERATIONAL_HTTP_ROUTES} == {
        (
            "POST",
            "/v1/matching/candidate-selector-assignments/claim",
            "claimCandidateSelectorAssignment",
        ),
        (
            "POST",
            "/v1/app/matching-review/queue/claim",
            "claimMatchingReviewAssignment",
        ),
        (
            "GET",
            "/v1/app/matching-review/assignment",
            "readMatchingReviewAssignment",
        ),
        (
            "POST",
            "/v1/app/matching-review/assignment/release",
            "releaseMatchingReviewAssignment",
        ),
    }
    assert is_matching_operational_path("/v1/app/matching-review/assignment")
    assert not is_matching_operational_path("/v1/app/matching-review/assignments")
    with pytest.raises(ValueError, match="RESOURCE_NOT_FOUND"):
        resolve_matching_operational_http_route(
            "GET", "/v1/app/matching-review/queue/claim"
        )


@async_test
async def test_operational_routes_use_authenticated_workspace_roles_and_exact_csrf_ids():
    dispatcher_value, *_ = dispatcher()
    security = SessionSecurity()
    service = RecordingOperationalService()
    candidate_app = MatchingAsgiApplication(
        dispatcher=dispatcher_value,
        operational_service=service,
        session_security=security,
        principal_resolver=OperationalPrincipalResolver(
            workspace_kind="ORGANIZATION", role_codes=("DEMAND_OWNER",)
        ),
        allowed_origins=("https://pilot.example.test",),
        trace_id_source=lambda: TRACE_ID,
    )
    candidate_payload = json.dumps({"demand_id": DEMAND_ID}).encode()
    candidate_headers = (
        (b"cookie", ("__Host-ds_session=" + RAW_HANDLE).encode()),
        (b"x-workspace-id", f"org:{ORG_ID}".encode()),
        (b"origin", b"https://pilot.example.test"),
        (b"x-csrf-token", RAW_CSRF.encode()),
        (b"idempotency-key", IDEMPOTENCY_KEY.encode()),
        (b"content-type", b"application/json"),
        (b"content-length", str(len(candidate_payload)).encode()),
    )
    status, _, body = await invoke_asgi(
        candidate_app,
        method="POST",
        path="/v1/matching/candidate-selector-assignments/claim",
        headers=candidate_headers,
        body=candidate_payload,
    )
    assert (status, body["operation"]) == (
        201,
        "/v1/matching/candidate-selector-assignments/claim",
    )
    assert security.csrf_calls[-1]["operation_id"] == "claimCandidateSelectorAssignment"
    assert service.calls[-1][1].organization_id == ORG_ID

    reviewer_app = MatchingAsgiApplication(
        dispatcher=dispatcher_value,
        operational_service=service,
        session_security=security,
        principal_resolver=OperationalPrincipalResolver(
            workspace_kind="PLATFORM", role_codes=("OPERATIONS_REVIEWER",)
        ),
        allowed_origins=("https://pilot.example.test",),
        trace_id_source=lambda: TRACE_ID,
    )
    empty_payload = b"{}"
    reviewer_headers = (
        (b"cookie", ("__Host-ds_session=" + RAW_HANDLE).encode()),
        (b"x-workspace-id", f"platform:{USER_ID}".encode()),
        (b"origin", b"https://pilot.example.test"),
        (b"x-csrf-token", RAW_CSRF.encode()),
        (b"idempotency-key", IDEMPOTENCY_KEY.encode()),
        (b"content-type", b"application/json"),
        (b"content-length", str(len(empty_payload)).encode()),
    )
    status, _, _ = await invoke_asgi(
        reviewer_app,
        method="POST",
        path="/v1/app/matching-review/queue/claim",
        headers=reviewer_headers,
        body=empty_payload,
    )
    assert status == 201
    assert security.csrf_calls[-1]["operation_id"] == "claimMatchingReviewAssignment"

    release_headers = reviewer_headers + ((b"if-match", b'"v1"'),)
    status, _, _ = await invoke_asgi(
        reviewer_app,
        method="POST",
        path="/v1/app/matching-review/assignment/release",
        headers=release_headers,
        body=empty_payload,
    )
    assert status == 200
    assert security.csrf_calls[-1]["operation_id"] == "releaseMatchingReviewAssignment"


@async_test
async def test_operational_routes_hide_wrong_authenticated_roles_before_service_dispatch():
    dispatcher_value, *_ = dispatcher()
    service = RecordingOperationalService()
    app = MatchingAsgiApplication(
        dispatcher=dispatcher_value,
        operational_service=service,
        session_security=SessionSecurity(),
        principal_resolver=OperationalPrincipalResolver(
            workspace_kind="PLATFORM", role_codes=("TRUST_OFFICER",)
        ),
        allowed_origins=("https://pilot.example.test",),
        trace_id_source=lambda: TRACE_ID,
    )
    headers = (
        (b"cookie", ("__Host-ds_session=" + RAW_HANDLE).encode()),
        (b"x-workspace-id", f"platform:{USER_ID}".encode()),
    )
    status, _, body = await invoke_asgi(
        app,
        path="/v1/app/matching-review/assignment",
        headers=headers,
    )
    assert (status, body["code"]) == (404, "RESOURCE_NOT_FOUND")
    assert service.calls == []

    candidate_app = MatchingAsgiApplication(
        dispatcher=dispatcher_value,
        operational_service=service,
        session_security=SessionSecurity(),
        principal_resolver=OperationalPrincipalResolver(
            workspace_kind="ORGANIZATION", role_codes=("ORG_ADMIN",)
        ),
        allowed_origins=("https://pilot.example.test",),
        trace_id_source=lambda: TRACE_ID,
    )
    status, _, body = await invoke_asgi(
        candidate_app,
        method="POST",
        path="/v1/matching/candidate-selector-assignments/claim",
        headers=(
            (b"cookie", ("__Host-ds_session=" + RAW_HANDLE).encode()),
            (b"x-workspace-id", f"org:{ORG_ID}".encode()),
        ),
    )
    assert (status, body["code"]) == (404, "RESOURCE_NOT_FOUND")
    assert service.calls == []


class RecordingApplication:
    def __init__(self, body):
        self.body = body
        self.paths = []

    async def __call__(self, scope, receive, send):
        self.paths.append(scope["path"])
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": self.body, "more_body": False})


async def invoke_mux(app, path):
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    await app(
        {"type": "http", "method": "GET", "path": path}, receive, send
    )
    return sent


@async_test
async def test_mux_routes_only_exact_matching_paths_and_fails_closed_when_unbound():
    iam = RecordingApplication(b"iam")
    editor = RecordingApplication(b"editor")
    matching = RecordingApplication(b"matching")
    mux = InternalSandboxApiMux(
        iam_application=iam,
        editor_application=editor,
        matching_application=matching,
    )
    messages = await invoke_mux(mux, "/v1/me/matching-invitations")
    assert messages[1]["body"] == b"matching"
    messages = await invoke_mux(mux, "/v1/app/matching-review/assignment")
    assert messages[1]["body"] == b"matching"
    assert not iam.paths
    unknown = await invoke_mux(mux, "/v1/me/matching-invitations-export")
    assert unknown[1]["body"] == b"iam"
    assert matching.paths == [
        "/v1/me/matching-invitations",
        "/v1/app/matching-review/assignment",
    ]

    closed = InternalSandboxApiMux(iam_application=iam, editor_application=editor)
    messages = await invoke_mux(closed, "/v1/me/matching-invitations")
    assert messages[0]["status"] == 503
    assert json.loads(messages[1]["body"])["code"] == "SERVICE_UNAVAILABLE"
    messages = await invoke_mux(closed, "/v1/app/matching-review/assignment")
    assert messages[0]["status"] == 503


def test_openapi_declares_unknown_outcome_for_every_mutation():
    contract = yaml.safe_load(
        (Path(__file__).parents[2] / "contracts/api/matching-v1.openapi.yaml").read_text()
    )
    assert "COMMAND_OUTCOME_UNKNOWN" in contract["components"]["schemas"]["Error"]["properties"]["code"]["enum"]
    mutations = [
        operation
        for path_item in contract["paths"].values()
        for method, operation in path_item.items()
        if method.lower() in {"post", "put", "patch", "delete"}
    ]
    assert len(mutations) == 8
    assert all("COMMAND_OUTCOME_UNKNOWN" in operation["x-error-codes"] for operation in mutations)
