from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[2] / "contracts"
OPENAPI = ROOT / "api/appeal-v1.openapi.yaml"
APPLICATION = ROOT / "domain/appeal-application-v1.schema.json"
REVIEW = ROOT / "domain/appeal-review-v1.schema.json"
EVENTS = ROOT / "events/appeal-v1.schema.json"

EVENT_TYPES = {
    "AppealOpened",
    "AppealApplicationDraftSaved",
    "AppealSubmitted",
    "AppealReviewClaimed",
    "AppealReviewAssignmentReleased",
    "AppealReviewDraftSaved",
    "AppealDecisionPublished",
}
WRITE_OPERATIONS = {
    "openAppeal",
    "saveAppealDraft",
    "submitAppeal",
    "claimAppeal",
    "releaseAppealAssignment",
    "saveAppealReviewDraft",
    "decideAppeal",
}
READ_OPERATIONS = {
    "findOwnAppealBySource",
    "listMyCompletedAppealAssignments",
    "listMyActiveAppealAssignments",
    "readOwnAppeal",
    "listAppealQueue",
    "readAssignedAppeal",
    "readMyCompletedAppeal",
}
PUBLIC_ERROR_CODES = {
    "APPEAL_NOT_AVAILABLE",
    "APPEAL_STATE_CONFLICT",
    "APPEAL_VALIDATION_FAILED",
    "ASSIGNMENT_UNAVAILABLE",
    "AUTHENTICATION_REQUIRED",
    "COMMAND_IN_PROGRESS",
    "COMMAND_OUTCOME_UNKNOWN",
    "CONFLICT_OF_INTEREST",
    "CSRF_INVALID",
    "CSRF_REQUIRED",
    "IDEMPOTENCY_KEY_REUSED",
    "INVALID_IDEMPOTENCY_KEY",
    "INVALID_REQUEST",
    "POLICY_ACCEPTANCE_REQUIRED",
    "PRECONDITION_REQUIRED",
    "RESOURCE_NOT_FOUND",
    "SERVICE_UNAVAILABLE",
    "SESSION_EXPIRED",
    "STALE_VERSION",
}
PATHS = {
    "/v1/app/appeals",
    "/v1/app/appeals/{appeal_id}",
    "/v1/app/appeals/{appeal_id}/draft",
    "/v1/app/appeals/{appeal_id}/submit",
    "/v1/app/appeal-review/queue",
    "/v1/app/appeal-review/queue/{appeal_id}/claim",
    "/v1/app/appeal-review/assignments",
    "/v1/app/appeal-review/history",
    "/v1/app/appeal-review/history/{appeal_id}",
    "/v1/app/appeal-review/appeals/{appeal_id}",
    "/v1/app/appeal-review/appeals/{appeal_id}/assignment/release",
    "/v1/app/appeal-review/appeals/{appeal_id}/review-draft",
    "/v1/app/appeal-review/appeals/{appeal_id}/decide",
}


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text("utf-8"))
    assert isinstance(value, dict)
    return value


def _walk(value: Any):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def test_appeal_contracts_are_independent_closed_resources():
    api = yaml.safe_load(OPENAPI.read_text("utf-8"))
    assert api["openapi"] == "3.1.0"
    assert api["info"]["title"] == "Desire Appeal API"
    assert set(api["paths"]) == PATHS
    assert not any("trust-v1.openapi" in str(value) for value in _walk(api))
    for document in (_json(APPLICATION), _json(REVIEW), _json(EVENTS)):
        assert document["additionalProperties"] is False


def test_exact_operations_session_workspace_csrf_idempotency_and_occ_are_closed():
    api = yaml.safe_load(OPENAPI.read_text("utf-8"))
    operations = {}
    for path, path_item in api["paths"].items():
        for method, operation in path_item.items():
            if method not in {"get", "post", "put"}:
                continue
            operations[operation["operationId"]] = (path, method, operation)
            assert operation["security"] == [{"sessionCookie": []}]
            names = {
                parameter.get("name")
                for parameter in operation.get("parameters", ())
                if isinstance(parameter, dict)
            }
            references = {
                parameter.get("$ref", "").rsplit("/", 1)[-1]
                for parameter in operation.get("parameters", ())
                if isinstance(parameter, dict)
            }
            assert "WorkspaceId" in references or "X-Workspace-Id" in names
            if method in {"post", "put"}:
                assert {"IdempotencyKey", "CsrfToken"}.issubset(references)
                if operation["operationId"] != "openAppeal":
                    assert "IfMatch" in references
                success = operation["responses"][
                    "201" if operation["operationId"] in {"openAppeal", "claimAppeal"} else "200"
                ]
                assert success == {"$ref": "#/components/responses/CommandCommitted"}
    assert set(operations) == WRITE_OPERATIONS | READ_OPERATIONS


def test_raw_application_and_review_text_are_write_only_and_bounded():
    application = _json(APPLICATION)
    review = _json(REVIEW)
    statement = application["properties"]["applicant_statement"]
    note = review["properties"]["reviewer_note"]
    for value in (statement, note):
        assert value["type"] == "string"
        assert value["writeOnly"] is True
        assert value["minLength"] == 1
        assert value["maxLength"] == 4000
    assert application["required"] == sorted(application["properties"])
    assert review["required"] == sorted(review["properties"])


def test_public_command_and_read_projections_exclude_authority_and_raw_text():
    api = yaml.safe_load(OPENAPI.read_text("utf-8"))
    assignment_responses = api["paths"][
        "/v1/app/appeal-review/assignments"
    ]["get"]["responses"]
    assert assignment_responses["400"] == {
        "$ref": "#/components/responses/BadRequest"
    }
    active = api["components"]["schemas"]["AppealActiveAssignmentItem"]
    assert active["additionalProperties"] is False
    assert set(active["properties"]) == {
        "appeal_id",
        "assignment_expires_at",
    }
    assert set(active["required"]) == set(active["properties"])
    command = api["components"]["schemas"]["AppealCommandResult"]
    assert command["additionalProperties"] is False
    assert set(command["properties"]) == {
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
    serialized = json.dumps(api, sort_keys=True)
    for forbidden in (
        "applicant_statement",
        "reviewer_note",
        "sealed_",
        "assignment_id",
        "duty_grant_id",
        "actor_user_id",
    ):
        assert forbidden not in serialized
    assert "statement_recorded" in serialized
    assert "review_note_recorded" in serialized
    own = api["components"]["schemas"]["AppealOwnProjection"]
    assigned = api["components"]["schemas"]["AppealAssignedProjection"]
    source = api["components"]["schemas"]["AppealSourceProjection"]
    draft = api["components"]["schemas"]["AppealApplicationDraftProjection"]
    assert {"application_draft", "source"}.issubset(own["properties"])
    assert "source" in assigned["properties"]
    assert "assessments" in api["components"]["schemas"][
        "AppealDecisionProjection"
    ]["properties"]
    assert set(source["properties"]).isdisjoint(
        {"organization_id", "decided_by_user_id", "applicant_user_id"}
    )
    assert set(draft["properties"]) == {
        "edited_at",
        "grounds",
        "new_evidence_reference_ids",
        "requested_outcome",
        "statement_recorded",
        "version",
    }
    completed = api["components"]["schemas"][
        "AppealCompletedDetailProjection"
    ]
    assert completed["additionalProperties"] is False
    assert set(completed["properties"]) == {
        "appeal_id",
        "application",
        "decision",
        "entity_tag",
        "review_note_recorded",
        "status",
    }
    assert completed["properties"]["status"] == {"const": "DECIDED"}
    assert completed["properties"]["review_note_recorded"] == {"const": True}
    history = api["paths"]["/v1/app/appeal-review/history"]["get"]
    assert history["parameters"] == [
        {"$ref": "#/components/parameters/WorkspaceId"}
    ]


def test_event_schema_is_exact_and_payload_never_contains_restricted_or_authority_facts():
    events = _json(EVENTS)
    assert events["properties"]["aggregate_type"] == {"const": "Appeal"}
    assert set(events["properties"]["event_type"]["enum"]) == EVENT_TYPES
    payload = events["$defs"]["Payload"]
    assert payload["additionalProperties"] is False
    serialized = json.dumps(payload, sort_keys=True)
    for forbidden in (
        "statement",
        "review_note",
        "sealed_",
        "assignment_id",
        "duty_grant",
        "applicant_user_id",
        "reviewer_user_id",
    ):
        assert forbidden not in serialized


def test_http_errors_are_one_closed_non_reflective_public_shape():
    api = yaml.safe_load(OPENAPI.read_text("utf-8"))
    error = api["components"]["schemas"]["Error"]
    assert error["additionalProperties"] is False
    assert error["required"] == ["code"]
    assert set(error["properties"]) == {"code", "path"}
    assert set(error["properties"]["code"]["enum"]) == PUBLIC_ERROR_CODES
    serialized = json.dumps(error, sort_keys=True)
    for forbidden in ("message", "request_id", "diagnostic", "detail"):
        assert forbidden not in serialized
