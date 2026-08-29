"""Closed framework-neutral HTTP presenter for the Appeal vertical."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
from typing import Any, Mapping, Optional, Protocol, Tuple

from .application import (
    AppealApplicationError,
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
from .domain import (
    AppealAssignmentReleaseReason,
    AppealDecisionCode,
    AppealGround,
    AppealGroundAssessment,
    AppealGroundAssessmentCode,
    RequestedAppealOutcome,
)
from .ports import (
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


_UUID_TEXT = (
    r"(?!00000000-0000-0000-0000-000000000000)"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}"
)
_UUID = re.compile(rf"{_UUID_TEXT}\Z")
_ENTITY_TAG = re.compile(r'^"appeal-([1-9][0-9]*)-([0-9a-f]{24})"$')
_IDEMPOTENCY_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~-]{15,127}\Z")

_GROUNDS = frozenset(item.value for item in AppealGround)
_REQUESTED_OUTCOMES = frozenset(item.value for item in RequestedAppealOutcome)
_RELEASE_REASONS = frozenset(item.value for item in AppealAssignmentReleaseReason)
_ASSESSMENT_CODES = frozenset(item.value for item in AppealGroundAssessmentCode)
_DECISION_CODES = frozenset(item.value for item in AppealDecisionCode)
_FINDING_CODES = frozenset(
    (
        "APPEAL_NOT_SUBSTANTIATED",
        "NEW_EVIDENCE_MATERIAL",
        "PROCEDURE_MATERIAL_ERROR",
        "RULE_APPLICATION_ERROR",
        "RULE_APPLIED_CORRECTLY",
    )
)
_REVIEW_REASON_CODES = frozenset(
    (
        "APPEAL_SCOPE_INVALID",
        "NEW_EVIDENCE_REVIEWED",
        "PROCEDURAL_REVIEW_COMPLETE",
        "REMAND_REQUIRED",
        "SOURCE_OUTCOME_SUPPORTED",
        "SOURCE_OUTCOME_UNSUPPORTED",
    )
)
_REMEDY_CODES = frozenset(
    (
        "NARROW_CORRECTIVE_MEASURE",
        "NO_CHANGE",
        "REMOVE_CORRECTIVE_MEASURE",
        "REPLACE_CORRECTIVE_MEASURE",
        "RETURN_TO_TRUST_REVIEW",
    )
)
_EVENT_TYPES = frozenset(
    (
        "AppealOpened",
        "AppealApplicationDraftSaved",
        "AppealSubmitted",
        "AppealReviewClaimed",
        "AppealReviewAssignmentReleased",
        "AppealReviewDraftSaved",
        "AppealDecisionPublished",
    )
)


@dataclass(frozen=True)
class AppealHttpRequest:
    method: str
    path: str
    headers: Mapping[str, str] = field(repr=False)
    query: Mapping[str, Tuple[str, ...]] = field(repr=False)
    json: Mapping[str, Any] = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.method, str)
            or not isinstance(self.path, str)
            or not isinstance(self.headers, Mapping)
            or not isinstance(self.query, Mapping)
            or not isinstance(self.json, Mapping)
            or any(
                not isinstance(name, str)
                or name != name.lower()
                or not isinstance(value, str)
                for name, value in self.headers.items()
            )
            or any(
                not isinstance(name, str)
                or not isinstance(values, tuple)
                or any(not isinstance(value, str) for value in values)
                for name, values in self.query.items()
            )
        ):
            raise TypeError("Appeal HTTP request is invalid")
        object.__setattr__(self, "headers", dict(self.headers))
        object.__setattr__(
            self,
            "query",
            {name: tuple(values) for name, values in self.query.items()},
        )
        object.__setattr__(self, "json", deepcopy(dict(self.json)))


@dataclass(frozen=True)
class AppealHttpResponse:
    status: int
    headers: Mapping[str, str]
    json: Mapping[str, Any] = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.status) is not int
            or not 100 <= self.status <= 599
            or not isinstance(self.headers, Mapping)
            or not isinstance(self.json, Mapping)
            or any(
                not isinstance(name, str) or not isinstance(value, str)
                for name, value in self.headers.items()
            )
        ):
            raise TypeError("Appeal HTTP response is invalid")
        object.__setattr__(self, "headers", dict(self.headers))
        object.__setattr__(self, "json", deepcopy(dict(self.json)))


class AppealHttpProjectionPort(Protocol):
    def find_own_appeal_by_source(
        self, *, actor: TrustActorContext, source_outcome_version_id: str
    ) -> Optional[AppealOwnProjection]: ...

    def read_own_appeal(
        self, *, actor: TrustActorContext, appeal_id: str
    ) -> AppealOwnProjection: ...

    def list_appeal_queue(
        self, *, actor: TrustActorContext, limit: int
    ) -> AppealQueueProjection: ...

    def list_my_active_appeal_assignments(
        self, *, actor: TrustActorContext, limit: int
    ) -> AppealActiveAssignmentsProjection: ...

    def read_assigned_appeal(
        self, *, actor: TrustActorContext, appeal_id: str
    ) -> AppealAssignedProjection: ...

    def list_my_completed_appeal_assignments(
        self, *, actor: TrustActorContext, limit: int
    ) -> AppealCompletedAssignmentsProjection: ...

    def read_my_completed_appeal(
        self, *, actor: TrustActorContext, appeal_id: str
    ) -> AppealCompletedDetailProjection: ...


@dataclass(frozen=True)
class AppealHttpPresenterBindings:
    open_appeal: OpenAppealHandler
    save_application_draft: SaveAppealDraftHandler
    submit_appeal: SubmitAppealHandler
    claim_appeal: ClaimAppealHandler
    release_assignment: ReleaseAppealAssignmentHandler
    save_review_draft: SaveAppealReviewDraftHandler
    decide_appeal: DecideAppealHandler
    projections: AppealHttpProjectionPort

    def __post_init__(self) -> None:
        expected = (
            (self.open_appeal, OpenAppealHandler),
            (self.save_application_draft, SaveAppealDraftHandler),
            (self.submit_appeal, SubmitAppealHandler),
            (self.claim_appeal, ClaimAppealHandler),
            (self.release_assignment, ReleaseAppealAssignmentHandler),
            (self.save_review_draft, SaveAppealReviewDraftHandler),
            (self.decide_appeal, DecideAppealHandler),
        )
        if any(not isinstance(value, kind) for value, kind in expected):
            raise TypeError("Appeal HTTP command handlers are unavailable")
        methods = (
            "find_own_appeal_by_source",
            "read_own_appeal",
            "list_appeal_queue",
            "list_my_active_appeal_assignments",
            "read_assigned_appeal",
            "list_my_completed_appeal_assignments",
            "read_my_completed_appeal",
        )
        if any(not callable(getattr(self.projections, name, None)) for name in methods):
            raise TypeError("Appeal HTTP projection port is unavailable")


@dataclass(frozen=True)
class _Route:
    method: str
    expression: re.Pattern[str]
    operation: str
    handler_name: Optional[str]
    success_status: int
    requires_if_match: bool


_ROUTES = (
    _Route("POST", re.compile(r"^/v1/app/appeals$"), "OPEN_APPEAL", "open_appeal", 201, False),
    _Route("GET", re.compile(r"^/v1/app/appeals$"), "FIND_OWN_APPEAL", None, 200, False),
    _Route("GET", re.compile(rf"^/v1/app/appeals/(?P<appeal_id>{_UUID_TEXT})$"), "READ_OWN_APPEAL", None, 200, False),
    _Route("PUT", re.compile(rf"^/v1/app/appeals/(?P<appeal_id>{_UUID_TEXT})/draft$"), "SAVE_APPEAL_DRAFT", "save_application_draft", 200, True),
    _Route("POST", re.compile(rf"^/v1/app/appeals/(?P<appeal_id>{_UUID_TEXT})/submit$"), "SUBMIT_APPEAL", "submit_appeal", 200, True),
    _Route("GET", re.compile(r"^/v1/app/appeal-review/queue$"), "LIST_APPEAL_QUEUE", None, 200, False),
    _Route("GET", re.compile(r"^/v1/app/appeal-review/assignments$"), "LIST_MY_ACTIVE_APPEAL_ASSIGNMENTS", None, 200, False),
    _Route("GET", re.compile(r"^/v1/app/appeal-review/history$"), "LIST_MY_COMPLETED_APPEAL_ASSIGNMENTS", None, 200, False),
    _Route("GET", re.compile(rf"^/v1/app/appeal-review/history/(?P<appeal_id>{_UUID_TEXT})$"), "READ_MY_COMPLETED_APPEAL", None, 200, False),
    _Route("POST", re.compile(rf"^/v1/app/appeal-review/queue/(?P<appeal_id>{_UUID_TEXT})/claim$"), "CLAIM_APPEAL", "claim_appeal", 201, True),
    _Route("GET", re.compile(rf"^/v1/app/appeal-review/appeals/(?P<appeal_id>{_UUID_TEXT})$"), "READ_ASSIGNED_APPEAL", None, 200, False),
    _Route("POST", re.compile(rf"^/v1/app/appeal-review/appeals/(?P<appeal_id>{_UUID_TEXT})/assignment/release$"), "RELEASE_APPEAL_ASSIGNMENT", "release_assignment", 200, True),
    _Route("PUT", re.compile(rf"^/v1/app/appeal-review/appeals/(?P<appeal_id>{_UUID_TEXT})/review-draft$"), "SAVE_APPEAL_REVIEW_DRAFT", "save_review_draft", 200, True),
    _Route("POST", re.compile(rf"^/v1/app/appeal-review/appeals/(?P<appeal_id>{_UUID_TEXT})/decide$"), "DECIDE_APPEAL", "decide_appeal", 200, True),
)


class _HttpRejection(Exception):
    def __init__(self, status: int, code: str, path: Optional[str] = None) -> None:
        self.status = status
        self.code = code
        self.path = path
        super().__init__(code)


class AppealHttpApplicationDispatcher:
    def __init__(self, *, bindings: AppealHttpPresenterBindings) -> None:
        if not isinstance(bindings, AppealHttpPresenterBindings):
            raise TypeError("Appeal HTTP presenter bindings are unavailable")
        self._bindings = bindings

    def handle(
        self, *, request: AppealHttpRequest, actor: TrustActorContext
    ) -> AppealHttpResponse:
        if not isinstance(request, AppealHttpRequest) or not isinstance(
            actor, TrustActorContext
        ):
            return _error(400, "INVALID_REQUEST")
        try:
            route, path_parameters = _match_route(request.method, request.path)
            if route.handler_name is None:
                _exact_object(request.json, ())
                projection = self._read(
                    route=route,
                    path_parameters=path_parameters,
                    query=request.query,
                    actor=actor,
                )
                return _projection_response(projection)
            _exact_query(request.query, ())
            idempotency_key = _idempotency_key(request.headers)
            expected_version = (
                _expected_version(request.headers)
                if route.requires_if_match
                else None
            )
            command = self._command(
                route=route,
                path_parameters=path_parameters,
                body=request.json,
                idempotency_key=idempotency_key,
                expected_version=expected_version,
            )
            handler = getattr(self._bindings, route.handler_name)
            result = handler.handle(actor=actor, command=command)
            if not isinstance(result, AppealCommandResult):
                raise _HttpRejection(503, "SERVICE_UNAVAILABLE")
            return AppealHttpResponse(
                status=route.success_status,
                headers={"content-type": "application/json"},
                json={"data": _public_command_result(result)},
            )
        except _HttpRejection as error:
            return _error(error.status, error.code, error.path)
        except AppealApplicationError as error:
            status, code = _application_error(error.code)
            return _error(status, code)
        except Exception:
            return _error(503, "SERVICE_UNAVAILABLE")

    def _read(
        self,
        *,
        route: _Route,
        path_parameters: Mapping[str, str],
        query: Mapping[str, Tuple[str, ...]],
        actor: TrustActorContext,
    ) -> Any:
        port = self._bindings.projections
        if route.operation == "FIND_OWN_APPEAL":
            _exact_query(query, ("source_outcome_version_id",))
            values = query["source_outcome_version_id"]
            if len(values) != 1 or _UUID.fullmatch(values[0]) is None:
                raise _HttpRejection(
                    400, "INVALID_REQUEST", "/query/source_outcome_version_id"
                )
            value = port.find_own_appeal_by_source(
                actor=actor, source_outcome_version_id=values[0]
            )
            if value is None:
                raise _HttpRejection(404, "RESOURCE_NOT_FOUND")
            return _closed_projection(value, AppealOwnProjection)
        _exact_query(query, ())
        if route.operation == "READ_OWN_APPEAL":
            return _closed_projection(
                port.read_own_appeal(
                    actor=actor, appeal_id=path_parameters["appeal_id"]
                ),
                AppealOwnProjection,
            )
        if route.operation == "LIST_APPEAL_QUEUE":
            return _closed_projection(
                port.list_appeal_queue(actor=actor, limit=100),
                AppealQueueProjection,
            )
        if route.operation == "LIST_MY_ACTIVE_APPEAL_ASSIGNMENTS":
            return _closed_projection(
                port.list_my_active_appeal_assignments(actor=actor, limit=100),
                AppealActiveAssignmentsProjection,
            )
        if route.operation == "READ_ASSIGNED_APPEAL":
            return _closed_projection(
                port.read_assigned_appeal(
                    actor=actor, appeal_id=path_parameters["appeal_id"]
                ),
                AppealAssignedProjection,
            )
        if route.operation == "LIST_MY_COMPLETED_APPEAL_ASSIGNMENTS":
            return _closed_projection(
                port.list_my_completed_appeal_assignments(
                    actor=actor,
                    limit=100,
                ),
                AppealCompletedAssignmentsProjection,
            )
        if route.operation == "READ_MY_COMPLETED_APPEAL":
            return _closed_projection(
                port.read_my_completed_appeal(
                    actor=actor,
                    appeal_id=path_parameters["appeal_id"],
                ),
                AppealCompletedDetailProjection,
            )
        raise _HttpRejection(404, "RESOURCE_NOT_FOUND")

    def _command(
        self,
        *,
        route: _Route,
        path_parameters: Mapping[str, str],
        body: Mapping[str, Any],
        idempotency_key: str,
        expected_version: Optional[int],
    ) -> Any:
        operation = route.operation
        if operation == "OPEN_APPEAL":
            _exact_object(body, ("source_outcome_version_id",))
            return OpenAppealCommand(
                source_outcome_version_id=_uuid(
                    body["source_outcome_version_id"],
                    "source_outcome_version_id",
                ),
                idempotency_key=idempotency_key,
            )
        if expected_version is None:
            raise _HttpRejection(
                428, "PRECONDITION_REQUIRED", "/headers/If-Match"
            )
        appeal_id = path_parameters["appeal_id"]
        if operation == "SAVE_APPEAL_DRAFT":
            values = _parse_application(body)
            return SaveAppealDraftCommand(
                appeal_id=appeal_id,
                expected_appeal_version=expected_version,
                idempotency_key=idempotency_key,
                **values,
            )
        if operation == "SUBMIT_APPEAL":
            _exact_object(body, ("expected_draft_version",))
            return SubmitAppealCommand(
                appeal_id=appeal_id,
                expected_appeal_version=expected_version,
                expected_draft_version=_integer(
                    body["expected_draft_version"],
                    1,
                    2_147_483_647,
                    "expected_draft_version",
                ),
                idempotency_key=idempotency_key,
            )
        if operation == "CLAIM_APPEAL":
            _exact_object(body, ())
            return ClaimAppealCommand(
                appeal_id=appeal_id,
                expected_appeal_version=expected_version,
                idempotency_key=idempotency_key,
            )
        if operation == "RELEASE_APPEAL_ASSIGNMENT":
            _exact_object(body, ("reason_code",))
            reason = _enum(body["reason_code"], _RELEASE_REASONS, "reason_code")
            return ReleaseAppealAssignmentCommand(
                appeal_id=appeal_id,
                expected_appeal_version=expected_version,
                reason_code=AppealAssignmentReleaseReason(reason),
                idempotency_key=idempotency_key,
            )
        if operation == "SAVE_APPEAL_REVIEW_DRAFT":
            values = _parse_review(body)
            return SaveAppealReviewDraftCommand(
                appeal_id=appeal_id,
                expected_appeal_version=expected_version,
                idempotency_key=idempotency_key,
                **values,
            )
        if operation == "DECIDE_APPEAL":
            _exact_object(
                body, ("decision_code", "expected_review_draft_version")
            )
            return DecideAppealCommand(
                appeal_id=appeal_id,
                expected_appeal_version=expected_version,
                expected_review_draft_version=_integer(
                    body["expected_review_draft_version"],
                    1,
                    2_147_483_647,
                    "expected_review_draft_version",
                ),
                decision_code=AppealDecisionCode(
                    _enum(
                        body["decision_code"],
                        _DECISION_CODES,
                        "decision_code",
                    )
                ),
                idempotency_key=idempotency_key,
            )
        raise _HttpRejection(404, "RESOURCE_NOT_FOUND")


def _match_route(method: str, path: str) -> tuple[_Route, Mapping[str, str]]:
    for route in _ROUTES:
        match = route.expression.fullmatch(path)
        if match is not None and route.method == method:
            return route, match.groupdict()
    raise _HttpRejection(404, "RESOURCE_NOT_FOUND")


def _idempotency_key(headers: Mapping[str, str]) -> str:
    value = headers.get("idempotency-key")
    if not isinstance(value, str) or _IDEMPOTENCY_KEY.fullmatch(value) is None:
        raise _HttpRejection(
            400, "INVALID_IDEMPOTENCY_KEY", "/headers/Idempotency-Key"
        )
    return value


def _expected_version(headers: Mapping[str, str]) -> int:
    value = headers.get("if-match")
    if value is None:
        raise _HttpRejection(
            428, "PRECONDITION_REQUIRED", "/headers/If-Match"
        )
    match = _ENTITY_TAG.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise _HttpRejection(400, "INVALID_REQUEST", "/headers/If-Match")
    return int(match.group(1))


def _parse_application(body: Mapping[str, Any]) -> Mapping[str, Any]:
    _exact_object(
        body,
        (
            "applicant_statement",
            "grounds",
            "new_evidence_reference_ids",
            "requested_outcome",
        ),
    )
    statement = body["applicant_statement"]
    if not isinstance(statement, str) or not 1 <= len(statement) <= 4_000:
        raise _HttpRejection(
            422, "APPEAL_VALIDATION_FAILED", "/body/applicant_statement"
        )
    grounds = _closed_array(body["grounds"], _GROUNDS, 1, 3, "grounds")
    evidence = _uuid_array(
        body["new_evidence_reference_ids"],
        0,
        32,
        "new_evidence_reference_ids",
    )
    if "NEW_MATERIAL_EVIDENCE" in grounds and not evidence:
        raise _HttpRejection(
            422,
            "APPEAL_VALIDATION_FAILED",
            "/body/new_evidence_reference_ids",
        )
    return {
        "grounds": tuple(AppealGround(value) for value in grounds),
        "requested_outcome": RequestedAppealOutcome(
            _enum(
                body["requested_outcome"],
                _REQUESTED_OUTCOMES,
                "requested_outcome",
            )
        ),
        "applicant_statement": statement,
        "new_evidence_reference_ids": evidence,
    }


def _parse_review(body: Mapping[str, Any]) -> Mapping[str, Any]:
    _exact_object(
        body,
        ("assessments", "reason_codes", "remedy_delta_codes", "reviewer_note"),
    )
    raw_assessments = body["assessments"]
    if not isinstance(raw_assessments, list) or not 1 <= len(raw_assessments) <= 3:
        raise _HttpRejection(
            422, "APPEAL_VALIDATION_FAILED", "/body/assessments"
        )
    assessments = []
    for index, value in enumerate(raw_assessments):
        path = f"assessments/{index}"
        _exact_object(
            value,
            (
                "accepted_evidence_reference_ids",
                "assessment_code",
                "finding_codes",
                "ground",
            ),
        )
        assessments.append(
            AppealGroundAssessment(
                ground=AppealGround(
                    _enum(value["ground"], _GROUNDS, f"{path}/ground")
                ),
                assessment_code=AppealGroundAssessmentCode(
                    _enum(
                        value["assessment_code"],
                        _ASSESSMENT_CODES,
                        f"{path}/assessment_code",
                    )
                ),
                finding_codes=_closed_array(
                    value["finding_codes"],
                    _FINDING_CODES,
                    1,
                    32,
                    f"{path}/finding_codes",
                ),
                accepted_evidence_reference_ids=_uuid_array(
                    value["accepted_evidence_reference_ids"],
                    0,
                    32,
                    f"{path}/accepted_evidence_reference_ids",
                ),
            )
        )
    if len({value.ground for value in assessments}) != len(assessments):
        raise _HttpRejection(
            422, "APPEAL_VALIDATION_FAILED", "/body/assessments"
        )
    note = body["reviewer_note"]
    if not isinstance(note, str) or not 1 <= len(note) <= 4_000:
        raise _HttpRejection(
            422, "APPEAL_VALIDATION_FAILED", "/body/reviewer_note"
        )
    return {
        "assessments": tuple(assessments),
        "reason_codes": _closed_array(
            body["reason_codes"],
            _REVIEW_REASON_CODES,
            1,
            32,
            "reason_codes",
        ),
        "remedy_delta_codes": _closed_array(
            body["remedy_delta_codes"],
            _REMEDY_CODES,
            1,
            32,
            "remedy_delta_codes",
        ),
        "reviewer_note": note,
    }


def _exact_object(body: Any, required: Tuple[str, ...]) -> None:
    if not isinstance(body, Mapping) or set(body) != set(required):
        raise _HttpRejection(400, "INVALID_REQUEST", "/body")


def _exact_query(
    query: Mapping[str, Tuple[str, ...]], required: Tuple[str, ...]
) -> None:
    if not isinstance(query, Mapping) or set(query) != set(required):
        raise _HttpRejection(400, "INVALID_REQUEST", "/query")


def _enum(value: Any, allowed: frozenset[str], field_name: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise _HttpRejection(
            422, "APPEAL_VALIDATION_FAILED", f"/body/{field_name}"
        )
    return value


def _integer(value: Any, minimum: int, maximum: int, field_name: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise _HttpRejection(
            422, "APPEAL_VALIDATION_FAILED", f"/body/{field_name}"
        )
    return value


def _uuid(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or _UUID.fullmatch(value) is None:
        raise _HttpRejection(
            422, "APPEAL_VALIDATION_FAILED", f"/body/{field_name}"
        )
    return value


def _closed_array(
    value: Any,
    allowed: frozenset[str],
    minimum: int,
    maximum: int,
    field_name: str,
) -> Tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not minimum <= len(value) <= maximum
        or any(not isinstance(item, str) or item not in allowed for item in value)
        or len(set(value)) != len(value)
    ):
        raise _HttpRejection(
            422, "APPEAL_VALIDATION_FAILED", f"/body/{field_name}"
        )
    return tuple(value)


def _uuid_array(
    value: Any, minimum: int, maximum: int, field_name: str
) -> Tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not minimum <= len(value) <= maximum
        or any(not isinstance(item, str) or _UUID.fullmatch(item) is None for item in value)
        or len(set(value)) != len(value)
    ):
        raise _HttpRejection(
            422, "APPEAL_VALIDATION_FAILED", f"/body/{field_name}"
        )
    return tuple(value)


def _public_command_result(result: AppealCommandResult) -> Mapping[str, Any]:
    status = getattr(result.appeal_status, "value", None)
    completed = result.completed_at
    optional_versions = (
        result.application_draft_version,
        result.application_version,
        result.review_draft_version,
    )
    if (
        not isinstance(result.appeal_id, str)
        or _UUID.fullmatch(result.appeal_id) is None
        or status not in {"DRAFT", "SUBMITTED", "IN_REVIEW", "DECIDED", "WITHDRAWN"}
        or type(result.aggregate_version) is not int
        or result.aggregate_version < 1
        or any(
            value is not None and (type(value) is not int or value < 1)
            for value in optional_versions
        )
        or (
            result.decision_version_id is not None
            and (
                not isinstance(result.decision_version_id, str)
                or _UUID.fullmatch(result.decision_version_id) is None
            )
        )
        or type(result.replayed) is not bool
        or not isinstance(result.event_types, tuple)
        or len(result.event_types) != 1
        or result.event_types[0] not in _EVENT_TYPES
        or not isinstance(completed, datetime)
        or completed.tzinfo is None
        or completed.utcoffset() is None
    ):
        raise _HttpRejection(503, "SERVICE_UNAVAILABLE")
    return {
        "aggregate_version": result.aggregate_version,
        "appeal_id": result.appeal_id,
        "appeal_status": status,
        "application_draft_version": result.application_draft_version,
        "application_version": result.application_version,
        "completed_at": _timestamp(completed),
        "decision_version_id": result.decision_version_id,
        "event_types": list(result.event_types),
        "replayed": result.replayed,
        "review_draft_version": result.review_draft_version,
    }


def _closed_projection(value: Any, expected_type: type[Any]) -> Any:
    if type(value) is not expected_type:
        raise _HttpRejection(503, "SERVICE_UNAVAILABLE")
    try:
        names = tuple(expected_type.__dataclass_fields__)
        if set(vars(value)) != set(names):
            raise ValueError
        return expected_type(**{name: getattr(value, name) for name in names})
    except (AttributeError, TypeError, ValueError):
        raise _HttpRejection(503, "SERVICE_UNAVAILABLE") from None


def _projection_response(value: Any) -> AppealHttpResponse:
    if isinstance(value, AppealOwnProjection):
        entity_tag = value.entity_tag
        data = _own_json(value)
    elif isinstance(value, AppealQueueProjection):
        entity_tag = value.entity_tag
        data = _queue_json(value)
    elif isinstance(value, AppealActiveAssignmentsProjection):
        entity_tag = value.entity_tag
        data = _active_assignments_json(value)
    elif isinstance(value, AppealAssignedProjection):
        entity_tag = value.entity_tag
        data = _assigned_json(value)
    elif isinstance(value, AppealCompletedAssignmentsProjection):
        entity_tag = value.entity_tag
        data = _completed_assignments_json(value)
    elif isinstance(value, AppealCompletedDetailProjection):
        entity_tag = value.entity_tag
        data = _completed_detail_json(value)
    else:
        raise _HttpRejection(503, "SERVICE_UNAVAILABLE")
    if _ENTITY_TAG.fullmatch(entity_tag) is None:
        raise _HttpRejection(503, "SERVICE_UNAVAILABLE")
    return AppealHttpResponse(
        status=200,
        headers={"content-type": "application/json", "etag": entity_tag},
        json={"data": data},
    )


def _source_json(value: AppealSourceProjection) -> Mapping[str, Any]:
    value = _closed_projection(value, AppealSourceProjection)
    return {
        "action_codes": list(value.action_codes),
        "appeal_deadline": _timestamp(value.appeal_deadline),
        "appeal_eligibility_code": value.appeal_eligibility_code,
        "appeal_eligible": value.appeal_eligible,
        "case_id": value.case_id,
        "content_sha256": value.content_sha256,
        "decided_at": _timestamp(value.decided_at),
        "demand_id": value.demand_id,
        "demand_version_id": value.demand_version_id,
        "evidence_packet_sha256": value.evidence_packet_sha256,
        "evidence_packet_version_id": value.evidence_packet_version_id,
        "outcome_code": value.outcome_code,
        "outcome_version_id": value.outcome_version_id,
        "policy_version": value.policy_version,
        "reason_codes": list(value.reason_codes),
    }


def _application_draft_json(
    value: AppealApplicationDraftProjection,
) -> Mapping[str, Any]:
    value = _closed_projection(value, AppealApplicationDraftProjection)
    return {
        "edited_at": _timestamp(value.edited_at),
        "grounds": list(value.grounds),
        "new_evidence_reference_ids": list(value.new_evidence_reference_ids),
        "requested_outcome": value.requested_outcome,
        "statement_recorded": value.statement_recorded,
        "version": value.version,
    }


def _application_json(
    value: AppealSubmittedApplicationProjection,
) -> Mapping[str, Any]:
    value = _closed_projection(value, AppealSubmittedApplicationProjection)
    return {
        "grounds": list(value.grounds),
        "new_evidence_reference_ids": list(value.new_evidence_reference_ids),
        "requested_outcome": value.requested_outcome,
        "statement_recorded": value.statement_recorded,
        "submitted_at": _timestamp(value.submitted_at),
    }


def _assessment_json(value: AppealAssessmentProjection) -> Mapping[str, Any]:
    value = _closed_projection(value, AppealAssessmentProjection)
    return {
        "accepted_evidence_reference_ids": list(
            value.accepted_evidence_reference_ids
        ),
        "assessment_code": value.assessment_code,
        "finding_codes": list(value.finding_codes),
        "ground": value.ground,
    }


def _decision_json(value: AppealDecisionProjection) -> Mapping[str, Any]:
    value = _closed_projection(value, AppealDecisionProjection)
    return {
        "assessments": [_assessment_json(item) for item in value.assessments],
        "decided_at": _timestamp(value.decided_at),
        "decision_code": value.decision_code,
        "decision_sha256": value.decision_sha256,
        "decision_version_id": value.decision_version_id,
        "policy_version": value.policy_version,
        "reason_codes": list(value.reason_codes),
        "remedy_delta_codes": list(value.remedy_delta_codes),
    }


def _own_json(value: AppealOwnProjection) -> Mapping[str, Any]:
    value = _closed_projection(value, AppealOwnProjection)
    return {
        "aggregate_version": value.aggregate_version,
        "appeal_id": value.appeal_id,
        "application": (
            None if value.application is None else _application_json(value.application)
        ),
        "application_draft": (
            None
            if value.application_draft is None
            else _application_draft_json(value.application_draft)
        ),
        "decision": None if value.decision is None else _decision_json(value.decision),
        "entity_tag": value.entity_tag,
        "source": _source_json(value.source),
        "source_case_id": value.source_case_id,
        "source_outcome_version_id": value.source_outcome_version_id,
        "status": value.status,
    }


def _queue_item_json(value: AppealQueueItem) -> Mapping[str, Any]:
    value = _closed_projection(value, AppealQueueItem)
    return {
        "appeal_id": value.appeal_id,
        "entity_tag": value.entity_tag,
        "grounds": list(value.grounds),
        "requested_outcome": value.requested_outcome,
        "source_case_id": value.source_case_id,
        "source_outcome_version_id": value.source_outcome_version_id,
        "submitted_at": _timestamp(value.submitted_at),
    }


def _queue_json(value: AppealQueueProjection) -> Mapping[str, Any]:
    value = _closed_projection(value, AppealQueueProjection)
    return {
        "entity_tag": value.entity_tag,
        "items": [_queue_item_json(item) for item in value.items],
    }


def _active_assignment_json(
    value: AppealActiveAssignmentItem,
) -> Mapping[str, Any]:
    value = _closed_projection(value, AppealActiveAssignmentItem)
    return {
        "appeal_id": value.appeal_id,
        "assignment_expires_at": _timestamp(value.assignment_expires_at),
    }


def _active_assignments_json(
    value: AppealActiveAssignmentsProjection,
) -> Mapping[str, Any]:
    value = _closed_projection(value, AppealActiveAssignmentsProjection)
    return {
        "entity_tag": value.entity_tag,
        "items": [_active_assignment_json(item) for item in value.items],
    }


def _completed_assignment_json(
    value: AppealCompletedAssignmentItem,
) -> Mapping[str, Any]:
    value = _closed_projection(value, AppealCompletedAssignmentItem)
    return {
        "appeal_id": value.appeal_id,
        "decided_at": _timestamp(value.decided_at),
        "decision_code": value.decision_code,
    }


def _completed_assignments_json(
    value: AppealCompletedAssignmentsProjection,
) -> Mapping[str, Any]:
    value = _closed_projection(value, AppealCompletedAssignmentsProjection)
    return {
        "entity_tag": value.entity_tag,
        "has_more": value.has_more,
        "items": [_completed_assignment_json(item) for item in value.items],
    }


def _completed_detail_json(
    value: AppealCompletedDetailProjection,
) -> Mapping[str, Any]:
    value = _closed_projection(value, AppealCompletedDetailProjection)
    return {
        "appeal_id": value.appeal_id,
        "application": _application_json(value.application),
        "decision": _decision_json(value.decision),
        "entity_tag": value.entity_tag,
        "review_note_recorded": value.review_note_recorded,
        "status": value.status,
    }


def _review_draft_json(value: AppealReviewDraftProjection) -> Mapping[str, Any]:
    value = _closed_projection(value, AppealReviewDraftProjection)
    return {
        "assessments": [_assessment_json(item) for item in value.assessments],
        "edited_at": _timestamp(value.edited_at),
        "reason_codes": list(value.reason_codes),
        "remedy_delta_codes": list(value.remedy_delta_codes),
        "review_note_recorded": value.review_note_recorded,
        "version": value.version,
    }


def _assigned_json(value: AppealAssignedProjection) -> Mapping[str, Any]:
    value = _closed_projection(value, AppealAssignedProjection)
    return {
        "appeal": _own_json(value.appeal),
        "application": _application_json(value.application),
        "assignment_expires_at": _timestamp(value.assignment_expires_at),
        "entity_tag": value.entity_tag,
        "review_draft": (
            None
            if value.review_draft is None
            else _review_draft_json(value.review_draft)
        ),
        "source": _source_json(value.source),
    }


def _timestamp(value: datetime) -> str:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise _HttpRejection(503, "SERVICE_UNAVAILABLE")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _error(
    status: int, code: str, path: Optional[str] = None
) -> AppealHttpResponse:
    detail: dict[str, str] = {"code": code}
    if path is not None:
        detail["path"] = path
    return AppealHttpResponse(
        status=status,
        headers={"content-type": "application/json"},
        json={"error": detail},
    )


def _application_error(code: str) -> tuple[int, str]:
    if code in {"AUTHENTICATION_REQUIRED", "SESSION_EXPIRED"}:
        return 401, code
    if code == "POLICY_ACCEPTANCE_REQUIRED":
        return 403, code
    if code in {"ACCESS_DENIED", "APPEAL_NOT_FOUND"}:
        return 404, "RESOURCE_NOT_FOUND"
    if code == "APPEAL_NOT_AVAILABLE":
        return 404, code
    if code == "PRECONDITION_FAILED":
        return 412, "STALE_VERSION"
    if code in {
        "IDEMPOTENCY_KEY_REUSED",
        "COMMAND_IN_PROGRESS",
        "CONFLICT_OF_INTEREST",
    }:
        return 409, code
    if code in {
        "APPEAL_ALREADY_ASSIGNED",
        "APPEAL_ASSIGNMENT_INVALID",
        "APPEAL_ASSIGNMENT_NOT_EXPIRED",
        "APPEAL_ASSIGNMENT_RELEASE_INVALID",
        "APPEAL_ASSIGNMENT_REQUIRED",
    }:
        return 409, "ASSIGNMENT_UNAVAILABLE"
    if code in {
        "APPEAL_ALREADY_EXISTS",
        "APPEAL_APPLICATION_FROZEN",
        "APPEAL_DEADLINE_PASSED",
        "APPEAL_DRAFT_VERSION_CONFLICT",
        "APPEAL_STATE_CONFLICT",
    }:
        return 409, "APPEAL_STATE_CONFLICT"
    if code in {
        "INVALID_REQUEST",
        "APPEAL_APPLICATION_INVALID",
        "APPEAL_DECISION_INVALID",
        "APPEAL_REVIEW_INVALID",
    }:
        return 422, "APPEAL_VALIDATION_FAILED"
    if code in {"COMMAND_OUTCOME_UNKNOWN", "SERVICE_UNAVAILABLE"}:
        return 503, code
    return 503, "SERVICE_UNAVAILABLE"


__all__ = [
    "AppealHttpApplicationDispatcher",
    "AppealHttpPresenterBindings",
    "AppealHttpProjectionPort",
    "AppealHttpRequest",
    "AppealHttpResponse",
]
