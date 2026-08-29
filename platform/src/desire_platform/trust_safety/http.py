"""Closed HTTP presenter contracts for the Trust and Safety vertical.

This module is deliberately framework and storage agnostic.  It converts the
fifteen reviewed HTTP operations into the existing immutable application
commands, and it accepts only six explicitly safe read projections.  Command
results are projected field-by-field; the internal assignment identifier is
never part of the public receipt envelope.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import re
from typing import Any, Mapping, Protocol, Tuple
from uuid import UUID

from .application import (
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
from .domain import (
    AssignmentReleaseReason,
    HoldAction,
    HoldReason,
    ReportCategory,
    TrustCaseOutcome,
)


_UUID_TEXT = (
    r"(?!00000000-0000-0000-0000-000000000000)"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}"
)
_UUID = re.compile(rf"{_UUID_TEXT}\Z")
_ENTITY_TAG = re.compile(r'^"trust-([1-9][0-9]*)-([a-f0-9]{24})"$')
_IDEMPOTENCY_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~-]{15,127}\Z")
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_SEALED_NOTE_REFERENCE = re.compile(
    r"sealed://trust/[a-z0-9][a-z0-9/_-]{4,255}\Z"
)
_OWN_REPORT_CURSOR = re.compile(
    r"[A-Za-z0-9_-]{64,1024}\.[A-Za-z0-9_-]{43}\Z"
)

_REPORT_CATEGORIES = frozenset(item.value for item in ReportCategory)
_IMPACT_CODES = frozenset(
    (
        "PARTICIPANT_SAFETY_RISK",
        "RETALIATION_RISK",
        "SYNTHETIC_DATA_DISCLOSED",
        "SYNTHETIC_FINANCIAL_RISK",
        "WORKFLOW_INTEGRITY_RISK",
    )
)
_PROTECTION_CODES = frozenset(
    ("PAUSE_MATCHING", "PAUSE_SUBMISSION", "PAUSE_VERIFICATION")
)
_HOLD_ACTIONS = frozenset(item.value for item in HoldAction)
_HOLD_REASONS = frozenset(item.value for item in HoldReason)
_RELEASE_REASONS = frozenset(item.value for item in AssignmentReleaseReason)
_HOLD_RELEASE_REASONS = frozenset(
    ("CASE_DECIDED", "RISK_MITIGATED", "SUPERSEDED", "TTL_CORRECTION")
)
_PRIORITIES = frozenset(("P0", "P1", "P2", "P3"))
_JURISDICTIONS = frozenset(
    ("LEGAL_REVIEW_REQUIRED", "ORGANIZATION_POLICY", "PLATFORM_INTERNAL")
)
_SEVERITIES = frozenset(("CRITICAL", "HIGH", "LOW", "MEDIUM"))
_ISSUE_CODES = frozenset(
    (
        "DATA_HANDLING_GAP",
        "FRAUD_INDICATOR",
        "HARASSMENT_INDICATOR",
        "RETALIATION_INDICATOR",
        "SCOPE_DISCLOSURE_RISK",
        "WORKFLOW_INTEGRITY_GAP",
    )
)
_INVESTIGATION_CODES = frozenset(
    (
        "CHECK_ACCESS_SCOPE",
        "CHECK_DEMAND_VERSION",
        "CHECK_POLICY_REQUIREMENTS",
        "CHECK_SYNTHETIC_EVIDENCE",
        "REQUEST_PARTY_CLARIFICATION",
    )
)
_OUTCOMES = frozenset(item.value for item in TrustCaseOutcome)
_OUTCOME_REASONS = frozenset(
    (
        "INSUFFICIENT_VERIFIED_EVIDENCE",
        "NO_POLICY_BREACH",
        "POLICY_REQUIREMENT_NOT_MET",
        "PRECAUTIONARY_ACTION_REQUIRED",
        "RISK_MITIGATED",
    )
)
_CASE_STATUSES = frozenset(
    (
        "APPEAL_PENDING",
        "DECIDED",
        "DISMISSED",
        "IN_REVIEW",
        "OPEN",
        "RESOLVED",
        "TRIAGING",
    )
)
_EVENT_TYPES = frozenset(
    (
        "SafetyHoldPlaced",
        "SafetyHoldReleased",
        "TrustCaseAssignmentReleased",
        "TrustCaseClaimed",
        "TrustCaseOutcomePublished",
        "TrustHoldReleaseClaimed",
        "TrustReportSubmitted",
        "TrustTriageDraftSaved",
        "TrustTriagePublished",
    )
)


@dataclass(frozen=True)
class TrustHttpRequest:
    method: str
    path: str
    headers: Mapping[str, str] = field(repr=False)
    json: Mapping[str, Any] = field(repr=False)
    query: Mapping[str, Tuple[str, ...]] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.method, str)
            or not isinstance(self.path, str)
            or not isinstance(self.headers, Mapping)
            or not isinstance(self.json, Mapping)
            or not isinstance(self.query, Mapping)
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
            raise TypeError("Trust HTTP request is invalid")
        object.__setattr__(self, "headers", dict(self.headers))
        object.__setattr__(self, "json", deepcopy(dict(self.json)))
        object.__setattr__(
            self,
            "query",
            {name: tuple(values) for name, values in self.query.items()},
        )


@dataclass(frozen=True)
class TrustHttpResponse:
    status: int
    headers: Mapping[str, str]
    json: Mapping[str, Any] = field(repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", dict(self.headers))
        object.__setattr__(self, "json", deepcopy(dict(self.json)))


@dataclass(frozen=True, init=False)
class TrustHttpProjection:
    """Detached, schema-checked projection returned by the durable read port."""

    kind: str
    entity_tag: str
    _canonical_json: str = field(repr=False)

    def __init__(
        self,
        kind: str,
        data: Mapping[str, Any],
        entity_tag: str,
    ) -> None:
        if kind not in {
            "REPORT",
            "OWN_REPORT_LIST",
            "CASE",
            "CASE_QUEUE",
            "HOLD_RELEASE_QUEUE",
            "MY_ACTIVE_CASE_ASSIGNMENTS",
            "MY_COMPLETED_CASE_ASSIGNMENTS",
            "ASSIGNED_HOLD_RELEASE",
        }:
            raise ValueError("TRUST_HTTP_PROJECTION_INVALID")
        if not isinstance(data, Mapping) or _ENTITY_TAG.fullmatch(entity_tag) is None:
            raise ValueError("TRUST_HTTP_PROJECTION_INVALID")
        try:
            canonical = json.dumps(
                data,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            detached = json.loads(canonical)
            _validate_projection(kind, detached, entity_tag)
        except (TypeError, ValueError, UnicodeError):
            raise ValueError("TRUST_HTTP_PROJECTION_INVALID") from None
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "entity_tag", entity_tag)
        object.__setattr__(self, "_canonical_json", canonical)

    def as_json(self) -> dict[str, Any]:
        return json.loads(self._canonical_json)


class TrustHttpProjectionPort(Protocol):
    def list_own_reports(
        self,
        *,
        actor: TrustActorContext,
        limit: int,
        cursor: str | None,
    ) -> TrustHttpProjection: ...

    def read_own_report(
        self, *, actor: TrustActorContext, report_id: str
    ) -> TrustHttpProjection: ...

    def list_case_queue(
        self, *, actor: TrustActorContext, limit: int
    ) -> TrustHttpProjection: ...

    def list_hold_release_queue(
        self, *, actor: TrustActorContext, limit: int
    ) -> TrustHttpProjection: ...

    def list_my_active_case_assignments(
        self, *, actor: TrustActorContext, limit: int
    ) -> TrustHttpProjection: ...

    def list_my_completed_case_assignments(
        self, *, actor: TrustActorContext, limit: int
    ) -> TrustHttpProjection: ...

    def read_assigned_case(
        self, *, actor: TrustActorContext, case_id: str
    ) -> TrustHttpProjection: ...

    def read_assigned_hold_release(
        self, *, actor: TrustActorContext, hold_id: str
    ) -> TrustHttpProjection: ...


@dataclass(frozen=True)
class TrustHttpPresenterBindings:
    """The exact nine command handlers and eight-query projection capability."""

    submit_report: SubmitSafetyReportHandler
    claim_case: ClaimSafetyCaseHandler
    release_assignment: ReleaseSafetyCaseAssignmentHandler
    save_triage: SaveTrustTriageDraftHandler
    publish_triage: PublishTrustTriageHandler
    place_hold: PlaceSafetyHoldHandler
    claim_hold_release: ClaimSafetyHoldReleaseHandler
    release_hold: ReleaseSafetyHoldHandler
    publish_outcome: PublishTrustOutcomeHandler
    projections: TrustHttpProjectionPort

    def __post_init__(self) -> None:
        # The PostgreSQL wrappers import ``TrustHttpProjection`` from this
        # module, so keep this reverse edge local to instance validation.  The
        # union is deliberately field-specific: a generic command handler, or
        # a valid handler wired to the wrong operation, remains unavailable.
        from .adapters.postgres.production import (
            PostgresClaimSafetyCaseHandler,
            PostgresClaimSafetyHoldReleaseHandler,
            PostgresPlaceSafetyHoldHandler,
            PostgresPublishTrustOutcomeHandler,
            PostgresPublishTrustTriageHandler,
            PostgresReleaseSafetyCaseAssignmentHandler,
            PostgresReleaseSafetyHoldHandler,
            PostgresSaveTrustTriageDraftHandler,
            PostgresSubmitSafetyReportHandler,
        )

        expected = (
            (
                self.submit_report,
                SubmitSafetyReportHandler,
                PostgresSubmitSafetyReportHandler,
            ),
            (
                self.claim_case,
                ClaimSafetyCaseHandler,
                PostgresClaimSafetyCaseHandler,
            ),
            (
                self.release_assignment,
                ReleaseSafetyCaseAssignmentHandler,
                PostgresReleaseSafetyCaseAssignmentHandler,
            ),
            (
                self.save_triage,
                SaveTrustTriageDraftHandler,
                PostgresSaveTrustTriageDraftHandler,
            ),
            (
                self.publish_triage,
                PublishTrustTriageHandler,
                PostgresPublishTrustTriageHandler,
            ),
            (
                self.place_hold,
                PlaceSafetyHoldHandler,
                PostgresPlaceSafetyHoldHandler,
            ),
            (
                self.claim_hold_release,
                ClaimSafetyHoldReleaseHandler,
                PostgresClaimSafetyHoldReleaseHandler,
            ),
            (
                self.release_hold,
                ReleaseSafetyHoldHandler,
                PostgresReleaseSafetyHoldHandler,
            ),
            (
                self.publish_outcome,
                PublishTrustOutcomeHandler,
                PostgresPublishTrustOutcomeHandler,
            ),
        )
        if any(
            not (isinstance(value, application_kind) or type(value) is postgres_kind)
            for value, application_kind, postgres_kind in expected
        ):
            raise TypeError("Trust HTTP command handlers are unavailable")
        methods = (
            "list_own_reports",
            "read_own_report",
            "list_case_queue",
            "list_hold_release_queue",
            "list_my_active_case_assignments",
            "list_my_completed_case_assignments",
            "read_assigned_case",
            "read_assigned_hold_release",
        )
        if any(not callable(getattr(self.projections, name, None)) for name in methods):
            raise TypeError("Trust HTTP projection port is unavailable")


@dataclass(frozen=True)
class _Route:
    method: str
    expression: re.Pattern[str]
    operation: str
    handler_name: str | None
    success_status: int
    requires_if_match: bool


_ROUTES = (
    _Route("POST", re.compile(r"^/v1/app/trust/reports$"), "SUBMIT_REPORT", "submit_report", 201, False),
    _Route("GET", re.compile(r"^/v1/app/trust/reports$"), "LIST_OWN_REPORTS", None, 200, False),
    _Route("GET", re.compile(rf"^/v1/app/trust/reports/(?P<report_id>{_UUID_TEXT})$"), "READ_OWN_REPORT", None, 200, False),
    _Route("GET", re.compile(r"^/v1/app/trust/queue$"), "LIST_CASE_QUEUE", None, 200, False),
    _Route("POST", re.compile(rf"^/v1/app/trust/queue/(?P<case_id>{_UUID_TEXT})/claim$"), "CLAIM_CASE", "claim_case", 201, True),
    _Route("GET", re.compile(r"^/v1/app/trust/hold-release-queue$"), "LIST_HOLD_RELEASE_QUEUE", None, 200, False),
    _Route("GET", re.compile(r"^/v1/app/trust/assignments$"), "LIST_MY_ACTIVE_CASE_ASSIGNMENTS", None, 200, False),
    _Route("GET", re.compile(r"^/v1/app/trust/history$"), "LIST_MY_COMPLETED_CASE_ASSIGNMENTS", None, 200, False),
    _Route("POST", re.compile(rf"^/v1/app/trust/hold-release-queue/(?P<hold_id>{_UUID_TEXT})/claim$"), "CLAIM_HOLD_RELEASE", "claim_hold_release", 201, True),
    _Route("GET", re.compile(rf"^/v1/app/trust/assigned-holds/(?P<hold_id>{_UUID_TEXT})$"), "READ_ASSIGNED_HOLD_RELEASE", None, 200, False),
    _Route("GET", re.compile(rf"^/v1/app/trust/cases/(?P<case_id>{_UUID_TEXT})$"), "READ_ASSIGNED_CASE", None, 200, False),
    _Route("POST", re.compile(rf"^/v1/app/trust/cases/(?P<case_id>{_UUID_TEXT})/assignment/release$"), "RELEASE_CASE_ASSIGNMENT", "release_assignment", 200, True),
    _Route("PUT", re.compile(rf"^/v1/app/trust/cases/(?P<case_id>{_UUID_TEXT})/triage-draft$"), "SAVE_TRIAGE_DRAFT", "save_triage", 200, True),
    _Route("POST", re.compile(rf"^/v1/app/trust/cases/(?P<case_id>{_UUID_TEXT})/triage-publish$"), "PUBLISH_TRIAGE", "publish_triage", 200, True),
    _Route("POST", re.compile(rf"^/v1/app/trust/cases/(?P<case_id>{_UUID_TEXT})/holds$"), "PLACE_HOLD", "place_hold", 201, True),
    _Route("POST", re.compile(rf"^/v1/app/trust/holds/(?P<hold_id>{_UUID_TEXT})/release$"), "RELEASE_HOLD", "release_hold", 200, True),
    _Route("POST", re.compile(rf"^/v1/app/trust/cases/(?P<case_id>{_UUID_TEXT})/decisions$"), "PUBLISH_OUTCOME", "publish_outcome", 201, True),
)


class _HttpRejection(Exception):
    def __init__(self, status: int, code: str, path: str | None = None) -> None:
        self.status = status
        self.code = code
        self.path = path
        super().__init__(code)


class TrustHttpApplicationDispatcher:
    """Parse one normalized request and invoke exactly one reviewed capability."""

    def __init__(self, *, bindings: TrustHttpPresenterBindings) -> None:
        if not isinstance(bindings, TrustHttpPresenterBindings):
            raise TypeError("Trust HTTP presenter bindings are unavailable")
        self._bindings = bindings

    def handle(
        self,
        *,
        request: TrustHttpRequest,
        actor: TrustActorContext,
    ) -> TrustHttpResponse:
        if not isinstance(request, TrustHttpRequest) or not isinstance(
            actor, TrustActorContext
        ):
            return _error(400, "INVALID_REQUEST")
        try:
            route, path_parameters = _match_route(request.method, request.path)
            if route.handler_name is None:
                projection = self._read(
                    route=route,
                    path_parameters=path_parameters,
                    actor=actor,
                    body=request.json,
                    query=request.query,
                )
                return _projection_response(route.success_status, projection)
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
                actor=actor,
                idempotency_key=idempotency_key,
                expected_version=expected_version,
            )
            handler = getattr(self._bindings, route.handler_name)
            result = handler.handle(actor=actor, command=command)
            if not isinstance(result, TrustCommandResult):
                raise _HttpRejection(503, "SERVICE_UNAVAILABLE")
            return TrustHttpResponse(
                status=route.success_status,
                headers={"content-type": "application/json"},
                json={"data": _public_command_result(result)},
            )
        except _HttpRejection as error:
            return _error(error.status, error.code, error.path)
        except TrustApplicationError as error:
            status, code = _application_error(error.code)
            return _error(status, code)
        except Exception:
            return _error(503, "SERVICE_UNAVAILABLE")

    def _read(
        self,
        *,
        route: _Route,
        path_parameters: Mapping[str, str],
        actor: TrustActorContext,
        body: Mapping[str, Any],
        query: Mapping[str, Tuple[str, ...]],
    ) -> TrustHttpProjection:
        _exact_object(body, ())
        port = self._bindings.projections
        if route.operation == "LIST_OWN_REPORTS":
            limit, cursor = _owned_report_page_query(query)
            value = port.list_own_reports(
                actor=actor,
                limit=limit,
                cursor=cursor,
            )
            return _expect_projection(value, "OWN_REPORT_LIST")
        _exact_query(query, ())
        if route.operation == "READ_OWN_REPORT":
            value = port.read_own_report(
                actor=actor, report_id=path_parameters["report_id"]
            )
            return _expect_projection(value, "REPORT")
        if route.operation == "LIST_CASE_QUEUE":
            value = port.list_case_queue(actor=actor, limit=100)
            return _expect_projection(value, "CASE_QUEUE")
        if route.operation == "LIST_HOLD_RELEASE_QUEUE":
            value = port.list_hold_release_queue(actor=actor, limit=100)
            return _expect_projection(value, "HOLD_RELEASE_QUEUE")
        if route.operation == "LIST_MY_ACTIVE_CASE_ASSIGNMENTS":
            value = port.list_my_active_case_assignments(actor=actor, limit=100)
            return _expect_projection(value, "MY_ACTIVE_CASE_ASSIGNMENTS")
        if route.operation == "LIST_MY_COMPLETED_CASE_ASSIGNMENTS":
            value = port.list_my_completed_case_assignments(actor=actor, limit=100)
            return _expect_projection(value, "MY_COMPLETED_CASE_ASSIGNMENTS")
        if route.operation == "READ_ASSIGNED_CASE":
            value = port.read_assigned_case(
                actor=actor, case_id=path_parameters["case_id"]
            )
            return _expect_projection(value, "CASE")
        if route.operation == "READ_ASSIGNED_HOLD_RELEASE":
            value = port.read_assigned_hold_release(
                actor=actor, hold_id=path_parameters["hold_id"]
            )
            return _expect_projection(value, "ASSIGNED_HOLD_RELEASE")
        raise _HttpRejection(404, "RESOURCE_NOT_FOUND")

    def _command(
        self,
        *,
        route: _Route,
        path_parameters: Mapping[str, str],
        body: Mapping[str, Any],
        actor: TrustActorContext,
        idempotency_key: str,
        expected_version: int | None,
    ) -> Any:
        operation = route.operation
        if operation == "SUBMIT_REPORT":
            values = _parse_report(body)
            return SubmitSafetyReportCommand(
                **values, idempotency_key=idempotency_key
            )
        if expected_version is None:
            raise _HttpRejection(428, "PRECONDITION_REQUIRED", "/headers/If-Match")
        if operation == "CLAIM_CASE":
            _exact_object(body, ())
            return ClaimSafetyCaseCommand(
                case_id=path_parameters["case_id"],
                expected_case_version=expected_version,
                idempotency_key=idempotency_key,
            )
        if operation == "CLAIM_HOLD_RELEASE":
            _exact_object(body, ())
            return ClaimSafetyHoldReleaseCommand(
                hold_id=path_parameters["hold_id"],
                expected_hold_version=expected_version,
                idempotency_key=idempotency_key,
            )
        if operation == "RELEASE_CASE_ASSIGNMENT":
            _exact_object(body, ("reason_code",))
            reason = _enum(body["reason_code"], _RELEASE_REASONS, "reason_code")
            return ReleaseSafetyCaseAssignmentCommand(
                case_id=path_parameters["case_id"],
                expected_case_version=expected_version,
                reason_code=AssignmentReleaseReason(reason),
                idempotency_key=idempotency_key,
            )
        if operation == "SAVE_TRIAGE_DRAFT":
            values = _parse_triage(body)
            return SaveTrustTriageDraftCommand(
                case_id=path_parameters["case_id"],
                expected_case_version=expected_version,
                idempotency_key=idempotency_key,
                **values,
            )
        if operation == "PUBLISH_TRIAGE":
            _exact_object(body, ("expected_draft_version",))
            return PublishTrustTriageCommand(
                case_id=path_parameters["case_id"],
                expected_case_version=expected_version,
                expected_draft_version=_integer(
                    body["expected_draft_version"],
                    1,
                    2_147_483_647,
                    "expected_draft_version",
                ),
                idempotency_key=idempotency_key,
            )
        if operation == "PLACE_HOLD":
            _exact_object(body, ("action_codes", "reason_code", "ttl_minutes"))
            return PlaceSafetyHoldCommand(
                case_id=path_parameters["case_id"],
                expected_case_version=expected_version,
                action_codes=tuple(
                    HoldAction(value)
                    for value in _closed_array(
                        body["action_codes"], _HOLD_ACTIONS, 1, 3, "action_codes"
                    )
                ),
                reason_code=HoldReason(
                    _enum(body["reason_code"], _HOLD_REASONS, "reason_code")
                ),
                hold_ttl_minutes=_integer(
                    body["ttl_minutes"], 15, 10_080, "ttl_minutes"
                ),
                idempotency_key=idempotency_key,
            )
        if operation == "RELEASE_HOLD":
            _exact_object(body, ("reason_code",))
            return ReleaseSafetyHoldCommand(
                hold_id=path_parameters["hold_id"],
                expected_hold_version=expected_version,
                release_reason_code=_enum(
                    body["reason_code"], _HOLD_RELEASE_REASONS, "reason_code"
                ),
                idempotency_key=idempotency_key,
            )
        if operation == "PUBLISH_OUTCOME":
            _exact_object(body, ("action_codes", "outcome_code", "reason_codes"))
            return PublishTrustOutcomeCommand(
                case_id=path_parameters["case_id"],
                expected_case_version=expected_version,
                outcome_code=TrustCaseOutcome(
                    _enum(body["outcome_code"], _OUTCOMES, "outcome_code")
                ),
                reason_codes=_closed_array(
                    body["reason_codes"], _OUTCOME_REASONS, 1, 8, "reason_codes"
                ),
                action_codes=tuple(
                    HoldAction(value)
                    for value in _closed_array(
                        body["action_codes"], _HOLD_ACTIONS, 0, 3, "action_codes"
                    )
                ),
                idempotency_key=idempotency_key,
            )
        raise _HttpRejection(404, "RESOURCE_NOT_FOUND")


def _match_route(method: str, path: str) -> tuple[_Route, Mapping[str, str]]:
    for route in _ROUTES:
        match = route.expression.fullmatch(path)
        if match is not None and method == route.method:
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
        raise _HttpRejection(428, "PRECONDITION_REQUIRED", "/headers/If-Match")
    match = _ENTITY_TAG.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise _HttpRejection(400, "INVALID_REQUEST", "/headers/If-Match")
    return int(match.group(1))


def _parse_report(body: Mapping[str, Any]) -> Mapping[str, Any]:
    fields = (
        "category",
        "demand_id",
        "demand_version_id",
        "evidence_reference_ids",
        "impact_codes",
        "incident_ended_at",
        "incident_started_at",
        "requested_protection_codes",
    )
    _exact_object(body, fields)
    ended = body["incident_ended_at"]
    return {
        "demand_id": _uuid(body["demand_id"], "demand_id"),
        "demand_version_id": _uuid(
            body["demand_version_id"], "demand_version_id"
        ),
        "category": ReportCategory(
            _enum(body["category"], _REPORT_CATEGORIES, "category")
        ),
        "incident_started_at": _timestamp(
            body["incident_started_at"], "incident_started_at"
        ),
        "incident_ended_at": (
            None if ended is None else _timestamp(ended, "incident_ended_at")
        ),
        "impact_codes": _closed_array(
            body["impact_codes"], _IMPACT_CODES, 1, 16, "impact_codes"
        ),
        "evidence_reference_ids": _uuid_array(
            body["evidence_reference_ids"], 1, 32, "evidence_reference_ids"
        ),
        "requested_protection_codes": _closed_array(
            body["requested_protection_codes"],
            _PROTECTION_CODES,
            1,
            3,
            "requested_protection_codes",
        ),
    }


def _parse_triage(body: Mapping[str, Any]) -> Mapping[str, Any]:
    fields = (
        "investigation_step_codes",
        "issue_codes",
        "jurisdiction_code",
        "priority_code",
        "proposed_hold_actions",
        "proposed_hold_ttl_minutes",
        "restricted_note",
        "severity_code",
    )
    _exact_object(body, fields)
    note = body["restricted_note"]
    if not isinstance(note, str) or not 1 <= len(note) <= 4_000:
        raise _HttpRejection(422, "TRUST_VALIDATION_FAILED", "/body/restricted_note")
    return {
        "priority_code": _enum(body["priority_code"], _PRIORITIES, "priority_code"),
        "jurisdiction_code": _enum(
            body["jurisdiction_code"], _JURISDICTIONS, "jurisdiction_code"
        ),
        "severity_code": _enum(body["severity_code"], _SEVERITIES, "severity_code"),
        "issue_codes": _closed_array(
            body["issue_codes"], _ISSUE_CODES, 1, 16, "issue_codes"
        ),
        "investigation_step_codes": _closed_array(
            body["investigation_step_codes"],
            _INVESTIGATION_CODES,
            1,
            16,
            "investigation_step_codes",
        ),
        "proposed_hold_actions": tuple(
            HoldAction(value)
            for value in _closed_array(
                body["proposed_hold_actions"],
                _HOLD_ACTIONS,
                1,
                3,
                "proposed_hold_actions",
            )
        ),
        "proposed_hold_ttl_minutes": _integer(
            body["proposed_hold_ttl_minutes"],
            15,
            10_080,
            "proposed_hold_ttl_minutes",
        ),
        "restricted_note": note,
    }


def _exact_object(body: Mapping[str, Any], required: Tuple[str, ...]) -> None:
    if not isinstance(body, Mapping) or set(body) != set(required):
        raise _HttpRejection(400, "INVALID_REQUEST", "/body")


def _exact_query(
    query: Mapping[str, Tuple[str, ...]], allowed: Tuple[str, ...]
) -> None:
    if not isinstance(query, Mapping) or set(query) != set(allowed):
        raise _HttpRejection(400, "INVALID_REQUEST", "/query")


def _owned_report_page_query(
    query: Mapping[str, Tuple[str, ...]],
) -> tuple[int, str | None]:
    if not isinstance(query, Mapping) or not set(query).issubset({"cursor", "limit"}):
        raise _HttpRejection(400, "INVALID_REQUEST", "/query")
    if any(not isinstance(values, tuple) or len(values) != 1 for values in query.values()):
        raise _HttpRejection(400, "INVALID_REQUEST", "/query")
    raw_limit = query.get("limit", ("20",))[0]
    if re.fullmatch(r"(?:[1-9]|[1-9][0-9]|100)", raw_limit) is None:
        raise _HttpRejection(400, "INVALID_REQUEST", "/query/limit")
    cursor = query.get("cursor", (None,))[0]
    if cursor is not None and _OWN_REPORT_CURSOR.fullmatch(cursor) is None:
        raise _HttpRejection(400, "INVALID_REQUEST", "/query/cursor")
    return int(raw_limit), cursor


def _enum(value: Any, allowed: frozenset[str], field_name: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise _HttpRejection(
            422, "TRUST_VALIDATION_FAILED", f"/body/{field_name}"
        )
    return value


def _integer(value: Any, minimum: int, maximum: int, field_name: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise _HttpRejection(
            422, "TRUST_VALIDATION_FAILED", f"/body/{field_name}"
        )
    return value


def _uuid(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or _UUID.fullmatch(value) is None:
        raise _HttpRejection(
            422, "TRUST_VALIDATION_FAILED", f"/body/{field_name}"
        )
    return value


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
            422, "TRUST_VALIDATION_FAILED", f"/body/{field_name}"
        )
    return tuple(sorted(value))


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
        or any(not isinstance(item, str) for item in value)
        or len(set(value)) != len(value)
        or any(item not in allowed for item in value)
    ):
        raise _HttpRejection(
            422, "TRUST_VALIDATION_FAILED", f"/body/{field_name}"
        )
    return tuple(sorted(value))


def _timestamp(value: Any, field_name: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise _HttpRejection(
            422, "TRUST_VALIDATION_FAILED", f"/body/{field_name}"
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise _HttpRejection(
            422, "TRUST_VALIDATION_FAILED", f"/body/{field_name}"
        ) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise _HttpRejection(
            422, "TRUST_VALIDATION_FAILED", f"/body/{field_name}"
        )
    return parsed.astimezone(timezone.utc)


def _public_command_result(result: TrustCommandResult) -> Mapping[str, Any]:
    completed = result.completed_at
    optional_ids = (result.hold_id, result.outcome_version_id, result.report_id)
    optional_versions = (
        result.hold_version,
        result.triage_draft_version,
        result.triage_version,
    )
    if (
        not isinstance(result.case_id, str)
        or _UUID.fullmatch(result.case_id) is None
        or type(result.aggregate_version) is not int
        or result.aggregate_version < 1
        or getattr(result.case_status, "value", None) not in _CASE_STATUSES
        or any(
            value is not None
            and (not isinstance(value, str) or _UUID.fullmatch(value) is None)
            for value in optional_ids
        )
        or any(
            value is not None and (type(value) is not int or value < 1)
            for value in optional_versions
        )
        or type(result.replayed) is not bool
        or not isinstance(result.event_types, tuple)
        or len(result.event_types) != 1
        or result.event_types[0] not in _EVENT_TYPES
        or completed.tzinfo is None
        or completed.utcoffset() is None
    ):
        raise _HttpRejection(503, "SERVICE_UNAVAILABLE")
    return {
        "aggregate_version": result.aggregate_version,
        "case_id": result.case_id,
        "case_status": result.case_status.value,
        "completed_at": completed.astimezone(timezone.utc).isoformat().replace(
            "+00:00", "Z"
        ),
        "event_types": list(result.event_types),
        "hold_id": result.hold_id,
        "hold_version": result.hold_version,
        "outcome_version_id": result.outcome_version_id,
        "report_id": result.report_id,
        "replayed": result.replayed,
        "triage_draft_version": result.triage_draft_version,
        "triage_version": result.triage_version,
    }


def _expect_projection(value: Any, kind: str) -> TrustHttpProjection:
    if not isinstance(value, TrustHttpProjection) or value.kind != kind:
        raise _HttpRejection(503, "SERVICE_UNAVAILABLE")
    return value


def _projection_response(status: int, projection: TrustHttpProjection) -> TrustHttpResponse:
    return TrustHttpResponse(
        status=status,
        headers={"content-type": "application/json", "etag": projection.entity_tag},
        json={"data": projection.as_json()},
    )


def _error(status: int, code: str, path: str | None = None) -> TrustHttpResponse:
    detail: dict[str, Any] = {"code": code}
    if path is not None:
        detail["path"] = path
    return TrustHttpResponse(
        status=status,
        headers={"content-type": "application/json"},
        json={"error": detail},
    )


def _application_error(code: str) -> tuple[int, str]:
    if code == "INVALID_CURSOR":
        return 400, "INVALID_REQUEST"
    if code in {"AUTHENTICATION_REQUIRED", "SESSION_EXPIRED"}:
        return 401, code
    if code in {
        "ACCESS_DENIED",
        "POLICY_ACCEPTANCE_REQUIRED",
        "RESOURCE_NOT_FOUND",
        "HOLD_NOT_FOUND",
    }:
        return 404, "RESOURCE_NOT_FOUND"
    if code in {"PRECONDITION_FAILED", "TRIAGE_VERSION_CONFLICT"}:
        return 412, "STALE_VERSION"
    if code == "IDEMPOTENCY_KEY_REUSED":
        return 409, code
    if code == "CONFLICT_OF_INTEREST":
        return 409, code
    if code in {
        "CASE_ALREADY_ASSIGNED",
        "CASE_ASSIGNMENT_INVALID",
        "CASE_ASSIGNMENT_REQUIRED",
        "CASE_STATE_CONFLICT",
        "HOLD_RELEASE_ALREADY_ASSIGNED",
        "HOLD_RELEASE_ASSIGNMENT_INVALID",
        "HOLD_STATE_CONFLICT",
        "INDEPENDENT_REVIEW_REQUIRED",
        "ASSIGNMENT_NOT_EXPIRED",
        "TRIAGE_ALREADY_PUBLISHED",
    }:
        return 409, "ASSIGNMENT_UNAVAILABLE"
    if code == "COMMAND_OUTCOME_UNKNOWN":
        return 503, code
    if code == "SERVICE_UNAVAILABLE":
        return 503, code
    if code in {
        "INVALID_REQUEST",
        "IDENTIFIER_INVALID",
        "TIME_INVALID",
        "REPORT_VALIDATION_FAILED",
        "TRIAGE_VALIDATION_FAILED",
        "HOLD_VALIDATION_FAILED",
        "HOLD_RELEASE_VALIDATION_FAILED",
        "ASSIGNMENT_RELEASE_VALIDATION_FAILED",
        "CASE_DECISION_VALIDATION_FAILED",
    }:
        return 422, "TRUST_VALIDATION_FAILED"
    return 503, "SERVICE_UNAVAILABLE"


def _validate_projection(kind: str, data: Any, entity_tag: str) -> None:
    if not isinstance(data, dict) or data.get("entity_tag") != entity_tag:
        raise ValueError
    if kind == "REPORT":
        _projection_report(data)
    elif kind == "OWN_REPORT_LIST":
        _projection_own_report_list(data)
    elif kind == "CASE_QUEUE":
        _projection_queue(data)
    elif kind == "HOLD_RELEASE_QUEUE":
        _projection_hold_queue(data)
    elif kind == "MY_ACTIVE_CASE_ASSIGNMENTS":
        _projection_active_assignments(data)
    elif kind == "MY_COMPLETED_CASE_ASSIGNMENTS":
        _projection_completed_assignments(data)
    elif kind == "ASSIGNED_HOLD_RELEASE":
        _projection_assigned_hold_release(data)
    elif kind == "CASE":
        _projection_case(data)
    else:
        raise ValueError


def _keys(value: Any, expected: Tuple[str, ...]) -> None:
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError


def _safe_uuid(value: Any) -> None:
    if not isinstance(value, str) or _UUID.fullmatch(value) is None:
        raise ValueError


def _safe_text(value: Any, allowed: frozenset[str]) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError


def _safe_timestamp(value: Any, *, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    if not isinstance(value, str):
        raise ValueError
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError


def _utc_timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError from None
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError
    return parsed.astimezone(timezone.utc)


def _safe_array(
    value: Any, allowed: frozenset[str], minimum: int, maximum: int
) -> None:
    if (
        not isinstance(value, list)
        or not minimum <= len(value) <= maximum
        or any(not isinstance(item, str) for item in value)
        or len(set(value)) != len(value)
        or any(item not in allowed for item in value)
    ):
        raise ValueError


def _report_summary(value: Any) -> None:
    _keys(
        value,
        (
            "category",
            "evidence_reference_ids",
            "impact_codes",
            "incident_ended_at",
            "incident_started_at",
            "requested_protection_codes",
        ),
    )
    _safe_text(value["category"], _REPORT_CATEGORIES)
    if (
        not isinstance(value["evidence_reference_ids"], list)
        or not 1 <= len(value["evidence_reference_ids"]) <= 32
        or len(set(value["evidence_reference_ids"]))
        != len(value["evidence_reference_ids"])
    ):
        raise ValueError
    for identifier in value["evidence_reference_ids"]:
        _safe_uuid(identifier)
    _safe_array(value["impact_codes"], _IMPACT_CODES, 1, 16)
    _safe_timestamp(value["incident_started_at"])
    _safe_timestamp(value["incident_ended_at"], nullable=True)
    _safe_array(value["requested_protection_codes"], _PROTECTION_CODES, 1, 3)


def _projection_report(value: dict[str, Any]) -> None:
    _keys(
        value,
        (
            "demand_id",
            "demand_version_id",
            "entity_tag",
            "outcome",
            "report",
            "report_id",
            "status",
            "submitted_at",
        ),
    )
    for field_name in ("demand_id", "demand_version_id", "report_id"):
        _safe_uuid(value[field_name])
    _safe_text(value["status"], frozenset(("DECIDED", "IN_REVIEW", "OPEN", "TRIAGING")))
    _safe_timestamp(value["submitted_at"])
    _report_summary(value["report"])
    if value["outcome"] is not None:
        _outcome_projection(value["outcome"])


def _projection_own_report_list(value: dict[str, Any]) -> None:
    _keys(value, ("entity_tag", "items", "next_cursor"))
    items = value["items"]
    if not isinstance(items, list) or len(items) > 100:
        raise ValueError
    if value["next_cursor"] is not None and (
        not isinstance(value["next_cursor"], str)
        or _OWN_REPORT_CURSOR.fullmatch(value["next_cursor"]) is None
        or not items
    ):
        raise ValueError
    seen: set[str] = set()
    previous: tuple[datetime, str] | None = None
    for item in items:
        _keys(
            item,
            (
                "category",
                "demand_id",
                "outcome",
                "report_id",
                "status",
                "submitted_at",
            ),
        )
        _safe_uuid(item["demand_id"])
        _safe_uuid(item["report_id"])
        if item["report_id"] in seen:
            raise ValueError
        seen.add(item["report_id"])
        _safe_text(item["category"], _REPORT_CATEGORIES)
        _safe_text(
            item["status"],
            frozenset(("DECIDED", "IN_REVIEW", "OPEN", "TRIAGING")),
        )
        submitted_at = _utc_timestamp(item["submitted_at"])
        order_key = (submitted_at, item["report_id"])
        if previous is not None and not (
            order_key[0] < previous[0]
            or (order_key[0] == previous[0] and order_key[1] > previous[1])
        ):
            raise ValueError
        previous = order_key
        outcome = item["outcome"]
        if outcome is None:
            if item["status"] == "DECIDED":
                raise ValueError
            continue
        _keys(
            outcome,
            (
                "appeal_deadline",
                "appeal_eligibility_code",
                "decided_at",
                "outcome_code",
                "outcome_version_id",
            ),
        )
        _safe_timestamp(outcome["appeal_deadline"], nullable=True)
        _safe_text(
            outcome["appeal_eligibility_code"],
            frozenset(("ELIGIBLE", "NOT_ELIGIBLE")),
        )
        _safe_timestamp(outcome["decided_at"])
        _safe_text(outcome["outcome_code"], _OUTCOMES)
        _safe_uuid(outcome["outcome_version_id"])
        if (
            item["status"] != "DECIDED"
            or (
                outcome["appeal_eligibility_code"] == "ELIGIBLE"
            ) != (outcome["appeal_deadline"] is not None)
        ):
            raise ValueError


def _projection_queue(value: dict[str, Any]) -> None:
    _keys(value, ("entity_tag", "items"))
    items = value["items"]
    if not isinstance(items, list) or len(items) > 100:
        raise ValueError
    for item in items:
        _keys(
            item,
            (
                "category",
                "case_id",
                "demand_id",
                "demand_version_id",
                "entity_tag",
                "impact_codes",
                "report_id",
                "submitted_at",
            ),
        )
        _safe_text(item["category"], _REPORT_CATEGORIES)
        for field_name in ("case_id", "demand_id", "demand_version_id", "report_id"):
            _safe_uuid(item[field_name])
        if _ENTITY_TAG.fullmatch(item["entity_tag"]) is None:
            raise ValueError
        _safe_array(item["impact_codes"], _IMPACT_CODES, 1, 16)
        _safe_timestamp(item["submitted_at"])


def _projection_hold_queue(value: dict[str, Any]) -> None:
    _keys(value, ("entity_tag", "items"))
    items = value["items"]
    if not isinstance(items, list) or len(items) > 100:
        raise ValueError
    for item in items:
        _keys(
            item,
            (
                "action_codes",
                "case_id",
                "demand_id",
                "demand_version_id",
                "entity_tag",
                "expires_at",
                "hold_id",
                "reason_code",
            ),
        )
        _safe_array(item["action_codes"], _HOLD_ACTIONS, 1, 3)
        for field_name in ("case_id", "demand_id", "demand_version_id", "hold_id"):
            _safe_uuid(item[field_name])
        if _ENTITY_TAG.fullmatch(item["entity_tag"]) is None:
            raise ValueError
        _safe_timestamp(item["expires_at"])
        _safe_text(
            item["reason_code"],
            frozenset(("PARTICIPANT_SAFETY_RISK", "RETALIATION_RISK")),
        )


def _projection_active_assignments(value: dict[str, Any]) -> None:
    _keys(value, ("entity_tag", "items"))
    items = value["items"]
    if not isinstance(items, list) or len(items) > 100:
        raise ValueError
    assignment_keys: set[tuple[str, str, str | None]] = set()
    for item in items:
        _keys(
            item,
            (
                "assignment_expires_at",
                "assignment_purpose",
                "case_id",
                "hold_id",
            ),
        )
        _safe_uuid(item["case_id"])
        _safe_text(
            item["assignment_purpose"],
            frozenset(("CASE_TRIAGE", "HOLD_RELEASE")),
        )
        purpose = item["assignment_purpose"]
        hold_id = item["hold_id"]
        if purpose == "CASE_TRIAGE":
            if hold_id is not None:
                raise ValueError
        else:
            _safe_uuid(hold_id)
        assignment_key = (item["case_id"], purpose, hold_id)
        if assignment_key in assignment_keys:
            raise ValueError
        assignment_keys.add(assignment_key)
        _safe_timestamp(item["assignment_expires_at"])


def _projection_completed_assignments(value: dict[str, Any]) -> None:
    _keys(value, ("entity_tag", "has_more", "items"))
    if type(value["has_more"]) is not bool:
        raise ValueError
    items = value["items"]
    if not isinstance(items, list) or len(items) > 100:
        raise ValueError
    seen: set[str] = set()
    previous: tuple[datetime, str] | None = None
    for item in items:
        _keys(item, ("case_id", "decided_at", "outcome_code"))
        _safe_uuid(item["case_id"])
        if item["case_id"] in seen:
            raise ValueError
        seen.add(item["case_id"])
        _safe_text(item["outcome_code"], _OUTCOMES)
        decided_at = _utc_timestamp(item["decided_at"])
        order_key = (decided_at, item["case_id"])
        if previous is not None and not (
            order_key[0] < previous[0]
            or (order_key[0] == previous[0] and order_key[1] < previous[1])
        ):
            raise ValueError
        previous = order_key


def _projection_assigned_hold_release(value: dict[str, Any]) -> None:
    _keys(
        value,
        (
            "action_codes",
            "assignment_expires_at",
            "case_id",
            "case_status",
            "effective_at",
            "entity_tag",
            "expires_at",
            "hold_id",
            "hold_status",
            "reason_code",
        ),
    )
    _safe_array(value["action_codes"], _HOLD_ACTIONS, 1, 3)
    _safe_uuid(value["case_id"])
    _safe_uuid(value["hold_id"])
    _safe_text(value["case_status"], frozenset(("IN_REVIEW",)))
    _safe_text(value["hold_status"], frozenset(("ACTIVE",)))
    _safe_text(
        value["reason_code"],
        frozenset(("PARTICIPANT_SAFETY_RISK", "RETALIATION_RISK")),
    )
    effective_at = _utc_timestamp(value["effective_at"])
    expires_at = _utc_timestamp(value["expires_at"])
    assignment_expires_at = _utc_timestamp(value["assignment_expires_at"])
    if effective_at >= expires_at or assignment_expires_at > expires_at:
        raise ValueError


def _projection_case(value: dict[str, Any]) -> None:
    _keys(
        value,
        (
            "active_hold",
            "aggregate_version",
            "case_id",
            "demand_id",
            "demand_version_id",
            "entity_tag",
            "outcome",
            "report",
            "report_id",
            "status",
            "triage_draft",
        ),
    )
    if type(value["aggregate_version"]) is not int or value["aggregate_version"] < 1:
        raise ValueError
    for field_name in ("case_id", "demand_id", "demand_version_id", "report_id"):
        _safe_uuid(value[field_name])
    _safe_text(value["status"], frozenset(("DECIDED", "IN_REVIEW", "TRIAGING")))
    _report_summary(value["report"])
    if value["active_hold"] is not None:
        _hold_projection(value["active_hold"])
    if value["triage_draft"] is not None:
        _triage_projection(value["triage_draft"])
    if value["outcome"] is not None:
        _outcome_projection(value["outcome"])


def _triage_projection(value: Any) -> None:
    _keys(value, ("content", "content_sha256", "saved_at", "triage_version"))
    if _SHA256.fullmatch(value["content_sha256"]) is None:
        raise ValueError
    _safe_timestamp(value["saved_at"])
    if type(value["triage_version"]) is not int or value["triage_version"] < 1:
        raise ValueError
    content = value["content"]
    _keys(
        content,
        (
            "investigation_step_codes",
            "issue_codes",
            "jurisdiction_code",
            "priority_code",
            "proposed_hold_actions",
            "proposed_hold_ttl_minutes",
            "sealed_note_reference",
            "sealed_note_sha256",
            "severity_code",
        ),
    )
    _safe_array(content["investigation_step_codes"], _INVESTIGATION_CODES, 1, 16)
    _safe_array(content["issue_codes"], _ISSUE_CODES, 1, 16)
    _safe_text(content["jurisdiction_code"], _JURISDICTIONS)
    _safe_text(content["priority_code"], _PRIORITIES)
    _safe_array(content["proposed_hold_actions"], _HOLD_ACTIONS, 1, 3)
    if (
        type(content["proposed_hold_ttl_minutes"]) is not int
        or not 15 <= content["proposed_hold_ttl_minutes"] <= 10_080
        or not isinstance(content["sealed_note_reference"], str)
        or _SEALED_NOTE_REFERENCE.fullmatch(content["sealed_note_reference"]) is None
        or not isinstance(content["sealed_note_sha256"], str)
        or _SHA256.fullmatch(content["sealed_note_sha256"]) is None
    ):
        raise ValueError
    _safe_text(content["severity_code"], _SEVERITIES)


def _hold_projection(value: Any) -> None:
    _keys(value, ("action_codes", "effective_at", "entity_tag", "expires_at", "hold_id", "status"))
    _safe_array(value["action_codes"], _HOLD_ACTIONS, 1, 3)
    _safe_timestamp(value["effective_at"])
    _safe_timestamp(value["expires_at"])
    _safe_uuid(value["hold_id"])
    if not isinstance(value["entity_tag"], str) or _ENTITY_TAG.fullmatch(value["entity_tag"]) is None:
        raise ValueError
    _safe_text(value["status"], frozenset(("ACTIVE", "EXPIRED", "RELEASED")))


def _outcome_projection(value: Any) -> None:
    _keys(
        value,
        (
            "action_codes",
            "appeal_deadline",
            "appeal_eligibility_code",
            "content_sha256",
            "decided_at",
            "evidence_packet_digest",
            "evidence_packet_version_id",
            "outcome_code",
            "outcome_version_id",
            "policy_version",
            "reason_codes",
            "redaction_profile_code",
            "source_digest",
        ),
    )
    _safe_array(value["action_codes"], _HOLD_ACTIONS, 0, 3)
    _safe_timestamp(value["appeal_deadline"], nullable=True)
    _safe_text(value["appeal_eligibility_code"], frozenset(("ELIGIBLE", "NOT_ELIGIBLE")))
    for field_name in ("content_sha256", "evidence_packet_digest", "source_digest"):
        if not isinstance(value[field_name], str) or _SHA256.fullmatch(value[field_name]) is None:
            raise ValueError
    _safe_timestamp(value["decided_at"])
    _safe_uuid(value["evidence_packet_version_id"])
    _safe_uuid(value["outcome_version_id"])
    _safe_text(value["outcome_code"], _OUTCOMES)
    if not isinstance(value["policy_version"], str) or re.fullmatch(
        r"trust-case-outcome-v[1-9][0-9]*", value["policy_version"]
    ) is None:
        raise ValueError
    _safe_array(value["reason_codes"], _OUTCOME_REASONS, 1, 8)
    _safe_text(
        value["redaction_profile_code"],
        frozenset(("OFFICER_RESTRICTED_V1", "PARTY_SAFE_V1")),
    )


__all__ = [
    "TrustHttpApplicationDispatcher",
    "TrustHttpPresenterBindings",
    "TrustHttpProjection",
    "TrustHttpProjectionPort",
    "TrustHttpRequest",
    "TrustHttpResponse",
]
