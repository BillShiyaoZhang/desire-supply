"""Closed framework-neutral HTTP presenter for public Matching v1 routes.

The presenter deliberately does not authenticate sessions, infer organizations,
or inspect storage.  A trusted HTTP boundary supplies a selected-workspace actor;
an explicitly injected resource-scope port resolves the organization for a
command, and field-specific command/projection bindings own all durable access.
There is no Memory or allow-all fallback.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import re
import unicodedata
from typing import Any, Mapping, Optional, Protocol, Tuple

from .application import (
    ChooseCreatorCommand,
    ChooseCreatorHandler,
    CloseSelectionWithoutChoiceCommand,
    CloseSelectionWithoutChoiceHandler,
    CreateInvitationCommand,
    CreateInvitationHandler,
    InvalidateAttemptCommand,
    InvalidateAttemptHandler,
    MatchingActorContext,
    MatchingActorKind,
    MatchingApplicationError,
    MatchingCommandResult,
    PublishInvitationCommand,
    PublishInvitationHandler,
    RespondInvitationCommand,
    RespondInvitationHandler,
    WithdrawAcceptedInvitationCommand,
    WithdrawAcceptedInvitationHandler,
)


_OPAQUE_TEXT = r"[A-Za-z0-9][A-Za-z0-9_-]{15,127}"
_OPAQUE_ID = re.compile(rf"{_OPAQUE_TEXT}\Z")
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_CODE = re.compile(r"[A-Z][A-Z0-9_]{1,63}\Z")
_DISCLOSURE_CODE = re.compile(r"[A-Z][A-Z0-9_.:-]{1,63}\Z")
_ENTITY_TAG = re.compile(r'^"v([1-9][0-9]*)"\Z')
_IDEMPOTENCY_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~-]{15,127}\Z")
_CURSOR = re.compile(r"[A-Za-z0-9._~-]{16,2048}\Z")
_CURRENCY = re.compile(r"[A-Z]{3}\Z")

_INVITATION_STATUSES = frozenset(
    ("CREATED", "SENT", "ACCEPTED", "DECLINED", "WITHDRAWN", "EXPIRED", "REVOKED")
)
_RECIPIENT_INVITATION_STATUSES = _INVITATION_STATUSES - {"CREATED"}
_RESPONSE_STATUSES = frozenset(("ACCEPTED", "DECLINED", "WITHDRAWN"))
_ATTEMPT_STATUSES = frozenset(
    ("OPEN", "SELECTED", "CLOSED_NO_SELECTION", "INVALIDATED", "CANCELLED")
)
_SELECTION_STATUSES = frozenset(
    (
        "OPEN", "PENDING_CHOICE", "PENDING_CLOSE",
        "SELECTED", "CLOSED_NO_SELECTION", "CANCELLED",
    )
)

_ERROR_STATUS = {
    "INVALID_REQUEST": 400,
    "AUTHENTICATION_REQUIRED": 401,
    "SESSION_EXPIRED": 401,
    "ACCESS_DENIED": 403,
    "SAFETY_HOLD_BLOCKED": 403,
    "POLICY_ACCEPTANCE_REQUIRED": 403,
    "RESOURCE_NOT_FOUND": 404,
    "INVALID_STATE_TRANSITION": 409,
    "INVITATION_ALREADY_SELECTED": 409,
    "SELECTOR_ASSIGNMENT_REQUIRED": 409,
    "IDEMPOTENCY_KEY_REUSED": 409,
    "MATCH_INPUT_CHANGED": 409,
    "MATCH_RULE_BUNDLE_CHANGED": 409,
    "FUNDING_FACT_CHANGED": 409,
    "INVITATION_ALREADY_EXISTS": 409,
    "PRECONDITION_FAILED": 412,
    "SELECTION_NOT_READY": 422,
    "POLICY_CONFIGURATION_UNAVAILABLE": 503,
    "COMMAND_OUTCOME_UNKNOWN": 503,
    "SERVICE_UNAVAILABLE": 503,
}
_ERROR_MESSAGE = {
    "INVALID_REQUEST": "The request is invalid.",
    "AUTHENTICATION_REQUIRED": "Authentication is required.",
    "SESSION_EXPIRED": "The session has expired.",
    "ACCESS_DENIED": "Access is denied.",
    "SAFETY_HOLD_BLOCKED": "The action is blocked by a safety hold.",
    "POLICY_ACCEPTANCE_REQUIRED": "Current policy acceptance is required.",
    "RESOURCE_NOT_FOUND": "The resource was not found.",
    "INVALID_STATE_TRANSITION": "The requested state transition is invalid.",
    "INVITATION_ALREADY_SELECTED": "The invitation is already selected.",
    "SELECTOR_ASSIGNMENT_REQUIRED": "An active Candidate Selector assignment is required.",
    "IDEMPOTENCY_KEY_REUSED": "The idempotency key was reused for another request.",
    "MATCH_INPUT_CHANGED": "The matching input has changed.",
    "MATCH_RULE_BUNDLE_CHANGED": "The matching rule bundle has changed.",
    "FUNDING_FACT_CHANGED": "The funding fact has changed.",
    "INVITATION_ALREADY_EXISTS": "An invitation already exists.",
    "PRECONDITION_FAILED": "The resource version does not match.",
    "SELECTION_NOT_READY": "The selection is not ready.",
    "POLICY_CONFIGURATION_UNAVAILABLE": "Policy configuration is unavailable.",
    "COMMAND_OUTCOME_UNKNOWN": "The command outcome is not yet known.",
    "SERVICE_UNAVAILABLE": "Service is temporarily unavailable.",
}


class MatchingHttpFamily(str):
    CREATOR = "CREATOR"
    CANDIDATE_SELECTOR = "CANDIDATE_SELECTOR"
    OPERATIONS = "OPERATIONS"


@dataclass(frozen=True)
class MatchingHttpRoute:
    method: str
    path_template: str
    operation_id: str
    family: str
    success_status: int
    projection_kind: str
    command_handler_name: Optional[str]
    expression: re.Pattern[str] = field(repr=False, compare=False)

    @property
    def mutating(self) -> bool:
        return self.command_handler_name is not None

    @property
    def paginated(self) -> bool:
        return self.projection_kind in {"RECIPIENT_INVITATION_LIST", "ATTEMPT_LIST"}


def _identifier(name: str) -> str:
    return rf"(?P<{name}>{_OPAQUE_TEXT})"


MATCHING_HTTP_ROUTES: Tuple[MatchingHttpRoute, ...] = (
    MatchingHttpRoute("GET", "/v1/me/matching-invitations", "listMyMatchingInvitations", MatchingHttpFamily.CREATOR, 200, "RECIPIENT_INVITATION_LIST", None, re.compile(r"^/v1/me/matching-invitations$")),
    MatchingHttpRoute("GET", "/v1/me/matching-invitations/{invitation_id}", "getMyMatchingInvitation", MatchingHttpFamily.CREATOR, 200, "RECIPIENT_INVITATION", None, re.compile(rf"^/v1/me/matching-invitations/{_identifier('invitation_id')}$")),
    MatchingHttpRoute("POST", "/v1/me/matching-invitations/{invitation_id}/accept", "acceptMatchingInvitation", MatchingHttpFamily.CREATOR, 200, "RECIPIENT_INVITATION", "respond_invitation", re.compile(rf"^/v1/me/matching-invitations/{_identifier('invitation_id')}/accept$")),
    MatchingHttpRoute("POST", "/v1/me/matching-invitations/{invitation_id}/decline", "declineMatchingInvitation", MatchingHttpFamily.CREATOR, 200, "RECIPIENT_INVITATION", "respond_invitation", re.compile(rf"^/v1/me/matching-invitations/{_identifier('invitation_id')}/decline$")),
    MatchingHttpRoute("POST", "/v1/me/matching-invitations/{invitation_id}/withdraw", "withdrawMatchingInvitationAcceptance", MatchingHttpFamily.CREATOR, 200, "RECIPIENT_INVITATION", "withdraw_invitation", re.compile(rf"^/v1/me/matching-invitations/{_identifier('invitation_id')}/withdraw$")),
    MatchingHttpRoute("GET", "/v1/organizations/{organization_id}/demands/{demand_id}/matching-attempts", "listDemandMatchingAttempts", MatchingHttpFamily.CANDIDATE_SELECTOR, 200, "ATTEMPT_LIST", None, re.compile(rf"^/v1/organizations/{_identifier('organization_id')}/demands/{_identifier('demand_id')}/matching-attempts$")),
    MatchingHttpRoute("GET", "/v1/organizations/{organization_id}/matching-attempts/{attempt_id}/selection", "getMatchingSelection", MatchingHttpFamily.CANDIDATE_SELECTOR, 200, "SELECTION", None, re.compile(rf"^/v1/organizations/{_identifier('organization_id')}/matching-attempts/{_identifier('attempt_id')}/selection$")),
    MatchingHttpRoute("GET", "/v1/organizations/{organization_id}/selections/{selection_id}", "getMatchingSelectionById", MatchingHttpFamily.CANDIDATE_SELECTOR, 200, "SELECTION", None, re.compile(rf"^/v1/organizations/{_identifier('organization_id')}/selections/{_identifier('selection_id')}$")),
    MatchingHttpRoute("POST", "/v1/organizations/{organization_id}/selections/{selection_id}/choose", "chooseMatchingCreator", MatchingHttpFamily.CANDIDATE_SELECTOR, 200, "SELECTION", "choose_creator", re.compile(rf"^/v1/organizations/{_identifier('organization_id')}/selections/{_identifier('selection_id')}/choose$")),
    MatchingHttpRoute("POST", "/v1/organizations/{organization_id}/selections/{selection_id}/close", "closeMatchingSelection", MatchingHttpFamily.CANDIDATE_SELECTOR, 200, "SELECTION", "close_selection", re.compile(rf"^/v1/organizations/{_identifier('organization_id')}/selections/{_identifier('selection_id')}/close$")),
    MatchingHttpRoute("POST", "/v1/operations/match-runs/{match_run_id}/invitations", "createMatchingInvitation", MatchingHttpFamily.OPERATIONS, 201, "REVIEWER_INVITATION", "create_invitation", re.compile(rf"^/v1/operations/match-runs/{_identifier('match_run_id')}/invitations$")),
    MatchingHttpRoute("POST", "/v1/operations/matching-invitations/{invitation_id}/publish", "publishMatchingInvitation", MatchingHttpFamily.OPERATIONS, 200, "REVIEWER_INVITATION", "publish_invitation", re.compile(rf"^/v1/operations/matching-invitations/{_identifier('invitation_id')}/publish$")),
    MatchingHttpRoute("POST", "/v1/operations/matching-attempts/{attempt_id}/invalidate", "invalidateMatchingAttempt", MatchingHttpFamily.OPERATIONS, 200, "ATTEMPT", "invalidate_attempt", re.compile(rf"^/v1/operations/matching-attempts/{_identifier('attempt_id')}/invalidate$")),
)


class MatchingHttpRouteNotFound(ValueError):
    pass


def resolve_matching_http_route(
    method: str, path: str
) -> tuple[MatchingHttpRoute, Mapping[str, str]]:
    if not isinstance(method, str) or method != method.upper() or not isinstance(path, str):
        raise MatchingHttpRouteNotFound("RESOURCE_NOT_FOUND")
    for route in MATCHING_HTTP_ROUTES:
        match = route.expression.fullmatch(path)
        if match is not None and method == route.method:
            return route, match.groupdict()
    raise MatchingHttpRouteNotFound("RESOURCE_NOT_FOUND")


def is_matching_public_path(path: Any) -> bool:
    return isinstance(path, str) and any(
        route.expression.fullmatch(path) is not None for route in MATCHING_HTTP_ROUTES
    )


@dataclass(frozen=True)
class MatchingHttpActor:
    actor_user_id: str
    session_id: str = field(repr=False)
    correlation_id: str
    causation_id: str
    trace_id: str
    original_actor_id: Optional[str]
    workspace_id: str
    workspace_kind: str
    organization_id: Optional[str]
    role_codes: Tuple[str, ...]
    authority_marker_sha256: bytes = field(default=b"", repr=False)

    def __post_init__(self) -> None:
        required = (
            self.actor_user_id,
            self.session_id,
            self.correlation_id,
            self.causation_id,
            self.trace_id,
            self.workspace_id,
            self.workspace_kind,
        )
        if any(not isinstance(value, str) or not value for value in required):
            raise TypeError("Matching HTTP actor facts are invalid")
        if self.original_actor_id is not None and (
            not isinstance(self.original_actor_id, str) or not self.original_actor_id
        ):
            raise TypeError("Matching HTTP original actor is invalid")
        if (
            not isinstance(self.role_codes, tuple)
            or not self.role_codes
            or self.role_codes != tuple(sorted(set(self.role_codes)))
            or not isinstance(self.authority_marker_sha256, bytes)
            or len(self.authority_marker_sha256) not in (0, 32)
        ):
            raise TypeError("Matching HTTP role facts are invalid")
        if self.workspace_kind == "ORGANIZATION":
            if self.organization_id is None or self.workspace_id != f"org:{self.organization_id}":
                raise TypeError("Matching HTTP organization workspace is invalid")
        elif self.workspace_kind == "PERSONAL":
            if self.organization_id is not None or self.workspace_id != f"personal:{self.actor_user_id}":
                raise TypeError("Matching HTTP personal workspace is invalid")
        elif self.workspace_kind == "PLATFORM":
            if self.organization_id is not None or self.workspace_id != f"platform:{self.actor_user_id}":
                raise TypeError("Matching HTTP platform workspace is invalid")
        else:
            raise TypeError("Matching HTTP workspace kind is invalid")


@dataclass(frozen=True)
class MatchingHttpRequest:
    method: str
    path: str
    headers: Mapping[str, str] = field(repr=False)
    json_body: Mapping[str, Any] = field(repr=False)
    query: Mapping[str, Tuple[str, ...]] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.method, str)
            or not isinstance(self.path, str)
            or not isinstance(self.headers, Mapping)
            or not isinstance(self.json_body, Mapping)
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
            raise TypeError("Matching HTTP request is invalid")
        object.__setattr__(self, "headers", dict(self.headers))
        object.__setattr__(self, "json_body", deepcopy(dict(self.json_body)))
        object.__setattr__(self, "query", {name: tuple(values) for name, values in self.query.items()})


@dataclass(frozen=True)
class MatchingHttpResponse:
    status: int
    headers: Mapping[str, str]
    json_body: Mapping[str, Any] = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.status) is not int or not isinstance(self.headers, Mapping) or not isinstance(self.json_body, Mapping):
            raise TypeError("Matching HTTP response is invalid")
        object.__setattr__(self, "headers", dict(self.headers))
        object.__setattr__(self, "json_body", deepcopy(dict(self.json_body)))


@dataclass(frozen=True, init=False)
class MatchingHttpProjection:
    """Detached and closed DTO returned by a durable projection adapter."""

    kind: str
    entity_tag: Optional[str]
    _canonical_json: str = field(repr=False)

    def __init__(
        self,
        *,
        kind: str,
        data: Mapping[str, Any],
        entity_tag: Optional[str] = None,
    ) -> None:
        if kind not in {
            "RECIPIENT_INVITATION_LIST",
            "RECIPIENT_INVITATION",
            "ATTEMPT_LIST",
            "ATTEMPT",
            "SELECTION",
            "REVIEWER_INVITATION",
        }:
            raise ValueError("MATCHING_HTTP_PROJECTION_INVALID")
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
            raise ValueError("MATCHING_HTTP_PROJECTION_INVALID") from None
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "entity_tag", entity_tag)
        object.__setattr__(self, "_canonical_json", canonical)

    def as_json(self) -> dict[str, Any]:
        return json.loads(self._canonical_json)


class MatchingHttpProjectionPort(Protocol):
    def list_recipient_invitations(self, *, actor: MatchingHttpActor, limit: int, cursor: Optional[str]) -> MatchingHttpProjection: ...
    def read_recipient_invitation(self, *, actor: MatchingHttpActor, invitation_id: str) -> MatchingHttpProjection: ...
    def list_demand_attempts(self, *, actor: MatchingHttpActor, organization_id: str, demand_id: str, limit: int, cursor: Optional[str]) -> MatchingHttpProjection: ...
    def read_selection_for_attempt(self, *, actor: MatchingHttpActor, organization_id: str, attempt_id: str) -> MatchingHttpProjection: ...
    def read_selection(self, *, actor: MatchingHttpActor, organization_id: str, selection_id: str) -> MatchingHttpProjection: ...
    def read_reviewer_invitation(self, *, actor: MatchingHttpActor, invitation_id: str) -> MatchingHttpProjection: ...
    def read_attempt(self, *, actor: MatchingHttpActor, attempt_id: str) -> MatchingHttpProjection: ...


class MatchingHttpCommandActorPort(Protocol):
    def resolve_actor(
        self,
        *,
        actor: MatchingHttpActor,
        operation_id: str,
        path_parameters: Mapping[str, str],
    ) -> MatchingActorContext: ...


class MatchingHttpReviewerAssignmentPort(Protocol):
    def resolve_assignment_id(
        self,
        *,
        actor: MatchingHttpActor,
        operation_id: str,
        path_parameters: Mapping[str, str],
    ) -> str: ...


@dataclass(frozen=True)
class MatchingHttpPresenterBindings:
    respond_invitation: RespondInvitationHandler
    withdraw_invitation: WithdrawAcceptedInvitationHandler
    choose_creator: ChooseCreatorHandler
    close_selection: CloseSelectionWithoutChoiceHandler
    projections: MatchingHttpProjectionPort
    command_actors: MatchingHttpCommandActorPort
    create_invitation: Optional[CreateInvitationHandler] = None
    publish_invitation: Optional[PublishInvitationHandler] = None
    invalidate_attempt: Optional[InvalidateAttemptHandler] = None
    reviewer_assignments: Optional[MatchingHttpReviewerAssignmentPort] = None

    def __post_init__(self) -> None:
        public_handlers = (
            (self.respond_invitation, RespondInvitationHandler),
            (self.withdraw_invitation, WithdrawAcceptedInvitationHandler),
            (self.choose_creator, ChooseCreatorHandler),
            (self.close_selection, CloseSelectionWithoutChoiceHandler),
        )
        if any(not isinstance(value, kind) for value, kind in public_handlers):
            raise TypeError("Matching HTTP command handlers are unavailable")
        operations_handlers = (
            (self.create_invitation, CreateInvitationHandler),
            (self.publish_invitation, PublishInvitationHandler),
            (self.invalidate_attempt, InvalidateAttemptHandler),
        )
        operations_enabled = all(
            isinstance(value, kind) for value, kind in operations_handlers
        )
        if not operations_enabled and any(
            value is not None for value, _kind in operations_handlers
        ):
            raise TypeError("Matching Operations handlers are only enabled as a set")
        public_projection_methods = (
            "list_recipient_invitations",
            "read_recipient_invitation",
            "list_demand_attempts",
            "read_selection_for_attempt",
            "read_selection",
        )
        if any(
            not callable(getattr(self.projections, name, None))
            for name in public_projection_methods
        ):
            raise TypeError("Matching HTTP projections are unavailable")
        if not callable(getattr(self.command_actors, "resolve_actor", None)):
            raise TypeError("Matching HTTP command actor resolver is unavailable")
        if operations_enabled and (
            any(
                not callable(getattr(self.projections, name, None))
                for name in ("read_reviewer_invitation", "read_attempt")
            )
            or not callable(
                getattr(self.reviewer_assignments, "resolve_assignment_id", None)
            )
        ):
            raise TypeError("Matching HTTP reviewer assignment resolver is unavailable")
        if not operations_enabled and self.reviewer_assignments is not None:
            raise TypeError("Matching Operations resolver is unexpectedly enabled")


class _HttpRejection(Exception):
    def __init__(self, code: str, status: Optional[int] = None) -> None:
        self.code = code if code in _ERROR_STATUS else "SERVICE_UNAVAILABLE"
        self.status = _ERROR_STATUS[self.code] if status is None else status
        super().__init__(self.code)


class MatchingHttpApplicationDispatcher:
    """Invoke exactly one reviewed Matching projection or command binding."""

    def __init__(self, *, bindings: MatchingHttpPresenterBindings) -> None:
        if not isinstance(bindings, MatchingHttpPresenterBindings):
            raise TypeError("Matching HTTP presenter bindings are unavailable")
        self._bindings = bindings

    def handle(
        self,
        *,
        request: MatchingHttpRequest,
        actor: MatchingHttpActor,
    ) -> MatchingHttpResponse:
        trace_id = actor.trace_id if isinstance(actor, MatchingHttpActor) else "trace-unavailable"
        if not isinstance(request, MatchingHttpRequest) or not isinstance(actor, MatchingHttpActor):
            return matching_http_error("INVALID_REQUEST", trace_id=trace_id)
        route: Optional[MatchingHttpRoute] = None
        command_dispatched = False
        try:
            route, path_parameters = resolve_matching_http_route(request.method, request.path)
            if route.family == MatchingHttpFamily.CREATOR and actor.workspace_kind != "PERSONAL":
                raise _HttpRejection("RESOURCE_NOT_FOUND")
            if route.family == MatchingHttpFamily.CANDIDATE_SELECTOR and (
                actor.workspace_kind != "ORGANIZATION"
                or actor.organization_id != path_parameters.get("organization_id")
            ):
                raise _HttpRejection("RESOURCE_NOT_FOUND")
            if route.family == MatchingHttpFamily.OPERATIONS and (
                actor.workspace_kind != "PLATFORM"
                or "OPERATIONS_REVIEWER" not in actor.role_codes
            ):
                raise _HttpRejection("RESOURCE_NOT_FOUND")
            if not route.mutating:
                projection = self._read(
                    route=route,
                    path_parameters=path_parameters,
                    actor=actor,
                    body=request.json_body,
                    query=request.query,
                )
                return _projection_response(route.success_status, projection)

            handler = getattr(self._bindings, route.command_handler_name or "")
            if handler is None:
                raise _HttpRejection("SERVICE_UNAVAILABLE")
            _exact_query(request.query, ())
            idempotency_key = _idempotency_key(request.headers)
            expected_version = _expected_version(request.headers)
            command_actor = self._bindings.command_actors.resolve_actor(
                actor=actor,
                operation_id=route.operation_id,
                path_parameters=path_parameters,
            )
            _validate_command_actor(http_actor=actor, command_actor=command_actor)
            command = self._command(
                route=route,
                path_parameters=path_parameters,
                body=request.json_body,
                http_actor=actor,
                idempotency_key=idempotency_key,
                expected_version=expected_version,
            )
            command_dispatched = True
            result = handler.handle(actor=command_actor, command=command)
            if not isinstance(result, MatchingCommandResult):
                raise _HttpRejection("COMMAND_OUTCOME_UNKNOWN")
            projection = self._read_after_command(
                route=route,
                path_parameters=path_parameters,
                actor=actor,
                result=result,
            )
            return _projection_response(route.success_status, projection)
        except MatchingHttpRouteNotFound:
            return matching_http_error("RESOURCE_NOT_FOUND", trace_id=trace_id)
        except _HttpRejection as error:
            return matching_http_error(error.code, trace_id=trace_id, status=error.status)
        except MatchingApplicationError as error:
            code = error.code if error.code in _ERROR_STATUS else "SERVICE_UNAVAILABLE"
            return matching_http_error(code, trace_id=trace_id)
        except Exception:
            code = "COMMAND_OUTCOME_UNKNOWN" if command_dispatched else "SERVICE_UNAVAILABLE"
            return matching_http_error(code, trace_id=trace_id)

    def _read(
        self,
        *,
        route: MatchingHttpRoute,
        path_parameters: Mapping[str, str],
        actor: MatchingHttpActor,
        body: Mapping[str, Any],
        query: Mapping[str, Tuple[str, ...]],
    ) -> MatchingHttpProjection:
        _exact_object(body, ())
        port = self._bindings.projections
        if route.operation_id == "listMyMatchingInvitations":
            limit, cursor = _page_query(query)
            return _expect_projection(
                port.list_recipient_invitations(actor=actor, limit=limit, cursor=cursor),
                route.projection_kind,
            )
        if route.operation_id == "getMyMatchingInvitation":
            _exact_query(query, ())
            return _expect_projection(
                port.read_recipient_invitation(actor=actor, invitation_id=path_parameters["invitation_id"]),
                route.projection_kind,
            )
        if route.operation_id == "listDemandMatchingAttempts":
            limit, cursor = _page_query(query)
            return _expect_projection(
                port.list_demand_attempts(
                    actor=actor,
                    organization_id=path_parameters["organization_id"],
                    demand_id=path_parameters["demand_id"],
                    limit=limit,
                    cursor=cursor,
                ),
                route.projection_kind,
            )
        if route.operation_id == "getMatchingSelection":
            _exact_query(query, ())
            return _expect_projection(
                port.read_selection_for_attempt(
                    actor=actor,
                    organization_id=path_parameters["organization_id"],
                    attempt_id=path_parameters["attempt_id"],
                ),
                route.projection_kind,
            )
        if route.operation_id == "getMatchingSelectionById":
            _exact_query(query, ())
            return _expect_projection(
                port.read_selection(
                    actor=actor,
                    organization_id=path_parameters["organization_id"],
                    selection_id=path_parameters["selection_id"],
                ),
                route.projection_kind,
            )
        raise _HttpRejection("RESOURCE_NOT_FOUND")

    def _command(
        self,
        *,
        route: MatchingHttpRoute,
        path_parameters: Mapping[str, str],
        body: Mapping[str, Any],
        http_actor: MatchingHttpActor,
        idempotency_key: str,
        expected_version: int,
    ) -> Any:
        operation = route.operation_id
        if operation == "acceptMatchingInvitation":
            _exact_object(body, ("snapshot_sha256",))
            return RespondInvitationCommand(
                invitation_id=path_parameters["invitation_id"],
                snapshot_sha256=_sha256(body["snapshot_sha256"]),
                expected_invitation_version=expected_version,
                accept=True,
                reason_code=None,
                note=None,
                idempotency_key=idempotency_key,
            )
        if operation == "declineMatchingInvitation":
            reason, note = _reason_body(body, snapshot=True)
            return RespondInvitationCommand(
                invitation_id=path_parameters["invitation_id"],
                snapshot_sha256=_sha256(body["snapshot_sha256"]),
                expected_invitation_version=expected_version,
                accept=False,
                reason_code=reason,
                note=note,
                idempotency_key=idempotency_key,
            )
        if operation == "withdrawMatchingInvitationAcceptance":
            reason, note = _reason_body(body, snapshot=True)
            return WithdrawAcceptedInvitationCommand(
                invitation_id=path_parameters["invitation_id"],
                snapshot_sha256=_sha256(body["snapshot_sha256"]),
                expected_invitation_version=expected_version,
                reason_code=reason,
                note=note,
                idempotency_key=idempotency_key,
            )
        if operation == "chooseMatchingCreator":
            _exact_object(
                body,
                (
                    "invitation_id",
                    "selection_basis_code",
                    "current_invitation_set_sha256",
                    "candidate_selector_assignment_id",
                    "candidate_selector_assignment_version",
                ),
            )
            return ChooseCreatorCommand(
                selection_id=path_parameters["selection_id"],
                invitation_id=_opaque(body["invitation_id"]),
                selection_basis_code=_code(body["selection_basis_code"]),
                current_invitation_set_sha256=_sha256(body["current_invitation_set_sha256"]),
                expected_selection_version=expected_version,
                assignment_id=_opaque(body["candidate_selector_assignment_id"]),
                expected_assignment_version=_positive_int(body["candidate_selector_assignment_version"]),
                idempotency_key=idempotency_key,
            )
        if operation == "closeMatchingSelection":
            _exact_object(
                body,
                (
                    "reason_code",
                    "current_invitation_set_sha256",
                    "candidate_selector_assignment_id",
                    "candidate_selector_assignment_version",
                ),
            )
            return CloseSelectionWithoutChoiceCommand(
                selection_id=path_parameters["selection_id"],
                reason_code=_code(body["reason_code"]),
                current_invitation_set_sha256=_sha256(body["current_invitation_set_sha256"]),
                expected_selection_version=expected_version,
                assignment_id=_opaque(body["candidate_selector_assignment_id"]),
                expected_assignment_version=_positive_int(body["candidate_selector_assignment_version"]),
                idempotency_key=idempotency_key,
            )
        if operation == "createMatchingInvitation":
            _exact_object(body, ("match_run_id", "creator_user_id", "expires_at"))
            match_run_id = _opaque(body["match_run_id"])
            if match_run_id != path_parameters["match_run_id"]:
                raise _HttpRejection("INVALID_REQUEST")
            return CreateInvitationCommand(
                match_run_id=match_run_id,
                creator_user_id=_opaque(body["creator_user_id"]),
                expires_at=_timestamp(body["expires_at"]),
                expected_run_version=expected_version,
                assignment_id=self._reviewer_assignment(http_actor, route, path_parameters),
                idempotency_key=idempotency_key,
            )
        if operation == "publishMatchingInvitation":
            _exact_object(body, ("snapshot_sha256",))
            return PublishInvitationCommand(
                invitation_id=path_parameters["invitation_id"],
                snapshot_sha256=_sha256(body["snapshot_sha256"]),
                expected_invitation_version=expected_version,
                assignment_id=self._reviewer_assignment(http_actor, route, path_parameters),
                idempotency_key=idempotency_key,
            )
        if operation == "invalidateMatchingAttempt":
            _exact_object(body, ("reason_code", "input_baseline_sha256"))
            return InvalidateAttemptCommand(
                attempt_id=path_parameters["attempt_id"],
                reason_code=_code(body["reason_code"]),
                input_baseline_sha256=_sha256(body["input_baseline_sha256"]),
                expected_attempt_version=expected_version,
                assignment_id=self._reviewer_assignment(http_actor, route, path_parameters),
                idempotency_key=idempotency_key,
            )
        raise _HttpRejection("RESOURCE_NOT_FOUND")

    def _reviewer_assignment(
        self,
        actor: MatchingHttpActor,
        route: MatchingHttpRoute,
        path_parameters: Mapping[str, str],
    ) -> str:
        resolver = self._bindings.reviewer_assignments
        if resolver is None:
            raise _HttpRejection("SERVICE_UNAVAILABLE")
        value = resolver.resolve_assignment_id(
            actor=actor,
            operation_id=route.operation_id,
            path_parameters=path_parameters,
        )
        try:
            return _opaque(value)
        except _HttpRejection:
            raise _HttpRejection("RESOURCE_NOT_FOUND") from None

    def _read_after_command(
        self,
        *,
        route: MatchingHttpRoute,
        path_parameters: Mapping[str, str],
        actor: MatchingHttpActor,
        result: MatchingCommandResult,
    ) -> MatchingHttpProjection:
        port = self._bindings.projections
        if route.projection_kind == "RECIPIENT_INVITATION":
            projection = port.read_recipient_invitation(actor=actor, invitation_id=result.target_id)
        elif route.projection_kind == "SELECTION":
            projection = port.read_selection(
                actor=actor,
                organization_id=path_parameters["organization_id"],
                selection_id=result.target_id,
            )
        elif route.projection_kind == "REVIEWER_INVITATION":
            projection = port.read_reviewer_invitation(actor=actor, invitation_id=result.target_id)
        elif route.projection_kind == "ATTEMPT":
            projection = port.read_attempt(actor=actor, attempt_id=result.target_id)
        else:
            raise _HttpRejection("COMMAND_OUTCOME_UNKNOWN")
        projection = _expect_projection(projection, route.projection_kind)
        data = projection.as_json()
        if (
            data.get("aggregate_version") != result.aggregate_version
            or data.get("status") != result.target_status
            or data.get(_projection_identifier(route.projection_kind)) != result.target_id
            or data.get("updated_at") != _utc_text(result.updated_at)
        ):
            raise _HttpRejection("COMMAND_OUTCOME_UNKNOWN")
        return projection


def _projection_identifier(kind: str) -> str:
    return {
        "RECIPIENT_INVITATION": "invitation_id",
        "REVIEWER_INVITATION": "invitation_id",
        "SELECTION": "selection_id",
        "ATTEMPT": "attempt_id",
    }[kind]


def _validate_command_actor(
    *, http_actor: MatchingHttpActor, command_actor: Any
) -> None:
    if (
        not isinstance(command_actor, MatchingActorContext)
        or command_actor.actor_kind is not MatchingActorKind.USER
        or command_actor.actor_id != http_actor.actor_user_id
        or command_actor.session_id != http_actor.session_id
        or command_actor.correlation_id != http_actor.correlation_id
        or command_actor.causation_id != http_actor.causation_id
        or command_actor.trace_id != http_actor.trace_id
        or command_actor.original_actor_id != http_actor.original_actor_id
        or command_actor.workload_credential_id is not None
        or not isinstance(command_actor.organization_id, str)
        or _OPAQUE_ID.fullmatch(command_actor.organization_id) is None
        or (
            http_actor.organization_id is not None
            and command_actor.organization_id != http_actor.organization_id
        )
    ):
        raise _HttpRejection("RESOURCE_NOT_FOUND")


def _idempotency_key(headers: Mapping[str, str]) -> str:
    value = headers.get("idempotency-key")
    if not isinstance(value, str) or _IDEMPOTENCY_KEY.fullmatch(value) is None:
        raise _HttpRejection("INVALID_REQUEST")
    return value


def _expected_version(headers: Mapping[str, str]) -> int:
    value = headers.get("if-match")
    match = _ENTITY_TAG.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise _HttpRejection("INVALID_REQUEST")
    version = int(match.group(1))
    if version > 2_147_483_647:
        raise _HttpRejection("INVALID_REQUEST")
    return version


def _exact_object(value: Mapping[str, Any], required: Tuple[str, ...]) -> None:
    if not isinstance(value, Mapping) or set(value) != set(required):
        raise _HttpRejection("INVALID_REQUEST")


def _exact_query(value: Mapping[str, Tuple[str, ...]], allowed: Tuple[str, ...]) -> None:
    if not isinstance(value, Mapping) or set(value) != set(allowed):
        raise _HttpRejection("INVALID_REQUEST")


def _page_query(value: Mapping[str, Tuple[str, ...]]) -> tuple[int, Optional[str]]:
    if not isinstance(value, Mapping) or not set(value).issubset({"cursor", "limit"}):
        raise _HttpRejection("INVALID_REQUEST")
    if any(not isinstance(items, tuple) or len(items) != 1 for items in value.values()):
        raise _HttpRejection("INVALID_REQUEST")
    raw_limit = value.get("limit", ("25",))[0]
    if re.fullmatch(r"(?:[1-9]|[1-9][0-9]|100)", raw_limit) is None:
        raise _HttpRejection("INVALID_REQUEST")
    cursor = value.get("cursor", (None,))[0]
    if cursor is not None and _CURSOR.fullmatch(cursor) is None:
        raise _HttpRejection("INVALID_REQUEST")
    return int(raw_limit), cursor


def _opaque(value: Any) -> str:
    if not isinstance(value, str) or _OPAQUE_ID.fullmatch(value) is None:
        raise _HttpRejection("INVALID_REQUEST")
    return value


def _sha256(value: Any) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise _HttpRejection("INVALID_REQUEST")
    return value


def _code(value: Any) -> str:
    if not isinstance(value, str) or _CODE.fullmatch(value) is None:
        raise _HttpRejection("INVALID_REQUEST")
    return value


def _positive_int(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= 2_147_483_647:
        raise _HttpRejection("INVALID_REQUEST")
    return value


def _timestamp(value: Any) -> datetime:
    try:
        parsed = _parse_utc(value)
    except ValueError:
        raise _HttpRejection("INVALID_REQUEST") from None
    return parsed


def _reason_body(body: Mapping[str, Any], *, snapshot: bool) -> tuple[str, Optional[str]]:
    required = ("snapshot_sha256", "reason_code", "note") if snapshot else ("reason_code", "note")
    _exact_object(body, required)
    if snapshot:
        _sha256(body["snapshot_sha256"])
    reason = _code(body["reason_code"])
    note = body["note"]
    if note is not None:
        if not isinstance(note, str) or not 1 <= len(note) <= 500 or not _safe_public_text(note, allow_angle=True):
            raise _HttpRejection("INVALID_REQUEST")
    return reason, note


def _expect_projection(value: Any, kind: str) -> MatchingHttpProjection:
    if not isinstance(value, MatchingHttpProjection) or value.kind != kind:
        raise _HttpRejection("SERVICE_UNAVAILABLE")
    return value


def _projection_response(status: int, projection: MatchingHttpProjection) -> MatchingHttpResponse:
    headers = {"content-type": "application/json"}
    if projection.entity_tag is not None:
        headers["etag"] = projection.entity_tag
    return MatchingHttpResponse(status=status, headers=headers, json_body=projection.as_json())


def matching_http_error(
    code: str,
    *,
    trace_id: str,
    status: Optional[int] = None,
) -> MatchingHttpResponse:
    safe_code = code if code in _ERROR_STATUS else "SERVICE_UNAVAILABLE"
    safe_trace = trace_id if isinstance(trace_id, str) and _OPAQUE_ID.fullmatch(trace_id) is not None else "trace-unavailable"
    return MatchingHttpResponse(
        status=_ERROR_STATUS[safe_code] if status is None else status,
        headers={"content-type": "application/json"},
        json_body={
            "code": safe_code,
            "message": _ERROR_MESSAGE[safe_code],
            "trace_id": safe_trace,
        },
    )


def _validate_projection(kind: str, data: Any, entity_tag: Optional[str]) -> None:
    if kind == "RECIPIENT_INVITATION_LIST":
        _keys(data, ("items", "next_cursor"))
        _list(data["items"], 100, _recipient_invitation)
        _nullable_cursor(data["next_cursor"])
        if entity_tag is not None:
            raise ValueError
        return
    if kind == "ATTEMPT_LIST":
        _keys(data, ("items", "next_cursor"))
        _list(data["items"], 100, _attempt)
        _nullable_cursor(data["next_cursor"])
        if entity_tag is not None:
            raise ValueError
        return
    validators = {
        "RECIPIENT_INVITATION": _recipient_invitation,
        "REVIEWER_INVITATION": _reviewer_invitation,
        "ATTEMPT": _attempt,
        "SELECTION": _selection,
    }
    validators[kind](data)
    if entity_tag != f'"v{data["aggregate_version"]}"':
        raise ValueError


def _recipient_invitation(value: Any) -> None:
    _keys(value, ("invitation_id", "status", "aggregate_version", "updated_at", "expires_at", "snapshot_sha256", "response_status", "disclosure"))
    _safe_id(value["invitation_id"])
    _safe_enum(value["status"], _RECIPIENT_INVITATION_STATUSES)
    _safe_version(value["aggregate_version"])
    _parse_utc(value["updated_at"])
    _parse_utc(value["expires_at"])
    _safe_sha(value["snapshot_sha256"])
    if value["response_status"] is not None:
        _safe_enum(value["response_status"], _RESPONSE_STATUSES)
    _disclosure(value["disclosure"], expected_id=value["invitation_id"], expected_sha=value["snapshot_sha256"])


def _reviewer_invitation(value: Any) -> None:
    _keys(value, ("invitation_id", "attempt_id", "match_run_id", "creator_user_id", "status", "aggregate_version", "updated_at", "expires_at", "snapshot_sha256"))
    for name in ("invitation_id", "attempt_id", "match_run_id", "creator_user_id"):
        _safe_id(value[name])
    _safe_enum(value["status"], _INVITATION_STATUSES)
    _safe_version(value["aggregate_version"])
    _parse_utc(value["updated_at"])
    _parse_utc(value["expires_at"])
    _safe_sha(value["snapshot_sha256"])


def _attempt(value: Any) -> None:
    _keys(value, ("attempt_id", "demand_id", "attempt_no", "status", "aggregate_version", "updated_at"))
    _safe_id(value["attempt_id"])
    _safe_id(value["demand_id"])
    _safe_version(value["attempt_no"])
    _safe_enum(value["status"], _ATTEMPT_STATUSES)
    _safe_version(value["aggregate_version"])
    _parse_utc(value["updated_at"])


def _selection(value: Any) -> None:
    _keys(value, ("selection_id", "attempt_id", "candidate_selector_assignment_id", "candidate_selector_assignment_version", "status", "aggregate_version", "updated_at", "current_invitation_set_sha256", "chosen_invitation_id", "accepted_invitations"))
    for name in ("selection_id", "attempt_id", "candidate_selector_assignment_id"):
        _safe_id(value[name])
    _safe_version(value["candidate_selector_assignment_version"])
    _safe_enum(value["status"], _SELECTION_STATUSES)
    _safe_version(value["aggregate_version"])
    _parse_utc(value["updated_at"])
    _safe_sha(value["current_invitation_set_sha256"])
    if value["chosen_invitation_id"] is not None:
        _safe_id(value["chosen_invitation_id"])
    _list(value["accepted_invitations"], 100, _selection_candidate)
    candidate_ids = [item["invitation_id"] for item in value["accepted_invitations"]]
    if len(candidate_ids) != len(set(candidate_ids)):
        raise ValueError
    if value["chosen_invitation_id"] is not None and value["chosen_invitation_id"] not in set(candidate_ids):
        raise ValueError
    if value["status"] in {"PENDING_CHOICE", "SELECTED"}:
        if value["chosen_invitation_id"] is None:
            raise ValueError
    elif value["chosen_invitation_id"] is not None:
        raise ValueError


def _selection_candidate(value: Any) -> None:
    _keys(value, ("invitation_id", "creator_display_handle", "profile_id", "profile_version_id", "accepted_at", "capability_summary"))
    for name in ("invitation_id", "profile_id", "profile_version_id"):
        _safe_id(value[name])
    _safe_text(value["creator_display_handle"], 120)
    _parse_utc(value["accepted_at"])
    _safe_text(value["capability_summary"], 500)


def _disclosure(value: Any, *, expected_id: str, expected_sha: str) -> None:
    fields = (
        "schema_version", "canonicalization_version", "invitation_id", "attempt_id",
        "demand_id", "demand_version_id", "profile_id", "profile_version_id",
        "organization_preview", "opportunity", "offer", "constraints", "expires_at",
        "demand_content_sha256", "profile_content_sha256", "snapshot_sha256",
    )
    _keys(value, fields)
    if value["schema_version"] != 1 or value["canonicalization_version"] != "invitation-disclosure-json-v1":
        raise ValueError
    for name in ("invitation_id", "attempt_id", "demand_id", "demand_version_id", "profile_id", "profile_version_id"):
        _safe_id(value[name])
    if value["invitation_id"] != expected_id:
        raise ValueError
    _keys(value["organization_preview"], ("organization_id", "display_label"))
    _safe_id(value["organization_preview"]["organization_id"])
    _safe_text(value["organization_preview"]["display_label"], 120)
    _keys(value["opportunity"], ("title", "problem_summary", "deliverable_summaries", "acceptance_summaries"))
    _safe_text(value["opportunity"]["title"], 120)
    _safe_text(value["opportunity"]["problem_summary"], 500)
    _text_list(value["opportunity"]["deliverable_summaries"])
    _text_list(value["opportunity"]["acceptance_summaries"])
    _keys(value["offer"], ("currency", "minimum_amount_minor", "maximum_amount_minor", "schedule_code", "duration_weeks"))
    if not isinstance(value["offer"]["currency"], str) or _CURRENCY.fullmatch(value["offer"]["currency"]) is None:
        raise ValueError
    minimum = value["offer"]["minimum_amount_minor"]
    maximum = value["offer"]["maximum_amount_minor"]
    if type(minimum) is not int or type(maximum) is not int or not 0 <= minimum <= maximum <= 9_007_199_254_740_991:
        raise ValueError
    _safe_disclosure_code(value["offer"]["schedule_code"])
    if type(value["offer"]["duration_weeks"]) is not int or not 1 <= value["offer"]["duration_weeks"] <= 520:
        raise ValueError
    _keys(value["constraints"], ("region_codes", "language_codes", "data_sensitivity_code", "ai_use_code"))
    _code_list(value["constraints"]["region_codes"])
    _code_list(value["constraints"]["language_codes"])
    _safe_enum(value["constraints"]["data_sensitivity_code"], frozenset(("PUBLIC", "INTERNAL", "HIGH", "RESTRICTED")))
    _safe_enum(value["constraints"]["ai_use_code"], frozenset(("PROHIBITED", "OPTIONAL", "REQUIRED")))
    _parse_utc(value["expires_at"])
    _safe_sha(value["demand_content_sha256"])
    _safe_sha(value["profile_content_sha256"])
    _safe_sha(value["snapshot_sha256"])
    if value["snapshot_sha256"] != expected_sha:
        raise ValueError
    signed = dict(value)
    del signed["snapshot_sha256"]
    encoded = json.dumps(signed, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if hashlib.sha256(encoded).hexdigest() != expected_sha:
        raise ValueError


def _keys(value: Any, expected: Tuple[str, ...]) -> None:
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError


def _list(value: Any, maximum: int, validator: Any) -> None:
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError
    for item in value:
        validator(item)


def _nullable_cursor(value: Any) -> None:
    if value is not None and (not isinstance(value, str) or _CURSOR.fullmatch(value) is None):
        raise ValueError


def _safe_id(value: Any) -> None:
    if not isinstance(value, str) or _OPAQUE_ID.fullmatch(value) is None:
        raise ValueError


def _safe_sha(value: Any) -> None:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError


def _safe_version(value: Any) -> None:
    if type(value) is not int or not 1 <= value <= 2_147_483_647:
        raise ValueError


def _safe_enum(value: Any, allowed: frozenset[str]) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError


def _safe_public_text(value: str, *, allow_angle: bool = False) -> bool:
    return (
        unicodedata.normalize("NFC", value) == value
        and all(ord(character) >= 32 and ord(character) not in range(127, 160) for character in value)
        and (allow_angle or ("<" not in value and ">" not in value))
    )


def _safe_text(value: Any, maximum: int) -> None:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or not _safe_public_text(value):
        raise ValueError


def _safe_disclosure_code(value: Any) -> None:
    if not isinstance(value, str) or _DISCLOSURE_CODE.fullmatch(value) is None:
        raise ValueError


def _text_list(value: Any) -> None:
    if not isinstance(value, list) or len(value) > 50:
        raise ValueError
    for item in value:
        _safe_text(item, 500)


def _code_list(value: Any) -> None:
    if not isinstance(value, list) or len(value) > 100 or len(value) != len(set(value)):
        raise ValueError
    for item in value:
        _safe_disclosure_code(item)


def _parse_utc(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError
    return parsed


def _utc_text(value: Any) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise _HttpRejection("COMMAND_OUTCOME_UNKNOWN")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


__all__ = [
    "MATCHING_HTTP_ROUTES",
    "MatchingHttpActor",
    "MatchingHttpApplicationDispatcher",
    "MatchingHttpCommandActorPort",
    "MatchingHttpFamily",
    "MatchingHttpPresenterBindings",
    "MatchingHttpProjection",
    "MatchingHttpProjectionPort",
    "MatchingHttpRequest",
    "MatchingHttpResponse",
    "MatchingHttpReviewerAssignmentPort",
    "MatchingHttpRoute",
    "MatchingHttpRouteNotFound",
    "is_matching_public_path",
    "matching_http_error",
    "resolve_matching_http_route",
]
