"""Validated IAM application queries for the nine public read operations."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import hashlib
import hmac
import json
import unicodedata
from typing import Any, Callable, Mapping, Optional, Sequence, Tuple

from ...utc import parse_utc_timestamp
from ..read_model_registry import (
    PAGED_READ_QUERY_SHAPE_DIGESTS,
    READ_STATEMENT_BUDGETS,
)
from ..domain.errors import IamError
from ..ports.access_invitation_capability import (
    AccessInvitationCapabilityPort,
    VerifiedAccessInvitationCapability,
)
from ..ports.read_models import (
    IamReadModelRepository,
    ReadModelClock,
    ReadModelCursorClaims,
    ReadModelCursorCodec,
    ReadModelCursorInvalidError,
    ReadModelCursorUnavailableError,
    ReadModelSnapshot,
    ReadModelStorageUnavailableError,
    ReadModelTelemetryEvent,
    ReadModelTelemetryPort,
    ReadPageWindow,
    SessionBootstrapCsrfMaterial,
    SessionBootstrapCsrfPort,
    SessionBootstrapCsrfUnavailableError,
    freeze_fact_object,
)


READ_MODEL_BEHAVIOR_NOT_AVAILABLE = "IAM_READ_MODEL_BEHAVIOR_NOT_AVAILABLE"

_SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
_POLICY_UNAVAILABLE = "POLICY_CONFIGURATION_UNAVAILABLE"
_RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
_AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
_SESSION_EXPIRED = "SESSION_EXPIRED"
_INVITATION_UNAVAILABLE = "ACCESS_INVITATION_UNAVAILABLE"
_INVALID_REQUEST = "INVALID_REQUEST"

_PAGED_OPERATIONS = {
    "listMyConsentGrants",
    "listMySessions",
    "listOrganizationAccessInvitations",
    "listOrganizationMemberships",
}
_CURSOR_VERSION = "iam-read-cursor-v1"
_CURSOR_TTL = timedelta(minutes=15)
_QUERY_SHAPE_DIGESTS = PAGED_READ_QUERY_SHAPE_DIGESTS
_JSON_TIMESTAMP_FIELDS = frozenset(
    {
        "accepted_at",
        "created_at",
        "effective_at",
        "effective_until",
        "expires_at",
        "granted_at",
        "last_activity_at",
        "not_after",
        "revoked_at",
        "updated_at",
        "withdrawn_at",
    }
)


class ReadCachePolicy(str, Enum):
    NO_STORE = "no-store"
    PUBLIC_IMMUTABLE = "public, max-age=31536000, immutable"


@dataclass(frozen=True)
class ReadActor:
    actor_user_id: str
    current_session_id: str
    trace_id: str = ""


@dataclass(frozen=True)
class PageRequest:
    limit: int = 25
    cursor: Optional[str] = field(default=None, repr=False)


@dataclass(frozen=True)
class GetSessionBootstrapQuery:
    actor: ReadActor
    raw_session_handle: str = field(repr=False)


@dataclass(frozen=True)
class InspectAccessInvitationQuery:
    access_invitation_token: str = field(repr=False)
    trace_id: str = ""


@dataclass(frozen=True)
class GetPolicyBundleQuery:
    policy_bundle_id: str
    trace_id: str = ""


@dataclass(frozen=True)
class GetMeQuery:
    actor: ReadActor


@dataclass(frozen=True)
class ListMyConsentGrantsQuery:
    actor: ReadActor
    page: PageRequest = PageRequest()


@dataclass(frozen=True)
class ListMySessionsQuery:
    actor: ReadActor
    page: PageRequest = PageRequest()


@dataclass(frozen=True)
class GetOrganizationSummaryQuery:
    actor: ReadActor
    organization_id: str


@dataclass(frozen=True)
class ListOrganizationAccessInvitationsQuery:
    actor: ReadActor
    organization_id: str
    page: PageRequest = PageRequest()


@dataclass(frozen=True)
class ListOrganizationMembershipsQuery:
    actor: ReadActor
    organization_id: str
    page: PageRequest = PageRequest()


@dataclass(frozen=True)
class ReadModelResponse:
    operation_id: str
    json_body: Any = field(repr=False)
    entity_tag: Optional[str]
    cache_policy: ReadCachePolicy

    def body_copy(self) -> dict[str, object]:
        from ..ports.read_models import thaw_fact_object

        return thaw_fact_object(self.json_body)


@dataclass(frozen=True)
class _AuthorityFacts:
    user: Mapping[str, Any]
    session: Mapping[str, Any]
    family: Mapping[str, Any]


@dataclass(frozen=True)
class _PolicyView:
    body: Mapping[str, Any]
    selector: Mapping[str, Any]
    bundle: Mapping[str, Any]
    documents: Tuple[Mapping[str, Any], ...]
    offers: Tuple[Mapping[str, Any], ...]


@dataclass(frozen=True)
class _PageState:
    window: ReadPageWindow
    claims: Optional[ReadModelCursorClaims]


class _ReadModelHandler:
    def __init__(
        self,
        *,
        repository: IamReadModelRepository,
        clock: ReadModelClock,
        telemetry: Optional[ReadModelTelemetryPort] = None,
    ) -> None:
        self._repository = repository
        self._clock = clock
        self._telemetry = telemetry

    def _now(self) -> datetime:
        return _utc(self._clock.now(), _SERVICE_UNAVAILABLE)

    def _read(
        self,
        operation_id: str,
        action: Callable[[], ReadModelSnapshot],
    ) -> tuple[dict[str, Any], datetime]:
        try:
            snapshot = action()
        except ReadModelStorageUnavailableError as error:
            raise IamError(_SERVICE_UNAVAILABLE) from error
        if not isinstance(snapshot, ReadModelSnapshot):
            raise IamError(_SERVICE_UNAVAILABLE)
        transaction_time = _utc(snapshot.transaction_time, _SERVICE_UNAVAILABLE)
        if (
            not _is_int(snapshot.statement_count)
            or snapshot.statement_count < 1
            or snapshot.statement_count > READ_STATEMENT_BUDGETS[operation_id]
        ):
            raise IamError(_SERVICE_UNAVAILABLE)
        facts = snapshot.facts_copy()
        if not isinstance(facts, dict):
            raise IamError(_SERVICE_UNAVAILABLE)
        return facts, transaction_time

    def _execute(
        self,
        *,
        operation_id: str,
        trace_id: str,
        authenticated: bool,
        cursor_present: bool,
        action: Callable[[], ReadModelResponse],
    ) -> ReadModelResponse:
        try:
            response = action()
        except IamError as error:
            self._record(
                operation_id=operation_id,
                trace_id=trace_id,
                outcome_code=error.code,
                authenticated=authenticated,
                cursor_present=cursor_present,
                row_count=0,
            )
            raise
        body = response.body_copy()
        items = body.get("items")
        row_count = len(items) if isinstance(items, list) else 1
        self._record(
            operation_id=operation_id,
            trace_id=trace_id,
            outcome_code="OK",
            authenticated=authenticated,
            cursor_present=cursor_present,
            row_count=row_count,
        )
        return response

    def _record(
        self,
        *,
        operation_id: str,
        trace_id: str,
        outcome_code: str,
        authenticated: bool,
        cursor_present: bool,
        row_count: int,
    ) -> None:
        if self._telemetry is None:
            return
        if row_count == 0:
            row_bucket = "0"
        elif row_count == 1:
            row_bucket = "1"
        else:
            row_bucket = "2-10" if row_count <= 10 else "11+"
        self._telemetry.record(
            ReadModelTelemetryEvent(
                operation_id=operation_id,
                outcome_code=outcome_code,
                authenticated=authenticated,
                cursor_present=cursor_present,
                row_count_bucket=row_bucket,
                latency_bucket="in-process",
                trace_id=trace_id,
            )
        )


class GetSessionBootstrapHandler(_ReadModelHandler):
    def __init__(
        self,
        *,
        repository: IamReadModelRepository,
        clock: ReadModelClock,
        csrf_tokens: SessionBootstrapCsrfPort,
        telemetry: Optional[ReadModelTelemetryPort] = None,
    ) -> None:
        super().__init__(repository=repository, clock=clock, telemetry=telemetry)
        self._csrf_tokens = csrf_tokens

    def handle(self, query: GetSessionBootstrapQuery) -> ReadModelResponse:
        return self._execute(
            operation_id="getSessionBootstrap",
            trace_id=query.actor.trace_id,
            authenticated=True,
            cursor_present=False,
            action=lambda: self._handle(query),
        )

    def _handle(self, query: GetSessionBootstrapQuery) -> ReadModelResponse:
        now = self._now()
        facts, transaction_time = self._read(
            "getSessionBootstrap",
            lambda: self._repository.read_session_bootstrap(
                actor_user_id=query.actor.actor_user_id,
                session_id=query.actor.current_session_id,
            ),
        )
        authority = _validate_authority(
            facts,
            query.actor,
            transaction_time,
            allowed_user_statuses={"PENDING_ENROLLMENT", "ACTIVE"},
        )
        session = authority.session
        material = SessionBootstrapCsrfMaterial(
            session_id=_text(session.get("session_id"), _SERVICE_UNAVAILABLE),
            generation=_positive_int(session.get("generation"), _SERVICE_UNAVAILABLE),
            csrf_salt=_bytes(session.get("csrf_salt"), _SERVICE_UNAVAILABLE),
            csrf_key_id=_text(session.get("csrf_key_id"), _SERVICE_UNAVAILABLE),
            csrf_digest=_bytes(session.get("csrf_digest"), _SERVICE_UNAVAILABLE),
        )
        try:
            csrf_token = self._csrf_tokens.derive(
                raw_session_handle=query.raw_session_handle,
                material=material,
            )
        except SessionBootstrapCsrfUnavailableError as error:
            raise IamError(_SERVICE_UNAVAILABLE) from error
        if not isinstance(csrf_token, str) or not csrf_token:
            raise IamError(_SERVICE_UNAVAILABLE)
        body = {
            "session": _session_dto(session, is_current=True, at=transaction_time),
            "user_status": _text(authority.user.get("status"), _SERVICE_UNAVAILABLE),
            "csrf_token": csrf_token,
        }
        return _response(
            "getSessionBootstrap",
            body,
            entity_tag=None,
            cache_policy=ReadCachePolicy.NO_STORE,
        )


class InspectAccessInvitationHandler(_ReadModelHandler):
    def __init__(
        self,
        *,
        repository: IamReadModelRepository,
        clock: ReadModelClock,
        invitation_capabilities: AccessInvitationCapabilityPort,
        telemetry: Optional[ReadModelTelemetryPort] = None,
    ) -> None:
        super().__init__(repository=repository, clock=clock, telemetry=telemetry)
        self._invitation_capabilities = invitation_capabilities

    def handle(self, query: InspectAccessInvitationQuery) -> ReadModelResponse:
        return self._execute(
            operation_id="inspectAccessInvitation",
            trace_id=query.trace_id,
            authenticated=False,
            cursor_present=False,
            action=lambda: self._handle(query),
        )

    def _handle(self, query: InspectAccessInvitationQuery) -> ReadModelResponse:
        now = self._now()
        try:
            capability = self._invitation_capabilities.verify(
                access_invitation_token=query.access_invitation_token,
                now=now,
            )
        except ValueError as error:
            raise IamError(_INVITATION_UNAVAILABLE) from error
        _validate_capability(capability, now)
        facts, transaction_time = self._read(
            "inspectAccessInvitation",
            lambda: self._repository.read_invitation_preview(capability=capability),
        )
        invitation = _mapping(facts.get("invitation"), _INVITATION_UNAVAILABLE)
        if invitation.get("status") != "ISSUED":
            raise IamError(_INVITATION_UNAVAILABLE)
        _validate_invitation_capability_binding(invitation, capability, transaction_time)
        organization = _mapping(facts.get("organization"), _INVITATION_UNAVAILABLE)
        if invitation.get("organization_id") != organization.get("organization_id"):
            raise IamError(_INVITATION_UNAVAILABLE)
        if organization.get("status") != "ACTIVE":
            raise IamError(_INVITATION_UNAVAILABLE)
        _organization_dto(organization)
        selector_digest = _sha256(
            invitation.get("policy_selector_digest"), _POLICY_UNAVAILABLE
        )
        policy = _validate_policy(
            facts.get("policy"),
            at=transaction_time,
            expected_selector_digest=selector_digest,
            requested_bundle_id=None,
            public_lookup=False,
        )
        _validate_invitation_policy_shape(invitation, policy.selector)
        version = _positive_int(invitation.get("aggregate_version"), _SERVICE_UNAVAILABLE)
        body = {
            "invitation_id": _text(invitation.get("invitation_id"), _SERVICE_UNAVAILABLE),
            "purpose": _text(invitation.get("purpose"), _SERVICE_UNAVAILABLE),
            "organization": {
                "public_name": _text(
                    organization.get("public_name"), _SERVICE_UNAVAILABLE
                )
            },
            "target_role": _text(invitation.get("target_role"), _SERVICE_UNAVAILABLE),
            "expires_at": _timestamp(
                _utc(invitation.get("expires_at"), _SERVICE_UNAVAILABLE)
            ),
            "required_policy_bundle_id": _text(
                policy.bundle.get("policy_bundle_id"), _POLICY_UNAVAILABLE
            ),
            "status": "ISSUED",
            "aggregate_version": version,
            "entity_tag": _etag(version),
        }
        return _response(
            "inspectAccessInvitation",
            body,
            entity_tag=_etag(version),
            cache_policy=ReadCachePolicy.NO_STORE,
        )


class GetPolicyBundleHandler(_ReadModelHandler):
    def handle(self, query: GetPolicyBundleQuery) -> ReadModelResponse:
        return self._execute(
            operation_id="getPolicyBundle",
            trace_id=query.trace_id,
            authenticated=False,
            cursor_present=False,
            action=lambda: self._handle(query),
        )

    def _handle(self, query: GetPolicyBundleQuery) -> ReadModelResponse:
        self._now()
        facts, transaction_time = self._read(
            "getPolicyBundle",
            lambda: self._repository.read_public_policy_bundle(
                policy_bundle_id=query.policy_bundle_id
            ),
        )
        policy = _validate_policy(
            facts,
            at=transaction_time,
            expected_selector_digest=None,
            requested_bundle_id=query.policy_bundle_id,
            public_lookup=True,
        )
        version = _positive_int(
            policy.bundle.get("aggregate_version"), _POLICY_UNAVAILABLE
        )
        return _response(
            "getPolicyBundle",
            policy.body,
            entity_tag=_etag(version),
            cache_policy=ReadCachePolicy.PUBLIC_IMMUTABLE,
        )


class GetMeHandler(_ReadModelHandler):
    def handle(self, query: GetMeQuery) -> ReadModelResponse:
        return self._execute(
            operation_id="getMe",
            trace_id=query.actor.trace_id,
            authenticated=True,
            cursor_present=False,
            action=lambda: self._handle(query),
        )

    def _handle(self, query: GetMeQuery) -> ReadModelResponse:
        self._now()
        facts, transaction_time = self._read(
            "getMe",
            lambda: self._repository.read_me(
                actor_user_id=query.actor.actor_user_id,
                session_id=query.actor.current_session_id,
            ),
        )
        authority = _validate_authority(
            facts,
            query.actor,
            transaction_time,
            allowed_user_statuses={"PENDING_ENROLLMENT", "ACTIVE"},
        )
        body = project_canonical_me_dto(facts, at=transaction_time)
        version = _positive_int(authority.user.get("aggregate_version"), _SERVICE_UNAVAILABLE)
        return _response(
            "getMe",
            body,
            entity_tag=_etag(version),
            cache_policy=ReadCachePolicy.NO_STORE,
        )


class _PagedReadModelHandler(_ReadModelHandler):
    def __init__(
        self,
        *,
        repository: IamReadModelRepository,
        clock: ReadModelClock,
        cursor_codec: ReadModelCursorCodec,
        telemetry: Optional[ReadModelTelemetryPort] = None,
    ) -> None:
        super().__init__(repository=repository, clock=clock, telemetry=telemetry)
        self._cursor_codec = cursor_codec

    def _page_state(
        self,
        *,
        operation_id: str,
        page: PageRequest,
        actor_user_id: str,
        organization_id: Optional[str],
        now: datetime,
    ) -> _PageState:
        if not _is_int(page.limit) or not 1 <= page.limit <= 100:
            raise IamError(_INVALID_REQUEST)
        if page.cursor is None:
            return _PageState(window=ReadPageWindow(limit=page.limit), claims=None)
        if not isinstance(page.cursor, str) or not page.cursor or len(page.cursor) > 2048:
            raise IamError(_INVALID_REQUEST)
        try:
            claims = self._cursor_codec.decode(page.cursor)
        except ReadModelCursorInvalidError as error:
            raise IamError(_INVALID_REQUEST) from error
        except ReadModelCursorUnavailableError as error:
            raise IamError(_SERVICE_UNAVAILABLE) from error
        _validate_cursor_claims(
            claims,
            operation_id=operation_id,
            actor_user_id=actor_user_id,
            organization_id=organization_id,
            page_limit=page.limit,
            now=now,
        )
        return _PageState(
            window=ReadPageWindow(
                limit=page.limit,
                snapshot_at=claims.snapshot_at,
                after_created_at=claims.after_created_at,
                after_id=claims.after_id,
            ),
            claims=claims,
        )

    def _project_page(
        self,
        *,
        operation_id: str,
        facts: Mapping[str, Any],
        transaction_time: datetime,
        page_state: _PageState,
        actor_user_id: str,
        organization_id: Optional[str],
        now: datetime,
        projector: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    ) -> Mapping[str, Any]:
        rows, snapshot_at, next_cursor = _validated_page_rows(
            facts,
            transaction_time=transaction_time,
            page_state=page_state,
            operation_id=operation_id,
            actor_user_id=actor_user_id,
            organization_id=organization_id,
            now=now,
            cursor_codec=self._cursor_codec,
        )
        del snapshot_at
        return {
            "items": [dict(projector(row)) for row in rows],
            "page": {"next_cursor": next_cursor},
        }


class ListMyConsentGrantsHandler(_PagedReadModelHandler):
    def handle(self, query: ListMyConsentGrantsQuery) -> ReadModelResponse:
        return self._execute(
            operation_id="listMyConsentGrants",
            trace_id=query.actor.trace_id,
            authenticated=True,
            cursor_present=query.page.cursor is not None,
            action=lambda: self._handle(query),
        )

    def _handle(self, query: ListMyConsentGrantsQuery) -> ReadModelResponse:
        request_now = self._now()
        page_state = self._page_state(
            operation_id="listMyConsentGrants",
            page=query.page,
            actor_user_id=query.actor.actor_user_id,
            organization_id=None,
            now=request_now,
        )
        facts, transaction_time = self._read(
            "listMyConsentGrants",
            lambda: self._repository.list_my_consent_grants(
                actor_user_id=query.actor.actor_user_id,
                session_id=query.actor.current_session_id,
                window=page_state.window,
            ),
        )
        response_now = self._now()
        actor_facts = _mapping(facts.get("actor"), _SERVICE_UNAVAILABLE)
        _validate_authority(
            actor_facts,
            query.actor,
            transaction_time,
            allowed_user_statuses={"ACTIVE"},
        )
        body = self._project_page(
            operation_id="listMyConsentGrants",
            facts=facts,
            transaction_time=transaction_time,
            page_state=page_state,
            actor_user_id=query.actor.actor_user_id,
            organization_id=None,
            now=response_now,
            projector=lambda row: _consent_grant_dto(
                row, query.actor.actor_user_id, transaction_time
            ),
        )
        return _response(
            "listMyConsentGrants",
            body,
            entity_tag=None,
            cache_policy=ReadCachePolicy.NO_STORE,
        )


class ListMySessionsHandler(_PagedReadModelHandler):
    def handle(self, query: ListMySessionsQuery) -> ReadModelResponse:
        return self._execute(
            operation_id="listMySessions",
            trace_id=query.actor.trace_id,
            authenticated=True,
            cursor_present=query.page.cursor is not None,
            action=lambda: self._handle(query),
        )

    def _handle(self, query: ListMySessionsQuery) -> ReadModelResponse:
        request_now = self._now()
        page_state = self._page_state(
            operation_id="listMySessions",
            page=query.page,
            actor_user_id=query.actor.actor_user_id,
            organization_id=None,
            now=request_now,
        )
        facts, transaction_time = self._read(
            "listMySessions",
            lambda: self._repository.list_my_sessions(
                actor_user_id=query.actor.actor_user_id,
                session_id=query.actor.current_session_id,
                window=page_state.window,
            ),
        )
        response_now = self._now()
        actor_facts = _mapping(facts.get("actor"), _SERVICE_UNAVAILABLE)
        _validate_authority(
            actor_facts,
            query.actor,
            transaction_time,
            allowed_user_statuses={"ACTIVE"},
        )
        body = self._project_page(
            operation_id="listMySessions",
            facts=facts,
            transaction_time=transaction_time,
            page_state=page_state,
            actor_user_id=query.actor.actor_user_id,
            organization_id=None,
            now=response_now,
            projector=lambda row: _session_list_dto(
                row,
                actor_user_id=query.actor.actor_user_id,
                current_session_id=query.actor.current_session_id,
                at=transaction_time,
            ),
        )
        return _response(
            "listMySessions",
            body,
            entity_tag=None,
            cache_policy=ReadCachePolicy.NO_STORE,
        )


class GetOrganizationSummaryHandler(_ReadModelHandler):
    def handle(self, query: GetOrganizationSummaryQuery) -> ReadModelResponse:
        return self._execute(
            operation_id="getOrganizationSummary",
            trace_id=query.actor.trace_id,
            authenticated=True,
            cursor_present=False,
            action=lambda: self._handle(query),
        )

    def _handle(self, query: GetOrganizationSummaryQuery) -> ReadModelResponse:
        self._now()
        facts, transaction_time = self._read(
            "getOrganizationSummary",
            lambda: self._repository.read_organization_summary(
                actor_user_id=query.actor.actor_user_id,
                session_id=query.actor.current_session_id,
                organization_id=query.organization_id,
            ),
        )
        actor_facts = _mapping(facts.get("actor"), _SERVICE_UNAVAILABLE)
        organization = _organization_authority(
            actor_facts=actor_facts,
            target=facts.get("organization"),
            actor=query.actor,
            organization_id=query.organization_id,
            at=transaction_time,
            require_admin=False,
        )
        body = _organization_dto(organization)
        version = _positive_int(
            organization.get("aggregate_version"), _SERVICE_UNAVAILABLE
        )
        return _response(
            "getOrganizationSummary",
            body,
            entity_tag=_etag(version),
            cache_policy=ReadCachePolicy.NO_STORE,
        )


class ListOrganizationAccessInvitationsHandler(_PagedReadModelHandler):
    def handle(
        self, query: ListOrganizationAccessInvitationsQuery
    ) -> ReadModelResponse:
        return self._execute(
            operation_id="listOrganizationAccessInvitations",
            trace_id=query.actor.trace_id,
            authenticated=True,
            cursor_present=query.page.cursor is not None,
            action=lambda: self._handle(query),
        )

    def _handle(
        self, query: ListOrganizationAccessInvitationsQuery
    ) -> ReadModelResponse:
        request_now = self._now()
        page_state = self._page_state(
            operation_id="listOrganizationAccessInvitations",
            page=query.page,
            actor_user_id=query.actor.actor_user_id,
            organization_id=query.organization_id,
            now=request_now,
        )
        facts, transaction_time = self._read(
            "listOrganizationAccessInvitations",
            lambda: self._repository.list_organization_access_invitations(
                actor_user_id=query.actor.actor_user_id,
                session_id=query.actor.current_session_id,
                organization_id=query.organization_id,
                window=page_state.window,
            ),
        )
        response_now = self._now()
        actor_facts = _mapping(facts.get("actor"), _SERVICE_UNAVAILABLE)
        _organization_authority(
            actor_facts=actor_facts,
            target=facts.get("organization"),
            actor=query.actor,
            organization_id=query.organization_id,
            at=transaction_time,
            require_admin=True,
        )
        body = self._project_page(
            operation_id="listOrganizationAccessInvitations",
            facts=facts,
            transaction_time=transaction_time,
            page_state=page_state,
            actor_user_id=query.actor.actor_user_id,
            organization_id=query.organization_id,
            now=response_now,
            projector=lambda row: _invitation_admin_dto(
                row, query.organization_id, transaction_time
            ),
        )
        return _response(
            "listOrganizationAccessInvitations",
            body,
            entity_tag=None,
            cache_policy=ReadCachePolicy.NO_STORE,
        )


class ListOrganizationMembershipsHandler(_PagedReadModelHandler):
    def handle(
        self, query: ListOrganizationMembershipsQuery
    ) -> ReadModelResponse:
        return self._execute(
            operation_id="listOrganizationMemberships",
            trace_id=query.actor.trace_id,
            authenticated=True,
            cursor_present=query.page.cursor is not None,
            action=lambda: self._handle(query),
        )

    def _handle(self, query: ListOrganizationMembershipsQuery) -> ReadModelResponse:
        request_now = self._now()
        page_state = self._page_state(
            operation_id="listOrganizationMemberships",
            page=query.page,
            actor_user_id=query.actor.actor_user_id,
            organization_id=query.organization_id,
            now=request_now,
        )
        facts, transaction_time = self._read(
            "listOrganizationMemberships",
            lambda: self._repository.list_organization_memberships(
                actor_user_id=query.actor.actor_user_id,
                session_id=query.actor.current_session_id,
                organization_id=query.organization_id,
                window=page_state.window,
            ),
        )
        response_now = self._now()
        actor_facts = _mapping(facts.get("actor"), _SERVICE_UNAVAILABLE)
        _organization_authority(
            actor_facts=actor_facts,
            target=facts.get("organization"),
            actor=query.actor,
            organization_id=query.organization_id,
            at=transaction_time,
            require_admin=True,
        )
        body = self._project_page(
            operation_id="listOrganizationMemberships",
            facts=facts,
            transaction_time=transaction_time,
            page_state=page_state,
            actor_user_id=query.actor.actor_user_id,
            organization_id=query.organization_id,
            now=response_now,
            projector=lambda row: _membership_admin_dto(
                row, query.organization_id, transaction_time
            ),
        )
        return _response(
            "listOrganizationMemberships",
            body,
            entity_tag=None,
            cache_policy=ReadCachePolicy.NO_STORE,
        )


def _response(
    operation_id: str,
    body: Mapping[str, Any],
    *,
    entity_tag: Optional[str],
    cache_policy: ReadCachePolicy,
) -> ReadModelResponse:
    return ReadModelResponse(
        operation_id=operation_id,
        json_body=freeze_fact_object(body),
        entity_tag=entity_tag,
        cache_policy=cache_policy,
    )


def _validate_authority(
    facts: Mapping[str, Any],
    actor: ReadActor,
    at: datetime,
    *,
    allowed_user_statuses: set[str],
) -> _AuthorityFacts:
    user = _mapping(facts.get("user"), _SERVICE_UNAVAILABLE)
    session = _mapping(facts.get("session"), _SERVICE_UNAVAILABLE)
    family = _mapping(facts.get("family"), _SERVICE_UNAVAILABLE)
    actor_user_id = _text(actor.actor_user_id, _SERVICE_UNAVAILABLE)
    actor_session_id = _text(actor.current_session_id, _SERVICE_UNAVAILABLE)
    if (
        user.get("user_id") != actor_user_id
        or session.get("session_id") != actor_session_id
        or session.get("user_id") != actor_user_id
        or family.get("user_id") != actor_user_id
        or session.get("family_id") != family.get("family_id")
    ):
        raise IamError(_SERVICE_UNAVAILABLE)
    user_status = user.get("status")
    if user_status not in allowed_user_statuses:
        raise IamError(_AUTHENTICATION_REQUIRED)
    if session.get("status") != "ACTIVE" or family.get("status") != "ACTIVE":
        raise IamError(_AUTHENTICATION_REQUIRED)
    generation = _positive_int(session.get("generation"), _SERVICE_UNAVAILABLE)
    if family.get("current_generation") != generation:
        raise IamError(_AUTHENTICATION_REQUIRED)
    created_at, last_activity_at, idle_expires_at, absolute_expires_at = (
        _session_times(session)
    )
    if not created_at <= last_activity_at < idle_expires_at <= absolute_expires_at:
        raise IamError(_SERVICE_UNAVAILABLE)
    if at >= idle_expires_at or at >= absolute_expires_at:
        raise IamError(_SESSION_EXPIRED)
    return _AuthorityFacts(user=user, session=session, family=family)


def _session_times(
    session: Mapping[str, Any],
) -> tuple[datetime, datetime, datetime, datetime]:
    return (
        _utc(session.get("created_at"), _SERVICE_UNAVAILABLE),
        _utc(session.get("last_activity_at"), _SERVICE_UNAVAILABLE),
        _utc(session.get("idle_expires_at"), _SERVICE_UNAVAILABLE),
        _utc(session.get("absolute_expires_at"), _SERVICE_UNAVAILABLE),
    )


def _session_dto(
    session: Mapping[str, Any], *, is_current: bool, at: datetime
) -> Mapping[str, Any]:
    created_at, last_activity_at, idle_expires_at, absolute_expires_at = (
        _session_times(session)
    )
    status = _text(session.get("status"), _SERVICE_UNAVAILABLE)
    if status not in {"ACTIVE", "REVOKED", "EXPIRED"}:
        raise IamError(_SERVICE_UNAVAILABLE)
    if status == "ACTIVE" and (at >= idle_expires_at or at >= absolute_expires_at):
        status = "EXPIRED"
    return {
        "session_id": _text(session.get("session_id"), _SERVICE_UNAVAILABLE),
        "created_at": _timestamp(created_at),
        "last_activity_at": _timestamp(last_activity_at),
        "expires_at": _timestamp(min(idle_expires_at, absolute_expires_at)),
        "is_current": is_current,
        "device_label": _text(session.get("device_label"), _SERVICE_UNAVAILABLE),
        "status": status,
    }


def _session_list_dto(
    session: Mapping[str, Any],
    *,
    actor_user_id: str,
    current_session_id: str,
    at: datetime,
) -> Mapping[str, Any]:
    if session.get("user_id") != actor_user_id:
        raise IamError(_SERVICE_UNAVAILABLE)
    _positive_int(session.get("generation"), _SERVICE_UNAVAILABLE)
    _text(session.get("family_id"), _SERVICE_UNAVAILABLE)
    created_at, last_activity_at, idle_expires_at, absolute_expires_at = (
        _session_times(session)
    )
    if not created_at <= last_activity_at < idle_expires_at <= absolute_expires_at:
        raise IamError(_SERVICE_UNAVAILABLE)
    return _session_dto(
        session,
        is_current=session.get("session_id") == current_session_id,
        at=at,
    )


def _validate_capability(
    capability: VerifiedAccessInvitationCapability, now: datetime
) -> None:
    if not isinstance(capability, VerifiedAccessInvitationCapability):
        raise IamError(_INVITATION_UNAVAILABLE)
    _text(capability.invitation_id, _INVITATION_UNAVAILABLE)
    _text(capability.invitation_nonce, _INVITATION_UNAVAILABLE)
    _text(capability.token_key_id, _INVITATION_UNAVAILABLE)
    _text(capability.token_format_version, _INVITATION_UNAVAILABLE)
    expires_at = _utc(capability.expires_at, _INVITATION_UNAVAILABLE)
    if now >= expires_at:
        raise IamError(_INVITATION_UNAVAILABLE)


def _validate_invitation_capability_binding(
    invitation: Mapping[str, Any],
    capability: VerifiedAccessInvitationCapability,
    at: datetime,
) -> None:
    expires_at = _utc(invitation.get("expires_at"), _INVITATION_UNAVAILABLE)
    if (
        invitation.get("invitation_id") != capability.invitation_id
        or invitation.get("token_nonce") != capability.invitation_nonce
        or invitation.get("token_key_id") != capability.token_key_id
        or invitation.get("token_format_version") != capability.token_format_version
        or expires_at != capability.expires_at
        or at >= expires_at
    ):
        raise IamError(_INVITATION_UNAVAILABLE)
    if (
        invitation.get("purpose") != "ORGANIZATION_MEMBERSHIP"
        or invitation.get("target_scope") != "ORGANIZATION"
        or invitation.get("organization_id") is None
        or invitation.get("target_role") not in {"ORG_ADMIN", "DEMAND_OWNER"}
        or not isinstance(invitation.get("is_initial_admin"), bool)
    ):
        raise IamError(_INVITATION_UNAVAILABLE)
    _positive_int(invitation.get("aggregate_version"), _SERVICE_UNAVAILABLE)


def _validate_invitation_policy_shape(
    invitation: Mapping[str, Any], selector: Mapping[str, Any]
) -> None:
    if (
        selector.get("access_purpose") != invitation.get("purpose")
        or selector.get("target_role") != invitation.get("target_role")
        or selector.get("scope_type") != "ORGANIZATION_ROLE"
    ):
        raise IamError(_POLICY_UNAVAILABLE)


def _validate_policy(
    value: object,
    *,
    at: datetime,
    expected_selector_digest: Optional[str],
    requested_bundle_id: Optional[str],
    public_lookup: bool,
) -> _PolicyView:
    if public_lookup and (
        value is None or (isinstance(value, Mapping) and not value)
    ):
        raise IamError(_RESOURCE_NOT_FOUND)
    resource = _mapping(value, _POLICY_UNAVAILABLE)
    selector = _mapping(resource.get("selector"), _POLICY_UNAVAILABLE)
    bundle = _mapping(resource.get("bundle"), _POLICY_UNAVAILABLE)
    selector_digest = _sha256(selector.get("selector_digest"), _POLICY_UNAVAILABLE)
    if expected_selector_digest is not None and selector_digest != expected_selector_digest:
        raise IamError(_POLICY_UNAVAILABLE)
    if selector.get("canonicalization_version") != "policy-selector-json-v1":
        raise IamError(_POLICY_UNAVAILABLE)
    selector_payload = {
        "access_purpose": _text(
            selector.get("access_purpose"), _POLICY_UNAVAILABLE
        ),
        "scope_type": _text(selector.get("scope_type"), _POLICY_UNAVAILABLE),
        "target_role": _text(selector.get("target_role"), _POLICY_UNAVAILABLE),
        "jurisdiction": unicodedata.normalize(
            "NFC", _text(selector.get("jurisdiction"), _POLICY_UNAVAILABLE)
        ),
        "locale": unicodedata.normalize(
            "NFC", _text(selector.get("locale"), _POLICY_UNAVAILABLE)
        ),
    }
    canonical_selector = json.dumps(
        selector_payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if not hmac.compare_digest(
        selector_digest, hashlib.sha256(canonical_selector).hexdigest()
    ):
        raise IamError(_POLICY_UNAVAILABLE)
    current_bundle_id = _text(
        selector.get("current_bundle_id"), _POLICY_UNAVAILABLE
    )
    bundle_id = _text(bundle.get("policy_bundle_id"), _POLICY_UNAVAILABLE)
    if requested_bundle_id is not None and bundle_id != requested_bundle_id:
        raise IamError(_SERVICE_UNAVAILABLE)
    if bundle.get("status") != "ACTIVE":
        if public_lookup:
            raise IamError(_RESOURCE_NOT_FOUND)
        raise IamError(_POLICY_UNAVAILABLE)
    if (
        current_bundle_id != bundle_id
        or bundle.get("selector_digest") != selector_digest
    ):
        raise IamError(_POLICY_UNAVAILABLE)
    effective_at = _utc(bundle.get("effective_at"), _POLICY_UNAVAILABLE)
    effective_until_value = bundle.get("effective_until")
    effective_until = (
        None
        if effective_until_value is None
        else _utc(effective_until_value, _POLICY_UNAVAILABLE)
    )
    if effective_at > at or (effective_until is not None and at >= effective_until):
        if public_lookup:
            raise IamError(_RESOURCE_NOT_FOUND)
        raise IamError(_POLICY_UNAVAILABLE)
    version = _positive_int(bundle.get("aggregate_version"), _POLICY_UNAVAILABLE)

    raw_documents = _list(resource.get("documents"), _POLICY_UNAVAILABLE)
    if not raw_documents or len(raw_documents) > 20:
        raise IamError(_POLICY_UNAVAILABLE)
    documents: list[Mapping[str, Any]] = []
    document_ids: set[str] = set()
    identities: set[tuple[str, str, str, str]] = set()
    expected_position = 1
    for raw_document in raw_documents:
        document = _mapping(raw_document, _POLICY_UNAVAILABLE)
        document_id = _text(document.get("document_id"), _POLICY_UNAVAILABLE)
        identity = (
            _text(document.get("kind"), _POLICY_UNAVAILABLE),
            _text(document.get("locale"), _POLICY_UNAVAILABLE),
            _text(document.get("jurisdiction"), _POLICY_UNAVAILABLE),
            _text(document.get("semantic_version"), _POLICY_UNAVAILABLE),
        )
        if (
            document_id in document_ids
            or identity in identities
            or document.get("position") != expected_position
            or document.get("bundle_id") != bundle_id
            or document.get("status") != "ACTIVE"
            or document.get("locale") != selector_payload["locale"]
            or document.get("jurisdiction") != selector_payload["jurisdiction"]
            or not isinstance(document.get("required"), bool)
        ):
            raise IamError(_POLICY_UNAVAILABLE)
        body = _text(document.get("canonical_body"), _POLICY_UNAVAILABLE)
        content_sha256 = _sha256(
            document.get("content_sha256"), _POLICY_UNAVAILABLE
        )
        if not hmac.compare_digest(
            content_sha256, hashlib.sha256(body.encode("utf-8")).hexdigest()
        ):
            raise IamError(_POLICY_UNAVAILABLE)
        _text(document.get("legal_effect"), _POLICY_UNAVAILABLE)
        document_ids.add(document_id)
        identities.add(identity)
        documents.append(document)
        expected_position += 1

    documents_by_id = {
        _text(document.get("document_id"), _POLICY_UNAVAILABLE): document
        for document in documents
    }
    raw_offers = _list(resource.get("offers"), _POLICY_UNAVAILABLE)
    if len(raw_offers) > 20:
        raise IamError(_POLICY_UNAVAILABLE)
    offers: list[Mapping[str, Any]] = []
    offer_ids: set[str] = set()
    previous_offer_key: Optional[tuple[str, str]] = None
    offer_bodies: list[Mapping[str, Any]] = []
    for raw_offer in raw_offers:
        offer = _mapping(raw_offer, _POLICY_UNAVAILABLE)
        offer_id = _text(offer.get("consent_offer_id"), _POLICY_UNAVAILABLE)
        purpose = _text(offer.get("purpose"), _POLICY_UNAVAILABLE)
        offer_key = (purpose, offer_id)
        if (
            offer_id in offer_ids
            or (previous_offer_key is not None and offer_key <= previous_offer_key)
            or offer.get("canonicalization_version") != "consent-offer-json-v1"
            or offer.get("policy_bundle_id") != bundle_id
            or not _is_int(offer.get("consent_offer_version"))
            or offer.get("consent_offer_version") < 1
            or offer.get("optional") is not True
        ):
            raise IamError(_POLICY_UNAVAILABLE)
        categories = _string_list(
            offer.get("data_categories"), _POLICY_UNAVAILABLE, nonempty=True
        )
        if len(categories) != len(set(categories)):
            raise IamError(_POLICY_UNAVAILABLE)
        supporting_document_id = _text(
            offer.get("supporting_document_id"), _POLICY_UNAVAILABLE
        )
        supporting_hash = _sha256(
            offer.get("supporting_document_sha256"), _POLICY_UNAVAILABLE
        )
        supporting_document = documents_by_id.get(supporting_document_id)
        if (
            supporting_document is None
            or supporting_document.get("content_sha256") != supporting_hash
            or supporting_document.get("legal_effect") != "CONSENT_TEXT"
        ):
            raise IamError(_POLICY_UNAVAILABLE)
        not_after = _utc(offer.get("not_after"), _POLICY_UNAVAILABLE)
        if not_after <= at:
            raise IamError(_POLICY_UNAVAILABLE)
        scope_type = _text(offer.get("scope_type"), _POLICY_UNAVAILABLE)
        scope_derivation = _text(
            offer.get("scope_derivation"), _POLICY_UNAVAILABLE
        )
        recipient_ref = _text(offer.get("recipient_ref"), _POLICY_UNAVAILABLE)
        recipient_label = _text(
            offer.get("recipient_label"), _POLICY_UNAVAILABLE
        )
        expiry_rule = _text(offer.get("expiry_rule"), _POLICY_UNAVAILABLE)
        expiry_days = offer.get("expiry_days")
        if expiry_days is not None and (
            not _is_int(expiry_days) or expiry_days < 1
        ):
            raise IamError(_POLICY_UNAVAILABLE)
        canonical_offer = {
            "canonicalization_version": "consent-offer-json-v1",
            "consent_offer_id": offer_id,
            "consent_offer_version": offer.get("consent_offer_version"),
            "policy_bundle_id": bundle_id,
            "purpose": purpose,
            "scope_type": scope_type,
            "scope_derivation": scope_derivation,
            "data_categories": categories,
            "recipient_ref": recipient_ref,
            "recipient_label": recipient_label,
            "supporting_document_id": supporting_document_id,
            "supporting_document_sha256": supporting_hash,
            "expiry_rule": expiry_rule,
            "expiry_days": expiry_days,
            "not_after": _timestamp(not_after),
            "optional": True,
        }
        canonical_bytes = json.dumps(
            canonical_offer,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        canonical_digest = _sha256(
            offer.get("canonical_offer_sha256"), _POLICY_UNAVAILABLE
        )
        if not hmac.compare_digest(
            canonical_digest, hashlib.sha256(canonical_bytes).hexdigest()
        ):
            raise IamError(_POLICY_UNAVAILABLE)
        offers.append(offer)
        offer_ids.add(offer_id)
        previous_offer_key = offer_key
        offer_bodies.append(
            {
                "consent_offer_id": offer_id,
                "purpose": purpose,
                "scope_type": scope_type,
                "data_categories": categories,
                "document_id": supporting_document_id,
                "content_sha256": supporting_hash,
                "recipient_label": recipient_label,
                "expiry_rule": expiry_rule,
                "not_after": _timestamp(not_after),
                "canonical_offer_sha256": canonical_digest,
                "optional": True,
            }
        )

    policy_body = {
        "policy_bundle_id": bundle_id,
        "purpose": selector_payload["access_purpose"],
        "jurisdiction": selector_payload["jurisdiction"],
        "locale": selector_payload["locale"],
        "documents": [
            {
                "document_id": _text(
                    document.get("document_id"), _POLICY_UNAVAILABLE
                ),
                "kind": _text(document.get("kind"), _POLICY_UNAVAILABLE),
                "semantic_version": _text(
                    document.get("semantic_version"), _POLICY_UNAVAILABLE
                ),
                "locale": _text(document.get("locale"), _POLICY_UNAVAILABLE),
                "content_sha256": _sha256(
                    document.get("content_sha256"), _POLICY_UNAVAILABLE
                ),
                "legal_effect": _text(
                    document.get("legal_effect"), _POLICY_UNAVAILABLE
                ),
                "body": _text(
                    document.get("canonical_body"), _POLICY_UNAVAILABLE
                ),
            }
            for document in documents
        ],
        "consent_offers": offer_bodies,
        "effective_at": _timestamp(effective_at),
        "entity_tag": _etag(version),
    }
    return _PolicyView(
        body=policy_body,
        selector=selector,
        bundle=bundle,
        documents=tuple(documents),
        offers=tuple(offers),
    )


def project_canonical_me_dto(
    facts: Mapping[str, Any], *, at: datetime
) -> Mapping[str, Any]:
    """Project the canonical ``MeDto`` from one complete authority snapshot.

    Authentication and Session validation belong to the caller.  This pure
    projector deliberately depends only on the closed User/authority/policy
    facts and the snapshot timestamp, so a command Unit of Work can project
    its own post-command state before COMMIT.  PostgreSQL JSON values encode
    timestamps as strings; restore only the reviewed timestamp fields without
    mutating the supplied snapshot.
    """

    at = _utc(at, _SERVICE_UNAVAILABLE)
    restored = _restore_json_timestamps(facts)
    facts = _mapping(restored, _SERVICE_UNAVAILABLE)
    user = _mapping(facts.get("user"), _SERVICE_UNAVAILABLE)
    user_id = _text(user.get("user_id"), _SERVICE_UNAVAILABLE)
    version = _positive_int(user.get("aggregate_version"), _SERVICE_UNAVAILABLE)
    base = {
        "user_id": user_id,
        "status": _text(user.get("status"), _SERVICE_UNAVAILABLE),
        "display_handle": _text(user.get("display_handle"), _SERVICE_UNAVAILABLE),
        "user_roles": [],
        "memberships": [],
        "policy_requirements": [],
        "aggregate_version": version,
        "entity_tag": _etag(version),
    }
    if user.get("status") == "PENDING_ENROLLMENT":
        return base

    policies: dict[str, _PolicyView] = {}
    for raw_policy in _list(facts.get("policies"), _POLICY_UNAVAILABLE):
        view = _validate_policy(
            raw_policy,
            at=at,
            expected_selector_digest=None,
            requested_bundle_id=None,
            public_lookup=False,
        )
        digest = _sha256(view.selector.get("selector_digest"), _POLICY_UNAVAILABLE)
        if digest in policies:
            raise IamError(_POLICY_UNAVAILABLE)
        policies[digest] = view

    invitations: dict[str, Mapping[str, Any]] = {}
    for raw_invitation in _list(
        facts.get("source_invitations"), _POLICY_UNAVAILABLE
    ):
        invitation = _mapping(raw_invitation, _POLICY_UNAVAILABLE)
        invitation_id = _text(
            invitation.get("invitation_id"), _POLICY_UNAVAILABLE
        )
        if invitation_id in invitations:
            raise IamError(_POLICY_UNAVAILABLE)
        invitations[invitation_id] = invitation

    accepted: set[tuple[str, str]] = set()
    for raw_acceptance in _list(facts.get("acceptances"), _SERVICE_UNAVAILABLE):
        acceptance = _mapping(raw_acceptance, _SERVICE_UNAVAILABLE)
        if acceptance.get("user_id") != user_id:
            raise IamError(_SERVICE_UNAVAILABLE)
        document_id = _text(
            acceptance.get("document_id"), _SERVICE_UNAVAILABLE
        )
        content_hash = _sha256(
            acceptance.get("content_sha256"), _SERVICE_UNAVAILABLE
        )
        _text(
            acceptance.get("policy_bundle_id"), _SERVICE_UNAVAILABLE
        )
        accepted.add((document_id, content_hash))

    scopes: list[tuple[str, str, str, Optional[str]]] = []
    user_roles: set[str] = set()
    seen_user_grants: set[str] = set()
    for raw_grant in _list(facts.get("user_role_grants"), _POLICY_UNAVAILABLE):
        grant = _mapping(raw_grant, _POLICY_UNAVAILABLE)
        if grant.get("revoked_at") is not None:
            continue
        grant_id = _text(grant.get("role_grant_id"), _POLICY_UNAVAILABLE)
        if grant_id in seen_user_grants or grant.get("user_id") != user_id:
            raise IamError(_POLICY_UNAVAILABLE)
        seen_user_grants.add(grant_id)
        role = _text(grant.get("role_code"), _POLICY_UNAVAILABLE)
        if role != "CREATOR":
            raise IamError(_POLICY_UNAVAILABLE)
        selector_digest = _sha256(
            grant.get("policy_selector_digest"), _POLICY_UNAVAILABLE
        )
        _validate_source_invitation(
            invitations.get(grant.get("source_invitation_id")),
            user_id=user_id,
            selector_digest=selector_digest,
            role=role,
            scope_type="USER_ROLE",
            organization_id=None,
        )
        _validate_scope_policy(policies.get(selector_digest), role, "USER_ROLE")
        user_roles.add(role)
        scopes.append((selector_digest, role, "USER_ROLE", None))

    membership_bodies: list[Mapping[str, Any]] = []
    seen_memberships: set[str] = set()
    for raw_entry in _list(facts.get("memberships"), _SERVICE_UNAVAILABLE):
        entry = _mapping(raw_entry, _SERVICE_UNAVAILABLE)
        membership = _mapping(entry.get("membership"), _SERVICE_UNAVAILABLE)
        status = membership.get("status")
        if status not in {"ACTIVE", "SUSPENDED", "REVOKED"}:
            raise IamError(_SERVICE_UNAVAILABLE)
        if status != "ACTIVE":
            continue
        membership_id = _text(
            membership.get("membership_id"), _SERVICE_UNAVAILABLE
        )
        if membership_id in seen_memberships or membership.get("user_id") != user_id:
            raise IamError(_SERVICE_UNAVAILABLE)
        seen_memberships.add(membership_id)
        organization = _mapping(entry.get("organization"), _SERVICE_UNAVAILABLE)
        organization_id = _text(
            organization.get("organization_id"), _SERVICE_UNAVAILABLE
        )
        if (
            membership.get("organization_id") != organization_id
            or organization.get("status") != "ACTIVE"
        ):
            continue
        roles: set[str] = set()
        for raw_grant in _list(entry.get("role_grants"), _POLICY_UNAVAILABLE):
            grant = _mapping(raw_grant, _POLICY_UNAVAILABLE)
            if grant.get("revoked_at") is not None:
                continue
            if (
                grant.get("membership_id") != membership_id
                or grant.get("organization_id") != organization_id
                or grant.get("user_id") != user_id
                or grant.get("source_invitation_id")
                != membership.get("source_invitation_id")
            ):
                raise IamError(_POLICY_UNAVAILABLE)
            role = _text(grant.get("role_code"), _POLICY_UNAVAILABLE)
            selector_digest = _sha256(
                grant.get("policy_selector_digest"), _POLICY_UNAVAILABLE
            )
            _validate_source_invitation(
                invitations.get(grant.get("source_invitation_id")),
                user_id=user_id,
                selector_digest=selector_digest,
                role=role,
                scope_type="ORGANIZATION_ROLE",
                organization_id=organization_id,
            )
            _validate_scope_policy(
                policies.get(selector_digest), role, "ORGANIZATION_ROLE"
            )
            if role in roles:
                raise IamError(_POLICY_UNAVAILABLE)
            roles.add(role)
            scopes.append(
                (selector_digest, role, "ORGANIZATION_ROLE", organization_id)
            )
        if not roles:
            raise IamError(_POLICY_UNAVAILABLE)
        membership_version = _positive_int(
            membership.get("aggregate_version"), _SERVICE_UNAVAILABLE
        )
        membership_bodies.append(
            {
                "membership_id": membership_id,
                "organization": _organization_dto(organization),
                "status": "ACTIVE",
                "roles": sorted(roles),
                "aggregate_version": membership_version,
                "entity_tag": _etag(membership_version),
            }
        )

    requirements: list[Mapping[str, Any]] = []
    seen_scopes: set[tuple[str, str, str, Optional[str]]] = set()
    for selector_digest, role, scope_type, scope_id in sorted(scopes):
        scope_key = (selector_digest, role, scope_type, scope_id)
        if scope_key in seen_scopes:
            raise IamError(_POLICY_UNAVAILABLE)
        seen_scopes.add(scope_key)
        policy = policies.get(selector_digest)
        if policy is None:
            raise IamError(_POLICY_UNAVAILABLE)
        bundle_id = _text(
            policy.bundle.get("policy_bundle_id"), _POLICY_UNAVAILABLE
        )
        missing: list[str] = []
        for document in policy.documents:
            if document.get("required") is not True:
                continue
            document_id = _text(
                document.get("document_id"), _POLICY_UNAVAILABLE
            )
            content_hash = _sha256(
                document.get("content_sha256"), _POLICY_UNAVAILABLE
            )
            if (document_id, content_hash) not in accepted:
                missing.append(document_id)
        requirements.append(
            {
                "selector_digest": selector_digest,
                "purpose": _text(
                    policy.selector.get("access_purpose"), _POLICY_UNAVAILABLE
                ),
                "role": role,
                "scope_type": scope_type,
                "scope_id": scope_id,
                "satisfied": not missing,
                "required_policy_bundle_id": bundle_id,
                "missing_document_ids": missing,
            }
        )

    base["user_roles"] = sorted(user_roles)
    base["memberships"] = sorted(
        membership_bodies,
        key=lambda item: (
            item["organization"]["organization_id"],
            item["membership_id"],
        ),
    )
    base["policy_requirements"] = requirements
    return base


def _restore_json_timestamps(value: object, *, field_name: str = "") -> object:
    if isinstance(value, Mapping):
        return {
            key: _restore_json_timestamps(item, field_name=str(key))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [
            _restore_json_timestamps(item, field_name=field_name) for item in value
        ]
    if isinstance(value, str) and field_name in _JSON_TIMESTAMP_FIELDS:
        try:
            return parse_utc_timestamp(value)
        except ValueError:
            return value
    return value


def _validate_source_invitation(
    value: object,
    *,
    user_id: str,
    selector_digest: str,
    role: str,
    scope_type: str,
    organization_id: Optional[str],
) -> None:
    invitation = _mapping(value, _POLICY_UNAVAILABLE)
    expected_target_scope = "USER" if scope_type == "USER_ROLE" else "ORGANIZATION"
    expected_purpose = (
        "CREATOR_ENROLLMENT"
        if scope_type == "USER_ROLE"
        else "ORGANIZATION_MEMBERSHIP"
    )
    if (
        invitation.get("status") != "ACCEPTED"
        or invitation.get("accepted_by_user_id") != user_id
        or invitation.get("policy_selector_digest") != selector_digest
        or invitation.get("target_role") != role
        or invitation.get("target_scope") != expected_target_scope
        or invitation.get("purpose") != expected_purpose
        or invitation.get("organization_id") != organization_id
    ):
        raise IamError(_POLICY_UNAVAILABLE)


def _validate_scope_policy(
    policy: Optional[_PolicyView], role: str, scope_type: str
) -> None:
    if policy is None:
        raise IamError(_POLICY_UNAVAILABLE)
    expected_purpose = (
        "CREATOR_ENROLLMENT"
        if scope_type == "USER_ROLE"
        else "ORGANIZATION_MEMBERSHIP"
    )
    if (
        policy.selector.get("target_role") != role
        or policy.selector.get("scope_type") != scope_type
        or policy.selector.get("access_purpose") != expected_purpose
    ):
        raise IamError(_POLICY_UNAVAILABLE)


def _consent_grant_dto(
    row: Mapping[str, Any], actor_user_id: str, at: datetime
) -> Mapping[str, Any]:
    grant = _mapping(row.get("grant"), _SERVICE_UNAVAILABLE)
    if grant.get("user_id") != actor_user_id:
        raise IamError(_SERVICE_UNAVAILABLE)
    grant_id = _text(grant.get("consent_grant_id"), _SERVICE_UNAVAILABLE)
    if row.get("sort_id") != grant_id:
        raise IamError(_SERVICE_UNAVAILABLE)
    granted_at = _utc(grant.get("granted_at"), _SERVICE_UNAVAILABLE)
    expires_at = _utc(grant.get("expires_at"), _SERVICE_UNAVAILABLE)
    if row.get("created_at") != granted_at or expires_at <= granted_at:
        raise IamError(_SERVICE_UNAVAILABLE)
    status = _text(grant.get("status"), _SERVICE_UNAVAILABLE)
    if status not in {"ACTIVE", "WITHDRAWN", "EXPIRED"}:
        raise IamError(_SERVICE_UNAVAILABLE)
    withdrawals = _list(row.get("withdrawals"), _SERVICE_UNAVAILABLE)
    withdrawn_at_value = grant.get("withdrawn_at")
    if status == "WITHDRAWN":
        if len(withdrawals) != 1:
            raise IamError(_SERVICE_UNAVAILABLE)
        withdrawal = _mapping(withdrawals[0], _SERVICE_UNAVAILABLE)
        withdrawn_at = _utc(withdrawn_at_value, _SERVICE_UNAVAILABLE)
        if (
            withdrawal.get("consent_grant_id") != grant_id
            or withdrawal.get("user_id") != actor_user_id
            or _utc(withdrawal.get("withdrawn_at"), _SERVICE_UNAVAILABLE)
            != withdrawn_at
            or not granted_at <= withdrawn_at <= at
        ):
            raise IamError(_SERVICE_UNAVAILABLE)
    elif withdrawals or withdrawn_at_value is not None:
        raise IamError(_SERVICE_UNAVAILABLE)
    projected_status = status
    if status == "ACTIVE" and at >= expires_at:
        projected_status = "EXPIRED"
    if status == "EXPIRED" and at < expires_at:
        raise IamError(_SERVICE_UNAVAILABLE)
    categories = _string_list(
        row.get("categories"), _SERVICE_UNAVAILABLE, nonempty=True
    )
    if len(categories) != len(set(categories)):
        raise IamError(_SERVICE_UNAVAILABLE)
    scope_type = _text(grant.get("scope_type"), _SERVICE_UNAVAILABLE)
    scope_id = grant.get("scope_id")
    if scope_type == "PLATFORM_PARTICIPATION" and scope_id is not None:
        raise IamError(_SERVICE_UNAVAILABLE)
    _text(grant.get("recipient_ref"), _SERVICE_UNAVAILABLE)
    version = _positive_int(grant.get("aggregate_version"), _SERVICE_UNAVAILABLE)
    return {
        "consent_grant_id": grant_id,
        "consent_offer_id": _text(
            grant.get("consent_offer_id"), _SERVICE_UNAVAILABLE
        ),
        "purpose": _text(grant.get("purpose"), _SERVICE_UNAVAILABLE),
        "scope_type": scope_type,
        "scope_id": scope_id,
        "data_categories": categories,
        "recipient_label": _text(
            grant.get("recipient_label"), _SERVICE_UNAVAILABLE
        ),
        "document_id": _text(grant.get("document_id"), _SERVICE_UNAVAILABLE),
        "content_sha256": _sha256(
            grant.get("content_sha256"), _SERVICE_UNAVAILABLE
        ),
        "granted_at": _timestamp(granted_at),
        "expires_at": _timestamp(expires_at),
        "status": projected_status,
        "aggregate_version": version,
        "entity_tag": _etag(version),
    }


def _organization_authority(
    *,
    actor_facts: Mapping[str, Any],
    target: object,
    actor: ReadActor,
    organization_id: str,
    at: datetime,
    require_admin: bool,
) -> Mapping[str, Any]:
    _validate_authority(
        actor_facts,
        actor,
        at,
        allowed_user_statuses={"ACTIVE"},
    )
    if target is None or actor_facts.get("membership") is None:
        raise IamError(_RESOURCE_NOT_FOUND)
    organization = _mapping(target, _SERVICE_UNAVAILABLE)
    if organization.get("organization_id") != organization_id:
        raise IamError(_SERVICE_UNAVAILABLE)
    if organization.get("status") != "ACTIVE":
        raise IamError(_RESOURCE_NOT_FOUND)
    membership = _mapping(actor_facts.get("membership"), _SERVICE_UNAVAILABLE)
    if (
        membership.get("status") != "ACTIVE"
        or membership.get("organization_id") != organization_id
        or membership.get("user_id") != actor.actor_user_id
    ):
        raise IamError(_RESOURCE_NOT_FOUND)
    actor_organization = _mapping(
        actor_facts.get("organization"), _SERVICE_UNAVAILABLE
    )
    if actor_organization.get("organization_id") != organization_id:
        raise IamError(_SERVICE_UNAVAILABLE)
    roles: set[str] = set()
    for raw_grant in _list(actor_facts.get("roles"), _SERVICE_UNAVAILABLE):
        grant = _mapping(raw_grant, _SERVICE_UNAVAILABLE)
        if grant.get("revoked_at") is not None:
            continue
        if (
            grant.get("membership_id") != membership.get("membership_id")
            or grant.get("organization_id") != organization_id
            or grant.get("user_id") != actor.actor_user_id
        ):
            raise IamError(_SERVICE_UNAVAILABLE)
        roles.add(_text(grant.get("role_code"), _SERVICE_UNAVAILABLE))
    allowed = {"ORG_ADMIN"} if require_admin else {"ORG_ADMIN", "DEMAND_OWNER"}
    if not roles.intersection(allowed):
        raise IamError(_RESOURCE_NOT_FOUND)
    return organization


def _organization_dto(organization: Mapping[str, Any]) -> Mapping[str, Any]:
    version = _positive_int(
        organization.get("aggregate_version"), _SERVICE_UNAVAILABLE
    )
    status = _text(organization.get("status"), _SERVICE_UNAVAILABLE)
    if status not in {"PENDING_ADMIN", "ACTIVE", "SUSPENDED", "CLOSED"}:
        raise IamError(_SERVICE_UNAVAILABLE)
    return {
        "organization_id": _text(
            organization.get("organization_id"), _SERVICE_UNAVAILABLE
        ),
        "public_name": _text(
            organization.get("public_name"), _SERVICE_UNAVAILABLE
        ),
        "type": _text(
            organization.get("organization_type"), _SERVICE_UNAVAILABLE
        ),
        "status": status,
        "aggregate_version": version,
        "entity_tag": _etag(version),
    }


def _invitation_admin_dto(
    row: Mapping[str, Any], organization_id: str, at: datetime
) -> Mapping[str, Any]:
    invitation = _mapping(row.get("invitation"), _SERVICE_UNAVAILABLE)
    invitation_id = _text(invitation.get("invitation_id"), _SERVICE_UNAVAILABLE)
    if (
        row.get("sort_id") != invitation_id
        or row.get("created_at") != invitation.get("created_at")
        or invitation.get("organization_id") != organization_id
        or invitation.get("purpose") != "ORGANIZATION_MEMBERSHIP"
        or invitation.get("target_scope") != "ORGANIZATION"
    ):
        raise IamError(_SERVICE_UNAVAILABLE)
    status = _text(invitation.get("status"), _SERVICE_UNAVAILABLE)
    if status not in {"ISSUED", "ACCEPTED", "REVOKED", "EXPIRED"}:
        raise IamError(_SERVICE_UNAVAILABLE)
    expires_at = _utc(invitation.get("expires_at"), _SERVICE_UNAVAILABLE)
    if status == "ISSUED" and at >= expires_at:
        status = "EXPIRED"
    created_at = _utc(invitation.get("created_at"), _SERVICE_UNAVAILABLE)
    selector_digest = _sha256(
        invitation.get("policy_selector_digest"), _POLICY_UNAVAILABLE
    )
    policy = _validate_policy(
        row.get("policy"),
        at=at,
        expected_selector_digest=selector_digest,
        requested_bundle_id=None,
        public_lookup=False,
    )
    _validate_invitation_policy_shape(invitation, policy.selector)
    masked = _text(
        invitation.get("masked_recipient_label"), _SERVICE_UNAVAILABLE
    )
    if row.get("recipient_mask_verified") is not True:
        raise IamError(_SERVICE_UNAVAILABLE)
    version = _positive_int(
        invitation.get("aggregate_version"), _SERVICE_UNAVAILABLE
    )
    return {
        "invitation_id": invitation_id,
        "purpose": "ORGANIZATION_MEMBERSHIP",
        "organization_id": organization_id,
        "target_role": _text(
            invitation.get("target_role"), _SERVICE_UNAVAILABLE
        ),
        "masked_recipient_label": masked,
        "is_initial_admin": _boolean(
            invitation.get("is_initial_admin"), _SERVICE_UNAVAILABLE
        ),
        "status": status,
        "expires_at": _timestamp(expires_at),
        "created_at": _timestamp(created_at),
        "required_policy_bundle_id": _text(
            policy.bundle.get("policy_bundle_id"), _POLICY_UNAVAILABLE
        ),
        "aggregate_version": version,
        "entity_tag": _etag(version),
    }


def _membership_admin_dto(
    row: Mapping[str, Any], organization_id: str, at: datetime
) -> Mapping[str, Any]:
    membership = _mapping(row.get("membership"), _SERVICE_UNAVAILABLE)
    user = _mapping(row.get("user"), _SERVICE_UNAVAILABLE)
    membership_id = _text(
        membership.get("membership_id"), _SERVICE_UNAVAILABLE
    )
    user_id = _text(membership.get("user_id"), _SERVICE_UNAVAILABLE)
    created_at = _utc(membership.get("created_at"), _SERVICE_UNAVAILABLE)
    if (
        row.get("sort_id") != membership_id
        or row.get("created_at") != created_at
        or membership.get("organization_id") != organization_id
        or user.get("user_id") != user_id
    ):
        raise IamError(_SERVICE_UNAVAILABLE)
    status = _text(membership.get("status"), _SERVICE_UNAVAILABLE)
    if status not in {"ACTIVE", "SUSPENDED", "REVOKED"}:
        raise IamError(_SERVICE_UNAVAILABLE)
    roles: set[str] = set()
    for raw_grant in _list(row.get("role_grants"), _SERVICE_UNAVAILABLE):
        grant = _mapping(raw_grant, _SERVICE_UNAVAILABLE)
        revoked_at = grant.get("revoked_at")
        if revoked_at is not None:
            _utc(revoked_at, _SERVICE_UNAVAILABLE)
        if (
            grant.get("membership_id") != membership_id
            or grant.get("organization_id") != organization_id
            or grant.get("user_id") != user_id
            or grant.get("source_invitation_id")
            != membership.get("source_invitation_id")
        ):
            raise IamError(_SERVICE_UNAVAILABLE)
        if status != "REVOKED" and revoked_at is not None:
            continue
        role = _text(grant.get("role_code"), _SERVICE_UNAVAILABLE)
        _sha256(grant.get("policy_selector_digest"), _SERVICE_UNAVAILABLE)
        if role in roles:
            raise IamError(_SERVICE_UNAVAILABLE)
        roles.add(role)
    if not roles:
        raise IamError(_SERVICE_UNAVAILABLE)
    version = _positive_int(
        membership.get("aggregate_version"), _SERVICE_UNAVAILABLE
    )
    return {
        "membership_id": membership_id,
        "organization_id": organization_id,
        "user_id": user_id,
        "display_handle": _text(user.get("display_handle"), _SERVICE_UNAVAILABLE),
        "status": status,
        "roles": sorted(roles),
        "aggregate_version": version,
        "entity_tag": _etag(version),
    }


def _validate_cursor_claims(
    claims: ReadModelCursorClaims,
    *,
    operation_id: str,
    actor_user_id: str,
    organization_id: Optional[str],
    page_limit: int,
    now: datetime,
) -> None:
    if not isinstance(claims, ReadModelCursorClaims):
        raise IamError(_INVALID_REQUEST)
    try:
        snapshot_at = _utc(claims.snapshot_at, _INVALID_REQUEST)
        after_created_at = _utc(claims.after_created_at, _INVALID_REQUEST)
        issued_at = _utc(claims.issued_at, _INVALID_REQUEST)
        expires_at = _utc(claims.expires_at, _INVALID_REQUEST)
    except IamError:
        raise
    if (
        claims.version != _CURSOR_VERSION
        or not isinstance(claims.key_id, str)
        or not claims.key_id
        or claims.operation_id != operation_id
        or claims.actor_user_id != actor_user_id
        or claims.organization_id != organization_id
        or claims.page_limit != page_limit
        or claims.query_shape_digest != _QUERY_SHAPE_DIGESTS[operation_id]
        or not isinstance(claims.after_id, str)
        or not claims.after_id
        or issued_at > now
        or now >= expires_at
        or snapshot_at > issued_at
        or after_created_at > snapshot_at
    ):
        raise IamError(_INVALID_REQUEST)


def _validated_page_rows(
    facts: Mapping[str, Any],
    *,
    transaction_time: datetime,
    page_state: _PageState,
    operation_id: str,
    actor_user_id: str,
    organization_id: Optional[str],
    now: datetime,
    cursor_codec: ReadModelCursorCodec,
) -> tuple[list[Mapping[str, Any]], datetime, Optional[str]]:
    rows_value = _list(facts.get("rows"), _SERVICE_UNAVAILABLE)
    if len(rows_value) > page_state.window.limit + 1:
        raise IamError(_SERVICE_UNAVAILABLE)
    snapshot_at = _utc(
        facts.get("snapshot_at", transaction_time), _SERVICE_UNAVAILABLE
    )
    if snapshot_at > now:
        raise IamError(_SERVICE_UNAVAILABLE)
    if page_state.claims is None:
        if snapshot_at != transaction_time:
            raise IamError(_SERVICE_UNAVAILABLE)
    elif snapshot_at != page_state.claims.snapshot_at:
        raise IamError(_SERVICE_UNAVAILABLE)

    rows: list[Mapping[str, Any]] = []
    seen_ids: set[str] = set()
    previous_key: Optional[tuple[datetime, str]] = None
    boundary = (
        None
        if page_state.claims is None
        else (page_state.claims.after_created_at, page_state.claims.after_id)
    )
    for raw_row in rows_value:
        row = _mapping(raw_row, _SERVICE_UNAVAILABLE)
        created_at = _utc(row.get("created_at"), _SERVICE_UNAVAILABLE)
        sort_id = _text(row.get("sort_id"), _SERVICE_UNAVAILABLE)
        key = (created_at, sort_id)
        if (
            sort_id in seen_ids
            or created_at > snapshot_at
            or (previous_key is not None and key >= previous_key)
            or (boundary is not None and key >= boundary)
        ):
            raise IamError(_SERVICE_UNAVAILABLE)
        seen_ids.add(sort_id)
        previous_key = key
        rows.append(row)

    visible = rows[: page_state.window.limit]
    next_cursor: Optional[str] = None
    if len(rows) > page_state.window.limit:
        last = visible[-1]
        claims = ReadModelCursorClaims(
            version=_CURSOR_VERSION,
            key_id=cursor_codec.active_key_id,
            operation_id=operation_id,
            actor_user_id=actor_user_id,
            organization_id=organization_id,
            page_limit=page_state.window.limit,
            query_shape_digest=_QUERY_SHAPE_DIGESTS[operation_id],
            snapshot_at=snapshot_at,
            after_created_at=_utc(last.get("created_at"), _SERVICE_UNAVAILABLE),
            after_id=_text(last.get("sort_id"), _SERVICE_UNAVAILABLE),
            issued_at=now,
            expires_at=now + _CURSOR_TTL,
        )
        try:
            next_cursor = cursor_codec.encode(claims)
        except ReadModelCursorUnavailableError as error:
            raise IamError(_SERVICE_UNAVAILABLE) from error
        if not isinstance(next_cursor, str) or not next_cursor:
            raise IamError(_SERVICE_UNAVAILABLE)
    return visible, snapshot_at, next_cursor


def _mapping(value: object, code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise IamError(code)
    return value


def _list(value: object, code: str) -> list[Any]:
    if not isinstance(value, list):
        raise IamError(code)
    return value


def _string_list(value: object, code: str, *, nonempty: bool) -> list[str]:
    values = _list(value, code)
    if nonempty and not values:
        raise IamError(code)
    if any(not isinstance(item, str) or not item for item in values):
        raise IamError(code)
    return list(values)


def _text(value: object, code: str) -> str:
    if not isinstance(value, str) or not value:
        raise IamError(code)
    return value


def _bytes(value: object, code: str) -> bytes:
    if not isinstance(value, bytes) or not value:
        raise IamError(code)
    return value


def _boolean(value: object, code: str) -> bool:
    if not isinstance(value, bool):
        raise IamError(code)
    return value


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _positive_int(value: object, code: str) -> int:
    if not _is_int(value) or value < 1:
        raise IamError(code)
    return value


def _utc(value: object, code: str) -> datetime:
    if not isinstance(value, datetime):
        raise IamError(code)
    offset = value.utcoffset()
    if offset is None or offset != timedelta(0):
        raise IamError(code)
    return value


def _sha256(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise IamError(code)
    return value


def _etag(version: int) -> str:
    return f'"v{version}"'


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


__all__ = [
    "GetMeHandler",
    "GetMeQuery",
    "GetOrganizationSummaryHandler",
    "GetOrganizationSummaryQuery",
    "GetPolicyBundleHandler",
    "GetPolicyBundleQuery",
    "GetSessionBootstrapHandler",
    "GetSessionBootstrapQuery",
    "InspectAccessInvitationHandler",
    "InspectAccessInvitationQuery",
    "ListMyConsentGrantsHandler",
    "ListMyConsentGrantsQuery",
    "ListMySessionsHandler",
    "ListMySessionsQuery",
    "ListOrganizationAccessInvitationsHandler",
    "ListOrganizationAccessInvitationsQuery",
    "ListOrganizationMembershipsHandler",
    "ListOrganizationMembershipsQuery",
    "PageRequest",
    "project_canonical_me_dto",
    "READ_MODEL_BEHAVIOR_NOT_AVAILABLE",
    "ReadActor",
    "ReadCachePolicy",
    "ReadModelResponse",
]
