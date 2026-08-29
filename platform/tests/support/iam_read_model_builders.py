"""Strict synthetic fixtures for the IAM read-model semantic RED suite."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Any, Mapping, Optional

from desire_platform.identity_access.application.read_models import (
    GetMeHandler,
    GetMeQuery,
    GetOrganizationSummaryHandler,
    GetOrganizationSummaryQuery,
    GetPolicyBundleHandler,
    GetPolicyBundleQuery,
    GetSessionBootstrapHandler,
    GetSessionBootstrapQuery,
    InspectAccessInvitationHandler,
    InspectAccessInvitationQuery,
    ListMyConsentGrantsHandler,
    ListMyConsentGrantsQuery,
    ListMySessionsHandler,
    ListMySessionsQuery,
    ListOrganizationAccessInvitationsHandler,
    ListOrganizationAccessInvitationsQuery,
    ListOrganizationMembershipsHandler,
    ListOrganizationMembershipsQuery,
    PageRequest,
    ReadActor,
)
from desire_platform.identity_access.ports.access_invitation_capability import (
    VerifiedAccessInvitationCapability,
)
from desire_platform.identity_access.ports.read_models import (
    ReadModelCursorClaims,
    ReadModelCursorInvalidError,
    ReadModelSnapshot,
    ReadModelTelemetryEvent,
    ReadPageWindow,
    SessionBootstrapCsrfMaterial,
)
from desire_platform.identity_access.read_model_registry import (
    PAGED_READ_QUERY_SHAPE_DIGESTS,
)


def _policy_selector_sha256(
    *,
    access_purpose: str,
    scope_type: str,
    target_role: str,
    jurisdiction: str,
    locale: str,
) -> str:
    """Independent oracle for the closed policy-selector-json-v1 bytes."""

    encoded = json.dumps(
        {
            "access_purpose": access_purpose,
            "scope_type": scope_type,
            "target_role": target_role,
            "jurisdiction": jurisdiction,
            "locale": locale,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


NOW = datetime(2026, 8, 8, 12, 0, tzinfo=timezone.utc)

ACTOR_USER_ID = "user_read_actor_0001"
OTHER_USER_ID = "user_read_other_0002"
CURRENT_SESSION_ID = "session_read_current_0001"
REVOKED_SESSION_ID = "session_read_revoked_0002"
SESSION_FAMILY_ID = "session_family_read_0001"
ORGANIZATION_ID = "organization_read_0001"
OTHER_ORGANIZATION_ID = "organization_read_other_0002"
ACTOR_MEMBERSHIP_ID = "membership_read_actor_0001"
TARGET_MEMBERSHIP_ID = "membership_read_target_0002"
CREATOR_INVITATION_ID = "invitation_read_creator_0001"
ORGANIZATION_INVITATION_ID = "invitation_read_org_0002"
ACCEPTED_INVITATION_ID = "invitation_read_accepted_0003"
CREATOR_SELECTOR_DIGEST = _policy_selector_sha256(
    access_purpose="CREATOR_ENROLLMENT",
    scope_type="USER_ROLE",
    target_role="CREATOR",
    jurisdiction="CN",
    locale="en",
)
ORGANIZATION_SELECTOR_DIGEST = _policy_selector_sha256(
    access_purpose="ORGANIZATION_MEMBERSHIP",
    scope_type="ORGANIZATION_ROLE",
    target_role="ORG_ADMIN",
    jurisdiction="CN",
    locale="en",
)
CREATOR_POLICY_BUNDLE_ID = "policy_bundle_read_creator_0001"
ORGANIZATION_POLICY_BUNDLE_ID = "policy_bundle_read_org_0002"
TERMS_DOCUMENT_ID = "policy_document_terms_0001"
CONSENT_DOCUMENT_ID = "policy_document_consent_0002"
ORG_DOCUMENT_ID = "policy_document_org_0003"
CONSENT_OFFER_ID = "consent_offer_read_0001"
ACTIVE_CONSENT_GRANT_ID = "consent_grant_read_active_0001"
WITHDRAWN_CONSENT_GRANT_ID = "consent_grant_read_withdrawn_0002"

RAW_SESSION_HANDLE_SENTINEL = "RAW_SESSION_HANDLE_SECRET_SENTINEL_0001"
RAW_INVITATION_TOKEN_SENTINEL = "RAW_INVITATION_TOKEN_SECRET_SENTINEL_0001"
CONTACT_SENTINEL = "recipient-secret@example.invalid"
SUBJECT_SENTINEL = "RAW_PROVIDER_SUBJECT_SECRET_SENTINEL_0001"
RECIPIENT_REF_SENTINEL = "INTERNAL_RECIPIENT_REF_SECRET_SENTINEL_0001"
HANDLE_DIGEST_SENTINEL = b"HANDLE_DIGEST_SECRET_SENTINEL"
CSRF_SALT_SENTINEL = b"CSRF_SALT_SECRET_SENTINEL_0001"
CSRF_DIGEST_SENTINEL = b"CSRF_DIGEST_SECRET_SENTINEL_01"
MASKED_CSRF_RESPONSE = "masked_csrf_response_value_0000000000000001"
CAPABILITY_NONCE_SENTINEL = "CAPABILITY_NONCE_SECRET_SENTINEL_0001"
POLICY_SIGNATURE_SENTINEL = "POLICY_SIGNATURE_SECRET_SENTINEL_0001"

OPERATION_IDS = (
    "getSessionBootstrap",
    "inspectAccessInvitation",
    "getPolicyBundle",
    "getMe",
    "listMyConsentGrants",
    "listMySessions",
    "getOrganizationSummary",
    "listOrganizationAccessInvitations",
    "listOrganizationMemberships",
)

STATEMENT_BUDGETS = {
    "getSessionBootstrap": 1,
    "inspectAccessInvitation": 1,
    "getPolicyBundle": 3,
    "getMe": 2,
    "listMyConsentGrants": 2,
    "listMySessions": 1,
    "getOrganizationSummary": 1,
    "listOrganizationAccessInvitations": 2,
    "listOrganizationMemberships": 2,
}


class FrozenClock:
    def __init__(self, value: datetime = NOW) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


class StrictReadModelRepository:
    """Operation-specific Memory repository; it has no write or lock API."""

    def __init__(self, facts: Mapping[str, Mapping[str, Any]]) -> None:
        self._facts = deepcopy(dict(facts))
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.statement_overrides: dict[str, int] = {}
        self.transaction_time_overrides: dict[str, datetime] = {}
        self.write_count = 0
        self.lock_count = 0

    def facts(self, operation_id: str) -> dict[str, Any]:
        return self._facts[operation_id]

    def _snapshot(self, operation_id: str, **arguments: Any) -> ReadModelSnapshot:
        self.calls.append((operation_id, deepcopy(arguments)))
        facts = deepcopy(self._facts[operation_id])
        if operation_id in _PAGED_OPERATIONS:
            window = arguments["window"]
            facts = _page_facts(facts, window)
        return ReadModelSnapshot.from_mapping(
            transaction_time=self.transaction_time_overrides.get(
                operation_id, NOW
            ),
            statement_count=self.statement_overrides.get(
                operation_id, STATEMENT_BUDGETS[operation_id]
            ),
            facts=facts,
        )

    def read_session_bootstrap(
        self, *, actor_user_id: str, session_id: str
    ) -> ReadModelSnapshot:
        return self._snapshot(
            "getSessionBootstrap",
            actor_user_id=actor_user_id,
            session_id=session_id,
        )

    def read_invitation_preview(
        self, *, capability: VerifiedAccessInvitationCapability
    ) -> ReadModelSnapshot:
        return self._snapshot(
            "inspectAccessInvitation", capability=capability
        )

    def read_public_policy_bundle(
        self, *, policy_bundle_id: str
    ) -> ReadModelSnapshot:
        return self._snapshot(
            "getPolicyBundle", policy_bundle_id=policy_bundle_id
        )

    def read_me(
        self, *, actor_user_id: str, session_id: str
    ) -> ReadModelSnapshot:
        return self._snapshot(
            "getMe", actor_user_id=actor_user_id, session_id=session_id
        )

    def list_my_consent_grants(
        self,
        *,
        actor_user_id: str,
        session_id: str,
        window: ReadPageWindow,
    ) -> ReadModelSnapshot:
        return self._snapshot(
            "listMyConsentGrants",
            actor_user_id=actor_user_id,
            session_id=session_id,
            window=window,
        )

    def list_my_sessions(
        self,
        *,
        actor_user_id: str,
        session_id: str,
        window: ReadPageWindow,
    ) -> ReadModelSnapshot:
        return self._snapshot(
            "listMySessions",
            actor_user_id=actor_user_id,
            session_id=session_id,
            window=window,
        )

    def read_organization_summary(
        self,
        *,
        actor_user_id: str,
        session_id: str,
        organization_id: str,
    ) -> ReadModelSnapshot:
        return self._snapshot(
            "getOrganizationSummary",
            actor_user_id=actor_user_id,
            session_id=session_id,
            organization_id=organization_id,
        )

    def list_organization_access_invitations(
        self,
        *,
        actor_user_id: str,
        session_id: str,
        organization_id: str,
        window: ReadPageWindow,
    ) -> ReadModelSnapshot:
        return self._snapshot(
            "listOrganizationAccessInvitations",
            actor_user_id=actor_user_id,
            session_id=session_id,
            organization_id=organization_id,
            window=window,
        )

    def list_organization_memberships(
        self,
        *,
        actor_user_id: str,
        session_id: str,
        organization_id: str,
        window: ReadPageWindow,
    ) -> ReadModelSnapshot:
        return self._snapshot(
            "listOrganizationMemberships",
            actor_user_id=actor_user_id,
            session_id=session_id,
            organization_id=organization_id,
            window=window,
        )


class StrictInvitationCapabilityVerifier:
    def __init__(self) -> None:
        self.calls: list[tuple[str, datetime]] = []

    def verify(
        self, *, access_invitation_token: str, now: datetime
    ) -> VerifiedAccessInvitationCapability:
        self.calls.append((access_invitation_token, now))
        if access_invitation_token != RAW_INVITATION_TOKEN_SENTINEL:
            raise ValueError("invalid synthetic capability")
        return VerifiedAccessInvitationCapability(
            invitation_id=ORGANIZATION_INVITATION_ID,
            invitation_nonce=CAPABILITY_NONCE_SENTINEL,
            expires_at=NOW + timedelta(days=2),
            token_key_id="invitation-token-key-read-0001",
            token_format_version="access-invitation-token-v1",
        )


class StrictSessionBootstrapCsrfPort:
    def __init__(self) -> None:
        self.calls: list[tuple[str, SessionBootstrapCsrfMaterial]] = []

    def derive(
        self,
        *,
        raw_session_handle: str,
        material: SessionBootstrapCsrfMaterial,
    ) -> str:
        self.calls.append((raw_session_handle, material))
        if raw_session_handle != RAW_SESSION_HANDLE_SENTINEL:
            raise ValueError("wrong synthetic session handle")
        return MASKED_CSRF_RESPONSE


class StrictCursorCodec:
    active_key_id = "iam-read-cursor-key-2026-01"

    def __init__(self) -> None:
        self.decoded: list[str] = []
        self.encoded: list[ReadModelCursorClaims] = []
        self.overrides: dict[str, object] = {}

    def encode(self, claims: ReadModelCursorClaims) -> str:
        self.encoded.append(claims)
        return next_cursor_for(claims.operation_id)

    def decode(self, raw_cursor: str) -> ReadModelCursorClaims:
        self.decoded.append(raw_cursor)
        override = self.overrides.get(raw_cursor)
        if isinstance(override, Exception):
            raise override
        if isinstance(override, ReadModelCursorClaims):
            return override
        for operation_id in _PAGED_OPERATIONS:
            if raw_cursor == next_cursor_for(operation_id):
                facts = _FACTORY_FACTS[operation_id]
                first = facts["rows"][0]
                return cursor_claims(
                    operation_id=operation_id,
                    after_created_at=first["created_at"],
                    after_id=first["sort_id"],
                    organization_id=(
                        ORGANIZATION_ID
                        if operation_id.startswith("listOrganization")
                        else None
                    ),
                    page_limit=1,
                )
        raise ReadModelCursorInvalidError("invalid synthetic cursor")


class StrictReadTelemetry:
    def __init__(self) -> None:
        self.events: list[ReadModelTelemetryEvent] = []

    def record(self, event: ReadModelTelemetryEvent) -> None:
        if not isinstance(event, ReadModelTelemetryEvent):
            raise AssertionError("telemetry accepts only closed events")
        self.events.append(event)


@dataclass
class ReadModelFixture:
    clock: FrozenClock
    repository: StrictReadModelRepository
    capability_verifier: StrictInvitationCapabilityVerifier
    csrf_tokens: StrictSessionBootstrapCsrfPort
    cursor_codec: StrictCursorCodec
    telemetry: StrictReadTelemetry
    actor: ReadActor
    handlers: dict[str, Any]
    queries: dict[str, Any]
    expected: dict[str, dict[str, Any]]


def build_read_model_fixture() -> ReadModelFixture:
    facts = build_authoritative_facts()
    global _FACTORY_FACTS
    _FACTORY_FACTS = deepcopy(facts)
    repository = StrictReadModelRepository(facts)
    clock = FrozenClock()
    capability_verifier = StrictInvitationCapabilityVerifier()
    csrf_tokens = StrictSessionBootstrapCsrfPort()
    cursor_codec = StrictCursorCodec()
    telemetry = StrictReadTelemetry()
    actor = ReadActor(
        actor_user_id=ACTOR_USER_ID,
        current_session_id=CURRENT_SESSION_ID,
        trace_id="trace_read_model_0001",
    )
    common = {
        "repository": repository,
        "clock": clock,
        "telemetry": telemetry,
    }
    handlers = {
        "getSessionBootstrap": GetSessionBootstrapHandler(
            **common, csrf_tokens=csrf_tokens
        ),
        "inspectAccessInvitation": InspectAccessInvitationHandler(
            **common, invitation_capabilities=capability_verifier
        ),
        "getPolicyBundle": GetPolicyBundleHandler(**common),
        "getMe": GetMeHandler(**common),
        "listMyConsentGrants": ListMyConsentGrantsHandler(
            **common, cursor_codec=cursor_codec
        ),
        "listMySessions": ListMySessionsHandler(
            **common, cursor_codec=cursor_codec
        ),
        "getOrganizationSummary": GetOrganizationSummaryHandler(**common),
        "listOrganizationAccessInvitations": (
            ListOrganizationAccessInvitationsHandler(
                **common, cursor_codec=cursor_codec
            )
        ),
        "listOrganizationMemberships": ListOrganizationMembershipsHandler(
            **common, cursor_codec=cursor_codec
        ),
    }
    queries = {
        "getSessionBootstrap": GetSessionBootstrapQuery(
            actor=actor, raw_session_handle=RAW_SESSION_HANDLE_SENTINEL
        ),
        "inspectAccessInvitation": InspectAccessInvitationQuery(
            access_invitation_token=RAW_INVITATION_TOKEN_SENTINEL,
            trace_id=actor.trace_id,
        ),
        "getPolicyBundle": GetPolicyBundleQuery(
            policy_bundle_id=CREATOR_POLICY_BUNDLE_ID,
            trace_id=actor.trace_id,
        ),
        "getMe": GetMeQuery(actor=actor),
        "listMyConsentGrants": ListMyConsentGrantsQuery(actor=actor),
        "listMySessions": ListMySessionsQuery(actor=actor),
        "getOrganizationSummary": GetOrganizationSummaryQuery(
            actor=actor, organization_id=ORGANIZATION_ID
        ),
        "listOrganizationAccessInvitations": (
            ListOrganizationAccessInvitationsQuery(
                actor=actor, organization_id=ORGANIZATION_ID
            )
        ),
        "listOrganizationMemberships": ListOrganizationMembershipsQuery(
            actor=actor, organization_id=ORGANIZATION_ID
        ),
    }
    return ReadModelFixture(
        clock=clock,
        repository=repository,
        capability_verifier=capability_verifier,
        csrf_tokens=csrf_tokens,
        cursor_codec=cursor_codec,
        telemetry=telemetry,
        actor=actor,
        handlers=handlers,
        queries=queries,
        expected=build_expected_bodies(facts),
    )


def build_authoritative_facts() -> dict[str, dict[str, Any]]:
    user = _user()
    session = _current_session()
    family = _session_family()
    organization = _organization()
    actor_membership = _actor_membership()
    actor_membership_role = _actor_membership_role()
    creator_policy = _creator_policy_resource()
    organization_policy = _organization_policy_resource()
    organization_invitation = _organization_invitation(status="ISSUED")
    accepted_invitation = _accepted_invitation()
    creator_source_invitation = _creator_source_invitation()
    actor_authority = {
        "user": deepcopy(user),
        "session": deepcopy(session),
        "family": deepcopy(family),
        "membership": deepcopy(actor_membership),
        "roles": [deepcopy(actor_membership_role)],
        "organization": deepcopy(organization),
    }
    return {
        "getSessionBootstrap": {
            "user": deepcopy(user),
            "session": deepcopy(session),
            "family": deepcopy(family),
        },
        "inspectAccessInvitation": {
            "invitation": deepcopy(organization_invitation),
            "organization": deepcopy(organization),
            "policy": deepcopy(organization_policy),
        },
        "getPolicyBundle": deepcopy(creator_policy),
        "getMe": {
            "user": deepcopy(user),
            "session": deepcopy(session),
            "family": deepcopy(family),
            "user_role_grants": [_creator_user_role()],
            "memberships": [
                {
                    "membership": deepcopy(actor_membership),
                    "organization": deepcopy(organization),
                    "role_grants": [deepcopy(actor_membership_role)],
                }
            ],
            "source_invitations": [
                creator_source_invitation,
                accepted_invitation,
            ],
            "policies": [creator_policy, organization_policy],
            "acceptances": [
                {
                    "user_id": ACTOR_USER_ID,
                    "document_id": TERMS_DOCUMENT_ID,
                    "content_sha256": creator_policy["documents"][0][
                        "content_sha256"
                    ],
                    "policy_bundle_id": CREATOR_POLICY_BUNDLE_ID,
                }
            ],
        },
        "listMyConsentGrants": {
            "actor": deepcopy(actor_authority),
            "rows": _consent_rows(),
        },
        "listMySessions": {
            "actor": deepcopy(actor_authority),
            "rows": [_current_session(), _revoked_session()],
        },
        "getOrganizationSummary": {
            "actor": deepcopy(actor_authority),
            "organization": deepcopy(organization),
        },
        "listOrganizationAccessInvitations": {
            "actor": deepcopy(actor_authority),
            "organization": deepcopy(organization),
            "rows": [
                {
                    "invitation": deepcopy(organization_invitation),
                    "policy": deepcopy(organization_policy),
                    "recipient_mask_verified": True,
                    "sort_id": organization_invitation["invitation_id"],
                    "created_at": organization_invitation["created_at"],
                },
                {
                    "invitation": deepcopy(accepted_invitation),
                    "policy": deepcopy(organization_policy),
                    "recipient_mask_verified": True,
                    "sort_id": accepted_invitation["invitation_id"],
                    "created_at": accepted_invitation["created_at"],
                },
            ],
        },
        "listOrganizationMemberships": {
            "actor": deepcopy(actor_authority),
            "organization": deepcopy(organization),
            "rows": [
                {
                    "membership": deepcopy(actor_membership),
                    "user": deepcopy(user),
                    "role_grants": [deepcopy(actor_membership_role)],
                    "provider_subject": SUBJECT_SENTINEL,
                    "sort_id": ACTOR_MEMBERSHIP_ID,
                    "created_at": actor_membership["created_at"],
                },
                _target_membership_row(),
            ],
        },
    }


def build_expected_bodies(
    facts: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    creator_policy = facts["getPolicyBundle"]
    organization = facts["getOrganizationSummary"]["organization"]
    invitation = facts["inspectAccessInvitation"]["invitation"]
    session_rows = facts["listMySessions"]["rows"]
    consent_rows = facts["listMyConsentGrants"]["rows"]
    invitation_rows = facts["listOrganizationAccessInvitations"]["rows"]
    membership_rows = facts["listOrganizationMemberships"]["rows"]
    expected = {
        "getSessionBootstrap": {
            "session": _session_dto(facts["getSessionBootstrap"]["session"], True),
            "user_status": "ACTIVE",
            "csrf_token": MASKED_CSRF_RESPONSE,
        },
        "inspectAccessInvitation": _invitation_preview_dto(
            invitation, organization
        ),
        "getPolicyBundle": _policy_bundle_dto(creator_policy),
        "getMe": _me_dto(facts["getMe"]),
        "listMyConsentGrants": {
            "items": [_consent_dto(row["grant"], row["categories"]) for row in consent_rows],
            "page": {"next_cursor": None},
        },
        "listMySessions": {
            "items": [
                _session_dto(row, row["session_id"] == CURRENT_SESSION_ID)
                for row in session_rows
            ],
            "page": {"next_cursor": None},
        },
        "getOrganizationSummary": _organization_dto(organization),
        "listOrganizationAccessInvitations": {
            "items": [
                _invitation_admin_dto(row["invitation"], row["policy"])
                for row in invitation_rows
            ],
            "page": {"next_cursor": None},
        },
        "listOrganizationMemberships": {
            "items": [_membership_admin_dto(row) for row in membership_rows],
            "page": {"next_cursor": None},
        },
    }
    return expected


def expected_response(
    fixture: ReadModelFixture, operation_id: str
) -> dict[str, Any]:
    entity_tags = {
        "inspectAccessInvitation": '"v1"',
        "getPolicyBundle": '"v1"',
        "getMe": '"v7"',
        "getOrganizationSummary": '"v4"',
    }
    return {
        "kind": "ok",
        "operation_id": operation_id,
        "body": deepcopy(fixture.expected[operation_id]),
        "entity_tag": entity_tags.get(operation_id),
        "cache_policy": (
            "public, max-age=31536000, immutable"
            if operation_id == "getPolicyBundle"
            else "no-store"
        ),
    }


def next_cursor_for(operation_id: str) -> str:
    return f"cursor_next_{operation_id}_0001"


def cursor_claims(
    *,
    operation_id: str,
    after_created_at: datetime,
    after_id: str,
    organization_id: Optional[str],
    page_limit: int,
) -> ReadModelCursorClaims:
    return ReadModelCursorClaims(
        version="iam-read-cursor-v1",
        key_id="iam-read-cursor-key-2026-01",
        operation_id=operation_id,
        actor_user_id=ACTOR_USER_ID,
        organization_id=organization_id,
        page_limit=page_limit,
        query_shape_digest=PAGED_READ_QUERY_SHAPE_DIGESTS[operation_id],
        snapshot_at=NOW,
        after_created_at=after_created_at,
        after_id=after_id,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=15),
    )


def paged_query(
    fixture: ReadModelFixture,
    operation_id: str,
    *,
    cursor: Optional[str],
    limit: int = 1,
) -> Any:
    page = PageRequest(limit=limit, cursor=cursor)
    if operation_id == "listMyConsentGrants":
        return ListMyConsentGrantsQuery(actor=fixture.actor, page=page)
    if operation_id == "listMySessions":
        return ListMySessionsQuery(actor=fixture.actor, page=page)
    if operation_id == "listOrganizationAccessInvitations":
        return ListOrganizationAccessInvitationsQuery(
            actor=fixture.actor,
            organization_id=ORGANIZATION_ID,
            page=page,
        )
    if operation_id == "listOrganizationMemberships":
        return ListOrganizationMembershipsQuery(
            actor=fixture.actor,
            organization_id=ORGANIZATION_ID,
            page=page,
        )
    raise AssertionError("not a paged operation")


def expected_page(
    fixture: ReadModelFixture,
    operation_id: str,
    *,
    index: int,
) -> dict[str, Any]:
    full_items = fixture.expected[operation_id]["items"]
    return {
        "kind": "ok",
        "operation_id": operation_id,
        "body": {
            "items": [deepcopy(full_items[index])],
            "page": {
                "next_cursor": (
                    next_cursor_for(operation_id) if index == 0 else None
                )
            },
        },
        "entity_tag": None,
        "cache_policy": "no-store",
    }


def all_secret_sentinels() -> tuple[object, ...]:
    return (
        RAW_SESSION_HANDLE_SENTINEL,
        RAW_INVITATION_TOKEN_SENTINEL,
        CONTACT_SENTINEL,
        SUBJECT_SENTINEL,
        RECIPIENT_REF_SENTINEL,
        HANDLE_DIGEST_SENTINEL,
        CSRF_SALT_SENTINEL,
        CSRF_DIGEST_SENTINEL,
        CAPABILITY_NONCE_SENTINEL,
        POLICY_SIGNATURE_SENTINEL,
    )


def _page_facts(facts: dict[str, Any], window: ReadPageWindow) -> dict[str, Any]:
    rows = facts["rows"]
    start = 0
    if window.after_id is not None:
        matching = [
            index for index, row in enumerate(rows) if row["sort_id"] == window.after_id
        ]
        if len(matching) != 1:
            return {**facts, "rows": [], "has_more": False}
        start = matching[0] + 1
    selected = rows[start : start + window.limit + 1]
    return {
        **facts,
        "rows": selected,
        "snapshot_at": window.snapshot_at or NOW,
    }


def _user() -> dict[str, Any]:
    return {
        "user_id": ACTOR_USER_ID,
        "status": "ACTIVE",
        "display_handle": "read_actor",
        "aggregate_version": 7,
        "external_subject": SUBJECT_SENTINEL,
    }


def _session_family() -> dict[str, Any]:
    return {
        "family_id": SESSION_FAMILY_ID,
        "user_id": ACTOR_USER_ID,
        "status": "ACTIVE",
        "current_generation": 3,
        "aggregate_version": 3,
    }


def _current_session() -> dict[str, Any]:
    return {
        "session_id": CURRENT_SESSION_ID,
        "user_id": ACTOR_USER_ID,
        "family_id": SESSION_FAMILY_ID,
        "generation": 3,
        "status": "ACTIVE",
        "created_at": NOW - timedelta(hours=2),
        "last_activity_at": NOW - timedelta(minutes=5),
        "idle_expires_at": NOW + timedelta(minutes=25),
        "absolute_expires_at": NOW + timedelta(hours=10),
        "device_label": "Browser",
        "aggregate_version": 3,
        "handle_digest": HANDLE_DIGEST_SENTINEL,
        "handle_digest_key_id": "session-handle-read-key-0001",
        "csrf_salt": CSRF_SALT_SENTINEL,
        "csrf_key_id": "session-csrf-read-key-0001",
        "csrf_digest": CSRF_DIGEST_SENTINEL,
        "auth_time": NOW - timedelta(minutes=2),
        "acr_code": "urn:example:mfa",
        "amr_codes": ["pwd", "otp"],
        "sort_id": CURRENT_SESSION_ID,
    }


def _revoked_session() -> dict[str, Any]:
    return {
        "session_id": REVOKED_SESSION_ID,
        "user_id": ACTOR_USER_ID,
        "family_id": "session_family_read_old_0002",
        "generation": 1,
        "status": "REVOKED",
        "created_at": NOW - timedelta(days=2),
        "last_activity_at": NOW - timedelta(days=2, minutes=-10),
        "idle_expires_at": NOW - timedelta(days=2, minutes=-30),
        "absolute_expires_at": NOW - timedelta(days=1, hours=12),
        "device_label": "Mobile browser",
        "aggregate_version": 2,
        "handle_digest": HANDLE_DIGEST_SENTINEL,
        "handle_digest_key_id": "session-handle-read-key-0001",
        "csrf_salt": CSRF_SALT_SENTINEL,
        "csrf_key_id": "session-csrf-read-key-0001",
        "csrf_digest": CSRF_DIGEST_SENTINEL,
        "sort_id": REVOKED_SESSION_ID,
    }


def _organization() -> dict[str, Any]:
    return {
        "organization_id": ORGANIZATION_ID,
        "public_name": "Synthetic Research Cooperative",
        "organization_type": "NONPROFIT",
        "jurisdiction": "CN",
        "status": "ACTIVE",
        "aggregate_version": 4,
    }


def _actor_membership() -> dict[str, Any]:
    return {
        "membership_id": ACTOR_MEMBERSHIP_ID,
        "organization_id": ORGANIZATION_ID,
        "user_id": ACTOR_USER_ID,
        "status": "ACTIVE",
        "source_invitation_id": ACCEPTED_INVITATION_ID,
        "aggregate_version": 2,
        "created_at": NOW - timedelta(days=30),
    }


def _actor_membership_role() -> dict[str, Any]:
    return {
        "role_grant_id": "membership_role_read_actor_0001",
        "organization_id": ORGANIZATION_ID,
        "membership_id": ACTOR_MEMBERSHIP_ID,
        "user_id": ACTOR_USER_ID,
        "role_code": "ORG_ADMIN",
        "source_invitation_id": ACCEPTED_INVITATION_ID,
        "policy_selector_digest": ORGANIZATION_SELECTOR_DIGEST,
        "revoked_at": None,
        "aggregate_version": 1,
    }


def _creator_user_role() -> dict[str, Any]:
    return {
        "role_grant_id": "user_role_read_creator_0001",
        "user_id": ACTOR_USER_ID,
        "role_code": "CREATOR",
        "source_invitation_id": CREATOR_INVITATION_ID,
        "policy_selector_digest": CREATOR_SELECTOR_DIGEST,
        "revoked_at": None,
        "aggregate_version": 1,
    }


def _creator_source_invitation() -> dict[str, Any]:
    return {
        "invitation_id": CREATOR_INVITATION_ID,
        "purpose": "CREATOR_ENROLLMENT",
        "organization_id": None,
        "target_scope": "USER",
        "target_role": "CREATOR",
        "is_initial_admin": False,
        "recipient_contact_id": "contact_point_read_creator_0002",
        "recipient_contact_locator": CONTACT_SENTINEL,
        "masked_recipient_label": "r***@example.invalid",
        "policy_selector_digest": CREATOR_SELECTOR_DIGEST,
        "issued_policy_bundle_id": CREATOR_POLICY_BUNDLE_ID,
        "status": "ACCEPTED",
        "accepted_by_user_id": ACTOR_USER_ID,
        "expires_at": NOW + timedelta(days=2),
        "created_at": NOW - timedelta(days=40),
        "aggregate_version": 2,
        "token_nonce": CAPABILITY_NONCE_SENTINEL,
        "token_key_id": "invitation-token-key-read-0001",
        "token_format_version": "access-invitation-token-v1",
        "sort_id": CREATOR_INVITATION_ID,
    }


def _accepted_invitation() -> dict[str, Any]:
    invitation = _organization_invitation(status="ACCEPTED")
    invitation.update(
        {
            "invitation_id": ACCEPTED_INVITATION_ID,
            "accepted_by_user_id": ACTOR_USER_ID,
            "aggregate_version": 2,
            "created_at": NOW - timedelta(days=31),
            "sort_id": ACCEPTED_INVITATION_ID,
        }
    )
    return invitation


def _organization_invitation(*, status: str) -> dict[str, Any]:
    return {
        "invitation_id": ORGANIZATION_INVITATION_ID,
        "purpose": "ORGANIZATION_MEMBERSHIP",
        "organization_id": ORGANIZATION_ID,
        "target_scope": "ORGANIZATION",
        "target_role": "ORG_ADMIN",
        "is_initial_admin": False,
        "recipient_contact_id": "contact_point_read_0001",
        "recipient_contact_locator": CONTACT_SENTINEL,
        "masked_recipient_label": "r***@example.invalid",
        "policy_selector_digest": ORGANIZATION_SELECTOR_DIGEST,
        "issued_policy_bundle_id": ORGANIZATION_POLICY_BUNDLE_ID,
        "status": status,
        "expires_at": NOW + timedelta(days=2),
        "created_at": NOW - timedelta(days=1),
        "aggregate_version": 1 if status == "ISSUED" else 2,
        "accepted_by_user_id": None if status == "ISSUED" else ACTOR_USER_ID,
        "token_nonce": CAPABILITY_NONCE_SENTINEL,
        "token_key_id": "invitation-token-key-read-0001",
        "token_format_version": "access-invitation-token-v1",
        "sort_id": ORGANIZATION_INVITATION_ID,
    }


def _creator_policy_resource() -> dict[str, Any]:
    terms_body = "Synthetic terms body for read-model tests."
    consent_body = "Synthetic optional research consent body."
    terms_hash = hashlib.sha256(terms_body.encode("utf-8")).hexdigest()
    consent_hash = hashlib.sha256(consent_body.encode("utf-8")).hexdigest()
    documents = [
        {
            "document_id": TERMS_DOCUMENT_ID,
            "bundle_id": CREATOR_POLICY_BUNDLE_ID,
            "position": 1,
            "required": True,
            "kind": "TERMS",
            "semantic_version": "1.0.0",
            "locale": "en",
            "jurisdiction": "CN",
            "canonical_body": terms_body,
            "content_sha256": terms_hash,
            "legal_effect": "CONTRACT_ACCEPTANCE",
            "status": "ACTIVE",
        },
        {
            "document_id": CONSENT_DOCUMENT_ID,
            "bundle_id": CREATOR_POLICY_BUNDLE_ID,
            "position": 2,
            "required": False,
            "kind": "CONSENT_TEXT",
            "semantic_version": "1.0.0",
            "locale": "en",
            "jurisdiction": "CN",
            "canonical_body": consent_body,
            "content_sha256": consent_hash,
            "legal_effect": "CONSENT_TEXT",
            "status": "ACTIVE",
        },
    ]
    offer = {
        "canonicalization_version": "consent-offer-json-v1",
        "consent_offer_id": CONSENT_OFFER_ID,
        "consent_offer_version": 1,
        "policy_bundle_id": CREATOR_POLICY_BUNDLE_ID,
        "purpose": "PILOT_RESEARCH",
        "scope_type": "PLATFORM_PARTICIPATION",
        "scope_derivation": "PLATFORM_PARTICIPATION_NULL_SCOPE",
        "data_categories": ["PROFILE", "MATCHING", "RESEARCH"],
        "recipient_ref": RECIPIENT_REF_SENTINEL,
        "recipient_label": "Synthetic Research Controller",
        "supporting_document_id": CONSENT_DOCUMENT_ID,
        "supporting_document_sha256": consent_hash,
        "expiry_rule": "EARLIER_OF_GRANTED_AT_PLUS_365_DAYS_OR_NOT_AFTER",
        "expiry_days": 365,
        "not_after": NOW + timedelta(days=365),
        "optional": True,
    }
    offer["canonical_offer_sha256"] = _canonical_offer_sha256(offer)
    return {
        "selector": {
            "selector_digest": CREATOR_SELECTOR_DIGEST,
            "canonicalization_version": "policy-selector-json-v1",
            "access_purpose": "CREATOR_ENROLLMENT",
            "scope_type": "USER_ROLE",
            "target_role": "CREATOR",
            "jurisdiction": "CN",
            "locale": "en",
            "current_bundle_id": CREATOR_POLICY_BUNDLE_ID,
        },
        "bundle": {
            "policy_bundle_id": CREATOR_POLICY_BUNDLE_ID,
            "selector_digest": CREATOR_SELECTOR_DIGEST,
            "status": "ACTIVE",
            "effective_at": NOW - timedelta(days=2),
            "effective_until": None,
            "aggregate_version": 1,
            "release_signature": POLICY_SIGNATURE_SENTINEL,
        },
        "documents": documents,
        "offers": [offer],
    }


def _organization_policy_resource() -> dict[str, Any]:
    body = "Synthetic organization covenant body."
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    return {
        "selector": {
            "selector_digest": ORGANIZATION_SELECTOR_DIGEST,
            "canonicalization_version": "policy-selector-json-v1",
            "access_purpose": "ORGANIZATION_MEMBERSHIP",
            "scope_type": "ORGANIZATION_ROLE",
            "target_role": "ORG_ADMIN",
            "jurisdiction": "CN",
            "locale": "en",
            "current_bundle_id": ORGANIZATION_POLICY_BUNDLE_ID,
        },
        "bundle": {
            "policy_bundle_id": ORGANIZATION_POLICY_BUNDLE_ID,
            "selector_digest": ORGANIZATION_SELECTOR_DIGEST,
            "status": "ACTIVE",
            "effective_at": NOW - timedelta(days=2),
            "effective_until": None,
            "aggregate_version": 3,
            "release_signature": POLICY_SIGNATURE_SENTINEL,
        },
        "documents": [
            {
                "document_id": ORG_DOCUMENT_ID,
                "bundle_id": ORGANIZATION_POLICY_BUNDLE_ID,
                "position": 1,
                "required": True,
                "kind": "COMMUNITY_TRANSACTION_COVENANT",
                "semantic_version": "1.0.0",
                "locale": "en",
                "jurisdiction": "CN",
                "canonical_body": body,
                "content_sha256": digest,
                "legal_effect": "CONTRACT_ACCEPTANCE",
                "status": "ACTIVE",
            }
        ],
        "offers": [],
    }


def _consent_rows() -> list[dict[str, Any]]:
    creator_policy = _creator_policy_resource()
    offer = creator_policy["offers"][0]
    active = {
        "consent_grant_id": ACTIVE_CONSENT_GRANT_ID,
        "user_id": ACTOR_USER_ID,
        "consent_offer_id": CONSENT_OFFER_ID,
        "consent_offer_version": 1,
        "policy_bundle_id": CREATOR_POLICY_BUNDLE_ID,
        "purpose": "PILOT_RESEARCH",
        "scope_type": "PLATFORM_PARTICIPATION",
        "scope_id": None,
        "recipient_ref": RECIPIENT_REF_SENTINEL,
        "recipient_label": offer["recipient_label"],
        "document_id": CONSENT_DOCUMENT_ID,
        "content_sha256": offer["supporting_document_sha256"],
        "granted_at": NOW - timedelta(days=1),
        "expires_at": NOW + timedelta(days=364),
        "status": "ACTIVE",
        "withdrawn_at": None,
        "aggregate_version": 1,
        "sort_id": ACTIVE_CONSENT_GRANT_ID,
    }
    withdrawn = {
        **deepcopy(active),
        "consent_grant_id": WITHDRAWN_CONSENT_GRANT_ID,
        "granted_at": NOW - timedelta(days=30),
        "expires_at": NOW + timedelta(days=335),
        "status": "WITHDRAWN",
        "withdrawn_at": NOW - timedelta(days=2),
        "aggregate_version": 2,
        "sort_id": WITHDRAWN_CONSENT_GRANT_ID,
    }
    return [
        {
            "grant": active,
            "categories": offer["data_categories"],
            "withdrawals": [],
            "sort_id": active["consent_grant_id"],
            "created_at": active["granted_at"],
        },
        {
            "grant": withdrawn,
            "categories": offer["data_categories"],
            "withdrawals": [
                {
                    "consent_grant_id": WITHDRAWN_CONSENT_GRANT_ID,
                    "user_id": ACTOR_USER_ID,
                    "withdrawn_at": withdrawn["withdrawn_at"],
                }
            ],
            "sort_id": withdrawn["consent_grant_id"],
            "created_at": withdrawn["granted_at"],
        },
    ]


def _target_membership_row() -> dict[str, Any]:
    membership = {
        "membership_id": TARGET_MEMBERSHIP_ID,
        "organization_id": ORGANIZATION_ID,
        "user_id": OTHER_USER_ID,
        "status": "SUSPENDED",
        "source_invitation_id": ORGANIZATION_INVITATION_ID,
        "aggregate_version": 3,
        "created_at": NOW - timedelta(days=60),
    }
    return {
        "membership": membership,
        "user": {
            "user_id": OTHER_USER_ID,
            "status": "ACTIVE",
            "display_handle": "read_member",
            "aggregate_version": 2,
        },
        "role_grants": [
            {
                "role_grant_id": "membership_role_read_target_0002",
                "organization_id": ORGANIZATION_ID,
                "membership_id": TARGET_MEMBERSHIP_ID,
                "user_id": OTHER_USER_ID,
                "role_code": "ORG_ADMIN",
                "source_invitation_id": ORGANIZATION_INVITATION_ID,
                "policy_selector_digest": ORGANIZATION_SELECTOR_DIGEST,
                "revoked_at": None,
                "aggregate_version": 1,
            }
        ],
        "provider_subject": SUBJECT_SENTINEL,
        "sort_id": TARGET_MEMBERSHIP_ID,
        "created_at": membership["created_at"],
    }


def _policy_bundle_dto(policy: Mapping[str, Any]) -> dict[str, Any]:
    selector = policy["selector"]
    bundle = policy["bundle"]
    return {
        "policy_bundle_id": bundle["policy_bundle_id"],
        "purpose": selector["access_purpose"],
        "jurisdiction": selector["jurisdiction"],
        "locale": selector["locale"],
        "documents": [
            {
                "document_id": document["document_id"],
                "kind": document["kind"],
                "semantic_version": document["semantic_version"],
                "locale": document["locale"],
                "content_sha256": document["content_sha256"],
                "legal_effect": document["legal_effect"],
                "body": document["canonical_body"],
            }
            for document in policy["documents"]
        ],
        "consent_offers": [
            {
                "consent_offer_id": offer["consent_offer_id"],
                "purpose": offer["purpose"],
                "scope_type": offer["scope_type"],
                "data_categories": deepcopy(offer["data_categories"]),
                "document_id": offer["supporting_document_id"],
                "content_sha256": offer["supporting_document_sha256"],
                "recipient_label": offer["recipient_label"],
                "expiry_rule": offer["expiry_rule"],
                "not_after": _timestamp(offer["not_after"]),
                "canonical_offer_sha256": offer["canonical_offer_sha256"],
                "optional": True,
            }
            for offer in policy["offers"]
        ],
        "effective_at": _timestamp(bundle["effective_at"]),
        "entity_tag": _etag(bundle["aggregate_version"]),
    }


def _me_dto(facts: Mapping[str, Any]) -> dict[str, Any]:
    user = facts["user"]
    membership_entry = facts["memberships"][0]
    policies = {
        policy["selector"]["selector_digest"]: policy
        for policy in facts["policies"]
    }
    accepted = {
        (item["document_id"], item["content_sha256"])
        for item in facts["acceptances"]
        if item["user_id"] == user["user_id"]
    }
    scopes = [
        (
            facts["user_role_grants"][0]["policy_selector_digest"],
            "CREATOR",
            "USER_ROLE",
            None,
        ),
        (
            membership_entry["role_grants"][0]["policy_selector_digest"],
            "ORG_ADMIN",
            "ORGANIZATION_ROLE",
            ORGANIZATION_ID,
        ),
    ]
    requirements = []
    for selector_digest, role, scope_type, scope_id in sorted(scopes):
        policy = policies[selector_digest]
        required = [doc for doc in policy["documents"] if doc["required"]]
        missing = [
            doc["document_id"]
            for doc in required
            if (doc["document_id"], doc["content_sha256"]) not in accepted
        ]
        requirements.append(
            {
                "selector_digest": selector_digest,
                "purpose": policy["selector"]["access_purpose"],
                "role": role,
                "scope_type": scope_type,
                "scope_id": scope_id,
                "satisfied": not missing,
                "required_policy_bundle_id": policy["bundle"]["policy_bundle_id"],
                "missing_document_ids": missing,
            }
        )
    membership = membership_entry["membership"]
    organization = membership_entry["organization"]
    return {
        "user_id": user["user_id"],
        "status": user["status"],
        "display_handle": user["display_handle"],
        "user_roles": ["CREATOR"],
        "memberships": [
            {
                "membership_id": membership["membership_id"],
                "organization": _organization_dto(organization),
                "status": membership["status"],
                "roles": ["ORG_ADMIN"],
                "aggregate_version": membership["aggregate_version"],
                "entity_tag": _etag(membership["aggregate_version"]),
            }
        ],
        "policy_requirements": requirements,
        "aggregate_version": user["aggregate_version"],
        "entity_tag": _etag(user["aggregate_version"]),
    }


def _organization_dto(organization: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "organization_id": organization["organization_id"],
        "public_name": organization["public_name"],
        "type": organization["organization_type"],
        "status": organization["status"],
        "aggregate_version": organization["aggregate_version"],
        "entity_tag": _etag(organization["aggregate_version"]),
    }


def _invitation_preview_dto(
    invitation: Mapping[str, Any], organization: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        "invitation_id": invitation["invitation_id"],
        "purpose": invitation["purpose"],
        "organization": {"public_name": organization["public_name"]},
        "target_role": invitation["target_role"],
        "expires_at": _timestamp(invitation["expires_at"]),
        "required_policy_bundle_id": ORGANIZATION_POLICY_BUNDLE_ID,
        "status": "ISSUED",
        "aggregate_version": invitation["aggregate_version"],
        "entity_tag": _etag(invitation["aggregate_version"]),
    }


def _invitation_admin_dto(
    invitation: Mapping[str, Any], policy: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        "invitation_id": invitation["invitation_id"],
        "purpose": invitation["purpose"],
        "organization_id": invitation["organization_id"],
        "target_role": invitation["target_role"],
        "masked_recipient_label": invitation["masked_recipient_label"],
        "is_initial_admin": invitation["is_initial_admin"],
        "status": invitation["status"],
        "expires_at": _timestamp(invitation["expires_at"]),
        "created_at": _timestamp(invitation["created_at"]),
        "required_policy_bundle_id": policy["bundle"]["policy_bundle_id"],
        "aggregate_version": invitation["aggregate_version"],
        "entity_tag": _etag(invitation["aggregate_version"]),
    }


def _membership_admin_dto(row: Mapping[str, Any]) -> dict[str, Any]:
    membership = row["membership"]
    user = row["user"]
    return {
        "membership_id": membership["membership_id"],
        "organization_id": membership["organization_id"],
        "user_id": membership["user_id"],
        "display_handle": user["display_handle"],
        "status": membership["status"],
        "roles": sorted({grant["role_code"] for grant in row["role_grants"]}),
        "aggregate_version": membership["aggregate_version"],
        "entity_tag": _etag(membership["aggregate_version"]),
    }


def _session_dto(session: Mapping[str, Any], is_current: bool) -> dict[str, Any]:
    expires_at = min(session["idle_expires_at"], session["absolute_expires_at"])
    return {
        "session_id": session["session_id"],
        "created_at": _timestamp(session["created_at"]),
        "last_activity_at": _timestamp(session["last_activity_at"]),
        "expires_at": _timestamp(expires_at),
        "is_current": is_current,
        "device_label": session["device_label"],
        "status": session["status"],
    }


def _consent_dto(
    grant: Mapping[str, Any], categories: list[str]
) -> dict[str, Any]:
    return {
        "consent_grant_id": grant["consent_grant_id"],
        "consent_offer_id": grant["consent_offer_id"],
        "purpose": grant["purpose"],
        "scope_type": grant["scope_type"],
        "scope_id": grant["scope_id"],
        "data_categories": deepcopy(categories),
        "recipient_label": grant["recipient_label"],
        "document_id": grant["document_id"],
        "content_sha256": grant["content_sha256"],
        "granted_at": _timestamp(grant["granted_at"]),
        "expires_at": _timestamp(grant["expires_at"]),
        "status": grant["status"],
        "aggregate_version": grant["aggregate_version"],
        "entity_tag": _etag(grant["aggregate_version"]),
    }


def _canonical_offer_sha256(offer: Mapping[str, Any]) -> str:
    canonical = {
        key: (
            _timestamp(value) if isinstance(value, datetime) else value
        )
        for key, value in offer.items()
        if key != "canonical_offer_sha256"
    }
    encoded = json.dumps(
        canonical,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _etag(version: int) -> str:
    return f'"v{version}"'


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


_PAGED_OPERATIONS = {
    "listMyConsentGrants",
    "listMySessions",
    "listOrganizationAccessInvitations",
    "listOrganizationMemberships",
}
_FACTORY_FACTS: dict[str, dict[str, Any]] = {}


__all__ = [
    "ACTOR_USER_ID",
    "ACTIVE_CONSENT_GRANT_ID",
    "CONTACT_SENTINEL",
    "CREATOR_POLICY_BUNDLE_ID",
    "CURRENT_SESSION_ID",
    "HANDLE_DIGEST_SENTINEL",
    "MASKED_CSRF_RESPONSE",
    "NOW",
    "OPERATION_IDS",
    "ORGANIZATION_ID",
    "ORGANIZATION_INVITATION_ID",
    "OTHER_ORGANIZATION_ID",
    "OTHER_USER_ID",
    "RAW_INVITATION_TOKEN_SENTINEL",
    "RAW_SESSION_HANDLE_SENTINEL",
    "RECIPIENT_REF_SENTINEL",
    "STATEMENT_BUDGETS",
    "SUBJECT_SENTINEL",
    "WITHDRAWN_CONSENT_GRANT_ID",
    "all_secret_sentinels",
    "build_read_model_fixture",
    "cursor_claims",
    "expected_page",
    "expected_response",
    "next_cursor_for",
    "paged_query",
]
