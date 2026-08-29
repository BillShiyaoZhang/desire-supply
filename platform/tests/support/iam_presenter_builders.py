"""Strict presenter fixtures for the 25-operation IAM HTTP registry."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Mapping, Tuple

from desire_platform.http import AuthenticatedHttpActor, IamHttpInvocation
from desire_platform.identity_access.application.access_invitations import (
    AcceptAccessInvitationResult,
    SessionRotation,
)
from desire_platform.identity_access.application.authentication import (
    BeginOidcAuthorizationResult,
    CompleteOidcAuthenticationResult,
)
from desire_platform.identity_access.application.issue_access_invitations import (
    IssueAccessInvitationResult,
)
from desire_platform.identity_access.application.organization_profile import (
    UpdateOrganizationPublicNameResult,
)
from desire_platform.identity_access.application.policy_consent_commands import (
    PolicyConsentCommandResult,
)
from desire_platform.identity_access.application.read_models import (
    ReadCachePolicy,
    ReadModelResponse,
)
from desire_platform.identity_access.domain.authority_lifecycle import (
    LifecycleCommandResult,
)
from desire_platform.identity_access.ports.read_models import freeze_fact_object


NOW = datetime(2026, 8, 8, 3, 4, 5, tzinfo=timezone.utc)
RAW_SESSION_HANDLE = "presenter_session_handle_0123456789abcdef"
RAW_OIDC_COOKIE = "presenter_oidc_cookie_0123456789abcdef"
RAW_SUCCESSOR_HANDLE = "presenter_successor_handle_0123456789abcdef"
RAW_INVITATION_TOKEN = "presenter_invitation_token_0123456789abcdef"
IDEMPOTENCY_KEY = "presenter_idem_0123456789abcdef"
TRACE_ID = "trace_presenter_0123456789abcdef"


def freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        return tuple((key, freeze_json(item)) for key, item in value.items())
    if isinstance(value, list):
        return tuple(freeze_json(item) for item in value)
    return value


ACTOR = AuthenticatedHttpActor(
    actor_user_id="user_presenter_0123456789",
    session_id="session_presenter_0123456789",
    correlation_id="correlation_presenter_0123456789",
    causation_id="causation_presenter_0123456789",
    trace_id=TRACE_ID,
    original_actor_id="original_presenter_0123456789",
    auth_time=NOW - timedelta(minutes=4),
    acr_code="urn:example:acr:mfa",
    amr_codes=("pwd", "otp"),
)


PATHS: Mapping[str, str] = {
    "beginOidcAuthorization": "/v1/auth/oidc/authorizations",
    "completeOidcAuthorization": "/v1/auth/oidc/callback",
    "getSessionBootstrap": "/v1/auth/session",
    "inspectAccessInvitation": "/v1/access-invitations/inspect",
    "acceptAccessInvitation": "/v1/access-invitations/invitation_presenter_012345/accept",
    "revokeAccessInvitation": "/v1/access-invitations/invitation_presenter_012345/revoke",
    "getPolicyBundle": "/v1/policy-bundles/policy_bundle_presenter_012345",
    "getMe": "/v1/me",
    "acceptCurrentPolicies": "/v1/me/policy-acceptances",
    "listMyConsentGrants": "/v1/me/consents",
    "grantConsent": "/v1/me/consents",
    "withdrawConsent": "/v1/me/consents/consent_grant_presenter_012345/withdraw",
    "listMySessions": "/v1/me/sessions",
    "revokeMySession": "/v1/me/sessions/session_target_presenter_012345",
    "getOrganizationSummary": "/v1/organizations/organization_presenter_012345",
    "updateOrganizationPublicName": "/v1/organizations/organization_presenter_012345/public-name",
    "listOrganizationAccessInvitations": "/v1/organizations/organization_presenter_012345/access-invitations",
    "issueOrganizationAccessInvitation": "/v1/organizations/organization_presenter_012345/access-invitations",
    "listOrganizationMemberships": "/v1/organizations/organization_presenter_012345/memberships",
    "suspendMembership": "/v1/memberships/membership_presenter_012345/suspend",
    "resumeMembership": "/v1/memberships/membership_presenter_012345/resume",
    "revokeMembership": "/v1/memberships/membership_presenter_012345/revoke",
    "suspendUser": "/v1/platform/users/user_target_presenter_012345/suspend",
    "resumeUser": "/v1/platform/users/user_target_presenter_012345/resume",
    "revokeAllUserSessions": "/v1/platform/users/user_target_presenter_012345/revoke-all-sessions",
}


PATH_PARAMETERS: Mapping[str, Tuple[Tuple[str, str], ...]] = {
    "acceptAccessInvitation": (("invitation_id", "invitation_presenter_012345"),),
    "revokeAccessInvitation": (("invitation_id", "invitation_presenter_012345"),),
    "getPolicyBundle": (("policy_bundle_id", "policy_bundle_presenter_012345"),),
    "withdrawConsent": (("consent_grant_id", "consent_grant_presenter_012345"),),
    "revokeMySession": (("session_id", "session_target_presenter_012345"),),
    "getOrganizationSummary": (("organization_id", "organization_presenter_012345"),),
    "updateOrganizationPublicName": (("organization_id", "organization_presenter_012345"),),
    "listOrganizationAccessInvitations": (("organization_id", "organization_presenter_012345"),),
    "issueOrganizationAccessInvitation": (("organization_id", "organization_presenter_012345"),),
    "listOrganizationMemberships": (("organization_id", "organization_presenter_012345"),),
    "suspendMembership": (("membership_id", "membership_presenter_012345"),),
    "resumeMembership": (("membership_id", "membership_presenter_012345"),),
    "revokeMembership": (("membership_id", "membership_presenter_012345"),),
    "suspendUser": (("user_id", "user_target_presenter_012345"),),
    "resumeUser": (("user_id", "user_target_presenter_012345"),),
    "revokeAllUserSessions": (("user_id", "user_target_presenter_012345"),),
}


POLICY_REQUIREMENT = {
    "selector_digest": "a" * 64,
    "scope_type": "ORGANIZATION_ROLE",
    "scope_id": "organization_presenter_012345",
}
POLICY_ACCEPTANCE = {
    "document_id": "document_presenter_012345",
    "content_sha256": "b" * 64,
    "affirmed": True,
}
CONSENT_CHOICE = {
    "consent_offer_id": "consent_offer_presenter_012345",
    "document_id": "consent_document_presenter_012345",
    "content_sha256": "c" * 64,
    "affirmed": True,
}


def body_for(operation_id: str) -> Dict[str, Any]:
    bodies: Dict[str, Dict[str, Any]] = {
        "beginOidcAuthorization": {
            "return_to": "/app",
            "access_invitation_token": RAW_INVITATION_TOKEN,
        },
        "inspectAccessInvitation": {
            "access_invitation_token": RAW_INVITATION_TOKEN,
        },
        "acceptAccessInvitation": {
            "policy_bundle_id": "policy_bundle_presenter_012345",
            "policy_acceptances": [dict(POLICY_ACCEPTANCE)],
            "consent_grants": [dict(CONSENT_CHOICE)],
        },
        "revokeAccessInvitation": {
            "reason_code": "ADMIN_REVOKED",
            "reason_note": "Closed administrative reason.",
        },
        "acceptCurrentPolicies": {
            "policy_requirement": dict(POLICY_REQUIREMENT),
            "policy_bundle_id": "policy_bundle_presenter_012345",
            "policy_acceptances": [dict(POLICY_ACCEPTANCE)],
        },
        "grantConsent": {
            "policy_requirement": dict(POLICY_REQUIREMENT),
            "policy_bundle_id": "policy_bundle_presenter_012345",
            **CONSENT_CHOICE,
        },
        "withdrawConsent": {"reason_code": "USER_WITHDREW"},
        "issueOrganizationAccessInvitation": {
            "recipient": {"type": "EMAIL", "value": "invitee@example.test"},
            "target_role": "DEMAND_OWNER",
            "expires_at": "2026-08-12T00:00:00Z",
        },
        "updateOrganizationPublicName": {
            "public_name": "Corrected Organization",
            "reason_code": "PUBLIC_NAME_CORRECTION",
        },
        "suspendMembership": {"reason_code": "SAFETY_REVIEW"},
        "resumeMembership": {"reason_code": "REVIEW_CLEARED"},
        "revokeMembership": {"reason_code": "ADMIN_REVOKED"},
        "suspendUser": {"reason_code": "SAFETY_REVIEW"},
        "resumeUser": {"reason_code": "REVIEW_CLEARED"},
        "revokeAllUserSessions": {"reason_code": "SECURITY_RESPONSE"},
    }
    return bodies.get(operation_id, {})


PAGED = {
    "listMyConsentGrants",
    "listMySessions",
    "listOrganizationAccessInvitations",
    "listOrganizationMemberships",
}
ANONYMOUS = {
    "completeOidcAuthorization",
    "inspectAccessInvitation",
    "getPolicyBundle",
}
NON_IDEMPOTENT = {
    "beginOidcAuthorization",
    "completeOidcAuthorization",
    "getSessionBootstrap",
    "inspectAccessInvitation",
    "getPolicyBundle",
    "getMe",
    "listMyConsentGrants",
    "listMySessions",
    "getOrganizationSummary",
    "listOrganizationAccessInvitations",
    "listOrganizationMemberships",
}
NO_IF_MATCH = NON_IDEMPOTENT | {"revokeMySession"}


def invocation_for(operation_id: str) -> IamHttpInvocation:
    query: Tuple[Tuple[str, str], ...] = ()
    if operation_id == "completeOidcAuthorization":
        query = (("state", "S" * 43), ("code", "C" * 43))
    elif operation_id in PAGED:
        query = (("cursor", "cursor_presenter_0123456789"), ("limit", "37"))
    return IamHttpInvocation(
        operation_id=operation_id,
        canonical_path=PATHS[operation_id],
        path_parameters=PATH_PARAMETERS.get(operation_id, ()),
        query_parameters=query,
        json_body=freeze_json(body_for(operation_id)),
        actor=None if operation_id in ANONYMOUS else ACTOR,
        idempotency_key=(None if operation_id in NON_IDEMPOTENT else IDEMPOTENCY_KEY),
        expected_version=None if operation_id in NO_IF_MATCH else 7,
        trace_id=TRACE_ID,
        raw_session_handle=(None if operation_id in ANONYMOUS else RAW_SESSION_HANDLE),
        raw_oidc_browser_cookie=(
            RAW_OIDC_COOKIE if operation_id == "completeOidcAuthorization" else None
        ),
    )


class RecordingHandler:
    def __init__(self, result: Any) -> None:
        self.result = result
        self.calls: List[Tuple[Tuple[Any, ...], Dict[str, Any]]] = []

    def handle(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append((args, kwargs))
        return self.result


READ_OPERATIONS = {
    "getSessionBootstrap",
    "inspectAccessInvitation",
    "getPolicyBundle",
    "getMe",
    "listMyConsentGrants",
    "listMySessions",
    "getOrganizationSummary",
    "listOrganizationAccessInvitations",
    "listOrganizationMemberships",
}


def result_for(operation_id: str) -> Any:
    if operation_id == "beginOidcAuthorization":
        return BeginOidcAuthorizationResult(
            auth_transaction_id="auth_transaction_presenter_012345",
            authorization_url="https://idp.example.test/authorize?opaque=1",
            expires_at=NOW + timedelta(minutes=10),
            oidc_browser_cookie=RAW_OIDC_COOKIE,
        )
    if operation_id == "completeOidcAuthorization":
        return CompleteOidcAuthenticationResult(
            return_to="/app",
            session_id="session_successor_presenter_012345",
            user_id=ACTOR.actor_user_id,
            user_status="ACTIVE",
            raw_session_handle=RAW_SUCCESSOR_HANDLE,
            csrf_token="csrf_presenter_0123456789abcdefghijklmnop",
        )
    if operation_id in READ_OPERATIONS:
        entity_tag = (
            '"v7"'
            if operation_id
            in {
                "inspectAccessInvitation",
                "getPolicyBundle",
                "getMe",
                "getOrganizationSummary",
            }
            else None
        )
        cache = (
            ReadCachePolicy.PUBLIC_IMMUTABLE
            if operation_id == "getPolicyBundle"
            else ReadCachePolicy.NO_STORE
        )
        return ReadModelResponse(
            operation_id=operation_id,
            json_body=freeze_fact_object({"operation_id": operation_id, "safe": True}),
            entity_tag=entity_tag,
            cache_policy=cache,
        )
    if operation_id == "acceptAccessInvitation":
        return AcceptAccessInvitationResult(
            replayed=False,
            safe_response={
                "invitation": {"entity_tag": '"v8"'},
                "me": {"entity_tag": '"v2"'},
                "activated_scope": "ORGANIZATION_MEMBERSHIP",
            },
            session_rotation=SessionRotation(
                session_id="session_successor_presenter_012345",
                raw_session_handle=RAW_SUCCESSOR_HANDLE,
                csrf_token="csrf_presenter_0123456789abcdefghijklmnop",
            ),
        )
    if operation_id in {"acceptCurrentPolicies", "grantConsent"}:
        return PolicyConsentCommandResult(
            operation_id=operation_id,
            replayed=False,
            http_status=200 if operation_id == "acceptCurrentPolicies" else 201,
            json_body={"operation_id": operation_id, "entity_tag": '"v8"'},
            response_entity_tag='"v8"',
            current_user_entity_tag='"v3"',
        )
    if operation_id == "issueOrganizationAccessInvitation":
        return IssueAccessInvitationResult(
            replayed=False,
            invitation={"invitation_id": "invitation_presenter_012345", "entity_tag": '"v1"'},
            access_invitation_token=RAW_INVITATION_TOKEN,
            join_fragment_url="/join#presenter_invitation_token_0123456789abcdef",
        )
    if operation_id == "updateOrganizationPublicName":
        return UpdateOrganizationPublicNameResult(
            replayed=False,
            organization={
                "organization_id": "organization_presenter_012345",
                "public_name": "Corrected Organization",
                "type": "BUSINESS",
                "status": "ACTIVE",
                "aggregate_version": 8,
                "entity_tag": '"v8"',
            },
        )
    status = 204 if operation_id == "revokeMySession" else 200
    safe_response = None if status == 204 else {
        "operation_id": operation_id,
        "entity_tag": '"v8"',
    }
    return LifecycleCommandResult(
        replayed=False,
        http_status=status,
        safe_response=safe_response,
        clear_current_session_cookie=(operation_id == "revokeMySession"),
    )


BINDING_FIELDS: Mapping[str, str] = {
    "beginOidcAuthorization": "begin_oidc_authorization",
    "completeOidcAuthorization": "complete_oidc_authorization",
    "getSessionBootstrap": "get_session_bootstrap",
    "inspectAccessInvitation": "inspect_access_invitation",
    "acceptAccessInvitation": "accept_access_invitation",
    "revokeAccessInvitation": "revoke_access_invitation",
    "getPolicyBundle": "get_policy_bundle",
    "getMe": "get_me",
    "acceptCurrentPolicies": "accept_current_policies",
    "listMyConsentGrants": "list_my_consent_grants",
    "grantConsent": "grant_consent",
    "withdrawConsent": "withdraw_consent",
    "listMySessions": "list_my_sessions",
    "revokeMySession": "revoke_my_session",
    "getOrganizationSummary": "get_organization_summary",
    "updateOrganizationPublicName": "update_organization_public_name",
    "listOrganizationAccessInvitations": "list_organization_access_invitations",
    "issueOrganizationAccessInvitation": "issue_organization_access_invitation",
    "listOrganizationMemberships": "list_organization_memberships",
    "suspendMembership": "suspend_membership",
    "resumeMembership": "resume_membership",
    "revokeMembership": "revoke_membership",
    "suspendUser": "suspend_user",
    "resumeUser": "resume_user",
    "revokeAllUserSessions": "revoke_all_user_sessions",
}


@dataclass
class PresenterFixture:
    handlers: Dict[str, RecordingHandler]
    bindings: Any


def make_presenter_fixture() -> PresenterFixture:
    from desire_platform.http import IamHttpPresenterBindings

    handlers = {
        operation_id: RecordingHandler(result_for(operation_id))
        for operation_id in BINDING_FIELDS
    }
    bindings = IamHttpPresenterBindings(
        **{
            field_name: handlers[operation_id]
            for operation_id, field_name in BINDING_FIELDS.items()
        }
    )
    return PresenterFixture(handlers=handlers, bindings=bindings)


__all__ = [
    "ACTOR",
    "BINDING_FIELDS",
    "CONSENT_CHOICE",
    "IDEMPOTENCY_KEY",
    "NOW",
    "PATHS",
    "POLICY_ACCEPTANCE",
    "POLICY_REQUIREMENT",
    "RAW_INVITATION_TOKEN",
    "RAW_OIDC_COOKIE",
    "RAW_SESSION_HANDLE",
    "RAW_SUCCESSOR_HANDLE",
    "TRACE_ID",
    "body_for",
    "freeze_json",
    "invocation_for",
    "make_presenter_fixture",
]
