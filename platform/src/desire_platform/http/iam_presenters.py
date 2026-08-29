"""Explicit application presenters for the 25 public IAM HTTP operations."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from datetime import datetime, timedelta, timezone
from enum import Enum
import unicodedata
from typing import Any, Optional, Tuple

from desire_platform.identity_access.application.access_invitations import (
    AcceptAccessInvitationCommand,
    AcceptAccessInvitationResult,
    ActorContext,
    SessionRotation,
)
from desire_platform.identity_access.application.authentication import (
    BeginOidcAuthorizationCommand,
    BeginOidcAuthorizationResult,
    CompleteOidcAuthenticationCommand,
    CompleteOidcAuthenticationResult,
    OidcBrowserContext,
)
from desire_platform.identity_access.application.issue_access_invitations import (
    InvitationIssuerContext,
    IssueAccessInvitationCommand,
    IssueAccessInvitationResult,
    IssuerKind,
    RecipientContactType,
    RecipientInput,
)
from desire_platform.identity_access.application.organization_profile import (
    OrganizationPublicNameActorContext,
    OrganizationPublicNameReasonCode,
    UpdateOrganizationPublicNameCommand,
    UpdateOrganizationPublicNameResult,
)
from desire_platform.identity_access.application.policy_consent_commands import (
    AcceptCurrentPoliciesCommand,
    GrantConsentCommand,
    PolicyConsentActor,
    PolicyConsentCommandResult,
    PolicyRequirementReference,
    PolicyRequirementScopeType,
)
from desire_platform.identity_access.application.read_models import (
    GetMeQuery,
    GetOrganizationSummaryQuery,
    GetPolicyBundleQuery,
    GetSessionBootstrapQuery,
    InspectAccessInvitationQuery,
    ListMyConsentGrantsQuery,
    ListMySessionsQuery,
    ListOrganizationAccessInvitationsQuery,
    ListOrganizationMembershipsQuery,
    PageRequest,
    ReadActor,
    ReadCachePolicy,
    ReadModelResponse,
)
from desire_platform.identity_access.domain.authority_lifecycle import (
    LifecycleActorContext,
    LifecycleCommandResult,
    LifecycleReason,
    ResumeMembershipCommand,
    ResumeUserCommand,
    RevokeAccessInvitationCommand,
    RevokeAllSessionsCommand,
    RevokeMembershipCommand,
    RevokeSessionCommand,
    SuspendMembershipCommand,
    SuspendUserCommand,
    WithdrawConsentGrantCommand,
)
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.domain.invitations import TargetRole
from desire_platform.identity_access.domain.policies import (
    ConsentOfferChoice,
    PolicyAcceptance,
)

from .contracts import (
    AuthenticatedHttpActor,
    CookieMutation,
    CookieMutationKind,
    FrozenJsonObject,
    FrozenJsonValue,
    IamHttpInvocation,
    IamHttpOperationResult,
)


_OPERATION_PATHS = {
    "beginOidcAuthorization": "/v1/auth/oidc/authorizations",
    "completeOidcAuthorization": "/v1/auth/oidc/callback",
    "getSessionBootstrap": "/v1/auth/session",
    "inspectAccessInvitation": "/v1/access-invitations/inspect",
    "acceptAccessInvitation": "/v1/access-invitations/{invitation_id}/accept",
    "revokeAccessInvitation": "/v1/access-invitations/{invitation_id}/revoke",
    "getPolicyBundle": "/v1/policy-bundles/{policy_bundle_id}",
    "getMe": "/v1/me",
    "acceptCurrentPolicies": "/v1/me/policy-acceptances",
    "listMyConsentGrants": "/v1/me/consents",
    "grantConsent": "/v1/me/consents",
    "withdrawConsent": "/v1/me/consents/{consent_grant_id}/withdraw",
    "listMySessions": "/v1/me/sessions",
    "revokeMySession": "/v1/me/sessions/{session_id}",
    "getOrganizationSummary": "/v1/organizations/{organization_id}",
    "updateOrganizationPublicName": "/v1/organizations/{organization_id}/public-name",
    "listOrganizationAccessInvitations": "/v1/organizations/{organization_id}/access-invitations",
    "issueOrganizationAccessInvitation": "/v1/organizations/{organization_id}/access-invitations",
    "listOrganizationMemberships": "/v1/organizations/{organization_id}/memberships",
    "suspendMembership": "/v1/memberships/{membership_id}/suspend",
    "resumeMembership": "/v1/memberships/{membership_id}/resume",
    "revokeMembership": "/v1/memberships/{membership_id}/revoke",
    "suspendUser": "/v1/platform/users/{user_id}/suspend",
    "resumeUser": "/v1/platform/users/{user_id}/resume",
    "revokeAllUserSessions": "/v1/platform/users/{user_id}/revoke-all-sessions",
}

_IDEMPOTENT_OPERATIONS = {
    "acceptAccessInvitation",
    "revokeAccessInvitation",
    "acceptCurrentPolicies",
    "grantConsent",
    "withdrawConsent",
    "revokeMySession",
    "issueOrganizationAccessInvitation",
    "updateOrganizationPublicName",
    "suspendMembership",
    "resumeMembership",
    "revokeMembership",
    "suspendUser",
    "resumeUser",
    "revokeAllUserSessions",
}
_IF_MATCH_OPERATIONS = _IDEMPOTENT_OPERATIONS - {"revokeMySession"}
_REQUIRED_ACTOR_OPERATIONS = {
    operation
    for operation in _OPERATION_PATHS
    if operation
    not in {
        "beginOidcAuthorization",
        "completeOidcAuthorization",
        "inspectAccessInvitation",
        "getPolicyBundle",
    }
}
_ANONYMOUS_OPERATIONS = {
    "inspectAccessInvitation",
    "getPolicyBundle",
}
_PAGED_OPERATIONS = {
    "listMyConsentGrants",
    "listMySessions",
    "listOrganizationAccessInvitations",
    "listOrganizationMemberships",
}
_BODY_SHAPES = {
    "beginOidcAuthorization": (
        {"return_to"},
        {"access_invitation_token", "reauthenticate"},
    ),
    "inspectAccessInvitation": ({"access_invitation_token"}, set()),
    "acceptAccessInvitation": (
        {"policy_bundle_id", "policy_acceptances", "consent_grants"},
        set(),
    ),
    "revokeAccessInvitation": ({"reason_code"}, {"reason_note"}),
    "acceptCurrentPolicies": (
        {"policy_requirement", "policy_bundle_id", "policy_acceptances"},
        set(),
    ),
    "grantConsent": (
        {
            "policy_requirement",
            "policy_bundle_id",
            "consent_offer_id",
            "document_id",
            "content_sha256",
            "affirmed",
        },
        set(),
    ),
    "withdrawConsent": ({"reason_code"}, {"reason_note"}),
    "issueOrganizationAccessInvitation": (
        {"recipient", "target_role", "expires_at"},
        set(),
    ),
    "updateOrganizationPublicName": ({"public_name", "reason_code"}, set()),
    "suspendMembership": ({"reason_code"}, {"reason_note"}),
    "resumeMembership": ({"reason_code"}, {"reason_note"}),
    "revokeMembership": ({"reason_code"}, {"reason_note"}),
    "suspendUser": ({"reason_code"}, {"reason_note"}),
    "resumeUser": ({"reason_code"}, {"reason_note"}),
    "revokeAllUserSessions": ({"reason_code"}, {"reason_note"}),
}
_READ_ETAG_OPERATIONS = {
    "inspectAccessInvitation",
    "getPolicyBundle",
    "getMe",
    "getOrganizationSummary",
}


@dataclass(frozen=True)
class IamHttpPresenterBindings:
    begin_oidc_authorization: Optional[Any] = field(default=None, repr=False)
    complete_oidc_authorization: Optional[Any] = field(default=None, repr=False)
    get_session_bootstrap: Optional[Any] = field(default=None, repr=False)
    inspect_access_invitation: Optional[Any] = field(default=None, repr=False)
    accept_access_invitation: Optional[Any] = field(default=None, repr=False)
    revoke_access_invitation: Optional[Any] = field(default=None, repr=False)
    get_policy_bundle: Optional[Any] = field(default=None, repr=False)
    get_me: Optional[Any] = field(default=None, repr=False)
    accept_current_policies: Optional[Any] = field(default=None, repr=False)
    list_my_consent_grants: Optional[Any] = field(default=None, repr=False)
    grant_consent: Optional[Any] = field(default=None, repr=False)
    withdraw_consent: Optional[Any] = field(default=None, repr=False)
    list_my_sessions: Optional[Any] = field(default=None, repr=False)
    revoke_my_session: Optional[Any] = field(default=None, repr=False)
    get_organization_summary: Optional[Any] = field(default=None, repr=False)
    update_organization_public_name: Optional[Any] = field(default=None, repr=False)
    list_organization_access_invitations: Optional[Any] = field(default=None, repr=False)
    issue_organization_access_invitation: Optional[Any] = field(default=None, repr=False)
    list_organization_memberships: Optional[Any] = field(default=None, repr=False)
    suspend_membership: Optional[Any] = field(default=None, repr=False)
    resume_membership: Optional[Any] = field(default=None, repr=False)
    revoke_membership: Optional[Any] = field(default=None, repr=False)
    suspend_user: Optional[Any] = field(default=None, repr=False)
    resume_user: Optional[Any] = field(default=None, repr=False)
    revoke_all_user_sessions: Optional[Any] = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if len(fields(self)) != 25:
            raise TypeError("IAM presenter registry must remain closed at 25 bindings")


class IamHttpApplicationDispatcher:
    """Translate normalized HTTP facts through one explicit use-case branch."""

    def __init__(self, *, bindings: Optional[IamHttpPresenterBindings] = None) -> None:
        if bindings is not None and not isinstance(bindings, IamHttpPresenterBindings):
            raise TypeError("bindings must be a closed IamHttpPresenterBindings")
        self._bindings = bindings or IamHttpPresenterBindings()

    @property
    def bindings(self) -> IamHttpPresenterBindings:
        return self._bindings

    def dispatch(self, invocation: IamHttpInvocation) -> IamHttpOperationResult:
        _validate_invocation(invocation)
        operation = invocation.operation_id
        if operation == "beginOidcAuthorization":
            return self._begin_oidc(invocation)
        if operation == "completeOidcAuthorization":
            return self._complete_oidc(invocation)
        if operation == "getSessionBootstrap":
            return self._read(
                invocation,
                self._bindings.get_session_bootstrap,
                GetSessionBootstrapQuery(
                    actor=_read_actor(invocation),
                    raw_session_handle=_required_text(invocation.raw_session_handle),
                ),
            )
        if operation == "inspectAccessInvitation":
            body = _body(invocation)
            return self._read(
                invocation,
                self._bindings.inspect_access_invitation,
                InspectAccessInvitationQuery(
                    access_invitation_token=_required_text(body.get("access_invitation_token")),
                    trace_id=invocation.trace_id,
                ),
            )
        if operation == "acceptAccessInvitation":
            return self._accept_invitation(invocation)
        if operation == "revokeAccessInvitation":
            body = _body(invocation)
            return self._lifecycle(
                invocation,
                self._bindings.revoke_access_invitation,
                RevokeAccessInvitationCommand(
                    invitation_id=_path_parameter(invocation, "invitation_id"),
                    expected_version=_expected_version(invocation),
                    idempotency_key=_idempotency_key(invocation),
                    reason=_reason(body),
                ),
            )
        if operation == "getPolicyBundle":
            return self._read(
                invocation,
                self._bindings.get_policy_bundle,
                GetPolicyBundleQuery(
                    policy_bundle_id=_path_parameter(invocation, "policy_bundle_id"),
                    trace_id=invocation.trace_id,
                ),
            )
        if operation == "getMe":
            return self._read(
                invocation,
                self._bindings.get_me,
                GetMeQuery(actor=_read_actor(invocation)),
            )
        if operation == "acceptCurrentPolicies":
            body = _body(invocation)
            return self._policy_consent(
                invocation,
                self._bindings.accept_current_policies,
                AcceptCurrentPoliciesCommand(
                    policy_requirement=_policy_requirement(body.get("policy_requirement")),
                    policy_bundle_id=_required_text(body.get("policy_bundle_id")),
                    policy_acceptances=_policy_acceptances(body.get("policy_acceptances")),
                    expected_user_version=_expected_version(invocation),
                    idempotency_key=_idempotency_key(invocation),
                ),
            )
        if operation == "listMyConsentGrants":
            return self._read(
                invocation,
                self._bindings.list_my_consent_grants,
                ListMyConsentGrantsQuery(actor=_read_actor(invocation), page=_page(invocation)),
            )
        if operation == "grantConsent":
            body = _body(invocation)
            return self._policy_consent(
                invocation,
                self._bindings.grant_consent,
                GrantConsentCommand(
                    policy_requirement=_policy_requirement(body.get("policy_requirement")),
                    policy_bundle_id=_required_text(body.get("policy_bundle_id")),
                    consent_choice=_consent_choice(body),
                    expected_user_version=_expected_version(invocation),
                    idempotency_key=_idempotency_key(invocation),
                ),
            )
        if operation == "withdrawConsent":
            body = _body(invocation)
            return self._lifecycle(
                invocation,
                self._bindings.withdraw_consent,
                WithdrawConsentGrantCommand(
                    consent_grant_id=_path_parameter(invocation, "consent_grant_id"),
                    expected_version=_expected_version(invocation),
                    idempotency_key=_idempotency_key(invocation),
                    reason=_reason(body),
                ),
            )
        if operation == "listMySessions":
            return self._read(
                invocation,
                self._bindings.list_my_sessions,
                ListMySessionsQuery(actor=_read_actor(invocation), page=_page(invocation)),
            )
        if operation == "revokeMySession":
            return self._lifecycle(
                invocation,
                self._bindings.revoke_my_session,
                RevokeSessionCommand(
                    session_id=_path_parameter(invocation, "session_id"),
                    idempotency_key=_idempotency_key(invocation),
                ),
            )
        if operation == "getOrganizationSummary":
            return self._read(
                invocation,
                self._bindings.get_organization_summary,
                GetOrganizationSummaryQuery(
                    actor=_read_actor(invocation),
                    organization_id=_path_parameter(invocation, "organization_id"),
                ),
            )
        if operation == "updateOrganizationPublicName":
            return self._update_organization_public_name(invocation)
        if operation == "listOrganizationAccessInvitations":
            return self._read(
                invocation,
                self._bindings.list_organization_access_invitations,
                ListOrganizationAccessInvitationsQuery(
                    actor=_read_actor(invocation),
                    organization_id=_path_parameter(invocation, "organization_id"),
                    page=_page(invocation),
                ),
            )
        if operation == "issueOrganizationAccessInvitation":
            return self._issue_invitation(invocation)
        if operation == "listOrganizationMemberships":
            return self._read(
                invocation,
                self._bindings.list_organization_memberships,
                ListOrganizationMembershipsQuery(
                    actor=_read_actor(invocation),
                    organization_id=_path_parameter(invocation, "organization_id"),
                    page=_page(invocation),
                ),
            )
        if operation == "suspendMembership":
            body = _body(invocation)
            return self._lifecycle(
                invocation,
                self._bindings.suspend_membership,
                SuspendMembershipCommand(
                    membership_id=_path_parameter(invocation, "membership_id"),
                    expected_version=_expected_version(invocation),
                    idempotency_key=_idempotency_key(invocation),
                    reason=_reason(body),
                ),
            )
        if operation == "resumeMembership":
            body = _body(invocation)
            return self._lifecycle(
                invocation,
                self._bindings.resume_membership,
                ResumeMembershipCommand(
                    membership_id=_path_parameter(invocation, "membership_id"),
                    expected_version=_expected_version(invocation),
                    idempotency_key=_idempotency_key(invocation),
                    reason=_reason(body),
                ),
            )
        if operation == "revokeMembership":
            body = _body(invocation)
            return self._lifecycle(
                invocation,
                self._bindings.revoke_membership,
                RevokeMembershipCommand(
                    membership_id=_path_parameter(invocation, "membership_id"),
                    expected_version=_expected_version(invocation),
                    idempotency_key=_idempotency_key(invocation),
                    reason=_reason(body),
                ),
            )
        if operation == "suspendUser":
            body = _body(invocation)
            return self._lifecycle(
                invocation,
                self._bindings.suspend_user,
                SuspendUserCommand(
                    user_id=_path_parameter(invocation, "user_id"),
                    expected_version=_expected_version(invocation),
                    idempotency_key=_idempotency_key(invocation),
                    reason=_reason(body),
                ),
            )
        if operation == "resumeUser":
            body = _body(invocation)
            return self._lifecycle(
                invocation,
                self._bindings.resume_user,
                ResumeUserCommand(
                    user_id=_path_parameter(invocation, "user_id"),
                    expected_version=_expected_version(invocation),
                    idempotency_key=_idempotency_key(invocation),
                    reason=_reason(body),
                ),
            )
        if operation == "revokeAllUserSessions":
            body = _body(invocation)
            return self._lifecycle(
                invocation,
                self._bindings.revoke_all_user_sessions,
                RevokeAllSessionsCommand(
                    user_id=_path_parameter(invocation, "user_id"),
                    expected_version=_expected_version(invocation),
                    idempotency_key=_idempotency_key(invocation),
                    reason=_reason(body),
                ),
            )
        raise IamError("SERVICE_UNAVAILABLE")

    def _begin_oidc(self, invocation: IamHttpInvocation) -> IamHttpOperationResult:
        body = _body(invocation)
        actor = invocation.actor
        if actor is not None:
            actor = _authenticated_actor(invocation)
        context = OidcBrowserContext(
            raw_session_handle=invocation.raw_session_handle,
            raw_oidc_browser_cookie=None,
            correlation_id=invocation.trace_id if actor is None else actor.correlation_id,
            causation_id=invocation.trace_id if actor is None else actor.causation_id,
            trace_id=invocation.trace_id,
        )
        command = BeginOidcAuthorizationCommand(
            return_to=_required_text(body.get("return_to")),
            access_invitation_token=_optional_text(body.get("access_invitation_token")),
            reauthenticate=body.get("reauthenticate", False),
        )
        result = _handler(self._bindings.begin_oidc_authorization).handle(
            context=context,
            command=command,
        )
        if not isinstance(result, BeginOidcAuthorizationResult):
            raise IamError("SERVICE_UNAVAILABLE")
        return IamHttpOperationResult(
            status_code=201,
            json_body=_freeze_object(
                {
                    "auth_transaction_id": _required_text(result.auth_transaction_id),
                    "authorization_url": _required_text(result.authorization_url),
                    "expires_at": _timestamp(result.expires_at),
                }
            ),
            cookie_mutations=(
                CookieMutation(
                    CookieMutationKind.SET_OIDC_BROWSER,
                    _required_text(result.oidc_browser_cookie),
                ),
            ),
        )

    def _complete_oidc(self, invocation: IamHttpInvocation) -> IamHttpOperationResult:
        if invocation.actor is not None:
            raise IamError("SERVICE_UNAVAILABLE")
        query = _query(invocation)
        command = CompleteOidcAuthenticationCommand(
            state=_required_text(query.get("state")),
            code=_optional_text(query.get("code")),
            provider_error=_optional_text(query.get("error")),
            provider_error_description=_optional_text(query.get("error_description")),
        )
        if (command.code is None) == (command.provider_error is None):
            raise IamError("SERVICE_UNAVAILABLE")
        result = _handler(self._bindings.complete_oidc_authorization).handle(
            context=OidcBrowserContext(
                raw_session_handle=invocation.raw_session_handle,
                raw_oidc_browser_cookie=_required_text(invocation.raw_oidc_browser_cookie),
                correlation_id=invocation.trace_id,
                causation_id=invocation.trace_id,
                trace_id=invocation.trace_id,
            ),
            command=command,
        )
        if (
            not isinstance(result, CompleteOidcAuthenticationResult)
            or result.clear_oidc_browser_cookie is not True
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        for value in (result.session_id, result.user_id, result.user_status, result.csrf_token):
            _required_text(value)
        return IamHttpOperationResult(
            status_code=303,
            json_body=None,
            redirect_location=_required_text(result.return_to),
            cookie_mutations=(
                CookieMutation(
                    CookieMutationKind.SET_SESSION,
                    _required_text(result.raw_session_handle),
                ),
                CookieMutation(CookieMutationKind.CLEAR_OIDC_BROWSER),
            ),
        )

    def _read(self, invocation: IamHttpInvocation, binding: Any, query: Any) -> IamHttpOperationResult:
        result = _handler(binding).handle(query)
        if (
            not isinstance(result, ReadModelResponse)
            or result.operation_id != invocation.operation_id
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        expected_cache = (
            ReadCachePolicy.PUBLIC_IMMUTABLE
            if invocation.operation_id == "getPolicyBundle"
            else ReadCachePolicy.NO_STORE
        )
        if result.cache_policy is not expected_cache:
            raise IamError("SERVICE_UNAVAILABLE")
        if invocation.operation_id in _READ_ETAG_OPERATIONS:
            entity_tag = _required_text(result.entity_tag)
        else:
            if result.entity_tag is not None:
                raise IamError("SERVICE_UNAVAILABLE")
            entity_tag = None
        return IamHttpOperationResult(
            status_code=200,
            json_body=_freeze_object(_safe_mapping(result.body_copy())),
            entity_tag=entity_tag,
        )

    def _accept_invitation(self, invocation: IamHttpInvocation) -> IamHttpOperationResult:
        body = _body(invocation)
        command = AcceptAccessInvitationCommand(
            invitation_id=_path_parameter(invocation, "invitation_id"),
            expected_version=_expected_version(invocation),
            idempotency_key=_idempotency_key(invocation),
            policy_bundle_id=_required_text(body.get("policy_bundle_id")),
            policy_acceptances=_policy_acceptances(body.get("policy_acceptances")),
            consent_grants=_consent_choices(body.get("consent_grants")),
        )
        result = _handler(self._bindings.accept_access_invitation).handle(
            actor=_accept_actor(invocation),
            command=command,
        )
        if not isinstance(result, AcceptAccessInvitationResult):
            raise IamError("SERVICE_UNAVAILABLE")
        if result.replayed:
            if result.session_rotation is not None:
                raise IamError("SERVICE_UNAVAILABLE")
            mutations: Tuple[CookieMutation, ...] = ()
        else:
            if not isinstance(result.session_rotation, SessionRotation):
                raise IamError("SERVICE_UNAVAILABLE")
            for value in (result.session_rotation.session_id, result.session_rotation.csrf_token):
                _required_text(value)
            mutations = (
                CookieMutation(
                    CookieMutationKind.SET_SESSION,
                    _required_text(result.session_rotation.raw_session_handle),
                ),
            )
        response = _safe_mapping(result.safe_response)
        return IamHttpOperationResult(
            status_code=200,
            json_body=_freeze_object(response),
            entity_tag=_nested_entity_tag(response, "invitation"),
            cookie_mutations=mutations,
            replayed=result.replayed,
        )

    def _policy_consent(self, invocation: IamHttpInvocation, binding: Any, command: Any) -> IamHttpOperationResult:
        result = _handler(binding).handle(actor=_policy_actor(invocation), command=command)
        expected_status = 200 if invocation.operation_id == "acceptCurrentPolicies" else 201
        if (
            not isinstance(result, PolicyConsentCommandResult)
            or result.operation_id != invocation.operation_id
            or result.http_status != expected_status
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        _required_text(result.current_user_entity_tag)
        return IamHttpOperationResult(
            status_code=expected_status,
            json_body=_freeze_object(_safe_mapping(result.json_body)),
            entity_tag=_required_text(result.response_entity_tag),
            replayed=result.replayed,
        )

    def _lifecycle(self, invocation: IamHttpInvocation, binding: Any, command: Any) -> IamHttpOperationResult:
        result = _handler(binding).handle(actor=_lifecycle_actor(invocation), command=command)
        expected_status = 204 if invocation.operation_id == "revokeMySession" else 200
        if not isinstance(result, LifecycleCommandResult) or result.http_status != expected_status:
            raise IamError("SERVICE_UNAVAILABLE")
        if expected_status == 204:
            if result.safe_response is not None:
                raise IamError("SERVICE_UNAVAILABLE")
            return IamHttpOperationResult(
                status_code=204,
                json_body=None,
                cookie_mutations=(
                    (CookieMutation(CookieMutationKind.CLEAR_SESSION),)
                    if result.clear_current_session_cookie
                    else ()
                ),
                replayed=result.replayed,
            )
        if result.clear_current_session_cookie:
            raise IamError("SERVICE_UNAVAILABLE")
        response = _safe_mapping(result.safe_response)
        return IamHttpOperationResult(
            status_code=200,
            json_body=_freeze_object(response),
            entity_tag=_entity_tag(response),
            replayed=result.replayed,
        )

    def _update_organization_public_name(
        self,
        invocation: IamHttpInvocation,
    ) -> IamHttpOperationResult:
        body = _body(invocation)
        actor = _authenticated_actor(invocation, require_auth_strength=True)
        try:
            reason_code = OrganizationPublicNameReasonCode(
                _required_text(body.get("reason_code"))
            )
            command = UpdateOrganizationPublicNameCommand(
                organization_id=_path_parameter(invocation, "organization_id"),
                expected_version=_expected_version(invocation),
                public_name=_required_text(body.get("public_name")),
                reason_code=reason_code,
                idempotency_key=_idempotency_key(invocation),
            )
            application_actor = OrganizationPublicNameActorContext(
                actor_user_id=actor.actor_user_id,
                current_session_id=actor.session_id,
                original_actor_id=actor.original_actor_id,
                correlation_id=actor.correlation_id,
                causation_id=actor.causation_id,
                trace_id=invocation.trace_id,
                auth_time=actor.auth_time,  # type: ignore[arg-type]
                acr_code=actor.acr_code,  # type: ignore[arg-type]
                amr_codes=actor.amr_codes,
            )
        except (IamError, TypeError, ValueError) as error:
            raise IamError("SERVICE_UNAVAILABLE") from error
        result = _handler(self._bindings.update_organization_public_name).handle(
            actor=application_actor,
            command=command,
        )
        if not isinstance(result, UpdateOrganizationPublicNameResult):
            raise IamError("SERVICE_UNAVAILABLE")
        organization = _safe_mapping(result.organization)
        return IamHttpOperationResult(
            status_code=200,
            json_body=_freeze_object(organization),
            entity_tag=_entity_tag(organization),
            replayed=result.replayed,
        )

    def _issue_invitation(self, invocation: IamHttpInvocation) -> IamHttpOperationResult:
        body = _body(invocation)
        recipient = _object(body.get("recipient"))
        actor = _authenticated_actor(invocation, require_auth_strength=True)
        try:
            recipient_type = RecipientContactType(_required_text(recipient.get("type")))
            target_role = TargetRole(_required_text(body.get("target_role")))
        except (TypeError, ValueError) as error:
            raise IamError("SERVICE_UNAVAILABLE") from error
        if target_role not in {TargetRole.ORG_ADMIN, TargetRole.DEMAND_OWNER}:
            raise IamError("SERVICE_UNAVAILABLE")
        command = IssueAccessInvitationCommand(
            organization_id=_path_parameter(invocation, "organization_id"),
            expected_organization_version=_expected_version(invocation),
            recipient=RecipientInput(
                type=recipient_type,
                value=_required_text(recipient.get("value")),
            ),
            target_role=target_role,
            expires_at=_parse_timestamp(body.get("expires_at")),
            idempotency_key=_idempotency_key(invocation),
        )
        result = _handler(self._bindings.issue_organization_access_invitation).handle(
            actor=InvitationIssuerContext(
                actor_kind=IssuerKind.USER,
                actor_id=actor.actor_user_id,
                session_id=actor.session_id,
                original_actor_id=actor.original_actor_id,
                correlation_id=actor.correlation_id,
                causation_id=actor.causation_id,
                trace_id=invocation.trace_id,
                auth_time=actor.auth_time,  # type: ignore[arg-type]
                acr_code=actor.acr_code,  # type: ignore[arg-type]
                amr_codes=actor.amr_codes,
            ),
            command=command,
        )
        if not isinstance(result, IssueAccessInvitationResult):
            raise IamError("SERVICE_UNAVAILABLE")
        invitation = _safe_mapping(result.invitation)
        return IamHttpOperationResult(
            status_code=201,
            json_body=_freeze_object(
                {
                    "invitation": invitation,
                    "access_invitation_token": _required_text(result.access_invitation_token),
                    "join_fragment_url": _required_text(result.join_fragment_url),
                }
            ),
            entity_tag=_entity_tag(invitation),
            replayed=result.replayed,
        )


def _handler(value: Any) -> Any:
    if value is None or not callable(getattr(value, "handle", None)):
        raise IamError("SERVICE_UNAVAILABLE")
    return value


def _validate_invocation(invocation: Any) -> None:
    if not isinstance(invocation, IamHttpInvocation):
        raise IamError("SERVICE_UNAVAILABLE")
    template = _OPERATION_PATHS.get(invocation.operation_id)
    if template is None or not isinstance(invocation.path_parameters, tuple):
        raise IamError("SERVICE_UNAVAILABLE")
    names = tuple(
        segment[1:-1]
        for segment in template.split("/")
        if segment.startswith("{") and segment.endswith("}")
    )
    if tuple(name for name, _ in invocation.path_parameters) != names:
        raise IamError("SERVICE_UNAVAILABLE")
    actual = template
    for name, value in invocation.path_parameters:
        actual = actual.replace("{" + _required_text(name) + "}", _required_text(value))
    if actual != invocation.canonical_path or not invocation.trace_id:
        raise IamError("SERVICE_UNAVAILABLE")

    operation = invocation.operation_id
    body = _object(invocation.json_body)
    required, optional = _BODY_SHAPES.get(operation, (set(), set()))
    if not required.issubset(body) or not set(body).issubset(required | optional):
        raise IamError("SERVICE_UNAVAILABLE")

    query = _query(invocation)
    if operation == "completeOidcAuthorization":
        if (
            "state" not in query
            or ("code" in query) == ("error" in query)
            or not set(query).issubset({"state", "code", "error", "error_description"})
        ):
            raise IamError("SERVICE_UNAVAILABLE")
    elif operation in _PAGED_OPERATIONS:
        if not set(query).issubset({"cursor", "limit"}):
            raise IamError("SERVICE_UNAVAILABLE")
    elif query:
        raise IamError("SERVICE_UNAVAILABLE")

    has_idempotency = invocation.idempotency_key is not None
    if has_idempotency != (operation in _IDEMPOTENT_OPERATIONS):
        raise IamError("SERVICE_UNAVAILABLE")
    has_expected_version = invocation.expected_version is not None
    if has_expected_version != (operation in _IF_MATCH_OPERATIONS):
        raise IamError("SERVICE_UNAVAILABLE")

    actor = invocation.actor
    if operation == "completeOidcAuthorization":
        if actor is not None:
            raise IamError("SERVICE_UNAVAILABLE")
        if invocation.raw_session_handle is not None:
            _required_text(invocation.raw_session_handle)
    elif operation in _ANONYMOUS_OPERATIONS:
        if actor is not None or invocation.raw_session_handle is not None:
            raise IamError("SERVICE_UNAVAILABLE")
    elif operation in _REQUIRED_ACTOR_OPERATIONS:
        _authenticated_actor(invocation)
        _required_text(invocation.raw_session_handle)
    else:
        if (actor is None) != (invocation.raw_session_handle is None):
            raise IamError("SERVICE_UNAVAILABLE")
        if actor is not None:
            _authenticated_actor(invocation)
    if operation == "completeOidcAuthorization":
        _required_text(invocation.raw_oidc_browser_cookie)
    elif invocation.raw_oidc_browser_cookie is not None:
        raise IamError("SERVICE_UNAVAILABLE")


def _path_parameter(invocation: IamHttpInvocation, name: str) -> str:
    values = [value for key, value in invocation.path_parameters if key == name]
    if len(values) != 1:
        raise IamError("SERVICE_UNAVAILABLE")
    return _required_text(values[0])


def _object(value: Any) -> dict[str, Any]:
    if not isinstance(value, tuple):
        raise IamError("SERVICE_UNAVAILABLE")
    result: dict[str, Any] = {}
    for item in value:
        if (
            not isinstance(item, tuple)
            or len(item) != 2
            or not isinstance(item[0], str)
            or item[0] in result
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        result[item[0]] = item[1]
    return result


def _body(invocation: IamHttpInvocation) -> dict[str, Any]:
    return _object(invocation.json_body)


def _query(invocation: IamHttpInvocation) -> dict[str, str]:
    if not isinstance(invocation.query_parameters, tuple):
        raise IamError("SERVICE_UNAVAILABLE")
    result: dict[str, str] = {}
    for key, value in invocation.query_parameters:
        if not isinstance(key, str) or not isinstance(value, str) or key in result:
            raise IamError("SERVICE_UNAVAILABLE")
        result[key] = value
    return result


def _page(invocation: IamHttpInvocation) -> PageRequest:
    query = _query(invocation)
    if not set(query).issubset({"cursor", "limit"}):
        raise IamError("SERVICE_UNAVAILABLE")
    raw_limit = query.get("limit")
    if raw_limit is None:
        limit = 25
    elif not raw_limit.isdigit() or not 1 <= int(raw_limit) <= 100:
        raise IamError("SERVICE_UNAVAILABLE")
    else:
        limit = int(raw_limit)
    return PageRequest(limit=limit, cursor=query.get("cursor"))


def _required_text(value: Any) -> str:
    if not isinstance(value, str) or not value or unicodedata.normalize("NFC", value) != value:
        raise IamError("SERVICE_UNAVAILABLE")
    return value


def _optional_text(value: Any) -> Optional[str]:
    return None if value is None else _required_text(value)


def _idempotency_key(invocation: IamHttpInvocation) -> str:
    return _required_text(invocation.idempotency_key)


def _expected_version(invocation: IamHttpInvocation) -> int:
    value = invocation.expected_version
    if type(value) is not int or value < 1:
        raise IamError("SERVICE_UNAVAILABLE")
    return value


def _policy_acceptance(value: Any) -> PolicyAcceptance:
    item = _object(value)
    if set(item) != {"document_id", "content_sha256", "affirmed"} or item["affirmed"] is not True:
        raise IamError("SERVICE_UNAVAILABLE")
    return PolicyAcceptance(
        document_id=_required_text(item["document_id"]),
        content_sha256=_required_text(item["content_sha256"]),
        affirmed=True,
    )


def _policy_acceptances(value: Any) -> Tuple[PolicyAcceptance, ...]:
    if not isinstance(value, tuple) or not value:
        raise IamError("SERVICE_UNAVAILABLE")
    return tuple(_policy_acceptance(item) for item in value)


def _consent_choice(value: Any) -> ConsentOfferChoice:
    item = _object(value) if isinstance(value, tuple) else value
    required = {"consent_offer_id", "document_id", "content_sha256", "affirmed"}
    if not isinstance(item, Mapping) or not required.issubset(item) or item["affirmed"] is not True:
        raise IamError("SERVICE_UNAVAILABLE")
    if isinstance(value, tuple) and set(item) != required:
        raise IamError("SERVICE_UNAVAILABLE")
    return ConsentOfferChoice(
        consent_offer_id=_required_text(item["consent_offer_id"]),
        document_id=_required_text(item["document_id"]),
        content_sha256=_required_text(item["content_sha256"]),
        affirmed=True,
    )


def _consent_choices(value: Any) -> Tuple[ConsentOfferChoice, ...]:
    if not isinstance(value, tuple):
        raise IamError("SERVICE_UNAVAILABLE")
    return tuple(_consent_choice(item) for item in value)


def _policy_requirement(value: Any) -> PolicyRequirementReference:
    item = _object(value)
    if set(item) != {"selector_digest", "scope_type", "scope_id"}:
        raise IamError("SERVICE_UNAVAILABLE")
    try:
        scope_type = PolicyRequirementScopeType(_required_text(item["scope_type"]))
        scope_id = None if item["scope_id"] is None else _required_text(item["scope_id"])
        return PolicyRequirementReference(
            selector_digest=_required_text(item["selector_digest"]),
            scope_type=scope_type,
            scope_id=scope_id,
        )
    except (IamError, TypeError, ValueError) as error:
        raise IamError("SERVICE_UNAVAILABLE") from error


def _reason(body: Mapping[str, Any]) -> LifecycleReason:
    if not set(body).issubset({"reason_code", "reason_note"}) or "reason_code" not in body:
        raise IamError("SERVICE_UNAVAILABLE")
    return LifecycleReason(
        reason_code=_required_text(body["reason_code"]),
        reason_note=_optional_text(body.get("reason_note")),
    )


def _authenticated_actor(
    invocation: IamHttpInvocation,
    *,
    require_auth_strength: bool = False,
) -> AuthenticatedHttpActor:
    actor = invocation.actor
    if not isinstance(actor, AuthenticatedHttpActor):
        raise IamError("SERVICE_UNAVAILABLE")
    for value in (
        actor.actor_user_id,
        actor.session_id,
        actor.correlation_id,
        actor.causation_id,
        actor.trace_id,
    ):
        _required_text(value)
    if actor.trace_id != invocation.trace_id:
        raise IamError("SERVICE_UNAVAILABLE")
    if actor.original_actor_id is not None:
        _required_text(actor.original_actor_id)
    if require_auth_strength:
        _require_utc(actor.auth_time)
        _required_text(actor.acr_code)
        if (
            not isinstance(actor.amr_codes, tuple)
            or not actor.amr_codes
            or len(set(actor.amr_codes)) != len(actor.amr_codes)
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        for code in actor.amr_codes:
            _required_text(code)
    return actor


def _read_actor(invocation: IamHttpInvocation) -> ReadActor:
    actor = _authenticated_actor(invocation)
    return ReadActor(actor.actor_user_id, actor.session_id, invocation.trace_id)


def _accept_actor(invocation: IamHttpInvocation) -> ActorContext:
    actor = _authenticated_actor(invocation)
    return ActorContext(
        actor_id=actor.actor_user_id,
        session_id=actor.session_id,
        original_actor_id=actor.original_actor_id,
        correlation_id=actor.correlation_id,
        causation_id=actor.causation_id,
        trace_id=invocation.trace_id,
    )


def _policy_actor(invocation: IamHttpInvocation) -> PolicyConsentActor:
    actor = _authenticated_actor(invocation)
    return PolicyConsentActor(
        actor_user_id=actor.actor_user_id,
        current_session_id=actor.session_id,
        original_actor_id=actor.original_actor_id,
        correlation_id=actor.correlation_id,
        causation_id=actor.causation_id,
        trace_id=invocation.trace_id,
    )


def _lifecycle_actor(invocation: IamHttpInvocation) -> LifecycleActorContext:
    actor = _authenticated_actor(invocation)
    return LifecycleActorContext(
        actor_user_id=actor.actor_user_id,
        current_session_id=actor.session_id,
        original_actor_id=actor.original_actor_id,
        correlation_id=actor.correlation_id,
        causation_id=actor.causation_id,
        trace_id=invocation.trace_id,
    )


def _require_utc(value: Any) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise IamError("SERVICE_UNAVAILABLE")
    return value


def _parse_timestamp(value: Any) -> datetime:
    text = _required_text(value)
    try:
        return _require_utc(datetime.fromisoformat(text.replace("Z", "+00:00")))
    except ValueError as error:
        raise IamError("SERVICE_UNAVAILABLE") from error


def _timestamp(value: Any) -> str:
    return _require_utc(value).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise IamError("SERVICE_UNAVAILABLE")
    return dict(value)


def _freeze_value(value: Any) -> FrozenJsonValue:
    if value is None or isinstance(value, (bool, str)):
        if isinstance(value, str) and unicodedata.normalize("NFC", value) != value:
            raise IamError("SERVICE_UNAVAILABLE")
        return value
    if type(value) is int:
        if not -(2**63) <= value <= 2**63 - 1:
            raise IamError("SERVICE_UNAVAILABLE")
        return value
    if isinstance(value, Enum):
        return _freeze_value(value.value)
    if isinstance(value, Mapping):
        return _freeze_object(value)
    if isinstance(value, (tuple, list)):
        return tuple(_freeze_value(item) for item in value)
    raise IamError("SERVICE_UNAVAILABLE")


def _freeze_object(value: Mapping[str, Any]) -> FrozenJsonObject:
    result = []
    for key, item in value.items():
        if not isinstance(key, str) or unicodedata.normalize("NFC", key) != key:
            raise IamError("SERVICE_UNAVAILABLE")
        result.append((key, _freeze_value(item)))
    return tuple(result)


def _entity_tag(body: Mapping[str, Any]) -> str:
    return _required_text(body.get("entity_tag"))


def _nested_entity_tag(body: Mapping[str, Any], name: str) -> str:
    nested = body.get(name)
    if not isinstance(nested, Mapping):
        raise IamError("SERVICE_UNAVAILABLE")
    return _entity_tag(nested)


__all__ = [
    "IamHttpApplicationDispatcher",
    "IamHttpPresenterBindings",
]
