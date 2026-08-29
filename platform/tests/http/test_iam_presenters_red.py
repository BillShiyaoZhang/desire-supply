"""TEST-HTTP-IAM-PRESENTER-001: explicit 25-operation application binding."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, fields, replace
from datetime import timezone
import unittest

from desire_platform.http import (
    CookieMutationKind,
    IamHttpApplicationDispatcher,
    IamHttpPresenterBindings,
    IamHttpTransport,
)
from desire_platform.identity_access.application.access_invitations import (
    AcceptAccessInvitationCommand,
    ActorContext,
)
from desire_platform.identity_access.application.authentication import (
    BeginOidcAuthorizationCommand,
    CompleteOidcAuthenticationCommand,
    OidcBrowserContext,
)
from desire_platform.identity_access.application.issue_access_invitations import (
    InvitationIssuerContext,
    IssueAccessInvitationCommand,
)
from desire_platform.identity_access.application.organization_profile import (
    OrganizationPublicNameActorContext,
    OrganizationPublicNameReasonCode,
    UpdateOrganizationPublicNameCommand,
)
from desire_platform.identity_access.application.policy_consent_commands import (
    AcceptCurrentPoliciesCommand,
    GrantConsentCommand,
    PolicyConsentActor,
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
)
from desire_platform.identity_access.domain.authority_lifecycle import (
    LifecycleActorContext,
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
from desire_platform.identity_access.domain.policies import (
    ConsentOfferChoice,
    PolicyAcceptance,
)
from tests.support.iam_http_transport_builders import (
    FakeCsrfVerifier,
    FakeOriginPolicy,
    FakeRateLimiter,
    FakeSessionAuthenticator,
    FixedTraceIdSource,
    OPENAPI_OPERATIONS,
    make_http_fixture,
    replace_json_body,
    request_for,
    response_json,
)
from tests.support.iam_presenter_builders import (
    ACTOR,
    BINDING_FIELDS,
    CONSENT_CHOICE,
    IDEMPOTENCY_KEY,
    NOW,
    POLICY_ACCEPTANCE,
    POLICY_REQUIREMENT,
    RAW_INVITATION_TOKEN,
    RAW_OIDC_COOKIE,
    RAW_SESSION_HANDLE,
    RAW_SUCCESSOR_HANDLE,
    body_for,
    invocation_for,
    make_presenter_fixture,
)


READ_QUERY_TYPES = {
    "getSessionBootstrap": GetSessionBootstrapQuery,
    "inspectAccessInvitation": InspectAccessInvitationQuery,
    "getPolicyBundle": GetPolicyBundleQuery,
    "getMe": GetMeQuery,
    "listMyConsentGrants": ListMyConsentGrantsQuery,
    "listMySessions": ListMySessionsQuery,
    "getOrganizationSummary": GetOrganizationSummaryQuery,
    "listOrganizationAccessInvitations": ListOrganizationAccessInvitationsQuery,
    "listOrganizationMemberships": ListOrganizationMembershipsQuery,
}
COMMAND_TYPES = {
    "beginOidcAuthorization": BeginOidcAuthorizationCommand,
    "completeOidcAuthorization": CompleteOidcAuthenticationCommand,
    "acceptAccessInvitation": AcceptAccessInvitationCommand,
    "revokeAccessInvitation": RevokeAccessInvitationCommand,
    "acceptCurrentPolicies": AcceptCurrentPoliciesCommand,
    "grantConsent": GrantConsentCommand,
    "withdrawConsent": WithdrawConsentGrantCommand,
    "revokeMySession": RevokeSessionCommand,
    "issueOrganizationAccessInvitation": IssueAccessInvitationCommand,
    "updateOrganizationPublicName": UpdateOrganizationPublicNameCommand,
    "suspendMembership": SuspendMembershipCommand,
    "resumeMembership": ResumeMembershipCommand,
    "revokeMembership": RevokeMembershipCommand,
    "suspendUser": SuspendUserCommand,
    "resumeUser": ResumeUserCommand,
    "revokeAllUserSessions": RevokeAllSessionsCommand,
}
EXPECTED_STATUS = {
    operation_id: (
        201
        if operation_id in {"beginOidcAuthorization", "grantConsent", "issueOrganizationAccessInvitation"}
        else 303
        if operation_id == "completeOidcAuthorization"
        else 204
        if operation_id == "revokeMySession"
        else 200
    )
    for operation_id in BINDING_FIELDS
}


class IamHttpPresenterRedTest(unittest.TestCase):
    def _dispatch(self, operation_id: str):
        fixture = make_presenter_fixture()
        dispatcher = IamHttpApplicationDispatcher(bindings=fixture.bindings)
        error = None
        result = None
        try:
            result = dispatcher.dispatch(invocation_for(operation_id))
        except IamError as caught:
            error = caught
        self.assertIsNone(error, getattr(error, "code", None))
        self.assertIsNotNone(result)
        return fixture, result

    def test_registry_is_frozen_closed_importable_and_missing_binding_denies(self) -> None:
        bindings = IamHttpPresenterBindings()
        self.assertEqual(len(fields(bindings)), 25)
        self.assertEqual(
            {field.name for field in fields(bindings)},
            set(BINDING_FIELDS.values()),
        )
        with self.assertRaises(FrozenInstanceError):
            bindings.get_me = object()  # type: ignore[misc]
        dispatcher = IamHttpApplicationDispatcher(bindings=bindings)
        with self.assertRaises(IamError) as caught:
            dispatcher.dispatch(invocation_for("getMe"))
        self.assertEqual(caught.exception.code, "SERVICE_UNAVAILABLE")
        self.assertNotEqual(caught.exception.code, "RESOURCE_NOT_FOUND")

    def test_all_25_operations_reach_one_exact_handler_and_status(self) -> None:
        self.assertEqual(len(BINDING_FIELDS), 25)
        for operation_id in BINDING_FIELDS:
            with self.subTest(operation_id=operation_id):
                fixture, result = self._dispatch(operation_id)
                self.assertEqual(result.status_code, EXPECTED_STATUS[operation_id])
                self.assertEqual(len(fixture.handlers[operation_id].calls), 1)
                self.assertTrue(
                    all(
                        not handler.calls
                        for candidate, handler in fixture.handlers.items()
                        if candidate != operation_id
                    )
                )

    def test_all_25_operations_cross_the_real_kernel_and_presenter_once(self) -> None:
        presenter = make_presenter_fixture()
        dispatcher = IamHttpApplicationDispatcher(bindings=presenter.bindings)
        transport = IamHttpTransport(
            dispatcher=dispatcher,
            session_authenticator=FakeSessionAuthenticator(),
            origin_policy=FakeOriginPolicy(),
            csrf_verifier=FakeCsrfVerifier(),
            rate_limiter=FakeRateLimiter(),
            trace_id_source=FixedTraceIdSource(),
        )
        for case in OPENAPI_OPERATIONS:
            with self.subTest(operation_id=case.operation_id):
                response = transport.handle(request_for(case.operation_id))
                self.assertEqual(response.status_code, case.success_status)
                self.assertEqual(len(presenter.handlers[case.operation_id].calls), 1)

    def test_each_branch_constructs_the_exact_public_command_or_query_type(self) -> None:
        for operation_id in BINDING_FIELDS:
            with self.subTest(operation_id=operation_id):
                fixture, _ = self._dispatch(operation_id)
                args, kwargs = fixture.handlers[operation_id].calls[0]
                if operation_id in READ_QUERY_TYPES:
                    self.assertEqual(len(args), 1)
                    self.assertEqual(kwargs, {})
                    self.assertIsInstance(args[0], READ_QUERY_TYPES[operation_id])
                else:
                    self.assertEqual(args, ())
                    self.assertIsInstance(kwargs.get("command"), COMMAND_TYPES[operation_id])
                    if operation_id in {
                        "beginOidcAuthorization",
                        "completeOidcAuthorization",
                    }:
                        self.assertIsInstance(kwargs.get("context"), OidcBrowserContext)
                    elif operation_id == "issueOrganizationAccessInvitation":
                        self.assertIsInstance(kwargs.get("actor"), InvitationIssuerContext)
                    elif operation_id == "updateOrganizationPublicName":
                        self.assertIsInstance(
                            kwargs.get("actor"), OrganizationPublicNameActorContext
                        )
                    elif operation_id in {
                        "acceptCurrentPolicies",
                        "grantConsent",
                    }:
                        self.assertIsInstance(kwargs.get("actor"), PolicyConsentActor)
                    elif operation_id == "acceptAccessInvitation":
                        self.assertIsInstance(kwargs.get("actor"), ActorContext)
                    else:
                        self.assertIsInstance(kwargs.get("actor"), LifecycleActorContext)

    def test_policy_consent_and_invitation_inputs_are_exactly_translated(self) -> None:
        fixture, _ = self._dispatch("acceptAccessInvitation")
        command = fixture.handlers["acceptAccessInvitation"].calls[0][1]["command"]
        self.assertEqual(command.invitation_id, "invitation_presenter_012345")
        self.assertEqual(command.expected_version, 7)
        self.assertEqual(command.idempotency_key, IDEMPOTENCY_KEY)
        self.assertEqual(command.policy_acceptances, (PolicyAcceptance(**POLICY_ACCEPTANCE),))
        self.assertEqual(command.consent_grants, (ConsentOfferChoice(**CONSENT_CHOICE),))

        fixture, _ = self._dispatch("acceptCurrentPolicies")
        accept = fixture.handlers["acceptCurrentPolicies"].calls[0][1]["command"]
        self.assertEqual(accept.policy_requirement.selector_digest, "a" * 64)
        self.assertEqual(accept.policy_requirement.scope_type.value, "ORGANIZATION_ROLE")
        self.assertEqual(accept.policy_requirement.scope_id, "organization_presenter_012345")
        self.assertEqual(accept.expected_user_version, 7)
        self.assertEqual(accept.policy_acceptances, (PolicyAcceptance(**POLICY_ACCEPTANCE),))

        fixture, _ = self._dispatch("grantConsent")
        grant = fixture.handlers["grantConsent"].calls[0][1]["command"]
        self.assertEqual(grant.policy_requirement.selector_digest, "a" * 64)
        self.assertEqual(grant.consent_choice, ConsentOfferChoice(**CONSENT_CHOICE))
        self.assertEqual(grant.policy_bundle_id, "policy_bundle_presenter_012345")

        fixture, _ = self._dispatch("issueOrganizationAccessInvitation")
        issue_call = fixture.handlers["issueOrganizationAccessInvitation"].calls[0][1]
        issue = issue_call["command"]
        issuer = issue_call["actor"]
        self.assertEqual(issue.organization_id, "organization_presenter_012345")
        self.assertEqual(issue.expected_organization_version, 7)
        self.assertEqual(issue.recipient.type.value, "EMAIL")
        self.assertEqual(issue.recipient.value, "invitee@example.test")
        self.assertEqual(issue.target_role.value, "DEMAND_OWNER")
        self.assertEqual(issue.expires_at, NOW.replace(day=12, hour=0, minute=0, second=0))
        self.assertEqual(issuer.actor_kind.value, "USER")
        self.assertEqual(issuer.auth_time, ACTOR.auth_time)
        self.assertEqual(issuer.acr_code, ACTOR.acr_code)
        self.assertEqual(issuer.amr_codes, ACTOR.amr_codes)

        fixture, result = self._dispatch("updateOrganizationPublicName")
        update_call = fixture.handlers["updateOrganizationPublicName"].calls[0][1]
        update = update_call["command"]
        profile_actor = update_call["actor"]
        self.assertEqual(update.organization_id, "organization_presenter_012345")
        self.assertEqual(update.expected_version, 7)
        self.assertEqual(update.public_name, "Corrected Organization")
        self.assertIs(
            update.reason_code,
            OrganizationPublicNameReasonCode.PUBLIC_NAME_CORRECTION,
        )
        self.assertEqual(update.idempotency_key, IDEMPOTENCY_KEY)
        self.assertEqual(profile_actor.actor_user_id, ACTOR.actor_user_id)
        self.assertEqual(profile_actor.current_session_id, ACTOR.session_id)
        self.assertEqual(profile_actor.auth_time, ACTOR.auth_time)
        self.assertEqual(profile_actor.acr_code, ACTOR.acr_code)
        self.assertEqual(profile_actor.amr_codes, ACTOR.amr_codes)
        self.assertEqual(result.entity_tag, '"v8"')
        self.assertEqual(dict(result.json_body)["public_name"], "Corrected Organization")

    def test_actor_raw_carriers_pagination_and_reason_are_bound_without_guessing(self) -> None:
        fixture, _ = self._dispatch("getSessionBootstrap")
        query = fixture.handlers["getSessionBootstrap"].calls[0][0][0]
        self.assertEqual(query.raw_session_handle, RAW_SESSION_HANDLE)
        self.assertEqual(query.actor.actor_user_id, ACTOR.actor_user_id)

        fixture, _ = self._dispatch("listOrganizationMemberships")
        query = fixture.handlers["listOrganizationMemberships"].calls[0][0][0]
        self.assertEqual(query.organization_id, "organization_presenter_012345")
        self.assertEqual(query.page.cursor, "cursor_presenter_0123456789")
        self.assertEqual(query.page.limit, 37)

        fixture, _ = self._dispatch("revokeAccessInvitation")
        call = fixture.handlers["revokeAccessInvitation"].calls[0][1]
        self.assertEqual(call["command"].reason.reason_code, "ADMIN_REVOKED")
        self.assertEqual(call["command"].reason.reason_note, "Closed administrative reason.")
        self.assertEqual(call["actor"].original_actor_id, ACTOR.original_actor_id)

        fixture, _ = self._dispatch("completeOidcAuthorization")
        call = fixture.handlers["completeOidcAuthorization"].calls[0][1]
        self.assertEqual(call["context"].raw_oidc_browser_cookie, RAW_OIDC_COOKIE)
        self.assertEqual(call["command"].state, "S" * 43)
        self.assertEqual(call["command"].code, "C" * 43)

        fixture = make_presenter_fixture()
        dispatcher = IamHttpApplicationDispatcher(bindings=fixture.bindings)
        dispatcher.dispatch(
            replace(
                invocation_for("completeOidcAuthorization"),
                raw_session_handle=RAW_SESSION_HANDLE,
            )
        )
        step_up_call = fixture.handlers["completeOidcAuthorization"].calls[0][1]
        self.assertEqual(
            step_up_call["context"].raw_session_handle,
            RAW_SESSION_HANDLE,
        )

    def test_safe_results_etags_redirects_and_cookie_actions_are_closed(self) -> None:
        fixture, begin = self._dispatch("beginOidcAuthorization")
        self.assertEqual(
            begin.cookie_mutations[0].kind,
            CookieMutationKind.SET_OIDC_BROWSER,
        )
        self.assertNotIn(RAW_OIDC_COOKIE, repr(begin))
        begin_body = dict(begin.json_body)
        self.assertEqual(begin_body["authorization_url"], fixture.handlers["beginOidcAuthorization"].result.authorization_url)

        _, complete = self._dispatch("completeOidcAuthorization")
        self.assertEqual(complete.redirect_location, "/app")
        self.assertEqual(
            tuple(item.kind for item in complete.cookie_mutations),
            (CookieMutationKind.SET_SESSION, CookieMutationKind.CLEAR_OIDC_BROWSER),
        )

        _, accept = self._dispatch("acceptAccessInvitation")
        self.assertEqual(accept.entity_tag, '"v8"')
        self.assertEqual(accept.cookie_mutations[0].kind, CookieMutationKind.SET_SESSION)
        self.assertEqual(accept.cookie_mutations[0].raw_value, RAW_SUCCESSOR_HANDLE)

        _, revoke = self._dispatch("revokeMySession")
        self.assertIsNone(revoke.json_body)
        self.assertEqual(
            tuple(item.kind for item in revoke.cookie_mutations),
            (CookieMutationKind.CLEAR_SESSION,),
        )

        other_fixture = make_presenter_fixture()
        other_handler = other_fixture.handlers["revokeMySession"]
        other_handler.result = replace(
            other_handler.result,
            clear_current_session_cookie=False,
        )
        other = IamHttpApplicationDispatcher(
            bindings=other_fixture.bindings
        ).dispatch(invocation_for("revokeMySession"))
        self.assertEqual(other.cookie_mutations, ())

    def test_openapi_policy_requirement_and_current_session_cookie_contract_reach_kernel(self) -> None:
        full_accept = body_for("acceptCurrentPolicies")
        full_grant = body_for("grantConsent")
        for operation_id, full_body in (
            ("acceptCurrentPolicies", full_accept),
            ("grantConsent", full_grant),
        ):
            with self.subTest(operation_id=operation_id, case="full"):
                fixture = make_http_fixture()
                response = fixture.transport.handle(
                    replace_json_body(request_for(operation_id), full_body)
                )
                self.assertEqual(response.status_code, EXPECTED_STATUS[operation_id])
                self.assertEqual(len(fixture.dispatcher.calls), 1)
            with self.subTest(operation_id=operation_id, case="missing-requirement"):
                incomplete = dict(full_body)
                incomplete.pop("policy_requirement")
                fixture = make_http_fixture()
                response = fixture.transport.handle(
                    replace_json_body(request_for(operation_id), incomplete)
                )
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response_json(response)["code"], "INVALID_REQUEST")
                self.assertEqual(fixture.dispatcher.calls, [])

        import yaml
        from pathlib import Path

        document = yaml.safe_load(
            (Path(__file__).resolve().parents[2] / "contracts/api/iam-v1.openapi.yaml").read_text(
                encoding="utf-8"
            )
        )
        response = document["paths"]["/v1/me/sessions/{session_id}"]["delete"]["responses"]["204"]
        self.assertIn("Set-Cookie", response.get("headers", {}))

    def test_corrupt_or_mismatched_internal_facts_fail_closed_without_fallback(self) -> None:
        fixture = make_presenter_fixture()
        dispatcher = IamHttpApplicationDispatcher(bindings=fixture.bindings)
        corrupt_cases = (
            replace(invocation_for("getMe"), canonical_path="/v1/me/other"),
            replace(
                invocation_for("issueOrganizationAccessInvitation"),
                actor=None,
                raw_session_handle=None,
            ),
        )
        for invocation in corrupt_cases:
            with self.subTest(operation_id=invocation.operation_id):
                with self.assertRaises(IamError) as caught:
                    dispatcher.dispatch(invocation)
                self.assertEqual(caught.exception.code, "SERVICE_UNAVAILABLE")
        self.assertEqual(sum(len(handler.calls) for handler in fixture.handlers.values()), 0)

        fixture = make_presenter_fixture()
        fixture.handlers["acceptAccessInvitation"].result = replace(
            fixture.handlers["acceptAccessInvitation"].result,
            replayed=True,
        )
        dispatcher = IamHttpApplicationDispatcher(bindings=fixture.bindings)
        with self.assertRaises(IamError) as caught:
            dispatcher.dispatch(invocation_for("acceptAccessInvitation"))
        self.assertEqual(caught.exception.code, "SERVICE_UNAVAILABLE")

    def test_normalized_actor_body_query_and_read_metadata_are_closed_again(self) -> None:
        actor_cases = (
            ("duplicate-amr", {"amr_codes": ("pwd", "pwd")}),
            ("missing-auth-time", {"auth_time": None}),
            ("naive-auth-time", {"auth_time": NOW.replace(tzinfo=None)}),
        )
        for label, changes in actor_cases:
            with self.subTest(case=label):
                with self.assertRaises((TypeError, ValueError)):
                    replace(ACTOR, **changes)

        fixture = make_presenter_fixture()
        dispatcher = IamHttpApplicationDispatcher(bindings=fixture.bindings)
        corrupt_invocations = (
            replace(invocation_for("getPolicyBundle"), actor=ACTOR, raw_session_handle=RAW_SESSION_HANDLE),
            replace(invocation_for("getMe"), json_body=(("unexpected", True),)),
            replace(invocation_for("getMe"), query_parameters=(("cursor", "forged_cursor_012345"),)),
            replace(invocation_for("getMe"), idempotency_key=IDEMPOTENCY_KEY),
        )
        for invocation in corrupt_invocations:
            with self.subTest(case=invocation.operation_id, fact=repr(invocation)):
                with self.assertRaises(IamError) as caught:
                    dispatcher.dispatch(invocation)
                self.assertEqual(caught.exception.code, "SERVICE_UNAVAILABLE")

        fixture = make_presenter_fixture()
        fixture.handlers["listMySessions"].result = replace(
            fixture.handlers["listMySessions"].result,
            entity_tag='"v7"',
        )
        with self.assertRaises(IamError) as caught:
            IamHttpApplicationDispatcher(bindings=fixture.bindings).dispatch(
                invocation_for("listMySessions")
            )
        self.assertEqual(caught.exception.code, "SERVICE_UNAVAILABLE")

        fixture = make_presenter_fixture()
        fixture.handlers["getMe"].result = replace(
            fixture.handlers["getMe"].result,
            entity_tag=None,
        )
        with self.assertRaises(IamError) as caught:
            IamHttpApplicationDispatcher(bindings=fixture.bindings).dispatch(
                invocation_for("getMe")
            )
        self.assertEqual(caught.exception.code, "SERVICE_UNAVAILABLE")

    def test_rich_actor_is_utc_frozen_and_secrets_are_repr_hidden(self) -> None:
        self.assertEqual(ACTOR.auth_time.utcoffset(), timezone.utc.utcoffset(ACTOR.auth_time))
        self.assertEqual(ACTOR.amr_codes, ("pwd", "otp"))
        with self.assertRaises(FrozenInstanceError):
            ACTOR.acr_code = "changed"  # type: ignore[misc]
        invocation = invocation_for("issueOrganizationAccessInvitation")
        rendered = repr(invocation)
        for secret in (
            RAW_SESSION_HANDLE,
            RAW_OIDC_COOKIE,
            RAW_INVITATION_TOKEN,
            IDEMPOTENCY_KEY,
            "invitee@example.test",
        ):
            self.assertNotIn(secret, rendered)


if __name__ == "__main__":
    unittest.main()
