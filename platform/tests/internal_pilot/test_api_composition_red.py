from __future__ import annotations

from dataclasses import fields, replace
from datetime import datetime, timedelta, timezone
import io
import unittest

from desire_platform.http import (
    ExactOriginPolicy,
    ExactOriginPolicySettings,
    IamHttpPresenterBindings,
    PsycopgIamSessionSecurity,
)
from desire_platform.http.observability import ObservedAsgiApplication
from desire_platform.identity_access.adapters.oidc import ClosedOidcProvider
from desire_platform.identity_access.adapters.postgres.editor_principal import (
    PsycopgEditorPrincipalResolver,
)
from desire_platform.identity_access.adapters.postgres.authority_markers import (
    PsycopgAuthorityMarkerResolver,
)
from desire_platform.identity_access.adapters.postgres.oidc_authentication import (
    PsycopgOidcAuthenticationUnitOfWork,
)
from desire_platform.identity_access.adapters.postgres.oidc_bundle import (
    PostgresBeginOidcAuthorizationHandler,
    PostgresCompleteOidcAuthenticationHandler,
)
from desire_platform.identity_access.adapters.postgres.read_models import (
    PsycopgIamReadModelRepository,
)
from desire_platform.identity_access.adapters.postgres.platform_user_lifecycle import (
    PsycopgPlatformUserLifecycleUnitOfWorkFactory,
)
from desire_platform.identity_access.adapters.postgres.organization_admin import (
    PsycopgOrganizationAdminTargetResolver,
    PsycopgOrganizationAdminUnitOfWorkFactory,
)
from desire_platform.identity_access.adapters.postgres.accept_access_invitation import (
    PsycopgAcceptAccessInvitationUnitOfWorkFactory,
)
from desire_platform.identity_access.adapters.postgres.organization_admin_accept import (
    InternalSandboxInvitationSafetyHold,
    OrganizationAcceptKeyring,
    PostgresAcceptOrganizationAccessInvitationHandler,
    PsycopgOrganizationAcceptScopeResolver,
)
from desire_platform.identity_access.adapters.postgres.organization_admin_handlers import (
    HmacOrganizationInvitationTokenCodec,
    InternalSandboxMembershipResumeSafetyHold,
    InternalSandboxOrganizationInvitationIssueSafetyHold,
    OrganizationAdminKeys,
    PostgresIssueOrganizationAccessInvitationHandler,
    PostgresResumeMembershipHandler,
    PostgresRevokeAccessInvitationHandler,
    PostgresRevokeMembershipHandler,
    PostgresSuspendMembershipHandler,
)
from desire_platform.identity_access.adapters.postgres.organization_public_name import (
    PostgresUpdateOrganizationPublicNameHandler,
    PsycopgOrganizationPublicNameUnitOfWorkFactory,
)
from desire_platform.identity_access.adapters.postgres.policy_consent_commands import (
    PsycopgPolicyConsentCommandUnitOfWorkFactory,
)
from desire_platform.identity_access.adapters.postgres.current_session_logout import (
    PsycopgOwnedSessionRevocationUnitOfWorkFactory,
)
from desire_platform.identity_access.application.authentication import (
    OidcSecurityPolicy,
)
from desire_platform.identity_access.application.read_models import (
    GetMeHandler,
    GetOrganizationSummaryHandler,
    GetPolicyBundleHandler,
    GetSessionBootstrapHandler,
    InspectAccessInvitationHandler,
    ListMySessionsHandler,
    ListOrganizationAccessInvitationsHandler,
    ListOrganizationMembershipsHandler,
)
from desire_platform.matching.adapters.postgres import (
    PsycopgMatchingAssignmentRuntime,
    PsycopgMatchingReviewRuntime,
    PsycopgMatchingRuntime,
)
from desire_platform.creator_profile.adapters.postgres import (
    PsycopgCreatorProfileUnitOfWorkFactory,
)
from desire_platform.demand.adapters.postgres import (
    DemandPostgresOperation,
    PsycopgDemandUnitOfWorkFactory,
)
from desire_platform.internal_pilot.api_composition import (
    InternalSandboxApiDependencies,
    InternalSandboxApiPools,
    LocalServerDependencyReadiness,
    OidcProviderReadiness,
    build_internal_sandbox_api,
)
from desire_platform.internal_pilot.account_admin import (
    PlatformUserAdminKeys,
    PostgresInternalSandboxAccountAdminService,
    PsycopgInternalSandboxAccountAdminRepository,
)
from desire_platform.internal_pilot.appeal_runtime import (
    InternalSandboxAppealPostgresRuntime,
    PsycopgAppealRuntimeReadiness,
)
from desire_platform.internal_pilot.editor import (
    EditorPostgresKeys,
    PostgresEditorAuthorityProvider,
    PostgresEditorService,
    PsycopgDemandCompletedVerifyReceiptProbe,
    PsycopgDemandReviewQueue,
    PsycopgEditorRepository,
    PsycopgProfileCompletedLifecycleReceiptProbe,
)
from desire_platform.internal_pilot.editor.sandbox_evidence import (
    InternalSandboxEditorEvidenceProvider,
)
from desire_platform.internal_pilot.finance_funding import (
    FinanceFundingKeys,
    PsycopgFinanceFundingService,
)
from desire_platform.internal_pilot.postgres_pool import (
    PostgresEndpointSettings,
    RoleBoundPsycopgPool,
)
from desire_platform.internal_pilot.policy_acceptance import (
    IamReceiptPolicyKeys,
    PostgresAcceptCurrentPoliciesHandler,
    PsycopgPolicyAcceptanceScopeResolver,
)
from desire_platform.internal_pilot.current_session_logout import (
    PostgresRevokeOwnedSessionHandler,
)
from desire_platform.internal_pilot.matching_postgres import (
    MatchingPostgresHttpKeys,
    MatchingPostgresOperationalHttpService,
    build_matching_postgres_http_bindings,
)
from desire_platform.internal_pilot.contract_validation import (
    DemandPostgresContractValidator,
    IamPostgresContractValidator,
    ProfilePostgresContractValidator,
)
from desire_platform.internal_pilot.runtime import (
    InternalBffTransportApplication,
    InternalSandboxApiMux,
    InternalSandboxRuntime,
)
from desire_platform.internal_pilot.runtime_adapters import (
    InternalSandboxRateLimitSettings,
    InternalSandboxRateLimiter,
    JsonLineHttpTelemetry,
    SecureRuntimeSources,
)
from desire_platform.internal_pilot.runtime_crypto import (
    HmacIamReadCursorCodec,
    RuntimeKeyMaterial,
)
from desire_platform.internal_pilot.schema_readiness import (
    PostgresSchemaCompatibilityReadiness,
    SchemaCompatibilityRequirement,
)
from desire_platform.internal_pilot.seed_readiness import (
    PostgresInternalSandboxSeedReadiness,
)
from desire_platform.internal_pilot.secrets import (
    FileSecretCarrier,
    ManagedRuntimeSecrets,
)
from desire_platform.runtime.config import DatabaseProfile
from desire_platform.trust_safety.adapters.postgres import (
    AppealPostgresReceiptKey,
    AppealPostgresReceiptKeyring,
    AppealSealedTextKey,
    AppealSealedTextKeyring,
    PsycopgAppealCommandGateway,
    PsycopgAppealHttpProjectionAdapter,
    PsycopgAppealReadGateway,
    PsycopgAppealReceiptProbe,
    PsycopgAppealRestrictedTextStore,
    PsycopgAppealSealedTextProvider,
    PsycopgTrustDemandSafetyHoldProvider,
    build_appeal_postgres_command_handlers,
)
from desire_platform.trust_safety.appeal_http import AppealHttpPresenterBindings


ISSUER = "https://identity.example.test/tenant"
AUDIENCE = "desire-internal-sandbox"
REDIRECT = "https://pilot.example.test/v1/auth/oidc/callback"


class _Credential:
    material = bytearray(b"closed-database-password-001")


class _NoConnectDbapi:
    @staticmethod
    def connect(**_facts):
        raise AssertionError("composition construction must not connect")


class _SessionKeyring:
    session_handle_digest_key_id = "session-key-01"
    retained_session_handle_digest_key_ids = ("session-key-01",)
    csrf_key_id = "csrf-key-01"
    retained_csrf_key_ids = ("csrf-key-01",)

    @staticmethod
    def keyed_digest_hex(*, key_id, canonical_bytes):
        del key_id, canonical_bytes
        return "11" * 32


class _RecipientBinding:
    @staticmethod
    def bind_verified(**_facts):
        raise AssertionError("composition construction must not bind a recipient")


class _ManagedEvidence:
    def __init__(self) -> None:
        self.closed = False

    editor_configuration = profile_hold = demand_content_policy = demand_hold = demand_rules = (
        lambda self, **_facts: None
    )

    def check_readiness(self, *, timeout_ms):
        if self.closed or timeout_ms < 1:
            raise RuntimeError("not ready")
        return None

    def close(self):
        self.closed = True


class _ManagedDemandRuleCatalog:
    def __init__(self) -> None:
        self.closed = False

    @staticmethod
    def current_requirement(**_facts):
        raise AssertionError("composition must not evaluate Demand rules")

    def check_readiness(self, *, timeout_ms):
        if self.closed or timeout_ms < 1:
            raise RuntimeError("not ready")
        return None

    def close(self):
        self.closed = True


class _FakeOidcTransport:
    def __init__(self) -> None:
        self.responses = []
        self.calls = []

    def get_json(self, *, url, timeout_seconds, maximum_bytes):
        self.calls.append((url, timeout_seconds, maximum_bytes))
        value = self.responses.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value

    def post_form_json(self, **_facts):
        raise AssertionError("readiness cannot exchange a code")


class _Verifier:
    @staticmethod
    def verify_id_token(**_facts):
        return {}


class _RecipientBinding:
    @staticmethod
    def bind_verified(**_facts):
        raise AssertionError("readiness cannot bind a recipient")


def _policy() -> OidcSecurityPolicy:
    return OidcSecurityPolicy(
        policy_version="internal-sandbox-oidc-v1",
        provider_issuer=ISSUER,
        provider_audience=AUDIENCE,
        redirect_uri=REDIRECT,
        allowed_return_to=("/app",),
    )


def _provider(transport: _FakeOidcTransport | None = None) -> ClosedOidcProvider:
    from desire_platform.identity_access.adapters.oidc import OidcProviderConfiguration

    return ClosedOidcProvider(
        configuration=OidcProviderConfiguration(
            issuer=ISSUER,
            client_id=AUDIENCE,
            client_secret="closed-provider-secret",
            redirect_uri=REDIRECT,
            allowed_signing_algorithms=("RS256",),
            metadata_ttl_seconds=300,
            request_timeout_seconds=3,
            maximum_response_bytes=262_144,
            clock_skew_seconds=30,
            subject_digest_key_id="subject-key-01",
        ),
        transport=transport or _FakeOidcTransport(),
        token_verifier=_Verifier(),
        recipient_binding=_RecipientBinding(),
        subject_digest_key=b"subject-digest-key-material-0001",
    )


def _pool(role: str, index: int) -> RoleBoundPsycopgPool:
    profile = DatabaseProfile(
        capability_id=f"CAPABILITY_{index}",
        online_role=role,
        credential_ref=f"secret://sandbox/{role}#v1",
        application_name=f"desire-{role.replace('_', '-')}",
        max_pool_size=2,
        checkout_timeout_ms=100,
        statement_timeout_ms=1_000,
        lock_timeout_ms=100,
        idle_in_transaction_timeout_ms=1_000,
    )
    return RoleBoundPsycopgPool(
        endpoint=PostgresEndpointSettings(
            host="db",
            port=5432,
            database="desire",
            transport_security="TRUSTED_CONTAINER_NETWORK",
        ),
        profile=profile,
        credential=_Credential(),
        dbapi=_NoConnectDbapi(),
    )


def _pools() -> InternalSandboxApiPools:
    values = {
        field.name: _pool(field.name, index)
        for index, field in enumerate(fields(InternalSandboxApiPools), start=1)
    }
    return InternalSandboxApiPools(**values)


def _schema_readiness(pools: InternalSandboxApiPools):
    return (
        PostgresSchemaCompatibilityReadiness(
            pool=pools.iam_app,
            requirement=SchemaCompatibilityRequirement(
                component="iam",
                expected_schema_head=20,
                expected_contract_sha256=b"i" * 32,
                required_iam_schema_version=None,
            ),
        ),
        PostgresSchemaCompatibilityReadiness(
            pool=pools.profile_app,
            requirement=SchemaCompatibilityRequirement(
                component="profile",
                expected_schema_head=2,
                expected_contract_sha256=b"p" * 32,
                required_iam_schema_version=None,
            ),
        ),
        PostgresSchemaCompatibilityReadiness(
            pool=pools.demand_self,
            requirement=SchemaCompatibilityRequirement(
                component="demand",
                expected_schema_head=2,
                expected_contract_sha256=b"d" * 32,
                required_iam_schema_version=20,
                expected_idempotency_key_id="demand-idempotency-2026-01",
                expected_payload_key_id="demand-payload-2026-01",
                expected_retained_idempotency_key_ids=(
                    "demand-idempotency-2026-01",
                ),
                expected_retained_payload_key_ids=(
                    "demand-payload-2026-01",
                ),
            ),
        ),
        PostgresSchemaCompatibilityReadiness(
            pool=pools.trust_self,
            requirement=SchemaCompatibilityRequirement(
                component="trust",
                expected_schema_head=1,
                expected_contract_sha256=b"t" * 32,
                required_iam_schema_version=36,
                required_demand_schema_version=8,
                expected_iam_contract_sha256=b"i" * 32,
                expected_demand_contract_sha256=b"d" * 32,
                expected_combined_contract_sha256=b"c" * 32,
            ),
        ),
        PostgresSchemaCompatibilityReadiness(
            pool=pools.matching_creator,
            requirement=SchemaCompatibilityRequirement(
                component="matching",
                expected_schema_head=2,
                expected_contract_sha256=b"m" * 32,
                required_iam_schema_version=43,
            ),
        ),
    )


def _dependencies() -> InternalSandboxApiDependencies:
    pools = _pools()
    provider = _provider()
    policy = _policy()
    oidc_uow = PsycopgOidcAuthenticationUnitOfWork(
        connections=pools.iam_onboarding
    )
    begin = object.__new__(PostgresBeginOidcAuthorizationHandler)
    begin._uow = oidc_uow
    begin._provider = provider
    begin._security_policy = policy
    complete = object.__new__(PostgresCompleteOidcAuthenticationHandler)
    complete._uow = oidc_uow
    complete._provider = provider
    complete._security_policy = policy

    reads = PsycopgIamReadModelRepository(
        app_connections=pools.iam_app,
        onboarding_connections=pools.iam_onboarding,
    )
    sources = SecureRuntimeSources()
    iam_validator = IamPostgresContractValidator()
    account_admin_keys = PlatformUserAdminKeys(
        idempotency_key=b"7" * 32,
        payload_hash_key=b"8" * 32,
    )
    session_handler = object.__new__(GetSessionBootstrapHandler)
    session_handler._repository = reads
    policy_bundle_handler = object.__new__(GetPolicyBundleHandler)
    policy_bundle_handler._repository = reads
    me_handler = object.__new__(GetMeHandler)
    me_handler._repository = reads
    cursor_codec = HmacIamReadCursorCodec(
        keys=(
            RuntimeKeyMaterial(
                purpose="IAM_READ_CURSOR",
                key_id="iam-read-cursor-test-v1",
                material=bytearray(b"c" * 32),
            ),
        ),
        active_key_id="iam-read-cursor-test-v1",
    )
    session_list_handler = object.__new__(ListMySessionsHandler)
    session_list_handler._repository = reads
    session_list_handler._cursor_codec = cursor_codec
    organization_handler = object.__new__(GetOrganizationSummaryHandler)
    organization_handler._repository = reads
    invitation_list_handler = object.__new__(
        ListOrganizationAccessInvitationsHandler
    )
    invitation_list_handler._repository = reads
    invitation_list_handler._cursor_codec = cursor_codec
    membership_list_handler = object.__new__(ListOrganizationMembershipsHandler)
    membership_list_handler._repository = reads
    membership_list_handler._cursor_codec = cursor_codec
    policy_uow = PsycopgPolicyConsentCommandUnitOfWorkFactory(
        connections=pools.iam_app,
        event_validator=iam_validator,
        response_validator=iam_validator,
    )
    receipt_keys = IamReceiptPolicyKeys.from_platform_user_admin_keys(
        account_admin_keys
    )
    policy_handler = PostgresAcceptCurrentPoliciesHandler(
        scope_resolver=PsycopgPolicyAcceptanceScopeResolver(
            connections=pools.iam_app
        ),
        uow_factory=policy_uow,
        keys=receipt_keys,
        clock=sources,
        id_source=sources,
    )
    logout_handler = PostgresRevokeOwnedSessionHandler(
        uow_factory=PsycopgOwnedSessionRevocationUnitOfWorkFactory(
            connections=pools.iam_app
        ),
        keys=receipt_keys,
        clock=sources,
        id_source=sources,
    )
    organization_keys = OrganizationAdminKeys(
        idempotency_key=bytes(account_admin_keys.idempotency_key),
        payload_hash_key=bytes(account_admin_keys.payload_hash_key),
        invitation_token_keys=(("invitation-token-test-v1", b"9" * 32),),
        active_invitation_token_key_id="invitation-token-test-v1",
    )
    organization_uow = PsycopgOrganizationAdminUnitOfWorkFactory(
        connections=pools.iam_app,
        event_validator=iam_validator,
        response_validator=iam_validator,
    )
    organization_public_name_uow = PsycopgOrganizationPublicNameUnitOfWorkFactory(
        connections=pools.iam_app,
        event_validator=iam_validator,
        response_validator=iam_validator,
    )
    target_resolver = PsycopgOrganizationAdminTargetResolver(
        connections=pools.iam_app
    )
    issue_handler = PostgresIssueOrganizationAccessInvitationHandler(
        uow_factory=organization_uow,
        target_resolver=target_resolver,
        safety_hold=InternalSandboxOrganizationInvitationIssueSafetyHold(
            deployment_mode="INTERNAL_SANDBOX", clock=sources
        ),
        safety_hold_policy_version="iam-organization-invitation-issue-hold-v1",
        recipient_binding=_RecipientBinding(),
        token_codec=HmacOrganizationInvitationTokenCodec(
            keys=organization_keys
        ),
        keys=organization_keys,
        clock=sources,
        id_source=sources,
        secret_source=sources,
    )
    inspect_handler = object.__new__(InspectAccessInvitationHandler)
    inspect_handler._repository = reads
    inspect_handler._invitation_capabilities = issue_handler._token_codec
    lifecycle_arguments = {
        "uow_factory": organization_uow,
        "target_resolver": target_resolver,
        "keys": organization_keys,
        "clock": sources,
        "id_source": sources,
    }
    iam_bindings = IamHttpPresenterBindings(
        begin_oidc_authorization=begin,
        complete_oidc_authorization=complete,
        get_session_bootstrap=session_handler,
        get_policy_bundle=policy_bundle_handler,
        get_me=me_handler,
        list_my_sessions=session_list_handler,
        inspect_access_invitation=inspect_handler,
        get_organization_summary=organization_handler,
        update_organization_public_name=PostgresUpdateOrganizationPublicNameHandler(
            uow_factory=organization_public_name_uow,
            keys=organization_keys,
            clock=sources,
            id_source=sources,
        ),
        list_organization_access_invitations=invitation_list_handler,
        issue_organization_access_invitation=issue_handler,
        list_organization_memberships=membership_list_handler,
        revoke_access_invitation=PostgresRevokeAccessInvitationHandler(
            **lifecycle_arguments
        ),
        suspend_membership=PostgresSuspendMembershipHandler(
            **lifecycle_arguments
        ),
        resume_membership=PostgresResumeMembershipHandler(
            **lifecycle_arguments,
            safety_hold=InternalSandboxMembershipResumeSafetyHold(
                deployment_mode="INTERNAL_SANDBOX", clock=sources
            ),
            safety_hold_policy_version="iam-membership-resume-hold-v1",
        ),
        revoke_membership=PostgresRevokeMembershipHandler(
            **lifecycle_arguments
        ),
        accept_current_policies=policy_handler,
        revoke_my_session=logout_handler,
    )

    session_keyring = _SessionKeyring()
    session_security = PsycopgIamSessionSecurity(
        connections=pools.iam_session_authenticator,
        keyring=session_keyring,
        id_source=sources,
    )
    begin._invitation_reads = reads
    begin._invitation_capabilities = issue_handler._token_codec
    begin._session_security = session_security
    complete._session_security = session_security
    acceptance_hold = InternalSandboxInvitationSafetyHold(
        deployment_mode="INTERNAL_SANDBOX",
        clock=sources,
    )
    iam_bindings = replace(
        iam_bindings,
        accept_access_invitation=PostgresAcceptOrganizationAccessInvitationHandler(
            scope_resolver=PsycopgOrganizationAcceptScopeResolver(
                connections=pools.iam_onboarding
            ),
            uow_factory=PsycopgAcceptAccessInvitationUnitOfWorkFactory(
                connections=pools.iam_onboarding,
                event_validator=iam_validator,
                response_validator=iam_validator,
            ),
            safety_hold=acceptance_hold,
            keyring=OrganizationAcceptKeyring(
                receipt_keys=organization_keys,
                session_keyring=session_keyring,
            ),
            clock=sources,
            id_source=sources,
            secret_source=sources,
        ),
    )
    marker_resolver = PsycopgAuthorityMarkerResolver(
        profile_connections=pools.profile_app,
        demand_owner_connections=pools.demand_self,
        demand_reviewer_connections=pools.demand_review,
    )
    authorities = PostgresEditorAuthorityProvider(
        marker_resolver=marker_resolver,
        profile_connections=pools.profile_app,
        demand_owner_connections=pools.demand_self,
        demand_reviewer_connections=pools.demand_review,
    )
    demand_safety_hold = PsycopgTrustDemandSafetyHoldProvider(
        decision_connections=pools.trust_decision,
    )
    evidence = InternalSandboxEditorEvidenceProvider(
        deployment_mode="INTERNAL_SANDBOX",
        demand_rule_catalog=_ManagedDemandRuleCatalog(),
        demand_safety_hold=demand_safety_hold,
        validation_clock=sources,
    )
    profile_validator = ProfilePostgresContractValidator()
    demand_validator = DemandPostgresContractValidator()
    profile_uow = PsycopgCreatorProfileUnitOfWorkFactory(
        connections=pools.profile_app,
        event_validator=profile_validator,
        response_validator=profile_validator,
    )
    demand_owner_uow = PsycopgDemandUnitOfWorkFactory(
        connections=pools.demand_self,
        event_validator=demand_validator,
        response_validator=demand_validator,
    )
    demand_review_uow = PsycopgDemandUnitOfWorkFactory(
        connections=pools.demand_review,
        event_validator=demand_validator,
        response_validator=demand_validator,
    )
    review_queue = PsycopgDemandReviewQueue(
        connections=pools.demand_review,
        event_validator=demand_validator,
    )
    repository = PsycopgEditorRepository(
        profile_uow=profile_uow,
        demand_uows={
            DemandPostgresOperation.CREATE: demand_owner_uow,
            DemandPostgresOperation.CREATE_VERSION: demand_owner_uow,
            DemandPostgresOperation.SUBMIT: demand_owner_uow,
            DemandPostgresOperation.CANCEL_OWNER: demand_owner_uow,
            DemandPostgresOperation.VERIFY: demand_review_uow,
            DemandPostgresOperation.REQUEST_CHANGES: demand_review_uow,
            DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT: (
                demand_review_uow
            ),
        },
        profile_reads=pools.profile_app,
        demand_owner_reads=pools.demand_self,
        demand_review_reads=pools.demand_review,
    )
    editor_keys = EditorPostgresKeys(
        id_key=b"1" * 32,
        profile_idempotency_key=b"2" * 32,
        profile_payload_key=b"3" * 32,
        demand_idempotency_key=b"4" * 32,
        demand_payload_key=b"5" * 32,
        demand_client_reference_key=b"6" * 32,
    )
    completed_verify_receipts = PsycopgDemandCompletedVerifyReceiptProbe(
        connections=pools.demand_review,
        idempotency_keys=((
            editor_keys.demand_idempotency_key_id,
            editor_keys.demand_idempotency_key,
        ),),
        payload_hash_keys=((
            editor_keys.demand_payload_key_id,
            editor_keys.demand_payload_key,
        ),),
    )
    completed_profile_lifecycle_receipts = (
        PsycopgProfileCompletedLifecycleReceiptProbe(
            connections=pools.profile_app,
            idempotency_keys=((
                editor_keys.profile_idempotency_key_id,
                editor_keys.profile_idempotency_key,
            ),),
            payload_hash_keys=((
                editor_keys.profile_payload_key_id,
                editor_keys.profile_payload_key,
            ),),
        )
    )
    editor_service = PostgresEditorService(
        repository=repository,
        authorities=authorities,
        evidence=evidence,
        keys=editor_keys,
        clock=sources,
        review_queue=review_queue,
        completed_verify_receipts=completed_verify_receipts,
        completed_profile_lifecycle_receipts=(
            completed_profile_lifecycle_receipts
        ),
    )
    finance_service = PsycopgFinanceFundingService(
        connections=pools.demand_finance,
        keys=FinanceFundingKeys(
            id_key=editor_service._keys.id_key,
            idempotency_key=editor_service._keys.demand_idempotency_key,
            payload_key=editor_service._keys.demand_payload_key,
            idempotency_key_id=(
                editor_service._keys.demand_idempotency_key_id
            ),
            payload_key_id=editor_service._keys.demand_payload_key_id,
        ),
    )
    account_admin_service = PostgresInternalSandboxAccountAdminService(
        repository=PsycopgInternalSandboxAccountAdminRepository(
            connections=pools.iam_app
        ),
        lifecycle=PsycopgPlatformUserLifecycleUnitOfWorkFactory(
            connections=pools.iam_app,
            event_validator=iam_validator,
            response_validator=iam_validator,
        ),
        keys=account_admin_keys,
        clock=sources,
        id_source=sources,
    )
    secret_carrier = FileSecretCarrier(
        purpose="CSRF",
        key_id="composition-test-v1",
        not_before=datetime.now(timezone.utc) - timedelta(days=1),
        not_after=datetime.now(timezone.utc) + timedelta(days=1),
        status="ACTIVE",
        material=bytearray(b"s" * 32),
    )
    appeal_receipt_keyring = AppealPostgresReceiptKeyring(
        idempotency_keys=(
            AppealPostgresReceiptKey(
                purpose="IDEMPOTENCY",
                key_id="trust-idempotency-2026-01",
                material=bytearray(b"a" * 32),
            ),
        ),
        payload_hash_keys=(
            AppealPostgresReceiptKey(
                purpose="PAYLOAD_HASH",
                key_id="trust-payload-2026-01",
                material=bytearray(b"b" * 32),
            ),
        ),
    )
    appeal_sealed_keyring = AppealSealedTextKeyring(
        keys=(
            AppealSealedTextKey(
                key_id="trust-sealed-note-v1",
                material=bytearray(b"c" * 32),
            ),
        ),
        active_key_id="trust-sealed-note-v1",
        retained_key_ids=("trust-sealed-note-v1",),
    )
    appeal_gateway = PsycopgAppealCommandGateway(
        applicant_connections=pools.trust_self,
        reviewer_connections=pools.trust_appeal,
    )
    appeal_receipt_probe = PsycopgAppealReceiptProbe(
        applicant_connections=pools.trust_self,
        reviewer_connections=pools.trust_appeal,
    )
    appeal_sealed_text = PsycopgAppealSealedTextProvider(
        store=PsycopgAppealRestrictedTextStore(
            applicant_connections=pools.trust_self,
            reviewer_connections=pools.trust_appeal,
        ),
        keyring=appeal_sealed_keyring,
    )
    appeal_handlers = build_appeal_postgres_command_handlers(
        gateway=appeal_gateway,
        receipt_probe=appeal_receipt_probe,
        receipt_keyring=appeal_receipt_keyring,
        id_source=sources,
        clock=sources,
        sealed_text=appeal_sealed_text,
    )
    appeal_runtime = InternalSandboxAppealPostgresRuntime(
        projections=PsycopgAppealHttpProjectionAdapter(
            read_gateway=PsycopgAppealReadGateway(
                applicant_connections=pools.trust_self,
                reviewer_connections=pools.trust_appeal,
            )
        ),
        command_gateway=appeal_gateway,
        receipt_probe=appeal_receipt_probe,
        receipt_keyring=appeal_receipt_keyring,
        sealed_text=appeal_sealed_text,
        runtime_readiness=PsycopgAppealRuntimeReadiness(
            applicant_connections=pools.trust_self,
            reviewer_connections=pools.trust_appeal,
        ),
    )
    appeal_bindings = AppealHttpPresenterBindings(
        projections=appeal_runtime,
        **appeal_handlers.__dict__,
    )
    matching_runtime = PsycopgMatchingRuntime(
        creator_connections=pools.matching_creator,
        selector_connections=pools.matching_selector,
    )
    matching_assignment_runtime = PsycopgMatchingAssignmentRuntime(
        connections=pools.matching_assignment,
    )
    matching_review_runtime = PsycopgMatchingReviewRuntime(
        connections=pools.matching_review,
    )
    matching_keys = MatchingPostgresHttpKeys(
        idempotency_key_id="matching-idempotency-v1",
        idempotency_key=bytearray(b"m" * 32),
        payload_hash_key_id="matching-payload-v1",
        payload_hash_key=bytearray(b"n" * 32),
        read_cursor_key_id="matching-read-cursor-v1",
        read_cursor_key=bytearray(b"o" * 32),
    )
    matching_bindings = build_matching_postgres_http_bindings(
        runtime=matching_runtime,
        keys=matching_keys,
        id_source=sources,
        review_runtime=matching_review_runtime,
        demand_hold=demand_safety_hold,
    )
    matching_operational_service = MatchingPostgresOperationalHttpService(
        assignment_runtime=matching_assignment_runtime,
        review_runtime=matching_review_runtime,
        keys=matching_keys,
        id_source=sources,
    )

    return InternalSandboxApiDependencies(
        pools=pools,
        runtime_secrets=ManagedRuntimeSecrets(
            carriers=(secret_carrier,),
            clock=sources.now,
        ),
        iam_presenter_bindings=iam_bindings,
        session_security=session_security,
        origin_policy=ExactOriginPolicy(
            ExactOriginPolicySettings(
                allowed_origins=("http://api:8000",),
                allow_internal_bff_http=True,
                deployment_mode="INTERNAL_SANDBOX",
            )
        ),
        rate_limiter=InternalSandboxRateLimiter(
            settings=InternalSandboxRateLimitSettings(), clock=sources
        ),
        telemetry=JsonLineHttpTelemetry(stream=io.StringIO()),
        runtime_sources=sources,
        editor_service=editor_service,
        account_admin_service=account_admin_service,
        editor_review_queue=review_queue,
        finance_funding_service=finance_service,
        editor_principal_resolver=PsycopgEditorPrincipalResolver(
            connections=pools.iam_app
        ),
        editor_authorities=authorities,
        editor_evidence=evidence,
        oidc_provider_readiness=OidcProviderReadiness(
            provider=provider,
            security_policy=policy,
        ),
        local_server_dependency_readiness=LocalServerDependencyReadiness(
            dependency_probe=lambda: None
        ),
        schema_readiness=_schema_readiness(pools),
        seed_readiness=PostgresInternalSandboxSeedReadiness(
            pool=pools.profile_app
        ),
        readiness_timeout_ms=1_000,
        appeal_http_bindings=appeal_bindings,
        matching_http_bindings=matching_bindings,
        matching_runtime=matching_runtime,
        matching_assignment_runtime=matching_assignment_runtime,
        matching_review_runtime=matching_review_runtime,
        matching_operational_service=matching_operational_service,
    )


class OidcProviderReadinessTests(unittest.TestCase):
    def test_local_jose_and_aead_dependencies_fail_closed_before_listen(self) -> None:
        readiness = LocalServerDependencyReadiness(
            dependency_probe=lambda: None
        )
        self.assertIsNone(readiness.check_readiness(timeout_ms=1_000))
        readiness.close()
        with self.assertRaises(RuntimeError):
            readiness.check_readiness(timeout_ms=1_000)

        failing = LocalServerDependencyReadiness(
            dependency_probe=lambda: (_ for _ in ()).throw(
                ImportError("sensitive dependency path")
            )
        )
        with self.assertRaisesRegex(RuntimeError, "LOCAL_SERVER_DEPENDENCY_NOT_READY"):
            failing.check_readiness(timeout_ms=1_000)

    def test_preloads_exact_discovery_and_jwks_without_exchanging_code(self) -> None:
        transport = _FakeOidcTransport()
        transport.responses = [
            {
                "issuer": ISSUER,
                "authorization_endpoint": ISSUER + "/authorize",
                "token_endpoint": ISSUER + "/token",
                "jwks_uri": ISSUER + "/jwks",
                "code_challenge_methods_supported": ["S256"],
                "id_token_signing_alg_values_supported": ["RS256"],
            },
            {"keys": [{"kty": "RSA", "kid": "key-1"}]},
        ]
        readiness = OidcProviderReadiness(
            provider=_provider(transport), security_policy=_policy()
        )

        self.assertIsNone(readiness.check_readiness(timeout_ms=1_000))
        self.assertEqual(len(transport.calls), 2)
        readiness.close()
        with self.assertRaises(RuntimeError):
            readiness.check_readiness(timeout_ms=1_000)


class InternalSandboxApiCompositionTests(unittest.TestCase):
    def test_builds_only_the_exact_pg_backed_internal_bff_application(self) -> None:
        dependencies = _dependencies()

        runtime = build_internal_sandbox_api(dependencies)

        self.assertIsInstance(runtime, InternalSandboxRuntime)
        self.assertTrue(callable(runtime.application))
        self.assertIsInstance(runtime._delegate, InternalBffTransportApplication)
        observed = runtime._delegate._application
        self.assertIsInstance(observed, ObservedAsgiApplication)
        self.assertIsInstance(observed.application, InternalSandboxApiMux)
        self.assertIsNotNone(observed.application._matching_application)
        matching_bindings = (
            observed.application._matching_application._dispatcher._bindings
        )
        self.assertIsNotNone(matching_bindings.create_invitation)
        self.assertIsNotNone(matching_bindings.publish_invitation)
        self.assertIsNotNone(matching_bindings.invalidate_attempt)
        self.assertIsNotNone(matching_bindings.reviewer_assignments)
        self.assertIs(
            observed.application._matching_application._operational_service,
            dependencies.matching_operational_service,
        )
        self.assertIn(dependencies.matching_runtime, runtime._resources)
        self.assertIn(dependencies.matching_assignment_runtime, runtime._resources)
        self.assertIn(dependencies.matching_review_runtime, runtime._resources)
        self.assertIsNone(
            observed.application._iam_application._transport._telemetry
        )
        self.assertNotIn("password", repr(runtime).lower())
        secret_material = dependencies.runtime_secrets.carriers[0].material
        runtime.close()
        self.assertTrue(dependencies.editor_authorities._closed)
        self.assertTrue(dependencies.editor_evidence._closed)
        self.assertTrue(dependencies.finance_funding_service._closed)
        self.assertTrue(dependencies.seed_readiness._closed)
        self.assertTrue(dependencies.matching_assignment_runtime._gateway.closed)
        self.assertTrue(dependencies.matching_review_runtime._gateway.closed)
        self.assertEqual(set(secret_material), {0})

    def test_rejects_wrong_pool_role_and_memory_shaped_dependencies(self) -> None:
        dependencies = _dependencies()
        with self.assertRaises(ValueError):
            InternalSandboxApiPools(
                **{
                    field.name: (
                        dependencies.pools.iam_app
                        if field.name == "profile_app"
                        else getattr(dependencies.pools, field.name)
                    )
                    for field in fields(InternalSandboxApiPools)
                }
            )

        dependencies.editor_service._authorities = object()
        with self.assertRaises(TypeError):
            build_internal_sandbox_api(dependencies)

        dependencies = _dependencies()
        dependencies.matching_runtime._selector_connections = (
            dependencies.pools.matching_creator
        )
        with self.assertRaises(TypeError):
            build_internal_sandbox_api(dependencies)

        dependencies = _dependencies()
        dependencies.matching_assignment_runtime._gateway.connections = (
            dependencies.pools.matching_review
        )
        with self.assertRaises(TypeError):
            build_internal_sandbox_api(dependencies)

        dependencies = _dependencies()
        dependencies.matching_operational_service._review_runtime = (
            dependencies.matching_assignment_runtime
        )
        with self.assertRaises(TypeError):
            build_internal_sandbox_api(dependencies)

        dependencies = _dependencies()
        object.__setattr__(
            dependencies.matching_http_bindings,
            "create_invitation",
            object(),
        )
        with self.assertRaises(TypeError):
            build_internal_sandbox_api(dependencies)

        dependencies = _dependencies()
        fake_evidence = _ManagedEvidence()
        dependencies.editor_service._authorities = dependencies.editor_authorities
        dependencies.editor_service._evidence = fake_evidence
        with self.assertRaises(TypeError):
            build_internal_sandbox_api(
                replace(dependencies, editor_evidence=fake_evidence)
            )

        dependencies = _dependencies()
        dependencies.editor_service._repo._profile_uow.event_validator = object()
        with self.assertRaises(TypeError):
            build_internal_sandbox_api(dependencies)

        dependencies = _dependencies()
        dependencies.editor_service._completed_profile_lifecycle_receipts = None
        with self.assertRaises(TypeError):
            build_internal_sandbox_api(dependencies)

        dependencies = _dependencies()
        dependencies.editor_service._completed_profile_lifecycle_receipts._connections = (
            dependencies.pools.demand_self
        )
        with self.assertRaises(TypeError):
            build_internal_sandbox_api(dependencies)

        dependencies = _dependencies()
        profile_probe = (
            dependencies.editor_service._completed_profile_lifecycle_receipts
        )
        profile_probe._payload_hash_keys = (
            ("profile-payload-retired", bytearray(b"p" * 32)),
            profile_probe._payload_hash_keys[0],
        )
        with self.assertRaises(TypeError):
            build_internal_sandbox_api(dependencies)

        dependencies = _dependencies()
        dependencies.editor_service._completed_verify_receipts = None
        with self.assertRaises(TypeError):
            build_internal_sandbox_api(dependencies)

        dependencies = _dependencies()
        dependencies.editor_service._completed_verify_receipts._connections = (
            dependencies.pools.demand_self
        )
        with self.assertRaises(TypeError):
            build_internal_sandbox_api(dependencies)

        dependencies = _dependencies()
        probe = dependencies.editor_service._completed_verify_receipts
        probe._idempotency_keys = (
            ("demand-idempotency-retired", bytearray(b"r" * 32)),
            probe._idempotency_keys[0],
        )
        with self.assertRaises(TypeError):
            build_internal_sandbox_api(dependencies)

        dependencies = _dependencies()
        with self.assertRaises(TypeError):
            build_internal_sandbox_api(
                replace(
                    dependencies,
                    seed_readiness=PostgresInternalSandboxSeedReadiness(
                        pool=dependencies.pools.demand_self
                    ),
                )
            )

    def test_requires_owner_cancel_to_use_the_exact_owner_uow(self) -> None:
        dependencies = _dependencies()
        demand_uows = dependencies.editor_service._repo._demand_uows
        owner_uow = demand_uows[DemandPostgresOperation.CREATE]
        self.assertIs(
            demand_uows[DemandPostgresOperation.CANCEL_OWNER],
            owner_uow,
        )

        del demand_uows[DemandPostgresOperation.CANCEL_OWNER]
        with self.assertRaises(TypeError):
            build_internal_sandbox_api(dependencies)

        dependencies = _dependencies()
        demand_uows = dependencies.editor_service._repo._demand_uows
        demand_uows[DemandPostgresOperation.CANCEL_OWNER] = demand_uows[
            DemandPostgresOperation.VERIFY
        ]
        with self.assertRaises(TypeError):
            build_internal_sandbox_api(dependencies)

    def test_rejects_appeal_handler_keyring_or_role_pool_miswiring(self) -> None:
        dependencies = _dependencies()
        runtime = dependencies.appeal_http_bindings.projections
        runtime._command_gateway._reviewer_connections = (
            dependencies.pools.trust_officer
        )
        with self.assertRaises(TypeError):
            build_internal_sandbox_api(dependencies)

        dependencies = _dependencies()
        handler = dependencies.appeal_http_bindings.open_appeal
        handler._receipt_keyring = object()
        with self.assertRaises(TypeError):
            build_internal_sandbox_api(dependencies)

        dependencies = _dependencies()
        object.__setattr__(
            dependencies.appeal_http_bindings,
            "claim_appeal",
            dependencies.appeal_http_bindings.release_assignment,
        )
        with self.assertRaises(TypeError):
            build_internal_sandbox_api(dependencies)

    def test_rejects_oidc_or_read_handlers_bound_to_another_pool(self) -> None:
        dependencies = _dependencies()
        begin = dependencies.iam_presenter_bindings.begin_oidc_authorization
        begin._uow = PsycopgOidcAuthenticationUnitOfWork(
            connections=dependencies.pools.iam_app
        )

        with self.assertRaises(TypeError):
            build_internal_sandbox_api(dependencies)

    def test_owned_session_revocation_is_exact_pg_binding_and_pool(self) -> None:
        dependencies = _dependencies()
        handler = dependencies.iam_presenter_bindings.revoke_my_session
        self.assertIsInstance(handler, PostgresRevokeOwnedSessionHandler)
        self.assertIsInstance(
            handler._uow_factory,
            PsycopgOwnedSessionRevocationUnitOfWorkFactory,
        )
        self.assertIs(
            handler._uow_factory.connections,
            dependencies.pools.iam_app,
        )
        runtime = build_internal_sandbox_api(dependencies)
        runtime.close()

        dependencies = _dependencies()
        handler = dependencies.iam_presenter_bindings.revoke_my_session
        handler._uow_factory.connections = dependencies.pools.iam_onboarding
        with self.assertRaises(TypeError):
            build_internal_sandbox_api(dependencies)

    def test_public_name_command_is_exact_pg_binding_pool_keys_and_sources(self) -> None:
        dependencies = _dependencies()
        handler = dependencies.iam_presenter_bindings.update_organization_public_name
        issue = dependencies.iam_presenter_bindings.issue_organization_access_invitation
        self.assertIsInstance(handler, PostgresUpdateOrganizationPublicNameHandler)
        self.assertIsInstance(
            handler._uow_factory,
            PsycopgOrganizationPublicNameUnitOfWorkFactory,
        )
        self.assertIs(handler._uow_factory.connections, dependencies.pools.iam_app)
        self.assertIs(handler._keys, issue._keys)
        self.assertIs(handler._clock, dependencies.runtime_sources)
        self.assertIs(handler._ids, dependencies.runtime_sources)
        runtime = build_internal_sandbox_api(dependencies)
        runtime.close()

        dependencies = _dependencies()
        handler = dependencies.iam_presenter_bindings.update_organization_public_name
        handler._uow_factory.connections = dependencies.pools.iam_onboarding
        with self.assertRaises(TypeError):
            build_internal_sandbox_api(dependencies)

    def test_session_list_is_exact_pg_read_binding_and_shared_cursor(self) -> None:
        dependencies = _dependencies()
        bindings = dependencies.iam_presenter_bindings
        handler = bindings.list_my_sessions
        self.assertIsInstance(handler, ListMySessionsHandler)
        self.assertIs(
            handler._repository,
            bindings.get_session_bootstrap._repository,
        )
        self.assertIs(
            handler._repository._app_connections,
            dependencies.pools.iam_app,
        )
        self.assertIs(
            handler._cursor_codec,
            bindings.list_organization_access_invitations._cursor_codec,
        )
        self.assertIs(
            handler._cursor_codec,
            bindings.list_organization_memberships._cursor_codec,
        )
        runtime = build_internal_sandbox_api(dependencies)
        runtime.close()

        dependencies = _dependencies()
        dependencies.iam_presenter_bindings.list_my_sessions._cursor_codec = (
            HmacIamReadCursorCodec(
                keys=(
                    RuntimeKeyMaterial(
                        purpose="IAM_READ_CURSOR",
                        key_id="iam-read-cursor-other-v1",
                        material=bytearray(b"d" * 32),
                    ),
                ),
                active_key_id="iam-read-cursor-other-v1",
            )
        )
        with self.assertRaises(TypeError):
            build_internal_sandbox_api(dependencies)

        class DerivedListMySessionsHandler(ListMySessionsHandler):
            pass

        dependencies = _dependencies()
        derived = object.__new__(DerivedListMySessionsHandler)
        derived.__dict__.update(
            dependencies.iam_presenter_bindings.list_my_sessions.__dict__
        )
        object.__setattr__(
            dependencies.iam_presenter_bindings,
            "list_my_sessions",
            derived,
        )
        with self.assertRaises(TypeError):
            build_internal_sandbox_api(dependencies)


if __name__ == "__main__":
    unittest.main()
