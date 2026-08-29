"""Concrete PostgreSQL-only ASGI composition for ``INTERNAL_SANDBOX``.

This module is intentionally narrower than the generic runtime composition
kernel.  It accepts already-created, role-bound PostgreSQL adapters and proves
their wiring before exposing the internal Docker BFF transport.  It never
selects a Memory implementation and never fills a missing dependency with a
no-op object.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from typing import Any, Callable, Tuple

from desire_platform.creator_profile.adapters.postgres import (
    PsycopgCreatorProfileUnitOfWorkFactory,
)
from desire_platform.demand.adapters.postgres import (
    DemandPostgresOperation,
    PsycopgDemandUnitOfWorkFactory,
)
from desire_platform.http import (
    ExactOriginPolicy,
    IamAsgiApplication,
    IamHttpApplicationDispatcher,
    IamHttpPresenterBindings,
    IamHttpTransport,
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
    MatchingOperationalPostgresSettings,
    MatchingPostgresSettings,
    PsycopgMatchingAssignmentRuntime,
    PsycopgMatchingReviewRuntime,
    PsycopgMatchingRuntime,
)
from desire_platform.matching.http import (
    MatchingHttpApplicationDispatcher,
    MatchingHttpPresenterBindings,
)
from desire_platform.trust_safety.http import (
    TrustHttpApplicationDispatcher,
    TrustHttpPresenterBindings,
)
from desire_platform.trust_safety.adapters.postgres import (
    PostgresClaimAppealHandler,
    PostgresClaimSafetyCaseHandler,
    PostgresClaimSafetyHoldReleaseHandler,
    PostgresDecideAppealHandler,
    PostgresOpenAppealHandler,
    PostgresPlaceSafetyHoldHandler,
    PostgresPublishTrustOutcomeHandler,
    PostgresPublishTrustTriageHandler,
    PostgresReleaseAppealAssignmentHandler,
    PostgresReleaseSafetyCaseAssignmentHandler,
    PostgresReleaseSafetyHoldHandler,
    PostgresSaveAppealDraftHandler,
    PostgresSaveAppealReviewDraftHandler,
    PostgresSaveTrustTriageDraftHandler,
    PostgresSubmitAppealHandler,
    PostgresSubmitSafetyReportHandler,
    PsycopgTrustDemandSafetyHoldProvider,
)
from desire_platform.trust_safety.appeal_http import (
    AppealHttpApplicationDispatcher,
    AppealHttpPresenterBindings,
)

from .editor import (
    EditorAsgiApplication,
    EditorHttpApi,
    EditorPostgresKeys,
    PostgresEditorAuthorityProvider,
    PostgresEditorService,
    PsycopgDemandCompletedVerifyReceiptProbe,
    PsycopgDemandReviewQueue,
    PsycopgEditorRepository,
    PsycopgProfileCompletedLifecycleReceiptProbe,
)
from .account_admin import (
    PlatformUserAdminKeys,
    PostgresInternalSandboxAccountAdminService,
    PsycopgInternalSandboxAccountAdminRepository,
)
from .contract_validation import (
    DemandPostgresContractValidator,
    IamPostgresContractValidator,
    ProfilePostgresContractValidator,
)
from .editor.sandbox_evidence import InternalSandboxEditorEvidenceProvider
from .finance_funding import PsycopgFinanceFundingService
from .postgres_pool import RoleBoundPsycopgPool
from .policy_acceptance import (
    IamReceiptPolicyKeys,
    PostgresAcceptCurrentPoliciesHandler,
    PsycopgPolicyAcceptanceScopeResolver,
)
from .current_session_logout import PostgresRevokeOwnedSessionHandler
from .matching_http import MatchingAsgiApplication
from .matching_postgres import (
    MatchingPostgresOperationalHttpService,
    PostgresCreateMatchingInvitationHandler,
    PostgresChooseCreatorHandler,
    PostgresCloseSelectionWithoutChoiceHandler,
    PostgresInvalidateMatchingAttemptHandler,
    PostgresPublishMatchingInvitationHandler,
    PostgresRespondInvitationHandler,
    PostgresWithdrawAcceptedInvitationHandler,
    PsycopgMatchingCommandActorResolver,
    PsycopgMatchingHttpProjectionAdapter,
    PsycopgMatchingReviewerAssignmentResolver,
)
from .appeal_http import AppealAsgiApplication
from .appeal_runtime import InternalSandboxAppealPostgresRuntime
from .trust_http import TrustAsgiApplication
from .trust_runtime import InternalSandboxTrustPostgresRuntime
from .task_discovery import CurrentAccountTaskDiscoveryService
from .runtime import (
    EditorPrincipalBridge,
    InternalBffTransportApplication,
    InternalSandboxApiMux,
    InternalSandboxRuntime,
)
from .runtime_adapters import (
    InternalSandboxRateLimiter,
    JsonLineHttpTelemetry,
    SecureRuntimeSources,
)
from .runtime_crypto import HmacIamReadCursorCodec
from .schema_readiness import PostgresSchemaCompatibilityReadiness
from .seed_readiness import PostgresInternalSandboxSeedReadiness
from .secrets import ManagedRuntimeSecrets


_OPEN_IAM_BINDINGS = frozenset(
    (
        "begin_oidc_authorization",
        "complete_oidc_authorization",
        "get_session_bootstrap",
        "get_policy_bundle",
        "get_me",
        "list_my_sessions",
        "inspect_access_invitation",
        "accept_access_invitation",
        "get_organization_summary",
        "update_organization_public_name",
        "list_organization_access_invitations",
        "issue_organization_access_invitation",
        "list_organization_memberships",
        "revoke_access_invitation",
        "suspend_membership",
        "resume_membership",
        "revoke_membership",
        "accept_current_policies",
        "revoke_my_session",
    )
)
_AUTHORITY_METHODS = (
    "profile",
    "demand",
    "profile_targets",
    "demand_targets",
)
_EVIDENCE_METHODS = (
    "editor_configuration",
    "profile_hold",
    "demand_content_policy",
    "demand_hold",
    "demand_rules",
)


def _managed(value: Any) -> bool:
    return callable(getattr(value, "check_readiness", None)) and callable(
        getattr(value, "close", None)
    )


@dataclass(frozen=True)
class InternalSandboxApiPools:
    """The fifteen reviewed online identities provisioned for the API process."""

    iam_app: RoleBoundPsycopgPool
    iam_session_authenticator: RoleBoundPsycopgPool
    iam_onboarding: RoleBoundPsycopgPool
    profile_app: RoleBoundPsycopgPool
    demand_self: RoleBoundPsycopgPool
    demand_review: RoleBoundPsycopgPool
    demand_finance: RoleBoundPsycopgPool
    trust_self: RoleBoundPsycopgPool
    trust_officer: RoleBoundPsycopgPool
    trust_appeal: RoleBoundPsycopgPool
    trust_decision: RoleBoundPsycopgPool
    matching_creator: RoleBoundPsycopgPool
    matching_selector: RoleBoundPsycopgPool
    matching_assignment: RoleBoundPsycopgPool
    matching_review: RoleBoundPsycopgPool

    def __post_init__(self) -> None:
        materialized = tuple(
            (field.name, getattr(self, field.name)) for field in fields(self)
        )
        if len({id(pool) for _, pool in materialized}) != len(materialized):
            raise ValueError("internal sandbox database pools cannot be aliased")
        for expected_role, pool in materialized:
            if not isinstance(pool, RoleBoundPsycopgPool):
                raise TypeError("internal sandbox requires role-bound PostgreSQL pools")
            profile = getattr(pool, "_profile", None)
            if getattr(profile, "online_role", None) != expected_role:
                raise ValueError("internal sandbox database pool role is miswired")

    def values(self) -> Tuple[RoleBoundPsycopgPool, ...]:
        return tuple(getattr(self, field.name) for field in fields(self))


class OidcProviderReadiness:
    """Warm exact discovery and JWKS before the ASGI server may listen."""

    def __init__(
        self,
        *,
        provider: ClosedOidcProvider,
        security_policy: OidcSecurityPolicy,
    ) -> None:
        if not isinstance(provider, ClosedOidcProvider):
            raise TypeError("closed OIDC provider is unavailable")
        if not isinstance(security_policy, OidcSecurityPolicy):
            raise TypeError("OIDC security policy is unavailable")
        self._provider = provider
        self._security_policy = security_policy
        self._closed = False

    def check_readiness(self, *, timeout_ms: int) -> None:
        if (
            self._closed
            or type(timeout_ms) is not int
            or not 1 <= timeout_ms <= 30_000
        ):
            raise RuntimeError("OIDC_PROVIDER_NOT_READY")
        policy = self._security_policy
        try:
            result = self._provider.preflight_exchange(
                expected_issuer=policy.provider_issuer,
                expected_audience=policy.provider_audience,
                redirect_uri=policy.redirect_uri,
            )
        except BaseException:
            raise RuntimeError("OIDC_PROVIDER_NOT_READY") from None
        if result is not None:
            raise RuntimeError("OIDC_PROVIDER_NOT_READY")
        return None

    def close(self) -> None:
        self._closed = True

    def __repr__(self) -> str:
        return f"OidcProviderReadiness(closed={self._closed}, provider=<redacted>)"


def _probe_local_server_dependencies() -> None:
    try:
        import jwt
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except (ImportError, ModuleNotFoundError):
        raise RuntimeError("LOCAL_SERVER_DEPENDENCY_NOT_READY") from None
    if (
        not callable(getattr(jwt, "decode", None))
        or not callable(getattr(jwt, "PyJWK", None))
        or not callable(AESGCM)
    ):
        raise RuntimeError("LOCAL_SERVER_DEPENDENCY_NOT_READY")
    algorithms = jwt.algorithms.get_default_algorithms()
    if not {"RS256", "ES256"}.issubset(algorithms):
        raise RuntimeError("LOCAL_SERVER_DEPENDENCY_NOT_READY")


class LocalServerDependencyReadiness:
    """Prove the optional JOSE/AEAD server extra before opening a socket."""

    def __init__(
        self,
        *,
        dependency_probe: Callable[[], None] = _probe_local_server_dependencies,
    ) -> None:
        if not callable(dependency_probe):
            raise TypeError("local server dependency probe is unavailable")
        self._dependency_probe = dependency_probe
        self._closed = False

    def check_readiness(self, *, timeout_ms: int) -> None:
        if (
            self._closed
            or type(timeout_ms) is not int
            or not 1 <= timeout_ms <= 30_000
        ):
            raise RuntimeError("LOCAL_SERVER_DEPENDENCY_NOT_READY")
        try:
            result = self._dependency_probe()
        except BaseException:
            raise RuntimeError("LOCAL_SERVER_DEPENDENCY_NOT_READY") from None
        if result is not None:
            raise RuntimeError("LOCAL_SERVER_DEPENDENCY_NOT_READY")

    def close(self) -> None:
        self._closed = True

    def __repr__(self) -> str:
        return f"LocalServerDependencyReadiness(closed={self._closed})"


@dataclass(frozen=True)
class InternalSandboxApiDependencies:
    """Closed dependency registry for the one current product API process."""

    pools: InternalSandboxApiPools
    runtime_secrets: ManagedRuntimeSecrets
    iam_presenter_bindings: IamHttpPresenterBindings
    session_security: PsycopgIamSessionSecurity
    origin_policy: ExactOriginPolicy
    rate_limiter: InternalSandboxRateLimiter
    telemetry: JsonLineHttpTelemetry
    runtime_sources: SecureRuntimeSources
    editor_service: PostgresEditorService
    account_admin_service: PostgresInternalSandboxAccountAdminService
    editor_review_queue: PsycopgDemandReviewQueue
    finance_funding_service: PsycopgFinanceFundingService
    editor_principal_resolver: PsycopgEditorPrincipalResolver
    editor_authorities: PostgresEditorAuthorityProvider
    editor_evidence: InternalSandboxEditorEvidenceProvider
    oidc_provider_readiness: OidcProviderReadiness
    local_server_dependency_readiness: LocalServerDependencyReadiness
    schema_readiness: Tuple[PostgresSchemaCompatibilityReadiness, ...]
    seed_readiness: PostgresInternalSandboxSeedReadiness
    readiness_timeout_ms: int
    appeal_http_bindings: AppealHttpPresenterBindings
    matching_http_bindings: MatchingHttpPresenterBindings
    matching_runtime: PsycopgMatchingRuntime
    matching_assignment_runtime: PsycopgMatchingAssignmentRuntime
    matching_review_runtime: PsycopgMatchingReviewRuntime
    matching_operational_service: MatchingPostgresOperationalHttpService
    trust_http_bindings: TrustHttpPresenterBindings | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.pools, InternalSandboxApiPools):
            raise TypeError("internal sandbox pools are unavailable")
        if not isinstance(self.runtime_secrets, ManagedRuntimeSecrets):
            raise TypeError("managed runtime secrets are unavailable")
        if not isinstance(self.iam_presenter_bindings, IamHttpPresenterBindings):
            raise TypeError("IAM presenter bindings are unavailable")
        if not isinstance(self.session_security, PsycopgIamSessionSecurity):
            raise TypeError("PostgreSQL session security is unavailable")
        if not isinstance(self.origin_policy, ExactOriginPolicy):
            raise TypeError("exact Origin policy is unavailable")
        if not isinstance(self.rate_limiter, InternalSandboxRateLimiter):
            raise TypeError("internal sandbox rate limiter is unavailable")
        if not isinstance(self.telemetry, JsonLineHttpTelemetry):
            raise TypeError("HTTP telemetry is unavailable")
        if not isinstance(self.runtime_sources, SecureRuntimeSources):
            raise TypeError("secure runtime sources are unavailable")
        if not isinstance(self.editor_service, PostgresEditorService):
            raise TypeError("PostgreSQL editor service is unavailable")
        if not isinstance(
            self.account_admin_service,
            PostgresInternalSandboxAccountAdminService,
        ):
            raise TypeError("PostgreSQL account administration is unavailable")
        if not isinstance(self.editor_review_queue, PsycopgDemandReviewQueue):
            raise TypeError("PostgreSQL Demand review queue is unavailable")
        if not isinstance(
            self.finance_funding_service, PsycopgFinanceFundingService
        ):
            raise TypeError("PostgreSQL Finance funding service is unavailable")
        if not isinstance(
            self.editor_authorities, PostgresEditorAuthorityProvider
        ):
            raise TypeError("PostgreSQL editor authority provider is unavailable")
        if not isinstance(
            self.editor_principal_resolver, PsycopgEditorPrincipalResolver
        ):
            raise TypeError("PostgreSQL editor principal resolver is unavailable")
        if not isinstance(
            self.editor_evidence, InternalSandboxEditorEvidenceProvider
        ):
            raise TypeError("internal sandbox editor evidence is unavailable")
        if not isinstance(self.oidc_provider_readiness, OidcProviderReadiness):
            raise TypeError("OIDC provider readiness is unavailable")
        if not isinstance(
            self.local_server_dependency_readiness,
            LocalServerDependencyReadiness,
        ):
            raise TypeError("local server dependency readiness is unavailable")
        if (
            not isinstance(self.schema_readiness, tuple)
            or len(self.schema_readiness) != 5
            or any(
                not isinstance(item, PostgresSchemaCompatibilityReadiness)
                for item in self.schema_readiness
            )
        ):
            raise TypeError("schema compatibility readiness is unavailable")
        if not isinstance(
            self.seed_readiness, PostgresInternalSandboxSeedReadiness
        ):
            raise TypeError("internal sandbox seed readiness is unavailable")
        if (
            type(self.readiness_timeout_ms) is not int
            or not 50 <= self.readiness_timeout_ms <= 30_000
        ):
            raise ValueError("readiness timeout is outside bounds")
        if self.trust_http_bindings is not None and (
            not isinstance(self.trust_http_bindings, TrustHttpPresenterBindings)
            or not _managed(self.trust_http_bindings.projections)
        ):
            raise TypeError("managed PostgreSQL Trust HTTP bindings are unavailable")
        if (
            not isinstance(self.appeal_http_bindings, AppealHttpPresenterBindings)
            or not _managed(self.appeal_http_bindings.projections)
        ):
            raise TypeError("managed PostgreSQL Appeal HTTP bindings are unavailable")
        if not isinstance(self.matching_http_bindings, MatchingHttpPresenterBindings):
            raise TypeError("PostgreSQL Matching HTTP bindings are unavailable")
        if not isinstance(self.matching_runtime, PsycopgMatchingRuntime) or not _managed(
            self.matching_runtime
        ):
            raise TypeError("managed PostgreSQL Matching runtime is unavailable")
        if not isinstance(
            self.matching_assignment_runtime, PsycopgMatchingAssignmentRuntime
        ) or not _managed(self.matching_assignment_runtime):
            raise TypeError(
                "managed PostgreSQL Matching assignment runtime is unavailable"
            )
        if not isinstance(
            self.matching_review_runtime, PsycopgMatchingReviewRuntime
        ) or not _managed(self.matching_review_runtime):
            raise TypeError(
                "managed PostgreSQL Matching review runtime is unavailable"
            )
        if not isinstance(
            self.matching_operational_service,
            MatchingPostgresOperationalHttpService,
        ):
            raise TypeError("PostgreSQL Matching operational service is unavailable")


def build_internal_sandbox_api(
    dependencies: InternalSandboxApiDependencies,
) -> InternalSandboxRuntime:
    """Prove exact PG wiring, then assemble health + IAM + editor ASGI."""

    if not isinstance(dependencies, InternalSandboxApiDependencies):
        raise TypeError("internal sandbox API dependencies are unavailable")
    _validate_dependencies(dependencies)

    dispatcher = IamHttpApplicationDispatcher(
        bindings=dependencies.iam_presenter_bindings
    )
    iam_transport = IamHttpTransport(
        dispatcher=dispatcher,
        session_authenticator=dependencies.session_security,
        origin_policy=dependencies.origin_policy,
        csrf_verifier=dependencies.session_security,
        rate_limiter=dependencies.rate_limiter,
        telemetry=None,
        trace_id_source=dependencies.runtime_sources,
        allow_insecure_http=False,
    )
    iam_application = IamAsgiApplication(iam_transport)
    editor_application = EditorAsgiApplication(
        api=EditorHttpApi(
            service=dependencies.editor_service,
            account_admin_service=dependencies.account_admin_service,
            finance_service=dependencies.finance_funding_service,
            task_service=CurrentAccountTaskDiscoveryService(
                editor_service=dependencies.editor_service,
                finance_service=dependencies.finance_funding_service,
                trust_projections=(
                    None
                    if dependencies.trust_http_bindings is None
                    else dependencies.trust_http_bindings.projections
                ),
                appeal_projections=dependencies.appeal_http_bindings.projections,
            ),
        ),
        session_security=dependencies.session_security,
        principal_resolver=EditorPrincipalBridge(
            resolver=dependencies.editor_principal_resolver
        ),
        allowed_origins=("http://api:8000",),
        trace_id_source=dependencies.runtime_sources.new_trace_id,
        allow_internal_bff_http=True,
        deployment_mode="INTERNAL_SANDBOX",
    )
    trust_application = None
    if dependencies.trust_http_bindings is not None:
        trust_application = TrustAsgiApplication(
            dispatcher=TrustHttpApplicationDispatcher(
                bindings=dependencies.trust_http_bindings
            ),
            session_security=dependencies.session_security,
            principal_resolver=EditorPrincipalBridge(
                resolver=dependencies.editor_principal_resolver
            ),
            allowed_origins=("http://api:8000",),
            trace_id_source=dependencies.runtime_sources.new_trace_id,
            allow_internal_bff_http=True,
            deployment_mode="INTERNAL_SANDBOX",
        )
    appeal_application = AppealAsgiApplication(
        dispatcher=AppealHttpApplicationDispatcher(
            bindings=dependencies.appeal_http_bindings
        ),
        session_security=dependencies.session_security,
        principal_resolver=EditorPrincipalBridge(
            resolver=dependencies.editor_principal_resolver
        ),
        allowed_origins=("http://api:8000",),
        trace_id_source=dependencies.runtime_sources.new_trace_id,
        allow_internal_bff_http=True,
        deployment_mode="INTERNAL_SANDBOX",
    )
    matching_application = MatchingAsgiApplication(
        dispatcher=MatchingHttpApplicationDispatcher(
            bindings=dependencies.matching_http_bindings
        ),
        session_security=dependencies.session_security,
        principal_resolver=EditorPrincipalBridge(
            resolver=dependencies.editor_principal_resolver
        ),
        allowed_origins=("http://api:8000",),
        trace_id_source=dependencies.runtime_sources.new_trace_id,
        operational_service=dependencies.matching_operational_service,
        allow_internal_bff_http=True,
        deployment_mode="INTERNAL_SANDBOX",
    )
    mux = InternalSandboxApiMux(
        iam_application=iam_application,
        editor_application=editor_application,
        trust_application=trust_application,
        appeal_application=appeal_application,
        matching_application=matching_application,
    )
    observed_mux = ObservedAsgiApplication(
        application=mux,
        observer=dependencies.telemetry.record_boundary,
        monotonic_seconds=dependencies.runtime_sources.monotonic,
    )
    bff_application = InternalBffTransportApplication(
        application=observed_mux,
        deployment_mode="INTERNAL_SANDBOX",
        enabled=True,
    )

    # Creation order is also ownership order.  Runtime closes the tuple in
    # reverse, so protocol components become unavailable before their pools.
    managed_resources = (
        (dependencies.runtime_secrets,)
        + dependencies.pools.values()
        + dependencies.schema_readiness
        + (
            dependencies.seed_readiness,
            dependencies.editor_service._completed_profile_lifecycle_receipts,
            dependencies.editor_service._completed_verify_receipts,
            dependencies.editor_review_queue,
            dependencies.finance_funding_service,
            dependencies.editor_authorities,
            dependencies.editor_evidence,
            dependencies.local_server_dependency_readiness,
            dependencies.oidc_provider_readiness,
            dependencies.session_security,
            dependencies.origin_policy,
            dependencies.rate_limiter,
            dependencies.telemetry,
        )
        + (
            ()
            if dependencies.trust_http_bindings is None
            else (dependencies.trust_http_bindings.projections,)
        )
        + (dependencies.appeal_http_bindings.projections,)
        + (
            dependencies.matching_runtime,
            dependencies.matching_assignment_runtime,
            dependencies.matching_review_runtime,
        )
    )
    return InternalSandboxRuntime(
        application=bff_application,
        managed_resources=managed_resources,
        readiness_timeout_ms=dependencies.readiness_timeout_ms,
    )


def _validate_trust_dependencies(
    dependencies: InternalSandboxApiDependencies,
    bindings: TrustHttpPresenterBindings,
) -> None:
    expected_handlers = {
        "submit_report": PostgresSubmitSafetyReportHandler,
        "claim_case": PostgresClaimSafetyCaseHandler,
        "release_assignment": PostgresReleaseSafetyCaseAssignmentHandler,
        "save_triage": PostgresSaveTrustTriageDraftHandler,
        "publish_triage": PostgresPublishTrustTriageHandler,
        "place_hold": PostgresPlaceSafetyHoldHandler,
        "claim_hold_release": PostgresClaimSafetyHoldReleaseHandler,
        "release_hold": PostgresReleaseSafetyHoldHandler,
        "publish_outcome": PostgresPublishTrustOutcomeHandler,
    }
    runtime = bindings.projections
    if not isinstance(runtime, InternalSandboxTrustPostgresRuntime) or any(
        type(getattr(bindings, name, None)) is not expected
        for name, expected in expected_handlers.items()
    ):
        raise TypeError("exact PostgreSQL Trust HTTP bindings are unavailable")
    projection_methods = (
        "list_own_reports",
        "read_own_report",
        "list_case_queue",
        "list_hold_release_queue",
        "list_my_active_case_assignments",
        "list_my_completed_case_assignments",
        "read_assigned_case",
        "read_assigned_hold_release",
    )
    if any(
        not callable(getattr(runtime, name, None))
        for name in projection_methods
    ):
        raise TypeError("exact PostgreSQL Trust projection port is unavailable")
    handlers = tuple(getattr(bindings, name) for name in expected_handlers)
    if any(
        handler._gateway is not runtime._command_gateway
        or handler._receipt_probe is not runtime._receipt_probe
        or handler._receipt_keyring is not runtime._receipt_keyring
        or handler._id_source is not dependencies.runtime_sources
        or handler._clock is not dependencies.runtime_sources
        for handler in handlers
    ):
        raise TypeError("Trust PostgreSQL command dependencies are miswired")
    if (
        bindings.save_triage._sealed_notes is not runtime._sealed_notes
        or bindings.publish_outcome._outcome_evidence
        is not runtime._outcome_evidence
    ):
        raise TypeError("Trust restricted dependencies are miswired")

    pools = dependencies.pools
    reporter_officer = (pools.trust_self, pools.trust_officer)
    gateway = runtime._command_gateway
    receipt_probe = runtime._receipt_probe
    read_gateway = runtime._projections._read_gateway
    sealed_store = runtime._sealed_notes._store
    outcome = runtime._outcome_evidence
    readiness = runtime._runtime_readiness
    if any(
        (
            provider._reporter_connections,
            provider._officer_connections,
        )
        != reporter_officer
        for provider in (gateway, receipt_probe, read_gateway)
    ) or (
        sealed_store._connections is not pools.trust_officer
        or outcome._connections is not pools.trust_officer
        or outcome._id_source is not dependencies.runtime_sources
        or tuple(readiness._sources.values())
        != (
            pools.trust_self,
            pools.trust_officer,
            pools.trust_appeal,
            pools.trust_decision,
        )
    ):
        raise TypeError("Trust PostgreSQL role identities are miswired")
    demand_hold = dependencies.editor_evidence._demand_safety_hold
    if (
        not isinstance(demand_hold, PsycopgTrustDemandSafetyHoldProvider)
        or demand_hold._connections is not pools.trust_decision
        or dependencies.editor_evidence._validation_clock
        is not dependencies.runtime_sources
    ):
        raise TypeError("Trust Demand safety hold is miswired")


def _validate_appeal_dependencies(
    dependencies: InternalSandboxApiDependencies,
    bindings: AppealHttpPresenterBindings,
) -> None:
    expected_handlers = {
        "open_appeal": PostgresOpenAppealHandler,
        "save_application_draft": PostgresSaveAppealDraftHandler,
        "submit_appeal": PostgresSubmitAppealHandler,
        "claim_appeal": PostgresClaimAppealHandler,
        "release_assignment": PostgresReleaseAppealAssignmentHandler,
        "save_review_draft": PostgresSaveAppealReviewDraftHandler,
        "decide_appeal": PostgresDecideAppealHandler,
    }
    runtime = bindings.projections
    if type(runtime) is not InternalSandboxAppealPostgresRuntime or any(
        type(getattr(bindings, name, None)) is not expected
        for name, expected in expected_handlers.items()
    ):
        raise TypeError("exact PostgreSQL Appeal HTTP bindings are unavailable")
    handlers = tuple(getattr(bindings, name) for name in expected_handlers)
    if any(
        handler._gateway is not runtime._command_gateway
        or handler._receipt_probe is not runtime._receipt_probe
        or handler._receipt_keyring is not runtime._receipt_keyring
        or handler._id_source is not dependencies.runtime_sources
        or handler._clock is not dependencies.runtime_sources
        for handler in handlers
    ) or (
        bindings.save_application_draft._sealed_text is not runtime._sealed_text
        or bindings.save_review_draft._sealed_text is not runtime._sealed_text
    ):
        raise TypeError("Appeal PostgreSQL command dependencies are miswired")

    pools = dependencies.pools
    applicant_reviewer = (pools.trust_self, pools.trust_appeal)
    providers = (
        runtime._command_gateway,
        runtime._receipt_probe,
        runtime._projections._read_gateway,
        runtime._sealed_text._store,
    )
    if any(
        (
            provider._applicant_connections,
            provider._reviewer_connections,
        )
        != applicant_reviewer
        for provider in providers
    ) or tuple(runtime._runtime_readiness._sources.values()) != applicant_reviewer:
        raise TypeError("Appeal PostgreSQL role identities are miswired")


def _validate_matching_dependencies(
    dependencies: InternalSandboxApiDependencies,
    bindings: MatchingHttpPresenterBindings,
) -> None:
    expected_handlers = {
        "respond_invitation": PostgresRespondInvitationHandler,
        "withdraw_invitation": PostgresWithdrawAcceptedInvitationHandler,
        "choose_creator": PostgresChooseCreatorHandler,
        "close_selection": PostgresCloseSelectionWithoutChoiceHandler,
        "create_invitation": PostgresCreateMatchingInvitationHandler,
        "publish_invitation": PostgresPublishMatchingInvitationHandler,
        "invalidate_attempt": PostgresInvalidateMatchingAttemptHandler,
    }
    runtime = dependencies.matching_runtime
    assignment_runtime = dependencies.matching_assignment_runtime
    review_runtime = dependencies.matching_review_runtime
    operational_service = dependencies.matching_operational_service
    projections = bindings.projections
    command_actors = bindings.command_actors
    reviewer_assignments = bindings.reviewer_assignments
    if (
        type(projections) is not PsycopgMatchingHttpProjectionAdapter
        or type(command_actors) is not PsycopgMatchingCommandActorResolver
        or type(reviewer_assignments) is not PsycopgMatchingReviewerAssignmentResolver
        or any(
            type(getattr(bindings, name, None)) is not expected
            for name, expected in expected_handlers.items()
        )
    ):
        raise TypeError("exact PostgreSQL Matching HTTP bindings are unavailable")
    public_handler_names = (
        "respond_invitation",
        "withdraw_invitation",
        "choose_creator",
        "close_selection",
    )
    reviewer_handler_names = (
        "create_invitation",
        "publish_invitation",
        "invalidate_attempt",
    )
    public_handlers = tuple(getattr(bindings, name) for name in public_handler_names)
    reviewer_handlers = tuple(
        getattr(bindings, name) for name in reviewer_handler_names
    )
    keys = getattr(projections, "_keys", None)
    if (
        getattr(projections, "_runtime", None) is not runtime
        or getattr(projections, "_review_runtime", None) is not review_runtime
        or getattr(command_actors, "_runtime", None) is not runtime
        or getattr(command_actors, "_review_runtime", None) is not review_runtime
        or getattr(reviewer_assignments, "_runtime", None) is not review_runtime
        or any(
            getattr(handler, "_runtime", None) is not runtime
            or getattr(handler, "_keys", None) is not keys
            or getattr(handler, "_id_source", None)
            is not dependencies.runtime_sources
            for handler in public_handlers
        )
        or any(
            getattr(handler, "_runtime", None) is not review_runtime
            or getattr(handler, "_keys", None) is not keys
            or getattr(handler, "_id_source", None)
            is not dependencies.runtime_sources
            for handler in reviewer_handlers
        )
        or getattr(operational_service, "_assignment_runtime", None)
        is not assignment_runtime
        or getattr(operational_service, "_review_runtime", None) is not review_runtime
        or getattr(operational_service, "_keys", None) is not keys
        or getattr(operational_service, "_id_source", None)
        is not dependencies.runtime_sources
        or any(
            getattr(handler, "_demand_hold", None)
            is not dependencies.editor_evidence._demand_safety_hold
            for handler in reviewer_handlers
        )
    ):
        raise TypeError("Matching PostgreSQL HTTP dependencies are miswired")
    settings = getattr(runtime, "_settings", None)
    assignment_gateway = getattr(assignment_runtime, "_gateway", None)
    review_gateway = getattr(review_runtime, "_gateway", None)
    if (
        not isinstance(settings, MatchingPostgresSettings)
        or getattr(runtime, "_creator_connections", None)
        is not dependencies.pools.matching_creator
        or getattr(runtime, "_selector_connections", None)
        is not dependencies.pools.matching_selector
        or settings.creator_role != "matching_creator"
        or settings.selector_role != "matching_selector"
        or getattr(assignment_gateway, "connections", None)
        is not dependencies.pools.matching_assignment
        or getattr(assignment_gateway, "role", None) != "matching_assignment"
        or not isinstance(
            getattr(assignment_gateway, "settings", None),
            MatchingOperationalPostgresSettings,
        )
        or getattr(review_gateway, "connections", None)
        is not dependencies.pools.matching_review
        or getattr(review_gateway, "role", None) != "matching_review"
        or not isinstance(
            getattr(review_gateway, "settings", None),
            MatchingOperationalPostgresSettings,
        )
    ):
        raise TypeError("Matching PostgreSQL role identities are miswired")


def _validate_dependencies(dependencies: InternalSandboxApiDependencies) -> None:
    pools = dependencies.pools
    bindings = dependencies.iam_presenter_bindings
    if dependencies.trust_http_bindings is not None:
        trust_bindings = dependencies.trust_http_bindings
        if (
            not isinstance(trust_bindings, TrustHttpPresenterBindings)
            or not _managed(trust_bindings.projections)
            or "memory" in type(trust_bindings.projections).__module__.lower()
        ):
            raise TypeError("durable Trust HTTP bindings are unavailable")
        _validate_trust_dependencies(dependencies, trust_bindings)
    appeal_bindings = dependencies.appeal_http_bindings
    if (
        not isinstance(appeal_bindings, AppealHttpPresenterBindings)
        or not _managed(appeal_bindings.projections)
        or "memory" in type(appeal_bindings.projections).__module__.lower()
    ):
        raise TypeError("durable Appeal HTTP bindings are unavailable")
    _validate_appeal_dependencies(dependencies, appeal_bindings)
    matching_bindings = dependencies.matching_http_bindings
    if "memory" in type(matching_bindings.projections).__module__.lower():
        raise TypeError("durable Matching HTTP bindings are unavailable")
    _validate_matching_dependencies(dependencies, matching_bindings)
    expected_binding_types = {
        "begin_oidc_authorization": PostgresBeginOidcAuthorizationHandler,
        "complete_oidc_authorization": PostgresCompleteOidcAuthenticationHandler,
        "get_session_bootstrap": GetSessionBootstrapHandler,
        "get_policy_bundle": GetPolicyBundleHandler,
        "get_me": GetMeHandler,
        "list_my_sessions": ListMySessionsHandler,
        "inspect_access_invitation": InspectAccessInvitationHandler,
        "accept_access_invitation": PostgresAcceptOrganizationAccessInvitationHandler,
        "get_organization_summary": GetOrganizationSummaryHandler,
        "update_organization_public_name": (
            PostgresUpdateOrganizationPublicNameHandler
        ),
        "list_organization_access_invitations": (
            ListOrganizationAccessInvitationsHandler
        ),
        "issue_organization_access_invitation": (
            PostgresIssueOrganizationAccessInvitationHandler
        ),
        "list_organization_memberships": ListOrganizationMembershipsHandler,
        "revoke_access_invitation": PostgresRevokeAccessInvitationHandler,
        "suspend_membership": PostgresSuspendMembershipHandler,
        "resume_membership": PostgresResumeMembershipHandler,
        "revoke_membership": PostgresRevokeMembershipHandler,
        "accept_current_policies": PostgresAcceptCurrentPoliciesHandler,
        "revoke_my_session": PostgresRevokeOwnedSessionHandler,
    }
    for field in fields(bindings):
        value = getattr(bindings, field.name)
        if field.name in _OPEN_IAM_BINDINGS:
            if (
                field.name == "list_my_sessions"
                and type(value) is not ListMySessionsHandler
            ) or (
                field.name != "list_my_sessions"
                and not isinstance(value, expected_binding_types[field.name])
            ):
                raise TypeError("required PostgreSQL IAM handler is unavailable")
        elif value is not None:
            raise TypeError("unreviewed IAM production handler is not open")

    begin = bindings.begin_oidc_authorization
    complete = bindings.complete_oidc_authorization
    oidc_uow = getattr(begin, "_uow", None)
    if (
        not isinstance(oidc_uow, PsycopgOidcAuthenticationUnitOfWork)
        or getattr(complete, "_uow", None) is not oidc_uow
        or getattr(oidc_uow, "_connections", None) is not pools.iam_onboarding
    ):
        raise TypeError("OIDC PostgreSQL unit of work is miswired")
    provider_readiness = dependencies.oidc_provider_readiness
    provider = getattr(provider_readiness, "_provider", None)
    policy = getattr(provider_readiness, "_security_policy", None)
    if (
        getattr(begin, "_provider", None) is not provider
        or getattr(complete, "_provider", None) is not provider
        or getattr(begin, "_security_policy", None) is not policy
        or getattr(complete, "_security_policy", None) is not policy
    ):
        raise TypeError("OIDC provider binding is miswired")

    session_handler = bindings.get_session_bootstrap
    policy_bundle_handler = bindings.get_policy_bundle
    me_handler = bindings.get_me
    read_repository = getattr(session_handler, "_repository", None)
    paged_read_handlers = (
        bindings.list_my_sessions,
        bindings.list_organization_access_invitations,
        bindings.list_organization_memberships,
    )
    organization_read_handlers = (
        bindings.get_organization_summary,
        bindings.list_organization_access_invitations,
        bindings.list_organization_memberships,
        bindings.inspect_access_invitation,
    )
    if (
        not isinstance(read_repository, PsycopgIamReadModelRepository)
        or getattr(policy_bundle_handler, "_repository", None) is not read_repository
        or getattr(me_handler, "_repository", None) is not read_repository
        or getattr(bindings.list_my_sessions, "_repository", None)
        is not read_repository
        or any(
            getattr(handler, "_repository", None) is not read_repository
            for handler in organization_read_handlers
        )
        or getattr(read_repository, "_app_connections", None) is not pools.iam_app
        or getattr(read_repository, "_onboarding_connections", None)
        is not pools.iam_onboarding
    ):
        raise TypeError("IAM PostgreSQL read model is miswired")
    read_cursor_codec = getattr(bindings.list_my_sessions, "_cursor_codec", None)
    if (
        type(read_cursor_codec) is not HmacIamReadCursorCodec
        or any(
            getattr(handler, "_cursor_codec", None) is not read_cursor_codec
            for handler in paged_read_handlers
        )
    ):
        raise TypeError("IAM PostgreSQL read cursor codec is miswired")

    if (
        getattr(begin, "_invitation_reads", None) is not read_repository
        or getattr(begin, "_invitation_capabilities", None)
        is not getattr(bindings.inspect_access_invitation, "_invitation_capabilities", None)
        or getattr(begin, "_session_security", None) is not dependencies.session_security
        or getattr(complete, "_session_security", None)
        is not dependencies.session_security
    ):
        raise TypeError("OIDC invitation STEP_UP bridge is miswired")

    accept_handler = bindings.accept_access_invitation
    accept_uow = getattr(accept_handler, "_uow_factory", None)
    accept_scope = getattr(accept_handler, "_scope_resolver", None)
    accept_hold = getattr(accept_handler, "_safety_hold", None)
    accept_keyring = getattr(accept_handler, "_keyring", None)
    if (
        not isinstance(accept_uow, PsycopgAcceptAccessInvitationUnitOfWorkFactory)
        or accept_uow.connections is not pools.iam_onboarding
        or not isinstance(accept_scope, PsycopgOrganizationAcceptScopeResolver)
        or accept_scope.connections is not pools.iam_onboarding
        or not isinstance(accept_hold, InternalSandboxInvitationSafetyHold)
        or not isinstance(accept_keyring, OrganizationAcceptKeyring)
        or accept_keyring.session_keyring is not getattr(
            dependencies.session_security, "_keyring", None
        )
    ):
        raise TypeError("PostgreSQL invitation Accept bridge is miswired")

    organization_write_handlers = (
        bindings.issue_organization_access_invitation,
        bindings.revoke_access_invitation,
        bindings.suspend_membership,
        bindings.resume_membership,
        bindings.revoke_membership,
    )
    organization_uow = getattr(organization_write_handlers[0], "_uow_factory", None)
    target_resolver = getattr(organization_write_handlers[1], "_resolver", None)
    organization_keys = getattr(organization_write_handlers[0], "_keys", None)
    if (
        not isinstance(organization_uow, PsycopgOrganizationAdminUnitOfWorkFactory)
        or organization_uow.connections is not pools.iam_app
        or not isinstance(target_resolver, PsycopgOrganizationAdminTargetResolver)
        or target_resolver.connections is not pools.iam_app
        or not isinstance(organization_keys, OrganizationAdminKeys)
        or accept_keyring.receipt_keys is not organization_keys
        or getattr(accept_handler, "_clock", None)
        is not dependencies.runtime_sources
        or getattr(accept_handler, "_ids", None)
        is not dependencies.runtime_sources
        or getattr(accept_handler, "_secrets", None)
        is not dependencies.runtime_sources
        or any(
            getattr(handler, "_uow_factory", None) is not organization_uow
            or getattr(handler, "_keys", None) is not organization_keys
            or (
                index > 0
                and getattr(handler, "_resolver", None) is not target_resolver
            )
            or getattr(handler, "_clock", None) is not dependencies.runtime_sources
            or getattr(handler, "_ids", None) is not dependencies.runtime_sources
            for index, handler in enumerate(organization_write_handlers)
        )
    ):
        raise TypeError("PostgreSQL organization administration is miswired")

    public_name_handler = bindings.update_organization_public_name
    public_name_uow = getattr(public_name_handler, "_uow_factory", None)
    if (
        not isinstance(
            public_name_uow,
            PsycopgOrganizationPublicNameUnitOfWorkFactory,
        )
        or public_name_uow.connections is not pools.iam_app
        or public_name_uow.event_validator is not organization_uow.event_validator
        or public_name_uow.response_validator
        is not organization_uow.response_validator
        or getattr(public_name_handler, "_keys", None) is not organization_keys
        or getattr(public_name_handler, "_clock", None)
        is not dependencies.runtime_sources
        or getattr(public_name_handler, "_ids", None)
        is not dependencies.runtime_sources
    ):
        raise TypeError("PostgreSQL organization public-name command is miswired")

    policy_handler = bindings.accept_current_policies
    policy_scope_resolver = getattr(policy_handler, "_scope_resolver", None)
    policy_uow = getattr(policy_handler, "_uow_factory", None)
    policy_keys = getattr(policy_handler, "_keys", None)
    policy_validator = getattr(policy_uow, "event_validator", None)
    if (
        not isinstance(
            policy_scope_resolver,
            PsycopgPolicyAcceptanceScopeResolver,
        )
        or policy_scope_resolver.connections is not pools.iam_app
        or not isinstance(policy_uow, PsycopgPolicyConsentCommandUnitOfWorkFactory)
        or policy_uow.connections is not pools.iam_app
        or not isinstance(policy_validator, IamPostgresContractValidator)
        or policy_uow.response_validator is not policy_validator
        or not isinstance(policy_keys, IamReceiptPolicyKeys)
        or getattr(policy_handler, "_clock", None) is not dependencies.runtime_sources
        or getattr(policy_handler, "_id_source", None)
        is not dependencies.runtime_sources
    ):
        raise TypeError("PostgreSQL policy acceptance is miswired")
    logout_handler = bindings.revoke_my_session
    logout_uow = getattr(logout_handler, "_uow_factory", None)
    if (
        not isinstance(
            logout_uow,
            PsycopgOwnedSessionRevocationUnitOfWorkFactory,
        )
        or logout_uow.connections is not pools.iam_app
        or getattr(logout_handler, "_keys", None) is not policy_keys
        or getattr(logout_handler, "_clock", None)
        is not dependencies.runtime_sources
        or getattr(logout_handler, "_id_source", None)
        is not dependencies.runtime_sources
    ):
        raise TypeError("PostgreSQL owned Session revocation is miswired")
    if (
        getattr(dependencies.session_security, "_connections", None)
        is not pools.iam_session_authenticator
        or getattr(dependencies.editor_principal_resolver, "_connections", None)
        is not pools.iam_app
    ):
        raise TypeError("IAM authentication pool binding is miswired")

    account_admin = dependencies.account_admin_service
    account_repository = getattr(account_admin, "_repo", None)
    account_lifecycle = getattr(account_admin, "_lifecycle", None)
    account_keys = getattr(account_admin, "_keys", None)
    iam_validator = getattr(account_lifecycle, "event_validator", None)
    if (
        not isinstance(
            account_repository,
            PsycopgInternalSandboxAccountAdminRepository,
        )
        or account_repository.connections is not pools.iam_app
        or not isinstance(
            account_lifecycle,
            PsycopgPlatformUserLifecycleUnitOfWorkFactory,
        )
        or account_lifecycle.connections is not pools.iam_app
        or not isinstance(iam_validator, IamPostgresContractValidator)
        or account_lifecycle.response_validator is not iam_validator
        or not isinstance(account_keys, PlatformUserAdminKeys)
        or getattr(account_admin, "_clock", None) is not dependencies.runtime_sources
        or getattr(account_admin, "_ids", None) is not dependencies.runtime_sources
        or policy_validator is not iam_validator
        or policy_keys.idempotency_key is not account_keys.idempotency_key
        or policy_keys.payload_hash_key is not account_keys.payload_hash_key
        or policy_keys.idempotency_key_id != account_keys.idempotency_key_id
        or policy_keys.payload_hash_key_id != account_keys.payload_hash_key_id
    ):
        raise TypeError("PostgreSQL account administration is miswired")

    service = dependencies.editor_service
    repository = getattr(service, "_repo", None)
    editor_keys = getattr(service, "_keys", None)
    completed_verify_receipts = getattr(
        service, "_completed_verify_receipts", None
    )
    completed_profile_lifecycle_receipts = getattr(
        service, "_completed_profile_lifecycle_receipts", None
    )
    completed_profile_idempotency_keys = getattr(
        completed_profile_lifecycle_receipts, "_idempotency_keys", None
    )
    completed_profile_payload_keys = getattr(
        completed_profile_lifecycle_receipts, "_payload_hash_keys", None
    )
    completed_idempotency_keys = getattr(
        completed_verify_receipts, "_idempotency_keys", None
    )
    completed_payload_keys = getattr(
        completed_verify_receipts, "_payload_hash_keys", None
    )
    if (
        not isinstance(repository, PsycopgEditorRepository)
        or getattr(service, "_authorities", None)
        is not dependencies.editor_authorities
        or getattr(service, "_evidence", None) is not dependencies.editor_evidence
        or not isinstance(editor_keys, EditorPostgresKeys)
        or getattr(service, "_clock", None) is not dependencies.runtime_sources
        or getattr(service, "_review_queue", None)
        is not dependencies.editor_review_queue
        or not isinstance(
            completed_profile_lifecycle_receipts,
            PsycopgProfileCompletedLifecycleReceiptProbe,
        )
        or completed_profile_lifecycle_receipts._connections is not pools.profile_app
        or type(completed_profile_idempotency_keys) is not tuple
        or not 1 <= len(completed_profile_idempotency_keys) <= 4
        or type(completed_profile_payload_keys) is not tuple
        or not 1 <= len(completed_profile_payload_keys) <= 4
        or completed_profile_idempotency_keys[0][0]
        != editor_keys.profile_idempotency_key_id
        or completed_profile_idempotency_keys[0][1]
        is not editor_keys.profile_idempotency_key
        or completed_profile_payload_keys[0][0]
        != editor_keys.profile_payload_key_id
        or completed_profile_payload_keys[0][1]
        is not editor_keys.profile_payload_key
        or len(
            {
                key_id
                for key_id, _material in completed_profile_idempotency_keys
            }
        )
        != len(completed_profile_idempotency_keys)
        or len(
            {key_id for key_id, _material in completed_profile_payload_keys}
        )
        != len(completed_profile_payload_keys)
        or {
            key_id for key_id, _material in completed_profile_idempotency_keys
        }.intersection(
            key_id for key_id, _material in completed_profile_payload_keys
        )
        or any(
            not isinstance(material, (bytes, bytearray))
            or len(material) < 32
            or not any(material)
            for _key_id, material in (
                completed_profile_idempotency_keys
                + completed_profile_payload_keys
            )
        )
        or len(
            {
                bytes(material)
                for _key_id, material in (
                    completed_profile_idempotency_keys
                    + completed_profile_payload_keys
                )
            }
        )
        != len(completed_profile_idempotency_keys) + len(
            completed_profile_payload_keys
        )
        or not isinstance(
            completed_verify_receipts,
            PsycopgDemandCompletedVerifyReceiptProbe,
        )
        or not callable(
            getattr(completed_verify_receipts, "read_completed_release", None)
        )
        or completed_verify_receipts._connections is not pools.demand_review
        or type(completed_idempotency_keys) is not tuple
        or not 1 <= len(completed_idempotency_keys) <= 4
        or type(completed_payload_keys) is not tuple
        or not 1 <= len(completed_payload_keys) <= 4
        or completed_idempotency_keys[0][0]
        != editor_keys.demand_idempotency_key_id
        or completed_idempotency_keys[0][1]
        is not editor_keys.demand_idempotency_key
        or completed_payload_keys[0][0] != editor_keys.demand_payload_key_id
        or completed_payload_keys[0][1] is not editor_keys.demand_payload_key
        or len({key_id for key_id, _material in completed_idempotency_keys})
        != len(completed_idempotency_keys)
        or len({key_id for key_id, _material in completed_payload_keys})
        != len(completed_payload_keys)
        or {
            key_id for key_id, _material in completed_idempotency_keys
        }.intersection(
            key_id for key_id, _material in completed_payload_keys
        )
        or any(
            not isinstance(material, (bytes, bytearray))
            or len(material) < 32
            or not any(material)
            for _key_id, material in (
                completed_idempotency_keys + completed_payload_keys
            )
        )
        or len(
            {
                bytes(material)
                for _key_id, material in (
                    completed_idempotency_keys + completed_payload_keys
                )
            }
        )
        != len(completed_idempotency_keys) + len(completed_payload_keys)
    ):
        raise TypeError("PostgreSQL editor service is miswired")

    profile_uow = getattr(repository, "_profile_uow", None)
    profile_validator = getattr(profile_uow, "event_validator", None)
    if (
        not isinstance(profile_uow, PsycopgCreatorProfileUnitOfWorkFactory)
        or profile_uow.connections is not pools.profile_app
        or not isinstance(profile_validator, ProfilePostgresContractValidator)
        or profile_uow.response_validator is not profile_validator
        or getattr(repository, "_profile_reads", None) is not pools.profile_app
    ):
        raise TypeError("Creator Profile PostgreSQL repository is miswired")

    demand_uows = getattr(repository, "_demand_uows", None)
    if not isinstance(demand_uows, dict) or frozenset(demand_uows) != frozenset(
        (
            DemandPostgresOperation.CREATE,
            DemandPostgresOperation.CREATE_VERSION,
            DemandPostgresOperation.SUBMIT,
            DemandPostgresOperation.CANCEL_OWNER,
            DemandPostgresOperation.REQUEST_CHANGES,
            DemandPostgresOperation.VERIFY,
            DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT,
        )
    ):
        raise TypeError("Demand PostgreSQL operation dispatch is miswired")
    demand_owner_uow = demand_uows[DemandPostgresOperation.CREATE]
    demand_review_uow = demand_uows[DemandPostgresOperation.REQUEST_CHANGES]
    demand_validator = getattr(demand_owner_uow, "event_validator", None)
    if (
        not isinstance(demand_owner_uow, PsycopgDemandUnitOfWorkFactory)
        or demand_uows[DemandPostgresOperation.CREATE_VERSION] is not demand_owner_uow
        or demand_uows[DemandPostgresOperation.SUBMIT] is not demand_owner_uow
        or demand_uows[DemandPostgresOperation.CANCEL_OWNER] is not demand_owner_uow
        or demand_owner_uow.connections is not pools.demand_self
        or not isinstance(demand_validator, DemandPostgresContractValidator)
        or demand_owner_uow.response_validator is not demand_validator
        or not isinstance(demand_review_uow, PsycopgDemandUnitOfWorkFactory)
        or demand_review_uow is demand_owner_uow
        or demand_review_uow.connections is not pools.demand_review
        or demand_uows[DemandPostgresOperation.VERIFY] is not demand_review_uow
        or demand_uows[DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT]
        is not demand_review_uow
        or demand_review_uow.event_validator is not demand_validator
        or demand_review_uow.response_validator is not demand_validator
        or getattr(repository, "_demand_owner_reads", None) is not pools.demand_self
        or getattr(repository, "_demand_review_reads", None) is not pools.demand_review
    ):
        raise TypeError("Demand PostgreSQL repository is miswired")
    review_queue = dependencies.editor_review_queue
    if (
        getattr(review_queue, "_connections", None) is not pools.demand_review
        or getattr(review_queue, "_event_validator", None) is not demand_validator
    ):
        raise TypeError("Demand review queue PostgreSQL adapter is miswired")
    finance_service = dependencies.finance_funding_service
    finance_keys = getattr(finance_service, "_keys", None)
    if (
        getattr(finance_service, "_connections", None) is not pools.demand_finance
        or getattr(finance_keys, "id_key", None) is not editor_keys.id_key
        or getattr(finance_keys, "idempotency_key", None)
        is not editor_keys.demand_idempotency_key
        or getattr(finance_keys, "payload_key", None)
        is not editor_keys.demand_payload_key
        or getattr(finance_keys, "idempotency_key_id", None)
        != editor_keys.demand_idempotency_key_id
        or getattr(finance_keys, "payload_key_id", None)
        != editor_keys.demand_payload_key_id
    ):
        raise TypeError("Finance funding PostgreSQL adapter is miswired")
    authorities = dependencies.editor_authorities
    marker_resolver = getattr(authorities, "_markers", None)
    authority_pools = (
        getattr(authorities, "_profile_connections", None),
        getattr(authorities, "_demand_owner_connections", None),
        getattr(authorities, "_demand_reviewer_connections", None),
    )
    if (
        not isinstance(marker_resolver, PsycopgAuthorityMarkerResolver)
        or authority_pools
        != (pools.profile_app, pools.demand_self, pools.demand_review)
        or (
            getattr(marker_resolver, "_profile_connections", None),
            getattr(marker_resolver, "_demand_owner_connections", None),
            getattr(marker_resolver, "_demand_reviewer_connections", None),
        )
        != authority_pools
    ):
        raise TypeError("PostgreSQL editor authority provider is miswired")
    for provider, methods in (
        (dependencies.editor_authorities, _AUTHORITY_METHODS),
        (dependencies.editor_evidence, _EVIDENCE_METHODS),
    ):
        if not _managed(provider) or any(
            not callable(getattr(provider, method, None)) for method in methods
        ):
            raise TypeError("editor authority or evidence provider is unavailable")

    requirements = tuple(
        getattr(item, "_requirement", None) for item in dependencies.schema_readiness
    )
    if tuple(getattr(item, "component", None) for item in requirements) != (
        "iam",
        "profile",
        "demand",
        "trust",
        "matching",
    ):
        raise TypeError("schema compatibility components are miswired")
    demand_requirement = requirements[2]
    if (
        tuple(key_id for key_id, _material in completed_idempotency_keys)
        != demand_requirement.expected_retained_idempotency_key_ids
        or tuple(key_id for key_id, _material in completed_payload_keys)
        != demand_requirement.expected_retained_payload_key_ids
    ):
        raise TypeError("Demand Verify replay readiness is miswired")
    expected_schema_pools = (
        pools.iam_app,
        pools.profile_app,
        pools.demand_self,
        pools.trust_self,
        pools.matching_creator,
    )
    if any(
        getattr(readiness, "_pool", None) is not expected_pool
        for readiness, expected_pool in zip(
            dependencies.schema_readiness, expected_schema_pools
        )
    ):
        raise TypeError("schema compatibility pool is miswired")
    if getattr(dependencies.seed_readiness, "_pool", None) is not pools.profile_app:
        raise TypeError("internal sandbox seed readiness pool is miswired")

    resources = (
        (dependencies.runtime_secrets,)
        + pools.values()
        + dependencies.schema_readiness
        + (
            dependencies.seed_readiness,
            dependencies.editor_review_queue,
            dependencies.finance_funding_service,
            dependencies.editor_authorities,
            dependencies.editor_evidence,
            dependencies.local_server_dependency_readiness,
            dependencies.oidc_provider_readiness,
            dependencies.session_security,
            dependencies.origin_policy,
            dependencies.rate_limiter,
            dependencies.telemetry,
        )
        + (
            ()
            if dependencies.trust_http_bindings is None
            else (dependencies.trust_http_bindings.projections,)
        )
        + (
            ()
            if dependencies.appeal_http_bindings is None
            else (dependencies.appeal_http_bindings.projections,)
        )
    )
    if any(not _managed(resource) for resource in resources) or len(
        {id(resource) for resource in resources}
    ) != len(resources):
        raise TypeError("internal sandbox managed resources are invalid")


__all__ = [
    "InternalSandboxApiDependencies",
    "InternalSandboxApiPools",
    "LocalServerDependencyReadiness",
    "OidcProviderReadiness",
    "build_internal_sandbox_api",
]
