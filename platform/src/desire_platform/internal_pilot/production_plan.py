"""Closed production dependency factory for the internal sandbox API.

Only one explicit environment pointer is accepted.  The pointed deployment
bundle then names the non-secret runtime configuration, secret manifest and
secret root.  This module never imports the deployment credential installer,
never accepts a DSN, and never substitutes an in-memory or permissive adapter.
"""

from __future__ import annotations

from datetime import timedelta
import hashlib
import hmac
from importlib import resources
from pathlib import Path
import sys
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, TextIO, Tuple

import psycopg

from desire_platform.creator_profile.adapters.postgres import (
    PsycopgCreatorProfileUnitOfWorkFactory,
)
from desire_platform.creator_profile.adapters.postgres.migrations import (
    PROFILE_REQUIRED_IAM_SCHEMA_VERSION,
    PROFILE_REVIEWED_MANIFEST_SHA256,
    PROFILE_SCHEMA_HEAD_VERSION,
)
from desire_platform.demand.adapters.postgres import (
    DemandPostgresOperation,
    PsycopgDemandRuleCatalog,
    PsycopgDemandUnitOfWorkFactory,
)
from desire_platform.demand.adapters.postgres.migrations import (
    DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
    DEMAND_REVIEWED_MANIFEST_SHA256,
    DEMAND_SCHEMA_HEAD_VERSION,
)
from desire_platform.http import (
    ExactOriginPolicy,
    ExactOriginPolicySettings,
    IamHttpPresenterBindings,
    PsycopgIamSessionSecurity,
    SessionSecuritySettings,
)
from desire_platform.identity_access.adapters.oidc import (
    ClosedOidcProvider,
    OidcProviderConfiguration,
    PyJwtOidcTokenVerifier,
    StdlibOidcJsonTransport,
)
from desire_platform.identity_access.adapters.pinned_oidc_transport import (
    PinnedPublicIpOidcJsonTransport,
)
from desire_platform.identity_access.adapters.postgres.authority_markers import (
    PsycopgAuthorityMarkerResolver,
)
from desire_platform.identity_access.adapters.postgres.editor_principal import (
    PsycopgEditorPrincipalResolver,
)
from desire_platform.identity_access.adapters.postgres.migrations import (
    IAM_REVIEWED_MANIFEST_SHA256,
    IAM_SCHEMA_HEAD_VERSION,
)
from desire_platform.identity_access.adapters.postgres.oidc_authentication import (
    PsycopgOidcAuthenticationUnitOfWork,
)
from desire_platform.identity_access.adapters.postgres.oidc_bundle import (
    build_postgres_iam_authentication_bundle,
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
    MATCHING_REQUIRED_IAM_SCHEMA_VERSION,
    MATCHING_REVIEWED_MANIFEST_SHA256,
    MATCHING_SCHEMA_HEAD_VERSION,
    MatchingOperationalPostgresSettings,
    MatchingPostgresSettings,
    PsycopgMatchingAssignmentRuntime,
    PsycopgMatchingReviewRuntime,
    PsycopgMatchingRuntime,
)
from desire_platform.runtime.artifacts import (
    PackageArtifactLocation,
    PackageArtifactVerifier,
)
from desire_platform.runtime.config import (
    ArtifactRequirement,
    KeyRequirement,
    RuntimeConfiguration,
    parse_runtime_config,
)
from desire_platform.trust_safety.adapters.postgres import (
    AppealPostgresGatewaySettings,
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
    PsycopgTrustCommandGateway,
    PsycopgTrustDemandSafetyHoldProvider,
    PsycopgTrustHttpProjectionAdapter,
    PsycopgTrustOutcomeEvidenceProvider,
    PsycopgTrustReadGateway,
    PsycopgTrustReceiptProbe,
    PsycopgTrustRestrictedTextStore,
    PsycopgTrustRuntimeReadiness,
    PsycopgTrustSealedNoteProvider,
    TrustPostgresGatewaySettings,
    TrustPostgresReceiptKey,
    TrustPostgresReceiptKeyring,
    TrustOwnedReportCursorKey,
    TrustOwnedReportCursorKeyring,
    TrustSealedTextKey,
    TrustSealedTextKeyring,
    build_appeal_postgres_command_handlers,
    build_trust_postgres_command_handlers,
)
from desire_platform.trust_safety.adapters.postgres.migrations import (
    TRUST_REQUIRED_DEMAND_CONTRACT_SHA256,
    TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
    TRUST_REQUIRED_IAM_CONTRACT_SHA256,
    TRUST_REQUIRED_IAM_SCHEMA_VERSION,
    TRUST_REVIEWED_MANIFEST_SHA256,
    TRUST_SCHEMA_HEAD_VERSION,
    TrustContractSources,
    combined_contract_sha256 as trust_combined_contract_sha256,
)
from desire_platform.trust_safety.appeal_http import AppealHttpPresenterBindings
from desire_platform.trust_safety.http import TrustHttpPresenterBindings

from .api_composition import (
    InternalSandboxApiDependencies,
    InternalSandboxApiPools,
    LocalServerDependencyReadiness,
    OidcProviderReadiness,
    build_internal_sandbox_api,
)
from .appeal_runtime import (
    InternalSandboxAppealPostgresRuntime,
    PsycopgAppealRuntimeReadiness,
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
from .deployment_config import (
    InternalSandboxDeploymentConfiguration,
    OIDC_NETWORK_BINDING_PINNED_PUBLIC_IP,
    OIDC_NETWORK_BINDING_SYSTEM_DNS_SYNTHETIC,
    _read_regular_config_file,
    load_internal_sandbox_deployment_config_pointer,
)
from .editor import (
    EditorPostgresKeys,
    PostgresEditorAuthorityProvider,
    PostgresEditorService,
    PsycopgDemandCompletedVerifyReceiptProbe,
    PsycopgDemandReviewQueue,
    PsycopgEditorRepository,
    PsycopgProfileCompletedLifecycleReceiptProbe,
)
from .editor.sandbox_evidence import InternalSandboxEditorEvidenceProvider
from .finance_funding import FinanceFundingKeys, PsycopgFinanceFundingService
from .matching_postgres import (
    MatchingPostgresHttpKeys,
    MatchingPostgresOperationalHttpService,
    build_matching_postgres_http_bindings,
)
from .postgres_pool import PsycopgRoleBoundPoolFactory
from .policy_acceptance import (
    IamReceiptPolicyKeys,
    PostgresAcceptCurrentPoliciesHandler,
    PsycopgPolicyAcceptanceScopeResolver,
)
from .current_session_logout import PostgresRevokeOwnedSessionHandler
from .runtime_adapters import (
    InternalSandboxRateLimiter,
    InternalSandboxRateLimitSettings,
    JsonLineHttpTelemetry,
    SecureRuntimeSources,
)
from .runtime_crypto import (
    AesGcmProtocolSecretBox,
    HmacIamReadCursorCodec,
    HmacRecipientBinding,
    HmacRuntimeKeyring,
    PostgresSessionBootstrapCsrfTokens,
    RuntimeKeyMaterial,
)
from .schema_readiness import (
    PostgresSchemaCompatibilityReadiness,
    SchemaCompatibilityRequirement,
)
from .seed_readiness import PostgresInternalSandboxSeedReadiness
from .secrets import (
    FileSecretCarrier,
    FileSecretManifestEntry,
    FilesystemSecretProvider,
    ManagedRuntimeSecrets,
    parse_file_secret_manifest,
)
from .synthetic_seed import (
    INTERNAL_SANDBOX_SYNTHETIC_SEED_SHA256,
    InternalSandboxSyntheticSeedError,
    InternalSandboxSyntheticSeedPlan,
    load_internal_sandbox_synthetic_seed,
)
from .trust_runtime import InternalSandboxTrustPostgresRuntime


INTERNAL_SANDBOX_CAPABILITY_ROLES: Tuple[Tuple[str, str], ...] = (
    ("IAM_APP", "iam_app"),
    ("IAM_SESSION_AUTHENTICATOR", "iam_session_authenticator"),
    ("IAM_ONBOARDING", "iam_onboarding"),
    ("PROFILE_APP", "profile_app"),
    ("DEMAND_SELF", "demand_self"),
    ("DEMAND_REVIEW", "demand_review"),
    ("DEMAND_FINANCE", "demand_finance"),
    ("TRUST_SELF", "trust_self"),
    ("TRUST_OFFICER", "trust_officer"),
    ("TRUST_APPEAL", "trust_appeal"),
    ("TRUST_DECISION", "trust_decision"),
    ("MATCHING_CREATOR", "matching_creator"),
    ("MATCHING_SELECTOR", "matching_selector"),
    ("MATCHING_ASSIGNMENT", "matching_assignment"),
    ("MATCHING_REVIEW", "matching_review"),
)

# The background Matching runtime is a separate process and receives only
# these role-bound credentials.  ``TRUST_DECISION`` is intentionally shared
# with the API because both processes call the same narrow, read-only safety
# decision program; none of the four worker/coordinator credentials is mounted
# into the API process.
INTERNAL_SANDBOX_MATCHING_RUNTIME_CAPABILITY_ROLES: Tuple[
    Tuple[str, str], ...
] = (
    ("DEMAND_MATCHING", "demand_matching"),
    ("PROFILE_MATCHER", "profile_matcher"),
    ("TRUST_DECISION", "trust_decision"),
    ("MATCHING_WORKER", "matching_worker"),
    ("MATCHING_COORDINATOR", "matching_coordinator"),
)

INTERNAL_SANDBOX_ONLINE_CAPABILITY_ROLES: Tuple[Tuple[str, str], ...] = (
    INTERNAL_SANDBOX_CAPABILITY_ROLES
    + tuple(
        item
        for item in INTERNAL_SANDBOX_MATCHING_RUNTIME_CAPABILITY_ROLES
        if item not in INTERNAL_SANDBOX_CAPABILITY_ROLES
    )
)

INTERNAL_SANDBOX_KEY_PURPOSES: Tuple[str, ...] = (
    "OIDC_STATE",
    "OIDC_BROWSER_BINDING",
    "OIDC_NONCE",
    "SESSION_HANDLE",
    "CSRF",
    "OIDC_PROTOCOL_AEAD",
    "OIDC_SUBJECT_DIGEST",
    "OIDC_RECIPIENT_BINDING",
    "OIDC_CLIENT_SECRET",
    "EDITOR_ID_DERIVATION",
    "PROFILE_IDEMPOTENCY",
    "PROFILE_PAYLOAD_HASH",
    "DEMAND_IDEMPOTENCY",
    "DEMAND_PAYLOAD_HASH",
    "DEMAND_CLIENT_REFERENCE",
    "MATCHING_IDEMPOTENCY",
    "MATCHING_PAYLOAD_HASH",
    "MATCHING_READ_CURSOR",
    "PLATFORM_USER_IDEMPOTENCY",
    "PLATFORM_USER_PAYLOAD_HASH",
    "ACCESS_INVITATION_TOKEN",
    "IAM_READ_CURSOR",
    "TRUST_IDEMPOTENCY",
    "TRUST_PAYLOAD_HASH",
    "TRUST_SEALED_NOTE",
    "TRUST_REPORT_CURSOR",
)

INTERNAL_SANDBOX_MATCHING_RUNTIME_KEY_PURPOSES: Tuple[str, ...] = (
    "MATCHING_WORKER_IDEMPOTENCY",
    "MATCHING_WORKER_PAYLOAD_HASH",
    "MATCHING_WORKER_LEASE_DIGEST",
    "MATCHING_COORDINATOR_IDEMPOTENCY",
    "MATCHING_COORDINATOR_PAYLOAD_HASH",
    "MATCHING_COORDINATOR_LEASE_DIGEST",
)

INTERNAL_SANDBOX_DEMAND_IDEMPOTENCY_KEY_ID = "demand-idempotency-2026-01"
INTERNAL_SANDBOX_DEMAND_PAYLOAD_KEY_ID = "demand-payload-2026-01"
INTERNAL_SANDBOX_DEMAND_IDEMPOTENCY_KEY_IDS = (
    INTERNAL_SANDBOX_DEMAND_IDEMPOTENCY_KEY_ID,
    "demand-idempotency-retained-2025-12",
)
INTERNAL_SANDBOX_DEMAND_PAYLOAD_KEY_IDS = (
    INTERNAL_SANDBOX_DEMAND_PAYLOAD_KEY_ID,
    "demand-payload-retained-2025-12",
)
INTERNAL_SANDBOX_TRUST_IDEMPOTENCY_KEY_ID = "trust-idempotency-2026-01"
INTERNAL_SANDBOX_TRUST_PAYLOAD_KEY_ID = "trust-payload-2026-01"
INTERNAL_SANDBOX_TRUST_SEALED_NOTE_KEY_ID = "trust-sealed-note-v1"
INTERNAL_SANDBOX_TRUST_REPORT_CURSOR_KEY_ID = "trust-report-cursor-2026-01"
INTERNAL_SANDBOX_MATCHING_IDEMPOTENCY_KEY_ID = "matching-idempotency-v1"
INTERNAL_SANDBOX_MATCHING_PAYLOAD_KEY_ID = "matching-payload-v1"
INTERNAL_SANDBOX_MATCHING_READ_CURSOR_KEY_ID = "matching-read-cursor-v1"

INTERNAL_SANDBOX_ARTIFACT_REQUIREMENTS: Tuple[ArtifactRequirement, ...] = (
    ArtifactRequirement(
        "iam-openapi-v1",
        "26ffd8243c0baa2580d21e8878897ed0f13aa61fd9ba468cca8edf1fe277477c",
    ),
    ArtifactRequirement(
        "iam-events-v1",
        "6af7e75f738bfeef9aeed0ac8e84da782485c1a42e1c937c9d51e66884bad934",
    ),
    ArtifactRequirement(
        "profile-openapi-v1",
        "f3ef514855c26d6fa058da6c776124b089ac2d7d662fedf2503c82e7800537e8",
    ),
    ArtifactRequirement(
        "profile-events-v1",
        "9dd6287bf3bef84c550dffad9d49d580ea8b0d7ff718702ead49f3f94c518ac8",
    ),
    ArtifactRequirement(
        "profile-domain-v1",
        "9b8ea984dab8c7a31a213c22e6341947316651529f71a9a90e3989a8f22db935",
    ),
    ArtifactRequirement(
        "demand-openapi-v1",
        "046561ae51d147e8df3b8fcf0b61f1dd922efe452175e63f128a937e8f11c4ff",
    ),
    ArtifactRequirement(
        "demand-events-v1",
        "46631be37cb70aea771d2103e1fe39dc39f3f4303239ae1dc6e55fa946d1059c",
    ),
    ArtifactRequirement(
        "demand-domain-v1",
        "4a3316ca66f58e92d23b946226b235578ad77e247f92f72863aa8f76c5b5c631",
    ),
    ArtifactRequirement(
        "matching-openapi-v1",
        "bbf292401809ff6b1fdf05fd687d7f337dfb34e193f5340c579dceaba4801e18",
    ),
    ArtifactRequirement(
        "matching-events-v1",
        "ec63cb0733f275eaedc99348427883bb958c6467c5ee49f2a26fb252c0aafb6a",
    ),
    ArtifactRequirement(
        "matching-rule-v1",
        "144337610f3d06b8bfbb324547f3e25ca54ee6c2f821a28f94812aefc01ea4aa",
    ),
    ArtifactRequirement(
        "matching-input-manifest-v1",
        "38c90e5d73f7aff05d7b3dc6263c52a0c50c6769daa3b8ee541dccd58057f970",
    ),
    ArtifactRequirement(
        "matching-run-input-v1",
        "8774cf412ffa82c9acf53e6e7e95af361f84ec8040d02b972f846d57bb395418",
    ),
    ArtifactRequirement(
        "matching-candidate-v1",
        "856f95a2169a095d238277586cfdb171d38104eaaaa03d2df925502e1b919a28",
    ),
    ArtifactRequirement(
        "matching-disclosure-v1",
        "6b8b739a27bbd3894372de8a566133a6991fca22d97da883c87d6ebf601763de",
    ),
    ArtifactRequirement(
        "internal-sandbox-deployment-schema-v1",
        "2e242bdd10ae124acc3f00682b22d4eddee28303acc9a5f04eb0c213e0398f38",
    ),
    ArtifactRequirement(
        "internal-sandbox-seed-v1",
        INTERNAL_SANDBOX_SYNTHETIC_SEED_SHA256.hex(),
    ),
    ArtifactRequirement(
        "trust-openapi-v1",
        "6647e16e9f8f0ab321ed9985eb2da4e591e2217fdaa43ba663355a4f152f44b2",
    ),
    ArtifactRequirement(
        "trust-events-v1",
        "a26c410ca62c6d996fd13148863935729f480ca1a1fd9a44378a96ab13eae582",
    ),
    ArtifactRequirement(
        "trust-report-v1",
        "29b0c97a576edf654b5517847c73ce7a059141158182b16008f2cce3ef996278",
    ),
    ArtifactRequirement(
        "trust-triage-v1",
        "de45a368bc75f7523e9135b83f61ab8753581a1e775cffe943c7a70cbe6f3084",
    ),
    ArtifactRequirement(
        "appeal-openapi-v1",
        "ad0fd5874ad6d3343c62334805fe51c088df7b9db9215decfda95ee90a836e46",
    ),
    ArtifactRequirement(
        "appeal-events-v1",
        "7d3916ab89ace8c677da6ba6b6b5a65cfae28b8d91cf0c71fc0b0d9a88a064ba",
    ),
    ArtifactRequirement(
        "appeal-application-v1",
        "3549b053c911da3b5bf5b526c8abfc9e1ef9cdafd1f81e177d43cb412cab8223",
    ),
    ArtifactRequirement(
        "appeal-review-v1",
        "08982687c6654d606040c52faedc15a14b7b50e1c5c80db560587bbf3e16f72b",
    ),
)

_ARTIFACT_LOCATIONS: Tuple[PackageArtifactLocation, ...] = (
    PackageArtifactLocation(
        "iam-openapi-v1", "desire_platform.contracts", "api/iam-v1.openapi.yaml"
    ),
    PackageArtifactLocation(
        "iam-events-v1", "desire_platform.contracts", "events/iam-v1.schema.json"
    ),
    PackageArtifactLocation(
        "profile-openapi-v1",
        "desire_platform.contracts",
        "api/profile-v1.openapi.yaml",
    ),
    PackageArtifactLocation(
        "profile-events-v1",
        "desire_platform.contracts",
        "events/profile-v1.schema.json",
    ),
    PackageArtifactLocation(
        "profile-domain-v1",
        "desire_platform.contracts",
        "domain/profile-version-v1.schema.json",
    ),
    PackageArtifactLocation(
        "demand-openapi-v1",
        "desire_platform.contracts",
        "api/demand-v1.openapi.yaml",
    ),
    PackageArtifactLocation(
        "demand-events-v1",
        "desire_platform.contracts",
        "events/demand-v1.schema.json",
    ),
    PackageArtifactLocation(
        "demand-domain-v1",
        "desire_platform.contracts",
        "domain/demand-content-v1.schema.json",
    ),
    PackageArtifactLocation(
        "matching-openapi-v1",
        "desire_platform.contracts",
        "api/matching-v1.openapi.yaml",
    ),
    PackageArtifactLocation(
        "matching-events-v1",
        "desire_platform.contracts",
        "events/matching-v1.schema.json",
    ),
    PackageArtifactLocation(
        "matching-rule-v1",
        "desire_platform.contracts",
        "domain/matching-rule-release-v1.schema.json",
    ),
    PackageArtifactLocation(
        "matching-input-manifest-v1",
        "desire_platform.contracts",
        "domain/match-input-manifest-v1.schema.json",
    ),
    PackageArtifactLocation(
        "matching-run-input-v1",
        "desire_platform.contracts",
        "domain/match-run-input-v1.schema.json",
    ),
    PackageArtifactLocation(
        "matching-candidate-v1",
        "desire_platform.contracts",
        "domain/match-candidate-result-v1.schema.json",
    ),
    PackageArtifactLocation(
        "matching-disclosure-v1",
        "desire_platform.contracts",
        "domain/invitation-disclosure-v1.schema.json",
    ),
    PackageArtifactLocation(
        "internal-sandbox-deployment-schema-v1",
        "desire_platform.contracts",
        "config/internal-sandbox-deployment-v1.schema.json",
    ),
    PackageArtifactLocation(
        "internal-sandbox-seed-v1",
        "desire_platform.internal_pilot.fixtures",
        "internal_sandbox_seed_v1.json",
        maximum_bytes=64 * 1024,
    ),
    PackageArtifactLocation(
        "trust-openapi-v1",
        "desire_platform.contracts",
        "api/trust-v1.openapi.yaml",
    ),
    PackageArtifactLocation(
        "trust-events-v1",
        "desire_platform.contracts",
        "events/trust-v1.schema.json",
    ),
    PackageArtifactLocation(
        "trust-report-v1",
        "desire_platform.contracts",
        "domain/trust-report-v1.schema.json",
    ),
    PackageArtifactLocation(
        "trust-triage-v1",
        "desire_platform.contracts",
        "domain/trust-triage-v1.schema.json",
    ),
    PackageArtifactLocation(
        "appeal-openapi-v1",
        "desire_platform.contracts",
        "api/appeal-v1.openapi.yaml",
    ),
    PackageArtifactLocation(
        "appeal-events-v1",
        "desire_platform.contracts",
        "events/appeal-v1.schema.json",
    ),
    PackageArtifactLocation(
        "appeal-application-v1",
        "desire_platform.contracts",
        "domain/appeal-application-v1.schema.json",
    ),
    PackageArtifactLocation(
        "appeal-review-v1",
        "desire_platform.contracts",
        "domain/appeal-review-v1.schema.json",
    ),
)

_HMAC_PURPOSES = INTERNAL_SANDBOX_KEY_PURPOSES[:5]
_INVITATION_TOKEN_PURPOSES = frozenset({"ACCESS_INVITATION_TOKEN"})
_IAM_READ_CURSOR_PURPOSES = frozenset({"IAM_READ_CURSOR"})
_RECIPIENT_BINDING_PURPOSES = frozenset({"OIDC_RECIPIENT_BINDING"})
_ORG_ADMIN_RECEIPT_PURPOSES = frozenset(
    {"PLATFORM_USER_IDEMPOTENCY", "PLATFORM_USER_PAYLOAD_HASH"}
)
_TRUST_ROTATING_PURPOSES = frozenset(
    (
        "TRUST_IDEMPOTENCY",
        "TRUST_PAYLOAD_HASH",
        "TRUST_SEALED_NOTE",
        "TRUST_REPORT_CURSOR",
    )
)
_DEMAND_ROTATING_PURPOSES = frozenset(
    ("DEMAND_IDEMPOTENCY", "DEMAND_PAYLOAD_HASH")
)
_SINGLE_KEY_PURPOSES = (
    frozenset(INTERNAL_SANDBOX_KEY_PURPOSES[6:])
    - _INVITATION_TOKEN_PURPOSES
    - _IAM_READ_CURSOR_PURPOSES
    - _RECIPIENT_BINDING_PURPOSES
    - _ORG_ADMIN_RECEIPT_PURPOSES
    - _TRUST_ROTATING_PURPOSES
    - _DEMAND_ROTATING_PURPOSES
)
_PROFILE_MANIFEST_PACKAGE = (
    "desire_platform.creator_profile.adapters.postgres.migrations"
)
_DEMAND_MANIFEST_PACKAGE = "desire_platform.demand.adapters.postgres.migrations"
_IAM_MANIFEST_PACKAGE = "desire_platform.identity_access.adapters.postgres.migrations"
_TRUST_MANIFEST_PACKAGE = "desire_platform.trust_safety.adapters.postgres.migrations"
_MATCHING_MANIFEST_PACKAGE = "desire_platform.matching.adapters.postgres.migrations"


class InternalSandboxProductionPlanError(RuntimeError):
    """Stable, non-reflective construction failure."""

    def __init__(self, code: str = "INTERNAL_SANDBOX_PRODUCTION_PLAN_INVALID") -> None:
        self.code = code
        super().__init__(code)


def build_internal_sandbox_server_plan(
    *,
    environment: Mapping[str, str],
    read_bytes: Optional[Callable[[str], bytes]] = None,
    dbapi: Any = psycopg,
    telemetry_stream: TextIO = sys.stderr,
    seed_loader: Callable[[], InternalSandboxSyntheticSeedPlan] = (
        load_internal_sandbox_synthetic_seed
    ),
) -> Any:
    """Build the exact API server plan without connecting or listening.

    Network and database readiness are deliberately performed by
    :mod:`api_server` immediately before Uvicorn is imported and called.
    """

    managed: list[Any] = []
    issued: list[FileSecretCarrier] = []
    try:
        deployment = load_internal_sandbox_deployment_config_pointer(
            environment=environment,
            read_bytes=read_bytes,
        )
        reader = _read_regular_config_file if read_bytes is None else read_bytes
        if not callable(reader):
            _invalid()
        runtime = parse_runtime_config(_read_exact(reader, deployment.runtime_config_path))
        _validate_runtime_contract(deployment, runtime)
        verifier = PackageArtifactVerifier(locations=_ARTIFACT_LOCATIONS)
        for requirement in runtime.artifacts:
            verifier.verify(requirement)
        _validate_schema_contract_constants()

        seed = seed_loader()
        if not isinstance(seed, InternalSandboxSyntheticSeedPlan):
            _invalid()
        seed.require_executable()
        if not hmac.compare_digest(
            seed.manifest_sha256,
            INTERNAL_SANDBOX_SYNTHETIC_SEED_SHA256.hex(),
        ):
            _invalid()

        manifest = parse_file_secret_manifest(
            _read_exact(reader, deployment.secret_manifest_path)
        )
        _validate_manifest(runtime, manifest)
        provider = FilesystemSecretProvider(
            allowed_root=Path(deployment.secret_root),
            entries=manifest,
        )

        credentials: Dict[str, FileSecretCarrier] = {}
        for profile in runtime.database_profiles:
            carrier = provider.resolve_credential(profile)
            issued.append(carrier)
            credentials[profile.capability_id] = carrier
        keys: Dict[Tuple[str, str], FileSecretCarrier] = {}
        for requirement in runtime.key_requirements:
            for key_id in requirement.retained_key_ids:
                carrier = provider.resolve_key(requirement.purpose, key_id)
                issued.append(carrier)
                keys[(requirement.purpose, key_id)] = carrier
        _validate_secret_material(runtime, issued, keys)
        sources = SecureRuntimeSources()
        runtime_secrets = ManagedRuntimeSecrets(
            carriers=tuple(issued),
            clock=sources.now,
        )
        managed.append(runtime_secrets)

        pool_factory = PsycopgRoleBoundPoolFactory(
            endpoint=deployment.postgres,
            dbapi=dbapi,
            allowed_roles=tuple(role for _, role in INTERNAL_SANDBOX_CAPABILITY_ROLES),
        )
        pool_values: Dict[str, Any] = {}
        for profile in runtime.database_profiles:
            pool = pool_factory.create(profile, credentials[profile.capability_id])
            managed.append(pool)
            pool_values[profile.capability_id.lower()] = pool
        pools = InternalSandboxApiPools(**pool_values)

        requirements = {item.purpose: item for item in runtime.key_requirements}
        runtime_key_material = {
            identity: RuntimeKeyMaterial(
                purpose=identity[0],
                key_id=identity[1],
                material=carrier.material,
            )
            for identity, carrier in keys.items()
            if identity[0] in frozenset(_HMAC_PURPOSES)
            | {"OIDC_PROTOCOL_AEAD", "OIDC_RECIPIENT_BINDING", "IAM_READ_CURSOR"}
        }
        keyring = HmacRuntimeKeyring(
            keys=tuple(
                runtime_key_material[(purpose, key_id)]
                for purpose in _HMAC_PURPOSES
                for key_id in requirements[purpose].retained_key_ids
            ),
            active_key_ids={
                purpose: requirements[purpose].active_key_id
                for purpose in _HMAC_PURPOSES
            },
            retained_key_ids={
                purpose: requirements[purpose].retained_key_ids
                for purpose in _HMAC_PURPOSES
            },
        )
        trust_idempotency_requirement = requirements["TRUST_IDEMPOTENCY"]
        trust_payload_requirement = requirements["TRUST_PAYLOAD_HASH"]
        trust_sealed_requirement = requirements["TRUST_SEALED_NOTE"]
        trust_report_cursor_requirement = requirements["TRUST_REPORT_CURSOR"]
        trust_receipt_keyring = TrustPostgresReceiptKeyring(
            idempotency_keys=tuple(
                TrustPostgresReceiptKey(
                    purpose="IDEMPOTENCY",
                    key_id=key_id,
                    material=keys[("TRUST_IDEMPOTENCY", key_id)].material,
                )
                for key_id in trust_idempotency_requirement.retained_key_ids
            ),
            payload_hash_keys=tuple(
                TrustPostgresReceiptKey(
                    purpose="PAYLOAD_HASH",
                    key_id=key_id,
                    material=keys[("TRUST_PAYLOAD_HASH", key_id)].material,
                )
                for key_id in trust_payload_requirement.retained_key_ids
            ),
        )
        trust_sealed_text_keyring = TrustSealedTextKeyring(
            keys=tuple(
                TrustSealedTextKey(
                    key_id=key_id,
                    material=keys[("TRUST_SEALED_NOTE", key_id)].material,
                )
                for key_id in trust_sealed_requirement.retained_key_ids
            ),
            active_key_id=trust_sealed_requirement.active_key_id,
            retained_key_ids=trust_sealed_requirement.retained_key_ids,
        )
        trust_report_cursor_keyring = TrustOwnedReportCursorKeyring(
            keys=tuple(
                TrustOwnedReportCursorKey(
                    purpose="TRUST_REPORT_CURSOR",
                    key_id=key_id,
                    material=keys[("TRUST_REPORT_CURSOR", key_id)].material,
                )
                for key_id in trust_report_cursor_requirement.retained_key_ids
            ),
            active_key_id=trust_report_cursor_requirement.active_key_id,
            retained_key_ids=trust_report_cursor_requirement.retained_key_ids,
        )
        appeal_receipt_keyring = AppealPostgresReceiptKeyring(
            idempotency_keys=tuple(
                AppealPostgresReceiptKey(
                    purpose="IDEMPOTENCY",
                    key_id=key_id,
                    material=keys[("TRUST_IDEMPOTENCY", key_id)].material,
                )
                for key_id in trust_idempotency_requirement.retained_key_ids
            ),
            payload_hash_keys=tuple(
                AppealPostgresReceiptKey(
                    purpose="PAYLOAD_HASH",
                    key_id=key_id,
                    material=keys[("TRUST_PAYLOAD_HASH", key_id)].material,
                )
                for key_id in trust_payload_requirement.retained_key_ids
            ),
        )
        appeal_sealed_text_keyring = AppealSealedTextKeyring(
            keys=tuple(
                AppealSealedTextKey(
                    key_id=key_id,
                    material=keys[("TRUST_SEALED_NOTE", key_id)].material,
                )
                for key_id in trust_sealed_requirement.retained_key_ids
            ),
            active_key_id=trust_sealed_requirement.active_key_id,
            retained_key_ids=trust_sealed_requirement.retained_key_ids,
        )
        managed.extend(
            (
                trust_receipt_keyring,
                trust_sealed_text_keyring,
                trust_report_cursor_keyring,
                appeal_receipt_keyring,
                appeal_sealed_text_keyring,
            )
        )
        aead_requirement = requirements["OIDC_PROTOCOL_AEAD"]
        secret_box = AesGcmProtocolSecretBox(
            keys=tuple(
                runtime_key_material[("OIDC_PROTOCOL_AEAD", key_id)]
                for key_id in aead_requirement.retained_key_ids
            ),
            active_key_id=aead_requirement.active_key_id,
        )
        recipient_requirement = requirements["OIDC_RECIPIENT_BINDING"]
        recipient_binding = HmacRecipientBinding(
            keys=tuple(
                runtime_key_material[("OIDC_RECIPIENT_BINDING", key_id)]
                for key_id in recipient_requirement.retained_key_ids
            ),
            active_key_id=recipient_requirement.active_key_id,
        )
        iam_reads = PsycopgIamReadModelRepository(
            app_connections=pools.iam_app,
            onboarding_connections=pools.iam_onboarding,
        )
        account_admin_keys = PlatformUserAdminKeys(
            idempotency_key=_active_material(
                keys, requirements, "PLATFORM_USER_IDEMPOTENCY"
            ),
            payload_hash_key=_active_material(
                keys, requirements, "PLATFORM_USER_PAYLOAD_HASH"
            ),
            idempotency_key_id=requirements[
                "PLATFORM_USER_IDEMPOTENCY"
            ].active_key_id,
            payload_hash_key_id=requirements[
                "PLATFORM_USER_PAYLOAD_HASH"
            ].active_key_id,
        )
        iam_receipt_keys = IamReceiptPolicyKeys.from_platform_user_admin_keys(
            account_admin_keys
        )
        invitation_requirement = requirements["ACCESS_INVITATION_TOKEN"]
        organization_admin_keys = OrganizationAdminKeys(
            idempotency_key=account_admin_keys.idempotency_key,
            payload_hash_key=account_admin_keys.payload_hash_key,
            invitation_token_keys=tuple(
                (
                    key_id,
                    keys[("ACCESS_INVITATION_TOKEN", key_id)].material,
                )
                for key_id in invitation_requirement.retained_key_ids
            ),
            active_invitation_token_key_id=invitation_requirement.active_key_id,
            idempotency_key_id=account_admin_keys.idempotency_key_id,
            payload_hash_key_id=account_admin_keys.payload_hash_key_id,
            idempotency_keyring=tuple(
                (
                    key_id,
                    keys[("PLATFORM_USER_IDEMPOTENCY", key_id)].material,
                )
                for key_id in requirements[
                    "PLATFORM_USER_IDEMPOTENCY"
                ].retained_key_ids
            ),
            payload_hash_keyring=tuple(
                (
                    key_id,
                    keys[("PLATFORM_USER_PAYLOAD_HASH", key_id)].material,
                )
                for key_id in requirements[
                    "PLATFORM_USER_PAYLOAD_HASH"
                ].retained_key_ids
            ),
        )
        invitation_token_codec = HmacOrganizationInvitationTokenCodec(
            keys=organization_admin_keys
        )
        cursor_requirement = requirements["IAM_READ_CURSOR"]
        iam_read_cursor_codec = HmacIamReadCursorCodec(
            keys=tuple(
                runtime_key_material[("IAM_READ_CURSOR", key_id)]
                for key_id in cursor_requirement.retained_key_ids
            ),
            active_key_id=cursor_requirement.active_key_id,
        )
        session_security = PsycopgIamSessionSecurity(
            connections=pools.iam_session_authenticator,
            keyring=keyring,
            id_source=sources,
            settings=SessionSecuritySettings(
                additional_csrf_operation_ids=(
                    "internalPilotEditorWrite",
                    "trustSafetyWrite",
                    "appealWrite",
                    "acceptMatchingInvitation",
                    "declineMatchingInvitation",
                    "withdrawMatchingInvitationAcceptance",
                    "chooseMatchingCreator",
                    "closeMatchingSelection",
                    "createMatchingInvitation",
                    "publishMatchingInvitation",
                    "invalidateMatchingAttempt",
                    "claimCandidateSelectorAssignment",
                    "claimMatchingReviewAssignment",
                    "releaseMatchingReviewAssignment",
                )
            ),
        )
        managed.append(session_security)

        matching_keys = MatchingPostgresHttpKeys(
            idempotency_key_id=requirements[
                "MATCHING_IDEMPOTENCY"
            ].active_key_id,
            idempotency_key=_active_material(
                keys, requirements, "MATCHING_IDEMPOTENCY"
            ),
            payload_hash_key_id=requirements[
                "MATCHING_PAYLOAD_HASH"
            ].active_key_id,
            payload_hash_key=_active_material(
                keys, requirements, "MATCHING_PAYLOAD_HASH"
            ),
            read_cursor_key_id=requirements[
                "MATCHING_READ_CURSOR"
            ].active_key_id,
            read_cursor_key=_active_material(
                keys, requirements, "MATCHING_READ_CURSOR"
            ),
        )
        matching_runtime = PsycopgMatchingRuntime(
            creator_connections=pools.matching_creator,
            selector_connections=pools.matching_selector,
            settings=MatchingPostgresSettings(),
        )
        managed.append(matching_runtime)
        matching_operational_settings = MatchingOperationalPostgresSettings()
        matching_assignment_runtime = PsycopgMatchingAssignmentRuntime(
            connections=pools.matching_assignment,
            settings=matching_operational_settings,
        )
        managed.append(matching_assignment_runtime)
        matching_review_runtime = PsycopgMatchingReviewRuntime(
            connections=pools.matching_review,
            settings=matching_operational_settings,
        )
        managed.append(matching_review_runtime)

        oidc_settings = deployment.oidc
        client_secret = keys[
            ("OIDC_CLIENT_SECRET", oidc_settings.client_secret_key_id)
        ]
        subject_key = keys[
            ("OIDC_SUBJECT_DIGEST", oidc_settings.subject_digest_key_id)
        ]
        network_binding = oidc_settings.network_binding
        if network_binding.mode == OIDC_NETWORK_BINDING_SYSTEM_DNS_SYNTHETIC:
            oidc_transport = StdlibOidcJsonTransport()
        elif network_binding.mode == OIDC_NETWORK_BINDING_PINNED_PUBLIC_IP:
            pinned_public_ipv4 = network_binding.pinned_public_ipv4
            if not isinstance(pinned_public_ipv4, str):
                _invalid()
            oidc_transport = PinnedPublicIpOidcJsonTransport(
                issuer=oidc_settings.issuer,
                pinned_public_ipv4=pinned_public_ipv4,
            )
        else:
            _invalid()
        oidc_provider = ClosedOidcProvider(
            configuration=OidcProviderConfiguration(
                issuer=oidc_settings.issuer,
                client_id=oidc_settings.client_id,
                client_secret=client_secret.material,
                redirect_uri=oidc_settings.redirect_uri,
                allowed_signing_algorithms=oidc_settings.allowed_signing_algorithms,
                metadata_ttl_seconds=oidc_settings.metadata_ttl_seconds,
                request_timeout_seconds=oidc_settings.request_timeout_seconds,
                maximum_response_bytes=oidc_settings.maximum_response_bytes,
                clock_skew_seconds=oidc_settings.clock_skew_seconds,
                subject_digest_key_id=oidc_settings.subject_digest_key_id,
            ),
            transport=oidc_transport,
            token_verifier=PyJwtOidcTokenVerifier(),
            recipient_binding=recipient_binding,
            subject_digest_key=subject_key.material,
        )
        oidc_policy = OidcSecurityPolicy(
            policy_version="internal-sandbox-oidc-v1",
            provider_issuer=oidc_settings.issuer,
            provider_audience=oidc_settings.client_id,
            redirect_uri=oidc_settings.redirect_uri,
            allowed_return_to=("/app",),
            provider_clock_skew=timedelta(seconds=oidc_settings.clock_skew_seconds),
        )
        oidc_uow = PsycopgOidcAuthenticationUnitOfWork(
            connections=pools.iam_onboarding
        )
        authentication = build_postgres_iam_authentication_bundle(
            oidc_uow=oidc_uow,
            provider=oidc_provider,
            protocol_keyring=keyring,
            protocol_secret_box=secret_box,
            session_keyring=keyring,
            clock=sources,
            id_source=sources,
            secret_source=sources,
            system_actor_id=deployment.system_actor_id,
            security_policy=oidc_policy,
            invitation_capabilities=invitation_token_codec,
            invitation_reads=iam_reads,
            session_security=session_security,
        )

        iam_validator = IamPostgresContractValidator()
        invitation_accept_hold = InternalSandboxInvitationSafetyHold(
            deployment_mode=deployment.deployment_mode,
            clock=sources,
        )
        managed.append(invitation_accept_hold)
        membership_resume_hold = InternalSandboxMembershipResumeSafetyHold(
            deployment_mode=deployment.deployment_mode,
            clock=sources,
        )
        managed.append(membership_resume_hold)
        invitation_issue_hold = InternalSandboxOrganizationInvitationIssueSafetyHold(
            deployment_mode=deployment.deployment_mode,
            clock=sources,
        )
        managed.append(invitation_issue_hold)
        invitation_accept_uow = PsycopgAcceptAccessInvitationUnitOfWorkFactory(
            connections=pools.iam_onboarding,
            event_validator=iam_validator,
            response_validator=iam_validator,
        )
        invitation_accept_scope = PsycopgOrganizationAcceptScopeResolver(
            connections=pools.iam_onboarding
        )
        invitation_accept_keyring = OrganizationAcceptKeyring(
            receipt_keys=organization_admin_keys,
            session_keyring=keyring,
        )
        policy_uow = PsycopgPolicyConsentCommandUnitOfWorkFactory(
            connections=pools.iam_app,
            event_validator=iam_validator,
            response_validator=iam_validator,
        )
        logout_uow = PsycopgOwnedSessionRevocationUnitOfWorkFactory(
            connections=pools.iam_app
        )
        policy_scope_resolver = PsycopgPolicyAcceptanceScopeResolver(
            connections=pools.iam_app
        )
        csrf_tokens = PostgresSessionBootstrapCsrfTokens(keyring=keyring)
        organization_admin_uow = PsycopgOrganizationAdminUnitOfWorkFactory(
            connections=pools.iam_app,
            event_validator=iam_validator,
            response_validator=iam_validator,
        )
        organization_public_name_uow = (
            PsycopgOrganizationPublicNameUnitOfWorkFactory(
                connections=pools.iam_app,
                event_validator=iam_validator,
                response_validator=iam_validator,
            )
        )
        organization_admin_target_resolver = (
            PsycopgOrganizationAdminTargetResolver(
                connections=pools.iam_app
            )
        )
        iam_bindings = IamHttpPresenterBindings(
            begin_oidc_authorization=authentication.begin_oidc_authorization,
            complete_oidc_authorization=authentication.complete_oidc_authorization,
            get_session_bootstrap=GetSessionBootstrapHandler(
                repository=iam_reads,
                clock=sources,
                csrf_tokens=csrf_tokens,
            ),
            get_policy_bundle=GetPolicyBundleHandler(
                repository=iam_reads,
                clock=sources,
            ),
            get_me=GetMeHandler(repository=iam_reads, clock=sources),
            list_my_sessions=ListMySessionsHandler(
                repository=iam_reads,
                clock=sources,
                cursor_codec=iam_read_cursor_codec,
            ),
            inspect_access_invitation=InspectAccessInvitationHandler(
                repository=iam_reads,
                clock=sources,
                invitation_capabilities=invitation_token_codec,
            ),
            accept_access_invitation=(
                PostgresAcceptOrganizationAccessInvitationHandler(
                    scope_resolver=invitation_accept_scope,
                    uow_factory=invitation_accept_uow,
                    safety_hold=invitation_accept_hold,
                    keyring=invitation_accept_keyring,
                    clock=sources,
                    id_source=sources,
                    secret_source=sources,
                )
            ),
            get_organization_summary=GetOrganizationSummaryHandler(
                repository=iam_reads, clock=sources
            ),
            update_organization_public_name=(
                PostgresUpdateOrganizationPublicNameHandler(
                    uow_factory=organization_public_name_uow,
                    keys=organization_admin_keys,
                    clock=sources,
                    id_source=sources,
                )
            ),
                list_organization_access_invitations=(
                    ListOrganizationAccessInvitationsHandler(
                        repository=iam_reads,
                        clock=sources,
                        cursor_codec=iam_read_cursor_codec,
                    )
                ),
                list_organization_memberships=ListOrganizationMembershipsHandler(
                    repository=iam_reads,
                    clock=sources,
                    cursor_codec=iam_read_cursor_codec,
                ),
            issue_organization_access_invitation=(
                PostgresIssueOrganizationAccessInvitationHandler(
                    uow_factory=organization_admin_uow,
                    target_resolver=organization_admin_target_resolver,
                    safety_hold=invitation_issue_hold,
                    safety_hold_policy_version=invitation_issue_hold.policy_version,
                    recipient_binding=recipient_binding,
                    token_codec=invitation_token_codec,
                    keys=organization_admin_keys,
                    clock=sources,
                    id_source=sources,
                    secret_source=sources,
                )
            ),
            revoke_access_invitation=PostgresRevokeAccessInvitationHandler(
                uow_factory=organization_admin_uow,
                target_resolver=organization_admin_target_resolver,
                keys=organization_admin_keys,
                clock=sources,
                id_source=sources,
            ),
            suspend_membership=PostgresSuspendMembershipHandler(
                uow_factory=organization_admin_uow,
                target_resolver=organization_admin_target_resolver,
                keys=organization_admin_keys,
                clock=sources,
                id_source=sources,
            ),
            resume_membership=PostgresResumeMembershipHandler(
                uow_factory=organization_admin_uow,
                target_resolver=organization_admin_target_resolver,
                safety_hold=membership_resume_hold,
                safety_hold_policy_version=membership_resume_hold.policy_version,
                keys=organization_admin_keys,
                clock=sources,
                id_source=sources,
            ),
            revoke_membership=PostgresRevokeMembershipHandler(
                uow_factory=organization_admin_uow,
                target_resolver=organization_admin_target_resolver,
                keys=organization_admin_keys,
                clock=sources,
                id_source=sources,
            ),
            accept_current_policies=PostgresAcceptCurrentPoliciesHandler(
                scope_resolver=policy_scope_resolver,
                uow_factory=policy_uow,
                keys=iam_receipt_keys,
                clock=sources,
                id_source=sources,
            ),
            revoke_my_session=PostgresRevokeOwnedSessionHandler(
                uow_factory=logout_uow,
                keys=iam_receipt_keys,
                clock=sources,
                id_source=sources,
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
        managed.append(authorities)
        trust_settings = TrustPostgresGatewaySettings()
        trust_gateway = PsycopgTrustCommandGateway(
            reporter_connections=pools.trust_self,
            officer_connections=pools.trust_officer,
            settings=trust_settings,
        )
        trust_receipt_probe = PsycopgTrustReceiptProbe(
            reporter_connections=pools.trust_self,
            officer_connections=pools.trust_officer,
            settings=trust_settings,
        )
        trust_restricted_text_store = PsycopgTrustRestrictedTextStore(
            officer_connections=pools.trust_officer,
            settings=trust_settings,
        )
        trust_sealed_notes = PsycopgTrustSealedNoteProvider(
            store=trust_restricted_text_store,
            keyring=trust_sealed_text_keyring,
        )
        trust_outcome_evidence = PsycopgTrustOutcomeEvidenceProvider(
            officer_connections=pools.trust_officer,
            id_source=sources,
            settings=trust_settings,
        )
        trust_handlers = build_trust_postgres_command_handlers(
            gateway=trust_gateway,
            receipt_probe=trust_receipt_probe,
            receipt_keyring=trust_receipt_keyring,
            id_source=sources,
            clock=sources,
            sealed_notes=trust_sealed_notes,
            outcome_evidence=trust_outcome_evidence,
        )
        trust_read_gateway = PsycopgTrustReadGateway(
            reporter_connections=pools.trust_self,
            officer_connections=pools.trust_officer,
            settings=trust_settings,
        )
        trust_projections = PsycopgTrustHttpProjectionAdapter(
            read_gateway=trust_read_gateway,
            cursor_keyring=trust_report_cursor_keyring,
        )
        trust_runtime_readiness = PsycopgTrustRuntimeReadiness(
            reporter_connections=pools.trust_self,
            officer_connections=pools.trust_officer,
            appeal_connections=pools.trust_appeal,
            decision_connections=pools.trust_decision,
            settings=TrustPostgresGatewaySettings(
                lock_timeout_ms=min(
                    2_000, runtime.budgets.readiness_timeout_ms
                ),
                statement_timeout_ms=runtime.budgets.readiness_timeout_ms,
                idle_in_transaction_timeout_ms=min(
                    15_000, runtime.budgets.readiness_timeout_ms
                ),
            ),
        )
        trust_runtime = InternalSandboxTrustPostgresRuntime(
            projections=trust_projections,
            command_gateway=trust_gateway,
            receipt_probe=trust_receipt_probe,
            receipt_keyring=trust_receipt_keyring,
            sealed_notes=trust_sealed_notes,
            outcome_evidence=trust_outcome_evidence,
            runtime_readiness=trust_runtime_readiness,
        )
        managed.append(trust_runtime)
        trust_bindings = TrustHttpPresenterBindings(
            projections=trust_runtime,
            **trust_handlers.__dict__,
        )
        appeal_settings = AppealPostgresGatewaySettings()
        appeal_gateway = PsycopgAppealCommandGateway(
            applicant_connections=pools.trust_self,
            reviewer_connections=pools.trust_appeal,
            settings=appeal_settings,
        )
        appeal_receipt_probe = PsycopgAppealReceiptProbe(
            applicant_connections=pools.trust_self,
            reviewer_connections=pools.trust_appeal,
            settings=appeal_settings,
        )
        appeal_restricted_text_store = PsycopgAppealRestrictedTextStore(
            applicant_connections=pools.trust_self,
            reviewer_connections=pools.trust_appeal,
            settings=appeal_settings,
        )
        appeal_sealed_text = PsycopgAppealSealedTextProvider(
            store=appeal_restricted_text_store,
            keyring=appeal_sealed_text_keyring,
        )
        appeal_handlers = build_appeal_postgres_command_handlers(
            gateway=appeal_gateway,
            receipt_probe=appeal_receipt_probe,
            receipt_keyring=appeal_receipt_keyring,
            id_source=sources,
            clock=sources,
            sealed_text=appeal_sealed_text,
        )
        appeal_read_gateway = PsycopgAppealReadGateway(
            applicant_connections=pools.trust_self,
            reviewer_connections=pools.trust_appeal,
            settings=appeal_settings,
        )
        appeal_projections = PsycopgAppealHttpProjectionAdapter(
            read_gateway=appeal_read_gateway
        )
        appeal_runtime_readiness = PsycopgAppealRuntimeReadiness(
            applicant_connections=pools.trust_self,
            reviewer_connections=pools.trust_appeal,
            settings=AppealPostgresGatewaySettings(
                lock_timeout_ms=min(
                    2_000, runtime.budgets.readiness_timeout_ms
                ),
                statement_timeout_ms=runtime.budgets.readiness_timeout_ms,
                idle_in_transaction_timeout_ms=min(
                    15_000, runtime.budgets.readiness_timeout_ms
                ),
            ),
        )
        appeal_runtime = InternalSandboxAppealPostgresRuntime(
            projections=appeal_projections,
            command_gateway=appeal_gateway,
            receipt_probe=appeal_receipt_probe,
            receipt_keyring=appeal_receipt_keyring,
            sealed_text=appeal_sealed_text,
            runtime_readiness=appeal_runtime_readiness,
        )
        managed.append(appeal_runtime)
        appeal_bindings = AppealHttpPresenterBindings(
            projections=appeal_runtime,
            **appeal_handlers.__dict__,
        )
        trust_demand_hold = PsycopgTrustDemandSafetyHoldProvider(
            decision_connections=pools.trust_decision,
            settings=trust_settings,
        )
        managed.append(trust_demand_hold)
        matching_bindings = build_matching_postgres_http_bindings(
            runtime=matching_runtime,
            keys=matching_keys,
            id_source=sources,
            review_runtime=matching_review_runtime,
            demand_hold=trust_demand_hold,
        )
        matching_operational_service = MatchingPostgresOperationalHttpService(
            assignment_runtime=matching_assignment_runtime,
            review_runtime=matching_review_runtime,
            keys=matching_keys,
            id_source=sources,
        )
        rule_catalog = PsycopgDemandRuleCatalog(connections=pools.demand_self)
        evidence = InternalSandboxEditorEvidenceProvider(
            deployment_mode="INTERNAL_SANDBOX",
            demand_rule_catalog=rule_catalog,
            demand_safety_hold=trust_demand_hold,
            validation_clock=sources,
        )
        managed.append(evidence)

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
        managed.append(review_queue)
        editor_repository = PsycopgEditorRepository(
            profile_uow=profile_uow,
            demand_uows={
                DemandPostgresOperation.CREATE: demand_owner_uow,
                DemandPostgresOperation.CREATE_VERSION: demand_owner_uow,
                DemandPostgresOperation.SUBMIT: demand_owner_uow,
                DemandPostgresOperation.CANCEL_OWNER: demand_owner_uow,
                DemandPostgresOperation.REQUEST_CHANGES: demand_review_uow,
                DemandPostgresOperation.VERIFY: demand_review_uow,
                DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT: (
                    demand_review_uow
                ),
            },
            profile_reads=pools.profile_app,
            demand_owner_reads=pools.demand_self,
            demand_review_reads=pools.demand_review,
        )
        editor_keys = EditorPostgresKeys(
            id_key=_active_material(keys, requirements, "EDITOR_ID_DERIVATION"),
            profile_idempotency_key=_active_material(
                keys, requirements, "PROFILE_IDEMPOTENCY"
            ),
            profile_payload_key=_active_material(
                keys, requirements, "PROFILE_PAYLOAD_HASH"
            ),
            demand_idempotency_key=_active_material(
                keys, requirements, "DEMAND_IDEMPOTENCY"
            ),
            demand_payload_key=_active_material(
                keys, requirements, "DEMAND_PAYLOAD_HASH"
            ),
            demand_client_reference_key=_active_material(
                keys, requirements, "DEMAND_CLIENT_REFERENCE"
            ),
            profile_idempotency_key_id=requirements[
                "PROFILE_IDEMPOTENCY"
            ].active_key_id,
            profile_payload_key_id=requirements["PROFILE_PAYLOAD_HASH"].active_key_id,
            demand_idempotency_key_id=requirements[
                "DEMAND_IDEMPOTENCY"
            ].active_key_id,
            demand_payload_key_id=requirements["DEMAND_PAYLOAD_HASH"].active_key_id,
            demand_client_reference_key_id=requirements[
                "DEMAND_CLIENT_REFERENCE"
            ].active_key_id,
        )
        completed_profile_lifecycle_receipts = (
            PsycopgProfileCompletedLifecycleReceiptProbe(
                connections=pools.profile_app,
                idempotency_keys=tuple(
                    (
                        key_id,
                        keys[("PROFILE_IDEMPOTENCY", key_id)].material,
                    )
                    for key_id in requirements[
                        "PROFILE_IDEMPOTENCY"
                    ].retained_key_ids
                ),
                payload_hash_keys=tuple(
                    (
                        key_id,
                        keys[("PROFILE_PAYLOAD_HASH", key_id)].material,
                    )
                    for key_id in requirements[
                        "PROFILE_PAYLOAD_HASH"
                    ].retained_key_ids
                ),
            )
        )
        completed_verify_receipts = PsycopgDemandCompletedVerifyReceiptProbe(
            connections=pools.demand_review,
            idempotency_keys=tuple(
                (
                    key_id,
                    keys[("DEMAND_IDEMPOTENCY", key_id)].material,
                )
                for key_id in requirements[
                    "DEMAND_IDEMPOTENCY"
                ].retained_key_ids
            ),
            payload_hash_keys=tuple(
                (
                    key_id,
                    keys[("DEMAND_PAYLOAD_HASH", key_id)].material,
                )
                for key_id in requirements[
                    "DEMAND_PAYLOAD_HASH"
                ].retained_key_ids
            ),
        )
        managed.append(completed_verify_receipts)
        editor_service = PostgresEditorService(
            repository=editor_repository,
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
        finance_funding_service = PsycopgFinanceFundingService(
            connections=pools.demand_finance,
            keys=FinanceFundingKeys(
                id_key=editor_keys.id_key,
                idempotency_key=editor_keys.demand_idempotency_key,
                payload_key=editor_keys.demand_payload_key,
                idempotency_key_id=editor_keys.demand_idempotency_key_id,
                payload_key_id=editor_keys.demand_payload_key_id,
            ),
        )
        managed.append(finance_funding_service)
        account_admin_repository = PsycopgInternalSandboxAccountAdminRepository(
            connections=pools.iam_app
        )
        account_admin_lifecycle = (
            PsycopgPlatformUserLifecycleUnitOfWorkFactory(
                connections=pools.iam_app,
                event_validator=iam_validator,
                response_validator=iam_validator,
            )
        )
        account_admin_service = PostgresInternalSandboxAccountAdminService(
            repository=account_admin_repository,
            lifecycle=account_admin_lifecycle,
            keys=account_admin_keys,
            clock=sources,
            id_source=sources,
        )
        principal_resolver = PsycopgEditorPrincipalResolver(connections=pools.iam_app)

        origin_policy = ExactOriginPolicy(
            ExactOriginPolicySettings(
                allowed_origins=(deployment.internal_bff_origin,),
                allow_internal_bff_http=True,
                deployment_mode=deployment.deployment_mode,
            )
        )
        managed.append(origin_policy)
        rate_limiter = InternalSandboxRateLimiter(
            settings=InternalSandboxRateLimitSettings(),
            clock=sources,
        )
        managed.append(rate_limiter)
        telemetry = JsonLineHttpTelemetry(stream=telemetry_stream)
        managed.append(telemetry)
        oidc_readiness = OidcProviderReadiness(
            provider=oidc_provider,
            security_policy=oidc_policy,
        )
        managed.append(oidc_readiness)
        local_server_dependencies = LocalServerDependencyReadiness()
        managed.append(local_server_dependencies)
        schema_readiness = _schema_readiness(
            pools,
            demand_idempotency_key_ids=(
                requirements["DEMAND_IDEMPOTENCY"].retained_key_ids
            ),
            demand_payload_key_ids=(
                requirements["DEMAND_PAYLOAD_HASH"].retained_key_ids
            ),
        )
        managed.extend(schema_readiness)
        seed_readiness = PostgresInternalSandboxSeedReadiness(
            pool=pools.profile_app
        )
        managed.append(seed_readiness)
        managed.append(completed_profile_lifecycle_receipts)

        _prove_secret_bindings(
            runtime_secrets=runtime_secrets,
            pools=pools,
            credentials=credentials,
            keys=keys,
            keyring=keyring,
            secret_box=secret_box,
            recipient_binding=recipient_binding,
            oidc_provider=oidc_provider,
            editor_keys=editor_keys,
            completed_profile_lifecycle_receipts=(
                completed_profile_lifecycle_receipts
            ),
            completed_verify_receipts=completed_verify_receipts,
            account_admin_keys=account_admin_keys,
            organization_admin_keys=organization_admin_keys,
            iam_read_cursor_codec=iam_read_cursor_codec,
            trust_receipt_keyring=trust_receipt_keyring,
            trust_sealed_text_keyring=trust_sealed_text_keyring,
            trust_report_cursor_keyring=trust_report_cursor_keyring,
            appeal_receipt_keyring=appeal_receipt_keyring,
            appeal_sealed_text_keyring=appeal_sealed_text_keyring,
            matching_keys=matching_keys,
        )
        runtime_handle = build_internal_sandbox_api(
            InternalSandboxApiDependencies(
                pools=pools,
                runtime_secrets=runtime_secrets,
                iam_presenter_bindings=iam_bindings,
                session_security=session_security,
                origin_policy=origin_policy,
                rate_limiter=rate_limiter,
                telemetry=telemetry,
                runtime_sources=sources,
                editor_service=editor_service,
                account_admin_service=account_admin_service,
                editor_review_queue=review_queue,
                finance_funding_service=finance_funding_service,
                editor_principal_resolver=principal_resolver,
                editor_authorities=authorities,
                editor_evidence=evidence,
                oidc_provider_readiness=oidc_readiness,
                local_server_dependency_readiness=local_server_dependencies,
                schema_readiness=schema_readiness,
                seed_readiness=seed_readiness,
                readiness_timeout_ms=runtime.budgets.readiness_timeout_ms,
                appeal_http_bindings=appeal_bindings,
                matching_http_bindings=matching_bindings,
                matching_runtime=matching_runtime,
                matching_assignment_runtime=matching_assignment_runtime,
                matching_review_runtime=matching_review_runtime,
                matching_operational_service=matching_operational_service,
                trust_http_bindings=trust_bindings,
            )
        )
        from .api_server_plan import InternalSandboxApiServerPlan

        return InternalSandboxApiServerPlan(
            deployment=deployment,
            runtime=runtime_handle,
            graceful_shutdown_timeout_seconds=max(
                1,
                (runtime.budgets.shutdown_timeout_ms + 999) // 1_000,
            ),
        )
    except InternalSandboxSyntheticSeedError as error:
        _cleanup(managed, issued)
        code = (
            "INTERNAL_SANDBOX_SYNTHETIC_SEED_BLOCKED"
            if error.code == "INTERNAL_SANDBOX_SYNTHETIC_SEED_BLOCKED"
            else "INTERNAL_SANDBOX_PRODUCTION_PLAN_INVALID"
        )
        raise InternalSandboxProductionPlanError(code) from None
    except InternalSandboxProductionPlanError:
        _cleanup(managed, issued)
        raise
    except BaseException:
        _cleanup(managed, issued)
        raise InternalSandboxProductionPlanError() from None


def _read_exact(reader: Callable[[str], bytes], path: str) -> bytes:
    raw = reader(path)
    if type(raw) is not bytes:
        _invalid()
    return raw


def _validate_runtime_contract(
    deployment: InternalSandboxDeploymentConfiguration,
    runtime: RuntimeConfiguration,
) -> None:
    if (
        runtime.schema_name != "desire-runtime-config-v1"
        or runtime.process.kind != "web-api"
        or runtime.process.capability_ids
        != tuple(item[0] for item in INTERNAL_SANDBOX_CAPABILITY_ROLES)
        or runtime.artifacts != INTERNAL_SANDBOX_ARTIFACT_REQUIREMENTS
        or tuple(item.capability_id for item in runtime.database_profiles)
        != runtime.process.capability_ids
        or tuple(item.online_role for item in runtime.database_profiles)
        != tuple(item[1] for item in INTERNAL_SANDBOX_CAPABILITY_ROLES)
        or tuple(item.purpose for item in runtime.key_requirements)
        != INTERNAL_SANDBOX_KEY_PURPOSES
    ):
        _invalid()
    for requirement in runtime.key_requirements:
        if (
            not requirement.retained_key_ids
            or requirement.retained_key_ids[0] != requirement.active_key_id
            or (
                requirement.purpose in _HMAC_PURPOSES
                and len(requirement.retained_key_ids) > 8
            )
            or (
                requirement.purpose == "OIDC_PROTOCOL_AEAD"
                and len(requirement.retained_key_ids) > 4
            )
            or (
                requirement.purpose in _INVITATION_TOKEN_PURPOSES
                and len(requirement.retained_key_ids) > 4
            )
            or (
                requirement.purpose in _IAM_READ_CURSOR_PURPOSES
                and len(requirement.retained_key_ids) > 4
            )
            or (
                requirement.purpose in _RECIPIENT_BINDING_PURPOSES
                and len(requirement.retained_key_ids) > 4
            )
            or (
                requirement.purpose in _ORG_ADMIN_RECEIPT_PURPOSES
                and len(requirement.retained_key_ids) > 4
            )
            or (
                requirement.purpose in _TRUST_ROTATING_PURPOSES
                and len(requirement.retained_key_ids) > 4
            )
            or (
                requirement.purpose in _DEMAND_ROTATING_PURPOSES
                and len(requirement.retained_key_ids) > 4
            )
            or (
                requirement.purpose in _SINGLE_KEY_PURPOSES
                and requirement.retained_key_ids != (requirement.active_key_id,)
            )
        ):
            _invalid()
    requirements = {item.purpose: item for item in runtime.key_requirements}
    all_key_ids = tuple(
        key_id
        for requirement in runtime.key_requirements
        for key_id in requirement.retained_key_ids
    )
    if (
        len(set(all_key_ids)) != len(all_key_ids)
        or requirements["DEMAND_IDEMPOTENCY"].retained_key_ids
        != INTERNAL_SANDBOX_DEMAND_IDEMPOTENCY_KEY_IDS
        or requirements["DEMAND_PAYLOAD_HASH"].retained_key_ids
        != INTERNAL_SANDBOX_DEMAND_PAYLOAD_KEY_IDS
        or deployment.oidc.client_secret_key_id
        != requirements["OIDC_CLIENT_SECRET"].active_key_id
        or deployment.oidc.subject_digest_key_id
        != requirements["OIDC_SUBJECT_DIGEST"].active_key_id
        or requirements["DEMAND_IDEMPOTENCY"].active_key_id
        != INTERNAL_SANDBOX_DEMAND_IDEMPOTENCY_KEY_ID
        or requirements["DEMAND_PAYLOAD_HASH"].active_key_id
        != INTERNAL_SANDBOX_DEMAND_PAYLOAD_KEY_ID
        or requirements["TRUST_IDEMPOTENCY"].active_key_id
        != INTERNAL_SANDBOX_TRUST_IDEMPOTENCY_KEY_ID
        or requirements["TRUST_PAYLOAD_HASH"].active_key_id
        != INTERNAL_SANDBOX_TRUST_PAYLOAD_KEY_ID
        or requirements["TRUST_SEALED_NOTE"].active_key_id
        != INTERNAL_SANDBOX_TRUST_SEALED_NOTE_KEY_ID
        or requirements["TRUST_REPORT_CURSOR"].active_key_id
        != INTERNAL_SANDBOX_TRUST_REPORT_CURSOR_KEY_ID
        or requirements["MATCHING_IDEMPOTENCY"].active_key_id
        != INTERNAL_SANDBOX_MATCHING_IDEMPOTENCY_KEY_ID
        or requirements["MATCHING_PAYLOAD_HASH"].active_key_id
        != INTERNAL_SANDBOX_MATCHING_PAYLOAD_KEY_ID
        or requirements["MATCHING_READ_CURSOR"].active_key_id
        != INTERNAL_SANDBOX_MATCHING_READ_CURSOR_KEY_ID
    ):
        _invalid()


def _validate_manifest(
    runtime: RuntimeConfiguration,
    entries: Tuple[FileSecretManifestEntry, ...],
) -> None:
    expected = tuple(
        (
            "DATABASE_CREDENTIAL",
            profile.credential_ref,
            f"DATABASE_CREDENTIAL:{profile.capability_id}",
            profile.credential_ref.rsplit("#", 1)[1],
        )
        for profile in runtime.database_profiles
    ) + tuple(
        ("KEY", None, requirement.purpose, key_id)
        for requirement in runtime.key_requirements
        for key_id in requirement.retained_key_ids
    )
    actual = tuple(
        (entry.kind, entry.credential_ref, entry.purpose, entry.key_id)
        for entry in entries
    )
    if actual != expected:
        _invalid()


def _validate_secret_material(
    runtime: RuntimeConfiguration,
    carriers: Sequence[FileSecretCarrier],
    keys: Mapping[Tuple[str, str], FileSecretCarrier],
) -> None:
    if len({hashlib.sha256(bytes(item.material)).digest() for item in carriers}) != len(
        carriers
    ):
        _invalid()
    requirements = {item.purpose: item for item in runtime.key_requirements}
    for (purpose, key_id), carrier in keys.items():
        requirement = requirements[purpose]
        allowed_statuses = (
            {"ACTIVE"}
            if key_id == requirement.active_key_id
            else {"ACTIVE", "VERIFY_ONLY"}
        )
        if (
            carrier.status not in allowed_statuses
            or (
                purpose in _DEMAND_ROTATING_PURPOSES
                and key_id != requirement.active_key_id
                and carrier.status != "VERIFY_ONLY"
            )
        ):
            _invalid()
        if purpose == "OIDC_PROTOCOL_AEAD" and len(carrier.material) != 32:
            _invalid()
        if purpose not in {"OIDC_CLIENT_SECRET"} and not 32 <= len(
            carrier.material
        ) <= 64:
            _invalid()


def _active_material(
    keys: Mapping[Tuple[str, str], FileSecretCarrier],
    requirements: Mapping[str, KeyRequirement],
    purpose: str,
) -> bytearray:
    return keys[(purpose, requirements[purpose].active_key_id)].material


def _schema_readiness(
    pools: InternalSandboxApiPools,
    *,
    demand_idempotency_key_ids: Tuple[str, ...],
    demand_payload_key_ids: Tuple[str, ...],
) -> Tuple[PostgresSchemaCompatibilityReadiness, ...]:
    artifact_sha = {
        item.artifact_id: bytes.fromhex(item.sha256)
        for item in INTERNAL_SANDBOX_ARTIFACT_REQUIREMENTS
    }
    iam_combined = hashlib.sha256(
        b"iam-v1-contract\x00"
        + artifact_sha["iam-openapi-v1"]
        + artifact_sha["iam-events-v1"]
        + IAM_REVIEWED_MANIFEST_SHA256
    ).digest()
    contracts = resources.files("desire_platform.contracts")
    trust_sources = TrustContractSources(
        api_contract_bytes=contracts.joinpath("api/trust-v1.openapi.yaml").read_bytes(),
        event_contract_bytes=contracts.joinpath("events/trust-v1.schema.json").read_bytes(),
        report_contract_bytes=contracts.joinpath(
            "domain/trust-report-v1.schema.json"
        ).read_bytes(),
        triage_contract_bytes=contracts.joinpath(
            "domain/trust-triage-v1.schema.json"
        ).read_bytes(),
        appeal_api_contract_bytes=contracts.joinpath(
            "api/appeal-v1.openapi.yaml"
        ).read_bytes(),
        appeal_event_contract_bytes=contracts.joinpath(
            "events/appeal-v1.schema.json"
        ).read_bytes(),
        appeal_application_contract_bytes=contracts.joinpath(
            "domain/appeal-application-v1.schema.json"
        ).read_bytes(),
        appeal_review_contract_bytes=contracts.joinpath(
            "domain/appeal-review-v1.schema.json"
        ).read_bytes(),
    )
    trust_combined = trust_combined_contract_sha256(
        sources=trust_sources,
        migration_manifest_sha256=TRUST_REVIEWED_MANIFEST_SHA256,
    )
    return (
        PostgresSchemaCompatibilityReadiness(
            pool=pools.iam_app,
            requirement=SchemaCompatibilityRequirement(
                component="iam",
                expected_schema_head=IAM_SCHEMA_HEAD_VERSION,
                expected_contract_sha256=iam_combined,
                required_iam_schema_version=None,
            ),
        ),
        PostgresSchemaCompatibilityReadiness(
            pool=pools.profile_app,
            requirement=SchemaCompatibilityRequirement(
                component="profile",
                expected_schema_head=PROFILE_SCHEMA_HEAD_VERSION,
                expected_contract_sha256=PROFILE_REVIEWED_MANIFEST_SHA256,
                required_iam_schema_version=None,
            ),
        ),
        PostgresSchemaCompatibilityReadiness(
            pool=pools.demand_self,
            requirement=SchemaCompatibilityRequirement(
                component="demand",
                expected_schema_head=DEMAND_SCHEMA_HEAD_VERSION,
                expected_contract_sha256=DEMAND_REVIEWED_MANIFEST_SHA256,
                required_iam_schema_version=DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
                expected_idempotency_key_id=demand_idempotency_key_ids[0],
                expected_payload_key_id=demand_payload_key_ids[0],
                expected_retained_idempotency_key_ids=(
                    demand_idempotency_key_ids
                ),
                expected_retained_payload_key_ids=demand_payload_key_ids,
            ),
        ),
        PostgresSchemaCompatibilityReadiness(
            pool=pools.trust_self,
            requirement=SchemaCompatibilityRequirement(
                component="trust",
                expected_schema_head=TRUST_SCHEMA_HEAD_VERSION,
                expected_contract_sha256=TRUST_REVIEWED_MANIFEST_SHA256,
                required_iam_schema_version=TRUST_REQUIRED_IAM_SCHEMA_VERSION,
                required_demand_schema_version=(
                    TRUST_REQUIRED_DEMAND_SCHEMA_VERSION
                ),
                expected_iam_contract_sha256=(
                    TRUST_REQUIRED_IAM_CONTRACT_SHA256
                ),
                expected_demand_contract_sha256=(
                    TRUST_REQUIRED_DEMAND_CONTRACT_SHA256
                ),
                expected_combined_contract_sha256=trust_combined,
            ),
        ),
        PostgresSchemaCompatibilityReadiness(
            pool=pools.matching_creator,
            requirement=SchemaCompatibilityRequirement(
                component="matching",
                expected_schema_head=MATCHING_SCHEMA_HEAD_VERSION,
                expected_contract_sha256=MATCHING_REVIEWED_MANIFEST_SHA256,
                required_iam_schema_version=(
                    MATCHING_REQUIRED_IAM_SCHEMA_VERSION
                ),
            ),
        ),
    )


def _validate_schema_contract_constants() -> None:
    if (
        IAM_SCHEMA_HEAD_VERSION != 46
        or PROFILE_SCHEMA_HEAD_VERSION != 5
        or PROFILE_REQUIRED_IAM_SCHEMA_VERSION != 46
        or DEMAND_SCHEMA_HEAD_VERSION != 15
        or DEMAND_REQUIRED_IAM_SCHEMA_VERSION != 45
        or TRUST_SCHEMA_HEAD_VERSION != 22
        or TRUST_REQUIRED_IAM_SCHEMA_VERSION != 46
        or TRUST_REQUIRED_DEMAND_SCHEMA_VERSION != 15
        or MATCHING_SCHEMA_HEAD_VERSION != 3
        or MATCHING_REQUIRED_IAM_SCHEMA_VERSION != 46
    ):
        raise InternalSandboxProductionPlanError(
            "INTERNAL_SANDBOX_SCHEMA_CONTRACT_PENDING"
        )
    for package, expected in (
        (_IAM_MANIFEST_PACKAGE, IAM_REVIEWED_MANIFEST_SHA256),
        (_PROFILE_MANIFEST_PACKAGE, PROFILE_REVIEWED_MANIFEST_SHA256),
        (_DEMAND_MANIFEST_PACKAGE, DEMAND_REVIEWED_MANIFEST_SHA256),
        (_TRUST_MANIFEST_PACKAGE, TRUST_REVIEWED_MANIFEST_SHA256),
        (_MATCHING_MANIFEST_PACKAGE, MATCHING_REVIEWED_MANIFEST_SHA256),
    ):
        try:
            raw = resources.files(package).joinpath("manifest.json").read_bytes()
        except BaseException:
            _invalid()
        if not hmac.compare_digest(hashlib.sha256(raw).digest(), expected):
            _invalid()


def _prove_secret_bindings(
    *,
    runtime_secrets: ManagedRuntimeSecrets,
    pools: InternalSandboxApiPools,
    credentials: Mapping[str, FileSecretCarrier],
    keys: Mapping[Tuple[str, str], FileSecretCarrier],
    keyring: HmacRuntimeKeyring,
    secret_box: AesGcmProtocolSecretBox,
    recipient_binding: HmacRecipientBinding,
    oidc_provider: ClosedOidcProvider,
    editor_keys: EditorPostgresKeys,
    completed_profile_lifecycle_receipts: (
        PsycopgProfileCompletedLifecycleReceiptProbe
    ),
    completed_verify_receipts: PsycopgDemandCompletedVerifyReceiptProbe,
    account_admin_keys: PlatformUserAdminKeys,
    organization_admin_keys: OrganizationAdminKeys,
    iam_read_cursor_codec: HmacIamReadCursorCodec,
    trust_receipt_keyring: TrustPostgresReceiptKeyring,
    trust_sealed_text_keyring: TrustSealedTextKeyring,
    trust_report_cursor_keyring: TrustOwnedReportCursorKeyring,
    appeal_receipt_keyring: AppealPostgresReceiptKeyring,
    appeal_sealed_text_keyring: AppealSealedTextKeyring,
    matching_keys: MatchingPostgresHttpKeys,
) -> None:
    if any(
        getattr(pool, "_credential", None) is not credentials[capability]
        for pool, (capability, _role) in zip(
            pools.values(), INTERNAL_SANDBOX_CAPABILITY_ROLES
        )
    ):
        _invalid()
    referenced = {
        id(item.material)
        for item in credentials.values()
    }
    referenced.update(id(item.material) for item in keyring._keys.values())
    referenced.update(id(item.material) for item in secret_box._keys.values())
    referenced.update(id(item.material) for item in recipient_binding._keys)
    referenced.add(id(oidc_provider._configuration.client_secret))
    referenced.add(id(oidc_provider._subject_digest_key))
    referenced.update(
        id(value)
        for value in (
            editor_keys.id_key,
            editor_keys.profile_idempotency_key,
            editor_keys.profile_payload_key,
            editor_keys.demand_idempotency_key,
            editor_keys.demand_payload_key,
            editor_keys.demand_client_reference_key,
            account_admin_keys.idempotency_key,
            account_admin_keys.payload_hash_key,
        )
    )
    referenced.update(
        id(material)
        for _key_id, material in organization_admin_keys.invitation_token_keys
    )
    referenced.update(
        id(item.material) for item in iam_read_cursor_codec._keys.values()
    )
    referenced.update(
        id(item.material) for item in trust_receipt_keyring._keys.values()
    )
    referenced.update(
        id(item.material) for item in trust_sealed_text_keyring._keys.values()
    )
    referenced.update(
        id(item.material) for item in trust_report_cursor_keyring._keys.values()
    )
    referenced.update(
        id(item.material) for item in appeal_receipt_keyring._keys.values()
    )
    referenced.update(
        id(item.material) for item in appeal_sealed_text_keyring._keys.values()
    )
    referenced.update(
        id(material)
        for material in (
            matching_keys.idempotency_key,
            matching_keys.payload_hash_key,
            matching_keys.read_cursor_key,
        )
    )
    referenced.update(
        id(material)
        for _key_id, material in (
            completed_profile_lifecycle_receipts._idempotency_keys
            + completed_profile_lifecycle_receipts._payload_hash_keys
        )
    )
    referenced.update(
        id(material)
        for _key_id, material in (
            completed_verify_receipts._idempotency_keys
            + completed_verify_receipts._payload_hash_keys
        )
    )
    if referenced != {id(item.material) for item in runtime_secrets.carriers}:
        _invalid()
    if len({bytes(item.material) for item in runtime_secrets.carriers}) != len(
        runtime_secrets.carriers
    ):
        _invalid()
    if any(
        item.material is not keys[identity].material
        for identity, item in keyring._keys.items()
    ) or any(
        item.material is not keys[("OIDC_PROTOCOL_AEAD", key_id)].material
        for key_id, item in secret_box._keys.items()
    ) or any(
        item.material is not keys[("IAM_READ_CURSOR", key_id)].material
        for key_id, item in iam_read_cursor_codec._keys.items()
    ) or any(
        item.material
        is not keys[("OIDC_RECIPIENT_BINDING", item.key_id)].material
        for item in recipient_binding._keys
    ) or any(
        item.material
        is not keys[(
            "TRUST_IDEMPOTENCY"
            if item.purpose == "IDEMPOTENCY"
            else "TRUST_PAYLOAD_HASH",
            item.key_id,
        )].material
        for item in trust_receipt_keyring._keys.values()
    ) or any(
        item.material is not keys[("TRUST_SEALED_NOTE", item.key_id)].material
        for item in trust_sealed_text_keyring._keys.values()
    ) or any(
        item.material
        is not keys[("TRUST_REPORT_CURSOR", item.key_id)].material
        for item in trust_report_cursor_keyring._keys.values()
    ) or any(
        item.material
        is not keys[(
            "TRUST_IDEMPOTENCY"
            if item.purpose == "IDEMPOTENCY"
            else "TRUST_PAYLOAD_HASH",
            item.key_id,
        )].material
        for item in appeal_receipt_keyring._keys.values()
    ) or any(
        item.material is not keys[("TRUST_SEALED_NOTE", item.key_id)].material
        for item in appeal_sealed_text_keyring._keys.values()
    ) or any(
        material
        is not keys[("PROFILE_IDEMPOTENCY", key_id)].material
        for key_id, material in (
            completed_profile_lifecycle_receipts._idempotency_keys
        )
    ) or any(
        material
        is not keys[("PROFILE_PAYLOAD_HASH", key_id)].material
        for key_id, material in (
            completed_profile_lifecycle_receipts._payload_hash_keys
        )
    ) or any(
        material
        is not keys[("DEMAND_IDEMPOTENCY", key_id)].material
        for key_id, material in completed_verify_receipts._idempotency_keys
    ) or any(
        material
        is not keys[("DEMAND_PAYLOAD_HASH", key_id)].material
        for key_id, material in completed_verify_receipts._payload_hash_keys
    ) or any(
        material is not keys[identity].material
        for material, identity in (
            (
                matching_keys.idempotency_key,
                (
                    "MATCHING_IDEMPOTENCY",
                    matching_keys.idempotency_key_id,
                ),
            ),
            (
                matching_keys.payload_hash_key,
                (
                    "MATCHING_PAYLOAD_HASH",
                    matching_keys.payload_hash_key_id,
                ),
            ),
            (
                matching_keys.read_cursor_key,
                (
                    "MATCHING_READ_CURSOR",
                    matching_keys.read_cursor_key_id,
                ),
            ),
        )
    ):
        _invalid()


def _cleanup(resources_to_close: Sequence[Any], carriers: Sequence[Any]) -> None:
    seen = set()
    for resource in reversed(tuple(resources_to_close)):
        identity = id(resource)
        if identity in seen:
            continue
        seen.add(identity)
        try:
            resource.close()
        except BaseException:
            pass
    for carrier in reversed(tuple(carriers)):
        try:
            carrier.destroy()
        except BaseException:
            pass


def _invalid() -> Any:
    raise InternalSandboxProductionPlanError()


__all__ = [
    "INTERNAL_SANDBOX_ARTIFACT_REQUIREMENTS",
    "INTERNAL_SANDBOX_CAPABILITY_ROLES",
    "INTERNAL_SANDBOX_DEMAND_IDEMPOTENCY_KEY_ID",
    "INTERNAL_SANDBOX_DEMAND_IDEMPOTENCY_KEY_IDS",
    "INTERNAL_SANDBOX_DEMAND_PAYLOAD_KEY_ID",
    "INTERNAL_SANDBOX_DEMAND_PAYLOAD_KEY_IDS",
    "INTERNAL_SANDBOX_KEY_PURPOSES",
    "INTERNAL_SANDBOX_MATCHING_RUNTIME_CAPABILITY_ROLES",
    "INTERNAL_SANDBOX_MATCHING_RUNTIME_KEY_PURPOSES",
    "INTERNAL_SANDBOX_ONLINE_CAPABILITY_ROLES",
    "INTERNAL_SANDBOX_MATCHING_IDEMPOTENCY_KEY_ID",
    "INTERNAL_SANDBOX_MATCHING_PAYLOAD_KEY_ID",
    "INTERNAL_SANDBOX_MATCHING_READ_CURSOR_KEY_ID",
    "INTERNAL_SANDBOX_TRUST_IDEMPOTENCY_KEY_ID",
    "INTERNAL_SANDBOX_TRUST_PAYLOAD_KEY_ID",
    "INTERNAL_SANDBOX_TRUST_SEALED_NOTE_KEY_ID",
    "INTERNAL_SANDBOX_TRUST_REPORT_CURSOR_KEY_ID",
    "InternalSandboxProductionPlanError",
    "build_internal_sandbox_server_plan",
]
