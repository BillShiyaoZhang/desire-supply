"""Deployment-only composition boundaries."""

from importlib import import_module

from .migrations import (
    DATABASE_ROLE_SPECS,
    IAM42_PUBLIC_NAME_PREDICATE_VERSION,
    MIGRATION_MEMBERSHIPS,
    DeploymentIam42PublicNamePreflightError,
    DeploymentMigrationConfigurationError,
    DeploymentMigrationError,
    DeploymentMigrationReport,
    DeploymentMigrationSettings,
    Iam42PublicNamePreflightReport,
    apply_reviewed_migrations,
    load_settings,
)
from .identity_bootstrap import (
    BOOTSTRAP_ROLE,
    IDENTITY_BOOTSTRAP_MANIFEST_FILE_ENV,
    IDENTITY_BOOTSTRAP_MANIFEST_SHA256_ENV,
    IDENTITY_BOOTSTRAP_SCHEMA,
    IdentityBootstrapAction,
    IdentityBootstrapConfigurationError,
    IdentityBootstrapError,
    IdentityBootstrapOutcome,
    IdentityBootstrapReport,
    apply_internal_sandbox_identity_bootstrap,
    load_identity_bootstrap_inputs,
    parse_internal_sandbox_identity_manifest,
    revoke_internal_sandbox_identity_bootstrap_access,
    verify_internal_sandbox_identity_bootstrap,
)
from .identity_bootstrap_manifest import (
    GeneratedIdentityBootstrapManifest,
    IDENTITY_BOOTSTRAP_OUTPUT_FILE_ENV,
    IDENTITY_BOOTSTRAP_SOURCE_ROOT_ENV,
    IDENTITY_BOOTSTRAP_TEMPLATE_FILE_ENV,
    IDENTITY_BOOTSTRAP_TEMPLATE_SCHEMA,
    IDENTITY_BOOTSTRAP_TEMPLATE_SHA256_ENV,
    IdentityBootstrapManifestGenerationError,
    generate_identity_bootstrap_manifest_file,
    generate_internal_sandbox_identity_manifest,
)
from .preprovisioned_identity_bootstrap_manifest import (
    GeneratedPreprovisionedIdentityBootstrapManifest,
    PREPROVISIONED_IDENTITY_BOOTSTRAP_OUTPUT_FILE_ENV,
    PREPROVISIONED_IDENTITY_BOOTSTRAP_SOURCE_ROOT_ENV,
    PREPROVISIONED_IDENTITY_BOOTSTRAP_TEMPLATE_FILE_ENV,
    PREPROVISIONED_IDENTITY_BOOTSTRAP_TEMPLATE_SHA256_ENV,
    PreprovisionedIdentityBootstrapManifestGenerationError,
    generate_preprovisioned_identity_bootstrap_manifest,
    generate_preprovisioned_identity_bootstrap_manifest_file,
)

_ONLINE_CREDENTIAL_EXPORTS = frozenset(
    {
        "ONLINE_ROLE_CREDENTIAL_SPECS",
        "OnlineRoleCredentialAction",
        "OnlineRoleCredentialConfigurationError",
        "OnlineRoleCredentialError",
        "OnlineRoleCredentialInputs",
        "OnlineRoleCredentialReport",
        "OnlineRoleCredentialSpec",
        "load_online_role_credential_inputs",
        "reconcile_online_role_credentials",
        "revoke_online_role_credentials",
        "verify_online_role_credentials",
    }
)


def __getattr__(name: str):
    if name not in _ONLINE_CREDENTIAL_EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(".online_credentials", __name__), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | _ONLINE_CREDENTIAL_EXPORTS)

__all__ = (
    "DATABASE_ROLE_SPECS",
    "IAM42_PUBLIC_NAME_PREDICATE_VERSION",
    "MIGRATION_MEMBERSHIPS",
    "DeploymentIam42PublicNamePreflightError",
    "DeploymentMigrationConfigurationError",
    "DeploymentMigrationError",
    "DeploymentMigrationReport",
    "DeploymentMigrationSettings",
    "Iam42PublicNamePreflightReport",
    "apply_reviewed_migrations",
    "load_settings",
    "ONLINE_ROLE_CREDENTIAL_SPECS",
    "OnlineRoleCredentialAction",
    "OnlineRoleCredentialConfigurationError",
    "OnlineRoleCredentialError",
    "OnlineRoleCredentialInputs",
    "OnlineRoleCredentialReport",
    "OnlineRoleCredentialSpec",
    "load_online_role_credential_inputs",
    "reconcile_online_role_credentials",
    "revoke_online_role_credentials",
    "verify_online_role_credentials",
    "BOOTSTRAP_ROLE",
    "IDENTITY_BOOTSTRAP_MANIFEST_FILE_ENV",
    "IDENTITY_BOOTSTRAP_MANIFEST_SHA256_ENV",
    "IDENTITY_BOOTSTRAP_SCHEMA",
    "IdentityBootstrapAction",
    "IdentityBootstrapConfigurationError",
    "IdentityBootstrapError",
    "IdentityBootstrapOutcome",
    "IdentityBootstrapReport",
    "apply_internal_sandbox_identity_bootstrap",
    "load_identity_bootstrap_inputs",
    "parse_internal_sandbox_identity_manifest",
    "revoke_internal_sandbox_identity_bootstrap_access",
    "verify_internal_sandbox_identity_bootstrap",
    "GeneratedIdentityBootstrapManifest",
    "IDENTITY_BOOTSTRAP_OUTPUT_FILE_ENV",
    "IDENTITY_BOOTSTRAP_SOURCE_ROOT_ENV",
    "IDENTITY_BOOTSTRAP_TEMPLATE_FILE_ENV",
    "IDENTITY_BOOTSTRAP_TEMPLATE_SCHEMA",
    "IDENTITY_BOOTSTRAP_TEMPLATE_SHA256_ENV",
    "IdentityBootstrapManifestGenerationError",
    "generate_identity_bootstrap_manifest_file",
    "generate_internal_sandbox_identity_manifest",
    "GeneratedPreprovisionedIdentityBootstrapManifest",
    "PREPROVISIONED_IDENTITY_BOOTSTRAP_OUTPUT_FILE_ENV",
    "PREPROVISIONED_IDENTITY_BOOTSTRAP_SOURCE_ROOT_ENV",
    "PREPROVISIONED_IDENTITY_BOOTSTRAP_TEMPLATE_FILE_ENV",
    "PREPROVISIONED_IDENTITY_BOOTSTRAP_TEMPLATE_SHA256_ENV",
    "PreprovisionedIdentityBootstrapManifestGenerationError",
    "generate_preprovisioned_identity_bootstrap_manifest",
    "generate_preprovisioned_identity_bootstrap_manifest_file",
)
