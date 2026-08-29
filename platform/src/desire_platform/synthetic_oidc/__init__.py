"""Controlled, synthetic-only OIDC provider for ``INTERNAL_SANDBOX``.

This package is a deployment fixture, not a production identity provider.  Its
public trust boundary is deliberately immutable so it cannot become an
arbitrary persona or claim minting interface.
"""

from .provider import (
    CLIENT_ID,
    ISSUER,
    REDIRECT_URI,
    SYNTHETIC_ACCOUNTS,
    SYNTHETIC_BOOTSTRAP_ACCOUNTS,
    SYNTHETIC_PROVIDER_ACCOUNTS,
    SYNTHETIC_PROVIDER_ONLY_ACCOUNTS,
    SyntheticAccount,
    SyntheticOidcConfiguration,
    SyntheticOidcConfigurationError,
    SyntheticOidcProvider,
    SyntheticOidcResponse,
    load_synthetic_oidc_configuration,
)

__all__ = [
    "CLIENT_ID",
    "ISSUER",
    "REDIRECT_URI",
    "SYNTHETIC_ACCOUNTS",
    "SYNTHETIC_BOOTSTRAP_ACCOUNTS",
    "SYNTHETIC_PROVIDER_ACCOUNTS",
    "SYNTHETIC_PROVIDER_ONLY_ACCOUNTS",
    "SyntheticAccount",
    "SyntheticOidcConfiguration",
    "SyntheticOidcConfigurationError",
    "SyntheticOidcProvider",
    "SyntheticOidcResponse",
    "load_synthetic_oidc_configuration",
]
