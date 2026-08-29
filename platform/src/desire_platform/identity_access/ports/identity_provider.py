"""Provider-neutral OIDC Authorization Code + PKCE contract."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol, Tuple

from .recipient_binding import RecipientBindingTuple


class IdentityProviderUnavailableError(RuntimeError):
    """A pre-exchange provider dependency is explicitly unavailable."""


class IdentityProviderRejectedError(RuntimeError):
    """The provider explicitly rejected or invalidated the authentication."""


class IdentityProviderResultUnknownError(RuntimeError):
    """A code may have been consumed but no trustworthy result is known."""


class IdentityProviderMisconfiguredError(RuntimeError):
    """The configured provider trust boundary is invalid."""


@dataclass(frozen=True)
class ProviderAuthorization:
    authorization_url: str = field(repr=False)
    issuer: str
    audience: str
    redirect_uri: str
    code_challenge_method: str


@dataclass(frozen=True)
class ProviderExchangeRequest:
    auth_transaction_id: str
    code: str = field(repr=False)
    state: str = field(repr=False)
    redirect_uri: str
    code_verifier: str = field(repr=False)
    expected_nonce: str = field(repr=False)
    expected_issuer: str
    expected_audience: str
    server_now: datetime


@dataclass(frozen=True)
class AuthenticatedSubject:
    issuer: str
    subject_digest: str = field(repr=False)
    subject_digest_key_id: str
    verified_recipient_binding: RecipientBindingTuple
    auth_time: datetime
    acr_code: str
    amr_codes: Tuple[str, ...]
    token_issued_at: datetime
    token_expires_at: datetime
    provider_session_reference: str | None = field(default=None, repr=False)
    verified_recipient_binding_candidates: Tuple[
        RecipientBindingTuple, ...
    ] = field(default=(), repr=False)


class IdentityProviderPort(Protocol):
    def preflight(
        self,
        *,
        expected_issuer: str,
        expected_audience: str,
        redirect_uri: str,
    ) -> None:
        ...

    def begin(
        self,
        *,
        auth_transaction_id: str,
        redirect_uri: str,
        code_challenge: str,
        state: str,
        nonce: str,
        expected_issuer: str,
        expected_audience: str,
    ) -> ProviderAuthorization:
        ...

    def preflight_exchange(
        self,
        *,
        expected_issuer: str,
        expected_audience: str,
        redirect_uri: str,
    ) -> None:
        """Warm discovery and verification keys before claiming a code."""
        ...

    def exchange(
        self,
        request: ProviderExchangeRequest,
    ) -> AuthenticatedSubject:
        ...
