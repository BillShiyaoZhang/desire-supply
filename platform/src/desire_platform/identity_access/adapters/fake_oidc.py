"""Deterministic OIDC adapter scaffold for the authentication RED slice."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import hashlib
from typing import Dict, Optional, Tuple
from urllib.parse import urlencode

from ..ports.identity_provider import (
    AuthenticatedSubject,
    IdentityProviderMisconfiguredError,
    IdentityProviderRejectedError,
    ProviderAuthorization,
    ProviderExchangeRequest,
)


@dataclass(frozen=True)
class FakeOidcCode:
    code: str = field(repr=False)
    state: str = field(repr=False)
    nonce: str = field(repr=False)
    code_challenge: str
    redirect_uri: str
    issuer: str
    audiences: Tuple[str, ...]
    authorized_party: Optional[str]
    raw_subject: str = field(repr=False)
    verified_contact_type: str
    verified_locator: str = field(repr=False)
    auth_time: datetime
    issued_at: datetime
    not_before: Optional[datetime]
    expires_at: datetime
    acr_code: str
    amr_codes: Tuple[str, ...]


@dataclass(frozen=True)
class FakeBeginCall:
    auth_transaction_id: str
    redirect_uri: str
    code_challenge: str
    state: str = field(repr=False)
    nonce: str = field(repr=False)
    expected_issuer: str
    expected_audience: str


class DeterministicFakeOidcProvider:
    """Importable strict fake whose protocol behavior is intentionally absent."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        recipient_binding,
        subject_digest_key_id: str = "oidc-subject-digest-2026-01",
    ) -> None:
        self.issuer = issuer
        self.audience = audience
        self.recipient_binding = recipient_binding
        self.subject_digest_key_id = subject_digest_key_id
        self.codes: Dict[str, FakeOidcCode] = {}
        self.used_codes: set[str] = set()
        self.preflight_calls: list[dict[str, str]] = []
        self.begin_calls: list[FakeBeginCall] = []
        self.exchange_calls: list[ProviderExchangeRequest] = []
        self.preflight_failure: Optional[Exception] = None
        self.begin_failure: Optional[Exception] = None
        self.exchange_failure: Optional[Exception] = None

    def register_code(self, script: FakeOidcCode) -> None:
        self.codes[script.code] = script

    def preflight(
        self,
        *,
        expected_issuer: str,
        expected_audience: str,
        redirect_uri: str,
    ) -> None:
        self.preflight_calls.append(
            {
                "expected_issuer": expected_issuer,
                "expected_audience": expected_audience,
                "redirect_uri": redirect_uri,
            }
        )
        if self.preflight_failure is not None:
            raise self.preflight_failure
        self._require_configuration(
            expected_issuer=expected_issuer,
            expected_audience=expected_audience,
            redirect_uri=redirect_uri,
        )

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
        self.begin_calls.append(
            FakeBeginCall(
                auth_transaction_id=auth_transaction_id,
                redirect_uri=redirect_uri,
                code_challenge=code_challenge,
                state=state,
                nonce=nonce,
                expected_issuer=expected_issuer,
                expected_audience=expected_audience,
            )
        )
        if self.begin_failure is not None:
            raise self.begin_failure
        self._require_configuration(
            expected_issuer=expected_issuer,
            expected_audience=expected_audience,
            redirect_uri=redirect_uri,
        )
        if (
            not auth_transaction_id
            or not code_challenge
            or not state
            or not nonce
        ):
            raise IdentityProviderMisconfiguredError(
                "synthetic OIDC begin facts are incomplete"
            )
        query = urlencode(
            {
                "client_id": expected_audience,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": "openid",
                "state": state,
                "nonce": nonce,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }
        )
        return ProviderAuthorization(
            authorization_url=self.issuer + "/authorize?" + query,
            issuer=self.issuer,
            audience=self.audience,
            redirect_uri=redirect_uri,
            code_challenge_method="S256",
        )

    def exchange(
        self,
        request: ProviderExchangeRequest,
    ) -> AuthenticatedSubject:
        self.exchange_calls.append(request)
        if request.code in self.used_codes:
            raise IdentityProviderRejectedError(
                "synthetic authorization code is no longer available"
            )
        script = self.codes.get(request.code)
        if script is None:
            raise IdentityProviderRejectedError(
                "synthetic authorization code is invalid"
            )
        self.used_codes.add(request.code)
        if self.exchange_failure is not None:
            raise self.exchange_failure

        self._require_configuration(
            expected_issuer=request.expected_issuer,
            expected_audience=request.expected_audience,
            redirect_uri=request.redirect_uri,
        )
        if request.state != script.state:
            raise IdentityProviderRejectedError("synthetic state mismatch")
        if request.expected_nonce != script.nonce:
            raise IdentityProviderRejectedError("synthetic nonce mismatch")
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(request.code_verifier.encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        if challenge != script.code_challenge:
            raise IdentityProviderRejectedError("synthetic PKCE mismatch")
        if request.redirect_uri != script.redirect_uri:
            raise IdentityProviderRejectedError("synthetic redirect mismatch")
        if script.issuer != request.expected_issuer:
            raise IdentityProviderRejectedError("synthetic issuer mismatch")
        if request.expected_audience not in script.audiences:
            raise IdentityProviderRejectedError("synthetic audience mismatch")
        if len(script.audiences) > 1 and (
            script.authorized_party != request.expected_audience
        ):
            raise IdentityProviderRejectedError(
                "synthetic authorized party mismatch"
            )
        _require_utc(request.server_now)
        for value in (
            script.auth_time,
            script.issued_at,
            script.expires_at,
        ):
            _require_utc(value)
        if script.not_before is not None:
            _require_utc(script.not_before)
        if (
            script.issued_at > request.server_now
            or (
                script.not_before is not None
                and script.not_before > request.server_now
            )
            or request.server_now >= script.expires_at
            or script.auth_time > request.server_now
        ):
            raise IdentityProviderRejectedError(
                "synthetic token time window is invalid"
            )
        bind_candidates = getattr(
            self.recipient_binding, "bind_verified_candidates", None
        )
        if callable(bind_candidates):
            bindings = bind_candidates(
                contact_type=script.verified_contact_type,
                verified_locator=script.verified_locator,
            )
        else:
            bindings = (
                self.recipient_binding.bind_verified(
                    contact_type=script.verified_contact_type,
                    verified_locator=script.verified_locator,
                ),
            )
        if not isinstance(bindings, tuple) or not 1 <= len(bindings) <= 4:
            raise IdentityProviderRejectedError(
                "synthetic recipient binding registry is invalid"
            )
        binding = bindings[0]
        return AuthenticatedSubject(
            issuer=script.issuer,
            subject_digest=hashlib.sha256(
                script.raw_subject.encode("utf-8")
            ).hexdigest(),
            subject_digest_key_id=self.subject_digest_key_id,
            verified_recipient_binding=binding,
            auth_time=script.auth_time,
            acr_code=script.acr_code,
            amr_codes=script.amr_codes,
            token_issued_at=script.issued_at,
            token_expires_at=script.expires_at,
            provider_session_reference=(
                "synthetic-provider-session:"
                + hashlib.sha256(script.code.encode("utf-8")).hexdigest()[:16]
            ),
            verified_recipient_binding_candidates=bindings,
        )

    def _require_configuration(
        self,
        *,
        expected_issuer: str,
        expected_audience: str,
        redirect_uri: str,
    ) -> None:
        if (
            expected_issuer != self.issuer
            or expected_audience != self.audience
            or not redirect_uri.startswith("https://")
        ):
            raise IdentityProviderRejectedError(
                "synthetic provider binding mismatch"
            )


def _require_utc(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise IdentityProviderMisconfiguredError(
            "synthetic provider time must be aware UTC"
        )
