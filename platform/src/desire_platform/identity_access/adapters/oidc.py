"""Fail-closed OpenID Connect Authorization Code + PKCE adapter.

HTTP and JOSE are deliberately injected at this boundary.  The adapter owns
the protocol invariants and secret-handling rules; concrete transports and
token verifiers can be selected by the production composition root without
making the authentication application depend on either library.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import ssl
import time
from typing import Any, Mapping, Protocol, Sequence, Tuple, Union
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from ..ports.identity_provider import (
    AuthenticatedSubject,
    IdentityProviderMisconfiguredError,
    IdentityProviderRejectedError,
    IdentityProviderResultUnknownError,
    IdentityProviderUnavailableError,
    ProviderAuthorization,
    ProviderExchangeRequest,
)


class OidcJsonTransport(Protocol):
    """Bounded JSON transport used by the OIDC protocol adapter."""

    def get_json(
        self,
        *,
        url: str,
        timeout_seconds: int,
        maximum_bytes: int,
    ) -> Mapping[str, Any]:
        ...

    def post_form_json(
        self,
        *,
        url: str,
        form: Mapping[str, str],
        timeout_seconds: int,
        maximum_bytes: int,
    ) -> Mapping[str, Any]:
        ...


class OidcTokenVerifier(Protocol):
    """JOSE implementation boundary.

    An implementation must verify the JWS before returning claims.  The
    adapter validates the returned claims again so a verifier cannot silently
    widen the configured trust boundary.
    """

    def verify_id_token(self, **facts: Any) -> Mapping[str, Any]:
        ...


@dataclass(frozen=True)
class OidcProviderConfiguration:
    issuer: str
    client_id: str
    client_secret: Union[str, bytearray] = field(repr=False)
    redirect_uri: str
    allowed_signing_algorithms: Tuple[str, ...]
    metadata_ttl_seconds: int
    request_timeout_seconds: int
    maximum_response_bytes: int
    clock_skew_seconds: int
    subject_digest_key_id: str

    def __post_init__(self) -> None:
        _require_https_url(
            self.issuer,
            field_name="issuer",
            allow_path=True,
            allow_query=False,
        )
        _require_https_url(
            self.redirect_uri,
            field_name="redirect_uri",
            allow_path=True,
        )
        if self.issuer.endswith("/"):
            raise IdentityProviderMisconfiguredError(
                "OIDC issuer must use its exact canonical value"
            )
        if not self.client_id or not _valid_client_secret(self.client_secret):
            raise IdentityProviderMisconfiguredError(
                "OIDC client credentials are incomplete"
            )
        algorithms = tuple(self.allowed_signing_algorithms)
        if (
            not algorithms
            or len(set(algorithms)) != len(algorithms)
            or any(
                not isinstance(value, str)
                or not value
                or value.lower() == "none"
                for value in algorithms
            )
        ):
            raise IdentityProviderMisconfiguredError(
                "OIDC signing algorithm allowlist is invalid"
            )
        if any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or value <= 0
            for value in (
                self.metadata_ttl_seconds,
                self.request_timeout_seconds,
                self.maximum_response_bytes,
            )
        ):
            raise IdentityProviderMisconfiguredError(
                "OIDC transport bounds must be positive integers"
            )
        if (
            not isinstance(self.clock_skew_seconds, int)
            or isinstance(self.clock_skew_seconds, bool)
            or self.clock_skew_seconds < 0
            or self.clock_skew_seconds > 300
        ):
            raise IdentityProviderMisconfiguredError(
                "OIDC clock skew is outside the closed range"
            )
        if not self.subject_digest_key_id:
            raise IdentityProviderMisconfiguredError(
                "OIDC subject digest key id is required"
            )


@dataclass(frozen=True)
class _ProviderMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    signing_algorithms: Tuple[str, ...]


class ClosedOidcProvider:
    """Strict OIDC provider adapter with no ambient network or key access."""

    def __init__(
        self,
        *,
        configuration: OidcProviderConfiguration,
        transport: OidcJsonTransport,
        token_verifier: OidcTokenVerifier,
        recipient_binding: Any,
        subject_digest_key: Union[bytes, bytearray],
    ) -> None:
        if (
            not isinstance(subject_digest_key, (bytes, bytearray))
            or not 16 <= len(subject_digest_key) <= 4_096
            or not any(subject_digest_key)
        ):
            raise IdentityProviderMisconfiguredError(
                "OIDC subject digest key material is invalid"
            )
        self._configuration = configuration
        self._transport = transport
        self._token_verifier = token_verifier
        self._recipient_binding = recipient_binding
        self._subject_digest_key = subject_digest_key
        self._metadata: _ProviderMetadata | None = None
        self._metadata_deadline = 0.0
        self._jwks: Mapping[str, Any] | None = None
        self._jwks_uri: str | None = None
        self._jwks_deadline = 0.0

    def preflight(
        self,
        *,
        expected_issuer: str,
        expected_audience: str,
        redirect_uri: str,
    ) -> None:
        self._require_application_binding(
            expected_issuer=expected_issuer,
            expected_audience=expected_audience,
            redirect_uri=redirect_uri,
        )
        self._load_metadata(force=True)

    def preflight_exchange(
        self,
        *,
        expected_issuer: str,
        expected_audience: str,
        redirect_uri: str,
    ) -> None:
        """Resolve and validate discovery plus keys before a code is claimed.

        A callback orchestrator must call this while its AuthTransaction is
        still PENDING.  ``exchange`` then reuses the bounded cache, so a JWKS
        outage cannot unnecessarily strand an already claimed one-time code.
        """

        self._require_application_binding(
            expected_issuer=expected_issuer,
            expected_audience=expected_audience,
            redirect_uri=redirect_uri,
        )
        metadata = self._load_metadata()
        self._load_jwks(metadata.jwks_uri, force=True)

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
        self._require_application_binding(
            expected_issuer=expected_issuer,
            expected_audience=expected_audience,
            redirect_uri=redirect_uri,
        )
        if not auth_transaction_id or not state or not nonce:
            raise IdentityProviderMisconfiguredError(
                "OIDC authorization transaction facts are incomplete"
            )
        _require_pkce_challenge(code_challenge)
        metadata = self._load_metadata()
        query = urlencode(
            {
                "client_id": self._configuration.client_id,
                "redirect_uri": self._configuration.redirect_uri,
                "response_type": "code",
                "scope": "openid email",
                "state": state,
                "nonce": nonce,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }
        )
        return ProviderAuthorization(
            authorization_url=metadata.authorization_endpoint + "?" + query,
            issuer=metadata.issuer,
            audience=self._configuration.client_id,
            redirect_uri=self._configuration.redirect_uri,
            code_challenge_method="S256",
        )

    def exchange(self, request: ProviderExchangeRequest) -> AuthenticatedSubject:
        self._require_application_binding(
            expected_issuer=request.expected_issuer,
            expected_audience=request.expected_audience,
            redirect_uri=request.redirect_uri,
        )
        _require_utc(request.server_now)
        if (
            not request.auth_transaction_id
            or not request.code
            or not request.code_verifier
            or not request.expected_nonce
            or not request.state
        ):
            raise IdentityProviderRejectedError(
                "OIDC exchange transaction facts are incomplete"
            )
        _require_pkce_verifier(request.code_verifier)

        # Discovery and keys are resolved before sending the one-time code.  A
        # failure here is safely retryable; a transport failure after POST is
        # deliberately classified as unknown because the code may be consumed.
        metadata = self._load_metadata()
        jwks = self._load_jwks(metadata.jwks_uri)
        form = {
            "grant_type": "authorization_code",
            "code": request.code,
            "redirect_uri": request.redirect_uri,
            "client_id": self._configuration.client_id,
            # A production composition may retain this secret in a destructible
            # carrier.  Decode only for the request-local form and never cache
            # an immutable copy on the provider or its configuration.
            "client_secret": _client_secret_text(
                self._configuration.client_secret
            ),
            "code_verifier": request.code_verifier,
        }
        try:
            token_response = self._transport.post_form_json(
                url=metadata.token_endpoint,
                form=form,
                timeout_seconds=self._configuration.request_timeout_seconds,
                maximum_bytes=self._configuration.maximum_response_bytes,
            )
        except Exception:
            raise IdentityProviderResultUnknownError(
                "OIDC token exchange result is unknown"
            ) from None
        id_token = _extract_id_token(token_response)
        try:
            returned_claims = self._token_verifier.verify_id_token(
                id_token=id_token,
                jwks=jwks,
                allowed_signing_algorithms=self._configuration.allowed_signing_algorithms,
                expected_issuer=request.expected_issuer,
                expected_audience=request.expected_audience,
                expected_nonce=request.expected_nonce,
                server_now=request.server_now,
                clock_skew_seconds=self._configuration.clock_skew_seconds,
            )
        except IdentityProviderRejectedError:
            raise
        except IdentityProviderMisconfiguredError:
            raise
        except Exception:
            raise IdentityProviderResultUnknownError(
                "OIDC token verification result is unknown"
            ) from None

        claims = _require_mapping(returned_claims, "OIDC claims")
        validated = self._validate_claims(
            claims=claims,
            request=request,
        )
        bind_candidates = getattr(
            self._recipient_binding, "bind_verified_candidates", None
        )
        if callable(bind_candidates):
            bindings = bind_candidates(
                contact_type="EMAIL",
                verified_locator=validated["email"],
            )
        else:
            bindings = (
                self._recipient_binding.bind_verified(
                    contact_type="EMAIL",
                    verified_locator=validated["email"],
                ),
            )
        if not isinstance(bindings, tuple) or not 1 <= len(bindings) <= 4:
            raise IdentityProviderMisconfiguredError(
                "OIDC recipient binding registry is invalid"
            )
        binding = bindings[0]
        subject_digest = hmac.new(
            self._subject_digest_key,
            (
                "oidc-subject-v1\x00"
                + validated["issuer"]
                + "\x00"
                + validated["subject"]
            ).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        provider_session_reference = None
        if validated["session_id"] is not None:
            provider_session_reference = hmac.new(
                self._subject_digest_key,
                (
                    "oidc-session-v1\x00" + validated["session_id"]
                ).encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
        return AuthenticatedSubject(
            issuer=validated["issuer"],
            subject_digest=subject_digest,
            subject_digest_key_id=self._configuration.subject_digest_key_id,
            verified_recipient_binding=binding,
            auth_time=validated["auth_time"],
            acr_code=validated["acr"],
            amr_codes=validated["amr"],
            token_issued_at=validated["issued_at"],
            token_expires_at=validated["expires_at"],
            provider_session_reference=provider_session_reference,
            verified_recipient_binding_candidates=bindings,
        )

    def _require_application_binding(
        self,
        *,
        expected_issuer: str,
        expected_audience: str,
        redirect_uri: str,
    ) -> None:
        if (
            expected_issuer != self._configuration.issuer
            or expected_audience != self._configuration.client_id
            or redirect_uri != self._configuration.redirect_uri
        ):
            raise IdentityProviderMisconfiguredError(
                "OIDC application binding does not match configuration"
            )

    def _load_metadata(self, *, force: bool = False) -> _ProviderMetadata:
        if (
            not force
            and self._metadata is not None
            and time.monotonic() < self._metadata_deadline
        ):
            return self._metadata
        discovery_url = (
            self._configuration.issuer
            + "/.well-known/openid-configuration"
        )
        try:
            document = self._transport.get_json(
                url=discovery_url,
                timeout_seconds=self._configuration.request_timeout_seconds,
                maximum_bytes=self._configuration.maximum_response_bytes,
            )
        except Exception:
            raise IdentityProviderUnavailableError(
                "OIDC discovery is unavailable"
            ) from None
        metadata = self._validate_metadata(document)
        self._metadata = metadata
        self._metadata_deadline = (
            time.monotonic() + self._configuration.metadata_ttl_seconds
        )
        return metadata

    def _validate_metadata(self, document: object) -> _ProviderMetadata:
        values = _require_mapping(document, "OIDC discovery document", misconfigured=True)
        issuer = _require_text(values, "issuer", misconfigured=True)
        if issuer != self._configuration.issuer:
            raise IdentityProviderMisconfiguredError(
                "OIDC discovery issuer does not match configuration"
            )
        endpoints = {
            name: _require_text(values, name, misconfigured=True)
            for name in (
                "authorization_endpoint",
                "token_endpoint",
                "jwks_uri",
            )
        }
        issuer_origin = _origin(self._configuration.issuer)
        for name, value in endpoints.items():
            _require_https_url(value, field_name=name, allow_path=True)
            if _origin(value) != issuer_origin:
                raise IdentityProviderMisconfiguredError(
                    "OIDC endpoint origin is outside the configured trust boundary"
                )
        challenge_methods = _require_text_sequence(
            values.get("code_challenge_methods_supported"),
            "code_challenge_methods_supported",
            misconfigured=True,
        )
        if "S256" not in challenge_methods:
            raise IdentityProviderMisconfiguredError(
                "OIDC provider does not advertise PKCE S256"
            )
        advertised_algorithms = _require_text_sequence(
            values.get("id_token_signing_alg_values_supported"),
            "id_token_signing_alg_values_supported",
            misconfigured=True,
        )
        allowed = self._configuration.allowed_signing_algorithms
        if not set(allowed).issubset(set(advertised_algorithms)):
            raise IdentityProviderMisconfiguredError(
                "OIDC provider signing algorithms do not satisfy the allowlist"
            )
        if any(value.lower() == "none" for value in advertised_algorithms):
            raise IdentityProviderMisconfiguredError(
                "OIDC provider advertises an unsigned ID token algorithm"
            )
        return _ProviderMetadata(
            issuer=issuer,
            authorization_endpoint=endpoints["authorization_endpoint"],
            token_endpoint=endpoints["token_endpoint"],
            jwks_uri=endpoints["jwks_uri"],
            signing_algorithms=tuple(advertised_algorithms),
        )

    def _load_jwks(
        self,
        jwks_uri: str,
        *,
        force: bool = False,
    ) -> Mapping[str, Any]:
        if (
            not force
            and self._jwks is not None
            and self._jwks_uri == jwks_uri
            and time.monotonic() < self._jwks_deadline
        ):
            return self._jwks
        try:
            document = self._transport.get_json(
                url=jwks_uri,
                timeout_seconds=self._configuration.request_timeout_seconds,
                maximum_bytes=self._configuration.maximum_response_bytes,
            )
        except Exception:
            raise IdentityProviderUnavailableError("OIDC keys are unavailable") from None
        jwks = _require_mapping(document, "OIDC key set", misconfigured=True)
        keys = jwks.get("keys")
        if not isinstance(keys, list) or not keys or not all(
            isinstance(value, Mapping) for value in keys
        ):
            raise IdentityProviderMisconfiguredError(
                "OIDC key set is empty or invalid"
            )
        self._jwks = jwks
        self._jwks_uri = jwks_uri
        self._jwks_deadline = (
            time.monotonic() + self._configuration.metadata_ttl_seconds
        )
        return jwks

    def _validate_claims(
        self,
        *,
        claims: Mapping[str, Any],
        request: ProviderExchangeRequest,
    ) -> Mapping[str, Any]:
        issuer = _require_text(claims, "iss")
        subject = _require_text(claims, "sub")
        if issuer != request.expected_issuer:
            raise IdentityProviderRejectedError("OIDC issuer claim mismatch")
        audiences = _audiences(claims.get("aud"))
        if request.expected_audience not in audiences:
            raise IdentityProviderRejectedError("OIDC audience claim mismatch")
        if len(audiences) > 1 and claims.get("azp") != request.expected_audience:
            raise IdentityProviderRejectedError(
                "OIDC authorized-party claim mismatch"
            )
        nonce = _require_text(claims, "nonce")
        if not hmac.compare_digest(nonce, request.expected_nonce):
            raise IdentityProviderRejectedError("OIDC nonce claim mismatch")

        issued_at = _numeric_date(claims, "iat")
        expires_at = _numeric_date(claims, "exp")
        auth_time = _numeric_date(claims, "auth_time")
        skew = timedelta(seconds=self._configuration.clock_skew_seconds)
        if (
            issued_at > request.server_now + skew
            or auth_time > request.server_now + skew
            or request.server_now >= expires_at
        ):
            raise IdentityProviderRejectedError("OIDC token time window is invalid")
        if "nbf" in claims and _numeric_date(claims, "nbf") > request.server_now + skew:
            raise IdentityProviderRejectedError("OIDC token is not yet valid")

        email = _require_text(claims, "email")
        if claims.get("email_verified") is not True:
            raise IdentityProviderRejectedError(
                "OIDC contact is not provider-verified"
            )
        acr = _require_text(claims, "acr")
        amr = _require_text_sequence(claims.get("amr"), "amr")
        if not acr or not amr:
            raise IdentityProviderRejectedError(
                "OIDC authentication context is insufficient"
            )
        session_id = claims.get("sid")
        if session_id is not None and (
            not isinstance(session_id, str) or not session_id
        ):
            raise IdentityProviderRejectedError("OIDC session claim is invalid")
        return {
            "issuer": issuer,
            "subject": subject,
            "email": email,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "auth_time": auth_time,
            "acr": acr,
            "amr": tuple(sorted(set(amr))),
            "session_id": session_id,
        }


class StdlibOidcJsonTransport:
    """Small redirect-denying HTTPS transport for production composition.

    The adapter accepts only validated HTTPS URLs from ``ClosedOidcProvider``.
    It reads at most ``maximum_bytes + 1`` bytes before parsing one JSON object,
    and intentionally has no cookie jar, proxy discovery, retry, or redirect
    behavior.
    """

    def __init__(self, *, ssl_context: ssl.SSLContext | None = None) -> None:
        context = ssl_context or ssl.create_default_context()
        self._opener = build_opener(
            # ``urllib`` otherwise installs a default ProxyHandler which reads
            # process proxy variables.  Identity-provider traffic must not
            # inherit ambient routing configuration from the host.
            ProxyHandler({}),
            _RejectRedirectHandler(),
            HTTPSHandler(context=context),
        )

    def get_json(
        self,
        *,
        url: str,
        timeout_seconds: int,
        maximum_bytes: int,
    ) -> Mapping[str, Any]:
        return self._request_json(
            Request(
                url,
                method="GET",
                headers={"Accept": "application/json"},
            ),
            timeout_seconds=timeout_seconds,
            maximum_bytes=maximum_bytes,
        )

    def post_form_json(
        self,
        *,
        url: str,
        form: Mapping[str, str],
        timeout_seconds: int,
        maximum_bytes: int,
    ) -> Mapping[str, Any]:
        encoded = urlencode(dict(form)).encode("ascii")
        return self._request_json(
            Request(
                url,
                data=encoded,
                method="POST",
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            ),
            timeout_seconds=timeout_seconds,
            maximum_bytes=maximum_bytes,
        )

    def _request_json(
        self,
        request: Request,
        *,
        timeout_seconds: int,
        maximum_bytes: int,
    ) -> Mapping[str, Any]:
        try:
            with self._opener.open(request, timeout=timeout_seconds) as response:
                status = getattr(response, "status", None)
                content_type = response.headers.get_content_type()
                if status != 200 or content_type not in {
                    "application/json",
                    "application/jwk-set+json",
                }:
                    raise RuntimeError("OIDC response protocol is invalid")
                raw = response.read(maximum_bytes + 1)
        except (HTTPError, URLError, OSError, TimeoutError, ValueError):
            raise RuntimeError("OIDC transport failed") from None
        if len(raw) > maximum_bytes:
            raise RuntimeError("OIDC response exceeded its bound")
        try:
            value = json.loads(raw.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RuntimeError("OIDC response JSON is invalid") from None
        if not isinstance(value, Mapping):
            raise RuntimeError("OIDC response JSON is not an object")
        return value


class _RejectRedirectHandler(HTTPRedirectHandler):
    """urllib handler interface that never follows provider redirects."""

    def redirect_request(
        self,
        request: Any,
        fp: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> Any:
        del request, fp, code, message, headers, new_url
        raise RuntimeError("OIDC redirects are not allowed")


class PyJwtOidcTokenVerifier:
    """PyJWT-backed verifier with an exact, asymmetric public-JWK boundary."""

    _PRIVATE_JWK_FIELDS = frozenset(("d", "p", "q", "dp", "dq", "qi", "oth", "k"))

    def verify_id_token(
        self,
        *,
        id_token: str,
        jwks: Mapping[str, Any],
        allowed_signing_algorithms: Tuple[str, ...],
        expected_issuer: str,
        expected_audience: str,
        expected_nonce: str,
        server_now: datetime,
        clock_skew_seconds: int,
    ) -> Mapping[str, Any]:
        try:
            import jwt
        except ImportError:
            raise IdentityProviderMisconfiguredError(
                "OIDC JOSE implementation is unavailable"
            ) from None
        if not isinstance(id_token, str) or not id_token:
            raise IdentityProviderRejectedError("OIDC ID token is invalid")
        _require_utc(server_now)
        if not isinstance(jwks, Mapping) or set(jwks) != {"keys"}:
            raise IdentityProviderMisconfiguredError("OIDC key set is not closed")
        keys = jwks.get("keys")
        if not isinstance(keys, list) or not keys:
            raise IdentityProviderMisconfiguredError("OIDC key set is empty")
        try:
            header = jwt.get_unverified_header(id_token)
        except Exception:
            raise IdentityProviderRejectedError("OIDC ID token header is invalid") from None
        if not isinstance(header, Mapping):
            raise IdentityProviderRejectedError("OIDC ID token header is invalid")
        if set(header).difference({"alg", "kid", "typ"}):
            raise IdentityProviderRejectedError("OIDC ID token header is not closed")
        algorithm = header.get("alg")
        key_id = header.get("kid")
        if (
            not isinstance(algorithm, str)
            or algorithm not in allowed_signing_algorithms
            or algorithm.lower() == "none"
            or not isinstance(key_id, str)
            or not key_id
        ):
            raise IdentityProviderRejectedError(
                "OIDC ID token algorithm or key id is invalid"
            )
        candidates = []
        for candidate in keys:
            if not isinstance(candidate, Mapping):
                raise IdentityProviderMisconfiguredError(
                    "OIDC key set contains an invalid key"
                )
            if set(candidate).intersection(self._PRIVATE_JWK_FIELDS):
                raise IdentityProviderMisconfiguredError(
                    "OIDC key set contains private or symmetric material"
                )
            if candidate.get("kid") == key_id:
                candidates.append(candidate)
        if len(candidates) != 1:
            raise IdentityProviderMisconfiguredError(
                "OIDC signing key id is missing or ambiguous"
            )
        candidate = candidates[0]
        if (
            candidate.get("kty") not in {"RSA", "EC", "OKP"}
            or candidate.get("use", "sig") != "sig"
            or candidate.get("alg", algorithm) != algorithm
        ):
            raise IdentityProviderMisconfiguredError(
                "OIDC signing key constraints are invalid"
            )
        try:
            public_key = jwt.PyJWK.from_dict(dict(candidate), algorithm=algorithm)
        except Exception:
            raise IdentityProviderMisconfiguredError(
                "OIDC signing key cannot be constructed"
            ) from None

        # PyJWT normally consults wall-clock time.  Supplying a deterministic
        # ``server_now`` is part of our port, so temporal claims are validated
        # below against that exact value after cryptographic/issuer/audience
        # verification succeeds.
        try:
            claims = jwt.decode(
                id_token,
                key=public_key,
                algorithms=list(allowed_signing_algorithms),
                audience=expected_audience,
                issuer=expected_issuer,
                options={
                    "require": ["iss", "sub", "aud", "iat", "exp", "nonce"],
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                    "verify_signature": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
        except Exception:
            raise IdentityProviderRejectedError(
                "OIDC ID token verification failed"
            ) from None
        if not isinstance(claims, Mapping):
            raise IdentityProviderRejectedError("OIDC ID token claims are invalid")
        nonce = claims.get("nonce")
        if not isinstance(nonce, str) or not hmac.compare_digest(nonce, expected_nonce):
            raise IdentityProviderRejectedError("OIDC ID token nonce mismatch")
        skew = timedelta(seconds=clock_skew_seconds)
        issued_at = _numeric_date(claims, "iat")
        expires_at = _numeric_date(claims, "exp")
        if issued_at > server_now + skew or server_now >= expires_at:
            raise IdentityProviderRejectedError("OIDC ID token time window is invalid")
        if "nbf" in claims and _numeric_date(claims, "nbf") > server_now + skew:
            raise IdentityProviderRejectedError("OIDC ID token is not yet valid")
        return dict(claims)


def _valid_client_secret(value: object) -> bool:
    if isinstance(value, str):
        try:
            encoded = value.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            return False
    elif isinstance(value, bytearray):
        encoded = value
        try:
            value.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return False
    else:
        return False
    return (
        1 <= len(encoded) <= 4_096
        and not any(character in encoded for character in (0, 10, 13))
        and any(encoded)
    )


def _client_secret_text(value: Union[str, bytearray]) -> str:
    if not _valid_client_secret(value):
        raise IdentityProviderMisconfiguredError(
            "OIDC client credentials are incomplete"
        )
    if isinstance(value, str):
        return value
    try:
        return value.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise IdentityProviderMisconfiguredError(
            "OIDC client credentials are incomplete"
        ) from None


def _extract_id_token(response: object) -> str:
    values = _require_mapping(response, "OIDC token response")
    if "error" in values:
        raise IdentityProviderRejectedError("OIDC provider rejected the code")
    token_type = values.get("token_type")
    id_token = values.get("id_token")
    if (
        not isinstance(token_type, str)
        or token_type.lower() != "bearer"
        or not isinstance(id_token, str)
        or not id_token
    ):
        raise IdentityProviderRejectedError("OIDC token response is incomplete")
    return id_token


def _require_mapping(
    value: object,
    label: str,
    *,
    misconfigured: bool = False,
) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    error_type = (
        IdentityProviderMisconfiguredError
        if misconfigured
        else IdentityProviderRejectedError
    )
    raise error_type(label + " is not a JSON object")


def _require_text(
    values: Mapping[str, Any],
    name: str,
    *,
    misconfigured: bool = False,
) -> str:
    value = values.get(name)
    if isinstance(value, str) and value:
        return value
    error_type = (
        IdentityProviderMisconfiguredError
        if misconfigured
        else IdentityProviderRejectedError
    )
    raise error_type("OIDC " + name + " value is missing or invalid")


def _require_text_sequence(
    value: object,
    name: str,
    *,
    misconfigured: bool = False,
) -> Tuple[str, ...]:
    if (
        isinstance(value, Sequence)
        and not isinstance(value, (str, bytes))
        and value
        and all(isinstance(item, str) and item for item in value)
    ):
        return tuple(value)
    error_type = (
        IdentityProviderMisconfiguredError
        if misconfigured
        else IdentityProviderRejectedError
    )
    raise error_type("OIDC " + name + " value is missing or invalid")


def _audiences(value: object) -> Tuple[str, ...]:
    if isinstance(value, str) and value:
        return (value,)
    return _require_text_sequence(value, "aud")


def _numeric_date(values: Mapping[str, Any], name: str) -> datetime:
    value = values.get(name)
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise IdentityProviderRejectedError("OIDC " + name + " is invalid")
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        raise IdentityProviderRejectedError("OIDC " + name + " is invalid") from None


def _require_utc(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise IdentityProviderMisconfiguredError(
            "OIDC server time must be aware UTC"
        )


def _require_https_url(
    value: str,
    *,
    field_name: str,
    allow_path: bool,
    allow_query: bool = True,
) -> None:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError):
        raise IdentityProviderMisconfiguredError(
            "OIDC " + field_name + " URL is invalid"
        ) from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or (not allow_query and parsed.query)
        or (not allow_path and parsed.path not in ("", "/"))
        or port is not None and (port < 1 or port > 65535)
    ):
        raise IdentityProviderMisconfiguredError(
            "OIDC " + field_name + " must be a closed HTTPS URL"
        )


def _origin(value: str) -> Tuple[str, str, int]:
    parsed = urlsplit(value)
    return (parsed.scheme, parsed.hostname or "", parsed.port or 443)


def _require_pkce_challenge(value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 43
        or any(character not in _PKCE_URLSAFE for character in value)
    ):
        raise IdentityProviderMisconfiguredError("OIDC PKCE challenge is invalid")


def _require_pkce_verifier(value: str) -> None:
    if (
        not isinstance(value, str)
        or not 43 <= len(value) <= 128
        or any(character not in _PKCE_VERIFIER for character in value)
    ):
        raise IdentityProviderRejectedError("OIDC PKCE verifier is invalid")


_PKCE_URLSAFE = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)
_PKCE_VERIFIER = _PKCE_URLSAFE | frozenset(".~")


__all__ = [
    "ClosedOidcProvider",
    "OidcJsonTransport",
    "OidcProviderConfiguration",
    "OidcTokenVerifier",
    "PyJwtOidcTokenVerifier",
    "StdlibOidcJsonTransport",
]
