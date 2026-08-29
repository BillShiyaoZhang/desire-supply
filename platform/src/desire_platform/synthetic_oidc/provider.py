"""Fail-closed protocol core for the INTERNAL_SANDBOX synthetic OIDC IdP."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import html
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
from typing import Callable, Mapping, NoReturn, Sequence, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit


ISSUER = "https://identity.example.test"
CLIENT_ID = "desire-internal-sandbox"
REDIRECT_URI = "https://pilot.example.test/v1/auth/oidc/callback"
SIGNING_ALGORITHM = "RS256"
SIGNING_KEY_ID = "internal-sandbox-synthetic-rs256-v1"
# Synthetic fixture evidence only: no real factor challenge occurs.  The
# explicit ``mfa`` markers let INTERNAL_SANDBOX exercise recent-MFA command
# paths without weakening the production IAM predicate.
ACR = "urn:desire:acr:synthetic-internal-sandbox:mfa"
AMR = ("synthetic", "mfa")

_BIND_HOST = "0.0.0.0"
_BIND_PORT = 8081
_INTERACTION_TTL = timedelta(minutes=5)
_CODE_TTL = timedelta(seconds=60)
_TOKEN_TTL = timedelta(minutes=5)
_MAX_PENDING = 128
_MAX_TARGET_BYTES = 8 * 1024
_MAX_BODY_BYTES = 16 * 1024
_OPAQUE_43 = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_EXPECTED_AUTHORIZATION_FIELDS = frozenset(
    (
        "client_id",
        "redirect_uri",
        "response_type",
        "scope",
        "state",
        "nonce",
        "code_challenge",
        "code_challenge_method",
    )
)
_EXPECTED_SELECTION_FIELDS = frozenset(("request_handle", "account_code"))
_EXPECTED_TOKEN_FIELDS = frozenset(
    (
        "grant_type",
        "code",
        "redirect_uri",
        "client_id",
        "client_secret",
        "code_verifier",
    )
)
_SYNTHETIC_ENV_PREFIX = "DESIRE_SYNTHETIC_OIDC_"
_CLIENT_SECRET_FILE_ENV = "DESIRE_SYNTHETIC_OIDC_CLIENT_SECRET_FILE"
_ALLOWED_SYNTHETIC_ENV = frozenset((_CLIENT_SECRET_FILE_ENV,))

# This deliberately public, fixed test key has no authority outside the
# synthetic issuer behind the locally trusted INTERNAL_SANDBOX TLS edge.  Only
# n/e leave this module at runtime.  The private exponent is never rendered,
# logged, returned in a JWK, or placed in a provider instance/repr.
_RSA_N_B64 = (
    "sb-Q6a_LjWmTtDXkj1oJEJOaRbuVOxGHtXIwWQBHwomwYG37nDBnb0WCiA1FSRbvbwcmtGY4"
    "AdnA1zNRGAwdQi9CsCZ4I5xSBod4m5H-cJzq0dXtR7zwI7jNwsk9W07kemwPI1khq7xgVY"
    "5OTFDTyz86JWFXrNaF0r4nza2iUclO1C8QURVtl7lGqtPHgMO6S4giISsDS2FB4UIUu6or"
    "qZNshKlUXlmaf0x6h9A-3ECCC0adAGq3QZGpvy8SWAxewdBWngn8tFygr5x5dRrGrRQbR43"
    "Gs8cUXFZhQ3-_f2mm1IT82O--cQ_7d272e35adY4tfdzVF2AZOzWme7Jutw"
)
_RSA_E_B64 = "AQAB"
_RSA_D_B64 = (
    "AVHZY7rKGBEDYZkbkNOi_VIEsHEJbJFCWAHELGctRCEuw5CGNlBBJRNmRamCeJf0Iw7afTbb"
    "zg0qy_b4zXw5LWPCWX93n1dWSMEgSYcMeEI3F5JjdTY3UgvZt_nWntSdcTWdXYXG8HMrMk"
    "093gmk3gNoe8tijAkziRJZ6TbNxlCrAjXRGgEVPGkqYIGSeM3OjMbIcYi_JW5I2buK7RkdY"
    "f9KmkvQnVdVwE7Ii-MzszvXtIrIrHh71ljEfHDEJ8j47x8DN-ySUMiC-spLD5woanad-qRP"
    "kAwMh_7RAIJ95gRLI45nSFxKWF2XYTJ5c72kz31VvbkYr7L4mxnOH67pfQ"
)


@dataclass(frozen=True)
class SyntheticAccount:
    account_code: str
    subject: str = field(repr=False)
    email: str


SYNTHETIC_BOOTSTRAP_ACCOUNTS = (
    SyntheticAccount(
        account_code="access_admin_01",
        subject="sandbox:access-admin-01",
        email="sandbox-access-admin-01@example.test",
    ),
    SyntheticAccount(
        account_code="appeal_reviewer_01",
        subject="sandbox:appeal-reviewer-01",
        email="sandbox-appeal-reviewer-01@example.test",
    ),
    SyntheticAccount(
        account_code="creator_01",
        subject="sandbox:creator-01",
        email="sandbox-creator-01@example.test",
    ),
    SyntheticAccount(
        account_code="demand_owner_01",
        subject="sandbox:demand-owner-01",
        email="sandbox-demand-owner-01@example.test",
    ),
    SyntheticAccount(
        account_code="finance_operator_01",
        subject="sandbox:finance-operator-01",
        email="sandbox-finance-operator-01@example.test",
    ),
    SyntheticAccount(
        account_code="finance_operator_02",
        subject="sandbox:finance-operator-02",
        email="sandbox-finance-operator-02@example.test",
    ),
    SyntheticAccount(
        account_code="operations_reviewer_01",
        subject="sandbox:operations-reviewer-01",
        email="sandbox-operations-reviewer-01@example.test",
    ),
    SyntheticAccount(
        account_code="org_admin_01",
        subject="sandbox:org-admin-01",
        email="sandbox-org-admin-01@example.test",
    ),
    SyntheticAccount(
        account_code="trust_officer_01",
        subject="sandbox:trust-officer-01",
        email="sandbox-trust-officer-01@example.test",
    ),
    SyntheticAccount(
        account_code="trust_officer_02",
        subject="sandbox:trust-officer-02",
        email="sandbox-trust-officer-02@example.test",
    ),
)
# Keep the long-standing public name scoped to the ten identities owned by the
# identity bootstrap.  Provider-only identities must never become bootstrap or
# role inputs merely because the synthetic chooser can authenticate them.
SYNTHETIC_ACCOUNTS = SYNTHETIC_BOOTSTRAP_ACCOUNTS
SYNTHETIC_PROVIDER_ONLY_ACCOUNTS = (
    SyntheticAccount(
        account_code="invited_demand_owner_02",
        subject="sandbox:invited-demand-owner-02",
        email="sandbox-invited-demand-owner-02@example.test",
    ),
)
SYNTHETIC_PROVIDER_ACCOUNTS = (
    SYNTHETIC_BOOTSTRAP_ACCOUNTS + SYNTHETIC_PROVIDER_ONLY_ACCOUNTS
)
_ACCOUNTS_BY_CODE = {
    value.account_code: value for value in SYNTHETIC_PROVIDER_ACCOUNTS
}


class SyntheticOidcConfigurationError(RuntimeError):
    """Stable non-reflective startup failure for the fixture."""

    def __init__(self) -> None:
        super().__init__("SYNTHETIC_OIDC_CONFIGURATION_INVALID")


@dataclass(repr=False)
class SyntheticOidcConfiguration:
    client_secret: bytearray = field(repr=False)
    bind_host: str = _BIND_HOST
    bind_port: int = _BIND_PORT

    def __repr__(self) -> str:
        return (
            "SyntheticOidcConfiguration(issuer=%r, bind_host=%r, "
            "bind_port=%r, client_secret=<redacted>)"
            % (ISSUER, self.bind_host, self.bind_port)
        )

    def close(self) -> None:
        _zero(self.client_secret)


@dataclass(frozen=True)
class SyntheticOidcResponse:
    status: int
    headers: Tuple[Tuple[str, str], ...]
    body: bytes = field(repr=False)


@dataclass(frozen=True, repr=False)
class _Interaction:
    state: str = field(repr=False)
    nonce: str = field(repr=False)
    code_challenge: str = field(repr=False)
    expires_at: datetime = field(repr=False)


@dataclass(frozen=True, repr=False)
class _AuthorizationCode:
    account: SyntheticAccount = field(repr=False)
    nonce: str = field(repr=False)
    code_challenge: str = field(repr=False)
    auth_time: datetime = field(repr=False)
    session_id: str = field(repr=False)
    expires_at: datetime = field(repr=False)


class _ProtocolError(RuntimeError):
    def __init__(self, *, status: int, code: str, token_error: str | None = None) -> None:
        self.status = status
        self.code = code
        self.token_error = token_error
        super().__init__(code)


class SyntheticOidcProvider:
    """In-memory authorization-code fixture with one immutable client.

    The process is expected to sit behind the controlled HTTPS edge.  Public
    protocol requests must carry the exact host and an edge-reconstructed
    ``X-Forwarded-Proto: https`` header; direct container-network HTTP calls
    cannot exercise OIDC routes.
    """

    def __init__(
        self,
        *,
        client_secret: bytearray,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        if not isinstance(client_secret, bytearray) or not _valid_secret(client_secret):
            raise SyntheticOidcConfigurationError()
        if not callable(clock):
            raise SyntheticOidcConfigurationError()
        self._client_secret = client_secret
        self._clock = clock
        self._interactions: dict[str, _Interaction] = {}
        self._codes: dict[str, _AuthorizationCode] = {}
        self._lock = threading.RLock()
        self._closed = False

    def __repr__(self) -> str:
        return (
            "SyntheticOidcProvider(issuer=%r, accounts=%r, "
            "client_secret=<redacted>, signing_key=<synthetic-fixed>)"
            % (
                ISSUER,
                tuple(value.account_code for value in SYNTHETIC_PROVIDER_ACCOUNTS),
            )
        )

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._interactions.clear()
            self._codes.clear()
            _zero(self._client_secret)

    def handle(
        self,
        *,
        method: str,
        raw_target: str,
        headers: Mapping[str, str] | Sequence[Tuple[str, str]],
        body: bytes,
    ) -> SyntheticOidcResponse:
        """Handle one already bounded HTTP request without network access."""

        path = ""
        try:
            if (
                not isinstance(method, str)
                or not isinstance(raw_target, str)
                or not isinstance(body, bytes)
                or len(raw_target.encode("ascii", errors="strict")) > _MAX_TARGET_BYTES
                or len(body) > _MAX_BODY_BYTES
            ):
                raise _ProtocolError(status=400, code="INVALID_REQUEST")
            parsed = urlsplit(raw_target)
            if parsed.scheme or parsed.netloc or parsed.fragment:
                raise _ProtocolError(status=400, code="INVALID_REQUEST")
            path = parsed.path
            header_pairs = _header_pairs(headers)

            if path in {"/health/live", "/health/ready"}:
                if method != "GET" or parsed.query or body:
                    raise _ProtocolError(status=405, code="METHOD_NOT_ALLOWED")
                self._require_health_boundary(header_pairs)
                if path == "/health/live":
                    return _json_response(200, {"status": "LIVE"})
                return _json_response(
                    200 if not self._closed else 503,
                    {"status": "READY" if not self._closed else "NOT_READY"},
                )

            self._require_public_https_proxy(header_pairs)
            if self._closed:
                raise _ProtocolError(status=503, code="SERVICE_UNAVAILABLE")
            if path == "/.well-known/openid-configuration":
                if method != "GET" or parsed.query or body:
                    raise _ProtocolError(status=405, code="METHOD_NOT_ALLOWED")
                return _json_response(200, _discovery_document())
            if path == "/jwks":
                if method != "GET" or parsed.query or body:
                    raise _ProtocolError(status=405, code="METHOD_NOT_ALLOWED")
                return _json_response(
                    200,
                    {"keys": [_public_jwk()]},
                    media_type="application/jwk-set+json",
                )
            if path == "/authorize" and method == "GET":
                if body:
                    raise _ProtocolError(status=400, code="INVALID_REQUEST")
                return self._begin_authorization(parsed.query)
            if path == "/authorize" and method == "POST":
                if parsed.query:
                    raise _ProtocolError(status=400, code="INVALID_REQUEST")
                _require_form_content_type(header_pairs)
                return self._select_account(body)
            if path == "/token" and method == "POST":
                if parsed.query:
                    raise _ProtocolError(
                        status=400, code="INVALID_REQUEST", token_error="invalid_request"
                    )
                _require_form_content_type(header_pairs, token_endpoint=True)
                return self._exchange_code(body)
            if path in {"/authorize", "/token"}:
                raise _ProtocolError(status=405, code="METHOD_NOT_ALLOWED")
            raise _ProtocolError(status=404, code="ROUTE_NOT_FOUND")
        except _ProtocolError as error:
            if path == "/token":
                return _json_response(
                    error.status,
                    {"error": error.token_error or "invalid_request"},
                )
            return _json_response(error.status, {"code": error.code})
        except Exception:
            if path == "/token":
                return _json_response(503, {"error": "temporarily_unavailable"})
            return _json_response(503, {"code": "SERVICE_UNAVAILABLE"})

    def _require_health_boundary(
        self, headers: Sequence[Tuple[str, str]]
    ) -> None:
        if (
            _values(headers, "host") != ("127.0.0.1:8081",)
            or _values(headers, "forwarded")
            or _values(headers, "x-forwarded-host")
            or _values(headers, "x-forwarded-proto")
        ):
            raise _ProtocolError(status=403, code="HEALTH_BOUNDARY_REQUIRED")

    def _require_public_https_proxy(
        self, headers: Sequence[Tuple[str, str]]
    ) -> None:
        host = _values(headers, "host")
        forwarded_host = _values(headers, "x-forwarded-host")
        protocol = _values(headers, "x-forwarded-proto")
        if (
            host != ("identity.example.test",)
            or forwarded_host != ("identity.example.test",)
            or protocol != ("https",)
            or _values(headers, "forwarded")
        ):
            raise _ProtocolError(status=403, code="HTTPS_PROXY_BOUNDARY_REQUIRED")

    def _begin_authorization(self, raw_query: str) -> SyntheticOidcResponse:
        values = _closed_urlencoded(raw_query.encode("ascii"), _EXPECTED_AUTHORIZATION_FIELDS)
        if (
            values["client_id"] != CLIENT_ID
            or values["redirect_uri"] != REDIRECT_URI
            or values["response_type"] != "code"
            or values["scope"] != "openid email"
            or values["code_challenge_method"] != "S256"
            or _OPAQUE_43.fullmatch(values["state"]) is None
            or _OPAQUE_43.fullmatch(values["nonce"]) is None
            or _OPAQUE_43.fullmatch(values["code_challenge"]) is None
        ):
            raise _ProtocolError(status=400, code="AUTHORIZATION_REQUEST_INVALID")
        now = self._now()
        with self._lock:
            self._purge(now)
            if len(self._interactions) >= _MAX_PENDING:
                raise _ProtocolError(status=503, code="CAPACITY_EXHAUSTED")
            handle = _new_opaque(self._interactions)
            self._interactions[handle] = _Interaction(
                state=values["state"],
                nonce=values["nonce"],
                code_challenge=values["code_challenge"],
                expires_at=now + _INTERACTION_TTL,
            )
        return _html_response(_chooser_html(handle))

    def _select_account(self, body: bytes) -> SyntheticOidcResponse:
        values = _closed_urlencoded(body, _EXPECTED_SELECTION_FIELDS)
        handle = values["request_handle"]
        if _OPAQUE_43.fullmatch(handle) is None:
            raise _ProtocolError(status=400, code="SELECTION_INVALID")
        now = self._now()
        with self._lock:
            self._purge(now)
            interaction = self._interactions.pop(handle, None)
            account = _ACCOUNTS_BY_CODE.get(values["account_code"])
            if (
                interaction is None
                or now >= interaction.expires_at
                or account is None
            ):
                raise _ProtocolError(status=400, code="SELECTION_INVALID")
            if len(self._codes) >= _MAX_PENDING:
                raise _ProtocolError(status=503, code="CAPACITY_EXHAUSTED")
            code = _new_opaque(self._codes)
            self._codes[code] = _AuthorizationCode(
                account=account,
                nonce=interaction.nonce,
                code_challenge=interaction.code_challenge,
                auth_time=now,
                session_id=_new_opaque({}),
                expires_at=now + _CODE_TTL,
            )
        location = REDIRECT_URI + "?" + urlencode(
            {"code": code, "state": interaction.state}
        )
        return SyntheticOidcResponse(
            status=303,
            headers=(
                ("Location", location),
                ("Cache-Control", "no-store"),
                ("Referrer-Policy", "no-referrer"),
            ),
            body=b"",
        )

    def _exchange_code(self, body: bytes) -> SyntheticOidcResponse:
        values = _closed_urlencoded(
            body,
            _EXPECTED_TOKEN_FIELDS,
            token_error="invalid_request",
        )
        try:
            supplied_secret = values["client_secret"].encode("ascii", errors="strict")
        except UnicodeEncodeError:
            supplied_secret = b""
        if not hmac.compare_digest(bytes(self._client_secret), supplied_secret):
            raise _ProtocolError(
                status=401, code="CLIENT_INVALID", token_error="invalid_client"
            )
        now = self._now()
        with self._lock:
            self._purge(now)
            # Consume after authenticating the sole client but before checking
            # any grant binding.  Wrong client/redirect/grant type/PKCE values
            # can never become a retry oracle for one authorization code.
            grant = self._codes.pop(values["code"], None)
        if (
            grant is None
            or now >= grant.expires_at
            or now < grant.auth_time
            or values["grant_type"] != "authorization_code"
            or values["client_id"] != CLIENT_ID
            or values["redirect_uri"] != REDIRECT_URI
        ):
            raise _ProtocolError(
                status=400, code="GRANT_INVALID", token_error="invalid_grant"
            )
        verifier = values["code_verifier"]
        try:
            challenge = _base64url(hashlib.sha256(verifier.encode("ascii")).digest())
        except UnicodeEncodeError:
            challenge = ""
        if (
            not 43 <= len(verifier) <= 128
            or re.fullmatch(r"[A-Za-z0-9._~-]+", verifier) is None
            or not hmac.compare_digest(challenge, grant.code_challenge)
        ):
            raise _ProtocolError(
                status=400, code="GRANT_INVALID", token_error="invalid_grant"
            )
        issued_at = int(now.timestamp())
        claims = {
            "iss": ISSUER,
            "sub": grant.account.subject,
            "aud": CLIENT_ID,
            "iat": issued_at,
            "exp": int((now + _TOKEN_TTL).timestamp()),
            "auth_time": int(grant.auth_time.timestamp()),
            "nonce": grant.nonce,
            "email": grant.account.email,
            "email_verified": True,
            "acr": ACR,
            "amr": list(AMR),
            "sid": grant.session_id,
        }
        return _json_response(
            200,
            {
                "access_token": _new_opaque({}),
                "token_type": "Bearer",
                "expires_in": int(_TOKEN_TTL.total_seconds()),
                "id_token": _sign_id_token(claims),
            },
        )

    def _now(self) -> datetime:
        value = self._clock()
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() != timedelta(0)
        ):
            raise _ProtocolError(status=503, code="CLOCK_INVALID")
        return value.replace(microsecond=0)

    def _purge(self, now: datetime) -> None:
        self._interactions = {
            key: value
            for key, value in self._interactions.items()
            if now < value.expires_at
        }
        self._codes = {
            key: value for key, value in self._codes.items() if now < value.expires_at
        }


def load_synthetic_oidc_configuration(
    *,
    environment: Mapping[str, str] = os.environ,
    allowed_secret_root: Path = Path("/run/secrets"),
) -> SyntheticOidcConfiguration:
    """Load the only mutable IdP fact: the API's mounted client secret."""

    try:
        if not isinstance(environment, Mapping) or not isinstance(allowed_secret_root, Path):
            _configuration_invalid()
        if (
            environment.get("DESIRE_DEPLOYMENT_MODE") != "INTERNAL_SANDBOX"
            or environment.get("DESIRE_EXTERNAL_PARTICIPANTS_ENABLED") != "false"
        ):
            _configuration_invalid()
        synthetic_keys = {
            key
            for key in environment
            if isinstance(key, str) and key.startswith(_SYNTHETIC_ENV_PREFIX)
        }
        if synthetic_keys != _ALLOWED_SYNTHETIC_ENV:
            _configuration_invalid()
        raw_path = environment.get(_CLIENT_SECRET_FILE_ENV)
        if not isinstance(raw_path, str) or not raw_path or "\x00" in raw_path:
            _configuration_invalid()
        root = allowed_secret_root.resolve(strict=True)
        if root != allowed_secret_root or not root.is_dir() or root.is_symlink():
            _configuration_invalid()
        path = Path(raw_path)
        if not path.is_absolute() or path.is_symlink():
            _configuration_invalid()
        resolved = path.resolve(strict=True)
        if resolved != path or resolved.parent != root:
            _configuration_invalid()
        material = _read_secret_file(resolved)
        return SyntheticOidcConfiguration(client_secret=material)
    except SyntheticOidcConfigurationError:
        raise
    except (OSError, TypeError, ValueError):
        _configuration_invalid()


def _configuration_invalid() -> NoReturn:
    raise SyntheticOidcConfigurationError()


def _valid_secret(value: bytearray) -> bool:
    return (
        32 <= len(value) <= 4_096
        and all(0x21 <= character <= 0x7E for character in value)
    )


def _read_secret_file(path: Path) -> bytearray:
    descriptor = None
    material = bytearray()
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or not 32 <= metadata.st_size <= 4_096
        ):
            _configuration_invalid()
        material = bytearray(metadata.st_size)
        view = memoryview(material)
        offset = 0
        while offset < len(material):
            count = os.readv(descriptor, [view[offset:]])
            if count <= 0:
                _configuration_invalid()
            offset += count
        final = os.fstat(descriptor)
        if (
            final.st_dev != metadata.st_dev
            or final.st_ino != metadata.st_ino
            or final.st_size != metadata.st_size
            or not _valid_secret(material)
        ):
            _configuration_invalid()
        return material
    except SyntheticOidcConfigurationError:
        _zero(material)
        raise
    except (OSError, TypeError, ValueError):
        _zero(material)
        _configuration_invalid()
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _zero(value: bytearray) -> None:
    if isinstance(value, bytearray):
        value[:] = b"\x00" * len(value)


def _header_pairs(
    headers: Mapping[str, str] | Sequence[Tuple[str, str]],
) -> Tuple[Tuple[str, str], ...]:
    pairs = headers.items() if isinstance(headers, Mapping) else headers
    try:
        original = tuple(pairs)
    except (TypeError, ValueError):
        raise _ProtocolError(status=400, code="HEADERS_INVALID") from None
    if any(
        not isinstance(pair, tuple)
        or len(pair) != 2
        or not isinstance(pair[0], str)
        or not isinstance(pair[1], str)
        or not pair[0]
        or "\r" in pair[1]
        or "\n" in pair[1]
        for pair in original
    ):
        raise _ProtocolError(status=400, code="HEADERS_INVALID")
    return tuple((name.lower(), value) for name, value in original)


def _values(headers: Sequence[Tuple[str, str]], name: str) -> Tuple[str, ...]:
    return tuple(value for candidate, value in headers if candidate == name)


def _require_form_content_type(
    headers: Sequence[Tuple[str, str]], *, token_endpoint: bool = False
) -> None:
    values = _values(headers, "content-type")
    if len(values) != 1 or values[0].split(";", 1)[0].strip().lower() != (
        "application/x-www-form-urlencoded"
    ):
        raise _ProtocolError(
            status=415,
            code="FORM_CONTENT_TYPE_REQUIRED",
            token_error="invalid_request" if token_endpoint else None,
        )


def _closed_urlencoded(
    raw: bytes,
    expected_fields: frozenset[str],
    *,
    token_error: str | None = None,
) -> dict[str, str]:
    try:
        text = raw.decode("ascii", errors="strict")
        pairs = parse_qsl(
            text,
            keep_blank_values=True,
            strict_parsing=True,
            encoding="ascii",
            errors="strict",
            max_num_fields=len(expected_fields) + 1,
            separator="&",
        )
    except (UnicodeDecodeError, UnicodeEncodeError, ValueError):
        raise _ProtocolError(
            status=400, code="FORM_INVALID", token_error=token_error
        ) from None
    values: dict[str, str] = {}
    for key, value in pairs:
        if key in values:
            raise _ProtocolError(
                status=400, code="FORM_INVALID", token_error=token_error
            )
        values[key] = value
    if frozenset(values) != expected_fields or any(value == "" for value in values.values()):
        raise _ProtocolError(status=400, code="FORM_INVALID", token_error=token_error)
    return values


def _new_opaque(existing: Mapping[str, object]) -> str:
    for _attempt in range(8):
        value = secrets.token_urlsafe(32)
        if _OPAQUE_43.fullmatch(value) is not None and value not in existing:
            return value
    raise _ProtocolError(status=503, code="RANDOM_SOURCE_INVALID")


def _discovery_document() -> dict[str, object]:
    return {
        "issuer": ISSUER,
        "authorization_endpoint": ISSUER + "/authorize",
        "token_endpoint": ISSUER + "/token",
        "jwks_uri": ISSUER + "/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": [SIGNING_ALGORITHM],
        "scopes_supported": ["openid", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
    }


def _public_jwk() -> dict[str, str]:
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": SIGNING_ALGORITHM,
        "kid": SIGNING_KEY_ID,
        "n": _RSA_N_B64,
        "e": _RSA_E_B64,
    }


def _chooser_html(request_handle: str) -> bytes:
    buttons = "".join(
        (
            '<button type="submit" name="account_code" value="{}">'
            "{} · {}</button>"
        ).format(
            html.escape(account.account_code, quote=True),
            html.escape(account.account_code),
            html.escape(account.email),
        )
        for account in SYNTHETIC_PROVIDER_ACCOUNTS
    )
    document = (
        "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>INTERNAL_SANDBOX 合成登录</title></head><body>"
        "<main><h1>选择冻结合成账号</h1>"
        "<p>仅用于 INTERNAL_SANDBOX；不代表真人身份。"
        "受邀身份未预置账号或权限。</p>"
        "<form method=\"post\" action=\"/authorize\">"
        '<input type="hidden" name="request_handle" value="{}">'
        "{}</form></main></body></html>"
    ).format(html.escape(request_handle, quote=True), buttons)
    return document.encode("utf-8")


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_base64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _sign_id_token(claims: Mapping[str, object]) -> str:
    header = {"alg": SIGNING_ALGORITHM, "kid": SIGNING_KEY_ID, "typ": "JWT"}
    encoded_header = _base64url(
        json.dumps(header, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode(
            "ascii"
        )
    )
    encoded_claims = _base64url(
        json.dumps(claims, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode(
            "ascii"
        )
    )
    signing_input = (encoded_header + "." + encoded_claims).encode("ascii")
    digest = hashlib.sha256(signing_input).digest()
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + digest
    modulus = int.from_bytes(_decode_base64url(_RSA_N_B64), "big")
    private_exponent = int.from_bytes(_decode_base64url(_RSA_D_B64), "big")
    width = (modulus.bit_length() + 7) // 8
    padding_length = width - len(digest_info) - 3
    if padding_length < 8:
        raise _ProtocolError(status=503, code="SIGNING_KEY_INVALID")
    encoded_message = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + digest_info
    signature = pow(int.from_bytes(encoded_message, "big"), private_exponent, modulus)
    return encoded_header + "." + encoded_claims + "." + _base64url(
        signature.to_bytes(width, "big")
    )


def _json_response(
    status: int,
    value: Mapping[str, object],
    *,
    media_type: str = "application/json",
) -> SyntheticOidcResponse:
    body = json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=False
    ).encode("ascii")
    return SyntheticOidcResponse(
        status=status,
        headers=(
            ("Content-Type", media_type),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
        ),
        body=body,
    )


def _html_response(body: bytes) -> SyntheticOidcResponse:
    return SyntheticOidcResponse(
        status=200,
        headers=(
            ("Content-Type", "text/html; charset=utf-8"),
            ("Cache-Control", "no-store"),
            (
                "Content-Security-Policy",
                "default-src 'none'; form-action 'self'; base-uri 'none'; "
                "frame-ancestors 'none'",
            ),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
        ),
        body=body,
    )
