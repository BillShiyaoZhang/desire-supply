"""Immutable HTTP values shared by presentation adapters.

Raw carriers are deliberately excluded from ``repr``.  These values are process-local
transport contracts, not logging DTOs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, Protocol, Tuple, Union


FrozenJsonScalar = Union[None, bool, int, str]
FrozenJsonValue = Union[
    FrozenJsonScalar,
    Tuple["FrozenJsonValue", ...],
    Tuple[Tuple[str, "FrozenJsonValue"], ...],
]
FrozenJsonObject = Tuple[Tuple[str, FrozenJsonValue], ...]


@dataclass(frozen=True)
class HttpHeader:
    name: bytes
    value: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.name, bytes) or not isinstance(self.value, bytes):
            raise TypeError("HTTP header name and value must be bytes")


@dataclass(frozen=True)
class HttpRequest:
    method: str
    scheme: str
    path: str = field(repr=False)
    raw_query_string: bytes = field(default=b"", repr=False)
    headers: Tuple[HttpHeader, ...] = field(default=(), repr=False)
    body: bytes = field(default=b"", repr=False)
    client_disconnected: bool = False

    def __post_init__(self) -> None:
        if not all(isinstance(value, str) for value in (self.method, self.scheme, self.path)):
            raise TypeError("HTTP method, scheme, and path must be strings")
        if not isinstance(self.raw_query_string, bytes) or not isinstance(self.body, bytes):
            raise TypeError("HTTP query and body must be bytes")
        if not isinstance(self.headers, tuple) or not all(
            isinstance(header, HttpHeader) for header in self.headers
        ):
            raise TypeError("HTTP headers must be an immutable header tuple")
        if not isinstance(self.client_disconnected, bool):
            raise TypeError("client_disconnected must be boolean")


@dataclass(frozen=True)
class HttpResponse:
    status_code: int
    headers: Tuple[HttpHeader, ...] = field(repr=False)
    body: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.status_code) is not int:
            raise TypeError("HTTP status must be an integer")
        if not isinstance(self.headers, tuple) or not all(
            isinstance(header, HttpHeader) for header in self.headers
        ):
            raise TypeError("HTTP headers must be an immutable header tuple")
        if not isinstance(self.body, bytes):
            raise TypeError("HTTP response body must be bytes")

    def header_values(self, name: bytes) -> Tuple[bytes, ...]:
        lowered = name.lower()
        return tuple(
            header.value
            for header in self.headers
            if header.name.lower() == lowered
        )


class CookieMutationKind(str, Enum):
    SET_OIDC_BROWSER = "SET_OIDC_BROWSER"
    CLEAR_OIDC_BROWSER = "CLEAR_OIDC_BROWSER"
    SET_SESSION = "SET_SESSION"
    CLEAR_SESSION = "CLEAR_SESSION"


@dataclass(frozen=True)
class CookieMutation:
    kind: CookieMutationKind
    raw_value: Optional[str] = field(default=None, repr=False)


@dataclass(frozen=True)
class AuthenticatedHttpActor:
    actor_user_id: str
    session_id: str
    correlation_id: str
    causation_id: str
    trace_id: str
    original_actor_id: Optional[str]
    auth_time: datetime
    acr_code: str
    amr_codes: Tuple[str, ...]

    def __post_init__(self) -> None:
        required_text = (
            self.actor_user_id,
            self.session_id,
            self.correlation_id,
            self.causation_id,
            self.trace_id,
            self.acr_code,
        )
        if any(not isinstance(value, str) or not value for value in required_text):
            raise TypeError("authenticated actor text facts must be non-empty")
        if self.original_actor_id is not None and (
            not isinstance(self.original_actor_id, str) or not self.original_actor_id
        ):
            raise TypeError("original_actor_id must be absent or non-empty")
        if (
            not isinstance(self.auth_time, datetime)
            or self.auth_time.tzinfo is None
            or self.auth_time.utcoffset() != timedelta(0)
        ):
            raise TypeError("auth_time must be an aware UTC datetime")
        if (
            not isinstance(self.amr_codes, tuple)
            or not self.amr_codes
            or len(set(self.amr_codes)) != len(self.amr_codes)
            or any(not isinstance(code, str) or not code for code in self.amr_codes)
        ):
            raise TypeError("amr_codes must be a unique non-empty text tuple")


@dataclass(frozen=True)
class IamHttpInvocation:
    operation_id: str
    canonical_path: str = field(repr=False)
    path_parameters: Tuple[Tuple[str, str], ...] = field(repr=False)
    query_parameters: Tuple[Tuple[str, str], ...] = field(default=(), repr=False)
    json_body: FrozenJsonObject = field(default=(), repr=False)
    actor: Optional[AuthenticatedHttpActor] = None
    idempotency_key: Optional[str] = field(default=None, repr=False)
    expected_version: Optional[int] = None
    trace_id: str = ""
    raw_session_handle: Optional[str] = field(default=None, repr=False)
    raw_oidc_browser_cookie: Optional[str] = field(default=None, repr=False)


@dataclass(frozen=True)
class IamHttpOperationResult:
    status_code: int
    json_body: Optional[FrozenJsonObject] = field(repr=False)
    entity_tag: Optional[str] = None
    cookie_mutations: Tuple[CookieMutation, ...] = field(default=(), repr=False)
    redirect_location: Optional[str] = field(default=None, repr=False)
    replayed: bool = False
    retry_after_seconds: Optional[int] = None


class IamHttpOperationDispatcher(Protocol):
    """Explicit presentation/application binding for one normalized invocation."""

    def dispatch(self, invocation: IamHttpInvocation) -> IamHttpOperationResult:
        ...


class SessionAuthenticator(Protocol):
    def authenticate(
        self, *, raw_session_handle: Optional[str], trace_id: str
    ) -> Optional[AuthenticatedHttpActor]:
        ...


class OriginPolicy(Protocol):
    def require_allowed(self, *, origin: Optional[str], operation_id: str) -> None:
        ...


class CsrfVerifier(Protocol):
    def require_valid(
        self,
        *,
        raw_session_handle: str,
        raw_csrf_token: Optional[str],
        actor: AuthenticatedHttpActor,
        operation_id: str,
    ) -> None:
        ...


class RateLimiter(Protocol):
    def require_allowed(
        self, *, operation_id: str, actor: Optional[AuthenticatedHttpActor]
    ) -> None:
        ...


class RateLimitExceeded(RuntimeError):
    """Closed limiter decision carrying the only legal Retry-After value."""

    code = "RATE_LIMITED"

    def __init__(self, retry_after_seconds: int) -> None:
        if type(retry_after_seconds) is not int:
            raise TypeError("Retry-After must be an integer")
        if not 1 <= retry_after_seconds <= 86_400:
            raise ValueError("Retry-After is outside the published bounds")
        self.retry_after_seconds = retry_after_seconds
        super().__init__("RATE_LIMITED")


class TraceIdSource(Protocol):
    def new_trace_id(self) -> str:
        ...


@dataclass(frozen=True)
class HttpTelemetryEvent:
    trace_id: str
    operation_id: Optional[str]
    method: str
    route_template: Optional[str]
    status_code: int
    error_code: Optional[str]
    request_size_bucket: str
    duration_bucket: str
    authenticated: bool
    replayed: bool


class HttpTelemetry(Protocol):
    def record(self, event: HttpTelemetryEvent) -> None:
        ...
