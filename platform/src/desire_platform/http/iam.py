"""Framework-independent IAM HTTP protocol kernel.

The kernel owns byte-to-protocol validation and safe response presentation.  It
does not implement an IAM use case: every routed operation is delegated through
the explicitly injected dispatcher.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import unquote_to_bytes

from desire_platform.identity_access.domain.errors import IamError, IamPreconditionFailed

from .contracts import (
    AuthenticatedHttpActor,
    CookieMutation,
    CookieMutationKind,
    CsrfVerifier,
    FrozenJsonObject,
    FrozenJsonValue,
    HttpHeader,
    HttpRequest,
    HttpResponse,
    HttpTelemetry,
    HttpTelemetryEvent,
    IamHttpInvocation,
    IamHttpOperationDispatcher,
    IamHttpOperationResult,
    OriginPolicy,
    RateLimitExceeded,
    RateLimiter,
    SessionAuthenticator,
    TraceIdSource,
)


class IamHttpOperation(str, Enum):
    BEGIN_OIDC_AUTHORIZATION = "beginOidcAuthorization"
    COMPLETE_OIDC_AUTHORIZATION = "completeOidcAuthorization"
    GET_SESSION_BOOTSTRAP = "getSessionBootstrap"
    INSPECT_ACCESS_INVITATION = "inspectAccessInvitation"
    ACCEPT_ACCESS_INVITATION = "acceptAccessInvitation"
    REVOKE_ACCESS_INVITATION = "revokeAccessInvitation"
    GET_POLICY_BUNDLE = "getPolicyBundle"
    GET_ME = "getMe"
    ACCEPT_CURRENT_POLICIES = "acceptCurrentPolicies"
    LIST_MY_CONSENT_GRANTS = "listMyConsentGrants"
    GRANT_CONSENT = "grantConsent"
    WITHDRAW_CONSENT = "withdrawConsent"
    LIST_MY_SESSIONS = "listMySessions"
    REVOKE_MY_SESSION = "revokeMySession"
    GET_ORGANIZATION_SUMMARY = "getOrganizationSummary"
    UPDATE_ORGANIZATION_PUBLIC_NAME = "updateOrganizationPublicName"
    LIST_ORGANIZATION_ACCESS_INVITATIONS = "listOrganizationAccessInvitations"
    ISSUE_ORGANIZATION_ACCESS_INVITATION = "issueOrganizationAccessInvitation"
    LIST_ORGANIZATION_MEMBERSHIPS = "listOrganizationMemberships"
    SUSPEND_MEMBERSHIP = "suspendMembership"
    RESUME_MEMBERSHIP = "resumeMembership"
    REVOKE_MEMBERSHIP = "revokeMembership"
    SUSPEND_USER = "suspendUser"
    RESUME_USER = "resumeUser"
    REVOKE_ALL_USER_SESSIONS = "revokeAllUserSessions"


class HttpAuthenticationMode(str, Enum):
    ANONYMOUS = "ANONYMOUS"
    OPTIONAL_SESSION = "OPTIONAL_SESSION"
    REQUIRED_SESSION = "REQUIRED_SESSION"
    OIDC_BROWSER = "OIDC_BROWSER"


class HttpCsrfMode(str, Enum):
    NONE = "NONE"
    ORIGIN_ONLY = "ORIGIN_ONLY"
    SESSION_IF_AUTHENTICATED = "SESSION_IF_AUTHENTICATED"
    SESSION_REQUIRED = "SESSION_REQUIRED"


@dataclass(frozen=True)
class IamHttpRoute:
    method: str
    path_template: str
    operation: IamHttpOperation
    authentication: HttpAuthenticationMode
    csrf: HttpCsrfMode
    body_limit_bytes: int
    query_limit_bytes: int = 8192


def _route(
    method: str,
    path: str,
    operation: IamHttpOperation,
    authentication: HttpAuthenticationMode,
    csrf: HttpCsrfMode,
    body_limit_bytes: int,
) -> IamHttpRoute:
    return IamHttpRoute(
        method=method,
        path_template=path,
        operation=operation,
        authentication=authentication,
        csrf=csrf,
        body_limit_bytes=body_limit_bytes,
    )


IAM_HTTP_ROUTES: Tuple[IamHttpRoute, ...] = (
    _route(
        "POST",
        "/v1/auth/oidc/authorizations",
        IamHttpOperation.BEGIN_OIDC_AUTHORIZATION,
        HttpAuthenticationMode.OPTIONAL_SESSION,
        HttpCsrfMode.SESSION_IF_AUTHENTICATED,
        8192,
    ),
    _route(
        "GET",
        "/v1/auth/oidc/callback",
        IamHttpOperation.COMPLETE_OIDC_AUTHORIZATION,
        HttpAuthenticationMode.OIDC_BROWSER,
        HttpCsrfMode.NONE,
        0,
    ),
    _route(
        "GET",
        "/v1/auth/session",
        IamHttpOperation.GET_SESSION_BOOTSTRAP,
        HttpAuthenticationMode.REQUIRED_SESSION,
        HttpCsrfMode.NONE,
        0,
    ),
    _route(
        "POST",
        "/v1/access-invitations/inspect",
        IamHttpOperation.INSPECT_ACCESS_INVITATION,
        HttpAuthenticationMode.ANONYMOUS,
        HttpCsrfMode.ORIGIN_ONLY,
        8192,
    ),
    _route(
        "POST",
        "/v1/access-invitations/{invitation_id}/accept",
        IamHttpOperation.ACCEPT_ACCESS_INVITATION,
        HttpAuthenticationMode.REQUIRED_SESSION,
        HttpCsrfMode.SESSION_REQUIRED,
        65536,
    ),
    _route(
        "POST",
        "/v1/access-invitations/{invitation_id}/revoke",
        IamHttpOperation.REVOKE_ACCESS_INVITATION,
        HttpAuthenticationMode.REQUIRED_SESSION,
        HttpCsrfMode.SESSION_REQUIRED,
        4096,
    ),
    _route(
        "GET",
        "/v1/policy-bundles/{policy_bundle_id}",
        IamHttpOperation.GET_POLICY_BUNDLE,
        HttpAuthenticationMode.ANONYMOUS,
        HttpCsrfMode.NONE,
        0,
    ),
    _route(
        "GET",
        "/v1/me",
        IamHttpOperation.GET_ME,
        HttpAuthenticationMode.REQUIRED_SESSION,
        HttpCsrfMode.NONE,
        0,
    ),
    _route(
        "POST",
        "/v1/me/policy-acceptances",
        IamHttpOperation.ACCEPT_CURRENT_POLICIES,
        HttpAuthenticationMode.REQUIRED_SESSION,
        HttpCsrfMode.SESSION_REQUIRED,
        65536,
    ),
    _route(
        "GET",
        "/v1/me/consents",
        IamHttpOperation.LIST_MY_CONSENT_GRANTS,
        HttpAuthenticationMode.REQUIRED_SESSION,
        HttpCsrfMode.NONE,
        0,
    ),
    _route(
        "POST",
        "/v1/me/consents",
        IamHttpOperation.GRANT_CONSENT,
        HttpAuthenticationMode.REQUIRED_SESSION,
        HttpCsrfMode.SESSION_REQUIRED,
        8192,
    ),
    _route(
        "POST",
        "/v1/me/consents/{consent_grant_id}/withdraw",
        IamHttpOperation.WITHDRAW_CONSENT,
        HttpAuthenticationMode.REQUIRED_SESSION,
        HttpCsrfMode.SESSION_REQUIRED,
        4096,
    ),
    _route(
        "GET",
        "/v1/me/sessions",
        IamHttpOperation.LIST_MY_SESSIONS,
        HttpAuthenticationMode.REQUIRED_SESSION,
        HttpCsrfMode.NONE,
        0,
    ),
    _route(
        "DELETE",
        "/v1/me/sessions/{session_id}",
        IamHttpOperation.REVOKE_MY_SESSION,
        HttpAuthenticationMode.REQUIRED_SESSION,
        HttpCsrfMode.SESSION_REQUIRED,
        0,
    ),
    _route(
        "GET",
        "/v1/organizations/{organization_id}",
        IamHttpOperation.GET_ORGANIZATION_SUMMARY,
        HttpAuthenticationMode.REQUIRED_SESSION,
        HttpCsrfMode.NONE,
        0,
    ),
    _route(
        "POST",
        "/v1/organizations/{organization_id}/public-name",
        IamHttpOperation.UPDATE_ORGANIZATION_PUBLIC_NAME,
        HttpAuthenticationMode.REQUIRED_SESSION,
        HttpCsrfMode.SESSION_REQUIRED,
        4096,
    ),
    _route(
        "GET",
        "/v1/organizations/{organization_id}/access-invitations",
        IamHttpOperation.LIST_ORGANIZATION_ACCESS_INVITATIONS,
        HttpAuthenticationMode.REQUIRED_SESSION,
        HttpCsrfMode.NONE,
        0,
    ),
    _route(
        "POST",
        "/v1/organizations/{organization_id}/access-invitations",
        IamHttpOperation.ISSUE_ORGANIZATION_ACCESS_INVITATION,
        HttpAuthenticationMode.REQUIRED_SESSION,
        HttpCsrfMode.SESSION_REQUIRED,
        8192,
    ),
    _route(
        "GET",
        "/v1/organizations/{organization_id}/memberships",
        IamHttpOperation.LIST_ORGANIZATION_MEMBERSHIPS,
        HttpAuthenticationMode.REQUIRED_SESSION,
        HttpCsrfMode.NONE,
        0,
    ),
    _route(
        "POST",
        "/v1/memberships/{membership_id}/suspend",
        IamHttpOperation.SUSPEND_MEMBERSHIP,
        HttpAuthenticationMode.REQUIRED_SESSION,
        HttpCsrfMode.SESSION_REQUIRED,
        4096,
    ),
    _route(
        "POST",
        "/v1/memberships/{membership_id}/resume",
        IamHttpOperation.RESUME_MEMBERSHIP,
        HttpAuthenticationMode.REQUIRED_SESSION,
        HttpCsrfMode.SESSION_REQUIRED,
        4096,
    ),
    _route(
        "POST",
        "/v1/memberships/{membership_id}/revoke",
        IamHttpOperation.REVOKE_MEMBERSHIP,
        HttpAuthenticationMode.REQUIRED_SESSION,
        HttpCsrfMode.SESSION_REQUIRED,
        4096,
    ),
    _route(
        "POST",
        "/v1/platform/users/{user_id}/suspend",
        IamHttpOperation.SUSPEND_USER,
        HttpAuthenticationMode.REQUIRED_SESSION,
        HttpCsrfMode.SESSION_REQUIRED,
        4096,
    ),
    _route(
        "POST",
        "/v1/platform/users/{user_id}/resume",
        IamHttpOperation.RESUME_USER,
        HttpAuthenticationMode.REQUIRED_SESSION,
        HttpCsrfMode.SESSION_REQUIRED,
        4096,
    ),
    _route(
        "POST",
        "/v1/platform/users/{user_id}/revoke-all-sessions",
        IamHttpOperation.REVOKE_ALL_USER_SESSIONS,
        HttpAuthenticationMode.REQUIRED_SESSION,
        HttpCsrfMode.SESSION_REQUIRED,
        4096,
    ),
)


DEFAULT_DENY_TRACE_ID = "trace_iam_http_red_0001"

_OPAQUE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{15,127}$")
_PROTOCOL_SECRET = re.compile(r"^[A-Za-z0-9._~-]{32,2048}$")
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]{15,127}$")
_CSRF_TOKEN = re.compile(r"^[A-Za-z0-9_-]{32,512}$")
_CONTENT_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_ENTITY_TAG = re.compile(r'^"v([1-9][0-9]*)"$')
_TRACE_ID = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_HEADER_NAME = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_REASON_CODE = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
_RETURN_TO = re.compile(r"^/(?!/)[A-Za-z0-9/_?&=.%~-]*$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_UTC_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|\+00:00)$"
)
_PERCENT_ESCAPE = re.compile(rb"%[0-9A-Fa-f]{2}")
_TRACEPARENT = re.compile(
    rb"^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$"
)

_DUPLICATE_CONTROL_HEADERS = {
    "cookie",
    "origin",
    "content-type",
    "content-length",
    "idempotency-key",
    "if-match",
    "x-csrf-token",
    "traceparent",
    "access-control-request-method",
    "access-control-request-headers",
}

_BODY_OPERATIONS = {
    IamHttpOperation.BEGIN_OIDC_AUTHORIZATION,
    IamHttpOperation.INSPECT_ACCESS_INVITATION,
    IamHttpOperation.ACCEPT_ACCESS_INVITATION,
    IamHttpOperation.REVOKE_ACCESS_INVITATION,
    IamHttpOperation.ACCEPT_CURRENT_POLICIES,
    IamHttpOperation.GRANT_CONSENT,
    IamHttpOperation.WITHDRAW_CONSENT,
    IamHttpOperation.ISSUE_ORGANIZATION_ACCESS_INVITATION,
    IamHttpOperation.UPDATE_ORGANIZATION_PUBLIC_NAME,
    IamHttpOperation.SUSPEND_MEMBERSHIP,
    IamHttpOperation.RESUME_MEMBERSHIP,
    IamHttpOperation.REVOKE_MEMBERSHIP,
    IamHttpOperation.SUSPEND_USER,
    IamHttpOperation.RESUME_USER,
    IamHttpOperation.REVOKE_ALL_USER_SESSIONS,
}

_PAGINATED_OPERATIONS = {
    IamHttpOperation.LIST_MY_CONSENT_GRANTS,
    IamHttpOperation.LIST_MY_SESSIONS,
    IamHttpOperation.LIST_ORGANIZATION_ACCESS_INVITATIONS,
    IamHttpOperation.LIST_ORGANIZATION_MEMBERSHIPS,
}

_SIDE_EFFECT_FREE_OPERATIONS = {
    IamHttpOperation.GET_SESSION_BOOTSTRAP,
    IamHttpOperation.INSPECT_ACCESS_INVITATION,
    IamHttpOperation.GET_POLICY_BUNDLE,
    IamHttpOperation.GET_ME,
    IamHttpOperation.LIST_MY_CONSENT_GRANTS,
    IamHttpOperation.LIST_MY_SESSIONS,
    IamHttpOperation.GET_ORGANIZATION_SUMMARY,
    IamHttpOperation.LIST_ORGANIZATION_ACCESS_INVITATIONS,
    IamHttpOperation.LIST_ORGANIZATION_MEMBERSHIPS,
}

_IDEMPOTENT_OPERATIONS = {
    IamHttpOperation.ACCEPT_ACCESS_INVITATION,
    IamHttpOperation.REVOKE_ACCESS_INVITATION,
    IamHttpOperation.ACCEPT_CURRENT_POLICIES,
    IamHttpOperation.GRANT_CONSENT,
    IamHttpOperation.WITHDRAW_CONSENT,
    IamHttpOperation.REVOKE_MY_SESSION,
    IamHttpOperation.ISSUE_ORGANIZATION_ACCESS_INVITATION,
    IamHttpOperation.UPDATE_ORGANIZATION_PUBLIC_NAME,
    IamHttpOperation.SUSPEND_MEMBERSHIP,
    IamHttpOperation.RESUME_MEMBERSHIP,
    IamHttpOperation.REVOKE_MEMBERSHIP,
    IamHttpOperation.SUSPEND_USER,
    IamHttpOperation.RESUME_USER,
    IamHttpOperation.REVOKE_ALL_USER_SESSIONS,
}

_IF_MATCH_OPERATIONS = _IDEMPOTENT_OPERATIONS - {
    IamHttpOperation.REVOKE_MY_SESSION
}

_EXPECTED_SUCCESS_STATUS = {
    IamHttpOperation.BEGIN_OIDC_AUTHORIZATION: 201,
    IamHttpOperation.COMPLETE_OIDC_AUTHORIZATION: 303,
    IamHttpOperation.GET_SESSION_BOOTSTRAP: 200,
    IamHttpOperation.INSPECT_ACCESS_INVITATION: 200,
    IamHttpOperation.ACCEPT_ACCESS_INVITATION: 200,
    IamHttpOperation.REVOKE_ACCESS_INVITATION: 200,
    IamHttpOperation.GET_POLICY_BUNDLE: 200,
    IamHttpOperation.GET_ME: 200,
    IamHttpOperation.ACCEPT_CURRENT_POLICIES: 200,
    IamHttpOperation.LIST_MY_CONSENT_GRANTS: 200,
    IamHttpOperation.GRANT_CONSENT: 201,
    IamHttpOperation.WITHDRAW_CONSENT: 200,
    IamHttpOperation.LIST_MY_SESSIONS: 200,
    IamHttpOperation.REVOKE_MY_SESSION: 204,
    IamHttpOperation.GET_ORGANIZATION_SUMMARY: 200,
    IamHttpOperation.UPDATE_ORGANIZATION_PUBLIC_NAME: 200,
    IamHttpOperation.LIST_ORGANIZATION_ACCESS_INVITATIONS: 200,
    IamHttpOperation.ISSUE_ORGANIZATION_ACCESS_INVITATION: 201,
    IamHttpOperation.LIST_ORGANIZATION_MEMBERSHIPS: 200,
    IamHttpOperation.SUSPEND_MEMBERSHIP: 200,
    IamHttpOperation.RESUME_MEMBERSHIP: 200,
    IamHttpOperation.REVOKE_MEMBERSHIP: 200,
    IamHttpOperation.SUSPEND_USER: 200,
    IamHttpOperation.RESUME_USER: 200,
    IamHttpOperation.REVOKE_ALL_USER_SESSIONS: 200,
}

_ERROR_STATUS = {
    "INVALID_REQUEST": 400,
    "AUTHENTICATION_REQUIRED": 401,
    "SESSION_EXPIRED": 401,
    "AUTH_TRANSACTION_INVALID": 401,
    "AUTHENTICATION_REJECTED": 401,
    "POLICY_ACCEPTANCE_REQUIRED": 403,
    "CONSENT_REQUIRED_FOR_PURPOSE": 403,
    "MFA_STEP_UP_REQUIRED": 403,
    "SAFETY_HOLD_BLOCKED": 403,
    "RESOURCE_NOT_FOUND": 404,
    "ACCESS_INVITATION_UNAVAILABLE": 404,
    "IDEMPOTENCY_KEY_REUSED": 409,
    "POLICY_BUNDLE_CHANGED": 409,
    "MEMBERSHIP_ALREADY_EXISTS": 409,
    "INVALID_STATE_TRANSITION": 409,
    "LAST_ACTIVE_ORG_ADMIN": 409,
    "SELF_MANAGEMENT_FORBIDDEN": 409,
    "LAST_ACTIVE_ACCESS_ADMIN": 409,
    "PRECONDITION_FAILED": 412,
    "RATE_LIMITED": 429,
    "IDENTITY_PROVIDER_UNAVAILABLE": 503,
    "POLICY_CONFIGURATION_UNAVAILABLE": 503,
    "SAFETY_DECISION_UNAVAILABLE": 503,
    "COMMAND_OUTCOME_UNKNOWN": 503,
    "SERVICE_UNAVAILABLE": 503,
}

_ERROR_MESSAGE = {
    "INVALID_REQUEST": "The request is invalid.",
    "AUTHENTICATION_REQUIRED": "Authentication is required.",
    "SESSION_EXPIRED": "The session has expired.",
    "AUTH_TRANSACTION_INVALID": "The authentication transaction is invalid.",
    "AUTHENTICATION_REJECTED": "Authentication was rejected.",
    "POLICY_ACCEPTANCE_REQUIRED": "Current policy acceptance is required.",
    "CONSENT_REQUIRED_FOR_PURPOSE": "Consent is required for this purpose.",
    "MFA_STEP_UP_REQUIRED": "Recent multi-factor authentication is required.",
    "SAFETY_HOLD_BLOCKED": "The action is blocked by a safety hold.",
    "RESOURCE_NOT_FOUND": "The resource was not found.",
    "ACCESS_INVITATION_UNAVAILABLE": "The access invitation is unavailable.",
    "IDEMPOTENCY_KEY_REUSED": "The idempotency key was reused for another request.",
    "POLICY_BUNDLE_CHANGED": "The current policy bundle has changed.",
    "MEMBERSHIP_ALREADY_EXISTS": "The membership already exists.",
    "INVALID_STATE_TRANSITION": "The requested state transition is invalid.",
    "LAST_ACTIVE_ORG_ADMIN": "The last active organization administrator cannot be removed.",
    "SELF_MANAGEMENT_FORBIDDEN": "An access administrator cannot manage their own account.",
    "LAST_ACTIVE_ACCESS_ADMIN": "The last active access administrator cannot be removed.",
    "PRECONDITION_FAILED": "The resource version does not match.",
    "RATE_LIMITED": "The request rate limit was exceeded.",
    "IDENTITY_PROVIDER_UNAVAILABLE": "The identity provider is unavailable.",
    "POLICY_CONFIGURATION_UNAVAILABLE": "Policy configuration is unavailable.",
    "SAFETY_DECISION_UNAVAILABLE": "The safety decision is unavailable.",
    "COMMAND_OUTCOME_UNKNOWN": "The command outcome is unknown.",
    "SERVICE_UNAVAILABLE": "Service is temporarily unavailable.",
}


class _RequestRejected(Exception):
    def __init__(
        self,
        *,
        code: str = "INVALID_REQUEST",
        status_code: int = 400,
        field_issues: Sequence[Mapping[str, str]] = (),
    ) -> None:
        self.code = code
        self.status_code = status_code
        self.field_issues = tuple(dict(issue) for issue in field_issues)
        super().__init__(code)


class _InvariantViolation(Exception):
    pass


class _DuplicateJsonKey(Exception):
    pass


class _InvalidJsonNumber(Exception):
    pass


def _field_issue(path: str, code: str) -> Mapping[str, str]:
    messages = {
        "MISSING_REQUIRED": "A required request field is missing.",
        "UNKNOWN_FIELD": "The request contains an unknown field.",
        "INVALID_TYPE": "A request field has an invalid type.",
        "INVALID_ENUM": "A request field has an invalid enum value.",
        "INVALID_FORMAT": "A request field has an invalid format.",
        "TOO_LARGE": "The request field exceeds its size limit.",
        "CONFLICT": "Request fields conflict.",
    }
    return {"path": path, "code": code, "message": messages[code]}


def _reject(path: str = "request", issue_code: str = "INVALID_FORMAT") -> None:
    raise _RequestRejected(field_issues=(_field_issue(path, issue_code),))


def _safe_trace_id(source: Optional[TraceIdSource]) -> str:
    if source is None:
        return DEFAULT_DENY_TRACE_ID
    try:
        candidate = source.new_trace_id()
    except Exception:
        return DEFAULT_DENY_TRACE_ID
    if isinstance(candidate, str) and _TRACE_ID.fullmatch(candidate):
        return candidate
    return DEFAULT_DENY_TRACE_ID


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _cors_headers(origin: Optional[str]) -> List[HttpHeader]:
    if origin is None:
        return []
    return [
        HttpHeader(b"access-control-allow-origin", origin.encode("ascii")),
        HttpHeader(b"access-control-allow-credentials", b"true"),
        HttpHeader(b"vary", b"Origin"),
    ]


def _error_response(
    *,
    trace_id: str,
    code: str,
    status_code: Optional[int] = None,
    field_issues: Sequence[Mapping[str, str]] = (),
    allowed_origin: Optional[str] = None,
    retry_after_seconds: Optional[int] = None,
    entity_tag: Optional[str] = None,
) -> HttpResponse:
    if code not in _ERROR_STATUS:
        code = "SERVICE_UNAVAILABLE"
    status = _ERROR_STATUS[code] if status_code is None else status_code
    body = _json_bytes(
        {
            "code": code,
            "message": _ERROR_MESSAGE[code],
            "trace_id": trace_id,
            "field_issues": [dict(issue) for issue in field_issues],
        }
    )
    headers = [
        HttpHeader(b"content-type", b"application/json"),
        HttpHeader(b"cache-control", b"no-store"),
        HttpHeader(b"x-content-type-options", b"nosniff"),
        HttpHeader(b"x-trace-id", trace_id.encode("ascii")),
    ]
    if entity_tag is not None:
        if (
            code != "PRECONDITION_FAILED"
            or status != 412
            or not isinstance(entity_tag, str)
            or _ENTITY_TAG.fullmatch(entity_tag) is None
        ):
            raise _InvariantViolation("error ETag decision is not closed")
        headers.append(HttpHeader(b"etag", entity_tag.encode("ascii")))
    if retry_after_seconds is not None:
        if (
            code != "RATE_LIMITED"
            or type(retry_after_seconds) is not int
            or not 1 <= retry_after_seconds <= 86_400
        ):
            raise _InvariantViolation("Retry-After decision is not closed")
        headers.append(
            HttpHeader(b"retry-after", str(retry_after_seconds).encode("ascii"))
        )
    headers.extend(_cors_headers(allowed_origin))
    return HttpResponse(status_code=status, headers=tuple(headers), body=body)


def service_unavailable_response(
    *, trace_id: str = DEFAULT_DENY_TRACE_ID
) -> HttpResponse:
    return _error_response(trace_id=trace_id, code="SERVICE_UNAVAILABLE")


def _parse_headers(headers: Sequence[HttpHeader]) -> Dict[str, Tuple[bytes, ...]]:
    if not isinstance(headers, tuple) or len(headers) > 100:
        _reject("headers", "TOO_LARGE")
    total = 0
    result: Dict[str, List[bytes]] = {}
    for header in headers:
        if not isinstance(header, HttpHeader):
            _reject("headers", "INVALID_TYPE")
        name = header.name
        value = header.value
        if not isinstance(name, bytes) or not isinstance(value, bytes):
            _reject("headers", "INVALID_TYPE")
        total += len(name) + len(value)
        if len(name) > 8192 or len(value) > 8192 or total > 32768:
            _reject("headers", "TOO_LARGE")
        if not name or _HEADER_NAME.fullmatch(name) is None:
            _reject("headers", "INVALID_FORMAT")
        if any(byte < 32 or byte == 127 for byte in value):
            _reject("headers", "INVALID_FORMAT")
        try:
            normalized = name.decode("ascii").lower()
        except UnicodeDecodeError:
            _reject("headers", "INVALID_FORMAT")
        result.setdefault(normalized, []).append(value)
    for name in _DUPLICATE_CONTROL_HEADERS:
        if len(result.get(name, ())) > 1:
            _reject("headers", "CONFLICT")
    traceparent = result.get("traceparent")
    if traceparent and _TRACEPARENT.fullmatch(traceparent[0]) is None:
        _reject("headers", "INVALID_FORMAT")
    return {name: tuple(values) for name, values in result.items()}


def _single_header(
    headers: Mapping[str, Tuple[bytes, ...]], name: str
) -> Optional[bytes]:
    values = headers.get(name, ())
    if not values:
        return None
    if len(values) != 1:
        _reject("headers", "CONFLICT")
    return values[0]


def _ascii_header(
    headers: Mapping[str, Tuple[bytes, ...]], name: str
) -> Optional[str]:
    raw = _single_header(headers, name)
    if raw is None:
        return None
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        _reject("headers", "INVALID_FORMAT")
    return None


def _parse_cookies(headers: Mapping[str, Tuple[bytes, ...]]) -> Dict[str, str]:
    raw = _ascii_header(headers, "cookie")
    if raw is None:
        return {}
    cookies: Dict[str, str] = {}
    for part in raw.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            _reject("headers", "INVALID_FORMAT")
        name, value = part.split("=", 1)
        try:
            encoded_name = name.encode("ascii")
        except UnicodeEncodeError:
            _reject("headers", "INVALID_FORMAT")
        if not name or _HEADER_NAME.fullmatch(encoded_name) is None:
            _reject("headers", "INVALID_FORMAT")
        if name in cookies:
            _reject("headers", "CONFLICT")
        cookies[name] = value
    return cookies


def _canonical_path_shape(path: str) -> bool:
    if not isinstance(path, str) or not path.startswith("/"):
        return False
    try:
        encoded_path = path.encode("utf-8")
    except UnicodeEncodeError:
        return False
    if len(encoded_path) > 2048:
        return False
    if unicodedata.normalize("NFC", path) != path:
        return False
    if "\\" in path or "//" in path or "\x00" in path:
        return False
    segments = path.split("/")[1:]
    return bool(segments) and all(segment not in {"", ".", ".."} for segment in segments)


def _match_route(
    *, method: str, path: str, routes: Sequence[IamHttpRoute]
) -> Tuple[Optional[IamHttpRoute], Tuple[Tuple[str, str], ...]]:
    if not _canonical_path_shape(path):
        return None, ()
    if not isinstance(method, str) or method != method.upper():
        return None, ()
    actual_segments = path.split("/")[1:]
    for route in routes:
        if route.method != method:
            continue
        template_segments = route.path_template.split("/")[1:]
        if len(template_segments) != len(actual_segments):
            continue
        parameters: List[Tuple[str, str]] = []
        matched = True
        for template, actual in zip(template_segments, actual_segments):
            if template.startswith("{") and template.endswith("}"):
                if _OPAQUE_ID.fullmatch(actual) is None:
                    matched = False
                    break
                parameters.append((template[1:-1], actual))
            elif template != actual:
                matched = False
                break
        if matched:
            return route, tuple(parameters)
    return None, ()


def _percent_decode(value: bytes) -> str:
    if b"+" in value:
        _reject("query", "INVALID_FORMAT")
    index = 0
    while index < len(value):
        if value[index : index + 1] == b"%":
            if index + 3 > len(value) or _PERCENT_ESCAPE.fullmatch(value[index : index + 3]) is None:
                _reject("query", "INVALID_FORMAT")
            index += 3
        else:
            index += 1
    try:
        decoded = unquote_to_bytes(value).decode("utf-8")
    except UnicodeDecodeError:
        _reject("query", "INVALID_FORMAT")
    if unicodedata.normalize("NFC", decoded) != decoded:
        _reject("query", "INVALID_FORMAT")
    return decoded


def _parse_query(
    raw: bytes, *, route: IamHttpRoute
) -> Tuple[Tuple[str, str], ...]:
    if not isinstance(raw, bytes) or len(raw) > route.query_limit_bytes:
        _reject("query", "TOO_LARGE")
    if not raw:
        values: Dict[str, str] = {}
    else:
        values = {}
        for part in raw.split(b"&"):
            if not part or b"=" not in part:
                _reject("query", "INVALID_FORMAT")
            key_raw, value_raw = part.split(b"=", 1)
            key = _percent_decode(key_raw)
            value = _percent_decode(value_raw)
            if not key or key in values:
                _reject("query", "CONFLICT")
            values[key] = value

    if route.operation is IamHttpOperation.COMPLETE_OIDC_AUTHORIZATION:
        allowed = {"state", "code", "error", "error_description"}
        if not set(values).issubset(allowed):
            _reject("query", "UNKNOWN_FIELD")
        state = values.get("state")
        if state is None:
            _reject("query.state", "MISSING_REQUIRED")
        if _PROTOCOL_SECRET.fullmatch(state) is None:
            _reject("query.state", "INVALID_FORMAT")
        has_code = "code" in values
        has_error = "error" in values
        if has_code == has_error:
            _reject("query", "CONFLICT")
        if has_code and _PROTOCOL_SECRET.fullmatch(values["code"]) is None:
            _reject("query.code", "INVALID_FORMAT")
        if has_error and values["error"] not in {
            "access_denied",
            "interaction_required",
            "login_required",
            "temporarily_unavailable",
            "server_error",
        }:
            _reject("query.error", "INVALID_ENUM")
        if len(values.get("error_description", "")) > 512:
            _reject("query.error_description", "TOO_LARGE")
        order = ("state", "code", "error", "error_description")
        return tuple((name, values[name]) for name in order if name in values)

    if route.operation in _PAGINATED_OPERATIONS:
        if not set(values).issubset({"cursor", "limit"}):
            _reject("query", "UNKNOWN_FIELD")
        cursor = values.get("cursor")
        if cursor is not None and (
            not 16 <= len(cursor) <= 2048
            or re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", cursor) is None
        ):
            _reject("query.cursor", "INVALID_FORMAT")
        limit = values.get("limit")
        if limit is not None:
            if not limit.isdigit() or (len(limit) > 1 and limit.startswith("0")):
                _reject("query.limit", "INVALID_FORMAT")
            if not 1 <= int(limit) <= 100:
                _reject("query.limit", "INVALID_FORMAT")
        return tuple((name, values[name]) for name in ("cursor", "limit") if name in values)

    if values:
        _reject("query", "UNKNOWN_FIELD")
    return ()


def _content_length(headers: Mapping[str, Tuple[bytes, ...]]) -> Optional[int]:
    raw = _ascii_header(headers, "content-length")
    if raw is None:
        return None
    if not raw or not raw.isdigit():
        _reject("headers", "INVALID_FORMAT")
    if len(raw) > 19:
        _reject("headers", "TOO_LARGE")
    value = int(raw)
    if value > 2**63 - 1:
        _reject("headers", "TOO_LARGE")
    return value


def _valid_content_type(value: str) -> bool:
    pieces = [piece.strip() for piece in value.split(";")]
    if pieces[0].lower() != "application/json":
        return False
    if len(pieces) == 1:
        return True
    return len(pieces) == 2 and pieces[1].lower() == "charset=utf-8"


def _unique_json_mapping(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey()
        result[key] = value
    return result


def _parse_int(raw: str) -> int:
    value = int(raw)
    if not -(2**63) <= value <= 2**63 - 1:
        raise _InvalidJsonNumber()
    return value


def _reject_number(raw: str) -> Any:
    del raw
    raise _InvalidJsonNumber()


def _validate_nfc_json(value: Any) -> None:
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            _reject("body", "INVALID_FORMAT")
    elif isinstance(value, list):
        for item in value:
            _validate_nfc_json(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            if unicodedata.normalize("NFC", key) != key:
                _reject("body", "INVALID_FORMAT")
            _validate_nfc_json(item)


def _closed_object(
    value: Any,
    *,
    required: Iterable[str],
    optional: Iterable[str] = (),
    path: str = "body",
) -> Dict[str, Any]:
    if not isinstance(value, dict):
        _reject(path, "INVALID_TYPE")
    required_set = set(required)
    allowed = required_set | set(optional)
    missing = required_set - set(value)
    if missing:
        name = sorted(missing)[0]
        _reject(path + "." + name, "MISSING_REQUIRED")
    if not set(value).issubset(allowed):
        _reject(path, "UNKNOWN_FIELD")
    return value


def _string(
    value: Any,
    *,
    path: str,
    minimum: int = 0,
    maximum: int,
) -> str:
    if not isinstance(value, str):
        _reject(path, "INVALID_TYPE")
    if not minimum <= len(value) <= maximum:
        _reject(path, "TOO_LARGE" if len(value) > maximum else "INVALID_FORMAT")
    return value


def _opaque(value: Any, path: str) -> str:
    value = _string(value, path=path, minimum=16, maximum=128)
    if _OPAQUE_ID.fullmatch(value) is None:
        _reject(path, "INVALID_FORMAT")
    return value


def _protocol_secret(value: Any, path: str) -> str:
    value = _string(value, path=path, minimum=32, maximum=2048)
    if _PROTOCOL_SECRET.fullmatch(value) is None:
        _reject(path, "INVALID_FORMAT")
    return value


def _sha256(value: Any, path: str) -> str:
    if not isinstance(value, str) or _CONTENT_SHA256.fullmatch(value) is None:
        _reject(path, "INVALID_FORMAT")
    return value


def _affirmed(value: Any, path: str) -> None:
    if value is not True:
        _reject(path, "INVALID_TYPE" if not isinstance(value, bool) else "INVALID_ENUM")


def _policy_acceptance(value: Any, path: str) -> None:
    item = _closed_object(
        value,
        required=("document_id", "content_sha256", "affirmed"),
        path=path,
    )
    _opaque(item["document_id"], path + ".document_id")
    _sha256(item["content_sha256"], path + ".content_sha256")
    _affirmed(item["affirmed"], path + ".affirmed")


def _consent_choice(value: Any, path: str) -> None:
    item = _closed_object(
        value,
        required=("consent_offer_id", "document_id", "content_sha256", "affirmed"),
        path=path,
    )
    _opaque(item["consent_offer_id"], path + ".consent_offer_id")
    _opaque(item["document_id"], path + ".document_id")
    _sha256(item["content_sha256"], path + ".content_sha256")
    _affirmed(item["affirmed"], path + ".affirmed")


def _policy_requirement(value: Any, path: str) -> None:
    item = _closed_object(
        value,
        required=("selector_digest", "scope_type", "scope_id"),
        path=path,
    )
    _sha256(item["selector_digest"], path + ".selector_digest")
    scope_type = item["scope_type"]
    if scope_type not in {"USER_ROLE", "ORGANIZATION_ROLE"}:
        _reject(path + ".scope_type", "INVALID_ENUM")
    if scope_type == "USER_ROLE":
        if item["scope_id"] is not None:
            _reject(path + ".scope_id", "CONFLICT")
    else:
        _opaque(item["scope_id"], path + ".scope_id")


def _array(
    value: Any,
    *,
    path: str,
    minimum: int,
    maximum: int,
    validator,
) -> None:
    if not isinstance(value, list):
        _reject(path, "INVALID_TYPE")
    if not minimum <= len(value) <= maximum:
        _reject(path, "TOO_LARGE" if len(value) > maximum else "MISSING_REQUIRED")
    seen = set()
    for index, item in enumerate(value):
        validator(item, f"{path}[{index}]")
        canonical = json.dumps(item, sort_keys=True, separators=(",", ":"))
        if canonical in seen:
            _reject(path, "CONFLICT")
        seen.add(canonical)


def _reason_request(value: Any) -> None:
    body = _closed_object(
        value,
        required=("reason_code",),
        optional=("reason_note",),
    )
    reason = _string(body["reason_code"], path="body.reason_code", minimum=3, maximum=64)
    if _REASON_CODE.fullmatch(reason) is None:
        _reject("body.reason_code", "INVALID_FORMAT")
    note = body.get("reason_note")
    if note is not None:
        _string(note, path="body.reason_note", minimum=1, maximum=500)


def _timestamp(value: Any, path: str) -> None:
    value = _string(value, path=path, minimum=1, maximum=64)
    if _UTC_TIMESTAMP.fullmatch(value) is None:
        _reject(path, "INVALID_FORMAT")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _reject(path, "INVALID_FORMAT")
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        _reject(path, "INVALID_FORMAT")


def _validate_body(operation: IamHttpOperation, value: Any) -> None:
    if operation is IamHttpOperation.BEGIN_OIDC_AUTHORIZATION:
        body = _closed_object(
            value,
            required=("return_to",),
            optional=("access_invitation_token", "reauthenticate"),
        )
        return_to = _string(body["return_to"], path="body.return_to", minimum=1, maximum=512)
        if _RETURN_TO.fullmatch(return_to) is None:
            _reject("body.return_to", "INVALID_FORMAT")
        if "access_invitation_token" in body:
            _protocol_secret(
                body["access_invitation_token"],
                "body.access_invitation_token",
            )
        if "reauthenticate" in body and not isinstance(
            body["reauthenticate"], bool
        ):
            _reject("body.reauthenticate", "INVALID_TYPE")
        return

    if operation is IamHttpOperation.INSPECT_ACCESS_INVITATION:
        body = _closed_object(value, required=("access_invitation_token",))
        _protocol_secret(body["access_invitation_token"], "body.access_invitation_token")
        return

    if operation is IamHttpOperation.ACCEPT_ACCESS_INVITATION:
        body = _closed_object(
            value,
            required=("policy_bundle_id", "policy_acceptances", "consent_grants"),
        )
        _opaque(body["policy_bundle_id"], "body.policy_bundle_id")
        _array(
            body["policy_acceptances"],
            path="body.policy_acceptances",
            minimum=1,
            maximum=20,
            validator=_policy_acceptance,
        )
        _array(
            body["consent_grants"],
            path="body.consent_grants",
            minimum=0,
            maximum=20,
            validator=_consent_choice,
        )
        return

    if operation is IamHttpOperation.ACCEPT_CURRENT_POLICIES:
        body = _closed_object(
            value,
            required=("policy_requirement", "policy_bundle_id", "policy_acceptances"),
        )
        _policy_requirement(body["policy_requirement"], "body.policy_requirement")
        _opaque(body["policy_bundle_id"], "body.policy_bundle_id")
        _array(
            body["policy_acceptances"],
            path="body.policy_acceptances",
            minimum=1,
            maximum=20,
            validator=_policy_acceptance,
        )
        return

    if operation is IamHttpOperation.GRANT_CONSENT:
        body = _closed_object(
            value,
            required=(
                "policy_requirement",
                "policy_bundle_id",
                "consent_offer_id",
                "document_id",
                "content_sha256",
                "affirmed",
            ),
        )
        _policy_requirement(body["policy_requirement"], "body.policy_requirement")
        _opaque(body["policy_bundle_id"], "body.policy_bundle_id")
        _consent_choice(
            {
                "consent_offer_id": body["consent_offer_id"],
                "document_id": body["document_id"],
                "content_sha256": body["content_sha256"],
                "affirmed": body["affirmed"],
            },
            "body",
        )
        return

    if operation in {
        IamHttpOperation.REVOKE_ACCESS_INVITATION,
        IamHttpOperation.WITHDRAW_CONSENT,
        IamHttpOperation.SUSPEND_MEMBERSHIP,
        IamHttpOperation.RESUME_MEMBERSHIP,
        IamHttpOperation.REVOKE_MEMBERSHIP,
        IamHttpOperation.SUSPEND_USER,
        IamHttpOperation.RESUME_USER,
        IamHttpOperation.REVOKE_ALL_USER_SESSIONS,
    }:
        _reason_request(value)
        return

    if operation is IamHttpOperation.ISSUE_ORGANIZATION_ACCESS_INVITATION:
        body = _closed_object(
            value,
            required=("recipient", "target_role", "expires_at"),
        )
        recipient = _closed_object(
            body["recipient"],
            required=("type", "value"),
            path="body.recipient",
        )
        if recipient["type"] != "EMAIL":
            _reject("body.recipient.type", "INVALID_ENUM")
        email = _string(
            recipient["value"],
            path="body.recipient.value",
            minimum=3,
            maximum=254,
        )
        if _EMAIL.fullmatch(email) is None:
            _reject("body.recipient.value", "INVALID_FORMAT")
        if body["target_role"] not in {"ORG_ADMIN", "DEMAND_OWNER"}:
            _reject("body.target_role", "INVALID_ENUM")
        _timestamp(body["expires_at"], "body.expires_at")
        return

    if operation is IamHttpOperation.UPDATE_ORGANIZATION_PUBLIC_NAME:
        body = _closed_object(
            value,
            required=("public_name", "reason_code"),
        )
        public_name = _string(
            body["public_name"],
            path="body.public_name",
            minimum=1,
            maximum=160,
        )
        if (
            public_name != public_name.strip()
            or unicodedata.normalize("NFC", public_name) != public_name
            or any(
                unicodedata.category(character) in {"Cc", "Cf"}
                for character in public_name
            )
        ):
            _reject("body.public_name", "INVALID_FORMAT")
        if body["reason_code"] != "PUBLIC_NAME_CORRECTION":
            _reject("body.reason_code", "INVALID_ENUM")
        return

    raise _InvariantViolation("missing closed request validator")


def _freeze_json(value: Any) -> FrozenJsonValue:
    if isinstance(value, dict):
        return tuple((key, _freeze_json(item)) for key, item in value.items())
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _parse_body(
    request: HttpRequest,
    *,
    headers: Mapping[str, Tuple[bytes, ...]],
    route: IamHttpRoute,
) -> FrozenJsonObject:
    if not isinstance(request.body, bytes):
        _reject("body", "INVALID_TYPE")
    declared = _content_length(headers)
    actual = len(request.body)
    if actual > route.body_limit_bytes or (
        declared is not None and declared > route.body_limit_bytes
    ):
        _reject("body", "TOO_LARGE")
    if declared is not None and declared != actual:
        _reject("headers", "CONFLICT")

    expects_body = route.operation in _BODY_OPERATIONS
    content_type = _ascii_header(headers, "content-type")
    if not expects_body:
        if actual or content_type is not None:
            _reject("body", "UNKNOWN_FIELD")
        return ()
    if content_type is None or not _valid_content_type(content_type):
        _reject("headers", "INVALID_FORMAT")
    if not request.body:
        _reject("body", "MISSING_REQUIRED")
    if request.body.startswith(b"\xef\xbb\xbf"):
        _reject("body", "INVALID_FORMAT")
    try:
        text = request.body.decode("utf-8")
        loaded = json.loads(
            text,
            object_pairs_hook=_unique_json_mapping,
            parse_int=_parse_int,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        _InvalidJsonNumber,
    ):
        _reject("body", "INVALID_FORMAT")
    if not isinstance(loaded, dict):
        _reject("body", "INVALID_TYPE")
    _validate_nfc_json(loaded)
    _validate_body(route.operation, loaded)
    frozen = _freeze_json(loaded)
    if not isinstance(frozen, tuple):
        raise _InvariantViolation("top-level JSON object did not freeze")
    return frozen


def _required_protocol_headers(
    *,
    route: IamHttpRoute,
    headers: Mapping[str, Tuple[bytes, ...]],
) -> Tuple[Optional[str], Optional[int], Optional[str]]:
    idempotency_key = _ascii_header(headers, "idempotency-key")
    if route.operation in _IDEMPOTENT_OPERATIONS:
        if idempotency_key is None:
            _reject("headers", "MISSING_REQUIRED")
        if _IDEMPOTENCY_KEY.fullmatch(idempotency_key) is None:
            _reject("headers", "INVALID_FORMAT")
    elif idempotency_key is not None:
        _reject("headers", "UNKNOWN_FIELD")

    expected_version: Optional[int] = None
    if_match = _ascii_header(headers, "if-match")
    if route.operation in _IF_MATCH_OPERATIONS:
        if if_match is None:
            _reject("headers", "MISSING_REQUIRED")
        matched = _ENTITY_TAG.fullmatch(if_match)
        if matched is None:
            _reject("headers", "INVALID_FORMAT")
        expected_version = int(matched.group(1))
    elif if_match is not None:
        _reject("headers", "UNKNOWN_FIELD")

    csrf = _ascii_header(headers, "x-csrf-token")
    if route.csrf is HttpCsrfMode.SESSION_REQUIRED:
        if csrf is None:
            _reject("headers", "MISSING_REQUIRED")
        if _CSRF_TOKEN.fullmatch(csrf) is None:
            _reject("headers", "INVALID_FORMAT")
    elif csrf is not None and route.csrf is not HttpCsrfMode.SESSION_IF_AUTHENTICATED:
        _reject("headers", "UNKNOWN_FIELD")
    elif csrf is not None and _CSRF_TOKEN.fullmatch(csrf) is None:
        _reject("headers", "INVALID_FORMAT")
    return idempotency_key, expected_version, csrf


def _thaw_json_value(value: FrozenJsonValue) -> Any:
    if value is None or isinstance(value, (bool, str)):
        if isinstance(value, str) and unicodedata.normalize("NFC", value) != value:
            raise _InvariantViolation("response string is not NFC")
        return value
    if type(value) is int:
        if not -(2**63) <= value <= 2**63 - 1:
            raise _InvariantViolation("response integer is outside signed 64-bit")
        return value
    if isinstance(value, tuple):
        if value and all(
            isinstance(item, tuple)
            and len(item) == 2
            and isinstance(item[0], str)
            for item in value
        ):
            result: Dict[str, Any] = {}
            for key, item in value:
                if key in result:
                    raise _InvariantViolation("duplicate response object key")
                result[key] = _thaw_json_value(item)
            return result
        return [_thaw_json_value(item) for item in value]
    raise _InvariantViolation("unsupported response JSON value")


def _thaw_json_object(value: FrozenJsonObject) -> Dict[str, Any]:
    if not isinstance(value, tuple):
        raise _InvariantViolation("response JSON body is not immutable")
    result: Dict[str, Any] = {}
    for pair in value:
        if not isinstance(pair, tuple) or len(pair) != 2 or not isinstance(pair[0], str):
            raise _InvariantViolation("response JSON body is not an object")
        key, item = pair
        if key in result:
            raise _InvariantViolation("duplicate response object key")
        result[key] = _thaw_json_value(item)
    return result


def _cookie_headers(
    operation: IamHttpOperation,
    result: IamHttpOperationResult,
) -> List[HttpHeader]:
    mutations = result.cookie_mutations
    if not isinstance(mutations, tuple) or not all(
        isinstance(mutation, CookieMutation) for mutation in mutations
    ):
        raise _InvariantViolation("cookie mutation collection is not closed")
    kinds = tuple(mutation.kind for mutation in mutations)
    if operation is IamHttpOperation.ACCEPT_ACCESS_INVITATION:
        if result.replayed:
            if mutations:
                raise _InvariantViolation("receipt replay attempted cookie mutation")
        elif kinds != (CookieMutationKind.SET_SESSION,):
            raise _InvariantViolation("first accept success requires one Session rotation")
    elif operation is IamHttpOperation.BEGIN_OIDC_AUTHORIZATION:
        if result.replayed or kinds != (CookieMutationKind.SET_OIDC_BROWSER,):
            raise _InvariantViolation("OIDC begin cookie mutation is invalid")
    elif operation is IamHttpOperation.COMPLETE_OIDC_AUTHORIZATION:
        if result.replayed or kinds != (
            CookieMutationKind.SET_SESSION,
            CookieMutationKind.CLEAR_OIDC_BROWSER,
        ):
            raise _InvariantViolation("OIDC callback cookie mutations are invalid")
    elif operation is IamHttpOperation.REVOKE_MY_SESSION:
        if kinds not in {(), (CookieMutationKind.CLEAR_SESSION,)}:
            raise _InvariantViolation("Session revoke cookie mutation is invalid")
    elif mutations:
        raise _InvariantViolation("operation is not allowed to mutate cookies")

    headers: List[HttpHeader] = []
    for mutation in mutations:
        if mutation.kind in {
            CookieMutationKind.CLEAR_OIDC_BROWSER,
            CookieMutationKind.CLEAR_SESSION,
        }:
            if mutation.raw_value is not None:
                raise _InvariantViolation("clear cookie cannot carry a raw value")
            cookie_name = (
                "__Host-ds_oidc"
                if mutation.kind is CookieMutationKind.CLEAR_OIDC_BROWSER
                else "__Host-ds_session"
            )
            serialized = (
                f"{cookie_name}=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"
            )
        else:
            raw = mutation.raw_value
            if not isinstance(raw, str) or _PROTOCOL_SECRET.fullmatch(raw) is None:
                raise _InvariantViolation("cookie secret is malformed")
            if mutation.kind is CookieMutationKind.SET_SESSION:
                serialized = (
                    f"__Host-ds_session={raw}; Secure; HttpOnly; "
                    "SameSite=Lax; Path=/"
                )
            elif mutation.kind is CookieMutationKind.SET_OIDC_BROWSER:
                serialized = (
                    f"__Host-ds_oidc={raw}; Secure; HttpOnly; "
                    "SameSite=Lax; Path=/; Max-Age=600"
                )
            else:
                raise _InvariantViolation("unknown cookie mutation")
        headers.append(HttpHeader(b"set-cookie", serialized.encode("ascii")))
    return headers


def _present_result(
    *,
    route: IamHttpRoute,
    result: IamHttpOperationResult,
    trace_id: str,
    allowed_origin: Optional[str],
) -> HttpResponse:
    if not isinstance(result, IamHttpOperationResult):
        raise _InvariantViolation("dispatcher returned an open result")
    expected_status = _EXPECTED_SUCCESS_STATUS[route.operation]
    if result.status_code != expected_status:
        raise _InvariantViolation("dispatcher returned an unregistered success status")
    if result.retry_after_seconds is not None:
        raise _InvariantViolation("success response cannot carry Retry-After")

    headers: List[HttpHeader] = [
        HttpHeader(b"x-content-type-options", b"nosniff"),
        HttpHeader(b"x-trace-id", trace_id.encode("ascii")),
    ]
    if route.operation is IamHttpOperation.GET_POLICY_BUNDLE:
        headers.append(
            HttpHeader(
                b"cache-control",
                b"public, max-age=31536000, immutable",
            )
        )
    else:
        headers.append(HttpHeader(b"cache-control", b"no-store"))
    headers.extend(_cors_headers(allowed_origin))

    if result.entity_tag is not None:
        if not isinstance(result.entity_tag, str) or _ENTITY_TAG.fullmatch(result.entity_tag) is None:
            raise _InvariantViolation("result ETag is not a strong aggregate tag")
        headers.append(HttpHeader(b"etag", result.entity_tag.encode("ascii")))

    if expected_status == 204:
        if result.json_body is not None or result.redirect_location is not None:
            raise _InvariantViolation("204 result must have no representation")
        body = b""
    elif expected_status == 303:
        if result.json_body is not None:
            raise _InvariantViolation("303 result must have no JSON body")
        location = result.redirect_location
        if not isinstance(location, str) or len(location) > 512 or _RETURN_TO.fullmatch(location) is None:
            raise _InvariantViolation("redirect location is not registered-path shaped")
        headers.append(HttpHeader(b"location", location.encode("ascii")))
        body = b""
    else:
        if result.json_body is None:
            raise _InvariantViolation("JSON success result is missing its body")
        body = _json_bytes(_thaw_json_object(result.json_body))
        headers.append(HttpHeader(b"content-type", b"application/json"))

    headers.extend(_cookie_headers(route.operation, result))
    return HttpResponse(
        status_code=expected_status,
        headers=tuple(headers),
        body=body,
    )


def _request_size_bucket(size: int) -> str:
    if size == 0:
        return "0"
    if size <= 1024:
        return "1-1024"
    if size <= 8192:
        return "1025-8192"
    if size <= 65536:
        return "8193-65536"
    return "65537+"


class IamHttpTransport:
    """Closed IAM HTTP protocol kernel with injected application/security ports."""

    def __init__(
        self,
        *,
        dispatcher: Optional[IamHttpOperationDispatcher] = None,
        session_authenticator: Optional[SessionAuthenticator] = None,
        origin_policy: Optional[OriginPolicy] = None,
        csrf_verifier: Optional[CsrfVerifier] = None,
        rate_limiter: Optional[RateLimiter] = None,
        telemetry: Optional[HttpTelemetry] = None,
        trace_id_source: Optional[TraceIdSource] = None,
        allow_insecure_http: bool = False,
        routes: Tuple[IamHttpRoute, ...] = IAM_HTTP_ROUTES,
    ) -> None:
        self._dispatcher = dispatcher
        self._session_authenticator = session_authenticator
        self._origin_policy = origin_policy
        self._csrf_verifier = csrf_verifier
        self._rate_limiter = rate_limiter
        self._telemetry = telemetry
        self._trace_id_source = trace_id_source
        self._allow_insecure_http = allow_insecure_http
        self._routes = tuple(routes)
        if not isinstance(allow_insecure_http, bool):
            raise TypeError("allow_insecure_http must be boolean")
        if not all(isinstance(route, IamHttpRoute) for route in self._routes):
            raise TypeError("routes must contain only immutable IamHttpRoute values")
        route_keys = {(route.method, route.path_template) for route in self._routes}
        operations = {route.operation for route in self._routes}
        if len(route_keys) != len(self._routes) or len(operations) != len(self._routes):
            raise ValueError("IAM HTTP routes must be unique by path/method and operation")

    @property
    def routes(self) -> Tuple[IamHttpRoute, ...]:
        return self._routes

    def body_limit_for(self, *, method: str, path: str) -> int:
        route, _ = _match_route(method=method, path=path, routes=self._routes)
        return -1 if route is None else route.body_limit_bytes

    def unavailable(self, request: HttpRequest) -> HttpResponse:
        trace_id = _safe_trace_id(self._trace_id_source)
        route, _ = _match_route(
            method=request.method,
            path=request.path,
            routes=self._routes,
        )
        response = _error_response(trace_id=trace_id, code="SERVICE_UNAVAILABLE")
        self._record(
            request=request,
            route=route,
            response=response,
            trace_id=trace_id,
            error_code="SERVICE_UNAVAILABLE",
            authenticated=False,
            replayed=False,
        )
        return response

    def deadline_exceeded(self, request: HttpRequest) -> HttpResponse:
        """Close an outer ASGI deadline without inferring command rollback.

        A read-only operation has no commit ambiguity and uses the ordinary
        availability classification.  Once a mutating operation may have
        entered its application unit of work, the only safe public outcome is
        ``COMMAND_OUTCOME_UNKNOWN``.  The adapter never retries either class.
        """

        trace_id = _safe_trace_id(self._trace_id_source)
        route, _ = _match_route(
            method=request.method,
            path=request.path,
            routes=self._routes,
        )
        code = (
            "SERVICE_UNAVAILABLE"
            if route is not None and route.operation in _SIDE_EFFECT_FREE_OPERATIONS
            else "COMMAND_OUTCOME_UNKNOWN"
        )
        response = _error_response(trace_id=trace_id, code=code)
        self._record(
            request=request,
            route=route,
            response=response,
            trace_id=trace_id,
            error_code=code,
            authenticated=False,
            replayed=False,
        )
        return response

    def invalid_request(
        self,
        request: HttpRequest,
        *,
        path: str,
        issue_code: str,
    ) -> HttpResponse:
        trace_id = _safe_trace_id(self._trace_id_source)
        route, _ = _match_route(
            method=request.method,
            path=request.path,
            routes=self._routes,
        )
        if issue_code not in {
            "MISSING_REQUIRED",
            "UNKNOWN_FIELD",
            "INVALID_TYPE",
            "INVALID_ENUM",
            "INVALID_FORMAT",
            "TOO_LARGE",
            "CONFLICT",
        }:
            issue_code = "INVALID_FORMAT"
        response = _error_response(
            trace_id=trace_id,
            code="INVALID_REQUEST",
            field_issues=(_field_issue(path, issue_code),),
        )
        self._record(
            request=request,
            route=route,
            response=response,
            trace_id=trace_id,
            error_code="INVALID_REQUEST",
            authenticated=False,
            replayed=False,
        )
        return response

    def _record(
        self,
        *,
        request: HttpRequest,
        route: Optional[IamHttpRoute],
        response: HttpResponse,
        trace_id: str,
        error_code: Optional[str],
        authenticated: bool,
        replayed: bool,
    ) -> None:
        if self._telemetry is None:
            return
        event = HttpTelemetryEvent(
            trace_id=trace_id,
            operation_id=None if route is None else route.operation.value,
            method=(
                request.method
                if request.method in {"GET", "POST", "DELETE", "OPTIONS"}
                else "OTHER"
            ),
            route_template=None if route is None else route.path_template,
            status_code=response.status_code,
            error_code=error_code,
            request_size_bucket=_request_size_bucket(len(request.body)),
            duration_bucket="not_measured",
            authenticated=authenticated,
            replayed=replayed,
        )
        try:
            self._telemetry.record(event)
        except Exception:
            pass

    def handle(self, request: HttpRequest) -> HttpResponse:
        trace_id = _safe_trace_id(self._trace_id_source)
        route: Optional[IamHttpRoute] = None
        actor: Optional[AuthenticatedHttpActor] = None
        allowed_origin: Optional[str] = None
        replayed = False

        def finish(response: HttpResponse, error_code: Optional[str]) -> HttpResponse:
            self._record(
                request=request,
                route=route,
                response=response,
                trace_id=trace_id,
                error_code=error_code,
                authenticated=actor is not None,
                replayed=replayed,
            )
            return response

        try:
            if not isinstance(request, HttpRequest):
                raise _RequestRejected(
                    field_issues=(_field_issue("request", "INVALID_TYPE"),)
                )
            if request.scheme != "https" and not (
                self._allow_insecure_http and request.scheme == "http"
            ):
                _reject("request", "INVALID_FORMAT")
            headers = _parse_headers(request.headers)

            if request.method == "OPTIONS":
                response, route, allowed_origin = self._preflight(
                    request=request,
                    headers=headers,
                    trace_id=trace_id,
                )
                return finish(response, None)

            route, path_parameters = _match_route(
                method=request.method,
                path=request.path,
                routes=self._routes,
            )
            if route is None:
                return finish(
                    _error_response(trace_id=trace_id, code="RESOURCE_NOT_FOUND"),
                    "RESOURCE_NOT_FOUND",
                )

            query_parameters = _parse_query(
                request.raw_query_string,
                route=route,
            )
            json_body = _parse_body(request, headers=headers, route=route)
            idempotency_key, expected_version, csrf_token = _required_protocol_headers(
                route=route,
                headers=headers,
            )

            origin = _ascii_header(headers, "origin")
            if route.csrf in {
                HttpCsrfMode.ORIGIN_ONLY,
                HttpCsrfMode.SESSION_IF_AUTHENTICATED,
                HttpCsrfMode.SESSION_REQUIRED,
            }:
                if self._origin_policy is None:
                    raise IamError("SERVICE_UNAVAILABLE")
                self._origin_policy.require_allowed(
                    origin=origin,
                    operation_id=route.operation.value,
                )
                allowed_origin = origin
            elif origin is not None and route.operation is not IamHttpOperation.COMPLETE_OIDC_AUTHORIZATION:
                if self._origin_policy is None:
                    raise IamError("SERVICE_UNAVAILABLE")
                self._origin_policy.require_allowed(
                    origin=origin,
                    operation_id=route.operation.value,
                )
                allowed_origin = origin

            cookies: Dict[str, str] = {}
            raw_session_handle: Optional[str] = None
            raw_oidc_cookie: Optional[str] = None
            if route.authentication is not HttpAuthenticationMode.ANONYMOUS:
                cookies = _parse_cookies(headers)

            if route.authentication is HttpAuthenticationMode.OIDC_BROWSER:
                raw_oidc_cookie = cookies.get("__Host-ds_oidc")
                if raw_oidc_cookie is None:
                    _reject("headers", "MISSING_REQUIRED")
                _protocol_secret(raw_oidc_cookie, "headers")
                candidate = cookies.get("__Host-ds_session")
                if candidate is not None:
                    if self._session_authenticator is None:
                        raise IamError("SERVICE_UNAVAILABLE")
                    try:
                        callback_actor = self._session_authenticator.authenticate(
                            raw_session_handle=candidate,
                            trace_id=trace_id,
                        )
                    except IamError as error:
                        if error.code not in {
                            "AUTHENTICATION_REQUIRED",
                            "SESSION_EXPIRED",
                        }:
                            raise
                        callback_actor = None
                    if callback_actor is not None and not isinstance(
                        callback_actor, AuthenticatedHttpActor
                    ):
                        raise IamError("SERVICE_UNAVAILABLE")
                    raw_session_handle = (
                        candidate if callback_actor is not None else None
                    )
            elif route.authentication is HttpAuthenticationMode.REQUIRED_SESSION:
                raw_session_handle = cookies.get("__Host-ds_session")
                if raw_session_handle is None:
                    raise IamError("AUTHENTICATION_REQUIRED")
                if self._session_authenticator is None:
                    raise IamError("SERVICE_UNAVAILABLE")
                actor = self._session_authenticator.authenticate(
                    raw_session_handle=raw_session_handle,
                    trace_id=trace_id,
                )
                if not isinstance(actor, AuthenticatedHttpActor):
                    raise IamError("AUTHENTICATION_REQUIRED")
            elif route.authentication is HttpAuthenticationMode.OPTIONAL_SESSION:
                candidate = cookies.get("__Host-ds_session")
                if candidate is not None:
                    if self._session_authenticator is None:
                        raise IamError("SERVICE_UNAVAILABLE")
                    try:
                        actor = self._session_authenticator.authenticate(
                            raw_session_handle=candidate,
                            trace_id=trace_id,
                        )
                    except IamError as error:
                        if error.code not in {
                            "AUTHENTICATION_REQUIRED",
                            "SESSION_EXPIRED",
                        }:
                            raise
                        actor = None
                    if actor is not None and not isinstance(
                        actor, AuthenticatedHttpActor
                    ):
                        raise IamError("SERVICE_UNAVAILABLE")
                    raw_session_handle = candidate if actor is not None else None

            requires_csrf = route.csrf is HttpCsrfMode.SESSION_REQUIRED or (
                route.csrf is HttpCsrfMode.SESSION_IF_AUTHENTICATED
                and actor is not None
            )
            if requires_csrf:
                if csrf_token is None or _CSRF_TOKEN.fullmatch(csrf_token) is None:
                    _reject("headers", "MISSING_REQUIRED")
                if (
                    self._csrf_verifier is None
                    or actor is None
                    or raw_session_handle is None
                ):
                    raise IamError("SERVICE_UNAVAILABLE")
                self._csrf_verifier.require_valid(
                    raw_session_handle=raw_session_handle,
                    raw_csrf_token=csrf_token,
                    actor=actor,
                    operation_id=route.operation.value,
                )

            if self._rate_limiter is None:
                raise IamError("SERVICE_UNAVAILABLE")
            self._rate_limiter.require_allowed(
                operation_id=route.operation.value,
                actor=actor,
            )
            if self._dispatcher is None:
                raise IamError("SERVICE_UNAVAILABLE")
            invocation = IamHttpInvocation(
                operation_id=route.operation.value,
                canonical_path=request.path,
                path_parameters=path_parameters,
                query_parameters=query_parameters,
                json_body=json_body,
                actor=actor,
                idempotency_key=idempotency_key,
                expected_version=expected_version,
                trace_id=trace_id,
                raw_session_handle=raw_session_handle,
                raw_oidc_browser_cookie=raw_oidc_cookie,
            )
            result = self._dispatcher.dispatch(invocation)
            replayed = result.replayed if isinstance(result, IamHttpOperationResult) else False
            response = _present_result(
                route=route,
                result=result,
                trace_id=trace_id,
                allowed_origin=allowed_origin,
            )
            return finish(response, None)
        except _RequestRejected as error:
            code = error.code if error.code in _ERROR_STATUS else "INVALID_REQUEST"
            return finish(
                _error_response(
                    trace_id=trace_id,
                    code=code,
                    status_code=error.status_code,
                    field_issues=error.field_issues,
                    allowed_origin=allowed_origin,
                ),
                code,
            )
        except RateLimitExceeded as error:
            return finish(
                _error_response(
                    trace_id=trace_id,
                    code="RATE_LIMITED",
                    allowed_origin=allowed_origin,
                    retry_after_seconds=error.retry_after_seconds,
                ),
                "RATE_LIMITED",
            )
        except IamPreconditionFailed as error:
            return finish(
                _error_response(
                    trace_id=trace_id,
                    code=error.code,
                    allowed_origin=allowed_origin,
                    entity_tag=error.entity_tag,
                ),
                error.code,
            )
        except IamError as error:
            code = error.code if error.code in _ERROR_STATUS else "SERVICE_UNAVAILABLE"
            return finish(
                _error_response(
                    trace_id=trace_id,
                    code=code,
                    allowed_origin=allowed_origin,
                ),
                code,
            )
        except Exception:
            return finish(
                _error_response(
                    trace_id=trace_id,
                    code="SERVICE_UNAVAILABLE",
                    allowed_origin=allowed_origin,
                ),
                "SERVICE_UNAVAILABLE",
            )

    def _preflight(
        self,
        *,
        request: HttpRequest,
        headers: Mapping[str, Tuple[bytes, ...]],
        trace_id: str,
    ) -> Tuple[HttpResponse, Optional[IamHttpRoute], Optional[str]]:
        if request.body or request.raw_query_string:
            _reject("request", "UNKNOWN_FIELD")
        requested_method = _ascii_header(
            headers,
            "access-control-request-method",
        )
        if requested_method is None:
            _reject("headers", "MISSING_REQUIRED")
        route, _ = _match_route(
            method=requested_method,
            path=request.path,
            routes=self._routes,
        )
        if route is None:
            return (
                _error_response(trace_id=trace_id, code="RESOURCE_NOT_FOUND"),
                None,
                None,
            )
        origin = _ascii_header(headers, "origin")
        if self._origin_policy is None:
            raise IamError("SERVICE_UNAVAILABLE")
        self._origin_policy.require_allowed(
            origin=origin,
            operation_id=route.operation.value,
        )
        requested_headers = _ascii_header(
            headers,
            "access-control-request-headers",
        )
        requested: List[str] = []
        if requested_headers is not None:
            for item in requested_headers.split(","):
                normalized = item.strip().lower()
                if not normalized or _HEADER_NAME.fullmatch(normalized.encode("ascii")) is None:
                    _reject("headers", "INVALID_FORMAT")
                requested.append(normalized)
            if len(requested) != len(set(requested)):
                _reject("headers", "CONFLICT")
            if not set(requested).issubset(
                {"content-type", "idempotency-key", "if-match", "x-csrf-token"}
            ):
                _reject("headers", "UNKNOWN_FIELD")
        response_headers = [
            HttpHeader(b"cache-control", b"no-store"),
            HttpHeader(b"x-content-type-options", b"nosniff"),
            HttpHeader(b"x-trace-id", trace_id.encode("ascii")),
            HttpHeader(b"access-control-allow-origin", origin.encode("ascii")),
            HttpHeader(b"access-control-allow-credentials", b"true"),
            HttpHeader(b"access-control-allow-methods", route.method.encode("ascii")),
            HttpHeader(b"vary", b"Origin"),
        ]
        if requested:
            response_headers.append(
                HttpHeader(
                    b"access-control-allow-headers",
                    ", ".join(requested).encode("ascii"),
                )
            )
        return (
            HttpResponse(status_code=204, headers=tuple(response_headers), body=b""),
            route,
            origin,
        )
