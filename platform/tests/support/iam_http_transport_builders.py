"""Synthetic builders and strict spies for TEST-HTTP-IAM-001."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlencode

import yaml

from desire_platform.http import (
    AuthenticatedHttpActor,
    CookieMutation,
    CookieMutationKind,
    HttpHeader,
    HttpRequest,
    HttpResponse,
    HttpTelemetryEvent,
    IamAsgiApplication,
    IamHttpInvocation,
    IamHttpOperationResult,
    IamHttpTransport,
)
from desire_platform.identity_access.domain.errors import IamError


PLATFORM_ROOT = Path(__file__).resolve().parents[2]
OPENAPI_PATH = PLATFORM_ROOT / "contracts" / "api" / "iam-v1.openapi.yaml"
ALLOWED_ORIGIN = "https://app.example.test"
SESSION_HANDLE = "session_handle_0123456789abcdefghijklmnop"
OIDC_BROWSER_COOKIE = "oidc_browser_0123456789abcdefghijklmnopq"
CSRF_TOKEN = "csrf_token_0123456789abcdefghijklmnopqrstuvwxyz"
IDEMPOTENCY_KEY = "idem_0123456789abcdef"
PROTOCOL_SECRET = "A" * 43
SENSITIVE_SENTINEL = "SECRET_SENTINEL_http_never_observe_9274"


@dataclass(frozen=True)
class OpenApiOperationCase:
    method: str
    path_template: str
    operation_id: str
    success_status: int
    parameter_components: Tuple[str, ...]
    has_json_body: bool
    security: Tuple[Tuple[str, ...], ...]


def load_openapi() -> Mapping[str, Any]:
    loaded = yaml.safe_load(OPENAPI_PATH.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise AssertionError("IAM OpenAPI root must be a mapping")
    return loaded


def _resolve(document: Mapping[str, Any], value: Any) -> Any:
    seen: set[str] = set()
    while isinstance(value, dict) and isinstance(value.get("$ref"), str):
        reference = value["$ref"]
        if reference in seen or not reference.startswith("#/"):
            raise AssertionError(f"invalid local reference: {reference}")
        seen.add(reference)
        current: Any = document
        for part in reference[2:].split("/"):
            current = current[part.replace("~1", "/").replace("~0", "~")]
        value = current
    return value


def openapi_operation_cases() -> Tuple[OpenApiOperationCase, ...]:
    document = load_openapi()
    cases: List[OpenApiOperationCase] = []
    for path_template, path_item in document["paths"].items():
        for method, operation in path_item.items():
            if method not in {"get", "post", "put", "patch", "delete"}:
                continue
            body = operation.get("requestBody")
            body = _resolve(document, body) if body is not None else None
            components: List[str] = []
            for parameter in operation.get("parameters", ()):
                reference = parameter.get("$ref")
                if isinstance(reference, str):
                    components.append(reference.rsplit("/", 1)[-1])
                else:
                    components.append(f"{parameter.get('in')}:{parameter.get('name')}")
            success = min(
                int(status)
                for status in operation["responses"]
                if status.isdigit() and 200 <= int(status) < 400
            )
            security = tuple(
                tuple(sorted(item)) for item in operation.get("security", ())
            )
            cases.append(
                OpenApiOperationCase(
                    method=method.upper(),
                    path_template=path_template,
                    operation_id=operation["operationId"],
                    success_status=success,
                    parameter_components=tuple(components),
                    has_json_body=body is not None,
                    security=security,
                )
            )
    return tuple(cases)


OPENAPI_OPERATIONS = openapi_operation_cases()


def freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        return tuple((key, freeze_json(item)) for key, item in value.items())
    if isinstance(value, list):
        return tuple(freeze_json(item) for item in value)
    return value


def success_result(case: OpenApiOperationCase) -> IamHttpOperationResult:
    cookie_mutations: Tuple[CookieMutation, ...] = ()
    if case.operation_id == "beginOidcAuthorization":
        cookie_mutations = (
            CookieMutation(CookieMutationKind.SET_OIDC_BROWSER, OIDC_BROWSER_COOKIE),
        )
    elif case.operation_id == "completeOidcAuthorization":
        cookie_mutations = (
            CookieMutation(
                CookieMutationKind.SET_SESSION,
                SESSION_HANDLE + "_successor",
            ),
            CookieMutation(CookieMutationKind.CLEAR_OIDC_BROWSER),
        )
    elif case.operation_id == "acceptAccessInvitation":
        cookie_mutations = (
            CookieMutation(
                CookieMutationKind.SET_SESSION,
                SESSION_HANDLE + "_successor",
            ),
        )
    if case.success_status in {204, 303}:
        return IamHttpOperationResult(
            status_code=case.success_status,
            json_body=None,
            redirect_location=(
                "/app" if case.operation_id == "completeOidcAuthorization" else None
            ),
            cookie_mutations=cookie_mutations,
        )
    return IamHttpOperationResult(
        status_code=case.success_status,
        json_body=freeze_json(
            {
                "operation_id": case.operation_id,
                "result": "synthetic-safe",
            }
        ),
        entity_tag=(
            '"v1"'
            if case.operation_id
            in {
                "inspectAccessInvitation",
                "acceptAccessInvitation",
                "revokeAccessInvitation",
                "getMe",
                "acceptCurrentPolicies",
                "grantConsent",
                "withdrawConsent",
                "getOrganizationSummary",
                "updateOrganizationPublicName",
                "issueOrganizationAccessInvitation",
                "suspendMembership",
                "resumeMembership",
                "revokeMembership",
                "suspendUser",
                "resumeUser",
                "revokeAllUserSessions",
            }
            else None
        ),
        cookie_mutations=cookie_mutations,
    )


class RecordingDispatcher:
    def __init__(self) -> None:
        self.calls: List[IamHttpInvocation] = []
        self.results: Dict[str, IamHttpOperationResult] = {
            case.operation_id: success_result(case) for case in OPENAPI_OPERATIONS
        }
        self.errors: Dict[str, BaseException] = {}

    def dispatch(self, invocation: IamHttpInvocation) -> IamHttpOperationResult:
        self.calls.append(invocation)
        error = self.errors.get(invocation.operation_id)
        if error is not None:
            raise error
        return self.results[invocation.operation_id]


class FakeSessionAuthenticator:
    def __init__(self) -> None:
        self.calls: List[Tuple[Optional[str], str]] = []
        self.error_code: Optional[str] = None
        self.actor = AuthenticatedHttpActor(
            actor_user_id="user_0123456789abcdef",
            session_id="session_0123456789abcdef",
            correlation_id="correlation_0123456789abcdef",
            causation_id="causation_0123456789abcdef",
            trace_id="trace_http_test_0123456789",
            original_actor_id=None,
            auth_time=datetime(2026, 8, 8, 0, 0, tzinfo=timezone.utc)
            - timedelta(minutes=5),
            acr_code="urn:example:acr:mfa",
            amr_codes=("pwd", "otp"),
        )

    def authenticate(
        self, *, raw_session_handle: Optional[str], trace_id: str
    ) -> Optional[AuthenticatedHttpActor]:
        self.calls.append((raw_session_handle, trace_id))
        if self.error_code is not None:
            raise IamError(self.error_code)
        if raw_session_handle != SESSION_HANDLE:
            raise IamError("AUTHENTICATION_REQUIRED")
        return self.actor


class FakeOriginPolicy:
    def __init__(self) -> None:
        self.calls: List[Tuple[Optional[str], str]] = []

    def require_allowed(self, *, origin: Optional[str], operation_id: str) -> None:
        self.calls.append((origin, operation_id))
        if origin != ALLOWED_ORIGIN:
            raise IamError("INVALID_REQUEST")


class FakeCsrfVerifier:
    def __init__(self) -> None:
        self.calls: List[Tuple[str, Optional[str], str, str]] = []

    def require_valid(
        self,
        *,
        raw_session_handle: str,
        raw_csrf_token: Optional[str],
        actor: AuthenticatedHttpActor,
        operation_id: str,
    ) -> None:
        self.calls.append(
            (raw_session_handle, raw_csrf_token, actor.session_id, operation_id)
        )
        if raw_session_handle != SESSION_HANDLE or raw_csrf_token != CSRF_TOKEN:
            raise IamError("INVALID_REQUEST")


class FakeRateLimiter:
    def __init__(self) -> None:
        self.calls: List[Tuple[str, Optional[str]]] = []
        self.reject = False

    def require_allowed(
        self, *, operation_id: str, actor: Optional[AuthenticatedHttpActor]
    ) -> None:
        self.calls.append(
            (operation_id, None if actor is None else actor.actor_user_id)
        )
        if self.reject:
            raise IamError("RATE_LIMITED")


class RecordingTelemetry:
    def __init__(self) -> None:
        self.events: List[HttpTelemetryEvent] = []

    def record(self, event: HttpTelemetryEvent) -> None:
        self.events.append(event)


class FixedTraceIdSource:
    def new_trace_id(self) -> str:
        return "trace_http_test_0123456789"


@dataclass
class HttpFixture:
    dispatcher: RecordingDispatcher
    session_authenticator: FakeSessionAuthenticator
    origin_policy: FakeOriginPolicy
    csrf_verifier: FakeCsrfVerifier
    rate_limiter: FakeRateLimiter
    telemetry: RecordingTelemetry
    transport: IamHttpTransport


def make_http_fixture() -> HttpFixture:
    dispatcher = RecordingDispatcher()
    session_authenticator = FakeSessionAuthenticator()
    origin_policy = FakeOriginPolicy()
    csrf_verifier = FakeCsrfVerifier()
    rate_limiter = FakeRateLimiter()
    telemetry = RecordingTelemetry()
    transport = IamHttpTransport(
        dispatcher=dispatcher,
        session_authenticator=session_authenticator,
        origin_policy=origin_policy,
        csrf_verifier=csrf_verifier,
        rate_limiter=rate_limiter,
        telemetry=telemetry,
        trace_id_source=FixedTraceIdSource(),
    )
    return HttpFixture(
        dispatcher=dispatcher,
        session_authenticator=session_authenticator,
        origin_policy=origin_policy,
        csrf_verifier=csrf_verifier,
        rate_limiter=rate_limiter,
        telemetry=telemetry,
        transport=transport,
    )


def operation_case(operation_id: str) -> OpenApiOperationCase:
    return next(case for case in OPENAPI_OPERATIONS if case.operation_id == operation_id)


def _request_body(operation_id: str, *, full: bool = False) -> Optional[Dict[str, Any]]:
    policy_acceptance = {
        "document_id": "document_0123456789abcdef",
        "content_sha256": "a" * 64,
        "affirmed": True,
    }
    consent_choice = {
        "consent_offer_id": "offer_0123456789abcdef",
        "document_id": "consent_document_0123456789abcdef",
        "content_sha256": "b" * 64,
        "affirmed": True,
    }
    bodies: Dict[str, Dict[str, Any]] = {
        "beginOidcAuthorization": {
            "return_to": "/app",
            **(
                {"access_invitation_token": PROTOCOL_SECRET}
                if full
                else {}
            ),
        },
        "inspectAccessInvitation": {
            "access_invitation_token": PROTOCOL_SECRET,
        },
        "acceptAccessInvitation": {
            "policy_bundle_id": "policy_bundle_0123456789abcdef",
            "policy_acceptances": [policy_acceptance],
            "consent_grants": [consent_choice] if full else [],
        },
        "revokeAccessInvitation": {"reason_code": "ADMIN_REVOKED"},
        "acceptCurrentPolicies": {
            "policy_requirement": {
                "selector_digest": "c" * 64,
                "scope_type": "USER_ROLE",
                "scope_id": None,
            },
            "policy_bundle_id": "policy_bundle_0123456789abcdef",
            "policy_acceptances": [policy_acceptance],
        },
        "grantConsent": {
            "policy_requirement": {
                "selector_digest": "c" * 64,
                "scope_type": "USER_ROLE",
                "scope_id": None,
            },
            "policy_bundle_id": "policy_bundle_0123456789abcdef",
            **consent_choice,
        },
        "withdrawConsent": {"reason_code": "USER_WITHDREW"},
        "issueOrganizationAccessInvitation": {
            "recipient": {"type": "EMAIL", "value": "invitee@example.test"},
            "target_role": "DEMAND_OWNER",
            "expires_at": "2026-08-12T00:00:00Z",
        },
        "updateOrganizationPublicName": {
            "public_name": "Corrected Organization",
            "reason_code": "PUBLIC_NAME_CORRECTION",
        },
        "suspendMembership": {"reason_code": "SAFETY_REVIEW"},
        "resumeMembership": {"reason_code": "REVIEW_CLEARED"},
        "revokeMembership": {"reason_code": "ADMIN_REVOKED"},
        "suspendUser": {"reason_code": "SAFETY_REVIEW"},
        "resumeUser": {"reason_code": "REVIEW_CLEARED"},
        "revokeAllUserSessions": {"reason_code": "SECURITY_RESPONSE"},
    }
    return bodies.get(operation_id)


_PATH_VALUES = {
    "invitation_id": "invitation_0123456789abcdef",
    "policy_bundle_id": "policy_bundle_0123456789abcdef",
    "consent_grant_id": "consent_grant_0123456789abcdef",
    "session_id": "session_0123456789abcdef",
    "organization_id": "organization_0123456789abcdef",
    "membership_id": "membership_0123456789abcdef",
    "user_id": "user_target_0123456789abcdef",
}


def request_for(
    operation_id: str,
    *,
    full: bool = False,
    body_override: Any = ...,
) -> HttpRequest:
    case = operation_case(operation_id)
    path = case.path_template
    for parameter, value in _PATH_VALUES.items():
        path = path.replace("{" + parameter + "}", value)

    body_value = _request_body(operation_id, full=full)
    if body_override is not ...:
        body_value = body_override
    body = (
        b""
        if body_value is None
        else json.dumps(body_value, separators=(",", ":")).encode("utf-8")
    )
    headers: List[HttpHeader] = []
    if body_value is not None:
        headers.append(HttpHeader(b"content-type", b"application/json"))
        headers.append(HttpHeader(b"content-length", str(len(body)).encode("ascii")))

    if case.method in {"POST", "DELETE"} and operation_id != "completeOidcAuthorization":
        headers.append(HttpHeader(b"origin", ALLOWED_ORIGIN.encode("ascii")))

    if operation_id == "completeOidcAuthorization":
        headers.append(
            HttpHeader(
                b"cookie",
                f"__Host-ds_oidc={OIDC_BROWSER_COOKIE}".encode("ascii"),
            )
        )
    elif case.security and operation_id != "beginOidcAuthorization":
        headers.append(
            HttpHeader(
                b"cookie",
                f"__Host-ds_session={SESSION_HANDLE}".encode("ascii"),
            )
        )

    if "IdempotencyKey" in case.parameter_components:
        headers.append(HttpHeader(b"idempotency-key", IDEMPOTENCY_KEY.encode("ascii")))
    if "IfMatch" in case.parameter_components:
        headers.append(HttpHeader(b"if-match", b'"v1"'))
    if "CsrfToken" in case.parameter_components:
        headers.append(HttpHeader(b"x-csrf-token", CSRF_TOKEN.encode("ascii")))

    query: Dict[str, str] = {}
    if operation_id == "completeOidcAuthorization":
        query = {"state": PROTOCOL_SECRET, "code": "B" * 43}
    elif operation_id in {
        "listMyConsentGrants",
        "listMySessions",
        "listOrganizationAccessInvitations",
        "listOrganizationMemberships",
    }:
        query = {"limit": "20"}

    return HttpRequest(
        method=case.method,
        scheme="https",
        path=path,
        raw_query_string=urlencode(query).encode("ascii"),
        headers=tuple(headers),
        body=body,
    )


def replace_header(
    request: HttpRequest,
    name: bytes,
    value: Optional[bytes],
    *,
    append: bool = False,
) -> HttpRequest:
    lowered = name.lower()
    headers = list(request.headers)
    if not append:
        headers = [header for header in headers if header.name.lower() != lowered]
    if value is not None:
        headers.append(HttpHeader(lowered, value))
    return replace(request, headers=tuple(headers))


def replace_json_body(request: HttpRequest, value: Any) -> HttpRequest:
    body = json.dumps(value, separators=(",", ":")).encode("utf-8")
    updated = replace(request, body=body)
    return replace_header(updated, b"content-length", str(len(body)).encode("ascii"))


def response_json(response: HttpResponse) -> Dict[str, Any]:
    loaded = json.loads(response.body.decode("utf-8"))
    if not isinstance(loaded, dict):
        raise AssertionError("HTTP JSON response must be an object")
    return loaded


def response_header_values(response: HttpResponse, name: str) -> Tuple[str, ...]:
    return tuple(
        value.decode("latin-1")
        for value in response.header_values(name.encode("ascii"))
    )


@dataclass(frozen=True)
class AsgiResult:
    messages: Tuple[Mapping[str, Any], ...]
    receive_calls: int

    @property
    def status_code(self) -> Optional[int]:
        starts = [message for message in self.messages if message["type"] == "http.response.start"]
        return None if not starts else int(starts[0]["status"])

    @property
    def body(self) -> bytes:
        return b"".join(
            bytes(message.get("body", b""))
            for message in self.messages
            if message["type"] == "http.response.body"
        )

    @property
    def headers(self) -> Tuple[Tuple[bytes, bytes], ...]:
        starts = [message for message in self.messages if message["type"] == "http.response.start"]
        return () if not starts else tuple(starts[0].get("headers", ()))


def run_asgi(
    application: IamAsgiApplication,
    request: HttpRequest,
    *,
    chunks: Optional[Sequence[bytes]] = None,
    disconnect_after_chunks: bool = False,
    receive_error: Optional[BaseException] = None,
) -> AsgiResult:
    body_chunks = list(chunks if chunks is not None else (request.body,))
    messages: List[Mapping[str, Any]] = []
    receive_calls = 0

    async def receive() -> Dict[str, Any]:
        nonlocal receive_calls
        receive_calls += 1
        if receive_error is not None:
            raise receive_error
        if body_chunks:
            chunk = body_chunks.pop(0)
            return {
                "type": "http.request",
                "body": chunk,
                "more_body": bool(body_chunks) or disconnect_after_chunks,
            }
        if disconnect_after_chunks:
            return {"type": "http.disconnect"}
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Dict[str, Any]) -> None:
        messages.append(message)

    scope: Dict[str, Any] = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.5"},
        "http_version": "1.1",
        "scheme": request.scheme,
        "method": request.method,
        "path": request.path,
        "raw_path": request.path.encode("ascii"),
        "query_string": request.raw_query_string,
        "headers": tuple((header.name, header.value) for header in request.headers),
        "server": ("app.example.test", 443),
    }
    asyncio.run(application(scope, receive, send))
    return AsgiResult(messages=tuple(messages), receive_calls=receive_calls)
