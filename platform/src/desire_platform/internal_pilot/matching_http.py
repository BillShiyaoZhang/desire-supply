"""Authenticated raw ASGI boundary for the closed Matching HTTP presenter."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import re
import unicodedata
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional, Tuple

from desire_platform.http.contracts import AuthenticatedHttpActor
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.matching.http import (
    MatchingHttpActor,
    MatchingHttpApplicationDispatcher,
    MatchingHttpFamily,
    MatchingHttpRequest,
    MatchingHttpResponse,
    MatchingHttpRoute,
    MatchingHttpRouteNotFound,
    matching_http_error,
    resolve_matching_http_route,
)

from .editor.contracts import EditorPrincipal


AsgiReceive = Callable[[], Awaitable[Dict[str, Any]]]
AsgiSend = Callable[[Dict[str, Any]], Awaitable[None]]

_HEADER_NAME = re.compile(rb"^[!#$%&'*+.^_`|~0-9a-z-]+$")
_SESSION_HANDLE = re.compile(r"[A-Za-z0-9_-]{43,128}\Z")
_CSRF_TOKEN = re.compile(r"[A-Za-z0-9_-]{32,512}\Z")
_TRACE_ID = re.compile(r"[A-Za-z0-9_-]{16,128}\Z")
_CURSOR = re.compile(r"[A-Za-z0-9._~-]{16,2048}\Z")
_WORKSPACE_ID = re.compile(
    r"^(?:org|personal|platform):"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}$"
)
_MAXIMUM_BODY_BYTES = 8_192
_MAXIMUM_HEADER_BYTES = 32_768
_MAXIMUM_PATH_BYTES = 2_048
_MAXIMUM_QUERY_BYTES = 2_048
_SINGLETON_HEADERS = frozenset(
    (
        "cookie",
        "origin",
        "content-type",
        "content-length",
        "transfer-encoding",
        "x-csrf-token",
        "idempotency-key",
        "if-match",
        "x-workspace-id",
        "traceparent",
    )
)


@dataclass(frozen=True)
class MatchingOperationalHttpRoute:
    method: str
    path: str
    operation_id: str
    family: str

    @property
    def mutating(self) -> bool:
        return self.method == "POST"

    @property
    def paginated(self) -> bool:
        return False


MATCHING_OPERATIONAL_HTTP_ROUTES = (
    MatchingOperationalHttpRoute(
        "POST",
        "/v1/matching/candidate-selector-assignments/claim",
        "claimCandidateSelectorAssignment",
        MatchingHttpFamily.CANDIDATE_SELECTOR,
    ),
    MatchingOperationalHttpRoute(
        "POST",
        "/v1/app/matching-review/queue/claim",
        "claimMatchingReviewAssignment",
        MatchingHttpFamily.OPERATIONS,
    ),
    MatchingOperationalHttpRoute(
        "GET",
        "/v1/app/matching-review/assignment",
        "readMatchingReviewAssignment",
        MatchingHttpFamily.OPERATIONS,
    ),
    MatchingOperationalHttpRoute(
        "POST",
        "/v1/app/matching-review/assignment/release",
        "releaseMatchingReviewAssignment",
        MatchingHttpFamily.OPERATIONS,
    ),
)


def resolve_matching_operational_http_route(
    method: str, path: str
) -> MatchingOperationalHttpRoute:
    if not isinstance(method, str) or method != method.upper() or not isinstance(path, str):
        raise MatchingHttpRouteNotFound("RESOURCE_NOT_FOUND")
    for route in MATCHING_OPERATIONAL_HTTP_ROUTES:
        if method == route.method and path == route.path:
            return route
    raise MatchingHttpRouteNotFound("RESOURCE_NOT_FOUND")


def is_matching_operational_path(path: Any) -> bool:
    return isinstance(path, str) and any(
        path == route.path for route in MATCHING_OPERATIONAL_HTTP_ROUTES
    )


class _DuplicateJsonKey(ValueError):
    pass


class _InvalidJsonNumber(ValueError):
    pass


class MatchingAsgiApplication:
    """Authenticate one browser call and dispatch one exact Matching route."""

    def __init__(
        self,
        *,
        dispatcher: MatchingHttpApplicationDispatcher,
        session_security: Any,
        principal_resolver: Any,
        allowed_origins: Tuple[str, ...],
        trace_id_source: Callable[[], str],
        operational_service: Any = None,
        request_timeout_seconds: float = 10.0,
        allow_internal_bff_http: bool = False,
        deployment_mode: Optional[str] = None,
    ) -> None:
        if not isinstance(dispatcher, MatchingHttpApplicationDispatcher):
            raise TypeError("Matching HTTP dispatcher is unavailable")
        if not callable(getattr(session_security, "authenticate", None)) or not callable(
            getattr(session_security, "require_valid", None)
        ):
            raise TypeError("Matching session security is unavailable")
        if not callable(getattr(principal_resolver, "resolve", None)):
            raise TypeError("Matching workspace resolver is unavailable")
        if operational_service is not None and not callable(
            getattr(operational_service, "handle", None)
        ):
            raise TypeError("Matching operational service is unavailable")
        if not allowed_origins or len(set(allowed_origins)) != len(allowed_origins):
            raise TypeError("Matching origin allowlist is unavailable")
        for origin in allowed_origins:
            valid_https = (
                isinstance(origin, str)
                and origin.startswith("https://")
                and not origin.endswith("/")
            )
            valid_internal = (
                allow_internal_bff_http
                and deployment_mode == "INTERNAL_SANDBOX"
                and allowed_origins == ("http://api:8000",)
                and origin == "http://api:8000"
            )
            if not (valid_https or valid_internal):
                raise TypeError("Matching origin allowlist is invalid")
        if (
            not isinstance(allow_internal_bff_http, bool)
            or (allow_internal_bff_http and deployment_mode != "INTERNAL_SANDBOX")
            or (not allow_internal_bff_http and deployment_mode is not None)
            or not callable(trace_id_source)
            or not isinstance(request_timeout_seconds, (int, float))
            or request_timeout_seconds <= 0
        ):
            raise TypeError("Matching transport configuration is invalid")
        self._dispatcher = dispatcher
        self._session_security = session_security
        self._principal_resolver = principal_resolver
        self._operational_service = operational_service
        self._allowed_origins = frozenset(allowed_origins)
        self._trace_id_source = trace_id_source
        self._request_timeout_seconds = float(request_timeout_seconds)
        self._allow_internal_bff_http = allow_internal_bff_http

    async def __call__(
        self,
        scope: Dict[str, Any],
        receive: AsgiReceive,
        send: AsgiSend,
    ) -> None:
        trace_id = _trace_id(self._trace_id_source)
        try:
            response = await asyncio.wait_for(
                self._handle(scope=scope, receive=receive, trace_id=trace_id),
                timeout=self._request_timeout_seconds,
            )
        except (asyncio.TimeoutError, TimeoutError):
            response = matching_http_error(
                "COMMAND_OUTCOME_UNKNOWN" if scope.get("method") == "POST" else "SERVICE_UNAVAILABLE",
                trace_id=trace_id,
            )
        except Exception:
            response = matching_http_error(
                "COMMAND_OUTCOME_UNKNOWN" if scope.get("method") == "POST" else "SERVICE_UNAVAILABLE",
                trace_id=trace_id,
            )
        await _send(send, response, fallback_trace_id=trace_id)

    async def _handle(
        self,
        *,
        scope: Dict[str, Any],
        receive: AsgiReceive,
        trace_id: str,
    ) -> MatchingHttpResponse:
        if scope.get("type") != "http":
            return matching_http_error("INVALID_REQUEST", trace_id=trace_id)
        method = scope.get("method")
        scheme = scope.get("scheme")
        path = scope.get("path")
        raw_path = scope.get("raw_path")
        raw_query = scope.get("query_string", b"")
        scheme_valid = scheme == "https" or (
            self._allow_internal_bff_http and scheme == "http"
        )
        if (
            method not in {"GET", "POST"}
            or not scheme_valid
            or not isinstance(path, str)
            or not isinstance(raw_path, bytes)
            or not isinstance(raw_query, bytes)
            or len(raw_path) > _MAXIMUM_PATH_BYTES
            or len(raw_query) > _MAXIMUM_QUERY_BYTES
        ):
            return matching_http_error(
                "RESOURCE_NOT_FOUND" if isinstance(path, str) else "INVALID_REQUEST",
                trace_id=trace_id,
            )
        try:
            if (
                raw_path.decode("ascii") != path
                or unicodedata.normalize("NFC", path) != path
                or any(token in path for token in ("//", "/./", "/../", "%", "\\", "\x00"))
            ):
                return matching_http_error("INVALID_REQUEST", trace_id=trace_id)
        except (UnicodeDecodeError, UnicodeEncodeError):
            return matching_http_error("INVALID_REQUEST", trace_id=trace_id)
        operational_route = False
        try:
            route, path_parameters = resolve_matching_http_route(method, path)
        except MatchingHttpRouteNotFound:
            try:
                route = resolve_matching_operational_http_route(method, path)
                path_parameters = {}
                operational_route = True
            except MatchingHttpRouteNotFound:
                return matching_http_error("RESOURCE_NOT_FOUND", trace_id=trace_id)
        query = _query(route=route, raw=raw_query, trace_id=trace_id)
        if isinstance(query, MatchingHttpResponse):
            return query
        headers = _headers(scope.get("headers", ()), trace_id=trace_id)
        if isinstance(headers, MatchingHttpResponse):
            return headers
        if "transfer-encoding" in headers:
            return matching_http_error("INVALID_REQUEST", trace_id=trace_id)
        raw_handle = _session_cookie(headers)
        if raw_handle is None:
            return matching_http_error("AUTHENTICATION_REQUIRED", trace_id=trace_id)
        try:
            authenticated = self._session_security.authenticate(
                raw_session_handle=raw_handle,
                trace_id=trace_id,
            )
        except IamError as error:
            code = error.code if error.code in {"AUTHENTICATION_REQUIRED", "SESSION_EXPIRED"} else "SERVICE_UNAVAILABLE"
            return matching_http_error(code, trace_id=trace_id)
        except Exception:
            return matching_http_error("SERVICE_UNAVAILABLE", trace_id=trace_id)
        if not isinstance(authenticated, AuthenticatedHttpActor):
            return matching_http_error("SERVICE_UNAVAILABLE", trace_id=trace_id)

        workspace_values = headers.get("x-workspace-id", ())
        if (
            len(workspace_values) != 1
            or _WORKSPACE_ID.fullmatch(workspace_values[0]) is None
        ):
            return matching_http_error("INVALID_REQUEST", trace_id=trace_id)
        requested_workspace_id = workspace_values[0]
        try:
            principal = self._principal_resolver.resolve(
                actor=authenticated,
                requested_workspace_id=requested_workspace_id,
            )
        except Exception:
            return matching_http_error("RESOURCE_NOT_FOUND", trace_id=trace_id)
        if not isinstance(principal, EditorPrincipal):
            return matching_http_error("SERVICE_UNAVAILABLE", trace_id=trace_id)
        if not _principal_matches(route=route, path_parameters=path_parameters, principal=principal):
            return matching_http_error("RESOURCE_NOT_FOUND", trace_id=trace_id)
        try:
            actor = _http_actor(
                authenticated=authenticated,
                principal=principal,
                expected_trace_id=trace_id,
            )
        except (TypeError, ValueError, AttributeError):
            return matching_http_error("SERVICE_UNAVAILABLE", trace_id=trace_id)

        if route.mutating:
            origins = headers.get("origin", ())
            if len(origins) != 1 or origins[0] not in self._allowed_origins:
                return matching_http_error("INVALID_REQUEST", trace_id=actor.trace_id, status=403)
            csrf_values = headers.get("x-csrf-token", ())
            if len(csrf_values) != 1 or _CSRF_TOKEN.fullmatch(csrf_values[0]) is None:
                return matching_http_error("INVALID_REQUEST", trace_id=actor.trace_id, status=403)
            try:
                self._session_security.require_valid(
                    raw_session_handle=raw_handle,
                    raw_csrf_token=csrf_values[0],
                    actor=authenticated,
                    operation_id=route.operation_id,
                )
            except IamError as error:
                if error.code == "INVALID_REQUEST":
                    return matching_http_error("INVALID_REQUEST", trace_id=actor.trace_id, status=403)
                return matching_http_error("SERVICE_UNAVAILABLE", trace_id=actor.trace_id)
            except Exception:
                return matching_http_error("SERVICE_UNAVAILABLE", trace_id=actor.trace_id)

        declared = _declared_content_length(headers)
        if declared is None and "content-length" in headers:
            return matching_http_error("INVALID_REQUEST", trace_id=actor.trace_id)
        if declared is not None and declared > _MAXIMUM_BODY_BYTES:
            return matching_http_error("INVALID_REQUEST", trace_id=actor.trace_id, status=413)
        body_bytes, body_error = await _read_body(receive)
        if body_error is not None:
            if body_error == 503:
                return matching_http_error("SERVICE_UNAVAILABLE", trace_id=actor.trace_id)
            return matching_http_error("INVALID_REQUEST", trace_id=actor.trace_id, status=body_error)
        if declared is not None and declared != len(body_bytes):
            return matching_http_error("INVALID_REQUEST", trace_id=actor.trace_id)
        if route.mutating:
            if headers.get("content-type", ()) != ("application/json",):
                return matching_http_error("INVALID_REQUEST", trace_id=actor.trace_id)
            if not body_bytes:
                return matching_http_error("INVALID_REQUEST", trace_id=actor.trace_id)
        elif body_bytes:
            return matching_http_error("INVALID_REQUEST", trace_id=actor.trace_id)
        try:
            payload = {} if not body_bytes else _decode_json(body_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateJsonKey, _InvalidJsonNumber, ValueError):
            return matching_http_error("INVALID_REQUEST", trace_id=actor.trace_id)
        if not isinstance(payload, dict):
            return matching_http_error("INVALID_REQUEST", trace_id=actor.trace_id)
        flattened_headers = {
            name: values[0] for name, values in headers.items() if len(values) == 1
        }
        try:
            if operational_route and self._operational_service is None:
                return matching_http_error("SERVICE_UNAVAILABLE", trace_id=actor.trace_id)
            target = (
                self._operational_service.handle
                if operational_route
                else self._dispatcher.handle
            )
            response = await asyncio.to_thread(
                target,
                request=MatchingHttpRequest(
                    method=method,
                    path=path,
                    headers=flattened_headers,
                    json_body=payload,
                    query=query,
                ),
                actor=actor,
            )
        except Exception:
            return matching_http_error(
                "COMMAND_OUTCOME_UNKNOWN" if route.mutating else "SERVICE_UNAVAILABLE",
                trace_id=actor.trace_id,
            )
        if not isinstance(response, MatchingHttpResponse):
            return matching_http_error(
                "COMMAND_OUTCOME_UNKNOWN" if route.mutating else "SERVICE_UNAVAILABLE",
                trace_id=actor.trace_id,
            )
        return response


def _query(
    *, route: MatchingHttpRoute | MatchingOperationalHttpRoute, raw: bytes, trace_id: str
) -> Mapping[str, Tuple[str, ...]] | MatchingHttpResponse:
    if not raw:
        return {}
    if not route.paginated:
        return matching_http_error("INVALID_REQUEST", trace_id=trace_id)
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return matching_http_error("INVALID_REQUEST", trace_id=trace_id)
    if any(token in text for token in ("%", "+", ";")):
        return matching_http_error("INVALID_REQUEST", trace_id=trace_id)
    pairs = text.split("&")
    if not 1 <= len(pairs) <= 2:
        return matching_http_error("INVALID_REQUEST", trace_id=trace_id)
    result: dict[str, Tuple[str, ...]] = {}
    for pair in pairs:
        if pair.count("=") != 1:
            return matching_http_error("INVALID_REQUEST", trace_id=trace_id)
        name, value = pair.split("=", 1)
        if name in result or name not in {"cursor", "limit"}:
            return matching_http_error("INVALID_REQUEST", trace_id=trace_id)
        if name == "limit":
            if re.fullmatch(r"(?:[1-9]|[1-9][0-9]|100)", value) is None:
                return matching_http_error("INVALID_REQUEST", trace_id=trace_id)
        elif _CURSOR.fullmatch(value) is None:
            return matching_http_error("INVALID_REQUEST", trace_id=trace_id)
        result[name] = (value,)
    return result


def _headers(
    value: Any, *, trace_id: str
) -> Mapping[str, Tuple[str, ...]] | MatchingHttpResponse:
    if not isinstance(value, (list, tuple)) or len(value) > 100:
        return matching_http_error("INVALID_REQUEST", trace_id=trace_id)
    result: Dict[str, list[str]] = {}
    total = 0
    for item in value:
        if (
            not isinstance(item, (list, tuple))
            or len(item) != 2
            or not isinstance(item[0], bytes)
            or not isinstance(item[1], bytes)
            or _HEADER_NAME.fullmatch(item[0]) is None
        ):
            return matching_http_error("INVALID_REQUEST", trace_id=trace_id)
        total += len(item[0]) + len(item[1])
        if total > _MAXIMUM_HEADER_BYTES or len(item[0]) > 8_192 or len(item[1]) > 8_192:
            return matching_http_error("INVALID_REQUEST", trace_id=trace_id)
        try:
            name = item[0].decode("ascii")
            raw = item[1].decode("latin-1")
        except UnicodeDecodeError:
            return matching_http_error("INVALID_REQUEST", trace_id=trace_id)
        if any(ord(character) < 32 or ord(character) == 127 for character in raw):
            return matching_http_error("INVALID_REQUEST", trace_id=trace_id)
        result.setdefault(name, []).append(raw)
    if any(len(result.get(name, ())) > 1 for name in _SINGLETON_HEADERS):
        return matching_http_error("INVALID_REQUEST", trace_id=trace_id)
    return {name: tuple(values) for name, values in result.items()}


def _session_cookie(headers: Mapping[str, Tuple[str, ...]]) -> Optional[str]:
    values = headers.get("cookie", ())
    if len(values) != 1:
        return None
    found = []
    for item in values[0].split(";"):
        name, separator, value = item.strip().partition("=")
        if separator and name == "__Host-ds_session":
            found.append(value)
    if len(found) != 1 or _SESSION_HANDLE.fullmatch(found[0]) is None:
        return None
    return found[0]


def _declared_content_length(headers: Mapping[str, Tuple[str, ...]]) -> Optional[int]:
    values = headers.get("content-length", ())
    if not values:
        return None
    value = values[0]
    if not value.isdigit() or len(value) > 10:
        return None
    return int(value)


async def _read_body(receive: AsgiReceive) -> Tuple[bytes, Optional[int]]:
    body = bytearray()
    while True:
        try:
            message = await receive()
        except Exception:
            return b"", 503
        if not isinstance(message, Mapping) or message.get("type") == "http.disconnect":
            return b"", 400
        if message.get("type") != "http.request":
            return b"", 400
        part = message.get("body", b"")
        if not isinstance(part, bytes):
            return b"", 400
        body.extend(part)
        if len(body) > _MAXIMUM_BODY_BYTES:
            return b"", 413
        if message.get("more_body") is not True:
            return bytes(body), None


def _decode_json(raw: bytes) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for name, value in pairs:
            if name in result:
                raise _DuplicateJsonKey()
            result[name] = value
        return result

    def integer(value: str) -> int:
        parsed = int(value)
        if not -(2**63) <= parsed <= 2**63 - 1:
            raise _InvalidJsonNumber()
        return parsed

    def invalid_number(value: str) -> Any:
        del value
        raise _InvalidJsonNumber()

    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=unique,
        parse_int=integer,
        parse_float=invalid_number,
        parse_constant=invalid_number,
    )
    _validate_nfc(value)
    return value


def _validate_nfc(value: Any) -> None:
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise ValueError("non-canonical Unicode")
    elif isinstance(value, list):
        for item in value:
            _validate_nfc(item)
    elif isinstance(value, dict):
        for name, item in value.items():
            if unicodedata.normalize("NFC", name) != name:
                raise ValueError("non-canonical Unicode")
            _validate_nfc(item)


def _principal_matches(
    *,
    route: MatchingHttpRoute | MatchingOperationalHttpRoute,
    path_parameters: Mapping[str, str],
    principal: EditorPrincipal,
) -> bool:
    if principal.workspace_id is None or principal.role_codes != tuple(sorted(set(principal.role_codes))):
        return False
    if route.family == MatchingHttpFamily.CREATOR:
        return (
            principal.workspace_kind == "PERSONAL"
            and principal.organization_id is None
            and principal.workspace_id == f"personal:{principal.user_id}"
            and "CREATOR" in principal.role_codes
        )
    if route.family == MatchingHttpFamily.CANDIDATE_SELECTOR:
        expected_organization_id = path_parameters.get("organization_id")
        return (
            principal.workspace_kind == "ORGANIZATION"
            and (
                expected_organization_id is None
                or principal.organization_id == expected_organization_id
            )
            and principal.workspace_id == f"org:{principal.organization_id}"
            and "DEMAND_OWNER" in principal.role_codes
        )
    return (
        route.family == MatchingHttpFamily.OPERATIONS
        and principal.workspace_kind == "PLATFORM"
        and principal.organization_id is None
        and principal.workspace_id == f"platform:{principal.user_id}"
        and "OPERATIONS_REVIEWER" in principal.role_codes
    )


def _http_actor(
    *,
    authenticated: AuthenticatedHttpActor,
    principal: EditorPrincipal,
    expected_trace_id: str,
) -> MatchingHttpActor:
    if (
        authenticated.actor_user_id != principal.user_id
        or authenticated.session_id != principal.session_id
        or authenticated.trace_id != expected_trace_id
        or authenticated.original_actor_id is not None
        or principal.workspace_id is None
        or principal.workspace_kind is None
    ):
        raise ValueError("Matching HTTP actor mismatch")
    return MatchingHttpActor(
        actor_user_id=authenticated.actor_user_id,
        session_id=authenticated.session_id,
        correlation_id=authenticated.correlation_id,
        causation_id=authenticated.causation_id,
        trace_id=authenticated.trace_id,
        original_actor_id=None,
        workspace_id=principal.workspace_id,
        workspace_kind=principal.workspace_kind,
        organization_id=principal.organization_id,
        role_codes=principal.role_codes,
        authority_marker_sha256=bytes(principal.principal_marker_sha256),
    )


def _trace_id(source: Callable[[], str]) -> str:
    try:
        value = source()
    except Exception:
        value = ""
    return value if isinstance(value, str) and _TRACE_ID.fullmatch(value) else "trace-unavailable"


async def _send(
    send: AsgiSend,
    response: MatchingHttpResponse,
    *,
    fallback_trace_id: str,
) -> None:
    try:
        body = json.dumps(
            response.json_body,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        response = matching_http_error("SERVICE_UNAVAILABLE", trace_id=fallback_trace_id)
        body = json.dumps(response.json_body, separators=(",", ":")).encode("ascii")
    headers = [
        (name.lower().encode("ascii"), value.encode("ascii"))
        for name, value in response.headers.items()
        if name.lower() in {"content-type", "etag"}
    ]
    headers.extend(
        (
            (b"cache-control", b"no-store"),
            (b"x-content-type-options", b"nosniff"),
            (b"content-length", str(len(body)).encode("ascii")),
        )
    )
    try:
        await send({"type": "http.response.start", "status": response.status, "headers": headers})
        await send({"type": "http.response.body", "body": body, "more_body": False})
    except OSError:
        return


__all__ = [
    "MATCHING_OPERATIONAL_HTTP_ROUTES",
    "MatchingAsgiApplication",
    "MatchingOperationalHttpRoute",
    "is_matching_operational_path",
    "resolve_matching_operational_http_route",
]
