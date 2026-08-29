"""Authenticated ASGI boundary for the closed Trust HTTP presenter."""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional, Tuple
from uuid import UUID

from desire_platform.identity_access.domain.errors import IamError
from desire_platform.trust_safety.application import TrustActorContext
from desire_platform.trust_safety.http import (
    TrustHttpApplicationDispatcher,
    TrustHttpRequest,
    TrustHttpResponse,
)

from .editor.contracts import EditorPrincipal


AsgiReceive = Callable[[], Awaitable[Dict[str, Any]]]
AsgiSend = Callable[[Dict[str, Any]], Awaitable[None]]

_HEADER_NAME = re.compile(rb"^[!#$%&'*+.^_`|~0-9a-z-]+$")
_SESSION_HANDLE = re.compile(r"[A-Za-z0-9_-]{43,128}\Z")
_CSRF_TOKEN = re.compile(r"[A-Za-z0-9_-]{32,512}\Z")
_TRACE_ID = re.compile(r"[A-Za-z0-9_-]{8,128}\Z")
_OWN_REPORT_CURSOR = re.compile(
    r"[A-Za-z0-9_-]{64,1024}\.[A-Za-z0-9_-]{43}\Z"
)
_WORKSPACE_ID = re.compile(
    r"^(?:org|personal|platform):"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}$"
)
_MAXIMUM_BODY_BYTES = 1_048_576
_MAXIMUM_HEADER_BYTES = 32_768
_MAXIMUM_PATH_BYTES = 2_048
_WRITE_METHODS = frozenset(("POST", "PUT"))
_KNOWN_METHODS = frozenset(("GET", "POST", "PUT"))
_SINGLETON_HEADERS = (
    "cookie",
    "origin",
    "content-type",
    "content-length",
    "x-csrf-token",
    "idempotency-key",
    "if-match",
    "x-workspace-id",
)


class TrustAsgiApplication:
    """Authenticate, select one exact workspace, and dispatch one Trust call."""

    def __init__(
        self,
        *,
        dispatcher: TrustHttpApplicationDispatcher,
        session_security: Any,
        principal_resolver: Any,
        allowed_origins: Tuple[str, ...],
        trace_id_source: Callable[[], str],
        request_timeout_seconds: float = 10.0,
        allow_internal_bff_http: bool = False,
        deployment_mode: Optional[str] = None,
    ) -> None:
        if not isinstance(dispatcher, TrustHttpApplicationDispatcher):
            raise TypeError("Trust HTTP dispatcher is unavailable")
        if not callable(getattr(session_security, "authenticate", None)) or not callable(
            getattr(session_security, "require_valid", None)
        ):
            raise TypeError("Trust Session security is unavailable")
        if not callable(getattr(principal_resolver, "resolve", None)):
            raise TypeError("Trust workspace resolver is unavailable")
        if not allowed_origins or len(set(allowed_origins)) != len(allowed_origins):
            raise TypeError("Trust origin allowlist is unavailable")
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
                raise TypeError("Trust origin allowlist is invalid")
        if (
            not isinstance(allow_internal_bff_http, bool)
            or (allow_internal_bff_http and deployment_mode != "INTERNAL_SANDBOX")
            or (not allow_internal_bff_http and deployment_mode is not None)
            or not callable(trace_id_source)
            or not isinstance(request_timeout_seconds, (int, float))
            or request_timeout_seconds <= 0
        ):
            raise TypeError("Trust transport configuration is invalid")
        self._dispatcher = dispatcher
        self._session_security = session_security
        self._principal_resolver = principal_resolver
        self._allowed_origins = frozenset(allowed_origins)
        self._trace_id_source = trace_id_source
        self._request_timeout_seconds = float(request_timeout_seconds)

    async def __call__(
        self,
        scope: Dict[str, Any],
        receive: AsgiReceive,
        send: AsgiSend,
    ) -> None:
        try:
            response = await asyncio.wait_for(
                self._handle(scope=scope, receive=receive),
                timeout=self._request_timeout_seconds,
            )
        except asyncio.TimeoutError:
            response = _error(
                503,
                (
                    "SERVICE_UNAVAILABLE"
                    if scope.get("method") == "GET"
                    else "COMMAND_OUTCOME_UNKNOWN"
                ),
            )
        await _send(send, response)

    async def _handle(
        self,
        *,
        scope: Dict[str, Any],
        receive: AsgiReceive,
    ) -> TrustHttpResponse:
        if scope.get("type") != "http":
            return _error(400, "INVALID_REQUEST")
        method = scope.get("method")
        scheme = scope.get("scheme")
        path = scope.get("path")
        raw_path = scope.get("raw_path")
        raw_query = scope.get("query_string", b"")
        if (
            method not in _KNOWN_METHODS
            or scheme != "https"
            or not isinstance(path, str)
            or not path.startswith("/v1/app/trust/")
            or not isinstance(raw_path, bytes)
            or not isinstance(raw_query, bytes)
            or len(raw_path) > _MAXIMUM_PATH_BYTES
        ):
            return _error(404 if isinstance(path, str) else 400, "RESOURCE_NOT_FOUND")
        try:
            if raw_path.decode("ascii") != path or any(
                token in path for token in ("//", "/./", "/../", "%", "\\")
            ):
                return _error(400, "INVALID_REQUEST")
        except UnicodeDecodeError:
            return _error(400, "INVALID_REQUEST")
        headers = _headers(scope.get("headers", ()))
        if isinstance(headers, TrustHttpResponse):
            return headers
        raw_handle = _session_cookie(headers)
        if raw_handle is None:
            return _error(401, "AUTHENTICATION_REQUIRED")
        trace_id = _trace_id(self._trace_id_source)
        try:
            authenticated = self._session_security.authenticate(
                raw_session_handle=raw_handle,
                trace_id=trace_id,
            )
        except IamError as error:
            if error.code in {"AUTHENTICATION_REQUIRED", "SESSION_EXPIRED"}:
                return _error(401, error.code)
            return _error(503, "SERVICE_UNAVAILABLE")
        except Exception:
            return _error(503, "SERVICE_UNAVAILABLE")

        workspace_values = headers.get("x-workspace-id", ())
        if (
            len(workspace_values) != 1
            or _WORKSPACE_ID.fullmatch(workspace_values[0]) is None
        ):
            return _error(400, "INVALID_REQUEST", "/headers/X-Workspace-Id")
        requested_workspace_id = workspace_values[0]
        try:
            principal = self._principal_resolver.resolve(
                actor=authenticated,
                requested_workspace_id=requested_workspace_id,
            )
        except (IamError, Exception):
            return _error(404, "RESOURCE_NOT_FOUND")
        if not isinstance(principal, EditorPrincipal):
            return _error(503, "SERVICE_UNAVAILABLE")

        reporter = path == "/v1/app/trust/reports" or path.startswith(
            "/v1/app/trust/reports/"
        )
        if not _principal_matches(principal, reporter=reporter):
            return _error(404, "RESOURCE_NOT_FOUND")
        query = _query(path=path, method=method, raw=raw_query)
        if isinstance(query, TrustHttpResponse):
            return query
        try:
            actor = _actor_context(authenticated, principal, reporter=reporter)
        except (TypeError, ValueError, AttributeError):
            return _error(503, "SERVICE_UNAVAILABLE")

        if method in _WRITE_METHODS:
            origins = headers.get("origin", ())
            if len(origins) != 1 or origins[0] not in self._allowed_origins:
                return _error(403, "CSRF_INVALID", "/headers/Origin")
            csrf_values = headers.get("x-csrf-token", ())
            if not csrf_values:
                return _error(403, "CSRF_REQUIRED", "/headers/X-CSRF-Token")
            if len(csrf_values) != 1 or _CSRF_TOKEN.fullmatch(csrf_values[0]) is None:
                return _error(403, "CSRF_INVALID", "/headers/X-CSRF-Token")
            try:
                self._session_security.require_valid(
                    raw_session_handle=raw_handle,
                    raw_csrf_token=csrf_values[0],
                    actor=authenticated,
                    operation_id="trustSafetyWrite",
                )
            except IamError as error:
                return _error(
                    403 if error.code == "INVALID_REQUEST" else 503,
                    (
                        "CSRF_INVALID"
                        if error.code == "INVALID_REQUEST"
                        else "SERVICE_UNAVAILABLE"
                    ),
                )
            except Exception:
                return _error(503, "SERVICE_UNAVAILABLE")

        declared = _declared_content_length(headers)
        if declared is None and "content-length" in headers:
            return _error(400, "INVALID_REQUEST")
        if declared is not None and declared > _MAXIMUM_BODY_BYTES:
            return _error(413, "INVALID_REQUEST")
        body_bytes, body_error = await _read_body(receive)
        if body_error is not None:
            return _error(body_error, "INVALID_REQUEST")
        if method in _WRITE_METHODS and headers.get("content-type", ()) != (
            "application/json",
        ):
            return _error(400, "INVALID_REQUEST", "/headers/Content-Type")
        try:
            payload = {} if not body_bytes else json.loads(body_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return _error(400, "INVALID_REQUEST", "/body")
        if not isinstance(payload, dict):
            return _error(400, "INVALID_REQUEST", "/body")
        flattened_headers = {
            name: values[0] for name, values in headers.items() if len(values) == 1
        }
        try:
            response = await asyncio.to_thread(
                self._dispatcher.handle,
                request=TrustHttpRequest(
                    method=method,
                    path=path,
                    headers=flattened_headers,
                    json=payload,
                    query=query,
                ),
                actor=actor,
            )
        except Exception:
            return _error(
                503,
                "SERVICE_UNAVAILABLE" if method == "GET" else "COMMAND_OUTCOME_UNKNOWN",
            )
        if not isinstance(response, TrustHttpResponse):
            return _error(503, "SERVICE_UNAVAILABLE")
        return response


def _query(
    *, path: str, method: str, raw: bytes
) -> Mapping[str, Tuple[str, ...]] | TrustHttpResponse:
    collection_read = method == "GET" and path == "/v1/app/trust/reports"
    if not raw:
        return {}
    if not collection_read:
        return _error(404, "RESOURCE_NOT_FOUND")
    if len(raw) > 1_500:
        return _error(400, "INVALID_REQUEST", "/query")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return _error(400, "INVALID_REQUEST", "/query")
    if any(token in text for token in ("%", "+", ";")):
        return _error(400, "INVALID_REQUEST", "/query")
    pairs = text.split("&")
    if not 1 <= len(pairs) <= 2:
        return _error(400, "INVALID_REQUEST", "/query")
    result: dict[str, Tuple[str, ...]] = {}
    for pair in pairs:
        if pair.count("=") != 1:
            return _error(400, "INVALID_REQUEST", "/query")
        name, value = pair.split("=", 1)
        if name in result or name not in {"cursor", "limit"}:
            return _error(400, "INVALID_REQUEST", "/query")
        if name == "limit":
            if re.fullmatch(r"(?:[1-9]|[1-9][0-9]|100)", value) is None:
                return _error(400, "INVALID_REQUEST", "/query/limit")
        elif _OWN_REPORT_CURSOR.fullmatch(value) is None:
            return _error(400, "INVALID_REQUEST", "/query/cursor")
        result[name] = (value,)
    return result


def _principal_matches(principal: EditorPrincipal, *, reporter: bool) -> bool:
    if reporter:
        return (
            principal.workspace_kind == "ORGANIZATION"
            and principal.organization_id is not None
            and principal.workspace_id == f"org:{principal.organization_id}"
            and principal.role_codes == tuple(sorted(set(principal.role_codes)))
            and "DEMAND_OWNER" in principal.role_codes
        )
    return (
        principal.workspace_kind == "PLATFORM"
        and principal.organization_id is None
        and principal.workspace_id == f"platform:{principal.user_id}"
        and principal.role_codes == tuple(sorted(set(principal.role_codes)))
        and "TRUST_OFFICER" in principal.role_codes
    )


def _actor_context(authenticated: Any, principal: EditorPrincipal, *, reporter: bool) -> TrustActorContext:
    user_id = _canonical_uuid(authenticated.actor_user_id)
    session_id = _canonical_uuid(authenticated.session_id)
    if (
        principal.user_id != user_id
        or principal.session_id != session_id
        or authenticated.original_actor_id is not None
    ):
        raise ValueError("Trust actor mismatch")
    return TrustActorContext(
        actor_user_id=user_id,
        session_id=session_id,
        organization_id=(
            _canonical_uuid(principal.organization_id) if reporter else None
        ),
        correlation_id=_canonical_uuid(authenticated.correlation_id),
        causation_id=_canonical_uuid(authenticated.causation_id),
        trace_id=_canonical_uuid(authenticated.trace_id),
        original_actor_user_id=None,
    )


def _canonical_uuid(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("identifier invalid")
    parsed = UUID(value)
    if str(parsed) != value or parsed.int == 0:
        raise ValueError("identifier invalid")
    return value


def _headers(value: Any) -> Mapping[str, Tuple[str, ...]] | TrustHttpResponse:
    if not isinstance(value, (list, tuple)) or len(value) > 100:
        return _error(400, "INVALID_REQUEST")
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
            return _error(400, "INVALID_REQUEST")
        total += len(item[0]) + len(item[1])
        if total > _MAXIMUM_HEADER_BYTES:
            return _error(400, "INVALID_REQUEST")
        try:
            name = item[0].decode("ascii")
            raw = item[1].decode("latin-1")
        except UnicodeDecodeError:
            return _error(400, "INVALID_REQUEST")
        if any(ord(character) < 32 or ord(character) == 127 for character in raw):
            return _error(400, "INVALID_REQUEST")
        result.setdefault(name, []).append(raw)
    if any(len(result.get(name, ())) > 1 for name in _SINGLETON_HEADERS):
        return _error(400, "INVALID_REQUEST")
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
        message = await receive()
        if not isinstance(message, Mapping):
            return b"", 400
        if message.get("type") == "http.disconnect":
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


def _trace_id(source: Callable[[], str]) -> str:
    try:
        value = source()
    except Exception:
        value = ""
    return (
        value
        if isinstance(value, str) and _TRACE_ID.fullmatch(value)
        else "trace-unavailable"
    )


def _error(status: int, code: str, path: str | None = None) -> TrustHttpResponse:
    detail: dict[str, str] = {"code": code}
    if path is not None:
        detail["path"] = path
    return TrustHttpResponse(
        status=status,
        headers={"content-type": "application/json"},
        json={"error": detail},
    )


async def _send(send: AsgiSend, response: TrustHttpResponse) -> None:
    try:
        body = json.dumps(
            response.json,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        response = _error(503, "SERVICE_UNAVAILABLE")
        body = b'{"error":{"code":"SERVICE_UNAVAILABLE"}}'
    headers = [
        (name.lower().encode("ascii"), value.encode("ascii"))
        for name, value in response.headers.items()
        if name.lower() in {"content-type", "etag"}
    ]
    headers.append((b"cache-control", b"no-store"))
    headers.append((b"content-length", str(len(body)).encode("ascii")))
    await send(
        {
            "type": "http.response.start",
            "status": response.status,
            "headers": headers,
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})


__all__ = ["TrustAsgiApplication"]
