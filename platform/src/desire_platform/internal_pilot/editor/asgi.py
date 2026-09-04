"""Bounded ASGI boundary for the authenticated internal-pilot editor."""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional, Tuple

from ...identity_access.domain.errors import IamError
from .contracts import EditorServiceError
from .contracts import EditorWorkspaceSummary
from .http import EditorHttpApi, HttpRequest


AsgiReceive = Callable[[], Awaitable[Dict[str, Any]]]
AsgiSend = Callable[[Dict[str, Any]], Awaitable[None]]

_HEADER_NAME = re.compile(rb"^[!#$%&'*+.^_`|~0-9a-z-]+$")
_SESSION_HANDLE = re.compile(r"^[A-Za-z0-9_-]{43,128}$")
_CSRF_TOKEN = re.compile(r"^[A-Za-z0-9_-]{32,512}$")
_TRACE_ID = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
_REVIEW_HISTORY_CURSOR = re.compile(
    r"^[A-Za-z0-9_-]{64,1024}\.[A-Za-z0-9_-]{43}$"
)
_WORKSPACE_ID = re.compile(
    r"^(?:org|personal|platform):"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}$"
)
_MAXIMUM_BODY_BYTES = 1_048_576
_MAXIMUM_HEADER_BYTES = 32_768
_MAXIMUM_PATH_BYTES = 2_048
_WRITE_METHODS = frozenset(("POST", "PUT", "PATCH", "DELETE"))
_KNOWN_METHODS = frozenset(("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"))


class EditorAsgiApplication:
    """Authenticate once, resolve authority server-side, and dispatch once."""

    def __init__(
        self,
        *,
        api: EditorHttpApi,
        session_security: Any,
        principal_resolver: Any,
        allowed_origins: Tuple[str, ...],
        trace_id_source: Callable[[], str],
        request_timeout_seconds: float = 10.0,
        allow_internal_bff_http: bool = False,
        deployment_mode: Optional[str] = None,
    ) -> None:
        if not isinstance(api, EditorHttpApi):
            raise TypeError("editor API is unavailable")
        if not allowed_origins or len(set(allowed_origins)) != len(allowed_origins):
            raise TypeError("editor origin allowlist is unavailable")
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
                raise TypeError("editor origin allowlist is invalid")
        if (
            not isinstance(allow_internal_bff_http, bool)
            or (allow_internal_bff_http and deployment_mode != "INTERNAL_SANDBOX")
            or (not allow_internal_bff_http and deployment_mode is not None)
        ):
            raise TypeError("editor internal BFF profile is invalid")
        if not callable(trace_id_source) or request_timeout_seconds <= 0:
            raise TypeError("editor transport configuration is invalid")
        self._api = api
        self._session_security = session_security
        self._principal_resolver = principal_resolver
        self._allowed_origins = frozenset(allowed_origins)
        self._trace_id_source = trace_id_source
        self._request_timeout_seconds = request_timeout_seconds

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
            method = scope.get("method")
            response = _error(
                503,
                "SERVICE_UNAVAILABLE" if method in {"GET", "HEAD"} else "COMMAND_OUTCOME_UNKNOWN",
            )
        await _send(send, response)

    async def _handle(
        self,
        *,
        scope: Dict[str, Any],
        receive: AsgiReceive,
    ) -> Tuple[int, Tuple[Tuple[bytes, bytes], ...], bytes]:
        if scope.get("type") != "http":
            return _error(400, "INVALID_REQUEST")
        method = scope.get("method")
        scheme = scope.get("scheme")
        path = scope.get("path")
        raw_path = scope.get("raw_path")
        query = scope.get("query_string", b"")
        if (
            method not in _KNOWN_METHODS
            or scheme != "https"
            or not isinstance(path, str)
            or not path.startswith("/v1/app/")
            or not isinstance(raw_path, bytes)
            or not isinstance(query, bytes)
            or len(query) > _MAXIMUM_PATH_BYTES
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
        query_values = _query_values(method=method, path=path, raw=query)
        if query_values is None:
            history_paths = {
                "/v1/app/review-history",
                "/v1/app/finance/funding-review-history",
            }
            return _error(
                400 if path in history_paths or path.startswith("/v1/app/admin/demands") else 404,
                "INVALID_REQUEST"
                if path in history_paths or path.startswith("/v1/app/admin/demands")
                else "RESOURCE_NOT_FOUND",
            )

        parsed_headers = _headers(scope.get("headers", ()))
        if isinstance(parsed_headers, tuple) and parsed_headers and parsed_headers[0] == 400:
            return parsed_headers  # type: ignore[return-value]
        headers = parsed_headers  # type: ignore[assignment]
        trace_id = _trace_id(self._trace_id_source)
        raw_handle = _session_cookie(headers)
        if raw_handle is None:
            return _error(401, "AUTHENTICATION_REQUIRED")
        try:
            actor = self._session_security.authenticate(
                raw_session_handle=raw_handle,
                trace_id=trace_id,
            )
        except IamError as error:
            if error.code in {"AUTHENTICATION_REQUIRED", "SESSION_EXPIRED"}:
                return _error(401, error.code)
            return _error(503, "SERVICE_UNAVAILABLE")
        workspace_values = headers.get("x-workspace-id", ())
        if workspace_values and (
            len(workspace_values) != 1
            or _WORKSPACE_ID.fullmatch(workspace_values[0]) is None
        ):
            return _error(400, "INVALID_REQUEST")
        requested_workspace_id = (
            None if not workspace_values else workspace_values[0]
        )
        if path == "/v1/app/workspaces":
            if method not in {"GET", "HEAD"} or requested_workspace_id is not None:
                return _error(400, "INVALID_REQUEST")
            try:
                workspaces = self._principal_resolver.list_workspaces(actor=actor)
            except (EditorServiceError, IamError) as error:
                code = getattr(error, "code", "SERVICE_UNAVAILABLE")
                status = 404 if code == "RESOURCE_NOT_FOUND" else 503
                return _error(
                    status,
                    code if code == "RESOURCE_NOT_FOUND" else "SERVICE_UNAVAILABLE",
                )
            except Exception:
                return _error(503, "SERVICE_UNAVAILABLE")
            if not isinstance(workspaces, tuple) or any(
                not isinstance(workspace, EditorWorkspaceSummary)
                for workspace in workspaces
            ):
                return _error(503, "SERVICE_UNAVAILABLE")
            identifiers = tuple(workspace.workspace_id for workspace in workspaces)
            if identifiers != tuple(sorted(set(identifiers))):
                return _error(503, "SERVICE_UNAVAILABLE")
            body = json.dumps(
                {
                    "data": {
                        "workspaces": [
                            {
                                "workspace_id": workspace.workspace_id,
                                "workspace_kind": workspace.workspace_kind,
                                "role_codes": list(workspace.role_codes),
                            }
                            for workspace in workspaces
                        ],
                        "selection_required": len(workspaces) > 1,
                    }
                },
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            if method == "HEAD":
                body = b""
            return (
                200,
                (
                    (b"content-type", b"application/json"),
                    (b"cache-control", b"no-store"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ),
                body,
            )
        try:
            principal = self._principal_resolver.resolve(
                actor=actor,
                requested_workspace_id=requested_workspace_id,
            )
        except (EditorServiceError, IamError) as error:
            code = getattr(error, "code", "ACCESS_DENIED")
            status_by_code = {
                "ACCESS_DENIED": 403,
                "WORKSPACE_REQUIRED": 409,
                "RESOURCE_NOT_FOUND": 404,
            }
            status = status_by_code.get(code, 503)
            return _error(
                status,
                code if code in status_by_code else "SERVICE_UNAVAILABLE",
            )
        except Exception:
            return _error(503, "SERVICE_UNAVAILABLE")

        if method in _WRITE_METHODS:
            origins = headers.get("origin", ())
            if len(origins) != 1 or origins[0] not in self._allowed_origins:
                return _error(403, "ORIGIN_NOT_ALLOWED")
            csrf_values = headers.get("x-csrf-token", ())
            if len(csrf_values) != 1 or _CSRF_TOKEN.fullmatch(csrf_values[0]) is None:
                return _error(403, "CSRF_REQUIRED")
            try:
                self._session_security.require_valid(
                    raw_session_handle=raw_handle,
                    raw_csrf_token=csrf_values[0],
                    actor=actor,
                    operation_id="internalPilotEditorWrite",
                )
            except IamError as error:
                return _error(
                    403 if error.code == "INVALID_REQUEST" else 503,
                    "CSRF_INVALID" if error.code == "INVALID_REQUEST" else "SERVICE_UNAVAILABLE",
                )

        declared = _declared_content_length(headers)
        if declared is None and "content-length" in headers:
            return _error(400, "INVALID_REQUEST")
        if declared is not None and declared > _MAXIMUM_BODY_BYTES:
            return _error(413, "REQUEST_TOO_LARGE")
        body_bytes, body_error = await _read_body(receive)
        if body_error is not None:
            return _error(body_error, "REQUEST_TOO_LARGE" if body_error == 413 else "INVALID_REQUEST")
        if method in _WRITE_METHODS:
            types = headers.get("content-type", ())
            if types != ("application/json",):
                return _error(415, "UNSUPPORTED_MEDIA_TYPE")
        try:
            payload = {} if not body_bytes else json.loads(body_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return _error(400, "INVALID_JSON")
        flattened_headers = {
            name: values[0]
            for name, values in headers.items()
            if len(values) == 1
        }
        try:
            result = await asyncio.to_thread(
                self._api.handle,
                request=HttpRequest(
                    method=method,
                    path=path,
                    headers=flattened_headers,
                    json=payload,
                    query=query_values,
                ),
                principal=principal,
            )
        except Exception:
            return _error(
                503,
                "SERVICE_UNAVAILABLE" if method in {"GET", "HEAD"} else "COMMAND_OUTCOME_UNKNOWN",
            )
        response_headers = [
            (name.lower().encode("ascii"), value.encode("utf-8"))
            for name, value in result.headers.items()
            if name.lower() in {"content-type", "etag", "retry-after"}
        ]
        response_headers.append((b"cache-control", b"no-store"))
        response_body = json.dumps(
            result.json,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        response_headers.append((b"content-length", str(len(response_body)).encode("ascii")))
        return result.status, tuple(response_headers), response_body


def _headers(value: Any) -> Any:
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
            return _error(431, "REQUEST_HEADERS_TOO_LARGE")
        try:
            name = item[0].decode("ascii")
            raw = item[1].decode("latin-1")
        except UnicodeDecodeError:
            return _error(400, "INVALID_REQUEST")
        if any(ord(character) < 32 or ord(character) == 127 for character in raw):
            return _error(400, "INVALID_REQUEST")
        result.setdefault(name, []).append(raw)
    for singleton in (
        "cookie",
        "origin",
        "content-type",
        "content-length",
        "x-csrf-token",
        "idempotency-key",
        "if-match",
        "x-workspace-id",
    ):
        if len(result.get(singleton, ())) > 1:
            return _error(400, "INVALID_REQUEST")
    return {name: tuple(values) for name, values in result.items()}


def _query_values(*, method: Any, path: str, raw: bytes) -> Optional[Dict[str, str]]:
    if not raw:
        return {}
    admin_path = path == "/v1/app/admin/demands" or re.fullmatch(r"/v1/app/admin/demands/[0-9a-f-]{36}/timeline", path) is not None
    if method != "GET" or (not admin_path and path not in {
        "/v1/app/review-history",
        "/v1/app/finance/funding-review-history",
    }):
        return None
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    if any(character in text for character in ("%", "+", ";")):
        return None
    values: Dict[str, str] = {}
    for pair in text.split("&"):
        key, separator, value = pair.partition("=")
        if (
            separator != "="
            or key not in {"cursor", "limit"}
            or key in values
            or not value
        ):
            return None
        values[key] = value
    cursor = values.get("cursor")
    limit = values.get("limit")
    if (
        cursor is not None
        and _REVIEW_HISTORY_CURSOR.fullmatch(cursor) is None
    ) or (
        limit is not None
        and re.fullmatch(r"(?:[1-9]|[1-9][0-9]|100)", limit) is None
    ):
        return None
    return values


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
    return value if isinstance(value, str) and _TRACE_ID.fullmatch(value) else "trace-unavailable"


def _error(status: int, code: str) -> Tuple[int, Tuple[Tuple[bytes, bytes], ...], bytes]:
    body = json.dumps(
        {"error": {"code": code}},
        separators=(",", ":"),
    ).encode("ascii")
    return (
        status,
        (
            (b"content-type", b"application/json"),
            (b"cache-control", b"no-store"),
            (b"content-length", str(len(body)).encode("ascii")),
        ),
        body,
    )


async def _send(
    send: AsgiSend,
    response: Tuple[int, Tuple[Tuple[bytes, bytes], ...], bytes],
) -> None:
    status, headers, body = response
    await send({"type": "http.response.start", "status": status, "headers": list(headers)})
    await send({"type": "http.response.body", "body": body, "more_body": False})


__all__ = ["EditorAsgiApplication"]
