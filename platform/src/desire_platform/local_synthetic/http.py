"""Small stdlib HTTP boundary for the loopback-only synthetic service."""

from __future__ import annotations

import json
import secrets
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit

from .service import LocalSyntheticError, LocalSyntheticService


MAX_BODY_BYTES = 64 * 1024
COOKIE_NAME = "ds_local_session"


def _json_no_duplicates(raw: bytes) -> Dict[str, Any]:
    def closed_pairs(pairs: Any) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise LocalSyntheticError("DUPLICATE_JSON_KEY", 400)
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=closed_pairs)
    except LocalSyntheticError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise LocalSyntheticError("MALFORMED_JSON", 400)
    if not isinstance(value, dict):
        raise LocalSyntheticError("JSON_OBJECT_REQUIRED", 400)
    return value


class LocalSyntheticHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: Tuple[str, int],
        service: LocalSyntheticService,
    ) -> None:
        host, _ = server_address
        if host != "127.0.0.1":
            raise ValueError("LOCAL_SYNTHETIC_HOST_MUST_BE_127_0_0_1")
        self.service = service
        super().__init__(server_address, LocalSyntheticRequestHandler)


class LocalSyntheticRequestHandler(BaseHTTPRequestHandler):
    server: LocalSyntheticHTTPServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format_string: str, *args: Any) -> None:
        # Do not log cookies, CSRF values, bodies, paths with user input, or raw
        # idempotency keys.  The local run banner is enough for this exercise.
        return

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")

    def _dispatch(self, method: str) -> None:
        request_id = "syn_request_" + secrets.token_hex(8)
        try:
            path = urlsplit(self.path)
            if path.query or path.fragment:
                raise LocalSyntheticError("ROUTE_NOT_FOUND", 404)
            self._require_loopback_host()
            if path.path == "/health/live" and method == "GET":
                self._send_json(200, {"status": "LIVE", "profile": "LOCAL_SYNTHETIC"}, request_id)
                return
            if path.path == "/health/ready" and method == "GET":
                self._send_json(200, {"status": "READY", "profile": "LOCAL_SYNTHETIC"}, request_id)
                return
            if path.path == "/v1/local/personas" and method == "GET":
                self._send_json(200, self.server.service.list_personas(), request_id)
                return
            if path.path == "/v1/local/session" and method == "POST":
                self._require_json_content_type()
                self._require_origin()
                body = self._read_json_body()
                if set(body) != {"persona_id"}:
                    raise LocalSyntheticError("INVALID_SESSION_SCHEMA", 400)
                created = self.server.service.create_session(body.get("persona_id"))
                cookie = "{}={}; HttpOnly; SameSite=Strict; Path=/".format(
                    COOKIE_NAME, created["cookie"]
                )
                self._send_json(201, created["session"], request_id, {"Set-Cookie": cookie})
                return
            if path.path == "/v1/local/session" and method == "DELETE":
                self._require_origin()
                cookie = self._session_cookie()
                self.server.service.close_session(cookie, self._csrf())
                self._send_json(
                    200,
                    {"status": "SIGNED_OUT"},
                    request_id,
                    {"Set-Cookie": "{}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0".format(COOKIE_NAME)},
                )
                return
            if path.path == "/v1/local/bootstrap" and method == "GET":
                result = self.server.service.bootstrap(self._session_cookie())
                self._send_json(200, result, request_id, {"ETag": '"r{}"'.format(result["revision"])})
                return
            if path.path == "/v1/local/actions" and method == "POST":
                self._require_json_content_type()
                self._require_origin()
                result = self.server.service.execute(
                    self._session_cookie(), self._csrf(), self._read_json_body()
                )
                self._send_json(200, result, request_id, {"ETag": '"r{}"'.format(result["revision"])})
                return
            if path.path == "/v1/local/reset" and method == "POST":
                self._require_json_content_type()
                self._require_origin()
                result = self.server.service.reset(
                    self._session_cookie(), self._csrf(), self._read_json_body()
                )
                self._send_json(200, result, request_id, {"ETag": '"r{}"'.format(result["revision"])})
                return
            known_methods = {
                "/health/live": {"GET"},
                "/health/ready": {"GET"},
                "/v1/local/personas": {"GET"},
                "/v1/local/session": {"POST", "DELETE"},
                "/v1/local/bootstrap": {"GET"},
                "/v1/local/actions": {"POST"},
                "/v1/local/reset": {"POST"},
            }
            if path.path in known_methods:
                raise LocalSyntheticError("METHOD_NOT_ALLOWED", 405)
            raise LocalSyntheticError("ROUTE_NOT_FOUND", 404)
        except LocalSyntheticError as error:
            self._send_json(
                error.status,
                {
                    "code": error.code,
                    "message": "本地平台拒绝了请求；请按稳定错误码检查输入或重新读取状态。",
                },
                request_id,
            )
        except Exception:
            self._send_json(
                503,
                {"code": "LOCAL_SERVICE_UNAVAILABLE", "message": "本地平台暂不可用。"},
                request_id,
            )

    def _require_loopback_host(self) -> None:
        expected = "127.0.0.1:{}".format(self.server.server_address[1])
        # Node/Fetch may omit an explicit Host header and let its HTTP client
        # generate it from the already closed loopback URL.  Accept omission,
        # but reject every explicit value other than the exact listener.
        provided = self.headers.get("Host")
        if provided not in (None, expected):
            raise LocalSyntheticError("HOST_NOT_ALLOWED", 403)

    def _require_origin(self) -> None:
        expected = "http://127.0.0.1:{}".format(self.server.server_address[1])
        if self.headers.get("Origin") != expected:
            raise LocalSyntheticError("ORIGIN_NOT_ALLOWED", 403)

    def _require_json_content_type(self) -> None:
        value = self.headers.get("Content-Type", "")
        if value.split(";", 1)[0].strip().lower() != "application/json":
            raise LocalSyntheticError("JSON_CONTENT_TYPE_REQUIRED", 415)

    def _read_json_body(self) -> Dict[str, Any]:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise LocalSyntheticError("CONTENT_LENGTH_REQUIRED", 411)
        try:
            length = int(raw_length)
        except ValueError:
            raise LocalSyntheticError("INVALID_CONTENT_LENGTH", 400)
        if length < 0 or length > MAX_BODY_BYTES:
            raise LocalSyntheticError("REQUEST_BODY_TOO_LARGE", 413)
        return _json_no_duplicates(self.rfile.read(length))

    def _session_cookie(self) -> str:
        header = self.headers.get("Cookie")
        if not header:
            raise LocalSyntheticError("SESSION_REQUIRED", 401)
        cookie = SimpleCookie()
        try:
            cookie.load(header)
        except Exception:
            raise LocalSyntheticError("SESSION_INVALID", 401)
        morsel = cookie.get(COOKIE_NAME)
        if morsel is None or not morsel.value:
            raise LocalSyntheticError("SESSION_REQUIRED", 401)
        return morsel.value

    def _csrf(self) -> str:
        value = self.headers.get("X-CSRF-Token")
        if not value:
            raise LocalSyntheticError("CSRF_INVALID", 403)
        return value

    def _send_json(
        self,
        status: int,
        payload: Any,
        request_id: str,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Request-ID", request_id)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)


__all__ = ["COOKIE_NAME", "LocalSyntheticHTTPServer", "MAX_BODY_BYTES"]
