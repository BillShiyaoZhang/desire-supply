"""Bounded stdlib HTTP listener for the synthetic OIDC protocol core."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Tuple

from .provider import SyntheticOidcProvider, SyntheticOidcResponse


MAX_BODY_BYTES = 16 * 1024


class SyntheticOidcHttpServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: Tuple[str, int],
        provider: SyntheticOidcProvider,
    ) -> None:
        # The production entrypoint is fixed to 0.0.0.0:8081.  An ephemeral
        # IPv4 loopback listener is the sole test seam, so protocol tests can
        # exercise this real HTTP boundary without opening a LAN socket.
        if server_address != ("0.0.0.0", 8081) and server_address != (
            "127.0.0.1",
            0,
        ):
            raise ValueError("SYNTHETIC_OIDC_BINDING_INVALID")
        if not isinstance(provider, SyntheticOidcProvider):
            raise TypeError("SYNTHETIC_OIDC_PROVIDER_INVALID")
        self.provider = provider
        super().__init__(server_address, SyntheticOidcRequestHandler)


class SyntheticOidcRequestHandler(BaseHTTPRequestHandler):
    server: SyntheticOidcHttpServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format_string: str, *args: Any) -> None:
        del format_string, args

    def send_error(
        self,
        code: int,
        message: str | None = None,
        explain: str | None = None,
    ) -> None:
        del message, explain
        self._write(
            SyntheticOidcResponse(
                code,
                (
                    ("Content-Type", "application/json"),
                    ("Cache-Control", "no-store"),
                    ("X-Content-Type-Options", "nosniff"),
                ),
                b'{"code":"HTTP_REQUEST_REJECTED"}',
            )
        )

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_HEAD(self) -> None:
        self._dispatch("HEAD")

    def do_PUT(self) -> None:
        self._dispatch("PUT")

    def do_PATCH(self) -> None:
        self._dispatch("PATCH")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")

    def do_OPTIONS(self) -> None:
        self._dispatch("OPTIONS")

    def do_TRACE(self) -> None:
        self._dispatch("TRACE")

    def do_CONNECT(self) -> None:
        self._dispatch("CONNECT")

    def handle_expect_100(self) -> bool:
        self.send_response_only(417)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        return False

    def _dispatch(self, method: str) -> None:
        body = b""
        lengths = self.headers.get_all("Content-Length", failobj=[])
        transfer_encoding = self.headers.get_all("Transfer-Encoding", failobj=[])
        if method == "POST":
            if len(lengths) != 1 or transfer_encoding:
                self._write(
                    SyntheticOidcResponse(
                        411,
                        (("Content-Type", "application/json"),),
                        b'{"code":"CONTENT_LENGTH_REQUIRED"}',
                    )
                )
                return
            try:
                length = int(lengths[0])
            except (TypeError, ValueError):
                length = -1
            if length < 0 or length > MAX_BODY_BYTES:
                self._write(
                    SyntheticOidcResponse(
                        413,
                        (("Content-Type", "application/json"),),
                        b'{"code":"REQUEST_BODY_TOO_LARGE"}',
                    )
                )
                return
            body = self.rfile.read(length)
            if len(body) != length:
                self.close_connection = True
                return
        elif transfer_encoding or len(lengths) > 1 or (
            lengths and lengths[0] not in {"0", "+0"}
        ):
            self._write(
                SyntheticOidcResponse(
                    400,
                    (("Content-Type", "application/json"),),
                    b'{"code":"REQUEST_BODY_NOT_ALLOWED"}',
                )
            )
            return
        response = self.server.provider.handle(
            method=method,
            raw_target=self.path,
            headers=tuple(self.headers.raw_items()),
            body=body,
        )
        self._write(response)

    def _write(self, response: SyntheticOidcResponse) -> None:
        self.send_response_only(response.status)
        seen = set()
        for name, value in response.headers:
            if name.lower() in seen:
                self.close_connection = True
                return
            seen.add(name.lower())
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(response.body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if getattr(self, "command", None) != "HEAD":
            self.wfile.write(response.body)
        self.close_connection = True


__all__ = ["MAX_BODY_BYTES", "SyntheticOidcHttpServer"]
