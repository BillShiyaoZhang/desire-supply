"""In-memory HTTP boundary tests for the container-only OIDC fixture."""

from __future__ import annotations

from io import BytesIO
import json

import pytest

from desire_platform.synthetic_oidc import SyntheticOidcProvider
from desire_platform.synthetic_oidc.http import (
    SyntheticOidcHttpServer,
    SyntheticOidcRequestHandler,
)


CLIENT_SECRET = bytearray(b"fixture-client-secret-material-0001")


class _OpenBytesIO(BytesIO):
    def close(self):
        # StreamRequestHandler owns and closes its files.  Retain the response
        # bytes so the test can inspect the exact serialized HTTP boundary.
        self.flush()


class _MemoryConnection:
    def __init__(self, request: bytes) -> None:
        self.request = _OpenBytesIO(request)
        self.response = _OpenBytesIO()

    def makefile(self, mode, buffering=None):
        del buffering
        return self.request if "r" in mode else self.response

    def sendall(self, value):
        self.response.write(value)


class _Server:
    def __init__(self, provider) -> None:
        self.provider = provider


def _exchange(provider, request: bytes):
    connection = _MemoryConnection(request)
    SyntheticOidcRequestHandler(connection, ("127.0.0.1", 1), _Server(provider))
    head, body = connection.response.getvalue().split(b"\r\n\r\n", 1)
    lines = head.decode("ascii").split("\r\n")
    status = int(lines[0].split(" ", 2)[1])
    headers = {}
    for line in lines[1:]:
        name, value = line.split(":", 1)
        headers[name] = value.strip()
    return status, headers, body


@pytest.fixture
def provider():
    value = SyntheticOidcProvider(client_secret=bytearray(CLIENT_SECRET))
    try:
        yield value
    finally:
        value.close()


def test_http_handler_exposes_health_and_proxy_guarded_discovery(provider):
    status, headers, body = _exchange(
        provider,
        b"GET /health/ready HTTP/1.1\r\nHost: 127.0.0.1:8081\r\n\r\n",
    )
    assert status == 200
    assert json.loads(body) == {"status": "READY"}
    assert "Server" not in headers
    assert "Date" not in headers

    status, _, body = _exchange(
        provider,
        b"GET /.well-known/openid-configuration HTTP/1.1\r\n"
        b"Host: identity.example.test\r\n"
        b"X-Forwarded-Host: identity.example.test\r\n"
        b"X-Forwarded-Proto: https\r\n\r\n",
    )
    assert status == 200
    assert json.loads(body)["issuer"] == "https://identity.example.test"

    status, _, body = _exchange(
        provider,
        b"GET /.well-known/openid-configuration HTTP/1.1\r\n"
        b"Host: identity.example.test\r\n\r\n",
    )
    assert status == 403
    assert json.loads(body) == {"code": "HTTPS_PROXY_BOUNDARY_REQUIRED"}

    status, _, body = _exchange(
        provider,
        b"GET /health/ready HTTP/1.1\r\nHost: identity.example.test\r\n"
        b"X-Forwarded-Proto: https\r\n\r\n",
    )
    assert status == 403
    assert json.loads(body) == {"code": "HEALTH_BOUNDARY_REQUIRED"}


def test_http_handler_rejects_registration_methods_and_unbounded_post(provider):
    for method, path in (
        ("GET", "/register"),
        ("PUT", "/authorize"),
        ("TRACE", "/authorize"),
        ("OPTIONS", "/token"),
    ):
        status, headers, _ = _exchange(
            provider,
            (
                f"{method} {path} HTTP/1.1\r\n"
                "Host: identity.example.test\r\n"
                "X-Forwarded-Host: identity.example.test\r\n"
                "X-Forwarded-Proto: https\r\n\r\n"
            ).encode("ascii"),
        )
        assert status in {404, 405}
        assert "Server" not in headers

    status, _, body = _exchange(
        provider,
        b"POST /token HTTP/1.1\r\nHost: identity.example.test\r\n"
        b"X-Forwarded-Host: identity.example.test\r\n"
        b"X-Forwarded-Proto: https\r\n\r\n",
    )
    assert status == 411
    assert json.loads(body) == {"code": "CONTENT_LENGTH_REQUIRED"}

    status, _, body = _exchange(
        provider,
        b"GET /jwks HTTP/1.1\r\nHost: identity.example.test\r\n"
        b"Host: identity.example.test\r\n"
        b"X-Forwarded-Host: identity.example.test\r\n"
        b"X-Forwarded-Proto: https\r\n\r\n",
    )
    assert status == 403
    assert json.loads(body) == {"code": "HTTPS_PROXY_BOUNDARY_REQUIRED"}

    status, headers, body = _exchange(
        provider,
        b"PROPFIND /authorize HTTP/1.1\r\nHost: identity.example.test\r\n"
        b"X-Forwarded-Host: identity.example.test\r\n"
        b"X-Forwarded-Proto: https\r\n\r\n",
    )
    assert status == 501
    assert headers["Content-Type"] == "application/json"
    assert "Server" not in headers
    assert "Date" not in headers
    assert json.loads(body) == {"code": "HTTP_REQUEST_REJECTED"}


def test_listener_binding_is_fixed_except_ephemeral_loopback(provider):
    with pytest.raises(ValueError):
        SyntheticOidcHttpServer(("127.0.0.1", 8081), provider)
    with pytest.raises(ValueError):
        SyntheticOidcHttpServer(("0.0.0.0", 8082), provider)
