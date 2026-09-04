from __future__ import annotations

import socket
import ssl
import unittest
from unittest.mock import patch

from desire_platform.identity_access.adapters import pinned_oidc_transport as subject
from desire_platform.identity_access.adapters.pinned_oidc_transport import (
    PinnedPublicIpOidcJsonTransport,
)


ISSUER = "https://login.example.com/tenant"
PINNED_IP = "8.8.8.8"


class _Headers:
    def __init__(self, content_type: str = "application/json") -> None:
        self._content_type = content_type

    def get_content_type(self) -> str:
        return self._content_type


class _Response:
    def __init__(
        self,
        body: bytes = b'{"status":"ok"}',
        *,
        status: int = 200,
        content_type: str = "application/json",
    ) -> None:
        self.status = status
        self.headers = _Headers(content_type)
        self._body = body
        self.closed = False

    def read(self, maximum: int) -> bytes:
        return self._body[:maximum]

    def close(self) -> None:
        self.closed = True


class _Connection:
    def __init__(self, response: _Response | None = None) -> None:
        self.response = response or _Response()
        self.requests: list[tuple] = []
        self.closed = False
        self.failure: BaseException | None = None

    def request(self, *args, **kwargs) -> None:
        self.requests.append((args, kwargs))
        if self.failure is not None:
            raise self.failure

    def getresponse(self) -> _Response:
        return self.response

    def close(self) -> None:
        self.closed = True


class PinnedPublicIpOidcJsonTransportTest(unittest.TestCase):
    def test_get_connects_pinned_ip_but_keeps_original_host_and_target(self) -> None:
        connection = _Connection()
        constructor_facts = []

        def factory(**facts):
            constructor_facts.append(facts)
            return connection

        transport = PinnedPublicIpOidcJsonTransport(
            issuer=ISSUER,
            pinned_public_ipv4=PINNED_IP,
        )
        with patch.object(subject, "_PinnedHttpsConnection", side_effect=factory):
            result = transport.get_json(
                url="https://login.example.com/tenant/jwks?version=1",
                timeout_seconds=3,
                maximum_bytes=4096,
            )

        self.assertEqual(result, {"status": "ok"})
        self.assertEqual(len(constructor_facts), 1)
        self.assertEqual(constructor_facts[0]["hostname"], "login.example.com")
        self.assertEqual(constructor_facts[0]["pinned_public_ipv4"], PINNED_IP)
        self.assertEqual(len(connection.requests), 1)
        args, kwargs = connection.requests[0]
        self.assertEqual(args, ("GET", "/tenant/jwks?version=1"))
        self.assertIsNone(kwargs["body"])
        self.assertEqual(kwargs["headers"]["Host"], "login.example.com")
        self.assertTrue(connection.closed)
        self.assertTrue(connection.response.closed)

    def test_socket_path_never_calls_dns_and_uses_issuer_for_sni(self) -> None:
        class RawSocket:
            def __init__(self) -> None:
                self.timeout = None
                self.endpoint = None
                self.closed = False

            def settimeout(self, value) -> None:
                self.timeout = value

            def connect(self, endpoint) -> None:
                self.endpoint = endpoint

            def close(self) -> None:
                self.closed = True

        class Context:
            verify_mode = ssl.CERT_REQUIRED
            check_hostname = True

            def __init__(self) -> None:
                self.calls = []

            def wrap_socket(self, raw, *, server_hostname):
                self.calls.append((raw, server_hostname))
                return object()

        raw = RawSocket()
        context = Context()
        connection = subject._PinnedHttpsConnection(
            hostname="login.example.com",
            pinned_public_ipv4=PINNED_IP,
            timeout=3,
            context=context,  # type: ignore[arg-type]
        )
        with (
            patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS")) as dns,
            patch.object(socket, "socket", return_value=raw) as socket_factory,
        ):
            connection.connect()

        dns.assert_not_called()
        socket_factory.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        self.assertEqual(raw.timeout, 3)
        self.assertEqual(raw.endpoint, (PINNED_IP, 443))
        self.assertEqual(context.calls, [(raw, "login.example.com")])

    def test_post_failure_is_attempted_exactly_once_and_never_retried(self) -> None:
        connection = _Connection()
        connection.failure = OSError("unknown outcome")
        constructions = []

        def factory(**facts):
            constructions.append(facts)
            return connection

        transport = PinnedPublicIpOidcJsonTransport(
            issuer=ISSUER,
            pinned_public_ipv4=PINNED_IP,
        )
        with (
            patch.object(subject, "_PinnedHttpsConnection", side_effect=factory),
            self.assertRaisesRegex(RuntimeError, "OIDC transport failed"),
        ):
            transport.post_form_json(
                url="https://login.example.com/tenant/token",
                form={"code": "one-use-code", "client_secret": "secret"},
                timeout_seconds=3,
                maximum_bytes=4096,
            )
        self.assertEqual(len(constructions), 1)
        self.assertEqual(len(connection.requests), 1)
        self.assertTrue(connection.closed)

    def test_redirect_cross_origin_and_noncanonical_paths_are_never_followed(self) -> None:
        redirect = _Connection(_Response(status=302))
        transport = PinnedPublicIpOidcJsonTransport(
            issuer=ISSUER,
            pinned_public_ipv4=PINNED_IP,
        )
        with (
            patch.object(subject, "_PinnedHttpsConnection", return_value=redirect),
            self.assertRaisesRegex(RuntimeError, "response protocol"),
        ):
            transport.get_json(
                url="https://login.example.com/tenant/jwks",
                timeout_seconds=3,
                maximum_bytes=4096,
            )
        self.assertEqual(len(redirect.requests), 1)

        for url in (
            "https://other.example.com/tenant/jwks",
            "https://login.example.com:444/tenant/jwks",
            "https://login.example.com/tenant/%2e%2e/jwks",
            "https://login.example.com/tenant/../jwks",
            "https://login.example.com/tenant\\jwks",
            "https://user@login.example.com/tenant/jwks",
        ):
            with self.subTest(url=url), self.assertRaises(RuntimeError):
                transport.get_json(
                    url=url,
                    timeout_seconds=3,
                    maximum_bytes=4096,
                )

    def test_direct_constructor_rejects_nonreal_names_addresses_and_weak_tls(self) -> None:
        invalid_issuers = (
            "https://127.0.0.1",
            "https://[2001:4860:4860::8888]",
            "https://login.example.test",
            "https://login.localhost",
            "https://login.local",
            "https://login.invalid",
            "https://login.example.123",
            "https://login.example.com/%2e%2e",
        )
        for issuer in invalid_issuers:
            with self.subTest(issuer=issuer), self.assertRaises(ValueError):
                PinnedPublicIpOidcJsonTransport(
                    issuer=issuer,
                    pinned_public_ipv4=PINNED_IP,
                )

        invalid_addresses = (
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "192.0.2.1",
            "2001:4860:4860::8888",
            "8.8.8.08",
        )
        for address in invalid_addresses:
            with self.subTest(address=address), self.assertRaises(ValueError):
                PinnedPublicIpOidcJsonTransport(
                    issuer=ISSUER,
                    pinned_public_ipv4=address,
                )

        weak = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        weak.check_hostname = False
        weak.verify_mode = ssl.CERT_NONE
        with self.assertRaises(ValueError):
            PinnedPublicIpOidcJsonTransport(
                issuer=ISSUER,
                pinned_public_ipv4=PINNED_IP,
                ssl_context=weak,
            )


if __name__ == "__main__":
    unittest.main()
