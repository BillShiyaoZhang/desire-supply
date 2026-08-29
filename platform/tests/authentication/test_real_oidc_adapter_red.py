"""Production OIDC adapter contract for the internal-pilot account slice.

The transport and JOSE implementation are injected so this suite never calls a
real network or leaks provider material.  These tests intentionally precede the
adapter implementation.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
import unittest
from urllib.request import ProxyHandler
from unittest.mock import patch

from desire_platform.identity_access.adapters.oidc import (
    ClosedOidcProvider,
    OidcProviderConfiguration,
    PyJwtOidcTokenVerifier,
    StdlibOidcJsonTransport,
)
from desire_platform.identity_access.ports.identity_provider import (
    IdentityProviderMisconfiguredError,
    IdentityProviderRejectedError,
    IdentityProviderResultUnknownError,
    IdentityProviderUnavailableError,
    ProviderExchangeRequest,
)


NOW = datetime(2026, 8, 12, 8, 0, tzinfo=timezone.utc)
ISSUER = "https://id.example.test/tenant"
CLIENT_ID = "desire-internal-pilot"
REDIRECT = "https://pilot.example.test/v1/auth/oidc/callback"
VERIFIER = "closed-verifier-abcdefghijklmnopqrstuvwxyz0123456789"
CHALLENGE = base64.urlsafe_b64encode(
    hashlib.sha256(VERIFIER.encode("ascii")).digest()
).rstrip(b"=").decode("ascii")


class FakeTransportError(RuntimeError):
    pass


class FakeTransport:
    def __init__(self) -> None:
        self.get_responses = []
        self.post_responses = []
        self.calls = []

    def get_json(self, *, url, timeout_seconds, maximum_bytes):
        self.calls.append(("GET", url, timeout_seconds, maximum_bytes))
        response = self.get_responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    def post_form_json(self, *, url, form, timeout_seconds, maximum_bytes):
        # The fake observes only the closed field names.  Raw code, verifier
        # and client secret are intentionally not retained in diagnostics.
        self.calls.append(("POST", url, tuple(sorted(form)), timeout_seconds, maximum_bytes))
        response = self.post_responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class CarrierAwareTransport(FakeTransport):
    def __init__(self, *, expected_client_secret: str) -> None:
        super().__init__()
        self.expected_client_secret = expected_client_secret
        self.client_secret_matched = False

    def post_form_json(self, *, url, form, timeout_seconds, maximum_bytes):
        self.client_secret_matched = (
            form.get("client_secret") == self.expected_client_secret
        )
        return super().post_form_json(
            url=url,
            form=form,
            timeout_seconds=timeout_seconds,
            maximum_bytes=maximum_bytes,
        )

class FakeVerifier:
    def __init__(self, claims=None, error=None) -> None:
        self.claims = claims or {}
        self.error = error
        self.calls = []

    def verify_id_token(self, **facts):
        self.calls.append(facts)
        if self.error:
            raise self.error
        return dict(self.claims)


class RecipientBinding:
    def __init__(self):
        self.calls = []

    def bind_verified(self, *, contact_type, verified_locator):
        self.calls.append((contact_type, verified_locator))
        return type(
            "Binding",
            (),
            {
                "contact_type": contact_type,
                "binding_digest": hashlib.sha256(
                    verified_locator.encode("utf-8")
                ).hexdigest(),
                "digest_key_id": "recipient-binding-key-01",
            },
        )()


def metadata():
    return {
        "issuer": ISSUER,
        "authorization_endpoint": ISSUER + "/authorize",
        "token_endpoint": ISSUER + "/token",
        "jwks_uri": ISSUER + "/jwks",
        "code_challenge_methods_supported": ["S256"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }


def claims(**changes):
    value = {
        "iss": ISSUER,
        "sub": "provider-subject-001",
        "aud": CLIENT_ID,
        "nonce": "nonce-001",
        "iat": int((NOW - timedelta(seconds=20)).timestamp()),
        "exp": int((NOW + timedelta(minutes=5)).timestamp()),
        "auth_time": int((NOW - timedelta(minutes=1)).timestamp()),
        "acr": "urn:desire:acr:mfa",
        "amr": ["pwd", "otp"],
        "email": "invited@example.test",
        "email_verified": True,
    }
    value.update(changes)
    return value


def exchange_request(**changes):
    value = dict(
        auth_transaction_id="auth-transaction-001",
        code="authorization-code-001",
        state="state-001",
        redirect_uri=REDIRECT,
        code_verifier=VERIFIER,
        expected_nonce="nonce-001",
        expected_issuer=ISSUER,
        expected_audience=CLIENT_ID,
        server_now=NOW,
    )
    value.update(changes)
    return ProviderExchangeRequest(**value)


def provider(*, transport=None, verifier=None, recipient_binding=None):
    transport = transport or FakeTransport()
    verifier = verifier or FakeVerifier(claims())
    recipient_binding = recipient_binding or RecipientBinding()
    return ClosedOidcProvider(
        configuration=OidcProviderConfiguration(
            issuer=ISSUER,
            client_id=CLIENT_ID,
            client_secret="client-secret-never-rendered",
            redirect_uri=REDIRECT,
            allowed_signing_algorithms=("RS256",),
            metadata_ttl_seconds=300,
            request_timeout_seconds=3,
            maximum_response_bytes=262_144,
            clock_skew_seconds=30,
            subject_digest_key_id="subject-digest-key-2026-01",
        ),
        transport=transport,
        token_verifier=verifier,
        recipient_binding=recipient_binding,
        subject_digest_key=b"subject-digest-test-key-material",
    ), transport, verifier


class ClosedOidcProviderRedTest(unittest.TestCase):
    def test_accepts_zeroizable_secret_carriers_without_long_lived_copies(self):
        client_secret = bytearray(b"carrier-client-secret-material")
        subject_key = bytearray(b"carrier-subject-digest-key-material")
        transport = CarrierAwareTransport(
            expected_client_secret=client_secret.decode("utf-8")
        )
        transport.get_responses = [
            metadata(),
            {"keys": [{"kty": "RSA", "kid": "key-1"}]},
        ]
        transport.post_responses = [
            {"token_type": "Bearer", "id_token": "header.payload.signature"}
        ]
        adapter = ClosedOidcProvider(
            configuration=OidcProviderConfiguration(
                issuer=ISSUER,
                client_id=CLIENT_ID,
                client_secret=client_secret,
                redirect_uri=REDIRECT,
                allowed_signing_algorithms=("RS256",),
                metadata_ttl_seconds=300,
                request_timeout_seconds=3,
                maximum_response_bytes=262_144,
                clock_skew_seconds=30,
                subject_digest_key_id="subject-digest-key-2026-01",
            ),
            transport=transport,
            token_verifier=FakeVerifier(claims()),
            recipient_binding=RecipientBinding(),
            subject_digest_key=subject_key,
        )

        adapter.exchange(exchange_request())

        self.assertTrue(transport.client_secret_matched)
        self.assertIs(adapter._configuration.client_secret, client_secret)
        self.assertIs(adapter._subject_digest_key, subject_key)
        client_secret[:] = b"\0" * len(client_secret)
        subject_key[:] = b"\0" * len(subject_key)
        self.assertEqual(set(adapter._configuration.client_secret), {0})
        self.assertEqual(set(adapter._subject_digest_key), {0})
        self.assertNotIn("carrier-client-secret-material", repr(adapter))

    def test_configuration_rejects_an_issuer_query_component(self):
        with self.assertRaises(IdentityProviderMisconfiguredError):
            OidcProviderConfiguration(
                issuer=ISSUER + "?tenant=other",
                client_id=CLIENT_ID,
                client_secret="client-secret-never-rendered",
                redirect_uri=REDIRECT,
                allowed_signing_algorithms=("RS256",),
                metadata_ttl_seconds=300,
                request_timeout_seconds=3,
                maximum_response_bytes=262_144,
                clock_skew_seconds=30,
                subject_digest_key_id="subject-digest-key-2026-01",
            )

    def test_preflight_and_begin_require_exact_https_metadata_and_s256(self):
        adapter, transport, _ = provider()
        transport.get_responses = [metadata()]

        adapter.preflight(
            expected_issuer=ISSUER,
            expected_audience=CLIENT_ID,
            redirect_uri=REDIRECT,
        )
        result = adapter.begin(
            auth_transaction_id="auth-transaction-001",
            redirect_uri=REDIRECT,
            code_challenge=CHALLENGE,
            state="state-001",
            nonce="nonce-001",
            expected_issuer=ISSUER,
            expected_audience=CLIENT_ID,
        )

        self.assertEqual(result.issuer, ISSUER)
        self.assertEqual(result.audience, CLIENT_ID)
        self.assertEqual(result.code_challenge_method, "S256")
        self.assertIn("code_challenge_method=S256", result.authorization_url)
        self.assertNotIn("client-secret", repr(adapter))

    def test_exchange_preflight_warms_metadata_and_jwks_before_code_claim(self):
        adapter, transport, _ = provider()
        transport.get_responses = [
            metadata(),
            {"keys": [{"kty": "RSA", "kid": "key-1"}]},
        ]
        adapter.preflight_exchange(
            expected_issuer=ISSUER,
            expected_audience=CLIENT_ID,
            redirect_uri=REDIRECT,
        )
        self.assertEqual(
            [call[0] for call in transport.calls],
            ["GET", "GET"],
        )
        transport.post_responses = [
            {"token_type": "Bearer", "id_token": "header.payload.signature"}
        ]
        adapter.exchange(exchange_request())
        self.assertEqual(
            [call[0] for call in transport.calls],
            ["GET", "GET", "POST"],
            "exchange fetched keys again after its confirmed preflight",
        )

    def test_discovery_url_preserves_a_path_issuer_exactly(self):
        adapter, transport, _ = provider()
        transport.get_responses = [metadata()]

        adapter.preflight(
            expected_issuer=ISSUER,
            expected_audience=CLIENT_ID,
            redirect_uri=REDIRECT,
        )

        self.assertEqual(
            transport.calls[0][1],
            ISSUER + "/.well-known/openid-configuration",
        )

    def test_metadata_redirect_insecure_endpoint_or_issuer_drift_fails_closed(self):
        cases = (
            dict(metadata(), issuer="https://other.example.test"),
            dict(metadata(), token_endpoint="http://id.example.test/token"),
            dict(metadata(), code_challenge_methods_supported=["plain"]),
            dict(metadata(), id_token_signing_alg_values_supported=["none"]),
        )
        for candidate in cases:
            with self.subTest(candidate=candidate):
                adapter, transport, _ = provider()
                transport.get_responses = [candidate]
                with self.assertRaises(IdentityProviderMisconfiguredError):
                    adapter.preflight(
                        expected_issuer=ISSUER,
                        expected_audience=CLIENT_ID,
                        redirect_uri=REDIRECT,
                    )

    def test_exchange_verifies_closed_token_bindings_and_returns_digest_subject(self):
        recipient_binding = RecipientBinding()
        adapter, transport, verifier = provider(recipient_binding=recipient_binding)
        transport.get_responses = [metadata(), {"keys": [{"kty": "RSA", "kid": "key-1"}]}]
        transport.post_responses = [{
            "token_type": "Bearer",
            "id_token": "header.payload.signature",
            "expires_in": 300,
        }]

        subject = adapter.exchange(exchange_request())

        self.assertEqual(subject.issuer, ISSUER)
        self.assertEqual(subject.subject_digest_key_id, "subject-digest-key-2026-01")
        self.assertNotEqual(subject.subject_digest, "provider-subject-001")
        self.assertEqual(subject.acr_code, "urn:desire:acr:mfa")
        self.assertEqual(subject.amr_codes, ("otp", "pwd"))
        self.assertEqual(
            recipient_binding.calls,
            [("EMAIL", "invited@example.test")],
        )
        self.assertEqual(verifier.calls[0]["expected_nonce"], "nonce-001")
        rendered = repr((adapter, subject, transport.calls))
        for secret in ("client-secret-never-rendered", "authorization-code-001", VERIFIER):
            self.assertNotIn(secret, rendered)

    def test_exchange_rejects_claim_drift_unverified_contact_and_weak_auth_context(self):
        cases = (
            claims(iss="https://other.example.test"),
            claims(aud="other-client"),
            claims(nonce="other-nonce"),
            claims(exp=int(NOW.timestamp())),
            claims(email_verified=False),
            claims(acr="", amr=[]),
            claims(aud=[CLIENT_ID, "other"], azp="other"),
        )
        for candidate in cases:
            with self.subTest(candidate=candidate):
                adapter, transport, _ = provider(verifier=FakeVerifier(candidate))
                transport.get_responses = [metadata(), {"keys": [{"kty": "RSA", "kid": "key-1"}]}]
                transport.post_responses = [{"token_type": "Bearer", "id_token": "x.y.z"}]
                with self.assertRaises(IdentityProviderRejectedError):
                    adapter.exchange(exchange_request())

    def test_pre_exchange_network_failure_is_unavailable_but_post_failure_is_unknown(self):
        adapter, transport, _ = provider()
        transport.get_responses = [FakeTransportError("metadata timeout")]
        with self.assertRaises(IdentityProviderUnavailableError):
            adapter.preflight(
                expected_issuer=ISSUER,
                expected_audience=CLIENT_ID,
                redirect_uri=REDIRECT,
            )

        adapter, transport, _ = provider()
        transport.get_responses = [
            metadata(),
            {"keys": [{"kty": "RSA", "kid": "key-1"}]},
        ]
        transport.post_responses = [FakeTransportError("token response lost")]
        with self.assertRaises(IdentityProviderResultUnknownError):
            adapter.exchange(exchange_request())


class StdlibOidcJsonTransportTest(unittest.TestCase):
    class _Headers:
        def __init__(self, content_type="application/json"):
            self._content_type = content_type

        def get_content_type(self):
            return self._content_type

    class _Response:
        def __init__(self, body, *, status=200, content_type="application/json"):
            self.status = status
            self.headers = StdlibOidcJsonTransportTest._Headers(content_type)
            self._stream = io.BytesIO(body)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, maximum):
            return self._stream.read(maximum)

    class _Opener:
        def __init__(self, response):
            self.response = response
            self.calls = []

        def open(self, request, timeout):
            self.calls.append((request, timeout))
            if isinstance(self.response, Exception):
                raise self.response
            return self.response

    def test_transport_has_closed_json_content_type_and_size_bounds(self):
        with patch.dict(
            os.environ,
            {"HTTPS_PROXY": "http://ambient-proxy.invalid:9999"},
            clear=False,
        ):
            adapter = StdlibOidcJsonTransport()
        proxy_handlers = [
            handler
            for handler in adapter._opener.handlers
            if isinstance(handler, ProxyHandler)
        ]
        # An empty explicit ProxyHandler suppresses urllib's environment-based
        # default.  urllib does not retain the empty handler in the opener.
        self.assertEqual(proxy_handlers, [])
        opener = self._Opener(self._Response(b'{"issuer":"https://id.test"}'))
        adapter._opener = opener
        self.assertEqual(
            adapter.get_json(
                url="https://id.test/.well-known/openid-configuration",
                timeout_seconds=3,
                maximum_bytes=1024,
            ),
            {"issuer": "https://id.test"},
        )
        self.assertEqual(opener.calls[0][1], 3)

        for response in (
            self._Response(b"{}", content_type="text/html"),
            self._Response(b"x" * 9),
            self._Response(b"[]"),
        ):
            with self.subTest(response=response):
                adapter._opener = self._Opener(response)
                with self.assertRaises(RuntimeError):
                    adapter.get_json(
                        url="https://id.test/configuration",
                        timeout_seconds=1,
                        maximum_bytes=8,
                    )


class PyJwtOidcTokenVerifierTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import jwt
            from cryptography.hazmat.primitives.asymmetric import rsa
        except ImportError as error:
            raise unittest.SkipTest("server extra is not installed") from error
        cls.jwt = jwt
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(cls.private_key.public_key()))
        public_jwk.update({"kid": "key-1", "use": "sig", "alg": "RS256"})
        cls.jwks = {"keys": [public_jwk]}

    def token(self, **changes):
        value = claims()
        value.update(changes)
        return self.jwt.encode(
            value,
            self.private_key,
            algorithm="RS256",
            headers={"kid": "key-1"},
        )

    def verify(self, token, **changes):
        facts = dict(
            id_token=token,
            jwks=self.jwks,
            allowed_signing_algorithms=("RS256",),
            expected_issuer=ISSUER,
            expected_audience=CLIENT_ID,
            expected_nonce="nonce-001",
            server_now=NOW,
            clock_skew_seconds=30,
        )
        facts.update(changes)
        return PyJwtOidcTokenVerifier().verify_id_token(**facts)

    def test_verifier_selects_exact_kid_algorithm_and_claim_contract(self):
        verified = self.verify(self.token())
        self.assertEqual(verified["sub"], "provider-subject-001")

        with self.assertRaises(IdentityProviderMisconfiguredError):
            self.verify(
                self.jwt.encode(
                    claims(),
                    self.private_key,
                    algorithm="RS256",
                    headers={"kid": "other-key"},
                )
            )
        cases = (
            self.token(nonce="other-nonce"),
            self.token(aud="other-audience"),
            self.token(exp=int(NOW.timestamp())),
        )
        for token in cases:
            with self.subTest(token=token[:16]):
                with self.assertRaises(IdentityProviderRejectedError):
                    self.verify(token)

    def test_verifier_rejects_duplicate_kid_private_or_symmetric_keys(self):
        public = dict(self.jwks["keys"][0])
        for keyset in (
            {"keys": [public, dict(public)]},
            {"keys": [{"kty": "oct", "kid": "key-1", "k": "c2VjcmV0"}]},
            {"keys": [{**public, "d": "private-material"}]},
        ):
            with self.subTest(keyset=keyset):
                with self.assertRaises(IdentityProviderMisconfiguredError):
                    self.verify(self.token(), jwks=keyset)


if __name__ == "__main__":
    unittest.main()
