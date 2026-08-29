"""Semantic RED for the provider-neutral OIDC Authorization Code port.

TEST-AUTH-TRANSACTION-001 protects the strict deterministic fake as an
executable provider contract.  The fake is importable and secret-safe, but its
protocol behavior intentionally remains default-deny in this RED slice.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import timedelta
from typing import Any, Callable
import unittest

from tests.support.iam_authentication_builders import (
    AUTH_TRANSACTION_ID,
    PROVIDER_AUDIENCE,
    PROVIDER_ISSUER,
    RAW_CODE,
    RAW_CODE_VERIFIER,
    RAW_NONCE,
    RAW_STATE,
    REDIRECT_URI,
    UTC_NOW,
    authentication_fixture,
    valid_exchange_request,
    valid_fake_code,
)


def _capture(call: Callable[[], Any]) -> tuple[Any, str | None]:
    try:
        return call(), None
    except Exception as error:  # the asserted type is part of the contract
        return None, type(error).__name__


class OidcProviderContractSemanticRedTest(unittest.TestCase):
    """Freeze exact state/nonce/PKCE/provider/time and replay semantics."""

    def test_protocol_value_objects_are_frozen_and_secret_safe(self) -> None:
        fixture = authentication_fixture()
        request = valid_exchange_request()
        script = valid_fake_code()

        rendered = repr((request, script))
        for raw_secret in (
            RAW_CODE,
            RAW_STATE,
            RAW_NONCE,
            RAW_CODE_VERIFIER,
            script.raw_subject,
            script.verified_locator,
        ):
            with self.subTest(raw_secret=raw_secret[:12]):
                self.assertNotIn(raw_secret, rendered)

        with self.assertRaises(FrozenInstanceError):
            request.redirect_uri = "https://attacker.example.test/callback"  # type: ignore[misc]
        self.assertEqual(fixture.provider.exchange_calls, [])

    def test_valid_code_pkce_round_trip_returns_closed_verified_subject(
        self,
    ) -> None:
        fixture = authentication_fixture()
        provider = fixture.provider

        preflight, preflight_error = _capture(
            lambda: provider.preflight(
                expected_issuer=PROVIDER_ISSUER,
                expected_audience=PROVIDER_AUDIENCE,
                redirect_uri=REDIRECT_URI,
            )
        )
        authorization, begin_error = _capture(
            lambda: provider.begin(
                auth_transaction_id=AUTH_TRANSACTION_ID,
                redirect_uri=REDIRECT_URI,
                code_challenge=valid_fake_code().code_challenge,
                state=RAW_STATE,
                nonce=RAW_NONCE,
                expected_issuer=PROVIDER_ISSUER,
                expected_audience=PROVIDER_AUDIENCE,
            )
        )
        subject, exchange_error = _capture(
            lambda: provider.exchange(valid_exchange_request())
        )

        self.assertEqual(
            {
                "preflight": preflight,
                "preflight_error": preflight_error,
                "begin_error": begin_error,
                "begin_issuer": getattr(authorization, "issuer", None),
                "begin_audience": getattr(authorization, "audience", None),
                "begin_redirect": getattr(authorization, "redirect_uri", None),
                "pkce_method": getattr(
                    authorization,
                    "code_challenge_method",
                    None,
                ),
                "exchange_error": exchange_error,
                "subject_issuer": getattr(subject, "issuer", None),
                "subject_key_id": getattr(
                    subject,
                    "subject_digest_key_id",
                    None,
                ),
                "subject_auth_time": getattr(subject, "auth_time", None),
                "subject_acr": getattr(subject, "acr_code", None),
                "subject_amr": getattr(subject, "amr_codes", None),
            },
            {
                "preflight": None,
                "preflight_error": None,
                "begin_error": None,
                "begin_issuer": PROVIDER_ISSUER,
                "begin_audience": PROVIDER_AUDIENCE,
                "begin_redirect": REDIRECT_URI,
                "pkce_method": "S256",
                "exchange_error": None,
                "subject_issuer": PROVIDER_ISSUER,
                "subject_key_id": "oidc-subject-digest-2026-01",
                "subject_auth_time": UTC_NOW - timedelta(minutes=1),
                "subject_acr": "urn:desire:acr:mfa",
                "subject_amr": ("pwd", "otp"),
            },
        )

    def test_exchange_rejects_every_exact_request_binding_mismatch(self) -> None:
        cases = (
            ("state", {"state": "wrong-state"}),
            ("nonce", {"expected_nonce": "wrong-nonce"}),
            ("pkce", {"code_verifier": "wrong-verifier"}),
            (
                "redirect",
                {"redirect_uri": "https://attacker.example.test/callback"},
            ),
            ("issuer", {"expected_issuer": "https://other.example.test"}),
            ("audience", {"expected_audience": "other-client"}),
        )

        for name, changes in cases:
            with self.subTest(name=name):
                fixture = authentication_fixture()
                _subject, error_type = _capture(
                    lambda: fixture.provider.exchange(
                        valid_exchange_request(**changes)
                    )
                )
                self.assertEqual(error_type, "IdentityProviderRejectedError")

    def test_exchange_rejects_issuer_audience_azp_and_token_time_window(
        self,
    ) -> None:
        cases = (
            (
                "issuer",
                replace(
                    valid_fake_code(),
                    issuer="https://other.example.test",
                ),
            ),
            (
                "audience",
                replace(valid_fake_code(), audiences=("other-client",)),
            ),
            (
                "multi-audience-missing-azp",
                replace(
                    valid_fake_code(),
                    audiences=(PROVIDER_AUDIENCE, "other-client"),
                    authorized_party=None,
                ),
            ),
            (
                "multi-audience-wrong-azp",
                replace(
                    valid_fake_code(),
                    audiences=(PROVIDER_AUDIENCE, "other-client"),
                    authorized_party="other-client",
                ),
            ),
            (
                "exclusive-expiry",
                replace(valid_fake_code(), expires_at=UTC_NOW),
            ),
            (
                "future-not-before",
                replace(
                    valid_fake_code(),
                    not_before=UTC_NOW + timedelta(minutes=1),
                ),
            ),
            (
                "future-issued-at",
                replace(
                    valid_fake_code(),
                    issued_at=UTC_NOW + timedelta(minutes=1),
                ),
            ),
        )

        for name, script in cases:
            with self.subTest(name=name):
                fixture = authentication_fixture()
                fixture.provider.codes[RAW_CODE] = script
                _subject, error_type = _capture(
                    lambda: fixture.provider.exchange(valid_exchange_request())
                )
                self.assertEqual(error_type, "IdentityProviderRejectedError")

    def test_authorization_code_is_single_use_even_after_success(self) -> None:
        fixture = authentication_fixture()
        first, first_error = _capture(
            lambda: fixture.provider.exchange(valid_exchange_request())
        )
        second, second_error = _capture(
            lambda: fixture.provider.exchange(valid_exchange_request())
        )

        self.assertEqual(
            {
                "first_error": first_error,
                "first_subject": getattr(first, "issuer", None),
                "second": second,
                "second_error": second_error,
                "calls": len(fixture.provider.exchange_calls),
            },
            {
                "first_error": None,
                "first_subject": PROVIDER_ISSUER,
                "second": None,
                "second_error": "IdentityProviderRejectedError",
                "calls": 2,
            },
        )


if __name__ == "__main__":
    unittest.main()
