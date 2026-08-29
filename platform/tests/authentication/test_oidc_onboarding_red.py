"""Application semantic RED for OIDC onboarding and BFF Sessions.

The tests cover TEST-AUTH-TRANSACTION-001 and TEST-AUTH-ONBOARDING-001.
They deliberately use only synthetic `.example.test` identities and inspect
stable facts rather than reproducing handler policy in test helpers.
"""

from __future__ import annotations

import base64
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from datetime import timedelta
import hashlib
from pathlib import Path
from typing import Any, Callable
import unittest

import yaml

from desire_platform.identity_access.application.authentication import (
    BeginOidcAuthorizationCommand,
    CompleteOidcAuthenticationCommand,
)
from desire_platform.identity_access.domain.invitations import InvitationStatus
from desire_platform.identity_access.ports.identity_provider import (
    IdentityProviderResultUnknownError,
)
from desire_platform.identity_access.security.cryptography import (
    csrf_digest,
    derive_csrf_token,
    session_handle_digest,
)
from tests.support.iam_authentication_builders import (
    AUTH_TRANSACTION_ID,
    CONTACT_POINT_ID,
    CSRF_KEY_ID,
    EXTERNAL_IDENTITY_ID,
    INVITATION_ID,
    NEW_SESSION_ID,
    OTHER_CONTACT_POINT_ID,
    OTHER_USER_ID,
    PENDING_USER_ID,
    PROTOCOL_ENCRYPTION_KEY_ID,
    PROVIDER_AUDIENCE,
    PROVIDER_ISSUER,
    RAW_BROWSER_COOKIE,
    RAW_CODE,
    RAW_CODE_VERIFIER,
    RAW_INVITATION_TOKEN,
    RAW_NONCE,
    RAW_SESSION_HANDLE,
    RAW_STATE,
    REDIRECT_URI,
    RETURN_TO,
    SESSION_FAMILY_ID,
    SESSION_HANDLE_KEY_ID,
    SESSION_ID,
    SUBJECT_DIGEST,
    SUBJECT_DIGEST_KEY_ID,
    SUCCESSOR_SESSION_ID,
    UTC_NOW,
    USER_ID,
    authentication_fixture,
    invoke_begin,
    invoke_complete,
    seed_current_session,
    seed_existing_identity,
    seed_pending_auth_transaction,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[2]
OPENAPI_PATH = PLATFORM_ROOT / "contracts" / "api" / "iam-v1.openapi.yaml"
RAW_PROTOCOL_SECRETS = (
    RAW_INVITATION_TOKEN,
    RAW_BROWSER_COOKIE,
    RAW_STATE,
    RAW_NONCE,
    RAW_CODE_VERIFIER,
    RAW_CODE,
    RAW_SESSION_HANDLE,
)


def _enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


def _row(snapshot: dict[str, dict[Any, Any]], table: str, key: Any) -> Any:
    return snapshot.get(table, {}).get(key)


def _safe_snapshot(snapshot: dict[str, dict[Any, Any]]) -> str:
    """Render persisted facts only; repr-safe production values stay redacted."""

    return repr(snapshot)


def _assert_no_raw_protocol_secret(
    test: unittest.TestCase,
    value: Any,
) -> None:
    rendered = repr(value)
    for secret in RAW_PROTOCOL_SECRETS:
        test.assertNotIn(secret, rendered)


def _replace_invitation(fixture: Any, **changes: Any) -> None:
    current = fixture.store._tables["invitations"][INVITATION_ID]
    fixture.store._tables["invitations"][INVITATION_ID] = replace(
        current,
        **changes,
    )


class OidcOnboardingApplicationSemanticRedTest(unittest.TestCase):
    """Freeze Begin/callback/onboarding/session behavior before GREEN."""

    def test_openapi_closes_browser_cookie_and_client_cannot_choose_authority(
        self,
    ) -> None:
        with OPENAPI_PATH.open(encoding="utf-8") as contract_file:
            contract = yaml.safe_load(contract_file)

        begin = contract["paths"]["/v1/auth/oidc/authorizations"]["post"]
        callback = contract["paths"]["/v1/auth/oidc/callback"]["get"]
        begin_schema = contract["components"]["schemas"][
            "BeginOidcAuthorizationRequest"
        ]
        browser_cookie = next(
            parameter
            for parameter in callback["parameters"]
            if parameter.get("name") == "__Host-ds_oidc"
        )
        set_cookie = begin["responses"]["201"]["headers"]["Set-Cookie"]

        self.assertEqual(
            {
                "request_closed": begin_schema["additionalProperties"],
                "client_fields": set(begin_schema["properties"]),
                "cookie_in": browser_cookie["in"],
                "cookie_required": browser_cookie["required"],
                "cookie_sensitive": browser_cookie["x-sensitive"],
                "cookie_log_policy": browser_cookie["x-log-policy"],
                "set_cookie_sensitive": set_cookie["schema"]["x-sensitive"],
                "set_cookie_log_policy": set_cookie["schema"]["x-log-policy"],
            },
            {
                "request_closed": False,
                "client_fields": {
                    "access_invitation_token",
                    "reauthenticate",
                    "return_to",
                },
                "cookie_in": "cookie",
                "cookie_required": True,
                "cookie_sensitive": True,
                "cookie_log_policy": "redact",
                "set_cookie_sensitive": True,
                "set_cookie_log_policy": "redact",
            },
        )

    def test_commands_are_frozen_and_never_render_transport_secrets(self) -> None:
        fixture = authentication_fixture()
        values = (
            fixture.anonymous_context,
            fixture.begin_invitation_command,
            fixture.complete_command,
        )
        _assert_no_raw_protocol_secret(self, values)
        with self.assertRaises(FrozenInstanceError):
            fixture.begin_invitation_command.return_to = "/attacker"  # type: ignore[misc]

    def test_begin_derives_the_four_closed_purpose_and_binding_combinations(
        self,
    ) -> None:
        cases = (
            (
                "anonymous-login",
                False,
                False,
                "LOGIN",
                None,
                None,
                None,
                None,
            ),
            (
                "current-session-login",
                True,
                False,
                "LOGIN",
                SESSION_ID,
                USER_ID,
                None,
                None,
            ),
            (
                "anonymous-enrollment",
                False,
                True,
                "ENROLLMENT",
                None,
                None,
                None,
                INVITATION_ID,
            ),
            (
                "current-session-step-up",
                True,
                True,
                "STEP_UP",
                SESSION_ID,
                USER_ID,
                USER_ID,
                INVITATION_ID,
            ),
        )

        for (
            name,
            current,
            invitation,
            expected_purpose,
            expected_session,
            expected_initiating_user,
            expected_user,
            expected_invitation,
        ) in cases:
            with self.subTest(name=name):
                fixture = authentication_fixture()
                if current:
                    seed_current_session(fixture)
                context = (
                    fixture.current_context
                    if current
                    else fixture.anonymous_context
                )
                command = (
                    fixture.begin_invitation_command
                    if invitation
                    else fixture.begin_login_command
                )

                result, code = invoke_begin(
                    fixture,
                    context=context,
                    command=command,
                )
                snapshot = fixture.store.snapshot()
                transaction = _row(
                    snapshot,
                    "auth_transactions",
                    AUTH_TRANSACTION_ID,
                ) or {}

                self.assertEqual(
                    {
                        "code": code,
                        "result_id": getattr(
                            result,
                            "auth_transaction_id",
                            None,
                        ),
                        "purpose": _enum_value(transaction.get("purpose")),
                        "initiating_session": transaction.get(
                            "initiating_session_id"
                        ),
                        "initiating_user": transaction.get(
                            "initiating_user_id"
                        ),
                        "expected_user": transaction.get("expected_user_id"),
                        "invitation": transaction.get("invitation_id"),
                        "invitation_version": transaction.get(
                            "invitation_version"
                        ),
                        "contact": transaction.get(
                            "expected_contact_point_id"
                        ),
                        "uow_commits": fixture.uow_factory.commit_count,
                        "preflight_calls": len(
                            fixture.provider.preflight_calls
                        ),
                        "begin_calls": len(fixture.provider.begin_calls),
                    },
                    {
                        "code": None,
                        "result_id": AUTH_TRANSACTION_ID,
                        "purpose": expected_purpose,
                        "initiating_session": expected_session,
                        "initiating_user": expected_initiating_user,
                        "expected_user": expected_user,
                        "invitation": expected_invitation,
                        "invitation_version": 1 if invitation else None,
                        "contact": CONTACT_POINT_ID if invitation else None,
                        "uow_commits": 1,
                        "preflight_calls": 1,
                        "begin_calls": 1,
                    },
                )

    def test_begin_persists_formal_pkce_browser_time_and_no_raw_secret(
        self,
    ) -> None:
        fixture = authentication_fixture()
        result, code = invoke_begin(
            fixture,
            context=fixture.anonymous_context,
            command=fixture.begin_invitation_command,
        )
        snapshot = fixture.store.snapshot()
        transaction = _row(
            snapshot,
            "auth_transactions",
            AUTH_TRANSACTION_ID,
        ) or {}
        begin_call = fixture.provider.begin_calls[0]
        decrypted_nonce = fixture.protocol_secret_box.decrypt(
            ciphertext=transaction["nonce_ciphertext"],
            key_id=transaction["nonce_encryption_key_id"],
        )
        decrypted_verifier = fixture.protocol_secret_box.decrypt(
            ciphertext=transaction["pkce_verifier_ciphertext"],
            key_id=transaction["pkce_encryption_key_id"],
        )

        self.assertEqual(
            {
                "code": code,
                "result": getattr(result, "auth_transaction_id", None),
                "status": _enum_value(transaction.get("status")),
                "version": transaction.get("aggregate_version"),
                "deadline": transaction.get("deadline"),
                "state_key": transaction.get("state_digest_key_id"),
                "browser_key": transaction.get(
                    "browser_binding_digest_key_id"
                ),
                "nonce_key": transaction.get("nonce_encryption_key_id"),
                "verifier_key": transaction.get("pkce_encryption_key_id"),
                "challenge_method": transaction.get(
                    "pkce_code_challenge_method"
                ),
                "issuer": transaction.get("provider_issuer"),
                "audience": transaction.get("provider_audience"),
                "redirect": transaction.get("redirect_uri"),
                "return_to": transaction.get("return_to"),
                "policy": transaction.get("security_policy_version"),
                "user_count": len(snapshot.get("users", {})),
                "session_count": len(snapshot.get("sessions", {})),
                "identity_count": len(
                    snapshot.get("external_identities", {})
                ),
                "server_replaced_browser_cookie": (
                    result.oidc_browser_cookie
                    != fixture.anonymous_context.raw_oidc_browser_cookie
                ),
                "browser_cookie_entropy_chars": len(
                    result.oidc_browser_cookie
                ),
                "browser_digest_matches": (
                    transaction["browser_binding_digest"]
                    == fixture.protocol_keyring.digest_text(
                        key_id=transaction[
                            "browser_binding_digest_key_id"
                        ],
                        value=result.oidc_browser_cookie,
                    )
                ),
                "state_digest_matches": (
                    transaction["state_digest"]
                    == fixture.protocol_keyring.digest_text(
                        key_id=transaction["state_digest_key_id"],
                        value=begin_call.state,
                    )
                ),
                "nonce_round_trip": decrypted_nonce == begin_call.nonce,
                "verifier_challenge_matches": (
                    transaction["pkce_code_challenge"]
                    == base64.urlsafe_b64encode(
                        hashlib.sha256(
                            decrypted_verifier.encode("ascii")
                        ).digest()
                    ).rstrip(b"=").decode("ascii")
                ),
            },
            {
                "code": None,
                "result": AUTH_TRANSACTION_ID,
                "status": "PENDING",
                "version": 1,
                "deadline": UTC_NOW + timedelta(minutes=10),
                "state_key": "oidc-state-digest-2026-01",
                "browser_key": "oidc-browser-digest-2026-01",
                "nonce_key": PROTOCOL_ENCRYPTION_KEY_ID,
                "verifier_key": PROTOCOL_ENCRYPTION_KEY_ID,
                "challenge_method": "S256",
                "issuer": PROVIDER_ISSUER,
                "audience": PROVIDER_AUDIENCE,
                "redirect": REDIRECT_URI,
                "return_to": RETURN_TO,
                "policy": "iam-security-v1",
                "user_count": 0,
                "session_count": 0,
                "identity_count": 0,
                "server_replaced_browser_cookie": True,
                "browser_cookie_entropy_chars": 43,
                "browser_digest_matches": True,
                "state_digest_matches": True,
                "nonce_round_trip": True,
                "verifier_challenge_matches": True,
            },
        )
        _assert_no_raw_protocol_secret(self, snapshot)
        for generated_secret in (
            result.oidc_browser_cookie,
            begin_call.state,
            begin_call.nonce,
            decrypted_verifier,
            result.authorization_url,
        ):
            self.assertNotIn(generated_secret, _safe_snapshot(snapshot))

    def test_invalid_session_is_anonymous_but_capability_is_still_checked(
        self,
    ) -> None:
        fixture = authentication_fixture()
        seed_current_session(fixture)
        fixture.store._tables["sessions"][SESSION_ID][
            "idle_expires_at"
        ] = UTC_NOW

        result, code = invoke_begin(
            fixture,
            context=fixture.current_context,
            command=fixture.begin_invitation_command,
        )
        transaction = fixture.store.snapshot().get(
            "auth_transactions",
            {},
        ).get(AUTH_TRANSACTION_ID, {})

        self.assertEqual(
            {
                "code": code,
                "result": getattr(result, "auth_transaction_id", None),
                "purpose": _enum_value(transaction.get("purpose")),
                "initiating_session": transaction.get(
                    "initiating_session_id"
                ),
                "expected_user": transaction.get("expected_user_id"),
                "invitation": transaction.get("invitation_id"),
                "capability_calls": fixture.invitation_capability.calls,
            },
            {
                "code": None,
                "result": AUTH_TRANSACTION_ID,
                "purpose": "ENROLLMENT",
                "initiating_session": None,
                "expected_user": None,
                "invitation": INVITATION_ID,
                "capability_calls": 1,
            },
        )

    def test_invalid_capability_or_authoritative_invitation_is_zero_write(
        self,
    ) -> None:
        def invalid_token(fixture: Any) -> BeginOidcAuthorizationCommand:
            return BeginOidcAuthorizationCommand(
                return_to=RETURN_TO,
                access_invitation_token="invalid-synthetic-token",
            )

        cases: tuple[
            tuple[
                str,
                Callable[[Any], BeginOidcAuthorizationCommand],
            ],
            ...,
        ] = (
            ("invalid-token", invalid_token),
            (
                "terminal-invitation",
                lambda fixture: (
                    _replace_invitation(
                        fixture,
                        status=InvitationStatus.REVOKED,
                    )
                    or fixture.begin_invitation_command
                ),
            ),
            (
                "exclusive-expiry",
                lambda fixture: (
                    _replace_invitation(fixture, expires_at=UTC_NOW)
                    or fixture.begin_invitation_command
                ),
            ),
            (
                "nonce-swap",
                lambda fixture: (
                    _replace_invitation(fixture, nonce="different-nonce")
                    or fixture.begin_invitation_command
                ),
            ),
            (
                "token-key-swap",
                lambda fixture: (
                    _replace_invitation(
                        fixture,
                        token_key_id="different-token-key",
                    )
                    or fixture.begin_invitation_command
                ),
            ),
            (
                "token-format-swap",
                lambda fixture: (
                    _replace_invitation(
                        fixture,
                        token_format_version="different-token-format",
                    )
                    or fixture.begin_invitation_command
                ),
            ),
        )

        for name, configure in cases:
            with self.subTest(name=name):
                fixture = authentication_fixture()
                before = fixture.store.snapshot()
                command = configure(fixture)
                result, code = invoke_begin(
                    fixture,
                    context=fixture.anonymous_context,
                    command=command,
                )
                after = fixture.store.snapshot()

                self.assertEqual(
                    {
                        "result": result,
                        "code": code,
                        "transactions": after.get(
                            "auth_transactions",
                            {},
                        ),
                        "users": after.get("users", {}),
                        "sessions": after.get("sessions", {}),
                        "writes": fixture.uow_factory.write_calls,
                        "provider_begin": fixture.provider.begin_calls,
                    },
                    {
                        "result": None,
                        "code": "ACCESS_INVITATION_UNAVAILABLE",
                        "transactions": {},
                        "users": before.get("users", {}),
                        "sessions": before.get("sessions", {}),
                        "writes": [],
                        "provider_begin": [],
                    },
                )

    def test_callback_compare_and_consume_allows_exactly_one_exchange(self) -> None:
        fixture = authentication_fixture()
        seed_pending_auth_transaction(fixture)

        def callback() -> tuple[Any, str | None]:
            return invoke_complete(fixture)

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(lambda _index: callback(), range(2)))

        codes = Counter(code for _result, code in outcomes)
        snapshot = fixture.store.snapshot()
        transaction = snapshot["auth_transactions"][AUTH_TRANSACTION_ID]

        self.assertEqual(
            {
                "codes": codes,
                "exchange_calls": len(fixture.provider.exchange_calls),
                "commits": fixture.uow_factory.commit_count,
                "transaction_status": _enum_value(
                    transaction.get("status")
                ),
                "transaction_version": transaction.get(
                    "aggregate_version"
                ),
                "session_count": len(snapshot.get("sessions", {})),
            },
            {
                "codes": Counter({None: 1, "AUTH_TRANSACTION_INVALID": 1}),
                "exchange_calls": 1,
                "commits": 2,
                "transaction_status": "SUCCEEDED",
                "transaction_version": 3,
                "session_count": 1,
            },
        )

    def test_callback_rejects_browser_state_deadline_and_every_exact_binding(
        self,
    ) -> None:
        def wrong_browser(fixture: Any) -> tuple[Any, Any]:
            context = replace(
                fixture.anonymous_context,
                raw_oidc_browser_cookie="wrong-browser-binding",
            )
            return context, fixture.complete_command

        def wrong_state(fixture: Any) -> tuple[Any, Any]:
            command = replace(fixture.complete_command, state="wrong-state")
            return fixture.anonymous_context, command

        def expired(fixture: Any) -> tuple[Any, Any]:
            fixture.store._tables["auth_transactions"][AUTH_TRANSACTION_ID][
                "deadline"
            ] = UTC_NOW
            return fixture.anonymous_context, fixture.complete_command

        def revoked_invitation(fixture: Any) -> tuple[Any, Any]:
            _replace_invitation(fixture, status=InvitationStatus.REVOKED)
            return fixture.anonymous_context, fixture.complete_command

        def invitation_version_swap(fixture: Any) -> tuple[Any, Any]:
            _replace_invitation(fixture, aggregate_version=2)
            return fixture.anonymous_context, fixture.complete_command

        def contact_type_swap(fixture: Any) -> tuple[Any, Any]:
            fixture.store._tables["contact_points"][CONTACT_POINT_ID][
                "type"
            ] = "PHONE"
            return fixture.anonymous_context, fixture.complete_command

        def contact_digest_swap(fixture: Any) -> tuple[Any, Any]:
            fixture.store._tables["contact_points"][CONTACT_POINT_ID][
                "binding_digest"
            ] = "f" * 64
            return fixture.anonymous_context, fixture.complete_command

        def contact_key_swap(fixture: Any) -> tuple[Any, Any]:
            fixture.store._tables["contact_points"][CONTACT_POINT_ID][
                "binding_digest_key_id"
            ] = "different-binding-key"
            return fixture.anonymous_context, fixture.complete_command

        def same_digest_other_row(fixture: Any) -> tuple[Any, Any]:
            fixture.store._tables["auth_transactions"][AUTH_TRANSACTION_ID][
                "expected_contact_point_id"
            ] = OTHER_CONTACT_POINT_ID
            return fixture.anonymous_context, fixture.complete_command

        cases = (
            ("wrong-browser", wrong_browser, "AUTH_TRANSACTION_INVALID"),
            ("wrong-state", wrong_state, "AUTH_TRANSACTION_INVALID"),
            ("exclusive-deadline", expired, "AUTH_TRANSACTION_INVALID"),
            (
                "revoked-invitation",
                revoked_invitation,
                "ACCESS_INVITATION_UNAVAILABLE",
            ),
            (
                "invitation-version",
                invitation_version_swap,
                "ACCESS_INVITATION_UNAVAILABLE",
            ),
            (
                "contact-type",
                contact_type_swap,
                "ACCESS_INVITATION_UNAVAILABLE",
            ),
            (
                "contact-digest",
                contact_digest_swap,
                "ACCESS_INVITATION_UNAVAILABLE",
            ),
            (
                "contact-key",
                contact_key_swap,
                "ACCESS_INVITATION_UNAVAILABLE",
            ),
            (
                "same-digest-other-row",
                same_digest_other_row,
                "ACCESS_INVITATION_UNAVAILABLE",
            ),
        )

        for name, configure, expected_code in cases:
            with self.subTest(name=name):
                fixture = authentication_fixture()
                seed_pending_auth_transaction(fixture)
                context, command = configure(fixture)
                result, code = invoke_complete(
                    fixture,
                    context=context,
                    command=command,
                )
                snapshot = fixture.store.snapshot()

                self.assertEqual(
                    {
                        "result": result,
                        "code": code,
                        "users": snapshot.get("users", {}),
                        "identities": snapshot.get(
                            "external_identities",
                            {},
                        ),
                        "sessions": snapshot.get("sessions", {}),
                        "exchange_calls": len(
                            fixture.provider.exchange_calls
                        ),
                    },
                    {
                        "result": None,
                        "code": expected_code,
                        "users": {},
                        "identities": {},
                        "sessions": {},
                        "exchange_calls": 0,
                    },
                )

    def test_callback_provider_and_commit_unknown_outcomes_are_not_retried(
        self,
    ) -> None:
        cases = (
            (
                "provider-explicit-error",
                "provider_error",
                "AUTHENTICATION_REJECTED",
                "FAILED",
                0,
            ),
            (
                "provider-result-unknown",
                "provider_unknown",
                "IDENTITY_PROVIDER_UNAVAILABLE",
                "RESULT_UNKNOWN",
                1,
            ),
            (
                "claim-commit-unknown",
                "claim_commit_unknown",
                "COMMAND_OUTCOME_UNKNOWN",
                "EXCHANGING",
                0,
            ),
            (
                "final-commit-unknown",
                "final_commit_unknown",
                "COMMAND_OUTCOME_UNKNOWN",
                "SUCCEEDED",
                1,
            ),
        )

        for name, mode, expected_code, expected_status, exchange_calls in cases:
            with self.subTest(name=name):
                fixture = authentication_fixture()
                seed_pending_auth_transaction(fixture)
                command = fixture.complete_command
                if mode == "provider_error":
                    command = CompleteOidcAuthenticationCommand(
                        state=RAW_STATE,
                        provider_error="access_denied",
                    )
                elif mode == "provider_unknown":
                    fixture.provider.exchange_failure = (
                        IdentityProviderResultUnknownError(
                            "synthetic provider result unknown"
                        )
                    )
                elif mode == "claim_commit_unknown":
                    fixture.uow_factory.commit_unknown_at = {1}
                elif mode == "final_commit_unknown":
                    fixture.uow_factory.commit_unknown_at = {2}

                result, code = invoke_complete(fixture, command=command)
                snapshot = fixture.store.snapshot()
                transaction = snapshot["auth_transactions"][
                    AUTH_TRANSACTION_ID
                ]

                self.assertEqual(
                    {
                        "result": result,
                        "code": code,
                        "status": _enum_value(transaction.get("status")),
                        "exchange_calls": len(
                            fixture.provider.exchange_calls
                        ),
                    },
                    {
                        "result": None,
                        "code": expected_code,
                        "status": expected_status,
                        "exchange_calls": exchange_calls,
                    },
                )

    def test_unknown_subject_login_is_zero_user_but_enrollment_is_atomic(
        self,
    ) -> None:
        login = authentication_fixture()
        seed_pending_auth_transaction(
            login,
            purpose="LOGIN",
            invitation_id=None,
            invitation_version=None,
            expected_contact_point_id=None,
        )
        login_result, login_code = invoke_complete(login)
        login_snapshot = login.store.snapshot()

        enrollment = authentication_fixture()
        seed_pending_auth_transaction(enrollment)
        enrollment_result, enrollment_code = invoke_complete(enrollment)
        enrollment_snapshot = enrollment.store.snapshot()
        pending_user = _row(
            enrollment_snapshot,
            "users",
            PENDING_USER_ID,
        ) or {}
        identity = _row(
            enrollment_snapshot,
            "external_identities",
            (PROVIDER_ISSUER, SUBJECT_DIGEST),
        ) or {}
        contact = _row(
            enrollment_snapshot,
            "contact_points",
            CONTACT_POINT_ID,
        ) or {}
        session = _row(
            enrollment_snapshot,
            "sessions",
            NEW_SESSION_ID,
        ) or {}

        self.assertEqual(
            {
                "login_result": login_result,
                "login_code": login_code,
                "login_users": login_snapshot.get("users", {}),
                "login_identities": login_snapshot.get(
                    "external_identities",
                    {},
                ),
                "login_sessions": login_snapshot.get("sessions", {}),
                "enrollment_code": enrollment_code,
                "enrollment_user_id": getattr(
                    enrollment_result,
                    "user_id",
                    None,
                ),
                "pending_status": pending_user.get("status"),
                "identity_id": identity.get("external_identity_id"),
                "identity_user": identity.get("user_id"),
                "identity_key": identity.get("subject_digest_key_id"),
                "contact_status": contact.get("status"),
                "contact_user": contact.get("user_id"),
                "session_invitation": session.get(
                    "verified_for_invitation_id"
                ),
                "session_contact": session.get(
                    "verified_contact_point_id"
                ),
            },
            {
                "login_result": None,
                "login_code": "AUTHENTICATION_REJECTED",
                "login_users": {},
                "login_identities": {},
                "login_sessions": {},
                "enrollment_code": None,
                "enrollment_user_id": PENDING_USER_ID,
                "pending_status": "PENDING_ENROLLMENT",
                "identity_id": EXTERNAL_IDENTITY_ID,
                "identity_user": PENDING_USER_ID,
                "identity_key": SUBJECT_DIGEST_KEY_ID,
                "contact_status": "VERIFIED",
                "contact_user": PENDING_USER_ID,
                "session_invitation": INVITATION_ID,
                "session_contact": CONTACT_POINT_ID,
            },
        )
        _assert_no_raw_protocol_secret(self, enrollment_snapshot)

    def test_existing_subject_is_exact_user_and_never_contact_auto_merge(
        self,
    ) -> None:
        def valid_existing(fixture: Any) -> None:
            seed_current_session(fixture)
            seed_existing_identity(fixture)
            seed_pending_auth_transaction(
                fixture,
                purpose="STEP_UP",
                initiating_session_id=SESSION_ID,
                initiating_user_id=USER_ID,
                expected_user_id=USER_ID,
            )

        def expected_user_swap(fixture: Any) -> None:
            valid_existing(fixture)
            fixture.store._tables["auth_transactions"][AUTH_TRANSACTION_ID][
                "expected_user_id"
            ] = OTHER_USER_ID

        def identity_other_user(fixture: Any) -> None:
            seed_current_session(fixture)
            seed_existing_identity(fixture, user_id=OTHER_USER_ID)
            seed_pending_auth_transaction(
                fixture,
                purpose="STEP_UP",
                initiating_session_id=SESSION_ID,
                initiating_user_id=USER_ID,
                expected_user_id=USER_ID,
            )

        def contact_already_other_user(fixture: Any) -> None:
            seed_existing_identity(fixture)
            seed_pending_auth_transaction(fixture)
            fixture.store._tables["contact_points"][CONTACT_POINT_ID][
                "user_id"
            ] = OTHER_USER_ID

        cases = (
            ("valid-exact-user", valid_existing, None, USER_ID, 2),
            (
                "expected-user-swap",
                expected_user_swap,
                "AUTHENTICATION_REJECTED",
                None,
                1,
            ),
            (
                "identity-owned-by-other-user",
                identity_other_user,
                "AUTHENTICATION_REJECTED",
                None,
                1,
            ),
            (
                "contact-owned-by-other-user",
                contact_already_other_user,
                "ACCESS_INVITATION_UNAVAILABLE",
                None,
                0,
            ),
        )

        for name, configure, expected_code, expected_user, base_sessions in cases:
            with self.subTest(name=name):
                fixture = authentication_fixture()
                configure(fixture)
                result, code = invoke_complete(fixture)
                snapshot = fixture.store.snapshot()

                self.assertEqual(
                    {
                        "code": code,
                        "user": getattr(result, "user_id", None),
                        "session_count": len(snapshot.get("sessions", {})),
                    },
                    {
                        "code": expected_code,
                        "user": expected_user,
                        "session_count": base_sessions,
                    },
                )

    def test_suspended_or_closed_existing_subject_never_gets_session(self) -> None:
        for status in ("SUSPENDED", "CLOSED"):
            with self.subTest(status=status):
                fixture = authentication_fixture()
                seed_existing_identity(fixture, user_status=status)
                seed_pending_auth_transaction(
                    fixture,
                    purpose="LOGIN",
                    invitation_id=None,
                    invitation_version=None,
                    expected_contact_point_id=None,
                )
                before = fixture.store.snapshot()
                result, code = invoke_complete(fixture)
                after = fixture.store.snapshot()

                self.assertEqual(
                    {
                        "result": result,
                        "code": code,
                        "sessions": after.get("sessions", {}),
                        "families": after.get("session_families", {}),
                        "user": after["users"][USER_ID],
                    },
                    {
                        "result": None,
                        "code": "AUTHENTICATION_REJECTED",
                        "sessions": {},
                        "families": {},
                        "user": before["users"][USER_ID],
                    },
                )

    def test_session_creation_and_rotation_persist_formal_auth_and_secret_facts(
        self,
    ) -> None:
        fixture = authentication_fixture()
        seed_current_session(fixture)
        seed_existing_identity(fixture)
        seed_pending_auth_transaction(
            fixture,
            purpose="STEP_UP",
            initiating_session_id=SESSION_ID,
            initiating_user_id=USER_ID,
            expected_user_id=USER_ID,
        )

        result, code = invoke_complete(fixture)
        snapshot = fixture.store.snapshot()
        family = _row(snapshot, "session_families", SESSION_FAMILY_ID) or {}
        predecessor = _row(snapshot, "sessions", SESSION_ID) or {}
        successor = _row(snapshot, "sessions", SUCCESSOR_SESSION_ID) or {}
        expected_handle_digest = session_handle_digest(
            fixture.protocol_keyring,
            result.raw_session_handle,
        )
        expected_csrf = derive_csrf_token(
            fixture.protocol_keyring,
            raw_session_handle=result.raw_session_handle,
            csrf_salt=successor["csrf_salt"],
            session_id=SUCCESSOR_SESSION_ID,
            generation=3,
            key_id=successor["csrf_key_id"],
        )
        expected_csrf_digest = csrf_digest(
            fixture.protocol_keyring,
            csrf_token=expected_csrf,
            key_id=successor["csrf_key_id"],
        )

        self.assertEqual(
            {
                "code": code,
                "result_session": getattr(result, "session_id", None),
                "family_generation": family.get("current_generation"),
                "predecessor_status": predecessor.get("status"),
                "successor_family": successor.get("session_family_id"),
                "successor_generation": successor.get("generation"),
                "successor_predecessor": successor.get(
                    "predecessor_session_id"
                ),
                "user": successor.get("user_id"),
                "auth_transaction": successor.get("auth_transaction_id"),
                "auth_time": successor.get("auth_time"),
                "acr": successor.get("acr_code"),
                "amr": successor.get("amr_codes"),
                "created": successor.get("created_at"),
                "last_activity": successor.get("last_activity_at"),
                "idle": successor.get("idle_expires_at"),
                "absolute": successor.get("absolute_expires_at"),
                "handle_key": successor.get("handle_digest_key_id"),
                "csrf_key": successor.get("csrf_key_id"),
                "csrf_salt_length": len(successor.get("csrf_salt", b"")),
                "handle_digest_matches": (
                    successor.get("handle_digest")
                    == expected_handle_digest
                ),
                "csrf_token_matches": result.csrf_token == expected_csrf,
                "csrf_digest_matches": (
                    successor.get("csrf_digest")
                    == expected_csrf_digest
                ),
                "invitation": successor.get(
                    "verified_for_invitation_id"
                ),
                "contact": successor.get("verified_contact_point_id"),
            },
            {
                "code": None,
                "result_session": SUCCESSOR_SESSION_ID,
                "family_generation": 3,
                "predecessor_status": "REVOKED",
                "successor_family": SESSION_FAMILY_ID,
                "successor_generation": 3,
                "successor_predecessor": SESSION_ID,
                "user": USER_ID,
                "auth_transaction": AUTH_TRANSACTION_ID,
                "auth_time": UTC_NOW - timedelta(minutes=1),
                "acr": "urn:desire:acr:mfa",
                "amr": ("pwd", "otp"),
                "created": UTC_NOW,
                "last_activity": UTC_NOW,
                "idle": UTC_NOW + timedelta(minutes=30),
                "absolute": UTC_NOW + timedelta(hours=12),
                "handle_key": SESSION_HANDLE_KEY_ID,
                "csrf_key": CSRF_KEY_ID,
                "csrf_salt_length": 32,
                "handle_digest_matches": True,
                "csrf_token_matches": True,
                "csrf_digest_matches": True,
                "invitation": INVITATION_ID,
                "contact": CONTACT_POINT_ID,
            },
        )
        _assert_no_raw_protocol_secret(self, snapshot)


if __name__ == "__main__":
    unittest.main()
