from __future__ import annotations

from dataclasses import FrozenInstanceError
import unittest

from desire_platform.http.iam import IAM_HTTP_ROUTES
from desire_platform.http import IamHttpTransport, RateLimitExceeded
from desire_platform.http.iam_security import (
    ExactOriginPolicy,
    ExactOriginPolicySettings,
    SessionSecuritySettings,
)
from desire_platform.identity_access.domain.errors import IamError
from tests.support.iam_http_transport_builders import (
    FixedTraceIdSource,
    make_http_fixture,
    request_for,
    response_header_values,
    response_json,
)


OPERATIONS = tuple(route.operation.value for route in IAM_HTTP_ROUTES)


def _origin_outcome(
    policy: ExactOriginPolicy,
    *,
    origin: str | None,
    operation_id: str,
) -> str | None:
    try:
        policy.require_allowed(origin=origin, operation_id=operation_id)
    except IamError as error:
        return error.code
    return None


def _readiness_outcome(policy: ExactOriginPolicy) -> str | None:
    try:
        policy.check_readiness(timeout_ms=100)
    except RuntimeError as error:
        return str(error)
    return None


class ExactOriginPolicyRedTests(unittest.TestCase):
    def test_settings_are_frozen_closed_and_secret_safe(self) -> None:
        settings = ExactOriginPolicySettings(
            allowed_origins=("https://app.example.test",),
        )
        with self.assertRaises(FrozenInstanceError):
            settings.allowed_origins = ()  # type: ignore[misc]
        self.assertNotIn("cookie", repr(settings).lower())
        self.assertIsNone(_readiness_outcome(ExactOriginPolicy(settings)))

    def test_exact_canonical_https_origin_is_allowed_for_every_operation(self) -> None:
        policy = ExactOriginPolicy(
            ExactOriginPolicySettings(
                allowed_origins=(
                    "https://app.example.test",
                    "https://admin.example.test:8443",
                )
            )
        )
        for operation_id in OPERATIONS:
            with self.subTest(operation_id=operation_id):
                self.assertIsNone(
                    _origin_outcome(
                        policy,
                        origin="https://app.example.test",
                        operation_id=operation_id,
                    )
                )

    def test_missing_alias_and_cross_origin_inputs_fail_closed(self) -> None:
        policy = ExactOriginPolicy(
            ExactOriginPolicySettings(
                allowed_origins=("https://app.example.test",)
            )
        )
        invalid = (
            None,
            "null",
            "https://APP.example.test",
            "https://app.example.test.",
            "https://app.example.test:443",
            "https://app.example.test/",
            "https://app.example.test/path",
            "http://app.example.test",
            "https://evil.example.test",
        )
        for origin in invalid:
            with self.subTest(origin=origin):
                self.assertEqual(
                    _origin_outcome(
                        policy,
                        origin=origin,
                        operation_id="getMe",
                    ),
                    "INVALID_REQUEST",
                )

    def test_configuration_rejects_noncanonical_or_open_allowlists(self) -> None:
        invalid_lists = (
            (),
            ("*",),
            ("null",),
            ("https://user@app.example.test",),
            ("https://app.example.test?query=1",),
            ("https://app.example.test#fragment",),
            ("https://app.example.test", "https://app.example.test"),
            ("http://localhost:3000",),
        )
        for allowed in invalid_lists:
            with self.subTest(allowed=allowed):
                with self.assertRaises((TypeError, ValueError)):
                    ExactOriginPolicySettings(allowed_origins=allowed)

    def test_synthetic_loopback_is_an_explicit_isolated_profile(self) -> None:
        settings = ExactOriginPolicySettings(
            allowed_origins=("http://127.0.0.1:3000",),
            allow_synthetic_loopback_http=True,
        )
        policy = ExactOriginPolicy(settings)
        self.assertIsNone(
            _origin_outcome(
                policy,
                origin="http://127.0.0.1:3000",
                operation_id="beginOidcAuthorization",
            )
        )
        with self.assertRaises(ValueError):
            ExactOriginPolicySettings(
                allowed_origins=("http://remote.example.test:3000",),
                allow_synthetic_loopback_http=True,
            )

    def test_internal_bff_http_is_exact_and_internal_sandbox_only(self) -> None:
        settings = ExactOriginPolicySettings(
            allowed_origins=("http://api:8000",),
            allow_internal_bff_http=True,
            deployment_mode="INTERNAL_SANDBOX",
        )
        policy = ExactOriginPolicy(settings)
        self.assertIsNone(
            _origin_outcome(
                policy,
                origin="http://api:8000",
                operation_id="getMe",
            )
        )
        for changed in (
            {
                "allowed_origins": ("http://api:8000",),
                "allow_internal_bff_http": True,
                "deployment_mode": "CONTROLLED_PILOT",
            },
            {
                "allowed_origins": ("http://api:8001",),
                "allow_internal_bff_http": True,
                "deployment_mode": "INTERNAL_SANDBOX",
            },
            {
                "allowed_origins": (
                    "http://api:8000",
                    "https://pilot.example.test",
                ),
                "allow_internal_bff_http": True,
                "deployment_mode": "INTERNAL_SANDBOX",
            },
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(ValueError):
                    ExactOriginPolicySettings(**changed)

    def test_unknown_operation_and_closed_component_are_unavailable(self) -> None:
        policy = ExactOriginPolicy(
            ExactOriginPolicySettings(
                allowed_origins=("https://app.example.test",)
            )
        )
        self.assertEqual(
            _origin_outcome(
                policy,
                origin="https://app.example.test",
                operation_id="unregisteredOperation",
            ),
            "SERVICE_UNAVAILABLE",
        )
        policy.close()
        self.assertEqual(
            _origin_outcome(
                policy,
                origin="https://app.example.test",
                operation_id="getMe",
            ),
            "SERVICE_UNAVAILABLE",
        )


class SessionSecuritySettingsTests(unittest.TestCase):
    def test_session_settings_are_closed_and_bounded(self) -> None:
        settings = SessionSecuritySettings()
        self.assertEqual(settings.runtime_role, "iam_session_authenticator")
        with self.assertRaises(FrozenInstanceError):
            settings.runtime_role = "schema_owner"  # type: ignore[misc]
        for changes in (
            {"runtime_role": "schema_owner"},
            {"lock_timeout_ms": 0},
            {"statement_timeout_ms": 0},
            {"idle_in_transaction_timeout_ms": 0},
            {"maximum_retained_handle_keys": 0},
            {"maximum_retained_handle_keys": 9},
            {"maximum_replay_resolution_attempts": 0},
            {"maximum_replay_resolution_attempts": 4},
            {"additional_csrf_operation_ids": ["internalPilotEditorWrite"]},
            {"additional_csrf_operation_ids": ("getMe",)},
            {"additional_csrf_operation_ids": ("invalid-operation",)},
            {
                "additional_csrf_operation_ids": (
                    "internalPilotEditorWrite",
                    "internalPilotEditorWrite",
                )
            },
        ):
            values = {
                "runtime_role": settings.runtime_role,
                "lock_timeout_ms": settings.lock_timeout_ms,
                "statement_timeout_ms": settings.statement_timeout_ms,
                "idle_in_transaction_timeout_ms": settings.idle_in_transaction_timeout_ms,
                "maximum_retained_handle_keys": settings.maximum_retained_handle_keys,
                "maximum_replay_resolution_attempts": settings.maximum_replay_resolution_attempts,
                "additional_csrf_operation_ids": settings.additional_csrf_operation_ids,
            }
            values.update(changes)
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    SessionSecuritySettings(**values)


class DurableRateDecisionTransportTests(unittest.TestCase):
    def test_only_closed_rate_decision_can_emit_retry_after(self) -> None:
        for invalid in (True, 0, -1, 86401, "5"):
            with self.subTest(invalid=invalid):
                with self.assertRaises((TypeError, ValueError)):
                    RateLimitExceeded(invalid)  # type: ignore[arg-type]

        fixture = make_http_fixture()

        class ClosedLimiter:
            def require_allowed(self, *, operation_id, actor):
                del operation_id, actor
                raise RateLimitExceeded(17)

        transport = IamHttpTransport(
            dispatcher=fixture.dispatcher,
            session_authenticator=fixture.session_authenticator,
            origin_policy=fixture.origin_policy,
            csrf_verifier=fixture.csrf_verifier,
            rate_limiter=ClosedLimiter(),
            telemetry=fixture.telemetry,
            trace_id_source=FixedTraceIdSource(),
        )
        response = transport.handle(request_for("getMe"))
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response_json(response)["code"], "RATE_LIMITED")
        self.assertEqual(response_header_values(response, "retry-after"), ("17",))

        fixture2 = make_http_fixture()
        fixture2.rate_limiter.reject = True
        generic = fixture2.transport.handle(request_for("getMe"))
        self.assertEqual(generic.status_code, 429)
        self.assertEqual(response_header_values(generic, "retry-after"), ())


if __name__ == "__main__":
    unittest.main()
