"""TEST-HTTP-IAM-001 semantic RED for the framework-independent kernel."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
import io
import json
import logging
import unittest
from urllib.parse import quote

from desire_platform.http import (
    CookieMutation,
    CookieMutationKind,
    HttpHeader,
    HttpRequest,
    HttpResponse,
    IAM_HTTP_ROUTES,
    IamHttpOperationResult,
    IamHttpTransport,
)
from desire_platform.identity_access.domain.errors import IamError, IamPreconditionFailed
from desire_platform.identity_access.ports.read_models import ReadModelCursorClaims
from desire_platform.internal_pilot.runtime_crypto import (
    HmacIamReadCursorCodec,
    RuntimeKeyMaterial,
)
from tests.support.iam_http_transport_builders import (
    ALLOWED_ORIGIN,
    CSRF_TOKEN,
    OPENAPI_OPERATIONS,
    PROTOCOL_SECRET,
    SENSITIVE_SENTINEL,
    SESSION_HANDLE,
    freeze_json,
    make_http_fixture,
    operation_case,
    replace_header,
    replace_json_body,
    request_for,
    response_header_values,
    response_json,
)


class IamHttpTransportRedTest(unittest.TestCase):
    """Semantic failures must not be ImportError, fixture, or async harness errors."""

    def assert_error(self, response, status: int, code: str) -> None:
        self.assertEqual(response.status_code, status)
        payload = response_json(response)
        self.assertEqual(
            set(payload),
            {"code", "message", "trace_id", "field_issues"},
        )
        self.assertEqual(payload["code"], code)
        self.assertIsInstance(payload["message"], str)
        self.assertGreater(len(payload["message"]), 0)
        self.assertIsInstance(payload["trace_id"], str)
        self.assertEqual(payload["field_issues"], [])
        self.assertEqual(response_header_values(response, "cache-control"), ("no-store",))

    def test_route_registry_exactly_matches_all_openapi_operations(self) -> None:
        expected = {
            (case.method, case.path_template, case.operation_id)
            for case in OPENAPI_OPERATIONS
        }
        actual = {
            (route.method, route.path_template, route.operation.value)
            for route in IAM_HTTP_ROUTES
        }
        self.assertEqual(len(expected), 25)
        self.assertEqual(actual, expected)
        self.assertEqual(len(IAM_HTTP_ROUTES), len(actual))

    def test_raw_carriers_are_immutable_and_hidden_from_repr(self) -> None:
        request = HttpRequest(
            method="POST",
            scheme="https",
            path="/v1/access-invitations/inspect",
            raw_query_string=f"state={SENSITIVE_SENTINEL}".encode("ascii"),
            headers=(
                HttpHeader(
                    b"cookie",
                    f"__Host-ds_session={SENSITIVE_SENTINEL}".encode("ascii"),
                ),
            ),
            body=json.dumps(
                {"access_invitation_token": SENSITIVE_SENTINEL}
            ).encode("utf-8"),
        )
        rendered = repr(request)
        self.assertNotIn(SENSITIVE_SENTINEL, rendered)
        self.assertNotIn("cookie", rendered.casefold())
        self.assertNotIn("access_invitation_token", rendered)
        response = HttpResponse(
            status_code=200,
            headers=(
                HttpHeader(
                    b"set-cookie",
                    f"__Host-ds_session={SENSITIVE_SENTINEL}".encode("ascii"),
                ),
            ),
            body=SENSITIVE_SENTINEL.encode("ascii"),
        )
        self.assertNotIn(SENSITIVE_SENTINEL, repr(response))
        with self.assertRaises(FrozenInstanceError):
            request.path = "/changed"  # type: ignore[misc]

    def test_every_openapi_operation_reaches_exact_dispatcher_binding(self) -> None:
        for case in OPENAPI_OPERATIONS:
            with self.subTest(operation_id=case.operation_id):
                fixture = make_http_fixture()
                response = fixture.transport.handle(request_for(case.operation_id))
                self.assertEqual(response.status_code, case.success_status)
                self.assertEqual(len(fixture.dispatcher.calls), 1)
                self.assertEqual(
                    fixture.dispatcher.calls[0].operation_id,
                    case.operation_id,
                )

    def test_closed_json_minimal_full_unknown_type_and_size(self) -> None:
        valid_cases = (
            ("minimal", request_for("acceptAccessInvitation", full=False)),
            ("full", request_for("acceptAccessInvitation", full=True)),
        )
        for label, request in valid_cases:
            with self.subTest(case=label):
                fixture = make_http_fixture()
                response = fixture.transport.handle(request)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(len(fixture.dispatcher.calls), 1)

        base = request_for("acceptAccessInvitation")
        base_payload = json.loads(base.body)
        unknown_payload = dict(base_payload, actor_user_id="user_from_client")
        wrong_type_payload = dict(base_payload, policy_bundle_id=42)
        duplicate_key_body = (
            b'{"policy_bundle_id":"policy_bundle_0123456789abcdef",'
            b'"policy_bundle_id":"policy_bundle_other_0123456789",'
            b'"policy_acceptances":[],"consent_grants":[]}'
        )
        invalid_cases = (
            ("unknown", replace_json_body(base, unknown_payload)),
            ("type", replace_json_body(base, wrong_type_payload)),
            (
                "size",
                replace_header(
                    replace(
                        request_for("beginOidcAuthorization"),
                        body=(b'{"return_to":"/' + b"x" * 9000 + b'"}'),
                    ),
                    b"content-length",
                    str(9017).encode("ascii"),
                ),
            ),
            (
                "content_type",
                replace_header(base, b"content-type", b"text/plain"),
            ),
            (
                "duplicate_json_key",
                replace_header(
                    replace(base, body=duplicate_key_body),
                    b"content-length",
                    str(len(duplicate_key_body)).encode("ascii"),
                ),
            ),
            (
                "invalid_utf8",
                replace_header(
                    replace(base, body=b'{"policy_bundle_id":"\xff"}'),
                    b"content-length",
                    str(len(b'{"policy_bundle_id":"\xff"}')).encode("ascii"),
                ),
            ),
        )
        for label, request in invalid_cases:
            with self.subTest(case=label):
                fixture = make_http_fixture()
                response = fixture.transport.handle(request)
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response_json(response)["code"], "INVALID_REQUEST")
                self.assertEqual(fixture.dispatcher.calls, [])

    def test_public_name_body_is_exact_nfc_and_rejects_unicode_controls(self) -> None:
        base = request_for("updateOrganizationPublicName")
        valid = {
            "public_name": "Corrected Organization 😀",
            "reason_code": "PUBLIC_NAME_CORRECTION",
        }
        fixture = make_http_fixture()
        response = fixture.transport.handle(replace_json_body(base, valid))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(fixture.dispatcher.calls), 1)

        invalid_bodies = (
            {"reason_code": "PUBLIC_NAME_CORRECTION"},
            {"public_name": "Corrected Organization"},
            dict(valid, unexpected=True),
            dict(valid, public_name=" Leading"),
            dict(valid, public_name="Trailing "),
            dict(valid, public_name="Cafe\u0301"),
            dict(valid, public_name="Line\nBreak"),
            dict(valid, public_name="Hidden\u200dFormat"),
            dict(valid, public_name="A" * 161),
            dict(valid, reason_code="OTHER"),
        )
        for body in invalid_bodies:
            with self.subTest(body=body):
                fixture = make_http_fixture()
                response = fixture.transport.handle(replace_json_body(base, body))
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response_json(response)["code"], "INVALID_REQUEST")
                self.assertEqual(fixture.dispatcher.calls, [])

    def test_header_query_cookie_path_and_method_ambiguity_fail_before_handler(self) -> None:
        base = request_for("acceptAccessInvitation")
        cases = (
            ("missing_idempotency", replace_header(base, b"idempotency-key", None), 400),
            ("weak_if_match", replace_header(base, b"if-match", b'W/"v1"'), 400),
            ("missing_csrf", replace_header(base, b"x-csrf-token", None), 400),
            (
                "duplicate_cookie",
                replace_header(
                    base,
                    b"cookie",
                    f"__Host-ds_session={SESSION_HANDLE}".encode("ascii"),
                    append=True,
                ),
                400,
            ),
            (
                "unknown_query",
                replace(request_for("listMySessions"), raw_query_string=b"limit=20&actor_id=other"),
                400,
            ),
            (
                "invalid_path_id",
                replace(base, path="/v1/access-invitations/short/accept"),
                404,
            ),
            ("trailing_slash", replace(base, path=base.path + "/"), 404),
            (
                "get_with_body",
                replace_json_body(request_for("getMe"), {"unexpected": True}),
                400,
            ),
        )
        for label, request, expected_status in cases:
            with self.subTest(case=label):
                fixture = make_http_fixture()
                response = fixture.transport.handle(request)
                self.assertEqual(response.status_code, expected_status)
                self.assertEqual(fixture.dispatcher.calls, [])

    def test_real_signed_cursor_with_one_dot_reaches_both_organization_lists(self) -> None:
        now = datetime(2026, 8, 16, 2, 0, tzinfo=timezone.utc)
        codec = HmacIamReadCursorCodec(
            keys=(
                RuntimeKeyMaterial(
                    purpose="IAM_READ_CURSOR",
                    key_id="iam-read-cursor-v1",
                    material=bytearray(b"c" * 32),
                ),
            ),
            active_key_id="iam-read-cursor-v1",
        )
        cursor = codec.encode(
            ReadModelCursorClaims(
                version="iam-read-cursor-v1",
                key_id=codec.active_key_id,
                operation_id="listOrganizationMemberships",
                actor_user_id="10000000-0000-4000-8000-000000000001",
                organization_id="20000000-0000-4000-8000-000000000002",
                page_limit=25,
                query_shape_digest="a" * 64,
                snapshot_at=now,
                after_created_at=now - timedelta(seconds=1),
                after_id="30000000-0000-4000-8000-000000000003",
                issued_at=now,
                expires_at=now + timedelta(minutes=15),
            )
        )
        self.assertEqual(cursor.count("."), 1)
        for operation_id in (
            "listOrganizationMemberships",
            "listOrganizationAccessInvitations",
        ):
            with self.subTest(operation_id=operation_id):
                fixture = make_http_fixture()
                request = replace(
                    request_for(operation_id),
                    raw_query_string=(
                        "cursor=" + quote(cursor, safe="") + "&limit=25"
                    ).encode("ascii"),
                )
                response = fixture.transport.handle(request)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(len(fixture.dispatcher.calls), 1)
                self.assertIn(
                    ("cursor", cursor),
                    fixture.dispatcher.calls[0].query_parameters,
                )

    def test_oidc_callback_optionally_binds_only_an_authenticated_old_session(self) -> None:
        base = request_for("completeOidcAuthorization")
        combined = replace_header(
            base,
            b"cookie",
            (
                "__Host-ds_oidc=" + PROTOCOL_SECRET + "; "
                "__Host-ds_session=" + SESSION_HANDLE
            ).encode("ascii"),
        )
        fixture = make_http_fixture()
        response = fixture.transport.handle(combined)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(
            fixture.session_authenticator.calls,
            [(SESSION_HANDLE, "trace_http_test_0123456789")],
        )
        invocation = fixture.dispatcher.calls[0]
        self.assertIsNone(invocation.actor)
        self.assertEqual(invocation.raw_session_handle, SESSION_HANDLE)
        self.assertEqual(invocation.raw_oidc_browser_cookie, PROTOCOL_SECRET)

        expired = make_http_fixture()
        expired.session_authenticator.error_code = "SESSION_EXPIRED"
        expired_response = expired.transport.handle(combined)
        self.assertEqual(expired_response.status_code, 303)
        self.assertEqual(len(expired.dispatcher.calls), 1)
        self.assertIsNone(expired.dispatcher.calls[0].raw_session_handle)

    def test_authentication_optional_session_and_rate_limit_matrix(self) -> None:
        required = request_for("getMe")
        auth_cases = (
            (
                "missing_session",
                replace_header(required, b"cookie", None),
                None,
                401,
                "AUTHENTICATION_REQUIRED",
            ),
            (
                "expired_session",
                required,
                "SESSION_EXPIRED",
                401,
                "SESSION_EXPIRED",
            ),
        )
        for label, request, auth_error, status, code in auth_cases:
            with self.subTest(case=label):
                fixture = make_http_fixture()
                fixture.session_authenticator.error_code = auth_error
                response = fixture.transport.handle(request)
                self.assertEqual(response.status_code, status)
                self.assertEqual(response_json(response)["code"], code)
                self.assertEqual(fixture.dispatcher.calls, [])

        with self.subTest(case="optional_invalid_session_becomes_anonymous"):
            fixture = make_http_fixture()
            request = replace_header(
                request_for("beginOidcAuthorization"),
                b"cookie",
                b"__Host-ds_session=invalid_but_not_logged",
            )
            response = fixture.transport.handle(request)
            self.assertEqual(response.status_code, 201)
            self.assertEqual(len(fixture.dispatcher.calls), 1)

        with self.subTest(case="anonymous_inspect_ignores_session_cookie"):
            fixture = make_http_fixture()
            request = replace_header(
                request_for("inspectAccessInvitation"),
                b"cookie",
                f"__Host-ds_session={SESSION_HANDLE}".encode("ascii"),
            )
            response = fixture.transport.handle(request)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(fixture.session_authenticator.calls, [])

        with self.subTest(case="anonymous_rate_limited"):
            fixture = make_http_fixture()
            fixture.rate_limiter.reject = True
            response = fixture.transport.handle(request_for("inspectAccessInvitation"))
            self.assertEqual(response.status_code, 429)
            self.assertEqual(response_json(response)["code"], "RATE_LIMITED")
            self.assertEqual(fixture.dispatcher.calls, [])

    def test_origin_csrf_and_cors_are_enforced_before_dispatch(self) -> None:
        base = request_for("acceptAccessInvitation")
        cases = (
            ("valid", base, 200, True),
            ("missing_origin", replace_header(base, b"origin", None), 400, False),
            (
                "cross_origin",
                replace_header(base, b"origin", b"https://evil.example.test"),
                400,
                False,
            ),
            (
                "wrong_csrf",
                replace_header(base, b"x-csrf-token", b"wrong_csrf_0123456789abcdef"),
                400,
                False,
            ),
        )
        for label, request, expected_status, dispatched in cases:
            with self.subTest(case=label):
                fixture = make_http_fixture()
                response = fixture.transport.handle(request)
                self.assertEqual(response.status_code, expected_status)
                self.assertEqual(bool(fixture.dispatcher.calls), dispatched)
                if label == "valid":
                    self.assertEqual(
                        response_header_values(response, "access-control-allow-origin"),
                        (ALLOWED_ORIGIN,),
                    )

        with self.subTest(case="preflight"):
            fixture = make_http_fixture()
            request = HttpRequest(
                method="OPTIONS",
                scheme="https",
                path=base.path,
                headers=(
                    HttpHeader(b"origin", ALLOWED_ORIGIN.encode("ascii")),
                    HttpHeader(b"access-control-request-method", b"POST"),
                    HttpHeader(
                        b"access-control-request-headers",
                        b"content-type,idempotency-key,if-match,x-csrf-token",
                    ),
                ),
            )
            response = fixture.transport.handle(request)
            self.assertEqual(response.status_code, 204)
            self.assertEqual(fixture.dispatcher.calls, [])

    def test_stable_application_error_codes_map_to_closed_status_envelopes(self) -> None:
        cases = (
            ("AUTHENTICATION_REQUIRED", 401),
            ("SAFETY_HOLD_BLOCKED", 403),
            ("RESOURCE_NOT_FOUND", 404),
            ("IDEMPOTENCY_KEY_REUSED", 409),
            ("PRECONDITION_FAILED", 412),
            ("RATE_LIMITED", 429),
            ("IDENTITY_PROVIDER_UNAVAILABLE", 503),
        )
        for code, status in cases:
            with self.subTest(code=code):
                fixture = make_http_fixture()
                fixture.dispatcher.errors["getMe"] = IamError(code)
                response = fixture.transport.handle(request_for("getMe"))
                self.assert_error(response, status, code)
                self.assertEqual(len(fixture.dispatcher.calls), 1)

    def test_typed_stale_precondition_alone_carries_current_etag(self) -> None:
        fixture = make_http_fixture()
        fixture.dispatcher.errors["updateOrganizationPublicName"] = (
            IamPreconditionFailed('"v8"')
        )
        response = fixture.transport.handle(
            request_for("updateOrganizationPublicName")
        )
        self.assert_error(response, 412, "PRECONDITION_FAILED")
        self.assertEqual(response_header_values(response, "etag"), ('"v8"',))

        fixture = make_http_fixture()
        fixture.dispatcher.errors["updateOrganizationPublicName"] = IamError(
            "PRECONDITION_FAILED"
        )
        response = fixture.transport.handle(
            request_for("updateOrganizationPublicName")
        )
        self.assert_error(response, 412, "PRECONDITION_FAILED")
        self.assertEqual(response_header_values(response, "etag"), ())

        for invalid in ('W/"v8"', '"v0"', "v8"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    IamPreconditionFailed(invalid)

    def test_unknown_route_method_and_missing_binding_remain_distinct(self) -> None:
        cases = (
            (
                "unknown_path",
                HttpRequest(method="GET", scheme="https", path="/v1/not-a-route"),
                404,
                "RESOURCE_NOT_FOUND",
            ),
            (
                "unknown_method",
                replace(request_for("getMe"), method="PUT"),
                404,
                "RESOURCE_NOT_FOUND",
            ),
        )
        fixture = make_http_fixture()
        for label, request, status, code in cases:
            with self.subTest(case=label):
                response = fixture.transport.handle(request)
                self.assert_error(response, status, code)

        with self.subTest(case="registered_but_unbound"):
            response = IamHttpTransport().handle(request_for("getMe"))
            self.assert_error(response, 503, "SERVICE_UNAVAILABLE")

    def test_accept_rotation_set_cookie_and_completed_receipt_replay(self) -> None:
        raw_successor = "successor_session_0123456789abcdefghijkl"
        first = make_http_fixture()
        first.dispatcher.results["acceptAccessInvitation"] = IamHttpOperationResult(
            status_code=200,
            json_body=freeze_json(
                {
                    "invitation_id": "invitation_0123456789abcdef",
                    "status": "ACCEPTED",
                }
            ),
            entity_tag='"v2"',
            cookie_mutations=(
                CookieMutation(CookieMutationKind.SET_SESSION, raw_successor),
            ),
            replayed=False,
        )
        first_response = first.transport.handle(request_for("acceptAccessInvitation"))
        self.assertEqual(first_response.status_code, 200)
        first_cookies = response_header_values(first_response, "set-cookie")
        self.assertEqual(len(first_cookies), 1)
        self.assertIn(f"__Host-ds_session={raw_successor}", first_cookies[0])
        for required_flag in ("Secure", "HttpOnly", "SameSite=Lax", "Path=/"):
            self.assertIn(required_flag, first_cookies[0])
        self.assertEqual(response_header_values(first_response, "etag"), ('"v2"',))
        self.assertEqual(response_header_values(first_response, "cache-control"), ("no-store",))

        replay = make_http_fixture()
        replay.dispatcher.results["acceptAccessInvitation"] = IamHttpOperationResult(
            status_code=200,
            json_body=first.dispatcher.results["acceptAccessInvitation"].json_body,
            entity_tag='"v2"',
            cookie_mutations=(),
            replayed=True,
        )
        replay_response = replay.transport.handle(request_for("acceptAccessInvitation"))
        self.assertEqual(replay_response.status_code, 200)
        self.assertEqual(response_header_values(replay_response, "set-cookie"), ())
        self.assertNotIn(raw_successor, replay_response.body.decode("utf-8"))

    def test_no_store_etag_and_public_immutable_cache_are_operation_scoped(self) -> None:
        cases = (
            ("getMe", 200, "no-store", '"v1"'),
            (
                "getPolicyBundle",
                200,
                "public, max-age=31536000, immutable",
                None,
            ),
        )
        for operation_id, status, cache_control, etag in cases:
            with self.subTest(operation_id=operation_id):
                fixture = make_http_fixture()
                response = fixture.transport.handle(request_for(operation_id))
                self.assertEqual(response.status_code, status)
                self.assertEqual(
                    response_header_values(response, "cache-control"),
                    (cache_control,),
                )
                if etag is not None:
                    self.assertEqual(response_header_values(response, "etag"), (etag,))

    def test_secret_sentinel_never_enters_error_or_telemetry(self) -> None:
        fixture = make_http_fixture()
        fixture.dispatcher.errors["inspectAccessInvitation"] = RuntimeError(
            SENSITIVE_SENTINEL
        )
        request = replace_json_body(
            request_for("inspectAccessInvitation"),
            {"access_invitation_token": SENSITIVE_SENTINEL},
        )
        request = replace_header(
            request,
            b"cookie",
            f"unrelated={SENSITIVE_SENTINEL}".encode("ascii"),
        )
        log_stream = io.StringIO()
        log_handler = logging.StreamHandler(log_stream)
        root_logger = logging.getLogger()
        root_logger.addHandler(log_handler)
        try:
            response = fixture.transport.handle(request)
        finally:
            root_logger.removeHandler(log_handler)
        self.assert_error(response, 503, "SERVICE_UNAVAILABLE")
        observed = repr(response) + repr(fixture.telemetry.events) + log_stream.getvalue()
        self.assertNotIn(SENSITIVE_SENTINEL, observed)
        self.assertNotIn(SENSITIVE_SENTINEL, repr(request))
        self.assertEqual(len(fixture.telemetry.events), 1)
        event = fixture.telemetry.events[0]
        self.assertEqual(event.operation_id, "inspectAccessInvitation")
        self.assertEqual(event.error_code, "SERVICE_UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
