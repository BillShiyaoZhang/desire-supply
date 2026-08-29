"""TEST-HTTP-IAM-001 ASGI streaming, disconnect, timeout and unknown-outcome RED."""

from __future__ import annotations

from dataclasses import replace
import json
import unittest

from desire_platform.http import IamAsgiApplication
from desire_platform.identity_access.domain.errors import IamError
from tests.support.iam_http_transport_builders import (
    SENSITIVE_SENTINEL,
    make_http_fixture,
    replace_header,
    request_for,
    run_asgi,
)


class IamAsgiBoundaryRedTest(unittest.TestCase):
    def test_multichunk_json_is_bounded_then_dispatched_once(self) -> None:
        fixture = make_http_fixture()
        request = request_for("inspectAccessInvitation")
        split = len(request.body) // 3
        chunks = (
            request.body[:split],
            request.body[split : split * 2],
            request.body[split * 2 :],
        )
        result = run_asgi(IamAsgiApplication(fixture.transport), request, chunks=chunks)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.receive_calls, 3)
        self.assertEqual(len(fixture.dispatcher.calls), 1)
        self.assertEqual(
            fixture.dispatcher.calls[0].operation_id,
            "inspectAccessInvitation",
        )

    def test_limit_plus_one_stops_stream_and_never_dispatches(self) -> None:
        fixture = make_http_fixture()
        request = request_for("beginOidcAuthorization")
        oversized = b'{"return_to":"/' + b"x" * 9000 + b'"}'
        request = replace_header(
            replace(request, body=oversized),
            b"content-length",
            str(len(oversized)).encode("ascii"),
        )
        result = run_asgi(
            IamAsgiApplication(fixture.transport),
            request,
            chunks=(oversized[:4096], oversized[4096:8193], oversized[8193:]),
        )
        self.assertEqual(result.status_code, 400)
        payload = json.loads(result.body)
        self.assertEqual(payload["code"], "INVALID_REQUEST")
        self.assertTrue(
            any(issue["code"] == "TOO_LARGE" for issue in payload["field_issues"])
        )
        self.assertEqual(fixture.dispatcher.calls, [])
        self.assertLessEqual(result.receive_calls, 2)

    def test_disconnect_before_complete_body_sends_nothing_and_does_not_dispatch(self) -> None:
        fixture = make_http_fixture()
        request = request_for("inspectAccessInvitation")
        result = run_asgi(
            IamAsgiApplication(fixture.transport),
            request,
            chunks=(request.body[:10],),
            disconnect_after_chunks=True,
        )
        self.assertEqual(result.messages, ())
        self.assertEqual(result.receive_calls, 2)
        self.assertEqual(fixture.dispatcher.calls, [])

    def test_receive_timeout_fails_closed_before_dispatch(self) -> None:
        fixture = make_http_fixture()
        request = request_for("inspectAccessInvitation")
        result = run_asgi(
            IamAsgiApplication(fixture.transport, request_timeout_seconds=0.001),
            request,
            receive_error=TimeoutError("synthetic receive deadline"),
        )
        self.assertEqual(result.receive_calls, 1)
        self.assertEqual(result.status_code, 503)
        payload = json.loads(result.body)
        self.assertEqual(payload["code"], "SERVICE_UNAVAILABLE")
        self.assertEqual(fixture.dispatcher.calls, [])

    def test_command_outcome_unknown_is_not_retried_or_reclassified(self) -> None:
        fixture = make_http_fixture()
        fixture.dispatcher.errors["acceptAccessInvitation"] = IamError(
            "COMMAND_OUTCOME_UNKNOWN"
        )
        request = request_for("acceptAccessInvitation")
        result = run_asgi(IamAsgiApplication(fixture.transport), request)
        self.assertEqual(result.status_code, 503)
        payload = json.loads(result.body)
        self.assertEqual(payload["code"], "COMMAND_OUTCOME_UNKNOWN")
        self.assertEqual(len(fixture.dispatcher.calls), 1)

    def test_secret_stream_and_internal_fault_never_reach_asgi_error(self) -> None:
        fixture = make_http_fixture()
        fixture.dispatcher.errors["inspectAccessInvitation"] = RuntimeError(
            SENSITIVE_SENTINEL
        )
        body = json.dumps(
            {"access_invitation_token": SENSITIVE_SENTINEL},
            separators=(",", ":"),
        ).encode("utf-8")
        request = request_for("inspectAccessInvitation")
        request = replace_header(
            replace(request, body=body),
            b"content-length",
            str(len(body)).encode("ascii"),
        )
        result = run_asgi(IamAsgiApplication(fixture.transport), request)
        self.assertEqual(result.status_code, 503)
        self.assertNotIn(SENSITIVE_SENTINEL.encode("ascii"), result.body)
        self.assertEqual(len(fixture.telemetry.events), 1)
        self.assertNotIn(SENSITIVE_SENTINEL, repr(fixture.telemetry.events))


if __name__ == "__main__":
    unittest.main()
