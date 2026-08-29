from __future__ import annotations

import asyncio
import json
import threading
import time
import unittest
from dataclasses import dataclass, replace
from typing import Any, Awaitable, Callable

from desire_platform.http import HttpHeader, IamAsgiApplication, IamHttpTransport
from tests.support.iam_http_transport_builders import (
    make_http_fixture,
    replace_header,
    request_for,
)


_MISSING = object()


@dataclass(frozen=True)
class _AsgiProbe:
    messages: tuple[dict[str, Any], ...]
    receive_calls: int
    send_calls: int
    exception: BaseException | None

    @property
    def status_code(self) -> int | None:
        for message in self.messages:
            if message.get("type") == "http.response.start":
                return int(message["status"])
        return None

    @property
    def json_body(self) -> dict[str, Any]:
        body = b"".join(
            message.get("body", b"")
            for message in self.messages
            if message.get("type") == "http.response.body"
        )
        return json.loads(body.decode("utf-8")) if body else {}


def _scope_for(
    request: Any,
    *,
    path: str | None = None,
    raw_path: bytes | object = _MISSING,
) -> dict[str, Any]:
    resolved_path = request.path if path is None else path
    scope: dict[str, Any] = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.5"},
        "http_version": "1.1",
        "scheme": request.scheme,
        "method": request.method,
        "path": resolved_path,
        "query_string": request.raw_query_string,
        "headers": tuple((header.name, header.value) for header in request.headers),
        "client": ("203.0.113.44", 43110),
        "server": ("api.example.test", 443),
    }
    if raw_path is _MISSING:
        scope["raw_path"] = request.path.encode("ascii")
    elif raw_path is not None:
        scope["raw_path"] = raw_path
    return scope


def _run_asgi(
    application: IamAsgiApplication,
    request: Any,
    *,
    scope: dict[str, Any] | None = None,
    receive_messages: tuple[dict[str, Any], ...] | None = None,
    send_fail_at: int | None = None,
) -> _AsgiProbe:
    inbound = list(
        receive_messages
        or (
            {
                "type": "http.request",
                "body": request.body,
                "more_body": False,
            },
        )
    )
    outbound: list[dict[str, Any]] = []
    receive_calls = 0
    send_calls = 0
    escaped: BaseException | None = None

    async def receive() -> dict[str, Any]:
        nonlocal receive_calls
        receive_calls += 1
        if inbound:
            return inbound.pop(0)
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        nonlocal send_calls
        send_calls += 1
        if send_fail_at == send_calls:
            raise OSError("synthetic downstream send failure")
        outbound.append(message)

    async def invoke() -> None:
        nonlocal escaped
        try:
            await application(scope or _scope_for(request), receive, send)
        except BaseException as exception:  # The RED asserts that nothing escapes.
            escaped = exception

    asyncio.run(invoke())
    return _AsgiProbe(
        messages=tuple(outbound),
        receive_calls=receive_calls,
        send_calls=send_calls,
        exception=escaped,
    )


class _BlockingDispatcher:
    def __init__(
        self,
        delegate: Any,
        *,
        delay_seconds: float,
        started: threading.Event | None = None,
    ) -> None:
        self._delegate = delegate
        self._delay_seconds = delay_seconds
        self._started = started
        self.calls: list[Any] = []

    def dispatch(self, invocation: Any) -> Any:
        self.calls.append(invocation)
        if self._started is not None:
            self._started.set()
        time.sleep(self._delay_seconds)
        return self._delegate.dispatch(invocation)


def _transport_with_dispatcher(fixture: Any, dispatcher: Any) -> IamHttpTransport:
    return IamHttpTransport(
        dispatcher=dispatcher,
        session_authenticator=fixture.session_authenticator,
        origin_policy=fixture.origin_policy,
        csrf_verifier=fixture.csrf_verifier,
        rate_limiter=fixture.rate_limiter,
        telemetry=fixture.telemetry,
    )


class IamHttpSecondRoundSecurityRedTests(unittest.TestCase):
    def test_huge_content_length_is_closed_before_receive_without_exception(self) -> None:
        fixture = make_http_fixture()
        request = replace_header(
            request_for("inspectAccessInvitation"),
            b"content-length",
            b"9" * 4_301,
        )

        probe = _run_asgi(IamAsgiApplication(fixture.transport), request)

        self.assertIsNone(probe.exception)
        self.assertEqual(probe.status_code, 400)
        self.assertEqual(probe.receive_calls, 0)
        self.assertEqual(fixture.dispatcher.calls, [])
        self.assertEqual(probe.json_body["code"], "INVALID_REQUEST")

    def test_transfer_encoding_and_cl_te_are_rejected_before_receive(self) -> None:
        for retain_content_length in (False, True):
            with self.subTest(retain_content_length=retain_content_length):
                fixture = make_http_fixture()
                request = request_for("inspectAccessInvitation")
                if not retain_content_length:
                    request = replace_header(request, b"content-length", None)
                request = replace_header(
                    request,
                    b"transfer-encoding",
                    b"chunked",
                )

                probe = _run_asgi(IamAsgiApplication(fixture.transport), request)

                self.assertIsNone(probe.exception)
                self.assertEqual(probe.status_code, 400)
                self.assertEqual(probe.receive_calls, 0)
                self.assertEqual(fixture.dispatcher.calls, [])
                self.assertEqual(probe.json_body["code"], "INVALID_REQUEST")

    def test_header_grammar_is_rejected_before_receive(self) -> None:
        base_request = request_for("inspectAccessInvitation")
        uppercase_origin = replace(
            base_request,
            headers=tuple(
                HttpHeader(
                    name=b"Origin" if header.name == b"origin" else header.name,
                    value=header.value,
                )
                for header in base_request.headers
            ),
        )
        controlled_origin = replace_header(
            base_request,
            b"origin",
            b"https://app.example.test\r\nx-injected: true",
        )

        for label, request in (
            ("uppercase-name", uppercase_origin),
            ("control-in-value", controlled_origin),
        ):
            with self.subTest(case=label):
                fixture = make_http_fixture()
                probe = _run_asgi(IamAsgiApplication(fixture.transport), request)

                self.assertIsNone(probe.exception)
                self.assertEqual(probe.status_code, 400)
                self.assertEqual(probe.receive_calls, 0)
                self.assertEqual(fixture.dispatcher.calls, [])
                self.assertEqual(fixture.session_authenticator.calls, [])

    def test_surrogate_path_is_a_stable_invalid_request_not_an_exception(self) -> None:
        fixture = make_http_fixture()
        request = request_for("getMe")
        scope = _scope_for(request, path="/v1/\ud800", raw_path=None)

        probe = _run_asgi(
            IamAsgiApplication(fixture.transport),
            request,
            scope=scope,
        )

        self.assertIsNone(probe.exception)
        self.assertEqual(probe.status_code, 400)
        self.assertEqual(probe.receive_calls, 0)
        self.assertEqual(fixture.dispatcher.calls, [])
        self.assertEqual(probe.json_body["code"], "INVALID_REQUEST")

    def test_synchronous_dispatch_is_inside_the_request_deadline(self) -> None:
        fixture = make_http_fixture()
        dispatcher = _BlockingDispatcher(
            fixture.dispatcher,
            delay_seconds=0.03,
        )
        transport = _transport_with_dispatcher(fixture, dispatcher)
        request = request_for("acceptAccessInvitation")

        probe = _run_asgi(
            IamAsgiApplication(transport, request_timeout_seconds=0.001),
            request,
        )

        self.assertIsNone(probe.exception)
        self.assertEqual(len(dispatcher.calls), 1)
        self.assertEqual(probe.status_code, 503)
        self.assertEqual(
            probe.json_body["code"],
            "COMMAND_OUTCOME_UNKNOWN",
        )

    def test_disconnect_after_dispatch_suppresses_the_response_without_retry(self) -> None:
        fixture = make_http_fixture()
        dispatch_started = threading.Event()
        dispatcher = _BlockingDispatcher(
            fixture.dispatcher,
            delay_seconds=0.03,
            started=dispatch_started,
        )
        transport = _transport_with_dispatcher(fixture, dispatcher)
        application = IamAsgiApplication(transport)
        request = request_for("acceptAccessInvitation")
        scope = _scope_for(request)
        outbound: list[dict[str, Any]] = []
        receive_calls = 0
        escaped: BaseException | None = None

        async def receive() -> dict[str, Any]:
            nonlocal receive_calls
            receive_calls += 1
            if receive_calls == 1:
                return {
                    "type": "http.request",
                    "body": request.body,
                    "more_body": False,
                }
            while not dispatch_started.is_set():
                await asyncio.sleep(0)
            return {"type": "http.disconnect"}

        async def send(message: dict[str, Any]) -> None:
            outbound.append(message)

        async def invoke() -> None:
            nonlocal escaped
            try:
                await application(scope, receive, send)
            except BaseException as exception:  # The RED asserts no escape.
                escaped = exception

        asyncio.run(invoke())

        self.assertIsNone(escaped)
        self.assertEqual(len(dispatcher.calls), 1)
        self.assertEqual(receive_calls, 2)
        self.assertEqual(outbound, [])

    def test_send_oserror_before_and_after_start_is_safely_contained(self) -> None:
        for send_fail_at in (1, 2):
            with self.subTest(send_fail_at=send_fail_at):
                fixture = make_http_fixture()
                request = request_for("inspectAccessInvitation")

                probe = _run_asgi(
                    IamAsgiApplication(fixture.transport),
                    request,
                    send_fail_at=send_fail_at,
                )

                self.assertIsNone(probe.exception)
                self.assertEqual(len(fixture.dispatcher.calls), 1)
                self.assertLessEqual(
                    sum(
                        message.get("type") == "http.response.start"
                        for message in probe.messages
                    ),
                    1,
                )


if __name__ == "__main__":
    unittest.main()
