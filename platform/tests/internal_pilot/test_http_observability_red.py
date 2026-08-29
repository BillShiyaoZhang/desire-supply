from __future__ import annotations

import io
import json
import unittest
from dataclasses import asdict
from typing import Any

from desire_platform.http.observability import (
    ObservedAsgiApplication,
)
from desire_platform.internal_pilot.runtime_adapters import JsonLineHttpTelemetry


class _Clock:
    def __init__(self, *values: float) -> None:
        self._values = iter(values)

    def __call__(self) -> float:
        return next(self._values)


class _ResponseApplication:
    def __init__(self, status: int = 204, body: bytes = b"") -> None:
        self.status = status
        self.body = body
        self.scopes: list[dict[str, Any]] = []

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        del receive
        self.scopes.append(scope)
        await send(
            {
                "type": "http.response.start",
                "status": self.status,
                "headers": [
                    (b"content-length", str(len(self.body)).encode("ascii"))
                ],
            }
        )
        await send({"type": "http.response.body", "body": self.body})


class _FailingApplication:
    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        del scope, receive, send
        raise RuntimeError("cookie=secret-session object=private-id")


def _scope(
    path: str,
    *,
    method: str = "GET",
    query: bytes = b"",
    headers: list[tuple[bytes, bytes]] | None = None,
) -> dict[str, Any]:
    return {
        "type": "http",
        "method": method,
        "scheme": "https",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": query,
        "headers": headers or [],
    }


async def _invoke(application: Any, scope: dict[str, Any]) -> list[dict[str, Any]]:
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    await application(scope, receive, send)
    return sent


class PrivacySafeHttpObservationTests(unittest.IsolatedAsyncioTestCase):
    async def test_emits_one_closed_low_cardinality_event_without_request_data(
        self,
    ) -> None:
        stream = io.StringIO()
        delegate = _ResponseApplication(
            status=204,
            body=b'{"private_response":"private-response"}',
        )
        telemetry = JsonLineHttpTelemetry(stream=stream)
        application = ObservedAsgiApplication(
            application=delegate,
            observer=telemetry.record_boundary,
            monotonic_seconds=_Clock(100.0, 100.023),
        )
        private_id = "30000000-0000-4000-8000-000000000003"
        sent = await _invoke(
            application,
            _scope(
                f"/v1/app/appeal-review/history/{private_id}",
                method="GET",
                query=b"token=private-query",
                headers=[
                    (b"cookie", b"__Host-desire_session=private-session"),
                    (b"authorization", b"Bearer private-token"),
                ],
            ),
        )

        self.assertEqual(sent[0]["status"], 204)
        self.assertEqual(
            json.loads(stream.getvalue()),
            {
                "component": "INTERNAL_SANDBOX_API",
                "event_type": "HTTP_BOUNDARY_OBSERVATION_V1",
                "latency_bucket": "LT_100_MS",
                "method": "GET",
                "operation": "APPEAL",
                "outcome": "SUCCEEDED",
                "status_class": "2XX",
            },
        )
        rendered = stream.getvalue()
        for forbidden in (
            private_id,
            "private-query",
            "private-session",
            "private-token",
            "private-response",
            "cookie",
            "authorization",
            "/v1/app/appeal-review",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, rendered)

    async def test_route_families_methods_and_statuses_are_closed(self) -> None:
        cases = (
            ("/v1/me", "GET", 302, "IAM", "GET", "3XX", "REDIRECTED"),
            ("/v1/app/profiles/private", "PATCH", 400, "EDITOR", "PATCH", "4XX", "REJECTED"),
            ("/v1/app/trust/cases/private", "PUT", 503, "TRUST", "PUT", "5XX", "FAILED"),
            ("/v1/app/appeals/private", "DELETE", 200, "APPEAL", "DELETE", "2XX", "SUCCEEDED"),
            ("/not-reviewed/private", "BREW", 404, "UNMATCHED", "OTHER", "4XX", "REJECTED"),
        )
        for path, method, status, operation, observed_method, status_class, outcome in cases:
            with self.subTest(path=path, method=method, status=status):
                events: list[Any] = []
                application = ObservedAsgiApplication(
                    application=_ResponseApplication(status=status),
                    observer=events.append,
                    monotonic_seconds=_Clock(1.0, 1.0005),
                )
                await _invoke(application, _scope(path, method=method))
                self.assertEqual(len(events), 1)
                event = asdict(events[0])
                self.assertEqual(event["operation"], operation)
                self.assertEqual(event["method"], observed_method)
                self.assertEqual(event["status_class"], status_class)
                self.assertEqual(event["outcome"], outcome)
                self.assertEqual(event["latency_bucket"], "LT_10_MS")

    async def test_latency_bucket_boundaries_are_closed(self) -> None:
        cases = (
            (0.0, "LT_10_MS"),
            (0.009999, "LT_10_MS"),
            (0.01, "LT_100_MS"),
            (0.099999, "LT_100_MS"),
            (0.1, "LT_1_S"),
            (0.999999, "LT_1_S"),
            (1.0, "LT_10_S"),
            (9.999999, "LT_10_S"),
            (10.0, "GTE_10_S"),
            (-0.001, "UNAVAILABLE"),
        )
        for elapsed, expected in cases:
            with self.subTest(elapsed=elapsed):
                events: list[Any] = []
                application = ObservedAsgiApplication(
                    application=_ResponseApplication(),
                    observer=events.append,
                    monotonic_seconds=_Clock(0.0, elapsed),
                )
                await _invoke(application, _scope("/v1/app/demands"))
                self.assertEqual(events[0].latency_bucket, expected)

    async def test_unhandled_exception_is_classified_without_reflection(self) -> None:
        stream = io.StringIO()
        telemetry = JsonLineHttpTelemetry(stream=stream)
        application = ObservedAsgiApplication(
            application=_FailingApplication(),
            observer=telemetry.record_boundary,
            monotonic_seconds=_Clock(1.0, 12.0),
        )

        with self.assertRaisesRegex(RuntimeError, "private-id"):
            await _invoke(application, _scope("/v1/app/trust/cases/private"))

        self.assertEqual(
            json.loads(stream.getvalue()),
            {
                "component": "INTERNAL_SANDBOX_API",
                "event_type": "HTTP_BOUNDARY_OBSERVATION_V1",
                "latency_bucket": "GTE_10_S",
                "method": "GET",
                "operation": "TRUST",
                "outcome": "FAILED",
                "status_class": "NO_RESPONSE",
            },
        )
        self.assertNotIn("secret-session", stream.getvalue())
        self.assertNotIn("private-id", stream.getvalue())

    async def test_observer_failure_never_changes_the_http_result(self) -> None:
        def fail(_event: Any) -> None:
            raise OSError("logging destination unavailable")

        application = ObservedAsgiApplication(
            application=_ResponseApplication(status=201),
            observer=fail,
            monotonic_seconds=_Clock(1.0, 1.1),
        )

        sent = await _invoke(application, _scope("/v1/app/demands", method="POST"))

        self.assertEqual(sent[0]["status"], 201)

    async def test_lifespan_is_forwarded_without_observation(self) -> None:
        scopes: list[dict[str, Any]] = []
        events: list[Any] = []

        async def delegate(scope: dict[str, Any], receive: Any, send: Any) -> None:
            del receive, send
            scopes.append(scope)

        application = ObservedAsgiApplication(
            application=delegate,
            observer=events.append,
            monotonic_seconds=lambda: 1.0,
        )
        scope = {"type": "lifespan"}

        await application(scope, None, None)

        self.assertEqual(scopes, [scope])
        self.assertEqual(events, [])


if __name__ == "__main__":
    unittest.main()
