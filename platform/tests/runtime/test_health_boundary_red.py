import asyncio
import json
import unittest
from typing import Any, Dict, List, Tuple

from desire_platform.runtime import RuntimeHandle, RuntimeState
from desire_platform.runtime.health import RuntimeHealthApplication


RAW_SECRET = "synthetic-health-secret-must-not-leak"


class _Resource:
    def __init__(self, label: str, events: List[str]) -> None:
        self.label = label
        self.events = events
        self.fail_readiness = False
        self.open_readiness_result: Any = None

    def check_readiness(self, timeout_ms: int) -> Any:
        self.events.append(f"ready:{self.label}:{timeout_ms}")
        if self.fail_readiness:
            raise RuntimeError(RAW_SECRET)
        return self.open_readiness_result

    def close(self) -> None:
        self.events.append(f"close:{self.label}")


class _Secret:
    def __init__(self, events: List[str]) -> None:
        self.events = events

    def destroy(self) -> None:
        self.events.append("destroy:secret")


class _Delegate:
    def __init__(self) -> None:
        self.scopes: List[Dict[str, Any]] = []

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        self.scopes.append(scope)
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})


def _handle() -> Tuple[RuntimeHandle, Dict[str, _Resource], List[str]]:
    events: List[str] = []
    resources = {
        "pool": _Resource("pool", events),
        "component": _Resource("component", events),
        "entrypoint": _Resource("entrypoint", events),
    }
    return (
        RuntimeHandle(
            entrypoint=resources["entrypoint"],
            components=(("component", resources["component"]),),
            pools=(("capability", resources["pool"]),),
            secrets=(_Secret(events),),
        ),
        resources,
        events,
    )


async def _request(
    application: Any,
    path: str,
    *,
    method: str = "GET",
    scope_type: str = "http",
) -> Tuple[int, List[Tuple[bytes, bytes]], bytes]:
    messages: List[Dict[str, Any]] = []

    async def receive() -> Dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Dict[str, Any]) -> None:
        messages.append(message)

    await application(
        {"type": scope_type, "path": path, "method": method},
        receive,
        send,
    )
    start = next(message for message in messages if message["type"] == "http.response.start")
    body = b"".join(
        message.get("body", b"")
        for message in messages
        if message["type"] == "http.response.body"
    )
    return start["status"], start["headers"], body


class RuntimeReadinessTests(unittest.TestCase):
    def test_rechecks_every_managed_resource_and_recovers_only_after_all_are_ready(self) -> None:
        handle, resources, events = _handle()

        self.assertTrue(handle.check_readiness(125))
        self.assertEqual(
            events,
            ["ready:pool:125", "ready:component:125", "ready:entrypoint:125"],
        )

        resources["component"].fail_readiness = True
        self.assertFalse(handle.check_readiness(125))
        self.assertEqual(handle.state, RuntimeState.FAILED)
        self.assertFalse(handle.ready)

        resources["component"].fail_readiness = False
        self.assertTrue(handle.check_readiness(125))
        self.assertEqual(handle.state, RuntimeState.READY)
        self.assertTrue(handle.ready)

    def test_open_or_invalid_readiness_result_fails_closed_without_leaking_details(self) -> None:
        handle, resources, _ = _handle()
        resources["entrypoint"].open_readiness_result = False

        self.assertFalse(handle.check_readiness(125))
        self.assertEqual(handle.state, RuntimeState.FAILED)
        self.assertNotIn(RAW_SECRET, repr(handle))

    def test_closed_runtime_cannot_become_ready_again(self) -> None:
        handle, _, events = _handle()
        handle.close()

        self.assertFalse(handle.check_readiness(125))
        self.assertEqual(handle.state, RuntimeState.CLOSED)
        self.assertEqual(
            events,
            [
                "close:entrypoint",
                "close:component",
                "close:pool",
                "destroy:secret",
            ],
        )


class RuntimeHealthApplicationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.handle, self.resources, self.events = _handle()
        self.delegate = _Delegate()
        self.application = RuntimeHealthApplication(
            application=self.delegate,
            runtime=self.handle,
            readiness_timeout_ms=125,
        )

    async def asyncTearDown(self) -> None:
        self.handle.close()

    async def test_live_ready_and_head_are_minimal_no_store_responses(self) -> None:
        status, headers, body = await _request(self.application, "/health/live")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"status": "LIVE"})
        self.assertIn((b"cache-control", b"no-store"), headers)

        status, _, body = await _request(self.application, "/health/ready")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"status": "READY"})
        self.assertEqual(
            self.events,
            ["ready:pool:125", "ready:component:125", "ready:entrypoint:125"],
        )

        status, _, body = await _request(
            self.application,
            "/health/ready",
            method="HEAD",
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, b"")

    async def test_dependency_failure_is_not_ready_but_remains_live_and_leaks_no_detail(self) -> None:
        self.resources["component"].fail_readiness = True
        status, _, body = await _request(self.application, "/health/ready")
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(body), {"status": "NOT_READY"})
        self.assertNotIn(RAW_SECRET.encode("ascii"), body)

        status, _, body = await _request(self.application, "/health/live")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"status": "LIVE"})

    async def test_closed_runtime_is_neither_live_nor_ready(self) -> None:
        self.handle.close()

        live_status, _, live_body = await _request(self.application, "/health/live")
        ready_status, _, ready_body = await _request(self.application, "/health/ready")
        self.assertEqual((live_status, json.loads(live_body)), (503, {"status": "NOT_LIVE"}))
        self.assertEqual((ready_status, json.loads(ready_body)), (503, {"status": "NOT_READY"}))

    async def test_non_health_scope_is_delegated_and_health_method_is_rejected(self) -> None:
        status, _, _ = await _request(self.application, "/projects")
        self.assertEqual(status, 204)
        self.assertEqual(self.delegate.scopes[-1]["path"], "/projects")

        status, headers, body = await _request(
            self.application,
            "/health/ready",
            method="POST",
        )
        self.assertEqual(status, 405)
        self.assertIn((b"allow", b"GET, HEAD"), headers)
        self.assertEqual(json.loads(body), {"status": "METHOD_NOT_ALLOWED"})

        status, _, _ = await _request(
            self.application,
            "/ignored",
            scope_type="websocket",
        )
        self.assertEqual(status, 204)
        self.assertEqual(self.delegate.scopes[-1]["type"], "websocket")


if __name__ == "__main__":
    unittest.main()
