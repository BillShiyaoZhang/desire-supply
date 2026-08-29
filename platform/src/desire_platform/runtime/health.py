"""Minimal ASGI liveness and readiness boundary for a composed runtime."""

import asyncio
import json
from typing import Any, Dict, Tuple

from .composition import RuntimeHandle, RuntimeState


_HEALTH_PATHS = frozenset(("/health/live", "/health/ready"))
_HEALTH_METHODS = frozenset(("GET", "HEAD"))


class RuntimeHealthApplication:
    """Serve infrastructure health routes and delegate all product traffic."""

    def __init__(
        self,
        *,
        application: Any,
        runtime: RuntimeHandle,
        readiness_timeout_ms: int,
    ) -> None:
        if not callable(application):
            raise TypeError("runtime application is unavailable")
        if not isinstance(runtime, RuntimeHandle):
            raise TypeError("runtime handle is unavailable")
        if type(readiness_timeout_ms) is not int or readiness_timeout_ms <= 0:
            raise TypeError("readiness timeout is unavailable")
        self._application = application
        self._runtime = runtime
        self._readiness_timeout_ms = readiness_timeout_ms

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        path = scope.get("path")
        if scope.get("type") != "http" or path not in _HEALTH_PATHS:
            await self._application(scope, receive, send)
            return

        method = scope.get("method")
        if method not in _HEALTH_METHODS:
            await self._respond(
                send,
                method=method,
                status_code=405,
                status="METHOD_NOT_ALLOWED",
                extra_headers=((b"allow", b"GET, HEAD"),),
            )
            return

        if path == "/health/live":
            live = self._runtime.state not in (
                RuntimeState.STOPPING,
                RuntimeState.CLOSED,
            )
            await self._respond(
                send,
                method=method,
                status_code=200 if live else 503,
                status="LIVE" if live else "NOT_LIVE",
            )
            return

        ready = await asyncio.to_thread(
            self._runtime.check_readiness,
            self._readiness_timeout_ms,
        )
        await self._respond(
            send,
            method=method,
            status_code=200 if ready else 503,
            status="READY" if ready else "NOT_READY",
        )

    @staticmethod
    async def _respond(
        send: Any,
        *,
        method: Any,
        status_code: int,
        status: str,
        extra_headers: Tuple[Tuple[bytes, bytes], ...] = (),
    ) -> None:
        body = json.dumps(
            {"status": status},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        headers = (
            (b"content-type", b"application/json"),
            (b"cache-control", b"no-store"),
            (b"content-length", str(len(body)).encode("ascii")),
        ) + extra_headers
        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": list(headers),
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": b"" if method == "HEAD" else body,
            }
        )
