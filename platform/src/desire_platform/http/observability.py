"""Privacy-safe, low-cardinality observation for the shared ASGI boundary."""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any, Awaitable, Callable, Mapping, Optional


AsgiReceive = Callable[[], Awaitable[Mapping[str, Any]]]
AsgiSend = Callable[[Mapping[str, Any]], Awaitable[None]]

_METHODS = frozenset(("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"))
_OPERATIONS = frozenset(("IAM", "EDITOR", "TRUST", "APPEAL", "UNMATCHED"))
_STATUS_CLASSES = frozenset(("2XX", "3XX", "4XX", "5XX", "NO_RESPONSE"))
_OUTCOMES = frozenset(("SUCCEEDED", "REDIRECTED", "REJECTED", "FAILED", "NO_RESPONSE"))
_LATENCY_BUCKETS = frozenset(
    ("LT_10_MS", "LT_100_MS", "LT_1_S", "LT_10_S", "GTE_10_S", "UNAVAILABLE")
)

_IAM_EXACT_PATHS = frozenset(("/v1/me",))
_IAM_PATH_PREFIXES = (
    "/v1/auth/",
    "/v1/access-invitations/",
    "/v1/policy-bundles/",
    "/v1/me/",
    "/v1/organizations/",
    "/v1/memberships/",
    "/v1/platform/users/",
)


@dataclass(frozen=True)
class HttpBoundaryObservation:
    """One closed observation with no request, identity, or object data."""

    operation: str
    method: str
    status_class: str
    outcome: str
    latency_bucket: str

    def __post_init__(self) -> None:
        if self.operation not in _OPERATIONS:
            raise ValueError("HTTP observation operation is unavailable")
        if self.method not in _METHODS | {"OTHER"}:
            raise ValueError("HTTP observation method is unavailable")
        if self.status_class not in _STATUS_CLASSES:
            raise ValueError("HTTP observation status class is unavailable")
        if self.outcome not in _OUTCOMES:
            raise ValueError("HTTP observation outcome is unavailable")
        if self.latency_bucket not in _LATENCY_BUCKETS:
            raise ValueError("HTTP observation latency bucket is unavailable")


def _operation(path: Any) -> str:
    if not isinstance(path, str):
        return "UNMATCHED"
    if (
        path == "/v1/app/appeals"
        or path.startswith("/v1/app/appeals/")
        or path == "/v1/app/appeal-review"
        or path.startswith("/v1/app/appeal-review/")
    ):
        return "APPEAL"
    if path == "/v1/app/trust" or path.startswith("/v1/app/trust/"):
        return "TRUST"
    if path == "/v1/app" or path.startswith("/v1/app/"):
        return "EDITOR"
    if path in _IAM_EXACT_PATHS or any(
        path.startswith(prefix) for prefix in _IAM_PATH_PREFIXES
    ):
        return "IAM"
    return "UNMATCHED"


def _method(value: Any) -> str:
    return value if isinstance(value, str) and value in _METHODS else "OTHER"


def _status_class(status: Optional[int]) -> str:
    if status is None:
        return "NO_RESPONSE"
    return f"{status // 100}XX"


def _outcome(status: Optional[int], *, failed: bool) -> str:
    if failed:
        return "FAILED"
    if status is None:
        return "NO_RESPONSE"
    return {
        2: "SUCCEEDED",
        3: "REDIRECTED",
        4: "REJECTED",
        5: "FAILED",
    }[status // 100]


def _clock_value(source: Callable[[], float]) -> Optional[float]:
    try:
        value = source()
    except BaseException:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    result = float(value)
    return result if math.isfinite(result) else None


def _latency_bucket(start: Optional[float], end: Optional[float]) -> str:
    if start is None or end is None or end < start:
        return "UNAVAILABLE"
    elapsed = end - start
    if elapsed < 0.01:
        return "LT_10_MS"
    if elapsed < 0.1:
        return "LT_100_MS"
    if elapsed < 1.0:
        return "LT_1_S"
    if elapsed < 10.0:
        return "LT_10_S"
    return "GTE_10_S"


class ObservedAsgiApplication:
    """Record one bounded event around an already-authenticated BFF envelope.

    The observer sees only the normalized method, route family, response status
    class, and monotonic latency bucket. It never receives the ASGI scope,
    request/response bytes, headers, exception, trace ID, or actor/object IDs.
    """

    def __init__(
        self,
        *,
        application: Any,
        observer: Callable[[HttpBoundaryObservation], None],
        monotonic_seconds: Callable[[], float],
    ) -> None:
        if not callable(application):
            raise TypeError("observed ASGI application is unavailable")
        if not callable(observer):
            raise TypeError("HTTP boundary observer is unavailable")
        if not callable(monotonic_seconds):
            raise TypeError("HTTP observation clock is unavailable")
        self._application = application
        self._observer = observer
        self._monotonic_seconds = monotonic_seconds

    @property
    def application(self) -> Any:
        return self._application

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if not isinstance(scope, dict) or scope.get("type") != "http":
            await self._application(scope, receive, send)
            return

        operation = _operation(scope.get("path"))
        method = _method(scope.get("method"))
        start = _clock_value(self._monotonic_seconds)
        status: Optional[int] = None
        failed = False

        async def observe_start(message: Any) -> None:
            nonlocal status
            if (
                status is None
                and isinstance(message, dict)
                and message.get("type") == "http.response.start"
            ):
                candidate = message.get("status")
                if (
                    type(candidate) is int
                    and 200 <= candidate <= 599
                ):
                    status = candidate
            await send(message)

        try:
            await self._application(scope, receive, observe_start)
        except BaseException:
            failed = True
            raise
        finally:
            end = _clock_value(self._monotonic_seconds)
            event = HttpBoundaryObservation(
                operation=operation,
                method=method,
                status_class=_status_class(status),
                outcome=_outcome(status, failed=failed),
                latency_bucket=_latency_bucket(start, end),
            )
            try:
                self._observer(event)
            except BaseException:
                # HTTP logs are operational telemetry, never an Audit source or
                # a reason to change an otherwise valid application response.
                pass


__all__ = ["HttpBoundaryObservation", "ObservedAsgiApplication"]
