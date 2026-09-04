"""Small concrete runtime adapters restricted to INTERNAL_SANDBOX."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import math
import secrets
import threading
import time
from typing import Any, Deque, Dict, Optional, TextIO, Tuple
from uuid import UUID, uuid4

from desire_platform.http.contracts import (
    AuthenticatedHttpActor,
    HttpTelemetryEvent,
    RateLimitExceeded,
)
from desire_platform.http.iam import IAM_HTTP_ROUTES
from desire_platform.http.observability import HttpBoundaryObservation


_OPERATIONS = frozenset(route.operation.value for route in IAM_HTTP_ROUTES)
_SECRET_PURPOSES = frozenset(
    (
        "oidc-state",
        "oidc-nonce",
        "oidc-pkce-verifier",
        "oidc-browser-binding",
        "bff-session-handle",
        "bff-csrf-salt",
        "access-invitation-nonce",
    )
)
_ID_PURPOSES = frozenset(
    (
        "auth_transaction",
        "security_audit_event",
        "exchange_owner",
        "user",
        "external_identity",
        "session_family",
        "session",
        "successor_session",
        "platform_user_command",
        "platform_user_correlation",
        "platform_user_trace",
        "platform_user_audit",
        "platform_user_outbox",
        "platform_user_session_event_namespace",
        "platform_duty_command",
        "platform_duty_correlation",
        "platform_duty_trace",
        "platform_duty_audit",
        "platform_duty_outbox",
        "platform_duty_session_event_namespace",
        "platform_duty_grant",
        "policy_consent_command",
        "policy_consent_acceptance",
        "policy_consent_audit",
        "policy_consent_outbox",
        "session-replay-security-event",
        "session-replay-audit-event",
        "session-replay-outbox-event",
        "access_invitation",
        "contact_point",
        "command_receipt",
        "policy_acceptance",
        "consent_grant",
        "membership",
        "membership_role_grant",
        "audit_event",
        "outbox_event",
        "membership_roles_revoked_outbox_event",
        "trust_command_receipt",
        "trust_audit_event",
        "trust_outbox_event",
        "safety_case",
        "safety_report",
        "trust_case_assignment",
        "trust_hold_release_assignment",
        "safety_hold",
        "trust_case_outcome_version",
        "trust_evidence_packet_version",
        "appeal",
        "appeal_audit_event",
        "appeal_command_receipt",
        "appeal_decision_version",
        "appeal_outbox_event",
        "appeal_review_assignment",
        "matching_command",
        "matching_command_receipt",
        "matching_fact",
        "matching_audit_event",
        "matching_outbox_event",
        "matching_review_assignment",
        "matching_candidate_selector_assignment",
        "matching_trust_hold_evidence",
        "matching_invitation",
        "matching_invitation_disclosure_snapshot",
        "matching_operational_command",
        "matching_operational_command_receipt",
        "matching_operational_audit_event",
    )
) | frozenset(f"matching_operational_outbox_event_{ordinal}" for ordinal in range(102))


@dataclass(frozen=True)
class InternalSandboxRateLimitSettings:
    window_seconds: int = 60
    authenticated_limit: int = 120
    anonymous_limit: int = 20
    maximum_buckets: int = 10_000

    def __post_init__(self) -> None:
        for value in (
            self.window_seconds,
            self.authenticated_limit,
            self.anonymous_limit,
            self.maximum_buckets,
        ):
            if type(value) is not int:
                raise TypeError("rate-limit values must be integers")
        if not 1 <= self.window_seconds <= 3_600:
            raise ValueError("rate-limit window is outside bounds")
        if not 1 <= self.authenticated_limit <= 10_000:
            raise ValueError("authenticated rate limit is outside bounds")
        if not 1 <= self.anonymous_limit <= 1_000:
            raise ValueError("anonymous rate limit is outside bounds")
        if not 1 <= self.maximum_buckets <= 100_000:
            raise ValueError("rate-limit bucket bound is outside bounds")


class InternalSandboxRateLimiter:
    """Bounded single-instance limiter; never an allow-all fallback.

    INTERNAL_SANDBOX currently has one API replica.  A multi-replica or
    CONTROLLED_PILOT deployment must replace this adapter with a durable,
    shared decision service before its composition can be considered closed.
    """

    def __init__(
        self,
        *,
        settings: InternalSandboxRateLimitSettings,
        clock: Any,
    ) -> None:
        if not isinstance(settings, InternalSandboxRateLimitSettings):
            raise TypeError("rate-limit settings are unavailable")
        if not callable(getattr(clock, "monotonic", None)):
            raise TypeError("rate-limit clock is unavailable")
        self._settings = settings
        self._clock = clock
        self._buckets: Dict[Tuple[str, str], Deque[float]] = {}
        self._closed = False
        self._lock = threading.RLock()

    def require_allowed(
        self,
        *,
        operation_id: str,
        actor: Optional[AuthenticatedHttpActor],
    ) -> None:
        if operation_id not in _OPERATIONS:
            raise RuntimeError("RATE_LIMIT_OPERATION_UNAVAILABLE")
        if actor is not None and not isinstance(actor, AuthenticatedHttpActor):
            raise RuntimeError("RATE_LIMIT_ACTOR_UNAVAILABLE")
        now = _monotonic(self._clock)
        identity = "anonymous" if actor is None else actor.actor_user_id
        key = (operation_id, identity)
        limit = (
            self._settings.anonymous_limit
            if actor is None
            else self._settings.authenticated_limit
        )
        with self._lock:
            if self._closed:
                raise RuntimeError("RATE_LIMITER_CLOSED")
            self._prune(now)
            bucket = self._buckets.get(key)
            if bucket is None:
                if len(self._buckets) >= self._settings.maximum_buckets:
                    raise RateLimitExceeded(self._settings.window_seconds)
                bucket = deque()
                self._buckets[key] = bucket
            if len(bucket) >= limit:
                retry = max(
                    1,
                    int(math.ceil(bucket[0] + self._settings.window_seconds - now)),
                )
                raise RateLimitExceeded(retry)
            bucket.append(now)

    def _prune(self, now: float) -> None:
        boundary = now - self._settings.window_seconds
        empty = []
        for key, bucket in self._buckets.items():
            while bucket and bucket[0] <= boundary:
                bucket.popleft()
            if not bucket:
                empty.append(key)
        for key in empty:
            del self._buckets[key]

    def check_readiness(self, *, timeout_ms: int) -> None:
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 30_000:
            raise ValueError("rate-limit readiness timeout is outside bounds")
        with self._lock:
            if self._closed:
                raise RuntimeError("RATE_LIMITER_CLOSED")
            _monotonic(self._clock)
            if len(self._buckets) > self._settings.maximum_buckets:
                raise RuntimeError("RATE_LIMITER_BOUND_EXCEEDED")
        return None

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._buckets.clear()

    def __repr__(self) -> str:
        with self._lock:
            return (
                "InternalSandboxRateLimiter("
                f"bucket_count={len(self._buckets)}, closed={self._closed})"
            )


class JsonLineHttpTelemetry:
    """Emit closed, already-redacted HTTP observation schemas as JSON Lines."""

    def __init__(self, *, stream: TextIO) -> None:
        if not callable(getattr(stream, "write", None)) or not callable(
            getattr(stream, "flush", None)
        ):
            raise TypeError("telemetry stream is unavailable")
        self._stream = stream
        self._closed = False
        self._failed = False
        self._lock = threading.RLock()

    def record(self, event: HttpTelemetryEvent) -> None:
        if not isinstance(event, HttpTelemetryEvent):
            raise TypeError("HTTP telemetry event is invalid")
        payload = {
            "authenticated": event.authenticated,
            "duration_bucket": event.duration_bucket,
            "error_code": event.error_code,
            "event_type": "IAM_HTTP_OBSERVATION_V1",
            "method": event.method,
            "operation_id": event.operation_id,
            "replayed": event.replayed,
            "request_size_bucket": event.request_size_bucket,
            "route_template": event.route_template,
            "status_code": event.status_code,
            "trace_id": event.trace_id,
        }
        self._write(payload)

    def record_boundary(self, event: HttpBoundaryObservation) -> None:
        if not isinstance(event, HttpBoundaryObservation):
            raise TypeError("HTTP boundary observation is invalid")
        self._write(
            {
                "component": "INTERNAL_SANDBOX_API",
                "event_type": "HTTP_BOUNDARY_OBSERVATION_V1",
                "latency_bucket": event.latency_bucket,
                "method": event.method,
                "operation": event.operation,
                "outcome": event.outcome,
                "status_class": event.status_class,
            }
        )

    def _write(self, payload: Dict[str, Any]) -> None:
        encoded = json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ) + "\n"
        with self._lock:
            if self._closed:
                raise RuntimeError("HTTP_TELEMETRY_CLOSED")
            try:
                self._stream.write(encoded)
                self._stream.flush()
            except Exception:
                self._failed = True
                raise RuntimeError("HTTP_TELEMETRY_UNAVAILABLE") from None

    def check_readiness(self, *, timeout_ms: int) -> None:
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 30_000:
            raise ValueError("telemetry readiness timeout is outside bounds")
        with self._lock:
            if self._closed or self._failed:
                raise RuntimeError("HTTP_TELEMETRY_UNAVAILABLE")
        return None

    def close(self) -> None:
        with self._lock:
            self._closed = True

    def __repr__(self) -> str:
        with self._lock:
            return (
                "JsonLineHttpTelemetry("
                f"closed={self._closed}, failed={self._failed}, stream=<redacted>)"
            )


class SecureRuntimeSources:
    """UTC/monotonic clock plus CSPRNG UUID/token sources with closed purposes."""

    def __init__(self) -> None:
        self.last_trace_id = ""

    @staticmethod
    def now() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def utc_now() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def monotonic() -> float:
        return time.monotonic()

    def new_trace_id(self) -> str:
        self.last_trace_id = str(uuid4())
        return self.last_trace_id

    @staticmethod
    def new_id(purpose: str) -> UUID:
        if purpose not in _ID_PURPOSES:
            raise ValueError("runtime ID purpose is unavailable")
        return uuid4()

    @staticmethod
    def token_bytes(purpose: str, length: int) -> bytes:
        if purpose not in _SECRET_PURPOSES or length != 32:
            raise ValueError("runtime secret purpose is unavailable")
        return secrets.token_bytes(length)


def _monotonic(clock: Any) -> float:
    try:
        value = clock.monotonic()
    except Exception:
        raise RuntimeError("monotonic clock is unavailable") from None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RuntimeError("monotonic clock is unavailable")
    result = float(value)
    if not math.isfinite(result):
        raise RuntimeError("monotonic clock is unavailable")
    return result


__all__ = [
    "InternalSandboxRateLimitSettings",
    "InternalSandboxRateLimiter",
    "JsonLineHttpTelemetry",
    "SecureRuntimeSources",
]
