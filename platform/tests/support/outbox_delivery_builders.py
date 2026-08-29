"""Strict, deterministic collaborators for outbox delivery semantic REDs.

These fakes model the documented port boundaries without making the production
worker green.  They use a lock and an injected UTC clock, never real sleep,
network, a process-global singleton, or IAM private storage.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import json
from threading import RLock
from typing import Iterable, Optional, Sequence

from desire_platform.outbox.delivery import (
    OutboxDeliveryCycleResult,
    OutboxDeliveryError,
    OutboxDeliveryErrorCode,
    OutboxDeliveryStatus,
    OutboxDeliveryWorker,
    OutboxEventEnvelope,
    OutboxLease,
    OutboxPublishAcknowledgement,
    OutboxTelemetryEvent,
    ValidatedOutboxMessage,
)


UTC_NOW = datetime(2026, 8, 8, 10, 0, tzinfo=timezone.utc)


class FixedUtcClock:
    def __init__(self, now: datetime = UTC_NOW) -> None:
        self._now = now

    def now(self) -> datetime:
        return self._now

    def advance(self, delta: timedelta) -> None:
        self._now += delta

    def set(self, value: datetime) -> None:
        self._now = value


@dataclass
class MemoryOutboxRow:
    envelope: OutboxEventEnvelope
    delivery_status: OutboxDeliveryStatus
    attempt_count: int
    available_at: datetime
    lease_owner: Optional[str]
    leased_at: Optional[datetime]
    lease_until: Optional[datetime]
    published_at: Optional[datetime]
    last_error_code: Optional[OutboxDeliveryErrorCode]
    created_at: datetime


def make_envelope(
    sequence: int = 1,
    *,
    aggregate_sequence: int = 1,
    aggregate_version: int = 1,
    schema_version: int = 1,
    event_type: str = "PolicyBundleSuperseded",
) -> OutboxEventEnvelope:
    policy_bundle_id = f"bundle_outbox_{aggregate_sequence:04d}"
    payload = {
        "policy_bundle_id": policy_bundle_id,
        "status": "SUPERSEDED",
        "superseded_by_policy_bundle_id": (
            f"bundle_outbox_{aggregate_sequence + 1000:04d}"
        ),
    }
    return OutboxEventEnvelope(
        event_id=f"evt_outbox_{sequence:06d}",
        event_type=event_type,
        schema_version=schema_version,
        occurred_at=UTC_NOW,
        aggregate_type="PolicyBundle",
        aggregate_id=policy_bundle_id,
        aggregate_version=aggregate_version,
        actor_kind="SYSTEM",
        actor_id="system_outbox_0001",
        original_actor_id=None,
        correlation_id=f"correlation_{sequence:06d}",
        causation_id=f"causation___{sequence:06d}",
        trace_id=f"trace_outbox_{sequence:06d}",
        organization_id=None,
        payload=payload,
    )


def make_row(
    envelope: Optional[OutboxEventEnvelope] = None,
    *,
    status: OutboxDeliveryStatus = OutboxDeliveryStatus.PENDING,
    attempt_count: int = 0,
    available_at: datetime = UTC_NOW,
    lease_owner: Optional[str] = None,
    leased_at: Optional[datetime] = None,
    lease_until: Optional[datetime] = None,
    published_at: Optional[datetime] = None,
    last_error_code: Optional[OutboxDeliveryErrorCode] = None,
    created_at: datetime = UTC_NOW,
) -> MemoryOutboxRow:
    return MemoryOutboxRow(
        envelope=envelope or make_envelope(),
        delivery_status=status,
        attempt_count=attempt_count,
        available_at=available_at,
        lease_owner=lease_owner,
        leased_at=leased_at,
        lease_until=lease_until,
        published_at=published_at,
        last_error_code=last_error_code,
        created_at=created_at,
    )


class StrictOutboxRepository:
    """Thread-safe oracle for atomic claim and exact lease fencing."""

    def __init__(
        self, *, clock: FixedUtcClock, rows: Iterable[MemoryOutboxRow]
    ) -> None:
        self.clock = clock
        self._lock = RLock()
        self._rows = {row.envelope.event_id: row for row in rows}
        self.readiness_calls = 0
        self.claim_calls = 0
        self.claim_history: list[tuple[str, str, int, bool]] = []
        self.operation_log: list[tuple[str, str]] = []

    def check_readiness(self) -> None:
        self.readiness_calls += 1

    def _eligible(self, row: MemoryOutboxRow, now: datetime) -> bool:
        if row.delivery_status is OutboxDeliveryStatus.PENDING:
            return row.available_at <= now
        return (
            row.delivery_status is OutboxDeliveryStatus.LEASED
            and row.lease_until is not None
            and row.lease_until <= now
        )

    def dead_letter_exhausted(self, *, max_attempts: int) -> int:
        with self._lock:
            now = self.clock.now()
            count = 0
            for row in self._rows.values():
                if self._eligible(row, now) and row.attempt_count >= max_attempts:
                    row.delivery_status = OutboxDeliveryStatus.DEAD
                    row.lease_owner = None
                    row.leased_at = None
                    row.lease_until = None
                    row.published_at = None
                    row.last_error_code = (
                        OutboxDeliveryErrorCode.DELIVERY_ATTEMPTS_EXHAUSTED
                    )
                    self.operation_log.append(("dead_exhausted", row.envelope.event_id))
                    count += 1
            return count

    def claim_batch(
        self,
        *,
        worker_id: str,
        batch_size: int,
        lease_duration: timedelta,
        max_attempts: int,
    ) -> tuple[OutboxLease, ...]:
        with self._lock:
            self.claim_calls += 1
            now = self.clock.now()
            candidates = sorted(
                self._rows.values(),
                key=lambda row: (
                    row.available_at,
                    row.created_at,
                    row.envelope.event_id,
                ),
            )
            leases: list[OutboxLease] = []
            for row in candidates:
                if len(leases) >= batch_size:
                    break
                if not self._eligible(row, now):
                    continue
                if row.attempt_count >= max_attempts:
                    continue
                reclaimed = row.delivery_status is OutboxDeliveryStatus.LEASED
                row.delivery_status = OutboxDeliveryStatus.LEASED
                row.attempt_count += 1
                row.lease_owner = worker_id
                row.leased_at = now
                row.lease_until = now + lease_duration
                row.published_at = None
                lease = OutboxLease(
                    envelope=row.envelope,
                    attempt_count=row.attempt_count,
                    lease_owner=worker_id,
                    leased_at=now,
                    lease_until=row.lease_until,
                    available_at=row.available_at,
                    created_at=row.created_at,
                    lease_reclaimed=reclaimed,
                )
                leases.append(lease)
                self.claim_history.append(
                    (worker_id, row.envelope.event_id, row.attempt_count, reclaimed)
                )
                self.operation_log.append(("claim", row.envelope.event_id))
            return tuple(leases)

    def _fenced_row(self, lease: OutboxLease) -> Optional[MemoryOutboxRow]:
        row = self._rows.get(lease.envelope.event_id)
        now = self.clock.now()
        if row is None or row.delivery_status is not OutboxDeliveryStatus.LEASED:
            return None
        if (
            row.lease_owner != lease.lease_owner
            or row.lease_until != lease.lease_until
            or row.attempt_count != lease.attempt_count
            or row.lease_until is None
            or now >= row.lease_until
        ):
            return None
        return row

    def mark_published(self, *, lease: OutboxLease) -> bool:
        with self._lock:
            row = self._fenced_row(lease)
            if row is None:
                return False
            row.delivery_status = OutboxDeliveryStatus.PUBLISHED
            row.published_at = self.clock.now()
            row.lease_owner = None
            row.leased_at = None
            row.lease_until = None
            row.last_error_code = None
            self.operation_log.append(("published", row.envelope.event_id))
            return True

    def reschedule(
        self,
        *,
        lease: OutboxLease,
        retry_after: timedelta,
        error_code: OutboxDeliveryErrorCode,
    ) -> bool:
        with self._lock:
            row = self._fenced_row(lease)
            if row is None:
                return False
            row.delivery_status = OutboxDeliveryStatus.PENDING
            row.available_at = self.clock.now() + retry_after
            row.lease_owner = None
            row.leased_at = None
            row.lease_until = None
            row.published_at = None
            row.last_error_code = error_code
            self.operation_log.append(("rescheduled", row.envelope.event_id))
            return True

    def mark_dead(
        self,
        *,
        lease: OutboxLease,
        error_code: OutboxDeliveryErrorCode,
    ) -> bool:
        with self._lock:
            row = self._fenced_row(lease)
            if row is None:
                return False
            row.delivery_status = OutboxDeliveryStatus.DEAD
            row.lease_owner = None
            row.leased_at = None
            row.lease_until = None
            row.published_at = None
            row.last_error_code = error_code
            self.operation_log.append(("dead", row.envelope.event_id))
            return True

    def release_unstarted(self, *, lease: OutboxLease) -> bool:
        with self._lock:
            row = self._fenced_row(lease)
            if row is None:
                return False
            row.delivery_status = OutboxDeliveryStatus.PENDING
            row.available_at = self.clock.now()
            row.lease_owner = None
            row.leased_at = None
            row.lease_until = None
            row.last_error_code = None
            self.operation_log.append(("released", row.envelope.event_id))
            return True

    def snapshot(self, event_id: str) -> MemoryOutboxRow:
        with self._lock:
            return replace(self._rows[event_id])


class StrictEventSchemaRegistry:
    """A narrow independent oracle for the IAM v1 superseded event."""

    def __init__(self, *, available: bool = True) -> None:
        self.available = available
        self.readiness_calls = 0
        self.validation_calls: list[str] = []

    def check_readiness(self) -> None:
        self.readiness_calls += 1
        if not self.available:
            raise OutboxDeliveryError(
                OutboxDeliveryErrorCode.SCHEMA_REGISTRY_UNAVAILABLE
            )

    @staticmethod
    def _timestamp(value: datetime) -> str:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise OutboxDeliveryError(
                OutboxDeliveryErrorCode.OUTBOX_EVENT_INVALID
            )
        return value.isoformat().replace("+00:00", "Z")

    def validate(self, envelope: OutboxEventEnvelope) -> ValidatedOutboxMessage:
        self.validation_calls.append(envelope.event_id)
        if not self.available:
            raise OutboxDeliveryError(
                OutboxDeliveryErrorCode.SCHEMA_REGISTRY_UNAVAILABLE
            )
        if envelope.schema_version != 1 or envelope.event_type != (
            "PolicyBundleSuperseded"
        ):
            raise OutboxDeliveryError(
                OutboxDeliveryErrorCode.OUTBOX_SCHEMA_UNSUPPORTED
            )
        required_payload = {
            "policy_bundle_id",
            "status",
            "superseded_by_policy_bundle_id",
        }
        if (
            envelope.aggregate_type != "PolicyBundle"
            or envelope.organization_id is not None
            or set(envelope.payload) != required_payload
            or envelope.payload.get("policy_bundle_id") != envelope.aggregate_id
            or envelope.payload.get("status") != "SUPERSEDED"
            or not isinstance(
                envelope.payload.get("superseded_by_policy_bundle_id"), str
            )
        ):
            raise OutboxDeliveryError(
                OutboxDeliveryErrorCode.OUTBOX_EVENT_INVALID
            )
        canonical = json.dumps(
            {
                "event_id": envelope.event_id,
                "event_type": envelope.event_type,
                "schema_version": envelope.schema_version,
                "occurred_at": self._timestamp(envelope.occurred_at),
                "aggregate_type": envelope.aggregate_type,
                "aggregate_id": envelope.aggregate_id,
                "aggregate_version": envelope.aggregate_version,
                "actor_kind": envelope.actor_kind,
                "actor_id": envelope.actor_id,
                "original_actor_id": envelope.original_actor_id,
                "correlation_id": envelope.correlation_id,
                "causation_id": envelope.causation_id,
                "trace_id": envelope.trace_id,
                "organization_id": envelope.organization_id,
                "payload": dict(envelope.payload),
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return ValidatedOutboxMessage(
            event_id=envelope.event_id,
            event_type=envelope.event_type,
            topic="iam.events.v1",
            partition_key=f"{envelope.aggregate_type}:{envelope.aggregate_id}",
            schema_id="iam-v1.schema.json",
            schema_version=envelope.schema_version,
            correlation_id=envelope.correlation_id,
            canonical_bytes=canonical,
        )


class StrictIdempotentProjectionConsumer:
    """Durable-inbox oracle with bounded aggregate-version buffering."""

    def __init__(self) -> None:
        self.inbox: set[tuple[str, str]] = set()
        self.current_versions: dict[str, int] = {}
        self.pending: dict[str, dict[int, tuple[str, str]]] = {}
        self.side_effects: list[tuple[str, int, str]] = []

    def consume(self, message: ValidatedOutboxMessage) -> bool:
        inbox_key = ("policy_projection_v1", message.event_id)
        if inbox_key in self.inbox:
            return False
        body = json.loads(message.canonical_bytes.decode("utf-8"))
        aggregate_id = body["aggregate_id"]
        version = body["aggregate_version"]
        self.inbox.add(inbox_key)
        current = self.current_versions.get(aggregate_id, 0)
        if version <= current:
            return False
        self.pending.setdefault(aggregate_id, {})[version] = (
            message.event_id,
            message.event_type,
        )
        while current + 1 in self.pending[aggregate_id]:
            next_version = current + 1
            event_id, _event_type = self.pending[aggregate_id].pop(next_version)
            self.side_effects.append((aggregate_id, next_version, event_id))
            current = next_version
            self.current_versions[aggregate_id] = current
        return True


class StrictBrokerPublisher:
    """Deterministic broker with explicit before-ack and after-ack faults."""

    SUCCESS = "SUCCESS"
    BEFORE_ACK = "BEFORE_ACK"
    AFTER_ACK = "AFTER_ACK"

    def __init__(
        self,
        *,
        clock: FixedUtcClock,
        modes: Sequence[str] = (SUCCESS,),
        consumer: Optional[StrictIdempotentProjectionConsumer] = None,
        provider_detail: Optional[str] = None,
        ready: bool = True,
    ) -> None:
        self.clock = clock
        self.modes = tuple(modes)
        self.consumer = consumer
        self.provider_detail = provider_detail
        self.ready = ready
        self.readiness_calls = 0
        self.calls: list[ValidatedOutboxMessage] = []
        self.accepted_event_ids: list[str] = []

    def check_readiness(self) -> None:
        self.readiness_calls += 1
        if not self.ready:
            raise OutboxDeliveryError(
                OutboxDeliveryErrorCode.BROKER_UNAVAILABLE
            )

    def publish(
        self, message: ValidatedOutboxMessage
    ) -> OutboxPublishAcknowledgement:
        self.calls.append(message)
        index = min(len(self.calls) - 1, len(self.modes) - 1)
        mode = self.modes[index]
        if mode == self.BEFORE_ACK:
            if self.provider_detail is not None:
                raise HostileProviderError(
                    OutboxDeliveryErrorCode.BROKER_UNAVAILABLE,
                    self.provider_detail,
                )
            raise OutboxDeliveryError(OutboxDeliveryErrorCode.BROKER_UNAVAILABLE)
        self.accepted_event_ids.append(message.event_id)
        if self.consumer is not None:
            self.consumer.consume(message)
        if mode == self.AFTER_ACK:
            if self.provider_detail is not None:
                raise HostileProviderError(
                    OutboxDeliveryErrorCode.BROKER_ACK_UNKNOWN,
                    self.provider_detail,
                )
            raise OutboxDeliveryError(OutboxDeliveryErrorCode.BROKER_ACK_UNKNOWN)
        return OutboxPublishAcknowledgement(
            event_id=message.event_id,
            acknowledged_at=self.clock.now(),
        )


class HostileProviderError(OutboxDeliveryError):
    """Typed provider failure whose free text must never reach observability."""

    def __init__(
        self, code: OutboxDeliveryErrorCode, provider_detail: str
    ) -> None:
        self.code = code
        self.provider_detail = provider_detail
        Exception.__init__(self, f"{code.value}: {provider_detail}")


class StrictBackoff:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    def delay_for(self, *, event_id: str, attempt_count: int) -> timedelta:
        self.calls.append((event_id, attempt_count))
        seconds = min(2 ** (attempt_count - 1), 300)
        return timedelta(seconds=seconds)


class StrictTelemetry:
    def __init__(self) -> None:
        self.events: list[OutboxTelemetryEvent] = []

    def emit(self, event: OutboxTelemetryEvent) -> None:
        self.events.append(event)


class StrictShutdownSignal:
    def __init__(self, *, stopping: bool = False) -> None:
        self.stopping = stopping

    def is_stopping(self) -> bool:
        return self.stopping


@dataclass(frozen=True)
class OutboxFixture:
    clock: FixedUtcClock
    repository: StrictOutboxRepository
    registry: StrictEventSchemaRegistry
    consumer: StrictIdempotentProjectionConsumer
    publisher: StrictBrokerPublisher
    backoff: StrictBackoff
    telemetry: StrictTelemetry
    shutdown: StrictShutdownSignal
    worker: OutboxDeliveryWorker


def make_outbox_fixture(
    *,
    rows: Optional[Iterable[MemoryOutboxRow]] = None,
    worker_id: str = "outbox-worker-a",
    publisher_modes: Sequence[str] = (StrictBrokerPublisher.SUCCESS,),
    provider_detail: Optional[str] = None,
    registry_available: bool = True,
    publisher_ready: bool = True,
    stopping: bool = False,
    now: datetime = UTC_NOW,
    max_attempts: int = 8,
) -> OutboxFixture:
    clock = FixedUtcClock(now)
    repository = StrictOutboxRepository(
        clock=clock,
        rows=(
            tuple(rows)
            if rows is not None
            else (make_row(available_at=now, created_at=now),)
        ),
    )
    registry = StrictEventSchemaRegistry(available=registry_available)
    consumer = StrictIdempotentProjectionConsumer()
    publisher = StrictBrokerPublisher(
        clock=clock,
        modes=publisher_modes,
        consumer=consumer,
        provider_detail=provider_detail,
        ready=publisher_ready,
    )
    backoff = StrictBackoff()
    telemetry = StrictTelemetry()
    shutdown = StrictShutdownSignal(stopping=stopping)
    worker = OutboxDeliveryWorker(
        repository=repository,
        schema_registry=registry,
        publisher=publisher,
        clock=clock,
        backoff=backoff,
        telemetry=telemetry,
        shutdown=shutdown,
        worker_id=worker_id,
        max_attempts=max_attempts,
    )
    return OutboxFixture(
        clock=clock,
        repository=repository,
        registry=registry,
        consumer=consumer,
        publisher=publisher,
        backoff=backoff,
        telemetry=telemetry,
        shutdown=shutdown,
        worker=worker,
    )


def stopped_result() -> OutboxDeliveryCycleResult:
    return OutboxDeliveryCycleResult(
        claimed_count=0,
        published_count=0,
        rescheduled_count=0,
        dead_lettered_count=0,
        lease_reclaimed_count=0,
    )
