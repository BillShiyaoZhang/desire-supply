"""Fail-closed contracts and orchestration for cross-context outbox delivery."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import re
from typing import Any, Mapping, Optional, Protocol, Tuple
import unicodedata


class OutboxDeliveryStatus(str, Enum):
    """Closed transport states; the event envelope is immutable in every state."""

    PENDING = "PENDING"
    LEASED = "LEASED"
    PUBLISHED = "PUBLISHED"
    DEAD = "DEAD"


class OutboxDeliveryErrorCode(str, Enum):
    """Safe operational classifications; provider text is never persisted."""

    BROKER_UNAVAILABLE = "BROKER_UNAVAILABLE"
    BROKER_ACK_UNKNOWN = "BROKER_ACK_UNKNOWN"
    SCHEMA_REGISTRY_UNAVAILABLE = "SCHEMA_REGISTRY_UNAVAILABLE"
    OUTBOX_SCHEMA_UNSUPPORTED = "OUTBOX_SCHEMA_UNSUPPORTED"
    OUTBOX_EVENT_INVALID = "OUTBOX_EVENT_INVALID"
    DELIVERY_ATTEMPTS_EXHAUSTED = "DELIVERY_ATTEMPTS_EXHAUSTED"
    DELIVERY_STORAGE_OUTCOME_UNKNOWN = "DELIVERY_STORAGE_OUTCOME_UNKNOWN"
    OUTBOX_CLOCK_INVALID = "OUTBOX_CLOCK_INVALID"
    OUTBOX_CONFIGURATION_INVALID = "OUTBOX_CONFIGURATION_INVALID"


class OutboxTelemetryOutcome(str, Enum):
    """Closed worker outcomes suitable for low-cardinality metrics and logs."""

    PUBLISHED = "PUBLISHED"
    RETRY_SCHEDULED = "RETRY_SCHEDULED"
    DEAD_LETTERED = "DEAD_LETTERED"
    STALE_LEASE = "STALE_LEASE"


class OutboxAttemptBucket(str, Enum):
    """Closed attempt buckets; raw event-specific labels are forbidden."""

    FIRST = "1"
    EARLY = "2_3"
    LATE = "4_7"
    EXHAUSTED = "8_PLUS"


class OutboxDeliveryError(Exception):
    """An error whose string form is always a closed, non-secret code."""

    def __init__(self, code: OutboxDeliveryErrorCode) -> None:
        self.code = code
        super().__init__(code.value)


@dataclass(frozen=True)
class OutboxEventEnvelope:
    """The safe, closed business envelope read from the local outbox."""

    event_id: str
    event_type: str
    schema_version: int
    occurred_at: datetime
    aggregate_type: str
    aggregate_id: str
    aggregate_version: int
    actor_kind: str
    actor_id: str
    original_actor_id: Optional[str]
    correlation_id: str
    causation_id: str
    trace_id: str
    organization_id: Optional[str]
    payload: Mapping[str, Any] = field(repr=False)


@dataclass(frozen=True)
class OutboxLease:
    """One exact fencing identity returned by an atomic database claim."""

    envelope: OutboxEventEnvelope
    attempt_count: int
    lease_owner: str
    leased_at: datetime
    lease_until: datetime
    available_at: datetime
    created_at: datetime
    lease_reclaimed: bool = False
    lease_token: Optional[str] = field(default=None, repr=False)


@dataclass(frozen=True)
class ValidatedOutboxMessage:
    """Registry-approved transport facts; bytes are intentionally non-printable."""

    event_id: str
    event_type: str
    topic: str
    partition_key: str
    schema_id: str
    schema_version: int
    correlation_id: str
    canonical_bytes: bytes = field(repr=False)


@dataclass(frozen=True)
class OutboxPublishAcknowledgement:
    """A broker acknowledgement bound to the submitted event ID."""

    event_id: str
    acknowledged_at: datetime


@dataclass(frozen=True)
class OutboxTelemetryEvent:
    """Closed, low-cardinality telemetry without event or aggregate identifiers."""

    event_type: str
    schema_version: int
    outcome: OutboxTelemetryOutcome
    error_code: Optional[OutboxDeliveryErrorCode]
    attempt_bucket: OutboxAttemptBucket
    lease_reclaimed: bool


@dataclass(frozen=True)
class OutboxDeliveryCycleResult:
    """Safe aggregate result; it never returns envelopes or provider responses."""

    claimed_count: int
    published_count: int
    rescheduled_count: int
    dead_lettered_count: int
    lease_reclaimed_count: int
    failure_codes: Tuple[OutboxDeliveryErrorCode, ...] = ()


class OutboxRepository(Protocol):
    """Fixed-operation repository; a real adapter maps these to reviewed SQL."""

    def check_readiness(self) -> None:
        ...

    def claim_batch(
        self,
        *,
        worker_id: str,
        batch_size: int,
        lease_duration: timedelta,
        max_attempts: int,
    ) -> Tuple[OutboxLease, ...]:
        ...

    def dead_letter_exhausted(self, *, max_attempts: int) -> int:
        ...

    def mark_published(self, *, lease: OutboxLease) -> bool:
        ...

    def reschedule(
        self,
        *,
        lease: OutboxLease,
        retry_after: timedelta,
        error_code: OutboxDeliveryErrorCode,
    ) -> bool:
        ...

    def mark_dead(
        self, *, lease: OutboxLease, error_code: OutboxDeliveryErrorCode
    ) -> bool:
        ...

    def release_unstarted(self, *, lease: OutboxLease) -> bool:
        ...


class OutboxEventSchemaRegistry(Protocol):
    def check_readiness(self) -> None:
        ...

    def validate(self, envelope: OutboxEventEnvelope) -> ValidatedOutboxMessage:
        ...


class OutboxBrokerPublisher(Protocol):
    def check_readiness(self) -> None:
        ...

    def publish(
        self, message: ValidatedOutboxMessage
    ) -> OutboxPublishAcknowledgement:
        ...


class OutboxClock(Protocol):
    def now(self) -> datetime:
        ...


class OutboxBackoff(Protocol):
    def delay_for(self, *, event_id: str, attempt_count: int) -> timedelta:
        ...


class OutboxTelemetry(Protocol):
    def emit(self, event: OutboxTelemetryEvent) -> None:
        ...


class OutboxShutdownSignal(Protocol):
    def is_stopping(self) -> bool:
        ...


class OutboxDeliveryWorker:
    """One fail-closed, at-least-once delivery cycle.

    Database atomicity and fencing remain the repository's responsibility; the
    worker never keeps a database transaction open across registry or broker
    calls and never mutates an event envelope to make a retry succeed.
    """

    _MAX_BATCH_SIZE = 100
    _MAX_ATTEMPTS_CONFIGURATION = 32
    _WORKER_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

    def __init__(
        self,
        *,
        repository: OutboxRepository,
        schema_registry: OutboxEventSchemaRegistry,
        publisher: OutboxBrokerPublisher,
        clock: OutboxClock,
        backoff: OutboxBackoff,
        telemetry: OutboxTelemetry,
        shutdown: OutboxShutdownSignal,
        worker_id: str,
        lease_duration: timedelta = timedelta(seconds=30),
        max_attempts: int = 8,
    ) -> None:
        self._repository = repository
        self._schema_registry = schema_registry
        self._publisher = publisher
        self._clock = clock
        self._backoff = backoff
        self._telemetry = telemetry
        self._shutdown = shutdown
        self._worker_id = worker_id
        self._lease_duration = lease_duration
        self._max_attempts = max_attempts

    def deliver_once(self, *, batch_size: int = 100) -> OutboxDeliveryCycleResult:
        """Claim, validate and publish one bounded batch.

        Provider exceptions are deliberately reduced to closed error codes.
        A false fenced update is a stale lease, not permission to overwrite the
        newer owner.  Storage outcome unknown is propagated so the caller can
        discard the connection and wait for normal lease recovery.
        """

        if self._is_stopping():
            return self._empty_result()
        self._validate_configuration(batch_size)
        self._safe_utc_now()
        self._check_readiness()

        exhausted_count = self._dead_letter_exhausted()
        failure_codes = []
        if exhausted_count:
            failure_codes.append(
                OutboxDeliveryErrorCode.DELIVERY_ATTEMPTS_EXHAUSTED
            )

        leases = self._claim_batch(batch_size)
        self._validate_claimed_leases(leases, batch_size=batch_size)
        published_count = 0
        rescheduled_count = 0
        dead_lettered_count = exhausted_count
        reclaimed_count = sum(1 for lease in leases if lease.lease_reclaimed)

        for index, lease in enumerate(leases):
            if self._is_stopping():
                self._release_unstarted(leases[index:])
                break

            if self._safe_utc_now() >= lease.lease_until:
                self._emit(
                    event_type="UNVALIDATED",
                    schema_version=0,
                    outcome=OutboxTelemetryOutcome.STALE_LEASE,
                    error_code=None,
                    lease=lease,
                )
                continue

            try:
                message = self._schema_registry.validate(lease.envelope)
            except OutboxDeliveryError as error:
                if error.code in {
                    OutboxDeliveryErrorCode.OUTBOX_SCHEMA_UNSUPPORTED,
                    OutboxDeliveryErrorCode.OUTBOX_EVENT_INVALID,
                }:
                    if self._mark_dead(lease=lease, error_code=error.code):
                        dead_lettered_count += 1
                        failure_codes.append(error.code)
                        self._emit(
                            event_type="UNVALIDATED",
                            schema_version=0,
                            outcome=OutboxTelemetryOutcome.DEAD_LETTERED,
                            error_code=error.code,
                            lease=lease,
                        )
                    else:
                        self._emit_stale(lease)
                    continue
                raise OutboxDeliveryError(
                    OutboxDeliveryErrorCode.SCHEMA_REGISTRY_UNAVAILABLE
                ) from None
            except Exception:
                raise OutboxDeliveryError(
                    OutboxDeliveryErrorCode.SCHEMA_REGISTRY_UNAVAILABLE
                ) from None

            if not self._message_is_bound(message, lease.envelope):
                raise OutboxDeliveryError(
                    OutboxDeliveryErrorCode.SCHEMA_REGISTRY_UNAVAILABLE
                )

            publish_error = self._publish(message)
            if publish_error is not None:
                outcome = self._retry_or_dead(
                    lease=lease,
                    event_type=message.event_type,
                    schema_version=message.schema_version,
                    error_code=publish_error,
                )
                if outcome is OutboxTelemetryOutcome.RETRY_SCHEDULED:
                    rescheduled_count += 1
                    failure_codes.append(publish_error)
                elif outcome is OutboxTelemetryOutcome.DEAD_LETTERED:
                    dead_lettered_count += 1
                    failure_codes.append(
                        OutboxDeliveryErrorCode.DELIVERY_ATTEMPTS_EXHAUSTED
                    )
                continue

            if self._mark_published(lease):
                published_count += 1
                self._emit(
                    event_type=message.event_type,
                    schema_version=message.schema_version,
                    outcome=OutboxTelemetryOutcome.PUBLISHED,
                    error_code=None,
                    lease=lease,
                )
            else:
                self._emit_stale(
                    lease,
                    event_type=message.event_type,
                    schema_version=message.schema_version,
                )

        return OutboxDeliveryCycleResult(
            claimed_count=len(leases),
            published_count=published_count,
            rescheduled_count=rescheduled_count,
            dead_lettered_count=dead_lettered_count,
            lease_reclaimed_count=reclaimed_count,
            failure_codes=tuple(failure_codes),
        )

    @staticmethod
    def _empty_result() -> OutboxDeliveryCycleResult:
        return OutboxDeliveryCycleResult(
            claimed_count=0,
            published_count=0,
            rescheduled_count=0,
            dead_lettered_count=0,
            lease_reclaimed_count=0,
        )

    def _is_stopping(self) -> bool:
        try:
            return self._shutdown.is_stopping() is True
        except Exception:
            # A broken lifecycle dependency must never permit a fresh claim.
            return True

    def _validate_configuration(self, batch_size: int) -> None:
        worker_id = unicodedata.normalize("NFC", self._worker_id)
        if worker_id != self._worker_id or not self._WORKER_ID_PATTERN.fullmatch(
            worker_id
        ):
            raise OutboxDeliveryError(
                OutboxDeliveryErrorCode.OUTBOX_CONFIGURATION_INVALID
            )
        if not isinstance(batch_size, int) or isinstance(batch_size, bool):
            raise OutboxDeliveryError(
                OutboxDeliveryErrorCode.OUTBOX_CONFIGURATION_INVALID
            )
        if not 1 <= batch_size <= self._MAX_BATCH_SIZE:
            raise OutboxDeliveryError(
                OutboxDeliveryErrorCode.OUTBOX_CONFIGURATION_INVALID
            )
        if not isinstance(self._lease_duration, timedelta) or not (
            timedelta(0) < self._lease_duration <= timedelta(days=1)
        ):
            raise OutboxDeliveryError(
                OutboxDeliveryErrorCode.OUTBOX_CONFIGURATION_INVALID
            )
        if (
            not isinstance(self._max_attempts, int)
            or isinstance(self._max_attempts, bool)
            or not 1
            <= self._max_attempts
            <= self._MAX_ATTEMPTS_CONFIGURATION
        ):
            raise OutboxDeliveryError(
                OutboxDeliveryErrorCode.OUTBOX_CONFIGURATION_INVALID
            )

    def _safe_utc_now(self) -> datetime:
        try:
            now = self._clock.now()
        except Exception:
            raise OutboxDeliveryError(
                OutboxDeliveryErrorCode.OUTBOX_CLOCK_INVALID
            ) from None
        if not self._is_utc_datetime(now):
            raise OutboxDeliveryError(
                OutboxDeliveryErrorCode.OUTBOX_CLOCK_INVALID
            )
        return now

    @staticmethod
    def _is_utc_datetime(value: Any) -> bool:
        if not isinstance(value, datetime) or value.tzinfo is None:
            return False
        try:
            return value.utcoffset() == timedelta(0)
        except Exception:
            return False

    def _check_readiness(self) -> None:
        self._safe_readiness_call(
            self._repository.check_readiness,
            OutboxDeliveryErrorCode.DELIVERY_STORAGE_OUTCOME_UNKNOWN,
        )
        self._safe_readiness_call(
            self._schema_registry.check_readiness,
            OutboxDeliveryErrorCode.SCHEMA_REGISTRY_UNAVAILABLE,
        )
        self._safe_readiness_call(
            self._publisher.check_readiness,
            OutboxDeliveryErrorCode.BROKER_UNAVAILABLE,
        )

    @staticmethod
    def _safe_readiness_call(operation: Any, code: OutboxDeliveryErrorCode) -> None:
        try:
            operation()
        except OutboxDeliveryError as error:
            if error.code is code:
                raise
            raise OutboxDeliveryError(code) from None
        except Exception:
            raise OutboxDeliveryError(code) from None

    def _dead_letter_exhausted(self) -> int:
        try:
            count = self._repository.dead_letter_exhausted(
                max_attempts=self._max_attempts
            )
        except OutboxDeliveryError as error:
            if (
                error.code
                is OutboxDeliveryErrorCode.DELIVERY_STORAGE_OUTCOME_UNKNOWN
            ):
                raise
            raise OutboxDeliveryError(
                OutboxDeliveryErrorCode.DELIVERY_STORAGE_OUTCOME_UNKNOWN
            ) from None
        except Exception:
            raise OutboxDeliveryError(
                OutboxDeliveryErrorCode.DELIVERY_STORAGE_OUTCOME_UNKNOWN
            ) from None
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise OutboxDeliveryError(
                OutboxDeliveryErrorCode.DELIVERY_STORAGE_OUTCOME_UNKNOWN
            )
        return count

    def _claim_batch(self, batch_size: int) -> Tuple[OutboxLease, ...]:
        try:
            leases = tuple(
                self._repository.claim_batch(
                    worker_id=self._worker_id,
                    batch_size=batch_size,
                    lease_duration=self._lease_duration,
                    max_attempts=self._max_attempts,
                )
            )
        except OutboxDeliveryError as error:
            if (
                error.code
                is OutboxDeliveryErrorCode.DELIVERY_STORAGE_OUTCOME_UNKNOWN
            ):
                raise
            raise OutboxDeliveryError(
                OutboxDeliveryErrorCode.DELIVERY_STORAGE_OUTCOME_UNKNOWN
            ) from None
        except Exception:
            raise OutboxDeliveryError(
                OutboxDeliveryErrorCode.DELIVERY_STORAGE_OUTCOME_UNKNOWN
            ) from None
        return leases

    def _validate_claimed_leases(
        self,
        leases: Tuple[OutboxLease, ...],
        *,
        batch_size: int,
    ) -> None:
        if len(leases) > batch_size:
            raise OutboxDeliveryError(
                OutboxDeliveryErrorCode.DELIVERY_STORAGE_OUTCOME_UNKNOWN
            )
        event_ids = set()
        for lease in leases:
            if not isinstance(lease, OutboxLease):
                raise OutboxDeliveryError(
                    OutboxDeliveryErrorCode.DELIVERY_STORAGE_OUTCOME_UNKNOWN
                )
            if (
                lease.lease_owner != self._worker_id
                or lease.envelope.event_id in event_ids
                or not 1 <= lease.attempt_count <= self._max_attempts
                or not self._is_utc_datetime(lease.leased_at)
                or not self._is_utc_datetime(lease.lease_until)
                or lease.lease_until <= lease.leased_at
            ):
                raise OutboxDeliveryError(
                    OutboxDeliveryErrorCode.DELIVERY_STORAGE_OUTCOME_UNKNOWN
                )
            event_ids.add(lease.envelope.event_id)

    @staticmethod
    def _message_is_bound(
        message: Any, envelope: OutboxEventEnvelope
    ) -> bool:
        return (
            isinstance(message, ValidatedOutboxMessage)
            and message.event_id == envelope.event_id
            and message.event_type == envelope.event_type
            and message.schema_version == envelope.schema_version
            and message.correlation_id == envelope.correlation_id
            and isinstance(message.canonical_bytes, bytes)
            and bool(message.canonical_bytes)
            and bool(message.topic)
            and bool(message.partition_key)
            and bool(message.schema_id)
        )

    def _publish(
        self, message: ValidatedOutboxMessage
    ) -> Optional[OutboxDeliveryErrorCode]:
        try:
            acknowledgement = self._publisher.publish(message)
        except OutboxDeliveryError as error:
            if error.code is OutboxDeliveryErrorCode.BROKER_UNAVAILABLE:
                return OutboxDeliveryErrorCode.BROKER_UNAVAILABLE
            return OutboxDeliveryErrorCode.BROKER_ACK_UNKNOWN
        except Exception:
            return OutboxDeliveryErrorCode.BROKER_ACK_UNKNOWN
        if (
            not isinstance(acknowledgement, OutboxPublishAcknowledgement)
            or acknowledgement.event_id != message.event_id
            or not self._is_utc_datetime(acknowledgement.acknowledged_at)
        ):
            return OutboxDeliveryErrorCode.BROKER_ACK_UNKNOWN
        return None

    def _retry_or_dead(
        self,
        *,
        lease: OutboxLease,
        event_type: str,
        schema_version: int,
        error_code: OutboxDeliveryErrorCode,
    ) -> OutboxTelemetryOutcome:
        if lease.attempt_count >= self._max_attempts:
            exhausted = OutboxDeliveryErrorCode.DELIVERY_ATTEMPTS_EXHAUSTED
            if self._mark_dead(lease=lease, error_code=exhausted):
                self._emit(
                    event_type=event_type,
                    schema_version=schema_version,
                    outcome=OutboxTelemetryOutcome.DEAD_LETTERED,
                    error_code=exhausted,
                    lease=lease,
                )
                return OutboxTelemetryOutcome.DEAD_LETTERED
            self._emit_stale(
                lease,
                event_type=event_type,
                schema_version=schema_version,
            )
            return OutboxTelemetryOutcome.STALE_LEASE

        try:
            retry_after = self._backoff.delay_for(
                event_id=lease.envelope.event_id,
                attempt_count=lease.attempt_count,
            )
        except Exception:
            raise OutboxDeliveryError(
                OutboxDeliveryErrorCode.OUTBOX_CONFIGURATION_INVALID
            ) from None
        raw_seconds = min(2 ** (lease.attempt_count - 1), 300)
        minimum_delay = timedelta(seconds=raw_seconds)
        maximum_delay = timedelta(seconds=raw_seconds * 1.2)
        if not isinstance(retry_after, timedelta) or not (
            minimum_delay <= retry_after <= maximum_delay
        ):
            raise OutboxDeliveryError(
                OutboxDeliveryErrorCode.OUTBOX_CONFIGURATION_INVALID
            )
        if self._reschedule(
            lease=lease,
            retry_after=retry_after,
            error_code=error_code,
        ):
            self._emit(
                event_type=event_type,
                schema_version=schema_version,
                outcome=OutboxTelemetryOutcome.RETRY_SCHEDULED,
                error_code=error_code,
                lease=lease,
            )
            return OutboxTelemetryOutcome.RETRY_SCHEDULED
        self._emit_stale(
            lease,
            event_type=event_type,
            schema_version=schema_version,
        )
        return OutboxTelemetryOutcome.STALE_LEASE

    def _mark_published(self, lease: OutboxLease) -> bool:
        try:
            return self._repository.mark_published(lease=lease) is True
        except OutboxDeliveryError as error:
            if (
                error.code
                is OutboxDeliveryErrorCode.DELIVERY_STORAGE_OUTCOME_UNKNOWN
            ):
                raise
            raise OutboxDeliveryError(
                OutboxDeliveryErrorCode.DELIVERY_STORAGE_OUTCOME_UNKNOWN
            ) from None
        except Exception:
            raise OutboxDeliveryError(
                OutboxDeliveryErrorCode.DELIVERY_STORAGE_OUTCOME_UNKNOWN
            ) from None

    def _reschedule(
        self,
        *,
        lease: OutboxLease,
        retry_after: timedelta,
        error_code: OutboxDeliveryErrorCode,
    ) -> bool:
        try:
            return (
                self._repository.reschedule(
                    lease=lease,
                    retry_after=retry_after,
                    error_code=error_code,
                )
                is True
            )
        except OutboxDeliveryError as error:
            if (
                error.code
                is OutboxDeliveryErrorCode.DELIVERY_STORAGE_OUTCOME_UNKNOWN
            ):
                raise
            raise OutboxDeliveryError(
                OutboxDeliveryErrorCode.DELIVERY_STORAGE_OUTCOME_UNKNOWN
            ) from None
        except Exception:
            raise OutboxDeliveryError(
                OutboxDeliveryErrorCode.DELIVERY_STORAGE_OUTCOME_UNKNOWN
            ) from None

    def _mark_dead(
        self, *, lease: OutboxLease, error_code: OutboxDeliveryErrorCode
    ) -> bool:
        try:
            return (
                self._repository.mark_dead(
                    lease=lease,
                    error_code=error_code,
                )
                is True
            )
        except OutboxDeliveryError as error:
            if (
                error.code
                is OutboxDeliveryErrorCode.DELIVERY_STORAGE_OUTCOME_UNKNOWN
            ):
                raise
            raise OutboxDeliveryError(
                OutboxDeliveryErrorCode.DELIVERY_STORAGE_OUTCOME_UNKNOWN
            ) from None
        except Exception:
            raise OutboxDeliveryError(
                OutboxDeliveryErrorCode.DELIVERY_STORAGE_OUTCOME_UNKNOWN
            ) from None

    def _release_unstarted(self, leases: Tuple[OutboxLease, ...]) -> None:
        for lease in leases:
            try:
                self._repository.release_unstarted(lease=lease)
            except Exception:
                # Shutdown is best effort; an exact lease naturally expires.
                continue

    @staticmethod
    def _attempt_bucket(attempt_count: int) -> OutboxAttemptBucket:
        if attempt_count <= 1:
            return OutboxAttemptBucket.FIRST
        if attempt_count <= 3:
            return OutboxAttemptBucket.EARLY
        if attempt_count <= 7:
            return OutboxAttemptBucket.LATE
        return OutboxAttemptBucket.EXHAUSTED

    def _emit(
        self,
        *,
        event_type: str,
        schema_version: int,
        outcome: OutboxTelemetryOutcome,
        error_code: Optional[OutboxDeliveryErrorCode],
        lease: OutboxLease,
    ) -> None:
        event = OutboxTelemetryEvent(
            event_type=event_type,
            schema_version=schema_version,
            outcome=outcome,
            error_code=error_code,
            attempt_bucket=self._attempt_bucket(lease.attempt_count),
            lease_reclaimed=lease.lease_reclaimed,
        )
        try:
            self._telemetry.emit(event)
        except Exception:
            # Observability is never allowed to change delivery state.
            return

    def _emit_stale(
        self,
        lease: OutboxLease,
        *,
        event_type: str = "UNVALIDATED",
        schema_version: int = 0,
    ) -> None:
        self._emit(
            event_type=event_type,
            schema_version=schema_version,
            outcome=OutboxTelemetryOutcome.STALE_LEASE,
            error_code=None,
            lease=lease,
        )
