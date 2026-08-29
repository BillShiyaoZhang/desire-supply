"""Reviewed PostgreSQL 18 adapters for outbox delivery and durable inbox."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import json
import re
import secrets
import time
from typing import Any, Mapping, Optional, Protocol, Tuple
import uuid

import psycopg
from psycopg.conninfo import make_conninfo
from psycopg.pq import TransactionStatus

from .delivery import (
    OutboxDeliveryError,
    OutboxDeliveryErrorCode,
    OutboxEventEnvelope,
    OutboxLease,
    OutboxPublishAcknowledgement,
    ValidatedOutboxMessage,
)


OUTBOX_POSTGRES_STATEMENT_NAMES: Tuple[str, ...] = (
    "dead_letter_exhausted_outbox_v1",
    "claim_outbox_batch_v1",
    "mark_outbox_published_v1",
    "reschedule_outbox_v1",
    "dead_letter_outbox_v1",
    "release_unstarted_outbox_lease_v1",
)

CONSUMER_INBOX_POSTGRES_STATEMENT_NAMES: Tuple[str, ...] = (
    "claim_consumer_inbox_v1",
    "read_consumer_inbox_duplicate_v1",
)


_DEAD_EXHAUSTED_SQL = """
WITH candidates AS MATERIALIZED (
    SELECT event_id
    FROM infra.outbox_events
    WHERE attempt_count >= %s
      AND (
          (delivery_status = 'PENDING' AND available_at <= transaction_timestamp())
          OR
          (delivery_status = 'LEASED' AND lease_until <= transaction_timestamp())
      )
    ORDER BY available_at, created_at, event_id
    FOR UPDATE SKIP LOCKED
)
UPDATE infra.outbox_events AS event
SET delivery_status = 'DEAD',
    lease_owner = NULL,
    leased_at = NULL,
    lease_token = NULL,
    lease_until = NULL,
    published_at = NULL,
    dead_at = transaction_timestamp(),
    last_error_code = 'DELIVERY_ATTEMPTS_EXHAUSTED'
FROM candidates
WHERE event.event_id = candidates.event_id
"""

_CLAIM_SQL = """
WITH candidates AS MATERIALIZED (
    SELECT
        event_id,
        available_at,
        created_at,
        delivery_status = 'LEASED' AS lease_reclaimed
    FROM infra.outbox_events
    WHERE attempt_count < %s
      AND (
          (delivery_status = 'PENDING' AND available_at <= transaction_timestamp())
          OR
          (delivery_status = 'LEASED' AND lease_until <= transaction_timestamp())
      )
    ORDER BY available_at, created_at, event_id
    FOR UPDATE SKIP LOCKED
    LIMIT %s
), updated AS (
    UPDATE infra.outbox_events AS event
    SET delivery_status = 'LEASED',
        attempt_count = event.attempt_count + 1,
        lease_owner = %s,
        leased_at = transaction_timestamp(),
        lease_token = %s,
        lease_until = transaction_timestamp() + %s,
        published_at = NULL,
        dead_at = NULL,
        last_error_code = NULL
    FROM candidates
    WHERE event.event_id = candidates.event_id
    RETURNING
        event.event_id,
        event.event_type,
        event.schema_version,
        event.occurred_at,
        event.aggregate_type,
        event.aggregate_id,
        event.aggregate_version,
        event.actor_kind,
        event.actor_id,
        event.original_actor_id,
        event.correlation_id,
        event.causation_id,
        event.trace_id,
        event.organization_id,
        event.payload,
        event.attempt_count,
        event.lease_owner,
        event.leased_at,
        event.lease_token,
        event.lease_until,
        event.available_at,
        event.created_at,
        candidates.lease_reclaimed
)
SELECT * FROM updated
ORDER BY available_at, created_at, event_id
"""

_MARK_PUBLISHED_SQL = """
UPDATE infra.outbox_events
SET delivery_status = 'PUBLISHED',
    lease_owner = NULL,
    leased_at = NULL,
    lease_token = NULL,
    lease_until = NULL,
    published_at = transaction_timestamp(),
    dead_at = NULL,
    last_error_code = NULL
WHERE event_id = %s
  AND delivery_status = 'LEASED'
  AND lease_owner = %s
  AND lease_token = %s
  AND attempt_count = %s
  AND lease_until = %s
  AND transaction_timestamp() < lease_until
"""

_RESCHEDULE_SQL = """
UPDATE infra.outbox_events
SET delivery_status = 'PENDING',
    available_at = transaction_timestamp() + %s,
    lease_owner = NULL,
    leased_at = NULL,
    lease_token = NULL,
    lease_until = NULL,
    published_at = NULL,
    dead_at = NULL,
    last_error_code = %s
WHERE event_id = %s
  AND delivery_status = 'LEASED'
  AND lease_owner = %s
  AND lease_token = %s
  AND attempt_count = %s
  AND lease_until = %s
  AND transaction_timestamp() < lease_until
"""

_DEAD_SQL = """
UPDATE infra.outbox_events
SET delivery_status = 'DEAD',
    lease_owner = NULL,
    leased_at = NULL,
    lease_token = NULL,
    lease_until = NULL,
    published_at = NULL,
    dead_at = transaction_timestamp(),
    last_error_code = %s
WHERE event_id = %s
  AND delivery_status = 'LEASED'
  AND lease_owner = %s
  AND lease_token = %s
  AND attempt_count = %s
  AND lease_until = %s
  AND transaction_timestamp() < lease_until
"""

_RELEASE_SQL = """
UPDATE infra.outbox_events
SET delivery_status = 'PENDING',
    available_at = transaction_timestamp(),
    lease_owner = NULL,
    leased_at = NULL,
    lease_token = NULL,
    lease_until = NULL,
    published_at = NULL,
    dead_at = NULL,
    last_error_code = NULL
WHERE event_id = %s
  AND delivery_status = 'LEASED'
  AND lease_owner = %s
  AND lease_token = %s
  AND attempt_count = %s
  AND lease_until = %s
  AND transaction_timestamp() < lease_until
"""

_CLAIM_INBOX_SQL = """
INSERT INTO infra.consumer_inbox_events (
    consumer_name,
    event_id,
    event_type,
    schema_version,
    aggregate_type,
    aggregate_id,
    aggregate_version,
    message_sha256,
    received_at,
    processed_at
) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,transaction_timestamp(),transaction_timestamp())
ON CONFLICT DO NOTHING
RETURNING consumer_name,event_id,event_type,schema_version,aggregate_type,
          aggregate_id,aggregate_version,message_sha256
"""

_READ_INBOX_DUPLICATE_SQL = """
SELECT consumer_name,event_id,event_type,schema_version,aggregate_type,
       aggregate_id,aggregate_version,message_sha256
FROM infra.consumer_inbox_events
WHERE consumer_name = %s AND event_id = %s
"""


class OutboxPostgresPersistenceCode(str, Enum):
    OUTBOX_POSTGRES_NOT_AVAILABLE = "OUTBOX_POSTGRES_NOT_AVAILABLE"
    OUTBOX_POSTGRES_OUTCOME_UNKNOWN = "OUTBOX_POSTGRES_OUTCOME_UNKNOWN"


class ConsumerInboxPersistenceCode(str, Enum):
    CONSUMER_INBOX_POSTGRES_NOT_AVAILABLE = (
        "CONSUMER_INBOX_POSTGRES_NOT_AVAILABLE"
    )
    CONSUMER_INBOX_OUTCOME_UNKNOWN = "CONSUMER_INBOX_OUTCOME_UNKNOWN"
    CONSUMER_INBOX_MESSAGE_ID_COLLISION = "CONSUMER_INBOX_MESSAGE_ID_COLLISION"


class PostgresConnectionDisposition(str, Enum):
    REUSE_AFTER_RESET = "REUSE_AFTER_RESET"
    DISCARD = "DISCARD"
    OUTCOME_UNKNOWN_DISCARD = "OUTCOME_UNKNOWN_DISCARD"


class BrokerSettlement(str, Enum):
    ACK = "ACK"
    NACK_REQUEUE = "NACK_REQUEUE"
    UNSETTLED_OUTCOME_UNKNOWN = "UNSETTLED_OUTCOME_UNKNOWN"


class OutboxPostgresUnavailable(OutboxDeliveryError):
    persistence_code = OutboxPostgresPersistenceCode.OUTBOX_POSTGRES_NOT_AVAILABLE
    connection_disposition = PostgresConnectionDisposition.DISCARD

    def __init__(self) -> None:
        super().__init__(OutboxDeliveryErrorCode.DELIVERY_STORAGE_OUTCOME_UNKNOWN)


class ConsumerInboxPostgresUnavailable(Exception):
    code = ConsumerInboxPersistenceCode.CONSUMER_INBOX_POSTGRES_NOT_AVAILABLE

    def __init__(self) -> None:
        super().__init__(self.code.value)


class ConsumerInboxOutcomeUnknown(ConsumerInboxPostgresUnavailable):
    code = ConsumerInboxPersistenceCode.CONSUMER_INBOX_OUTCOME_UNKNOWN


class ConsumerInboxMessageIdentityCollision(ConsumerInboxPostgresUnavailable):
    code = ConsumerInboxPersistenceCode.CONSUMER_INBOX_MESSAGE_ID_COLLISION


@dataclass(frozen=True)
class PostgresOutboxSettings:
    conninfo: str = field(repr=False)
    application_name: str = "desire-outbox-worker"
    connect_timeout_seconds: int = 5

    def __post_init__(self) -> None:
        if (
            not isinstance(self.conninfo, str)
            or not self.conninfo
            or not _valid_application_name(self.application_name)
            or not isinstance(self.connect_timeout_seconds, int)
            or isinstance(self.connect_timeout_seconds, bool)
            or not 1 <= self.connect_timeout_seconds <= 30
        ):
            raise OutboxPostgresUnavailable()


@dataclass(frozen=True)
class PostgresConsumerInboxSettings:
    conninfo: str = field(repr=False)
    consumer_name: str
    application_name: str = "desire-durable-consumer"
    connect_timeout_seconds: int = 5

    def __post_init__(self) -> None:
        if (
            not isinstance(self.conninfo, str)
            or not self.conninfo
            or not _CONSUMER_NAME.fullmatch(self.consumer_name)
            or not _valid_application_name(self.application_name)
            or not isinstance(self.connect_timeout_seconds, int)
            or isinstance(self.connect_timeout_seconds, bool)
            or not 1 <= self.connect_timeout_seconds <= 30
        ):
            raise ConsumerInboxPostgresUnavailable()


@dataclass(frozen=True)
class ConsumerInboxResult:
    settlement: BrokerSettlement
    duplicate: bool
    applied: bool
    connection_disposition: PostgresConnectionDisposition


class ConsumerProjectionTransaction(Protocol):
    def execute_statement(
        self, *, name: str, parameters: Mapping[str, Any]
    ) -> int:
        ...


class DurableConsumerHandler(Protocol):
    def apply(
        self,
        *,
        message: ValidatedOutboxMessage,
        transaction: ConsumerProjectionTransaction,
    ) -> None:
        ...


class BrokerConsumerDelivery(Protocol):
    @property
    def message(self) -> ValidatedOutboxMessage:
        ...

    def ack(self) -> None:
        ...

    def nack(self, *, requeue: bool) -> None:
        ...


_CONSUMER_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{2,95}$")
_APPLICATION_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")


class PostgresOutboxRepository:
    """One fresh physical connection per fenced PostgreSQL operation."""

    statement_names = OUTBOX_POSTGRES_STATEMENT_NAMES

    def __init__(self, *, settings: PostgresOutboxSettings) -> None:
        if not isinstance(settings, PostgresOutboxSettings):
            raise OutboxPostgresUnavailable()
        self._settings = settings

    def check_readiness(self) -> None:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT current_user, current_setting('server_version_num')::integer, "
                "pg_catalog.to_regclass('infra.outbox_events'), "
                "EXISTS (SELECT 1 FROM pg_catalog.pg_attribute AS attribute "
                "WHERE attribute.attrelid='infra.outbox_events'::regclass "
                "AND attribute.attname='lease_token' AND NOT attribute.attisdropped), "
                "has_column_privilege(current_user,'infra.outbox_events','payload','SELECT'), "
                "has_column_privilege(current_user,'infra.outbox_events','payload','UPDATE')"
            ).fetchone()
            if row != (
                "iam_outbox_worker",
                connection.info.server_version,
                "infra.outbox_events",
                True,
                True,
                False,
            ):
                raise OutboxPostgresUnavailable()
        except OutboxPostgresUnavailable:
            raise
        except Exception:
            raise OutboxPostgresUnavailable() from None
        finally:
            connection.close()

    def claim_batch(
        self,
        *,
        worker_id: str,
        batch_size: int,
        lease_duration: timedelta,
        max_attempts: int,
    ) -> Tuple[OutboxLease, ...]:
        if (
            not _valid_worker_id(worker_id)
            or not isinstance(batch_size, int)
            or isinstance(batch_size, bool)
            or not 1 <= batch_size <= 100
            or not isinstance(max_attempts, int)
            or isinstance(max_attempts, bool)
            or not 1 <= max_attempts <= 32
            or not isinstance(lease_duration, timedelta)
            or not timedelta(seconds=1) <= lease_duration <= timedelta(minutes=5)
        ):
            raise OutboxPostgresUnavailable()
        token = _uuid7()

        def operation(connection: Any) -> Tuple[OutboxLease, ...]:
            rows = connection.execute(
                _CLAIM_SQL,
                (max_attempts, batch_size, worker_id, token, lease_duration),
            ).fetchall()
            return tuple(_lease_from_row(row) for row in rows)

        return self._transaction(
            operation_name="CLAIM",
            worker_id=worker_id,
            claim_token=token,
            event_id=None,
            operation=operation,
        )

    def dead_letter_exhausted(self, *, max_attempts: int) -> int:
        if (
            not isinstance(max_attempts, int)
            or isinstance(max_attempts, bool)
            or not 1 <= max_attempts <= 32
        ):
            raise OutboxPostgresUnavailable()

        def operation(connection: Any) -> int:
            cursor = connection.execute(_DEAD_EXHAUSTED_SQL, (max_attempts,))
            return cursor.rowcount

        return self._transaction(
            operation_name="DEAD_EXHAUSTED",
            worker_id=None,
            claim_token=None,
            event_id=None,
            operation=operation,
        )

    def mark_published(self, *, lease: OutboxLease) -> bool:
        token = _lease_token(lease)

        def operation(connection: Any) -> bool:
            cursor = connection.execute(
                _MARK_PUBLISHED_SQL,
                _fence_parameters(lease, token),
            )
            return cursor.rowcount == 1

        return self._lease_transaction("MARK_PUBLISHED", lease, token, operation)

    def reschedule(
        self,
        *,
        lease: OutboxLease,
        retry_after: timedelta,
        error_code: OutboxDeliveryErrorCode,
    ) -> bool:
        if (
            not isinstance(retry_after, timedelta)
            or not timedelta(seconds=1) <= retry_after <= timedelta(seconds=360)
            or error_code
            not in {
                OutboxDeliveryErrorCode.BROKER_UNAVAILABLE,
                OutboxDeliveryErrorCode.BROKER_ACK_UNKNOWN,
            }
        ):
            raise OutboxPostgresUnavailable()
        token = _lease_token(lease)

        def operation(connection: Any) -> bool:
            cursor = connection.execute(
                _RESCHEDULE_SQL,
                (retry_after, error_code.value) + _fence_parameters(lease, token),
            )
            return cursor.rowcount == 1

        return self._lease_transaction("RESCHEDULE", lease, token, operation)

    def mark_dead(
        self, *, lease: OutboxLease, error_code: OutboxDeliveryErrorCode
    ) -> bool:
        if error_code not in {
            OutboxDeliveryErrorCode.OUTBOX_SCHEMA_UNSUPPORTED,
            OutboxDeliveryErrorCode.OUTBOX_EVENT_INVALID,
            OutboxDeliveryErrorCode.DELIVERY_ATTEMPTS_EXHAUSTED,
        }:
            raise OutboxPostgresUnavailable()
        token = _lease_token(lease)

        def operation(connection: Any) -> bool:
            cursor = connection.execute(
                _DEAD_SQL,
                (error_code.value,) + _fence_parameters(lease, token),
            )
            return cursor.rowcount == 1

        return self._lease_transaction("DEAD", lease, token, operation)

    def release_unstarted(self, *, lease: OutboxLease) -> bool:
        token = _lease_token(lease)

        def operation(connection: Any) -> bool:
            cursor = connection.execute(
                _RELEASE_SQL,
                _fence_parameters(lease, token),
            )
            return cursor.rowcount == 1

        return self._lease_transaction("RELEASE_UNSTARTED", lease, token, operation)

    def _lease_transaction(self, name: str, lease: OutboxLease, token: uuid.UUID, operation):
        return self._transaction(
            operation_name=name,
            worker_id=lease.lease_owner,
            claim_token=token,
            event_id=lease.envelope.event_id,
            operation=operation,
        )

    def _connect(self):
        try:
            connection = psycopg.connect(
                make_conninfo(
                    self._settings.conninfo,
                    application_name=self._settings.application_name,
                    connect_timeout=self._settings.connect_timeout_seconds,
                ),
                autocommit=True,
            )
        except Exception:
            raise OutboxPostgresUnavailable() from None
        if (
            connection.info.transaction_status != TransactionStatus.IDLE
            or connection.info.server_version // 10_000 != 18
        ):
            connection.close()
            raise OutboxPostgresUnavailable()
        return connection

    def _transaction(
        self,
        *,
        operation_name: str,
        worker_id: Optional[str],
        claim_token: Optional[uuid.UUID],
        event_id: Optional[str],
        operation: Any,
    ):
        connection = self._connect()
        transaction_active = False
        commit_sent = False
        try:
            connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED")
            transaction_active = True
            _set_local(connection, "scope_kind", "OUTBOX_DELIVERY")
            _set_local(connection, "operation", operation_name)
            if worker_id is not None:
                _set_local(connection, "outbox_worker_id", worker_id)
            if claim_token is not None:
                _set_local(connection, "outbox_claim_token", str(claim_token))
            if event_id is not None:
                _set_local(connection, "outbox_event_id", event_id)
            result = operation(connection)
            commit_sent = True
            connection.execute("COMMIT")
            transaction_active = False
            return result
        except OutboxDeliveryError:
            raise
        except BaseException:
            if transaction_active and not commit_sent:
                try:
                    connection.execute("ROLLBACK")
                except Exception:
                    pass
            raise OutboxDeliveryError(
                OutboxDeliveryErrorCode.DELIVERY_STORAGE_OUTCOME_UNKNOWN
            ) from None
        finally:
            connection.close()


class _ConsumerProjectionTransaction:
    def __init__(self, connection: Any) -> None:
        self._connection = connection

    def execute_statement(
        self, *, name: str, parameters: Mapping[str, Any]
    ) -> int:
        del name, parameters
        raise ConsumerInboxPostgresUnavailable()


class PostgresDurableConsumerInbox:
    statement_names = CONSUMER_INBOX_POSTGRES_STATEMENT_NAMES

    def __init__(self, *, settings: PostgresConsumerInboxSettings) -> None:
        if not isinstance(settings, PostgresConsumerInboxSettings):
            raise ConsumerInboxPostgresUnavailable()
        self._settings = settings

    def check_readiness(self) -> None:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT current_user,current_setting('server_version_num')::integer,"
                "pg_catalog.to_regclass('infra.consumer_inbox_events'),"
                "infra.consumer_session_matches_name(%s)",
                (self._settings.consumer_name,),
            ).fetchone()
            if row != (
                "iam_projection_consumer",
                connection.info.server_version,
                "infra.consumer_inbox_events",
                True,
            ):
                raise ConsumerInboxPostgresUnavailable()
        except ConsumerInboxPostgresUnavailable:
            raise
        except Exception:
            raise ConsumerInboxPostgresUnavailable() from None
        finally:
            connection.close()

    def process(
        self,
        *,
        delivery: BrokerConsumerDelivery,
        handler: DurableConsumerHandler,
    ) -> ConsumerInboxResult:
        message = delivery.message
        metadata = _consumer_metadata(self._settings.consumer_name, message)
        connection = self._connect()
        transaction_active = False
        commit_sent = False
        try:
            connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED")
            transaction_active = True
            _set_local(connection, "consumer_name", self._settings.consumer_name)
            inserted = connection.execute(_CLAIM_INBOX_SQL, metadata).fetchone()
            duplicate = inserted is None
            if duplicate:
                existing = connection.execute(
                    _READ_INBOX_DUPLICATE_SQL,
                    (self._settings.consumer_name, metadata[1]),
                ).fetchone()
                if existing is None or tuple(existing) != metadata:
                    connection.execute("ROLLBACK")
                    transaction_active = False
                    delivery.nack(requeue=True)
                    raise ConsumerInboxMessageIdentityCollision()
            else:
                try:
                    handler.apply(
                        message=message,
                        transaction=_ConsumerProjectionTransaction(connection),
                    )
                except BaseException:
                    connection.execute("ROLLBACK")
                    transaction_active = False
                    delivery.nack(requeue=True)
                    return ConsumerInboxResult(
                        settlement=BrokerSettlement.NACK_REQUEUE,
                        duplicate=False,
                        applied=False,
                        connection_disposition=(
                            PostgresConnectionDisposition.REUSE_AFTER_RESET
                        ),
                    )
            commit_sent = True
            connection.execute("COMMIT")
            transaction_active = False
        except ConsumerInboxMessageIdentityCollision:
            raise
        except BaseException:
            if transaction_active and not commit_sent:
                try:
                    connection.execute("ROLLBACK")
                except Exception:
                    pass
            if commit_sent:
                raise ConsumerInboxOutcomeUnknown() from None
            raise ConsumerInboxPostgresUnavailable() from None
        finally:
            connection.close()

        delivery.ack()
        return ConsumerInboxResult(
            settlement=BrokerSettlement.ACK,
            duplicate=duplicate,
            applied=not duplicate,
            connection_disposition=PostgresConnectionDisposition.REUSE_AFTER_RESET,
        )

    def _connect(self):
        try:
            connection = psycopg.connect(
                make_conninfo(
                    self._settings.conninfo,
                    application_name=self._settings.application_name,
                    connect_timeout=self._settings.connect_timeout_seconds,
                ),
                autocommit=True,
            )
        except Exception:
            raise ConsumerInboxPostgresUnavailable() from None
        if (
            connection.info.transaction_status != TransactionStatus.IDLE
            or connection.info.server_version // 10_000 != 18
        ):
            connection.close()
            raise ConsumerInboxPostgresUnavailable()
        return connection


def _lease_from_row(row: Any) -> OutboxLease:
    if len(row) != 23:
        raise OutboxPostgresUnavailable()
    envelope = OutboxEventEnvelope(
        event_id=str(row[0]),
        event_type=row[1],
        schema_version=row[2],
        occurred_at=_utc(row[3]),
        aggregate_type=row[4],
        aggregate_id=str(row[5]),
        aggregate_version=row[6],
        actor_kind=row[7],
        actor_id=str(row[8]),
        original_actor_id=None if row[9] is None else str(row[9]),
        correlation_id=str(row[10]),
        causation_id=str(row[11]),
        trace_id=str(row[12]),
        organization_id=None if row[13] is None else str(row[13]),
        payload=dict(row[14]),
    )
    return OutboxLease(
        envelope=envelope,
        attempt_count=row[15],
        lease_owner=row[16],
        leased_at=_utc(row[17]),
        lease_until=_utc(row[19]),
        available_at=_utc(row[20]),
        created_at=_utc(row[21]),
        lease_reclaimed=bool(row[22]),
        lease_token=str(row[18]),
    )


def _lease_token(lease: OutboxLease) -> uuid.UUID:
    if not isinstance(lease, OutboxLease) or lease.lease_token is None:
        raise OutboxPostgresUnavailable()
    try:
        return uuid.UUID(lease.lease_token)
    except (AttributeError, TypeError, ValueError):
        raise OutboxPostgresUnavailable() from None


def _fence_parameters(lease: OutboxLease, token: uuid.UUID) -> tuple[Any, ...]:
    return (
        uuid.UUID(lease.envelope.event_id),
        lease.lease_owner,
        token,
        lease.attempt_count,
        lease.lease_until,
    )


def _consumer_metadata(
    consumer_name: str,
    message: ValidatedOutboxMessage,
) -> tuple[Any, ...]:
    if not isinstance(message, ValidatedOutboxMessage):
        raise ConsumerInboxPostgresUnavailable()
    try:
        body = json.loads(message.canonical_bytes.decode("utf-8"))
        event_id = uuid.UUID(message.event_id)
        aggregate_id = uuid.UUID(body["aggregate_id"])
        aggregate_type = body["aggregate_type"]
        aggregate_version = body["aggregate_version"]
    except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        raise ConsumerInboxPostgresUnavailable() from None
    if (
        body.get("event_id") != message.event_id
        or body.get("event_type") != message.event_type
        or body.get("schema_version") != message.schema_version
        or not isinstance(aggregate_type, str)
        or not isinstance(aggregate_version, int)
        or isinstance(aggregate_version, bool)
        or aggregate_version < 1
    ):
        raise ConsumerInboxPostgresUnavailable()
    return (
        consumer_name,
        event_id,
        message.event_type,
        message.schema_version,
        aggregate_type,
        aggregate_id,
        aggregate_version,
        hashlib.sha256(message.canonical_bytes).digest(),
    )


def _set_local(connection: Any, name: str, value: str) -> None:
    connection.execute(
        "SELECT pg_catalog.set_config(%s,%s,true)",
        ("app." + name, value),
    )


def _utc(value: Any) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise OutboxPostgresUnavailable()
    return value.astimezone(timezone.utc)


def _uuid7() -> uuid.UUID:
    milliseconds = time.time_ns() // 1_000_000
    random_bits = int.from_bytes(secrets.token_bytes(10), "big")
    value = ((milliseconds & ((1 << 48) - 1)) << 80) | random_bits
    value &= ~(0xF << 76)
    value |= 0x7 << 76
    value &= ~(0x3 << 62)
    value |= 0x2 << 62
    return uuid.UUID(int=value)


def _valid_worker_id(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value))
    )


def _valid_application_name(value: Any) -> bool:
    return isinstance(value, str) and bool(_APPLICATION_NAME.fullmatch(value))


def acknowledge_is_bound(
    *,
    acknowledgement: OutboxPublishAcknowledgement,
    message: ValidatedOutboxMessage,
) -> bool:
    return acknowledgement.event_id == message.event_id


__all__ = [
    "BrokerConsumerDelivery",
    "BrokerSettlement",
    "CONSUMER_INBOX_POSTGRES_STATEMENT_NAMES",
    "ConsumerInboxPersistenceCode",
    "ConsumerInboxPostgresUnavailable",
    "ConsumerInboxResult",
    "ConsumerProjectionTransaction",
    "DurableConsumerHandler",
    "OUTBOX_POSTGRES_STATEMENT_NAMES",
    "OutboxPostgresPersistenceCode",
    "OutboxPostgresUnavailable",
    "PostgresConnectionDisposition",
    "PostgresConsumerInboxSettings",
    "PostgresDurableConsumerInbox",
    "PostgresOutboxRepository",
    "PostgresOutboxSettings",
    "acknowledge_is_bound",
]
