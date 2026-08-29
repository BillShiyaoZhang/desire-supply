"""Fixed PostgreSQL boundary for the INTERNAL_SANDBOX Demand review queue."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional, Protocol, Tuple
from uuid import UUID

import psycopg

from ...demand.adapters.postgres.migrations import (
    DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
    DEMAND_SCHEMA_HEAD_VERSION,
)
from .contracts import (
    EditorPrincipal,
    EditorReviewClaimDto,
    EditorReviewHistoryItemDto,
    EditorReviewQueueItemDto,
)


class DemandReviewQueueContractValidator(Protocol):
    def validate(self, value: Any, *, schema_name: str) -> None: ...


class DemandReviewQueueError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class DemandReviewQueueCommitOutcomeUnknownError(DemandReviewQueueError):
    def __init__(self) -> None:
        super().__init__("COMMAND_OUTCOME_UNKNOWN")


@dataclass(frozen=True)
class DemandReviewClaimRequest:
    principal: EditorPrincipal
    demand_id: UUID
    expected_demand_revision: int
    assignment_id: UUID
    receipt_id: UUID
    idempotency_key_digest_key_id: str
    idempotency_key_digest: bytes = field(repr=False)
    payload_hash_key_id: str
    payload_hash: bytes = field(repr=False)
    audit_event_id: UUID
    outbox_event_id: UUID
    correlation_id: UUID
    causation_id: UUID
    trace_id: UUID

    def __post_init__(self) -> None:
        identifiers = (
            self.demand_id,
            self.assignment_id,
            self.receipt_id,
            self.audit_event_id,
            self.outbox_event_id,
            self.correlation_id,
            self.causation_id,
            self.trace_id,
        )
        if (
            not isinstance(self.principal, EditorPrincipal)
            or any(not isinstance(value, UUID) or value.int == 0 for value in identifiers)
            or isinstance(self.expected_demand_revision, bool)
            or not isinstance(self.expected_demand_revision, int)
            or self.expected_demand_revision < 1
            or not _key_id(self.idempotency_key_digest_key_id)
            or not _digest(self.idempotency_key_digest)
            or not _key_id(self.payload_hash_key_id)
            or not _digest(self.payload_hash)
            or self.idempotency_key_digest_key_id == self.payload_hash_key_id
        ):
            raise ValueError("closed Demand review claim request is invalid")


class PsycopgDemandReviewQueue:
    """Allowlisted list/resolve/claim programs over the ``demand_review`` pool."""

    def __init__(
        self,
        *,
        connections: Any,
        event_validator: DemandReviewQueueContractValidator,
    ) -> None:
        if not all(
            callable(getattr(connections, name, None))
            for name in ("checkout", "release", "discard")
        ) or not callable(getattr(event_validator, "validate", None)):
            raise TypeError("Demand review queue dependencies are unavailable")
        self._connections = connections
        self._event_validator = event_validator
        self._closed = False

    def list_available(
        self, *, principal: EditorPrincipal
    ) -> Tuple[EditorReviewQueueItemDto, ...]:
        if self._closed:
            raise DemandReviewQueueError("SERVICE_UNAVAILABLE")
        _reviewer(principal)
        connection: Any = None
        transaction = False
        released = False
        try:
            connection = self._connections.checkout()
            _prepare(connection)
            connection.execute(
                "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
            )
            transaction = True
            _install_context(
                connection,
                principal=principal,
                operation="LIST_REVIEW_QUEUE",
            )
            rows = tuple(
                connection.execute(
                    "SELECT demand_id,demand_revision,demand_version_no,"
                    "submitted_at,demand_expires_at FROM "
                    "demand_api.list_available_demand_reviews_v1(%s,%s,%s,%s)",
                    (
                        UUID(principal.user_id),
                        UUID(principal.session_id),
                        principal.principal_marker_sha256,
                        100,
                    ),
                ).fetchall()
            )
            if len(rows) > 100 or any(len(row) != 5 for row in rows):
                raise DemandReviewQueueError("SERVICE_UNAVAILABLE")
            result = tuple(
                EditorReviewQueueItemDto(
                    demand_id=str(row[0]),
                    demand_revision=int(row[1]),
                    demand_version_no=int(row[2]),
                    submitted_at=_utc(row[3]),
                    demand_expires_at=_utc(row[4]),
                    etag=f'"demand-{int(row[1])}-review-queue"',
                )
                for row in rows
            )
            connection.execute("COMMIT")
            transaction = False
            _reset(connection)
            self._connections.release(connection)
            released = True
            return result
        except DemandReviewQueueError:
            raise
        except BaseException as error:
            if transaction:
                _rollback(connection)
            _discard(self._connections, connection)
            released = True
            if isinstance(error, (TypeError, ValueError, psycopg.Error)):
                raise DemandReviewQueueError("SERVICE_UNAVAILABLE") from None
            raise
        finally:
            if connection is not None and not released:
                _discard(self._connections, connection)

    def list_history(
        self,
        *,
        principal: EditorPrincipal,
        maximum_items: int,
        cursor_reviewed_at: Optional[datetime] = None,
        cursor_review_id: Optional[UUID] = None,
    ) -> Tuple[EditorReviewHistoryItemDto, ...]:
        """Read only this reviewer\'s terminal decisions in stable keyset order."""

        if self._closed:
            raise DemandReviewQueueError("SERVICE_UNAVAILABLE")
        _reviewer(principal)
        if (
            type(maximum_items) is not int
            or not 1 <= maximum_items <= 100
            or (cursor_reviewed_at is None) is not (cursor_review_id is None)
            or (
                cursor_reviewed_at is not None
                and (
                    _utc(cursor_reviewed_at) != cursor_reviewed_at
                    or not isinstance(cursor_review_id, UUID)
                    or cursor_review_id.int == 0
                )
            )
        ):
            raise ValueError("closed Demand review history request is invalid")
        connection: Any = None
        transaction = False
        released = False
        try:
            connection = self._connections.checkout()
            _prepare(connection)
            connection.execute(
                "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
            )
            transaction = True
            # The reviewed IAM capability names this read family
            # LIST_REVIEW_QUEUE.  Demand0011 changes app.operation to the
            # narrower LIST_REVIEW_HISTORY only after that capability succeeds.
            _install_context(
                connection,
                principal=principal,
                operation="LIST_REVIEW_QUEUE",
            )
            rows = tuple(
                connection.execute(
                    "SELECT review_id,demand_id,demand_version_id,decision,"
                    "reason_codes,required_field_codes,budget_health_code,"
                    "risk_code,reviewed_at FROM "
                    "demand_api.list_own_demand_review_history_v1("
                    "%s,%s,%s,%s,%s,%s)",
                    (
                        UUID(principal.user_id),
                        UUID(principal.session_id),
                        principal.principal_marker_sha256,
                        maximum_items,
                        cursor_reviewed_at,
                        cursor_review_id,
                    ),
                ).fetchall()
            )
            if len(rows) > maximum_items + 1 or any(len(row) != 9 for row in rows):
                raise DemandReviewQueueError("SERVICE_UNAVAILABLE")
            result = tuple(
                EditorReviewHistoryItemDto(
                    review_id=str(_uuid(row[0])),
                    demand_id=str(_uuid(row[1])),
                    demand_version_id=str(_uuid(row[2])),
                    decision=_text(row[3]),
                    reason_codes=_text_tuple(row[4]),
                    required_field_codes=_text_tuple(row[5]),
                    budget_health_code=_optional_text(row[6]),
                    risk_code=_optional_text(row[7]),
                    reviewed_at=_utc(row[8]),
                )
                for row in rows
            )
            connection.execute("COMMIT")
            transaction = False
            _reset(connection)
            self._connections.release(connection)
            released = True
            return result
        except DemandReviewQueueError:
            raise
        except BaseException as error:
            if transaction:
                _rollback(connection)
            _discard(self._connections, connection)
            released = True
            if isinstance(error, (TypeError, ValueError, psycopg.Error)):
                raise DemandReviewQueueError("SERVICE_UNAVAILABLE") from None
            raise
        finally:
            if connection is not None and not released:
                _discard(self._connections, connection)

    def claim(self, request: DemandReviewClaimRequest) -> EditorReviewClaimDto:
        if not isinstance(request, DemandReviewClaimRequest):
            raise ValueError("closed Demand review claim request is required")
        if self._closed:
            raise DemandReviewQueueError("SERVICE_UNAVAILABLE")
        _reviewer(request.principal)
        connection: Any = None
        transaction = False
        commit_sent = False
        released = False
        try:
            connection = self._connections.checkout()
            _prepare(connection)
            connection.execute("BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED")
            transaction = True
            _install_context(
                connection,
                principal=request.principal,
                operation="RESOLVE_REVIEW_QUEUE_TARGET",
                demand_id=request.demand_id,
            )
            target = connection.execute(
                "SELECT organization_id,demand_revision,demand_version_id,"
                "submission_id FROM demand_api.resolve_review_queue_target_v1("
                "%s,%s,%s,%s)",
                (
                    UUID(request.principal.user_id),
                    UUID(request.principal.session_id),
                    request.demand_id,
                    request.principal.principal_marker_sha256,
                ),
            ).fetchone()
            if target is None or len(target) != 4:
                raise DemandReviewQueueError("RESOURCE_NOT_FOUND")
            organization_id = _uuid(target[0])
            demand_revision = _positive_int(target[1])
            demand_version_id = _uuid(target[2])
            _uuid(target[3])
            if demand_revision != request.expected_demand_revision:
                raise DemandReviewQueueError("PRECONDITION_FAILED")

            _set_local(connection, "app.operation", "CLAIM_REVIEW")
            _set_local(connection, "app.organization_id", str(organization_id))
            occurred_at = _utc(
                connection.execute("SELECT transaction_timestamp()").fetchone()[0]
            )
            self._event_validator.validate(
                {
                    "event_id": str(request.outbox_event_id),
                    "event_type": "DemandReviewClaimed",
                    "schema_version": 1,
                    "occurred_at": _rfc3339_z(occurred_at),
                    "aggregate_type": "Demand",
                    "aggregate_id": str(request.demand_id),
                    "aggregate_version": demand_revision,
                    "actor_kind": "USER",
                    "actor_id": request.principal.user_id,
                    "original_actor_id": None,
                    "correlation_id": str(request.correlation_id),
                    "causation_id": str(request.causation_id),
                    "trace_id": str(request.trace_id),
                    "organization_id": str(organization_id),
                    "payload": {
                        "demand_id": str(request.demand_id),
                        "demand_version_id": str(demand_version_id),
                        "status": "SUBMITTED",
                    },
                },
                schema_name="demand-v1",
            )
            row = connection.execute(
                "SELECT assignment_id,demand_id,demand_revision,"
                "assignment_status,assignment_expires_at,response_entity_tag,"
                "replayed FROM demand_api.claim_demand_review_v1("
                "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (
                    UUID(request.principal.user_id),
                    UUID(request.principal.session_id),
                    organization_id,
                    request.demand_id,
                    demand_revision,
                    request.principal.principal_marker_sha256,
                    request.assignment_id,
                    request.receipt_id,
                    request.idempotency_key_digest_key_id,
                    request.idempotency_key_digest,
                    request.payload_hash_key_id,
                    request.payload_hash,
                    request.audit_event_id,
                    request.outbox_event_id,
                    request.correlation_id,
                    request.causation_id,
                    request.trace_id,
                ),
            ).fetchone()
            if row is None or len(row) != 7:
                raise DemandReviewQueueError("RESOURCE_NOT_FOUND")
            result = EditorReviewClaimDto(
                assignment_id=str(row[0]),
                demand_id=str(row[1]),
                demand_revision=int(row[2]),
                status=str(row[3]),
                expires_at=_utc(row[4]),
                etag=str(row[5]),
                replayed=row[6],
            )
            if (
                result.assignment_id != str(request.assignment_id)
                and not result.replayed
            ) or result.demand_id != str(request.demand_id):
                raise DemandReviewQueueError("SERVICE_UNAVAILABLE")
            commit_sent = True
            connection.execute("COMMIT")
            transaction = False
            _reset(connection)
            self._connections.release(connection)
            released = True
            return result
        except psycopg.Error as error:
            if commit_sent:
                _discard(self._connections, connection)
                released = True
                raise DemandReviewQueueCommitOutcomeUnknownError() from None
            if transaction:
                _rollback(connection)
            _discard(self._connections, connection)
            released = True
            raise DemandReviewQueueError(_database_code(error)) from None
        except DemandReviewQueueError:
            if transaction:
                _rollback(connection)
            _discard(self._connections, connection)
            released = True
            raise
        except BaseException:
            if transaction:
                _rollback(connection)
            _discard(self._connections, connection)
            released = True
            raise DemandReviewQueueError("SERVICE_UNAVAILABLE") from None
        finally:
            if connection is not None and not released:
                _discard(self._connections, connection)

    def check_readiness(self, *, timeout_ms: int) -> None:
        if self._closed or type(timeout_ms) is not int or not 1 <= timeout_ms <= 30_000:
            raise RuntimeError("DEMAND_REVIEW_QUEUE_NOT_READY")
        connection: Any = None
        try:
            connection = self._connections.checkout()
            _prepare(connection)
            row = connection.execute(
                "SELECT pg_catalog.to_regprocedure("
                "'demand_api.list_available_demand_reviews_v1(uuid,uuid,bytea,integer)'"
                ") IS NOT NULL,pg_catalog.to_regprocedure("
                "'demand_api.resolve_review_queue_target_v1(uuid,uuid,uuid,bytea)'"
                ") IS NOT NULL,pg_catalog.to_regprocedure("
                "'demand_api.claim_demand_review_v1(uuid,uuid,uuid,uuid,bigint,bytea,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid,uuid)'"
                ") IS NOT NULL,pg_catalog.to_regprocedure("
                "'demand_api.list_own_demand_review_history_v1(uuid,uuid,bytea,integer,timestamptz,uuid)'"
                ") IS NOT NULL"
            ).fetchone()
            if row != (True, True, True, True):
                raise RuntimeError("review queue functions are unavailable")
            _reset(connection)
            self._connections.release(connection)
            connection = None
        except BaseException:
            if connection is not None:
                _discard(self._connections, connection)
            raise RuntimeError("DEMAND_REVIEW_QUEUE_NOT_READY") from None

    def close(self) -> None:
        self._closed = True


def _prepare(connection: Any) -> None:
    _reset(connection)
    identity = connection.execute(
        "SELECT session_user,current_user,"
        "current_setting('server_version_num')::integer/10000"
    ).fetchone()
    compatibility = connection.execute(
        "SELECT component,current_schema_version,schema_head_version,"
        "min_app_compatible_version,max_app_compatible_version,"
        "required_iam_schema_version FROM demand.schema_compatibility"
    ).fetchone()
    if identity != ("demand_review", "demand_review", 18) or compatibility != (
        "demand",
        DEMAND_SCHEMA_HEAD_VERSION,
        DEMAND_SCHEMA_HEAD_VERSION,
        DEMAND_SCHEMA_HEAD_VERSION,
        DEMAND_SCHEMA_HEAD_VERSION,
        DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
    ):
        raise DemandReviewQueueError("SERVICE_UNAVAILABLE")


def _install_context(
    connection: Any,
    *,
    principal: EditorPrincipal,
    operation: str,
    demand_id: Optional[UUID] = None,
) -> None:
    for name, value in (
        ("TimeZone", "UTC"),
        ("lock_timeout", "2s"),
        ("statement_timeout", "10s"),
        ("idle_in_transaction_session_timeout", "15s"),
        ("app.scope_kind", "DEMAND_REVIEW"),
        ("app.operation", operation),
        ("app.actor_id", principal.user_id),
        ("app.session_id", principal.session_id),
        ("app.organization_id", ""),
        ("app.demand_id", "" if demand_id is None else str(demand_id)),
        ("app.assignment_id", ""),
    ):
        _set_local(connection, name, value)


def _set_local(connection: Any, name: str, value: str) -> None:
    installed = connection.execute(
        "SELECT pg_catalog.set_config(%s,%s,true)", (name, value)
    ).fetchone()
    if installed != (value,):
        raise DemandReviewQueueError("SERVICE_UNAVAILABLE")


def _reset(connection: Any) -> None:
    connection.execute("RESET ROLE")
    connection.execute("RESET ALL")
    connection.execute("DISCARD TEMP")


def _rollback(connection: Any) -> None:
    try:
        connection.execute("ROLLBACK")
    except BaseException:
        pass


def _discard(source: Any, connection: Any) -> None:
    if connection is not None:
        try:
            source.discard(connection)
        except BaseException:
            pass


def _reviewer(principal: EditorPrincipal) -> None:
    if (
        not isinstance(principal, EditorPrincipal)
        or principal.workspace_kind != "PLATFORM"
        or "OPERATIONS_REVIEWER" not in principal.role_codes
        or "OPERATIONS_REVIEWER" not in principal.platform_duty_codes
        or principal.organization_id is not None
        or not _digest(principal.principal_marker_sha256)
    ):
        raise DemandReviewQueueError("RESOURCE_NOT_FOUND")


def _database_code(error: psycopg.Error) -> str:
    constraint = getattr(getattr(error, "diag", None), "constraint_name", None)
    if constraint == "review_claim_idempotency_reused":
        return "IDEMPOTENCY_KEY_REUSED"
    if constraint == "review_already_claimed":
        return "REVIEW_ALREADY_CLAIMED"
    if constraint == "uq_demand_active_review_assignment":
        return "REVIEW_ALREADY_CLAIMED"
    if constraint == "review_claim_precondition_failed":
        return "PRECONDITION_FAILED"
    if constraint == "review_claim_resource_not_found":
        return "RESOURCE_NOT_FOUND"
    if constraint == "review_claim_conflict_declared":
        return "RESOURCE_NOT_FOUND"
    return "SERVICE_UNAVAILABLE"


def _uuid(value: Any) -> UUID:
    if not isinstance(value, UUID) or value.int == 0:
        raise DemandReviewQueueError("SERVICE_UNAVAILABLE")
    return value


def _positive_int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise DemandReviewQueueError("SERVICE_UNAVAILABLE")
    return value


def _text(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise DemandReviewQueueError("SERVICE_UNAVAILABLE")
    return value


def _optional_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    return _text(value)


def _text_tuple(value: Any) -> Tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise DemandReviewQueueError("SERVICE_UNAVAILABLE")
    return tuple(value)


def _utc(value: Any) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise DemandReviewQueueError("SERVICE_UNAVAILABLE")
    try:
        if value.utcoffset() is None:
            raise ValueError
        return value.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        raise DemandReviewQueueError("SERVICE_UNAVAILABLE") from None


def _rfc3339_z(value: datetime) -> str:
    return _utc(value).isoformat().replace("+00:00", "Z")


def _digest(value: Any) -> bool:
    return isinstance(value, bytes) and len(value) == 32


def _key_id(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 128
        and value[0].isalnum()
        and all(character.isalnum() or character in "._:-" for character in value)
    )


__all__ = [
    "DemandReviewClaimRequest",
    "DemandReviewQueueCommitOutcomeUnknownError",
    "DemandReviewQueueError",
    "PsycopgDemandReviewQueue",
]
