"""PostgreSQL boundaries for exact Session revocation.

The frozen IAM36 current-Session adapter and the IAM38 owned-Session adapter
each invoke one reviewed ``SECURITY DEFINER`` program.  Neither can express
``RevokeAllSessions``, a SessionFamily revocation, or a direct table mutation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Mapping, Optional, Protocol
from uuid import UUID

from psycopg.pq import TransactionStatus

from ...domain.errors import IamError


CURRENT_SESSION_LOGOUT_FUNCTION_SIGNATURE = (
    "iam_api.revoke_current_session_v1(uuid,uuid,uuid,uuid,uuid,uuid,bytea,text,"
    "bytea,text,text,timestamp with time zone,uuid,uuid)"
)
OWNED_SESSION_REVOCATION_FUNCTION_SIGNATURE = (
    "iam_api.revoke_owned_session_v1(uuid,uuid,uuid,uuid,uuid,uuid,uuid,bytea,text,"
    "bytea,text,text,timestamp with time zone,uuid,uuid)"
)
_FUNCTION = "iam_api.revoke_current_session_v1"
_CANONICALIZATION_VERSION = "restricted-canonical-json-v1"
_IDEMPOTENCY_KEY_ID = "iam-receipt-idempotency-hmac-2026-01"
_PAYLOAD_HASH_KEY_ID = "iam-receipt-payload-hmac-2026-01"
_RESULT_KEYS = frozenset(
    (
        "outcome",
        "session_id",
        "session_family_id",
        "session_status",
        "session_version",
        "replayed",
        "clear_current_session_cookie",
    )
)


class CurrentSessionLogoutPostgresConnectionSource(Protocol):
    def checkout(self) -> Any: ...

    def release(self, connection: Any) -> None: ...

    def discard(self, connection: Any) -> None: ...


class CurrentSessionLogoutPostgresConfigurationError(RuntimeError):
    """The PostgreSQL identity, state, or fixed-program result is unsafe."""


class CurrentSessionLogoutPostgresCommitOutcomeUnknownError(RuntimeError):
    """COMMIT was sent, so only an exact same-key replay may recover."""

    code = "COMMAND_OUTCOME_UNKNOWN"


@dataclass(frozen=True)
class CurrentSessionLogoutPostgresSettings:
    runtime_role: str = "iam_app"
    lock_timeout_ms: int = 2_000
    statement_timeout_ms: int = 10_000
    idle_in_transaction_timeout_ms: int = 15_000
    max_precommit_retries: int = 3

    def __post_init__(self) -> None:
        if self.runtime_role != "iam_app":
            raise ValueError("current Session logout runtime role must be iam_app")
        if not 1 <= self.lock_timeout_ms <= 10_000:
            raise ValueError("current Session logout lock timeout is invalid")
        if not 1 <= self.statement_timeout_ms <= 30_000:
            raise ValueError("current Session logout statement timeout is invalid")
        if not 1 <= self.idle_in_transaction_timeout_ms <= 30_000:
            raise ValueError("current Session logout idle timeout is invalid")
        if self.max_precommit_retries != 3:
            raise ValueError("current Session logout retry count must be exactly 3")


@dataclass(frozen=True)
class CurrentSessionLogoutPostgresExecutionScope:
    actor_user_id: UUID
    current_session_id: UUID
    target_session_id: UUID
    command_id: UUID
    correlation_id: UUID
    causation_id: UUID
    trace_id: UUID
    original_actor_id: Optional[UUID]

    def __post_init__(self) -> None:
        required = (
            self.actor_user_id,
            self.current_session_id,
            self.target_session_id,
            self.command_id,
            self.correlation_id,
            self.causation_id,
            self.trace_id,
        )
        if any(not isinstance(value, UUID) or value.int == 0 for value in required):
            raise ValueError("current Session logout scope IDs must be non-zero UUIDs")
        if self.target_session_id != self.current_session_id:
            raise ValueError("logout target must be the current Session")
        if self.causation_id != self.command_id:
            raise ValueError("current Session logout causation must be the command")
        if self.original_actor_id is not None:
            raise ValueError("current Session logout forbids an original actor")


@dataclass(frozen=True)
class CurrentSessionLogoutPostgresReceiptMaterial:
    receipt_id: UUID
    idempotency_key_digest: bytes = field(repr=False)
    idempotency_key_digest_key_id: str
    payload_hash: bytes = field(repr=False)
    payload_hash_key_id: str
    canonicalization_version: str
    retain_until: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.receipt_id, UUID) or self.receipt_id.int == 0:
            raise ValueError("current Session logout receipt ID is invalid")
        if not isinstance(self.idempotency_key_digest, bytes) or len(
            self.idempotency_key_digest
        ) != 32:
            raise ValueError("current Session logout idempotency digest is invalid")
        if not isinstance(self.payload_hash, bytes) or len(self.payload_hash) != 32:
            raise ValueError("current Session logout payload digest is invalid")
        if self.idempotency_key_digest_key_id != _IDEMPOTENCY_KEY_ID:
            raise ValueError("current Session logout idempotency key ID is invalid")
        if self.payload_hash_key_id != _PAYLOAD_HASH_KEY_ID:
            raise ValueError("current Session logout payload key ID is invalid")
        if self.canonicalization_version != _CANONICALIZATION_VERSION:
            raise ValueError("current Session logout canonicalization is invalid")
        _require_utc(self.retain_until, "current Session logout retention")


@dataclass(frozen=True)
class CurrentSessionLogoutPostgresGeneratedIds:
    audit_event_id: UUID
    outbox_event_id: UUID

    def __post_init__(self) -> None:
        if (
            not isinstance(self.audit_event_id, UUID)
            or self.audit_event_id.int == 0
            or not isinstance(self.outbox_event_id, UUID)
            or self.outbox_event_id.int == 0
            or self.audit_event_id == self.outbox_event_id
        ):
            raise ValueError("current Session logout generated IDs are invalid")


@dataclass(frozen=True)
class CurrentSessionLogoutPostgresDatabaseRequest:
    scope: CurrentSessionLogoutPostgresExecutionScope
    receipt: CurrentSessionLogoutPostgresReceiptMaterial
    generated_ids: CurrentSessionLogoutPostgresGeneratedIds

    def __post_init__(self) -> None:
        if not isinstance(self.scope, CurrentSessionLogoutPostgresExecutionScope):
            raise TypeError("current Session logout scope is unavailable")
        if not isinstance(self.receipt, CurrentSessionLogoutPostgresReceiptMaterial):
            raise TypeError("current Session logout receipt is unavailable")
        if not isinstance(self.generated_ids, CurrentSessionLogoutPostgresGeneratedIds):
            raise TypeError("current Session logout generated IDs are unavailable")
        if self.receipt.receipt_id != self.scope.command_id:
            raise ValueError("current Session logout receipt must be the command")
        all_ids = (
            self.scope.command_id,
            self.generated_ids.audit_event_id,
            self.generated_ids.outbox_event_id,
        )
        if len(set(all_ids)) != len(all_ids):
            raise ValueError("current Session logout write IDs must be distinct")


@dataclass(frozen=True)
class CurrentSessionLogoutPostgresDatabaseResult:
    session_id: UUID
    session_family_id: UUID
    session_status: str
    session_version: int
    replayed: bool
    clear_current_session_cookie: bool


class PsycopgCurrentSessionLogoutUnitOfWorkFactory:
    """Call only the exact current-Session logout fixed program."""

    def __init__(
        self,
        *,
        connections: CurrentSessionLogoutPostgresConnectionSource,
        settings: CurrentSessionLogoutPostgresSettings = (
            CurrentSessionLogoutPostgresSettings()
        ),
    ) -> None:
        if not all(
            callable(getattr(connections, name, None))
            for name in ("checkout", "release", "discard")
        ):
            raise TypeError("current Session logout connections are unavailable")
        if not isinstance(settings, CurrentSessionLogoutPostgresSettings):
            raise TypeError("current Session logout settings are unavailable")
        self.connections = connections
        self.settings = settings

    def execute(
        self, request: CurrentSessionLogoutPostgresDatabaseRequest
    ) -> CurrentSessionLogoutPostgresDatabaseResult:
        if not isinstance(request, CurrentSessionLogoutPostgresDatabaseRequest):
            raise TypeError("current Session logout request is unavailable")
        for attempt in range(self.settings.max_precommit_retries + 1):
            try:
                return self._execute_once(request)
            except BaseException as error:
                if attempt < self.settings.max_precommit_retries and _retryable(error):
                    continue
                raise
        raise AssertionError("closed current Session logout retry loop did not terminate")

    def _execute_once(
        self, request: CurrentSessionLogoutPostgresDatabaseRequest
    ) -> CurrentSessionLogoutPostgresDatabaseResult:
        connection = self.connections.checkout()
        state = "NEW"
        disposed = False
        try:
            self._validate_connection(connection)
            connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED")
            state = "BEGUN"
            self._configure(connection, request)
            state = "WRITING"
            row = connection.execute(
                "SELECT iam_api.revoke_current_session_v1("
                "%s::uuid,%s::uuid,%s::uuid,%s::uuid,%s::uuid,%s::uuid,"
                "%s::bytea,%s::text,%s::bytea,%s::text,%s::text,"
                "%s::timestamptz,%s::uuid,%s::uuid)",
                _parameters(request),
            ).fetchone()
            result = _result(request, row)
            state = "COMMIT_SENT"
            connection.execute("COMMIT")
            state = "COMMITTED"
        except BaseException as error:
            if state == "COMMIT_SENT":
                self.connections.discard(connection)
                disposed = True
                raise CurrentSessionLogoutPostgresCommitOutcomeUnknownError() from error
            if state in {"BEGUN", "WRITING"}:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    self.connections.discard(connection)
                    disposed = True
                else:
                    disposed = self._release_or_discard(connection)
            else:
                self.connections.discard(connection)
                disposed = True
            translated = _database_error(error)
            if translated is not None:
                raise translated from None
            raise
        else:
            disposed = self._release_or_discard(connection)
            return result
        finally:
            if not disposed:
                self.connections.discard(connection)

    def _validate_connection(self, connection: Any) -> None:
        if (
            getattr(connection, "autocommit", None) is not True
            or connection.info.transaction_status != TransactionStatus.IDLE
        ):
            raise CurrentSessionLogoutPostgresConfigurationError(
                "current Session logout checkout must be transaction-idle"
            )
        identity = connection.execute(
            "SELECT current_user,session_user,"
            "current_setting('server_version_num')::integer"
        ).fetchone()
        if identity is None or identity[0:2] != (
            self.settings.runtime_role,
            self.settings.runtime_role,
        ) or identity[2] // 10_000 != 18:
            raise CurrentSessionLogoutPostgresConfigurationError(
                "current Session logout connection identity is invalid"
            )

    def _configure(
        self, connection: Any, request: CurrentSessionLogoutPostgresDatabaseRequest
    ) -> None:
        connection.execute("SET LOCAL TIME ZONE 'UTC'")
        connection.execute(
            "SET LOCAL lock_timeout = '%dms'" % self.settings.lock_timeout_ms
        )
        connection.execute(
            "SET LOCAL statement_timeout = '%dms'"
            % self.settings.statement_timeout_ms
        )
        connection.execute(
            "SET LOCAL idle_in_transaction_session_timeout = '%dms'"
            % self.settings.idle_in_transaction_timeout_ms
        )
        values = (
            ("app.scope_kind", "SELF"),
            ("app.operation", "REVOKE_CURRENT_SESSION"),
            ("app.actor_user_id", str(request.scope.actor_user_id)),
            ("app.session_id", str(request.scope.current_session_id)),
            ("app.target_session_id", str(request.scope.target_session_id)),
            ("app.command_id", str(request.scope.command_id)),
        )
        for name, value in values:
            configured = connection.execute(
                "SELECT pg_catalog.set_config(%s,%s,true)", (name, value)
            ).fetchone()
            if configured != (value,):
                raise CurrentSessionLogoutPostgresConfigurationError(
                    "current Session logout context was rejected"
                )
        for name, expected in values:
            actual = connection.execute(
                "SELECT current_setting(%s,true)", (name,)
            ).fetchone()
            if actual != (expected,):
                raise CurrentSessionLogoutPostgresConfigurationError(
                    "current Session logout context readback failed"
                )

    def _release_or_discard(self, connection: Any) -> bool:
        try:
            if connection.info.transaction_status != TransactionStatus.IDLE:
                self.connections.discard(connection)
                return True
            connection.execute("RESET ALL")
            connection.execute("DISCARD TEMP")
            clean = connection.execute(
                "SELECT current_user,session_user,"
                "current_setting('app.scope_kind',true)"
            ).fetchone()
            if clean not in (
                (self.settings.runtime_role, self.settings.runtime_role, None),
                (self.settings.runtime_role, self.settings.runtime_role, ""),
            ):
                self.connections.discard(connection)
                return True
        except BaseException:
            self.connections.discard(connection)
            return True
        self.connections.release(connection)
        return True


@dataclass(frozen=True)
class OwnedSessionRevocationPostgresExecutionScope:
    """Closed SELF scope for revoking one Session owned by the actor."""

    actor_user_id: UUID
    current_session_id: UUID
    target_session_id: UUID
    command_id: UUID
    correlation_id: UUID
    causation_id: UUID
    trace_id: UUID
    original_actor_id: Optional[UUID]

    def __post_init__(self) -> None:
        required = (
            self.actor_user_id,
            self.current_session_id,
            self.target_session_id,
            self.command_id,
            self.correlation_id,
            self.causation_id,
            self.trace_id,
        )
        if any(not isinstance(value, UUID) or value.int == 0 for value in required):
            raise ValueError("owned Session revocation IDs must be non-zero UUIDs")
        if self.causation_id != self.command_id:
            raise ValueError("owned Session revocation causation must be the command")
        if self.original_actor_id is not None:
            raise ValueError("owned Session revocation forbids an original actor")


@dataclass(frozen=True)
class OwnedSessionRevocationPostgresDatabaseRequest:
    scope: OwnedSessionRevocationPostgresExecutionScope
    receipt: CurrentSessionLogoutPostgresReceiptMaterial
    generated_ids: CurrentSessionLogoutPostgresGeneratedIds

    def __post_init__(self) -> None:
        if not isinstance(self.scope, OwnedSessionRevocationPostgresExecutionScope):
            raise TypeError("owned Session revocation scope is unavailable")
        if not isinstance(self.receipt, CurrentSessionLogoutPostgresReceiptMaterial):
            raise TypeError("owned Session revocation receipt is unavailable")
        if not isinstance(self.generated_ids, CurrentSessionLogoutPostgresGeneratedIds):
            raise TypeError("owned Session revocation generated IDs are unavailable")
        if self.receipt.receipt_id != self.scope.command_id:
            raise ValueError("owned Session revocation receipt must be the command")
        all_ids = (
            self.scope.command_id,
            self.generated_ids.audit_event_id,
            self.generated_ids.outbox_event_id,
        )
        if len(set(all_ids)) != len(all_ids):
            raise ValueError("owned Session revocation write IDs must be distinct")


@dataclass(frozen=True)
class OwnedSessionRevocationPostgresDatabaseResult:
    current_session_id: UUID
    session_id: UUID
    session_family_id: UUID
    session_status: str
    session_version: int
    replayed: bool
    clear_current_session_cookie: bool


class PsycopgOwnedSessionRevocationUnitOfWorkFactory(
    PsycopgCurrentSessionLogoutUnitOfWorkFactory
):
    """Call only the exact owned-Session revocation fixed program."""

    def execute(
        self, request: OwnedSessionRevocationPostgresDatabaseRequest
    ) -> OwnedSessionRevocationPostgresDatabaseResult:
        if not isinstance(request, OwnedSessionRevocationPostgresDatabaseRequest):
            raise TypeError("owned Session revocation request is unavailable")
        for attempt in range(self.settings.max_precommit_retries + 1):
            try:
                return self._execute_owned_once(request)
            except BaseException as error:
                if attempt < self.settings.max_precommit_retries and _retryable(error):
                    continue
                raise
        raise AssertionError("closed owned Session revocation retry loop did not terminate")

    def _execute_owned_once(
        self, request: OwnedSessionRevocationPostgresDatabaseRequest
    ) -> OwnedSessionRevocationPostgresDatabaseResult:
        connection = self.connections.checkout()
        state = "NEW"
        disposed = False
        try:
            self._validate_connection(connection)
            connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED")
            state = "BEGUN"
            self._configure_owned(connection, request)
            state = "WRITING"
            row = connection.execute(
                "SELECT iam_api.revoke_owned_session_v1("
                "%s::uuid,%s::uuid,%s::uuid,%s::uuid,%s::uuid,%s::uuid,"
                "%s::uuid,%s::bytea,%s::text,%s::bytea,%s::text,%s::text,"
                "%s::timestamptz,%s::uuid,%s::uuid)",
                _owned_parameters(request),
            ).fetchone()
            result = _owned_result(request, row)
            state = "COMMIT_SENT"
            connection.execute("COMMIT")
            state = "COMMITTED"
        except BaseException as error:
            if state == "COMMIT_SENT":
                self.connections.discard(connection)
                disposed = True
                raise CurrentSessionLogoutPostgresCommitOutcomeUnknownError() from error
            if state in {"BEGUN", "WRITING"}:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    self.connections.discard(connection)
                    disposed = True
                else:
                    disposed = self._release_or_discard(connection)
            else:
                self.connections.discard(connection)
                disposed = True
            translated = _owned_database_error(error)
            if translated is not None:
                raise translated from None
            raise
        else:
            disposed = self._release_or_discard(connection)
            return result
        finally:
            if not disposed:
                self.connections.discard(connection)

    def _configure_owned(
        self,
        connection: Any,
        request: OwnedSessionRevocationPostgresDatabaseRequest,
    ) -> None:
        connection.execute("SET LOCAL TIME ZONE 'UTC'")
        connection.execute(
            "SET LOCAL lock_timeout = '%dms'" % self.settings.lock_timeout_ms
        )
        connection.execute(
            "SET LOCAL statement_timeout = '%dms'"
            % self.settings.statement_timeout_ms
        )
        connection.execute(
            "SET LOCAL idle_in_transaction_session_timeout = '%dms'"
            % self.settings.idle_in_transaction_timeout_ms
        )
        values = (
            ("app.scope_kind", "SELF"),
            ("app.operation", "REVOKE_SESSION"),
            ("app.actor_user_id", str(request.scope.actor_user_id)),
            ("app.session_id", str(request.scope.current_session_id)),
            ("app.target_session_id", str(request.scope.target_session_id)),
            ("app.command_id", str(request.scope.command_id)),
        )
        for name, value in values:
            configured = connection.execute(
                "SELECT pg_catalog.set_config(%s,%s,true)", (name, value)
            ).fetchone()
            if configured != (value,):
                raise CurrentSessionLogoutPostgresConfigurationError(
                    "owned Session revocation context was rejected"
                )
        for name, expected in values:
            actual = connection.execute(
                "SELECT current_setting(%s,true)", (name,)
            ).fetchone()
            if actual != (expected,):
                raise CurrentSessionLogoutPostgresConfigurationError(
                    "owned Session revocation context readback failed"
                )


def _parameters(request: CurrentSessionLogoutPostgresDatabaseRequest) -> tuple[Any, ...]:
    return (
        request.scope.actor_user_id,
        request.scope.current_session_id,
        request.scope.command_id,
        request.scope.correlation_id,
        request.scope.causation_id,
        request.scope.trace_id,
        request.receipt.idempotency_key_digest,
        request.receipt.idempotency_key_digest_key_id,
        request.receipt.payload_hash,
        request.receipt.payload_hash_key_id,
        request.receipt.canonicalization_version,
        request.receipt.retain_until,
        request.generated_ids.audit_event_id,
        request.generated_ids.outbox_event_id,
    )


def _owned_parameters(
    request: OwnedSessionRevocationPostgresDatabaseRequest,
) -> tuple[Any, ...]:
    return (
        request.scope.actor_user_id,
        request.scope.current_session_id,
        request.scope.target_session_id,
        request.scope.command_id,
        request.scope.correlation_id,
        request.scope.causation_id,
        request.scope.trace_id,
        request.receipt.idempotency_key_digest,
        request.receipt.idempotency_key_digest_key_id,
        request.receipt.payload_hash,
        request.receipt.payload_hash_key_id,
        request.receipt.canonicalization_version,
        request.receipt.retain_until,
        request.generated_ids.audit_event_id,
        request.generated_ids.outbox_event_id,
    )


def _result(
    request: CurrentSessionLogoutPostgresDatabaseRequest, row: Any
) -> CurrentSessionLogoutPostgresDatabaseResult:
    if row is None or len(row) != 1 or not isinstance(row[0], Mapping):
        raise CurrentSessionLogoutPostgresConfigurationError(
            "current Session logout result is unavailable"
        )
    payload = row[0]
    if set(payload) != _RESULT_KEYS:
        raise CurrentSessionLogoutPostgresConfigurationError(
            "current Session logout result shape is invalid"
        )
    try:
        session_id = UUID(str(payload["session_id"]))
        family_id = UUID(str(payload["session_family_id"]))
    except (TypeError, ValueError):
        raise CurrentSessionLogoutPostgresConfigurationError(
            "current Session logout result identity is invalid"
        ) from None
    replayed = payload["replayed"]
    outcome = payload["outcome"]
    session_status = payload["session_status"]
    version = payload["session_version"]
    terminal_outcome = (
        outcome == "REPLAYED"
        if replayed is True
        else (outcome, session_status)
        in {
            ("REVOKED", "REVOKED"),
            ("EXPIRED", "EXPIRED"),
            ("ALREADY_TERMINAL", "REVOKED"),
            ("ALREADY_TERMINAL", "EXPIRED"),
        }
    )
    if (
        session_id != request.scope.current_session_id
        or family_id.int == 0
        or session_status not in {"REVOKED", "EXPIRED"}
        or not isinstance(replayed, bool)
        or not terminal_outcome
        or not isinstance(version, int)
        or isinstance(version, bool)
        or version < 1
        or payload["clear_current_session_cookie"] is not True
    ):
        raise CurrentSessionLogoutPostgresConfigurationError(
            "current Session logout result proof is invalid"
        )
    return CurrentSessionLogoutPostgresDatabaseResult(
        session_id=session_id,
        session_family_id=family_id,
        session_status=session_status,
        session_version=version,
        replayed=replayed,
        clear_current_session_cookie=True,
    )


def _database_error(error: BaseException) -> Optional[IamError]:
    constraint = getattr(getattr(error, "diag", None), "constraint_name", None)
    code = {
        "ck_current_session_logout_authentication": "AUTHENTICATION_REQUIRED",
        "ck_current_session_logout_expired": "SESSION_EXPIRED",
        "ck_current_session_logout_idempotency_reused": "IDEMPOTENCY_KEY_REUSED",
        "ck_current_session_logout_in_progress": "COMMAND_IN_PROGRESS",
        "ck_current_session_logout_key_policy": "POLICY_CONFIGURATION_UNAVAILABLE",
        "ck_current_session_logout_context": "SERVICE_UNAVAILABLE",
    }.get(constraint)
    return None if code is None else IamError(code)


_OWNED_RESULT_KEYS = frozenset(
    (
        "outcome",
        "current_session_id",
        "session_id",
        "session_family_id",
        "session_status",
        "session_version",
        "replayed",
        "clear_current_session_cookie",
    )
)


def _owned_result(
    request: OwnedSessionRevocationPostgresDatabaseRequest, row: Any
) -> OwnedSessionRevocationPostgresDatabaseResult:
    if row is None or len(row) != 1 or not isinstance(row[0], Mapping):
        raise CurrentSessionLogoutPostgresConfigurationError(
            "owned Session revocation result is unavailable"
        )
    payload = row[0]
    if set(payload) != _OWNED_RESULT_KEYS:
        raise CurrentSessionLogoutPostgresConfigurationError(
            "owned Session revocation result shape is invalid"
        )
    try:
        current_session_id = UUID(str(payload["current_session_id"]))
        session_id = UUID(str(payload["session_id"]))
        family_id = UUID(str(payload["session_family_id"]))
    except (TypeError, ValueError):
        raise CurrentSessionLogoutPostgresConfigurationError(
            "owned Session revocation result identity is invalid"
        ) from None
    replayed = payload["replayed"]
    outcome = payload["outcome"]
    session_status = payload["session_status"]
    version = payload["session_version"]
    clear_cookie = payload["clear_current_session_cookie"]
    terminal_outcome = (
        outcome == "REPLAYED"
        if replayed is True
        else (outcome, session_status)
        in {
            ("REVOKED", "REVOKED"),
            ("EXPIRED", "EXPIRED"),
            ("ALREADY_TERMINAL", "REVOKED"),
            ("ALREADY_TERMINAL", "EXPIRED"),
        }
    )
    expected_clear = request.scope.target_session_id == request.scope.current_session_id
    if (
        current_session_id != request.scope.current_session_id
        or session_id != request.scope.target_session_id
        or family_id.int == 0
        or session_status not in {"REVOKED", "EXPIRED"}
        or not isinstance(replayed, bool)
        or not terminal_outcome
        or not isinstance(version, int)
        or isinstance(version, bool)
        or version < 1
        or not isinstance(clear_cookie, bool)
        or clear_cookie is not expected_clear
    ):
        raise CurrentSessionLogoutPostgresConfigurationError(
            "owned Session revocation result proof is invalid"
        )
    return OwnedSessionRevocationPostgresDatabaseResult(
        current_session_id=current_session_id,
        session_id=session_id,
        session_family_id=family_id,
        session_status=session_status,
        session_version=version,
        replayed=replayed,
        clear_current_session_cookie=clear_cookie,
    )


def _owned_database_error(error: BaseException) -> Optional[IamError]:
    constraint = getattr(getattr(error, "diag", None), "constraint_name", None)
    code = {
        "ck_owned_session_revocation_authentication": "AUTHENTICATION_REQUIRED",
        "ck_owned_session_revocation_expired": "SESSION_EXPIRED",
        "ck_owned_session_revocation_target_unavailable": "RESOURCE_NOT_FOUND",
        "ck_owned_session_revocation_idempotency_reused": "IDEMPOTENCY_KEY_REUSED",
        "ck_owned_session_revocation_in_progress": "COMMAND_IN_PROGRESS",
        "ck_owned_session_revocation_key_policy": (
            "POLICY_CONFIGURATION_UNAVAILABLE"
        ),
        "ck_owned_session_revocation_context": "SERVICE_UNAVAILABLE",
    }.get(constraint)
    return None if code is None else IamError(code)


def _retryable(error: BaseException) -> bool:
    return getattr(error, "sqlstate", None) in {"40001", "40P01", "55P03"}


def _require_utc(value: Any, label: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise ValueError(f"{label} must be UTC")
    return value


__all__ = [
    "CURRENT_SESSION_LOGOUT_FUNCTION_SIGNATURE",
    "OWNED_SESSION_REVOCATION_FUNCTION_SIGNATURE",
    "CurrentSessionLogoutPostgresCommitOutcomeUnknownError",
    "CurrentSessionLogoutPostgresConfigurationError",
    "CurrentSessionLogoutPostgresDatabaseRequest",
    "CurrentSessionLogoutPostgresDatabaseResult",
    "CurrentSessionLogoutPostgresExecutionScope",
    "CurrentSessionLogoutPostgresGeneratedIds",
    "CurrentSessionLogoutPostgresReceiptMaterial",
    "CurrentSessionLogoutPostgresSettings",
    "PsycopgCurrentSessionLogoutUnitOfWorkFactory",
    "OwnedSessionRevocationPostgresDatabaseRequest",
    "OwnedSessionRevocationPostgresDatabaseResult",
    "OwnedSessionRevocationPostgresExecutionScope",
    "PsycopgOwnedSessionRevocationUnitOfWorkFactory",
]
