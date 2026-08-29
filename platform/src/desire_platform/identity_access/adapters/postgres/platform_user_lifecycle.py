"""PostgreSQL 18 boundary for ACCESS_ADMIN user/session lifecycle commands.

The request contains only UUID coordinates, closed reason codes, and keyed
digests prepared by the application.  It never accepts a password, raw OIDC
carrier, raw Idempotency-Key, CSRF token, or free-text reason note.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import hmac
import re
from typing import Any, Dict, Mapping, Optional, Protocol, Sequence, Tuple
from uuid import UUID, uuid5

from psycopg.pq import TransactionStatus
from psycopg.types.json import Jsonb

from ...domain.errors import IamError


_REASON_CODE = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
_ETAG = re.compile(r'^"v[1-9][0-9]*"$')


class PlatformUserPostgresOperation(str, Enum):
    SUSPEND_USER = "SuspendUser"
    RESUME_USER = "ResumeUser"
    REVOKE_ALL_SESSIONS = "RevokeAllSessions"
    GRANT_PLATFORM_DUTY = "GrantPlatformDuty"
    REVOKE_PLATFORM_DUTY = "RevokePlatformDuty"


class PlatformUserPostgresWriteCheckpoint(str, Enum):
    COMMAND_RECEIPT_CLAIM = "command_receipt.claim"
    SESSION_FAMILY_REVOKE = "session_family.revoke"
    SESSION_REVOKE = "session.revoke"
    PLATFORM_DUTY_MUTATION = "platform_duty.mutate"
    USER_VERSION_CAS = "user.version-cas"
    AUDIT_EVENT_INSERT = "audit_event.insert"
    OUTBOX_EVENT_INSERT = "outbox_event.insert"
    COMMAND_RECEIPT_COMPLETE = "command_receipt.complete"


PLATFORM_USER_POSTGRES_WRITE_CHECKPOINTS: Tuple[
    PlatformUserPostgresWriteCheckpoint, ...
] = tuple(PlatformUserPostgresWriteCheckpoint)


class PlatformUserPostgresConnectionSource(Protocol):
    def checkout(self) -> Any: ...

    def release(self, connection: Any) -> None: ...

    def discard(self, connection: Any) -> None: ...


class PlatformUserPostgresFaultInjector(Protocol):
    def before_write(
        self,
        checkpoint: PlatformUserPostgresWriteCheckpoint,
        ordinal: int,
    ) -> None: ...


class PlatformUserPostgresSchemaValidator(Protocol):
    def validate(
        self,
        value: Mapping[str, Any],
        schema_name: Optional[str] = None,
    ) -> None: ...


class NoPlatformUserPostgresFaults:
    def before_write(
        self,
        checkpoint: PlatformUserPostgresWriteCheckpoint,
        ordinal: int,
    ) -> None:
        del checkpoint, ordinal


class PlatformUserPostgresConfigurationError(RuntimeError):
    """The role, server, connection state, or deployment settings are unsafe."""


class PlatformUserPostgresCommitOutcomeUnknownError(RuntimeError):
    """COMMIT was sent, so this request cannot infer its outcome."""

    code = "COMMAND_OUTCOME_UNKNOWN"


@dataclass(frozen=True)
class PlatformUserPostgresSettings:
    runtime_role: str = "iam_app"
    lock_timeout_ms: int = 2_000
    statement_timeout_ms: int = 10_000
    idle_in_transaction_timeout_ms: int = 15_000
    max_precommit_retries: int = 3

    def __post_init__(self) -> None:
        if self.runtime_role != "iam_app":
            raise ValueError("platform user lifecycle runtime role must be iam_app")
        if not 1 <= self.lock_timeout_ms <= 10_000:
            raise ValueError("platform user lifecycle lock timeout is invalid")
        if not 1 <= self.statement_timeout_ms <= 30_000:
            raise ValueError("platform user lifecycle statement timeout is invalid")
        if not 1 <= self.idle_in_transaction_timeout_ms <= 30_000:
            raise ValueError(
                "platform user lifecycle idle transaction timeout is invalid"
            )
        if self.max_precommit_retries != 3:
            raise ValueError("platform user lifecycle retry count must be exactly 3")


@dataclass(frozen=True)
class PlatformUserPostgresExecutionScope:
    actor_user_id: UUID
    current_session_id: UUID
    target_user_id: UUID
    command_id: UUID
    correlation_id: UUID
    causation_id: UUID
    trace_id: UUID
    original_actor_id: Optional[UUID]

    def __post_init__(self) -> None:
        required = (
            self.actor_user_id,
            self.current_session_id,
            self.target_user_id,
            self.command_id,
            self.correlation_id,
            self.causation_id,
            self.trace_id,
        )
        if any(not isinstance(value, UUID) or value.int == 0 for value in required):
            raise ValueError("platform user lifecycle scope IDs must be non-zero UUIDs")
        if self.actor_user_id == self.target_user_id:
            raise ValueError("platform user lifecycle cannot target the actor")
        if self.causation_id != self.command_id:
            raise ValueError("platform user lifecycle causation must be the command")
        if self.original_actor_id is not None and (
            not isinstance(self.original_actor_id, UUID)
            or self.original_actor_id.int == 0
            or self.original_actor_id == self.actor_user_id
        ):
            raise ValueError("platform user lifecycle original actor is invalid")


@dataclass(frozen=True)
class PlatformUserPostgresReceiptMaterial:
    receipt_id: UUID
    idempotency_key_digest: bytes = field(repr=False)
    idempotency_key_digest_key_id: str
    payload_hash: bytes = field(repr=False)
    payload_hash_key_id: str
    canonicalization_version: str
    retain_until: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.receipt_id, UUID) or self.receipt_id.int == 0:
            raise ValueError("platform user lifecycle receipt ID must be non-zero")
        _require_digest(self.idempotency_key_digest, "idempotency digest")
        _require_digest(self.payload_hash, "payload digest")
        _require_key_id(
            self.idempotency_key_digest_key_id,
            "idempotency digest key ID",
        )
        _require_key_id(self.payload_hash_key_id, "payload digest key ID")
        if self.canonicalization_version != "restricted-canonical-json-v1":
            raise ValueError("unsupported platform user canonicalization")
        _require_utc(self.retain_until, "receipt retain_until")


@dataclass(frozen=True)
class PlatformUserPostgresGeneratedIds:
    audit_event_id: UUID
    main_outbox_event_id: UUID
    session_event_namespace: UUID
    platform_duty_grant_id: Optional[UUID] = None

    def __post_init__(self) -> None:
        values = (
            self.audit_event_id,
            self.main_outbox_event_id,
            self.session_event_namespace,
        )
        if any(not isinstance(value, UUID) or value.int == 0 for value in values):
            raise ValueError("generated platform user IDs must be non-zero UUIDs")
        if len(set(values)) != len(values):
            raise ValueError("generated platform user IDs must be distinct")
        if self.platform_duty_grant_id is not None and (
            not isinstance(self.platform_duty_grant_id, UUID)
            or self.platform_duty_grant_id.int == 0
            or self.platform_duty_grant_id in values
        ):
            raise ValueError("generated platform duty grant ID is invalid")


@dataclass(frozen=True)
class PlatformUserPostgresDatabaseRequest:
    operation: PlatformUserPostgresOperation
    scope: PlatformUserPostgresExecutionScope
    receipt: PlatformUserPostgresReceiptMaterial
    expected_user_version: int
    reason_code: str
    generated_ids: PlatformUserPostgresGeneratedIds
    duty_code: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.operation, PlatformUserPostgresOperation):
            raise ValueError("platform user lifecycle operation is not closed")
        if self.receipt.receipt_id != self.scope.command_id:
            raise ValueError("platform user lifecycle receipt must be the command")
        if (
            not isinstance(self.expected_user_version, int)
            or isinstance(self.expected_user_version, bool)
            or self.expected_user_version < 1
        ):
            raise ValueError("expected User version must be positive")
        if (
            not isinstance(self.reason_code, str)
            or _REASON_CODE.fullmatch(self.reason_code) is None
        ):
            raise ValueError("platform user lifecycle reason code is invalid")
        duty_operation = self.operation in {
            PlatformUserPostgresOperation.GRANT_PLATFORM_DUTY,
            PlatformUserPostgresOperation.REVOKE_PLATFORM_DUTY,
        }
        if duty_operation != (self.duty_code in {
            "ACCESS_ADMIN",
            "OPERATIONS_REVIEWER",
            "FINANCE_OPERATOR",
            "TRUST_OFFICER",
            "APPEAL_REVIEWER",
        }):
            raise ValueError("platform duty command is not closed")
        if (
            self.operation is PlatformUserPostgresOperation.GRANT_PLATFORM_DUTY
        ) != (self.generated_ids.platform_duty_grant_id is not None):
            raise ValueError("platform duty grant ID binding is invalid")


@dataclass(frozen=True)
class PlatformUserPostgresDatabaseResult:
    operation: PlatformUserPostgresOperation
    replayed: bool
    safe_response: Mapping[str, Any] = field(repr=False)
    response_entity_tag: str


@dataclass(frozen=True)
class _OutboxRecord:
    event_id: UUID
    event_type: str
    aggregate_type: str
    aggregate_id: UUID
    aggregate_version: int
    payload: Mapping[str, Any] = field(repr=False)


class PsycopgPlatformUserLifecycleUnitOfWorkFactory:
    """Execute the reviewed ACCESS_ADMIN programs on PostgreSQL 18."""

    def __init__(
        self,
        *,
        connections: PlatformUserPostgresConnectionSource,
        event_validator: PlatformUserPostgresSchemaValidator,
        response_validator: PlatformUserPostgresSchemaValidator,
        settings: Optional[PlatformUserPostgresSettings] = None,
        fault_injector: Optional[PlatformUserPostgresFaultInjector] = None,
    ) -> None:
        self.connections = connections
        self.event_validator = event_validator
        self.response_validator = response_validator
        self.settings = settings or PlatformUserPostgresSettings()
        self.fault_injector = fault_injector or NoPlatformUserPostgresFaults()

    def execute_suspend_user(
        self,
        request: PlatformUserPostgresDatabaseRequest,
    ) -> PlatformUserPostgresDatabaseResult:
        return self._execute(request, PlatformUserPostgresOperation.SUSPEND_USER)

    def execute_resume_user(
        self,
        request: PlatformUserPostgresDatabaseRequest,
    ) -> PlatformUserPostgresDatabaseResult:
        return self._execute(request, PlatformUserPostgresOperation.RESUME_USER)

    def execute_revoke_all_sessions(
        self,
        request: PlatformUserPostgresDatabaseRequest,
    ) -> PlatformUserPostgresDatabaseResult:
        return self._execute(
            request,
            PlatformUserPostgresOperation.REVOKE_ALL_SESSIONS,
        )

    def execute_grant_platform_duty(
        self,
        request: PlatformUserPostgresDatabaseRequest,
    ) -> PlatformUserPostgresDatabaseResult:
        return self._execute(
            request,
            PlatformUserPostgresOperation.GRANT_PLATFORM_DUTY,
        )

    def execute_revoke_platform_duty(
        self,
        request: PlatformUserPostgresDatabaseRequest,
    ) -> PlatformUserPostgresDatabaseResult:
        return self._execute(
            request,
            PlatformUserPostgresOperation.REVOKE_PLATFORM_DUTY,
        )

    def _execute(
        self,
        request: PlatformUserPostgresDatabaseRequest,
        expected: PlatformUserPostgresOperation,
    ) -> PlatformUserPostgresDatabaseResult:
        _require_operation(request, expected)
        attempts = self.settings.max_precommit_retries + 1
        for attempt in range(attempts):
            try:
                return self._execute_once(request)
            except BaseException as error:
                if attempt + 1 < attempts and _retryable(error):
                    continue
                raise
        raise AssertionError("closed platform user retry loop did not terminate")

    def _execute_once(
        self,
        request: PlatformUserPostgresDatabaseRequest,
    ) -> PlatformUserPostgresDatabaseResult:
        connection = self.connections.checkout()
        state = "NEW"
        disposed = False
        try:
            self._validate_connection(connection)
            connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED")
            state = "BEGUN"
            self._configure_transaction(connection, request)
            state = "WRITING"
            result = self._execute_transaction(connection, request)
            state = "COMMIT_SENT"
            connection.execute("COMMIT")
            state = "COMMITTED"
        except BaseException as error:
            if state == "COMMIT_SENT":
                self.connections.discard(connection)
                disposed = True
                raise PlatformUserPostgresCommitOutcomeUnknownError() from error
            if state in ("BEGUN", "WRITING"):
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
            raise
        else:
            disposed = self._release_or_discard(connection)
            return result
        finally:
            if not disposed:
                self.connections.discard(connection)

    def _validate_connection(self, connection: Any) -> None:
        if connection.info.transaction_status != TransactionStatus.IDLE:
            raise PlatformUserPostgresConfigurationError(
                "platform user lifecycle checkout must be transaction-idle"
            )
        identity = connection.execute(
            "SELECT current_user,session_user,"
            "current_setting('server_version_num')::integer"
        ).fetchone()
        if identity is None or identity[0:2] != (
            self.settings.runtime_role,
            self.settings.runtime_role,
        ):
            raise PlatformUserPostgresConfigurationError(
                "platform user lifecycle connection identity is not iam_app"
            )
        if identity[2] // 10_000 != 18:
            raise PlatformUserPostgresConfigurationError(
                "platform user lifecycle requires PostgreSQL major 18"
            )

    def _configure_transaction(
        self,
        connection: Any,
        request: PlatformUserPostgresDatabaseRequest,
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
        values = _transaction_context(request)
        for name, value in values:
            configured = connection.execute(
                "SELECT pg_catalog.set_config(%s,%s,true)",
                (name, value),
            ).fetchone()
            if configured != (value,):
                raise PlatformUserPostgresConfigurationError(
                    "platform user lifecycle transaction context was rejected"
                )
        for name, expected in values:
            actual = connection.execute(
                "SELECT current_setting(%s,true)",
                (name,),
            ).fetchone()
            if actual != (expected,):
                raise PlatformUserPostgresConfigurationError(
                    "platform user lifecycle context readback failed"
                )

    def _execute_transaction(
        self,
        connection: Any,
        request: PlatformUserPostgresDatabaseRequest,
    ) -> PlatformUserPostgresDatabaseResult:
        ordinals: Dict[PlatformUserPostgresWriteCheckpoint, int] = {}

        def before_write(checkpoint: PlatformUserPostgresWriteCheckpoint) -> None:
            ordinal = ordinals.get(checkpoint, 0)
            self.fault_injector.before_write(checkpoint, ordinal)
            ordinals[checkpoint] = ordinal + 1

        now = connection.execute("SELECT transaction_timestamp()").fetchone()[0]
        if request.receipt.retain_until <= now:
            raise IamError("SERVICE_UNAVAILABLE")
        _validate_key_policy(connection, request.receipt)
        if not _is_duty_operation(request.operation):
            _validate_synthetic_lifecycle_target(connection, request)
        existing = _load_receipt(connection, request)
        if existing is not None:
            plan = _lock_plan(connection, request, replay=True)
            return self._replay(request, existing, plan, now)
        if _command_scope_receipt_exists(connection, request):
            raise IamError("IDEMPOTENCY_KEY_REUSED")

        before_write(PlatformUserPostgresWriteCheckpoint.COMMAND_RECEIPT_CLAIM)
        claimed = connection.execute(
            "INSERT INTO infra.command_receipts ("
            "id,principal_kind,principal_id,command_name,command_version,"
            "idempotency_key_digest,idempotency_key_digest_key_id,payload_hash,"
            "payload_hash_key_id,canonicalization_version,target_kind,target_id,"
            "http_method,canonical_path,if_match_version,status,"
            "response_schema_version,safe_response_body,reconstruction_metadata,"
            "response_http_status,response_schema_name,response_entity_tag,"
            "current_user_entity_tag,created_at,retain_until,completed_at) VALUES ("
            "%s,'USER',%s,%s,1,%s,%s,%s,%s,%s,'User',%s,'POST',%s,%s,"
            "'IN_PROGRESS',NULL,NULL,NULL,NULL,NULL,NULL,NULL,%s,%s,NULL) "
            "ON CONFLICT DO NOTHING RETURNING id",
            (
                request.receipt.receipt_id,
                request.scope.actor_user_id,
                request.operation.value,
                request.receipt.idempotency_key_digest,
                request.receipt.idempotency_key_digest_key_id,
                request.receipt.payload_hash,
                request.receipt.payload_hash_key_id,
                request.receipt.canonicalization_version,
                request.scope.target_user_id,
                _canonical_path(request),
                request.expected_user_version,
                now,
                request.receipt.retain_until,
            ),
        ).fetchone()
        if claimed is None:
            raced = _load_receipt(connection, request)
            if raced is None:
                if _command_scope_receipt_exists(connection, request):
                    raise IamError("IDEMPOTENCY_KEY_REUSED")
                raise IamError("SERVICE_UNAVAILABLE")
            plan = _lock_plan(connection, request, replay=True)
            return self._replay(request, raced, plan, now)

        plan = _lock_plan(connection, request, replay=False)
        target = _target(plan)
        duty_operation = _is_duty_operation(request.operation)
        families = () if duty_operation else _plan_rows(
            plan, "active_session_families"
        )
        sessions = () if duty_operation else _plan_rows(plan, "active_sessions")

        for family in families:
            family_id = _uuid(family.get("session_family_id"))
            family_version = _positive_int(family.get("aggregate_version"))
            before_write(PlatformUserPostgresWriteCheckpoint.SESSION_FAMILY_REVOKE)
            updated = connection.execute(
                "UPDATE iam.session_families SET status='REVOKED',revoked_at=%s,"
                "revocation_reason_code=%s,aggregate_version=aggregate_version+1,"
                "updated_at=%s WHERE id=%s AND user_id=%s AND status='ACTIVE' "
                "AND aggregate_version=%s RETURNING aggregate_version",
                (
                    now,
                    request.reason_code,
                    now,
                    family_id,
                    request.scope.target_user_id,
                    family_version,
                ),
            ).fetchone()
            if updated != (family_version + 1,):
                raise IamError("PRECONDITION_FAILED")

        revoked_sessions = []
        for session in sessions:
            session_id = _uuid(session.get("session_id"))
            family_id = _uuid(session.get("session_family_id"))
            session_version = _positive_int(session.get("aggregate_version"))
            before_write(PlatformUserPostgresWriteCheckpoint.SESSION_REVOKE)
            updated = connection.execute(
                "UPDATE iam.sessions SET status='REVOKED',revoked_at=%s,"
                "revocation_reason_code=%s,aggregate_version=aggregate_version+1,"
                "updated_at=%s WHERE id=%s AND user_id=%s AND family_id=%s "
                "AND status='ACTIVE' AND aggregate_version=%s "
                "RETURNING aggregate_version",
                (
                    now,
                    request.reason_code,
                    now,
                    session_id,
                    request.scope.target_user_id,
                    family_id,
                    session_version,
                ),
            ).fetchone()
            if updated != (session_version + 1,):
                raise IamError("PRECONDITION_FAILED")
            revoked_sessions.append((session_id, family_id, session_version + 1))

        duty_transition: Optional[Tuple[UUID, Optional[int], int, str, str]] = None
        if duty_operation:
            before_write(PlatformUserPostgresWriteCheckpoint.PLATFORM_DUTY_MUTATION)
            if request.operation is PlatformUserPostgresOperation.GRANT_PLATFORM_DUTY:
                grant_id = request.generated_ids.platform_duty_grant_id
                if not isinstance(grant_id, UUID):
                    raise IamError("SERVICE_UNAVAILABLE")
                inserted = connection.execute(
                    "INSERT INTO iam.platform_duty_grants ("
                    "id,user_id,duty_code,granted_by_kind,granted_by_id,granted_at,"
                    "expires_at,revoked_at,revocation_reason_code,aggregate_version,"
                    "created_at,updated_at) VALUES ("
                    "%s,%s,%s,'USER',%s,%s,NULL,NULL,NULL,1,%s,%s) "
                    "RETURNING id,aggregate_version",
                    (
                        grant_id,
                        request.scope.target_user_id,
                        request.duty_code,
                        request.scope.actor_user_id,
                        now,
                        now,
                        now,
                    ),
                ).fetchone()
                if inserted != (grant_id, 1):
                    raise IamError("SERVICE_UNAVAILABLE")
                duty_transition = (grant_id, None, 1, "ABSENT", "ACTIVE")
            else:
                grant = plan.get("platform_duty_grant")
                if not isinstance(grant, dict):
                    raise IamError("SERVICE_UNAVAILABLE")
                grant_id = _uuid(grant.get("grant_id"))
                grant_version = _positive_int(grant.get("aggregate_version"))
                updated = connection.execute(
                    "UPDATE iam.platform_duty_grants SET revoked_at=%s,"
                    "revocation_reason_code=%s,aggregate_version=aggregate_version+1,"
                    "updated_at=%s WHERE id=%s AND user_id=%s AND duty_code=%s "
                    "AND revoked_at IS NULL AND aggregate_version=%s "
                    "RETURNING id,aggregate_version",
                    (
                        now,
                        request.reason_code,
                        now,
                        grant_id,
                        request.scope.target_user_id,
                        request.duty_code,
                        grant_version,
                    ),
                ).fetchone()
                if updated != (grant_id, grant_version + 1):
                    raise IamError("PRECONDITION_FAILED")
                duty_transition = (
                    grant_id,
                    grant_version,
                    grant_version + 1,
                    "ACTIVE",
                    "REVOKED",
                )

        before_status = _text(target.get("status"))
        after_status = _after_status(request.operation, before_status)
        before_version = _positive_int(target.get("aggregate_version"))
        before_write(PlatformUserPostgresWriteCheckpoint.USER_VERSION_CAS)
        updated_user = connection.execute(
            "UPDATE iam.users SET status=%s,aggregate_version=aggregate_version+1,"
            "updated_at=%s WHERE id=%s AND status=%s AND aggregate_version=%s "
            "RETURNING display_handle,status,aggregate_version",
            (
                after_status,
                now,
                request.scope.target_user_id,
                before_status,
                before_version,
            ),
        ).fetchone()
        if updated_user is None:
            raise IamError("PRECONDITION_FAILED")
        response = {
            "user_id": str(request.scope.target_user_id),
            "display_handle": updated_user[0],
            "status": updated_user[1],
            "aggregate_version": updated_user[2],
            "entity_tag": _entity_tag(updated_user[2]),
            "revoked_session_count": len(revoked_sessions),
            "revoked_session_family_count": len(families),
        }
        self._validate_response(response)
        events = _events(
            request,
            response,
            revoked_sessions,
            now,
            duty_transition=duty_transition,
        )
        for event in events:
            self._validate_event(_event_envelope(request, event, now))

        before_write(PlatformUserPostgresWriteCheckpoint.AUDIT_EVENT_INSERT)
        audit_target_kind = "User"
        audit_target_id = request.scope.target_user_id
        audit_before_status = before_status
        audit_after_status = after_status
        audit_before_version: Optional[int] = before_version
        audit_after_version = updated_user[2]
        audit_role_code = "ACCESS_ADMIN"
        if duty_transition is not None:
            audit_target_kind = "PlatformDutyGrant"
            audit_target_id = duty_transition[0]
            audit_before_version = duty_transition[1]
            audit_after_version = duty_transition[2]
            audit_before_status = duty_transition[3]
            audit_after_status = duty_transition[4]
            audit_role_code = _text(request.duty_code)
        connection.execute(
            "INSERT INTO audit.audit_events ("
            "event_id,occurred_at,actor_kind,actor_id,original_actor_id,action_code,"
            "target_kind,target_id,organization_id,before_status,after_status,"
            "before_version,after_version,role_code,purpose_code,reason_code,"
            "auth_strength_code,result_code,command_id,correlation_id,causation_id,"
            "trace_id,safe_attributes) VALUES ("
            "%s,%s,'USER',%s,%s,%s,%s,%s,NULL,%s,%s,%s,%s,%s,"
            "NULL,%s,%s,'SUCCEEDED',%s,%s,%s,%s,%s)",
            (
                request.generated_ids.audit_event_id,
                now,
                request.scope.actor_user_id,
                request.scope.original_actor_id,
                request.operation.value,
                audit_target_kind,
                audit_target_id,
                audit_before_status,
                audit_after_status,
                audit_before_version,
                audit_after_version,
                audit_role_code,
                request.reason_code,
                _text(plan.get("actor_acr_code")),
                request.scope.command_id,
                request.scope.correlation_id,
                request.scope.command_id,
                request.scope.trace_id,
                Jsonb({}),
            ),
        )

        for event in events:
            before_write(PlatformUserPostgresWriteCheckpoint.OUTBOX_EVENT_INSERT)
            connection.execute(
                "INSERT INTO infra.outbox_events ("
                "event_id,event_type,schema_version,occurred_at,aggregate_type,"
                "aggregate_id,aggregate_version,actor_kind,actor_id,original_actor_id,"
                "correlation_id,causation_id,trace_id,organization_id,payload,"
                "delivery_status,attempt_count,available_at,lease_owner,lease_until,"
                "published_at,last_error_code,created_at) VALUES ("
                "%s,%s,1,%s,%s,%s,%s,'USER',%s,%s,%s,%s,%s,NULL,%s,"
                "'PENDING',0,%s,NULL,NULL,NULL,NULL,%s)",
                (
                    event.event_id,
                    event.event_type,
                    now,
                    event.aggregate_type,
                    event.aggregate_id,
                    event.aggregate_version,
                    request.scope.actor_user_id,
                    request.scope.original_actor_id,
                    request.scope.correlation_id,
                    request.scope.command_id,
                    request.scope.trace_id,
                    Jsonb(dict(event.payload)),
                    now,
                    now,
                ),
            )

        before_write(PlatformUserPostgresWriteCheckpoint.COMMAND_RECEIPT_COMPLETE)
        completed = connection.execute(
            "UPDATE infra.command_receipts SET status='COMPLETED',"
            "response_schema_version=1,safe_response_body=%s,"
            "response_http_status=200,response_schema_name='PlatformUserAdminDto',"
            "response_entity_tag=%s,current_user_entity_tag=%s,completed_at=%s "
            "WHERE id=%s AND status='IN_PROGRESS' RETURNING id",
            (
                Jsonb(response),
                response["entity_tag"],
                response["entity_tag"],
                now,
                request.receipt.receipt_id,
            ),
        ).fetchone()
        if completed != (request.receipt.receipt_id,):
            raise IamError("SERVICE_UNAVAILABLE")
        return PlatformUserPostgresDatabaseResult(
            operation=request.operation,
            replayed=False,
            safe_response=response,
            response_entity_tag=response["entity_tag"],
        )

    def _replay(
        self,
        request: PlatformUserPostgresDatabaseRequest,
        receipt: Mapping[str, Any],
        plan: Mapping[str, Any],
        now: datetime,
    ) -> PlatformUserPostgresDatabaseResult:
        if not hmac.compare_digest(receipt["payload_hash"], request.receipt.payload_hash):
            raise IamError("IDEMPOTENCY_KEY_REUSED")
        if (
            receipt.get("payload_hash_key_id") != request.receipt.payload_hash_key_id
            or receipt.get("canonicalization_version")
            != request.receipt.canonicalization_version
            or receipt.get("target_id") != request.scope.target_user_id
            or receipt.get("canonical_path") != _canonical_path(request)
            or receipt.get("if_match_version") != request.expected_user_version
            or receipt.get("status") != "COMPLETED"
            or receipt.get("response_schema_version") != 1
            or receipt.get("response_http_status") != 200
            or receipt.get("response_schema_name") != "PlatformUserAdminDto"
            or receipt.get("retain_until") <= now
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        response = receipt.get("safe_response_body")
        if not isinstance(response, dict):
            raise IamError("SERVICE_UNAVAILABLE")
        target = _target(plan)
        response_version = _positive_int(response.get("aggregate_version"))
        if (
            target.get("user_id") != str(request.scope.target_user_id)
            or response.get("user_id") != str(request.scope.target_user_id)
            or response_version != request.expected_user_version + 1
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        entity_tag = receipt.get("response_entity_tag")
        if (
            not isinstance(entity_tag, str)
            or _ETAG.fullmatch(entity_tag) is None
            or receipt.get("current_user_entity_tag") != entity_tag
            or response.get("entity_tag") != entity_tag
            or entity_tag != _entity_tag(response_version)
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        self._validate_response(response)
        return PlatformUserPostgresDatabaseResult(
            operation=request.operation,
            replayed=True,
            safe_response=response,
            response_entity_tag=entity_tag,
        )

    def _validate_event(self, event: Mapping[str, Any]) -> None:
        try:
            self.event_validator.validate(event)
        except (AssertionError, TypeError, ValueError) as error:
            raise IamError("SERVICE_UNAVAILABLE") from error

    def _validate_response(self, response: Mapping[str, Any]) -> None:
        try:
            self.response_validator.validate(response, "PlatformUserAdminDto")
        except (AssertionError, TypeError, ValueError) as error:
            raise IamError("SERVICE_UNAVAILABLE") from error

    def _release_or_discard(self, connection: Any) -> bool:
        try:
            if connection.info.transaction_status != TransactionStatus.IDLE:
                self.connections.discard(connection)
                return True
            connection.execute("RESET ROLE")
            connection.execute("RESET ALL")
            connection.execute("DISCARD TEMP")
            identity = connection.execute(
                "SELECT current_user,session_user,"
                "current_setting('app.actor_user_id',true)"
            ).fetchone()
            if identity not in (
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


def _transaction_context(
    request: PlatformUserPostgresDatabaseRequest,
) -> Tuple[Tuple[str, str], ...]:
    return (
        (
            "app.scope_kind",
            (
                "INTERNAL_SANDBOX_PLATFORM_DUTY_ADMIN"
                if _is_duty_operation(request.operation)
                else "PLATFORM_USER_ADMIN"
            ),
        ),
        ("app.operation", _database_operation(request.operation)),
        ("app.actor_user_id", str(request.scope.actor_user_id)),
        ("app.actor_id", str(request.scope.actor_user_id)),
        ("app.target_user_id", str(request.scope.target_user_id)),
        ("app.session_id", str(request.scope.current_session_id)),
        ("app.expected_version", str(request.expected_user_version)),
        ("app.reason_code", request.reason_code),
        ("app.duty_code", request.duty_code or ""),
        ("app.command_id", str(request.scope.command_id)),
        ("app.command_name", request.operation.value),
        ("app.command_version", "1"),
        (
            "app.idempotency_key_digest_key_id",
            request.receipt.idempotency_key_digest_key_id,
        ),
        ("app.idempotency_key_digest", request.receipt.idempotency_key_digest.hex()),
        ("app.organization_id", ""),
    )


def _validate_key_policy(
    connection: Any,
    material: PlatformUserPostgresReceiptMaterial,
) -> None:
    rows = connection.execute(
        "SELECT active_idempotency_key_id,active_payload_hash_key_id,"
        "active_canonicalization_version,retained_idempotency_key_ids,"
        "retained_payload_hash_key_ids,retained_canonicalization_versions "
        "FROM infra.iam_receipt_key_policy WHERE singleton_key"
    ).fetchall()
    if len(rows) != 1:
        raise IamError("SERVICE_UNAVAILABLE")
    row = rows[0]
    if (
        row[0] != material.idempotency_key_digest_key_id
        or row[1] != material.payload_hash_key_id
        or row[2] != material.canonicalization_version
        or material.idempotency_key_digest_key_id not in tuple(row[3])
        or material.payload_hash_key_id not in tuple(row[4])
        or material.canonicalization_version not in tuple(row[5])
    ):
        raise IamError("SERVICE_UNAVAILABLE")


def _load_receipt(
    connection: Any,
    request: PlatformUserPostgresDatabaseRequest,
) -> Optional[Mapping[str, Any]]:
    rows = connection.execute(
        "SELECT payload_hash,payload_hash_key_id,canonicalization_version,"
        "target_id,canonical_path,if_match_version,status,response_schema_version,"
        "safe_response_body,response_http_status,response_schema_name,"
        "response_entity_tag,current_user_entity_tag,retain_until "
        "FROM infra.command_receipts WHERE principal_kind='USER' "
        "AND principal_id=%s AND command_name=%s AND command_version=1 "
        "AND idempotency_key_digest_key_id=%s AND idempotency_key_digest=%s "
        "ORDER BY id FOR UPDATE",
        (
            request.scope.actor_user_id,
            request.operation.value,
            request.receipt.idempotency_key_digest_key_id,
            request.receipt.idempotency_key_digest,
        ),
    ).fetchall()
    if not rows:
        return None
    if len(rows) != 1:
        raise IamError("SERVICE_UNAVAILABLE")
    row = rows[0]
    return {
        "payload_hash": bytes(row[0]),
        "payload_hash_key_id": row[1],
        "canonicalization_version": row[2],
        "target_id": row[3],
        "canonical_path": row[4],
        "if_match_version": row[5],
        "status": row[6],
        "response_schema_version": row[7],
        "safe_response_body": row[8],
        "response_http_status": row[9],
        "response_schema_name": row[10],
        "response_entity_tag": row[11],
        "current_user_entity_tag": row[12],
        "retain_until": row[13],
    }


def _validate_synthetic_lifecycle_target(
    connection: Any,
    request: PlatformUserPostgresDatabaseRequest,
) -> None:
    row = connection.execute(
        "SELECT iam_api.validate_internal_sandbox_platform_user_admin_target_v2("
        "%s,%s,%s,%s)",
        (
            request.scope.actor_user_id,
            request.scope.current_session_id,
            request.scope.target_user_id,
            _database_operation(request.operation),
        ),
    ).fetchone()
    if row is None or not isinstance(row[0], str):
        raise IamError("SERVICE_UNAVAILABLE")
    decision = row[0]
    if decision == "AUTHORIZED":
        return
    if decision in {
        "RESOURCE_NOT_FOUND",
        "SELF_MANAGEMENT_FORBIDDEN",
        "SERVICE_UNAVAILABLE",
    }:
        raise IamError(decision)
    raise IamError("SERVICE_UNAVAILABLE")


def _command_scope_receipt_exists(
    connection: Any,
    request: PlatformUserPostgresDatabaseRequest,
) -> bool:
    row = connection.execute(
        "SELECT iam_api.probe_platform_user_admin_command_receipt_v1("
        "%s,%s,%s,%s,%s,%s)",
        (
            request.scope.actor_user_id,
            request.scope.current_session_id,
            request.scope.target_user_id,
            request.operation.value,
            request.receipt.idempotency_key_digest_key_id,
            request.receipt.idempotency_key_digest,
        ),
    ).fetchone()
    if row not in ((True,), (False,)):
        raise IamError("SERVICE_UNAVAILABLE")
    return bool(row[0])


def _lock_plan(
    connection: Any,
    request: PlatformUserPostgresDatabaseRequest,
    *,
    replay: bool,
) -> Mapping[str, Any]:
    if _is_duty_operation(request.operation):
        row = connection.execute(
            "SELECT iam_api.lock_internal_sandbox_platform_duty_admin_v2("
            "%s,%s,%s,%s,%s,%s,%s)",
            (
                request.scope.actor_user_id,
                request.scope.current_session_id,
                request.scope.target_user_id,
                _database_operation(request.operation),
                request.expected_user_version,
                request.duty_code,
                replay,
            ),
        ).fetchone()
    else:
        row = connection.execute(
            "SELECT iam_api.lock_internal_sandbox_platform_user_admin_v2("
            "%s,%s,%s,%s,%s,%s)",
            (
                request.scope.actor_user_id,
                request.scope.current_session_id,
                request.scope.target_user_id,
                _database_operation(request.operation),
                request.expected_user_version,
                replay,
            ),
        ).fetchone()
    if row is None or not isinstance(row[0], dict):
        raise IamError("SERVICE_UNAVAILABLE")
    plan = row[0]
    decision = plan.get("decision_code")
    if decision != "AUTHORIZED":
        if decision in {
            "AUTHENTICATION_REQUIRED",
            "SESSION_EXPIRED",
            "MFA_STEP_UP_REQUIRED",
            "RESOURCE_NOT_FOUND",
            "SELF_MANAGEMENT_FORBIDDEN",
            "LAST_ACTIVE_ACCESS_ADMIN",
            "INVALID_STATE_TRANSITION",
            "PRECONDITION_FAILED",
            "SERVICE_UNAVAILABLE",
        }:
            raise IamError(decision)
        raise IamError("SERVICE_UNAVAILABLE")
    return plan


def _target(plan: Mapping[str, Any]) -> Mapping[str, Any]:
    target = plan.get("target_user")
    if not isinstance(target, dict):
        raise IamError("SERVICE_UNAVAILABLE")
    return target


def _plan_rows(plan: Mapping[str, Any], name: str) -> Sequence[Mapping[str, Any]]:
    value = plan.get(name)
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise IamError("SERVICE_UNAVAILABLE")
    return value


def _events(
    request: PlatformUserPostgresDatabaseRequest,
    response: Mapping[str, Any],
    sessions: Sequence[Tuple[UUID, UUID, int]],
    now: datetime,
    *,
    duty_transition: Optional[Tuple[UUID, Optional[int], int, str, str]],
) -> Tuple[_OutboxRecord, ...]:
    del now
    if duty_transition is not None:
        grant_id, _, after_version, _, after_status = duty_transition
        event_type = (
            "PlatformDutyGranted"
            if request.operation is PlatformUserPostgresOperation.GRANT_PLATFORM_DUTY
            else "PlatformDutyRevoked"
        )
        return (
            _OutboxRecord(
                event_id=request.generated_ids.main_outbox_event_id,
                event_type=event_type,
                aggregate_type="PlatformDutyGrant",
                aggregate_id=grant_id,
                aggregate_version=after_version,
                payload={
                    "grant_id": str(grant_id),
                    "user_id": str(request.scope.target_user_id),
                    "duty_code": _text(request.duty_code),
                    "status": after_status,
                },
            ),
        )
    main_type = {
        PlatformUserPostgresOperation.SUSPEND_USER: "UserSuspended",
        PlatformUserPostgresOperation.RESUME_USER: "UserResumed",
        PlatformUserPostgresOperation.REVOKE_ALL_SESSIONS: "SessionsRevoked",
    }[request.operation]
    main_payload = (
        {
            "user_id": str(request.scope.target_user_id),
            "scope": "ALL_ACTIVE_SESSION_FAMILIES",
        }
        if request.operation is PlatformUserPostgresOperation.REVOKE_ALL_SESSIONS
        else {
            "user_id": str(request.scope.target_user_id),
            "status": response["status"],
        }
    )
    events = [
        _OutboxRecord(
            event_id=request.generated_ids.main_outbox_event_id,
            event_type=main_type,
            aggregate_type="User",
            aggregate_id=request.scope.target_user_id,
            aggregate_version=_positive_int(response.get("aggregate_version")),
            payload=main_payload,
        )
    ]
    for session_id, family_id, version in sessions:
        event_id = uuid5(
            request.generated_ids.session_event_namespace,
            "%s:%d" % (session_id, version),
        )
        events.append(
            _OutboxRecord(
                event_id=event_id,
                event_type="SessionRevoked",
                aggregate_type="Session",
                aggregate_id=session_id,
                aggregate_version=version,
                payload={
                    "session_id": str(session_id),
                    "session_family_id": str(family_id),
                    "user_id": str(request.scope.target_user_id),
                    "status": "REVOKED",
                },
            )
        )
    if len({item.event_id for item in events}) != len(events):
        raise IamError("SERVICE_UNAVAILABLE")
    return tuple(events)


def _event_envelope(
    request: PlatformUserPostgresDatabaseRequest,
    event: _OutboxRecord,
    occurred_at: datetime,
) -> Dict[str, Any]:
    return {
        "event_id": str(event.event_id),
        "event_type": event.event_type,
        "schema_version": 1,
        "occurred_at": _timestamp(occurred_at),
        "aggregate_type": event.aggregate_type,
        "aggregate_id": str(event.aggregate_id),
        "aggregate_version": event.aggregate_version,
        "actor_kind": "USER",
        "actor_id": str(request.scope.actor_user_id),
        "original_actor_id": (
            str(request.scope.original_actor_id)
            if request.scope.original_actor_id is not None
            else None
        ),
        "correlation_id": str(request.scope.correlation_id),
        "causation_id": str(request.scope.command_id),
        "trace_id": str(request.scope.trace_id),
        "organization_id": None,
        "payload": dict(event.payload),
    }


def _canonical_path(request: PlatformUserPostgresDatabaseRequest) -> str:
    if _is_duty_operation(request.operation):
        action = (
            "grant"
            if request.operation is PlatformUserPostgresOperation.GRANT_PLATFORM_DUTY
            else "revoke"
        )
        return (
            "/v1/app/admin/accounts/%s/platform-duties/%s/%s"
            % (request.scope.target_user_id, request.duty_code, action)
        )
    suffix = {
        PlatformUserPostgresOperation.SUSPEND_USER: "suspend",
        PlatformUserPostgresOperation.RESUME_USER: "resume",
        PlatformUserPostgresOperation.REVOKE_ALL_SESSIONS: "revoke-all-sessions",
    }[request.operation]
    return "/v1/platform/users/%s/%s" % (request.scope.target_user_id, suffix)


def _database_operation(operation: PlatformUserPostgresOperation) -> str:
    return {
        PlatformUserPostgresOperation.SUSPEND_USER: "SUSPEND_USER",
        PlatformUserPostgresOperation.RESUME_USER: "RESUME_USER",
        PlatformUserPostgresOperation.REVOKE_ALL_SESSIONS: "REVOKE_ALL_SESSIONS",
        PlatformUserPostgresOperation.GRANT_PLATFORM_DUTY: "GRANT_PLATFORM_DUTY",
        PlatformUserPostgresOperation.REVOKE_PLATFORM_DUTY: "REVOKE_PLATFORM_DUTY",
    }[operation]


def _is_duty_operation(operation: PlatformUserPostgresOperation) -> bool:
    return operation in {
        PlatformUserPostgresOperation.GRANT_PLATFORM_DUTY,
        PlatformUserPostgresOperation.REVOKE_PLATFORM_DUTY,
    }


def _after_status(operation: PlatformUserPostgresOperation, before: str) -> str:
    if operation is PlatformUserPostgresOperation.SUSPEND_USER:
        return "SUSPENDED"
    if operation is PlatformUserPostgresOperation.RESUME_USER:
        return "ACTIVE"
    return before


def _entity_tag(version: int) -> str:
    return '"v%d"' % _positive_int(version)


def _timestamp(value: datetime) -> str:
    _require_utc(value, "event occurred_at")
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _positive_int(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise IamError("SERVICE_UNAVAILABLE")
    return value


def _text(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise IamError("SERVICE_UNAVAILABLE")
    return value


def _uuid(value: object) -> UUID:
    try:
        parsed = value if isinstance(value, UUID) else UUID(str(value))
    except (TypeError, ValueError, AttributeError) as error:
        raise IamError("SERVICE_UNAVAILABLE") from error
    if parsed.int == 0:
        raise IamError("SERVICE_UNAVAILABLE")
    return parsed


def _require_operation(
    request: object,
    expected: PlatformUserPostgresOperation,
) -> None:
    if not isinstance(request, PlatformUserPostgresDatabaseRequest):
        raise TypeError("closed platform user database request is required")
    if request.operation is not expected:
        raise ValueError("platform user database request operation mismatch")


def _retryable(error: BaseException) -> bool:
    if isinstance(error, PlatformUserPostgresCommitOutcomeUnknownError):
        return False
    return getattr(error, "sqlstate", None) in ("40001", "40P01", "55P03")


def _require_digest(value: object, label: str) -> None:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError("%s must be a 32-byte digest" % label)


def _require_key_id(value: object, label: str) -> None:
    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        raise ValueError("%s is invalid" % label)


def _require_utc(value: object, label: str) -> None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise ValueError("%s must be aware UTC" % label)


__all__ = [
    "NoPlatformUserPostgresFaults",
    "PLATFORM_USER_POSTGRES_WRITE_CHECKPOINTS",
    "PlatformUserPostgresCommitOutcomeUnknownError",
    "PlatformUserPostgresConfigurationError",
    "PlatformUserPostgresConnectionSource",
    "PlatformUserPostgresDatabaseRequest",
    "PlatformUserPostgresDatabaseResult",
    "PlatformUserPostgresExecutionScope",
    "PlatformUserPostgresFaultInjector",
    "PlatformUserPostgresGeneratedIds",
    "PlatformUserPostgresOperation",
    "PlatformUserPostgresReceiptMaterial",
    "PlatformUserPostgresSchemaValidator",
    "PlatformUserPostgresSettings",
    "PlatformUserPostgresWriteCheckpoint",
    "PsycopgPlatformUserLifecycleUnitOfWorkFactory",
]
