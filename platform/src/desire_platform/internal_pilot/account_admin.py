"""PostgreSQL-only ACCESS_ADMIN workbench for synthetic role accounts.

The workbench is deliberately scoped to the at-most-sixteen accounts recorded
by the active INTERNAL_SANDBOX identity bootstrap.  Authentication and the
selected platform workspace are resolved before this service is called, then
PostgreSQL independently revalidates the exact User, Session, SessionFamily
and ACCESS_ADMIN duty for every read and command.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import re
from typing import Any, Mapping, Optional, Protocol, Sequence, Tuple, Union
from uuid import UUID

from psycopg.pq import TransactionStatus

from desire_platform.identity_access.adapters.postgres.platform_user_lifecycle import (
    PlatformUserPostgresCommitOutcomeUnknownError,
    PlatformUserPostgresConfigurationError,
    PlatformUserPostgresDatabaseRequest,
    PlatformUserPostgresExecutionScope,
    PlatformUserPostgresGeneratedIds,
    PlatformUserPostgresOperation,
    PlatformUserPostgresReceiptMaterial,
    PsycopgPlatformUserLifecycleUnitOfWorkFactory,
)
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.utc import parse_utc_timestamp

from .editor.contracts import EditorPrincipal, EditorServiceError


ACCOUNT_ADMIN_REASON_CODES: Tuple[str, ...] = (
    "ACCESS_REVIEW",
    "SAFETY_REVIEW",
    "SESSION_HYGIENE",
)
ACCOUNT_ADMIN_PLATFORM_DUTY_CODES: Tuple[str, ...] = (
    "ACCESS_ADMIN",
    "APPEAL_REVIEWER",
    "FINANCE_OPERATOR",
    "OPERATIONS_REVIEWER",
    "TRUST_OFFICER",
)

_ACCOUNT_ACTIONS = {
    "SUSPEND": PlatformUserPostgresOperation.SUSPEND_USER,
    "RESUME": PlatformUserPostgresOperation.RESUME_USER,
    "REVOKE_ALL_SESSIONS": PlatformUserPostgresOperation.REVOKE_ALL_SESSIONS,
}
_ACCOUNT_CODE = re.compile(r"^[a-z][a-z0-9_]{2,31}$")
_DISPLAY_HANDLE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{1,79}$")
_ETAG = re.compile(r'^"v([1-9][0-9]*)"$')
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]{15,127}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
_ROLE_CODES = frozenset(
    (
        "ACCESS_ADMIN",
        "APPEAL_REVIEWER",
        "CREATOR",
        "DEMAND_OWNER",
        "FINANCE_OPERATOR",
        "OPERATIONS_REVIEWER",
        "ORG_ADMIN",
        "TRUST_OFFICER",
    )
)
_READ_SCOPE = "INTERNAL_SANDBOX_ACCOUNT_ADMIN_READ"
_READ_OPERATIONS = frozenset(("LIST_ACCOUNTS", "GET_ACCOUNT"))
_READ_FUNCTION = "iam_api.read_internal_sandbox_account_workbench_v2"
_IDEMPOTENCY_KEY_ID = "iam-receipt-idempotency-hmac-2026-01"
_PAYLOAD_KEY_ID = "iam-receipt-payload-hmac-2026-01"


class AccountAdminConnectionSource(Protocol):
    def checkout(self) -> Any: ...

    def release(self, connection: Any) -> None: ...

    def discard(self, connection: Any) -> None: ...


class AccountAdminClock(Protocol):
    def now(self) -> datetime: ...


class AccountAdminIdSource(Protocol):
    def new_id(self, purpose: str) -> UUID: ...


@dataclass(frozen=True, repr=False)
class PlatformUserAdminKeys:
    """Two stable, non-aliased receipt keys owned by managed secrets."""

    idempotency_key: Union[bytes, bytearray] = field(repr=False)
    payload_hash_key: Union[bytes, bytearray] = field(repr=False)
    idempotency_key_id: str = _IDEMPOTENCY_KEY_ID
    payload_hash_key_id: str = _PAYLOAD_KEY_ID

    def __post_init__(self) -> None:
        materials = (self.idempotency_key, self.payload_hash_key)
        if any(
            not isinstance(value, (bytes, bytearray))
            or len(value) < 32
            or not any(value)
            for value in materials
        ):
            raise ValueError("platform user administration keys are unavailable")
        if hmac.compare_digest(bytes(materials[0]), bytes(materials[1])):
            raise ValueError("platform user administration keys must not alias")
        if (
            any(
                _KEY_ID.fullmatch(value) is None
                for value in (self.idempotency_key_id, self.payload_hash_key_id)
            )
        ):
            raise ValueError("platform user administration key IDs are invalid")

    def __repr__(self) -> str:
        return (
            "PlatformUserAdminKeys("
            f"idempotency_key_id={self.idempotency_key_id!r}, "
            f"payload_hash_key_id={self.payload_hash_key_id!r}, "
            "material=<redacted>)"
        )


@dataclass(frozen=True)
class AccountAdminPostgresSettings:
    runtime_role: str = "iam_app"
    lock_timeout_ms: int = 500
    statement_timeout_ms: int = 5_000
    idle_in_transaction_timeout_ms: int = 10_000

    def __post_init__(self) -> None:
        if self.runtime_role != "iam_app":
            raise ValueError("account workbench runtime role must be iam_app")
        if not 1 <= self.lock_timeout_ms <= 1_000:
            raise ValueError("account workbench lock timeout is invalid")
        if not 1 <= self.statement_timeout_ms <= 5_000:
            raise ValueError("account workbench statement timeout is invalid")
        if not 1 <= self.idle_in_transaction_timeout_ms <= 10_000:
            raise ValueError("account workbench idle timeout is invalid")


@dataclass(frozen=True)
class InternalSandboxAccountAdminDto:
    account_code: str
    user_id: str
    display_handle: str
    status: str
    aggregate_version: int
    entity_tag: str
    role_codes: Tuple[str, ...]
    active_session_count: int
    created_at: datetime
    updated_at: datetime
    is_self: bool

    def __post_init__(self) -> None:
        user_id = _uuid_text(self.user_id)
        expected_tag = f'"v{self.aggregate_version}"'
        if (
            _ACCOUNT_CODE.fullmatch(self.account_code) is None
            or user_id != self.user_id
            or _DISPLAY_HANDLE.fullmatch(self.display_handle) is None
            or self.status not in {"ACTIVE", "SUSPENDED"}
            or not isinstance(self.aggregate_version, int)
            or isinstance(self.aggregate_version, bool)
            or self.aggregate_version < 1
            or self.entity_tag != expected_tag
            or not isinstance(self.role_codes, tuple)
            or not 0 <= len(self.role_codes) <= 8
            or self.role_codes != tuple(sorted(set(self.role_codes)))
            or not set(self.role_codes).issubset(_ROLE_CODES)
            or not isinstance(self.active_session_count, int)
            or isinstance(self.active_session_count, bool)
            or not 0 <= self.active_session_count <= 64
            or not isinstance(self.is_self, bool)
        ):
            raise ValueError("internal sandbox account projection is invalid")
        created = _utc(self.created_at)
        updated = _utc(self.updated_at)
        if created > updated:
            raise ValueError("internal sandbox account timestamps are invalid")


@dataclass(frozen=True)
class InternalSandboxAccountAdminCollectionDto:
    schema_version: str
    evaluated_at: datetime
    accounts: Tuple[InternalSandboxAccountAdminDto, ...]

    def __post_init__(self) -> None:
        evaluated = _utc(self.evaluated_at)
        if (
            self.schema_version != "internal-sandbox-account-admin-v1"
            or not isinstance(self.accounts, tuple)
            or not 1 <= len(self.accounts) <= 16
            or any(
                not isinstance(account, InternalSandboxAccountAdminDto)
                for account in self.accounts
            )
            or tuple(account.account_code for account in self.accounts)
            != tuple(sorted(account.account_code for account in self.accounts))
            or len({account.account_code for account in self.accounts})
            != len(self.accounts)
            or len({account.user_id for account in self.accounts}) != len(self.accounts)
            or sum(account.is_self for account in self.accounts) != 1
            or any(account.updated_at > evaluated for account in self.accounts)
        ):
            raise ValueError("internal sandbox account collection is invalid")


@dataclass(frozen=True)
class InternalSandboxAccountAdminCommandDto:
    user_id: str
    display_handle: str
    status: str
    aggregate_version: int
    entity_tag: str
    revoked_session_count: int
    revoked_session_family_count: int
    replayed: bool

    @property
    def etag(self) -> str:
        return self.entity_tag

    def __post_init__(self) -> None:
        if (
            _uuid_text(self.user_id) != self.user_id
            or _DISPLAY_HANDLE.fullmatch(self.display_handle) is None
            or self.status not in {"ACTIVE", "SUSPENDED"}
            or not isinstance(self.aggregate_version, int)
            or isinstance(self.aggregate_version, bool)
            or self.aggregate_version < 1
            or self.entity_tag != f'"v{self.aggregate_version}"'
            or any(
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
                for value in (
                    self.revoked_session_count,
                    self.revoked_session_family_count,
                )
            )
            or not isinstance(self.replayed, bool)
        ):
            raise ValueError("internal sandbox account command result is invalid")


class PsycopgInternalSandboxAccountAdminRepository:
    """Execute the one IAM0027 account-workbench read program."""

    def __init__(
        self,
        *,
        connections: AccountAdminConnectionSource,
        settings: AccountAdminPostgresSettings = AccountAdminPostgresSettings(),
    ) -> None:
        if not all(
            callable(getattr(connections, name, None))
            for name in ("checkout", "release", "discard")
        ):
            raise TypeError("account workbench connection source is unavailable")
        if not isinstance(settings, AccountAdminPostgresSettings):
            raise TypeError("account workbench settings are unavailable")
        self.connections = connections
        self.settings = settings

    def list_accounts(
        self, *, actor_user_id: str, session_id: str
    ) -> InternalSandboxAccountAdminCollectionDto:
        result = self._read(
            actor_user_id=actor_user_id,
            session_id=session_id,
            target_user_id=None,
        )
        if not isinstance(result, InternalSandboxAccountAdminCollectionDto):
            raise IamError("SERVICE_UNAVAILABLE")
        return result

    def get_account(
        self, *, actor_user_id: str, session_id: str, target_user_id: str
    ) -> InternalSandboxAccountAdminDto:
        target = _uuid_text(target_user_id)
        result = self._read(
            actor_user_id=actor_user_id,
            session_id=session_id,
            target_user_id=target,
        )
        if (
            not isinstance(result, InternalSandboxAccountAdminDto)
            or result.user_id != target
        ):
            raise IamError("RESOURCE_NOT_FOUND")
        return result

    def _read(
        self,
        *,
        actor_user_id: str,
        session_id: str,
        target_user_id: Optional[str],
    ) -> Union[
        InternalSandboxAccountAdminCollectionDto,
        InternalSandboxAccountAdminDto,
    ]:
        actor = _uuid_text(actor_user_id)
        session = _uuid_text(session_id)
        operation = "LIST_ACCOUNTS" if target_user_id is None else "GET_ACCOUNT"
        if operation not in _READ_OPERATIONS:
            raise IamError("SERVICE_UNAVAILABLE")
        connection = self.connections.checkout()
        transaction_started = False
        disposed = False
        try:
            self._validate_connection(connection)
            connection.execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
            transaction_started = True
            self._configure(
                connection,
                operation=operation,
                actor_user_id=actor,
                session_id=session,
                target_user_id=target_user_id,
            )
            row = connection.execute(
                f"SELECT {_READ_FUNCTION}(%s::uuid,%s::uuid,%s::uuid)",
                (actor, session, target_user_id),
            ).fetchone()
            if row is None or len(row) != 1 or not isinstance(row[0], dict):
                raise IamError("SERVICE_UNAVAILABLE")
            result = (
                _collection(row[0])
                if target_user_id is None
                else _detail(row[0], target_user_id=target_user_id)
            )
            connection.execute("COMMIT")
            transaction_started = False
        except IamError:
            if transaction_started:
                _rollback(connection)
            disposed = self._release_or_discard(connection)
            raise
        except BaseException:
            if transaction_started:
                _rollback(connection)
            disposed = self._release_or_discard(connection)
            raise IamError("SERVICE_UNAVAILABLE") from None
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
            raise RuntimeError("account workbench checkout is not transaction-idle")
        identity = connection.execute(
            "SELECT current_user,session_user,"
            "current_setting('server_version_num')::integer"
        ).fetchone()
        if identity is None or identity[0:2] != (
            self.settings.runtime_role,
            self.settings.runtime_role,
        ) or identity[2] // 10_000 != 18:
            raise RuntimeError("account workbench connection identity is invalid")

    def _configure(
        self,
        connection: Any,
        *,
        operation: str,
        actor_user_id: str,
        session_id: str,
        target_user_id: Optional[str],
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
            ("app.scope_kind", _READ_SCOPE),
            ("app.operation", operation),
            ("app.actor_user_id", actor_user_id),
            ("app.session_id", session_id),
            ("app.target_user_id", target_user_id or ""),
            ("app.organization_id", ""),
        )
        for name, value in values:
            configured = connection.execute(
                "SELECT pg_catalog.set_config(%s,%s,true)", (name, value)
            ).fetchone()
            if configured != (value,):
                raise RuntimeError("account workbench context was rejected")
        for name, expected in values:
            actual = connection.execute(
                "SELECT current_setting(%s,true)", (name,)
            ).fetchone()
            if actual != (expected,):
                raise RuntimeError("account workbench context readback failed")

    def _release_or_discard(self, connection: Any) -> bool:
        try:
            if connection.info.transaction_status != TransactionStatus.IDLE:
                self.connections.discard(connection)
                return True
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


class PostgresInternalSandboxAccountAdminService:
    """Translate selected-workspace calls into exact reads and IAM0018 UoWs."""

    def __init__(
        self,
        *,
        repository: PsycopgInternalSandboxAccountAdminRepository,
        lifecycle: PsycopgPlatformUserLifecycleUnitOfWorkFactory,
        keys: PlatformUserAdminKeys,
        clock: AccountAdminClock,
        id_source: AccountAdminIdSource,
    ) -> None:
        if not isinstance(repository, PsycopgInternalSandboxAccountAdminRepository):
            raise TypeError("PostgreSQL account workbench repository is unavailable")
        if not isinstance(lifecycle, PsycopgPlatformUserLifecycleUnitOfWorkFactory):
            raise TypeError("PostgreSQL platform user lifecycle is unavailable")
        if not isinstance(keys, PlatformUserAdminKeys):
            raise TypeError("platform user administration keys are unavailable")
        if not callable(getattr(clock, "now", None)) or not callable(
            getattr(id_source, "new_id", None)
        ):
            raise TypeError("account workbench runtime sources are unavailable")
        self._repo = repository
        self._lifecycle = lifecycle
        self._keys = keys
        self._clock = clock
        self._ids = id_source

    def list_accounts(
        self, *, principal: EditorPrincipal
    ) -> InternalSandboxAccountAdminCollectionDto:
        self._require_access_admin(principal)
        try:
            return self._repo.list_accounts(
                actor_user_id=principal.user_id,
                session_id=principal.session_id,
            )
        except IamError as error:
            self._raise_read(error)

    def get_account(
        self, *, principal: EditorPrincipal, user_id: str
    ) -> InternalSandboxAccountAdminDto:
        self._require_access_admin(principal)
        target = _uuid_text_or_not_found(user_id)
        try:
            return self._repo.get_account(
                actor_user_id=principal.user_id,
                session_id=principal.session_id,
                target_user_id=target,
            )
        except IamError as error:
            self._raise_read(error)

    def manage_account(
        self,
        *,
        principal: EditorPrincipal,
        user_id: str,
        action: str,
        if_match: str,
        idempotency_key: str,
        reason_code: str,
    ) -> InternalSandboxAccountAdminCommandDto:
        self._require_access_admin(principal)
        target = _uuid_text_or_not_found(user_id)
        if target == principal.user_id:
            raise EditorServiceError(status=403, code="SELF_MANAGEMENT_FORBIDDEN")
        try:
            operation = _ACCOUNT_ACTIONS[action]
        except (KeyError, TypeError):
            raise EditorServiceError(status=404, code="RESOURCE_NOT_FOUND") from None
        match = _ETAG.fullmatch(if_match) if isinstance(if_match, str) else None
        if match is None:
            raise EditorServiceError(
                status=422, code="INVALID_PRECONDITION", path="/headers/If-Match"
            )
        if (
            not isinstance(idempotency_key, str)
            or _IDEMPOTENCY_KEY.fullmatch(idempotency_key) is None
        ):
            raise EditorServiceError(
                status=422,
                code="INVALID_IDEMPOTENCY_KEY",
                path="/headers/Idempotency-Key",
            )
        if reason_code not in ACCOUNT_ADMIN_REASON_CODES:
            raise EditorServiceError(
                status=422, code="INVALID_REASON_CODE", path="/reason_code"
            )
        self._require_synthetic_target(principal=principal, target_user_id=target)
        request = self._request(
            principal=principal,
            target_user_id=target,
            operation=operation,
            expected_version=int(match.group(1)),
            idempotency_key=idempotency_key,
            reason_code=reason_code,
        )
        try:
            executor = {
                PlatformUserPostgresOperation.SUSPEND_USER: (
                    self._lifecycle.execute_suspend_user
                ),
                PlatformUserPostgresOperation.RESUME_USER: (
                    self._lifecycle.execute_resume_user
                ),
                PlatformUserPostgresOperation.REVOKE_ALL_SESSIONS: (
                    self._lifecycle.execute_revoke_all_sessions
                ),
            }[operation]
            result = executor(request)
            return _command(result.safe_response, replayed=result.replayed)
        except PlatformUserPostgresCommitOutcomeUnknownError:
            raise EditorServiceError(status=503, code="COMMAND_OUTCOME_UNKNOWN") from None
        except PlatformUserPostgresConfigurationError:
            raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE") from None
        except IamError as error:
            self._raise_command(
                error,
                principal=principal,
                target_user_id=target,
            )

    def manage_platform_duty(
        self,
        *,
        principal: EditorPrincipal,
        user_id: str,
        duty_code: str,
        action: str,
        if_match: str,
        idempotency_key: str,
        reason_code: str,
    ) -> InternalSandboxAccountAdminCommandDto:
        self._require_access_admin(principal)
        target = _uuid_text_or_not_found(user_id)
        if target == principal.user_id:
            raise EditorServiceError(status=403, code="SELF_MANAGEMENT_FORBIDDEN")
        if duty_code not in ACCOUNT_ADMIN_PLATFORM_DUTY_CODES:
            raise EditorServiceError(status=404, code="RESOURCE_NOT_FOUND")
        try:
            operation = {
                "GRANT": PlatformUserPostgresOperation.GRANT_PLATFORM_DUTY,
                "REVOKE": PlatformUserPostgresOperation.REVOKE_PLATFORM_DUTY,
            }[action]
        except (KeyError, TypeError):
            raise EditorServiceError(status=404, code="RESOURCE_NOT_FOUND") from None
        match = _ETAG.fullmatch(if_match) if isinstance(if_match, str) else None
        if match is None:
            raise EditorServiceError(
                status=422, code="INVALID_PRECONDITION", path="/headers/If-Match"
            )
        if (
            not isinstance(idempotency_key, str)
            or _IDEMPOTENCY_KEY.fullmatch(idempotency_key) is None
        ):
            raise EditorServiceError(
                status=422,
                code="INVALID_IDEMPOTENCY_KEY",
                path="/headers/Idempotency-Key",
            )
        if reason_code not in ACCOUNT_ADMIN_REASON_CODES:
            raise EditorServiceError(
                status=422, code="INVALID_REASON_CODE", path="/reason_code"
            )
        request = self._duty_request(
            principal=principal,
            target_user_id=target,
            operation=operation,
            expected_version=int(match.group(1)),
            idempotency_key=idempotency_key,
            reason_code=reason_code,
            duty_code=duty_code,
        )
        try:
            executor = {
                PlatformUserPostgresOperation.GRANT_PLATFORM_DUTY: (
                    self._lifecycle.execute_grant_platform_duty
                ),
                PlatformUserPostgresOperation.REVOKE_PLATFORM_DUTY: (
                    self._lifecycle.execute_revoke_platform_duty
                ),
            }[operation]
            result = executor(request)
            return _command(result.safe_response, replayed=result.replayed)
        except PlatformUserPostgresCommitOutcomeUnknownError:
            raise EditorServiceError(status=503, code="COMMAND_OUTCOME_UNKNOWN") from None
        except PlatformUserPostgresConfigurationError:
            raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE") from None
        except IamError as error:
            self._raise_command(
                error,
                principal=principal,
                target_user_id=target,
            )

    def _request(
        self,
        *,
        principal: EditorPrincipal,
        target_user_id: str,
        operation: PlatformUserPostgresOperation,
        expected_version: int,
        idempotency_key: str,
        reason_code: str,
    ) -> PlatformUserPostgresDatabaseRequest:
        actor = UUID(principal.user_id)
        target = UUID(target_user_id)
        session = UUID(principal.session_id)
        command_id = self._new_id("platform_user_command")
        correlation_id = self._new_id("platform_user_correlation")
        trace_id = self._new_id("platform_user_trace")
        now = self._now()
        canonical_path = _command_path(operation, target_user_id)
        command_name = operation.value
        reason_body = {"reason_code": reason_code, "reason_note_digest": None}
        idempotency_digest = _hmac(
            self._keys.idempotency_key,
            _canonical(
                {
                    "domain": "iam-lifecycle-idempotency-key-v1",
                    "idempotency_key": idempotency_key,
                }
            ),
        )
        payload_hash = _hmac(
            self._keys.payload_hash_key,
            _canonical(
                {
                    "body": {"reason": reason_body},
                    "canonicalization_version": "restricted-canonical-json-v1",
                    "command_name": command_name,
                    "command_version": 1,
                    "http_method": "POST",
                    "if_match_version": expected_version,
                    "path": canonical_path,
                    "target_id": target_user_id,
                    "target_kind": "User",
                }
            ),
        )
        return PlatformUserPostgresDatabaseRequest(
            operation=operation,
            scope=PlatformUserPostgresExecutionScope(
                actor_user_id=actor,
                current_session_id=session,
                target_user_id=target,
                command_id=command_id,
                correlation_id=correlation_id,
                causation_id=command_id,
                trace_id=trace_id,
                original_actor_id=None,
            ),
            receipt=PlatformUserPostgresReceiptMaterial(
                receipt_id=command_id,
                idempotency_key_digest=idempotency_digest,
                idempotency_key_digest_key_id=self._keys.idempotency_key_id,
                payload_hash=payload_hash,
                payload_hash_key_id=self._keys.payload_hash_key_id,
                canonicalization_version="restricted-canonical-json-v1",
                retain_until=now + timedelta(days=30),
            ),
            expected_user_version=expected_version,
            reason_code=reason_code,
            generated_ids=PlatformUserPostgresGeneratedIds(
                audit_event_id=self._new_id("platform_user_audit"),
                main_outbox_event_id=self._new_id("platform_user_outbox"),
                session_event_namespace=self._new_id(
                    "platform_user_session_event_namespace"
                ),
            ),
        )

    def _duty_request(
        self,
        *,
        principal: EditorPrincipal,
        target_user_id: str,
        operation: PlatformUserPostgresOperation,
        expected_version: int,
        idempotency_key: str,
        reason_code: str,
        duty_code: str,
    ) -> PlatformUserPostgresDatabaseRequest:
        actor = UUID(principal.user_id)
        target = UUID(target_user_id)
        session = UUID(principal.session_id)
        command_id = self._new_id("platform_duty_command")
        correlation_id = self._new_id("platform_duty_correlation")
        trace_id = self._new_id("platform_duty_trace")
        now = self._now()
        action = (
            "grant"
            if operation is PlatformUserPostgresOperation.GRANT_PLATFORM_DUTY
            else "revoke"
        )
        canonical_path = (
            f"/v1/app/admin/accounts/{target_user_id}/platform-duties/"
            f"{duty_code}/{action}"
        )
        reason_body = {"reason_code": reason_code, "reason_note_digest": None}
        idempotency_digest = _hmac(
            self._keys.idempotency_key,
            _canonical(
                {
                    "domain": "iam-platform-duty-idempotency-key-v1",
                    "idempotency_key": idempotency_key,
                }
            ),
        )
        payload_hash = _hmac(
            self._keys.payload_hash_key,
            _canonical(
                {
                    "body": {"reason": reason_body},
                    "canonicalization_version": "restricted-canonical-json-v1",
                    "command_name": operation.value,
                    "command_version": 1,
                    "http_method": "POST",
                    "if_match_version": expected_version,
                    "path": canonical_path,
                    "target_id": target_user_id,
                    "target_kind": "User",
                }
            ),
        )
        return PlatformUserPostgresDatabaseRequest(
            operation=operation,
            scope=PlatformUserPostgresExecutionScope(
                actor_user_id=actor,
                current_session_id=session,
                target_user_id=target,
                command_id=command_id,
                correlation_id=correlation_id,
                causation_id=command_id,
                trace_id=trace_id,
                original_actor_id=None,
            ),
            receipt=PlatformUserPostgresReceiptMaterial(
                receipt_id=command_id,
                idempotency_key_digest=idempotency_digest,
                idempotency_key_digest_key_id=self._keys.idempotency_key_id,
                payload_hash=payload_hash,
                payload_hash_key_id=self._keys.payload_hash_key_id,
                canonicalization_version="restricted-canonical-json-v1",
                retain_until=now + timedelta(days=30),
            ),
            expected_user_version=expected_version,
            reason_code=reason_code,
            generated_ids=PlatformUserPostgresGeneratedIds(
                audit_event_id=self._new_id("platform_duty_audit"),
                main_outbox_event_id=self._new_id("platform_duty_outbox"),
                session_event_namespace=self._new_id(
                    "platform_duty_session_event_namespace"
                ),
                platform_duty_grant_id=(
                    self._new_id("platform_duty_grant")
                    if operation is PlatformUserPostgresOperation.GRANT_PLATFORM_DUTY
                    else None
                ),
            ),
            duty_code=duty_code,
        )

    @staticmethod
    def _require_access_admin(principal: EditorPrincipal) -> None:
        if (
            not isinstance(principal, EditorPrincipal)
            or principal.workspace_kind != "PLATFORM"
            or principal.workspace_id != f"platform:{principal.user_id}"
            or "ACCESS_ADMIN" not in principal.role_codes
            or principal.role_codes
            != tuple(sorted(set(principal.platform_duty_codes)))
            or len(principal.principal_marker_sha256) != 32
        ):
            raise EditorServiceError(status=404, code="RESOURCE_NOT_FOUND")

    @staticmethod
    def _raise_read(error: IamError) -> None:
        if error.code == "RESOURCE_NOT_FOUND":
            raise EditorServiceError(status=404, code="RESOURCE_NOT_FOUND") from None
        raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE") from None

    def _raise_command(
        self,
        error: IamError,
        *,
        principal: EditorPrincipal,
        target_user_id: str,
    ) -> None:
        status = {
            "RESOURCE_NOT_FOUND": 404,
            "SELF_MANAGEMENT_FORBIDDEN": 403,
            "MFA_STEP_UP_REQUIRED": 403,
            "IDEMPOTENCY_KEY_REUSED": 409,
            "LAST_ACTIVE_ACCESS_ADMIN": 409,
            "INVALID_STATE_TRANSITION": 409,
            "PRECONDITION_FAILED": 412,
        }.get(error.code)
        if status is None:
            raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE") from None
        etag = None
        if error.code == "PRECONDITION_FAILED":
            try:
                current = self._repo.get_account(
                    actor_user_id=principal.user_id,
                    session_id=principal.session_id,
                    target_user_id=target_user_id,
                )
                etag = current.entity_tag
            except BaseException:
                raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE") from None
        raise EditorServiceError(status=status, code=error.code, etag=etag) from None

    def _require_synthetic_target(
        self,
        *,
        principal: EditorPrincipal,
        target_user_id: str,
    ) -> None:
        try:
            target = self._repo.get_account(
                actor_user_id=principal.user_id,
                session_id=principal.session_id,
                target_user_id=target_user_id,
            )
        except IamError as error:
            self._raise_read(error)
        if target.user_id != target_user_id:
            raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE")

    def _now(self) -> datetime:
        try:
            return _utc(self._clock.now())
        except BaseException:
            raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE") from None

    def _new_id(self, purpose: str) -> UUID:
        try:
            value = self._ids.new_id(purpose)
        except BaseException:
            raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE") from None
        if not isinstance(value, UUID) or value.int == 0:
            raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE")
        return value


def _collection(value: Mapping[str, Any]) -> InternalSandboxAccountAdminCollectionDto:
    if set(value) != {"schema_version", "evaluated_at", "accounts"}:
        raise IamError("SERVICE_UNAVAILABLE")
    raw_accounts = value.get("accounts")
    if not isinstance(raw_accounts, list):
        raise IamError("SERVICE_UNAVAILABLE")
    try:
        return InternalSandboxAccountAdminCollectionDto(
            schema_version=value["schema_version"],
            evaluated_at=_timestamp(value["evaluated_at"]),
            accounts=tuple(_account(item) for item in raw_accounts),
        )
    except (KeyError, TypeError, ValueError):
        raise IamError("SERVICE_UNAVAILABLE") from None


def _detail(
    value: Mapping[str, Any], *, target_user_id: str
) -> InternalSandboxAccountAdminDto:
    if set(value) != {"schema_version", "evaluated_at", "accounts"}:
        raise IamError("SERVICE_UNAVAILABLE")
    if value.get("schema_version") != "internal-sandbox-account-admin-v1":
        raise IamError("SERVICE_UNAVAILABLE")
    raw_accounts = value.get("accounts")
    if raw_accounts == []:
        raise IamError("RESOURCE_NOT_FOUND")
    if not isinstance(raw_accounts, list) or len(raw_accounts) != 1:
        raise IamError("SERVICE_UNAVAILABLE")
    try:
        evaluated_at = _timestamp(value["evaluated_at"])
        account = _account(raw_accounts[0])
        if account.user_id != target_user_id or account.updated_at > evaluated_at:
            raise ValueError("account detail is inconsistent")
        return account
    except (KeyError, TypeError, ValueError):
        raise IamError("SERVICE_UNAVAILABLE") from None


def _account(value: Any) -> InternalSandboxAccountAdminDto:
    expected = {
        "account_code",
        "user_id",
        "display_handle",
        "status",
        "aggregate_version",
        "entity_tag",
        "role_codes",
        "active_session_count",
        "created_at",
        "updated_at",
        "is_self",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("invalid account row")
    roles = value["role_codes"]
    if not isinstance(roles, list):
        raise ValueError("invalid role codes")
    return InternalSandboxAccountAdminDto(
        account_code=value["account_code"],
        user_id=value["user_id"],
        display_handle=value["display_handle"],
        status=value["status"],
        aggregate_version=value["aggregate_version"],
        entity_tag=value["entity_tag"],
        role_codes=tuple(roles),
        active_session_count=value["active_session_count"],
        created_at=_timestamp(value["created_at"]),
        updated_at=_timestamp(value["updated_at"]),
        is_self=value["is_self"],
    )


def _command(value: Mapping[str, Any], *, replayed: bool) -> InternalSandboxAccountAdminCommandDto:
    expected = {
        "user_id",
        "display_handle",
        "status",
        "aggregate_version",
        "entity_tag",
        "revoked_session_count",
        "revoked_session_family_count",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE")
    try:
        return InternalSandboxAccountAdminCommandDto(
            **dict(value), replayed=replayed
        )
    except (TypeError, ValueError):
        raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE") from None


def _uuid_text(value: Any) -> str:
    try:
        parsed = UUID(value)
    except (AttributeError, TypeError, ValueError):
        raise ValueError("account identifier is invalid") from None
    if parsed.int == 0 or str(parsed) != value:
        raise ValueError("account identifier is invalid")
    return str(parsed)


def _uuid_text_or_not_found(value: Any) -> str:
    try:
        return _uuid_text(value)
    except ValueError:
        raise EditorServiceError(status=404, code="RESOURCE_NOT_FOUND") from None


def _utc(value: Any) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("account timestamp is not aware")
    try:
        result = value.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        raise ValueError("account timestamp is invalid") from None
    if result.utcoffset() != timedelta(0):
        raise ValueError("account timestamp is not UTC")
    return result


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith(("Z", "+00:00")):
        raise ValueError("account timestamp text is invalid")
    try:
        return parse_utc_timestamp(value)
    except ValueError:
        raise ValueError("account timestamp text is invalid") from None


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _hmac(key: Union[bytes, bytearray], value: bytes) -> bytes:
    return hmac.new(key, value, hashlib.sha256).digest()


def _command_path(operation: PlatformUserPostgresOperation, target: str) -> str:
    suffix = {
        PlatformUserPostgresOperation.SUSPEND_USER: "suspend",
        PlatformUserPostgresOperation.RESUME_USER: "resume",
        PlatformUserPostgresOperation.REVOKE_ALL_SESSIONS: "revoke-all-sessions",
    }[operation]
    return f"/v1/platform/users/{target}/{suffix}"


def _rollback(connection: Any) -> None:
    try:
        connection.execute("ROLLBACK")
    except BaseException:
        pass


__all__ = [
    "ACCOUNT_ADMIN_PLATFORM_DUTY_CODES",
    "ACCOUNT_ADMIN_REASON_CODES",
    "AccountAdminPostgresSettings",
    "InternalSandboxAccountAdminCollectionDto",
    "InternalSandboxAccountAdminCommandDto",
    "InternalSandboxAccountAdminDto",
    "PlatformUserAdminKeys",
    "PostgresInternalSandboxAccountAdminService",
    "PsycopgInternalSandboxAccountAdminRepository",
]
