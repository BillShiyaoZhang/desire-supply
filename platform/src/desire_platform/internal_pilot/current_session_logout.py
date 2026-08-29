"""Production bridges for exact current and actor-owned Session revocation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import hmac
import json
from typing import Any, Mapping
from uuid import UUID

from desire_platform.identity_access.adapters.postgres.current_session_logout import (
    CurrentSessionLogoutPostgresCommitOutcomeUnknownError,
    CurrentSessionLogoutPostgresConfigurationError,
    CurrentSessionLogoutPostgresDatabaseRequest,
    CurrentSessionLogoutPostgresExecutionScope,
    CurrentSessionLogoutPostgresGeneratedIds,
    CurrentSessionLogoutPostgresReceiptMaterial,
    OwnedSessionRevocationPostgresDatabaseRequest,
    OwnedSessionRevocationPostgresExecutionScope,
)
from desire_platform.identity_access.domain.authority_lifecycle import (
    LifecycleActorContext,
    LifecycleCommandResult,
    RevokeSessionCommand,
)
from desire_platform.identity_access.domain.errors import IamError

from .policy_acceptance import IamReceiptPolicyKeys


_CANONICALIZATION_VERSION = "restricted-canonical-json-v1"
_IDENTITY_DOMAIN = "iam-self-command-idempotency-key-v1"
_RECEIPT_RETENTION = timedelta(days=30)


class PostgresRevokeCurrentSessionHandler:
    """Digest transport evidence and invoke only the current-Session UoW."""

    def __init__(
        self,
        *,
        uow_factory: Any,
        keys: IamReceiptPolicyKeys,
        clock: Any,
        id_source: Any,
    ) -> None:
        if not callable(getattr(uow_factory, "execute", None)):
            raise TypeError("current Session logout PostgreSQL unit of work is unavailable")
        if not isinstance(keys, IamReceiptPolicyKeys):
            raise TypeError("IAM receipt policy keys are unavailable")
        if not callable(getattr(clock, "now", None)) or not callable(
            getattr(id_source, "new_id", None)
        ):
            raise TypeError("current Session logout runtime sources are unavailable")
        self._uow_factory = uow_factory
        self._keys = keys
        self._clock = clock
        self._id_source = id_source

    def handle(
        self,
        *,
        actor: LifecycleActorContext,
        command: RevokeSessionCommand,
    ) -> LifecycleCommandResult:
        if not isinstance(actor, LifecycleActorContext) or not isinstance(
            command, RevokeSessionCommand
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        if actor.original_actor_id is not None:
            raise IamError("AUTHENTICATION_REQUIRED")
        try:
            actor_id = _uuid(actor.actor_user_id)
            current_session_id = _uuid(actor.current_session_id)
            target_session_id = _uuid(command.session_id)
            correlation_id = _uuid(actor.correlation_id)
            trace_id = _uuid(actor.trace_id)
        except (TypeError, ValueError):
            raise IamError("INVALID_REQUEST") from None
        if target_session_id != current_session_id:
            raise IamError("INVALID_REQUEST")
        if not isinstance(command.idempotency_key, str) or not command.idempotency_key:
            raise IamError("INVALID_REQUEST")
        try:
            now = _utc(self._clock.now())
        except BaseException:
            raise IamError("SERVICE_UNAVAILABLE") from None

        command_id = self._new_id("command_receipt")
        audit_event_id = self._new_id("audit_event")
        outbox_event_id = self._new_id("outbox_event")
        if len({command_id, audit_event_id, outbox_event_id}) != 3:
            raise IamError("SERVICE_UNAVAILABLE")

        identity = _canonical_bytes(
            {
                "domain": _IDENTITY_DOMAIN,
                "idempotency_key": command.idempotency_key,
            }
        )
        payload = _canonical_bytes(
            {
                "body": {},
                "canonicalization_version": _CANONICALIZATION_VERSION,
                "command_name": "RevokeSession",
                "command_version": 1,
                "http_method": "DELETE",
                "if_match_version": None,
                "path": f"/v1/me/sessions/{target_session_id}",
                "target_id": str(target_session_id),
                "target_kind": "Session",
            }
        )
        request = CurrentSessionLogoutPostgresDatabaseRequest(
            scope=CurrentSessionLogoutPostgresExecutionScope(
                actor_user_id=actor_id,
                current_session_id=current_session_id,
                target_session_id=target_session_id,
                command_id=command_id,
                correlation_id=correlation_id,
                causation_id=command_id,
                trace_id=trace_id,
                original_actor_id=None,
            ),
            receipt=CurrentSessionLogoutPostgresReceiptMaterial(
                receipt_id=command_id,
                idempotency_key_digest=_hmac(self._keys.idempotency_key, identity),
                idempotency_key_digest_key_id=self._keys.idempotency_key_id,
                payload_hash=_hmac(self._keys.payload_hash_key, payload),
                payload_hash_key_id=self._keys.payload_hash_key_id,
                canonicalization_version=_CANONICALIZATION_VERSION,
                retain_until=now + _RECEIPT_RETENTION,
            ),
            generated_ids=CurrentSessionLogoutPostgresGeneratedIds(
                audit_event_id=audit_event_id,
                outbox_event_id=outbox_event_id,
            ),
        )
        try:
            result = self._uow_factory.execute(request)
        except CurrentSessionLogoutPostgresCommitOutcomeUnknownError:
            raise IamError("COMMAND_OUTCOME_UNKNOWN") from None
        except CurrentSessionLogoutPostgresConfigurationError:
            raise IamError("SERVICE_UNAVAILABLE") from None
        except IamError:
            raise
        except BaseException:
            raise IamError("SERVICE_UNAVAILABLE") from None
        if (
            getattr(result, "session_id", None) != current_session_id
            or getattr(result, "session_status", None) not in {"REVOKED", "EXPIRED"}
            or type(getattr(result, "replayed", None)) is not bool
            or getattr(result, "clear_current_session_cookie", None) is not True
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        return LifecycleCommandResult(
            replayed=result.replayed,
            http_status=204,
            safe_response=None,
            clear_current_session_cookie=True,
        )

    def _new_id(self, purpose: str) -> UUID:
        try:
            value = self._id_source.new_id(purpose)
        except BaseException:
            raise IamError("SERVICE_UNAVAILABLE") from None
        if not isinstance(value, UUID) or value.int == 0:
            raise IamError("SERVICE_UNAVAILABLE")
        return value

    def __repr__(self) -> str:
        return "PostgresRevokeCurrentSessionHandler(dependencies=<redacted>)"


class PostgresRevokeOwnedSessionHandler:
    """Revoke one actor-owned Session through the IAM38 fixed program."""

    def __init__(
        self,
        *,
        uow_factory: Any,
        keys: IamReceiptPolicyKeys,
        clock: Any,
        id_source: Any,
    ) -> None:
        if not callable(getattr(uow_factory, "execute", None)):
            raise TypeError("owned Session revocation unit of work is unavailable")
        if not isinstance(keys, IamReceiptPolicyKeys):
            raise TypeError("IAM receipt policy keys are unavailable")
        if not callable(getattr(clock, "now", None)) or not callable(
            getattr(id_source, "new_id", None)
        ):
            raise TypeError("owned Session revocation runtime sources are unavailable")
        self._uow_factory = uow_factory
        self._keys = keys
        self._clock = clock
        self._id_source = id_source

    def handle(
        self,
        *,
        actor: LifecycleActorContext,
        command: RevokeSessionCommand,
    ) -> LifecycleCommandResult:
        if not isinstance(actor, LifecycleActorContext) or not isinstance(
            command, RevokeSessionCommand
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        if actor.original_actor_id is not None:
            raise IamError("AUTHENTICATION_REQUIRED")
        try:
            actor_id = _uuid(actor.actor_user_id)
            current_session_id = _uuid(actor.current_session_id)
            target_session_id = _uuid(command.session_id)
            correlation_id = _uuid(actor.correlation_id)
            trace_id = _uuid(actor.trace_id)
        except (TypeError, ValueError):
            raise IamError("INVALID_REQUEST") from None
        if not isinstance(command.idempotency_key, str) or not command.idempotency_key:
            raise IamError("INVALID_REQUEST")
        try:
            now = _utc(self._clock.now())
        except BaseException:
            raise IamError("SERVICE_UNAVAILABLE") from None

        command_id = self._new_id("command_receipt")
        audit_event_id = self._new_id("audit_event")
        outbox_event_id = self._new_id("outbox_event")
        if len({command_id, audit_event_id, outbox_event_id}) != 3:
            raise IamError("SERVICE_UNAVAILABLE")

        identity = _canonical_bytes(
            {
                "domain": _IDENTITY_DOMAIN,
                "idempotency_key": command.idempotency_key,
            }
        )
        payload = _canonical_bytes(
            {
                "body": {},
                "canonicalization_version": _CANONICALIZATION_VERSION,
                "command_name": "RevokeSession",
                "command_version": 1,
                "http_method": "DELETE",
                "if_match_version": None,
                "path": f"/v1/me/sessions/{target_session_id}",
                "target_id": str(target_session_id),
                "target_kind": "Session",
            }
        )
        request = OwnedSessionRevocationPostgresDatabaseRequest(
            scope=OwnedSessionRevocationPostgresExecutionScope(
                actor_user_id=actor_id,
                current_session_id=current_session_id,
                target_session_id=target_session_id,
                command_id=command_id,
                correlation_id=correlation_id,
                causation_id=command_id,
                trace_id=trace_id,
                original_actor_id=None,
            ),
            receipt=CurrentSessionLogoutPostgresReceiptMaterial(
                receipt_id=command_id,
                idempotency_key_digest=_hmac(self._keys.idempotency_key, identity),
                idempotency_key_digest_key_id=self._keys.idempotency_key_id,
                payload_hash=_hmac(self._keys.payload_hash_key, payload),
                payload_hash_key_id=self._keys.payload_hash_key_id,
                canonicalization_version=_CANONICALIZATION_VERSION,
                retain_until=now + _RECEIPT_RETENTION,
            ),
            generated_ids=CurrentSessionLogoutPostgresGeneratedIds(
                audit_event_id=audit_event_id,
                outbox_event_id=outbox_event_id,
            ),
        )
        try:
            result = self._uow_factory.execute(request)
        except CurrentSessionLogoutPostgresCommitOutcomeUnknownError:
            raise IamError("COMMAND_OUTCOME_UNKNOWN") from None
        except CurrentSessionLogoutPostgresConfigurationError:
            raise IamError("SERVICE_UNAVAILABLE") from None
        except IamError:
            raise
        except BaseException:
            raise IamError("SERVICE_UNAVAILABLE") from None

        expected_clear = target_session_id == current_session_id
        if (
            getattr(result, "current_session_id", None) != current_session_id
            or getattr(result, "session_id", None) != target_session_id
            or getattr(result, "session_status", None) not in {"REVOKED", "EXPIRED"}
            or type(getattr(result, "replayed", None)) is not bool
            or getattr(result, "clear_current_session_cookie", None)
            is not expected_clear
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        return LifecycleCommandResult(
            replayed=result.replayed,
            http_status=204,
            safe_response=None,
            clear_current_session_cookie=expected_clear,
        )

    def _new_id(self, purpose: str) -> UUID:
        try:
            value = self._id_source.new_id(purpose)
        except BaseException:
            raise IamError("SERVICE_UNAVAILABLE") from None
        if not isinstance(value, UUID) or value.int == 0:
            raise IamError("SERVICE_UNAVAILABLE")
        return value

    def __repr__(self) -> str:
        return "PostgresRevokeOwnedSessionHandler(dependencies=<redacted>)"


def _uuid(value: Any) -> UUID:
    if not isinstance(value, str):
        raise TypeError("UUID value is unavailable")
    result = UUID(value)
    if result.int == 0 or str(result) != value:
        raise ValueError("UUID value is not canonical")
    return result


def _utc(value: Any) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise ValueError("UTC time is unavailable")
    return value.astimezone(timezone.utc)


def _canonical_bytes(value: object) -> bytes:
    def normalize(item: object) -> object:
        if isinstance(item, Mapping):
            return {str(key): normalize(child) for key, child in item.items()}
        if isinstance(item, (list, tuple)):
            return [normalize(child) for child in item]
        if isinstance(item, Enum):
            return item.value
        if isinstance(item, datetime):
            return _utc(item).isoformat().replace("+00:00", "Z")
        if isinstance(item, float):
            raise IamError("INVALID_REQUEST")
        return item

    try:
        return json.dumps(
            normalize(value),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except IamError:
        raise
    except (TypeError, ValueError, UnicodeError, OverflowError) as error:
        raise IamError("INVALID_REQUEST") from error


def _hmac(key: bytes | bytearray, value: bytes) -> bytes:
    return hmac.new(bytes(key), value, hashlib.sha256).digest()


__all__ = [
    "PostgresRevokeCurrentSessionHandler",
    "PostgresRevokeOwnedSessionHandler",
]
