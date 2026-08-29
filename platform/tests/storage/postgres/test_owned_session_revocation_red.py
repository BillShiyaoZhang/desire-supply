from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from types import SimpleNamespace
from uuid import UUID

import pytest

from desire_platform.identity_access.adapters.postgres.current_session_logout import (
    OWNED_SESSION_REVOCATION_FUNCTION_SIGNATURE,
    CurrentSessionLogoutPostgresCommitOutcomeUnknownError,
    CurrentSessionLogoutPostgresConfigurationError,
    CurrentSessionLogoutPostgresGeneratedIds,
    CurrentSessionLogoutPostgresReceiptMaterial,
    OwnedSessionRevocationPostgresDatabaseRequest,
    OwnedSessionRevocationPostgresExecutionScope,
    PsycopgOwnedSessionRevocationUnitOfWorkFactory,
)
from desire_platform.identity_access.domain.authority_lifecycle import (
    LifecycleActorContext,
    RevokeSessionCommand,
)
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.internal_pilot.current_session_logout import (
    PostgresRevokeOwnedSessionHandler,
)
from desire_platform.internal_pilot.policy_acceptance import IamReceiptPolicyKeys


ACTOR_ID = UUID("10000000-0000-4000-8000-000000000101")
CURRENT_SESSION_ID = UUID("10000000-0000-4000-8000-000000000102")
TARGET_SESSION_ID = UUID("10000000-0000-4000-8000-000000000109")
COMMAND_ID = UUID("10000000-0000-4000-8000-000000000103")
CORRELATION_ID = UUID("10000000-0000-4000-8000-000000000104")
TRACE_ID = UUID("10000000-0000-4000-8000-000000000105")
AUDIT_ID = UUID("10000000-0000-4000-8000-000000000106")
OUTBOX_ID = UUID("10000000-0000-4000-8000-000000000107")
TARGET_FAMILY_ID = UUID("10000000-0000-4000-8000-000000000108")


def _request(
    *, target_session_id: UUID = TARGET_SESSION_ID
) -> OwnedSessionRevocationPostgresDatabaseRequest:
    return OwnedSessionRevocationPostgresDatabaseRequest(
        scope=OwnedSessionRevocationPostgresExecutionScope(
            actor_user_id=ACTOR_ID,
            current_session_id=CURRENT_SESSION_ID,
            target_session_id=target_session_id,
            command_id=COMMAND_ID,
            correlation_id=CORRELATION_ID,
            causation_id=COMMAND_ID,
            trace_id=TRACE_ID,
            original_actor_id=None,
        ),
        receipt=CurrentSessionLogoutPostgresReceiptMaterial(
            receipt_id=COMMAND_ID,
            idempotency_key_digest=hmac.new(
                b"i" * 32, b"key", hashlib.sha256
            ).digest(),
            idempotency_key_digest_key_id=(
                "iam-receipt-idempotency-hmac-2026-01"
            ),
            payload_hash=hmac.new(
                b"p" * 32, b"payload", hashlib.sha256
            ).digest(),
            payload_hash_key_id="iam-receipt-payload-hmac-2026-01",
            canonicalization_version="restricted-canonical-json-v1",
            retain_until=datetime.now(timezone.utc) + timedelta(days=30),
        ),
        generated_ids=CurrentSessionLogoutPostgresGeneratedIds(
            audit_event_id=AUDIT_ID,
            outbox_event_id=OUTBOX_ID,
        ),
    )


class _Cursor:
    def __init__(self, row):
        self._row = row

    def fetchone(self):
        return self._row


class _Connection:
    autocommit = True

    def __init__(self, *, result_payload=None):
        self.info = SimpleNamespace(transaction_status=0)
        self.result_payload = result_payload
        self.calls = []

    def execute(self, query, parameters=None):
        text = str(query)
        self.calls.append((text, parameters))
        if "server_version_num" in text:
            return _Cursor(("iam_app", "iam_app", 180000))
        if "set_config" in text and parameters is not None:
            return _Cursor((parameters[1],))
        if "current_setting" in text and parameters is not None:
            expected = next(
                value
                for query_text, value in reversed(self.calls)
                if "set_config" in query_text and value[0] == parameters[0]
            )
            return _Cursor((expected[1],))
        if "revoke_owned_session_v1" in text:
            return _Cursor(
                (
                    self.result_payload
                    or {
                        "outcome": "REVOKED",
                        "current_session_id": str(CURRENT_SESSION_ID),
                        "session_id": str(TARGET_SESSION_ID),
                        "session_family_id": str(TARGET_FAMILY_ID),
                        "session_status": "REVOKED",
                        "session_version": 2,
                        "replayed": False,
                        "clear_current_session_cookie": False,
                    },
                )
            )
        if "RESET ALL" in text or "DISCARD TEMP" in text:
            return _Cursor(None)
        if "app.scope_kind" in text:
            return _Cursor(("iam_app", "iam_app", None))
        return _Cursor(None)


class _Connections:
    def __init__(self, connection):
        self.connection = connection
        self.released = []
        self.discarded = []

    def checkout(self):
        return self.connection

    def release(self, connection):
        self.released.append(connection)

    def discard(self, connection):
        self.discarded.append(connection)


def test_owned_scope_accepts_a_distinct_target_and_fixed_program_is_only_write():
    request = _request()
    assert request.scope.target_session_id != request.scope.current_session_id
    assert OWNED_SESSION_REVOCATION_FUNCTION_SIGNATURE == (
        "iam_api.revoke_owned_session_v1(uuid,uuid,uuid,uuid,uuid,uuid,uuid,"
        "bytea,text,bytea,text,text,timestamp with time zone,uuid,uuid)"
    )
    connection = _Connection()
    connections = _Connections(connection)
    result = PsycopgOwnedSessionRevocationUnitOfWorkFactory(
        connections=connections
    ).execute(request)

    statements = "\n".join(query for query, _ in connection.calls)
    assert "iam_api.revoke_owned_session_v1" in statements
    assert "revoke_current_session_v1" not in statements
    assert "UPDATE iam." not in statements
    assert result.session_id == TARGET_SESSION_ID
    assert result.clear_current_session_cookie is False
    assert connections.released == [connection]
    assert connections.discarded == []


def test_database_result_proves_cookie_clear_iff_exact_target_is_current():
    current_payload = {
        "outcome": "REVOKED",
        "current_session_id": str(CURRENT_SESSION_ID),
        "session_id": str(CURRENT_SESSION_ID),
        "session_family_id": str(TARGET_FAMILY_ID),
        "session_status": "REVOKED",
        "session_version": 2,
        "replayed": False,
        "clear_current_session_cookie": True,
    }
    current = PsycopgOwnedSessionRevocationUnitOfWorkFactory(
        connections=_Connections(_Connection(result_payload=current_payload))
    ).execute(_request(target_session_id=CURRENT_SESSION_ID))
    assert current.clear_current_session_cookie is True

    invalid = {**current_payload, "session_id": str(TARGET_SESSION_ID)}
    with pytest.raises(CurrentSessionLogoutPostgresConfigurationError):
        PsycopgOwnedSessionRevocationUnitOfWorkFactory(
            connections=_Connections(_Connection(result_payload=invalid))
        ).execute(_request())


class _Clock:
    @staticmethod
    def now():
        return datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)


class _Ids:
    def __init__(self):
        self._values = iter((COMMAND_ID, AUDIT_ID, OUTBOX_ID))

    def new_id(self, purpose):
        assert purpose in {"command_receipt", "audit_event", "outbox_event"}
        return next(self._values)


class _Uow:
    def __init__(self, *, target=TARGET_SESSION_ID, error=None):
        self.target = target
        self.error = error
        self.request = None

    def execute(self, request):
        self.request = request
        if self.error is not None:
            raise self.error
        return SimpleNamespace(
            current_session_id=CURRENT_SESSION_ID,
            session_id=self.target,
            session_family_id=TARGET_FAMILY_ID,
            session_status="REVOKED",
            session_version=2,
            replayed=False,
            clear_current_session_cookie=self.target == CURRENT_SESSION_ID,
        )


def _actor():
    return LifecycleActorContext(
        actor_user_id=str(ACTOR_ID),
        current_session_id=str(CURRENT_SESSION_ID),
        original_actor_id=None,
        correlation_id=str(CORRELATION_ID),
        causation_id=str(TRACE_ID),
        trace_id=str(TRACE_ID),
    )


def _handler(uow):
    return PostgresRevokeOwnedSessionHandler(
        uow_factory=uow,
        keys=IamReceiptPolicyKeys(
            idempotency_key=b"i" * 32,
            payload_hash_key=b"p" * 32,
        ),
        clock=_Clock(),
        id_source=_Ids(),
    )


def test_handler_allows_other_owned_target_without_clearing_current_cookie():
    uow = _Uow()
    result = _handler(uow).handle(
        actor=_actor(),
        command=RevokeSessionCommand(
            session_id=str(TARGET_SESSION_ID),
            idempotency_key="revoke-owned-session-key-0001",
        ),
    )
    assert result.http_status == 204
    assert result.safe_response is None
    assert result.clear_current_session_cookie is False
    assert uow.request.scope.current_session_id == CURRENT_SESSION_ID
    assert uow.request.scope.target_session_id == TARGET_SESSION_ID


def test_handler_keeps_current_cookie_semantics_and_closed_error_translation():
    current = _handler(_Uow(target=CURRENT_SESSION_ID)).handle(
        actor=_actor(),
        command=RevokeSessionCommand(
            session_id=str(CURRENT_SESSION_ID),
            idempotency_key="revoke-current-session-key-0001",
        ),
    )
    assert current.clear_current_session_cookie is True

    for error, code in (
        (CurrentSessionLogoutPostgresCommitOutcomeUnknownError(), "COMMAND_OUTCOME_UNKNOWN"),
        (IamError("RESOURCE_NOT_FOUND"), "RESOURCE_NOT_FOUND"),
    ):
        with pytest.raises(IamError) as raised:
            _handler(_Uow(error=error)).handle(
                actor=_actor(),
                command=RevokeSessionCommand(
                    session_id=str(TARGET_SESSION_ID),
                    idempotency_key="revoke-owned-session-key-0001",
                ),
            )
        assert raised.value.code == code
