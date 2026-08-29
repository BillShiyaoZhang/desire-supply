from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from types import SimpleNamespace
from uuid import UUID

import pytest

from desire_platform.identity_access.adapters.postgres.current_session_logout import (
    CURRENT_SESSION_LOGOUT_FUNCTION_SIGNATURE,
    CurrentSessionLogoutPostgresCommitOutcomeUnknownError,
    CurrentSessionLogoutPostgresDatabaseRequest,
    CurrentSessionLogoutPostgresExecutionScope,
    CurrentSessionLogoutPostgresGeneratedIds,
    CurrentSessionLogoutPostgresReceiptMaterial,
    PsycopgCurrentSessionLogoutUnitOfWorkFactory,
)
from desire_platform.identity_access.domain.authority_lifecycle import (
    LifecycleActorContext,
    RevokeSessionCommand,
)
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.internal_pilot.current_session_logout import (
    PostgresRevokeCurrentSessionHandler,
)
from desire_platform.internal_pilot.policy_acceptance import IamReceiptPolicyKeys


ACTOR_ID = UUID("10000000-0000-4000-8000-000000000101")
SESSION_ID = UUID("10000000-0000-4000-8000-000000000102")
COMMAND_ID = UUID("10000000-0000-4000-8000-000000000103")
CORRELATION_ID = UUID("10000000-0000-4000-8000-000000000104")
TRACE_ID = UUID("10000000-0000-4000-8000-000000000105")
AUDIT_ID = UUID("10000000-0000-4000-8000-000000000106")
OUTBOX_ID = UUID("10000000-0000-4000-8000-000000000107")
FAMILY_ID = UUID("10000000-0000-4000-8000-000000000108")


def _request() -> CurrentSessionLogoutPostgresDatabaseRequest:
    return CurrentSessionLogoutPostgresDatabaseRequest(
        scope=CurrentSessionLogoutPostgresExecutionScope(
            actor_user_id=ACTOR_ID,
            current_session_id=SESSION_ID,
            target_session_id=SESSION_ID,
            command_id=COMMAND_ID,
            correlation_id=CORRELATION_ID,
            causation_id=COMMAND_ID,
            trace_id=TRACE_ID,
            original_actor_id=None,
        ),
        receipt=CurrentSessionLogoutPostgresReceiptMaterial(
            receipt_id=COMMAND_ID,
            idempotency_key_digest=hmac.new(b"i" * 32, b"key", hashlib.sha256).digest(),
            idempotency_key_digest_key_id="iam-receipt-idempotency-hmac-2026-01",
            payload_hash=hmac.new(b"p" * 32, b"payload", hashlib.sha256).digest(),
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

    def __init__(
        self,
        *,
        commit_error: BaseException | None = None,
        result_payload: dict[str, object] | None = None,
    ):
        self.info = SimpleNamespace(transaction_status=0)
        self.commit_error = commit_error
        self.result_payload = result_payload
        self.calls: list[tuple[str, object]] = []

    def execute(self, query, parameters=None):
        text = str(query)
        self.calls.append((text, parameters))
        if text == "COMMIT" and self.commit_error is not None:
            raise self.commit_error
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
        if "revoke_current_session_v1" in text:
            return _Cursor((self.result_payload or {
                "outcome": "REVOKED",
                "session_id": str(SESSION_ID),
                "session_family_id": str(FAMILY_ID),
                "session_status": "REVOKED",
                "session_version": 2,
                "replayed": False,
                "clear_current_session_cookie": True,
            },))
        if "RESET ALL" in text or "DISCARD TEMP" in text:
            return _Cursor(None)
        if "app.scope_kind" in text:
            return _Cursor(("iam_app", "iam_app", None))
        return _Cursor(None)


class _Connections:
    def __init__(self, connection):
        self.connection = connection
        self.released: list[object] = []
        self.discarded: list[object] = []

    def checkout(self):
        return self.connection

    def release(self, connection):
        self.released.append(connection)

    def discard(self, connection):
        self.discarded.append(connection)


def test_fixed_program_signature_and_exact_current_session_request_are_closed():
    assert CURRENT_SESSION_LOGOUT_FUNCTION_SIGNATURE == (
        "iam_api.revoke_current_session_v1(uuid,uuid,uuid,uuid,uuid,uuid,bytea,text,"
        "bytea,text,text,timestamp with time zone,uuid,uuid)"
    )
    request = _request()
    assert request.scope.target_session_id == request.scope.current_session_id
    with pytest.raises(ValueError, match="target must be the current Session"):
        CurrentSessionLogoutPostgresDatabaseRequest(
            scope=CurrentSessionLogoutPostgresExecutionScope(
                **{
                    **request.scope.__dict__,
                    "target_session_id": UUID("10000000-0000-4000-8000-000000000109"),
                }
            ),
            receipt=request.receipt,
            generated_ids=request.generated_ids,
        )


def test_adapter_calls_only_fixed_logout_program_and_returns_cookie_clear_proof():
    connection = _Connection()
    connections = _Connections(connection)
    result = PsycopgCurrentSessionLogoutUnitOfWorkFactory(
        connections=connections
    ).execute(_request())

    statements = "\n".join(query for query, _parameters in connection.calls)
    assert "iam_api.revoke_current_session_v1" in statements
    assert "revoke_all" not in statements.lower()
    assert "UPDATE iam." not in statements
    assert result.clear_current_session_cookie is True
    assert result.replayed is False
    assert connections.released == [connection]
    assert connections.discarded == []


def test_adapter_accepts_deadline_expiry_as_a_terminal_cookie_clear_proof():
    connection = _Connection(result_payload={
        "outcome": "EXPIRED",
        "session_id": str(SESSION_ID),
        "session_family_id": str(FAMILY_ID),
        "session_status": "EXPIRED",
        "session_version": 2,
        "replayed": False,
        "clear_current_session_cookie": True,
    })
    result = PsycopgCurrentSessionLogoutUnitOfWorkFactory(
        connections=_Connections(connection)
    ).execute(_request())
    assert result.session_status == "EXPIRED"
    assert result.clear_current_session_cookie is True


def test_commit_ack_loss_is_unknown_and_never_rolls_back_or_releases():
    connection = _Connection(commit_error=ConnectionError("ack lost"))
    connections = _Connections(connection)
    with pytest.raises(CurrentSessionLogoutPostgresCommitOutcomeUnknownError):
        PsycopgCurrentSessionLogoutUnitOfWorkFactory(
            connections=connections
        ).execute(_request())

    statements = [query for query, _parameters in connection.calls]
    commit_index = statements.index("COMMIT")
    assert "ROLLBACK" not in statements[commit_index + 1 :]
    assert connections.released == []
    assert connections.discarded == [connection]


class _Clock:
    @staticmethod
    def now():
        return datetime(2026, 8, 18, 12, 0, tzinfo=timezone.utc)


class _Ids:
    def __init__(self):
        self._values = iter((COMMAND_ID, AUDIT_ID, OUTBOX_ID))

    def new_id(self, purpose):
        assert purpose in {"command_receipt", "audit_event", "outbox_event"}
        return next(self._values)


class _Uow:
    def __init__(self, error: BaseException | None = None):
        self.request = None
        self.error = error

    def execute(self, request):
        self.request = request
        if self.error is not None:
            raise self.error
        return SimpleNamespace(
            session_id=SESSION_ID,
            session_family_id=FAMILY_ID,
            session_status="REVOKED",
            session_version=2,
            replayed=False,
            clear_current_session_cookie=True,
        )


def _actor() -> LifecycleActorContext:
    return LifecycleActorContext(
        actor_user_id=str(ACTOR_ID),
        current_session_id=str(SESSION_ID),
        original_actor_id=None,
        correlation_id=str(CORRELATION_ID),
        causation_id=str(TRACE_ID),
        trace_id=str(TRACE_ID),
    )


def test_handler_projects_raw_key_to_receipt_and_only_clears_after_db_proof():
    uow = _Uow()
    handler = PostgresRevokeCurrentSessionHandler(
        uow_factory=uow,
        keys=IamReceiptPolicyKeys(
            idempotency_key=b"i" * 32,
            payload_hash_key=b"p" * 32,
        ),
        clock=_Clock(),
        id_source=_Ids(),
    )
    result = handler.handle(
        actor=_actor(),
        command=RevokeSessionCommand(
            session_id=str(SESSION_ID),
            idempotency_key="logout-key-1234567890",
        ),
    )

    assert result.http_status == 204
    assert result.safe_response is None
    assert result.clear_current_session_cookie is True
    assert uow.request.scope.current_session_id == SESSION_ID
    assert uow.request.scope.target_session_id == SESSION_ID
    assert uow.request.scope.causation_id == uow.request.scope.command_id
    assert b"logout-key-1234567890" not in repr(uow.request).encode()


def test_handler_rejects_a_different_session_instead_of_expanding_to_revoke_all():
    handler = PostgresRevokeCurrentSessionHandler(
        uow_factory=_Uow(),
        keys=IamReceiptPolicyKeys(
            idempotency_key=b"i" * 32,
            payload_hash_key=b"p" * 32,
        ),
        clock=_Clock(),
        id_source=_Ids(),
    )
    with pytest.raises(IamError) as raised:
        handler.handle(
            actor=_actor(),
            command=RevokeSessionCommand(
                session_id="10000000-0000-4000-8000-000000000109",
                idempotency_key="logout-key-1234567890",
            ),
        )
    assert raised.value.code == "INVALID_REQUEST"


def test_handler_exposes_commit_unknown_without_retrying_or_clearing_cookie():
    uow = _Uow(CurrentSessionLogoutPostgresCommitOutcomeUnknownError())
    handler = PostgresRevokeCurrentSessionHandler(
        uow_factory=uow,
        keys=IamReceiptPolicyKeys(
            idempotency_key=b"i" * 32,
            payload_hash_key=b"p" * 32,
        ),
        clock=_Clock(),
        id_source=_Ids(),
    )
    with pytest.raises(IamError) as raised:
        handler.handle(
            actor=_actor(),
            command=RevokeSessionCommand(
                session_id=str(SESSION_ID),
                idempotency_key="logout-key-1234567890",
            ),
        )
    assert raised.value.code == "COMMAND_OUTCOME_UNKNOWN"
    assert uow.request is not None
