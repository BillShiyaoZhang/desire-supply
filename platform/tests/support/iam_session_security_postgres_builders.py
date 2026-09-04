"""Real-PostgreSQL fixtures for the IAM HTTP Session security adapter.

Everything in this module is test-only.  Raw browser carriers are deliberately
kept out of connection traces, and the connection source exposes only the
pool-disposition facts needed by the semantic PostgreSQL tests.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import threading
from typing import Any, Optional
import uuid

import psycopg

from desire_platform.identity_access.security.cryptography import (
    KeyUnavailableError,
    csrf_digest,
    derive_csrf_token,
    session_handle_digest_for_key,
)


ACTIVE_HANDLE_KEY_ID = "iam-session-handle-hmac-2026-02"
OLD_HANDLE_KEY_ID = "iam-session-handle-hmac-2026-01"
ACTIVE_CSRF_KEY_ID = "iam-session-csrf-hmac-2026-02"
OLD_CSRF_KEY_ID = "iam-session-csrf-hmac-2026-01"

RAW_ACTIVE_HANDLE = "raw_session_secret_SENTINEL_0123456789ABCDE"
RAW_REPLAYED_HANDLE = "old_session_secret_SENTINEL_0123456789ABCDE"
RAW_OTHER_HANDLE = "other_session_handle_0123456789ABCDEFGHIJKLM"
RAW_UNKNOWN_HANDLE = "unknown_session_handle_0123456789ABCDEFGHIJK"
RAW_WRONG_CSRF_TOKEN = "wrong_csrf_token_0123456789ABCDEFGHIJKLMNOPQ"


@dataclass(frozen=True)
class SessionSecurityPostgresFixture:
    user_id: uuid.UUID
    family_id: uuid.UUID
    replayed_session_id: uuid.UUID
    current_session_id: uuid.UUID
    other_family_id: uuid.UUID
    other_session_id: uuid.UUID
    trace_id: uuid.UUID
    raw_active_handle: str
    raw_replayed_handle: str
    active_csrf_token: str
    active_csrf_salt: bytes


class DeterministicSessionSecurityKeyring:
    """Purpose-separated retained keyring with observable, secret-safe calls."""

    session_handle_digest_key_id = ACTIVE_HANDLE_KEY_ID
    retained_session_handle_digest_key_ids = (
        ACTIVE_HANDLE_KEY_ID,
        OLD_HANDLE_KEY_ID,
    )
    csrf_key_id = ACTIVE_CSRF_KEY_ID
    retained_csrf_key_ids = (ACTIVE_CSRF_KEY_ID, OLD_CSRF_KEY_ID)

    def __init__(self) -> None:
        self._keys = {
            ACTIVE_HANDLE_KEY_ID: hashlib.sha256(
                b"test-only-session-handle-key-2026-02"
            ).digest(),
            OLD_HANDLE_KEY_ID: hashlib.sha256(
                b"test-only-session-handle-key-2026-01"
            ).digest(),
            ACTIVE_CSRF_KEY_ID: hashlib.sha256(
                b"test-only-session-csrf-key-2026-02"
            ).digest(),
            OLD_CSRF_KEY_ID: hashlib.sha256(
                b"test-only-session-csrf-key-2026-01"
            ).digest(),
        }
        self.calls: list[tuple[str, str]] = []

    def remove_key_material(self, key_id: str) -> None:
        self._keys.pop(key_id, None)

    def clear_calls(self) -> None:
        self.calls.clear()

    def keyed_digest_hex(self, *, key_id: str, canonical_bytes: bytes) -> str:
        try:
            key = self._keys[key_id]
        except KeyError as error:
            raise KeyUnavailableError("configured IAM Session key is unavailable") from error
        purpose = "other"
        try:
            value = json.loads(canonical_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError):
            value = None
        if isinstance(value, dict):
            if "raw_session_handle" in value:
                purpose = "session-handle"
            elif "csrf_token" in value:
                purpose = "csrf-digest"
            elif value.get("purpose") == "IAM_KEY_AVAILABILITY_PREFLIGHT":
                purpose = "preflight"
        self.calls.append((purpose, key_id))
        return hmac.new(key, canonical_bytes, hashlib.sha256).hexdigest()

    def session_digest(self, *, raw_handle: str, key_id: str) -> bytes:
        return bytes.fromhex(
            session_handle_digest_for_key(
                self,
                raw_session_handle=raw_handle,
                key_id=key_id,
            )
        )

    def csrf_token(
        self,
        *,
        raw_handle: str,
        csrf_salt: bytes,
        session_id: uuid.UUID,
        generation: int,
        key_id: str,
    ) -> str:
        return derive_csrf_token(
            self,
            raw_session_handle=raw_handle,
            csrf_salt=csrf_salt,
            session_id=str(session_id),
            generation=generation,
            key_id=key_id,
        )

    def persisted_csrf_digest(self, *, token: str, key_id: str) -> bytes:
        return bytes.fromhex(csrf_digest(self, csrf_token=token, key_id=key_id))


class DeterministicSessionSecurityIdSource:
    """Thread-safe UUID source; purpose names remain observable but non-secret."""

    _namespace = uuid.UUID("85dd54f2-c38b-4be3-9447-d11573ce73cd")

    def __init__(self, label: str = "session-security") -> None:
        self._label = label
        self._lock = threading.Lock()
        self._ordinal = 0
        self.calls: list[str] = []

    def new_id(self, purpose: str) -> str:
        if not isinstance(purpose, str) or not purpose:
            raise AssertionError("Session security requested an invalid ID purpose")
        with self._lock:
            ordinal = self._ordinal
            self._ordinal += 1
            self.calls.append(purpose)
        return str(uuid.uuid5(self._namespace, f"{self._label}:{purpose}:{ordinal}"))


class _TrackingSessionSecurityConnection:
    def __init__(self, raw: Any, source: "TrackingSessionSecurityConnectionSource"):
        self._raw = raw
        self._source = source
        self._replay_scope_installed = False

    def execute(self, query: Any, parameters: Any = None, *args: Any, **kwargs: Any):
        normalized = " ".join(str(query).strip().split())
        self._source.trace.append(normalized)
        if _contains_replay_operation(normalized, parameters):
            self._replay_scope_installed = True
            if (
                self._source.replay_barrier is not None
                and not getattr(self._source._replay_barrier_worker, "used", False)
            ):
                # Retry connections belong to the same original contender.
                self._source._replay_barrier_worker.used = True
                self._source.replay_barrier.wait()
        if normalized.upper() == "COMMIT" and self._should_lose_commit_ack():
            result = self._raw.execute(query, parameters, *args, **kwargs)
            self._raw.close()
            del result
            raise psycopg.OperationalError(
                "synthetic IAM Session replay COMMIT acknowledgement loss"
            )
        return self._raw.execute(query, parameters, *args, **kwargs)

    def commit(self) -> None:
        if self._should_lose_commit_ack():
            self._raw.commit()
            self._raw.close()
            raise psycopg.OperationalError(
                "synthetic IAM Session replay COMMIT acknowledgement loss"
            )
        self._raw.commit()

    def _should_lose_commit_ack(self) -> bool:
        if not self._replay_scope_installed:
            return False
        with self._source._fault_lock:
            if not self._source.lose_replay_commit_ack:
                return False
            self._source.lose_replay_commit_ack = False
            self._source.commit_ack_losses += 1
            return True

    def __getattr__(self, name: str) -> Any:
        return getattr(self._raw, name)


class TrackingSessionSecurityConnectionSource:
    """Role-bound real psycopg source with safe pool disposition evidence."""

    def __init__(
        self,
        conninfo: str,
        *,
        reuse_released: bool = False,
        lose_replay_commit_ack: bool = False,
        replay_barrier: Optional[threading.Barrier] = None,
    ) -> None:
        self.conninfo = conninfo
        self.reuse_released = reuse_released
        self.lose_replay_commit_ack = lose_replay_commit_ack
        self.replay_barrier = replay_barrier
        self._replay_barrier_worker = threading.local()
        self.trace: list[str] = []
        self.checked_out: list[Any] = []
        self.released: list[Any] = []
        self.discarded: list[Any] = []
        self.backend_pids: list[int] = []
        self.commit_ack_losses = 0
        self._fault_lock = threading.Lock()
        self._reusable_raw: Optional[Any] = None

    def checkout(self) -> Any:
        raw = self._reusable_raw
        if raw is None or raw.closed or not self.reuse_released:
            raw = psycopg.connect(self.conninfo, autocommit=True)
            if self.reuse_released:
                self._reusable_raw = raw
        self.backend_pids.append(raw.info.backend_pid)
        wrapped = _TrackingSessionSecurityConnection(raw, self)
        self.checked_out.append(wrapped)
        return wrapped

    def release(self, connection: Any) -> None:
        self.released.append(connection)
        if not self.reuse_released:
            connection.close()

    def discard(self, connection: Any) -> None:
        self.discarded.append(connection)
        connection.close()
        if self._reusable_raw is not None and self._reusable_raw.closed:
            self._reusable_raw = None

    def prime_reusable_connection(self) -> int:
        if not self.reuse_released:
            raise AssertionError("pool poisoning requires reuse_released=True")
        raw = self._reusable_raw
        if raw is None or raw.closed:
            raw = psycopg.connect(self.conninfo, autocommit=True)
            self._reusable_raw = raw
        raw.execute("SET TimeZone TO 'Pacific/Honolulu'")
        raw.execute("SET app.scope_kind TO 'POISONED_SCOPE'")
        raw.execute("SET app.operation TO 'POISONED_OPERATION'")
        raw.execute("SET app.session_handle_digest TO 'pool-poison-secret'")
        return raw.info.backend_pid

    def reusable_session_state(self) -> tuple[str, str, str, str, str]:
        raw = self._reusable_raw
        if raw is None or raw.closed:
            raise AssertionError("reusable connection is unavailable")
        values = raw.execute(
            "SELECT current_setting('TimeZone'),"
            "COALESCE(current_setting('app.scope_kind',true),''),"
            "COALESCE(current_setting('app.operation',true),''),"
            "COALESCE(current_setting('app.session_handle_digest',true),'')"
        ).fetchone()
        return (*values, raw.info.transaction_status.name)

    def close(self) -> None:
        if self._reusable_raw is not None and not self._reusable_raw.closed:
            self._reusable_raw.close()


def reset_session_security_database(connection: Any) -> None:
    if connection.execute(
        "SELECT pg_catalog.to_regclass('iam.session_security_events')"
    ).fetchone()[0] is not None:
        connection.execute("TRUNCATE TABLE iam.session_security_events CASCADE")
    connection.execute(
        "TRUNCATE TABLE audit.audit_events,infra.outbox_events,"
        "iam.sessions,iam.session_families,iam.users CASCADE"
    )


def seed_session_security_graph(
    connection: Any,
    keyring: DeterministicSessionSecurityKeyring,
    *,
    active_handle_key_id: str = ACTIVE_HANDLE_KEY_ID,
) -> SessionSecurityPostgresFixture:
    user_id = uuid.UUID("10000000-0000-4000-8000-000000000001")
    family_id = uuid.UUID("20000000-0000-4000-8000-000000000001")
    replayed_session_id = uuid.UUID("30000000-0000-4000-8000-000000000001")
    current_session_id = uuid.UUID("30000000-0000-4000-8000-000000000002")
    other_family_id = uuid.UUID("20000000-0000-4000-8000-000000000002")
    other_session_id = uuid.UUID("30000000-0000-4000-8000-000000000003")
    trace_id = uuid.UUID("40000000-0000-4000-8000-000000000001")
    active_csrf_salt = hashlib.sha256(b"active-session-csrf-salt").digest()
    replayed_csrf_salt = hashlib.sha256(b"replayed-session-csrf-salt").digest()
    other_csrf_salt = hashlib.sha256(b"other-session-csrf-salt").digest()

    active_csrf_token = keyring.csrf_token(
        raw_handle=RAW_ACTIVE_HANDLE,
        csrf_salt=active_csrf_salt,
        session_id=current_session_id,
        generation=2,
        key_id=ACTIVE_CSRF_KEY_ID,
    )
    replayed_csrf_token = keyring.csrf_token(
        raw_handle=RAW_REPLAYED_HANDLE,
        csrf_salt=replayed_csrf_salt,
        session_id=replayed_session_id,
        generation=1,
        key_id=OLD_CSRF_KEY_ID,
    )
    other_csrf_token = keyring.csrf_token(
        raw_handle=RAW_OTHER_HANDLE,
        csrf_salt=other_csrf_salt,
        session_id=other_session_id,
        generation=1,
        key_id=ACTIVE_CSRF_KEY_ID,
    )

    connection.execute(
        "INSERT INTO iam.users "
        "(id,status,display_handle,aggregate_version,created_at,updated_at) "
        "VALUES (%s,'ACTIVE','session_actor',1,"
        "transaction_timestamp()-interval '1 day',transaction_timestamp())",
        (user_id,),
    )
    connection.execute(
        "INSERT INTO iam.session_families "
        "(id,user_id,status,current_generation,revoked_at,"
        "revocation_reason_code,aggregate_version,created_at,updated_at) VALUES "
        "(%s,%s,'ACTIVE',2,NULL,NULL,1,"
        "transaction_timestamp()-interval '6 hours',transaction_timestamp()),"
        "(%s,%s,'ACTIVE',1,NULL,NULL,1,"
        "transaction_timestamp()-interval '6 hours',transaction_timestamp())",
        (family_id, user_id, other_family_id, user_id),
    )
    _insert_session(
        connection,
        session_id=replayed_session_id,
        user_id=user_id,
        family_id=family_id,
        generation=1,
        predecessor_session_id=None,
        handle_digest=keyring.session_digest(
            raw_handle=RAW_REPLAYED_HANDLE,
            key_id=OLD_HANDLE_KEY_ID,
        ),
        handle_key_id=OLD_HANDLE_KEY_ID,
        csrf_salt=replayed_csrf_salt,
        csrf_key_id=OLD_CSRF_KEY_ID,
        csrf_digest_value=keyring.persisted_csrf_digest(
            token=replayed_csrf_token,
            key_id=OLD_CSRF_KEY_ID,
        ),
        status="REVOKED",
        rotation_reason="LOGIN",
    )
    _insert_session(
        connection,
        session_id=current_session_id,
        user_id=user_id,
        family_id=family_id,
        generation=2,
        predecessor_session_id=replayed_session_id,
        handle_digest=keyring.session_digest(
            raw_handle=RAW_ACTIVE_HANDLE,
            key_id=active_handle_key_id,
        ),
        handle_key_id=active_handle_key_id,
        csrf_salt=active_csrf_salt,
        csrf_key_id=ACTIVE_CSRF_KEY_ID,
        csrf_digest_value=keyring.persisted_csrf_digest(
            token=active_csrf_token,
            key_id=ACTIVE_CSRF_KEY_ID,
        ),
        status="ACTIVE",
        rotation_reason="STEP_UP",
    )
    _insert_session(
        connection,
        session_id=other_session_id,
        user_id=user_id,
        family_id=other_family_id,
        generation=1,
        predecessor_session_id=None,
        handle_digest=keyring.session_digest(
            raw_handle=RAW_OTHER_HANDLE,
            key_id=ACTIVE_HANDLE_KEY_ID,
        ),
        handle_key_id=ACTIVE_HANDLE_KEY_ID,
        csrf_salt=other_csrf_salt,
        csrf_key_id=ACTIVE_CSRF_KEY_ID,
        csrf_digest_value=keyring.persisted_csrf_digest(
            token=other_csrf_token,
            key_id=ACTIVE_CSRF_KEY_ID,
        ),
        status="ACTIVE",
        rotation_reason="LOGIN",
    )
    keyring.clear_calls()
    return SessionSecurityPostgresFixture(
        user_id=user_id,
        family_id=family_id,
        replayed_session_id=replayed_session_id,
        current_session_id=current_session_id,
        other_family_id=other_family_id,
        other_session_id=other_session_id,
        trace_id=trace_id,
        raw_active_handle=RAW_ACTIVE_HANDLE,
        raw_replayed_handle=RAW_REPLAYED_HANDLE,
        active_csrf_token=active_csrf_token,
        active_csrf_salt=active_csrf_salt,
    )


def _insert_session(
    connection: Any,
    *,
    session_id: uuid.UUID,
    user_id: uuid.UUID,
    family_id: uuid.UUID,
    generation: int,
    predecessor_session_id: Optional[uuid.UUID],
    handle_digest: bytes,
    handle_key_id: str,
    csrf_salt: bytes,
    csrf_key_id: str,
    csrf_digest_value: bytes,
    status: str,
    rotation_reason: str,
) -> None:
    terminal = status != "ACTIVE"
    connection.execute(
        "INSERT INTO iam.sessions ("
        "id,user_id,family_id,generation,predecessor_session_id,handle_digest,"
        "handle_digest_key_id,csrf_salt,csrf_key_id,csrf_digest,"
        "verified_contact_point_id,verified_at,verified_for_invitation_id,"
        "auth_transaction_id,auth_time,acr_code,amr_codes,created_at,"
        "last_activity_at,idle_expires_at,absolute_expires_at,updated_at,"
        "device_label,status,rotation_reason,revoked_at,revocation_reason_code,"
        "aggregate_version) VALUES ("
        "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL,NULL,NULL,NULL,"
        "transaction_timestamp()-interval '4 hours',"
        "'urn:desire:acr:mfa',ARRAY['pwd','otp']::text[],"
        "transaction_timestamp()-interval '3 hours',"
        "transaction_timestamp()-interval '2 hours',"
        "transaction_timestamp()+interval '2 hours',"
        "transaction_timestamp()+interval '21 hours',transaction_timestamp(),"
        "'Browser',%s,%s,"
        "CASE WHEN %s THEN transaction_timestamp() ELSE NULL END,"
        "CASE WHEN %s THEN 'TEST_PREDECESSOR_ROTATED' ELSE NULL END,1)",
        (
            session_id,
            user_id,
            family_id,
            generation,
            predecessor_session_id,
            handle_digest,
            handle_key_id,
            csrf_salt,
            csrf_key_id,
            csrf_digest_value,
            status,
            rotation_reason,
            terminal,
            terminal,
        ),
    )


def _contains_replay_operation(query: str, parameters: Any) -> bool:
    if "REVOKE_REPLAYED_FAMILY" in query:
        return True
    if parameters is None:
        return False
    if isinstance(parameters, dict):
        values = parameters.values()
    elif isinstance(parameters, (tuple, list)):
        values = parameters
    else:
        values = (parameters,)
    return any(value == "REVOKE_REPLAYED_FAMILY" for value in values)


__all__ = [
    "ACTIVE_CSRF_KEY_ID",
    "ACTIVE_HANDLE_KEY_ID",
    "DeterministicSessionSecurityIdSource",
    "DeterministicSessionSecurityKeyring",
    "OLD_CSRF_KEY_ID",
    "OLD_HANDLE_KEY_ID",
    "RAW_ACTIVE_HANDLE",
    "RAW_OTHER_HANDLE",
    "RAW_REPLAYED_HANDLE",
    "RAW_UNKNOWN_HANDLE",
    "RAW_WRONG_CSRF_TOKEN",
    "SessionSecurityPostgresFixture",
    "TrackingSessionSecurityConnectionSource",
    "reset_session_security_database",
    "seed_session_security_graph",
]
