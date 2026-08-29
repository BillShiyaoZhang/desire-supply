from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from typing import Any, Mapping, Optional, Sequence
import uuid

from desire_platform.identity_access.security.cryptography import (
    KeyUnavailableError,
    csrf_digest,
    derive_csrf_token,
    session_handle_digest_for_key,
)


NOW = datetime(2026, 8, 8, 12, 0, tzinfo=timezone.utc)
TRACE_ID = "11111111-1111-4111-8111-111111111111"
USER_ID = "22222222-2222-4222-8222-222222222222"
SESSION_ID = "33333333-3333-4333-8333-333333333333"
FAMILY_ID = "44444444-4444-4444-8444-444444444444"
ACTIVE_HANDLE = "A" * 43
OLD_KEY_HANDLE = "B" * 43
UNKNOWN_HANDLE = "C" * 43
ACTIVE_HANDLE_KEY = "session-handle-key-active"
OLD_HANDLE_KEY = "session-handle-key-old"
ACTIVE_CSRF_KEY = "session-csrf-key-active"
OLD_CSRF_KEY = "session-csrf-key-old"

COOKIE_COLUMNS = (
    "session_id",
    "user_id",
    "family_id",
    "generation",
    "session_status",
    "handle_digest_key_id",
    "handle_digest",
    "csrf_salt",
    "csrf_key_id",
    "csrf_digest",
    "auth_time",
    "acr_code",
    "amr_codes",
    "idle_expires_at",
    "absolute_expires_at",
    "verified_contact_point_id",
    "verified_at",
    "verified_for_invitation_id",
    "auth_transaction_id",
    "device_label",
    "session_aggregate_version",
    "family_status",
    "current_generation",
    "family_aggregate_version",
    "user_status",
    "resolved_at",
)


class SyntheticCommitOutcomeUnknown(RuntimeError):
    sqlstate = None


class FixedSessionSecurityKeyring:
    session_handle_digest_key_id = ACTIVE_HANDLE_KEY
    retained_session_handle_digest_key_ids = (OLD_HANDLE_KEY, ACTIVE_HANDLE_KEY)
    csrf_key_id = ACTIVE_CSRF_KEY
    retained_csrf_key_ids = (OLD_CSRF_KEY, ACTIVE_CSRF_KEY)

    def __init__(self) -> None:
        self.material = {
            ACTIVE_HANDLE_KEY: b"active-session-handle-material-v1",
            OLD_HANDLE_KEY: b"old-session-handle-material-0001",
            ACTIVE_CSRF_KEY: b"active-session-csrf-material-01",
            OLD_CSRF_KEY: b"old-session-csrf-material-00001",
        }
        self.calls: list[tuple[str, bytes]] = []

    def keyed_digest_hex(self, *, key_id: str, canonical_bytes: bytes) -> str:
        self.calls.append((key_id, bytes(canonical_bytes)))
        try:
            material = self.material[key_id]
        except KeyError:
            raise KeyUnavailableError("configured test key is unavailable") from None
        return hmac.new(material, canonical_bytes, hashlib.sha256).hexdigest()


class FixedSessionSecurityIdSource:
    def __init__(self) -> None:
        self.counter = 0

    def new_id(self, purpose: str) -> str:
        if not isinstance(purpose, str) or not purpose:
            raise AssertionError("security ID purpose is required")
        self.counter += 1
        return str(uuid.UUID(int=self.counter))


@dataclass(frozen=True)
class FakeDescription:
    name: str


class FakeCursor:
    def __init__(
        self,
        rows: Sequence[Sequence[Any]] = (),
        columns: Sequence[str] = (),
    ) -> None:
        self._rows = [tuple(row) for row in rows]
        self.description = tuple(FakeDescription(name) for name in columns)

    def fetchone(self) -> Optional[tuple[Any, ...]]:
        return None if not self._rows else self._rows[0]

    def fetchall(self) -> list[tuple[Any, ...]]:
        return list(self._rows)


class ScriptedSessionConnection:
    def __init__(self, source: "ScriptedSessionConnectionSource") -> None:
        self.source = source
        self.autocommit = True
        self.current_digest: Optional[str] = None
        self.current_key_id: Optional[str] = None
        self.closed = False
        self.in_transaction = False
        self.replay_scope = False

    def execute(
        self,
        statement: str,
        parameters: Sequence[Any] = (),
    ) -> FakeCursor:
        normalized = " ".join(statement.split())
        params = tuple(parameters)
        self.source.executions.append((normalized, params))
        if "RAW_SESSION_SENTINEL" in repr((normalized, params)):
            raise AssertionError("raw Session sentinel crossed SQL boundary")
        if normalized.startswith("BEGIN"):
            self.in_transaction = True
            return FakeCursor()
        if normalized == "COMMIT":
            self.in_transaction = False
            if self.replay_scope and self.source.lose_replay_commit_ack:
                self.source.lose_replay_commit_ack = False
                self.source.commit_ack_losses += 1
                self.closed = True
                raise SyntheticCommitOutcomeUnknown(
                    "synthetic replay COMMIT acknowledgement loss"
                )
            return FakeCursor()
        if normalized == "ROLLBACK":
            self.in_transaction = False
            return FakeCursor()
        if normalized in {
            "RESET ROLE",
            "RESET ALL",
            "SET TIME ZONE 'UTC'",
            "SET LOCAL TIME ZONE 'UTC'",
            "DISCARD TEMP",
        }:
            return FakeCursor()
        if "iam.install_session_authenticate_context_v2" in normalized:
            self.current_key_id = str(params[-2])
            self.current_digest = str(params[-1])
            return FakeCursor(
                ((
                    self.source.session_role,
                    self.source.current_role,
                    self.source.server_version,
                    self.source.transaction_time,
                    self.source.timezone_name,
                ),),
                (
                    "session_user",
                    "current_user",
                    "server_version",
                    "transaction_time",
                    "timezone_name",
                ),
            )
        if "iam.install_session_replay_context_v1" in normalized:
            self.replay_scope = True
            return FakeCursor(
                ((
                    self.source.session_role,
                    self.source.current_role,
                    self.source.server_version,
                    self.source.transaction_time,
                    self.source.timezone_name,
                ),),
                (
                    "session_user",
                    "current_user",
                    "server_version",
                    "transaction_time",
                    "timezone_name",
                ),
            )
        if (
            "revoke_replayed_session_family_v1" in normalized
            and "iam.session_security_readiness_v2" not in normalized
        ):
            self.source.replay_calls += 1
            outcome = "REVOKED" if self.source.replay_calls == 1 else "ALREADY_REVOKED"
            return FakeCursor(
                ((
                    outcome,
                    uuid.UUID("55555555-5555-4555-8555-555555555555"),
                    3,
                    3,
                ),),
                (
                    "outcome",
                    "revoked_session_id",
                    "family_version",
                    "session_version",
                ),
            )
        if "iam.resolve_cookie_session_v2" in normalized:
            raw_rows = self.source.rows_by_digest.get(self.current_digest or "", ())
            rows = [tuple(row[column] for column in COOKIE_COLUMNS) for row in raw_rows]
            return FakeCursor(rows, COOKIE_COLUMNS)
        if "iam.session_security_readiness_v2" in normalized:
            return FakeCursor(
                ((
                    self.source.session_role,
                    self.source.current_role,
                    self.source.server_version,
                    self.source.timezone_name,
                    True,
                ),),
                (
                    "session_user",
                    "current_user",
                    "server_version",
                    "timezone_name",
                    "capability_ready",
                ),
            )
        raise AssertionError(f"unregistered Session security SQL: {normalized}")


class ScriptedSessionConnectionSource:
    def __init__(self) -> None:
        self.rows_by_digest: dict[str, list[dict[str, Any]]] = {}
        self.transaction_time = NOW
        self.session_role = "iam_session_authenticator"
        self.current_role = "iam_session_authenticator"
        self.server_version = 180000
        self.timezone_name = "UTC"
        self.checkout_count = 0
        self.released: list[ScriptedSessionConnection] = []
        self.discarded: list[ScriptedSessionConnection] = []
        self.executions: list[tuple[str, tuple[Any, ...]]] = []
        self.lose_replay_commit_ack = False
        self.commit_ack_losses = 0
        self.replay_calls = 0

    def checkout(self) -> ScriptedSessionConnection:
        self.checkout_count += 1
        return ScriptedSessionConnection(self)

    def release(self, connection: ScriptedSessionConnection) -> None:
        self.released.append(connection)

    def discard(self, connection: ScriptedSessionConnection) -> None:
        self.discarded.append(connection)


def session_row(
    keyring: FixedSessionSecurityKeyring,
    *,
    raw_handle: str = ACTIVE_HANDLE,
    handle_key_id: str = ACTIVE_HANDLE_KEY,
    session_status: str = "ACTIVE",
    family_status: str = "ACTIVE",
    user_status: str = "ACTIVE",
    generation: int = 2,
    current_generation: int = 2,
    idle_expires_at: datetime = NOW + timedelta(minutes=30),
    absolute_expires_at: datetime = NOW + timedelta(hours=12),
    csrf_key_id: str = ACTIVE_CSRF_KEY,
    csrf_salt: bytes = b"s" * 32,
    csrf_digest_override: Optional[bytes] = None,
    session_id: str = SESSION_ID,
    user_id: str = USER_ID,
    family_id: str = FAMILY_ID,
) -> dict[str, Any]:
    handle_digest_hex = session_handle_digest_for_key(
        keyring,
        raw_session_handle=raw_handle,
        key_id=handle_key_id,
    )
    token = derive_csrf_token(
        keyring,
        raw_session_handle=raw_handle,
        csrf_salt=csrf_salt,
        session_id=session_id,
        generation=generation,
        key_id=csrf_key_id,
    )
    persisted_csrf_digest = bytes.fromhex(
        csrf_digest(keyring, csrf_token=token, key_id=csrf_key_id)
    )
    return {
        "session_id": uuid.UUID(session_id),
        "user_id": uuid.UUID(user_id),
        "family_id": uuid.UUID(family_id),
        "generation": generation,
        "session_status": session_status,
        "handle_digest_key_id": handle_key_id,
        "handle_digest": bytes.fromhex(handle_digest_hex),
        "csrf_salt": csrf_salt,
        "csrf_key_id": csrf_key_id,
        "csrf_digest": (
            persisted_csrf_digest
            if csrf_digest_override is None
            else csrf_digest_override
        ),
        "auth_time": NOW - timedelta(minutes=5),
        "acr_code": "urn:desire:acr:mfa",
        "amr_codes": ["pwd", "otp"],
        "idle_expires_at": idle_expires_at,
        "absolute_expires_at": absolute_expires_at,
        "verified_contact_point_id": None,
        "verified_at": None,
        "verified_for_invitation_id": None,
        "auth_transaction_id": None,
        "device_label": "Browser",
        "session_aggregate_version": 2,
        "family_status": family_status,
        "current_generation": current_generation,
        "family_aggregate_version": 2,
        "user_status": user_status,
        "resolved_at": NOW,
        "csrf_token": token,
        "handle_digest_hex": handle_digest_hex,
    }


def seed_row(
    source: ScriptedSessionConnectionSource,
    row: Mapping[str, Any],
) -> None:
    persisted = dict(row)
    persisted.pop("csrf_token", None)
    digest = str(persisted.pop("handle_digest_hex"))
    source.rows_by_digest.setdefault(digest, []).append(persisted)
