"""AEAD sealing and durable PostgreSQL storage for restricted Trust text."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import re
import secrets
from typing import Any, Callable, Optional, Tuple
from uuid import UUID

from ...ports.commands import TrustSealedNote, TrustSealedNoteUnavailableError
from .gateway import (
    TrustPostgresCommitOutcomeUnknownError,
    TrustPostgresConfigurationError,
    TrustPostgresGatewaySettings,
    TrustPostgresReplayMaterial,
    _configure,
    _database_error,
    _discard,
    _prepare,
    _reset,
)


_KEY_ID = re.compile(r"[a-z0-9][a-z0-9-]{2,127}\Z")
_REFERENCE = re.compile(r"sealed://trust/[a-z0-9][a-z0-9/_-]{4,255}\Z")
_HKDF_SALT = b"desire:trust:sealed-note:hkdf-salt:v1"
_AEAD_INFO = b"desire:trust:sealed-note:aead-key:v1\x00"
_PLAINTEXT_HMAC_INFO = b"desire:trust:sealed-note:plaintext-hmac-key:v1\x00"
_REFERENCE_INFO = b"desire:trust:sealed-note:reference-key:v1\x00"
_REFERENCE_DOMAIN = b"desire:trust:sealed-note:reference:v1\x00"


@dataclass(repr=False)
class TrustSealedTextKey:
    key_id: str
    material: bytearray = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.key_id, str) or _KEY_ID.fullmatch(self.key_id) is None:
            raise ValueError("Trust sealed-text key ID is invalid")
        if (
            not isinstance(self.material, bytearray)
            or not 32 <= len(self.material) <= 64
            or not any(self.material)
        ):
            raise ValueError("Trust sealed-text key material is unavailable")

    def __repr__(self) -> str:
        return f"TrustSealedTextKey(key_id={self.key_id!r}, material=<redacted>)"


class TrustSealedTextKeyring:
    """Active-first retained root keys with purpose-separated HKDF output."""

    def __init__(
        self,
        *,
        keys: Tuple[TrustSealedTextKey, ...],
        active_key_id: str,
        retained_key_ids: Tuple[str, ...],
    ) -> None:
        if (
            type(keys) is not tuple
            or not 1 <= len(keys) <= 4
            or any(not isinstance(item, TrustSealedTextKey) for item in keys)
            or type(retained_key_ids) is not tuple
            or not 1 <= len(retained_key_ids) <= 4
            or retained_key_ids[0] != active_key_id
            or len(set(retained_key_ids)) != len(retained_key_ids)
        ):
            raise ValueError("Trust sealed-text keyring is invalid")
        registry = {item.key_id: item for item in keys}
        if (
            len(registry) != len(keys)
            or set(registry) != set(retained_key_ids)
            or len({bytes(item.material) for item in keys}) != len(keys)
        ):
            raise ValueError("Trust sealed-text retained keys are invalid")
        self.active_key_id = active_key_id
        self.retained_key_ids = retained_key_ids
        self._keys = registry
        self._closed = False

    def reference(
        self,
        *,
        key_id: str,
        case_id: UUID,
        actor_user_id: UUID,
        purpose: str,
        raw_idempotency_key: str,
    ) -> str:
        material = _reference_material(
            case_id=case_id,
            actor_user_id=actor_user_id,
            purpose=purpose,
            raw_idempotency_key=raw_idempotency_key,
        )
        digest = hmac.new(
            self._derived(key_id, _REFERENCE_INFO),
            material,
            hashlib.sha256,
        ).hexdigest()
        return f"sealed://trust/triage-note/{digest}"

    def encrypt(
        self,
        *,
        key_id: str,
        nonce: bytes,
        plaintext: bytes,
        aad: bytes,
    ) -> bytes:
        if not isinstance(nonce, bytes) or len(nonce) != 12:
            raise ValueError("Trust sealed-text nonce is invalid")
        return _aesgcm(self._derived(key_id, _AEAD_INFO)).encrypt(
            nonce,
            plaintext,
            aad,
        )

    def plaintext_hmac(self, *, key_id: str, plaintext: bytes) -> bytes:
        if not isinstance(plaintext, bytes) or not plaintext:
            raise ValueError("Trust sealed-text plaintext is invalid")
        return hmac.new(
            self._derived(key_id, _PLAINTEXT_HMAC_INFO),
            plaintext,
            hashlib.sha256,
        ).digest()

    def decrypt(
        self,
        *,
        key_id: str,
        nonce: bytes,
        ciphertext: bytes,
        aad: bytes,
    ) -> str:
        if (
            key_id not in self.retained_key_ids
            or not isinstance(nonce, bytes)
            or len(nonce) != 12
            or not isinstance(ciphertext, bytes)
            or len(ciphertext) < 17
            or not isinstance(aad, bytes)
        ):
            raise ValueError("Trust sealed-text envelope is invalid")
        try:
            plaintext = _aesgcm(self._derived(key_id, _AEAD_INFO)).decrypt(
                nonce,
                ciphertext,
                aad,
            )
            return plaintext.decode("utf-8", errors="strict")
        except Exception:
            raise ValueError("Trust sealed-text authentication failed") from None

    def _derived(self, key_id: str, info_prefix: bytes) -> bytes:
        if self._closed:
            raise LookupError("Trust sealed-text key is unavailable")
        try:
            root = bytes(self._keys[key_id].material)
        except (KeyError, TypeError):
            raise LookupError("Trust sealed-text key is unavailable") from None
        prk = hmac.new(_HKDF_SALT, root, hashlib.sha256).digest()
        return hmac.new(
            prk,
            info_prefix + key_id.encode("ascii") + b"\x01",
            hashlib.sha256,
        ).digest()

    def close(self) -> None:
        if not self._closed:
            for key in self._keys.values():
                key.material[:] = b"\x00" * len(key.material)
            self._closed = True

    def __repr__(self) -> str:
        return (
            "TrustSealedTextKeyring("
            f"active_key_id={self.active_key_id!r}, "
            f"retained={len(self.retained_key_ids)}, material=<redacted>)"
        )


@dataclass(frozen=True)
class TrustRestrictedTextStoreRequest:
    actor_user_id: UUID
    session_id: UUID = field(repr=False)
    case_id: UUID
    purpose: str
    encryption_key_ids: Tuple[str, ...]
    candidate_references: Tuple[str, ...] = field(repr=False)
    plaintext_hmac_sha256s: Tuple[bytes, ...] = field(repr=False)
    envelope_sha256: bytes = field(repr=False)
    encryption_key_id: str
    nonce: bytes = field(repr=False)
    ciphertext: bytes = field(repr=False)
    aad_sha256: bytes = field(repr=False)
    replay_material: TrustPostgresReplayMaterial = field(repr=False)
    retention_class: str
    retain_until: datetime

    def __post_init__(self) -> None:
        for value in (self.actor_user_id, self.session_id, self.case_id):
            if not isinstance(value, UUID) or value.int == 0:
                raise ValueError("Trust restricted-text identifier is invalid")
        if (
            self.purpose != "TRIAGE_NOTE"
            or self.retention_class != "TRUST_CASE_NOTE"
            or type(self.encryption_key_ids) is not tuple
            or not 1 <= len(self.encryption_key_ids) <= 4
            or len(self.encryption_key_ids) != len(self.candidate_references)
            or len(set(self.encryption_key_ids)) != len(self.encryption_key_ids)
            or any(_KEY_ID.fullmatch(value) is None for value in self.encryption_key_ids)
            or type(self.candidate_references) is not tuple
            or len(set(self.candidate_references)) != len(self.candidate_references)
            or any(_REFERENCE.fullmatch(value) is None for value in self.candidate_references)
            or self.encryption_key_id != self.encryption_key_ids[0]
            or type(self.plaintext_hmac_sha256s) is not tuple
            or len(self.plaintext_hmac_sha256s) != len(self.encryption_key_ids)
            or any(not _digest(value) for value in self.plaintext_hmac_sha256s)
            or not _digest(self.envelope_sha256)
            or not isinstance(self.nonce, bytes)
            or len(self.nonce) != 12
            or not isinstance(self.ciphertext, bytes)
            or not 17 <= len(self.ciphertext) <= 16_384
            or not _digest(self.aad_sha256)
            or not isinstance(self.replay_material, TrustPostgresReplayMaterial)
            or not isinstance(self.retain_until, datetime)
            or self.retain_until.tzinfo is None
            or self.retain_until.utcoffset() is None
        ):
            raise ValueError("Trust restricted-text request is invalid")


class PsycopgTrustRestrictedTextStore:
    """One fixed, idempotent store program; no raw text crosses this boundary."""

    def __init__(
        self,
        *,
        officer_connections: Any,
        settings: TrustPostgresGatewaySettings = TrustPostgresGatewaySettings(),
    ) -> None:
        if not all(
            callable(getattr(officer_connections, name, None))
            for name in ("checkout", "release", "discard")
        ):
            raise TypeError("Trust officer connection source is unavailable")
        if not isinstance(settings, TrustPostgresGatewaySettings):
            raise TypeError("Trust PostgreSQL gateway settings are unavailable")
        self._connections = officer_connections
        self._settings = settings
        self._closed = False

    def store(self, request: TrustRestrictedTextStoreRequest) -> TrustSealedNote:
        if not isinstance(request, TrustRestrictedTextStoreRequest):
            raise TypeError("Trust restricted-text request is unavailable")
        if self._closed:
            raise TrustPostgresConfigurationError()
        try:
            return self._store_once(request)
        except TrustPostgresCommitOutcomeUnknownError:
            return self._store_once(request)

    def _store_once(self, request: TrustRestrictedTextStoreRequest) -> TrustSealedNote:
        connection = None
        state = "NEW"
        disposed = False
        try:
            connection = self._connections.checkout()
            _prepare(connection, "trust_officer")
            connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED")
            state = "BEGUN"
            _configure(
                connection,
                settings=self._settings,
                scope="TRUST_OFFICER",
                operation="SAVE_TRIAGE_DRAFT",
                actor_id=request.actor_user_id,
                session_id=request.session_id,
                organization_id=None,
            )
            material = request.replay_material
            state = "WRITING"
            row = connection.execute(
                "SELECT * FROM trust_api.store_restricted_text_blob_v1("
                + ",".join(["%s"] * 16)
                + ")",
                (
                    request.actor_user_id,
                    request.session_id,
                    request.case_id,
                    request.purpose,
                    list(request.encryption_key_ids),
                    list(request.candidate_references),
                    list(request.plaintext_hmac_sha256s),
                    request.envelope_sha256,
                    request.encryption_key_id,
                    request.nonce,
                    request.ciphertext,
                    request.aad_sha256,
                    list(material.idempotency_key_digest_key_ids),
                    list(material.idempotency_key_digests),
                    request.retention_class,
                    request.retain_until,
                ),
            ).fetchone()
            result = _sealed_result(row, request)
            state = "COMMIT_SENT"
            connection.execute("COMMIT")
            state = "COMMITTED"
            _reset(connection)
            self._connections.release(connection)
            disposed = True
            return result
        except BaseException as error:
            if connection is not None and state == "COMMIT_SENT":
                _discard(self._connections, connection)
                disposed = True
                raise TrustPostgresCommitOutcomeUnknownError() from None
            if connection is not None and state in {"BEGUN", "WRITING"}:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    pass
            if connection is not None and not disposed:
                _discard(self._connections, connection)
                disposed = True
            translated = _database_error(error)
            if translated is not None:
                raise translated from None
            if isinstance(error, (TrustPostgresConfigurationError, ValueError)):
                raise
            raise TrustPostgresConfigurationError() from None
        finally:
            if connection is not None and not disposed:
                _discard(self._connections, connection)

    def close(self) -> None:
        self._closed = True


class PsycopgTrustSealedNoteProvider:
    """Seal restricted notes using AES-256-GCM before durable storage."""

    def __init__(
        self,
        *,
        store: PsycopgTrustRestrictedTextStore,
        keyring: TrustSealedTextKeyring,
        nonce_source: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        if not isinstance(store, PsycopgTrustRestrictedTextStore):
            raise TypeError("Trust restricted-text store is unavailable")
        if not isinstance(keyring, TrustSealedTextKeyring):
            raise TypeError("Trust sealed-text keyring is unavailable")
        if not callable(nonce_source):
            raise TypeError("Trust sealed-text nonce source is unavailable")
        self._store = store
        self._keyring = keyring
        self._nonce_source = nonce_source
        self._closed = False

    def seal(
        self,
        *,
        actor_user_id: UUID,
        session_id: UUID,
        case_id: UUID,
        purpose: str,
        raw_note: str,
        raw_idempotency_key: str,
        replay_material: TrustPostgresReplayMaterial,
        retain_until: datetime,
    ) -> TrustSealedNote:
        try:
            if self._closed:
                raise TrustSealedNoteUnavailableError()
            if any(
                not isinstance(value, UUID) or value.int == 0
                for value in (actor_user_id, session_id, case_id)
            ):
                raise ValueError
            if (
                purpose != "TRIAGE_NOTE"
                or not isinstance(raw_note, str)
                or not raw_note.strip()
                or len(raw_note) > 4_000
                or not isinstance(raw_idempotency_key, str)
                or not 1 <= len(raw_idempotency_key) <= 256
                or not isinstance(replay_material, TrustPostgresReplayMaterial)
            ):
                raise ValueError
            plaintext = raw_note.encode("utf-8", errors="strict")
            if len(plaintext) > 12_000:
                raise ValueError
            plaintext_hmac_sha256s = tuple(
                self._keyring.plaintext_hmac(
                    key_id=key_id,
                    plaintext=plaintext,
                )
                for key_id in self._keyring.retained_key_ids
            )
            references = tuple(
                self._keyring.reference(
                    key_id=key_id,
                    case_id=case_id,
                    actor_user_id=actor_user_id,
                    purpose=purpose,
                    raw_idempotency_key=raw_idempotency_key,
                )
                for key_id in self._keyring.retained_key_ids
            )
            active_key_id = self._keyring.active_key_id
            aad = self.associated_data(
                reference=references[0],
                case_id=case_id,
                actor_user_id=actor_user_id,
                purpose=purpose,
                plaintext_hmac_sha256=plaintext_hmac_sha256s[0],
                key_id=active_key_id,
            )
            nonce = self._nonce_source(12)
            if not isinstance(nonce, bytes) or len(nonce) != 12:
                raise ValueError
            ciphertext = self._keyring.encrypt(
                key_id=active_key_id,
                nonce=nonce,
                plaintext=plaintext,
                aad=aad,
            )
            aad_sha256 = hashlib.sha256(aad).digest()
            envelope_sha256 = self.envelope_digest(
                key_id=active_key_id,
                nonce=nonce,
                ciphertext=ciphertext,
                aad_sha256=aad_sha256,
            )
            return self._store.store(
                TrustRestrictedTextStoreRequest(
                    actor_user_id=actor_user_id,
                    session_id=session_id,
                    case_id=case_id,
                    purpose=purpose,
                    encryption_key_ids=self._keyring.retained_key_ids,
                    candidate_references=references,
                    plaintext_hmac_sha256s=plaintext_hmac_sha256s,
                    envelope_sha256=envelope_sha256,
                    encryption_key_id=active_key_id,
                    nonce=nonce,
                    ciphertext=ciphertext,
                    aad_sha256=aad_sha256,
                    replay_material=replay_material,
                    retention_class="TRUST_CASE_NOTE",
                    retain_until=retain_until,
                )
            )
        except TrustSealedNoteUnavailableError:
            raise
        except Exception:
            raise TrustSealedNoteUnavailableError() from None

    def close(self) -> None:
        if not self._closed:
            self._store.close()
            self._keyring.close()
            self._closed = True

    @staticmethod
    def associated_data(
        *,
        reference: str,
        case_id: UUID,
        actor_user_id: UUID,
        purpose: str,
        plaintext_hmac_sha256: bytes,
        key_id: str,
    ) -> bytes:
        if (
            not isinstance(reference, str)
            or _REFERENCE.fullmatch(reference) is None
            or not isinstance(case_id, UUID)
            or case_id.int == 0
            or not isinstance(actor_user_id, UUID)
            or actor_user_id.int == 0
            or purpose != "TRIAGE_NOTE"
            or not _digest(plaintext_hmac_sha256)
            or not isinstance(key_id, str)
            or _KEY_ID.fullmatch(key_id) is None
        ):
            raise ValueError("Trust sealed-text AAD is invalid")
        return "\x1f".join(
            (
                "desire:trust:restricted-text-aad:v1",
                reference,
                str(case_id),
                str(actor_user_id),
                purpose,
                plaintext_hmac_sha256.hex(),
                key_id,
            )
        ).encode("utf-8")

    @staticmethod
    def envelope_digest(
        *,
        key_id: str,
        nonce: bytes,
        ciphertext: bytes,
        aad_sha256: bytes,
    ) -> bytes:
        if (
            not isinstance(key_id, str)
            or _KEY_ID.fullmatch(key_id) is None
            or not isinstance(nonce, bytes)
            or len(nonce) != 12
            or not isinstance(ciphertext, bytes)
            or len(ciphertext) < 17
            or not _digest(aad_sha256)
        ):
            raise ValueError("Trust sealed-text envelope is invalid")
        return hashlib.sha256(
            "\x1f".join(
                (
                    "desire:trust:restricted-text-envelope:v1",
                    key_id,
                    nonce.hex(),
                    ciphertext.hex(),
                    aad_sha256.hex(),
                )
            ).encode("utf-8")
        ).digest()


def _sealed_result(
    row: Any,
    request: TrustRestrictedTextStoreRequest,
) -> TrustSealedNote:
    if not isinstance(row, tuple) or len(row) != 5 or type(row[4]) is not bool:
        raise TrustPostgresConfigurationError()
    reference, digest, retention, sealed_at, replayed = row
    try:
        candidate_index = request.candidate_references.index(reference)
    except (TypeError, ValueError):
        raise TrustPostgresConfigurationError() from None
    if (
        not isinstance(digest, bytes)
        or len(digest) != 32
        or (
            not replayed
            and (
                candidate_index != 0
                or not hmac.compare_digest(digest, request.envelope_sha256)
            )
        )
        or retention != request.retention_class
        or not isinstance(sealed_at, datetime)
        or sealed_at.tzinfo is None
        or sealed_at.utcoffset() is None
        or sealed_at.astimezone(timezone.utc) > datetime.now(timezone.utc)
    ):
        raise TrustPostgresConfigurationError()
    return TrustSealedNote(
        sealed_note_reference=reference,
        sealed_note_sha256=digest.hex(),
        retention_class=retention,
        sealed_at=sealed_at.astimezone(timezone.utc),
    )


def _reference_material(
    *,
    case_id: UUID,
    actor_user_id: UUID,
    purpose: str,
    raw_idempotency_key: str,
) -> bytes:
    return _REFERENCE_DOMAIN + "\x1f".join(
        (
            str(case_id),
            str(actor_user_id),
            purpose,
            raw_idempotency_key,
        )
    ).encode("utf-8")


def _aesgcm(key: bytes) -> Any:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except (ImportError, ModuleNotFoundError):
        raise TrustSealedNoteUnavailableError() from None
    return AESGCM(key)


def _digest(value: Any) -> bool:
    return isinstance(value, bytes) and len(value) == 32


__all__ = [
    "PsycopgTrustRestrictedTextStore",
    "PsycopgTrustSealedNoteProvider",
    "TrustRestrictedTextStoreRequest",
    "TrustSealedTextKey",
    "TrustSealedTextKeyring",
]
