"""Production composition over the fixed Trust0002 Appeal PostgreSQL ABI."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import hmac
import json
import re
import secrets
from types import MappingProxyType
from typing import Any, Callable, Mapping, Optional, Tuple
from uuid import UUID

from ...application.appeal_commands import (
    ClaimAppealCommand,
    DecideAppealCommand,
    OpenAppealCommand,
    ReleaseAppealAssignmentCommand,
    SaveAppealDraftCommand,
    SaveAppealReviewDraftCommand,
    SubmitAppealCommand,
)
from ...application.appeal_handlers import (
    AppealApplicationError,
    ClaimAppealHandler,
    DecideAppealHandler,
    OpenAppealHandler,
    ReleaseAppealAssignmentHandler,
    SaveAppealDraftHandler,
    SaveAppealReviewDraftHandler,
    SubmitAppealHandler,
    _CANONICAL_PATHS,
    _METHODS,
    _OPERATIONS,
    _command_body,
    _validate_actor,
    _validate_command,
)
from ...application.commands import TrustActorContext
from ...ports.appeal import AppealSealedText, AppealSealedTextUnavailableError
from .appeal_gateway import (
    AppealCompletedReceiptProbeRequest,
    AppealPostgresCommandContext,
    AppealPostgresCommitOutcomeUnknownError,
    AppealPostgresConfigurationError,
    AppealPostgresReceiptMaterial,
    AppealPostgresRejectedError,
    AppealPostgresReplayMaterial,
    AppealRestrictedTextStoreRequest,
    AppealReviewAssessmentPostgres,
    ClaimAppealPostgresRequest,
    DecideAppealPostgresRequest,
    OpenAppealPostgresRequest,
    PsycopgAppealCommandGateway,
    PsycopgAppealReadGateway,
    PsycopgAppealReceiptProbe,
    PsycopgAppealRestrictedTextStore,
    ReleaseAppealAssignmentPostgresRequest,
    SaveAppealDraftPostgresRequest,
    SaveAppealReviewDraftPostgresRequest,
    SubmitAppealPostgresRequest,
)


APPLICATION_TO_DATABASE_SEALED_PURPOSE = MappingProxyType(
    {
        "APPLICATION_STATEMENT": "APPEAL_STATEMENT",
        "REVIEW_NOTE": "APPEAL_REVIEW_NOTE",
    }
)

_KEY_ID = re.compile(r"[a-z0-9][a-z0-9-]{2,127}\Z")
_SEALED_REFERENCE = re.compile(r"sealed://trust/[a-z0-9][a-z0-9/_-]{4,255}\Z")
_IDEMPOTENCY_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~-]{15,127}\Z")
_CANONICALIZATION_VERSION = "appeal-command-json-v1"
_SEALED_RETENTION = timedelta(days=2_555)
_HKDF_SALT = b"desire:trust:appeal-sealed-text:hkdf-salt:v1"
_AEAD_INFO = b"desire:trust:appeal-sealed-text:aead-key:v1\x00"
_PLAINTEXT_HMAC_INFO = (
    b"desire:trust:appeal-sealed-text:plaintext-hmac-key:v1\x00"
)
_REFERENCE_INFO = b"desire:trust:appeal-sealed-text:reference-key:v1\x00"
_REFERENCE_DOMAIN = b"desire:trust:appeal-sealed-text:reference:v1\x00"
_COMMAND_TYPES = {
    "open": OpenAppealCommand,
    "save_draft": SaveAppealDraftCommand,
    "submit": SubmitAppealCommand,
    "claim": ClaimAppealCommand,
    "release_assignment": ReleaseAppealAssignmentCommand,
    "save_review": SaveAppealReviewDraftCommand,
    "decide": DecideAppealCommand,
}
_APPLICANT_OPERATIONS = frozenset({"open", "save_draft", "submit"})


@dataclass(repr=False)
class AppealPostgresReceiptKey:
    purpose: str
    key_id: str
    material: bytearray = field(repr=False)

    def __post_init__(self) -> None:
        if (
            self.purpose not in {"IDEMPOTENCY", "PAYLOAD_HASH"}
            or not isinstance(self.key_id, str)
            or _KEY_ID.fullmatch(self.key_id) is None
            or not isinstance(self.material, bytearray)
            or not 32 <= len(self.material) <= 64
            or not any(self.material)
        ):
            raise ValueError("Appeal receipt key is invalid")

    def __repr__(self) -> str:
        return (
            "AppealPostgresReceiptKey("
            f"purpose={self.purpose!r}, key_id={self.key_id!r}, "
            "material=<redacted>)"
        )


class AppealPostgresReceiptKeyring:
    """Active-first, purpose-separated HMAC-SHA256 receipt keys."""

    def __init__(
        self,
        *,
        idempotency_keys: Tuple[AppealPostgresReceiptKey, ...],
        payload_hash_keys: Tuple[AppealPostgresReceiptKey, ...],
    ) -> None:
        if (
            type(idempotency_keys) is not tuple
            or type(payload_hash_keys) is not tuple
            or not 1 <= len(idempotency_keys) <= 4
            or not 1 <= len(payload_hash_keys) <= 4
            or any(
                not isinstance(item, AppealPostgresReceiptKey)
                or item.purpose != purpose
                for values, purpose in (
                    (idempotency_keys, "IDEMPOTENCY"),
                    (payload_hash_keys, "PAYLOAD_HASH"),
                )
                for item in values
            )
        ):
            raise ValueError("Appeal receipt keyring is invalid")
        keys = (*idempotency_keys, *payload_hash_keys)
        registry = {item.key_id: item for item in keys}
        if (
            len(registry) != len(keys)
            or len({bytes(item.material) for item in keys}) != len(keys)
        ):
            raise ValueError("Appeal receipt key purposes are not isolated")
        self.idempotency_key_digest_key_ids = tuple(
            item.key_id for item in idempotency_keys
        )
        self.payload_hash_key_ids = tuple(item.key_id for item in payload_hash_keys)
        self._keys = registry
        self._closed = False

    def keyed_digest(self, key_id: str, value: bytes) -> str:
        return self.digest_bytes(key_id=key_id, value=value).hex()

    def digest_bytes(self, *, key_id: str, value: bytes) -> bytes:
        if self._closed or not isinstance(value, bytes) or not value:
            raise LookupError("Appeal receipt key is unavailable")
        key = self._keys.get(key_id)
        if key is None:
            raise LookupError("Appeal receipt key is unavailable")
        return hmac.new(bytes(key.material), value, hashlib.sha256).digest()

    def close(self) -> None:
        if not self._closed:
            for key in self._keys.values():
                key.material[:] = b"\x00" * len(key.material)
            self._closed = True

    def __repr__(self) -> str:
        return (
            "AppealPostgresReceiptKeyring("
            f"idempotency_retained={len(self.idempotency_key_digest_key_ids)}, "
            f"payload_retained={len(self.payload_hash_key_ids)}, "
            "material=<redacted>)"
        )


@dataclass(repr=False)
class AppealSealedTextKey:
    key_id: str
    material: bytearray = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.key_id, str)
            or _KEY_ID.fullmatch(self.key_id) is None
            or not isinstance(self.material, bytearray)
            or not 32 <= len(self.material) <= 64
            or not any(self.material)
        ):
            raise ValueError("Appeal sealed-text key is invalid")

    def __repr__(self) -> str:
        return f"AppealSealedTextKey(key_id={self.key_id!r}, material=<redacted>)"


class AppealSealedTextKeyring:
    """Active-first retained roots with purpose-separated derived keys."""

    def __init__(
        self,
        *,
        keys: Tuple[AppealSealedTextKey, ...],
        active_key_id: str,
        retained_key_ids: Tuple[str, ...],
    ) -> None:
        if (
            type(keys) is not tuple
            or not 1 <= len(keys) <= 4
            or any(not isinstance(item, AppealSealedTextKey) for item in keys)
            or type(retained_key_ids) is not tuple
            or not 1 <= len(retained_key_ids) <= 4
            or retained_key_ids[0] != active_key_id
            or len(set(retained_key_ids)) != len(retained_key_ids)
        ):
            raise ValueError("Appeal sealed-text keyring is invalid")
        registry = {item.key_id: item for item in keys}
        if (
            len(registry) != len(keys)
            or set(registry) != set(retained_key_ids)
            or len({bytes(item.material) for item in keys}) != len(keys)
        ):
            raise ValueError("Appeal sealed-text retained keys are invalid")
        self.active_key_id = active_key_id
        self.retained_key_ids = retained_key_ids
        self._keys = registry
        self._closed = False

    def reference(
        self,
        *,
        key_id: str,
        appeal_id: UUID,
        actor_user_id: UUID,
        purpose_code: str,
        raw_idempotency_key: str,
    ) -> str:
        purpose_path = {
            "APPEAL_STATEMENT": "appeal-statement",
            "APPEAL_REVIEW_NOTE": "appeal-review-note",
        }.get(purpose_code)
        if purpose_path is None:
            raise ValueError("Appeal sealed-text purpose is invalid")
        material = _REFERENCE_DOMAIN + "\x1f".join(
            (
                str(appeal_id),
                str(actor_user_id),
                purpose_code,
                raw_idempotency_key,
            )
        ).encode("utf-8")
        digest = hmac.new(
            self._derived(key_id, _REFERENCE_INFO), material, hashlib.sha256
        ).hexdigest()
        return f"sealed://trust/{purpose_path}/{digest}"

    def encrypt(
        self, *, key_id: str, nonce: bytes, plaintext: bytes, aad: bytes
    ) -> bytes:
        if not isinstance(nonce, bytes) or len(nonce) != 12:
            raise ValueError("Appeal sealed-text nonce is invalid")
        return _aesgcm(self._derived(key_id, _AEAD_INFO)).encrypt(
            nonce, plaintext, aad
        )

    def plaintext_hmac(self, *, key_id: str, plaintext: bytes) -> bytes:
        if not isinstance(plaintext, bytes) or not plaintext:
            raise ValueError("Appeal sealed-text plaintext is invalid")
        return hmac.new(
            self._derived(key_id, _PLAINTEXT_HMAC_INFO),
            plaintext,
            hashlib.sha256,
        ).digest()

    def _derived(self, key_id: str, info_prefix: bytes) -> bytes:
        if self._closed:
            raise LookupError("Appeal sealed-text key is unavailable")
        try:
            root = bytes(self._keys[key_id].material)
        except (KeyError, TypeError):
            raise LookupError("Appeal sealed-text key is unavailable") from None
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
            "AppealSealedTextKeyring("
            f"active_key_id={self.active_key_id!r}, "
            f"retained={len(self.retained_key_ids)}, material=<redacted>)"
        )


class PsycopgAppealSealedTextProvider:
    """Encrypt applicant/reviewer text before its fixed PostgreSQL store call."""

    def __init__(
        self,
        *,
        store: PsycopgAppealRestrictedTextStore,
        keyring: AppealSealedTextKeyring,
        nonce_source: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        if not isinstance(store, PsycopgAppealRestrictedTextStore):
            raise TypeError("Appeal restricted-text store is unavailable")
        if not isinstance(keyring, AppealSealedTextKeyring):
            raise TypeError("Appeal sealed-text keys are unavailable")
        if not callable(nonce_source):
            raise TypeError("Appeal sealed-text nonce source is unavailable")
        self._store = store
        self._keyring = keyring
        self._nonce_source = nonce_source
        self._closed = False

    def seal(
        self,
        *,
        actor_user_id: UUID,
        session_id: UUID,
        organization_id: Optional[UUID],
        appeal_id: UUID,
        purpose: str,
        raw_text: str,
        raw_idempotency_key: str,
        replay_material: AppealPostgresReplayMaterial,
        retain_until: datetime,
    ) -> AppealSealedText:
        try:
            if self._closed:
                raise AppealSealedTextUnavailableError()
            purpose_code = _database_sealed_purpose(purpose)
            if any(
                not isinstance(value, UUID) or value.int == 0
                for value in (actor_user_id, session_id, appeal_id)
            ):
                raise ValueError
            applicant = purpose_code == "APPEAL_STATEMENT"
            if applicant != (organization_id is not None):
                raise ValueError
            if organization_id is not None and (
                not isinstance(organization_id, UUID) or organization_id.int == 0
            ):
                raise ValueError
            if (
                not isinstance(raw_text, str)
                or not 1 <= len(raw_text) <= 4_000
                or not isinstance(raw_idempotency_key, str)
                or _IDEMPOTENCY_KEY.fullmatch(raw_idempotency_key) is None
                or not isinstance(replay_material, AppealPostgresReplayMaterial)
                or not _is_utc(retain_until)
            ):
                raise ValueError
            plaintext = raw_text.encode("utf-8", errors="strict")
            if not plaintext or len(plaintext) > 12_000:
                raise ValueError
            plaintext_hmacs = tuple(
                self._keyring.plaintext_hmac(key_id=key_id, plaintext=plaintext)
                for key_id in self._keyring.retained_key_ids
            )
            references = tuple(
                self._keyring.reference(
                    key_id=key_id,
                    appeal_id=appeal_id,
                    actor_user_id=actor_user_id,
                    purpose_code=purpose_code,
                    raw_idempotency_key=raw_idempotency_key,
                )
                for key_id in self._keyring.retained_key_ids
            )
            active_key_id = self._keyring.active_key_id
            aad = self.associated_data(
                reference=references[0],
                appeal_id=appeal_id,
                actor_user_id=actor_user_id,
                purpose_code=purpose_code,
                plaintext_hmac_sha256=plaintext_hmacs[0],
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
                AppealRestrictedTextStoreRequest(
                    actor_user_id=actor_user_id,
                    session_id=session_id,
                    organization_id=organization_id,
                    appeal_id=appeal_id,
                    purpose_code=purpose_code,
                    encryption_key_ids=self._keyring.retained_key_ids,
                    candidate_references=references,
                    plaintext_hmac_sha256s=plaintext_hmacs,
                    envelope_sha256=envelope_sha256,
                    encryption_key_id=active_key_id,
                    nonce=nonce,
                    ciphertext=ciphertext,
                    aad_sha256=aad_sha256,
                    replay_material=replay_material,
                    retention_class="APPEAL_RESTRICTED_TEXT",
                    retain_until=retain_until,
                    duty_grant_id=None,
                    duty_grant_version=None,
                )
            )
        except AppealSealedTextUnavailableError:
            raise
        except Exception:
            raise AppealSealedTextUnavailableError() from None

    def close(self) -> None:
        if not self._closed:
            self._store.close()
            self._keyring.close()
            self._closed = True

    @staticmethod
    def associated_data(
        *,
        reference: str,
        appeal_id: UUID,
        actor_user_id: UUID,
        purpose_code: str,
        plaintext_hmac_sha256: bytes,
        key_id: str,
    ) -> bytes:
        if (
            not isinstance(reference, str)
            or _SEALED_REFERENCE.fullmatch(reference) is None
            or not isinstance(appeal_id, UUID)
            or appeal_id.int == 0
            or not isinstance(actor_user_id, UUID)
            or actor_user_id.int == 0
            or purpose_code not in {"APPEAL_STATEMENT", "APPEAL_REVIEW_NOTE"}
            or not _digest(plaintext_hmac_sha256)
            or not isinstance(key_id, str)
            or _KEY_ID.fullmatch(key_id) is None
        ):
            raise ValueError("Appeal sealed-text AAD is invalid")
        return "\x1f".join(
            (
                "desire:trust:appeal-restricted-text-aad:v1",
                reference,
                str(appeal_id),
                str(actor_user_id),
                purpose_code,
                plaintext_hmac_sha256.hex(),
                key_id,
            )
        ).encode("utf-8")

    @staticmethod
    def envelope_digest(
        *, key_id: str, nonce: bytes, ciphertext: bytes, aad_sha256: bytes
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
            raise ValueError("Appeal sealed-text envelope is invalid")
        return hashlib.sha256(
            "\x1f".join(
                (
                    "desire:trust:appeal-restricted-text-envelope:v1",
                    key_id,
                    nonce.hex(),
                    ciphertext.hex(),
                    aad_sha256.hex(),
                )
            ).encode("utf-8")
        ).digest()


class _PostgresAppealCommandHandler:
    operation: str

    def __init__(
        self,
        *,
        gateway: PsycopgAppealCommandGateway,
        receipt_probe: PsycopgAppealReceiptProbe,
        receipt_keyring: AppealPostgresReceiptKeyring,
        id_source: Any,
        clock: Any,
        sealed_text: Optional[PsycopgAppealSealedTextProvider] = None,
    ) -> None:
        if not isinstance(gateway, PsycopgAppealCommandGateway):
            raise TypeError("Appeal PostgreSQL command gateway is unavailable")
        if not isinstance(receipt_probe, PsycopgAppealReceiptProbe):
            raise TypeError("Appeal PostgreSQL receipt probe is unavailable")
        if not isinstance(receipt_keyring, AppealPostgresReceiptKeyring):
            raise TypeError("Appeal PostgreSQL receipt keys are unavailable")
        if not callable(getattr(id_source, "new_id", None)) or not callable(
            getattr(clock, "now", None)
        ):
            raise TypeError("Appeal secure runtime sources are unavailable")
        if self.operation in {"save_draft", "save_review"} and not isinstance(
            sealed_text, PsycopgAppealSealedTextProvider
        ):
            raise TypeError("Appeal durable sealed-text provider is unavailable")
        self._gateway = gateway
        self._receipt_probe = receipt_probe
        self._receipt_keyring = receipt_keyring
        self._id_source = id_source
        self._clock = clock
        self._sealed_text = sealed_text

    def handle(self, *, actor: TrustActorContext, command: Any) -> Any:
        if not isinstance(actor, TrustActorContext) or not isinstance(
            command, _COMMAND_TYPES[self.operation]
        ):
            raise AppealApplicationError("INVALID_REQUEST")
        try:
            applicant = self.operation in _APPLICANT_OPERATIONS
            _validate_actor(actor, applicant=applicant)
            _validate_command(self.operation, command)
            context = _context(actor)
            replay_material = self._replay_material(actor, command)
            probe_request = self._probe_request(
                actor=actor,
                command=command,
                context=context,
                replay_material=replay_material,
            )
            prior = self._receipt_probe.read_completed(probe_request)
            if prior is not None:
                return prior
            receipt = AppealPostgresReceiptMaterial(
                receipt_id=self._new_id("appeal_command_receipt"),
                audit_event_id=self._new_id("appeal_audit_event"),
                outbox_event_id=self._new_id("appeal_outbox_event"),
                idempotency_key_digest_key_ids=(
                    replay_material.idempotency_key_digest_key_ids
                ),
                idempotency_key_digests=replay_material.idempotency_key_digests,
                payload_hash_key_ids=replay_material.payload_hash_key_ids,
                payload_hashes=replay_material.payload_hashes,
            )
            request = self._postgres_request(
                actor=actor,
                command=command,
                context=context,
                receipt=receipt,
                replay_material=replay_material,
            )
            try:
                return self._write(request)
            except AppealPostgresCommitOutcomeUnknownError:
                recovered = self._receipt_probe.read_completed(probe_request)
                if recovered is not None:
                    return recovered
                raise AppealApplicationError("COMMAND_OUTCOME_UNKNOWN") from None
        except AppealApplicationError:
            raise
        except AppealPostgresRejectedError as error:
            raise AppealApplicationError(error.code) from None
        except AppealPostgresCommitOutcomeUnknownError:
            raise AppealApplicationError("COMMAND_OUTCOME_UNKNOWN") from None
        except (AppealPostgresConfigurationError, AppealSealedTextUnavailableError):
            raise AppealApplicationError("SERVICE_UNAVAILABLE") from None
        except (TypeError, ValueError, UnicodeError):
            raise AppealApplicationError("INVALID_REQUEST") from None
        except Exception:
            raise AppealApplicationError("SERVICE_UNAVAILABLE") from None

    def _replay_material(
        self, actor: TrustActorContext, command: Any
    ) -> AppealPostgresReplayMaterial:
        raw_key = command.idempotency_key
        if not isinstance(raw_key, str) or _IDEMPOTENCY_KEY.fullmatch(raw_key) is None:
            raise AppealApplicationError("INVALID_REQUEST")
        operation = _OPERATIONS[self.operation]
        identity = (
            b"desire:appeal:idempotency:v1\0"
            + actor.actor_user_id.encode("ascii")
            + b"\0"
            + operation.encode("ascii")
            + b"\0"
            + raw_key.encode("utf-8")
        )
        document = {
            "body": _command_body(self.operation, command),
            "canonical_path": _CANONICAL_PATHS[self.operation],
            "command_schema_version": 1,
            "method": _METHODS[self.operation],
            "workspace_organization_id": actor.organization_id,
        }
        encoded = json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        payload = (
            b"desire:appeal:command-payload:v1\0"
            + operation.encode("ascii")
            + b"\0"
            + encoded
        )
        return AppealPostgresReplayMaterial(
            idempotency_key_digest_key_ids=(
                self._receipt_keyring.idempotency_key_digest_key_ids
            ),
            idempotency_key_digests=tuple(
                self._receipt_keyring.digest_bytes(key_id=key_id, value=identity)
                for key_id in self._receipt_keyring.idempotency_key_digest_key_ids
            ),
            payload_hash_key_ids=self._receipt_keyring.payload_hash_key_ids,
            payload_hashes=tuple(
                self._receipt_keyring.digest_bytes(key_id=key_id, value=payload)
                for key_id in self._receipt_keyring.payload_hash_key_ids
            ),
        )

    def _probe_request(
        self,
        *,
        actor: TrustActorContext,
        command: Any,
        context: AppealPostgresCommandContext,
        replay_material: AppealPostgresReplayMaterial,
    ) -> AppealCompletedReceiptProbeRequest:
        return AppealCompletedReceiptProbeRequest(
            context=context,
            material=replay_material,
            operation=_OPERATIONS[self.operation],
            organization_id=(
                _uuid(actor.organization_id)
                if self.operation in _APPLICANT_OPERATIONS
                else None
            ),
            target_appeal_id=(
                None if self.operation == "open" else _uuid(command.appeal_id)
            ),
            expected_appeal_version=(
                None
                if self.operation == "open"
                else command.expected_appeal_version
            ),
        )

    def _postgres_request(
        self,
        *,
        actor: TrustActorContext,
        command: Any,
        context: AppealPostgresCommandContext,
        receipt: AppealPostgresReceiptMaterial,
        replay_material: AppealPostgresReplayMaterial,
    ) -> Any:
        if self.operation == "open":
            return OpenAppealPostgresRequest(
                context=context,
                receipt=receipt,
                organization_id=_uuid(actor.organization_id),
                appeal_id=self._new_id("appeal"),
                source_outcome_version_id=_uuid(command.source_outcome_version_id),
            )
        if self.operation == "save_draft":
            sealed = self._seal(
                actor=actor,
                command=command,
                context=context,
                replay_material=replay_material,
                purpose="APPLICATION_STATEMENT",
                raw_text=command.applicant_statement,
            )
            return SaveAppealDraftPostgresRequest(
                context=context,
                receipt=receipt,
                organization_id=_uuid(actor.organization_id),
                appeal_id=_uuid(command.appeal_id),
                expected_appeal_version=command.expected_appeal_version,
                sealed_statement_reference=sealed.sealed_reference,
                sealed_statement_sha256=bytes.fromhex(sealed.sealed_sha256),
                grounds=tuple(sorted(value.value for value in command.grounds)),
                requested_outcome=command.requested_outcome.value,
                new_evidence_reference_ids=tuple(
                    sorted(
                        (_uuid(value) for value in command.new_evidence_reference_ids),
                        key=str,
                    )
                ),
            )
        if self.operation == "submit":
            return SubmitAppealPostgresRequest(
                context=context,
                receipt=receipt,
                organization_id=_uuid(actor.organization_id),
                appeal_id=_uuid(command.appeal_id),
                expected_appeal_version=command.expected_appeal_version,
                expected_draft_version=command.expected_draft_version,
            )
        if self.operation == "claim":
            return ClaimAppealPostgresRequest(
                context=context,
                receipt=receipt,
                assignment_id=self._new_id("appeal_review_assignment"),
                appeal_id=_uuid(command.appeal_id),
                expected_appeal_version=command.expected_appeal_version,
            )
        if self.operation == "release_assignment":
            return ReleaseAppealAssignmentPostgresRequest(
                context=context,
                receipt=receipt,
                appeal_id=_uuid(command.appeal_id),
                expected_appeal_version=command.expected_appeal_version,
                reason_code=command.reason_code.value,
            )
        if self.operation == "save_review":
            sealed = self._seal(
                actor=actor,
                command=command,
                context=context,
                replay_material=replay_material,
                purpose="REVIEW_NOTE",
                raw_text=command.reviewer_note,
            )
            assessments = tuple(
                sorted(
                    (
                        AppealReviewAssessmentPostgres(
                            ground=value.ground.value,
                            assessment_code=value.assessment_code.value,
                            finding_codes=tuple(sorted(value.finding_codes)),
                            accepted_evidence_reference_ids=tuple(
                                sorted(
                                    (
                                        _uuid(identifier)
                                        for identifier in value.accepted_evidence_reference_ids
                                    ),
                                    key=str,
                                )
                            ),
                        )
                        for value in command.assessments
                    ),
                    key=lambda value: value.ground,
                )
            )
            return SaveAppealReviewDraftPostgresRequest(
                context=context,
                receipt=receipt,
                appeal_id=_uuid(command.appeal_id),
                expected_appeal_version=command.expected_appeal_version,
                sealed_review_note_reference=sealed.sealed_reference,
                sealed_review_note_sha256=bytes.fromhex(sealed.sealed_sha256),
                assessments=assessments,
                reason_codes=tuple(sorted(command.reason_codes)),
                remedy_delta_codes=tuple(sorted(command.remedy_delta_codes)),
            )
        if self.operation == "decide":
            return DecideAppealPostgresRequest(
                context=context,
                receipt=receipt,
                decision_version_id=self._new_id("appeal_decision_version"),
                appeal_id=_uuid(command.appeal_id),
                expected_appeal_version=command.expected_appeal_version,
                expected_review_draft_version=(
                    command.expected_review_draft_version
                ),
                decision_code=command.decision_code.value,
            )
        raise AppealPostgresConfigurationError()

    def _seal(
        self,
        *,
        actor: TrustActorContext,
        command: Any,
        context: AppealPostgresCommandContext,
        replay_material: AppealPostgresReplayMaterial,
        purpose: str,
        raw_text: str,
    ) -> AppealSealedText:
        if self._sealed_text is None:
            raise AppealPostgresConfigurationError()
        return self._sealed_text.seal(
            actor_user_id=context.actor_user_id,
            session_id=context.session_id,
            organization_id=(
                _uuid(actor.organization_id)
                if purpose == "APPLICATION_STATEMENT"
                else None
            ),
            appeal_id=_uuid(command.appeal_id),
            purpose=purpose,
            raw_text=raw_text,
            raw_idempotency_key=command.idempotency_key,
            replay_material=replay_material,
            retain_until=self._now() + _SEALED_RETENTION,
        )

    def _write(self, request: Any) -> Any:
        method = {
            "open": self._gateway.open_appeal,
            "save_draft": self._gateway.save_appeal_draft,
            "submit": self._gateway.submit_appeal,
            "claim": self._gateway.claim_appeal,
            "release_assignment": self._gateway.release_appeal_assignment,
            "save_review": self._gateway.save_appeal_review_draft,
            "decide": self._gateway.decide_appeal,
        }[self.operation]
        return method(request)

    def _new_id(self, purpose: str) -> UUID:
        return _uuid(self._id_source.new_id(purpose))

    def _now(self) -> datetime:
        value = self._clock.now()
        if not _is_utc(value):
            raise AppealPostgresConfigurationError()
        return value.astimezone(timezone.utc)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(dependencies=<redacted>)"


class PostgresOpenAppealHandler(_PostgresAppealCommandHandler, OpenAppealHandler):
    operation = "open"


class PostgresSaveAppealDraftHandler(
    _PostgresAppealCommandHandler, SaveAppealDraftHandler
):
    operation = "save_draft"


class PostgresSubmitAppealHandler(
    _PostgresAppealCommandHandler, SubmitAppealHandler
):
    operation = "submit"


class PostgresClaimAppealHandler(_PostgresAppealCommandHandler, ClaimAppealHandler):
    operation = "claim"


class PostgresReleaseAppealAssignmentHandler(
    _PostgresAppealCommandHandler, ReleaseAppealAssignmentHandler
):
    operation = "release_assignment"


class PostgresSaveAppealReviewDraftHandler(
    _PostgresAppealCommandHandler, SaveAppealReviewDraftHandler
):
    operation = "save_review"


class PostgresDecideAppealHandler(_PostgresAppealCommandHandler, DecideAppealHandler):
    operation = "decide"


@dataclass(frozen=True)
class AppealPostgresCommandHandlers:
    open_appeal: PostgresOpenAppealHandler
    save_application_draft: PostgresSaveAppealDraftHandler
    submit_appeal: PostgresSubmitAppealHandler
    claim_appeal: PostgresClaimAppealHandler
    release_assignment: PostgresReleaseAppealAssignmentHandler
    save_review_draft: PostgresSaveAppealReviewDraftHandler
    decide_appeal: PostgresDecideAppealHandler


def build_appeal_postgres_command_handlers(
    *,
    gateway: PsycopgAppealCommandGateway,
    receipt_probe: PsycopgAppealReceiptProbe,
    receipt_keyring: AppealPostgresReceiptKeyring,
    id_source: Any,
    clock: Any,
    sealed_text: PsycopgAppealSealedTextProvider,
) -> AppealPostgresCommandHandlers:
    common = {
        "gateway": gateway,
        "receipt_probe": receipt_probe,
        "receipt_keyring": receipt_keyring,
        "id_source": id_source,
        "clock": clock,
    }
    return AppealPostgresCommandHandlers(
        open_appeal=PostgresOpenAppealHandler(**common),
        save_application_draft=PostgresSaveAppealDraftHandler(
            **common, sealed_text=sealed_text
        ),
        submit_appeal=PostgresSubmitAppealHandler(**common),
        claim_appeal=PostgresClaimAppealHandler(**common),
        release_assignment=PostgresReleaseAppealAssignmentHandler(**common),
        save_review_draft=PostgresSaveAppealReviewDraftHandler(
            **common, sealed_text=sealed_text
        ),
        decide_appeal=PostgresDecideAppealHandler(**common),
    )


class PsycopgAppealHttpProjectionAdapter:
    """Expose the seven strict typed projections to the Appeal presenter."""

    def __init__(self, *, read_gateway: PsycopgAppealReadGateway) -> None:
        if not isinstance(read_gateway, PsycopgAppealReadGateway):
            raise TypeError("Appeal PostgreSQL read gateway is unavailable")
        self._read_gateway = read_gateway

    def find_own_appeal_by_source(
        self, *, actor: TrustActorContext, source_outcome_version_id: str
    ) -> Any:
        _require_projection_actor(actor, applicant=True)
        return self._invoke(
            lambda: self._read_gateway.find_own_appeal_by_source(
                actor_user_id=_uuid(actor.actor_user_id),
                session_id=_uuid(actor.session_id),
                organization_id=_uuid(actor.organization_id),
                source_outcome_version_id=_uuid(source_outcome_version_id),
            )
        )

    def read_own_appeal(
        self, *, actor: TrustActorContext, appeal_id: str
    ) -> Any:
        _require_projection_actor(actor, applicant=True)
        return self._invoke(
            lambda: self._read_gateway.read_own_appeal(
                actor_user_id=_uuid(actor.actor_user_id),
                session_id=_uuid(actor.session_id),
                organization_id=_uuid(actor.organization_id),
                appeal_id=_uuid(appeal_id),
            )
        )

    def list_appeal_queue(self, *, actor: TrustActorContext, limit: int) -> Any:
        _require_projection_actor(actor, applicant=False)
        return self._invoke(
            lambda: self._read_gateway.list_appeal_queue(
                actor_user_id=_uuid(actor.actor_user_id),
                session_id=_uuid(actor.session_id),
                limit=limit,
            )
        )

    def list_my_active_appeal_assignments(
        self, *, actor: TrustActorContext, limit: int
    ) -> Any:
        _require_projection_actor(actor, applicant=False)
        return self._invoke(
            lambda: self._read_gateway.list_my_active_appeal_assignments(
                actor_user_id=_uuid(actor.actor_user_id),
                session_id=_uuid(actor.session_id),
                limit=limit,
            )
        )

    def read_assigned_appeal(
        self, *, actor: TrustActorContext, appeal_id: str
    ) -> Any:
        _require_projection_actor(actor, applicant=False)
        return self._invoke(
            lambda: self._read_gateway.read_assigned_appeal(
                actor_user_id=_uuid(actor.actor_user_id),
                session_id=_uuid(actor.session_id),
                appeal_id=_uuid(appeal_id),
            )
        )

    def list_my_completed_appeal_assignments(
        self, *, actor: TrustActorContext, limit: int
    ) -> Any:
        _require_projection_actor(actor, applicant=False)
        return self._invoke(
            lambda: self._read_gateway.list_my_completed_appeal_assignments(
                actor_user_id=_uuid(actor.actor_user_id),
                session_id=_uuid(actor.session_id),
                limit=limit,
            )
        )

    def read_my_completed_appeal(
        self, *, actor: TrustActorContext, appeal_id: str
    ) -> Any:
        _require_projection_actor(actor, applicant=False)
        return self._invoke(
            lambda: self._read_gateway.read_my_completed_appeal(
                actor_user_id=_uuid(actor.actor_user_id),
                session_id=_uuid(actor.session_id),
                appeal_id=_uuid(appeal_id),
            )
        )

    def close(self) -> None:
        self._read_gateway.close()

    @staticmethod
    def _invoke(call: Any) -> Any:
        try:
            return call()
        except AppealPostgresRejectedError as error:
            raise AppealApplicationError(error.code) from None
        except AppealPostgresConfigurationError:
            raise AppealApplicationError("SERVICE_UNAVAILABLE") from None
        except AppealApplicationError:
            raise
        except Exception:
            raise AppealApplicationError("SERVICE_UNAVAILABLE") from None


def _database_sealed_purpose(purpose: Any) -> str:
    if not isinstance(purpose, str):
        raise ValueError("Appeal sealed-text purpose is invalid")
    try:
        return APPLICATION_TO_DATABASE_SEALED_PURPOSE[purpose]
    except KeyError:
        raise ValueError("Appeal sealed-text purpose is invalid") from None


def _context(actor: TrustActorContext) -> AppealPostgresCommandContext:
    return AppealPostgresCommandContext(
        actor_user_id=_uuid(actor.actor_user_id),
        session_id=_uuid(actor.session_id),
        correlation_id=_uuid(actor.correlation_id),
        causation_id=_uuid(actor.causation_id),
        trace_id=_uuid(actor.trace_id),
    )


def _uuid(value: Any) -> UUID:
    if isinstance(value, UUID):
        result = value
    elif isinstance(value, str):
        try:
            result = UUID(value)
        except ValueError:
            raise ValueError("Appeal identifier is invalid") from None
        if str(result) != value:
            raise ValueError("Appeal identifier is not canonical")
    else:
        raise TypeError("Appeal identifier is unavailable")
    if result.int == 0:
        raise ValueError("Appeal identifier is invalid")
    return result


def _require_projection_actor(actor: Any, *, applicant: bool) -> None:
    if not isinstance(actor, TrustActorContext):
        raise AppealApplicationError("INVALID_REQUEST")
    try:
        _validate_actor(actor, applicant=applicant)
    except AppealApplicationError:
        raise
    except Exception:
        raise AppealApplicationError("INVALID_REQUEST") from None


def _is_utc(value: Any) -> bool:
    return (
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() == timezone.utc.utcoffset(value)
    )


def _digest(value: Any) -> bool:
    return isinstance(value, bytes) and len(value) == 32


def _aesgcm(key: bytes) -> Any:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except (ImportError, ModuleNotFoundError):
        raise AppealSealedTextUnavailableError() from None
    return AESGCM(key)


__all__ = [
    "APPLICATION_TO_DATABASE_SEALED_PURPOSE",
    "AppealPostgresCommandHandlers",
    "AppealPostgresReceiptKey",
    "AppealPostgresReceiptKeyring",
    "AppealSealedTextKey",
    "AppealSealedTextKeyring",
    "PostgresClaimAppealHandler",
    "PostgresDecideAppealHandler",
    "PostgresOpenAppealHandler",
    "PostgresReleaseAppealAssignmentHandler",
    "PostgresSaveAppealDraftHandler",
    "PostgresSaveAppealReviewDraftHandler",
    "PostgresSubmitAppealHandler",
    "PsycopgAppealHttpProjectionAdapter",
    "PsycopgAppealSealedTextProvider",
    "build_appeal_postgres_command_handlers",
]
