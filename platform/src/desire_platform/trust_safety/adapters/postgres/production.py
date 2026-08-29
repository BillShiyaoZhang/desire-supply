"""Closed production handlers over the Trust0001 PostgreSQL programs."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import re
from typing import Any, Mapping, Optional, Tuple
from uuid import UUID

from ...application.commands import (
    ClaimSafetyCaseCommand,
    ClaimSafetyHoldReleaseCommand,
    PlaceSafetyHoldCommand,
    PublishTrustOutcomeCommand,
    PublishTrustTriageCommand,
    ReleaseSafetyCaseAssignmentCommand,
    ReleaseSafetyHoldCommand,
    SaveTrustTriageDraftCommand,
    SubmitSafetyReportCommand,
    TrustActorContext,
    TrustCommandResult,
)
from ...application.handlers import (
    TrustApplicationError,
    _CANONICAL_PATHS,
    _OPERATION_NAMES,
    _command_body,
    _validate_actor_context,
    _validate_occ_fields,
)
from ...http import TrustHttpProjection
from ...ports.commands import (
    TrustDecisionEvidenceUnavailableError,
    TrustSealedNoteUnavailableError,
)
from .gateway import (
    ClaimCasePostgresRequest,
    ClaimHoldReleasePostgresRequest,
    PlaceHoldPostgresRequest,
    PsycopgTrustCommandGateway,
    PsycopgTrustReadGateway,
    PsycopgTrustReceiptProbe,
    PublishOutcomePostgresRequest,
    PublishTriagePostgresRequest,
    ReleaseCaseAssignmentPostgresRequest,
    ReleaseHoldPostgresRequest,
    SaveTriageDraftPostgresRequest,
    SubmitReportPostgresRequest,
    TrustCompletedReceiptProbeRequest,
    TrustPostgresCommandContext,
    TrustPostgresCommitOutcomeUnknownError,
    TrustPostgresConfigurationError,
    TrustPostgresReceiptMaterial,
    TrustPostgresRejectedError,
    TrustPostgresReplayMaterial,
)
from .outcome_evidence import (
    PsycopgTrustOutcomeEvidenceProvider,
    TrustOutcomeEvidenceRequest,
)
from .sealed_text import PsycopgTrustSealedNoteProvider


_KEY_ID = re.compile(r"[a-z0-9][a-z0-9-]{2,127}\Z")
_CANONICALIZATION_VERSION = "trust-command-json-v1"
_SEALED_RETENTION = timedelta(days=2_555)
_OWN_REPORT_CURSOR_VERSION = "trust-owned-report-page-v1"
_OWN_REPORT_CURSOR = re.compile(
    r"[A-Za-z0-9_-]{64,1024}\.[A-Za-z0-9_-]{43}\Z"
)
_OWN_REPORT_CURSOR_DOMAIN = b"desire:trust:owned-report-cursor:v1\x00"
_COMMAND_TYPES = {
    "submit_report": SubmitSafetyReportCommand,
    "claim_case": ClaimSafetyCaseCommand,
    "release_assignment": ReleaseSafetyCaseAssignmentCommand,
    "save_triage": SaveTrustTriageDraftCommand,
    "publish_triage": PublishTrustTriageCommand,
    "place_hold": PlaceSafetyHoldCommand,
    "claim_hold_release": ClaimSafetyHoldReleaseCommand,
    "release_hold": ReleaseSafetyHoldCommand,
    "publish_outcome": PublishTrustOutcomeCommand,
}


@dataclass(repr=False)
class TrustPostgresReceiptKey:
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
            raise ValueError("Trust receipt key is invalid")

    def __repr__(self) -> str:
        return (
            "TrustPostgresReceiptKey("
            f"purpose={self.purpose!r}, key_id={self.key_id!r}, "
            "material=<redacted>)"
        )


class TrustPostgresReceiptKeyring:
    """Active-first, purpose-separated HMAC-SHA256 receipt keys."""

    def __init__(
        self,
        *,
        idempotency_keys: Tuple[TrustPostgresReceiptKey, ...],
        payload_hash_keys: Tuple[TrustPostgresReceiptKey, ...],
    ) -> None:
        if (
            type(idempotency_keys) is not tuple
            or type(payload_hash_keys) is not tuple
            or not 1 <= len(idempotency_keys) <= 4
            or not 1 <= len(payload_hash_keys) <= 4
            or any(
                not isinstance(item, TrustPostgresReceiptKey)
                or item.purpose != purpose
                for values, purpose in (
                    (idempotency_keys, "IDEMPOTENCY"),
                    (payload_hash_keys, "PAYLOAD_HASH"),
                )
                for item in values
            )
        ):
            raise ValueError("Trust receipt keyring is invalid")
        keys = (*idempotency_keys, *payload_hash_keys)
        registry = {item.key_id: item for item in keys}
        if (
            len(registry) != len(keys)
            or len({bytes(item.material) for item in keys}) != len(keys)
        ):
            raise ValueError("Trust receipt key purposes are not isolated")
        self.idempotency_key_digest_key_ids = tuple(
            item.key_id for item in idempotency_keys
        )
        self.payload_hash_key_ids = tuple(
            item.key_id for item in payload_hash_keys
        )
        self._keys = registry
        self._closed = False

    def keyed_digest(self, key_id: str, value: bytes) -> str:
        return self.digest_bytes(key_id=key_id, value=value).hex()

    def digest_bytes(self, *, key_id: str, value: bytes) -> bytes:
        if self._closed or not isinstance(value, bytes) or not value:
            raise LookupError("Trust receipt key is unavailable")
        key = self._keys.get(key_id)
        if key is None:
            raise LookupError("Trust receipt key is unavailable")
        return hmac.new(bytes(key.material), value, hashlib.sha256).digest()

    def close(self) -> None:
        if not self._closed:
            for key in self._keys.values():
                key.material[:] = b"\x00" * len(key.material)
            self._closed = True

    def __repr__(self) -> str:
        return (
            "TrustPostgresReceiptKeyring("
            f"idempotency_retained={len(self.idempotency_key_digest_key_ids)}, "
            f"payload_retained={len(self.payload_hash_key_ids)}, "
            "material=<redacted>)"
        )


@dataclass(repr=False)
class TrustOwnedReportCursorKey:
    purpose: str
    key_id: str
    material: bytearray = field(repr=False)

    def __post_init__(self) -> None:
        if (
            self.purpose != "TRUST_REPORT_CURSOR"
            or not isinstance(self.key_id, str)
            or _KEY_ID.fullmatch(self.key_id) is None
            or not isinstance(self.material, bytearray)
            or not 32 <= len(self.material) <= 64
            or not any(self.material)
        ):
            raise ValueError("Trust report cursor key is invalid")

    def __repr__(self) -> str:
        return (
            "TrustOwnedReportCursorKey("
            f"purpose={self.purpose!r}, key_id={self.key_id!r}, "
            "material=<redacted>)"
        )


class TrustOwnedReportCursorKeyring:
    """Active-first, purpose-separated HMAC-SHA256 cursor keys."""

    def __init__(
        self,
        *,
        keys: Tuple[TrustOwnedReportCursorKey, ...],
        active_key_id: str,
        retained_key_ids: Tuple[str, ...],
    ) -> None:
        if (
            type(keys) is not tuple
            or not 1 <= len(keys) <= 4
            or any(
                not isinstance(item, TrustOwnedReportCursorKey)
                or item.purpose != "TRUST_REPORT_CURSOR"
                for item in keys
            )
            or not isinstance(active_key_id, str)
            or type(retained_key_ids) is not tuple
            or not retained_key_ids
            or retained_key_ids[0] != active_key_id
            or len(set(retained_key_ids)) != len(retained_key_ids)
        ):
            raise ValueError("Trust report cursor keyring is invalid")
        registry = {item.key_id: item for item in keys}
        if (
            tuple(registry) != retained_key_ids
            or set(registry) != set(retained_key_ids)
            or len({bytes(item.material) for item in keys}) != len(keys)
        ):
            raise ValueError("Trust report cursor keys are not isolated")
        self.active_key_id = active_key_id
        self.retained_key_ids = retained_key_ids
        self._keys = registry
        self._closed = False

    def sign(self, value: bytes) -> tuple[str, bytes]:
        if self._closed or not isinstance(value, bytes) or not value:
            raise LookupError("Trust report cursor key is unavailable")
        key = self._keys[self.active_key_id]
        return key.key_id, hmac.new(
            bytes(key.material),
            _OWN_REPORT_CURSOR_DOMAIN + value,
            hashlib.sha256,
        ).digest()

    def verify(self, *, key_id: str, value: bytes, signature: bytes) -> bool:
        if (
            self._closed
            or not isinstance(key_id, str)
            or not isinstance(value, bytes)
            or not value
            or not isinstance(signature, bytes)
            or len(signature) != 32
        ):
            return False
        key = self._keys.get(key_id)
        material = bytes(key.material) if key is not None else bytes(32)
        expected = hmac.new(
            material,
            _OWN_REPORT_CURSOR_DOMAIN + value,
            hashlib.sha256,
        ).digest()
        return hmac.compare_digest(expected, signature) and key is not None

    def close(self) -> None:
        if self._closed:
            return
        for key in self._keys.values():
            key.material[:] = b"\x00" * len(key.material)
        self._closed = True

    def __repr__(self) -> str:
        return (
            "TrustOwnedReportCursorKeyring("
            f"active_key_id={self.active_key_id!r}, "
            f"retained={len(self.retained_key_ids)}, material=<redacted>)"
        )


class _PostgresTrustCommandHandler:
    operation: str

    def __init__(
        self,
        *,
        gateway: PsycopgTrustCommandGateway,
        receipt_probe: PsycopgTrustReceiptProbe,
        receipt_keyring: TrustPostgresReceiptKeyring,
        id_source: Any,
        clock: Any,
        sealed_notes: Optional[PsycopgTrustSealedNoteProvider] = None,
        outcome_evidence: Optional[PsycopgTrustOutcomeEvidenceProvider] = None,
    ) -> None:
        if not isinstance(gateway, PsycopgTrustCommandGateway):
            raise TypeError("Trust PostgreSQL command gateway is unavailable")
        if not isinstance(receipt_probe, PsycopgTrustReceiptProbe):
            raise TypeError("Trust PostgreSQL receipt probe is unavailable")
        if not isinstance(receipt_keyring, TrustPostgresReceiptKeyring):
            raise TypeError("Trust PostgreSQL receipt keys are unavailable")
        if not callable(getattr(id_source, "new_id", None)) or not callable(
            getattr(clock, "now", None)
        ):
            raise TypeError("Trust secure runtime sources are unavailable")
        if self.operation == "save_triage" and not isinstance(
            sealed_notes, PsycopgTrustSealedNoteProvider
        ):
            raise TypeError("Trust durable sealed-note provider is unavailable")
        if self.operation == "publish_outcome" and not isinstance(
            outcome_evidence, PsycopgTrustOutcomeEvidenceProvider
        ):
            raise TypeError("Trust outcome evidence provider is unavailable")
        self._gateway = gateway
        self._receipt_probe = receipt_probe
        self._receipt_keyring = receipt_keyring
        self._id_source = id_source
        self._clock = clock
        self._sealed_notes = sealed_notes
        self._outcome_evidence = outcome_evidence

    def handle(
        self,
        *,
        actor: TrustActorContext,
        command: Any,
    ) -> TrustCommandResult:
        if not isinstance(actor, TrustActorContext) or not isinstance(
            command, _COMMAND_TYPES[self.operation]
        ):
            raise TrustApplicationError("INVALID_REQUEST")
        try:
            _validate_actor_context(
                actor, reporter=self.operation == "submit_report"
            )
            _validate_occ_fields(self.operation, command)
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
            receipt = TrustPostgresReceiptMaterial(
                receipt_id=self._new_id("trust_command_receipt"),
                audit_event_id=self._new_id("trust_audit_event"),
                outbox_event_id=self._new_id("trust_outbox_event"),
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
            except TrustPostgresCommitOutcomeUnknownError:
                recovered = self._receipt_probe.read_completed(probe_request)
                if recovered is not None:
                    return recovered
                raise TrustApplicationError("COMMAND_OUTCOME_UNKNOWN") from None
        except TrustApplicationError:
            raise
        except TrustPostgresRejectedError as error:
            raise TrustApplicationError(error.code) from None
        except TrustPostgresCommitOutcomeUnknownError:
            raise TrustApplicationError("COMMAND_OUTCOME_UNKNOWN") from None
        except (
            TrustPostgresConfigurationError,
            TrustSealedNoteUnavailableError,
            TrustDecisionEvidenceUnavailableError,
        ):
            raise TrustApplicationError("SERVICE_UNAVAILABLE") from None
        except (TypeError, ValueError, UnicodeError):
            raise TrustApplicationError("INVALID_REQUEST") from None
        except Exception:
            raise TrustApplicationError("SERVICE_UNAVAILABLE") from None

    def _replay_material(
        self,
        actor: TrustActorContext,
        command: Any,
    ) -> TrustPostgresReplayMaterial:
        raw_key = command.idempotency_key
        if (
            not isinstance(raw_key, str)
            or not raw_key
            or len(raw_key.encode("utf-8")) > 512
        ):
            raise TrustApplicationError("INVALID_REQUEST")
        operation = _OPERATION_NAMES[self.operation]
        identity = (
            b"desire:trust-safety:idempotency:v1\0"
            + operation.encode("ascii")
            + b"\0"
            + raw_key.encode("utf-8")
        )
        document = {
            "method": "PUT" if self.operation == "save_triage" else "POST",
            "canonical_path": _CANONICAL_PATHS[self.operation],
            "command_schema_version": 1,
            "workspace_organization_id": actor.organization_id,
            "body": _command_body(self.operation, command),
        }
        encoded = json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        payload = (
            b"desire:trust-safety:command-payload:v1\0"
            + operation.encode("ascii")
            + b"\0"
            + encoded
        )
        return TrustPostgresReplayMaterial(
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
        context: TrustPostgresCommandContext,
        replay_material: TrustPostgresReplayMaterial,
    ) -> TrustCompletedReceiptProbeRequest:
        if self.operation == "submit_report":
            return TrustCompletedReceiptProbeRequest(
                context=context,
                material=replay_material,
                operation="SUBMIT_REPORT",
                organization_id=_uuid(actor.organization_id),
                target_id=None,
                expected_version=None,
            )
        hold_operation = self.operation in {
            "claim_hold_release",
            "release_hold",
        }
        return TrustCompletedReceiptProbeRequest(
            context=context,
            material=replay_material,
            operation=_OPERATION_NAMES[self.operation],
            organization_id=None,
            target_id=_uuid(
                command.hold_id if hold_operation else command.case_id
            ),
            expected_version=(
                command.expected_hold_version
                if hold_operation
                else command.expected_case_version
            ),
        )

    def _postgres_request(
        self,
        *,
        actor: TrustActorContext,
        command: Any,
        context: TrustPostgresCommandContext,
        receipt: TrustPostgresReceiptMaterial,
        replay_material: TrustPostgresReplayMaterial,
    ) -> Any:
        if self.operation == "submit_report":
            return SubmitReportPostgresRequest(
                context=context,
                receipt=receipt,
                organization_id=_uuid(actor.organization_id),
                report_id=self._new_id("safety_report"),
                case_id=self._new_id("safety_case"),
                demand_id=_uuid(command.demand_id),
                demand_version_id=_uuid(command.demand_version_id),
                category=command.category.value,
                incident_started_at=command.incident_started_at,
                incident_ended_at=command.incident_ended_at,
                impact_codes=command.impact_codes,
                evidence_reference_ids=tuple(
                    _uuid(value) for value in command.evidence_reference_ids
                ),
                requested_protection_codes=command.requested_protection_codes,
            )
        if self.operation == "claim_case":
            return ClaimCasePostgresRequest(
                context=context,
                receipt=receipt,
                assignment_id=self._new_id("trust_case_assignment"),
                case_id=_uuid(command.case_id),
                expected_case_version=command.expected_case_version,
            )
        if self.operation == "release_assignment":
            return ReleaseCaseAssignmentPostgresRequest(
                context=context,
                receipt=receipt,
                case_id=_uuid(command.case_id),
                expected_case_version=command.expected_case_version,
                reason_code=command.reason_code.value,
            )
        if self.operation == "save_triage":
            if self._sealed_notes is None:
                raise TrustPostgresConfigurationError()
            sealed = self._sealed_notes.seal(
                actor_user_id=context.actor_user_id,
                session_id=context.session_id,
                case_id=_uuid(command.case_id),
                purpose="TRIAGE_NOTE",
                raw_note=command.restricted_note,
                raw_idempotency_key=command.idempotency_key,
                replay_material=replay_material,
                retain_until=self._now() + _SEALED_RETENTION,
            )
            return SaveTriageDraftPostgresRequest(
                context=context,
                receipt=receipt,
                case_id=_uuid(command.case_id),
                expected_case_version=command.expected_case_version,
                priority_code=command.priority_code,
                jurisdiction_code=command.jurisdiction_code,
                severity_code=command.severity_code,
                issue_codes=command.issue_codes,
                investigation_step_codes=command.investigation_step_codes,
                proposed_hold_actions=tuple(
                    value.value for value in command.proposed_hold_actions
                ),
                proposed_hold_ttl_minutes=command.proposed_hold_ttl_minutes,
                sealed_note_reference=sealed.sealed_note_reference,
                sealed_note_sha256=bytes.fromhex(sealed.sealed_note_sha256),
            )
        if self.operation == "publish_triage":
            return PublishTriagePostgresRequest(
                context=context,
                receipt=receipt,
                case_id=_uuid(command.case_id),
                expected_case_version=command.expected_case_version,
                expected_draft_version=command.expected_draft_version,
            )
        if self.operation == "place_hold":
            return PlaceHoldPostgresRequest(
                context=context,
                receipt=receipt,
                hold_id=self._new_id("safety_hold"),
                case_id=_uuid(command.case_id),
                expected_case_version=command.expected_case_version,
                action_codes=tuple(value.value for value in command.action_codes),
                reason_code=command.reason_code.value,
                hold_ttl_minutes=command.hold_ttl_minutes,
            )
        if self.operation == "claim_hold_release":
            return ClaimHoldReleasePostgresRequest(
                context=context,
                receipt=receipt,
                assignment_id=self._new_id("trust_hold_release_assignment"),
                hold_id=_uuid(command.hold_id),
                expected_hold_version=command.expected_hold_version,
            )
        if self.operation == "release_hold":
            return ReleaseHoldPostgresRequest(
                context=context,
                receipt=receipt,
                hold_id=_uuid(command.hold_id),
                expected_hold_version=command.expected_hold_version,
                release_reason_code=command.release_reason_code,
            )
        if self.operation == "publish_outcome":
            if self._outcome_evidence is None:
                raise TrustPostgresConfigurationError()
            evidence = self._outcome_evidence.prepare_for_postgres(
                TrustOutcomeEvidenceRequest(
                    actor_user_id=context.actor_user_id,
                    session_id=context.session_id,
                    case_id=_uuid(command.case_id),
                    expected_case_version=command.expected_case_version,
                    outcome_code=command.outcome_code.value,
                    reason_codes=command.reason_codes,
                    action_codes=tuple(
                        value.value for value in command.action_codes
                    ),
                )
            )
            return PublishOutcomePostgresRequest(
                context=context,
                receipt=receipt,
                outcome_version_id=self._new_id(
                    "trust_case_outcome_version"
                ),
                case_id=_uuid(command.case_id),
                expected_case_version=command.expected_case_version,
                outcome_code=command.outcome_code.value,
                reason_codes=command.reason_codes,
                action_codes=tuple(
                    value.value for value in command.action_codes
                ),
                evidence=evidence,
            )
        raise TrustPostgresConfigurationError()

    def _write(self, request: Any) -> TrustCommandResult:
        method = {
            "submit_report": self._gateway.submit_report,
            "claim_case": self._gateway.claim_case,
            "release_assignment": self._gateway.release_case_assignment,
            "save_triage": self._gateway.save_triage_draft,
            "publish_triage": self._gateway.publish_triage,
            "place_hold": self._gateway.place_hold,
            "claim_hold_release": self._gateway.claim_hold_release,
            "release_hold": self._gateway.release_hold,
            "publish_outcome": self._gateway.publish_outcome,
        }[self.operation]
        return method(request)

    def _new_id(self, purpose: str) -> UUID:
        value = self._id_source.new_id(purpose)
        return _uuid(value)

    def _now(self) -> datetime:
        value = self._clock.now()
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() != timedelta(0)
        ):
            raise TrustPostgresConfigurationError()
        return value.astimezone(timezone.utc)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(dependencies=<redacted>)"


class PostgresSubmitSafetyReportHandler(_PostgresTrustCommandHandler):
    operation = "submit_report"


class PostgresClaimSafetyCaseHandler(_PostgresTrustCommandHandler):
    operation = "claim_case"


class PostgresReleaseSafetyCaseAssignmentHandler(_PostgresTrustCommandHandler):
    operation = "release_assignment"


class PostgresSaveTrustTriageDraftHandler(_PostgresTrustCommandHandler):
    operation = "save_triage"


class PostgresPublishTrustTriageHandler(_PostgresTrustCommandHandler):
    operation = "publish_triage"


class PostgresPlaceSafetyHoldHandler(_PostgresTrustCommandHandler):
    operation = "place_hold"


class PostgresClaimSafetyHoldReleaseHandler(_PostgresTrustCommandHandler):
    operation = "claim_hold_release"


class PostgresReleaseSafetyHoldHandler(_PostgresTrustCommandHandler):
    operation = "release_hold"


class PostgresPublishTrustOutcomeHandler(_PostgresTrustCommandHandler):
    operation = "publish_outcome"


@dataclass(frozen=True)
class TrustPostgresCommandHandlers:
    submit_report: PostgresSubmitSafetyReportHandler
    claim_case: PostgresClaimSafetyCaseHandler
    release_assignment: PostgresReleaseSafetyCaseAssignmentHandler
    save_triage: PostgresSaveTrustTriageDraftHandler
    publish_triage: PostgresPublishTrustTriageHandler
    place_hold: PostgresPlaceSafetyHoldHandler
    claim_hold_release: PostgresClaimSafetyHoldReleaseHandler
    release_hold: PostgresReleaseSafetyHoldHandler
    publish_outcome: PostgresPublishTrustOutcomeHandler


def build_trust_postgres_command_handlers(
    *,
    gateway: PsycopgTrustCommandGateway,
    receipt_probe: PsycopgTrustReceiptProbe,
    receipt_keyring: TrustPostgresReceiptKeyring,
    id_source: Any,
    clock: Any,
    sealed_notes: PsycopgTrustSealedNoteProvider,
    outcome_evidence: PsycopgTrustOutcomeEvidenceProvider,
) -> TrustPostgresCommandHandlers:
    common = {
        "gateway": gateway,
        "receipt_probe": receipt_probe,
        "receipt_keyring": receipt_keyring,
        "id_source": id_source,
        "clock": clock,
    }
    return TrustPostgresCommandHandlers(
        submit_report=PostgresSubmitSafetyReportHandler(**common),
        claim_case=PostgresClaimSafetyCaseHandler(**common),
        release_assignment=PostgresReleaseSafetyCaseAssignmentHandler(**common),
        save_triage=PostgresSaveTrustTriageDraftHandler(
            **common, sealed_notes=sealed_notes
        ),
        publish_triage=PostgresPublishTrustTriageHandler(**common),
        place_hold=PostgresPlaceSafetyHoldHandler(**common),
        claim_hold_release=PostgresClaimSafetyHoldReleaseHandler(**common),
        release_hold=PostgresReleaseSafetyHoldHandler(**common),
        publish_outcome=PostgresPublishTrustOutcomeHandler(
            **common, outcome_evidence=outcome_evidence
        ),
    )


class PsycopgTrustHttpProjectionAdapter:
    """Convert the seven strict PG projections into the HTTP port type."""

    def __init__(
        self,
        *,
        read_gateway: PsycopgTrustReadGateway,
        cursor_keyring: TrustOwnedReportCursorKeyring,
    ) -> None:
        if (
            not isinstance(read_gateway, PsycopgTrustReadGateway)
            or not isinstance(cursor_keyring, TrustOwnedReportCursorKeyring)
        ):
            raise TypeError("Trust PostgreSQL read gateway is unavailable")
        self._read_gateway = read_gateway
        self._cursor_keyring = cursor_keyring

    def list_own_reports(
        self,
        *,
        actor: TrustActorContext,
        limit: int,
        cursor: str | None,
    ) -> TrustHttpProjection:
        _require_projection_actor(actor, reporter=True)
        if type(limit) is not int or not 1 <= limit <= 100:
            raise TrustApplicationError("INVALID_REQUEST")
        actor_user_id = _uuid(actor.actor_user_id)
        session_id = _uuid(actor.session_id)
        organization_id = _uuid(actor.organization_id)
        try:
            cursor_created_at, cursor_report_id = _decode_owned_report_cursor(
                cursor,
                keyring=self._cursor_keyring,
                actor_user_id=actor_user_id,
                organization_id=organization_id,
                limit=limit,
            )
            value = self._read_gateway.list_own_reports(
                actor_user_id=actor_user_id,
                session_id=session_id,
                organization_id=organization_id,
                limit=limit,
                cursor_created_at=cursor_created_at,
                cursor_report_id=cursor_report_id,
            )
            next_cursor = None
            if value.next_created_at is not None and value.next_report_id is not None:
                next_cursor = _encode_owned_report_cursor(
                    keyring=self._cursor_keyring,
                    actor_user_id=actor_user_id,
                    organization_id=organization_id,
                    limit=limit,
                    created_at=value.next_created_at,
                    report_id=value.next_report_id,
                )
            return TrustHttpProjection(
                kind="OWN_REPORT_LIST",
                data={**value.projection, "next_cursor": next_cursor},
                entity_tag=value.response_entity_tag,
            )
        except TrustPostgresRejectedError as error:
            raise TrustApplicationError(error.code) from None
        except TrustApplicationError:
            raise
        except (TypeError, ValueError, binascii.Error, UnicodeError):
            raise TrustApplicationError("INVALID_CURSOR") from None
        except TrustPostgresConfigurationError:
            raise TrustApplicationError("SERVICE_UNAVAILABLE") from None
        except Exception:
            raise TrustApplicationError("SERVICE_UNAVAILABLE") from None

    def read_own_report(
        self, *, actor: TrustActorContext, report_id: str
    ) -> TrustHttpProjection:
        _require_projection_actor(actor, reporter=True)
        return self._invoke(
            lambda: self._read_gateway.read_own_report(
                actor_user_id=_uuid(actor.actor_user_id),
                session_id=_uuid(actor.session_id),
                organization_id=_uuid(actor.organization_id),
                report_id=_uuid(report_id),
            )
        )

    def list_case_queue(
        self, *, actor: TrustActorContext, limit: int
    ) -> TrustHttpProjection:
        _require_projection_actor(actor, reporter=False)
        return self._invoke(
            lambda: self._read_gateway.list_case_queue(
                actor_user_id=_uuid(actor.actor_user_id),
                session_id=_uuid(actor.session_id),
                limit=limit,
            )
        )

    def list_hold_release_queue(
        self, *, actor: TrustActorContext, limit: int
    ) -> TrustHttpProjection:
        _require_projection_actor(actor, reporter=False)
        return self._invoke(
            lambda: self._read_gateway.list_hold_release_queue(
                actor_user_id=_uuid(actor.actor_user_id),
                session_id=_uuid(actor.session_id),
                limit=limit,
            )
        )

    def list_my_active_case_assignments(
        self, *, actor: TrustActorContext, limit: int
    ) -> TrustHttpProjection:
        _require_projection_actor(actor, reporter=False)
        return self._invoke(
            lambda: self._read_gateway.list_my_active_case_assignments(
                actor_user_id=_uuid(actor.actor_user_id),
                session_id=_uuid(actor.session_id),
                limit=limit,
            )
        )

    def list_my_completed_case_assignments(
        self, *, actor: TrustActorContext, limit: int
    ) -> TrustHttpProjection:
        _require_projection_actor(actor, reporter=False)
        return self._invoke(
            lambda: self._read_gateway.list_my_completed_case_assignments(
                actor_user_id=_uuid(actor.actor_user_id),
                session_id=_uuid(actor.session_id),
                limit=limit,
            )
        )

    def read_assigned_case(
        self, *, actor: TrustActorContext, case_id: str
    ) -> TrustHttpProjection:
        _require_projection_actor(actor, reporter=False)
        return self._invoke(
            lambda: self._read_gateway.read_assigned_case(
                actor_user_id=_uuid(actor.actor_user_id),
                session_id=_uuid(actor.session_id),
                case_id=_uuid(case_id),
            )
        )

    def read_assigned_hold_release(
        self, *, actor: TrustActorContext, hold_id: str
    ) -> TrustHttpProjection:
        _require_projection_actor(actor, reporter=False)
        return self._invoke(
            lambda: self._read_gateway.read_assigned_hold_release(
                actor_user_id=_uuid(actor.actor_user_id),
                session_id=_uuid(actor.session_id),
                hold_id=_uuid(hold_id),
            )
        )

    def close(self) -> None:
        self._read_gateway.close()
        self._cursor_keyring.close()

    @staticmethod
    def _invoke(call: Any) -> TrustHttpProjection:
        try:
            value = call()
            return TrustHttpProjection(
                kind=value.kind,
                data=value.projection,
                entity_tag=value.response_entity_tag,
            )
        except TrustPostgresRejectedError as error:
            raise TrustApplicationError(error.code) from None
        except TrustPostgresConfigurationError:
            raise TrustApplicationError("SERVICE_UNAVAILABLE") from None
        except TrustApplicationError:
            raise
        except Exception:
            raise TrustApplicationError("SERVICE_UNAVAILABLE") from None


def _context(actor: TrustActorContext) -> TrustPostgresCommandContext:
    return TrustPostgresCommandContext(
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
            raise ValueError("Trust identifier is invalid") from None
        if str(result) != value:
            raise ValueError("Trust identifier is not canonical")
    else:
        raise TypeError("Trust identifier is unavailable")
    if result.int == 0:
        raise ValueError("Trust identifier is invalid")
    return result


def _require_projection_actor(actor: Any, *, reporter: bool) -> None:
    if not isinstance(actor, TrustActorContext):
        raise TrustApplicationError("INVALID_REQUEST")
    try:
        _validate_actor_context(actor, reporter=reporter)
    except TrustApplicationError:
        raise
    except Exception:
        raise TrustApplicationError("INVALID_REQUEST") from None


def _encode_owned_report_cursor(
    *,
    keyring: TrustOwnedReportCursorKeyring,
    actor_user_id: UUID,
    organization_id: UUID,
    limit: int,
    created_at: datetime,
    report_id: UUID,
) -> str:
    if not isinstance(keyring, TrustOwnedReportCursorKeyring):
        raise ValueError("Trust cursor keyring is invalid")
    _require_uuids_for_cursor(actor_user_id, organization_id, report_id)
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Trust cursor limit is invalid")
    document = {
        "actor_user_id": str(actor_user_id),
        "created_at": _cursor_timestamp(created_at),
        "limit": limit,
        "organization_id": str(organization_id),
        "report_id": str(report_id),
        "key_id": keyring.active_key_id,
        "version": _OWN_REPORT_CURSOR_VERSION,
    }
    canonical = json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    key_id, signature = keyring.sign(canonical)
    if key_id != document["key_id"]:
        raise ValueError("Trust cursor active key changed")
    encoded = base64.urlsafe_b64encode(canonical).decode("ascii").rstrip("=")
    encoded_signature = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    token = f"{encoded}.{encoded_signature}"
    if _OWN_REPORT_CURSOR.fullmatch(token) is None:
        raise ValueError("Trust cursor encoding is invalid")
    return token


def _decode_owned_report_cursor(
    cursor: str | None,
    *,
    keyring: TrustOwnedReportCursorKeyring,
    actor_user_id: UUID,
    organization_id: UUID,
    limit: int,
) -> tuple[datetime | None, UUID | None]:
    if not isinstance(keyring, TrustOwnedReportCursorKeyring):
        raise ValueError("Trust cursor keyring is invalid")
    _require_uuids_for_cursor(actor_user_id, organization_id)
    if cursor is None:
        return None, None
    if (
        not isinstance(cursor, str)
        or _OWN_REPORT_CURSOR.fullmatch(cursor) is None
        or type(limit) is not int
        or not 1 <= limit <= 100
    ):
        raise ValueError("Trust cursor is invalid")
    encoded, encoded_signature = cursor.split(".", 1)
    padding = "=" * (-len(encoded) % 4)
    raw = base64.b64decode(
        (encoded + padding).encode("ascii"),
        altchars=b"-_",
        validate=True,
    )
    signature_padding = "=" * (-len(encoded_signature) % 4)
    signature = base64.b64decode(
        (encoded_signature + signature_padding).encode("ascii"),
        altchars=b"-_",
        validate=True,
    )
    if len(raw) > 768:
        raise ValueError("Trust cursor is invalid")
    pairs: list[tuple[str, Any]] = json.loads(
        raw.decode("ascii"), object_pairs_hook=lambda value: value
    )
    if not isinstance(pairs, list) or any(
        not isinstance(pair, tuple) or len(pair) != 2 for pair in pairs
    ):
        raise ValueError("Trust cursor is invalid")
    names = [name for name, _value in pairs]
    if len(set(names)) != len(names):
        raise ValueError("Trust cursor is invalid")
    document = dict(pairs)
    if set(document) != {
        "actor_user_id",
        "created_at",
        "key_id",
        "limit",
        "organization_id",
        "report_id",
        "version",
    }:
        raise ValueError("Trust cursor is invalid")
    canonical = json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    key_id = document["key_id"] if isinstance(document["key_id"], str) else ""
    signature_valid = keyring.verify(
        key_id=key_id,
        value=canonical,
        signature=signature,
    )
    if (
        document["version"] != _OWN_REPORT_CURSOR_VERSION
        or key_id not in keyring.retained_key_ids
        or document["actor_user_id"] != str(actor_user_id)
        or document["organization_id"] != str(organization_id)
        or document["limit"] != limit
        or not signature_valid
    ):
        raise ValueError("Trust cursor authority is invalid")
    report_id = _uuid(document["report_id"])
    created_at = datetime.fromisoformat(
        document["created_at"].replace("Z", "+00:00")
    )
    if (
        _cursor_timestamp(created_at) != document["created_at"]
        or base64.urlsafe_b64encode(canonical).decode("ascii").rstrip("=") != encoded
    ):
        raise ValueError("Trust cursor is invalid")
    return created_at, report_id


def _cursor_timestamp(value: datetime) -> str:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise ValueError("Trust cursor timestamp is invalid")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _require_uuids_for_cursor(*values: UUID) -> None:
    if any(not isinstance(value, UUID) or value.int == 0 for value in values):
        raise ValueError("Trust cursor identifier is invalid")


__all__ = [
    "PostgresClaimSafetyCaseHandler",
    "PostgresClaimSafetyHoldReleaseHandler",
    "PostgresPlaceSafetyHoldHandler",
    "PostgresPublishTrustOutcomeHandler",
    "PostgresPublishTrustTriageHandler",
    "PostgresReleaseSafetyCaseAssignmentHandler",
    "PostgresReleaseSafetyHoldHandler",
    "PostgresSaveTrustTriageDraftHandler",
    "PostgresSubmitSafetyReportHandler",
    "PsycopgTrustHttpProjectionAdapter",
    "TrustPostgresCommandHandlers",
    "TrustPostgresReceiptKey",
    "TrustPostgresReceiptKeyring",
    "TrustOwnedReportCursorKey",
    "TrustOwnedReportCursorKeyring",
    "build_trust_postgres_command_handlers",
]
