"""Default-deny Trust command orchestration.

Every external authority, Demand target/conflict, and sealed-note call happens
before a unit of work is opened.  Inside the unit of work, the idempotency
receipt claim is the first durable write; aggregate facts, audit, outbox, and
receipt completion then commit atomically.  Raw note text is used only to make
the request digest and to call the sealed-note port.  It is never copied into a
receipt, audit record, event, result, or exception.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import hmac
import json
import re
from typing import Any, Mapping, Optional, Tuple
from uuid import UUID

from ..domain import (
    SafetyCase,
    SafetyCaseAssignment,
    SafetyCaseAssignmentRelease,
    SafetyCaseStatus,
    SafetyHold,
    SafetyHoldReleaseAssignment,
    SafetyReport,
    TrustCaseOutcomeVersion,
    TrustDomainError,
    TrustTriageDraft,
    TrustTriageVersion,
)
from ..ports import (
    TrustAuthorityUnavailableError,
    TrustCommitOutcomeUnknownError,
    TrustDemandTarget,
    TrustDecisionEvidenceUnavailableError,
    TrustInitialOutcomeEvidence,
    TrustOfficerAuthority,
    TrustOfficerConflictCheck,
    TrustReporterAuthority,
    TrustSealedNote,
    TrustSealedNoteUnavailableError,
    TrustStorageUnavailableError,
    TrustTargetUnavailableError,
)
from .commands import (
    ClaimSafetyCaseCommand,
    ClaimSafetyHoldReleaseCommand,
    PlaceSafetyHoldCommand,
    PublishTrustTriageCommand,
    PublishTrustOutcomeCommand,
    ReleaseSafetyCaseAssignmentCommand,
    ReleaseSafetyHoldCommand,
    SaveTrustTriageDraftCommand,
    SubmitSafetyReportCommand,
    TrustActorContext,
    TrustCommandResult,
)


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SEALED_REFERENCE = re.compile(r"sealed://[a-z0-9][a-z0-9/_-]{4,255}\Z")

_OPERATION_NAMES = {
    "submit_report": "SUBMIT_REPORT",
    "claim_case": "CLAIM_CASE",
    "release_assignment": "RELEASE_CASE_ASSIGNMENT",
    "save_triage": "SAVE_TRIAGE_DRAFT",
    "publish_triage": "PUBLISH_TRIAGE",
    "place_hold": "PLACE_HOLD",
    "claim_hold_release": "CLAIM_HOLD_RELEASE",
    "release_hold": "RELEASE_HOLD",
    "publish_outcome": "PUBLISH_OUTCOME",
}

_CANONICAL_PATHS = {
    "submit_report": "/v1/app/trust/reports",
    "claim_case": "/v1/app/trust/queue/{case_id}/claim",
    "release_assignment": "/v1/app/trust/cases/{case_id}/assignment/release",
    "save_triage": "/v1/app/trust/cases/{case_id}/triage-draft",
    "publish_triage": "/v1/app/trust/cases/{case_id}/triage-publish",
    "place_hold": "/v1/app/trust/cases/{case_id}/holds",
    "claim_hold_release": "/v1/app/trust/hold-release-queue/{hold_id}/claim",
    "release_hold": "/v1/app/trust/holds/{hold_id}/release",
    "publish_outcome": "/v1/app/trust/cases/{case_id}/decisions",
}

_EVENT_TYPES = {
    "submit_report": "TrustReportSubmitted",
    "claim_case": "TrustCaseClaimed",
    "release_assignment": "TrustCaseAssignmentReleased",
    "save_triage": "TrustTriageDraftSaved",
    "publish_triage": "TrustTriagePublished",
    "place_hold": "SafetyHoldPlaced",
    "claim_hold_release": "TrustHoldReleaseClaimed",
    "release_hold": "SafetyHoldReleased",
    "publish_outcome": "TrustCaseOutcomePublished",
}

_AUDIT_ACTIONS = {
    "submit_report": "trust.report_submitted",
    "claim_case": "trust.case_claimed",
    "release_assignment": "trust.case_assignment_released",
    "save_triage": "trust.triage_draft_saved",
    "publish_triage": "trust.triage_published",
    "place_hold": "trust.hold_placed",
    "claim_hold_release": "trust.hold_release_claimed",
    "release_hold": "trust.hold_released",
    "publish_outcome": "trust.outcome_published",
}

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

_REPORTABLE_DEMAND_STATUSES = frozenset(
    {
        "SUBMITTED",
        "NEEDS_CHANGES",
        "VERIFIED",
        "FUNDING_PENDING",
        "FUNDED",
        "MATCHING",
        "MATCHED",
        "NO_MATCH",
    }
)


class TrustApplicationError(RuntimeError):
    """One closed application rejection safe for a later HTTP mapper."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class _Mutation:
    case: SafetyCase
    report: Optional[SafetyReport] = None
    assignment: Optional[SafetyCaseAssignment] = None
    assignment_release: Optional[SafetyCaseAssignmentRelease] = None
    hold_release_assignment: Optional[SafetyHoldReleaseAssignment] = None
    triage_draft: Optional[TrustTriageDraft] = None
    triage_version: Optional[TrustTriageVersion] = None
    hold: Optional[SafetyHold] = None
    outcome: Optional[TrustCaseOutcomeVersion] = None


@dataclass(frozen=True)
class _PreparedDependencies:
    target: Optional[TrustDemandTarget] = None
    conflict: Optional[TrustOfficerConflictCheck] = None
    sealed_note: Optional[TrustSealedNote] = None
    outcome_evidence: Optional[TrustInitialOutcomeEvidence] = None


class _TrustHandler:
    operation: str

    def __init__(
        self,
        *,
        authority: Any,
        target: Any,
        sealed_notes: Any,
        decision_evidence: Any,
        uow_factory: Any,
        clock: Any,
        id_source: Any,
        receipt_keyring: Any,
        assignment_ttl_minutes: int = 240,
        hold_policy_version: str = "trust-demand-hold-v1",
        outcome_policy_version: str = "trust-case-outcome-v1",
    ) -> None:
        if (
            type(assignment_ttl_minutes) is not int
            or not 15 <= assignment_ttl_minutes <= 1_440
            or not isinstance(hold_policy_version, str)
            or not hold_policy_version
            or not isinstance(outcome_policy_version, str)
            or not outcome_policy_version
        ):
            raise ValueError("TRUST_HANDLER_CONFIGURATION_INVALID")
        self._authority = authority
        self._target = target
        self._sealed_notes = sealed_notes
        self._decision_evidence = decision_evidence
        self._uow_factory = uow_factory
        self._clock = clock
        self._id_source = id_source
        self._receipt_keyring = receipt_keyring
        self._assignment_ttl_minutes = assignment_ttl_minutes
        self._hold_policy_version = hold_policy_version
        self._outcome_policy_version = outcome_policy_version

    def handle(
        self,
        *,
        actor: TrustActorContext,
        command: Any,
    ) -> TrustCommandResult:
        if not isinstance(actor, TrustActorContext) or not isinstance(
            command, _COMMAND_TYPES[self.operation]
        ):
            _fail("INVALID_REQUEST")
        _validate_actor_context(actor, reporter=self.operation == "submit_report")
        _validate_occ_fields(self.operation, command)
        now = self._now()
        granted = self._authorize(actor=actor)
        identities = self._receipt_identities(
            actor_user_id=actor.actor_user_id,
            idempotency_key=command.idempotency_key,
        )
        identity = identities[0]
        payload_hashes = self._payload_hashes(actor=actor, command=command)
        payload_hash = payload_hashes[self._payload_key_ids()[0]]
        snapshot = self._safe_snapshot()
        prior = _find_receipt(
            snapshot.get("command_receipts", {}), identities
        )
        if prior is not None:
            return _replay_or_conflict(prior, payload_hashes)

        prepared = self._prepare_external(
            actor=actor,
            command=command,
            granted=granted,
            identity=identity,
            snapshot=snapshot,
            now=now,
        )
        generated_ids = self._generated_ids()
        receipt_id = self._new_id("trust_command_receipt")
        audit_id = self._new_id("trust_audit_event")
        outbox_id = self._new_id("trust_outbox_event")

        try:
            with self._uow_factory.begin() as uow:
                self._lock_all(
                    uow=uow,
                    actor=actor,
                    command=command,
                    granted=granted,
                    identities=identities,
                    prepared=prepared,
                )
                raced = _find_receipt(
                    {
                        str(index): value
                        for index, value in enumerate(
                            uow.values("command_receipts")
                        )
                    },
                    identities,
                )
                if raced is not None:
                    return _replay_or_conflict(raced, payload_hashes)

                mutation = self._apply_domain(
                    uow=uow,
                    actor=actor,
                    command=command,
                    granted=granted,
                    prepared=prepared,
                    generated_ids=generated_ids,
                    now=now,
                )
                event_type = _EVENT_TYPES[self.operation]
                safe_response = _safe_response(
                    mutation=mutation,
                    event_type=event_type,
                    completed_at=now,
                )
                pending = {
                    "receipt_id": receipt_id,
                    **identity,
                    "canonicalization_version": "trust-command-json-v1",
                    "payload_hash_key_id": self._payload_key_ids()[0],
                    "payload_hash": payload_hash,
                    "target_case_id": mutation.case.case_id,
                    "status": "IN_PROGRESS",
                }

                # No business fact is written before this receipt claim.
                uow.put(
                    "command_receipts",
                    receipt_id,
                    pending,
                    checkpoint="receipt.pending",
                )
                self._write_business_facts(uow=uow, mutation=mutation)

                audit = _audit_record(
                    audit_id=audit_id,
                    action=_AUDIT_ACTIONS[self.operation],
                    actor=actor,
                    mutation=mutation,
                    occurred_at=now,
                )
                uow.put(
                    "audit_events",
                    audit_id,
                    audit,
                    checkpoint="audit." + self.operation,
                )
                event = _outbox_event(
                    event_id=outbox_id,
                    event_type=event_type,
                    actor=actor,
                    mutation=mutation,
                    occurred_at=now,
                )
                uow.put(
                    "outbox_events",
                    outbox_id,
                    event,
                    checkpoint="outbox." + self.operation,
                )
                completed = {
                    **pending,
                    "status": "COMPLETED",
                    "target_aggregate_version": mutation.case.aggregate_version,
                    "completed_at": _timestamp(now),
                    "safe_response": safe_response,
                }
                uow.put(
                    "command_receipts",
                    receipt_id,
                    completed,
                    checkpoint="receipt.completed",
                )
                uow.commit()
                return _result_from_safe_response(safe_response, replayed=False)
        except TrustCommitOutcomeUnknownError:
            recovered = self._recover_unknown(identities, payload_hashes)
            if recovered is not None:
                return recovered
            _fail("COMMAND_OUTCOME_UNKNOWN")
        except TrustApplicationError:
            raise
        except TrustDomainError as error:
            _fail(error.code)
        except TrustStorageUnavailableError:
            _fail("SERVICE_UNAVAILABLE")
        except Exception:
            # Dependency details and, in particular, sealed-note errors must
            # never be reflected into a client-visible message.
            _fail("SERVICE_UNAVAILABLE")
        raise AssertionError("unreachable")

    def _authorize(self, *, actor: TrustActorContext) -> Any:
        try:
            if self.operation == "submit_report":
                if not isinstance(actor.organization_id, str):
                    _fail("ACCESS_DENIED")
                result = self._authority.authorize_reporter(
                    actor=actor,
                    operation=_OPERATION_NAMES[self.operation],
                    organization_id=actor.organization_id,
                )
                return _validate_reporter_authority(result, actor)
            result = self._authority.authorize_officer(
                actor=actor,
                operation=_OPERATION_NAMES[self.operation],
            )
            return _validate_officer_authority(result, actor)
        except TrustApplicationError:
            raise
        except TrustAuthorityUnavailableError:
            _fail("SERVICE_UNAVAILABLE")
        except Exception:
            _fail("SERVICE_UNAVAILABLE")
        raise AssertionError("unreachable")

    def _prepare_external(
        self,
        *,
        actor: TrustActorContext,
        command: Any,
        granted: Any,
        identity: Mapping[str, Any],
        snapshot: Mapping[str, Mapping[str, Any]],
        now: datetime,
    ) -> _PreparedDependencies:
        if self.operation == "submit_report":
            return _PreparedDependencies(
                target=self._resolve_report_target(
                    actor=actor,
                    command=command,
                    granted=granted,
                    now=now,
                )
            )
        if self.operation in {"claim_hold_release", "release_hold"}:
            hold = _snapshot_hold(snapshot, command.hold_id)
            if hold.aggregate_version != command.expected_hold_version:
                _fail("PRECONDITION_FAILED")
            case = _snapshot_case(snapshot, hold.case_id)
        else:
            case = _snapshot_case(snapshot, command.case_id)
            if case.aggregate_version != command.expected_case_version:
                _fail("PRECONDITION_FAILED")
        if self.operation == "claim_case":
            conflict = self._check_conflict(
                actor=actor,
                case=case,
                granted=granted,
                now=now,
            )
            return _PreparedDependencies(conflict=conflict)
        if self.operation == "claim_hold_release":
            conflict = self._check_conflict(
                actor=actor,
                case=case,
                granted=granted,
                now=now,
            )
            return _PreparedDependencies(conflict=conflict)
        if self.operation == "save_triage":
            return _PreparedDependencies(
                sealed_note=self._seal_note(
                    actor=actor,
                    command=command,
                    identity=identity,
                    now=now,
                )
            )
        if self.operation == "publish_outcome":
            return _PreparedDependencies(
                outcome_evidence=self._prepare_outcome_evidence(
                    actor=actor,
                    command=command,
                    case=case,
                    granted=granted,
                    snapshot=snapshot,
                    now=now,
                )
            )
        return _PreparedDependencies()

    def _resolve_report_target(
        self,
        *,
        actor: TrustActorContext,
        command: SubmitSafetyReportCommand,
        granted: TrustReporterAuthority,
        now: datetime,
    ) -> TrustDemandTarget:
        try:
            target = self._target.resolve_report_target(
                reporter_authority=granted,
                demand_id=command.demand_id,
                demand_version_id=command.demand_version_id,
            )
        except TrustTargetUnavailableError:
            _fail("SERVICE_UNAVAILABLE")
        except Exception:
            _fail("SERVICE_UNAVAILABLE")
        if not isinstance(target, TrustDemandTarget):
            _fail("SERVICE_UNAVAILABLE")
        if (
            target.owner_user_id != actor.actor_user_id
            or target.organization_id != granted.organization_id
            or target.demand_id != command.demand_id
            or target.demand_version_id != command.demand_version_id
        ):
            _fail("SERVICE_UNAVAILABLE")
        if (
            type(target.demand_version_no) is not int
            or target.demand_version_no < 1
            or type(target.demand_aggregate_version) is not int
            or target.demand_aggregate_version < 1
            or not _is_uuid(target.demand_version_id)
            or not _is_digest(target.content_sha256)
            or not _is_digest(target.reporter_party_marker_sha256)
            or not _is_digest(target.target_marker_sha256)
            or not isinstance(target.reportable_until, datetime)
            or target.reportable_until.tzinfo is None
            or target.reportable_until.utcoffset() != timedelta(0)
        ):
            _fail("SERVICE_UNAVAILABLE")
        if (
            target.demand_status not in _REPORTABLE_DEMAND_STATUSES
            or target.reportable_until <= now
        ):
            _fail("RESOURCE_NOT_FOUND")
        return target

    def _prepare_outcome_evidence(
        self,
        *,
        actor: TrustActorContext,
        command: PublishTrustOutcomeCommand,
        case: SafetyCase,
        granted: TrustOfficerAuthority,
        snapshot: Mapping[str, Mapping[str, Any]],
        now: datetime,
    ) -> TrustInitialOutcomeEvidence:
        report = _snapshot_report(snapshot, case.report_id)
        triage = _snapshot_current_triage(snapshot, case)
        active_holds = _snapshot_active_holds(snapshot, case, now)
        try:
            result = self._decision_evidence.prepare_initial_outcome(
                officer_authority=granted,
                case=case,
                report=report,
                triage=triage,
                active_holds=active_holds,
                outcome=command.outcome_code,
                reason_codes=command.reason_codes,
                action_codes=command.action_codes,
                now=now,
            )
        except TrustDecisionEvidenceUnavailableError:
            _fail("SERVICE_UNAVAILABLE")
        except Exception:
            _fail("SERVICE_UNAVAILABLE")
        if not isinstance(result, TrustInitialOutcomeEvidence):
            _fail("SERVICE_UNAVAILABLE")
        if (
            result.case_id != case.case_id
            or result.case_aggregate_version != case.aggregate_version
            or result.triage_version != triage.version
            or result.outcome_code != command.outcome_code.value
            or result.reason_codes != command.reason_codes
            or result.action_codes
            != tuple(action.value for action in command.action_codes)
            or not _is_uuid(result.evidence_packet_version_id)
            or not _is_digest(result.evidence_packet_digest)
            or not _is_digest(result.source_digest)
            or result.redaction_profile_code
            not in {"OFFICER_RESTRICTED_V1", "PARTY_SAFE_V1"}
            or result.policy_version != self._outcome_policy_version
            or type(result.appeal_eligible) is not bool
            or result.appeal_eligibility_code
            not in {"ELIGIBLE", "NOT_ELIGIBLE"}
            or result.appeal_eligible
            != (result.appeal_eligibility_code == "ELIGIBLE")
            or not isinstance(result.evaluated_at, datetime)
            or not isinstance(result.valid_until, datetime)
            or result.evaluated_at.tzinfo is None
            or result.valid_until.tzinfo is None
            or result.evaluated_at.utcoffset() != timedelta(0)
            or result.valid_until.utcoffset() != timedelta(0)
            or result.evaluated_at > now
            or result.valid_until <= now
        ):
            _fail("SERVICE_UNAVAILABLE")
        deadline = result.appeal_deadline
        if result.appeal_eligible:
            if (
                not isinstance(deadline, datetime)
                or deadline.tzinfo is None
                or deadline.utcoffset() != timedelta(0)
                or deadline <= now
            ):
                _fail("SERVICE_UNAVAILABLE")
        elif deadline is not None:
            _fail("SERVICE_UNAVAILABLE")
        return result

    def _check_conflict(
        self,
        *,
        actor: TrustActorContext,
        case: SafetyCase,
        granted: TrustOfficerAuthority,
        now: datetime,
    ) -> TrustOfficerConflictCheck:
        try:
            result = self._target.check_officer_conflict(
                officer_authority=granted,
                operation=_OPERATION_NAMES[self.operation],
                organization_id=case.organization_id,
                demand_id=case.demand_id,
                demand_version_id=case.demand_version_id,
            )
        except TrustTargetUnavailableError:
            _fail("SERVICE_UNAVAILABLE")
        except Exception:
            _fail("SERVICE_UNAVAILABLE")
        if not isinstance(result, TrustOfficerConflictCheck):
            _fail("SERVICE_UNAVAILABLE")
        if (
            not isinstance(result.evaluated_at, datetime)
            or not isinstance(result.valid_until, datetime)
            or result.evaluated_at.tzinfo is None
            or result.valid_until.tzinfo is None
            or result.evaluated_at.utcoffset() != timedelta(0)
            or result.valid_until.utcoffset() != timedelta(0)
        ):
            _fail("SERVICE_UNAVAILABLE")
        if (
            result.officer_user_id != actor.actor_user_id
            or result.organization_id != case.organization_id
            or result.demand_id != case.demand_id
            or result.demand_version_id != case.demand_version_id
            or result.evaluated_at > now
            or result.valid_until <= now
            or not _is_digest(result.conflict_attestation_sha256)
        ):
            _fail("SERVICE_UNAVAILABLE")
        if not result.conflict_free:
            _fail("CONFLICT_OF_INTEREST")
        return result

    def _seal_note(
        self,
        *,
        actor: TrustActorContext,
        command: SaveTrustTriageDraftCommand,
        identity: Mapping[str, Any],
        now: datetime,
    ) -> TrustSealedNote:
        if (
            not isinstance(command.restricted_note, str)
            or not command.restricted_note.strip()
            or len(command.restricted_note) > 4_000
        ):
            _fail("TRIAGE_VALIDATION_FAILED")
        try:
            result = self._sealed_notes.seal(
                case_id=command.case_id,
                actor_user_id=actor.actor_user_id,
                purpose="TRIAGE_DRAFT",
                raw_note=command.restricted_note,
                idempotency_key_digest=identity["idempotency_key_digest"],
            )
        except TrustSealedNoteUnavailableError:
            _fail("SERVICE_UNAVAILABLE")
        except Exception:
            _fail("SERVICE_UNAVAILABLE")
        if (
            not isinstance(result, TrustSealedNote)
            or not isinstance(result.sealed_note_reference, str)
            or _SEALED_REFERENCE.fullmatch(result.sealed_note_reference) is None
            or not _is_digest(result.sealed_note_sha256)
            or result.retention_class != "TRUST_CASE_NOTE"
            or not isinstance(result.sealed_at, datetime)
            or result.sealed_at.tzinfo is None
            or result.sealed_at.utcoffset() != timedelta(0)
            or result.sealed_at > now
        ):
            _fail("SERVICE_UNAVAILABLE")
        return result

    def _lock_all(
        self,
        *,
        uow: Any,
        actor: TrustActorContext,
        command: Any,
        granted: Any,
        identities: Tuple[Mapping[str, Any], ...],
        prepared: _PreparedDependencies,
    ) -> None:
        try:
            uow.lock(
                "iam.authority_marker", (granted.authority_marker_sha256,)
            )
            if prepared.target is not None:
                uow.lock(
                    "demand.report_target",
                    (
                        prepared.target.organization_id,
                        prepared.target.demand_id,
                        prepared.target.demand_version_id,
                    ),
                )
            case_id = getattr(command, "case_id", None)
            if self.operation in {"claim_hold_release", "release_hold"}:
                uow.lock("trust.safety_hold", (command.hold_id,))
                locked_hold = uow.get("safety_holds", command.hold_id)
                if not isinstance(locked_hold, SafetyHold):
                    _fail("RESOURCE_NOT_FOUND")
                case_id = locked_hold.case_id
            if case_id is not None:
                uow.lock("trust.safety_case", (case_id,))
                locked_case = uow.get("safety_cases", case_id)
                assignment_id = (
                    locked_case.assignment_id
                    if isinstance(locked_case, SafetyCase)
                    else None
                )
                uow.lock(
                    "trust.case_assignment",
                    ((assignment_id,) if assignment_id else ()),
                )
            if self.operation == "release_hold":
                locked_hold = uow.get("safety_holds", command.hold_id)
                candidate_ids = (
                    (locked_hold.release_assignment_id,)
                    if isinstance(locked_hold, SafetyHold)
                    and locked_hold.release_assignment_id is not None
                    else ()
                )
                uow.lock(
                    "trust.independent_release_assignment", candidate_ids
                )
            uow.lock(
                "trust.command_receipt",
                tuple(
                    identity["idempotency_key_digest"]
                    for identity in identities
                ),
            )
        except TrustApplicationError:
            raise
        except Exception:
            _fail("SERVICE_UNAVAILABLE")

    def _apply_domain(
        self,
        *,
        uow: Any,
        actor: TrustActorContext,
        command: Any,
        granted: Any,
        prepared: _PreparedDependencies,
        generated_ids: Mapping[str, str],
        now: datetime,
    ) -> _Mutation:
        if self.operation == "submit_report":
            target = prepared.target
            if target is None:
                _fail("SERVICE_UNAVAILABLE")
            if any(
                uow.get(collection, identifier) is not None
                for collection, identifier in (
                    ("safety_cases", generated_ids["case_id"]),
                    ("reports", generated_ids["report_id"]),
                )
            ):
                _fail("SERVICE_UNAVAILABLE")
            case, report = SafetyCase.open_report(
                case_id=generated_ids["case_id"],
                report_id=generated_ids["report_id"],
                organization_id=target.organization_id,
                demand_id=target.demand_id,
                demand_version_id=target.demand_version_id,
                demand_version_no=target.demand_version_no,
                demand_aggregate_version=target.demand_aggregate_version,
                demand_status=target.demand_status,
                demand_content_sha256=target.content_sha256,
                reporter_party_marker_sha256=(
                    target.reporter_party_marker_sha256
                ),
                target_marker_sha256=target.target_marker_sha256,
                reportable_until=target.reportable_until,
                reporter_user_id=actor.actor_user_id,
                category=command.category,
                incident_started_at=command.incident_started_at,
                incident_ended_at=command.incident_ended_at,
                impact_codes=command.impact_codes,
                evidence_reference_ids=command.evidence_reference_ids,
                requested_protection_codes=command.requested_protection_codes,
                now=now,
            )
            return _Mutation(case=case, report=report)

        if self.operation in {"claim_hold_release", "release_hold"}:
            hold = uow.get("safety_holds", command.hold_id)
            if not isinstance(hold, SafetyHold):
                _fail("RESOURCE_NOT_FOUND")
            case = _locked_case(uow, hold.case_id)
            if hold.aggregate_version != command.expected_hold_version:
                _fail("PRECONDITION_FAILED")
        else:
            case = _locked_case(uow, command.case_id)
            if case.aggregate_version != command.expected_case_version:
                _fail("PRECONDITION_FAILED")

        if self.operation == "claim_case":
            conflict = prepared.conflict
            if conflict is None or not isinstance(granted, TrustOfficerAuthority):
                _fail("SERVICE_UNAVAILABLE")
            case, assignment = case.claim(
                assignment_id=generated_ids["assignment_id"],
                officer_user_id=actor.actor_user_id,
                duty_grant_id=granted.duty_grant_id,
                duty_grant_version=granted.duty_grant_version,
                conflict_attestation_sha256=conflict.conflict_attestation_sha256,
                expires_at=now
                + timedelta(minutes=self._assignment_ttl_minutes),
                now=now,
            )
            return _Mutation(case=case, assignment=assignment)

        if self.operation == "release_assignment":
            if command.reason_code.value == "ASSIGNMENT_EXPIRED":
                _require_case_assignment_fact(uow=uow, case=case)
            else:
                _require_current_assignment_authority(
                    uow=uow,
                    case=case,
                    actor=actor,
                    granted=granted,
                    now=now,
                )
            case, assignment_release = case.release_assignment(
                requester_user_id=actor.actor_user_id,
                reason_code=command.reason_code,
                now=now,
            )
            return _Mutation(
                case=case,
                assignment_release=assignment_release,
            )

        if self.operation == "claim_hold_release":
            conflict = prepared.conflict
            if conflict is None or not isinstance(granted, TrustOfficerAuthority):
                _fail("SERVICE_UNAVAILABLE")
            updated_hold, assignment = case.claim_hold_release(
                hold=hold,
                assignment_id=generated_ids["hold_release_assignment_id"],
                officer_user_id=actor.actor_user_id,
                duty_grant_id=granted.duty_grant_id,
                duty_grant_version=granted.duty_grant_version,
                conflict_attestation_sha256=conflict.conflict_attestation_sha256,
                expires_at=min(
                    hold.expires_at,
                    now + timedelta(minutes=self._assignment_ttl_minutes),
                ),
                now=now,
            )
            return _Mutation(
                case=case,
                hold=updated_hold,
                hold_release_assignment=assignment,
            )

        if self.operation in {
            "save_triage",
            "publish_triage",
            "place_hold",
            "publish_outcome",
        }:
            _require_current_assignment_authority(
                uow=uow,
                case=case,
                actor=actor,
                granted=granted,
                now=now,
            )

        if self.operation == "save_triage":
            sealed = prepared.sealed_note
            if sealed is None:
                _fail("SERVICE_UNAVAILABLE")
            case, draft = case.save_triage_draft(
                officer_user_id=actor.actor_user_id,
                priority_code=command.priority_code,
                jurisdiction_code=command.jurisdiction_code,
                severity_code=command.severity_code,
                issue_codes=command.issue_codes,
                investigation_step_codes=command.investigation_step_codes,
                proposed_hold_actions=command.proposed_hold_actions,
                proposed_hold_ttl_minutes=command.proposed_hold_ttl_minutes,
                sealed_note_reference=sealed.sealed_note_reference,
                sealed_note_sha256=sealed.sealed_note_sha256,
                now=now,
            )
            return _Mutation(case=case, triage_draft=draft)

        if self.operation == "publish_triage":
            case, version = case.publish_triage(
                officer_user_id=actor.actor_user_id,
                expected_draft_version=command.expected_draft_version,
                now=now,
            )
            return _Mutation(case=case, triage_version=version)

        if self.operation == "place_hold":
            published = _current_triage_version(uow, case)
            if (
                not set(command.action_codes).issubset(
                    set(published.proposed_hold_actions)
                )
                or type(command.hold_ttl_minutes) is not int
                or command.hold_ttl_minutes < 1
                or command.hold_ttl_minutes
                > published.proposed_hold_ttl_minutes
            ):
                _fail("HOLD_VALIDATION_FAILED")
            case, hold = case.place_hold(
                hold_id=generated_ids["hold_id"],
                officer_user_id=actor.actor_user_id,
                action_codes=command.action_codes,
                reason_code=command.reason_code,
                expires_at=now + timedelta(minutes=command.hold_ttl_minutes),
                policy_version=self._hold_policy_version,
                now=now,
            )
            return _Mutation(case=case, hold=hold)

        if self.operation == "release_hold":
            independent_assignment = None
            if hold.requires_independent_release:
                independent_assignment = _independent_release_assignment(
                    uow=uow,
                    hold=hold,
                    actor=actor,
                    granted=granted,
                    now=now,
                )
            else:
                _require_current_assignment_authority(
                    uow=uow,
                    case=case,
                    actor=actor,
                    granted=granted,
                    now=now,
                )
            case, released = case.release_hold(
                hold=hold,
                officer_user_id=actor.actor_user_id,
                release_reason_code=command.release_reason_code,
                independent_assignment=independent_assignment,
                now=now,
            )
            return _Mutation(case=case, hold=released)

        if self.operation == "publish_outcome":
            evidence = prepared.outcome_evidence
            if evidence is None:
                _fail("SERVICE_UNAVAILABLE")
            case, outcome = case.record_initial_outcome(
                outcome_version_id=generated_ids["outcome_version_id"],
                officer_user_id=actor.actor_user_id,
                outcome=command.outcome_code,
                reason_codes=command.reason_codes,
                action_codes=command.action_codes,
                evidence_packet_version_id=evidence.evidence_packet_version_id,
                evidence_packet_digest=evidence.evidence_packet_digest,
                source_digest=evidence.source_digest,
                redaction_profile_code=evidence.redaction_profile_code,
                appeal_eligible=evidence.appeal_eligible,
                appeal_eligibility_code=evidence.appeal_eligibility_code,
                appeal_deadline=evidence.appeal_deadline,
                policy_version=evidence.policy_version,
                now=now,
            )
            return _Mutation(case=case, outcome=outcome)

        _fail("INVALID_REQUEST")
        raise AssertionError("unreachable")

    def _write_business_facts(self, *, uow: Any, mutation: _Mutation) -> None:
        if self.operation != "claim_hold_release":
            uow.put(
                "safety_cases",
                mutation.case.case_id,
                mutation.case,
                checkpoint="case." + self.operation,
            )
        if mutation.report is not None:
            uow.put(
                "reports",
                mutation.report.report_id,
                mutation.report,
                checkpoint="report.submitted",
            )
        if mutation.assignment is not None:
            uow.put(
                "case_assignments",
                mutation.assignment.assignment_id,
                mutation.assignment,
                checkpoint="assignment.claimed",
            )
        if mutation.assignment_release is not None:
            uow.put(
                "assignment_releases",
                mutation.assignment_release.assignment_id,
                mutation.assignment_release,
                checkpoint="assignment.released",
            )
        if mutation.hold_release_assignment is not None:
            uow.put(
                "hold_release_assignments",
                mutation.hold_release_assignment.assignment_id,
                mutation.hold_release_assignment,
                checkpoint="hold_release_assignment.claimed",
            )
        if mutation.triage_draft is not None:
            uow.put(
                "triage_drafts",
                _version_key(
                    mutation.triage_draft.case_id,
                    mutation.triage_draft.version,
                ),
                mutation.triage_draft,
                checkpoint="triage.draft_saved",
            )
        if mutation.triage_version is not None:
            uow.put(
                "triage_versions",
                _version_key(
                    mutation.triage_version.case_id,
                    mutation.triage_version.version,
                ),
                mutation.triage_version,
                checkpoint="triage.published",
            )
        if mutation.hold is not None:
            uow.put(
                "safety_holds",
                mutation.hold.hold_id,
                mutation.hold,
                checkpoint=(
                    "hold.released"
                    if self.operation == "release_hold"
                    else "hold.placed"
                ),
            )
        if mutation.outcome is not None:
            uow.put(
                "case_outcomes",
                mutation.outcome.outcome_version_id,
                mutation.outcome,
                checkpoint="outcome.published",
            )

    def _generated_ids(self) -> Mapping[str, str]:
        if self.operation == "submit_report":
            return {
                "case_id": self._new_id("safety_case"),
                "report_id": self._new_id("safety_report"),
            }
        if self.operation == "claim_case":
            return {"assignment_id": self._new_id("trust_case_assignment")}
        if self.operation == "claim_hold_release":
            return {
                "hold_release_assignment_id": self._new_id(
                    "trust_hold_release_assignment"
                )
            }
        if self.operation == "place_hold":
            return {"hold_id": self._new_id("safety_hold")}
        if self.operation == "publish_outcome":
            return {
                "outcome_version_id": self._new_id(
                    "trust_case_outcome_version"
                )
            }
        return {}

    def _now(self) -> datetime:
        try:
            value = self._clock.now()
        except Exception:
            _fail("SERVICE_UNAVAILABLE")
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() != timedelta(0)
        ):
            _fail("SERVICE_UNAVAILABLE")
        return value.astimezone(timezone.utc)

    def _new_id(self, kind: str) -> str:
        try:
            value = self._id_source.new_id(kind)
        except Exception:
            _fail("SERVICE_UNAVAILABLE")
        if not _is_uuid(value):
            _fail("SERVICE_UNAVAILABLE")
        return value

    def _safe_snapshot(self) -> Mapping[str, Mapping[str, Any]]:
        try:
            value = self._uow_factory.store.snapshot()
        except Exception:
            _fail("SERVICE_UNAVAILABLE")
        if not isinstance(value, Mapping):
            _fail("SERVICE_UNAVAILABLE")
        return value

    def _receipt_identities(
        self,
        *,
        actor_user_id: str,
        idempotency_key: str,
    ) -> Tuple[Mapping[str, Any], ...]:
        if (
            not isinstance(idempotency_key, str)
            or not idempotency_key
            or len(idempotency_key.encode("utf-8")) > 512
        ):
            _fail("INVALID_REQUEST")
        key_ids = getattr(
            self._receipt_keyring,
            "idempotency_key_digest_key_ids",
            None,
        )
        if (
            not isinstance(key_ids, tuple)
            or not 1 <= len(key_ids) <= 4
            or len(key_ids) != len(set(key_ids))
            or any(not isinstance(value, str) or not value for value in key_ids)
        ):
            _fail("SERVICE_UNAVAILABLE")
        material = (
            b"desire:trust-safety:idempotency:v1\0"
            + _OPERATION_NAMES[self.operation].encode("ascii")
            + b"\0"
            + idempotency_key.encode("utf-8")
        )
        return tuple(
            {
                "principal_kind": "USER",
                "principal_id": actor_user_id,
                "command_name": _OPERATION_NAMES[self.operation],
                "command_version": 1,
                "idempotency_key_digest_key_id": key_id,
                "idempotency_key_digest": self._keyed_digest(key_id, material),
            }
            for key_id in key_ids
        )

    def _payload_key_ids(self) -> Tuple[str, ...]:
        value = getattr(self._receipt_keyring, "payload_hash_key_ids", None)
        if (
            not isinstance(value, tuple)
            or not 1 <= len(value) <= 4
            or len(value) != len(set(value))
            or any(not isinstance(item, str) or not item for item in value)
        ):
            _fail("SERVICE_UNAVAILABLE")
        return value

    def _payload_hashes(
        self,
        *,
        actor: TrustActorContext,
        command: Any,
    ) -> Mapping[str, str]:
        try:
            material = {
                "method": (
                    "POST" if self.operation != "save_triage" else "PUT"
                ),
                "canonical_path": _CANONICAL_PATHS[self.operation],
                "command_schema_version": 1,
                "workspace_organization_id": actor.organization_id,
                "body": _command_body(self.operation, command),
            }
            encoded = json.dumps(
                material,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        except TrustApplicationError:
            raise
        except (AttributeError, TypeError, ValueError, UnicodeError):
            _fail("INVALID_REQUEST")
        keyed_material = (
            b"desire:trust-safety:command-payload:v1\0"
            + _OPERATION_NAMES[self.operation].encode("ascii")
            + b"\0"
            + encoded
        )
        return {
            key_id: self._keyed_digest(key_id, keyed_material)
            for key_id in self._payload_key_ids()
        }

    def _keyed_digest(self, key_id: str, material: bytes) -> str:
        try:
            value = self._receipt_keyring.keyed_digest(key_id, material)
        except Exception:
            _fail("SERVICE_UNAVAILABLE")
        if not _is_digest(value):
            _fail("SERVICE_UNAVAILABLE")
        return value

    def _recover_unknown(
        self,
        identities: Tuple[Mapping[str, Any], ...],
        payload_hashes: Mapping[str, str],
    ) -> Optional[TrustCommandResult]:
        try:
            snapshot = self._safe_snapshot()
        except TrustApplicationError:
            return None
        receipt = _find_receipt(
            snapshot.get("command_receipts", {}), identities
        )
        if receipt is None:
            return None
        try:
            return _replay_or_conflict(receipt, payload_hashes)
        except TrustApplicationError as error:
            if error.code == "IDEMPOTENCY_KEY_REUSED":
                raise
            return None


class SubmitSafetyReportHandler(_TrustHandler):
    operation = "submit_report"


class ClaimSafetyCaseHandler(_TrustHandler):
    operation = "claim_case"


class ReleaseSafetyCaseAssignmentHandler(_TrustHandler):
    operation = "release_assignment"


class SaveTrustTriageDraftHandler(_TrustHandler):
    operation = "save_triage"


class PublishTrustTriageHandler(_TrustHandler):
    operation = "publish_triage"


class PlaceSafetyHoldHandler(_TrustHandler):
    operation = "place_hold"


class ClaimSafetyHoldReleaseHandler(_TrustHandler):
    operation = "claim_hold_release"


class ReleaseSafetyHoldHandler(_TrustHandler):
    operation = "release_hold"


class PublishTrustOutcomeHandler(_TrustHandler):
    operation = "publish_outcome"


def _validate_actor_context(
    actor: TrustActorContext,
    *,
    reporter: bool,
) -> None:
    if (
        not _is_uuid(actor.actor_user_id)
        or not _is_uuid(actor.session_id)
        or not _is_uuid(actor.correlation_id)
        or not _is_uuid(actor.causation_id)
        or not _is_uuid(actor.trace_id)
        or actor.original_actor_user_id is not None
    ):
        _fail("ACCESS_DENIED")
    if reporter:
        if not _is_uuid(actor.organization_id):
            _fail("ACCESS_DENIED")
    elif actor.organization_id is not None:
        _fail("ACCESS_DENIED")


def _validate_reporter_authority(
    value: Any,
    actor: TrustActorContext,
) -> TrustReporterAuthority:
    if not isinstance(value, TrustReporterAuthority):
        _fail("SERVICE_UNAVAILABLE")
    if value.user_status != "ACTIVE":
        _fail("AUTHENTICATION_REQUIRED")
    if (
        value.session_status != "ACTIVE"
        or value.session_family_status != "ACTIVE"
        or value.session_id != actor.session_id
    ):
        _fail("SESSION_EXPIRED")
    if (
        value.actor_user_id != actor.actor_user_id
        or value.organization_id != actor.organization_id
        or value.organization_status != "ACTIVE"
        or value.membership_status != "ACTIVE"
        or value.role_code != "DEMAND_OWNER"
    ):
        _fail("RESOURCE_NOT_FOUND")
    if type(value.policy_requirements_satisfied) is not bool:
        _fail("SERVICE_UNAVAILABLE")
    if not value.policy_requirements_satisfied:
        _fail("POLICY_ACCEPTANCE_REQUIRED")
    if (
        type(value.membership_role_grant_version) is not int
        or value.membership_role_grant_version < 1
        or not _is_uuid(value.actor_user_id)
        or not _is_uuid(value.session_id)
        or not _is_uuid(value.organization_id)
        or not _is_uuid(value.membership_id)
        or not _is_uuid(value.membership_role_grant_id)
        or not _is_digest(value.authority_marker_sha256)
    ):
        _fail("SERVICE_UNAVAILABLE")
    return value


def _validate_occ_fields(operation: str, command: Any) -> None:
    if operation not in {"submit_report", "claim_hold_release", "release_hold"}:
        value = getattr(command, "expected_case_version", None)
        if type(value) is not int or value < 1:
            _fail("INVALID_REQUEST")
    if operation == "publish_triage":
        value = command.expected_draft_version
        if type(value) is not int or value < 1:
            _fail("INVALID_REQUEST")
    if operation in {"claim_hold_release", "release_hold"}:
        value = command.expected_hold_version
        if type(value) is not int or value < 1:
            _fail("INVALID_REQUEST")


def _validate_officer_authority(
    value: Any,
    actor: TrustActorContext,
) -> TrustOfficerAuthority:
    if not isinstance(value, TrustOfficerAuthority):
        _fail("SERVICE_UNAVAILABLE")
    if value.user_status != "ACTIVE":
        _fail("AUTHENTICATION_REQUIRED")
    if (
        value.session_status != "ACTIVE"
        or value.session_family_status != "ACTIVE"
        or value.session_id != actor.session_id
    ):
        _fail("SESSION_EXPIRED")
    if (
        value.actor_user_id != actor.actor_user_id
        or value.duty_code != "TRUST_OFFICER"
    ):
        _fail("ACCESS_DENIED")
    if (
        type(value.duty_grant_version) is not int
        or value.duty_grant_version < 1
        or not _is_uuid(value.actor_user_id)
        or not _is_uuid(value.session_id)
        or not _is_uuid(value.duty_grant_id)
        or not _is_digest(value.authority_marker_sha256)
    ):
        _fail("SERVICE_UNAVAILABLE")
    return value


def _snapshot_case(
    snapshot: Mapping[str, Mapping[str, Any]],
    case_id: str,
) -> SafetyCase:
    value = snapshot.get("safety_cases", {}).get(case_id)
    if not isinstance(value, SafetyCase):
        _fail("RESOURCE_NOT_FOUND")
    return value


def _snapshot_hold(
    snapshot: Mapping[str, Mapping[str, Any]],
    hold_id: str,
) -> SafetyHold:
    value = snapshot.get("safety_holds", {}).get(hold_id)
    if not isinstance(value, SafetyHold):
        _fail("RESOURCE_NOT_FOUND")
    return value


def _snapshot_report(
    snapshot: Mapping[str, Mapping[str, Any]],
    report_id: str,
) -> SafetyReport:
    value = snapshot.get("reports", {}).get(report_id)
    if not isinstance(value, SafetyReport):
        _fail("SERVICE_UNAVAILABLE")
    return value


def _snapshot_current_triage(
    snapshot: Mapping[str, Mapping[str, Any]],
    case: SafetyCase,
) -> TrustTriageVersion:
    if case.current_triage_version is None:
        _fail("CASE_STATE_CONFLICT")
    value = snapshot.get("triage_versions", {}).get(
        _version_key(case.case_id, case.current_triage_version)
    )
    if not isinstance(value, TrustTriageVersion):
        _fail("SERVICE_UNAVAILABLE")
    return value


def _snapshot_active_holds(
    snapshot: Mapping[str, Mapping[str, Any]],
    case: SafetyCase,
    now: datetime,
) -> Tuple[SafetyHold, ...]:
    values = snapshot.get("safety_holds", {})
    if not isinstance(values, Mapping):
        _fail("SERVICE_UNAVAILABLE")
    holds = tuple(
        sorted(
            (
                value
                for value in values.values()
                if isinstance(value, SafetyHold)
                and value.case_id == case.case_id
                and value.status.value == "ACTIVE"
                and now < value.expires_at
            ),
            key=lambda value: value.hold_id.encode("ascii"),
        )
    )
    if any(not isinstance(value, SafetyHold) for value in values.values()):
        _fail("SERVICE_UNAVAILABLE")
    return holds


def _locked_case(uow: Any, case_id: str) -> SafetyCase:
    value = uow.get("safety_cases", case_id)
    if not isinstance(value, SafetyCase):
        _fail("RESOURCE_NOT_FOUND")
    return value


def _current_triage_version(uow: Any, case: SafetyCase) -> TrustTriageVersion:
    if case.current_triage_version is None:
        _fail("CASE_STATE_CONFLICT")
    value = uow.get(
        "triage_versions",
        _version_key(case.case_id, case.current_triage_version),
    )
    if not isinstance(value, TrustTriageVersion):
        _fail("SERVICE_UNAVAILABLE")
    return value


def _require_current_assignment_authority(
    *,
    uow: Any,
    case: SafetyCase,
    actor: TrustActorContext,
    granted: Any,
    now: datetime,
) -> SafetyCaseAssignment:
    if not isinstance(granted, TrustOfficerAuthority):
        _fail("SERVICE_UNAVAILABLE")
    assignment = _require_case_assignment_fact(uow=uow, case=case)
    if (
        assignment.officer_user_id != actor.actor_user_id
        or assignment.duty_grant_id != granted.duty_grant_id
        or assignment.duty_grant_version != granted.duty_grant_version
        or assignment.assigned_at > now
        or now >= assignment.expires_at
        or not _is_digest(assignment.conflict_attestation_sha256)
    ):
        _fail("CASE_ASSIGNMENT_REQUIRED")
    return assignment


def _require_case_assignment_fact(
    *,
    uow: Any,
    case: SafetyCase,
) -> SafetyCaseAssignment:
    assignment = (
        uow.get("case_assignments", case.assignment_id)
        if case.assignment_id is not None
        else None
    )
    if not isinstance(assignment, SafetyCaseAssignment):
        _fail("CASE_ASSIGNMENT_REQUIRED")
    if (
        assignment.assignment_id != case.assignment_id
        or assignment.case_id != case.case_id
        or assignment.officer_user_id != case.assigned_officer_user_id
        or assignment.expires_at != case.assignment_expires_at
        or type(assignment.duty_grant_version) is not int
        or assignment.duty_grant_version < 1
        or not _is_uuid(assignment.duty_grant_id)
        or not _is_digest(assignment.conflict_attestation_sha256)
    ):
        _fail("SERVICE_UNAVAILABLE")
    return assignment


def _independent_release_assignment(
    *,
    uow: Any,
    hold: SafetyHold,
    actor: TrustActorContext,
    granted: Any,
    now: datetime,
) -> Optional[SafetyHoldReleaseAssignment]:
    if not isinstance(granted, TrustOfficerAuthority):
        _fail("SERVICE_UNAVAILABLE")
    if hold.release_assignment_id is None:
        return None
    assignment = uow.get(
        "hold_release_assignments", hold.release_assignment_id
    )
    if not isinstance(assignment, SafetyHoldReleaseAssignment):
        _fail("SERVICE_UNAVAILABLE")
    if (
        assignment.assignment_id != hold.release_assignment_id
        or assignment.hold_id != hold.hold_id
        or assignment.case_id != hold.case_id
        or assignment.officer_user_id != actor.actor_user_id
        or assignment.officer_user_id != hold.release_assigned_officer_user_id
        or assignment.officer_user_id == hold.issued_by_user_id
        or assignment.duty_grant_id != granted.duty_grant_id
        or assignment.duty_grant_version != granted.duty_grant_version
        or assignment.expires_at != hold.release_assignment_expires_at
        or not assignment.assigned_at <= now < assignment.expires_at
        or not _is_digest(assignment.conflict_attestation_sha256)
    ):
        return None
    return assignment


def _find_receipt(
    receipts: Mapping[str, Any],
    identities: Tuple[Mapping[str, Any], ...],
) -> Optional[Mapping[str, Any]]:
    if not isinstance(receipts, Mapping) or not identities:
        _fail("SERVICE_UNAVAILABLE")
    matches = []
    for value in receipts.values():
        if not isinstance(value, Mapping):
            _fail("SERVICE_UNAVAILABLE")
        if any(
            all(value.get(key) == expected for key, expected in identity.items())
            for identity in identities
        ):
            matches.append(value)
    if len(matches) > 1:
        _fail("SERVICE_UNAVAILABLE")
    return matches[0] if matches else None


def _replay_or_conflict(
    receipt: Mapping[str, Any],
    payload_hashes: Mapping[str, str],
) -> TrustCommandResult:
    payload_key_id = receipt.get("payload_hash_key_id")
    payload_hash = payload_hashes.get(payload_key_id)
    stored_hash = receipt.get("payload_hash")
    if not isinstance(payload_hash, str) or not isinstance(stored_hash, str):
        _fail("SERVICE_UNAVAILABLE")
    if not hmac.compare_digest(stored_hash, payload_hash):
        _fail("IDEMPOTENCY_KEY_REUSED")
    if receipt.get("status") != "COMPLETED":
        _fail("COMMAND_OUTCOME_UNKNOWN")
    safe = receipt.get("safe_response")
    if not isinstance(safe, Mapping):
        _fail("SERVICE_UNAVAILABLE")
    return _result_from_safe_response(safe, replayed=True)


def _command_body(operation: str, command: Any) -> Mapping[str, Any]:
    if operation == "submit_report":
        return {
            "demand_id": command.demand_id,
            "demand_version_id": command.demand_version_id,
            "category": _enum_value(command.category),
            "incident_started_at": _timestamp(command.incident_started_at),
            "incident_ended_at": (
                None
                if command.incident_ended_at is None
                else _timestamp(command.incident_ended_at)
            ),
            "impact_codes": list(command.impact_codes),
            "evidence_reference_ids": list(command.evidence_reference_ids),
            "requested_protection_codes": list(
                command.requested_protection_codes
            ),
        }
    if operation == "claim_case":
        return {
            "case_id": command.case_id,
            "expected_case_version": command.expected_case_version,
        }
    if operation == "release_assignment":
        return {
            "case_id": command.case_id,
            "expected_case_version": command.expected_case_version,
            "reason_code": _enum_value(command.reason_code),
        }
    if operation == "save_triage":
        # Only a one-way digest enters canonical material; raw text is never
        # retained by the receipt pipeline.
        restricted_note_digest = hashlib.sha256(
            command.restricted_note.encode("utf-8")
        ).hexdigest()
        return {
            "case_id": command.case_id,
            "expected_case_version": command.expected_case_version,
            "priority_code": command.priority_code,
            "jurisdiction_code": command.jurisdiction_code,
            "severity_code": command.severity_code,
            "issue_codes": list(command.issue_codes),
            "investigation_step_codes": list(
                command.investigation_step_codes
            ),
            "proposed_hold_actions": [
                _enum_value(value) for value in command.proposed_hold_actions
            ],
            "proposed_hold_ttl_minutes": command.proposed_hold_ttl_minutes,
            "restricted_note_sha256": restricted_note_digest,
        }
    if operation == "publish_triage":
        return {
            "case_id": command.case_id,
            "expected_case_version": command.expected_case_version,
            "expected_draft_version": command.expected_draft_version,
        }
    if operation == "place_hold":
        return {
            "case_id": command.case_id,
            "expected_case_version": command.expected_case_version,
            "action_codes": [
                _enum_value(value) for value in command.action_codes
            ],
            "reason_code": _enum_value(command.reason_code),
            "hold_ttl_minutes": command.hold_ttl_minutes,
        }
    if operation == "claim_hold_release":
        return {
            "hold_id": command.hold_id,
            "expected_hold_version": command.expected_hold_version,
        }
    if operation == "release_hold":
        return {
            "hold_id": command.hold_id,
            "expected_hold_version": command.expected_hold_version,
            "release_reason_code": command.release_reason_code,
        }
    if operation == "publish_outcome":
        return {
            "case_id": command.case_id,
            "expected_case_version": command.expected_case_version,
            "outcome_code": _enum_value(command.outcome_code),
            "reason_codes": list(command.reason_codes),
            "action_codes": [
                _enum_value(value) for value in command.action_codes
            ],
        }
    _fail("INVALID_REQUEST")
    raise AssertionError("unreachable")


def _safe_response(
    *,
    mutation: _Mutation,
    event_type: str,
    completed_at: datetime,
) -> Mapping[str, Any]:
    return {
        "case_id": mutation.case.case_id,
        "case_status": mutation.case.status.value,
        "aggregate_version": mutation.case.aggregate_version,
        "report_id": (
            mutation.report.report_id if mutation.report is not None else None
        ),
        "assignment_id": (
            mutation.assignment.assignment_id
            if mutation.assignment is not None
            else (
                mutation.assignment_release.assignment_id
                if mutation.assignment_release is not None
                else (
                    mutation.hold_release_assignment.assignment_id
                    if mutation.hold_release_assignment is not None
                    else None
                )
            )
        ),
        "triage_draft_version": (
            mutation.triage_draft.version
            if mutation.triage_draft is not None
            else None
        ),
        "triage_version": (
            mutation.triage_version.version
            if mutation.triage_version is not None
            else None
        ),
        "hold_id": mutation.hold.hold_id if mutation.hold is not None else None,
        "hold_version": (
            mutation.hold.aggregate_version
            if mutation.hold is not None
            else None
        ),
        "outcome_version_id": (
            mutation.outcome.outcome_version_id
            if mutation.outcome is not None
            else None
        ),
        "event_types": [event_type],
        "completed_at": _timestamp(completed_at),
    }


def _result_from_safe_response(
    safe: Mapping[str, Any],
    *,
    replayed: bool,
) -> TrustCommandResult:
    try:
        expected_keys = {
            "aggregate_version",
            "assignment_id",
            "case_id",
            "case_status",
            "completed_at",
            "event_types",
            "hold_id",
            "hold_version",
            "outcome_version_id",
            "report_id",
            "triage_draft_version",
            "triage_version",
        }
        if set(safe) != expected_keys:
            raise ValueError
        case_id = safe["case_id"]
        status = SafetyCaseStatus(safe["case_status"])
        aggregate_version = safe["aggregate_version"]
        event_types = tuple(safe["event_types"])
        completed_at = _parse_timestamp(safe["completed_at"])
        optional_ids = {
            key: safe.get(key)
            for key in (
                "report_id",
                "assignment_id",
                "hold_id",
                "outcome_version_id",
            )
        }
        if (
            not _is_uuid(case_id)
            or type(aggregate_version) is not int
            or aggregate_version < 1
            or len(event_types) != 1
            or event_types[0] not in set(_EVENT_TYPES.values())
            or any(
                value is not None and not _is_uuid(value)
                for value in optional_ids.values()
            )
        ):
            raise ValueError
        for key in ("triage_draft_version", "triage_version", "hold_version"):
            value = safe.get(key)
            if value is not None and (type(value) is not int or value < 1):
                raise ValueError
        return TrustCommandResult(
            case_id=case_id,
            case_status=status,
            aggregate_version=aggregate_version,
            report_id=optional_ids["report_id"],
            assignment_id=optional_ids["assignment_id"],
            triage_draft_version=safe.get("triage_draft_version"),
            triage_version=safe.get("triage_version"),
            hold_id=optional_ids["hold_id"],
            hold_version=safe.get("hold_version"),
            outcome_version_id=optional_ids["outcome_version_id"],
            replayed=replayed,
            event_types=event_types,
            completed_at=completed_at,
        )
    except (KeyError, TypeError, ValueError):
        _fail("SERVICE_UNAVAILABLE")
    raise AssertionError("unreachable")


def _audit_record(
    *,
    audit_id: str,
    action: str,
    actor: TrustActorContext,
    mutation: _Mutation,
    occurred_at: datetime,
) -> Mapping[str, Any]:
    return {
        "audit_event_id": audit_id,
        "action": action,
        "case_id": mutation.case.case_id,
        "aggregate_version": mutation.case.aggregate_version,
        "actor_user_id": actor.actor_user_id,
        "occurred_at": _timestamp(occurred_at),
        "trace_id": actor.trace_id,
    }


def _outbox_event(
    *,
    event_id: str,
    event_type: str,
    actor: TrustActorContext,
    mutation: _Mutation,
    occurred_at: datetime,
) -> Mapping[str, Any]:
    data: dict[str, Any] = {
        "case_id": mutation.case.case_id,
        "case_status": mutation.case.status.value,
    }
    if mutation.report is not None:
        data.update(
            {
                "report_id": mutation.report.report_id,
                "organization_id": mutation.report.organization_id,
                "demand_id": mutation.report.demand_id,
                "demand_version_id": mutation.report.demand_version_id,
            }
        )
    if mutation.assignment is not None:
        data["assignment_id"] = mutation.assignment.assignment_id
        data["assignment_expires_at"] = _timestamp(
            mutation.assignment.expires_at
        )
    if mutation.assignment_release is not None:
        data["assignment_id"] = mutation.assignment_release.assignment_id
    if mutation.hold_release_assignment is not None:
        data["assignment_id"] = mutation.hold_release_assignment.assignment_id
        data["hold_id"] = mutation.hold_release_assignment.hold_id
        data["assignment_expires_at"] = _timestamp(
            mutation.hold_release_assignment.expires_at
        )
    if mutation.triage_draft is not None:
        data["triage_draft_version"] = mutation.triage_draft.version
    if mutation.triage_version is not None:
        data["triage_version"] = mutation.triage_version.version
    if mutation.hold is not None:
        data.update(
            {
                "hold_id": mutation.hold.hold_id,
                "hold_status": mutation.hold.status.value,
                "hold_version": mutation.hold.aggregate_version,
                "action_codes": [
                    action.value for action in mutation.hold.action_codes
                ],
                "expires_at": _timestamp(mutation.hold.expires_at),
            }
        )
    if mutation.outcome is not None:
        data.update(
            {
                "outcome_version_id": mutation.outcome.outcome_version_id,
                "outcome_version": mutation.outcome.outcome_version,
                "outcome_code": mutation.outcome.outcome.value,
                "content_sha256": mutation.outcome.content_sha256,
                "appeal_eligible": mutation.outcome.appeal_eligible,
                "appeal_eligibility_code": (
                    mutation.outcome.appeal_eligibility_code
                ),
                "appeal_deadline": (
                    None
                    if mutation.outcome.appeal_deadline is None
                    else _timestamp(mutation.outcome.appeal_deadline)
                ),
            }
        )
    return {
        "event_id": event_id,
        "event_type": event_type,
        "schema_version": 1,
        "aggregate_type": "SafetyCase",
        "aggregate_id": mutation.case.case_id,
        "aggregate_version": mutation.case.aggregate_version,
        "occurred_at": _timestamp(occurred_at),
        "actor_kind": "USER",
        "actor_id": actor.actor_user_id,
        "original_actor_id": actor.original_actor_user_id,
        "organization_id": mutation.case.organization_id,
        "correlation_id": actor.correlation_id,
        "causation_id": actor.causation_id,
        "trace_id": actor.trace_id,
        "payload": data,
    }


def _version_key(case_id: str, version: int) -> str:
    return f"{case_id}:{version}"


def _enum_value(value: Any) -> str:
    if not isinstance(value, Enum):
        raise TypeError("closed enum required")
    return str(value.value)


def _timestamp(value: datetime) -> str:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise ValueError("UTC timestamp required")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("invalid timestamp")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.utcoffset() != timedelta(0):
        raise ValueError("invalid timestamp")
    return parsed


def _is_uuid(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = UUID(value)
    except (TypeError, ValueError, AttributeError):
        return False
    return parsed.int != 0 and str(parsed) == value


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _fail(code: str) -> None:
    raise TrustApplicationError(code)


__all__ = [
    "ClaimSafetyCaseHandler",
    "ClaimSafetyHoldReleaseHandler",
    "PlaceSafetyHoldHandler",
    "PublishTrustTriageHandler",
    "PublishTrustOutcomeHandler",
    "ReleaseSafetyCaseAssignmentHandler",
    "ReleaseSafetyHoldHandler",
    "SaveTrustTriageDraftHandler",
    "SubmitSafetyReportHandler",
    "TrustApplicationError",
]
