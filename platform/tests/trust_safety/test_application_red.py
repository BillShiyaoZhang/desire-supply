from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from typing import Any, Iterator, Mapping, Optional, Sequence, Tuple
from uuid import UUID

import pytest

from desire_platform.trust_safety.application import handlers as handlers_module

from desire_platform.trust_safety.application import (
    ClaimSafetyCaseCommand,
    ClaimSafetyCaseHandler,
    ClaimSafetyHoldReleaseCommand,
    ClaimSafetyHoldReleaseHandler,
    PlaceSafetyHoldCommand,
    PlaceSafetyHoldHandler,
    PublishTrustTriageCommand,
    PublishTrustTriageHandler,
    PublishTrustOutcomeCommand,
    PublishTrustOutcomeHandler,
    ReleaseSafetyCaseAssignmentCommand,
    ReleaseSafetyCaseAssignmentHandler,
    ReleaseSafetyHoldCommand,
    ReleaseSafetyHoldHandler,
    SaveTrustTriageDraftCommand,
    SaveTrustTriageDraftHandler,
    SubmitSafetyReportCommand,
    SubmitSafetyReportHandler,
    TrustActorContext,
    TrustApplicationError,
)
from desire_platform.trust_safety.domain import (
    AssignmentReleaseReason,
    HoldAction,
    HoldReason,
    ReportCategory,
    SafetyCase,
    SafetyCaseStatus,
    SafetyHold,
    SafetyHoldReleaseAssignment,
    SafetyHoldStatus,
    TrustCaseOutcome,
)
from desire_platform.trust_safety.ports import (
    TrustDemandTarget,
    TrustInitialOutcomeEvidence,
    TrustOfficerAuthority,
    TrustOfficerConflictCheck,
    TrustReporterAuthority,
    TrustSealedNote,
)


NOW = datetime(2026, 8, 18, 6, 0, tzinfo=timezone.utc)


def _uuid(number: int) -> str:
    return str(UUID(int=number))


REPORTER_ID = _uuid(1)
OFFICER_ID = _uuid(2)
SESSION_ID = _uuid(3)
ORGANIZATION_ID = _uuid(4)
DEMAND_ID = _uuid(5)
DEMAND_VERSION_ID = _uuid(6)


class FixedClock:
    def __init__(self, value: datetime = NOW) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


class SequenceIds:
    def __init__(self, start: int = 100) -> None:
        self.next_value = start
        self.kinds: list[str] = []

    def new_id(self, kind: str) -> str:
        self.kinds.append(kind)
        value = _uuid(self.next_value)
        self.next_value += 1
        return value


class TestKeyring:
    idempotency_key_digest_key_ids = ("TRUST_IDEMPOTENCY_V1",)
    payload_hash_key_ids = ("TRUST_PAYLOAD_HASH_V1",)

    def keyed_digest(self, key_id: str, value: bytes) -> str:
        return hmac.new(key_id.encode("ascii"), value, hashlib.sha256).hexdigest()


class AuthorityFake:
    def authorize_reporter(
        self,
        *,
        actor: TrustActorContext,
        operation: str,
        organization_id: str,
    ) -> TrustReporterAuthority:
        assert operation == "SUBMIT_REPORT"
        return TrustReporterAuthority(
            actor_user_id=actor.actor_user_id,
            session_id=actor.session_id,
            organization_id=organization_id,
            user_status="ACTIVE",
            session_status="ACTIVE",
            session_family_status="ACTIVE",
            organization_status="ACTIVE",
            membership_id=_uuid(20),
            membership_status="ACTIVE",
            membership_role_grant_id=_uuid(21),
            membership_role_grant_version=3,
            role_code="DEMAND_OWNER",
            policy_requirements_satisfied=True,
            authority_marker_sha256="11" * 32,
        )

    def authorize_officer(
        self,
        *,
        actor: TrustActorContext,
        operation: str,
    ) -> TrustOfficerAuthority:
        assert operation in {
            "CLAIM_CASE",
            "RELEASE_CASE_ASSIGNMENT",
            "SAVE_TRIAGE_DRAFT",
            "PUBLISH_TRIAGE",
            "PLACE_HOLD",
            "CLAIM_HOLD_RELEASE",
            "RELEASE_HOLD",
            "PUBLISH_OUTCOME",
        }
        return TrustOfficerAuthority(
            actor_user_id=actor.actor_user_id,
            session_id=actor.session_id,
            user_status="ACTIVE",
            session_status="ACTIVE",
            session_family_status="ACTIVE",
            duty_grant_id=_uuid(22),
            duty_grant_version=7,
            duty_code="TRUST_OFFICER",
            authority_marker_sha256="22" * 32,
        )


class TargetFake:
    def resolve_report_target(
        self,
        *,
        reporter_authority: TrustReporterAuthority,
        demand_id: str,
        demand_version_id: str,
    ) -> TrustDemandTarget:
        assert demand_version_id == DEMAND_VERSION_ID
        return TrustDemandTarget(
            organization_id=reporter_authority.organization_id,
            demand_id=demand_id,
            demand_version_id=DEMAND_VERSION_ID,
            demand_version_no=2,
            demand_aggregate_version=4,
            demand_status="SUBMITTED",
            content_sha256="33" * 32,
            owner_user_id=reporter_authority.actor_user_id,
            reportable_until=NOW + timedelta(days=7),
            reporter_party_marker_sha256="34" * 32,
            target_marker_sha256="44" * 32,
        )

    def check_officer_conflict(
        self,
        *,
        officer_authority: TrustOfficerAuthority,
        operation: str,
        organization_id: str,
        demand_id: str,
        demand_version_id: str,
    ) -> TrustOfficerConflictCheck:
        assert operation in {"CLAIM_CASE", "CLAIM_HOLD_RELEASE"}
        officer_user_id = officer_authority.actor_user_id
        assert (organization_id, demand_id, demand_version_id) == (
            ORGANIZATION_ID,
            DEMAND_ID,
            DEMAND_VERSION_ID,
        )
        return TrustOfficerConflictCheck(
            officer_user_id=officer_user_id,
            organization_id=organization_id,
            demand_id=demand_id,
            demand_version_id=demand_version_id,
            conflict_free=True,
            conflict_attestation_sha256="55" * 32,
            evaluated_at=NOW,
            valid_until=NOW + timedelta(minutes=10),
        )


class SealedNotesFake:
    def __init__(self) -> None:
        self.raw_notes: list[str] = []
        self.unavailable = False

    def seal(
        self,
        *,
        case_id: str,
        actor_user_id: str,
        purpose: str,
        raw_note: str,
        idempotency_key_digest: str,
    ) -> TrustSealedNote:
        assert purpose == "TRIAGE_DRAFT"
        assert case_id and actor_user_id and idempotency_key_digest
        if self.unavailable:
            raise RuntimeError("sealed note unavailable")
        self.raw_notes.append(raw_note)
        return TrustSealedNote(
            sealed_note_reference=f"sealed://trust/triage-note-{len(self.raw_notes)}",
            sealed_note_sha256=hashlib.sha256(raw_note.encode("utf-8")).hexdigest(),
            retention_class="TRUST_CASE_NOTE",
            sealed_at=NOW,
        )


class DecisionEvidenceFake:
    def __init__(self) -> None:
        self.calls = 0
        self.unavailable = False

    def prepare_initial_outcome(
        self,
        *,
        officer_authority: TrustOfficerAuthority,
        case: SafetyCase,
        report: Any,
        triage: Any,
        active_holds: Tuple[SafetyHold, ...],
        outcome: TrustCaseOutcome,
        reason_codes: Tuple[str, ...],
        action_codes: Tuple[HoldAction, ...],
        now: datetime,
    ) -> TrustInitialOutcomeEvidence:
        assert officer_authority.actor_user_id == OFFICER_ID
        assert report.case_id == case.case_id
        assert triage.case_id == case.case_id
        assert all(hold.case_id == case.case_id for hold in active_holds)
        if self.unavailable:
            raise RuntimeError("outcome evidence unavailable")
        self.calls += 1
        return TrustInitialOutcomeEvidence(
            case_id=case.case_id,
            case_aggregate_version=case.aggregate_version,
            triage_version=triage.version,
            outcome_code=outcome.value,
            reason_codes=reason_codes,
            action_codes=tuple(value.value for value in action_codes),
            evidence_packet_version_id=_uuid(70),
            evidence_packet_digest="77" * 32,
            source_digest="78" * 32,
            appeal_eligible=True,
            appeal_eligibility_code="ELIGIBLE",
            appeal_deadline=now + timedelta(days=7),
            policy_version="trust-case-outcome-v1",
            redaction_profile_code="PARTY_SAFE_V1",
            evaluated_at=now,
            valid_until=now + timedelta(minutes=10),
        )


class MemoryStore:
    def __init__(self) -> None:
        self.data: dict[str, dict[str, Any]] = {}

    def snapshot(self) -> Mapping[str, Mapping[str, Any]]:
        return deepcopy(self.data)


class MemoryUnitOfWork:
    def __init__(self, factory: "MemoryUnitOfWorkFactory") -> None:
        self._factory = factory
        self._staged = deepcopy(factory.store.data)
        self.checkpoints: list[str] = []
        self.locks: list[tuple[str, Tuple[str, ...]]] = []
        self.committed = False

    def lock(self, resource: str, keys: Sequence[str]) -> None:
        self.locks.append((resource, tuple(keys)))

    def get(self, collection: str, key: str) -> Any:
        return self._staged.get(collection, {}).get(key)

    def values(self, collection: str) -> Tuple[Any, ...]:
        return tuple(self._staged.get(collection, {}).values())

    def put(
        self,
        collection: str,
        key: str,
        value: Any,
        *,
        checkpoint: str,
    ) -> None:
        self.checkpoints.append(checkpoint)
        self._staged.setdefault(collection, {})[key] = value

    def commit(self) -> None:
        assert not self.committed
        self._factory.store.data = self._staged
        self._factory.committed_checkpoints.append(tuple(self.checkpoints))
        self.committed = True


class MemoryUnitOfWorkFactory:
    def __init__(self) -> None:
        self.store = MemoryStore()
        self.committed_checkpoints: list[Tuple[str, ...]] = []

    @contextmanager
    def begin(self) -> Iterator[MemoryUnitOfWork]:
        uow = MemoryUnitOfWork(self)
        yield uow


class Harness:
    def __init__(self) -> None:
        self.clock = FixedClock()
        self.ids = SequenceIds()
        self.keyring = TestKeyring()
        self.authority = AuthorityFake()
        self.target = TargetFake()
        self.sealed_notes = SealedNotesFake()
        self.decision_evidence = DecisionEvidenceFake()
        self.uows = MemoryUnitOfWorkFactory()

    def handler(self, handler_type: type[Any]) -> Any:
        return handler_type(
            authority=self.authority,
            target=self.target,
            sealed_notes=self.sealed_notes,
            decision_evidence=self.decision_evidence,
            uow_factory=self.uows,
            clock=self.clock,
            id_source=self.ids,
            receipt_keyring=self.keyring,
            assignment_ttl_minutes=240,
            hold_policy_version="trust-demand-hold-v1",
            outcome_policy_version="trust-case-outcome-v1",
        )


def _reporter() -> TrustActorContext:
    return TrustActorContext(
        actor_user_id=REPORTER_ID,
        session_id=SESSION_ID,
        organization_id=ORGANIZATION_ID,
        correlation_id=_uuid(30),
        causation_id=_uuid(31),
        trace_id=_uuid(36),
        original_actor_user_id=None,
    )


def _officer() -> TrustActorContext:
    return TrustActorContext(
        actor_user_id=OFFICER_ID,
        session_id=SESSION_ID,
        organization_id=None,
        correlation_id=_uuid(32),
        causation_id=_uuid(33),
        trace_id=_uuid(37),
        original_actor_user_id=None,
    )


def _other_officer() -> TrustActorContext:
    return TrustActorContext(
        actor_user_id=_uuid(8),
        session_id=SESSION_ID,
        organization_id=None,
        correlation_id=_uuid(34),
        causation_id=_uuid(35),
        trace_id=_uuid(38),
        original_actor_user_id=None,
    )


def _submit(harness: Harness, *, idempotency_key: str = "submit-key") -> Any:
    command = SubmitSafetyReportCommand(
        demand_id=DEMAND_ID,
        demand_version_id=DEMAND_VERSION_ID,
        category=ReportCategory.DATA_EXPOSURE,
        incident_started_at=NOW - timedelta(hours=2),
        incident_ended_at=NOW - timedelta(hours=1),
        impact_codes=("SYNTHETIC_DATA_DISCLOSED",),
        evidence_reference_ids=(_uuid(40),),
        requested_protection_codes=("PAUSE_VERIFICATION",),
        idempotency_key=idempotency_key,
    )
    return harness.handler(SubmitSafetyReportHandler).handle(
        actor=_reporter(), command=command
    )


def _claim(harness: Harness, case_id: str, expected_version: int = 1) -> Any:
    return harness.handler(ClaimSafetyCaseHandler).handle(
        actor=_officer(),
        command=ClaimSafetyCaseCommand(
            case_id=case_id,
            expected_case_version=expected_version,
            idempotency_key=f"claim-{case_id}-{expected_version}",
        ),
    )


def _save_triage(
    harness: Harness,
    case_id: str,
    *,
    expected_version: int = 2,
    restricted_note: str = "Restricted synthetic triage observation",
    idempotency_key: str = "save-triage-key",
) -> Any:
    return harness.handler(SaveTrustTriageDraftHandler).handle(
        actor=_officer(),
        command=SaveTrustTriageDraftCommand(
            case_id=case_id,
            expected_case_version=expected_version,
            priority_code="P1",
            jurisdiction_code="PLATFORM_INTERNAL",
            severity_code="HIGH",
            issue_codes=("DATA_HANDLING_GAP",),
            investigation_step_codes=("CHECK_DEMAND_VERSION",),
            proposed_hold_actions=(HoldAction.VERIFY_DEMAND,),
            proposed_hold_ttl_minutes=60,
            restricted_note=restricted_note,
            idempotency_key=idempotency_key,
        ),
    )


def _publish(harness: Harness, case_id: str, expected_version: int = 3) -> Any:
    return harness.handler(PublishTrustTriageHandler).handle(
        actor=_officer(),
        command=PublishTrustTriageCommand(
            case_id=case_id,
            expected_case_version=expected_version,
            expected_draft_version=1,
            idempotency_key="publish-triage-key",
        ),
    )


def test_submit_report_is_receipt_first_atomic_and_exactly_replayable() -> None:
    harness = Harness()

    first = _submit(harness)
    assert first.case_status is SafetyCaseStatus.OPEN
    assert first.aggregate_version == 1
    assert first.report_id is not None
    assert first.replayed is False
    assert first.event_types == ("TrustReportSubmitted",)
    assert harness.uows.committed_checkpoints[-1][0] == "receipt.pending"
    assert isinstance(
        harness.uows.store.data["safety_cases"][first.case_id], SafetyCase
    )
    assert harness.uows.store.data["reports"][first.report_id].demand_version_id == (
        DEMAND_VERSION_ID
    )

    writes_before = len(harness.uows.committed_checkpoints)
    replay = _submit(harness)
    assert replay.replayed is True
    assert replay.case_id == first.case_id
    assert replay.report_id == first.report_id
    assert replay.completed_at == first.completed_at
    assert len(harness.uows.committed_checkpoints) == writes_before


def test_same_idempotency_key_with_changed_payload_is_rejected_without_write() -> None:
    harness = Harness()
    _submit(harness)
    writes_before = len(harness.uows.committed_checkpoints)
    changed = SubmitSafetyReportCommand(
        demand_id=DEMAND_ID,
        demand_version_id=DEMAND_VERSION_ID,
        category=ReportCategory.FRAUD_RISK,
        incident_started_at=NOW - timedelta(hours=2),
        incident_ended_at=NOW - timedelta(hours=1),
        impact_codes=("SYNTHETIC_DATA_DISCLOSED",),
        evidence_reference_ids=(_uuid(40),),
        requested_protection_codes=("PAUSE_VERIFICATION",),
        idempotency_key="submit-key",
    )

    with pytest.raises(TrustApplicationError) as raised:
        harness.handler(SubmitSafetyReportHandler).handle(
            actor=_reporter(), command=changed
        )
    assert raised.value.code == "IDEMPOTENCY_KEY_REUSED"
    assert len(harness.uows.committed_checkpoints) == writes_before


def test_retained_receipt_keys_replay_without_external_calls_or_new_writes() -> None:
    harness = Harness()
    first = _submit(harness)
    writes_before = len(harness.uows.committed_checkpoints)
    harness.keyring.idempotency_key_digest_key_ids = (
        "TRUST_IDEMPOTENCY_V2",
        "TRUST_IDEMPOTENCY_V1",
    )
    harness.keyring.payload_hash_key_ids = (
        "TRUST_PAYLOAD_HASH_V2",
        "TRUST_PAYLOAD_HASH_V1",
    )

    replay = _submit(harness)

    assert replay.replayed is True
    assert replay.case_id == first.case_id
    assert len(harness.uows.committed_checkpoints) == writes_before


def test_claim_checks_occ_and_binds_exact_conflict_and_duty_facts() -> None:
    harness = Harness()
    submitted = _submit(harness)

    with pytest.raises(TrustApplicationError) as raised:
        _claim(harness, submitted.case_id, expected_version=9)
    assert raised.value.code == "PRECONDITION_FAILED"

    claimed = _claim(harness, submitted.case_id)
    assert claimed.case_status is SafetyCaseStatus.TRIAGING
    assert claimed.aggregate_version == 2
    assignment = harness.uows.store.data["case_assignments"][claimed.assignment_id]
    assert assignment.duty_grant_version == 7
    assert assignment.conflict_attestation_sha256 == "55" * 32
    assert harness.uows.committed_checkpoints[-1][0] == "receipt.pending"


def test_assignment_can_be_released_or_recovered_without_naming_next_officer() -> None:
    harness = Harness()
    submitted = _submit(harness)
    claimed = _claim(harness, submitted.case_id)
    released = harness.handler(ReleaseSafetyCaseAssignmentHandler).handle(
        actor=_officer(),
        command=ReleaseSafetyCaseAssignmentCommand(
            case_id=submitted.case_id,
            expected_case_version=2,
            reason_code=AssignmentReleaseReason.CONFLICT_DECLARED,
            idempotency_key="release-assignment-key",
        ),
    )
    assert released.case_status is SafetyCaseStatus.OPEN
    assert released.aggregate_version == 3
    assert released.assignment_id == claimed.assignment_id
    stored_release = harness.uows.store.data["assignment_releases"][
        claimed.assignment_id
    ]
    assert stored_release.reason_code is AssignmentReleaseReason.CONFLICT_DECLARED
    assert harness.uows.store.data["safety_cases"][submitted.case_id].assignment_id is None
    assert harness.uows.committed_checkpoints[-1][0] == "receipt.pending"

    reclaimed = _claim(harness, submitted.case_id, expected_version=3)
    assert reclaimed.aggregate_version == 4
    writes_before = len(harness.uows.committed_checkpoints)
    harness.clock.value = NOW + timedelta(hours=3, minutes=59)
    with pytest.raises(TrustApplicationError) as raised:
        harness.handler(ReleaseSafetyCaseAssignmentHandler).handle(
            actor=_other_officer(),
            command=ReleaseSafetyCaseAssignmentCommand(
                case_id=submitted.case_id,
                expected_case_version=4,
                reason_code=AssignmentReleaseReason.ASSIGNMENT_EXPIRED,
                idempotency_key="recover-too-early-key",
            ),
        )
    assert raised.value.code == "ASSIGNMENT_NOT_EXPIRED"
    assert len(harness.uows.committed_checkpoints) == writes_before

    harness.clock.value = NOW + timedelta(hours=4)
    recovered = harness.handler(ReleaseSafetyCaseAssignmentHandler).handle(
        actor=_other_officer(),
        command=ReleaseSafetyCaseAssignmentCommand(
            case_id=submitted.case_id,
            expected_case_version=4,
            reason_code=AssignmentReleaseReason.ASSIGNMENT_EXPIRED,
            idempotency_key="recover-expired-key",
        ),
    )
    assert recovered.case_status is SafetyCaseStatus.OPEN
    assert recovered.aggregate_version == 5
    assert recovered.assignment_id == reclaimed.assignment_id


def test_restricted_note_is_sealed_and_never_persisted_in_receipt_audit_or_outbox() -> None:
    harness = Harness()
    submitted = _submit(harness)
    _claim(harness, submitted.case_id)
    restricted_note = "private restricted note: do not leak"
    command = SaveTrustTriageDraftCommand(
        case_id=submitted.case_id,
        expected_case_version=2,
        priority_code="P1",
        jurisdiction_code="PLATFORM_INTERNAL",
        severity_code="HIGH",
        issue_codes=("DATA_HANDLING_GAP",),
        investigation_step_codes=("CHECK_DEMAND_VERSION",),
        proposed_hold_actions=(HoldAction.VERIFY_DEMAND,),
        proposed_hold_ttl_minutes=60,
        restricted_note=restricted_note,
        idempotency_key="save-private-note",
    )

    assert restricted_note not in repr(command)
    saved = harness.handler(SaveTrustTriageDraftHandler).handle(
        actor=_officer(), command=command
    )
    assert saved.triage_draft_version == 1
    assert harness.sealed_notes.raw_notes == [restricted_note]
    draft = next(iter(harness.uows.store.data["triage_drafts"].values()))
    assert draft.sealed_note_reference == "sealed://trust/triage-note-1"
    for collection in ("command_receipts", "audit_events", "outbox_events"):
        assert restricted_note not in repr(harness.uows.store.data[collection])
    assert harness.uows.committed_checkpoints[-1][0] == "receipt.pending"

    seal_count = len(harness.sealed_notes.raw_notes)
    harness.sealed_notes.unavailable = True
    replay = harness.handler(SaveTrustTriageDraftHandler).handle(
        actor=_officer(), command=command
    )
    assert replay.replayed is True
    assert len(harness.sealed_notes.raw_notes) == seal_count

    changed_note = SaveTrustTriageDraftCommand(
        **{
            **command.__dict__,
            "restricted_note": "different private note",
        }
    )
    with pytest.raises(TrustApplicationError) as raised:
        harness.handler(SaveTrustTriageDraftHandler).handle(
            actor=_officer(), command=changed_note
        )
    assert raised.value.code == "IDEMPOTENCY_KEY_REUSED"
    assert len(harness.sealed_notes.raw_notes) == seal_count


def test_publish_hold_release_and_outcome_form_one_occ_chain() -> None:
    harness = Harness()
    submitted = _submit(harness)
    _claim(harness, submitted.case_id)
    _save_triage(harness, submitted.case_id)
    published = _publish(harness, submitted.case_id)
    assert published.case_status is SafetyCaseStatus.IN_REVIEW
    assert published.aggregate_version == 4
    assert published.triage_version == 1

    placed = harness.handler(PlaceSafetyHoldHandler).handle(
        actor=_officer(),
        command=PlaceSafetyHoldCommand(
            case_id=submitted.case_id,
            expected_case_version=4,
            action_codes=(HoldAction.VERIFY_DEMAND,),
            reason_code=HoldReason.WORKFLOW_INTEGRITY_RISK,
            hold_ttl_minutes=60,
            idempotency_key="place-hold-key",
        ),
    )
    assert placed.aggregate_version == 5
    hold = harness.uows.store.data["safety_holds"][placed.hold_id]
    assert isinstance(hold, SafetyHold)
    assert hold.status is SafetyHoldStatus.ACTIVE
    assert hold.policy_version == "trust-demand-hold-v1"

    with pytest.raises(TrustApplicationError) as raised:
        harness.handler(ReleaseSafetyHoldHandler).handle(
            actor=_officer(),
            command=ReleaseSafetyHoldCommand(
                hold_id=placed.hold_id,
                expected_hold_version=9,
                release_reason_code="RISK_MITIGATED",
                idempotency_key="stale-release-key",
            ),
        )
    assert raised.value.code == "PRECONDITION_FAILED"

    released = harness.handler(ReleaseSafetyHoldHandler).handle(
        actor=_officer(),
        command=ReleaseSafetyHoldCommand(
            hold_id=placed.hold_id,
            expected_hold_version=1,
            release_reason_code="RISK_MITIGATED",
            idempotency_key="release-hold-key",
        ),
    )
    assert released.aggregate_version == 6
    assert released.hold_version == 2
    assert harness.uows.store.data["safety_holds"][placed.hold_id].status is (
        SafetyHoldStatus.RELEASED
    )

    outcome_command = PublishTrustOutcomeCommand(
        case_id=submitted.case_id,
        expected_case_version=6,
        outcome_code=TrustCaseOutcome.PROTECTION_MODIFIED,
        reason_codes=("RISK_MITIGATED",),
        action_codes=(HoldAction.VERIFY_DEMAND,),
        idempotency_key="publish-outcome-key",
    )
    outcome = harness.handler(PublishTrustOutcomeHandler).handle(
        actor=_officer(),
        command=outcome_command,
    )
    assert outcome.case_status is SafetyCaseStatus.DECIDED
    assert outcome.aggregate_version == 7
    assert outcome.outcome_version_id is not None
    stored = harness.uows.store.data["case_outcomes"][
        outcome.outcome_version_id
    ]
    assert stored.policy_version == "trust-case-outcome-v1"
    assert stored.appeal_deadline == NOW + timedelta(days=7)
    assert stored.evidence_packet_digest == "77" * 32
    assert stored.source_digest == "78" * 32
    assert harness.decision_evidence.calls == 1
    writes_before = len(harness.uows.committed_checkpoints)
    harness.decision_evidence.unavailable = True
    replay = harness.handler(PublishTrustOutcomeHandler).handle(
        actor=_officer(), command=outcome_command
    )
    assert replay.replayed is True
    assert replay.outcome_version_id == outcome.outcome_version_id
    assert harness.decision_evidence.calls == 1
    assert len(harness.uows.committed_checkpoints) == writes_before
    assert all(
        checkpoints[0] == "receipt.pending"
        for checkpoints in harness.uows.committed_checkpoints
    )


def test_high_risk_hold_requires_server_derived_independent_assignment() -> None:
    harness = Harness()
    submitted = _submit(harness)
    _claim(harness, submitted.case_id)
    _save_triage(harness, submitted.case_id)
    _publish(harness, submitted.case_id)
    placed = harness.handler(PlaceSafetyHoldHandler).handle(
        actor=_officer(),
        command=PlaceSafetyHoldCommand(
            case_id=submitted.case_id,
            expected_case_version=4,
            action_codes=(HoldAction.VERIFY_DEMAND,),
            reason_code=HoldReason.PARTICIPANT_SAFETY_RISK,
            hold_ttl_minutes=60,
            idempotency_key="place-high-risk-hold",
        ),
    )

    with pytest.raises(TrustApplicationError) as raised:
        harness.handler(ReleaseSafetyHoldHandler).handle(
            actor=_officer(),
            command=ReleaseSafetyHoldCommand(
                hold_id=placed.hold_id,
                expected_hold_version=1,
                release_reason_code="RISK_MITIGATED",
                idempotency_key="self-release-high-risk",
            ),
        )
    assert raised.value.code == "INDEPENDENT_REVIEW_REQUIRED"

    with pytest.raises(TrustApplicationError) as raised:
        harness.handler(ClaimSafetyHoldReleaseHandler).handle(
            actor=_officer(),
            command=ClaimSafetyHoldReleaseCommand(
                hold_id=placed.hold_id,
                expected_hold_version=1,
                idempotency_key="issuer-cannot-claim-release",
            ),
        )
    assert raised.value.code == "INDEPENDENT_REVIEW_REQUIRED"

    claimed = harness.handler(ClaimSafetyHoldReleaseHandler).handle(
        actor=_other_officer(),
        command=ClaimSafetyHoldReleaseCommand(
            hold_id=placed.hold_id,
            expected_hold_version=1,
            idempotency_key="claim-independent-release",
        ),
    )
    independent = harness.uows.store.data["hold_release_assignments"][
        claimed.assignment_id
    ]
    assert isinstance(independent, SafetyHoldReleaseAssignment)
    assert independent.officer_user_id == _uuid(8)
    assert claimed.hold_version == 2

    released = harness.handler(ReleaseSafetyHoldHandler).handle(
        actor=_other_officer(),
        command=ReleaseSafetyHoldCommand(
            hold_id=placed.hold_id,
            expected_hold_version=2,
            release_reason_code="RISK_MITIGATED",
            idempotency_key="independent-release-high-risk",
        ),
    )
    assert released.aggregate_version == 6
    assert released.hold_version == 3
    assert harness.uows.store.data["safety_holds"][placed.hold_id].status is (
        SafetyHoldStatus.RELEASED
    )


def test_command_dtos_are_frozen_and_hide_secret_inputs_from_repr() -> None:
    command = SaveTrustTriageDraftCommand(
        case_id=_uuid(80),
        expected_case_version=2,
        priority_code="P2",
        jurisdiction_code="PLATFORM_INTERNAL",
        severity_code="MEDIUM",
        issue_codes=("DATA_HANDLING_GAP",),
        investigation_step_codes=("CHECK_ACCESS_SCOPE",),
        proposed_hold_actions=(HoldAction.VERIFY_DEMAND,),
        proposed_hold_ttl_minutes=30,
        restricted_note="raw-secret",
        idempotency_key="idempotency-secret",
    )
    assert "raw-secret" not in repr(command)
    assert "idempotency-secret" not in repr(command)
    with pytest.raises(FrozenInstanceError):
        command.priority_code = "P0"  # type: ignore[misc]

    with pytest.raises(TypeError):
        PublishTrustOutcomeCommand(
            case_id=_uuid(81),
            expected_case_version=4,
            outcome_code=TrustCaseOutcome.NO_ACTION,
            reason_codes=("NO_POLICY_BREACH",),
            action_codes=(),
            idempotency_key="outcome-key",
            appeal_eligible=True,  # type: ignore[call-arg]
        )


def test_application_paths_and_reportable_statuses_match_the_machine_contract() -> None:
    assert handlers_module._CANONICAL_PATHS["claim_case"] == (
        "/v1/app/trust/queue/{case_id}/claim"
    )
    assert handlers_module._CANONICAL_PATHS["publish_triage"] == (
        "/v1/app/trust/cases/{case_id}/triage-publish"
    )
    assert handlers_module._CANONICAL_PATHS["publish_outcome"] == (
        "/v1/app/trust/cases/{case_id}/decisions"
    )
    assert handlers_module._CANONICAL_PATHS["claim_hold_release"] == (
        "/v1/app/trust/hold-release-queue/{hold_id}/claim"
    )
    assert handlers_module._REPORTABLE_DEMAND_STATUSES == frozenset(
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
