from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from typing import Any, Iterator, Mapping, Sequence, Tuple
from uuid import UUID

import pytest

from desire_platform.trust_safety.application import (
    ClaimAppealCommand,
    ClaimAppealHandler,
    DecideAppealCommand,
    DecideAppealHandler,
    OpenAppealCommand,
    OpenAppealHandler,
    ReleaseAppealAssignmentCommand,
    ReleaseAppealAssignmentHandler,
    SaveAppealDraftCommand,
    SaveAppealDraftHandler,
    SaveAppealReviewDraftCommand,
    SaveAppealReviewDraftHandler,
    SubmitAppealCommand,
    SubmitAppealHandler,
    TrustActorContext,
)
from desire_platform.trust_safety.application.appeal_handlers import (
    AppealApplicationError,
)
from desire_platform.trust_safety.domain import (
    Appeal,
    AppealAssignmentReleaseReason,
    AppealDecisionCode,
    AppealGround,
    AppealGroundAssessment,
    AppealGroundAssessmentCode,
    AppealStatus,
    RequestedAppealOutcome,
    TrustCaseOutcomeSource,
)
from desire_platform.trust_safety.ports import (
    AppealApplicantAuthority,
    AppealApplicantSource,
    AppealApplicationDraftProjection,
    AppealAssessmentProjection,
    AppealAssignedProjection,
    AppealCommitOutcomeUnknownError,
    AppealDecisionProjection,
    AppealDecisionPolicy,
    AppealOwnProjection,
    AppealQueueItem,
    AppealQueueProjection,
    AppealReviewDraftProjection,
    AppealReviewerAuthority,
    AppealReviewerConflictCheck,
    AppealSealedText,
    AppealSourceProjection,
    AppealSubmittedApplicationProjection,
    ReadOwnAppealQuery,
)


NOW = datetime(2026, 8, 18, 8, 0, tzinfo=timezone.utc)


def _id(number: int) -> str:
    return str(UUID(int=number))


APPLICANT_ID = _id(1)
REVIEWER_ID = _id(2)
SESSION_ID = _id(3)
ORGANIZATION_ID = _id(4)
OUTCOME_ID = _id(5)
CASE_ID = _id(6)
DEMAND_ID = _id(7)
DEMAND_VERSION_ID = _id(8)


def _source() -> TrustCaseOutcomeSource:
    return TrustCaseOutcomeSource(
        outcome_version_id=OUTCOME_ID,
        case_id=CASE_ID,
        organization_id=ORGANIZATION_ID,
        demand_id=DEMAND_ID,
        demand_version_id=DEMAND_VERSION_ID,
        outcome_code="PROTECTION_MODIFIED",
        reason_codes=("POLICY_REQUIREMENT_NOT_MET",),
        action_codes=("VERIFY_DEMAND",),
        evidence_packet_version_id=_id(9),
        evidence_packet_sha256="11" * 32,
        policy_version="trust-case-outcome-v1",
        decided_at=NOW - timedelta(days=1),
        appeal_eligible=True,
        appeal_eligibility_code="ELIGIBLE",
        appeal_deadline=NOW + timedelta(days=7),
        content_sha256="22" * 32,
    )


class FixedClock:
    def __init__(self) -> None:
        self.value = NOW

    def now(self) -> datetime:
        return self.value


class SequenceIds:
    def __init__(self) -> None:
        self.value = 100
        self.kinds: list[str] = []

    def new_id(self, kind: str) -> str:
        self.kinds.append(kind)
        value = _id(self.value)
        self.value += 1
        return value


class Keyring:
    idempotency_key_digest_key_ids = ("APPEAL_IDEMPOTENCY_V1",)
    payload_hash_key_ids = ("APPEAL_PAYLOAD_V1",)

    @staticmethod
    def keyed_digest(key_id: str, value: bytes) -> str:
        return hmac.new(key_id.encode("ascii"), value, hashlib.sha256).hexdigest()


class Authority:
    def __init__(self) -> None:
        self.operations: list[str] = []
        self.reviewer_duty_grant_id = _id(22)
        self.reviewer_duty_grant_version = 4

    def authorize_applicant(self, *, actor, operation, organization_id):
        self.operations.append(operation)
        assert operation in {
            "OPEN_APPEAL",
            "SAVE_APPEAL_DRAFT",
            "SUBMIT_APPEAL",
        }
        return AppealApplicantAuthority(
            actor_user_id=actor.actor_user_id,
            session_id=actor.session_id,
            organization_id=organization_id,
            user_status="ACTIVE",
            session_status="ACTIVE",
            session_family_status="ACTIVE",
            organization_status="ACTIVE",
            membership_id=_id(20),
            membership_status="ACTIVE",
            membership_role_grant_id=_id(21),
            membership_role_grant_version=3,
            role_code="DEMAND_OWNER",
            policy_requirements_satisfied=True,
            authority_marker_sha256="33" * 32,
        )

    def authorize_reviewer(self, *, actor, operation):
        self.operations.append(operation)
        assert operation in {
            "CLAIM_APPEAL",
            "RELEASE_APPEAL_ASSIGNMENT",
            "SAVE_APPEAL_REVIEW_DRAFT",
            "DECIDE_APPEAL",
        }
        return AppealReviewerAuthority(
            actor_user_id=actor.actor_user_id,
            session_id=actor.session_id,
            user_status="ACTIVE",
            session_status="ACTIVE",
            session_family_status="ACTIVE",
            duty_grant_id=self.reviewer_duty_grant_id,
            duty_grant_version=self.reviewer_duty_grant_version,
            duty_expires_at=NOW + timedelta(days=1),
            duty_code="APPEAL_REVIEWER",
            authority_marker_sha256="44" * 32,
        )


class Sources:
    def __init__(self) -> None:
        self.calls = 0

    def resolve_applicant_source(
        self, *, applicant_authority, source_outcome_version_id
    ):
        self.calls += 1
        assert source_outcome_version_id == OUTCOME_ID
        return AppealApplicantSource(
            applicant_user_id=applicant_authority.actor_user_id,
            organization_id=applicant_authority.organization_id,
            source=_source(),
            applicant_is_party=True,
            applicant_party_marker_sha256="55" * 32,
            evaluated_at=NOW,
            valid_until=NOW + timedelta(minutes=10),
        )


class Conflicts:
    def __init__(self) -> None:
        self.calls = 0
        self.conflict_free = True

    def check_reviewer_conflict(
        self, *, reviewer_authority, source, appeal_id, applicant_user_id
    ):
        self.calls += 1
        assert reviewer_authority.actor_user_id != applicant_user_id
        return AppealReviewerConflictCheck(
            appeal_id=appeal_id,
            source_outcome_version_id=source.outcome_version_id,
            source_case_id=source.case_id,
            reviewer_user_id=reviewer_authority.actor_user_id,
            duty_grant_id=reviewer_authority.duty_grant_id,
            duty_grant_version=reviewer_authority.duty_grant_version,
            conflict_free=self.conflict_free,
            conflict_marker_sha256="66" * 32,
            evaluated_at=NOW,
            valid_until=NOW + timedelta(minutes=10),
        )


class Sealer:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def seal(
        self,
        *,
        appeal_id,
        actor_user_id,
        purpose,
        raw_text,
        idempotency_key_digest,
    ):
        assert appeal_id and actor_user_id and idempotency_key_digest
        self.calls.append((purpose, raw_text))
        return AppealSealedText(
            sealed_reference=(
                f"sealed://trust/appeal/{purpose.lower()}-{len(self.calls)}"
            ),
            sealed_sha256=hashlib.sha256(raw_text.encode()).hexdigest(),
            retention_class="APPEAL_RESTRICTED_TEXT",
            sealed_at=NOW,
        )


class Policies:
    def __init__(self) -> None:
        self.calls = 0

    def resolve_decision_policy(
        self,
        *,
        reviewer_authority,
        appeal,
        decision_code,
        now,
    ):
        self.calls += 1
        return AppealDecisionPolicy(
            appeal_id=appeal.appeal_id,
            appeal_aggregate_version=appeal.aggregate_version,
            source_outcome_version_id=appeal.source.outcome_version_id,
            review_draft_version=appeal.current_review_draft_version,
            decision_code=decision_code.value,
            policy_version="appeal-decision-v1",
            policy_marker_sha256="77" * 32,
            evaluated_at=now,
            valid_until=now + timedelta(minutes=10),
        )


class MemoryStore:
    def __init__(self) -> None:
        self.data: dict[str, dict[str, Any]] = {}

    def snapshot(self) -> Mapping[str, Mapping[str, Any]]:
        return deepcopy(self.data)


class MemoryUow:
    def __init__(self, factory: "Uows") -> None:
        self.factory = factory
        self.staged = deepcopy(factory.store.data)
        self.checkpoints: list[str] = []
        self.locks: list[tuple[str, Tuple[str, ...]]] = []

    def lock(self, resource: str, keys: Sequence[str]) -> None:
        self.locks.append((resource, tuple(keys)))

    def get(self, collection: str, key: str) -> Any:
        return self.staged.get(collection, {}).get(key)

    def values(self, collection: str) -> Tuple[Any, ...]:
        return tuple(self.staged.get(collection, {}).values())

    def put(self, collection, key, value, *, checkpoint):
        self.checkpoints.append(checkpoint)
        self.staged.setdefault(collection, {})[key] = value

    def commit(self) -> None:
        self.factory.store.data = self.staged
        self.factory.commits.append(tuple(self.checkpoints))
        if self.factory.outcome_unknown:
            self.factory.outcome_unknown = False
            raise AppealCommitOutcomeUnknownError()


class Uows:
    def __init__(self) -> None:
        self.store = MemoryStore()
        self.commits: list[Tuple[str, ...]] = []
        self.outcome_unknown = False

    @contextmanager
    def begin(self) -> Iterator[MemoryUow]:
        yield MemoryUow(self)


class Harness:
    def __init__(self) -> None:
        self.clock = FixedClock()
        self.ids = SequenceIds()
        self.keys = Keyring()
        self.authority = Authority()
        self.sources = Sources()
        self.conflicts = Conflicts()
        self.sealer = Sealer()
        self.policies = Policies()
        self.uows = Uows()

    def handler(self, handler_type):
        return handler_type(
            authority=self.authority,
            sources=self.sources,
            conflicts=self.conflicts,
            sealed_text=self.sealer,
            decision_policy=self.policies,
            uow_factory=self.uows,
            clock=self.clock,
            id_source=self.ids,
            receipt_keyring=self.keys,
            assignment_ttl_minutes=240,
        )


def _applicant() -> TrustActorContext:
    return TrustActorContext(
        actor_user_id=APPLICANT_ID,
        session_id=SESSION_ID,
        organization_id=ORGANIZATION_ID,
        correlation_id=_id(30),
        causation_id=_id(31),
        trace_id=_id(32),
        original_actor_user_id=None,
    )


def _reviewer() -> TrustActorContext:
    return TrustActorContext(
        actor_user_id=REVIEWER_ID,
        session_id=SESSION_ID,
        organization_id=None,
        correlation_id=_id(33),
        causation_id=_id(34),
        trace_id=_id(35),
        original_actor_user_id=None,
    )


def _open(harness: Harness, *, idempotency_key="appeal-open-key-1"):
    return harness.handler(OpenAppealHandler).handle(
        actor=_applicant(),
        command=OpenAppealCommand(
            source_outcome_version_id=OUTCOME_ID,
            idempotency_key=idempotency_key,
        ),
    )


def _save_application(
    harness: Harness,
    appeal_id: str,
    *,
    expected_version=1,
    raw_statement="private applicant statement",
    idempotency_key="appeal-draft-key",
):
    return harness.handler(SaveAppealDraftHandler).handle(
        actor=_applicant(),
        command=SaveAppealDraftCommand(
            appeal_id=appeal_id,
            expected_appeal_version=expected_version,
            grounds=(AppealGround.PROCEDURAL_ERROR,),
            requested_outcome=RequestedAppealOutcome.MODIFY_MEASURE,
            applicant_statement=raw_statement,
            new_evidence_reference_ids=(),
            idempotency_key=idempotency_key,
        ),
    )


def _submit(harness: Harness, appeal_id: str, expected_version=2):
    return harness.handler(SubmitAppealHandler).handle(
        actor=_applicant(),
        command=SubmitAppealCommand(
            appeal_id=appeal_id,
            expected_appeal_version=expected_version,
            expected_draft_version=1,
            idempotency_key="appeal-submit-key",
        ),
    )


def _claim(harness: Harness, appeal_id: str, expected_version=3):
    return harness.handler(ClaimAppealHandler).handle(
        actor=_reviewer(),
        command=ClaimAppealCommand(
            appeal_id=appeal_id,
            expected_appeal_version=expected_version,
            idempotency_key="appeal-claim-key",
        ),
    )


def test_open_is_receipt_first_and_retained_exact_replay_precedes_source_and_ids():
    harness = Harness()
    first = _open(harness)
    assert first.appeal_status is AppealStatus.DRAFT
    assert first.aggregate_version == 1
    assert first.event_types == ("AppealOpened",)
    assert harness.uows.commits[-1][0] == "receipt.pending"
    assert isinstance(harness.uows.store.data["appeals"][first.appeal_id], Appeal)
    calls = harness.sources.calls
    id_count = len(harness.ids.kinds)
    writes = len(harness.uows.commits)
    harness.keys.idempotency_key_digest_key_ids = (
        "APPEAL_IDEMPOTENCY_V2",
        "APPEAL_IDEMPOTENCY_V1",
    )
    harness.keys.payload_hash_key_ids = (
        "APPEAL_PAYLOAD_V2",
        "APPEAL_PAYLOAD_V1",
    )

    replay = _open(harness)

    assert replay.replayed is True
    assert replay.appeal_id == first.appeal_id
    assert harness.sources.calls == calls
    assert len(harness.ids.kinds) == id_count
    assert len(harness.uows.commits) == writes


def test_raw_statement_is_hidden_sealed_after_replay_and_absent_from_all_durable_records():
    harness = Harness()
    opened = _open(harness)
    raw = "restricted applicant statement: never persist"
    command = SaveAppealDraftCommand(
        appeal_id=opened.appeal_id,
        expected_appeal_version=1,
        grounds=(AppealGround.PROCEDURAL_ERROR,),
        requested_outcome=RequestedAppealOutcome.MODIFY_MEASURE,
        applicant_statement=raw,
        new_evidence_reference_ids=(),
        idempotency_key="appeal-draft-key",
    )
    assert raw not in repr(command)

    first = harness.handler(SaveAppealDraftHandler).handle(
        actor=_applicant(), command=command
    )
    assert first.event_types == ("AppealApplicationDraftSaved",)
    assert harness.sealer.calls == [("APPLICATION_STATEMENT", raw)]
    durable = repr(harness.uows.store.data)
    assert raw not in durable
    assert "sealed://" not in repr(
        harness.uows.store.data["appeal_command_receipts"]
    )
    assert raw not in repr(harness.uows.store.data["audit_events"])
    assert raw not in repr(harness.uows.store.data["outbox_events"])

    calls = len(harness.sealer.calls)
    replay = harness.handler(SaveAppealDraftHandler).handle(
        actor=_applicant(), command=command
    )
    assert replay.replayed is True
    assert len(harness.sealer.calls) == calls

    changed = SaveAppealDraftCommand(
        **{
            **command.__dict__,
            "applicant_statement": "changed private statement",
        }
    )
    with pytest.raises(AppealApplicationError) as raised:
        harness.handler(SaveAppealDraftHandler).handle(
            actor=_applicant(), command=changed
        )
    assert raised.value.code == "IDEMPOTENCY_KEY_REUSED"
    assert len(harness.sealer.calls) == calls


def test_seven_write_handlers_apply_occ_conflict_assignment_and_atomic_events():
    harness = Harness()
    opened = _open(harness)
    saved = _save_application(harness, opened.appeal_id)
    submitted = _submit(harness, opened.appeal_id)
    claimed = _claim(harness, opened.appeal_id)
    assert (
        opened.aggregate_version,
        saved.aggregate_version,
        submitted.aggregate_version,
        claimed.aggregate_version,
    ) == (1, 2, 3, 4)
    assignment = next(iter(harness.uows.store.data["appeal_assignments"].values()))
    assert assignment.reviewer_user_id == REVIEWER_ID
    assert assignment.conflict_attestation_sha256 == "66" * 32

    review_note = "private reviewer note"
    reviewed = harness.handler(SaveAppealReviewDraftHandler).handle(
        actor=_reviewer(),
        command=SaveAppealReviewDraftCommand(
            appeal_id=opened.appeal_id,
            expected_appeal_version=4,
            assessments=(
                AppealGroundAssessment(
                    ground=AppealGround.PROCEDURAL_ERROR,
                    assessment_code=AppealGroundAssessmentCode.ACCEPTED,
                    finding_codes=("PROCEDURE_MATERIAL_ERROR",),
                    accepted_evidence_reference_ids=(),
                ),
            ),
            reason_codes=("PROCEDURAL_REVIEW_COMPLETE",),
            remedy_delta_codes=("NARROW_CORRECTIVE_MEASURE",),
            reviewer_note=review_note,
            idempotency_key="appeal-review-key",
        ),
    )
    assert reviewed.aggregate_version == 5
    assert review_note not in repr(harness.uows.store.data)
    decided = harness.handler(DecideAppealHandler).handle(
        actor=_reviewer(),
        command=DecideAppealCommand(
            appeal_id=opened.appeal_id,
            expected_appeal_version=5,
            expected_review_draft_version=1,
            decision_code=AppealDecisionCode.MODIFY,
            idempotency_key="appeal-decide-key",
        ),
    )
    assert decided.appeal_status is AppealStatus.DECIDED
    assert decided.aggregate_version == 6
    assert decided.event_types == ("AppealDecisionPublished",)
    assert decided.decision_version_id is not None
    assert all(commit[0] == "receipt.pending" for commit in harness.uows.commits)

    other = Harness()
    opened = _open(other)
    _save_application(other, opened.appeal_id)
    _submit(other, opened.appeal_id)
    _claim(other, opened.appeal_id)
    released = other.handler(ReleaseAppealAssignmentHandler).handle(
        actor=_reviewer(),
        command=ReleaseAppealAssignmentCommand(
            appeal_id=opened.appeal_id,
            expected_appeal_version=4,
            reason_code=AppealAssignmentReleaseReason.CONFLICT_DECLARED,
            idempotency_key="appeal-release-key",
        ),
    )
    assert released.appeal_status is AppealStatus.SUBMITTED
    assert released.event_types == ("AppealReviewAssignmentReleased",)


def test_occ_conflict_and_commit_unknown_recovery_fail_closed():
    harness = Harness()
    opened = _open(harness)
    writes = len(harness.uows.commits)
    with pytest.raises(AppealApplicationError) as raised:
        _save_application(harness, opened.appeal_id, expected_version=99)
    assert raised.value.code == "PRECONDITION_FAILED"
    assert len(harness.uows.commits) == writes

    _save_application(harness, opened.appeal_id)
    _submit(harness, opened.appeal_id)
    harness.conflicts.conflict_free = False
    with pytest.raises(AppealApplicationError) as raised:
        _claim(harness, opened.appeal_id)
    assert raised.value.code == "CONFLICT_OF_INTEREST"

    recovered = Harness()
    recovered.uows.outcome_unknown = True
    result = _open(recovered)
    assert result.appeal_status is AppealStatus.DRAFT
    assert result.replayed is True
    assert len(recovered.uows.store.data["appeals"]) == 1


def test_assignment_precheck_precedes_seal_policy_and_ids_but_not_receipt_replay():
    unassigned = Harness()
    opened = _open(unassigned)
    _save_application(unassigned, opened.appeal_id)
    _submit(unassigned, opened.appeal_id)
    review_command = SaveAppealReviewDraftCommand(
        appeal_id=opened.appeal_id,
        expected_appeal_version=3,
        assessments=(
            AppealGroundAssessment(
                ground=AppealGround.PROCEDURAL_ERROR,
                assessment_code=AppealGroundAssessmentCode.ACCEPTED,
                finding_codes=("PROCEDURE_MATERIAL_ERROR",),
                accepted_evidence_reference_ids=(),
            ),
        ),
        reason_codes=("PROCEDURAL_REVIEW_COMPLETE",),
        remedy_delta_codes=("NARROW_CORRECTIVE_MEASURE",),
        reviewer_note="must not be sealed without assignment",
        idempotency_key="appeal-review-unassigned-key",
    )
    seal_calls = len(unassigned.sealer.calls)
    id_calls = len(unassigned.ids.kinds)
    with pytest.raises(AppealApplicationError) as raised:
        unassigned.handler(SaveAppealReviewDraftHandler).handle(
            actor=_reviewer(), command=review_command
        )
    assert raised.value.code == "APPEAL_ASSIGNMENT_REQUIRED"
    assert len(unassigned.sealer.calls) == seal_calls
    assert len(unassigned.ids.kinds) == id_calls
    with pytest.raises(AppealApplicationError) as raised:
        unassigned.handler(DecideAppealHandler).handle(
            actor=_reviewer(),
            command=DecideAppealCommand(
                appeal_id=opened.appeal_id,
                expected_appeal_version=3,
                expected_review_draft_version=1,
                decision_code=AppealDecisionCode.MODIFY,
                idempotency_key="appeal-decide-unassigned-key",
            ),
        )
    assert raised.value.code == "APPEAL_ASSIGNMENT_REQUIRED"
    assert unassigned.policies.calls == 0

    wrong_duty = Harness()
    opened = _open(wrong_duty)
    _save_application(wrong_duty, opened.appeal_id)
    _submit(wrong_duty, opened.appeal_id)
    _claim(wrong_duty, opened.appeal_id)
    wrong_duty.authority.reviewer_duty_grant_version = 5
    seal_calls = len(wrong_duty.sealer.calls)
    with pytest.raises(AppealApplicationError) as raised:
        wrong_duty.handler(SaveAppealReviewDraftHandler).handle(
            actor=_reviewer(),
            command=SaveAppealReviewDraftCommand(
                **{
                    **review_command.__dict__,
                    "appeal_id": opened.appeal_id,
                    "expected_appeal_version": 4,
                    "idempotency_key": "appeal-review-wrong-duty-key",
                }
            ),
        )
    assert raised.value.code == "APPEAL_ASSIGNMENT_REQUIRED"
    assert len(wrong_duty.sealer.calls) == seal_calls
    id_calls = len(wrong_duty.ids.kinds)
    with pytest.raises(AppealApplicationError) as raised:
        wrong_duty.handler(ReleaseAppealAssignmentHandler).handle(
            actor=_reviewer(),
            command=ReleaseAppealAssignmentCommand(
                appeal_id=opened.appeal_id,
                expected_appeal_version=4,
                reason_code=AppealAssignmentReleaseReason.WORKLOAD_RELEASE,
                idempotency_key="appeal-release-wrong-duty-key",
            ),
        )
    assert raised.value.code == "APPEAL_ASSIGNMENT_REQUIRED"
    assert len(wrong_duty.ids.kinds) == id_calls

    replayed = Harness()
    opened = _open(replayed)
    _save_application(replayed, opened.appeal_id)
    _submit(replayed, opened.appeal_id)
    _claim(replayed, opened.appeal_id)
    command = SaveAppealReviewDraftCommand(
        **{
            **review_command.__dict__,
            "appeal_id": opened.appeal_id,
            "expected_appeal_version": 4,
            "idempotency_key": "appeal-review-replay-key",
        }
    )
    first = replayed.handler(SaveAppealReviewDraftHandler).handle(
        actor=_reviewer(), command=command
    )
    assert first.replayed is False
    seal_calls = len(replayed.sealer.calls)
    replayed.clock.value = NOW + timedelta(minutes=20)
    second = replayed.handler(SaveAppealReviewDraftHandler).handle(
        actor=_reviewer(), command=command
    )
    assert second.replayed is True
    assert len(replayed.sealer.calls) == seal_calls

    expired = Harness()
    opened = _open(expired)
    _save_application(expired, opened.appeal_id)
    _submit(expired, opened.appeal_id)
    _claim(expired, opened.appeal_id)
    expired.clock.value = NOW + timedelta(minutes=10)
    seal_calls = len(expired.sealer.calls)
    with pytest.raises(AppealApplicationError) as raised:
        expired.handler(SaveAppealReviewDraftHandler).handle(
            actor=_reviewer(),
            command=SaveAppealReviewDraftCommand(
                **{
                    **review_command.__dict__,
                    "appeal_id": opened.appeal_id,
                    "expected_appeal_version": 4,
                    "idempotency_key": "appeal-review-expired-key",
                }
            ),
        )
    assert raised.value.code == "APPEAL_ASSIGNMENT_REQUIRED"
    assert len(expired.sealer.calls) == seal_calls
    with pytest.raises(AppealApplicationError) as raised:
        expired.handler(DecideAppealHandler).handle(
            actor=_reviewer(),
            command=DecideAppealCommand(
                appeal_id=opened.appeal_id,
                expected_appeal_version=4,
                expected_review_draft_version=1,
                decision_code=AppealDecisionCode.MODIFY,
                idempotency_key="appeal-decide-expired-key",
            ),
        )
    assert raised.value.code == "APPEAL_ASSIGNMENT_REQUIRED"
    assert expired.policies.calls == 0
    released = expired.handler(ReleaseAppealAssignmentHandler).handle(
        actor=TrustActorContext(
            actor_user_id=_id(200),
            session_id=SESSION_ID,
            organization_id=None,
            correlation_id=_id(201),
            causation_id=_id(202),
            trace_id=_id(203),
            original_actor_user_id=None,
        ),
        command=ReleaseAppealAssignmentCommand(
            appeal_id=opened.appeal_id,
            expected_appeal_version=4,
            reason_code=AppealAssignmentReleaseReason.ASSIGNMENT_EXPIRED,
            idempotency_key="appeal-release-expired-key",
        ),
    )
    assert released.appeal_status is AppealStatus.SUBMITTED


def test_read_dtos_are_frozen_safe_and_own_lookup_has_exactly_one_target():
    with pytest.raises(ValueError, match="APPEAL_READ_QUERY_INVALID"):
        ReadOwnAppealQuery(
            appeal_id=_id(40), source_outcome_version_id=OUTCOME_ID
        )
    query = ReadOwnAppealQuery(
        appeal_id=None, source_outcome_version_id=OUTCOME_ID
    )
    assert query.source_outcome_version_id == OUTCOME_ID
    source = AppealSourceProjection(
        outcome_version_id=OUTCOME_ID,
        case_id=CASE_ID,
        demand_id=DEMAND_ID,
        demand_version_id=DEMAND_VERSION_ID,
        outcome_code="PROTECTION_MODIFIED",
        reason_codes=("POLICY_REQUIREMENT_NOT_MET",),
        action_codes=("VERIFY_DEMAND",),
        evidence_packet_version_id=_id(9),
        evidence_packet_sha256="11" * 32,
        policy_version="trust-case-outcome-v1",
        decided_at=NOW - timedelta(days=1),
        appeal_eligible=True,
        appeal_eligibility_code="ELIGIBLE",
        appeal_deadline=NOW + timedelta(days=7),
        content_sha256="22" * 32,
    )
    draft = AppealApplicationDraftProjection(
        version=1,
        grounds=("PROCEDURAL_ERROR",),
        requested_outcome="MODIFY_MEASURE",
        statement_recorded=True,
        new_evidence_reference_ids=(),
        edited_at=NOW,
    )
    application = AppealSubmittedApplicationProjection(
        grounds=("PROCEDURAL_ERROR",),
        requested_outcome="MODIFY_MEASURE",
        statement_recorded=True,
        new_evidence_reference_ids=(),
        submitted_at=NOW,
    )
    own = AppealOwnProjection(
        appeal_id=_id(40),
        source_outcome_version_id=OUTCOME_ID,
        source_case_id=CASE_ID,
        source=source,
        status="SUBMITTED",
        aggregate_version=3,
        application_draft=draft,
        application=application,
        decision=None,
        entity_tag='"appeal-3-0123456789abcdef01234567"',
    )
    assert "sealed://" not in repr(own)
    assert own.application_draft == draft
    queue = AppealQueueProjection(
        items=(
            AppealQueueItem(
                appeal_id=own.appeal_id,
                source_outcome_version_id=OUTCOME_ID,
                source_case_id=CASE_ID,
                grounds=("PROCEDURAL_ERROR",),
                requested_outcome="MODIFY_MEASURE",
                submitted_at=NOW,
                entity_tag=own.entity_tag,
            ),
        ),
        entity_tag='"appeal-1-111111111111111111111111"',
    )
    with pytest.raises(FrozenInstanceError):
        queue.entity_tag = "changed"  # type: ignore[misc]


def test_read_dtos_reject_unknown_codes_bad_etags_and_duplicate_grounds():
    source = AppealSourceProjection(
        outcome_version_id=OUTCOME_ID,
        case_id=CASE_ID,
        demand_id=DEMAND_ID,
        demand_version_id=DEMAND_VERSION_ID,
        outcome_code="PROTECTION_MODIFIED",
        reason_codes=("POLICY_REQUIREMENT_NOT_MET",),
        action_codes=("VERIFY_DEMAND",),
        evidence_packet_version_id=_id(9),
        evidence_packet_sha256="11" * 32,
        policy_version="trust-case-outcome-v1",
        decided_at=NOW - timedelta(days=1),
        appeal_eligible=True,
        appeal_eligibility_code="ELIGIBLE",
        appeal_deadline=NOW + timedelta(days=7),
        content_sha256="22" * 32,
    )
    with pytest.raises(TypeError):
        AppealSourceProjection(
            **{
                **source.__dict__,
                "organization_id": ORGANIZATION_ID,
            }
        )
    with pytest.raises(TypeError):
        AppealApplicationDraftProjection(
            version=1,
            grounds=("PROCEDURAL_ERROR",),
            requested_outcome="MODIFY_MEASURE",
            statement_recorded=True,
            new_evidence_reference_ids=(),
            edited_at=NOW,
            sealed_statement_reference="sealed://forbidden",  # type: ignore[call-arg]
        )
    application = AppealSubmittedApplicationProjection(
        grounds=("PROCEDURAL_ERROR",),
        requested_outcome="MODIFY_MEASURE",
        statement_recorded=True,
        new_evidence_reference_ids=(),
        submitted_at=NOW,
    )
    with pytest.raises(TypeError):
        AppealSubmittedApplicationProjection(
            grounds=("PROCEDURAL_ERROR",),
            requested_outcome="MODIFY_MEASURE",
            statement_recorded=True,
            new_evidence_reference_ids=(),
            submitted_at=NOW,
            sealed_statement_reference="sealed://forbidden",  # type: ignore[call-arg]
        )
    with pytest.raises(ValueError, match="APPEAL_READ_PROJECTION_INVALID"):
        AppealDecisionProjection(
            decision_version_id=_id(41),
            decision_code="ALLOW_UNKNOWN",
            assessments=(
                AppealAssessmentProjection(
                    ground="PROCEDURAL_ERROR",
                    assessment_code="ACCEPTED",
                    finding_codes=("PROCEDURE_MATERIAL_ERROR",),
                    accepted_evidence_reference_ids=(),
                ),
            ),
            reason_codes=("PROCEDURAL_REVIEW_COMPLETE",),
            remedy_delta_codes=("NARROW_CORRECTIVE_MEASURE",),
            policy_version="appeal-decision-v1",
            decided_at=NOW,
            decision_sha256="99" * 32,
        )
    with pytest.raises(ValueError, match="APPEAL_READ_PROJECTION_INVALID"):
        AppealQueueItem(
            appeal_id=_id(42),
            source_outcome_version_id=OUTCOME_ID,
            source_case_id=CASE_ID,
            grounds=("PROCEDURAL_ERROR",),
            requested_outcome="MODIFY_MEASURE",
            submitted_at=NOW,
            entity_tag="appeal-3-not-quoted",
        )
    assessment = AppealAssessmentProjection(
        ground="PROCEDURAL_ERROR",
        assessment_code="ACCEPTED",
        finding_codes=("PROCEDURE_MATERIAL_ERROR",),
        accepted_evidence_reference_ids=(),
    )
    with pytest.raises(ValueError, match="APPEAL_READ_PROJECTION_INVALID"):
        AppealReviewDraftProjection(
            version=1,
            assessments=(assessment, assessment),
            reason_codes=("PROCEDURAL_REVIEW_COMPLETE",),
            remedy_delta_codes=("NARROW_CORRECTIVE_MEASURE",),
            review_note_recorded=True,
            edited_at=NOW,
        )
    own = AppealOwnProjection(
        appeal_id=_id(43),
        source_outcome_version_id=OUTCOME_ID,
        source_case_id=CASE_ID,
        source=source,
        status="IN_REVIEW",
        aggregate_version=4,
        application_draft=None,
        application=application,
        decision=None,
        entity_tag='"appeal-4-0123456789abcdef01234567"',
    )
    assigned = AppealAssignedProjection(
        appeal=own,
        source=source,
        application=application,
        review_draft=None,
        assignment_expires_at=NOW + timedelta(hours=1),
        entity_tag=own.entity_tag,
    )
    assert assigned.source.outcome_version_id == OUTCOME_ID
    assert not hasattr(assigned.source, "organization_id")
    with pytest.raises(ValueError, match="APPEAL_READ_PROJECTION_INVALID"):
        AppealAssignedProjection(
            appeal=own,
            source=source,
            application=application,
            review_draft=None,
            assignment_expires_at=NOW + timedelta(hours=1),
            entity_tag='"appeal-5-0123456789abcdef01234567"',
        )


def test_read_projection_state_and_final_assessment_relationships_are_closed():
    with pytest.raises(ValueError, match="APPEAL_READ_PROJECTION_INVALID"):
        AppealSubmittedApplicationProjection(
            grounds=("NEW_MATERIAL_EVIDENCE",),
            requested_outcome="VACATE_AND_REMAND",
            statement_recorded=True,
            new_evidence_reference_ids=(),
            submitted_at=NOW,
        )
    source = AppealSourceProjection(
        outcome_version_id=OUTCOME_ID,
        case_id=CASE_ID,
        demand_id=DEMAND_ID,
        demand_version_id=DEMAND_VERSION_ID,
        outcome_code="PROTECTION_MODIFIED",
        reason_codes=("POLICY_REQUIREMENT_NOT_MET",),
        action_codes=("VERIFY_DEMAND",),
        evidence_packet_version_id=_id(9),
        evidence_packet_sha256="11" * 32,
        policy_version="trust-case-outcome-v1",
        decided_at=NOW - timedelta(days=1),
        appeal_eligible=True,
        appeal_eligibility_code="ELIGIBLE",
        appeal_deadline=NOW + timedelta(days=7),
        content_sha256="22" * 32,
    )
    application = AppealSubmittedApplicationProjection(
        grounds=("PROCEDURAL_ERROR",),
        requested_outcome="MODIFY_MEASURE",
        statement_recorded=True,
        new_evidence_reference_ids=(),
        submitted_at=NOW,
    )
    decision = AppealDecisionProjection(
        decision_version_id=_id(45),
        decision_code="MODIFY",
        assessments=(
            AppealAssessmentProjection(
                ground="PROCEDURAL_ERROR",
                assessment_code="ACCEPTED",
                finding_codes=("PROCEDURE_MATERIAL_ERROR",),
                accepted_evidence_reference_ids=(),
            ),
        ),
        reason_codes=("PROCEDURAL_REVIEW_COMPLETE",),
        remedy_delta_codes=("NARROW_CORRECTIVE_MEASURE",),
        policy_version="appeal-decision-v1",
        decided_at=NOW,
        decision_sha256="aa" * 32,
    )
    decided = AppealOwnProjection(
        appeal_id=_id(46),
        source_outcome_version_id=OUTCOME_ID,
        source_case_id=CASE_ID,
        source=source,
        status="DECIDED",
        aggregate_version=6,
        application_draft=None,
        application=application,
        decision=decision,
        entity_tag='"appeal-6-0123456789abcdef01234567"',
    )
    assert decided.decision is decision
    with pytest.raises(ValueError, match="APPEAL_READ_PROJECTION_INVALID"):
        AppealOwnProjection(
            **{
                **decided.__dict__,
                "status": "DRAFT",
                "decision": None,
            }
        )
    with pytest.raises(ValueError, match="APPEAL_READ_PROJECTION_INVALID"):
        AppealOwnProjection(
            **{
                **decided.__dict__,
                "status": "WITHDRAWN",
            }
        )
    mismatched = AppealDecisionProjection(
        **{
            **decision.__dict__,
            "assessments": (
                AppealAssessmentProjection(
                    ground="RULE_MISAPPLICATION",
                    assessment_code="ACCEPTED",
                    finding_codes=("RULE_APPLICATION_ERROR",),
                    accepted_evidence_reference_ids=(),
                ),
            ),
        }
    )
    with pytest.raises(ValueError, match="APPEAL_READ_PROJECTION_INVALID"):
        AppealOwnProjection(
            **{
                **decided.__dict__,
                "decision": mismatched,
            }
        )


def test_authority_source_conflict_policy_and_raw_text_repr_are_secret_safe():
    actor = _applicant()
    applicant_authority = Authority().authorize_applicant(
        actor=actor,
        operation="OPEN_APPEAL",
        organization_id=ORGANIZATION_ID,
    )
    authority = Authority().authorize_reviewer(
        actor=_reviewer(), operation="CLAIM_APPEAL"
    )
    applicant_source = Sources().resolve_applicant_source(
        applicant_authority=applicant_authority,
        source_outcome_version_id=OUTCOME_ID,
    )
    conflict = Conflicts().check_reviewer_conflict(
        reviewer_authority=authority,
        source=_source(),
        appeal_id=_id(44),
        applicant_user_id=APPLICANT_ID,
    )
    policy = AppealDecisionPolicy(
        appeal_id=_id(44),
        appeal_aggregate_version=5,
        source_outcome_version_id=OUTCOME_ID,
        review_draft_version=1,
        decision_code="MODIFY",
        policy_version="appeal-decision-v1",
        policy_marker_sha256="77" * 32,
        evaluated_at=NOW,
        valid_until=NOW + timedelta(minutes=10),
    )
    combined = " ".join(
        repr(value)
        for value in (
            applicant_authority,
            authority,
            applicant_source,
            conflict,
            policy,
        )
    )
    for secret in (
        APPLICANT_ID,
        REVIEWER_ID,
        ORGANIZATION_ID,
        authority.duty_grant_id,
        "33" * 32,
        "44" * 32,
        "55" * 32,
        "66" * 32,
        "77" * 32,
    ):
        assert secret not in combined
