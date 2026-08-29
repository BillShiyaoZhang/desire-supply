from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest

from desire_platform.trust_safety.domain import (
    Appeal,
    AppealAssignmentReleaseReason,
    AppealDecisionCode,
    AppealDomainError,
    AppealGround,
    AppealGroundAssessment,
    AppealGroundAssessmentCode,
    AppealStatus,
    RequestedAppealOutcome,
    TrustCaseOutcomeSource,
)


NOW = datetime(2026, 8, 18, 8, 0, tzinfo=timezone.utc)


def _id(number: int) -> str:
    return str(UUID(int=number))


def _source(*, eligible: bool = True) -> TrustCaseOutcomeSource:
    return TrustCaseOutcomeSource(
        outcome_version_id=_id(1),
        case_id=_id(2),
        organization_id=_id(3),
        demand_id=_id(4),
        demand_version_id=_id(5),
        outcome_code="PROTECTION_MODIFIED",
        reason_codes=("POLICY_REQUIREMENT_NOT_MET",),
        action_codes=("VERIFY_DEMAND",),
        evidence_packet_version_id=_id(6),
        evidence_packet_sha256="11" * 32,
        policy_version="trust-case-outcome-v1",
        decided_at=NOW - timedelta(days=1),
        appeal_eligible=eligible,
        appeal_eligibility_code=("ELIGIBLE" if eligible else "NOT_ELIGIBLE"),
        appeal_deadline=NOW + timedelta(days=7) if eligible else None,
        content_sha256="22" * 32,
    )


def _draft() -> Appeal:
    appeal = Appeal.open(
        appeal_id=_id(10),
        source=_source(),
        applicant_user_id=_id(11),
        applicant_is_party=True,
        now=NOW,
    )
    appeal, first = appeal.save_application_draft(
        applicant_user_id=_id(11),
        grounds=(AppealGround.PROCEDURAL_ERROR,),
        requested_outcome=RequestedAppealOutcome.MODIFY_MEASURE,
        sealed_statement_reference="sealed://trust/appeal/statement-one",
        sealed_statement_sha256="33" * 32,
        new_evidence_reference_ids=(),
        now=NOW + timedelta(minutes=1),
    )
    appeal, second = appeal.save_application_draft(
        applicant_user_id=_id(11),
        grounds=(
            AppealGround.PROCEDURAL_ERROR,
            AppealGround.NEW_MATERIAL_EVIDENCE,
        ),
        requested_outcome=RequestedAppealOutcome.VACATE_AND_REMAND,
        sealed_statement_reference="sealed://trust/appeal/statement-two",
        sealed_statement_sha256="44" * 32,
        new_evidence_reference_ids=(_id(12),),
        now=NOW + timedelta(minutes=2),
    )
    assert first.version == 1
    assert second.version == 2
    return appeal


def _submitted() -> Appeal:
    appeal = _draft()
    appeal, submitted = appeal.submit(
        applicant_user_id=_id(11),
        expected_draft_version=2,
        now=NOW + timedelta(minutes=3),
    )
    assert submitted.version == 1
    return appeal


def _claimed() -> Appeal:
    appeal = _submitted()
    appeal, _assignment = appeal.claim(
        assignment_id=_id(20),
        reviewer_user_id=_id(21),
        duty_grant_id=_id(22),
        duty_grant_version=4,
        conflict_attestation_sha256="55" * 32,
        expires_at=NOW + timedelta(hours=4),
        now=NOW + timedelta(minutes=4),
    )
    return appeal


def _reviewed() -> Appeal:
    appeal = _claimed()
    appeal, first = appeal.save_review_draft(
        reviewer_user_id=_id(21),
        assessments=(
            AppealGroundAssessment(
                ground=AppealGround.PROCEDURAL_ERROR,
                assessment_code=AppealGroundAssessmentCode.PARTIALLY_ACCEPTED,
                finding_codes=("PROCEDURE_MATERIAL_ERROR",),
                accepted_evidence_reference_ids=(),
            ),
            AppealGroundAssessment(
                ground=AppealGround.NEW_MATERIAL_EVIDENCE,
                assessment_code=AppealGroundAssessmentCode.ACCEPTED,
                finding_codes=("NEW_EVIDENCE_MATERIAL",),
                accepted_evidence_reference_ids=(_id(12),),
            ),
        ),
        reason_codes=("NEW_EVIDENCE_REVIEWED",),
        remedy_delta_codes=("RETURN_TO_TRUST_REVIEW",),
        sealed_review_note_reference="sealed://trust/appeal/review-one",
        sealed_review_note_sha256="66" * 32,
        now=NOW + timedelta(minutes=5),
    )
    assert first.version == 1
    return appeal


def test_draft_is_editable_then_submission_freezes_application() -> None:
    appeal = _submitted()
    assert appeal.status is AppealStatus.SUBMITTED
    assert appeal.current_application_draft_version == 2
    with pytest.raises(AppealDomainError) as raised:
        appeal.save_application_draft(
            applicant_user_id=_id(11),
            grounds=(AppealGround.RULE_MISAPPLICATION,),
            requested_outcome=RequestedAppealOutcome.REMOVE_MEASURE,
            sealed_statement_reference="sealed://trust/appeal/late",
            sealed_statement_sha256="77" * 32,
            new_evidence_reference_ids=(),
            now=NOW + timedelta(minutes=4),
        )
    assert raised.value.code == "APPEAL_APPLICATION_FROZEN"


def test_ineligible_nonparty_and_exclusive_deadline_fail_closed() -> None:
    with pytest.raises(AppealDomainError) as raised:
        Appeal.open(
            appeal_id=_id(10),
            source=_source(eligible=False),
            applicant_user_id=_id(11),
            applicant_is_party=True,
            now=NOW,
        )
    assert raised.value.code == "APPEAL_NOT_AVAILABLE"

    with pytest.raises(AppealDomainError) as raised:
        Appeal.open(
            appeal_id=_id(10),
            source=_source(),
            applicant_user_id=_id(11),
            applicant_is_party=False,
            now=NOW,
        )
    assert raised.value.code == "APPEAL_NOT_AVAILABLE"

    with pytest.raises(AppealDomainError) as raised:
        Appeal.open(
            appeal_id=_id(10),
            source=_source(),
            applicant_user_id=_id(11),
            applicant_is_party=True,
            now=NOW + timedelta(days=7),
        )
    assert raised.value.code == "APPEAL_NOT_AVAILABLE"


def test_reviewer_must_be_distinct_and_assessment_covers_each_ground() -> None:
    appeal = _submitted()
    with pytest.raises(AppealDomainError) as raised:
        appeal.claim(
            assignment_id=_id(20),
            reviewer_user_id=_id(11),
            duty_grant_id=_id(22),
            duty_grant_version=1,
            conflict_attestation_sha256="55" * 32,
            expires_at=NOW + timedelta(hours=1),
            now=NOW + timedelta(minutes=4),
        )
    assert raised.value.code == "APPEAL_ASSIGNMENT_INVALID"

    appeal = _claimed()
    with pytest.raises(AppealDomainError) as raised:
        appeal.save_review_draft(
            reviewer_user_id=_id(21),
            assessments=(
                AppealGroundAssessment(
                    ground=AppealGround.PROCEDURAL_ERROR,
                    assessment_code=AppealGroundAssessmentCode.REJECTED,
                    finding_codes=("APPEAL_NOT_SUBSTANTIATED",),
                    accepted_evidence_reference_ids=(),
                ),
            ),
            reason_codes=("PROCEDURAL_REVIEW_COMPLETE",),
            remedy_delta_codes=("NO_CHANGE",),
            sealed_review_note_reference="sealed://trust/appeal/incomplete",
            sealed_review_note_sha256="66" * 32,
            now=NOW + timedelta(minutes=5),
        )
    assert raised.value.code == "APPEAL_REVIEW_INVALID"


def test_new_evidence_ground_requires_evidence_and_review_cannot_invent_refs() -> None:
    appeal = Appeal.open(
        appeal_id=_id(40),
        source=_source(),
        applicant_user_id=_id(11),
        applicant_is_party=True,
        now=NOW,
    )
    with pytest.raises(AppealDomainError) as raised:
        appeal.save_application_draft(
            applicant_user_id=_id(11),
            grounds=(AppealGround.NEW_MATERIAL_EVIDENCE,),
            requested_outcome=RequestedAppealOutcome.VACATE_AND_REMAND,
            sealed_statement_reference="sealed://trust/appeal/no-evidence",
            sealed_statement_sha256="99" * 32,
            new_evidence_reference_ids=(),
            now=NOW + timedelta(minutes=1),
        )
    assert raised.value.code == "APPEAL_APPLICATION_INVALID"

    appeal = _claimed()
    with pytest.raises(AppealDomainError) as raised:
        appeal.save_review_draft(
            reviewer_user_id=_id(21),
            assessments=(
                AppealGroundAssessment(
                    ground=AppealGround.PROCEDURAL_ERROR,
                    assessment_code=AppealGroundAssessmentCode.REJECTED,
                    finding_codes=("APPEAL_NOT_SUBSTANTIATED",),
                    accepted_evidence_reference_ids=(),
                ),
                AppealGroundAssessment(
                    ground=AppealGround.NEW_MATERIAL_EVIDENCE,
                    assessment_code=AppealGroundAssessmentCode.ACCEPTED,
                    finding_codes=("NEW_EVIDENCE_MATERIAL",),
                    accepted_evidence_reference_ids=(_id(99),),
                ),
            ),
            reason_codes=("NEW_EVIDENCE_REVIEWED",),
            remedy_delta_codes=("RETURN_TO_TRUST_REVIEW",),
            sealed_review_note_reference="sealed://trust/appeal/invented",
            sealed_review_note_sha256="aa" * 32,
            now=NOW + timedelta(minutes=5),
        )
    assert raised.value.code == "APPEAL_REVIEW_INVALID"


def test_reviewer_can_recuse_and_expired_assignment_can_be_recovered() -> None:
    appeal = _claimed()
    appeal, released = appeal.release_assignment(
        requester_user_id=_id(21),
        reason_code=AppealAssignmentReleaseReason.CONFLICT_DECLARED,
        now=NOW + timedelta(minutes=5),
    )
    assert released.reason_code is AppealAssignmentReleaseReason.CONFLICT_DECLARED
    assert appeal.status is AppealStatus.SUBMITTED
    assert appeal.assignment is None

    appeal = _claimed()
    with pytest.raises(AppealDomainError) as raised:
        appeal.release_assignment(
            requester_user_id=_id(23),
            reason_code=AppealAssignmentReleaseReason.ASSIGNMENT_EXPIRED,
            now=NOW + timedelta(hours=3),
        )
    assert raised.value.code == "APPEAL_ASSIGNMENT_NOT_EXPIRED"
    appeal, _released = appeal.release_assignment(
        requester_user_id=_id(23),
        reason_code=AppealAssignmentReleaseReason.ASSIGNMENT_EXPIRED,
        now=NOW + timedelta(hours=4),
    )
    assert appeal.status is AppealStatus.SUBMITTED


def test_assignment_repr_excludes_reviewer_duty_and_conflict_coordinates() -> None:
    appeal = _claimed()
    assignment = appeal.assignment
    assert assignment is not None
    rendered = repr(assignment)
    for secret in (_id(21), _id(22), "55" * 32):
        assert secret not in rendered


def test_final_decision_is_new_immutable_version_and_never_mutates_source() -> None:
    appeal = _reviewed()
    original_source = appeal.source
    appeal, decision = appeal.decide(
        decision_version_id=_id(30),
        reviewer_user_id=_id(21),
        expected_review_draft_version=1,
        decision_code=AppealDecisionCode.VACATE_AND_REMAND,
        policy_version="appeal-decision-v1",
        now=NOW + timedelta(minutes=6),
    )
    assert appeal.status is AppealStatus.DECIDED
    assert appeal.source is original_source
    assert decision.source_outcome_version_id == original_source.outcome_version_id
    assert decision.source_outcome_sha256 == original_source.content_sha256
    assert len(decision.decision_sha256) == 64
    with pytest.raises(FrozenInstanceError):
        decision.decision_code = AppealDecisionCode.AFFIRM  # type: ignore[misc]


def test_affirm_requires_all_grounds_rejected_and_no_remedy_change() -> None:
    appeal = _claimed()
    appeal, _draft = appeal.save_review_draft(
        reviewer_user_id=_id(21),
        assessments=(
            AppealGroundAssessment(
                ground=AppealGround.PROCEDURAL_ERROR,
                assessment_code=AppealGroundAssessmentCode.REJECTED,
                finding_codes=("APPEAL_NOT_SUBSTANTIATED",),
                accepted_evidence_reference_ids=(),
            ),
            AppealGroundAssessment(
                ground=AppealGround.NEW_MATERIAL_EVIDENCE,
                assessment_code=AppealGroundAssessmentCode.REJECTED,
                finding_codes=("APPEAL_NOT_SUBSTANTIATED",),
                accepted_evidence_reference_ids=(),
            ),
        ),
        reason_codes=("SOURCE_OUTCOME_SUPPORTED",),
        remedy_delta_codes=("NO_CHANGE",),
        sealed_review_note_reference="sealed://trust/appeal/affirm",
        sealed_review_note_sha256="88" * 32,
        now=NOW + timedelta(minutes=5),
    )
    _appeal, decision = appeal.decide(
        decision_version_id=_id(31),
        reviewer_user_id=_id(21),
        expected_review_draft_version=1,
        decision_code=AppealDecisionCode.AFFIRM,
        policy_version="appeal-decision-v1",
        now=NOW + timedelta(minutes=6),
    )
    assert decision.decision_code is AppealDecisionCode.AFFIRM
