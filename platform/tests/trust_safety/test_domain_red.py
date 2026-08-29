from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from desire_platform.trust_safety.domain import (
    AssignmentReleaseReason,
    HoldAction,
    HoldReason,
    ReportCategory,
    SafetyCase,
    SafetyCaseStatus,
    SafetyHoldStatus,
    TrustCaseOutcome,
    TrustDomainError,
)


NOW = datetime(2026, 8, 18, 4, 0, tzinfo=timezone.utc)


def _id() -> str:
    return str(uuid4())


def _open_case() -> SafetyCase:
    case, report = SafetyCase.open_report(
        case_id=_id(),
        report_id=_id(),
        organization_id=_id(),
        demand_id=_id(),
        demand_version_id=_id(),
        demand_version_no=2,
        demand_aggregate_version=4,
        demand_status="SUBMITTED",
        demand_content_sha256="10" * 32,
        reporter_party_marker_sha256="11" * 32,
        target_marker_sha256="12" * 32,
        reportable_until=NOW + timedelta(days=7),
        reporter_user_id=_id(),
        category=ReportCategory.DATA_EXPOSURE,
        incident_started_at=NOW - timedelta(hours=2),
        incident_ended_at=NOW - timedelta(hours=1),
        impact_codes=("SYNTHETIC_DATA_DISCLOSED",),
        evidence_reference_ids=(_id(),),
        requested_protection_codes=("PAUSE_VERIFICATION",),
        now=NOW,
    )
    assert report.case_id == case.case_id
    return case


def _claimed_case() -> tuple[SafetyCase, str]:
    case = _open_case()
    officer_id = _id()
    case, assignment = case.claim(
        assignment_id=_id(),
        officer_user_id=officer_id,
        duty_grant_id=_id(),
        duty_grant_version=3,
        conflict_attestation_sha256="11" * 32,
        expires_at=NOW + timedelta(hours=4),
        now=NOW,
    )
    assert assignment.officer_user_id == officer_id
    return case, officer_id


def _triaged_case() -> tuple[SafetyCase, str]:
    case, officer_id = _claimed_case()
    case, first = case.save_triage_draft(
        officer_user_id=officer_id,
        priority_code="P2",
        jurisdiction_code="PLATFORM_INTERNAL",
        severity_code="MEDIUM",
        issue_codes=("DATA_HANDLING_GAP",),
        investigation_step_codes=("CHECK_DEMAND_VERSION", "CHECK_ACCESS_SCOPE"),
        proposed_hold_actions=(HoldAction.VERIFY_DEMAND,),
        proposed_hold_ttl_minutes=120,
        sealed_note_reference="sealed://trust/triage-note-one",
        sealed_note_sha256="22" * 32,
        now=NOW + timedelta(minutes=1),
    )
    case, second = case.save_triage_draft(
        officer_user_id=officer_id,
        priority_code="P1",
        jurisdiction_code="PLATFORM_INTERNAL",
        severity_code="HIGH",
        issue_codes=("DATA_HANDLING_GAP", "SCOPE_DISCLOSURE_RISK"),
        investigation_step_codes=("CHECK_ACCESS_SCOPE", "CHECK_DEMAND_VERSION"),
        proposed_hold_actions=(HoldAction.VERIFY_DEMAND,),
        proposed_hold_ttl_minutes=180,
        sealed_note_reference="sealed://trust/triage-note-two",
        sealed_note_sha256="33" * 32,
        now=NOW + timedelta(minutes=2),
    )
    assert first.version == 1
    assert second.version == 2
    case, published = case.publish_triage(
        officer_user_id=officer_id,
        expected_draft_version=2,
        now=NOW + timedelta(minutes=3),
    )
    assert published.version == 1
    return case, officer_id


def test_report_is_structured_immutable_and_contains_no_narrative() -> None:
    case, report = SafetyCase.open_report(
        case_id=_id(),
        report_id=_id(),
        organization_id=_id(),
        demand_id=_id(),
        demand_version_id=_id(),
        demand_version_no=2,
        demand_aggregate_version=4,
        demand_status="SUBMITTED",
        demand_content_sha256="10" * 32,
        reporter_party_marker_sha256="11" * 32,
        target_marker_sha256="12" * 32,
        reportable_until=NOW + timedelta(days=7),
        reporter_user_id=_id(),
        category=ReportCategory.FRAUD_RISK,
        incident_started_at=NOW - timedelta(minutes=30),
        incident_ended_at=None,
        impact_codes=("SYNTHETIC_FINANCIAL_RISK", "WORKFLOW_INTEGRITY_RISK"),
        evidence_reference_ids=(_id(), _id()),
        requested_protection_codes=("PAUSE_VERIFICATION",),
        now=NOW,
    )

    assert case.status is SafetyCaseStatus.OPEN
    assert case.aggregate_version == 1
    assert report.category is ReportCategory.FRAUD_RISK
    assert not hasattr(report, "narrative")
    assert "reporter_user_id" not in repr(report)
    assert "demand_content_sha256" not in repr(report)
    assert "reporter_party_marker_sha256" not in repr(report)
    assert "target_marker_sha256" not in repr(report)
    with pytest.raises(FrozenInstanceError):
        report.category = ReportCategory.HARASSMENT  # type: ignore[misc]


@pytest.mark.parametrize(
    "mutation,code",
    (
        ({"impact_codes": ()}, "REPORT_VALIDATION_FAILED"),
        ({"requested_protection_codes": ()}, "REPORT_VALIDATION_FAILED"),
        ({"incident_started_at": NOW + timedelta(seconds=1)}, "REPORT_VALIDATION_FAILED"),
        ({"impact_codes": ("Z", "A")}, "REPORT_VALIDATION_FAILED"),
    ),
)
def test_report_rejects_incomplete_future_or_noncanonical_facts(
    mutation: dict[str, object], code: str
) -> None:
    facts: dict[str, object] = {
        "case_id": _id(),
        "report_id": _id(),
        "organization_id": _id(),
        "demand_id": _id(),
        "demand_version_id": _id(),
        "demand_version_no": 2,
        "demand_aggregate_version": 4,
        "demand_status": "SUBMITTED",
        "demand_content_sha256": "10" * 32,
        "reporter_party_marker_sha256": "11" * 32,
        "target_marker_sha256": "12" * 32,
        "reportable_until": NOW + timedelta(days=7),
        "reporter_user_id": _id(),
        "category": ReportCategory.DATA_EXPOSURE,
        "incident_started_at": NOW - timedelta(minutes=20),
        "incident_ended_at": None,
        "impact_codes": ("SYNTHETIC_DATA_DISCLOSED",),
        "evidence_reference_ids": (_id(),),
        "requested_protection_codes": ("PAUSE_VERIFICATION",),
        "now": NOW,
    }
    facts.update(mutation)
    with pytest.raises(TrustDomainError) as raised:
        SafetyCase.open_report(**facts)
    assert raised.value.code == code


def test_assignment_binds_duty_conflict_attestation_and_expiry() -> None:
    case, officer_id = _claimed_case()
    assert case.status is SafetyCaseStatus.TRIAGING
    assert case.assigned_officer_user_id == officer_id
    assert case.aggregate_version == 2

    with pytest.raises(TrustDomainError) as raised:
        case.claim(
            assignment_id=_id(),
            officer_user_id=_id(),
            duty_grant_id=_id(),
            duty_grant_version=1,
            conflict_attestation_sha256="44" * 32,
            expires_at=NOW + timedelta(hours=1),
            now=NOW,
        )
    assert raised.value.code == "CASE_ALREADY_ASSIGNED"


def test_assigned_officer_can_recuse_and_case_returns_to_queue() -> None:
    case, officer_id = _claimed_case()
    case, released = case.release_assignment(
        requester_user_id=officer_id,
        reason_code=AssignmentReleaseReason.CONFLICT_DECLARED,
        now=NOW + timedelta(minutes=1),
    )

    assert released.reason_code is AssignmentReleaseReason.CONFLICT_DECLARED
    assert case.status is SafetyCaseStatus.OPEN
    assert case.assignment_id is None
    assert case.assigned_officer_user_id is None
    assert case.aggregate_version == 3


def test_expired_assignment_can_be_recovered_by_another_authorized_officer() -> None:
    case, _officer_id = _claimed_case()
    recovery_officer = _id()
    with pytest.raises(TrustDomainError) as raised:
        case.release_assignment(
            requester_user_id=recovery_officer,
            reason_code=AssignmentReleaseReason.ASSIGNMENT_EXPIRED,
            now=NOW + timedelta(hours=3),
        )
    assert raised.value.code == "ASSIGNMENT_NOT_EXPIRED"

    case, released = case.release_assignment(
        requester_user_id=recovery_officer,
        reason_code=AssignmentReleaseReason.ASSIGNMENT_EXPIRED,
        now=NOW + timedelta(hours=4),
    )
    assert released.released_by_user_id == recovery_officer
    assert case.status is SafetyCaseStatus.OPEN


def test_triage_is_editable_before_publish_and_frozen_after_publish() -> None:
    case, officer_id = _triaged_case()
    assert case.status is SafetyCaseStatus.IN_REVIEW
    assert case.current_triage_draft_version == 2
    assert case.current_triage_version == 1

    with pytest.raises(TrustDomainError) as raised:
        case.save_triage_draft(
            officer_user_id=officer_id,
            priority_code="P2",
            jurisdiction_code="PLATFORM_INTERNAL",
            severity_code="MEDIUM",
            issue_codes=("DATA_HANDLING_GAP",),
            investigation_step_codes=("CHECK_ACCESS_SCOPE",),
            proposed_hold_actions=(HoldAction.VERIFY_DEMAND,),
            proposed_hold_ttl_minutes=60,
            sealed_note_reference="sealed://trust/triage-note-late",
            sealed_note_sha256="55" * 32,
            now=NOW + timedelta(minutes=4),
        )
    assert raised.value.code == "TRIAGE_ALREADY_PUBLISHED"


def test_exact_demand_hold_can_be_configured_and_released() -> None:
    case, officer_id = _triaged_case()
    case, hold = case.place_hold(
        hold_id=_id(),
        officer_user_id=officer_id,
        action_codes=(HoldAction.SUBMIT_DEMAND, HoldAction.VERIFY_DEMAND),
        reason_code=HoldReason.WORKFLOW_INTEGRITY_RISK,
        expires_at=NOW + timedelta(hours=2),
        policy_version="trust-demand-hold-v1",
        now=NOW + timedelta(minutes=4),
    )
    assert hold.status is SafetyHoldStatus.ACTIVE
    assert hold.demand_id == case.demand_id
    assert hold.action_codes == (
        HoldAction.SUBMIT_DEMAND,
        HoldAction.VERIFY_DEMAND,
    )

    case, released = case.release_hold(
        hold=hold,
        officer_user_id=officer_id,
        release_reason_code="RISK_MITIGATED",
        now=NOW + timedelta(minutes=10),
    )
    assert released.status is SafetyHoldStatus.RELEASED
    assert case.aggregate_version == 7


def test_high_severity_hold_cannot_be_self_released() -> None:
    case, officer_id = _triaged_case()
    case, hold = case.place_hold(
        hold_id=_id(),
        officer_user_id=officer_id,
        action_codes=(HoldAction.VERIFY_DEMAND,),
        reason_code=HoldReason.PARTICIPANT_SAFETY_RISK,
        expires_at=NOW + timedelta(hours=2),
        policy_version="trust-demand-hold-v1",
        now=NOW + timedelta(minutes=4),
    )
    with pytest.raises(TrustDomainError) as raised:
        case.release_hold(
            hold=hold,
            officer_user_id=officer_id,
            release_reason_code="RISK_MITIGATED",
            now=NOW + timedelta(minutes=5),
        )
    assert raised.value.code == "INDEPENDENT_REVIEW_REQUIRED"


def test_high_severity_hold_can_be_released_by_a_second_bound_officer() -> None:
    case, officer_id = _triaged_case()
    case, hold = case.place_hold(
        hold_id=_id(),
        officer_user_id=officer_id,
        action_codes=(HoldAction.VERIFY_DEMAND,),
        reason_code=HoldReason.PARTICIPANT_SAFETY_RISK,
        expires_at=NOW + timedelta(hours=2),
        policy_version="trust-demand-hold-v1",
        now=NOW + timedelta(minutes=4),
    )
    second_officer = _id()
    hold, release_assignment = case.claim_hold_release(
        hold=hold,
        assignment_id=_id(),
        officer_user_id=second_officer,
        duty_grant_id=_id(),
        duty_grant_version=2,
        conflict_attestation_sha256="88" * 32,
        expires_at=NOW + timedelta(hours=1),
        now=NOW + timedelta(minutes=5),
    )

    case, released = case.release_hold(
        hold=hold,
        officer_user_id=second_officer,
        release_reason_code="RISK_MITIGATED",
        independent_assignment=release_assignment,
        now=NOW + timedelta(minutes=6),
    )

    assert released.status is SafetyHoldStatus.RELEASED
    assert released.released_by_user_id == second_officer
    assert case.aggregate_version == 7
    assert released.aggregate_version == 3


def test_hold_deadline_validation_is_safe_on_leap_day() -> None:
    leap_now = datetime(2028, 2, 29, 12, 0, tzinfo=timezone.utc)
    case, _report = SafetyCase.open_report(
        case_id=_id(),
        report_id=_id(),
        organization_id=_id(),
        demand_id=_id(),
        demand_version_id=_id(),
        demand_version_no=2,
        demand_aggregate_version=4,
        demand_status="SUBMITTED",
        demand_content_sha256="10" * 32,
        reporter_party_marker_sha256="11" * 32,
        target_marker_sha256="12" * 32,
        reportable_until=leap_now + timedelta(days=7),
        reporter_user_id=_id(),
        category=ReportCategory.DATA_EXPOSURE,
        incident_started_at=leap_now - timedelta(hours=2),
        incident_ended_at=None,
        impact_codes=("SYNTHETIC_DATA_DISCLOSED",),
        evidence_reference_ids=(_id(),),
        requested_protection_codes=("PAUSE_VERIFICATION",),
        now=leap_now,
    )
    officer_id = _id()
    case, _assignment = case.claim(
        assignment_id=_id(),
        officer_user_id=officer_id,
        duty_grant_id=_id(),
        duty_grant_version=1,
        conflict_attestation_sha256="99" * 32,
        expires_at=leap_now + timedelta(hours=4),
        now=leap_now,
    )
    case, _draft = case.save_triage_draft(
        officer_user_id=officer_id,
        priority_code="P2",
        jurisdiction_code="PLATFORM_INTERNAL",
        severity_code="MEDIUM",
        issue_codes=("DATA_HANDLING_GAP",),
        investigation_step_codes=("CHECK_DEMAND_VERSION",),
        proposed_hold_actions=(HoldAction.VERIFY_DEMAND,),
        proposed_hold_ttl_minutes=60,
        sealed_note_reference="sealed://trust/triage-note-leap",
        sealed_note_sha256="aa" * 32,
        now=leap_now + timedelta(minutes=1),
    )
    case, _published = case.publish_triage(
        officer_user_id=officer_id,
        expected_draft_version=1,
        now=leap_now + timedelta(minutes=2),
    )

    _case, hold = case.place_hold(
        hold_id=_id(),
        officer_user_id=officer_id,
        action_codes=(HoldAction.VERIFY_DEMAND,),
        reason_code=HoldReason.WORKFLOW_INTEGRITY_RISK,
        expires_at=leap_now + timedelta(days=30),
        policy_version="trust-demand-hold-v1",
        now=leap_now + timedelta(minutes=3),
    )
    assert hold.status is SafetyHoldStatus.ACTIVE


def test_initial_outcome_is_immutable_and_appeal_ready() -> None:
    case, officer_id = _triaged_case()
    case, decision = case.record_initial_outcome(
        outcome_version_id=_id(),
        officer_user_id=officer_id,
        outcome=TrustCaseOutcome.PROTECTION_MODIFIED,
        reason_codes=("POLICY_REQUIREMENT_NOT_MET",),
        action_codes=(HoldAction.VERIFY_DEMAND,),
        evidence_packet_version_id=_id(),
        evidence_packet_digest="66" * 32,
        source_digest="77" * 32,
        redaction_profile_code="PARTY_SAFE_V1",
        appeal_eligible=True,
        appeal_eligibility_code="ELIGIBLE",
        appeal_deadline=NOW + timedelta(days=7),
        policy_version="trust-case-outcome-v1",
        now=NOW + timedelta(minutes=5),
    )
    assert case.status is SafetyCaseStatus.DECIDED
    assert decision.outcome_version == 1
    assert len(decision.content_sha256) == 64
    assert decision.appeal_eligible is True
    assert decision.appeal_eligibility_code == "ELIGIBLE"
    assert decision.appeal_deadline == NOW + timedelta(days=7)
    assert "evidence_packet_digest" not in repr(decision)
    with pytest.raises(FrozenInstanceError):
        decision.outcome = TrustCaseOutcome.NO_ACTION  # type: ignore[misc]

    invalid_case, invalid_officer = _triaged_case()
    with pytest.raises(TrustDomainError) as raised:
        invalid_case.record_initial_outcome(
            outcome_version_id=_id(),
            officer_user_id=invalid_officer,
            outcome=TrustCaseOutcome.PROTECTION_MODIFIED,
            reason_codes=("POLICY_REQUIREMENT_NOT_MET",),
            action_codes=(HoldAction.VERIFY_DEMAND,),
            evidence_packet_version_id=_id(),
            evidence_packet_digest="66" * 32,
            source_digest="77" * 32,
            redaction_profile_code="PARTY_SAFE_V1",
            appeal_eligible=True,
            appeal_eligibility_code="NOT_ELIGIBLE",
            appeal_deadline=NOW + timedelta(days=7),
            policy_version="trust-case-outcome-v1",
            now=NOW + timedelta(minutes=5),
        )
    assert raised.value.code == "CASE_DECISION_VALIDATION_FAILED"


def test_only_assigned_officer_can_edit_or_decide() -> None:
    case, _officer_id = _claimed_case()
    outsider = _id()
    with pytest.raises(TrustDomainError) as raised:
        case.save_triage_draft(
            officer_user_id=outsider,
            priority_code="P2",
            jurisdiction_code="PLATFORM_INTERNAL",
            severity_code="MEDIUM",
            issue_codes=("DATA_HANDLING_GAP",),
            investigation_step_codes=("CHECK_ACCESS_SCOPE",),
            proposed_hold_actions=(HoldAction.VERIFY_DEMAND,),
            proposed_hold_ttl_minutes=60,
            sealed_note_reference="sealed://trust/triage-note-outsider",
            sealed_note_sha256="77" * 32,
            now=NOW + timedelta(minutes=1),
        )
    assert raised.value.code == "CASE_ASSIGNMENT_REQUIRED"
