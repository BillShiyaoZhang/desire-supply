"""Immutable trust-case facts and closed state transitions.

The first vertical intentionally targets a Demand rather than modelling a
generic moderation bucket.  Reports contain structured facts only.  Any human
note is represented by an opaque sealed reference and digest so raw sensitive
text cannot leak through domain reprs, receipts, audit events, or outbox data.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import json
import re
from typing import Iterable, Optional, Tuple, TypeVar
from uuid import UUID


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CODE = re.compile(r"[A-Z][A-Z0-9_]{1,63}\Z")
_SEALED_REFERENCE = re.compile(r"sealed://[a-z0-9][a-z0-9/_-]{4,255}\Z")


class TrustDomainError(ValueError):
    """One closed, user-safe domain rejection."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ReportCategory(str, Enum):
    DATA_EXPOSURE = "DATA_EXPOSURE"
    FRAUD_RISK = "FRAUD_RISK"
    HARASSMENT = "HARASSMENT"
    RETALIATION = "RETALIATION"
    WORKFLOW_INTEGRITY = "WORKFLOW_INTEGRITY"


class SafetyCaseStatus(str, Enum):
    OPEN = "OPEN"
    TRIAGING = "TRIAGING"
    IN_REVIEW = "IN_REVIEW"
    DECIDED = "DECIDED"
    APPEAL_PENDING = "APPEAL_PENDING"
    RESOLVED = "RESOLVED"
    DISMISSED = "DISMISSED"


class AssignmentReleaseReason(str, Enum):
    CONFLICT_DECLARED = "CONFLICT_DECLARED"
    WORKLOAD_RELEASE = "WORKLOAD_RELEASE"
    ASSIGNMENT_EXPIRED = "ASSIGNMENT_EXPIRED"


class SafetyHoldStatus(str, Enum):
    ACTIVE = "ACTIVE"
    RELEASED = "RELEASED"
    EXPIRED = "EXPIRED"


class HoldAction(str, Enum):
    REQUEST_MATCHING = "REQUEST_MATCHING"
    SUBMIT_DEMAND = "SUBMIT_DEMAND"
    VERIFY_DEMAND = "VERIFY_DEMAND"


class HoldReason(str, Enum):
    PARTICIPANT_SAFETY_RISK = "PARTICIPANT_SAFETY_RISK"
    RETALIATION_RISK = "RETALIATION_RISK"
    SYNTHETIC_DATA_EXPOSURE_RISK = "SYNTHETIC_DATA_EXPOSURE_RISK"
    WORKFLOW_INTEGRITY_RISK = "WORKFLOW_INTEGRITY_RISK"


class TrustCaseOutcome(str, Enum):
    NO_ACTION = "NO_ACTION"
    PROTECTION_LIFTED = "PROTECTION_LIFTED"
    PROTECTION_MAINTAINED = "PROTECTION_MAINTAINED"
    PROTECTION_MODIFIED = "PROTECTION_MODIFIED"
    REMEDIATION_REQUIRED = "REMEDIATION_REQUIRED"


_IMPACT_CODES = frozenset(
    {
        "SYNTHETIC_DATA_DISCLOSED",
        "SYNTHETIC_FINANCIAL_RISK",
        "WORKFLOW_INTEGRITY_RISK",
        "PARTICIPANT_SAFETY_RISK",
        "RETALIATION_RISK",
    }
)
_PROTECTION_CODES = frozenset(
    {"PAUSE_SUBMISSION", "PAUSE_VERIFICATION", "PAUSE_MATCHING"}
)
_PRIORITY_CODES = frozenset({"P0", "P1", "P2", "P3"})
_JURISDICTION_CODES = frozenset(
    {"PLATFORM_INTERNAL", "ORGANIZATION_POLICY", "LEGAL_REVIEW_REQUIRED"}
)
_SEVERITY_CODES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})
_ISSUE_CODES = frozenset(
    {
        "DATA_HANDLING_GAP",
        "SCOPE_DISCLOSURE_RISK",
        "FRAUD_INDICATOR",
        "HARASSMENT_INDICATOR",
        "RETALIATION_INDICATOR",
        "WORKFLOW_INTEGRITY_GAP",
    }
)
_INVESTIGATION_STEP_CODES = frozenset(
    {
        "CHECK_ACCESS_SCOPE",
        "CHECK_DEMAND_VERSION",
        "CHECK_POLICY_REQUIREMENTS",
        "CHECK_SYNTHETIC_EVIDENCE",
        "REQUEST_PARTY_CLARIFICATION",
    }
)
_RELEASE_REASON_CODES = frozenset(
    {
        "CASE_DECIDED",
        "RISK_MITIGATED",
        "SUPERSEDED",
        "TTL_CORRECTION",
    }
)
_DECISION_REASON_CODES = frozenset(
    {
        "INSUFFICIENT_VERIFIED_EVIDENCE",
        "NO_POLICY_BREACH",
        "POLICY_REQUIREMENT_NOT_MET",
        "PRECAUTIONARY_ACTION_REQUIRED",
        "RISK_MITIGATED",
    }
)


@dataclass(frozen=True)
class SafetyReport:
    report_id: str
    case_id: str
    organization_id: str
    demand_id: str
    demand_version_id: str
    demand_version_no: int
    demand_aggregate_version: int
    demand_status: str
    demand_content_sha256: str = field(repr=False)
    reporter_party_marker_sha256: str = field(repr=False)
    target_marker_sha256: str = field(repr=False)
    reportable_until: datetime
    reporter_user_id: str = field(repr=False)
    category: ReportCategory
    incident_started_at: datetime
    incident_ended_at: Optional[datetime]
    impact_codes: Tuple[str, ...]
    evidence_reference_ids: Tuple[str, ...] = field(repr=False)
    requested_protection_codes: Tuple[str, ...]
    created_at: datetime


@dataclass(frozen=True)
class SafetyCaseAssignment:
    assignment_id: str
    case_id: str
    officer_user_id: str
    duty_grant_id: str
    duty_grant_version: int
    conflict_attestation_sha256: str = field(repr=False)
    assigned_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class SafetyCaseAssignmentRelease:
    assignment_id: str
    case_id: str
    released_by_user_id: str
    reason_code: AssignmentReleaseReason
    released_at: datetime


@dataclass(frozen=True)
class SafetyHoldReleaseAssignment:
    assignment_id: str
    hold_id: str
    case_id: str
    officer_user_id: str
    duty_grant_id: str
    duty_grant_version: int
    conflict_attestation_sha256: str = field(repr=False)
    assigned_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class TrustTriageDraft:
    case_id: str
    version: int
    priority_code: str
    jurisdiction_code: str
    severity_code: str
    issue_codes: Tuple[str, ...]
    investigation_step_codes: Tuple[str, ...]
    proposed_hold_actions: Tuple[HoldAction, ...]
    proposed_hold_ttl_minutes: int
    sealed_note_reference: str = field(repr=False)
    sealed_note_sha256: str = field(repr=False)
    edited_by_user_id: str
    edited_at: datetime


@dataclass(frozen=True)
class TrustTriageVersion:
    case_id: str
    version: int
    source_draft_version: int
    priority_code: str
    jurisdiction_code: str
    severity_code: str
    issue_codes: Tuple[str, ...]
    investigation_step_codes: Tuple[str, ...]
    proposed_hold_actions: Tuple[HoldAction, ...]
    proposed_hold_ttl_minutes: int
    sealed_note_reference: str = field(repr=False)
    sealed_note_sha256: str = field(repr=False)
    published_by_user_id: str
    published_at: datetime


@dataclass(frozen=True)
class SafetyHold:
    hold_id: str
    case_id: str
    organization_id: str
    demand_id: str
    demand_version_id: str
    action_codes: Tuple[HoldAction, ...]
    reason_code: HoldReason
    status: SafetyHoldStatus
    policy_version: str
    issued_by_user_id: str
    effective_at: datetime
    expires_at: datetime
    aggregate_version: int
    released_at: Optional[datetime]
    released_by_user_id: Optional[str]
    release_reason_code: Optional[str]
    requires_independent_release: bool
    release_assignment_id: Optional[str] = None
    release_assigned_officer_user_id: Optional[str] = None
    release_assignment_expires_at: Optional[datetime] = None


@dataclass(frozen=True)
class TrustCaseOutcomeVersion:
    outcome_version_id: str
    case_id: str
    outcome_version: int
    outcome: TrustCaseOutcome
    reason_codes: Tuple[str, ...]
    action_codes: Tuple[HoldAction, ...]
    evidence_packet_version_id: str
    evidence_packet_digest: str = field(repr=False)
    source_digest: str = field(repr=False)
    redaction_profile_code: str
    appeal_eligible: bool
    appeal_eligibility_code: str
    appeal_deadline: Optional[datetime]
    policy_version: str
    decided_by_user_id: str
    decided_at: datetime
    content_sha256: str


@dataclass(frozen=True)
class SafetyCase:
    case_id: str
    report_id: str
    organization_id: str
    demand_id: str
    demand_version_id: str
    reporter_user_id: str = field(repr=False)
    status: SafetyCaseStatus
    aggregate_version: int
    assigned_officer_user_id: Optional[str]
    assignment_id: Optional[str]
    assignment_expires_at: Optional[datetime]
    current_triage_draft_version: Optional[int]
    current_triage_version: Optional[int]
    latest_triage_draft: Optional[TrustTriageDraft] = field(
        default=None, repr=False
    )
    outcome_version_id: Optional[str] = None
    opened_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def open_report(
        cls,
        *,
        case_id: str,
        report_id: str,
        organization_id: str,
        demand_id: str,
        demand_version_id: str,
        demand_version_no: int,
        demand_aggregate_version: int,
        demand_status: str,
        demand_content_sha256: str,
        reporter_party_marker_sha256: str,
        target_marker_sha256: str,
        reportable_until: datetime,
        reporter_user_id: str,
        category: ReportCategory,
        incident_started_at: datetime,
        incident_ended_at: Optional[datetime],
        impact_codes: Tuple[str, ...],
        evidence_reference_ids: Tuple[str, ...],
        requested_protection_codes: Tuple[str, ...],
        now: datetime,
    ) -> tuple["SafetyCase", SafetyReport]:
        identifiers = tuple(
            _uuid(value)
            for value in (
                case_id,
                report_id,
                organization_id,
                demand_id,
                demand_version_id,
                reporter_user_id,
            )
        )
        if len(set(identifiers)) != len(identifiers):
            _reject("REPORT_VALIDATION_FAILED")
        if not isinstance(category, ReportCategory):
            _reject("REPORT_VALIDATION_FAILED")
        if (
            type(demand_version_no) is not int
            or demand_version_no < 1
            or type(demand_aggregate_version) is not int
            or demand_aggregate_version < 1
            or demand_status not in {
                "SUBMITTED",
                "NEEDS_CHANGES",
                "VERIFIED",
                "FUNDING_PENDING",
                "FUNDED",
                "MATCHING",
                "MATCHED",
                "NO_MATCH",
            }
        ):
            _reject("REPORT_VALIDATION_FAILED")
        _digest(demand_content_sha256, "REPORT_VALIDATION_FAILED")
        _digest(reporter_party_marker_sha256, "REPORT_VALIDATION_FAILED")
        _digest(target_marker_sha256, "REPORT_VALIDATION_FAILED")
        current = _utc(now)
        reportable_deadline = _utc(reportable_until)
        if reportable_deadline <= current:
            _reject("REPORT_VALIDATION_FAILED")
        started = _utc(incident_started_at)
        ended = None if incident_ended_at is None else _utc(incident_ended_at)
        if started > current or (ended is not None and (ended < started or ended > current)):
            _reject("REPORT_VALIDATION_FAILED")
        impacts = _closed_codes(impact_codes, _IMPACT_CODES, "REPORT_VALIDATION_FAILED")
        protections = _closed_codes(
            requested_protection_codes,
            _PROTECTION_CODES,
            "REPORT_VALIDATION_FAILED",
        )
        evidence = _identifiers(evidence_reference_ids, "REPORT_VALIDATION_FAILED")
        report = SafetyReport(
            report_id=report_id,
            case_id=case_id,
            organization_id=organization_id,
            demand_id=demand_id,
            demand_version_id=demand_version_id,
            demand_version_no=demand_version_no,
            demand_aggregate_version=demand_aggregate_version,
            demand_status=demand_status,
            demand_content_sha256=demand_content_sha256,
            reporter_party_marker_sha256=reporter_party_marker_sha256,
            target_marker_sha256=target_marker_sha256,
            reportable_until=reportable_deadline,
            reporter_user_id=reporter_user_id,
            category=category,
            incident_started_at=started,
            incident_ended_at=ended,
            impact_codes=impacts,
            evidence_reference_ids=evidence,
            requested_protection_codes=protections,
            created_at=current,
        )
        case = cls(
            case_id=case_id,
            report_id=report_id,
            organization_id=organization_id,
            demand_id=demand_id,
            demand_version_id=demand_version_id,
            reporter_user_id=reporter_user_id,
            status=SafetyCaseStatus.OPEN,
            aggregate_version=1,
            assigned_officer_user_id=None,
            assignment_id=None,
            assignment_expires_at=None,
            current_triage_draft_version=None,
            current_triage_version=None,
            opened_at=current,
            updated_at=current,
        )
        return case, report

    def claim(
        self,
        *,
        assignment_id: str,
        officer_user_id: str,
        duty_grant_id: str,
        duty_grant_version: int,
        conflict_attestation_sha256: str,
        expires_at: datetime,
        now: datetime,
    ) -> tuple["SafetyCase", SafetyCaseAssignment]:
        if self.status is not SafetyCaseStatus.OPEN or self.assignment_id is not None:
            _reject("CASE_ALREADY_ASSIGNED")
        _uuid(assignment_id)
        _uuid(officer_user_id)
        _uuid(duty_grant_id)
        if type(duty_grant_version) is not int or duty_grant_version < 1:
            _reject("CASE_ASSIGNMENT_INVALID")
        _digest(conflict_attestation_sha256, "CASE_ASSIGNMENT_INVALID")
        assigned_at = _utc(now)
        deadline = _utc(expires_at)
        if deadline <= assigned_at:
            _reject("CASE_ASSIGNMENT_INVALID")
        assignment = SafetyCaseAssignment(
            assignment_id=assignment_id,
            case_id=self.case_id,
            officer_user_id=officer_user_id,
            duty_grant_id=duty_grant_id,
            duty_grant_version=duty_grant_version,
            conflict_attestation_sha256=conflict_attestation_sha256,
            assigned_at=assigned_at,
            expires_at=deadline,
        )
        return (
            replace(
                self,
                status=SafetyCaseStatus.TRIAGING,
                aggregate_version=self.aggregate_version + 1,
                assigned_officer_user_id=officer_user_id,
                assignment_id=assignment_id,
                assignment_expires_at=deadline,
                updated_at=assigned_at,
            ),
            assignment,
        )

    def claim_hold_release(
        self,
        *,
        hold: SafetyHold,
        assignment_id: str,
        officer_user_id: str,
        duty_grant_id: str,
        duty_grant_version: int,
        conflict_attestation_sha256: str,
        expires_at: datetime,
        now: datetime,
    ) -> tuple[SafetyHold, SafetyHoldReleaseAssignment]:
        if not isinstance(hold, SafetyHold) or hold.case_id != self.case_id:
            _reject("HOLD_NOT_FOUND")
        current = _utc(now)
        if (
            self.status is not SafetyCaseStatus.IN_REVIEW
            or hold.status is not SafetyHoldStatus.ACTIVE
            or current >= hold.expires_at
            or not hold.requires_independent_release
        ):
            _reject("HOLD_STATE_CONFLICT")
        if officer_user_id == hold.issued_by_user_id:
            _reject("INDEPENDENT_REVIEW_REQUIRED")
        if (
            hold.release_assignment_id is not None
            and hold.release_assignment_expires_at is not None
            and current < hold.release_assignment_expires_at
        ):
            _reject("HOLD_RELEASE_ALREADY_ASSIGNED")
        _uuid(assignment_id)
        _uuid(officer_user_id)
        _uuid(duty_grant_id)
        if type(duty_grant_version) is not int or duty_grant_version < 1:
            _reject("HOLD_RELEASE_ASSIGNMENT_INVALID")
        _digest(
            conflict_attestation_sha256,
            "HOLD_RELEASE_ASSIGNMENT_INVALID",
        )
        deadline = _utc(expires_at)
        if (
            deadline <= current
            or deadline > current + timedelta(days=1)
            or deadline > hold.expires_at
        ):
            _reject("HOLD_RELEASE_ASSIGNMENT_INVALID")
        assignment = SafetyHoldReleaseAssignment(
            assignment_id=assignment_id,
            hold_id=hold.hold_id,
            case_id=self.case_id,
            officer_user_id=officer_user_id,
            duty_grant_id=duty_grant_id,
            duty_grant_version=duty_grant_version,
            conflict_attestation_sha256=conflict_attestation_sha256,
            assigned_at=current,
            expires_at=deadline,
        )
        return (
            replace(
                hold,
                aggregate_version=hold.aggregate_version + 1,
                release_assignment_id=assignment_id,
                release_assigned_officer_user_id=officer_user_id,
                release_assignment_expires_at=deadline,
            ),
            assignment,
        )

    def save_triage_draft(
        self,
        *,
        officer_user_id: str,
        priority_code: str,
        jurisdiction_code: str,
        severity_code: str,
        issue_codes: Tuple[str, ...],
        investigation_step_codes: Tuple[str, ...],
        proposed_hold_actions: Tuple[HoldAction, ...],
        proposed_hold_ttl_minutes: int,
        sealed_note_reference: str,
        sealed_note_sha256: str,
        now: datetime,
    ) -> tuple["SafetyCase", TrustTriageDraft]:
        if self.status is not SafetyCaseStatus.TRIAGING:
            _reject(
                "TRIAGE_ALREADY_PUBLISHED"
                if self.current_triage_version is not None
                else "CASE_STATE_CONFLICT"
            )
        current = self._assigned(officer_user_id, now)
        if priority_code not in _PRIORITY_CODES:
            _reject("TRIAGE_VALIDATION_FAILED")
        if jurisdiction_code not in _JURISDICTION_CODES:
            _reject("TRIAGE_VALIDATION_FAILED")
        if severity_code not in _SEVERITY_CODES:
            _reject("TRIAGE_VALIDATION_FAILED")
        issues = _closed_codes(issue_codes, _ISSUE_CODES, "TRIAGE_VALIDATION_FAILED")
        steps = _closed_codes(
            investigation_step_codes,
            _INVESTIGATION_STEP_CODES,
            "TRIAGE_VALIDATION_FAILED",
        )
        actions = _enum_tuple(
            proposed_hold_actions,
            HoldAction,
            "TRIAGE_VALIDATION_FAILED",
        )
        if (
            type(proposed_hold_ttl_minutes) is not int
            or not 15 <= proposed_hold_ttl_minutes <= 10_080
            or not isinstance(sealed_note_reference, str)
            or _SEALED_REFERENCE.fullmatch(sealed_note_reference) is None
        ):
            _reject("TRIAGE_VALIDATION_FAILED")
        _digest(sealed_note_sha256, "TRIAGE_VALIDATION_FAILED")
        version = (self.current_triage_draft_version or 0) + 1
        draft = TrustTriageDraft(
            case_id=self.case_id,
            version=version,
            priority_code=priority_code,
            jurisdiction_code=jurisdiction_code,
            severity_code=severity_code,
            issue_codes=issues,
            investigation_step_codes=steps,
            proposed_hold_actions=actions,
            proposed_hold_ttl_minutes=proposed_hold_ttl_minutes,
            sealed_note_reference=sealed_note_reference,
            sealed_note_sha256=sealed_note_sha256,
            edited_by_user_id=officer_user_id,
            edited_at=current,
        )
        return (
            replace(
                self,
                aggregate_version=self.aggregate_version + 1,
                current_triage_draft_version=version,
                latest_triage_draft=draft,
                updated_at=current,
            ),
            draft,
        )

    def release_assignment(
        self,
        *,
        requester_user_id: str,
        reason_code: AssignmentReleaseReason,
        now: datetime,
    ) -> tuple["SafetyCase", SafetyCaseAssignmentRelease]:
        if (
            self.status is not SafetyCaseStatus.TRIAGING
            or self.assignment_id is None
            or self.assigned_officer_user_id is None
            or self.assignment_expires_at is None
        ):
            _reject("CASE_ASSIGNMENT_REQUIRED")
        _uuid(requester_user_id)
        if not isinstance(reason_code, AssignmentReleaseReason):
            _reject("ASSIGNMENT_RELEASE_VALIDATION_FAILED")
        current = _utc(now)
        if reason_code is AssignmentReleaseReason.ASSIGNMENT_EXPIRED:
            if current < self.assignment_expires_at:
                _reject("ASSIGNMENT_NOT_EXPIRED")
        elif requester_user_id != self.assigned_officer_user_id:
            _reject("CASE_ASSIGNMENT_REQUIRED")
        released = SafetyCaseAssignmentRelease(
            assignment_id=self.assignment_id,
            case_id=self.case_id,
            released_by_user_id=requester_user_id,
            reason_code=reason_code,
            released_at=current,
        )
        return (
            replace(
                self,
                status=SafetyCaseStatus.OPEN,
                aggregate_version=self.aggregate_version + 1,
                assigned_officer_user_id=None,
                assignment_id=None,
                assignment_expires_at=None,
                current_triage_draft_version=None,
                latest_triage_draft=None,
                updated_at=current,
            ),
            released,
        )

    def publish_triage(
        self,
        *,
        officer_user_id: str,
        expected_draft_version: int,
        now: datetime,
    ) -> tuple["SafetyCase", TrustTriageVersion]:
        if self.status is not SafetyCaseStatus.TRIAGING:
            _reject("CASE_STATE_CONFLICT")
        current = self._assigned(officer_user_id, now)
        draft = self.latest_triage_draft
        if (
            draft is None
            or type(expected_draft_version) is not int
            or expected_draft_version != draft.version
        ):
            _reject("TRIAGE_VERSION_CONFLICT")
        version = (self.current_triage_version or 0) + 1
        published = TrustTriageVersion(
            case_id=self.case_id,
            version=version,
            source_draft_version=draft.version,
            priority_code=draft.priority_code,
            jurisdiction_code=draft.jurisdiction_code,
            severity_code=draft.severity_code,
            issue_codes=draft.issue_codes,
            investigation_step_codes=draft.investigation_step_codes,
            proposed_hold_actions=draft.proposed_hold_actions,
            proposed_hold_ttl_minutes=draft.proposed_hold_ttl_minutes,
            sealed_note_reference=draft.sealed_note_reference,
            sealed_note_sha256=draft.sealed_note_sha256,
            published_by_user_id=officer_user_id,
            published_at=current,
        )
        return (
            replace(
                self,
                status=SafetyCaseStatus.IN_REVIEW,
                aggregate_version=self.aggregate_version + 1,
                current_triage_version=version,
                updated_at=current,
            ),
            published,
        )

    def place_hold(
        self,
        *,
        hold_id: str,
        officer_user_id: str,
        action_codes: Tuple[HoldAction, ...],
        reason_code: HoldReason,
        expires_at: datetime,
        policy_version: str,
        now: datetime,
    ) -> tuple["SafetyCase", SafetyHold]:
        if self.status is not SafetyCaseStatus.IN_REVIEW:
            _reject("CASE_STATE_CONFLICT")
        current = self._assigned(officer_user_id, now)
        _uuid(hold_id)
        actions = _enum_tuple(action_codes, HoldAction, "HOLD_VALIDATION_FAILED")
        if not isinstance(reason_code, HoldReason):
            _reject("HOLD_VALIDATION_FAILED")
        deadline = _utc(expires_at)
        if deadline <= current or deadline > current + timedelta(days=365):
            _reject("HOLD_VALIDATION_FAILED")
        _closed_text(policy_version, "HOLD_VALIDATION_FAILED")
        hold = SafetyHold(
            hold_id=hold_id,
            case_id=self.case_id,
            organization_id=self.organization_id,
            demand_id=self.demand_id,
            demand_version_id=self.demand_version_id,
            action_codes=actions,
            reason_code=reason_code,
            status=SafetyHoldStatus.ACTIVE,
            policy_version=policy_version,
            issued_by_user_id=officer_user_id,
            effective_at=current,
            expires_at=deadline,
            aggregate_version=1,
            released_at=None,
            released_by_user_id=None,
            release_reason_code=None,
            requires_independent_release=reason_code
            in {
                HoldReason.PARTICIPANT_SAFETY_RISK,
                HoldReason.RETALIATION_RISK,
            },
        )
        return (
            replace(
                self,
                aggregate_version=self.aggregate_version + 1,
                updated_at=current,
            ),
            hold,
        )

    def release_hold(
        self,
        *,
        hold: SafetyHold,
        officer_user_id: str,
        release_reason_code: str,
        independent_assignment: Optional[SafetyHoldReleaseAssignment] = None,
        now: datetime,
    ) -> tuple["SafetyCase", SafetyHold]:
        if not isinstance(hold, SafetyHold) or hold.case_id != self.case_id:
            _reject("HOLD_NOT_FOUND")
        current = _utc(now)
        _uuid(officer_user_id)
        if hold.status is not SafetyHoldStatus.ACTIVE or current >= hold.expires_at:
            _reject("HOLD_STATE_CONFLICT")
        if release_reason_code not in _RELEASE_REASON_CODES:
            _reject("HOLD_RELEASE_VALIDATION_FAILED")
        if hold.requires_independent_release:
            if not _valid_independent_assignment(
                independent_assignment,
                case_id=self.case_id,
                hold_id=hold.hold_id,
                officer_user_id=officer_user_id,
                excluded_officer_user_id=hold.issued_by_user_id,
                now=current,
            ) or (
                independent_assignment is None
                or hold.release_assignment_id
                != independent_assignment.assignment_id
                or hold.release_assigned_officer_user_id
                != independent_assignment.officer_user_id
                or hold.release_assignment_expires_at
                != independent_assignment.expires_at
            ):
                _reject("INDEPENDENT_REVIEW_REQUIRED")
        else:
            self._assigned(officer_user_id, current)
        released = replace(
            hold,
            status=SafetyHoldStatus.RELEASED,
            aggregate_version=hold.aggregate_version + 1,
            released_at=current,
            released_by_user_id=officer_user_id,
            release_reason_code=release_reason_code,
        )
        return (
            replace(
                self,
                aggregate_version=self.aggregate_version + 1,
                updated_at=current,
            ),
            released,
        )

    def record_initial_outcome(
        self,
        *,
        outcome_version_id: str,
        officer_user_id: str,
        outcome: TrustCaseOutcome,
        reason_codes: Tuple[str, ...],
        action_codes: Tuple[HoldAction, ...],
        evidence_packet_version_id: str,
        evidence_packet_digest: str,
        source_digest: str,
        redaction_profile_code: str,
        appeal_eligible: bool,
        appeal_eligibility_code: str,
        appeal_deadline: Optional[datetime],
        policy_version: str,
        now: datetime,
    ) -> tuple["SafetyCase", TrustCaseOutcomeVersion]:
        if self.status is not SafetyCaseStatus.IN_REVIEW or self.outcome_version_id is not None:
            _reject("CASE_STATE_CONFLICT")
        current = self._assigned(officer_user_id, now)
        _uuid(outcome_version_id)
        _uuid(evidence_packet_version_id)
        if not isinstance(outcome, TrustCaseOutcome):
            _reject("CASE_DECISION_VALIDATION_FAILED")
        reasons = _closed_codes(
            reason_codes,
            _DECISION_REASON_CODES,
            "CASE_DECISION_VALIDATION_FAILED",
        )
        actions = _enum_tuple(
            action_codes,
            HoldAction,
            "CASE_DECISION_VALIDATION_FAILED",
            allow_empty=True,
        )
        if outcome in {TrustCaseOutcome.NO_ACTION, TrustCaseOutcome.PROTECTION_LIFTED}:
            if actions:
                _reject("CASE_DECISION_VALIDATION_FAILED")
        elif not actions:
            _reject("CASE_DECISION_VALIDATION_FAILED")
        _digest(evidence_packet_digest, "CASE_DECISION_VALIDATION_FAILED")
        _digest(source_digest, "CASE_DECISION_VALIDATION_FAILED")
        if redaction_profile_code not in {
            "OFFICER_RESTRICTED_V1",
            "PARTY_SAFE_V1",
        }:
            _reject("CASE_DECISION_VALIDATION_FAILED")
        _closed_text(policy_version, "CASE_DECISION_VALIDATION_FAILED")
        if (
            type(appeal_eligible) is not bool
            or appeal_eligibility_code not in {"ELIGIBLE", "NOT_ELIGIBLE"}
            or appeal_eligible != (appeal_eligibility_code == "ELIGIBLE")
        ):
            _reject("CASE_DECISION_VALIDATION_FAILED")
        deadline = None if appeal_deadline is None else _utc(appeal_deadline)
        if appeal_eligible:
            if deadline is None or deadline <= current:
                _reject("CASE_DECISION_VALIDATION_FAILED")
        elif deadline is not None:
            _reject("CASE_DECISION_VALIDATION_FAILED")
        payload = {
            "appeal_deadline": None if deadline is None else _iso(deadline),
            "appeal_eligible": appeal_eligible,
            "appeal_eligibility_code": appeal_eligibility_code,
            "action_codes": [value.value for value in actions],
            "case_id": self.case_id,
            "evidence_packet_digest": evidence_packet_digest,
            "evidence_packet_version_id": evidence_packet_version_id,
            "outcome": outcome.value,
            "outcome_version": 1,
            "policy_version": policy_version,
            "reason_codes": list(reasons),
            "redaction_profile_code": redaction_profile_code,
            "source_digest": source_digest,
        }
        digest = hashlib.sha256(
            json.dumps(
                payload,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        ).hexdigest()
        decision = TrustCaseOutcomeVersion(
            outcome_version_id=outcome_version_id,
            case_id=self.case_id,
            outcome_version=1,
            outcome=outcome,
            reason_codes=reasons,
            action_codes=actions,
            evidence_packet_version_id=evidence_packet_version_id,
            evidence_packet_digest=evidence_packet_digest,
            source_digest=source_digest,
            redaction_profile_code=redaction_profile_code,
            appeal_eligible=appeal_eligible,
            appeal_eligibility_code=appeal_eligibility_code,
            appeal_deadline=deadline,
            policy_version=policy_version,
            decided_by_user_id=officer_user_id,
            decided_at=current,
            content_sha256=digest,
        )
        return (
            replace(
                self,
                status=SafetyCaseStatus.DECIDED,
                aggregate_version=self.aggregate_version + 1,
                outcome_version_id=outcome_version_id,
                updated_at=current,
            ),
            decision,
        )

    def _assigned(self, officer_user_id: str, now: datetime) -> datetime:
        _uuid(officer_user_id)
        current = _utc(now)
        if (
            self.assigned_officer_user_id != officer_user_id
            or self.assignment_id is None
            or self.assignment_expires_at is None
            or current >= self.assignment_expires_at
        ):
            _reject("CASE_ASSIGNMENT_REQUIRED")
        return current


def _reject(code: str) -> None:
    raise TrustDomainError(code)


def _valid_independent_assignment(
    assignment: object,
    *,
    case_id: str,
    hold_id: str,
    officer_user_id: str,
    excluded_officer_user_id: str,
    now: datetime,
) -> bool:
    if not isinstance(assignment, SafetyHoldReleaseAssignment):
        return False
    try:
        _uuid(assignment.assignment_id)
        _uuid(assignment.hold_id)
        _uuid(assignment.case_id)
        _uuid(assignment.officer_user_id)
        _uuid(assignment.duty_grant_id)
        _digest(assignment.conflict_attestation_sha256, "CASE_ASSIGNMENT_INVALID")
        assigned_at = _utc(assignment.assigned_at)
        expires_at = _utc(assignment.expires_at)
    except TrustDomainError:
        return False
    return (
        assignment.case_id == case_id
        and assignment.hold_id == hold_id
        and assignment.officer_user_id == officer_user_id
        and assignment.officer_user_id != excluded_officer_user_id
        and type(assignment.duty_grant_version) is int
        and assignment.duty_grant_version >= 1
        and assigned_at <= now < expires_at
    )


def _uuid(value: object) -> str:
    try:
        parsed = UUID(str(value))
    except (TypeError, ValueError, AttributeError):
        _reject("IDENTIFIER_INVALID")
    if parsed.int == 0 or str(parsed) != str(value):
        _reject("IDENTIFIER_INVALID")
    return str(parsed)


def _utc(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _reject("TIME_INVALID")
    converted = value.astimezone(timezone.utc)
    if value.utcoffset() != timezone.utc.utcoffset(value):
        _reject("TIME_INVALID")
    return converted


def _digest(value: object, code: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _reject(code)
    return value


def _identifiers(values: object, code: str) -> Tuple[str, ...]:
    if not isinstance(values, tuple) or not values:
        _reject(code)
    normalized = tuple(sorted((_uuid(value) for value in values), key=lambda item: item.encode("utf-8")))
    if len(normalized) != len(set(normalized)) or len(normalized) > 32:
        _reject(code)
    return normalized


def _closed_codes(values: object, allowed: frozenset[str], code: str) -> Tuple[str, ...]:
    if not isinstance(values, tuple) or not values or len(values) > 32:
        _reject(code)
    if any(not isinstance(value, str) or value not in allowed for value in values):
        _reject(code)
    normalized = tuple(sorted(values, key=lambda item: item.encode("utf-8")))
    if len(normalized) != len(set(normalized)):
        _reject(code)
    return normalized


_EnumT = TypeVar("_EnumT", bound=Enum)


def _enum_tuple(
    values: object,
    enum_type: type[_EnumT],
    code: str,
    *,
    allow_empty: bool = False,
) -> Tuple[_EnumT, ...]:
    if (
        not isinstance(values, tuple)
        or (not allow_empty and not values)
        or len(values) > 8
    ):
        _reject(code)
    if any(not isinstance(value, enum_type) for value in values):
        _reject(code)
    normalized = tuple(sorted(values, key=lambda item: str(item.value).encode("utf-8")))
    if len(normalized) != len(set(normalized)):
        _reject(code)
    return normalized


def _closed_text(value: object, code: str) -> str:
    if not isinstance(value, str) or _CODE.fullmatch(value.upper().replace("-", "_")) is None:
        _reject(code)
    if not 3 <= len(value) <= 128:
        _reject(code)
    return value


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
