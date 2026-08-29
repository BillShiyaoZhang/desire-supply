"""Immutable Appeal facts bound to a frozen Trust outcome version.

Appeal is not a mutable flag on a Trust case.  The applicant edits a draft
against one immutable source outcome, freezes it by submitting, and an
independently assigned reviewer creates a separate review draft and final
decision.  Sensitive statements and evidence are represented only by sealed
or opaque references in this domain.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
from typing import Optional, Tuple
from uuid import UUID


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SEALED_REFERENCE = re.compile(r"sealed://trust/[a-z0-9][a-z0-9/_-]{4,255}\Z")
_POLICY_VERSION = re.compile(r"[a-z][a-z0-9._-]{2,95}\Z")


class AppealDomainError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class AppealStatus(str, Enum):
    DRAFT = "DRAFT"
    SUBMITTED = "SUBMITTED"
    IN_REVIEW = "IN_REVIEW"
    DECIDED = "DECIDED"
    WITHDRAWN = "WITHDRAWN"


class AppealGround(str, Enum):
    PROCEDURAL_ERROR = "PROCEDURAL_ERROR"
    NEW_MATERIAL_EVIDENCE = "NEW_MATERIAL_EVIDENCE"
    RULE_MISAPPLICATION = "RULE_MISAPPLICATION"


class RequestedAppealOutcome(str, Enum):
    REMOVE_MEASURE = "REMOVE_MEASURE"
    MODIFY_MEASURE = "MODIFY_MEASURE"
    VACATE_AND_REMAND = "VACATE_AND_REMAND"


class AppealGroundAssessmentCode(str, Enum):
    ACCEPTED = "ACCEPTED"
    PARTIALLY_ACCEPTED = "PARTIALLY_ACCEPTED"
    REJECTED = "REJECTED"


class AppealDecisionCode(str, Enum):
    AFFIRM = "AFFIRM"
    MODIFY = "MODIFY"
    VACATE_AND_REMAND = "VACATE_AND_REMAND"
    DISMISS = "DISMISS"


class AppealAssignmentReleaseReason(str, Enum):
    CONFLICT_DECLARED = "CONFLICT_DECLARED"
    WORKLOAD_RELEASE = "WORKLOAD_RELEASE"
    ASSIGNMENT_EXPIRED = "ASSIGNMENT_EXPIRED"


_REVIEW_FINDING_CODES = frozenset(
    {
        "PROCEDURE_MATERIAL_ERROR",
        "NEW_EVIDENCE_MATERIAL",
        "RULE_APPLIED_CORRECTLY",
        "RULE_APPLICATION_ERROR",
        "APPEAL_NOT_SUBSTANTIATED",
    }
)
_REVIEW_REASON_CODES = frozenset(
    {
        "SOURCE_OUTCOME_SUPPORTED",
        "SOURCE_OUTCOME_UNSUPPORTED",
        "PROCEDURAL_REVIEW_COMPLETE",
        "NEW_EVIDENCE_REVIEWED",
        "REMAND_REQUIRED",
        "APPEAL_SCOPE_INVALID",
    }
)
_REMEDY_DELTA_CODES = frozenset(
    {
        "NO_CHANGE",
        "REMOVE_CORRECTIVE_MEASURE",
        "NARROW_CORRECTIVE_MEASURE",
        "REPLACE_CORRECTIVE_MEASURE",
        "RETURN_TO_TRUST_REVIEW",
    }
)
_SOURCE_OUTCOME_CODES = frozenset(
    {
        "NO_ACTION",
        "PROTECTION_LIFTED",
        "PROTECTION_MAINTAINED",
        "PROTECTION_MODIFIED",
        "REMEDIATION_REQUIRED",
    }
)
_SOURCE_REASON_CODES = frozenset(
    {
        "INSUFFICIENT_VERIFIED_EVIDENCE",
        "NO_POLICY_BREACH",
        "POLICY_REQUIREMENT_NOT_MET",
        "PRECAUTIONARY_ACTION_REQUIRED",
        "RISK_MITIGATED",
    }
)
_SOURCE_ACTION_CODES = frozenset(
    {"REQUEST_MATCHING", "SUBMIT_DEMAND", "VERIFY_DEMAND"}
)


@dataclass(frozen=True)
class TrustCaseOutcomeSource:
    outcome_version_id: str
    case_id: str
    organization_id: str
    demand_id: str
    demand_version_id: str
    outcome_code: str
    reason_codes: Tuple[str, ...]
    action_codes: Tuple[str, ...]
    evidence_packet_version_id: str
    evidence_packet_sha256: str = field(repr=False)
    policy_version: str
    decided_at: datetime
    appeal_eligible: bool
    appeal_eligibility_code: str
    appeal_deadline: Optional[datetime]
    content_sha256: str


@dataclass(frozen=True)
class AppealApplicationDraft:
    appeal_id: str
    version: int
    grounds: Tuple[AppealGround, ...]
    requested_outcome: RequestedAppealOutcome
    sealed_statement_reference: str = field(repr=False)
    sealed_statement_sha256: str = field(repr=False)
    new_evidence_reference_ids: Tuple[str, ...] = field(repr=False)
    edited_by_user_id: str = field(repr=False)
    edited_at: datetime


@dataclass(frozen=True)
class AppealApplicationVersion:
    appeal_id: str
    version: int
    source_draft_version: int
    grounds: Tuple[AppealGround, ...]
    requested_outcome: RequestedAppealOutcome
    sealed_statement_reference: str = field(repr=False)
    sealed_statement_sha256: str = field(repr=False)
    new_evidence_reference_ids: Tuple[str, ...] = field(repr=False)
    submitted_by_user_id: str = field(repr=False)
    submitted_at: datetime


@dataclass(frozen=True)
class AppealReviewAssignment:
    assignment_id: str
    appeal_id: str
    reviewer_user_id: str = field(repr=False)
    duty_grant_id: str = field(repr=False)
    duty_grant_version: int = field(repr=False)
    conflict_attestation_sha256: str = field(repr=False)
    assigned_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class AppealAssignmentRelease:
    assignment_id: str
    appeal_id: str
    released_by_user_id: str = field(repr=False)
    reason_code: AppealAssignmentReleaseReason
    released_at: datetime


@dataclass(frozen=True)
class AppealGroundAssessment:
    ground: AppealGround
    assessment_code: AppealGroundAssessmentCode
    finding_codes: Tuple[str, ...]
    accepted_evidence_reference_ids: Tuple[str, ...] = field(repr=False)


@dataclass(frozen=True)
class AppealReviewDraft:
    appeal_id: str
    version: int
    assessments: Tuple[AppealGroundAssessment, ...]
    reason_codes: Tuple[str, ...]
    remedy_delta_codes: Tuple[str, ...]
    sealed_review_note_reference: str = field(repr=False)
    sealed_review_note_sha256: str = field(repr=False)
    edited_by_user_id: str = field(repr=False)
    edited_at: datetime


@dataclass(frozen=True)
class AppealDecisionVersion:
    decision_version_id: str
    appeal_id: str
    version: int
    source_outcome_version_id: str
    source_outcome_sha256: str
    source_application_version: int
    source_review_draft_version: int
    decision_code: AppealDecisionCode
    assessments: Tuple[AppealGroundAssessment, ...]
    reason_codes: Tuple[str, ...]
    remedy_delta_codes: Tuple[str, ...]
    policy_version: str
    decided_by_user_id: str = field(repr=False)
    decided_at: datetime
    decision_sha256: str


@dataclass(frozen=True)
class Appeal:
    appeal_id: str
    source: TrustCaseOutcomeSource = field(repr=False)
    applicant_user_id: str = field(repr=False)
    status: AppealStatus
    aggregate_version: int
    current_application_draft_version: Optional[int]
    submitted_application_version: Optional[int]
    latest_application_draft: Optional[AppealApplicationDraft] = field(
        default=None,
        repr=False,
    )
    assignment: Optional[AppealReviewAssignment] = field(default=None, repr=False)
    current_review_draft_version: Optional[int] = None
    latest_review_draft: Optional[AppealReviewDraft] = field(default=None, repr=False)
    decision_version_id: Optional[str] = None
    opened_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def open(
        cls,
        *,
        appeal_id: str,
        source: TrustCaseOutcomeSource,
        applicant_user_id: str,
        applicant_is_party: bool,
        now: datetime,
    ) -> "Appeal":
        _uuid(appeal_id)
        _uuid(applicant_user_id)
        _validate_source(source)
        current = _utc(now)
        if (
            type(applicant_is_party) is not bool
            or not applicant_is_party
            or not source.appeal_eligible
            or source.appeal_deadline is None
            or current >= source.appeal_deadline
        ):
            _reject("APPEAL_NOT_AVAILABLE")
        return cls(
            appeal_id=appeal_id,
            source=source,
            applicant_user_id=applicant_user_id,
            status=AppealStatus.DRAFT,
            aggregate_version=1,
            current_application_draft_version=None,
            submitted_application_version=None,
            opened_at=current,
            updated_at=current,
        )

    def save_application_draft(
        self,
        *,
        applicant_user_id: str,
        grounds: Tuple[AppealGround, ...],
        requested_outcome: RequestedAppealOutcome,
        sealed_statement_reference: str,
        sealed_statement_sha256: str,
        new_evidence_reference_ids: Tuple[str, ...],
        now: datetime,
    ) -> tuple["Appeal", AppealApplicationDraft]:
        if self.status is not AppealStatus.DRAFT:
            _reject("APPEAL_APPLICATION_FROZEN")
        current = self._applicant(applicant_user_id, now)
        if current >= self.source.appeal_deadline:  # type: ignore[operator]
            _reject("APPEAL_DEADLINE_PASSED")
        normalized_grounds = _enum_tuple(
            grounds,
            AppealGround,
            "APPEAL_APPLICATION_INVALID",
        )
        if not isinstance(requested_outcome, RequestedAppealOutcome):
            _reject("APPEAL_APPLICATION_INVALID")
        _sealed(
            sealed_statement_reference,
            sealed_statement_sha256,
            "APPEAL_APPLICATION_INVALID",
        )
        evidence = _identifiers(
            new_evidence_reference_ids,
            "APPEAL_APPLICATION_INVALID",
            allow_empty=True,
        )
        if AppealGround.NEW_MATERIAL_EVIDENCE in normalized_grounds and not evidence:
            _reject("APPEAL_APPLICATION_INVALID")
        version = (self.current_application_draft_version or 0) + 1
        draft = AppealApplicationDraft(
            appeal_id=self.appeal_id,
            version=version,
            grounds=normalized_grounds,
            requested_outcome=requested_outcome,
            sealed_statement_reference=sealed_statement_reference,
            sealed_statement_sha256=sealed_statement_sha256,
            new_evidence_reference_ids=evidence,
            edited_by_user_id=applicant_user_id,
            edited_at=current,
        )
        return (
            replace(
                self,
                aggregate_version=self.aggregate_version + 1,
                current_application_draft_version=version,
                latest_application_draft=draft,
                updated_at=current,
            ),
            draft,
        )

    def submit(
        self,
        *,
        applicant_user_id: str,
        expected_draft_version: int,
        now: datetime,
    ) -> tuple["Appeal", AppealApplicationVersion]:
        if self.status is not AppealStatus.DRAFT:
            _reject("APPEAL_STATE_CONFLICT")
        current = self._applicant(applicant_user_id, now)
        if current >= self.source.appeal_deadline:  # type: ignore[operator]
            _reject("APPEAL_DEADLINE_PASSED")
        draft = self.latest_application_draft
        if (
            draft is None
            or type(expected_draft_version) is not int
            or expected_draft_version != draft.version
        ):
            _reject("APPEAL_DRAFT_VERSION_CONFLICT")
        submitted = AppealApplicationVersion(
            appeal_id=self.appeal_id,
            version=1,
            source_draft_version=draft.version,
            grounds=draft.grounds,
            requested_outcome=draft.requested_outcome,
            sealed_statement_reference=draft.sealed_statement_reference,
            sealed_statement_sha256=draft.sealed_statement_sha256,
            new_evidence_reference_ids=draft.new_evidence_reference_ids,
            submitted_by_user_id=applicant_user_id,
            submitted_at=current,
        )
        return (
            replace(
                self,
                status=AppealStatus.SUBMITTED,
                aggregate_version=self.aggregate_version + 1,
                submitted_application_version=1,
                updated_at=current,
            ),
            submitted,
        )

    def claim(
        self,
        *,
        assignment_id: str,
        reviewer_user_id: str,
        duty_grant_id: str,
        duty_grant_version: int,
        conflict_attestation_sha256: str,
        expires_at: datetime,
        now: datetime,
    ) -> tuple["Appeal", AppealReviewAssignment]:
        if self.status is not AppealStatus.SUBMITTED or self.assignment is not None:
            _reject("APPEAL_ALREADY_ASSIGNED")
        _uuid(assignment_id)
        _uuid(reviewer_user_id)
        _uuid(duty_grant_id)
        if (
            reviewer_user_id == self.applicant_user_id
            or type(duty_grant_version) is not int
            or duty_grant_version < 1
        ):
            _reject("APPEAL_ASSIGNMENT_INVALID")
        _digest(conflict_attestation_sha256, "APPEAL_ASSIGNMENT_INVALID")
        current = _utc(now)
        deadline = _utc(expires_at)
        if deadline <= current:
            _reject("APPEAL_ASSIGNMENT_INVALID")
        assignment = AppealReviewAssignment(
            assignment_id=assignment_id,
            appeal_id=self.appeal_id,
            reviewer_user_id=reviewer_user_id,
            duty_grant_id=duty_grant_id,
            duty_grant_version=duty_grant_version,
            conflict_attestation_sha256=conflict_attestation_sha256,
            assigned_at=current,
            expires_at=deadline,
        )
        return (
            replace(
                self,
                status=AppealStatus.IN_REVIEW,
                aggregate_version=self.aggregate_version + 1,
                assignment=assignment,
                updated_at=current,
            ),
            assignment,
        )

    def release_assignment(
        self,
        *,
        requester_user_id: str,
        reason_code: AppealAssignmentReleaseReason,
        now: datetime,
    ) -> tuple["Appeal", AppealAssignmentRelease]:
        assignment = self.assignment
        if self.status is not AppealStatus.IN_REVIEW or assignment is None:
            _reject("APPEAL_ASSIGNMENT_REQUIRED")
        _uuid(requester_user_id)
        if not isinstance(reason_code, AppealAssignmentReleaseReason):
            _reject("APPEAL_ASSIGNMENT_RELEASE_INVALID")
        current = _utc(now)
        if reason_code is AppealAssignmentReleaseReason.ASSIGNMENT_EXPIRED:
            if current < assignment.expires_at:
                _reject("APPEAL_ASSIGNMENT_NOT_EXPIRED")
        elif requester_user_id != assignment.reviewer_user_id:
            _reject("APPEAL_ASSIGNMENT_REQUIRED")
        released = AppealAssignmentRelease(
            assignment_id=assignment.assignment_id,
            appeal_id=self.appeal_id,
            released_by_user_id=requester_user_id,
            reason_code=reason_code,
            released_at=current,
        )
        return (
            replace(
                self,
                status=AppealStatus.SUBMITTED,
                aggregate_version=self.aggregate_version + 1,
                assignment=None,
                current_review_draft_version=None,
                latest_review_draft=None,
                updated_at=current,
            ),
            released,
        )

    def save_review_draft(
        self,
        *,
        reviewer_user_id: str,
        assessments: Tuple[AppealGroundAssessment, ...],
        reason_codes: Tuple[str, ...],
        remedy_delta_codes: Tuple[str, ...],
        sealed_review_note_reference: str,
        sealed_review_note_sha256: str,
        now: datetime,
    ) -> tuple["Appeal", AppealReviewDraft]:
        current = self._reviewer(reviewer_user_id, now)
        normalized_assessments = _assessments(
            assessments,
            expected_grounds=self.latest_application_draft.grounds  # type: ignore[union-attr]
            if self.latest_application_draft is not None
            else (),
            allowed_new_evidence=self.latest_application_draft.new_evidence_reference_ids
            if self.latest_application_draft is not None
            else (),
        )
        reasons = _codes(
            reason_codes,
            _REVIEW_REASON_CODES,
            "APPEAL_REVIEW_INVALID",
        )
        remedy = _codes(
            remedy_delta_codes,
            _REMEDY_DELTA_CODES,
            "APPEAL_REVIEW_INVALID",
        )
        _sealed(
            sealed_review_note_reference,
            sealed_review_note_sha256,
            "APPEAL_REVIEW_INVALID",
        )
        version = (self.current_review_draft_version or 0) + 1
        draft = AppealReviewDraft(
            appeal_id=self.appeal_id,
            version=version,
            assessments=normalized_assessments,
            reason_codes=reasons,
            remedy_delta_codes=remedy,
            sealed_review_note_reference=sealed_review_note_reference,
            sealed_review_note_sha256=sealed_review_note_sha256,
            edited_by_user_id=reviewer_user_id,
            edited_at=current,
        )
        return (
            replace(
                self,
                aggregate_version=self.aggregate_version + 1,
                current_review_draft_version=version,
                latest_review_draft=draft,
                updated_at=current,
            ),
            draft,
        )

    def decide(
        self,
        *,
        decision_version_id: str,
        reviewer_user_id: str,
        expected_review_draft_version: int,
        decision_code: AppealDecisionCode,
        policy_version: str,
        now: datetime,
    ) -> tuple["Appeal", AppealDecisionVersion]:
        if self.status is not AppealStatus.IN_REVIEW or self.decision_version_id:
            _reject("APPEAL_STATE_CONFLICT")
        current = self._reviewer(reviewer_user_id, now)
        draft = self.latest_review_draft
        if (
            draft is None
            or type(expected_review_draft_version) is not int
            or expected_review_draft_version != draft.version
            or not isinstance(decision_code, AppealDecisionCode)
            or not isinstance(policy_version, str)
            or _POLICY_VERSION.fullmatch(policy_version) is None
        ):
            _reject("APPEAL_DECISION_INVALID")
        _uuid(decision_version_id)
        _validate_decision_shape(
            decision_code,
            assessments=draft.assessments,
            remedy_delta_codes=draft.remedy_delta_codes,
        )
        payload = {
            "appeal_id": self.appeal_id,
            "assessments": [
                {
                    "assessment_code": value.assessment_code.value,
                    "accepted_evidence_reference_ids": list(
                        value.accepted_evidence_reference_ids
                    ),
                    "finding_codes": list(value.finding_codes),
                    "ground": value.ground.value,
                }
                for value in draft.assessments
            ],
            "decision_code": decision_code.value,
            "policy_version": policy_version,
            "reason_codes": list(draft.reason_codes),
            "remedy_delta_codes": list(draft.remedy_delta_codes),
            "source_application_version": self.submitted_application_version,
            "source_outcome_sha256": self.source.content_sha256,
            "source_outcome_version_id": self.source.outcome_version_id,
            "source_review_draft_version": draft.version,
            "version": 1,
        }
        digest = hashlib.sha256(
            json.dumps(
                payload,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        ).hexdigest()
        decision = AppealDecisionVersion(
            decision_version_id=decision_version_id,
            appeal_id=self.appeal_id,
            version=1,
            source_outcome_version_id=self.source.outcome_version_id,
            source_outcome_sha256=self.source.content_sha256,
            source_application_version=self.submitted_application_version or 0,
            source_review_draft_version=draft.version,
            decision_code=decision_code,
            assessments=draft.assessments,
            reason_codes=draft.reason_codes,
            remedy_delta_codes=draft.remedy_delta_codes,
            policy_version=policy_version,
            decided_by_user_id=reviewer_user_id,
            decided_at=current,
            decision_sha256=digest,
        )
        return (
            replace(
                self,
                status=AppealStatus.DECIDED,
                aggregate_version=self.aggregate_version + 1,
                decision_version_id=decision_version_id,
                updated_at=current,
            ),
            decision,
        )

    def _applicant(self, applicant_user_id: str, now: datetime) -> datetime:
        _uuid(applicant_user_id)
        if applicant_user_id != self.applicant_user_id:
            _reject("APPEAL_NOT_FOUND")
        return _utc(now)

    def _reviewer(self, reviewer_user_id: str, now: datetime) -> datetime:
        _uuid(reviewer_user_id)
        current = _utc(now)
        assignment = self.assignment
        if (
            self.status is not AppealStatus.IN_REVIEW
            or assignment is None
            or assignment.reviewer_user_id != reviewer_user_id
            or current >= assignment.expires_at
        ):
            _reject("APPEAL_ASSIGNMENT_REQUIRED")
        return current


def _validate_source(source: object) -> None:
    if not isinstance(source, TrustCaseOutcomeSource):
        _reject("APPEAL_SOURCE_INVALID")
    for value in (
        source.outcome_version_id,
        source.case_id,
        source.organization_id,
        source.demand_id,
        source.demand_version_id,
        source.evidence_packet_version_id,
    ):
        _uuid(value)
    if source.outcome_code not in _SOURCE_OUTCOME_CODES:
        _reject("APPEAL_SOURCE_INVALID")
    _codes(source.reason_codes, _SOURCE_REASON_CODES, "APPEAL_SOURCE_INVALID")
    if not isinstance(source.action_codes, tuple) or len(source.action_codes) > 3:
        _reject("APPEAL_SOURCE_INVALID")
    if any(
        not isinstance(value, str) or value not in _SOURCE_ACTION_CODES
        for value in source.action_codes
    ) or len(set(source.action_codes)) != len(source.action_codes):
        _reject("APPEAL_SOURCE_INVALID")
    if source.outcome_code in {"NO_ACTION", "PROTECTION_LIFTED"}:
        if source.action_codes:
            _reject("APPEAL_SOURCE_INVALID")
    elif not source.action_codes:
        _reject("APPEAL_SOURCE_INVALID")
    _digest(source.evidence_packet_sha256, "APPEAL_SOURCE_INVALID")
    _digest(source.content_sha256, "APPEAL_SOURCE_INVALID")
    if not isinstance(source.policy_version, str) or _POLICY_VERSION.fullmatch(
        source.policy_version
    ) is None:
        _reject("APPEAL_SOURCE_INVALID")
    decided_at = _utc(source.decided_at)
    deadline = None if source.appeal_deadline is None else _utc(source.appeal_deadline)
    if (
        type(source.appeal_eligible) is not bool
        or source.appeal_eligibility_code not in {"ELIGIBLE", "NOT_ELIGIBLE"}
        or source.appeal_eligible
        != (source.appeal_eligibility_code == "ELIGIBLE")
        or (source.appeal_eligible and (deadline is None or deadline <= decided_at))
        or (not source.appeal_eligible and deadline is not None)
    ):
        _reject("APPEAL_SOURCE_INVALID")


def _assessments(
    values: object,
    *,
    expected_grounds: Tuple[AppealGround, ...],
    allowed_new_evidence: Tuple[str, ...],
) -> Tuple[AppealGroundAssessment, ...]:
    if not isinstance(values, tuple) or not values or len(values) > 3:
        _reject("APPEAL_REVIEW_INVALID")
    normalized = []
    for value in values:
        if (
            not isinstance(value, AppealGroundAssessment)
            or not isinstance(value.ground, AppealGround)
            or not isinstance(value.assessment_code, AppealGroundAssessmentCode)
        ):
            _reject("APPEAL_REVIEW_INVALID")
        findings = _codes(
            value.finding_codes,
            _REVIEW_FINDING_CODES,
            "APPEAL_REVIEW_INVALID",
        )
        evidence = _identifiers(
            value.accepted_evidence_reference_ids,
            "APPEAL_REVIEW_INVALID",
            allow_empty=True,
        )
        if not set(evidence).issubset(allowed_new_evidence):
            _reject("APPEAL_REVIEW_INVALID")
        normalized.append(
            replace(
                value,
                finding_codes=findings,
                accepted_evidence_reference_ids=evidence,
            )
        )
    normalized.sort(key=lambda value: value.ground.value.encode("ascii"))
    if (
        len({value.ground for value in normalized}) != len(normalized)
        or tuple(value.ground for value in normalized) != expected_grounds
    ):
        _reject("APPEAL_REVIEW_INVALID")
    return tuple(normalized)


def _validate_decision_shape(
    decision_code: AppealDecisionCode,
    *,
    assessments: Tuple[AppealGroundAssessment, ...],
    remedy_delta_codes: Tuple[str, ...],
) -> None:
    any_accepted = any(
        value.assessment_code
        in {AppealGroundAssessmentCode.ACCEPTED, AppealGroundAssessmentCode.PARTIALLY_ACCEPTED}
        for value in assessments
    )
    if decision_code in {AppealDecisionCode.MODIFY, AppealDecisionCode.VACATE_AND_REMAND}:
        if not any_accepted or remedy_delta_codes == ("NO_CHANGE",):
            _reject("APPEAL_DECISION_INVALID")
    elif decision_code in {AppealDecisionCode.AFFIRM, AppealDecisionCode.DISMISS}:
        if any_accepted or remedy_delta_codes != ("NO_CHANGE",):
            _reject("APPEAL_DECISION_INVALID")


def _enum_tuple(values: object, enum_type: type[Enum], code: str):
    if not isinstance(values, tuple) or not values or len(values) > 3:
        _reject(code)
    if any(not isinstance(value, enum_type) for value in values):
        _reject(code)
    normalized = tuple(sorted(values, key=lambda value: value.value.encode("ascii")))
    if len(set(normalized)) != len(normalized):
        _reject(code)
    return normalized


def _codes(
    values: object,
    allowed: frozenset[str],
    code: str,
) -> Tuple[str, ...]:
    if not isinstance(values, tuple) or not values or len(values) > 32:
        _reject(code)
    if any(not isinstance(value, str) or value not in allowed for value in values):
        _reject(code)
    normalized = tuple(sorted(values, key=lambda value: value.encode("utf-8")))
    if len(set(normalized)) != len(normalized):
        _reject(code)
    return normalized


def _identifiers(values: object, code: str, *, allow_empty: bool) -> Tuple[str, ...]:
    if not isinstance(values, tuple) or len(values) > 32 or (not allow_empty and not values):
        _reject(code)
    normalized = tuple(sorted((_uuid(value) for value in values), key=str.encode))
    if len(set(normalized)) != len(normalized):
        _reject(code)
    return normalized


def _sealed(reference: object, digest: object, code: str) -> None:
    if not isinstance(reference, str) or _SEALED_REFERENCE.fullmatch(reference) is None:
        _reject(code)
    _digest(digest, code)


def _digest(value: object, code: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _reject(code)
    return value


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
    if value.utcoffset() != timezone.utc.utcoffset(value):
        _reject("TIME_INVALID")
    return value.astimezone(timezone.utc)


def _reject(code: str) -> None:
    raise AppealDomainError(code)


__all__ = [
    "Appeal",
    "AppealApplicationDraft",
    "AppealApplicationVersion",
    "AppealAssignmentRelease",
    "AppealAssignmentReleaseReason",
    "AppealDecisionCode",
    "AppealDecisionVersion",
    "AppealDomainError",
    "AppealGround",
    "AppealGroundAssessment",
    "AppealGroundAssessmentCode",
    "AppealReviewAssignment",
    "AppealReviewDraft",
    "AppealStatus",
    "RequestedAppealOutcome",
    "TrustCaseOutcomeSource",
]
