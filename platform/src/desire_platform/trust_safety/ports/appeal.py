"""Closed dependency and read-projection ports for Appeal application work."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
from typing import Any, ContextManager, Mapping, Optional, Protocol, Sequence, Tuple
from uuid import UUID

from ..domain import Appeal, TrustCaseOutcomeSource


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ETAG = re.compile(r'^"appeal-[1-9][0-9]*-[0-9a-f]{24}"$')
_STATUSES = frozenset(("DRAFT", "SUBMITTED", "IN_REVIEW", "DECIDED", "WITHDRAWN"))
_GROUNDS = frozenset(("PROCEDURAL_ERROR", "NEW_MATERIAL_EVIDENCE", "RULE_MISAPPLICATION"))
_REQUESTED = frozenset(("REMOVE_MEASURE", "MODIFY_MEASURE", "VACATE_AND_REMAND"))
_ASSESSMENT_CODES = frozenset(("ACCEPTED", "PARTIALLY_ACCEPTED", "REJECTED"))
_FINDING_CODES = frozenset(
    (
        "PROCEDURE_MATERIAL_ERROR",
        "NEW_EVIDENCE_MATERIAL",
        "RULE_APPLIED_CORRECTLY",
        "RULE_APPLICATION_ERROR",
        "APPEAL_NOT_SUBSTANTIATED",
    )
)
_REVIEW_REASONS = frozenset(
    (
        "SOURCE_OUTCOME_SUPPORTED",
        "SOURCE_OUTCOME_UNSUPPORTED",
        "PROCEDURAL_REVIEW_COMPLETE",
        "NEW_EVIDENCE_REVIEWED",
        "REMAND_REQUIRED",
        "APPEAL_SCOPE_INVALID",
    )
)
_REMEDIES = frozenset(
    (
        "NO_CHANGE",
        "REMOVE_CORRECTIVE_MEASURE",
        "NARROW_CORRECTIVE_MEASURE",
        "REPLACE_CORRECTIVE_MEASURE",
        "RETURN_TO_TRUST_REVIEW",
    )
)
_DECISIONS = frozenset(("AFFIRM", "MODIFY", "VACATE_AND_REMAND", "DISMISS"))
_SOURCE_OUTCOMES = frozenset(
    (
        "NO_ACTION",
        "PROTECTION_LIFTED",
        "PROTECTION_MAINTAINED",
        "PROTECTION_MODIFIED",
        "REMEDIATION_REQUIRED",
    )
)
_SOURCE_REASONS = frozenset(
    (
        "INSUFFICIENT_VERIFIED_EVIDENCE",
        "NO_POLICY_BREACH",
        "POLICY_REQUIREMENT_NOT_MET",
        "PRECAUTIONARY_ACTION_REQUIRED",
        "RISK_MITIGATED",
    )
)
_SOURCE_ACTIONS = frozenset(
    ("REQUEST_MATCHING", "SUBMIT_DEMAND", "VERIFY_DEMAND")
)
_POLICY = re.compile(r"[a-z][a-z0-9._-]{2,95}\Z")


class AppealStorageUnavailableError(Exception):
    """Durable storage failed before COMMIT was sent."""


class AppealCommitOutcomeUnknownError(Exception):
    """COMMIT was sent but its durable outcome was not acknowledged."""


class AppealAuthorityUnavailableError(Exception):
    """The exact IAM authority projection is unavailable."""


class AppealSourceUnavailableError(Exception):
    """The Trust source or Demand applicant-party binding is unavailable."""


class AppealConflictUnavailableError(Exception):
    """The exact reviewer conflict proof is unavailable."""


class AppealSealedTextUnavailableError(Exception):
    """Restricted text could not be durably sealed."""


class AppealDecisionPolicyUnavailableError(Exception):
    """Server-derived decision policy facts are unavailable."""


@dataclass(frozen=True)
class AppealApplicantAuthority:
    """Exact IAM applicant authority; every identity coordinate is hidden."""

    actor_user_id: str = field(repr=False)
    session_id: str = field(repr=False)
    organization_id: str = field(repr=False)
    user_status: str
    session_status: str
    session_family_status: str
    organization_status: str
    membership_id: str = field(repr=False)
    membership_status: str = field(repr=False)
    membership_role_grant_id: str = field(repr=False)
    membership_role_grant_version: int = field(repr=False)
    role_code: str = field(repr=False)
    policy_requirements_satisfied: bool = field(repr=False)
    authority_marker_sha256: str = field(repr=False)


@dataclass(frozen=True)
class AppealReviewerAuthority:
    actor_user_id: str = field(repr=False)
    session_id: str = field(repr=False)
    user_status: str
    session_status: str
    session_family_status: str
    duty_grant_id: str = field(repr=False)
    duty_grant_version: int = field(repr=False)
    duty_expires_at: Optional[datetime] = field(repr=False)
    duty_code: str = field(repr=False)
    authority_marker_sha256: str = field(repr=False)


@dataclass(frozen=True)
class AppealApplicantSource:
    applicant_user_id: str = field(repr=False)
    organization_id: str = field(repr=False)
    source: TrustCaseOutcomeSource = field(repr=False)
    applicant_is_party: bool = field(repr=False)
    applicant_party_marker_sha256: str = field(repr=False)
    evaluated_at: datetime
    valid_until: datetime


@dataclass(frozen=True)
class AppealReviewerConflictCheck:
    """Opaque proof that reviewer conflicts were evaluated server-side.

    ``conflict_free`` covers both the applicant and the officer that published
    the immutable source outcome.  Neither identity is projected here.
    """

    appeal_id: str
    source_outcome_version_id: str
    source_case_id: str
    reviewer_user_id: str = field(repr=False)
    duty_grant_id: str = field(repr=False)
    duty_grant_version: int = field(repr=False)
    conflict_free: bool
    conflict_marker_sha256: str = field(repr=False)
    evaluated_at: datetime
    valid_until: datetime


@dataclass(frozen=True)
class AppealSealedText:
    sealed_reference: str = field(repr=False)
    sealed_sha256: str = field(repr=False)
    retention_class: str
    sealed_at: datetime


@dataclass(frozen=True)
class AppealDecisionPolicy:
    appeal_id: str
    appeal_aggregate_version: int
    source_outcome_version_id: str
    review_draft_version: Optional[int]
    decision_code: str
    policy_version: str
    policy_marker_sha256: str = field(repr=False)
    evaluated_at: datetime
    valid_until: datetime


class AppealAuthorityPort(Protocol):
    def authorize_applicant(
        self, *, actor: Any, operation: str, organization_id: str
    ) -> AppealApplicantAuthority: ...

    def authorize_reviewer(
        self, *, actor: Any, operation: str
    ) -> AppealReviewerAuthority: ...


class AppealSourcePort(Protocol):
    def resolve_applicant_source(
        self,
        *,
        applicant_authority: AppealApplicantAuthority,
        source_outcome_version_id: str,
    ) -> AppealApplicantSource: ...


class AppealReviewerConflictPort(Protocol):
    def check_reviewer_conflict(
        self,
        *,
        reviewer_authority: AppealReviewerAuthority,
        source: TrustCaseOutcomeSource,
        appeal_id: str,
        applicant_user_id: str,
    ) -> AppealReviewerConflictCheck: ...


class AppealSealedTextPort(Protocol):
    def seal(
        self,
        *,
        appeal_id: str,
        actor_user_id: str,
        purpose: str,
        raw_text: str,
        idempotency_key_digest: str,
    ) -> AppealSealedText: ...


class AppealDecisionPolicyPort(Protocol):
    def resolve_decision_policy(
        self,
        *,
        reviewer_authority: AppealReviewerAuthority,
        appeal: Appeal,
        decision_code: Any,
        now: datetime,
    ) -> AppealDecisionPolicy: ...


class AppealClock(Protocol):
    def now(self) -> datetime: ...


class AppealIdSource(Protocol):
    def new_id(self, kind: str) -> str: ...


class AppealReceiptKeyring(Protocol):
    idempotency_key_digest_key_ids: Tuple[str, ...]
    payload_hash_key_ids: Tuple[str, ...]

    def keyed_digest(self, key_id: str, value: bytes) -> str: ...


class AppealUnitOfWork(Protocol):
    def lock(self, resource: str, keys: Sequence[str]) -> None: ...

    def get(self, collection: str, key: str) -> Any: ...

    def values(self, collection: str) -> Tuple[Any, ...]: ...

    def put(
        self, collection: str, key: str, value: Any, *, checkpoint: str
    ) -> None: ...

    def commit(self) -> None: ...


class AppealReadStore(Protocol):
    def snapshot(self) -> Mapping[str, Mapping[str, Any]]: ...


class AppealUnitOfWorkFactory(Protocol):
    store: AppealReadStore

    def begin(self) -> ContextManager[AppealUnitOfWork]: ...


@dataclass(frozen=True)
class ReadOwnAppealQuery:
    appeal_id: Optional[str]
    source_outcome_version_id: Optional[str]

    def __post_init__(self) -> None:
        values = (self.appeal_id, self.source_outcome_version_id)
        if sum(value is not None for value in values) != 1 or any(
            value is not None and not _is_uuid(value) for value in values
        ):
            raise ValueError("APPEAL_READ_QUERY_INVALID")


@dataclass(frozen=True)
class AppealSourceProjection:
    """Immutable party-safe source outcome summary with no identity facts."""

    outcome_version_id: str
    case_id: str
    demand_id: str
    demand_version_id: str
    outcome_code: str
    reason_codes: Tuple[str, ...]
    action_codes: Tuple[str, ...]
    evidence_packet_version_id: str
    evidence_packet_sha256: str
    policy_version: str
    decided_at: datetime
    appeal_eligible: bool
    appeal_eligibility_code: str
    appeal_deadline: datetime
    content_sha256: str

    def __post_init__(self) -> None:
        empty_actions_allowed = self.outcome_code in {
            "NO_ACTION",
            "PROTECTION_LIFTED",
        }
        if (
            not all(
                _is_uuid(value)
                for value in (
                    self.outcome_version_id,
                    self.case_id,
                    self.demand_id,
                    self.demand_version_id,
                    self.evidence_packet_version_id,
                )
            )
            or self.outcome_code not in _SOURCE_OUTCOMES
            or not _closed_tuple(
                self.reason_codes, _SOURCE_REASONS, minimum=1, maximum=32
            )
            or not _closed_tuple(
                self.action_codes,
                _SOURCE_ACTIONS,
                minimum=0 if empty_actions_allowed else 1,
                maximum=3,
            )
            or (empty_actions_allowed and bool(self.action_codes))
            or not isinstance(self.evidence_packet_sha256, str)
            or _SHA256.fullmatch(self.evidence_packet_sha256) is None
            or not isinstance(self.content_sha256, str)
            or _SHA256.fullmatch(self.content_sha256) is None
            or not isinstance(self.policy_version, str)
            or _POLICY.fullmatch(self.policy_version) is None
            or not _is_utc(self.decided_at)
            or self.appeal_eligible is not True
            or self.appeal_eligibility_code != "ELIGIBLE"
            or not _is_utc(self.appeal_deadline)
            or self.appeal_deadline <= self.decided_at
        ):
            raise ValueError("APPEAL_READ_PROJECTION_INVALID")


@dataclass(frozen=True)
class AppealApplicationDraftProjection:
    version: int
    grounds: Tuple[str, ...]
    requested_outcome: str
    statement_recorded: bool
    new_evidence_reference_ids: Tuple[str, ...] = field(repr=False)
    edited_at: datetime

    def __post_init__(self) -> None:
        if (
            type(self.version) is not int
            or self.version < 1
            or not _closed_tuple(self.grounds, _GROUNDS, minimum=1, maximum=3)
            or self.requested_outcome not in _REQUESTED
            or self.statement_recorded is not True
            or not _uuid_tuple(self.new_evidence_reference_ids, maximum=32)
            or not _is_utc(self.edited_at)
            or (
                "NEW_MATERIAL_EVIDENCE" in self.grounds
                and not self.new_evidence_reference_ids
            )
        ):
            raise ValueError("APPEAL_READ_PROJECTION_INVALID")


@dataclass(frozen=True)
class AppealSubmittedApplicationProjection:
    grounds: Tuple[str, ...]
    requested_outcome: str
    statement_recorded: bool
    new_evidence_reference_ids: Tuple[str, ...] = field(repr=False)
    submitted_at: datetime

    def __post_init__(self) -> None:
        if (
            not _closed_tuple(self.grounds, _GROUNDS, minimum=1, maximum=3)
            or self.requested_outcome not in _REQUESTED
            or self.statement_recorded is not True
            or not _uuid_tuple(self.new_evidence_reference_ids, maximum=32)
            or not _is_utc(self.submitted_at)
            or (
                "NEW_MATERIAL_EVIDENCE" in self.grounds
                and not self.new_evidence_reference_ids
            )
        ):
            raise ValueError("APPEAL_READ_PROJECTION_INVALID")


@dataclass(frozen=True)
class AppealDecisionProjection:
    decision_version_id: str
    decision_code: str
    assessments: Tuple[AppealAssessmentProjection, ...]
    reason_codes: Tuple[str, ...]
    remedy_delta_codes: Tuple[str, ...]
    policy_version: str
    decided_at: datetime
    decision_sha256: str

    def __post_init__(self) -> None:
        if (
            not _is_uuid(self.decision_version_id)
            or self.decision_code not in _DECISIONS
            or not isinstance(self.assessments, tuple)
            or not 1 <= len(self.assessments) <= 3
            or any(
                not isinstance(value, AppealAssessmentProjection)
                for value in self.assessments
            )
            or len({value.ground for value in self.assessments})
            != len(self.assessments)
            or not _closed_tuple(
                self.reason_codes, _REVIEW_REASONS, minimum=1, maximum=32
            )
            or not _closed_tuple(
                self.remedy_delta_codes, _REMEDIES, minimum=1, maximum=32
            )
            or not isinstance(self.policy_version, str)
            or _POLICY.fullmatch(self.policy_version) is None
            or not _is_utc(self.decided_at)
            or not isinstance(self.decision_sha256, str)
            or _SHA256.fullmatch(self.decision_sha256) is None
        ):
            raise ValueError("APPEAL_READ_PROJECTION_INVALID")


@dataclass(frozen=True)
class AppealOwnProjection:
    appeal_id: str
    source_outcome_version_id: str
    source_case_id: str
    source: AppealSourceProjection
    status: str
    aggregate_version: int
    application_draft: Optional[AppealApplicationDraftProjection]
    application: Optional[AppealSubmittedApplicationProjection]
    decision: Optional[AppealDecisionProjection]
    entity_tag: str

    def __post_init__(self) -> None:
        if (
            not all(
                _is_uuid(value)
                for value in (
                    self.appeal_id,
                    self.source_outcome_version_id,
                    self.source_case_id,
                )
            )
            or self.status not in _STATUSES
            or not isinstance(self.source, AppealSourceProjection)
            or self.source.outcome_version_id != self.source_outcome_version_id
            or self.source.case_id != self.source_case_id
            or type(self.aggregate_version) is not int
            or self.aggregate_version < 1
            or (
                self.application_draft is not None
                and not isinstance(
                    self.application_draft, AppealApplicationDraftProjection
                )
            )
            or (
                self.application is not None
                and not isinstance(
                    self.application, AppealSubmittedApplicationProjection
                )
            )
            or (
                self.decision is not None
                and not isinstance(self.decision, AppealDecisionProjection)
            )
            or (
                self.status == "DRAFT"
                and (self.application is not None or self.decision is not None)
            )
            or (
                self.status in {"SUBMITTED", "IN_REVIEW"}
                and (self.application is None or self.decision is not None)
            )
            or (
                self.status == "DECIDED"
                and (self.application is None or self.decision is None)
            )
            or (self.status == "WITHDRAWN" and self.decision is not None)
            or (
                self.application is not None
                and self.decision is not None
                and tuple(
                    assessment.ground
                    for assessment in self.decision.assessments
                )
                != self.application.grounds
            )
            or _ETAG.fullmatch(self.entity_tag) is None
        ):
            raise ValueError("APPEAL_READ_PROJECTION_INVALID")


@dataclass(frozen=True)
class AppealQueueItem:
    appeal_id: str
    source_outcome_version_id: str
    source_case_id: str
    grounds: Tuple[str, ...]
    requested_outcome: str
    submitted_at: datetime
    entity_tag: str

    def __post_init__(self) -> None:
        if (
            not all(
                _is_uuid(value)
                for value in (
                    self.appeal_id,
                    self.source_outcome_version_id,
                    self.source_case_id,
                )
            )
            or not _closed_tuple(self.grounds, _GROUNDS, minimum=1, maximum=3)
            or self.requested_outcome not in _REQUESTED
            or not _is_utc(self.submitted_at)
            or _ETAG.fullmatch(self.entity_tag) is None
        ):
            raise ValueError("APPEAL_READ_PROJECTION_INVALID")


@dataclass(frozen=True)
class AppealQueueProjection:
    items: Tuple[AppealQueueItem, ...]
    entity_tag: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.items, tuple)
            or len(self.items) > 100
            or any(not isinstance(item, AppealQueueItem) for item in self.items)
            or len({item.appeal_id for item in self.items}) != len(self.items)
            or _ETAG.fullmatch(self.entity_tag) is None
        ):
            raise ValueError("APPEAL_READ_PROJECTION_INVALID")


@dataclass(frozen=True)
class AppealActiveAssignmentItem:
    """Minimal reviewer-owned assignment index entry.

    The assignment identifier, reviewer authority, applicant identity, source
    facts, and all restricted text deliberately remain outside this DTO.  The
    appeal identifier is only a short-lived navigation coordinate for the
    existing assigned-appeal read.
    """

    appeal_id: str
    assignment_expires_at: datetime

    def __post_init__(self) -> None:
        if not _is_uuid(self.appeal_id) or not _is_utc(
            self.assignment_expires_at
        ):
            raise ValueError("APPEAL_READ_PROJECTION_INVALID")


@dataclass(frozen=True)
class AppealActiveAssignmentsProjection:
    items: Tuple[AppealActiveAssignmentItem, ...]
    entity_tag: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.items, tuple)
            or len(self.items) > 100
            or any(
                not isinstance(item, AppealActiveAssignmentItem)
                for item in self.items
            )
            or len({item.appeal_id for item in self.items}) != len(self.items)
            or _ETAG.fullmatch(self.entity_tag) is None
        ):
            raise ValueError("APPEAL_READ_PROJECTION_INVALID")


@dataclass(frozen=True)
class AppealAssessmentProjection:
    ground: str
    assessment_code: str
    finding_codes: Tuple[str, ...]
    accepted_evidence_reference_ids: Tuple[str, ...] = field(repr=False)

    def __post_init__(self) -> None:
        if (
            self.ground not in _GROUNDS
            or self.assessment_code not in _ASSESSMENT_CODES
            or not _closed_tuple(
                self.finding_codes, _FINDING_CODES, minimum=1, maximum=32
            )
            or not _uuid_tuple(
                self.accepted_evidence_reference_ids, maximum=32
            )
        ):
            raise ValueError("APPEAL_READ_PROJECTION_INVALID")


@dataclass(frozen=True)
class AppealReviewDraftProjection:
    version: int
    assessments: Tuple[AppealAssessmentProjection, ...]
    reason_codes: Tuple[str, ...]
    remedy_delta_codes: Tuple[str, ...]
    review_note_recorded: bool
    edited_at: datetime

    def __post_init__(self) -> None:
        if (
            type(self.version) is not int
            or self.version < 1
            or not isinstance(self.assessments, tuple)
            or not 1 <= len(self.assessments) <= 3
            or any(
                not isinstance(value, AppealAssessmentProjection)
                for value in self.assessments
            )
            or len({value.ground for value in self.assessments})
            != len(self.assessments)
            or not _closed_tuple(
                self.reason_codes, _REVIEW_REASONS, minimum=1, maximum=32
            )
            or not _closed_tuple(
                self.remedy_delta_codes, _REMEDIES, minimum=1, maximum=32
            )
            or self.review_note_recorded is not True
            or not _is_utc(self.edited_at)
        ):
            raise ValueError("APPEAL_READ_PROJECTION_INVALID")


@dataclass(frozen=True)
class AppealAssignedProjection:
    appeal: AppealOwnProjection
    source: AppealSourceProjection
    application: AppealSubmittedApplicationProjection
    review_draft: Optional[AppealReviewDraftProjection]
    assignment_expires_at: datetime
    entity_tag: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.appeal, AppealOwnProjection)
            or self.appeal.status != "IN_REVIEW"
            or not isinstance(self.source, AppealSourceProjection)
            or self.source != self.appeal.source
            or not isinstance(
                self.application, AppealSubmittedApplicationProjection
            )
            or self.appeal.application != self.application
            or (
                self.review_draft is not None
                and (
                    not isinstance(
                        self.review_draft, AppealReviewDraftProjection
                    )
                    or tuple(
                        assessment.ground
                        for assessment in self.review_draft.assessments
                    )
                    != self.application.grounds
                )
            )
            or not _is_utc(self.assignment_expires_at)
            or _ETAG.fullmatch(self.entity_tag) is None
            or self.entity_tag != self.appeal.entity_tag
        ):
            raise ValueError("APPEAL_READ_PROJECTION_INVALID")


@dataclass(frozen=True)
class AppealCompletedAssignmentItem:
    """Minimal terminal appeal-review index entry owned by one reviewer."""

    appeal_id: str
    decided_at: datetime
    decision_code: str

    def __post_init__(self) -> None:
        if (
            not _is_uuid(self.appeal_id)
            or not _is_utc(self.decided_at)
            or self.decision_code not in _DECISIONS
        ):
            raise ValueError("APPEAL_READ_PROJECTION_INVALID")


@dataclass(frozen=True)
class AppealCompletedAssignmentsProjection:
    items: Tuple[AppealCompletedAssignmentItem, ...]
    has_more: bool
    entity_tag: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.items, tuple)
            or len(self.items) > 100
            or any(
                not isinstance(item, AppealCompletedAssignmentItem)
                for item in self.items
            )
            or len({item.appeal_id for item in self.items}) != len(self.items)
            or type(self.has_more) is not bool
            or (self.has_more and not self.items)
            or _ETAG.fullmatch(self.entity_tag) is None
        ):
            raise ValueError("APPEAL_READ_PROJECTION_INVALID")
        coordinates = tuple(
            (item.decided_at, UUID(item.appeal_id).int) for item in self.items
        )
        if any(left <= right for left, right in zip(coordinates, coordinates[1:])):
            raise ValueError("APPEAL_READ_PROJECTION_INVALID")


@dataclass(frozen=True)
class AppealCompletedDetailProjection:
    """Party-safe terminal decision, excluding every authority coordinate."""

    appeal_id: str
    status: str
    application: AppealSubmittedApplicationProjection
    decision: AppealDecisionProjection
    review_note_recorded: bool
    entity_tag: str

    def __post_init__(self) -> None:
        if (
            not _is_uuid(self.appeal_id)
            or self.status != "DECIDED"
            or not isinstance(
                self.application, AppealSubmittedApplicationProjection
            )
            or not isinstance(self.decision, AppealDecisionProjection)
            or tuple(
                assessment.ground for assessment in self.decision.assessments
            )
            != self.application.grounds
            or self.decision.decided_at < self.application.submitted_at
            or self.review_note_recorded is not True
            or _ETAG.fullmatch(self.entity_tag) is None
        ):
            raise ValueError("APPEAL_READ_PROJECTION_INVALID")


class AppealReadPort(Protocol):
    def read_own_appeal(
        self,
        *,
        actor: Any,
        applicant_authority: AppealApplicantAuthority,
        query: ReadOwnAppealQuery,
    ) -> Optional[AppealOwnProjection]: ...

    def list_appeal_queue(
        self,
        *,
        actor: Any,
        reviewer_authority: AppealReviewerAuthority,
        limit: int,
    ) -> AppealQueueProjection: ...

    def list_my_active_appeal_assignments(
        self,
        *,
        actor: Any,
        reviewer_authority: AppealReviewerAuthority,
        limit: int,
    ) -> AppealActiveAssignmentsProjection: ...

    def read_assigned_appeal(
        self,
        *,
        actor: Any,
        reviewer_authority: AppealReviewerAuthority,
        appeal_id: str,
    ) -> AppealAssignedProjection: ...

    def list_my_completed_appeal_assignments(
        self,
        *,
        actor: Any,
        reviewer_authority: AppealReviewerAuthority,
        limit: int,
    ) -> AppealCompletedAssignmentsProjection: ...

    def read_my_completed_appeal(
        self,
        *,
        actor: Any,
        reviewer_authority: AppealReviewerAuthority,
        appeal_id: str,
    ) -> AppealCompletedDetailProjection: ...


def _is_uuid(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError):
        return False
    return parsed.int != 0 and str(parsed) == value


def _is_utc(value: object) -> bool:
    return (
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() == timezone.utc.utcoffset(value)
    )


def _closed_tuple(
    values: object,
    allowed: frozenset[str],
    *,
    minimum: int,
    maximum: int,
) -> bool:
    return (
        isinstance(values, tuple)
        and minimum <= len(values) <= maximum
        and len(set(values)) == len(values)
        and all(isinstance(value, str) and value in allowed for value in values)
    )


def _uuid_tuple(values: object, *, maximum: int) -> bool:
    return (
        isinstance(values, tuple)
        and len(values) <= maximum
        and len(set(values)) == len(values)
        and all(_is_uuid(value) for value in values)
    )


__all__ = [
    "AppealActiveAssignmentItem",
    "AppealActiveAssignmentsProjection",
    "AppealApplicantSource",
    "AppealApplicantAuthority",
    "AppealApplicationDraftProjection",
    "AppealAssignedProjection",
    "AppealAssessmentProjection",
    "AppealAuthorityPort",
    "AppealAuthorityUnavailableError",
    "AppealClock",
    "AppealCommitOutcomeUnknownError",
    "AppealCompletedAssignmentItem",
    "AppealCompletedAssignmentsProjection",
    "AppealCompletedDetailProjection",
    "AppealConflictUnavailableError",
    "AppealDecisionPolicy",
    "AppealDecisionPolicyPort",
    "AppealDecisionPolicyUnavailableError",
    "AppealDecisionProjection",
    "AppealIdSource",
    "AppealOwnProjection",
    "AppealQueueItem",
    "AppealQueueProjection",
    "AppealReadPort",
    "AppealReadStore",
    "AppealReceiptKeyring",
    "AppealReviewDraftProjection",
    "AppealReviewerAuthority",
    "AppealReviewerConflictCheck",
    "AppealReviewerConflictPort",
    "AppealSealedText",
    "AppealSealedTextPort",
    "AppealSealedTextUnavailableError",
    "AppealSourcePort",
    "AppealSourceProjection",
    "AppealSourceUnavailableError",
    "AppealStorageUnavailableError",
    "AppealSubmittedApplicationProjection",
    "AppealUnitOfWork",
    "AppealUnitOfWorkFactory",
    "ReadOwnAppealQuery",
]
