"""Immutable Demand facts for the first contract/domain/application RED.

These production-importable shapes intentionally contain no Memory behavior,
database assumptions, HTTP semantics, or test-mode branch.  Every state
transition and validator remains fail-closed behind one stable sentinel until
the same semantic assertions are taken through a later GREEN.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from enum import Enum
import hashlib
import hmac
import json
import unicodedata
from typing import Any, Optional, Tuple, Union


DEMAND_DOMAIN_BEHAVIOR_NOT_AVAILABLE = "DEMAND_DOMAIN_BEHAVIOR_NOT_AVAILABLE"


class DemandDomainBehaviorNotAvailable(RuntimeError):
    """Stable default-deny signal for domain behavior not implemented yet."""


class DemandDomainError(ValueError):
    """Closed domain rejection reserved for the future minimal behavior."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class DemandStatus(str, Enum):
    DRAFT = "DRAFT"
    SUBMITTED = "SUBMITTED"
    NEEDS_CHANGES = "NEEDS_CHANGES"
    VERIFIED = "VERIFIED"
    FUNDING_PENDING = "FUNDING_PENDING"
    FUNDED = "FUNDED"
    MATCHING = "MATCHING"
    MATCHED = "MATCHED"
    NO_MATCH = "NO_MATCH"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"


class ReviewAssignmentStatus(str, Enum):
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class ReviewResult(str, Enum):
    NEEDS_CHANGES = "NEEDS_CHANGES"
    VERIFIED = "VERIFIED"


class FinanceFundingFindingDisposition(str, Enum):
    DISCREPANCY = "DISCREPANCY"
    REJECTED = "REJECTED"


class FundingObservedStatus(str, Enum):
    SECURED = "SECURED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    REPLACED = "REPLACED"


class MatchingRequestStatus(str, Enum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    INVALIDATED = "INVALIDATED"
    CANCELLED = "CANCELLED"


class CancelReasonCode(str, Enum):
    OWNER_WITHDREW = "OWNER_WITHDREW"
    REQUIREMENTS_CHANGED = "REQUIREMENTS_CHANGED"
    REVIEW_CLOSED = "REVIEW_CLOSED"
    FUNDING_UNAVAILABLE = "FUNDING_UNAVAILABLE"
    SAFETY_RESTRICTION = "SAFETY_RESTRICTION"
    DEADLINE_REACHED = "DEADLINE_REACHED"


FrozenScalar = Union[None, bool, int, str]
FrozenJson = Union[FrozenScalar, "DemandContent", Tuple["FrozenJson", ...]]


@dataclass(frozen=True)
class DemandContent:
    """Insertion-order-preserving immutable JSON object with secret-safe repr."""

    members: Tuple[Tuple[str, FrozenJson], ...] = field(repr=False)


@dataclass(frozen=True)
class DemandVersion:
    demand_version_id: str
    organization_id: str
    demand_id: str
    version_no: int
    based_on_demand_version_id: Optional[str]
    content: DemandContent = field(repr=False)
    content_sha256: str
    demand_schema_version: int
    canonicalization_version: str
    taxonomy_bundle_id: str
    created_by_user_id: str
    created_at: datetime


@dataclass(frozen=True)
class DemandSubmission:
    submission_id: str
    organization_id: str
    demand_id: str
    demand_version_id: str
    submission_no: int
    submitted_by_user_id: str
    submitted_at: datetime
    content_sha256: str
    content_policy_version: str
    content_policy_result_sha256: str


@dataclass(frozen=True)
class DemandReviewAssignment:
    assignment_id: str
    organization_id: str
    demand_id: str
    reviewer_user_id: str
    duty_grant_id: str
    duty_grant_version: int
    issued_by_user_id: str
    purpose: str
    status: ReviewAssignmentStatus
    conflict_attestation_sha256: str
    assigned_at: datetime
    expires_at: datetime
    aggregate_version: int


@dataclass(frozen=True)
class DemandReview:
    review_id: str
    organization_id: str
    demand_id: str
    demand_version_id: str
    submission_id: str
    assignment_id: str
    reviewer_user_id: str
    result: ReviewResult
    reason_codes: Tuple[str, ...]
    required_field_codes: Tuple[str, ...]
    budget_health_code: str
    risk_code: str
    evidence_summary_sha256: str = field(repr=False)
    reviewed_at: datetime


@dataclass(frozen=True)
class DemandFinanceFundingFinding:
    """Owner-safe immutable terminal fact from synthetic Finance review."""

    finding_id: str
    organization_id: str
    demand_id: str
    demand_version_id: str
    funding_review_id: str
    disposition: FinanceFundingFindingDisposition
    reason_codes: Tuple[str, ...]
    required_field_codes: Tuple[str, ...]
    created_at: datetime

    def __post_init__(self) -> None:
        identifiers = (
            self.finding_id,
            self.organization_id,
            self.demand_id,
            self.demand_version_id,
            self.funding_review_id,
        )
        allowed_reasons = {
            FinanceFundingFindingDisposition.DISCREPANCY: {
                "EVIDENCE_REFERENCE_MISMATCH",
                "TARGET_CONTENT_MISMATCH",
            },
            FinanceFundingFindingDisposition.REJECTED: {
                "BUDGET_PLAN_UNACCEPTABLE",
                "DECLARATION_CONFLICT",
                "SYNTHETIC_SCOPE_VIOLATION",
            },
        }
        if (
            any(not isinstance(value, str) or not value for value in identifiers)
            or not isinstance(
                self.disposition, FinanceFundingFindingDisposition
            )
            or not isinstance(self.reason_codes, tuple)
            or not self.reason_codes
            or tuple(sorted(self.reason_codes)) != self.reason_codes
            or len(set(self.reason_codes)) != len(self.reason_codes)
            or any(
                value not in allowed_reasons[self.disposition]
                for value in self.reason_codes
            )
            or not isinstance(self.required_field_codes, tuple)
            or not self.required_field_codes
            or tuple(sorted(self.required_field_codes))
                != self.required_field_codes
            or len(set(self.required_field_codes))
                != len(self.required_field_codes)
            or any(
                value not in {"BUDGET", "DECLARATIONS", "RISK", "SCOPE"}
                for value in self.required_field_codes
            )
            or not isinstance(self.created_at, datetime)
            or self.created_at.tzinfo is None
        ):
            _reject("DEMAND_VALIDATION_FAILED")


@dataclass(frozen=True)
class DemandFundingMarker:
    funding_marker_id: str
    organization_id: str
    demand_id: str
    demand_version_id: str
    funding_id: str
    amount_currency_sha256: str
    verification_reference_sha256: str = field(repr=False)
    source_event_id: str
    source_aggregate_version: int
    observed_status: FundingObservedStatus
    observed_at: datetime


@dataclass(frozen=True)
class MatchingRequest:
    matching_request_id: str
    organization_id: str
    demand_id: str
    demand_version_id: str
    funding_id: str
    taxonomy_bundle_id: str
    budget_rule_bundle_id: str
    matching_rule_bundle_id: str
    reason_code_bundle_id: str
    composite_rule_requirement_id: str
    status: MatchingRequestStatus
    requested_at: datetime


@dataclass(frozen=True)
class Demand:
    demand_id: str
    organization_id: str
    created_by_user_id: str
    status: DemandStatus
    aggregate_version: int
    current_version_id: str
    verified_version_id: Optional[str]
    current_funding_id: Optional[str]
    current_matching_request_id: Optional[str]
    client_reference_digest_key_id: str
    client_reference_digest: str = field(repr=False)
    expires_at: datetime
    cancelled_at: Optional[datetime]
    expired_at: Optional[datetime]
    reason_code: Optional[CancelReasonCode]
    created_at: datetime
    updated_at: datetime

    @classmethod
    def create(cls, **facts: object) -> tuple["Demand", DemandVersion]:
        now = _datetime_fact(facts, "now")
        expires_at = _datetime_fact(facts, "expires_at")
        if expires_at <= now:
            _reject("DEMAND_VALIDATION_FAILED")
        content = _content_fact(facts, "content")
        validate_demand_content(content, for_submission=False)
        demand_id = _string_fact(facts, "demand_id")
        taxonomy_bundle_id = _string_fact(facts, "taxonomy_bundle_id")
        version = DemandVersion(
            demand_version_id=_string_fact(facts, "demand_version_id"),
            organization_id=_string_fact(facts, "organization_id"),
            demand_id=demand_id,
            version_no=1,
            based_on_demand_version_id=None,
            content=content,
            content_sha256=demand_version_content_sha256(
                demand_id=demand_id,
                version_no=1,
                taxonomy_bundle_id=taxonomy_bundle_id,
                content=content,
            ),
            demand_schema_version=1,
            canonicalization_version="demand-content-json-v1",
            taxonomy_bundle_id=taxonomy_bundle_id,
            created_by_user_id=_string_fact(facts, "created_by_user_id"),
            created_at=now,
        )
        root = cls(
            demand_id=demand_id,
            organization_id=version.organization_id,
            created_by_user_id=version.created_by_user_id,
            status=DemandStatus.DRAFT,
            aggregate_version=1,
            current_version_id=version.demand_version_id,
            verified_version_id=None,
            current_funding_id=None,
            current_matching_request_id=None,
            client_reference_digest_key_id=_string_fact(
                facts, "client_reference_digest_key_id"
            ),
            client_reference_digest=_digest_fact(facts, "client_reference_digest"),
            expires_at=expires_at,
            cancelled_at=None,
            expired_at=None,
            reason_code=None,
            created_at=now,
            updated_at=now,
        )
        return root, version

    def create_version(self, **facts: object) -> tuple["Demand", DemandVersion]:
        if self.status not in {DemandStatus.DRAFT, DemandStatus.NEEDS_CHANGES}:
            _reject("INVALID_STATE_TRANSITION")
        existing = _typed_tuple(facts.get("existing_versions"), DemandVersion)
        base_id = _string_fact(facts, "based_on_demand_version_id")
        if base_id != self.current_version_id:
            _reject("PRECONDITION_FAILED")
        current = next(
            (item for item in existing if item.demand_version_id == base_id), None
        )
        if current is None:
            _reject("INVALID_STATE_TRANSITION")
        content = _content_fact(facts, "content")
        validate_demand_content(content, for_submission=False)
        version_no = max((item.version_no for item in existing), default=0) + 1
        taxonomy_bundle_id = _string_fact(facts, "taxonomy_bundle_id")
        version = DemandVersion(
            demand_version_id=_string_fact(facts, "demand_version_id"),
            organization_id=self.organization_id,
            demand_id=self.demand_id,
            version_no=version_no,
            based_on_demand_version_id=base_id,
            content=content,
            content_sha256=demand_version_content_sha256(
                demand_id=self.demand_id,
                version_no=version_no,
                taxonomy_bundle_id=taxonomy_bundle_id,
                content=content,
            ),
            demand_schema_version=1,
            canonicalization_version="demand-content-json-v1",
            taxonomy_bundle_id=taxonomy_bundle_id,
            created_by_user_id=_string_fact(facts, "actor_user_id"),
            created_at=_datetime_fact(facts, "now"),
        )
        validate_demand_version(
            version,
            demand=self,
            prior_versions=existing,
            for_submission=False,
        )
        root = _replace_root(
            self,
            status=self.status,
            aggregate_version=self.aggregate_version + 1,
            current_version_id=version.demand_version_id,
            verified_version_id=None,
            current_funding_id=None,
            current_matching_request_id=None,
            updated_at=version.created_at,
        )
        return root, version

    def submit(self, **facts: object) -> tuple["Demand", DemandSubmission]:
        if self.status not in {DemandStatus.DRAFT, DemandStatus.NEEDS_CHANGES}:
            _reject("INVALID_STATE_TRANSITION")
        version = _instance_fact(facts, "current_version", DemandVersion)
        if (
            version.demand_version_id != self.current_version_id
            or version.demand_id != self.demand_id
            or version.organization_id != self.organization_id
        ):
            _reject("INVALID_STATE_TRANSITION")
        validate_demand_version(
            version,
            demand=self,
            prior_versions=(),
            for_submission=True,
        )
        prior = _typed_tuple(facts.get("prior_submissions"), DemandSubmission)
        if any(item.demand_version_id == version.demand_version_id for item in prior):
            _reject("INVALID_STATE_TRANSITION")
        now = _datetime_fact(facts, "now")
        submission = DemandSubmission(
            submission_id=_string_fact(facts, "submission_id"),
            organization_id=self.organization_id,
            demand_id=self.demand_id,
            demand_version_id=version.demand_version_id,
            submission_no=max((item.submission_no for item in prior), default=0) + 1,
            submitted_by_user_id=_string_fact(facts, "actor_user_id"),
            submitted_at=now,
            content_sha256=version.content_sha256,
            content_policy_version=_string_fact(facts, "content_policy_version"),
            content_policy_result_sha256=_digest_fact(
                facts, "content_policy_result_sha256"
            ),
        )
        return (
            _replace_root(
                self,
                status=DemandStatus.SUBMITTED,
                aggregate_version=self.aggregate_version + 1,
                updated_at=now,
            ),
            submission,
        )

    def request_changes(self, **facts: object) -> tuple["Demand", DemandReview]:
        return self._review(result=ReviewResult.NEEDS_CHANGES, facts=facts)

    def verify(self, **facts: object) -> tuple["Demand", DemandReview]:
        return self._review(result=ReviewResult.VERIFIED, facts=facts)

    def _review(
        self,
        *,
        result: ReviewResult,
        facts: dict[str, object],
    ) -> tuple["Demand", DemandReview]:
        if self.status is not DemandStatus.SUBMITTED:
            _reject("INVALID_STATE_TRANSITION")
        version = _instance_fact(facts, "current_version", DemandVersion)
        submitted = _instance_fact(facts, "submission", DemandSubmission)
        assignment = _instance_fact(
            facts, "assignment", DemandReviewAssignment
        )
        expected_assignment_id = _string_fact(facts, "assignment_id")
        reviewer_id = _string_fact(facts, "reviewer_user_id")
        now = _datetime_fact(facts, "now")
        if (
            version.demand_version_id != self.current_version_id
            or version.demand_id != self.demand_id
            or submitted.demand_id != self.demand_id
            or submitted.demand_version_id != version.demand_version_id
            or submitted.content_sha256 != version.content_sha256
            or assignment.demand_id != self.demand_id
            or assignment.assignment_id != expected_assignment_id
            or assignment.organization_id != self.organization_id
            or assignment.reviewer_user_id != reviewer_id
            or assignment.status is not ReviewAssignmentStatus.ACTIVE
            or assignment.expires_at <= now
            or assignment.purpose != "DEMAND_REVIEW"
        ):
            _reject("REVIEW_CONFLICT")
        reason_codes = _string_tuple(facts.get("reason_codes", ()))
        required_fields = _string_tuple(facts.get("required_field_codes", ()))
        if result is ReviewResult.NEEDS_CHANGES:
            if not reason_codes or not required_fields:
                _reject("DEMAND_VALIDATION_FAILED")
        elif reason_codes or required_fields:
            _reject("DEMAND_VALIDATION_FAILED")
        review = DemandReview(
            review_id=_string_fact(facts, "review_id"),
            organization_id=self.organization_id,
            demand_id=self.demand_id,
            demand_version_id=version.demand_version_id,
            submission_id=submitted.submission_id,
            assignment_id=assignment.assignment_id,
            reviewer_user_id=reviewer_id,
            result=result,
            reason_codes=reason_codes,
            required_field_codes=required_fields,
            budget_health_code=str(facts.get("budget_health_code", "NOT_REVIEWED")),
            risk_code=str(facts.get("risk_code", "NOT_REVIEWED")),
            evidence_summary_sha256=(
                _digest_fact(facts, "evidence_summary_sha256")
                if result is ReviewResult.VERIFIED
                else "0" * 64
            ),
            reviewed_at=now,
        )
        if result is ReviewResult.VERIFIED:
            root = _replace_root(
                self,
                status=DemandStatus.VERIFIED,
                aggregate_version=self.aggregate_version + 1,
                verified_version_id=version.demand_version_id,
                updated_at=now,
            )
        else:
            root = _replace_root(
                self,
                status=DemandStatus.NEEDS_CHANGES,
                aggregate_version=self.aggregate_version + 1,
                verified_version_id=None,
                current_funding_id=None,
                current_matching_request_id=None,
                updated_at=now,
            )
        return root, review

    def apply_funding_secured(
        self, **facts: object
    ) -> tuple["Demand", DemandFundingMarker]:
        if self.status not in {
            DemandStatus.VERIFIED,
            DemandStatus.FUNDING_PENDING,
        }:
            _reject("INVALID_STATE_TRANSITION")
        version_id = _string_fact(facts, "demand_version_id")
        if version_id != self.current_version_id or version_id != self.verified_version_id:
            _reject("FUNDING_FACT_CHANGED")
        marker = DemandFundingMarker(
            funding_marker_id=_string_fact(facts, "funding_marker_id"),
            organization_id=self.organization_id,
            demand_id=self.demand_id,
            demand_version_id=version_id,
            funding_id=_string_fact(facts, "funding_id"),
            amount_currency_sha256=_digest_fact(facts, "amount_currency_sha256"),
            verification_reference_sha256=_digest_fact(
                facts, "verification_reference_sha256"
            ),
            source_event_id=_string_fact(facts, "source_event_id"),
            source_aggregate_version=_positive_int_fact(
                facts, "source_aggregate_version"
            ),
            observed_status=FundingObservedStatus.SECURED,
            observed_at=_datetime_fact(facts, "now"),
        )
        return (
            _replace_root(
                self,
                status=DemandStatus.FUNDED,
                aggregate_version=self.aggregate_version + 1,
                current_funding_id=marker.funding_id,
                updated_at=marker.observed_at,
            ),
            marker,
        )

    def request_matching(
        self, **facts: object
    ) -> tuple["Demand", MatchingRequest]:
        if self.status not in {DemandStatus.FUNDED, DemandStatus.NO_MATCH}:
            _reject("INVALID_STATE_TRANSITION")
        marker = _instance_fact(facts, "funding_marker", DemandFundingMarker)
        if (
            marker.observed_status is not FundingObservedStatus.SECURED
            or marker.funding_id != self.current_funding_id
            or marker.demand_version_id != self.current_version_id
            or self.verified_version_id != self.current_version_id
        ):
            _reject("FUNDING_FACT_CHANGED")
        now = _datetime_fact(facts, "now")
        request = MatchingRequest(
            matching_request_id=_string_fact(facts, "matching_request_id"),
            organization_id=self.organization_id,
            demand_id=self.demand_id,
            demand_version_id=self.current_version_id,
            funding_id=marker.funding_id,
            taxonomy_bundle_id=_string_fact(facts, "taxonomy_bundle_id"),
            budget_rule_bundle_id=_string_fact(facts, "budget_rule_bundle_id"),
            matching_rule_bundle_id=_string_fact(facts, "matching_rule_bundle_id"),
            reason_code_bundle_id=_string_fact(facts, "reason_code_bundle_id"),
            composite_rule_requirement_id=_string_fact(
                facts, "composite_rule_requirement_id"
            ),
            status=MatchingRequestStatus.OPEN,
            requested_at=now,
        )
        return (
            _replace_root(
                self,
                status=DemandStatus.MATCHING,
                aggregate_version=self.aggregate_version + 1,
                current_matching_request_id=request.matching_request_id,
                updated_at=now,
            ),
            request,
        )

    def cancel(self, **facts: object) -> "Demand":
        if self.status in {
            DemandStatus.MATCHED,
            DemandStatus.CANCELLED,
            DemandStatus.EXPIRED,
        }:
            _reject("INVALID_STATE_TRANSITION")
        now = _datetime_fact(facts, "now")
        reason = facts.get("reason_code")
        if not isinstance(reason, CancelReasonCode) or reason is CancelReasonCode.DEADLINE_REACHED:
            _reject("DEMAND_VALIDATION_FAILED")
        return _replace_root(
            self,
            status=DemandStatus.CANCELLED,
            aggregate_version=self.aggregate_version + 1,
            current_matching_request_id=None,
            cancelled_at=now,
            expired_at=None,
            reason_code=reason,
            updated_at=now,
        )

    def expire(self, **facts: object) -> "Demand":
        if self.status not in {
            DemandStatus.DRAFT,
            DemandStatus.SUBMITTED,
            DemandStatus.NEEDS_CHANGES,
            DemandStatus.VERIFIED,
            DemandStatus.FUNDING_PENDING,
            DemandStatus.FUNDED,
        }:
            _reject("INVALID_STATE_TRANSITION")
        now = _datetime_fact(facts, "now")
        deadline = facts.get("deadline", self.expires_at)
        if not isinstance(deadline, datetime) or deadline > now or self.expires_at > now:
            _reject("INVALID_STATE_TRANSITION")
        return _replace_root(
            self,
            status=DemandStatus.EXPIRED,
            aggregate_version=self.aggregate_version + 1,
            current_matching_request_id=None,
            cancelled_at=None,
            expired_at=now,
            reason_code=CancelReasonCode.DEADLINE_REACHED,
            updated_at=now,
        )


def validate_demand_content(
    content: DemandContent,
    *,
    for_submission: bool,
) -> None:
    value = _thaw(content)
    if not isinstance(value, dict):
        _reject("DEMAND_VALIDATION_FAILED")
    allowed_groups = {
        "problem",
        "scope",
        "acceptance",
        "skills",
        "matching",
        "schedule",
        "budget",
        "milestone_plan",
        "risk",
        "ai",
        "collaboration",
        "location",
        "declarations",
    }
    if set(value).difference(allowed_groups):
        _reject("DEMAND_VALIDATION_FAILED")
    _validate_all_strings(value)
    _validate_content_shapes(value)
    _validate_content_relations(value, for_submission=for_submission)


def canonical_demand_version_bytes(
    *,
    demand_id: str,
    version_no: int,
    taxonomy_bundle_id: str,
    content: DemandContent,
) -> bytes:
    if not isinstance(version_no, int) or isinstance(version_no, bool) or version_no < 1:
        _reject("DEMAND_VALIDATION_FAILED")
    surface = {
        "canonicalization_version": "demand-content-json-v1",
        "content": _thaw(content),
        "demand_id": demand_id,
        "demand_schema_version": 1,
        "taxonomy_bundle_id": taxonomy_bundle_id,
        "version_no": version_no,
    }
    try:
        return json.dumps(
            surface,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise DemandDomainError("DEMAND_VALIDATION_FAILED") from error


def demand_version_content_sha256(
    *,
    demand_id: str,
    version_no: int,
    taxonomy_bundle_id: str,
    content: DemandContent,
) -> str:
    return hashlib.sha256(
        canonical_demand_version_bytes(
            demand_id=demand_id,
            version_no=version_no,
            taxonomy_bundle_id=taxonomy_bundle_id,
            content=content,
        )
    ).hexdigest()


def validate_demand_version(
    version: DemandVersion,
    *,
    demand: Demand,
    prior_versions: Tuple[DemandVersion, ...],
    for_submission: bool,
) -> None:
    if (
        version.demand_id != demand.demand_id
        or version.organization_id != demand.organization_id
        or version.version_no < 1
        or version.demand_schema_version != 1
        or version.canonicalization_version != "demand-content-json-v1"
    ):
        _reject("INVALID_STATE_TRANSITION")
    if any(
        prior.demand_version_id == version.demand_version_id
        or prior.version_no == version.version_no
        for prior in prior_versions
    ):
        _reject("INVALID_STATE_TRANSITION")
    if version.version_no == 1:
        if version.based_on_demand_version_id is not None:
            _reject("INVALID_STATE_TRANSITION")
    elif prior_versions:
        base = next(
            (
                prior
                for prior in prior_versions
                if prior.demand_version_id == version.based_on_demand_version_id
            ),
            None,
        )
        if base is None or base.version_no >= version.version_no:
            _reject("INVALID_STATE_TRANSITION")
    validate_demand_content(version.content, for_submission=for_submission)
    expected = demand_version_content_sha256(
        demand_id=version.demand_id,
        version_no=version.version_no,
        taxonomy_bundle_id=version.taxonomy_bundle_id,
        content=version.content,
    )
    if not hmac.compare_digest(expected, version.content_sha256):
        _reject("DEMAND_VALIDATION_FAILED")


def validate_demand(
    demand: Demand,
    *,
    versions: Tuple[DemandVersion, ...],
    submissions: Tuple[DemandSubmission, ...],
    reviews: Tuple[DemandReview, ...],
    funding_markers: Tuple[DemandFundingMarker, ...],
    matching_requests: Tuple[MatchingRequest, ...],
    finance_findings: Tuple[DemandFinanceFundingFinding, ...] = (),
) -> None:
    exact_finance_findings = _typed_tuple(
        finance_findings, DemandFinanceFundingFinding
    )
    current = next(
        (item for item in versions if item.demand_version_id == demand.current_version_id),
        None,
    )
    if current is None or current.demand_id != demand.demand_id:
        _reject("INVALID_STATE_TRANSITION")
    if demand.aggregate_version < 1:
        _reject("INVALID_STATE_TRANSITION")
    terminal = demand.status in {
        DemandStatus.MATCHED,
        DemandStatus.CANCELLED,
        DemandStatus.EXPIRED,
    }
    if demand.status is DemandStatus.CANCELLED:
        if demand.cancelled_at is None or demand.reason_code in {
            None,
            CancelReasonCode.DEADLINE_REACHED,
        }:
            _reject("INVALID_STATE_TRANSITION")
    elif demand.status is DemandStatus.EXPIRED:
        if (
            demand.expired_at is None
            or demand.reason_code is not CancelReasonCode.DEADLINE_REACHED
        ):
            _reject("INVALID_STATE_TRANSITION")
    elif demand.cancelled_at is not None or demand.expired_at is not None:
        _reject("INVALID_STATE_TRANSITION")
    if not terminal and demand.reason_code is not None:
        _reject("INVALID_STATE_TRANSITION")
    if demand.status in {
        DemandStatus.DRAFT,
        DemandStatus.SUBMITTED,
        DemandStatus.NEEDS_CHANGES,
    } and any(
        pointer is not None
        for pointer in (demand.verified_version_id, demand.current_funding_id)
    ):
        _reject("INVALID_STATE_TRANSITION")
    if demand.status in {
        DemandStatus.VERIFIED,
        DemandStatus.FUNDING_PENDING,
        DemandStatus.FUNDED,
        DemandStatus.MATCHING,
        DemandStatus.NO_MATCH,
        DemandStatus.MATCHED,
    } and demand.verified_version_id != demand.current_version_id:
        _reject("INVALID_STATE_TRANSITION")
    if demand.status is DemandStatus.SUBMITTED and not any(
        item.demand_version_id == demand.current_version_id
        and item.content_sha256 == current.content_sha256
        for item in submissions
    ):
        _reject("INVALID_STATE_TRANSITION")
    if any(
        item.organization_id != demand.organization_id
        or item.demand_id != demand.demand_id
        for item in exact_finance_findings
    ):
        _reject("INVALID_STATE_TRANSITION")
    if (
        demand.status is DemandStatus.NEEDS_CHANGES
        and reviews
        and not any(
            item.result is ReviewResult.NEEDS_CHANGES
            and item.demand_version_id == demand.current_version_id
            for item in reviews
        )
        and not any(
            item.disposition is FinanceFundingFindingDisposition.REJECTED
            and item.demand_version_id == demand.current_version_id
            for item in exact_finance_findings
        )
    ):
        _reject("INVALID_STATE_TRANSITION")
    if demand.status in {DemandStatus.FUNDED, DemandStatus.MATCHING}:
        if demand.current_funding_id is None or not any(
            item.funding_id == demand.current_funding_id
            and item.demand_version_id == demand.current_version_id
            and item.observed_status is FundingObservedStatus.SECURED
            for item in funding_markers
        ):
            _reject("INVALID_STATE_TRANSITION")
    if demand.status is DemandStatus.MATCHING:
        if demand.current_matching_request_id is None or not any(
            item.matching_request_id == demand.current_matching_request_id
            and item.status is MatchingRequestStatus.OPEN
            for item in matching_requests
        ):
            _reject("INVALID_STATE_TRANSITION")
    elif demand.current_matching_request_id is not None:
        _reject("INVALID_STATE_TRANSITION")


def require_demand_version_immutable(
    *,
    before: DemandVersion,
    after: DemandVersion,
) -> None:
    if before != after:
        _reject("INVALID_STATE_TRANSITION")


def _not_available() -> None:
    raise DemandDomainBehaviorNotAvailable(DEMAND_DOMAIN_BEHAVIOR_NOT_AVAILABLE)


def _reject(code: str) -> None:
    raise DemandDomainError(code)


def _replace_root(root: Demand, **changes: object) -> Demand:
    values = {
        field_name: getattr(root, field_name)
        for field_name in root.__dataclass_fields__
    }
    values.update(changes)
    return Demand(**values)


def _thaw(value: FrozenJson) -> Any:
    if isinstance(value, DemandContent):
        result: dict[str, Any] = {}
        for key, child in value.members:
            if key in result:
                _reject("DEMAND_VALIDATION_FAILED")
            result[key] = _thaw(child)
        return result
    if isinstance(value, tuple):
        return [_thaw(child) for child in value]
    if value is None or isinstance(value, (bool, int, str)):
        return value
    _reject("DEMAND_VALIDATION_FAILED")


def _closed_object(
    value: Any,
    *,
    required: set[str],
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != required:
        _reject("DEMAND_VALIDATION_FAILED")
    return value


def _array(value: Any, *, maximum: int = 50) -> list[Any]:
    if not isinstance(value, list) or len(value) > maximum:
        _reject("DEMAND_VALIDATION_FAILED")
    return value


def _integer(value: Any, minimum: int, maximum: int) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > maximum
    ):
        _reject("DEMAND_VALIDATION_FAILED")
    return value


def _code(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 2 <= len(value) <= 64
        or not value[0].isalpha()
        or value.upper() != value
        or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-" for character in value)
    ):
        _reject("DEMAND_VALIDATION_FAILED")
    return value


def _unique_strings(values: Any, *, codes: bool = False) -> list[str]:
    items = _array(values, maximum=50)
    if any(not isinstance(item, str) for item in items) or len(items) != len(set(items)):
        _reject("DEMAND_VALIDATION_FAILED")
    if codes:
        for item in items:
            _code(item)
    return items


def _validate_all_strings(value: Any, path: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            _validate_all_strings(child, key)
    elif isinstance(value, list):
        for child in value:
            _validate_all_strings(child, path)
    elif isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value or any(
            unicodedata.category(character) == "Cc" for character in value
        ):
            _reject("DEMAND_VALIDATION_FAILED")
        bounds = {
            "background": (4000, 12000),
            "data_handling_plan": (2000, 6000),
            "data_model_policy": (2000, 6000),
            "description": (500, 1500),
            "desired_outcomes": (500, 1500),
            "label": (120, 360),
        }
        character_max, byte_max = bounds.get(path, (500, 1500))
        if len(value) > character_max or len(value.encode("utf-8")) > byte_max:
            _reject("DEMAND_VALIDATION_FAILED")


def _validate_content_shapes(content: dict[str, Any]) -> None:
    if "problem" in content:
        problem = _closed_object(
            content["problem"],
            required={"background", "domain_code", "problem_type_codes", "target_user_category_codes", "desired_outcomes"},
        )
        if not isinstance(problem["background"], str) or not problem["background"]:
            _reject("DEMAND_VALIDATION_FAILED")
        _code(problem["domain_code"])
        _unique_strings(problem["problem_type_codes"], codes=True)
        _unique_strings(problem["target_user_category_codes"], codes=True)
        outcomes = _array(problem["desired_outcomes"], maximum=20)
        if any(not isinstance(item, str) or not item for item in outcomes):
            _reject("DEMAND_VALIDATION_FAILED")
    if "scope" in content:
        scope = _closed_object(content["scope"], required={"deliverables", "out_of_scope"})
        deliverables = _array(scope["deliverables"])
        ids = []
        for item in deliverables:
            item = _closed_object(item, required={"item_id", "description"})
            _item_id(item["item_id"])
            if not isinstance(item["description"], str) or not item["description"]:
                _reject("DEMAND_VALIDATION_FAILED")
            ids.append(item["item_id"])
        if len(ids) != len(set(ids)):
            _reject("DEMAND_VALIDATION_FAILED")
        out = _array(scope["out_of_scope"])
        if any(not isinstance(item, str) or not item for item in out):
            _reject("DEMAND_VALIDATION_FAILED")
    if "acceptance" in content:
        acceptance = _closed_object(content["acceptance"], required={"criteria", "response_days", "owner_role_code"})
        ids = []
        for item in _array(acceptance["criteria"]):
            item = _closed_object(item, required={"criterion_id", "description"})
            _item_id(item["criterion_id"])
            if not isinstance(item["description"], str) or not item["description"]:
                _reject("DEMAND_VALIDATION_FAILED")
            ids.append(item["criterion_id"])
        if len(ids) != len(set(ids)) or acceptance["owner_role_code"] != "DEMAND_OWNER":
            _reject("DEMAND_VALIDATION_FAILED")
        _integer(acceptance["response_days"], 1, 30)
    if "skills" in content:
        skills = _closed_object(content["skills"], required={"must_have", "nice_to_have"})
        for collection in (skills["must_have"], skills["nice_to_have"]):
            seen = []
            for item in _array(collection):
                item = _closed_object(item, required={"skill_code", "minimum_level_code"})
                seen.append(_code(item["skill_code"]))
                if item["minimum_level_code"] not in {"FOUNDATION", "WORKING", "ADVANCED", "EXPERT"}:
                    _reject("DEMAND_VALIDATION_FAILED")
            if len(seen) != len(set(seen)):
                _reject("DEMAND_VALIDATION_FAILED")
    if "matching" in content:
        matching = _closed_object(content["matching"], required={"problem_codes", "domain_codes", "task_codes"})
        for name in ("problem_codes", "domain_codes", "task_codes"):
            _unique_strings(matching[name], codes=True)
    if "schedule" in content:
        schedule = _closed_object(content["schedule"], required={"start_date", "due_date", "estimated_days", "weekly_hours", "duration_weeks"})
        for name in ("start_date", "due_date"):
            if not isinstance(schedule[name], str):
                _reject("DEMAND_VALIDATION_FAILED")
            try:
                date.fromisoformat(schedule[name])
            except ValueError as error:
                raise DemandDomainError("DEMAND_VALIDATION_FAILED") from error
        _integer(schedule["estimated_days"], 1, 366)
        _integer(schedule["weekly_hours"], 1, 80)
        _integer(schedule["duration_weeks"], 1, 104)
    if "budget" in content:
        budget = _closed_object(content["budget"], required={"minimum_amount_minor", "maximum_amount_minor", "direct_cost_amount_minor", "currency"})
        for name in ("minimum_amount_minor", "maximum_amount_minor", "direct_cost_amount_minor"):
            _integer(budget[name], 0, 9007199254740991)
        currency = budget["currency"]
        if not isinstance(currency, str) or len(currency) != 3 or not currency.isalpha() or currency.upper() != currency:
            _reject("DEMAND_VALIDATION_FAILED")
    if "milestone_plan" in content:
        plan = _closed_object(content["milestone_plan"], required={"items"})
        ids = []
        for item in _array(plan["items"]):
            item = _closed_object(item, required={"item_id", "label", "percent"})
            ids.append(_item_id(item["item_id"]))
            if not isinstance(item["label"], str) or not item["label"]:
                _reject("DEMAND_VALIDATION_FAILED")
            _integer(item["percent"], 1, 100)
        if len(ids) != len(set(ids)):
            _reject("DEMAND_VALIDATION_FAILED")
    if "risk" in content:
        risk = _closed_object(content["risk"], required={"uncertainty_code", "urgency_code", "dependency_codes", "data_sensitivity", "data_handling_plan"})
        if risk["uncertainty_code"] not in {"LOW", "MEDIUM", "HIGH"} or risk["urgency_code"] not in {"LOW", "MEDIUM", "HIGH"}:
            _reject("DEMAND_VALIDATION_FAILED")
        _unique_strings(risk["dependency_codes"], codes=True)
        if risk["data_sensitivity"] not in {"PUBLIC", "INTERNAL", "HIGH", "RESTRICTED"}:
            _reject("DEMAND_VALIDATION_FAILED")
        if risk["data_handling_plan"] is not None and not isinstance(risk["data_handling_plan"], str):
            _reject("DEMAND_VALIDATION_FAILED")
    if "ai" in content:
        ai = _closed_object(content["ai"], required={"allowed", "required", "data_model_policy", "human_review_code"})
        if not isinstance(ai["allowed"], bool) or not isinstance(ai["required"], bool):
            _reject("DEMAND_VALIDATION_FAILED")
        if ai["data_model_policy"] is not None and not isinstance(ai["data_model_policy"], str):
            _reject("DEMAND_VALIDATION_FAILED")
        if ai["human_review_code"] not in {"NEVER", "RISK_BASED", "ALWAYS"}:
            _reject("DEMAND_VALIDATION_FAILED")
    if "collaboration" in content:
        collaboration = _closed_object(content["collaboration"], required={"languages", "work_mode", "feedback_cadence", "team_preference"})
        _unique_strings(collaboration["languages"])
        if collaboration["work_mode"] not in {"REMOTE", "HYBRID", "ONSITE", "FLEXIBLE"} or collaboration["feedback_cadence"] not in {"ASYNC", "DAILY", "TWICE_WEEKLY", "WEEKLY"} or collaboration["team_preference"] not in {"SOLO", "PAIR", "SMALL_TEAM", "ANY"}:
            _reject("DEMAND_VALIDATION_FAILED")
    if "location" in content:
        location = _closed_object(content["location"], required={"demand_region_code", "allowed_creator_region_codes"})
        _region(location["demand_region_code"])
        regions = _unique_strings(location["allowed_creator_region_codes"])
        for region in regions:
            _region(region)
    if "declarations" in content:
        declarations = _closed_object(content["declarations"], required={"decision_authority", "data_rights", "procurement_intent"})
        if any(not isinstance(value, bool) for value in declarations.values()):
            _reject("DEMAND_VALIDATION_FAILED")


def _validate_content_relations(content: dict[str, Any], *, for_submission: bool) -> None:
    schedule = content.get("schedule")
    if schedule and date.fromisoformat(schedule["start_date"]) > date.fromisoformat(schedule["due_date"]):
        _reject("DEMAND_VALIDATION_FAILED")
    budget = content.get("budget")
    if budget and budget["minimum_amount_minor"] > budget["maximum_amount_minor"]:
        _reject("DEMAND_VALIDATION_FAILED")
    plan = content.get("milestone_plan")
    if plan and plan["items"] and sum(item["percent"] for item in plan["items"]) != 100:
        _reject("DEMAND_VALIDATION_FAILED")
    skills = content.get("skills")
    if skills:
        must = {item["skill_code"] for item in skills["must_have"]}
        nice = {item["skill_code"] for item in skills["nice_to_have"]}
        if must.intersection(nice):
            _reject("DEMAND_VALIDATION_FAILED")
    problem = content.get("problem")
    matching = content.get("matching")
    if problem and matching and problem["domain_code"] not in matching["domain_codes"]:
        _reject("DEMAND_VALIDATION_FAILED")
    risk = content.get("risk")
    if risk and risk["data_sensitivity"] in {"HIGH", "RESTRICTED"} and not risk["data_handling_plan"]:
        _reject("DEMAND_VALIDATION_FAILED")
    ai = content.get("ai")
    if ai and (ai["required"] and not ai["allowed"] or ai["allowed"] and not ai["data_model_policy"]):
        _reject("DEMAND_VALIDATION_FAILED")
    if for_submission:
        required = {"problem", "scope", "acceptance", "skills", "matching", "schedule", "budget", "milestone_plan", "risk", "ai", "collaboration", "location", "declarations"}
        if set(content) != required:
            _reject("DEMAND_VALIDATION_FAILED")
        if not content["scope"]["deliverables"] or not content["acceptance"]["criteria"] or not content["skills"]["must_have"] or not content["milestone_plan"]["items"] or not all(content["declarations"].values()):
            _reject("DEMAND_VALIDATION_FAILED")


def _item_id(value: Any) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 64 or not value[0].islower() or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for character in value):
        _reject("DEMAND_VALIDATION_FAILED")
    return value


def _region(value: Any) -> str:
    if not isinstance(value, str) or not 2 <= len(value) <= 32 or value.upper() != value or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-" for character in value):
        _reject("DEMAND_VALIDATION_FAILED")
    return value


def _string_fact(facts: dict[str, object], name: str) -> str:
    value = facts.get(name)
    if not isinstance(value, str) or not value:
        _reject("DEMAND_VALIDATION_FAILED")
    return value


def _digest_fact(facts: dict[str, object], name: str) -> str:
    value = _string_fact(facts, name)
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        _reject("DEMAND_VALIDATION_FAILED")
    return value


def _positive_int_fact(facts: dict[str, object], name: str) -> int:
    value = facts.get(name)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        _reject("DEMAND_VALIDATION_FAILED")
    return value


def _datetime_fact(facts: dict[str, object], name: str) -> datetime:
    value = facts.get(name)
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        _reject("DEMAND_VALIDATION_FAILED")
    return value


def _content_fact(facts: dict[str, object], name: str) -> DemandContent:
    value = facts.get(name)
    if not isinstance(value, DemandContent):
        _reject("DEMAND_VALIDATION_FAILED")
    return value


def _instance_fact(facts: dict[str, object], name: str, expected_type: type[Any]) -> Any:
    value = facts.get(name)
    if not isinstance(value, expected_type):
        _reject("DEMAND_VALIDATION_FAILED")
    return value


def _typed_tuple(value: object, expected_type: type[Any]) -> tuple[Any, ...]:
    if not isinstance(value, tuple) or any(not isinstance(item, expected_type) for item in value):
        _reject("DEMAND_VALIDATION_FAILED")
    return value


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, tuple) or any(not isinstance(item, str) or not item for item in value) or len(value) != len(set(value)):
        _reject("DEMAND_VALIDATION_FAILED")
    return value
