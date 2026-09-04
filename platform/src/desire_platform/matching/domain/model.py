"""Immutable Matching v1 facts and fail-closed behavior surface.

The implementation is framework-neutral: state transitions and canonical
hashing have no Memory-store, PostgreSQL, HTTP, clock, or actor dependency.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
from decimal import Decimal
from enum import Enum
import hashlib
import json
import re
from typing import Any, Optional, Tuple, Union


MATCHING_DOMAIN_BEHAVIOR_NOT_AVAILABLE = "MATCHING_DOMAIN_BEHAVIOR_NOT_AVAILABLE"


class MatchingDomainBehaviorNotAvailable(RuntimeError):
    """Stable default-deny signal for intentionally absent domain behavior."""


class MatchingDomainError(ValueError):
    """Closed future domain rejection."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class MatchingAttemptStatus(str, Enum):
    OPEN = "OPEN"
    SELECTED = "SELECTED"
    CLOSED_NO_SELECTION = "CLOSED_NO_SELECTION"
    INVALIDATED = "INVALIDATED"
    CANCELLED = "CANCELLED"


class MatchRunStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SUPERSEDED = "SUPERSEDED"
    CANCELLED = "CANCELLED"


class CandidateEligibility(str, Enum):
    ELIGIBLE = "ELIGIBLE"
    EXCLUDED = "EXCLUDED"


class InvitationStatus(str, Enum):
    CREATED = "CREATED"
    SENT = "SENT"
    ACCEPTED = "ACCEPTED"
    DECLINED = "DECLINED"
    WITHDRAWN = "WITHDRAWN"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


@dataclass(frozen=True)
class SelectionInvitationSetEntry:
    """Minimal authoritative Invitation fact used by the shared hash surface."""

    invitation_id: str
    attempt_id: str
    match_run_id: str
    aggregate_version: int
    status: InvitationStatus
    snapshot_sha256: str = field(repr=False)


class InvitationResponseKind(str, Enum):
    ACCEPTED = "ACCEPTED"
    DECLINED = "DECLINED"


class SelectionStatus(str, Enum):
    OPEN = "OPEN"
    SELECTED = "SELECTED"
    CLOSED_NO_SELECTION = "CLOSED_NO_SELECTION"
    CANCELLED = "CANCELLED"


class CandidateSelectorAssignmentStatus(str, Enum):
    """Closed lifecycle for the exact human selection authority."""

    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    RELEASED = "RELEASED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class CandidateSelectorRoleCode(str, Enum):
    CANDIDATE_SELECTOR = "CANDIDATE_SELECTOR"


@dataclass(frozen=True)
class CandidateSelectorAssignment:
    """Immutable, resource-scoped authority fact for one Selection.

    This is deliberately not an organization-wide role grant.  A caller may
    choose a candidate only when the exact assignment, version and resource
    chain remain active at database time.
    """

    assignment_id: str
    aggregate_version: int
    status: CandidateSelectorAssignmentStatus
    role_code: CandidateSelectorRoleCode
    assigned_user_id: str
    organization_id: str
    demand_id: str
    selection_id: str
    assigned_at: datetime
    expires_at: datetime


FrozenScalar = Union[None, bool, int, str]
FrozenJson = Union[FrozenScalar, Tuple["FrozenJson", ...], Tuple[Tuple[str, "FrozenJson"], ...]]


@dataclass(frozen=True)
class MatchingRuleBundle:
    bundle_id: str
    semantic_version: str
    status: str
    selector_digest: str
    canonical_manifest_sha256: str
    taxonomy_bundle_id: str
    engine_identifier: str
    engine_artifact_sha256: str
    effective_at: datetime
    effective_until: Optional[datetime]


@dataclass(frozen=True)
class MatchInputManifest:
    attempt_id: str
    run_id: str
    organization_id: str
    demand_id: str
    demand_version_id: str
    demand_content_sha256: str
    funding_id: str
    matching_request_id: str
    matching_request_version: int
    matching_rule_bundle_id: str
    selector_digest: str
    rule_manifest_sha256: str
    ordered_candidate_identities: Tuple[Tuple[str, str, str, str, str], ...]
    captured_at: datetime
    candidate_count: int
    input_set_sha256: str


@dataclass(frozen=True)
class MatchRunInput:
    attempt_id: str
    run_id: str
    demand_id: str
    demand_version_id: str
    matching_rule_bundle_id: str
    input_set_sha256: str
    demand_facts: Tuple[Tuple[str, FrozenJson], ...] = field(repr=False)
    profile_facts: Tuple[Tuple[Tuple[str, FrozenJson], ...], ...] = field(repr=False)


@dataclass(frozen=True)
class ComponentScore:
    code: str
    ordinal: int
    score: Decimal


@dataclass(frozen=True)
class EvidenceFact:
    code: str
    kind: str
    value: object
    source_version_digest: str


@dataclass(frozen=True)
class MatchCandidate:
    attempt_id: str
    run_id: str
    creator_user_id: str
    profile_id: str
    profile_version_id: str
    profile_content_sha256: str
    eligibility: CandidateEligibility
    exclusion_reason_codes: Tuple[str, ...]
    components: Tuple[ComponentScore, ...]
    total_score: Optional[Decimal]
    rank: Optional[int]
    evidence_facts: Tuple[EvidenceFact, ...] = field(repr=False)
    candidate_result_sha256: str = field(repr=False)


@dataclass(frozen=True)
class MatchRun:
    run_id: str
    attempt_id: str
    run_no: int
    status: MatchRunStatus
    aggregate_version: int
    matching_rule_bundle_id: str
    input_manifest: Optional[MatchInputManifest] = field(repr=False)
    input_set_sha256: Optional[str] = field(repr=False)
    ordered_result_sha256: Optional[str] = field(repr=False)
    candidate_count: Optional[int]
    eligible_count: Optional[int]
    excluded_count: Optional[int]
    worker_id: Optional[str] = field(repr=False)
    lease_token: Optional[str] = field(repr=False)
    fencing_generation: int = field(repr=False)
    lease_until: Optional[datetime] = field(repr=False)
    supersedes_run_id: Optional[str]
    superseded_by_run_id: Optional[str]
    failure_code: Optional[str]
    created_at: datetime
    updated_at: datetime

    def start(self, **facts: object) -> "MatchRun":
        _require_state(self.status is MatchRunStatus.QUEUED)
        now = _datetime_fact(facts, "now")
        lease_until = _datetime_fact(facts, "lease_until")
        generation = _positive_int_fact(facts, "fencing_generation")
        if lease_until <= now or generation <= self.fencing_generation:
            _reject("LEASE_FENCING_REJECTED")
        return replace(
            self,
            status=MatchRunStatus.RUNNING,
            aggregate_version=self.aggregate_version + 1,
            worker_id=_string_fact(facts, "worker_id"),
            lease_token=_string_fact(facts, "lease_token"),
            fencing_generation=generation,
            lease_until=lease_until,
            updated_at=now,
        )

    def complete(self, **facts: object) -> "MatchRun":
        now = _datetime_fact(facts, "now")
        self._require_fenced_worker(facts=facts, now=now)
        candidates = facts.get("candidates")
        if not isinstance(candidates, tuple) or not all(
            isinstance(item, MatchCandidate) for item in candidates
        ):
            _reject("MATCH_RESULT_INVALID")
        for item in candidates:
            validate_match_candidate(item)
            if item.run_id != self.run_id or item.attempt_id != self.attempt_id:
                _reject("MATCH_RESULT_INVALID")
        eligible_count = sum(
            item.eligibility is CandidateEligibility.ELIGIBLE
            for item in candidates
        )
        return replace(
            self,
            status=MatchRunStatus.COMPLETED,
            aggregate_version=self.aggregate_version + 1,
            ordered_result_sha256=_digest_fact(facts, "ordered_result_sha256"),
            candidate_count=len(candidates),
            eligible_count=eligible_count,
            excluded_count=len(candidates) - eligible_count,
            updated_at=now,
        )

    def fail(self, **facts: object) -> "MatchRun":
        now = _datetime_fact(facts, "now")
        self._require_fenced_worker(facts=facts, now=now)
        return replace(
            self,
            status=MatchRunStatus.FAILED,
            aggregate_version=self.aggregate_version + 1,
            failure_code=_code_fact(facts, "failure_code"),
            updated_at=now,
        )

    def supersede(self, **facts: object) -> "MatchRun":
        if self.status not in {MatchRunStatus.FAILED, MatchRunStatus.COMPLETED}:
            _reject("INVALID_STATE_TRANSITION")
        successor_run_id = _string_fact(facts, "successor_run_id")
        if successor_run_id == self.run_id:
            _reject("INVALID_STATE_TRANSITION")
        return replace(
            self,
            status=MatchRunStatus.SUPERSEDED,
            aggregate_version=self.aggregate_version + 1,
            superseded_by_run_id=successor_run_id,
            updated_at=_datetime_fact(facts, "now"),
        )

    def _require_fenced_worker(
        self, *, facts: dict[str, object], now: datetime
    ) -> None:
        if self.status is not MatchRunStatus.RUNNING:
            _reject("INVALID_STATE_TRANSITION")
        if (
            _string_fact(facts, "worker_id") != self.worker_id
            or _string_fact(facts, "lease_token") != self.lease_token
            or _positive_int_fact(facts, "fencing_generation")
            != self.fencing_generation
            or self.lease_until is None
            or self.lease_until <= now
        ):
            _reject("LEASE_FENCING_REJECTED")


@dataclass(frozen=True)
class AttemptDemandBinding:
    """Immutable Demand/source facts captured when an attempt is opened."""

    attempt_id: str
    source_event_id: str
    organization_id: str
    demand_id: str
    demand_aggregate_version: int
    demand_version_id: str
    funding_id: str
    matching_request_id: str
    matching_request_version: int
    composite_rule_requirement_id: str
    matching_rule_bundle_id: str
    selector_digest: str = field(repr=False)
    created_at: datetime


@dataclass(frozen=True)
class MatchingAttempt:
    attempt_id: str
    organization_id: str
    demand_id: str
    demand_version_id: str
    matching_request_id: str
    funding_id: str
    attempt_no: int
    status: MatchingAttemptStatus
    aggregate_version: int
    current_match_run_id: Optional[str]
    selection_id: Optional[str]
    input_baseline_sha256: str = field(repr=False)
    created_at: datetime
    updated_at: datetime

    @classmethod
    def open(cls, **facts: object) -> tuple["MatchingAttempt", MatchRun]:
        now = _datetime_fact(facts, "now")
        attempt_id = _string_fact(facts, "attempt_id")
        run_id = _string_fact(facts, "run_id")
        attempt = cls(
            attempt_id=attempt_id,
            organization_id=_string_fact(facts, "organization_id"),
            demand_id=_string_fact(facts, "demand_id"),
            demand_version_id=_string_fact(facts, "demand_version_id"),
            matching_request_id=_string_fact(facts, "matching_request_id"),
            funding_id=_string_fact(facts, "funding_id"),
            attempt_no=_positive_int_fact(facts, "attempt_no"),
            status=MatchingAttemptStatus.OPEN,
            aggregate_version=1,
            current_match_run_id=run_id,
            selection_id=None,
            input_baseline_sha256=_digest_fact(facts, "input_baseline_sha256"),
            created_at=now,
            updated_at=now,
        )
        matching_rule_bundle_id = facts.get(
            "matching_rule_bundle_id", "matching_bundle_pending"
        )
        if not isinstance(matching_rule_bundle_id, str):
            _reject("INVALID_REQUEST")
        run = MatchRun(
            run_id=run_id,
            attempt_id=attempt_id,
            run_no=1,
            status=MatchRunStatus.QUEUED,
            aggregate_version=1,
            matching_rule_bundle_id=matching_rule_bundle_id,
            input_manifest=None,
            input_set_sha256=None,
            ordered_result_sha256=None,
            candidate_count=None,
            eligible_count=None,
            excluded_count=None,
            worker_id=None,
            lease_token=None,
            fencing_generation=0,
            lease_until=None,
            supersedes_run_id=None,
            superseded_by_run_id=None,
            failure_code=None,
            created_at=now,
            updated_at=now,
        )
        return attempt, run

    def close_without_selection(self, **facts: object) -> "MatchingAttempt":
        _require_state(self.status is MatchingAttemptStatus.OPEN)
        return replace(
            self,
            status=MatchingAttemptStatus.CLOSED_NO_SELECTION,
            aggregate_version=self.aggregate_version + 1,
            updated_at=_datetime_fact(facts, "now"),
        )

    def invalidate(self, **facts: object) -> "MatchingAttempt":
        _require_state(self.status is MatchingAttemptStatus.OPEN)
        return replace(
            self,
            status=MatchingAttemptStatus.INVALIDATED,
            aggregate_version=self.aggregate_version + 1,
            updated_at=_datetime_fact(facts, "now"),
        )

    def cancel(self, **facts: object) -> "MatchingAttempt":
        _require_state(self.status is MatchingAttemptStatus.OPEN)
        return replace(
            self,
            status=MatchingAttemptStatus.CANCELLED,
            aggregate_version=self.aggregate_version + 1,
            updated_at=_datetime_fact(facts, "now"),
        )

    def select(self, **facts: object) -> "MatchingAttempt":
        _require_state(self.status is MatchingAttemptStatus.OPEN)
        selection_id = _string_fact(facts, "selection_id")
        if self.selection_id not in {None, selection_id}:
            _reject("INVALID_STATE_TRANSITION")
        return replace(
            self,
            status=MatchingAttemptStatus.SELECTED,
            aggregate_version=self.aggregate_version + 1,
            selection_id=selection_id,
            updated_at=_datetime_fact(facts, "now"),
        )


@dataclass(frozen=True)
class InvitationDisclosureSnapshot:
    snapshot_id: str
    invitation_id: str
    attempt_id: str
    demand_id: str
    demand_version_id: str
    profile_id: str
    profile_version_id: str
    demand_content_sha256: str
    profile_content_sha256: str
    snapshot_sha256: str = field(repr=False)
    canonical_bytes: bytes = field(repr=False)


@dataclass(frozen=True)
class InvitationResponse:
    response_id: str
    invitation_id: str
    creator_user_id: str
    response_kind: InvitationResponseKind
    snapshot_sha256: str
    reason_code: Optional[str] = field(repr=False)
    restricted_note: Optional[str] = field(default=None, repr=False)
    responded_at: datetime = field(default_factory=datetime.now)


@dataclass(frozen=True)
class InvitationWithdrawal:
    """Restricted Creator fact that never participates in candidate ranking."""

    withdrawal_id: str
    invitation_id: str
    accepted_response_id: str
    creator_user_id: str
    snapshot_sha256: str = field(repr=False)
    reason_code: str = field(repr=False)
    restricted_note: Optional[str] = field(default=None, repr=False)
    withdrawn_at: datetime = field(default_factory=datetime.now)


@dataclass(frozen=True)
class Invitation:
    invitation_id: str
    attempt_id: str
    match_run_id: str
    creator_user_id: str
    profile_id: str
    profile_version_id: str
    profile_content_sha256: str
    demand_id: str
    demand_version_id: str
    funding_id: str
    matching_rule_bundle_id: str
    disclosure_snapshot_id: str
    snapshot_sha256: str = field(repr=False)
    status: InvitationStatus = InvitationStatus.CREATED
    aggregate_version: int = 1
    expires_at: datetime = field(default_factory=datetime.now)
    created_at: datetime = field(default_factory=datetime.now)
    sent_at: Optional[datetime] = None
    responded_at: Optional[datetime] = None
    updated_at: datetime = field(default_factory=datetime.now)
    withdrawn_at: Optional[datetime] = None

    @classmethod
    def create(cls, **facts: object) -> "Invitation":
        candidate = facts.get("candidate")
        run = facts.get("run")
        if not isinstance(candidate, MatchCandidate) or not isinstance(run, MatchRun):
            _reject("RESOURCE_NOT_FOUND")
        if (
            run.status is not MatchRunStatus.COMPLETED
            or run.superseded_by_run_id is not None
            or candidate.run_id != run.run_id
            or candidate.eligibility is not CandidateEligibility.ELIGIBLE
        ):
            _reject("RESOURCE_NOT_FOUND")
        now = _datetime_fact(facts, "now")
        expires_at = _datetime_fact(facts, "expires_at")
        if expires_at <= now:
            _reject("INVALID_REQUEST")
        return cls(
            invitation_id=_string_fact(facts, "invitation_id"),
            attempt_id=candidate.attempt_id,
            match_run_id=run.run_id,
            creator_user_id=candidate.creator_user_id,
            profile_id=candidate.profile_id,
            profile_version_id=candidate.profile_version_id,
            profile_content_sha256=candidate.profile_content_sha256,
            demand_id=_string_fact(facts, "demand_id"),
            demand_version_id=_string_fact(facts, "demand_version_id"),
            funding_id=_string_fact(facts, "funding_id"),
            matching_rule_bundle_id=run.matching_rule_bundle_id,
            disclosure_snapshot_id=_string_fact(facts, "disclosure_snapshot_id"),
            snapshot_sha256=_digest_fact(facts, "snapshot_sha256"),
            status=InvitationStatus.CREATED,
            aggregate_version=1,
            expires_at=expires_at,
            created_at=now,
            updated_at=now,
        )

    def publish(self, **facts: object) -> "Invitation":
        _require_state(self.status is InvitationStatus.CREATED)
        now = _datetime_fact(facts, "now")
        if self.expires_at <= now:
            _reject("INVALID_STATE_TRANSITION")
        if _digest_fact(facts, "snapshot_sha256") != self.snapshot_sha256:
            _reject("PRECONDITION_FAILED")
        return replace(
            self,
            status=InvitationStatus.SENT,
            aggregate_version=self.aggregate_version + 1,
            sent_at=now,
            updated_at=now,
        )

    def respond(self, **facts: object) -> tuple["Invitation", InvitationResponse]:
        _require_state(self.status is InvitationStatus.SENT)
        now = _datetime_fact(facts, "now")
        if invitation_is_expired(invitation=self, database_now=now):
            _reject("INVALID_STATE_TRANSITION")
        creator_user_id = _string_fact(facts, "creator_user_id")
        if creator_user_id != self.creator_user_id:
            _reject("RESOURCE_NOT_FOUND")
        snapshot_sha256 = _digest_fact(facts, "snapshot_sha256")
        if snapshot_sha256 != self.snapshot_sha256:
            _reject("PRECONDITION_FAILED")
        response_kind = facts.get("response_kind")
        if not isinstance(response_kind, InvitationResponseKind):
            _reject("INVALID_REQUEST")
        reason_code = facts.get("reason_code")
        if response_kind is InvitationResponseKind.ACCEPTED and reason_code is not None:
            _reject("INVALID_REQUEST")
        if response_kind is InvitationResponseKind.DECLINED:
            reason_code = _code_fact(facts, "reason_code")
        status = (
            InvitationStatus.ACCEPTED
            if response_kind is InvitationResponseKind.ACCEPTED
            else InvitationStatus.DECLINED
        )
        response = InvitationResponse(
            response_id=_string_fact(facts, "response_id"),
            invitation_id=self.invitation_id,
            creator_user_id=creator_user_id,
            response_kind=response_kind,
            snapshot_sha256=snapshot_sha256,
            reason_code=reason_code if isinstance(reason_code, str) else None,
            restricted_note=_optional_string_fact(facts, "note"),
            responded_at=now,
        )
        return (
            replace(
                self,
                status=status,
                aggregate_version=self.aggregate_version + 1,
                responded_at=now,
                updated_at=now,
            ),
            response,
        )

    def expire(self, **facts: object) -> "Invitation":
        if self.status not in {InvitationStatus.CREATED, InvitationStatus.SENT}:
            _reject("INVALID_STATE_TRANSITION")
        now = _datetime_fact(facts, "now")
        if self.expires_at > now:
            _reject("INVALID_STATE_TRANSITION")
        return replace(
            self,
            status=InvitationStatus.EXPIRED,
            aggregate_version=self.aggregate_version + 1,
            updated_at=now,
        )

    def withdraw(
        self, **facts: object
    ) -> tuple["Invitation", InvitationWithdrawal]:
        """Withdraw a prior acceptance while human selection is still idle."""

        _require_state(self.status is InvitationStatus.ACCEPTED)
        creator_user_id = _string_fact(facts, "creator_user_id")
        if creator_user_id != self.creator_user_id:
            _reject("RESOURCE_NOT_FOUND")
        if _digest_fact(facts, "snapshot_sha256") != self.snapshot_sha256:
            _reject("PRECONDITION_FAILED")
        if (
            facts.get("selection_status") is not SelectionStatus.OPEN
            or facts.get("selection_intent_recorded") is not False
        ):
            _reject("SELECTION_ALREADY_IN_PROGRESS")
        now = _datetime_fact(facts, "now")
        withdrawal = InvitationWithdrawal(
            withdrawal_id=_string_fact(facts, "withdrawal_id"),
            invitation_id=self.invitation_id,
            accepted_response_id=_string_fact(
                facts,
                "accepted_response_id",
            ),
            creator_user_id=creator_user_id,
            snapshot_sha256=self.snapshot_sha256,
            reason_code=_code_fact(facts, "reason_code"),
            restricted_note=_optional_string_fact(facts, "note"),
            withdrawn_at=now,
        )
        return (
            replace(
                self,
                status=InvitationStatus.WITHDRAWN,
                aggregate_version=self.aggregate_version + 1,
                withdrawn_at=now,
                updated_at=now,
            ),
            withdrawal,
        )

    def revoke(self, **facts: object) -> "Invitation":
        if self.status not in {InvitationStatus.CREATED, InvitationStatus.SENT}:
            _reject("INVALID_STATE_TRANSITION")
        now = _datetime_fact(facts, "now")
        return replace(
            self,
            status=InvitationStatus.REVOKED,
            aggregate_version=self.aggregate_version + 1,
            updated_at=now,
        )


@dataclass(frozen=True)
class Selection:
    selection_id: str
    attempt_id: str
    status: SelectionStatus
    aggregate_version: int
    current_invitation_set_sha256: str
    chosen_invitation_id: Optional[str]
    selection_basis_code: Optional[str]
    reason_code: Optional[str]
    decision_actor_id: Optional[str]
    created_at: datetime
    updated_at: datetime

    @classmethod
    def open(cls, **facts: object) -> "Selection":
        now = _datetime_fact(facts, "now")
        return cls(
            selection_id=_string_fact(facts, "selection_id"),
            attempt_id=_string_fact(facts, "attempt_id"),
            status=SelectionStatus.OPEN,
            aggregate_version=1,
            current_invitation_set_sha256=_digest_fact(
                facts, "current_invitation_set_sha256"
            ),
            chosen_invitation_id=None,
            selection_basis_code=None,
            reason_code=None,
            decision_actor_id=None,
            created_at=now,
            updated_at=now,
        )

    def choose(self, **facts: object) -> "Selection":
        _require_state(self.status is SelectionStatus.OPEN)
        if (
            _digest_fact(facts, "expected_invitation_set_sha256")
            != self.current_invitation_set_sha256
        ):
            _reject("PRECONDITION_FAILED")
        invitation = facts.get("invitation")
        invitations = facts.get("invitation_set")
        if not isinstance(invitation, Invitation) or not isinstance(invitations, tuple):
            _reject("SELECTION_NOT_READY")
        if (
            invitation.status is not InvitationStatus.ACCEPTED
            or invitation.attempt_id != self.attempt_id
            or not any(
                isinstance(item, Invitation)
                and item.invitation_id == invitation.invitation_id
                and item.status is InvitationStatus.ACCEPTED
                for item in invitations
            )
        ):
            _reject("SELECTION_NOT_READY")
        return replace(
            self,
            status=SelectionStatus.SELECTED,
            aggregate_version=self.aggregate_version + 1,
            chosen_invitation_id=invitation.invitation_id,
            selection_basis_code=_code_fact(facts, "selection_basis_code"),
            decision_actor_id=_string_fact(facts, "actor_id"),
            updated_at=_datetime_fact(facts, "now"),
        )

    def refresh_invitation_set(self, **facts: object) -> "Selection":
        _require_state(self.status is SelectionStatus.OPEN)
        current_invitation_set_sha256 = _digest_fact(
            facts,
            "current_invitation_set_sha256",
        )
        if current_invitation_set_sha256 == self.current_invitation_set_sha256:
            _reject("PRECONDITION_FAILED")
        return replace(
            self,
            aggregate_version=self.aggregate_version + 1,
            current_invitation_set_sha256=current_invitation_set_sha256,
            updated_at=_datetime_fact(facts, "now"),
        )

    def close_without_choice(self, **facts: object) -> "Selection":
        _require_state(self.status is SelectionStatus.OPEN)
        return replace(
            self,
            status=SelectionStatus.CLOSED_NO_SELECTION,
            aggregate_version=self.aggregate_version + 1,
            reason_code=_code_fact(facts, "reason_code"),
            decision_actor_id=_string_fact(facts, "actor_id"),
            updated_at=_datetime_fact(facts, "now"),
        )

    def cancel(self, **facts: object) -> "Selection":
        _require_state(self.status is SelectionStatus.OPEN)
        return replace(
            self,
            status=SelectionStatus.CANCELLED,
            aggregate_version=self.aggregate_version + 1,
            reason_code=_code_fact(facts, "reason_code"),
            updated_at=_datetime_fact(facts, "now"),
        )


def validate_match_candidate(candidate: MatchCandidate) -> None:
    if not isinstance(candidate, MatchCandidate):
        _reject("MATCH_RESULT_INVALID")
    if candidate.eligibility is CandidateEligibility.ELIGIBLE:
        if candidate.exclusion_reason_codes or candidate.total_score is None:
            _reject("MATCH_RESULT_INVALID")
        if (
            not isinstance(candidate.rank, int)
            or isinstance(candidate.rank, bool)
            or candidate.rank < 1
        ):
            _reject("MATCH_RESULT_INVALID")
        expected_codes = (
            "interest",
            "capability",
            "availability",
            "compensation",
            "collaboration",
            "evidence_trust",
        )
        if len(candidate.components) != 6:
            _reject("MATCH_RESULT_INVALID")
        for ordinal, (component, code) in enumerate(
            zip(candidate.components, expected_codes), 1
        ):
            if (
                component.code != code
                or component.ordinal != ordinal
                or not isinstance(component.score, Decimal)
                or component.score < Decimal("0")
                or component.score > Decimal("100")
                or component.score != component.score.quantize(Decimal("0.01"))
            ):
                _reject("MATCH_RESULT_INVALID")
        if (
            not isinstance(candidate.total_score, Decimal)
            or candidate.total_score < Decimal("0")
            or candidate.total_score > Decimal("100")
            or candidate.total_score
            != candidate.total_score.quantize(Decimal("0.01"))
        ):
            _reject("MATCH_RESULT_INVALID")
    else:
        if (
            not candidate.exclusion_reason_codes
            or candidate.components
            or candidate.total_score is not None
            or candidate.rank is not None
            or len(candidate.exclusion_reason_codes)
            != len(set(candidate.exclusion_reason_codes))
        ):
            _reject("MATCH_RESULT_INVALID")
    _require_digest(candidate.profile_content_sha256)
    for fact in candidate.evidence_facts:
        if fact.kind not in {"BOOLEAN", "CODE", "BUCKET"}:
            _reject("MATCH_RESULT_INVALID")
        if fact.kind == "BOOLEAN" and not isinstance(fact.value, bool):
            _reject("MATCH_RESULT_INVALID")
        if fact.kind != "BOOLEAN" and not isinstance(fact.value, str):
            _reject("MATCH_RESULT_INVALID")
        _require_digest(fact.source_version_digest)


def validate_candidate_selector_assignment(
    assignment: CandidateSelectorAssignment,
    *,
    database_now: datetime,
) -> None:
    """Fail closed unless an exact assignment fact is currently exercisable."""

    if (
        not isinstance(assignment, CandidateSelectorAssignment)
        or not isinstance(database_now, datetime)
        or not isinstance(assignment.aggregate_version, int)
        or isinstance(assignment.aggregate_version, bool)
        or assignment.aggregate_version < 1
        or assignment.status is not CandidateSelectorAssignmentStatus.ACTIVE
        or assignment.role_code is not CandidateSelectorRoleCode.CANDIDATE_SELECTOR
        or not assignment.assignment_id
        or not assignment.assigned_user_id
        or not assignment.organization_id
        or not assignment.demand_id
        or not assignment.selection_id
        or not isinstance(assignment.assigned_at, datetime)
        or not isinstance(assignment.expires_at, datetime)
        or assignment.assigned_at.tzinfo is None
        or assignment.assigned_at.utcoffset() is None
        or assignment.expires_at.tzinfo is None
        or assignment.expires_at.utcoffset() is None
        or database_now.tzinfo is None
        or database_now.utcoffset() is None
        or assignment.assigned_at > database_now
        or assignment.expires_at <= database_now
        or assignment.expires_at <= assignment.assigned_at
    ):
        _reject("CANDIDATE_SELECTOR_ASSIGNMENT_INACTIVE")


def canonical_candidate_result_bytes(candidate: MatchCandidate) -> bytes:
    validate_match_candidate(candidate)
    value = {
        "schema_version": 1,
        "canonicalization_version": "match-candidate-result-json-v1",
        "attempt_id": candidate.attempt_id,
        "run_id": candidate.run_id,
        "creator_user_id": candidate.creator_user_id,
        "profile_id": candidate.profile_id,
        "profile_version_id": candidate.profile_version_id,
        "profile_content_sha256": candidate.profile_content_sha256,
        "eligibility": candidate.eligibility.value,
        "exclusion_reason_codes": list(candidate.exclusion_reason_codes),
        "components": [
            {
                "code": item.code,
                "ordinal": item.ordinal,
                "score": _score_string(item.score),
            }
            for item in candidate.components
        ],
        "total_score": (
            _score_string(candidate.total_score)
            if candidate.total_score is not None
            else None
        ),
        "rank": candidate.rank,
        "evidence_facts": [
            {
                "code": item.code,
                "kind": item.kind,
                "value": item.value,
                "source_version_digest": item.source_version_digest,
            }
            for item in candidate.evidence_facts
        ],
    }
    return _jcs_bytes(value)


def candidate_result_sha256(candidate: MatchCandidate) -> str:
    return hashlib.sha256(canonical_candidate_result_bytes(candidate)).hexdigest()


def canonical_match_input_bytes(
    *, manifest: MatchInputManifest, run_input: MatchRunInput
) -> bytes:
    if (
        manifest.attempt_id != run_input.attempt_id
        or manifest.run_id != run_input.run_id
        or manifest.demand_id != run_input.demand_id
        or manifest.demand_version_id != run_input.demand_version_id
        or manifest.matching_rule_bundle_id
        != run_input.matching_rule_bundle_id
        or manifest.candidate_count
        != len(manifest.ordered_candidate_identities)
        or manifest.candidate_count != len(run_input.profile_facts)
    ):
        _reject("MATCH_INPUT_CHANGED")
    identities = [
        {
            "creator_user_id": creator_user_id,
            "profile_id": profile_id,
            "profile_version_id": profile_version_id,
            "profile_content_sha256": profile_content_sha256,
            "evidence_version_digest": evidence_version_digest,
        }
        for (
            creator_user_id,
            profile_id,
            profile_version_id,
            profile_content_sha256,
            evidence_version_digest,
        ) in manifest.ordered_candidate_identities
    ]
    profiles = [_frozen_object(item) for item in run_input.profile_facts]
    for identity, profile in zip(identities, profiles):
        if any(profile.get(name) != value for name, value in identity.items()):
            _reject("MATCH_INPUT_CHANGED")
    surface = {
        "manifest_references": {
            "attempt_id": manifest.attempt_id,
            "run_id": manifest.run_id,
            "organization_id": manifest.organization_id,
            "demand_id": manifest.demand_id,
            "demand_version_id": manifest.demand_version_id,
            "demand_content_sha256": manifest.demand_content_sha256,
            "funding_id": manifest.funding_id,
            "matching_request_id": manifest.matching_request_id,
            "matching_request_version": manifest.matching_request_version,
            "matching_rule_bundle_id": manifest.matching_rule_bundle_id,
            "selector_digest": manifest.selector_digest,
            "rule_manifest_sha256": manifest.rule_manifest_sha256,
            "ordered_candidates": identities,
            "captured_at": manifest.captured_at.isoformat().replace(
                "+00:00", "Z"
            ),
            "candidate_count": manifest.candidate_count,
        },
        "run_input": {
            "schema_version": 1,
            "canonicalization_version": "match-run-input-json-v1",
            "attempt_id": run_input.attempt_id,
            "run_id": run_input.run_id,
            "demand_id": run_input.demand_id,
            "demand_version_id": run_input.demand_version_id,
            "matching_rule_bundle_id": run_input.matching_rule_bundle_id,
            "demand": _frozen_object(run_input.demand_facts),
            "profiles": profiles,
        },
    }
    return _jcs_bytes(surface)


def match_input_set_sha256(
    *, manifest: MatchInputManifest, run_input: MatchRunInput
) -> str:
    return hashlib.sha256(
        canonical_match_input_bytes(manifest=manifest, run_input=run_input)
    ).hexdigest()


def canonical_selection_invitation_set_bytes(
    *,
    attempt_id: str,
    run_id: str,
    invitations: Tuple[Union[Invitation, SelectionInvitationSetEntry], ...],
) -> bytes:
    """Canonical owner-visible Invitation state bound to an open Selection."""

    if not isinstance(attempt_id, str) or not attempt_id:
        _reject("INVALID_REQUEST")
    if not isinstance(run_id, str) or not run_id:
        _reject("INVALID_REQUEST")
    if not isinstance(invitations, tuple):
        _reject("INVALID_REQUEST")
    if any(
        not isinstance(item, (Invitation, SelectionInvitationSetEntry))
        for item in invitations
    ):
        _reject("MATCH_INPUT_CHANGED")
    visible = tuple(
        item for item in invitations if item.status is not InvitationStatus.CREATED
    )
    if any(
        item.attempt_id != attempt_id or item.match_run_id != run_id
        for item in visible
    ):
        _reject("MATCH_INPUT_CHANGED")
    invitation_ids = tuple(item.invitation_id for item in visible)
    if len(invitation_ids) != len(frozenset(invitation_ids)):
        _reject("MATCH_INPUT_CHANGED")
    for item in visible:
        _require_digest(item.snapshot_sha256)
        if (
            not isinstance(item.aggregate_version, int)
            or isinstance(item.aggregate_version, bool)
            or item.aggregate_version < 1
        ):
            _reject("MATCH_INPUT_CHANGED")
    ordered = sorted(visible, key=lambda item: item.invitation_id.encode("utf-8"))
    return _jcs_bytes(
        {
            "schema_version": 1,
            "canonicalization_version": "selection-invitation-set-json-v1",
            "attempt_id": attempt_id,
            "run_id": run_id,
            "invitations": [
                {
                    "invitation_id": item.invitation_id,
                    "aggregate_version": item.aggregate_version,
                    "status": item.status.value,
                    "snapshot_sha256": item.snapshot_sha256,
                }
                for item in ordered
            ],
        }
    )


def selection_invitation_set_sha256(
    *,
    attempt_id: str,
    run_id: str,
    invitations: Tuple[Union[Invitation, SelectionInvitationSetEntry], ...],
) -> str:
    return hashlib.sha256(
        canonical_selection_invitation_set_bytes(
            attempt_id=attempt_id,
            run_id=run_id,
            invitations=invitations,
        )
    ).hexdigest()


def deterministic_rank_and_hash(
    *,
    candidates: Tuple[MatchCandidate, ...],
    matching_rule_bundle_id: str,
    input_set_sha256: str,
) -> tuple[Tuple[MatchCandidate, ...], str]:
    _require_digest(input_set_sha256)
    if not isinstance(candidates, tuple):
        _reject("MATCH_RESULT_INVALID")
    if len({item.creator_user_id for item in candidates}) != len(candidates):
        _reject("MATCH_RESULT_INVALID")
    for item in candidates:
        validate_match_candidate(item)
    eligible = sorted(
        (
            item
            for item in candidates
            if item.eligibility is CandidateEligibility.ELIGIBLE
        ),
        key=lambda item: (
            -item.total_score,  # type: ignore[operator]
            item.creator_user_id.encode("utf-8"),
        ),
    )
    ranked = [
        replace(item, rank=rank, candidate_result_sha256="")
        for rank, item in enumerate(eligible, 1)
    ]
    excluded = sorted(
        (
            item
            for item in candidates
            if item.eligibility is CandidateEligibility.EXCLUDED
        ),
        key=lambda item: item.creator_user_id.encode("utf-8"),
    )
    normalized = tuple(
        replace(item, candidate_result_sha256=candidate_result_sha256(item))
        for item in (*ranked, *excluded)
    )
    result_surface = {
        "matching_rule_bundle_id": matching_rule_bundle_id,
        "input_set_sha256": input_set_sha256,
        "candidate_digests": [
            {
                "creator_user_id": item.creator_user_id,
                "eligibility": item.eligibility.value,
                "rank": item.rank,
                "candidate_result_sha256": item.candidate_result_sha256,
            }
            for item in normalized
        ],
    }
    return normalized, hashlib.sha256(_jcs_bytes(result_surface)).hexdigest()


def validate_invitation_disclosure(snapshot: InvitationDisclosureSnapshot) -> None:
    if not isinstance(snapshot, InvitationDisclosureSnapshot):
        _reject("INVALID_REQUEST")
    _require_digest(snapshot.demand_content_sha256)
    _require_digest(snapshot.profile_content_sha256)
    _require_digest(snapshot.snapshot_sha256)
    if len(snapshot.canonical_bytes) > 65536:
        _reject("INVALID_REQUEST")
    try:
        value = json.loads(snapshot.canonical_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MatchingDomainError("INVALID_REQUEST") from error
    root_fields = {
        "schema_version",
        "canonicalization_version",
        "invitation_id",
        "attempt_id",
        "demand_id",
        "demand_version_id",
        "profile_id",
        "profile_version_id",
        "organization_preview",
        "opportunity",
        "offer",
        "constraints",
        "expires_at",
        "demand_content_sha256",
        "profile_content_sha256",
    }
    if not isinstance(value, dict) or set(value) != root_fields:
        _reject("INVALID_REQUEST")
    # The frozen disclosure-v1 Timestamp is RFC 3339 with a literal Z suffix.
    # Validate the signed value before storage; never rewrite a signed string
    # or its digest to accommodate a producer that emitted an offset instead.
    expires_at = value["expires_at"]
    if not isinstance(expires_at, str) or re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z",
        expires_at,
    ) is None:
        _reject("INVALID_REQUEST")
    try:
        datetime.fromisoformat(expires_at[:-1] + "+00:00")
    except ValueError:
        _reject("INVALID_REQUEST")
    if snapshot.canonical_bytes != _jcs_bytes(value):
        _reject("INVALID_REQUEST")
    expected_bindings = {
        "schema_version": 1,
        "canonicalization_version": "invitation-disclosure-json-v1",
        "invitation_id": snapshot.invitation_id,
        "attempt_id": snapshot.attempt_id,
        "demand_id": snapshot.demand_id,
        "demand_version_id": snapshot.demand_version_id,
        "profile_id": snapshot.profile_id,
        "profile_version_id": snapshot.profile_version_id,
        "demand_content_sha256": snapshot.demand_content_sha256,
        "profile_content_sha256": snapshot.profile_content_sha256,
    }
    if any(value[name] != expected for name, expected in expected_bindings.items()):
        _reject("PRECONDITION_FAILED")
    object_shapes = {
        "organization_preview": {"organization_id", "display_label"},
        "opportunity": {
            "title",
            "problem_summary",
            "deliverable_summaries",
            "acceptance_summaries",
        },
        "offer": {
            "currency",
            "minimum_amount_minor",
            "maximum_amount_minor",
            "schedule_code",
            "duration_weeks",
        },
        "constraints": {
            "region_codes",
            "language_codes",
            "data_sensitivity_code",
            "ai_use_code",
        },
    }
    for name, fields in object_shapes.items():
        child = value[name]
        if not isinstance(child, dict) or set(child) != fields:
            _reject("INVALID_REQUEST")
    offer = value["offer"]
    for name in ("minimum_amount_minor", "maximum_amount_minor", "duration_weeks"):
        if (
            not isinstance(offer[name], int)
            or isinstance(offer[name], bool)
            or offer[name] < 0
        ):
            _reject("INVALID_REQUEST")
    if offer["minimum_amount_minor"] > offer["maximum_amount_minor"]:
        _reject("INVALID_REQUEST")
    for text in _all_strings(value):
        if any(character in text for character in ("<", ">")) or "http://" in text.lower() or "https://" in text.lower():
            _reject("INVALID_REQUEST")
    if (
        hashlib.sha256(snapshot.canonical_bytes).hexdigest()
        != snapshot.snapshot_sha256
    ):
        _reject("PRECONDITION_FAILED")


def invitation_is_expired(*, invitation: Invitation, database_now: datetime) -> bool:
    return invitation.expires_at <= database_now


def _not_available() -> Any:
    raise MatchingDomainBehaviorNotAvailable(
        MATCHING_DOMAIN_BEHAVIOR_NOT_AVAILABLE
    )


def _reject(code: str) -> Any:
    raise MatchingDomainError(code)


def _require_state(condition: bool) -> None:
    if not condition:
        _reject("INVALID_STATE_TRANSITION")


def _string_fact(facts: dict[str, object], name: str) -> str:
    value = facts.get(name)
    if not isinstance(value, str) or not value:
        _reject("INVALID_REQUEST")
    return value


def _optional_string_fact(
    facts: dict[str, object], name: str
) -> Optional[str]:
    value = facts.get(name)
    if value is None:
        return None
    if not isinstance(value, str):
        _reject("INVALID_REQUEST")
    return value


def _code_fact(facts: dict[str, object], name: str) -> str:
    value = _string_fact(facts, name)
    if not value.replace("_", "").isalnum() or value.upper() != value:
        _reject("INVALID_REQUEST")
    return value


def _datetime_fact(facts: dict[str, object], name: str) -> datetime:
    value = facts.get(name)
    if not isinstance(value, datetime) or value.tzinfo is None:
        _reject("INVALID_REQUEST")
    return value


def _positive_int_fact(facts: dict[str, object], name: str) -> int:
    value = facts.get(name)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        _reject("INVALID_REQUEST")
    return value


def _digest_fact(facts: dict[str, object], name: str) -> str:
    value = _string_fact(facts, name)
    _require_digest(value)
    return value


def _require_digest(value: str) -> None:
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        _reject("INVALID_REQUEST")


def _score_string(value: Decimal) -> str:
    return format(value.quantize(Decimal("0.01")), "f")


def _jcs_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _all_strings(value: object) -> Tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, dict):
        return tuple(
            child
            for item in value.values()
            for child in _all_strings(item)
        )
    if isinstance(value, list):
        return tuple(child for item in value for child in _all_strings(item))
    return ()


def _frozen_object(value: Tuple[Tuple[str, FrozenJson], ...]) -> dict[str, object]:
    if len({key for key, _ in value}) != len(value):
        _reject("MATCH_INPUT_CHANGED")

    def thaw(child: FrozenJson) -> object:
        if isinstance(child, tuple):
            if child and all(
                isinstance(item, tuple)
                and len(item) == 2
                and isinstance(item[0], str)
                for item in child
            ):
                return _frozen_object(child)  # type: ignore[arg-type]
            return [thaw(item) for item in child]
        return child

    return {key: thaw(child) for key, child in value}
