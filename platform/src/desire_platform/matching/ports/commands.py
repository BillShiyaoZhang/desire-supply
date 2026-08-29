"""Closed dependency ports for Matching command orchestration."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, ContextManager, Mapping, Optional, Protocol, Sequence, Tuple

from ..application.commands import MatchingActorContext, MatchingRequestedSourceEvent
from ..domain.model import (
    CandidateSelectorAssignment,
    MatchInputManifest,
    MatchRunInput,
)


class MatchingStorageUnavailableError(Exception):
    """Storage failed before COMMIT was sent."""


class MatchingCommitOutcomeUnknownError(Exception):
    """COMMIT was sent but its durable outcome was not acknowledged."""


class MatchingAuthorityUnavailableError(Exception):
    """Exact IAM or assignment authority could not be read safely."""


class MatchingSourceEventInvalidError(Exception):
    """Source envelope/workload/target binding is invalid."""


class MatchingInputChangedError(Exception):
    """Demand/Profile capture is missing, duplicated, reordered or drifted."""


class MatchingSafetyHoldUnavailableError(Exception):
    """Versioned transaction SafetyHold could not be evaluated safely."""


class MatchingSafeResponseInvalidError(Exception):
    """A persisted or newly built response failed its closed validator."""


@dataclass(frozen=True)
class MatchingPrincipalAuthority:
    actor_kind: MatchingActorKind
    actor_id: str
    session_id: Optional[str] = field(default=None, repr=False)
    user_status: Optional[str] = None
    session_status: Optional[str] = None
    session_family_status: Optional[str] = None
    workload_credential_id: Optional[str] = field(default=None, repr=False)
    workload_credential_status: Optional[str] = None
    valid_until: Optional[datetime] = None
    principal_marker_sha256: str = ""


@dataclass(frozen=True)
class MatchingSystemAuthority:
    workload_principal_id: str
    workload_credential_id: str = field(repr=False)
    operation: str
    organization_id: str
    attempt_id: Optional[str]
    match_run_id: Optional[str]
    source_event_id: Optional[str]
    job_id: Optional[str]
    valid_until: datetime
    authority_marker_sha256: str


@dataclass(frozen=True)
class MatchingReviewerAuthority:
    actor_user_id: str
    session_id: str = field(repr=False)
    organization_id: str
    assignment_id: str
    assignment_status: str
    assignment_version: int
    assignment_expires_at: datetime
    assignment_attempt_id: str
    assignment_run_id: Optional[str]
    assignment_purpose: str
    duty_grant_id: str
    duty_grant_version: int
    duty_code: str
    conflict_attestation_sha256: str
    authority_marker_sha256: str


@dataclass(frozen=True)
class MatchingCreatorAuthority:
    actor_user_id: str
    session_id: str = field(repr=False)
    user_status: str
    session_status: str
    session_family_status: str
    creator_grant_id: str
    creator_grant_version: int
    creator_grant_status: str
    invitation_id: str
    profile_id: str
    profile_version_id: str
    authority_marker_sha256: str


@dataclass(frozen=True)
class MatchingCandidateSelectorAuthority:
    """Exact assignment authority; never inferred from an organization role."""

    actor_user_id: str
    session_id: str = field(repr=False)
    assignment: CandidateSelectorAssignment
    authority_marker_sha256: str = field(repr=False)


@dataclass(frozen=True)
class DemandMatchingFacts:
    organization_id: str
    demand_id: str
    demand_aggregate_version: int
    demand_version_id: str
    demand_content_sha256: str
    funding_id: str
    funding_status: str
    matching_request_id: str
    matching_request_version: int
    matching_request_status: str
    composite_rule_requirement_id: str
    selector_digest: str
    matching_rule_bundle_id: str
    discovery_facts: Tuple[Tuple[str, object], ...] = field(repr=False)


@dataclass(frozen=True)
class CapturedMatchInputs:
    manifest: MatchInputManifest = field(repr=False)
    run_input: MatchRunInput = field(repr=False)
    candidate_allowlist_sha256: str
    captured_at: datetime


@dataclass(frozen=True)
class MatchingProfileFacts:
    creator_user_id: str
    user_status: str
    creator_grant_status: str
    profile_id: str
    profile_status: str
    current_profile_version_id: str
    current_profile_content_sha256: str
    current_evidence_version_digest: str


class MatchingHoldDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class MatchingSafetyHoldResult:
    decision: MatchingHoldDecision
    action: str
    actor_id: str
    organization_id: str
    attempt_id: str
    match_run_id: Optional[str]
    candidate_creator_user_id: Optional[str]
    invitation_id: Optional[str]
    selection_id: Optional[str]
    prospective_versions_sha256: str
    demand_profile_input_result_snapshot_sha256: str
    policy_version: str
    evaluated_at: datetime
    valid_until: datetime


class MatchingSystemAuthorityPort(Protocol):
    def authorize(self, *, actor: MatchingActorContext, operation: str, source_event_id: Optional[str], attempt_id: Optional[str], match_run_id: Optional[str]) -> MatchingSystemAuthority: ...


class MatchingReviewerAuthorityPort(Protocol):
    def authorize(self, *, actor: MatchingActorContext, operation: str, assignment_id: str, attempt_id: str, match_run_id: Optional[str]) -> MatchingReviewerAuthority: ...


class MatchingCreatorAuthorityPort(Protocol):
    def authorize(self, *, actor: MatchingActorContext, operation: str, invitation_id: str) -> MatchingCreatorAuthority: ...


class MatchingCandidateSelectorAuthorityPort(Protocol):
    def authorize(self, *, actor: MatchingActorContext, operation: str, organization_id: str, selection_id: str, assignment_id: str) -> MatchingCandidateSelectorAuthority: ...


# Import compatibility only.  The legacy names now require the exact scoped
# assignment shape and cannot represent a DEMAND_OWNER role grant.
MatchingOwnerAuthority = MatchingCandidateSelectorAuthority
MatchingOwnerAuthorityPort = MatchingCandidateSelectorAuthorityPort


class MatchingPrincipalAuthorityPort(Protocol):
    def authenticate(self, *, actor: MatchingActorContext) -> MatchingPrincipalAuthority: ...


class MatchingSourceEventValidatorPort(Protocol):
    def validate(self, *, actor: MatchingActorContext, event: MatchingRequestedSourceEvent) -> None: ...


class DemandMatchingFactsPort(Protocol):
    def read_exact(self, *, organization_id: str, demand_id: str, demand_version_id: str, funding_id: str, matching_request_id: str) -> DemandMatchingFacts: ...


class CaptureMatchInputsPort(Protocol):
    def capture(self, *, attempt_id: str, run_id: str, matching_request_id: str, discovery_facts: Mapping[str, object]) -> CapturedMatchInputs: ...


class MatchingProfileFactsPort(Protocol):
    def read_exact(self, *, creator_user_id: str, profile_id: str, profile_version_id: str) -> MatchingProfileFacts: ...


class MatchingSafetyHoldPort(Protocol):
    def evaluate(self, **binding: object) -> MatchingSafetyHoldResult: ...


class MatchingClock(Protocol):
    def now(self) -> datetime: ...


class MatchingIdSource(Protocol):
    def next_id(self, kind: str) -> str: ...


class MatchingEventValidatorPort(Protocol):
    def validate(self, event: Mapping[str, object]) -> None: ...


class MatchingSafeResponseValidatorPort(Protocol):
    def validate(self, *, operation: str, response: Mapping[str, object]) -> None: ...


class MatchingReceiptKeyringPort(Protocol):
    identity_key_id: str
    payload_hash_key_id: str

    def keyed_digest(self, key_id: str, value: bytes) -> str: ...


class MatchingRepositoryPort(Protocol):
    def get(self, target_id: str) -> Any: ...
    def add(self, value: Any) -> None: ...
    def replace(self, value: Any) -> None: ...


class MatchingUnitOfWorkPort(Protocol):
    def lock(self, resource: str, keys: Sequence[str]) -> None: ...
    def get(self, collection: str, key: str) -> Any: ...
    def values(self, collection: str) -> Tuple[Any, ...]: ...
    def put(self, collection: str, key: str, value: Any) -> None: ...
    def checkpoint(self, name: str) -> None: ...
    def commit(self) -> None: ...


class MatchingSnapshotStorePort(Protocol):
    def snapshot(self) -> Mapping[str, Mapping[str, Any]]: ...


class MatchingUnitOfWorkFactoryPort(Protocol):
    store: MatchingSnapshotStorePort

    def begin(self) -> ContextManager[MatchingUnitOfWorkPort]: ...


class MatchingRecoveryReaderPort(Protocol):
    def read_receipt(self, receipt_identity: str) -> Any: ...
    def read_target(self, target_id: str) -> Any: ...
    def read_fact(self, collection: str, identifier: str) -> Any: ...


class MatchingDisclosureBuilderPort(Protocol):
    def build(self, **facts: object) -> Any: ...
