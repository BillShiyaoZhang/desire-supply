"""Closed dependency ports for Trust command orchestration.

No adapter or in-memory fallback lives in this production module.  Deployment
composition must provide independently authenticated authority, target,
sealed-note, key, clock, identifier, and durable unit-of-work adapters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import (
    TYPE_CHECKING,
    Any,
    ContextManager,
    Mapping,
    Protocol,
    Sequence,
    Tuple,
)

if TYPE_CHECKING:
    from ..application.commands import TrustActorContext
    from ..domain import (
        HoldAction,
        SafetyCase,
        SafetyHold,
        SafetyReport,
        TrustCaseOutcome,
        TrustTriageVersion,
    )


class TrustStorageUnavailableError(Exception):
    """Storage failed before COMMIT was sent."""


class TrustCommitOutcomeUnknownError(Exception):
    """COMMIT was sent but its durable outcome was not acknowledged."""


class TrustAuthorityUnavailableError(Exception):
    """The exact IAM authority projection could not be obtained safely."""


class TrustTargetUnavailableError(Exception):
    """The exact Demand target or conflict projection is unavailable."""


class TrustSealedNoteUnavailableError(Exception):
    """The restricted note could not be durably sealed."""


class TrustDecisionEvidenceUnavailableError(Exception):
    """Server-derived outcome evidence or appeal policy is unavailable."""


@dataclass(frozen=True)
class TrustReporterAuthority:
    actor_user_id: str
    session_id: str = field(repr=False)
    organization_id: str
    user_status: str
    session_status: str
    session_family_status: str
    organization_status: str
    membership_id: str
    membership_status: str
    membership_role_grant_id: str
    membership_role_grant_version: int
    role_code: str
    policy_requirements_satisfied: bool
    authority_marker_sha256: str = field(repr=False)


@dataclass(frozen=True)
class TrustOfficerAuthority:
    actor_user_id: str
    session_id: str = field(repr=False)
    user_status: str
    session_status: str
    session_family_status: str
    duty_grant_id: str
    duty_grant_version: int
    duty_code: str
    authority_marker_sha256: str = field(repr=False)


@dataclass(frozen=True)
class TrustDemandTarget:
    organization_id: str
    demand_id: str
    demand_version_id: str
    demand_version_no: int
    demand_aggregate_version: int
    demand_status: str
    content_sha256: str = field(repr=False)
    owner_user_id: str = field(repr=False)
    reportable_until: datetime
    reporter_party_marker_sha256: str = field(repr=False)
    target_marker_sha256: str = field(repr=False)


@dataclass(frozen=True)
class TrustOfficerConflictCheck:
    officer_user_id: str
    organization_id: str
    demand_id: str
    demand_version_id: str
    conflict_free: bool
    conflict_attestation_sha256: str = field(repr=False)
    evaluated_at: datetime
    valid_until: datetime


@dataclass(frozen=True)
class TrustSealedNote:
    sealed_note_reference: str = field(repr=False)
    sealed_note_sha256: str = field(repr=False)
    retention_class: str
    sealed_at: datetime


@dataclass(frozen=True)
class TrustInitialOutcomeEvidence:
    case_id: str
    case_aggregate_version: int
    triage_version: int
    outcome_code: str
    reason_codes: Tuple[str, ...]
    action_codes: Tuple[str, ...]
    evidence_packet_version_id: str
    evidence_packet_digest: str = field(repr=False)
    source_digest: str = field(repr=False)
    appeal_eligible: bool
    appeal_eligibility_code: str
    appeal_deadline: datetime | None
    policy_version: str
    redaction_profile_code: str
    evaluated_at: datetime
    valid_until: datetime


class TrustAuthorityPort(Protocol):
    def authorize_reporter(
        self,
        *,
        actor: "TrustActorContext",
        operation: str,
        organization_id: str,
    ) -> TrustReporterAuthority: ...

    def authorize_officer(
        self,
        *,
        actor: "TrustActorContext",
        operation: str,
    ) -> TrustOfficerAuthority: ...


class TrustTargetPort(Protocol):
    def resolve_report_target(
        self,
        *,
        reporter_authority: TrustReporterAuthority,
        demand_id: str,
        demand_version_id: str,
    ) -> TrustDemandTarget: ...

    def check_officer_conflict(
        self,
        *,
        officer_authority: TrustOfficerAuthority,
        operation: str,
        organization_id: str,
        demand_id: str,
        demand_version_id: str,
    ) -> TrustOfficerConflictCheck: ...


class TrustSealedNotePort(Protocol):
    def seal(
        self,
        *,
        case_id: str,
        actor_user_id: str,
        purpose: str,
        raw_note: str,
        idempotency_key_digest: str,
    ) -> TrustSealedNote: ...


class TrustDecisionEvidencePort(Protocol):
    def prepare_initial_outcome(
        self,
        *,
        officer_authority: TrustOfficerAuthority,
        case: "SafetyCase",
        report: "SafetyReport",
        triage: "TrustTriageVersion",
        active_holds: Tuple["SafetyHold", ...],
        outcome: "TrustCaseOutcome",
        reason_codes: Tuple[str, ...],
        action_codes: Tuple["HoldAction", ...],
        now: datetime,
    ) -> TrustInitialOutcomeEvidence: ...


class TrustClock(Protocol):
    def now(self) -> datetime: ...


class TrustIdSource(Protocol):
    def new_id(self, kind: str) -> str: ...


class TrustReceiptKeyring(Protocol):
    idempotency_key_digest_key_ids: Tuple[str, ...]
    payload_hash_key_ids: Tuple[str, ...]

    def keyed_digest(self, key_id: str, value: bytes) -> str: ...


class TrustUnitOfWork(Protocol):
    def lock(self, resource: str, keys: Sequence[str]) -> None: ...

    def get(self, collection: str, key: str) -> Any: ...

    def values(self, collection: str) -> Tuple[Any, ...]: ...

    def put(
        self,
        collection: str,
        key: str,
        value: Any,
        *,
        checkpoint: str,
    ) -> None: ...

    def commit(self) -> None: ...


class TrustReadStore(Protocol):
    def snapshot(self) -> Mapping[str, Mapping[str, Any]]: ...


class TrustUnitOfWorkFactory(Protocol):
    store: TrustReadStore

    def begin(self) -> ContextManager[TrustUnitOfWork]: ...


__all__ = [
    "TrustAuthorityPort",
    "TrustAuthorityUnavailableError",
    "TrustClock",
    "TrustCommitOutcomeUnknownError",
    "TrustDemandTarget",
    "TrustDecisionEvidencePort",
    "TrustDecisionEvidenceUnavailableError",
    "TrustIdSource",
    "TrustInitialOutcomeEvidence",
    "TrustOfficerAuthority",
    "TrustOfficerConflictCheck",
    "TrustReadStore",
    "TrustReceiptKeyring",
    "TrustReporterAuthority",
    "TrustSealedNote",
    "TrustSealedNotePort",
    "TrustSealedNoteUnavailableError",
    "TrustStorageUnavailableError",
    "TrustTargetPort",
    "TrustTargetUnavailableError",
    "TrustUnitOfWork",
    "TrustUnitOfWorkFactory",
]
