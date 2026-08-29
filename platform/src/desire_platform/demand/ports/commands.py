"""Closed dependency ports for Demand command orchestration."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import (
    TYPE_CHECKING,
    Any,
    ContextManager,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
)

if TYPE_CHECKING:
    from ..application.commands import DemandActorContext, FundingSecuredSourceEvent


class DemandStorageUnavailableError(Exception):
    """Storage failed before COMMIT was sent."""


class DemandCommitOutcomeUnknownError(Exception):
    """COMMIT was sent but its durable result was not acknowledged."""


class DemandAuthorityUnavailableError(Exception):
    """The exact IAM authority projection could not be obtained safely."""


class DemandContentPolicyUnavailableError(Exception):
    """The required content-policy result could not be obtained safely."""


class DemandSafetyHoldUnavailableError(Exception):
    """The required SafetyHold decision could not be obtained safely."""


class DemandRuleCatalogUnavailableError(Exception):
    """Current taxonomy, budget, risk, or matching rules are unavailable."""


class DemandSourceEventInvalidError(Exception):
    """A source envelope or workload binding is invalid or undisclosable."""


@dataclass(frozen=True)
class DemandOwnerAuthority:
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
    policy_selector_digest: str
    policy_bundle_id: str
    policy_requirements_satisfied: bool
    authority_marker_sha256: str


@dataclass(frozen=True)
class DemandReviewAuthority:
    actor_user_id: str
    session_id: str = field(repr=False)
    organization_id: str
    demand_id: str
    assignment_id: str
    assignment_status: str
    assignment_version: int
    assignment_expires_at: datetime
    duty_grant_id: str
    duty_grant_version: int
    duty_code: str
    conflict_attestation_sha256: str
    reviewer_is_creator: bool
    reviewer_is_owning_organization_member: bool
    authority_marker_sha256: str


@dataclass(frozen=True)
class DemandSystemAuthority:
    workload_principal_id: str
    workload_credential_id: str = field(repr=False)
    operation: str
    organization_id: str
    demand_id: str
    source_event_id: Optional[str]
    valid_until: datetime
    authority_marker_sha256: str


class DemandContentPolicyDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class DemandContentPolicyResult:
    decision: DemandContentPolicyDecision
    demand_id: str
    demand_version_id: str
    content_sha256: str
    policy_version: str
    result_sha256: str
    evaluated_at: datetime
    valid_until: datetime


class DemandHoldDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class DemandSafetyHoldResult:
    decision: DemandHoldDecision
    actor_id: str
    organization_id: str
    demand_id: str
    prospective_aggregate_version: int
    demand_version_id: str
    content_sha256: str
    action: str
    policy_version: str
    evaluated_at: datetime
    valid_until: datetime


@dataclass(frozen=True)
class DemandRuleRequirement:
    taxonomy_bundle_id: str
    budget_rule_bundle_id: str
    risk_rule_bundle_id: str
    matching_rule_bundle_id: str
    reason_code_bundle_id: str
    composite_rule_requirement_id: str
    effective_at: datetime
    effective_until: Optional[datetime]
    requirement_sha256: str


class DemandOwnerAuthorityPort(Protocol):
    def authorize(
        self,
        *,
        actor: DemandActorContext,
        operation: str,
        demand_id: Optional[str],
    ) -> DemandOwnerAuthority: ...


class DemandReviewAuthorityPort(Protocol):
    def authorize(
        self,
        *,
        actor: DemandActorContext,
        operation: str,
        assignment_id: str,
        demand_id: str,
    ) -> DemandReviewAuthority: ...


class DemandSystemAuthorityPort(Protocol):
    def authorize(
        self,
        *,
        actor: DemandActorContext,
        operation: str,
        demand_id: str,
        source_event_id: Optional[str],
    ) -> DemandSystemAuthority: ...


class DemandContentPolicyPort(Protocol):
    def evaluate(
        self,
        *,
        demand_id: str,
        demand_version_id: str,
        content_sha256: str,
        content: Any,
        policy_version: str,
    ) -> DemandContentPolicyResult: ...


class DemandSafetyHoldPort(Protocol):
    def evaluate(
        self,
        *,
        actor_id: str,
        organization_id: str,
        demand_id: str,
        prospective_aggregate_version: int,
        demand_version_id: str,
        content_sha256: str,
        action: str,
        policy_version: str,
    ) -> DemandSafetyHoldResult: ...


class DemandRuleCatalogPort(Protocol):
    def current_requirement(
        self,
        *,
        organization_id: str,
        demand_id: str,
        operation: str,
    ) -> DemandRuleRequirement: ...


class DemandSourceEventValidatorPort(Protocol):
    def validate(
        self,
        *,
        actor: DemandActorContext,
        event: FundingSecuredSourceEvent,
    ) -> None: ...


class DemandClock(Protocol):
    def now(self) -> datetime: ...


class DemandIdSource(Protocol):
    def new_id(self, kind: str) -> str: ...


class DemandReceiptKeyring(Protocol):
    idempotency_key_digest_key_id: str
    client_reference_digest_key_id: str
    payload_hash_key_id: str

    def keyed_digest(self, key_id: str, value: bytes) -> str: ...


class DemandSchemaValidator(Protocol):
    def validate(self, value: Mapping[str, Any], schema_name: str) -> None: ...


class DemandUnitOfWork(Protocol):
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


class DemandReadStore(Protocol):
    def snapshot(self) -> Mapping[str, Mapping[str, Any]]: ...


class DemandUnitOfWorkFactory(Protocol):
    store: DemandReadStore

    def begin(self) -> ContextManager[DemandUnitOfWork]: ...


__all__ = [
    "DemandAuthorityUnavailableError",
    "DemandClock",
    "DemandCommitOutcomeUnknownError",
    "DemandContentPolicyDecision",
    "DemandContentPolicyPort",
    "DemandContentPolicyResult",
    "DemandContentPolicyUnavailableError",
    "DemandHoldDecision",
    "DemandIdSource",
    "DemandOwnerAuthority",
    "DemandOwnerAuthorityPort",
    "DemandReadStore",
    "DemandReceiptKeyring",
    "DemandReviewAuthority",
    "DemandReviewAuthorityPort",
    "DemandRuleCatalogPort",
    "DemandRuleCatalogUnavailableError",
    "DemandRuleRequirement",
    "DemandSafetyHoldPort",
    "DemandSafetyHoldResult",
    "DemandSafetyHoldUnavailableError",
    "DemandSchemaValidator",
    "DemandSourceEventInvalidError",
    "DemandSourceEventValidatorPort",
    "DemandStorageUnavailableError",
    "DemandSystemAuthority",
    "DemandSystemAuthorityPort",
    "DemandUnitOfWork",
    "DemandUnitOfWorkFactory",
]
