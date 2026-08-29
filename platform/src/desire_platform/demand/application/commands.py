"""Deeply immutable command facts for Demand v1."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Tuple

from ..domain.model import (
    CancelReasonCode,
    Demand,
    DemandContent,
    DemandFundingMarker,
    DemandReview,
    DemandSubmission,
    DemandVersion,
    MatchingRequest,
)


class DemandActorKind(str, Enum):
    USER = "USER"
    SYSTEM = "SYSTEM"


@dataclass(frozen=True)
class DemandActorContext:
    actor_kind: DemandActorKind
    actor_id: str
    session_id: Optional[str] = field(repr=False)
    organization_id: str
    correlation_id: str
    causation_id: str
    trace_id: str
    original_actor_id: Optional[str]
    workload_credential_id: Optional[str] = field(default=None, repr=False)


@dataclass(frozen=True)
class CreateDemandCommand:
    taxonomy_bundle_id: str
    content: DemandContent = field(repr=False)
    raw_client_reference: str = field(repr=False)
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class CreateDemandVersionCommand:
    demand_id: str
    expected_version: int
    based_on_demand_version_id: str
    taxonomy_bundle_id: str
    content: DemandContent = field(repr=False)
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class SubmitDemandCommand:
    demand_id: str
    expected_version: int
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class RequestDemandChangesCommand:
    assignment_id: str
    demand_id: str
    expected_version: int
    reason_codes: Tuple[str, ...]
    required_field_codes: Tuple[str, ...]
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class VerifyDemandCommand:
    assignment_id: str
    demand_id: str
    expected_version: int
    identity_subject_verified: bool
    payment_subject_verified: bool
    decision_authority_verified: bool
    budget_health_verified: bool
    budget_health_code: str
    risk_code: str
    evidence_summary_sha256: str = field(repr=False)
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class FundingSecuredSourceEvent:
    event_id: str
    event_type: str
    schema_version: int
    source_aggregate_type: str
    source_aggregate_id: str
    source_aggregate_version: int
    organization_id: str
    demand_id: str
    demand_version_id: str
    funding_id: str
    target_type: str
    observed_status: str
    amount_currency_sha256: str
    verification_reference_sha256: str = field(repr=False)
    occurred_at: datetime


@dataclass(frozen=True)
class ApplyFundingSecuredCommand:
    demand_id: str
    expected_version: int
    source_event: FundingSecuredSourceEvent = field(repr=False)


@dataclass(frozen=True)
class RequestMatchingCommand:
    demand_id: str
    expected_version: int
    assignment_id: Optional[str]
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class CancelDemandCommand:
    demand_id: str
    expected_version: int
    assignment_id: Optional[str]
    reason_code: CancelReasonCode
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class ExpireDemandCommand:
    demand_id: str
    expected_version: int
    deadline: datetime
    scheduler_command_id: str = field(repr=False)


@dataclass(frozen=True)
class DemandCommandResult:
    demand: Demand
    versions: Tuple[DemandVersion, ...]
    submissions: Tuple[DemandSubmission, ...]
    reviews: Tuple[DemandReview, ...]
    funding_markers: Tuple[DemandFundingMarker, ...]
    matching_requests: Tuple[MatchingRequest, ...]
    replayed: bool
    event_types: Tuple[str, ...]
    completed_at: datetime
