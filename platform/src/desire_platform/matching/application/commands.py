"""Deeply immutable Matching v1 command facts."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Tuple

from ..domain.model import MatchCandidate


class MatchingActorKind(str, Enum):
    USER = "USER"
    SYSTEM = "SYSTEM"


@dataclass(frozen=True)
class MatchingActorContext:
    actor_kind: MatchingActorKind
    actor_id: str
    session_id: Optional[str] = field(repr=False)
    organization_id: str
    correlation_id: str
    causation_id: str
    trace_id: str
    original_actor_id: Optional[str]
    workload_credential_id: Optional[str] = field(default=None, repr=False)


@dataclass(frozen=True)
class MatchingRequestedSourceEvent:
    event_id: str
    event_type: str
    schema_version: int
    aggregate_type: str
    aggregate_id: str
    aggregate_version: int
    organization_id: str
    demand_id: str
    demand_version_id: str
    funding_id: str
    matching_request_id: str
    composite_rule_requirement_id: str
    occurred_at: datetime


@dataclass(frozen=True)
class CreateMatchingAttemptCommand:
    source_event: MatchingRequestedSourceEvent = field(repr=False)


@dataclass(frozen=True)
class StartMatchRunCommand:
    match_run_id: str
    worker_id: str
    lease_token: str = field(repr=False)
    fencing_generation: int


@dataclass(frozen=True)
class CompleteMatchRunCommand:
    match_run_id: str
    worker_id: str
    lease_token: str = field(repr=False)
    fencing_generation: int
    input_set_sha256: str
    candidate_results: Tuple[MatchCandidate, ...] = field(repr=False)


@dataclass(frozen=True)
class FailMatchRunCommand:
    match_run_id: str
    worker_id: str
    lease_token: str = field(repr=False)
    fencing_generation: int
    failure_code: str
    private_error: Optional[str] = field(default=None, repr=False)


@dataclass(frozen=True)
class RetryMatchRunCommand:
    attempt_id: str
    failed_run_id: str
    expected_attempt_version: int
    input_baseline_sha256: str
    assignment_id: Optional[str]
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class CreateInvitationCommand:
    match_run_id: str
    creator_user_id: str
    expires_at: datetime
    expected_run_version: int
    assignment_id: str
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class PublishInvitationCommand:
    invitation_id: str
    snapshot_sha256: str
    expected_invitation_version: int
    assignment_id: str
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class RespondInvitationCommand:
    invitation_id: str
    snapshot_sha256: str
    expected_invitation_version: int
    accept: bool
    reason_code: Optional[str]
    note: Optional[str] = field(repr=False)
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class WithdrawAcceptedInvitationCommand:
    invitation_id: str
    snapshot_sha256: str
    expected_invitation_version: int
    reason_code: str = field(repr=False)
    note: Optional[str] = field(repr=False)
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class ChooseCreatorCommand:
    selection_id: str
    invitation_id: str
    selection_basis_code: str
    current_invitation_set_sha256: str
    expected_selection_version: int
    assignment_id: str
    expected_assignment_version: int
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class CloseSelectionWithoutChoiceCommand:
    selection_id: str
    reason_code: str
    current_invitation_set_sha256: str
    expected_selection_version: int
    assignment_id: str
    expected_assignment_version: int
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class ExpireInvitationCommand:
    invitation_id: str
    expected_invitation_version: int
    scheduler_command_id: str = field(repr=False)


@dataclass(frozen=True)
class InvalidateAttemptCommand:
    attempt_id: str
    reason_code: str
    input_baseline_sha256: str
    expected_attempt_version: int
    assignment_id: Optional[str]
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class MatchingCommandResult:
    target_id: str
    target_status: str
    aggregate_version: int
    updated_at: datetime
    replayed: bool
    event_types: Tuple[str, ...]
