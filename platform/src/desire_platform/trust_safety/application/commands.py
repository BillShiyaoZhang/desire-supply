"""Deeply immutable command contracts for the first Trust vertical.

The DTOs deliberately contain only closed, structured fields.  The one raw
human input admitted by this slice is a triage note; it is hidden from repr and
must be converted to an opaque sealed-note reference before any transaction is
opened.  Idempotency keys and evidence digests are likewise never rendered.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Tuple

from ..domain import (
    AssignmentReleaseReason,
    HoldAction,
    HoldReason,
    ReportCategory,
    SafetyCaseStatus,
    TrustCaseOutcome,
)


@dataclass(frozen=True)
class TrustActorContext:
    actor_user_id: str
    session_id: str = field(repr=False)
    organization_id: Optional[str]
    correlation_id: str
    causation_id: str
    trace_id: str
    original_actor_user_id: Optional[str]


@dataclass(frozen=True)
class SubmitSafetyReportCommand:
    demand_id: str
    demand_version_id: str
    category: ReportCategory
    incident_started_at: datetime
    incident_ended_at: Optional[datetime]
    impact_codes: Tuple[str, ...]
    evidence_reference_ids: Tuple[str, ...] = field(repr=False)
    requested_protection_codes: Tuple[str, ...]
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class ClaimSafetyCaseCommand:
    case_id: str
    expected_case_version: int
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class ReleaseSafetyCaseAssignmentCommand:
    case_id: str
    expected_case_version: int
    reason_code: AssignmentReleaseReason
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class SaveTrustTriageDraftCommand:
    case_id: str
    expected_case_version: int
    priority_code: str
    jurisdiction_code: str
    severity_code: str
    issue_codes: Tuple[str, ...]
    investigation_step_codes: Tuple[str, ...]
    proposed_hold_actions: Tuple[HoldAction, ...]
    proposed_hold_ttl_minutes: int
    restricted_note: str = field(repr=False)
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class PublishTrustTriageCommand:
    case_id: str
    expected_case_version: int
    expected_draft_version: int
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class PlaceSafetyHoldCommand:
    case_id: str
    expected_case_version: int
    action_codes: Tuple[HoldAction, ...]
    reason_code: HoldReason
    hold_ttl_minutes: int
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class ClaimSafetyHoldReleaseCommand:
    hold_id: str
    expected_hold_version: int
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class ReleaseSafetyHoldCommand:
    hold_id: str
    expected_hold_version: int
    release_reason_code: str
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class PublishTrustOutcomeCommand:
    case_id: str
    expected_case_version: int
    outcome_code: TrustCaseOutcome
    reason_codes: Tuple[str, ...]
    action_codes: Tuple[HoldAction, ...]
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class TrustCommandResult:
    """A receipt-safe command result, suitable for exact replay.

    Rich case/report/note facts are deliberately read through separately
    authorized projections.  A completed receipt therefore needs only this
    non-sensitive identifier and version projection.
    """

    case_id: str
    case_status: SafetyCaseStatus
    aggregate_version: int
    report_id: Optional[str]
    assignment_id: Optional[str]
    triage_draft_version: Optional[int]
    triage_version: Optional[int]
    hold_id: Optional[str]
    hold_version: Optional[int]
    outcome_version_id: Optional[str]
    replayed: bool
    event_types: Tuple[str, ...]
    completed_at: datetime


__all__ = [
    "ClaimSafetyHoldReleaseCommand",
    "ClaimSafetyCaseCommand",
    "PlaceSafetyHoldCommand",
    "PublishTrustTriageCommand",
    "PublishTrustOutcomeCommand",
    "ReleaseSafetyCaseAssignmentCommand",
    "ReleaseSafetyHoldCommand",
    "SaveTrustTriageDraftCommand",
    "SubmitSafetyReportCommand",
    "TrustActorContext",
    "TrustCommandResult",
]
