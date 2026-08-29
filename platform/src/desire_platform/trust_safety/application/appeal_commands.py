"""Deeply immutable command DTOs for the Appeal application boundary."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Tuple

from ..domain import (
    AppealAssignmentReleaseReason,
    AppealDecisionCode,
    AppealGround,
    AppealGroundAssessment,
    AppealStatus,
    RequestedAppealOutcome,
)


@dataclass(frozen=True)
class OpenAppealCommand:
    source_outcome_version_id: str
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class SaveAppealDraftCommand:
    appeal_id: str
    expected_appeal_version: int
    grounds: Tuple[AppealGround, ...]
    requested_outcome: RequestedAppealOutcome
    applicant_statement: str = field(repr=False)
    new_evidence_reference_ids: Tuple[str, ...] = field(repr=False)
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class SubmitAppealCommand:
    appeal_id: str
    expected_appeal_version: int
    expected_draft_version: int
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class ClaimAppealCommand:
    appeal_id: str
    expected_appeal_version: int
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class ReleaseAppealAssignmentCommand:
    appeal_id: str
    expected_appeal_version: int
    reason_code: AppealAssignmentReleaseReason
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class SaveAppealReviewDraftCommand:
    appeal_id: str
    expected_appeal_version: int
    assessments: Tuple[AppealGroundAssessment, ...]
    reason_codes: Tuple[str, ...]
    remedy_delta_codes: Tuple[str, ...]
    reviewer_note: str = field(repr=False)
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class DecideAppealCommand:
    appeal_id: str
    expected_appeal_version: int
    expected_review_draft_version: int
    decision_code: AppealDecisionCode
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class AppealCommandResult:
    """Receipt-safe write result with no assignment or sealed-text facts."""

    appeal_id: str
    appeal_status: AppealStatus
    aggregate_version: int
    application_draft_version: int | None
    application_version: int | None
    review_draft_version: int | None
    decision_version_id: str | None
    replayed: bool
    event_types: Tuple[str, ...]
    completed_at: datetime


__all__ = [
    "AppealCommandResult",
    "ClaimAppealCommand",
    "DecideAppealCommand",
    "OpenAppealCommand",
    "ReleaseAppealAssignmentCommand",
    "SaveAppealDraftCommand",
    "SaveAppealReviewDraftCommand",
    "SubmitAppealCommand",
]
