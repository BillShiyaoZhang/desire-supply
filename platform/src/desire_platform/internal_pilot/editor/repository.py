"""Memory persistence port for the editor contract.

This is deliberately process-local and exists for deterministic service and
HTTP tests.  It is not a production-persistence claim; the deployment
composition must provide a PostgreSQL implementation with atomic receipts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import RLock
from typing import Any, Dict, Optional, Tuple

from ...creator_profile.domain import CreatorProfile, ProfileVersion
from ...demand.domain import (
    Demand,
    DemandReview,
    DemandReviewAssignment,
    DemandSubmission,
    DemandVersion,
)


@dataclass
class MemoryEditorRepository:
    profiles: Dict[str, CreatorProfile] = field(default_factory=dict)
    profile_versions: Dict[str, ProfileVersion] = field(default_factory=dict)
    demands: Dict[str, Demand] = field(default_factory=dict)
    demand_versions: Dict[str, DemandVersion] = field(default_factory=dict)
    demand_submissions: Dict[str, DemandSubmission] = field(default_factory=dict)
    review_assignments: Dict[str, DemandReviewAssignment] = field(default_factory=dict)
    demand_reviews: Dict[str, DemandReview] = field(default_factory=dict)
    receipts: Dict[Tuple[str, str, str], Tuple[str, Any]] = field(default_factory=dict)
    _lock: RLock = field(default_factory=RLock, repr=False)

    @property
    def lock(self) -> RLock:
        return self._lock

    def profile_versions_for(self, profile_id: str) -> Tuple[ProfileVersion, ...]:
        return tuple(
            sorted(
                (
                    item
                    for item in self.profile_versions.values()
                    if item.profile_id == profile_id
                ),
                key=lambda item: item.version_no,
            )
        )

    def demand_versions_for(self, demand_id: str) -> Tuple[DemandVersion, ...]:
        return tuple(
            sorted(
                (
                    item
                    for item in self.demand_versions.values()
                    if item.demand_id == demand_id
                ),
                key=lambda item: item.version_no,
            )
        )

    def submissions_for(self, demand_id: str) -> Tuple[DemandSubmission, ...]:
        return tuple(
            sorted(
                (
                    item
                    for item in self.demand_submissions.values()
                    if item.demand_id == demand_id
                ),
                key=lambda item: item.submission_no,
            )
        )

    def reviews_for(self, demand_id: str) -> Tuple[DemandReview, ...]:
        return tuple(
            sorted(
                (
                    item
                    for item in self.demand_reviews.values()
                    if item.demand_id == demand_id
                ),
                key=lambda item: (item.reviewed_at, item.review_id),
            )
        )

    def assignments_for_reviewer(
        self, reviewer_user_id: str
    ) -> Tuple[DemandReviewAssignment, ...]:
        return tuple(
            item
            for item in self.review_assignments.values()
            if item.reviewer_user_id == reviewer_user_id
        )

    def add_review_assignment(self, assignment: DemandReviewAssignment) -> None:
        with self._lock:
            self.review_assignments[assignment.assignment_id] = assignment

    def receipt(
        self, *, actor_user_id: str, operation: str, key: str
    ) -> Optional[Tuple[str, Any]]:
        return self.receipts.get((actor_user_id, operation, key))

    def save_receipt(
        self,
        *,
        actor_user_id: str,
        operation: str,
        key: str,
        payload_sha256: str,
        result: Any,
    ) -> None:
        self.receipts[(actor_user_id, operation, key)] = (
            payload_sha256,
            result,
        )
