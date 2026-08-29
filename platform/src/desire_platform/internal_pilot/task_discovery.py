"""Current-account task and history discovery over existing durable projections.

The service deliberately owns no persistence query.  Every item comes from an
existing principal-scoped Editor, Finance, Trust, or Appeal read surface.  It
therefore cannot turn a caller-supplied identifier into visibility and cannot
invent work that has not already been persisted by one of those domains.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Tuple
from uuid import UUID

from desire_platform.internal_pilot.editor.contracts import (
    EditorPrincipal,
    EditorResourceDto,
    EditorReviewHistoryItemDto,
    EditorReviewHistoryPageDto,
    EditorReviewQueueItemDto,
    EditorServiceError,
)
from desire_platform.internal_pilot.finance_funding import (
    FinanceFundingQueueItemDto,
    FinanceFundingReviewDto,
)
from desire_platform.trust_safety.application import TrustActorContext
from desire_platform.trust_safety.http import TrustHttpProjection
from desire_platform.trust_safety.ports.appeal import (
    AppealActiveAssignmentsProjection,
    AppealCompletedAssignmentsProjection,
    AppealOwnProjection,
    AppealQueueProjection,
)


class TaskClassification(str, Enum):
    NEEDS_ACTION = "NEEDS_ACTION"
    WAITING = "WAITING"
    COMPLETED = "COMPLETED"


_RESOURCE_KINDS = frozenset(
    (
        "APPEAL",
        "APPEAL_REVIEW",
        "CREATOR_PROFILE",
        "DEMAND",
        "DEMAND_REVIEW",
        "FINANCE_FUNDING_REVIEW",
        "TRUST_CASE",
        "TRUST_HOLD_RELEASE",
        "TRUST_REPORT",
    )
)
_NEXT_ACTIONS = frozenset(
    (
        "CLAIM_APPEAL_REVIEW",
        "CLAIM_DEMAND_REVIEW",
        "CLAIM_FINANCE_REVIEW",
        "CLAIM_TRUST_CASE",
        "CLAIM_TRUST_HOLD_RELEASE",
        "CONTINUE_FINANCE_REVIEW",
        "EDIT_APPEAL",
        "EDIT_OR_SUBMIT_DEMAND",
        "REVIEW_ASSIGNED_APPEAL",
        "REVIEW_ASSIGNED_DEMAND",
        "REVIEW_ASSIGNED_TRUST_CASE",
        "REVIEW_ASSIGNED_TRUST_HOLD_RELEASE",
        "VIEW_APPEAL_HISTORY",
        "VIEW_APPEAL_REVIEW_HISTORY",
        "VIEW_CREATOR_PROFILE",
        "VIEW_DEMAND_HISTORY",
        "VIEW_DEMAND_REVIEW_HISTORY",
        "VIEW_TRUST_CASE_HISTORY",
        "VIEW_TRUST_REPORT_HISTORY",
        "WAIT_FOR_APPEAL_REVIEW",
        "WAIT_FOR_DEMAND_PROCESSING",
        "WAIT_FOR_FINANCE_CONFIRMATION",
        "WAIT_FOR_TRUST_REVIEW",
    )
)
_ASSIGNED_ACTIONS = frozenset(
    (
        "CONTINUE_FINANCE_REVIEW",
        "REVIEW_ASSIGNED_APPEAL",
        "REVIEW_ASSIGNED_DEMAND",
        "REVIEW_ASSIGNED_TRUST_CASE",
        "REVIEW_ASSIGNED_TRUST_HOLD_RELEASE",
        "WAIT_FOR_FINANCE_CONFIRMATION",
    )
)
_DEMAND_STATUSES = frozenset(
    (
        "CANCELLED",
        "DRAFT",
        "EXPIRED",
        "FUNDED",
        "FUNDING_PENDING",
        "MATCHED",
        "MATCHING",
        "NEEDS_CHANGES",
        "NO_MATCH",
        "SUBMITTED",
        "VERIFIED",
    )
)
_TRUST_REPORT_STATUSES = frozenset(("DECIDED", "IN_REVIEW", "OPEN", "TRIAGING"))
_APPEAL_STATUSES = frozenset(
    ("DECIDED", "DRAFT", "IN_REVIEW", "SUBMITTED", "WITHDRAWN")
)
_PROFILE_STATUSES = frozenset(("ACTIVE", "ARCHIVED", "DRAFT", "PAUSED"))
_CLASSIFICATION_ORDER = {
    TaskClassification.NEEDS_ACTION: 0,
    TaskClassification.WAITING: 1,
    TaskClassification.COMPLETED: 2,
}
_MINIMUM_TIME = datetime.min.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class CurrentAccountTask:
    classification: str
    resource_kind: str
    resource_id: str
    source_status: str
    next_action: str
    resource_path: str
    updated_at: Optional[datetime]
    due_at: Optional[datetime]

    def __post_init__(self) -> None:
        try:
            identifier = UUID(self.resource_id)
        except (TypeError, ValueError, AttributeError):
            raise ValueError("current-account task is invalid") from None
        if (
            self.classification not in {item.value for item in TaskClassification}
            or self.resource_kind not in _RESOURCE_KINDS
            or identifier.int == 0
            or str(identifier) != self.resource_id
            or not isinstance(self.source_status, str)
            or not self.source_status
            or self.next_action not in _NEXT_ACTIONS
            or not isinstance(self.resource_path, str)
            or not self.resource_path.startswith("/v1/app/")
            or "//" in self.resource_path
            or "%" in self.resource_path
        ):
            raise ValueError("current-account task is invalid")
        if self.updated_at is not None:
            _utc(self.updated_at)
        if self.due_at is not None:
            _utc(self.due_at)


@dataclass(frozen=True)
class CurrentAccountTaskDiscovery:
    schema_version: str
    items: Tuple[CurrentAccountTask, ...]
    has_more: bool

    def __post_init__(self) -> None:
        keys = tuple((item.resource_kind, item.resource_id) for item in self.items)
        if (
            self.schema_version != "current-account-task-discovery-v1"
            or not isinstance(self.items, tuple)
            or any(not isinstance(item, CurrentAccountTask) for item in self.items)
            or len(set(keys)) != len(keys)
            or type(self.has_more) is not bool
            or self.items != _sorted_tasks(self.items)
        ):
            raise ValueError("current-account task discovery is invalid")


class CurrentAccountTaskDiscoveryService:
    """Aggregate only records already authorized by durable domain readers."""

    def __init__(
        self,
        *,
        editor_service: Any,
        finance_service: Any,
        trust_projections: Any,
        appeal_projections: Any,
    ) -> None:
        self._editor = editor_service
        self._finance = finance_service
        self._trust = trust_projections
        self._appeal = appeal_projections

    def list_tasks(
        self, *, principal: EditorPrincipal
    ) -> CurrentAccountTaskDiscovery:
        _authoritative_principal(principal)
        tasks: Dict[tuple[str, str], CurrentAccountTask] = {}
        has_more = False
        try:
            roles = frozenset(principal.role_codes)
            if principal.workspace_kind == "ORGANIZATION" and "DEMAND_OWNER" in roles:
                self._owner_demands(principal=principal, tasks=tasks)
                has_more = self._owner_trust_and_appeals(
                    principal=principal,
                    tasks=tasks,
                )
            if principal.workspace_kind == "PERSONAL" and "CREATOR" in roles:
                self._creator_profiles(principal=principal, tasks=tasks)
            if principal.workspace_kind == "PLATFORM":
                if "OPERATIONS_REVIEWER" in roles:
                    has_more = self._operations(
                        principal=principal,
                        tasks=tasks,
                    ) or has_more
                if "FINANCE_OPERATOR" in roles:
                    self._finance_reviews(principal=principal, tasks=tasks)
                if "TRUST_OFFICER" in roles:
                    has_more = self._trust_officer(
                        principal=principal,
                        tasks=tasks,
                    ) or has_more
                if "APPEAL_REVIEWER" in roles:
                    has_more = self._appeal_reviewer(
                        principal=principal,
                        tasks=tasks,
                    ) or has_more
            return CurrentAccountTaskDiscovery(
                schema_version="current-account-task-discovery-v1",
                items=_sorted_tasks(tuple(tasks.values())),
                has_more=has_more,
            )
        except EditorServiceError as error:
            if error.status == 503 and error.code == "SERVICE_UNAVAILABLE":
                raise
            raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE") from None
        except Exception:
            raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE") from None

    def _creator_profiles(
        self,
        *,
        principal: EditorPrincipal,
        tasks: Dict[tuple[str, str], CurrentAccountTask],
    ) -> None:
        _require_methods(self._editor, ("list_profiles",))
        resources = self._editor.list_profiles(principal=principal)
        if not isinstance(resources, tuple) or len(resources) > 1000:
            _unavailable()
        for resource in resources:
            if (
                type(resource) is not EditorResourceDto
                or resource.resource_type != "CREATOR_PROFILE"
                or resource.status not in _PROFILE_STATUSES
            ):
                _unavailable()
            profile_id = _uuid(resource.object_id)
            if resource.status == "DRAFT":
                classification = TaskClassification.NEEDS_ACTION
                next_action = "VIEW_CREATOR_PROFILE"
            elif resource.status == "ARCHIVED":
                classification = TaskClassification.COMPLETED
                next_action = "VIEW_CREATOR_PROFILE"
            else:
                # ACTIVE and PAUSED are discoverable account state, but neither
                # is represented as compulsory work for the current creator.
                classification = TaskClassification.WAITING
                next_action = "VIEW_CREATOR_PROFILE"
            _put_task(
                tasks,
                CurrentAccountTask(
                    classification=classification.value,
                    resource_kind="CREATOR_PROFILE",
                    resource_id=profile_id,
                    source_status=resource.status,
                    next_action=next_action,
                    resource_path=f"/v1/app/profiles/{profile_id}",
                    updated_at=_resource_updated_at(resource),
                    due_at=None,
                ),
            )

    def _owner_demands(
        self,
        *,
        principal: EditorPrincipal,
        tasks: Dict[tuple[str, str], CurrentAccountTask],
    ) -> None:
        _require_methods(self._editor, ("list_demands",))
        resources = self._editor.list_demands(principal=principal)
        if not isinstance(resources, tuple) or len(resources) > 1000:
            _unavailable()
        for resource in resources:
            if type(resource) is not EditorResourceDto or resource.resource_type != "DEMAND":
                _unavailable()
            demand_id = _uuid(resource.object_id)
            if resource.status not in _DEMAND_STATUSES:
                _unavailable()
            if resource.status in {"DRAFT", "NEEDS_CHANGES", "NO_MATCH"}:
                classification = TaskClassification.NEEDS_ACTION
                next_action = "EDIT_OR_SUBMIT_DEMAND"
            elif resource.status in {"MATCHED", "CANCELLED", "EXPIRED"}:
                classification = TaskClassification.COMPLETED
                next_action = "VIEW_DEMAND_HISTORY"
            else:
                classification = TaskClassification.WAITING
                next_action = "WAIT_FOR_DEMAND_PROCESSING"
            _put_task(
                tasks,
                CurrentAccountTask(
                    classification=classification.value,
                    resource_kind="DEMAND",
                    resource_id=demand_id,
                    source_status=resource.status,
                    next_action=next_action,
                    resource_path=f"/v1/app/demands/{demand_id}",
                    updated_at=_demand_updated_at(resource),
                    due_at=None,
                ),
            )

    def _operations(
        self,
        *,
        principal: EditorPrincipal,
        tasks: Dict[tuple[str, str], CurrentAccountTask],
    ) -> bool:
        _require_methods(
            self._editor,
            ("list_demands", "list_review_history", "list_review_queue"),
        )
        queue = self._editor.list_review_queue(principal=principal)
        if not isinstance(queue, tuple) or len(queue) > 100:
            _unavailable()
        for item in queue:
            if type(item) is not EditorReviewQueueItemDto:
                _unavailable()
            demand_id = _uuid(item.demand_id)
            _put_task(
                tasks,
                CurrentAccountTask(
                    classification=TaskClassification.NEEDS_ACTION.value,
                    resource_kind="DEMAND_REVIEW",
                    resource_id=demand_id,
                    source_status="AVAILABLE",
                    next_action="CLAIM_DEMAND_REVIEW",
                    resource_path="/v1/app/review-queue",
                    updated_at=_utc(item.submitted_at),
                    due_at=_utc(item.demand_expires_at),
                ),
            )
        assigned = self._editor.list_demands(principal=principal)
        if not isinstance(assigned, tuple) or len(assigned) > 1000:
            _unavailable()
        for resource in assigned:
            if (
                type(resource) is not EditorResourceDto
                or resource.resource_type != "DEMAND"
                or resource.status not in _DEMAND_STATUSES
            ):
                _unavailable()
            demand_id = _uuid(resource.object_id)
            active = (
                resource.review_assignment is not None
                and resource.review_assignment.status == "ACTIVE"
                and "RECORD_FINDINGS" in resource.capabilities
            )
            _put_task(
                tasks,
                CurrentAccountTask(
                    classification=(
                        TaskClassification.NEEDS_ACTION.value
                        if active
                        else TaskClassification.WAITING.value
                    ),
                    resource_kind="DEMAND_REVIEW",
                    resource_id=demand_id,
                    source_status=resource.status,
                    next_action=(
                        "REVIEW_ASSIGNED_DEMAND"
                        if active
                        else "WAIT_FOR_DEMAND_PROCESSING"
                    ),
                    resource_path=f"/v1/app/demands/{demand_id}",
                    updated_at=_demand_updated_at(resource),
                    due_at=(
                        None
                        if resource.review_assignment is None
                        else _utc(resource.review_assignment.expires_at)
                    ),
                ),
            )
        history = self._editor.list_review_history(
            principal=principal,
            cursor=None,
            limit=100,
        )
        if type(history) is not EditorReviewHistoryPageDto:
            _unavailable()
        for item in history.items:
            if type(item) is not EditorReviewHistoryItemDto:
                _unavailable()
            review_id = _uuid(item.review_id)
            _put_task(
                tasks,
                CurrentAccountTask(
                    classification=TaskClassification.COMPLETED.value,
                    resource_kind="DEMAND_REVIEW",
                    resource_id=review_id,
                    source_status=item.decision,
                    next_action="VIEW_DEMAND_REVIEW_HISTORY",
                    resource_path="/v1/app/review-history",
                    updated_at=_utc(item.reviewed_at),
                    due_at=None,
                ),
            )
        return history.has_more

    def _finance_reviews(
        self,
        *,
        principal: EditorPrincipal,
        tasks: Dict[tuple[str, str], CurrentAccountTask],
    ) -> None:
        _require_methods(
            self._finance,
            ("list_funding_reviews", "get_funding_review"),
        )
        queue = self._finance.list_funding_reviews(principal=principal)
        if not isinstance(queue, tuple) or len(queue) > 100:
            _unavailable()
        for item in queue:
            if type(item) is not FinanceFundingQueueItemDto:
                _unavailable()
            if item.review_status == "AVAILABLE":
                resource_id = _uuid(item.demand_id)
                classification = TaskClassification.NEEDS_ACTION
                action = "CLAIM_FINANCE_REVIEW"
                path = "/v1/app/finance/funding-reviews"
                source_status = "AVAILABLE"
            elif item.review_status == "PENDING" and item.funding_review_id is not None:
                resource_id = _uuid(item.funding_review_id)
                source_status = "PENDING"
                if item.assigned_to_me:
                    detail = self._finance.get_funding_review(
                        principal=principal,
                        funding_review_id=resource_id,
                    )
                    if type(detail) is not FinanceFundingReviewDto:
                        _unavailable()
                    source_status = detail.status
                    if detail.available_actions:
                        classification = TaskClassification.NEEDS_ACTION
                        action = "CONTINUE_FINANCE_REVIEW"
                    else:
                        classification = TaskClassification.WAITING
                        action = "WAIT_FOR_FINANCE_CONFIRMATION"
                    path = f"/v1/app/finance/funding-reviews/{resource_id}"
                else:
                    classification = TaskClassification.NEEDS_ACTION
                    action = "CLAIM_FINANCE_REVIEW"
                    path = "/v1/app/finance/funding-reviews"
            else:
                _unavailable()
            _put_task(
                tasks,
                CurrentAccountTask(
                    classification=classification.value,
                    resource_kind="FINANCE_FUNDING_REVIEW",
                    resource_id=resource_id,
                    source_status=source_status,
                    next_action=action,
                    resource_path=path,
                    updated_at=None,
                    due_at=_utc(item.expires_at),
                ),
            )

    def _owner_trust_and_appeals(
        self,
        *,
        principal: EditorPrincipal,
        tasks: Dict[tuple[str, str], CurrentAccountTask],
    ) -> bool:
        _require_methods(self._trust, ("list_own_reports",))
        _require_methods(self._appeal, ("find_own_appeal_by_source",))
        actor = _trust_actor(principal, organization_scoped=True)
        projection = self._trust.list_own_reports(
            actor=actor,
            limit=100,
            cursor=None,
        )
        data = _trust_projection(projection, "OWN_REPORT_LIST")
        items = data.get("items")
        if not isinstance(items, list) or len(items) > 100:
            _unavailable()
        for item in items:
            if not isinstance(item, dict):
                _unavailable()
            report_id = _uuid(item.get("report_id"))
            status = item.get("status")
            if status not in _TRUST_REPORT_STATUSES:
                _unavailable()
            outcome = item.get("outcome")
            updated_at = _parse_utc(item.get("submitted_at"))
            if outcome is not None:
                if not isinstance(outcome, dict):
                    _unavailable()
                updated_at = _parse_utc(outcome.get("decided_at"))
            terminal = status == "DECIDED"
            _put_task(
                tasks,
                CurrentAccountTask(
                    classification=(
                        TaskClassification.COMPLETED.value
                        if terminal
                        else TaskClassification.WAITING.value
                    ),
                    resource_kind="TRUST_REPORT",
                    resource_id=report_id,
                    source_status=status,
                    next_action=(
                        "VIEW_TRUST_REPORT_HISTORY"
                        if terminal
                        else "WAIT_FOR_TRUST_REVIEW"
                    ),
                    resource_path=f"/v1/app/trust/reports/{report_id}",
                    updated_at=updated_at,
                    due_at=None,
                ),
            )
            if outcome is not None:
                outcome_id = _uuid(outcome.get("outcome_version_id"))
                appeal = self._appeal.find_own_appeal_by_source(
                    actor=actor,
                    source_outcome_version_id=outcome_id,
                )
                if appeal is not None:
                    self._owner_appeal(tasks=tasks, appeal=appeal)
        next_cursor = data.get("next_cursor")
        if next_cursor is not None and not isinstance(next_cursor, str):
            _unavailable()
        return next_cursor is not None

    def _owner_appeal(
        self,
        *,
        tasks: Dict[tuple[str, str], CurrentAccountTask],
        appeal: Any,
    ) -> None:
        if type(appeal) is not AppealOwnProjection or appeal.status not in _APPEAL_STATUSES:
            _unavailable()
        appeal_id = _uuid(appeal.appeal_id)
        if appeal.status == "DRAFT":
            classification = TaskClassification.NEEDS_ACTION
            action = "EDIT_APPEAL"
        elif appeal.status in {"SUBMITTED", "IN_REVIEW"}:
            classification = TaskClassification.WAITING
            action = "WAIT_FOR_APPEAL_REVIEW"
        else:
            classification = TaskClassification.COMPLETED
            action = "VIEW_APPEAL_HISTORY"
        timestamps = [appeal.source.decided_at]
        if appeal.application_draft is not None:
            timestamps.append(appeal.application_draft.edited_at)
        if appeal.application is not None:
            timestamps.append(appeal.application.submitted_at)
        if appeal.decision is not None:
            timestamps.append(appeal.decision.decided_at)
        _put_task(
            tasks,
            CurrentAccountTask(
                classification=classification.value,
                resource_kind="APPEAL",
                resource_id=appeal_id,
                source_status=appeal.status,
                next_action=action,
                resource_path=f"/v1/app/appeals/{appeal_id}",
                updated_at=max(_utc(value) for value in timestamps),
                due_at=None,
            ),
        )

    def _trust_officer(
        self,
        *,
        principal: EditorPrincipal,
        tasks: Dict[tuple[str, str], CurrentAccountTask],
    ) -> bool:
        _require_methods(
            self._trust,
            (
                "list_case_queue",
                "list_hold_release_queue",
                "list_my_active_case_assignments",
                "list_my_completed_case_assignments",
            ),
        )
        actor = _trust_actor(principal, organization_scoped=False)
        case_queue = _trust_projection(
            self._trust.list_case_queue(actor=actor, limit=100),
            "CASE_QUEUE",
        )
        case_items = case_queue.get("items")
        if not isinstance(case_items, list) or len(case_items) > 100:
            _unavailable()
        for item in case_items:
            if not isinstance(item, dict):
                _unavailable()
            case_id = _uuid(item.get("case_id"))
            _put_task(
                tasks,
                CurrentAccountTask(
                    classification=TaskClassification.NEEDS_ACTION.value,
                    resource_kind="TRUST_CASE",
                    resource_id=case_id,
                    source_status="AVAILABLE",
                    next_action="CLAIM_TRUST_CASE",
                    resource_path="/v1/app/trust/queue",
                    updated_at=_parse_utc(item.get("submitted_at")),
                    due_at=None,
                ),
            )
        hold_queue = _trust_projection(
            self._trust.list_hold_release_queue(actor=actor, limit=100),
            "HOLD_RELEASE_QUEUE",
        )
        hold_items = hold_queue.get("items")
        if not isinstance(hold_items, list) or len(hold_items) > 100:
            _unavailable()
        for item in hold_items:
            if not isinstance(item, dict):
                _unavailable()
            hold_id = _uuid(item.get("hold_id"))
            _put_task(
                tasks,
                CurrentAccountTask(
                    classification=TaskClassification.NEEDS_ACTION.value,
                    resource_kind="TRUST_HOLD_RELEASE",
                    resource_id=hold_id,
                    source_status="AVAILABLE",
                    next_action="CLAIM_TRUST_HOLD_RELEASE",
                    resource_path="/v1/app/trust/hold-release-queue",
                    updated_at=None,
                    due_at=_parse_utc(item.get("expires_at")),
                ),
            )
        assignments = _trust_projection(
            self._trust.list_my_active_case_assignments(actor=actor, limit=100),
            "MY_ACTIVE_CASE_ASSIGNMENTS",
        )
        assignment_items = assignments.get("items")
        if not isinstance(assignment_items, list) or len(assignment_items) > 100:
            _unavailable()
        for item in assignment_items:
            if not isinstance(item, dict):
                _unavailable()
            case_id = _uuid(item.get("case_id"))
            purpose = item.get("assignment_purpose")
            due_at = _parse_utc(item.get("assignment_expires_at"))
            if purpose == "CASE_TRIAGE" and item.get("hold_id") is None:
                kind = "TRUST_CASE"
                resource_id = case_id
                action = "REVIEW_ASSIGNED_TRUST_CASE"
                path = f"/v1/app/trust/cases/{case_id}"
            elif purpose == "HOLD_RELEASE":
                kind = "TRUST_HOLD_RELEASE"
                resource_id = _uuid(item.get("hold_id"))
                action = "REVIEW_ASSIGNED_TRUST_HOLD_RELEASE"
                path = f"/v1/app/trust/assigned-holds/{resource_id}"
            else:
                _unavailable()
            _put_task(
                tasks,
                CurrentAccountTask(
                    classification=TaskClassification.NEEDS_ACTION.value,
                    resource_kind=kind,
                    resource_id=resource_id,
                    source_status="ASSIGNED",
                    next_action=action,
                    resource_path=path,
                    updated_at=None,
                    due_at=due_at,
                ),
            )
        completed = _trust_projection(
            self._trust.list_my_completed_case_assignments(
                actor=actor,
                limit=100,
            ),
            "MY_COMPLETED_CASE_ASSIGNMENTS",
        )
        completed_items = completed.get("items")
        if not isinstance(completed_items, list) or len(completed_items) > 100:
            _unavailable()
        for item in completed_items:
            if not isinstance(item, dict):
                _unavailable()
            case_id = _uuid(item.get("case_id"))
            outcome_code = item.get("outcome_code")
            if outcome_code not in {
                "NO_ACTION",
                "PROTECTION_LIFTED",
                "PROTECTION_MAINTAINED",
                "PROTECTION_MODIFIED",
                "REMEDIATION_REQUIRED",
            }:
                _unavailable()
            _put_task(
                tasks,
                CurrentAccountTask(
                    classification=TaskClassification.COMPLETED.value,
                    resource_kind="TRUST_CASE",
                    resource_id=case_id,
                    source_status=outcome_code,
                    next_action="VIEW_TRUST_CASE_HISTORY",
                    resource_path="/v1/app/trust/history",
                    updated_at=_parse_utc(item.get("decided_at")),
                    due_at=None,
                ),
            )
        has_more = completed.get("has_more")
        if type(has_more) is not bool:
            _unavailable()
        return has_more

    def _appeal_reviewer(
        self,
        *,
        principal: EditorPrincipal,
        tasks: Dict[tuple[str, str], CurrentAccountTask],
    ) -> bool:
        _require_methods(
            self._appeal,
            (
                "list_appeal_queue",
                "list_my_active_appeal_assignments",
                "list_my_completed_appeal_assignments",
            ),
        )
        actor = _trust_actor(principal, organization_scoped=False)
        queue = self._appeal.list_appeal_queue(actor=actor, limit=100)
        if type(queue) is not AppealQueueProjection:
            _unavailable()
        for item in queue.items:
            appeal_id = _uuid(item.appeal_id)
            _put_task(
                tasks,
                CurrentAccountTask(
                    classification=TaskClassification.NEEDS_ACTION.value,
                    resource_kind="APPEAL_REVIEW",
                    resource_id=appeal_id,
                    source_status="AVAILABLE",
                    next_action="CLAIM_APPEAL_REVIEW",
                    resource_path="/v1/app/appeal-review/queue",
                    updated_at=_utc(item.submitted_at),
                    due_at=None,
                ),
            )
        assignments = self._appeal.list_my_active_appeal_assignments(
            actor=actor,
            limit=100,
        )
        if type(assignments) is not AppealActiveAssignmentsProjection:
            _unavailable()
        for item in assignments.items:
            appeal_id = _uuid(item.appeal_id)
            _put_task(
                tasks,
                CurrentAccountTask(
                    classification=TaskClassification.NEEDS_ACTION.value,
                    resource_kind="APPEAL_REVIEW",
                    resource_id=appeal_id,
                    source_status="ASSIGNED",
                    next_action="REVIEW_ASSIGNED_APPEAL",
                    resource_path=(
                        f"/v1/app/appeal-review/appeals/{appeal_id}"
                    ),
                    updated_at=None,
                    due_at=_utc(item.assignment_expires_at),
                ),
            )
        completed = self._appeal.list_my_completed_appeal_assignments(
            actor=actor,
            limit=100,
        )
        if type(completed) is not AppealCompletedAssignmentsProjection:
            _unavailable()
        for item in completed.items:
            appeal_id = _uuid(item.appeal_id)
            _put_task(
                tasks,
                CurrentAccountTask(
                    classification=TaskClassification.COMPLETED.value,
                    resource_kind="APPEAL_REVIEW",
                    resource_id=appeal_id,
                    source_status=item.decision_code,
                    next_action="VIEW_APPEAL_REVIEW_HISTORY",
                    resource_path="/v1/app/appeal-review/history",
                    updated_at=_utc(item.decided_at),
                    due_at=None,
                ),
                replace_existing=True,
            )
        return completed.has_more


def _authoritative_principal(principal: Any) -> None:
    if not isinstance(principal, EditorPrincipal):
        _unavailable()
    try:
        user_id = _uuid(principal.user_id)
        session_id = _uuid(principal.session_id)
    except EditorServiceError:
        raise
    if (
        user_id != principal.user_id
        or session_id != principal.session_id
        or principal.workspace_kind not in {"ORGANIZATION", "PERSONAL", "PLATFORM"}
        or principal.workspace_id is None
        or len(principal.principal_marker_sha256) != 32
        or principal.role_codes != tuple(sorted(set(principal.role_codes)))
    ):
        _unavailable()


def _trust_actor(
    principal: EditorPrincipal, *, organization_scoped: bool
) -> TrustActorContext:
    # These three facts are structurally required by the shared command actor,
    # but the durable read gateways consume only user/session/organization.
    # Reusing the authenticated session coordinate adds no caller input and no
    # authority; no audit event is written by these projections.
    coordinate = _uuid(principal.session_id)
    return TrustActorContext(
        actor_user_id=_uuid(principal.user_id),
        session_id=coordinate,
        organization_id=(
            _uuid(principal.organization_id) if organization_scoped else None
        ),
        correlation_id=coordinate,
        causation_id=coordinate,
        trace_id=coordinate,
        original_actor_user_id=None,
    )


def _trust_projection(value: Any, expected_kind: str) -> Mapping[str, Any]:
    if type(value) is not TrustHttpProjection or value.kind != expected_kind:
        _unavailable()
    data = value.as_json()
    if not isinstance(data, dict):
        _unavailable()
    return data


def _resource_updated_at(resource: EditorResourceDto) -> Optional[datetime]:
    candidates = []
    for value in resource.versions:
        candidates.append(_utc(value.created_at))
    for value in resource.submissions:
        candidates.append(_utc(value.submitted_at))
    for value in resource.findings:
        candidates.append(_utc(value.reviewed_at))
    return max(candidates) if candidates else None


def _demand_updated_at(resource: EditorResourceDto) -> Optional[datetime]:
    return _resource_updated_at(resource)


def _put_task(
    tasks: Dict[tuple[str, str], CurrentAccountTask],
    item: CurrentAccountTask,
    *,
    replace_existing: bool = False,
) -> None:
    key = (item.resource_kind, item.resource_id)
    existing = tasks.get(key)
    if replace_existing or existing is None or (
        item.next_action in _ASSIGNED_ACTIONS
        and existing.next_action not in _ASSIGNED_ACTIONS
    ):
        tasks[key] = item


def _sorted_tasks(
    values: Tuple[CurrentAccountTask, ...],
) -> Tuple[CurrentAccountTask, ...]:
    result = list(values)
    result.sort(key=lambda item: (item.resource_kind, item.resource_id))
    result.sort(
        key=lambda item: item.updated_at or item.due_at or _MINIMUM_TIME,
        reverse=True,
    )
    result.sort(
        key=lambda item: _CLASSIFICATION_ORDER[TaskClassification(item.classification)]
    )
    return tuple(result)


def _require_methods(value: Any, methods: Tuple[str, ...]) -> None:
    if value is None or any(not callable(getattr(value, method, None)) for method in methods):
        _unavailable()


def _uuid(value: Any) -> str:
    if not isinstance(value, str):
        _unavailable()
    try:
        parsed = UUID(value)
    except (TypeError, ValueError, AttributeError):
        _unavailable()
    if parsed.int == 0 or str(parsed) != value:
        _unavailable()
    return value


def _utc(value: Any) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _unavailable()
    try:
        result = value.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        _unavailable()
    if result.utcoffset() != timezone.utc.utcoffset(result):
        _unavailable()
    return result


def _parse_utc(value: Any) -> datetime:
    if not isinstance(value, str):
        _unavailable()
    if value.endswith("Z"):
        normalized = value[:-1] + "+00:00"
    elif value.endswith("+00:00"):
        normalized = value
    else:
        _unavailable()
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        _unavailable()
    return _utc(parsed)


def _unavailable() -> None:
    raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE")


__all__ = [
    "CurrentAccountTask",
    "CurrentAccountTaskDiscovery",
    "CurrentAccountTaskDiscoveryService",
    "TaskClassification",
]
