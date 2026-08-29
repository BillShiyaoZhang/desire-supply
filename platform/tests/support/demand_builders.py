"""Independent deterministic fixtures for the Demand semantic RED.

The fakes expose exact owner/reviewer/system authority, content policy, hold,
rules, receipt, checkpoints, rollback, and unknown-COMMIT observations without
importing IAM aggregates, PostgreSQL, HTTP, Profile, or existing IAM helpers.
"""

from __future__ import annotations

from contextlib import AbstractContextManager
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from typing import Any, Mapping, Optional

from desire_platform.demand.application import (
    ApplyFundingSecuredCommand,
    ApplyFundingSecuredHandler,
    CancelDemandCommand,
    CancelDemandHandler,
    CreateDemandCommand,
    CreateDemandHandler,
    CreateDemandVersionCommand,
    CreateDemandVersionHandler,
    DemandActorContext,
    DemandActorKind,
    ExpireDemandCommand,
    ExpireDemandHandler,
    FundingSecuredSourceEvent,
    RequestDemandChangesCommand,
    RequestDemandChangesHandler,
    RequestMatchingCommand,
    RequestMatchingHandler,
    SubmitDemandCommand,
    SubmitDemandHandler,
    VerifyDemandCommand,
    VerifyDemandHandler,
)
from desire_platform.demand.domain import (
    CancelReasonCode,
    Demand,
    DemandContent,
    DemandFundingMarker,
    DemandReview,
    DemandReviewAssignment,
    DemandStatus,
    DemandSubmission,
    DemandVersion,
    FundingObservedStatus,
    MatchingRequest,
    MatchingRequestStatus,
    ReviewAssignmentStatus,
    ReviewResult,
    demand_version_content_sha256,
)
from desire_platform.demand.ports.commands import (
    DemandCommitOutcomeUnknownError,
    DemandContentPolicyDecision,
    DemandContentPolicyResult,
    DemandHoldDecision,
    DemandOwnerAuthority,
    DemandReviewAuthority,
    DemandRuleRequirement,
    DemandSafetyHoldResult,
    DemandStorageUnavailableError,
    DemandSystemAuthority,
)


UTC_NOW = datetime(2026, 8, 8, 12, 0, tzinfo=timezone.utc)
ORGANIZATION_ID = "organization_demand_0001"
OTHER_ORGANIZATION_ID = "organization_demand_0002"
OWNER_USER_ID = "user_demand_owner_00001"
REVIEWER_USER_ID = "user_demand_review_0001"
SYSTEM_ID = "system_demand_worker_0001"
SESSION_ID = "session_demand_owner_001"
REVIEW_SESSION_ID = "session_demand_review_01"
DEMAND_ID = "demand_target_00000001"
SECOND_DEMAND_ID = "demand_target_00000002"
VERSION_ID = "demand_version_0000001"
SECOND_VERSION_ID = "demand_version_0000002"
SUBMISSION_ID = "demand_submission_00001"
ASSIGNMENT_ID = "demand_assignment_00001"
REVIEW_ID = "demand_review_00000001"
FUNDING_ID = "funding_target_0000001"
FUNDING_MARKER_ID = "funding_marker_0000001"
FUNDING_EVENT_ID = "funding_event_000000001"
MATCHING_REQUEST_ID = "matching_request_000001"
TAXONOMY_ID = "taxonomy_bundle_000001"
BUDGET_RULE_ID = "budget_rule_bundle_0001"
RISK_RULE_ID = "risk_rule_bundle_000001"
MATCHING_RULE_ID = "matching_rule_bundle_001"
REASON_RULE_ID = "reason_rule_bundle_0001"
COMPOSITE_RULE_ID = "composite_rule_req_0001"
IDEMPOTENCY_KEY = "demand-idempotency-key-0001"
RAW_CLIENT_REFERENCE = "private-client-reference-0001"
RAW_PRIVATE_SENTINELS = (
    RAW_CLIENT_REFERENCE,
    IDEMPOTENCY_KEY,
    "demand-owner@example.invalid",
    "provider-evidence-object-private-0001",
    "reviewer private narrative must not escape",
    "session-cookie-demand-private-0001",
    "csrf-demand-private-0000000001",
)


DEMAND_WRITE_CHECKPOINTS = (
    "receipt.claim",
    "demand_version.insert",
    "demand_root.insert_or_update",
    "submission.insert",
    "review.insert",
    "review_assignment.update",
    "source_inbox.claim",
    "funding_marker.insert",
    "matching_request.insert",
    "audit.insert",
    "outbox.insert",
    "source_inbox.complete",
    "receipt.complete",
)


def freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return DemandContent(
            tuple((str(key), freeze_json(child)) for key, child in value.items())
        )
    if isinstance(value, list):
        return tuple(freeze_json(child) for child in value)
    if value is None or isinstance(value, (bool, int, str)):
        return value
    raise TypeError("test Demand JSON contains an unsupported value")


def thaw_json(value: Any) -> Any:
    if isinstance(value, DemandContent):
        return {key: thaw_json(child) for key, child in value.members}
    if isinstance(value, tuple):
        return [thaw_json(child) for child in value]
    return value


def valid_content_mapping() -> dict[str, Any]:
    return {
        "problem": {
            "background": "Reduce energy waste in community buildings.",
            "domain_code": "DOMAIN.ENERGY",
            "problem_type_codes": ["PROBLEM.EFFICIENCY"],
            "target_user_category_codes": ["USER.COMMUNITY_MANAGER"],
            "desired_outcomes": ["A reproducible energy reduction plan."],
        },
        "scope": {
            "deliverables": [
                {
                    "item_id": "energy_plan",
                    "description": "Validated plan and evidence summary.",
                }
            ],
            "out_of_scope": ["Building construction."],
        },
        "acceptance": {
            "criteria": [
                {
                    "criterion_id": "measurable",
                    "description": "Recommendations include measurable baselines.",
                }
            ],
            "response_days": 10,
            "owner_role_code": "DEMAND_OWNER",
        },
        "skills": {
            "must_have": [
                {
                    "skill_code": "SKILL.ENERGY_ANALYSIS",
                    "minimum_level_code": "ADVANCED",
                }
            ],
            "nice_to_have": [
                {
                    "skill_code": "SKILL.FACILITATION",
                    "minimum_level_code": "WORKING",
                }
            ],
        },
        "matching": {
            "problem_codes": ["PROBLEM.EFFICIENCY"],
            "domain_codes": ["DOMAIN.ENERGY"],
            "task_codes": ["TASK.RESEARCH"],
        },
        "schedule": {
            "start_date": "2026-09-01",
            "due_date": "2026-10-31",
            "estimated_days": 30,
            "weekly_hours": 20,
            "duration_weeks": 8,
        },
        "budget": {
            "minimum_amount_minor": 100000,
            "maximum_amount_minor": 200000,
            "direct_cost_amount_minor": 20000,
            "currency": "CNY",
        },
        "milestone_plan": {
            "items": [
                {"item_id": "discovery", "label": "Discovery", "percent": 40},
                {"item_id": "plan", "label": "Final plan", "percent": 60},
            ]
        },
        "risk": {
            "uncertainty_code": "MEDIUM",
            "urgency_code": "LOW",
            "dependency_codes": ["DEPENDENCY.DATA_ACCESS"],
            "data_sensitivity": "HIGH",
            "data_handling_plan": (
                "Use minimized synthetic extracts and controlled access."
            ),
        },
        "ai": {
            "allowed": True,
            "required": False,
            "data_model_policy": (
                "Only approved regional models may process minimized extracts."
            ),
            "human_review_code": "ALWAYS",
        },
        "collaboration": {
            "languages": ["zh-CN", "en"],
            "work_mode": "HYBRID",
            "feedback_cadence": "WEEKLY",
            "team_preference": "SMALL_TEAM",
        },
        "location": {
            "demand_region_code": "CN-SH",
            "allowed_creator_region_codes": ["CN-SH", "CN-ZJ"],
        },
        "declarations": {
            "decision_authority": True,
            "data_rights": True,
            "procurement_intent": True,
        },
    }


def valid_content() -> DemandContent:
    return freeze_json(valid_content_mapping())


VALID_CONTENT_SHA256 = demand_version_content_sha256(
    demand_id=DEMAND_ID,
    version_no=1,
    taxonomy_bundle_id=TAXONOMY_ID,
    content=valid_content(),
)


def demand(
    *,
    status: DemandStatus = DemandStatus.DRAFT,
    aggregate_version: int = 1,
    current_version_id: str = VERSION_ID,
    verified_version_id: Optional[str] = None,
    current_funding_id: Optional[str] = None,
    current_matching_request_id: Optional[str] = None,
    organization_id: str = ORGANIZATION_ID,
    created_by_user_id: str = OWNER_USER_ID,
    cancelled_at: Optional[datetime] = None,
    expired_at: Optional[datetime] = None,
    reason_code: Optional[CancelReasonCode] = None,
) -> Demand:
    return Demand(
        demand_id=DEMAND_ID,
        organization_id=organization_id,
        created_by_user_id=created_by_user_id,
        status=status,
        aggregate_version=aggregate_version,
        current_version_id=current_version_id,
        verified_version_id=verified_version_id,
        current_funding_id=current_funding_id,
        current_matching_request_id=current_matching_request_id,
        client_reference_digest_key_id="demand-client-ref-2026-01",
        client_reference_digest="a" * 64,
        expires_at=UTC_NOW + timedelta(days=60),
        cancelled_at=cancelled_at,
        expired_at=expired_at,
        reason_code=reason_code,
        created_at=UTC_NOW - timedelta(days=1),
        updated_at=UTC_NOW,
    )


def demand_version(
    *,
    demand_version_id: str = VERSION_ID,
    version_no: int = 1,
    based_on_demand_version_id: Optional[str] = None,
    content: Optional[DemandContent] = None,
    content_sha256: Optional[str] = None,
    taxonomy_bundle_id: str = TAXONOMY_ID,
) -> DemandVersion:
    return DemandVersion(
        demand_version_id=demand_version_id,
        organization_id=ORGANIZATION_ID,
        demand_id=DEMAND_ID,
        version_no=version_no,
        based_on_demand_version_id=based_on_demand_version_id,
        content=content or valid_content(),
        content_sha256=content_sha256 or demand_version_content_sha256(
            demand_id=DEMAND_ID,
            version_no=version_no,
            taxonomy_bundle_id=taxonomy_bundle_id,
            content=content or valid_content(),
        ),
        demand_schema_version=1,
        canonicalization_version="demand-content-json-v1",
        taxonomy_bundle_id=taxonomy_bundle_id,
        created_by_user_id=OWNER_USER_ID,
        created_at=UTC_NOW - timedelta(minutes=10),
    )


def submission() -> DemandSubmission:
    return DemandSubmission(
        submission_id=SUBMISSION_ID,
        organization_id=ORGANIZATION_ID,
        demand_id=DEMAND_ID,
        demand_version_id=VERSION_ID,
        submission_no=1,
        submitted_by_user_id=OWNER_USER_ID,
        submitted_at=UTC_NOW - timedelta(minutes=5),
        content_sha256=VALID_CONTENT_SHA256,
        content_policy_version="demand-content-policy-v1",
        content_policy_result_sha256="c" * 64,
    )


def review_assignment(
    *,
    status: ReviewAssignmentStatus = ReviewAssignmentStatus.ACTIVE,
    reviewer_user_id: str = REVIEWER_USER_ID,
    expires_at: datetime = UTC_NOW + timedelta(hours=1),
) -> DemandReviewAssignment:
    return DemandReviewAssignment(
        assignment_id=ASSIGNMENT_ID,
        organization_id=ORGANIZATION_ID,
        demand_id=DEMAND_ID,
        reviewer_user_id=reviewer_user_id,
        duty_grant_id="duty_grant_review_0001",
        duty_grant_version=1,
        issued_by_user_id="user_assignment_issuer_01",
        purpose="DEMAND_REVIEW",
        status=status,
        conflict_attestation_sha256="d" * 64,
        assigned_at=UTC_NOW - timedelta(hours=1),
        expires_at=expires_at,
        aggregate_version=1,
    )


def review(*, result: ReviewResult = ReviewResult.VERIFIED) -> DemandReview:
    return DemandReview(
        review_id=REVIEW_ID,
        organization_id=ORGANIZATION_ID,
        demand_id=DEMAND_ID,
        demand_version_id=VERSION_ID,
        submission_id=SUBMISSION_ID,
        assignment_id=ASSIGNMENT_ID,
        reviewer_user_id=REVIEWER_USER_ID,
        result=result,
        reason_codes=("SCOPE_UNCLEAR",) if result is ReviewResult.NEEDS_CHANGES else (),
        required_field_codes=("SCOPE",) if result is ReviewResult.NEEDS_CHANGES else (),
        budget_health_code="HEALTHY",
        risk_code="STANDARD",
        evidence_summary_sha256="e" * 64,
        reviewed_at=UTC_NOW,
    )


def funding_marker() -> DemandFundingMarker:
    return DemandFundingMarker(
        funding_marker_id=FUNDING_MARKER_ID,
        organization_id=ORGANIZATION_ID,
        demand_id=DEMAND_ID,
        demand_version_id=VERSION_ID,
        funding_id=FUNDING_ID,
        amount_currency_sha256="f" * 64,
        verification_reference_sha256="1" * 64,
        source_event_id=FUNDING_EVENT_ID,
        source_aggregate_version=3,
        observed_status=FundingObservedStatus.SECURED,
        observed_at=UTC_NOW,
    )


def matching_request() -> MatchingRequest:
    return MatchingRequest(
        matching_request_id=MATCHING_REQUEST_ID,
        organization_id=ORGANIZATION_ID,
        demand_id=DEMAND_ID,
        demand_version_id=VERSION_ID,
        funding_id=FUNDING_ID,
        taxonomy_bundle_id=TAXONOMY_ID,
        budget_rule_bundle_id=BUDGET_RULE_ID,
        matching_rule_bundle_id=MATCHING_RULE_ID,
        reason_code_bundle_id=REASON_RULE_ID,
        composite_rule_requirement_id=COMPOSITE_RULE_ID,
        status=MatchingRequestStatus.OPEN,
        requested_at=UTC_NOW,
    )


def owner_actor(
    *, organization_id: str = ORGANIZATION_ID
) -> DemandActorContext:
    return DemandActorContext(
        actor_kind=DemandActorKind.USER,
        actor_id=OWNER_USER_ID,
        session_id=SESSION_ID,
        organization_id=organization_id,
        correlation_id="correlation_demand_0001",
        causation_id="causation_demand_00001",
        trace_id="trace_demand_000000001",
        original_actor_id=None,
    )


def reviewer_actor() -> DemandActorContext:
    return DemandActorContext(
        actor_kind=DemandActorKind.USER,
        actor_id=REVIEWER_USER_ID,
        session_id=REVIEW_SESSION_ID,
        organization_id=ORGANIZATION_ID,
        correlation_id="correlation_demand_0002",
        causation_id="causation_demand_00002",
        trace_id="trace_demand_000000002",
        original_actor_id=None,
    )


def system_actor() -> DemandActorContext:
    return DemandActorContext(
        actor_kind=DemandActorKind.SYSTEM,
        actor_id=SYSTEM_ID,
        session_id=None,
        organization_id=ORGANIZATION_ID,
        correlation_id="correlation_demand_0003",
        causation_id=FUNDING_EVENT_ID,
        trace_id="trace_demand_000000003",
        original_actor_id=None,
        workload_credential_id="workload_credential_private_01",
    )


def funding_event(**overrides: Any) -> FundingSecuredSourceEvent:
    event = FundingSecuredSourceEvent(
        event_id=FUNDING_EVENT_ID,
        event_type="FundingSecured",
        schema_version=1,
        source_aggregate_type="Funding",
        source_aggregate_id=FUNDING_ID,
        source_aggregate_version=3,
        organization_id=ORGANIZATION_ID,
        demand_id=DEMAND_ID,
        demand_version_id=VERSION_ID,
        funding_id=FUNDING_ID,
        target_type="DEMAND_VERSION",
        observed_status="SECURED",
        amount_currency_sha256="f" * 64,
        verification_reference_sha256="1" * 64,
        occurred_at=UTC_NOW - timedelta(seconds=10),
    )
    return replace(event, **overrides)


def commands() -> dict[str, Any]:
    return {
        "create": CreateDemandCommand(
            taxonomy_bundle_id=TAXONOMY_ID,
            content=valid_content(),
            raw_client_reference=RAW_CLIENT_REFERENCE,
            idempotency_key=IDEMPOTENCY_KEY,
        ),
        "version": CreateDemandVersionCommand(
            demand_id=DEMAND_ID,
            expected_version=1,
            based_on_demand_version_id=VERSION_ID,
            taxonomy_bundle_id=TAXONOMY_ID,
            content=valid_content(),
            idempotency_key=IDEMPOTENCY_KEY,
        ),
        "submit": SubmitDemandCommand(
            demand_id=DEMAND_ID,
            expected_version=1,
            idempotency_key=IDEMPOTENCY_KEY,
        ),
        "changes": RequestDemandChangesCommand(
            assignment_id=ASSIGNMENT_ID,
            demand_id=DEMAND_ID,
            expected_version=2,
            reason_codes=("SCOPE_UNCLEAR",),
            required_field_codes=("SCOPE",),
            idempotency_key=IDEMPOTENCY_KEY,
        ),
        "verify": VerifyDemandCommand(
            assignment_id=ASSIGNMENT_ID,
            demand_id=DEMAND_ID,
            expected_version=2,
            identity_subject_verified=True,
            payment_subject_verified=True,
            decision_authority_verified=True,
            budget_health_verified=True,
            budget_health_code="HEALTHY",
            risk_code="STANDARD",
            evidence_summary_sha256="e" * 64,
            idempotency_key=IDEMPOTENCY_KEY,
        ),
        "funding": ApplyFundingSecuredCommand(
            demand_id=DEMAND_ID,
            expected_version=4,
            source_event=funding_event(),
        ),
        "matching": RequestMatchingCommand(
            demand_id=DEMAND_ID,
            expected_version=5,
            assignment_id=ASSIGNMENT_ID,
            idempotency_key=IDEMPOTENCY_KEY,
        ),
        "cancel": CancelDemandCommand(
            demand_id=DEMAND_ID,
            expected_version=1,
            assignment_id=None,
            reason_code=CancelReasonCode.OWNER_WITHDREW,
            idempotency_key=IDEMPOTENCY_KEY,
        ),
        "expire": ExpireDemandCommand(
            demand_id=DEMAND_ID,
            expected_version=1,
            deadline=UTC_NOW,
            scheduler_command_id="scheduler_demand_expire_01",
        ),
    }


def valid_owner_authority() -> DemandOwnerAuthority:
    return DemandOwnerAuthority(
        actor_user_id=OWNER_USER_ID,
        session_id=SESSION_ID,
        organization_id=ORGANIZATION_ID,
        user_status="ACTIVE",
        session_status="ACTIVE",
        session_family_status="ACTIVE",
        organization_status="ACTIVE",
        membership_id="membership_demand_00001",
        membership_status="ACTIVE",
        membership_role_grant_id="role_grant_demand_0001",
        membership_role_grant_version=1,
        role_code="DEMAND_OWNER",
        policy_selector_digest="2" * 64,
        policy_bundle_id="policy_bundle_demand_001",
        policy_requirements_satisfied=True,
        authority_marker_sha256="3" * 64,
    )


def valid_review_authority() -> DemandReviewAuthority:
    return DemandReviewAuthority(
        actor_user_id=REVIEWER_USER_ID,
        session_id=REVIEW_SESSION_ID,
        organization_id=ORGANIZATION_ID,
        demand_id=DEMAND_ID,
        assignment_id=ASSIGNMENT_ID,
        assignment_status="ACTIVE",
        assignment_version=1,
        assignment_expires_at=UTC_NOW + timedelta(hours=1),
        duty_grant_id="duty_grant_review_0001",
        duty_grant_version=1,
        duty_code="OPERATIONS_REVIEWER",
        conflict_attestation_sha256="d" * 64,
        reviewer_is_creator=False,
        reviewer_is_owning_organization_member=False,
        authority_marker_sha256="4" * 64,
    )


def valid_system_authority() -> DemandSystemAuthority:
    return DemandSystemAuthority(
        workload_principal_id=SYSTEM_ID,
        workload_credential_id="workload_credential_private_01",
        operation="APPLY_FUNDING_SECURED",
        organization_id=ORGANIZATION_ID,
        demand_id=DEMAND_ID,
        source_event_id=FUNDING_EVENT_ID,
        valid_until=UTC_NOW + timedelta(minutes=5),
        authority_marker_sha256="5" * 64,
    )


class FixedClock:
    def __init__(self, now: datetime = UTC_NOW) -> None:
        self.value = now
        self.calls = 0

    def now(self) -> datetime:
        self.calls += 1
        return self.value


class ScriptedIdSource:
    def __init__(self) -> None:
        self.values = {
            "demand": [DEMAND_ID],
            "demand_version": [VERSION_ID, SECOND_VERSION_ID],
            "submission": [SUBMISSION_ID],
            "review": [REVIEW_ID],
            "funding_marker": [FUNDING_MARKER_ID],
            "matching_request": [MATCHING_REQUEST_ID],
            "command_receipt": ["demand_receipt_000001"],
            "audit_event": ["demand_audit_0000001"],
            "outbox_event": [f"demand_event_{index:08d}" for index in range(1, 10)],
        }
        self.calls: list[str] = []

    def new_id(self, kind: str) -> str:
        self.calls.append(kind)
        values = self.values.get(kind, [])
        if not values:
            raise AssertionError(f"unregistered Demand ID kind: {kind}")
        return values.pop(0)


class DeterministicReceiptKeyring:
    idempotency_key_digest_key_id = "demand-idempotency-2026-01"
    client_reference_digest_key_id = "demand-client-ref-2026-01"
    payload_hash_key_id = "demand-payload-2026-01"

    def keyed_digest(self, key_id: str, value: bytes) -> str:
        key = ("demand-test-key:" + key_id).encode("utf-8")
        return hmac.new(key, value, hashlib.sha256).hexdigest()


class RecordingValidator:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Mapping[str, Any]]] = []

    def validate(self, value: Mapping[str, Any], schema_name: str) -> None:
        self.calls.append((schema_name, deepcopy(dict(value))))


class ScriptedOwnerAuthority:
    def __init__(self) -> None:
        self.result = valid_owner_authority()
        self.error: Optional[Exception] = None
        self.calls: list[dict[str, Any]] = []

    def authorize(self, **query: Any) -> DemandOwnerAuthority:
        self.calls.append(deepcopy(query))
        if self.error is not None:
            raise self.error
        return self.result


class ScriptedReviewAuthority:
    def __init__(self) -> None:
        self.result = valid_review_authority()
        self.error: Optional[Exception] = None
        self.calls: list[dict[str, Any]] = []

    def authorize(self, **query: Any) -> DemandReviewAuthority:
        self.calls.append(deepcopy(query))
        if self.error is not None:
            raise self.error
        return self.result


class ScriptedSystemAuthority:
    def __init__(self) -> None:
        self.result = valid_system_authority()
        self.overrides: dict[str, Any] = {}
        self.error: Optional[Exception] = None
        self.calls: list[dict[str, Any]] = []

    def authorize(self, **query: Any) -> DemandSystemAuthority:
        self.calls.append(deepcopy(query))
        if self.error is not None:
            raise self.error
        changes = {
            "workload_principal_id": query["actor"].actor_id,
            "workload_credential_id": query["actor"].workload_credential_id,
            "operation": query["operation"],
            "organization_id": query["actor"].organization_id,
            "demand_id": query["demand_id"],
            "source_event_id": query.get("source_event_id"),
        }
        changes.update(self.overrides)
        return replace(self.result, **changes)


class ScriptedContentPolicy:
    def __init__(self) -> None:
        self.result = DemandContentPolicyResult(
            decision=DemandContentPolicyDecision.ALLOW,
            demand_id=DEMAND_ID,
            demand_version_id=VERSION_ID,
            content_sha256=VALID_CONTENT_SHA256,
            policy_version="demand-content-policy-v1",
            result_sha256="c" * 64,
            evaluated_at=UTC_NOW - timedelta(seconds=1),
            valid_until=UTC_NOW + timedelta(minutes=5),
        )
        self.error: Optional[Exception] = None
        self.overrides: dict[str, Any] = {}
        self.calls: list[dict[str, Any]] = []

    def evaluate(self, **query: Any) -> DemandContentPolicyResult:
        self.calls.append(deepcopy(query))
        if self.error is not None:
            raise self.error
        changes = {
            "demand_id": query["demand_id"],
            "demand_version_id": query["demand_version_id"],
            "content_sha256": query["content_sha256"],
            "policy_version": query["policy_version"],
        }
        changes.update(self.overrides)
        return replace(self.result, **changes)


class ScriptedSafetyHold:
    def __init__(self) -> None:
        self.result = DemandSafetyHoldResult(
            decision=DemandHoldDecision.ALLOW,
            actor_id=OWNER_USER_ID,
            organization_id=ORGANIZATION_ID,
            demand_id=DEMAND_ID,
            prospective_aggregate_version=2,
            demand_version_id=VERSION_ID,
            content_sha256=VALID_CONTENT_SHA256,
            action="SUBMIT_DEMAND",
            policy_version="demand-safety-hold-v1",
            evaluated_at=UTC_NOW - timedelta(seconds=1),
            valid_until=UTC_NOW + timedelta(minutes=5),
        )
        self.error: Optional[Exception] = None
        self.overrides: dict[str, Any] = {}
        self.calls: list[dict[str, Any]] = []

    def evaluate(self, **query: Any) -> DemandSafetyHoldResult:
        self.calls.append(deepcopy(query))
        if self.error is not None:
            raise self.error
        changes = {
            "actor_id": query["actor_id"],
            "organization_id": query["organization_id"],
            "demand_id": query["demand_id"],
            "prospective_aggregate_version": query["prospective_aggregate_version"],
            "demand_version_id": query["demand_version_id"],
            "content_sha256": query["content_sha256"],
            "action": query["action"],
            "policy_version": query["policy_version"],
        }
        changes.update(self.overrides)
        return replace(self.result, **changes)


class ScriptedRuleCatalog:
    def __init__(self) -> None:
        self.result = DemandRuleRequirement(
            taxonomy_bundle_id=TAXONOMY_ID,
            budget_rule_bundle_id=BUDGET_RULE_ID,
            risk_rule_bundle_id=RISK_RULE_ID,
            matching_rule_bundle_id=MATCHING_RULE_ID,
            reason_code_bundle_id=REASON_RULE_ID,
            composite_rule_requirement_id=COMPOSITE_RULE_ID,
            effective_at=UTC_NOW - timedelta(days=1),
            effective_until=None,
            requirement_sha256="6" * 64,
        )
        self.error: Optional[Exception] = None
        self.calls: list[dict[str, Any]] = []

    def current_requirement(self, **query: Any) -> DemandRuleRequirement:
        self.calls.append(deepcopy(query))
        if self.error is not None:
            raise self.error
        return self.result


class RecordingSourceEventValidator:
    def __init__(self) -> None:
        self.error: Optional[Exception] = None
        self.calls: list[dict[str, Any]] = []

    def validate(self, **query: Any) -> None:
        self.calls.append(deepcopy(query))
        if self.error is not None:
            raise self.error


class SnapshotStore:
    def __init__(self, seed: Optional[Mapping[str, Mapping[str, Any]]] = None) -> None:
        self.data = deepcopy(seed or {})

    def snapshot(self) -> Mapping[str, Mapping[str, Any]]:
        return deepcopy(self.data)


class ScriptedDemandUnitOfWork(AbstractContextManager["ScriptedDemandUnitOfWork"]):
    def __init__(self, factory: "ScriptedDemandUnitOfWorkFactory") -> None:
        self.factory = factory
        self.working = deepcopy(factory.store.data)
        self.locks: list[tuple[str, tuple[str, ...]]] = []
        self.checkpoints: list[str] = []

    def __enter__(self) -> "ScriptedDemandUnitOfWork":
        self.factory.instances.append(self)
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None

    def lock(self, resource: str, keys: Any) -> None:
        self.locks.append((resource, tuple(keys)))

    def get(self, collection: str, key: str) -> Any:
        return deepcopy(self.working.get(collection, {}).get(key))

    def values(self, collection: str) -> tuple[Any, ...]:
        return tuple(deepcopy(tuple(self.working.get(collection, {}).values())))

    def put(self, collection: str, key: str, value: Any, *, checkpoint: str) -> None:
        self.checkpoints.append(checkpoint)
        if self.factory.fail_checkpoint == checkpoint:
            raise DemandStorageUnavailableError(checkpoint)
        self.working.setdefault(collection, {})[key] = deepcopy(value)

    def commit(self) -> None:
        if self.factory.commit_unknown:
            if self.factory.commit_unknown_durable:
                self.factory.store.data = deepcopy(self.working)
            raise DemandCommitOutcomeUnknownError("demand commit acknowledgement lost")
        self.factory.store.data = deepcopy(self.working)


class ScriptedDemandUnitOfWorkFactory:
    def __init__(self, seed: Optional[Mapping[str, Mapping[str, Any]]] = None) -> None:
        self.store = SnapshotStore(seed)
        self.fail_checkpoint: Optional[str] = None
        self.commit_unknown = False
        self.commit_unknown_durable = False
        self.instances: list[ScriptedDemandUnitOfWork] = []

    def begin(self) -> ScriptedDemandUnitOfWork:
        return ScriptedDemandUnitOfWork(self)


@dataclass
class DemandHarness:
    owner_authority: ScriptedOwnerAuthority
    review_authority: ScriptedReviewAuthority
    system_authority: ScriptedSystemAuthority
    content_policy: ScriptedContentPolicy
    safety_hold: ScriptedSafetyHold
    rule_catalog: ScriptedRuleCatalog
    source_event_validator: RecordingSourceEventValidator
    uow_factory: ScriptedDemandUnitOfWorkFactory
    clock: FixedClock
    id_source: ScriptedIdSource
    receipt_keyring: DeterministicReceiptKeyring
    event_validator: RecordingValidator
    safe_response_validator: RecordingValidator
    handlers: dict[str, Any]


def build_harness(
    seed: Optional[Mapping[str, Mapping[str, Any]]] = None,
) -> DemandHarness:
    owner_authority = ScriptedOwnerAuthority()
    review_authority = ScriptedReviewAuthority()
    system_authority = ScriptedSystemAuthority()
    content_policy = ScriptedContentPolicy()
    safety_hold = ScriptedSafetyHold()
    rule_catalog = ScriptedRuleCatalog()
    source_event_validator = RecordingSourceEventValidator()
    uow_factory = ScriptedDemandUnitOfWorkFactory(seed)
    clock = FixedClock()
    id_source = ScriptedIdSource()
    seeded = seed or {}
    existing_by_kind = {
        "demand": set(seeded.get("demands", {})),
        "demand_version": set(seeded.get("demand_versions", {})),
        "submission": set(seeded.get("submissions", {})),
        "review": set(seeded.get("reviews", {})),
        "funding_marker": set(seeded.get("funding_markers", {})),
        "matching_request": set(seeded.get("matching_requests", {})),
        "command_receipt": set(seeded.get("receipts", {})),
        "audit_event": set(seeded.get("audits", {})),
        "outbox_event": set(seeded.get("outbox", {})),
    }
    for kind, existing in existing_by_kind.items():
        id_source.values[kind] = [
            value for value in id_source.values[kind] if value not in existing
        ]
    receipt_keyring = DeterministicReceiptKeyring()
    event_validator = RecordingValidator()
    safe_response_validator = RecordingValidator()
    dependencies = {
        "owner_authority": owner_authority,
        "review_authority": review_authority,
        "system_authority": system_authority,
        "content_policy": content_policy,
        "safety_hold": safety_hold,
        "rule_catalog": rule_catalog,
        "source_event_validator": source_event_validator,
        "uow_factory": uow_factory,
        "clock": clock,
        "id_source": id_source,
        "receipt_keyring": receipt_keyring,
        "event_validator": event_validator,
        "safe_response_validator": safe_response_validator,
    }
    handlers = {
        "create": CreateDemandHandler(**dependencies),
        "version": CreateDemandVersionHandler(**dependencies),
        "submit": SubmitDemandHandler(**dependencies),
        "changes": RequestDemandChangesHandler(**dependencies),
        "verify": VerifyDemandHandler(**dependencies),
        "funding": ApplyFundingSecuredHandler(**dependencies),
        "matching": RequestMatchingHandler(**dependencies),
        "cancel": CancelDemandHandler(**dependencies),
        "expire": ExpireDemandHandler(**dependencies),
    }
    return DemandHarness(
        owner_authority=owner_authority,
        review_authority=review_authority,
        system_authority=system_authority,
        content_policy=content_policy,
        safety_hold=safety_hold,
        rule_catalog=rule_catalog,
        source_event_validator=source_event_validator,
        uow_factory=uow_factory,
        clock=clock,
        id_source=id_source,
        receipt_keyring=receipt_keyring,
        event_validator=event_validator,
        safe_response_validator=safe_response_validator,
        handlers=handlers,
    )
