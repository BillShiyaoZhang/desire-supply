"""Secret-safe canonical fixtures for Matching machine-contract gates."""

from __future__ import annotations

from copy import deepcopy
from typing import Any


OID = "matching_object_00000001"
SHA = "a" * 64
SHA_B = "b" * 64
NOW = "2035-01-01T00:00:00Z"

HARD_FILTERS = (
    "CREATOR_INACTIVE", "BOUNDARY_DOMAIN", "BOUNDARY_TASK",
    "MISSING_MUST_HAVE_SKILL", "DATE_CONFLICT", "CAPACITY_CONFLICT",
    "DURATION_CONFLICT", "CURRENCY_MISMATCH", "BELOW_PRIVATE_FLOOR",
    "DATA_POLICY_CONFLICT", "AI_POLICY_CONFLICT", "LANGUAGE_MISMATCH",
    "WORK_MODE_CONFLICT", "LOCATION_RESTRICTION", "CONFLICT_OF_INTEREST",
)
COMPONENTS = (
    ("interest", 3000), ("capability", 2500), ("availability", 1500),
    ("compensation", 1500), ("collaboration", 1000),
    ("evidence_trust", 500),
)


def rule_release() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "canonicalization_version": "matching-rule-release-json-v1",
        "bundle_id": "matching_bundle_00000001",
        "semantic_version": "1.0.0",
        "selector_digest": SHA,
        "jurisdiction_code": "JURISDICTION.CN",
        "locale": "zh-CN",
        "demand_type_code": "DEMAND.PROJECT",
        "taxonomy_family_code": "TAXONOMY.GENERAL",
        "engine_identifier": "deterministic-matcher-v1",
        "engine_major": 1,
        "engine_artifact_sha256": SHA_B,
        "taxonomy_bundle_id": "taxonomy_bundle_0000001",
        "budget_rule_version": "budget-v1",
        "matching_rule_version": "matching-v1",
        "reason_code_version": "reason-v1",
        "explanation_template_version": "explanation-v1",
        "hard_filters": [
            {"code": code, "ordinal": ordinal, "enabled": True}
            for ordinal, code in enumerate(HARD_FILTERS, 1)
        ],
        "components": [
            {"code": code, "ordinal": ordinal, "weight_bps": weight}
            for ordinal, (code, weight) in enumerate(COMPONENTS, 1)
        ],
        "invitation_limit": 10,
        "golden_vectors": [
            {"vector_id": f"golden_vector_{kind}_0001", "input_sha256": SHA, "expected_result_sha256": SHA_B}
            for kind in ("budget", "excluded", "tie")
        ],
        "effective_at": NOW,
        "effective_until": None,
    }


def candidate_identity() -> dict[str, Any]:
    return {
        "creator_user_id": "creator_user_000000001",
        "profile_id": "creator_profile_0000001",
        "profile_version_id": "profile_version_0000001",
        "profile_content_sha256": SHA,
        "evidence_version_digest": SHA_B,
    }


def input_manifest(*, empty: bool = False) -> dict[str, Any]:
    candidates = [] if empty else [candidate_identity()]
    return {
        "schema_version": 1,
        "canonicalization_version": "match-input-manifest-v1",
        "attempt_id": "matching_attempt_0000001",
        "run_id": "matching_run_0000000001",
        "organization_id": "organization_0000000001",
        "demand_id": "demand_object_000000001",
        "demand_version_id": "demand_version_00000001",
        "demand_content_sha256": SHA,
        "funding_id": "funding_object_00000001",
        "matching_request_id": "matching_request_000001",
        "matching_request_version": 1,
        "matching_rule_bundle_id": "matching_bundle_00000001",
        "selector_digest": SHA,
        "rule_manifest_sha256": SHA_B,
        "ordered_candidates": candidates,
        "captured_at": NOW,
        "candidate_count": len(candidates),
        "input_set_sha256": SHA,
    }


def run_input(*, empty: bool = False) -> dict[str, Any]:
    profiles = [] if empty else [{
        **candidate_identity(),
        "status": "ACTIVE",
        "interest_problem_type_codes": ["PROBLEM.EFFICIENCY"],
        "interest_domain_codes": ["DOMAIN.ENERGY"],
        "interest_task_codes": ["TASK.ANALYZE"],
        "interest_intensity": 4,
        "prohibited_domain_codes": [],
        "prohibited_task_codes": [],
        "skills": [{"skill_code": "SKILL.ANALYSIS", "proficiency_level": 4, "evidence_trust_level": 3, "evidence_bucket": "VERIFIED"}],
        "available_from": "2035-01-01",
        "available_weekly_hours": 20,
        "available_duration_weeks": 8,
        "currency": "CNY",
        "within_offered_budget": True,
        "private_floor_evidence_digest": SHA_B,
        "allowed_data_sensitivity_codes": ["INTERNAL"],
        "ai_use_code": "OPTIONAL",
        "language_codes": ["LANGUAGE.ZH"],
        "work_mode_code": "WORK_MODE.REMOTE",
        "region_code": "REGION.CN",
        "location_eligible": True,
        "conflict_of_interest": False,
    }]
    return {
        "schema_version": 1,
        "canonicalization_version": "match-run-input-json-v1",
        "attempt_id": "matching_attempt_0000001",
        "run_id": "matching_run_0000000001",
        "demand_id": "demand_object_000000001",
        "demand_version_id": "demand_version_00000001",
        "matching_rule_bundle_id": "matching_bundle_00000001",
        "input_set_sha256": SHA,
        "demand": {
            "problem_type_codes": ["PROBLEM.EFFICIENCY"],
            "domain_codes": ["DOMAIN.ENERGY"],
            "task_codes": ["TASK.ANALYZE"],
            "must_have_skills": [{"skill_code": "SKILL.ANALYSIS", "minimum_level": 3}],
            "nice_to_have_skills": [],
            "start_date": "2035-01-02",
            "due_date": "2035-02-28",
            "required_weekly_hours": 10,
            "required_duration_weeks": 6,
            "currency": "CNY",
            "minimum_amount_minor": 100000,
            "maximum_amount_minor": 200000,
            "allowed_region_codes": ["REGION.CN"],
            "required_language_codes": ["LANGUAGE.ZH"],
            "required_work_mode_code": "WORK_MODE.REMOTE",
            "data_sensitivity_code": "INTERNAL",
            "ai_use_code": "OPTIONAL",
            "budget_override_code": None,
        },
        "profiles": profiles,
    }


def candidate_result(*, eligible: bool = True) -> dict[str, Any]:
    components = [
        {"code": code, "ordinal": ordinal, "score": "80.00"}
        for ordinal, (code, _) in enumerate(COMPONENTS, 1)
    ]
    return {
        "schema_version": 1,
        "canonicalization_version": "match-candidate-result-json-v1",
        "attempt_id": "matching_attempt_0000001",
        "run_id": "matching_run_0000000001",
        "creator_user_id": "creator_user_000000001",
        "profile_id": "creator_profile_0000001",
        "profile_version_id": "profile_version_0000001",
        "profile_content_sha256": SHA,
        "eligibility": "ELIGIBLE" if eligible else "EXCLUDED",
        "exclusion_reason_codes": [] if eligible else ["BELOW_PRIVATE_FLOOR"],
        "components": components if eligible else [],
        "total_score": "80.00" if eligible else None,
        "rank": 1 if eligible else None,
        "evidence_facts": [{"code": "WITHIN_BUDGET", "kind": "BOOLEAN", "value": eligible, "source_version_digest": SHA}],
        "candidate_result_sha256": SHA_B,
    }


def invitation_disclosure() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "canonicalization_version": "invitation-disclosure-json-v1",
        "invitation_id": "business_invitation_0001",
        "attempt_id": "matching_attempt_0000001",
        "demand_id": "demand_object_000000001",
        "demand_version_id": "demand_version_00000001",
        "profile_id": "creator_profile_0000001",
        "profile_version_id": "profile_version_0000001",
        "organization_preview": {"organization_id": "organization_0000000001", "display_label": "Community Energy Lab"},
        "opportunity": {"title": "Energy analysis", "problem_summary": "Reduce energy waste.", "deliverable_summaries": ["Validated plan."], "acceptance_summaries": ["Measurable baseline."]},
        "offer": {"currency": "CNY", "minimum_amount_minor": 100000, "maximum_amount_minor": 200000, "schedule_code": "SCHEDULE.FLEXIBLE", "duration_weeks": 6},
        "constraints": {"region_codes": ["REGION.CN"], "language_codes": ["LANGUAGE.ZH"], "data_sensitivity_code": "INTERNAL", "ai_use_code": "OPTIONAL"},
        "expires_at": NOW,
        "demand_content_sha256": SHA,
        "profile_content_sha256": SHA_B,
        "snapshot_sha256": SHA,
    }


def event(event_type: str) -> dict[str, Any]:
    base = {
        "event_id": "matching_event_000000001",
        "event_type": event_type,
        "schema_version": 1,
        "occurred_at": NOW,
        "aggregate_type": "MatchingAttempt",
        "aggregate_id": "matching_attempt_0000001",
        "aggregate_version": 1,
        "actor_kind": "SYSTEM",
        "actor_id": "system_actor_0000000001",
        "original_actor_id": None,
        "organization_id": "organization_0000000001",
        "correlation_id": "correlation_00000000001",
        "causation_id": "causation_000000000001",
        "trace_id": "trace_identifier_0000001",
    }
    attempt = {"attempt_id": "matching_attempt_0000001", "demand_id": "demand_object_000000001", "demand_version_id": "demand_version_00000001", "matching_request_id": "matching_request_000001", "attempt_no": 1, "status": "OPEN", "reason_code": None, "selection_id": None, "chosen_invitation_id": None}
    run = {"run_id": "matching_run_0000000001", "attempt_id": "matching_attempt_0000001", "run_no": 1, "rule_bundle_id": "matching_bundle_00000001", "input_set_sha256": SHA, "status": "QUEUED", "candidate_count": None, "eligible_count": None, "excluded_count": None, "ordered_result_sha256": None, "failure_code": None, "successor_run_id": None}
    invitation = {"invitation_id": "business_invitation_0001", "attempt_id": "matching_attempt_0000001", "run_id": "matching_run_0000000001", "creator_user_id": "creator_user_000000001", "profile_version_id": "profile_version_0000001", "snapshot_sha256": SHA, "status": "CREATED", "expires_at": NOW, "reason_code": None}
    selection = {"selection_id": "matching_selection_00001", "attempt_id": "matching_attempt_0000001", "status": "OPEN", "current_invitation_set_sha256": SHA, "chosen_invitation_id": None, "selection_basis_code": None, "reason_code": None}
    operational = {
        "CandidateSelectorAssigned": (
            "CandidateSelectorAssignment",
            "selector_assignment_00001",
            {"assignment_id": "selector_assignment_00001", "selection_id": "matching_selection_00001", "demand_id": "demand_object_000000001", "status": "ACTIVE"},
        ),
        "MatchingRulePublished": (
            "MatchingRule",
            "matching_bundle_00000001",
            {"rule_bundle_id": "matching_bundle_00000001", "selector_digest": SHA, "status": "ACTIVE"},
        ),
        "MatchJobClaimed": (
            "MatchJob",
            "matching_job_0000000001",
            {"job_id": "matching_job_0000000001", "attempt_id": "matching_attempt_0000001", "match_run_id": "matching_run_0000000001", "status": "LEASED", "fencing_generation": 1, "recovery_status": "CLAIMED"},
        ),
        "MatchRunRetryScheduled": (
            "MatchRun",
            "matching_run_0000000001",
            {"failed_run_id": "matching_run_0000000001", "failed_run_version": 2, "successor_run_id": "matching_run_0000000002", "successor_job_id": "matching_job_0000000002", "attempt_id": "matching_attempt_0000001", "failure_code": "ENGINE_FAILURE", "status": "QUEUED"},
        ),
        "SelectionCompletionClaimed": (
            "SelectionCompletionJob",
            "selection_completion_0001",
            {"completion_job_id": "selection_completion_0001", "selection_id": "matching_selection_00001", "intent_kind": "CHOOSE", "status": "LEASED", "fencing_generation": 1, "attempt_count": 1, "failure_code": None},
        ),
        "SelectionCompletionFailed": (
            "SelectionCompletionJob",
            "selection_completion_0001",
            {"completion_job_id": "selection_completion_0001", "selection_id": "matching_selection_00001", "intent_kind": "CHOOSE", "status": "FAILED", "fencing_generation": 3, "attempt_count": 3, "failure_code": "LEASE_EXHAUSTED"},
        ),
        "SelectionCompletionRetryScheduled": (
            "SelectionCompletionJob",
            "selection_completion_0001",
            {"completion_job_id": "selection_completion_0001", "selection_id": "matching_selection_00001", "intent_kind": "CLOSE", "status": "AVAILABLE", "fencing_generation": 1, "attempt_count": 1, "failure_code": "TRANSIENT_FAILURE"},
        ),
        "MatchingReviewAssignmentClaimed": (
            "MatchingReviewAssignment",
            "review_assignment_000001",
            {"assignment_id": "review_assignment_000001", "attempt_id": "matching_attempt_0000001", "match_run_id": "matching_run_0000000001", "purpose_code": "INVITATION_REVIEW", "status": "ACTIVE", "assignment_version": 1},
        ),
        "MatchingReviewAssignmentReleased": (
            "MatchingReviewAssignment",
            "review_assignment_000001",
            {"assignment_id": "review_assignment_000001", "attempt_id": "matching_attempt_0000001", "match_run_id": "matching_run_0000000001", "purpose_code": "INVITATION_REVIEW", "status": "REVOKED", "assignment_version": 2},
        ),
    }
    if event_type in operational:
        aggregate_type, aggregate_id, payload = operational[event_type]
        base.update(
            aggregate_type=aggregate_type,
            aggregate_id=aggregate_id,
            payload=payload,
        )
        return deepcopy(base)
    if event_type.startswith("MatchRun"):
        base.update(aggregate_type="MatchRun", aggregate_id=run["run_id"])
        run["status"] = {"MatchRunQueued": "QUEUED", "MatchRunStarted": "RUNNING", "MatchRunCompleted": "COMPLETED", "MatchRunFailed": "FAILED", "MatchRunSuperseded": "SUPERSEDED"}[event_type]
        if event_type == "MatchRunCompleted":
            run.update(candidate_count=1, eligible_count=1, excluded_count=0, ordered_result_sha256=SHA_B)
        elif event_type == "MatchRunFailed":
            run["failure_code"] = "ENGINE_FAILURE"
        elif event_type == "MatchRunSuperseded":
            run["successor_run_id"] = "matching_run_0000000002"
        base["payload"] = run
    elif event_type.startswith("Invitation"):
        base.update(aggregate_type="Invitation", aggregate_id=invitation["invitation_id"])
        invitation["status"] = event_type.removeprefix("Invitation").upper()
        if invitation["status"] in {
            "DECLINED",
            "WITHDRAWN",
            "REVOKED",
            "EXPIRED",
        }:
            invitation["reason_code"] = (
                "RECIPIENT_DECLINED"
                if invitation["status"] == "DECLINED"
                else "RECIPIENT_WITHDREW"
                if invitation["status"] == "WITHDRAWN"
                else "DEADLINE_REACHED"
            )
        base["payload"] = invitation
    elif event_type.startswith("Selection"):
        base.update(aggregate_type="Selection", aggregate_id=selection["selection_id"])
        selection["status"] = {"SelectionOpened": "OPEN", "SelectionInvitationSetChanged": "OPEN", "SelectionIntentRecorded": "PENDING_CHOICE", "SelectionCloseIntentRecorded": "PENDING_CLOSE", "SelectionMade": "SELECTED", "SelectionClosedWithoutChoice": "CLOSED_NO_SELECTION", "SelectionCancelled": "CANCELLED"}[event_type]
        if event_type in {"SelectionIntentRecorded", "SelectionMade"}:
            selection.update(chosen_invitation_id="business_invitation_0001", selection_basis_code="ALGORITHM_TOP")
        elif event_type not in {"SelectionOpened", "SelectionInvitationSetChanged"}:
            selection["reason_code"] = "OWNER_CLOSED"
        base["payload"] = selection
    else:
        attempt["status"] = {"MatchingAttemptOpened": "OPEN", "MatchingAttemptSelected": "SELECTED", "MatchingAttemptClosedWithoutSelection": "CLOSED_NO_SELECTION", "MatchingAttemptInvalidated": "INVALIDATED", "MatchingAttemptCancelled": "CANCELLED"}[event_type]
        if event_type == "MatchingAttemptSelected":
            attempt.update(selection_id="matching_selection_00001", chosen_invitation_id="business_invitation_0001")
        elif event_type == "MatchingAttemptClosedWithoutSelection":
            attempt["selection_id"] = "matching_selection_00001"
        elif event_type in {"MatchingAttemptInvalidated", "MatchingAttemptCancelled"}:
            attempt["reason_code"] = "INPUT_CHANGED"
        base["payload"] = attempt
    return deepcopy(base)
