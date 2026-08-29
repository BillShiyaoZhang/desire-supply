"""TDD contracts for the executable INTERNAL_SANDBOX evidence boundary."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
from uuid import UUID

import pytest

from desire_platform.creator_profile.domain import (
    canonical_profile_version_bytes,
    freeze_profile_content,
)
from desire_platform.demand.domain import canonical_demand_version_bytes
from desire_platform.demand.ports.commands import (
    DemandHoldDecision,
    DemandRuleRequirement,
    DemandSafetyHoldResult,
)
from desire_platform.internal_pilot.editor import EditorPrincipal, EditorServiceError
from desire_platform.internal_pilot.editor.sandbox_evidence import (
    InternalSandboxEditorEvidenceProvider,
)
from tests.support.creator_profile_builders import valid_content_mapping as profile_content
from tests.support.demand_builders import (
    freeze_json as freeze_demand,
    valid_content_mapping as demand_content,
)


NOW = datetime(2026, 8, 12, 12, 0, tzinfo=timezone.utc)
ACTOR = "10000000-0000-4000-8000-000000000001"
SESSION = "20000000-0000-4000-8000-000000000001"
ORG = "81000000-0000-4000-8000-000000000001"
MEMBERSHIP = "83000000-0000-4000-8000-000000000001"
PROFILE = UUID("31000000-0000-4000-8000-000000000001")
DEMAND = UUID("41000000-0000-4000-8000-000000000001")
VERSION = UUID("42000000-0000-4000-8000-000000000001")
TAXONOMY = UUID("50000000-0000-4000-8000-000000000001")
MARKER = hashlib.sha256(b"principal-authority-graph").digest()


class _Rules:
    def __init__(self, *, taxonomy: UUID = TAXONOMY) -> None:
        self.taxonomy = taxonomy
        self.calls = []
        self.readiness_calls = []
        self.closed = False

    def current_requirement(self, **query):
        self.calls.append(query)
        return DemandRuleRequirement(
            taxonomy_bundle_id=str(self.taxonomy),
            budget_rule_bundle_id="51000000-0000-4000-8000-000000000001",
            risk_rule_bundle_id="52000000-0000-4000-8000-000000000001",
            matching_rule_bundle_id="53000000-0000-4000-8000-000000000001",
            reason_code_bundle_id="54000000-0000-4000-8000-000000000001",
            composite_rule_requirement_id="55000000-0000-4000-8000-000000000001",
            effective_at=NOW - timedelta(days=1),
            effective_until=NOW + timedelta(days=1),
            requirement_sha256=hashlib.sha256(b"reviewed-rule-requirement").hexdigest(),
        )

    def check_readiness(self, *, timeout_ms: int) -> None:
        if self.closed:
            raise RuntimeError("RULE_CATALOG_CLOSED")
        self.readiness_calls.append(timeout_ms)

    def close(self) -> None:
        self.closed = True


class _SequencedClock:
    def __init__(self, *values: datetime) -> None:
        self.values = list(values)

    def now(self) -> datetime:
        if not self.values:
            raise RuntimeError("CLOCK_EXHAUSTED")
        return self.values.pop(0)


class _DemandHold:
    def __init__(self, result: DemandSafetyHoldResult | BaseException) -> None:
        self.result = result
        self.calls = []
        self.closed = False

    def evaluate(self, **query):
        self.calls.append(query)
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result

    def close(self) -> None:
        self.closed = True


def _profile_principal() -> EditorPrincipal:
    return EditorPrincipal(
        user_id=ACTOR,
        session_id=SESSION,
        organization_id=None,
        role_codes=("CREATOR",),
        workspace_id=f"personal:{ACTOR}",
        workspace_kind="PERSONAL",
        user_role_codes=("CREATOR",),
        principal_marker_sha256=MARKER,
    )


def _demand_principal() -> EditorPrincipal:
    return EditorPrincipal(
        user_id=ACTOR,
        session_id=SESSION,
        organization_id=ORG,
        role_codes=("DEMAND_OWNER",),
        workspace_id=f"org:{ORG}",
        workspace_kind="ORGANIZATION",
        membership_id=MEMBERSHIP,
        organization_role_codes=("DEMAND_OWNER",),
        principal_marker_sha256=MARKER,
    )


def _safe_profile() -> dict:
    value = profile_content()
    value["boundaries"]["allowed_data_sensitivity"]["data_sensitivity"] = "INTERNAL"
    value["ai"]["allowed"] = False
    value["ai"]["requires_ai"] = False
    return value


def _safe_demand() -> dict:
    value = demand_content()
    value["problem"]["background"] = "INTERNAL_SANDBOX 合成问题背景"
    value["problem"]["domain_code"] = "DOMAIN.SOFTWARE"
    value["problem"]["problem_type_codes"] = ["PROBLEM.OPERATIONS"]
    value["problem"]["target_user_category_codes"] = ["SYNTHETIC_USER"]
    value["skills"] = {
        "must_have": [
            {
                "skill_code": "SKILL.SYSTEMS_ANALYSIS",
                "minimum_level_code": "WORKING",
            }
        ],
        "nice_to_have": [],
    }
    value["matching"] = {
        "problem_codes": ["PROBLEM.OPERATIONS"],
        "domain_codes": ["DOMAIN.SOFTWARE"],
        "task_codes": ["TASK.ANALYSIS"],
    }
    value["scope"]["out_of_scope"] = ["真实用户与真实交易"]
    value["budget"] = {
        "minimum_amount_minor": 0,
        "maximum_amount_minor": 680_000,
        "direct_cost_amount_minor": 0,
        "currency": "CNY",
    }
    value["risk"]["data_sensitivity"] = "INTERNAL"
    value["risk"]["data_handling_plan"] = "仅使用合成资料。"
    value["ai"] = {
        "allowed": False,
        "required": False,
        "data_model_policy": None,
        "human_review_code": "RISK_BASED",
    }
    value["location"] = {
        "demand_region_code": "CN",
        "allowed_creator_region_codes": ["CN"],
    }
    value["declarations"] = {
        "decision_authority": True,
        "data_rights": True,
        "procurement_intent": True,
    }
    return value


def _profile_hash(content: dict) -> bytes:
    return hashlib.sha256(
        canonical_profile_version_bytes(
            profile_id=str(PROFILE),
            version_no=1,
            taxonomy_bundle_id=str(TAXONOMY),
            content=freeze_profile_content(content, for_publish=True),
        )
    ).digest()


def _demand_hash(content: dict) -> bytes:
    return hashlib.sha256(
        canonical_demand_version_bytes(
            demand_id=str(DEMAND),
            version_no=1,
            taxonomy_bundle_id=str(TAXONOMY),
            content=freeze_demand(content),
        )
    ).digest()


def test_safe_synthetic_content_produces_a_closed_short_lived_chain() -> None:
    rules = _Rules()
    provider = InternalSandboxEditorEvidenceProvider(
        deployment_mode="INTERNAL_SANDBOX",
        demand_rule_catalog=rules,
    )
    profile_content_value = _safe_profile()
    demand_content_value = _safe_demand()
    profile_hash = _profile_hash(profile_content_value)
    demand_hash = _demand_hash(demand_content_value)

    profile = provider.profile_hold(
        principal=_profile_principal(),
        action="PublishCreatorProfileVersion",
        profile_id=PROFILE,
        profile_version_no=1,
        taxonomy_bundle_id=TAXONOMY,
        prospective_aggregate_version=3,
        content_sha256=profile_hash,
        content=profile_content_value,
        evaluated_at=NOW,
    )
    policy = provider.demand_content_policy(
        principal=_demand_principal(),
        demand_id=DEMAND,
        demand_version_id=VERSION,
        demand_version_no=1,
        taxonomy_bundle_id=TAXONOMY,
        content_sha256=demand_hash,
        content=demand_content_value,
        evaluated_at=NOW,
    )
    hold = provider.demand_hold(
        principal=_demand_principal(),
        demand_id=DEMAND,
        demand_version_id=VERSION,
        prospective_aggregate_version=4,
        content_sha256=demand_hash,
        action="SUBMIT_DEMAND",
        content_policy=policy,
        evaluated_at=NOW,
    )
    requirement = provider.demand_rules(
        principal=_demand_principal(),
        demand_id=DEMAND,
        taxonomy_bundle_id=TAXONOMY,
        operation="SUBMIT_DEMAND",
        evaluated_at=NOW,
    )

    assert profile.policy_version == "creator-profile-hold-v1"
    assert policy.policy_version == "demand-content-policy-v1"
    assert hold.policy_version == "demand-safety-hold-v1"
    assert profile.valid_until == policy.valid_until == hold.valid_until
    assert profile.valid_until == NOW + timedelta(minutes=2)
    assert requirement.taxonomy_bundle_id == TAXONOMY
    assert rules.calls == [
        {
            "organization_id": ORG,
            "demand_id": str(DEMAND),
            "operation": "SUBMIT_DEMAND",
        }
    ]


def test_trust_hold_uses_a_post_query_clock_and_exact_server_facts() -> None:
    database_time = NOW + timedelta(microseconds=1)
    validation_time = NOW + timedelta(microseconds=2)
    hold_port = _DemandHold(
        DemandSafetyHoldResult(
            decision=DemandHoldDecision.ALLOW,
            actor_id=ACTOR,
            organization_id=ORG,
            demand_id=str(DEMAND),
            prospective_aggregate_version=4,
            demand_version_id=str(VERSION),
            content_sha256=_demand_hash(_safe_demand()).hex(),
            action="SUBMIT_DEMAND",
            policy_version="demand-safety-hold-v1",
            evaluated_at=database_time,
            valid_until=database_time + timedelta(seconds=15),
        )
    )
    provider = InternalSandboxEditorEvidenceProvider(
        deployment_mode="INTERNAL_SANDBOX",
        demand_rule_catalog=_Rules(),
        demand_safety_hold=hold_port,
        validation_clock=_SequencedClock(validation_time),
    )
    content = _safe_demand()
    digest = _demand_hash(content)
    policy = provider.demand_content_policy(
        principal=_demand_principal(),
        demand_id=DEMAND,
        demand_version_id=VERSION,
        demand_version_no=1,
        taxonomy_bundle_id=TAXONOMY,
        content_sha256=digest,
        content=content,
        evaluated_at=NOW,
    )

    result = provider.demand_hold(
        principal=_demand_principal(),
        demand_id=DEMAND,
        demand_version_id=VERSION,
        prospective_aggregate_version=4,
        content_sha256=digest,
        action="SUBMIT_DEMAND",
        content_policy=policy,
        evaluated_at=NOW,
    )

    assert result.decision == "ALLOW"
    assert result.evaluated_at == database_time
    assert result.valid_until == database_time + timedelta(seconds=15)
    assert hold_port.calls == [
        {
            "actor_id": ACTOR,
            "organization_id": ORG,
            "demand_id": str(DEMAND),
            "prospective_aggregate_version": 4,
            "demand_version_id": str(VERSION),
            "content_sha256": digest.hex(),
            "action": "SUBMIT_DEMAND",
            "policy_version": "demand-safety-hold-v1",
        }
    ]


@pytest.mark.parametrize(
    ("result", "expected_status", "expected_code"),
    (
        (
            DemandSafetyHoldResult(
                decision=DemandHoldDecision.BLOCK,
                actor_id=ACTOR,
                organization_id=ORG,
                demand_id=str(DEMAND),
                prospective_aggregate_version=4,
                demand_version_id=str(VERSION),
                content_sha256=_demand_hash(_safe_demand()).hex(),
                action="SUBMIT_DEMAND",
                policy_version="demand-safety-hold-v1",
                evaluated_at=NOW + timedelta(microseconds=1),
                valid_until=NOW + timedelta(seconds=15),
            ),
            403,
            "SAFETY_HOLD_BLOCKED",
        ),
        (
            DemandSafetyHoldResult(
                decision=DemandHoldDecision.BLOCK,
                actor_id="10000000-0000-4000-8000-000000000099",
                organization_id=ORG,
                demand_id=str(DEMAND),
                prospective_aggregate_version=4,
                demand_version_id=str(VERSION),
                content_sha256=_demand_hash(_safe_demand()).hex(),
                action="SUBMIT_DEMAND",
                policy_version="demand-safety-hold-v1",
                evaluated_at=NOW + timedelta(microseconds=1),
                valid_until=NOW + timedelta(seconds=15),
            ),
            503,
            "SERVICE_UNAVAILABLE",
        ),
        (
            DemandSafetyHoldResult(
                decision="BLOCK",  # type: ignore[arg-type]
                actor_id=ACTOR,
                organization_id=ORG,
                demand_id=str(DEMAND),
                prospective_aggregate_version=4,
                demand_version_id=str(VERSION),
                content_sha256=_demand_hash(_safe_demand()).hex(),
                action="SUBMIT_DEMAND",
                policy_version="demand-safety-hold-v1",
                evaluated_at=NOW + timedelta(microseconds=1),
                valid_until=NOW + timedelta(seconds=15),
            ),
            503,
            "SERVICE_UNAVAILABLE",
        ),
        (RuntimeError("provider detail must not escape"), 503, "SERVICE_UNAVAILABLE"),
    ),
)
def test_trust_hold_blocks_only_after_exact_binding_validation(
    result,
    expected_status: int,
    expected_code: str,
) -> None:
    hold_port = _DemandHold(result)
    provider = InternalSandboxEditorEvidenceProvider(
        deployment_mode="INTERNAL_SANDBOX",
        demand_rule_catalog=_Rules(),
        demand_safety_hold=hold_port,
        validation_clock=_SequencedClock(NOW + timedelta(microseconds=2)),
    )
    content = _safe_demand()
    digest = _demand_hash(content)
    policy = provider.demand_content_policy(
        principal=_demand_principal(),
        demand_id=DEMAND,
        demand_version_id=VERSION,
        demand_version_no=1,
        taxonomy_bundle_id=TAXONOMY,
        content_sha256=digest,
        content=content,
        evaluated_at=NOW,
    )

    with pytest.raises(EditorServiceError) as raised:
        provider.demand_hold(
            principal=_demand_principal(),
            demand_id=DEMAND,
            demand_version_id=VERSION,
            prospective_aggregate_version=4,
            content_sha256=digest,
            action="SUBMIT_DEMAND",
            content_policy=policy,
            evaluated_at=NOW,
        )

    assert (raised.value.status, raised.value.code) == (
        expected_status,
        expected_code,
    )
    assert "provider detail" not in repr(raised.value)


def test_editor_configuration_comes_from_the_current_rule_requirement_for_each_edit_workspace() -> None:
    rules = _Rules()
    provider = InternalSandboxEditorEvidenceProvider(
        deployment_mode="INTERNAL_SANDBOX",
        demand_rule_catalog=rules,
    )

    profile_configuration = provider.editor_configuration(
        principal=_profile_principal(), evaluated_at=NOW
    )
    demand_configuration = provider.editor_configuration(
        principal=_demand_principal(), evaluated_at=NOW
    )

    assert profile_configuration.schema_version == "editor-configuration-v2"
    assert profile_configuration.deployment_mode == "INTERNAL_SANDBOX"
    assert profile_configuration.taxonomy_bundle.bundle_id == str(TAXONOMY)
    assert profile_configuration.taxonomy_bundle.status == "CURRENT_APPROVED"
    assert profile_configuration.taxonomy_bundle.effective_at == NOW - timedelta(days=1)
    assert profile_configuration.taxonomy_bundle.effective_until == NOW + timedelta(days=1)
    choices = profile_configuration.editor_choices
    assert (choices.schema_version, choices.locale, len(choices.fields)) == (
        "editor-choices-v1",
        "zh-CN",
        23,
    )
    fields = {
        (field.resource_type, field.path_template): field
        for field in choices.fields
    }
    assert tuple(fields) == tuple(sorted(fields))
    assert fields[("CREATOR_PROFILE", "/interests/*/domain_code")].options[0].value == (
        "DOMAIN.SOFTWARE"
    )
    assert fields[("CREATOR_PROFILE", "/interests/*/problem_code")].options[0].label == (
        "运营改进"
    )
    demand_target = fields[
        ("DEMAND", "/problem/target_user_category_codes/*")
    ]
    assert tuple(option.value for option in demand_target.options) == (
        "SYNTHETIC_USER",
    )
    assert demand_target.options[0].source == "INTERNAL_SANDBOX_POLICY"
    assert "TARGET_USER.SMALL_TEAM" not in {
        option.value for field in choices.fields for option in field.options
        if field.resource_type == "DEMAND"
        and field.path_template == "/problem/target_user_category_codes/*"
    }
    for identity in (
        ("CREATOR_PROFILE", "/ai/prohibited_case_codes/*"),
        ("DEMAND", "/risk/dependency_codes/*"),
    ):
        assert (
            fields[identity].status,
            fields[identity].reason_code,
            fields[identity].options,
        ) == ("UNAVAILABLE", "NO_REVIEWED_CHOICE_SET", ())
    assert demand_configuration == profile_configuration
    assert rules.calls == [
        {
            "organization_id": ACTOR,
            "demand_id": ACTOR,
            "operation": "SUBMIT_DEMAND",
        },
        {
            "organization_id": ORG,
            "demand_id": ACTOR,
            "operation": "SUBMIT_DEMAND",
        },
    ]


def test_editor_configuration_rejects_unapproved_expired_or_unscoped_facts() -> None:
    rules = _Rules()
    provider = InternalSandboxEditorEvidenceProvider(
        deployment_mode="INTERNAL_SANDBOX",
        demand_rule_catalog=rules,
    )
    reviewer = EditorPrincipal(
        user_id=ACTOR,
        session_id=SESSION,
        organization_id=None,
        role_codes=("OPERATIONS_REVIEWER",),
        workspace_id=f"platform:{ACTOR}",
        workspace_kind="PLATFORM",
        platform_duty_codes=("OPERATIONS_REVIEWER",),
        principal_marker_sha256=MARKER,
    )

    with pytest.raises(EditorServiceError) as hidden:
        provider.editor_configuration(principal=reviewer, evaluated_at=NOW)
    assert (hidden.value.status, hidden.value.code) == (404, "RESOURCE_NOT_FOUND")

    original = rules.current_requirement
    rules.current_requirement = lambda **query: replace(
        original(**query), effective_until=NOW
    )
    with pytest.raises(EditorServiceError) as expired:
        provider.editor_configuration(principal=_profile_principal(), evaluated_at=NOW)
    assert (expired.value.status, expired.value.code) == (
        503,
        "EDITOR_CONFIGURATION_UNAVAILABLE",
    )

    wrong_bundle_provider = InternalSandboxEditorEvidenceProvider(
        deployment_mode="INTERNAL_SANDBOX",
        demand_rule_catalog=_Rules(
            taxonomy=UUID("50000000-0000-4000-8000-000000000002")
        ),
    )
    with pytest.raises(EditorServiceError) as wrong_bundle:
        wrong_bundle_provider.editor_configuration(
            principal=_profile_principal(), evaluated_at=NOW
        )
    assert (wrong_bundle.value.status, wrong_bundle.value.code) == (
        503,
        "EDITOR_CONFIGURATION_UNAVAILABLE",
    )


@pytest.mark.parametrize(
    "mutate",
    (
        lambda value: value["problem"].__setitem__(
            "background", "INTERNAL_SANDBOX creator@example.com"
        ),
        lambda value: value["risk"].__setitem__("data_sensitivity", "HIGH"),
        lambda value: value["ai"].__setitem__("allowed", True),
        lambda value: value["budget"].__setitem__("maximum_amount_minor", 680_001),
        lambda value: value["problem"].__setitem__(
            "target_user_category_codes", ["REAL_USER"]
        ),
        lambda value: value["problem"].__setitem__(
            "target_user_category_codes", ["TARGET_USER.SMALL_TEAM"]
        ),
    ),
)
def test_demand_submission_rejects_real_or_out_of_scope_material(mutate) -> None:
    content = _safe_demand()
    mutate(content)
    provider = InternalSandboxEditorEvidenceProvider(
        deployment_mode="INTERNAL_SANDBOX",
        demand_rule_catalog=_Rules(),
    )

    with pytest.raises(EditorServiceError) as rejected:
        provider.demand_content_policy(
            principal=_demand_principal(),
            demand_id=DEMAND,
            demand_version_id=VERSION,
            demand_version_no=1,
            taxonomy_bundle_id=TAXONOMY,
            content_sha256=_demand_hash(content),
            content=content,
            evaluated_at=NOW,
        )
    assert (rejected.value.status, rejected.value.code, rejected.value.path) == (
        422,
        "SYNTHETIC_DATA_REQUIRED",
        "/content",
    )


def test_profile_publish_rejects_evidence_or_ai_boundary_expansion() -> None:
    content = _safe_profile()
    content["interests"][0]["source_kind"] = "VERIFIED_EVIDENCE"
    content["interests"][0]["evidence_ids"] = ["synthetic_evidence_000001"]
    provider = InternalSandboxEditorEvidenceProvider(
        deployment_mode="INTERNAL_SANDBOX",
        demand_rule_catalog=_Rules(),
    )

    with pytest.raises(EditorServiceError) as rejected:
        provider.profile_hold(
            principal=_profile_principal(),
            action="PublishCreatorProfileVersion",
            profile_id=PROFILE,
            profile_version_no=1,
            taxonomy_bundle_id=TAXONOMY,
            prospective_aggregate_version=3,
            content_sha256=_profile_hash(content),
            content=content,
            evaluated_at=NOW,
        )
    assert (rejected.value.status, rejected.value.code) == (
        422,
        "SYNTHETIC_DATA_REQUIRED",
    )


def test_hold_requires_the_exact_prior_content_policy_fact() -> None:
    provider = InternalSandboxEditorEvidenceProvider(
        deployment_mode="INTERNAL_SANDBOX",
        demand_rule_catalog=_Rules(),
    )
    content = _safe_demand()
    content_hash = _demand_hash(content)
    policy = provider.demand_content_policy(
        principal=_demand_principal(),
        demand_id=DEMAND,
        demand_version_id=VERSION,
        demand_version_no=1,
        taxonomy_bundle_id=TAXONOMY,
        content_sha256=content_hash,
        content=content,
        evaluated_at=NOW,
    )
    with pytest.raises(EditorServiceError) as unavailable:
        provider.demand_hold(
            principal=_demand_principal(),
            demand_id=DEMAND,
            demand_version_id=VERSION,
            prospective_aggregate_version=4,
            content_sha256=hashlib.sha256(b"different-content").digest(),
            action="SUBMIT_DEMAND",
            content_policy=policy,
            evaluated_at=NOW,
        )
    assert (unavailable.value.status, unavailable.value.code) == (
        503,
        "EVIDENCE_CHAIN_UNAVAILABLE",
    )


def test_taxonomy_mismatch_and_non_sandbox_profile_fail_closed() -> None:
    with pytest.raises(ValueError, match="INTERNAL_SANDBOX"):
        InternalSandboxEditorEvidenceProvider(
            deployment_mode="PUBLIC",
            demand_rule_catalog=_Rules(),
        )
    provider = InternalSandboxEditorEvidenceProvider(
        deployment_mode="INTERNAL_SANDBOX",
        demand_rule_catalog=_Rules(
            taxonomy=UUID("50000000-0000-4000-8000-000000000099")
        ),
    )
    with pytest.raises(EditorServiceError) as mismatch:
        provider.demand_rules(
            principal=_demand_principal(),
            demand_id=DEMAND,
            taxonomy_bundle_id=TAXONOMY,
            operation="SUBMIT_DEMAND",
            evaluated_at=NOW,
        )
    assert (mismatch.value.status, mismatch.value.code) == (
        503,
        "RULE_REQUIREMENT_UNAVAILABLE",
    )


def test_managed_lifecycle_closes_the_catalog_but_never_exposes_content() -> None:
    rules = _Rules()
    provider = InternalSandboxEditorEvidenceProvider(
        deployment_mode="INTERNAL_SANDBOX",
        demand_rule_catalog=rules,
    )
    provider.check_readiness(timeout_ms=1_000)
    assert rules.readiness_calls == [1_000]
    assert "creator@example.com" not in repr(provider)
    provider.close()
    provider.close()
    assert rules.closed is True
    with pytest.raises(RuntimeError, match="EDITOR_EVIDENCE_NOT_READY"):
        provider.check_readiness(timeout_ms=1_000)
