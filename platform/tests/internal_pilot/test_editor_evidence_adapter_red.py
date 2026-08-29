"""TDD contract for closed domain-port to PostgreSQL evidence conversion."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
from uuid import UUID

import pytest

from desire_platform.creator_profile.ports.commands import (
    CreatorProfileHoldDecision,
    CreatorProfileSafetyHoldResult,
)
from desire_platform.demand.ports.commands import (
    DemandContentPolicyDecision,
    DemandContentPolicyResult,
    DemandHoldDecision,
    DemandRuleRequirement,
    DemandSafetyHoldResult,
)
from desire_platform.internal_pilot.editor import EditorPrincipal, EditorServiceError
from desire_platform.internal_pilot.editor.evidence import (
    PortBackedEditorEvidenceProvider,
)


NOW = datetime(2026, 8, 12, 12, 0, tzinfo=timezone.utc)
ACTOR = "10000000-0000-4000-8000-000000000001"
SESSION = "20000000-0000-4000-8000-000000000001"
ORG = "81000000-0000-4000-8000-000000000001"
PROFILE = UUID("31000000-0000-4000-8000-000000000001")
DEMAND = UUID("41000000-0000-4000-8000-000000000001")
VERSION = UUID("42000000-0000-4000-8000-000000000001")
TAXONOMY_ID = "50000000-0000-4000-8000-000000000001"
CONTENT_HASH = hashlib.sha256(b"closed synthetic content").digest()


class _ProfileHold:
    def __init__(self) -> None:
        self.calls = []

    def evaluate(self, **query):
        self.calls.append(query)
        return CreatorProfileSafetyHoldResult(
            decision=CreatorProfileHoldDecision.ALLOW,
            profile_id=query["profile_id"],
            prospective_aggregate_version=query["prospective_aggregate_version"],
            content_sha256=query["content_sha256"],
            actor_user_id=query["actor_user_id"],
            policy_version=query["policy_version"],
            evaluated_at=NOW - timedelta(seconds=1),
            valid_until=NOW + timedelta(minutes=5),
        )


class _ContentPolicy:
    def __init__(self) -> None:
        self.calls = []

    def evaluate(self, **query):
        self.calls.append(query)
        return DemandContentPolicyResult(
            decision=DemandContentPolicyDecision.ALLOW,
            demand_id=query["demand_id"],
            demand_version_id=query["demand_version_id"],
            content_sha256=query["content_sha256"],
            policy_version=query["policy_version"],
            result_sha256=hashlib.sha256(b"content-policy-result").hexdigest(),
            evaluated_at=NOW - timedelta(seconds=1),
            valid_until=NOW + timedelta(minutes=5),
        )


class _DemandHold:
    def __init__(self) -> None:
        self.calls = []

    def evaluate(self, **query):
        self.calls.append(query)
        return DemandSafetyHoldResult(
            decision=DemandHoldDecision.ALLOW,
            actor_id=query["actor_id"],
            organization_id=query["organization_id"],
            demand_id=query["demand_id"],
            prospective_aggregate_version=query["prospective_aggregate_version"],
            demand_version_id=query["demand_version_id"],
            content_sha256=query["content_sha256"],
            action=query["action"],
            policy_version=query["policy_version"],
            evaluated_at=NOW - timedelta(seconds=1),
            valid_until=NOW + timedelta(minutes=5),
        )


class _Rules:
    def __init__(self) -> None:
        self.calls = []

    def current_requirement(self, **query):
        self.calls.append(query)
        return DemandRuleRequirement(
            taxonomy_bundle_id=TAXONOMY_ID,
            budget_rule_bundle_id="50000000-0000-4000-8000-000000000002",
            risk_rule_bundle_id="50000000-0000-4000-8000-000000000003",
            matching_rule_bundle_id="50000000-0000-4000-8000-000000000004",
            reason_code_bundle_id="50000000-0000-4000-8000-000000000005",
            composite_rule_requirement_id="50000000-0000-4000-8000-000000000006",
            effective_at=NOW - timedelta(days=1),
            effective_until=NOW + timedelta(days=1),
            requirement_sha256=hashlib.sha256(b"rule-requirement").hexdigest(),
        )


def _principal() -> EditorPrincipal:
    return EditorPrincipal(
        user_id=ACTOR,
        session_id=SESSION,
        organization_id=ORG,
        role_codes=("DEMAND_OWNER",),
    )


def _provider():
    profile, content, hold, rules = (
        _ProfileHold(),
        _ContentPolicy(),
        _DemandHold(),
        _Rules(),
    )
    return (
        PortBackedEditorEvidenceProvider(
            profile_safety_hold=profile,
            demand_content_policy=content,
            demand_safety_hold=hold,
            demand_rule_catalog=rules,
        ),
        profile,
        content,
        hold,
        rules,
    )


def test_exact_profile_and_demand_facts_are_forwarded_and_converted() -> None:
    provider, profile, content_policy, demand_hold, rules = _provider()
    principal = _principal()
    profile_result = provider.profile_hold(
        principal=principal,
        action="PublishCreatorProfileVersion",
        profile_id=PROFILE,
        profile_version_no=1,
        taxonomy_bundle_id=UUID(TAXONOMY_ID),
        prospective_aggregate_version=4,
        content_sha256=CONTENT_HASH,
        content={"interests": [], "skills": []},
        evaluated_at=NOW,
    )
    demand_content = {"problem": {"background": "synthetic"}}
    policy_result = provider.demand_content_policy(
        principal=principal,
        demand_id=DEMAND,
        demand_version_id=VERSION,
        demand_version_no=1,
        taxonomy_bundle_id=UUID(TAXONOMY_ID),
        content_sha256=CONTENT_HASH,
        content=demand_content,
        evaluated_at=NOW,
    )
    hold_result = provider.demand_hold(
        principal=principal,
        demand_id=DEMAND,
        demand_version_id=VERSION,
        prospective_aggregate_version=5,
        content_sha256=CONTENT_HASH,
        action="SUBMIT_DEMAND",
        content_policy=policy_result,
        evaluated_at=NOW,
    )
    rule_result = provider.demand_rules(
        principal=principal,
        demand_id=DEMAND,
        taxonomy_bundle_id=UUID(TAXONOMY_ID),
        operation="SUBMIT_DEMAND",
        evaluated_at=NOW,
    )

    assert profile_result.content_sha256 == policy_result.content_sha256 == CONTENT_HASH
    assert hold_result.content_sha256 == CONTENT_HASH
    assert rule_result.requirement_sha256 == hashlib.sha256(
        b"rule-requirement"
    ).digest()
    assert profile.calls == [
        {
            "actor_user_id": ACTOR,
            "action": "PublishCreatorProfileVersion",
            "profile_id": str(PROFILE),
            "prospective_aggregate_version": 4,
            "content_sha256": CONTENT_HASH.hex(),
            "policy_version": "creator-profile-hold-v1",
        }
    ]
    assert content_policy.calls[0]["content"] is demand_content
    assert demand_hold.calls[0]["organization_id"] == ORG
    assert rules.calls == [
        {
            "organization_id": ORG,
            "demand_id": str(DEMAND),
            "operation": "SUBMIT_DEMAND",
        }
    ]


def test_profile_resume_hold_uses_the_exact_action_and_unknown_actions_fail_closed() -> None:
    provider, profile, _content, _hold, _rules = _provider()
    provider.profile_hold(
        principal=_principal(),
        action="ResumeCreatorProfile",
        profile_id=PROFILE,
        profile_version_no=1,
        taxonomy_bundle_id=UUID(TAXONOMY_ID),
        prospective_aggregate_version=5,
        content_sha256=CONTENT_HASH,
        content={"interests": [], "skills": []},
        evaluated_at=NOW,
    )
    assert profile.calls[0]["action"] == "ResumeCreatorProfile"
    with pytest.raises(EditorServiceError) as rejected:
        provider.profile_hold(
            principal=_principal(),
            action="PauseCreatorProfile",
            profile_id=PROFILE,
            profile_version_no=1,
            taxonomy_bundle_id=UUID(TAXONOMY_ID),
            prospective_aggregate_version=6,
            content_sha256=CONTENT_HASH,
            content={"interests": [], "skills": []},
            evaluated_at=NOW,
        )
    assert (rejected.value.status, rejected.value.code) == (
        503,
        "SERVICE_UNAVAILABLE",
    )
    assert len(profile.calls) == 1


@pytest.mark.parametrize(
    ("which", "expected_status", "expected_code"),
    (
        ("profile", 403, "SAFETY_HOLD_BLOCKED"),
        ("content", 422, "DEMAND_VALIDATION_FAILED"),
        ("hold", 403, "SAFETY_HOLD_BLOCKED"),
    ),
)
def test_explicit_blocks_are_not_collapsed_into_dependency_failure(
    which: str, expected_status: int, expected_code: str
) -> None:
    provider, profile, content, hold, _rules = _provider()
    if which == "profile":
        original = profile.evaluate
        profile.evaluate = lambda **query: replace(
            original(**query), decision=CreatorProfileHoldDecision.BLOCK
        )
        call = lambda: provider.profile_hold(
            principal=_principal(),
            action="PublishCreatorProfileVersion",
            profile_id=PROFILE,
            profile_version_no=1,
            taxonomy_bundle_id=UUID(TAXONOMY_ID),
            prospective_aggregate_version=2,
            content_sha256=CONTENT_HASH,
            content={"interests": [], "skills": []},
            evaluated_at=NOW,
        )
    elif which == "content":
        original = content.evaluate
        content.evaluate = lambda **query: replace(
            original(**query), decision=DemandContentPolicyDecision.BLOCK
        )
        call = lambda: provider.demand_content_policy(
            principal=_principal(),
            demand_id=DEMAND,
            demand_version_id=VERSION,
            demand_version_no=1,
            taxonomy_bundle_id=UUID(TAXONOMY_ID),
            content_sha256=CONTENT_HASH,
            content={},
            evaluated_at=NOW,
        )
    else:
        original = hold.evaluate
        hold.evaluate = lambda **query: replace(
            original(**query), decision=DemandHoldDecision.BLOCK
        )
        policy = provider.demand_content_policy(
            principal=_principal(),
            demand_id=DEMAND,
            demand_version_id=VERSION,
            demand_version_no=1,
            taxonomy_bundle_id=UUID(TAXONOMY_ID),
            content_sha256=CONTENT_HASH,
            content={},
            evaluated_at=NOW,
        )
        call = lambda: provider.demand_hold(
            principal=_principal(),
            demand_id=DEMAND,
            demand_version_id=VERSION,
            prospective_aggregate_version=3,
            content_sha256=CONTENT_HASH,
            action="SUBMIT_DEMAND",
            content_policy=policy,
            evaluated_at=NOW,
        )
    with pytest.raises(EditorServiceError) as rejected:
        call()
    assert (rejected.value.status, rejected.value.code) == (
        expected_status,
        expected_code,
    )


def test_expired_mismatched_or_unavailable_evidence_fails_closed() -> None:
    provider, profile, _content, _hold, rules = _provider()
    original = profile.evaluate
    profile.evaluate = lambda **query: replace(
        original(**query), valid_until=NOW
    )
    with pytest.raises(EditorServiceError) as expired:
        provider.profile_hold(
            principal=_principal(),
            action="PublishCreatorProfileVersion",
            profile_id=PROFILE,
            profile_version_no=1,
            taxonomy_bundle_id=UUID(TAXONOMY_ID),
            prospective_aggregate_version=2,
            content_sha256=CONTENT_HASH,
            content={"interests": [], "skills": []},
            evaluated_at=NOW,
        )
    assert (expired.value.status, expired.value.code) == (503, "SERVICE_UNAVAILABLE")

    rules.current_requirement = lambda **_query: (_ for _ in ()).throw(
        RuntimeError("provider secret must not escape")
    )
    with pytest.raises(EditorServiceError) as unavailable:
        provider.demand_rules(
            principal=_principal(),
            demand_id=DEMAND,
            taxonomy_bundle_id=UUID(TAXONOMY_ID),
            operation="SUBMIT_DEMAND",
            evaluated_at=NOW,
        )
    assert (unavailable.value.status, unavailable.value.code) == (
        503,
        "SERVICE_UNAVAILABLE",
    )
    assert "secret" not in str(unavailable.value)
