"""Focused application boundary tests for the explicit SYSTEM workflow."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import UUID

import pytest

from desire_platform.demand.ports.commands import DemandHoldDecision, DemandSafetyHoldResult
from desire_platform.internal_pilot.matching_workflow import (
    MatchingSystemWorkflow, MatchingWorkflowError, MatchingWorkflowSnapshot,
    MatchingWorkflowTarget, SYSTEM_WORKLOAD_ID, _secret, main,
)


def _fixture():
    target = MatchingWorkflowTarget(UUID(int=1), UUID(int=2), 3, UUID(int=4))
    snapshot = MatchingWorkflowSnapshot(UUID(int=5), b"c" * 32, UUID(int=6), UUID(int=7))
    now = datetime.now(timezone.utc)
    rule = SimpleNamespace(**{name: str(UUID(int=index)) for index, name in enumerate((
        "taxonomy_bundle_id", "budget_rule_bundle_id", "risk_rule_bundle_id",
        "matching_rule_bundle_id", "reason_code_bundle_id", "composite_rule_requirement_id",
    ), 10)}, requirement_sha256="ab" * 32, effective_at=now - timedelta(days=1), effective_until=None)
    holds = Mock()
    holds.evaluate.side_effect = lambda **fields: DemandSafetyHoldResult(
        **fields, decision=DemandHoldDecision.ALLOW, evaluated_at=now, valid_until=now + timedelta(seconds=15)
    )
    writer = Mock()
    workflow = MatchingSystemWorkflow(
        targets=Mock(read=Mock(return_value=snapshot)), rules=Mock(current_requirement=Mock(return_value=rule)),
        holds=holds, writer=writer, idempotency_key=b"i" * 32, payload_key=b"p" * 32,
    )
    return target, snapshot, workflow, writer, holds


def test_closed_system_scope_carries_real_funding_causation_and_repeatable_receipt():
    target, snapshot, workflow, writer, holds = _fixture()
    workflow.request(target)
    first = writer.execute_request_matching_system.call_args.args[0]
    workflow.request(target)
    second = writer.execute_request_matching_system.call_args.args[0]
    assert first.scope.actor_kind == "SYSTEM"
    assert first.scope.actor_id == SYSTEM_WORKLOAD_ID
    assert first.scope.session_id is None and first.assignment_id is None
    assert first.scope.causation_id == snapshot.funding_source_event_id
    assert first.scope.original_actor_id == snapshot.original_actor_user_id
    assert first.content_policy is None and first.source_event is None
    assert first.scope == second.scope
    assert first.receipt.payload_hash == second.receipt.payload_hash
    assert first.matching_request_id == second.matching_request_id
    assert holds.evaluate.call_args.kwargs["prospective_aggregate_version"] == 4
    assert first.hold.content_sha256 == snapshot.content_sha256


def test_same_public_request_identity_with_changed_target_has_payload_conflict_material():
    target, _, workflow, writer, _ = _fixture()
    workflow.request(target)
    first = writer.execute_request_matching_system.call_args.args[0]
    workflow.request(replace(target, expected_version=5))
    second = writer.execute_request_matching_system.call_args.args[0]
    assert first.receipt.idempotency_key_digest == second.receipt.idempotency_key_digest
    assert first.receipt.payload_hash != second.receipt.payload_hash


def test_hold_block_does_not_invoke_writer():
    target, _, workflow, writer, holds = _fixture()
    allowed = holds.evaluate(**dict(actor_id=str(SYSTEM_WORKLOAD_ID), organization_id=str(target.organization_id),
        demand_id=str(target.demand_id), prospective_aggregate_version=4, demand_version_id=str(UUID(int=5)),
        content_sha256="cc" * 32, action="REQUEST_MATCHING", policy_version="demand-safety-hold-v1"))
    holds.evaluate.side_effect = None
    holds.evaluate.return_value = replace(allowed, decision=DemandHoldDecision.BLOCK)
    with pytest.raises(MatchingWorkflowError, match="SAFETY_HOLD_BLOCKED"):
        workflow.request(target)
    writer.execute_request_matching_system.assert_not_called()


def test_mismatched_hold_evidence_cannot_become_system_command():
    target, _, workflow, writer, holds = _fixture()
    original = holds.evaluate.side_effect
    holds.evaluate.side_effect = lambda **fields: replace(original(**fields), demand_id=str(UUID(int=987)))
    with pytest.raises(ValueError):
        workflow.request(target)
    writer.execute_request_matching_system.assert_not_called()


def test_secret_symlink_and_group_readable_files_are_rejected(tmp_path):
    original = tmp_path / "original"
    original.write_bytes(b"never-print-this-secret" * 2)
    original.chmod(0o600)
    (tmp_path / "link").symlink_to(original)
    with pytest.raises(MatchingWorkflowError):
        _secret(tmp_path, "link")
    original.chmod(0o640)
    with pytest.raises(MatchingWorkflowError):
        _secret(tmp_path, "original")


def test_cli_failure_is_sanitized(capsys, tmp_path):
    code = main(["--organization-id", str(UUID(int=1)), "--demand-id", str(UUID(int=2)),
        "--expected-version", "1", "--request-id", str(UUID(int=3)), "--database", "desire_local",
        "--credential-directory", str(tmp_path)])
    output = capsys.readouterr().out
    assert code == 1
    assert str(tmp_path) not in output
    assert "FAILED" in output
