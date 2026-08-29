"""RED integration contract between ChooseCreator and CompleteSelection.

This test intentionally uses only facts durably committed by the real
``ChooseCreatorHandler``.  It must not invent a command id, hold result,
version, or matching evidence when the producer has not persisted one.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields, is_dataclass
from typing import Any, Mapping, Sequence
import unittest

from desire_platform.coordination import (
    COMPLETE_SELECTION_TRIGGER_PRODUCER_COMPATIBLE,
    AttemptSelectionFact,
    ChooseReceiptFact,
    CompleteSelectionCommand,
    InvitationSelectionFact,
    RunSelectionFact,
    SelectionHoldBinding,
    SelectionIntentFact,
    SelectionSelectionFact,
)
from desire_platform.matching.application import (
    ChooseCreatorHandler,
    MatchingActorKind,
)
from tests.support.matching_builders import (
    actor,
    build_application_harness,
    command_for,
)


_UNAVAILABLE = "COMPLETE_SELECTION_TRIGGER_PRODUCER_CONTRACT_UNAVAILABLE"


class _ProducerContractUnavailable(RuntimeError):
    """Test oracle for a closed, value-redacted producer-contract failure."""

    def __init__(self, missing_fields: Sequence[str]) -> None:
        self.code = _UNAVAILABLE
        self.missing_fields = tuple(sorted(set(missing_fields)))
        super().__init__(self.code)


@dataclass(frozen=True)
class _ClosedMatchingTrigger:
    command: CompleteSelectionCommand
    receipt: ChooseReceiptFact
    intent: SelectionIntentFact
    selection: SelectionSelectionFact
    attempt: AttemptSelectionFact
    invitation: InvitationSelectionFact
    run: RunSelectionFact


def _as_mapping(value: Any, *, path: str, missing: list[str]) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if is_dataclass(value):
        converted = asdict(value)
        if isinstance(converted, Mapping):
            return converted
    missing.append(path)
    return {}


def _required(
    source: Mapping[str, Any],
    key: str,
    *,
    path: str,
    missing: list[str],
) -> Any:
    value = source.get(key)
    if value is None:
        missing.append(f"{path}.{key}")
    return value


def _single(
    values: Sequence[Any], *, path: str, missing: list[str]
) -> Any:
    if len(values) != 1:
        missing.append(path)
        return None
    return values[0]


def _closed_trigger_from_committed_matching_facts(
    snapshot: Mapping[str, Mapping[str, Any]],
) -> _ClosedMatchingTrigger:
    """Strictly adapt durable Matching facts or fail without fallback values."""

    missing: list[str] = []
    security_receipts = tuple(
        item
        for item in snapshot.get("receipts", {}).values()
        if isinstance(item, Mapping)
        and item.get("operation") == "CHOOSE_CREATOR"
        and item.get("status") == "COMPLETED"
    )
    producer_receipts = tuple(snapshot.get("choose_receipts", {}).values())
    triggers = tuple(
        snapshot.get("pending_complete_selection_triggers", {}).values()
    )
    intents = tuple(snapshot.get("selection_intents", {}).values())
    intent_events = tuple(
        item
        for item in snapshot.get("outbox", {}).values()
        if isinstance(item, Mapping)
        and item.get("event_type") == "SelectionIntentRecorded"
    )
    _single(
        security_receipts,
        path="security_receipt.single_completed_choose",
        missing=missing,
    )
    receipt_value = _single(
        producer_receipts,
        path="choose_receipt.single_completed_choose",
        missing=missing,
    )
    intent_value = _single(
        intents, path="selection_intent.single_completed", missing=missing
    )
    event_value = _single(
        intent_events, path="outbox.single_selection_intent_event", missing=missing
    )
    trigger_value = _single(
        triggers, path="completion_trigger.single_ready", missing=missing
    )
    receipt = _as_mapping(receipt_value, path="receipt.closed_shape", missing=missing)
    intent = _as_mapping(
        intent_value, path="selection_intent.closed_shape", missing=missing
    )
    event = _as_mapping(event_value, path="outbox.closed_shape", missing=missing)
    trigger = _as_mapping(
        trigger_value, path="completion_trigger.closed_shape", missing=missing
    )
    payload = _as_mapping(
        event.get("payload"), path="outbox.payload.closed_shape", missing=missing
    )

    selection_id = intent.get("selection_id") or payload.get("selection_id")
    invitation_id = intent.get("invitation_id") or payload.get(
        "chosen_invitation_id"
    )
    attempt_id = intent.get("attempt_id") or payload.get("attempt_id")
    selection_value = snapshot.get("selections", {}).get(selection_id)
    invitation_value = snapshot.get("invitations", {}).get(invitation_id)
    selection_source = _as_mapping(
        selection_value, path="matching_selection.closed_shape", missing=missing
    )
    invitation_source = _as_mapping(
        invitation_value, path="matching_invitation.closed_shape", missing=missing
    )
    run_id = intent.get("run_id") or invitation_source.get("match_run_id")
    run_value = snapshot.get("runs", {}).get(run_id)
    attempt_value = snapshot.get("attempts", {}).get(attempt_id)
    run_source = _as_mapping(
        run_value, path="match_run.closed_shape", missing=missing
    )
    attempt_source = _as_mapping(
        attempt_value, path="matching_attempt.closed_shape", missing=missing
    )
    candidates = tuple(
        item
        for item in snapshot.get("candidates", {}).values()
        if getattr(item, "run_id", None) == run_id
        and getattr(item, "creator_user_id", None)
        == invitation_source.get("creator_user_id")
    )
    candidate_value = _single(
        candidates, path="match_candidate.single_chosen", missing=missing
    )
    candidate_source = _as_mapping(
        candidate_value, path="match_candidate.closed_shape", missing=missing
    )
    manifest = _as_mapping(
        run_source.get("input_manifest"),
        path="match_run.input_manifest.closed_shape",
        missing=missing,
    )

    # These exact facts must be bound by the completed receipt.  Recovering
    # their current values from aggregates would not prove what Choose accepted.
    receipt_values = {
        field.name: _required(
            receipt, field.name, path="receipt", missing=missing
        )
        for field in fields(ChooseReceiptFact)
    }
    intent_values = {
        field.name: _required(
            intent, field.name, path="selection_intent", missing=missing
        )
        for field in fields(SelectionIntentFact)
        if field.name != "hold_binding"
    }
    hold_source = _as_mapping(
        intent.get("hold_binding"),
        path="selection_intent.hold_binding.closed_shape",
        missing=missing,
    )
    hold_values = {
        field.name: _required(
            hold_source,
            field.name,
            path="selection_intent.hold_binding",
            missing=missing,
        )
        for field in fields(SelectionHoldBinding)
    }

    organization_id = _required(
        event, "organization_id", path="outbox", missing=missing
    )
    selection_values = {
        "selection_id": _required(
            selection_source,
            "selection_id",
            path="matching_selection",
            missing=missing,
        ),
        "organization_id": organization_id,
        "attempt_id": _required(
            selection_source,
            "attempt_id",
            path="matching_selection",
            missing=missing,
        ),
        "status": getattr(selection_source.get("status"), "value", None),
        "aggregate_version": _required(
            selection_source,
            "aggregate_version",
            path="matching_selection",
            missing=missing,
        ),
        "current_invitation_set_sha256": _required(
            selection_source,
            "current_invitation_set_sha256",
            path="matching_selection",
            missing=missing,
        ),
        "chosen_invitation_id": selection_source.get("chosen_invitation_id"),
        "selection_basis_code": selection_source.get("selection_basis_code"),
        "decision_actor_id": selection_source.get("decision_actor_id"),
        "updated_at": _required(
            selection_source,
            "updated_at",
            path="matching_selection",
            missing=missing,
        ),
    }
    attempt_values = {
        "attempt_id": _required(
            attempt_source, "attempt_id", path="matching_attempt", missing=missing
        ),
        "organization_id": _required(
            attempt_source,
            "organization_id",
            path="matching_attempt",
            missing=missing,
        ),
        "demand_id": _required(
            attempt_source, "demand_id", path="matching_attempt", missing=missing
        ),
        "demand_version_id": _required(
            attempt_source,
            "demand_version_id",
            path="matching_attempt",
            missing=missing,
        ),
        "matching_request_id": _required(
            attempt_source,
            "matching_request_id",
            path="matching_attempt",
            missing=missing,
        ),
        "matching_request_version": receipt.get("matching_request_version"),
        "funding_id": _required(
            attempt_source, "funding_id", path="matching_attempt", missing=missing
        ),
        "status": getattr(attempt_source.get("status"), "value", None),
        "aggregate_version": _required(
            attempt_source,
            "aggregate_version",
            path="matching_attempt",
            missing=missing,
        ),
        "current_run_id": _required(
            attempt_source,
            "current_match_run_id",
            path="matching_attempt",
            missing=missing,
        ),
        "selection_id": _required(
            attempt_source,
            "selection_id",
            path="matching_attempt",
            missing=missing,
        ),
        "updated_at": _required(
            attempt_source,
            "updated_at",
            path="matching_attempt",
            missing=missing,
        ),
    }
    invitation_values = {
        "invitation_id": _required(
            invitation_source,
            "invitation_id",
            path="matching_invitation",
            missing=missing,
        ),
        "organization_id": organization_id,
        "attempt_id": _required(
            invitation_source,
            "attempt_id",
            path="matching_invitation",
            missing=missing,
        ),
        "run_id": _required(
            invitation_source,
            "match_run_id",
            path="matching_invitation",
            missing=missing,
        ),
        "creator_user_id": _required(
            invitation_source,
            "creator_user_id",
            path="matching_invitation",
            missing=missing,
        ),
        "demand_id": _required(
            invitation_source,
            "demand_id",
            path="matching_invitation",
            missing=missing,
        ),
        "demand_version_id": _required(
            invitation_source,
            "demand_version_id",
            path="matching_invitation",
            missing=missing,
        ),
        "funding_id": _required(
            invitation_source,
            "funding_id",
            path="matching_invitation",
            missing=missing,
        ),
        "matching_rule_bundle_id": _required(
            invitation_source,
            "matching_rule_bundle_id",
            path="matching_invitation",
            missing=missing,
        ),
        "candidate_result_sha256": _required(
            candidate_source,
            "candidate_result_sha256",
            path="match_candidate",
            missing=missing,
        ),
        "snapshot_sha256": _required(
            invitation_source,
            "snapshot_sha256",
            path="matching_invitation",
            missing=missing,
        ),
        "status": getattr(invitation_source.get("status"), "value", None),
        "aggregate_version": _required(
            invitation_source,
            "aggregate_version",
            path="matching_invitation",
            missing=missing,
        ),
    }
    run_values = {
        "run_id": _required(
            run_source, "run_id", path="match_run", missing=missing
        ),
        "attempt_id": _required(
            run_source, "attempt_id", path="match_run", missing=missing
        ),
        "status": getattr(run_source.get("status"), "value", None),
        "aggregate_version": _required(
            run_source, "aggregate_version", path="match_run", missing=missing
        ),
        "superseded_by_run_id": run_source.get("superseded_by_run_id"),
        "matching_rule_bundle_id": _required(
            run_source,
            "matching_rule_bundle_id",
            path="match_run",
            missing=missing,
        ),
        "rule_manifest_sha256": _required(
            manifest,
            "rule_manifest_sha256",
            path="match_run.input_manifest",
            missing=missing,
        ),
        "input_set_sha256": _required(
            run_source,
            "input_set_sha256",
            path="match_run",
            missing=missing,
        ),
        "ordered_result_sha256": _required(
            run_source,
            "ordered_result_sha256",
            path="match_run",
            missing=missing,
        ),
    }
    if missing:
        raise _ProducerContractUnavailable(missing)

    hold = SelectionHoldBinding(**hold_values)
    intent_values["hold_binding"] = hold
    closed_receipt = ChooseReceiptFact(**receipt_values)
    closed_intent = SelectionIntentFact(**intent_values)
    complete_command = CompleteSelectionCommand(
        completion_command_id=_required(
            trigger,
            "completion_command_id",
            path="completion_trigger",
            missing=missing,
        ),
        choose_receipt_id=closed_receipt.receipt_id,
        choose_command_id=closed_receipt.command_id,
        selection_id=closed_receipt.selection_id,
        expected_selection_version=closed_receipt.expected_selection_version,
        attempt_id=closed_receipt.attempt_id,
        expected_attempt_version=closed_receipt.expected_attempt_version,
        invitation_id=closed_receipt.invitation_id,
        run_id=closed_receipt.run_id,
        demand_id=closed_receipt.demand_id,
        expected_demand_version=closed_receipt.expected_demand_version,
        demand_version_id=closed_receipt.demand_version_id,
        matching_request_id=closed_receipt.matching_request_id,
        matching_request_version=closed_receipt.matching_request_version,
        funding_id=closed_receipt.funding_id,
        candidate_selector_assignment_id=(
            closed_receipt.candidate_selector_assignment_id
        ),
        expected_candidate_selector_assignment_version=(
            closed_receipt.candidate_selector_assignment_version
        ),
    )
    return _ClosedMatchingTrigger(
        command=complete_command,
        receipt=closed_receipt,
        intent=closed_intent,
        selection=SelectionSelectionFact(**selection_values),
        attempt=AttemptSelectionFact(**attempt_values),
        invitation=InvitationSelectionFact(**invitation_values),
        run=RunSelectionFact(**run_values),
    )


class CompleteSelectionProducerContractIntegrationRedTests(unittest.TestCase):
    def test_choose_creator_commits_closed_complete_selection_trigger_contract(
        self,
    ) -> None:
        command = command_for(ChooseCreatorHandler)
        harness = build_application_harness(ChooseCreatorHandler, command)
        owner = actor(kind=MatchingActorKind.USER)
        result = ChooseCreatorHandler(**harness.dependencies).handle(
            actor=owner,
            command=command,
        )
        self.assertEqual(result.event_types, ("SelectionIntentRecorded",))
        committed = harness.uow_factory.store.snapshot()

        try:
            trigger = _closed_trigger_from_committed_matching_facts(committed)
        except _ProducerContractUnavailable as error:
            self.assertFalse(COMPLETE_SELECTION_TRIGGER_PRODUCER_COMPATIBLE)
            self.assertEqual(str(error), _UNAVAILABLE)
            self.assertNotIn(command.idempotency_key, f"{error!r} {error}")
            if owner.session_id is not None:
                self.assertNotIn(owner.session_id, f"{error!r} {error}")
            self.fail(
                f"{error.code}: missing closed durable fields "
                + ", ".join(error.missing_fields)
            )

        self.assertTrue(COMPLETE_SELECTION_TRIGGER_PRODUCER_COMPATIBLE)
        self.assertEqual(trigger.receipt.selection_id, trigger.command.selection_id)
        self.assertEqual(trigger.intent.receipt_id, trigger.receipt.receipt_id)
        self.assertEqual(trigger.invitation.run_id, trigger.run.run_id)
        self.assertEqual(trigger.attempt.current_run_id, trigger.run.run_id)
        self.assertEqual(
            (
                trigger.command.candidate_selector_assignment_id,
                trigger.command.expected_candidate_selector_assignment_version,
            ),
            (
                command.assignment_id,
                command.expected_assignment_version,
            ),
        )
        self.assertEqual(
            (
                trigger.receipt.candidate_selector_assignment_id,
                trigger.receipt.candidate_selector_assignment_version,
                trigger.intent.hold_binding.candidate_selector_assignment_id,
                trigger.intent.hold_binding.candidate_selector_assignment_version,
            ),
            (
                command.assignment_id,
                command.expected_assignment_version,
                command.assignment_id,
                command.expected_assignment_version,
            ),
        )


if __name__ == "__main__":
    unittest.main()
