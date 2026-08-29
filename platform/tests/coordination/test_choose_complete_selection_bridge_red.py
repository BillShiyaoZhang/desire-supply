"""Memory composition proof from the real Choose producer to its coordinator.

This is not a PostgreSQL or production binding.  The adapter below only makes
the already-closed producer facts explicit so the cross-context protocol can
be exercised end to end without inventing missing evidence.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
import unittest

from desire_platform.coordination import (
    AttemptSelectionFact,
    CandidateSelectorAuthorityFact,
    CompleteSelectionActor,
    CompleteSelectionCoordinator,
    CompleteSelectionError,
    DemandSelectionFact,
    InvitationSelectionFact,
    RunSelectionFact,
    SelectionSelectionFact,
    SystemCoordinatorAuthorityFact,
)
from desire_platform.matching.application import (
    ChooseCreatorHandler,
    MatchingActorKind,
)
from desire_platform.matching.domain import (
    Invitation,
    MatchCandidate,
    MatchRun,
    MatchingAttempt,
    Selection,
)
from tests.coordination.test_complete_selection_producer_contract_integration_red import (
    _closed_trigger_from_committed_matching_facts,
)
from tests.coordination.test_complete_selection_red import (
    ConcurrentIdSource,
    FixedClock,
    MemoryUowFactory,
    RecoveryReader,
)
from tests.support.matching_builders import (
    NOW,
    actor,
    build_application_harness,
    command_for,
)


SYSTEM_ACTOR = "system_actor_0000000001"
SYSTEM_CREDENTIAL = "workload_secret_complete_selection_0001"


def _composition_seed(matching_snapshot, owner, selector_authority):
    adapted = _closed_trigger_from_committed_matching_facts(matching_snapshot)
    receipt = adapted.receipt
    intent = adapted.intent
    source_trigger = matching_snapshot["pending_complete_selection_triggers"][
        receipt.receipt_id
    ]
    attempt = matching_snapshot["attempts"][receipt.attempt_id]
    selection = matching_snapshot["selections"][receipt.selection_id]
    invitation = matching_snapshot["invitations"][receipt.invitation_id]
    run = matching_snapshot["runs"][receipt.run_id]
    candidate = matching_snapshot["candidates"][
        f"{receipt.run_id}:{invitation.creator_user_id}"
    ]
    if not all(
        (
            isinstance(attempt, MatchingAttempt),
            isinstance(selection, Selection),
            isinstance(invitation, Invitation),
            isinstance(run, MatchRun),
            isinstance(candidate, MatchCandidate),
        )
    ):
        raise AssertionError("closed Matching projection unavailable")
    organization_id = receipt.organization_id
    assignment = selector_authority.assignment
    return adapted, {
        "system_authorities": {
            SYSTEM_ACTOR: SystemCoordinatorAuthorityFact(
                actor_id=SYSTEM_ACTOR,
                workload_credential_id=SYSTEM_CREDENTIAL,
                operation="COMPLETE_SELECTION",
                organization_id=organization_id,
                selection_id=receipt.selection_id,
                attempt_id=receipt.attempt_id,
                status="ACTIVE",
                valid_until=NOW + timedelta(minutes=5),
            )
        },
        "candidate_selector_authorities": {
            assignment.assignment_id: CandidateSelectorAuthorityFact(
                assignment_id=assignment.assignment_id,
                aggregate_version=assignment.aggregate_version,
                status=assignment.status.value,
                role_code=assignment.role_code.value,
                assigned_user_id=assignment.assigned_user_id,
                organization_id=organization_id,
                demand_id=receipt.demand_id,
                selection_id=receipt.selection_id,
                authority_marker_sha256=(
                    selector_authority.authority_marker_sha256
                ),
                assigned_at=assignment.assigned_at,
                expires_at=assignment.expires_at,
            )
        },
        "choose_receipts": {receipt.receipt_id: receipt},
        "selection_intents": {receipt.selection_id: intent},
        "pending_complete_selection_triggers": {
            receipt.receipt_id: source_trigger
        },
        "selections": {
            receipt.selection_id: SelectionSelectionFact(
                selection_id=selection.selection_id,
                organization_id=organization_id,
                attempt_id=selection.attempt_id,
                status=selection.status.value,
                aggregate_version=selection.aggregate_version,
                current_invitation_set_sha256=(
                    selection.current_invitation_set_sha256
                ),
                chosen_invitation_id=selection.chosen_invitation_id,
                selection_basis_code=selection.selection_basis_code,
                decision_actor_id=selection.decision_actor_id,
                updated_at=selection.updated_at,
            )
        },
        "attempts": {
            receipt.attempt_id: AttemptSelectionFact(
                attempt_id=attempt.attempt_id,
                organization_id=attempt.organization_id,
                demand_id=attempt.demand_id,
                demand_version_id=attempt.demand_version_id,
                matching_request_id=attempt.matching_request_id,
                matching_request_version=receipt.matching_request_version,
                funding_id=attempt.funding_id,
                status=attempt.status.value,
                aggregate_version=attempt.aggregate_version,
                current_run_id=attempt.current_match_run_id or "",
                selection_id=attempt.selection_id or "",
                updated_at=attempt.updated_at,
            )
        },
        "invitations": {
            receipt.invitation_id: InvitationSelectionFact(
                invitation_id=invitation.invitation_id,
                organization_id=organization_id,
                attempt_id=invitation.attempt_id,
                run_id=invitation.match_run_id,
                creator_user_id=invitation.creator_user_id,
                demand_id=invitation.demand_id,
                demand_version_id=invitation.demand_version_id,
                funding_id=invitation.funding_id,
                matching_rule_bundle_id=invitation.matching_rule_bundle_id,
                candidate_result_sha256=candidate.candidate_result_sha256,
                snapshot_sha256=invitation.snapshot_sha256,
                status=invitation.status.value,
                aggregate_version=invitation.aggregate_version,
            )
        },
        "runs": {
            receipt.run_id: RunSelectionFact(
                run_id=run.run_id,
                attempt_id=run.attempt_id,
                status=run.status.value,
                aggregate_version=run.aggregate_version,
                superseded_by_run_id=run.superseded_by_run_id,
                matching_rule_bundle_id=run.matching_rule_bundle_id,
                rule_manifest_sha256=receipt.rule_manifest_sha256,
                input_set_sha256=receipt.input_set_sha256,
                ordered_result_sha256=receipt.ordered_result_sha256,
            )
        },
        "demands": {
            receipt.demand_id: DemandSelectionFact(
                demand_id=receipt.demand_id,
                organization_id=organization_id,
                demand_version_id=receipt.demand_version_id,
                status="MATCHING",
                aggregate_version=receipt.expected_demand_version,
                funding_id=receipt.funding_id,
                funding_status="SECURED",
                matching_request_id=receipt.matching_request_id,
                matching_request_version=receipt.matching_request_version,
                updated_at=NOW,
            )
        },
    }


class ChooseCompleteSelectionBridgeRedTests(unittest.TestCase):
    def test_real_choose_trigger_completes_once_and_both_replays_converge(self):
        choose_command = command_for(ChooseCreatorHandler)
        choose_harness = build_application_harness(
            ChooseCreatorHandler, choose_command
        )
        owner = actor(kind=MatchingActorKind.USER)
        choose_handler = ChooseCreatorHandler(**choose_harness.dependencies)
        first_choose = choose_handler.handle(actor=owner, command=choose_command)
        adapted, state = _composition_seed(
            choose_harness.uow_factory.store.snapshot(),
            owner,
            choose_harness.dependencies["candidate_selector_authority"].result,
        )
        factory = MemoryUowFactory(state)
        coordinator = CompleteSelectionCoordinator(
            uow_factory=factory,
            recovery_reader=RecoveryReader(factory),
            clock=FixedClock(),
            id_source=ConcurrentIdSource(),
        )
        system = CompleteSelectionActor(
            actor_kind="SYSTEM",
            actor_id=SYSTEM_ACTOR,
            workload_credential_id=SYSTEM_CREDENTIAL,
            organization_id=owner.organization_id,
            original_actor_id=owner.actor_id,
            correlation_id=owner.correlation_id,
            causation_id=adapted.receipt.command_id,
            trace_id=owner.trace_id,
        )

        first_complete = coordinator.handle(
            actor=system, command=adapted.command
        )
        complete_snapshot = factory.store.snapshot()
        second_complete = coordinator.handle(
            actor=system, command=adapted.command
        )
        second_choose = choose_handler.handle(actor=owner, command=choose_command)

        self.assertFalse(first_choose.replayed)
        self.assertTrue(second_choose.replayed)
        self.assertFalse(first_complete.replayed)
        self.assertTrue(second_complete.replayed)
        self.assertEqual(factory.store.snapshot(), complete_snapshot)
        self.assertEqual(len(complete_snapshot["projects"]), 1)
        self.assertEqual(len(complete_snapshot["agreements"]), 1)
        self.assertEqual(complete_snapshot["selections"][adapted.command.selection_id].status, "SELECTED")
        self.assertEqual(
            (
                complete_snapshot["selections"][
                    adapted.command.selection_id
                ].candidate_selector_assignment_id,
                first_complete.candidate_selector_assignment_id,
            ),
            (choose_command.assignment_id, choose_command.assignment_id),
        )
        self.assertEqual(complete_snapshot["attempts"][adapted.command.attempt_id].status, "SELECTED")
        self.assertEqual(complete_snapshot["demands"][adapted.command.demand_id].status, "MATCHED")
        self.assertEqual(len(complete_snapshot["outbox"]), 5)

    def test_trigger_or_current_candidate_drift_is_atomic_rejection(self):
        choose_command = command_for(ChooseCreatorHandler)
        choose_harness = build_application_harness(
            ChooseCreatorHandler, choose_command
        )
        owner = actor(kind=MatchingActorKind.USER)
        ChooseCreatorHandler(**choose_harness.dependencies).handle(
            actor=owner, command=choose_command
        )
        adapted, state = _composition_seed(
            choose_harness.uow_factory.store.snapshot(),
            owner,
            choose_harness.dependencies["candidate_selector_authority"].result,
        )
        state["invitations"][adapted.command.invitation_id] = replace(
            state["invitations"][adapted.command.invitation_id],
            candidate_result_sha256="f" * 64,
        )
        before = deepcopy(state)
        factory = MemoryUowFactory(state)
        coordinator = CompleteSelectionCoordinator(
            uow_factory=factory,
            recovery_reader=RecoveryReader(factory),
            clock=FixedClock(),
            id_source=ConcurrentIdSource(),
        )
        system = CompleteSelectionActor(
            actor_kind="SYSTEM",
            actor_id=SYSTEM_ACTOR,
            workload_credential_id=SYSTEM_CREDENTIAL,
            organization_id=owner.organization_id,
            original_actor_id=owner.actor_id,
            correlation_id=owner.correlation_id,
            causation_id=adapted.receipt.command_id,
            trace_id=owner.trace_id,
        )

        with self.assertRaisesRegex(
            CompleteSelectionError, "SELECTION_NOT_READY"
        ):
            coordinator.handle(actor=system, command=adapted.command)
        self.assertEqual(factory.store.snapshot(), before)

    def test_real_choose_trigger_rejects_missing_stale_or_mismatched_selector(self):
        choose_command = command_for(ChooseCreatorHandler)
        choose_harness = build_application_harness(
            ChooseCreatorHandler, choose_command
        )
        selector = actor(kind=MatchingActorKind.USER)
        ChooseCreatorHandler(**choose_harness.dependencies).handle(
            actor=selector, command=choose_command
        )
        adapted, baseline = _composition_seed(
            choose_harness.uow_factory.store.snapshot(),
            selector,
            choose_harness.dependencies["candidate_selector_authority"].result,
        )
        assignment_id = adapted.command.candidate_selector_assignment_id
        mutations = (
            lambda state: state["candidate_selector_authorities"].clear(),
            lambda state: state["candidate_selector_authorities"].update(
                {
                    assignment_id: replace(
                        state["candidate_selector_authorities"][assignment_id],
                        aggregate_version=(
                            adapted.command.expected_candidate_selector_assignment_version
                            + 1
                        ),
                    )
                }
            ),
            lambda state: state["candidate_selector_authorities"].update(
                {
                    assignment_id: replace(
                        state["candidate_selector_authorities"][assignment_id],
                        selection_id="other_selection_0001",
                    )
                }
            ),
            lambda state: state["candidate_selector_authorities"].update(
                {
                    assignment_id: replace(
                        state["candidate_selector_authorities"][assignment_id],
                        status="REVOKED",
                    )
                }
            ),
        )
        system = CompleteSelectionActor(
            actor_kind="SYSTEM",
            actor_id=SYSTEM_ACTOR,
            workload_credential_id=SYSTEM_CREDENTIAL,
            organization_id=selector.organization_id,
            original_actor_id=selector.actor_id,
            correlation_id=selector.correlation_id,
            causation_id=adapted.receipt.command_id,
            trace_id=selector.trace_id,
        )

        for mutation in mutations:
            with self.subTest(mutation=mutation):
                state = deepcopy(baseline)
                mutation(state)
                factory = MemoryUowFactory(state)
                before = factory.store.snapshot()
                coordinator = CompleteSelectionCoordinator(
                    uow_factory=factory,
                    recovery_reader=RecoveryReader(factory),
                    clock=FixedClock(),
                    id_source=ConcurrentIdSource(),
                )

                with self.assertRaisesRegex(
                    CompleteSelectionError, "ACCESS_DENIED"
                ):
                    coordinator.handle(actor=system, command=adapted.command)
                self.assertEqual(factory.store.snapshot(), before)


if __name__ == "__main__":
    unittest.main()
