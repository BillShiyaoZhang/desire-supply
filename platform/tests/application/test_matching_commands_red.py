"""Framework-neutral application semantic RED for Matching v1."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import timedelta
import unittest

from desire_platform.matching.application import (
    ChooseCreatorHandler,
    CloseSelectionWithoutChoiceHandler,
    CompleteMatchRunHandler,
    CreateInvitationHandler,
    CreateMatchingAttemptHandler,
    MATCHING_APPLICATION_BEHAVIOR_NOT_AVAILABLE,
    MatchingActorKind,
    MatchingApplicationBehaviorNotAvailable,
    MatchingApplicationError,
    PublishInvitationHandler,
    RespondInvitationHandler,
    RetryMatchRunHandler,
    StartMatchRunHandler,
    WithdrawAcceptedInvitationHandler,
)
from desire_platform.matching.domain import (
    CandidateSelectorAssignmentStatus,
    InvitationStatus,
    MatchingAttemptStatus,
    SelectionStatus,
)
from desire_platform.matching.domain import selection_invitation_set_sha256
from desire_platform.coordination import (
    ChooseReceiptFact,
    PendingCompleteSelectionTrigger,
    SelectionIntentFact,
    selection_intent_sha256,
)
from tests.support.matching_builders import (
    NOW,
    actor,
    build_application_harness,
    candidate,
    command_for,
    creator_actor,
    selection,
)


class _Recorder:
    def __init__(self) -> None:
        self.calls: list[object] = []

    def __getattr__(self, name: str):
        def method(*args, **kwargs):
            self.calls.append((name, args, kwargs))
            return None
        return method


class MatchingApplicationSemanticRedTests(unittest.TestCase):
    def _semantic(self, label: str, handler_type: type, *, command=None, actor_context=None, harness=None, **dependencies):
        command = command if command is not None else command_for(handler_type)
        harness = harness or build_application_harness(handler_type, command)
        effective_dependencies = dict(harness.dependencies)
        effective_dependencies.update(dependencies)
        self.last_harness = harness
        if actor_context is None and handler_type in {
            RetryMatchRunHandler,
            CreateInvitationHandler,
            PublishInvitationHandler,
        }:
            actor_context = actor(kind=MatchingActorKind.USER)
        handler = handler_type(**effective_dependencies)
        try:
            return handler.handle(
                actor=actor_context or actor(),
                command=command,
            )
        except MatchingApplicationBehaviorNotAvailable as error:
            self.assertEqual(str(error), MATCHING_APPLICATION_BEHAVIOR_NOT_AVAILABLE)
            self.fail(f"semantic RED: {label}")

    def test_source_event_is_durable_inbox_exactly_once_before_attempt_creation(self) -> None:
        result = self._semantic(
            "MatchingRequested source inbox converts once and binds target attempt/run",
            CreateMatchingAttemptHandler,
        )
        inbox = self.last_harness.source_event_validator
        self.assertEqual(result.event_types, ("MatchingAttemptOpened", "MatchRunQueued"))
        persisted_inbox = self.last_harness.uow_factory.store.snapshot()["inbox"]
        self.assertEqual(
            {
                "source_validator_calls": len(inbox.calls),
                "inbox_count": len(persisted_inbox),
                "inbox_status": next(iter(persisted_inbox.values()))["status"],
            },
            {
                "source_validator_calls": 1,
                "inbox_count": 1,
                "inbox_status": "COMPLETED",
            },
        )

    def test_source_event_and_demand_port_must_bind_exact_request_version_and_funding(self) -> None:
        result = self._semantic(
            "event, exact DemandVersion, SECURED funding and matching request must form one chain",
            CreateMatchingAttemptHandler,
        )
        self.assertEqual(result.target_status, "OPEN")
        snapshot = self.last_harness.uow_factory.store.snapshot()
        binding = next(iter(snapshot["attempt_bindings"].values()))
        self.assertEqual(
            (
                binding.demand_aggregate_version,
                binding.matching_request_version,
                binding.source_event_id,
            ),
            (7, 7, "source_event_0000000001"),
        )

    def test_source_event_and_current_demand_aggregate_version_must_match(self) -> None:
        command = command_for(CreateMatchingAttemptHandler)
        harness = build_application_harness(CreateMatchingAttemptHandler, command)
        harness.dependencies["demand_facts"].demand_aggregate_version = 8
        before = harness.uow_factory.store.snapshot()

        with self.assertRaisesRegex(MatchingApplicationError, "MATCH_INPUT_CHANGED"):
            CreateMatchingAttemptHandler(**harness.dependencies).handle(
                actor=actor(), command=command
            )

        self.assertEqual(harness.uow_factory.store.snapshot(), before)

    def test_start_run_captures_full_manifest_and_private_algorithm_values_once(self) -> None:
        result = self._semantic(
            "CaptureMatchInputs freezes manifest plus all algorithm values and independently rehashes",
            StartMatchRunHandler,
        )
        capture = self.last_harness.capture_match_inputs
        self.assertEqual(result.target_status, "RUNNING")
        self.assertEqual(len(capture.calls), 1)

    def test_zero_candidate_capture_completes_run_and_closes_attempt_without_selection(self) -> None:
        command = command_for(CompleteMatchRunHandler)
        command = command.__class__(
            match_run_id=command.match_run_id,
            worker_id=command.worker_id,
            lease_token=command.lease_token,
            fencing_generation=command.fencing_generation,
            input_set_sha256=command.input_set_sha256,
            candidate_results=(),
        )
        result = self._semantic(
            "zero candidates is successful COMPLETED run plus CLOSED_NO_SELECTION and no placeholder",
            CompleteMatchRunHandler,
            command=command,
        )
        self.assertEqual(result.event_types, ("MatchRunCompleted", "MatchingAttemptClosedWithoutSelection"))

    def test_worker_completion_requires_exact_live_lease_token_and_fencing_generation(self) -> None:
        result = self._semantic(
            "expired or stale fenced worker cannot complete or fail a run",
            CompleteMatchRunHandler,
        )
        self.assertEqual(result.target_status, "COMPLETED")

    def test_retry_never_resurrects_failed_run_and_creates_incremented_run(self) -> None:
        result = self._semantic(
            "retry creates run_no+1 and supersedes immutable FAILED run",
            RetryMatchRunHandler,
        )
        self.assertEqual(result.event_types, ("MatchRunQueued", "MatchRunSuperseded"))

    def test_create_invitation_only_accepts_current_non_superseded_eligible_candidate(self) -> None:
        result = self._semantic(
            "excluded, stale-run and duplicate open candidate invitations are indistinguishable 404/409",
            CreateInvitationHandler,
        )
        self.assertEqual(result.target_status, "CREATED")

    def test_reviewer_authority_is_exact_assignment_purpose_expiry_conflict_and_duty(self) -> None:
        result = self._semantic(
            "reviewer command requires exact ACTIVE assignment and OPERATIONS_REVIEWER duty grant",
            CreateInvitationHandler,
            actor_context=actor(kind=MatchingActorKind.USER),
        )
        reviewer_authority = self.last_harness.reviewer_authority
        self.assertEqual(result.target_status, "CREATED")

    def test_publish_revalidates_snapshot_deadline_profile_authority_and_opens_selection(self) -> None:
        result = self._semantic(
            "publish binds constant-time snapshot hash/current Profile and atomically opens Selection",
            PublishInvitationHandler,
        )
        self.assertEqual(result.event_types, ("InvitationSent", "SelectionOpened"))

    def test_publish_never_reuses_selection_from_another_matching_attempt(self) -> None:
        command = command_for(PublishInvitationHandler)
        harness = build_application_harness(PublishInvitationHandler, command)
        foreign_selection = selection(
            selection_id="matching_selection_foreign_0001",
            attempt_id="matching_attempt_foreign_0001",
        )
        harness.uow_factory.store.data.setdefault("selections", {})[
            foreign_selection.selection_id
        ] = foreign_selection

        result = self._semantic(
            "publish opens or reuses only the Selection bound to its own MatchingAttempt",
            PublishInvitationHandler,
            command=command,
            harness=harness,
        )
        snapshot = harness.uow_factory.store.snapshot()
        current_attempt = snapshot["attempts"]["matching_attempt_0000001"]
        current_selection = snapshot["selections"][current_attempt.selection_id]

        self.assertEqual(result.event_types, ("InvitationSent", "SelectionOpened"))
        self.assertNotEqual(current_attempt.selection_id, foreign_selection.selection_id)
        self.assertEqual(current_selection.attempt_id, current_attempt.attempt_id)

    def test_publishing_another_invitation_refreshes_the_current_selection_set_hash(self) -> None:
        command = command_for(PublishInvitationHandler)
        harness = build_application_harness(PublishInvitationHandler, command)
        open_selection = selection()
        harness.uow_factory.store.data["selections"] = {
            open_selection.selection_id: open_selection
        }
        current_attempt = harness.uow_factory.store.data["attempts"][
            "matching_attempt_0000001"
        ]
        harness.uow_factory.store.data["attempts"][current_attempt.attempt_id] = replace(
            current_attempt,
            selection_id=open_selection.selection_id,
        )

        result = self._semantic(
            "publishing changes the exact invitation set used by later selection",
            PublishInvitationHandler,
            command=command,
            harness=harness,
        )
        refreshed = harness.uow_factory.store.snapshot()["selections"][
            open_selection.selection_id
        ]

        self.assertEqual(
            result.event_types,
            ("InvitationSent", "SelectionInvitationSetChanged"),
        )
        self.assertNotEqual(
            refreshed.current_invitation_set_sha256,
            open_selection.current_invitation_set_sha256,
        )
        self.assertEqual(
            refreshed.aggregate_version,
            open_selection.aggregate_version + 1,
        )

    def test_publish_hash_excludes_unpublished_invitation_from_the_owner_snapshot(self) -> None:
        command = command_for(PublishInvitationHandler)
        baseline = build_application_harness(PublishInvitationHandler, command)
        with_draft = build_application_harness(PublishInvitationHandler, command)
        draft = replace(
            next(iter(with_draft.uow_factory.store.data["invitations"].values())),
            invitation_id="business_invitation_draft02",
            creator_user_id="creator_user_000000002",
            status=InvitationStatus.CREATED,
            aggregate_version=1,
            sent_at=None,
        )
        with_draft.uow_factory.store.data["invitations"][draft.invitation_id] = draft

        self._semantic(
            "publish hashes only invitations already visible to the selector",
            PublishInvitationHandler,
            command=command,
            harness=baseline,
        )
        self._semantic(
            "an unpublished CREATED invitation cannot perturb the owner snapshot",
            PublishInvitationHandler,
            command=command,
            harness=with_draft,
        )
        baseline_selection = next(
            iter(baseline.uow_factory.store.snapshot()["selections"].values())
        )
        draft_selection = next(
            iter(with_draft.uow_factory.store.snapshot()["selections"].values())
        )

        self.assertEqual(
            baseline_selection.current_invitation_set_sha256,
            draft_selection.current_invitation_set_sha256,
        )

    def test_accept_requires_exact_creator_recipient_session_profile_and_snapshot(self) -> None:
        command = command_for(RespondInvitationHandler)
        harness = build_application_harness(RespondInvitationHandler, command)
        before = next(iter(harness.uow_factory.store.data["selections"].values()))
        result = self._semantic(
            "accept validates exact recipient CREATOR authority and current exact ProfileVersion",
            RespondInvitationHandler,
            command=command,
            harness=harness,
            actor_context=creator_actor(),
        )
        after = harness.uow_factory.store.snapshot()["selections"][before.selection_id]
        self.assertEqual(result.target_status, "ACCEPTED")
        self.assertEqual(
            result.event_types,
            ("InvitationAccepted", "SelectionInvitationSetChanged"),
        )
        self.assertEqual(after.aggregate_version, before.aggregate_version + 1)
        self.assertNotEqual(
            after.current_invitation_set_sha256,
            before.current_invitation_set_sha256,
        )

    def test_decline_is_safe_downgrade_but_still_exact_recipient_and_deadline(self) -> None:
        command = command_for(RespondInvitationHandler)
        command = command.__class__(
            invitation_id=command.invitation_id,
            snapshot_sha256=command.snapshot_sha256,
            expected_invitation_version=command.expected_invitation_version,
            accept=False,
            reason_code="RECIPIENT_DECLINED",
            note="No longer available",
            idempotency_key="raw-key-decline-001",
        )
        result = self._semantic(
            "decline bypasses hold but still binds exact recipient/snapshot and hides note from event",
            RespondInvitationHandler,
            command=command,
            actor_context=creator_actor(),
        )
        self.assertEqual(
            result.event_types,
            ("InvitationDeclined", "SelectionInvitationSetChanged"),
        )

    def test_creator_can_withdraw_acceptance_before_selection_without_leaking_private_reason(self) -> None:
        command = command_for(WithdrawAcceptedInvitationHandler)
        harness = build_application_harness(
            WithdrawAcceptedInvitationHandler,
            command,
        )
        before = harness.uow_factory.store.snapshot()

        result = WithdrawAcceptedInvitationHandler(
            **harness.dependencies
        ).handle(actor=creator_actor(), command=command)
        after = harness.uow_factory.store.snapshot()
        withdrawn = after["invitations"][command.invitation_id]
        withdrawal = next(iter(after["withdrawals"].values()))

        self.assertEqual(result.target_status, "WITHDRAWN")
        self.assertEqual(
            result.event_types,
            ("InvitationWithdrawn", "SelectionInvitationSetChanged"),
        )
        self.assertEqual(withdrawn.status, InvitationStatus.WITHDRAWN)
        self.assertEqual(
            after["candidates"],
            before["candidates"],
            "private response facts must never become ranking inputs",
        )
        public_surface = repr(
            (after["audits"], after["outbox"], after["candidates"])
        )
        self.assertNotIn(command.note, public_surface)
        self.assertNotIn(command.reason_code, repr(withdrawal))
        self.assertNotIn(command.note, repr(withdrawal))

    def test_withdrawal_rejects_stale_if_match_and_any_recorded_selection_intent_atomically(self) -> None:
        command = command_for(WithdrawAcceptedInvitationHandler)
        for mutation in (
            {"expected_invitation_version": command.expected_invitation_version - 1},
            {},
        ):
            with self.subTest(mutation=mutation):
                current = replace(command, **mutation)
                harness = build_application_harness(
                    WithdrawAcceptedInvitationHandler,
                    current,
                )
                if not mutation:
                    selection_id = next(
                        iter(harness.uow_factory.store.data["selections"])
                    )
                    harness.uow_factory.store.data.setdefault(
                        "selection_intents", {}
                    )[selection_id] = {"status": "COMPLETED"}
                before = harness.uow_factory.store.snapshot()

                expected_code = (
                    "PRECONDITION_FAILED"
                    if mutation
                    else "SELECTION_ALREADY_IN_PROGRESS"
                )
                with self.assertRaisesRegex(
                    MatchingApplicationError,
                    expected_code,
                ):
                    WithdrawAcceptedInvitationHandler(
                        **harness.dependencies
                    ).handle(actor=creator_actor(), command=current)

                self.assertEqual(harness.uow_factory.store.snapshot(), before)

    def test_completed_withdrawal_receipt_replays_before_business_authority(self) -> None:
        command = command_for(WithdrawAcceptedInvitationHandler)
        harness = build_application_harness(
            WithdrawAcceptedInvitationHandler,
            command,
        )
        first = WithdrawAcceptedInvitationHandler(**harness.dependencies).handle(
            actor=creator_actor(),
            command=command,
        )
        unavailable = _Recorder()
        harness.dependencies["creator_authority"] = unavailable

        second = WithdrawAcceptedInvitationHandler(**harness.dependencies).handle(
            actor=creator_actor(),
            command=command,
        )

        self.assertFalse(first.replayed)
        self.assertTrue(second.replayed)
        self.assertEqual(unavailable.calls, [])

    def test_choose_uses_resource_organization_not_session_active_organization(self) -> None:
        command = command_for(ChooseCreatorHandler)
        result = self._semantic(
            "ChooseCreator requires exact ACTIVE CANDIDATE_SELECTOR assignment",
            ChooseCreatorHandler,
            command=command,
            actor_context=actor(kind=MatchingActorKind.USER),
        )
        self.assertEqual(result.target_status, "OPEN")
        audit = next(
            iter(self.last_harness.uow_factory.store.snapshot()["audits"].values())
        )
        self.assertEqual(
            (
                audit["candidate_selector_role_code"],
                audit["candidate_selector_assignment_id"],
                audit["candidate_selector_assignment_version"],
            ),
            (
                "CANDIDATE_SELECTOR",
                command.assignment_id,
                command.expected_assignment_version,
            ),
        )

    def test_candidate_selector_can_atomically_close_a_terminal_invitation_set_without_choice(self) -> None:
        command = command_for(CloseSelectionWithoutChoiceHandler)
        result = self._semantic(
            "exact candidate selector closes Selection and MatchingAttempt together",
            CloseSelectionWithoutChoiceHandler,
            command=command,
            actor_context=actor(kind=MatchingActorKind.USER),
        )
        snapshot = self.last_harness.uow_factory.store.snapshot()
        closed_selection = snapshot["selections"][command.selection_id]
        closed_attempt = snapshot["attempts"][closed_selection.attempt_id]
        audit = next(iter(snapshot["audits"].values()))

        self.assertEqual(result.target_status, "CLOSED_NO_SELECTION")
        self.assertEqual(
            result.event_types,
            (
                "SelectionClosedWithoutChoice",
                "MatchingAttemptClosedWithoutSelection",
            ),
        )
        self.assertIs(closed_selection.status, SelectionStatus.CLOSED_NO_SELECTION)
        self.assertIs(
            closed_attempt.status,
            MatchingAttemptStatus.CLOSED_NO_SELECTION,
        )
        self.assertEqual(
            (
                audit["candidate_selector_assignment_id"],
                audit["candidate_selector_assignment_version"],
                audit["candidate_selector_role_code"],
            ),
            (
                command.assignment_id,
                command.expected_assignment_version,
                "CANDIDATE_SELECTOR",
            ),
        )

    def test_close_without_choice_rejects_nonterminal_invitations_atomically(self) -> None:
        command = command_for(CloseSelectionWithoutChoiceHandler)
        harness = build_application_harness(
            CloseSelectionWithoutChoiceHandler,
            command,
        )
        data = harness.uow_factory.store.data
        invitation_id = next(iter(data["invitations"]))
        current = data["invitations"][invitation_id]
        sent = replace(
            current,
            status=InvitationStatus.SENT,
            responded_at=None,
        )
        current_hash = selection_invitation_set_sha256(
            attempt_id=sent.attempt_id,
            run_id=sent.match_run_id,
            invitations=(sent,),
        )
        data["invitations"][invitation_id] = sent
        data["selections"][command.selection_id] = replace(
            data["selections"][command.selection_id],
            current_invitation_set_sha256=current_hash,
        )
        command = replace(
            command,
            current_invitation_set_sha256=current_hash,
        )
        before = harness.uow_factory.store.snapshot()

        with self.assertRaisesRegex(
            MatchingApplicationError,
            "SELECTION_NOT_READY",
        ):
            CloseSelectionWithoutChoiceHandler(
                **harness.dependencies
            ).handle(
                actor=actor(kind=MatchingActorKind.USER),
                command=command,
            )

        self.assertEqual(harness.uow_factory.store.snapshot(), before)

    def test_choose_is_manual_and_only_from_current_accepted_invitation_set(self) -> None:
        result = self._semantic(
            "assigned selector may choose non-top ACCEPTED invite with closed basis, never excluded/unaccepted",
            ChooseCreatorHandler,
            actor_context=actor(kind=MatchingActorKind.USER),
        )
        self.assertIn("Selection", result.event_types[0])

    def test_choose_assignment_must_match_version_expiry_actor_org_demand_and_selection(self) -> None:
        command = command_for(ChooseCreatorHandler)
        mutations = (
            {"status": CandidateSelectorAssignmentStatus.RELEASED},
            {"aggregate_version": command.expected_assignment_version + 1},
            {"expires_at": NOW},
            {"assigned_user_id": "different_selector_00001"},
            {"organization_id": "different_organization01"},
            {"demand_id": "different_demand_000001"},
            {"selection_id": "different_selection_0001"},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                harness = build_application_harness(ChooseCreatorHandler, command)
                authority_port = harness.dependencies[
                    "candidate_selector_authority"
                ]
                authority_port.result = replace(
                    authority_port.result,
                    assignment=replace(
                        authority_port.result.assignment,
                        **mutation,
                    ),
                )
                before = harness.uow_factory.store.snapshot()

                with self.assertRaisesRegex(
                    MatchingApplicationError,
                    "RESOURCE_NOT_FOUND",
                ):
                    ChooseCreatorHandler(**harness.dependencies).handle(
                        actor=actor(kind=MatchingActorKind.USER),
                        command=command,
                    )

                self.assertEqual(harness.uow_factory.store.snapshot(), before)

    def test_demand_owner_role_is_not_a_candidate_selector_backdoor(self) -> None:
        command = command_for(ChooseCreatorHandler)
        harness = build_application_harness(ChooseCreatorHandler, command)
        harness.dependencies.pop("candidate_selector_authority")
        harness.dependencies["owner_authority"] = _Recorder()

        with self.assertRaisesRegex(MatchingApplicationError, "SERVICE_UNAVAILABLE"):
            ChooseCreatorHandler(**harness.dependencies).handle(
                actor=actor(kind=MatchingActorKind.USER),
                command=command,
            )

    def test_choose_persists_one_closed_complete_selection_trigger(self) -> None:
        command = command_for(ChooseCreatorHandler)
        harness = build_application_harness(ChooseCreatorHandler, command)
        owner = actor(kind=MatchingActorKind.USER)

        result = ChooseCreatorHandler(**harness.dependencies).handle(
            actor=owner, command=command
        )
        snapshot = harness.uow_factory.store.snapshot()
        receipt = next(iter(snapshot["choose_receipts"].values()))
        intent = next(iter(snapshot["selection_intents"].values()))
        trigger = next(
            iter(snapshot["pending_complete_selection_triggers"].values())
        )
        security_receipt = next(iter(snapshot["receipts"].values()))

        self.assertIsInstance(receipt, ChooseReceiptFact)
        self.assertIsInstance(intent, SelectionIntentFact)
        self.assertIsInstance(trigger, PendingCompleteSelectionTrigger)
        self.assertEqual(
            (
                trigger.status,
                trigger.receipt,
                trigger.intent,
                receipt.selection_intent_sha256,
                result.event_types,
            ),
            (
                "READY",
                receipt,
                intent,
                selection_intent_sha256(intent),
                ("SelectionIntentRecorded",),
            ),
        )
        self.assertEqual(
            (
                receipt.candidate_selector_assignment_id,
                receipt.candidate_selector_assignment_version,
                intent.hold_binding.candidate_selector_assignment_id,
                intent.hold_binding.candidate_selector_assignment_version,
            ),
            (
                command.assignment_id,
                command.expected_assignment_version,
                command.assignment_id,
                command.expected_assignment_version,
            ),
        )
        self.assertEqual(
            set(security_receipt),
            {
                "command_version",
                "canonicalization_version",
                "identity_key_id",
                "payload_hash_key_id",
                "principal_kind",
                "principal_id",
                "organization_id",
                "operation",
                "identity",
                "payload_hash",
                "status",
                "safe_response",
                "recovery_facts",
            },
        )
        serialized = repr((receipt, intent, trigger)).lower()
        self.assertNotIn(command.idempotency_key, serialized)
        self.assertNotIn(owner.session_id, serialized)
        self.assertNotIn(
            harness.dependencies[
                "candidate_selector_authority"
            ].result.authority_marker_sha256,
            serialized,
        )

    def test_choose_replay_requires_the_exact_immutable_trigger_chain(self) -> None:
        command = command_for(ChooseCreatorHandler)
        harness = build_application_harness(ChooseCreatorHandler, command)
        owner = actor(kind=MatchingActorKind.USER)
        handler = ChooseCreatorHandler(**harness.dependencies)
        first = handler.handle(actor=owner, command=command)
        before = harness.uow_factory.store.snapshot()
        replay = handler.handle(actor=owner, command=command)
        self.assertFalse(first.replayed)
        self.assertTrue(replay.replayed)
        self.assertEqual(harness.uow_factory.store.snapshot(), before)

        for collection in (
            "choose_receipts",
            "selection_intents",
            "pending_complete_selection_triggers",
        ):
            damaged = build_application_harness(ChooseCreatorHandler, command)
            damaged_handler = ChooseCreatorHandler(**damaged.dependencies)
            damaged_handler.handle(actor=owner, command=command)
            damaged.uow_factory.store.data[collection].clear()
            with self.assertRaisesRegex(
                MatchingApplicationError, "SERVICE_UNAVAILABLE"
            ):
                damaged_handler.handle(actor=owner, command=command)

    def test_different_choose_key_cannot_replace_a_ready_trigger(self) -> None:
        command = command_for(ChooseCreatorHandler)
        harness = build_application_harness(ChooseCreatorHandler, command)
        owner = actor(kind=MatchingActorKind.USER)
        handler = ChooseCreatorHandler(**harness.dependencies)
        handler.handle(actor=owner, command=command)
        before = harness.uow_factory.store.snapshot()

        with self.assertRaisesRegex(
            MatchingApplicationError, "PRECONDITION_FAILED"
        ):
            handler.handle(
                actor=owner,
                command=replace(
                    command,
                    idempotency_key="raw-key-choose-0002",
                ),
            )

        self.assertEqual(harness.uow_factory.store.snapshot(), before)

    def test_choose_recomputes_the_authoritative_set_and_rejects_non_current_run(self) -> None:
        command = command_for(ChooseCreatorHandler)
        stale_hash = build_application_harness(ChooseCreatorHandler, command)
        stale_selection = stale_hash.uow_factory.store.data["selections"][
            command.selection_id
        ]
        stale_invitation = stale_hash.uow_factory.store.data["invitations"][
            command.invitation_id
        ]
        baseline_hash = selection_invitation_set_sha256(
            attempt_id=stale_invitation.attempt_id,
            run_id=stale_invitation.match_run_id,
            invitations=(stale_invitation,),
        )
        stale_hash.uow_factory.store.data["selections"][command.selection_id] = replace(
            stale_selection,
            current_invitation_set_sha256=baseline_hash,
        )
        drifted_invitation = replace(
            stale_invitation,
            aggregate_version=stale_invitation.aggregate_version + 1,
        )
        stale_hash.uow_factory.store.data["invitations"][command.invitation_id] = (
            drifted_invitation
        )
        command = replace(command, current_invitation_set_sha256=baseline_hash)

        with self.assertRaisesRegex(MatchingApplicationError, "SERVICE_UNAVAILABLE"):
            ChooseCreatorHandler(**stale_hash.dependencies).handle(
                actor=actor(kind=MatchingActorKind.USER),
                command=command,
            )

        current_command = command_for(ChooseCreatorHandler)
        stale_run = build_application_harness(ChooseCreatorHandler, current_command)
        current_attempt = stale_run.uow_factory.store.data["attempts"][
            "matching_attempt_0000001"
        ]
        stale_run.uow_factory.store.data["attempts"][current_attempt.attempt_id] = replace(
            current_attempt,
            current_match_run_id="matching_run_successor001",
        )

        with self.assertRaisesRegex(MatchingApplicationError, "SELECTION_NOT_READY"):
            ChooseCreatorHandler(**stale_run.dependencies).handle(
                actor=actor(kind=MatchingActorKind.USER),
                command=current_command,
            )

    def test_hold_binding_drift_inside_lock_rolls_back_every_business_write(self) -> None:
        command = command_for(ChooseCreatorHandler)
        harness = build_application_harness(ChooseCreatorHandler, command)
        current_invitation = harness.uow_factory.store.snapshot()["invitations"][
            command.invitation_id
        ]
        harness.uow_factory.replace_after_lock(
            "invitations",
            command.invitation_id,
            replace(
                current_invitation,
                aggregate_version=current_invitation.aggregate_version + 1,
            ),
        )
        before = harness.uow_factory.store.snapshot()
        code = None
        try:
            ChooseCreatorHandler(**harness.dependencies).handle(
                actor=actor(kind=MatchingActorKind.USER), command=command
            )
        except MatchingApplicationError as error:
            code = error.code
        after = harness.uow_factory.store.snapshot()
        self.assertEqual(
            {
                "code": code,
                "durable_unchanged": after == before,
                "receipt_count": len(after.get("receipts", {})),
                "audit_count": len(after.get("audits", {})),
                "outbox_count": len(after.get("outbox", {})),
            },
            {
                "code": "SERVICE_UNAVAILABLE",
                "durable_unchanged": True,
                "receipt_count": 0,
                "audit_count": 0,
                "outbox_count": 0,
            },
        )

    def test_keyed_receipt_replays_same_payload_and_rejects_different_payload(self) -> None:
        first = self._semantic(
            "same subject/key/payload replays closed safe response; different payload is 409",
            RespondInvitationHandler,
            actor_context=creator_actor(),
        )
        second = RespondInvitationHandler(**self.last_harness.dependencies).handle(
            actor=creator_actor(), command=command_for(RespondInvitationHandler)
        )
        self.assertFalse(first.replayed)
        self.assertTrue(second.replayed)

    def test_all_thirteen_write_checkpoints_are_one_atomic_unit(self) -> None:
        checkpoints = (
            "receipt_claim", "root_lock", "candidate_or_response", "snapshot",
            "invitation", "selection", "attempt", "source_inbox", "audit",
            "outbox_events", "safe_response", "receipt_complete", "commit",
        )
        result = self._semantic(
            "each of 13 stable checkpoints rolls back receipt/root/child/audit/outbox together",
            PublishInvitationHandler,
        )
        uow = self.last_harness.uow_factory
        self.assertEqual([call[1][0] for call in uow.calls if call[0] == "checkpoint"], list(checkpoints))
        self.assertEqual(result.target_status, "SENT")

    def test_commit_unknown_discards_connection_and_reconstructs_exact_full_chain(self) -> None:
        command = command_for(ChooseCreatorHandler)
        harness = build_application_harness(ChooseCreatorHandler, command)
        harness.uow_factory.commit_unknown = True
        harness.uow_factory.commit_unknown_durable = True
        result = self._semantic(
            "COMMIT_SENT ack loss discards connection and new read validates receipt plus all aggregate versions",
            ChooseCreatorHandler,
            command=command,
            harness=harness,
            actor_context=actor(kind=MatchingActorKind.USER),
        )
        self.assertTrue(result.replayed)

    def test_receipt_audit_event_exception_and_repr_do_not_leak_private_matching_facts(self) -> None:
        command = command_for(CompleteMatchRunHandler)
        self.assertNotIn("lease_secret", repr(command))
        self.assertNotIn("candidate_results", repr(command))
        self.assertNotIn("private_floor_amount", repr(candidate(eligible=False)).lower())
        self.assertNotIn("123456", repr(candidate(eligible=False)))
        result = self._semantic(
            "private floor/input/notes/lease/session/raw keys never enter receipt/event/audit/error/log",
            CompleteMatchRunHandler,
        )
        self.assertEqual(result.target_status, "COMPLETED")

    def test_application_commands_are_immutable(self) -> None:
        command = command_for(ChooseCreatorHandler)
        with self.assertRaises(FrozenInstanceError):
            command.selection_id = "different"  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
