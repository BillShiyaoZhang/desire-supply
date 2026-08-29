"""Executable §11 semantics for the CompleteSelection composition primitive."""

from __future__ import annotations

from contextlib import AbstractContextManager
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from threading import Barrier, Lock, RLock, Thread
import unittest
from typing import Any, Mapping, Optional

from desire_platform.coordination import (
    COMPLETE_SELECTION_CHECKPOINTS,
    COMPLETE_SELECTION_CONTEXT_EVENT_BINDINGS_AVAILABLE,
    COMPLETE_SELECTION_PRODUCTION_BINDING_AVAILABLE,
    COMPLETE_SELECTION_TRIGGER_PRODUCER_COMPATIBLE,
    AgreementRoot,
    AttemptSelectionFact,
    CandidateSelectorAuthorityFact,
    ChooseReceiptFact,
    CompleteSelectionActor,
    CompleteSelectionCommand,
    CompleteSelectionCommitOutcomeUnknownError,
    CompleteSelectionCoordinator,
    CompleteSelectionError,
    CompleteSelectionStorageError,
    CompleteSelectionUniqueConflictError,
    DemandSelectionFact,
    InvitationSelectionFact,
    PendingCompleteSelectionTrigger,
    ProjectShell,
    RunSelectionFact,
    SelectionHoldBinding,
    SelectionIntentFact,
    SelectionSelectionFact,
    SystemCoordinatorAuthorityFact,
    selection_intent_sha256,
)
from desire_platform.matching.domain import (
    InvitationStatus,
    SelectionInvitationSetEntry,
    selection_invitation_set_sha256,
)


NOW = datetime(2035, 1, 1, tzinfo=timezone.utc)
ORG = "organization_0000000001"
SYSTEM_ACTOR = "system_actor_0000000001"
SYSTEM_CREDENTIAL = "workload_secret_complete_selection_0001"
OWNER = "demand_owner_000000001"
SELECTOR_ASSIGNMENT = "selector_assignment_00001"
SELECTOR_ASSIGNMENT_VERSION = 3
SELECTOR_AUTHORITY_SHA = "8" * 64
SELECTION = "matching_selection_00001"
ATTEMPT = "matching_attempt_0000001"
INVITATION = "business_invitation_0001"
RUN = "matching_run_0000000001"
DEMAND = "demand_object_000000001"
DEMAND_VERSION = "demand_version_00000001"
FUNDING = "funding_object_00000001"
MATCHING_REQUEST = "matching_request_000001"
CHOOSE_COMMAND = "choose_command_000000001"
CHOOSE_RECEIPT = "choose_receipt_000000001"
CORRELATION = "correlation_00000000001"
SNAPSHOT_SHA = "9" * 64
RULE_SHA = "b" * 64
INPUT_SHA = "c" * 64
RESULT_SHA = "d" * 64
CANDIDATE_SHA = "e" * 64
RULE_BUNDLE = "matching_bundle_00000001"
SHA = selection_invitation_set_sha256(
    attempt_id=ATTEMPT,
    run_id=RUN,
    invitations=(
        SelectionInvitationSetEntry(
            invitation_id=INVITATION,
            attempt_id=ATTEMPT,
            match_run_id=RUN,
            aggregate_version=4,
            status=InvitationStatus.ACCEPTED,
            snapshot_sha256=SNAPSHOT_SHA,
        ),
    ),
)


def actor(**changes: Any) -> CompleteSelectionActor:
    value = CompleteSelectionActor(
        actor_kind="SYSTEM",
        actor_id=SYSTEM_ACTOR,
        workload_credential_id=SYSTEM_CREDENTIAL,
        organization_id=ORG,
        original_actor_id=OWNER,
        correlation_id=CORRELATION,
        causation_id=CHOOSE_COMMAND,
        trace_id="trace_identifier_0000001",
    )
    return replace(value, **changes)


def command(**changes: Any) -> CompleteSelectionCommand:
    value = CompleteSelectionCommand(
        completion_command_id="complete_selection_command_0001",
        choose_receipt_id=CHOOSE_RECEIPT,
        choose_command_id=CHOOSE_COMMAND,
        selection_id=SELECTION,
        expected_selection_version=3,
        attempt_id=ATTEMPT,
        expected_attempt_version=5,
        invitation_id=INVITATION,
        run_id=RUN,
        demand_id=DEMAND,
        expected_demand_version=11,
        demand_version_id=DEMAND_VERSION,
        matching_request_id=MATCHING_REQUEST,
        matching_request_version=2,
        funding_id=FUNDING,
        candidate_selector_assignment_id=SELECTOR_ASSIGNMENT,
        expected_candidate_selector_assignment_version=(
            SELECTOR_ASSIGNMENT_VERSION
        ),
    )
    return replace(value, **changes)


def hold_binding(**changes: Any) -> SelectionHoldBinding:
    value = SelectionHoldBinding(
        selection_id=SELECTION,
        selection_version=3,
        current_invitation_set_sha256=SHA,
        attempt_id=ATTEMPT,
        attempt_version=5,
        invitation_id=INVITATION,
        invitation_version=4,
        run_id=RUN,
        run_version=7,
        demand_id=DEMAND,
        demand_version=11,
        demand_version_id=DEMAND_VERSION,
        matching_request_id=MATCHING_REQUEST,
        matching_request_version=2,
        funding_id=FUNDING,
        matching_rule_bundle_id=RULE_BUNDLE,
        candidate_selector_assignment_id=SELECTOR_ASSIGNMENT,
        candidate_selector_assignment_version=SELECTOR_ASSIGNMENT_VERSION,
        candidate_selector_authority_marker_sha256=SELECTOR_AUTHORITY_SHA,
        rule_manifest_sha256=RULE_SHA,
        input_set_sha256=INPUT_SHA,
        ordered_result_sha256=RESULT_SHA,
        candidate_result_sha256=CANDIDATE_SHA,
    )
    return replace(value, **changes)


def seed() -> dict[str, dict[str, Any]]:
    intent = SelectionIntentFact(
        selection_id=SELECTION,
        receipt_id=CHOOSE_RECEIPT,
        choose_command_id=CHOOSE_COMMAND,
        event_type="SelectionIntentRecorded",
        status="COMPLETED",
        actor_id=OWNER,
        organization_id=ORG,
        attempt_id=ATTEMPT,
        invitation_id=INVITATION,
        run_id=RUN,
        selection_basis_code="ALGORITHM_TOP",
        hold_decision="ALLOW",
        hold_valid_until=NOW + timedelta(minutes=5),
        hold_binding=hold_binding(),
    )
    receipt = ChooseReceiptFact(
        receipt_id=CHOOSE_RECEIPT,
        command_id=CHOOSE_COMMAND,
        operation="CHOOSE_CREATOR",
        status="COMPLETED",
        actor_id=OWNER,
        organization_id=ORG,
        correlation_id=CORRELATION,
        selection_id=SELECTION,
        attempt_id=ATTEMPT,
        invitation_id=INVITATION,
        run_id=RUN,
        expected_selection_version=3,
        expected_attempt_version=5,
        expected_demand_version=11,
        demand_id=DEMAND,
        demand_version_id=DEMAND_VERSION,
        matching_request_id=MATCHING_REQUEST,
        matching_request_version=2,
        funding_id=FUNDING,
        matching_rule_bundle_id=RULE_BUNDLE,
        candidate_selector_assignment_id=SELECTOR_ASSIGNMENT,
        candidate_selector_assignment_version=SELECTOR_ASSIGNMENT_VERSION,
        candidate_selector_authority_marker_sha256=SELECTOR_AUTHORITY_SHA,
        rule_manifest_sha256=RULE_SHA,
        input_set_sha256=INPUT_SHA,
        ordered_result_sha256=RESULT_SHA,
        candidate_result_sha256=CANDIDATE_SHA,
        selection_intent_sha256=selection_intent_sha256(intent),
        payload_sha256=SHA,
    )
    return {
        "system_authorities": {
            SYSTEM_ACTOR: SystemCoordinatorAuthorityFact(
                actor_id=SYSTEM_ACTOR,
                workload_credential_id=SYSTEM_CREDENTIAL,
                operation="COMPLETE_SELECTION",
                organization_id=ORG,
                selection_id=SELECTION,
                attempt_id=ATTEMPT,
                status="ACTIVE",
                valid_until=NOW + timedelta(minutes=5),
            )
        },
        "candidate_selector_authorities": {
            SELECTOR_ASSIGNMENT: CandidateSelectorAuthorityFact(
                assignment_id=SELECTOR_ASSIGNMENT,
                aggregate_version=SELECTOR_ASSIGNMENT_VERSION,
                status="ACTIVE",
                role_code="CANDIDATE_SELECTOR",
                assigned_user_id=OWNER,
                organization_id=ORG,
                demand_id=DEMAND,
                selection_id=SELECTION,
                authority_marker_sha256=SELECTOR_AUTHORITY_SHA,
                assigned_at=NOW - timedelta(minutes=5),
                expires_at=NOW + timedelta(minutes=5),
            )
        },
        "choose_receipts": {CHOOSE_RECEIPT: receipt},
        "selection_intents": {SELECTION: intent},
        "pending_complete_selection_triggers": {
            CHOOSE_RECEIPT: PendingCompleteSelectionTrigger(
                completion_command_id="complete_selection_command_0001",
                status="READY",
                recorded_at=NOW,
                receipt=receipt,
                intent=intent,
            )
        },
        "selections": {
            SELECTION: SelectionSelectionFact(
                selection_id=SELECTION,
                organization_id=ORG,
                attempt_id=ATTEMPT,
                status="OPEN",
                aggregate_version=3,
                current_invitation_set_sha256=SHA,
                chosen_invitation_id=None,
                selection_basis_code=None,
                decision_actor_id=None,
                updated_at=NOW,
            )
        },
        "attempts": {
            ATTEMPT: AttemptSelectionFact(
                attempt_id=ATTEMPT,
                organization_id=ORG,
                demand_id=DEMAND,
                demand_version_id=DEMAND_VERSION,
                matching_request_id=MATCHING_REQUEST,
                matching_request_version=2,
                funding_id=FUNDING,
                status="OPEN",
                aggregate_version=5,
                current_run_id=RUN,
                selection_id=SELECTION,
                updated_at=NOW,
            )
        },
        "invitations": {
            INVITATION: InvitationSelectionFact(
                invitation_id=INVITATION,
                organization_id=ORG,
                attempt_id=ATTEMPT,
                run_id=RUN,
                creator_user_id="creator_user_000000001",
                demand_id=DEMAND,
                demand_version_id=DEMAND_VERSION,
                funding_id=FUNDING,
                matching_rule_bundle_id=RULE_BUNDLE,
                candidate_result_sha256=CANDIDATE_SHA,
                snapshot_sha256=SNAPSHOT_SHA,
                status="ACCEPTED",
                aggregate_version=4,
            )
        },
        "runs": {
            RUN: RunSelectionFact(
                run_id=RUN,
                attempt_id=ATTEMPT,
                status="COMPLETED",
                aggregate_version=7,
                superseded_by_run_id=None,
                matching_rule_bundle_id=RULE_BUNDLE,
                rule_manifest_sha256=RULE_SHA,
                input_set_sha256=INPUT_SHA,
                ordered_result_sha256=RESULT_SHA,
            )
        },
        "demands": {
            DEMAND: DemandSelectionFact(
                demand_id=DEMAND,
                organization_id=ORG,
                demand_version_id=DEMAND_VERSION,
                status="MATCHING",
                aggregate_version=11,
                funding_id=FUNDING,
                funding_status="SECURED",
                matching_request_id=MATCHING_REQUEST,
                matching_request_version=2,
                updated_at=NOW,
            )
        },
    }


class FixedClock:
    def now(self) -> datetime:
        return NOW


class ExpiringAfterFirstReadClock:
    def __init__(self) -> None:
        self.calls = 0

    def now(self) -> datetime:
        self.calls += 1
        if self.calls == 1:
            return NOW
        return NOW + timedelta(minutes=10)


class BackwardAfterFirstReadClock:
    def __init__(self) -> None:
        self.calls = 0

    def now(self) -> datetime:
        self.calls += 1
        if self.calls == 1:
            return NOW
        return NOW - timedelta(seconds=1)


class ConcurrentIdSource:
    def __init__(self) -> None:
        self._lock = Lock()
        self._counters: dict[str, int] = {}

    def next_id(self, kind: str) -> str:
        with self._lock:
            value = self._counters.get(kind, 0) + 1
            self._counters[kind] = value
            return f"coordination_{kind}_{value:08d}"


class MemoryStore:
    def __init__(self, initial: Mapping[str, Mapping[str, Any]]) -> None:
        self.lock = RLock()
        self.data = deepcopy(initial)
        self.generation = 0

    def snapshot(self) -> dict[str, dict[str, Any]]:
        with self.lock:
            return deepcopy(self.data)


class MemoryUow(AbstractContextManager["MemoryUow"]):
    def __init__(self, factory: "MemoryUowFactory") -> None:
        self.factory = factory
        with factory.store.lock:
            self.working = deepcopy(factory.store.data)
            self.base_generation = factory.store.generation
        self.calls: list[Any] = []

    def __enter__(self) -> "MemoryUow":
        self.factory.instances.append(self)
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None

    def checkpoint(self, name: str) -> None:
        self.calls.append(("checkpoint", name))
        if self.factory.fail_checkpoint == name:
            raise CompleteSelectionStorageError(
                f"database private secret at {name}"
            )

    def lock(self, resource: str, keys: Any) -> None:
        self.calls.append(("lock", resource, tuple(keys)))
        for collection, key, replacement in self.factory.locked_replacements:
            self.working.setdefault(collection, {})[key] = deepcopy(replacement)

    def get(self, collection: str, key: str) -> Any:
        return deepcopy(self.working.get(collection, {}).get(key))

    def values(self, collection: str) -> tuple[Any, ...]:
        return tuple(deepcopy(tuple(self.working.get(collection, {}).values())))

    def put(self, collection: str, key: str, value: Any) -> None:
        self.working.setdefault(collection, {})[key] = deepcopy(value)

    def commit(self) -> None:
        barrier = self.factory.commit_barrier
        if barrier is not None:
            barrier.wait(timeout=5)
        with self.factory.store.lock:
            if self.factory.commit_unknown:
                if self.factory.commit_unknown_durable:
                    self.factory.store.data = deepcopy(self.working)
                    self.factory.store.generation += 1
                raise CompleteSelectionCommitOutcomeUnknownError(
                    "commit acknowledgement contained private secret"
                )
            if self.factory.store.generation != self.base_generation:
                if any(
                    item.selection_id == SELECTION
                    for item in self.factory.store.data.get("projects", {}).values()
                ):
                    raise CompleteSelectionUniqueConflictError(
                        "selection_id unique violation with private detail"
                    )
                raise CompleteSelectionStorageError("serialization private detail")
            self.factory.store.data = deepcopy(self.working)
            self.factory.store.generation += 1


class MemoryUowFactory:
    def __init__(self, initial: Optional[Mapping[str, Mapping[str, Any]]] = None) -> None:
        self.store = MemoryStore(initial or seed())
        self.instances: list[MemoryUow] = []
        self.fail_checkpoint: Optional[str] = None
        self.commit_unknown = False
        self.commit_unknown_durable = False
        self.commit_barrier: Optional[Barrier] = None
        self.locked_replacements: list[tuple[str, str, Any]] = []

    def begin(self) -> MemoryUow:
        return MemoryUow(self)


class RecoveryReader:
    def __init__(self, factory: MemoryUowFactory) -> None:
        self.factory = factory

    def snapshot(self) -> Mapping[str, Mapping[str, Any]]:
        return self.factory.store.snapshot()


def coordinator(
    factory: MemoryUowFactory,
    *,
    clock: Optional[Any] = None,
) -> CompleteSelectionCoordinator:
    return CompleteSelectionCoordinator(
        uow_factory=factory,
        recovery_reader=RecoveryReader(factory),
        clock=clock or FixedClock(),
        id_source=ConcurrentIdSource(),
    )


def code(callable_: Any) -> str:
    try:
        callable_()
    except CompleteSelectionError as error:
        return error.code
    raise AssertionError("expected CompleteSelectionError")


class CompleteSelectionRedTests(unittest.TestCase):
    def test_is_explicitly_a_composition_primitive_not_a_production_binding(self) -> None:
        self.assertFalse(COMPLETE_SELECTION_PRODUCTION_BINDING_AVAILABLE)
        self.assertTrue(COMPLETE_SELECTION_TRIGGER_PRODUCER_COMPATIBLE)
        self.assertFalse(COMPLETE_SELECTION_CONTEXT_EVENT_BINDINGS_AVAILABLE)

    def test_success_uses_fixed_lock_order_and_one_atomic_commit(self) -> None:
        factory = MemoryUowFactory()
        result = coordinator(factory).handle(actor=actor(), command=command())
        snapshot = factory.store.snapshot()

        self.assertEqual(
            {
                "selection": snapshot["selections"][SELECTION].status,
                "attempt": snapshot["attempts"][ATTEMPT].status,
                "demand": snapshot["demands"][DEMAND].status,
                "projects": len(snapshot["projects"]),
                "agreements": len(snapshot["agreements"]),
                "events": sorted(
                    item.event_type for item in snapshot["outbox"].values()
                ),
                "audits": len(snapshot["coordination_audits"]),
                "completions": len(snapshot["completion_records"]),
                "replayed": result.replayed,
            },
            {
                "selection": "SELECTED",
                "attempt": "SELECTED",
                "demand": "MATCHED",
                "projects": 1,
                "agreements": 1,
                "events": sorted(
                    (
                        "SelectionMade",
                        "MatchingAttemptSelected",
                        "ProjectCreated",
                        "AgreementCreated",
                        "DemandMatched",
                    )
                ),
                "audits": 1,
                "completions": 1,
                "replayed": False,
            },
        )
        calls = factory.instances[0].calls
        self.assertEqual(
            [item for item in calls if item[0] == "lock"],
            [
                (
                    "lock",
                    "matching.candidate_selector_assignment",
                    (SELECTOR_ASSIGNMENT,),
                ),
                ("lock", "matching.selection", (SELECTION,)),
                ("lock", "matching.attempt", (ATTEMPT,)),
                ("lock", "demand.demand", (DEMAND,)),
            ],
        )
        self.assertEqual(
            tuple(item[1] for item in calls if item[0] == "checkpoint"),
            COMPLETE_SELECTION_CHECKPOINTS,
        )
        project = next(iter(snapshot["projects"].values()))
        agreement = next(iter(snapshot["agreements"].values()))
        audit = next(iter(snapshot["coordination_audits"].values()))
        self.assertIsInstance(project, ProjectShell)
        self.assertIsInstance(agreement, AgreementRoot)
        self.assertEqual(project.status, "PENDING_AGREEMENT")
        self.assertEqual(agreement.project_id, project.project_id)
        self.assertEqual(
            {
                "rule": audit.matching_rule_bundle_id,
                "rule_hash": audit.rule_manifest_sha256,
                "input_hash": audit.input_set_sha256,
                "result_hash": audit.ordered_result_sha256,
                "candidate_hash": audit.candidate_result_sha256,
                "invitation_set_hash": audit.current_invitation_set_sha256,
                "basis": audit.selection_basis_code,
            },
            {
                "rule": RULE_BUNDLE,
                "rule_hash": RULE_SHA,
                "input_hash": INPUT_SHA,
                "result_hash": RESULT_SHA,
                "candidate_hash": CANDIDATE_SHA,
                "invitation_set_hash": SHA,
                "basis": "ALGORITHM_TOP",
            },
        )
        selection_event = next(
            item for item in snapshot["outbox"].values()
            if item.event_type == "SelectionMade"
        )
        self.assertEqual(
            dict(selection_event.payload),
            {
                "status": "SELECTED",
                "current_invitation_set_sha256": SHA,
                "chosen_invitation_id": INVITATION,
                "selection_basis_code": "ALGORITHM_TOP",
                "candidate_selector_assignment_id": SELECTOR_ASSIGNMENT,
                "candidate_selector_assignment_version": (
                    SELECTOR_ASSIGNMENT_VERSION
                ),
                "reason_code": None,
            },
        )
        selected = snapshot["selections"][SELECTION]
        self.assertEqual(
            (
                selected.candidate_selector_assignment_id,
                selected.candidate_selector_assignment_version,
                audit.candidate_selector_assignment_id,
                audit.candidate_selector_assignment_version,
                result.candidate_selector_assignment_id,
                result.candidate_selector_assignment_version,
            ),
            (
                SELECTOR_ASSIGNMENT,
                SELECTOR_ASSIGNMENT_VERSION,
                SELECTOR_ASSIGNMENT,
                SELECTOR_ASSIGNMENT_VERSION,
                SELECTOR_ASSIGNMENT,
                SELECTOR_ASSIGNMENT_VERSION,
            ),
        )

    def test_system_and_original_current_selector_are_both_required(self) -> None:
        for mutation in (
            lambda data: data["system_authorities"].clear(),
            lambda data: data["candidate_selector_authorities"].clear(),
            lambda data: data["candidate_selector_authorities"].update(
                {SELECTOR_ASSIGNMENT: replace(
                    data["candidate_selector_authorities"][SELECTOR_ASSIGNMENT],
                    role_code="DEMAND_OWNER",
                )}
            ),
            lambda data: data["candidate_selector_authorities"].update(
                {SELECTOR_ASSIGNMENT: replace(
                    data["candidate_selector_authorities"][SELECTOR_ASSIGNMENT],
                    demand_id="other_demand",
                )}
            ),
            lambda data: data["candidate_selector_authorities"].update(
                {SELECTOR_ASSIGNMENT: replace(
                    data["candidate_selector_authorities"][SELECTOR_ASSIGNMENT],
                    assigned_user_id="other_selector",
                )}
            ),
            lambda data: data["candidate_selector_authorities"].update(
                {SELECTOR_ASSIGNMENT: replace(
                    data["candidate_selector_authorities"][SELECTOR_ASSIGNMENT],
                    selection_id="other_selection",
                )}
            ),
            lambda data: data["candidate_selector_authorities"].update(
                {SELECTOR_ASSIGNMENT: replace(
                    data["candidate_selector_authorities"][SELECTOR_ASSIGNMENT],
                    aggregate_version=SELECTOR_ASSIGNMENT_VERSION + 1,
                )}
            ),
            lambda data: data["candidate_selector_authorities"].update(
                {SELECTOR_ASSIGNMENT: replace(
                    data["candidate_selector_authorities"][SELECTOR_ASSIGNMENT],
                    authority_marker_sha256="not-a-marker",
                )}
            ),
        ):
            state = seed()
            mutation(state)
            factory = MemoryUowFactory(state)
            before = factory.store.snapshot()
            self.assertEqual(
                code(lambda: coordinator(factory).handle(
                    actor=actor(), command=command()
                )),
                "ACCESS_DENIED",
            )
            self.assertEqual(factory.store.snapshot(), before)

    def test_demand_owner_fact_is_not_a_candidate_selector_backdoor(self) -> None:
        state = seed()
        state["candidate_selector_authorities"].clear()
        state["original_actor_authorities"] = {
            OWNER: {
                "actor_id": OWNER,
                "organization_id": ORG,
                "demand_id": DEMAND,
                "selection_id": SELECTION,
                "role_code": "DEMAND_OWNER",
                "status": "ACTIVE",
            }
        }
        factory = MemoryUowFactory(state)
        before = factory.store.snapshot()

        self.assertEqual(
            code(lambda: coordinator(factory).handle(
                actor=actor(), command=command()
            )),
            "ACCESS_DENIED",
        )
        self.assertEqual(factory.store.snapshot(), before)

    def test_authority_and_hold_are_revalidated_after_lock_wait(self) -> None:
        factory = MemoryUowFactory()
        before = factory.store.snapshot()
        clock = ExpiringAfterFirstReadClock()

        self.assertEqual(
            code(lambda: coordinator(factory, clock=clock).handle(
                actor=actor(), command=command()
            )),
            "ACCESS_DENIED",
        )
        self.assertGreaterEqual(clock.calls, 2)
        self.assertEqual(factory.store.snapshot(), before)

        revoked = replace(
            seed()["candidate_selector_authorities"][SELECTOR_ASSIGNMENT],
            status="REVOKED",
        )
        changed = MemoryUowFactory()
        changed.locked_replacements.append(
            ("candidate_selector_authorities", SELECTOR_ASSIGNMENT, revoked)
        )
        before_changed = changed.store.snapshot()
        self.assertEqual(
            code(lambda: coordinator(changed).handle(
                actor=actor(), command=command()
            )),
            "ACCESS_DENIED",
        )
        self.assertEqual(changed.store.snapshot(), before_changed)

        hold_state = seed()
        hold_state["system_authorities"][SYSTEM_ACTOR] = replace(
            hold_state["system_authorities"][SYSTEM_ACTOR],
            valid_until=NOW + timedelta(minutes=20),
        )
        hold_state["candidate_selector_authorities"][SELECTOR_ASSIGNMENT] = replace(
            hold_state["candidate_selector_authorities"][SELECTOR_ASSIGNMENT],
            expires_at=NOW + timedelta(minutes=20),
        )
        expired_hold = MemoryUowFactory(hold_state)
        self.assertEqual(
            code(lambda: coordinator(
                expired_hold,
                clock=ExpiringAfterFirstReadClock(),
            ).handle(actor=actor(), command=command())),
            "PRECONDITION_FAILED",
        )

        backward = MemoryUowFactory()
        self.assertEqual(
            code(lambda: coordinator(
                backward,
                clock=BackwardAfterFirstReadClock(),
            ).handle(actor=actor(), command=command())),
            "SERVICE_UNAVAILABLE",
        )

    def test_closed_pending_trigger_is_required(self) -> None:
        state = seed()
        state["pending_complete_selection_triggers"].clear()
        factory = MemoryUowFactory(state)
        before = factory.store.snapshot()
        self.assertEqual(
            code(lambda: coordinator(factory).handle(
                actor=actor(), command=command()
            )),
            "TRIGGER_INVALID",
        )
        self.assertEqual(factory.store.snapshot(), before)

    def test_exact_completed_choose_receipt_and_intent_are_required(self) -> None:
        mutations = (
            lambda data: data["choose_receipts"].update(
                {CHOOSE_RECEIPT: replace(
                    data["choose_receipts"][CHOOSE_RECEIPT], status="IN_PROGRESS"
                )}
            ),
            lambda data: data["selection_intents"].update(
                {SELECTION: replace(
                    data["selection_intents"][SELECTION],
                    choose_command_id="other_choose_command",
                )}
            ),
            lambda data: data["selection_intents"].update(
                {SELECTION: replace(
                    data["selection_intents"][SELECTION],
                    actor_id="other_owner",
                )}
            ),
        )
        for mutation in mutations:
            state = seed()
            mutation(state)
            factory = MemoryUowFactory(state)
            before = factory.store.snapshot()
            self.assertEqual(
                code(lambda: coordinator(factory).handle(
                    actor=actor(), command=command()
                )),
                "TRIGGER_INVALID",
            )
            self.assertEqual(factory.store.snapshot(), before)

    def test_wrong_run_unaccepted_and_cross_attempt_invitation_all_roll_back(self) -> None:
        mutations = (
            lambda data: data["invitations"].update(
                {INVITATION: replace(
                    data["invitations"][INVITATION], run_id="other_run"
                )}
            ),
            lambda data: data["invitations"].update(
                {INVITATION: replace(
                    data["invitations"][INVITATION], status="SENT"
                )}
            ),
            lambda data: data["invitations"].update(
                {INVITATION: replace(
                    data["invitations"][INVITATION], attempt_id="other_attempt"
                )}
            ),
            lambda data: data["runs"].update(
                {RUN: replace(
                    data["runs"][RUN], superseded_by_run_id="newer_run"
                )}
            ),
        )
        for mutation in mutations:
            state = seed()
            mutation(state)
            factory = MemoryUowFactory(state)
            before = factory.store.snapshot()
            self.assertEqual(
                code(lambda: coordinator(factory).handle(
                    actor=actor(), command=command()
                )),
                "SELECTION_NOT_READY",
            )
            self.assertEqual(factory.store.snapshot(), before)

    def test_selection_attempt_and_demand_version_drift_fail_closed(self) -> None:
        mutations = (
            ("selections", SELECTION, "aggregate_version", 4),
            ("attempts", ATTEMPT, "aggregate_version", 6),
            ("demands", DEMAND, "aggregate_version", 12),
            ("demands", DEMAND, "matching_request_version", 3),
            ("demands", DEMAND, "funding_id", "replacement_funding"),
        )
        for collection, key, field, value in mutations:
            state = seed()
            state[collection][key] = replace(
                state[collection][key], **{field: value}
            )
            factory = MemoryUowFactory(state)
            before = factory.store.snapshot()
            self.assertEqual(
                code(lambda: coordinator(factory).handle(
                    actor=actor(), command=command()
                )),
                "PRECONDITION_FAILED",
            )
            self.assertEqual(factory.store.snapshot(), before)

    def test_corrupt_open_selection_and_snapshot_digest_drift_fail_closed(self) -> None:
        mutations = (
            lambda data: data["selections"].update(
                {SELECTION: replace(
                    data["selections"][SELECTION],
                    chosen_invitation_id=INVITATION,
                )}
            ),
            lambda data: data["selections"].update(
                {SELECTION: replace(
                    data["selections"][SELECTION],
                    selection_basis_code="ALGORITHM_TOP",
                )}
            ),
            lambda data: data["selections"].update(
                {SELECTION: replace(
                    data["selections"][SELECTION], decision_actor_id=OWNER
                )}
            ),
            lambda data: data["runs"].update(
                {RUN: replace(
                    data["runs"][RUN], input_set_sha256="f" * 64
                )}
            ),
            lambda data: data["invitations"].update(
                {INVITATION: replace(
                    data["invitations"][INVITATION],
                    candidate_result_sha256="f" * 64,
                )}
            ),
        )
        for mutation in mutations:
            state = seed()
            mutation(state)
            factory = MemoryUowFactory(state)
            before = factory.store.snapshot()
            self.assertEqual(
                code(lambda: coordinator(factory).handle(
                    actor=actor(), command=command()
                )),
                "SELECTION_NOT_READY",
            )
            self.assertEqual(factory.store.snapshot(), before)

    def test_current_invitation_set_is_recomputed_inside_the_locks(self) -> None:
        added = seed()
        added["invitations"]["business_invitation_0002"] = replace(
            added["invitations"][INVITATION],
            invitation_id="business_invitation_0002",
            status="SENT",
            aggregate_version=2,
        )
        snapshot_changed = seed()
        snapshot_changed["invitations"][INVITATION] = replace(
            snapshot_changed["invitations"][INVITATION],
            snapshot_sha256="7" * 64,
        )
        for state in (added, snapshot_changed):
            factory = MemoryUowFactory(state)
            before = factory.store.snapshot()
            self.assertEqual(
                code(lambda: coordinator(factory).handle(
                    actor=actor(), command=command()
                )),
                "PRECONDITION_FAILED",
            )
            self.assertEqual(factory.store.snapshot(), before)

        completed_factory = MemoryUowFactory()
        coordinator(completed_factory).handle(actor=actor(), command=command())
        completed = completed_factory.store.snapshot()
        completed["invitations"]["business_invitation_0002"] = replace(
            completed["invitations"][INVITATION],
            invitation_id="business_invitation_0002",
            status="SENT",
            aggregate_version=2,
        )
        corrupted_replay = MemoryUowFactory(completed)
        self.assertEqual(
            code(lambda: coordinator(corrupted_replay).handle(
                actor=actor(), command=command()
            )),
            "PRECONDITION_FAILED",
        )

    def test_hold_binding_drift_or_expiry_rolls_back(self) -> None:
        for mutation in (
            lambda value: replace(
                value,
                hold_binding=replace(value.hold_binding, run_version=99),
            ),
            lambda value: replace(value, hold_valid_until=NOW),
            lambda value: replace(value, hold_decision="BLOCK"),
        ):
            state = seed()
            state["selection_intents"][SELECTION] = mutation(
                state["selection_intents"][SELECTION]
            )
            state["choose_receipts"][CHOOSE_RECEIPT] = replace(
                state["choose_receipts"][CHOOSE_RECEIPT],
                selection_intent_sha256=selection_intent_sha256(
                    state["selection_intents"][SELECTION]
                ),
            )
            state["pending_complete_selection_triggers"][CHOOSE_RECEIPT] = (
                PendingCompleteSelectionTrigger(
                    completion_command_id="complete_selection_command_0001",
                    status="READY",
                    recorded_at=NOW,
                    receipt=state["choose_receipts"][CHOOSE_RECEIPT],
                    intent=state["selection_intents"][SELECTION],
                )
            )
            factory = MemoryUowFactory(state)
            before = factory.store.snapshot()
            self.assertEqual(
                code(lambda: coordinator(factory).handle(
                    actor=actor(), command=command()
                )),
                "PRECONDITION_FAILED",
            )
            self.assertEqual(factory.store.snapshot(), before)

    def test_every_protocol_checkpoint_rolls_back_all_writes(self) -> None:
        for checkpoint in COMPLETE_SELECTION_CHECKPOINTS:
            factory = MemoryUowFactory()
            factory.fail_checkpoint = checkpoint
            before = factory.store.snapshot()
            error_code = code(lambda: coordinator(factory).handle(
                actor=actor(), command=command()
            ))
            self.assertEqual(error_code, "SERVICE_UNAVAILABLE", checkpoint)
            self.assertEqual(factory.store.snapshot(), before, checkpoint)

    def test_complete_replay_converges_but_every_partial_chain_is_rejected(self) -> None:
        factory = MemoryUowFactory()
        service = coordinator(factory)
        first = service.handle(actor=actor(), command=command())
        completed = factory.store.snapshot()
        second = service.handle(actor=actor(), command=command())
        self.assertTrue(second.replayed)
        self.assertEqual(second.project_id, first.project_id)

        removals = (
            ("projects", first.project_id),
            ("agreements", first.agreement_id),
            ("completion_records", CHOOSE_RECEIPT),
            ("coordination_audits", next(iter(completed["coordination_audits"]))),
            ("outbox", first.event_ids[0]),
        )
        for collection, identifier in removals:
            partial = deepcopy(completed)
            del partial[collection][identifier]
            partial_factory = MemoryUowFactory(partial)
            self.assertEqual(
                code(lambda: coordinator(partial_factory).handle(
                    actor=actor(), command=command()
                )),
                "RECOVERY_INCOMPLETE",
                collection,
            )

    def test_commit_unknown_requires_the_complete_durable_chain(self) -> None:
        durable = MemoryUowFactory()
        durable.commit_unknown = True
        durable.commit_unknown_durable = True
        result = coordinator(durable).handle(actor=actor(), command=command())
        self.assertTrue(result.replayed)
        self.assertEqual(len(durable.store.snapshot()["projects"]), 1)

        absent = MemoryUowFactory()
        absent.commit_unknown = True
        before = absent.store.snapshot()
        self.assertEqual(
            code(lambda: coordinator(absent).handle(
                actor=actor(), command=command()
            )),
            "COMMIT_OUTCOME_UNKNOWN",
        )
        self.assertEqual(absent.store.snapshot(), before)

    def test_recovery_rejects_corruption_and_duplicate_chain_facts(self) -> None:
        factory = MemoryUowFactory()
        first = coordinator(factory).handle(actor=actor(), command=command())
        completed = factory.store.snapshot()
        corruptions = []

        wrong_basis = deepcopy(completed)
        wrong_basis["selections"][SELECTION] = replace(
            wrong_basis["selections"][SELECTION], selection_basis_code=None
        )
        corruptions.append(wrong_basis)

        duplicate_project = deepcopy(completed)
        project = duplicate_project["projects"][first.project_id]
        duplicate_project["projects"]["other_project"] = replace(
            project,
            project_id="other_project",
            agreement_id="other_agreement",
        )
        corruptions.append(duplicate_project)

        duplicate_event = deepcopy(completed)
        event = duplicate_event["outbox"][first.event_ids[0]]
        duplicate_event["outbox"]["extra_event"] = replace(
            event, event_id="extra_event"
        )
        corruptions.append(duplicate_event)

        for corrupted in corruptions:
            corrupt_factory = MemoryUowFactory(corrupted)
            self.assertEqual(
                code(lambda: coordinator(corrupt_factory).handle(
                    actor=actor(), command=command()
                )),
                "RECOVERY_INCOMPLETE",
            )

    def test_recovery_chain_binds_the_complete_receipt_and_intent(self) -> None:
        factory = MemoryUowFactory()
        coordinator(factory).handle(actor=actor(), command=command())
        completed = factory.store.snapshot()

        changed_intent = deepcopy(completed)
        intent = replace(
            changed_intent["selection_intents"][SELECTION],
            hold_binding=replace(
                changed_intent["selection_intents"][SELECTION].hold_binding,
                selection_id="other_selection_0001",
            ),
        )
        receipt = replace(
            changed_intent["choose_receipts"][CHOOSE_RECEIPT],
            selection_intent_sha256=selection_intent_sha256(intent),
        )
        changed_intent["selection_intents"][SELECTION] = intent
        changed_intent["choose_receipts"][CHOOSE_RECEIPT] = receipt
        changed_intent["pending_complete_selection_triggers"][CHOOSE_RECEIPT] = (
            PendingCompleteSelectionTrigger(
                completion_command_id="complete_selection_command_0001",
                status="READY",
                recorded_at=NOW,
                receipt=receipt,
                intent=intent,
            )
        )

        changed_payload = deepcopy(completed)
        receipt = replace(
            changed_payload["choose_receipts"][CHOOSE_RECEIPT],
            payload_sha256="f" * 64,
        )
        changed_payload["choose_receipts"][CHOOSE_RECEIPT] = receipt
        changed_payload["pending_complete_selection_triggers"][CHOOSE_RECEIPT] = (
            PendingCompleteSelectionTrigger(
                completion_command_id="complete_selection_command_0001",
                status="READY",
                recorded_at=NOW,
                receipt=receipt,
                intent=changed_payload["selection_intents"][SELECTION],
            )
        )

        for corrupted in (changed_intent, changed_payload):
            corrupt_factory = MemoryUowFactory(corrupted)
            self.assertEqual(
                code(lambda: coordinator(corrupt_factory).handle(
                    actor=actor(), command=command()
                )),
                "RECOVERY_INCOMPLETE",
            )

    def test_two_overlapping_transactions_converge_on_one_unique_project(self) -> None:
        factory = MemoryUowFactory()
        factory.commit_barrier = Barrier(2)
        shared = coordinator(factory)
        results: list[Any] = []
        errors: list[BaseException] = []

        def run_once() -> None:
            try:
                results.append(shared.handle(actor=actor(), command=command()))
            except BaseException as error:  # pragma: no cover - diagnostic
                errors.append(error)

        threads = (Thread(target=run_once), Thread(target=run_once))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        self.assertFalse(errors)
        self.assertEqual(len(results), 2)
        self.assertEqual({result.project_id for result in results}, {results[0].project_id})
        self.assertEqual(sorted(result.replayed for result in results), [False, True])
        snapshot = factory.store.snapshot()
        self.assertEqual(len(snapshot["projects"]), 1)
        self.assertEqual(len(snapshot["agreements"]), 1)

    def test_competing_completion_key_cannot_claim_the_winning_project(self) -> None:
        factory = MemoryUowFactory()
        shared = coordinator(factory)
        self.assertEqual(
            code(lambda: shared.handle(
                actor=actor(),
                command=command(
                    completion_command_id="competing_completion_command"
                ),
            )),
            "TRIGGER_INVALID",
        )
        self.assertEqual(len(factory.store.snapshot().get("projects", {})), 0)
        result = shared.handle(actor=actor(), command=command())
        snapshot = factory.store.snapshot()
        self.assertEqual(len(snapshot["projects"]), 1)
        self.assertEqual(len(snapshot["agreements"]), 1)
        record = next(iter(snapshot["completion_records"].values()))
        self.assertEqual(record.completion_command_id, command().completion_command_id)
        self.assertEqual(result.project_id, record.project_id)

    def test_private_credentials_and_dependency_details_never_escape(self) -> None:
        self.assertNotIn(SYSTEM_CREDENTIAL, repr(actor()))
        factory = MemoryUowFactory()
        factory.fail_checkpoint = "project_agreement_write"
        try:
            coordinator(factory).handle(actor=actor(), command=command())
        except CompleteSelectionError as error:
            rendered = f"{error!r} {error}"
        else:  # pragma: no cover - test guard
            self.fail("expected error")
        self.assertNotIn("private secret", rendered.lower())
        self.assertNotIn(SYSTEM_CREDENTIAL, rendered)
        self.assertEqual(rendered.count("SERVICE_UNAVAILABLE"), 2)

        success = MemoryUowFactory()
        coordinator(success).handle(actor=actor(), command=command())
        persisted = success.store.snapshot()
        self.assertNotIn(
            SYSTEM_CREDENTIAL,
            repr(
                {
                    "audit": persisted["coordination_audits"],
                    "outbox": persisted["outbox"],
                    "completion": persisted["completion_records"],
                }
            ),
        )


if __name__ == "__main__":
    unittest.main()
