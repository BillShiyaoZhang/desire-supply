"""Framework-neutral CompleteSelection composition primitive.

This module encodes the only cross-context atomic protocol currently allowed
by the architecture.  It deliberately stops at an injected unit-of-work port:
there is no HTTP route, database adapter, IAM adapter, or claim that this is a
production binding.  The Matching memory producer now persists the shared
closed trigger contract,
but the coordination outbox facts are not context-schema-validated envelopes.
Those limits are executable through the three ``*_AVAILABLE``/``*_COMPATIBLE``
flags below; PostgreSQL uniqueness, RLS, serialization, and recovery still
require a real production binding and real PostgreSQL 18 tests.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, field, is_dataclass, replace
from datetime import datetime, timedelta
import hashlib
import json
from typing import Any, ContextManager, Mapping, Optional, Protocol, Sequence, Tuple

from .selection_trigger import (
    ChooseReceiptFact,
    PendingCompleteSelectionTrigger,
    SelectionHoldBinding,
    SelectionIntentFact,
    pending_complete_selection_trigger_sha256,
    selection_intent_sha256,
)


COMPLETE_SELECTION_PRODUCTION_BINDING_AVAILABLE = False
# The Matching memory producer persists the same closed receipt/intent/hold
# dataclasses consumed by this primitive.  This says nothing about PostgreSQL,
# RLS, process composition, or production enablement.
COMPLETE_SELECTION_TRIGGER_PRODUCER_COMPATIBLE = True
# This primitive emits closed coordination facts only.  Context-owned event
# schema adapters and validators do not yet exist, so these are not claimed as
# matching-v1/demand-v1 production envelopes.
COMPLETE_SELECTION_CONTEXT_EVENT_BINDINGS_AVAILABLE = False

COMPLETE_SELECTION_CHECKPOINTS = (
    "authority_and_trigger",
    "candidate_selector_lock",
    "selection_lock",
    "attempt_lock",
    "demand_lock",
    "hold_revalidation",
    "matching_write",
    "project_agreement_write",
    "demand_write",
    "audit_outbox_write",
    "receipt_complete",
    "commit",
)


class CompleteSelectionError(RuntimeError):
    """Closed, secret-safe application rejection."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class CompleteSelectionStorageError(Exception):
    """Storage failed before COMMIT had an acknowledged durable result."""


class CompleteSelectionCommitOutcomeUnknownError(Exception):
    """COMMIT was sent but its durable result was not acknowledged."""


class CompleteSelectionUniqueConflictError(Exception):
    """A storage uniqueness guard observed a competing completion."""


@dataclass(frozen=True)
class CompleteSelectionActor:
    actor_kind: str
    actor_id: str
    workload_credential_id: str = field(repr=False)
    organization_id: str = ""
    original_actor_id: str = ""
    correlation_id: str = ""
    causation_id: str = ""
    trace_id: str = ""


@dataclass(frozen=True)
class CompleteSelectionCommand:
    completion_command_id: str
    choose_receipt_id: str
    choose_command_id: str
    selection_id: str
    expected_selection_version: int
    attempt_id: str
    expected_attempt_version: int
    invitation_id: str
    run_id: str
    demand_id: str
    expected_demand_version: int
    demand_version_id: str
    matching_request_id: str
    matching_request_version: int
    funding_id: str
    candidate_selector_assignment_id: str
    expected_candidate_selector_assignment_version: int


@dataclass(frozen=True)
class SystemCoordinatorAuthorityFact:
    actor_id: str
    workload_credential_id: str = field(repr=False)
    operation: str = ""
    organization_id: str = ""
    selection_id: str = ""
    attempt_id: str = ""
    status: str = ""
    valid_until: Optional[datetime] = None


@dataclass(frozen=True)
class CandidateSelectorAuthorityFact:
    """Current exact, resource-scoped authority used by CompleteSelection."""

    assignment_id: str
    aggregate_version: int
    status: str
    role_code: str
    assigned_user_id: str
    organization_id: str
    demand_id: str
    selection_id: str
    authority_marker_sha256: str = field(repr=False)
    assigned_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class SelectionSelectionFact:
    selection_id: str
    organization_id: str
    attempt_id: str
    status: str
    aggregate_version: int
    current_invitation_set_sha256: str
    chosen_invitation_id: Optional[str]
    selection_basis_code: Optional[str]
    decision_actor_id: Optional[str]
    updated_at: datetime
    candidate_selector_assignment_id: Optional[str] = None
    candidate_selector_assignment_version: Optional[int] = None


@dataclass(frozen=True)
class AttemptSelectionFact:
    attempt_id: str
    organization_id: str
    demand_id: str
    demand_version_id: str
    matching_request_id: str
    matching_request_version: int
    funding_id: str
    status: str
    aggregate_version: int
    current_run_id: str
    selection_id: str
    updated_at: datetime


@dataclass(frozen=True)
class InvitationSelectionFact:
    invitation_id: str
    organization_id: str
    attempt_id: str
    run_id: str
    creator_user_id: str
    demand_id: str
    demand_version_id: str
    funding_id: str
    matching_rule_bundle_id: str
    candidate_result_sha256: str = field(repr=False)
    snapshot_sha256: str = field(repr=False)
    status: str
    aggregate_version: int


@dataclass(frozen=True)
class RunSelectionFact:
    run_id: str
    attempt_id: str
    status: str
    aggregate_version: int
    superseded_by_run_id: Optional[str]
    matching_rule_bundle_id: str
    rule_manifest_sha256: str = field(repr=False)
    input_set_sha256: str = field(repr=False)
    ordered_result_sha256: str = field(repr=False)


@dataclass(frozen=True)
class DemandSelectionFact:
    demand_id: str
    organization_id: str
    demand_version_id: str
    status: str
    aggregate_version: int
    funding_id: str
    funding_status: str
    matching_request_id: str
    matching_request_version: int
    updated_at: datetime


@dataclass(frozen=True)
class ProjectShell:
    project_id: str
    selection_id: str
    organization_id: str
    demand_id: str
    demand_version_id: str
    creator_user_id: str
    agreement_id: str
    status: str
    aggregate_version: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class AgreementRoot:
    agreement_id: str
    project_id: str
    status: str
    aggregate_version: int
    current_agreement_version_id: Optional[str]
    current_open_version_id: Optional[str]
    next_version_no: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class CoordinationOutboxEvent:
    event_id: str
    schema_version: int
    owning_context: str
    event_type: str
    aggregate_type: str
    aggregate_id: str
    aggregate_version: int
    actor_kind: str
    actor_id: str
    original_actor_id: str
    organization_id: str
    correlation_id: str
    causation_id: str
    trace_id: str
    occurred_at: datetime
    payload: Tuple[Tuple[str, str | int | None], ...]


@dataclass(frozen=True)
class CrossContextSelectionAudit:
    audit_id: str
    operation: str
    choose_receipt_id: str
    choose_command_id: str
    completion_command_id: str
    selection_id: str
    attempt_id: str
    invitation_id: str
    run_id: str
    demand_id: str
    project_id: str
    agreement_id: str
    matching_rule_bundle_id: str
    candidate_selector_assignment_id: str
    candidate_selector_assignment_version: int
    rule_manifest_sha256: str = field(repr=False)
    input_set_sha256: str = field(repr=False)
    ordered_result_sha256: str = field(repr=False)
    candidate_result_sha256: str = field(repr=False)
    current_invitation_set_sha256: str = field(repr=False)
    selection_basis_code: str
    actor_kind: str
    actor_id: str
    original_actor_id: str
    organization_id: str
    correlation_id: str
    causation_id: str
    trace_id: str
    result_code: str
    occurred_at: datetime


@dataclass(frozen=True)
class CompleteSelectionRecord:
    choose_receipt_id: str
    choose_command_id: str
    completion_command_id: str
    selection_id: str
    attempt_id: str
    demand_id: str
    project_id: str
    agreement_id: str
    audit_id: str
    event_ids: Tuple[str, ...]
    correlation_id: str
    original_actor_id: str
    candidate_selector_assignment_id: str
    candidate_selector_assignment_version: int
    status: str
    trigger_sha256: str = field(repr=False)
    chain_sha256: str = field(repr=False)
    completed_at: datetime = field(default_factory=datetime.now)


@dataclass(frozen=True)
class CompleteSelectionResult:
    selection_id: str
    project_id: str
    agreement_id: str
    selection_version: int
    attempt_version: int
    demand_version: int
    candidate_selector_assignment_id: str
    candidate_selector_assignment_version: int
    event_ids: Tuple[str, ...]
    completed_at: datetime
    replayed: bool


class CompleteSelectionUnitOfWork(Protocol):
    def checkpoint(self, name: str) -> None: ...
    def lock(self, resource: str, keys: Sequence[str]) -> None: ...
    def get(self, collection: str, key: str) -> Any: ...
    def values(self, collection: str) -> Tuple[Any, ...]: ...
    def put(self, collection: str, key: str, value: Any) -> None: ...
    def commit(self) -> None: ...


class CompleteSelectionUnitOfWorkFactory(Protocol):
    def begin(self) -> ContextManager[CompleteSelectionUnitOfWork]: ...


class CompleteSelectionRecoveryReader(Protocol):
    def snapshot(self) -> Mapping[str, Mapping[str, Any]]: ...


class CompleteSelectionClock(Protocol):
    def now(self) -> datetime: ...


class CompleteSelectionIdSource(Protocol):
    def next_id(self, kind: str) -> str: ...


@dataclass(frozen=True)
class _AllocatedIds:
    project_id: str
    agreement_id: str
    audit_id: str
    event_ids: Tuple[str, ...]


class CompleteSelectionCoordinator:
    """Coordinate one exact ChooseCreator trigger in one injected transaction."""

    def __init__(
        self,
        *,
        uow_factory: CompleteSelectionUnitOfWorkFactory,
        recovery_reader: CompleteSelectionRecoveryReader,
        clock: CompleteSelectionClock,
        id_source: CompleteSelectionIdSource,
    ) -> None:
        self._uow_factory = uow_factory
        self._recovery_reader = recovery_reader
        self._clock = clock
        self._id_source = id_source

    def handle(
        self,
        *,
        actor: CompleteSelectionActor,
        command: CompleteSelectionCommand,
    ) -> CompleteSelectionResult:
        now = self._utc_now()
        try:
            with self._uow_factory.begin() as uow:
                uow.checkpoint("authority_and_trigger")
                receipt, intent, trigger = self._validate_trigger(
                    get=uow.get,
                    actor=actor,
                    command=command,
                    now=now,
                )
                allocated = self._allocate_ids()

                uow.checkpoint("candidate_selector_lock")
                uow.lock(
                    "matching.candidate_selector_assignment",
                    (command.candidate_selector_assignment_id,),
                )

                uow.checkpoint("selection_lock")
                uow.lock("matching.selection", (command.selection_id,))
                selection = self._typed_get(
                    uow.get,
                    "selections",
                    command.selection_id,
                    SelectionSelectionFact,
                    "SELECTION_NOT_READY",
                )

                uow.checkpoint("attempt_lock")
                uow.lock("matching.attempt", (command.attempt_id,))
                attempt = self._typed_get(
                    uow.get,
                    "attempts",
                    command.attempt_id,
                    AttemptSelectionFact,
                    "SELECTION_NOT_READY",
                )

                uow.checkpoint("demand_lock")
                uow.lock("demand.demand", (command.demand_id,))
                demand = self._typed_get(
                    uow.get,
                    "demands",
                    command.demand_id,
                    DemandSelectionFact,
                    "SELECTION_NOT_READY",
                )

                # Authority and hold lifetimes are security facts, not request
                # start-time facts.  Lock waits must not let an expired or
                # revoked grant pass on the timestamp captured above.
                locked_now = self._utc_now()
                if locked_now < now:
                    raise CompleteSelectionError("SERVICE_UNAVAILABLE")
                now = locked_now
                locked_receipt, locked_intent, locked_trigger = (
                    self._validate_trigger(
                        get=uow.get,
                        actor=actor,
                        command=command,
                        now=now,
                    )
                )
                if (
                    locked_receipt != receipt
                    or locked_intent != intent
                    or locked_trigger != trigger
                ):
                    raise CompleteSelectionError("TRIGGER_INVALID")
                receipt, intent, trigger = (
                    locked_receipt,
                    locked_intent,
                    locked_trigger,
                )

                uow.checkpoint("hold_revalidation")
                invitation = self._typed_get(
                    uow.get,
                    "invitations",
                    command.invitation_id,
                    InvitationSelectionFact,
                    "SELECTION_NOT_READY",
                )
                run = self._typed_get(
                    uow.get,
                    "runs",
                    command.run_id,
                    RunSelectionFact,
                    "SELECTION_NOT_READY",
                )
                self._validate_static_chain(
                    actor=actor,
                    command=command,
                    receipt=receipt,
                    intent=intent,
                    selection=selection,
                    attempt=attempt,
                    invitation=invitation,
                    run=run,
                    demand=demand,
                )
                current_invitation_set_sha256 = (
                    self._current_invitation_set_sha256(
                        values=uow.values,
                        actor=actor,
                        command=command,
                        run=run,
                    )
                )
                if (
                    selection.current_invitation_set_sha256
                    != current_invitation_set_sha256
                ):
                    raise CompleteSelectionError("PRECONDITION_FAILED")
                if self._completion_is_present(
                    values=uow.values,
                    get=uow.get,
                    command=command,
                    selection=selection,
                    attempt=attempt,
                    demand=demand,
                ):
                    return self._resolve_complete_chain(
                        get=uow.get,
                        values=uow.values,
                        actor=actor,
                        command=command,
                        receipt=receipt,
                        intent=intent,
                        trigger=trigger,
                        selection=selection,
                        attempt=attempt,
                        invitation=invitation,
                        run=run,
                        demand=demand,
                        replayed=True,
                    )
                self._validate_open_preconditions(
                    command=command,
                    receipt=receipt,
                    intent=intent,
                    selection=selection,
                    attempt=attempt,
                    invitation=invitation,
                    run=run,
                    demand=demand,
                    now=now,
                    current_invitation_set_sha256=(
                        current_invitation_set_sha256
                    ),
                )

                selected_selection = replace(
                    selection,
                    status="SELECTED",
                    aggregate_version=selection.aggregate_version + 1,
                    chosen_invitation_id=invitation.invitation_id,
                    selection_basis_code=intent.selection_basis_code,
                    decision_actor_id=actor.original_actor_id,
                    updated_at=now,
                    candidate_selector_assignment_id=(
                        command.candidate_selector_assignment_id
                    ),
                    candidate_selector_assignment_version=(
                        command.expected_candidate_selector_assignment_version
                    ),
                )
                selected_attempt = replace(
                    attempt,
                    status="SELECTED",
                    aggregate_version=attempt.aggregate_version + 1,
                    updated_at=now,
                )
                matched_demand = replace(
                    demand,
                    status="MATCHED",
                    aggregate_version=demand.aggregate_version + 1,
                    updated_at=now,
                )
                project = ProjectShell(
                    project_id=allocated.project_id,
                    selection_id=selection.selection_id,
                    organization_id=actor.organization_id,
                    demand_id=demand.demand_id,
                    demand_version_id=demand.demand_version_id,
                    creator_user_id=invitation.creator_user_id,
                    agreement_id=allocated.agreement_id,
                    status="PENDING_AGREEMENT",
                    aggregate_version=1,
                    created_at=now,
                    updated_at=now,
                )
                agreement = AgreementRoot(
                    agreement_id=allocated.agreement_id,
                    project_id=allocated.project_id,
                    status="EMPTY",
                    aggregate_version=1,
                    current_agreement_version_id=None,
                    current_open_version_id=None,
                    next_version_no=1,
                    created_at=now,
                    updated_at=now,
                )

                uow.checkpoint("matching_write")
                uow.put("selections", selection.selection_id, selected_selection)
                uow.put("attempts", attempt.attempt_id, selected_attempt)

                uow.checkpoint("project_agreement_write")
                if any(
                    isinstance(item, ProjectShell)
                    and item.selection_id == selection.selection_id
                    for item in uow.values("projects")
                ):
                    raise CompleteSelectionUniqueConflictError(
                        "selection project already exists"
                    )
                uow.put("projects", project.project_id, project)
                uow.put("agreements", agreement.agreement_id, agreement)

                uow.checkpoint("demand_write")
                uow.put("demands", demand.demand_id, matched_demand)

                audit = self._audit(
                    allocated=allocated,
                    actor=actor,
                    command=command,
                    intent=intent,
                    selection=selection,
                    invitation=invitation,
                    run=run,
                    now=now,
                )
                events = self._events(
                    allocated=allocated,
                    actor=actor,
                    command=command,
                    selection=selected_selection,
                    attempt=selected_attempt,
                    project=project,
                    agreement=agreement,
                    demand=matched_demand,
                    now=now,
                )
                uow.checkpoint("audit_outbox_write")
                uow.put("coordination_audits", audit.audit_id, audit)
                for event in events:
                    uow.put("outbox", event.event_id, event)

                chain_sha256 = self._chain_sha256(
                    receipt=receipt,
                    intent=intent,
                    trigger=trigger,
                    selection=selected_selection,
                    attempt=selected_attempt,
                    demand=matched_demand,
                    project=project,
                    agreement=agreement,
                    audit=audit,
                    events=events,
                )
                record = CompleteSelectionRecord(
                    choose_receipt_id=command.choose_receipt_id,
                    choose_command_id=command.choose_command_id,
                    completion_command_id=command.completion_command_id,
                    selection_id=command.selection_id,
                    attempt_id=command.attempt_id,
                    demand_id=command.demand_id,
                    project_id=project.project_id,
                    agreement_id=agreement.agreement_id,
                    audit_id=audit.audit_id,
                    event_ids=tuple(event.event_id for event in events),
                    correlation_id=actor.correlation_id,
                    original_actor_id=actor.original_actor_id,
                    candidate_selector_assignment_id=(
                        command.candidate_selector_assignment_id
                    ),
                    candidate_selector_assignment_version=(
                        command.expected_candidate_selector_assignment_version
                    ),
                    status="COMPLETED",
                    trigger_sha256=(
                        pending_complete_selection_trigger_sha256(trigger)
                    ),
                    chain_sha256=chain_sha256,
                    completed_at=now,
                )
                uow.checkpoint("receipt_complete")
                uow.put(
                    "completion_records",
                    command.choose_receipt_id,
                    record,
                )

                result = self._result(
                    selection=selected_selection,
                    attempt=selected_attempt,
                    demand=matched_demand,
                    record=record,
                    replayed=False,
                )
                uow.checkpoint("commit")
                uow.commit()
                return result
        except CompleteSelectionError:
            raise
        except CompleteSelectionCommitOutcomeUnknownError:
            return self._recover(
                actor=actor,
                command=command,
                missing_code="COMMIT_OUTCOME_UNKNOWN",
            )
        except CompleteSelectionUniqueConflictError:
            return self._recover(
                actor=actor,
                command=command,
                missing_code="RECOVERY_INCOMPLETE",
            )
        except CompleteSelectionStorageError:
            raise CompleteSelectionError("SERVICE_UNAVAILABLE") from None
        except Exception:
            raise CompleteSelectionError("SERVICE_UNAVAILABLE") from None

    def _validate_trigger(
        self,
        *,
        get: Any,
        actor: CompleteSelectionActor,
        command: CompleteSelectionCommand,
        now: datetime,
    ) -> tuple[
        ChooseReceiptFact,
        SelectionIntentFact,
        PendingCompleteSelectionTrigger,
    ]:
        system = get("system_authorities", actor.actor_id)
        selector = get(
            "candidate_selector_authorities",
            command.candidate_selector_assignment_id,
        )
        if (
            actor.actor_kind != "SYSTEM"
            or not isinstance(system, SystemCoordinatorAuthorityFact)
            or system.actor_id != actor.actor_id
            or system.workload_credential_id != actor.workload_credential_id
            or system.operation != "COMPLETE_SELECTION"
            or system.organization_id != actor.organization_id
            or system.selection_id != command.selection_id
            or system.attempt_id != command.attempt_id
            or system.status != "ACTIVE"
            or system.valid_until is None
            or system.valid_until <= now
            or not isinstance(selector, CandidateSelectorAuthorityFact)
            or selector.assignment_id
            != command.candidate_selector_assignment_id
            or not command.candidate_selector_assignment_id
            or not isinstance(
                command.expected_candidate_selector_assignment_version,
                int,
            )
            or isinstance(
                command.expected_candidate_selector_assignment_version,
                bool,
            )
            or command.expected_candidate_selector_assignment_version < 1
            or selector.aggregate_version
            != command.expected_candidate_selector_assignment_version
            or not isinstance(selector.aggregate_version, int)
            or isinstance(selector.aggregate_version, bool)
            or selector.aggregate_version < 1
            or selector.status != "ACTIVE"
            or selector.role_code != "CANDIDATE_SELECTOR"
            or selector.assigned_user_id != actor.original_actor_id
            or selector.organization_id != actor.organization_id
            or selector.demand_id != command.demand_id
            or selector.selection_id != command.selection_id
            or not _is_sha256(selector.authority_marker_sha256)
            or not _is_utc_datetime(selector.assigned_at)
            or not _is_utc_datetime(selector.expires_at)
            or selector.assigned_at > now
            or selector.expires_at <= now
        ):
            raise CompleteSelectionError("ACCESS_DENIED")

        receipt = get("choose_receipts", command.choose_receipt_id)
        intent = get("selection_intents", command.selection_id)
        trigger = get(
            "pending_complete_selection_triggers",
            command.choose_receipt_id,
        )
        if (
            not isinstance(receipt, ChooseReceiptFact)
            or not isinstance(intent, SelectionIntentFact)
            or not isinstance(trigger, PendingCompleteSelectionTrigger)
        ):
            raise CompleteSelectionError("TRIGGER_INVALID")
        receipt_expected = (
            command.choose_receipt_id,
            command.choose_command_id,
            "CHOOSE_CREATOR",
            "COMPLETED",
            actor.original_actor_id,
            actor.organization_id,
            actor.correlation_id,
            command.selection_id,
            command.attempt_id,
            command.invitation_id,
            command.run_id,
            command.expected_selection_version,
            command.expected_attempt_version,
            command.expected_demand_version,
            command.demand_id,
            command.demand_version_id,
            command.matching_request_id,
            command.matching_request_version,
            command.funding_id,
            receipt.matching_rule_bundle_id,
            command.candidate_selector_assignment_id,
            command.expected_candidate_selector_assignment_version,
            selector.authority_marker_sha256,
        )
        receipt_actual = (
            receipt.receipt_id,
            receipt.command_id,
            receipt.operation,
            receipt.status,
            receipt.actor_id,
            receipt.organization_id,
            receipt.correlation_id,
            receipt.selection_id,
            receipt.attempt_id,
            receipt.invitation_id,
            receipt.run_id,
            receipt.expected_selection_version,
            receipt.expected_attempt_version,
            receipt.expected_demand_version,
            receipt.demand_id,
            receipt.demand_version_id,
            receipt.matching_request_id,
            receipt.matching_request_version,
            receipt.funding_id,
            receipt.matching_rule_bundle_id,
            receipt.candidate_selector_assignment_id,
            receipt.candidate_selector_assignment_version,
            receipt.candidate_selector_authority_marker_sha256,
        )
        if (
            receipt_actual != receipt_expected
            or not all(
                _is_sha256(value)
                for value in (
                    receipt.payload_sha256,
                    receipt.selection_intent_sha256,
                    receipt.rule_manifest_sha256,
                    receipt.input_set_sha256,
                    receipt.ordered_result_sha256,
                    receipt.candidate_result_sha256,
                    receipt.candidate_selector_authority_marker_sha256,
                )
            )
            or receipt.selection_intent_sha256
            != selection_intent_sha256(intent)
            or actor.causation_id != command.choose_command_id
            or trigger.completion_command_id != command.completion_command_id
            or trigger.status != "READY"
            or trigger.receipt != receipt
            or trigger.intent != intent
            or not _is_utc_datetime(trigger.recorded_at)
            or not _is_utc_datetime(intent.hold_valid_until)
            or trigger.recorded_at > now
            or trigger.recorded_at > intent.hold_valid_until
            or intent.hold_binding.candidate_selector_assignment_id
            != command.candidate_selector_assignment_id
            or intent.hold_binding.candidate_selector_assignment_version
            != command.expected_candidate_selector_assignment_version
            or intent.hold_binding.candidate_selector_authority_marker_sha256
            != selector.authority_marker_sha256
            or (
                intent.selection_id,
                intent.receipt_id,
                intent.choose_command_id,
                intent.event_type,
                intent.status,
                intent.actor_id,
                intent.organization_id,
                intent.attempt_id,
                intent.invitation_id,
                intent.run_id,
            )
            != (
                command.selection_id,
                command.choose_receipt_id,
                command.choose_command_id,
                "SelectionIntentRecorded",
                "COMPLETED",
                actor.original_actor_id,
                actor.organization_id,
                command.attempt_id,
                command.invitation_id,
                command.run_id,
            )
            or not intent.selection_basis_code
        ):
            raise CompleteSelectionError("TRIGGER_INVALID")
        return receipt, intent, trigger

    def _utc_now(self) -> datetime:
        try:
            value = self._clock.now()
        except Exception:
            raise CompleteSelectionError("SERVICE_UNAVAILABLE") from None
        if not _is_utc_datetime(value):
            raise CompleteSelectionError("SERVICE_UNAVAILABLE")
        return value

    @staticmethod
    def _validate_static_chain(
        *,
        actor: CompleteSelectionActor,
        command: CompleteSelectionCommand,
        receipt: ChooseReceiptFact,
        intent: SelectionIntentFact,
        selection: SelectionSelectionFact,
        attempt: AttemptSelectionFact,
        invitation: InvitationSelectionFact,
        run: RunSelectionFact,
        demand: DemandSelectionFact,
    ) -> None:
        if (
            selection.selection_id != command.selection_id
            or selection.organization_id != actor.organization_id
            or selection.attempt_id != command.attempt_id
            or attempt.attempt_id != command.attempt_id
            or attempt.organization_id != actor.organization_id
            or attempt.selection_id != command.selection_id
            or invitation.invitation_id != command.invitation_id
            or invitation.organization_id != actor.organization_id
            or invitation.attempt_id != command.attempt_id
            or invitation.run_id != command.run_id
            or invitation.status != "ACCEPTED"
            or run.run_id != command.run_id
            or run.attempt_id != command.attempt_id
            or run.status != "COMPLETED"
            or run.superseded_by_run_id is not None
            or attempt.current_run_id != command.run_id
            or invitation.matching_rule_bundle_id
            != run.matching_rule_bundle_id
            or receipt.matching_rule_bundle_id
            != run.matching_rule_bundle_id
            or receipt.rule_manifest_sha256 != run.rule_manifest_sha256
            or receipt.input_set_sha256 != run.input_set_sha256
            or receipt.ordered_result_sha256
            != run.ordered_result_sha256
            or receipt.candidate_result_sha256
            != invitation.candidate_result_sha256
            or intent.hold_binding.matching_rule_bundle_id
            != run.matching_rule_bundle_id
            or intent.hold_binding.rule_manifest_sha256
            != run.rule_manifest_sha256
            or intent.hold_binding.input_set_sha256
            != run.input_set_sha256
            or intent.hold_binding.ordered_result_sha256
            != run.ordered_result_sha256
            or intent.hold_binding.candidate_result_sha256
            != invitation.candidate_result_sha256
            or demand.demand_id != command.demand_id
            or demand.organization_id != actor.organization_id
        ):
            raise CompleteSelectionError("SELECTION_NOT_READY")

    @staticmethod
    def _current_invitation_set_sha256(
        *,
        values: Any,
        actor: CompleteSelectionActor,
        command: CompleteSelectionCommand,
        run: RunSelectionFact,
    ) -> str:
        # Local import prevents the shared producer fact module from creating a
        # Matching -> coordination -> Matching import cycle.
        from desire_platform.matching.domain import (
            InvitationStatus,
            SelectionInvitationSetEntry,
            selection_invitation_set_sha256,
        )

        entries = []
        for item in values("invitations"):
            if not isinstance(item, InvitationSelectionFact):
                raise CompleteSelectionError("SELECTION_NOT_READY")
            if (
                item.attempt_id != command.attempt_id
                or item.run_id != command.run_id
            ):
                continue
            if (
                item.organization_id != actor.organization_id
                or item.demand_id != command.demand_id
                or item.demand_version_id != command.demand_version_id
                or item.funding_id != command.funding_id
                or item.matching_rule_bundle_id
                != run.matching_rule_bundle_id
                or not _is_sha256(item.snapshot_sha256)
            ):
                raise CompleteSelectionError("SELECTION_NOT_READY")
            try:
                status = InvitationStatus(item.status)
            except (TypeError, ValueError):
                raise CompleteSelectionError("SELECTION_NOT_READY") from None
            entries.append(
                SelectionInvitationSetEntry(
                    invitation_id=item.invitation_id,
                    attempt_id=item.attempt_id,
                    match_run_id=item.run_id,
                    aggregate_version=item.aggregate_version,
                    status=status,
                    snapshot_sha256=item.snapshot_sha256,
                )
            )
        try:
            return selection_invitation_set_sha256(
                attempt_id=command.attempt_id,
                run_id=command.run_id,
                invitations=tuple(entries),
            )
        except Exception:
            raise CompleteSelectionError("SELECTION_NOT_READY") from None

    @staticmethod
    def _validate_open_preconditions(
        *,
        command: CompleteSelectionCommand,
        receipt: ChooseReceiptFact,
        intent: SelectionIntentFact,
        selection: SelectionSelectionFact,
        attempt: AttemptSelectionFact,
        invitation: InvitationSelectionFact,
        run: RunSelectionFact,
        demand: DemandSelectionFact,
        now: datetime,
        current_invitation_set_sha256: str,
    ) -> None:
        if (
            selection.status != "OPEN"
            or attempt.status != "OPEN"
            or demand.status != "MATCHING"
            or selection.chosen_invitation_id is not None
            or selection.selection_basis_code is not None
            or selection.decision_actor_id is not None
            or selection.candidate_selector_assignment_id is not None
            or selection.candidate_selector_assignment_version is not None
        ):
            raise CompleteSelectionError("SELECTION_NOT_READY")
        if (
            selection.aggregate_version != command.expected_selection_version
            or attempt.aggregate_version != command.expected_attempt_version
            or demand.aggregate_version != command.expected_demand_version
            or attempt.demand_id != command.demand_id
            or attempt.demand_version_id != command.demand_version_id
            or invitation.demand_id != command.demand_id
            or invitation.demand_version_id != command.demand_version_id
            or demand.demand_version_id != command.demand_version_id
            or attempt.matching_request_id != command.matching_request_id
            or attempt.matching_request_version != command.matching_request_version
            or demand.matching_request_id != command.matching_request_id
            or demand.matching_request_version != command.matching_request_version
            or attempt.funding_id != command.funding_id
            or invitation.funding_id != command.funding_id
            or demand.funding_id != command.funding_id
            or demand.funding_status != "SECURED"
            or selection.current_invitation_set_sha256
            != current_invitation_set_sha256
        ):
            raise CompleteSelectionError("PRECONDITION_FAILED")
        current_binding = SelectionHoldBinding(
            selection_id=selection.selection_id,
            selection_version=selection.aggregate_version,
            current_invitation_set_sha256=selection.current_invitation_set_sha256,
            attempt_id=attempt.attempt_id,
            attempt_version=attempt.aggregate_version,
            invitation_id=invitation.invitation_id,
            invitation_version=invitation.aggregate_version,
            run_id=run.run_id,
            run_version=run.aggregate_version,
            demand_id=demand.demand_id,
            demand_version=demand.aggregate_version,
            demand_version_id=demand.demand_version_id,
            matching_request_id=demand.matching_request_id,
            matching_request_version=demand.matching_request_version,
            funding_id=demand.funding_id,
            matching_rule_bundle_id=run.matching_rule_bundle_id,
            candidate_selector_assignment_id=(
                command.candidate_selector_assignment_id
            ),
            candidate_selector_assignment_version=(
                command.expected_candidate_selector_assignment_version
            ),
            candidate_selector_authority_marker_sha256=(
                receipt.candidate_selector_authority_marker_sha256
            ),
            rule_manifest_sha256=run.rule_manifest_sha256,
            input_set_sha256=run.input_set_sha256,
            ordered_result_sha256=run.ordered_result_sha256,
            candidate_result_sha256=invitation.candidate_result_sha256,
        )
        if (
            intent.hold_decision != "ALLOW"
            or intent.hold_valid_until <= now
            or intent.hold_binding != current_binding
        ):
            raise CompleteSelectionError("PRECONDITION_FAILED")

    @staticmethod
    def _completion_is_present(
        *,
        values: Any,
        get: Any,
        command: CompleteSelectionCommand,
        selection: SelectionSelectionFact,
        attempt: AttemptSelectionFact,
        demand: DemandSelectionFact,
    ) -> bool:
        if (
            selection.status != "OPEN"
            or attempt.status != "OPEN"
            or demand.status != "MATCHING"
            or get("completion_records", command.choose_receipt_id) is not None
        ):
            return True
        if any(
            isinstance(item, ProjectShell)
            and item.selection_id == command.selection_id
            for item in values("projects")
        ):
            return True
        if any(
            isinstance(item, CrossContextSelectionAudit)
            and item.choose_receipt_id == command.choose_receipt_id
            for item in values("coordination_audits")
        ):
            return True
        return any(
            isinstance(item, CoordinationOutboxEvent)
            and item.causation_id == command.choose_command_id
            and item.correlation_id
            for item in values("outbox")
        )

    def _recover(
        self,
        *,
        actor: CompleteSelectionActor,
        command: CompleteSelectionCommand,
        missing_code: str,
    ) -> CompleteSelectionResult:
        try:
            snapshot = self._recovery_reader.snapshot()
            get = lambda collection, key: deepcopy(
                snapshot.get(collection, {}).get(key)
            )
            values = lambda collection: tuple(
                deepcopy(tuple(snapshot.get(collection, {}).values()))
            )
            now = self._utc_now()
            receipt, intent, trigger = self._validate_trigger(
                get=get,
                actor=actor,
                command=command,
                now=now,
            )
            selection = self._typed_get(
                get, "selections", command.selection_id,
                SelectionSelectionFact, missing_code,
            )
            attempt = self._typed_get(
                get, "attempts", command.attempt_id,
                AttemptSelectionFact, missing_code,
            )
            invitation = self._typed_get(
                get, "invitations", command.invitation_id,
                InvitationSelectionFact, missing_code,
            )
            run = self._typed_get(
                get, "runs", command.run_id, RunSelectionFact, missing_code,
            )
            demand = self._typed_get(
                get, "demands", command.demand_id,
                DemandSelectionFact, missing_code,
            )
            self._validate_static_chain(
                actor=actor,
                command=command,
                receipt=receipt,
                intent=intent,
                selection=selection,
                attempt=attempt,
                invitation=invitation,
                run=run,
                demand=demand,
            )
            current_invitation_set_sha256 = (
                self._current_invitation_set_sha256(
                    values=values,
                    actor=actor,
                    command=command,
                    run=run,
                )
            )
            if (
                selection.current_invitation_set_sha256
                != current_invitation_set_sha256
            ):
                raise CompleteSelectionError(missing_code)
            return self._resolve_complete_chain(
                get=get,
                values=values,
                actor=actor,
                command=command,
                receipt=receipt,
                intent=intent,
                trigger=trigger,
                selection=selection,
                attempt=attempt,
                invitation=invitation,
                run=run,
                demand=demand,
                replayed=True,
            )
        except CompleteSelectionError:
            raise CompleteSelectionError(missing_code) from None
        except Exception:
            raise CompleteSelectionError(missing_code) from None

    def _resolve_complete_chain(
        self,
        *,
        get: Any,
        values: Any,
        actor: CompleteSelectionActor,
        command: CompleteSelectionCommand,
        receipt: ChooseReceiptFact,
        intent: SelectionIntentFact,
        trigger: PendingCompleteSelectionTrigger,
        selection: SelectionSelectionFact,
        attempt: AttemptSelectionFact,
        invitation: InvitationSelectionFact,
        run: RunSelectionFact,
        demand: DemandSelectionFact,
        replayed: bool,
    ) -> CompleteSelectionResult:
        projects = tuple(
            item for item in values("projects")
            if isinstance(item, ProjectShell)
            and item.selection_id == command.selection_id
        )
        record = get("completion_records", command.choose_receipt_id)
        if len(projects) != 1 or not isinstance(record, CompleteSelectionRecord):
            raise CompleteSelectionError("RECOVERY_INCOMPLETE")
        project = projects[0]
        agreements = tuple(
            item for item in values("agreements")
            if isinstance(item, AgreementRoot)
            and item.project_id == project.project_id
        )
        if len(agreements) != 1:
            raise CompleteSelectionError("RECOVERY_INCOMPLETE")
        agreement = agreements[0]
        audit = get("coordination_audits", record.audit_id)
        events = tuple(get("outbox", event_id) for event_id in record.event_ids)
        related_audits = tuple(
            item for item in values("coordination_audits")
            if isinstance(item, CrossContextSelectionAudit)
            and item.choose_receipt_id == command.choose_receipt_id
        )
        related_events = tuple(
            item for item in values("outbox")
            if isinstance(item, CoordinationOutboxEvent)
            and item.correlation_id == actor.correlation_id
            and item.causation_id == command.choose_command_id
            and item.event_type in {
                "SelectionMade",
                "MatchingAttemptSelected",
                "ProjectCreated",
                "AgreementCreated",
                "DemandMatched",
            }
        )
        expected_event_shape = {
            ("MATCHING", "SelectionMade", "Selection", selection.selection_id),
            (
                "MATCHING",
                "MatchingAttemptSelected",
                "MatchingAttempt",
                attempt.attempt_id,
            ),
            (
                "PROJECT_AGREEMENT",
                "ProjectCreated",
                "Project",
                project.project_id,
            ),
            (
                "PROJECT_AGREEMENT",
                "AgreementCreated",
                "Agreement",
                agreement.agreement_id,
            ),
            ("DEMAND", "DemandMatched", "Demand", demand.demand_id),
        }
        actual_event_shape = {
            (
                item.owning_context,
                item.event_type,
                item.aggregate_type,
                item.aggregate_id,
            )
            for item in events
            if isinstance(item, CoordinationOutboxEvent)
        }
        selection_events = tuple(
            item
            for item in events
            if isinstance(item, CoordinationOutboxEvent)
            and item.event_type == "SelectionMade"
        )
        expected_pre_hold_binding = SelectionHoldBinding(
            selection_id=selection.selection_id,
            selection_version=command.expected_selection_version,
            current_invitation_set_sha256=(
                selection.current_invitation_set_sha256
            ),
            attempt_id=attempt.attempt_id,
            attempt_version=command.expected_attempt_version,
            invitation_id=invitation.invitation_id,
            invitation_version=invitation.aggregate_version,
            run_id=run.run_id,
            run_version=run.aggregate_version,
            demand_id=demand.demand_id,
            demand_version=command.expected_demand_version,
            demand_version_id=demand.demand_version_id,
            matching_request_id=demand.matching_request_id,
            matching_request_version=demand.matching_request_version,
            funding_id=demand.funding_id,
            matching_rule_bundle_id=run.matching_rule_bundle_id,
            candidate_selector_assignment_id=(
                command.candidate_selector_assignment_id
            ),
            candidate_selector_assignment_version=(
                command.expected_candidate_selector_assignment_version
            ),
            candidate_selector_authority_marker_sha256=(
                receipt.candidate_selector_authority_marker_sha256
            ),
            rule_manifest_sha256=run.rule_manifest_sha256,
            input_set_sha256=run.input_set_sha256,
            ordered_result_sha256=run.ordered_result_sha256,
            candidate_result_sha256=invitation.candidate_result_sha256,
        )
        if (
            selection.status != "SELECTED"
            or selection.aggregate_version != command.expected_selection_version + 1
            or selection.chosen_invitation_id != command.invitation_id
            or selection.selection_basis_code != intent.selection_basis_code
            or selection.decision_actor_id != actor.original_actor_id
            or selection.candidate_selector_assignment_id
            != command.candidate_selector_assignment_id
            or selection.candidate_selector_assignment_version
            != command.expected_candidate_selector_assignment_version
            or selection.current_invitation_set_sha256
            != intent.hold_binding.current_invitation_set_sha256
            or intent.hold_decision != "ALLOW"
            or intent.hold_binding != expected_pre_hold_binding
            or record.completed_at > intent.hold_valid_until
            or attempt.status != "SELECTED"
            or attempt.aggregate_version != command.expected_attempt_version + 1
            or attempt.selection_id != command.selection_id
            or attempt.demand_id != command.demand_id
            or attempt.demand_version_id != command.demand_version_id
            or attempt.matching_request_id != command.matching_request_id
            or attempt.matching_request_version
            != command.matching_request_version
            or attempt.funding_id != command.funding_id
            or demand.status != "MATCHED"
            or demand.aggregate_version != command.expected_demand_version + 1
            or demand.demand_version_id != command.demand_version_id
            or demand.funding_id != command.funding_id
            or demand.funding_status != "SECURED"
            or demand.matching_request_id != command.matching_request_id
            or demand.matching_request_version
            != command.matching_request_version
            or invitation.demand_id != command.demand_id
            or invitation.demand_version_id != command.demand_version_id
            or invitation.funding_id != command.funding_id
            or invitation.aggregate_version
            != intent.hold_binding.invitation_version
            or run.aggregate_version != intent.hold_binding.run_version
            or run.matching_rule_bundle_id
            != intent.hold_binding.matching_rule_bundle_id
            or run.rule_manifest_sha256
            != intent.hold_binding.rule_manifest_sha256
            or run.input_set_sha256
            != intent.hold_binding.input_set_sha256
            or run.ordered_result_sha256
            != intent.hold_binding.ordered_result_sha256
            or invitation.candidate_result_sha256
            != intent.hold_binding.candidate_result_sha256
            or project.project_id != record.project_id
            or project.agreement_id != record.agreement_id
            or project.selection_id != command.selection_id
            or project.organization_id != actor.organization_id
            or project.demand_id != command.demand_id
            or project.demand_version_id != command.demand_version_id
            or project.creator_user_id != invitation.creator_user_id
            or project.status != "PENDING_AGREEMENT"
            or project.aggregate_version != 1
            or agreement.agreement_id != record.agreement_id
            or agreement.status != "EMPTY"
            or agreement.aggregate_version != 1
            or agreement.current_agreement_version_id is not None
            or agreement.current_open_version_id is not None
            or agreement.next_version_no != 1
            or not isinstance(audit, CrossContextSelectionAudit)
            or audit.audit_id != record.audit_id
            or audit.choose_receipt_id != command.choose_receipt_id
            or audit.choose_command_id != command.choose_command_id
            or audit.completion_command_id != command.completion_command_id
            or audit.selection_id != command.selection_id
            or audit.attempt_id != command.attempt_id
            or audit.invitation_id != command.invitation_id
            or audit.run_id != command.run_id
            or audit.demand_id != command.demand_id
            or audit.project_id != project.project_id
            or audit.agreement_id != agreement.agreement_id
            or audit.candidate_selector_assignment_id
            != command.candidate_selector_assignment_id
            or audit.candidate_selector_assignment_version
            != command.expected_candidate_selector_assignment_version
            or audit.matching_rule_bundle_id
            != run.matching_rule_bundle_id
            or audit.rule_manifest_sha256 != run.rule_manifest_sha256
            or audit.input_set_sha256 != run.input_set_sha256
            or audit.ordered_result_sha256
            != run.ordered_result_sha256
            or not all(
                _is_sha256(value)
                for value in (
                    audit.rule_manifest_sha256,
                    audit.input_set_sha256,
                    audit.ordered_result_sha256,
                    audit.candidate_result_sha256,
                    audit.current_invitation_set_sha256,
                )
            )
            or audit.candidate_result_sha256
            != invitation.candidate_result_sha256
            or audit.current_invitation_set_sha256
            != selection.current_invitation_set_sha256
            or audit.selection_basis_code
            != selection.selection_basis_code
            or audit.actor_kind != "SYSTEM"
            or audit.actor_id != actor.actor_id
            or audit.original_actor_id != actor.original_actor_id
            or audit.organization_id != actor.organization_id
            or audit.correlation_id != actor.correlation_id
            or audit.causation_id != command.choose_command_id
            or audit.result_code != "SUCCESS"
            or len(related_audits) != 1
            or len(events) != 5
            or len(related_events) != 5
            or {item.event_id for item in related_events}
            != set(record.event_ids)
            or actual_event_shape != expected_event_shape
            or len(selection_events) != 1
            or dict(selection_events[0].payload)
            != {
                "status": "SELECTED",
                "current_invitation_set_sha256": (
                    selection.current_invitation_set_sha256
                ),
                "chosen_invitation_id": command.invitation_id,
                "selection_basis_code": selection.selection_basis_code,
                "candidate_selector_assignment_id": (
                    command.candidate_selector_assignment_id
                ),
                "candidate_selector_assignment_version": (
                    command.expected_candidate_selector_assignment_version
                ),
                "reason_code": None,
            }
            or any(
                not isinstance(item, CoordinationOutboxEvent)
                or item.schema_version != 1
                or item.correlation_id != actor.correlation_id
                or item.causation_id != command.choose_command_id
                or item.trace_id != actor.trace_id
                or item.original_actor_id != actor.original_actor_id
                or item.actor_kind != "SYSTEM"
                or item.actor_id != actor.actor_id
                for item in events
            )
            or {
                item.event_type: item.aggregate_version
                for item in events
                if isinstance(item, CoordinationOutboxEvent)
            }
            != {
                "SelectionMade": selection.aggregate_version,
                "MatchingAttemptSelected": attempt.aggregate_version,
                "ProjectCreated": project.aggregate_version,
                "AgreementCreated": agreement.aggregate_version,
                "DemandMatched": demand.aggregate_version,
            }
            or record.choose_receipt_id != command.choose_receipt_id
            or record.choose_command_id != command.choose_command_id
            or record.completion_command_id != command.completion_command_id
            or record.selection_id != command.selection_id
            or record.attempt_id != command.attempt_id
            or record.demand_id != command.demand_id
            or record.correlation_id != actor.correlation_id
            or record.original_actor_id != actor.original_actor_id
            or record.candidate_selector_assignment_id
            != command.candidate_selector_assignment_id
            or record.candidate_selector_assignment_version
            != command.expected_candidate_selector_assignment_version
            or record.status != "COMPLETED"
            or record.trigger_sha256
            != pending_complete_selection_trigger_sha256(trigger)
        ):
            raise CompleteSelectionError("RECOVERY_INCOMPLETE")
        chain_sha256 = self._chain_sha256(
            receipt=receipt,
            intent=intent,
            trigger=trigger,
            selection=selection,
            attempt=attempt,
            demand=demand,
            project=project,
            agreement=agreement,
            audit=audit,
            events=events,
        )
        if record.chain_sha256 != chain_sha256:
            raise CompleteSelectionError("RECOVERY_INCOMPLETE")
        return self._result(
            selection=selection,
            attempt=attempt,
            demand=demand,
            record=record,
            replayed=replayed,
        )

    def _allocate_ids(self) -> _AllocatedIds:
        return _AllocatedIds(
            project_id=self._id_source.next_id("project"),
            agreement_id=self._id_source.next_id("agreement"),
            audit_id=self._id_source.next_id("audit"),
            event_ids=tuple(
                self._id_source.next_id("event") for _ in range(5)
            ),
        )

    @staticmethod
    def _typed_get(
        get: Any,
        collection: str,
        key: str,
        expected_type: type,
        code: str,
    ) -> Any:
        value = get(collection, key)
        if not isinstance(value, expected_type):
            raise CompleteSelectionError(code)
        return value

    @staticmethod
    def _audit(
        *,
        allocated: _AllocatedIds,
        actor: CompleteSelectionActor,
        command: CompleteSelectionCommand,
        intent: SelectionIntentFact,
        selection: SelectionSelectionFact,
        invitation: InvitationSelectionFact,
        run: RunSelectionFact,
        now: datetime,
    ) -> CrossContextSelectionAudit:
        return CrossContextSelectionAudit(
            audit_id=allocated.audit_id,
            operation="COMPLETE_SELECTION",
            choose_receipt_id=command.choose_receipt_id,
            choose_command_id=command.choose_command_id,
            completion_command_id=command.completion_command_id,
            selection_id=command.selection_id,
            attempt_id=command.attempt_id,
            invitation_id=command.invitation_id,
            run_id=command.run_id,
            demand_id=command.demand_id,
            project_id=allocated.project_id,
            agreement_id=allocated.agreement_id,
            matching_rule_bundle_id=run.matching_rule_bundle_id,
            candidate_selector_assignment_id=(
                command.candidate_selector_assignment_id
            ),
            candidate_selector_assignment_version=(
                command.expected_candidate_selector_assignment_version
            ),
            rule_manifest_sha256=run.rule_manifest_sha256,
            input_set_sha256=run.input_set_sha256,
            ordered_result_sha256=run.ordered_result_sha256,
            candidate_result_sha256=invitation.candidate_result_sha256,
            current_invitation_set_sha256=(
                selection.current_invitation_set_sha256
            ),
            selection_basis_code=intent.selection_basis_code,
            actor_kind=actor.actor_kind,
            actor_id=actor.actor_id,
            original_actor_id=actor.original_actor_id,
            organization_id=actor.organization_id,
            correlation_id=actor.correlation_id,
            causation_id=actor.causation_id,
            trace_id=actor.trace_id,
            result_code="SUCCESS",
            occurred_at=now,
        )

    @staticmethod
    def _events(
        *,
        allocated: _AllocatedIds,
        actor: CompleteSelectionActor,
        command: CompleteSelectionCommand,
        selection: SelectionSelectionFact,
        attempt: AttemptSelectionFact,
        project: ProjectShell,
        agreement: AgreementRoot,
        demand: DemandSelectionFact,
        now: datetime,
    ) -> Tuple[CoordinationOutboxEvent, ...]:
        definitions = (
            (
                "MATCHING", "SelectionMade", "Selection",
                selection.selection_id, selection.aggregate_version,
                (
                    ("status", "SELECTED"),
                    ("current_invitation_set_sha256", selection.current_invitation_set_sha256),
                    ("chosen_invitation_id", command.invitation_id),
                    ("selection_basis_code", selection.selection_basis_code),
                    (
                        "candidate_selector_assignment_id",
                        command.candidate_selector_assignment_id,
                    ),
                    (
                        "candidate_selector_assignment_version",
                        command.expected_candidate_selector_assignment_version,
                    ),
                    ("reason_code", None),
                ),
            ),
            (
                "MATCHING", "MatchingAttemptSelected", "MatchingAttempt",
                attempt.attempt_id, attempt.aggregate_version,
                (("status", "SELECTED"), ("selection_id", selection.selection_id)),
            ),
            (
                "PROJECT_AGREEMENT", "ProjectCreated", "Project",
                project.project_id, project.aggregate_version,
                (("status", "PENDING_AGREEMENT"), ("selection_id", selection.selection_id)),
            ),
            (
                "PROJECT_AGREEMENT", "AgreementCreated", "Agreement",
                agreement.agreement_id, agreement.aggregate_version,
                (("status", "EMPTY"), ("project_id", project.project_id)),
            ),
            (
                "DEMAND", "DemandMatched", "Demand",
                demand.demand_id, demand.aggregate_version,
                (("status", "MATCHED"), ("selection_id", selection.selection_id)),
            ),
        )
        return tuple(
            CoordinationOutboxEvent(
                event_id=event_id,
                schema_version=1,
                owning_context=definition[0],
                event_type=definition[1],
                aggregate_type=definition[2],
                aggregate_id=definition[3],
                aggregate_version=definition[4],
                actor_kind=actor.actor_kind,
                actor_id=actor.actor_id,
                original_actor_id=actor.original_actor_id,
                organization_id=actor.organization_id,
                correlation_id=actor.correlation_id,
                causation_id=command.choose_command_id,
                trace_id=actor.trace_id,
                occurred_at=now,
                payload=definition[5],
            )
            for event_id, definition in zip(allocated.event_ids, definitions)
        )

    @staticmethod
    def _result(
        *,
        selection: SelectionSelectionFact,
        attempt: AttemptSelectionFact,
        demand: DemandSelectionFact,
        record: CompleteSelectionRecord,
        replayed: bool,
    ) -> CompleteSelectionResult:
        return CompleteSelectionResult(
            selection_id=selection.selection_id,
            project_id=record.project_id,
            agreement_id=record.agreement_id,
            selection_version=selection.aggregate_version,
            attempt_version=attempt.aggregate_version,
            demand_version=demand.aggregate_version,
            candidate_selector_assignment_id=(
                record.candidate_selector_assignment_id
            ),
            candidate_selector_assignment_version=(
                record.candidate_selector_assignment_version
            ),
            event_ids=record.event_ids,
            completed_at=record.completed_at,
            replayed=replayed,
        )

    @classmethod
    def _chain_sha256(
        cls,
        *,
        receipt: ChooseReceiptFact,
        intent: SelectionIntentFact,
        trigger: PendingCompleteSelectionTrigger,
        selection: SelectionSelectionFact,
        attempt: AttemptSelectionFact,
        demand: DemandSelectionFact,
        project: ProjectShell,
        agreement: AgreementRoot,
        audit: CrossContextSelectionAudit,
        events: Tuple[CoordinationOutboxEvent, ...],
    ) -> str:
        surface = {
            "receipt": receipt,
            "intent": intent,
            "trigger": trigger,
            "selection": selection,
            "attempt": attempt,
            "demand": demand,
            "project": project,
            "agreement": agreement,
            "audit": audit,
            "events": events,
        }
        return hashlib.sha256(cls._canonical_bytes(surface)).hexdigest()

    @classmethod
    def _canonical_bytes(cls, value: Any) -> bytes:
        def normalize(item: Any) -> Any:
            if is_dataclass(item):
                return normalize(asdict(item))
            if isinstance(item, datetime):
                return item.isoformat().replace("+00:00", "Z")
            if isinstance(item, tuple):
                return [normalize(child) for child in item]
            if isinstance(item, Mapping):
                return {
                    str(key): normalize(child)
                    for key, child in sorted(item.items(), key=lambda pair: str(pair[0]))
                }
            return item
        return json.dumps(
            normalize(value),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_utc_datetime(value: Any) -> bool:
    return (
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() == timedelta(0)
    )


__all__ = [
    "COMPLETE_SELECTION_CHECKPOINTS",
    "COMPLETE_SELECTION_PRODUCTION_BINDING_AVAILABLE",
    "COMPLETE_SELECTION_TRIGGER_PRODUCER_COMPATIBLE",
    "COMPLETE_SELECTION_CONTEXT_EVENT_BINDINGS_AVAILABLE",
    "AgreementRoot",
    "AttemptSelectionFact",
    "CandidateSelectorAuthorityFact",
    "ChooseReceiptFact",
    "CompleteSelectionActor",
    "CompleteSelectionClock",
    "CompleteSelectionCommand",
    "CompleteSelectionCommitOutcomeUnknownError",
    "CompleteSelectionCoordinator",
    "CompleteSelectionError",
    "CompleteSelectionIdSource",
    "CompleteSelectionRecord",
    "CompleteSelectionRecoveryReader",
    "CompleteSelectionResult",
    "CompleteSelectionStorageError",
    "CompleteSelectionUniqueConflictError",
    "CompleteSelectionUnitOfWork",
    "CompleteSelectionUnitOfWorkFactory",
    "CoordinationOutboxEvent",
    "CrossContextSelectionAudit",
    "DemandSelectionFact",
    "InvitationSelectionFact",
    "PendingCompleteSelectionTrigger",
    "ProjectShell",
    "RunSelectionFact",
    "SelectionHoldBinding",
    "SelectionIntentFact",
    "SelectionSelectionFact",
    "SystemCoordinatorAuthorityFact",
    "pending_complete_selection_trigger_sha256",
    "selection_intent_sha256",
]
