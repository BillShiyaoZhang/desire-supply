"""Framework-neutral transactional orchestration for Matching v1."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass, replace
from datetime import datetime, timedelta
from decimal import Decimal
from enum import Enum
import json
from typing import Any, Mapping, Optional

from desire_platform.coordination.selection_trigger import (
    ChooseReceiptFact,
    PendingCompleteSelectionTrigger,
    SelectionHoldBinding,
    SelectionIntentFact,
    selection_intent_sha256,
)

from ..domain.model import (
    AttemptDemandBinding,
    CandidateSelectorAssignment,
    CandidateEligibility,
    Invitation,
    InvitationResponse,
    InvitationResponseKind,
    InvitationStatus,
    MatchRun,
    MatchCandidate,
    MatchInputManifest,
    MatchRunStatus,
    MatchingAttempt,
    MatchingAttemptStatus,
    MatchingDomainError,
    Selection,
    candidate_result_sha256,
    deterministic_rank_and_hash,
    match_input_set_sha256,
    selection_invitation_set_sha256,
    validate_candidate_selector_assignment,
    validate_invitation_disclosure,
)
from ..ports.commands import (
    MatchingAuthorityUnavailableError,
    MatchingCommitOutcomeUnknownError,
    MatchingCreatorAuthority,
    MatchingHoldDecision,
    MatchingInputChangedError,
    MatchingCandidateSelectorAuthority,
    MatchingPrincipalAuthority,
    MatchingReviewerAuthority,
    MatchingSafeResponseInvalidError,
    MatchingSafetyHoldUnavailableError,
    MatchingSafetyHoldResult,
    MatchingSourceEventInvalidError,
    MatchingStorageUnavailableError,
    MatchingSystemAuthority,
)
from .commands import (
    ChooseCreatorCommand,
    CloseSelectionWithoutChoiceCommand,
    CompleteMatchRunCommand,
    CreateInvitationCommand,
    CreateMatchingAttemptCommand,
    MatchingActorContext,
    MatchingActorKind,
    MatchingCommandResult,
    PublishInvitationCommand,
    RespondInvitationCommand,
    RetryMatchRunCommand,
    StartMatchRunCommand,
    WithdrawAcceptedInvitationCommand,
)


MATCHING_APPLICATION_BEHAVIOR_NOT_AVAILABLE = (
    "MATCHING_APPLICATION_BEHAVIOR_NOT_AVAILABLE"
)

MATCHING_WRITE_CHECKPOINTS = (
    "receipt_claim",
    "root_lock",
    "candidate_or_response",
    "snapshot",
    "invitation",
    "selection",
    "attempt",
    "source_inbox",
    "audit",
    "outbox_events",
    "safe_response",
    "receipt_complete",
    "commit",
)


class MatchingApplicationBehaviorNotAvailable(RuntimeError):
    """Compatibility sentinel retained after Memory behavior became available."""


class MatchingApplicationError(RuntimeError):
    """Closed application rejection safe for a future presenter."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


_DEPENDENCY_ERRORS = (
    MatchingAuthorityUnavailableError,
    MatchingInputChangedError,
    MatchingSafetyHoldUnavailableError,
    MatchingSafeResponseInvalidError,
    MatchingSourceEventInvalidError,
)


class _MatchingHandler:
    operation = ""

    def __init__(self, **dependencies: Any) -> None:
        self._dependencies = dict(dependencies)

    def handle(
        self, *, actor: MatchingActorContext, command: Any
    ) -> MatchingCommandResult:
        try:
            now = self._clock().now()
            self._preflight_principal(actor=actor, now=now)
            receipt = self._receipt_binding(actor=actor, command=command)
            replay = self._read_completed_receipt(receipt)
            if replay is not None:
                return self._result_from_receipt(replay, replayed=True)
            authority = self._authorize(actor=actor, command=command, now=now)
            outside = self._outside_checks(
                actor=actor,
                command=command,
                authority=authority,
                now=now,
            )
            return self._transaction(
                actor=actor,
                command=command,
                authority=authority,
                outside=outside,
                receipt=receipt,
                now=now,
            )
        except MatchingApplicationError:
            raise
        except MatchingDomainError as error:
            raise MatchingApplicationError(error.code) from error
        except _DEPENDENCY_ERRORS as error:
            raise MatchingApplicationError("SERVICE_UNAVAILABLE") from error
        except MatchingStorageUnavailableError as error:
            raise MatchingApplicationError("SERVICE_UNAVAILABLE") from error

    def _clock(self) -> Any:
        return self._required("clock")

    def _required(self, name: str) -> Any:
        value = self._dependencies.get(name)
        if value is None:
            raise MatchingApplicationError("SERVICE_UNAVAILABLE")
        return value

    def _preflight_principal(
        self, *, actor: MatchingActorContext, now: datetime
    ) -> None:
        principal = self._required("principal_authority").authenticate(
            actor=actor
        )
        if (
            not isinstance(principal, MatchingPrincipalAuthority)
            or principal.actor_kind is not actor.actor_kind
            or principal.actor_id != actor.actor_id
            or principal.valid_until is None
            or principal.valid_until <= now
            or len(principal.principal_marker_sha256) != 64
        ):
            raise MatchingApplicationError("AUTHENTICATION_REQUIRED")
        if actor.actor_kind is MatchingActorKind.USER:
            if principal.user_status != "ACTIVE":
                raise MatchingApplicationError("AUTHENTICATION_REQUIRED")
            if (
                actor.session_id is None
                or principal.session_id != actor.session_id
                or principal.session_status != "ACTIVE"
                or principal.session_family_status != "ACTIVE"
            ):
                raise MatchingApplicationError("SESSION_EXPIRED")
            return
        if (
            actor.workload_credential_id is None
            or principal.workload_credential_id
            != actor.workload_credential_id
            or principal.workload_credential_status != "ACTIVE"
        ):
            raise MatchingApplicationError("AUTHENTICATION_REQUIRED")

    def _authorize(
        self,
        *,
        actor: MatchingActorContext,
        command: Any,
        now: datetime,
    ) -> Any:
        if self.operation in {
            "CREATE_MATCHING_ATTEMPT",
            "START_MATCH_RUN",
            "COMPLETE_MATCH_RUN",
            "FAIL_MATCH_RUN",
        }:
            source_event_id = (
                command.source_event.event_id
                if isinstance(command, CreateMatchingAttemptCommand)
                else None
            )
            run_id = getattr(command, "match_run_id", None)
            authority = self._required("system_authority").authorize(
                actor=actor,
                operation=self.operation,
                source_event_id=source_event_id,
                attempt_id=None,
                match_run_id=run_id,
            )
            self._validate_system_authority(
                actor=actor,
                authority=authority,
                source_event_id=source_event_id,
                run_id=run_id,
                now=now,
            )
            if isinstance(command, CreateMatchingAttemptCommand):
                self._required("source_event_validator").validate(
                    actor=actor, event=command.source_event
                )
            return authority
        if self.operation in {"RETRY_MATCH_RUN", "CREATE_INVITATION", "PUBLISH_INVITATION"}:
            assignment_id = getattr(command, "assignment_id", None)
            if not isinstance(assignment_id, str):
                raise MatchingApplicationError("RESOURCE_NOT_FOUND")
            authority = self._required("reviewer_authority").authorize(
                actor=actor,
                operation=self.operation,
                assignment_id=assignment_id,
                attempt_id=getattr(command, "attempt_id", ""),
                match_run_id=getattr(command, "match_run_id", None),
            )
            self._validate_reviewer_authority(
                actor=actor,
                authority=authority,
                assignment_id=assignment_id,
                now=now,
            )
            return authority
        if self.operation in {
            "RESPOND_INVITATION",
            "WITHDRAW_ACCEPTED_INVITATION",
        }:
            if isinstance(command, WithdrawAcceptedInvitationCommand):
                creator_operation = "WITHDRAW_ACCEPTED_INVITATION"
            else:
                creator_operation = (
                    "RESPOND_INVITATION_ACCEPT"
                    if command.accept
                    else "RESPOND_INVITATION_DECLINE"
                )
            authority = self._required("creator_authority").authorize(
                actor=actor,
                operation=creator_operation,
                invitation_id=command.invitation_id,
            )
            self._validate_creator_authority(
                actor=actor, authority=authority, command=command
            )
            return authority
        if self.operation in {
            "CHOOSE_CREATOR",
            "CLOSE_SELECTION_WITHOUT_CHOICE",
        }:
            authority = self._required(
                "candidate_selector_authority"
            ).authorize(
                actor=actor,
                operation=self.operation,
                organization_id=actor.organization_id,
                selection_id=command.selection_id,
                assignment_id=command.assignment_id,
            )
            self._validate_candidate_selector_authority(
                actor=actor,
                authority=authority,
                command=command,
                now=now,
            )
            return authority
        raise MatchingApplicationError("SERVICE_UNAVAILABLE")

    def _outside_checks(
        self,
        *,
        actor: MatchingActorContext,
        command: Any,
        authority: Any,
        now: datetime,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        if isinstance(command, CreateMatchingAttemptCommand):
            event = command.source_event
            facts = self._required("demand_facts").read_exact(
                organization_id=event.organization_id,
                demand_id=event.demand_id,
                demand_version_id=event.demand_version_id,
                funding_id=event.funding_id,
                matching_request_id=event.matching_request_id,
            )
            if (
                facts.organization_id != event.organization_id
                or facts.demand_id != event.demand_id
                or facts.demand_aggregate_version != event.aggregate_version
                or facts.demand_version_id != event.demand_version_id
                or facts.funding_id != event.funding_id
                or facts.funding_status != "SECURED"
                or facts.matching_request_id != event.matching_request_id
                or facts.matching_request_status != "OPEN"
                or facts.composite_rule_requirement_id
                != event.composite_rule_requirement_id
            ):
                raise MatchingApplicationError("MATCH_INPUT_CHANGED")
            result["demand_facts"] = facts
        if isinstance(command, StartMatchRunCommand):
            result["capture_port"] = self._required("capture_match_inputs")
        if isinstance(command, PublishInvitationCommand):
            result["profile_facts"] = self._required("profile_facts")
        if isinstance(command, RespondInvitationCommand):
            result["profile_facts"] = self._required("profile_facts")
        if self.operation in {
            "CREATE_MATCHING_ATTEMPT",
            "CREATE_INVITATION",
            "PUBLISH_INVITATION",
            "RESPOND_INVITATION",
            "CHOOSE_CREATOR",
        } and not (
            isinstance(command, RespondInvitationCommand) and not command.accept
        ):
            hold_port = self._required("safety_hold")
            result["hold_port"] = hold_port
            if isinstance(command, ChooseCreatorCommand):
                snapshot = self._required("uow_factory").store.snapshot()
                selection = snapshot.get("selections", {}).get(
                    command.selection_id
                )
                attempt = (
                    snapshot.get("attempts", {}).get(selection.attempt_id)
                    if isinstance(selection, Selection)
                    else None
                )
                assignment = (
                    authority.assignment
                    if isinstance(
                        authority, MatchingCandidateSelectorAuthority
                    )
                    else None
                )
                if (
                    not isinstance(attempt, MatchingAttempt)
                    or not isinstance(assignment, CandidateSelectorAssignment)
                    or assignment.organization_id != attempt.organization_id
                    or assignment.demand_id != attempt.demand_id
                    or assignment.selection_id != selection.selection_id
                ):
                    raise MatchingApplicationError("RESOURCE_NOT_FOUND")
                invitation = snapshot.get("invitations", {}).get(
                    command.invitation_id
                )
                if isinstance(selection, Selection) and isinstance(
                    invitation, Invitation
                ):
                    run = snapshot.get("runs", {}).get(
                        invitation.match_run_id
                    )
                    if isinstance(attempt, MatchingAttempt) and isinstance(
                        run, MatchRun
                    ):
                        selection_hold_binding = self._selection_hold_binding(
                            get=lambda collection, key: snapshot.get(
                                collection, {}
                            ).get(key),
                            attempt=attempt,
                            run=run,
                            invitation=invitation,
                            selection=selection,
                            authority=authority,
                        )
                        binding = self._hold_binding(
                            actor=actor,
                            action=self.operation,
                            attempt=attempt,
                            run=run,
                            invitation=invitation,
                            selection=selection,
                            selection_hold_binding=selection_hold_binding,
                        )
                        hold_result = hold_port.evaluate(**binding)
                        self._validate_hold_result(
                            binding=binding,
                            result=hold_result,
                            now=now,
                        )
                        result["hold_result"] = hold_result
                        result["selection_hold_binding"] = (
                            selection_hold_binding
                        )
        return result

    def _transaction(
        self,
        *,
        actor: MatchingActorContext,
        command: Any,
        authority: Any,
        outside: Mapping[str, Any],
        receipt: Mapping[str, str],
        now: datetime,
    ) -> MatchingCommandResult:
        factory = self._required("uow_factory")
        try:
            with factory.begin() as uow:
                for checkpoint in MATCHING_WRITE_CHECKPOINTS[:-1]:
                    uow.checkpoint(checkpoint)
                    if checkpoint == "receipt_claim":
                        existing = uow.get("receipts", receipt["identity"])
                        if existing is not None:
                            return self._resolve_locked_receipt(
                                existing=existing, receipt=receipt
                            )
                        uow.put(
                            "receipts",
                            receipt["identity"],
                            {
                                **receipt,
                                "status": "IN_PROGRESS",
                                "safe_response": None,
                                "recovery_facts": None,
                            },
                        )
                    if checkpoint == "root_lock":
                        uow.lock(self.operation, self._lock_keys(command))
                    if checkpoint == "candidate_or_response":
                        result, writes, event_types = self._apply_command(
                            uow=uow,
                            actor=actor,
                            command=command,
                            authority=authority,
                            outside=outside,
                            receipt=receipt,
                            now=now,
                        )
                    if checkpoint == "audit":
                        audit_id = self._required("id_source").next_id("audit")
                        uow.put(
                            "audits",
                            audit_id,
                            self._audit_record(
                                actor=actor,
                                command=command,
                                authority=authority,
                                result=result,
                                now=now,
                            ),
                        )
                    if checkpoint == "outbox_events":
                        for event_type in event_types:
                            envelope = self._event(
                                event_type=event_type,
                                actor=actor,
                                command=command,
                                result=result,
                                uow=uow,
                                now=now,
                            )
                            self._required("event_validator").validate(envelope)
                            uow.put(
                                "outbox",
                                envelope["event_id"],
                                envelope,
                            )
                    if checkpoint == "safe_response":
                        safe_response = self._safe_response(result)
                        self._required("safe_response_validator").validate(
                            operation=self.operation,
                            response=safe_response,
                        )
                    if checkpoint == "receipt_complete":
                        uow.put(
                            "receipts",
                            receipt["identity"],
                            {
                                **receipt,
                                "status": "COMPLETED",
                                "safe_response": safe_response,
                                "recovery_facts": self._recovery_facts(
                                    uow=uow, identifiers=writes
                                ),
                            },
                        )
                uow.checkpoint("commit")
                uow.commit()
                return result
        except MatchingCommitOutcomeUnknownError:
            return self._recover_unknown(receipt)

    def _apply_command(
        self,
        *,
        uow: Any,
        actor: MatchingActorContext,
        command: Any,
        authority: Any,
        outside: Mapping[str, Any],
        receipt: Mapping[str, str],
        now: datetime,
    ) -> tuple[MatchingCommandResult, tuple[str, ...], tuple[str, ...]]:
        if isinstance(command, CreateMatchingAttemptCommand):
            return self._create_attempt(uow, actor, command, outside, now)
        if isinstance(command, StartMatchRunCommand):
            return self._start_run(uow, command, outside, now)
        if isinstance(command, CompleteMatchRunCommand):
            return self._complete_run(uow, command, now)
        if isinstance(command, RetryMatchRunCommand):
            return self._retry_run(uow, command, authority, now)
        if isinstance(command, CreateInvitationCommand):
            return self._create_invitation(
                uow, actor, command, authority, outside, now
            )
        if isinstance(command, PublishInvitationCommand):
            return self._publish_invitation(
                uow, actor, command, authority, outside, now
            )
        if isinstance(command, RespondInvitationCommand):
            return self._respond_invitation(
                uow, actor, command, authority, outside, now
            )
        if isinstance(command, WithdrawAcceptedInvitationCommand):
            return self._withdraw_accepted_invitation(
                uow,
                actor,
                command,
                authority,
                now,
            )
        if isinstance(command, ChooseCreatorCommand):
            return self._choose_creator(
                uow, actor, command, authority, outside, receipt, now
            )
        if isinstance(command, CloseSelectionWithoutChoiceCommand):
            return self._close_selection_without_choice(
                uow, actor, command, authority, now
            )
        raise MatchingApplicationError("SERVICE_UNAVAILABLE")

    def _create_attempt(self, uow: Any, actor: Any, command: Any, outside: Any, now: datetime):
        event = command.source_event
        if uow.get("inbox", event.event_id) is not None:
            raise MatchingApplicationError("INVALID_STATE_TRANSITION")
        facts = outside["demand_facts"]
        if any(
            item.status is MatchingAttemptStatus.OPEN
            and item.demand_id == event.demand_id
            for item in uow.values("attempts")
        ):
            raise MatchingApplicationError("INVALID_STATE_TRANSITION")
        attempt_no = 1 + max(
            (item.attempt_no for item in uow.values("attempts") if item.demand_id == event.demand_id),
            default=0,
        )
        attempt_id = self._required("id_source").next_id("attempt")
        run_id = self._required("id_source").next_id("run")
        attempt, run = MatchingAttempt.open(
            attempt_id=attempt_id,
            run_id=run_id,
            organization_id=event.organization_id,
            demand_id=event.demand_id,
            demand_version_id=event.demand_version_id,
            matching_request_id=event.matching_request_id,
            funding_id=event.funding_id,
            attempt_no=attempt_no,
            input_baseline_sha256=self._simple_hash(
                (
                    facts.organization_id,
                    facts.demand_id,
                    facts.demand_version_id,
                    facts.demand_content_sha256,
                    facts.funding_id,
                    facts.matching_request_id,
                    facts.matching_request_version,
                    facts.matching_rule_bundle_id,
                    facts.selector_digest,
                )
            ),
            matching_rule_bundle_id=facts.matching_rule_bundle_id,
            now=now,
        )
        binding = AttemptDemandBinding(
            attempt_id=attempt.attempt_id,
            source_event_id=event.event_id,
            organization_id=event.organization_id,
            demand_id=event.demand_id,
            demand_aggregate_version=event.aggregate_version,
            demand_version_id=event.demand_version_id,
            funding_id=event.funding_id,
            matching_request_id=event.matching_request_id,
            matching_request_version=facts.matching_request_version,
            composite_rule_requirement_id=event.composite_rule_requirement_id,
            matching_rule_bundle_id=facts.matching_rule_bundle_id,
            selector_digest=facts.selector_digest,
            created_at=now,
        )
        self._validate_hold(
            port=outside["hold_port"], actor=actor, action=self.operation,
            attempt=attempt, run=run, invitation=None, selection=None, now=now,
        )
        uow.put("attempts", attempt.attempt_id, attempt)
        uow.put("runs", run.run_id, run)
        uow.put("attempt_bindings", attempt.attempt_id, binding)
        uow.put("inbox", event.event_id, {"status": "COMPLETED", "attempt_id": attempt.attempt_id})
        result = self._result(attempt.attempt_id, attempt.status.value, attempt.aggregate_version, now, False, ("MatchingAttemptOpened", "MatchRunQueued"))
        return result, (
            attempt.attempt_id,
            run.run_id,
            f"attempt_bindings:{attempt.attempt_id}",
        ), result.event_types

    def _start_run(self, uow: Any, command: StartMatchRunCommand, outside: Any, now: datetime):
        run = self._entity(uow, "runs", command.match_run_id, MatchRun)
        attempt = self._entity(uow, "attempts", run.attempt_id, MatchingAttempt)
        captured = outside["capture_port"].capture(
            attempt_id=attempt.attempt_id,
            run_id=run.run_id,
            matching_request_id=attempt.matching_request_id,
            discovery_facts={},
        )
        if (
            captured.manifest.attempt_id != attempt.attempt_id
            or captured.manifest.run_id != run.run_id
            or captured.manifest.matching_request_id != attempt.matching_request_id
            or captured.manifest.candidate_count
            != len(captured.manifest.ordered_candidate_identities)
        ):
            raise MatchingApplicationError("MATCH_INPUT_CHANGED")
        computed_input_sha256 = match_input_set_sha256(
            manifest=captured.manifest,
            run_input=captured.run_input,
        )
        if (
            captured.run_input.input_set_sha256 != computed_input_sha256
            or captured.manifest.input_set_sha256 != computed_input_sha256
        ):
            raise MatchingApplicationError("MATCH_INPUT_CHANGED")
        started = run.start(
            worker_id=command.worker_id,
            lease_token=command.lease_token,
            fencing_generation=command.fencing_generation,
            lease_until=now + timedelta(minutes=5),
            now=now,
        )
        started = replace(started, input_manifest=captured.manifest, input_set_sha256=captured.manifest.input_set_sha256)
        uow.put("runs", started.run_id, started)
        uow.put("run_inputs", started.run_id, captured.run_input)
        result = self._result(started.run_id, started.status.value, started.aggregate_version, now, False, ("MatchRunStarted",))
        return result, (
            started.run_id,
            f"run_inputs:{started.run_id}",
        ), result.event_types

    def _complete_run(self, uow: Any, command: CompleteMatchRunCommand, now: datetime):
        run = self._entity(uow, "runs", command.match_run_id, MatchRun)
        attempt = self._entity(uow, "attempts", run.attempt_id, MatchingAttempt)
        if run.input_set_sha256 != command.input_set_sha256:
            raise MatchingApplicationError("MATCH_INPUT_CHANGED")
        normalized, ordered_hash = deterministic_rank_and_hash(
            candidates=command.candidate_results,
            matching_rule_bundle_id=run.matching_rule_bundle_id,
            input_set_sha256=command.input_set_sha256,
        )
        completed = run.complete(
            worker_id=command.worker_id,
            lease_token=command.lease_token,
            fencing_generation=command.fencing_generation,
            candidates=normalized,
            ordered_result_sha256=ordered_hash,
            now=now,
        )
        uow.put("runs", completed.run_id, completed)
        for item in normalized:
            uow.put("candidates", f"{item.run_id}:{item.creator_user_id}", item)
        event_types = ["MatchRunCompleted"]
        target_id = completed.run_id
        target_status = completed.status.value
        target_version = completed.aggregate_version
        if not normalized:
            closed = attempt.close_without_selection(now=now)
            uow.put("attempts", closed.attempt_id, closed)
            event_types.append("MatchingAttemptClosedWithoutSelection")
        result = self._result(target_id, target_status, target_version, now, False, tuple(event_types))
        related = [completed.run_id, attempt.attempt_id]
        related.extend(
            f"candidates:{item.run_id}:{item.creator_user_id}"
            for item in normalized
        )
        return result, tuple(related), result.event_types

    def _retry_run(
        self,
        uow: Any,
        command: RetryMatchRunCommand,
        authority: MatchingReviewerAuthority,
        now: datetime,
    ):
        attempt = self._entity(uow, "attempts", command.attempt_id, MatchingAttempt)
        failed = self._entity(uow, "runs", command.failed_run_id, MatchRun)
        if (
            authority.assignment_attempt_id != attempt.attempt_id
            or authority.assignment_run_id not in {None, failed.run_id}
        ):
            raise MatchingApplicationError("RESOURCE_NOT_FOUND")
        if attempt.status is not MatchingAttemptStatus.OPEN or failed.status is not MatchRunStatus.FAILED or attempt.aggregate_version != command.expected_attempt_version or attempt.input_baseline_sha256 != command.input_baseline_sha256:
            raise MatchingApplicationError("PRECONDITION_FAILED")
        successor_id = self._required("id_source").next_id("run")
        successor = replace(
            failed,
            run_id=successor_id,
            run_no=failed.run_no + 1,
            status=MatchRunStatus.QUEUED,
            aggregate_version=1,
            input_manifest=None,
            input_set_sha256=None,
            ordered_result_sha256=None,
            candidate_count=None,
            eligible_count=None,
            excluded_count=None,
            worker_id=None,
            lease_token=None,
            fencing_generation=0,
            lease_until=None,
            supersedes_run_id=failed.run_id,
            superseded_by_run_id=None,
            failure_code=None,
            created_at=now,
            updated_at=now,
        )
        superseded = failed.supersede(successor_run_id=successor_id, now=now)
        updated_attempt = replace(attempt, aggregate_version=attempt.aggregate_version + 1, current_match_run_id=successor_id, updated_at=now)
        uow.put("runs", superseded.run_id, superseded)
        uow.put("runs", successor.run_id, successor)
        uow.put("attempts", updated_attempt.attempt_id, updated_attempt)
        result = self._result(successor.run_id, successor.status.value, successor.aggregate_version, now, False, ("MatchRunQueued", "MatchRunSuperseded"))
        return result, (
            successor.run_id,
            failed.run_id,
            updated_attempt.attempt_id,
        ), result.event_types

    def _create_invitation(
        self,
        uow: Any,
        actor: Any,
        command: CreateInvitationCommand,
        authority: MatchingReviewerAuthority,
        outside: Any,
        now: datetime,
    ):
        run = self._entity(uow, "runs", command.match_run_id, MatchRun)
        attempt = self._entity(uow, "attempts", run.attempt_id, MatchingAttempt)
        candidate = self._entity(uow, "candidates", f"{run.run_id}:{command.creator_user_id}", object)
        if (
            authority.assignment_attempt_id != attempt.attempt_id
            or authority.assignment_run_id != run.run_id
        ):
            raise MatchingApplicationError("RESOURCE_NOT_FOUND")
        if run.aggregate_version != command.expected_run_version:
            raise MatchingApplicationError("PRECONDITION_FAILED")
        if any(item.attempt_id == attempt.attempt_id and item.creator_user_id == command.creator_user_id and item.status in {InvitationStatus.CREATED, InvitationStatus.SENT} for item in uow.values("invitations")):
            raise MatchingApplicationError("INVITATION_ALREADY_EXISTS")
        snapshot = self._required("disclosure_builder").build(attempt=attempt, run=run, candidate=candidate, invitation_id=self._required("id_source").peek_id("invitation"), expires_at=command.expires_at)
        validate_invitation_disclosure(snapshot)
        invitation = Invitation.create(
            invitation_id=self._required("id_source").next_id("invitation"), candidate=candidate, run=run,
            demand_id=attempt.demand_id, demand_version_id=attempt.demand_version_id,
            funding_id=attempt.funding_id, disclosure_snapshot_id=snapshot.snapshot_id,
            snapshot_sha256=snapshot.snapshot_sha256, expires_at=command.expires_at, now=now,
        )
        self._validate_hold(port=outside["hold_port"], actor=actor, action=self.operation, attempt=attempt, run=run, invitation=invitation, selection=None, now=now)
        uow.put("snapshots", snapshot.snapshot_id, snapshot)
        uow.put("invitations", invitation.invitation_id, invitation)
        result = self._result(invitation.invitation_id, invitation.status.value, invitation.aggregate_version, now, False, ("InvitationCreated",))
        return result, (
            invitation.invitation_id,
            attempt.attempt_id,
            run.run_id,
            f"candidates:{run.run_id}:{candidate.creator_user_id}",
            f"snapshots:{snapshot.snapshot_id}",
        ), result.event_types

    def _publish_invitation(
        self,
        uow: Any,
        actor: Any,
        command: PublishInvitationCommand,
        authority: MatchingReviewerAuthority,
        outside: Any,
        now: datetime,
    ):
        invitation = self._entity(uow, "invitations", command.invitation_id, Invitation)
        attempt = self._entity(uow, "attempts", invitation.attempt_id, MatchingAttempt)
        run = self._entity(uow, "runs", invitation.match_run_id, MatchRun)
        snapshot = self._entity(uow, "snapshots", invitation.disclosure_snapshot_id, object)
        if (
            authority.assignment_attempt_id != attempt.attempt_id
            or authority.assignment_run_id != run.run_id
        ):
            raise MatchingApplicationError("RESOURCE_NOT_FOUND")
        if invitation.aggregate_version != command.expected_invitation_version:
            raise MatchingApplicationError("PRECONDITION_FAILED")
        validate_invitation_disclosure(snapshot)
        profile = outside["profile_facts"].read_exact(creator_user_id=invitation.creator_user_id, profile_id=invitation.profile_id, profile_version_id=invitation.profile_version_id)
        self._validate_profile(invitation, profile)
        published = invitation.publish(snapshot_sha256=command.snapshot_sha256, now=now)
        current_invitation_set_sha256 = self._current_invitation_set_hash(
            uow=uow,
            attempt=attempt,
            run=run,
            replacement=published,
        )
        existing = next(
            (
                item
                for item in uow.values("selections")
                if item.attempt_id == attempt.attempt_id
            ),
            None,
        )
        if existing is None:
            selection = Selection.open(selection_id=self._required("id_source").next_id("selection"), attempt_id=attempt.attempt_id, current_invitation_set_sha256=current_invitation_set_sha256, now=now)
            uow.put("selections", selection.selection_id, selection)
            uow.put("attempts", attempt.attempt_id, replace(attempt, selection_id=selection.selection_id, aggregate_version=attempt.aggregate_version + 1, updated_at=now))
            event_types = ("InvitationSent", "SelectionOpened")
        else:
            selection = existing.refresh_invitation_set(
                current_invitation_set_sha256=current_invitation_set_sha256,
                now=now,
            )
            uow.put("selections", selection.selection_id, selection)
            event_types = ("InvitationSent", "SelectionInvitationSetChanged")
        self._validate_hold(port=outside["hold_port"], actor=actor, action=self.operation, attempt=attempt, run=run, invitation=published, selection=selection, now=now)
        uow.put("invitations", published.invitation_id, published)
        result = self._result(published.invitation_id, published.status.value, published.aggregate_version, now, False, event_types)
        return result, (
            published.invitation_id,
            attempt.attempt_id,
            run.run_id,
            selection.selection_id,
            f"snapshots:{snapshot.snapshot_id}",
        ), result.event_types

    def _respond_invitation(
        self,
        uow: Any,
        actor: Any,
        command: RespondInvitationCommand,
        authority: MatchingCreatorAuthority,
        outside: Any,
        now: datetime,
    ):
        invitation = self._entity(uow, "invitations", command.invitation_id, Invitation)
        attempt = self._entity(uow, "attempts", invitation.attempt_id, MatchingAttempt)
        run = self._entity(uow, "runs", invitation.match_run_id, MatchRun)
        if (
            authority.profile_id != invitation.profile_id
            or authority.profile_version_id != invitation.profile_version_id
        ):
            raise MatchingApplicationError("RESOURCE_NOT_FOUND")
        if invitation.aggregate_version != command.expected_invitation_version:
            raise MatchingApplicationError("PRECONDITION_FAILED")
        profile = outside["profile_facts"].read_exact(creator_user_id=invitation.creator_user_id, profile_id=invitation.profile_id, profile_version_id=invitation.profile_version_id)
        self._validate_profile(invitation, profile)
        if command.accept:
            selection = next((item for item in uow.values("selections") if item.attempt_id == attempt.attempt_id), None)
            self._validate_hold(port=outside["hold_port"], actor=actor, action="RESPOND_INVITATION_ACCEPT", attempt=attempt, run=run, invitation=invitation, selection=selection, now=now)
        updated, response = invitation.respond(response_id=self._required("id_source").next_id("response"), creator_user_id=actor.actor_id, response_kind=InvitationResponseKind.ACCEPTED if command.accept else InvitationResponseKind.DECLINED, snapshot_sha256=command.snapshot_sha256, reason_code=command.reason_code, note=command.note, now=now)
        selection = next(
            (
                item
                for item in uow.values("selections")
                if item.attempt_id == attempt.attempt_id
            ),
            None,
        )
        if selection is None:
            raise MatchingApplicationError("SERVICE_UNAVAILABLE")
        refreshed = selection.refresh_invitation_set(
            current_invitation_set_sha256=self._current_invitation_set_hash(
                uow=uow,
                attempt=attempt,
                run=run,
                replacement=updated,
            ),
            now=now,
        )
        uow.put("responses", response.response_id, response)
        uow.put("invitations", updated.invitation_id, updated)
        uow.put("selections", refreshed.selection_id, refreshed)
        event_type = "InvitationAccepted" if command.accept else "InvitationDeclined"
        result = self._result(
            updated.invitation_id,
            updated.status.value,
            updated.aggregate_version,
            now,
            False,
            (event_type, "SelectionInvitationSetChanged"),
        )
        related = [updated.invitation_id, attempt.attempt_id, run.run_id]
        related.append(f"responses:{response.response_id}")
        related.append(refreshed.selection_id)
        return result, tuple(related), result.event_types

    def _withdraw_accepted_invitation(
        self,
        uow: Any,
        actor: MatchingActorContext,
        command: WithdrawAcceptedInvitationCommand,
        authority: MatchingCreatorAuthority,
        now: datetime,
    ):
        invitation = self._entity(
            uow,
            "invitations",
            command.invitation_id,
            Invitation,
        )
        attempt = self._entity(
            uow,
            "attempts",
            invitation.attempt_id,
            MatchingAttempt,
        )
        run = self._entity(
            uow,
            "runs",
            invitation.match_run_id,
            MatchRun,
        )
        selection = next(
            (
                item
                for item in uow.values("selections")
                if item.attempt_id == attempt.attempt_id
            ),
            None,
        )
        if not isinstance(selection, Selection):
            raise MatchingApplicationError("SERVICE_UNAVAILABLE")
        # A production UOW must map this to the documented deterministic lock
        # order; Memory keeps the same resource chain explicit for tests.
        uow.lock(
            self.operation,
            (
                attempt.attempt_id,
                selection.selection_id,
                invitation.invitation_id,
            ),
        )
        if (
            authority.profile_id != invitation.profile_id
            or authority.profile_version_id != invitation.profile_version_id
            or invitation.aggregate_version
            != command.expected_invitation_version
        ):
            raise MatchingApplicationError(
                "PRECONDITION_FAILED"
                if invitation.aggregate_version
                != command.expected_invitation_version
                else "RESOURCE_NOT_FOUND"
            )
        accepted_responses = tuple(
            item
            for item in uow.values("responses")
            if isinstance(item, InvitationResponse)
            and item.invitation_id == invitation.invitation_id
            and item.response_kind is InvitationResponseKind.ACCEPTED
        )
        if len(accepted_responses) != 1:
            raise MatchingApplicationError("SERVICE_UNAVAILABLE")
        selection_intent_recorded = (
            uow.get("selection_intents", selection.selection_id) is not None
        )
        updated, withdrawal = invitation.withdraw(
            withdrawal_id=self._required("id_source").next_id("withdrawal"),
            accepted_response_id=accepted_responses[0].response_id,
            creator_user_id=actor.actor_id,
            snapshot_sha256=command.snapshot_sha256,
            selection_status=selection.status,
            selection_intent_recorded=selection_intent_recorded,
            reason_code=command.reason_code,
            note=command.note,
            now=now,
        )
        refreshed = selection.refresh_invitation_set(
            current_invitation_set_sha256=self._current_invitation_set_hash(
                uow=uow,
                attempt=attempt,
                run=run,
                replacement=updated,
            ),
            now=now,
        )
        uow.put("withdrawals", withdrawal.withdrawal_id, withdrawal)
        uow.put("invitations", updated.invitation_id, updated)
        uow.put("selections", refreshed.selection_id, refreshed)
        result = self._result(
            updated.invitation_id,
            updated.status.value,
            updated.aggregate_version,
            now,
            False,
            ("InvitationWithdrawn", "SelectionInvitationSetChanged"),
        )
        return result, (
            updated.invitation_id,
            attempt.attempt_id,
            run.run_id,
            refreshed.selection_id,
            f"withdrawals:{withdrawal.withdrawal_id}",
        ), result.event_types

    def _choose_creator(
        self,
        uow: Any,
        actor: Any,
        command: ChooseCreatorCommand,
        authority: MatchingCandidateSelectorAuthority,
        outside: Any,
        receipt: Mapping[str, str],
        now: datetime,
    ):
        selection = self._entity(uow, "selections", command.selection_id, Selection)
        attempt = self._entity(uow, "attempts", selection.attempt_id, MatchingAttempt)
        invitation = self._entity(uow, "invitations", command.invitation_id, Invitation)
        run = self._entity(uow, "runs", invitation.match_run_id, MatchRun)
        assignment = authority.assignment
        if (
            assignment.organization_id != attempt.organization_id
            or assignment.demand_id != attempt.demand_id
            or assignment.selection_id != selection.selection_id
        ):
            raise MatchingApplicationError("RESOURCE_NOT_FOUND")
        if selection.aggregate_version != command.expected_selection_version or selection.current_invitation_set_sha256 != command.current_invitation_set_sha256:
            raise MatchingApplicationError("PRECONDITION_FAILED")
        if (
            invitation.status is not InvitationStatus.ACCEPTED
            or invitation.attempt_id != attempt.attempt_id
            or invitation.match_run_id != attempt.current_match_run_id
            or run.status is not MatchRunStatus.COMPLETED
            or run.superseded_by_run_id is not None
        ):
            raise MatchingApplicationError("SELECTION_NOT_READY")
        authoritative_invitation_set_sha256 = selection_invitation_set_sha256(
            attempt_id=attempt.attempt_id,
            run_id=run.run_id,
            invitations=tuple(
                item
                for item in uow.values("invitations")
                if item.attempt_id == attempt.attempt_id
                and item.match_run_id == run.run_id
            ),
        )
        if (
            selection.current_invitation_set_sha256
            != authoritative_invitation_set_sha256
        ):
            raise MatchingApplicationError("SERVICE_UNAVAILABLE")
        hold_binding = self._selection_hold_binding(
            get=uow.get,
            attempt=attempt,
            run=run,
            invitation=invitation,
            selection=selection,
            authority=authority,
        )
        if hold_binding != outside.get("selection_hold_binding"):
            raise MatchingApplicationError("SERVICE_UNAVAILABLE")
        self._validate_hold(
            port=outside["hold_port"],
            actor=actor,
            action=self.operation,
            attempt=attempt,
            run=run,
            invitation=invitation,
            selection=selection,
            now=now,
            expected=outside.get("hold_result"),
            selection_hold_binding=hold_binding,
        )
        # External Choose records a durable intent; CompleteSelection alone makes
        # the aggregate SELECTED and emits SelectionMade.
        receipt_id = receipt["identity"]
        choose_command_id = f"matching_choose_command_{receipt_id}"
        completion_command_id = f"complete_selection_command_{receipt_id}"
        if (
            uow.get("choose_receipts", receipt_id) is not None
            or uow.get("selection_intents", selection.selection_id) is not None
            or any(
                isinstance(item, PendingCompleteSelectionTrigger)
                and item.intent.selection_id == selection.selection_id
                for item in uow.values("pending_complete_selection_triggers")
            )
        ):
            raise MatchingApplicationError("PRECONDITION_FAILED")
        hold_result = outside.get("hold_result")
        if not isinstance(hold_result, MatchingSafetyHoldResult):
            raise MatchingApplicationError("SERVICE_UNAVAILABLE")
        intent = SelectionIntentFact(
            selection_id=selection.selection_id,
            receipt_id=receipt_id,
            choose_command_id=choose_command_id,
            event_type="SelectionIntentRecorded",
            status="COMPLETED",
            actor_id=actor.actor_id,
            organization_id=actor.organization_id,
            attempt_id=attempt.attempt_id,
            invitation_id=invitation.invitation_id,
            run_id=run.run_id,
            selection_basis_code=command.selection_basis_code,
            hold_decision=hold_result.decision.value,
            hold_valid_until=hold_result.valid_until,
            hold_binding=hold_binding,
        )
        choose_receipt = ChooseReceiptFact(
            receipt_id=receipt_id,
            command_id=choose_command_id,
            operation=self.operation,
            status="COMPLETED",
            actor_id=actor.actor_id,
            organization_id=actor.organization_id,
            correlation_id=actor.correlation_id,
            selection_id=selection.selection_id,
            attempt_id=attempt.attempt_id,
            invitation_id=invitation.invitation_id,
            run_id=run.run_id,
            expected_selection_version=selection.aggregate_version,
            expected_attempt_version=attempt.aggregate_version,
            expected_demand_version=hold_binding.demand_version,
            demand_id=hold_binding.demand_id,
            demand_version_id=hold_binding.demand_version_id,
            matching_request_id=hold_binding.matching_request_id,
            matching_request_version=hold_binding.matching_request_version,
            funding_id=hold_binding.funding_id,
            matching_rule_bundle_id=hold_binding.matching_rule_bundle_id,
            candidate_selector_assignment_id=(
                hold_binding.candidate_selector_assignment_id
            ),
            candidate_selector_assignment_version=(
                hold_binding.candidate_selector_assignment_version
            ),
            candidate_selector_authority_marker_sha256=(
                hold_binding.candidate_selector_authority_marker_sha256
            ),
            rule_manifest_sha256=hold_binding.rule_manifest_sha256,
            input_set_sha256=hold_binding.input_set_sha256,
            ordered_result_sha256=hold_binding.ordered_result_sha256,
            candidate_result_sha256=hold_binding.candidate_result_sha256,
            selection_intent_sha256=selection_intent_sha256(intent),
            payload_sha256=receipt["payload_hash"],
        )
        trigger = PendingCompleteSelectionTrigger(
            completion_command_id=completion_command_id,
            status="READY",
            recorded_at=now,
            receipt=choose_receipt,
            intent=intent,
        )
        uow.put("choose_receipts", receipt_id, choose_receipt)
        uow.put("selection_intents", selection.selection_id, intent)
        uow.put("pending_complete_selection_triggers", receipt_id, trigger)
        result = self._result(
            selection.selection_id,
            selection.status.value,
            selection.aggregate_version,
            now,
            False,
            ("SelectionIntentRecorded",),
        )
        return result, (
            f"choose_receipts:{receipt_id}",
            f"selection_intents:{selection.selection_id}",
            f"pending_complete_selection_triggers:{receipt_id}",
        ), result.event_types

    def _close_selection_without_choice(
        self,
        uow: Any,
        actor: MatchingActorContext,
        command: CloseSelectionWithoutChoiceCommand,
        authority: MatchingCandidateSelectorAuthority,
        now: datetime,
    ):
        selection = self._entity(
            uow, "selections", command.selection_id, Selection
        )
        attempt = self._entity(
            uow, "attempts", selection.attempt_id, MatchingAttempt
        )
        assignment = authority.assignment
        if (
            assignment.organization_id != attempt.organization_id
            or assignment.demand_id != attempt.demand_id
            or assignment.selection_id != selection.selection_id
        ):
            raise MatchingApplicationError("RESOURCE_NOT_FOUND")
        uow.lock(
            self.operation,
            (attempt.attempt_id, selection.selection_id),
        )
        if (
            selection.aggregate_version != command.expected_selection_version
            or selection.current_invitation_set_sha256
            != command.current_invitation_set_sha256
        ):
            raise MatchingApplicationError("PRECONDITION_FAILED")
        if uow.get("selection_intents", selection.selection_id) is not None:
            raise MatchingApplicationError("SELECTION_ALREADY_IN_PROGRESS")
        invitations = tuple(
            item
            for item in uow.values("invitations")
            if isinstance(item, Invitation)
            and item.attempt_id == attempt.attempt_id
            and item.match_run_id == attempt.current_match_run_id
        )
        authoritative_invitation_set_sha256 = selection_invitation_set_sha256(
            attempt_id=attempt.attempt_id,
            run_id=attempt.current_match_run_id,
            invitations=invitations,
        )
        if (
            selection.current_invitation_set_sha256
            != authoritative_invitation_set_sha256
        ):
            raise MatchingApplicationError("SERVICE_UNAVAILABLE")
        if any(
            invitation.status
            in {InvitationStatus.CREATED, InvitationStatus.SENT}
            for invitation in invitations
        ):
            raise MatchingApplicationError("SELECTION_NOT_READY")
        closed_selection = selection.close_without_choice(
            reason_code=command.reason_code,
            actor_id=actor.actor_id,
            now=now,
        )
        closed_attempt = attempt.close_without_selection(now=now)
        uow.put(
            "selections",
            closed_selection.selection_id,
            closed_selection,
        )
        uow.put(
            "attempts",
            closed_attempt.attempt_id,
            closed_attempt,
        )
        result = self._result(
            closed_selection.selection_id,
            closed_selection.status.value,
            closed_selection.aggregate_version,
            now,
            False,
            (
                "SelectionClosedWithoutChoice",
                "MatchingAttemptClosedWithoutSelection",
            ),
        )
        return result, (
            closed_selection.selection_id,
            closed_attempt.attempt_id,
        ), result.event_types

    @staticmethod
    def _selection_hold_binding(
        *,
        get: Any,
        attempt: MatchingAttempt,
        run: MatchRun,
        invitation: Invitation,
        selection: Selection,
        authority: MatchingCandidateSelectorAuthority,
    ) -> SelectionHoldBinding:
        attempt_binding = get("attempt_bindings", attempt.attempt_id)
        candidate = get(
            "candidates", f"{run.run_id}:{invitation.creator_user_id}"
        )
        manifest = run.input_manifest
        if (
            not isinstance(attempt_binding, AttemptDemandBinding)
            or not isinstance(candidate, MatchCandidate)
            or not isinstance(manifest, MatchInputManifest)
            or candidate.eligibility is not CandidateEligibility.ELIGIBLE
            or candidate.candidate_result_sha256
            != candidate_result_sha256(candidate)
            or (
                candidate.attempt_id,
                candidate.run_id,
                candidate.creator_user_id,
                candidate.profile_id,
                candidate.profile_version_id,
                candidate.profile_content_sha256,
            )
            != (
                attempt.attempt_id,
                run.run_id,
                invitation.creator_user_id,
                invitation.profile_id,
                invitation.profile_version_id,
                invitation.profile_content_sha256,
            )
            or attempt_binding.attempt_id != attempt.attempt_id
            or attempt_binding.organization_id != attempt.organization_id
            or attempt_binding.demand_id != attempt.demand_id
            or attempt_binding.demand_version_id != attempt.demand_version_id
            or attempt_binding.funding_id != attempt.funding_id
            or attempt_binding.matching_request_id != attempt.matching_request_id
            or attempt_binding.matching_rule_bundle_id
            != run.matching_rule_bundle_id
            or manifest.attempt_id != attempt.attempt_id
            or manifest.run_id != run.run_id
            or manifest.organization_id != attempt.organization_id
            or manifest.demand_id != attempt.demand_id
            or manifest.demand_version_id != attempt.demand_version_id
            or manifest.funding_id != attempt.funding_id
            or manifest.matching_request_id != attempt.matching_request_id
            or manifest.matching_request_version
            != attempt_binding.matching_request_version
            or manifest.matching_rule_bundle_id != run.matching_rule_bundle_id
            or manifest.rule_manifest_sha256 == ""
            or manifest.input_set_sha256 != run.input_set_sha256
            or run.ordered_result_sha256 is None
            or invitation.demand_id != attempt.demand_id
            or invitation.demand_version_id != attempt.demand_version_id
            or invitation.funding_id != attempt.funding_id
            or invitation.matching_rule_bundle_id != run.matching_rule_bundle_id
            or not isinstance(authority, MatchingCandidateSelectorAuthority)
            or authority.assignment.organization_id != attempt.organization_id
            or authority.assignment.demand_id != attempt.demand_id
            or authority.assignment.selection_id != selection.selection_id
            or not isinstance(authority.authority_marker_sha256, str)
            or len(authority.authority_marker_sha256) != 64
        ):
            raise MatchingApplicationError("SERVICE_UNAVAILABLE")
        return SelectionHoldBinding(
            selection_id=selection.selection_id,
            selection_version=selection.aggregate_version,
            current_invitation_set_sha256=(
                selection.current_invitation_set_sha256
            ),
            attempt_id=attempt.attempt_id,
            attempt_version=attempt.aggregate_version,
            invitation_id=invitation.invitation_id,
            invitation_version=invitation.aggregate_version,
            run_id=run.run_id,
            run_version=run.aggregate_version,
            demand_id=attempt_binding.demand_id,
            demand_version=attempt_binding.demand_aggregate_version,
            demand_version_id=attempt_binding.demand_version_id,
            matching_request_id=attempt_binding.matching_request_id,
            matching_request_version=attempt_binding.matching_request_version,
            funding_id=attempt_binding.funding_id,
            matching_rule_bundle_id=run.matching_rule_bundle_id,
            candidate_selector_assignment_id=(
                authority.assignment.assignment_id
            ),
            candidate_selector_assignment_version=(
                authority.assignment.aggregate_version
            ),
            candidate_selector_authority_marker_sha256=(
                authority.authority_marker_sha256
            ),
            rule_manifest_sha256=manifest.rule_manifest_sha256,
            input_set_sha256=run.input_set_sha256,
            ordered_result_sha256=run.ordered_result_sha256,
            candidate_result_sha256=candidate.candidate_result_sha256,
        )

    @staticmethod
    def _validate_system_authority(*, actor: Any, authority: Any, source_event_id: Any, run_id: Any, now: datetime) -> None:
        if not isinstance(authority, MatchingSystemAuthority) or actor.actor_kind is not MatchingActorKind.SYSTEM or authority.workload_principal_id != actor.actor_id or authority.organization_id != actor.organization_id or authority.operation == "" or authority.valid_until <= now or authority.source_event_id != source_event_id or (run_id is not None and authority.match_run_id != run_id):
            raise MatchingApplicationError("ACCESS_DENIED")

    @staticmethod
    def _validate_reviewer_authority(*, actor: Any, authority: Any, assignment_id: str, now: datetime) -> None:
        if not isinstance(authority, MatchingReviewerAuthority) or actor.actor_kind is not MatchingActorKind.USER or authority.actor_user_id != actor.actor_id or authority.session_id != actor.session_id or authority.organization_id != actor.organization_id or authority.assignment_id != assignment_id or authority.assignment_status != "ACTIVE" or authority.assignment_expires_at <= now or authority.assignment_purpose not in {"MATCH_REVIEW", "INVITATION_REVIEW"} or authority.duty_code != "OPERATIONS_REVIEWER" or not authority.conflict_attestation_sha256:
            raise MatchingApplicationError("RESOURCE_NOT_FOUND")

    @staticmethod
    def _validate_creator_authority(*, actor: Any, authority: Any, command: Any) -> None:
        if not isinstance(authority, MatchingCreatorAuthority) or actor.actor_kind is not MatchingActorKind.USER or authority.actor_user_id != actor.actor_id or authority.session_id != actor.session_id or authority.user_status != "ACTIVE" or authority.session_status != "ACTIVE" or authority.session_family_status != "ACTIVE" or authority.creator_grant_status != "ACTIVE" or authority.invitation_id != command.invitation_id:
            raise MatchingApplicationError("RESOURCE_NOT_FOUND")

    @staticmethod
    def _validate_candidate_selector_authority(
        *,
        actor: Any,
        authority: Any,
        command: ChooseCreatorCommand | CloseSelectionWithoutChoiceCommand,
        now: datetime,
    ) -> None:
        if (
            not isinstance(authority, MatchingCandidateSelectorAuthority)
            or actor.actor_kind is not MatchingActorKind.USER
            or authority.actor_user_id != actor.actor_id
            or authority.session_id != actor.session_id
            or not isinstance(authority.assignment, CandidateSelectorAssignment)
            or authority.assignment.assignment_id != command.assignment_id
            or authority.assignment.aggregate_version
            != command.expected_assignment_version
            or authority.assignment.assigned_user_id != actor.actor_id
            or authority.assignment.organization_id != actor.organization_id
            or authority.assignment.selection_id != command.selection_id
            or not isinstance(authority.authority_marker_sha256, str)
            or len(authority.authority_marker_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in authority.authority_marker_sha256
            )
        ):
            raise MatchingApplicationError("RESOURCE_NOT_FOUND")
        try:
            validate_candidate_selector_assignment(
                authority.assignment,
                database_now=now,
            )
        except MatchingDomainError as error:
            raise MatchingApplicationError("RESOURCE_NOT_FOUND") from error

    @staticmethod
    def _validate_profile(invitation: Invitation, profile: Any) -> None:
        if profile.creator_user_id != invitation.creator_user_id or profile.user_status != "ACTIVE" or profile.creator_grant_status != "ACTIVE" or profile.profile_id != invitation.profile_id or profile.profile_status != "ACTIVE" or profile.current_profile_version_id != invitation.profile_version_id or profile.current_profile_content_sha256 != invitation.profile_content_sha256:
            raise MatchingApplicationError("MATCH_INPUT_CHANGED")

    def _hold_binding(
        self,
        *,
        actor: Any,
        action: str,
        attempt: MatchingAttempt,
        run: Optional[MatchRun],
        invitation: Optional[Invitation],
        selection: Optional[Selection],
        selection_hold_binding: Optional[SelectionHoldBinding] = None,
    ) -> dict[str, Any]:
        if selection_hold_binding is None:
            prospective_versions = (
                attempt.aggregate_version + 1,
                run.aggregate_version if run else None,
                invitation.aggregate_version if invitation else None,
                selection.aggregate_version if selection else None,
            )
            snapshot_surface: Any = (
                attempt.demand_version_id,
                run.input_set_sha256 if run else None,
                run.ordered_result_sha256 if run else None,
                invitation.snapshot_sha256 if invitation else None,
            )
        else:
            prospective_versions = (
                selection_hold_binding.selection_version + 1,
                selection_hold_binding.attempt_version + 1,
                selection_hold_binding.demand_version + 1,
                selection_hold_binding.invitation_version,
                selection_hold_binding.run_version,
            )
            snapshot_surface = asdict(selection_hold_binding)
        return {
            "action": action, "actor_id": actor.actor_id,
            "organization_id": attempt.organization_id,
            "attempt_id": attempt.attempt_id,
            "match_run_id": run.run_id if run else None,
            "candidate_creator_user_id": invitation.creator_user_id if invitation else None,
            "invitation_id": invitation.invitation_id if invitation else None,
            "selection_id": selection.selection_id if selection else None,
            "prospective_versions_sha256": self._simple_hash(prospective_versions),
            "demand_profile_input_result_snapshot_sha256": self._simple_hash(snapshot_surface),
            "policy_version": "matching-safety-hold-v1",
        }

    def _validate_hold(
        self,
        *,
        port: Any,
        actor: Any,
        action: str,
        attempt: MatchingAttempt,
        run: Optional[MatchRun],
        invitation: Optional[Invitation],
        selection: Optional[Selection],
        now: datetime,
        expected: Optional[MatchingSafetyHoldResult] = None,
        selection_hold_binding: Optional[SelectionHoldBinding] = None,
    ) -> None:
        binding = self._hold_binding(
            actor=actor,
            action=action,
            attempt=attempt,
            run=run,
            invitation=invitation,
            selection=selection,
            selection_hold_binding=selection_hold_binding,
        )
        result = expected if expected is not None else port.evaluate(**binding)
        self._validate_hold_result(binding=binding, result=result, now=now)

    @staticmethod
    def _validate_hold_result(
        *,
        binding: Mapping[str, Any],
        result: Any,
        now: datetime,
    ) -> None:
        if not isinstance(result, MatchingSafetyHoldResult):
            raise MatchingApplicationError("SERVICE_UNAVAILABLE")
        for key, value in binding.items():
            if getattr(result, key) != value:
                raise MatchingApplicationError("SERVICE_UNAVAILABLE")
        if result.valid_until <= now:
            raise MatchingApplicationError("SERVICE_UNAVAILABLE")
        if result.decision is MatchingHoldDecision.BLOCK:
            raise MatchingApplicationError("SAFETY_HOLD_BLOCKED")

    def _receipt_binding(self, *, actor: Any, command: Any) -> dict[str, Any]:
        raw_key = getattr(command, "idempotency_key", None)
        if raw_key is None:
            raw_key = getattr(command, "scheduler_command_id", None)
        if raw_key is None and isinstance(command, CreateMatchingAttemptCommand):
            raw_key = command.source_event.event_id
        if raw_key is None:
            raw_key = f"{self.operation}:{getattr(command, 'match_run_id', '')}:{getattr(command, 'fencing_generation', '')}"
        keyring = self._required("receipt_keyring")
        identity_key_id = getattr(keyring, "identity_key_id", None)
        payload_hash_key_id = getattr(keyring, "payload_hash_key_id", None)
        if (
            not isinstance(identity_key_id, str)
            or not identity_key_id
            or not isinstance(payload_hash_key_id, str)
            or not payload_hash_key_id
            or identity_key_id == payload_hash_key_id
            or not isinstance(raw_key, str)
            or not raw_key
        ):
            raise MatchingApplicationError("SERVICE_UNAVAILABLE")
        identity_surface = {
            "canonicalization_version": "matching-command-json-v1",
            "command_version": 1,
            "principal_kind": actor.actor_kind.value,
            "principal_id": actor.actor_id,
            "organization_id": actor.organization_id,
            "operation": self.operation,
            "idempotency_key": raw_key,
        }
        identity_bytes = json.dumps(
            identity_surface,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        identity = keyring.keyed_digest(identity_key_id, identity_bytes)
        payload = keyring.keyed_digest(
            payload_hash_key_id, self._canonical_command(actor, command)
        )
        if (
            not isinstance(identity, str)
            or len(identity) != 64
            or not isinstance(payload, str)
            or len(payload) != 64
        ):
            raise MatchingApplicationError("SERVICE_UNAVAILABLE")
        return {
            "command_version": 1,
            "canonicalization_version": "matching-command-json-v1",
            "identity_key_id": identity_key_id,
            "payload_hash_key_id": payload_hash_key_id,
            "principal_kind": actor.actor_kind.value,
            "principal_id": actor.actor_id,
            "organization_id": actor.organization_id,
            "operation": self.operation,
            "identity": identity,
            "payload_hash": payload,
        }

    def _read_completed_receipt(self, receipt: Mapping[str, str]) -> Optional[Mapping[str, Any]]:
        persisted = self._required("uow_factory").store.snapshot().get("receipts", {}).get(receipt["identity"])
        if persisted is None:
            return None
        return self._validate_receipt(persisted, receipt)

    def _resolve_locked_receipt(self, *, existing: Any, receipt: Any) -> MatchingCommandResult:
        return self._result_from_receipt(self._validate_receipt(existing, receipt), replayed=True)

    def _validate_receipt(self, persisted: Any, receipt: Mapping[str, Any]) -> Mapping[str, Any]:
        expected_keys = {
            *receipt.keys(),
            "status",
            "safe_response",
            "recovery_facts",
        }
        if not isinstance(persisted, Mapping) or set(persisted) != expected_keys:
            raise MatchingApplicationError("SERVICE_UNAVAILABLE")
        if (
            persisted.get("command_version") != 1
            or persisted.get("canonicalization_version")
            != "matching-command-json-v1"
            or persisted.get("identity_key_id") != receipt["identity_key_id"]
            or persisted.get("payload_hash_key_id")
            != receipt["payload_hash_key_id"]
            or persisted.get("principal_kind") != receipt["principal_kind"]
            or persisted.get("principal_id") != receipt["principal_id"]
            or persisted.get("organization_id") != receipt["organization_id"]
            or persisted.get("operation") != receipt["operation"]
            or persisted.get("identity") != receipt["identity"]
            or not isinstance(persisted.get("payload_hash"), str)
            or len(persisted["payload_hash"]) != 64
        ):
            raise MatchingApplicationError("SERVICE_UNAVAILABLE")
        if persisted["payload_hash"] != receipt["payload_hash"]:
            raise MatchingApplicationError("IDEMPOTENCY_KEY_REUSED")
        if (
            persisted.get("status") != "COMPLETED"
            or not isinstance(persisted.get("safe_response"), Mapping)
        ):
            raise MatchingApplicationError("SERVICE_UNAVAILABLE")
        self._required("safe_response_validator").validate(
            operation=self.operation, response=persisted["safe_response"]
        )
        recovery_facts = persisted.get("recovery_facts")
        if not isinstance(recovery_facts, list) or not recovery_facts:
            raise MatchingApplicationError("SERVICE_UNAVAILABLE")
        snapshot = self._required("uow_factory").store.snapshot()
        for expected in recovery_facts:
            if (
                not isinstance(expected, Mapping)
                or set(expected) != {"collection", "identifier", "marker"}
                or not all(isinstance(expected[key], str) for key in expected)
            ):
                raise MatchingApplicationError("SERVICE_UNAVAILABLE")
            actual = snapshot.get(expected.get("collection"), {}).get(
                expected.get("identifier")
            )
            if self._fact_marker(actual) != expected.get("marker"):
                raise MatchingApplicationError("SERVICE_UNAVAILABLE")
        self._validate_safe_target(
            snapshot=snapshot,
            safe=persisted["safe_response"],
            receipt_identity=receipt["identity"],
        )
        return persisted

    def _recover_unknown(self, receipt: Mapping[str, str]) -> MatchingCommandResult:
        persisted = self._required("recovery_reader").read_receipt(receipt["identity"])
        validated = self._validate_receipt(persisted, receipt)
        safe = validated["safe_response"]
        body = safe["body"]
        if self.operation != "CHOOSE_CREATOR":
            state = self._required("recovery_reader").read_target(
                body["target_id"]
            )
            if state is None or state.aggregate_version != body["aggregate_version"] or state.status.value != body["target_status"]:
                raise MatchingApplicationError("SERVICE_UNAVAILABLE")
        return self._result_from_receipt(validated, replayed=True)

    def _safe_response(self, result: MatchingCommandResult) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "response_schema": "MatchingCommandResult",
            "http_status": 201 if self.operation == "CREATE_INVITATION" else 200,
            "etag": f'"v{result.aggregate_version}"',
            "body": {
                "target_id": result.target_id,
                "target_status": result.target_status,
                "aggregate_version": result.aggregate_version,
                "updated_at": result.updated_at.isoformat().replace(
                    "+00:00", "Z"
                ),
                "event_types": list(result.event_types),
            },
        }

    def _result_from_receipt(self, receipt: Mapping[str, Any], *, replayed: bool) -> MatchingCommandResult:
        safe = receipt["safe_response"]["body"]
        return MatchingCommandResult(target_id=safe["target_id"], target_status=safe["target_status"], aggregate_version=safe["aggregate_version"], updated_at=datetime.fromisoformat(safe["updated_at"].replace("Z", "+00:00")), replayed=replayed, event_types=tuple(safe["event_types"]))

    @staticmethod
    def _result(target_id: str, status: str, version: int, now: datetime, replayed: bool, event_types: tuple[str, ...]) -> MatchingCommandResult:
        return MatchingCommandResult(target_id=target_id, target_status=status, aggregate_version=version, updated_at=now, replayed=replayed, event_types=event_types)

    def _entity(self, uow: Any, collection: str, key: str, expected: type) -> Any:
        value = uow.get(collection, key)
        if value is None or (expected is not object and not isinstance(value, expected)):
            raise MatchingApplicationError("RESOURCE_NOT_FOUND")
        return value

    @staticmethod
    def _lock_keys(command: Any) -> tuple[str, ...]:
        return tuple(str(value) for name in ("attempt_id", "match_run_id", "invitation_id", "selection_id", "assignment_id") if (value := getattr(command, name, None)) is not None)

    def _audit_record(
        self,
        *,
        actor: Any,
        command: Any,
        authority: Any,
        result: Any,
        now: datetime,
    ) -> dict[str, Any]:
        record = {
            "schema_version": 1,
            "operation": self.operation,
            "command_version": 1,
            "actor_kind": actor.actor_kind.value,
            "actor_id": actor.actor_id,
            "original_actor_id": actor.original_actor_id,
            "organization_id": actor.organization_id,
            "target_id": result.target_id,
            "target_status": result.target_status,
            "aggregate_version": result.aggregate_version,
            "result_code": "SUCCESS",
            "event_types": list(result.event_types),
            "occurred_at": now.isoformat().replace("+00:00", "Z"),
            "correlation_id": actor.correlation_id,
            "causation_id": actor.causation_id,
            "trace_id": actor.trace_id,
        }
        if isinstance(authority, MatchingCandidateSelectorAuthority):
            record["candidate_selector_assignment_id"] = (
                authority.assignment.assignment_id
            )
            record["candidate_selector_assignment_version"] = (
                authority.assignment.aggregate_version
            )
            record["candidate_selector_role_code"] = (
                authority.assignment.role_code.value
            )
        return record

    def _event(
        self,
        *,
        event_type: str,
        actor: Any,
        command: Any,
        result: Any,
        uow: Any,
        now: datetime,
    ) -> dict[str, Any]:
        aggregate_type: str
        aggregate: Any
        payload: dict[str, Any]
        if event_type.startswith("MatchingAttempt"):
            if isinstance(command, CreateMatchingAttemptCommand):
                aggregate = uow.get("attempts", result.target_id)
            elif isinstance(command, CloseSelectionWithoutChoiceCommand):
                selection = uow.get("selections", command.selection_id)
                aggregate = uow.get("attempts", selection.attempt_id)
            else:
                run_id = getattr(command, "match_run_id", result.target_id)
                run = uow.get("runs", run_id)
                aggregate = uow.get("attempts", run.attempt_id)
            aggregate_type = "MatchingAttempt"
            payload = {
                "attempt_id": aggregate.attempt_id,
                "demand_id": aggregate.demand_id,
                "demand_version_id": aggregate.demand_version_id,
                "matching_request_id": aggregate.matching_request_id,
                "attempt_no": aggregate.attempt_no,
                "status": aggregate.status.value,
                "reason_code": None,
                "selection_id": aggregate.selection_id,
                "chosen_invitation_id": None,
            }
        elif event_type.startswith("MatchRun"):
            if event_type == "MatchRunSuperseded":
                aggregate = next(
                    item
                    for item in uow.values("runs")
                    if item.superseded_by_run_id == result.target_id
                )
                run_id = aggregate.run_id
            else:
                run_id = (
                    result.target_id
                    if uow.get("runs", result.target_id) is not None
                    else uow.get("attempts", result.target_id).current_match_run_id
                )
            aggregate = uow.get("runs", run_id)
            aggregate_type = "MatchRun"
            payload = {
                "run_id": aggregate.run_id,
                "attempt_id": aggregate.attempt_id,
                "run_no": aggregate.run_no,
                "rule_bundle_id": aggregate.matching_rule_bundle_id,
                "input_set_sha256": aggregate.input_set_sha256 or "0" * 64,
                "status": aggregate.status.value,
                "candidate_count": aggregate.candidate_count,
                "eligible_count": aggregate.eligible_count,
                "excluded_count": aggregate.excluded_count,
                "ordered_result_sha256": aggregate.ordered_result_sha256,
                "failure_code": aggregate.failure_code,
                "successor_run_id": aggregate.superseded_by_run_id,
            }
        elif event_type.startswith("Invitation"):
            invitation_id = getattr(command, "invitation_id", result.target_id)
            aggregate = uow.get("invitations", invitation_id)
            aggregate_type = "Invitation"
            reason_code = None
            response = next(
                (
                    item
                    for item in uow.values("responses")
                    if item.invitation_id == aggregate.invitation_id
                ),
                None,
            )
            if response is not None:
                reason_code = response.reason_code
            if event_type == "InvitationWithdrawn":
                withdrawal = next(
                    (
                        item
                        for item in uow.values("withdrawals")
                        if item.invitation_id == aggregate.invitation_id
                    ),
                    None,
                )
                if withdrawal is None:
                    raise MatchingApplicationError("SERVICE_UNAVAILABLE")
                reason_code = withdrawal.reason_code
            payload = {
                "invitation_id": aggregate.invitation_id,
                "attempt_id": aggregate.attempt_id,
                "run_id": aggregate.match_run_id,
                "creator_user_id": aggregate.creator_user_id,
                "profile_version_id": aggregate.profile_version_id,
                "snapshot_sha256": aggregate.snapshot_sha256,
                "status": aggregate.status.value,
                "expires_at": aggregate.expires_at.isoformat().replace(
                    "+00:00", "Z"
                ),
                "reason_code": reason_code,
            }
        else:
            if uow.get("selections", result.target_id) is not None:
                selection_id = result.target_id
            elif uow.get("attempts", result.target_id) is not None:
                selection_id = uow.get("attempts", result.target_id).selection_id
            elif uow.get("invitations", result.target_id) is not None:
                invitation = uow.get("invitations", result.target_id)
                selection_id = uow.get("attempts", invitation.attempt_id).selection_id
            else:
                raise MatchingApplicationError("SERVICE_UNAVAILABLE")
            aggregate = uow.get("selections", selection_id)
            aggregate_type = "Selection"
            intent = uow.get("selection_intents", selection_id)
            projected_status = (
                "PENDING_CHOICE"
                if event_type == "SelectionIntentRecorded"
                else aggregate.status.value
            )
            payload = {
                "selection_id": aggregate.selection_id,
                "attempt_id": aggregate.attempt_id,
                "status": projected_status,
                "current_invitation_set_sha256": aggregate.current_invitation_set_sha256,
                "chosen_invitation_id": (
                    intent.invitation_id
                    if event_type == "SelectionIntentRecorded"
                    else aggregate.chosen_invitation_id
                ),
                "selection_basis_code": (
                    intent.selection_basis_code
                    if event_type == "SelectionIntentRecorded"
                    else aggregate.selection_basis_code
                ),
                "reason_code": aggregate.reason_code,
            }
        return {
            "event_id": self._required("id_source").next_id("event"),
            "event_type": event_type,
            "schema_version": 1,
            "occurred_at": now.isoformat().replace("+00:00", "Z"),
            "aggregate_type": aggregate_type,
            "aggregate_id": aggregate.attempt_id
            if aggregate_type == "MatchingAttempt"
            else getattr(
                aggregate,
                {
                    "MatchRun": "run_id",
                    "Invitation": "invitation_id",
                    "Selection": "selection_id",
                }[aggregate_type],
            ),
            "aggregate_version": aggregate.aggregate_version,
            "actor_kind": actor.actor_kind.value,
            "actor_id": actor.actor_id,
            "original_actor_id": actor.original_actor_id,
            "organization_id": actor.organization_id,
            "correlation_id": actor.correlation_id,
            "causation_id": actor.causation_id,
            "trace_id": actor.trace_id,
            "payload": payload,
        }

    def _canonical_command(self, actor: Any, command: Any) -> bytes:
        def normalize(value: Any) -> Any:
            if is_dataclass(value):
                return {
                    key: normalize(child)
                    for key, child in asdict(value).items()
                    if key
                    not in {"idempotency_key", "scheduler_command_id"}
                }
            if isinstance(value, Enum):
                return value.value
            if isinstance(value, datetime):
                return value.isoformat().replace("+00:00", "Z")
            if isinstance(value, Decimal):
                return format(value, "f")
            if isinstance(value, tuple):
                return [normalize(child) for child in value]
            if isinstance(value, dict):
                return {str(key): normalize(child) for key, child in value.items()}
            return value
        transport = self._command_transport(actor=actor, command=command)
        surface = {
            "method": "POST",
            "canonical_path": transport["canonical_path"],
            "organization_id": actor.organization_id,
            "target": transport["target"],
            "if_match": transport["if_match"],
            "command_schema_version": 1,
            "body": normalize(command),
        }
        return json.dumps(
            surface,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")

    def _command_transport(
        self, *, actor: MatchingActorContext, command: Any
    ) -> dict[str, Any]:
        parent_kind: Optional[str] = None
        parent_id: Optional[str] = None
        if_match: Optional[int] = None
        if isinstance(command, CreateMatchingAttemptCommand):
            target_kind = "Demand"
            target_id = command.source_event.demand_id
            path = (
                "/internal/matching/source-events/"
                f"{command.source_event.event_id}"
            )
        elif isinstance(command, StartMatchRunCommand):
            target_kind = "MatchRun"
            target_id = command.match_run_id
            path = f"/internal/matching/match-runs/{target_id}/start"
        elif isinstance(command, CompleteMatchRunCommand):
            target_kind = "MatchRun"
            target_id = command.match_run_id
            path = f"/internal/matching/match-runs/{target_id}/complete"
        elif isinstance(command, RetryMatchRunCommand):
            target_kind = "MatchingAttempt"
            target_id = command.attempt_id
            if_match = command.expected_attempt_version
            path = f"/internal/matching/matching-attempts/{target_id}/retry"
        elif isinstance(command, CreateInvitationCommand):
            target_kind = "MatchRun"
            target_id = command.match_run_id
            if_match = command.expected_run_version
            path = f"/v1/operations/match-runs/{target_id}/invitations"
        elif isinstance(command, PublishInvitationCommand):
            target_kind = "Invitation"
            target_id = command.invitation_id
            if_match = command.expected_invitation_version
            path = (
                "/v1/operations/matching-invitations/"
                f"{target_id}/publish"
            )
        elif isinstance(command, RespondInvitationCommand):
            target_kind = "Invitation"
            target_id = command.invitation_id
            if_match = command.expected_invitation_version
            response = "accept" if command.accept else "decline"
            path = f"/v1/me/matching-invitations/{target_id}/{response}"
        elif isinstance(command, WithdrawAcceptedInvitationCommand):
            target_kind = "Invitation"
            target_id = command.invitation_id
            if_match = command.expected_invitation_version
            path = (
                f"/v1/me/matching-invitations/{target_id}/withdraw"
            )
        elif isinstance(command, ChooseCreatorCommand):
            target_kind = "Selection"
            target_id = command.selection_id
            if_match = command.expected_selection_version
            path = (
                f"/v1/organizations/{actor.organization_id}/selections/"
                f"{target_id}/choose"
            )
        elif isinstance(command, CloseSelectionWithoutChoiceCommand):
            target_kind = "Selection"
            target_id = command.selection_id
            if_match = command.expected_selection_version
            path = (
                f"/v1/organizations/{actor.organization_id}/selections/"
                f"{target_id}/close"
            )
        else:
            raise MatchingApplicationError("SERVICE_UNAVAILABLE")
        return {
            "canonical_path": path,
            "target": {
                "kind": target_kind,
                "id": target_id,
                "parent_kind": parent_kind,
                "parent_id": parent_id,
            },
            "if_match": if_match,
        }

    def _validate_safe_target(
        self,
        *,
        snapshot: Mapping[str, Mapping[str, Any]],
        safe: Mapping[str, Any],
        receipt_identity: Optional[str] = None,
    ) -> None:
        body = safe.get("body")
        if not isinstance(body, Mapping):
            raise MatchingApplicationError("SERVICE_UNAVAILABLE")
        if self.operation == "CHOOSE_CREATOR":
            trigger = snapshot.get(
                "pending_complete_selection_triggers", {}
            ).get(receipt_identity)
            if not isinstance(trigger, PendingCompleteSelectionTrigger):
                raise MatchingApplicationError("SERVICE_UNAVAILABLE")
            expected_version = trigger.receipt.expected_selection_version
            expected_updated_at = trigger.recorded_at.isoformat().replace(
                "+00:00", "Z"
            )
            if (
                body.get("target_id") != trigger.intent.selection_id
                or body.get("target_status") != "OPEN"
                or body.get("aggregate_version") != expected_version
                or body.get("updated_at") != expected_updated_at
                or body.get("event_types") != ["SelectionIntentRecorded"]
                or safe.get("etag") != f'"v{expected_version}"'
                or safe.get("http_status") != 200
            ):
                raise MatchingApplicationError("SERVICE_UNAVAILABLE")
            return
        target_id = body.get("target_id")
        target = None
        for collection in ("attempts", "runs", "invitations", "selections"):
            target = snapshot.get(collection, {}).get(target_id)
            if target is not None:
                break
        if (
            target is None
            or target.aggregate_version != body.get("aggregate_version")
            or target.status.value != body.get("target_status")
            or target.updated_at.isoformat().replace("+00:00", "Z")
            != body.get("updated_at")
            or safe.get("etag") != f'"v{target.aggregate_version}"'
            or safe.get("http_status")
            != (201 if self.operation == "CREATE_INVITATION" else 200)
        ):
            raise MatchingApplicationError("SERVICE_UNAVAILABLE")

    @staticmethod
    def _simple_hash(value: Any) -> str:
        import hashlib
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()

    @staticmethod
    def _current_invitation_set_hash(
        *,
        uow: Any,
        attempt: MatchingAttempt,
        run: MatchRun,
        replacement: Invitation,
    ) -> str:
        invitations = tuple(
            item
            for item in uow.values("invitations")
            if item.attempt_id == attempt.attempt_id
            and item.match_run_id == run.run_id
            and item.invitation_id != replacement.invitation_id
        ) + (replacement,)
        return selection_invitation_set_sha256(
            attempt_id=attempt.attempt_id,
            run_id=run.run_id,
            invitations=invitations,
        )

    def _recovery_facts(
        self, *, uow: Any, identifiers: tuple[str, ...]
    ) -> list[dict[str, str]]:
        facts: list[dict[str, str]] = []
        for identifier in identifiers:
            prefix, separator, remainder = identifier.partition(":")
            if separator and prefix in {
                "run_inputs",
                "candidates",
                "snapshots",
                "responses",
                "withdrawals",
                "selection_intents",
                "attempt_bindings",
                "choose_receipts",
                "pending_complete_selection_triggers",
            }:
                collection = prefix
                key = remainder
            else:
                collection = ""
                key = identifier
                for candidate_collection in (
                    "attempts",
                    "runs",
                    "invitations",
                    "selections",
                ):
                    if uow.get(candidate_collection, key) is not None:
                        collection = candidate_collection
                        break
            if not collection:
                raise MatchingApplicationError("SERVICE_UNAVAILABLE")
            value = uow.get(collection, key)
            facts.append(
                {
                    "collection": collection,
                    "identifier": key,
                    "marker": self._fact_marker(value),
                }
            )
        return facts

    def _fact_marker(self, value: Any) -> str:
        if value is None:
            return ""
        if is_dataclass(value):
            surface = {
                "type": value.__class__.__name__,
                "facts": asdict(value),
            }
        elif isinstance(value, Mapping):
            surface = dict(value)
        else:
            raise MatchingApplicationError("SERVICE_UNAVAILABLE")
        return self._simple_hash(surface)


class CreateMatchingAttemptHandler(_MatchingHandler): operation = "CREATE_MATCHING_ATTEMPT"
class StartMatchRunHandler(_MatchingHandler): operation = "START_MATCH_RUN"
class CompleteMatchRunHandler(_MatchingHandler): operation = "COMPLETE_MATCH_RUN"
class FailMatchRunHandler(_MatchingHandler): operation = "FAIL_MATCH_RUN"
class RetryMatchRunHandler(_MatchingHandler): operation = "RETRY_MATCH_RUN"
class CreateInvitationHandler(_MatchingHandler): operation = "CREATE_INVITATION"
class PublishInvitationHandler(_MatchingHandler): operation = "PUBLISH_INVITATION"
class RespondInvitationHandler(_MatchingHandler): operation = "RESPOND_INVITATION"
class WithdrawAcceptedInvitationHandler(_MatchingHandler): operation = "WITHDRAW_ACCEPTED_INVITATION"
class ChooseCreatorHandler(_MatchingHandler): operation = "CHOOSE_CREATOR"
class CloseSelectionWithoutChoiceHandler(_MatchingHandler): operation = "CLOSE_SELECTION_WITHOUT_CHOICE"
class ExpireInvitationHandler(_MatchingHandler): operation = "EXPIRE_INVITATION"
class InvalidateAttemptHandler(_MatchingHandler): operation = "INVALIDATE_ATTEMPT"
