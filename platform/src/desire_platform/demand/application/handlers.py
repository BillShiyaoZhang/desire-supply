"""Framework-neutral Memory orchestration for Demand v1.

The handlers use only the published dependency ports.  They preserve one
transaction for aggregate facts, receipts/inbox, audit, and outbox; transaction
failures never fall back to IAM fixtures, owner connections, or partial writes.
"""

from __future__ import annotations

from dataclasses import fields, is_dataclass, replace
from datetime import datetime, timezone
from enum import Enum
import json
from typing import Any, Mapping, Optional

from ..domain.model import (
    Demand,
    DemandContent,
    DemandDomainError,
    DemandFundingMarker,
    DemandReview,
    DemandReviewAssignment,
    DemandStatus,
    DemandSubmission,
    DemandVersion,
    MatchingRequest,
    ReviewAssignmentStatus,
    demand_version_content_sha256,
)
from ..ports.commands import (
    DemandAuthorityUnavailableError,
    DemandCommitOutcomeUnknownError,
    DemandContentPolicyDecision,
    DemandContentPolicyUnavailableError,
    DemandHoldDecision,
    DemandRuleCatalogUnavailableError,
    DemandSafetyHoldUnavailableError,
    DemandSourceEventInvalidError,
    DemandStorageUnavailableError,
)
from .commands import (
    ApplyFundingSecuredCommand,
    CancelDemandCommand,
    CreateDemandCommand,
    CreateDemandVersionCommand,
    DemandActorContext,
    DemandActorKind,
    DemandCommandResult,
    ExpireDemandCommand,
    FundingSecuredSourceEvent,
    RequestDemandChangesCommand,
    RequestMatchingCommand,
    SubmitDemandCommand,
    VerifyDemandCommand,
)


DEMAND_APPLICATION_BEHAVIOR_NOT_AVAILABLE = (
    "DEMAND_APPLICATION_BEHAVIOR_NOT_AVAILABLE"
)


class DemandApplicationBehaviorNotAvailable(RuntimeError):
    """Compatibility type retained after the Memory behavior became available."""


class DemandApplicationError(RuntimeError):
    """Closed application error safe for the future presenter boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


_DEPENDENCY_ERRORS = (
    DemandAuthorityUnavailableError,
    DemandContentPolicyUnavailableError,
    DemandRuleCatalogUnavailableError,
    DemandSafetyHoldUnavailableError,
    DemandSourceEventInvalidError,
)


def demand_command_payload_hash(
    *,
    actor: DemandActorContext,
    command: Any,
    receipt_keyring: Any,
) -> str:
    """Return the domain-separated keyed payload hash used by receipts."""

    payload = _canonical_command_payload(
        actor=actor,
        command=command,
        receipt_keyring=receipt_keyring,
    )
    return receipt_keyring.keyed_digest(
        receipt_keyring.payload_hash_key_id,
        payload,
    )


class _DemandHandler:
    operation = ""

    def __init__(
        self,
        *,
        owner_authority: Any,
        review_authority: Any,
        system_authority: Any,
        content_policy: Any,
        safety_hold: Any,
        rule_catalog: Any,
        source_event_validator: Any,
        uow_factory: Any,
        clock: Any,
        id_source: Any,
        receipt_keyring: Any,
        event_validator: Any,
        safe_response_validator: Any,
        content_policy_version: str = "demand-content-policy-v1",
        safety_hold_policy_version: str = "demand-safety-hold-v1",
    ) -> None:
        self._owner_authority = owner_authority
        self._review_authority = review_authority
        self._system_authority = system_authority
        self._content_policy = content_policy
        self._safety_hold = safety_hold
        self._rule_catalog = rule_catalog
        self._source_event_validator = source_event_validator
        self._uow_factory = uow_factory
        self._clock = clock
        self._id_source = id_source
        self._receipt_keyring = receipt_keyring
        self._event_validator = event_validator
        self._safe_response_validator = safe_response_validator
        self._content_policy_version = content_policy_version
        self._safety_hold_policy_version = safety_hold_policy_version

    def _execute(
        self,
        *,
        actor: DemandActorContext,
        command: Any,
    ) -> DemandCommandResult:
        try:
            now = self._clock.now()
            authority = self._authorize(actor=actor, command=command, now=now)
            snapshot = self._uow_factory.store.snapshot()
            receipt = self._receipt_context(actor=actor, command=command)
            replay = self._find_receipt(snapshot, receipt)
            if replay is not None:
                return self._resolve_existing_receipt(
                    snapshot=snapshot,
                    receipt=receipt,
                    persisted=replay,
                    now=now,
                )
            outside = self._outside_checks(
                actor=actor,
                command=command,
                snapshot=snapshot,
                now=now,
            )
            return self._transaction(
                actor=actor,
                command=command,
                authority=authority,
                receipt=receipt,
                outside=outside,
                now=now,
            )
        except DemandApplicationError:
            raise
        except DemandDomainError as error:
            raise DemandApplicationError(error.code) from error
        except _DEPENDENCY_ERRORS as error:
            raise DemandApplicationError("SERVICE_UNAVAILABLE") from error
        except DemandStorageUnavailableError as error:
            raise DemandApplicationError("SERVICE_UNAVAILABLE") from error

    def _authorize(
        self,
        *,
        actor: DemandActorContext,
        command: Any,
        now: datetime,
    ) -> Any:
        demand_id = getattr(command, "demand_id", None)
        if self.operation in {
            "CREATE_DEMAND",
            "CREATE_DEMAND_VERSION",
            "SUBMIT_DEMAND",
        } or (
            self.operation == "CANCEL_DEMAND"
            and getattr(command, "assignment_id", None) is None
        ):
            authority = self._owner_authority.authorize(
                actor=actor,
                operation=self.operation,
                demand_id=demand_id,
            )
            self._validate_owner_authority(actor, authority)
            return authority
        if self.operation == "REQUEST_MATCHING" and (
            actor.actor_kind is DemandActorKind.SYSTEM
        ):
            if getattr(command, "assignment_id", None) is not None:
                _app_reject("INVALID_REQUEST")
            authority = self._system_authority.authorize(
                actor=actor,
                operation=self.operation,
                demand_id=demand_id,
                source_event_id=None,
            )
            self._validate_system_authority(
                actor,
                authority,
                demand_id=demand_id,
                source_event_id=None,
                now=now,
            )
            return authority
        if self.operation in {
            "REQUEST_DEMAND_CHANGES",
            "VERIFY_DEMAND",
            "REQUEST_MATCHING",
        } or (
            self.operation == "CANCEL_DEMAND"
            and getattr(command, "assignment_id", None) is not None
        ):
            assignment_id = getattr(command, "assignment_id", None)
            if not isinstance(assignment_id, str):
                _app_reject("RESOURCE_NOT_FOUND")
            authority = self._review_authority.authorize(
                actor=actor,
                operation=self.operation,
                assignment_id=assignment_id,
                demand_id=demand_id,
            )
            self._validate_review_authority(
                actor,
                authority,
                assignment_id=assignment_id,
                demand_id=demand_id,
                now=now,
            )
            return authority
        source_event_id = (
            command.source_event.event_id
            if isinstance(command, ApplyFundingSecuredCommand)
            else None
        )
        authority = self._system_authority.authorize(
            actor=actor,
            operation=self.operation,
            demand_id=demand_id,
            source_event_id=source_event_id,
        )
        self._validate_system_authority(
            actor,
            authority,
            demand_id=demand_id,
            source_event_id=source_event_id,
            now=now,
        )
        if isinstance(command, ApplyFundingSecuredCommand):
            self._source_event_validator.validate(
                actor=actor,
                event=command.source_event,
            )
            self._validate_funding_event(actor, command.source_event)
        return authority

    @staticmethod
    def _validate_owner_authority(actor: DemandActorContext, authority: Any) -> None:
        if (
            actor.actor_kind is not DemandActorKind.USER
            or authority.actor_user_id != actor.actor_id
            or authority.session_id != actor.session_id
            or authority.organization_id != actor.organization_id
            or authority.user_status != "ACTIVE"
            or authority.session_status != "ACTIVE"
            or authority.session_family_status != "ACTIVE"
            or authority.organization_status != "ACTIVE"
            or authority.membership_status != "ACTIVE"
            or authority.role_code != "DEMAND_OWNER"
            or not authority.policy_requirements_satisfied
            or authority.membership_role_grant_version < 1
        ):
            _app_reject("RESOURCE_NOT_FOUND")

    @staticmethod
    def _validate_review_authority(
        actor: DemandActorContext,
        authority: Any,
        *,
        assignment_id: str,
        demand_id: str,
        now: datetime,
    ) -> None:
        if authority.reviewer_is_creator or authority.reviewer_is_owning_organization_member:
            _app_reject("REVIEW_CONFLICT")
        if (
            actor.actor_kind is not DemandActorKind.USER
            or authority.actor_user_id != actor.actor_id
            or authority.session_id != actor.session_id
            or authority.organization_id != actor.organization_id
            or authority.demand_id != demand_id
            or authority.assignment_id != assignment_id
            or authority.assignment_status != "ACTIVE"
            or authority.assignment_version < 1
            or authority.assignment_expires_at <= now
            or authority.duty_code != "OPERATIONS_REVIEWER"
            or authority.duty_grant_version < 1
        ):
            _app_reject("RESOURCE_NOT_FOUND")

    def _validate_system_authority(
        self,
        actor: DemandActorContext,
        authority: Any,
        *,
        demand_id: str,
        source_event_id: Optional[str],
        now: datetime,
    ) -> None:
        if (
            actor.actor_kind is not DemandActorKind.SYSTEM
            or authority.workload_principal_id != actor.actor_id
            or authority.workload_credential_id != actor.workload_credential_id
            or authority.operation != self.operation
            or authority.organization_id != actor.organization_id
            or authority.demand_id != demand_id
            or authority.source_event_id != source_event_id
            or authority.valid_until <= now
        ):
            _app_reject("RESOURCE_NOT_FOUND")

    @staticmethod
    def _validate_funding_event(
        actor: DemandActorContext,
        event: FundingSecuredSourceEvent,
    ) -> None:
        if (
            event.event_type != "FundingSecured"
            or event.schema_version != 1
            or event.source_aggregate_type != "Funding"
            or event.organization_id != actor.organization_id
            or event.target_type != "DEMAND_VERSION"
            or event.observed_status != "SECURED"
            or event.source_aggregate_id != event.funding_id
            or event.source_aggregate_version < 1
        ):
            _app_reject("FUNDING_FACT_CHANGED")

    def _outside_checks(
        self,
        *,
        actor: DemandActorContext,
        command: Any,
        snapshot: Mapping[str, Mapping[str, Any]],
        now: datetime,
    ) -> dict[str, Any]:
        if self.operation not in {
            "SUBMIT_DEMAND",
            "VERIFY_DEMAND",
            "REQUEST_MATCHING",
        }:
            return {}
        root = snapshot.get("demands", {}).get(command.demand_id)
        if not isinstance(root, Demand):
            _app_reject("RESOURCE_NOT_FOUND")
        version = snapshot.get("demand_versions", {}).get(root.current_version_id)
        if not isinstance(version, DemandVersion):
            _app_reject("SERVICE_UNAVAILABLE")
        requirement = self._rule_catalog.current_requirement(
            organization_id=root.organization_id,
            demand_id=root.demand_id,
            operation=self.operation,
        )
        if requirement.taxonomy_bundle_id != version.taxonomy_bundle_id:
            _app_reject("TAXONOMY_BUNDLE_CHANGED")
        result: dict[str, Any] = {
            "root_version": root.aggregate_version,
            "version_id": version.demand_version_id,
            "content_sha256": version.content_sha256,
            "requirement": requirement,
        }
        if self.operation == "SUBMIT_DEMAND":
            policy = self._content_policy.evaluate(
                demand_id=root.demand_id,
                demand_version_id=version.demand_version_id,
                content_sha256=version.content_sha256,
                content=version.content,
                policy_version=self._content_policy_version,
            )
            if policy.decision is DemandContentPolicyDecision.BLOCK:
                _app_reject("DEMAND_VALIDATION_FAILED")
            if (
                policy.demand_id != root.demand_id
                or policy.demand_version_id != version.demand_version_id
                or policy.content_sha256 != version.content_sha256
                or policy.policy_version != self._content_policy_version
                or policy.valid_until <= now
            ):
                _app_reject("SERVICE_UNAVAILABLE")
            result["content_policy"] = policy
        action = {
            "SUBMIT_DEMAND": "SUBMIT_DEMAND",
            "VERIFY_DEMAND": "VERIFY_DEMAND",
            "REQUEST_MATCHING": "REQUEST_MATCHING",
        }[self.operation]
        hold = self._safety_hold.evaluate(
            actor_id=actor.actor_id,
            organization_id=root.organization_id,
            demand_id=root.demand_id,
            prospective_aggregate_version=root.aggregate_version + 1,
            demand_version_id=version.demand_version_id,
            content_sha256=version.content_sha256,
            action=action,
            policy_version=self._safety_hold_policy_version,
        )
        if hold.decision is DemandHoldDecision.BLOCK:
            _app_reject("SAFETY_HOLD_BLOCKED")
        if (
            hold.actor_id != actor.actor_id
            or hold.organization_id != root.organization_id
            or hold.demand_id != root.demand_id
            or hold.prospective_aggregate_version != root.aggregate_version + 1
            or hold.demand_version_id != version.demand_version_id
            or hold.content_sha256 != version.content_sha256
            or hold.action != action
            or hold.policy_version != self._safety_hold_policy_version
            or hold.valid_until <= now
        ):
            _app_reject("SERVICE_UNAVAILABLE")
        result["hold"] = hold
        return result

    def _receipt_context(
        self,
        *,
        actor: DemandActorContext,
        command: Any,
    ) -> Optional[dict[str, Any]]:
        raw_key = getattr(command, "idempotency_key", None)
        if not isinstance(raw_key, str):
            return None
        key_id = self._receipt_keyring.idempotency_key_digest_key_id
        return {
            "principal_kind": actor.actor_kind.value,
            "principal_id": actor.actor_id,
            "organization_id": actor.organization_id,
            "command_name": command.__class__.__name__.removesuffix("Command"),
            "command_version": 1,
            "key_digest_key_id": key_id,
            "key_digest": self._receipt_keyring.keyed_digest(
                key_id, raw_key.encode("utf-8")
            ),
            "payload_hash_key_id": self._receipt_keyring.payload_hash_key_id,
            "payload_hash": demand_command_payload_hash(
                actor=actor,
                command=command,
                receipt_keyring=self._receipt_keyring,
            ),
        }

    @staticmethod
    def _find_receipt(
        snapshot: Mapping[str, Mapping[str, Any]],
        receipt: Optional[dict[str, Any]],
    ) -> Optional[Mapping[str, Any]]:
        if receipt is None:
            return None
        identity = (
            "principal_kind",
            "principal_id",
            "organization_id",
            "command_name",
            "command_version",
            "key_digest_key_id",
            "key_digest",
        )
        for persisted in snapshot.get("receipts", {}).values():
            if isinstance(persisted, Mapping) and all(
                persisted.get(field) == receipt[field] for field in identity
            ):
                return persisted
        return None

    def _resolve_existing_receipt(
        self,
        *,
        snapshot: Mapping[str, Mapping[str, Any]],
        receipt: dict[str, Any],
        persisted: Mapping[str, Any],
        now: datetime,
    ) -> DemandCommandResult:
        if persisted.get("payload_hash") != receipt["payload_hash"]:
            _app_reject("IDEMPOTENCY_KEY_REUSED")
        if persisted.get("status") != "COMPLETED":
            _app_reject("SERVICE_UNAVAILABLE")
        safe = persisted.get("safe_response")
        if not isinstance(safe, Mapping):
            _app_reject("SERVICE_UNAVAILABLE")
        expected_safe_keys = {
            "demand_id",
            "organization_id",
            "demand_version_id",
            "status",
            "aggregate_version",
            "etag",
            "replayed",
        }
        if set(safe) != expected_safe_keys:
            _app_reject("SERVICE_UNAVAILABLE")
        root = snapshot.get("demands", {}).get(persisted.get("target_id"))
        if (
            not isinstance(root, Demand)
            or persisted.get("target_version") != root.aggregate_version
            or safe.get("demand_id") != root.demand_id
            or safe.get("organization_id") != root.organization_id
            or safe.get("demand_version_id") != root.current_version_id
            or safe.get("status") != root.status.value
            or safe.get("aggregate_version") != root.aggregate_version
            or safe.get("etag") != f'"v{root.aggregate_version}"'
            or safe.get("replayed") is not False
        ):
            _app_reject("SERVICE_UNAVAILABLE")
        self._safe_response_validator.validate(
            safe,
            "DemandCommandResponse",
        )
        return self._result_from_snapshot(
            snapshot=snapshot,
            demand_id=str(persisted.get("target_id")),
            event_types=tuple(persisted.get("event_types", ())),
            replayed=True,
            completed_at=now,
        )

    def _transaction(
        self,
        *,
        actor: DemandActorContext,
        command: Any,
        authority: Any,
        receipt: Optional[dict[str, Any]],
        outside: Mapping[str, Any],
        now: datetime,
    ) -> DemandCommandResult:
        target_id = getattr(command, "demand_id", None)
        if isinstance(command, CreateDemandCommand):
            target_id = self._id_source.new_id("demand")
        try:
            with self._uow_factory.begin() as uow:
                self._lock(uow, actor=actor, command=command, authority=authority)
                result = self._apply(
                    uow=uow,
                    actor=actor,
                    command=command,
                    target_id=target_id,
                    receipt=receipt,
                    outside=outside,
                    now=now,
                )
                uow.commit()
                return result
        except DemandCommitOutcomeUnknownError as error:
            recovered = self._recover_unknown_commit(
                target_id=target_id,
                receipt=receipt,
                now=now,
            )
            if recovered is None:
                raise DemandApplicationError("SERVICE_UNAVAILABLE") from error
            return recovered

    def _lock(self, uow: Any, *, actor: DemandActorContext, command: Any, authority: Any) -> None:
        uow.lock("iam_family", (actor.actor_id,))
        if actor.session_id is not None:
            uow.lock("iam_session", (actor.session_id,))
        uow.lock("iam_user", (actor.actor_id,))
        uow.lock("organization", (actor.organization_id,))
        if hasattr(authority, "membership_id"):
            uow.lock("membership", (authority.membership_id,))
            uow.lock("membership_role_grant", (authority.membership_role_grant_id,))
        if hasattr(authority, "assignment_id"):
            uow.lock("review_assignment", (authority.assignment_id,))
        demand_id = getattr(command, "demand_id", None)
        if isinstance(demand_id, str):
            uow.lock("demand", (demand_id,))

    def _apply(
        self,
        *,
        uow: Any,
        actor: DemandActorContext,
        command: Any,
        target_id: str,
        receipt: Optional[dict[str, Any]],
        outside: Mapping[str, Any],
        now: datetime,
    ) -> DemandCommandResult:
        if receipt is not None:
            existing_receipts = {
                str(index): value
                for index, value in enumerate(uow.values("receipts"))
            }
            existing = self._find_receipt(
                {"receipts": existing_receipts}, receipt
            )
            if existing is not None:
                snapshot = self._uow_factory.store.snapshot()
                return self._resolve_existing_receipt(
                    snapshot=snapshot,
                    receipt=receipt,
                    persisted=existing,
                    now=now,
                )
            claim = {**receipt, "status": "IN_PROGRESS", "target_id": target_id}
            uow.put(
                "receipts",
                receipt["key_digest"],
                claim,
                checkpoint="receipt.claim",
            )

        root: Demand
        versions: tuple[DemandVersion, ...] = ()
        submissions: tuple[DemandSubmission, ...] = ()
        reviews: tuple[DemandReview, ...] = ()
        markers: tuple[DemandFundingMarker, ...] = ()
        requests: tuple[MatchingRequest, ...] = ()
        events: tuple[str, ...]

        if isinstance(command, CreateDemandCommand):
            client_digest = self._receipt_keyring.keyed_digest(
                self._receipt_keyring.client_reference_digest_key_id,
                command.raw_client_reference.encode("utf-8"),
            )
            if any(
                isinstance(item, Demand)
                and item.organization_id == actor.organization_id
                and item.client_reference_digest == client_digest
                for item in uow.values("demands")
            ):
                _app_reject("DEMAND_ALREADY_EXISTS")
            version_id = self._id_source.new_id("demand_version")
            root, version = Demand.create(
                demand_id=target_id,
                demand_version_id=version_id,
                organization_id=actor.organization_id,
                created_by_user_id=actor.actor_id,
                taxonomy_bundle_id=command.taxonomy_bundle_id,
                content=command.content,
                client_reference_digest_key_id=self._receipt_keyring.client_reference_digest_key_id,
                client_reference_digest=client_digest,
                expires_at=now.replace(year=now.year + 1),
                now=now,
            )
            versions = (version,)
            uow.put("demand_versions", version.demand_version_id, version, checkpoint="demand_version.insert")
            uow.put("demands", root.demand_id, root, checkpoint="demand_root.insert_or_update")
            events = ("DemandCreated", "DemandVersionCreated")
        else:
            root = uow.get("demands", target_id)
            if not isinstance(root, Demand) or root.organization_id != actor.organization_id:
                _app_reject("RESOURCE_NOT_FOUND")
            if root.aggregate_version != command.expected_version:
                _app_reject("PRECONDITION_FAILED")
            current = uow.get("demand_versions", root.current_version_id)
            if not isinstance(current, DemandVersion):
                _app_reject("SERVICE_UNAVAILABLE")
            self._validate_outside(root=root, version=current, outside=outside)
            if isinstance(command, CreateDemandVersionCommand):
                root, version = root.create_version(
                    demand_version_id=self._id_source.new_id("demand_version"),
                    based_on_demand_version_id=command.based_on_demand_version_id,
                    taxonomy_bundle_id=command.taxonomy_bundle_id,
                    content=command.content,
                    actor_user_id=actor.actor_id,
                    existing_versions=tuple(uow.values("demand_versions")),
                    now=now,
                )
                versions = (version,)
                uow.put("demand_versions", version.demand_version_id, version, checkpoint="demand_version.insert")
                uow.put("demands", root.demand_id, root, checkpoint="demand_root.insert_or_update")
                events = ("DemandVersionCreated",)
            elif isinstance(command, SubmitDemandCommand):
                policy = outside.get("content_policy")
                if policy is None:
                    _app_reject("SERVICE_UNAVAILABLE")
                root, submitted = root.submit(
                    submission_id=self._id_source.new_id("submission"),
                    actor_user_id=actor.actor_id,
                    current_version=current,
                    prior_submissions=tuple(uow.values("submissions")),
                    content_policy_version=policy.policy_version,
                    content_policy_result_sha256=policy.result_sha256,
                    now=now,
                )
                submissions = (submitted,)
                uow.put("submissions", submitted.submission_id, submitted, checkpoint="submission.insert")
                uow.put("demands", root.demand_id, root, checkpoint="demand_root.insert_or_update")
                events = ("DemandSubmitted",)
            elif isinstance(command, (RequestDemandChangesCommand, VerifyDemandCommand)):
                assignment = uow.get("review_assignments", command.assignment_id)
                submitted = next(
                    (
                        item
                        for item in uow.values("submissions")
                        if isinstance(item, DemandSubmission)
                        and item.demand_version_id == current.demand_version_id
                    ),
                    None,
                )
                if not isinstance(assignment, DemandReviewAssignment) or not isinstance(submitted, DemandSubmission):
                    _app_reject("RESOURCE_NOT_FOUND")
                review_id = self._id_source.new_id("review")
                if isinstance(command, RequestDemandChangesCommand):
                    root, reviewed = root.request_changes(
                        review_id=review_id,
                        assignment_id=command.assignment_id,
                        current_version=current,
                        submission=submitted,
                        assignment=assignment,
                        reviewer_user_id=actor.actor_id,
                        reason_codes=command.reason_codes,
                        required_field_codes=command.required_field_codes,
                        now=now,
                    )
                    events = ("DemandChangesRequested",)
                else:
                    if not all(
                        (
                            command.identity_subject_verified,
                            command.payment_subject_verified,
                            command.decision_authority_verified,
                            command.budget_health_verified,
                        )
                    ):
                        _app_reject("DEMAND_VALIDATION_FAILED")
                    root, reviewed = root.verify(
                        review_id=review_id,
                        assignment_id=command.assignment_id,
                        current_version=current,
                        submission=submitted,
                        assignment=assignment,
                        reviewer_user_id=actor.actor_id,
                        budget_health_code=command.budget_health_code,
                        risk_code=command.risk_code,
                        evidence_summary_sha256=command.evidence_summary_sha256,
                        now=now,
                    )
                    events = ("DemandVerified",)
                reviews = (reviewed,)
                completed_assignment = replace(
                    assignment,
                    status=ReviewAssignmentStatus.COMPLETED,
                    aggregate_version=assignment.aggregate_version + 1,
                )
                uow.put("reviews", reviewed.review_id, reviewed, checkpoint="review.insert")
                uow.put("demands", root.demand_id, root, checkpoint="demand_root.insert_or_update")
                uow.put("review_assignments", assignment.assignment_id, completed_assignment, checkpoint="review_assignment.update")
            elif isinstance(command, ApplyFundingSecuredCommand):
                event = command.source_event
                existing_inbox = uow.get("source_inbox", event.event_id)
                if isinstance(existing_inbox, Mapping):
                    if existing_inbox.get("status") == "COMPLETED":
                        return self._result_from_snapshot(
                            snapshot=self._uow_factory.store.snapshot(),
                            demand_id=root.demand_id,
                            event_types=("DemandFunded",),
                            replayed=True,
                            completed_at=now,
                        )
                    _app_reject("SERVICE_UNAVAILABLE")
                uow.put("source_inbox", event.event_id, {"status": "IN_PROGRESS", "event_id": event.event_id}, checkpoint="source_inbox.claim")
                root, marker = root.apply_funding_secured(
                    funding_marker_id=self._id_source.new_id("funding_marker"),
                    demand_version_id=event.demand_version_id,
                    funding_id=event.funding_id,
                    amount_currency_sha256=event.amount_currency_sha256,
                    verification_reference_sha256=event.verification_reference_sha256,
                    source_event_id=event.event_id,
                    source_aggregate_version=event.source_aggregate_version,
                    now=now,
                )
                markers = (marker,)
                uow.put("funding_markers", marker.funding_marker_id, marker, checkpoint="funding_marker.insert")
                uow.put("demands", root.demand_id, root, checkpoint="demand_root.insert_or_update")
                events = ("DemandFunded",)
            elif isinstance(command, RequestMatchingCommand):
                marker = next(
                    (
                        item
                        for item in uow.values("funding_markers")
                        if isinstance(item, DemandFundingMarker)
                        and item.funding_id == root.current_funding_id
                    ),
                    None,
                )
                if not isinstance(marker, DemandFundingMarker):
                    _app_reject("FUNDING_REQUIRED")
                requirement = outside.get("requirement")
                if requirement is None:
                    _app_reject("SERVICE_UNAVAILABLE")
                root, request = root.request_matching(
                    matching_request_id=self._id_source.new_id("matching_request"),
                    funding_marker=marker,
                    taxonomy_bundle_id=requirement.taxonomy_bundle_id,
                    budget_rule_bundle_id=requirement.budget_rule_bundle_id,
                    matching_rule_bundle_id=requirement.matching_rule_bundle_id,
                    reason_code_bundle_id=requirement.reason_code_bundle_id,
                    composite_rule_requirement_id=requirement.composite_rule_requirement_id,
                    now=now,
                )
                requests = (request,)
                uow.put("matching_requests", request.matching_request_id, request, checkpoint="matching_request.insert")
                uow.put("demands", root.demand_id, root, checkpoint="demand_root.insert_or_update")
                events = ("MatchingRequested",)
            elif isinstance(command, CancelDemandCommand):
                root = root.cancel(reason_code=command.reason_code, now=now)
                uow.put("demands", root.demand_id, root, checkpoint="demand_root.insert_or_update")
                events = ("DemandCancelled",)
            elif isinstance(command, ExpireDemandCommand):
                scheduler_key = f"{root.demand_id}:{command.deadline.isoformat()}:EXPIRE"
                existing = uow.get("source_inbox", scheduler_key)
                if isinstance(existing, Mapping) and existing.get("status") == "COMPLETED":
                    return self._result_from_snapshot(
                        snapshot=self._uow_factory.store.snapshot(),
                        demand_id=root.demand_id,
                        event_types=("DemandExpired",),
                        replayed=True,
                        completed_at=now,
                    )
                root = root.expire(deadline=command.deadline, now=now)
                uow.put("demands", root.demand_id, root, checkpoint="demand_root.insert_or_update")
                events = ("DemandExpired",)
            else:
                _app_reject("INVALID_REQUEST")

        audit_id = self._id_source.new_id("audit_event")
        audit = {
            "audit_id": audit_id,
            "action": self.operation,
            "actor_id": actor.actor_id,
            "organization_id": root.organization_id,
            "target_id": root.demand_id,
            "target_version": root.aggregate_version,
            "result": "SUCCEEDED",
            "correlation_id": actor.correlation_id,
            "occurred_at": _utc_text(now),
        }
        uow.put("audits", audit_id, audit, checkpoint="audit.insert")
        for event_type in events:
            event_id = self._id_source.new_id("outbox_event")
            envelope = _event_envelope(
                event_id=event_id,
                event_type=event_type,
                actor=actor,
                demand=root,
                versions=versions,
                submissions=submissions,
                reviews=reviews,
                markers=markers,
                requests=requests,
                now=now,
            )
            self._event_validator.validate(envelope, "demand-v1")
            uow.put("outbox", event_id, envelope, checkpoint="outbox.insert")

        if isinstance(command, ApplyFundingSecuredCommand):
            uow.put(
                "source_inbox",
                command.source_event.event_id,
                {
                    "status": "COMPLETED",
                    "event_id": command.source_event.event_id,
                    "target_id": root.demand_id,
                    "target_version": root.aggregate_version,
                },
                checkpoint="source_inbox.complete",
            )

        if receipt is not None:
            safe_response = _safe_response(root, versions=versions)
            self._safe_response_validator.validate(
                safe_response,
                "DemandCommandResponse",
            )
            complete = {
                **receipt,
                "status": "COMPLETED",
                "target_id": root.demand_id,
                "target_version": root.aggregate_version,
                "event_types": events,
                "safe_response": safe_response,
            }
            uow.put(
                "receipts",
                receipt["key_digest"],
                complete,
                checkpoint="receipt.complete",
            )

        return DemandCommandResult(
            demand=root,
            versions=versions,
            submissions=submissions,
            reviews=reviews,
            funding_markers=markers,
            matching_requests=requests,
            replayed=False,
            event_types=events,
            completed_at=now,
        )

    @staticmethod
    def _validate_outside(
        *,
        root: Demand,
        version: DemandVersion,
        outside: Mapping[str, Any],
    ) -> None:
        if outside and (
            outside.get("root_version") != root.aggregate_version
            or outside.get("version_id") != version.demand_version_id
            or outside.get("content_sha256") != version.content_sha256
        ):
            _app_reject("SERVICE_UNAVAILABLE")

    def _recover_unknown_commit(
        self,
        *,
        target_id: str,
        receipt: Optional[dict[str, Any]],
        now: datetime,
    ) -> Optional[DemandCommandResult]:
        snapshot = self._uow_factory.store.snapshot()
        if receipt is None:
            return None
        persisted = self._find_receipt(snapshot, receipt)
        if persisted is None or persisted.get("status") != "COMPLETED":
            return None
        try:
            return self._resolve_existing_receipt(
                snapshot=snapshot,
                receipt=receipt,
                persisted=persisted,
                now=now,
            )
        except DemandApplicationError:
            return None

    @staticmethod
    def _result_from_snapshot(
        *,
        snapshot: Mapping[str, Mapping[str, Any]],
        demand_id: str,
        event_types: tuple[str, ...],
        replayed: bool,
        completed_at: datetime,
    ) -> DemandCommandResult:
        root = snapshot.get("demands", {}).get(demand_id)
        if not isinstance(root, Demand):
            _app_reject("SERVICE_UNAVAILABLE")
        def related(collection: str, expected: type[Any]) -> tuple[Any, ...]:
            return tuple(
                item
                for item in snapshot.get(collection, {}).values()
                if isinstance(item, expected) and item.demand_id == demand_id
            )
        return DemandCommandResult(
            demand=root,
            versions=related("demand_versions", DemandVersion),
            submissions=related("submissions", DemandSubmission),
            reviews=related("reviews", DemandReview),
            funding_markers=related("funding_markers", DemandFundingMarker),
            matching_requests=related("matching_requests", MatchingRequest),
            replayed=replayed,
            event_types=event_types,
            completed_at=completed_at,
        )


class CreateDemandHandler(_DemandHandler):
    operation = "CREATE_DEMAND"

    def handle(self, *, actor: DemandActorContext, command: CreateDemandCommand) -> DemandCommandResult:
        return self._execute(actor=actor, command=command)


class CreateDemandVersionHandler(_DemandHandler):
    operation = "CREATE_DEMAND_VERSION"

    def handle(self, *, actor: DemandActorContext, command: CreateDemandVersionCommand) -> DemandCommandResult:
        return self._execute(actor=actor, command=command)


class SubmitDemandHandler(_DemandHandler):
    operation = "SUBMIT_DEMAND"

    def handle(self, *, actor: DemandActorContext, command: SubmitDemandCommand) -> DemandCommandResult:
        return self._execute(actor=actor, command=command)


class RequestDemandChangesHandler(_DemandHandler):
    operation = "REQUEST_DEMAND_CHANGES"

    def handle(self, *, actor: DemandActorContext, command: RequestDemandChangesCommand) -> DemandCommandResult:
        return self._execute(actor=actor, command=command)


class VerifyDemandHandler(_DemandHandler):
    operation = "VERIFY_DEMAND"

    def handle(self, *, actor: DemandActorContext, command: VerifyDemandCommand) -> DemandCommandResult:
        return self._execute(actor=actor, command=command)


class ApplyFundingSecuredHandler(_DemandHandler):
    operation = "APPLY_FUNDING_SECURED"

    def handle(self, *, actor: DemandActorContext, command: ApplyFundingSecuredCommand) -> DemandCommandResult:
        return self._execute(actor=actor, command=command)


class RequestMatchingHandler(_DemandHandler):
    operation = "REQUEST_MATCHING"

    def handle(self, *, actor: DemandActorContext, command: RequestMatchingCommand) -> DemandCommandResult:
        return self._execute(actor=actor, command=command)


class CancelDemandHandler(_DemandHandler):
    operation = "CANCEL_DEMAND"

    def handle(self, *, actor: DemandActorContext, command: CancelDemandCommand) -> DemandCommandResult:
        return self._execute(actor=actor, command=command)


class ExpireDemandHandler(_DemandHandler):
    operation = "EXPIRE_DEMAND"

    def handle(self, *, actor: DemandActorContext, command: ExpireDemandCommand) -> DemandCommandResult:
        return self._execute(actor=actor, command=command)


def _canonical_command_payload(
    *,
    actor: DemandActorContext,
    command: Any,
    receipt_keyring: Any,
) -> bytes:
    body: dict[str, Any] = {}
    for descriptor in fields(command):
        if descriptor.name == "idempotency_key":
            continue
        value = getattr(command, descriptor.name)
        if descriptor.name == "raw_client_reference":
            value = {
                "digest_key_id": receipt_keyring.client_reference_digest_key_id,
                "keyed_digest": receipt_keyring.keyed_digest(
                    receipt_keyring.client_reference_digest_key_id,
                    value.encode("utf-8"),
                ),
            }
        body[descriptor.name] = _json_value(value)
    surface = {
        "actor_id": actor.actor_id,
        "actor_kind": actor.actor_kind.value,
        "command_name": command.__class__.__name__.removesuffix("Command"),
        "command_version": 1,
        "organization_id": actor.organization_id,
        "body": body,
    }
    return json.dumps(
        surface,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _json_value(value: Any) -> Any:
    if isinstance(value, DemandContent):
        return {key: _json_value(child) for key, child in value.members}
    if isinstance(value, Mapping):
        return {str(key): _json_value(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_json_value(child) for child in value]
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return _utc_text(value)
    if is_dataclass(value):
        return {
            descriptor.name: _json_value(getattr(value, descriptor.name))
            for descriptor in fields(value)
        }
    if value is None or isinstance(value, (bool, int, str)):
        return value
    raise TypeError(f"unsupported Demand command value: {type(value).__name__}")


def _safe_response(root: Demand, *, versions: tuple[DemandVersion, ...]) -> dict[str, Any]:
    version_id = versions[-1].demand_version_id if versions else root.current_version_id
    return {
        "demand_id": root.demand_id,
        "organization_id": root.organization_id,
        "demand_version_id": version_id,
        "status": root.status.value,
        "aggregate_version": root.aggregate_version,
        "etag": f'"v{root.aggregate_version}"',
        "replayed": False,
    }


def _event_envelope(
    *,
    event_id: str,
    event_type: str,
    actor: DemandActorContext,
    demand: Demand,
    versions: tuple[DemandVersion, ...],
    submissions: tuple[DemandSubmission, ...],
    reviews: tuple[DemandReview, ...],
    markers: tuple[DemandFundingMarker, ...],
    requests: tuple[MatchingRequest, ...],
    now: datetime,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "demand_id": demand.demand_id,
        "status": demand.status.value,
    }
    if event_type == "DemandCreated":
        payload = {
            "demand_id": demand.demand_id,
            "organization_id": demand.organization_id,
            "status": demand.status.value,
            "demand_version_id": versions[-1].demand_version_id,
        }
    elif event_type == "DemandVersionCreated":
        version = versions[-1]
        payload = {
            "demand_id": demand.demand_id,
            "demand_version_id": version.demand_version_id,
            "version_no": version.version_no,
            "content_sha256": version.content_sha256,
            "taxonomy_bundle_id": version.taxonomy_bundle_id,
        }
    elif event_type == "DemandSubmitted":
        submitted = submissions[-1]
        payload = {
            "demand_id": demand.demand_id,
            "demand_version_id": submitted.demand_version_id,
            "submission_id": submitted.submission_id,
            "status": demand.status.value,
        }
    elif event_type in {"DemandChangesRequested", "DemandVerified"}:
        reviewed = reviews[-1]
        payload = {
            "demand_id": demand.demand_id,
            "demand_version_id": reviewed.demand_version_id,
            "review_id": reviewed.review_id,
            "status": demand.status.value,
        }
        if event_type == "DemandChangesRequested":
            payload.update(
                reason_codes=list(reviewed.reason_codes),
                required_field_codes=list(reviewed.required_field_codes),
            )
        else:
            payload["budget_health_code"] = reviewed.budget_health_code
    elif event_type == "DemandFunded":
        marker = markers[-1]
        payload.update(
            demand_version_id=marker.demand_version_id,
            funding_id=marker.funding_id,
        )
    elif event_type == "MatchingRequested":
        request = requests[-1]
        payload.update(
            demand_version_id=request.demand_version_id,
            funding_id=request.funding_id,
            matching_request_id=request.matching_request_id,
            composite_rule_requirement_id=request.composite_rule_requirement_id,
        )
    elif event_type == "DemandCancelled":
        payload["reason_code"] = demand.reason_code.value if demand.reason_code else None
    elif event_type == "DemandExpired":
        payload["reason_code"] = "DEADLINE_REACHED"
    return {
        "event_id": event_id,
        "event_type": event_type,
        "schema_version": 1,
        "occurred_at": _utc_text(now),
        "aggregate_type": "Demand",
        "aggregate_id": demand.demand_id,
        "aggregate_version": demand.aggregate_version,
        "actor_kind": actor.actor_kind.value,
        "actor_id": actor.actor_id,
        "original_actor_id": actor.original_actor_id,
        "correlation_id": actor.correlation_id,
        "causation_id": actor.causation_id,
        "trace_id": actor.trace_id,
        "organization_id": demand.organization_id,
        "payload": payload,
    }


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _app_reject(code: str) -> None:
    raise DemandApplicationError(code)
