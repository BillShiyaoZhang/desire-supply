"""Default-deny Appeal command orchestration.

Exact receipt replay is resolved before source, conflict, sealed-text, policy,
or identifier dependencies are used.  Restricted text contributes only a
one-way digest to canonical request material and is never written to receipts,
audit records, events, results, or exceptions.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import json
import re
from typing import Any, Mapping, Optional, Tuple
from uuid import UUID

from ..domain import (
    Appeal,
    AppealApplicationDraft,
    AppealApplicationVersion,
    AppealAssignmentReleaseReason,
    AppealAssignmentRelease,
    AppealDecisionCode,
    AppealDecisionVersion,
    AppealDomainError,
    AppealGround,
    AppealGroundAssessment,
    AppealGroundAssessmentCode,
    AppealReviewAssignment,
    AppealReviewDraft,
    AppealStatus,
    RequestedAppealOutcome,
    TrustCaseOutcomeSource,
)
from ..ports import (
    AppealApplicantAuthority,
    AppealApplicantSource,
    AppealAuthorityUnavailableError,
    AppealCommitOutcomeUnknownError,
    AppealConflictUnavailableError,
    AppealDecisionPolicy,
    AppealDecisionPolicyUnavailableError,
    AppealReviewerAuthority,
    AppealReviewerConflictCheck,
    AppealSealedText,
    AppealSealedTextUnavailableError,
    AppealSourceUnavailableError,
    AppealStorageUnavailableError,
)
from .appeal_commands import (
    AppealCommandResult,
    ClaimAppealCommand,
    DecideAppealCommand,
    OpenAppealCommand,
    ReleaseAppealAssignmentCommand,
    SaveAppealDraftCommand,
    SaveAppealReviewDraftCommand,
    SubmitAppealCommand,
)
from .commands import TrustActorContext


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SEALED_REFERENCE = re.compile(r"sealed://trust/[a-z0-9][a-z0-9/_-]{4,255}\Z")
_IDEMPOTENCY_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~-]{15,127}\Z")
_FINDING_CODES = frozenset(
    (
        "PROCEDURE_MATERIAL_ERROR",
        "NEW_EVIDENCE_MATERIAL",
        "RULE_APPLIED_CORRECTLY",
        "RULE_APPLICATION_ERROR",
        "APPEAL_NOT_SUBSTANTIATED",
    )
)
_REVIEW_REASON_CODES = frozenset(
    (
        "SOURCE_OUTCOME_SUPPORTED",
        "SOURCE_OUTCOME_UNSUPPORTED",
        "PROCEDURAL_REVIEW_COMPLETE",
        "NEW_EVIDENCE_REVIEWED",
        "REMAND_REQUIRED",
        "APPEAL_SCOPE_INVALID",
    )
)
_REMEDY_DELTA_CODES = frozenset(
    (
        "NO_CHANGE",
        "REMOVE_CORRECTIVE_MEASURE",
        "NARROW_CORRECTIVE_MEASURE",
        "REPLACE_CORRECTIVE_MEASURE",
        "RETURN_TO_TRUST_REVIEW",
    )
)

_OPERATIONS = {
    "open": "OPEN_APPEAL",
    "save_draft": "SAVE_APPEAL_DRAFT",
    "submit": "SUBMIT_APPEAL",
    "claim": "CLAIM_APPEAL",
    "release_assignment": "RELEASE_APPEAL_ASSIGNMENT",
    "save_review": "SAVE_APPEAL_REVIEW_DRAFT",
    "decide": "DECIDE_APPEAL",
}
_CANONICAL_PATHS = {
    "open": "/v1/app/appeals",
    "save_draft": "/v1/app/appeals/{appeal_id}/draft",
    "submit": "/v1/app/appeals/{appeal_id}/submit",
    "claim": "/v1/app/appeal-review/queue/{appeal_id}/claim",
    "release_assignment": (
        "/v1/app/appeal-review/appeals/{appeal_id}/assignment/release"
    ),
    "save_review": "/v1/app/appeal-review/appeals/{appeal_id}/review-draft",
    "decide": "/v1/app/appeal-review/appeals/{appeal_id}/decide",
}
_METHODS = {
    "open": "POST",
    "save_draft": "PUT",
    "submit": "POST",
    "claim": "POST",
    "release_assignment": "POST",
    "save_review": "PUT",
    "decide": "POST",
}
_EVENTS = {
    "open": "AppealOpened",
    "save_draft": "AppealApplicationDraftSaved",
    "submit": "AppealSubmitted",
    "claim": "AppealReviewClaimed",
    "release_assignment": "AppealReviewAssignmentReleased",
    "save_review": "AppealReviewDraftSaved",
    "decide": "AppealDecisionPublished",
}
_COMMAND_TYPES = {
    "open": OpenAppealCommand,
    "save_draft": SaveAppealDraftCommand,
    "submit": SubmitAppealCommand,
    "claim": ClaimAppealCommand,
    "release_assignment": ReleaseAppealAssignmentCommand,
    "save_review": SaveAppealReviewDraftCommand,
    "decide": DecideAppealCommand,
}
_APPLICANT_OPERATIONS = frozenset(("open", "save_draft", "submit"))


class AppealApplicationError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class _Prepared:
    applicant_source: Optional[AppealApplicantSource] = None
    conflict: Optional[AppealReviewerConflictCheck] = None
    sealed_text: Optional[AppealSealedText] = None
    decision_policy: Optional[AppealDecisionPolicy] = None


@dataclass(frozen=True)
class _Mutation:
    appeal: Appeal
    application_draft: Optional[AppealApplicationDraft] = None
    application_version: Optional[AppealApplicationVersion] = None
    assignment: Optional[AppealReviewAssignment] = None
    assignment_release: Optional[AppealAssignmentRelease] = None
    review_draft: Optional[AppealReviewDraft] = None
    decision: Optional[AppealDecisionVersion] = None


class _AppealHandler:
    operation: str

    def __init__(
        self,
        *,
        authority: Any,
        sources: Any,
        conflicts: Any,
        sealed_text: Any,
        decision_policy: Any,
        uow_factory: Any,
        clock: Any,
        id_source: Any,
        receipt_keyring: Any,
        assignment_ttl_minutes: int = 240,
    ) -> None:
        if (
            type(assignment_ttl_minutes) is not int
            or not 15 <= assignment_ttl_minutes <= 1_440
        ):
            raise ValueError("APPEAL_HANDLER_CONFIGURATION_INVALID")
        self._authority = authority
        self._sources = sources
        self._conflicts = conflicts
        self._sealed_text = sealed_text
        self._decision_policy = decision_policy
        self._uow_factory = uow_factory
        self._clock = clock
        self._id_source = id_source
        self._receipt_keyring = receipt_keyring
        self._assignment_ttl_minutes = assignment_ttl_minutes

    def handle(
        self,
        *,
        actor: TrustActorContext,
        command: Any,
    ) -> AppealCommandResult:
        if not isinstance(actor, TrustActorContext) or not isinstance(
            command, _COMMAND_TYPES[self.operation]
        ):
            _fail("INVALID_REQUEST")
        _validate_actor(actor, applicant=self.operation in _APPLICANT_OPERATIONS)
        _validate_command(self.operation, command)
        now = self._now()
        granted = self._authorize(actor, now)
        identities = self._receipt_identities(
            actor_user_id=actor.actor_user_id,
            idempotency_key=command.idempotency_key,
        )
        payload_hashes = self._payload_hashes(actor=actor, command=command)
        snapshot = self._snapshot()
        prior = _find_receipt(
            snapshot.get("appeal_command_receipts", {}), identities
        )
        if prior is not None:
            return _replay(prior, payload_hashes)

        appeal = self._snapshot_appeal(snapshot, actor=actor, command=command)
        self._precheck_server_facts(
            appeal=appeal,
            actor=actor,
            command=command,
            granted=granted,
            now=now,
        )
        prepared = self._prepare(
            actor=actor,
            command=command,
            granted=granted,
            appeal=appeal,
            identity=identities[0],
            now=now,
        )
        generated = self._generated_ids()
        receipt_id = self._new_id("appeal_command_receipt")
        audit_id = self._new_id("appeal_audit_event")
        outbox_id = self._new_id("appeal_outbox_event")

        try:
            with self._uow_factory.begin() as uow:
                self._lock(uow, actor=actor, command=command)
                raced = _find_receipt(
                    {
                        str(index): value
                        for index, value in enumerate(
                            uow.values("appeal_command_receipts")
                        )
                    },
                    identities,
                )
                if raced is not None:
                    return _replay(raced, payload_hashes)
                locked = self._locked_appeal(
                    uow, actor=actor, command=command
                )
                mutation = self._apply(
                    actor=actor,
                    command=command,
                    appeal=locked,
                    granted=granted,
                    prepared=prepared,
                    generated=generated,
                    now=now,
                )
                event_type = _EVENTS[self.operation]
                safe = _safe_response(
                    mutation.appeal,
                    decision=mutation.decision,
                    event_type=event_type,
                    completed_at=now,
                )
                pending = {
                    "receipt_id": receipt_id,
                    **identities[0],
                    "canonicalization_version": "appeal-command-json-v1",
                    "payload_hash_key_id": self._payload_key_ids()[0],
                    "payload_hash": payload_hashes[self._payload_key_ids()[0]],
                    "target_appeal_id": mutation.appeal.appeal_id,
                    "status": "IN_PROGRESS",
                }
                # No business, audit, or event fact precedes receipt claim.
                uow.put(
                    "appeal_command_receipts",
                    receipt_id,
                    pending,
                    checkpoint="receipt.pending",
                )
                self._write_business(uow, mutation)
                uow.put(
                    "audit_events",
                    audit_id,
                    _audit(
                        audit_id=audit_id,
                        actor=actor,
                        appeal=mutation.appeal,
                        event_type=event_type,
                        occurred_at=now,
                        receipt_id=receipt_id,
                    ),
                    checkpoint="audit." + self.operation,
                )
                uow.put(
                    "outbox_events",
                    outbox_id,
                    _event(
                        event_id=outbox_id,
                        actor=actor,
                        appeal=mutation.appeal,
                        event_type=event_type,
                        occurred_at=now,
                    ),
                    checkpoint="outbox." + self.operation,
                )
                uow.put(
                    "appeal_command_receipts",
                    receipt_id,
                    {
                        **pending,
                        "status": "COMPLETED",
                        "completed_at": _timestamp(now),
                        "safe_response": safe,
                    },
                    checkpoint="receipt.completed",
                )
                uow.commit()
                return _result(safe, replayed=False)
        except AppealCommitOutcomeUnknownError:
            recovered = self._recover(identities, payload_hashes)
            if recovered is not None:
                return recovered
            _fail("COMMAND_OUTCOME_UNKNOWN")
        except AppealApplicationError:
            raise
        except AppealDomainError as error:
            _fail(error.code)
        except AppealStorageUnavailableError:
            _fail("SERVICE_UNAVAILABLE")
        except Exception:
            _fail("SERVICE_UNAVAILABLE")
        raise AssertionError("unreachable")

    def _authorize(self, actor: TrustActorContext, now: datetime) -> Any:
        try:
            if self.operation in _APPLICANT_OPERATIONS:
                value = self._authority.authorize_applicant(
                    actor=actor,
                    operation=_OPERATIONS[self.operation],
                    organization_id=actor.organization_id,
                )
                return _validate_applicant_authority(value, actor)
            value = self._authority.authorize_reviewer(
                actor=actor,
                operation=_OPERATIONS[self.operation],
            )
            return _validate_reviewer_authority(value, actor, now)
        except AppealApplicationError:
            raise
        except AppealAuthorityUnavailableError:
            _fail("SERVICE_UNAVAILABLE")
        except Exception:
            _fail("SERVICE_UNAVAILABLE")

    def _snapshot(self) -> Mapping[str, Mapping[str, Any]]:
        try:
            value = self._uow_factory.store.snapshot()
        except Exception:
            _fail("SERVICE_UNAVAILABLE")
        if not isinstance(value, Mapping):
            _fail("SERVICE_UNAVAILABLE")
        return value

    def _snapshot_appeal(
        self,
        snapshot: Mapping[str, Mapping[str, Any]],
        *,
        actor: TrustActorContext,
        command: Any,
    ) -> Optional[Appeal]:
        if self.operation == "open":
            return None
        value = snapshot.get("appeals", {}).get(command.appeal_id)
        if not isinstance(value, Appeal):
            _fail("APPEAL_NOT_FOUND")
        if value.aggregate_version != command.expected_appeal_version:
            _fail("PRECONDITION_FAILED")
        if self.operation in _APPLICANT_OPERATIONS:
            if (
                value.applicant_user_id != actor.actor_user_id
                or value.source.organization_id != actor.organization_id
            ):
                _fail("APPEAL_NOT_FOUND")
        return value

    def _prepare(
        self,
        *,
        actor: TrustActorContext,
        command: Any,
        granted: Any,
        appeal: Optional[Appeal],
        identity: Mapping[str, Any],
        now: datetime,
    ) -> _Prepared:
        try:
            if self.operation == "open":
                source = self._sources.resolve_applicant_source(
                    applicant_authority=granted,
                    source_outcome_version_id=command.source_outcome_version_id,
                )
                return _Prepared(
                    applicant_source=_validate_applicant_source(
                        source, granted, command.source_outcome_version_id, now
                    )
                )
            if self.operation == "save_draft":
                sealed = self._sealed_text.seal(
                    appeal_id=command.appeal_id,
                    actor_user_id=actor.actor_user_id,
                    purpose="APPLICATION_STATEMENT",
                    raw_text=command.applicant_statement,
                    idempotency_key_digest=identity[
                        "idempotency_key_digest"
                    ],
                )
                return _Prepared(sealed_text=_validate_sealed(sealed, now))
            if self.operation == "claim":
                if appeal is None:
                    _fail("APPEAL_NOT_FOUND")
                conflict = self._conflicts.check_reviewer_conflict(
                    reviewer_authority=granted,
                    source=appeal.source,
                    appeal_id=appeal.appeal_id,
                    applicant_user_id=appeal.applicant_user_id,
                )
                return _Prepared(
                    conflict=_validate_conflict(
                        conflict,
                        reviewer=granted,
                        appeal=appeal,
                        now=now,
                    )
                )
            if self.operation == "save_review":
                sealed = self._sealed_text.seal(
                    appeal_id=command.appeal_id,
                    actor_user_id=actor.actor_user_id,
                    purpose="REVIEW_NOTE",
                    raw_text=command.reviewer_note,
                    idempotency_key_digest=identity[
                        "idempotency_key_digest"
                    ],
                )
                return _Prepared(sealed_text=_validate_sealed(sealed, now))
            if self.operation == "decide":
                if appeal is None:
                    _fail("APPEAL_NOT_FOUND")
                policy = self._decision_policy.resolve_decision_policy(
                    reviewer_authority=granted,
                    appeal=appeal,
                    decision_code=command.decision_code,
                    now=now,
                )
                return _Prepared(
                    decision_policy=_validate_policy(
                        policy,
                        appeal=appeal,
                        command=command,
                        now=now,
                    )
                )
            return _Prepared()
        except AppealApplicationError:
            raise
        except (
            AppealSourceUnavailableError,
            AppealConflictUnavailableError,
            AppealSealedTextUnavailableError,
            AppealDecisionPolicyUnavailableError,
        ):
            _fail("SERVICE_UNAVAILABLE")
        except Exception:
            _fail("SERVICE_UNAVAILABLE")

    def _precheck_server_facts(
        self,
        *,
        appeal: Optional[Appeal],
        actor: TrustActorContext,
        command: Any,
        granted: Any,
        now: datetime,
    ) -> None:
        """Reject stale assignment facts before any external side effect."""

        if self.operation in _APPLICANT_OPERATIONS or self.operation == "open":
            return
        if appeal is None or not isinstance(granted, AppealReviewerAuthority):
            _fail("APPEAL_NOT_FOUND")
        if self.operation == "claim":
            if appeal.status is not AppealStatus.SUBMITTED or appeal.assignment is not None:
                _fail("APPEAL_ALREADY_ASSIGNED")
            return
        assignment = appeal.assignment
        if appeal.status is not AppealStatus.IN_REVIEW or assignment is None:
            _fail("APPEAL_ASSIGNMENT_REQUIRED")
        if (
            self.operation == "release_assignment"
            and command.reason_code
            is AppealAssignmentReleaseReason.ASSIGNMENT_EXPIRED
        ):
            if now < assignment.expires_at:
                _fail("APPEAL_ASSIGNMENT_NOT_EXPIRED")
            return
        if (
            assignment.reviewer_user_id != actor.actor_user_id
            or assignment.duty_grant_id != granted.duty_grant_id
            or assignment.duty_grant_version != granted.duty_grant_version
            or now >= assignment.expires_at
        ):
            _fail("APPEAL_ASSIGNMENT_REQUIRED")
        if self.operation == "decide" and (
            appeal.latest_review_draft is None
            or appeal.current_review_draft_version
            != command.expected_review_draft_version
        ):
            _fail("APPEAL_DECISION_INVALID")

    def _generated_ids(self) -> Mapping[str, str]:
        if self.operation == "open":
            return {"appeal_id": self._new_id("appeal")}
        if self.operation == "claim":
            return {"assignment_id": self._new_id("appeal_review_assignment")}
        if self.operation == "decide":
            return {"decision_id": self._new_id("appeal_decision_version")}
        return {}

    def _lock(self, uow: Any, *, actor: TrustActorContext, command: Any) -> None:
        try:
            if self.operation == "open":
                uow.lock(
                    "appeal_source",
                    (actor.actor_user_id, command.source_outcome_version_id),
                )
            else:
                uow.lock("appeal", (command.appeal_id,))
        except Exception:
            _fail("SERVICE_UNAVAILABLE")

    def _locked_appeal(
        self, uow: Any, *, actor: TrustActorContext, command: Any
    ) -> Optional[Appeal]:
        if self.operation == "open":
            for value in uow.values("appeals"):
                if (
                    isinstance(value, Appeal)
                    and value.applicant_user_id == actor.actor_user_id
                    and value.source.outcome_version_id
                    == command.source_outcome_version_id
                ):
                    _fail("APPEAL_ALREADY_EXISTS")
            return None
        value = uow.get("appeals", command.appeal_id)
        if not isinstance(value, Appeal):
            _fail("APPEAL_NOT_FOUND")
        if value.aggregate_version != command.expected_appeal_version:
            _fail("PRECONDITION_FAILED")
        if self.operation in _APPLICANT_OPERATIONS and (
            value.applicant_user_id != actor.actor_user_id
            or value.source.organization_id != actor.organization_id
        ):
            _fail("APPEAL_NOT_FOUND")
        return value

    def _apply(
        self,
        *,
        actor: TrustActorContext,
        command: Any,
        appeal: Optional[Appeal],
        granted: Any,
        prepared: _Prepared,
        generated: Mapping[str, str],
        now: datetime,
    ) -> _Mutation:
        if self.operation == "open":
            resolution = prepared.applicant_source
            if resolution is None:
                _fail("SERVICE_UNAVAILABLE")
            opened = Appeal.open(
                appeal_id=generated["appeal_id"],
                source=resolution.source,
                applicant_user_id=actor.actor_user_id,
                applicant_is_party=resolution.applicant_is_party,
                now=now,
            )
            return _Mutation(appeal=opened)
        if appeal is None:
            _fail("APPEAL_NOT_FOUND")
        self._precheck_server_facts(
            appeal=appeal,
            actor=actor,
            command=command,
            granted=granted,
            now=now,
        )
        if self.operation == "save_draft":
            sealed = prepared.sealed_text
            if sealed is None:
                _fail("SERVICE_UNAVAILABLE")
            changed, draft = appeal.save_application_draft(
                applicant_user_id=actor.actor_user_id,
                grounds=command.grounds,
                requested_outcome=command.requested_outcome,
                sealed_statement_reference=sealed.sealed_reference,
                sealed_statement_sha256=sealed.sealed_sha256,
                new_evidence_reference_ids=command.new_evidence_reference_ids,
                now=now,
            )
            return _Mutation(appeal=changed, application_draft=draft)
        if self.operation == "submit":
            changed, application = appeal.submit(
                applicant_user_id=actor.actor_user_id,
                expected_draft_version=command.expected_draft_version,
                now=now,
            )
            return _Mutation(appeal=changed, application_version=application)
        if self.operation == "claim":
            conflict = prepared.conflict
            if conflict is None or not conflict.conflict_free:
                _fail("CONFLICT_OF_INTEREST")
            deadline = now + timedelta(minutes=self._assignment_ttl_minutes)
            deadline = min(deadline, conflict.valid_until)
            if granted.duty_expires_at is not None:
                deadline = min(deadline, granted.duty_expires_at)
            if deadline <= now:
                _fail("SESSION_EXPIRED")
            changed, assignment = appeal.claim(
                assignment_id=generated["assignment_id"],
                reviewer_user_id=actor.actor_user_id,
                duty_grant_id=granted.duty_grant_id,
                duty_grant_version=granted.duty_grant_version,
                conflict_attestation_sha256=conflict.conflict_marker_sha256,
                expires_at=deadline,
                now=now,
            )
            return _Mutation(appeal=changed, assignment=assignment)
        if self.operation == "release_assignment":
            changed, release = appeal.release_assignment(
                requester_user_id=actor.actor_user_id,
                reason_code=command.reason_code,
                now=now,
            )
            return _Mutation(appeal=changed, assignment_release=release)
        if self.operation == "save_review":
            sealed = prepared.sealed_text
            if sealed is None:
                _fail("SERVICE_UNAVAILABLE")
            changed, draft = appeal.save_review_draft(
                reviewer_user_id=actor.actor_user_id,
                assessments=command.assessments,
                reason_codes=command.reason_codes,
                remedy_delta_codes=command.remedy_delta_codes,
                sealed_review_note_reference=sealed.sealed_reference,
                sealed_review_note_sha256=sealed.sealed_sha256,
                now=now,
            )
            return _Mutation(appeal=changed, review_draft=draft)
        if self.operation == "decide":
            policy = prepared.decision_policy
            if policy is None:
                _fail("SERVICE_UNAVAILABLE")
            changed, decision = appeal.decide(
                decision_version_id=generated["decision_id"],
                reviewer_user_id=actor.actor_user_id,
                expected_review_draft_version=command.expected_review_draft_version,
                decision_code=command.decision_code,
                policy_version=policy.policy_version,
                now=now,
            )
            return _Mutation(appeal=changed, decision=decision)
        _fail("INVALID_REQUEST")

    def _write_business(self, uow: Any, mutation: _Mutation) -> None:
        appeal = mutation.appeal
        uow.put(
            "appeals",
            appeal.appeal_id,
            appeal,
            checkpoint="appeal." + self.operation,
        )
        if mutation.application_draft is not None:
            value = mutation.application_draft
            uow.put(
                "appeal_application_drafts",
                f"{value.appeal_id}:{value.version}",
                value,
                checkpoint="application_draft",
            )
        if mutation.application_version is not None:
            value = mutation.application_version
            uow.put(
                "appeal_application_versions",
                f"{value.appeal_id}:{value.version}",
                value,
                checkpoint="application_version",
            )
        if mutation.assignment is not None:
            value = mutation.assignment
            uow.put(
                "appeal_assignments",
                value.assignment_id,
                value,
                checkpoint="assignment",
            )
        if mutation.assignment_release is not None:
            value = mutation.assignment_release
            uow.put(
                "appeal_assignment_releases",
                value.assignment_id,
                value,
                checkpoint="assignment_release",
            )
        if mutation.review_draft is not None:
            value = mutation.review_draft
            uow.put(
                "appeal_review_drafts",
                f"{value.appeal_id}:{value.version}",
                value,
                checkpoint="review_draft",
            )
        if mutation.decision is not None:
            value = mutation.decision
            uow.put(
                "appeal_decisions",
                value.decision_version_id,
                value,
                checkpoint="decision",
            )

    def _receipt_identities(
        self, *, actor_user_id: str, idempotency_key: str
    ) -> Tuple[Mapping[str, Any], ...]:
        key_ids = _key_ids(
            getattr(
                self._receipt_keyring,
                "idempotency_key_digest_key_ids",
                None,
            )
        )
        material = (
            b"desire:appeal:idempotency:v1\0"
            + actor_user_id.encode("ascii")
            + b"\0"
            + _OPERATIONS[self.operation].encode("ascii")
            + b"\0"
            + idempotency_key.encode("utf-8")
        )
        return tuple(
            {
                "principal_kind": "USER",
                "principal_id": actor_user_id,
                "command_name": _OPERATIONS[self.operation],
                "command_version": 1,
                "idempotency_key_digest_key_id": key_id,
                "idempotency_key_digest": self._digest(key_id, material),
            }
            for key_id in key_ids
        )

    def _payload_key_ids(self) -> Tuple[str, ...]:
        return _key_ids(
            getattr(self._receipt_keyring, "payload_hash_key_ids", None)
        )

    def _payload_hashes(
        self, *, actor: TrustActorContext, command: Any
    ) -> Mapping[str, str]:
        body = _command_body(self.operation, command)
        material = {
            "body": body,
            "canonical_path": _CANONICAL_PATHS[self.operation],
            "command_schema_version": 1,
            "method": _METHODS[self.operation],
            "workspace_organization_id": actor.organization_id,
        }
        try:
            encoded = json.dumps(
                material,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        except (TypeError, ValueError, UnicodeError):
            _fail("INVALID_REQUEST")
        keyed = (
            b"desire:appeal:command-payload:v1\0"
            + _OPERATIONS[self.operation].encode("ascii")
            + b"\0"
            + encoded
        )
        return {
            key_id: self._digest(key_id, keyed)
            for key_id in self._payload_key_ids()
        }

    def _digest(self, key_id: str, material: bytes) -> str:
        try:
            value = self._receipt_keyring.keyed_digest(key_id, material)
        except Exception:
            _fail("SERVICE_UNAVAILABLE")
        if not _is_digest(value):
            _fail("SERVICE_UNAVAILABLE")
        return value

    def _new_id(self, kind: str) -> str:
        try:
            value = self._id_source.new_id(kind)
        except Exception:
            _fail("SERVICE_UNAVAILABLE")
        if not _is_uuid(value):
            _fail("SERVICE_UNAVAILABLE")
        return value

    def _now(self) -> datetime:
        try:
            value = self._clock.now()
        except Exception:
            _fail("SERVICE_UNAVAILABLE")
        if not _is_utc(value):
            _fail("SERVICE_UNAVAILABLE")
        return value

    def _recover(
        self,
        identities: Tuple[Mapping[str, Any], ...],
        payload_hashes: Mapping[str, str],
    ) -> Optional[AppealCommandResult]:
        try:
            snapshot = self._snapshot()
            value = _find_receipt(
                snapshot.get("appeal_command_receipts", {}), identities
            )
            if value is None:
                return None
            return _replay(value, payload_hashes)
        except AppealApplicationError as error:
            if error.code == "IDEMPOTENCY_KEY_REUSED":
                raise
            return None


class OpenAppealHandler(_AppealHandler):
    operation = "open"


class SaveAppealDraftHandler(_AppealHandler):
    operation = "save_draft"


class SubmitAppealHandler(_AppealHandler):
    operation = "submit"


class ClaimAppealHandler(_AppealHandler):
    operation = "claim"


class ReleaseAppealAssignmentHandler(_AppealHandler):
    operation = "release_assignment"


class SaveAppealReviewDraftHandler(_AppealHandler):
    operation = "save_review"


class DecideAppealHandler(_AppealHandler):
    operation = "decide"


def _validate_actor(actor: TrustActorContext, *, applicant: bool) -> None:
    if (
        not _is_uuid(actor.actor_user_id)
        or not _is_uuid(actor.session_id)
        or not _is_uuid(actor.correlation_id)
        or not _is_uuid(actor.causation_id)
        or not _is_uuid(actor.trace_id)
        or actor.original_actor_user_id is not None
        or (applicant and not _is_uuid(actor.organization_id))
        or (not applicant and actor.organization_id is not None)
    ):
        _fail("ACCESS_DENIED")


def _validate_command(operation: str, command: Any) -> None:
    if (
        not isinstance(command.idempotency_key, str)
        or _IDEMPOTENCY_KEY.fullmatch(command.idempotency_key) is None
    ):
        _fail("INVALID_REQUEST")
    if operation == "open":
        if not _is_uuid(command.source_outcome_version_id):
            _fail("INVALID_REQUEST")
        return
    if (
        not _is_uuid(command.appeal_id)
        or type(command.expected_appeal_version) is not int
        or command.expected_appeal_version < 1
    ):
        _fail("INVALID_REQUEST")
    if operation == "save_draft" and (
        not isinstance(command.applicant_statement, str)
        or not 1 <= len(command.applicant_statement) <= 4_000
        or not isinstance(command.grounds, tuple)
        or not 1 <= len(command.grounds) <= 3
        or any(not isinstance(value, AppealGround) for value in command.grounds)
        or len(set(command.grounds)) != len(command.grounds)
        or not isinstance(command.requested_outcome, RequestedAppealOutcome)
        or not _uuid_tuple(command.new_evidence_reference_ids, maximum=32)
        or (
            AppealGround.NEW_MATERIAL_EVIDENCE in command.grounds
            and not command.new_evidence_reference_ids
        )
    ):
        _fail("APPEAL_APPLICATION_INVALID")
    if operation == "release_assignment" and not isinstance(
        command.reason_code, AppealAssignmentReleaseReason
    ):
        _fail("APPEAL_ASSIGNMENT_RELEASE_INVALID")
    if operation == "save_review" and (
        not isinstance(command.reviewer_note, str)
        or not 1 <= len(command.reviewer_note) <= 4_000
        or not _valid_assessments(command.assessments)
        or not _closed_codes(
            command.reason_codes, _REVIEW_REASON_CODES, maximum=32
        )
        or not _closed_codes(
            command.remedy_delta_codes, _REMEDY_DELTA_CODES, maximum=32
        )
    ):
        _fail("APPEAL_REVIEW_INVALID")
    if operation == "submit" and (
        type(command.expected_draft_version) is not int
        or command.expected_draft_version < 1
    ):
        _fail("INVALID_REQUEST")
    if operation == "decide" and (
        type(command.expected_review_draft_version) is not int
        or command.expected_review_draft_version < 1
        or not isinstance(command.decision_code, AppealDecisionCode)
    ):
        _fail("INVALID_REQUEST")


def _validate_applicant_authority(
    value: Any, actor: TrustActorContext
) -> AppealApplicantAuthority:
    if not isinstance(value, AppealApplicantAuthority):
        _fail("SERVICE_UNAVAILABLE")
    if value.user_status != "ACTIVE":
        _fail("AUTHENTICATION_REQUIRED")
    if (
        value.session_status != "ACTIVE"
        or value.session_family_status != "ACTIVE"
        or value.session_id != actor.session_id
    ):
        _fail("SESSION_EXPIRED")
    if (
        value.actor_user_id != actor.actor_user_id
        or value.organization_id != actor.organization_id
        or value.organization_status != "ACTIVE"
        or value.membership_status != "ACTIVE"
        or value.role_code != "DEMAND_OWNER"
    ):
        _fail("APPEAL_NOT_FOUND")
    if not value.policy_requirements_satisfied:
        _fail("POLICY_ACCEPTANCE_REQUIRED")
    if (
        type(value.membership_role_grant_version) is not int
        or value.membership_role_grant_version < 1
        or not all(
            _is_uuid(identifier)
            for identifier in (
                value.actor_user_id,
                value.session_id,
                value.organization_id,
                value.membership_id,
                value.membership_role_grant_id,
            )
        )
        or not _is_digest(value.authority_marker_sha256)
    ):
        _fail("SERVICE_UNAVAILABLE")
    return value


def _validate_reviewer_authority(
    value: Any, actor: TrustActorContext, now: datetime
) -> AppealReviewerAuthority:
    if not isinstance(value, AppealReviewerAuthority):
        _fail("SERVICE_UNAVAILABLE")
    if value.user_status != "ACTIVE":
        _fail("AUTHENTICATION_REQUIRED")
    if (
        value.session_status != "ACTIVE"
        or value.session_family_status != "ACTIVE"
        or value.session_id != actor.session_id
    ):
        _fail("SESSION_EXPIRED")
    if value.actor_user_id != actor.actor_user_id or value.duty_code != "APPEAL_REVIEWER":
        _fail("ACCESS_DENIED")
    if (
        type(value.duty_grant_version) is not int
        or value.duty_grant_version < 1
        or not _is_uuid(value.actor_user_id)
        or not _is_uuid(value.session_id)
        or not _is_uuid(value.duty_grant_id)
        or not _is_digest(value.authority_marker_sha256)
        or (
            value.duty_expires_at is not None
            and (
                not _is_utc(value.duty_expires_at)
                or value.duty_expires_at <= now
            )
        )
    ):
        _fail("SERVICE_UNAVAILABLE")
    return value


def _validate_applicant_source(
    value: Any,
    authority: AppealApplicantAuthority,
    source_outcome_version_id: str,
    now: datetime,
) -> AppealApplicantSource:
    if not isinstance(value, AppealApplicantSource):
        _fail("SERVICE_UNAVAILABLE")
    source = value.source
    if (
        value.applicant_user_id != authority.actor_user_id
        or value.organization_id != authority.organization_id
        or not isinstance(source, TrustCaseOutcomeSource)
        or source.outcome_version_id != source_outcome_version_id
        or source.organization_id != authority.organization_id
        or type(value.applicant_is_party) is not bool
        or not value.applicant_is_party
        or not _is_digest(value.applicant_party_marker_sha256)
        or not _is_utc(value.evaluated_at)
        or not _is_utc(value.valid_until)
        or value.evaluated_at > now
        or now >= value.valid_until
        or not source.appeal_eligible
        or source.appeal_eligibility_code != "ELIGIBLE"
        or source.appeal_deadline is None
        or not _is_utc(source.appeal_deadline)
        or now >= source.appeal_deadline
    ):
        _fail("APPEAL_NOT_AVAILABLE")
    return value


def _validate_conflict(
    value: Any,
    *,
    reviewer: AppealReviewerAuthority,
    appeal: Appeal,
    now: datetime,
) -> AppealReviewerConflictCheck:
    if not isinstance(value, AppealReviewerConflictCheck):
        _fail("SERVICE_UNAVAILABLE")
    if (
        value.appeal_id != appeal.appeal_id
        or value.source_outcome_version_id != appeal.source.outcome_version_id
        or value.source_case_id != appeal.source.case_id
        or value.reviewer_user_id != reviewer.actor_user_id
        or value.duty_grant_id != reviewer.duty_grant_id
        or value.duty_grant_version != reviewer.duty_grant_version
        or type(value.conflict_free) is not bool
        or not _is_digest(value.conflict_marker_sha256)
        or not _is_utc(value.evaluated_at)
        or not _is_utc(value.valid_until)
        or value.evaluated_at > now
        or now >= value.valid_until
    ):
        _fail("SERVICE_UNAVAILABLE")
    if not value.conflict_free:
        _fail("CONFLICT_OF_INTEREST")
    return value


def _validate_sealed(value: Any, now: datetime) -> AppealSealedText:
    if (
        not isinstance(value, AppealSealedText)
        or not isinstance(value.sealed_reference, str)
        or _SEALED_REFERENCE.fullmatch(value.sealed_reference) is None
        or not _is_digest(value.sealed_sha256)
        or value.retention_class != "APPEAL_RESTRICTED_TEXT"
        or not _is_utc(value.sealed_at)
        or value.sealed_at > now
    ):
        _fail("SERVICE_UNAVAILABLE")
    return value


def _validate_policy(
    value: Any,
    *,
    appeal: Appeal,
    command: DecideAppealCommand,
    now: datetime,
) -> AppealDecisionPolicy:
    if (
        not isinstance(value, AppealDecisionPolicy)
        or value.appeal_id != appeal.appeal_id
        or value.appeal_aggregate_version != appeal.aggregate_version
        or value.source_outcome_version_id != appeal.source.outcome_version_id
        or value.review_draft_version != command.expected_review_draft_version
        or value.decision_code != command.decision_code.value
        or not isinstance(value.policy_version, str)
        or not value.policy_version
        or not _is_digest(value.policy_marker_sha256)
        or not _is_utc(value.evaluated_at)
        or not _is_utc(value.valid_until)
        or value.evaluated_at > now
        or now >= value.valid_until
    ):
        _fail("SERVICE_UNAVAILABLE")
    return value


def _key_ids(value: Any) -> Tuple[str, ...]:
    if (
        not isinstance(value, tuple)
        or not 1 <= len(value) <= 4
        or len(set(value)) != len(value)
        or any(not isinstance(item, str) or not item for item in value)
    ):
        _fail("SERVICE_UNAVAILABLE")
    return value


def _uuid_tuple(value: Any, *, maximum: int) -> bool:
    return (
        isinstance(value, tuple)
        and len(value) <= maximum
        and all(_is_uuid(item) for item in value)
        and len(set(value)) == len(value)
    )


def _closed_codes(
    value: Any, allowed: frozenset[str], *, maximum: int
) -> bool:
    return (
        isinstance(value, tuple)
        and 1 <= len(value) <= maximum
        and all(isinstance(item, str) and item in allowed for item in value)
        and len(set(value)) == len(value)
    )


def _valid_assessments(value: Any) -> bool:
    if (
        not isinstance(value, tuple)
        or not 1 <= len(value) <= 3
        or any(not isinstance(item, AppealGroundAssessment) for item in value)
    ):
        return False
    if any(
        not isinstance(item.ground, AppealGround)
        or not isinstance(item.assessment_code, AppealGroundAssessmentCode)
        for item in value
    ):
        return False
    grounds = tuple(item.ground for item in value)
    if len(set(grounds)) != len(grounds):
        return False
    return all(
        _closed_codes(item.finding_codes, _FINDING_CODES, maximum=32)
        and _uuid_tuple(item.accepted_evidence_reference_ids, maximum=32)
        for item in value
    )


def _find_receipt(
    receipts: Mapping[str, Any], identities: Tuple[Mapping[str, Any], ...]
) -> Optional[Mapping[str, Any]]:
    if not isinstance(receipts, Mapping):
        _fail("SERVICE_UNAVAILABLE")
    matches = []
    for receipt in receipts.values():
        if not isinstance(receipt, Mapping):
            _fail("SERVICE_UNAVAILABLE")
        for identity in identities:
            if all(receipt.get(name) == value for name, value in identity.items()):
                matches.append(receipt)
                break
    if len(matches) > 1:
        _fail("SERVICE_UNAVAILABLE")
    return None if not matches else matches[0]


def _replay(
    receipt: Mapping[str, Any], payload_hashes: Mapping[str, str]
) -> AppealCommandResult:
    key_id = receipt.get("payload_hash_key_id")
    expected = payload_hashes.get(key_id)
    if expected is None:
        _fail("SERVICE_UNAVAILABLE")
    if receipt.get("payload_hash") != expected:
        _fail("IDEMPOTENCY_KEY_REUSED")
    if receipt.get("status") == "IN_PROGRESS":
        _fail("COMMAND_IN_PROGRESS")
    if receipt.get("status") != "COMPLETED":
        _fail("SERVICE_UNAVAILABLE")
    safe = receipt.get("safe_response")
    if not isinstance(safe, Mapping):
        _fail("SERVICE_UNAVAILABLE")
    return _result(safe, replayed=True)


def _safe_response(
    appeal: Appeal,
    *,
    decision: Optional[AppealDecisionVersion],
    event_type: str,
    completed_at: datetime,
) -> Mapping[str, Any]:
    return {
        "appeal_id": appeal.appeal_id,
        "appeal_status": appeal.status.value,
        "aggregate_version": appeal.aggregate_version,
        "application_draft_version": appeal.current_application_draft_version,
        "application_version": appeal.submitted_application_version,
        "review_draft_version": appeal.current_review_draft_version,
        "decision_version_id": (
            decision.decision_version_id
            if decision is not None
            else appeal.decision_version_id
        ),
        "event_types": [event_type],
        "completed_at": _timestamp(completed_at),
    }


def _result(safe: Mapping[str, Any], *, replayed: bool) -> AppealCommandResult:
    expected = {
        "appeal_id",
        "appeal_status",
        "aggregate_version",
        "application_draft_version",
        "application_version",
        "review_draft_version",
        "decision_version_id",
        "event_types",
        "completed_at",
    }
    if set(safe) != expected:
        _fail("SERVICE_UNAVAILABLE")
    try:
        completed = datetime.fromisoformat(
            safe["completed_at"].replace("Z", "+00:00")
        )
        status = AppealStatus(safe["appeal_status"])
        events = tuple(safe["event_types"])
    except (AttributeError, TypeError, ValueError):
        _fail("SERVICE_UNAVAILABLE")
    if (
        not _is_uuid(safe["appeal_id"])
        or type(safe["aggregate_version"]) is not int
        or safe["aggregate_version"] < 1
        or any(
            value is not None and (type(value) is not int or value < 1)
            for value in (
                safe["application_draft_version"],
                safe["application_version"],
                safe["review_draft_version"],
            )
        )
        or (
            safe["decision_version_id"] is not None
            and not _is_uuid(safe["decision_version_id"])
        )
        or len(events) != 1
        or events[0] not in set(_EVENTS.values())
        or not _is_utc(completed)
    ):
        _fail("SERVICE_UNAVAILABLE")
    return AppealCommandResult(
        appeal_id=safe["appeal_id"],
        appeal_status=status,
        aggregate_version=safe["aggregate_version"],
        application_draft_version=safe["application_draft_version"],
        application_version=safe["application_version"],
        review_draft_version=safe["review_draft_version"],
        decision_version_id=safe["decision_version_id"],
        replayed=replayed,
        event_types=events,
        completed_at=completed,
    )


def _command_body(operation: str, command: Any) -> Mapping[str, Any]:
    if operation == "open":
        return {"source_outcome_version_id": command.source_outcome_version_id}
    common = {
        "appeal_id": command.appeal_id,
        "expected_appeal_version": command.expected_appeal_version,
    }
    if operation == "save_draft":
        return {
            **common,
            "grounds": [_enum(value) for value in command.grounds],
            "requested_outcome": _enum(command.requested_outcome),
            "applicant_statement_sha256": hashlib.sha256(
                command.applicant_statement.encode("utf-8")
            ).hexdigest(),
            "new_evidence_reference_ids": list(
                command.new_evidence_reference_ids
            ),
        }
    if operation == "submit":
        return {**common, "expected_draft_version": command.expected_draft_version}
    if operation == "claim":
        return common
    if operation == "release_assignment":
        return {**common, "reason_code": _enum(command.reason_code)}
    if operation == "save_review":
        return {
            **common,
            "assessments": [
                {
                    "accepted_evidence_reference_ids": list(
                        value.accepted_evidence_reference_ids
                    ),
                    "assessment_code": _enum(value.assessment_code),
                    "finding_codes": list(value.finding_codes),
                    "ground": _enum(value.ground),
                }
                for value in command.assessments
            ],
            "reason_codes": list(command.reason_codes),
            "remedy_delta_codes": list(command.remedy_delta_codes),
            "reviewer_note_sha256": hashlib.sha256(
                command.reviewer_note.encode("utf-8")
            ).hexdigest(),
        }
    if operation == "decide":
        return {
            **common,
            "decision_code": _enum(command.decision_code),
            "expected_review_draft_version": command.expected_review_draft_version,
        }
    _fail("INVALID_REQUEST")


def _enum(value: Any) -> Any:
    return value.value if isinstance(value, Enum) else value


def _audit(
    *,
    audit_id: str,
    actor: TrustActorContext,
    appeal: Appeal,
    event_type: str,
    occurred_at: datetime,
    receipt_id: str,
) -> Mapping[str, Any]:
    return {
        "audit_id": audit_id,
        "occurred_at": _timestamp(occurred_at),
        "actor_kind": "USER",
        "actor_id": actor.actor_user_id,
        "original_actor_id": None,
        "action_code": event_type,
        "target_kind": "Appeal",
        "target_id": appeal.appeal_id,
        "organization_id": appeal.source.organization_id,
        "result_code": "SUCCESS",
        "command_receipt_id": receipt_id,
        "correlation_id": actor.correlation_id,
        "causation_id": actor.causation_id,
        "trace_id": actor.trace_id,
        "safe_attributes": {
            "appeal_id": appeal.appeal_id,
            "appeal_status": appeal.status.value,
            "event_type": event_type,
        },
    }


def _event(
    *,
    event_id: str,
    actor: TrustActorContext,
    appeal: Appeal,
    event_type: str,
    occurred_at: datetime,
) -> Mapping[str, Any]:
    payload: dict[str, Any] = {
        "appeal_id": appeal.appeal_id,
        "appeal_status": appeal.status.value,
        "source_outcome_version_id": appeal.source.outcome_version_id,
    }
    if appeal.current_application_draft_version is not None:
        payload["application_draft_version"] = appeal.current_application_draft_version
    if appeal.submitted_application_version is not None:
        payload["application_version"] = appeal.submitted_application_version
    if appeal.current_review_draft_version is not None:
        payload["review_draft_version"] = appeal.current_review_draft_version
    if appeal.decision_version_id is not None:
        payload["decision_version_id"] = appeal.decision_version_id
    return {
        "event_id": event_id,
        "event_type": event_type,
        "schema_version": 1,
        "occurred_at": _timestamp(occurred_at),
        "aggregate_type": "Appeal",
        "aggregate_id": appeal.appeal_id,
        "aggregate_version": appeal.aggregate_version,
        "actor_kind": "USER",
        "actor_id": actor.actor_user_id,
        "original_actor_id": None,
        "correlation_id": actor.correlation_id,
        "causation_id": actor.causation_id,
        "trace_id": actor.trace_id,
        "organization_id": appeal.source.organization_id,
        "payload": payload,
    }


def _is_uuid(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError):
        return False
    return parsed.int != 0 and str(parsed) == value


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _is_utc(value: Any) -> bool:
    return (
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() == timezone.utc.utcoffset(value)
    )


def _timestamp(value: datetime) -> str:
    if not _is_utc(value):
        _fail("SERVICE_UNAVAILABLE")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _fail(code: str) -> None:
    raise AppealApplicationError(code)


__all__ = [
    "AppealApplicationError",
    "ClaimAppealHandler",
    "DecideAppealHandler",
    "OpenAppealHandler",
    "ReleaseAppealAssignmentHandler",
    "SaveAppealDraftHandler",
    "SaveAppealReviewDraftHandler",
    "SubmitAppealHandler",
]
