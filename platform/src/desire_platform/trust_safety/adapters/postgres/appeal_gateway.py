"""Closed PostgreSQL boundary for the Trust0002 Appeal programs.

The boundary deliberately exposes named operations only.  Callers cannot
provide function names, SQL fragments, result mappers, or database roles.
Restricted text is encrypted before it reaches :class:`AppealRestrictedTextStoreRequest`;
raw applicant and reviewer text therefore never crosses this module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hmac
import re
from typing import Any, Mapping, Optional, Tuple
from uuid import UUID

from psycopg.pq import TransactionStatus
from psycopg.types.json import Jsonb

from ._session_settings import set_config_result_matches

from ...application.appeal_commands import AppealCommandResult
from ...domain import AppealStatus
from ...ports.appeal import (
    AppealActiveAssignmentItem,
    AppealActiveAssignmentsProjection,
    AppealApplicationDraftProjection,
    AppealAssignedProjection,
    AppealAssessmentProjection,
    AppealCompletedAssignmentItem,
    AppealCompletedAssignmentsProjection,
    AppealCompletedDetailProjection,
    AppealDecisionProjection,
    AppealOwnProjection,
    AppealQueueItem,
    AppealQueueProjection,
    AppealReviewDraftProjection,
    AppealSealedText,
    AppealSourceProjection,
    AppealSubmittedApplicationProjection,
)
from .migrations import (
    TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
    TRUST_REQUIRED_IAM_SCHEMA_VERSION,
    TRUST_SCHEMA_HEAD_VERSION,
)


_KEY_ID = re.compile(r"[a-z0-9][a-z0-9-]{2,127}\Z")
_SEALED_REFERENCE = re.compile(r"sealed://trust/[a-z0-9][a-z0-9/_-]{4,255}\Z")
_OPERATIONS = frozenset(
    {
        "OPEN_APPEAL",
        "SAVE_APPEAL_DRAFT",
        "SUBMIT_APPEAL",
        "CLAIM_APPEAL",
        "RELEASE_APPEAL_ASSIGNMENT",
        "SAVE_APPEAL_REVIEW_DRAFT",
        "DECIDE_APPEAL",
    }
)
_APPLICANT_OPERATIONS = frozenset(
    {"OPEN_APPEAL", "SAVE_APPEAL_DRAFT", "SUBMIT_APPEAL"}
)
_EVENT_TYPES = {
    "OPEN_APPEAL": "AppealOpened",
    "SAVE_APPEAL_DRAFT": "AppealApplicationDraftSaved",
    "SUBMIT_APPEAL": "AppealSubmitted",
    "CLAIM_APPEAL": "AppealReviewClaimed",
    "RELEASE_APPEAL_ASSIGNMENT": "AppealReviewAssignmentReleased",
    "SAVE_APPEAL_REVIEW_DRAFT": "AppealReviewDraftSaved",
    "DECIDE_APPEAL": "AppealDecisionPublished",
}
_SAFE_RESULT_KEYS = frozenset(
    {
        "aggregate_version",
        "appeal_id",
        "appeal_status",
        "application_draft_version",
        "application_version",
        "completed_at",
        "decision_version_id",
        "event_types",
        "review_draft_version",
    }
)
_GROUNDS = frozenset(
    {"PROCEDURAL_ERROR", "NEW_MATERIAL_EVIDENCE", "RULE_MISAPPLICATION"}
)
_REQUESTED_OUTCOMES = frozenset(
    {"REMOVE_MEASURE", "MODIFY_MEASURE", "VACATE_AND_REMAND"}
)
_ASSESSMENT_CODES = frozenset({"ACCEPTED", "PARTIALLY_ACCEPTED", "REJECTED"})
_FINDING_CODES = frozenset(
    {
        "PROCEDURE_MATERIAL_ERROR",
        "NEW_EVIDENCE_MATERIAL",
        "RULE_APPLIED_CORRECTLY",
        "RULE_APPLICATION_ERROR",
        "APPEAL_NOT_SUBSTANTIATED",
    }
)
_REVIEW_REASON_CODES = frozenset(
    {
        "SOURCE_OUTCOME_SUPPORTED",
        "SOURCE_OUTCOME_UNSUPPORTED",
        "PROCEDURAL_REVIEW_COMPLETE",
        "NEW_EVIDENCE_REVIEWED",
        "REMAND_REQUIRED",
        "APPEAL_SCOPE_INVALID",
    }
)
_REMEDY_CODES = frozenset(
    {
        "NO_CHANGE",
        "REMOVE_CORRECTIVE_MEASURE",
        "NARROW_CORRECTIVE_MEASURE",
        "REPLACE_CORRECTIVE_MEASURE",
        "RETURN_TO_TRUST_REVIEW",
    }
)
_RELEASE_REASONS = frozenset(
    {"CONFLICT_DECLARED", "WORKLOAD_RELEASE", "ASSIGNMENT_EXPIRED"}
)
_DECISIONS = frozenset({"AFFIRM", "MODIFY", "VACATE_AND_REMAND", "DISMISS"})


class AppealPostgresError(RuntimeError):
    """Base class for the closed Appeal database boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class AppealPostgresConfigurationError(AppealPostgresError):
    def __init__(self) -> None:
        super().__init__("SERVICE_UNAVAILABLE")


class AppealPostgresCommitOutcomeUnknownError(AppealPostgresError):
    def __init__(self) -> None:
        super().__init__("COMMAND_OUTCOME_UNKNOWN")


class AppealPostgresRejectedError(AppealPostgresError):
    pass


@dataclass(frozen=True)
class AppealPostgresGatewaySettings:
    lock_timeout_ms: int = 2_000
    statement_timeout_ms: int = 10_000
    idle_in_transaction_timeout_ms: int = 15_000

    def __post_init__(self) -> None:
        if (
            type(self.lock_timeout_ms) is not int
            or not 1 <= self.lock_timeout_ms <= 10_000
            or type(self.statement_timeout_ms) is not int
            or not 1 <= self.statement_timeout_ms <= 30_000
            or type(self.idle_in_transaction_timeout_ms) is not int
            or not 1 <= self.idle_in_transaction_timeout_ms <= 30_000
        ):
            raise ValueError("Appeal PostgreSQL gateway settings are invalid")


@dataclass(frozen=True)
class AppealPostgresCommandContext:
    actor_user_id: UUID
    session_id: UUID = field(repr=False)
    correlation_id: UUID
    causation_id: UUID
    trace_id: UUID

    def __post_init__(self) -> None:
        _require_uuids(
            self.actor_user_id,
            self.session_id,
            self.correlation_id,
            self.causation_id,
            self.trace_id,
        )


@dataclass(frozen=True)
class AppealPostgresReceiptMaterial:
    receipt_id: UUID
    audit_event_id: UUID
    outbox_event_id: UUID
    idempotency_key_digest_key_ids: Tuple[str, ...]
    idempotency_key_digests: Tuple[bytes, ...] = field(repr=False)
    payload_hash_key_ids: Tuple[str, ...]
    payload_hashes: Tuple[bytes, ...] = field(repr=False)

    def __post_init__(self) -> None:
        _require_uuids(self.receipt_id, self.audit_event_id, self.outbox_event_id)
        if len({self.receipt_id, self.audit_event_id, self.outbox_event_id}) != 3:
            raise ValueError("Appeal PostgreSQL write IDs must be distinct")
        _require_key_material(
            self.idempotency_key_digest_key_ids,
            self.idempotency_key_digests,
        )
        _require_key_material(self.payload_hash_key_ids, self.payload_hashes)
        if set(self.idempotency_key_digest_key_ids) & set(self.payload_hash_key_ids):
            raise ValueError("Appeal PostgreSQL key purposes must be disjoint")


@dataclass(frozen=True)
class AppealPostgresReplayMaterial:
    idempotency_key_digest_key_ids: Tuple[str, ...]
    idempotency_key_digests: Tuple[bytes, ...] = field(repr=False)
    payload_hash_key_ids: Tuple[str, ...]
    payload_hashes: Tuple[bytes, ...] = field(repr=False)

    def __post_init__(self) -> None:
        _require_key_material(
            self.idempotency_key_digest_key_ids,
            self.idempotency_key_digests,
        )
        _require_key_material(self.payload_hash_key_ids, self.payload_hashes)
        if set(self.idempotency_key_digest_key_ids) & set(self.payload_hash_key_ids):
            raise ValueError("Appeal PostgreSQL key purposes must be disjoint")


@dataclass(frozen=True)
class AppealCompletedReceiptProbeRequest:
    context: AppealPostgresCommandContext
    material: AppealPostgresReplayMaterial = field(repr=False)
    operation: str
    organization_id: Optional[UUID]
    target_appeal_id: Optional[UUID]
    expected_appeal_version: Optional[int]

    def __post_init__(self) -> None:
        if not isinstance(self.context, AppealPostgresCommandContext) or not isinstance(
            self.material, AppealPostgresReplayMaterial
        ):
            raise TypeError("Appeal receipt probe dependencies are unavailable")
        if self.operation not in _OPERATIONS:
            raise ValueError("Appeal receipt probe operation is invalid")
        applicant = self.operation in _APPLICANT_OPERATIONS
        if applicant != (self.organization_id is not None):
            raise ValueError("Appeal receipt probe organization is invalid")
        if self.organization_id is not None:
            _require_uuids(self.organization_id)
        if self.operation == "OPEN_APPEAL":
            if self.target_appeal_id is not None or self.expected_appeal_version is not None:
                raise ValueError("Appeal open receipt probe is invalid")
        else:
            _require_uuids(self.target_appeal_id)
            _require_version(self.expected_appeal_version)


@dataclass(frozen=True)
class OpenAppealPostgresRequest:
    context: AppealPostgresCommandContext
    receipt: AppealPostgresReceiptMaterial
    organization_id: UUID
    appeal_id: UUID
    source_outcome_version_id: UUID

    def __post_init__(self) -> None:
        _require_request(self.context, self.receipt)
        _require_uuids(self.organization_id, self.appeal_id, self.source_outcome_version_id)


@dataclass(frozen=True)
class SaveAppealDraftPostgresRequest:
    context: AppealPostgresCommandContext
    receipt: AppealPostgresReceiptMaterial
    organization_id: UUID
    appeal_id: UUID
    expected_appeal_version: int
    sealed_statement_reference: str = field(repr=False)
    sealed_statement_sha256: bytes = field(repr=False)
    grounds: Tuple[str, ...]
    requested_outcome: str
    new_evidence_reference_ids: Tuple[UUID, ...] = field(repr=False)

    def __post_init__(self) -> None:
        _require_request(self.context, self.receipt)
        _require_uuids(self.organization_id, self.appeal_id)
        _require_version(self.expected_appeal_version)
        _require_sealed(self.sealed_statement_reference, self.sealed_statement_sha256)
        _require_codes(self.grounds, _GROUNDS, 1, 3)
        _require_enum(self.requested_outcome, _REQUESTED_OUTCOMES)
        _require_uuid_tuple(self.new_evidence_reference_ids, 0, 32)
        if "NEW_MATERIAL_EVIDENCE" in self.grounds and not self.new_evidence_reference_ids:
            raise ValueError("Appeal draft evidence is required")


@dataclass(frozen=True)
class SubmitAppealPostgresRequest:
    context: AppealPostgresCommandContext
    receipt: AppealPostgresReceiptMaterial
    organization_id: UUID
    appeal_id: UUID
    expected_appeal_version: int
    expected_draft_version: int

    def __post_init__(self) -> None:
        _require_request(self.context, self.receipt)
        _require_uuids(self.organization_id, self.appeal_id)
        _require_version(self.expected_appeal_version)
        _require_version(self.expected_draft_version)


@dataclass(frozen=True)
class ClaimAppealPostgresRequest:
    context: AppealPostgresCommandContext
    receipt: AppealPostgresReceiptMaterial
    assignment_id: UUID
    appeal_id: UUID
    expected_appeal_version: int

    def __post_init__(self) -> None:
        _require_request(self.context, self.receipt)
        _require_uuids(self.assignment_id, self.appeal_id)
        _require_version(self.expected_appeal_version)


@dataclass(frozen=True)
class ReleaseAppealAssignmentPostgresRequest:
    context: AppealPostgresCommandContext
    receipt: AppealPostgresReceiptMaterial
    appeal_id: UUID
    expected_appeal_version: int
    reason_code: str

    def __post_init__(self) -> None:
        _require_request(self.context, self.receipt)
        _require_uuids(self.appeal_id)
        _require_version(self.expected_appeal_version)
        _require_enum(self.reason_code, _RELEASE_REASONS)


@dataclass(frozen=True)
class AppealReviewAssessmentPostgres:
    ground: str
    assessment_code: str
    finding_codes: Tuple[str, ...]
    accepted_evidence_reference_ids: Tuple[UUID, ...] = field(repr=False)

    def __post_init__(self) -> None:
        _require_enum(self.ground, _GROUNDS)
        _require_enum(self.assessment_code, _ASSESSMENT_CODES)
        _require_codes(self.finding_codes, _FINDING_CODES, 1, 32)
        _require_uuid_tuple(self.accepted_evidence_reference_ids, 0, 32)

    def as_json(self) -> Mapping[str, Any]:
        return {
            "accepted_evidence_reference_ids": [
                str(value) for value in self.accepted_evidence_reference_ids
            ],
            "assessment_code": self.assessment_code,
            "finding_codes": list(self.finding_codes),
            "ground": self.ground,
        }


@dataclass(frozen=True)
class SaveAppealReviewDraftPostgresRequest:
    context: AppealPostgresCommandContext
    receipt: AppealPostgresReceiptMaterial
    appeal_id: UUID
    expected_appeal_version: int
    sealed_review_note_reference: str = field(repr=False)
    sealed_review_note_sha256: bytes = field(repr=False)
    assessments: Tuple[AppealReviewAssessmentPostgres, ...]
    reason_codes: Tuple[str, ...]
    remedy_delta_codes: Tuple[str, ...]

    def __post_init__(self) -> None:
        _require_request(self.context, self.receipt)
        _require_uuids(self.appeal_id)
        _require_version(self.expected_appeal_version)
        _require_sealed(
            self.sealed_review_note_reference, self.sealed_review_note_sha256
        )
        if (
            type(self.assessments) is not tuple
            or not 1 <= len(self.assessments) <= 3
            or any(
                not isinstance(value, AppealReviewAssessmentPostgres)
                for value in self.assessments
            )
            or len({value.ground for value in self.assessments})
            != len(self.assessments)
        ):
            raise ValueError("Appeal review assessments are invalid")
        _require_codes(self.reason_codes, _REVIEW_REASON_CODES, 1, 32)
        _require_codes(self.remedy_delta_codes, _REMEDY_CODES, 1, 32)


@dataclass(frozen=True)
class DecideAppealPostgresRequest:
    context: AppealPostgresCommandContext
    receipt: AppealPostgresReceiptMaterial
    decision_version_id: UUID
    appeal_id: UUID
    expected_appeal_version: int
    expected_review_draft_version: int
    decision_code: str

    def __post_init__(self) -> None:
        _require_request(self.context, self.receipt)
        _require_uuids(self.decision_version_id, self.appeal_id)
        _require_version(self.expected_appeal_version)
        _require_version(self.expected_review_draft_version)
        _require_enum(self.decision_code, _DECISIONS)


@dataclass(frozen=True)
class AppealRestrictedTextStoreRequest:
    actor_user_id: UUID
    session_id: UUID = field(repr=False)
    organization_id: Optional[UUID]
    appeal_id: UUID
    purpose_code: str
    encryption_key_ids: Tuple[str, ...]
    candidate_references: Tuple[str, ...] = field(repr=False)
    plaintext_hmac_sha256s: Tuple[bytes, ...] = field(repr=False)
    envelope_sha256: bytes = field(repr=False)
    encryption_key_id: str
    nonce: bytes = field(repr=False)
    ciphertext: bytes = field(repr=False)
    aad_sha256: bytes = field(repr=False)
    replay_material: AppealPostgresReplayMaterial = field(repr=False)
    retention_class: str
    retain_until: datetime
    duty_grant_id: Optional[UUID] = field(default=None, repr=False)
    duty_grant_version: Optional[int] = field(default=None, repr=False)

    def __post_init__(self) -> None:
        _require_uuids(self.actor_user_id, self.session_id, self.appeal_id)
        if self.organization_id is not None:
            _require_uuids(self.organization_id)
        applicant = self.purpose_code == "APPEAL_STATEMENT"
        if self.purpose_code not in {"APPEAL_STATEMENT", "APPEAL_REVIEW_NOTE"}:
            raise ValueError("Appeal restricted-text purpose is invalid")
        if applicant != (self.organization_id is not None):
            raise ValueError("Appeal restricted-text organization is invalid")
        if self.retention_class != "APPEAL_RESTRICTED_TEXT":
            raise ValueError("Appeal restricted-text retention is invalid")
        if (
            type(self.encryption_key_ids) is not tuple
            or not 1 <= len(self.encryption_key_ids) <= 4
            or len(set(self.encryption_key_ids)) != len(self.encryption_key_ids)
            or any(not _valid_key_id(value) for value in self.encryption_key_ids)
            or type(self.candidate_references) is not tuple
            or len(self.candidate_references) != len(self.encryption_key_ids)
            or len(set(self.candidate_references)) != len(self.candidate_references)
            or any(
                not isinstance(value, str)
                or _SEALED_REFERENCE.fullmatch(value) is None
                for value in self.candidate_references
            )
            or self.encryption_key_id != self.encryption_key_ids[0]
            or type(self.plaintext_hmac_sha256s) is not tuple
            or len(self.plaintext_hmac_sha256s) != len(self.encryption_key_ids)
            or any(not _digest(value) for value in self.plaintext_hmac_sha256s)
            or not _digest(self.envelope_sha256)
            or not isinstance(self.nonce, bytes)
            or len(self.nonce) != 12
            or not isinstance(self.ciphertext, bytes)
            or not 17 <= len(self.ciphertext) <= 16_384
            or not _digest(self.aad_sha256)
            or not isinstance(self.replay_material, AppealPostgresReplayMaterial)
        ):
            raise ValueError("Appeal restricted-text envelope is invalid")
        _require_utc(self.retain_until)
        if (self.duty_grant_id is None) != (self.duty_grant_version is None):
            raise ValueError("Appeal reviewer duty echo is incomplete")
        if applicant and self.duty_grant_id is not None:
            raise ValueError("Appeal applicant duty echo is forbidden")
        if self.duty_grant_id is not None:
            _require_uuids(self.duty_grant_id)
            _require_version(self.duty_grant_version)


class PsycopgAppealCommandGateway:
    """Invoke only the seven reviewed Appeal write programs."""

    def __init__(
        self,
        *,
        applicant_connections: Any,
        reviewer_connections: Any,
        settings: AppealPostgresGatewaySettings = AppealPostgresGatewaySettings(),
    ) -> None:
        _require_sources(applicant_connections, reviewer_connections)
        if not isinstance(settings, AppealPostgresGatewaySettings):
            raise TypeError("Appeal PostgreSQL gateway settings are unavailable")
        self._applicant_connections = applicant_connections
        self._reviewer_connections = reviewer_connections
        self._settings = settings
        self._closed = False

    def open_appeal(self, request: OpenAppealPostgresRequest) -> AppealCommandResult:
        _require_type(request, OpenAppealPostgresRequest)
        context, receipt = request.context, request.receipt
        return self._run(
            operation="OPEN_APPEAL",
            request=request,
            function="open_appeal_v1",
            count=15,
            parameters=(
                context.actor_user_id,
                context.session_id,
                request.organization_id,
                context.correlation_id,
                context.causation_id,
                context.trace_id,
                receipt.receipt_id,
                receipt.audit_event_id,
                receipt.outbox_event_id,
                request.appeal_id,
                request.source_outcome_version_id,
                *_receipt_parameters(receipt),
            ),
        )

    def save_appeal_draft(
        self, request: SaveAppealDraftPostgresRequest
    ) -> AppealCommandResult:
        _require_type(request, SaveAppealDraftPostgresRequest)
        context, receipt = request.context, request.receipt
        return self._run(
            operation="SAVE_APPEAL_DRAFT",
            request=request,
            function="save_appeal_draft_v1",
            count=20,
            parameters=(
                context.actor_user_id,
                context.session_id,
                request.organization_id,
                context.correlation_id,
                context.causation_id,
                context.trace_id,
                receipt.receipt_id,
                receipt.audit_event_id,
                receipt.outbox_event_id,
                request.appeal_id,
                request.expected_appeal_version,
                *_receipt_parameters(receipt),
                request.sealed_statement_reference,
                request.sealed_statement_sha256,
                list(request.grounds),
                request.requested_outcome,
                list(request.new_evidence_reference_ids),
            ),
        )

    def submit_appeal(
        self, request: SubmitAppealPostgresRequest
    ) -> AppealCommandResult:
        _require_type(request, SubmitAppealPostgresRequest)
        context, receipt = request.context, request.receipt
        return self._run(
            operation="SUBMIT_APPEAL",
            request=request,
            function="submit_appeal_v1",
            count=16,
            parameters=(
                context.actor_user_id,
                context.session_id,
                request.organization_id,
                context.correlation_id,
                context.causation_id,
                context.trace_id,
                receipt.receipt_id,
                receipt.audit_event_id,
                receipt.outbox_event_id,
                request.appeal_id,
                request.expected_appeal_version,
                request.expected_draft_version,
                *_receipt_parameters(receipt),
            ),
        )

    def claim_appeal(self, request: ClaimAppealPostgresRequest) -> AppealCommandResult:
        _require_type(request, ClaimAppealPostgresRequest)
        context, receipt = request.context, request.receipt
        return self._run(
            operation="CLAIM_APPEAL",
            request=request,
            function="claim_appeal_v1",
            count=15,
            parameters=(
                context.actor_user_id,
                context.session_id,
                context.correlation_id,
                context.causation_id,
                context.trace_id,
                receipt.receipt_id,
                receipt.audit_event_id,
                receipt.outbox_event_id,
                request.assignment_id,
                request.appeal_id,
                request.expected_appeal_version,
                *_receipt_parameters(receipt),
            ),
        )

    def release_appeal_assignment(
        self, request: ReleaseAppealAssignmentPostgresRequest
    ) -> AppealCommandResult:
        _require_type(request, ReleaseAppealAssignmentPostgresRequest)
        context, receipt = request.context, request.receipt
        return self._run(
            operation="RELEASE_APPEAL_ASSIGNMENT",
            request=request,
            function="release_appeal_assignment_v1",
            count=15,
            parameters=(
                context.actor_user_id,
                context.session_id,
                context.correlation_id,
                context.causation_id,
                context.trace_id,
                receipt.receipt_id,
                receipt.audit_event_id,
                receipt.outbox_event_id,
                request.appeal_id,
                request.expected_appeal_version,
                request.reason_code,
                *_receipt_parameters(receipt),
            ),
        )

    def save_appeal_review_draft(
        self, request: SaveAppealReviewDraftPostgresRequest
    ) -> AppealCommandResult:
        _require_type(request, SaveAppealReviewDraftPostgresRequest)
        context, receipt = request.context, request.receipt
        return self._run(
            operation="SAVE_APPEAL_REVIEW_DRAFT",
            request=request,
            function="save_appeal_review_draft_v1",
            count=19,
            parameters=(
                context.actor_user_id,
                context.session_id,
                context.correlation_id,
                context.causation_id,
                context.trace_id,
                receipt.receipt_id,
                receipt.audit_event_id,
                receipt.outbox_event_id,
                request.appeal_id,
                request.expected_appeal_version,
                *_receipt_parameters(receipt),
                request.sealed_review_note_reference,
                request.sealed_review_note_sha256,
                Jsonb([dict(value.as_json()) for value in request.assessments]),
                list(request.reason_codes),
                list(request.remedy_delta_codes),
            ),
        )

    def decide_appeal(
        self, request: DecideAppealPostgresRequest
    ) -> AppealCommandResult:
        _require_type(request, DecideAppealPostgresRequest)
        context, receipt = request.context, request.receipt
        return self._run(
            operation="DECIDE_APPEAL",
            request=request,
            function="decide_appeal_v1",
            count=17,
            parameters=(
                context.actor_user_id,
                context.session_id,
                context.correlation_id,
                context.causation_id,
                context.trace_id,
                receipt.receipt_id,
                receipt.audit_event_id,
                receipt.outbox_event_id,
                request.decision_version_id,
                request.appeal_id,
                request.expected_appeal_version,
                request.expected_review_draft_version,
                request.decision_code,
                *_receipt_parameters(receipt),
            ),
        )

    def close(self) -> None:
        self._closed = True

    def _run(
        self,
        *,
        operation: str,
        request: Any,
        function: str,
        count: int,
        parameters: tuple[Any, ...],
    ) -> AppealCommandResult:
        if self._closed:
            raise AppealPostgresConfigurationError()
        if len(parameters) != count:
            raise AppealPostgresConfigurationError()
        applicant = operation in _APPLICANT_OPERATIONS
        return self._write_once(
            source=(
                self._applicant_connections if applicant else self._reviewer_connections
            ),
            role="trust_self" if applicant else "trust_appeal",
            operation=operation,
            organization_id=getattr(request, "organization_id", None),
            appeal_id=getattr(request, "appeal_id", None),
            request=request,
            statement=(
                f"SELECT safe_response,replayed FROM trust_api.{function}("
                + ",".join(["%s"] * count)
                + ")"
            ),
            parameters=parameters,
        )

    def _write_once(
        self,
        *,
        source: Any,
        role: str,
        operation: str,
        organization_id: Optional[UUID],
        appeal_id: Optional[UUID],
        request: Any,
        statement: str,
        parameters: tuple[Any, ...],
    ) -> AppealCommandResult:
        connection = None
        state = "NEW"
        disposed = False
        try:
            connection = source.checkout()
            _prepare(connection, role)
            connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED")
            state = "BEGUN"
            _configure(
                connection,
                settings=self._settings,
                scope="APPEAL_COMMAND",
                operation=operation,
                actor_id=request.context.actor_user_id,
                session_id=request.context.session_id,
                organization_id=organization_id,
                appeal_id=appeal_id,
            )
            state = "WRITING"
            row = connection.execute(statement, parameters).fetchone()
            result = _command_result(operation, request, row)
            state = "COMMIT_SENT"
            connection.execute("COMMIT")
            state = "COMMITTED"
            _reset(connection)
            source.release(connection)
            disposed = True
            return result
        except BaseException as error:
            if connection is not None and state == "COMMIT_SENT":
                _discard(source, connection)
                disposed = True
                raise AppealPostgresCommitOutcomeUnknownError() from None
            if connection is not None and state in {"BEGUN", "WRITING"}:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    pass
            if connection is not None and not disposed:
                _discard(source, connection)
                disposed = True
            if isinstance(error, AppealPostgresError):
                raise
            translated = _database_error(error)
            if translated is not None:
                raise translated from None
            raise AppealPostgresConfigurationError() from None
        finally:
            if connection is not None and not disposed:
                _discard(source, connection)


class PsycopgAppealReceiptProbe:
    """Authority-first completed receipt lookup with no business mutation."""

    def __init__(
        self,
        *,
        applicant_connections: Any,
        reviewer_connections: Any,
        settings: AppealPostgresGatewaySettings = AppealPostgresGatewaySettings(),
    ) -> None:
        _require_sources(applicant_connections, reviewer_connections)
        if not isinstance(settings, AppealPostgresGatewaySettings):
            raise TypeError("Appeal PostgreSQL gateway settings are unavailable")
        self._applicant_connections = applicant_connections
        self._reviewer_connections = reviewer_connections
        self._settings = settings
        self._closed = False

    def read_completed(
        self, request: AppealCompletedReceiptProbeRequest
    ) -> Optional[AppealCommandResult]:
        _require_type(request, AppealCompletedReceiptProbeRequest)
        if self._closed:
            raise AppealPostgresConfigurationError()
        applicant = request.operation in _APPLICANT_OPERATIONS
        source = (
            self._applicant_connections if applicant else self._reviewer_connections
        )
        role = "trust_self" if applicant else "trust_appeal"
        connection = None
        transaction = False
        disposed = False
        try:
            connection = source.checkout()
            _prepare(connection, role)
            # The fixed receipt reader takes a shared lock on the active key
            # policy so a rotation cannot race a completed-receipt decision.
            # PostgreSQL forbids that lock in a READ ONLY transaction.
            connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED")
            transaction = True
            _configure(
                connection,
                settings=self._settings,
                scope="APPEAL_RECEIPT_READ",
                operation=request.operation,
                actor_id=request.context.actor_user_id,
                session_id=request.context.session_id,
                organization_id=request.organization_id,
                appeal_id=request.target_appeal_id,
            )
            material = request.material
            rows = connection.execute(
                "SELECT safe_response,replayed "
                "FROM trust_api.read_completed_appeal_receipt_v1("
                + ",".join(["%s"] * 10)
                + ")",
                (
                    request.context.actor_user_id,
                    request.context.session_id,
                    request.organization_id,
                    request.operation,
                    request.target_appeal_id,
                    request.expected_appeal_version,
                    list(material.idempotency_key_digest_key_ids),
                    list(material.idempotency_key_digests),
                    list(material.payload_hash_key_ids),
                    list(material.payload_hashes),
                ),
            ).fetchmany(2)
            if not isinstance(rows, list) or len(rows) > 1:
                raise AppealPostgresConfigurationError()
            result = None
            if rows:
                result = _command_result(request.operation, request, rows[0])
                if not result.replayed:
                    raise AppealPostgresConfigurationError()
                if (
                    request.target_appeal_id is not None
                    and result.appeal_id != str(request.target_appeal_id)
                ):
                    raise AppealPostgresConfigurationError()
            connection.execute("COMMIT")
            transaction = False
            _reset(connection)
            source.release(connection)
            disposed = True
            return result
        except BaseException as error:
            if connection is not None and transaction:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    pass
            if connection is not None and not disposed:
                _discard(source, connection)
                disposed = True
            if isinstance(error, AppealPostgresError):
                raise
            translated = _database_error(error)
            if translated is not None:
                raise translated from None
            raise AppealPostgresConfigurationError() from None
        finally:
            if connection is not None and not disposed:
                _discard(source, connection)

    def close(self) -> None:
        self._closed = True


class PsycopgAppealReadGateway:
    """Invoke and strictly parse only the seven authorized Appeal reads."""

    def __init__(
        self,
        *,
        applicant_connections: Any,
        reviewer_connections: Any,
        settings: AppealPostgresGatewaySettings = AppealPostgresGatewaySettings(),
    ) -> None:
        _require_sources(applicant_connections, reviewer_connections)
        if not isinstance(settings, AppealPostgresGatewaySettings):
            raise TypeError("Appeal PostgreSQL gateway settings are unavailable")
        self._applicant_connections = applicant_connections
        self._reviewer_connections = reviewer_connections
        self._settings = settings
        self._closed = False

    def find_own_appeal_by_source(
        self,
        *,
        actor_user_id: UUID,
        session_id: UUID,
        organization_id: UUID,
        source_outcome_version_id: UUID,
    ) -> Optional[AppealOwnProjection]:
        _require_uuids(
            actor_user_id, session_id, organization_id, source_outcome_version_id
        )
        return self._read(
            source=self._applicant_connections,
            role="trust_self",
            scope="APPEAL_OWN_READ",
            operation="FIND_OWN_APPEAL",
            kind="OWN",
            actor_id=actor_user_id,
            session_id=session_id,
            organization_id=organization_id,
            appeal_id=None,
            allow_missing=True,
            statement=(
                "SELECT projection FROM trust_api.find_own_appeal_by_source_v1("
                "%s,%s,%s,%s)"
            ),
            parameters=(
                actor_user_id,
                session_id,
                organization_id,
                source_outcome_version_id,
            ),
        )

    def read_own_appeal(
        self,
        *,
        actor_user_id: UUID,
        session_id: UUID,
        organization_id: UUID,
        appeal_id: UUID,
    ) -> AppealOwnProjection:
        _require_uuids(actor_user_id, session_id, organization_id, appeal_id)
        result = self._read(
            source=self._applicant_connections,
            role="trust_self",
            scope="APPEAL_OWN_READ",
            operation="READ_OWN_APPEAL",
            kind="OWN",
            actor_id=actor_user_id,
            session_id=session_id,
            organization_id=organization_id,
            appeal_id=appeal_id,
            allow_missing=False,
            statement=(
                "SELECT projection FROM trust_api.read_own_appeal_v1("
                "%s,%s,%s,%s)"
            ),
            parameters=(actor_user_id, session_id, organization_id, appeal_id),
        )
        if not isinstance(result, AppealOwnProjection):
            raise AppealPostgresConfigurationError()
        return result

    def list_appeal_queue(
        self, *, actor_user_id: UUID, session_id: UUID, limit: int
    ) -> AppealQueueProjection:
        _require_uuids(actor_user_id, session_id)
        _require_limit(limit)
        result = self._read(
            source=self._reviewer_connections,
            role="trust_appeal",
            scope="APPEAL_QUEUE_READ",
            operation="LIST_APPEAL_QUEUE",
            kind="QUEUE",
            actor_id=actor_user_id,
            session_id=session_id,
            organization_id=None,
            appeal_id=None,
            allow_missing=False,
            statement=(
                "SELECT projection FROM trust_api.list_appeal_queue_v1(%s,%s,%s)"
            ),
            parameters=(actor_user_id, session_id, limit),
        )
        if not isinstance(result, AppealQueueProjection):
            raise AppealPostgresConfigurationError()
        return result

    def list_my_active_appeal_assignments(
        self, *, actor_user_id: UUID, session_id: UUID, limit: int
    ) -> AppealActiveAssignmentsProjection:
        _require_uuids(actor_user_id, session_id)
        _require_limit(limit)
        result = self._read(
            source=self._reviewer_connections,
            role="trust_appeal",
            scope="APPEAL_ACTIVE_ASSIGNMENTS_READ",
            operation="LIST_MY_ACTIVE_APPEAL_ASSIGNMENTS",
            kind="ACTIVE_ASSIGNMENTS",
            actor_id=actor_user_id,
            session_id=session_id,
            organization_id=None,
            appeal_id=None,
            allow_missing=False,
            statement=(
                "SELECT projection FROM "
                "trust_api.list_my_active_appeal_assignments_v1(%s,%s,%s)"
            ),
            parameters=(actor_user_id, session_id, limit),
        )
        if not isinstance(result, AppealActiveAssignmentsProjection):
            raise AppealPostgresConfigurationError()
        return result

    def read_assigned_appeal(
        self, *, actor_user_id: UUID, session_id: UUID, appeal_id: UUID
    ) -> AppealAssignedProjection:
        _require_uuids(actor_user_id, session_id, appeal_id)
        result = self._read(
            source=self._reviewer_connections,
            role="trust_appeal",
            scope="APPEAL_ASSIGNED_READ",
            operation="READ_ASSIGNED_APPEAL",
            kind="ASSIGNED",
            actor_id=actor_user_id,
            session_id=session_id,
            organization_id=None,
            appeal_id=appeal_id,
            allow_missing=False,
            statement=(
                "SELECT projection FROM trust_api.read_assigned_appeal_v1(%s,%s,%s)"
            ),
            parameters=(actor_user_id, session_id, appeal_id),
        )
        if not isinstance(result, AppealAssignedProjection):
            raise AppealPostgresConfigurationError()
        return result

    def list_my_completed_appeal_assignments(
        self, *, actor_user_id: UUID, session_id: UUID, limit: int
    ) -> AppealCompletedAssignmentsProjection:
        _require_uuids(actor_user_id, session_id)
        _require_limit(limit)
        result = self._read(
            source=self._reviewer_connections,
            role="trust_appeal",
            scope="APPEAL_COMPLETED_HISTORY_READ",
            operation="READ_ASSIGNED_APPEAL",
            kind="COMPLETED_ASSIGNMENTS",
            actor_id=actor_user_id,
            session_id=session_id,
            organization_id=None,
            appeal_id=None,
            allow_missing=False,
            statement=(
                "SELECT projection FROM "
                "trust_api.list_my_completed_appeal_reviews_v1(%s,%s,%s)"
            ),
            parameters=(actor_user_id, session_id, limit),
        )
        if not isinstance(result, AppealCompletedAssignmentsProjection):
            raise AppealPostgresConfigurationError()
        return result

    def read_my_completed_appeal(
        self, *, actor_user_id: UUID, session_id: UUID, appeal_id: UUID
    ) -> AppealCompletedDetailProjection:
        _require_uuids(actor_user_id, session_id, appeal_id)
        result = self._read(
            source=self._reviewer_connections,
            role="trust_appeal",
            scope="APPEAL_COMPLETED_DETAIL_READ",
            operation="READ_ASSIGNED_APPEAL",
            kind="COMPLETED_DETAIL",
            actor_id=actor_user_id,
            session_id=session_id,
            organization_id=None,
            appeal_id=appeal_id,
            allow_missing=False,
            statement=(
                "SELECT projection FROM "
                "trust_api.read_my_completed_appeal_review_v1(%s,%s,%s)"
            ),
            parameters=(actor_user_id, session_id, appeal_id),
        )
        if not isinstance(result, AppealCompletedDetailProjection):
            raise AppealPostgresConfigurationError()
        return result

    def close(self) -> None:
        self._closed = True

    def _read(
        self,
        *,
        source: Any,
        role: str,
        scope: str,
        operation: str,
        kind: str,
        actor_id: UUID,
        session_id: UUID,
        organization_id: Optional[UUID],
        appeal_id: Optional[UUID],
        allow_missing: bool,
        statement: str,
        parameters: tuple[Any, ...],
    ) -> Any:
        if self._closed:
            raise AppealPostgresConfigurationError()
        connection = None
        transaction = False
        disposed = False
        try:
            connection = source.checkout()
            _prepare(connection, role)
            connection.execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
            transaction = True
            _configure(
                connection,
                settings=self._settings,
                scope=scope,
                operation=operation,
                actor_id=actor_id,
                session_id=session_id,
                organization_id=organization_id,
                appeal_id=appeal_id,
            )
            rows = connection.execute(statement, parameters).fetchmany(2)
            if not isinstance(rows, list) or len(rows) > 1:
                raise AppealPostgresConfigurationError()
            if not rows:
                if allow_missing:
                    result = None
                else:
                    raise AppealPostgresRejectedError("APPEAL_NOT_FOUND")
            else:
                result = _projection(kind, rows[0])
            connection.execute("COMMIT")
            transaction = False
            _reset(connection)
            source.release(connection)
            disposed = True
            return result
        except BaseException as error:
            if connection is not None and transaction:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    pass
            if connection is not None and not disposed:
                _discard(source, connection)
                disposed = True
            if isinstance(error, AppealPostgresError):
                raise
            translated = _database_error(error)
            if translated is not None:
                raise translated from None
            raise AppealPostgresConfigurationError() from None
        finally:
            if connection is not None and not disposed:
                _discard(source, connection)


class PsycopgAppealRestrictedTextStore:
    """Persist one encrypted Appeal text envelope through the fixed ABI."""

    def __init__(
        self,
        *,
        applicant_connections: Any,
        reviewer_connections: Any,
        settings: AppealPostgresGatewaySettings = AppealPostgresGatewaySettings(),
    ) -> None:
        _require_sources(applicant_connections, reviewer_connections)
        if not isinstance(settings, AppealPostgresGatewaySettings):
            raise TypeError("Appeal PostgreSQL gateway settings are unavailable")
        self._applicant_connections = applicant_connections
        self._reviewer_connections = reviewer_connections
        self._settings = settings
        self._closed = False

    def store(self, request: AppealRestrictedTextStoreRequest) -> AppealSealedText:
        _require_type(request, AppealRestrictedTextStoreRequest)
        if self._closed:
            raise AppealPostgresConfigurationError()
        applicant = request.purpose_code == "APPEAL_STATEMENT"
        source = (
            self._applicant_connections if applicant else self._reviewer_connections
        )
        role = "trust_self" if applicant else "trust_appeal"
        connection = None
        state = "NEW"
        disposed = False
        try:
            connection = source.checkout()
            _prepare(connection, role)
            connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED")
            state = "BEGUN"
            _configure(
                connection,
                settings=self._settings,
                scope="APPEAL_SEALED_TEXT",
                operation=(
                    "SAVE_APPEAL_DRAFT" if applicant else "SAVE_APPEAL_REVIEW_DRAFT"
                ),
                actor_id=request.actor_user_id,
                session_id=request.session_id,
                organization_id=request.organization_id,
                appeal_id=request.appeal_id,
            )
            material = request.replay_material
            parameters = (
                request.actor_user_id,
                request.session_id,
                request.organization_id,
                request.appeal_id,
                request.purpose_code,
                list(request.encryption_key_ids),
                list(request.candidate_references),
                list(request.plaintext_hmac_sha256s),
                request.envelope_sha256,
                request.encryption_key_id,
                request.nonce,
                request.ciphertext,
                request.aad_sha256,
                list(material.idempotency_key_digest_key_ids),
                list(material.idempotency_key_digests),
                request.retention_class,
                request.retain_until,
                request.duty_grant_id,
                request.duty_grant_version,
            )
            state = "WRITING"
            row = connection.execute(
                "SELECT * FROM trust_api.store_appeal_restricted_text_v1("
                + ",".join(["%s"] * 19)
                + ")",
                parameters,
            ).fetchone()
            result = _sealed_result(row, request)
            state = "COMMIT_SENT"
            connection.execute("COMMIT")
            state = "COMMITTED"
            _reset(connection)
            source.release(connection)
            disposed = True
            return result
        except BaseException as error:
            if connection is not None and state == "COMMIT_SENT":
                _discard(source, connection)
                disposed = True
                raise AppealPostgresCommitOutcomeUnknownError() from None
            if connection is not None and state in {"BEGUN", "WRITING"}:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    pass
            if connection is not None and not disposed:
                _discard(source, connection)
                disposed = True
            if isinstance(error, AppealPostgresError):
                raise
            translated = _database_error(error)
            if translated is not None:
                raise translated from None
            raise AppealPostgresConfigurationError() from None
        finally:
            if connection is not None and not disposed:
                _discard(source, connection)

    def close(self) -> None:
        self._closed = True


def _receipt_parameters(material: Any) -> tuple[Any, ...]:
    return (
        list(material.idempotency_key_digest_key_ids),
        list(material.idempotency_key_digests),
        list(material.payload_hash_key_ids),
        list(material.payload_hashes),
    )


def _command_result(operation: str, request: Any, row: Any) -> AppealCommandResult:
    if (
        not isinstance(row, tuple)
        or len(row) != 2
        or not isinstance(row[0], Mapping)
        or type(row[1]) is not bool
    ):
        raise AppealPostgresConfigurationError()
    safe, replayed = row
    if set(safe) != _SAFE_RESULT_KEYS:
        raise AppealPostgresConfigurationError()
    appeal_id = _uuid_text(safe["appeal_id"])
    decision_id = _optional_uuid_text(safe["decision_version_id"])
    try:
        status = AppealStatus(safe["appeal_status"])
    except (TypeError, ValueError):
        raise AppealPostgresConfigurationError() from None
    aggregate_version = safe["aggregate_version"]
    versions: dict[str, Optional[int]] = {}
    for name in (
        "application_draft_version",
        "application_version",
        "review_draft_version",
    ):
        value = safe[name]
        if value is not None and (type(value) is not int or value < 1):
            raise AppealPostgresConfigurationError()
        versions[name] = value
    events = safe["event_types"]
    completed = _timestamp(safe["completed_at"])
    if (
        appeal_id is None
        or type(aggregate_version) is not int
        or aggregate_version < 1
        or not isinstance(events, list)
        or events != [_EVENT_TYPES[operation]]
        or completed is None
    ):
        raise AppealPostgresConfigurationError()
    generated_appeal = getattr(request, "appeal_id", None)
    if (
        not replayed
        and isinstance(generated_appeal, UUID)
        and appeal_id != str(generated_appeal)
    ):
        raise AppealPostgresConfigurationError()
    generated_decision = getattr(request, "decision_version_id", None)
    if (
        not replayed
        and isinstance(generated_decision, UUID)
        and decision_id != str(generated_decision)
    ):
        raise AppealPostgresConfigurationError()
    if operation == "DECIDE_APPEAL" and decision_id is None:
        raise AppealPostgresConfigurationError()
    if operation != "DECIDE_APPEAL" and decision_id is not None:
        raise AppealPostgresConfigurationError()
    return AppealCommandResult(
        appeal_id=appeal_id,
        appeal_status=status,
        aggregate_version=aggregate_version,
        application_draft_version=versions["application_draft_version"],
        application_version=versions["application_version"],
        review_draft_version=versions["review_draft_version"],
        decision_version_id=decision_id,
        replayed=replayed,
        event_types=tuple(events),
        completed_at=completed,
    )


def _projection(kind: str, row: Any) -> Any:
    if not isinstance(row, tuple) or len(row) != 1 or not isinstance(row[0], Mapping):
        raise AppealPostgresConfigurationError()
    try:
        document = dict(row[0])
        if kind == "OWN":
            return _own_projection(document)
        if kind == "QUEUE":
            _exact_keys(document, {"entity_tag", "items"})
            items = document["items"]
            if not isinstance(items, list):
                raise ValueError
            return AppealQueueProjection(
                items=tuple(_queue_item(value) for value in items),
                entity_tag=document["entity_tag"],
            )
        if kind == "ACTIVE_ASSIGNMENTS":
            _exact_keys(document, {"entity_tag", "items"})
            items = document["items"]
            if not isinstance(items, list):
                raise ValueError
            return AppealActiveAssignmentsProjection(
                items=tuple(_active_assignment_item(value) for value in items),
                entity_tag=document["entity_tag"],
            )
        if kind == "ASSIGNED":
            _exact_keys(
                document,
                {
                    "appeal",
                    "application",
                    "assignment_expires_at",
                    "entity_tag",
                    "review_draft",
                    "source",
                },
            )
            return AppealAssignedProjection(
                appeal=_own_projection(document["appeal"]),
                source=_source_projection(document["source"]),
                application=_application_projection(document["application"]),
                review_draft=(
                    None
                    if document["review_draft"] is None
                    else _review_draft_projection(document["review_draft"])
                ),
                assignment_expires_at=_required_timestamp(
                    document["assignment_expires_at"]
                ),
                entity_tag=document["entity_tag"],
            )
        if kind == "COMPLETED_ASSIGNMENTS":
            _exact_keys(document, {"entity_tag", "has_more", "items"})
            items = document["items"]
            if not isinstance(items, list):
                raise ValueError
            return AppealCompletedAssignmentsProjection(
                items=tuple(_completed_assignment_item(value) for value in items),
                has_more=document["has_more"],
                entity_tag=document["entity_tag"],
            )
        if kind == "COMPLETED_DETAIL":
            _exact_keys(
                document,
                {
                    "appeal_id",
                    "application",
                    "decision",
                    "entity_tag",
                    "review_note_recorded",
                    "status",
                },
            )
            return AppealCompletedDetailProjection(
                appeal_id=document["appeal_id"],
                status=document["status"],
                application=_application_projection(document["application"]),
                decision=_decision_projection(document["decision"]),
                review_note_recorded=document["review_note_recorded"],
                entity_tag=document["entity_tag"],
            )
    except (KeyError, TypeError, ValueError, AttributeError):
        raise AppealPostgresConfigurationError() from None
    raise AppealPostgresConfigurationError()


def _own_projection(value: Any) -> AppealOwnProjection:
    _exact_keys(
        value,
        {
            "aggregate_version",
            "appeal_id",
            "application",
            "application_draft",
            "decision",
            "entity_tag",
            "source",
            "source_case_id",
            "source_outcome_version_id",
            "status",
        },
    )
    return AppealOwnProjection(
        appeal_id=value["appeal_id"],
        source_outcome_version_id=value["source_outcome_version_id"],
        source_case_id=value["source_case_id"],
        source=_source_projection(value["source"]),
        status=value["status"],
        aggregate_version=value["aggregate_version"],
        application_draft=(
            None
            if value["application_draft"] is None
            else _application_draft_projection(value["application_draft"])
        ),
        application=(
            None
            if value["application"] is None
            else _application_projection(value["application"])
        ),
        decision=(
            None
            if value["decision"] is None
            else _decision_projection(value["decision"])
        ),
        entity_tag=value["entity_tag"],
    )


def _source_projection(value: Any) -> AppealSourceProjection:
    _exact_keys(
        value,
        {
            "action_codes",
            "appeal_deadline",
            "appeal_eligibility_code",
            "appeal_eligible",
            "case_id",
            "content_sha256",
            "decided_at",
            "demand_id",
            "demand_version_id",
            "evidence_packet_sha256",
            "evidence_packet_version_id",
            "outcome_code",
            "outcome_version_id",
            "policy_version",
            "reason_codes",
        },
    )
    return AppealSourceProjection(
        outcome_version_id=value["outcome_version_id"],
        case_id=value["case_id"],
        demand_id=value["demand_id"],
        demand_version_id=value["demand_version_id"],
        outcome_code=value["outcome_code"],
        reason_codes=_string_tuple(value["reason_codes"]),
        action_codes=_string_tuple(value["action_codes"]),
        evidence_packet_version_id=value["evidence_packet_version_id"],
        evidence_packet_sha256=value["evidence_packet_sha256"],
        policy_version=value["policy_version"],
        decided_at=_required_timestamp(value["decided_at"]),
        appeal_eligible=value["appeal_eligible"],
        appeal_eligibility_code=value["appeal_eligibility_code"],
        appeal_deadline=_required_timestamp(value["appeal_deadline"]),
        content_sha256=value["content_sha256"],
    )


def _application_draft_projection(value: Any) -> AppealApplicationDraftProjection:
    _exact_keys(
        value,
        {
            "edited_at",
            "grounds",
            "new_evidence_reference_ids",
            "requested_outcome",
            "statement_recorded",
            "version",
        },
    )
    return AppealApplicationDraftProjection(
        version=value["version"],
        grounds=_string_tuple(value["grounds"]),
        requested_outcome=value["requested_outcome"],
        statement_recorded=value["statement_recorded"],
        new_evidence_reference_ids=_string_tuple(value["new_evidence_reference_ids"]),
        edited_at=_required_timestamp(value["edited_at"]),
    )


def _application_projection(value: Any) -> AppealSubmittedApplicationProjection:
    _exact_keys(
        value,
        {
            "grounds",
            "new_evidence_reference_ids",
            "requested_outcome",
            "statement_recorded",
            "submitted_at",
        },
    )
    return AppealSubmittedApplicationProjection(
        grounds=_string_tuple(value["grounds"]),
        requested_outcome=value["requested_outcome"],
        statement_recorded=value["statement_recorded"],
        new_evidence_reference_ids=_string_tuple(value["new_evidence_reference_ids"]),
        submitted_at=_required_timestamp(value["submitted_at"]),
    )


def _assessment_projection(value: Any) -> AppealAssessmentProjection:
    _exact_keys(
        value,
        {
            "accepted_evidence_reference_ids",
            "assessment_code",
            "finding_codes",
            "ground",
        },
    )
    return AppealAssessmentProjection(
        ground=value["ground"],
        assessment_code=value["assessment_code"],
        finding_codes=_string_tuple(value["finding_codes"]),
        accepted_evidence_reference_ids=_string_tuple(
            value["accepted_evidence_reference_ids"]
        ),
    )


def _decision_projection(value: Any) -> AppealDecisionProjection:
    _exact_keys(
        value,
        {
            "assessments",
            "decided_at",
            "decision_code",
            "decision_sha256",
            "decision_version_id",
            "policy_version",
            "reason_codes",
            "remedy_delta_codes",
        },
    )
    assessments = value["assessments"]
    if not isinstance(assessments, list):
        raise ValueError
    return AppealDecisionProjection(
        decision_version_id=value["decision_version_id"],
        decision_code=value["decision_code"],
        assessments=tuple(_assessment_projection(item) for item in assessments),
        reason_codes=_string_tuple(value["reason_codes"]),
        remedy_delta_codes=_string_tuple(value["remedy_delta_codes"]),
        policy_version=value["policy_version"],
        decided_at=_required_timestamp(value["decided_at"]),
        decision_sha256=value["decision_sha256"],
    )


def _queue_item(value: Any) -> AppealQueueItem:
    _exact_keys(
        value,
        {
            "appeal_id",
            "entity_tag",
            "grounds",
            "requested_outcome",
            "source_case_id",
            "source_outcome_version_id",
            "submitted_at",
        },
    )
    return AppealQueueItem(
        appeal_id=value["appeal_id"],
        source_outcome_version_id=value["source_outcome_version_id"],
        source_case_id=value["source_case_id"],
        grounds=_string_tuple(value["grounds"]),
        requested_outcome=value["requested_outcome"],
        submitted_at=_required_timestamp(value["submitted_at"]),
        entity_tag=value["entity_tag"],
    )


def _active_assignment_item(value: Any) -> AppealActiveAssignmentItem:
    _exact_keys(value, {"appeal_id", "assignment_expires_at"})
    return AppealActiveAssignmentItem(
        appeal_id=value["appeal_id"],
        assignment_expires_at=_required_timestamp(
            value["assignment_expires_at"]
        ),
    )


def _completed_assignment_item(value: Any) -> AppealCompletedAssignmentItem:
    _exact_keys(value, {"appeal_id", "decided_at", "decision_code"})
    return AppealCompletedAssignmentItem(
        appeal_id=value["appeal_id"],
        decided_at=_required_timestamp(value["decided_at"]),
        decision_code=value["decision_code"],
    )


def _review_draft_projection(value: Any) -> AppealReviewDraftProjection:
    _exact_keys(
        value,
        {
            "assessments",
            "edited_at",
            "reason_codes",
            "remedy_delta_codes",
            "review_note_recorded",
            "version",
        },
    )
    assessments = value["assessments"]
    if not isinstance(assessments, list):
        raise ValueError
    return AppealReviewDraftProjection(
        version=value["version"],
        assessments=tuple(_assessment_projection(item) for item in assessments),
        reason_codes=_string_tuple(value["reason_codes"]),
        remedy_delta_codes=_string_tuple(value["remedy_delta_codes"]),
        review_note_recorded=value["review_note_recorded"],
        edited_at=_required_timestamp(value["edited_at"]),
    )


def _sealed_result(
    row: Any, request: AppealRestrictedTextStoreRequest
) -> AppealSealedText:
    if not isinstance(row, tuple) or len(row) != 5 or type(row[4]) is not bool:
        raise AppealPostgresConfigurationError()
    reference, digest, retention, sealed_at, replayed = row
    try:
        candidate_index = request.candidate_references.index(reference)
    except (TypeError, ValueError):
        raise AppealPostgresConfigurationError() from None
    if (
        not _digest(digest)
        or (
            not replayed
            and (
                candidate_index != 0
                or not hmac.compare_digest(digest, request.envelope_sha256)
            )
        )
        or retention != request.retention_class
        or not isinstance(sealed_at, datetime)
        or sealed_at.tzinfo is None
        or sealed_at.utcoffset() is None
        or sealed_at.astimezone(timezone.utc) > datetime.now(timezone.utc)
    ):
        raise AppealPostgresConfigurationError()
    return AppealSealedText(
        sealed_reference=reference,
        sealed_sha256=digest.hex(),
        retention_class=retention,
        sealed_at=sealed_at.astimezone(timezone.utc),
    )


def _prepare(connection: Any, role: str) -> None:
    _reset(connection)
    row = connection.execute(
        "SELECT session_user,current_user,"
        "current_setting('server_version_num')::integer/10000,"
        "component,current_schema_version,schema_head_version,"
        "min_app_compatible_version,max_app_compatible_version,"
        "required_iam_schema_version,required_demand_schema_version "
        "FROM trust.schema_compatibility"
    ).fetchone()
    expected = (
        role,
        role,
        18,
        "trust",
        TRUST_SCHEMA_HEAD_VERSION,
        TRUST_SCHEMA_HEAD_VERSION,
        TRUST_SCHEMA_HEAD_VERSION,
        TRUST_SCHEMA_HEAD_VERSION,
        TRUST_REQUIRED_IAM_SCHEMA_VERSION,
        TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
    )
    if row != expected:
        raise AppealPostgresConfigurationError()


def _configure(
    connection: Any,
    *,
    settings: AppealPostgresGatewaySettings,
    scope: str,
    operation: str,
    actor_id: UUID,
    session_id: UUID,
    organization_id: Optional[UUID],
    appeal_id: Optional[UUID],
) -> None:
    values = (
        ("TimeZone", "UTC"),
        ("lock_timeout", f"{settings.lock_timeout_ms}ms"),
        ("statement_timeout", f"{settings.statement_timeout_ms}ms"),
        (
            "idle_in_transaction_session_timeout",
            f"{settings.idle_in_transaction_timeout_ms}ms",
        ),
        ("app.scope_kind", scope),
        ("app.appeal_scope_kind", scope),
        ("app.operation", operation),
        ("app.actor_id", str(actor_id)),
        ("app.session_id", str(session_id)),
        ("app.organization_id", "" if organization_id is None else str(organization_id)),
        ("app.appeal_id", "" if appeal_id is None else str(appeal_id)),
        ("app.case_id", ""),
        ("app.demand_id", ""),
    )
    for name, value in values:
        row = connection.execute(
            "SELECT pg_catalog.set_config(%s,%s,true)", (name, value)
        ).fetchone()
        if not set_config_result_matches(
            name=name,
            requested_value=value,
            row=row,
        ):
            raise AppealPostgresConfigurationError()


def _reset(connection: Any) -> None:
    if (
        getattr(connection, "autocommit", None) is not True
        or getattr(getattr(connection, "info", None), "transaction_status", None)
        != TransactionStatus.IDLE
    ):
        raise AppealPostgresConfigurationError()
    connection.execute("RESET ROLE")
    connection.execute("RESET ALL")
    connection.execute("CLOSE ALL")
    connection.execute("DISCARD TEMP")


def _discard(source: Any, connection: Any) -> None:
    try:
        source.discard(connection)
    except BaseException:
        pass


def _database_error(error: BaseException) -> Optional[AppealPostgresRejectedError]:
    message = getattr(getattr(error, "diag", None), "message_primary", None)
    if not isinstance(message, str):
        message = str(error) if isinstance(error, Exception) else ""
    codes = {
        "ACCESS_DENIED",
        "APPEAL_ALREADY_ASSIGNED",
        "APPEAL_ALREADY_EXISTS",
        "APPEAL_APPLICATION_FROZEN",
        "APPEAL_APPLICATION_DRAFT_REQUIRED",
        "APPEAL_APPLICATION_INVALID",
        "APPEAL_ASSIGNMENT_NOT_EXPIRED",
        "APPEAL_ASSIGNMENT_RELEASE_INVALID",
        "APPEAL_ASSIGNMENT_REQUIRED",
        "APPEAL_DECISION_INVALID",
        "APPEAL_DEADLINE_PASSED",
        "APPEAL_DRAFT_VERSION_CONFLICT",
        "APPEAL_NOT_AVAILABLE",
        "APPEAL_NOT_FOUND",
        "APPEAL_REVIEW_INVALID",
        "APPEAL_STATE_CONFLICT",
        "AUTHENTICATION_REQUIRED",
        "COMMAND_IN_PROGRESS",
        "COMMAND_OUTCOME_UNKNOWN",
        "CONFLICT_OF_INTEREST",
        "IDEMPOTENCY_KEY_REUSED",
        "INVALID_REQUEST",
        "POLICY_ACCEPTANCE_REQUIRED",
        "PRECONDITION_FAILED",
        "RESOURCE_NOT_FOUND",
        "SESSION_EXPIRED",
    }
    if message in codes:
        return AppealPostgresRejectedError(message)
    if getattr(error, "sqlstate", None) in {"40001", "40P01", "55P03"}:
        return AppealPostgresRejectedError("PRECONDITION_FAILED")
    return None


def _require_sources(first: Any, second: Any) -> None:
    if first is second:
        raise TypeError("Appeal PostgreSQL roles must be isolated")
    for source in (first, second):
        if not all(
            callable(getattr(source, name, None))
            for name in ("checkout", "release", "discard")
        ):
            raise TypeError("Appeal PostgreSQL connection source is unavailable")


def _require_request(context: Any, receipt: Any) -> None:
    if not isinstance(context, AppealPostgresCommandContext) or not isinstance(
        receipt, AppealPostgresReceiptMaterial
    ):
        raise TypeError("Appeal PostgreSQL request dependencies are unavailable")


def _require_type(value: Any, expected: type) -> None:
    if type(value) is not expected:
        raise TypeError("Appeal PostgreSQL request type is invalid")


def _require_uuids(*values: Any) -> None:
    if any(not isinstance(value, UUID) or value.int == 0 for value in values):
        raise ValueError("Appeal PostgreSQL identifier is invalid")


def _require_version(value: Any) -> None:
    if type(value) is not int or value < 1:
        raise ValueError("Appeal PostgreSQL version is invalid")


def _require_limit(value: Any) -> None:
    if type(value) is not int or not 1 <= value <= 100:
        raise ValueError("Appeal PostgreSQL read limit is invalid")


def _require_enum(value: Any, allowed: frozenset[str]) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError("Appeal PostgreSQL code is invalid")


def _require_codes(
    values: Any, allowed: frozenset[str], minimum: int, maximum: int
) -> None:
    if (
        type(values) is not tuple
        or not minimum <= len(values) <= maximum
        or len(set(values)) != len(values)
        or tuple(sorted(values)) != values
        or any(not isinstance(value, str) or value not in allowed for value in values)
    ):
        raise ValueError("Appeal PostgreSQL code array is invalid")


def _require_uuid_tuple(values: Any, minimum: int, maximum: int) -> None:
    if (
        type(values) is not tuple
        or not minimum <= len(values) <= maximum
        or len(set(values)) != len(values)
        or tuple(sorted(values, key=str)) != values
    ):
        raise ValueError("Appeal PostgreSQL identifier array is invalid")
    _require_uuids(*values)


def _require_key_material(key_ids: Any, digests: Any) -> None:
    if (
        type(key_ids) is not tuple
        or type(digests) is not tuple
        or not 1 <= len(key_ids) <= 4
        or len(key_ids) != len(digests)
        or len(set(key_ids)) != len(key_ids)
        or any(not _valid_key_id(value) for value in key_ids)
        or any(not _digest(value) for value in digests)
    ):
        raise ValueError("Appeal PostgreSQL key material is invalid")


def _require_sealed(reference: Any, digest: Any) -> None:
    if (
        not isinstance(reference, str)
        or _SEALED_REFERENCE.fullmatch(reference) is None
        or not _digest(digest)
    ):
        raise ValueError("Appeal PostgreSQL sealed reference is invalid")


def _require_utc(value: Any) -> None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timezone.utc.utcoffset(value)
    ):
        raise ValueError("Appeal PostgreSQL timestamp is invalid")


def _timestamp(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, str):
        try:
            result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if result.tzinfo is None or result.utcoffset() is None:
        return None
    return result.astimezone(timezone.utc)


def _required_timestamp(value: Any) -> datetime:
    result = _timestamp(value)
    if result is None:
        raise ValueError("Appeal projection timestamp is invalid")
    return result


def _uuid_text(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    try:
        result = UUID(value)
    except ValueError:
        return None
    return value if result.int != 0 and str(result) == value else None


def _optional_uuid_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    result = _uuid_text(value)
    if result is None:
        raise AppealPostgresConfigurationError()
    return result


def _exact_keys(value: Any, keys: set[str]) -> None:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ValueError("Appeal projection shape is invalid")


def _string_tuple(value: Any) -> Tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError("Appeal projection array is invalid")
    return tuple(value)


def _valid_key_id(value: Any) -> bool:
    return isinstance(value, str) and _KEY_ID.fullmatch(value) is not None


def _digest(value: Any) -> bool:
    return isinstance(value, bytes) and len(value) == 32


__all__ = [
    "AppealCompletedReceiptProbeRequest",
    "AppealPostgresCommandContext",
    "AppealPostgresCommitOutcomeUnknownError",
    "AppealPostgresConfigurationError",
    "AppealPostgresError",
    "AppealPostgresGatewaySettings",
    "AppealPostgresReceiptMaterial",
    "AppealPostgresRejectedError",
    "AppealPostgresReplayMaterial",
    "AppealRestrictedTextStoreRequest",
    "AppealReviewAssessmentPostgres",
    "ClaimAppealPostgresRequest",
    "DecideAppealPostgresRequest",
    "OpenAppealPostgresRequest",
    "PsycopgAppealCommandGateway",
    "PsycopgAppealReadGateway",
    "PsycopgAppealReceiptProbe",
    "PsycopgAppealRestrictedTextStore",
    "ReleaseAppealAssignmentPostgresRequest",
    "SaveAppealDraftPostgresRequest",
    "SaveAppealReviewDraftPostgresRequest",
    "SubmitAppealPostgresRequest",
]
