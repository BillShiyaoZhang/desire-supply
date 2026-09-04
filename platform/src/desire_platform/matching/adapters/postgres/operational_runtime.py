"""Least-privilege PostgreSQL gateways for Matching v3 operations.

Each gateway owns exactly one production role.  The public API may construct
the assignment and review gateways; worker and coordinator gateways belong to
the dedicated Matching process.  Writes are never retried after COMMIT is sent
and an uncertain outcome is surfaced as ``COMMAND_OUTCOME_UNKNOWN``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import hmac
import json
import re
from typing import Any, Callable, Mapping, Optional, Protocol, Sequence, Tuple
from uuid import UUID, uuid4, uuid5

from psycopg.pq import TransactionStatus
from psycopg.types.json import Jsonb

from desire_platform.matching.application.commands import MatchingCommandResult
from desire_platform.matching.domain import (
    InvitationDisclosureSnapshot,
    MatchingDomainError,
    validate_invitation_disclosure,
)
from desire_platform.matching.engine_v1 import (
    DeterministicMatchResultV1,
    DeterministicMatcherV1Error,
    LoadedMatchingRuleReleaseV1,
    MatchRunInputV1,
    compose_match_run_input_v1,
    demand_postgres_snapshot_to_input_v1,
    evaluate_match_run_v1,
    load_rule_release_v1,
)
from desire_platform.utc import parse_utc_timestamp

from .runtime import (
    MatchingPostgresCommitOutcomeUnknownError,
    MatchingPostgresConfigurationError,
    MatchingPostgresConnectionSource,
    MatchingPostgresError,
    MatchingPostgresRejectedError,
)


_ZERO_UUID = UUID(int=0)
_KEY_ID = re.compile(r"[a-z0-9][a-z0-9-]{2,127}\Z")
_CODE = re.compile(r"[A-Z][A-Z0-9_]{1,63}\Z")
_REVIEW_PURPOSES = frozenset(
    {"MATCH_RETRY", "INVITATION_REVIEW", "ATTEMPT_REVIEW"}
)
_ASSIGNMENT_STATUSES = frozenset({"ACTIVE", "REVOKED", "EXPIRED"})
_INVITATION_STATUSES = frozenset(
    {"CREATED", "SENT", "ACCEPTED", "DECLINED", "WITHDRAWN", "EXPIRED", "REVOKED"}
)
MATCHING_OPERATIONAL_WORKLOAD_ID = UUID(
    "48000000-0000-4000-8000-000000000001"
)
MATCHING_OPERATIONAL_AUTHORITY_MARKER_SHA256 = hashlib.sha256(
    b"exact-demand-match-request-allowlist"
).digest()
_OPERATIONAL_ID_NAMESPACE = UUID("67d22f44-609b-4be8-bd1e-f7f90ee6d7e1")


@dataclass(frozen=True)
class MatchingOperationalPostgresSettings:
    required_server_major: int = 18
    lock_timeout_ms: int = 2_000
    statement_timeout_ms: int = 15_000
    idle_in_transaction_timeout_ms: int = 20_000

    def __post_init__(self) -> None:
        if self.required_server_major != 18:
            raise ValueError("Matching PostgreSQL major must be 18")
        for value, upper in (
            (self.lock_timeout_ms, 10_000),
            (self.statement_timeout_ms, 30_000),
            (self.idle_in_transaction_timeout_ms, 30_000),
        ):
            if type(value) is not int or not 1 <= value <= upper:
                raise ValueError("Matching PostgreSQL timeout is invalid")


@dataclass(frozen=True)
class MatchingReviewContext:
    actor_user_id: UUID
    session_id: UUID = field(repr=False)
    principal_marker_sha256: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _require_uuid(self.actor_user_id, self.session_id)
        _require_digest(self.principal_marker_sha256)


@dataclass(frozen=True)
class MatchingAssignmentContext:
    actor_user_id: UUID
    session_id: UUID = field(repr=False)
    organization_id: UUID
    principal_marker_sha256: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _require_uuid(self.actor_user_id, self.session_id, self.organization_id)
        _require_digest(self.principal_marker_sha256)


@dataclass(frozen=True)
class MatchingWorkloadContext:
    workload_id: UUID
    authority_marker_sha256: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _require_uuid(self.workload_id)
        _require_digest(self.authority_marker_sha256)


@dataclass(frozen=True)
class MatchingOperationalCommandMaterial:
    command_id: UUID
    receipt_id: UUID
    identity_key_id: str
    identity_digest: bytes = field(repr=False)
    payload_hash_key_id: str
    payload_hash: bytes = field(repr=False)
    audit_event_id: UUID
    outbox_event_ids: Tuple[UUID, ...]
    correlation_id: UUID
    trace_id: UUID

    def __post_init__(self) -> None:
        _require_uuid(
            self.command_id,
            self.receipt_id,
            self.audit_event_id,
            self.correlation_id,
            self.trace_id,
        )
        if not isinstance(self.outbox_event_ids, tuple):
            raise TypeError("Matching outbox identifiers must be a tuple")
        _require_uuid(*self.outbox_event_ids)
        identifiers = (
            self.command_id,
            self.receipt_id,
            self.audit_event_id,
            *self.outbox_event_ids,
        )
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("Matching command identifiers must be distinct")
        _require_key(self.identity_key_id)
        _require_key(self.payload_hash_key_id)
        if self.identity_key_id == self.payload_hash_key_id:
            raise ValueError("Matching command keys must be purpose-separated")
        _require_digest(self.identity_digest)
        _require_digest(self.payload_hash)


@dataclass(frozen=True)
class MatchingTrustEvidence:
    evidence_id: UUID
    evidence_sha256: bytes = field(repr=False)
    evaluated_at: datetime
    valid_until: datetime

    def __post_init__(self) -> None:
        _require_uuid(self.evidence_id)
        _require_digest(self.evidence_sha256)
        if (
            not _aware_utc(self.evaluated_at)
            or not _aware_utc(self.valid_until)
            or self.valid_until <= self.evaluated_at
        ):
            raise ValueError("Matching Trust evidence window is invalid")


@dataclass(frozen=True)
class MatchingCandidateSelectorClaimRequest:
    context: MatchingAssignmentContext
    demand_id: UUID
    assignment_id: UUID
    material: MatchingOperationalCommandMaterial = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.context, MatchingAssignmentContext):
            raise TypeError("Matching assignment context is unavailable")
        if not isinstance(self.material, MatchingOperationalCommandMaterial):
            raise TypeError("Matching command material is unavailable")
        _require_uuid(self.demand_id, self.assignment_id)
        _require_outboxes(self.material, 1)


@dataclass(frozen=True)
class MatchingCandidateSelectorClaimResult:
    assignment_id: UUID
    assignment_version: int
    selection_id: UUID
    attempt_id: UUID
    demand_id: UUID
    status: str
    expires_at: datetime
    selection_status: str
    selection_version: int
    current_invitation_set_sha256: bytes = field(repr=False)
    replayed: bool

    def __post_init__(self) -> None:
        _require_uuid(
            self.assignment_id,
            self.selection_id,
            self.attempt_id,
            self.demand_id,
        )
        _require_version(self.assignment_version, self.selection_version)
        _require_digest(self.current_invitation_set_sha256)
        if (
            self.status != "ACTIVE"
            or self.selection_status not in {"OPEN", "PENDING_CHOICE", "PENDING_CLOSE"}
            or not _aware_utc(self.expires_at)
            or type(self.replayed) is not bool
        ):
            raise ValueError("Candidate Selector claim projection is invalid")


@dataclass(frozen=True)
class MatchingReviewClaimRequest:
    context: MatchingReviewContext
    assignment_id: UUID
    material: MatchingOperationalCommandMaterial = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.context, MatchingReviewContext):
            raise TypeError("Matching review context is unavailable")
        if not isinstance(self.material, MatchingOperationalCommandMaterial):
            raise TypeError("Matching command material is unavailable")
        _require_uuid(self.assignment_id)
        _require_outboxes(self.material, 1)


@dataclass(frozen=True)
class MatchingReviewAssignmentSummary:
    assignment_id: UUID
    organization_id: UUID
    attempt_id: UUID
    match_run_id: UUID
    purpose_code: str
    role_code: str
    status: str
    aggregate_version: int
    expires_at: datetime
    replayed: bool = False

    def __post_init__(self) -> None:
        _require_uuid(
            self.assignment_id,
            self.organization_id,
            self.attempt_id,
            self.match_run_id,
        )
        _require_version(self.aggregate_version)
        if (
            self.purpose_code not in _REVIEW_PURPOSES
            or self.role_code != "MATCHING_REVIEWER"
            or self.status not in _ASSIGNMENT_STATUSES
            or not _aware_utc(self.expires_at)
            or type(self.replayed) is not bool
        ):
            raise ValueError("Matching review assignment is invalid")


@dataclass(frozen=True)
class MatchingReviewAttemptView:
    attempt_no: int
    status: str
    aggregate_version: int
    updated_at: datetime
    demand_id: UUID
    demand_version_id: UUID
    demand_aggregate_version: int
    demand_content_sha256: bytes = field(repr=False)
    input_baseline_sha256: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _require_uuid(self.demand_id, self.demand_version_id)
        _require_version(
            self.attempt_no,
            self.aggregate_version,
            self.demand_aggregate_version,
        )
        _require_digest(self.demand_content_sha256)
        _require_digest(self.input_baseline_sha256)
        if self.status not in {
            "OPEN",
            "SELECTED",
            "CLOSED_NO_SELECTION",
            "INVALIDATED",
            "CANCELLED",
        } or not _aware_utc(self.updated_at):
            raise ValueError("Matching review attempt projection is invalid")


@dataclass(frozen=True)
class MatchingReviewRunView:
    status: str
    aggregate_version: int
    ordered_result_sha256: Optional[bytes] = field(repr=False)
    candidate_count: Optional[int]
    eligible_count: Optional[int]
    excluded_count: Optional[int]
    failure_code: Optional[str]

    def __post_init__(self) -> None:
        _require_version(self.aggregate_version)
        if self.status not in {
            "QUEUED",
            "RUNNING",
            "COMPLETED",
            "FAILED",
            "SUPERSEDED",
            "CANCELLED",
        }:
            raise ValueError("Matching review run status is invalid")
        counts = (self.candidate_count, self.eligible_count, self.excluded_count)
        if any(value is not None and value < 0 for value in counts):
            raise ValueError("Matching review run counts are invalid")
        if self.status in {"COMPLETED", "SUPERSEDED"}:
            if (
                self.ordered_result_sha256 is None
                or any(value is None for value in counts)
                or self.candidate_count != self.eligible_count + self.excluded_count
                or self.failure_code is not None
            ):
                raise ValueError("Matching completed run projection is invalid")
            _require_digest(self.ordered_result_sha256)
        elif self.status == "FAILED":
            if (
                self.ordered_result_sha256 is not None
                or any(value is not None for value in counts)
                or not isinstance(self.failure_code, str)
                or not _CODE.fullmatch(self.failure_code)
            ):
                raise ValueError("Matching failed run projection is invalid")
        elif (
            self.ordered_result_sha256 is not None
            or any(value is not None for value in counts)
            or self.failure_code is not None
        ):
            raise ValueError("Matching pending run projection is invalid")


@dataclass(frozen=True)
class MatchingReviewCandidateView:
    creator_user_id: UUID
    creator_display_handle: str
    profile_id: UUID
    profile_version_id: UUID
    profile_content_sha256: bytes = field(repr=False)
    evidence_version_digest: bytes = field(repr=False)
    total_score: str
    rank: int
    component_scores: Tuple["MatchingReviewComponentScoreView", ...]
    candidate_result_sha256: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _require_uuid(
            self.creator_user_id,
            self.profile_id,
            self.profile_version_id,
        )
        _require_digest(self.profile_content_sha256)
        _require_digest(self.evidence_version_digest)
        _require_digest(self.candidate_result_sha256)
        _require_version(self.rank)
        if (
            not re.fullmatch(r"creator_[a-f0-9]{16}", self.creator_display_handle)
            or len(self.component_scores) != 6
            or tuple(item.ordinal for item in self.component_scores)
            != tuple(range(1, 7))
        ):
            raise ValueError("Matching review candidate projection is invalid")


@dataclass(frozen=True)
class MatchingReviewComponentScoreView:
    code: str
    ordinal: int
    score: str


@dataclass(frozen=True)
class MatchingReviewInvitationView:
    invitation_id: UUID
    creator_user_id: UUID
    status: str
    aggregate_version: int
    snapshot_sha256: bytes = field(repr=False)
    expires_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class MatchingReviewActions:
    can_create_invitation: bool
    can_publish_invitation: bool
    can_invalidate_attempt: bool


@dataclass(frozen=True)
class MatchingReviewAssignmentView:
    assignment: MatchingReviewAssignmentSummary
    attempt: MatchingReviewAttemptView
    run: MatchingReviewRunView
    eligible_candidates: Tuple[MatchingReviewCandidateView, ...]
    invitations: Tuple[MatchingReviewInvitationView, ...]
    actions: MatchingReviewActions


@dataclass(frozen=True)
class MatchingReviewerAssignmentResolution:
    assignment_id: UUID
    organization_id: UUID
    attempt_id: UUID
    match_run_id: UUID
    purpose_code: str
    assignment_version: int
    expires_at: datetime


@dataclass(frozen=True)
class MatchingReviewReleaseRequest:
    context: MatchingReviewContext
    expected_assignment_version: int
    material: MatchingOperationalCommandMaterial = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.context, MatchingReviewContext):
            raise TypeError("Matching review context is unavailable")
        if not isinstance(self.material, MatchingOperationalCommandMaterial):
            raise TypeError("Matching command material is unavailable")
        _require_version(self.expected_assignment_version)
        _require_outboxes(self.material, 1)


@dataclass(frozen=True)
class MatchingReviewCreateInvitationReplayRequest:
    context: MatchingReviewContext
    organization_id: UUID
    match_run_id: UUID
    expected_match_run_version: int
    material: MatchingOperationalCommandMaterial = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.context, MatchingReviewContext):
            raise TypeError("Matching review context is unavailable")
        if not isinstance(self.material, MatchingOperationalCommandMaterial):
            raise TypeError("Matching command material is unavailable")
        _require_uuid(self.organization_id, self.match_run_id)
        _require_version(self.expected_match_run_version)
        _require_outboxes(self.material, 1)


@dataclass(frozen=True)
class MatchingReviewPrepareInvitationRequest:
    context: MatchingReviewContext
    organization_id: UUID
    assignment_id: UUID
    expected_assignment_version: int
    match_run_id: UUID
    expected_match_run_version: int
    creator_user_id: UUID
    invitation_id: UUID
    snapshot_id: UUID
    expires_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.context, MatchingReviewContext):
            raise TypeError("Matching review context is unavailable")
        _require_uuid(
            self.organization_id,
            self.assignment_id,
            self.match_run_id,
            self.creator_user_id,
            self.invitation_id,
            self.snapshot_id,
        )
        _require_version(
            self.expected_assignment_version, self.expected_match_run_version
        )
        if not _aware_utc(self.expires_at):
            raise ValueError("Matching invitation expiry is invalid")


@dataclass(frozen=True)
class MatchingPreparedInvitationDisclosure:
    snapshot: InvitationDisclosureSnapshot
    document: Mapping[str, Any]


@dataclass(frozen=True)
class MatchingReviewCreateInvitationRequest:
    context: MatchingReviewContext
    organization_id: UUID
    assignment_id: UUID
    expected_assignment_version: int
    match_run_id: UUID
    expected_match_run_version: int
    creator_user_id: UUID
    invitation_id: UUID
    snapshot_id: UUID
    expires_at: datetime
    prepared: MatchingPreparedInvitationDisclosure
    trust: MatchingTrustEvidence
    material: MatchingOperationalCommandMaterial = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.context, MatchingReviewContext):
            raise TypeError("Matching review context is unavailable")
        if not isinstance(self.prepared, MatchingPreparedInvitationDisclosure):
            raise TypeError("Prepared Matching disclosure is unavailable")
        if not isinstance(self.trust, MatchingTrustEvidence):
            raise TypeError("Matching Trust evidence is unavailable")
        if not isinstance(self.material, MatchingOperationalCommandMaterial):
            raise TypeError("Matching command material is unavailable")
        _require_uuid(
            self.organization_id,
            self.assignment_id,
            self.match_run_id,
            self.creator_user_id,
            self.invitation_id,
            self.snapshot_id,
        )
        _require_version(
            self.expected_assignment_version, self.expected_match_run_version
        )
        if self.prepared.snapshot.invitation_id != str(self.invitation_id):
            raise ValueError("Matching disclosure invitation binding is invalid")
        if self.prepared.snapshot.snapshot_id != str(self.snapshot_id):
            raise ValueError("Matching disclosure snapshot binding is invalid")
        if not _aware_utc(self.expires_at):
            raise ValueError("Matching invitation expiry is invalid")
        validate_invitation_disclosure(self.prepared.snapshot)
        _require_outboxes(self.material, 1)


@dataclass(frozen=True)
class MatchingReviewPublishInvitationRequest:
    context: MatchingReviewContext
    organization_id: UUID
    assignment_id: UUID
    expected_assignment_version: int
    invitation_id: UUID
    expected_invitation_version: int
    expected_snapshot_sha256: bytes = field(repr=False)
    trust: MatchingTrustEvidence
    material: MatchingOperationalCommandMaterial = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.context, MatchingReviewContext):
            raise TypeError("Matching review context is unavailable")
        if not isinstance(self.trust, MatchingTrustEvidence):
            raise TypeError("Matching Trust evidence is unavailable")
        if not isinstance(self.material, MatchingOperationalCommandMaterial):
            raise TypeError("Matching command material is unavailable")
        _require_uuid(self.organization_id, self.assignment_id, self.invitation_id)
        _require_version(
            self.expected_assignment_version, self.expected_invitation_version
        )
        _require_digest(self.expected_snapshot_sha256)
        _require_outboxes(self.material, 2)


@dataclass(frozen=True)
class MatchingReviewInvalidateAttemptRequest:
    context: MatchingReviewContext
    organization_id: UUID
    assignment_id: UUID
    expected_assignment_version: int
    attempt_id: UUID
    expected_attempt_version: int
    expected_input_baseline_sha256: bytes = field(repr=False)
    reason_code: str
    material: MatchingOperationalCommandMaterial = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.context, MatchingReviewContext):
            raise TypeError("Matching review context is unavailable")
        if not isinstance(self.material, MatchingOperationalCommandMaterial):
            raise TypeError("Matching command material is unavailable")
        _require_uuid(self.organization_id, self.assignment_id, self.attempt_id)
        _require_version(
            self.expected_assignment_version, self.expected_attempt_version
        )
        _require_digest(self.expected_input_baseline_sha256)
        _require_code(self.reason_code)
        if len(self.material.outbox_event_ids) < 2:
            raise ValueError("Matching invalidation event identifiers are missing")


class PsycopgMatchingAssignmentRuntime:
    """Authenticated Candidate Selector opt-in via ``matching_assignment``."""

    def __init__(
        self,
        *,
        connections: MatchingPostgresConnectionSource,
        settings: MatchingOperationalPostgresSettings = MatchingOperationalPostgresSettings(),
    ) -> None:
        self._gateway = _RoleGateway(
            connections=connections, role="matching_assignment", settings=settings
        )

    def close(self) -> None:
        self._gateway.close()

    def check_readiness(self, timeout_ms: int) -> None:
        self._gateway.check_readiness(
            timeout_ms,
            (
                "matching_api.claim_candidate_selector_v1(uuid,uuid,uuid,uuid,bytea,uuid,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid)",
            ),
        )

    def claim_candidate_selector(
        self, request: MatchingCandidateSelectorClaimRequest
    ) -> MatchingCandidateSelectorClaimResult:
        if not isinstance(request, MatchingCandidateSelectorClaimRequest):
            raise TypeError("Candidate Selector claim request is unavailable")
        context = request.context
        material = request.material
        rows = self._gateway.execute(
            write=True,
            scope="MATCHING_ASSIGNMENT",
            operation="OPT_IN_CANDIDATE_SELECTOR",
            actor_user_id=context.actor_user_id,
            session_id=context.session_id,
            organization_id=context.organization_id,
            demand_id=request.demand_id,
            authority_marker=context.principal_marker_sha256,
            command_id=material.command_id,
            statement=(
                "SELECT safe_projection,replayed FROM "
                "matching_api.claim_candidate_selector_v1("
                + ",".join(["%s"] * 16)
                + ")"
            ),
            parameters=(
                context.actor_user_id,
                context.session_id,
                context.organization_id,
                request.demand_id,
                context.principal_marker_sha256,
                request.assignment_id,
                material.receipt_id,
                material.command_id,
                material.identity_key_id,
                material.identity_digest,
                material.payload_hash_key_id,
                material.payload_hash,
                material.audit_event_id,
                material.outbox_event_ids[0],
                material.correlation_id,
                material.trace_id,
            ),
            maximum_rows=2,
        )
        projection, replayed = _one_projection(rows)
        return _candidate_selector_claim(projection, replayed)


class PsycopgMatchingReviewRuntime:
    """Request-driven Operations reviewer gateway via ``matching_review``."""

    def __init__(
        self,
        *,
        connections: MatchingPostgresConnectionSource,
        settings: MatchingOperationalPostgresSettings = MatchingOperationalPostgresSettings(),
    ) -> None:
        self._gateway = _RoleGateway(
            connections=connections, role="matching_review", settings=settings
        )

    def close(self) -> None:
        self._gateway.close()

    def check_readiness(self, timeout_ms: int) -> None:
        self._gateway.check_readiness(
            timeout_ms,
            (
                "matching_api.claim_matching_review_v1(uuid,uuid,bytea,uuid,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid)",
                "matching_api.read_matching_review_assignment_v1(uuid,uuid,bytea)",
                "matching_api.resolve_matching_review_assignment_v1(uuid,uuid,bytea,text,uuid)",
                "matching_api.release_matching_review_v1(uuid,uuid,bytea,bigint,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid)",
                "matching_api.prepare_matching_invitation_v1(uuid,uuid,bytea,uuid,uuid,bigint,uuid,bigint,uuid,uuid,timestamptz)",
                "matching_api.read_create_invitation_receipt_v1(uuid,uuid,bytea,uuid,uuid,bigint,text,bytea,text,bytea)",
                "matching_api.create_matching_invitation_v1(uuid,uuid,bytea,uuid,uuid,bigint,uuid,bigint,uuid,timestamptz,bytea,jsonb,bytea,uuid,uuid,uuid,bytea,timestamptz,timestamptz,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid)",
                "matching_api.publish_matching_invitation_v1(uuid,uuid,bytea,uuid,uuid,bigint,uuid,bigint,bytea,uuid,bytea,timestamptz,timestamptz,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid,uuid)",
                "matching_api.invalidate_matching_attempt_v1(uuid,uuid,bytea,uuid,uuid,bigint,uuid,bigint,bytea,text,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid[],uuid,uuid)",
            ),
        )

    def claim_assignment(
        self, request: MatchingReviewClaimRequest
    ) -> Optional[MatchingReviewAssignmentSummary]:
        if not isinstance(request, MatchingReviewClaimRequest):
            raise TypeError("Matching review claim request is unavailable")
        context, material = request.context, request.material
        rows = self._gateway.execute(
            write=True,
            scope="MATCHING_REVIEW_CLAIM",
            operation="CLAIM_MATCHING_REVIEW",
            actor_user_id=context.actor_user_id,
            session_id=context.session_id,
            authority_marker=context.principal_marker_sha256,
            command_id=material.command_id,
            statement=(
                "SELECT safe_assignment,replayed FROM "
                "matching_api.claim_matching_review_v1("
                + ",".join(["%s"] * 14)
                + ")"
            ),
            parameters=(
                context.actor_user_id,
                context.session_id,
                context.principal_marker_sha256,
                request.assignment_id,
                material.command_id,
                material.receipt_id,
                material.identity_key_id,
                material.identity_digest,
                material.payload_hash_key_id,
                material.payload_hash,
                material.audit_event_id,
                material.outbox_event_ids[0],
                material.correlation_id,
                material.trace_id,
            ),
            maximum_rows=2,
        )
        if not rows:
            return None
        projection, replayed = _one_projection(rows)
        return _review_summary(projection, replayed)

    def read_assignment(
        self, context: MatchingReviewContext
    ) -> Optional[MatchingReviewAssignmentView]:
        _require_review_context(context)
        rows = self._gateway.execute(
            write=False,
            scope="MATCHING_REVIEW_RESUME",
            operation="READ_MATCHING_REVIEW_ASSIGNMENT",
            actor_user_id=context.actor_user_id,
            session_id=context.session_id,
            authority_marker=context.principal_marker_sha256,
            statement=(
                "SELECT safe_assignment FROM "
                "matching_api.read_matching_review_assignment_v1(%s,%s,%s)"
            ),
            parameters=(
                context.actor_user_id,
                context.session_id,
                context.principal_marker_sha256,
            ),
            maximum_rows=2,
        )
        if not rows:
            return None
        if len(rows) != 1 or not isinstance(rows[0], tuple) or len(rows[0]) != 1:
            raise MatchingPostgresConfigurationError()
        return _review_view(_mapping(rows[0][0]))

    def resolve_assignment(
        self,
        *,
        context: MatchingReviewContext,
        operation: str,
        target_id: UUID,
    ) -> Optional[MatchingReviewerAssignmentResolution]:
        _require_review_context(context)
        if operation not in {
            "CREATE_INVITATION",
            "PUBLISH_INVITATION",
            "INVALIDATE_ATTEMPT",
        }:
            raise ValueError("Matching review operation is invalid")
        _require_uuid(target_id)
        rows = self._gateway.execute(
            write=False,
            scope="MATCHING_REVIEW_RESOLVE",
            operation=operation,
            actor_user_id=context.actor_user_id,
            session_id=context.session_id,
            authority_marker=context.principal_marker_sha256,
            statement=(
                "SELECT * FROM matching_api."
                "resolve_matching_review_assignment_v1(%s,%s,%s,%s,%s)"
            ),
            parameters=(
                context.actor_user_id,
                context.session_id,
                context.principal_marker_sha256,
                operation,
                target_id,
            ),
            maximum_rows=2,
        )
        if not rows:
            return None
        if len(rows) != 1 or len(rows[0]) != 7:
            raise MatchingPostgresConfigurationError()
        row = rows[0]
        return MatchingReviewerAssignmentResolution(
            assignment_id=_uuid(row[0]),
            organization_id=_uuid(row[1]),
            attempt_id=_uuid(row[2]),
            match_run_id=_uuid(row[3]),
            purpose_code=_purpose(row[4]),
            assignment_version=_version(row[5]),
            expires_at=_timestamp(row[6]),
        )

    def release_assignment(
        self, request: MatchingReviewReleaseRequest
    ) -> MatchingReviewAssignmentSummary:
        if not isinstance(request, MatchingReviewReleaseRequest):
            raise TypeError("Matching review release request is unavailable")
        context, material = request.context, request.material
        rows = self._gateway.execute(
            write=True,
            scope="MATCHING_REVIEW_RESUME",
            operation="RELEASE_MATCHING_REVIEW",
            actor_user_id=context.actor_user_id,
            session_id=context.session_id,
            authority_marker=context.principal_marker_sha256,
            command_id=material.command_id,
            statement=(
                "SELECT safe_assignment,replayed FROM "
                "matching_api.release_matching_review_v1("
                + ",".join(["%s"] * 14)
                + ")"
            ),
            parameters=(
                context.actor_user_id,
                context.session_id,
                context.principal_marker_sha256,
                request.expected_assignment_version,
                material.command_id,
                material.receipt_id,
                material.identity_key_id,
                material.identity_digest,
                material.payload_hash_key_id,
                material.payload_hash,
                material.audit_event_id,
                material.outbox_event_ids[0],
                material.correlation_id,
                material.trace_id,
            ),
            maximum_rows=2,
        )
        projection, replayed = _one_projection(rows)
        return _review_summary(projection, replayed)

    def replay_create_invitation(
        self, request: MatchingReviewCreateInvitationReplayRequest
    ) -> Optional[MatchingCommandResult]:
        if not isinstance(request, MatchingReviewCreateInvitationReplayRequest):
            raise TypeError("Matching create receipt request is unavailable")
        context, material = request.context, request.material
        rows = self._gateway.execute(
            write=False,
            scope="MATCHING_REVIEW",
            operation="CREATE_INVITATION",
            actor_user_id=context.actor_user_id,
            session_id=context.session_id,
            organization_id=request.organization_id,
            match_run_id=request.match_run_id,
            target_id=request.match_run_id,
            authority_marker=context.principal_marker_sha256,
            statement=(
                "SELECT safe_response,replayed FROM "
                "matching_api.read_create_invitation_receipt_v1("
                + ",".join(["%s"] * 10) + ")"
            ),
            parameters=(
                context.actor_user_id, context.session_id,
                context.principal_marker_sha256, request.organization_id,
                request.match_run_id, request.expected_match_run_version,
                material.identity_key_id, material.identity_digest,
                material.payload_hash_key_id, material.payload_hash,
            ),
            maximum_rows=2,
        )
        if not rows:
            return None
        projection, replayed = _one_projection(rows)
        if not replayed:
            raise MatchingPostgresConfigurationError()
        return _invitation_command_result(projection, True, ("InvitationCreated",))

    def prepare_invitation(
        self, request: MatchingReviewPrepareInvitationRequest
    ) -> MatchingPreparedInvitationDisclosure:
        if not isinstance(request, MatchingReviewPrepareInvitationRequest):
            raise TypeError("Matching invitation preparation is unavailable")
        context = request.context
        rows = self._gateway.execute(
            write=False,
            scope="MATCHING_REVIEW",
            operation="PREPARE_INVITATION",
            actor_user_id=context.actor_user_id,
            session_id=context.session_id,
            organization_id=request.organization_id,
            match_run_id=request.match_run_id,
            target_id=request.match_run_id,
            authority_marker=context.principal_marker_sha256,
            statement=(
                "SELECT safe_disclosure FROM "
                "matching_api.prepare_matching_invitation_v1("
                + ",".join(["%s"] * 11)
                + ")"
            ),
            parameters=(
                context.actor_user_id,
                context.session_id,
                context.principal_marker_sha256,
                request.organization_id,
                request.assignment_id,
                request.expected_assignment_version,
                request.match_run_id,
                request.expected_match_run_version,
                request.creator_user_id,
                request.invitation_id,
                request.expires_at,
            ),
            maximum_rows=2,
        )
        if len(rows) != 1 or len(rows[0]) != 1:
            raise MatchingPostgresConfigurationError()
        document = _mapping(rows[0][0])
        canonical = _canonical_json_bytes(document)
        digest = hashlib.sha256(canonical).digest()
        snapshot = InvitationDisclosureSnapshot(
            snapshot_id=str(request.snapshot_id),
            invitation_id=str(request.invitation_id),
            attempt_id=_text(document, "attempt_id"),
            demand_id=_text(document, "demand_id"),
            demand_version_id=_text(document, "demand_version_id"),
            profile_id=_text(document, "profile_id"),
            profile_version_id=_text(document, "profile_version_id"),
            demand_content_sha256=_text(document, "demand_content_sha256"),
            profile_content_sha256=_text(document, "profile_content_sha256"),
            snapshot_sha256=digest.hex(),
            canonical_bytes=canonical,
        )
        try:
            validate_invitation_disclosure(snapshot)
        except MatchingDomainError:
            # A malformed database-produced disclosure must not reach CREATE,
            # and is a producer/configuration failure rather than user input.
            raise MatchingPostgresConfigurationError() from None
        return MatchingPreparedInvitationDisclosure(snapshot=snapshot, document=document)

    def create_invitation(
        self, request: MatchingReviewCreateInvitationRequest
    ) -> MatchingCommandResult:
        if not isinstance(request, MatchingReviewCreateInvitationRequest):
            raise TypeError("Matching create invitation request is unavailable")
        context, material, trust = request.context, request.material, request.trust
        snapshot = request.prepared.snapshot
        full_document = dict(request.prepared.document)
        full_document["snapshot_sha256"] = snapshot.snapshot_sha256
        rows = self._gateway.execute(
            write=True,
            scope="MATCHING_REVIEW",
            operation="CREATE_INVITATION",
            actor_user_id=context.actor_user_id,
            session_id=context.session_id,
            organization_id=request.organization_id,
            match_run_id=request.match_run_id,
            target_id=request.match_run_id,
            authority_marker=context.principal_marker_sha256,
            command_id=material.command_id,
            statement=(
                "SELECT safe_response,replayed FROM "
                "matching_api.create_matching_invitation_v1("
                + ",".join(["%s"] * 29)
                + ")"
            ),
            parameters=(
                context.actor_user_id,
                context.session_id,
                context.principal_marker_sha256,
                request.organization_id,
                request.assignment_id,
                request.expected_assignment_version,
                request.match_run_id,
                request.expected_match_run_version,
                request.creator_user_id,
                request.expires_at,
                snapshot.canonical_bytes,
                Jsonb(full_document),
                bytes.fromhex(snapshot.snapshot_sha256),
                request.invitation_id,
                request.snapshot_id,
                trust.evidence_id,
                trust.evidence_sha256,
                trust.evaluated_at,
                trust.valid_until,
                material.command_id,
                material.receipt_id,
                material.identity_key_id,
                material.identity_digest,
                material.payload_hash_key_id,
                material.payload_hash,
                material.audit_event_id,
                material.outbox_event_ids[0],
                material.correlation_id,
                material.trace_id,
            ),
            maximum_rows=2,
        )
        projection, replayed = _one_projection(rows)
        return _invitation_command_result(
            projection, replayed, ("InvitationCreated",)
        )

    def publish_invitation(
        self, request: MatchingReviewPublishInvitationRequest
    ) -> MatchingCommandResult:
        if not isinstance(request, MatchingReviewPublishInvitationRequest):
            raise TypeError("Matching publish invitation request is unavailable")
        context, material, trust = request.context, request.material, request.trust
        rows = self._gateway.execute(
            write=True,
            scope="MATCHING_REVIEW",
            operation="PUBLISH_INVITATION",
            actor_user_id=context.actor_user_id,
            session_id=context.session_id,
            organization_id=request.organization_id,
            invitation_id=request.invitation_id,
            target_id=request.invitation_id,
            authority_marker=context.principal_marker_sha256,
            command_id=material.command_id,
            statement=(
                "SELECT safe_response,replayed FROM "
                "matching_api.publish_matching_invitation_v1("
                + ",".join(["%s"] * 24)
                + ")"
            ),
            parameters=(
                context.actor_user_id,
                context.session_id,
                context.principal_marker_sha256,
                request.organization_id,
                request.assignment_id,
                request.expected_assignment_version,
                request.invitation_id,
                request.expected_invitation_version,
                request.expected_snapshot_sha256,
                trust.evidence_id,
                trust.evidence_sha256,
                trust.evaluated_at,
                trust.valid_until,
                material.command_id,
                material.receipt_id,
                material.identity_key_id,
                material.identity_digest,
                material.payload_hash_key_id,
                material.payload_hash,
                material.audit_event_id,
                material.outbox_event_ids[0],
                material.outbox_event_ids[1],
                material.correlation_id,
                material.trace_id,
            ),
            maximum_rows=2,
        )
        projection, replayed = _one_projection(rows)
        return _invitation_command_result(
            projection,
            replayed,
            ("InvitationSent", "SelectionInvitationSetChanged"),
        )

    def invalidate_attempt(
        self, request: MatchingReviewInvalidateAttemptRequest
    ) -> MatchingCommandResult:
        if not isinstance(request, MatchingReviewInvalidateAttemptRequest):
            raise TypeError("Matching invalidate attempt request is unavailable")
        context, material = request.context, request.material
        invitation_events = material.outbox_event_ids[2:]
        rows = self._gateway.execute(
            write=True,
            scope="MATCHING_REVIEW",
            operation="INVALIDATE_ATTEMPT",
            actor_user_id=context.actor_user_id,
            session_id=context.session_id,
            organization_id=request.organization_id,
            attempt_id=request.attempt_id,
            target_id=request.attempt_id,
            authority_marker=context.principal_marker_sha256,
            command_id=material.command_id,
            statement=(
                "SELECT safe_response,replayed FROM "
                "matching_api.invalidate_matching_attempt_v1("
                + ",".join(["%s"] * 22)
                + ")"
            ),
            parameters=(
                context.actor_user_id,
                context.session_id,
                context.principal_marker_sha256,
                request.organization_id,
                request.assignment_id,
                request.expected_assignment_version,
                request.attempt_id,
                request.expected_attempt_version,
                request.expected_input_baseline_sha256,
                request.reason_code,
                material.command_id,
                material.receipt_id,
                material.identity_key_id,
                material.identity_digest,
                material.payload_hash_key_id,
                material.payload_hash,
                material.audit_event_id,
                material.outbox_event_ids[0],
                material.outbox_event_ids[1],
                list(invitation_events),
                material.correlation_id,
                material.trace_id,
            ),
            maximum_rows=2,
        )
        projection, replayed = _one_projection(rows)
        events = (
            *(("InvitationRevoked",) if invitation_events else ()),
            "SelectionCancelled",
            "MatchingAttemptInvalidated",
        )
        return _attempt_command_result(projection, replayed, events)


@dataclass(frozen=True)
class MatchingRulePublicationRequest:
    context: MatchingWorkloadContext
    organization_id: UUID
    rule: LoadedMatchingRuleReleaseV1
    signature_key_id: str
    review_approval_id: UUID
    review_approval_version: int
    material: MatchingOperationalCommandMaterial = field(repr=False)

    def __post_init__(self) -> None:
        _require_workload_context(self.context)
        _require_uuid(self.organization_id, self.review_approval_id)
        _require_version(self.review_approval_version)
        _require_key(self.signature_key_id)
        _require_rule(self.rule)
        if not isinstance(self.material, MatchingOperationalCommandMaterial):
            raise TypeError("Matching command material is unavailable")
        _require_outboxes(self.material, 1)


@dataclass(frozen=True)
class MatchingRulePublicationResult:
    rule_bundle_id: UUID
    status: str
    selector_digest: bytes = field(repr=False)
    canonical_manifest_sha256: bytes = field(repr=False)
    engine_artifact_sha256: bytes = field(repr=False)
    invitation_limit: int
    replayed: bool

    def __post_init__(self) -> None:
        _require_uuid(self.rule_bundle_id)
        if self.status != "ACTIVE":
            raise ValueError("Matching rule publication projection is invalid")
        _require_digest(
            self.selector_digest,
            self.canonical_manifest_sha256,
            self.engine_artifact_sha256,
        )
        if type(self.invitation_limit) is not int or not 1 <= self.invitation_limit <= 100:
            raise ValueError("Matching invitation limit is invalid")
        if type(self.replayed) is not bool:
            raise TypeError("Matching replay flag is invalid")


@dataclass(frozen=True)
class MatchingRequestedIngestRequest:
    context: MatchingWorkloadContext
    organization_id: UUID
    requested: Mapping[str, Any] = field(repr=False)
    attempt_id: UUID
    run_id: UUID
    job_id: UUID
    selection_id: UUID
    coordinator_workload_id: UUID
    coordinator_authority_marker_sha256: bytes = field(repr=False)
    material: MatchingOperationalCommandMaterial = field(repr=False)

    def __post_init__(self) -> None:
        _require_workload_context(self.context)
        _mapping(self.requested)
        _require_uuid(
            self.organization_id,
            self.attempt_id,
            self.run_id,
            self.job_id,
            self.selection_id,
            self.coordinator_workload_id,
        )
        _require_digest(self.coordinator_authority_marker_sha256)
        if not isinstance(self.material, MatchingOperationalCommandMaterial):
            raise TypeError("Matching command material is unavailable")
        _require_outboxes(self.material, 2)


@dataclass(frozen=True)
class MatchingRequestedIngestResult:
    attempt_id: UUID
    aggregate_version: int
    run_id: UUID
    job_id: UUID
    selection_id: UUID
    source_event_id: UUID
    status: str
    replayed: bool

    def __post_init__(self) -> None:
        _require_uuid(
            self.attempt_id,
            self.run_id,
            self.job_id,
            self.selection_id,
            self.source_event_id,
        )
        _require_version(self.aggregate_version)
        if self.status != "OPEN" or type(self.replayed) is not bool:
            raise ValueError("Matching ingest projection is invalid")


@dataclass(frozen=True)
class MatchingWorkerJobClaimRequest:
    context: MatchingWorkloadContext
    lease_digest_key_id: str
    lease_digest: bytes = field(repr=False)
    lease_seconds: int
    material: MatchingOperationalCommandMaterial = field(repr=False)

    def __post_init__(self) -> None:
        _require_workload_context(self.context)
        _require_key(self.lease_digest_key_id)
        _require_digest(self.lease_digest)
        if type(self.lease_seconds) is not int or not 1 <= self.lease_seconds <= 300:
            raise ValueError("Matching worker lease is invalid")
        if not isinstance(self.material, MatchingOperationalCommandMaterial):
            raise TypeError("Matching command material is unavailable")
        if self.lease_digest_key_id in {
            self.material.identity_key_id,
            self.material.payload_hash_key_id,
        }:
            raise ValueError("Matching lease key is not purpose-separated")
        _require_outboxes(self.material, 1)


@dataclass(frozen=True)
class MatchingWorkerJobClaim:
    organization_id: UUID
    job_id: UUID
    attempt_id: UUID
    match_run_id: UUID
    demand_id: UUID
    demand_version_id: UUID
    matching_request_id: UUID
    matching_rule_bundle_id: UUID
    selector_digest: bytes = field(repr=False)
    source_authorization_digest: bytes = field(repr=False)
    status: str
    run_status: str
    fencing_generation: int
    lease_until: Optional[datetime]
    attempt_count: Optional[int]
    run_attempt: int
    recovery_status: str
    failure_code: Optional[str]
    replayed: bool

    def __post_init__(self) -> None:
        _require_uuid(
            self.organization_id,
            self.job_id,
            self.attempt_id,
            self.match_run_id,
            self.demand_id,
            self.demand_version_id,
            self.matching_request_id,
            self.matching_rule_bundle_id,
        )
        _require_digest(
            self.selector_digest,
            self.source_authorization_digest,
        )
        _require_fence(self.fencing_generation)
        if self.status not in {"LEASED", "FAILED"}:
            raise ValueError("Matching worker job status is invalid")
        if self.run_status not in {"QUEUED", "RUNNING", "FAILED"}:
            raise ValueError("Matching worker run status is invalid")
        if self.recovery_status not in {
            "CLAIMED",
            "QUEUED_LEASE_RECOVERED",
            "RUNNING_LEASE_RETRY_LEASED",
            "REVIEW_REQUIRED",
        }:
            raise ValueError("Matching worker recovery status is invalid")
        if (self.status == "LEASED") != (self.lease_until is not None):
            raise ValueError("Matching worker lease projection is invalid")
        if self.lease_until is not None and not _aware_utc(self.lease_until):
            raise ValueError("Matching worker lease time is invalid")
        if self.attempt_count is not None and (
            type(self.attempt_count) is not int or not 1 <= self.attempt_count <= 3
        ):
            raise ValueError("Matching worker attempt count is invalid")
        if type(self.run_attempt) is not int or not 1 <= self.run_attempt <= 3:
            raise ValueError("Matching worker run attempt is invalid")
        if self.failure_code is not None:
            _require_code(self.failure_code)
        if type(self.replayed) is not bool:
            raise TypeError("Matching replay flag is invalid")


@dataclass(frozen=True)
class MatchingRunStartPayload:
    canonical_manifest_bytes: bytes = field(repr=False)
    manifest: Mapping[str, Any]
    manifest_sha256: bytes = field(repr=False)
    canonical_run_input_bytes: bytes = field(repr=False)
    run_input: Mapping[str, Any]
    run_input_sha256: bytes = field(repr=False)
    canonical_input_set_bytes: bytes = field(repr=False)
    input_set_sha256: bytes = field(repr=False)
    candidate_allowlist_sha256: bytes = field(repr=False)
    candidate_count: int
    canonical_source_capture_bytes: bytes = field(repr=False)
    source_capture: Mapping[str, Any]
    source_capture_sha256: bytes = field(repr=False)
    source_authorization_valid_until: datetime

    def __post_init__(self) -> None:
        for raw, document, digest in (
            (self.canonical_manifest_bytes, self.manifest, self.manifest_sha256),
            (
                self.canonical_run_input_bytes,
                self.run_input,
                self.run_input_sha256,
            ),
            (
                self.canonical_source_capture_bytes,
                self.source_capture,
                self.source_capture_sha256,
            ),
        ):
            if not isinstance(raw, bytes) or _canonical_json_bytes(_mapping(document)) != raw:
                raise ValueError("Matching canonical input bytes are invalid")
            _require_digest(digest)
            if hashlib.sha256(raw).digest() != digest:
                raise ValueError("Matching input digest is invalid")
        if not isinstance(self.canonical_input_set_bytes, bytes):
            raise ValueError("Matching canonical input set is invalid")
        _require_digest(self.input_set_sha256)
        if hashlib.sha256(self.canonical_input_set_bytes).digest() != self.input_set_sha256:
            raise ValueError("Matching input-set digest is invalid")
        _require_digest(self.candidate_allowlist_sha256)
        if type(self.candidate_count) is not int or not 0 <= self.candidate_count <= 500:
            raise ValueError("Matching candidate count is invalid")
        if not _aware_utc(self.source_authorization_valid_until):
            raise ValueError("Matching source authorization is invalid")


@dataclass(frozen=True)
class MatchingWorkerStartRunRequest:
    context: MatchingWorkloadContext
    organization_id: UUID
    job_id: UUID
    match_run_id: UUID
    fencing_generation: int
    lease_digest_key_id: str
    lease_digest: bytes = field(repr=False)
    payload: MatchingRunStartPayload = field(repr=False)
    material: MatchingOperationalCommandMaterial = field(repr=False)

    def __post_init__(self) -> None:
        _require_workload_context(self.context)
        _require_uuid(self.organization_id, self.job_id, self.match_run_id)
        _require_fence(self.fencing_generation)
        _require_key(self.lease_digest_key_id)
        _require_digest(self.lease_digest)
        if not isinstance(self.payload, MatchingRunStartPayload):
            raise TypeError("Matching run input payload is unavailable")
        if not isinstance(self.material, MatchingOperationalCommandMaterial):
            raise TypeError("Matching command material is unavailable")
        _require_outboxes(self.material, 1)


@dataclass(frozen=True)
class MatchingWorkerCompleteRunRequest:
    context: MatchingWorkloadContext
    organization_id: UUID
    job_id: UUID
    match_run_id: UUID
    fencing_generation: int
    lease_digest_key_id: str
    lease_digest: bytes = field(repr=False)
    run_input: MatchRunInputV1 = field(repr=False)
    rule: LoadedMatchingRuleReleaseV1 = field(repr=False)
    result: DeterministicMatchResultV1 = field(repr=False)
    system_close_intent_id: Optional[UUID]
    system_close_audit_event_id: Optional[UUID]
    selection_close_intent_event_id: Optional[UUID]
    attempt_close_event_id: Optional[UUID]
    material: MatchingOperationalCommandMaterial = field(repr=False)

    def __post_init__(self) -> None:
        _require_workload_context(self.context)
        _require_uuid(self.organization_id, self.job_id, self.match_run_id)
        _require_fence(self.fencing_generation)
        _require_key(self.lease_digest_key_id)
        _require_digest(self.lease_digest)
        if not isinstance(self.run_input, MatchRunInputV1):
            raise TypeError("Matching normalized run input is unavailable")
        _require_rule(self.rule)
        if not isinstance(self.result, DeterministicMatchResultV1):
            raise TypeError("Matching deterministic result is unavailable")
        system_identifiers = (
            self.system_close_intent_id,
            self.system_close_audit_event_id,
            self.selection_close_intent_event_id,
            self.attempt_close_event_id,
        )
        has_system_close = any(value is not None for value in system_identifiers)
        if has_system_close and not all(
            isinstance(value, UUID) and value != _ZERO_UUID
            for value in system_identifiers
        ):
            raise ValueError("Matching system-close identifiers are incomplete")
        eligible_count = sum(
            1
            for candidate in self.result.candidate_documents
            if candidate.get("eligibility") == "ELIGIBLE"
        )
        if (eligible_count == 0) != has_system_close:
            raise ValueError("Matching system-close identity does not match result")
        if not isinstance(self.material, MatchingOperationalCommandMaterial):
            raise TypeError("Matching command material is unavailable")
        _require_outboxes(self.material, 1)
        if has_system_close:
            identifiers = (
                *system_identifiers,
                self.material.audit_event_id,
                *self.material.outbox_event_ids,
            )
            if len(identifiers) != len(set(identifiers)):
                raise ValueError("Matching system-close identifiers must be distinct")


@dataclass(frozen=True)
class MatchingWorkerFailRunRequest:
    context: MatchingWorkloadContext
    organization_id: UUID
    job_id: UUID
    match_run_id: UUID
    fencing_generation: int
    lease_digest_key_id: str
    lease_digest: bytes = field(repr=False)
    failure_code: str
    retry_run_id: Optional[UUID]
    retry_job_id: Optional[UUID]
    retry_available_at: Optional[datetime]
    material: MatchingOperationalCommandMaterial = field(repr=False)

    def __post_init__(self) -> None:
        _require_workload_context(self.context)
        _require_uuid(self.organization_id, self.job_id, self.match_run_id)
        _require_fence(self.fencing_generation)
        _require_key(self.lease_digest_key_id)
        _require_digest(self.lease_digest)
        _require_code(self.failure_code)
        retry = self.retry_run_id is not None
        if retry != (self.retry_job_id is not None) or retry != (
            self.retry_available_at is not None
        ):
            raise ValueError("Matching retry facts are incomplete")
        if retry:
            _require_uuid(self.retry_run_id, self.retry_job_id)  # type: ignore[arg-type]
            if not _aware_utc(self.retry_available_at):
                raise ValueError("Matching retry time is invalid")
        if not isinstance(self.material, MatchingOperationalCommandMaterial):
            raise TypeError("Matching command material is unavailable")
        _require_outboxes(self.material, 1)


@dataclass(frozen=True)
class MatchingWorkerRunResult:
    projection: Mapping[str, Any]
    replayed: bool

    def __post_init__(self) -> None:
        _mapping(self.projection)
        if type(self.replayed) is not bool:
            raise TypeError("Matching replay flag is invalid")


class PsycopgMatchingWorkerRuntime:
    """Fixed worker programs via the dedicated ``matching_worker`` role."""

    def __init__(
        self,
        *,
        connections: MatchingPostgresConnectionSource,
        settings: MatchingOperationalPostgresSettings = MatchingOperationalPostgresSettings(),
    ) -> None:
        self._gateway = _RoleGateway(
            connections=connections, role="matching_worker", settings=settings
        )

    def close(self) -> None:
        self._gateway.close()

    def check_readiness(self, timeout_ms: int) -> None:
        self._gateway.check_readiness(
            timeout_ms,
            (
                "matching_api.read_runtime_dependency_snapshot_v1()",
                "matching_api.publish_rule_bundle_v1(uuid,uuid,bytea,bytea,jsonb,bytea,text,uuid,bigint,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid)",
                "matching_api.read_rule_bundle_for_match_v1(uuid,uuid,bytea,uuid,bytea)",
                "matching_api.ingest_matching_requested_v1(uuid,uuid,bytea,jsonb,uuid,uuid,uuid,uuid,uuid,bytea,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid,uuid)",
                "matching_api.claim_match_job_v1(uuid,bytea,text,bytea,integer,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid)",
                "matching_api.start_match_run_v1(uuid,uuid,bytea,uuid,uuid,bigint,text,bytea,bytea,jsonb,bytea,bytea,jsonb,bytea,bytea,bytea,bytea,integer,bytea,jsonb,bytea,timestamptz,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid)",
                "matching_api.complete_match_run_v1(uuid,uuid,bytea,uuid,uuid,bigint,text,bytea,bytea,jsonb,bytea,bytea,uuid,uuid,uuid,uuid,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid)",
                "matching_api.fail_match_run_v1(uuid,uuid,bytea,uuid,uuid,bigint,text,bytea,text,uuid,uuid,timestamptz,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid)",
            ),
        )

    def publish_rule_bundle(
        self, request: MatchingRulePublicationRequest
    ) -> MatchingRulePublicationResult:
        if not isinstance(request, MatchingRulePublicationRequest):
            raise TypeError("Matching rule publication is unavailable")
        context, material = request.context, request.material
        rule = load_rule_release_v1(
            request.rule.canonical_manifest_bytes,
            expected_manifest_sha256=request.rule.canonical_manifest_sha256,
        )
        manifest = json.loads(rule.canonical_manifest_bytes)
        rows = self._gateway.execute(
            write=True,
            scope="MATCHING_WORKER",
            operation="PUBLISH_MATCHING_RULE",
            workload_id=context.workload_id,
            organization_id=request.organization_id,
            authority_marker=context.authority_marker_sha256,
            command_id=material.command_id,
            statement=(
                "SELECT safe_projection,replayed FROM "
                "matching_api.publish_rule_bundle_v1("
                + ",".join(["%s"] * 19)
                + ")"
            ),
            parameters=(
                context.workload_id,
                request.organization_id,
                context.authority_marker_sha256,
                rule.canonical_manifest_bytes,
                Jsonb(manifest),
                bytes.fromhex(rule.canonical_manifest_sha256),
                request.signature_key_id,
                request.review_approval_id,
                request.review_approval_version,
                material.receipt_id,
                material.command_id,
                material.identity_key_id,
                material.identity_digest,
                material.payload_hash_key_id,
                material.payload_hash,
                material.audit_event_id,
                material.outbox_event_ids[0],
                material.correlation_id,
                material.trace_id,
            ),
            maximum_rows=2,
        )
        projection, replayed = _one_projection(rows)
        _exact_keys(
            projection,
            {"rule_bundle_id", "status", "selector_digest", "canonical_manifest_sha256", "engine_artifact_sha256", "invitation_limit"},
        )
        return MatchingRulePublicationResult(
            rule_bundle_id=_json_uuid(projection["rule_bundle_id"]),
            status=_text(projection, "status"),
            selector_digest=_hex_digest(projection["selector_digest"]),
            canonical_manifest_sha256=_hex_digest(
                projection["canonical_manifest_sha256"]
            ),
            engine_artifact_sha256=_hex_digest(
                projection["engine_artifact_sha256"]
            ),
            invitation_limit=_positive_integer(projection["invitation_limit"]),
            replayed=replayed,
        )

    def read_rule_bundle(
        self,
        *,
        context: MatchingWorkloadContext,
        organization_id: UUID,
        rule_bundle_id: UUID,
        selector_digest: bytes,
    ) -> LoadedMatchingRuleReleaseV1:
        _require_workload_context(context)
        _require_uuid(organization_id, rule_bundle_id)
        _require_digest(selector_digest)
        rows = self._gateway.execute(
            write=False,
            scope="MATCHING_WORKER",
            operation="READ_MATCHING_RULE",
            workload_id=context.workload_id,
            organization_id=organization_id,
            rule_bundle_id=rule_bundle_id,
            authority_marker=context.authority_marker_sha256,
            statement=(
                "SELECT * FROM matching_api."
                "read_rule_bundle_for_match_v1(%s,%s,%s,%s,%s)"
            ),
            parameters=(
                context.workload_id,
                organization_id,
                context.authority_marker_sha256,
                rule_bundle_id,
                selector_digest,
            ),
            maximum_rows=2,
        )
        if len(rows) != 1 or len(rows[0]) != 10:
            raise MatchingPostgresConfigurationError()
        row = rows[0]
        if (
            _uuid(row[0]) != rule_bundle_id
            or bytes(row[1]) != selector_digest
            or not isinstance(row[2], bytes)
            or not isinstance(row[3], dict)
            or hashlib.sha256(row[2]).digest() != bytes(row[4])
            or row[5] != "deterministic-matcher-v1"
            or type(row[7]) is not int
            or not _aware_utc(_timestamp(row[8]))
            or (row[9] is not None and not _aware_utc(_timestamp(row[9])))
        ):
            raise MatchingPostgresConfigurationError()
        loaded = load_rule_release_v1(
            row[2], expected_manifest_sha256=bytes(row[4]).hex()
        )
        if (
            loaded.bundle_id != str(rule_bundle_id)
            or loaded.selector_digest != selector_digest.hex()
            or loaded.engine_artifact_sha256 != bytes(row[6]).hex()
            or loaded.invitation_limit != row[7]
            or json.loads(loaded.canonical_manifest_bytes) != row[3]
        ):
            raise MatchingPostgresConfigurationError()
        return loaded

    def ingest_matching_requested(
        self, request: MatchingRequestedIngestRequest
    ) -> MatchingRequestedIngestResult:
        if not isinstance(request, MatchingRequestedIngestRequest):
            raise TypeError("MatchingRequested ingest is unavailable")
        context, material = request.context, request.material
        rows = self._gateway.execute(
            write=True,
            scope="MATCHING_WORKER",
            operation="INGEST_MATCHING_REQUESTED",
            workload_id=context.workload_id,
            organization_id=request.organization_id,
            authority_marker=context.authority_marker_sha256,
            command_id=material.command_id,
            statement=(
                "SELECT safe_projection,replayed FROM "
                "matching_api.ingest_matching_requested_v1("
                + ",".join(["%s"] * 21)
                + ")"
            ),
            parameters=(
                context.workload_id,
                request.organization_id,
                context.authority_marker_sha256,
                Jsonb(dict(request.requested)),
                request.attempt_id,
                request.run_id,
                request.job_id,
                request.selection_id,
                request.coordinator_workload_id,
                request.coordinator_authority_marker_sha256,
                material.receipt_id,
                material.command_id,
                material.identity_key_id,
                material.identity_digest,
                material.payload_hash_key_id,
                material.payload_hash,
                material.audit_event_id,
                material.outbox_event_ids[0],
                material.outbox_event_ids[1],
                material.correlation_id,
                material.trace_id,
            ),
            maximum_rows=2,
        )
        projection, replayed = _one_projection(rows)
        required = {"attempt_id", "aggregate_version", "status", "source_event_id"}
        if set(projection) not in (
            required,
            required | {"run_id", "job_id", "selection_id"},
        ):
            raise MatchingPostgresConfigurationError()
        return MatchingRequestedIngestResult(
            attempt_id=_json_uuid(projection["attempt_id"]),
            aggregate_version=_version(projection["aggregate_version"]),
            run_id=(request.run_id if "run_id" not in projection else _json_uuid(projection["run_id"])),
            job_id=(request.job_id if "job_id" not in projection else _json_uuid(projection["job_id"])),
            selection_id=(request.selection_id if "selection_id" not in projection else _json_uuid(projection["selection_id"])),
            source_event_id=_json_uuid(projection["source_event_id"]),
            status=_text(projection, "status"),
            replayed=replayed,
        )

    def claim_job(
        self, request: MatchingWorkerJobClaimRequest
    ) -> Optional[MatchingWorkerJobClaim]:
        if not isinstance(request, MatchingWorkerJobClaimRequest):
            raise TypeError("Matching worker claim is unavailable")
        context, material = request.context, request.material
        rows = self._gateway.execute(
            write=True,
            scope="MATCHING_WORKER",
            operation="CLAIM_MATCH_JOB",
            workload_id=context.workload_id,
            authority_marker=context.authority_marker_sha256,
            command_id=material.command_id,
            lease_digest_key_id=request.lease_digest_key_id,
            lease_digest=request.lease_digest,
            statement=(
                "SELECT safe_projection,replayed FROM "
                "matching_api.claim_match_job_v1("
                + ",".join(["%s"] * 15)
                + ")"
            ),
            parameters=(
                context.workload_id,
                context.authority_marker_sha256,
                request.lease_digest_key_id,
                request.lease_digest,
                request.lease_seconds,
                material.receipt_id,
                material.command_id,
                material.identity_key_id,
                material.identity_digest,
                material.payload_hash_key_id,
                material.payload_hash,
                material.audit_event_id,
                material.outbox_event_ids[0],
                material.correlation_id,
                material.trace_id,
            ),
            maximum_rows=2,
        )
        if not rows:
            return None
        projection, replayed = _one_projection(rows)
        return _worker_claim(projection, replayed)

    def start_run(
        self, request: MatchingWorkerStartRunRequest
    ) -> MatchingWorkerRunResult:
        if not isinstance(request, MatchingWorkerStartRunRequest):
            raise TypeError("Matching start run request is unavailable")
        context, material, payload = request.context, request.material, request.payload
        rows = self._gateway.execute(
            write=True,
            scope="MATCHING_WORKER",
            operation="START_MATCH_RUN",
            workload_id=context.workload_id,
            organization_id=request.organization_id,
            authority_marker=context.authority_marker_sha256,
            command_id=material.command_id,
            lease_digest_key_id=request.lease_digest_key_id,
            lease_digest=request.lease_digest,
            statement=(
                "SELECT safe_projection,replayed FROM "
                "matching_api.start_match_run_v1("
                + ",".join(["%s"] * 32)
                + ")"
            ),
            parameters=(
                context.workload_id,
                request.organization_id,
                context.authority_marker_sha256,
                request.job_id,
                request.match_run_id,
                request.fencing_generation,
                request.lease_digest_key_id,
                request.lease_digest,
                payload.canonical_manifest_bytes,
                Jsonb(dict(payload.manifest)),
                payload.manifest_sha256,
                payload.canonical_run_input_bytes,
                Jsonb(dict(payload.run_input)),
                payload.run_input_sha256,
                payload.canonical_input_set_bytes,
                payload.input_set_sha256,
                payload.candidate_allowlist_sha256,
                payload.candidate_count,
                payload.canonical_source_capture_bytes,
                Jsonb(dict(payload.source_capture)),
                payload.source_capture_sha256,
                payload.source_authorization_valid_until,
                material.receipt_id,
                material.command_id,
                material.identity_key_id,
                material.identity_digest,
                material.payload_hash_key_id,
                material.payload_hash,
                material.audit_event_id,
                material.outbox_event_ids[0],
                material.correlation_id,
                material.trace_id,
            ),
            maximum_rows=2,
        )
        projection, replayed = _one_projection(rows)
        return MatchingWorkerRunResult(projection=dict(projection), replayed=replayed)

    def complete_run(
        self, request: MatchingWorkerCompleteRunRequest
    ) -> MatchingWorkerRunResult:
        if not isinstance(request, MatchingWorkerCompleteRunRequest):
            raise TypeError("Matching complete run request is unavailable")
        # This pure re-evaluation deliberately happens before checkout.  SQL
        # binds the immutable capture and lease; Python owns the reviewed engine
        # and candidate-domain hash/rank validation.
        recomputed = evaluate_match_run_v1(request.run_input, request.rule)
        if recomputed != request.result:
            raise MatchingPostgresRejectedError("MATCH_RESULT_INVALID")
        context, material, result = request.context, request.material, recomputed
        rows = self._gateway.execute(
            write=True,
            scope="MATCHING_WORKER",
            operation="COMPLETE_MATCH_RUN",
            workload_id=context.workload_id,
            organization_id=request.organization_id,
            authority_marker=context.authority_marker_sha256,
            command_id=material.command_id,
            lease_digest_key_id=request.lease_digest_key_id,
            lease_digest=request.lease_digest,
            statement=(
                "SELECT safe_projection,replayed FROM "
                "matching_api.complete_match_run_v1("
                + ",".join(["%s"] * 26)
                + ")"
            ),
            parameters=(
                context.workload_id,
                request.organization_id,
                context.authority_marker_sha256,
                request.job_id,
                request.match_run_id,
                request.fencing_generation,
                request.lease_digest_key_id,
                request.lease_digest,
                result.canonical_result_bytes,
                Jsonb(dict(result.result_document)),
                bytes.fromhex(result.engine_result_sha256),
                bytes.fromhex(result.ordered_result_sha256),
                request.system_close_intent_id,
                request.system_close_audit_event_id,
                request.selection_close_intent_event_id,
                request.attempt_close_event_id,
                material.receipt_id,
                material.command_id,
                material.identity_key_id,
                material.identity_digest,
                material.payload_hash_key_id,
                material.payload_hash,
                material.audit_event_id,
                material.outbox_event_ids[0],
                material.correlation_id,
                material.trace_id,
            ),
            maximum_rows=2,
        )
        projection, replayed = _one_projection(rows)
        return MatchingWorkerRunResult(projection=dict(projection), replayed=replayed)

    def fail_run(
        self, request: MatchingWorkerFailRunRequest
    ) -> MatchingWorkerRunResult:
        if not isinstance(request, MatchingWorkerFailRunRequest):
            raise TypeError("Matching fail run request is unavailable")
        context, material = request.context, request.material
        rows = self._gateway.execute(
            write=True,
            scope="MATCHING_WORKER",
            operation="FAIL_MATCH_RUN",
            workload_id=context.workload_id,
            organization_id=request.organization_id,
            authority_marker=context.authority_marker_sha256,
            command_id=material.command_id,
            lease_digest_key_id=request.lease_digest_key_id,
            lease_digest=request.lease_digest,
            statement=(
                "SELECT safe_projection,replayed FROM "
                "matching_api.fail_match_run_v1("
                + ",".join(["%s"] * 22)
                + ")"
            ),
            parameters=(
                context.workload_id,
                request.organization_id,
                context.authority_marker_sha256,
                request.job_id,
                request.match_run_id,
                request.fencing_generation,
                request.lease_digest_key_id,
                request.lease_digest,
                request.failure_code,
                request.retry_run_id,
                request.retry_job_id,
                request.retry_available_at,
                material.receipt_id,
                material.command_id,
                material.identity_key_id,
                material.identity_digest,
                material.payload_hash_key_id,
                material.payload_hash,
                material.audit_event_id,
                material.outbox_event_ids[0],
                material.correlation_id,
                material.trace_id,
            ),
            maximum_rows=2,
        )
        projection, replayed = _one_projection(rows)
        return MatchingWorkerRunResult(projection=dict(projection), replayed=replayed)


@dataclass(frozen=True)
class MatchingCoordinatorClaimRequest:
    context: MatchingWorkloadContext
    lease_digest_key_id: str
    lease_digest: bytes = field(repr=False)
    lease_seconds: int
    material: MatchingOperationalCommandMaterial = field(repr=False)

    def __post_init__(self) -> None:
        _require_workload_context(self.context)
        _require_key(self.lease_digest_key_id)
        _require_digest(self.lease_digest)
        if type(self.lease_seconds) is not int or not 15 <= self.lease_seconds <= 300:
            raise ValueError("Matching coordinator lease is invalid")
        if not isinstance(self.material, MatchingOperationalCommandMaterial):
            raise TypeError("Matching command material is unavailable")
        if self.lease_digest_key_id in {
            self.material.identity_key_id,
            self.material.payload_hash_key_id,
        }:
            raise ValueError("Matching lease key is not purpose-separated")
        _require_outboxes(self.material, 1)


@dataclass(frozen=True)
class MatchingSelectionCompletionClaim:
    completion_job_id: UUID
    organization_id: UUID
    selection_id: UUID
    attempt_id: UUID
    match_run_id: UUID
    intent_receipt_id: UUID
    intent_kind: str
    status: str
    fencing_generation: int
    attempt_count: int
    lease_until: Optional[datetime]
    failure_code: Optional[str]
    original_actor_user_id: UUID
    demand_id: UUID
    prospective_demand_version: int
    demand_version_id: UUID
    demand_content_sha256: bytes = field(repr=False)
    replayed: bool

    def __post_init__(self) -> None:
        _require_uuid(
            self.completion_job_id,
            self.organization_id,
            self.selection_id,
            self.attempt_id,
            self.match_run_id,
            self.intent_receipt_id,
            self.original_actor_user_id,
            self.demand_id,
            self.demand_version_id,
        )
        if self.intent_kind not in {"CHOOSE", "CLOSE", "SYSTEM_CLOSE"}:
            raise ValueError("Matching completion intent is invalid")
        if self.status not in {"LEASED", "FAILED"}:
            raise ValueError("Matching completion status is invalid")
        _require_fence(self.fencing_generation)
        if type(self.attempt_count) is not int or not 1 <= self.attempt_count <= 3:
            raise ValueError("Matching completion attempt count is invalid")
        if (self.status == "LEASED") != (self.lease_until is not None):
            raise ValueError("Matching completion lease projection is invalid")
        if self.lease_until is not None and not _aware_utc(self.lease_until):
            raise ValueError("Matching completion lease time is invalid")
        if self.failure_code is not None:
            _require_code(self.failure_code)
        _require_version(self.prospective_demand_version)
        _require_digest(self.demand_content_sha256)
        if type(self.replayed) is not bool:
            raise TypeError("Matching replay flag is invalid")


@dataclass(frozen=True)
class MatchingCoordinatorCompleteRequest:
    context: MatchingWorkloadContext
    claim: MatchingSelectionCompletionClaim
    lease_digest_key_id: str
    lease_digest: bytes = field(repr=False)
    trust: Optional[MatchingTrustEvidence]
    material: MatchingOperationalCommandMaterial = field(repr=False)

    def __post_init__(self) -> None:
        _require_workload_context(self.context)
        if not isinstance(self.claim, MatchingSelectionCompletionClaim):
            raise TypeError("Matching completion claim is unavailable")
        if not isinstance(self.material, MatchingOperationalCommandMaterial):
            raise TypeError("Matching command material is unavailable")
        _require_key(self.lease_digest_key_id)
        _require_digest(self.lease_digest)
        if self.claim.intent_kind == "CHOOSE":
            if not isinstance(self.trust, MatchingTrustEvidence):
                raise TypeError("Matching completion Trust evidence is unavailable")
            _require_outboxes(self.material, 3)
        elif self.claim.intent_kind in {"CLOSE", "SYSTEM_CLOSE"}:
            if self.trust is not None:
                raise ValueError("Matching close completion cannot carry Trust evidence")
            _require_outboxes(self.material, 2)
        else:
            raise ValueError("Matching completion intent is invalid")


@dataclass(frozen=True)
class MatchingCoordinatorFailRequest:
    context: MatchingWorkloadContext
    claim: MatchingSelectionCompletionClaim
    lease_digest_key_id: str
    lease_digest: bytes = field(repr=False)
    failure_code: str
    retry_available_at: datetime
    material: MatchingOperationalCommandMaterial = field(repr=False)

    def __post_init__(self) -> None:
        _require_workload_context(self.context)
        if not isinstance(self.claim, MatchingSelectionCompletionClaim):
            raise TypeError("Matching completion claim is unavailable")
        _require_key(self.lease_digest_key_id)
        _require_digest(self.lease_digest)
        _require_code(self.failure_code)
        if not _aware_utc(self.retry_available_at):
            raise ValueError("Matching completion retry time is invalid")
        if not isinstance(self.material, MatchingOperationalCommandMaterial):
            raise TypeError("Matching command material is unavailable")
        _require_outboxes(self.material, 1)


@dataclass(frozen=True)
class MatchingSelectionCompletionResult:
    projection: Mapping[str, Any]
    replayed: bool

    def __post_init__(self) -> None:
        _mapping(self.projection)
        if type(self.replayed) is not bool:
            raise TypeError("Matching replay flag is invalid")


class PsycopgMatchingCoordinatorRuntime:
    """Lease/fence-only coordinator gateway; it never calls Demand directly."""

    def __init__(
        self,
        *,
        connections: MatchingPostgresConnectionSource,
        settings: MatchingOperationalPostgresSettings = MatchingOperationalPostgresSettings(),
    ) -> None:
        self._gateway = _RoleGateway(
            connections=connections, role="matching_coordinator", settings=settings
        )

    def close(self) -> None:
        self._gateway.close()

    def check_readiness(self, timeout_ms: int) -> None:
        self._gateway.check_readiness(
            timeout_ms,
            (
                "matching_api.read_runtime_dependency_snapshot_v1()",
                "matching_api.claim_selection_completion_v1(uuid,bytea,uuid,uuid,text,bytea,text,bytea,text,bytea,integer,uuid,uuid,uuid,uuid)",
                "matching_api.complete_claimed_selection_v1(uuid,bytea,uuid,bigint,text,bytea,bytea,timestamptz,timestamptz,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid,uuid,uuid)",
                "matching_api.fail_claimed_selection_v1(uuid,bytea,uuid,bigint,text,bytea,text,timestamptz,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid)",
            ),
        )

    def claim_completion(
        self, request: MatchingCoordinatorClaimRequest
    ) -> Optional[MatchingSelectionCompletionClaim]:
        if not isinstance(request, MatchingCoordinatorClaimRequest):
            raise TypeError("Matching coordinator claim is unavailable")
        context, material = request.context, request.material
        rows = self._gateway.execute(
            write=True,
            scope="MATCHING_COORDINATOR_CLAIM",
            operation="CLAIM_SELECTION_COMPLETION",
            workload_id=context.workload_id,
            authority_marker=context.authority_marker_sha256,
            command_id=material.command_id,
            statement=(
                "SELECT safe_claim,replayed FROM "
                "matching_api.claim_selection_completion_v1("
                + ",".join(["%s"] * 15)
                + ")"
            ),
            parameters=(
                context.workload_id,
                context.authority_marker_sha256,
                material.command_id,
                material.receipt_id,
                material.identity_key_id,
                material.identity_digest,
                material.payload_hash_key_id,
                material.payload_hash,
                request.lease_digest_key_id,
                request.lease_digest,
                request.lease_seconds,
                material.audit_event_id,
                material.outbox_event_ids[0],
                material.correlation_id,
                material.trace_id,
            ),
            maximum_rows=2,
        )
        if not rows:
            return None
        projection, replayed = _one_projection(rows)
        return _completion_claim(projection, replayed)

    def complete_claimed_selection(
        self, request: MatchingCoordinatorCompleteRequest
    ) -> MatchingSelectionCompletionResult:
        if not isinstance(request, MatchingCoordinatorCompleteRequest):
            raise TypeError("Matching coordinator completion is unavailable")
        context, claim, material = request.context, request.claim, request.material
        trust = request.trust
        selection_event = material.outbox_event_ids[0]
        attempt_event = (
            material.outbox_event_ids[1] if claim.intent_kind == "CHOOSE" else None
        )
        demand_event = (
            material.outbox_event_ids[2]
            if claim.intent_kind == "CHOOSE"
            else material.outbox_event_ids[1]
        )
        rows = self._gateway.execute(
            write=True,
            scope="MATCHING_COORDINATOR",
            operation="COMPLETE_SELECTION",
            workload_id=context.workload_id,
            organization_id=claim.organization_id,
            selection_id=claim.selection_id,
            target_id=claim.completion_job_id,
            authority_marker=context.authority_marker_sha256,
            command_id=material.command_id,
            statement=(
                "SELECT safe_projection,replayed FROM "
                "matching_api.complete_claimed_selection_v1("
                + ",".join(["%s"] * 21)
                + ")"
            ),
            parameters=(
                context.workload_id,
                context.authority_marker_sha256,
                claim.completion_job_id,
                claim.fencing_generation,
                request.lease_digest_key_id,
                request.lease_digest,
                None if trust is None else trust.evidence_sha256,
                None if trust is None else trust.evaluated_at,
                None if trust is None else trust.valid_until,
                material.receipt_id,
                material.command_id,
                material.identity_key_id,
                material.identity_digest,
                material.payload_hash_key_id,
                material.payload_hash,
                material.audit_event_id,
                selection_event,
                attempt_event,
                demand_event,
                material.correlation_id,
                material.trace_id,
            ),
            maximum_rows=2,
        )
        projection, replayed = _one_projection(rows)
        return MatchingSelectionCompletionResult(
            projection=dict(projection), replayed=replayed
        )

    def fail_completion(
        self, request: MatchingCoordinatorFailRequest
    ) -> MatchingSelectionCompletionResult:
        if not isinstance(request, MatchingCoordinatorFailRequest):
            raise TypeError("Matching coordinator failure is unavailable")
        context, claim, material = request.context, request.claim, request.material
        rows = self._gateway.execute(
            write=True,
            scope="MATCHING_COORDINATOR",
            operation="FAIL_SELECTION_COMPLETION",
            workload_id=context.workload_id,
            organization_id=claim.organization_id,
            selection_id=claim.selection_id,
            target_id=claim.completion_job_id,
            authority_marker=context.authority_marker_sha256,
            command_id=material.command_id,
            statement=(
                "SELECT safe_result,replayed FROM "
                "matching_api.fail_claimed_selection_v1("
                + ",".join(["%s"] * 18)
                + ")"
            ),
            parameters=(
                context.workload_id,
                context.authority_marker_sha256,
                claim.completion_job_id,
                claim.fencing_generation,
                request.lease_digest_key_id,
                request.lease_digest,
                request.failure_code,
                request.retry_available_at,
                material.receipt_id,
                material.command_id,
                material.identity_key_id,
                material.identity_digest,
                material.payload_hash_key_id,
                material.payload_hash,
                material.audit_event_id,
                material.outbox_event_ids[0],
                material.correlation_id,
                material.trace_id,
            ),
            maximum_rows=2,
        )
        projection, replayed = _one_projection(rows)
        return MatchingSelectionCompletionResult(
            projection=dict(projection), replayed=replayed
        )


@dataclass(frozen=True)
class MatchingOperationalKeyRing:
    """Three purpose-separated active keys owned by one runtime role."""

    identity_key_id: str
    identity_key: bytes | bytearray = field(repr=False)
    payload_hash_key_id: str
    payload_hash_key: bytes | bytearray = field(repr=False)
    lease_digest_key_id: str
    lease_digest_key: bytes | bytearray = field(repr=False)

    def __post_init__(self) -> None:
        for value in (
            self.identity_key_id,
            self.payload_hash_key_id,
            self.lease_digest_key_id,
        ):
            _require_key(value)
        if len(
            {
                self.identity_key_id,
                self.payload_hash_key_id,
                self.lease_digest_key_id,
            }
        ) != 3:
            raise ValueError("Matching operational key IDs must be distinct")
        materials = (
            self.identity_key,
            self.payload_hash_key,
            self.lease_digest_key,
        )
        for value in materials:
            if not isinstance(value, (bytes, bytearray)) or not 32 <= len(value) <= 128:
                raise ValueError("Matching operational key material is invalid")
        if any(
            hmac.compare_digest(materials[left], materials[right])
            for left, right in ((0, 1), (0, 2), (1, 2))
        ):
            raise ValueError("Matching operational keys must be purpose-separated")


@dataclass(frozen=True)
class MatchingOperationalTick:
    status: str
    worked: bool

    def __post_init__(self) -> None:
        if self.status not in {
            "IDLE",
            "DELIVERY_INGESTED",
            "MATCH_COMPLETED",
            "MATCH_LEASE_LOST",
            "MATCH_RETRY_SCHEDULED",
            "MATCH_REVIEW_REQUIRED",
            "SELECTION_COMPLETED",
            "SELECTION_LEASE_LOST",
            "SELECTION_RETRY_SCHEDULED",
            "SELECTION_REVIEW_REQUIRED",
        } or type(self.worked) is not bool:
            raise ValueError("Matching operational tick is invalid")
        if (self.status == "IDLE") == self.worked:
            raise ValueError("Matching operational tick work flag is invalid")


class MatchingWorkerProcess:
    """One bounded delivery-or-worker tick with durable replay identities."""

    def __init__(
        self,
        *,
        runtime: PsycopgMatchingWorkerRuntime,
        demand_delivery: Any,
        demand_capture: Any,
        profile_capture: Any,
        context: MatchingWorkloadContext,
        coordinator_context: MatchingWorkloadContext,
        keys: MatchingOperationalKeyRing,
        default_rule: LoadedMatchingRuleReleaseV1,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        id_source: Callable[[], UUID] = uuid4,
        lease_seconds: int = 60,
        delivery_lease_digest_key_id: str = "demand-matching-delivery-lease-v1",
    ) -> None:
        if not isinstance(runtime, PsycopgMatchingWorkerRuntime):
            raise TypeError("Matching worker runtime is unavailable")
        for dependency, methods in (
            (
                demand_delivery,
                (
                    "claim_matching_requested_delivery",
                    "complete_matching_requested_delivery",
                ),
            ),
            (demand_capture, ("capture_match_inputs",)),
            (profile_capture, ("capture_derived_match_inputs",)),
        ):
            if dependency is None or any(
                not callable(getattr(dependency, method, None))
                for method in methods
            ):
                raise TypeError("Matching worker dependency is unavailable")
        _require_fixed_operational_context(context)
        _require_workload_context(coordinator_context)
        if coordinator_context.workload_id == context.workload_id:
            raise ValueError("Matching worker and coordinator identities overlap")
        if not isinstance(keys, MatchingOperationalKeyRing):
            raise TypeError("Matching worker keys are unavailable")
        _require_rule(default_rule)
        if not callable(clock) or not callable(id_source):
            raise TypeError("Matching worker source is unavailable")
        if type(lease_seconds) is not int or not 15 <= lease_seconds <= 300:
            raise ValueError("Matching worker lease is invalid")
        _require_key(delivery_lease_digest_key_id)
        self._runtime = runtime
        self._demand_delivery = demand_delivery
        self._demand_capture = demand_capture
        self._profile_capture = profile_capture
        self._context = context
        self._coordinator_context = coordinator_context
        self._keys = keys
        self._default_rule = default_rule
        self._clock = clock
        self._id_source = id_source
        self._lease_seconds = lease_seconds
        # Demand owns its retained delivery-key identifiers. Matching job
        # leases keep their own key ID; the HMAC labels separate both uses.
        self._delivery_lease_digest_key_id = delivery_lease_digest_key_id
        self._delivery_slot = _new_operational_slot(id_source)
        self._claim_slot = _new_operational_slot(id_source)

    def run_once(self) -> MatchingOperationalTick:
        now = _operational_now(self._clock)
        delivery_lease = _lease_digest(
            self._keys, "demand-delivery", self._delivery_slot
        )
        from desire_platform.demand.adapters.postgres import (
            DemandMatchingDeliveryContext,
        )

        delivery_context = DemandMatchingDeliveryContext(
            workload_id=self._context.workload_id,
            authority_marker_sha256=self._context.authority_marker_sha256,
        )
        delivery = self._demand_delivery.claim_matching_requested_delivery(
            context=delivery_context,
            lease_digest_key_id=self._delivery_lease_digest_key_id,
            lease_digest=delivery_lease,
            lease_seconds=self._lease_seconds,
        )
        if delivery is not None:
            tick = self._ingest_delivery(
                delivery=delivery,
                delivery_context=delivery_context,
                lease_digest=delivery_lease,
            )
            self._delivery_slot = _new_operational_slot(self._id_source)
            return tick

        claim_lease = _lease_digest(self._keys, "match-job", self._claim_slot)
        claim_material = _operational_material(
            keys=self._keys,
            operation="CLAIM_MATCH_JOB",
            stable_key=str(self._claim_slot),
            payload={
                "lease_digest": claim_lease.hex(),
                "lease_seconds": self._lease_seconds,
            },
            outbox_count=1,
        )
        claim = self._runtime.claim_job(
            MatchingWorkerJobClaimRequest(
                context=self._context,
                lease_digest_key_id=self._keys.lease_digest_key_id,
                lease_digest=claim_lease,
                lease_seconds=self._lease_seconds,
                material=claim_material,
            )
        )
        if claim is None:
            self._claim_slot = _new_operational_slot(self._id_source)
            return MatchingOperationalTick(status="IDLE", worked=False)
        if claim.status == "FAILED":
            self._claim_slot = _new_operational_slot(self._id_source)
            return MatchingOperationalTick(
                status="MATCH_REVIEW_REQUIRED", worked=True
            )

        try:
            tick = self._execute_match(
                claim=claim,
                lease_digest=claim_lease,
                now=now,
            )
        except MatchingPostgresRejectedError as error:
            if error.code != "LEASE_LOST":
                raise
            # A conclusive stale fence can never be recovered by replaying the
            # frozen claim receipt.  Rotate only this claim identity; commit-
            # unknown and every other failure retain it for safe replay.
            self._claim_slot = _new_operational_slot(self._id_source)
            return MatchingOperationalTick(
                status="MATCH_LEASE_LOST", worked=True
            )
        self._claim_slot = _new_operational_slot(self._id_source)
        return tick

    def _ingest_delivery(
        self,
        *,
        delivery: Any,
        delivery_context: Any,
        lease_digest: bytes,
    ) -> MatchingOperationalTick:
        if (
            delivery.authorized_workload_principal_id
            != MATCHING_OPERATIONAL_WORKLOAD_ID
            or delivery.authorization_digest
            != MATCHING_OPERATIONAL_AUTHORITY_MARKER_SHA256
            or delivery.original_actor_user_id == _ZERO_UUID
        ):
            raise MatchingPostgresRejectedError("ACCESS_DENIED")
        if (
            delivery.matching_rule_bundle_id != UUID(self._default_rule.bundle_id)
            or delivery.matching_selector_digest
            != bytes.fromhex(self._default_rule.selector_digest)
        ):
            raise MatchingPostgresRejectedError("MATCH_RULE_BUNDLE_CHANGED")
        self._publish_default_rule(delivery.organization_id)
        source_key = str(delivery.source_event_id)
        requested = _matching_requested_document(delivery)
        ingest = self._runtime.ingest_matching_requested(
            MatchingRequestedIngestRequest(
                context=self._context,
                organization_id=delivery.organization_id,
                requested=requested,
                attempt_id=_operational_uuid(
                    "matching-attempt", source_key
                ),
                run_id=_operational_uuid("match-run", source_key),
                job_id=_operational_uuid("match-job", source_key),
                selection_id=_operational_uuid("selection", source_key),
                coordinator_workload_id=self._coordinator_context.workload_id,
                coordinator_authority_marker_sha256=(
                    self._coordinator_context.authority_marker_sha256
                ),
                material=_operational_material(
                    keys=self._keys,
                    operation="INGEST_MATCHING_REQUESTED",
                    stable_key=source_key,
                    payload=requested,
                    outbox_count=2,
                ),
            )
        )
        self._demand_delivery.complete_matching_requested_delivery(
            context=delivery_context,
            delivery_id=delivery.delivery_id,
            source_event_id=delivery.source_event_id,
            fencing_generation=delivery.fencing_generation,
            lease_digest_key_id=self._delivery_lease_digest_key_id,
            lease_digest=lease_digest,
            matching_attempt_id=ingest.attempt_id,
        )
        return MatchingOperationalTick(status="DELIVERY_INGESTED", worked=True)

    def _publish_default_rule(self, organization_id: UUID) -> None:
        stable_key = f"{organization_id}:{self._default_rule.bundle_id}"
        result = self._runtime.publish_rule_bundle(
            MatchingRulePublicationRequest(
                context=self._context,
                organization_id=organization_id,
                rule=self._default_rule,
                signature_key_id="matching-rule-review-v1",
                review_approval_id=_operational_uuid(
                    "rule-review-approval", self._default_rule.bundle_id
                ),
                review_approval_version=1,
                material=_operational_material(
                    keys=self._keys,
                    operation="PUBLISH_MATCHING_RULE",
                    stable_key=stable_key,
                    payload={
                        "organization_id": str(organization_id),
                        "rule_bundle_id": self._default_rule.bundle_id,
                        "manifest_sha256": (
                            self._default_rule.canonical_manifest_sha256
                        ),
                    },
                    outbox_count=1,
                ),
            )
        )
        if (
            result.rule_bundle_id != UUID(self._default_rule.bundle_id)
            or result.selector_digest
            != bytes.fromhex(self._default_rule.selector_digest)
            or result.canonical_manifest_sha256
            != bytes.fromhex(self._default_rule.canonical_manifest_sha256)
            or result.engine_artifact_sha256
            != bytes.fromhex(self._default_rule.engine_artifact_sha256)
            or result.invitation_limit != self._default_rule.invitation_limit
        ):
            raise MatchingPostgresConfigurationError()

    def _execute_match(
        self,
        *,
        claim: MatchingWorkerJobClaim,
        lease_digest: bytes,
        now: datetime,
    ) -> MatchingOperationalTick:
        from desire_platform.creator_profile.adapters.postgres import (
            CreatorProfilePostgresDerivedMatchCaptureRequest,
        )
        from desire_platform.demand.adapters.postgres import (
            DemandPostgresMatchCaptureRequest,
        )

        demand_capture = self._demand_capture.capture_match_inputs(
            DemandPostgresMatchCaptureRequest(
                match_run_id=claim.match_run_id,
                workload_principal_id=self._context.workload_id,
                matching_request_ids=(claim.matching_request_id,),
                authorization_digest=claim.source_authorization_digest,
                requested_at=now,
            )
        )
        if len(demand_capture.snapshots) != 1:
            raise MatchingPostgresRejectedError("MATCH_INPUT_CHANGED")
        demand_snapshot = demand_capture.snapshots[0]
        demand_context_bytes = _profile_demand_context_bytes(demand_snapshot)
        profile_capture = self._profile_capture.capture_derived_match_inputs(
            CreatorProfilePostgresDerivedMatchCaptureRequest(
                match_run_id=claim.match_run_id,
                workload_id=self._context.workload_id,
                authorization_digest=claim.source_authorization_digest,
                demand_match_context_bytes=demand_context_bytes,
                demand_match_context_sha256=hashlib.sha256(
                    demand_context_bytes
                ).digest(),
            )
        )
        rule = self._runtime.read_rule_bundle(
            context=self._context,
            organization_id=claim.organization_id,
            rule_bundle_id=claim.matching_rule_bundle_id,
            selector_digest=claim.selector_digest,
        )
        if rule.engine_artifact_sha256 != self._default_rule.engine_artifact_sha256:
            raise MatchingPostgresRejectedError("MATCH_RULE_BUNDLE_CHANGED")
        payload, run_input = _compose_start_payload(
            claim=claim,
            demand_capture=demand_capture,
            profile_capture=profile_capture,
            rule=rule,
            workload_id=self._context.workload_id,
        )
        self._runtime.start_run(
            MatchingWorkerStartRunRequest(
                context=self._context,
                organization_id=claim.organization_id,
                job_id=claim.job_id,
                match_run_id=claim.match_run_id,
                fencing_generation=claim.fencing_generation,
                lease_digest_key_id=self._keys.lease_digest_key_id,
                lease_digest=lease_digest,
                payload=payload,
                material=_operational_material(
                    keys=self._keys,
                    operation="START_MATCH_RUN",
                    stable_key=str(claim.match_run_id),
                    payload={
                        "manifest_sha256": payload.manifest_sha256.hex(),
                        "run_input_sha256": payload.run_input_sha256.hex(),
                        "source_capture_sha256": (
                            payload.source_capture_sha256.hex()
                        ),
                    },
                    outbox_count=1,
                ),
            )
        )
        try:
            result = evaluate_match_run_v1(run_input, rule)
        except DeterministicMatcherV1Error:
            return self._fail_started_run(
                claim=claim,
                lease_digest=lease_digest,
                failure_code="MATCH_ENGINE_REJECTED",
            )

        eligible_count = sum(
            item.get("eligibility") == "ELIGIBLE"
            for item in result.candidate_documents
        )
        system_ids: Tuple[Optional[UUID], ...]
        if eligible_count == 0:
            system_ids = tuple(
                _operational_uuid(label, str(claim.match_run_id))
                for label in (
                    "system-close-intent",
                    "system-close-audit",
                    "system-close-selection-event",
                    "system-close-attempt-event",
                )
            )
        else:
            system_ids = (None, None, None, None)
        self._runtime.complete_run(
            MatchingWorkerCompleteRunRequest(
                context=self._context,
                organization_id=claim.organization_id,
                job_id=claim.job_id,
                match_run_id=claim.match_run_id,
                fencing_generation=claim.fencing_generation,
                lease_digest_key_id=self._keys.lease_digest_key_id,
                lease_digest=lease_digest,
                run_input=run_input,
                rule=rule,
                result=result,
                system_close_intent_id=system_ids[0],
                system_close_audit_event_id=system_ids[1],
                selection_close_intent_event_id=system_ids[2],
                attempt_close_event_id=system_ids[3],
                material=_operational_material(
                    keys=self._keys,
                    operation="COMPLETE_MATCH_RUN",
                    stable_key=str(claim.match_run_id),
                    payload={
                        "engine_result_sha256": result.engine_result_sha256,
                        "ordered_result_sha256": result.ordered_result_sha256,
                    },
                    outbox_count=1,
                ),
            )
        )
        return MatchingOperationalTick(status="MATCH_COMPLETED", worked=True)

    def _fail_started_run(
        self,
        *,
        claim: MatchingWorkerJobClaim,
        lease_digest: bytes,
        failure_code: str,
    ) -> MatchingOperationalTick:
        retry = claim.run_attempt < 3
        retry_run_id = (
            _operational_uuid("retry-match-run", str(claim.match_run_id))
            if retry
            else None
        )
        retry_job_id = (
            _operational_uuid("retry-match-job", str(claim.match_run_id))
            if retry
            else None
        )
        retry_at = (
            claim.lease_until + timedelta(seconds=30)
            if retry and claim.lease_until is not None
            else None
        )
        result = self._runtime.fail_run(
            MatchingWorkerFailRunRequest(
                context=self._context,
                organization_id=claim.organization_id,
                job_id=claim.job_id,
                match_run_id=claim.match_run_id,
                fencing_generation=claim.fencing_generation,
                lease_digest_key_id=self._keys.lease_digest_key_id,
                lease_digest=lease_digest,
                failure_code=failure_code,
                retry_run_id=retry_run_id,
                retry_job_id=retry_job_id,
                retry_available_at=retry_at,
                material=_operational_material(
                    keys=self._keys,
                    operation="FAIL_MATCH_RUN",
                    stable_key=str(claim.match_run_id),
                    payload={
                        "failure_code": failure_code,
                        "retry_run_id": (
                            None if retry_run_id is None else str(retry_run_id)
                        ),
                    },
                    outbox_count=1,
                ),
            )
        )
        status = result.projection.get("status")
        return MatchingOperationalTick(
            status=(
                "MATCH_RETRY_SCHEDULED"
                if status == "QUEUED"
                else "MATCH_REVIEW_REQUIRED"
            ),
            worked=True,
        )


class MatchingCoordinatorProcess:
    """One bounded, fenced selection-completion tick."""

    def __init__(
        self,
        *,
        runtime: PsycopgMatchingCoordinatorRuntime,
        context: MatchingWorkloadContext,
        keys: MatchingOperationalKeyRing,
        trust_evidence: Any = None,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        id_source: Callable[[], UUID] = uuid4,
        lease_seconds: int = 60,
    ) -> None:
        if not isinstance(runtime, PsycopgMatchingCoordinatorRuntime):
            raise TypeError("Matching coordinator runtime is unavailable")
        _require_workload_context(context)
        if not isinstance(keys, MatchingOperationalKeyRing):
            raise TypeError("Matching coordinator keys are unavailable")
        if trust_evidence is not None and not (
            callable(trust_evidence)
            or callable(getattr(trust_evidence, "evaluate_for_matching", None))
        ):
            raise TypeError("Matching Trust evidence provider is unavailable")
        if not callable(clock) or not callable(id_source):
            raise TypeError("Matching coordinator source is unavailable")
        if type(lease_seconds) is not int or not 15 <= lease_seconds <= 300:
            raise ValueError("Matching coordinator lease is invalid")
        self._runtime = runtime
        self._context = context
        self._keys = keys
        self._trust_evidence_provider = trust_evidence
        self._clock = clock
        self._id_source = id_source
        self._lease_seconds = lease_seconds
        self._claim_slot = _new_operational_slot(id_source)
        self._trust_by_claim: dict[tuple[UUID, int], MatchingTrustEvidence] = {}

    def run_once(self) -> MatchingOperationalTick:
        now = _operational_now(self._clock)
        lease_digest = _lease_digest(
            self._keys, "selection-completion", self._claim_slot
        )
        claim = self._runtime.claim_completion(
            MatchingCoordinatorClaimRequest(
                context=self._context,
                lease_digest_key_id=self._keys.lease_digest_key_id,
                lease_digest=lease_digest,
                lease_seconds=self._lease_seconds,
                material=_operational_material(
                    keys=self._keys,
                    operation="CLAIM_SELECTION_COMPLETION",
                    stable_key=str(self._claim_slot),
                    payload={
                        "lease_digest": lease_digest.hex(),
                        "lease_seconds": self._lease_seconds,
                    },
                    outbox_count=1,
                ),
            )
        )
        if claim is None:
            self._claim_slot = _new_operational_slot(self._id_source)
            return MatchingOperationalTick(status="IDLE", worked=False)
        if claim.status == "FAILED":
            self._claim_slot = _new_operational_slot(self._id_source)
            return MatchingOperationalTick(
                status="SELECTION_REVIEW_REQUIRED", worked=True
            )

        trust: Optional[MatchingTrustEvidence] = None
        if claim.intent_kind == "CHOOSE":
            cache_key = (claim.completion_job_id, claim.fencing_generation)
            try:
                trust = self._trust_by_claim.get(cache_key)
                if trust is None:
                    trust = _matching_trust_evidence(
                        self._trust_evidence_provider, claim, now,
                        clock=self._clock,
                    )
                    self._trust_by_claim[cache_key] = trust
            except Exception as error:
                tick = self._fail_claim(
                    claim=claim,
                    lease_digest=lease_digest,
                    failure_code=(
                        "TRUST_HOLD_BLOCKED"
                        if isinstance(error, MatchingPostgresRejectedError)
                        and error.code == "TRUST_HOLD_BLOCKED"
                        else "TRUST_EVIDENCE_UNAVAILABLE"
                    ),
                )
                self._trust_by_claim.pop(cache_key, None)
                self._claim_slot = _new_operational_slot(self._id_source)
                return tick

        stable_key = (
            f"{claim.completion_job_id}:{claim.fencing_generation}"
        )
        outbox_count = 3 if claim.intent_kind == "CHOOSE" else 2
        try:
            self._runtime.complete_claimed_selection(
                MatchingCoordinatorCompleteRequest(
                    context=self._context,
                    claim=claim,
                    lease_digest_key_id=self._keys.lease_digest_key_id,
                    lease_digest=lease_digest,
                    trust=trust,
                    material=_operational_material(
                        keys=self._keys,
                        operation="COMPLETE_SELECTION",
                        stable_key=stable_key,
                        payload={
                            "completion_job_id": str(claim.completion_job_id),
                            "fencing_generation": claim.fencing_generation,
                            "intent_kind": claim.intent_kind,
                            "trust_evidence_sha256": (
                                None
                                if trust is None
                                else trust.evidence_sha256.hex()
                            ),
                        },
                        outbox_count=outbox_count,
                    ),
                )
            )
        except MatchingPostgresRejectedError as error:
            if error.code != "LEASE_LOST":
                raise
            self._trust_by_claim.pop(
                (claim.completion_job_id, claim.fencing_generation), None
            )
            self._claim_slot = _new_operational_slot(self._id_source)
            return MatchingOperationalTick(
                status="SELECTION_LEASE_LOST", worked=True
            )
        self._trust_by_claim.pop(
            (claim.completion_job_id, claim.fencing_generation), None
        )
        self._claim_slot = _new_operational_slot(self._id_source)
        return MatchingOperationalTick(status="SELECTION_COMPLETED", worked=True)

    def _fail_claim(
        self,
        *,
        claim: MatchingSelectionCompletionClaim,
        lease_digest: bytes,
        failure_code: str,
    ) -> MatchingOperationalTick:
        retry_at = (
            claim.lease_until + timedelta(seconds=30)
            if claim.lease_until is not None
            else _operational_now(self._clock) + timedelta(seconds=30)
        )
        result = self._runtime.fail_completion(
            MatchingCoordinatorFailRequest(
                context=self._context,
                claim=claim,
                lease_digest_key_id=self._keys.lease_digest_key_id,
                lease_digest=lease_digest,
                failure_code=failure_code,
                retry_available_at=retry_at,
                material=_operational_material(
                    keys=self._keys,
                    operation="FAIL_SELECTION_COMPLETION",
                    stable_key=(
                        f"{claim.completion_job_id}:"
                        f"{claim.fencing_generation}"
                    ),
                    payload={
                        "failure_code": failure_code,
                        "retry_available_at": _timestamp_text(retry_at),
                    },
                    outbox_count=1,
                ),
            )
        )
        return MatchingOperationalTick(
            status=(
                "SELECTION_RETRY_SCHEDULED"
                if result.projection.get("status") == "AVAILABLE"
                else "SELECTION_REVIEW_REQUIRED"
            ),
            worked=True,
        )


class _RoleGateway:
    def __init__(
        self,
        *,
        connections: MatchingPostgresConnectionSource,
        role: str,
        settings: MatchingOperationalPostgresSettings,
    ) -> None:
        if connections is None or any(
            not callable(getattr(connections, name, None))
            for name in ("checkout", "release", "discard")
        ):
            raise TypeError("Matching PostgreSQL connection source is unavailable")
        if role not in {
            "matching_assignment",
            "matching_review",
            "matching_worker",
            "matching_coordinator",
        }:
            raise ValueError("Matching operational role is invalid")
        if not isinstance(settings, MatchingOperationalPostgresSettings):
            raise TypeError("Matching PostgreSQL settings are unavailable")
        self.connections = connections
        self.role = role
        self.settings = settings
        self.closed = False

    def close(self) -> None:
        self.closed = True

    def check_readiness(self, timeout_ms: int, signatures: Tuple[str, ...]) -> None:
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 30_000:
            raise ValueError("Matching readiness timeout is invalid")
        if not signatures:
            raise ValueError("Matching readiness programs are unavailable")
        connection = None
        disposed = False
        try:
            connection = self.connections.checkout()
            _prepare(connection, self.role)
            row = connection.execute(
                "WITH expected(signature) AS (SELECT unnest(%s::text[])),"
                "resolved AS (SELECT signature,to_regprocedure(signature) oid "
                "FROM expected) SELECT count(*)=%s AND bool_and(resolved.oid IS NOT NULL "
                "AND has_function_privilege(session_user,resolved.oid,'EXECUTE') "
                "AND procedure.prosecdef AND owner.rolname='matching_schema_owner' "
                "AND procedure.proconfig=ARRAY['search_path=pg_catalog, matching']::text[] "
                "AND NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(COALESCE("
                "procedure.proacl,pg_catalog.acldefault('f',procedure.proowner))) acl "
                "WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE')) "
                "FROM resolved LEFT JOIN pg_proc procedure ON procedure.oid=resolved.oid "
                "LEFT JOIN pg_roles owner ON owner.oid=procedure.proowner",
                (list(signatures), len(signatures)),
            ).fetchone()
            if row != (True,):
                raise MatchingPostgresConfigurationError()
            if self.role in {"matching_worker", "matching_coordinator"}:
                dependency_row = connection.execute(
                    "SELECT * FROM "
                    "matching_api.read_runtime_dependency_snapshot_v1()"
                ).fetchone()
                if dependency_row != _expected_runtime_dependency_snapshot():
                    raise MatchingPostgresConfigurationError()
            self.connections.release(connection)
            disposed = True
        except BaseException as error:
            if connection is not None and not disposed:
                _discard(self.connections, connection)
                disposed = True
            if isinstance(error, MatchingPostgresError):
                raise
            raise MatchingPostgresConfigurationError() from None
        finally:
            if connection is not None and not disposed:
                _discard(self.connections, connection)

    def execute(
        self,
        *,
        write: bool,
        scope: str,
        operation: str,
        authority_marker: bytes,
        statement: str,
        parameters: Tuple[Any, ...],
        maximum_rows: int,
        actor_user_id: Optional[UUID] = None,
        session_id: Optional[UUID] = None,
        workload_id: Optional[UUID] = None,
        organization_id: Optional[UUID] = None,
        demand_id: Optional[UUID] = None,
        attempt_id: Optional[UUID] = None,
        match_run_id: Optional[UUID] = None,
        invitation_id: Optional[UUID] = None,
        selection_id: Optional[UUID] = None,
        target_id: Optional[UUID] = None,
        command_id: Optional[UUID] = None,
        lease_digest_key_id: Optional[str] = None,
        lease_digest: Optional[bytes] = None,
        rule_bundle_id: Optional[UUID] = None,
    ) -> list[tuple[Any, ...]]:
        if self.closed:
            raise MatchingPostgresConfigurationError()
        connection = None
        state = "NEW"
        disposed = False
        try:
            connection = self.connections.checkout()
            _prepare(connection, self.role)
            connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED")
            state = "BEGUN"
            _configure(
                connection,
                settings=self.settings,
                scope=scope,
                operation=operation,
                authority_marker=authority_marker,
                actor_user_id=actor_user_id,
                session_id=session_id,
                workload_id=workload_id,
                organization_id=organization_id,
                demand_id=demand_id,
                attempt_id=attempt_id,
                match_run_id=match_run_id,
                invitation_id=invitation_id,
                selection_id=selection_id,
                target_id=target_id,
                command_id=command_id,
                lease_digest_key_id=lease_digest_key_id,
                lease_digest=lease_digest,
                rule_bundle_id=rule_bundle_id,
            )
            state = "WRITING" if write else "READING"
            rows = connection.execute(statement, parameters).fetchmany(maximum_rows)
            if not isinstance(rows, list):
                raise MatchingPostgresConfigurationError()
            state = "COMMIT_SENT"
            connection.execute("COMMIT")
            state = "COMMITTED"
            _reset(connection)
            self.connections.release(connection)
            disposed = True
            return rows
        except BaseException as error:
            if connection is not None and state == "COMMIT_SENT":
                _discard(self.connections, connection)
                disposed = True
                if write:
                    raise MatchingPostgresCommitOutcomeUnknownError() from None
                raise MatchingPostgresConfigurationError() from None
            if connection is not None and state in {"BEGUN", "READING", "WRITING"}:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    pass
            if connection is not None and not disposed:
                _discard(self.connections, connection)
                disposed = True
            if isinstance(error, MatchingPostgresError):
                raise
            translated = _database_error(error)
            if translated is not None:
                raise translated from None
            raise MatchingPostgresConfigurationError() from None
        finally:
            if connection is not None and not disposed:
                _discard(self.connections, connection)


def _prepare(connection: Any, role: str) -> None:
    _reset(connection)
    row = connection.execute(
        "SELECT session_user,current_user,"
        "current_setting('server_version_num')::integer/10000"
    ).fetchone()
    if row != (role, role, 18):
        raise MatchingPostgresConfigurationError()


def _configure(
    connection: Any,
    *,
    settings: MatchingOperationalPostgresSettings,
    scope: str,
    operation: str,
    authority_marker: bytes,
    actor_user_id: Optional[UUID],
    session_id: Optional[UUID],
    workload_id: Optional[UUID],
    organization_id: Optional[UUID],
    demand_id: Optional[UUID],
    attempt_id: Optional[UUID],
    match_run_id: Optional[UUID],
    invitation_id: Optional[UUID],
    selection_id: Optional[UUID],
    target_id: Optional[UUID],
    command_id: Optional[UUID],
    lease_digest_key_id: Optional[str],
    lease_digest: Optional[bytes],
    rule_bundle_id: Optional[UUID],
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
        ("app.operation", operation),
        ("app.actor_user_id", _optional(actor_user_id)),
        ("app.session_id", _optional(session_id)),
        ("app.workload_id", _optional(workload_id)),
        ("app.organization_id", _optional(organization_id)),
        ("app.demand_id", _optional(demand_id)),
        ("app.attempt_id", _optional(attempt_id)),
        ("app.match_run_id", _optional(match_run_id)),
        ("app.invitation_id", _optional(invitation_id)),
        ("app.selection_id", _optional(selection_id)),
        ("app.target_id", _optional(target_id)),
        ("app.command_id", _optional(command_id)),
        ("app.authority_marker_sha256", authority_marker.hex()),
        ("app.lease_token_digest_key_id", lease_digest_key_id or ""),
        ("app.lease_token_digest", "" if lease_digest is None else lease_digest.hex()),
        ("app.rule_bundle_id", _optional(rule_bundle_id)),
    )
    for name, value in values:
        row = connection.execute(
            "SELECT pg_catalog.set_config(%s,%s,true)", (name, value)
        ).fetchone()
        # PostgreSQL canonicalizes built-in duration GUCs (for example,
        # ``2000ms`` is returned as ``2s``).  set_config raises on an invalid
        # value, while the security-bearing custom GUCs must echo exactly.
        if (
            row is None
            or len(row) != 1
            or not isinstance(row[0], str)
            or (
                (name == "TimeZone" or name.startswith("app."))
                and row != (value,)
            )
        ):
            raise MatchingPostgresConfigurationError()


def _reset(connection: Any) -> None:
    if (
        getattr(connection, "autocommit", None) is not True
        or getattr(getattr(connection, "info", None), "transaction_status", None)
        != TransactionStatus.IDLE
    ):
        raise MatchingPostgresConfigurationError()
    connection.execute("RESET ROLE")
    connection.execute("RESET ALL")
    connection.execute("CLOSE ALL")
    connection.execute("DISCARD TEMP")


def _discard(source: MatchingPostgresConnectionSource, connection: Any) -> None:
    try:
        source.discard(connection)
    except BaseException:
        pass


def _database_error(error: BaseException) -> Optional[MatchingPostgresRejectedError]:
    message = getattr(getattr(error, "diag", None), "message_primary", None)
    if not isinstance(message, str):
        message = str(error) if isinstance(error, Exception) else ""
    known = {
        "ACCESS_DENIED",
        "CANDIDATE_SELECTOR_ALREADY_ASSIGNED",
        "COMMAND_OUTCOME_UNKNOWN",
        "IDEMPOTENCY_KEY_REUSED",
        "INVALID_REQUEST",
        "INVALID_STATE_TRANSITION",
        "INVITATION_ALREADY_EXISTS",
        "LEASE_LOST",
        "MATCH_INPUT_CHANGED",
        "MATCH_RULE_BUNDLE_CHANGED",
        "PRECONDITION_FAILED",
        "RESOURCE_NOT_FOUND",
        "SELECTION_DECISION_PENDING",
        "SELECTION_NOT_READY",
        "SERVICE_UNAVAILABLE",
        "SOURCE_EVENT_REUSED",
    }
    for code in known:
        if message == code or message.startswith(code + "\n"):
            if code == "COMMAND_OUTCOME_UNKNOWN":
                return MatchingPostgresRejectedError(code)
            return MatchingPostgresRejectedError(code)
    return None


def _expected_runtime_dependency_snapshot() -> tuple[Any, ...]:
    """Exact reviewed database heads consumed by the operational processes."""

    from desire_platform.creator_profile.adapters.postgres.migrations import (
        PROFILE_REQUIRED_IAM_SCHEMA_VERSION,
        PROFILE_REVIEWED_MANIFEST_SHA256,
        PROFILE_SCHEMA_HEAD_VERSION,
    )
    from desire_platform.demand.adapters.postgres.migrations import (
        DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
        DEMAND_REVIEWED_MANIFEST_SHA256,
        DEMAND_SCHEMA_HEAD_VERSION,
    )
    from desire_platform.identity_access.adapters.postgres.migrations import (
        IAM_MAX_APP_COMPATIBLE_VERSION,
        IAM_MIN_APP_COMPATIBLE_VERSION,
        IAM_SCHEMA_HEAD_VERSION,
    )
    from desire_platform.matching.adapters.postgres.migrations import (
        MATCHING_REQUIRED_IAM_SCHEMA_VERSION,
        MATCHING_REVIEWED_MANIFEST_SHA256,
        MATCHING_SCHEMA_HEAD_VERSION,
    )
    from desire_platform.trust_safety.adapters.postgres.migrations import (
        TRUST_REQUIRED_DEMAND_CONTRACT_SHA256,
        TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
        TRUST_REQUIRED_IAM_CONTRACT_SHA256,
        TRUST_REQUIRED_IAM_SCHEMA_VERSION,
        TRUST_REVIEWED_COMBINED_CONTRACT_SHA256,
        TRUST_REVIEWED_MANIFEST_SHA256,
        TRUST_SCHEMA_HEAD_VERSION,
    )

    return (
        MATCHING_SCHEMA_HEAD_VERSION,
        MATCHING_SCHEMA_HEAD_VERSION,
        MATCHING_SCHEMA_HEAD_VERSION,
        MATCHING_SCHEMA_HEAD_VERSION,
        MATCHING_REQUIRED_IAM_SCHEMA_VERSION,
        MATCHING_REVIEWED_MANIFEST_SHA256,
        IAM_SCHEMA_HEAD_VERSION,
        IAM_SCHEMA_HEAD_VERSION,
        IAM_MIN_APP_COMPATIBLE_VERSION,
        IAM_MAX_APP_COMPATIBLE_VERSION,
        TRUST_REQUIRED_IAM_CONTRACT_SHA256,
        DEMAND_SCHEMA_HEAD_VERSION,
        DEMAND_SCHEMA_HEAD_VERSION,
        DEMAND_SCHEMA_HEAD_VERSION,
        DEMAND_SCHEMA_HEAD_VERSION,
        DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
        DEMAND_REVIEWED_MANIFEST_SHA256,
        PROFILE_SCHEMA_HEAD_VERSION,
        PROFILE_SCHEMA_HEAD_VERSION,
        PROFILE_SCHEMA_HEAD_VERSION,
        PROFILE_SCHEMA_HEAD_VERSION,
        PROFILE_REQUIRED_IAM_SCHEMA_VERSION,
        PROFILE_REVIEWED_MANIFEST_SHA256,
        TRUST_SCHEMA_HEAD_VERSION,
        TRUST_SCHEMA_HEAD_VERSION,
        TRUST_SCHEMA_HEAD_VERSION,
        TRUST_SCHEMA_HEAD_VERSION,
        TRUST_REQUIRED_IAM_SCHEMA_VERSION,
        TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
        TRUST_REQUIRED_IAM_CONTRACT_SHA256,
        TRUST_REQUIRED_DEMAND_CONTRACT_SHA256,
        TRUST_REVIEWED_COMBINED_CONTRACT_SHA256,
        TRUST_REVIEWED_MANIFEST_SHA256,
    )


def _candidate_selector_claim(
    value: Mapping[str, Any], replayed: bool
) -> MatchingCandidateSelectorClaimResult:
    _exact_keys(
        value,
        {
            "candidate_selector_assignment_id",
            "candidate_selector_assignment_version",
            "selection_id",
            "attempt_id",
            "demand_id",
            "status",
            "expires_at",
            "selection_status",
            "selection_version",
            "current_invitation_set_sha256",
        },
    )
    return MatchingCandidateSelectorClaimResult(
        assignment_id=_json_uuid(value["candidate_selector_assignment_id"]),
        assignment_version=_version(value["candidate_selector_assignment_version"]),
        selection_id=_json_uuid(value["selection_id"]),
        attempt_id=_json_uuid(value["attempt_id"]),
        demand_id=_json_uuid(value["demand_id"]),
        status=value["status"],
        expires_at=_timestamp(value["expires_at"]),
        selection_status=value["selection_status"],
        selection_version=_version(value["selection_version"]),
        current_invitation_set_sha256=_hex_digest(
            value["current_invitation_set_sha256"]
        ),
        replayed=replayed,
    )


def _worker_claim(
    value: Mapping[str, Any], replayed: bool
) -> MatchingWorkerJobClaim:
    normal = {
        "organization_id",
        "job_id",
        "attempt_id",
        "match_run_id",
        "demand_id",
        "demand_version_id",
        "matching_request_id",
        "matching_rule_bundle_id",
        "selector_digest",
        "source_authorization_digest",
        "job_kind",
        "status",
        "run_status",
        "fencing_generation",
        "lease_until",
        "attempt_count",
        "run_attempt",
        "maximum_run_attempts",
        "recovery_status",
    }
    recovered = normal | {
        "failed_job_id",
        "failed_match_run_id",
        "run_attempt",
        "maximum_run_attempts",
        "failure_code",
    }
    terminal = {
        "organization_id",
        "job_id",
        "attempt_id",
        "match_run_id",
        "demand_id",
        "demand_version_id",
        "matching_request_id",
        "matching_rule_bundle_id",
        "selector_digest",
        "source_authorization_digest",
        "status",
        "run_status",
        "aggregate_version",
        "fencing_generation",
        "run_attempt",
        "maximum_run_attempts",
        "recovery_status",
        "failure_code",
    }
    keys = set(value)
    if keys not in (normal, recovered, terminal):
        raise MatchingPostgresConfigurationError()
    recovery = _text(value, "recovery_status")
    if recovery not in {
        "CLAIMED",
        "QUEUED_LEASE_RECOVERED",
        "RUNNING_LEASE_RETRY_LEASED",
        "REVIEW_REQUIRED",
    }:
        raise MatchingPostgresConfigurationError()
    lease_until = (
        None if "lease_until" not in value else _timestamp(value["lease_until"])
    )
    attempt_count = (
        None
        if "attempt_count" not in value
        else _positive_integer(value["attempt_count"])
    )
    failure = value.get("failure_code")
    if failure is not None and (
        not isinstance(failure, str) or not _CODE.fullmatch(failure)
    ):
        raise MatchingPostgresConfigurationError()
    if (recovery == "REVIEW_REQUIRED") != (value["status"] == "FAILED"):
        raise MatchingPostgresConfigurationError()
    if _integer(value["maximum_run_attempts"]) != 3:
        raise MatchingPostgresConfigurationError()
    return MatchingWorkerJobClaim(
        organization_id=_json_uuid(value["organization_id"]),
        job_id=_json_uuid(value["job_id"]),
        attempt_id=_json_uuid(value["attempt_id"]),
        match_run_id=_json_uuid(value["match_run_id"]),
        demand_id=_json_uuid(value["demand_id"]),
        demand_version_id=_json_uuid(value["demand_version_id"]),
        matching_request_id=_json_uuid(value["matching_request_id"]),
        matching_rule_bundle_id=_json_uuid(value["matching_rule_bundle_id"]),
        selector_digest=_hex_digest(value["selector_digest"]),
        source_authorization_digest=_hex_digest(
            value["source_authorization_digest"]
        ),
        status=_text(value, "status"),
        run_status=_text(value, "run_status"),
        fencing_generation=_version(value["fencing_generation"]),
        lease_until=lease_until,
        attempt_count=attempt_count,
        run_attempt=_positive_integer(value["run_attempt"]),
        recovery_status=recovery,
        failure_code=failure,
        replayed=replayed,
    )


def _completion_claim(
    value: Mapping[str, Any], replayed: bool
) -> MatchingSelectionCompletionClaim:
    _exact_keys(
        value,
        {
            "completion_job_id",
            "organization_id",
            "selection_id",
            "attempt_id",
            "match_run_id",
            "intent_receipt_id",
            "intent_kind",
            "status",
            "fencing_generation",
            "attempt_count",
            "lease_until",
            "failure_code",
            "original_actor_user_id",
            "demand_id",
            "prospective_demand_version",
            "demand_version_id",
            "demand_content_sha256",
        },
    )
    intent = _text(value, "intent_kind")
    status = _text(value, "status")
    failure = value["failure_code"]
    if (
        intent not in {"CHOOSE", "CLOSE", "SYSTEM_CLOSE"}
        or status not in {"LEASED", "FAILED"}
        or (status == "LEASED") != (value["lease_until"] is not None)
        or (failure is not None and (
            not isinstance(failure, str) or not _CODE.fullmatch(failure)
        ))
    ):
        raise MatchingPostgresConfigurationError()
    return MatchingSelectionCompletionClaim(
        completion_job_id=_json_uuid(value["completion_job_id"]),
        organization_id=_json_uuid(value["organization_id"]),
        selection_id=_json_uuid(value["selection_id"]),
        attempt_id=_json_uuid(value["attempt_id"]),
        match_run_id=_json_uuid(value["match_run_id"]),
        intent_receipt_id=_json_uuid(value["intent_receipt_id"]),
        intent_kind=intent,
        status=status,
        fencing_generation=_version(value["fencing_generation"]),
        attempt_count=_positive_integer(value["attempt_count"]),
        lease_until=(
            None if value["lease_until"] is None else _timestamp(value["lease_until"])
        ),
        failure_code=failure,
        original_actor_user_id=_json_uuid(value["original_actor_user_id"]),
        demand_id=_json_uuid(value["demand_id"]),
        prospective_demand_version=_version(value["prospective_demand_version"]),
        demand_version_id=_json_uuid(value["demand_version_id"]),
        demand_content_sha256=_hex_digest(value["demand_content_sha256"]),
        replayed=replayed,
    )


def _review_summary(
    value: Mapping[str, Any], replayed: bool = False
) -> MatchingReviewAssignmentSummary:
    _exact_keys(
        value,
        {
            "assignment_id",
            "organization_id",
            "attempt_id",
            "match_run_id",
            "purpose_code",
            "role_code",
            "status",
            "aggregate_version",
            "expires_at",
        },
    )
    return MatchingReviewAssignmentSummary(
        assignment_id=_json_uuid(value["assignment_id"]),
        organization_id=_json_uuid(value["organization_id"]),
        attempt_id=_json_uuid(value["attempt_id"]),
        match_run_id=_json_uuid(value["match_run_id"]),
        purpose_code=_purpose(value["purpose_code"]),
        role_code=value["role_code"],
        status=value["status"],
        aggregate_version=_version(value["aggregate_version"]),
        expires_at=_timestamp(value["expires_at"]),
        replayed=replayed,
    )


def _review_view(value: Mapping[str, Any]) -> MatchingReviewAssignmentView:
    _exact_keys(
        value,
        {
            "assignment_id",
            "organization_id",
            "attempt_id",
            "match_run_id",
            "purpose_code",
            "role_code",
            "status",
            "aggregate_version",
            "expires_at",
            "attempt",
            "run",
            "eligible_candidates",
            "invitations",
            "actions",
        },
    )
    summary = _review_summary(
        {key: value[key] for key in (
            "assignment_id",
            "organization_id",
            "attempt_id",
            "match_run_id",
            "purpose_code",
            "role_code",
            "status",
            "aggregate_version",
            "expires_at",
        )}
    )
    attempt = _mapping(value["attempt"])
    _exact_keys(
        attempt,
        {
            "attempt_no",
            "status",
            "aggregate_version",
            "updated_at",
            "demand_id",
            "demand_version_id",
            "demand_aggregate_version",
            "demand_content_sha256",
            "input_baseline_sha256",
        },
    )
    attempt_view = MatchingReviewAttemptView(
        attempt_no=_positive_integer(attempt["attempt_no"]),
        status=_text(attempt, "status"),
        aggregate_version=_version(attempt["aggregate_version"]),
        updated_at=_timestamp(attempt["updated_at"]),
        demand_id=_json_uuid(attempt["demand_id"]),
        demand_version_id=_json_uuid(attempt["demand_version_id"]),
        demand_aggregate_version=_version(attempt["demand_aggregate_version"]),
        demand_content_sha256=_hex_digest(attempt["demand_content_sha256"]),
        input_baseline_sha256=_hex_digest(attempt["input_baseline_sha256"]),
    )
    run = _mapping(value["run"])
    _exact_keys(
        run,
        {
            "status",
            "aggregate_version",
            "ordered_result_sha256",
            "candidate_count",
            "eligible_count",
            "excluded_count",
            "failure_code",
        },
    )
    run_view = MatchingReviewRunView(
        status=_text(run, "status"),
        aggregate_version=_version(run["aggregate_version"]),
        ordered_result_sha256=(
            None
            if run["ordered_result_sha256"] is None
            else _hex_digest(run["ordered_result_sha256"])
        ),
        candidate_count=_optional_integer(run["candidate_count"]),
        eligible_count=_optional_integer(run["eligible_count"]),
        excluded_count=_optional_integer(run["excluded_count"]),
        failure_code=(None if run["failure_code"] is None else str(run["failure_code"])),
    )
    candidates = tuple(_review_candidate(item) for item in _sequence(value["eligible_candidates"]))
    invitations = tuple(_review_invitation(item) for item in _sequence(value["invitations"]))
    actions = _mapping(value["actions"])
    _exact_keys(
        actions,
        {"can_create_invitation", "can_publish_invitation", "can_invalidate_attempt"},
    )
    if any(type(actions[key]) is not bool for key in actions):
        raise MatchingPostgresConfigurationError()
    return MatchingReviewAssignmentView(
        assignment=summary,
        attempt=attempt_view,
        run=run_view,
        eligible_candidates=candidates,
        invitations=invitations,
        actions=MatchingReviewActions(**actions),
    )


def _review_candidate(value: Any) -> MatchingReviewCandidateView:
    item = _mapping(value)
    _exact_keys(
        item,
        {
            "creator_user_id",
            "creator_display_handle",
            "profile_id",
            "profile_version_id",
            "profile_content_sha256",
            "evidence_version_digest",
            "total_score",
            "rank",
            "component_scores",
            "candidate_result_sha256",
        },
    )
    return MatchingReviewCandidateView(
        creator_user_id=_json_uuid(item["creator_user_id"]),
        creator_display_handle=_text(item, "creator_display_handle"),
        profile_id=_json_uuid(item["profile_id"]),
        profile_version_id=_json_uuid(item["profile_version_id"]),
        profile_content_sha256=_hex_digest(item["profile_content_sha256"]),
        evidence_version_digest=_hex_digest(item["evidence_version_digest"]),
        total_score=_score_text(item["total_score"]),
        rank=_positive_integer(item["rank"]),
        component_scores=tuple(
            _review_component(component)
            for component in _sequence(item["component_scores"])
        ),
        candidate_result_sha256=_hex_digest(item["candidate_result_sha256"]),
    )


def _review_component(value: Any) -> MatchingReviewComponentScoreView:
    item = _mapping(value)
    _exact_keys(item, {"code", "ordinal", "score"})
    code = _text(item, "code")
    if not re.fullmatch(r"[a-z][a-z0-9_]{1,63}", code):
        raise MatchingPostgresConfigurationError()
    return MatchingReviewComponentScoreView(
        code=code,
        ordinal=_positive_integer(item["ordinal"]),
        score=_score_text(item["score"]),
    )


def _review_invitation(value: Any) -> MatchingReviewInvitationView:
    item = _mapping(value)
    _exact_keys(
        item,
        {
            "invitation_id",
            "creator_user_id",
            "status",
            "aggregate_version",
            "snapshot_sha256",
            "expires_at",
            "updated_at",
        },
    )
    if item["status"] not in _INVITATION_STATUSES:
        raise MatchingPostgresConfigurationError()
    return MatchingReviewInvitationView(
        invitation_id=_json_uuid(item["invitation_id"]),
        creator_user_id=_json_uuid(item["creator_user_id"]),
        status=item["status"],
        aggregate_version=_version(item["aggregate_version"]),
        snapshot_sha256=_hex_digest(item["snapshot_sha256"]),
        expires_at=_timestamp(item["expires_at"]),
        updated_at=_timestamp(item["updated_at"]),
    )


def _invitation_command_result(
    value: Mapping[str, Any], replayed: bool, events: Tuple[str, ...]
) -> MatchingCommandResult:
    _exact_keys(
        value,
        {
            "invitation_id",
            "attempt_id",
            "match_run_id",
            "creator_user_id",
            "status",
            "aggregate_version",
            "updated_at",
            "expires_at",
            "snapshot_sha256",
        },
    )
    return MatchingCommandResult(
        target_id=str(_json_uuid(value["invitation_id"])),
        target_status=_text(value, "status"),
        aggregate_version=_version(value["aggregate_version"]),
        updated_at=_timestamp(value["updated_at"]),
        replayed=replayed,
        event_types=events,
    )


def _attempt_command_result(
    value: Mapping[str, Any], replayed: bool, events: Tuple[str, ...]
) -> MatchingCommandResult:
    _exact_keys(
        value,
        {"attempt_id", "demand_id", "attempt_no", "status", "aggregate_version", "updated_at"},
    )
    return MatchingCommandResult(
        target_id=str(_json_uuid(value["attempt_id"])),
        target_status=_text(value, "status"),
        aggregate_version=_version(value["aggregate_version"]),
        updated_at=_timestamp(value["updated_at"]),
        replayed=replayed,
        event_types=events,
    )


def _one_projection(rows: list[tuple[Any, ...]]) -> Tuple[Mapping[str, Any], bool]:
    if (
        len(rows) != 1
        or not isinstance(rows[0], tuple)
        or len(rows[0]) != 2
        or type(rows[0][1]) is not bool
    ):
        raise MatchingPostgresConfigurationError()
    return _mapping(rows[0][0]), rows[0][1]


def _require_fixed_operational_context(value: Any) -> None:
    _require_workload_context(value)
    if (
        value.workload_id != MATCHING_OPERATIONAL_WORKLOAD_ID
        or not hmac.compare_digest(
            value.authority_marker_sha256,
            MATCHING_OPERATIONAL_AUTHORITY_MARKER_SHA256,
        )
    ):
        raise ValueError("Matching Demand workload identity is not exact")


def _new_operational_slot(id_source: Callable[[], UUID]) -> UUID:
    value = id_source()
    if not isinstance(value, UUID) or value == _ZERO_UUID:
        raise MatchingPostgresConfigurationError()
    return value


def _operational_now(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise MatchingPostgresConfigurationError()
    try:
        result = value.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        raise MatchingPostgresConfigurationError() from None
    if not _aware_utc(result):
        raise MatchingPostgresConfigurationError()
    return result


def _timestamp_text(value: datetime) -> str:
    if not _aware_utc(value):
        raise MatchingPostgresConfigurationError()
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _operational_uuid(label: str, stable_key: str) -> UUID:
    if (
        not isinstance(label, str)
        or not label
        or not isinstance(stable_key, str)
        or not stable_key
    ):
        raise MatchingPostgresConfigurationError()
    return uuid5(_OPERATIONAL_ID_NAMESPACE, f"matching-v3|{label}|{stable_key}")


def _lease_digest(
    keys: MatchingOperationalKeyRing,
    label: str,
    slot: UUID,
) -> bytes:
    if not isinstance(keys, MatchingOperationalKeyRing):
        raise MatchingPostgresConfigurationError()
    _require_uuid(slot)
    if label not in {"demand-delivery", "match-job", "selection-completion"}:
        raise MatchingPostgresConfigurationError()
    return hmac.digest(
        keys.lease_digest_key,
        f"matching-v3|lease|{label}|{slot}".encode("ascii"),
        "sha256",
    )


def _operational_material(
    *,
    keys: MatchingOperationalKeyRing,
    operation: str,
    stable_key: str,
    payload: Mapping[str, Any],
    outbox_count: int,
) -> MatchingOperationalCommandMaterial:
    if not isinstance(keys, MatchingOperationalKeyRing):
        raise MatchingPostgresConfigurationError()
    _require_code(operation)
    if not isinstance(stable_key, str) or not stable_key:
        raise MatchingPostgresConfigurationError()
    if type(outbox_count) is not int or not 1 <= outbox_count <= 100:
        raise MatchingPostgresConfigurationError()
    canonical_payload = _canonical_json_bytes(_mapping(payload))
    identity_message = (
        f"matching-v3|identity|{operation}|{stable_key}".encode("utf-8")
    )
    payload_message = (
        f"matching-v3|payload|{operation}|".encode("ascii")
        + canonical_payload
    )
    id_key = f"{operation}|{stable_key}"
    return MatchingOperationalCommandMaterial(
        command_id=_operational_uuid("command", id_key),
        receipt_id=_operational_uuid("receipt", id_key),
        identity_key_id=keys.identity_key_id,
        identity_digest=hmac.digest(
            keys.identity_key, identity_message, "sha256"
        ),
        payload_hash_key_id=keys.payload_hash_key_id,
        payload_hash=hmac.digest(
            keys.payload_hash_key, payload_message, "sha256"
        ),
        audit_event_id=_operational_uuid("audit", id_key),
        outbox_event_ids=tuple(
            _operational_uuid(f"outbox-{ordinal}", id_key)
            for ordinal in range(1, outbox_count + 1)
        ),
        correlation_id=_operational_uuid("correlation", id_key),
        trace_id=_operational_uuid("trace", id_key),
    )


def _matching_requested_document(delivery: Any) -> Mapping[str, Any]:
    try:
        from desire_platform.demand.adapters.postgres import (
            MatchingRequestedDelivery,
        )

        if not isinstance(delivery, MatchingRequestedDelivery):
            raise TypeError
        return {
            "source_event_id": str(delivery.source_event_id),
            "event_type": delivery.event_type,
            "schema_version": delivery.schema_version,
            "aggregate_type": delivery.aggregate_type,
            "source_aggregate_id": str(delivery.source_aggregate_id),
            "source_aggregate_version": delivery.source_aggregate_version,
            "original_actor_user_id": str(delivery.original_actor_user_id),
            "organization_id": str(delivery.organization_id),
            "demand_id": str(delivery.demand_id),
            "demand_version_id": str(delivery.demand_version_id),
            "envelope_sha256": delivery.envelope_sha256.hex(),
            "demand_content_sha256": delivery.demand_content_sha256.hex(),
            "demand_aggregate_version": delivery.demand_aggregate_version,
            "matching_request_id": str(delivery.matching_request_id),
            "matching_request_version": delivery.matching_request_version,
            "funding_id": str(delivery.funding_id),
            "composite_rule_requirement_id": str(
                delivery.composite_rule_requirement_id
            ),
            "matching_rule_bundle_id": str(delivery.matching_rule_bundle_id),
            "matching_selector_digest": delivery.matching_selector_digest.hex(),
            "rule_requirement_sha256": delivery.rule_requirement_sha256.hex(),
            "authorization_digest": delivery.authorization_digest.hex(),
            "authorized_workload_principal_id": str(
                delivery.authorized_workload_principal_id
            ),
        }
    except (AttributeError, TypeError, ValueError):
        raise MatchingPostgresConfigurationError() from None


def _profile_demand_context_bytes(snapshot: Any) -> bytes:
    try:
        value = {
            "schema_version": 1,
            "canonicalization_version": "profile-match-demand-context-json-v1",
            "organization_id": str(snapshot.organization_id),
            "demand_id": str(snapshot.demand_id),
            "demand_version_id": str(snapshot.demand_version_id),
            "taxonomy_bundle_id": str(snapshot.taxonomy_bundle_id),
            "currency": snapshot.currency,
            "minimum_amount_minor": snapshot.minimum_amount_minor,
            "maximum_amount_minor": snapshot.maximum_amount_minor,
            "allowed_region_codes": list(snapshot.allowed_region_codes),
            "required_language_codes": list(snapshot.required_language_codes),
            "required_work_mode_code": snapshot.required_work_mode_code,
            "data_sensitivity_code": snapshot.data_sensitivity_code,
            "ai_use_code": snapshot.ai_use_code,
        }
        return _canonical_json_bytes(value)
    except (AttributeError, TypeError, ValueError):
        raise MatchingPostgresConfigurationError() from None


def _canonical_document(raw: Any) -> Mapping[str, Any]:
    if not isinstance(raw, bytes) or not raw:
        raise MatchingPostgresConfigurationError()
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise MatchingPostgresConfigurationError() from None
    document = _mapping(value)
    if not hmac.compare_digest(_canonical_json_bytes(document), raw):
        raise MatchingPostgresConfigurationError()
    return document


def _compose_start_payload(
    *,
    claim: MatchingWorkerJobClaim,
    demand_capture: Any,
    profile_capture: Any,
    rule: LoadedMatchingRuleReleaseV1,
    workload_id: UUID,
) -> Tuple[MatchingRunStartPayload, MatchRunInputV1]:
    _require_rule(rule)
    _require_uuid(workload_id)
    try:
        if (
            demand_capture.match_run_id != claim.match_run_id
            or demand_capture.requested_matching_request_ids
            != (claim.matching_request_id,)
            or len(demand_capture.snapshots) != 1
            or profile_capture.match_run_id != claim.match_run_id
            or profile_capture.workload_id != workload_id
            or profile_capture.capture_contract_version != 2
            or profile_capture.status != "COMPLETED"
            or profile_capture.candidate_count != len(profile_capture.snapshots)
            or UUID(rule.bundle_id) != claim.matching_rule_bundle_id
            or bytes.fromhex(rule.selector_digest) != claim.selector_digest
        ):
            raise MatchingPostgresRejectedError("MATCH_INPUT_CHANGED")
        demand_snapshot = demand_capture.snapshots[0]
        if (
            demand_snapshot.organization_id != claim.organization_id
            or demand_snapshot.demand_id != claim.demand_id
            or demand_snapshot.demand_version_id != claim.demand_version_id
            or demand_snapshot.matching_request_id != claim.matching_request_id
            or demand_snapshot.matching_rule_bundle_id
            != claim.matching_rule_bundle_id
            or demand_snapshot.matching_selector_digest != claim.selector_digest
        ):
            raise MatchingPostgresRejectedError("MATCH_INPUT_CHANGED")

        demand_document = demand_postgres_snapshot_to_input_v1(demand_snapshot)
        ordered_snapshots = tuple(
            sorted(
                profile_capture.snapshots,
                key=lambda item: (item.creator_user_id.bytes, item.profile_id.bytes),
            )
        )
        if len({item.creator_user_id for item in ordered_snapshots}) != len(
            ordered_snapshots
        ):
            raise MatchingPostgresRejectedError("MATCH_INPUT_CHANGED")
        profile_documents = tuple(
            _canonical_document(item.canonical_derived_input_bytes)
            for item in ordered_snapshots
        )
        ordered_candidates = [
            {
                "creator_user_id": str(item.creator_user_id),
                "profile_id": str(item.profile_id),
                "profile_version_id": str(item.profile_version_id),
                "profile_content_sha256": item.profile_content_sha256.hex(),
                "evidence_version_digest": item.evidence_version_digest.hex(),
            }
            for item in ordered_snapshots
        ]
        captured_at = _timestamp_text(profile_capture.captured_at)
        manifest_references = {
            "attempt_id": str(claim.attempt_id),
            "run_id": str(claim.match_run_id),
            "organization_id": str(claim.organization_id),
            "demand_id": str(claim.demand_id),
            "demand_version_id": str(claim.demand_version_id),
            "demand_content_sha256": demand_snapshot.content_sha256.hex(),
            "funding_id": str(demand_snapshot.funding_id),
            "matching_request_id": str(claim.matching_request_id),
            "matching_request_version": demand_snapshot.matching_request_version,
            "matching_rule_bundle_id": rule.bundle_id,
            "selector_digest": rule.selector_digest,
            "rule_manifest_sha256": rule.canonical_manifest_sha256,
            "ordered_candidates": ordered_candidates,
            "captured_at": captured_at,
            "candidate_count": len(ordered_snapshots),
        }
        run_without_digest = {
            "schema_version": 1,
            "canonicalization_version": "match-run-input-json-v1",
            "attempt_id": str(claim.attempt_id),
            "run_id": str(claim.match_run_id),
            "demand_id": str(claim.demand_id),
            "demand_version_id": str(claim.demand_version_id),
            "matching_rule_bundle_id": rule.bundle_id,
            "demand": demand_document,
            "profiles": list(profile_documents),
        }
        canonical_input_set_bytes = _canonical_json_bytes(
            {
                "manifest_references": manifest_references,
                "run_input": run_without_digest,
            }
        )
        input_set_sha256 = hashlib.sha256(canonical_input_set_bytes).hexdigest()
        run_input = compose_match_run_input_v1(
            attempt_id=str(claim.attempt_id),
            run_id=str(claim.match_run_id),
            demand_id=str(claim.demand_id),
            demand_version_id=str(claim.demand_version_id),
            matching_rule_bundle_id=rule.bundle_id,
            input_set_sha256=input_set_sha256,
            demand=demand_document,
            profiles=profile_documents,
        )
        run_document = _mapping(json.loads(run_input.canonical_input_bytes))
        manifest = {
            "schema_version": 1,
            "canonicalization_version": "match-input-manifest-v1",
            **manifest_references,
            "input_set_sha256": input_set_sha256,
        }
        canonical_manifest_bytes = _canonical_json_bytes(manifest)
        source_snapshots = []
        for ordinal, item in enumerate(ordered_snapshots, start=1):
            raw_document = _canonical_document(
                item.canonical_profile_version_bytes
            )
            derived_document = _canonical_document(
                item.canonical_derived_input_bytes
            )
            if (
                hashlib.sha256(item.canonical_profile_version_bytes).digest()
                != item.profile_content_sha256
                or hashlib.sha256(item.canonical_derived_input_bytes).digest()
                != item.derived_input_sha256
                or item.taxonomy_bundle_id != demand_snapshot.taxonomy_bundle_id
            ):
                raise MatchingPostgresRejectedError("MATCH_INPUT_CHANGED")
            source_snapshots.append(
                {
                    "snapshot_ordinal": ordinal,
                    "creator_user_id": str(item.creator_user_id),
                    "profile_id": str(item.profile_id),
                    "profile_version_id": str(item.profile_version_id),
                    "version_no": item.version_no,
                    "taxonomy_bundle_id": str(item.taxonomy_bundle_id),
                    "canonical_content_hex": (
                        item.canonical_profile_version_bytes.hex()
                    ),
                    "content": raw_document,
                    "content_sha256": item.profile_content_sha256.hex(),
                    "canonical_derived_input_hex": (
                        item.canonical_derived_input_bytes.hex()
                    ),
                    "derived_input": derived_document,
                    "derived_input_sha256": item.derived_input_sha256.hex(),
                    "evidence_version_digest": (
                        item.evidence_version_digest.hex()
                    ),
                }
            )
        demand_raw_document = _canonical_document(
            demand_snapshot.canonical_demand_version_bytes
        )
        if (
            hashlib.sha256(demand_snapshot.canonical_demand_version_bytes).digest()
            != demand_snapshot.content_sha256
        ):
            raise MatchingPostgresRejectedError("MATCH_INPUT_CHANGED")
        source_capture = {
            "schema_version": 1,
            "canonicalization_version": (
                "matching-source-capture-bundle-json-v1"
            ),
            "match_run_id": str(claim.match_run_id),
            "workload_id": str(workload_id),
            "authorization_digest": claim.source_authorization_digest.hex(),
            "demand": {
                "matching_request_id": str(claim.matching_request_id),
                "demand_id": str(claim.demand_id),
                "demand_version_id": str(claim.demand_version_id),
                "content_sha256": demand_snapshot.content_sha256.hex(),
                "canonical_content_hex": (
                    demand_snapshot.canonical_demand_version_bytes.hex()
                ),
                "content": demand_raw_document,
                "captured_at": _timestamp_text(demand_capture.captured_at),
            },
            "profile": {
                "capture_contract_version": 2,
                "status": "COMPLETED",
                "captured_at": captured_at,
                "authorization_valid_until": _timestamp_text(
                    profile_capture.authorization_valid_until
                ),
                "candidate_count": len(ordered_snapshots),
                "allowlist_sha256": profile_capture.allowlist_sha256.hex(),
                "snapshots": source_snapshots,
            },
        }
        canonical_source_capture_bytes = _canonical_json_bytes(source_capture)
        payload = MatchingRunStartPayload(
            canonical_manifest_bytes=canonical_manifest_bytes,
            manifest=manifest,
            manifest_sha256=hashlib.sha256(canonical_manifest_bytes).digest(),
            canonical_run_input_bytes=run_input.canonical_input_bytes,
            run_input=run_document,
            run_input_sha256=bytes.fromhex(run_input.canonical_input_sha256),
            canonical_input_set_bytes=canonical_input_set_bytes,
            input_set_sha256=bytes.fromhex(input_set_sha256),
            candidate_allowlist_sha256=profile_capture.allowlist_sha256,
            candidate_count=len(ordered_snapshots),
            canonical_source_capture_bytes=canonical_source_capture_bytes,
            source_capture=source_capture,
            source_capture_sha256=hashlib.sha256(
                canonical_source_capture_bytes
            ).digest(),
            source_authorization_valid_until=(
                profile_capture.authorization_valid_until
            ),
        )
        return payload, run_input
    except MatchingPostgresError:
        raise
    except DeterministicMatcherV1Error:
        raise
    except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
        raise MatchingPostgresConfigurationError() from None


def _matching_trust_evidence(
    provider: Any,
    claim: MatchingSelectionCompletionClaim,
    now: datetime,
    *,
    clock: Any,
) -> MatchingTrustEvidence:
    if provider is None:
        raise MatchingPostgresConfigurationError()
    if callable(getattr(provider, "evaluate_for_matching", None)):
        result = provider.evaluate_for_matching(
            actor_id=str(claim.original_actor_user_id),
            organization_id=str(claim.organization_id),
            demand_id=str(claim.demand_id),
            prospective_aggregate_version=claim.prospective_demand_version,
            demand_version_id=str(claim.demand_version_id),
            content_sha256=claim.demand_content_sha256.hex(),
            action="REQUEST_MATCHING",
            policy_version="demand-safety-hold-v1",
        )
        decision = getattr(result.decision, "value", result.decision)
        if decision != "ALLOW":
            raise MatchingPostgresRejectedError("TRUST_HOLD_BLOCKED")
        if (
            result.actor_id != str(claim.original_actor_user_id)
            or result.organization_id != str(claim.organization_id)
            or result.demand_id != str(claim.demand_id)
            or result.prospective_aggregate_version
            != claim.prospective_demand_version
            or result.demand_version_id != str(claim.demand_version_id)
            or result.content_sha256 != claim.demand_content_sha256.hex()
            or result.action != "REQUEST_MATCHING"
            or result.policy_version != "demand-safety-hold-v1"
        ):
            raise MatchingPostgresConfigurationError()
        evidence = MatchingTrustEvidence(
            evidence_id=_operational_uuid(
                "trust-evidence",
                f"{claim.completion_job_id}:{claim.fencing_generation}:"
                f"{result.evidence_sha256.hex()}",
            ),
            evidence_sha256=result.evidence_sha256,
            evaluated_at=result.evaluated_at.astimezone(timezone.utc),
            valid_until=result.valid_until.astimezone(timezone.utc),
        )
    elif callable(provider):
        evidence = provider(claim, now)
    else:
        raise MatchingPostgresConfigurationError()
    # Trust evaluates in its own transaction after the claim. Compare its
    # timestamp with the current clock after that read, not the earlier tick
    # start, which would incorrectly reject every newly-produced SQL evidence.
    checked_at = _operational_now(clock)
    if (
        not isinstance(evidence, MatchingTrustEvidence)
        or evidence.evaluated_at > checked_at
        or evidence.valid_until <= checked_at
    ):
        raise MatchingPostgresConfigurationError()
    return evidence


def _canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise MatchingPostgresConfigurationError() from None


def _mapping(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise MatchingPostgresConfigurationError()
    return value


def _sequence(value: Any) -> Sequence[Any]:
    if not isinstance(value, list):
        raise MatchingPostgresConfigurationError()
    return value


def _exact_keys(value: Mapping[str, Any], keys: set[str]) -> None:
    if set(value) != keys:
        raise MatchingPostgresConfigurationError()


def _text(value: Mapping[str, Any], key: str) -> str:
    result = value.get(key)
    if not isinstance(result, str) or not result:
        raise MatchingPostgresConfigurationError()
    return result


def _json_uuid(value: Any) -> UUID:
    if not isinstance(value, str):
        raise MatchingPostgresConfigurationError()
    return _uuid(value)


def _uuid(value: Any) -> UUID:
    try:
        result = value if isinstance(value, UUID) else UUID(value)
    except (TypeError, ValueError, AttributeError):
        raise MatchingPostgresConfigurationError() from None
    if result == _ZERO_UUID:
        raise MatchingPostgresConfigurationError()
    return result


def _timestamp(value: Any) -> datetime:
    try:
        parsed = parse_utc_timestamp(value)
    except (TypeError, ValueError):
        if isinstance(value, str) and value.endswith("+00:00"):
            try:
                parsed = datetime.fromisoformat(value)
            except ValueError:
                raise MatchingPostgresConfigurationError() from None
        else:
            raise MatchingPostgresConfigurationError() from None
    if not _aware_utc(parsed):
        raise MatchingPostgresConfigurationError()
    return parsed.astimezone(timezone.utc)


def _hex_digest(value: Any) -> bytes:
    if not isinstance(value, str) or len(value) != 64:
        raise MatchingPostgresConfigurationError()
    try:
        result = bytes.fromhex(value)
    except ValueError:
        raise MatchingPostgresConfigurationError() from None
    _require_digest(result)
    return result


def _version(value: Any) -> int:
    if type(value) is not int or value < 1:
        raise MatchingPostgresConfigurationError()
    return value


def _integer(value: Any) -> int:
    if type(value) is not int:
        raise MatchingPostgresConfigurationError()
    return value


def _positive_integer(value: Any) -> int:
    result = _integer(value)
    if result < 1:
        raise MatchingPostgresConfigurationError()
    return result


def _optional_integer(value: Any) -> Optional[int]:
    if value is None:
        return None
    result = _integer(value)
    if result < 0:
        raise MatchingPostgresConfigurationError()
    return result


def _score_text(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, (Decimal, int, str)):
        raise MatchingPostgresConfigurationError()
    try:
        score = Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise MatchingPostgresConfigurationError() from None
    if not score.is_finite() or not Decimal("0") <= score <= Decimal("100"):
        raise MatchingPostgresConfigurationError()
    if score != score.quantize(Decimal("0.01")):
        raise MatchingPostgresConfigurationError()
    return format(score, ".2f")


def _purpose(value: Any) -> str:
    if value not in _REVIEW_PURPOSES:
        raise MatchingPostgresConfigurationError()
    return value


def _optional(value: Optional[UUID]) -> str:
    return "" if value is None else str(value)


def _require_uuid(*values: UUID) -> None:
    if any(not isinstance(value, UUID) or value == _ZERO_UUID for value in values):
        raise ValueError("Matching UUID fact is invalid")


def _require_digest(*values: bytes) -> None:
    if any(not isinstance(value, bytes) or len(value) != 32 for value in values):
        raise ValueError("Matching digest is invalid")


def _require_key(value: str) -> None:
    if not isinstance(value, str) or not _KEY_ID.fullmatch(value):
        raise ValueError("Matching key identifier is invalid")


def _require_code(value: str) -> None:
    if not isinstance(value, str) or not _CODE.fullmatch(value):
        raise ValueError("Matching code is invalid")


def _require_version(*values: int) -> None:
    if any(type(value) is not int or value < 1 for value in values):
        raise ValueError("Matching aggregate version is invalid")


def _require_outboxes(
    material: MatchingOperationalCommandMaterial, count: int
) -> None:
    if len(material.outbox_event_ids) != count:
        raise ValueError("Matching outbox event count is invalid")


def _require_review_context(value: Any) -> None:
    if not isinstance(value, MatchingReviewContext):
        raise TypeError("Matching review context is unavailable")


def _require_workload_context(value: Any) -> None:
    if not isinstance(value, MatchingWorkloadContext):
        raise TypeError("Matching workload context is unavailable")


def _require_rule(value: Any) -> None:
    if not isinstance(value, LoadedMatchingRuleReleaseV1):
        raise TypeError("Matching rule release is unavailable")
    try:
        reloaded = load_rule_release_v1(
            value.canonical_manifest_bytes,
            expected_manifest_sha256=value.canonical_manifest_sha256,
        )
    except Exception:
        raise ValueError("Matching rule release is invalid") from None
    if reloaded != value:
        raise ValueError("Matching rule release is invalid")


def _require_fence(value: int) -> None:
    if type(value) is not int or value < 1:
        raise ValueError("Matching fencing generation is invalid")


def _aware_utc(value: Any) -> bool:
    return (
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() is not None
        and value.utcoffset().total_seconds() == 0
    )


__all__ = (
    "MATCHING_OPERATIONAL_AUTHORITY_MARKER_SHA256",
    "MATCHING_OPERATIONAL_WORKLOAD_ID",
    "MatchingAssignmentContext",
    "MatchingCandidateSelectorClaimRequest",
    "MatchingCandidateSelectorClaimResult",
    "MatchingCoordinatorClaimRequest",
    "MatchingCoordinatorCompleteRequest",
    "MatchingCoordinatorFailRequest",
    "MatchingOperationalCommandMaterial",
    "MatchingOperationalKeyRing",
    "MatchingOperationalPostgresSettings",
    "MatchingOperationalTick",
    "MatchingPreparedInvitationDisclosure",
    "MatchingRequestedIngestRequest",
    "MatchingRequestedIngestResult",
    "MatchingReviewActions",
    "MatchingReviewAssignmentSummary",
    "MatchingReviewAssignmentView",
    "MatchingReviewAttemptView",
    "MatchingReviewCandidateView",
    "MatchingReviewComponentScoreView",
    "MatchingReviewClaimRequest",
    "MatchingReviewContext",
    "MatchingReviewCreateInvitationRequest",
    "MatchingReviewInvalidateAttemptRequest",
    "MatchingReviewInvitationView",
    "MatchingReviewPrepareInvitationRequest",
    "MatchingReviewPublishInvitationRequest",
    "MatchingReviewReleaseRequest",
    "MatchingReviewerAssignmentResolution",
    "MatchingReviewRunView",
    "MatchingRulePublicationRequest",
    "MatchingRulePublicationResult",
    "MatchingRunStartPayload",
    "MatchingSelectionCompletionClaim",
    "MatchingSelectionCompletionResult",
    "MatchingTrustEvidence",
    "MatchingWorkloadContext",
    "MatchingWorkerCompleteRunRequest",
    "MatchingWorkerFailRunRequest",
    "MatchingWorkerJobClaim",
    "MatchingWorkerJobClaimRequest",
    "MatchingWorkerRunResult",
    "MatchingWorkerStartRunRequest",
    "MatchingWorkerProcess",
    "MatchingCoordinatorProcess",
    "PsycopgMatchingAssignmentRuntime",
    "PsycopgMatchingCoordinatorRuntime",
    "PsycopgMatchingReviewRuntime",
    "PsycopgMatchingWorkerRuntime",
)
