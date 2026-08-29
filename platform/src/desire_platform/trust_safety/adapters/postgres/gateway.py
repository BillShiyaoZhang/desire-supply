"""Closed PostgreSQL gateway for the Trust0001 fixed programs.

The command surface has nine named methods and the read surface has seven.  No
caller can supply a function name, SQL fragment, table name, or result mapper.
Connections are role-isolated and every checkout is reset and compatibility
checked before use.  A COMMIT transport failure is surfaced to the production
handler, which recovers only through the authority-first completed-receipt
probe; the gateway never repeats a mutating call by itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import re
from typing import Any, Mapping, Optional, Tuple
from uuid import UUID

from psycopg.pq import TransactionStatus

from desire_platform.utc import parse_utc_timestamp

from ._session_settings import set_config_result_matches

from ...application.commands import TrustCommandResult
from ...domain import SafetyCaseStatus
from .migrations import (
    TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
    TRUST_REQUIRED_IAM_SCHEMA_VERSION,
    TRUST_SCHEMA_HEAD_VERSION,
)


_KEY_ID = re.compile(r"[a-z0-9][a-z0-9-]{2,127}\Z")
_CODE = re.compile(r"[A-Z][A-Z0-9_]{1,63}\Z")
_SEALED_REFERENCE = re.compile(
    r"sealed://trust/[a-z0-9][a-z0-9/_-]{4,255}\Z"
)
_ENTITY_TAG = re.compile(r'"trust-[1-9][0-9]*-[a-f0-9]{24}"\Z')

_REPORT_CATEGORIES = frozenset(
    {
        "DATA_EXPOSURE",
        "FRAUD_RISK",
        "HARASSMENT",
        "RETALIATION",
        "WORKFLOW_INTEGRITY",
    }
)
_IMPACT_CODES = frozenset(
    {
        "SYNTHETIC_DATA_DISCLOSED",
        "SYNTHETIC_FINANCIAL_RISK",
        "WORKFLOW_INTEGRITY_RISK",
        "PARTICIPANT_SAFETY_RISK",
        "RETALIATION_RISK",
    }
)
_PROTECTION_CODES = frozenset(
    {"PAUSE_SUBMISSION", "PAUSE_VERIFICATION", "PAUSE_MATCHING"}
)
_PRIORITY_CODES = frozenset({"P0", "P1", "P2", "P3"})
_JURISDICTION_CODES = frozenset(
    {"PLATFORM_INTERNAL", "ORGANIZATION_POLICY", "LEGAL_REVIEW_REQUIRED"}
)
_SEVERITY_CODES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})
_ISSUE_CODES = frozenset(
    {
        "DATA_HANDLING_GAP",
        "SCOPE_DISCLOSURE_RISK",
        "FRAUD_INDICATOR",
        "HARASSMENT_INDICATOR",
        "RETALIATION_INDICATOR",
        "WORKFLOW_INTEGRITY_GAP",
    }
)
_INVESTIGATION_CODES = frozenset(
    {
        "CHECK_ACCESS_SCOPE",
        "CHECK_DEMAND_VERSION",
        "CHECK_POLICY_REQUIREMENTS",
        "CHECK_SYNTHETIC_EVIDENCE",
        "REQUEST_PARTY_CLARIFICATION",
    }
)
_HOLD_ACTIONS = frozenset(
    {"REQUEST_MATCHING", "SUBMIT_DEMAND", "VERIFY_DEMAND"}
)
_HOLD_REASONS = frozenset(
    {
        "PARTICIPANT_SAFETY_RISK",
        "RETALIATION_RISK",
        "SYNTHETIC_DATA_EXPOSURE_RISK",
        "WORKFLOW_INTEGRITY_RISK",
    }
)
_ASSIGNMENT_RELEASE_REASONS = frozenset(
    {"CONFLICT_DECLARED", "WORKLOAD_RELEASE", "ASSIGNMENT_EXPIRED"}
)
_HOLD_RELEASE_REASONS = frozenset(
    {"CASE_DECIDED", "RISK_MITIGATED", "SUPERSEDED", "TTL_CORRECTION"}
)
_OUTCOMES = frozenset(
    {
        "NO_ACTION",
        "PROTECTION_LIFTED",
        "PROTECTION_MAINTAINED",
        "PROTECTION_MODIFIED",
        "REMEDIATION_REQUIRED",
    }
)
_OUTCOME_REASONS = frozenset(
    {
        "INSUFFICIENT_VERIFIED_EVIDENCE",
        "NO_POLICY_BREACH",
        "POLICY_REQUIREMENT_NOT_MET",
        "PRECAUTIONARY_ACTION_REQUIRED",
        "RISK_MITIGATED",
    }
)
_EVENT_TYPES = {
    "SUBMIT_REPORT": "TrustReportSubmitted",
    "CLAIM_CASE": "TrustCaseClaimed",
    "RELEASE_CASE_ASSIGNMENT": "TrustCaseAssignmentReleased",
    "SAVE_TRIAGE_DRAFT": "TrustTriageDraftSaved",
    "PUBLISH_TRIAGE": "TrustTriagePublished",
    "PLACE_HOLD": "SafetyHoldPlaced",
    "CLAIM_HOLD_RELEASE": "TrustHoldReleaseClaimed",
    "RELEASE_HOLD": "SafetyHoldReleased",
    "PUBLISH_OUTCOME": "TrustCaseOutcomePublished",
}
_SAFE_RESULT_KEYS = frozenset(
    {
        "aggregate_version",
        "assignment_id",
        "case_id",
        "case_status",
        "completed_at",
        "event_types",
        "hold_id",
        "hold_version",
        "outcome_version_id",
        "report_id",
        "triage_draft_version",
        "triage_version",
    }
)


class TrustPostgresError(RuntimeError):
    """Closed PostgreSQL boundary error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class TrustPostgresConfigurationError(TrustPostgresError):
    def __init__(self) -> None:
        super().__init__("SERVICE_UNAVAILABLE")


class TrustPostgresCommitOutcomeUnknownError(TrustPostgresError):
    def __init__(self) -> None:
        super().__init__("COMMAND_OUTCOME_UNKNOWN")


class TrustPostgresRejectedError(TrustPostgresError):
    pass


@dataclass(frozen=True)
class TrustPostgresGatewaySettings:
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
            raise ValueError("Trust PostgreSQL gateway settings are invalid")


@dataclass(frozen=True)
class TrustPostgresCommandContext:
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
class TrustPostgresReceiptMaterial:
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
            raise ValueError("Trust PostgreSQL write IDs must be distinct")
        _require_key_material(
            self.idempotency_key_digest_key_ids,
            self.idempotency_key_digests,
        )
        _require_key_material(self.payload_hash_key_ids, self.payload_hashes)
        if set(self.idempotency_key_digest_key_ids) & set(
            self.payload_hash_key_ids
        ):
            raise ValueError("Trust PostgreSQL key purposes must be disjoint")


@dataclass(frozen=True)
class TrustPostgresReplayMaterial:
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
        if set(self.idempotency_key_digest_key_ids) & set(
            self.payload_hash_key_ids
        ):
            raise ValueError("Trust PostgreSQL key purposes must be disjoint")


@dataclass(frozen=True)
class TrustCompletedReceiptProbeRequest:
    context: TrustPostgresCommandContext
    material: TrustPostgresReplayMaterial = field(repr=False)
    operation: str
    organization_id: Optional[UUID]
    target_id: Optional[UUID]
    expected_version: Optional[int]

    def __post_init__(self) -> None:
        if not isinstance(self.context, TrustPostgresCommandContext) or not isinstance(
            self.material, TrustPostgresReplayMaterial
        ):
            raise TypeError("Trust receipt probe dependencies are unavailable")
        if self.operation not in _EVENT_TYPES:
            raise ValueError("Trust receipt probe operation is invalid")
        if self.operation == "SUBMIT_REPORT":
            if (
                not isinstance(self.organization_id, UUID)
                or self.organization_id.int == 0
                or self.target_id is not None
                or self.expected_version is not None
            ):
                raise ValueError("Trust reporter receipt probe is invalid")
        elif (
            self.organization_id is not None
            or not isinstance(self.target_id, UUID)
            or self.target_id.int == 0
            or type(self.expected_version) is not int
            or self.expected_version < 1
        ):
            raise ValueError("Trust officer receipt probe is invalid")


@dataclass(frozen=True)
class SubmitReportPostgresRequest:
    context: TrustPostgresCommandContext
    receipt: TrustPostgresReceiptMaterial
    organization_id: UUID
    report_id: UUID
    case_id: UUID
    demand_id: UUID
    demand_version_id: UUID
    category: str
    incident_started_at: datetime
    incident_ended_at: Optional[datetime]
    impact_codes: Tuple[str, ...]
    evidence_reference_ids: Tuple[UUID, ...] = field(repr=False)
    requested_protection_codes: Tuple[str, ...]

    def __post_init__(self) -> None:
        _require_request(self.context, self.receipt)
        _require_uuids(
            self.organization_id,
            self.report_id,
            self.case_id,
            self.demand_id,
            self.demand_version_id,
        )
        if len(
            {
                self.context.actor_user_id,
                self.organization_id,
                self.report_id,
                self.case_id,
                self.demand_id,
                self.demand_version_id,
            }
        ) != 6:
            raise ValueError("Trust report identities must be distinct")
        _require_enum(self.category, _REPORT_CATEGORIES)
        _require_utc(self.incident_started_at)
        if self.incident_ended_at is not None:
            _require_utc(self.incident_ended_at)
            if self.incident_ended_at < self.incident_started_at:
                raise ValueError("Trust report incident window is invalid")
        _require_codes(self.impact_codes, _IMPACT_CODES, 1, 16)
        _require_uuid_tuple(self.evidence_reference_ids, 1, 32)
        _require_codes(
            self.requested_protection_codes,
            _PROTECTION_CODES,
            1,
            3,
        )


@dataclass(frozen=True)
class ClaimCasePostgresRequest:
    context: TrustPostgresCommandContext
    receipt: TrustPostgresReceiptMaterial
    assignment_id: UUID
    case_id: UUID
    expected_case_version: int

    def __post_init__(self) -> None:
        _require_request(self.context, self.receipt)
        _require_uuids(self.assignment_id, self.case_id)
        _require_version(self.expected_case_version)


@dataclass(frozen=True)
class ReleaseCaseAssignmentPostgresRequest:
    context: TrustPostgresCommandContext
    receipt: TrustPostgresReceiptMaterial
    case_id: UUID
    expected_case_version: int
    reason_code: str

    def __post_init__(self) -> None:
        _require_request(self.context, self.receipt)
        _require_uuids(self.case_id)
        _require_version(self.expected_case_version)
        _require_enum(self.reason_code, _ASSIGNMENT_RELEASE_REASONS)


@dataclass(frozen=True)
class SaveTriageDraftPostgresRequest:
    context: TrustPostgresCommandContext
    receipt: TrustPostgresReceiptMaterial
    case_id: UUID
    expected_case_version: int
    priority_code: str
    jurisdiction_code: str
    severity_code: str
    issue_codes: Tuple[str, ...]
    investigation_step_codes: Tuple[str, ...]
    proposed_hold_actions: Tuple[str, ...]
    proposed_hold_ttl_minutes: int
    sealed_note_reference: str = field(repr=False)
    sealed_note_sha256: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _require_request(self.context, self.receipt)
        _require_uuids(self.case_id)
        _require_version(self.expected_case_version)
        _require_enum(self.priority_code, _PRIORITY_CODES)
        _require_enum(self.jurisdiction_code, _JURISDICTION_CODES)
        _require_enum(self.severity_code, _SEVERITY_CODES)
        _require_codes(self.issue_codes, _ISSUE_CODES, 1, 16)
        _require_codes(
            self.investigation_step_codes,
            _INVESTIGATION_CODES,
            1,
            16,
        )
        _require_codes(self.proposed_hold_actions, _HOLD_ACTIONS, 1, 3)
        if (
            type(self.proposed_hold_ttl_minutes) is not int
            or not 15 <= self.proposed_hold_ttl_minutes <= 10_080
            or not isinstance(self.sealed_note_reference, str)
            or _SEALED_REFERENCE.fullmatch(self.sealed_note_reference) is None
            or not _digest(self.sealed_note_sha256)
        ):
            raise ValueError("Trust triage draft is invalid")


@dataclass(frozen=True)
class PublishTriagePostgresRequest:
    context: TrustPostgresCommandContext
    receipt: TrustPostgresReceiptMaterial
    case_id: UUID
    expected_case_version: int
    expected_draft_version: int

    def __post_init__(self) -> None:
        _require_request(self.context, self.receipt)
        _require_uuids(self.case_id)
        _require_version(self.expected_case_version)
        _require_version(self.expected_draft_version)


@dataclass(frozen=True)
class PlaceHoldPostgresRequest:
    context: TrustPostgresCommandContext
    receipt: TrustPostgresReceiptMaterial
    hold_id: UUID
    case_id: UUID
    expected_case_version: int
    action_codes: Tuple[str, ...]
    reason_code: str
    hold_ttl_minutes: int

    def __post_init__(self) -> None:
        _require_request(self.context, self.receipt)
        _require_uuids(self.hold_id, self.case_id)
        _require_version(self.expected_case_version)
        _require_codes(self.action_codes, _HOLD_ACTIONS, 1, 3)
        _require_enum(self.reason_code, _HOLD_REASONS)
        if type(self.hold_ttl_minutes) is not int or not 15 <= self.hold_ttl_minutes <= 10_080:
            raise ValueError("Trust hold TTL is invalid")


@dataclass(frozen=True)
class ClaimHoldReleasePostgresRequest:
    context: TrustPostgresCommandContext
    receipt: TrustPostgresReceiptMaterial
    assignment_id: UUID
    hold_id: UUID
    expected_hold_version: int

    def __post_init__(self) -> None:
        _require_request(self.context, self.receipt)
        _require_uuids(self.assignment_id, self.hold_id)
        _require_version(self.expected_hold_version)


@dataclass(frozen=True)
class ReleaseHoldPostgresRequest:
    context: TrustPostgresCommandContext
    receipt: TrustPostgresReceiptMaterial
    hold_id: UUID
    expected_hold_version: int
    release_reason_code: str

    def __post_init__(self) -> None:
        _require_request(self.context, self.receipt)
        _require_uuids(self.hold_id)
        _require_version(self.expected_hold_version)
        _require_enum(self.release_reason_code, _HOLD_RELEASE_REASONS)


@dataclass(frozen=True)
class TrustOutcomePostgresEvidence:
    case_id: UUID
    case_aggregate_version: int
    triage_version: int
    outcome_code: str
    reason_codes: Tuple[str, ...]
    action_codes: Tuple[str, ...]
    evidence_packet_version_id: UUID
    evidence_packet_digest: bytes = field(repr=False)
    source_digest: bytes = field(repr=False)
    appeal_eligible: bool
    appeal_eligibility_code: str
    appeal_deadline: Optional[datetime]
    policy_version: str
    redaction_profile_code: str
    evaluated_at: datetime
    valid_until: datetime

    def __post_init__(self) -> None:
        _require_uuids(self.case_id, self.evidence_packet_version_id)
        _require_version(self.case_aggregate_version)
        _require_version(self.triage_version)
        _require_enum(self.outcome_code, _OUTCOMES)
        _require_codes(self.reason_codes, _OUTCOME_REASONS, 1, 8)
        _require_codes(self.action_codes, _HOLD_ACTIONS, 0, 3)
        if (
            not _digest(self.evidence_packet_digest)
            or not _digest(self.source_digest)
            or type(self.appeal_eligible) is not bool
            or self.appeal_eligibility_code not in {"ELIGIBLE", "NOT_ELIGIBLE"}
            or self.appeal_eligible
            != (self.appeal_eligibility_code == "ELIGIBLE")
            or self.policy_version != "trust-case-outcome-v1"
            or self.redaction_profile_code
            not in {"OFFICER_RESTRICTED_V1", "PARTY_SAFE_V1"}
        ):
            raise ValueError("Trust outcome evidence is invalid")
        _require_utc(self.evaluated_at)
        _require_utc(self.valid_until)
        if self.evaluated_at >= self.valid_until:
            raise ValueError("Trust outcome evidence window is invalid")
        if self.appeal_eligible:
            if self.appeal_deadline is None:
                raise ValueError("Trust appeal deadline is required")
            _require_utc(self.appeal_deadline)
            if self.appeal_deadline <= self.evaluated_at:
                raise ValueError("Trust appeal deadline is invalid")
        elif self.appeal_deadline is not None:
            raise ValueError("Trust appeal deadline is forbidden")


@dataclass(frozen=True)
class PublishOutcomePostgresRequest:
    context: TrustPostgresCommandContext
    receipt: TrustPostgresReceiptMaterial
    outcome_version_id: UUID
    case_id: UUID
    expected_case_version: int
    outcome_code: str
    reason_codes: Tuple[str, ...]
    action_codes: Tuple[str, ...]
    evidence: TrustOutcomePostgresEvidence = field(repr=False)

    def __post_init__(self) -> None:
        _require_request(self.context, self.receipt)
        _require_uuids(self.outcome_version_id, self.case_id)
        _require_version(self.expected_case_version)
        _require_enum(self.outcome_code, _OUTCOMES)
        _require_codes(self.reason_codes, _OUTCOME_REASONS, 1, 8)
        _require_codes(self.action_codes, _HOLD_ACTIONS, 0, 3)
        if (
            not isinstance(self.evidence, TrustOutcomePostgresEvidence)
            or self.evidence.case_id != self.case_id
            or self.evidence.case_aggregate_version != self.expected_case_version
            or self.evidence.outcome_code != self.outcome_code
            or self.evidence.reason_codes != self.reason_codes
            or self.evidence.action_codes != self.action_codes
        ):
            raise ValueError("Trust outcome evidence does not echo the command")


@dataclass(frozen=True)
class TrustPostgresProjection:
    kind: str
    projection: Mapping[str, Any] = field(repr=False)
    response_entity_tag: str

    def __post_init__(self) -> None:
        if self.kind not in {
            "REPORT",
            "CASE",
            "CASE_QUEUE",
            "HOLD_RELEASE_QUEUE",
            "MY_ACTIVE_CASE_ASSIGNMENTS",
            "MY_COMPLETED_CASE_ASSIGNMENTS",
            "ASSIGNED_HOLD_RELEASE",
        }:
            raise TrustPostgresConfigurationError()
        object.__setattr__(self, "projection", dict(self.projection))


@dataclass(frozen=True)
class TrustPostgresOwnedReportPage:
    projection: Mapping[str, Any] = field(repr=False)
    response_entity_tag: str
    next_created_at: Optional[datetime]
    next_report_id: Optional[UUID]

    def __post_init__(self) -> None:
        document = dict(self.projection)
        _validate_owned_report_list_projection(document)
        _require_entity_tag(self.response_entity_tag)
        if document["entity_tag"] != self.response_entity_tag:
            raise TrustPostgresConfigurationError()
        if (self.next_created_at is None) != (self.next_report_id is None):
            raise TrustPostgresConfigurationError()
        if self.next_created_at is not None:
            _require_utc(self.next_created_at)
            _require_uuids(self.next_report_id)
            if not document["items"]:
                raise TrustPostgresConfigurationError()
        object.__setattr__(self, "projection", document)


class PsycopgTrustCommandGateway:
    """Invoke only the nine reviewed Trust write programs."""

    def __init__(
        self,
        *,
        reporter_connections: Any,
        officer_connections: Any,
        settings: TrustPostgresGatewaySettings = TrustPostgresGatewaySettings(),
    ) -> None:
        _require_sources(reporter_connections, officer_connections)
        if not isinstance(settings, TrustPostgresGatewaySettings):
            raise TypeError("Trust PostgreSQL gateway settings are unavailable")
        self._reporter_connections = reporter_connections
        self._officer_connections = officer_connections
        self._settings = settings
        self._closed = False

    def submit_report(
        self, request: SubmitReportPostgresRequest
    ) -> TrustCommandResult:
        _require_type(request, SubmitReportPostgresRequest)
        context, receipt = request.context, request.receipt
        return self._run(
            source=self._reporter_connections,
            role="trust_self",
            operation="SUBMIT_REPORT",
            request=request,
            statement=(
                "SELECT safe_response,replayed FROM trust_api.submit_report_v1("
                + ",".join(["%s"] * 23)
                + ")"
            ),
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
                request.report_id,
                request.case_id,
                list(receipt.idempotency_key_digest_key_ids),
                list(receipt.idempotency_key_digests),
                list(receipt.payload_hash_key_ids),
                list(receipt.payload_hashes),
                request.demand_id,
                request.demand_version_id,
                request.category,
                request.incident_started_at,
                request.incident_ended_at,
                list(request.impact_codes),
                list(request.evidence_reference_ids),
                list(request.requested_protection_codes),
            ),
        )

    def claim_case(self, request: ClaimCasePostgresRequest) -> TrustCommandResult:
        _require_type(request, ClaimCasePostgresRequest)
        common = _common_parameters(request)
        return self._officer(
            operation="CLAIM_CASE",
            request=request,
            function="claim_case_v1",
            count=15,
            parameters=common[:8]
            + (request.assignment_id,)
            + common[8:]
            + (request.case_id, request.expected_case_version),
        )

    def release_case_assignment(
        self, request: ReleaseCaseAssignmentPostgresRequest
    ) -> TrustCommandResult:
        _require_type(request, ReleaseCaseAssignmentPostgresRequest)
        return self._officer(
            operation="RELEASE_CASE_ASSIGNMENT",
            request=request,
            function="release_case_assignment_v1",
            count=15,
            parameters=_common_parameters(request)
            + (
                request.case_id,
                request.expected_case_version,
                request.reason_code,
            ),
        )

    def save_triage_draft(
        self, request: SaveTriageDraftPostgresRequest
    ) -> TrustCommandResult:
        _require_type(request, SaveTriageDraftPostgresRequest)
        return self._officer(
            operation="SAVE_TRIAGE_DRAFT",
            request=request,
            function="save_triage_draft_v1",
            count=23,
            parameters=_common_parameters(request)
            + (
                request.case_id,
                request.expected_case_version,
                request.priority_code,
                request.jurisdiction_code,
                request.severity_code,
                list(request.issue_codes),
                list(request.investigation_step_codes),
                list(request.proposed_hold_actions),
                request.proposed_hold_ttl_minutes,
                request.sealed_note_reference,
                request.sealed_note_sha256,
            ),
        )

    def publish_triage(
        self, request: PublishTriagePostgresRequest
    ) -> TrustCommandResult:
        _require_type(request, PublishTriagePostgresRequest)
        return self._officer(
            operation="PUBLISH_TRIAGE",
            request=request,
            function="publish_triage_v1",
            count=15,
            parameters=_common_parameters(request)
            + (
                request.case_id,
                request.expected_case_version,
                request.expected_draft_version,
            ),
        )

    def place_hold(self, request: PlaceHoldPostgresRequest) -> TrustCommandResult:
        _require_type(request, PlaceHoldPostgresRequest)
        common = _common_parameters(request)
        return self._officer(
            operation="PLACE_HOLD",
            request=request,
            function="place_hold_v1",
            count=18,
            parameters=common[:8]
            + (request.hold_id,)
            + common[8:]
            + (
                request.case_id,
                request.expected_case_version,
                list(request.action_codes),
                request.reason_code,
                request.hold_ttl_minutes,
            ),
        )

    def claim_hold_release(
        self, request: ClaimHoldReleasePostgresRequest
    ) -> TrustCommandResult:
        _require_type(request, ClaimHoldReleasePostgresRequest)
        common = _common_parameters(request)
        return self._officer(
            operation="CLAIM_HOLD_RELEASE",
            request=request,
            function="claim_hold_release_v1",
            count=15,
            parameters=common[:8]
            + (request.assignment_id,)
            + common[8:]
            + (request.hold_id, request.expected_hold_version),
        )

    def release_hold(
        self, request: ReleaseHoldPostgresRequest
    ) -> TrustCommandResult:
        _require_type(request, ReleaseHoldPostgresRequest)
        return self._officer(
            operation="RELEASE_HOLD",
            request=request,
            function="release_hold_v1",
            count=15,
            parameters=_common_parameters(request)
            + (
                request.hold_id,
                request.expected_hold_version,
                request.release_reason_code,
            ),
        )

    def publish_outcome(
        self, request: PublishOutcomePostgresRequest
    ) -> TrustCommandResult:
        _require_type(request, PublishOutcomePostgresRequest)
        common = _common_parameters(request)
        evidence = request.evidence
        return self._officer(
            operation="PUBLISH_OUTCOME",
            request=request,
            function="publish_outcome_v1",
            count=34,
            parameters=common[:8]
            + (request.outcome_version_id,)
            + common[8:]
            + (
                request.case_id,
                request.expected_case_version,
                request.outcome_code,
                list(request.reason_codes),
                list(request.action_codes),
                evidence.case_id,
                evidence.case_aggregate_version,
                evidence.triage_version,
                evidence.outcome_code,
                list(evidence.reason_codes),
                list(evidence.action_codes),
                evidence.evidence_packet_version_id,
                evidence.evidence_packet_digest,
                evidence.source_digest,
                evidence.appeal_eligible,
                evidence.appeal_eligibility_code,
                evidence.appeal_deadline,
                evidence.policy_version,
                evidence.redaction_profile_code,
                evidence.evaluated_at,
                evidence.valid_until,
            ),
        )

    def close(self) -> None:
        self._closed = True

    def _officer(
        self,
        *,
        operation: str,
        request: Any,
        function: str,
        count: int,
        parameters: tuple[Any, ...],
    ) -> TrustCommandResult:
        return self._run(
            source=self._officer_connections,
            role="trust_officer",
            operation=operation,
            request=request,
            statement=(
                f"SELECT safe_response,replayed FROM trust_api.{function}("
                + ",".join(["%s"] * count)
                + ")"
            ),
            parameters=parameters,
        )

    def _run(
        self,
        *,
        source: Any,
        role: str,
        operation: str,
        request: Any,
        statement: str,
        parameters: tuple[Any, ...],
    ) -> TrustCommandResult:
        if self._closed:
            raise TrustPostgresConfigurationError()
        return self._write_once(
            source=source,
            role=role,
            operation=operation,
            request=request,
            statement=statement,
            parameters=parameters,
        )

    def _write_once(
        self,
        *,
        source: Any,
        role: str,
        operation: str,
        request: Any,
        statement: str,
        parameters: tuple[Any, ...],
    ) -> TrustCommandResult:
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
                scope="TRUST_REPORTER" if role == "trust_self" else "TRUST_OFFICER",
                operation=operation,
                actor_id=request.context.actor_user_id,
                session_id=request.context.session_id,
                organization_id=getattr(request, "organization_id", None),
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
                raise TrustPostgresCommitOutcomeUnknownError() from None
            if connection is not None and state in {"BEGUN", "WRITING"}:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    pass
            if connection is not None and not disposed:
                _discard(source, connection)
                disposed = True
            if isinstance(error, TrustPostgresError):
                raise
            translated = _database_error(error)
            if translated is not None:
                raise translated from None
            raise TrustPostgresConfigurationError() from None
        finally:
            if connection is not None and not disposed:
                _discard(source, connection)


class PsycopgTrustReceiptProbe:
    """Read a completed receipt without claiming or mutating business state."""

    def __init__(
        self,
        *,
        reporter_connections: Any,
        officer_connections: Any,
        settings: TrustPostgresGatewaySettings = TrustPostgresGatewaySettings(),
    ) -> None:
        _require_sources(reporter_connections, officer_connections)
        if not isinstance(settings, TrustPostgresGatewaySettings):
            raise TypeError("Trust PostgreSQL gateway settings are unavailable")
        self._reporter_connections = reporter_connections
        self._officer_connections = officer_connections
        self._settings = settings
        self._closed = False

    def read_completed(
        self,
        request: TrustCompletedReceiptProbeRequest,
    ) -> Optional[TrustCommandResult]:
        _require_type(request, TrustCompletedReceiptProbeRequest)
        if self._closed:
            raise TrustPostgresConfigurationError()
        role = "trust_self" if request.operation == "SUBMIT_REPORT" else "trust_officer"
        source = (
            self._reporter_connections
            if role == "trust_self"
            else self._officer_connections
        )
        connection = None
        transaction = False
        disposed = False
        try:
            connection = source.checkout()
            _prepare(connection, role)
            connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED")
            transaction = True
            _configure(
                connection,
                settings=self._settings,
                scope="TRUST_REPORTER" if role == "trust_self" else "TRUST_OFFICER",
                operation=request.operation,
                actor_id=request.context.actor_user_id,
                session_id=request.context.session_id,
                organization_id=request.organization_id,
            )
            material = request.material
            rows = connection.execute(
                "SELECT safe_response,replayed "
                "FROM trust_api.read_completed_command_receipt_v1("
                + ",".join(["%s"] * 10)
                + ")",
                (
                    request.context.actor_user_id,
                    request.context.session_id,
                    request.organization_id,
                    request.operation,
                    request.target_id,
                    request.expected_version,
                    list(material.idempotency_key_digest_key_ids),
                    list(material.idempotency_key_digests),
                    list(material.payload_hash_key_ids),
                    list(material.payload_hashes),
                ),
            ).fetchmany(2)
            if not isinstance(rows, list) or len(rows) > 1:
                raise TrustPostgresConfigurationError()
            result = None
            if rows:
                result = _command_result(request.operation, request, rows[0])
                if not result.replayed:
                    raise TrustPostgresConfigurationError()
                if request.target_id is not None:
                    expected = (
                        result.hold_id
                        if request.operation
                        in {"CLAIM_HOLD_RELEASE", "RELEASE_HOLD"}
                        else result.case_id
                    )
                    if expected != str(request.target_id):
                        raise TrustPostgresConfigurationError()
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
            if isinstance(error, TrustPostgresError):
                raise
            translated = _database_error(error)
            if translated is not None:
                raise translated from None
            raise TrustPostgresConfigurationError() from None
        finally:
            if connection is not None and not disposed:
                _discard(source, connection)

    def close(self) -> None:
        self._closed = True


class PsycopgTrustReadGateway:
    """Invoke and strictly parse only the eight authorized Trust reads."""

    def __init__(
        self,
        *,
        reporter_connections: Any,
        officer_connections: Any,
        settings: TrustPostgresGatewaySettings = TrustPostgresGatewaySettings(),
    ) -> None:
        _require_sources(reporter_connections, officer_connections)
        if not isinstance(settings, TrustPostgresGatewaySettings):
            raise TypeError("Trust PostgreSQL gateway settings are unavailable")
        self._reporter_connections = reporter_connections
        self._officer_connections = officer_connections
        self._settings = settings
        self._closed = False

    def list_own_reports(
        self,
        *,
        actor_user_id: UUID,
        session_id: UUID,
        organization_id: UUID,
        limit: int,
        cursor_created_at: Optional[datetime],
        cursor_report_id: Optional[UUID],
    ) -> TrustPostgresOwnedReportPage:
        _require_uuids(actor_user_id, session_id, organization_id)
        _require_limit(limit)
        if (cursor_created_at is None) != (cursor_report_id is None):
            raise ValueError("Trust owned report cursor is invalid")
        if cursor_created_at is not None:
            _require_utc(cursor_created_at)
            _require_uuids(cursor_report_id)
        return self._read_owned_report_page(
            actor_id=actor_user_id,
            session_id=session_id,
            organization_id=organization_id,
            limit=limit,
            statement=(
                "SELECT projection,next_created_at,next_report_id FROM "
                "trust_api.list_own_reports_v1(%s,%s,%s,%s,%s,%s)"
            ),
            parameters=(
                actor_user_id,
                session_id,
                organization_id,
                limit,
                cursor_created_at,
                cursor_report_id,
            ),
        )

    def read_own_report(
        self,
        *,
        actor_user_id: UUID,
        session_id: UUID,
        organization_id: UUID,
        report_id: UUID,
    ) -> TrustPostgresProjection:
        _require_uuids(actor_user_id, session_id, organization_id, report_id)
        return self._read(
            source=self._reporter_connections,
            role="trust_self",
            operation="READ_OWN_REPORT",
            kind="REPORT",
            actor_id=actor_user_id,
            session_id=session_id,
            organization_id=organization_id,
            statement=(
                "SELECT projection FROM trust_api.read_own_report_v1("
                "%s,%s,%s,%s)"
            ),
            parameters=(actor_user_id, session_id, organization_id, report_id),
        )

    def list_case_queue(
        self,
        *,
        actor_user_id: UUID,
        session_id: UUID,
        limit: int,
    ) -> TrustPostgresProjection:
        _require_uuids(actor_user_id, session_id)
        _require_limit(limit)
        return self._read(
            source=self._officer_connections,
            role="trust_officer",
            operation="LIST_CASE_QUEUE",
            kind="CASE_QUEUE",
            actor_id=actor_user_id,
            session_id=session_id,
            organization_id=None,
            statement=(
                "SELECT projection FROM trust_api.list_safety_case_queue_v1("
                "%s,%s,%s)"
            ),
            parameters=(actor_user_id, session_id, limit),
        )

    def list_hold_release_queue(
        self,
        *,
        actor_user_id: UUID,
        session_id: UUID,
        limit: int,
    ) -> TrustPostgresProjection:
        _require_uuids(actor_user_id, session_id)
        _require_limit(limit)
        return self._read(
            source=self._officer_connections,
            role="trust_officer",
            operation="LIST_HOLD_RELEASE_QUEUE",
            kind="HOLD_RELEASE_QUEUE",
            actor_id=actor_user_id,
            session_id=session_id,
            organization_id=None,
            statement=(
                "SELECT projection FROM trust_api.list_hold_release_queue_v1("
                "%s,%s,%s)"
            ),
            parameters=(actor_user_id, session_id, limit),
        )

    def list_my_active_case_assignments(
        self,
        *,
        actor_user_id: UUID,
        session_id: UUID,
        limit: int,
    ) -> TrustPostgresProjection:
        _require_uuids(actor_user_id, session_id)
        _require_limit(limit)
        return self._read(
            source=self._officer_connections,
            role="trust_officer",
            operation="LIST_MY_ACTIVE_CASE_ASSIGNMENTS",
            kind="MY_ACTIVE_CASE_ASSIGNMENTS",
            actor_id=actor_user_id,
            session_id=session_id,
            organization_id=None,
            statement=(
                "SELECT projection FROM "
                "trust_api.list_my_active_case_assignments_v1(%s,%s,%s)"
            ),
            parameters=(actor_user_id, session_id, limit),
        )

    def list_my_completed_case_assignments(
        self,
        *,
        actor_user_id: UUID,
        session_id: UUID,
        limit: int,
    ) -> TrustPostgresProjection:
        _require_uuids(actor_user_id, session_id)
        _require_limit(limit)
        return self._read(
            source=self._officer_connections,
            role="trust_officer",
            # IAM36 exposes the exact read capability under this operation;
            # the SQL projection further narrows it to the caller's own
            # completed CASE_TRIAGE assignments.
            operation="READ_ASSIGNED_CASE",
            kind="MY_COMPLETED_CASE_ASSIGNMENTS",
            actor_id=actor_user_id,
            session_id=session_id,
            organization_id=None,
            statement=(
                "SELECT projection FROM "
                "trust_api.list_my_completed_case_assignments_v1(%s,%s,%s)"
            ),
            parameters=(actor_user_id, session_id, limit),
        )

    def read_assigned_case(
        self,
        *,
        actor_user_id: UUID,
        session_id: UUID,
        case_id: UUID,
    ) -> TrustPostgresProjection:
        _require_uuids(actor_user_id, session_id, case_id)
        return self._read(
            source=self._officer_connections,
            role="trust_officer",
            operation="READ_ASSIGNED_CASE",
            kind="CASE",
            actor_id=actor_user_id,
            session_id=session_id,
            organization_id=None,
            statement=(
                "SELECT projection FROM "
                "trust_api.read_my_active_case_triage_assignment_v1("
                "%s,%s,%s)"
            ),
            parameters=(actor_user_id, session_id, case_id),
        )

    def read_assigned_hold_release(
        self,
        *,
        actor_user_id: UUID,
        session_id: UUID,
        hold_id: UUID,
    ) -> TrustPostgresProjection:
        _require_uuids(actor_user_id, session_id, hold_id)
        return self._read(
            source=self._officer_connections,
            role="trust_officer",
            operation="READ_ASSIGNED_CASE",
            kind="ASSIGNED_HOLD_RELEASE",
            actor_id=actor_user_id,
            session_id=session_id,
            organization_id=None,
            statement=(
                "SELECT projection FROM "
                "trust_api.read_my_active_hold_release_assignment_v1("
                "%s,%s,%s)"
            ),
            parameters=(actor_user_id, session_id, hold_id),
        )

    def close(self) -> None:
        self._closed = True

    def _read(
        self,
        *,
        source: Any,
        role: str,
        operation: str,
        kind: str,
        actor_id: UUID,
        session_id: UUID,
        organization_id: Optional[UUID],
        statement: str,
        parameters: tuple[Any, ...],
    ) -> TrustPostgresProjection:
        if self._closed:
            raise TrustPostgresConfigurationError()
        connection = None
        transaction = False
        disposed = False
        try:
            connection = source.checkout()
            _prepare(connection, role)
            connection.execute(
                "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY"
            )
            transaction = True
            _configure(
                connection,
                settings=self._settings,
                scope="TRUST_REPORTER" if role == "trust_self" else "TRUST_OFFICER",
                operation=operation,
                actor_id=actor_id,
                session_id=session_id,
                organization_id=organization_id,
            )
            rows = connection.execute(statement, parameters).fetchmany(2)
            if not isinstance(rows, list) or len(rows) != 1:
                raise TrustPostgresRejectedError("RESOURCE_NOT_FOUND")
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
            if isinstance(error, TrustPostgresError):
                raise
            translated = _database_error(error)
            if translated is not None:
                raise translated from None
            raise TrustPostgresConfigurationError() from None
        finally:
            if connection is not None and not disposed:
                _discard(source, connection)

    def _read_owned_report_page(
        self,
        *,
        actor_id: UUID,
        session_id: UUID,
        organization_id: UUID,
        limit: int,
        statement: str,
        parameters: tuple[Any, ...],
    ) -> TrustPostgresOwnedReportPage:
        if self._closed:
            raise TrustPostgresConfigurationError()
        connection = None
        transaction = False
        disposed = False
        try:
            connection = self._reporter_connections.checkout()
            _prepare(connection, "trust_self")
            connection.execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
            transaction = True
            _configure(
                connection,
                settings=self._settings,
                scope="TRUST_REPORTER",
                operation="READ_OWN_REPORT",
                actor_id=actor_id,
                session_id=session_id,
                organization_id=organization_id,
            )
            rows = connection.execute(statement, parameters).fetchmany(2)
            if not isinstance(rows, list) or len(rows) != 1:
                raise TrustPostgresRejectedError("RESOURCE_NOT_FOUND")
            row = rows[0]
            if (
                not isinstance(row, tuple)
                or len(row) != 3
                or not isinstance(row[0], Mapping)
            ):
                raise TrustPostgresConfigurationError()
            document = dict(row[0])
            _validate_owned_report_list_projection(document)
            next_created_at = row[1]
            next_report_id = row[2]
            result = TrustPostgresOwnedReportPage(
                projection=document,
                response_entity_tag=document["entity_tag"],
                next_created_at=next_created_at,
                next_report_id=next_report_id,
            )
            if result.next_created_at is not None and len(document["items"]) != limit:
                raise TrustPostgresConfigurationError()
            connection.execute("COMMIT")
            transaction = False
            _reset(connection)
            self._reporter_connections.release(connection)
            disposed = True
            return result
        except BaseException as error:
            if connection is not None and transaction:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    pass
            if connection is not None and not disposed:
                _discard(self._reporter_connections, connection)
                disposed = True
            if isinstance(error, TrustPostgresError):
                raise
            translated = _database_error(error)
            if translated is not None:
                raise translated from None
            raise TrustPostgresConfigurationError() from None
        finally:
            if connection is not None and not disposed:
                _discard(self._reporter_connections, connection)


def _common_parameters(request: Any) -> tuple[Any, ...]:
    context, receipt = request.context, request.receipt
    return (
        context.actor_user_id,
        context.session_id,
        context.correlation_id,
        context.causation_id,
        context.trace_id,
        receipt.receipt_id,
        receipt.audit_event_id,
        receipt.outbox_event_id,
        list(receipt.idempotency_key_digest_key_ids),
        list(receipt.idempotency_key_digests),
        list(receipt.payload_hash_key_ids),
        list(receipt.payload_hashes),
    )


def _command_result(
    operation: str,
    request: Any,
    row: Any,
) -> TrustCommandResult:
    if (
        not isinstance(row, tuple)
        or len(row) != 2
        or not isinstance(row[0], Mapping)
        or type(row[1]) is not bool
    ):
        raise TrustPostgresConfigurationError()
    safe, replayed = row
    if set(safe) != _SAFE_RESULT_KEYS:
        raise TrustPostgresConfigurationError()
    case_id = _uuid_text(safe["case_id"])
    optional_ids = {
        name: _optional_uuid_text(safe[name])
        for name in ("assignment_id", "hold_id", "outcome_version_id", "report_id")
    }
    try:
        status = SafetyCaseStatus(safe["case_status"])
    except (TypeError, ValueError):
        raise TrustPostgresConfigurationError() from None
    aggregate_version = safe["aggregate_version"]
    event_types = safe["event_types"]
    completed_at = _timestamp(safe["completed_at"])
    if (
        case_id is None
        or type(aggregate_version) is not int
        or aggregate_version < 1
        or not isinstance(event_types, list)
        or event_types != [_EVENT_TYPES[operation]]
        or completed_at is None
    ):
        raise TrustPostgresConfigurationError()
    versions = {}
    for name in ("hold_version", "triage_draft_version", "triage_version"):
        value = safe[name]
        if value is not None and (type(value) is not int or value < 1):
            raise TrustPostgresConfigurationError()
        versions[name] = value
    expected_non_null = {
        "SUBMIT_REPORT": {"report_id"},
        "CLAIM_CASE": {"assignment_id"},
        "RELEASE_CASE_ASSIGNMENT": {"assignment_id"},
        "SAVE_TRIAGE_DRAFT": {"triage_draft_version"},
        "PUBLISH_TRIAGE": {"triage_version"},
        "PLACE_HOLD": {"hold_id", "hold_version"},
        "CLAIM_HOLD_RELEASE": {"assignment_id", "hold_id", "hold_version"},
        "RELEASE_HOLD": {"hold_id", "hold_version"},
        "PUBLISH_OUTCOME": {"outcome_version_id"},
    }[operation]
    values = {**optional_ids, **versions}
    if any(
        (name in expected_non_null) != (value is not None)
        for name, value in values.items()
    ):
        raise TrustPostgresConfigurationError()
    target_case = getattr(request, "case_id", None)
    if not replayed and target_case is not None and case_id != str(target_case):
        raise TrustPostgresConfigurationError()
    generated = {
        "SUBMIT_REPORT": ("report_id", getattr(request, "report_id", None)),
        "CLAIM_CASE": ("assignment_id", getattr(request, "assignment_id", None)),
        "PLACE_HOLD": ("hold_id", getattr(request, "hold_id", None)),
        "CLAIM_HOLD_RELEASE": (
            "assignment_id",
            getattr(request, "assignment_id", None),
        ),
        "PUBLISH_OUTCOME": (
            "outcome_version_id",
            getattr(request, "outcome_version_id", None),
        ),
    }.get(operation)
    if (
        not replayed
        and generated is not None
        and optional_ids[generated[0]] != str(generated[1])
    ):
        raise TrustPostgresConfigurationError()
    return TrustCommandResult(
        case_id=case_id,
        case_status=status,
        aggregate_version=aggregate_version,
        report_id=optional_ids["report_id"],
        assignment_id=optional_ids["assignment_id"],
        triage_draft_version=versions["triage_draft_version"],
        triage_version=versions["triage_version"],
        hold_id=optional_ids["hold_id"],
        hold_version=versions["hold_version"],
        outcome_version_id=optional_ids["outcome_version_id"],
        replayed=replayed,
        event_types=tuple(event_types),
        completed_at=completed_at,
    )


def _projection(kind: str, row: Any) -> TrustPostgresProjection:
    if not isinstance(row, tuple) or len(row) != 1 or not isinstance(row[0], Mapping):
        raise TrustPostgresConfigurationError()
    document = dict(row[0])
    if kind == "REPORT":
        _validate_report_projection(document)
    elif kind == "CASE_QUEUE":
        _validate_queue_projection(document, hold_release=False)
    elif kind == "HOLD_RELEASE_QUEUE":
        _validate_queue_projection(document, hold_release=True)
    elif kind == "MY_ACTIVE_CASE_ASSIGNMENTS":
        _validate_active_assignments_projection(document)
    elif kind == "MY_COMPLETED_CASE_ASSIGNMENTS":
        _validate_completed_assignments_projection(document)
    elif kind == "ASSIGNED_HOLD_RELEASE":
        _validate_assigned_hold_release_projection(document)
    elif kind == "CASE":
        _validate_case_projection(document)
    else:
        raise TrustPostgresConfigurationError()
    return TrustPostgresProjection(
        kind=kind,
        projection=document,
        response_entity_tag=document["entity_tag"],
    )


def _validate_report_summary(value: Any) -> None:
    keys = {
        "category",
        "evidence_reference_ids",
        "impact_codes",
        "incident_ended_at",
        "incident_started_at",
        "requested_protection_codes",
    }
    if not isinstance(value, Mapping) or set(value) != keys:
        raise TrustPostgresConfigurationError()
    _require_enum(value["category"], _REPORT_CATEGORIES)
    _require_json_uuid_list(value["evidence_reference_ids"], 1, 32)
    _require_json_codes(value["impact_codes"], _IMPACT_CODES, 1, 16)
    if _timestamp(value["incident_started_at"]) is None:
        raise TrustPostgresConfigurationError()
    if value["incident_ended_at"] is not None and _timestamp(
        value["incident_ended_at"]
    ) is None:
        raise TrustPostgresConfigurationError()
    _require_json_codes(
        value["requested_protection_codes"], _PROTECTION_CODES, 1, 3
    )


def _validate_report_projection(value: Mapping[str, Any]) -> None:
    if set(value) != {
        "demand_id",
        "demand_version_id",
        "entity_tag",
        "outcome",
        "report",
        "report_id",
        "status",
        "submitted_at",
    }:
        raise TrustPostgresConfigurationError()
    _require_json_ids(value, "demand_id", "demand_version_id", "report_id")
    _require_entity_tag(value["entity_tag"])
    _validate_report_summary(value["report"])
    if value["outcome"] is not None:
        _validate_outcome(value["outcome"])
    if value["status"] not in {"OPEN", "TRIAGING", "IN_REVIEW", "DECIDED"}:
        raise TrustPostgresConfigurationError()
    if _timestamp(value["submitted_at"]) is None:
        raise TrustPostgresConfigurationError()


def _validate_owned_report_list_projection(value: Mapping[str, Any]) -> None:
    if set(value) != {"entity_tag", "items"}:
        raise TrustPostgresConfigurationError()
    _require_entity_tag(value["entity_tag"])
    items = value["items"]
    if not isinstance(items, list) or len(items) > 100:
        raise TrustPostgresConfigurationError()
    seen: set[str] = set()
    previous: tuple[datetime, str] | None = None
    for item in items:
        if not isinstance(item, Mapping) or set(item) != {
            "category",
            "demand_id",
            "outcome",
            "report_id",
            "status",
            "submitted_at",
        }:
            raise TrustPostgresConfigurationError()
        _require_json_ids(item, "demand_id", "report_id")
        if item["report_id"] in seen:
            raise TrustPostgresConfigurationError()
        seen.add(item["report_id"])
        _require_enum(item["category"], _REPORT_CATEGORIES)
        _require_enum(item["status"], {"OPEN", "TRIAGING", "IN_REVIEW", "DECIDED"})
        submitted_at = _timestamp(item["submitted_at"])
        if submitted_at is None:
            raise TrustPostgresConfigurationError()
        key = (submitted_at, item["report_id"])
        if previous is not None and not (
            key[0] < previous[0]
            or (key[0] == previous[0] and key[1] > previous[1])
        ):
            raise TrustPostgresConfigurationError()
        previous = key
        outcome = item["outcome"]
        if outcome is None:
            if item["status"] == "DECIDED":
                raise TrustPostgresConfigurationError()
            continue
        if not isinstance(outcome, Mapping) or set(outcome) != {
            "appeal_deadline",
            "appeal_eligibility_code",
            "decided_at",
            "outcome_code",
            "outcome_version_id",
        }:
            raise TrustPostgresConfigurationError()
        _require_json_ids(outcome, "outcome_version_id")
        _require_enum(outcome["outcome_code"], _OUTCOMES)
        _require_enum(
            outcome["appeal_eligibility_code"], {"ELIGIBLE", "NOT_ELIGIBLE"}
        )
        if (
            item["status"] != "DECIDED"
            or _timestamp(outcome["decided_at"]) is None
            or (
                outcome["appeal_deadline"] is not None
                and _timestamp(outcome["appeal_deadline"]) is None
            )
            or (
                outcome["appeal_eligibility_code"] == "ELIGIBLE"
            ) != (outcome["appeal_deadline"] is not None)
        ):
            raise TrustPostgresConfigurationError()


def _validate_queue_projection(value: Mapping[str, Any], *, hold_release: bool) -> None:
    if set(value) != {"entity_tag", "items"}:
        raise TrustPostgresConfigurationError()
    _require_entity_tag(value["entity_tag"])
    items = value["items"]
    if not isinstance(items, list) or len(items) > 100:
        raise TrustPostgresConfigurationError()
    for item in items:
        if not isinstance(item, Mapping):
            raise TrustPostgresConfigurationError()
        if hold_release:
            if set(item) != {
                "action_codes",
                "case_id",
                "demand_id",
                "demand_version_id",
                "entity_tag",
                "expires_at",
                "hold_id",
                "reason_code",
            }:
                raise TrustPostgresConfigurationError()
            _require_json_ids(
                item, "case_id", "demand_id", "demand_version_id", "hold_id"
            )
            _require_json_codes(item["action_codes"], _HOLD_ACTIONS, 1, 3)
            _require_enum(
                item["reason_code"],
                {"PARTICIPANT_SAFETY_RISK", "RETALIATION_RISK"},
            )
            if _timestamp(item["expires_at"]) is None:
                raise TrustPostgresConfigurationError()
        else:
            if set(item) != {
                "case_id",
                "category",
                "demand_id",
                "demand_version_id",
                "entity_tag",
                "impact_codes",
                "report_id",
                "submitted_at",
            }:
                raise TrustPostgresConfigurationError()
            _require_json_ids(
                item,
                "case_id",
                "demand_id",
                "demand_version_id",
                "report_id",
            )
            _require_enum(item["category"], _REPORT_CATEGORIES)
            _require_json_codes(item["impact_codes"], _IMPACT_CODES, 1, 16)
            if _timestamp(item["submitted_at"]) is None:
                raise TrustPostgresConfigurationError()
        _require_entity_tag(item["entity_tag"])


def _validate_active_assignments_projection(value: Mapping[str, Any]) -> None:
    if set(value) != {"entity_tag", "items"}:
        raise TrustPostgresConfigurationError()
    _require_entity_tag(value["entity_tag"])
    items = value["items"]
    if not isinstance(items, list) or len(items) > 100:
        raise TrustPostgresConfigurationError()
    assignment_keys: set[tuple[str, str, str | None]] = set()
    for item in items:
        if not isinstance(item, Mapping) or set(item) != {
            "assignment_expires_at",
            "assignment_purpose",
            "case_id",
            "hold_id",
        }:
            raise TrustPostgresConfigurationError()
        _require_json_ids(item, "case_id")
        _require_enum(item["assignment_purpose"], {"CASE_TRIAGE", "HOLD_RELEASE"})
        purpose = item["assignment_purpose"]
        hold_id = item["hold_id"]
        if purpose == "CASE_TRIAGE":
            if hold_id is not None:
                raise TrustPostgresConfigurationError()
        elif _uuid_text(hold_id) is None:
            raise TrustPostgresConfigurationError()
        assignment_key = (item["case_id"], purpose, hold_id)
        if assignment_key in assignment_keys:
            raise TrustPostgresConfigurationError()
        assignment_keys.add(assignment_key)
        if _timestamp(item["assignment_expires_at"]) is None:
            raise TrustPostgresConfigurationError()


def _validate_completed_assignments_projection(value: Mapping[str, Any]) -> None:
    if set(value) != {"entity_tag", "has_more", "items"}:
        raise TrustPostgresConfigurationError()
    _require_entity_tag(value["entity_tag"])
    if type(value["has_more"]) is not bool:
        raise TrustPostgresConfigurationError()
    items = value["items"]
    if not isinstance(items, list) or len(items) > 100:
        raise TrustPostgresConfigurationError()
    seen: set[str] = set()
    previous: tuple[datetime, str] | None = None
    for item in items:
        if not isinstance(item, Mapping) or set(item) != {
            "case_id",
            "decided_at",
            "outcome_code",
        }:
            raise TrustPostgresConfigurationError()
        _require_json_ids(item, "case_id")
        if item["case_id"] in seen:
            raise TrustPostgresConfigurationError()
        seen.add(item["case_id"])
        _require_enum(item["outcome_code"], _OUTCOMES)
        decided_at = _timestamp(item["decided_at"])
        if decided_at is None:
            raise TrustPostgresConfigurationError()
        order_key = (decided_at, item["case_id"])
        if previous is not None and not (
            order_key[0] < previous[0]
            or (order_key[0] == previous[0] and order_key[1] < previous[1])
        ):
            raise TrustPostgresConfigurationError()
        previous = order_key


def _validate_assigned_hold_release_projection(value: Mapping[str, Any]) -> None:
    if set(value) != {
        "action_codes",
        "assignment_expires_at",
        "case_id",
        "case_status",
        "effective_at",
        "entity_tag",
        "expires_at",
        "hold_id",
        "hold_status",
        "reason_code",
    }:
        raise TrustPostgresConfigurationError()
    _require_json_ids(value, "case_id", "hold_id")
    _require_entity_tag(value["entity_tag"])
    _require_json_codes(value["action_codes"], _HOLD_ACTIONS, 1, 3)
    _require_enum(value["case_status"], {"IN_REVIEW"})
    _require_enum(value["hold_status"], {"ACTIVE"})
    _require_enum(
        value["reason_code"],
        {"PARTICIPANT_SAFETY_RISK", "RETALIATION_RISK"},
    )
    effective_at = _timestamp(value["effective_at"])
    expires_at = _timestamp(value["expires_at"])
    assignment_expires_at = _timestamp(value["assignment_expires_at"])
    if (
        effective_at is None
        or expires_at is None
        or assignment_expires_at is None
        or effective_at >= expires_at
        or assignment_expires_at > expires_at
    ):
        raise TrustPostgresConfigurationError()


def _validate_case_projection(value: Mapping[str, Any]) -> None:
    if set(value) != {
        "active_hold",
        "aggregate_version",
        "case_id",
        "demand_id",
        "demand_version_id",
        "entity_tag",
        "outcome",
        "report",
        "report_id",
        "status",
        "triage_draft",
    }:
        raise TrustPostgresConfigurationError()
    _require_json_ids(value, "case_id", "demand_id", "demand_version_id", "report_id")
    _require_entity_tag(value["entity_tag"])
    _require_version(value["aggregate_version"])
    if value["status"] not in {"TRIAGING", "IN_REVIEW", "DECIDED"}:
        raise TrustPostgresConfigurationError()
    _validate_report_summary(value["report"])
    active_hold = value["active_hold"]
    if active_hold is not None:
        if not isinstance(active_hold, Mapping) or set(active_hold) != {
            "action_codes",
            "effective_at",
            "entity_tag",
            "expires_at",
            "hold_id",
            "status",
        }:
            raise TrustPostgresConfigurationError()
        _require_json_ids(active_hold, "hold_id")
        _require_json_codes(active_hold["action_codes"], _HOLD_ACTIONS, 1, 3)
        _require_entity_tag(active_hold["entity_tag"])
        if (
            _timestamp(active_hold["effective_at"]) is None
            or _timestamp(active_hold["expires_at"]) is None
            or active_hold["status"] != "ACTIVE"
        ):
            raise TrustPostgresConfigurationError()
    draft = value["triage_draft"]
    if draft is not None:
        _validate_triage_draft(draft)
    outcome = value["outcome"]
    if outcome is not None:
        _validate_outcome(outcome)


def _validate_triage_draft(value: Any) -> None:
    if not isinstance(value, Mapping) or set(value) != {
        "content",
        "content_sha256",
        "saved_at",
        "triage_version",
    }:
        raise TrustPostgresConfigurationError()
    if not _digest_hex(value["content_sha256"]):
        raise TrustPostgresConfigurationError()
    _require_version(value["triage_version"])
    if _timestamp(value["saved_at"]) is None:
        raise TrustPostgresConfigurationError()
    content = value["content"]
    if not isinstance(content, Mapping) or set(content) != {
        "investigation_step_codes",
        "issue_codes",
        "jurisdiction_code",
        "priority_code",
        "proposed_hold_actions",
        "proposed_hold_ttl_minutes",
        "sealed_note_reference",
        "sealed_note_sha256",
        "severity_code",
    }:
        raise TrustPostgresConfigurationError()
    _require_json_codes(content["investigation_step_codes"], _INVESTIGATION_CODES, 1, 16)
    _require_json_codes(content["issue_codes"], _ISSUE_CODES, 1, 16)
    _require_enum(content["jurisdiction_code"], _JURISDICTION_CODES)
    _require_enum(content["priority_code"], _PRIORITY_CODES)
    _require_json_codes(content["proposed_hold_actions"], _HOLD_ACTIONS, 1, 3)
    _require_enum(content["severity_code"], _SEVERITY_CODES)
    if (
        type(content["proposed_hold_ttl_minutes"]) is not int
        or not 15 <= content["proposed_hold_ttl_minutes"] <= 10_080
        or not isinstance(content["sealed_note_reference"], str)
        or _SEALED_REFERENCE.fullmatch(content["sealed_note_reference"]) is None
        or not _digest_hex(content["sealed_note_sha256"])
    ):
        raise TrustPostgresConfigurationError()


def _validate_outcome(value: Any) -> None:
    if not isinstance(value, Mapping) or set(value) != {
        "action_codes",
        "appeal_deadline",
        "appeal_eligibility_code",
        "content_sha256",
        "decided_at",
        "evidence_packet_digest",
        "evidence_packet_version_id",
        "outcome_code",
        "outcome_version_id",
        "policy_version",
        "reason_codes",
        "redaction_profile_code",
        "source_digest",
    }:
        raise TrustPostgresConfigurationError()
    _require_json_ids(value, "evidence_packet_version_id", "outcome_version_id")
    _require_json_codes(value["action_codes"], _HOLD_ACTIONS, 0, 3)
    _require_enum(value["outcome_code"], _OUTCOMES)
    _require_json_codes(value["reason_codes"], _OUTCOME_REASONS, 1, 8)
    for key in ("content_sha256", "evidence_packet_digest", "source_digest"):
        if not _digest_hex(value[key]):
            raise TrustPostgresConfigurationError()
    if (
        value["appeal_eligibility_code"] not in {"ELIGIBLE", "NOT_ELIGIBLE"}
        or value["policy_version"] != "trust-case-outcome-v1"
        or value["redaction_profile_code"]
        not in {"OFFICER_RESTRICTED_V1", "PARTY_SAFE_V1"}
        or _timestamp(value["decided_at"]) is None
        or (
            value["appeal_deadline"] is not None
            and _timestamp(value["appeal_deadline"]) is None
        )
    ):
        raise TrustPostgresConfigurationError()


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
        raise TrustPostgresConfigurationError()


def _configure(
    connection: Any,
    *,
    settings: TrustPostgresGatewaySettings,
    scope: str,
    operation: str,
    actor_id: UUID,
    session_id: Optional[UUID],
    organization_id: Optional[UUID],
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
        ("app.actor_id", str(actor_id)),
        ("app.session_id", "" if session_id is None else str(session_id)),
        ("app.organization_id", "" if organization_id is None else str(organization_id)),
        ("app.case_id", ""),
        ("app.demand_id", ""),
    )
    for name, value in values:
        row = connection.execute(
            "SELECT pg_catalog.set_config(%s,%s,true)",
            (name, value),
        ).fetchone()
        if not set_config_result_matches(
            name=name,
            requested_value=value,
            row=row,
        ):
            raise TrustPostgresConfigurationError()


def _reset(connection: Any) -> None:
    if (
        getattr(connection, "autocommit", None) is not True
        or getattr(getattr(connection, "info", None), "transaction_status", None)
        != TransactionStatus.IDLE
    ):
        raise TrustPostgresConfigurationError()
    connection.execute("RESET ROLE")
    connection.execute("RESET ALL")
    connection.execute("CLOSE ALL")
    connection.execute("DISCARD TEMP")


def _discard(source: Any, connection: Any) -> None:
    try:
        source.discard(connection)
    except BaseException:
        pass


def _database_error(error: BaseException) -> Optional[TrustPostgresRejectedError]:
    message = getattr(getattr(error, "diag", None), "message_primary", None)
    if not isinstance(message, str):
        message = str(error) if isinstance(error, Exception) else ""
    direct = {
        "ACCESS_DENIED": "ACCESS_DENIED",
        "CASE_ALREADY_ASSIGNED": "CASE_ALREADY_ASSIGNED",
        "CASE_ASSIGNMENT_REQUIRED": "CASE_ASSIGNMENT_REQUIRED",
        "CASE_DECISION_VALIDATION_FAILED": "CASE_DECISION_VALIDATION_FAILED",
        "CASE_STATE_CONFLICT": "CASE_STATE_CONFLICT",
        "COMMAND_OUTCOME_UNKNOWN": "COMMAND_OUTCOME_UNKNOWN",
        "HOLD_RELEASE_ALREADY_ASSIGNED": "HOLD_RELEASE_ALREADY_ASSIGNED",
        "HOLD_STATE_CONFLICT": "HOLD_STATE_CONFLICT",
        "IDEMPOTENCY_KEY_REUSED": "IDEMPOTENCY_KEY_REUSED",
        "INDEPENDENT_REVIEW_REQUIRED": "INDEPENDENT_REVIEW_REQUIRED",
        "INVALID_REQUEST": "INVALID_REQUEST",
        "PRECONDITION_FAILED": "PRECONDITION_FAILED",
        "RESOURCE_NOT_FOUND": "RESOURCE_NOT_FOUND",
        "TRIAGE_VERSION_CONFLICT": "TRIAGE_VERSION_CONFLICT",
    }.get(message)
    if direct is not None:
        if direct == "COMMAND_OUTCOME_UNKNOWN":
            return TrustPostgresRejectedError("COMMAND_OUTCOME_UNKNOWN")
        return TrustPostgresRejectedError(direct)
    sqlstate = getattr(error, "sqlstate", None)
    if sqlstate in {"40001", "40P01", "55P03"}:
        return TrustPostgresRejectedError("PRECONDITION_FAILED")
    return None


def _require_sources(first: Any, second: Any) -> None:
    if first is second:
        raise TypeError("Trust PostgreSQL roles must be isolated")
    for source in (first, second):
        if not all(
            callable(getattr(source, name, None))
            for name in ("checkout", "release", "discard")
        ):
            raise TypeError("Trust PostgreSQL connection source is unavailable")


def _require_request(context: Any, receipt: Any) -> None:
    if not isinstance(context, TrustPostgresCommandContext) or not isinstance(
        receipt, TrustPostgresReceiptMaterial
    ):
        raise TypeError("Trust PostgreSQL request dependencies are unavailable")


def _require_type(value: Any, expected: type) -> None:
    if not isinstance(value, expected):
        raise TypeError("Trust PostgreSQL request is unavailable")


def _require_uuids(*values: Any) -> None:
    if any(not isinstance(value, UUID) or value.int == 0 for value in values):
        raise ValueError("Trust PostgreSQL identifier is invalid")


def _require_uuid_tuple(values: Any, minimum: int, maximum: int) -> None:
    if (
        type(values) is not tuple
        or not minimum <= len(values) <= maximum
        or len(set(values)) != len(values)
    ):
        raise ValueError("Trust PostgreSQL identifier list is invalid")
    _require_uuids(*values)


def _require_key_material(key_ids: Any, digests: Any) -> None:
    if (
        type(key_ids) is not tuple
        or type(digests) is not tuple
        or not 1 <= len(key_ids) <= 4
        or len(key_ids) != len(digests)
        or len(set(key_ids)) != len(key_ids)
        or any(
            not isinstance(value, str) or _KEY_ID.fullmatch(value) is None
            for value in key_ids
        )
        or any(not _digest(value) for value in digests)
    ):
        raise ValueError("Trust PostgreSQL receipt material is invalid")


def _require_version(value: Any) -> None:
    if type(value) is not int or value < 1:
        raise ValueError("Trust PostgreSQL version is invalid")


def _require_limit(value: Any) -> None:
    if type(value) is not int or not 1 <= value <= 100:
        raise ValueError("Trust PostgreSQL query limit is invalid")


def _require_enum(value: Any, allowed: Any) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError("Trust PostgreSQL code is invalid")


def _require_codes(values: Any, allowed: Any, minimum: int, maximum: int) -> None:
    if (
        type(values) is not tuple
        or not minimum <= len(values) <= maximum
        or values != tuple(sorted(values))
        or len(set(values)) != len(values)
        or any(
            not isinstance(value, str)
            or _CODE.fullmatch(value) is None
            or value not in allowed
            for value in values
        )
    ):
        raise ValueError("Trust PostgreSQL code list is invalid")


def _require_json_codes(value: Any, allowed: Any, minimum: int, maximum: int) -> None:
    if not isinstance(value, list):
        raise TrustPostgresConfigurationError()
    try:
        _require_codes(tuple(value), allowed, minimum, maximum)
    except (TypeError, ValueError):
        raise TrustPostgresConfigurationError() from None


def _require_json_uuid_list(value: Any, minimum: int, maximum: int) -> None:
    if (
        not isinstance(value, list)
        or not minimum <= len(value) <= maximum
        or len(set(value)) != len(value)
        or any(_uuid_text(item) is None for item in value)
    ):
        raise TrustPostgresConfigurationError()


def _require_json_ids(value: Mapping[str, Any], *keys: str) -> None:
    if any(_uuid_text(value[key]) is None for key in keys):
        raise TrustPostgresConfigurationError()


def _require_entity_tag(value: Any) -> None:
    if not isinstance(value, str) or _ENTITY_TAG.fullmatch(value) is None:
        raise TrustPostgresConfigurationError()


def _require_utc(value: Any) -> None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise ValueError("Trust PostgreSQL timestamp must be UTC")


def _timestamp(value: Any) -> Optional[datetime]:
    try:
        return parse_utc_timestamp(value)
    except ValueError:
        return None


def _uuid_text(value: Any) -> Optional[str]:
    if isinstance(value, UUID):
        return str(value) if value.int != 0 else None
    if not isinstance(value, str):
        return None
    try:
        parsed = UUID(value)
    except ValueError:
        return None
    return value if parsed.int != 0 and str(parsed) == value else None


def _optional_uuid_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    parsed = _uuid_text(value)
    if parsed is None:
        raise TrustPostgresConfigurationError()
    return parsed


def _digest(value: Any) -> bool:
    return isinstance(value, bytes) and len(value) == 32


def _digest_hex(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64 or value != value.lower():
        return False
    try:
        return len(bytes.fromhex(value)) == 32
    except ValueError:
        return False


__all__ = [
    "ClaimCasePostgresRequest",
    "ClaimHoldReleasePostgresRequest",
    "PlaceHoldPostgresRequest",
    "PsycopgTrustCommandGateway",
    "PsycopgTrustReadGateway",
    "PsycopgTrustReceiptProbe",
    "PublishOutcomePostgresRequest",
    "PublishTriagePostgresRequest",
    "ReleaseCaseAssignmentPostgresRequest",
    "ReleaseHoldPostgresRequest",
    "SaveTriageDraftPostgresRequest",
    "SubmitReportPostgresRequest",
    "TrustOutcomePostgresEvidence",
    "TrustPostgresCommandContext",
    "TrustCompletedReceiptProbeRequest",
    "TrustPostgresCommitOutcomeUnknownError",
    "TrustPostgresConfigurationError",
    "TrustPostgresError",
    "TrustPostgresGatewaySettings",
    "TrustPostgresOwnedReportPage",
    "TrustPostgresProjection",
    "TrustPostgresReplayMaterial",
    "TrustPostgresReceiptMaterial",
    "TrustPostgresRejectedError",
]
