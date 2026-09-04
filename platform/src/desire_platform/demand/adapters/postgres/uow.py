"""Default-deny PostgreSQL 18 seam for Demand.

This RED surface freezes role-bound settings, closed immutable database
requests, fixed statement identities, write checkpoints, receipt/source
identity, MATCH_INPUT allowlists, and the COMMIT_SENT boundary.  It contains
no SQL and deliberately fails before checking out a connection.  There is no
owner, BYPASSRLS, Memory, migration, or generic execute fallback.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from enum import Enum
import hashlib
import hmac
import json
import math
from types import MappingProxyType
from typing import Any, Callable, Dict, List, Mapping, Optional, Protocol, Tuple
from uuid import UUID

import psycopg

from ...domain import (
    DemandContent,
    DemandDomainError,
    canonical_demand_version_bytes,
    validate_demand_content,
)
from .migrations.runner import (
    DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
    DEMAND_SCHEMA_HEAD_VERSION,
)


DEMAND_POSTGRES_BEHAVIOR_NOT_AVAILABLE = "DEMAND_POSTGRES_BEHAVIOR_NOT_AVAILABLE"


class DemandPostgresBehaviorNotAvailable(RuntimeError):
    """Stable semantic-RED sentinel for absent reviewed SQL programs."""


class DemandPostgresConfigurationError(RuntimeError):
    """The role, server, catalog, transaction, or reset state is untrusted."""


class DemandPostgresDatabaseError(RuntimeError):
    """Closed semantic rejection from a future fixed SQL program."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class DemandPostgresCommitOutcomeUnknownError(RuntimeError):
    """COMMIT was sent but its durable outcome was not acknowledged."""

    code = "COMMAND_OUTCOME_UNKNOWN"


class DemandPostgresOperation(str, Enum):
    CREATE = "CreateDemand"
    CREATE_VERSION = "CreateDemandVersion"
    SUBMIT = "SubmitDemand"
    REQUEST_CHANGES = "RequestDemandChanges"
    VERIFY = "VerifyDemand"
    RELEASE_REVIEW_ASSIGNMENT = "ReleaseDemandReviewAssignment"
    APPLY_FUNDING_SECURED = "ApplyFundingSecured"
    REQUEST_MATCHING = "RequestMatching"
    REQUEST_MATCHING_SYSTEM = "RequestMatchingSystem"
    CANCEL_OWNER = "CancelDemandByOwner"
    CANCEL_REVIEW = "CancelDemandByReview"
    EXPIRE = "ExpireDemand"
    CAPTURE_MATCH_INPUTS = "CaptureDemandMatchInputs"


class DemandPostgresWriteCheckpoint(str, Enum):
    RECEIPT_PENDING = "receipt.pending"
    SOURCE_INBOX_PENDING = "source_inbox.pending"
    DEMAND_ROOT = "demand.root"
    DEMAND_VERSION = "demand_version.insert"
    SUBMISSION = "submission.insert"
    REVIEW = "review.insert"
    REVIEW_ASSIGNMENT = "review_assignment.complete"
    REVIEW_ASSIGNMENT_RELEASE = "review_assignment.release"
    REVIEW_ASSIGNMENT_RELEASE_FACT = "review_assignment_release.insert"
    FUNDING_MARKER = "funding_marker.insert"
    MATCHING_REQUEST = "matching_request.insert"
    AUDIT = "audit.insert"
    OUTBOX_DEMAND_CREATED = "outbox.demand_created"
    OUTBOX_VERSION_CREATED = "outbox.demand_version_created"
    OUTBOX_STATE_CHANGED = "outbox.state_changed"
    RECEIPT_COMPLETED = "receipt.completed"
    SOURCE_INBOX_COMPLETED = "source_inbox.completed"


DEMAND_POSTGRES_WRITE_CHECKPOINTS: Tuple[DemandPostgresWriteCheckpoint, ...] = (
    tuple(DemandPostgresWriteCheckpoint)
)

DEMAND_POSTGRES_SUBMIT_WRITE_CHECKPOINTS = (
    DemandPostgresWriteCheckpoint.RECEIPT_PENDING,
    DemandPostgresWriteCheckpoint.SUBMISSION,
    DemandPostgresWriteCheckpoint.DEMAND_ROOT,
    DemandPostgresWriteCheckpoint.AUDIT,
    DemandPostgresWriteCheckpoint.OUTBOX_STATE_CHANGED,
    DemandPostgresWriteCheckpoint.RECEIPT_COMPLETED,
)


class DemandPostgresConnectionSource(Protocol):
    """A connection source already bound to exactly one reviewed role."""

    def checkout(self) -> Any: ...

    def release(self, connection: Any) -> None: ...

    def discard(self, connection: Any) -> None: ...


class DemandPostgresFaultInjector(Protocol):
    def before_write(
        self,
        checkpoint: DemandPostgresWriteCheckpoint,
        ordinal: int,
    ) -> None: ...


class DemandPostgresSchemaValidator(Protocol):
    def validate(
        self,
        value: Mapping[str, Any],
        schema_name: Optional[str] = None,
    ) -> None: ...


class NoDemandPostgresFaults:
    def before_write(
        self,
        checkpoint: DemandPostgresWriteCheckpoint,
        ordinal: int,
    ) -> None:
        del checkpoint, ordinal


@dataclass(frozen=True)
class DemandPostgresSettings:
    self_role: str = "demand_self"
    review_role: str = "demand_review"
    finance_role: str = "demand_finance"
    matching_role: str = "demand_matching"
    system_role: str = "demand_system"
    required_server_major: int = 18
    lock_timeout_ms: int = 2_000
    statement_timeout_ms: int = 10_000
    idle_in_transaction_timeout_ms: int = 15_000
    maximum_canonical_version_bytes: int = 1024 * 1024
    maximum_match_requests: int = 500
    max_precommit_retries: int = 3

    def __post_init__(self) -> None:
        expected = (
            "demand_self",
            "demand_review",
            "demand_finance",
            "demand_matching",
            "demand_system",
        )
        actual = (
            self.self_role,
            self.review_role,
            self.finance_role,
            self.matching_role,
            self.system_role,
        )
        if actual != expected:
            raise ValueError("Demand online roles are not the reviewed closed set")
        if self.required_server_major != 18:
            raise ValueError("Demand PostgreSQL major must be 18")
        if not 1 <= self.lock_timeout_ms <= 10_000:
            raise ValueError("Demand lock timeout is outside reviewed bounds")
        if not 1 <= self.statement_timeout_ms <= 30_000:
            raise ValueError("Demand statement timeout is outside reviewed bounds")
        if not 1 <= self.idle_in_transaction_timeout_ms <= 30_000:
            raise ValueError("Demand idle timeout is outside reviewed bounds")
        if self.maximum_canonical_version_bytes != 1024 * 1024:
            raise ValueError("Demand v1 canonical version ceiling must be 1 MiB")
        if self.maximum_match_requests != 500:
            raise ValueError("Demand v1 MATCH_INPUT ceiling must be 500")
        if self.max_precommit_retries != 3:
            raise ValueError("Demand pre-COMMIT retry count must be exactly 3")


@dataclass(frozen=True)
class DemandPostgresStatementProfile:
    operation: DemandPostgresOperation
    runtime_role: str
    statement_names: Tuple[str, ...]
    statement_budget: int
    query_shape_sha256: str

    def __post_init__(self) -> None:
        expected_role = _ROLE_BY_OPERATION[self.operation]
        if self.runtime_role != expected_role:
            raise ValueError("Demand fixed program has the wrong online role")
        if (
            not self.statement_names
            or len(self.statement_names) != self.statement_budget
            or len(set(self.statement_names)) != len(self.statement_names)
        ):
            raise ValueError("Demand fixed statement budget is not closed")
        if (
            len(self.query_shape_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.query_shape_sha256
            )
        ):
            raise ValueError("Demand query-shape digest is invalid")


_ROLE_BY_OPERATION = MappingProxyType(
    {
        DemandPostgresOperation.CREATE: "demand_self",
        DemandPostgresOperation.CREATE_VERSION: "demand_self",
        DemandPostgresOperation.SUBMIT: "demand_self",
        DemandPostgresOperation.REQUEST_CHANGES: "demand_review",
        DemandPostgresOperation.VERIFY: "demand_review",
        DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT: "demand_review",
        DemandPostgresOperation.APPLY_FUNDING_SECURED: "demand_finance",
        DemandPostgresOperation.REQUEST_MATCHING: "demand_review",
        DemandPostgresOperation.REQUEST_MATCHING_SYSTEM: "demand_system",
        DemandPostgresOperation.CANCEL_OWNER: "demand_self",
        DemandPostgresOperation.CANCEL_REVIEW: "demand_review",
        DemandPostgresOperation.EXPIRE: "demand_system",
        DemandPostgresOperation.CAPTURE_MATCH_INPUTS: "demand_matching",
    }
)


def _statement_profile(
    operation: DemandPostgresOperation,
    names: Tuple[str, ...],
) -> DemandPostgresStatementProfile:
    role = _ROLE_BY_OPERATION[operation]
    material = json.dumps(
        {
            "operation": operation.value,
            "runtime_role": role,
            "statement_names": names,
            "statement_budget": len(names),
            "shape_version": "demand-postgres-v1",
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return DemandPostgresStatementProfile(
        operation=operation,
        runtime_role=role,
        statement_names=names,
        statement_budget=len(names),
        query_shape_sha256=hashlib.sha256(material).hexdigest(),
    )


DEMAND_POSTGRES_STATEMENT_PROFILES = MappingProxyType(
    {
        DemandPostgresOperation.CREATE: _statement_profile(
            DemandPostgresOperation.CREATE,
            (
                "iam_api.lock_demand_owner_authority_v1",
                "claim_demand_receipt_v1",
                "lock_demand_client_reference_v1",
                "insert_demand_root_v1",
                "insert_demand_version_v1",
                "insert_demand_audit_v1",
                "insert_demand_created_outbox_v1",
                "insert_demand_version_created_outbox_v1",
                "complete_demand_receipt_v1",
            ),
        ),
        DemandPostgresOperation.CREATE_VERSION: _statement_profile(
            DemandPostgresOperation.CREATE_VERSION,
            (
                "iam_api.lock_demand_owner_authority_v1",
                "lock_demand_graph_v1",
                "claim_demand_receipt_v1",
                "insert_demand_version_v1",
                "cas_demand_root_v1",
                "insert_demand_audit_v1",
                "insert_demand_outbox_v1",
                "complete_demand_receipt_v1",
            ),
        ),
        DemandPostgresOperation.SUBMIT: _statement_profile(
            DemandPostgresOperation.SUBMIT,
            (
                "iam_api.lock_demand_owner_authority_v1",
                "lock_demand_graph_v1",
                "claim_demand_receipt_v1",
                "revalidate_demand_submit_evidence_v1",
                "insert_demand_submission_v1",
                "cas_demand_root_v1",
                "insert_demand_audit_v1",
                "insert_demand_outbox_v1",
                "complete_demand_receipt_v1",
            ),
        ),
        DemandPostgresOperation.REQUEST_CHANGES: _statement_profile(
            DemandPostgresOperation.REQUEST_CHANGES,
            (
                "iam_api.lock_demand_reviewer_authority_v2",
                "lock_demand_graph_v1",
                "claim_demand_receipt_v1",
                "insert_demand_review_v1",
                "complete_demand_review_assignment_v1",
                "cas_demand_root_v1",
                "insert_demand_audit_v1",
                "insert_demand_outbox_v1",
                "complete_demand_receipt_v1",
            ),
        ),
        DemandPostgresOperation.VERIFY: _statement_profile(
            DemandPostgresOperation.VERIFY,
            (
                "iam_api.lock_demand_reviewer_authority_v2",
                "lock_demand_graph_v1",
                "claim_demand_receipt_v1",
                "revalidate_demand_verify_evidence_v1",
                "insert_demand_review_v1",
                "complete_demand_review_assignment_v1",
                "cas_demand_root_v1",
                "insert_demand_audit_v1",
                "insert_demand_outbox_v1",
                "complete_demand_receipt_v1",
            ),
        ),
        DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT: _statement_profile(
            DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT,
            (
                "iam_api.lock_demand_reviewer_authority_v2",
                "lock_demand_graph_v1",
                "claim_demand_receipt_v1",
                "release_demand_review_assignment_v1",
                "insert_demand_review_assignment_release_v1",
                "cas_demand_root_v1",
                "insert_demand_audit_v1",
                "insert_demand_outbox_v1",
                "complete_demand_receipt_v1",
            ),
        ),
        DemandPostgresOperation.APPLY_FUNDING_SECURED: _statement_profile(
            DemandPostgresOperation.APPLY_FUNDING_SECURED,
            (
                "lock_demand_finance_authority_v1",
                "lock_demand_graph_v1",
                "claim_demand_source_inbox_v1",
                "insert_demand_funding_marker_v1",
                "cas_demand_root_v1",
                "insert_demand_audit_v1",
                "insert_demand_outbox_v1",
                "complete_demand_source_inbox_v1",
            ),
        ),
        DemandPostgresOperation.REQUEST_MATCHING: _statement_profile(
            DemandPostgresOperation.REQUEST_MATCHING,
            (
                "iam_api.lock_demand_reviewer_authority_v2",
                "lock_demand_graph_v1",
                "claim_demand_receipt_v1",
                "revalidate_demand_matching_evidence_v1",
                "insert_demand_matching_request_v1",
                "cas_demand_root_v1",
                "insert_demand_audit_v1",
                "insert_demand_outbox_v1",
                "complete_demand_receipt_v1",
            ),
        ),
        DemandPostgresOperation.REQUEST_MATCHING_SYSTEM: _statement_profile(
            DemandPostgresOperation.REQUEST_MATCHING_SYSTEM,
            (
                "lock_demand_system_authority_v1",
                "lock_demand_graph_v1",
                "claim_demand_receipt_v1",
                "revalidate_demand_matching_evidence_v1",
                "insert_demand_matching_request_v1",
                "cas_demand_root_v1",
                "insert_demand_audit_v1",
                "insert_demand_outbox_v1",
                "complete_demand_receipt_v1",
            ),
        ),
        DemandPostgresOperation.CANCEL_OWNER: _statement_profile(
            DemandPostgresOperation.CANCEL_OWNER,
            (
                "iam_api.lock_demand_owner_authority_v1",
                "lock_demand_graph_v1",
                "claim_demand_receipt_v1",
                "cas_demand_root_v1",
                "insert_demand_audit_v1",
                "insert_demand_outbox_v1",
                "complete_demand_receipt_v1",
            ),
        ),
        DemandPostgresOperation.CANCEL_REVIEW: _statement_profile(
            DemandPostgresOperation.CANCEL_REVIEW,
            (
                "iam_api.lock_demand_reviewer_authority_v2",
                "lock_demand_graph_v1",
                "claim_demand_receipt_v1",
                "cas_demand_root_v1",
                "insert_demand_audit_v1",
                "insert_demand_outbox_v1",
                "complete_demand_receipt_v1",
            ),
        ),
        DemandPostgresOperation.EXPIRE: _statement_profile(
            DemandPostgresOperation.EXPIRE,
            (
                "lock_demand_system_authority_v1",
                "lock_demand_graph_v1",
                "claim_demand_source_inbox_v1",
                "cas_demand_root_v1",
                "insert_demand_audit_v1",
                "insert_demand_outbox_v1",
                "complete_demand_source_inbox_v1",
            ),
        ),
        DemandPostgresOperation.CAPTURE_MATCH_INPUTS: _statement_profile(
            DemandPostgresOperation.CAPTURE_MATCH_INPUTS,
            (
                "lock_demand_match_capture_scope_v1",
                "capture_demand_match_inputs_v1",
            ),
        ),
    }
)


@dataclass(frozen=True)
class DemandPostgresReceiptMaterial:
    receipt_id: UUID
    principal_kind: str
    principal_id: UUID
    organization_id: UUID
    command_name: str
    command_version: int
    idempotency_key_digest_key_id: str
    idempotency_key_digest: bytes = field(repr=False)
    payload_hash_key_id: str
    canonicalization_version: str
    payload_hash: bytes = field(repr=False)
    http_method: str
    canonical_path: str
    if_match_version: Optional[int]
    retain_until: datetime

    def __post_init__(self) -> None:
        for value, label in (
            (self.receipt_id, "receipt ID"),
            (self.principal_id, "receipt principal"),
            (self.organization_id, "receipt organization"),
        ):
            _require_uuid(value, label)
        if self.principal_kind not in {"USER", "SYSTEM"}:
            raise ValueError("Demand command receipt principal kind is not closed")
        if self.command_name not in _RECEIPT_COMMAND_NAMES:
            raise ValueError("Demand receipt command name is not closed")
        _require_positive_int(self.command_version, "receipt command version")
        if self.command_version != 1:
            raise ValueError("Demand receipt command version must be 1")
        _require_key_id(self.idempotency_key_digest_key_id, "identity key ID")
        _require_digest(self.idempotency_key_digest, "identity digest")
        _require_key_id(self.payload_hash_key_id, "payload key ID")
        if self.idempotency_key_digest_key_id == self.payload_hash_key_id:
            raise ValueError("Demand receipt identity and payload keys must differ")
        _require_digest(self.payload_hash, "payload HMAC")
        if self.canonicalization_version != "demand-command-json-v1":
            raise ValueError("unsupported Demand receipt canonicalization")
        if self.http_method != "POST" or not self.canonical_path.startswith("/v1/"):
            raise ValueError("Demand receipt transport identity is invalid")
        if self.command_name == "CreateDemand":
            if self.if_match_version is not None:
                raise ValueError("CreateDemand receipt transport identity is open")
        else:
            _require_positive_int(self.if_match_version, "receipt If-Match version")
        _require_utc(self.retain_until, "receipt retain_until")


@dataclass(frozen=True)
class DemandPostgresExecutionScope:
    actor_kind: str
    actor_id: UUID
    session_id: Optional[UUID] = field(repr=False)
    organization_id: UUID
    demand_id: UUID
    command_id: UUID
    audit_event_id: UUID
    outbox_event_ids: Tuple[UUID, ...]
    correlation_id: UUID
    causation_id: UUID
    trace_id: UUID
    original_actor_id: Optional[UUID]
    expected_authority_marker_sha256: bytes = field(repr=False)

    def __post_init__(self) -> None:
        for value, label in (
            (self.actor_id, "actor"),
            (self.organization_id, "organization"),
            (self.demand_id, "Demand"),
            (self.command_id, "command"),
            (self.audit_event_id, "audit event"),
            (self.correlation_id, "correlation"),
            (self.causation_id, "causation"),
            (self.trace_id, "trace"),
        ):
            _require_uuid(value, label)
        if self.actor_kind not in {"USER", "SYSTEM"}:
            raise ValueError("Demand database actor kind is not closed")
        if self.actor_kind == "USER":
            _require_uuid(self.session_id, "Session")
        elif self.session_id is not None:
            raise ValueError("SYSTEM Demand scope cannot carry a Session")
        if self.original_actor_id is not None:
            _require_uuid(self.original_actor_id, "original actor")
        if len(set(self.outbox_event_ids)) != len(self.outbox_event_ids):
            raise ValueError("Demand outbox event IDs are not unique")
        for value in self.outbox_event_ids:
            _require_uuid(value, "outbox event")
        _require_digest(self.expected_authority_marker_sha256, "authority marker")


@dataclass(frozen=True)
class DemandPostgresContentPolicyEvidence:
    demand_id: UUID
    demand_version_id: UUID
    content_sha256: bytes = field(repr=False)
    decision: str
    policy_version: str
    result_sha256: bytes = field(repr=False)
    evaluated_at: datetime
    valid_until: datetime

    def __post_init__(self) -> None:
        _require_uuid(self.demand_id, "content-policy Demand")
        _require_uuid(self.demand_version_id, "content-policy version")
        _require_digest(self.content_sha256, "content-policy content hash")
        if self.decision != "ALLOW" or self.policy_version != "demand-content-policy-v1":
            raise ValueError("Demand content-policy evidence is not an ALLOW v1 result")
        _require_digest(self.result_sha256, "content-policy result digest")
        _require_window(self.evaluated_at, self.valid_until, "content-policy")


@dataclass(frozen=True)
class DemandPostgresHoldEvidence:
    actor_id: UUID
    organization_id: UUID
    demand_id: UUID
    prospective_aggregate_version: int
    demand_version_id: UUID
    content_sha256: bytes = field(repr=False)
    action: str
    decision: str
    policy_version: str
    evaluated_at: datetime
    valid_until: datetime

    def __post_init__(self) -> None:
        for value, label in (
            (self.actor_id, "hold actor"),
            (self.organization_id, "hold organization"),
            (self.demand_id, "hold Demand"),
            (self.demand_version_id, "hold DemandVersion"),
        ):
            _require_uuid(value, label)
        _require_positive_int(self.prospective_aggregate_version, "hold version")
        _require_digest(self.content_sha256, "hold content hash")
        if self.action not in {"SUBMIT_DEMAND", "VERIFY_DEMAND", "REQUEST_MATCHING"}:
            raise ValueError("Demand hold action is not closed")
        if self.decision != "ALLOW" or self.policy_version != "demand-safety-hold-v1":
            raise ValueError("Demand hold evidence is not an ALLOW v1 result")
        _require_window(self.evaluated_at, self.valid_until, "hold")


@dataclass(frozen=True)
class DemandPostgresRuleRequirement:
    taxonomy_bundle_id: UUID
    budget_rule_bundle_id: UUID
    risk_rule_bundle_id: UUID
    matching_rule_bundle_id: UUID
    reason_code_bundle_id: UUID
    composite_rule_requirement_id: UUID
    requirement_sha256: bytes = field(repr=False)
    effective_at: datetime
    effective_until: Optional[datetime]

    def __post_init__(self) -> None:
        for value, label in (
            (self.taxonomy_bundle_id, "taxonomy bundle"),
            (self.budget_rule_bundle_id, "budget rule bundle"),
            (self.risk_rule_bundle_id, "risk rule bundle"),
            (self.matching_rule_bundle_id, "matching rule bundle"),
            (self.reason_code_bundle_id, "reason-code bundle"),
            (self.composite_rule_requirement_id, "composite requirement"),
        ):
            _require_uuid(value, label)
        _require_digest(self.requirement_sha256, "rule requirement digest")
        _require_utc(self.effective_at, "rule effective_at")
        if self.effective_until is not None:
            _require_utc(self.effective_until, "rule effective_until")
            if self.effective_until <= self.effective_at:
                raise ValueError("Demand rule requirement has an empty window")


@dataclass(frozen=True)
class DemandPostgresSourceEvent:
    source_event_id: UUID
    event_type: str
    schema_version: int
    source_aggregate_type: str
    source_aggregate_id: UUID
    source_aggregate_version: int
    organization_id: UUID
    demand_id: UUID
    demand_version_id: UUID
    funding_id: Optional[UUID]
    envelope_sha256: bytes = field(repr=False)
    occurred_at: datetime
    amount_currency_sha256: Optional[bytes] = field(default=None, repr=False)
    verification_reference_sha256: Optional[bytes] = field(default=None, repr=False)

    def __post_init__(self) -> None:
        for value, label in (
            (self.source_event_id, "source event"),
            (self.source_aggregate_id, "source aggregate"),
            (self.organization_id, "source organization"),
            (self.demand_id, "source Demand"),
            (self.demand_version_id, "source DemandVersion"),
        ):
            _require_uuid(value, label)
        _require_positive_int(self.schema_version, "source schema version")
        if self.schema_version != 1:
            raise ValueError("Demand source schema version must be 1")
        _require_positive_int(self.source_aggregate_version, "source aggregate version")
        if self.event_type == "FundingSecured":
            if self.source_aggregate_type != "Funding" or self.funding_id != self.source_aggregate_id:
                raise ValueError("Funding source identity is invalid")
            _require_uuid(self.funding_id, "funding ID")
            _require_digest(self.amount_currency_sha256, "amount/currency digest")
            _require_digest(
                self.verification_reference_sha256,
                "funding verification digest",
            )
        elif self.event_type == "DemandExpiryDue":
            if (
                self.source_aggregate_type != "Scheduler"
                or self.funding_id is not None
                or self.amount_currency_sha256 is not None
                or self.verification_reference_sha256 is not None
            ):
                raise ValueError("Demand expiry source identity is invalid")
        else:
            raise ValueError("Demand source event type is not closed")
        _require_digest(self.envelope_sha256, "source envelope digest")
        _require_utc(self.occurred_at, "source occurred_at")


_RECEIPT_COMMAND_NAMES = frozenset(
    {
        "CreateDemand",
        "CreateDemandVersion",
        "SubmitDemand",
        "RequestDemandChanges",
        "VerifyDemand",
        "ReleaseDemandReviewAssignment",
        "RequestMatching",
        "CancelDemand",
    }
)

_EXPECTED_RECEIPT_NAME = MappingProxyType(
    {
        DemandPostgresOperation.CREATE: "CreateDemand",
        DemandPostgresOperation.CREATE_VERSION: "CreateDemandVersion",
        DemandPostgresOperation.SUBMIT: "SubmitDemand",
        DemandPostgresOperation.REQUEST_CHANGES: "RequestDemandChanges",
        DemandPostgresOperation.VERIFY: "VerifyDemand",
        DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT: "ReleaseDemandReviewAssignment",
        DemandPostgresOperation.REQUEST_MATCHING: "RequestMatching",
        DemandPostgresOperation.REQUEST_MATCHING_SYSTEM: "RequestMatching",
        DemandPostgresOperation.CANCEL_OWNER: "CancelDemand",
        DemandPostgresOperation.CANCEL_REVIEW: "CancelDemand",
    }
)


@dataclass(frozen=True)
class DemandPostgresCommand:
    operation: DemandPostgresOperation
    scope: DemandPostgresExecutionScope
    receipt: Optional[DemandPostgresReceiptMaterial]
    expected_aggregate_version: Optional[int]
    demand_version_id: Optional[UUID]
    based_on_demand_version_id: Optional[UUID]
    taxonomy_bundle_id: Optional[UUID]
    canonical_demand_version_bytes: Optional[bytes] = field(default=None, repr=False)
    content_sha256: Optional[bytes] = field(default=None, repr=False)
    client_reference_digest_key_id: Optional[str] = None
    client_reference_digest: Optional[bytes] = field(default=None, repr=False)
    submission_id: Optional[UUID] = None
    assignment_id: Optional[UUID] = None
    review_id: Optional[UUID] = None
    reason_codes: Tuple[str, ...] = ()
    required_field_codes: Tuple[str, ...] = ()
    budget_health_code: Optional[str] = None
    risk_code: Optional[str] = None
    evidence_summary_sha256: Optional[bytes] = field(default=None, repr=False)
    funding_marker_id: Optional[UUID] = None
    matching_request_id: Optional[UUID] = None
    cancel_reason_code: Optional[str] = None
    release_reason_code: Optional[str] = None
    deadline: Optional[datetime] = None
    content_policy: Optional[DemandPostgresContentPolicyEvidence] = field(
        default=None,
        repr=False,
    )
    hold: Optional[DemandPostgresHoldEvidence] = field(default=None, repr=False)
    rule_requirement: Optional[DemandPostgresRuleRequirement] = field(
        default=None,
        repr=False,
    )
    source_event: Optional[DemandPostgresSourceEvent] = field(
        default=None,
        repr=False,
    )

    def __post_init__(self) -> None:
        if not isinstance(self.operation, DemandPostgresOperation):
            raise ValueError("Demand PostgreSQL operation is not closed")
        if self.operation is DemandPostgresOperation.CAPTURE_MATCH_INPUTS:
            raise ValueError("MATCH_INPUT is not a writer command")
        expected_actor = (
            "SYSTEM"
            if self.operation
            in {
                DemandPostgresOperation.APPLY_FUNDING_SECURED,
                DemandPostgresOperation.REQUEST_MATCHING_SYSTEM,
                DemandPostgresOperation.EXPIRE,
            }
            else "USER"
        )
        if self.scope.actor_kind != expected_actor:
            raise ValueError("Demand actor kind does not match the fixed program")
        expected_events = 2 if self.operation is DemandPostgresOperation.CREATE else 1
        if len(self.scope.outbox_event_ids) != expected_events:
            raise ValueError("Demand outbox IDs do not match operation semantics")
        expected_receipt_name = _EXPECTED_RECEIPT_NAME.get(self.operation)
        if expected_receipt_name is None:
            if self.receipt is not None:
                raise ValueError("source-driven Demand command cannot carry a receipt")
        else:
            if self.receipt is None:
                raise ValueError("user Demand command requires a receipt")
            if (
                self.receipt.command_name != expected_receipt_name
                or self.receipt.principal_kind != self.scope.actor_kind
                or self.receipt.receipt_id != self.scope.command_id
                or self.receipt.principal_id != self.scope.actor_id
                or self.receipt.organization_id != self.scope.organization_id
            ):
                raise ValueError("Demand receipt is not bound to the command scope")
            if self.receipt.canonical_path != self._expected_receipt_path():
                raise ValueError("Demand receipt path is not bound to the fixed program")
        if self.operation is DemandPostgresOperation.CREATE:
            if self.expected_aggregate_version is not None:
                raise ValueError("CreateDemand cannot carry expected aggregate version")
        else:
            _require_positive_int(
                self.expected_aggregate_version,
                "expected Demand aggregate version",
            )
        self._validate_operation_shape()

    def _expected_receipt_path(self) -> str:
        organization = str(self.scope.organization_id)
        demand = str(self.scope.demand_id)
        if self.operation is DemandPostgresOperation.CREATE:
            return f"/v1/organizations/{organization}/demands"
        if self.operation is DemandPostgresOperation.CREATE_VERSION:
            return f"/v1/organizations/{organization}/demands/{demand}/versions"
        if self.operation is DemandPostgresOperation.SUBMIT:
            return f"/v1/organizations/{organization}/demands/{demand}/submit"
        if self.operation is DemandPostgresOperation.REQUEST_CHANGES:
            return f"/v1/operations/demand-review-assignments/{self.assignment_id}/request-changes"
        if self.operation is DemandPostgresOperation.VERIFY:
            return f"/v1/operations/demand-review-assignments/{self.assignment_id}/verify"
        if self.operation is DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT:
            return f"/v1/operations/demand-review-assignments/{self.assignment_id}/release"
        if self.operation in {
            DemandPostgresOperation.REQUEST_MATCHING,
            DemandPostgresOperation.REQUEST_MATCHING_SYSTEM,
        }:
            return f"/v1/operations/demands/{demand}/request-matching"
        if self.operation in {
            DemandPostgresOperation.CANCEL_OWNER,
            DemandPostgresOperation.CANCEL_REVIEW,
        }:
            return f"/v1/organizations/{organization}/demands/{demand}/cancel"
        raise ValueError("source-driven Demand command has no receipt path")

    def _validate_operation_shape(self) -> None:
        op = self.operation
        if op is DemandPostgresOperation.CREATE:
            self._require_version_material(based_required=False, client_required=True)
            self._require_absent(
                "submission_id", "assignment_id", "review_id", "funding_marker_id",
                "matching_request_id", "cancel_reason_code", "deadline",
                "content_policy", "hold", "rule_requirement", "source_event",
            )
        elif op is DemandPostgresOperation.CREATE_VERSION:
            self._require_version_material(based_required=True, client_required=False)
            self._require_absent(
                "submission_id", "assignment_id", "review_id", "funding_marker_id",
                "matching_request_id", "cancel_reason_code", "deadline",
                "content_policy", "hold", "rule_requirement", "source_event",
            )
        elif op is DemandPostgresOperation.SUBMIT:
            self._require_uuid_fields("demand_version_id", "submission_id")
            self._require_evidence(content_policy=True, hold_action="SUBMIT_DEMAND", rules=True)
            if self.reason_codes or self.required_field_codes:
                raise ValueError("SubmitDemand cannot carry review codes")
            self._require_absent(
                "based_on_demand_version_id", "taxonomy_bundle_id",
                "canonical_demand_version_bytes", "content_sha256",
                "client_reference_digest_key_id", "client_reference_digest",
                "assignment_id", "review_id", "funding_marker_id",
                "matching_request_id", "cancel_reason_code", "deadline", "source_event",
                "budget_health_code", "risk_code", "evidence_summary_sha256",
            )
        elif op is DemandPostgresOperation.REQUEST_CHANGES:
            self._require_uuid_fields("demand_version_id", "assignment_id", "review_id")
            _require_code_tuple(self.reason_codes, "review reason codes", nonempty=True)
            _require_code_tuple(
                self.required_field_codes,
                "required field codes",
                nonempty=True,
            )
            self._require_absent_common_review_evidence()
        elif op is DemandPostgresOperation.VERIFY:
            self._require_uuid_fields("demand_version_id", "assignment_id", "review_id")
            if self.reason_codes or self.required_field_codes:
                raise ValueError("VerifyDemand cannot carry change-request codes")
            if self.budget_health_code not in {"HEALTHY", "APPROVED_EXCEPTION"}:
                raise ValueError("VerifyDemand budget health code is not closed")
            if self.risk_code not in {"STANDARD", "ELEVATED_APPROVED"}:
                raise ValueError("VerifyDemand risk code is not closed")
            _require_digest(self.evidence_summary_sha256, "review evidence digest")
            self._require_evidence(content_policy=False, hold_action="VERIFY_DEMAND", rules=True)
            self._require_absent(
                "based_on_demand_version_id", "taxonomy_bundle_id",
                "canonical_demand_version_bytes", "content_sha256",
                "client_reference_digest_key_id", "client_reference_digest",
                "submission_id", "funding_marker_id", "matching_request_id",
                "cancel_reason_code", "deadline", "source_event",
            )
        elif op is DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT:
            self._require_uuid_fields("demand_version_id", "assignment_id")
            if self.release_reason_code not in {
                "CONFLICT_DECLARED",
                "WORKLOAD_RELEASE",
            }:
                raise ValueError("review assignment release reason code is not closed")
            if self.reason_codes or self.required_field_codes:
                raise ValueError("review assignment release cannot carry review codes")
            self._require_absent(
                "based_on_demand_version_id", "taxonomy_bundle_id",
                "canonical_demand_version_bytes", "content_sha256",
                "client_reference_digest_key_id", "client_reference_digest",
                "submission_id", "review_id", "funding_marker_id",
                "matching_request_id", "cancel_reason_code", "deadline",
                "content_policy", "hold", "rule_requirement", "source_event",
                "budget_health_code", "risk_code", "evidence_summary_sha256",
            )
        elif op is DemandPostgresOperation.APPLY_FUNDING_SECURED:
            self._require_uuid_fields("demand_version_id", "funding_marker_id")
            if self.source_event is None or self.source_event.event_type != "FundingSecured":
                raise ValueError("ApplyFundingSecured requires a Funding source event")
            self._require_source_binding()
            self._require_absent_except_source()
        elif op in {
            DemandPostgresOperation.REQUEST_MATCHING,
            DemandPostgresOperation.REQUEST_MATCHING_SYSTEM,
        }:
            self._require_uuid_fields("demand_version_id", "matching_request_id")
            if op is DemandPostgresOperation.REQUEST_MATCHING:
                self._require_uuid_fields("assignment_id")
            elif self.assignment_id is not None:
                raise ValueError("system RequestMatching cannot carry an assignment")
            self._require_evidence(
                content_policy=False,
                hold_action="REQUEST_MATCHING",
                rules=True,
            )
            self._require_absent(
                "based_on_demand_version_id", "taxonomy_bundle_id",
                "canonical_demand_version_bytes", "content_sha256",
                "client_reference_digest_key_id", "client_reference_digest",
                "submission_id", "review_id", "funding_marker_id",
                "cancel_reason_code", "deadline", "source_event",
                "budget_health_code", "risk_code", "evidence_summary_sha256",
            )
            if self.reason_codes or self.required_field_codes:
                raise ValueError("RequestMatching cannot carry review codes")
        elif op in {
            DemandPostgresOperation.CANCEL_OWNER,
            DemandPostgresOperation.CANCEL_REVIEW,
        }:
            if self.cancel_reason_code not in {
                "OWNER_WITHDREW", "REQUIREMENTS_CHANGED", "REVIEW_CLOSED",
                "FUNDING_UNAVAILABLE", "SAFETY_RESTRICTION",
            }:
                raise ValueError("CancelDemand reason code is not closed")
            if op is DemandPostgresOperation.CANCEL_REVIEW:
                self._require_uuid_fields("assignment_id")
            elif self.assignment_id is not None:
                raise ValueError("owner cancel cannot carry a review assignment")
            self._require_absent(
                "demand_version_id", "based_on_demand_version_id", "taxonomy_bundle_id",
                "canonical_demand_version_bytes", "content_sha256",
                "client_reference_digest_key_id", "client_reference_digest",
                "submission_id", "review_id", "funding_marker_id",
                "matching_request_id", "deadline", "content_policy", "hold",
                "rule_requirement", "source_event", "budget_health_code",
                "risk_code", "evidence_summary_sha256",
            )
            if self.reason_codes or self.required_field_codes:
                raise ValueError("CancelDemand cannot carry review codes")
        elif op is DemandPostgresOperation.EXPIRE:
            if self.deadline is None:
                raise ValueError("ExpireDemand requires a deadline")
            _require_utc(self.deadline, "Demand expiry deadline")
            if self.source_event is None or self.source_event.event_type != "DemandExpiryDue":
                raise ValueError("ExpireDemand requires a scheduler source event")
            self._require_source_binding()
            self._require_absent_except_source(keep_deadline=True)
            if self.funding_marker_id is not None:
                raise ValueError("ExpireDemand cannot carry a Funding marker")
        else:
            raise ValueError("unknown Demand writer operation")

        if (
            op is not DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT
            and self.release_reason_code is not None
        ):
            raise ValueError("Demand database request has an open operation shape")

    def _require_version_material(
        self,
        *,
        based_required: bool,
        client_required: bool,
    ) -> None:
        self._require_uuid_fields("demand_version_id", "taxonomy_bundle_id")
        if based_required:
            self._require_uuid_fields("based_on_demand_version_id")
        elif self.based_on_demand_version_id is not None:
            raise ValueError("initial DemandVersion cannot carry based-on ID")
        canonical = self.canonical_demand_version_bytes
        if not isinstance(canonical, bytes) or not canonical or len(canonical) > 1024 * 1024:
            raise ValueError("canonical DemandVersion bytes are outside v1 bounds")
        _require_digest(self.content_sha256, "DemandVersion content hash")
        if client_required:
            _require_key_id(self.client_reference_digest_key_id, "client reference key ID")
            _require_digest(self.client_reference_digest, "client reference digest")
        elif self.client_reference_digest_key_id is not None or self.client_reference_digest is not None:
            raise ValueError("non-create Demand command cannot carry client reference")
        if self.reason_codes or self.required_field_codes:
            raise ValueError("DemandVersion command cannot carry review codes")
        self._require_absent("budget_health_code", "risk_code", "evidence_summary_sha256")

    def _require_evidence(
        self,
        *,
        content_policy: bool,
        hold_action: str,
        rules: bool,
    ) -> None:
        if content_policy != (self.content_policy is not None):
            raise ValueError("Demand content-policy evidence shape is invalid")
        if self.hold is None or self.hold.action != hold_action:
            raise ValueError("Demand hold evidence does not match the operation")
        if rules != (self.rule_requirement is not None):
            raise ValueError("Demand rule requirement shape is invalid")
        if (
            self.hold.actor_id != self.scope.actor_id
            or self.hold.organization_id != self.scope.organization_id
            or self.hold.demand_id != self.scope.demand_id
            or self.hold.demand_version_id != self.demand_version_id
            or self.hold.prospective_aggregate_version
            != self.expected_aggregate_version + 1
        ):
            raise ValueError("Demand hold is not bound to the database command")
        if self.content_policy is not None and (
            self.content_policy.demand_id != self.scope.demand_id
            or self.content_policy.demand_version_id != self.demand_version_id
            or self.content_policy.content_sha256 != self.hold.content_sha256
        ):
            raise ValueError("Demand content-policy evidence is misbound")

    def _require_absent_common_review_evidence(self) -> None:
        self._require_absent(
            "based_on_demand_version_id", "taxonomy_bundle_id",
            "canonical_demand_version_bytes", "content_sha256",
            "client_reference_digest_key_id", "client_reference_digest",
            "submission_id", "funding_marker_id", "matching_request_id",
            "cancel_reason_code", "deadline", "content_policy", "hold",
            "rule_requirement", "source_event", "budget_health_code",
            "risk_code", "evidence_summary_sha256",
        )

    def _require_source_binding(self) -> None:
        if (
            self.source_event.organization_id != self.scope.organization_id
            or self.source_event.demand_id != self.scope.demand_id
            or self.source_event.demand_version_id != self.demand_version_id
            or self.source_event.source_event_id != self.scope.causation_id
        ):
            raise ValueError("Demand source event is not bound to the command")

    def _require_absent_except_source(self, *, keep_deadline: bool = False) -> None:
        names = [
            "based_on_demand_version_id", "taxonomy_bundle_id",
            "canonical_demand_version_bytes", "content_sha256",
            "client_reference_digest_key_id", "client_reference_digest",
            "submission_id", "assignment_id", "review_id", "matching_request_id",
            "cancel_reason_code", "content_policy", "hold", "rule_requirement",
            "budget_health_code", "risk_code", "evidence_summary_sha256",
        ]
        if not keep_deadline:
            names.append("deadline")
        self._require_absent(*names)
        if self.reason_codes or self.required_field_codes:
            raise ValueError("source-driven Demand command cannot carry review codes")

    def _require_uuid_fields(self, *names: str) -> None:
        for name in names:
            _require_uuid(getattr(self, name), name.replace("_", " "))

    def _require_absent(self, *names: str) -> None:
        if any(getattr(self, name) is not None for name in names):
            raise ValueError("Demand database request has an open operation shape")


@dataclass(frozen=True)
class DemandPostgresDatabaseResult:
    operation: DemandPostgresOperation
    replayed: bool
    demand_id: UUID
    current_version_id: UUID
    status: str
    aggregate_version: int
    safe_response: Mapping[str, Any] = field(repr=False)
    event_types: Tuple[str, ...]


@dataclass(frozen=True)
class DemandPostgresMatchCaptureRequest:
    match_run_id: UUID
    workload_principal_id: UUID
    matching_request_ids: Tuple[UUID, ...]
    authorization_digest: bytes = field(repr=False)
    requested_at: datetime

    def __post_init__(self) -> None:
        _require_uuid(self.match_run_id, "MatchRun")
        _require_uuid(self.workload_principal_id, "matching workload")
        if (
            not self.matching_request_ids
            or len(self.matching_request_ids) > 500
            or len(set(self.matching_request_ids)) != len(self.matching_request_ids)
            or self.matching_request_ids
            != tuple(sorted(self.matching_request_ids, key=lambda value: value.bytes))
        ):
            raise ValueError("Demand matching request allowlist is not canonical")
        for value in self.matching_request_ids:
            _require_uuid(value, "MatchingRequest")
        _require_digest(self.authorization_digest, "MATCH_INPUT authorization digest")
        _require_utc(self.requested_at, "MATCH_INPUT requested_at")


@dataclass(frozen=True, repr=False)
class DemandPostgresMatchSkillRequirement:
    skill_code: str
    minimum_level: int

    def __post_init__(self) -> None:
        _require_code(self.skill_code, "MATCH_INPUT skill code")
        if (
            isinstance(self.minimum_level, bool)
            or not isinstance(self.minimum_level, int)
            or not 1 <= self.minimum_level <= 4
        ):
            raise ValueError("MATCH_INPUT skill level must be an integer from 1 to 4")

    def __repr__(self) -> str:
        return "DemandPostgresMatchSkillRequirement(<redacted>)"


@dataclass(frozen=True, repr=False)
class DemandPostgresMatchInputSnapshot:
    matching_request_id: UUID
    matching_request_version: int
    matching_request_status: str
    organization_id: UUID
    demand_id: UUID
    demand_status: str
    demand_version_id: UUID
    demand_version_no: int
    verification_decision: str
    content_sha256: bytes = field(repr=False)
    canonical_demand_version_bytes: bytes = field(repr=False)
    taxonomy_bundle_id: UUID
    funding_id: UUID
    funding_status: str
    composite_rule_requirement_id: UUID
    budget_rule_bundle_id: UUID
    risk_rule_bundle_id: UUID
    matching_rule_bundle_id: UUID
    reason_code_bundle_id: UUID
    matching_selector_digest: bytes = field(repr=False)
    rule_requirement_sha256: bytes = field(repr=False)
    problem_type_codes: Tuple[str, ...]
    domain_codes: Tuple[str, ...]
    task_codes: Tuple[str, ...]
    must_have_skills: Tuple[DemandPostgresMatchSkillRequirement, ...]
    nice_to_have_skills: Tuple[DemandPostgresMatchSkillRequirement, ...]
    start_date: date
    due_date: date
    required_weekly_hours: int
    required_duration_weeks: int
    currency: str
    minimum_amount_minor: int = field(repr=False)
    maximum_amount_minor: int = field(repr=False)
    allowed_region_codes: Tuple[str, ...] = field(repr=False)
    required_language_codes: Tuple[str, ...] = field(repr=False)
    required_work_mode_code: str = field(repr=False)
    data_sensitivity_code: str = field(repr=False)
    ai_use_code: str = field(repr=False)
    budget_override_code: Optional[str] = field(repr=False)
    captured_at: datetime

    def __post_init__(self) -> None:
        for value, label in (
            (self.matching_request_id, "MatchingRequest"),
            (self.organization_id, "MATCH_INPUT organization"),
            (self.demand_id, "MATCH_INPUT Demand"),
            (self.demand_version_id, "MATCH_INPUT DemandVersion"),
            (self.taxonomy_bundle_id, "MATCH_INPUT taxonomy bundle"),
            (self.funding_id, "MATCH_INPUT Funding"),
            (self.composite_rule_requirement_id, "composite rule requirement"),
            (self.budget_rule_bundle_id, "budget rule bundle"),
            (self.risk_rule_bundle_id, "risk rule bundle"),
            (self.matching_rule_bundle_id, "matching rule bundle"),
            (self.reason_code_bundle_id, "reason-code bundle"),
        ):
            _require_uuid(value, label)
        _require_positive_int(
            self.matching_request_version,
            "MatchingRequest version",
        )
        _require_positive_int(self.demand_version_no, "DemandVersion number")
        if self.matching_request_status != "OPEN":
            raise ValueError("MATCH_INPUT requires an OPEN MatchingRequest")
        if self.demand_status != "MATCHING":
            raise ValueError("MATCH_INPUT requires a MATCHING Demand")
        if self.verification_decision != "VERIFIED":
            raise ValueError("MATCH_INPUT requires an exact VERIFIED DemandVersion")
        if self.funding_status != "SECURED":
            raise ValueError("MATCH_INPUT requires exact SECURED Funding")
        _require_digest(self.content_sha256, "MATCH_INPUT content digest")
        if (
            not isinstance(self.canonical_demand_version_bytes, bytes)
            or not self.canonical_demand_version_bytes
            or len(self.canonical_demand_version_bytes) > 1024 * 1024
        ):
            raise ValueError("MATCH_INPUT canonical DemandVersion is outside v1 bounds")
        _require_digest(self.matching_selector_digest, "matching selector digest")
        _require_digest(self.rule_requirement_sha256, "rule requirement digest")
        for value, label in (
            (self.problem_type_codes, "problem type codes"),
            (self.domain_codes, "domain codes"),
            (self.task_codes, "task codes"),
            (self.allowed_region_codes, "allowed region codes"),
            (self.required_language_codes, "required language codes"),
        ):
            _require_canonical_code_tuple(value, label)
        for value, label in (
            (self.must_have_skills, "must-have skills"),
            (self.nice_to_have_skills, "nice-to-have skills"),
        ):
            _require_canonical_skill_tuple(value, label)
        if {
            item.skill_code for item in self.must_have_skills
        }.intersection(item.skill_code for item in self.nice_to_have_skills):
            raise ValueError("MATCH_INPUT must-have and nice-to-have skills overlap")
        if (
            not isinstance(self.start_date, date)
            or isinstance(self.start_date, datetime)
            or not isinstance(self.due_date, date)
            or isinstance(self.due_date, datetime)
            or self.due_date < self.start_date
        ):
            raise ValueError("MATCH_INPUT schedule dates are invalid")
        _require_bounded_nonbool_int(
            self.required_weekly_hours,
            "required weekly hours",
            minimum=1,
            maximum=168,
        )
        _require_bounded_nonbool_int(
            self.required_duration_weeks,
            "required duration weeks",
            minimum=1,
            maximum=520,
        )
        if (
            not isinstance(self.currency, str)
            or len(self.currency) != 3
            or not self.currency.isascii()
            or not self.currency.isalpha()
            or self.currency != self.currency.upper()
        ):
            raise ValueError("MATCH_INPUT currency is invalid")
        _require_bounded_nonbool_int(
            self.minimum_amount_minor,
            "minimum amount",
            minimum=0,
            maximum=9_007_199_254_740_991,
        )
        _require_bounded_nonbool_int(
            self.maximum_amount_minor,
            "maximum amount",
            minimum=0,
            maximum=9_007_199_254_740_991,
        )
        if self.minimum_amount_minor > self.maximum_amount_minor:
            raise ValueError("MATCH_INPUT offered budget range is inverted")
        _require_code(self.required_work_mode_code, "required work mode")
        if self.data_sensitivity_code not in {
            "PUBLIC", "INTERNAL", "HIGH", "RESTRICTED"
        }:
            raise ValueError("MATCH_INPUT data sensitivity is not closed")
        if self.ai_use_code not in {"PROHIBITED", "OPTIONAL", "REQUIRED"}:
            raise ValueError("MATCH_INPUT AI use is not closed")
        if self.budget_override_code not in {None, "APPROVED_EXCEPTION"}:
            raise ValueError("MATCH_INPUT budget override is not closed")
        _require_utc(self.captured_at, "MATCH_INPUT captured_at")
        _validate_match_snapshot_canonical_facts(self)

    def __repr__(self) -> str:
        return (
            "DemandPostgresMatchInputSnapshot("
            f"matching_request_id={self.matching_request_id!r}, "
            f"demand_id={self.demand_id!r}, "
            f"demand_version_id={self.demand_version_id!r})"
        )


@dataclass(frozen=True)
class DemandPostgresMatchCaptureResult:
    match_run_id: UUID
    captured_at: datetime
    requested_matching_request_ids: Tuple[UUID, ...] = field(repr=False)
    snapshots: Tuple[DemandPostgresMatchInputSnapshot, ...] = field(repr=False)
    statement_count: int

    def __post_init__(self) -> None:
        _require_uuid(self.match_run_id, "MATCH_INPUT result MatchRun")
        _require_utc(self.captured_at, "MATCH_INPUT result captured_at")
        if (
            not self.requested_matching_request_ids
            or len(self.requested_matching_request_ids) > 500
            or self.requested_matching_request_ids
            != tuple(
                sorted(
                    self.requested_matching_request_ids,
                    key=lambda value: value.bytes,
                )
            )
            or len(set(self.requested_matching_request_ids))
            != len(self.requested_matching_request_ids)
        ):
            raise ValueError("MATCH_INPUT result allowlist is not canonical")
        for value in self.requested_matching_request_ids:
            _require_uuid(value, "MATCH_INPUT result request ID")
        if (
            not isinstance(self.snapshots, tuple)
            or any(
                not isinstance(item, DemandPostgresMatchInputSnapshot)
                for item in self.snapshots
            )
            or tuple(item.matching_request_id for item in self.snapshots)
            != self.requested_matching_request_ids
            or any(item.captured_at != self.captured_at for item in self.snapshots)
        ):
            raise ValueError("MATCH_INPUT result is partial, reordered, or clock-drifted")
        if self.statement_count != 2:
            raise ValueError("MATCH_INPUT statement count must be exactly 2")


class PsycopgDemandUnitOfWorkFactory:
    """Ten role-bound fixed PostgreSQL writer programs."""

    def __init__(
        self,
        *,
        connections: DemandPostgresConnectionSource,
        event_validator: DemandPostgresSchemaValidator,
        response_validator: DemandPostgresSchemaValidator,
        settings: Optional[DemandPostgresSettings] = None,
        fault_injector: Optional[DemandPostgresFaultInjector] = None,
    ) -> None:
        self.connections = connections
        self.event_validator = event_validator
        self.response_validator = response_validator
        self.settings = settings or DemandPostgresSettings()
        self.fault_injector = fault_injector or NoDemandPostgresFaults()

    @staticmethod
    def profile(operation: DemandPostgresOperation) -> DemandPostgresStatementProfile:
        try:
            return DEMAND_POSTGRES_STATEMENT_PROFILES[operation]
        except KeyError as error:
            raise ValueError("unknown Demand PostgreSQL operation") from error

    def execute_create(
        self,
        request: DemandPostgresCommand,
        *,
        before_mutation: Optional[Callable[[], None]] = None,
    ) -> DemandPostgresDatabaseResult:
        return self._execute(
            request,
            DemandPostgresOperation.CREATE,
            before_mutation=before_mutation,
        )

    def execute_create_version(
        self,
        request: DemandPostgresCommand,
        *,
        before_mutation: Optional[Callable[[], None]] = None,
    ) -> DemandPostgresDatabaseResult:
        return self._execute(
            request,
            DemandPostgresOperation.CREATE_VERSION,
            before_mutation=before_mutation,
        )

    def execute_submit(
        self,
        request: DemandPostgresCommand,
        *,
        before_mutation: Optional[Callable[[], None]] = None,
    ) -> DemandPostgresDatabaseResult:
        return self._execute(
            request,
            DemandPostgresOperation.SUBMIT,
            before_mutation=before_mutation,
        )

    def execute_request_changes(self, request: DemandPostgresCommand) -> DemandPostgresDatabaseResult:
        return self._execute(request, DemandPostgresOperation.REQUEST_CHANGES)

    def execute_verify(self, request: DemandPostgresCommand) -> DemandPostgresDatabaseResult:
        return self._execute(request, DemandPostgresOperation.VERIFY)

    def execute_release_review_assignment(
        self, request: DemandPostgresCommand
    ) -> DemandPostgresDatabaseResult:
        return self._execute(
            request,
            DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT,
        )

    def execute_apply_funding_secured(self, request: DemandPostgresCommand) -> DemandPostgresDatabaseResult:
        return self._execute(request, DemandPostgresOperation.APPLY_FUNDING_SECURED)

    def execute_request_matching(self, request: DemandPostgresCommand) -> DemandPostgresDatabaseResult:
        return self._execute(request, DemandPostgresOperation.REQUEST_MATCHING)

    def execute_request_matching_system(
        self, request: DemandPostgresCommand
    ) -> DemandPostgresDatabaseResult:
        return self._execute(request, DemandPostgresOperation.REQUEST_MATCHING_SYSTEM)

    def execute_cancel_owner(self, request: DemandPostgresCommand) -> DemandPostgresDatabaseResult:
        return self._execute(request, DemandPostgresOperation.CANCEL_OWNER)

    def execute_cancel_review(self, request: DemandPostgresCommand) -> DemandPostgresDatabaseResult:
        return self._execute(request, DemandPostgresOperation.CANCEL_REVIEW)

    def execute_expire(self, request: DemandPostgresCommand) -> DemandPostgresDatabaseResult:
        return self._execute(request, DemandPostgresOperation.EXPIRE)

    def _execute(
        self,
        request: DemandPostgresCommand,
        expected: DemandPostgresOperation,
        *,
        before_mutation: Optional[Callable[[], None]] = None,
    ) -> DemandPostgresDatabaseResult:
        if not isinstance(request, DemandPostgresCommand):
            raise ValueError("closed Demand database request is required")
        if request.operation is not expected:
            raise ValueError("Demand database operation mismatch")
        connection = self.connections.checkout()
        commit_sent = False
        transaction_open = False
        try:
            _preflight_writer(connection, expected)
            connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED")
            transaction_open = True
            _install_writer_context(connection, request, self.settings)
            now = connection.execute("SELECT transaction_timestamp()").fetchone()[0]
            ordinal = [0]

            assignment = None
            reviewer_authority: Optional[Tuple[UUID, int]] = None
            if expected in _OWNER_OPERATIONS:
                _require_owner_authority(connection, request)
            elif expected in _REVIEW_OPERATIONS:
                reviewer_authority = _require_reviewer_authority(
                    connection, request
                )
            else:
                _require_workload_authority(connection, request)

            root = None
            if expected is not DemandPostgresOperation.CREATE:
                root = _lock_demand_root(connection, request)
            if expected in _REVIEW_OPERATIONS:
                if reviewer_authority is None:
                    raise AssertionError("reviewer authority disappeared")
                assignment = _lock_review_assignment(
                    connection, request, now, reviewer_authority
                )

            replay = None
            if request.receipt is not None:
                replay = _claim_or_replay_receipt(
                    connection,
                    request,
                    self.fault_injector,
                    ordinal,
                )
            else:
                replay = _claim_or_replay_source(
                    connection,
                    request,
                    self.fault_injector,
                    ordinal,
                )
            if replay is not None:
                result = replay
            else:
                if before_mutation is not None:
                    before_mutation()
                result = _execute_writer_program(
                    connection=connection,
                    request=request,
                    root=root,
                    assignment=assignment,
                    now=now,
                    event_validator=self.event_validator,
                    response_validator=self.response_validator,
                    fault_injector=self.fault_injector,
                    ordinal=ordinal,
                )

            commit_sent = True
            connection.execute("COMMIT")
            transaction_open = False
            _reset_writer_connection(connection)
            self.connections.release(connection)
            return result
        except psycopg.Error as error:
            if commit_sent:
                self.connections.discard(connection)
                raise DemandPostgresCommitOutcomeUnknownError() from None
            if transaction_open:
                _rollback_quietly(connection)
            _release_after_failure(self.connections, connection)
            mapped = _map_database_error(error, expected)
            if mapped is not None:
                raise mapped from None
            raise DemandPostgresConfigurationError(
                "Demand fixed PostgreSQL program failed"
            ) from None
        except BaseException:
            if transaction_open:
                _rollback_quietly(connection)
            _release_after_failure(self.connections, connection)
            raise


_OWNER_OPERATIONS = frozenset(
    {
        DemandPostgresOperation.CREATE,
        DemandPostgresOperation.CREATE_VERSION,
        DemandPostgresOperation.SUBMIT,
        DemandPostgresOperation.CANCEL_OWNER,
    }
)

_REVIEW_OPERATIONS = frozenset(
    {
        DemandPostgresOperation.REQUEST_CHANGES,
        DemandPostgresOperation.VERIFY,
        DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT,
        DemandPostgresOperation.REQUEST_MATCHING,
        DemandPostgresOperation.CANCEL_REVIEW,
    }
)

_AUTHORITY_OPERATION = MappingProxyType(
    {
        DemandPostgresOperation.CREATE: "CREATE",
        DemandPostgresOperation.CREATE_VERSION: "CREATE_VERSION",
        DemandPostgresOperation.SUBMIT: "SUBMIT",
        DemandPostgresOperation.CANCEL_OWNER: "CANCEL_OWNER",
        DemandPostgresOperation.REQUEST_CHANGES: "REQUEST_CHANGES",
        DemandPostgresOperation.VERIFY: "VERIFY",
        DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT: "RELEASE_REVIEW_ASSIGNMENT",
        DemandPostgresOperation.REQUEST_MATCHING: "REQUEST_MATCHING",
        DemandPostgresOperation.REQUEST_MATCHING_SYSTEM: "REQUEST_MATCHING",
        DemandPostgresOperation.CANCEL_REVIEW: "CANCEL_REVIEW",
    }
)

_EVENT_TYPE = MappingProxyType(
    {
        DemandPostgresOperation.CREATE_VERSION: "DemandVersionCreated",
        DemandPostgresOperation.SUBMIT: "DemandSubmitted",
        DemandPostgresOperation.REQUEST_CHANGES: "DemandChangesRequested",
        DemandPostgresOperation.VERIFY: "DemandVerified",
        DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT: "DemandReviewAssignmentReleased",
        DemandPostgresOperation.APPLY_FUNDING_SECURED: "DemandFunded",
        DemandPostgresOperation.REQUEST_MATCHING: "MatchingRequested",
        DemandPostgresOperation.REQUEST_MATCHING_SYSTEM: "MatchingRequested",
        DemandPostgresOperation.CANCEL_OWNER: "DemandCancelled",
        DemandPostgresOperation.CANCEL_REVIEW: "DemandCancelled",
        DemandPostgresOperation.EXPIRE: "DemandExpired",
    }
)


def _preflight_writer(connection: Any, operation: DemandPostgresOperation) -> None:
    expected_role = _ROLE_BY_OPERATION[operation]
    row = connection.execute(
        "SELECT session_user,current_user,"
        "current_setting('server_version_num')::integer/10000,"
        "current_schema_version,schema_head_version,"
        "min_app_compatible_version,max_app_compatible_version,"
        "required_iam_schema_version "
        "FROM demand.schema_compatibility"
    ).fetchone()
    if row != (
        expected_role,
        expected_role,
        18,
        DEMAND_SCHEMA_HEAD_VERSION,
        DEMAND_SCHEMA_HEAD_VERSION,
        DEMAND_SCHEMA_HEAD_VERSION,
        DEMAND_SCHEMA_HEAD_VERSION,
        DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
    ):
        raise DemandPostgresConfigurationError(
            "Demand PostgreSQL role, server, or catalog is untrusted"
        )


def _install_writer_context(
    connection: Any,
    request: DemandPostgresCommand,
    settings: DemandPostgresSettings,
) -> None:
    scope_kind = (
        "DEMAND_OWNER"
        if request.operation in _OWNER_OPERATIONS
        else "DEMAND_REVIEW"
        if request.operation in _REVIEW_OPERATIONS
        else "DEMAND_FINANCE"
        if request.operation is DemandPostgresOperation.APPLY_FUNDING_SECURED
        else "DEMAND_SYSTEM"
    )
    values = (
        ("lock_timeout", f"{settings.lock_timeout_ms}ms"),
        ("statement_timeout", f"{settings.statement_timeout_ms}ms"),
        (
            "idle_in_transaction_session_timeout",
            f"{settings.idle_in_transaction_timeout_ms}ms",
        ),
        ("TimeZone", "UTC"),
        ("app.scope_kind", scope_kind),
        (
            "app.operation",
            _AUTHORITY_OPERATION.get(request.operation, request.operation.value),
        ),
        ("app.actor_id", str(request.scope.actor_id)),
        ("app.organization_id", str(request.scope.organization_id)),
        ("app.demand_id", str(request.scope.demand_id)),
        (
            "app.session_id",
            "" if request.scope.session_id is None else str(request.scope.session_id),
        ),
        (
            "app.assignment_id",
            "" if request.assignment_id is None else str(request.assignment_id),
        ),
        ("app.command_id", str(request.scope.command_id)),
    )
    for name, value in values:
        connection.execute(
            "SELECT pg_catalog.set_config(%s,%s,true)",
            (name, value),
        )


def _require_owner_authority(
    connection: Any,
    request: DemandPostgresCommand,
) -> None:
    row = connection.execute(
        "SELECT 1 FROM iam_api.lock_demand_owner_authority_v1("
        "%s,%s,%s,%s,%s,%s)",
        (
            request.scope.actor_id,
            request.scope.session_id,
            request.scope.organization_id,
            _AUTHORITY_OPERATION[request.operation],
            request.scope.demand_id,
            request.scope.expected_authority_marker_sha256,
        ),
    ).fetchone()
    if row != (1,):
        raise DemandPostgresDatabaseError("RESOURCE_NOT_FOUND")


def _require_reviewer_authority(
    connection: Any,
    request: DemandPostgresCommand,
) -> Tuple[UUID, int]:
    row = connection.execute(
        "SELECT duty_grant_id,duty_grant_version "
        "FROM iam_api.lock_demand_reviewer_authority_v2("
        "%s,%s,%s,%s,%s,%s,%s)",
        (
            request.scope.actor_id,
            request.scope.session_id,
            request.scope.organization_id,
            request.scope.demand_id,
            request.assignment_id,
            _AUTHORITY_OPERATION[request.operation],
            request.scope.expected_authority_marker_sha256,
        ),
    ).fetchone()
    if (
        row is None
        or len(row) != 2
        or not isinstance(row[0], UUID)
        or isinstance(row[1], bool)
        or not isinstance(row[1], int)
        or row[1] < 1
    ):
        raise DemandPostgresDatabaseError("RESOURCE_NOT_FOUND")
    return row[0], row[1]


def _require_workload_authority(
    connection: Any,
    request: DemandPostgresCommand,
) -> None:
    row = connection.execute(
        "SELECT finance_workload_principal_id,finance_authority_marker_sha256,"
        "system_workload_principal_id,system_authority_marker_sha256 "
        "FROM demand.receipt_key_policy WHERE singleton_key"
    ).fetchone()
    if row is None:
        raise DemandPostgresConfigurationError("Demand workload policy is absent")
    if request.operation is DemandPostgresOperation.APPLY_FUNDING_SECURED:
        principal, marker = row[0], row[1]
    else:
        principal, marker = row[2], row[3]
    if (
        principal != request.scope.actor_id
        or not hmac.compare_digest(marker, request.scope.expected_authority_marker_sha256)
    ):
        raise DemandPostgresDatabaseError("RESOURCE_NOT_FOUND")


def _lock_review_assignment(
    connection: Any,
    request: DemandPostgresCommand,
    now: datetime,
    reviewer_authority: Tuple[UUID, int],
) -> Tuple[Any, ...]:
    row = connection.execute(
        "SELECT id,organization_id,demand_id,submission_id,demand_version_id,"
        "reviewer_user_id,duty_grant_id,duty_grant_version,purpose_code,"
        "conflict_attestation_sha256,authority_marker_sha256,status,expires_at,"
        "aggregate_version FROM demand.demand_review_assignments "
        "WHERE id=%s AND organization_id=%s AND demand_id=%s FOR UPDATE",
        (
            request.assignment_id,
            request.scope.organization_id,
            request.scope.demand_id,
        ),
    ).fetchone()
    if (
        row is None
        or row[5] != request.scope.actor_id
        or row[6] != reviewer_authority[0]
        or row[7] != reviewer_authority[1]
        or row[8] != "DEMAND_REVIEW"
        or row[11] != "ACTIVE"
        or row[12] <= now
        or not isinstance(row[10], bytes)
        or len(row[10]) != 32
    ):
        raise DemandPostgresDatabaseError("RESOURCE_NOT_FOUND")
    return row


def _lock_demand_root(
    connection: Any,
    request: DemandPostgresCommand,
) -> Optional[Tuple[Any, ...]]:
    return connection.execute(
        "SELECT id,organization_id,creator_user_id,status,aggregate_version,"
        "current_version_id,current_submission_id,current_review_id,"
        "verified_version_id,current_funding_marker_id,"
        "current_matching_request_id,expires_at,terminal_at,"
        "terminal_reason_code FROM demand.demands "
        "WHERE organization_id=%s AND id=%s FOR UPDATE",
        (request.scope.organization_id, request.scope.demand_id),
    ).fetchone()


def _key_policy(connection: Any) -> Tuple[Any, ...]:
    row = connection.execute(
        "SELECT active_idempotency_key_id,active_payload_key_id,"
        "active_canonicalization_version,retained_idempotency_key_ids,"
        "retained_payload_key_ids,retained_canonicalization_versions,"
        "taxonomy_bundle_id,budget_rule_bundle_id,risk_rule_bundle_id,"
        "matching_rule_bundle_id,reason_code_bundle_id,"
        "composite_rule_requirement_id,rule_requirement_sha256,"
        "matching_selector_digest,rule_effective_at,rule_effective_until "
        "FROM demand.receipt_key_policy WHERE singleton_key"
    ).fetchone()
    if row is None:
        raise DemandPostgresConfigurationError("Demand key/rule policy is absent")
    return row


def _claim_or_replay_receipt(
    connection: Any,
    request: DemandPostgresCommand,
    fault_injector: DemandPostgresFaultInjector,
    ordinal: List[int],
) -> Optional[DemandPostgresDatabaseResult]:
    receipt = request.receipt
    if receipt is None:
        raise AssertionError("receipt claim called without receipt")
    policy = _key_policy(connection)
    if (
        receipt.idempotency_key_digest_key_id not in tuple(policy[3])
        or receipt.payload_hash_key_id not in tuple(policy[4])
        or receipt.canonicalization_version not in tuple(policy[5])
    ):
        raise DemandPostgresConfigurationError("Demand retained receipt key is absent")

    _before_write(
        fault_injector,
        ordinal,
        DemandPostgresWriteCheckpoint.RECEIPT_PENDING,
    )
    inserted = connection.execute(
        "INSERT INTO demand.command_receipts ("
        "receipt_id,principal_kind,principal_id,organization_id,command_name,"
        "command_version,idempotency_key_digest_key_id,"
        "idempotency_key_digest,payload_hash_key_id,canonicalization_version,"
        "payload_hash,http_method,canonical_path,if_match_version,status,"
        "retain_until,created_at) VALUES ("
        "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'IN_PROGRESS',"
        "%s,transaction_timestamp()) ON CONFLICT DO NOTHING RETURNING receipt_id",
        (
            receipt.receipt_id,
            receipt.principal_kind,
            receipt.principal_id,
            receipt.organization_id,
            receipt.command_name,
            receipt.command_version,
            receipt.idempotency_key_digest_key_id,
            receipt.idempotency_key_digest,
            receipt.payload_hash_key_id,
            receipt.canonicalization_version,
            receipt.payload_hash,
            receipt.http_method,
            receipt.canonical_path,
            receipt.if_match_version,
            receipt.retain_until,
        ),
    ).fetchone()
    if inserted is not None:
        return None

    row = connection.execute(
        "SELECT receipt_id,principal_kind,principal_id,organization_id,"
        "command_name,command_version,idempotency_key_digest_key_id,"
        "idempotency_key_digest,payload_hash_key_id,canonicalization_version,"
        "payload_hash,http_method,canonical_path,if_match_version,status,"
        "response_http_status,response_schema_name,response_schema_version,"
        "response_entity_tag,safe_response_body,target_id,target_version,"
        "result_status,event_types,retain_until,completed_at "
        "FROM demand.command_receipts WHERE receipt_id=%s OR ("
        "principal_kind=%s AND principal_id=%s AND organization_id=%s "
        "AND command_name=%s AND command_version=%s "
        "AND idempotency_key_digest_key_id=%s "
        "AND idempotency_key_digest=%s) FOR UPDATE",
        (
            receipt.receipt_id,
            receipt.principal_kind,
            receipt.principal_id,
            receipt.organization_id,
            receipt.command_name,
            receipt.command_version,
            receipt.idempotency_key_digest_key_id,
            receipt.idempotency_key_digest,
        ),
    ).fetchone()
    return _decode_receipt_replay(row, request, policy)


def _decode_receipt_replay(
    row: Optional[Tuple[Any, ...]],
    request: DemandPostgresCommand,
    policy: Tuple[Any, ...],
) -> DemandPostgresDatabaseResult:
    receipt = request.receipt
    if receipt is None or row is None:
        raise DemandPostgresConfigurationError("Demand receipt conflict is corrupt")
    stable = (
        row[1], row[2], row[3], row[4], row[5], row[11], row[12], row[13]
    )
    expected = (
        receipt.principal_kind,
        receipt.principal_id,
        receipt.organization_id,
        receipt.command_name,
        receipt.command_version,
        receipt.http_method,
        receipt.canonical_path,
        receipt.if_match_version,
    )
    if stable != expected or row[9] != receipt.canonicalization_version:
        raise DemandPostgresConfigurationError("Demand receipt binding is corrupt")
    if row[8] == receipt.payload_hash_key_id:
        if not hmac.compare_digest(row[10], receipt.payload_hash):
            raise DemandPostgresDatabaseError("IDEMPOTENCY_KEY_REUSED")
    elif receipt.payload_hash_key_id not in tuple(policy[4]):
        raise DemandPostgresConfigurationError("Demand receipt payload key is absent")
    if row[14] != "COMPLETED":
        raise DemandPostgresConfigurationError("Demand receipt is incomplete")
    safe = row[19]
    if (
        row[15] not in {200, 201}
        or row[16] != "DemandDto"
        or row[17] != 1
        or row[18] != f'"v{row[21]}"'
        or not isinstance(safe, dict)
        or set(safe) != {
            "aggregate_version",
            "demand_id",
            "demand_version_id",
            "status",
        }
        or safe["demand_id"] != str(row[20])
        or safe["aggregate_version"] != row[21]
        or safe["status"] != row[22]
        or tuple(row[23]) != _event_types(request.operation)
        or row[25] is None
    ):
        raise DemandPostgresConfigurationError("Demand completed receipt is corrupt")
    try:
        version_id = UUID(safe["demand_version_id"])
    except (TypeError, ValueError) as error:
        raise DemandPostgresConfigurationError(
            "Demand receipt version identity is corrupt"
        ) from error
    return DemandPostgresDatabaseResult(
        operation=request.operation,
        replayed=True,
        demand_id=row[20],
        current_version_id=version_id,
        status=row[22],
        aggregate_version=row[21],
        safe_response=MappingProxyType(dict(safe)),
        event_types=tuple(row[23]),
    )


def _claim_or_replay_source(
    connection: Any,
    request: DemandPostgresCommand,
    fault_injector: DemandPostgresFaultInjector,
    ordinal: List[int],
) -> Optional[DemandPostgresDatabaseResult]:
    source = request.source_event
    if source is None:
        raise AssertionError("source claim called without source event")
    _before_write(
        fault_injector,
        ordinal,
        DemandPostgresWriteCheckpoint.SOURCE_INBOX_PENDING,
    )
    inserted = connection.execute(
        "INSERT INTO demand.source_inbox ("
        "source_event_id,source_kind,event_type,schema_version,"
        "source_aggregate_id,source_aggregate_version,organization_id,"
        "demand_id,demand_version_id,envelope_sha256,status,created_at) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'IN_PROGRESS',"
        "transaction_timestamp()) ON CONFLICT DO NOTHING "
        "RETURNING source_event_id",
        (
            source.source_event_id,
            source.source_aggregate_type,
            source.event_type,
            source.schema_version,
            source.source_aggregate_id,
            source.source_aggregate_version,
            source.organization_id,
            source.demand_id,
            source.demand_version_id,
            source.envelope_sha256,
        ),
    ).fetchone()
    if inserted is not None:
        return None
    row = connection.execute(
        "SELECT source_event_id,source_kind,event_type,schema_version,"
        "source_aggregate_id,source_aggregate_version,organization_id,"
        "demand_id,demand_version_id,envelope_sha256,status,"
        "result_aggregate_version,result_event_types,completed_at "
        "FROM demand.source_inbox WHERE source_event_id=%s FOR UPDATE",
        (source.source_event_id,),
    ).fetchone()
    expected = (
        source.source_event_id,
        source.source_aggregate_type,
        source.event_type,
        source.schema_version,
        source.source_aggregate_id,
        source.source_aggregate_version,
        source.organization_id,
        source.demand_id,
        source.demand_version_id,
    )
    if row is None or tuple(row[:9]) != expected:
        code = (
            "FUNDING_FACT_CHANGED"
            if request.operation is DemandPostgresOperation.APPLY_FUNDING_SECURED
            else "SERVICE_UNAVAILABLE"
        )
        if code == "SERVICE_UNAVAILABLE":
            raise DemandPostgresConfigurationError("Demand source identity is corrupt")
        raise DemandPostgresDatabaseError(code)
    if not hmac.compare_digest(row[9], source.envelope_sha256):
        if request.operation is DemandPostgresOperation.APPLY_FUNDING_SECURED:
            raise DemandPostgresDatabaseError("FUNDING_FACT_CHANGED")
        raise DemandPostgresConfigurationError("Demand source envelope is corrupt")
    if row[10] != "COMPLETED" or row[11] is None or row[13] is None:
        raise DemandPostgresConfigurationError("Demand source inbox is incomplete")
    event_types = tuple(row[12])
    if event_types != _event_types(request.operation):
        raise DemandPostgresConfigurationError("Demand source result is corrupt")
    status = (
        "FUNDED"
        if request.operation is DemandPostgresOperation.APPLY_FUNDING_SECURED
        else "EXPIRED"
    )
    safe = _safe_response(
        request.scope.demand_id,
        request.demand_version_id,
        status,
        row[11],
    )
    return DemandPostgresDatabaseResult(
        operation=request.operation,
        replayed=True,
        demand_id=request.scope.demand_id,
        current_version_id=request.demand_version_id,
        status=status,
        aggregate_version=row[11],
        safe_response=MappingProxyType(safe),
        event_types=event_types,
    )


def _execute_writer_program(
    *,
    connection: Any,
    request: DemandPostgresCommand,
    root: Optional[Tuple[Any, ...]],
    assignment: Optional[Tuple[Any, ...]],
    now: datetime,
    event_validator: DemandPostgresSchemaValidator,
    response_validator: DemandPostgresSchemaValidator,
    fault_injector: DemandPostgresFaultInjector,
    ordinal: List[int],
) -> DemandPostgresDatabaseResult:
    operation = request.operation
    if operation is DemandPostgresOperation.CREATE:
        result = _write_create(connection, request, now, fault_injector, ordinal)
    elif root is None:
        raise DemandPostgresDatabaseError("RESOURCE_NOT_FOUND")
    elif operation is DemandPostgresOperation.CREATE_VERSION:
        result = _write_create_version(
            connection, request, root, now, fault_injector, ordinal
        )
    elif operation is DemandPostgresOperation.SUBMIT:
        result = _write_submit(
            connection, request, root, now, fault_injector, ordinal
        )
    elif operation in {
        DemandPostgresOperation.REQUEST_CHANGES,
        DemandPostgresOperation.VERIFY,
    }:
        result = _write_review(
            connection,
            request,
            root,
            assignment,
            now,
            fault_injector,
            ordinal,
        )
    elif operation is DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT:
        result = _write_review_assignment_release(
            connection,
            request,
            root,
            assignment,
            now,
            fault_injector,
            ordinal,
        )
    elif operation is DemandPostgresOperation.APPLY_FUNDING_SECURED:
        result = _write_funding(
            connection, request, root, now, fault_injector, ordinal
        )
    elif operation in {
        DemandPostgresOperation.REQUEST_MATCHING,
        DemandPostgresOperation.REQUEST_MATCHING_SYSTEM,
    }:
        result = _write_matching(
            connection,
            request,
            root,
            assignment,
            now,
            fault_injector,
            ordinal,
        )
    elif operation in {
        DemandPostgresOperation.CANCEL_OWNER,
        DemandPostgresOperation.CANCEL_REVIEW,
    }:
        result = _write_cancel(
            connection,
            request,
            root,
            assignment,
            now,
            fault_injector,
            ordinal,
        )
    elif operation is DemandPostgresOperation.EXPIRE:
        result = _write_expire(
            connection, request, root, now, fault_injector, ordinal
        )
    else:
        raise AssertionError("unknown Demand writer program")

    events = _events_for_result(connection, request, result, now)
    for event in events:
        event_validator.validate(event, "demand-v1")
    response_validator.validate(dict(result.safe_response), "DemandDto")
    _write_audit(connection, request, root, result, now, fault_injector, ordinal)
    _write_outbox(
        connection,
        request,
        result,
        events,
        now,
        fault_injector,
        ordinal,
    )
    if request.receipt is not None:
        _complete_receipt(
            connection, request, result, now, fault_injector, ordinal
        )
    else:
        _complete_source(connection, request, result, now, fault_injector, ordinal)
    return result


def _before_write(
    fault_injector: DemandPostgresFaultInjector,
    ordinal: List[int],
    checkpoint: DemandPostgresWriteCheckpoint,
) -> None:
    ordinal[0] += 1
    fault_injector.before_write(checkpoint, ordinal[0])


def _require_root_version(
    root: Tuple[Any, ...],
    request: DemandPostgresCommand,
) -> None:
    if root[4] != request.expected_aggregate_version:
        raise DemandPostgresDatabaseError("PRECONDITION_FAILED")
    if (
        request.operation is not DemandPostgresOperation.CREATE_VERSION
        and request.demand_version_id is not None
        and root[5] != request.demand_version_id
    ):
        raise DemandPostgresDatabaseError("PRECONDITION_FAILED")


def _load_version(
    connection: Any,
    request: DemandPostgresCommand,
    version_id: UUID,
) -> Tuple[Any, ...]:
    row = connection.execute(
        "SELECT id,version_no,based_on_demand_version_id,taxonomy_bundle_id,"
        "canonical_version_bytes,content,content_sha256 "
        "FROM demand.demand_versions WHERE organization_id=%s "
        "AND demand_id=%s AND id=%s",
        (request.scope.organization_id, request.scope.demand_id, version_id),
    ).fetchone()
    if row is None:
        raise DemandPostgresConfigurationError("Demand current version is absent")
    return row


def _validated_canonical_content(
    request: DemandPostgresCommand,
    expected_version_no: int,
) -> Dict[str, Any]:
    canonical = request.canonical_demand_version_bytes
    if canonical is None or request.content_sha256 is None:
        raise DemandPostgresConfigurationError("Demand canonical version is absent")
    try:
        decoded = json.loads(
            canonical.decode("utf-8"),
            object_pairs_hook=_closed_json_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON number")
            ),
        )
        if not isinstance(decoded, dict) or set(decoded) != {
            "canonicalization_version",
            "content",
            "demand_id",
            "demand_schema_version",
            "taxonomy_bundle_id",
            "version_no",
        }:
            raise ValueError("open canonical root")
        if (
            decoded["canonicalization_version"] != "demand-content-json-v1"
            or decoded["demand_schema_version"] != 1
            or decoded["demand_id"] != str(request.scope.demand_id)
            or decoded["taxonomy_bundle_id"] != str(request.taxonomy_bundle_id)
            or decoded["version_no"] != expected_version_no
        ):
            raise ValueError("canonical identity mismatch")
        frozen = _freeze_demand_json(decoded["content"])
        if not isinstance(frozen, DemandContent):
            raise ValueError("canonical content is not an object")
        validate_demand_content(frozen, for_submission=False)
        recomputed = canonical_demand_version_bytes(
            demand_id=str(request.scope.demand_id),
            version_no=expected_version_no,
            taxonomy_bundle_id=str(request.taxonomy_bundle_id),
            content=frozen,
        )
        if recomputed != canonical or not hmac.compare_digest(
            hashlib.sha256(recomputed).digest(), request.content_sha256
        ):
            raise ValueError("canonical hash mismatch")
        return decoded["content"]
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        DemandDomainError,
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        raise DemandPostgresDatabaseError("DEMAND_VALIDATION_FAILED") from error


def _write_create(
    connection: Any,
    request: DemandPostgresCommand,
    now: datetime,
    fault_injector: DemandPostgresFaultInjector,
    ordinal: List[int],
) -> DemandPostgresDatabaseResult:
    duplicate = connection.execute(
        "SELECT 1 FROM demand.demands WHERE organization_id=%s AND ("
        "id=%s OR (client_reference_digest_key_id=%s "
        "AND client_reference_digest=%s)) FOR UPDATE",
        (
            request.scope.organization_id,
            request.scope.demand_id,
            request.client_reference_digest_key_id,
            request.client_reference_digest,
        ),
    ).fetchone()
    if duplicate is not None:
        raise DemandPostgresDatabaseError("DEMAND_ALREADY_EXISTS")
    content = _validated_canonical_content(request, 1)
    _before_write(
        fault_injector, ordinal, DemandPostgresWriteCheckpoint.DEMAND_ROOT
    )
    connection.execute(
        "INSERT INTO demand.demands ("
        "id,organization_id,creator_user_id,client_reference_digest_key_id,"
        "client_reference_digest,status,aggregate_version,current_version_id,"
        "expires_at,created_at,updated_at) VALUES ("
        "%s,%s,%s,%s,%s,'DRAFT',1,%s,%s,%s,%s)",
        (
            request.scope.demand_id,
            request.scope.organization_id,
            request.scope.actor_id,
            request.client_reference_digest_key_id,
            request.client_reference_digest,
            request.demand_version_id,
            now + timedelta(days=90),
            now,
            now,
        ),
    )
    _before_write(
        fault_injector, ordinal, DemandPostgresWriteCheckpoint.DEMAND_VERSION
    )
    connection.execute(
        "INSERT INTO demand.demand_versions ("
        "id,organization_id,demand_id,version_no,based_on_demand_version_id,"
        "demand_schema_version,canonicalization_version,taxonomy_bundle_id,"
        "canonical_version_bytes,content,content_sha256,created_by_user_id,"
        "created_at) VALUES ("
        "%s,%s,%s,1,NULL,1,'demand-content-json-v1',%s,%s,%s::jsonb,%s,%s,%s)",
        (
            request.demand_version_id,
            request.scope.organization_id,
            request.scope.demand_id,
            request.taxonomy_bundle_id,
            request.canonical_demand_version_bytes,
            json.dumps(content, ensure_ascii=False, separators=(",", ":")),
            request.content_sha256,
            request.scope.actor_id,
            now,
        ),
    )
    return _make_result(request, "DRAFT", 1, request.demand_version_id)


def _write_create_version(
    connection: Any,
    request: DemandPostgresCommand,
    root: Tuple[Any, ...],
    now: datetime,
    fault_injector: DemandPostgresFaultInjector,
    ordinal: List[int],
) -> DemandPostgresDatabaseResult:
    _require_root_version(root, request)
    if root[3] not in {"DRAFT", "NEEDS_CHANGES", "NO_MATCH"}:
        raise DemandPostgresDatabaseError("INVALID_STATE_TRANSITION")
    if request.based_on_demand_version_id != root[5]:
        raise DemandPostgresDatabaseError("PRECONDITION_FAILED")
    current = _load_version(connection, request, root[5])
    next_no = current[1] + 1
    content = _validated_canonical_content(request, next_no)
    _before_write(
        fault_injector, ordinal, DemandPostgresWriteCheckpoint.DEMAND_VERSION
    )
    connection.execute(
        "INSERT INTO demand.demand_versions ("
        "id,organization_id,demand_id,version_no,based_on_demand_version_id,"
        "demand_schema_version,canonicalization_version,taxonomy_bundle_id,"
        "canonical_version_bytes,content,content_sha256,created_by_user_id,"
        "created_at) VALUES ("
        "%s,%s,%s,%s,%s,1,'demand-content-json-v1',%s,%s,%s::jsonb,%s,%s,%s)",
        (
            request.demand_version_id,
            request.scope.organization_id,
            request.scope.demand_id,
            next_no,
            request.based_on_demand_version_id,
            request.taxonomy_bundle_id,
            request.canonical_demand_version_bytes,
            json.dumps(content, ensure_ascii=False, separators=(",", ":")),
            request.content_sha256,
            request.scope.actor_id,
            now,
        ),
    )
    aggregate = root[4] + 1
    _before_write(
        fault_injector, ordinal, DemandPostgresWriteCheckpoint.DEMAND_ROOT
    )
    connection.execute(
        "UPDATE demand.demands SET current_version_id=%s,aggregate_version=%s,"
        "current_submission_id=NULL,current_review_id=NULL,"
        "verified_version_id=NULL,current_funding_marker_id=NULL,"
        "current_matching_request_id=NULL,updated_at=%s WHERE id=%s",
        (request.demand_version_id, aggregate, now, request.scope.demand_id),
    )
    return _make_result(request, root[3], aggregate, request.demand_version_id)


def _validate_evidence(
    connection: Any,
    request: DemandPostgresCommand,
    version: Tuple[Any, ...],
    now: datetime,
) -> Tuple[Any, ...]:
    if request.content_policy is not None:
        if (
            request.content_policy.valid_until <= now
            or request.content_policy.evaluated_at > now
            or not hmac.compare_digest(
                request.content_policy.content_sha256, version[6]
            )
        ):
            raise DemandPostgresConfigurationError(
                "Demand content-policy evidence is unavailable"
            )
    if request.hold is not None:
        if (
            request.hold.valid_until <= now
            or request.hold.evaluated_at > now
            or not hmac.compare_digest(request.hold.content_sha256, version[6])
        ):
            raise DemandPostgresDatabaseError("SAFETY_HOLD_BLOCKED")
    policy = _key_policy(connection)
    rule = request.rule_requirement
    if rule is not None:
        expected = (
            policy[6],
            policy[7],
            policy[8],
            policy[9],
            policy[10],
            policy[11],
        )
        actual = (
            rule.taxonomy_bundle_id,
            rule.budget_rule_bundle_id,
            rule.risk_rule_bundle_id,
            rule.matching_rule_bundle_id,
            rule.reason_code_bundle_id,
            rule.composite_rule_requirement_id,
        )
        stale = (
            actual != expected
            or not hmac.compare_digest(rule.requirement_sha256, policy[12])
            or rule.effective_at > now
            or (rule.effective_until is not None and rule.effective_until <= now)
            or policy[14] > now
            or (policy[15] is not None and policy[15] <= now)
        )
        if stale:
            code = (
                "MATCHING_RULE_BUNDLE_CHANGED"
                if request.operation in {
                    DemandPostgresOperation.REQUEST_MATCHING,
                    DemandPostgresOperation.REQUEST_MATCHING_SYSTEM,
                }
                else "TAXONOMY_BUNDLE_CHANGED"
            )
            raise DemandPostgresDatabaseError(code)
    return policy


def _write_submit(
    connection: Any,
    request: DemandPostgresCommand,
    root: Tuple[Any, ...],
    now: datetime,
    fault_injector: DemandPostgresFaultInjector,
    ordinal: List[int],
) -> DemandPostgresDatabaseResult:
    _require_root_version(root, request)
    if root[3] not in {"DRAFT", "NEEDS_CHANGES"}:
        raise DemandPostgresDatabaseError("INVALID_STATE_TRANSITION")
    version = _load_version(connection, request, root[5])
    _validate_evidence(connection, request, version, now)
    _before_write(
        fault_injector, ordinal, DemandPostgresWriteCheckpoint.SUBMISSION
    )
    connection.execute(
        "INSERT INTO demand.demand_submissions ("
        "id,organization_id,demand_id,demand_version_id,content_sha256,"
        "submitted_by_user_id,content_policy_version,"
        "content_policy_result_sha256,rule_requirement_sha256,submitted_at) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        (
            request.submission_id,
            request.scope.organization_id,
            request.scope.demand_id,
            request.demand_version_id,
            version[6],
            request.scope.actor_id,
            request.content_policy.policy_version,
            request.content_policy.result_sha256,
            request.rule_requirement.requirement_sha256,
            now,
        ),
    )
    aggregate = root[4] + 1
    _before_write(
        fault_injector, ordinal, DemandPostgresWriteCheckpoint.DEMAND_ROOT
    )
    connection.execute(
        "UPDATE demand.demands SET status='SUBMITTED',aggregate_version=%s,"
        "current_submission_id=%s,current_review_id=NULL,"
        "verified_version_id=NULL,current_funding_marker_id=NULL,"
        "current_matching_request_id=NULL,updated_at=%s WHERE id=%s",
        (aggregate, request.submission_id, now, request.scope.demand_id),
    )
    return _make_result(request, "SUBMITTED", aggregate, root[5])


def _write_review(
    connection: Any,
    request: DemandPostgresCommand,
    root: Tuple[Any, ...],
    assignment: Optional[Tuple[Any, ...]],
    now: datetime,
    fault_injector: DemandPostgresFaultInjector,
    ordinal: List[int],
) -> DemandPostgresDatabaseResult:
    _require_root_version(root, request)
    if (
        root[3] != "SUBMITTED"
        or root[6] is None
        or assignment is None
        or root[2] == request.scope.actor_id
    ):
        raise DemandPostgresDatabaseError("INVALID_STATE_TRANSITION")
    if assignment[3] != root[6] or assignment[4] != root[5]:
        raise DemandPostgresDatabaseError("RESOURCE_NOT_FOUND")
    version = _load_version(connection, request, root[5])
    submission = connection.execute(
        "SELECT content_sha256 FROM demand.demand_submissions "
        "WHERE id=%s AND organization_id=%s AND demand_id=%s",
        (root[6], request.scope.organization_id, request.scope.demand_id),
    ).fetchone()
    if submission is None or not hmac.compare_digest(submission[0], version[6]):
        raise DemandPostgresConfigurationError("Demand submission hash is corrupt")
    if request.operation is DemandPostgresOperation.VERIFY:
        _validate_evidence(connection, request, version, now)
        decision = "VERIFIED"
    else:
        decision = "NEEDS_CHANGES"
    _before_write(
        fault_injector, ordinal, DemandPostgresWriteCheckpoint.REVIEW
    )
    connection.execute(
        "INSERT INTO demand.demand_reviews ("
        "id,organization_id,demand_id,submission_id,demand_version_id,"
        "content_sha256,assignment_id,reviewer_user_id,decision,reason_codes,"
        "required_field_codes,budget_health_code,risk_code,"
        "evidence_summary_sha256,rule_requirement_sha256,reviewed_at) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        (
            request.review_id,
            request.scope.organization_id,
            request.scope.demand_id,
            root[6],
            request.demand_version_id,
            version[6],
            request.assignment_id,
            request.scope.actor_id,
            decision,
            list(request.reason_codes),
            list(request.required_field_codes),
            request.budget_health_code,
            request.risk_code,
            request.evidence_summary_sha256,
            (
                None
                if request.rule_requirement is None
                else request.rule_requirement.requirement_sha256
            ),
            now,
        ),
    )
    _before_write(
        fault_injector,
        ordinal,
        DemandPostgresWriteCheckpoint.REVIEW_ASSIGNMENT,
    )
    connection.execute(
        "UPDATE demand.demand_review_assignments SET status='COMPLETED',"
        "aggregate_version=aggregate_version+1,completed_at=%s WHERE id=%s",
        (now, request.assignment_id),
    )
    aggregate = root[4] + 1
    _before_write(
        fault_injector, ordinal, DemandPostgresWriteCheckpoint.DEMAND_ROOT
    )
    connection.execute(
        "UPDATE demand.demands SET status=%s,aggregate_version=%s,"
        "current_review_id=%s,verified_version_id=%s,updated_at=%s WHERE id=%s",
        (
            decision,
            aggregate,
            request.review_id,
            request.demand_version_id if decision == "VERIFIED" else None,
            now,
            request.scope.demand_id,
        ),
    )
    return _make_result(request, decision, aggregate, root[5])


def _write_review_assignment_release(
    connection: Any,
    request: DemandPostgresCommand,
    root: Tuple[Any, ...],
    assignment: Optional[Tuple[Any, ...]],
    now: datetime,
    fault_injector: DemandPostgresFaultInjector,
    ordinal: List[int],
) -> DemandPostgresDatabaseResult:
    """Release one still-active reviewer lease without deciding the Demand."""

    _require_root_version(root, request)
    if (
        root[3] != "SUBMITTED"
        or root[6] is None
        or assignment is None
        or root[2] == request.scope.actor_id
    ):
        raise DemandPostgresDatabaseError("INVALID_STATE_TRANSITION")
    if assignment[3] != root[6] or assignment[4] != root[5]:
        raise DemandPostgresDatabaseError("RESOURCE_NOT_FOUND")

    _before_write(
        fault_injector,
        ordinal,
        DemandPostgresWriteCheckpoint.REVIEW_ASSIGNMENT_RELEASE,
    )
    updated = connection.execute(
        "UPDATE demand.demand_review_assignments SET status='REVOKED',"
        "aggregate_version=aggregate_version+1,completed_at=%s "
        "WHERE id=%s AND status='ACTIVE'",
        (now, request.assignment_id),
    )
    if updated.rowcount != 1:
        raise DemandPostgresDatabaseError("RESOURCE_NOT_FOUND")

    _before_write(
        fault_injector,
        ordinal,
        DemandPostgresWriteCheckpoint.REVIEW_ASSIGNMENT_RELEASE_FACT,
    )
    connection.execute(
        "INSERT INTO demand.demand_review_assignment_releases ("
        "id,organization_id,demand_id,submission_id,demand_version_id,"
        "assignment_id,reviewer_user_id,reason_code,authority_marker_sha256,"
        "released_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        (
            request.scope.command_id,
            request.scope.organization_id,
            request.scope.demand_id,
            root[6],
            request.demand_version_id,
            request.assignment_id,
            request.scope.actor_id,
            request.release_reason_code,
            request.scope.expected_authority_marker_sha256,
            now,
        ),
    )

    aggregate = root[4] + 1
    _before_write(
        fault_injector,
        ordinal,
        DemandPostgresWriteCheckpoint.DEMAND_ROOT,
    )
    updated = connection.execute(
        "UPDATE demand.demands SET aggregate_version=%s,updated_at=%s "
        "WHERE id=%s AND status='SUBMITTED' AND aggregate_version=%s",
        (
            aggregate,
            now,
            request.scope.demand_id,
            root[4],
        ),
    )
    if updated.rowcount != 1:
        raise DemandPostgresDatabaseError("PRECONDITION_FAILED")
    return _make_result(request, "SUBMITTED", aggregate, root[5])


def _write_funding(
    connection: Any,
    request: DemandPostgresCommand,
    root: Tuple[Any, ...],
    now: datetime,
    fault_injector: DemandPostgresFaultInjector,
    ordinal: List[int],
) -> DemandPostgresDatabaseResult:
    _require_root_version(root, request)
    source = request.source_event
    if root[3] not in {"VERIFIED", "FUNDING_PENDING"} or root[8] != root[5]:
        raise DemandPostgresDatabaseError("INVALID_STATE_TRANSITION")
    if source is None:
        raise AssertionError("Funding source disappeared")
    _load_version(connection, request, root[5])
    _before_write(
        fault_injector, ordinal, DemandPostgresWriteCheckpoint.FUNDING_MARKER
    )
    connection.execute(
        "INSERT INTO demand.demand_funding_markers ("
        "id,organization_id,demand_id,demand_version_id,funding_id,status,"
        "source_event_id,source_aggregate_version,amount_currency_sha256,"
        "verification_reference_sha256,occurred_at,created_at) VALUES ("
        "%s,%s,%s,%s,%s,'SECURED',%s,%s,%s,%s,%s,%s)",
        (
            request.funding_marker_id,
            request.scope.organization_id,
            request.scope.demand_id,
            request.demand_version_id,
            source.funding_id,
            source.source_event_id,
            source.source_aggregate_version,
            source.amount_currency_sha256,
            source.verification_reference_sha256,
            source.occurred_at,
            now,
        ),
    )
    aggregate = root[4] + 1
    _before_write(
        fault_injector, ordinal, DemandPostgresWriteCheckpoint.DEMAND_ROOT
    )
    connection.execute(
        "UPDATE demand.demands SET status='FUNDED',aggregate_version=%s,"
        "current_funding_marker_id=%s,updated_at=%s WHERE id=%s",
        (aggregate, request.funding_marker_id, now, request.scope.demand_id),
    )
    return _make_result(request, "FUNDED", aggregate, root[5])


def _write_matching(
    connection: Any,
    request: DemandPostgresCommand,
    root: Tuple[Any, ...],
    assignment: Optional[Tuple[Any, ...]],
    now: datetime,
    fault_injector: DemandPostgresFaultInjector,
    ordinal: List[int],
) -> DemandPostgresDatabaseResult:
    _require_root_version(root, request)
    if (
        root[3] not in {"FUNDED", "NO_MATCH"}
        or root[8] != root[5]
        or root[9] is None
        or (
            request.operation is DemandPostgresOperation.REQUEST_MATCHING
            and (assignment is None or root[2] == request.scope.actor_id)
        )
        or (
            request.operation is DemandPostgresOperation.REQUEST_MATCHING_SYSTEM
            and assignment is not None
        )
    ):
        raise DemandPostgresDatabaseError("INVALID_STATE_TRANSITION")
    version = _load_version(connection, request, root[5])
    policy = _validate_evidence(connection, request, version, now)
    funding = connection.execute(
        "SELECT id,funding_id,status,demand_version_id "
        "FROM demand.demand_funding_markers WHERE id=%s "
        "AND organization_id=%s AND demand_id=%s",
        (root[9], request.scope.organization_id, request.scope.demand_id),
    ).fetchone()
    if funding is None or funding[2] != "SECURED" or funding[3] != root[5]:
        raise DemandPostgresDatabaseError("FUNDING_REQUIRED")
    _before_write(
        fault_injector,
        ordinal,
        DemandPostgresWriteCheckpoint.MATCHING_REQUEST,
    )
    connection.execute(
        "INSERT INTO demand.matching_requests ("
        "id,organization_id,demand_id,aggregate_version,status,"
        "demand_version_id,verified_review_id,funding_marker_id,funding_id,"
        "taxonomy_bundle_id,budget_rule_bundle_id,risk_rule_bundle_id,"
        "matching_rule_bundle_id,reason_code_bundle_id,"
        "composite_rule_requirement_id,matching_selector_digest,"
        "rule_requirement_sha256,budget_override_code,"
        "authorized_workload_principal_id,authorization_digest,requested_at) "
        "VALUES (%s,%s,%s,1,'OPEN',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,"
        "%s,%s,%s,%s)",
        (
            request.matching_request_id,
            request.scope.organization_id,
            request.scope.demand_id,
            request.demand_version_id,
            root[7],
            funding[0],
            funding[1],
            policy[6],
            policy[7],
            policy[8],
            policy[9],
            policy[10],
            policy[11],
            policy[13],
            policy[12],
            request.budget_health_code,
            UUID("48000000-0000-4000-8000-000000000001"),
            hashlib.sha256(
                b"exact-demand-match-request-allowlist"
            ).digest(),
            now,
        ),
    )
    aggregate = root[4] + 1
    _before_write(
        fault_injector, ordinal, DemandPostgresWriteCheckpoint.DEMAND_ROOT
    )
    connection.execute(
        "UPDATE demand.demands SET status='MATCHING',aggregate_version=%s,"
        "current_matching_request_id=%s,updated_at=%s WHERE id=%s",
        (aggregate, request.matching_request_id, now, request.scope.demand_id),
    )
    return _make_result(request, "MATCHING", aggregate, root[5])


def _write_cancel(
    connection: Any,
    request: DemandPostgresCommand,
    root: Tuple[Any, ...],
    assignment: Optional[Tuple[Any, ...]],
    now: datetime,
    fault_injector: DemandPostgresFaultInjector,
    ordinal: List[int],
) -> DemandPostgresDatabaseResult:
    _require_root_version(root, request)
    if root[3] in {"MATCHED", "CANCELLED", "EXPIRED"}:
        raise DemandPostgresDatabaseError("INVALID_STATE_TRANSITION")
    if (
        request.operation is DemandPostgresOperation.CANCEL_REVIEW
        and (assignment is None or root[2] == request.scope.actor_id)
    ):
        raise DemandPostgresDatabaseError("RESOURCE_NOT_FOUND")
    aggregate = root[4] + 1
    _before_write(
        fault_injector, ordinal, DemandPostgresWriteCheckpoint.DEMAND_ROOT
    )
    connection.execute(
        "UPDATE demand.demands SET status='CANCELLED',aggregate_version=%s,"
        "terminal_at=%s,terminal_reason_code=%s,updated_at=%s WHERE id=%s",
        (
            aggregate,
            now,
            request.cancel_reason_code,
            now,
            request.scope.demand_id,
        ),
    )
    return _make_result(request, "CANCELLED", aggregate, root[5])


def _write_expire(
    connection: Any,
    request: DemandPostgresCommand,
    root: Tuple[Any, ...],
    now: datetime,
    fault_injector: DemandPostgresFaultInjector,
    ordinal: List[int],
) -> DemandPostgresDatabaseResult:
    _require_root_version(root, request)
    if root[3] in {"MATCHING", "MATCHED", "CANCELLED", "EXPIRED"}:
        raise DemandPostgresDatabaseError("INVALID_STATE_TRANSITION")
    if request.deadline > now or root[11] > now:
        raise DemandPostgresDatabaseError("INVALID_STATE_TRANSITION")
    aggregate = root[4] + 1
    _before_write(
        fault_injector, ordinal, DemandPostgresWriteCheckpoint.DEMAND_ROOT
    )
    connection.execute(
        "UPDATE demand.demands SET status='EXPIRED',aggregate_version=%s,"
        "terminal_at=%s,terminal_reason_code='DEADLINE_REACHED',updated_at=%s "
        "WHERE id=%s",
        (aggregate, now, now, request.scope.demand_id),
    )
    return _make_result(request, "EXPIRED", aggregate, root[5])


def _make_result(
    request: DemandPostgresCommand,
    status: str,
    aggregate_version: int,
    current_version_id: UUID,
) -> DemandPostgresDatabaseResult:
    safe = _safe_response(
        request.scope.demand_id,
        current_version_id,
        status,
        aggregate_version,
    )
    return DemandPostgresDatabaseResult(
        operation=request.operation,
        replayed=False,
        demand_id=request.scope.demand_id,
        current_version_id=current_version_id,
        status=status,
        aggregate_version=aggregate_version,
        safe_response=MappingProxyType(safe),
        event_types=_event_types(request.operation),
    )


def _safe_response(
    demand_id: UUID,
    demand_version_id: UUID,
    status: str,
    aggregate_version: int,
) -> Dict[str, Any]:
    return {
        "aggregate_version": aggregate_version,
        "demand_id": str(demand_id),
        "demand_version_id": str(demand_version_id),
        "status": status,
    }


def _event_types(operation: DemandPostgresOperation) -> Tuple[str, ...]:
    if operation is DemandPostgresOperation.CREATE:
        return ("DemandCreated", "DemandVersionCreated")
    return (_EVENT_TYPE[operation],)


def _events_for_result(
    connection: Any,
    request: DemandPostgresCommand,
    result: DemandPostgresDatabaseResult,
    now: datetime,
) -> Tuple[Dict[str, Any], ...]:
    events = []
    for event_id, event_type in zip(
        request.scope.outbox_event_ids,
        result.event_types,
    ):
        if event_type == "DemandCreated":
            payload = {
                "demand_id": str(result.demand_id),
                "organization_id": str(request.scope.organization_id),
                "status": "DRAFT",
                "demand_version_id": str(result.current_version_id),
            }
        elif event_type == "DemandVersionCreated":
            version_no = 1
            if request.operation is DemandPostgresOperation.CREATE_VERSION:
                version_no = result.aggregate_version
            payload = {
                "demand_id": str(result.demand_id),
                "demand_version_id": str(result.current_version_id),
                "version_no": version_no,
                "content_sha256": request.content_sha256.hex(),
                "taxonomy_bundle_id": str(request.taxonomy_bundle_id),
            }
        elif event_type == "DemandSubmitted":
            payload = {
                "demand_id": str(result.demand_id),
                "demand_version_id": str(result.current_version_id),
                "submission_id": str(request.submission_id),
                "status": "SUBMITTED",
            }
        elif event_type == "DemandChangesRequested":
            payload = {
                "demand_id": str(result.demand_id),
                "demand_version_id": str(result.current_version_id),
                "review_id": str(request.review_id),
                "reason_codes": list(request.reason_codes),
                "required_field_codes": list(request.required_field_codes),
                "status": "NEEDS_CHANGES",
            }
        elif event_type == "DemandVerified":
            payload = {
                "demand_id": str(result.demand_id),
                "demand_version_id": str(result.current_version_id),
                "review_id": str(request.review_id),
                "budget_health_code": request.budget_health_code,
                "status": "VERIFIED",
            }
        elif event_type == "DemandReviewAssignmentReleased":
            payload = {
                "demand_id": str(result.demand_id),
                "demand_version_id": str(result.current_version_id),
                "assignment_id": str(request.assignment_id),
                "reason_code": request.release_reason_code,
                "status": "SUBMITTED",
            }
        elif event_type == "DemandFunded":
            payload = {
                "demand_id": str(result.demand_id),
                "demand_version_id": str(result.current_version_id),
                "funding_id": str(request.source_event.funding_id),
                "status": "FUNDED",
            }
        elif event_type == "MatchingRequested":
            payload = {
                "demand_id": str(result.demand_id),
                "demand_version_id": str(result.current_version_id),
                "funding_id": str(_funding_id_for_event(connection, request)),
                "matching_request_id": str(request.matching_request_id),
                "composite_rule_requirement_id": str(
                    request.rule_requirement.composite_rule_requirement_id
                ),
                "status": "MATCHING",
            }
        elif event_type == "DemandCancelled":
            payload = {
                "demand_id": str(result.demand_id),
                "status": "CANCELLED",
                "reason_code": request.cancel_reason_code,
            }
        elif event_type == "DemandExpired":
            payload = {
                "demand_id": str(result.demand_id),
                "status": "EXPIRED",
                "reason_code": "DEADLINE_REACHED",
            }
        else:
            raise AssertionError("unknown Demand event type")
        events.append(
            {
                "event_id": str(event_id),
                "event_type": event_type,
                "schema_version": 1,
                "occurred_at": _utc_z(now),
                "aggregate_type": "Demand",
                "aggregate_id": str(result.demand_id),
                "aggregate_version": result.aggregate_version,
                "actor_kind": request.scope.actor_kind,
                "actor_id": str(request.scope.actor_id),
                "original_actor_id": (
                    None
                    if request.scope.original_actor_id is None
                    else str(request.scope.original_actor_id)
                ),
                "correlation_id": str(request.scope.correlation_id),
                "causation_id": str(request.scope.causation_id),
                "trace_id": str(request.scope.trace_id),
                "organization_id": str(request.scope.organization_id),
                "payload": payload,
            }
        )
    return tuple(events)


def _funding_id_for_event(connection: Any, request: DemandPostgresCommand) -> UUID:
    row = connection.execute(
        "SELECT marker.funding_id FROM demand.demands root "
        "JOIN demand.demand_funding_markers marker "
        "ON marker.organization_id=root.organization_id "
        "AND marker.demand_id=root.id "
        "AND marker.id=root.current_funding_marker_id "
        "WHERE root.organization_id=%s AND root.id=%s",
        (request.scope.organization_id, request.scope.demand_id),
    ).fetchone()
    if row is None:
        raise DemandPostgresConfigurationError("Demand Funding marker disappeared")
    return row[0]


def _utc_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _write_audit(
    connection: Any,
    request: DemandPostgresCommand,
    before_root: Optional[Tuple[Any, ...]],
    result: DemandPostgresDatabaseResult,
    now: datetime,
    fault_injector: DemandPostgresFaultInjector,
    ordinal: List[int],
) -> None:
    _before_write(fault_injector, ordinal, DemandPostgresWriteCheckpoint.AUDIT)
    connection.execute(
        "INSERT INTO audit.audit_events ("
        "event_id,occurred_at,actor_kind,actor_id,original_actor_id,"
        "action_code,target_kind,target_id,organization_id,before_status,"
        "after_status,before_version,after_version,role_code,purpose_code,"
        "reason_code,auth_strength_code,result_code,command_id,correlation_id,"
        "causation_id,trace_id,safe_attributes) VALUES ("
        "%s,%s,%s,%s,%s,%s,'Demand',%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL,"
        "'SUCCEEDED',%s,%s,%s,%s,%s::jsonb)",
        (
            request.scope.audit_event_id,
            now,
            request.scope.actor_kind,
            request.scope.actor_id,
            request.scope.original_actor_id,
            request.operation.value,
            request.scope.demand_id,
            request.scope.organization_id,
            None if before_root is None else before_root[3],
            result.status,
            None if before_root is None else before_root[4],
            result.aggregate_version,
            (
                "DEMAND_OWNER"
                if request.operation in _OWNER_OPERATIONS
                else "OPERATIONS_REVIEWER"
                if request.operation in _REVIEW_OPERATIONS
                else None
            ),
            (
                "DEMAND_REVIEW"
                if request.operation in _REVIEW_OPERATIONS
                else request.source_event.event_type
                if request.source_event is not None
                else None
            ),
            (
                request.release_reason_code
                if request.operation
                is DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT
                else request.cancel_reason_code
            ),
            request.scope.command_id,
            request.scope.correlation_id,
            request.scope.causation_id,
            request.scope.trace_id,
            json.dumps(
                {
                    "event_types": list(result.event_types),
                    "result_status": result.status,
                },
                separators=(",", ":"),
                sort_keys=True,
            ),
        ),
    )


def _write_outbox(
    connection: Any,
    request: DemandPostgresCommand,
    result: DemandPostgresDatabaseResult,
    events: Tuple[Dict[str, Any], ...],
    now: datetime,
    fault_injector: DemandPostgresFaultInjector,
    ordinal: List[int],
) -> None:
    for index, event in enumerate(events):
        checkpoint = (
            DemandPostgresWriteCheckpoint.OUTBOX_DEMAND_CREATED
            if event["event_type"] == "DemandCreated"
            else DemandPostgresWriteCheckpoint.OUTBOX_VERSION_CREATED
            if event["event_type"] == "DemandVersionCreated"
            else DemandPostgresWriteCheckpoint.OUTBOX_STATE_CHANGED
        )
        _before_write(fault_injector, ordinal, checkpoint)
        connection.execute(
            "INSERT INTO infra.outbox_events ("
            "event_id,event_type,schema_version,occurred_at,aggregate_type,"
            "aggregate_id,aggregate_version,actor_kind,actor_id,"
            "original_actor_id,correlation_id,causation_id,trace_id,"
            "organization_id,payload,delivery_status,attempt_count,"
            "available_at,lease_owner,lease_until,published_at,last_error_code,"
            "created_at) VALUES ("
            "%s,%s,1,%s,'Demand',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,"
            "'PENDING',0,%s,NULL,NULL,NULL,NULL,%s)",
            (
                request.scope.outbox_event_ids[index],
                event["event_type"],
                now,
                result.demand_id,
                result.aggregate_version,
                request.scope.actor_kind,
                request.scope.actor_id,
                request.scope.original_actor_id,
                request.scope.correlation_id,
                request.scope.causation_id,
                request.scope.trace_id,
                request.scope.organization_id,
                json.dumps(
                    event["payload"],
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ),
                now,
                now,
            ),
        )


def _complete_receipt(
    connection: Any,
    request: DemandPostgresCommand,
    result: DemandPostgresDatabaseResult,
    now: datetime,
    fault_injector: DemandPostgresFaultInjector,
    ordinal: List[int],
) -> None:
    _before_write(
        fault_injector,
        ordinal,
        DemandPostgresWriteCheckpoint.RECEIPT_COMPLETED,
    )
    updated = connection.execute(
        "UPDATE demand.command_receipts SET status='COMPLETED',"
        "response_http_status=%s,response_schema_name='DemandDto',"
        "response_schema_version=1,response_entity_tag=%s,"
        "safe_response_body=%s::jsonb,target_id=%s,target_version=%s,"
        "result_status=%s,event_types=%s,completed_at=%s "
        "WHERE receipt_id=%s AND status='IN_PROGRESS'",
        (
            201 if request.operation is DemandPostgresOperation.CREATE else 200,
            f'"v{result.aggregate_version}"',
            json.dumps(
                dict(result.safe_response),
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ),
            result.demand_id,
            result.aggregate_version,
            result.status,
            list(result.event_types),
            now,
            request.receipt.receipt_id,
        ),
    )
    if updated.rowcount != 1:
        raise DemandPostgresConfigurationError("Demand receipt completion drifted")


def _complete_source(
    connection: Any,
    request: DemandPostgresCommand,
    result: DemandPostgresDatabaseResult,
    now: datetime,
    fault_injector: DemandPostgresFaultInjector,
    ordinal: List[int],
) -> None:
    _before_write(
        fault_injector,
        ordinal,
        DemandPostgresWriteCheckpoint.SOURCE_INBOX_COMPLETED,
    )
    updated = connection.execute(
        "UPDATE demand.source_inbox SET status='COMPLETED',"
        "result_aggregate_version=%s,result_event_types=%s,completed_at=%s "
        "WHERE source_event_id=%s AND status='IN_PROGRESS'",
        (
            result.aggregate_version,
            list(result.event_types),
            now,
            request.source_event.source_event_id,
        ),
    )
    if updated.rowcount != 1:
        raise DemandPostgresConfigurationError("Demand source completion drifted")


def _reset_writer_connection(connection: Any) -> None:
    connection.execute("RESET ALL")
    connection.execute("DISCARD TEMP")


def _rollback_quietly(connection: Any) -> None:
    try:
        connection.execute("ROLLBACK")
    except BaseException:
        pass


def _release_after_failure(
    source: DemandPostgresConnectionSource,
    connection: Any,
) -> None:
    try:
        _reset_writer_connection(connection)
    except BaseException:
        source.discard(connection)
    else:
        source.release(connection)


def _map_database_error(
    error: psycopg.Error,
    operation: DemandPostgresOperation,
) -> Optional[DemandPostgresDatabaseError]:
    constraint = getattr(getattr(error, "diag", None), "constraint_name", None)
    if isinstance(error, psycopg.errors.UniqueViolation):
        if constraint in {"pk_demands", "uq_demand_client_reference"} or operation is DemandPostgresOperation.CREATE:
            return DemandPostgresDatabaseError("DEMAND_ALREADY_EXISTS")
        if constraint in {
            "uq_demand_submission_version",
            "uq_demand_review_assignment",
            "uq_demand_active_review_assignment",
            "uq_demand_open_matching_request",
        }:
            return DemandPostgresDatabaseError("INVALID_STATE_TRANSITION")
    return None


class PsycopgDemandMatchingRepository:
    """Exact allowlisted MATCH_INPUT capture through one fixed function."""

    def __init__(
        self,
        *,
        connections: DemandPostgresConnectionSource,
        settings: Optional[DemandPostgresSettings] = None,
    ) -> None:
        self.connections = connections
        self.settings = settings or DemandPostgresSettings()

    def capture_match_inputs(
        self,
        request: DemandPostgresMatchCaptureRequest,
    ) -> DemandPostgresMatchCaptureResult:
        if not isinstance(request, DemandPostgresMatchCaptureRequest):
            raise ValueError("closed Demand MATCH_INPUT request is required")
        connection = self.connections.checkout()
        transaction_open = False
        try:
            row = connection.execute(
                "SELECT session_user,current_user,"
                "current_setting('server_version_num')::integer/10000,"
                "current_schema_version,schema_head_version,"
                "required_iam_schema_version FROM demand.schema_compatibility"
            ).fetchone()
            if row != (
                "demand_matching",
                "demand_matching",
                18,
                DEMAND_SCHEMA_HEAD_VERSION,
                DEMAND_SCHEMA_HEAD_VERSION,
                DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
            ):
                raise DemandPostgresDatabaseError("SERVICE_UNAVAILABLE")
            connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY")
            transaction_open = True
            for name, value in (
                ("lock_timeout", f"{self.settings.lock_timeout_ms}ms"),
                ("statement_timeout", f"{self.settings.statement_timeout_ms}ms"),
                ("TimeZone", "UTC"),
                ("app.scope_kind", "DEMAND_MATCH_CAPTURE"),
                ("app.actor_id", str(request.workload_principal_id)),
            ):
                connection.execute(
                    "SELECT pg_catalog.set_config(%s,%s,true)",
                    (name, value),
                )
            rows = tuple(
                connection.execute(
                    "SELECT captured.* FROM demand.capture_match_inputs_v1("
                    "%s,%s,%s,%s) AS captured "
                    "WHERE captured.captured_at=transaction_timestamp()",
                    (
                        request.match_run_id,
                        request.workload_principal_id,
                        list(request.matching_request_ids),
                        request.authorization_digest,
                    ),
                ).fetchall()
            )
            if (
                len(rows) != len(request.matching_request_ids)
                or tuple(item[0] for item in rows) != request.matching_request_ids
            ):
                raise DemandPostgresDatabaseError("RESOURCE_NOT_FOUND")
            snapshots = tuple(_snapshot_from_capture_row(item) for item in rows)
            captured_at = snapshots[0].captured_at
            result = DemandPostgresMatchCaptureResult(
                match_run_id=request.match_run_id,
                captured_at=captured_at,
                requested_matching_request_ids=request.matching_request_ids,
                snapshots=snapshots,
                statement_count=2,
            )
            connection.execute("COMMIT")
            transaction_open = False
            _reset_writer_connection(connection)
            self.connections.release(connection)
            return result
        except DemandPostgresDatabaseError:
            if transaction_open:
                _rollback_quietly(connection)
            _release_after_failure(self.connections, connection)
            raise
        except (psycopg.Error, ValueError) as error:
            if transaction_open:
                _rollback_quietly(connection)
            _release_after_failure(self.connections, connection)
            raise DemandPostgresDatabaseError("SERVICE_UNAVAILABLE") from error


def _snapshot_from_capture_row(row: Tuple[Any, ...]) -> DemandPostgresMatchInputSnapshot:
    try:
        decoded = json.loads(
            row[10].decode("utf-8"),
            object_pairs_hook=_closed_json_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON number")
            ),
        )
        content = decoded["content"]
        skills = content["skills"]
        levels = {
            "FOUNDATION": 1,
            "WORKING": 2,
            "ADVANCED": 3,
            "EXPERT": 4,
        }

        def skill_tuple(key: str) -> Tuple[DemandPostgresMatchSkillRequirement, ...]:
            return tuple(
                sorted(
                    (
                        DemandPostgresMatchSkillRequirement(
                            skill_code=item["skill_code"],
                            minimum_level=levels[item["minimum_level_code"]],
                        )
                        for item in skills[key]
                    ),
                    key=lambda item: item.skill_code.encode("utf-8"),
                )
            )

        matching = content["matching"]
        schedule = content["schedule"]
        budget = content["budget"]
        collaboration = content["collaboration"]
        location = content["location"]
        risk = content["risk"]
        ai_policy = content["ai"]
        ai_use = (
            "REQUIRED"
            if ai_policy["required"] is True
            else "OPTIONAL"
            if ai_policy["allowed"] is True
            else "PROHIBITED"
        )
        return DemandPostgresMatchInputSnapshot(
            matching_request_id=row[0],
            matching_request_version=row[1],
            matching_request_status=row[2],
            organization_id=row[3],
            demand_id=row[4],
            demand_status=row[5],
            demand_version_id=row[6],
            demand_version_no=row[7],
            verification_decision=row[8],
            content_sha256=row[9],
            canonical_demand_version_bytes=row[10],
            taxonomy_bundle_id=row[11],
            funding_id=row[12],
            funding_status=row[13],
            composite_rule_requirement_id=row[14],
            budget_rule_bundle_id=row[15],
            risk_rule_bundle_id=row[16],
            matching_rule_bundle_id=row[17],
            reason_code_bundle_id=row[18],
            matching_selector_digest=row[19],
            rule_requirement_sha256=row[20],
            problem_type_codes=_sorted_codes(matching["problem_codes"]),
            domain_codes=_sorted_codes(matching["domain_codes"]),
            task_codes=_sorted_codes(matching["task_codes"]),
            must_have_skills=skill_tuple("must_have"),
            nice_to_have_skills=skill_tuple("nice_to_have"),
            start_date=date.fromisoformat(schedule["start_date"]),
            due_date=date.fromisoformat(schedule["due_date"]),
            required_weekly_hours=schedule["weekly_hours"],
            required_duration_weeks=schedule["duration_weeks"],
            currency=budget["currency"],
            minimum_amount_minor=budget["minimum_amount_minor"],
            maximum_amount_minor=budget["maximum_amount_minor"],
            allowed_region_codes=_sorted_codes(
                "REGION." + item.upper()
                for item in location["allowed_creator_region_codes"]
            ),
            required_language_codes=_matching_language_codes(collaboration["languages"]),
            required_work_mode_code=(
                "WORK_MODE." + collaboration["work_mode"].upper()
            ),
            data_sensitivity_code=risk["data_sensitivity"],
            ai_use_code=ai_use,
            budget_override_code=row[21],
            captured_at=row[22],
        )
    except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Demand MATCH_INPUT persisted facts are corrupt") from error


def _require_uuid(value: Any, label: str) -> None:
    if not isinstance(value, UUID) or value.int == 0:
        raise ValueError(label + " must be a non-zero UUID")


def _require_key_id(value: Any, label: str) -> None:
    if (
        not isinstance(value, str)
        or not 8 <= len(value) <= 128
        or any(
            character
            not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
            for character in value
        )
    ):
        raise ValueError(label + " is invalid")


def _require_digest(value: Any, label: str) -> None:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError(label + " must be exactly 32 bytes")


def _require_positive_int(value: Any, label: str) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= 2_147_483_647
    ):
        raise ValueError(label + " must be a positive integer")


def _require_utc(value: Any, label: str) -> None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise ValueError(label + " must be UTC-aware")


def _require_window(evaluated_at: datetime, valid_until: datetime, label: str) -> None:
    _require_utc(evaluated_at, label + " evaluated_at")
    _require_utc(valid_until, label + " valid_until")
    if valid_until <= evaluated_at:
        raise ValueError(label + " validity window is empty")


def _validate_match_snapshot_canonical_facts(
    snapshot: DemandPostgresMatchInputSnapshot,
) -> None:
    try:
        decoded = json.loads(
            snapshot.canonical_demand_version_bytes.decode("utf-8"),
            object_pairs_hook=_closed_json_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON number")
            ),
        )
        if not isinstance(decoded, dict) or set(decoded) != {
            "canonicalization_version",
            "content",
            "demand_id",
            "demand_schema_version",
            "taxonomy_bundle_id",
            "version_no",
        }:
            raise ValueError("canonical DemandVersion root is open")
        if (
            decoded["canonicalization_version"] != "demand-content-json-v1"
            or decoded["demand_schema_version"] != 1
            or decoded["demand_id"] != str(snapshot.demand_id)
            or decoded["taxonomy_bundle_id"] != str(snapshot.taxonomy_bundle_id)
            or decoded["version_no"] != snapshot.demand_version_no
        ):
            raise ValueError("canonical DemandVersion identity drifted")
        frozen_content = _freeze_demand_json(decoded["content"])
        if not isinstance(frozen_content, DemandContent):
            raise ValueError("canonical DemandVersion content is not an object")
        validate_demand_content(frozen_content, for_submission=True)
        recomputed = canonical_demand_version_bytes(
            demand_id=str(snapshot.demand_id),
            version_no=snapshot.demand_version_no,
            taxonomy_bundle_id=str(snapshot.taxonomy_bundle_id),
            content=frozen_content,
        )
        if recomputed != snapshot.canonical_demand_version_bytes:
            raise ValueError("canonical DemandVersion bytes are not restricted JCS")
        if not hmac.compare_digest(
            hashlib.sha256(recomputed).digest(),
            snapshot.content_sha256,
        ):
            raise ValueError("canonical DemandVersion hash drifted")

        content = decoded["content"]
        matching = content["matching"]
        skills = content["skills"]
        schedule = content["schedule"]
        budget = content["budget"]
        location = content["location"]
        collaboration = content["collaboration"]
        risk = content["risk"]
        ai_policy = content["ai"]
        skill_levels = {
            "FOUNDATION": 1,
            "WORKING": 2,
            "ADVANCED": 3,
            "EXPERT": 4,
        }

        def derived_skills(key: str) -> Tuple[DemandPostgresMatchSkillRequirement, ...]:
            return tuple(
                sorted(
                    (
                        DemandPostgresMatchSkillRequirement(
                            skill_code=item["skill_code"],
                            minimum_level=skill_levels[item["minimum_level_code"]],
                        )
                        for item in skills[key]
                    ),
                    key=lambda item: item.skill_code.encode("utf-8"),
                )
            )

        ai_use_code = (
            "REQUIRED"
            if ai_policy["required"] is True
            else "OPTIONAL"
            if ai_policy["allowed"] is True
            else "PROHIBITED"
        )
        expected = {
            "problem_type_codes": _sorted_codes(matching["problem_codes"]),
            "domain_codes": _sorted_codes(matching["domain_codes"]),
            "task_codes": _sorted_codes(matching["task_codes"]),
            "must_have_skills": derived_skills("must_have"),
            "nice_to_have_skills": derived_skills("nice_to_have"),
            "start_date": date.fromisoformat(schedule["start_date"]),
            "due_date": date.fromisoformat(schedule["due_date"]),
            "required_weekly_hours": schedule["weekly_hours"],
            "required_duration_weeks": schedule["duration_weeks"],
            "currency": budget["currency"],
            "minimum_amount_minor": budget["minimum_amount_minor"],
            "maximum_amount_minor": budget["maximum_amount_minor"],
            "allowed_region_codes": _sorted_codes(
                "REGION." + item.upper()
                for item in location["allowed_creator_region_codes"]
            ),
            "required_language_codes": _matching_language_codes(collaboration["languages"]),
            "required_work_mode_code": (
                "WORK_MODE." + collaboration["work_mode"].upper()
            ),
            "data_sensitivity_code": risk["data_sensitivity"],
            "ai_use_code": ai_use_code,
        }
        if any(getattr(snapshot, key) != value for key, value in expected.items()):
            raise ValueError("MATCH_INPUT derived facts drifted from canonical content")
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        DemandDomainError,
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        raise ValueError("MATCH_INPUT canonical DemandVersion facts are invalid") from error


def _closed_json_object(pairs: Any) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if not isinstance(key, str) or key in result:
            raise ValueError("canonical DemandVersion has duplicate JSON keys")
        result[key] = value
    return result


def _freeze_demand_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return DemandContent(
            tuple((str(key), _freeze_demand_json(child)) for key, child in value.items())
        )
    if isinstance(value, list):
        return tuple(_freeze_demand_json(child) for child in value)
    if value is None or isinstance(value, (bool, int, str)):
        return value
    raise ValueError("canonical DemandVersion contains an unsupported JSON value")


def _sorted_codes(values: Any) -> Tuple[str, ...]:
    result = tuple(sorted(tuple(values), key=lambda item: item.encode("utf-8")))
    _require_canonical_code_tuple(result, "derived MATCH_INPUT codes")
    return result


def _matching_language_codes(values: Any) -> Tuple[str, ...]:
    # Profile5's reviewed derived-input contract uses DISTINCT root languages,
    # e.g. zh-CN and zh-TW both become LANGUAGE.ZH. Preserve source locale
    # tags in canonical DemandVersion bytes and align only the matching view.
    return _sorted_codes({"LANGUAGE." + item.split("-", 1)[0].upper() for item in values})


def _require_code(value: Any, label: str) -> None:
    if (
        not isinstance(value, str)
        or not 2 <= len(value) <= 64
        or value[0] not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        or any(
            character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-"
            for character in value
        )
    ):
        raise ValueError(label + " is not a closed code")


def _require_canonical_code_tuple(value: Any, label: str) -> None:
    if not isinstance(value, tuple):
        raise ValueError(label + " are not an immutable tuple")
    for item in value:
        _require_code(item, label)
    if (
        len(value) != len(set(value))
        or value != tuple(sorted(value, key=lambda item: item.encode("utf-8")))
    ):
        raise ValueError(label + " are not unique and UTF-8 sorted")


def _require_canonical_skill_tuple(value: Any, label: str) -> None:
    if (
        not isinstance(value, tuple)
        or any(
            not isinstance(item, DemandPostgresMatchSkillRequirement)
            for item in value
        )
        or len({item.skill_code for item in value}) != len(value)
        or value
        != tuple(sorted(value, key=lambda item: item.skill_code.encode("utf-8")))
    ):
        raise ValueError(label + " are not an immutable canonical tuple")


def _require_bounded_nonbool_int(
    value: Any,
    label: str,
    *,
    minimum: int,
    maximum: int,
) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise ValueError(label + " is outside the closed integer range")


def _require_code_tuple(
    value: Any,
    label: str,
    *,
    nonempty: bool,
) -> None:
    if (
        not isinstance(value, tuple)
        or (nonempty and not value)
        or len(value) != len(set(value))
        or any(
            not isinstance(item, str)
            or not 2 <= len(item) <= 64
            or item.upper() != item
            or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" for character in item)
            for item in value
        )
    ):
        raise ValueError(label + " are not a closed unique tuple")
