"""Production PostgreSQL 18 fixed programs for Taxonomy.

The surface freezes reviewed roles, immutable database requests, fixed
statement identities, checkpoints, exact projections, receipt material, and
the COMMIT_SENT boundary.  The implementation uses only static parameterized
programs and reviewed database functions; there is no Memory, owner,
BYPASSRLS, generic-query, or test-environment fallback.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import hmac
import json
from types import MappingProxyType
from typing import Any, Mapping, Optional, Protocol, Tuple

from ...domain import (
    TaxonomyArtifactDescriptor,
    TaxonomyAttribute,
    TaxonomyCompatibilityLevel,
    TaxonomyCrosswalkArtifact,
    TaxonomyCrosswalkMapping,
    TaxonomyEdge,
    TaxonomyEdgeKind,
    TaxonomyEdgesArtifact,
    TaxonomyLabel,
    TaxonomyLabelsArtifact,
    TaxonomyMappingKind,
    TaxonomyNode,
    TaxonomyNodeKind,
    TaxonomyNodeStatus,
    TaxonomyNodesArtifact,
    TaxonomyReleaseCandidate,
    TaxonomyReleaseManifest,
    TaxonomySelector,
    ValidatedTaxonomyRelease,
)


TAXONOMY_POSTGRES_BEHAVIOR_NOT_AVAILABLE = (
    "TAXONOMY_POSTGRES_BEHAVIOR_NOT_AVAILABLE"
)


class TaxonomyPostgresBehaviorNotAvailable(RuntimeError):
    """Stable semantic-RED sentinel for absent reviewed SQL programs."""


class TaxonomyPostgresConfigurationError(RuntimeError):
    """The server, role, catalog, transaction, or reset state is untrusted."""


class TaxonomyPostgresDatabaseError(RuntimeError):
    """Closed database rejection from a future fixed program."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class TaxonomyPostgresCommitOutcomeUnknownError(RuntimeError):
    """COMMIT was sent but its durable result was not acknowledged."""

    code = "COMMAND_OUTCOME_UNKNOWN"


class TaxonomyPostgresOperation(str, Enum):
    PUBLISH = "PublishTaxonomyBundle"
    RETIRE = "RetireTaxonomyBundle"
    READ_BUNDLE = "ReadExactTaxonomyBundle"
    READ_NODE = "ReadExactTaxonomyNode"
    READ_EDGE_PAIR = "ReadExactTaxonomyEdgePair"
    CAPTURE_CONSUMER = "CaptureTaxonomyConsumerRelease"
    CLAIM_CONSUMER_INBOX = "ClaimTaxonomyConsumerInbox"


class TaxonomyPostgresWriteCheckpoint(str, Enum):
    RECEIPT_PENDING = "receipt.pending"
    BUNDLE_INSERT = "bundle.insert"
    ARTIFACTS_INSERT = "artifacts.insert"
    NODES_INSERT = "nodes.insert"
    EDGES_INSERT = "edges.insert"
    LABELS_INSERT = "labels.insert"
    CROSSWALK_INSERT_OPTIONAL = "crosswalk.insert_optional"
    PREDECESSOR_SUPERSEDE_OPTIONAL = "predecessor.supersede_optional"
    CURRENT_ADVANCE = "current.advance"
    BUNDLE_RETIRE = "bundle.retire"
    CURRENT_CLEAR_IF_CURRENT = "current.clear_if_current"
    AUDIT_APPEND = "audit.append"
    OUTBOX_APPEND = "outbox.append"
    RECEIPT_COMPLETE = "receipt.complete"
    COMMIT = "commit"


TAXONOMY_POSTGRES_PUBLISH_WRITE_CHECKPOINTS = (
    TaxonomyPostgresWriteCheckpoint.RECEIPT_PENDING,
    TaxonomyPostgresWriteCheckpoint.BUNDLE_INSERT,
    TaxonomyPostgresWriteCheckpoint.ARTIFACTS_INSERT,
    TaxonomyPostgresWriteCheckpoint.NODES_INSERT,
    TaxonomyPostgresWriteCheckpoint.EDGES_INSERT,
    TaxonomyPostgresWriteCheckpoint.LABELS_INSERT,
    TaxonomyPostgresWriteCheckpoint.CROSSWALK_INSERT_OPTIONAL,
    TaxonomyPostgresWriteCheckpoint.PREDECESSOR_SUPERSEDE_OPTIONAL,
    TaxonomyPostgresWriteCheckpoint.CURRENT_ADVANCE,
    TaxonomyPostgresWriteCheckpoint.AUDIT_APPEND,
    TaxonomyPostgresWriteCheckpoint.OUTBOX_APPEND,
    TaxonomyPostgresWriteCheckpoint.RECEIPT_COMPLETE,
    TaxonomyPostgresWriteCheckpoint.COMMIT,
)

TAXONOMY_POSTGRES_RETIRE_WRITE_CHECKPOINTS = (
    TaxonomyPostgresWriteCheckpoint.RECEIPT_PENDING,
    TaxonomyPostgresWriteCheckpoint.BUNDLE_RETIRE,
    TaxonomyPostgresWriteCheckpoint.CURRENT_CLEAR_IF_CURRENT,
    TaxonomyPostgresWriteCheckpoint.AUDIT_APPEND,
    TaxonomyPostgresWriteCheckpoint.OUTBOX_APPEND,
    TaxonomyPostgresWriteCheckpoint.RECEIPT_COMPLETE,
    TaxonomyPostgresWriteCheckpoint.COMMIT,
)

TAXONOMY_POSTGRES_WRITE_CHECKPOINTS = tuple(
    TaxonomyPostgresWriteCheckpoint
)


class TaxonomyPostgresConnectionSource(Protocol):
    def checkout(self) -> Any: ...

    def release(self, connection: Any) -> None: ...

    def discard(self, connection: Any) -> None: ...


class TaxonomyPostgresFaultInjector(Protocol):
    def before_write(
        self,
        checkpoint: TaxonomyPostgresWriteCheckpoint,
        ordinal: int,
    ) -> None: ...


class TaxonomyPostgresSchemaValidator(Protocol):
    def validate(
        self,
        value: Mapping[str, Any],
        schema_name: Optional[str] = None,
    ) -> None: ...


class NoTaxonomyPostgresFaults:
    def before_write(
        self,
        checkpoint: TaxonomyPostgresWriteCheckpoint,
        ordinal: int,
    ) -> None:
        del checkpoint, ordinal


@dataclass(frozen=True)
class TaxonomyPostgresSettings:
    publisher_role: str = "taxonomy_publisher"
    admin_role: str = "taxonomy_admin"
    reader_role: str = "taxonomy_reader"
    consumer_role: str = "taxonomy_consumer"
    required_server_major: int = 18
    lock_timeout_ms: int = 2_000
    statement_timeout_ms: int = 10_000
    idle_in_transaction_timeout_ms: int = 15_000
    maximum_release_bytes: int = 4 * 1024 * 1024
    maximum_consumer_nodes: int = 50_000
    max_precommit_retries: int = 3

    def __post_init__(self) -> None:
        if (
            self.publisher_role,
            self.admin_role,
            self.reader_role,
            self.consumer_role,
        ) != (
            "taxonomy_publisher",
            "taxonomy_admin",
            "taxonomy_reader",
            "taxonomy_consumer",
        ):
            raise ValueError("Taxonomy online roles are not the reviewed set")
        if self.required_server_major != 18:
            raise ValueError("Taxonomy PostgreSQL major must be 18")
        if not 1 <= self.lock_timeout_ms <= 10_000:
            raise ValueError("Taxonomy lock timeout is outside reviewed bounds")
        if not 1 <= self.statement_timeout_ms <= 30_000:
            raise ValueError("Taxonomy statement timeout is outside reviewed bounds")
        if not 1 <= self.idle_in_transaction_timeout_ms <= 30_000:
            raise ValueError("Taxonomy idle timeout is outside reviewed bounds")
        if self.maximum_release_bytes != 4 * 1024 * 1024:
            raise ValueError("Taxonomy v1 release ceiling must be 4 MiB")
        if self.maximum_consumer_nodes != 50_000:
            raise ValueError("Taxonomy v1 consumer node ceiling must be 50000")
        if self.max_precommit_retries != 3:
            raise ValueError("Taxonomy pre-COMMIT retries must be exactly 3")


@dataclass(frozen=True)
class TaxonomyPostgresStatementProfile:
    operation: TaxonomyPostgresOperation
    runtime_role: str
    statement_names: Tuple[str, ...]
    statement_budget: int
    query_shape_sha256: str

    def __post_init__(self) -> None:
        if self.runtime_role != _ROLE_BY_OPERATION[self.operation]:
            raise ValueError("Taxonomy fixed program has the wrong role")
        if (
            not self.statement_names
            or len(self.statement_names) != self.statement_budget
            or len(set(self.statement_names)) != len(self.statement_names)
        ):
            raise ValueError("Taxonomy fixed statement budget is not closed")
        if len(self.query_shape_sha256) != 64 or any(
            character not in "0123456789abcdef"
            for character in self.query_shape_sha256
        ):
            raise ValueError("Taxonomy query-shape digest is invalid")


_ROLE_BY_OPERATION = MappingProxyType(
    {
        TaxonomyPostgresOperation.PUBLISH: "taxonomy_publisher",
        TaxonomyPostgresOperation.RETIRE: "taxonomy_admin",
        TaxonomyPostgresOperation.READ_BUNDLE: "taxonomy_reader",
        TaxonomyPostgresOperation.READ_NODE: "taxonomy_reader",
        TaxonomyPostgresOperation.READ_EDGE_PAIR: "taxonomy_reader",
        TaxonomyPostgresOperation.CAPTURE_CONSUMER: "taxonomy_consumer",
        TaxonomyPostgresOperation.CLAIM_CONSUMER_INBOX: "taxonomy_consumer",
    }
)

_STATEMENTS_BY_OPERATION = MappingProxyType(
    {
        TaxonomyPostgresOperation.PUBLISH: (
            "preflight_publish_v1",
            "claim_command_receipt_v1",
            "lock_selector_and_evidence_v1",
            "insert_release_graph_v1",
            "validate_and_advance_current_v1",
            "append_publish_audit_v1",
            "append_publish_outbox_v1",
            "complete_command_receipt_v1",
        ),
        TaxonomyPostgresOperation.RETIRE: (
            "preflight_retire_v1",
            "claim_command_receipt_v1",
            "lock_and_retire_bundle_v1",
            "append_retire_audit_v1",
            "append_retire_outbox_v1",
            "complete_command_receipt_v1",
        ),
        TaxonomyPostgresOperation.READ_BUNDLE: ("read_exact_bundle_v1",),
        TaxonomyPostgresOperation.READ_NODE: ("read_exact_node_v1",),
        TaxonomyPostgresOperation.READ_EDGE_PAIR: ("read_exact_edge_pair_v1",),
        TaxonomyPostgresOperation.CAPTURE_CONSUMER: (
            "lock_consumer_authorization_v1",
            "capture_exact_consumer_release_v1",
        ),
        TaxonomyPostgresOperation.CLAIM_CONSUMER_INBOX: (
            "claim_consumer_inbox_v1",
            "complete_consumer_inbox_v1",
        ),
    }
)


def _profile(operation: TaxonomyPostgresOperation) -> TaxonomyPostgresStatementProfile:
    statements = _STATEMENTS_BY_OPERATION[operation]
    surface = json.dumps(
        {
            "profile_version": "taxonomy-postgres-v1",
            "operation": operation.value,
            "role": _ROLE_BY_OPERATION[operation],
            "statement_names": statements,
            "statement_budget": len(statements),
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return TaxonomyPostgresStatementProfile(
        operation=operation,
        runtime_role=_ROLE_BY_OPERATION[operation],
        statement_names=statements,
        statement_budget=len(statements),
        query_shape_sha256=hashlib.sha256(surface).hexdigest(),
    )


TAXONOMY_POSTGRES_STATEMENT_PROFILES = MappingProxyType(
    {operation: _profile(operation) for operation in TaxonomyPostgresOperation}
)


def _require_identifier(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not 16 <= len(value) <= 128:
        raise ValueError(f"{field_name} is not a closed identifier")


def _require_sha256(value: bytes, field_name: str) -> None:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError(f"{field_name} must be a 32-byte digest")


@dataclass(frozen=True)
class TaxonomyPostgresExecutionScope:
    operation: TaxonomyPostgresOperation
    workload_principal_id: str
    workload_credential_id: str = field(repr=False)
    workload_attestation_sha256: bytes = field(repr=False)
    correlation_id: str = ""
    causation_id: str = ""
    trace_id: str = ""
    selector_digest: Optional[bytes] = field(default=None, repr=False)
    bundle_id: Optional[str] = None
    consumer_code: Optional[str] = None
    consumer_job_id: Optional[str] = None
    consumer_authorization_digest: Optional[bytes] = field(
        default=None, repr=False
    )

    def __post_init__(self) -> None:
        for value, name in (
            (self.workload_principal_id, "workload_principal_id"),
            (self.workload_credential_id, "workload_credential_id"),
            (self.correlation_id, "correlation_id"),
            (self.causation_id, "causation_id"),
            (self.trace_id, "trace_id"),
        ):
            _require_identifier(value, name)
        _require_sha256(
            self.workload_attestation_sha256,
            "workload_attestation_sha256",
        )
        if self.selector_digest is not None:
            _require_sha256(self.selector_digest, "selector_digest")
        if self.bundle_id is not None:
            _require_identifier(self.bundle_id, "bundle_id")
        if self.operation in (
            TaxonomyPostgresOperation.CAPTURE_CONSUMER,
            TaxonomyPostgresOperation.CLAIM_CONSUMER_INBOX,
        ):
            if self.consumer_code not in ("PROFILE", "DEMAND", "MATCHING"):
                raise ValueError("consumer_code is outside the reviewed set")
            _require_identifier(self.consumer_job_id or "", "consumer_job_id")
            _require_sha256(
                self.consumer_authorization_digest or b"",
                "consumer_authorization_digest",
            )
        elif any(
            value is not None
            for value in (
                self.consumer_code,
                self.consumer_job_id,
                self.consumer_authorization_digest,
            )
        ):
            raise ValueError("consumer scope is forbidden for this operation")


@dataclass(frozen=True)
class TaxonomyPostgresReceiptMaterial:
    identity_key_id: str
    payload_hash_key_id: str
    identity_digest: bytes = field(repr=False)
    payload_digest: bytes = field(repr=False)
    canonicalization_version: str = "taxonomy-command-json-v1"
    command_version: int = 1
    retained_until: Optional[datetime] = None

    def __post_init__(self) -> None:
        _require_identifier(self.identity_key_id, "identity_key_id")
        _require_identifier(self.payload_hash_key_id, "payload_hash_key_id")
        _require_sha256(self.identity_digest, "identity_digest")
        _require_sha256(self.payload_digest, "payload_digest")
        if self.canonicalization_version != "taxonomy-command-json-v1":
            raise ValueError("receipt canonicalization version is unsupported")
        if self.command_version != 1:
            raise ValueError("receipt command version is unsupported")


@dataclass(frozen=True)
class TaxonomyPostgresSignatureEvidence:
    signature_receipt_id: str
    trust_record_id: str
    signing_key_id: str
    algorithm: str
    release_manifest_sha256: bytes = field(repr=False)
    verified_at: datetime
    valid_until: datetime

    def __post_init__(self) -> None:
        for value, name in (
            (self.signature_receipt_id, "signature_receipt_id"),
            (self.trust_record_id, "trust_record_id"),
            (self.signing_key_id, "signing_key_id"),
        ):
            _require_identifier(value, name)
        if self.algorithm != "ED25519":
            raise ValueError("signature algorithm is unsupported")
        _require_sha256(
            self.release_manifest_sha256, "release_manifest_sha256"
        )
        if self.valid_until <= self.verified_at:
            raise ValueError("signature validity window is empty")


@dataclass(frozen=True)
class TaxonomyPostgresTrustEvidence:
    trust_record_id: str
    signing_key_id: str
    trust_status: str
    allowed_algorithm: str
    release_manifest_sha256: bytes = field(repr=False)
    valid_until: datetime

    def __post_init__(self) -> None:
        _require_identifier(self.trust_record_id, "trust_record_id")
        _require_identifier(self.signing_key_id, "signing_key_id")
        if self.trust_status not in ("ACTIVE", "REVOKED"):
            raise ValueError("trust status is outside the closed set")
        if self.allowed_algorithm != "ED25519":
            raise ValueError("trust algorithm is unsupported")
        _require_sha256(
            self.release_manifest_sha256, "release_manifest_sha256"
        )


@dataclass(frozen=True)
class TaxonomyPostgresApprovalEvidence:
    approval_id: str
    duty_code: str
    reviewer_id: str
    approval_status: str
    release_manifest_sha256: bytes = field(repr=False)
    golden_result_sha256: bytes = field(repr=False)
    approved_at: datetime
    valid_until: datetime

    def __post_init__(self) -> None:
        for value, name in (
            (self.approval_id, "approval_id"),
            (self.reviewer_id, "reviewer_id"),
        ):
            _require_identifier(value, name)
        if self.duty_code not in ("DOMAIN_STEWARD", "SAFETY_DATA_STEWARD"):
            raise ValueError("approval duty is unsupported")
        if self.approval_status not in ("APPROVED", "REVOKED"):
            raise ValueError("approval status is outside the closed set")
        _require_sha256(
            self.release_manifest_sha256, "release_manifest_sha256"
        )
        _require_sha256(self.golden_result_sha256, "golden_result_sha256")
        if self.valid_until <= self.approved_at:
            raise ValueError("approval validity window is empty")


@dataclass(frozen=True)
class TaxonomyPostgresArtifactSet:
    validated_release: ValidatedTaxonomyRelease = field(repr=False)
    canonical_bytes_by_kind: Tuple[Tuple[str, Optional[str], bytes], ...] = field(
        repr=False
    )

    def __post_init__(self) -> None:
        if not self.canonical_bytes_by_kind:
            raise ValueError("exact Taxonomy artifacts are required")
        keys = tuple((kind, locale) for kind, locale, _value in self.canonical_bytes_by_kind)
        if len(set(keys)) != len(keys):
            raise ValueError("Taxonomy artifact identity is duplicated")
        if any(not isinstance(value, bytes) or not value for _kind, _locale, value in self.canonical_bytes_by_kind):
            raise ValueError("Taxonomy canonical artifact bytes are invalid")


@dataclass(frozen=True)
class TaxonomyPostgresPublishRequest:
    scope: TaxonomyPostgresExecutionScope
    receipt: TaxonomyPostgresReceiptMaterial = field(repr=False)
    artifacts: TaxonomyPostgresArtifactSet = field(repr=False)
    signature: TaxonomyPostgresSignatureEvidence
    trust: TaxonomyPostgresTrustEvidence
    approvals: Tuple[
        TaxonomyPostgresApprovalEvidence,
        TaxonomyPostgresApprovalEvidence,
    ]
    expected_current_bundle_id: Optional[str]

    def __post_init__(self) -> None:
        if self.scope.operation is not TaxonomyPostgresOperation.PUBLISH:
            raise ValueError("publish request has the wrong operation")
        candidate = self.artifacts.validated_release.candidate
        if self.scope.bundle_id != candidate.manifest.bundle_id:
            raise ValueError("publish scope is not bound to the candidate")
        if self.expected_current_bundle_id != candidate.manifest.predecessor_bundle_id:
            raise ValueError("publish predecessor/current binding is invalid")
        if len(self.approvals) != 2:
            raise ValueError("publish requires two approvals")
        domain, safety = self.approvals
        if (
            domain.duty_code != "DOMAIN_STEWARD"
            or safety.duty_code != "SAFETY_DATA_STEWARD"
            or domain.reviewer_id == safety.reviewer_id
            or domain.release_manifest_sha256
            != safety.release_manifest_sha256
            or domain.golden_result_sha256 != safety.golden_result_sha256
            or domain.release_manifest_sha256
            != self.signature.release_manifest_sha256
            or self.trust.trust_record_id != self.signature.trust_record_id
            or self.trust.signing_key_id != self.signature.signing_key_id
            or self.trust.allowed_algorithm != self.signature.algorithm
            or self.trust.release_manifest_sha256
            != self.signature.release_manifest_sha256
            or domain.release_manifest_sha256.hex()
            != self.artifacts.validated_release.release_manifest_sha256
        ):
            raise ValueError("publish evidence binding is invalid")


@dataclass(frozen=True)
class TaxonomyPostgresRetireRequest:
    scope: TaxonomyPostgresExecutionScope
    receipt: TaxonomyPostgresReceiptMaterial = field(repr=False)
    bundle_id: str
    expected_bundle_version: int
    reason_code: str

    def __post_init__(self) -> None:
        if self.scope.operation is not TaxonomyPostgresOperation.RETIRE:
            raise ValueError("retire request has the wrong operation")
        _require_identifier(self.bundle_id, "bundle_id")
        if self.scope.bundle_id != self.bundle_id:
            raise ValueError("retire scope is not bound to the bundle")
        if self.expected_bundle_version < 1 or not self.reason_code:
            raise ValueError("retire version/reason is invalid")


@dataclass(frozen=True)
class TaxonomyPostgresExactReadRequest:
    scope: TaxonomyPostgresExecutionScope
    bundle_id: str
    code: Optional[str] = None
    to_code: Optional[str] = None
    locale: Optional[str] = None

    def __post_init__(self) -> None:
        if self.scope.operation not in (
            TaxonomyPostgresOperation.READ_BUNDLE,
            TaxonomyPostgresOperation.READ_NODE,
            TaxonomyPostgresOperation.READ_EDGE_PAIR,
        ):
            raise ValueError("exact read request has the wrong operation")
        _require_identifier(self.bundle_id, "bundle_id")
        if self.scope.bundle_id != self.bundle_id:
            raise ValueError("exact read scope is not bound to the bundle")
        if self.scope.operation is TaxonomyPostgresOperation.READ_BUNDLE:
            if self.code is not None or self.to_code is not None:
                raise ValueError("bundle read cannot carry a code")
        elif self.scope.operation is TaxonomyPostgresOperation.READ_NODE:
            if self.code is None or self.to_code is not None or self.locale is None:
                raise ValueError("node read requires one code and locale")
        elif self.code is None or self.to_code is None:
            raise ValueError("edge read requires an exact code pair")


@dataclass(frozen=True)
class TaxonomyPostgresConsumerCaptureRequest:
    scope: TaxonomyPostgresExecutionScope
    bundle_id: str
    release_manifest_sha256: bytes = field(repr=False)
    supported_family_code: str
    supported_schema_version: int
    supported_semantic_majors: Tuple[int, ...]

    def __post_init__(self) -> None:
        if self.scope.operation is not TaxonomyPostgresOperation.CAPTURE_CONSUMER:
            raise ValueError("consumer capture has the wrong operation")
        _require_identifier(self.bundle_id, "bundle_id")
        _require_sha256(
            self.release_manifest_sha256, "release_manifest_sha256"
        )
        if self.scope.bundle_id != self.bundle_id:
            raise ValueError("consumer capture is not bound to the bundle")
        if self.supported_schema_version != 1 or not self.supported_semantic_majors:
            raise ValueError("consumer compatibility surface is invalid")


@dataclass(frozen=True)
class TaxonomyPostgresInboxRequest:
    scope: TaxonomyPostgresExecutionScope
    event_id: str
    event_sha256: bytes = field(repr=False)
    source_schema_version: int

    def __post_init__(self) -> None:
        if self.scope.operation is not TaxonomyPostgresOperation.CLAIM_CONSUMER_INBOX:
            raise ValueError("consumer inbox request has the wrong operation")
        _require_identifier(self.event_id, "event_id")
        _require_sha256(self.event_sha256, "event_sha256")
        if self.source_schema_version != 1:
            raise ValueError("consumer inbox schema version is unsupported")


@dataclass(frozen=True)
class TaxonomyPostgresDatabaseResult:
    target_id: str
    target_status: str
    aggregate_version: int
    entity_tag: str
    event_types: Tuple[str, ...]
    replayed: bool
    completed_at: datetime


@dataclass(frozen=True)
class TaxonomyPostgresConsumerRelease:
    bundle_id: str
    semantic_version: str
    status: str
    compatibility_level: str
    aggregate_version: int
    selector_digest: bytes = field(repr=False)
    release_manifest_sha256: bytes = field(repr=False)
    release: TaxonomyReleaseCandidate = field(repr=False)
    captured_at: datetime


class PsycopgTaxonomyUnitOfWorkFactory:
    """Production fixed-program Taxonomy repository and Unit of Work."""

    def __init__(
        self,
        *,
        connections: TaxonomyPostgresConnectionSource,
        event_validator: TaxonomyPostgresSchemaValidator,
        response_validator: TaxonomyPostgresSchemaValidator,
        settings: TaxonomyPostgresSettings = TaxonomyPostgresSettings(),
        fault_injector: TaxonomyPostgresFaultInjector = NoTaxonomyPostgresFaults(),
    ) -> None:
        self._connections = connections
        self._event_validator = event_validator
        self._response_validator = response_validator
        self._settings = settings
        self._fault_injector = fault_injector

    def publish(
        self, request: TaxonomyPostgresPublishRequest
    ) -> TaxonomyPostgresDatabaseResult:
        self._require_request(request, TaxonomyPostgresPublishRequest)
        return self._execute_write(request, self._publish_transaction)

    def retire(
        self, request: TaxonomyPostgresRetireRequest
    ) -> TaxonomyPostgresDatabaseResult:
        self._require_request(request, TaxonomyPostgresRetireRequest)
        return self._execute_write(request, self._retire_transaction)

    def read_exact_bundle(
        self, request: TaxonomyPostgresExactReadRequest
    ) -> Mapping[str, Any]:
        self._require_request(request, TaxonomyPostgresExactReadRequest)
        return self._execute_read(request, self._read_bundle_transaction)

    def read_exact_node(
        self, request: TaxonomyPostgresExactReadRequest
    ) -> Mapping[str, Any]:
        self._require_request(request, TaxonomyPostgresExactReadRequest)
        return self._execute_read(request, self._read_node_transaction)

    def read_exact_edge_pair(
        self, request: TaxonomyPostgresExactReadRequest
    ) -> Tuple[Mapping[str, Any], ...]:
        self._require_request(request, TaxonomyPostgresExactReadRequest)
        return self._execute_read(request, self._read_edge_transaction)

    def capture_consumer_release(
        self, request: TaxonomyPostgresConsumerCaptureRequest
    ) -> TaxonomyPostgresConsumerRelease:
        self._require_request(request, TaxonomyPostgresConsumerCaptureRequest)
        return self._execute_read(request, self._capture_consumer_transaction)

    def claim_consumer_inbox(
        self, request: TaxonomyPostgresInboxRequest
    ) -> TaxonomyPostgresDatabaseResult:
        self._require_request(request, TaxonomyPostgresInboxRequest)
        return self._execute_write(request, self._claim_inbox_transaction)

    @staticmethod
    def _require_request(request: Any, expected: type) -> None:
        if not isinstance(request, expected):
            raise TaxonomyPostgresConfigurationError(
                "TAXONOMY_POSTGRES_REQUEST_INVALID"
            )

    def _execute_write(self, request: Any, program: Any) -> Any:
        connection = None
        transaction_active = False
        commit_sent = False
        expected_role = _ROLE_BY_OPERATION[request.scope.operation]
        try:
            connection = self._connections.checkout()
            self._prepare_connection(connection, expected_role)
            connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED")
            transaction_active = True
            self._set_scope(connection, request.scope)
            self._validate_workload_authority(connection, request.scope)
            result = program(connection, request)
            commit_sent = True
            connection.execute("COMMIT")
            transaction_active = False
            commit_sent = False
            self._reset_and_release(connection, expected_role)
            return result
        except TaxonomyPostgresCommitOutcomeUnknownError:
            raise
        except BaseException as error:
            if connection is None:
                raise
            if commit_sent:
                self._connections.discard(connection)
                raise TaxonomyPostgresCommitOutcomeUnknownError() from None
            if transaction_active:
                try:
                    connection.execute("ROLLBACK")
                    transaction_active = False
                except BaseException:
                    self._connections.discard(connection)
                    raise TaxonomyPostgresDatabaseError(
                        "SERVICE_UNAVAILABLE"
                    ) from None
            try:
                self._reset_and_release(connection, expected_role)
            except BaseException:
                self._connections.discard(connection)
                raise TaxonomyPostgresDatabaseError(
                    "SERVICE_UNAVAILABLE"
                ) from None
            if isinstance(error, TaxonomyPostgresDatabaseError):
                raise
            if isinstance(error, TaxonomyPostgresConfigurationError):
                raise TaxonomyPostgresDatabaseError(
                    "SERVICE_UNAVAILABLE"
                ) from None
            if _is_database_exception(error):
                raise TaxonomyPostgresDatabaseError(
                    "SERVICE_UNAVAILABLE"
                ) from None
            raise

    def _execute_read(self, request: Any, program: Any) -> Any:
        connection = None
        transaction_active = False
        expected_role = _ROLE_BY_OPERATION[request.scope.operation]
        try:
            connection = self._connections.checkout()
            self._prepare_connection(connection, expected_role)
            connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY")
            transaction_active = True
            self._set_scope(connection, request.scope)
            result = program(connection, request)
            connection.execute("COMMIT")
            transaction_active = False
            self._reset_and_release(connection, expected_role)
            return result
        except BaseException as error:
            if connection is None:
                raise
            if transaction_active:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    self._connections.discard(connection)
                    raise TaxonomyPostgresDatabaseError(
                        "SERVICE_UNAVAILABLE"
                    ) from None
            try:
                self._reset_and_release(connection, expected_role)
            except BaseException:
                self._connections.discard(connection)
                raise TaxonomyPostgresDatabaseError(
                    "SERVICE_UNAVAILABLE"
                ) from None
            if isinstance(error, TaxonomyPostgresDatabaseError):
                raise
            if isinstance(error, TaxonomyPostgresConfigurationError):
                raise TaxonomyPostgresDatabaseError(
                    "SERVICE_UNAVAILABLE"
                ) from None
            if _is_database_exception(error):
                raise TaxonomyPostgresDatabaseError(
                    "SERVICE_UNAVAILABLE"
                ) from None
            raise

    def _prepare_connection(self, connection: Any, expected_role: str) -> None:
        row = connection.execute(
            "SELECT session_user,current_user,"
            "current_setting('server_version_num')::integer / 10000,"
            "pg_catalog.to_regnamespace('taxonomy')::text,"
            "(SELECT schema_head_version FROM taxonomy.schema_contracts WHERE singleton_key),"
            "(SELECT min_app_compatible_version FROM taxonomy.schema_contracts WHERE singleton_key),"
            "(SELECT max_app_compatible_version FROM taxonomy.schema_contracts WHERE singleton_key)"
        ).fetchone()
        if row != (
            expected_role,
            expected_role,
            self._settings.required_server_major,
            "taxonomy",
            2,
            2,
            2,
        ):
            raise TaxonomyPostgresConfigurationError(
                "TAXONOMY_POSTGRES_CONNECTION_UNTRUSTED"
            )

    def _set_scope(
        self, connection: Any, scope: TaxonomyPostgresExecutionScope
    ) -> None:
        connection.execute(
            "SELECT "
            "set_config('TimeZone','UTC',true),"
            "set_config('lock_timeout',%s,true),"
            "set_config('statement_timeout',%s,true),"
            "set_config('idle_in_transaction_session_timeout',%s,true),"
            "set_config('app.taxonomy_operation',%s,true),"
            "set_config('app.workload_principal_id',%s,true),"
            "set_config('app.workload_credential_sha256',%s,true),"
            "set_config('app.workload_attestation_sha256',%s,true),"
            "set_config('app.taxonomy_bundle_id',%s,true),"
            "set_config('app.taxonomy_selector_digest',%s,true),"
            "set_config('app.consumer_code',%s,true),"
            "set_config('app.consumer_job_id',%s,true),"
            "set_config('app.consumer_authorization_digest',%s,true)",
            (
                f"{self._settings.lock_timeout_ms}ms",
                f"{self._settings.statement_timeout_ms}ms",
                f"{self._settings.idle_in_transaction_timeout_ms}ms",
                scope.operation.value,
                scope.workload_principal_id,
                hashlib.sha256(
                    scope.workload_credential_id.encode("utf-8")
                ).hexdigest(),
                scope.workload_attestation_sha256.hex(),
                scope.bundle_id or "",
                (scope.selector_digest or b"").hex(),
                scope.consumer_code or "",
                scope.consumer_job_id or "",
                (scope.consumer_authorization_digest or b"").hex(),
            ),
        )

    def _validate_workload_authority(
        self, connection: Any, scope: TaxonomyPostgresExecutionScope
    ) -> None:
        if scope.operation not in (
            TaxonomyPostgresOperation.PUBLISH,
            TaxonomyPostgresOperation.RETIRE,
        ):
            return
        row = connection.execute(
            "SELECT taxonomy_api.lock_workload_authority_v1(%s,%s,%s,%s)",
            (
                scope.workload_principal_id,
                scope.operation.value,
                hashlib.sha256(
                    scope.workload_credential_id.encode("utf-8")
                ).digest(),
                scope.workload_attestation_sha256,
            ),
        ).fetchone()
        if row != (True,):
            raise TaxonomyPostgresDatabaseError("ACCESS_DENIED")

    def _reset_and_release(self, connection: Any, expected_role: str) -> None:
        polluted = connection.execute(
            "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_prepared_statements),"
            "EXISTS(SELECT 1 FROM pg_catalog.pg_class "
            "WHERE relnamespace=pg_catalog.pg_my_temp_schema())"
        ).fetchone()
        if polluted != (False, False):
            raise TaxonomyPostgresConfigurationError(
                "TAXONOMY_POSTGRES_POOL_POLLUTED"
            )
        connection.execute("RESET ROLE")
        connection.execute("RESET ALL")
        connection.execute("DISCARD TEMP")
        row = connection.execute(
            "SELECT session_user,current_user,"
            "current_setting('app.taxonomy_operation',true),"
            "current_setting('app.workload_principal_id',true),"
            "current_setting('app.taxonomy_bundle_id',true),"
            "current_setting('app.consumer_code',true),"
            "current_setting('app.consumer_authorization_digest',true)"
        ).fetchone()
        if (
            row is None
            or row[:2] != (expected_role, expected_role)
            or any(value not in (None, "") for value in row[2:])
        ):
            raise TaxonomyPostgresConfigurationError(
                "TAXONOMY_POSTGRES_RESET_FAILED"
            )
        self._connections.release(connection)

    def _before(
        self,
        checkpoint: TaxonomyPostgresWriteCheckpoint,
        ordinal: list[int],
    ) -> None:
        ordinal[0] += 1
        self._fault_injector.before_write(checkpoint, ordinal[0])

    def _publish_transaction(
        self, connection: Any, request: TaxonomyPostgresPublishRequest
    ) -> TaxonomyPostgresDatabaseResult:
        candidate = request.artifacts.validated_release.candidate
        manifest = candidate.manifest
        now = connection.execute("SELECT transaction_timestamp()").fetchone()[0]
        self._validate_publish_evidence(request, now)
        ordinal = [0]
        self._before(TaxonomyPostgresWriteCheckpoint.RECEIPT_PENDING, ordinal)
        receipt = self._claim_receipt(connection, request)
        if receipt is not None:
            return receipt
        connection.execute(
            "SELECT pg_advisory_xact_lock(pg_catalog.hashtextextended(%s,0))",
            (manifest.selector.selector_digest,),
        )
        current = connection.execute(
            "SELECT bundle_id FROM taxonomy.current_bundles "
            "WHERE selector_digest=%s FOR UPDATE",
            (bytes.fromhex(manifest.selector.selector_digest),),
        ).fetchone()
        current_id = current[0] if current else None
        if current_id != request.expected_current_bundle_id:
            raise TaxonomyPostgresDatabaseError("PRECONDITION_FAILED")

        release_json = _json_value(candidate)
        self._before(TaxonomyPostgresWriteCheckpoint.BUNDLE_INSERT, ordinal)
        connection.execute(
            "INSERT INTO taxonomy.families(family_code,status,created_at) "
            "VALUES(%s,'ACTIVE',%s) ON CONFLICT(family_code) DO NOTHING",
            (manifest.family_code, now),
        )
        connection.execute(
            "INSERT INTO taxonomy.selectors("
            "selector_digest,jurisdiction_code,locale_set_digest,semantic_major,"
            "intended_consumer_set_digest) VALUES(%s,%s,%s,%s,%s) "
            "ON CONFLICT(selector_digest) DO NOTHING",
            (
                bytes.fromhex(manifest.selector.selector_digest),
                manifest.selector.jurisdiction_code,
                bytes.fromhex(manifest.selector.locale_set_digest),
                manifest.selector.semantic_major,
                bytes.fromhex(manifest.selector.intended_consumer_set_digest),
            ),
        )
        connection.execute(
            "INSERT INTO taxonomy.bundles("
            "bundle_id,family_code,semantic_version,selector_digest,"
            "release_manifest_sha256,compatibility_level,status,aggregate_version,"
            "predecessor_bundle_id,successor_bundle_id,effective_at,effective_until,"
            "retired_reason_code,release_json,created_at,updated_at) "
            "VALUES(%s,%s,%s,%s,%s,%s,'ACTIVE',1,%s,NULL,%s,%s,NULL,%s::jsonb,%s,%s)",
            (
                manifest.bundle_id,
                manifest.family_code,
                manifest.semantic_version,
                bytes.fromhex(manifest.selector.selector_digest),
                bytes.fromhex(
                    request.artifacts.validated_release.release_manifest_sha256
                ),
                manifest.compatibility_level.value,
                manifest.predecessor_bundle_id,
                manifest.effective_at,
                manifest.effective_until,
                json.dumps(release_json, ensure_ascii=False, separators=(",", ":")),
                now,
                now,
            ),
        )

        descriptors = {
            (item.artifact_kind, item.locale): item
            for item in manifest.artifacts
        }
        self._before(TaxonomyPostgresWriteCheckpoint.ARTIFACTS_INSERT, ordinal)
        for kind, locale, canonical in request.artifacts.canonical_bytes_by_kind:
            descriptor = descriptors.get((kind, locale))
            if kind == "RELEASE":
                schema_name = "taxonomy-release-v1"
                item_count = 1
                expected_sha = request.artifacts.validated_release.release_manifest_sha256
            elif descriptor is not None:
                schema_name = descriptor.schema_name
                item_count = descriptor.item_count
                expected_sha = descriptor.sha256
            else:
                raise TaxonomyPostgresDatabaseError("ARTIFACT_INVALID")
            if not hmac.compare_digest(hashlib.sha256(canonical).hexdigest(), expected_sha):
                raise TaxonomyPostgresDatabaseError("ARTIFACT_INVALID")
            connection.execute(
                "INSERT INTO taxonomy.release_artifacts("
                "bundle_id,artifact_kind,locale,schema_name,item_count,"
                "artifact_sha256,canonical_bytes) VALUES(%s,%s,%s,%s,%s,%s,%s)",
                (
                    manifest.bundle_id,
                    kind,
                    locale or "",
                    schema_name,
                    item_count,
                    bytes.fromhex(expected_sha),
                    canonical,
                ),
            )
        if set(descriptors) - {
            (kind, locale)
            for kind, locale, _canonical in request.artifacts.canonical_bytes_by_kind
        }:
            raise TaxonomyPostgresDatabaseError("ARTIFACT_INVALID")

        self._before(TaxonomyPostgresWriteCheckpoint.NODES_INSERT, ordinal)
        for node in candidate.nodes.nodes:
            attributes_json = json.dumps(
                _json_value(node.attributes), ensure_ascii=False, separators=(",", ":")
            )
            attributes_sha = hashlib.sha256(
                _canonical_json(_json_value(node.attributes))
            ).digest()
            existing = connection.execute(
                "SELECT kind,definition_code,attributes_sha256 "
                "FROM taxonomy.code_registry WHERE family_code=%s AND code=%s",
                (manifest.family_code, node.code),
            ).fetchone()
            meaning = (node.kind.value, node.definition_code, attributes_sha)
            if existing is not None and (
                existing[0], existing[1], bytes(existing[2])
            ) != meaning:
                raise TaxonomyPostgresDatabaseError("CODE_MEANING_CONFLICT")
            if existing is None:
                connection.execute(
                    "INSERT INTO taxonomy.code_registry("
                    "family_code,code,kind,definition_code,attributes_sha256) "
                    "VALUES(%s,%s,%s,%s,%s)",
                    (
                        manifest.family_code,
                        node.code,
                        node.kind.value,
                        node.definition_code,
                        attributes_sha,
                    ),
                )
            connection.execute(
                "INSERT INTO taxonomy.nodes("
                "bundle_id,code,kind,definition_code,status,introduced_in_bundle_id,"
                "deprecated_reason_code,replacement_codes,attributes) "
                "VALUES(%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb)",
                (
                    manifest.bundle_id,
                    node.code,
                    node.kind.value,
                    node.definition_code,
                    node.status.value,
                    node.introduced_in_bundle_id,
                    node.deprecated_reason_code,
                    json.dumps(list(node.replacement_codes), separators=(",", ":")),
                    attributes_json,
                ),
            )

        self._before(TaxonomyPostgresWriteCheckpoint.EDGES_INSERT, ordinal)
        for edge in candidate.edges.edges:
            connection.execute(
                "INSERT INTO taxonomy.edges("
                "bundle_id,edge_kind,from_code,to_code,ordinal) VALUES(%s,%s,%s,%s,%s)",
                (
                    manifest.bundle_id,
                    edge.edge_kind.value,
                    edge.from_code,
                    edge.to_code,
                    edge.ordinal,
                ),
            )

        self._before(TaxonomyPostgresWriteCheckpoint.LABELS_INSERT, ordinal)
        for labels in candidate.labels:
            for label in labels.labels:
                connection.execute(
                    "INSERT INTO taxonomy.labels("
                    "bundle_id,code,locale,short_label,description,accessibility_label) "
                    "VALUES(%s,%s,%s,%s,%s,%s)",
                    (
                        manifest.bundle_id,
                        label.code,
                        labels.locale,
                        label.short_label,
                        label.description,
                        label.accessibility_label,
                    ),
                )

        self._before(
            TaxonomyPostgresWriteCheckpoint.CROSSWALK_INSERT_OPTIONAL, ordinal
        )
        if candidate.crosswalk is not None:
            crosswalk = candidate.crosswalk
            connection.execute(
                "INSERT INTO taxonomy.crosswalks("
                "crosswalk_id,source_bundle_id,target_bundle_id,compatibility_level,"
                "manifest_sha256,mappings) VALUES(%s,%s,%s,%s,%s,%s::jsonb)",
                (
                    crosswalk.crosswalk_id,
                    crosswalk.source_bundle_id,
                    crosswalk.target_bundle_id,
                    crosswalk.compatibility_level.value,
                    bytes.fromhex(
                        request.artifacts.validated_release.crosswalk_manifest_sha256
                        or ""
                    ),
                    json.dumps(_json_value(crosswalk.mappings), separators=(",", ":")),
                ),
            )

        self._insert_evidence(connection, request)
        self._before(
            TaxonomyPostgresWriteCheckpoint.PREDECESSOR_SUPERSEDE_OPTIONAL,
            ordinal,
        )
        predecessor_event: Optional[Tuple[str, str, int, str, Mapping[str, Any]]] = None
        if manifest.predecessor_bundle_id is not None:
            changed = connection.execute(
                "UPDATE taxonomy.bundles SET status='SUPERSEDED',"
                "successor_bundle_id=%s,aggregate_version=aggregate_version+1,"
                "updated_at=%s WHERE bundle_id=%s AND status='ACTIVE' "
                "AND successor_bundle_id IS NULL RETURNING bundle_id,aggregate_version",
                (manifest.bundle_id, now, manifest.predecessor_bundle_id),
            ).fetchone()
            if changed is None:
                raise TaxonomyPostgresDatabaseError("PRECONDITION_FAILED")
            predecessor_event = (
                "TaxonomyBundleSuperseded",
                changed[0],
                int(changed[1]),
                "TaxonomyBundle",
                {
                    "bundle_id": changed[0],
                    "successor_bundle_id": manifest.bundle_id,
                    "status": "SUPERSEDED",
                },
            )

        self._before(TaxonomyPostgresWriteCheckpoint.CURRENT_ADVANCE, ordinal)
        connection.execute(
            "INSERT INTO taxonomy.current_bundles("
            "selector_digest,bundle_id,pointer_version,updated_at) "
            "VALUES(%s,%s,1,%s) ON CONFLICT(selector_digest) DO UPDATE SET "
            "bundle_id=excluded.bundle_id,pointer_version=taxonomy.current_bundles.pointer_version+1,"
            "updated_at=excluded.updated_at",
            (
                bytes.fromhex(manifest.selector.selector_digest),
                manifest.bundle_id,
                now,
            ),
        )
        publish_events: list[
            Tuple[str, str, int, str, Mapping[str, Any]]
        ] = [
            (
                "TaxonomyBundlePublished",
                manifest.bundle_id,
                1,
                "TaxonomyBundle",
                {
                    "bundle_id": manifest.bundle_id,
                    "family_code": manifest.family_code,
                    "semantic_version": manifest.semantic_version,
                    "selector_digest": manifest.selector.selector_digest,
                    "release_manifest_sha256": request.artifacts.validated_release.release_manifest_sha256,
                    "effective_at": _timestamp(manifest.effective_at),
                    "status": "ACTIVE",
                },
            )
        ]
        if predecessor_event is not None:
            publish_events.append(predecessor_event)
        if candidate.crosswalk is not None:
            publish_events.append(
                (
                    "TaxonomyCrosswalkPublished",
                    candidate.crosswalk.crosswalk_id,
                    1,
                    "TaxonomyCrosswalk",
                    {
                        "crosswalk_id": candidate.crosswalk.crosswalk_id,
                        "source_bundle_id": candidate.crosswalk.source_bundle_id,
                        "target_bundle_id": candidate.crosswalk.target_bundle_id,
                        "manifest_sha256": request.artifacts.validated_release.crosswalk_manifest_sha256,
                    },
                )
            )
        result = self._finish_command(
            connection,
            request,
            ordinal,
            target_id=manifest.bundle_id,
            target_status="ACTIVE",
            target_version=1,
            events=tuple(publish_events),
            now=now,
        )
        return result

    def _validate_publish_evidence(
        self, request: TaxonomyPostgresPublishRequest, now: datetime
    ) -> None:
        signature = request.signature
        trust = request.trust
        if (
            trust.trust_status != "ACTIVE"
            or signature.algorithm != trust.allowed_algorithm
            or signature.valid_until <= now
            or trust.valid_until <= now
            or signature.verified_at > now
        ):
            raise TaxonomyPostgresDatabaseError("SIGNATURE_INVALID")
        if any(
            item.approval_status != "APPROVED"
            or item.valid_until <= now
            or item.approved_at > now
            for item in request.approvals
        ):
            raise TaxonomyPostgresDatabaseError("REVIEW_APPROVAL_REQUIRED")

    def _insert_evidence(
        self, connection: Any, request: TaxonomyPostgresPublishRequest
    ) -> None:
        signature = request.signature
        trust = request.trust
        connection.execute(
            "INSERT INTO taxonomy.signature_evidence("
            "signature_receipt_id,trust_record_id,signing_key_id,algorithm,"
            "release_manifest_sha256,verified_at,valid_until) VALUES(%s,%s,%s,%s,%s,%s,%s)",
            (
                signature.signature_receipt_id,
                signature.trust_record_id,
                signature.signing_key_id,
                signature.algorithm,
                signature.release_manifest_sha256,
                signature.verified_at,
                signature.valid_until,
            ),
        )
        connection.execute(
            "INSERT INTO taxonomy.trust_evidence("
            "trust_record_id,signing_key_id,trust_status,algorithm,"
            "release_manifest_sha256,valid_until) VALUES(%s,%s,%s,%s,%s,%s)",
            (
                trust.trust_record_id,
                trust.signing_key_id,
                trust.trust_status,
                trust.allowed_algorithm,
                trust.release_manifest_sha256,
                trust.valid_until,
            ),
        )
        for approval in request.approvals:
            connection.execute(
                "INSERT INTO taxonomy.review_approvals("
                "approval_id,duty_code,reviewer_id,approval_status,"
                "release_manifest_sha256,golden_result_sha256,approved_at,valid_until) "
                "VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
                (
                    approval.approval_id,
                    approval.duty_code,
                    approval.reviewer_id,
                    approval.approval_status,
                    approval.release_manifest_sha256,
                    approval.golden_result_sha256,
                    approval.approved_at,
                    approval.valid_until,
                ),
            )

    def _claim_receipt(
        self, connection: Any, request: Any
    ) -> Optional[TaxonomyPostgresDatabaseResult]:
        receipt = request.receipt
        scope = request.scope
        connection.execute(
            "SELECT set_config('app.taxonomy_receipt_identity_digest',%s,true)",
            (receipt.identity_digest.hex(),),
        )
        now = connection.execute("SELECT transaction_timestamp()").fetchone()[0]
        connection.execute(
            "INSERT INTO taxonomy.command_receipts("
            "identity_digest,identity_key_id,payload_hash_key_id,payload_digest,"
            "principal_id,operation,canonicalization_version,command_version,status,"
            "retained_until,created_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,'PENDING',%s,%s) "
            "ON CONFLICT(identity_digest) DO NOTHING",
            (
                receipt.identity_digest,
                receipt.identity_key_id,
                receipt.payload_hash_key_id,
                receipt.payload_digest,
                scope.workload_principal_id,
                scope.operation.value,
                receipt.canonicalization_version,
                receipt.command_version,
                receipt.retained_until,
                now,
            ),
        )
        row = connection.execute(
            "SELECT payload_digest,principal_id,operation,canonicalization_version,"
            "command_version,status,target_id,target_status,target_version,safe_response,"
            "completed_at FROM taxonomy.command_receipts "
            "WHERE identity_digest=%s FOR UPDATE",
            (receipt.identity_digest,),
        ).fetchone()
        if row is None:
            raise TaxonomyPostgresDatabaseError("SERVICE_UNAVAILABLE")
        if (
            not hmac.compare_digest(bytes(row[0]), receipt.payload_digest)
            or row[1] != scope.workload_principal_id
            or row[2] != scope.operation.value
            or row[3] != receipt.canonicalization_version
            or int(row[4]) != receipt.command_version
        ):
            raise TaxonomyPostgresDatabaseError("IDEMPOTENCY_KEY_REUSED")
        if row[5] != "COMPLETED":
            return None
        safe = row[9]
        if not isinstance(safe, Mapping) or set(safe) != {
            "target_id", "target_status", "aggregate_version", "entity_tag"
        }:
            raise TaxonomyPostgresDatabaseError("SERVICE_UNAVAILABLE")
        if (
            safe["target_id"] != row[6]
            or safe["target_status"] != row[7]
            or safe["aggregate_version"] != row[8]
            or safe["entity_tag"] != f'"v{row[8]}"'
        ):
            raise TaxonomyPostgresDatabaseError("SERVICE_UNAVAILABLE")
        self._response_validator.validate(safe, "TaxonomyCommandResponse")
        return TaxonomyPostgresDatabaseResult(
            target_id=row[6],
            target_status=row[7],
            aggregate_version=int(row[8]),
            entity_tag=safe["entity_tag"],
            event_types=(),
            replayed=True,
            completed_at=row[10],
        )

    def _finish_command(
        self,
        connection: Any,
        request: Any,
        ordinal: list[int],
        *,
        target_id: str,
        target_status: str,
        target_version: int,
        events: Tuple[
            Tuple[str, str, int, str, Mapping[str, Any]], ...
        ],
        now: datetime,
    ) -> TaxonomyPostgresDatabaseResult:
        safe = {
            "target_id": target_id,
            "target_status": target_status,
            "aggregate_version": target_version,
            "entity_tag": f'"v{target_version}"',
        }
        self._response_validator.validate(safe, "TaxonomyCommandResponse")
        envelopes = []
        for event_type, aggregate_id, aggregate_version, aggregate_type, payload in events:
            event_id = _derived_id(
                "taxonomy_event",
                hashlib.sha256(
                    request.receipt.identity_digest
                    + event_type.encode("ascii")
                    + aggregate_id.encode("utf-8")
                ).digest(),
            )
            envelope = {
                "event_id": event_id,
                "event_type": event_type,
                "schema_version": 1,
                "occurred_at": _timestamp(now),
                "aggregate_type": aggregate_type,
                "aggregate_id": aggregate_id,
                "aggregate_version": aggregate_version,
                "actor_kind": "SYSTEM",
                "actor_id": request.scope.workload_principal_id,
                "original_actor_id": None,
                "correlation_id": request.scope.correlation_id,
                "causation_id": request.scope.causation_id,
                "trace_id": request.scope.trace_id,
                "organization_id": None,
                "payload": dict(payload),
            }
            self._event_validator.validate(envelope, event_type + "Event")
            envelopes.append((event_id, event_type, aggregate_id, aggregate_version, envelope))
        self._before(TaxonomyPostgresWriteCheckpoint.AUDIT_APPEND, ordinal)
        connection.execute(
            "INSERT INTO taxonomy.audit_log("
            "audit_id,operation,actor_id,target_id,result,evidence_sha256,"
            "correlation_id,causation_id,trace_id,occurred_at) "
            "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                _derived_id("taxonomy_audit", request.receipt.identity_digest),
                request.scope.operation.value,
                request.scope.workload_principal_id,
                target_id,
                target_status,
                request.receipt.payload_digest,
                request.scope.correlation_id,
                request.scope.causation_id,
                request.scope.trace_id,
                now,
            ),
        )
        self._before(TaxonomyPostgresWriteCheckpoint.OUTBOX_APPEND, ordinal)
        for event_id, event_type, aggregate_id, aggregate_version, envelope in envelopes:
            connection.execute(
                "INSERT INTO taxonomy.outbox_events("
                "event_id,aggregate_id,aggregate_version,event_type,envelope,occurred_at) "
                "VALUES(%s,%s,%s,%s,%s::jsonb,%s)",
                (
                    event_id,
                    aggregate_id,
                    aggregate_version,
                    event_type,
                    json.dumps(envelope, ensure_ascii=False, separators=(",", ":")),
                    now,
                ),
            )
        self._before(TaxonomyPostgresWriteCheckpoint.RECEIPT_COMPLETE, ordinal)
        completed = connection.execute(
            "UPDATE taxonomy.command_receipts SET status='COMPLETED',target_id=%s,"
            "target_status=%s,target_version=%s,safe_response=%s::jsonb,completed_at=%s "
            "WHERE identity_digest=%s AND status='PENDING' RETURNING completed_at",
            (
                target_id,
                target_status,
                target_version,
                json.dumps(safe, separators=(",", ":")),
                now,
                request.receipt.identity_digest,
            ),
        ).fetchone()
        if completed is None:
            raise TaxonomyPostgresDatabaseError("SERVICE_UNAVAILABLE")
        self._before(TaxonomyPostgresWriteCheckpoint.COMMIT, ordinal)
        return TaxonomyPostgresDatabaseResult(
            target_id=target_id,
            target_status=target_status,
            aggregate_version=target_version,
            entity_tag=safe["entity_tag"],
            event_types=tuple(item[0] for item in events),
            replayed=False,
            completed_at=completed[0],
        )

    def _retire_transaction(
        self, connection: Any, request: TaxonomyPostgresRetireRequest
    ) -> TaxonomyPostgresDatabaseResult:
        ordinal = [0]
        self._before(TaxonomyPostgresWriteCheckpoint.RECEIPT_PENDING, ordinal)
        replay = self._claim_receipt(connection, request)
        if replay is not None:
            return replay
        connection.execute(
            "SELECT pg_advisory_xact_lock(pg_catalog.hashtextextended(%s,0))",
            (request.bundle_id,),
        )
        row = connection.execute(
            "SELECT selector_digest,status,aggregate_version FROM taxonomy.bundles "
            "WHERE bundle_id=%s FOR UPDATE",
            (request.bundle_id,),
        ).fetchone()
        if row is None:
            raise TaxonomyPostgresDatabaseError("RESOURCE_NOT_FOUND")
        if row[1] not in ("ACTIVE", "SUPERSEDED"):
            raise TaxonomyPostgresDatabaseError("TERMINAL_STATE")
        if int(row[2]) != request.expected_bundle_version:
            raise TaxonomyPostgresDatabaseError("PRECONDITION_FAILED")
        now = connection.execute("SELECT transaction_timestamp()").fetchone()[0]
        self._before(TaxonomyPostgresWriteCheckpoint.BUNDLE_RETIRE, ordinal)
        updated = connection.execute(
            "UPDATE taxonomy.bundles SET status='RETIRED',"
            "retired_reason_code=%s,aggregate_version=aggregate_version+1,updated_at=%s "
            "WHERE bundle_id=%s AND aggregate_version=%s "
            "RETURNING aggregate_version",
            (
                request.reason_code,
                now,
                request.bundle_id,
                request.expected_bundle_version,
            ),
        ).fetchone()
        if updated is None:
            raise TaxonomyPostgresDatabaseError("PRECONDITION_FAILED")
        self._before(
            TaxonomyPostgresWriteCheckpoint.CURRENT_CLEAR_IF_CURRENT, ordinal
        )
        connection.execute(
            "DELETE FROM taxonomy.current_bundles "
            "WHERE selector_digest=%s AND bundle_id=%s",
            (row[0], request.bundle_id),
        )
        return self._finish_command(
            connection,
            request,
            ordinal,
            target_id=request.bundle_id,
            target_status="RETIRED",
            target_version=int(updated[0]),
            events=(
                (
                    "TaxonomyBundleRetired",
                    request.bundle_id,
                    int(updated[0]),
                    "TaxonomyBundle",
                    {
                        "bundle_id": request.bundle_id,
                        "status": "RETIRED",
                        "reason_code": request.reason_code,
                    },
                ),
            ),
            now=now,
        )

    def _read_bundle_transaction(
        self, connection: Any, request: TaxonomyPostgresExactReadRequest
    ) -> Mapping[str, Any]:
        row = connection.execute(
            "SELECT bundle_id,family_code,semantic_version,status,aggregate_version,"
            "encode(selector_digest,'hex'),encode(release_manifest_sha256,'hex') "
            "FROM taxonomy.bundles WHERE bundle_id=%s",
            (request.bundle_id,),
        ).fetchone()
        if row is None:
            raise TaxonomyPostgresDatabaseError("RESOURCE_NOT_FOUND")
        return MappingProxyType(
            {
                "bundle_id": row[0],
                "family_code": row[1],
                "semantic_version": row[2],
                "status": row[3],
                "aggregate_version": int(row[4]),
                "selector_digest": row[5],
                "release_manifest_sha256": row[6],
            }
        )

    def _read_node_transaction(
        self, connection: Any, request: TaxonomyPostgresExactReadRequest
    ) -> Mapping[str, Any]:
        row = connection.execute(
            "SELECT n.code,n.kind,n.definition_code,n.status,n.replacement_codes,"
            "n.attributes,l.short_label,l.description,l.accessibility_label "
            "FROM taxonomy.nodes n JOIN taxonomy.labels l "
            "ON l.bundle_id=n.bundle_id AND l.code=n.code "
            "WHERE n.bundle_id=%s AND n.code=%s AND l.locale=%s",
            (request.bundle_id, request.code, request.locale),
        ).fetchone()
        if row is None:
            raise TaxonomyPostgresDatabaseError("RESOURCE_NOT_FOUND")
        return MappingProxyType(
            {
                "code": row[0],
                "kind": row[1],
                "definition_code": row[2],
                "status": row[3],
                "replacement_codes": tuple(row[4]),
                "attributes": tuple(row[5]),
                "label": {
                    "locale": request.locale,
                    "short_label": row[6],
                    "description": row[7],
                    "accessibility_label": row[8],
                },
            }
        )

    def _read_edge_transaction(
        self, connection: Any, request: TaxonomyPostgresExactReadRequest
    ) -> Tuple[Mapping[str, Any], ...]:
        rows = connection.execute(
            "SELECT edge_kind,from_code,to_code,ordinal FROM taxonomy.edges "
            "WHERE bundle_id=%s AND ((from_code=%s AND to_code=%s) "
            "OR (from_code=%s AND to_code=%s)) "
            "ORDER BY edge_kind,from_code,to_code,ordinal",
            (
                request.bundle_id,
                request.code,
                request.to_code,
                request.to_code,
                request.code,
            ),
        ).fetchall()
        if not rows:
            raise TaxonomyPostgresDatabaseError("RESOURCE_NOT_FOUND")
        return tuple(
            MappingProxyType(
                {
                    "edge_kind": row[0],
                    "from_code": row[1],
                    "to_code": row[2],
                    "ordinal": int(row[3]),
                }
            )
            for row in rows
        )

    def _capture_consumer_transaction(
        self, connection: Any, request: TaxonomyPostgresConsumerCaptureRequest
    ) -> TaxonomyPostgresConsumerRelease:
        authorization = connection.execute(
            "SELECT bundle_id,release_manifest_sha256,valid_until "
            "FROM taxonomy.consumer_authorizations "
            "WHERE authorization_digest=%s AND consumer_code=%s "
            "AND consumer_job_id=%s AND workload_principal_id=%s",
            (
                request.scope.consumer_authorization_digest,
                request.scope.consumer_code,
                request.scope.consumer_job_id,
                request.scope.workload_principal_id,
            ),
        ).fetchone()
        if authorization is None:
            raise TaxonomyPostgresDatabaseError("ACCESS_DENIED")
        now = connection.execute("SELECT transaction_timestamp()").fetchone()[0]
        if (
            authorization[0] != request.bundle_id
            or not hmac.compare_digest(bytes(authorization[1]), request.release_manifest_sha256)
            or authorization[2] <= now
        ):
            raise TaxonomyPostgresDatabaseError("ACCESS_DENIED")
        row = connection.execute(
            "SELECT family_code,semantic_version,status,compatibility_level,"
            "aggregate_version,selector_digest,release_manifest_sha256,release_json,"
            "effective_at,effective_until "
            "FROM taxonomy.bundles WHERE bundle_id=%s",
            (request.bundle_id,),
        ).fetchone()
        if row is None:
            raise TaxonomyPostgresDatabaseError("RESOURCE_NOT_FOUND")
        if row[0] != request.supported_family_code or not hmac.compare_digest(
            bytes(row[6]), request.release_manifest_sha256
        ):
            raise TaxonomyPostgresDatabaseError("SERVICE_UNAVAILABLE")
        if row[8] > now or (row[9] is not None and now >= row[9]):
            raise TaxonomyPostgresDatabaseError("RESOURCE_NOT_FOUND")
        try:
            major = int(str(row[1]).split(".", 1)[0])
        except (TypeError, ValueError):
            raise TaxonomyPostgresDatabaseError("SERVICE_UNAVAILABLE") from None
        if major not in request.supported_semantic_majors:
            raise TaxonomyPostgresDatabaseError(
                "TAXONOMY_COMPATIBILITY_REJECTED"
            )
        release = _candidate_from_json(row[7])
        if (
            _json_value(release) != row[7]
            or release.manifest.schema_version != request.supported_schema_version
            or release.manifest.bundle_id != request.bundle_id
            or release.manifest.family_code != row[0]
            or release.manifest.semantic_version != row[1]
            or release.manifest.selector.selector_digest != bytes(row[5]).hex()
            or not hmac.compare_digest(
                hashlib.sha256(
                    _canonical_json(_json_value(release.manifest))
                ).digest(),
                bytes(row[6]),
            )
            or len(release.nodes.nodes) > self._settings.maximum_consumer_nodes
        ):
            raise TaxonomyPostgresDatabaseError("SERVICE_UNAVAILABLE")
        self._validate_consumer_graph(connection, request, release)
        return TaxonomyPostgresConsumerRelease(
            bundle_id=request.bundle_id,
            semantic_version=row[1],
            status=row[2],
            compatibility_level=row[3],
            aggregate_version=int(row[4]),
            selector_digest=bytes(row[5]),
            release_manifest_sha256=bytes(row[6]),
            release=release,
            captured_at=now,
        )

    def _validate_consumer_graph(
        self,
        connection: Any,
        request: TaxonomyPostgresConsumerCaptureRequest,
        release: TaxonomyReleaseCandidate,
    ) -> None:
        descriptors = {
            (item.artifact_kind, item.locale or ""): item
            for item in release.manifest.artifacts
        }
        artifact_values: dict[Tuple[str, str], Any] = {
            ("RELEASE", ""): release.manifest,
            ("NODES", ""): release.nodes,
            ("EDGES", ""): release.edges,
        }
        artifact_values.update(
            {("LABELS", item.locale): item for item in release.labels}
        )
        if release.crosswalk is not None:
            artifact_values[("CROSSWALK", "")] = release.crosswalk
        rows = connection.execute(
            "SELECT artifact_kind,locale,schema_name,item_count,artifact_sha256,"
            "canonical_bytes FROM taxonomy.release_artifacts "
            "WHERE bundle_id=%s ORDER BY artifact_kind,locale",
            (request.bundle_id,),
        ).fetchall()
        if len(rows) != len(artifact_values):
            raise TaxonomyPostgresDatabaseError("SERVICE_UNAVAILABLE")
        for kind, locale, schema_name, item_count, digest, canonical in rows:
            value = artifact_values.get((kind, locale))
            descriptor = descriptors.get((kind, locale))
            if value is None:
                raise TaxonomyPostgresDatabaseError("SERVICE_UNAVAILABLE")
            expected_bytes = _canonical_json(_json_value(value))
            if kind == "RELEASE":
                expected_schema = "taxonomy-release-v1"
                expected_count = 1
                expected_digest = request.release_manifest_sha256
            elif descriptor is not None:
                expected_schema = descriptor.schema_name
                expected_count = descriptor.item_count
                expected_digest = bytes.fromhex(descriptor.sha256)
            else:
                raise TaxonomyPostgresDatabaseError("SERVICE_UNAVAILABLE")
            if (
                schema_name != expected_schema
                or int(item_count) != expected_count
                or not hmac.compare_digest(bytes(digest), expected_digest)
                or not hmac.compare_digest(bytes(canonical), expected_bytes)
                or not hmac.compare_digest(
                    hashlib.sha256(bytes(canonical)).digest(), bytes(digest)
                )
            ):
                raise TaxonomyPostgresDatabaseError("SERVICE_UNAVAILABLE")

        node_rows = tuple(
            connection.execute(
                "SELECT code,kind,definition_code,status,introduced_in_bundle_id,"
                "deprecated_reason_code,replacement_codes,attributes "
                "FROM taxonomy.nodes WHERE bundle_id=%s ORDER BY kind,code",
                (request.bundle_id,),
            ).fetchall()
        )
        expected_nodes = tuple(
            (
                item.code,
                item.kind.value,
                item.definition_code,
                item.status.value,
                item.introduced_in_bundle_id,
                item.deprecated_reason_code,
                list(item.replacement_codes),
                _json_value(item.attributes),
            )
            for item in release.nodes.nodes
        )
        edge_rows = tuple(
            connection.execute(
                "SELECT edge_kind,from_code,to_code,ordinal FROM taxonomy.edges "
                "WHERE bundle_id=%s ORDER BY edge_kind,from_code,to_code,ordinal",
                (request.bundle_id,),
            ).fetchall()
        )
        expected_edges = tuple(
            (
                item.edge_kind.value,
                item.from_code,
                item.to_code,
                item.ordinal,
            )
            for item in release.edges.edges
        )
        label_rows = tuple(
            connection.execute(
                "SELECT locale,code,short_label,description,accessibility_label "
                "FROM taxonomy.labels WHERE bundle_id=%s ORDER BY locale,code",
                (request.bundle_id,),
            ).fetchall()
        )
        expected_labels = tuple(
            (
                labels.locale,
                item.code,
                item.short_label,
                item.description,
                item.accessibility_label,
            )
            for labels in release.labels
            for item in labels.labels
        )
        crosswalk_rows = tuple(
            connection.execute(
                "SELECT crosswalk_id,source_bundle_id,target_bundle_id,"
                "compatibility_level,manifest_sha256,mappings "
                "FROM taxonomy.crosswalks WHERE source_bundle_id=%s OR target_bundle_id=%s "
                "ORDER BY crosswalk_id",
                (request.bundle_id, request.bundle_id),
            ).fetchall()
        )
        expected_crosswalks: Tuple[Tuple[Any, ...], ...] = ()
        if release.crosswalk is not None:
            expected_crosswalks = (
                (
                    release.crosswalk.crosswalk_id,
                    release.crosswalk.source_bundle_id,
                    release.crosswalk.target_bundle_id,
                    release.crosswalk.compatibility_level.value,
                    bytes.fromhex(
                        descriptors[("CROSSWALK", "")].sha256
                    ),
                    _json_value(release.crosswalk.mappings),
                ),
            )
        normalized_crosswalk_rows = tuple(
            (*row[:4], bytes(row[4]), row[5]) for row in crosswalk_rows
        )
        if (
            node_rows != expected_nodes
            or edge_rows != expected_edges
            or label_rows != expected_labels
            or normalized_crosswalk_rows != expected_crosswalks
        ):
            raise TaxonomyPostgresDatabaseError("SERVICE_UNAVAILABLE")

    def _claim_inbox_transaction(
        self, connection: Any, request: TaxonomyPostgresInboxRequest
    ) -> TaxonomyPostgresDatabaseResult:
        now = connection.execute("SELECT transaction_timestamp()").fetchone()[0]
        connection.execute(
            "INSERT INTO taxonomy.consumer_inbox("
            "event_id,event_sha256,consumer_code,status,received_at) "
            "VALUES(%s,%s,%s,'PENDING',%s) ON CONFLICT(event_id) DO NOTHING",
            (
                request.event_id,
                request.event_sha256,
                request.scope.consumer_code,
                now,
            ),
        )
        row = connection.execute(
            "SELECT event_sha256,consumer_code,status,safe_response,completed_at "
            "FROM taxonomy.consumer_inbox WHERE event_id=%s FOR UPDATE",
            (request.event_id,),
        ).fetchone()
        if row is None or not hmac.compare_digest(
            bytes(row[0]), request.event_sha256
        ) or row[1] != request.scope.consumer_code:
            raise TaxonomyPostgresDatabaseError("IDEMPOTENCY_KEY_REUSED")
        if row[2] == "COMPLETED":
            safe = row[3]
            if not isinstance(safe, Mapping) or set(safe) != {
                "target_id", "target_status", "aggregate_version", "entity_tag"
            }:
                raise TaxonomyPostgresDatabaseError("SERVICE_UNAVAILABLE")
            return TaxonomyPostgresDatabaseResult(
                target_id=safe["target_id"],
                target_status=safe["target_status"],
                aggregate_version=int(safe["aggregate_version"]),
                entity_tag=safe["entity_tag"],
                event_types=(),
                replayed=True,
                completed_at=row[4],
            )
        safe = {
            "target_id": request.event_id,
            "target_status": "COMPLETED",
            "aggregate_version": 1,
            "entity_tag": '"v1"',
        }
        completed = connection.execute(
            "UPDATE taxonomy.consumer_inbox SET status='COMPLETED',"
            "safe_response=%s::jsonb,completed_at=%s "
            "WHERE event_id=%s AND status='PENDING' RETURNING completed_at",
            (json.dumps(safe, separators=(",", ":")), now, request.event_id),
        ).fetchone()
        if completed is None:
            raise TaxonomyPostgresDatabaseError("SERVICE_UNAVAILABLE")
        return TaxonomyPostgresDatabaseResult(
            target_id=request.event_id,
            target_status="COMPLETED",
            aggregate_version=1,
            entity_tag='"v1"',
            event_types=(),
            replayed=False,
            completed_at=completed[0],
        )


def _is_database_exception(error: BaseException) -> bool:
    module = type(error).__module__
    return module == "psycopg" or module.startswith("psycopg.")


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _derived_id(prefix: str, digest: bytes) -> str:
    return f"{prefix}_{hashlib.sha256(prefix.encode('ascii') + digest).hexdigest()[:32]}"


def _json_value(value: Any) -> Any:
    if is_dataclass(value):
        return {key: _json_value(child) for key, child in asdict(value).items()}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return _timestamp(value)
    if isinstance(value, tuple):
        return [_json_value(child) for child in value]
    if isinstance(value, Mapping):
        return {str(key): _json_value(child) for key, child in value.items()}
    return value


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _candidate_from_json(value: Mapping[str, Any]) -> TaxonomyReleaseCandidate:
    try:
        manifest_value = value["manifest"]
        selector_value = manifest_value["selector"]
        selector = TaxonomySelector(
            jurisdiction_code=selector_value["jurisdiction_code"],
            locale_set_digest=selector_value["locale_set_digest"],
            semantic_major=int(selector_value["semantic_major"]),
            intended_consumer_set_digest=selector_value[
                "intended_consumer_set_digest"
            ],
            selector_digest=selector_value["selector_digest"],
        )
        descriptors = tuple(
            TaxonomyArtifactDescriptor(
                artifact_kind=item["artifact_kind"],
                schema_name=item["schema_name"],
                locale=item.get("locale"),
                sha256=item["sha256"],
                item_count=int(item["item_count"]),
            )
            for item in manifest_value["artifacts"]
        )
        manifest = TaxonomyReleaseManifest(
            schema_version=int(manifest_value["schema_version"]),
            canonicalization_version=manifest_value["canonicalization_version"],
            bundle_id=manifest_value["bundle_id"],
            family_code=manifest_value["family_code"],
            semantic_version=manifest_value["semantic_version"],
            selector=selector,
            compatibility_level=TaxonomyCompatibilityLevel(
                manifest_value["compatibility_level"]
            ),
            predecessor_bundle_id=manifest_value.get("predecessor_bundle_id"),
            effective_at=_parse_timestamp(manifest_value["effective_at"]),
            effective_until=(
                _parse_timestamp(manifest_value["effective_until"])
                if manifest_value.get("effective_until") is not None
                else None
            ),
            artifacts=descriptors,
        )
        nodes_value = value["nodes"]
        nodes = TaxonomyNodesArtifact(
            schema_version=int(nodes_value["schema_version"]),
            canonicalization_version=nodes_value["canonicalization_version"],
            bundle_id=nodes_value["bundle_id"],
            family_code=nodes_value["family_code"],
            nodes=tuple(
                TaxonomyNode(
                    code=item["code"],
                    kind=TaxonomyNodeKind(item["kind"]),
                    definition_code=item["definition_code"],
                    status=TaxonomyNodeStatus(item["status"]),
                    introduced_in_bundle_id=item["introduced_in_bundle_id"],
                    deprecated_reason_code=item.get("deprecated_reason_code"),
                    replacement_codes=tuple(item["replacement_codes"]),
                    attributes=tuple(
                        TaxonomyAttribute(
                            key=attribute["key"],
                            value_kind=attribute["value_kind"],
                            code_value=attribute.get("code_value"),
                            integer_value=attribute.get("integer_value"),
                        )
                        for attribute in item["attributes"]
                    ),
                )
                for item in nodes_value["nodes"]
            ),
        )
        edges_value = value["edges"]
        edges = TaxonomyEdgesArtifact(
            schema_version=int(edges_value["schema_version"]),
            canonicalization_version=edges_value["canonicalization_version"],
            bundle_id=edges_value["bundle_id"],
            family_code=edges_value["family_code"],
            edges=tuple(
                TaxonomyEdge(
                    TaxonomyEdgeKind(item["edge_kind"]),
                    item["from_code"],
                    item["to_code"],
                    int(item["ordinal"]),
                )
                for item in edges_value["edges"]
            ),
        )
        labels = tuple(
            TaxonomyLabelsArtifact(
                schema_version=int(item["schema_version"]),
                canonicalization_version=item["canonicalization_version"],
                bundle_id=item["bundle_id"],
                family_code=item["family_code"],
                locale=item["locale"],
                labels=tuple(
                    TaxonomyLabel(
                        code=label["code"],
                        short_label=label["short_label"],
                        description=label.get("description"),
                        accessibility_label=label.get("accessibility_label"),
                    )
                    for label in item["labels"]
                ),
            )
            for item in value["labels"]
        )
        crosswalk_value = value.get("crosswalk")
        crosswalk = None
        if crosswalk_value is not None:
            crosswalk = TaxonomyCrosswalkArtifact(
                schema_version=int(crosswalk_value["schema_version"]),
                canonicalization_version=crosswalk_value[
                    "canonicalization_version"
                ],
                crosswalk_id=crosswalk_value["crosswalk_id"],
                source_bundle_id=crosswalk_value["source_bundle_id"],
                target_bundle_id=crosswalk_value["target_bundle_id"],
                compatibility_level=TaxonomyCompatibilityLevel(
                    crosswalk_value["compatibility_level"]
                ),
                mappings=tuple(
                    TaxonomyCrosswalkMapping(
                        source_code=item["source_code"],
                        target_codes=tuple(item["target_codes"]),
                        mapping_kind=TaxonomyMappingKind(item["mapping_kind"]),
                        confidence_code=item["confidence_code"],
                        review_reason_code=item["review_reason_code"],
                    )
                    for item in crosswalk_value["mappings"]
                ),
            )
        return TaxonomyReleaseCandidate(manifest, nodes, edges, labels, crosswalk)
    except (KeyError, TypeError, ValueError) as error:
        raise TaxonomyPostgresDatabaseError("SERVICE_UNAVAILABLE") from error
