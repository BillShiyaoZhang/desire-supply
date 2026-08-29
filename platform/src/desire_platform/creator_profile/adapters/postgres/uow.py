"""Role-bound PostgreSQL 18 fixed UoWs for Creator Profile.

The module owns immutable database requests, closed statement profiles,
logical write checkpoints, explicit pool disposition, COMMIT_SENT handling,
and the immutable exact MatchRun input capture.  It has no Memory, owner,
BYPASSRLS, generic-query, or test-mode fallback.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import hmac
import json
import re
from types import MappingProxyType
from typing import Any, Callable, Mapping, Optional, Protocol, Tuple
from uuid import UUID

from desire_platform.creator_profile.domain import (
    ProfileContent,
    canonical_profile_version_bytes,
    freeze_profile_content,
)


PROFILE_POSTGRES_BEHAVIOR_NOT_AVAILABLE = (
    "PROFILE_POSTGRES_BEHAVIOR_NOT_AVAILABLE"
)
PROFILE_POSTGRES_SCHEMA_HEAD_VERSION = 5


class CreatorProfilePostgresBehaviorNotAvailable(RuntimeError):
    """Stable semantic-RED sentinel for the absent fixed PostgreSQL programs."""


class CreatorProfilePostgresConfigurationError(RuntimeError):
    """Role, server, transaction, catalog, or reset state is not trustworthy."""


class CreatorProfilePostgresDatabaseError(RuntimeError):
    """Closed semantic rejection returned by a future fixed SQL program."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class CreatorProfilePostgresCommitOutcomeUnknownError(RuntimeError):
    """COMMIT was sent, so the current call cannot infer its outcome."""

    code = "COMMAND_OUTCOME_UNKNOWN"


class CreatorProfilePostgresOperation(str, Enum):
    CREATE = "CreateCreatorProfile"
    SAVE_DRAFT = "SaveCreatorProfileDraft"
    PUBLISH = "PublishCreatorProfileVersion"
    PAUSE = "PauseCreatorProfile"
    RESUME = "ResumeCreatorProfile"
    ARCHIVE = "ArchiveCreatorProfile"
    CAPTURE_MATCH_INPUTS = "CaptureCreatorProfileMatchInputs"
    CAPTURE_DERIVED_MATCH_INPUTS = "CaptureDerivedCreatorProfileMatchInputs"


class CreatorProfilePostgresWriteCheckpoint(str, Enum):
    RECEIPT_PENDING = "receipt.pending"
    PROFILE_VERSION_DRAFT = "profile_version.draft"
    PROFILE_VERSION_DISCARDED = "profile_version.discarded"
    PROFILE_VERSION_PUBLISHED = "profile_version.published"
    PROFILE_VERSION_SUPERSEDED = "profile_version.superseded"
    PROFILE_VERSION_RETIRED = "profile_version.retired"
    PROFILE_ROOT = "profile.root"
    AUDIT_PROFILE_CREATED = "audit.profile_created"
    AUDIT_PROFILE_DRAFT_SAVED = "audit.profile_draft_saved"
    AUDIT_PROFILE_PUBLISHED = "audit.profile_published"
    AUDIT_PROFILE_PAUSED = "audit.profile_paused"
    AUDIT_PROFILE_RESUMED = "audit.profile_resumed"
    AUDIT_PROFILE_ARCHIVED = "audit.profile_archived"
    OUTBOX_PROFILE_CREATED = "outbox.profile_created"
    OUTBOX_PROFILE_PUBLISHED = "outbox.profile_published"
    OUTBOX_PROFILE_PAUSED = "outbox.profile_paused"
    OUTBOX_PROFILE_RESUMED = "outbox.profile_resumed"
    OUTBOX_PROFILE_ARCHIVED = "outbox.profile_archived"
    RECEIPT_COMPLETED = "receipt.completed"


CREATOR_PROFILE_POSTGRES_WRITE_CHECKPOINTS: Tuple[
    CreatorProfilePostgresWriteCheckpoint, ...
] = tuple(CreatorProfilePostgresWriteCheckpoint)

CREATOR_PROFILE_POSTGRES_PUBLISH_WRITE_CHECKPOINTS = (
    CreatorProfilePostgresWriteCheckpoint.RECEIPT_PENDING,
    CreatorProfilePostgresWriteCheckpoint.PROFILE_VERSION_SUPERSEDED,
    CreatorProfilePostgresWriteCheckpoint.PROFILE_VERSION_PUBLISHED,
    CreatorProfilePostgresWriteCheckpoint.PROFILE_ROOT,
    CreatorProfilePostgresWriteCheckpoint.AUDIT_PROFILE_PUBLISHED,
    CreatorProfilePostgresWriteCheckpoint.OUTBOX_PROFILE_PUBLISHED,
    CreatorProfilePostgresWriteCheckpoint.RECEIPT_COMPLETED,
)


class CreatorProfilePostgresConnectionSource(Protocol):
    """A pool already bound to exactly one reviewed online role."""

    def checkout(self) -> Any: ...

    def release(self, connection: Any) -> None: ...

    def discard(self, connection: Any) -> None: ...


class CreatorProfilePostgresFaultInjector(Protocol):
    """Test hook immediately before one logical write; never changes SQL."""

    def before_write(
        self,
        checkpoint: CreatorProfilePostgresWriteCheckpoint,
        ordinal: int,
    ) -> None: ...


class CreatorProfilePostgresSchemaValidator(Protocol):
    def validate(
        self,
        value: Mapping[str, Any],
        schema_name: Optional[str] = None,
    ) -> None: ...


class NoCreatorProfilePostgresFaults:
    def before_write(
        self,
        checkpoint: CreatorProfilePostgresWriteCheckpoint,
        ordinal: int,
    ) -> None:
        del checkpoint, ordinal


@dataclass(frozen=True)
class CreatorProfilePostgresSettings:
    writer_role: str = "profile_app"
    matcher_role: str = "profile_matcher"
    required_server_major: int = 18
    required_schema_head_version: int = PROFILE_POSTGRES_SCHEMA_HEAD_VERSION
    lock_timeout_ms: int = 2_000
    statement_timeout_ms: int = 10_000
    idle_in_transaction_timeout_ms: int = 15_000
    maximum_content_bytes: int = 512 * 1024
    maximum_match_candidates: int = 500
    max_precommit_retries: int = 3

    def __post_init__(self) -> None:
        if self.writer_role != "profile_app":
            raise ValueError("Creator Profile writer role must be profile_app")
        if self.matcher_role != "profile_matcher":
            raise ValueError("Creator Profile matcher role must be profile_matcher")
        if self.required_server_major != 18:
            raise ValueError("Creator Profile PostgreSQL major must be 18")
        if self.required_schema_head_version != PROFILE_POSTGRES_SCHEMA_HEAD_VERSION:
            raise ValueError("Creator Profile PostgreSQL schema head must be 5")
        if not 1 <= self.lock_timeout_ms <= 10_000:
            raise ValueError("Profile lock timeout is outside reviewed bounds")
        if not 1 <= self.statement_timeout_ms <= 120_000:
            raise ValueError("Profile statement timeout is outside reviewed bounds")
        if not 1 <= self.idle_in_transaction_timeout_ms <= 30_000:
            raise ValueError(
                "Profile idle-in-transaction timeout is outside reviewed bounds"
            )
        if self.maximum_content_bytes != 512 * 1024:
            raise ValueError("Profile v1 content byte ceiling must be 512 KiB")
        if self.maximum_match_candidates != 500:
            raise ValueError("Profile v1 match candidate ceiling must be 500")
        if self.max_precommit_retries != 3:
            raise ValueError("Profile pre-COMMIT retry count must be exactly 3")


@dataclass(frozen=True)
class CreatorProfilePostgresStatementProfile:
    operation: CreatorProfilePostgresOperation
    runtime_role: str
    statement_names: Tuple[str, ...]
    statement_budget: int
    query_shape_sha256: str

    def __post_init__(self) -> None:
        expected_role = (
            "profile_matcher"
            if self.operation
            in {
                CreatorProfilePostgresOperation.CAPTURE_MATCH_INPUTS,
                CreatorProfilePostgresOperation.CAPTURE_DERIVED_MATCH_INPUTS,
            }
            else "profile_app"
        )
        if self.runtime_role != expected_role:
            raise ValueError("Profile fixed program has the wrong online role")
        if (
            not self.statement_names
            or len(self.statement_names) != self.statement_budget
            or len(set(self.statement_names)) != len(self.statement_names)
        ):
            raise ValueError("Profile fixed statement budget is not closed")
        if len(self.query_shape_sha256) != 64:
            raise ValueError("Profile query-shape digest is invalid")


def _statement_profile(
    operation: CreatorProfilePostgresOperation,
    role: str,
    names: Tuple[str, ...],
) -> CreatorProfilePostgresStatementProfile:
    material = json.dumps(
        {
            "operation": operation.value,
            "runtime_role": role,
            "statement_names": names,
            "statement_budget": len(names),
            "shape_version": "creator-profile-postgres-v1",
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return CreatorProfilePostgresStatementProfile(
        operation=operation,
        runtime_role=role,
        statement_names=names,
        statement_budget=len(names),
        query_shape_sha256=hashlib.sha256(material).hexdigest(),
    )


CREATOR_PROFILE_POSTGRES_STATEMENT_PROFILES = MappingProxyType(
    {
        CreatorProfilePostgresOperation.CREATE: _statement_profile(
            CreatorProfilePostgresOperation.CREATE,
            "profile_app",
            (
                "lock_creator_profile_self_authority_v1",
                "claim_profile_receipt_v1",
                "insert_creator_profile_root_v1",
                "insert_profile_audit_v1",
                "insert_profile_outbox_v1",
                "complete_profile_receipt_v1",
            ),
        ),
        CreatorProfilePostgresOperation.SAVE_DRAFT: _statement_profile(
            CreatorProfilePostgresOperation.SAVE_DRAFT,
            "profile_app",
            (
                "lock_creator_profile_self_authority_v1",
                "lock_creator_profile_graph_v1",
                "claim_profile_receipt_v1",
                "discard_current_profile_draft_v1",
                "insert_profile_draft_v1",
                "cas_creator_profile_root_v1",
                "insert_profile_audit_v1",
                "complete_profile_receipt_v1",
            ),
        ),
        CreatorProfilePostgresOperation.PUBLISH: _statement_profile(
            CreatorProfilePostgresOperation.PUBLISH,
            "profile_app",
            (
                "lock_creator_profile_self_authority_v1",
                "lock_creator_profile_graph_v1",
                "claim_profile_receipt_v1",
                "supersede_published_profile_version_v1",
                "publish_profile_version_v1",
                "cas_creator_profile_root_v1",
                "insert_profile_audit_v1",
                "insert_profile_outbox_v1",
                "complete_profile_receipt_v1",
            ),
        ),
        CreatorProfilePostgresOperation.PAUSE: _statement_profile(
            CreatorProfilePostgresOperation.PAUSE,
            "profile_app",
            (
                "lock_creator_profile_self_authority_v1",
                "lock_creator_profile_graph_v1",
                "claim_profile_receipt_v1",
                "cas_creator_profile_root_v1",
                "insert_profile_audit_v1",
                "insert_profile_outbox_v1",
                "complete_profile_receipt_v1",
            ),
        ),
        CreatorProfilePostgresOperation.RESUME: _statement_profile(
            CreatorProfilePostgresOperation.RESUME,
            "profile_app",
            (
                "lock_creator_profile_self_authority_v1",
                "lock_creator_profile_graph_v1",
                "claim_profile_receipt_v1",
                "cas_creator_profile_root_v1",
                "insert_profile_audit_v1",
                "insert_profile_outbox_v1",
                "complete_profile_receipt_v1",
            ),
        ),
        CreatorProfilePostgresOperation.ARCHIVE: _statement_profile(
            CreatorProfilePostgresOperation.ARCHIVE,
            "profile_app",
            (
                "lock_creator_profile_self_authority_v1",
                "lock_creator_profile_graph_v1",
                "claim_profile_receipt_v1",
                "retire_current_profile_versions_v1",
                "cas_creator_profile_root_v1",
                "insert_profile_audit_v1",
                "insert_profile_outbox_v1",
                "complete_profile_receipt_v1",
            ),
        ),
        CreatorProfilePostgresOperation.CAPTURE_MATCH_INPUTS: _statement_profile(
            CreatorProfilePostgresOperation.CAPTURE_MATCH_INPUTS,
            "profile_matcher",
            (
                "discover_and_capture_creator_profile_match_inputs_v1",
            ),
        ),
        CreatorProfilePostgresOperation.CAPTURE_DERIVED_MATCH_INPUTS: _statement_profile(
            CreatorProfilePostgresOperation.CAPTURE_DERIVED_MATCH_INPUTS,
            "profile_matcher",
            (
                "discover_and_capture_derived_creator_match_inputs_v1",
            ),
        ),
    }
)


@dataclass(frozen=True)
class CreatorProfilePostgresReceiptMaterial:
    receipt_id: UUID
    principal_id: UUID
    idempotency_key_digest_key_id: str
    idempotency_key_digest: bytes = field(repr=False)
    payload_hash_key_id: str
    canonicalization_version: str
    payload_hash: bytes = field(repr=False)
    retain_until: datetime

    def __post_init__(self) -> None:
        _require_uuid(self.receipt_id, "receipt ID")
        _require_uuid(self.principal_id, "receipt principal")
        _require_key_id(
            self.idempotency_key_digest_key_id,
            "idempotency digest key ID",
        )
        _require_digest(self.idempotency_key_digest, "idempotency digest")
        _require_key_id(self.payload_hash_key_id, "payload hash key ID")
        if self.canonicalization_version != "profile-command-json-v1":
            raise ValueError("unsupported Profile receipt canonicalization")
        _require_digest(self.payload_hash, "payload hash")
        _require_utc(self.retain_until, "receipt retain_until")


@dataclass(frozen=True)
class CreatorProfilePostgresExecutionScope:
    actor_user_id: UUID
    session_id: UUID
    profile_id: UUID
    command_id: UUID
    audit_event_id: UUID
    outbox_event_id: Optional[UUID]
    correlation_id: UUID
    causation_id: UUID
    trace_id: UUID
    original_actor_id: Optional[UUID]
    expected_authority_marker_sha256: bytes = field(repr=False)

    def __post_init__(self) -> None:
        for name, value in (
            ("actor User", self.actor_user_id),
            ("Session", self.session_id),
            ("Profile", self.profile_id),
            ("command", self.command_id),
            ("audit event", self.audit_event_id),
            ("correlation", self.correlation_id),
            ("causation", self.causation_id),
            ("trace", self.trace_id),
        ):
            _require_uuid(value, name)
        if self.outbox_event_id is not None:
            _require_uuid(self.outbox_event_id, "outbox event")
        if self.original_actor_id is not None:
            _require_uuid(self.original_actor_id, "original actor")
        _require_digest(
            self.expected_authority_marker_sha256,
            "authority marker",
        )


@dataclass(frozen=True)
class CreatorProfilePostgresHoldEvidence:
    profile_id: UUID
    prospective_aggregate_version: int
    content_sha256: bytes = field(repr=False)
    actor_user_id: UUID
    policy_version: str
    evaluated_at: datetime
    valid_until: datetime

    def __post_init__(self) -> None:
        _require_uuid(self.profile_id, "hold Profile")
        _require_uuid(self.actor_user_id, "hold actor")
        _require_positive_int(
            self.prospective_aggregate_version,
            "hold aggregate version",
        )
        _require_digest(self.content_sha256, "hold content hash")
        if self.policy_version != "creator-profile-hold-v1":
            raise ValueError("unsupported Creator Profile hold policy")
        _require_utc(self.evaluated_at, "hold evaluated_at")
        _require_utc(self.valid_until, "hold valid_until")
        if self.valid_until <= self.evaluated_at:
            raise ValueError("Profile hold validity window is empty")


@dataclass(frozen=True)
class CreatorProfilePostgresCommand:
    operation: CreatorProfilePostgresOperation
    scope: CreatorProfilePostgresExecutionScope
    receipt: CreatorProfilePostgresReceiptMaterial
    expected_aggregate_version: Optional[int]
    profile_version_id: Optional[UUID]
    based_on_profile_version_id: Optional[UUID]
    taxonomy_bundle_id: Optional[UUID]
    canonical_profile_version_bytes: Optional[bytes] = field(
        default=None,
        repr=False,
    )
    content_sha256: Optional[bytes] = field(default=None, repr=False)
    confirmed: Optional[bool] = None
    reason_code: Optional[str] = None
    hold: Optional[CreatorProfilePostgresHoldEvidence] = field(
        default=None,
        repr=False,
    )

    def __post_init__(self) -> None:
        if not isinstance(self.operation, CreatorProfilePostgresOperation):
            raise ValueError("Creator Profile PostgreSQL operation is not closed")
        if self.operation is CreatorProfilePostgresOperation.CAPTURE_MATCH_INPUTS:
            raise ValueError("match capture is not a writer command")
        if self.receipt.receipt_id != self.scope.command_id:
            raise ValueError("Profile receipt and command IDs must match")
        if self.receipt.principal_id != self.scope.actor_user_id:
            raise ValueError("Profile receipt principal must be the actor")
        if self.operation is CreatorProfilePostgresOperation.CREATE:
            if any(
                value is not None
                for value in (
                    self.expected_aggregate_version,
                    self.profile_version_id,
                    self.based_on_profile_version_id,
                    self.taxonomy_bundle_id,
                    self.canonical_profile_version_bytes,
                    self.content_sha256,
                    self.confirmed,
                    self.reason_code,
                    self.hold,
                )
            ):
                raise ValueError("CreateCreatorProfile database request is open")
        else:
            _require_positive_int(
                self.expected_aggregate_version,
                "expected Profile aggregate version",
            )
        if self.operation is CreatorProfilePostgresOperation.SAVE_DRAFT:
            if (
                self.profile_version_id is None
                or self.taxonomy_bundle_id is None
                or self.canonical_profile_version_bytes is None
                or self.content_sha256 is None
                or self.confirmed is not None
                or self.reason_code is not None
                or self.hold is not None
            ):
                raise ValueError("SaveCreatorProfileDraft database request is open")
            _require_uuid(self.profile_version_id, "new ProfileVersion")
            _require_uuid(self.taxonomy_bundle_id, "TaxonomyBundle")
            if self.based_on_profile_version_id is not None:
                _require_uuid(self.based_on_profile_version_id, "based-on version")
            _require_canonical_bytes(self.canonical_profile_version_bytes)
            _require_digest(self.content_sha256, "Profile content hash")
        elif self.operation is CreatorProfilePostgresOperation.PUBLISH:
            if (
                self.profile_version_id is None
                or self.based_on_profile_version_id is not None
                or self.taxonomy_bundle_id is not None
                or self.canonical_profile_version_bytes is not None
                or self.content_sha256 is not None
                or self.confirmed is not True
                or self.reason_code is not None
                or self.hold is None
            ):
                raise ValueError("PublishCreatorProfileVersion request is open")
            _require_uuid(self.profile_version_id, "published ProfileVersion")
        elif self.operation is CreatorProfilePostgresOperation.PAUSE:
            if (
                self.reason_code
                not in {
                    "OWNER_REQUEST",
                    "TEMPORARY_UNAVAILABILITY",
                    "SAFETY_REVIEW",
                }
                or self.profile_version_id is not None
                or self.based_on_profile_version_id is not None
                or self.taxonomy_bundle_id is not None
                or self.canonical_profile_version_bytes is not None
                or self.content_sha256 is not None
                or self.confirmed is not None
                or self.hold is not None
            ):
                raise ValueError("PauseCreatorProfile request is open")
        elif self.operation is CreatorProfilePostgresOperation.RESUME:
            if (
                self.hold is None
                or any(
                    value is not None
                    for value in (
                        self.profile_version_id,
                        self.based_on_profile_version_id,
                        self.taxonomy_bundle_id,
                        self.canonical_profile_version_bytes,
                        self.content_sha256,
                        self.confirmed,
                        self.reason_code,
                    )
                )
            ):
                raise ValueError("ResumeCreatorProfile request is open")
        elif self.operation is CreatorProfilePostgresOperation.ARCHIVE:
            if (
                self.reason_code
                not in {"OWNER_REQUEST", "ACCOUNT_CLOSURE", "SAFETY_REVIEW"}
                or self.profile_version_id is not None
                or self.based_on_profile_version_id is not None
                or self.taxonomy_bundle_id is not None
                or self.canonical_profile_version_bytes is not None
                or self.content_sha256 is not None
                or self.confirmed is not None
                or self.hold is not None
            ):
                raise ValueError("ArchiveCreatorProfile request is open")

        event_required = self.operation is not CreatorProfilePostgresOperation.SAVE_DRAFT
        if event_required != (self.scope.outbox_event_id is not None):
            raise ValueError("Profile outbox ID does not match operation semantics")
        if self.hold is not None and (
            self.hold.profile_id != self.scope.profile_id
            or self.hold.actor_user_id != self.scope.actor_user_id
            or self.hold.prospective_aggregate_version
            != self.expected_aggregate_version + 1
        ):
            raise ValueError("Profile hold is not bound to the database command")


@dataclass(frozen=True)
class CreatorProfilePostgresDatabaseResult:
    operation: CreatorProfilePostgresOperation
    replayed: bool
    profile_id: UUID
    aggregate_version: int
    safe_response: Mapping[str, Any] = field(repr=False)
    event_types: Tuple[str, ...]


@dataclass(frozen=True)
class CreatorProfilePostgresMatchCaptureRequest:
    match_run_id: UUID
    workload_id: UUID
    authorization_digest: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _require_uuid(self.match_run_id, "MatchRun")
        _require_uuid(self.workload_id, "matcher workload")
        _require_digest(self.authorization_digest, "match authorization digest")
        if self.authorization_digest == b"\x00" * 32:
            raise ValueError("match authorization digest must be non-zero")


@dataclass(frozen=True)
class CreatorProfilePostgresMatchInput:
    """One closed, exact published input for a bound Matching run."""

    creator_user_id: UUID
    profile_id: UUID
    profile_version_id: UUID
    version_no: int
    taxonomy_bundle_id: UUID
    canonical_profile_version_bytes: bytes = field(repr=False)
    content: ProfileContent = field(repr=False)
    content_sha256: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _require_uuid(self.creator_user_id, "match input Creator")
        _require_uuid(self.profile_id, "match input Profile")
        _require_uuid(self.profile_version_id, "match input ProfileVersion")
        if (
            isinstance(self.version_no, bool)
            or not isinstance(self.version_no, int)
            or not 1 <= self.version_no <= 2_147_483_647
        ):
            raise ValueError("match input version number is invalid")
        _require_uuid(self.taxonomy_bundle_id, "match input taxonomy bundle")
        _require_canonical_bytes(self.canonical_profile_version_bytes)
        if not isinstance(self.content, ProfileContent):
            raise ValueError("match input content is not closed")
        _require_digest(self.content_sha256, "match input content hash")


@dataclass(frozen=True)
class CreatorProfilePostgresMatchCaptureResult:
    match_run_id: UUID
    workload_id: UUID
    capture_contract_version: int
    status: str
    captured_at: datetime
    authorization_valid_until: datetime
    candidate_count: int
    allowlist_sha256: bytes = field(repr=False)
    replayed: bool
    snapshots: Tuple[CreatorProfilePostgresMatchInput, ...] = field(repr=False)
    statement_count: int

    def __post_init__(self) -> None:
        _require_uuid(self.match_run_id, "captured MatchRun")
        _require_uuid(self.workload_id, "captured matcher workload")
        if self.capture_contract_version != 1 or self.status != "COMPLETED":
            raise ValueError("match capture result contract is invalid")
        _require_utc(self.captured_at, "match captured_at")
        _require_utc(
            self.authorization_valid_until,
            "match authorization_valid_until",
        )
        if self.authorization_valid_until <= self.captured_at:
            raise ValueError("match authorization validity window is empty")
        if (
            isinstance(self.candidate_count, bool)
            or not isinstance(self.candidate_count, int)
            or not 0 <= self.candidate_count <= 500
            or self.candidate_count != len(self.snapshots)
        ):
            raise ValueError("match capture candidate count is invalid")
        _require_digest(self.allowlist_sha256, "match allowlist hash")
        if not isinstance(self.replayed, bool) or self.statement_count != 1:
            raise ValueError("match capture execution metadata is invalid")
        if tuple(item.profile_id for item in self.snapshots) != tuple(
            sorted((item.profile_id for item in self.snapshots), key=lambda value: value.bytes)
        ):
            raise ValueError("match capture snapshots are not canonical")


@dataclass(frozen=True)
class CreatorProfilePostgresDerivedMatchCaptureRequest:
    match_run_id: UUID
    workload_id: UUID
    authorization_digest: bytes = field(repr=False)
    demand_match_context_bytes: bytes = field(repr=False)
    demand_match_context_sha256: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _require_uuid(self.match_run_id, "derived MatchRun")
        _require_uuid(self.workload_id, "derived matcher workload")
        _require_digest(self.authorization_digest, "derived authorization digest")
        if self.authorization_digest == b"\x00" * 32:
            raise ValueError("derived authorization digest must be non-zero")
        _decode_demand_match_context(
            self.demand_match_context_bytes,
            self.demand_match_context_sha256,
        )


@dataclass(frozen=True)
class CreatorProfilePostgresDerivedMatchInput:
    creator_user_id: UUID
    profile_id: UUID
    profile_version_id: UUID
    version_no: int
    taxonomy_bundle_id: UUID
    canonical_profile_version_bytes: bytes = field(repr=False)
    profile_content: ProfileContent = field(repr=False)
    profile_content_sha256: bytes = field(repr=False)
    derived_schema_version: int
    derived_canonicalization_version: str
    canonical_derived_input_bytes: bytes = field(repr=False)
    derived_input: ProfileContent = field(repr=False)
    derived_input_sha256: bytes = field(repr=False)
    evidence_version_digest: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _require_uuid(self.creator_user_id, "derived input Creator")
        _require_uuid(self.profile_id, "derived input Profile")
        _require_uuid(self.profile_version_id, "derived input ProfileVersion")
        _require_positive_int(self.version_no, "derived input version")
        _require_uuid(self.taxonomy_bundle_id, "derived input taxonomy bundle")
        _require_canonical_bytes(self.canonical_profile_version_bytes)
        if not isinstance(self.profile_content, ProfileContent):
            raise ValueError("derived raw Profile content is not closed")
        _require_digest(self.profile_content_sha256, "derived raw Profile hash")
        if (
            self.derived_schema_version != 1
            or self.derived_canonicalization_version
            != "profile-match-input-json-v1"
        ):
            raise ValueError("derived Profile input contract is invalid")
        if (
            not isinstance(self.canonical_derived_input_bytes, bytes)
            or not self.canonical_derived_input_bytes
            or len(self.canonical_derived_input_bytes) > 512 * 1024
            or not isinstance(self.derived_input, ProfileContent)
        ):
            raise ValueError("derived Profile input bytes are invalid")
        _require_digest(self.derived_input_sha256, "derived Profile input hash")
        _require_digest(self.evidence_version_digest, "derived evidence digest")


@dataclass(frozen=True)
class CreatorProfilePostgresDerivedMatchCaptureResult:
    match_run_id: UUID
    workload_id: UUID
    capture_contract_version: int
    status: str
    captured_at: datetime
    candidate_count: int
    allowlist_sha256: bytes = field(repr=False)
    authorization_valid_until: datetime
    replayed: bool
    snapshots: Tuple[CreatorProfilePostgresDerivedMatchInput, ...] = field(
        repr=False
    )
    statement_count: int

    def __post_init__(self) -> None:
        _require_uuid(self.match_run_id, "derived captured MatchRun")
        _require_uuid(self.workload_id, "derived captured workload")
        if self.capture_contract_version != 2 or self.status != "COMPLETED":
            raise ValueError("derived capture result contract is invalid")
        _require_utc(self.captured_at, "derived captured_at")
        _require_utc(
            self.authorization_valid_until,
            "derived authorization_valid_until",
        )
        if self.authorization_valid_until <= self.captured_at:
            raise ValueError("derived authorization validity window is empty")
        if (
            isinstance(self.candidate_count, bool)
            or not isinstance(self.candidate_count, int)
            or not 0 <= self.candidate_count <= 500
            or self.candidate_count != len(self.snapshots)
        ):
            raise ValueError("derived candidate count is invalid")
        _require_digest(self.allowlist_sha256, "derived allowlist hash")
        if not isinstance(self.replayed, bool) or self.statement_count != 1:
            raise ValueError("derived execution metadata is invalid")
        if tuple(item.profile_id for item in self.snapshots) != tuple(
            sorted((item.profile_id for item in self.snapshots), key=lambda value: value.bytes)
        ):
            raise ValueError("derived snapshots are not canonical")


class PsycopgCreatorProfileUnitOfWorkFactory:
    """Six role-bound fixed writer programs for PostgreSQL 18."""

    def __init__(
        self,
        *,
        connections: CreatorProfilePostgresConnectionSource,
        event_validator: CreatorProfilePostgresSchemaValidator,
        response_validator: CreatorProfilePostgresSchemaValidator,
        settings: Optional[CreatorProfilePostgresSettings] = None,
        fault_injector: Optional[CreatorProfilePostgresFaultInjector] = None,
    ) -> None:
        self.connections = connections
        self.event_validator = event_validator
        self.response_validator = response_validator
        self.settings = settings or CreatorProfilePostgresSettings()
        self.fault_injector = fault_injector or NoCreatorProfilePostgresFaults()

    @staticmethod
    def profile(
        operation: CreatorProfilePostgresOperation,
    ) -> CreatorProfilePostgresStatementProfile:
        try:
            return CREATOR_PROFILE_POSTGRES_STATEMENT_PROFILES[operation]
        except KeyError as error:
            raise ValueError("unknown Creator Profile PostgreSQL operation") from error

    def execute_create(
        self, request: CreatorProfilePostgresCommand
    ) -> CreatorProfilePostgresDatabaseResult:
        return self._execute(request, CreatorProfilePostgresOperation.CREATE)

    def execute_save_draft(
        self,
        request: CreatorProfilePostgresCommand,
        *,
        before_mutation: Optional[Callable[[], None]] = None,
    ) -> CreatorProfilePostgresDatabaseResult:
        return self._execute(
            request,
            CreatorProfilePostgresOperation.SAVE_DRAFT,
            before_mutation=before_mutation,
        )

    def execute_publish(
        self,
        request: CreatorProfilePostgresCommand,
        *,
        before_mutation: Optional[Callable[[], None]] = None,
    ) -> CreatorProfilePostgresDatabaseResult:
        return self._execute(
            request,
            CreatorProfilePostgresOperation.PUBLISH,
            before_mutation=before_mutation,
        )

    def execute_pause(
        self, request: CreatorProfilePostgresCommand
    ) -> CreatorProfilePostgresDatabaseResult:
        return self._execute(request, CreatorProfilePostgresOperation.PAUSE)

    def execute_resume(
        self, request: CreatorProfilePostgresCommand
    ) -> CreatorProfilePostgresDatabaseResult:
        return self._execute(request, CreatorProfilePostgresOperation.RESUME)

    def execute_archive(
        self, request: CreatorProfilePostgresCommand
    ) -> CreatorProfilePostgresDatabaseResult:
        return self._execute(request, CreatorProfilePostgresOperation.ARCHIVE)

    def _execute(
        self,
        request: CreatorProfilePostgresCommand,
        expected: CreatorProfilePostgresOperation,
        *,
        before_mutation: Optional[Callable[[], None]] = None,
    ) -> CreatorProfilePostgresDatabaseResult:
        if not isinstance(request, CreatorProfilePostgresCommand):
            raise ValueError("closed Creator Profile database request is required")
        if request.operation is not expected:
            raise ValueError("Creator Profile database operation mismatch")
        connection = None
        transaction_active = False
        commit_sent = False
        validation_error: Optional[BaseException] = None
        try:
            connection = self.connections.checkout()
            _prepare_connection(
                connection,
                expected_role=self.settings.writer_role,
                required_server_major=self.settings.required_server_major,
                required_schema_head_version=(
                    self.settings.required_schema_head_version
                ),
            )
            connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED")
            transaction_active = True
            _set_writer_scope(connection, request, self.settings)

            authority = connection.execute(
                _SQL_LOCK_CREATOR_PROFILE_AUTHORITY,
                (
                    request.scope.actor_user_id,
                    request.scope.session_id,
                    _operation_guc(expected),
                    request.scope.expected_authority_marker_sha256,
                ),
            ).fetchone()
            if authority is None:
                raise CreatorProfilePostgresDatabaseError("RESOURCE_NOT_FOUND")
            if not authority[4] or not hmac_compare(
                bytes(authority[3]),
                request.scope.expected_authority_marker_sha256,
            ):
                raise CreatorProfilePostgresDatabaseError("SERVICE_UNAVAILABLE")

            graph = None
            versions: Tuple[Mapping[str, Any], ...] = ()
            if expected is not CreatorProfilePostgresOperation.CREATE:
                graph_row = connection.execute(
                    _SQL_LOCK_PROFILE_GRAPH,
                    (request.scope.profile_id,),
                ).fetchone()
                if graph_row is None:
                    raise CreatorProfilePostgresDatabaseError("RESOURCE_NOT_FOUND")
                graph = {
                    "id": graph_row[0],
                    "owner_user_id": graph_row[1],
                    "status": graph_row[2],
                    "aggregate_version": graph_row[3],
                    "current_draft_version_id": graph_row[4],
                    "current_published_version_id": graph_row[5],
                }
                versions = tuple(graph_row[6] or ())

            ordinal = [0]
            self._before(
                CreatorProfilePostgresWriteCheckpoint.RECEIPT_PENDING,
                ordinal,
            )
            receipt_row = connection.execute(
                _SQL_CLAIM_PROFILE_RECEIPT,
                (
                    request.receipt.receipt_id,
                    request.receipt.principal_id,
                    expected.value,
                    request.receipt.idempotency_key_digest_key_id,
                    request.receipt.idempotency_key_digest,
                    request.receipt.payload_hash_key_id,
                    request.receipt.canonicalization_version,
                    request.receipt.payload_hash,
                    request.scope.profile_id,
                    request.expected_aggregate_version,
                    request.receipt.retain_until,
                    request.receipt.principal_id,
                    expected.value,
                    request.receipt.idempotency_key_digest_key_id,
                    request.receipt.idempotency_key_digest,
                ),
            ).fetchone()
            if receipt_row is None:
                raise CreatorProfilePostgresDatabaseError("IDEMPOTENCY_KEY_REUSED")
            if not hmac_compare(bytes(receipt_row[1]), request.receipt.payload_hash):
                raise CreatorProfilePostgresDatabaseError("IDEMPOTENCY_KEY_REUSED")
            if receipt_row[0] == "COMPLETED":
                safe_response = dict(receipt_row[2])
                result = CreatorProfilePostgresDatabaseResult(
                    operation=expected,
                    replayed=True,
                    profile_id=request.scope.profile_id,
                    aggregate_version=receipt_row[3],
                    safe_response=safe_response,
                    event_types=(),
                )
                connection.execute("COMMIT")
                transaction_active = False
                _reset_and_release(
                    connection,
                    source=self.connections,
                    expected_role=self.settings.writer_role,
                )
                return result
            if not receipt_row[4]:
                raise CreatorProfilePostgresDatabaseError("SERVICE_UNAVAILABLE")

            if graph is not None and (
                graph["owner_user_id"] != request.scope.actor_user_id
                or graph["aggregate_version"] != request.expected_aggregate_version
            ):
                raise CreatorProfilePostgresDatabaseError("PRECONDITION_FAILED")

            if before_mutation is not None:
                try:
                    before_mutation()
                except BaseException as error:
                    validation_error = error
                    raise

            safe_response, event_type, event_payload, before_status = self._mutate(
                connection,
                request,
                graph,
                versions,
                ordinal,
            )
            aggregate_version = int(safe_response["aggregate_version"])
            self.response_validator.validate(
                safe_response,
                "CreatorProfileCommandResponse",
            )
            event_types: Tuple[str, ...] = ()
            if event_type is not None:
                event = _event_envelope(
                    request,
                    event_type=event_type,
                    aggregate_version=aggregate_version,
                    payload=event_payload,
                )
                self.event_validator.validate(event, event_type + "Event")
                self._before(_outbox_checkpoint(expected), ordinal)
                connection.execute(
                    _SQL_INSERT_PROFILE_OUTBOX,
                    (
                        request.scope.outbox_event_id,
                        event_type,
                        request.scope.profile_id,
                        aggregate_version,
                        request.scope.actor_user_id,
                        request.scope.original_actor_id,
                        request.scope.correlation_id,
                        request.scope.causation_id,
                        request.scope.trace_id,
                        json.dumps(event_payload, separators=(",", ":")),
                    ),
                )
                event_types = (event_type,)

            self._before(
                CreatorProfilePostgresWriteCheckpoint.RECEIPT_COMPLETED,
                ordinal,
            )
            completed = connection.execute(
                _SQL_COMPLETE_PROFILE_RECEIPT,
                (
                    json.dumps(safe_response, separators=(",", ":")),
                    aggregate_version,
                    request.receipt.receipt_id,
                ),
            ).fetchone()
            if completed is None:
                raise CreatorProfilePostgresDatabaseError("SERVICE_UNAVAILABLE")

            commit_sent = True
            connection.execute("COMMIT")
            transaction_active = False
            commit_sent = False
            _reset_and_release(
                connection,
                source=self.connections,
                expected_role=self.settings.writer_role,
            )
            return CreatorProfilePostgresDatabaseResult(
                operation=expected,
                replayed=False,
                profile_id=request.scope.profile_id,
                aggregate_version=aggregate_version,
                safe_response=safe_response,
                event_types=event_types,
            )
        except CreatorProfilePostgresCommitOutcomeUnknownError:
            raise
        except BaseException as error:
            if connection is None:
                raise
            if commit_sent:
                self.connections.discard(connection)
                raise CreatorProfilePostgresCommitOutcomeUnknownError() from None
            if transaction_active:
                try:
                    connection.execute("ROLLBACK")
                    transaction_active = False
                except BaseException:
                    self.connections.discard(connection)
                    raise CreatorProfilePostgresDatabaseError(
                        "SERVICE_UNAVAILABLE"
                    ) from None
            try:
                _reset_and_release(
                    connection,
                    source=self.connections,
                    expected_role=self.settings.writer_role,
                )
            except BaseException:
                self.connections.discard(connection)
                raise CreatorProfilePostgresDatabaseError(
                    "SERVICE_UNAVAILABLE"
                ) from None
            if isinstance(error, CreatorProfilePostgresDatabaseError):
                raise
            if isinstance(error, CreatorProfilePostgresConfigurationError):
                raise
            if error is validation_error:
                raise
            if getattr(error, "sqlstate", None) == "23505" and expected is (
                CreatorProfilePostgresOperation.CREATE
            ):
                raise CreatorProfilePostgresDatabaseError(
                    "PROFILE_ALREADY_EXISTS"
                ) from None
            raise CreatorProfilePostgresDatabaseError(
                "SERVICE_UNAVAILABLE"
            ) from None

    def _before(
        self,
        checkpoint: CreatorProfilePostgresWriteCheckpoint,
        ordinal: list[int],
    ) -> None:
        ordinal[0] += 1
        self.fault_injector.before_write(checkpoint, ordinal[0])

    def _mutate(
        self,
        connection: Any,
        request: CreatorProfilePostgresCommand,
        graph: Optional[Mapping[str, Any]],
        versions: Tuple[Mapping[str, Any], ...],
        ordinal: list[int],
    ) -> Tuple[Mapping[str, Any], Optional[str], Mapping[str, Any], Optional[str]]:
        operation = request.operation
        before_status = graph["status"] if graph is not None else None
        before_version = graph["aggregate_version"] if graph is not None else None

        if operation is CreatorProfilePostgresOperation.CREATE:
            self._before(CreatorProfilePostgresWriteCheckpoint.PROFILE_ROOT, ordinal)
            row = connection.execute(
                _SQL_INSERT_PROFILE_ROOT,
                (request.scope.profile_id, request.scope.actor_user_id),
            ).fetchone()
            if row is None:
                raise CreatorProfilePostgresDatabaseError("PROFILE_ALREADY_EXISTS")
            status, aggregate_version = row
            event_type = "CreatorProfileCreated"
            event_payload = {
                "profile_id": str(request.scope.profile_id),
                "owner_user_id": str(request.scope.actor_user_id),
                "status": status,
            }
        elif operation is CreatorProfilePostgresOperation.SAVE_DRAFT:
            assert graph is not None
            canonical = request.canonical_profile_version_bytes
            digest = request.content_sha256
            if not hmac_compare(hashlib.sha256(canonical).digest(), digest):
                raise CreatorProfilePostgresDatabaseError("SERVICE_UNAVAILABLE")
            decoded = json.loads(canonical.decode("utf-8"))
            version_no = 1 + max(
                (int(item["version_no"]) for item in versions),
                default=0,
            )
            if (
                decoded.get("profile_id") != str(request.scope.profile_id)
                or decoded.get("version_no") != version_no
                or decoded.get("taxonomy_bundle_id") != str(request.taxonomy_bundle_id)
            ):
                raise CreatorProfilePostgresDatabaseError("SERVICE_UNAVAILABLE")
            self._before(
                CreatorProfilePostgresWriteCheckpoint.PROFILE_VERSION_DISCARDED,
                ordinal,
            )
            connection.execute(
                _SQL_DISCARD_PROFILE_DRAFT,
                (graph["current_draft_version_id"], request.scope.profile_id),
            )
            self._before(
                CreatorProfilePostgresWriteCheckpoint.PROFILE_VERSION_DRAFT,
                ordinal,
            )
            inserted = connection.execute(
                _SQL_INSERT_PROFILE_DRAFT,
                (
                    request.profile_version_id,
                    request.scope.profile_id,
                    version_no,
                    request.based_on_profile_version_id,
                    request.taxonomy_bundle_id,
                    canonical,
                    canonical.decode("utf-8"),
                    digest,
                    request.scope.actor_user_id,
                    request.taxonomy_bundle_id,
                ),
            ).fetchone()
            if inserted is None:
                raise CreatorProfilePostgresDatabaseError("SERVICE_UNAVAILABLE")
            self._before(CreatorProfilePostgresWriteCheckpoint.PROFILE_ROOT, ordinal)
            row = connection.execute(
                _SQL_UPDATE_PROFILE_DRAFT_ROOT,
                (
                    request.profile_version_id,
                    request.scope.profile_id,
                    request.expected_aggregate_version,
                ),
            ).fetchone()
            if row is None:
                raise CreatorProfilePostgresDatabaseError("PRECONDITION_FAILED")
            status, aggregate_version = row
            event_type = None
            event_payload = {}
        elif operation is CreatorProfilePostgresOperation.PUBLISH:
            assert graph is not None
            draft = _version_by_id(versions, request.profile_version_id)
            if draft is None or draft["status"] != "DRAFT":
                raise CreatorProfilePostgresDatabaseError("PRECONDITION_FAILED")
            if not _valid_hold(request, bytes.fromhex(draft["content_sha256"])):
                raise CreatorProfilePostgresDatabaseError("SERVICE_UNAVAILABLE")
            current_published_version_id = graph[
                "current_published_version_id"
            ]
            # PostgreSQL checks a non-deferrable partial unique index after
            # each physical row update.  A single CASE update over the old
            # published row and the new draft therefore has an ordering race:
            # the draft may be promoted before the old row is superseded.
            # Retire the old row first inside the same transaction, then
            # promote the draft.  The fixed checkpoint remains present even
            # on the first publish, where the exact UPDATE changes zero rows.
            self._before(
                CreatorProfilePostgresWriteCheckpoint.PROFILE_VERSION_SUPERSEDED,
                ordinal,
            )
            superseded = connection.execute(
                _SQL_SUPERSEDE_PROFILE_VERSION,
                (
                    current_published_version_id,
                    request.scope.profile_id,
                ),
            ).fetchone()
            if current_published_version_id is None:
                if superseded is not None:
                    raise CreatorProfilePostgresDatabaseError(
                        "SERVICE_UNAVAILABLE"
                    )
            elif (
                superseded is None
                or superseded[0] != current_published_version_id
                or superseded[1] != "SUPERSEDED"
            ):
                raise CreatorProfilePostgresDatabaseError(
                    "PRECONDITION_FAILED"
                )
            self._before(
                CreatorProfilePostgresWriteCheckpoint.PROFILE_VERSION_PUBLISHED,
                ordinal,
            )
            published = connection.execute(
                _SQL_PUBLISH_PROFILE_VERSION,
                (
                    request.profile_version_id,
                    request.scope.profile_id,
                ),
            ).fetchone()
            if published is None or published[1] != "PUBLISHED":
                raise CreatorProfilePostgresDatabaseError("SERVICE_UNAVAILABLE")
            self._before(CreatorProfilePostgresWriteCheckpoint.PROFILE_ROOT, ordinal)
            row = connection.execute(
                _SQL_UPDATE_PROFILE_PUBLISHED_ROOT,
                (
                    request.profile_version_id,
                    request.scope.profile_id,
                    request.expected_aggregate_version,
                ),
            ).fetchone()
            if row is None:
                raise CreatorProfilePostgresDatabaseError("PRECONDITION_FAILED")
            status, aggregate_version = row
            event_type = "CreatorProfilePublished"
            event_payload = {
                "profile_id": str(request.scope.profile_id),
                "profile_version_id": str(request.profile_version_id),
                "version_no": int(draft["version_no"]),
                "content_sha256": draft["content_sha256"],
                "taxonomy_bundle_id": str(draft["taxonomy_bundle_id"]),
                "status": status,
            }
        elif operation is CreatorProfilePostgresOperation.PAUSE:
            assert graph is not None
            if graph["status"] != "ACTIVE":
                raise CreatorProfilePostgresDatabaseError("PRECONDITION_FAILED")
            self._before(CreatorProfilePostgresWriteCheckpoint.PROFILE_ROOT, ordinal)
            row = connection.execute(
                _SQL_PAUSE_PROFILE_ROOT,
                (
                    request.reason_code,
                    request.scope.profile_id,
                    request.expected_aggregate_version,
                ),
            ).fetchone()
            if row is None:
                raise CreatorProfilePostgresDatabaseError("PRECONDITION_FAILED")
            status, aggregate_version = row
            event_type = "CreatorProfilePaused"
            event_payload = _status_payload(request, status)
        elif operation is CreatorProfilePostgresOperation.RESUME:
            assert graph is not None
            published = _version_by_id(
                versions,
                graph["current_published_version_id"],
            )
            if (
                graph["status"] != "PAUSED"
                or published is None
                or not _valid_hold(
                    request,
                    bytes.fromhex(published["content_sha256"]),
                )
            ):
                raise CreatorProfilePostgresDatabaseError("SERVICE_UNAVAILABLE")
            self._before(CreatorProfilePostgresWriteCheckpoint.PROFILE_ROOT, ordinal)
            row = connection.execute(
                _SQL_RESUME_PROFILE_ROOT,
                (request.scope.profile_id, request.expected_aggregate_version),
            ).fetchone()
            if row is None:
                raise CreatorProfilePostgresDatabaseError("PRECONDITION_FAILED")
            status, aggregate_version = row
            event_type = "CreatorProfileResumed"
            event_payload = _status_payload(request, status)
        else:
            assert graph is not None
            self._before(
                CreatorProfilePostgresWriteCheckpoint.PROFILE_VERSION_RETIRED,
                ordinal,
            )
            connection.execute(
                _SQL_RETIRE_PROFILE_VERSIONS,
                (request.scope.profile_id,),
            )
            self._before(CreatorProfilePostgresWriteCheckpoint.PROFILE_ROOT, ordinal)
            row = connection.execute(
                _SQL_ARCHIVE_PROFILE_ROOT,
                (
                    request.reason_code,
                    request.scope.profile_id,
                    request.expected_aggregate_version,
                ),
            ).fetchone()
            if row is None:
                raise CreatorProfilePostgresDatabaseError("PRECONDITION_FAILED")
            status, aggregate_version = row
            event_type = "CreatorProfileArchived"
            event_payload = _status_payload(request, status)

        self._before(_audit_checkpoint(operation), ordinal)
        connection.execute(
            _SQL_INSERT_PROFILE_AUDIT,
            (
                request.scope.audit_event_id,
                request.scope.actor_user_id,
                request.scope.original_actor_id,
                _audit_action(operation),
                request.scope.profile_id,
                before_status,
                status,
                before_version,
                aggregate_version,
                request.reason_code,
                request.scope.command_id,
                request.scope.correlation_id,
                request.scope.causation_id,
                request.scope.trace_id,
            ),
        )
        safe_response = {
            "profile_id": str(request.scope.profile_id),
            "aggregate_version": int(aggregate_version),
            "status": status,
        }
        return safe_response, event_type, event_payload, before_status


class PsycopgCreatorProfileMatcherRepository:
    """One fixed program discovers and immutably captures a MatchRun input set."""

    def __init__(
        self,
        *,
        connections: CreatorProfilePostgresConnectionSource,
        settings: Optional[CreatorProfilePostgresSettings] = None,
    ) -> None:
        self.connections = connections
        self.settings = settings or CreatorProfilePostgresSettings()

    def capture_match_inputs(
        self,
        request: CreatorProfilePostgresMatchCaptureRequest,
    ) -> CreatorProfilePostgresMatchCaptureResult:
        if not isinstance(request, CreatorProfilePostgresMatchCaptureRequest):
            raise ValueError("closed match capture request is required")
        for attempt in range(self.settings.max_precommit_retries):
            connection = None
            transaction_active = False
            commit_sent = False
            try:
                connection = self.connections.checkout()
                _prepare_connection(
                    connection,
                    expected_role=self.settings.matcher_role,
                    required_server_major=self.settings.required_server_major,
                    required_schema_head_version=(
                        self.settings.required_schema_head_version
                    ),
                )
                connection.execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
                transaction_active = True
                _set_matcher_scope(connection, request, self.settings)
                rows = tuple(
                    connection.execute(
                        _SQL_DISCOVER_AND_CAPTURE_PROFILE_MATCH_INPUTS,
                        (
                            request.match_run_id,
                            request.workload_id,
                            request.authorization_digest,
                        ),
                    ).fetchall()
                )
                result = _decode_match_capture_rows(request, rows)
                commit_sent = True
                connection.execute("COMMIT")
                transaction_active = False
                commit_sent = False
                _reset_and_release(
                    connection,
                    source=self.connections,
                    expected_role=self.settings.matcher_role,
                )
                return result
            except CreatorProfilePostgresCommitOutcomeUnknownError:
                raise
            except BaseException as error:
                if connection is None:
                    raise
                if commit_sent:
                    self.connections.discard(connection)
                    raise CreatorProfilePostgresCommitOutcomeUnknownError() from None
                if transaction_active:
                    try:
                        connection.execute("ROLLBACK")
                        transaction_active = False
                    except BaseException:
                        self.connections.discard(connection)
                        raise CreatorProfilePostgresDatabaseError(
                            "SERVICE_UNAVAILABLE"
                        ) from None
                try:
                    _reset_and_release(
                        connection,
                        source=self.connections,
                        expected_role=self.settings.matcher_role,
                    )
                except BaseException:
                    self.connections.discard(connection)
                    raise CreatorProfilePostgresDatabaseError(
                        "SERVICE_UNAVAILABLE"
                    ) from None
                if isinstance(error, CreatorProfilePostgresDatabaseError):
                    raise
                if isinstance(error, CreatorProfilePostgresConfigurationError):
                    raise
                if (
                    getattr(error, "sqlstate", None)
                    in {"23505", "40001", "40P01", "55P03"}
                    and attempt + 1 < self.settings.max_precommit_retries
                ):
                    continue
                raise _map_match_capture_error(error) from None
        raise CreatorProfilePostgresDatabaseError("SERVICE_UNAVAILABLE")

    def capture_derived_match_inputs(
        self,
        request: CreatorProfilePostgresDerivedMatchCaptureRequest,
    ) -> CreatorProfilePostgresDerivedMatchCaptureResult:
        if not isinstance(
            request,
            CreatorProfilePostgresDerivedMatchCaptureRequest,
        ):
            raise ValueError("closed derived match capture request is required")
        for attempt in range(self.settings.max_precommit_retries):
            connection = None
            transaction_active = False
            commit_sent = False
            try:
                connection = self.connections.checkout()
                _prepare_connection(
                    connection,
                    expected_role=self.settings.matcher_role,
                    required_server_major=self.settings.required_server_major,
                    required_schema_head_version=(
                        self.settings.required_schema_head_version
                    ),
                )
                connection.execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
                transaction_active = True
                _set_derived_matcher_scope(connection, request, self.settings)
                rows = tuple(
                    connection.execute(
                        _SQL_DISCOVER_AND_CAPTURE_DERIVED_PROFILE_MATCH_INPUTS,
                        (
                            request.match_run_id,
                            request.workload_id,
                            request.authorization_digest,
                            request.demand_match_context_bytes,
                            request.demand_match_context_sha256,
                        ),
                    ).fetchall()
                )
                result = _decode_derived_match_capture_rows(request, rows)
                commit_sent = True
                connection.execute("COMMIT")
                transaction_active = False
                commit_sent = False
                _reset_and_release(
                    connection,
                    source=self.connections,
                    expected_role=self.settings.matcher_role,
                )
                return result
            except CreatorProfilePostgresCommitOutcomeUnknownError:
                raise
            except BaseException as error:
                if connection is None:
                    raise
                if commit_sent:
                    self.connections.discard(connection)
                    raise CreatorProfilePostgresCommitOutcomeUnknownError() from None
                if transaction_active:
                    try:
                        connection.execute("ROLLBACK")
                        transaction_active = False
                    except BaseException:
                        self.connections.discard(connection)
                        raise CreatorProfilePostgresDatabaseError(
                            "SERVICE_UNAVAILABLE"
                        ) from None
                try:
                    _reset_and_release(
                        connection,
                        source=self.connections,
                        expected_role=self.settings.matcher_role,
                    )
                except BaseException:
                    self.connections.discard(connection)
                    raise CreatorProfilePostgresDatabaseError(
                        "SERVICE_UNAVAILABLE"
                    ) from None
                if isinstance(error, CreatorProfilePostgresDatabaseError):
                    raise
                if isinstance(error, CreatorProfilePostgresConfigurationError):
                    raise
                if (
                    getattr(error, "sqlstate", None)
                    in {"23505", "40001", "40P01", "55P03"}
                    and attempt + 1 < self.settings.max_precommit_retries
                ):
                    continue
                raise _map_match_capture_error(error) from None
        raise CreatorProfilePostgresDatabaseError("SERVICE_UNAVAILABLE")


def _decode_match_capture_rows(
    request: CreatorProfilePostgresMatchCaptureRequest,
    rows: Tuple[Tuple[Any, ...], ...],
) -> CreatorProfilePostgresMatchCaptureResult:
    if not rows or any(len(row) != 18 for row in rows):
        raise CreatorProfilePostgresDatabaseError("SERVICE_UNAVAILABLE")
    first = rows[0]
    if (
        first[0] != request.match_run_id
        or first[1] != request.workload_id
        or isinstance(first[2], bool)
        or int(first[2]) != 1
        or first[3] != "COMPLETED"
        or isinstance(first[5], bool)
        or not isinstance(first[5], int)
        or not 0 <= first[5] <= 500
        or not isinstance(first[8], bool)
    ):
        raise CreatorProfilePostgresDatabaseError("SERVICE_UNAVAILABLE")
    captured_at = first[4]
    candidate_count = int(first[5])
    allowlist_sha256 = bytes(first[6])
    authorization_valid_until = first[7]
    _require_utc(captured_at, "match captured_at")
    _require_utc(
        authorization_valid_until,
        "match authorization_valid_until",
    )
    if authorization_valid_until <= captured_at:
        raise CreatorProfilePostgresDatabaseError("SERVICE_UNAVAILABLE")
    _require_digest(allowlist_sha256, "match allowlist hash")
    common = (
        request.match_run_id,
        request.workload_id,
        1,
        "COMPLETED",
        captured_at,
        candidate_count,
        allowlist_sha256,
        authorization_valid_until,
        first[8],
    )
    for row in rows:
        row_common = (
            row[0],
            row[1],
            int(row[2]),
            row[3],
            row[4],
            int(row[5]),
            bytes(row[6]),
            row[7],
            row[8],
        )
        if row_common != common:
            raise CreatorProfilePostgresDatabaseError("SERVICE_UNAVAILABLE")

    snapshots = []
    if candidate_count == 0:
        if len(rows) != 1 or any(value is not None for value in first[9:]):
            raise CreatorProfilePostgresDatabaseError("SERVICE_UNAVAILABLE")
    else:
        if len(rows) != candidate_count:
            raise CreatorProfilePostgresDatabaseError("SERVICE_UNAVAILABLE")
        for expected_ordinal, row in enumerate(rows, start=1):
            if row[9] != expected_ordinal or any(
                value is None for value in row[10:]
            ):
                raise CreatorProfilePostgresDatabaseError(
                    "SERVICE_UNAVAILABLE"
                )
            canonical = bytes(row[15])
            try:
                canonical_root = json.loads(canonical.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise CreatorProfilePostgresDatabaseError(
                    "SERVICE_UNAVAILABLE"
                ) from error
            if (
                not isinstance(canonical_root, Mapping)
                or set(canonical_root)
                != {
                    "profile_schema_version",
                    "canonicalization_version",
                    "profile_id",
                    "version_no",
                    "taxonomy_bundle_id",
                    "content",
                }
                or isinstance(canonical_root["profile_schema_version"], bool)
                or canonical_root["profile_schema_version"] != 1
                or canonical_root["canonicalization_version"]
                != "profile-version-json-v1"
                or canonical_root["profile_id"] != str(row[11])
                or isinstance(canonical_root["version_no"], bool)
                or canonical_root["version_no"] != int(row[13])
                or canonical_root["taxonomy_bundle_id"] != str(row[14])
                or not isinstance(canonical_root["content"], Mapping)
                or canonical_root != row[16]
            ):
                raise CreatorProfilePostgresDatabaseError(
                    "SERVICE_UNAVAILABLE"
                )
            content = freeze_profile_content(
                canonical_root["content"],
                for_publish=True,
            )
            reconstructed = canonical_profile_version_bytes(
                profile_id=str(row[11]),
                version_no=int(row[13]),
                taxonomy_bundle_id=str(row[14]),
                content=content,
            )
            digest = bytes(row[17])
            if (
                not hmac_compare(reconstructed, canonical)
                or not hmac_compare(
                    hashlib.sha256(reconstructed).digest(),
                    digest,
                )
            ):
                raise CreatorProfilePostgresDatabaseError(
                    "SERVICE_UNAVAILABLE"
                )
            snapshots.append(
                CreatorProfilePostgresMatchInput(
                    creator_user_id=row[10],
                    profile_id=row[11],
                    profile_version_id=row[12],
                    version_no=int(row[13]),
                    taxonomy_bundle_id=row[14],
                    canonical_profile_version_bytes=canonical,
                    content=content,
                    content_sha256=digest,
                )
            )
    expected_allowlist = hashlib.sha256(
        (
            "profile-match-allowlist-v1|"
            + str(candidate_count)
            + "|"
            + ",".join(str(snapshot.profile_id) for snapshot in snapshots)
        ).encode("utf-8")
    ).digest()
    if not hmac_compare(expected_allowlist, allowlist_sha256):
        raise CreatorProfilePostgresDatabaseError("SERVICE_UNAVAILABLE")
    return CreatorProfilePostgresMatchCaptureResult(
        match_run_id=request.match_run_id,
        workload_id=request.workload_id,
        capture_contract_version=1,
        status="COMPLETED",
        captured_at=captured_at,
        authorization_valid_until=authorization_valid_until,
        candidate_count=candidate_count,
        allowlist_sha256=allowlist_sha256,
        replayed=first[8],
        snapshots=tuple(snapshots),
        statement_count=1,
    )


def _decode_derived_match_capture_rows(
    request: CreatorProfilePostgresDerivedMatchCaptureRequest,
    rows: Tuple[Tuple[Any, ...], ...],
) -> CreatorProfilePostgresDerivedMatchCaptureResult:
    if not rows or any(len(row) != 24 for row in rows):
        raise CreatorProfilePostgresDatabaseError("SERVICE_UNAVAILABLE")
    first = rows[0]
    if (
        first[0] != request.match_run_id
        or first[1] != request.workload_id
        or isinstance(first[2], bool)
        or int(first[2]) != 2
        or first[3] != "COMPLETED"
        or isinstance(first[5], bool)
        or not isinstance(first[5], int)
        or not 0 <= first[5] <= 500
        or not isinstance(first[8], bool)
    ):
        raise CreatorProfilePostgresDatabaseError("SERVICE_UNAVAILABLE")
    captured_at = first[4]
    candidate_count = int(first[5])
    allowlist_sha256 = bytes(first[6])
    authorization_valid_until = first[7]
    try:
        _require_utc(captured_at, "derived captured_at")
        _require_utc(
            authorization_valid_until,
            "derived authorization_valid_until",
        )
        _require_digest(allowlist_sha256, "derived allowlist hash")
    except ValueError as error:
        raise CreatorProfilePostgresDatabaseError(
            "SERVICE_UNAVAILABLE"
        ) from error
    if authorization_valid_until <= captured_at:
        raise CreatorProfilePostgresDatabaseError("SERVICE_UNAVAILABLE")
    common = (
        request.match_run_id,
        request.workload_id,
        2,
        "COMPLETED",
        captured_at,
        candidate_count,
        allowlist_sha256,
        authorization_valid_until,
        first[8],
    )
    for row in rows:
        if (
            row[0],
            row[1],
            int(row[2]),
            row[3],
            row[4],
            int(row[5]),
            bytes(row[6]),
            row[7],
            row[8],
        ) != common:
            raise CreatorProfilePostgresDatabaseError("SERVICE_UNAVAILABLE")

    snapshots = []
    if candidate_count == 0:
        if len(rows) != 1 or any(value is not None for value in first[9:]):
            raise CreatorProfilePostgresDatabaseError("SERVICE_UNAVAILABLE")
    else:
        if len(rows) != candidate_count:
            raise CreatorProfilePostgresDatabaseError("SERVICE_UNAVAILABLE")
        for expected_ordinal, row in enumerate(rows, start=1):
            if row[9] != expected_ordinal or any(
                value is None for value in row[10:]
            ):
                raise CreatorProfilePostgresDatabaseError(
                    "SERVICE_UNAVAILABLE"
                )
            try:
                raw_bytes = bytes(row[15])
                raw_document = json.loads(raw_bytes.decode("utf-8"))
                raw_content = freeze_profile_content(
                    raw_document["content"],
                    for_publish=True,
                )
                reconstructed_raw = canonical_profile_version_bytes(
                    profile_id=str(row[11]),
                    version_no=int(row[13]),
                    taxonomy_bundle_id=str(row[14]),
                    content=raw_content,
                )
                raw_sha256 = bytes(row[17])
                if (
                    not isinstance(raw_document, Mapping)
                    or set(raw_document)
                    != {
                        "profile_schema_version",
                        "canonicalization_version",
                        "profile_id",
                        "version_no",
                        "taxonomy_bundle_id",
                        "content",
                    }
                    or raw_document["content"] != row[16]
                    or not hmac_compare(reconstructed_raw, raw_bytes)
                    or not hmac_compare(
                        hashlib.sha256(raw_bytes).digest(),
                        raw_sha256,
                    )
                ):
                    raise ValueError("raw Profile snapshot mismatch")

                if (
                    isinstance(row[18], bool)
                    or int(row[18]) != 1
                    or row[19] != "profile-match-input-json-v1"
                ):
                    raise ValueError("derived input contract mismatch")
                derived_bytes = bytes(row[20])
                derived_document = json.loads(derived_bytes.decode("utf-8"))
                _validate_derived_input_document(
                    derived_document,
                    creator_user_id=row[10],
                    profile_id=row[11],
                    profile_version_id=row[12],
                    profile_content_sha256=raw_sha256,
                    evidence_version_digest=bytes(row[23]),
                )
                if (
                    derived_document != row[21]
                    or not hmac_compare(
                        _canonical_json_bytes(derived_document),
                        derived_bytes,
                    )
                ):
                    raise ValueError("derived Profile canonical bytes mismatch")
                derived_sha256 = bytes(row[22])
                if not hmac_compare(
                    hashlib.sha256(derived_bytes).digest(),
                    derived_sha256,
                ):
                    raise ValueError("derived Profile hash mismatch")
                frozen_derived = _freeze_json_document(derived_document)
            except (
                KeyError,
                TypeError,
                ValueError,
                UnicodeDecodeError,
                json.JSONDecodeError,
            ) as error:
                raise CreatorProfilePostgresDatabaseError(
                    "SERVICE_UNAVAILABLE"
                ) from error
            snapshots.append(
                CreatorProfilePostgresDerivedMatchInput(
                    creator_user_id=row[10],
                    profile_id=row[11],
                    profile_version_id=row[12],
                    version_no=int(row[13]),
                    taxonomy_bundle_id=row[14],
                    canonical_profile_version_bytes=raw_bytes,
                    profile_content=raw_content,
                    profile_content_sha256=raw_sha256,
                    derived_schema_version=1,
                    derived_canonicalization_version=row[19],
                    canonical_derived_input_bytes=derived_bytes,
                    derived_input=frozen_derived,
                    derived_input_sha256=derived_sha256,
                    evidence_version_digest=bytes(row[23]),
                )
            )
    expected_allowlist = hashlib.sha256(
        (
            "profile-derived-match-allowlist-v1|"
            + str(candidate_count)
            + "|"
            + ",".join(str(snapshot.profile_id) for snapshot in snapshots)
        ).encode("utf-8")
    ).digest()
    if not hmac_compare(expected_allowlist, allowlist_sha256):
        raise CreatorProfilePostgresDatabaseError("SERVICE_UNAVAILABLE")
    return CreatorProfilePostgresDerivedMatchCaptureResult(
        match_run_id=request.match_run_id,
        workload_id=request.workload_id,
        capture_contract_version=2,
        status="COMPLETED",
        captured_at=captured_at,
        candidate_count=candidate_count,
        allowlist_sha256=allowlist_sha256,
        authorization_valid_until=authorization_valid_until,
        replayed=first[8],
        snapshots=tuple(snapshots),
        statement_count=1,
    )


def _map_match_capture_error(error: BaseException) -> CreatorProfilePostgresDatabaseError:
    sqlstate = getattr(error, "sqlstate", None)
    if sqlstate == "42501":
        return CreatorProfilePostgresDatabaseError("ACCESS_DENIED")
    if sqlstate == "54000":
        return CreatorProfilePostgresDatabaseError(
            "MATCH_CANDIDATE_LIMIT_EXCEEDED"
        )
    diagnostic = getattr(error, "diag", None)
    if getattr(diagnostic, "constraint_name", None) in {
        "ck_profile_match_capture_binding",
        "ck_profile_derived_match_capture_binding",
    }:
        return CreatorProfilePostgresDatabaseError(
            "CAPTURE_BINDING_MISMATCH"
        )
    return CreatorProfilePostgresDatabaseError("SERVICE_UNAVAILABLE")


_SQL_LOCK_CREATOR_PROFILE_AUTHORITY = (
    "SELECT user_id,creator_grant_id,current_bundle_id,"
    "authority_marker_sha256,marker_matches "
    "FROM iam_api.lock_creator_profile_self_v1(%s,%s,%s,%s)"
)

_SQL_LOCK_PROFILE_GRAPH = (
    "WITH locked_root AS MATERIALIZED ("
    " SELECT id,owner_user_id,status,aggregate_version,"
    " current_draft_version_id,current_published_version_id "
    " FROM profile.creator_profiles WHERE id=%s FOR UPDATE"
    "), locked_versions AS MATERIALIZED ("
    " SELECT id,version_no,status,taxonomy_bundle_id,content_sha256 "
    " FROM profile.profile_versions "
    " WHERE profile_id=(SELECT id FROM locked_root) "
    " ORDER BY version_no FOR UPDATE"
    ") SELECT root.id,root.owner_user_id,root.status,root.aggregate_version,"
    "root.current_draft_version_id,root.current_published_version_id,"
    "COALESCE((SELECT jsonb_agg(jsonb_build_object("
    "'id',version.id,'version_no',version.version_no,'status',version.status,"
    "'taxonomy_bundle_id',version.taxonomy_bundle_id,"
    "'content_sha256',encode(version.content_sha256,'hex')) "
    "ORDER BY version.version_no) FROM locked_versions AS version),'[]'::jsonb) "
    "FROM locked_root AS root"
)

_SQL_CLAIM_PROFILE_RECEIPT = (
    "WITH attempted AS ("
    " INSERT INTO profile.command_receipts ("
    " id,principal_kind,principal_id,command_name,command_version,"
    " idempotency_key_digest_key_id,idempotency_key_digest,payload_hash_key_id,"
    " canonicalization_version,payload_hash,target_profile_id,"
    " expected_aggregate_version,status,safe_response_body,"
    " response_schema_version,completed_aggregate_version,created_at,"
    " retain_until,completed_at) VALUES ("
    " %s,'USER',%s,%s,1,%s,%s,%s,%s,%s,%s,%s,'IN_PROGRESS',"
    " NULL,NULL,NULL,transaction_timestamp(),%s,NULL) "
    " ON CONFLICT DO NOTHING "
    " RETURNING status,payload_hash,safe_response_body,"
    " completed_aggregate_version,true AS inserted"
    "), chosen AS ("
    " SELECT * FROM attempted UNION ALL "
    " SELECT status,payload_hash,safe_response_body,"
    " completed_aggregate_version,false AS inserted "
    " FROM profile.command_receipts WHERE principal_kind='USER' "
    " AND principal_id=%s AND command_name=%s AND command_version=1 "
    " AND idempotency_key_digest_key_id=%s AND idempotency_key_digest=%s "
    " AND NOT EXISTS (SELECT 1 FROM attempted)"
    ") SELECT status,payload_hash,safe_response_body,"
    "completed_aggregate_version,inserted FROM chosen LIMIT 1"
)

_SQL_INSERT_PROFILE_ROOT = (
    "INSERT INTO profile.creator_profiles ("
    "id,owner_user_id,status,aggregate_version,current_draft_version_id,"
    "current_published_version_id,paused_at,pause_reason_code,archived_at,"
    "archive_reason_code,created_at,updated_at) VALUES ("
    "%s,%s,'DRAFT',1,NULL,NULL,NULL,NULL,NULL,NULL,"
    "transaction_timestamp(),transaction_timestamp()) "
    "RETURNING status,aggregate_version"
)

_SQL_DISCARD_PROFILE_DRAFT = (
    "UPDATE profile.profile_versions SET status='DISCARDED' "
    "WHERE id=%s AND profile_id=%s AND status='DRAFT' RETURNING id"
)

_SQL_INSERT_PROFILE_DRAFT = (
    "INSERT INTO profile.profile_versions ("
    "id,profile_id,version_no,status,based_on_profile_version_id,"
    "schema_version,canonicalization_version,taxonomy_bundle_id,"
    "canonical_content,content,content_sha256,created_by_user_id,created_at,"
    "published_at,confirmed) "
    "SELECT %s,%s,%s,'DRAFT',%s,1,'profile-version-json-v1',%s,%s,%s::jsonb,"
    "%s,%s,transaction_timestamp(),NULL,false "
    "WHERE EXISTS (SELECT 1 FROM profile.taxonomy_bundle_markers "
    "WHERE id=%s AND status='ACTIVE') RETURNING id"
)

_SQL_UPDATE_PROFILE_DRAFT_ROOT = (
    "UPDATE profile.creator_profiles SET current_draft_version_id=%s,"
    "aggregate_version=aggregate_version+1,updated_at=transaction_timestamp() "
    "WHERE id=%s AND aggregate_version=%s AND status IN ('DRAFT','ACTIVE') "
    "RETURNING status,aggregate_version"
)

_SQL_SUPERSEDE_PROFILE_VERSION = (
    "UPDATE profile.profile_versions SET status='SUPERSEDED',confirmed=true "
    "WHERE id=%s AND profile_id=%s AND status='PUBLISHED' RETURNING id,status"
)

_SQL_PUBLISH_PROFILE_VERSION = (
    "UPDATE profile.profile_versions SET status='PUBLISHED',"
    "published_at=transaction_timestamp(),confirmed=true "
    "WHERE id=%s AND profile_id=%s AND status='DRAFT' RETURNING id,status"
)

_SQL_UPDATE_PROFILE_PUBLISHED_ROOT = (
    "UPDATE profile.creator_profiles SET status='ACTIVE',"
    "current_published_version_id=%s,current_draft_version_id=NULL,"
    "paused_at=NULL,pause_reason_code=NULL,aggregate_version=aggregate_version+1,"
    "updated_at=transaction_timestamp() "
    "WHERE id=%s AND aggregate_version=%s AND status IN ('DRAFT','ACTIVE') "
    "RETURNING status,aggregate_version"
)

_SQL_PAUSE_PROFILE_ROOT = (
    "UPDATE profile.creator_profiles SET status='PAUSED',"
    "paused_at=transaction_timestamp(),pause_reason_code=%s,"
    "aggregate_version=aggregate_version+1,updated_at=transaction_timestamp() "
    "WHERE id=%s AND aggregate_version=%s AND status='ACTIVE' "
    "RETURNING status,aggregate_version"
)

_SQL_RESUME_PROFILE_ROOT = (
    "UPDATE profile.creator_profiles SET status='ACTIVE',paused_at=NULL,"
    "pause_reason_code=NULL,aggregate_version=aggregate_version+1,"
    "updated_at=transaction_timestamp() "
    "WHERE id=%s AND aggregate_version=%s AND status='PAUSED' "
    "RETURNING status,aggregate_version"
)

_SQL_RETIRE_PROFILE_VERSIONS = (
    "UPDATE profile.profile_versions SET status=CASE "
    "WHEN status='DRAFT' THEN 'DISCARDED' ELSE 'RETIRED' END "
    "WHERE profile_id=%s AND status IN ('DRAFT','PUBLISHED') RETURNING id"
)

_SQL_ARCHIVE_PROFILE_ROOT = (
    "UPDATE profile.creator_profiles SET status='ARCHIVED',"
    "current_draft_version_id=NULL,current_published_version_id=NULL,"
    "paused_at=NULL,pause_reason_code=NULL,archived_at=transaction_timestamp(),"
    "archive_reason_code=%s,aggregate_version=aggregate_version+1,"
    "updated_at=transaction_timestamp() "
    "WHERE id=%s AND aggregate_version=%s AND status<>'ARCHIVED' "
    "RETURNING status,aggregate_version"
)

_SQL_INSERT_PROFILE_AUDIT = (
    "INSERT INTO audit.audit_events ("
    "event_id,occurred_at,actor_kind,actor_id,original_actor_id,action_code,"
    "target_kind,target_id,organization_id,before_status,after_status,"
    "before_version,after_version,role_code,purpose_code,reason_code,"
    "auth_strength_code,result_code,command_id,correlation_id,causation_id,"
    "trace_id,safe_attributes) VALUES ("
    "%s,transaction_timestamp(),'USER',%s,%s,%s,'CreatorProfile',%s,NULL,"
    "%s,%s,%s,%s,'CREATOR',NULL,%s,NULL,'SUCCEEDED',%s,%s,%s,%s,'{}'::jsonb)"
)

_SQL_INSERT_PROFILE_OUTBOX = (
    "INSERT INTO infra.outbox_events ("
    "event_id,event_type,schema_version,occurred_at,aggregate_type,aggregate_id,"
    "aggregate_version,actor_kind,actor_id,original_actor_id,correlation_id,"
    "causation_id,trace_id,organization_id,payload,delivery_status,attempt_count,"
    "available_at,lease_owner,lease_until,published_at,last_error_code,created_at) "
    "VALUES (%s,%s,1,transaction_timestamp(),'CreatorProfile',%s,%s,'USER',"
    "%s,%s,%s,%s,%s,NULL,%s::jsonb,'PENDING',0,transaction_timestamp(),"
    "NULL,NULL,NULL,NULL,transaction_timestamp())"
)

_SQL_COMPLETE_PROFILE_RECEIPT = (
    "UPDATE profile.command_receipts SET status='COMPLETED',"
    "safe_response_body=%s::jsonb,response_schema_version=1,"
    "completed_aggregate_version=%s,completed_at=transaction_timestamp() "
    "WHERE id=%s AND status='IN_PROGRESS' RETURNING id"
)

_SQL_DISCOVER_AND_CAPTURE_PROFILE_MATCH_INPUTS = (
    "SELECT * FROM "
    "profile_api.discover_and_capture_creator_profile_match_inputs_v1("
    "%s,%s,%s)"
)

_SQL_DISCOVER_AND_CAPTURE_DERIVED_PROFILE_MATCH_INPUTS = (
    "SELECT * FROM "
    "profile_api.discover_and_capture_derived_creator_match_inputs_v1("
    "%s,%s,%s,%s,%s)"
)


def _prepare_connection(
    connection: Any,
    *,
    expected_role: str,
    required_server_major: int,
    required_schema_head_version: int,
) -> None:
    connection.execute("RESET ROLE")
    connection.execute("RESET ALL")
    connection.execute("DISCARD TEMP")
    if expected_role == "profile_matcher":
        row = connection.execute(
            "SELECT session_user,current_user,"
            "current_setting('server_version_num')::integer/10000,"
            "current_setting('transaction_read_only')"
        ).fetchone()
        expected_row = (
            expected_role,
            expected_role,
            required_server_major,
            "off",
        )
    else:
        row = connection.execute(
            "SELECT session_user,current_user,"
            "current_setting('server_version_num')::integer/10000,"
            "current_setting('transaction_read_only'),"
            "component,current_schema_version,schema_head_version,"
            "min_app_compatible_version,max_app_compatible_version "
            "FROM profile.schema_compatibility"
        ).fetchone()
        expected_row = (
            expected_role,
            expected_role,
            required_server_major,
            "off",
            "profile",
            required_schema_head_version,
            required_schema_head_version,
            required_schema_head_version,
            required_schema_head_version,
        )
    if row != expected_row:
        raise CreatorProfilePostgresConfigurationError(
            "PROFILE_POSTGRES_CONNECTION_INVALID"
        )


def _reset_and_release(
    connection: Any,
    *,
    source: CreatorProfilePostgresConnectionSource,
    expected_role: str,
) -> None:
    connection.execute("RESET ROLE")
    connection.execute("RESET ALL")
    connection.execute("DISCARD TEMP")
    row = connection.execute(
        "SELECT session_user,current_user,"
        "NULLIF(current_setting('app.scope_kind',true),''),"
        "NULLIF(current_setting('app.actor_user_id',true),''),"
        "NULLIF(current_setting('app.profile_id',true),''),"
        "NULLIF(current_setting('app.match_run_id',true),''),"
        "NULLIF(current_setting('app.workload_id',true),''),"
        "NULLIF(current_setting('app.match_authorization_digest',true),''),"
        "NULLIF(current_setting('app.authorization_digest',true),''),"
        "NULLIF(current_setting('app.demand_match_context_sha256',true),''),"
        "NULLIF(current_setting('app.profile_match_taxonomy_bundle_id',true),''),"
        "NULLIF(current_setting('app.profile_match_candidate_user_id',true),''),"
        "NULLIF(current_setting('app.profile_match_candidate_profile_id',true),'')"
    ).fetchone()
    if row != (
        expected_role,
        expected_role,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    ):
        raise CreatorProfilePostgresConfigurationError(
            "PROFILE_POSTGRES_RESET_FAILED"
        )
    source.release(connection)


def _set_writer_scope(
    connection: Any,
    request: CreatorProfilePostgresCommand,
    settings: CreatorProfilePostgresSettings,
) -> None:
    values = (
        ("TimeZone", "UTC"),
        ("lock_timeout", f"{settings.lock_timeout_ms}ms"),
        ("statement_timeout", f"{settings.statement_timeout_ms}ms"),
        (
            "idle_in_transaction_session_timeout",
            f"{settings.idle_in_transaction_timeout_ms}ms",
        ),
        ("app.scope_kind", "PROFILE_SELF"),
        ("app.operation", _operation_guc(request.operation)),
        ("app.actor_user_id", str(request.scope.actor_user_id)),
        ("app.session_id", str(request.scope.session_id)),
        ("app.profile_id", str(request.scope.profile_id)),
        ("app.command_id", str(request.scope.command_id)),
        ("app.command_name", request.operation.value),
        ("app.command_version", "1"),
        (
            "app.idempotency_key_digest_key_id",
            request.receipt.idempotency_key_digest_key_id,
        ),
        (
            "app.idempotency_key_digest",
            request.receipt.idempotency_key_digest.hex(),
        ),
        (
            "app.expected_aggregate_version",
            "" if request.expected_aggregate_version is None else str(
                request.expected_aggregate_version
            ),
        ),
        ("app.causation_id", str(request.scope.causation_id)),
    )
    for name, value in values:
        connection.execute(
            "SELECT pg_catalog.set_config(%s,%s,true)",
            (name, value),
        )


def _set_matcher_scope(
    connection: Any,
    request: CreatorProfilePostgresMatchCaptureRequest,
    settings: CreatorProfilePostgresSettings,
) -> None:
    values = (
        ("TimeZone", "UTC"),
        ("lock_timeout", f"{settings.lock_timeout_ms}ms"),
        ("statement_timeout", f"{settings.statement_timeout_ms}ms"),
        (
            "idle_in_transaction_session_timeout",
            f"{settings.idle_in_transaction_timeout_ms}ms",
        ),
        ("app.scope_kind", "PROFILE_MATCH_CAPTURE"),
        ("app.operation", "CAPTURE_MATCH_INPUTS"),
        ("app.match_run_id", str(request.match_run_id)),
        ("app.workload_id", str(request.workload_id)),
        ("app.match_authorization_digest", request.authorization_digest.hex()),
    )
    for name, value in values:
        connection.execute(
            "SELECT pg_catalog.set_config(%s,%s,true)",
            (name, value),
        )


def _set_derived_matcher_scope(
    connection: Any,
    request: CreatorProfilePostgresDerivedMatchCaptureRequest,
    settings: CreatorProfilePostgresSettings,
) -> None:
    values = (
        ("TimeZone", "UTC"),
        ("lock_timeout", f"{settings.lock_timeout_ms}ms"),
        ("statement_timeout", f"{settings.statement_timeout_ms}ms"),
        (
            "idle_in_transaction_session_timeout",
            f"{settings.idle_in_transaction_timeout_ms}ms",
        ),
        ("app.scope_kind", "PROFILE_MATCH_DERIVATION"),
        ("app.operation", "CAPTURE_DERIVED_MATCH_INPUTS"),
        ("app.match_run_id", str(request.match_run_id)),
        ("app.workload_id", str(request.workload_id)),
        ("app.authorization_digest", request.authorization_digest.hex()),
        (
            "app.demand_match_context_sha256",
            request.demand_match_context_sha256.hex(),
        ),
    )
    for name, value in values:
        connection.execute(
            "SELECT pg_catalog.set_config(%s,%s,true)",
            (name, value),
        )


def _operation_guc(operation: CreatorProfilePostgresOperation) -> str:
    return {
        CreatorProfilePostgresOperation.CREATE: "CREATE_PROFILE",
        CreatorProfilePostgresOperation.SAVE_DRAFT: "SAVE_PROFILE_DRAFT",
        CreatorProfilePostgresOperation.PUBLISH: "PUBLISH_PROFILE",
        CreatorProfilePostgresOperation.PAUSE: "PAUSE_PROFILE",
        CreatorProfilePostgresOperation.RESUME: "RESUME_PROFILE",
        CreatorProfilePostgresOperation.ARCHIVE: "ARCHIVE_PROFILE",
    }[operation]


def _version_by_id(
    versions: Tuple[Mapping[str, Any], ...],
    version_id: Optional[UUID],
) -> Optional[Mapping[str, Any]]:
    if version_id is None:
        return None
    for version in versions:
        if UUID(str(version["id"])) == version_id:
            return version
    return None


def _valid_hold(
    request: CreatorProfilePostgresCommand,
    content_sha256: bytes,
) -> bool:
    hold = request.hold
    return bool(
        hold is not None
        and hmac_compare(hold.content_sha256, content_sha256)
        and hold.valid_until > datetime.now(timezone.utc)
        and hold.evaluated_at <= datetime.now(timezone.utc)
    )


def hmac_compare(left: bytes, right: bytes) -> bool:
    return isinstance(left, bytes) and isinstance(right, bytes) and hmac.compare_digest(
        left,
        right,
    )


def _audit_action(operation: CreatorProfilePostgresOperation) -> str:
    return {
        CreatorProfilePostgresOperation.CREATE: "PROFILE_CREATED",
        CreatorProfilePostgresOperation.SAVE_DRAFT: "PROFILE_DRAFT_SAVED",
        CreatorProfilePostgresOperation.PUBLISH: "PROFILE_PUBLISHED",
        CreatorProfilePostgresOperation.PAUSE: "PROFILE_PAUSED",
        CreatorProfilePostgresOperation.RESUME: "PROFILE_RESUMED",
        CreatorProfilePostgresOperation.ARCHIVE: "PROFILE_ARCHIVED",
    }[operation]


def _audit_checkpoint(
    operation: CreatorProfilePostgresOperation,
) -> CreatorProfilePostgresWriteCheckpoint:
    return {
        CreatorProfilePostgresOperation.CREATE:
            CreatorProfilePostgresWriteCheckpoint.AUDIT_PROFILE_CREATED,
        CreatorProfilePostgresOperation.SAVE_DRAFT:
            CreatorProfilePostgresWriteCheckpoint.AUDIT_PROFILE_DRAFT_SAVED,
        CreatorProfilePostgresOperation.PUBLISH:
            CreatorProfilePostgresWriteCheckpoint.AUDIT_PROFILE_PUBLISHED,
        CreatorProfilePostgresOperation.PAUSE:
            CreatorProfilePostgresWriteCheckpoint.AUDIT_PROFILE_PAUSED,
        CreatorProfilePostgresOperation.RESUME:
            CreatorProfilePostgresWriteCheckpoint.AUDIT_PROFILE_RESUMED,
        CreatorProfilePostgresOperation.ARCHIVE:
            CreatorProfilePostgresWriteCheckpoint.AUDIT_PROFILE_ARCHIVED,
    }[operation]


def _outbox_checkpoint(
    operation: CreatorProfilePostgresOperation,
) -> CreatorProfilePostgresWriteCheckpoint:
    return {
        CreatorProfilePostgresOperation.CREATE:
            CreatorProfilePostgresWriteCheckpoint.OUTBOX_PROFILE_CREATED,
        CreatorProfilePostgresOperation.PUBLISH:
            CreatorProfilePostgresWriteCheckpoint.OUTBOX_PROFILE_PUBLISHED,
        CreatorProfilePostgresOperation.PAUSE:
            CreatorProfilePostgresWriteCheckpoint.OUTBOX_PROFILE_PAUSED,
        CreatorProfilePostgresOperation.RESUME:
            CreatorProfilePostgresWriteCheckpoint.OUTBOX_PROFILE_RESUMED,
        CreatorProfilePostgresOperation.ARCHIVE:
            CreatorProfilePostgresWriteCheckpoint.OUTBOX_PROFILE_ARCHIVED,
    }[operation]


def _status_payload(
    request: CreatorProfilePostgresCommand,
    status: str,
) -> Mapping[str, Any]:
    return {
        "profile_id": str(request.scope.profile_id),
        "owner_user_id": str(request.scope.actor_user_id),
        "status": status,
    }


def _event_envelope(
    request: CreatorProfilePostgresCommand,
    *,
    event_type: str,
    aggregate_version: int,
    payload: Mapping[str, Any],
) -> Mapping[str, Any]:
    return {
        "event_id": str(request.scope.outbox_event_id),
        "event_type": event_type,
        "schema_version": 1,
        "occurred_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "aggregate_type": "CreatorProfile",
        "aggregate_id": str(request.scope.profile_id),
        "aggregate_version": aggregate_version,
        "actor_kind": "USER",
        "actor_id": str(request.scope.actor_user_id),
        "original_actor_id": (
            None
            if request.scope.original_actor_id is None
            else str(request.scope.original_actor_id)
        ),
        "correlation_id": str(request.scope.correlation_id),
        "causation_id": str(request.scope.causation_id),
        "trace_id": str(request.scope.trace_id),
        "organization_id": None,
        "payload": dict(payload),
    }


def _require_uuid(value: Any, label: str) -> None:
    if not isinstance(value, UUID) or value.int == 0:
        raise ValueError(label + " must be a non-zero UUID")


def _require_key_id(value: Any, label: str) -> None:
    if (
        not isinstance(value, str)
        or not 8 <= len(value) <= 128
        or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-" for character in value)
    ):
        raise ValueError(label + " is invalid")


def _require_digest(value: Any, label: str) -> None:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError(label + " must be exactly 32 bytes")


def _require_positive_int(value: Any, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 2_147_483_647:
        raise ValueError(label + " must be a positive integer")


def _require_utc(value: Any, label: str) -> None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise ValueError(label + " must be UTC-aware")


def _require_canonical_bytes(value: Any) -> None:
    if not isinstance(value, bytes) or not value or len(value) > 512 * 1024:
        raise ValueError("canonical ProfileVersion bytes are outside v1 bounds")


_DEMAND_MATCH_CONTEXT_KEYS = frozenset(
    {
        "schema_version",
        "canonicalization_version",
        "organization_id",
        "demand_id",
        "demand_version_id",
        "taxonomy_bundle_id",
        "currency",
        "minimum_amount_minor",
        "maximum_amount_minor",
        "allowed_region_codes",
        "required_language_codes",
        "required_work_mode_code",
        "data_sensitivity_code",
        "ai_use_code",
    }
)
_DERIVED_PROFILE_INPUT_KEYS = frozenset(
    {
        "creator_user_id",
        "profile_id",
        "profile_version_id",
        "profile_content_sha256",
        "evidence_version_digest",
        "status",
        "interest_problem_type_codes",
        "interest_domain_codes",
        "interest_task_codes",
        "interest_intensity",
        "prohibited_domain_codes",
        "prohibited_task_codes",
        "skills",
        "available_from",
        "available_weekly_hours",
        "available_duration_weeks",
        "currency",
        "within_offered_budget",
        "private_floor_evidence_digest",
        "allowed_data_sensitivity_codes",
        "ai_use_code",
        "language_codes",
        "work_mode_code",
        "region_code",
        "location_eligible",
        "conflict_of_interest",
    }
)
_MATCH_CODE = re.compile(r"[A-Z][A-Z0-9_.:-]{1,63}\Z")
_MATCH_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_MATCH_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _decode_demand_match_context(
    canonical_bytes: Any,
    expected_sha256: Any,
) -> Mapping[str, Any]:
    if (
        not isinstance(canonical_bytes, bytes)
        or not canonical_bytes
        or len(canonical_bytes) > 65_536
    ):
        raise ValueError("demand match context bytes are outside bounds")
    _require_digest(expected_sha256, "demand match context hash")
    if not hmac_compare(hashlib.sha256(canonical_bytes).digest(), expected_sha256):
        raise ValueError("demand match context hash does not match")
    try:
        value = json.loads(canonical_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("demand match context is not UTF-8 JSON") from error
    if (
        not isinstance(value, Mapping)
        or set(value) != _DEMAND_MATCH_CONTEXT_KEYS
        or not hmac_compare(_canonical_json_bytes(value), canonical_bytes)
        or isinstance(value["schema_version"], bool)
        or value["schema_version"] != 1
        or value["canonicalization_version"]
        != "profile-match-demand-context-json-v1"
    ):
        raise ValueError("demand match context contract is invalid")
    for key in (
        "organization_id",
        "demand_id",
        "demand_version_id",
        "taxonomy_bundle_id",
    ):
        try:
            parsed = UUID(value[key])
        except (TypeError, ValueError, AttributeError) as error:
            raise ValueError("demand match context identifier is invalid") from error
        if parsed.int == 0 or str(parsed) != value[key]:
            raise ValueError("demand match context identifier is invalid")
    if (
        not isinstance(value["currency"], str)
        or re.fullmatch(r"[A-Z]{3}", value["currency"]) is None
    ):
        raise ValueError("demand match context currency is invalid")
    for key in ("minimum_amount_minor", "maximum_amount_minor"):
        amount = value[key]
        if (
            isinstance(amount, bool)
            or not isinstance(amount, int)
            or not 0 <= amount <= 9_007_199_254_740_991
        ):
            raise ValueError("demand match context amount is invalid")
    if value["minimum_amount_minor"] > value["maximum_amount_minor"]:
        raise ValueError("demand match context amount range is invalid")
    for key in ("allowed_region_codes", "required_language_codes"):
        _validate_code_array(value[key], maximum=100)
    if (
        not isinstance(value["required_work_mode_code"], str)
        or _MATCH_CODE.fullmatch(value["required_work_mode_code"]) is None
        or value["data_sensitivity_code"]
        not in {"PUBLIC", "INTERNAL", "HIGH", "RESTRICTED"}
        or value["ai_use_code"]
        not in {"PROHIBITED", "OPTIONAL", "REQUIRED"}
    ):
        raise ValueError("demand match context code is invalid")
    return value


def _validate_code_array(value: Any, *, maximum: int) -> None:
    if (
        not isinstance(value, list)
        or len(value) > maximum
        or any(
            not isinstance(item, str) or _MATCH_CODE.fullmatch(item) is None
            for item in value
        )
        or value != sorted(set(value), key=lambda item: item.encode("utf-8"))
    ):
        raise ValueError("match code array is not canonical")


def _validate_derived_input_document(
    value: Any,
    *,
    creator_user_id: UUID,
    profile_id: UUID,
    profile_version_id: UUID,
    profile_content_sha256: bytes,
    evidence_version_digest: bytes,
) -> None:
    if not isinstance(value, Mapping) or set(value) != _DERIVED_PROFILE_INPUT_KEYS:
        raise ValueError("derived Profile input keys are invalid")
    if (
        value["creator_user_id"] != str(creator_user_id)
        or value["profile_id"] != str(profile_id)
        or value["profile_version_id"] != str(profile_version_id)
        or value["profile_content_sha256"] != profile_content_sha256.hex()
        or value["evidence_version_digest"] != evidence_version_digest.hex()
        or value["status"] != "ACTIVE"
    ):
        raise ValueError("derived Profile identity binding is invalid")
    for key in (
        "interest_problem_type_codes",
        "interest_domain_codes",
        "interest_task_codes",
        "prohibited_domain_codes",
        "prohibited_task_codes",
        "language_codes",
    ):
        _validate_code_array(value[key], maximum=100)
    if (
        isinstance(value["interest_intensity"], bool)
        or not isinstance(value["interest_intensity"], int)
        or not 0 <= value["interest_intensity"] <= 4
    ):
        raise ValueError("derived interest intensity is invalid")
    skills = value["skills"]
    if not isinstance(skills, list) or len(skills) > 100:
        raise ValueError("derived skill facts are invalid")
    previous_skill = None
    for skill in skills:
        if (
            not isinstance(skill, Mapping)
            or set(skill)
            != {
                "skill_code",
                "proficiency_level",
                "evidence_trust_level",
                "evidence_bucket",
            }
            or not isinstance(skill["skill_code"], str)
            or _MATCH_CODE.fullmatch(skill["skill_code"]) is None
            or isinstance(skill["proficiency_level"], bool)
            or not isinstance(skill["proficiency_level"], int)
            or not 0 <= skill["proficiency_level"] <= 4
            or isinstance(skill["evidence_trust_level"], bool)
            or not isinstance(skill["evidence_trust_level"], int)
            or not 0 <= skill["evidence_trust_level"] <= 4
            or skill["evidence_bucket"]
            not in {"NONE", "SELF_ASSERTED", "DOCUMENTED", "VERIFIED"}
            or (
                previous_skill is not None
                and previous_skill.encode("utf-8")
                >= skill["skill_code"].encode("utf-8")
            )
        ):
            raise ValueError("derived skill fact is invalid")
        previous_skill = skill["skill_code"]
    if (
        not isinstance(value["available_from"], str)
        or _MATCH_DATE.fullmatch(value["available_from"]) is None
    ):
        raise ValueError("derived availability date is invalid")
    datetime.strptime(value["available_from"], "%Y-%m-%d")
    for key, maximum in (
        ("available_weekly_hours", 168),
        ("available_duration_weeks", 520),
    ):
        number = value[key]
        if (
            isinstance(number, bool)
            or not isinstance(number, int)
            or not 0 <= number <= maximum
        ):
            raise ValueError("derived availability amount is invalid")
    if (
        not isinstance(value["currency"], str)
        or re.fullmatch(r"[A-Z]{3}", value["currency"]) is None
        or not isinstance(value["within_offered_budget"], bool)
        or not isinstance(value["private_floor_evidence_digest"], str)
        or _MATCH_SHA256.fullmatch(value["private_floor_evidence_digest"])
        is None
    ):
        raise ValueError("derived private floor result is invalid")
    sensitivities = value["allowed_data_sensitivity_codes"]
    if (
        not isinstance(sensitivities, list)
        or sensitivities
        != sorted(
            set(sensitivities),
            key=lambda item: item.encode("utf-8") if isinstance(item, str) else b"",
        )
        or any(
            item not in {"PUBLIC", "INTERNAL", "HIGH", "RESTRICTED"}
            for item in sensitivities
        )
        or value["ai_use_code"]
        not in {"PROHIBITED", "OPTIONAL", "REQUIRED"}
        or not isinstance(value["work_mode_code"], str)
        or _MATCH_CODE.fullmatch(value["work_mode_code"]) is None
        or not isinstance(value["region_code"], str)
        or _MATCH_CODE.fullmatch(value["region_code"]) is None
        or not isinstance(value["location_eligible"], bool)
        or not isinstance(value["conflict_of_interest"], bool)
    ):
        raise ValueError("derived policy input is invalid")


def _freeze_json_document(value: Mapping[str, Any]) -> ProfileContent:
    def freeze(child: Any) -> Any:
        if isinstance(child, Mapping):
            return ProfileContent(
                tuple((str(key), freeze(item)) for key, item in child.items())
            )
        if isinstance(child, list):
            return tuple(freeze(item) for item in child)
        return child

    result = freeze(value)
    if not isinstance(result, ProfileContent):
        raise ValueError("JSON document root is invalid")
    return result
