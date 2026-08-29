"""Closed PostgreSQL 18 boundary for same-organization ORG_ADMIN writes.

The adapter deliberately has no arbitrary statement or Memory execution path.
Each public method selects one reviewed operation and invokes the IAM0035
contract-hardened database boundary inside one configured transaction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import re
import unicodedata
from typing import Any, Mapping, Optional, Protocol, Tuple
from uuid import UUID

from psycopg.pq import TransactionStatus

from ...domain.errors import IamError, IamPreconditionFailed


_DIGEST_BYTES = 32
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_MASKED_LABEL = re.compile(r"^[^\x00-\x1f\x7f]{3,80}$")
_REASON_CODE = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
_TOKEN_FORMAT = "access-invitation-token-v1"
_FUNCTION = "iam_api.execute_organization_admin_v3"
_AUTHORIZED_WRITE_RESULT_KEYS = frozenset(
    {
        "decision_code",
        "replayed",
        "safe_response",
        "response_entity_tag",
        "outbox_event",
        "secondary_outbox_event",
        "capability_reconstruction",
    }
)
_AUTHORIZED_REPLAY_RESULT_KEYS = frozenset(
    _AUTHORIZED_WRITE_RESULT_KEYS - {"secondary_outbox_event"}
)


class OrganizationAdminPostgresOperation(str, Enum):
    ISSUE_ACCESS_INVITATION = "IssueAccessInvitation"
    REVOKE_ACCESS_INVITATION = "RevokeAccessInvitation"
    SUSPEND_MEMBERSHIP = "SuspendMembership"
    RESUME_MEMBERSHIP = "ResumeMembership"
    REVOKE_MEMBERSHIP = "RevokeMembership"
    UPDATE_ORGANIZATION_PUBLIC_NAME = "UpdateOrganizationPublicName"


ORGANIZATION_ADMIN_POSTGRES_OPERATIONS: Tuple[
    OrganizationAdminPostgresOperation, ...
] = tuple(OrganizationAdminPostgresOperation)


class OrganizationAdminPostgresConnectionSource(Protocol):
    def checkout(self) -> Any: ...

    def release(self, connection: Any) -> None: ...

    def discard(self, connection: Any) -> None: ...


class OrganizationAdminPostgresSchemaValidator(Protocol):
    def validate(
        self,
        value: Mapping[str, Any],
        schema_name: Optional[str] = None,
    ) -> None: ...


class OrganizationAdminPostgresConfigurationError(RuntimeError):
    """The checked-out connection or closed runtime settings are unsafe."""


class OrganizationAdminPostgresCommitOutcomeUnknownError(RuntimeError):
    """COMMIT was sent and the caller must recover through receipt replay."""

    code = "COMMAND_OUTCOME_UNKNOWN"


class OrganizationAdminPostgresSafetyDecisionStaleError(RuntimeError):
    """The locked resume dependencies no longer match the external ALLOW."""


@dataclass(frozen=True, repr=False)
class OrganizationAdminPostgresResumeResolution:
    organization_id: UUID
    target_version: int
    snapshot_digest: bytes = field(repr=False)
    replayed: bool

    def __post_init__(self) -> None:
        if not isinstance(self.organization_id, UUID) or self.organization_id.int == 0:
            raise ValueError("organization resume organization is invalid")
        if (
            not isinstance(self.target_version, int)
            or isinstance(self.target_version, bool)
            or self.target_version < 1
        ):
            raise ValueError("organization resume target version is invalid")
        _require_digest(self.snapshot_digest, "resume snapshot digest")
        if not isinstance(self.replayed, bool):
            raise ValueError("organization resume replay marker is invalid")


@dataclass(frozen=True, repr=False)
class OrganizationAdminPostgresIssueResolution:
    organization_id: UUID
    target_version: int
    snapshot_digest: bytes = field(repr=False)
    replayed: bool
    safe_response: Optional[Mapping[str, Any]] = field(
        default=None, repr=False
    )
    response_entity_tag: Optional[str] = None
    capability_reconstruction: Optional[Mapping[str, Any]] = field(
        default=None, repr=False
    )

    def __post_init__(self) -> None:
        if not isinstance(self.organization_id, UUID) or self.organization_id.int == 0:
            raise ValueError("organization issue organization is invalid")
        if (
            not isinstance(self.target_version, int)
            or isinstance(self.target_version, bool)
            or self.target_version < 1
        ):
            raise ValueError("organization issue target version is invalid")
        _require_digest(self.snapshot_digest, "issue snapshot digest")
        if not isinstance(self.replayed, bool):
            raise ValueError("organization issue replay marker is invalid")
        replay_shape = (
            isinstance(self.safe_response, Mapping)
            and isinstance(self.response_entity_tag, str)
            and self.safe_response.get("entity_tag") == self.response_entity_tag
            and isinstance(self.capability_reconstruction, Mapping)
        )
        if replay_shape is not self.replayed:
            raise ValueError("organization issue replay result is invalid")


@dataclass(frozen=True, repr=False)
class OrganizationAdminPostgresIssueHoldEvidence:
    action: str
    target_type: str
    target_id: UUID
    target_version: int
    organization_id: UUID
    policy_version: str
    evaluated_at: datetime
    valid_until: datetime
    snapshot_digest: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if (
            self.action != "IssueAccessInvitation"
            or self.target_type != "AccessInvitation"
        ):
            raise ValueError("organization issue hold action is invalid")
        if (
            not isinstance(self.target_id, UUID)
            or self.target_id.int == 0
            or not isinstance(self.organization_id, UUID)
            or self.organization_id.int == 0
            or self.target_id == self.organization_id
            or not isinstance(self.target_version, int)
            or isinstance(self.target_version, bool)
            or self.target_version != 1
            or not isinstance(self.policy_version, str)
            or _KEY_ID.fullmatch(self.policy_version) is None
        ):
            raise ValueError("organization issue hold binding is invalid")
        _require_utc(self.evaluated_at)
        _require_utc(self.valid_until)
        if self.valid_until <= self.evaluated_at:
            raise ValueError("organization issue hold deadline is invalid")
        _require_digest(self.snapshot_digest, "issue hold snapshot digest")


@dataclass(frozen=True, repr=False)
class OrganizationAdminPostgresResumeHoldEvidence:
    action: str
    target_type: str
    target_id: UUID
    target_version: int
    organization_id: UUID
    policy_version: str
    evaluated_at: datetime
    valid_until: datetime
    snapshot_digest: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if self.action != "ResumeMembership" or self.target_type != "Membership":
            raise ValueError("organization resume hold action is invalid")
        if (
            not isinstance(self.target_id, UUID)
            or self.target_id.int == 0
            or not isinstance(self.organization_id, UUID)
            or self.organization_id.int == 0
            or not isinstance(self.target_version, int)
            or isinstance(self.target_version, bool)
            or self.target_version < 1
            or not isinstance(self.policy_version, str)
            or _KEY_ID.fullmatch(self.policy_version) is None
        ):
            raise ValueError("organization resume hold binding is invalid")
        _require_utc(self.evaluated_at)
        _require_utc(self.valid_until)
        if self.valid_until <= self.evaluated_at:
            raise ValueError("organization resume hold deadline is invalid")
        _require_digest(self.snapshot_digest, "resume hold snapshot digest")


@dataclass(frozen=True)
class OrganizationAdminPostgresSettings:
    runtime_role: str = "iam_app"
    lock_timeout_ms: int = 2_000
    statement_timeout_ms: int = 10_000
    idle_in_transaction_timeout_ms: int = 15_000
    max_precommit_retries: int = 3

    def __post_init__(self) -> None:
        if self.runtime_role != "iam_app":
            raise ValueError("organization administration role must be iam_app")
        if not 1 <= self.lock_timeout_ms <= 10_000:
            raise ValueError("organization administration lock timeout is invalid")
        if not 1 <= self.statement_timeout_ms <= 30_000:
            raise ValueError("organization administration statement timeout is invalid")
        if not 1 <= self.idle_in_transaction_timeout_ms <= 30_000:
            raise ValueError("organization administration idle timeout is invalid")
        if self.max_precommit_retries != 3:
            raise ValueError("organization administration retries must be exactly three")


@dataclass(frozen=True)
class OrganizationAdminPostgresScope:
    actor_user_id: UUID
    current_session_id: UUID
    organization_id: UUID
    target_id: UUID
    command_id: UUID
    correlation_id: UUID
    causation_id: UUID
    trace_id: UUID
    original_actor_id: Optional[UUID]

    def __post_init__(self) -> None:
        required = (
            self.actor_user_id,
            self.current_session_id,
            self.organization_id,
            self.target_id,
            self.command_id,
            self.correlation_id,
            self.causation_id,
            self.trace_id,
        )
        if any(not isinstance(value, UUID) or value.int == 0 for value in required):
            raise ValueError("organization administration scope IDs must be non-zero UUIDs")
        if self.causation_id != self.command_id:
            raise ValueError("organization administration causation must be the command")
        if self.original_actor_id is not None and (
            not isinstance(self.original_actor_id, UUID)
            or self.original_actor_id.int == 0
            or self.original_actor_id == self.actor_user_id
        ):
            raise ValueError("organization administration original actor is invalid")


@dataclass(frozen=True, repr=False)
class OrganizationAdminPostgresReceiptMaterial:
    receipt_id: UUID
    idempotency_key_digest: bytes = field(repr=False)
    idempotency_key_digest_key_id: str
    payload_hash: bytes = field(repr=False)
    payload_hash_key_id: str
    retain_until: datetime
    idempotency_candidates: Tuple[Tuple[str, bytes], ...] = field(
        default=(), repr=False
    )
    payload_hash_candidates: Tuple[Tuple[str, bytes], ...] = field(
        default=(), repr=False
    )

    def __post_init__(self) -> None:
        if not isinstance(self.receipt_id, UUID) or self.receipt_id.int == 0:
            raise ValueError("organization administration receipt ID is invalid")
        _require_digest(self.idempotency_key_digest, "idempotency digest")
        _require_digest(self.payload_hash, "payload digest")
        _require_key_id(self.idempotency_key_digest_key_id)
        _require_key_id(self.payload_hash_key_id)
        _require_utc(self.retain_until)
        identities = self.idempotency_candidates or (
            (self.idempotency_key_digest_key_id, self.idempotency_key_digest),
        )
        payloads = self.payload_hash_candidates or (
            (self.payload_hash_key_id, self.payload_hash),
        )
        for label, candidates, active, maximum, unique_key_ids in (
            (
                "idempotency",
                identities,
                (self.idempotency_key_digest_key_id, self.idempotency_key_digest),
                4,
                True,
            ),
            (
                "payload",
                payloads,
                (self.payload_hash_key_id, self.payload_hash),
                16,
                False,
            ),
        ):
            if (
                not 1 <= len(candidates) <= maximum
                or candidates[0] != active
                or (
                    unique_key_ids
                    and len({key_id for key_id, _digest in candidates})
                    != len(candidates)
                )
                or len(set(candidates)) != len(candidates)
            ):
                raise ValueError(
                    f"organization administration {label} candidates are invalid"
                )
            for key_id, digest in candidates:
                _require_key_id(key_id)
                _require_digest(digest, f"{label} candidate digest")
        object.__setattr__(self, "idempotency_candidates", identities)
        object.__setattr__(self, "payload_hash_candidates", payloads)


@dataclass(frozen=True, repr=False)
class OrganizationAdminPostgresInvitationMaterial:
    recipient_contact_id: UUID
    recipient_binding_digest: bytes = field(repr=False)
    recipient_binding_digest_key_id: str
    masked_recipient_label: str
    target_role: str
    expires_at: datetime
    token_nonce: bytes = field(repr=False)
    token_key_id: str
    token_format_version: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.recipient_contact_id, UUID)
            or self.recipient_contact_id.int == 0
        ):
            raise ValueError("organization invitation contact ID is invalid")
        _require_digest(self.recipient_binding_digest, "recipient binding digest")
        _require_digest(self.token_nonce, "invitation token nonce")
        _require_key_id(self.recipient_binding_digest_key_id)
        _require_key_id(self.token_key_id)
        if (
            not isinstance(self.masked_recipient_label, str)
            or _MASKED_LABEL.fullmatch(self.masked_recipient_label) is None
            or self.target_role not in {"ORG_ADMIN", "DEMAND_OWNER"}
            or self.token_format_version != _TOKEN_FORMAT
        ):
            raise ValueError("organization invitation material is invalid")
        _require_utc(self.expires_at)


@dataclass(frozen=True)
class OrganizationAdminPostgresGeneratedIds:
    audit_event_id: UUID
    outbox_event_id: UUID
    recipient_contact_id: Optional[UUID]
    secondary_outbox_event_id: Optional[UUID] = None

    def __post_init__(self) -> None:
        required = (self.audit_event_id, self.outbox_event_id)
        if any(not isinstance(value, UUID) or value.int == 0 for value in required):
            raise ValueError("organization administration generated IDs are invalid")
        if self.audit_event_id == self.outbox_event_id:
            raise ValueError("organization administration generated IDs must be distinct")
        if self.recipient_contact_id is not None and (
            not isinstance(self.recipient_contact_id, UUID)
            or self.recipient_contact_id.int == 0
            or self.recipient_contact_id in required
        ):
            raise ValueError("organization invitation contact ID is invalid")
        if self.secondary_outbox_event_id is not None and (
            not isinstance(self.secondary_outbox_event_id, UUID)
            or self.secondary_outbox_event_id.int == 0
            or self.secondary_outbox_event_id in required
            or self.secondary_outbox_event_id == self.recipient_contact_id
        ):
            raise ValueError(
                "organization administration secondary event ID is invalid"
            )


@dataclass(frozen=True)
class OrganizationAdminPostgresDatabaseRequest:
    operation: OrganizationAdminPostgresOperation
    scope: OrganizationAdminPostgresScope
    receipt: OrganizationAdminPostgresReceiptMaterial
    expected_version: int
    generated_ids: OrganizationAdminPostgresGeneratedIds
    invitation: Optional[OrganizationAdminPostgresInvitationMaterial]
    issue_hold: Optional[OrganizationAdminPostgresIssueHoldEvidence] = None
    resume_hold: Optional[OrganizationAdminPostgresResumeHoldEvidence] = None
    reason_code: Optional[str] = None
    public_name: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.operation, OrganizationAdminPostgresOperation):
            raise ValueError("organization administration operation is not closed")
        if self.receipt.receipt_id != self.scope.command_id:
            raise ValueError("organization administration receipt must be the command")
        if (
            not isinstance(self.expected_version, int)
            or isinstance(self.expected_version, bool)
            or self.expected_version < 1
        ):
            raise ValueError("organization administration If-Match is invalid")
        issue = self.operation is OrganizationAdminPostgresOperation.ISSUE_ACCESS_INVITATION
        public_name_update = (
            self.operation
            is OrganizationAdminPostgresOperation.UPDATE_ORGANIZATION_PUBLIC_NAME
        )
        if issue:
            if (
                not isinstance(self.invitation, OrganizationAdminPostgresInvitationMaterial)
                or self.resume_hold is not None
                or self.reason_code is not None
                or self.public_name is not None
                or self.generated_ids.recipient_contact_id
                != self.invitation.recipient_contact_id
            ):
                raise ValueError("IssueAccessInvitation request shape is invalid")
            if self.issue_hold is not None and (
                not isinstance(
                    self.issue_hold, OrganizationAdminPostgresIssueHoldEvidence
                )
                or self.issue_hold.organization_id != self.scope.organization_id
                or self.issue_hold.target_id != self.scope.target_id
                or self.issue_hold.target_version != 1
            ):
                raise ValueError("issue hold evidence is not bound to the request")
            if self.scope.target_id == self.scope.command_id:
                raise ValueError("invitation and command IDs must be distinct")
        elif public_name_update:
            if (
                self.invitation is not None
                or self.issue_hold is not None
                or self.resume_hold is not None
                or self.generated_ids.recipient_contact_id is not None
                or self.generated_ids.secondary_outbox_event_id is not None
                or self.scope.target_id != self.scope.organization_id
                or self.reason_code != "PUBLIC_NAME_CORRECTION"
                or not _canonical_public_name(self.public_name)
            ):
                raise ValueError("UpdateOrganizationPublicName request shape is invalid")
        elif (
            self.invitation is not None
            or self.issue_hold is not None
            or self.generated_ids.recipient_contact_id is not None
            or self.public_name is not None
            or not isinstance(self.reason_code, str)
            or _REASON_CODE.fullmatch(self.reason_code) is None
        ):
            raise ValueError("organization lifecycle request shape is invalid")
        elif self.operation is not OrganizationAdminPostgresOperation.RESUME_MEMBERSHIP:
            if self.resume_hold is not None:
                raise ValueError("resume hold evidence is operation-scoped")
        elif self.resume_hold is not None and (
            not isinstance(
                self.resume_hold, OrganizationAdminPostgresResumeHoldEvidence
            )
            or self.resume_hold.target_id != self.scope.target_id
            or self.resume_hold.organization_id != self.scope.organization_id
        ):
            raise ValueError("resume hold evidence is not bound to the request")
        if (
            self.operation
            is OrganizationAdminPostgresOperation.REVOKE_MEMBERSHIP
        ) != (self.generated_ids.secondary_outbox_event_id is not None):
            raise ValueError(
                "organization membership role event ID is operation-scoped"
            )


@dataclass(frozen=True)
class OrganizationAdminPostgresDatabaseResult:
    operation: OrganizationAdminPostgresOperation
    replayed: bool
    safe_response: Mapping[str, Any] = field(repr=False)
    response_entity_tag: str
    capability_reconstruction: Optional[Mapping[str, Any]] = field(
        default=None, repr=False
    )


class PsycopgOrganizationAdminUnitOfWorkFactory:
    """Execute the six reviewed ORG_ADMIN programs on PostgreSQL 18."""

    def __init__(
        self,
        *,
        connections: OrganizationAdminPostgresConnectionSource,
        event_validator: OrganizationAdminPostgresSchemaValidator,
        response_validator: OrganizationAdminPostgresSchemaValidator,
        settings: OrganizationAdminPostgresSettings = OrganizationAdminPostgresSettings(),
    ) -> None:
        if not all(
            callable(getattr(connections, name, None))
            for name in ("checkout", "release", "discard")
        ):
            raise TypeError("organization administration connection source is unavailable")
        if not callable(getattr(event_validator, "validate", None)) or not callable(
            getattr(response_validator, "validate", None)
        ):
            raise TypeError("organization administration validators are unavailable")
        if not isinstance(settings, OrganizationAdminPostgresSettings):
            raise TypeError("organization administration settings are unavailable")
        self.connections = connections
        self.event_validator = event_validator
        self.response_validator = response_validator
        self.settings = settings

    def execute_issue_access_invitation(
        self, request: OrganizationAdminPostgresDatabaseRequest
    ) -> OrganizationAdminPostgresDatabaseResult:
        return self._execute(request, OrganizationAdminPostgresOperation.ISSUE_ACCESS_INVITATION)

    def execute_revoke_access_invitation(
        self, request: OrganizationAdminPostgresDatabaseRequest
    ) -> OrganizationAdminPostgresDatabaseResult:
        return self._execute(request, OrganizationAdminPostgresOperation.REVOKE_ACCESS_INVITATION)

    def execute_suspend_membership(
        self, request: OrganizationAdminPostgresDatabaseRequest
    ) -> OrganizationAdminPostgresDatabaseResult:
        return self._execute(request, OrganizationAdminPostgresOperation.SUSPEND_MEMBERSHIP)

    def execute_resume_membership(
        self, request: OrganizationAdminPostgresDatabaseRequest
    ) -> OrganizationAdminPostgresDatabaseResult:
        return self._execute(request, OrganizationAdminPostgresOperation.RESUME_MEMBERSHIP)

    def execute_revoke_membership(
        self, request: OrganizationAdminPostgresDatabaseRequest
    ) -> OrganizationAdminPostgresDatabaseResult:
        return self._execute(request, OrganizationAdminPostgresOperation.REVOKE_MEMBERSHIP)

    def execute_update_organization_public_name(
        self, request: OrganizationAdminPostgresDatabaseRequest
    ) -> OrganizationAdminPostgresDatabaseResult:
        return self._execute(
            request,
            OrganizationAdminPostgresOperation.UPDATE_ORGANIZATION_PUBLIC_NAME,
        )

    def _execute(
        self,
        request: OrganizationAdminPostgresDatabaseRequest,
        expected: OrganizationAdminPostgresOperation,
    ) -> OrganizationAdminPostgresDatabaseResult:
        if not isinstance(request, OrganizationAdminPostgresDatabaseRequest) or request.operation is not expected:
            raise ValueError("organization administration operation does not match entry point")
        for attempt in range(self.settings.max_precommit_retries + 1):
            try:
                return self._execute_once(request)
            except BaseException as error:
                if attempt < self.settings.max_precommit_retries and _retryable(error):
                    continue
                raise
        raise AssertionError("closed organization administration retry loop did not terminate")

    def _execute_once(
        self, request: OrganizationAdminPostgresDatabaseRequest
    ) -> OrganizationAdminPostgresDatabaseResult:
        connection = self.connections.checkout()
        state = "NEW"
        disposed = False
        try:
            self._validate_connection(connection)
            connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED")
            state = "BEGUN"
            self._configure(connection, request)
            state = "WRITING"
            row = connection.execute(
                f"SELECT {_FUNCTION}(%s::text,%s::uuid,%s::uuid,%s::uuid,%s::uuid,"
                "%s::uuid,%s::uuid,%s::uuid,%s::uuid,%s::uuid,%s::bigint,"
                "%s::bytea,%s::text,%s::bytea,%s::text,%s::timestamptz,"
                "%s::uuid,%s::uuid,%s::uuid,%s::uuid,%s::bytea,%s::text,%s::text,"
                "%s::timestamptz,%s::bytea,%s::text,%s::text,%s::text,"
                "%s::text,%s::text,%s::uuid,%s::bigint,%s::uuid,%s::text,"
                "%s::timestamptz,%s::timestamptz,%s::bytea,"
                "%s::text[],%s::bytea[],%s::text[],%s::bytea[],"
                "%s::text,%s::text,%s::uuid,%s::bigint,%s::uuid,%s::text,"
                "%s::timestamptz,%s::timestamptz,%s::bytea,%s::text)",
                _parameters(request),
            ).fetchone()
            result, events = _result(request.operation, row)
            response_schema = (
                "OrganizationSummaryDto"
                if request.operation
                is OrganizationAdminPostgresOperation.UPDATE_ORGANIZATION_PUBLIC_NAME
                else "AccessInvitationAdminDto"
                if request.operation in {
                    OrganizationAdminPostgresOperation.ISSUE_ACCESS_INVITATION,
                    OrganizationAdminPostgresOperation.REVOKE_ACCESS_INVITATION,
                }
                else "MembershipAdminDto"
            )
            self.response_validator.validate(result.safe_response, response_schema)
            for event in events:
                self._validate_event(event)
            state = "COMMIT_SENT"
            connection.execute("COMMIT")
            state = "COMMITTED"
        except BaseException as error:
            if state == "COMMIT_SENT":
                self.connections.discard(connection)
                disposed = True
                raise OrganizationAdminPostgresCommitOutcomeUnknownError() from error
            if state in {"BEGUN", "WRITING"}:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    self.connections.discard(connection)
                    disposed = True
                else:
                    disposed = self._release_or_discard(connection)
            else:
                self.connections.discard(connection)
                disposed = True
            raise
        else:
            disposed = self._release_or_discard(connection)
            return result
        finally:
            if not disposed:
                self.connections.discard(connection)

    def _validate_event(self, event: Mapping[str, Any]) -> None:
        try:
            self.event_validator.validate(event)
        except Exception as error:
            raise OrganizationAdminPostgresConfigurationError(
                "organization administration event contract was rejected"
            ) from error

    def _validate_connection(self, connection: Any) -> None:
        if (
            getattr(connection, "autocommit", None) is not True
            or connection.info.transaction_status != TransactionStatus.IDLE
        ):
            raise OrganizationAdminPostgresConfigurationError(
                "organization administration checkout must be transaction-idle"
            )
        identity = connection.execute(
            "SELECT current_user,session_user,"
            "current_setting('server_version_num')::integer"
        ).fetchone()
        if identity is None or identity[0:2] != (
            self.settings.runtime_role,
            self.settings.runtime_role,
        ) or identity[2] // 10_000 != 18:
            raise OrganizationAdminPostgresConfigurationError(
                "organization administration connection identity is invalid"
            )

    def _configure(
        self, connection: Any, request: OrganizationAdminPostgresDatabaseRequest
    ) -> None:
        connection.execute("SET LOCAL TIME ZONE 'UTC'")
        connection.execute(
            "SET LOCAL lock_timeout = '%dms'" % self.settings.lock_timeout_ms
        )
        connection.execute(
            "SET LOCAL statement_timeout = '%dms'" % self.settings.statement_timeout_ms
        )
        connection.execute(
            "SET LOCAL idle_in_transaction_session_timeout = '%dms'"
            % self.settings.idle_in_transaction_timeout_ms
        )
        values = (
            ("app.scope_kind", "ORGANIZATION_ADMIN"),
            ("app.operation", request.operation.value),
            ("app.actor_user_id", str(request.scope.actor_user_id)),
            ("app.session_id", str(request.scope.current_session_id)),
            ("app.organization_id", str(request.scope.organization_id)),
            ("app.target_id", str(request.scope.target_id)),
            ("app.command_id", str(request.scope.command_id)),
            ("app.expected_version", str(request.expected_version)),
        )
        for name, value in values:
            configured = connection.execute(
                "SELECT pg_catalog.set_config(%s,%s,true)", (name, value)
            ).fetchone()
            if configured != (value,):
                raise OrganizationAdminPostgresConfigurationError(
                    "organization administration context was rejected"
                )
        for name, expected in values:
            actual = connection.execute(
                "SELECT current_setting(%s,true)", (name,)
            ).fetchone()
            if actual != (expected,):
                raise OrganizationAdminPostgresConfigurationError(
                    "organization administration context readback failed"
                )

    def _release_or_discard(self, connection: Any) -> bool:
        try:
            if connection.info.transaction_status != TransactionStatus.IDLE:
                self.connections.discard(connection)
                return True
            connection.execute("RESET ALL")
            connection.execute("DISCARD TEMP")
            clean = connection.execute(
                "SELECT current_user,session_user,current_setting('app.scope_kind',true)"
            ).fetchone()
            if clean not in (
                (self.settings.runtime_role, self.settings.runtime_role, None),
                (self.settings.runtime_role, self.settings.runtime_role, ""),
            ):
                self.connections.discard(connection)
                return True
        except BaseException:
            self.connections.discard(connection)
            return True
        self.connections.release(connection)
        return True


class PsycopgOrganizationAdminTargetResolver:
    """Resolve a lifecycle target's organization through one fixed PG function.

    The returned identifier is only a transaction coordinate.  IAM0035 repeats
    all same-organization and authority checks under the write locks.
    """

    _OPERATIONS = frozenset(
        (
            "RevokeAccessInvitation",
            "SuspendMembership",
            "ResumeMembership",
            "RevokeMembership",
        )
    )

    def __init__(
        self,
        *,
        connections: OrganizationAdminPostgresConnectionSource,
        settings: OrganizationAdminPostgresSettings = OrganizationAdminPostgresSettings(),
    ) -> None:
        if not all(
            callable(getattr(connections, name, None))
            for name in ("checkout", "release", "discard")
        ) or not isinstance(settings, OrganizationAdminPostgresSettings):
            raise TypeError("organization administration target resolver is unavailable")
        self.connections = connections
        self.settings = settings

    def resolve(
        self,
        *,
        actor_user_id: str,
        session_id: str,
        target_id: str,
        operation: str,
    ) -> str:
        if operation not in self._OPERATIONS:
            raise IamError("RESOURCE_NOT_FOUND")
        try:
            actor = UUID(actor_user_id)
            session = UUID(session_id)
            target = UUID(target_id)
        except (TypeError, ValueError, AttributeError):
            raise IamError("RESOURCE_NOT_FOUND") from None
        if any(value.int == 0 for value in (actor, session, target)):
            raise IamError("RESOURCE_NOT_FOUND")
        connection = self.connections.checkout()
        begun = False
        disposed = False
        try:
            if (
                getattr(connection, "autocommit", None) is not True
                or connection.info.transaction_status != TransactionStatus.IDLE
            ):
                raise OrganizationAdminPostgresConfigurationError(
                    "organization administration resolver checkout is unsafe"
                )
            identity = connection.execute(
                "SELECT current_user,session_user,"
                "current_setting('server_version_num')::integer"
            ).fetchone()
            if identity is None or identity[0:2] != (
                self.settings.runtime_role,
                self.settings.runtime_role,
            ) or identity[2] // 10_000 != 18:
                raise OrganizationAdminPostgresConfigurationError(
                    "organization administration resolver identity is invalid"
                )
            connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY")
            begun = True
            connection.execute("SET LOCAL TIME ZONE 'UTC'")
            connection.execute(
                "SET LOCAL statement_timeout = '%dms'"
                % self.settings.statement_timeout_ms
            )
            values = (
                ("app.scope_kind", "ORGANIZATION_ADMIN_TARGET_RESOLVE"),
                ("app.operation", operation),
                ("app.actor_user_id", str(actor)),
                ("app.session_id", str(session)),
                ("app.target_id", str(target)),
            )
            for name, value in values:
                configured = connection.execute(
                    "SELECT pg_catalog.set_config(%s,%s,true)", (name, value)
                ).fetchone()
                if configured != (value,):
                    raise OrganizationAdminPostgresConfigurationError(
                        "organization administration resolver context was rejected"
                    )
            row = connection.execute(
                "SELECT iam_api.resolve_organization_admin_target_v1("
                "%s::uuid,%s::uuid,%s::uuid,%s::text)",
                (actor, session, target, operation),
            ).fetchone()
            if row is None or len(row) != 1 or not isinstance(row[0], Mapping):
                raise IamError("SERVICE_UNAVAILABLE")
            decision = row[0].get("decision_code")
            organization = row[0].get("organization_id")
            if decision != "AUTHORIZED":
                if decision not in {
                    "AUTHENTICATION_REQUIRED",
                    "SESSION_EXPIRED",
                    "MFA_STEP_UP_REQUIRED",
                    "RESOURCE_NOT_FOUND",
                    "SERVICE_UNAVAILABLE",
                }:
                    decision = "SERVICE_UNAVAILABLE"
                raise IamError(decision)
            parsed = UUID(str(organization))
            if parsed.int == 0:
                raise ValueError
            connection.execute("COMMIT")
            begun = False
        except IamError:
            if begun:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    self.connections.discard(connection)
                    disposed = True
            if not disposed:
                disposed = _clean_release(
                    self.connections, connection, self.settings.runtime_role
                )
            raise
        except BaseException:
            if begun:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    self.connections.discard(connection)
                    disposed = True
            if not disposed:
                disposed = _clean_release(
                    self.connections, connection, self.settings.runtime_role
                )
            raise IamError("SERVICE_UNAVAILABLE") from None
        else:
            disposed = _clean_release(
                self.connections, connection, self.settings.runtime_role
            )
            return str(parsed)
        finally:
            if not disposed:
                self.connections.discard(connection)

    def resolve_issue(
        self,
        *,
        actor_user_id: str,
        session_id: str,
        organization_id: str,
        target_role: str,
        idempotency_candidates: Tuple[Tuple[str, bytes], ...],
        payload_hash_candidates: Tuple[Tuple[str, bytes], ...],
    ) -> OrganizationAdminPostgresIssueResolution:
        try:
            actor = UUID(actor_user_id)
            session = UUID(session_id)
            organization = UUID(organization_id)
        except (TypeError, ValueError, AttributeError):
            raise IamError("RESOURCE_NOT_FOUND") from None
        if any(value.int == 0 for value in (actor, session, organization)):
            raise IamError("RESOURCE_NOT_FOUND")
        if target_role not in {"ORG_ADMIN", "DEMAND_OWNER"}:
            raise IamError("INVALID_REQUEST")
        for candidates, maximum, unique_key_ids in (
            (idempotency_candidates, 4, True),
            (payload_hash_candidates, 16, False),
        ):
            if (
                not 1 <= len(candidates) <= maximum
                or (
                    unique_key_ids
                    and len({key_id for key_id, _digest in candidates})
                    != len(candidates)
                )
                or len(set(candidates)) != len(candidates)
            ):
                raise IamError("SERVICE_UNAVAILABLE")
            for key_id, digest in candidates:
                _require_key_id(key_id)
                _require_digest(digest, "receipt candidate digest")
        connection = self.connections.checkout()
        begun = False
        disposed = False
        try:
            if (
                getattr(connection, "autocommit", None) is not True
                or connection.info.transaction_status != TransactionStatus.IDLE
            ):
                raise OrganizationAdminPostgresConfigurationError(
                    "organization issue resolver checkout is unsafe"
                )
            identity = connection.execute(
                "SELECT current_user,session_user,"
                "current_setting('server_version_num')::integer"
            ).fetchone()
            if identity is None or identity[0:2] != (
                self.settings.runtime_role,
                self.settings.runtime_role,
            ) or identity[2] // 10_000 != 18:
                raise OrganizationAdminPostgresConfigurationError(
                    "organization issue resolver identity is invalid"
                )
            connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY")
            begun = True
            connection.execute("SET LOCAL TIME ZONE 'UTC'")
            connection.execute(
                "SET LOCAL statement_timeout = '%dms'"
                % self.settings.statement_timeout_ms
            )
            values = (
                ("app.scope_kind", "ORGANIZATION_ADMIN_ISSUE_RESOLVE"),
                ("app.operation", "IssueAccessInvitation"),
                ("app.actor_user_id", str(actor)),
                ("app.session_id", str(session)),
                ("app.organization_id", str(organization)),
                ("app.target_id", str(organization)),
            )
            for name, value in values:
                configured = connection.execute(
                    "SELECT pg_catalog.set_config(%s,%s,true)", (name, value)
                ).fetchone()
                if configured != (value,):
                    raise OrganizationAdminPostgresConfigurationError(
                        "organization issue resolver context was rejected"
                    )
            row = connection.execute(
                "SELECT iam_api.resolve_organization_admin_issue_scope_v1("
                "%s::uuid,%s::uuid,%s::uuid,%s::bytea[],%s::text[],"
                "%s::bytea[],%s::text[],%s::text)",
                (
                    actor,
                    session,
                    organization,
                    [digest for _key_id, digest in idempotency_candidates],
                    [key_id for key_id, _digest in idempotency_candidates],
                    [digest for _key_id, digest in payload_hash_candidates],
                    [key_id for key_id, _digest in payload_hash_candidates],
                    target_role,
                ),
            ).fetchone()
            if row is None or len(row) != 1 or not isinstance(row[0], Mapping):
                raise IamError("SERVICE_UNAVAILABLE")
            payload = row[0]
            decision = payload.get("decision_code")
            if decision not in {"MISS", "REPLAY"}:
                if decision not in {
                    "AUTHENTICATION_REQUIRED",
                    "SESSION_EXPIRED",
                    "MFA_STEP_UP_REQUIRED",
                    "RESOURCE_NOT_FOUND",
                    "IDEMPOTENCY_KEY_REUSED",
                    "COMMAND_IN_PROGRESS",
                    "POLICY_CONFIGURATION_UNAVAILABLE",
                    "SERVICE_UNAVAILABLE",
                }:
                    decision = "SERVICE_UNAVAILABLE"
                raise IamError(decision)
            encoded_snapshot = payload.get("snapshot_digest")
            if (
                not isinstance(encoded_snapshot, str)
                or re.fullmatch(r"[0-9a-f]{64}", encoded_snapshot) is None
            ):
                raise IamError("SERVICE_UNAVAILABLE")
            replayed = decision == "REPLAY"
            safe_response = payload.get("safe_response")
            response_entity_tag = payload.get("response_entity_tag")
            reconstruction = payload.get("capability_reconstruction")
            if replayed:
                if (
                    not isinstance(safe_response, Mapping)
                    or not isinstance(response_entity_tag, str)
                    or safe_response.get("entity_tag") != response_entity_tag
                    or not isinstance(reconstruction, Mapping)
                    or set(reconstruction)
                    != {
                        "nonce",
                        "token_key_id",
                        "token_format_version",
                        "expires_at",
                    }
                ):
                    raise IamError("SERVICE_UNAVAILABLE")
            elif any(
                value is not None
                for value in (
                    safe_response,
                    response_entity_tag,
                    reconstruction,
                )
            ):
                raise IamError("SERVICE_UNAVAILABLE")
            resolution = OrganizationAdminPostgresIssueResolution(
                organization_id=UUID(str(payload.get("organization_id"))),
                target_version=payload.get("target_version"),
                snapshot_digest=bytes.fromhex(encoded_snapshot),
                replayed=replayed,
                safe_response=(
                    dict(safe_response)
                    if isinstance(safe_response, Mapping)
                    else None
                ),
                response_entity_tag=response_entity_tag,
                capability_reconstruction=(
                    dict(reconstruction)
                    if isinstance(reconstruction, Mapping)
                    else None
                ),
            )
            if resolution.organization_id != organization:
                raise IamError("SERVICE_UNAVAILABLE")
            connection.execute("COMMIT")
            begun = False
        except IamError:
            if begun:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    self.connections.discard(connection)
                    disposed = True
            if not disposed:
                disposed = _clean_release(
                    self.connections, connection, self.settings.runtime_role
                )
            raise
        except BaseException:
            if begun:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    self.connections.discard(connection)
                    disposed = True
            if not disposed:
                disposed = _clean_release(
                    self.connections, connection, self.settings.runtime_role
                )
            raise IamError("SERVICE_UNAVAILABLE") from None
        else:
            disposed = _clean_release(
                self.connections, connection, self.settings.runtime_role
            )
            return resolution
        finally:
            if not disposed:
                self.connections.discard(connection)

    def resolve_resume(
        self,
        *,
        actor_user_id: str,
        session_id: str,
        target_id: str,
        idempotency_key_digest: bytes,
        idempotency_key_digest_key_id: str,
        payload_hash: bytes,
        payload_hash_key_id: str,
        idempotency_candidates: Tuple[Tuple[str, bytes], ...] = (),
        payload_hash_candidates: Tuple[Tuple[str, bytes], ...] = (),
    ) -> OrganizationAdminPostgresResumeResolution:
        """Probe replay before SafetyHold and bind ALLOW to a dependency snapshot."""

        organization_id = self.resolve(
            actor_user_id=actor_user_id,
            session_id=session_id,
            target_id=target_id,
            operation=OrganizationAdminPostgresOperation.RESUME_MEMBERSHIP.value,
        )
        try:
            actor = UUID(actor_user_id)
            session = UUID(session_id)
            target = UUID(target_id)
            organization = UUID(organization_id)
        except (TypeError, ValueError, AttributeError):
            raise IamError("RESOURCE_NOT_FOUND") from None
        _require_digest(idempotency_key_digest, "idempotency digest")
        _require_digest(payload_hash, "payload digest")
        _require_key_id(idempotency_key_digest_key_id)
        _require_key_id(payload_hash_key_id)
        identity_candidates = idempotency_candidates or (
            (idempotency_key_digest_key_id, idempotency_key_digest),
        )
        payload_candidates = payload_hash_candidates or (
            (payload_hash_key_id, payload_hash),
        )
        if (
            not 1 <= len(identity_candidates) <= 4
            or not 1 <= len(payload_candidates) <= 4
            or identity_candidates[0]
            != (idempotency_key_digest_key_id, idempotency_key_digest)
            or payload_candidates[0] != (payload_hash_key_id, payload_hash)
            or len({key_id for key_id, _digest in identity_candidates})
            != len(identity_candidates)
            or len({key_id for key_id, _digest in payload_candidates})
            != len(payload_candidates)
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        for key_id, digest in identity_candidates + payload_candidates:
            _require_key_id(key_id)
            _require_digest(digest, "receipt candidate digest")
        connection = self.connections.checkout()
        begun = False
        disposed = False
        try:
            if (
                getattr(connection, "autocommit", None) is not True
                or connection.info.transaction_status != TransactionStatus.IDLE
            ):
                raise OrganizationAdminPostgresConfigurationError(
                    "organization resume resolver checkout is unsafe"
                )
            identity = connection.execute(
                "SELECT current_user,session_user,"
                "current_setting('server_version_num')::integer"
            ).fetchone()
            if identity is None or identity[0:2] != (
                self.settings.runtime_role,
                self.settings.runtime_role,
            ) or identity[2] // 10_000 != 18:
                raise OrganizationAdminPostgresConfigurationError(
                    "organization resume resolver identity is invalid"
                )
            connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY")
            begun = True
            connection.execute("SET LOCAL TIME ZONE 'UTC'")
            connection.execute(
                "SET LOCAL statement_timeout = '%dms'"
                % self.settings.statement_timeout_ms
            )
            values = (
                ("app.scope_kind", "ORGANIZATION_ADMIN_RESUME_RESOLVE"),
                ("app.operation", "ResumeMembership"),
                ("app.actor_user_id", str(actor)),
                ("app.session_id", str(session)),
                ("app.organization_id", str(organization)),
                ("app.target_id", str(target)),
            )
            for name, value in values:
                configured = connection.execute(
                    "SELECT pg_catalog.set_config(%s,%s,true)", (name, value)
                ).fetchone()
                if configured != (value,):
                    raise OrganizationAdminPostgresConfigurationError(
                        "organization resume resolver context was rejected"
                    )
            row = connection.execute(
                "SELECT iam_api.resolve_organization_admin_resume_scope_v1("
                "%s::uuid,%s::uuid,%s::uuid,%s::uuid,%s::bytea[],%s::text[],"
                "%s::bytea[],%s::text[])",
                (
                    actor,
                    session,
                    organization,
                    target,
                    [digest for _key_id, digest in identity_candidates],
                    [key_id for key_id, _digest in identity_candidates],
                    [digest for _key_id, digest in payload_candidates],
                    [key_id for key_id, _digest in payload_candidates],
                ),
            ).fetchone()
            if row is None or len(row) != 1 or not isinstance(row[0], Mapping):
                raise IamError("SERVICE_UNAVAILABLE")
            payload = row[0]
            decision = payload.get("decision_code")
            if decision not in {"MISS", "REPLAY"}:
                if decision not in {
                    "AUTHENTICATION_REQUIRED",
                    "SESSION_EXPIRED",
                    "MFA_STEP_UP_REQUIRED",
                    "RESOURCE_NOT_FOUND",
                    "IDEMPOTENCY_KEY_REUSED",
                    "COMMAND_IN_PROGRESS",
                    "INVALID_STATE_TRANSITION",
                    "SERVICE_UNAVAILABLE",
                }:
                    decision = "SERVICE_UNAVAILABLE"
                raise IamError(decision)
            resolved_organization = UUID(str(payload.get("organization_id")))
            target_version = payload.get("target_version")
            encoded_snapshot = payload.get("snapshot_digest")
            if (
                not isinstance(encoded_snapshot, str)
                or re.fullmatch(r"[0-9a-f]{64}", encoded_snapshot) is None
            ):
                raise IamError("SERVICE_UNAVAILABLE")
            snapshot_digest = bytes.fromhex(encoded_snapshot)
            resolution = OrganizationAdminPostgresResumeResolution(
                organization_id=resolved_organization,
                target_version=target_version,
                snapshot_digest=snapshot_digest,
                replayed=decision == "REPLAY",
            )
            if resolution.organization_id != organization:
                raise IamError("SERVICE_UNAVAILABLE")
            connection.execute("COMMIT")
            begun = False
        except IamError:
            if begun:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    self.connections.discard(connection)
                    disposed = True
            if not disposed:
                disposed = _clean_release(
                    self.connections, connection, self.settings.runtime_role
                )
            raise
        except BaseException:
            if begun:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    self.connections.discard(connection)
                    disposed = True
            if not disposed:
                disposed = _clean_release(
                    self.connections, connection, self.settings.runtime_role
                )
            raise IamError("SERVICE_UNAVAILABLE") from None
        else:
            disposed = _clean_release(
                self.connections, connection, self.settings.runtime_role
            )
            return resolution
        finally:
            if not disposed:
                self.connections.discard(connection)


def _parameters(request: OrganizationAdminPostgresDatabaseRequest) -> tuple[Any, ...]:
    invitation = request.invitation
    issue_hold = request.issue_hold
    resume_hold = request.resume_hold
    generated = request.generated_ids
    scope = request.scope
    receipt = request.receipt
    return (
        request.operation.value,
        scope.actor_user_id,
        scope.current_session_id,
        scope.organization_id,
        scope.target_id,
        scope.command_id,
        scope.correlation_id,
        scope.causation_id,
        scope.trace_id,
        scope.original_actor_id,
        request.expected_version,
        receipt.idempotency_key_digest,
        receipt.idempotency_key_digest_key_id,
        receipt.payload_hash,
        receipt.payload_hash_key_id,
        receipt.retain_until,
        generated.audit_event_id,
        generated.outbox_event_id,
        generated.secondary_outbox_event_id,
        generated.recipient_contact_id,
        invitation.recipient_binding_digest if invitation else None,
        invitation.recipient_binding_digest_key_id if invitation else None,
        invitation.masked_recipient_label if invitation else None,
        invitation.expires_at if invitation else None,
        invitation.token_nonce if invitation else None,
        invitation.token_key_id if invitation else None,
        invitation.token_format_version if invitation else None,
        invitation.target_role if invitation else request.reason_code,
        resume_hold.action if resume_hold else None,
        resume_hold.target_type if resume_hold else None,
        resume_hold.target_id if resume_hold else None,
        resume_hold.target_version if resume_hold else None,
        resume_hold.organization_id if resume_hold else None,
        resume_hold.policy_version if resume_hold else None,
        resume_hold.evaluated_at if resume_hold else None,
        resume_hold.valid_until if resume_hold else None,
        resume_hold.snapshot_digest if resume_hold else None,
        [key_id for key_id, _digest in receipt.idempotency_candidates],
        [digest for _key_id, digest in receipt.idempotency_candidates],
        [key_id for key_id, _digest in receipt.payload_hash_candidates],
        [digest for _key_id, digest in receipt.payload_hash_candidates],
        issue_hold.action if issue_hold else None,
        issue_hold.target_type if issue_hold else None,
        issue_hold.target_id if issue_hold else None,
        issue_hold.target_version if issue_hold else None,
        issue_hold.organization_id if issue_hold else None,
        issue_hold.policy_version if issue_hold else None,
        issue_hold.evaluated_at if issue_hold else None,
        issue_hold.valid_until if issue_hold else None,
        issue_hold.snapshot_digest if issue_hold else None,
        request.public_name,
    )


def _result(
    operation: OrganizationAdminPostgresOperation, row: Any
) -> tuple[
    OrganizationAdminPostgresDatabaseResult,
    Tuple[Mapping[str, Any], ...],
]:
    if row is None or len(row) != 1 or not isinstance(row[0], Mapping):
        raise IamError("SERVICE_UNAVAILABLE")
    payload = row[0]
    decision = payload.get("decision_code")
    if decision == "SAFETY_DECISION_STALE":
        raise OrganizationAdminPostgresSafetyDecisionStaleError()
    if (
        operation
        is OrganizationAdminPostgresOperation.UPDATE_ORGANIZATION_PUBLIC_NAME
        and decision == "PRECONDITION_FAILED"
    ):
        if frozenset(payload) != {"decision_code", "current_entity_tag"}:
            raise IamError("SERVICE_UNAVAILABLE")
        try:
            raise IamPreconditionFailed(payload["current_entity_tag"])
        except ValueError:
            raise IamError("SERVICE_UNAVAILABLE") from None
    if (
        operation
        is OrganizationAdminPostgresOperation.UPDATE_ORGANIZATION_PUBLIC_NAME
        and decision != "AUTHORIZED"
        and frozenset(payload) != {"decision_code"}
    ):
        raise IamError("SERVICE_UNAVAILABLE")
    if decision != "AUTHORIZED":
        if not isinstance(decision, str) or decision not in {
            "AUTHENTICATION_REQUIRED",
            "SESSION_EXPIRED",
            "MFA_STEP_UP_REQUIRED",
            "RESOURCE_NOT_FOUND",
            "IDEMPOTENCY_KEY_REUSED",
            "COMMAND_IN_PROGRESS",
            "INVALID_STATE_TRANSITION",
            "LAST_ACTIVE_ORG_ADMIN",
            "SELF_MANAGEMENT_FORBIDDEN",
            "PRECONDITION_FAILED",
            "POLICY_CONFIGURATION_UNAVAILABLE",
            "SERVICE_UNAVAILABLE",
        }:
            decision = "SERVICE_UNAVAILABLE"
        raise IamError(decision)
    replayed = payload.get("replayed")
    if not isinstance(replayed, bool):
        raise IamError("SERVICE_UNAVAILABLE")
    expected_keys = (
        _AUTHORIZED_REPLAY_RESULT_KEYS
        if replayed
        else _AUTHORIZED_WRITE_RESULT_KEYS
    )
    if frozenset(payload) != expected_keys:
        raise IamError("SERVICE_UNAVAILABLE")
    response = payload.get("safe_response")
    entity_tag = payload.get("response_entity_tag")
    event = payload.get("outbox_event")
    secondary_event = payload.get("secondary_outbox_event")
    reconstruction = payload.get("capability_reconstruction")
    expects_secondary = (
        not replayed
        and operation is OrganizationAdminPostgresOperation.REVOKE_MEMBERSHIP
    )
    expected_event_type = {
        OrganizationAdminPostgresOperation.ISSUE_ACCESS_INVITATION: (
            "AccessInvitationIssued"
        ),
        OrganizationAdminPostgresOperation.REVOKE_ACCESS_INVITATION: (
            "AccessInvitationRevoked"
        ),
        OrganizationAdminPostgresOperation.SUSPEND_MEMBERSHIP: (
            "MembershipSuspended"
        ),
        OrganizationAdminPostgresOperation.RESUME_MEMBERSHIP: (
            "MembershipResumed"
        ),
        OrganizationAdminPostgresOperation.REVOKE_MEMBERSHIP: (
            "MembershipRevoked"
        ),
        OrganizationAdminPostgresOperation.UPDATE_ORGANIZATION_PUBLIC_NAME: (
            "OrganizationPublicNameChanged"
        ),
    }[operation]
    if (
        not isinstance(response, Mapping)
        or not isinstance(entity_tag, str)
        or response.get("entity_tag") != entity_tag
        or (not replayed) != isinstance(event, Mapping)
        or (
            isinstance(event, Mapping)
            and event.get("event_type") != expected_event_type
        )
        or expects_secondary != isinstance(secondary_event, Mapping)
        or (
            isinstance(secondary_event, Mapping)
            and secondary_event.get("event_type")
            != "MembershipRolesRevoked"
        )
        or (
            operation
            is OrganizationAdminPostgresOperation.ISSUE_ACCESS_INVITATION
            and not isinstance(reconstruction, Mapping)
        )
        or (
            operation
            is not OrganizationAdminPostgresOperation.ISSUE_ACCESS_INVITATION
            and reconstruction is not None
        )
    ):
        raise IamError("SERVICE_UNAVAILABLE")
    events = ((dict(event),) if isinstance(event, Mapping) else ()) + (
        (dict(secondary_event),)
        if isinstance(secondary_event, Mapping)
        else ()
    )
    return (
        OrganizationAdminPostgresDatabaseResult(
            operation=operation,
            replayed=replayed,
            safe_response=dict(response),
            response_entity_tag=entity_tag,
            capability_reconstruction=(
                dict(reconstruction)
                if isinstance(reconstruction, Mapping)
                else None
            ),
        ),
        events,
    )


def _require_digest(value: Any, label: str) -> None:
    if not isinstance(value, bytes) or len(value) != _DIGEST_BYTES:
        raise ValueError(f"{label} must be exactly 32 bytes")


def _canonical_public_name(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 160
        and value == value.strip()
        and value == unicodedata.normalize("NFC", value)
        and all(unicodedata.category(character) not in {"Cc", "Cf"} for character in value)
    )


def _require_key_id(value: Any) -> None:
    if not isinstance(value, str) or _KEY_ID.fullmatch(value) is None:
        raise ValueError("organization administration key ID is invalid")


def _require_utc(value: Any) -> None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset().total_seconds() != 0
    ):
        raise ValueError("organization administration timestamp must be UTC")


def _retryable(error: BaseException) -> bool:
    sqlstate = getattr(error, "sqlstate", None)
    return sqlstate in {"40001", "40P01", "55P03"}


def _clean_release(source: Any, connection: Any, runtime_role: str) -> bool:
    try:
        if connection.info.transaction_status != TransactionStatus.IDLE:
            source.discard(connection)
            return True
        connection.execute("RESET ALL")
        connection.execute("DISCARD TEMP")
        clean = connection.execute(
            "SELECT current_user,session_user,current_setting('app.scope_kind',true)"
        ).fetchone()
        if clean not in (
            (runtime_role, runtime_role, None),
            (runtime_role, runtime_role, ""),
        ):
            source.discard(connection)
            return True
    except BaseException:
        source.discard(connection)
        return True
    source.release(connection)
    return True


__all__ = [
    "ORGANIZATION_ADMIN_POSTGRES_OPERATIONS",
    "OrganizationAdminPostgresCommitOutcomeUnknownError",
    "OrganizationAdminPostgresConfigurationError",
    "OrganizationAdminPostgresDatabaseRequest",
    "OrganizationAdminPostgresDatabaseResult",
    "OrganizationAdminPostgresGeneratedIds",
    "OrganizationAdminPostgresInvitationMaterial",
    "OrganizationAdminPostgresIssueHoldEvidence",
    "OrganizationAdminPostgresIssueResolution",
    "OrganizationAdminPostgresOperation",
    "OrganizationAdminPostgresReceiptMaterial",
    "OrganizationAdminPostgresResumeHoldEvidence",
    "OrganizationAdminPostgresResumeResolution",
    "OrganizationAdminPostgresSafetyDecisionStaleError",
    "OrganizationAdminPostgresScope",
    "OrganizationAdminPostgresSettings",
    "PsycopgOrganizationAdminUnitOfWorkFactory",
    "PsycopgOrganizationAdminTargetResolver",
]
