"""Role-bound PostgreSQL 18 runtime for creator and candidate-selector work.

The adapter exposes only fixed reads and the two reviewed database programs.
It never loads Memory aggregates, accepts SQL identifiers, persists a raw
idempotency key, or retries a write after COMMIT has been sent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import re
from typing import Any, Mapping, Optional, Protocol, Tuple
from uuid import UUID

from psycopg.pq import TransactionStatus

from desire_platform.utc import parse_utc_timestamp

from .migrations import (
    MATCHING_REQUIRED_IAM_SCHEMA_VERSION,
    MATCHING_REVIEWED_MANIFEST_SHA256,
    MATCHING_SCHEMA_HEAD_VERSION,
)


_CODE = re.compile(r"[A-Z][A-Z0-9_]{1,63}\Z")
_KEY_ID = re.compile(r"[a-z0-9][a-z0-9-]{2,127}\Z")
_READINESS_PROGRAMS = (
    (
        "matching_api.list_creator_invitations_v1("
        "uuid,uuid,bytea,integer,timestamptz,uuid)",
        True,
        False,
        True,
    ),
    (
        "matching_api.read_creator_invitation_v1(uuid,uuid,bytea,uuid)",
        True,
        False,
        True,
    ),
    (
        "matching_api.execute_creator_invitation_v1("
        "text,uuid,uuid,uuid,uuid,bigint,bytea,text,text,bytea,uuid,uuid,"
        "uuid,uuid,uuid,uuid,text,bytea,text,bytea,uuid,uuid)",
        True,
        False,
        True,
    ),
    (
        "matching_api.execute_candidate_selection_v1("
        "text,uuid,uuid,uuid,uuid,bigint,bytea,uuid,bigint,bytea,uuid,text,"
        "text,uuid,uuid,uuid,uuid,uuid,uuid,text,bytea,text,bytea,uuid,uuid)",
        False,
        True,
        True,
    ),
    (
        "matching_api.list_candidate_selector_attempts_v1("
        "uuid,uuid,uuid,uuid,bytea,integer,timestamptz,uuid)",
        False,
        True,
        True,
    ),
    (
        "matching_api.read_candidate_selector_selection_v1("
        "uuid,uuid,uuid,uuid,bytea)",
        False,
        True,
        True,
    ),
    (
        "matching_api.read_candidate_selector_selection_by_id_v1("
        "uuid,uuid,uuid,uuid,bytea)",
        False,
        True,
        True,
    ),
    (
        "matching.recipient_invitation_projection_v1(uuid)",
        True,
        False,
        False,
    ),
    (
        "matching.selection_projection_v1(uuid,uuid,bigint)",
        False,
        True,
        False,
    ),
)
_READINESS_SQL = """
WITH expected AS (
    SELECT *
    FROM unnest(%s::text[], %s::boolean[], %s::boolean[])
      AS item(signature, may_execute, security_definer)
), resolved AS (
    SELECT expected.*, pg_catalog.to_regprocedure(expected.signature) AS oid
    FROM expected
)
SELECT pg_catalog.count(*)=%s
   AND pg_catalog.bool_and(
        resolved.oid IS NOT NULL
        AND pg_catalog.has_function_privilege(
            session_user,resolved.oid,'EXECUTE'
        )=resolved.may_execute
        AND procedure.prosecdef=resolved.security_definer
        AND owner.rolname='matching_schema_owner'
        AND procedure.proconfig=ARRAY[
            'search_path=pg_catalog, matching'
        ]::text[]
        AND NOT EXISTS (
            SELECT 1
            FROM pg_catalog.aclexplode(COALESCE(
                procedure.proacl,
                pg_catalog.acldefault('f',procedure.proowner)
            )) AS privilege
            WHERE privilege.grantee=0
              AND privilege.privilege_type='EXECUTE'
        )
    )
   AND pg_catalog.has_schema_privilege(
        session_user,'matching','USAGE'
   )
   AND pg_catalog.has_schema_privilege(
        session_user,'matching_api','USAGE'
   )
   AND pg_catalog.has_table_privilege(
        session_user,'matching.schema_compatibility','SELECT'
   )
FROM resolved
LEFT JOIN pg_catalog.pg_proc AS procedure ON procedure.oid=resolved.oid
LEFT JOIN pg_catalog.pg_roles AS owner ON owner.oid=procedure.proowner
"""
_CREATOR_STATUSES = frozenset(
    {"SENT", "ACCEPTED", "DECLINED", "WITHDRAWN", "EXPIRED", "REVOKED"}
)
_SELECTION_STATUSES = frozenset(
    {
        "OPEN", "PENDING_CHOICE", "PENDING_CLOSE",
        "SELECTED", "CLOSED_NO_SELECTION", "CANCELLED",
    }
)
_ATTEMPT_STATUSES = frozenset(
    {"OPEN", "SELECTED", "CLOSED_NO_SELECTION", "INVALIDATED", "CANCELLED"}
)


class MatchingPostgresError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class MatchingPostgresConfigurationError(MatchingPostgresError):
    def __init__(self) -> None:
        super().__init__("SERVICE_UNAVAILABLE")


class MatchingPostgresRejectedError(MatchingPostgresError):
    pass


class MatchingPostgresCommitOutcomeUnknownError(MatchingPostgresError):
    def __init__(self) -> None:
        super().__init__("COMMAND_OUTCOME_UNKNOWN")


class MatchingPostgresConnectionSource(Protocol):
    def checkout(self) -> Any: ...

    def release(self, connection: Any) -> None: ...

    def discard(self, connection: Any) -> None: ...


@dataclass(frozen=True)
class MatchingPostgresSettings:
    creator_role: str = "matching_creator"
    selector_role: str = "matching_selector"
    required_server_major: int = 18
    lock_timeout_ms: int = 2_000
    statement_timeout_ms: int = 10_000
    idle_in_transaction_timeout_ms: int = 15_000

    def __post_init__(self) -> None:
        if (self.creator_role, self.selector_role) != (
            "matching_creator",
            "matching_selector",
        ):
            raise ValueError("Matching online roles are not the reviewed set")
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
class MatchingCreatorContext:
    actor_user_id: UUID
    session_id: UUID = field(repr=False)
    authority_marker_sha256: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _require_uuids(self.actor_user_id, self.session_id)
        _require_digest(self.authority_marker_sha256)


@dataclass(frozen=True)
class MatchingSelectorDiscoveryContext:
    """Selector identity facts available before an assignment is discovered."""

    actor_user_id: UUID
    session_id: UUID = field(repr=False)
    organization_id: UUID
    authority_marker_sha256: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _require_uuids(
            self.actor_user_id,
            self.session_id,
            self.organization_id,
        )
        _require_digest(self.authority_marker_sha256)


@dataclass(frozen=True)
class MatchingSelectorContext:
    actor_user_id: UUID
    session_id: UUID = field(repr=False)
    organization_id: UUID
    selection_id: UUID
    assignment_id: UUID
    assignment_version: int
    authority_marker_sha256: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _require_uuids(
            self.actor_user_id,
            self.session_id,
            self.organization_id,
            self.selection_id,
            self.assignment_id,
        )
        _require_version(self.assignment_version)
        _require_digest(self.authority_marker_sha256)


@dataclass(frozen=True)
class MatchingCommandContext:
    command_id: UUID
    correlation_id: UUID
    trace_id: UUID

    def __post_init__(self) -> None:
        _require_uuids(self.command_id, self.correlation_id, self.trace_id)


@dataclass(frozen=True)
class MatchingWriteMaterial:
    receipt_id: UUID
    fact_id: Optional[UUID]
    audit_event_id: UUID
    primary_outbox_event_id: UUID
    secondary_outbox_event_id: Optional[UUID]
    identity_key_id: str
    identity_digest: bytes = field(repr=False)
    payload_hash_key_id: str
    payload_hash: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _require_uuids(
            self.receipt_id,
            self.audit_event_id,
            self.primary_outbox_event_id,
        )
        if self.fact_id is not None:
            _require_uuids(self.fact_id)
        if self.secondary_outbox_event_id is not None:
            _require_uuids(self.secondary_outbox_event_id)
        ids = tuple(
            value
            for value in (
                self.receipt_id,
                self.fact_id,
                self.audit_event_id,
                self.primary_outbox_event_id,
                self.secondary_outbox_event_id,
            )
            if value is not None
        )
        if len(ids) != len(set(ids)):
            raise ValueError("Matching write identifiers must be distinct")
        if (
            not _KEY_ID.fullmatch(self.identity_key_id)
            or not _KEY_ID.fullmatch(self.payload_hash_key_id)
            or self.identity_key_id == self.payload_hash_key_id
        ):
            raise ValueError("Matching receipt key identifiers are invalid")
        _require_digest(self.identity_digest)
        _require_digest(self.payload_hash)


class CreatorInvitationOperation(str, Enum):
    ACCEPT = "ACCEPT_INVITATION"
    DECLINE = "DECLINE_INVITATION"
    WITHDRAW = "WITHDRAW_INVITATION"


class CandidateSelectionOperation(str, Enum):
    CHOOSE = "CHOOSE_CREATOR"
    CLOSE = "CLOSE_SELECTION"


@dataclass(frozen=True)
class CreatorInvitationMutation:
    operation: CreatorInvitationOperation
    creator: MatchingCreatorContext
    command: MatchingCommandContext
    organization_id: UUID
    invitation_id: UUID
    expected_invitation_version: int
    expected_snapshot_sha256: bytes = field(repr=False)
    reason_code: Optional[str]
    restricted_note: Optional[str] = field(repr=False)
    material: MatchingWriteMaterial = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.operation, CreatorInvitationOperation):
            raise TypeError("Creator invitation operation is invalid")
        if not isinstance(self.creator, MatchingCreatorContext):
            raise TypeError("Creator context is invalid")
        if not isinstance(self.command, MatchingCommandContext):
            raise TypeError("Command context is invalid")
        if not isinstance(self.material, MatchingWriteMaterial):
            raise TypeError("Write material is invalid")
        _require_uuids(self.organization_id, self.invitation_id)
        _require_version(self.expected_invitation_version)
        _require_digest(self.expected_snapshot_sha256)
        if self.operation is CreatorInvitationOperation.ACCEPT:
            if self.reason_code is not None or self.restricted_note is not None:
                raise ValueError("Accept invitation payload is invalid")
        else:
            _require_code(self.reason_code)
            _require_note(self.restricted_note)
        if self.material.fact_id is None:
            raise ValueError("Creator response fact identifier is required")
        if self.material.secondary_outbox_event_id is None:
            raise ValueError("Selection-set event identifier is required")


@dataclass(frozen=True)
class CandidateSelectionMutation:
    operation: CandidateSelectionOperation
    selector: MatchingSelectorContext
    command: MatchingCommandContext
    expected_selection_version: int
    expected_invitation_set_sha256: bytes = field(repr=False)
    invitation_id: Optional[UUID]
    selection_basis_code: Optional[str]
    reason_code: Optional[str]
    material: MatchingWriteMaterial = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.operation, CandidateSelectionOperation):
            raise TypeError("Candidate selection operation is invalid")
        if not isinstance(self.selector, MatchingSelectorContext):
            raise TypeError("Selector context is invalid")
        if not isinstance(self.command, MatchingCommandContext):
            raise TypeError("Command context is invalid")
        if not isinstance(self.material, MatchingWriteMaterial):
            raise TypeError("Write material is invalid")
        _require_version(self.expected_selection_version)
        _require_digest(self.expected_invitation_set_sha256)
        if self.operation is CandidateSelectionOperation.CHOOSE:
            _require_uuids(self.invitation_id)
            _require_code(self.selection_basis_code)
            if self.reason_code is not None or self.material.fact_id is None:
                raise ValueError("Choose creator payload is invalid")
            if self.material.secondary_outbox_event_id is not None:
                raise ValueError("Choose creator has one outbox event")
        else:
            if (
                self.invitation_id is not None
                or self.selection_basis_code is not None
                or self.material.fact_id is not None
            ):
                raise ValueError("Close selection payload is invalid")
            _require_code(self.reason_code)
            if self.material.secondary_outbox_event_id is None:
                raise ValueError("Attempt-close event identifier is required")


@dataclass(frozen=True)
class RecipientInvitationView:
    invitation_id: UUID
    status: str
    aggregate_version: int
    updated_at: datetime
    expires_at: datetime
    snapshot_sha256: str = field(repr=False)
    response_status: Optional[str]
    disclosure: Mapping[str, Any] = field(repr=False)

    @property
    def entity_tag(self) -> str:
        return f'"v{self.aggregate_version}"'


@dataclass(frozen=True)
class MatchingAttemptView:
    attempt_id: UUID
    demand_id: UUID
    attempt_no: int
    status: str
    aggregate_version: int
    updated_at: datetime

    @property
    def entity_tag(self) -> str:
        return f'"v{self.aggregate_version}"'


@dataclass(frozen=True)
class SelectionCandidateView:
    invitation_id: UUID
    creator_display_handle: str
    profile_id: UUID
    profile_version_id: UUID
    accepted_at: datetime
    capability_summary: str


@dataclass(frozen=True)
class MatchingSelectionView:
    selection_id: UUID
    attempt_id: UUID
    candidate_selector_assignment_id: UUID
    candidate_selector_assignment_version: int
    status: str
    aggregate_version: int
    updated_at: datetime
    current_invitation_set_sha256: str = field(repr=False)
    chosen_invitation_id: Optional[UUID]
    accepted_invitations: Tuple[SelectionCandidateView, ...]

    @property
    def entity_tag(self) -> str:
        return f'"v{self.aggregate_version}"'


@dataclass(frozen=True)
class RecipientInvitationPage:
    items: Tuple[RecipientInvitationView, ...]
    next_updated_at: Optional[datetime]
    next_invitation_id: Optional[UUID]


@dataclass(frozen=True)
class MatchingAttemptPage:
    items: Tuple[MatchingAttemptView, ...]
    next_updated_at: Optional[datetime]
    next_attempt_id: Optional[UUID]


@dataclass(frozen=True)
class RecipientInvitationCommandResult:
    invitation: RecipientInvitationView
    replayed: bool


@dataclass(frozen=True)
class CandidateSelectionCommandResult:
    selection: MatchingSelectionView
    replayed: bool


class PsycopgMatchingRuntime:
    """Closed read/write gateway over two separately credentialed pools."""

    def __init__(
        self,
        *,
        creator_connections: MatchingPostgresConnectionSource,
        selector_connections: MatchingPostgresConnectionSource,
        settings: MatchingPostgresSettings = MatchingPostgresSettings(),
    ) -> None:
        for source in (creator_connections, selector_connections):
            if source is None or any(
                not callable(getattr(source, name, None))
                for name in ("checkout", "release", "discard")
            ):
                raise TypeError("Matching connection source is unavailable")
        if creator_connections is selector_connections:
            raise TypeError("Matching role connection sources must be distinct")
        if not isinstance(settings, MatchingPostgresSettings):
            raise TypeError("Matching PostgreSQL settings are unavailable")
        self._creator_connections = creator_connections
        self._selector_connections = selector_connections
        self._settings = settings
        self._closed = False

    def close(self) -> None:
        self._closed = True

    def check_readiness(self, timeout_ms: int) -> None:
        """Prove both physical roles and their reviewed program grants."""

        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 30_000:
            raise ValueError("Matching readiness timeout is invalid")
        if self._closed:
            raise MatchingPostgresConfigurationError()
        for source, role in (
            (self._creator_connections, "matching_creator"),
            (self._selector_connections, "matching_selector"),
        ):
            self._check_role_readiness(
                source=source,
                role=role,
                timeout_ms=timeout_ms,
            )

    def list_creator_invitations(
        self,
        *,
        context: MatchingCreatorContext,
        limit: int,
        cursor_updated_at: Optional[datetime] = None,
        cursor_invitation_id: Optional[UUID] = None,
    ) -> RecipientInvitationPage:
        _require_creator_context(context)
        _require_page(limit, cursor_updated_at, cursor_invitation_id)
        rows = self._read(
            source=self._creator_connections,
            role="matching_creator",
            scope="MATCHING_CREATOR",
            operation="LIST_MATCHING_INVITATIONS",
            actor_id=context.actor_user_id,
            session_id=context.session_id,
            organization_id=None,
            demand_id=None,
            attempt_id=None,
            invitation_id=None,
            selection_id=None,
            assignment_id=None,
            authority_marker=context.authority_marker_sha256,
            statement=(
                "SELECT safe_invitation,updated_at,invitation_id FROM "
                "matching_api.list_creator_invitations_v1("
                + ",".join(["%s"] * 6)
                + ")"
            ),
            parameters=(
                context.actor_user_id,
                context.session_id,
                context.authority_marker_sha256,
                limit + 1,
                cursor_updated_at,
                cursor_invitation_id,
            ),
        )
        visible = rows[:limit]
        items = tuple(_recipient_view(row[0]) for row in visible)
        if len(rows) <= limit or not visible:
            return RecipientInvitationPage(items, None, None)
        return RecipientInvitationPage(items, visible[-1][1], visible[-1][2])

    def read_creator_invitation(
        self,
        *,
        context: MatchingCreatorContext,
        invitation_id: UUID,
    ) -> Optional[RecipientInvitationView]:
        _require_creator_context(context)
        _require_uuids(invitation_id)
        rows = self._read(
            source=self._creator_connections,
            role="matching_creator",
            scope="MATCHING_CREATOR",
            operation="READ_MATCHING_INVITATION",
            actor_id=context.actor_user_id,
            session_id=context.session_id,
            organization_id=None,
            demand_id=None,
            attempt_id=None,
            invitation_id=invitation_id,
            selection_id=None,
            assignment_id=None,
            authority_marker=context.authority_marker_sha256,
            statement=(
                "SELECT safe_invitation FROM "
                "matching_api.read_creator_invitation_v1("
                + ",".join(["%s"] * 4)
                + ")"
            ),
            parameters=(
                context.actor_user_id,
                context.session_id,
                context.authority_marker_sha256,
                invitation_id,
            ),
        )
        if not rows:
            return None
        if len(rows) != 1:
            raise MatchingPostgresConfigurationError()
        return _recipient_view(rows[0][0])

    def list_selector_attempts(
        self,
        *,
        context: MatchingSelectorDiscoveryContext,
        demand_id: UUID,
        limit: int,
        cursor_updated_at: Optional[datetime] = None,
        cursor_attempt_id: Optional[UUID] = None,
    ) -> MatchingAttemptPage:
        _require_selector_discovery_context(context)
        _require_uuids(demand_id)
        _require_page(limit, cursor_updated_at, cursor_attempt_id)
        rows = self._read(
            source=self._selector_connections,
            role="matching_selector",
            scope="CANDIDATE_SELECTOR",
            operation="LIST_SELECTOR_ATTEMPTS",
            actor_id=context.actor_user_id,
            session_id=context.session_id,
            organization_id=context.organization_id,
            demand_id=demand_id,
            attempt_id=None,
            invitation_id=None,
            selection_id=None,
            assignment_id=None,
            authority_marker=context.authority_marker_sha256,
            statement=(
                "SELECT attempt_id,demand_id,attempt_no,status,"
                "aggregate_version,updated_at FROM "
                "matching_api.list_candidate_selector_attempts_v1("
                + ",".join(["%s"] * 8)
                + ")"
            ),
            parameters=(
                context.actor_user_id,
                context.session_id,
                context.organization_id,
                demand_id,
                context.authority_marker_sha256,
                limit + 1,
                cursor_updated_at,
                cursor_attempt_id,
            ),
        )
        visible = rows[:limit]
        items = tuple(_attempt_view(row) for row in visible)
        if len(rows) <= limit or not visible:
            return MatchingAttemptPage(items, None, None)
        return MatchingAttemptPage(items, visible[-1][5], visible[-1][0])

    def read_selection_by_attempt(
        self,
        *,
        context: MatchingSelectorDiscoveryContext,
        attempt_id: UUID,
    ) -> Optional[MatchingSelectionView]:
        _require_selector_discovery_context(context)
        _require_uuids(attempt_id)
        rows = self._read(
            source=self._selector_connections,
            role="matching_selector",
            scope="CANDIDATE_SELECTOR",
            operation="READ_SELECTION_BY_ATTEMPT",
            actor_id=context.actor_user_id,
            session_id=context.session_id,
            organization_id=context.organization_id,
            demand_id=None,
            attempt_id=attempt_id,
            invitation_id=None,
            selection_id=None,
            assignment_id=None,
            authority_marker=context.authority_marker_sha256,
            statement=(
                "SELECT safe_projection FROM "
                "matching_api.read_candidate_selector_selection_v1("
                + ",".join(["%s"] * 5)
                + ")"
            ),
            parameters=(
                context.actor_user_id,
                context.session_id,
                context.organization_id,
                attempt_id,
                context.authority_marker_sha256,
            ),
        )
        return self._single_selection(rows)

    def read_selection_by_id(
        self,
        *,
        context: MatchingSelectorDiscoveryContext,
        selection_id: UUID,
    ) -> Optional[MatchingSelectionView]:
        """Resolve the exact assignment, including a just-completed close."""

        _require_selector_discovery_context(context)
        _require_uuids(selection_id)
        rows = self._read(
            source=self._selector_connections,
            role="matching_selector",
            scope="CANDIDATE_SELECTOR",
            operation="READ_SELECTION_BY_ID",
            actor_id=context.actor_user_id,
            session_id=context.session_id,
            organization_id=context.organization_id,
            demand_id=None,
            attempt_id=None,
            invitation_id=None,
            selection_id=selection_id,
            assignment_id=None,
            authority_marker=context.authority_marker_sha256,
            statement=(
                "SELECT safe_projection FROM "
                "matching_api.read_candidate_selector_selection_by_id_v1("
                + ",".join(["%s"] * 5)
                + ")"
            ),
            parameters=(
                context.actor_user_id,
                context.session_id,
                context.organization_id,
                selection_id,
                context.authority_marker_sha256,
            ),
        )
        return self._single_selection(rows)

    def read_selection(
        self, *, context: MatchingSelectorContext
    ) -> Optional[MatchingSelectionView]:
        _require_selector_context(context)
        selection = self.read_selection_by_id(
            context=MatchingSelectorDiscoveryContext(
                actor_user_id=context.actor_user_id,
                session_id=context.session_id,
                organization_id=context.organization_id,
                authority_marker_sha256=context.authority_marker_sha256,
            ),
            selection_id=context.selection_id,
        )
        if selection is None:
            return None
        if (
            selection.candidate_selector_assignment_id
            != context.assignment_id
            or selection.candidate_selector_assignment_version
            != context.assignment_version
        ):
            raise MatchingPostgresRejectedError(
                "SELECTOR_ASSIGNMENT_REQUIRED"
            )
        return selection

    @staticmethod
    def _single_selection(
        rows: list[tuple[Any, ...]],
    ) -> Optional[MatchingSelectionView]:
        if not rows:
            return None
        if len(rows) != 1 or len(rows[0]) != 1:
            raise MatchingPostgresConfigurationError()
        return _selection_view(rows[0][0])

    def accept_invitation(
        self, request: CreatorInvitationMutation
    ) -> RecipientInvitationCommandResult:
        _require_creator_operation(request, CreatorInvitationOperation.ACCEPT)
        return self._creator_write(request)

    def decline_invitation(
        self, request: CreatorInvitationMutation
    ) -> RecipientInvitationCommandResult:
        _require_creator_operation(request, CreatorInvitationOperation.DECLINE)
        return self._creator_write(request)

    def withdraw_invitation(
        self, request: CreatorInvitationMutation
    ) -> RecipientInvitationCommandResult:
        _require_creator_operation(request, CreatorInvitationOperation.WITHDRAW)
        return self._creator_write(request)

    def choose_creator(
        self, request: CandidateSelectionMutation
    ) -> CandidateSelectionCommandResult:
        _require_selector_operation(request, CandidateSelectionOperation.CHOOSE)
        return self._selector_write(request)

    def close_selection(
        self, request: CandidateSelectionMutation
    ) -> CandidateSelectionCommandResult:
        _require_selector_operation(request, CandidateSelectionOperation.CLOSE)
        return self._selector_write(request)

    def _creator_write(
        self, request: CreatorInvitationMutation
    ) -> RecipientInvitationCommandResult:
        material = request.material
        creator = request.creator
        row = self._write(
            source=self._creator_connections,
            role="matching_creator",
            scope="MATCHING_CREATOR",
            operation=request.operation.value,
            actor_id=creator.actor_user_id,
            session_id=creator.session_id,
            organization_id=request.organization_id,
            invitation_id=request.invitation_id,
            selection_id=None,
            assignment_id=None,
            authority_marker=creator.authority_marker_sha256,
            command_id=request.command.command_id,
            target_id=request.invitation_id,
            statement=(
                "SELECT safe_response,replayed FROM "
                "matching_api.execute_creator_invitation_v1("
                + ",".join(["%s"] * 22)
                + ")"
            ),
            parameters=(
                request.operation.value,
                creator.actor_user_id,
                creator.session_id,
                request.organization_id,
                request.invitation_id,
                request.expected_invitation_version,
                request.expected_snapshot_sha256,
                request.reason_code,
                request.restricted_note,
                creator.authority_marker_sha256,
                request.command.command_id,
                material.receipt_id,
                material.fact_id,
                material.audit_event_id,
                material.primary_outbox_event_id,
                material.secondary_outbox_event_id,
                material.identity_key_id,
                material.identity_digest,
                material.payload_hash_key_id,
                material.payload_hash,
                request.command.correlation_id,
                request.command.trace_id,
            ),
        )
        return RecipientInvitationCommandResult(
            invitation=_recipient_view(row[0]), replayed=_strict_bool(row[1])
        )

    @staticmethod
    def _check_role_readiness(
        *,
        source: MatchingPostgresConnectionSource,
        role: str,
        timeout_ms: int,
    ) -> None:
        connection = None
        transaction = False
        disposed = False
        try:
            connection = source.checkout()
            _prepare(connection, role)
            connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY")
            transaction = True
            timeout = f"{timeout_ms}ms"
            row = connection.execute(
                "SELECT pg_catalog.set_config(%s,%s,true)",
                ("statement_timeout", timeout),
            ).fetchone()
            if not _set_config_result_matches("statement_timeout", timeout, row):
                raise MatchingPostgresConfigurationError()
            role_index = 1 if role == "matching_creator" else 2
            signatures = [item[0] for item in _READINESS_PROGRAMS]
            executable = [item[role_index] for item in _READINESS_PROGRAMS]
            security_definer = [item[3] for item in _READINESS_PROGRAMS]
            readiness = connection.execute(
                _READINESS_SQL,
                (
                    signatures,
                    executable,
                    security_definer,
                    len(_READINESS_PROGRAMS),
                ),
            ).fetchone()
            if readiness != (True,):
                raise MatchingPostgresConfigurationError()
            connection.execute("COMMIT")
            transaction = False
            _reset(connection)
            source.release(connection)
            disposed = True
        except BaseException as error:
            if connection is not None and transaction:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    pass
            if connection is not None and not disposed:
                _discard(source, connection)
                disposed = True
            if isinstance(error, MatchingPostgresError):
                raise
            raise MatchingPostgresConfigurationError() from None
        finally:
            if connection is not None and not disposed:
                _discard(source, connection)

    def _selector_write(
        self, request: CandidateSelectionMutation
    ) -> CandidateSelectionCommandResult:
        material = request.material
        selector = request.selector
        row = self._write(
            source=self._selector_connections,
            role="matching_selector",
            scope="CANDIDATE_SELECTOR",
            operation=request.operation.value,
            actor_id=selector.actor_user_id,
            session_id=selector.session_id,
            organization_id=selector.organization_id,
            invitation_id=None,
            selection_id=selector.selection_id,
            assignment_id=selector.assignment_id,
            authority_marker=selector.authority_marker_sha256,
            command_id=request.command.command_id,
            target_id=selector.selection_id,
            statement=(
                "SELECT safe_response,replayed FROM "
                "matching_api.execute_candidate_selection_v1("
                + ",".join(["%s"] * 25)
                + ")"
            ),
            parameters=(
                request.operation.value,
                selector.actor_user_id,
                selector.session_id,
                selector.organization_id,
                selector.selection_id,
                request.expected_selection_version,
                request.expected_invitation_set_sha256,
                selector.assignment_id,
                selector.assignment_version,
                selector.authority_marker_sha256,
                request.invitation_id,
                request.selection_basis_code,
                request.reason_code,
                request.command.command_id,
                material.receipt_id,
                material.fact_id,
                material.audit_event_id,
                material.primary_outbox_event_id,
                material.secondary_outbox_event_id,
                material.identity_key_id,
                material.identity_digest,
                material.payload_hash_key_id,
                material.payload_hash,
                request.command.correlation_id,
                request.command.trace_id,
            ),
        )
        return CandidateSelectionCommandResult(
            selection=_selection_view(row[0]), replayed=_strict_bool(row[1])
        )

    def _read(
        self,
        *,
        source: MatchingPostgresConnectionSource,
        role: str,
        scope: str,
        operation: str,
        actor_id: UUID,
        session_id: UUID,
        organization_id: Optional[UUID],
        demand_id: Optional[UUID],
        attempt_id: Optional[UUID],
        invitation_id: Optional[UUID],
        selection_id: Optional[UUID],
        assignment_id: Optional[UUID],
        authority_marker: bytes,
        statement: str,
        parameters: tuple[Any, ...],
    ) -> list[tuple[Any, ...]]:
        if self._closed:
            raise MatchingPostgresConfigurationError()
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
                demand_id=demand_id,
                attempt_id=attempt_id,
                invitation_id=invitation_id,
                selection_id=selection_id,
                assignment_id=assignment_id,
                authority_marker=authority_marker,
                command_id=None,
                target_id=None,
            )
            rows = connection.execute(statement, parameters).fetchall()
            if not isinstance(rows, list):
                raise MatchingPostgresConfigurationError()
            connection.execute("COMMIT")
            transaction = False
            _reset(connection)
            source.release(connection)
            disposed = True
            return rows
        except BaseException as error:
            if connection is not None and transaction:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    pass
            if connection is not None and not disposed:
                _discard(source, connection)
                disposed = True
            if isinstance(error, MatchingPostgresError):
                raise
            translated = _database_error(error)
            if translated is not None:
                raise translated from None
            raise MatchingPostgresConfigurationError() from None
        finally:
            if connection is not None and not disposed:
                _discard(source, connection)

    def _write(
        self,
        *,
        source: MatchingPostgresConnectionSource,
        role: str,
        scope: str,
        operation: str,
        actor_id: UUID,
        session_id: UUID,
        organization_id: UUID,
        invitation_id: Optional[UUID],
        selection_id: Optional[UUID],
        assignment_id: Optional[UUID],
        authority_marker: bytes,
        command_id: UUID,
        target_id: UUID,
        statement: str,
        parameters: tuple[Any, ...],
    ) -> tuple[Any, ...]:
        if self._closed:
            raise MatchingPostgresConfigurationError()
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
                scope=scope,
                operation=operation,
                actor_id=actor_id,
                session_id=session_id,
                organization_id=organization_id,
                demand_id=None,
                attempt_id=None,
                invitation_id=invitation_id,
                selection_id=selection_id,
                assignment_id=assignment_id,
                authority_marker=authority_marker,
                command_id=command_id,
                target_id=target_id,
            )
            state = "WRITING"
            rows = connection.execute(statement, parameters).fetchmany(2)
            if not isinstance(rows, list) or len(rows) != 1:
                raise MatchingPostgresConfigurationError()
            row = rows[0]
            if not isinstance(row, tuple) or len(row) != 2:
                raise MatchingPostgresConfigurationError()
            state = "COMMIT_SENT"
            connection.execute("COMMIT")
            state = "COMMITTED"
            _reset(connection)
            source.release(connection)
            disposed = True
            return row
        except BaseException as error:
            if connection is not None and state == "COMMIT_SENT":
                _discard(source, connection)
                disposed = True
                raise MatchingPostgresCommitOutcomeUnknownError() from None
            if connection is not None and state in {"BEGUN", "WRITING"}:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    pass
            if connection is not None and not disposed:
                _discard(source, connection)
                disposed = True
            if isinstance(error, MatchingPostgresError):
                raise
            translated = _database_error(error)
            if translated is not None:
                raise translated from None
            raise MatchingPostgresConfigurationError() from None
        finally:
            if connection is not None and not disposed:
                _discard(source, connection)


def _prepare(connection: Any, role: str) -> None:
    _reset(connection)
    row = connection.execute(
        "SELECT session_user,current_user,"
        "current_setting('server_version_num')::integer/10000,"
        "component,current_schema_version,schema_head_version,"
        "min_app_compatible_version,max_app_compatible_version,"
        "required_iam_schema_version,migration_manifest_sha256 "
        "FROM matching.schema_compatibility"
    ).fetchone()
    expected = (
        role,
        role,
        18,
        "matching",
        MATCHING_SCHEMA_HEAD_VERSION,
        MATCHING_SCHEMA_HEAD_VERSION,
        MATCHING_SCHEMA_HEAD_VERSION,
        MATCHING_SCHEMA_HEAD_VERSION,
        MATCHING_REQUIRED_IAM_SCHEMA_VERSION,
        MATCHING_REVIEWED_MANIFEST_SHA256,
    )
    if row != expected:
        raise MatchingPostgresConfigurationError()


def _configure(
    connection: Any,
    *,
    settings: MatchingPostgresSettings,
    scope: str,
    operation: str,
    actor_id: UUID,
    session_id: UUID,
    organization_id: Optional[UUID],
    demand_id: Optional[UUID],
    attempt_id: Optional[UUID],
    invitation_id: Optional[UUID],
    selection_id: Optional[UUID],
    assignment_id: Optional[UUID],
    authority_marker: bytes,
    command_id: Optional[UUID],
    target_id: Optional[UUID],
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
        ("app.actor_user_id", str(actor_id)),
        ("app.session_id", str(session_id)),
        ("app.organization_id", _optional_text(organization_id)),
        ("app.demand_id", _optional_text(demand_id)),
        ("app.attempt_id", _optional_text(attempt_id)),
        ("app.invitation_id", _optional_text(invitation_id)),
        ("app.selection_id", _optional_text(selection_id)),
        ("app.selector_assignment_id", _optional_text(assignment_id)),
        ("app.authority_marker_sha256", authority_marker.hex()),
        ("app.command_id", _optional_text(command_id)),
        ("app.target_id", _optional_text(target_id)),
    )
    for name, value in values:
        row = connection.execute(
            "SELECT pg_catalog.set_config(%s,%s,true)", (name, value)
        ).fetchone()
        if not _set_config_result_matches(name, value, row):
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
    codes = {
        "ACCESS_DENIED",
        "IDEMPOTENCY_KEY_REUSED",
        "INVALID_STATE_TRANSITION",
        "INVITATION_ALREADY_SELECTED",
        "PRECONDITION_FAILED",
        "RESOURCE_NOT_FOUND",
        "SELECTION_NOT_READY",
        "SELECTOR_ASSIGNMENT_REQUIRED",
        "SERVICE_UNAVAILABLE",
    }
    for code in codes:
        if message == code or message.startswith(code + "\n"):
            return MatchingPostgresRejectedError(code)
    return None


def _recipient_view(value: Any) -> RecipientInvitationView:
    if not isinstance(value, dict) or set(value) != {
        "invitation_id",
        "status",
        "aggregate_version",
        "updated_at",
        "expires_at",
        "snapshot_sha256",
        "response_status",
        "disclosure",
    }:
        raise MatchingPostgresConfigurationError()
    status = value["status"]
    response_status = value["response_status"]
    if (
        status not in _CREATOR_STATUSES
        or response_status not in {None, "ACCEPTED", "DECLINED", "WITHDRAWN"}
        or not _hex_digest(value["snapshot_sha256"])
        or not isinstance(value["disclosure"], dict)
    ):
        raise MatchingPostgresConfigurationError()
    version = _json_version(value["aggregate_version"])
    return RecipientInvitationView(
        invitation_id=_json_uuid(value["invitation_id"]),
        status=status,
        aggregate_version=version,
        updated_at=_json_timestamp(value["updated_at"]),
        expires_at=_json_timestamp(value["expires_at"]),
        snapshot_sha256=value["snapshot_sha256"],
        response_status=response_status,
        disclosure=_deep_copy_json(value["disclosure"]),
    )


def _selection_view(value: Any) -> MatchingSelectionView:
    if not isinstance(value, dict) or set(value) != {
        "selection_id",
        "attempt_id",
        "candidate_selector_assignment_id",
        "candidate_selector_assignment_version",
        "status",
        "aggregate_version",
        "updated_at",
        "current_invitation_set_sha256",
        "chosen_invitation_id",
        "accepted_invitations",
    }:
        raise MatchingPostgresConfigurationError()
    if (
        value["status"] not in _SELECTION_STATUSES
        or not _hex_digest(value["current_invitation_set_sha256"])
        or not isinstance(value["accepted_invitations"], list)
        or len(value["accepted_invitations"]) > 100
    ):
        raise MatchingPostgresConfigurationError()
    candidates = tuple(_selection_candidate(item) for item in value["accepted_invitations"])
    if len({item.invitation_id for item in candidates}) != len(candidates):
        raise MatchingPostgresConfigurationError()
    candidate_ids = {str(item.invitation_id) for item in candidates}
    chosen_id = value["chosen_invitation_id"]
    if chosen_id is not None and chosen_id not in candidate_ids:
        raise MatchingPostgresConfigurationError()
    if value["status"] in {"PENDING_CHOICE", "SELECTED"}:
        if chosen_id is None:
            raise MatchingPostgresConfigurationError()
    elif chosen_id is not None:
        raise MatchingPostgresConfigurationError()
    return MatchingSelectionView(
        selection_id=_json_uuid(value["selection_id"]),
        attempt_id=_json_uuid(value["attempt_id"]),
        candidate_selector_assignment_id=_json_uuid(
            value["candidate_selector_assignment_id"]
        ),
        candidate_selector_assignment_version=_json_version(
            value["candidate_selector_assignment_version"]
        ),
        status=value["status"],
        aggregate_version=_json_version(value["aggregate_version"]),
        updated_at=_json_timestamp(value["updated_at"]),
        current_invitation_set_sha256=value["current_invitation_set_sha256"],
        chosen_invitation_id=(
            None
            if value["chosen_invitation_id"] is None
            else _json_uuid(value["chosen_invitation_id"])
        ),
        accepted_invitations=candidates,
    )


def _selection_candidate(value: Any) -> SelectionCandidateView:
    if not isinstance(value, dict) or set(value) != {
        "invitation_id",
        "creator_display_handle",
        "profile_id",
        "profile_version_id",
        "accepted_at",
        "capability_summary",
    }:
        raise MatchingPostgresConfigurationError()
    handle, summary = value["creator_display_handle"], value["capability_summary"]
    if (
        not isinstance(handle, str)
        or not 1 <= len(handle) <= 120
        or not isinstance(summary, str)
        or not 1 <= len(summary) <= 500
        or any(character in handle + summary for character in "<>\x00")
    ):
        raise MatchingPostgresConfigurationError()
    return SelectionCandidateView(
        invitation_id=_json_uuid(value["invitation_id"]),
        creator_display_handle=handle,
        profile_id=_json_uuid(value["profile_id"]),
        profile_version_id=_json_uuid(value["profile_version_id"]),
        accepted_at=_json_timestamp(value["accepted_at"]),
        capability_summary=summary,
    )


def _attempt_view(row: tuple[Any, ...]) -> MatchingAttemptView:
    if not isinstance(row, tuple) or len(row) != 6 or row[3] not in _ATTEMPT_STATUSES:
        raise MatchingPostgresConfigurationError()
    _require_version(row[2])
    _require_version(row[4])
    return MatchingAttemptView(
        attempt_id=_coerce_uuid(row[0]),
        demand_id=_coerce_uuid(row[1]),
        attempt_no=row[2],
        status=row[3],
        aggregate_version=row[4],
        updated_at=_coerce_timestamp(row[5]),
    )


def _json_uuid(value: Any) -> UUID:
    if not isinstance(value, str):
        raise MatchingPostgresConfigurationError()
    try:
        return UUID(value)
    except (ValueError, AttributeError):
        raise MatchingPostgresConfigurationError() from None


def _coerce_uuid(value: Any) -> UUID:
    if isinstance(value, UUID):
        return value
    return _json_uuid(value)


def _json_timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise MatchingPostgresConfigurationError()
    try:
        parsed = parse_utc_timestamp(value)
    except (TypeError, ValueError):
        if value.endswith("+00:00"):
            try:
                parsed = datetime.fromisoformat(value)
            except ValueError:
                raise MatchingPostgresConfigurationError() from None
        else:
            raise MatchingPostgresConfigurationError() from None
    return _coerce_timestamp(parsed)


def _coerce_timestamp(value: Any) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise MatchingPostgresConfigurationError()
    return value.astimezone(timezone.utc)


def _json_version(value: Any) -> int:
    try:
        _require_version(value)
    except (TypeError, ValueError):
        raise MatchingPostgresConfigurationError() from None
    return value


def _deep_copy_json(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, list):
        return tuple(_deep_copy_json(item) for item in value)
    if isinstance(value, dict):
        return {key: _deep_copy_json(item) for key, item in value.items()}
    raise MatchingPostgresConfigurationError()


def _require_creator_context(value: Any) -> None:
    if not isinstance(value, MatchingCreatorContext):
        raise TypeError("Creator context is invalid")


def _require_selector_discovery_context(value: Any) -> None:
    if not isinstance(value, MatchingSelectorDiscoveryContext):
        raise TypeError("Selector discovery context is invalid")


def _require_selector_context(value: Any) -> None:
    if not isinstance(value, MatchingSelectorContext):
        raise TypeError("Selector context is invalid")


def _require_creator_operation(
    value: Any, operation: CreatorInvitationOperation
) -> None:
    if not isinstance(value, CreatorInvitationMutation) or value.operation is not operation:
        raise TypeError("Creator invitation request is invalid")


def _require_selector_operation(
    value: Any, operation: CandidateSelectionOperation
) -> None:
    if not isinstance(value, CandidateSelectionMutation) or value.operation is not operation:
        raise TypeError("Candidate selection request is invalid")


def _require_page(
    limit: Any, cursor_time: Optional[datetime], cursor_id: Optional[UUID]
) -> None:
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Matching page limit is invalid")
    if (cursor_time is None) != (cursor_id is None):
        raise ValueError("Matching page cursor is invalid")
    if cursor_time is not None:
        _coerce_timestamp(cursor_time)
        _require_uuids(cursor_id)


def _require_uuids(*values: Any) -> None:
    if any(not isinstance(value, UUID) or value.int == 0 for value in values):
        raise ValueError("Matching UUID fact is invalid")


def _require_version(value: Any) -> None:
    if type(value) is not int or not 1 <= value <= 2_147_483_647:
        raise ValueError("Matching aggregate version is invalid")


def _require_digest(value: Any) -> None:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError("Matching digest is invalid")


def _hex_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _require_code(value: Any) -> None:
    if not isinstance(value, str) or not _CODE.fullmatch(value):
        raise ValueError("Matching reason code is invalid")


def _require_note(value: Any) -> None:
    if value is not None and (
        not isinstance(value, str)
        or len(value) > 500
        or any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in value)
    ):
        raise ValueError("Matching restricted note is invalid")


def _optional_text(value: Optional[UUID]) -> str:
    return "" if value is None else str(value)


def _strict_bool(value: Any) -> bool:
    if type(value) is not bool:
        raise MatchingPostgresConfigurationError()
    return value


def _set_config_result_matches(name: str, requested: str, row: Any) -> bool:
    if (
        type(row) is not tuple
        or len(row) != 1
        or type(row[0]) is not str
    ):
        return False
    if name not in {
        "lock_timeout",
        "statement_timeout",
        "idle_in_transaction_session_timeout",
    }:
        return row[0] == requested
    return _timeout_milliseconds(row[0]) == _timeout_milliseconds(requested)


def _timeout_milliseconds(value: str) -> Optional[int]:
    if value.endswith("ms"):
        digits, multiplier = value[:-2], 1
    elif value.endswith("s"):
        digits, multiplier = value[:-1], 1_000
    else:
        return None
    if not digits.isascii() or not digits.isdecimal() or int(digits) <= 0:
        return None
    return int(digits) * multiplier


__all__ = (
    "CandidateSelectionCommandResult",
    "CandidateSelectionMutation",
    "CandidateSelectionOperation",
    "CreatorInvitationMutation",
    "CreatorInvitationOperation",
    "MatchingAttemptPage",
    "MatchingAttemptView",
    "MatchingCommandContext",
    "MatchingCreatorContext",
    "MatchingPostgresCommitOutcomeUnknownError",
    "MatchingPostgresConfigurationError",
    "MatchingPostgresConnectionSource",
    "MatchingPostgresError",
    "MatchingPostgresRejectedError",
    "MatchingPostgresSettings",
    "MatchingSelectionView",
    "MatchingSelectorDiscoveryContext",
    "MatchingSelectorContext",
    "MatchingWriteMaterial",
    "PsycopgMatchingRuntime",
    "RecipientInvitationCommandResult",
    "RecipientInvitationPage",
    "RecipientInvitationView",
    "SelectionCandidateView",
)
