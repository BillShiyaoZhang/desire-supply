"""Authoritative PostgreSQL editor-workspace resolution.

The browser may name only an opaque, server-issued ``workspace_id``.  It
cannot submit an organization UUID or any role choice.  PostgreSQL derives
all candidates from the active OIDC-backed IAM user/session authority graph.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Any, Optional, Protocol, Sequence, Tuple
from uuid import UUID

from psycopg.pq import TransactionStatus

from ...domain.errors import IamError


_WORKSPACE_ID = re.compile(
    r"^(?P<kind>org|personal|platform):"
    r"(?P<identifier>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12})$"
)
_ORGANIZATION_ROLES = frozenset(("ORG_ADMIN", "DEMAND_OWNER"))
_USER_ROLES = frozenset(("CREATOR",))
_PLATFORM_DUTIES = frozenset(
    (
        "ACCESS_ADMIN",
        "OPERATIONS_REVIEWER",
        "FINANCE_OPERATOR",
        "TRUST_OFFICER",
        "APPEAL_REVIEWER",
    )
)


class WorkspaceKind(str, Enum):
    ORGANIZATION = "ORGANIZATION"
    PERSONAL = "PERSONAL"
    PLATFORM = "PLATFORM"


@dataclass(frozen=True)
class EditorPrincipalResolutionRequest:
    actor_user_id: UUID
    session_id: UUID
    requested_workspace_id: Optional[str]

    def __post_init__(self) -> None:
        _require_uuid(self.actor_user_id, "actor user")
        _require_uuid(self.session_id, "session")
        if self.requested_workspace_id is not None:
            _parse_workspace_id(self.requested_workspace_id)


@dataclass(frozen=True)
class EditorWorkspaceListRequest:
    actor_user_id: UUID
    session_id: UUID

    def __post_init__(self) -> None:
        _require_uuid(self.actor_user_id, "actor user")
        _require_uuid(self.session_id, "session")


@dataclass(frozen=True)
class ResolvedEditorWorkspace:
    workspace_id: str
    workspace_kind: WorkspaceKind
    user_id: UUID
    session_id: UUID
    organization_id: Optional[UUID]
    membership_id: Optional[UUID]
    organization_role_codes: Tuple[str, ...]
    user_role_codes: Tuple[str, ...]
    platform_duty_codes: Tuple[str, ...]
    principal_marker: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _require_uuid(self.user_id, "resolved user")
        _require_uuid(self.session_id, "resolved session")
        if not isinstance(self.workspace_kind, WorkspaceKind):
            raise ValueError("resolved workspace kind is not closed")
        prefix, identifier = _parse_workspace_id(self.workspace_id)
        _require_codes(
            self.organization_role_codes,
            _ORGANIZATION_ROLES,
            "organization roles",
        )
        _require_codes(self.user_role_codes, _USER_ROLES, "user roles")
        _require_codes(
            self.platform_duty_codes,
            _PLATFORM_DUTIES,
            "platform duties",
        )
        if (
            not isinstance(self.principal_marker, bytes)
            or len(self.principal_marker) != 32
        ):
            raise ValueError("principal marker must be exactly 32 bytes")

        if self.workspace_kind is WorkspaceKind.ORGANIZATION:
            _require_uuid(self.organization_id, "organization")
            _require_uuid(self.membership_id, "membership")
            if prefix != "org" or identifier != self.organization_id:
                raise ValueError("organization workspace ID does not match authority")
            if not self.organization_role_codes:
                raise ValueError("organization workspace requires an active role")
        elif self.workspace_kind is WorkspaceKind.PERSONAL:
            if prefix != "personal" or identifier != self.user_id:
                raise ValueError("personal workspace ID does not match user")
            if self.organization_id is not None or self.membership_id is not None:
                raise ValueError("personal workspace cannot contain organization IDs")
            if self.organization_role_codes:
                raise ValueError("personal workspace cannot contain organization roles")
            if "CREATOR" not in self.user_role_codes:
                raise ValueError("personal workspace requires CREATOR authority")
        else:
            if prefix != "platform" or identifier != self.user_id:
                raise ValueError("platform workspace ID does not match user")
            if self.organization_id is not None or self.membership_id is not None:
                raise ValueError("platform workspace cannot contain organization IDs")
            if self.organization_role_codes:
                raise ValueError("platform workspace cannot contain organization roles")
            if not self.platform_duty_codes:
                raise ValueError("platform workspace requires an active platform duty")


class _ConnectionSource(Protocol):
    def checkout(self) -> Any: ...

    def release(self, connection: Any) -> None: ...

    def discard(self, connection: Any) -> None: ...


@dataclass(frozen=True)
class _Settings:
    runtime_role: str = "iam_app"
    lock_timeout_ms: int = 2_000
    statement_timeout_ms: int = 10_000
    idle_in_transaction_timeout_ms: int = 15_000


class PsycopgEditorPrincipalResolver:
    """Resolve exactly one editor workspace through the reviewed DB program."""

    def __init__(self, *, connections: _ConnectionSource) -> None:
        self._connections = connections
        self._settings = _Settings()

    def resolve(
        self,
        request: EditorPrincipalResolutionRequest,
    ) -> ResolvedEditorWorkspace:
        if not isinstance(request, EditorPrincipalResolutionRequest):
            raise TypeError("editor principal request is invalid")
        candidates = self._load_workspaces(
            actor_user_id=request.actor_user_id,
            session_id=request.session_id,
        )
        return _select_workspace(candidates, request.requested_workspace_id)

    def list_workspaces(
        self,
        request: EditorWorkspaceListRequest,
    ) -> Tuple[ResolvedEditorWorkspace, ...]:
        """Return the closed authority-derived candidates without selecting one."""

        if not isinstance(request, EditorWorkspaceListRequest):
            raise TypeError("editor workspace list request is invalid")
        return self._load_workspaces(
            actor_user_id=request.actor_user_id,
            session_id=request.session_id,
        )

    def _load_workspaces(
        self,
        *,
        actor_user_id: UUID,
        session_id: UUID,
    ) -> Tuple[ResolvedEditorWorkspace, ...]:
        connection = self._connections.checkout()
        transaction_started = False
        released = False
        try:
            self._validate_connection(connection)
            connection.execute(
                "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
            )
            transaction_started = True
            self._install_context(
                connection,
                actor_user_id=actor_user_id,
                session_id=session_id,
            )
            rows = connection.execute(
                """
                SELECT
                    workspace_id,
                    workspace_kind,
                    user_id,
                    session_id,
                    organization_id,
                    membership_id,
                    organization_role_codes,
                    user_role_codes,
                    platform_duty_codes,
                    principal_marker_sha256
                FROM iam_api.resolve_editor_principal_v1(%s, %s)
                ORDER BY workspace_id
                """,
                (actor_user_id, session_id),
            ).fetchall()
            identity_request = EditorWorkspaceListRequest(
                actor_user_id=actor_user_id,
                session_id=session_id,
            )
            candidates = tuple(
                _workspace_from_row(row, request=identity_request) for row in rows
            )
            _validate_candidate_set(candidates)
            connection.execute("COMMIT")
            transaction_started = False
            released = self._release_or_discard(connection)
            return candidates
        except IamError:
            self._abort_and_discard(
                connection,
                transaction_started=transaction_started,
            )
            released = True
            raise
        except BaseException as error:
            self._abort_and_discard(
                connection,
                transaction_started=transaction_started,
            )
            released = True
            raise IamError("SERVICE_UNAVAILABLE") from error
        finally:
            if not released:
                self._connections.discard(connection)

    def _validate_connection(self, connection: Any) -> None:
        if connection.info.transaction_status != TransactionStatus.IDLE:
            raise RuntimeError("editor principal checkout must be transaction-idle")
        _reset_connection(connection)
        identity = connection.execute(
            "SELECT current_user, session_user, "
            "current_setting('server_version_num')::integer"
        ).fetchone()
        if identity is None or identity[0:2] != (
            self._settings.runtime_role,
            self._settings.runtime_role,
        ):
            raise RuntimeError("editor principal connection identity is not iam_app")
        if identity[2] // 10_000 != 18:
            raise RuntimeError("editor principal resolution requires PostgreSQL 18")

    def _install_context(
        self,
        connection: Any,
        *,
        actor_user_id: UUID,
        session_id: UUID,
    ) -> None:
        connection.execute("SET LOCAL TIME ZONE 'UTC'")
        connection.execute(
            "SET LOCAL lock_timeout = '%dms'" % self._settings.lock_timeout_ms
        )
        connection.execute(
            "SET LOCAL statement_timeout = '%dms'"
            % self._settings.statement_timeout_ms
        )
        connection.execute(
            "SET LOCAL idle_in_transaction_session_timeout = '%dms'"
            % self._settings.idle_in_transaction_timeout_ms
        )
        values = (
            ("app.scope_kind", "EDITOR_PRINCIPAL"),
            ("app.actor_user_id", str(actor_user_id)),
            ("app.session_id", str(session_id)),
        )
        for name, value in values:
            installed = connection.execute(
                "SELECT pg_catalog.set_config(%s, %s, true)",
                (name, value),
            ).fetchone()
            if installed != (value,):
                raise RuntimeError("editor principal context installation failed")
        for name, value in values:
            observed = connection.execute(
                "SELECT current_setting(%s, true)",
                (name,),
            ).fetchone()
            if observed != (value,):
                raise RuntimeError("editor principal context readback failed")

    def _release_or_discard(self, connection: Any) -> bool:
        try:
            if connection.info.transaction_status != TransactionStatus.IDLE:
                self._connections.discard(connection)
                return True
            _reset_connection(connection)
            identity = connection.execute(
                "SELECT current_user, session_user, "
                "current_setting('app.actor_user_id', true), "
                "current_setting('app.session_id', true)"
            ).fetchone()
            if identity not in (
                (self._settings.runtime_role, self._settings.runtime_role, None, None),
                (self._settings.runtime_role, self._settings.runtime_role, "", ""),
            ):
                self._connections.discard(connection)
                return True
        except BaseException:
            self._connections.discard(connection)
            return True
        self._connections.release(connection)
        return True

    def _abort_and_discard(
        self,
        connection: Any,
        *,
        transaction_started: bool,
    ) -> None:
        try:
            if transaction_started:
                connection.execute("ROLLBACK")
            _reset_connection(connection)
        except BaseException:
            pass
        self._connections.discard(connection)


def _workspace_from_row(
    row: Sequence[Any],
    *,
    request: EditorWorkspaceListRequest,
) -> ResolvedEditorWorkspace:
    if not isinstance(row, Sequence) or isinstance(row, (str, bytes)) or len(row) != 10:
        raise ValueError("editor principal row shape is invalid")
    kind = WorkspaceKind(row[1])
    user_id = _database_uuid(row[2], "resolved user")
    session_id = _database_uuid(row[3], "resolved session")
    if user_id != request.actor_user_id or session_id != request.session_id:
        raise ValueError("editor principal row crossed the requested identity")
    organization_id = (
        None if row[4] is None else _database_uuid(row[4], "organization")
    )
    membership_id = None if row[5] is None else _database_uuid(row[5], "membership")
    marker = row[9]
    if isinstance(marker, memoryview):
        marker = marker.tobytes()
    return ResolvedEditorWorkspace(
        workspace_id=_database_text(row[0], "workspace ID"),
        workspace_kind=kind,
        user_id=user_id,
        session_id=session_id,
        organization_id=organization_id,
        membership_id=membership_id,
        organization_role_codes=_database_codes(row[6], "organization roles"),
        user_role_codes=_database_codes(row[7], "user roles"),
        platform_duty_codes=_database_codes(row[8], "platform duties"),
        principal_marker=marker,
    )


def _select_workspace(
    candidates: Tuple[ResolvedEditorWorkspace, ...],
    requested_workspace_id: Optional[str],
) -> ResolvedEditorWorkspace:
    _validate_candidate_set(candidates)
    if requested_workspace_id is None:
        if not candidates:
            raise IamError("RESOURCE_NOT_FOUND")
        if len(candidates) != 1:
            raise IamError("WORKSPACE_REQUIRED")
        return candidates[0]
    matches = tuple(
        candidate
        for candidate in candidates
        if candidate.workspace_id == requested_workspace_id
    )
    if len(matches) != 1:
        raise IamError("RESOURCE_NOT_FOUND")
    return matches[0]


def _validate_candidate_set(
    candidates: Tuple[ResolvedEditorWorkspace, ...],
) -> None:
    identifiers = tuple(candidate.workspace_id for candidate in candidates)
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("editor principal database returned duplicate workspaces")
    if identifiers != tuple(sorted(identifiers)):
        raise ValueError("editor principal database returned unordered workspaces")


def _parse_workspace_id(value: str) -> Tuple[str, UUID]:
    if not isinstance(value, str):
        raise ValueError("workspace ID must be text")
    match = _WORKSPACE_ID.fullmatch(value)
    if match is None:
        raise ValueError("workspace ID is not closed")
    identifier = UUID(match.group("identifier"))
    if identifier.int == 0:
        raise ValueError("workspace ID cannot contain a zero UUID")
    return match.group("kind"), identifier


def _require_uuid(value: object, label: str) -> None:
    if not isinstance(value, UUID) or value.int == 0:
        raise ValueError("%s ID must be a non-zero UUID" % label)


def _database_uuid(value: object, label: str) -> UUID:
    if isinstance(value, UUID):
        parsed = value
    elif isinstance(value, str):
        parsed = UUID(value)
    else:
        raise ValueError("%s ID is invalid" % label)
    _require_uuid(parsed, label)
    return parsed


def _database_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("%s is invalid" % label)
    return value


def _database_codes(value: object, label: str) -> Tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError("%s array is invalid" % label)
    result = tuple(value)
    if any(not isinstance(code, str) for code in result):
        raise ValueError("%s array contains a non-text code" % label)
    return result


def _require_codes(
    value: Tuple[str, ...],
    allowed: frozenset,
    label: str,
) -> None:
    if not isinstance(value, tuple):
        raise ValueError("%s must be immutable" % label)
    if tuple(sorted(set(value))) != value or not set(value).issubset(allowed):
        raise ValueError("%s are not closed, unique, and sorted" % label)


def _reset_connection(connection: Any) -> None:
    connection.execute("RESET ROLE")
    connection.execute("RESET ALL")
    connection.execute("DISCARD TEMP")
