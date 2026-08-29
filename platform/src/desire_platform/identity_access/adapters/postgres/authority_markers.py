"""Role-bound PostgreSQL authority-marker resolution.

The three public methods accept only closed, immutable authority requests and
return one opaque SHA-256 marker.  Target aggregate rows are deliberately not
part of this adapter: PostgreSQL revalidates only the IAM authority graph and
binds the caller-supplied target identifiers into the marker.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, FrozenSet, Protocol, Sequence, Tuple
from uuid import UUID

from psycopg.pq import TransactionStatus

from ...domain.errors import IamError


_PROFILE_OPERATIONS: FrozenSet[str] = frozenset(
    (
        "CREATE_PROFILE",
        "SAVE_PROFILE_DRAFT",
        "PUBLISH_PROFILE",
        "PAUSE_PROFILE",
        "RESUME_PROFILE",
        "ARCHIVE_PROFILE",
    )
)
_DEMAND_OWNER_OPERATIONS: FrozenSet[str] = frozenset(
    ("CREATE", "CREATE_VERSION", "SUBMIT", "CANCEL_OWNER")
)
_DEMAND_REVIEWER_OPERATIONS: FrozenSet[str] = frozenset(
    (
        "REQUEST_CHANGES",
        "VERIFY",
        "RELEASE_REVIEW_ASSIGNMENT",
        "REQUEST_MATCHING",
        "CANCEL_REVIEW",
    )
)


@dataclass(frozen=True)
class ProfileSelfAuthorityMarkerRequest:
    actor_user_id: UUID
    session_id: UUID
    operation: str
    profile_id: UUID

    def __post_init__(self) -> None:
        _require_uuid(self.actor_user_id, "actor User")
        _require_uuid(self.session_id, "Session")
        _require_operation(self.operation, _PROFILE_OPERATIONS, "Profile")
        _require_uuid(self.profile_id, "Profile")


@dataclass(frozen=True)
class DemandOwnerAuthorityMarkerRequest:
    actor_user_id: UUID
    session_id: UUID
    organization_id: UUID
    operation: str
    demand_id: UUID

    def __post_init__(self) -> None:
        _require_uuid(self.actor_user_id, "actor User")
        _require_uuid(self.session_id, "Session")
        _require_uuid(self.organization_id, "Organization")
        _require_operation(
            self.operation,
            _DEMAND_OWNER_OPERATIONS,
            "Demand owner",
        )
        _require_uuid(self.demand_id, "Demand")


@dataclass(frozen=True)
class DemandReviewerAuthorityMarkerRequest:
    actor_user_id: UUID
    session_id: UUID
    organization_id: UUID
    operation: str
    demand_id: UUID
    assignment_id: UUID

    def __post_init__(self) -> None:
        _require_uuid(self.actor_user_id, "actor User")
        _require_uuid(self.session_id, "Session")
        _require_uuid(self.organization_id, "Organization")
        _require_operation(
            self.operation,
            _DEMAND_REVIEWER_OPERATIONS,
            "Demand reviewer",
        )
        _require_uuid(self.demand_id, "Demand")
        _require_uuid(self.assignment_id, "review assignment")


class _ConnectionSource(Protocol):
    def checkout(self) -> Any: ...

    def release(self, connection: Any) -> None: ...

    def discard(self, connection: Any) -> None: ...


@dataclass(frozen=True)
class _Resolution:
    connections: _ConnectionSource
    runtime_role: str
    scope_kind: str
    context: Tuple[Tuple[str, str], ...]
    statement: str
    parameters: Tuple[object, ...]


@dataclass(frozen=True)
class _Settings:
    postgres_major: int = 18
    lock_timeout_ms: int = 2_000
    statement_timeout_ms: int = 10_000
    idle_in_transaction_timeout_ms: int = 15_000


class PsycopgAuthorityMarkerResolver:
    """Resolve marker-only authority through three isolated runtime pools."""

    def __init__(
        self,
        *,
        profile_connections: _ConnectionSource,
        demand_owner_connections: _ConnectionSource,
        demand_reviewer_connections: _ConnectionSource,
    ) -> None:
        self._profile_connections = profile_connections
        self._demand_owner_connections = demand_owner_connections
        self._demand_reviewer_connections = demand_reviewer_connections
        self._settings = _Settings()

    def resolve_profile_self(
        self,
        request: ProfileSelfAuthorityMarkerRequest,
    ) -> bytes:
        if not isinstance(request, ProfileSelfAuthorityMarkerRequest):
            raise TypeError("Profile authority-marker request is invalid")
        return self._resolve(
            _Resolution(
                connections=self._profile_connections,
                runtime_role="profile_app",
                scope_kind="PROFILE_SELF",
                context=(
                    ("app.actor_user_id", str(request.actor_user_id)),
                    ("app.session_id", str(request.session_id)),
                    ("app.operation", request.operation),
                    ("app.profile_id", str(request.profile_id)),
                ),
                statement=(
                    "SELECT authority_marker_sha256 FROM "
                    "iam_api.resolve_profile_self_authority_marker_v1("
                    "%s,%s,%s,%s)"
                ),
                parameters=(
                    request.actor_user_id,
                    request.session_id,
                    request.operation,
                    request.profile_id,
                ),
            )
        )

    def resolve_demand_owner(
        self,
        request: DemandOwnerAuthorityMarkerRequest,
    ) -> bytes:
        if not isinstance(request, DemandOwnerAuthorityMarkerRequest):
            raise TypeError("Demand owner authority-marker request is invalid")
        return self._resolve(
            _Resolution(
                connections=self._demand_owner_connections,
                runtime_role="demand_self",
                scope_kind="DEMAND_OWNER",
                context=(
                    ("app.actor_id", str(request.actor_user_id)),
                    ("app.session_id", str(request.session_id)),
                    ("app.organization_id", str(request.organization_id)),
                    ("app.operation", request.operation),
                    ("app.demand_id", str(request.demand_id)),
                ),
                statement=(
                    "SELECT authority_marker_sha256 FROM "
                    "iam_api.resolve_demand_owner_authority_marker_v1("
                    "%s,%s,%s,%s,%s)"
                ),
                parameters=(
                    request.actor_user_id,
                    request.session_id,
                    request.organization_id,
                    request.operation,
                    request.demand_id,
                ),
            )
        )

    def resolve_demand_reviewer(
        self,
        request: DemandReviewerAuthorityMarkerRequest,
    ) -> bytes:
        if not isinstance(request, DemandReviewerAuthorityMarkerRequest):
            raise TypeError("Demand reviewer authority-marker request is invalid")
        return self._resolve(
            _Resolution(
                connections=self._demand_reviewer_connections,
                runtime_role="demand_review",
                scope_kind="DEMAND_REVIEW",
                context=(
                    ("app.actor_id", str(request.actor_user_id)),
                    ("app.session_id", str(request.session_id)),
                    ("app.organization_id", str(request.organization_id)),
                    ("app.operation", request.operation),
                    ("app.demand_id", str(request.demand_id)),
                    ("app.assignment_id", str(request.assignment_id)),
                ),
                statement=(
                    "SELECT authority_marker_sha256 FROM "
                    "iam_api.resolve_demand_reviewer_authority_marker_v2("
                    "%s,%s,%s,%s,%s,%s)"
                ),
                parameters=(
                    request.actor_user_id,
                    request.session_id,
                    request.organization_id,
                    request.operation,
                    request.demand_id,
                    request.assignment_id,
                ),
            )
        )

    def _resolve(self, resolution: _Resolution) -> bytes:
        connection = resolution.connections.checkout()
        transaction_started = False
        disposed = False
        try:
            self._prepare_connection(connection, resolution.runtime_role)
            connection.execute(
                "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
            )
            transaction_started = True
            self._install_context(connection, resolution)
            rows = connection.execute(
                resolution.statement,
                resolution.parameters,
            ).fetchall()
            marker = _one_marker(rows)
            connection.execute("COMMIT")
            transaction_started = False
            self._reset_and_release(connection, resolution)
            disposed = True
            return marker
        except IamError:
            self._abort_and_discard(
                connection,
                connections=resolution.connections,
                transaction_started=transaction_started,
            )
            disposed = True
            raise
        except BaseException as error:
            self._abort_and_discard(
                connection,
                connections=resolution.connections,
                transaction_started=transaction_started,
            )
            disposed = True
            raise IamError("SERVICE_UNAVAILABLE") from error
        finally:
            if not disposed:
                resolution.connections.discard(connection)

    def _prepare_connection(self, connection: Any, runtime_role: str) -> None:
        if connection.info.transaction_status != TransactionStatus.IDLE:
            raise RuntimeError("authority-marker checkout must be transaction-idle")
        _reset_connection(connection)
        identity = connection.execute(
            "SELECT current_user,session_user,"
            "current_setting('server_version_num')::integer"
        ).fetchone()
        if identity is None or identity[0:2] != (runtime_role, runtime_role):
            raise RuntimeError("authority-marker runtime identity is invalid")
        if identity[2] // 10_000 != self._settings.postgres_major:
            raise RuntimeError("authority-marker resolution requires PostgreSQL 18")

    def _install_context(self, connection: Any, resolution: _Resolution) -> None:
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
        values = (("app.scope_kind", resolution.scope_kind),) + resolution.context
        for name, value in values:
            installed = connection.execute(
                "SELECT pg_catalog.set_config(%s,%s,true)",
                (name, value),
            ).fetchone()
            if installed != (value,):
                raise RuntimeError("authority-marker context installation failed")
        for name, value in values:
            observed = connection.execute(
                "SELECT current_setting(%s,true)",
                (name,),
            ).fetchone()
            if observed != (value,):
                raise RuntimeError("authority-marker context readback failed")

    @staticmethod
    def _reset_and_release(connection: Any, resolution: _Resolution) -> None:
        _reset_connection(connection)
        setting_names = tuple(name for name, _value in resolution.context)
        expressions = ",".join(
            "NULLIF(current_setting(%s,true),'')" for _name in setting_names
        )
        identity = connection.execute(
            "SELECT current_user,session_user,"
            "NULLIF(current_setting('app.scope_kind',true),'')"
            + ("," + expressions if expressions else ""),
            setting_names,
        ).fetchone()
        if identity != (
            resolution.runtime_role,
            resolution.runtime_role,
            None,
        ) + (None,) * len(setting_names):
            raise RuntimeError("authority-marker connection reset failed")
        resolution.connections.release(connection)

    @staticmethod
    def _abort_and_discard(
        connection: Any,
        *,
        connections: _ConnectionSource,
        transaction_started: bool,
    ) -> None:
        try:
            if transaction_started:
                connection.execute("ROLLBACK")
            _reset_connection(connection)
        except BaseException:
            pass
        connections.discard(connection)


def _one_marker(rows: Sequence[Sequence[object]]) -> bytes:
    if len(rows) == 0:
        raise IamError("RESOURCE_NOT_FOUND")
    if len(rows) != 1 or len(rows[0]) != 1:
        raise ValueError("authority-marker database cardinality is invalid")
    marker = rows[0][0]
    if isinstance(marker, memoryview):
        marker = marker.tobytes()
    if type(marker) is not bytes or len(marker) != 32:
        raise ValueError("authority-marker database value is invalid")
    return marker


def _require_uuid(value: object, label: str) -> None:
    if not isinstance(value, UUID) or value.int == 0:
        raise ValueError("%s ID must be a non-zero UUID" % label)


def _require_operation(
    value: object,
    allowed: FrozenSet[str],
    label: str,
) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError("%s operation is not closed" % label)


def _reset_connection(connection: Any) -> None:
    connection.execute("RESET ROLE")
    connection.execute("RESET ALL")
    connection.execute("DISCARD TEMP")
