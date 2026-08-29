"""PostgreSQL target discovery and object-authority composition.

The selected editor workspace decides which one authority layer is active.
Target discovery is performed by the corresponding narrow Profile or Demand
database program using the principal-graph marker.  Every returned target is
then rebound to an object/operation marker through the canonical IAM adapter;
the browser never supplies an organization, role, or assignment as authority.
"""

from __future__ import annotations

from typing import Any, Optional, Sequence, Tuple
from uuid import UUID

from psycopg.pq import TransactionStatus

from ...creator_profile.adapters.postgres import CreatorProfilePostgresOperation
from ...demand.adapters.postgres import DemandPostgresOperation
from ...identity_access.adapters.postgres.authority_markers import (
    DemandOwnerAuthorityMarkerRequest,
    DemandReviewerAuthorityMarkerRequest,
    ProfileSelfAuthorityMarkerRequest,
    PsycopgAuthorityMarkerResolver,
)
from ...identity_access.domain.errors import IamError
from .contracts import EditorPrincipal, EditorServiceError
from .postgres import DemandReadAuthority, ProfileReadAuthority


_PROFILE_OPERATIONS = {
    CreatorProfilePostgresOperation.CREATE: "CREATE_PROFILE",
    CreatorProfilePostgresOperation.SAVE_DRAFT: "SAVE_PROFILE_DRAFT",
    CreatorProfilePostgresOperation.PUBLISH: "PUBLISH_PROFILE",
    CreatorProfilePostgresOperation.PAUSE: "PAUSE_PROFILE",
    CreatorProfilePostgresOperation.RESUME: "RESUME_PROFILE",
    CreatorProfilePostgresOperation.ARCHIVE: "ARCHIVE_PROFILE",
}
_DEMAND_OWNER_OPERATIONS = {
    DemandPostgresOperation.CREATE: "CREATE",
    DemandPostgresOperation.CREATE_VERSION: "CREATE_VERSION",
    DemandPostgresOperation.SUBMIT: "SUBMIT",
    DemandPostgresOperation.CANCEL_OWNER: "CANCEL_OWNER",
}
_DEMAND_REVIEW_OPERATIONS = {
    DemandPostgresOperation.REQUEST_CHANGES: "REQUEST_CHANGES",
    DemandPostgresOperation.VERIFY: "VERIFY",
    DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT: (
        "RELEASE_REVIEW_ASSIGNMENT"
    ),
    DemandPostgresOperation.REQUEST_MATCHING: "REQUEST_MATCHING",
    DemandPostgresOperation.CANCEL_REVIEW: "CANCEL_REVIEW",
}
_MAXIMUM_TARGETS = 1_000


class PostgresEditorAuthorityProvider:
    """Resolve only session-bound targets and matching canonical markers."""

    def __init__(
        self,
        *,
        marker_resolver: PsycopgAuthorityMarkerResolver,
        profile_connections: Any,
        demand_owner_connections: Any,
        demand_reviewer_connections: Any,
    ) -> None:
        if not all(
            callable(getattr(source, name, None))
            for source in (
                profile_connections,
                demand_owner_connections,
                demand_reviewer_connections,
            )
            for name in ("checkout", "release", "discard")
        ):
            raise TypeError("editor authority connection sources are unavailable")
        if not all(
            callable(getattr(marker_resolver, name, None))
            for name in (
                "resolve_profile_self",
                "resolve_demand_owner",
                "resolve_demand_reviewer",
            )
        ):
            raise TypeError("editor authority marker resolver is unavailable")
        expected_sources = (
            getattr(marker_resolver, "_profile_connections", None),
            getattr(marker_resolver, "_demand_owner_connections", None),
            getattr(marker_resolver, "_demand_reviewer_connections", None),
        )
        supplied_sources = (
            profile_connections,
            demand_owner_connections,
            demand_reviewer_connections,
        )
        if expected_sources != supplied_sources:
            raise ValueError("editor authority pools are miswired")
        self._markers = marker_resolver
        self._profile_connections = profile_connections
        self._demand_owner_connections = demand_owner_connections
        self._demand_reviewer_connections = demand_reviewer_connections
        self._closed = False

    def profile(
        self,
        *,
        principal: EditorPrincipal,
        operation: CreatorProfilePostgresOperation,
        profile_id: str,
    ) -> ProfileReadAuthority:
        self._require_personal(principal)
        try:
            marker = self._markers.resolve_profile_self(
                ProfileSelfAuthorityMarkerRequest(
                    actor_user_id=_uuid(principal.user_id),
                    session_id=_uuid(principal.session_id),
                    operation=_PROFILE_OPERATIONS[operation],
                    profile_id=_uuid(profile_id),
                )
            )
        except KeyError:
            _not_found()
        except IamError as error:
            _iam_error(error)
        except (TypeError, ValueError):
            _unavailable()
        return ProfileReadAuthority(
            expected_authority_marker_sha256=marker,
            operation=operation,
        )

    def demand(
        self,
        *,
        principal: EditorPrincipal,
        operation: DemandPostgresOperation,
        demand_id: str,
        assignment_id: Optional[str] = None,
    ) -> DemandReadAuthority:
        if principal.workspace_kind == "ORGANIZATION":
            self._require_organization(principal)
            if assignment_id is not None:
                _not_found()
            try:
                operation_code = _DEMAND_OWNER_OPERATIONS[operation]
                organization_id = _uuid(principal.organization_id)
                marker = self._markers.resolve_demand_owner(
                    DemandOwnerAuthorityMarkerRequest(
                        actor_user_id=_uuid(principal.user_id),
                        session_id=_uuid(principal.session_id),
                        organization_id=organization_id,
                        operation=operation_code,
                        demand_id=_uuid(demand_id),
                    )
                )
            except KeyError:
                _not_found()
            except IamError as error:
                _iam_error(error)
            except (TypeError, ValueError):
                _unavailable()
            return DemandReadAuthority(
                operation=operation,
                expected_authority_marker_sha256=marker,
                organization_id=None,
            )

        self._require_platform_reviewer(principal)
        try:
            operation_code = _DEMAND_REVIEW_OPERATIONS[operation]
            target_id = _uuid(demand_id)
            assignment = None if assignment_id is None else _uuid(assignment_id)
        except KeyError:
            _not_found()
        candidates = tuple(
            item
            for item in self._reviewer_targets(principal)
            if item[1] == target_id and (assignment is None or item[2] == assignment)
        )
        if len(candidates) != 1:
            _not_found()
        organization_id, target_id, assignment = candidates[0]
        try:
            marker = self._markers.resolve_demand_reviewer(
                DemandReviewerAuthorityMarkerRequest(
                    actor_user_id=_uuid(principal.user_id),
                    session_id=_uuid(principal.session_id),
                    organization_id=organization_id,
                    operation=operation_code,
                    demand_id=target_id,
                    assignment_id=assignment,
                )
            )
        except IamError as error:
            _iam_error(error)
        except (TypeError, ValueError):
            _unavailable()
        return DemandReadAuthority(
            operation=operation,
            expected_authority_marker_sha256=marker,
            assignment_id=assignment,
            organization_id=organization_id,
        )

    def profile_targets(
        self, *, principal: EditorPrincipal
    ) -> Tuple[Tuple[str, ProfileReadAuthority], ...]:
        self._require_personal(principal)
        rows = self._discover(
            source=self._profile_connections,
            role="profile_app",
            context=(
                ("app.scope_kind", "PROFILE_SELF"),
                ("app.actor_user_id", principal.user_id),
                ("app.session_id", principal.session_id),
                ("app.operation", "LIST_PROFILE_TARGETS"),
            ),
            statement=(
                "SELECT profile_id FROM "
                "profile_api.list_owned_profile_targets_v1(%s,%s,%s) "
                "LIMIT 1001"
            ),
            parameters=(
                _uuid(principal.user_id),
                _uuid(principal.session_id),
                _principal_marker(principal),
            ),
            row_size=1,
        )
        profile_ids = _unique_rows(rows, columns=1)
        return tuple(
            (
                str(row[0]),
                self.profile(
                    principal=principal,
                    operation=CreatorProfilePostgresOperation.SAVE_DRAFT,
                    profile_id=str(row[0]),
                ),
            )
            for row in profile_ids
        )

    def demand_targets(
        self, *, principal: EditorPrincipal
    ) -> Tuple[Tuple[str, DemandReadAuthority], ...]:
        if principal.workspace_kind == "ORGANIZATION":
            self._require_organization(principal)
            rows = self._discover(
                source=self._demand_owner_connections,
                role="demand_self",
                context=(
                    ("app.scope_kind", "DEMAND_OWNER"),
                    ("app.actor_id", principal.user_id),
                    ("app.session_id", principal.session_id),
                    ("app.organization_id", principal.organization_id or ""),
                    ("app.operation", "LIST_DEMAND_TARGETS"),
                ),
                statement=(
                    "SELECT demand_id FROM "
                    "demand_api.list_owned_demand_targets_v1(%s,%s,%s,%s) "
                    "LIMIT 1001"
                ),
                parameters=(
                    _uuid(principal.user_id),
                    _uuid(principal.session_id),
                    _uuid(principal.organization_id),
                    _principal_marker(principal),
                ),
                row_size=1,
            )
            targets = _unique_rows(rows, columns=1)
            return tuple(
                (
                    str(row[0]),
                    self.demand(
                        principal=principal,
                        operation=DemandPostgresOperation.CREATE_VERSION,
                        demand_id=str(row[0]),
                    ),
                )
                for row in targets
            )

        self._require_platform_reviewer(principal)
        targets = self._reviewer_targets(principal)
        return tuple(
            (
                str(demand_id),
                self.demand(
                    principal=principal,
                    operation=DemandPostgresOperation.REQUEST_CHANGES,
                    demand_id=str(demand_id),
                    assignment_id=str(assignment_id),
                ),
            )
            for organization_id, demand_id, assignment_id in targets
        )

    def check_readiness(self, *, timeout_ms: int) -> None:
        if (
            self._closed
            or type(timeout_ms) is not int
            or not 1 <= timeout_ms <= 30_000
        ):
            raise RuntimeError("EDITOR_AUTHORITY_NOT_READY")
        checks = (
            (
                self._profile_connections,
                "profile_app",
                "profile_api.list_owned_profile_targets_v1(uuid,uuid,bytea)",
            ),
            (
                self._demand_owner_connections,
                "demand_self",
                "demand_api.list_owned_demand_targets_v1(uuid,uuid,uuid,bytea)",
            ),
            (
                self._demand_reviewer_connections,
                "demand_review",
                "demand_api.list_reviewer_demand_targets_v1(uuid,uuid,bytea)",
            ),
        )
        try:
            for source, role, signature in checks:
                rows = self._discover(
                    source=source,
                    role=role,
                    context=(),
                    statement=(
                        "SELECT pg_catalog.to_regprocedure(%s) IS NOT NULL,"
                        "pg_catalog.has_function_privilege(current_user,%s,'EXECUTE')"
                    ),
                    parameters=(signature, signature),
                    row_size=2,
                    readiness=True,
                )
                if rows != ((True, True),):
                    raise RuntimeError("authority discovery surface drifted")
        except BaseException:
            raise RuntimeError("EDITOR_AUTHORITY_NOT_READY") from None
        return None

    def close(self) -> None:
        self._closed = True

    def _reviewer_targets(
        self, principal: EditorPrincipal
    ) -> Tuple[Tuple[UUID, UUID, UUID], ...]:
        rows = self._discover(
            source=self._demand_reviewer_connections,
            role="demand_review",
            context=(
                ("app.scope_kind", "DEMAND_REVIEW"),
                ("app.actor_id", principal.user_id),
                ("app.session_id", principal.session_id),
                ("app.operation", "LIST_REVIEW_TARGETS"),
            ),
            statement=(
                "SELECT organization_id,demand_id,assignment_id FROM "
                "demand_api.list_reviewer_demand_targets_v1(%s,%s,%s) "
                "LIMIT 1001"
            ),
            parameters=(
                _uuid(principal.user_id),
                _uuid(principal.session_id),
                _principal_marker(principal),
            ),
            row_size=3,
        )
        return _unique_rows(rows, columns=3)

    def _discover(
        self,
        *,
        source: Any,
        role: str,
        context: Tuple[Tuple[str, str], ...],
        statement: str,
        parameters: Tuple[Any, ...],
        row_size: int,
        readiness: bool = False,
    ) -> Tuple[Tuple[Any, ...], ...]:
        if self._closed:
            _unavailable()
        connection = source.checkout()
        transaction = False
        released = False
        try:
            _reset(connection)
            identity = connection.execute(
                "SELECT current_user,session_user,"
                "current_setting('server_version_num')::integer"
            ).fetchone()
            if identity != (role, role, 180004) and (
                not isinstance(identity, tuple)
                or len(identity) != 3
                or identity[:2] != (role, role)
                or type(identity[2]) is not int
                or identity[2] // 10_000 != 18
            ):
                raise RuntimeError("authority discovery identity drifted")
            connection.execute(
                "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
            )
            transaction = True
            connection.execute("SET LOCAL TIME ZONE 'UTC'")
            connection.execute("SET LOCAL lock_timeout = '2000ms'")
            connection.execute("SET LOCAL statement_timeout = '10000ms'")
            connection.execute(
                "SET LOCAL idle_in_transaction_session_timeout = '15000ms'"
            )
            for name, value in context:
                installed = connection.execute(
                    "SELECT pg_catalog.set_config(%s,%s,true)", (name, value)
                ).fetchone()
                if installed != (value,):
                    raise RuntimeError("authority discovery context drifted")
            result = connection.execute(statement, parameters)
            rows = (
                (result.fetchone(),)
                if readiness
                else tuple(result.fetchall())
            )
            if readiness and rows == ((None,),):
                rows = ()
            if len(rows) > _MAXIMUM_TARGETS or any(
                not isinstance(row, Sequence)
                or isinstance(row, (str, bytes))
                or len(row) != row_size
                for row in rows
            ):
                raise ValueError("authority discovery row shape drifted")
            connection.execute("COMMIT")
            transaction = False
            _reset(connection)
            source.release(connection)
            released = True
            return tuple(tuple(row) for row in rows)
        except EditorServiceError:
            raise
        except BaseException:
            if transaction:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    pass
            try:
                _reset(connection)
            except BaseException:
                pass
            source.discard(connection)
            released = True
            _unavailable()
        finally:
            if not released:
                source.discard(connection)
        raise AssertionError("unreachable")

    @staticmethod
    def _require_personal(principal: EditorPrincipal) -> None:
        _production_principal(principal)
        if principal.workspace_kind != "PERSONAL" or principal.role_codes != (
            "CREATOR",
        ):
            _not_found()

    @staticmethod
    def _require_organization(principal: EditorPrincipal) -> None:
        _production_principal(principal)
        if (
            principal.workspace_kind != "ORGANIZATION"
            or principal.organization_id is None
            or "DEMAND_OWNER" not in principal.role_codes
        ):
            _not_found()

    @staticmethod
    def _require_platform_reviewer(principal: EditorPrincipal) -> None:
        _production_principal(principal)
        if (
            principal.workspace_kind != "PLATFORM"
            or "OPERATIONS_REVIEWER" not in principal.role_codes
        ):
            _not_found()


def _production_principal(principal: EditorPrincipal) -> None:
    if (
        not isinstance(principal, EditorPrincipal)
        or principal.workspace_id is None
        or not isinstance(principal.principal_marker_sha256, bytes)
        or len(principal.principal_marker_sha256) != 32
    ):
        _unavailable()


def _principal_marker(principal: EditorPrincipal) -> bytes:
    _production_principal(principal)
    return principal.principal_marker_sha256


def _unique_rows(
    rows: Tuple[Tuple[Any, ...], ...], *, columns: int
) -> Tuple[Tuple[UUID, ...], ...]:
    try:
        normalized = tuple(
            tuple(_database_uuid(value) for value in row) for row in rows
        )
    except (TypeError, ValueError):
        _unavailable()
    if any(len(row) != columns for row in normalized) or len(set(normalized)) != len(
        normalized
    ):
        _unavailable()
    return normalized


def _uuid(value: Any) -> UUID:
    try:
        result = value if isinstance(value, UUID) else UUID(value)
    except (TypeError, ValueError, AttributeError):
        _not_found()
    if result.int == 0 or str(result) != str(value):
        _not_found()
    return result


def _database_uuid(value: Any) -> UUID:
    result = value if isinstance(value, UUID) else UUID(value)
    if result.int == 0 or (isinstance(value, str) and str(result) != value):
        raise ValueError("database UUID is not canonical")
    return result


def _reset(connection: Any) -> None:
    if getattr(connection.info, "transaction_status", None) != TransactionStatus.IDLE:
        raise RuntimeError("authority discovery checkout is not idle")
    connection.execute("RESET ROLE")
    connection.execute("RESET ALL")
    connection.execute("DISCARD TEMP")


def _iam_error(error: IamError) -> None:
    if error.code in {"RESOURCE_NOT_FOUND", "ACCESS_DENIED"}:
        _not_found()
    _unavailable()


def _not_found() -> None:
    raise EditorServiceError(status=404, code="RESOURCE_NOT_FOUND")


def _unavailable() -> None:
    raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE")


__all__ = ["PostgresEditorAuthorityProvider"]
