"""Closed PostgreSQL projection from Trust to authoritative Demand facts.

The two connection sources are deliberately role-isolated.  This adapter can
only invoke the reviewed Demand 0008 functions; it has no table SQL, generic
query hook, role switching, or in-memory fallback.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional
from uuid import UUID

from psycopg.pq import TransactionStatus

from ...ports.commands import (
    TrustDemandTarget,
    TrustOfficerAuthority,
    TrustOfficerConflictCheck,
    TrustReporterAuthority,
    TrustTargetUnavailableError,
)
from ....demand.adapters.postgres.migrations import (
    DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
    DEMAND_SCHEMA_HEAD_VERSION,
)


_REPORTER_ROLE = "trust_self"
_OFFICER_ROLE = "trust_officer"
_REPORT_OPERATION = "SUBMIT_REPORT"
_CONFLICT_OPERATIONS = frozenset({"CLAIM_CASE", "CLAIM_HOLD_RELEASE"})
_REPORTABLE_STATUSES = frozenset(
    {
        "SUBMITTED",
        "NEEDS_CHANGES",
        "VERIFIED",
        "FUNDING_PENDING",
        "FUNDED",
        "MATCHING",
        "MATCHED",
        "NO_MATCH",
        # Demand returns this uniform synthetic shape for terminal, foreign,
        # and absent targets so callers can map all three to the same 404.
        "TARGET_NOT_FOUND",
    }
)
_DEFAULT_STATEMENT_TIMEOUT_MS = 10_000


class PsycopgDemandTrustTarget:
    """Managed ``TrustTargetPort`` over two fixed Demand projections."""

    def __init__(
        self,
        *,
        reporter_connections: Any,
        officer_connections: Any,
    ) -> None:
        if reporter_connections is officer_connections:
            raise TypeError("Trust target connection roles must be isolated")
        for source in (reporter_connections, officer_connections):
            if not all(
                callable(getattr(source, method, None))
                for method in ("checkout", "release", "discard")
            ):
                raise TypeError("Trust target connection source is unavailable")
        self._reporter_connections = reporter_connections
        self._officer_connections = officer_connections
        self._closed = False

    def resolve_report_target(
        self,
        *,
        reporter_authority: TrustReporterAuthority,
        demand_id: str,
        demand_version_id: str,
    ) -> TrustDemandTarget:
        if (
            self._closed
            or not _valid_reporter_authority(reporter_authority)
            or not _canonical_uuid(demand_id)
            or not _canonical_uuid(demand_version_id)
        ):
            _unavailable()
        context = (
            ("app.scope_kind", "TRUST_REPORTER"),
            ("app.actor_id", reporter_authority.actor_user_id),
            ("app.session_id", reporter_authority.session_id),
            ("app.organization_id", reporter_authority.organization_id),
            ("app.operation", _REPORT_OPERATION),
            ("app.membership_id", reporter_authority.membership_id),
            (
                "app.membership_role_grant_id",
                reporter_authority.membership_role_grant_id,
            ),
            (
                "app.membership_role_grant_version",
                str(reporter_authority.membership_role_grant_version),
            ),
            ("app.demand_id", demand_id),
            ("app.demand_version_id", demand_version_id),
        )
        parameters = (
            UUID(reporter_authority.actor_user_id),
            UUID(reporter_authority.session_id),
            UUID(reporter_authority.organization_id),
            UUID(reporter_authority.membership_id),
            UUID(reporter_authority.membership_role_grant_id),
            reporter_authority.membership_role_grant_version,
            UUID(demand_id),
            UUID(demand_version_id),
            bytes.fromhex(reporter_authority.authority_marker_sha256),
        )
        target = self._read(
            source=self._reporter_connections,
            role=_REPORTER_ROLE,
            context=context,
            statement=(
                "SELECT organization_id,demand_id,demand_version_id,"
                "demand_version_no,demand_aggregate_version,demand_status,"
                "content_sha256,owner_user_id,reportable_until,"
                "reporter_party_marker_sha256,target_marker_sha256 "
                "FROM demand_api.resolve_trust_report_target_v1("
                "%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            ),
            parameters=parameters,
            projector=lambda row: _require_report_target(
                row,
                organization_id=reporter_authority.organization_id,
                demand_id=demand_id,
                demand_version_id=demand_version_id,
                owner_user_id=reporter_authority.actor_user_id,
            ),
        )
        return target

    def check_officer_conflict(
        self,
        *,
        officer_authority: TrustOfficerAuthority,
        operation: str,
        organization_id: str,
        demand_id: str,
        demand_version_id: str,
    ) -> TrustOfficerConflictCheck:
        if (
            self._closed
            or not _valid_officer_authority(officer_authority)
            or operation not in _CONFLICT_OPERATIONS
            or not _canonical_uuid(organization_id)
            or not _canonical_uuid(demand_id)
            or not _canonical_uuid(demand_version_id)
        ):
            _unavailable()
        context = (
            ("app.scope_kind", "TRUST_OFFICER"),
            ("app.actor_id", officer_authority.actor_user_id),
            ("app.session_id", officer_authority.session_id),
            ("app.organization_id", organization_id),
            ("app.operation", operation),
            ("app.duty_grant_id", officer_authority.duty_grant_id),
            (
                "app.duty_grant_version",
                str(officer_authority.duty_grant_version),
            ),
            ("app.demand_id", demand_id),
            ("app.demand_version_id", demand_version_id),
        )
        parameters = (
            UUID(officer_authority.actor_user_id),
            UUID(officer_authority.session_id),
            operation,
            UUID(officer_authority.duty_grant_id),
            officer_authority.duty_grant_version,
            UUID(organization_id),
            UUID(demand_id),
            UUID(demand_version_id),
            bytes.fromhex(officer_authority.authority_marker_sha256),
        )
        conflict = self._read(
            source=self._officer_connections,
            role=_OFFICER_ROLE,
            context=context,
            statement=(
                "SELECT officer_user_id,organization_id,demand_id,"
                "demand_version_id,conflict_free,"
                "conflict_attestation_sha256,evaluated_at,valid_until "
                "FROM demand_api.resolve_trust_officer_conflict_v1("
                "%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            ),
            parameters=parameters,
            projector=lambda row: _require_officer_conflict(
                row,
                officer_user_id=officer_authority.actor_user_id,
                organization_id=organization_id,
                demand_id=demand_id,
                demand_version_id=demand_version_id,
            ),
        )
        return conflict

    def close(self) -> None:
        # Pools belong to the composition root and may be shared with the
        # Trust authority/UOW adapters.  Closing this projection only seals it.
        self._closed = True

    def _read(
        self,
        *,
        source: Any,
        role: str,
        context: tuple[tuple[str, str], ...],
        statement: str,
        parameters: tuple[Any, ...],
        projector: Callable[[Any], Any],
    ) -> Any:
        connection: Any = None
        transaction = False
        handed_back = False
        try:
            connection = source.checkout()
            _reset(connection)
            preflight = connection.execute(
                "SELECT session_user,current_user,"
                "current_setting('server_version_num')::integer/10000,"
                "current_schema_version,schema_head_version,"
                "min_app_compatible_version,max_app_compatible_version,"
                "required_iam_schema_version "
                "FROM demand.schema_compatibility"
            ).fetchone()
            expected = (
                role,
                role,
                18,
                DEMAND_SCHEMA_HEAD_VERSION,
                DEMAND_SCHEMA_HEAD_VERSION,
                DEMAND_SCHEMA_HEAD_VERSION,
                DEMAND_SCHEMA_HEAD_VERSION,
                DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
            )
            if preflight != expected:
                raise RuntimeError("Demand Trust target preflight drifted")
            connection.execute(
                "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
            )
            transaction = True
            connection.execute("SET LOCAL TIME ZONE 'UTC'")
            connection.execute("SET LOCAL lock_timeout = '2000ms'")
            connection.execute(
                "SET LOCAL statement_timeout = '%dms'"
                % _DEFAULT_STATEMENT_TIMEOUT_MS
            )
            connection.execute(
                "SET LOCAL idle_in_transaction_session_timeout = '15000ms'"
            )
            for name, value in context:
                installed = connection.execute(
                    "SELECT pg_catalog.set_config(%s,%s,true)",
                    (name, value),
                ).fetchone()
                if installed != (value,):
                    raise RuntimeError("Demand Trust target context drifted")
            rows = connection.execute(statement, parameters).fetchmany(2)
            if not isinstance(rows, list) or len(rows) != 1:
                raise RuntimeError("Demand Trust projection cardinality drifted")
            result = projector(rows[0])
            connection.execute("COMMIT")
            transaction = False
            _reset(connection)
            source.release(connection)
            handed_back = True
            return result
        except BaseException:
            if connection is not None:
                if transaction:
                    try:
                        connection.execute("ROLLBACK")
                    except BaseException:
                        pass
                try:
                    _reset(connection)
                except BaseException:
                    pass
                if not handed_back:
                    try:
                        source.discard(connection)
                    except BaseException:
                        pass
            _unavailable()
        raise AssertionError("unreachable")

    def __repr__(self) -> str:
        return f"PsycopgDemandTrustTarget(closed={self._closed})"


def _valid_reporter_authority(value: Any) -> bool:
    return (
        isinstance(value, TrustReporterAuthority)
        and _canonical_uuid(value.actor_user_id)
        and _canonical_uuid(value.session_id)
        and _canonical_uuid(value.organization_id)
        and _canonical_uuid(value.membership_id)
        and _canonical_uuid(value.membership_role_grant_id)
        and type(value.membership_role_grant_version) is int
        and value.membership_role_grant_version >= 1
        and value.user_status == "ACTIVE"
        and value.session_status == "ACTIVE"
        and value.session_family_status == "ACTIVE"
        and value.organization_status == "ACTIVE"
        and value.membership_status == "ACTIVE"
        and value.role_code == "DEMAND_OWNER"
        and value.policy_requirements_satisfied is True
        and _digest_hex(value.authority_marker_sha256)
    )


def _valid_officer_authority(value: Any) -> bool:
    return (
        isinstance(value, TrustOfficerAuthority)
        and _canonical_uuid(value.actor_user_id)
        and _canonical_uuid(value.session_id)
        and _canonical_uuid(value.duty_grant_id)
        and type(value.duty_grant_version) is int
        and value.duty_grant_version >= 1
        and value.user_status == "ACTIVE"
        and value.session_status == "ACTIVE"
        and value.session_family_status == "ACTIVE"
        and value.duty_code == "TRUST_OFFICER"
        and _digest_hex(value.authority_marker_sha256)
    )


def _report_target(row: Any) -> Optional[TrustDemandTarget]:
    if not isinstance(row, tuple) or len(row) != 11:
        return None
    organization_id = _uuid_text(row[0])
    demand_id = _uuid_text(row[1])
    demand_version_id = _uuid_text(row[2])
    content_sha256 = _digest_bytes(row[6])
    owner_user_id = _uuid_text(row[7])
    reportable_until = _utc(row[8])
    reporter_marker = _digest_bytes(row[9])
    target_marker = _digest_bytes(row[10])
    if (
        organization_id is None
        or demand_id is None
        or demand_version_id is None
        or type(row[3]) is not int
        or row[3] < 1
        or type(row[4]) is not int
        or row[4] < 1
        or row[5] not in _REPORTABLE_STATUSES
        or content_sha256 is None
        or owner_user_id is None
        or reportable_until is None
        or reporter_marker is None
        or target_marker is None
    ):
        return None
    return TrustDemandTarget(
        organization_id=organization_id,
        demand_id=demand_id,
        demand_version_id=demand_version_id,
        demand_version_no=row[3],
        demand_aggregate_version=row[4],
        demand_status=row[5],
        content_sha256=content_sha256,
        owner_user_id=owner_user_id,
        reportable_until=reportable_until,
        reporter_party_marker_sha256=reporter_marker,
        target_marker_sha256=target_marker,
    )


def _require_report_target(
    row: Any,
    *,
    organization_id: str,
    demand_id: str,
    demand_version_id: str,
    owner_user_id: str,
) -> TrustDemandTarget:
    result = _report_target(row)
    if (
        result is None
        or result.organization_id != organization_id
        or result.demand_id != demand_id
        or result.demand_version_id != demand_version_id
        or result.owner_user_id != owner_user_id
    ):
        raise RuntimeError("Demand Trust report projection drifted")
    return result


def _officer_conflict(row: Any) -> Optional[TrustOfficerConflictCheck]:
    if not isinstance(row, tuple) or len(row) != 8:
        return None
    officer_user_id = _uuid_text(row[0])
    organization_id = _uuid_text(row[1])
    demand_id = _uuid_text(row[2])
    demand_version_id = _uuid_text(row[3])
    attestation = _digest_bytes(row[5])
    evaluated_at = _utc(row[6])
    valid_until = _utc(row[7])
    if (
        officer_user_id is None
        or organization_id is None
        or demand_id is None
        or demand_version_id is None
        or type(row[4]) is not bool
        or attestation is None
        or evaluated_at is None
        or valid_until is None
        or not evaluated_at < valid_until
        or valid_until - evaluated_at > timedelta(minutes=5)
    ):
        return None
    return TrustOfficerConflictCheck(
        officer_user_id=officer_user_id,
        organization_id=organization_id,
        demand_id=demand_id,
        demand_version_id=demand_version_id,
        conflict_free=row[4],
        conflict_attestation_sha256=attestation,
        evaluated_at=evaluated_at,
        valid_until=valid_until,
    )


def _require_officer_conflict(
    row: Any,
    *,
    officer_user_id: str,
    organization_id: str,
    demand_id: str,
    demand_version_id: str,
) -> TrustOfficerConflictCheck:
    result = _officer_conflict(row)
    if (
        result is None
        or result.officer_user_id != officer_user_id
        or result.organization_id != organization_id
        or result.demand_id != demand_id
        or result.demand_version_id != demand_version_id
    ):
        raise RuntimeError("Demand Trust conflict projection drifted")
    return result


def _uuid_text(value: Any) -> Optional[str]:
    if not isinstance(value, UUID) or value.int == 0:
        return None
    return str(value)


def _canonical_uuid(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = UUID(value)
    except (AttributeError, TypeError, ValueError):
        return False
    return parsed.int != 0 and str(parsed) == value


def _digest_hex(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        return len(bytes.fromhex(value)) == 32 and value == value.lower()
    except ValueError:
        return False


def _digest_bytes(value: Any) -> Optional[str]:
    if not isinstance(value, bytes) or len(value) != 32:
        return None
    return value.hex()


def _utc(value: Any) -> Optional[datetime]:
    if not isinstance(value, datetime) or value.tzinfo is None:
        return None
    try:
        if value.utcoffset() is None:
            return None
        return value.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        return None


def _reset(connection: Any) -> None:
    if (
        getattr(connection, "autocommit", None) is not True
        or getattr(getattr(connection, "info", None), "transaction_status", None)
        != TransactionStatus.IDLE
    ):
        raise RuntimeError("Demand Trust target connection is not idle")
    connection.execute("RESET ROLE")
    connection.execute("RESET ALL")
    connection.execute("CLOSE ALL")
    connection.execute("DISCARD TEMP")


def _unavailable() -> None:
    raise TrustTargetUnavailableError("Trust target unavailable")


__all__ = ["PsycopgDemandTrustTarget"]
