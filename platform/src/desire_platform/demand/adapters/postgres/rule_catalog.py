"""Exact PostgreSQL projection for the current Demand rule requirement.

This is a read-only dependency adapter, not an authorization shortcut.  It
borrows the reviewed ``demand_self`` pool, proves its physical identity and
schema head, and reads the singleton policy in one repeatable-read snapshot.
No caller-provided SQL, role, rule identifier, or permissive fallback exists.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional, Tuple
from uuid import UUID

from psycopg.pq import TransactionStatus

from ...ports.commands import (
    DemandRuleCatalogUnavailableError,
    DemandRuleRequirement,
)
from .migrations.runner import (
    DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
    DEMAND_SCHEMA_HEAD_VERSION,
)


_OPERATIONS = frozenset(
    ("SUBMIT_DEMAND", "VERIFY_DEMAND", "REQUEST_MATCHING")
)
_EXPECTED_PREFLIGHT = (
    "demand_self",
    "demand_self",
    18,
    DEMAND_SCHEMA_HEAD_VERSION,
    DEMAND_SCHEMA_HEAD_VERSION,
    DEMAND_SCHEMA_HEAD_VERSION,
    DEMAND_SCHEMA_HEAD_VERSION,
    DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
)
_DEFAULT_STATEMENT_TIMEOUT_MS = 10_000
_READINESS_ORGANIZATION_ID = "00000000-0000-4000-8000-000000000001"
_READINESS_DEMAND_ID = "00000000-0000-4000-8000-000000000002"


class PsycopgDemandRuleCatalog:
    """Managed ``DemandRuleCatalogPort`` over the authoritative singleton."""

    def __init__(self, *, connections: Any) -> None:
        if not all(
            callable(getattr(connections, name, None))
            for name in ("checkout", "release", "discard")
        ):
            raise TypeError("Demand rule catalog connection source is unavailable")
        self._connections = connections
        self._closed = False

    def current_requirement(
        self,
        *,
        organization_id: str,
        demand_id: str,
        operation: str,
    ) -> DemandRuleRequirement:
        if (
            self._closed
            or not _canonical_uuid(organization_id)
            or not _canonical_uuid(demand_id)
            or operation not in _OPERATIONS
        ):
            _unavailable()
        return self._read(
            organization_id=organization_id,
            demand_id=demand_id,
            operation=operation,
            timeout_ms=_DEFAULT_STATEMENT_TIMEOUT_MS,
        )

    def check_readiness(self, *, timeout_ms: int) -> None:
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 30_000:
            raise ValueError("Demand rule catalog readiness timeout is outside bounds")
        if self._closed:
            _unavailable()
        self._read(
            organization_id=_READINESS_ORGANIZATION_ID,
            demand_id=_READINESS_DEMAND_ID,
            operation="SUBMIT_DEMAND",
            timeout_ms=timeout_ms,
        )
        return None

    def close(self) -> None:
        # The pool belongs to the composition root and may be shared with the
        # writer/repository.  Closing this adapter must never close that pool.
        self._closed = True

    def _read(
        self,
        *,
        organization_id: str,
        demand_id: str,
        operation: str,
        timeout_ms: int,
    ) -> DemandRuleRequirement:
        connection: Any = None
        transaction = False
        handed_back = False
        try:
            connection = self._connections.checkout()
            _reset(connection)
            preflight = connection.execute(
                "SELECT session_user,current_user,"
                "current_setting('server_version_num')::integer/10000,"
                "current_schema_version,schema_head_version,"
                "min_app_compatible_version,max_app_compatible_version,"
                "required_iam_schema_version "
                "FROM demand.schema_compatibility"
            ).fetchone()
            if preflight != _EXPECTED_PREFLIGHT:
                raise RuntimeError("Demand rule catalog preflight drifted")
            connection.execute(
                "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
            )
            transaction = True
            connection.execute("SET LOCAL TIME ZONE 'UTC'")
            connection.execute(
                "SET LOCAL lock_timeout = '%dms'" % min(2_000, timeout_ms)
            )
            connection.execute(
                "SET LOCAL statement_timeout = '%dms'" % timeout_ms
            )
            connection.execute(
                "SET LOCAL idle_in_transaction_session_timeout = '15000ms'"
            )
            context = (
                ("app.scope_kind", "DEMAND_RULE_CATALOG"),
                ("app.organization_id", organization_id),
                ("app.demand_id", demand_id),
                ("app.operation", operation),
            )
            for name, value in context:
                installed = connection.execute(
                    "SELECT pg_catalog.set_config(%s,%s,true)",
                    (name, value),
                ).fetchone()
                if installed != (value,):
                    raise RuntimeError("Demand rule catalog context drifted")
            row = connection.execute(
                "SELECT taxonomy_bundle_id,budget_rule_bundle_id,"
                "risk_rule_bundle_id,matching_rule_bundle_id,"
                "reason_code_bundle_id,composite_rule_requirement_id,"
                "rule_requirement_sha256,rule_effective_at,"
                "rule_effective_until,transaction_timestamp() "
                "FROM demand.receipt_key_policy WHERE singleton_key "
                "AND rule_effective_at<=transaction_timestamp() "
                "AND (rule_effective_until IS NULL "
                "OR transaction_timestamp()<rule_effective_until)"
            ).fetchone()
            result = _requirement(row)
            connection.execute("COMMIT")
            transaction = False
            _reset(connection)
            self._connections.release(connection)
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
                        self._connections.discard(connection)
                    except BaseException:
                        pass
            _unavailable()
        raise AssertionError("unreachable")

    def __repr__(self) -> str:
        return f"PsycopgDemandRuleCatalog(closed={self._closed})"


def _requirement(row: Any) -> DemandRuleRequirement:
    if not isinstance(row, tuple) or len(row) != 10:
        _unavailable()
    identifiers = row[:6]
    if any(not isinstance(value, UUID) or value.int == 0 for value in identifiers):
        _unavailable()
    if len(set(identifiers)) != len(identifiers):
        _unavailable()
    digest = row[6]
    effective_at = _utc(row[7])
    effective_until = None if row[8] is None else _utc(row[8])
    server_now = _utc(row[9])
    if (
        not isinstance(digest, bytes)
        or len(digest) != 32
        or effective_at is None
        or server_now is None
        or effective_at > server_now
        or (effective_until is not None and server_now >= effective_until)
        or (effective_until is not None and effective_at >= effective_until)
    ):
        _unavailable()
    values: Tuple[str, ...] = tuple(str(value) for value in identifiers)
    return DemandRuleRequirement(
        taxonomy_bundle_id=values[0],
        budget_rule_bundle_id=values[1],
        risk_rule_bundle_id=values[2],
        matching_rule_bundle_id=values[3],
        reason_code_bundle_id=values[4],
        composite_rule_requirement_id=values[5],
        effective_at=effective_at,
        effective_until=effective_until,
        requirement_sha256=digest.hex(),
    )


def _utc(value: Any) -> Optional[datetime]:
    if not isinstance(value, datetime) or value.tzinfo is None:
        return None
    try:
        if value.utcoffset() is None:
            return None
        result = value.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        return None
    return result


def _canonical_uuid(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = UUID(value)
    except (AttributeError, TypeError, ValueError):
        return False
    return parsed.int != 0 and str(parsed) == value


def _reset(connection: Any) -> None:
    if (
        getattr(connection, "autocommit", None) is not True
        or getattr(getattr(connection, "info", None), "transaction_status", None)
        != TransactionStatus.IDLE
    ):
        raise RuntimeError("Demand rule catalog connection is not idle")
    connection.execute("RESET ROLE")
    connection.execute("RESET ALL")
    connection.execute("CLOSE ALL")
    connection.execute("DISCARD TEMP")


def _unavailable() -> None:
    raise DemandRuleCatalogUnavailableError(
        "Demand rule catalog unavailable"
    ) from None


__all__ = ["PsycopgDemandRuleCatalog"]
