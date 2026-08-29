"""Managed Trust decision provider for Demand safety-hold evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hmac
from typing import Any
from uuid import UUID

from ....demand.ports.commands import DemandHoldDecision, DemandSafetyHoldResult
from .gateway import (
    TrustPostgresConfigurationError,
    TrustPostgresGatewaySettings,
    _configure,
    _database_error,
    _discard,
    _prepare,
    _reset,
)


_ACTIONS = frozenset({"SUBMIT_DEMAND", "VERIFY_DEMAND", "REQUEST_MATCHING"})
_POLICY = "demand-safety-hold-v1"


@dataclass(frozen=True)
class TrustDemandHoldEvidenceResult:
    """Exact Trust decision material safe to bind into Matching completion."""

    decision: DemandHoldDecision
    actor_id: str
    organization_id: str
    demand_id: str
    prospective_aggregate_version: int
    demand_version_id: str
    content_sha256: str
    action: str
    policy_version: str
    evidence_sha256: bytes = field(repr=False)
    evaluated_at: datetime
    valid_until: datetime

    def as_demand_safety_hold_result(self) -> DemandSafetyHoldResult:
        return DemandSafetyHoldResult(
            decision=self.decision,
            actor_id=self.actor_id,
            organization_id=self.organization_id,
            demand_id=self.demand_id,
            prospective_aggregate_version=self.prospective_aggregate_version,
            demand_version_id=self.demand_version_id,
            content_sha256=self.content_sha256,
            action=self.action,
            policy_version=self.policy_version,
            evaluated_at=self.evaluated_at,
            valid_until=self.valid_until,
        )


class PsycopgTrustDemandSafetyHoldProvider:
    """Return only an exact, current result from ``evaluate_demand_hold_v1``."""

    def __init__(
        self,
        *,
        decision_connections: Any,
        settings: TrustPostgresGatewaySettings = TrustPostgresGatewaySettings(),
    ) -> None:
        if not all(
            callable(getattr(decision_connections, name, None))
            for name in ("checkout", "release", "discard")
        ):
            raise TypeError("Trust decision connection source is unavailable")
        if not isinstance(settings, TrustPostgresGatewaySettings):
            raise TypeError("Trust PostgreSQL gateway settings are unavailable")
        self._connections = decision_connections
        self._settings = settings
        self._closed = False

    def evaluate(
        self,
        *,
        actor_id: str,
        organization_id: str,
        demand_id: str,
        prospective_aggregate_version: int,
        demand_version_id: str,
        content_sha256: str,
        action: str,
        policy_version: str,
    ) -> DemandSafetyHoldResult:
        return self.evaluate_for_matching(
            actor_id=actor_id,
            organization_id=organization_id,
            demand_id=demand_id,
            prospective_aggregate_version=prospective_aggregate_version,
            demand_version_id=demand_version_id,
            content_sha256=content_sha256,
            action=action,
            policy_version=policy_version,
        ).as_demand_safety_hold_result()

    def evaluate_for_matching(
        self,
        *,
        actor_id: str,
        organization_id: str,
        demand_id: str,
        prospective_aggregate_version: int,
        demand_version_id: str,
        content_sha256: str,
        action: str,
        policy_version: str,
    ) -> TrustDemandHoldEvidenceResult:
        if self._closed:
            raise TrustPostgresConfigurationError()
        actor = _uuid(actor_id)
        organization = _uuid(organization_id)
        demand = _uuid(demand_id)
        demand_version = _uuid(demand_version_id)
        if (
            type(prospective_aggregate_version) is not int
            or prospective_aggregate_version < 1
            or action not in _ACTIONS
            or policy_version != _POLICY
        ):
            raise ValueError("Trust Demand hold query is invalid")
        content_digest = _hex_digest(content_sha256)
        parameters = (
            actor,
            organization,
            demand,
            prospective_aggregate_version,
            demand_version,
            content_digest,
            action,
            policy_version,
        )
        connection = None
        transaction = False
        disposed = False
        try:
            connection = self._connections.checkout()
            _prepare(connection, "trust_decision")
            connection.execute(
                "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY"
            )
            transaction = True
            _configure(
                connection,
                settings=self._settings,
                scope="TRUST_DECISION",
                operation="EVALUATE_DEMAND_HOLD",
                actor_id=actor,
                session_id=None,
                organization_id=organization,
            )
            rows = connection.execute(
                "SELECT * FROM trust_api.evaluate_demand_hold_v1("
                + ",".join(["%s"] * 8)
                + ")",
                parameters,
            ).fetchmany(2)
            result = _parse_result(rows, parameters)
            connection.execute("COMMIT")
            transaction = False
            _reset(connection)
            self._connections.release(connection)
            disposed = True
            return result
        except BaseException as error:
            if connection is not None and transaction:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    pass
            if connection is not None and not disposed:
                _discard(self._connections, connection)
                disposed = True
            translated = _database_error(error)
            if translated is not None:
                raise translated from None
            if isinstance(error, (TrustPostgresConfigurationError, ValueError)):
                raise
            raise TrustPostgresConfigurationError() from None
        finally:
            if connection is not None and not disposed:
                _discard(self._connections, connection)

    def close(self) -> None:
        self._closed = True


def _parse_result(
    rows: Any,
    expected: tuple[Any, ...],
) -> TrustDemandHoldEvidenceResult:
    if not isinstance(rows, list) or len(rows) != 1:
        raise TrustPostgresConfigurationError()
    row = rows[0]
    if not isinstance(row, tuple) or len(row) != 12 or row[:8] != expected:
        raise TrustPostgresConfigurationError()
    decision, evidence, evaluated_at, valid_until = row[8:]
    if decision not in {"ALLOW", "BLOCK"} or not isinstance(evidence, bytes):
        raise TrustPostgresConfigurationError()
    if len(evidence) != 32 or not isinstance(evaluated_at, datetime) or not isinstance(
        valid_until, datetime
    ):
        raise TrustPostgresConfigurationError()
    if evaluated_at.tzinfo is None or valid_until.tzinfo is None:
        raise TrustPostgresConfigurationError()
    evaluated_at = evaluated_at.astimezone(timezone.utc)
    valid_until = valid_until.astimezone(timezone.utc)
    now = datetime.now(timezone.utc)
    if (
        evaluated_at > now
        or valid_until <= now
        or valid_until <= evaluated_at
        or valid_until - evaluated_at > timedelta(seconds=15)
    ):
        raise TrustPostgresConfigurationError()
    return TrustDemandHoldEvidenceResult(
        decision=DemandHoldDecision(decision),
        actor_id=str(expected[0]),
        organization_id=str(expected[1]),
        demand_id=str(expected[2]),
        prospective_aggregate_version=expected[3],
        demand_version_id=str(expected[4]),
        content_sha256=expected[5].hex(),
        action=expected[6],
        policy_version=expected[7],
        evidence_sha256=evidence,
        evaluated_at=evaluated_at,
        valid_until=valid_until,
    )


def _uuid(value: Any) -> UUID:
    if not isinstance(value, str):
        raise ValueError("Trust Demand hold identifier is invalid")
    try:
        result = UUID(value)
    except ValueError:
        raise ValueError("Trust Demand hold identifier is invalid") from None
    if result.int == 0 or str(result) != value:
        raise ValueError("Trust Demand hold identifier is invalid")
    return result


def _hex_digest(value: Any) -> bytes:
    if not isinstance(value, str) or len(value) != 64 or value != value.lower():
        raise ValueError("Trust Demand hold digest is invalid")
    try:
        result = bytes.fromhex(value)
    except ValueError:
        raise ValueError("Trust Demand hold digest is invalid") from None
    if len(result) != 32 or not hmac.compare_digest(result.hex(), value):
        raise ValueError("Trust Demand hold digest is invalid")
    return result


__all__ = [
    "PsycopgTrustDemandSafetyHoldProvider",
    "TrustDemandHoldEvidenceResult",
]
