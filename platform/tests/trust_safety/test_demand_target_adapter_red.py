from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from psycopg.pq import TransactionStatus

from desire_platform.demand.adapters.postgres.migrations import (
    DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
    DEMAND_SCHEMA_HEAD_VERSION,
)
from desire_platform.trust_safety.adapters.postgres import (
    PsycopgDemandTrustTarget,
)
from desire_platform.trust_safety.ports.commands import (
    TrustDemandTarget,
    TrustOfficerAuthority,
    TrustOfficerConflictCheck,
    TrustReporterAuthority,
    TrustTargetUnavailableError,
)


ACTOR_ID = "71000000-0000-4000-8000-000000000001"
OFFICER_ID = "71000000-0000-4000-8000-000000000002"
SESSION_ID = "72000000-0000-4000-8000-000000000001"
OFFICER_SESSION_ID = "72000000-0000-4000-8000-000000000002"
ORGANIZATION_ID = "73000000-0000-4000-8000-000000000001"
MEMBERSHIP_ID = "74000000-0000-4000-8000-000000000001"
ROLE_GRANT_ID = "75000000-0000-4000-8000-000000000001"
DUTY_GRANT_ID = "75000000-0000-4000-8000-000000000002"
DEMAND_ID = "76000000-0000-4000-8000-000000000001"
DEMAND_VERSION_ID = "77000000-0000-4000-8000-000000000001"
NOW = datetime(2035, 1, 1, tzinfo=timezone.utc)


class _Result:
    def __init__(self, row=None) -> None:
        self._row = row

    def fetchone(self):
        return self._row

    def fetchmany(self, size):
        if self._row is None:
            return []
        if isinstance(self._row, list):
            return self._row[:size]
        return [self._row]


class _Info:
    transaction_status = TransactionStatus.IDLE


class _Connection:
    def __init__(self, role: str, row, *, fail: bool = False) -> None:
        self.role = role
        self.row = row
        self.fail = fail
        self.autocommit = True
        self.info = _Info()
        self.calls: list[tuple[str, object]] = []

    def execute(self, statement, parameters=None):
        self.calls.append((statement, parameters))
        if statement.startswith("BEGIN"):
            self.info.transaction_status = TransactionStatus.INTRANS
            return _Result()
        if statement in {"COMMIT", "ROLLBACK"}:
            self.info.transaction_status = TransactionStatus.IDLE
            return _Result()
        if "FROM demand.schema_compatibility" in statement:
            return _Result(
                (
                    self.role,
                    self.role,
                    18,
                    DEMAND_SCHEMA_HEAD_VERSION,
                    DEMAND_SCHEMA_HEAD_VERSION,
                    DEMAND_SCHEMA_HEAD_VERSION,
                    DEMAND_SCHEMA_HEAD_VERSION,
                    DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
                )
            )
        if "set_config" in statement:
            return _Result((parameters[1],))
        if "demand_api.resolve_trust_" in statement:
            if self.fail:
                raise RuntimeError("secret database diagnostic")
            return _Result(self.row)
        return _Result()


class _Source:
    def __init__(self, connection: _Connection) -> None:
        self.connection = connection
        self.checked_out = []
        self.released = []
        self.discarded = []

    def checkout(self):
        self.checked_out.append(self.connection)
        return self.connection

    def release(self, connection):
        self.released.append(connection)

    def discard(self, connection):
        self.discarded.append(connection)


def _reporter() -> TrustReporterAuthority:
    return TrustReporterAuthority(
        actor_user_id=ACTOR_ID,
        session_id=SESSION_ID,
        organization_id=ORGANIZATION_ID,
        user_status="ACTIVE",
        session_status="ACTIVE",
        session_family_status="ACTIVE",
        organization_status="ACTIVE",
        membership_id=MEMBERSHIP_ID,
        membership_status="ACTIVE",
        membership_role_grant_id=ROLE_GRANT_ID,
        membership_role_grant_version=3,
        role_code="DEMAND_OWNER",
        policy_requirements_satisfied=True,
        authority_marker_sha256="11" * 32,
    )


def _officer() -> TrustOfficerAuthority:
    return TrustOfficerAuthority(
        actor_user_id=OFFICER_ID,
        session_id=OFFICER_SESSION_ID,
        user_status="ACTIVE",
        session_status="ACTIVE",
        session_family_status="ACTIVE",
        duty_grant_id=DUTY_GRANT_ID,
        duty_grant_version=7,
        duty_code="TRUST_OFFICER",
        authority_marker_sha256="22" * 32,
    )


def _report_row(*, status: str = "SUBMITTED"):
    return (
        UUID(ORGANIZATION_ID),
        UUID(DEMAND_ID),
        UUID(DEMAND_VERSION_ID),
        2,
        4,
        status,
        bytes.fromhex("33" * 32),
        UUID(ACTOR_ID),
        NOW + timedelta(days=7),
        bytes.fromhex("44" * 32),
        bytes.fromhex("55" * 32),
    )


def _conflict_row(*, conflict_free: bool = True):
    return (
        UUID(OFFICER_ID),
        UUID(ORGANIZATION_ID),
        UUID(DEMAND_ID),
        UUID(DEMAND_VERSION_ID),
        conflict_free,
        bytes.fromhex("66" * 32),
        NOW,
        NOW + timedelta(minutes=5),
    )


_UNSET = object()


def _adapter(*, report_row=_UNSET, conflict_row=_UNSET):
    reporter_connection = _Connection(
        "trust_self", _report_row() if report_row is _UNSET else report_row
    )
    officer_connection = _Connection(
        "trust_officer",
        _conflict_row() if conflict_row is _UNSET else conflict_row,
    )
    reporter_source = _Source(reporter_connection)
    officer_source = _Source(officer_connection)
    return (
        PsycopgDemandTrustTarget(
            reporter_connections=reporter_source,
            officer_connections=officer_source,
        ),
        reporter_source,
        officer_source,
    )


def test_report_target_uses_one_fixed_read_only_trust_self_program() -> None:
    adapter, reporter_source, officer_source = _adapter()

    result = adapter.resolve_report_target(
        reporter_authority=_reporter(),
        demand_id=DEMAND_ID,
        demand_version_id=DEMAND_VERSION_ID,
    )

    assert result == TrustDemandTarget(
        organization_id=ORGANIZATION_ID,
        demand_id=DEMAND_ID,
        demand_version_id=DEMAND_VERSION_ID,
        demand_version_no=2,
        demand_aggregate_version=4,
        demand_status="SUBMITTED",
        content_sha256="33" * 32,
        owner_user_id=ACTOR_ID,
        reportable_until=NOW + timedelta(days=7),
        reporter_party_marker_sha256="44" * 32,
        target_marker_sha256="55" * 32,
    )
    assert reporter_source.released == [reporter_source.connection]
    assert reporter_source.discarded == []
    assert officer_source.checked_out == []
    statements = tuple(item[0] for item in reporter_source.connection.calls)
    assert "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY" in statements
    program = next(
        statement
        for statement in statements
        if "demand_api.resolve_trust_report_target_v1" in statement
    )
    assert "SELECT organization_id,demand_id,demand_version_id" in program
    assert "SELECT *" not in program.upper()
    assert not any(
        token in statement.upper()
        for statement in statements
        for token in ("INSERT ", "UPDATE ", "DELETE ", "ALTER ", "CREATE ")
    )
    contexts = {
        parameters[0]: parameters[1]
        for statement, parameters in reporter_source.connection.calls
        if "set_config" in statement
    }
    assert contexts == {
        "app.scope_kind": "TRUST_REPORTER",
        "app.actor_id": ACTOR_ID,
        "app.session_id": SESSION_ID,
        "app.organization_id": ORGANIZATION_ID,
        "app.operation": "SUBMIT_REPORT",
        "app.membership_id": MEMBERSHIP_ID,
        "app.membership_role_grant_id": ROLE_GRANT_ID,
        "app.membership_role_grant_version": "3",
        "app.demand_id": DEMAND_ID,
        "app.demand_version_id": DEMAND_VERSION_ID,
    }


@pytest.mark.parametrize("operation", ("CLAIM_CASE", "CLAIM_HOLD_RELEASE"))
@pytest.mark.parametrize("conflict_free", (True, False))
def test_officer_conflict_returns_closed_boolean_without_identity_reasons(
    conflict_free: bool,
    operation: str,
) -> None:
    adapter, reporter_source, officer_source = _adapter(
        conflict_row=_conflict_row(conflict_free=conflict_free)
    )

    result = adapter.check_officer_conflict(
        officer_authority=_officer(),
        operation=operation,
        organization_id=ORGANIZATION_ID,
        demand_id=DEMAND_ID,
        demand_version_id=DEMAND_VERSION_ID,
    )

    assert result == TrustOfficerConflictCheck(
        officer_user_id=OFFICER_ID,
        organization_id=ORGANIZATION_ID,
        demand_id=DEMAND_ID,
        demand_version_id=DEMAND_VERSION_ID,
        conflict_free=conflict_free,
        conflict_attestation_sha256="66" * 32,
        evaluated_at=NOW,
        valid_until=NOW + timedelta(minutes=5),
    )
    assert reporter_source.checked_out == []
    assert officer_source.released == [officer_source.connection]
    statements = tuple(item[0] for item in officer_source.connection.calls)
    assert "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY" in statements
    program = next(
        statement
        for statement in statements
        if "demand_api.resolve_trust_officer_conflict_v1" in statement
    )
    assert "conflict_free" in program
    assert "reason" not in program.lower()
    contexts = {
        parameters[0]: parameters[1]
        for statement, parameters in officer_source.connection.calls
        if "set_config" in statement
    }
    assert contexts["app.operation"] == operation


def test_authority_projection_and_pool_drift_fail_closed_before_sql() -> None:
    adapter, reporter_source, officer_source = _adapter()
    invalid_reporter = TrustReporterAuthority(
        **{
            **_reporter().__dict__,
            "membership_role_grant_version": 0,
        }
    )
    with pytest.raises(TrustTargetUnavailableError):
        adapter.resolve_report_target(
            reporter_authority=invalid_reporter,
            demand_id=DEMAND_ID,
            demand_version_id=DEMAND_VERSION_ID,
        )
    assert reporter_source.checked_out == []

    invalid_officer = TrustOfficerAuthority(
        **{
            **_officer().__dict__,
            "duty_code": "OPERATIONS_REVIEWER",
        }
    )
    with pytest.raises(TrustTargetUnavailableError):
        adapter.check_officer_conflict(
            officer_authority=invalid_officer,
            operation="CLAIM_CASE",
            organization_id=ORGANIZATION_ID,
            demand_id=DEMAND_ID,
            demand_version_id=DEMAND_VERSION_ID,
        )
    assert officer_source.checked_out == []

    with pytest.raises(TrustTargetUnavailableError):
        adapter.check_officer_conflict(
            officer_authority=_officer(),
            operation="PUBLISH_OUTCOME",
            organization_id=ORGANIZATION_ID,
            demand_id=DEMAND_ID,
            demand_version_id=DEMAND_VERSION_ID,
        )
    assert officer_source.checked_out == []

    shared = _Source(_Connection("trust_self", _report_row()))
    with pytest.raises(TypeError):
        PsycopgDemandTrustTarget(
            reporter_connections=shared,
            officer_connections=shared,
        )


@pytest.mark.parametrize(
    "report_row",
    (
        None,
        [_report_row(), _report_row()],
        (UUID(ORGANIZATION_ID),),
        _report_row()[:-1] + (b"short",),
        _report_row()[:7] + (UUID(OFFICER_ID),) + _report_row()[8:],
        _report_row()[:8]
        + ((NOW + timedelta(days=7)).replace(tzinfo=None),)
        + _report_row()[9:],
    ),
)
def test_missing_or_malformed_report_projection_is_secret_safe(report_row) -> None:
    adapter, reporter_source, _officer_source = _adapter(report_row=report_row)
    with pytest.raises(TrustTargetUnavailableError) as raised:
        adapter.resolve_report_target(
            reporter_authority=_reporter(),
            demand_id=DEMAND_ID,
            demand_version_id=DEMAND_VERSION_ID,
        )
    assert str(raised.value) == "Trust target unavailable"
    assert reporter_source.released == []
    assert reporter_source.discarded == [reporter_source.connection]


def test_database_details_wrong_physical_role_and_close_are_fail_closed() -> None:
    adapter, reporter_source, officer_source = _adapter()
    reporter_source.connection.fail = True
    with pytest.raises(TrustTargetUnavailableError) as raised:
        adapter.resolve_report_target(
            reporter_authority=_reporter(),
            demand_id=DEMAND_ID,
            demand_version_id=DEMAND_VERSION_ID,
        )
    assert "secret database diagnostic" not in repr(raised.value)
    assert reporter_source.discarded == [reporter_source.connection]

    adapter.close()
    adapter.close()
    with pytest.raises(TrustTargetUnavailableError):
        adapter.check_officer_conflict(
            officer_authority=_officer(),
            operation="CLAIM_CASE",
            organization_id=ORGANIZATION_ID,
            demand_id=DEMAND_ID,
            demand_version_id=DEMAND_VERSION_ID,
        )
    assert officer_source.checked_out == []
