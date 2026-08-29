"""Fast closure checks for the Demand Matching PostgreSQL gateway."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import UUID

import pytest
from psycopg.pq import TransactionStatus

from desire_platform.demand.adapters.postgres.matching_runtime import (
    CompleteSelectionDemandCommand,
    DemandMatchingCoordinatorContext,
    DemandMatchingDeliveryContext,
    DemandMatchingPostgresCommitOutcomeUnknownError,
    DemandMatchingPostgresConfigurationError,
    DemandMatchingPostgresRejectedError,
    DemandMatchingRuntimeSettings,
    MatchingRequestedDelivery,
    PsycopgDemandMatchingRuntime,
)


def uid(value: int) -> UUID:
    return UUID(f"d{value:07x}-0000-4000-8000-000000000001")


class ClosedSource:
    def checkout(self):
        raise AssertionError("validation must fail before checkout")

    def release(self, connection):
        del connection

    def discard(self, connection):
        del connection


class Cursor:
    def __init__(self, *, row=None, rows=None) -> None:
        self.row = row
        self.rows = [] if rows is None else rows

    def fetchone(self):
        return self.row

    def fetchmany(self, maximum):
        return list(self.rows[:maximum])


class CommitUnknownConnection:
    autocommit = True

    def __init__(self, role: str, result_row: tuple[object, ...]) -> None:
        self.role = role
        self.result_row = result_row
        self.info = SimpleNamespace(transaction_status=TransactionStatus.IDLE)

    def execute(self, statement, parameters=None):
        if statement.startswith("SELECT session_user"):
            return Cursor(row=(self.role, self.role, 18))
        if statement.startswith("SELECT pg_catalog.set_config"):
            assert parameters is not None
            return Cursor(row=(parameters[1],))
        if "claim_matching_requested_delivery_v1" in statement:
            return Cursor(rows=[self.result_row])
        if statement == "COMMIT":
            raise ConnectionError("commit acknowledgement lost")
        return Cursor()


class TrackingSource:
    def __init__(self, connection) -> None:
        self.connection = connection
        self.released = 0
        self.discarded = 0

    def checkout(self):
        return self.connection

    def release(self, connection):
        assert connection is self.connection
        self.released += 1

    def discard(self, connection):
        assert connection is self.connection
        self.discarded += 1


def test_role_sources_settings_and_closed_state_are_fail_closed() -> None:
    source = ClosedSource()
    with pytest.raises(TypeError):
        PsycopgDemandMatchingRuntime(
            delivery_connections=source,
            coordinator_connections=source,
        )
    with pytest.raises(ValueError):
        DemandMatchingRuntimeSettings(coordinator_role="demand_matching")
    runtime = PsycopgDemandMatchingRuntime(
        delivery_connections=ClosedSource(),
        coordinator_connections=ClosedSource(),
    )
    runtime.close()
    with pytest.raises(DemandMatchingPostgresConfigurationError):
        runtime.check_readiness(1_000)


def test_true_demand_envelope_tuple_is_a_dto_invariant() -> None:
    now = datetime.now(timezone.utc)
    values = dict(
        delivery_id=uid(1),
        source_event_id=uid(2),
        fencing_generation=1,
        lease_until=now,
        event_type="MatchingRequested",
        schema_version=1,
        aggregate_type="Demand",
        source_aggregate_id=uid(3),
        source_aggregate_version=7,
        original_actor_user_id=uid(11),
        organization_id=uid(4),
        demand_id=uid(3),
        demand_version_id=uid(5),
        envelope_sha256=b"e" * 32,
        demand_content_sha256=b"c" * 32,
        demand_aggregate_version=7,
        matching_request_id=uid(6),
        matching_request_version=1,
        funding_id=uid(7),
        composite_rule_requirement_id=uid(8),
        matching_rule_bundle_id=uid(9),
        matching_selector_digest=b"s" * 32,
        rule_requirement_sha256=b"r" * 32,
        authorization_digest=b"a" * 32,
        authorized_workload_principal_id=uid(10),
        replayed=False,
    )
    MatchingRequestedDelivery(**values)
    with pytest.raises(ValueError):
        MatchingRequestedDelivery(
            **{**values, "source_aggregate_id": values["matching_request_id"]}
        )


def test_complete_selection_trace_id_is_uuid_typed_end_to_end() -> None:
    values = dict(
        completion_command_id=uid(1),
        choose_receipt_id=uid(2),
        selection_id=uid(3),
        attempt_id=uid(4),
        invitation_id=uid(5),
        match_run_id=uid(6),
        expected_demand_version=7,
        demand_version_id=uid(7),
        matching_request_id=uid(8),
        matching_request_version=1,
        funding_id=uid(9),
        payload_hash_key_id="matching-payload-v1",
        payload_hash=b"p" * 32,
        demand_matched_event_id=uid(10),
        correlation_id=uid(11),
        trace_id=uid(12),
    )

    CompleteSelectionDemandCommand(**values)
    with pytest.raises(ValueError):
        CompleteSelectionDemandCommand(
            **{**values, "trace_id": str(values["trace_id"])}
        )

    runtime = PsycopgDemandMatchingRuntime(
        delivery_connections=ClosedSource(),
        coordinator_connections=ClosedSource(),
    )
    context = DemandMatchingCoordinatorContext(
        original_actor_user_id=uid(13),
        coordinator_workload_id=uid(14),
        organization_id=uid(15),
        demand_id=uid(16),
        coordinator_authority_marker_sha256=b"m" * 32,
    )
    with pytest.raises(DemandMatchingPostgresRejectedError) as denied:
        runtime.execute_complete_selection(
            context=context,
            command=CompleteSelectionDemandCommand(**values),
        )
    assert denied.value.code == "ACCESS_DENIED"


def test_commit_unknown_discards_and_is_never_retried() -> None:
    now = datetime.now(timezone.utc)
    result = (
        uid(1), uid(2), 1, now,
        "MatchingRequested", 1, "Demand", uid(3), 7,
        uid(11), uid(4), uid(3), uid(5), b"e" * 32, b"c" * 32, 7,
        uid(6), 1, uid(7), uid(8), uid(9), b"s" * 32,
        b"r" * 32, b"a" * 32, uid(10), False,
    )
    delivery_source = TrackingSource(
        CommitUnknownConnection("demand_matching", result)
    )
    runtime = PsycopgDemandMatchingRuntime(
        delivery_connections=delivery_source,
        coordinator_connections=ClosedSource(),
    )
    with pytest.raises(DemandMatchingPostgresCommitOutcomeUnknownError):
        runtime.claim_matching_requested_delivery(
            context=DemandMatchingDeliveryContext(uid(10), b"a" * 32),
            lease_digest_key_id="demand-matching-delivery-lease-v1",
            lease_digest=b"l" * 32,
            lease_seconds=60,
        )
    assert delivery_source.discarded == 1
    assert delivery_source.released == 0
