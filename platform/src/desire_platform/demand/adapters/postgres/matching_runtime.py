"""Role-bound Demand delivery used by the production Matching workflow.

The gateway owns no orchestration policy. It binds the physical
``demand_matching`` pool to the fenced Demand15 handoff and uses the distinct
``matching_coordinator`` pool only to prove that direct Demand terminal
programs remain non-executable. Matching completion must cross the atomic
Matching-owned gateway instead. Connections are discarded after uncertain
COMMIT and no raw Demand content or Matching rank/score facts are exposed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
from typing import Any, Optional, Protocol
from uuid import UUID

from psycopg.pq import TransactionStatus


_KEY_ID = re.compile(r"[a-z0-9][a-z0-9-]{2,127}\Z")
_CLOSED_CODE = re.compile(r"[A-Z][A-Z0-9_]{1,63}\Z")
_ZERO_UUID = UUID(int=0)


class DemandMatchingPostgresError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class DemandMatchingPostgresConfigurationError(DemandMatchingPostgresError):
    def __init__(self) -> None:
        super().__init__("SERVICE_UNAVAILABLE")


class DemandMatchingPostgresRejectedError(DemandMatchingPostgresError):
    pass


class DemandMatchingPostgresCommitOutcomeUnknownError(
    DemandMatchingPostgresError
):
    def __init__(self) -> None:
        super().__init__("COMMAND_OUTCOME_UNKNOWN")


class DemandMatchingPostgresConnectionSource(Protocol):
    def checkout(self) -> Any: ...

    def release(self, connection: Any) -> None: ...

    def discard(self, connection: Any) -> None: ...


@dataclass(frozen=True)
class DemandMatchingRuntimeSettings:
    delivery_role: str = "demand_matching"
    coordinator_role: str = "matching_coordinator"
    required_server_major: int = 18
    lock_timeout_ms: int = 2_000
    statement_timeout_ms: int = 15_000
    idle_in_transaction_timeout_ms: int = 20_000

    def __post_init__(self) -> None:
        if (self.delivery_role, self.coordinator_role) != (
            "demand_matching",
            "matching_coordinator",
        ):
            raise ValueError("Demand Matching roles are not the reviewed set")
        if self.required_server_major != 18:
            raise ValueError("Demand Matching PostgreSQL major must be 18")
        for value, upper in (
            (self.lock_timeout_ms, 10_000),
            (self.statement_timeout_ms, 30_000),
            (self.idle_in_transaction_timeout_ms, 30_000),
        ):
            if type(value) is not int or not 1 <= value <= upper:
                raise ValueError("Demand Matching timeout is invalid")


@dataclass(frozen=True)
class DemandMatchingDeliveryContext:
    workload_id: UUID
    authority_marker_sha256: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _require_uuid(self.workload_id)
        _require_digest(self.authority_marker_sha256)


@dataclass(frozen=True)
class DemandMatchingCoordinatorContext:
    original_actor_user_id: UUID
    coordinator_workload_id: UUID
    organization_id: UUID
    demand_id: UUID
    coordinator_authority_marker_sha256: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _require_uuid(
            self.original_actor_user_id,
            self.coordinator_workload_id,
            self.organization_id,
            self.demand_id,
        )
        _require_digest(self.coordinator_authority_marker_sha256)


@dataclass(frozen=True)
class MatchingRequestedDelivery:
    delivery_id: UUID
    source_event_id: UUID
    fencing_generation: int
    lease_until: datetime
    event_type: str
    schema_version: int
    aggregate_type: str
    source_aggregate_id: UUID
    source_aggregate_version: int
    original_actor_user_id: UUID
    organization_id: UUID
    demand_id: UUID
    demand_version_id: UUID
    envelope_sha256: bytes = field(repr=False)
    demand_content_sha256: bytes = field(repr=False)
    demand_aggregate_version: int
    matching_request_id: UUID
    matching_request_version: int
    funding_id: UUID
    composite_rule_requirement_id: UUID
    matching_rule_bundle_id: UUID
    matching_selector_digest: bytes = field(repr=False)
    rule_requirement_sha256: bytes = field(repr=False)
    authorization_digest: bytes = field(repr=False)
    authorized_workload_principal_id: UUID
    replayed: bool

    def __post_init__(self) -> None:
        _require_uuid(
            self.delivery_id,
            self.source_event_id,
            self.source_aggregate_id,
            self.original_actor_user_id,
            self.organization_id,
            self.demand_id,
            self.demand_version_id,
            self.matching_request_id,
            self.funding_id,
            self.composite_rule_requirement_id,
            self.matching_rule_bundle_id,
            self.authorized_workload_principal_id,
        )
        for digest in (
            self.envelope_sha256,
            self.demand_content_sha256,
            self.matching_selector_digest,
            self.rule_requirement_sha256,
            self.authorization_digest,
        ):
            _require_digest(digest)
        if (
            self.event_type != "MatchingRequested"
            or self.schema_version != 1
            or self.aggregate_type != "Demand"
            or self.source_aggregate_id != self.demand_id
            or self.source_aggregate_version != self.demand_aggregate_version
            or type(self.fencing_generation) is not int
            or self.fencing_generation < 1
            or type(self.source_aggregate_version) is not int
            or self.source_aggregate_version < 1
            or type(self.matching_request_version) is not int
            or self.matching_request_version < 1
            or not _aware_utc(self.lease_until)
            or type(self.replayed) is not bool
        ):
            raise ValueError("MatchingRequested delivery projection is invalid")


@dataclass(frozen=True)
class DemandMatchingDeliveryMutationResult:
    status: str
    attempt_count: int
    next_available_at: Optional[datetime]
    replayed: bool

    def __post_init__(self) -> None:
        if (
            self.status not in {"AVAILABLE", "COMPLETED", "FAILED"}
            or type(self.attempt_count) is not int
            or self.attempt_count < 1
            or (
                self.next_available_at is not None
                and not _aware_utc(self.next_available_at)
            )
            or (self.status == "AVAILABLE")
            != (self.next_available_at is not None)
            or type(self.replayed) is not bool
        ):
            raise ValueError("Demand delivery mutation projection is invalid")


@dataclass(frozen=True)
class DemandMatchingTerminalResult:
    demand_id: UUID
    demand_version: int
    matching_request_version: int
    demand_status: str
    matching_request_status: str
    replayed: bool

    def __post_init__(self) -> None:
        _require_uuid(self.demand_id)
        if (
            type(self.demand_version) is not int
            or self.demand_version < 2
            or type(self.matching_request_version) is not int
            or self.matching_request_version < 2
            or self.demand_status not in {"MATCHED", "NO_MATCH"}
            or self.matching_request_status != "CLOSED"
            or type(self.replayed) is not bool
        ):
            raise ValueError("Demand Matching terminal projection is invalid")


@dataclass(frozen=True)
class CompleteSelectionDemandCommand:
    completion_command_id: UUID
    choose_receipt_id: UUID
    selection_id: UUID
    attempt_id: UUID
    invitation_id: UUID
    match_run_id: UUID
    expected_demand_version: int
    demand_version_id: UUID
    matching_request_id: UUID
    matching_request_version: int
    funding_id: UUID
    payload_hash_key_id: str
    payload_hash: bytes = field(repr=False)
    demand_matched_event_id: UUID
    correlation_id: UUID
    trace_id: UUID

    def __post_init__(self) -> None:
        _require_uuid(
            self.completion_command_id,
            self.choose_receipt_id,
            self.selection_id,
            self.attempt_id,
            self.invitation_id,
            self.match_run_id,
            self.demand_version_id,
            self.matching_request_id,
            self.funding_id,
            self.demand_matched_event_id,
            self.correlation_id,
            self.trace_id,
        )
        _require_version(self.expected_demand_version)
        _require_version(self.matching_request_version)
        _require_key(self.payload_hash_key_id)
        _require_digest(self.payload_hash)


@dataclass(frozen=True)
class CloseMatchingWithoutSelectionDemandCommand:
    completion_command_id: UUID
    close_receipt_id: UUID
    selection_id: UUID
    attempt_id: UUID
    match_run_id: UUID
    expected_demand_version: int
    demand_version_id: UUID
    matching_request_id: UUID
    expected_matching_request_version: int
    funding_id: UUID
    payload_hash_key_id: str
    payload_hash: bytes = field(repr=False)
    demand_closed_event_id: UUID
    correlation_id: UUID
    trace_id: UUID
    reason_code: str

    def __post_init__(self) -> None:
        _require_uuid(
            self.completion_command_id,
            self.close_receipt_id,
            self.selection_id,
            self.attempt_id,
            self.match_run_id,
            self.demand_version_id,
            self.matching_request_id,
            self.funding_id,
            self.demand_closed_event_id,
            self.correlation_id,
            self.trace_id,
        )
        _require_version(self.expected_demand_version)
        _require_version(self.expected_matching_request_version)
        _require_key(self.payload_hash_key_id)
        _require_digest(self.payload_hash)
        if not isinstance(self.reason_code, str) or not _CLOSED_CODE.fullmatch(
            self.reason_code
        ):
            raise ValueError("Demand no-selection reason is invalid")


class PsycopgDemandMatchingRuntime:
    """Closed delivery gateway plus direct-coordinator denial readiness."""

    def __init__(
        self,
        *,
        delivery_connections: DemandMatchingPostgresConnectionSource,
        coordinator_connections: DemandMatchingPostgresConnectionSource,
        settings: DemandMatchingRuntimeSettings = DemandMatchingRuntimeSettings(),
    ) -> None:
        for source in (delivery_connections, coordinator_connections):
            if source is None or any(
                not callable(getattr(source, name, None))
                for name in ("checkout", "release", "discard")
            ):
                raise TypeError("Demand Matching connection source is unavailable")
        if delivery_connections is coordinator_connections:
            raise TypeError("Demand Matching role pools must be distinct")
        if not isinstance(settings, DemandMatchingRuntimeSettings):
            raise TypeError("Demand Matching settings are unavailable")
        self._delivery_connections = delivery_connections
        self._coordinator_connections = coordinator_connections
        self._settings = settings
        self._closed = False

    def close(self) -> None:
        self._closed = True

    def check_readiness(self, timeout_ms: int) -> None:
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 30_000:
            raise ValueError("Demand Matching readiness timeout is invalid")
        if self._closed:
            raise DemandMatchingPostgresConfigurationError()
        self._check_role_readiness(
            source=self._delivery_connections,
            role="demand_matching",
            signatures=(
                "demand_api.claim_matching_requested_delivery_v1(uuid,bytea,text,bytea,integer)",
                "demand_api.complete_matching_requested_delivery_v1(uuid,uuid,bigint,text,bytea,uuid)",
                "demand_api.fail_matching_requested_delivery_v1(uuid,uuid,bigint,text,bytea,character varying,timestamp with time zone)",
            ),
            may_execute=True,
            timeout_ms=timeout_ms,
        )
        self._check_role_readiness(
            source=self._coordinator_connections,
            role="matching_coordinator",
            signatures=(
                "demand_api.execute_complete_selection_system_v1(uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,bigint,uuid,uuid,bigint,uuid,uuid,uuid,bytea,character varying,bytea,uuid,uuid,uuid)",
                "demand_api.execute_close_matching_without_selection_system_v1(uuid,uuid,uuid,uuid,uuid,uuid,uuid,bigint,uuid,uuid,bigint,uuid,uuid,uuid,bytea,text,bytea,uuid,uuid,uuid,text)",
            ),
            may_execute=False,
            timeout_ms=timeout_ms,
        )

    def claim_matching_requested_delivery(
        self,
        *,
        context: DemandMatchingDeliveryContext,
        lease_digest_key_id: str,
        lease_digest: bytes,
        lease_seconds: int,
    ) -> Optional[MatchingRequestedDelivery]:
        _require_delivery_context(context)
        _require_key(lease_digest_key_id)
        _require_digest(lease_digest)
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 86_400:
            raise ValueError("Demand Matching lease is invalid")
        rows = self._write(
            source=self._delivery_connections,
            role="demand_matching",
            scope="DEMAND_MATCH_DELIVERY",
            operation="CLAIM_MATCHING_REQUESTED_DELIVERY",
            workload_id=context.workload_id,
            authority_marker=context.authority_marker_sha256,
            statement=(
                "SELECT * FROM demand_api.claim_matching_requested_delivery_v1("
                "%s,%s,%s,%s,%s)"
            ),
            parameters=(
                context.workload_id,
                context.authority_marker_sha256,
                lease_digest_key_id,
                lease_digest,
                lease_seconds,
            ),
            maximum_rows=1,
        )
        if not rows:
            return None
        return _delivery(rows[0])

    def complete_matching_requested_delivery(
        self,
        *,
        context: DemandMatchingDeliveryContext,
        delivery_id: UUID,
        source_event_id: UUID,
        fencing_generation: int,
        lease_digest_key_id: str,
        lease_digest: bytes,
        matching_attempt_id: UUID,
    ) -> DemandMatchingDeliveryMutationResult:
        _require_delivery_context(context)
        _require_uuid(delivery_id, source_event_id, matching_attempt_id)
        _require_fence(fencing_generation)
        _require_key(lease_digest_key_id)
        _require_digest(lease_digest)
        return self._delivery_mutation(
            context=context,
            operation="COMPLETE_MATCHING_REQUESTED_DELIVERY",
            statement=(
                "SELECT * FROM demand_api."
                "complete_matching_requested_delivery_v1(%s,%s,%s,%s,%s,%s)"
            ),
            parameters=(
                delivery_id,
                source_event_id,
                fencing_generation,
                lease_digest_key_id,
                lease_digest,
                matching_attempt_id,
            ),
        )

    def fail_matching_requested_delivery(
        self,
        *,
        context: DemandMatchingDeliveryContext,
        delivery_id: UUID,
        source_event_id: UUID,
        fencing_generation: int,
        lease_digest_key_id: str,
        lease_digest: bytes,
        failure_code: str,
        retry_available_at: datetime,
    ) -> DemandMatchingDeliveryMutationResult:
        _require_delivery_context(context)
        _require_uuid(delivery_id, source_event_id)
        _require_fence(fencing_generation)
        _require_key(lease_digest_key_id)
        _require_digest(lease_digest)
        if not isinstance(failure_code, str) or not _CLOSED_CODE.fullmatch(
            failure_code
        ):
            raise ValueError("Demand delivery failure code is invalid")
        if not _aware_utc(retry_available_at):
            raise ValueError("Demand delivery retry time is invalid")
        return self._delivery_mutation(
            context=context,
            operation="FAIL_MATCHING_REQUESTED_DELIVERY",
            statement=(
                "SELECT * FROM demand_api."
                "fail_matching_requested_delivery_v1(%s,%s,%s,%s,%s,%s,%s)"
            ),
            parameters=(
                delivery_id,
                source_event_id,
                fencing_generation,
                lease_digest_key_id,
                lease_digest,
                failure_code,
                retry_available_at,
            ),
        )

    def execute_complete_selection(
        self,
        *,
        context: DemandMatchingCoordinatorContext,
        command: CompleteSelectionDemandCommand,
    ) -> DemandMatchingTerminalResult:
        _require_coordinator_context(context)
        if not isinstance(command, CompleteSelectionDemandCommand):
            raise TypeError("Demand completion command is unavailable")
        raise DemandMatchingPostgresRejectedError("ACCESS_DENIED")

    def execute_close_matching_without_selection(
        self,
        *,
        context: DemandMatchingCoordinatorContext,
        command: CloseMatchingWithoutSelectionDemandCommand,
    ) -> DemandMatchingTerminalResult:
        _require_coordinator_context(context)
        if not isinstance(command, CloseMatchingWithoutSelectionDemandCommand):
            raise TypeError("Demand no-selection command is unavailable")
        raise DemandMatchingPostgresRejectedError("ACCESS_DENIED")

    def _delivery_mutation(
        self,
        *,
        context: DemandMatchingDeliveryContext,
        operation: str,
        statement: str,
        parameters: tuple[Any, ...],
    ) -> DemandMatchingDeliveryMutationResult:
        rows = self._write(
            source=self._delivery_connections,
            role="demand_matching",
            scope="DEMAND_MATCH_DELIVERY",
            operation=operation,
            workload_id=context.workload_id,
            authority_marker=context.authority_marker_sha256,
            statement=statement,
            parameters=parameters,
            maximum_rows=2,
        )
        if len(rows) != 1:
            raise DemandMatchingPostgresConfigurationError()
        return _delivery_mutation(rows[0])

    def _coordinator_write(
        self,
        *,
        context: DemandMatchingCoordinatorContext,
        command_id: UUID,
        statement: str,
        parameters: tuple[Any, ...],
    ) -> list[tuple[Any, ...]]:
        rows = self._write(
            source=self._coordinator_connections,
            role="matching_coordinator",
            scope="DEMAND_MATCHING_COORDINATOR",
            operation="COMPLETE_SELECTION",
            workload_id=context.coordinator_workload_id,
            authority_marker=context.coordinator_authority_marker_sha256,
            actor_user_id=context.original_actor_user_id,
            organization_id=context.organization_id,
            demand_id=context.demand_id,
            command_id=command_id,
            statement=statement,
            parameters=parameters,
            maximum_rows=2,
        )
        if len(rows) != 1:
            raise DemandMatchingPostgresConfigurationError()
        return rows

    def _write(
        self,
        *,
        source: DemandMatchingPostgresConnectionSource,
        role: str,
        scope: str,
        operation: str,
        workload_id: UUID,
        authority_marker: bytes,
        statement: str,
        parameters: tuple[Any, ...],
        maximum_rows: int,
        actor_user_id: Optional[UUID] = None,
        organization_id: Optional[UUID] = None,
        demand_id: Optional[UUID] = None,
        command_id: Optional[UUID] = None,
    ) -> list[tuple[Any, ...]]:
        if self._closed:
            raise DemandMatchingPostgresConfigurationError()
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
                workload_id=workload_id,
                authority_marker=authority_marker,
                actor_user_id=actor_user_id,
                organization_id=organization_id,
                demand_id=demand_id,
                command_id=command_id,
            )
            state = "WRITING"
            rows = connection.execute(statement, parameters).fetchmany(maximum_rows)
            if not isinstance(rows, list):
                raise DemandMatchingPostgresConfigurationError()
            state = "COMMIT_SENT"
            connection.execute("COMMIT")
            state = "COMMITTED"
            _reset(connection)
            source.release(connection)
            disposed = True
            return rows
        except BaseException as error:
            if connection is not None and state == "COMMIT_SENT":
                _discard(source, connection)
                disposed = True
                raise DemandMatchingPostgresCommitOutcomeUnknownError() from None
            if connection is not None and state in {"BEGUN", "WRITING"}:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    pass
            if connection is not None and not disposed:
                _discard(source, connection)
                disposed = True
            if isinstance(error, DemandMatchingPostgresError):
                raise
            translated = _database_error(error)
            if translated is not None:
                raise translated from None
            raise DemandMatchingPostgresConfigurationError() from None
        finally:
            if connection is not None and not disposed:
                _discard(source, connection)

    def _check_role_readiness(
        self,
        *,
        source: DemandMatchingPostgresConnectionSource,
        role: str,
        signatures: tuple[str, ...],
        may_execute: bool,
        timeout_ms: int,
    ) -> None:
        connection = None
        disposed = False
        try:
            connection = source.checkout()
            _prepare(connection, role)
            row = connection.execute(
                "WITH expected(signature) AS (SELECT unnest(%s::text[])),"
                "resolved AS (SELECT signature,to_regprocedure(signature) oid "
                "FROM expected) SELECT count(*)=%s AND bool_and(oid IS NOT NULL "
                "AND has_function_privilege(session_user,oid,'EXECUTE')=%s "
                "AND procedure.prosecdef AND owner.rolname='demand_schema_owner' "
                "AND procedure.proconfig=ARRAY['search_path=pg_catalog, demand']::text[] "
                "AND NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(COALESCE("
                "procedure.proacl,pg_catalog.acldefault('f',procedure.proowner))) acl "
                "WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE')) "
                "FROM resolved LEFT JOIN pg_proc procedure ON procedure.oid=resolved.oid "
                "LEFT JOIN pg_roles owner ON owner.oid=procedure.proowner",
                (list(signatures), len(signatures), may_execute),
            ).fetchone()
            if row != (True,):
                raise DemandMatchingPostgresConfigurationError()
            source.release(connection)
            disposed = True
        except BaseException as error:
            if connection is not None and not disposed:
                _discard(source, connection)
                disposed = True
            if isinstance(error, DemandMatchingPostgresError):
                raise
            raise DemandMatchingPostgresConfigurationError() from None
        finally:
            if connection is not None and not disposed:
                _discard(source, connection)


def _prepare(connection: Any, role: str) -> None:
    _reset(connection)
    row = connection.execute(
        "SELECT session_user,current_user,"
        "current_setting('server_version_num')::integer/10000"
    ).fetchone()
    if row != (role, role, 18):
        raise DemandMatchingPostgresConfigurationError()


def _configure(
    connection: Any,
    *,
    settings: DemandMatchingRuntimeSettings,
    scope: str,
    operation: str,
    workload_id: UUID,
    authority_marker: bytes,
    actor_user_id: Optional[UUID],
    organization_id: Optional[UUID],
    demand_id: Optional[UUID],
    command_id: Optional[UUID],
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
        ("app.workload_id", str(workload_id)),
        ("app.authority_marker_sha256", authority_marker.hex()),
        ("app.actor_user_id", _optional_text(actor_user_id)),
        ("app.organization_id", _optional_text(organization_id)),
        ("app.demand_id", _optional_text(demand_id)),
        ("app.command_id", _optional_text(command_id)),
    )
    for name, value in values:
        row = connection.execute(
            "SELECT pg_catalog.set_config(%s,%s,true)", (name, value)
        ).fetchone()
        if row != (value,):
            raise DemandMatchingPostgresConfigurationError()


def _reset(connection: Any) -> None:
    if (
        getattr(connection, "autocommit", None) is not True
        or getattr(getattr(connection, "info", None), "transaction_status", None)
        != TransactionStatus.IDLE
    ):
        raise DemandMatchingPostgresConfigurationError()
    connection.execute("RESET ROLE")
    connection.execute("RESET ALL")
    connection.execute("CLOSE ALL")
    connection.execute("DISCARD TEMP")


def _discard(
    source: DemandMatchingPostgresConnectionSource,
    connection: Any,
) -> None:
    try:
        source.discard(connection)
    except BaseException:
        pass


def _database_error(
    error: BaseException,
) -> Optional[DemandMatchingPostgresRejectedError]:
    message = getattr(getattr(error, "diag", None), "message_primary", None)
    if not isinstance(message, str):
        message = str(error) if isinstance(error, Exception) else ""
    known = {
        "DEMAND_MATCH_DELIVERY_ACCESS_DENIED",
        "DEMAND_MATCHING_COORDINATOR_ACCESS_DENIED",
        "DEMAND_MATCH_DELIVERY_KEY_POLICY_UNAVAILABLE",
        "DEMAND_MATCH_DELIVERY_NOT_FOUND",
        "DEMAND_MATCH_DELIVERY_STALE_LEASE",
        "DEMAND_MATCH_DELIVERY_RECEIPT_MISMATCH",
        "DEMAND_COMPLETE_SELECTION_RECEIPT_MISMATCH",
        "DEMAND_CLOSE_WITHOUT_SELECTION_RECEIPT_MISMATCH",
        "INVALID_REQUEST",
        "INVALID_RETRY_AVAILABLE_AT",
        "PRECONDITION_FAILED",
        "SERVICE_UNAVAILABLE",
    }
    for code in known:
        if message == code or message.startswith(code + "\n"):
            return DemandMatchingPostgresRejectedError(code)
    return None


def _delivery(row: Any) -> MatchingRequestedDelivery:
    if not isinstance(row, tuple) or len(row) != 26:
        raise DemandMatchingPostgresConfigurationError()
    try:
        return MatchingRequestedDelivery(
            delivery_id=_uuid(row[0]),
            source_event_id=_uuid(row[1]),
            fencing_generation=_integer(row[2]),
            lease_until=_timestamp(row[3]),
            event_type=row[4],
            schema_version=_integer(row[5]),
            aggregate_type=row[6],
            source_aggregate_id=_uuid(row[7]),
            source_aggregate_version=_integer(row[8]),
            original_actor_user_id=_uuid(row[9]),
            organization_id=_uuid(row[10]),
            demand_id=_uuid(row[11]),
            demand_version_id=_uuid(row[12]),
            envelope_sha256=_digest(row[13]),
            demand_content_sha256=_digest(row[14]),
            demand_aggregate_version=_integer(row[15]),
            matching_request_id=_uuid(row[16]),
            matching_request_version=_integer(row[17]),
            funding_id=_uuid(row[18]),
            composite_rule_requirement_id=_uuid(row[19]),
            matching_rule_bundle_id=_uuid(row[20]),
            matching_selector_digest=_digest(row[21]),
            rule_requirement_sha256=_digest(row[22]),
            authorization_digest=_digest(row[23]),
            authorized_workload_principal_id=_uuid(row[24]),
            replayed=row[25],
        )
    except (TypeError, ValueError) as error:
        raise DemandMatchingPostgresConfigurationError() from error


def _delivery_mutation(row: Any) -> DemandMatchingDeliveryMutationResult:
    if not isinstance(row, tuple) or len(row) != 4:
        raise DemandMatchingPostgresConfigurationError()
    try:
        return DemandMatchingDeliveryMutationResult(
            status=row[0],
            attempt_count=_integer(row[1]),
            next_available_at=(None if row[2] is None else _timestamp(row[2])),
            replayed=row[3],
        )
    except (TypeError, ValueError) as error:
        raise DemandMatchingPostgresConfigurationError() from error


def _terminal(row: Any) -> DemandMatchingTerminalResult:
    if not isinstance(row, tuple) or len(row) != 6:
        raise DemandMatchingPostgresConfigurationError()
    try:
        return DemandMatchingTerminalResult(
            demand_id=_uuid(row[0]),
            demand_version=_integer(row[1]),
            matching_request_version=_integer(row[2]),
            demand_status=row[3],
            matching_request_status=row[4],
            replayed=row[5],
        )
    except (TypeError, ValueError) as error:
        raise DemandMatchingPostgresConfigurationError() from error


def _require_delivery_context(value: Any) -> None:
    if not isinstance(value, DemandMatchingDeliveryContext):
        raise TypeError("Demand delivery context is unavailable")


def _require_coordinator_context(value: Any) -> None:
    if not isinstance(value, DemandMatchingCoordinatorContext):
        raise TypeError("Demand coordinator context is unavailable")


def _require_uuid(*values: UUID) -> None:
    if any(not isinstance(value, UUID) or value == _ZERO_UUID for value in values):
        raise ValueError("UUID fact is invalid")


def _require_digest(value: bytes) -> None:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError("Digest fact is invalid")


def _require_version(value: int) -> None:
    if type(value) is not int or value < 1:
        raise ValueError("Aggregate version is invalid")


def _require_fence(value: int) -> None:
    if type(value) is not int or value < 1:
        raise ValueError("Fencing generation is invalid")


def _require_key(value: str) -> None:
    if not isinstance(value, str) or not _KEY_ID.fullmatch(value):
        raise ValueError("Digest key id is invalid")


def _uuid(value: Any) -> UUID:
    if isinstance(value, UUID):
        result = value
    elif isinstance(value, str):
        result = UUID(value)
    else:
        raise TypeError
    _require_uuid(result)
    return result


def _digest(value: Any) -> bytes:
    if isinstance(value, memoryview):
        value = value.tobytes()
    _require_digest(value)
    return value


def _integer(value: Any) -> int:
    if type(value) is not int:
        raise TypeError
    return value


def _timestamp(value: Any) -> datetime:
    if not _aware_utc(value):
        raise TypeError
    return value


def _aware_utc(value: Any) -> bool:
    return (
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() is not None
        and value.astimezone(timezone.utc).utcoffset() is not None
    )


def _optional_text(value: Optional[UUID]) -> str:
    return "" if value is None else str(value)


__all__ = [
    "CloseMatchingWithoutSelectionDemandCommand",
    "CompleteSelectionDemandCommand",
    "DemandMatchingCoordinatorContext",
    "DemandMatchingDeliveryContext",
    "DemandMatchingDeliveryMutationResult",
    "DemandMatchingPostgresCommitOutcomeUnknownError",
    "DemandMatchingPostgresConfigurationError",
    "DemandMatchingPostgresConnectionSource",
    "DemandMatchingPostgresError",
    "DemandMatchingPostgresRejectedError",
    "DemandMatchingRuntimeSettings",
    "DemandMatchingTerminalResult",
    "MatchingRequestedDelivery",
    "PsycopgDemandMatchingRuntime",
]
