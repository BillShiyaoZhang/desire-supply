"""Deployment-only psycopg 3 boundary for reviewed IAM migrations.

The runner owns ordering and recovery.  This adapter deliberately exposes a
small, explicit DB-API surface: one autocommit connection holds the
session-level advisory lock and every artifact is applied in its own explicit
READ COMMITTED transaction.  No caller-controlled SQL or identifier reaches
the connection.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Optional, Sequence

from .catalog import MigrationArtifact, MigrationDescriptor, MigrationPhase
from .runner import (
    IamContractParameters,
    MigrationCommitOutcomeUnknown,
    MigrationConnectionLost,
    MigrationDatabaseState,
    MigrationLedgerRecord,
    MigrationRunnerError,
)


_SESSION_ROLES = frozenset({"iam_migration_runner"})
_SCHEMA_ROLES = frozenset({"schema_owner"})


@dataclass(frozen=True)
class PsycopgMigrationSettings:
    """Closed deployment-session settings; the conninfo is never reflected."""

    conninfo: str
    application_name: str = "desire-iam-migration-runner"
    connect_timeout_seconds: int = 5
    lock_timeout_ms: int = 5_000
    statement_timeout_ms: int = 30_000
    idle_in_transaction_timeout_ms: int = 15_000

    def __post_init__(self) -> None:
        if (
            not isinstance(self.conninfo, str)
            or not self.conninfo
            or not isinstance(self.application_name, str)
            or not self.application_name
            or self.connect_timeout_seconds <= 0
            or self.lock_timeout_ms <= 0
            or self.statement_timeout_ms <= 0
            or self.idle_in_transaction_timeout_ms <= 0
        ):
            raise MigrationRunnerError("MIGRATION_RUNNER_CONFIGURATION_INVALID")


class PsycopgMigrationAdapterUnavailable(MigrationRunnerError):
    """Backward-compatible name for the former default-deny scaffold."""

    def __init__(self) -> None:
        super().__init__("IAM_PG_MIGRATION_SESSION_NOT_AVAILABLE")


class PsycopgMigrationDriver:
    """Open one physical psycopg connection for a migration runner session."""

    def __init__(self, *, settings: PsycopgMigrationSettings, dbapi: Any) -> None:
        self._settings = settings
        self._dbapi = dbapi

    def connect(self, *, session_role: str) -> "PsycopgMigrationSession":
        _require_allowed_role(session_role, _SESSION_ROLES)
        try:
            connection = self._dbapi.connect(
                self._settings.conninfo,
                autocommit=True,
                application_name=self._settings.application_name,
                connect_timeout=self._settings.connect_timeout_seconds,
            )
        except Exception as error:
            if _is_connection_error(self._dbapi, error):
                raise MigrationConnectionLost() from None
            raise MigrationRunnerError("MIGRATION_CONNECTION_UNAVAILABLE") from None
        return PsycopgMigrationSession(
            connection=connection,
            dbapi=self._dbapi,
            settings=self._settings,
            session_role=session_role,
        )


class PsycopgMigrationSession:
    """Concrete implementation of the runner's closed ``MigrationSession``."""

    def __init__(
        self,
        *,
        connection: Any,
        dbapi: Any,
        settings: PsycopgMigrationSettings,
        session_role: str,
    ) -> None:
        _require_allowed_role(session_role, _SESSION_ROLES)
        self._connection = connection
        self._dbapi = dbapi
        self._settings = settings
        self._session_role = session_role
        self._schema_role: Optional[str] = None
        self._server_version_num: Optional[int] = None
        self._locked = False
        self._transaction_active = False
        self._lost = False
        self._closed = False

    def acquire_advisory_lock(self, key1: int, key2: int) -> None:
        self._require_open()
        if self._locked or self._transaction_active:
            raise MigrationRunnerError("MIGRATION_SESSION_STATE_INVALID")
        self._execute("SELECT pg_catalog.pg_advisory_lock(%s, %s)", (key1, key2))
        self._locked = True

    def prepare_runner(self, *, schema_role: str, postgres_major: int) -> None:
        # The runner acquires the lock first.  Keeping this primitive usable in
        # isolation makes the adapter boundary directly testable; the runner's
        # protocol remains the authority for cross-method ordering.
        self._require_open()
        if self._transaction_active:
            raise MigrationRunnerError("MIGRATION_SESSION_STATE_INVALID")
        _require_allowed_role(schema_role, _SCHEMA_ROLES)
        if postgres_major != 18:
            raise MigrationRunnerError("MIGRATION_POSTGRES_MAJOR_UNSUPPORTED")

        # Identifiers cannot be bind parameters.  The exact closed allowlist
        # above is therefore the authority for this one interpolation point.
        self._execute("SET ROLE " + schema_role)
        row = self._fetchone(
            "SELECT current_user, session_user, "
            "current_setting('server_version_num')::integer"
        )
        if row is None or len(row) != 3:
            raise MigrationRunnerError("MIGRATION_RUNNER_PREFLIGHT_FAILED")
        current_user, session_user, server_version_num = row
        try:
            version_number = int(server_version_num)
        except (TypeError, ValueError):
            raise MigrationRunnerError("MIGRATION_RUNNER_PREFLIGHT_FAILED") from None
        if current_user != schema_role or session_user != self._session_role:
            raise MigrationRunnerError("MIGRATION_RUNNER_ROLE_MISMATCH")
        if version_number // 10_000 != postgres_major:
            raise MigrationRunnerError("MIGRATION_POSTGRES_MAJOR_UNSUPPORTED")
        self._schema_role = schema_role
        self._server_version_num = version_number

    def inspect_database(self) -> MigrationDatabaseState:
        self._require_prepared_idle()
        relation_row = self._fetchone(
            "SELECT pg_catalog.to_regclass(%s), (EXISTS ("
            "SELECT 1 FROM pg_catalog.pg_namespace AS n "
            "WHERE n.nspname = ANY(%s)"
            ") OR EXISTS ("
            "SELECT 1 FROM pg_catalog.pg_class AS c "
            "JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace "
            "WHERE n.nspname = ANY(%s) AND c.relkind IN ('r','p','v','m','S','f')"
            "))",
            (
                "infra.schema_migrations",
                ["iam", "infra", "audit", "iam_api"],
                ["iam", "infra", "audit", "iam_api"],
            ),
        )
        if relation_row is None or len(relation_row) != 2:
            raise MigrationRunnerError("MIGRATION_RUNNER_PREFLIGHT_FAILED")
        ledger_exists = relation_row[0] is not None
        has_objects = bool(relation_row[1])
        records: tuple[MigrationLedgerRecord, ...] = ()
        if ledger_exists:
            rows = self._fetchall(
                "SELECT component, version, phase, name, checksum_sha256 "
                "FROM infra.schema_migrations WHERE component = %s "
                "ORDER BY version",
                ("iam",),
            )
            records = tuple(_ledger_record(row) for row in rows)
        return MigrationDatabaseState(
            ledger_exists=ledger_exists,
            has_unledgered_iam_objects=(not ledger_exists and has_objects),
            applied_migrations=records,
        )

    def begin_migration(self, descriptor: MigrationDescriptor) -> None:
        self._require_open()
        if self._transaction_active:
            raise MigrationRunnerError("MIGRATION_SESSION_STATE_INVALID")
        if not isinstance(descriptor, MigrationDescriptor):
            raise MigrationRunnerError("MIGRATION_CATALOG_INVALID")
        self._execute("BEGIN ISOLATION LEVEL READ COMMITTED")
        self._transaction_active = True

    def set_local_timeouts(self) -> None:
        self._require_transaction()
        settings = (
            ("lock_timeout", self._settings.lock_timeout_ms),
            ("statement_timeout", self._settings.statement_timeout_ms),
            (
                "idle_in_transaction_session_timeout",
                self._settings.idle_in_transaction_timeout_ms,
            ),
        )
        for name, milliseconds in settings:
            self._execute(
                "SELECT pg_catalog.set_config('" + name + "', %s, true)",
                (f"{milliseconds}ms",),
            )

    def execute_artifact(self, artifact: MigrationArtifact) -> None:
        self._require_transaction()
        if not isinstance(artifact, MigrationArtifact):
            raise MigrationRunnerError("MIGRATION_CATALOG_INVALID")
        try:
            sql_text = artifact.sql_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise MigrationRunnerError("MIGRATION_CATALOG_INVALID") from None
        self._execute(sql_text)

    def assert_artifact(self, descriptor: MigrationDescriptor) -> None:
        self._require_transaction()
        relation_names = _ASSERTED_RELATIONS.get(descriptor.version)
        if relation_names is None:
            raise MigrationRunnerError("MIGRATION_CATALOG_INVALID")
        if relation_names:
            placeholders = ", ".join("%s::pg_catalog.regclass" for _ in relation_names)
            self._execute("SELECT " + placeholders, tuple(relation_names))

    def insert_contract_row(self, parameters: IamContractParameters) -> None:
        self._require_transaction()
        self._execute(
            "INSERT INTO infra.iam_schema_contracts ("
            "component, schema_head_version, min_app_compatible_version, "
            "max_app_compatible_version, api_contract_sha256, "
            "event_contract_sha256, migration_manifest_sha256, "
            "combined_contract_sha256, generated_at"
            ") VALUES (%s, %s, %s, %s, %s, %s, %s, %s, "
            "transaction_timestamp()) "
            "ON CONFLICT (component) DO UPDATE SET "
            "schema_head_version = EXCLUDED.schema_head_version, "
            "min_app_compatible_version = EXCLUDED.min_app_compatible_version, "
            "max_app_compatible_version = EXCLUDED.max_app_compatible_version, "
            "api_contract_sha256 = EXCLUDED.api_contract_sha256, "
            "event_contract_sha256 = EXCLUDED.event_contract_sha256, "
            "migration_manifest_sha256 = EXCLUDED.migration_manifest_sha256, "
            "combined_contract_sha256 = EXCLUDED.combined_contract_sha256, "
            "generated_at = EXCLUDED.generated_at "
            "WHERE infra.iam_schema_contracts.schema_head_version "
            "< EXCLUDED.schema_head_version",
            (
                parameters.component,
                parameters.schema_head_version,
                parameters.min_app_compatible_version,
                parameters.max_app_compatible_version,
                parameters.api_contract_sha256,
                parameters.event_contract_sha256,
                parameters.migration_manifest_sha256,
                parameters.combined_contract_sha256,
            ),
        )

    def read_contract_parameters(self) -> Optional[IamContractParameters]:
        self._require_transaction()
        row = self._fetchone(
            "SELECT c.component, c.schema_head_version, "
            "c.min_app_compatible_version, c.max_app_compatible_version, "
            "c.api_contract_sha256, c.event_contract_sha256, "
            "c.migration_manifest_sha256, c.combined_contract_sha256 "
            "FROM infra.iam_schema_contracts AS c "
            "JOIN infra.iam_schema_compatibility AS v "
            "ON v.component = c.component "
            "AND v.schema_head_version = c.schema_head_version "
            "AND v.min_app_compatible_version = c.min_app_compatible_version "
            "AND v.max_app_compatible_version = c.max_app_compatible_version "
            "AND v.combined_contract_sha256 = c.combined_contract_sha256 "
            "WHERE c.component = %s "
            "AND v.current_schema_version = c.schema_head_version",
            ("iam",),
        )
        if row is None:
            return None
        if len(row) != 8:
            raise MigrationRunnerError("MIGRATION_CONTRACT_DRIFT")
        return IamContractParameters(*row)

    def insert_ledger_row(
        self,
        record: MigrationLedgerRecord,
        *,
        runner_version: str,
    ) -> None:
        self._require_transaction()
        schema_role = self._schema_role or "schema_owner"
        server_version_num = self._server_version_num
        if server_version_num is None:
            server_version_num = getattr(self._connection, "server_version_num", None)
        if server_version_num is None:
            server_version_num = getattr(
                getattr(self._connection, "info", None),
                "server_version",
                None,
            )
        if server_version_num is None:
            raise MigrationRunnerError("MIGRATION_SESSION_STATE_INVALID")
        self._execute(
            "INSERT INTO infra.schema_migrations ("
            "component, version, phase, name, checksum_sha256, applied_at, "
            "duration_ms, runner_version, applied_by_session_role, "
            "applied_as_role, postgres_server_version_num"
            ") VALUES (%s, %s, %s, %s, %s, transaction_timestamp(), %s, "
            "%s, %s, %s, %s)",
            (
                record.component,
                record.version,
                record.phase.value,
                record.name,
                record.checksum_sha256,
                0,
                runner_version,
                self._session_role,
                schema_role,
                int(server_version_num),
            ),
        )

    def commit_migration(self) -> None:
        self._require_transaction()
        try:
            self._connection.commit()
        except Exception:
            # Once COMMIT has been sent no driver state can prove whether the
            # transaction became durable.  The runner must reconnect and use
            # the ledger protocol; this physical connection is never reused.
            self._transaction_active = False
            self._lost = True
            raise MigrationCommitOutcomeUnknown() from None
        self._transaction_active = False

    def rollback_migration(self) -> None:
        self._require_transaction()
        try:
            self._connection.rollback()
        except Exception as error:
            self._transaction_active = False
            if _is_connection_error(self._dbapi, error):
                self._lost = True
                raise MigrationConnectionLost() from None
            raise MigrationRunnerError("MIGRATION_ROLLBACK_FAILED") from None
        self._transaction_active = False

    def read_ledger_record(
        self,
        *,
        component: str,
        version: int,
    ) -> Optional[MigrationLedgerRecord]:
        self._require_prepared_idle()
        row = self._fetchone(
            "SELECT component, version, phase, name, checksum_sha256 "
            "FROM infra.schema_migrations WHERE component = %s AND version = %s",
            (component, version),
        )
        return None if row is None else _ledger_record(row)

    def release_advisory_lock(self, key1: int, key2: int) -> None:
        self._require_locked_idle()
        row = self._fetchone(
            "SELECT pg_catalog.pg_advisory_unlock(%s, %s)",
            (key1, key2),
        )
        if row is None or len(row) != 1 or row[0] is not True:
            raise MigrationRunnerError("MIGRATION_ADVISORY_UNLOCK_FAILED")
        self._locked = False

    def close(self, *, discard: bool) -> None:
        if self._closed:
            raise MigrationRunnerError("MIGRATION_SESSION_STATE_INVALID")
        if not discard and (self._lost or self._transaction_active or self._locked):
            raise MigrationRunnerError("MIGRATION_SESSION_STATE_INVALID")
        # For a deployment-only non-pooled connection, both dispositions close
        # the physical session.  A discard path intentionally executes nothing
        # before close (no rollback, RESET, probe, or advisory unlock).
        try:
            self._connection.close()
        finally:
            self._closed = True

    def _execute(self, sql: str, parameters: Optional[Sequence[Any]] = None) -> Any:
        self._require_open()
        try:
            return self._connection.execute(sql, parameters)
        except Exception as error:
            if _is_connection_error(self._dbapi, error):
                self._lost = True
                self._locked = False
                self._transaction_active = False
                raise MigrationConnectionLost() from None
            raise

    def _fetchone(
        self,
        sql: str,
        parameters: Optional[Sequence[Any]] = None,
    ) -> Any:
        cursor = self._execute(sql, parameters)
        return cursor.fetchone()

    def _fetchall(
        self,
        sql: str,
        parameters: Optional[Sequence[Any]] = None,
    ) -> Iterable[Any]:
        cursor = self._execute(sql, parameters)
        return cursor.fetchall()

    def _require_open(self) -> None:
        if self._closed or self._lost:
            raise MigrationConnectionLost()

    def _require_locked_idle(self) -> None:
        self._require_open()
        if not self._locked or self._transaction_active:
            raise MigrationRunnerError("MIGRATION_SESSION_STATE_INVALID")

    def _require_prepared_idle(self) -> None:
        self._require_locked_idle()
        if self._schema_role is None or self._server_version_num is None:
            raise MigrationRunnerError("MIGRATION_SESSION_STATE_INVALID")

    def _require_transaction(self) -> None:
        self._require_open()
        if not self._transaction_active:
            raise MigrationRunnerError("MIGRATION_SESSION_STATE_INVALID")


_ASSERTED_RELATIONS = {
    0: ("infra.schema_migrations",),
    1: ("iam.policy_selectors", "iam.policy_bundles"),
    2: (
        "iam.access_invitations",
        "iam.user_role_grants",
        "iam.membership_role_grants",
    ),
    3: ("iam.session_families", "iam.sessions", "iam.consent_grants"),
    4: (
        "infra.command_receipts",
        "audit.audit_events",
        "infra.outbox_events",
    ),
    5: (),
    6: (),
    7: ("infra.iam_schema_contracts", "infra.iam_schema_compatibility"),
    8: ("infra.consumer_principals", "infra.consumer_inbox_events"),
    9: (),
    10: (),
    11: (),
    12: (
        "iam_api.read_session_bootstrap_v1",
        "iam_api.read_invitation_preview_v1",
        "iam_api.read_me_authority_policy_graph_v1",
        "iam_api.read_organization_memberships_page_v1",
    ),
    13: (),
    14: (),
    15: (),
    16: (),
    17: ("iam.platform_duty_grants",),
    18: ("iam.platform_duty_grants",),
    19: (),
    20: (),
    21: (),
    22: (),
    23: (
        "infra.iam_sandbox_bootstrap_state",
        "infra.iam_sandbox_bootstrap_accounts",
        "infra.iam_sandbox_bootstrap_runs",
    ),
    24: (
        "iam_api.resolve_cookie_session_v2",
        "iam.session_security_events",
    ),
    25: (),
    26: (),
    27: (),
    28: (),
    29: (),
    30: ("iam.platform_duty_grants", "infra.command_receipts"),
    31: ("infra.iam_sandbox_bootstrap_manifest_bridges",),
    32: (),
    33: (),
    34: (),
    35: (),
    36: (),
    37: (),
    38: (),
    39: (),
    40: (),
    41: (),
    42: (),
    43: (),
    44: (),
    45: (),
    46: (),
    47: (),
    48: (),
}


def _require_allowed_role(role: str, allowed: frozenset[str]) -> None:
    if not isinstance(role, str) or role not in allowed:
        raise MigrationRunnerError("MIGRATION_RUNNER_CONFIGURATION_INVALID")


def _is_connection_error(dbapi: Any, error: BaseException) -> bool:
    operational_error = getattr(dbapi, "OperationalError", ())
    return isinstance(error, operational_error)


def _ledger_record(row: Sequence[Any]) -> MigrationLedgerRecord:
    if len(row) != 5:
        raise MigrationRunnerError("MIGRATION_LEDGER_DRIFT")
    try:
        phase = MigrationPhase(row[2])
    except (TypeError, ValueError):
        raise MigrationRunnerError("MIGRATION_LEDGER_DRIFT") from None
    checksum = bytes(row[4])
    return MigrationLedgerRecord(
        component=row[0],
        version=row[1],
        phase=phase,
        name=row[3],
        checksum_sha256=checksum,
    )
