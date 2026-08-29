"""Fake DB-API REDs for the deployment-only psycopg migration boundary."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import unittest

from desire_platform.identity_access.adapters.postgres.migrations import (
    IAM_MIGRATION_LAYOUT,
    IAM_MIGRATION_LOCK,
    IAM_SCHEMA_HEAD_VERSION,
    IamContractParameters,
    MigrationArtifact,
    MigrationCommitOutcomeUnknown,
    MigrationDescriptor,
    MigrationLedgerRecord,
    MigrationPhase,
    MigrationRunnerError,
    PsycopgMigrationAdapterUnavailable,
    PsycopgMigrationDriver,
    PsycopgMigrationSession,
    PsycopgMigrationSettings,
)


class _FakeOperationalError(Exception):
    pass


@dataclass
class _FakeInfo:
    transaction_status: str = "IDLE"


class _FakeCursor:
    def __init__(self, connection: "_FakeConnection") -> None:
        self.connection = connection
        self.last_sql = ""
        self.rowcount = 1

    def execute(self, sql, params=None):
        sql_text = sql.decode("utf-8") if isinstance(sql, bytes) else str(sql)
        self.last_sql = sql_text
        self.connection.trace.append(
            ("execute", sql_text, params, self.connection.info.transaction_status)
        )
        if sql_text.strip().upper().startswith("BEGIN"):
            self.connection.info.transaction_status = "INTRANS"
        return self

    def fetchone(self):
        if "pg_advisory_unlock" in self.last_sql:
            return (True,)
        if "pg_advisory_lock" in self.last_sql:
            return (None,)
        if "server_version_num" in self.last_sql:
            return (
                self.connection.current_user,
                self.connection.session_user,
                self.connection.server_version_num,
            )
        if self.connection.fetchone_results:
            return self.connection.fetchone_results.pop(0)
        return None

    def fetchall(self):
        if self.connection.fetchall_results:
            return self.connection.fetchall_results.pop(0)
        return []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


class _FakeConnection:
    def __init__(self, *, server_version_num: int = 180001) -> None:
        self.autocommit = False
        self.closed = False
        self.fail_commit = False
        self.trace = []
        self.info = _FakeInfo()
        self.current_user = "schema_owner"
        self.session_user = "iam_migration_runner"
        self.server_version_num = server_version_num
        self.fetchone_results = []
        self.fetchall_results = []

    def cursor(self):
        return _FakeCursor(self)

    def execute(self, sql, params=None):
        return self.cursor().execute(sql, params)

    def commit(self):
        self.trace.append(("commit", self.info.transaction_status))
        if self.fail_commit:
            self.closed = True
            raise _FakeOperationalError("lost after COMMIT send")
        self.info.transaction_status = "IDLE"

    def rollback(self):
        self.trace.append(("rollback", self.info.transaction_status))
        self.info.transaction_status = "IDLE"

    def close(self):
        self.trace.append(("close",))
        self.closed = True


class _FakeDbApi:
    OperationalError = _FakeOperationalError

    def __init__(self, connection: _FakeConnection) -> None:
        self.connection = connection
        self.connect_calls = []

    def connect(self, conninfo: str, **kwargs):
        self.connect_calls.append((conninfo, kwargs))
        self.connection.autocommit = kwargs.get("autocommit", False)
        return self.connection


class PsycopgMigrationAdapterSemanticRedTest(unittest.TestCase):
    def setUp(self) -> None:
        self.settings = PsycopgMigrationSettings(
            conninfo="postgresql://redacted.invalid/iam_ephemeral_test"
        )

    def test_driver_uses_autocommit_session_lock_and_confirmed_unlock(self) -> None:
        connection = _FakeConnection()
        dbapi = _FakeDbApi(connection)
        driver = PsycopgMigrationDriver(settings=self.settings, dbapi=dbapi)

        session = self._require_behavior(
            "driver must open an autocommit deployment session",
            lambda: driver.connect(session_role="iam_migration_runner"),
        )
        self._require_behavior(
            "advisory lock must be session-scoped outside a transaction",
            lambda: session.acquire_advisory_lock(*IAM_MIGRATION_LOCK),
        )
        self._require_behavior(
            "confirmed path must explicitly unlock",
            lambda: session.release_advisory_lock(*IAM_MIGRATION_LOCK),
        )
        self._require_behavior(
            "confirmed path must close without discard",
            lambda: session.close(discard=False),
        )

        self.assertEqual(len(dbapi.connect_calls), 1)
        _conninfo, connect_kwargs = dbapi.connect_calls[0]
        self.assertTrue(connect_kwargs.get("autocommit"))
        self.assertEqual(
            connect_kwargs.get("application_name"),
            "desire-iam-migration-runner",
        )
        self.assertEqual(connect_kwargs.get("connect_timeout"), 5)
        lock_events = [
            event
            for event in connection.trace
            if event[0] == "execute" and "pg_advisory_lock" in event[1]
        ]
        unlock_events = [
            event
            for event in connection.trace
            if event[0] == "execute" and "pg_advisory_unlock" in event[1]
        ]
        self.assertEqual(len(lock_events), 1)
        self.assertEqual(lock_events[0][2], IAM_MIGRATION_LOCK)
        self.assertEqual(lock_events[0][3], "IDLE")
        self.assertEqual(len(unlock_events), 1)
        self.assertEqual(unlock_events[0][2], IAM_MIGRATION_LOCK)
        self.assertTrue(connection.closed)

        invalid_dbapi = _FakeDbApi(_FakeConnection())
        invalid_driver = PsycopgMigrationDriver(
            settings=self.settings,
            dbapi=invalid_dbapi,
        )
        with self.assertRaises(MigrationRunnerError):
            invalid_driver.connect(session_role="iam_migration_runner SET ROLE schema_owner")
        self.assertEqual(invalid_dbapi.connect_calls, [])

    def test_prepare_runner_sets_closed_role_and_enforces_postgres_18(self) -> None:
        session, connection = self._connected_session(server_version_num=180001)
        self._require_behavior(
            "preflight must SET ROLE and verify current/session role plus PG18",
            lambda: session.prepare_runner(schema_role="schema_owner", postgres_major=18),
        )
        statements = [event[1] for event in connection.trace if event[0] == "execute"]
        self.assertIn("SET ROLE schema_owner", statements)
        self.assertTrue(any("server_version_num" in sql for sql in statements))
        self.assertTrue(
            all(
                event[3] == "IDLE"
                for event in connection.trace
                if event[0] == "execute"
            )
        )

        old_session, _connection = self._connected_session(server_version_num=170099)
        with self.assertRaises(MigrationRunnerError) as raised:
            old_session.prepare_runner(schema_role="schema_owner", postgres_major=18)
        self.assertEqual(raised.exception.code, "MIGRATION_POSTGRES_MAJOR_UNSUPPORTED")

        unclosed_session, unclosed_connection = self._connected_session()
        with self.assertRaises(MigrationRunnerError):
            unclosed_session.prepare_runner(
                schema_role="schema_owner; SELECT pg_sleep(1)",
                postgres_major=18,
            )
        self.assertEqual(unclosed_connection.trace, [])

        wrong_current_session, wrong_current_connection = self._connected_session()
        wrong_current_connection.current_user = "iam_migration_runner"
        with self.assertRaises(MigrationRunnerError):
            wrong_current_session.prepare_runner(
                schema_role="schema_owner",
                postgres_major=18,
            )

        wrong_login_session, wrong_login_connection = self._connected_session()
        wrong_login_connection.session_user = "postgres"
        with self.assertRaises(MigrationRunnerError):
            wrong_login_session.prepare_runner(
                schema_role="schema_owner",
                postgres_major=18,
            )

    def test_each_file_is_one_transaction_with_raw_sql_and_bound_metadata(self) -> None:
        session, connection = self._connected_session()
        sql_bytes = b"CREATE VIEW infra.iam_schema_compatibility AS SELECT 7;\n"
        descriptor = MigrationDescriptor(
            component="iam",
            version=7,
            phase=MigrationPhase.CONTRACT,
            name="verify_iam_v1",
            relative_path="0007_contract__verify_iam_v1.sql",
            checksum_sha256=hashlib.sha256(sql_bytes).digest(),
        )
        artifact = MigrationArtifact(descriptor=descriptor, sql_bytes=sql_bytes)
        contract = IamContractParameters(
            component="iam",
            schema_head_version=7,
            min_app_compatible_version=7,
            max_app_compatible_version=7,
            api_contract_sha256=b"a" * 32,
            event_contract_sha256=b"e" * 32,
            migration_manifest_sha256=b"m" * 32,
            combined_contract_sha256=b"c" * 32,
        )
        ledger = MigrationLedgerRecord.from_descriptor(descriptor)
        connection.fetchone_results.append(
            (
                contract.component,
                contract.schema_head_version,
                contract.min_app_compatible_version,
                contract.max_app_compatible_version,
                contract.api_contract_sha256,
                contract.event_contract_sha256,
                contract.migration_manifest_sha256,
                contract.combined_contract_sha256,
            )
        )

        operations = (
            ("BEGIN must be explicit per artifact", lambda: session.begin_migration(descriptor)),
            ("timeouts must use transaction-local bound values", session.set_local_timeouts),
            ("artifact raw SQL must execute without bind values", lambda: session.execute_artifact(artifact)),
            ("artifact catalog assertion must remain in the transaction", lambda: session.assert_artifact(descriptor)),
            ("0007 contract values must be bind parameters", lambda: session.insert_contract_row(contract)),
            (
                "ledger metadata must be bound in the same transaction",
                lambda: session.insert_ledger_row(ledger, runner_version="red-runner/1"),
            ),
            (
                "0007 compatibility view must be read back after ledger insert",
                lambda: self.assertEqual(session.read_contract_parameters(), contract),
            ),
            ("COMMIT must be explicit", session.commit_migration),
        )
        for behavior, operation in operations:
            self._require_behavior(behavior, operation)

        execute_events = [event for event in connection.trace if event[0] == "execute"]
        begin = [event for event in execute_events if event[1].startswith("BEGIN")]
        self.assertEqual(len(begin), 1)
        self.assertIn("READ COMMITTED", begin[0][1])
        artifact_events = [event for event in execute_events if event[1] == sql_bytes.decode()]
        self.assertEqual(len(artifact_events), 1)
        self.assertIsNone(artifact_events[0][2])
        self.assertEqual(artifact_events[0][3], "INTRANS")

        timeout_names = (
            "lock_timeout",
            "statement_timeout",
            "idle_in_transaction_session_timeout",
        )
        timeout_events = [
            event
            for event in execute_events
            if any(name in event[1] for name in timeout_names)
        ]
        self.assertEqual(len(timeout_events), 3)
        self.assertEqual(
            {event[2] for event in timeout_events},
            {("5000ms",), ("30000ms",), ("15000ms",)},
        )
        for event in timeout_events:
            self.assertIn("%s", event[1])
            self.assertIn("set_config", event[1].lower())
            self.assertEqual(event[3], "INTRANS")

        metadata_events = [
            event
            for event in execute_events
            if "iam_schema_contracts" in event[1] or "schema_migrations" in event[1]
        ]
        self.assertGreaterEqual(len(metadata_events), 2)
        for event in metadata_events:
            self.assertIn("%s", event[1])
            self.assertIsNotNone(event[2])
            self.assertNotIn("red-runner/1", event[1])
        contract_writes = [
            event
            for event in execute_events
            if event[1].startswith("INSERT INTO infra.iam_schema_contracts")
        ]
        self.assertEqual(len(contract_writes), 1)
        self.assertIn("ON CONFLICT (component) DO UPDATE", contract_writes[0][1])
        self.assertIn(
            "schema_head_version < EXCLUDED.schema_head_version",
            contract_writes[0][1],
        )
        contract_readbacks = [
            event
            for event in execute_events
            if "JOIN infra.iam_schema_compatibility" in event[1]
        ]
        self.assertEqual(
            len(contract_readbacks),
            1,
            "0007 must be read back through the final compatibility view",
        )
        self.assertEqual(connection.info.transaction_status, "IDLE")

    def test_current_iam_head_has_a_closed_artifact_assertion_mapping(self) -> None:
        session, connection = self._connected_session()
        version, phase, name, relative_path = IAM_MIGRATION_LAYOUT[-1]
        self.assertEqual(version, IAM_SCHEMA_HEAD_VERSION)
        descriptor = MigrationDescriptor(
            component="iam",
            version=version,
            phase=phase,
            name=name,
            relative_path=relative_path,
            checksum_sha256=b"i" * 32,
        )
        session.begin_migration(descriptor)
        execute_count_before_assertion = len(
            [event for event in connection.trace if event[0] == "execute"]
        )

        session.assert_artifact(descriptor)

        execute_count_after_assertion = len(
            [event for event in connection.trace if event[0] == "execute"]
        )
        self.assertEqual(execute_count_after_assertion, execute_count_before_assertion)
        session.rollback_migration()

    def test_lost_commit_connection_is_unknown_and_discard_sends_nothing_else(self) -> None:
        session, connection = self._connected_session()
        descriptor = MigrationDescriptor(
            component="iam",
            version=0,
            phase=MigrationPhase.EXPAND,
            name="schemas_and_ledger",
            relative_path="0000_expand__schemas_and_ledger.sql",
            checksum_sha256=b"s" * 32,
        )
        self._require_behavior(
            "transaction must begin before COMMIT fault injection",
            lambda: session.begin_migration(descriptor),
        )
        connection.fail_commit = True

        with self.assertRaises(MigrationCommitOutcomeUnknown):
            session.commit_migration()
        trace_at_loss = tuple(connection.trace)
        self._require_behavior(
            "unknown-outcome connection must be physically discarded",
            lambda: session.close(discard=True),
        )

        self.assertTrue(connection.closed)
        self.assertTrue(any(event[0] == "commit" for event in trace_at_loss))
        after_commit = connection.trace[
            next(i for i, event in enumerate(connection.trace) if event[0] == "commit") + 1 :
        ]
        self.assertFalse(any(event[0] == "rollback" for event in after_commit))
        self.assertFalse(
            any(
                event[0] == "execute" and "pg_advisory_unlock" in event[1]
                for event in after_commit
            )
        )
        self.assertEqual(after_commit, [("close",)])

    def _connected_session(self, *, server_version_num: int = 180001):
        connection = _FakeConnection(server_version_num=server_version_num)
        connection.autocommit = True
        dbapi = _FakeDbApi(connection)
        session = PsycopgMigrationSession(
            connection=connection,
            dbapi=dbapi,
            settings=self.settings,
            session_role="iam_migration_runner",
        )
        return session, connection

    def _require_behavior(self, behavior: str, operation):
        try:
            return operation()
        except PsycopgMigrationAdapterUnavailable as exc:
            self.fail("semantic RED: %s; scaffold returned %s" % (behavior, exc.code))


if __name__ == "__main__":
    unittest.main()
