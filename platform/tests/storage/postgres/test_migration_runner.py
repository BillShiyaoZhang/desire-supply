"""TEST-DB-MIG-IAM-002 runner transaction and recovery semantic REDs.

These tests use a strict scripted deployment connection.  It models durable
ledger effects, transaction rollback, and a lost COMMIT acknowledgement without
pretending that a mock database proves the PostgreSQL catalog/RLS tests.
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import unittest

from desire_platform.identity_access.adapters.postgres.migrations import (
    IAM_MAX_APP_COMPATIBLE_VERSION,
    IAM_MIGRATION_LOCK,
    IAM_MIGRATION_SCHEMA_ROLE,
    IAM_MIGRATION_SESSION_ROLE,
    IAM_MIN_APP_COMPATIBLE_VERSION,
    IAM_POSTGRES_MAJOR,
    IAM_SCHEMA_HEAD_VERSION,
    IamContractParameters,
    IamContractSources,
    IamMigrationRunner,
    MigrationArtifact,
    MigrationCatalog,
    MigrationCommitOutcomeUnknown,
    MigrationConnectionLost,
    MigrationDatabaseState,
    MigrationDescriptor,
    MigrationLedgerRecord,
    MigrationRunnerError,
)


class _ScriptedSqlFailure(RuntimeError):
    pass


class _ScriptedLedgerInsertFailure(RuntimeError):
    pass


class _ScriptedCleanupFailure(RuntimeError):
    pass


class _ScriptedDatabase:
    def __init__(
        self,
        *,
        ledger_exists: bool,
        has_unledgered_iam_objects: bool = False,
        records=(),
    ) -> None:
        self.ledger_exists = ledger_exists
        self.has_unledgered_iam_objects = has_unledgered_iam_objects
        self.ledger = {record.version: record for record in records}
        self.contract_parameters = None


class _ScriptedDriver:
    def __init__(
        self,
        database: _ScriptedDatabase,
        *,
        sql_failure_versions=(),
        ledger_failure_versions=(),
        unknown_commit_versions=(),
        corrupt_after_unknown=(),
        absent_after_unknown=(),
        unlock_connection_lost_sessions=(),
        read_ledger_connection_lost_once_versions=(),
        corrupt_contract_parameters=False,
        rollback_failure_versions=(),
        unlock_failure_sessions=(),
    ) -> None:
        self.database = database
        self.sql_failure_versions = set(sql_failure_versions)
        self.ledger_failure_versions = set(ledger_failure_versions)
        self.unknown_commit_versions = set(unknown_commit_versions)
        self.corrupt_after_unknown = set(corrupt_after_unknown)
        self.absent_after_unknown = set(absent_after_unknown)
        self.unlock_connection_lost_sessions = set(
            unlock_connection_lost_sessions
        )
        self.read_ledger_connection_lost_once_versions = set(
            read_ledger_connection_lost_once_versions
        )
        self.read_ledger_connection_losses_used = set()
        self.corrupt_contract_parameters = corrupt_contract_parameters
        self.rollback_failure_versions = set(rollback_failure_versions)
        self.unlock_failure_sessions = set(unlock_failure_sessions)
        self.unknown_commits_used = set()
        self.sessions = []
        self.trace = []

    def connect(self, *, session_role: str):
        if session_role != IAM_MIGRATION_SESSION_ROLE:
            raise AssertionError("runner connected with an unexpected deployment role")
        session = _ScriptedSession(self, len(self.sessions) + 1)
        self.sessions.append(session)
        self.trace.append(("connect", session.number, session_role))
        return session


class _ScriptedSession:
    def __init__(self, driver: _ScriptedDriver, number: int) -> None:
        self.driver = driver
        self.number = number
        self.locked = False
        self.prepared = False
        self.active = False
        self.lost = False
        self.closed = False
        self.tainted = False
        self.timeouts_set = False
        self.executed = False
        self.asserted = False
        self.descriptor = None
        self.pending_ledger = None
        self.pending_contract = None
        self.transaction_number = 0

    def acquire_advisory_lock(self, key1: int, key2: int) -> None:
        self._require_open()
        if self.locked or self.active:
            raise AssertionError("advisory lock was acquired in an invalid state")
        self.locked = True
        self.driver.trace.append(("lock", self.number, key1, key2))

    def prepare_runner(self, *, schema_role: str, postgres_major: int) -> None:
        self._require_locked()
        if schema_role != IAM_MIGRATION_SCHEMA_ROLE or postgres_major != IAM_POSTGRES_MAJOR:
            raise AssertionError("runner role or PostgreSQL major was not closed")
        self.prepared = True
        self.driver.trace.append(
            ("prepare", self.number, schema_role, postgres_major)
        )

    def inspect_database(self) -> MigrationDatabaseState:
        self._require_prepared()
        if self.active:
            raise AssertionError("database preflight ran inside a file transaction")
        self.driver.trace.append(("inspect", self.number))
        database = self.driver.database
        return MigrationDatabaseState(
            ledger_exists=database.ledger_exists,
            has_unledgered_iam_objects=database.has_unledgered_iam_objects,
            applied_migrations=tuple(
                database.ledger[version] for version in sorted(database.ledger)
            ),
        )

    def begin_migration(self, descriptor: MigrationDescriptor) -> None:
        self._require_prepared()
        if self.active:
            raise AssertionError("migration transactions cannot nest")
        self.active = True
        self.timeouts_set = False
        self.executed = False
        self.asserted = False
        self.descriptor = descriptor
        self.pending_ledger = None
        self.pending_contract = None
        self.transaction_number += 1
        self.driver.trace.append(
            ("begin", self.number, self.transaction_number, descriptor.version)
        )

    def set_local_timeouts(self) -> None:
        self._require_transaction()
        if self.timeouts_set:
            raise AssertionError("local timeouts were configured more than once")
        self.timeouts_set = True
        self.driver.trace.append(
            ("timeouts", self.number, self.transaction_number, self._version)
        )

    def execute_artifact(self, artifact: MigrationArtifact) -> None:
        self._require_transaction()
        if not self.timeouts_set or artifact.descriptor != self.descriptor:
            raise AssertionError("artifact execution bypassed transaction preparation")
        self.driver.trace.append(
            ("execute", self.number, self.transaction_number, self._version)
        )
        if self._version in self.driver.sql_failure_versions:
            raise _ScriptedSqlFailure("scripted SQL execution fault")
        self.executed = True

    def assert_artifact(self, descriptor: MigrationDescriptor) -> None:
        self._require_transaction()
        if not self.executed or descriptor != self.descriptor:
            raise AssertionError("catalog assertions did not follow exact SQL execution")
        self.asserted = True
        self.driver.trace.append(
            ("assert", self.number, self.transaction_number, self._version)
        )

    def insert_contract_row(self, parameters: IamContractParameters) -> None:
        self._require_transaction()
        if (
            not self.asserted
            or self._version != IAM_SCHEMA_HEAD_VERSION
            or self.pending_contract is not None
        ):
            raise AssertionError("contract parameters escaped the schema-head transaction")
        self.pending_contract = (
            replace(parameters, combined_contract_sha256=b"!" * 32)
            if self.driver.corrupt_contract_parameters
            else parameters
        )
        self.driver.trace.append(
            (
                "contract",
                self.number,
                self.transaction_number,
                self.pending_contract,
            )
        )

    def read_contract_parameters(self):
        self._require_transaction()
        if (
            self._version != IAM_SCHEMA_HEAD_VERSION
            or self.pending_contract is None
            or self.pending_ledger is None
        ):
            raise AssertionError("contract row was read outside the schema-head transaction")
        self.driver.trace.append(
            (
                "read_contract",
                self.number,
                self.transaction_number,
                self.pending_contract,
            )
        )
        return self.pending_contract

    def insert_ledger_row(
        self,
        record: MigrationLedgerRecord,
        *,
        runner_version: str,
    ) -> None:
        self._require_transaction()
        expected = MigrationLedgerRecord.from_descriptor(self.descriptor)
        if not self.asserted or record != expected:
            raise AssertionError("ledger row did not match the executed artifact")
        if (
            self._version == IAM_SCHEMA_HEAD_VERSION
            and self.pending_contract is None
        ):
            raise AssertionError(
                "schema-head ledger was inserted before its contract parameters"
            )
        self.driver.trace.append(
            (
                "ledger",
                self.number,
                self.transaction_number,
                self._version,
                runner_version,
            )
        )
        if self._version in self.driver.ledger_failure_versions:
            raise _ScriptedLedgerInsertFailure("scripted ledger insert fault")
        self.pending_ledger = record

    def commit_migration(self) -> None:
        self._require_transaction()
        if self.pending_ledger is None:
            raise AssertionError("transaction committed without its ledger row")
        version = self._version
        transaction_number = self.transaction_number
        record = self.pending_ledger
        contract = self.pending_contract
        self._publish_pending()
        if (
            version in self.driver.unknown_commit_versions
            and version not in self.driver.unknown_commits_used
        ):
            self.driver.unknown_commits_used.add(version)
            if version in self.driver.corrupt_after_unknown:
                self.driver.database.ledger[version] = replace(
                    record,
                    checksum_sha256=b"!" * 32,
                )
            if version in self.driver.absent_after_unknown:
                self.driver.database.ledger.pop(version, None)
                if version == IAM_SCHEMA_HEAD_VERSION:
                    self.driver.database.contract_parameters = None
            self.lost = True
            self.locked = False
            self.driver.trace.append(
                ("commit_outcome_unknown", self.number, transaction_number, version)
            )
            raise MigrationCommitOutcomeUnknown()
        self.driver.trace.append(
            ("commit", self.number, transaction_number, version)
        )
        if version == IAM_SCHEMA_HEAD_VERSION and contract is None:
            raise AssertionError("schema-head contract did not commit with its ledger row")

    def rollback_migration(self) -> None:
        self._require_transaction()
        version = self._version
        transaction_number = self.transaction_number
        if version in self.driver.rollback_failure_versions:
            self.tainted = True
            self.driver.trace.append(
                ("rollback_failure", self.number, transaction_number, version)
            )
            raise _ScriptedCleanupFailure("scripted rollback cleanup fault")
        self._clear_transaction()
        self.driver.trace.append(
            ("rollback", self.number, transaction_number, version)
        )

    def read_ledger_record(self, *, component: str, version: int):
        self._require_prepared()
        if self.active:
            raise AssertionError("post-commit ledger read ran inside a transaction")
        if component != "iam":
            raise AssertionError("runner read an unknown migration component")
        if (
            version in self.driver.read_ledger_connection_lost_once_versions
            and version not in self.driver.read_ledger_connection_losses_used
        ):
            self.driver.read_ledger_connection_losses_used.add(version)
            self.locked = False
            self.lost = True
            self.driver.trace.append(
                ("read_ledger_connection_lost", self.number, version)
            )
            raise MigrationConnectionLost()
        self.driver.trace.append(("read_ledger", self.number, version))
        return self.driver.database.ledger.get(version)

    def release_advisory_lock(self, key1: int, key2: int) -> None:
        self._require_locked()
        if self.active or (key1, key2) != IAM_MIGRATION_LOCK:
            raise AssertionError("runner released the wrong lock or unlocked in transaction")
        if self.number in self.driver.unlock_connection_lost_sessions:
            self.locked = False
            self.lost = True
            self.driver.trace.append(
                ("unlock_connection_lost", self.number, key1, key2)
            )
            raise MigrationConnectionLost()
        if self.number in self.driver.unlock_failure_sessions:
            self.tainted = True
            self.driver.trace.append(
                ("unlock_failure", self.number, key1, key2)
            )
            raise _ScriptedCleanupFailure("scripted unlock cleanup fault")
        self.locked = False
        self.driver.trace.append(("unlock", self.number, key1, key2))

    def close(self, *, discard: bool) -> None:
        if self.closed:
            raise AssertionError("migration connection was closed twice")
        if (
            (self.active and not discard)
            or (self.locked and not discard)
            or ((self.lost or self.tainted) and not discard)
            or (not self.lost and not self.tainted and discard)
        ):
            raise AssertionError("migration connection had the wrong close disposition")
        self.closed = True
        self.driver.trace.append(("close", self.number, discard))

    @property
    def _version(self) -> int:
        if self.descriptor is None:
            raise AssertionError("no current migration descriptor")
        return self.descriptor.version

    def _publish_pending(self) -> None:
        database = self.driver.database
        database.ledger_exists = True
        database.ledger[self.pending_ledger.version] = self.pending_ledger
        if self.pending_contract is not None:
            database.contract_parameters = self.pending_contract
        self._clear_transaction()

    def _clear_transaction(self) -> None:
        self.active = False
        self.timeouts_set = False
        self.executed = False
        self.asserted = False
        self.descriptor = None
        self.pending_ledger = None
        self.pending_contract = None

    def _require_open(self) -> None:
        if self.closed or self.lost:
            raise AssertionError("lost or closed migration connection was reused")

    def _require_locked(self) -> None:
        self._require_open()
        if not self.locked:
            raise AssertionError("operation ran without the session advisory lock")

    def _require_prepared(self) -> None:
        self._require_locked()
        if not self.prepared:
            raise AssertionError("operation ran before role/server preparation")

    def _require_transaction(self) -> None:
        self._require_prepared()
        if not self.active:
            raise AssertionError("operation ran outside a migration transaction")


class IamMigrationRunnerSemanticRedTest(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.catalog = self._catalog()
        self.contract_sources = IamContractSources(
            api_contract_bytes=b"openapi: 3.1.0\ninfo:\n  title: IAM v1\n",
            event_contract_bytes=b'{"$id":"urn:iam-v1"}\n',
        )

    def test_closed_protocol_constants_are_not_runtime_configuration(self) -> None:
        self.assertEqual(IAM_MIGRATION_LOCK, (1229016369, 1))
        self.assertEqual(IAM_MIGRATION_SESSION_ROLE, "iam_migration_runner")
        self.assertEqual(IAM_MIGRATION_SCHEMA_ROLE, "schema_owner")
        self.assertEqual(IAM_POSTGRES_MAJOR, 18)
        self.assertEqual(
            (
                IAM_SCHEMA_HEAD_VERSION,
                IAM_MIN_APP_COMPATIBLE_VERSION,
                IAM_MAX_APP_COMPATIBLE_VERSION,
            ),
            (self.catalog.artifacts[-1].descriptor.version,) * 3,
        )

    def test_exact_ledger_is_skipped_under_one_fixed_session_lock(self) -> None:
        database = self._database_with_exact_versions(range(len(self.catalog.artifacts)))
        driver = _ScriptedDriver(database)

        report = self._run(driver)

        self.assertEqual(report.applied_versions, ())
        self.assertEqual(report.recovered_versions, ())
        self.assertEqual(
            report.skipped_versions,
            tuple(range(len(self.catalog.artifacts))),
        )
        self.assertEqual(self._events(driver, "lock"), [("lock", 1, *IAM_MIGRATION_LOCK)])
        self.assertEqual(
            self._events(driver, "unlock"), [("unlock", 1, *IAM_MIGRATION_LOCK)]
        )
        self.assertEqual(self._events(driver, "begin"), [])
        self.assertEqual(self._events(driver, "execute"), [])
        self.assertEqual(self._events(driver, "ledger"), [])
        self.assertEqual(self._events(driver, "close"), [("close", 1, False)])

    def test_unknown_applied_version_fails_before_any_database_write(self) -> None:
        unknown = MigrationLedgerRecord(
            component="iam",
            version=len(self.catalog.artifacts),
            phase=self.catalog.artifacts[-1].descriptor.phase,
            name="unreviewed_future_version",
            checksum_sha256=b"u" * 32,
        )
        database = self._database_with_exact_versions((0, 1))
        database.ledger[unknown.version] = unknown
        driver = _ScriptedDriver(database)

        self._assert_runner_error(driver, "MIGRATION_LEDGER_UNKNOWN_VERSION")

        self._assert_no_write(driver)
        self.assertEqual(self._events(driver, "unlock"), [("unlock", 1, *IAM_MIGRATION_LOCK)])

    def test_applied_field_or_checksum_drift_fails_before_any_database_write(self) -> None:
        database = self._database_with_exact_versions((0, 1, 2))
        database.ledger[1] = replace(
            database.ledger[1],
            checksum_sha256=b"d" * 32,
        )
        driver = _ScriptedDriver(database)

        self._assert_runner_error(driver, "MIGRATION_LEDGER_DRIFT")

        self._assert_no_write(driver)
        self.assertEqual(self._events(driver, "unlock"), [("unlock", 1, *IAM_MIGRATION_LOCK)])

    def test_iam_objects_without_a_ledger_require_manual_inspection(self) -> None:
        database = _ScriptedDatabase(
            ledger_exists=False,
            has_unledgered_iam_objects=True,
        )
        driver = _ScriptedDriver(database)

        self._assert_runner_error(driver, "MIGRATION_UNLEDGERED_DATABASE")

        self._assert_no_write(driver)
        self.assertEqual(self._events(driver, "unlock"), [("unlock", 1, *IAM_MIGRATION_LOCK)])

    def test_each_unapplied_file_has_its_own_verified_transaction(self) -> None:
        database = _ScriptedDatabase(ledger_exists=False)
        driver = _ScriptedDriver(database)

        report = self._run(driver)

        self.assertEqual(
            report.applied_versions,
            tuple(range(len(self.catalog.artifacts))),
        )
        self.assertEqual(report.recovered_versions, ())
        self.assertEqual(report.skipped_versions, ())
        for event_name in ("begin", "timeouts", "execute", "assert", "ledger", "commit"):
            self.assertEqual(
                [event[3] for event in self._events(driver, event_name)],
                list(range(len(self.catalog.artifacts))),
            )
        transaction_ids = [event[2] for event in self._events(driver, "begin")]
        self.assertEqual(
            transaction_ids,
            list(range(1, len(self.catalog.artifacts) + 1)),
        )
        self.assertEqual(
            [event[2] for event in self._events(driver, "read_ledger")],
            list(range(len(self.catalog.artifacts))),
        )
        self.assertEqual(
            [event[4] for event in self._events(driver, "ledger")],
            ["test-runner/1"] * len(self.catalog.artifacts),
        )
        self.assertEqual(
            sorted(database.ledger),
            list(range(len(self.catalog.artifacts))),
        )

    def test_sql_fault_rolls_back_only_the_current_file_and_finally_unlocks(self) -> None:
        database = self._database_with_exact_versions((0, 1))
        before = dict(database.ledger)
        driver = _ScriptedDriver(database, sql_failure_versions=(2,))

        with self.assertRaises(_ScriptedSqlFailure):
            self._run(driver)

        self.assertEqual(database.ledger, before)
        self.assertEqual(
            self._events(driver, "begin"), [("begin", 1, 1, 2)]
        )
        self.assertEqual(
            self._events(driver, "rollback"), [("rollback", 1, 1, 2)]
        )
        self.assertEqual(self._events(driver, "ledger"), [])
        self.assertEqual(self._events(driver, "unlock"), [("unlock", 1, *IAM_MIGRATION_LOCK)])
        self.assertEqual(self._events(driver, "close"), [("close", 1, False)])

    def test_schema_head_hash_parameters_and_ledger_are_atomic(self) -> None:
        database = self._database_with_exact_versions(range(IAM_SCHEMA_HEAD_VERSION))
        driver = _ScriptedDriver(database)

        self._run(driver)

        expected = self._expected_contract_parameters()
        self.assertEqual(database.contract_parameters, expected)
        contract_event = self._events(driver, "contract")
        ledger_event = self._events(driver, "ledger")
        read_contract_event = self._events(driver, "read_contract")
        commit_event = self._events(driver, "commit")
        self.assertEqual(len(contract_event), 1)
        self.assertEqual(contract_event[0][3], expected)
        self.assertEqual(contract_event[0][1:3], ledger_event[0][1:3])
        self.assertEqual(contract_event[0][1:3], commit_event[0][1:3])
        self.assertLess(driver.trace.index(contract_event[0]), driver.trace.index(ledger_event[0]))
        self.assertLess(
            driver.trace.index(ledger_event[0]),
            driver.trace.index(read_contract_event[0]),
        )
        self.assertLess(
            driver.trace.index(read_contract_event[0]),
            driver.trace.index(commit_event[0]),
        )
        self.assertLess(driver.trace.index(ledger_event[0]), driver.trace.index(commit_event[0]))

        rollback_database = self._database_with_exact_versions(
            range(IAM_SCHEMA_HEAD_VERSION)
        )
        rollback_driver = _ScriptedDriver(
            rollback_database,
            ledger_failure_versions=(IAM_SCHEMA_HEAD_VERSION,),
        )
        with self.assertRaises(_ScriptedLedgerInsertFailure):
            self._run(rollback_driver)
        self.assertIsNone(rollback_database.contract_parameters)
        self.assertNotIn(IAM_SCHEMA_HEAD_VERSION, rollback_database.ledger)
        self.assertEqual(
            self._events(rollback_driver, "rollback"),
            [("rollback", 1, 1, IAM_SCHEMA_HEAD_VERSION)],
        )

    def test_unknown_commit_reconnects_and_recovers_only_from_exact_ledger(self) -> None:
        database = self._database_with_exact_versions((0, 1, 2))
        driver = _ScriptedDriver(database, unknown_commit_versions=(3,))

        report = self._run(driver)

        self.assertEqual(report.skipped_versions, (0, 1, 2))
        self.assertEqual(report.recovered_versions, (3,))
        self.assertEqual(
            report.applied_versions,
            tuple(range(4, len(self.catalog.artifacts))),
        )
        self.assertEqual(len(driver.sessions), 2)
        self.assertEqual(
            [event[3] for event in self._events(driver, "execute")].count(3),
            1,
        )
        self.assertEqual(
            self._events(driver, "close")[0],
            ("close", 1, True),
        )
        self.assertEqual(
            [event[1] for event in self._events(driver, "unlock")],
            [2],
        )
        self.assertEqual(
            [event[1] for event in self._events(driver, "lock")],
            [1, 2],
        )
        self.assertEqual(
            sorted(database.ledger),
            list(range(len(self.catalog.artifacts))),
        )

    def test_unknown_commit_recovery_rejects_drift_without_reexecution(self) -> None:
        database = self._database_with_exact_versions((0, 1, 2))
        driver = _ScriptedDriver(
            database,
            unknown_commit_versions=(3,),
            corrupt_after_unknown=(3,),
        )

        self._assert_runner_error(driver, "MIGRATION_LEDGER_DRIFT")

        self.assertEqual(len(driver.sessions), 2)
        self.assertEqual(
            [event[3] for event in self._events(driver, "execute")].count(3),
            1,
        )
        self.assertNotIn(4, database.ledger)
        self.assertEqual(self._events(driver, "close")[0], ("close", 1, True))
        self.assertEqual(
            [event[1] for event in self._events(driver, "unlock")],
            [2],
        )

    def test_unknown_commit_without_ledger_reexecutes_under_the_new_lock(self) -> None:
        """An atomically rolled-back unknown outcome is safe to apply again."""

        database = self._database_with_exact_versions((0, 1, 2))
        driver = _ScriptedDriver(
            database,
            unknown_commit_versions=(3,),
            absent_after_unknown=(3,),
        )

        report = self._run(driver)

        self.assertEqual(report.skipped_versions, (0, 1, 2))
        self.assertEqual(report.recovered_versions, ())
        self.assertEqual(
            report.applied_versions,
            tuple(range(3, len(self.catalog.artifacts))),
        )
        self.assertEqual(len(driver.sessions), 2)
        self.assertEqual(
            [event[3] for event in self._events(driver, "execute")].count(3),
            2,
        )
        self.assertEqual(
            sorted(database.ledger),
            list(range(len(self.catalog.artifacts))),
        )
        self.assertEqual(self._events(driver, "close")[0], ("close", 1, True))
        self.assertEqual(
            [event[1] for event in self._events(driver, "unlock")],
            [2],
        )

    def test_connection_lost_while_unlocking_still_discards_the_session(self) -> None:
        """Cleanup cannot leak a tainted physical connection or session lock."""

        database = self._database_with_exact_versions(range(len(self.catalog.artifacts)))
        driver = _ScriptedDriver(
            database,
            unlock_connection_lost_sessions=(1,),
        )

        with self.assertRaises(MigrationConnectionLost):
            self._run(driver)

        self.assertEqual(
            self._events(driver, "unlock_connection_lost"),
            [("unlock_connection_lost", 1, *IAM_MIGRATION_LOCK)],
        )
        self.assertEqual(self._events(driver, "close"), [("close", 1, True)])

    def test_post_commit_ledger_read_disconnect_rejoins_without_reexecution(self) -> None:
        """A committed file is recovered only from the exact row on reconnect."""

        database = self._database_with_exact_versions((0,))
        driver = _ScriptedDriver(
            database,
            read_ledger_connection_lost_once_versions=(1,),
        )

        report = self._run(driver)

        self.assertEqual(report.skipped_versions, (0,))
        self.assertEqual(report.recovered_versions, (1,))
        self.assertEqual(
            report.applied_versions,
            tuple(range(2, len(self.catalog.artifacts))),
        )
        self.assertEqual(len(driver.sessions), 2)
        self.assertEqual(
            [event[3] for event in self._events(driver, "execute")].count(1),
            1,
        )
        self.assertEqual(self._events(driver, "close")[0], ("close", 1, True))
        self.assertEqual(
            self._events(driver, "read_ledger_connection_lost"),
            [("read_ledger_connection_lost", 1, 1)],
        )

    def test_schema_head_final_compatibility_readback_must_match(self) -> None:
        """A driver cannot acknowledge altered contract hashes under the port."""

        database = self._database_with_exact_versions(range(IAM_SCHEMA_HEAD_VERSION))
        driver = _ScriptedDriver(
            database,
            corrupt_contract_parameters=True,
        )

        self._assert_runner_error(driver, "MIGRATION_CONTRACT_DRIFT")

        self.assertNotIn(IAM_SCHEMA_HEAD_VERSION, database.ledger)
        self.assertIsNone(database.contract_parameters)
        self.assertEqual(
            [event[3] for event in self._events(driver, "ledger")],
            [IAM_SCHEMA_HEAD_VERSION],
        )
        self.assertEqual(
            self._events(driver, "rollback"),
            [("rollback", 1, 1, IAM_SCHEMA_HEAD_VERSION)],
        )

    def test_runner_rejects_canonical_but_unreviewed_catalog_before_connect(self) -> None:
        """A self-consistent replacement manifest cannot bypass the review pin."""

        artifacts = list(self.catalog.artifacts)
        bad_sql = b"SELECT 0;\n"
        bad_descriptor = replace(
            artifacts[0].descriptor,
            checksum_sha256=hashlib.sha256(bad_sql).digest(),
        )
        artifacts[0] = MigrationArtifact(
            descriptor=bad_descriptor,
            sql_bytes=bad_sql,
        )
        entries = [
            {
                "component": artifact.descriptor.component,
                "version": artifact.descriptor.version,
                "phase": artifact.descriptor.phase.value,
                "name": artifact.descriptor.name,
                "path": artifact.descriptor.relative_path,
                "sha256": artifact.descriptor.checksum_sha256.hex(),
            }
            for artifact in artifacts
        ]
        manifest_bytes = json.dumps(
            entries,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("ascii") + b"\n"
        unvalidated = MigrationCatalog(
            artifacts=tuple(artifacts),
            manifest_bytes=manifest_bytes,
            manifest_sha256=hashlib.sha256(manifest_bytes).digest(),
        )
        driver = _ScriptedDriver(_ScriptedDatabase(ledger_exists=False))
        runner = IamMigrationRunner(driver=driver, runner_version="test-runner/1")

        with self.assertRaises(MigrationRunnerError) as raised:
            runner.run(
                catalog=unvalidated,
                contract_sources=self.contract_sources,
            )

        self.assertEqual(raised.exception.code, "MIGRATION_CATALOG_INVALID")
        self.assertEqual(driver.sessions, [])

    def test_unlock_cleanup_failure_is_stable_and_discards_the_session(self) -> None:
        """A still-locked connection is never returned to the deployment pool."""

        database = self._database_with_exact_versions(range(len(self.catalog.artifacts)))
        driver = _ScriptedDriver(database, unlock_failure_sessions=(1,))

        with self.assertRaises(MigrationRunnerError) as raised:
            self._run(driver)

        self.assertEqual(
            raised.exception.code,
            "MIGRATION_SESSION_CLEANUP_FAILED",
        )
        self.assertEqual(
            self._events(driver, "unlock_failure"),
            [("unlock_failure", 1, *IAM_MIGRATION_LOCK)],
        )
        self.assertEqual(self._events(driver, "close"), [("close", 1, True)])

    def test_rollback_cleanup_failure_preserves_primary_and_discards(self) -> None:
        """Rollback trouble taints the connection without hiding the SQL fault."""

        database = self._database_with_exact_versions((0, 1))
        driver = _ScriptedDriver(
            database,
            sql_failure_versions=(2,),
            rollback_failure_versions=(2,),
        )

        with self.assertRaises(_ScriptedSqlFailure):
            self._run(driver)

        self.assertEqual(
            self._events(driver, "rollback_failure"),
            [("rollback_failure", 1, 1, 2)],
        )
        self.assertEqual(self._events(driver, "close"), [("close", 1, True)])

    def _run(self, driver: _ScriptedDriver):
        runner = IamMigrationRunner(driver=driver, runner_version="test-runner/1")
        try:
            return runner.run(
                catalog=self.catalog,
                contract_sources=self.contract_sources,
            )
        except MigrationRunnerError as exc:
            if exc.code == "IAM_MIGRATION_RUNNER_NOT_AVAILABLE":
                self.fail(
                    "semantic RED: the fail-closed IAM migration runner scaffold "
                    "has not implemented this behavior"
                )
            raise

    def _assert_runner_error(self, driver: _ScriptedDriver, expected_code: str) -> None:
        with self.assertRaises(MigrationRunnerError) as raised:
            self._run(driver)
        self.assertEqual(raised.exception.code, expected_code)

    @staticmethod
    def _events(driver: _ScriptedDriver, event_name: str):
        return [event for event in driver.trace if event[0] == event_name]

    def _assert_no_write(self, driver: _ScriptedDriver) -> None:
        for event_name in ("begin", "execute", "contract", "ledger", "commit"):
            self.assertEqual(self._events(driver, event_name), [])

    def _database_with_exact_versions(self, versions) -> _ScriptedDatabase:
        records = tuple(
            MigrationLedgerRecord.from_descriptor(
                self.catalog.artifacts[version].descriptor
            )
            for version in versions
        )
        return _ScriptedDatabase(ledger_exists=True, records=records)

    def _expected_contract_parameters(self) -> IamContractParameters:
        api_hash = hashlib.sha256(
            self.contract_sources.api_contract_bytes
        ).digest()
        event_hash = hashlib.sha256(
            self.contract_sources.event_contract_bytes
        ).digest()
        combined_hash = hashlib.sha256(
            b"iam-v1-contract"
            + b"\x00"
            + api_hash
            + event_hash
            + self.catalog.manifest_sha256
        ).digest()
        return IamContractParameters(
            component="iam",
            schema_head_version=IAM_SCHEMA_HEAD_VERSION,
            min_app_compatible_version=IAM_SCHEMA_HEAD_VERSION,
            max_app_compatible_version=IAM_SCHEMA_HEAD_VERSION,
            api_contract_sha256=api_hash,
            event_contract_sha256=event_hash,
            migration_manifest_sha256=self.catalog.manifest_sha256,
            combined_contract_sha256=combined_hash,
        )

    @staticmethod
    def _catalog() -> MigrationCatalog:
        migration_root = (
            Path(__file__).resolve().parents[3]
            / "src/desire_platform/identity_access/adapters/postgres/migrations"
        )
        return MigrationCatalog.load(migration_root)


if __name__ == "__main__":
    unittest.main()
