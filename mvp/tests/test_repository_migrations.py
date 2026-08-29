"""Database migration contract tests for REQ-MIG-003/004/006/008.

Expected production API (intentionally absent when these red tests land):

* ``MigrationRunner(repository, lock_timeout_seconds=...)``
* ``runner.status()`` -> object with ``state`` and ``database_version``
* ``runner.plan(target_version=1, resolutions=None)`` -> immutable plan with
  ``plan_id``, ``source_database_version``, ``target_database_version`` and
  ``blockers`` (each blocker exposes a stable ``code``)
* ``runner.apply(plan, backup_dir, fault_injector=None)`` -> result with
  ``status``, ``plan_id`` and ``backup_path``
* all expected migration failures raise ``MigrationError`` with stable ``code``

The fault callback receives the public stage names documented in
``PRECOMMIT_FAULT_STAGES`` below.  This keeps fault injection out of SQL text and
makes every transaction boundary independently testable.
"""

import copy
import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from desire_mvp.migrations import MigrationError, MigrationPlan, MigrationRunner
from desire_mvp.migration_support import MIGRATION_HISTORY_TRIGGER_DEFINITIONS
from desire_mvp.repository import Repository

from helpers import load_sample
from migration_fixtures import (
    create_legacy_database,
    json_text,
    legacy_records,
    logical_database_snapshot,
    recommendation_blob_rows,
    sha256_text,
    table_exists,
)


PRECOMMIT_FAULT_STAGES = (
    "after_backup",
    "after_0001_bootstrap_and_expand",
    "after_0002_backfill_payload_v1",
    "after_0003_contract_v1_and_history",
    "before_commit",
)


def error_code(context_manager: unittest.case._AssertRaisesContext) -> str:
    return context_manager.exception.code


def blocker_codes(plan) -> set:
    return {blocker.code for blocker in plan.blockers}


class RepositoryMigrationTests(unittest.TestCase):
    def test_supported_baselines_and_initialize(self):
        """REQ-MIG-003: empty becomes current; legacy initialize is zero-write."""

        with tempfile.TemporaryDirectory() as directory:
            empty_dir = Path(directory) / "empty"
            repository = Repository(empty_dir)
            repository.initialize()
            database_path = repository.path

            with sqlite3.connect(str(database_path)) as connection:
                registry = connection.execute(
                    """
                    SELECT version, name, checksum_sha256
                    FROM schema_migrations ORDER BY version
                    """
                ).fetchall()
                entity_columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(entities)").fetchall()
                }
                outcome_columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(outcomes)").fetchall()
                }

            self.assertEqual([row[0] for row in registry], [1, 2, 3])
            self.assertEqual(
                [row[1] for row in registry],
                [
                    "0001_bootstrap_and_expand",
                    "0002_backfill_payload_v1",
                    "0003_contract_v1_and_history",
                ],
            )
            self.assertTrue(all(len(row[2]) == 64 for row in registry))
            self.assertIn("payload_schema_version", entity_columns)
            self.assertIn("payload_schema_version", outcome_columns)

            first_registry = registry
            repository.initialize()
            with sqlite3.connect(str(database_path)) as connection:
                second_registry = connection.execute(
                    """
                    SELECT version, name, checksum_sha256
                    FROM schema_migrations ORDER BY version
                    """
                ).fetchall()
            self.assertEqual(second_registry, first_registry)
            status = MigrationRunner(repository).status()
            self.assertEqual(status.state, "current")
            self.assertEqual(status.database_version, 3)

        for variant in ("v0a", "v0b"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                data_dir = Path(directory) / variant
                database_path = create_legacy_database(data_dir, variant=variant)
                before = logical_database_snapshot(database_path)

                with self.assertRaises(MigrationError) as raised:
                    Repository(data_dir).initialize()

                self.assertEqual(error_code(raised), "MIGRATION_REQUIRED")
                self.assertEqual(logical_database_snapshot(database_path), before)
                self.assertFalse(table_exists(database_path, "schema_migrations"))
                plan = MigrationRunner(Repository(data_dir)).plan(target_version=1)
                self.assertFalse(plan.blockers)
                self.assertEqual(plan.source_database_version, 0)
                self.assertEqual(plan.target_database_version, 3)

    def test_recommendation_history_is_byte_immutable(self):
        """REQ-MIG-004: all three historical blobs and their digests are frozen."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "live"
            backup_dir = root / "backups"
            backup_dir.mkdir()
            database_path = create_legacy_database(data_dir)
            before = list(recommendation_blob_rows(database_path))
            before_digests = [
                tuple(sha256_text(value) for value in row[1:]) for row in before
            ]

            runner = MigrationRunner(Repository(data_dir))
            plan = runner.plan(target_version=1)
            result = runner.apply(plan, backup_dir=backup_dir)
            self.assertEqual(result.status, "applied")

            after = list(recommendation_blob_rows(database_path))
            self.assertEqual(after, before)
            self.assertEqual(
                [tuple(sha256_text(value) for value in row[1:]) for row in after],
                before_digests,
            )

            with sqlite3.connect(str(database_path)) as connection:
                manifest_rows = connection.execute(
                    """
                    SELECT recommendation_id, snapshot_schema_version,
                           input_sha256, result_sha256, budget_sha256
                    FROM recommendation_snapshot_manifests
                    ORDER BY recommendation_id
                    """
                ).fetchall()
                self.assertEqual(
                    manifest_rows,
                    [
                        (
                            before[0][0],
                            0,
                            before_digests[0][0],
                            before_digests[0][1],
                            before_digests[0][2],
                        )
                    ],
                )

                mutation_statements = (
                    "UPDATE recommendations SET result_json='{}' WHERE id=1",
                    "DELETE FROM recommendations WHERE id=1",
                    "UPDATE recommendation_snapshot_manifests SET input_sha256=lower(hex(randomblob(32))) WHERE recommendation_id=1",
                    "DELETE FROM recommendation_snapshot_manifests WHERE recommendation_id=1",
                )
                for statement in mutation_statements:
                    with self.subTest(statement=statement), self.assertRaises(sqlite3.IntegrityError):
                        connection.execute(statement)

            self.assertEqual(list(recommendation_blob_rows(database_path)), before)

    def test_atomic_idempotent_apply(self):
        """REQ-MIG-006: every pre-commit failure rolls back all three steps."""

        for stage in PRECOMMIT_FAULT_STAGES:
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                data_dir = root / "live"
                backup_dir = root / "backups"
                backup_dir.mkdir()
                database_path = create_legacy_database(data_dir)
                before = logical_database_snapshot(database_path)
                runner = MigrationRunner(Repository(data_dir))
                plan = runner.plan(target_version=1)

                def fail_at(current_stage, expected_stage=stage):
                    if current_stage == expected_stage:
                        raise RuntimeError("injected migration fault")

                with self.assertRaises(MigrationError) as raised:
                    runner.apply(plan, backup_dir=backup_dir, fault_injector=fail_at)

                self.assertEqual(error_code(raised), "MIGRATION_ROLLED_BACK")
                self.assertEqual(logical_database_snapshot(database_path), before)
                self.assertFalse(table_exists(database_path, "schema_migrations"))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "live"
            backup_dir = root / "backups"
            backup_dir.mkdir()
            database_path = create_legacy_database(data_dir)
            records = legacy_records()
            with sqlite3.connect(str(database_path)) as connection:
                v1_creator_before = connection.execute(
                    "SELECT payload_json FROM entities WHERE kind='creator' AND entity_id=?",
                    (records["current_creator"]["id"],),
                ).fetchone()[0]

            runner = MigrationRunner(Repository(data_dir))
            plan = runner.plan(target_version=1)
            first = runner.apply(plan, backup_dir=backup_dir)
            self.assertEqual(first.status, "applied")
            backup_files_after_first = sorted(path.name for path in backup_dir.iterdir())

            with sqlite3.connect(str(database_path)) as connection:
                entity_rows = connection.execute(
                    """
                    SELECT kind, entity_id, payload_schema_version, payload_json
                    FROM entities ORDER BY kind, entity_id
                    """
                ).fetchall()
                outcome_rows = connection.execute(
                    "SELECT payload_schema_version, payload_json FROM outcomes ORDER BY project_id"
                ).fetchall()
                run_rows_before_retry = connection.execute(
                    "SELECT plan_id, applied_at FROM migration_runs"
                ).fetchall()

            self.assertTrue(entity_rows)
            for _, _, payload_version, payload_json in entity_rows:
                self.assertEqual(payload_version, 1)
                self.assertEqual(json.loads(payload_json)["schema_version"], 1)
            for payload_version, payload_json in outcome_rows:
                self.assertEqual(payload_version, 1)
                self.assertEqual(json.loads(payload_json)["schema_version"], 1)

            migrated_creator = next(
                json.loads(row[3])
                for row in entity_rows
                if row[1] == records["withdrawn_creator"]["id"]
            )
            self.assertEqual(migrated_creator["status"], "inactive")
            current_creator_text = next(
                row[3]
                for row in entity_rows
                if row[1] == records["current_creator"]["id"]
            )
            self.assertEqual(current_creator_text, v1_creator_before)

            second = runner.apply(plan, backup_dir=backup_dir)
            self.assertEqual(second.status, "already_applied")
            self.assertEqual(second.plan_id, first.plan_id)
            self.assertEqual(sorted(path.name for path in backup_dir.iterdir()), backup_files_after_first)
            with sqlite3.connect(str(database_path)) as connection:
                self.assertEqual(
                    connection.execute("SELECT plan_id, applied_at FROM migration_runs").fetchall(),
                    run_rows_before_retry,
                )

    def test_stale_plan_does_not_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "live"
            backup_dir = root / "backups"
            backup_dir.mkdir()
            database_path = create_legacy_database(data_dir)
            runner = MigrationRunner(Repository(data_dir))
            plan = runner.plan(target_version=1)

            with sqlite3.connect(str(database_path)) as connection:
                connection.execute(
                    "UPDATE decisions SET reason_note=? WHERE id=1",
                    ("operator changed the source after planning",),
                )
                connection.commit()
            changed_source = logical_database_snapshot(database_path)

            with self.assertRaises(MigrationError) as raised:
                runner.apply(plan, backup_dir=backup_dir)

            self.assertEqual(error_code(raised), "STALE_MIGRATION_PLAN")
            self.assertEqual(logical_database_snapshot(database_path), changed_source)
            self.assertEqual(list(backup_dir.iterdir()), [])
            self.assertFalse(table_exists(database_path, "schema_migrations"))

    def test_unknown_schema_and_bad_payload_are_blocked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "unknown-schema"
            backup_dir = root / "backups"
            backup_dir.mkdir()
            database_path = create_legacy_database(data_dir)
            with sqlite3.connect(str(database_path)) as connection:
                connection.execute("CREATE TABLE unexpected_contract_table(id INTEGER PRIMARY KEY)")
                connection.commit()
            before = logical_database_snapshot(database_path)

            with self.assertRaises(MigrationError) as raised:
                MigrationRunner(Repository(data_dir)).plan(target_version=1)

            self.assertEqual(error_code(raised), "UNRECOGNIZED_LEGACY_SCHEMA")
            self.assertEqual(logical_database_snapshot(database_path), before)

        bad_payloads = (
            ("{not-json", "INVALID_LEGACY_PAYLOAD"),
            (json_text({"schema_version": 99, "id": "demand-demo-001"}), "UNSUPPORTED_SCHEMA_VERSION"),
        )
        for payload, expected_code in bad_payloads:
            with self.subTest(code=expected_code), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                data_dir = root / "bad-payload"
                backup_dir = root / "backups"
                backup_dir.mkdir()
                database_path = create_legacy_database(
                    data_dir,
                    entity_payload_overrides={"demand-demo-001": payload},
                )
                before = logical_database_snapshot(database_path)
                runner = MigrationRunner(Repository(data_dir))
                plan = runner.plan(target_version=1)

                self.assertIn(expected_code, blocker_codes(plan))
                with self.assertRaises(MigrationError) as raised:
                    runner.apply(plan, backup_dir=backup_dir)
                self.assertEqual(error_code(raised), "MIGRATION_BLOCKED")
                self.assertEqual(logical_database_snapshot(database_path), before)
                self.assertEqual(list(backup_dir.iterdir()), [])

    def test_invalid_migration_history_blocks_initialize_without_repair(self):
        for corruption in ("checksum", "future-version", "drop-managed-trigger"):
            with self.subTest(corruption=corruption), tempfile.TemporaryDirectory() as directory:
                data_dir = Path(directory) / "current"
                repository = Repository(data_dir)
                repository.initialize()
                with sqlite3.connect(str(repository.path)) as connection:
                    if corruption == "checksum":
                        connection.execute(
                            "DROP TRIGGER schema_migrations_no_update"
                        )
                        connection.execute(
                            "UPDATE schema_migrations SET checksum_sha256=? WHERE version=1",
                            ("0" * 64,),
                        )
                        connection.execute(
                            MIGRATION_HISTORY_TRIGGER_DEFINITIONS[
                                "schema_migrations_no_update"
                            ][1]
                        )
                    elif corruption == "future-version":
                        connection.execute(
                            "DROP TRIGGER schema_migrations_no_insert_after_current"
                        )
                        connection.execute(
                            """
                            INSERT INTO schema_migrations(
                                version, name, checksum_sha256, app_version,
                                plan_id, applied_at
                            ) VALUES (?, ?, ?, ?, ?, ?)
                            """,
                            (
                                999,
                                "future_unknown_migration",
                                "f" * 64,
                                "future",
                                "future-plan",
                                "2099-01-01T00:00:00+00:00",
                            ),
                        )
                        connection.execute(
                            MIGRATION_HISTORY_TRIGGER_DEFINITIONS[
                                "schema_migrations_no_insert_after_current"
                            ][1]
                        )
                    else:
                        connection.execute(
                            "DROP TRIGGER recommendations_history_no_update"
                        )
                    connection.commit()
                corrupt_state = logical_database_snapshot(repository.path)

                with self.assertRaises(MigrationError) as raised:
                    repository.initialize()

                self.assertEqual(error_code(raised), "MIGRATION_HISTORY_INVALID")
                self.assertEqual(logical_database_snapshot(repository.path), corrupt_state)

    def test_req_mig_005_rejects_tampered_plan_body_with_unchanged_plan_id(self):
        """REQ-MIG-005: plan_id authenticates every persisted plan field."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "live"
            backup_dir = root / "backups"
            backup_dir.mkdir()
            database_path = create_legacy_database(data_dir)
            before = logical_database_snapshot(database_path)
            runner = MigrationRunner(Repository(data_dir))
            plan = runner.plan(target_version=1)
            tampered = plan.to_dict()
            tampered["source_database_version"] = 888
            tampered["target_database_version"] = 999
            tampered["counts"] = {"forged": -1}

            with self.assertRaises(MigrationError) as raised:
                untrusted_plan = MigrationPlan.from_dict(tampered)
                runner.apply(untrusted_plan, backup_dir=backup_dir)

            self.assertIn(
                error_code(raised),
                {"INVALID_MIGRATION_PLAN", "STALE_MIGRATION_PLAN"},
            )
            self.assertEqual(logical_database_snapshot(database_path), before)
            self.assertEqual(list(backup_dir.iterdir()), [])

    def test_req_mig_006_apply_of_current_plan_is_a_zero_write_noop(self):
        """REQ-MIG-006: an already-current database does not rerun migrations."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "current"
            backup_dir = root / "backups"
            backup_dir.mkdir()
            repository = Repository(data_dir)
            repository.initialize()
            before = logical_database_snapshot(repository.path)
            runner = MigrationRunner(repository)
            plan = runner.plan(target_version=1)

            try:
                result = runner.apply(plan, backup_dir=backup_dir)
            except MigrationError as exc:
                self.assertEqual(exc.code, "MIGRATION_NOT_REQUIRED")
            else:
                self.assertIn(result.status, {"no_changes", "already_current"})
            self.assertEqual(logical_database_snapshot(repository.path), before)
            self.assertEqual(list(backup_dir.iterdir()), [])

    def test_req_mig_004_rejects_same_named_but_wrong_managed_trigger(self):
        """REQ-MIG-004: trigger names alone cannot attest immutability."""

        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "current"
            repository = Repository(data_dir)
            repository.initialize()
            with sqlite3.connect(str(repository.path)) as connection:
                connection.execute("DROP TRIGGER recommendations_history_no_update")
                connection.execute(
                    """
                    CREATE TRIGGER recommendations_history_no_update
                    AFTER INSERT ON entities
                    BEGIN
                        SELECT 1;
                    END
                    """
                )
                connection.commit()
            corrupt_state = logical_database_snapshot(repository.path)

            with self.assertRaises(MigrationError) as raised:
                repository.initialize()

            self.assertEqual(error_code(raised), "MIGRATION_HISTORY_INVALID")
            self.assertEqual(logical_database_snapshot(repository.path), corrupt_state)

    def test_req_mig_001_blocks_legacy_payload_invalid_under_v1_contract(self):
        """REQ-MIG-001: adding schema_version cannot make an invalid v1 record."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "invalid-payload"
            backup_dir = root / "backups"
            backup_dir.mkdir()
            database_path = create_legacy_database(
                data_dir,
                entity_payload_overrides={
                    "demand-demo-001": json_text({"id": "demand-demo-001"})
                },
            )
            before = logical_database_snapshot(database_path)
            runner = MigrationRunner(Repository(data_dir))
            plan = runner.plan(target_version=1)

            self.assertTrue(
                plan.blockers,
                "the planned v1 target must be validated before apply",
            )
            with self.assertRaises(MigrationError) as raised:
                runner.apply(plan, backup_dir=backup_dir)
            self.assertEqual(error_code(raised), "MIGRATION_BLOCKED")
            self.assertEqual(logical_database_snapshot(database_path), before)
            self.assertEqual(list(backup_dir.iterdir()), [])

    def test_req_mig_005_rejects_rehashed_semantically_forged_current_plan(self):
        """REQ-MIG-005: a digest match is not a substitute for plan semantics."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "current"
            backup_dir = root / "backups"
            backup_dir.mkdir()
            repository = Repository(data_dir)
            repository.initialize()
            before = logical_database_snapshot(repository.path)
            generated = MigrationRunner(repository).plan(target_version=1)

            forged_document = generated.to_dict()
            forged_document.update(
                {
                    "source_database_version": 0,
                    "target_database_version": 999,
                    "migrations": [],
                    "counts": {"forged": -9},
                }
            )
            digest_body = dict(forged_document)
            digest_body.pop("plan_id")
            forged_document["plan_id"] = hashlib.sha256(
                json.dumps(
                    digest_body,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()

            with self.assertRaises(MigrationError) as raised:
                forged = MigrationPlan.from_dict(forged_document)
                MigrationRunner(repository).apply(forged, backup_dir=backup_dir)

            self.assertIn(
                error_code(raised),
                {"INVALID_MIGRATION_PLAN", "STALE_MIGRATION_PLAN"},
            )
            self.assertEqual(logical_database_snapshot(repository.path), before)
            self.assertEqual(list(backup_dir.iterdir()), [])

    def test_req_mig_005_plan_parser_rejects_nonexact_document_shapes(self):
        """REQ-MIG-005: persisted plans are closed, typed documents."""

        with tempfile.TemporaryDirectory() as directory:
            repository = Repository(Path(directory) / "current")
            repository.initialize()
            generated = MigrationRunner(repository).plan(target_version=1)

            malformed_documents = []

            unknown_root = generated.to_dict()
            unknown_root["unexpected_root_field"] = "must not be ignored"
            malformed_documents.append(("unknown-root-field", unknown_root))

            non_object_blocker = generated.to_dict()
            non_object_blocker["blockers"] = ["must not be filtered"]
            malformed_documents.append(("non-object-blocker", non_object_blocker))

            blocker_extra_field = generated.to_dict()
            blocker_extra_field["blockers"] = [
                {"code": "FORGED_BLOCKER", "count": 1, "extra": True}
            ]
            normalized_blocker_body = dict(blocker_extra_field)
            normalized_blocker_body.pop("plan_id")
            normalized_blocker_body["blockers"] = [
                {"code": "FORGED_BLOCKER", "count": 1}
            ]
            blocker_extra_field["plan_id"] = hashlib.sha256(
                json.dumps(
                    normalized_blocker_body,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            malformed_documents.append(
                ("blocker-extra-field", blocker_extra_field)
            )

            migrations_as_pairs = generated.to_dict()
            migrations_as_pairs["migrations"] = [
                [list(pair) for pair in item.items()]
                for item in migrations_as_pairs["migrations"]
            ]
            malformed_documents.append(("migration-not-object", migrations_as_pairs))

            string_count = generated.to_dict()
            string_count["counts"]["entities"] = str(
                string_count["counts"]["entities"]
            )
            malformed_documents.append(("count-not-integer", string_count))

            for case, document in malformed_documents:
                with self.subTest(case=case):
                    with self.assertRaises(MigrationError) as raised:
                        MigrationPlan.from_dict(document)
                    self.assertEqual(error_code(raised), "INVALID_MIGRATION_PLAN")

    def test_req_mig_003_rejects_same_named_legacy_index_on_wrong_columns(self):
        """REQ-MIG-003: a legacy fingerprint includes index definitions."""

        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "legacy"
            database_path = create_legacy_database(data_dir)
            with sqlite3.connect(str(database_path)) as connection:
                connection.execute("DROP INDEX idx_entities_pilot")
                connection.execute(
                    "CREATE INDEX idx_entities_pilot ON entities(entity_id)"
                )
                connection.commit()
            malformed = logical_database_snapshot(database_path)
            runner = MigrationRunner(Repository(data_dir))

            operations = (
                ("status", runner.status),
                ("plan", lambda: runner.plan(target_version=1)),
            )
            for operation_name, operation in operations:
                with self.subTest(operation=operation_name):
                    with self.assertRaises(MigrationError) as raised:
                        operation()
                    self.assertEqual(
                        error_code(raised), "UNRECOGNIZED_LEGACY_SCHEMA"
                    )
            self.assertEqual(logical_database_snapshot(database_path), malformed)

    def test_req_mig_003_rejects_same_named_legacy_definition_drift(self):
        """REQ-MIG-003: names and column lists do not prove frozen legacy DDL."""

        cases = (
            (
                "unique-index",
                """
                DROP INDEX idx_entities_pilot;
                CREATE UNIQUE INDEX idx_entities_pilot
                ON entities(pilot_id, kind);
                """,
            ),
            (
                "partial-index",
                """
                DROP INDEX idx_entities_pilot;
                CREATE INDEX idx_entities_pilot
                ON entities(pilot_id, kind) WHERE pilot_id IS NOT NULL;
                """,
            ),
            (
                "descending-index",
                """
                DROP INDEX idx_entities_pilot;
                CREATE INDEX idx_entities_pilot
                ON entities(pilot_id DESC, kind);
                """,
            ),
            (
                "table-without-types-or-constraints",
                """
                ALTER TABLE entities RENAME TO entities_old;
                CREATE TABLE entities (
                    kind,
                    entity_id,
                    pilot_id,
                    payload_json,
                    updated_at
                );
                INSERT INTO entities SELECT * FROM entities_old;
                DROP TABLE entities_old;
                CREATE INDEX idx_entities_pilot ON entities(pilot_id, kind);
                """,
            ),
        )

        for case, replacement_sql in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                data_dir = Path(directory) / "legacy"
                database_path = create_legacy_database(data_dir)
                with sqlite3.connect(str(database_path)) as connection:
                    connection.executescript(replacement_sql)
                    connection.commit()
                bytes_before = database_path.read_bytes()
                files_before = sorted(path.name for path in data_dir.iterdir())
                malformed = logical_database_snapshot(database_path)
                runner = MigrationRunner(Repository(data_dir))

                for operation_name, operation in (
                    ("status", runner.status),
                    ("plan", lambda: runner.plan(target_version=1)),
                ):
                    with self.subTest(case=case, operation=operation_name):
                        with self.assertRaises(MigrationError) as raised:
                            operation()
                        self.assertEqual(
                            error_code(raised), "UNRECOGNIZED_LEGACY_SCHEMA"
                        )

                self.assertEqual(database_path.read_bytes(), bytes_before)
                self.assertEqual(
                    sorted(path.name for path in data_dir.iterdir()), files_before
                )
                self.assertEqual(logical_database_snapshot(database_path), malformed)

    def test_req_mig_003_rejects_current_table_with_columns_but_no_constraints(self):
        """REQ-MIG-003: current table constraints are part of managed shape."""

        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "current"
            repository = Repository(data_dir)
            repository.initialize()
            with sqlite3.connect(str(repository.path)) as connection:
                connection.executescript(
                    """
                    ALTER TABLE entities RENAME TO entities_old;
                    CREATE TABLE entities (
                        kind TEXT NOT NULL,
                        entity_id TEXT NOT NULL,
                        pilot_id TEXT,
                        payload_schema_version INTEGER NOT NULL,
                        payload_json TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                    INSERT INTO entities SELECT * FROM entities_old;
                    DROP TABLE entities_old;
                    CREATE INDEX idx_entities_pilot ON entities(pilot_id, kind);
                    """
                )
                connection.commit()
            malformed = logical_database_snapshot(repository.path)

            with self.assertRaises(MigrationError) as raised:
                repository.initialize()

            self.assertEqual(error_code(raised), "MIGRATION_HISTORY_INVALID")
            self.assertEqual(logical_database_snapshot(repository.path), malformed)

    def test_req_mig_003_current_plan_validates_the_managed_contract(self):
        """REQ-MIG-003: current dry-run cannot attest a damaged managed shape."""

        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "current"
            repository = Repository(data_dir)
            repository.initialize()
            with sqlite3.connect(str(repository.path)) as connection:
                connection.execute("DROP TRIGGER recommendation_manifests_no_delete")
                connection.commit()
            malformed = logical_database_snapshot(repository.path)

            with self.assertRaises(MigrationError) as raised:
                MigrationRunner(repository).plan(target_version=1)

            self.assertEqual(error_code(raised), "MIGRATION_HISTORY_INVALID")
            self.assertEqual(logical_database_snapshot(repository.path), malformed)

    def test_req_mig_003_unknown_managed_table_trigger_is_rejected(self):
        """REQ-MIG-003: unregistered triggers cannot turn writes into no-ops."""

        with tempfile.TemporaryDirectory() as directory:
            repository = Repository(Path(directory) / "current")
            repository.initialize()
            with sqlite3.connect(str(repository.path)) as connection:
                connection.executescript(
                    """
                    CREATE TRIGGER swallow_entity_insert
                    BEFORE INSERT ON entities
                    BEGIN
                        SELECT RAISE(IGNORE);
                    END;
                    """
                )
            creator = copy.deepcopy(load_sample("creators.json")[0])

            with self.assertRaises(MigrationError) as raised:
                repository.put_entity("creator", creator)

            self.assertEqual(error_code(raised), "MIGRATION_HISTORY_INVALID")
            with sqlite3.connect(str(repository.path)) as connection:
                self.assertEqual(
                    connection.execute("SELECT count(*) FROM entities").fetchone()[0],
                    0,
                )


if __name__ == "__main__":
    unittest.main()
