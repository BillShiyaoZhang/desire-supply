"""Backup, recovery, locking and commit-unknown tests for REQ-MIG-007/008.

Expected recovery API:

``SqliteBackupService.restore(backup_path, manifest_path, destination_dir)``
validates the adjacent manifest, SHA-256, SQLite integrity and source logical
fingerprint before creating ``destination_dir/mvp.sqlite3``.  It never replaces
the live file.  Apply creates the manifest at ``<backup_path>.manifest.json``.
"""

import copy
import json
import os
import queue
import shutil
import sqlite3
import stat
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import desire_mvp.migrations as migrations_module
from desire_mvp.migrations import (
    MigrationError,
    MigrationRunner,
    SqliteBackupService,
    logical_fingerprint,
)
from desire_mvp.repository import Repository

from helpers import load_sample
from migration_fixtures import (
    create_legacy_database,
    logical_database_snapshot,
    recommendation_blob_rows,
)


def error_code(context_manager: unittest.case._AssertRaisesContext) -> str:
    return context_manager.exception.code


class MigrationRecoveryTests(unittest.TestCase):
    def test_backup_restore_round_trip(self):
        """REQ-MIG-007: restore the real pre-migration backup into isolation."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "live"
            backup_dir = root / "encrypted-backups"
            restore_dir = root / "isolated-restore"
            backup_dir.mkdir()
            database_path = create_legacy_database(data_dir)
            source_snapshot = logical_database_snapshot(database_path)
            source_recommendations = list(recommendation_blob_rows(database_path))

            runner = MigrationRunner(Repository(data_dir))
            plan = runner.plan(target_version=1)
            result = runner.apply(plan, backup_dir=backup_dir)
            backup_path = Path(result.backup_path)
            manifest_path = Path(str(backup_path) + ".manifest.json")

            self.assertTrue(backup_path.is_file())
            self.assertTrue(manifest_path.is_file())
            self.assertEqual(stat.S_IMODE(backup_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(manifest_path.stat().st_mode), 0o600)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["plan_id"], plan.plan_id)
            self.assertEqual(manifest["source_fingerprint"], plan.source_fingerprint)

            restored_path = SqliteBackupService().restore(
                backup_path=backup_path,
                manifest_path=manifest_path,
                destination_dir=restore_dir,
            )
            self.assertEqual(restored_path, restore_dir / "mvp.sqlite3")
            self.assertEqual(logical_database_snapshot(restored_path), source_snapshot)
            self.assertEqual(list(recommendation_blob_rows(restored_path)), source_recommendations)
            with sqlite3.connect(str(restored_path)) as connection:
                self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")

            # A restored v0 backup remains a readable legacy source; restore does
            # not migrate it or silently initialize it.
            restored_repository = Repository(restore_dir)
            self.assertEqual(len(restored_repository.list_entities("demand")), 1)
            restored_status = MigrationRunner(restored_repository).status()
            self.assertEqual(restored_status.state, "migration_required")
            self.assertEqual(restored_status.database_version, 0)

    def test_invalid_backup_is_rejected_without_partial_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "live"
            backup_dir = root / "backups"
            backup_dir.mkdir()
            create_legacy_database(data_dir)
            runner = MigrationRunner(Repository(data_dir))
            plan = runner.plan(target_version=1)
            result = runner.apply(plan, backup_dir=backup_dir)
            original_backup = Path(result.backup_path)
            original_manifest = Path(str(original_backup) + ".manifest.json")
            corrupt_backup = backup_dir / "corrupt.sqlite3"
            corrupt_manifest = Path(str(corrupt_backup) + ".manifest.json")
            shutil.copyfile(original_backup, corrupt_backup)
            shutil.copyfile(original_manifest, corrupt_manifest)
            with corrupt_backup.open("r+b") as handle:
                handle.seek(128)
                original = handle.read(1)
                handle.seek(128)
                handle.write(bytes([original[0] ^ 0xFF]))

            restore_dir = root / "rejected-restore"
            with self.assertRaises(MigrationError) as raised:
                SqliteBackupService().restore(
                    backup_path=corrupt_backup,
                    manifest_path=corrupt_manifest,
                    destination_dir=restore_dir,
                )

            self.assertEqual(error_code(raised), "BACKUP_INTEGRITY_ERROR")
            self.assertFalse((restore_dir / "mvp.sqlite3").exists())

    def test_backup_precondition_failure_leaves_source_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "live"
            database_path = create_legacy_database(data_dir)
            before = logical_database_snapshot(database_path)
            runner = MigrationRunner(Repository(data_dir))
            plan = runner.plan(target_version=1)

            # The design explicitly rejects a backup destination inside the
            # live data directory even if it happens to be writable.
            invalid_backup_dir = data_dir / "backups"
            invalid_backup_dir.mkdir()
            with self.assertRaises(MigrationError) as raised:
                runner.apply(plan, backup_dir=invalid_backup_dir)

            self.assertEqual(error_code(raised), "BACKUP_FAILED")
            self.assertEqual(logical_database_snapshot(database_path), before)
            self.assertEqual(list(invalid_backup_dir.iterdir()), [])

    def test_commit_unknown_is_recoverable_by_status_and_idempotent_retry(self):
        """REQ-MIG-008: a lost response after commit is not auto-retried blindly."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "live"
            backup_dir = root / "backups"
            backup_dir.mkdir()
            create_legacy_database(data_dir)
            runner = MigrationRunner(Repository(data_dir))
            plan = runner.plan(target_version=1)

            def lose_response(stage):
                if stage == "after_commit":
                    raise RuntimeError("simulated lost commit response")

            with self.assertRaises(MigrationError) as raised:
                runner.apply(plan, backup_dir=backup_dir, fault_injector=lose_response)

            self.assertEqual(error_code(raised), "MIGRATION_RECOVERY_REQUIRED")
            status = MigrationRunner(Repository(data_dir)).status(plan_id=plan.plan_id)
            self.assertEqual(status.state, "applied")
            self.assertEqual(status.plan_id, plan.plan_id)
            backup_files = sorted(path.name for path in backup_dir.iterdir())

            retry = MigrationRunner(Repository(data_dir)).apply(plan, backup_dir=backup_dir)
            self.assertEqual(retry.status, "already_applied")
            self.assertEqual(sorted(path.name for path in backup_dir.iterdir()), backup_files)

    def test_req_mig_008_commit_call_ack_loss_requires_recovery(self):
        """REQ-MIG-008: an exception returned by COMMIT may still mean committed."""

        class CommitAckLostConnection:
            def __init__(self, inner):
                object.__setattr__(self, "inner", inner)

            def __getattr__(self, name):
                return getattr(self.inner, name)

            def __setattr__(self, name, value):
                setattr(self.inner, name, value)

            def execute(self, sql, *args, **kwargs):
                result = self.inner.execute(sql, *args, **kwargs)
                if str(sql).strip().upper() == "COMMIT":
                    raise sqlite3.OperationalError("commit acknowledgement lost")
                return result

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "live"
            backup_dir = root / "backups"
            backup_dir.mkdir()
            database_path = create_legacy_database(data_dir)
            repository = Repository(data_dir)
            runner = MigrationRunner(repository)
            plan = runner.plan(target_version=1)
            real_connect = migrations_module.sqlite3.connect

            def connect_with_commit_ack_loss(path, *args, **kwargs):
                connection = real_connect(path, *args, **kwargs)
                if (
                    Path(path) == database_path
                    and kwargs.get("isolation_level", "not-specified") is None
                ):
                    return CommitAckLostConnection(connection)
                return connection

            with mock.patch(
                "desire_mvp.migrations.sqlite3.connect",
                side_effect=connect_with_commit_ack_loss,
            ):
                with self.assertRaises(MigrationError) as raised:
                    runner.apply(plan, backup_dir=backup_dir)

            self.assertEqual(error_code(raised), "MIGRATION_RECOVERY_REQUIRED")
            self.assertEqual(runner.status(plan_id=plan.plan_id).state, "applied")
            self.assertEqual(
                runner.apply(plan, backup_dir=backup_dir).status,
                "already_applied",
            )

    def test_second_apply_reports_busy_without_writing(self):
        """REQ-MIG-008: the migration lock has a stable non-destructive result."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "live"
            first_backup_dir = root / "backups-first"
            second_backup_dir = root / "backups-second"
            first_backup_dir.mkdir()
            second_backup_dir.mkdir()
            create_legacy_database(data_dir)
            repository = Repository(data_dir)
            plan = MigrationRunner(repository).plan(target_version=1)
            lock_acquired = threading.Event()
            release_first = threading.Event()
            first_result = queue.Queue()

            def pause_after_lock(stage):
                if stage == "after_lock_acquired":
                    lock_acquired.set()
                    if not release_first.wait(timeout=5):
                        raise RuntimeError("test timed out waiting to release migration")

            def run_first_apply():
                try:
                    first_result.put(
                        MigrationRunner(repository).apply(
                            plan,
                            backup_dir=first_backup_dir,
                            fault_injector=pause_after_lock,
                        )
                    )
                except BaseException as exc:  # surfaced in the main test thread
                    first_result.put(exc)

            worker = threading.Thread(target=run_first_apply, daemon=True)
            worker.start()
            self.assertTrue(lock_acquired.wait(timeout=5), "first apply never acquired its lock")
            try:
                with self.assertRaises(MigrationError) as raised:
                    MigrationRunner(repository, lock_timeout_seconds=0.05).apply(
                        plan,
                        backup_dir=second_backup_dir,
                    )
                self.assertEqual(error_code(raised), "MIGRATION_BUSY")
                self.assertEqual(list(second_backup_dir.iterdir()), [])
            finally:
                release_first.set()
                worker.join(timeout=10)

            self.assertFalse(worker.is_alive(), "first apply did not finish")
            first_outcome = first_result.get_nowait()
            if isinstance(first_outcome, BaseException):
                raise first_outcome
            self.assertEqual(first_outcome.status, "applied")

    def test_req_mig_007_restore_never_deletes_an_existing_destination(self):
        """REQ-MIG-007: failed restore cleanup owns only files it created."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "live"
            backup_dir = root / "backups"
            backup_dir.mkdir()
            create_legacy_database(data_dir)
            runner = MigrationRunner(Repository(data_dir))
            plan = runner.plan(target_version=1)
            result = runner.apply(plan, backup_dir=backup_dir)
            backup_path = Path(result.backup_path)
            manifest_path = Path(str(backup_path) + ".manifest.json")
            destination_dir = root / "existing-destination"
            destination_dir.mkdir()
            destination = destination_dir / "mvp.sqlite3"
            sentinel = b"existing database must survive a rejected restore"
            destination.write_bytes(sentinel)

            with self.assertRaises(MigrationError) as raised:
                SqliteBackupService().restore(
                    backup_path=backup_path,
                    manifest_path=manifest_path,
                    destination_dir=destination_dir,
                )

            self.assertEqual(error_code(raised), "BACKUP_INTEGRITY_ERROR")
            self.assertTrue(destination.is_file())
            self.assertEqual(destination.read_bytes(), sentinel)

    def test_req_mig_007_rejects_backup_directory_inside_a_repository(self):
        """REQ-MIG-007: migration backups must not be written into a worktree."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "worktree"
            root.mkdir()
            (root / ".git").mkdir()
            data_dir = root / "live"
            backup_dir = root / "backups"
            backup_dir.mkdir()
            database_path = create_legacy_database(data_dir)
            before = logical_database_snapshot(database_path)
            runner = MigrationRunner(Repository(data_dir))
            plan = runner.plan(target_version=1)

            with self.assertRaises(MigrationError) as raised:
                runner.apply(plan, backup_dir=backup_dir)

            self.assertEqual(error_code(raised), "BACKUP_FAILED")
            self.assertEqual(logical_database_snapshot(database_path), before)
            self.assertEqual(list(backup_dir.iterdir()), [])

    def test_req_mig_008_postcommit_mismatch_never_reports_success(self):
        """REQ-MIG-008: verify the committed target before acknowledging apply."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "live"
            backup_dir = root / "backups"
            backup_dir.mkdir()
            database_path = create_legacy_database(data_dir)
            runner = MigrationRunner(Repository(data_dir))
            plan = runner.plan(target_version=1)

            def mutate_before_ack(stage):
                if stage == "after_commit":
                    with sqlite3.connect(str(database_path)) as connection:
                        connection.execute(
                            """
                            UPDATE entities
                            SET updated_at='2099-01-01T00:00:00+00:00'
                            WHERE rowid=(SELECT min(rowid) FROM entities)
                            """
                        )
                        connection.commit()

            with self.assertRaises(MigrationError) as raised:
                runner.apply(
                    plan,
                    backup_dir=backup_dir,
                    fault_injector=mutate_before_ack,
                )

            self.assertEqual(error_code(raised), "MIGRATION_RECOVERY_REQUIRED")

    def test_req_mig_008_fresh_database_rejects_forged_applied_receipt(self):
        """REQ-MIG-008: status cannot trust an unlinked migration_runs row."""

        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "current"
            repository = Repository(data_dir)
            repository.initialize()
            fake_plan_id = "a" * 64
            summary = json.dumps(
                {
                    "entities": 0,
                    "outcomes": 0,
                    "v0_records": 0,
                    "v1_records": 0,
                    "recommendations": 0,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            with sqlite3.connect(str(repository.path)) as connection:
                # Simulate an externally corrupted file by first removing the
                # managed late-insert guard.  Normal SQL writes are rejected
                # by that guard before a forged receipt can be created.
                connection.execute(
                    "DROP TRIGGER migration_runs_no_insert_after_registry"
                )
                connection.execute(
                    """
                    INSERT INTO migration_runs(
                        plan_id, source_database_version, target_database_version,
                        source_fingerprint, target_fingerprint, resolution_sha256,
                        backup_path, backup_sha256, summary_json, applied_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        fake_plan_id,
                        0,
                        3,
                        "b" * 64,
                        "c" * 64,
                        None,
                        "/controlled/missing-backup.sqlite3",
                        "d" * 64,
                        summary,
                        "2026-08-07T00:00:00+00:00",
                    ),
                )
                connection.commit()

            with self.assertRaises(MigrationError) as raised:
                MigrationRunner(repository).status(plan_id=fake_plan_id)

            self.assertEqual(error_code(raised), "MIGRATION_HISTORY_INVALID")

    def test_req_mig_007_backup_create_race_never_deletes_foreign_file(self):
        """REQ-MIG-007: failed exclusive-create cleanup owns only its files."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "live"
            backup_dir = root / "backups"
            backup_dir.mkdir()
            database_path = create_legacy_database(data_dir)
            plan_id = "b" * 64
            backup_path = backup_dir / "mvp-before-{}.sqlite3".format(
                plan_id[:16]
            )
            sentinel = b"created by another process during the O_EXCL race"
            real_open = os.open

            def race_before_exclusive_create(path, flags, mode=0o777, *args, **kwargs):
                candidate = Path(path)
                if candidate == backup_path or candidate.name == backup_path.name:
                    descriptor = real_open(
                        str(backup_path),
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o600,
                    )
                    try:
                        os.write(descriptor, sentinel)
                    finally:
                        os.close(descriptor)
                    raise FileExistsError("simulated exclusive-create race")
                return real_open(path, flags, mode, *args, **kwargs)

            with mock.patch(
                "desire_mvp.migrations.os.open",
                side_effect=race_before_exclusive_create,
            ):
                with self.assertRaises(MigrationError) as raised:
                    SqliteBackupService().create(
                        database_path,
                        backup_dir,
                        plan_id=plan_id,
                        source_fingerprint=logical_fingerprint(database_path),
                    )

            self.assertEqual(error_code(raised), "BACKUP_FAILED")
            self.assertTrue(backup_path.is_file())
            self.assertEqual(backup_path.read_bytes(), sentinel)

    def test_req_mig_007_backup_cleanup_preserves_replacement_inode(self):
        """REQ-MIG-007: path ownership cannot outlive the inode it created."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "live"
            backup_dir = root / "backups"
            backup_dir.mkdir()
            database_path = create_legacy_database(data_dir)
            source_before = logical_database_snapshot(database_path)
            source_fingerprint = logical_fingerprint(database_path)
            plan_id = "f" * 64
            backup_path = backup_dir / "mvp-before-{}.sqlite3".format(
                plan_id[:16]
            )
            sentinel = b"foreign inode installed after the owned path was closed"

            def replace_owned_path_then_fail(_source_path):
                self.assertTrue(backup_path.is_file())
                backup_path.unlink()
                backup_path.write_bytes(sentinel)
                raise OSError("simulated replacement race")

            with mock.patch(
                "desire_mvp.migrations._readonly_connection",
                side_effect=replace_owned_path_then_fail,
            ):
                with self.assertRaises(MigrationError) as raised:
                    SqliteBackupService().create(
                        database_path,
                        backup_dir,
                        plan_id=plan_id,
                        source_fingerprint=source_fingerprint,
                    )

            self.assertEqual(error_code(raised), "BACKUP_FAILED")
            self.assertTrue(backup_path.is_file())
            self.assertEqual(backup_path.read_bytes(), sentinel)
            self.assertFalse(Path(str(backup_path) + ".manifest.json").exists())
            self.assertEqual(logical_database_snapshot(database_path), source_before)

    def test_req_mig_007_backup_never_writes_a_replacement_inode(self):
        """REQ-MIG-007: reserved output paths are never reopened for writing."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "live"
            backup_dir = root / "backups"
            backup_dir.mkdir()
            database_path = create_legacy_database(data_dir)
            plan_id = "9" * 64
            backup_path = backup_dir / "mvp-before-{}.sqlite3".format(
                plan_id[:16]
            )
            real_readonly = migrations_module._readonly_connection
            source_fingerprint = logical_fingerprint(database_path)
            replaced = False

            def replace_reserved_path_then_open(source_path):
                nonlocal replaced
                if Path(source_path) == database_path and not replaced:
                    replaced = True
                    backup_path.unlink()
                    with sqlite3.connect(str(backup_path)) as foreign:
                        foreign.execute(
                            "CREATE TABLE foreign_marker(value TEXT NOT NULL)"
                        )
                        foreign.execute(
                            "INSERT INTO foreign_marker(value) VALUES ('keep-me')"
                        )
                return real_readonly(source_path)

            with mock.patch(
                "desire_mvp.migrations._readonly_connection",
                side_effect=replace_reserved_path_then_open,
            ):
                with self.assertRaises(MigrationError) as raised:
                    SqliteBackupService().create(
                        database_path,
                        backup_dir,
                        plan_id=plan_id,
                        source_fingerprint=source_fingerprint,
                    )

            self.assertEqual(error_code(raised), "BACKUP_FAILED")
            with sqlite3.connect(str(backup_path)) as foreign:
                self.assertEqual(
                    foreign.execute("SELECT value FROM foreign_marker").fetchone()[0],
                    "keep-me",
                )

    def test_req_mig_007_restore_cleanup_preserves_replacement_inode(self):
        """REQ-MIG-007: restore cleanup only unlinks its original inode."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_dir = root / "source"
            backup_dir = root / "backups"
            restore_dir = root / "restore"
            backup_dir.mkdir()
            database_path = create_legacy_database(source_dir)
            backup_path, manifest_path, _ = SqliteBackupService().create(
                database_path,
                backup_dir,
                plan_id="8" * 64,
                source_fingerprint=logical_fingerprint(database_path),
            )
            destination = restore_dir / "mvp.sqlite3"
            sentinel = b"foreign replacement must survive restore cleanup"
            real_copy = shutil.copyfileobj

            def replace_destination_then_fail(source, target):
                real_copy(source, target)
                destination.unlink()
                destination.write_bytes(sentinel)
                raise OSError("simulated post-copy replacement")

            with mock.patch(
                "desire_mvp.migrations.shutil.copyfileobj",
                side_effect=replace_destination_then_fail,
            ):
                with self.assertRaises(MigrationError) as raised:
                    SqliteBackupService().restore(
                        backup_path=backup_path,
                        manifest_path=manifest_path,
                        destination_dir=restore_dir,
                    )

            self.assertEqual(error_code(raised), "BACKUP_INTEGRITY_ERROR")
            self.assertEqual(destination.read_bytes(), sentinel)

    def test_req_mig_007_backup_hashing_is_streaming(self):
        """REQ-MIG-007: backup verification must not load a database at once."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "live"
            backup_dir = root / "backups"
            backup_dir.mkdir()
            database_path = create_legacy_database(data_dir)

            with mock.patch.object(
                Path,
                "read_bytes",
                side_effect=AssertionError("whole-file read is forbidden"),
            ):
                backup_path, manifest_path, digest = SqliteBackupService().create(
                    database_path,
                    backup_dir,
                    plan_id="c" * 64,
                    source_fingerprint=logical_fingerprint(database_path),
                )

            self.assertTrue(backup_path.is_file())
            self.assertTrue(manifest_path.is_file())
            self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_req_mig_006_receipt_survives_legitimate_postmigration_writes(self):
        """REQ-MIG-006: a durable receipt is not a live business-data checksum."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "live"
            backup_dir = root / "backups"
            backup_dir.mkdir()
            create_legacy_database(data_dir)
            repository = Repository(data_dir)
            runner = MigrationRunner(repository)
            plan = runner.plan(target_version=1)
            first = runner.apply(plan, backup_dir=backup_dir)
            self.assertEqual(first.status, "applied")

            # This is an ordinary, valid v1 business write after cutover.  It
            # necessarily changes the live logical business fingerprint, but
            # it cannot make the atomic migration receipt cease to exist.
            repository.put_entity(
                "creator", copy.deepcopy(load_sample("creators.json")[2])
            )

            def migration_metadata():
                with sqlite3.connect(str(repository.path)) as connection:
                    return {
                        "runs": connection.execute(
                            "SELECT * FROM migration_runs ORDER BY plan_id"
                        ).fetchall(),
                        "registry": connection.execute(
                            "SELECT * FROM schema_migrations ORDER BY version"
                        ).fetchall(),
                        "audit": connection.execute(
                            """
                            SELECT * FROM payload_migration_audit
                            ORDER BY plan_id, record_type, record_key
                            """
                        ).fetchall(),
                    }

            metadata_after_business_write = migration_metadata()
            backup_files_after_business_write = sorted(
                path.name for path in backup_dir.iterdir()
            )

            status = runner.status(plan_id=plan.plan_id)
            self.assertEqual(status.state, "applied")
            self.assertEqual(status.plan_id, plan.plan_id)
            retry = runner.apply(plan, backup_dir=backup_dir)
            self.assertEqual(retry.status, "already_applied")

            self.assertEqual(migration_metadata(), metadata_after_business_write)
            self.assertEqual(
                sorted(path.name for path in backup_dir.iterdir()),
                backup_files_after_business_write,
            )

    def test_req_mig_004_migration_history_is_append_once_after_cutover(self):
        """REQ-MIG-004: registry, receipt and audit history becomes immutable."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "live"
            backup_dir = root / "backups"
            backup_dir.mkdir()
            create_legacy_database(data_dir)
            repository = Repository(data_dir)
            runner = MigrationRunner(repository)
            plan = runner.plan(target_version=1)
            runner.apply(plan, backup_dir=backup_dir)

            statements = (
                "UPDATE schema_migrations SET plan_id='{}' WHERE version=1".format(
                    "e" * 64
                ),
                "DELETE FROM schema_migrations WHERE version=1",
                """
                INSERT INTO schema_migrations(
                    version, name, checksum_sha256, app_version, plan_id, applied_at
                ) VALUES (4, 'forged', '{}', 'forged', '{}', '2026-08-07T00:00:00+00:00')
                """.format("a" * 64, plan.plan_id),
                "UPDATE migration_runs SET target_fingerprint='{}'".format("d" * 64),
                """
                INSERT INTO migration_runs
                SELECT '{}', source_database_version, target_database_version,
                       source_fingerprint, target_fingerprint, resolution_sha256,
                       backup_path, backup_sha256, summary_json, applied_at
                FROM migration_runs LIMIT 1
                """.format("f" * 64),
                "UPDATE payload_migration_audit SET change_codes_json='[]'",
                "DELETE FROM payload_migration_audit",
            )
            with sqlite3.connect(str(repository.path)) as connection:
                connection.execute("PRAGMA foreign_keys = ON")
                for index, statement in enumerate(statements):
                    with self.subTest(statement=index):
                        connection.execute("SAVEPOINT immutable_history")
                        try:
                            with self.assertRaises(sqlite3.IntegrityError):
                                connection.execute(statement)
                        finally:
                            connection.execute("ROLLBACK TO immutable_history")
                            connection.execute("RELEASE immutable_history")


if __name__ == "__main__":
    unittest.main()
