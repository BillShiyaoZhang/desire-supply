import contextlib
import copy
import io
import json
import sqlite3
import stat
import tempfile
import unittest
from pathlib import Path

from desire_mvp.cli import main
from desire_mvp.repository import Repository

from helpers import ROOT, load_sample


# Frozen legacy-v0b DDL.  This intentionally does not import Repository.SCHEMA:
# the production constant will become v1, while this fixture must remain a
# reproducible pre-migration database.
LEGACY_V0B_SCHEMA = """
CREATE TABLE IF NOT EXISTS entities (
    kind TEXT NOT NULL CHECK(kind IN ('creator', 'demand')),
    entity_id TEXT NOT NULL,
    pilot_id TEXT,
    payload_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (kind, entity_id)
);

CREATE TABLE IF NOT EXISTS recommendations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    demand_id TEXT NOT NULL,
    pilot_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    input_snapshot_json TEXT NOT NULL,
    result_json TEXT NOT NULL,
    budget_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recommendation_id INTEGER NOT NULL,
    demand_id TEXT NOT NULL,
    pilot_id TEXT NOT NULL,
    selected_creator_id TEXT,
    invited_creator_ids_json TEXT NOT NULL,
    participant_responses_json TEXT NOT NULL DEFAULT '[]',
    reason_code TEXT NOT NULL,
    reason_note TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(recommendation_id) REFERENCES recommendations(id)
);

CREATE TABLE IF NOT EXISTS outcomes (
    project_id TEXT PRIMARY KEY,
    pilot_id TEXT NOT NULL,
    demand_id TEXT NOT NULL,
    creator_ids_json TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_entities_pilot ON entities(pilot_id, kind);
CREATE INDEX IF NOT EXISTS idx_recommendations_pilot ON recommendations(pilot_id, demand_id);
CREATE INDEX IF NOT EXISTS idx_decisions_pilot ON decisions(pilot_id, demand_id);
CREATE INDEX IF NOT EXISTS idx_outcomes_pilot ON outcomes(pilot_id, demand_id);
"""

PRIVATE_SENTINEL = "PRIVATE-MIGRATION-EVIDENCE-do-not-disclose"


def _canonical_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _create_legacy_v0b(data_dir, private_sentinel=PRIVATE_SENTINEL):
    data_dir.mkdir(parents=True)
    database = data_dir / "mvp.sqlite3"
    demand = copy.deepcopy(load_sample("demands.json")[0])
    creators = copy.deepcopy(load_sample("creators.json")[:2])
    demand.pop("schema_version", None)
    for creator in creators:
        creator.pop("schema_version", None)
    creators[0]["skills"][0]["evidence_ref"] = private_sentinel

    with sqlite3.connect(str(database)) as connection:
        connection.executescript(LEGACY_V0B_SCHEMA)
        connection.execute(
            """
            INSERT INTO entities(kind, entity_id, pilot_id, payload_json, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                "demand",
                demand["id"],
                demand["pilot_id"],
                _canonical_json(demand),
                "2026-08-01T00:00:00+00:00",
            ),
        )
        connection.executemany(
            """
            INSERT INTO entities(kind, entity_id, pilot_id, payload_json, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                (
                    "creator",
                    creator["id"],
                    None,
                    _canonical_json(creator),
                    "2026-08-01T00:00:00+00:00",
                )
                for creator in creators
            ],
        )
    return database, demand, creators


def _database_snapshot(database):
    """Return schema and raw SQL values without normalizing JSON payloads."""

    with sqlite3.connect(str(database)) as connection:
        schema = connection.execute(
            """
            SELECT type, name, tbl_name, sql
            FROM sqlite_master
            ORDER BY type, name
            """
        ).fetchall()
        table_names = [
            row[0]
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                ORDER BY name
                """
            ).fetchall()
        ]
        rows = {}
        for table_name in table_names:
            quoted = table_name.replace('"', '""')
            rows[table_name] = connection.execute(
                'SELECT * FROM "{}" ORDER BY rowid'.format(quoted)
            ).fetchall()
    return {"schema": schema, "rows": rows}


def _sqlite_backup_files(backup_dir):
    backups = []
    for path in backup_dir.rglob("*"):
        if path.is_file():
            with path.open("rb") as handle:
                if handle.read(16) == b"SQLite format 3\x00":
                    backups.append(path)
    return backups


def _invoke(data_dir, *arguments):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            main(
                [
                    "--data-dir",
                    str(data_dir),
                    "--config-dir",
                    str(ROOT / "config"),
                    *arguments,
                ]
            )
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
            return code, stdout.getvalue(), stderr.getvalue()
    return 0, stdout.getvalue(), stderr.getvalue()


def _dry_run(data_dir, plan_path):
    return _invoke(
        data_dir,
        "migrate",
        "--payload-schema",
        "1",
        "--dry-run",
        "--plan-out",
        str(plan_path),
    )


def _apply(data_dir, plan_path, backup_dir):
    return _invoke(
        data_dir,
        "migrate",
        "--payload-schema",
        "1",
        "--apply",
        "--plan",
        str(plan_path),
        "--backup-dir",
        str(backup_dir),
    )


class MigrationCliTests(unittest.TestCase):
    def invoke(self, data_dir, *arguments):
        return _invoke(data_dir, *arguments)

    def dry_run(self, data_dir, plan_path):
        return _dry_run(data_dir, plan_path)

    def apply(self, data_dir, plan_path, backup_dir):
        return _apply(data_dir, plan_path, backup_dir)

    def assert_private_payload_is_absent(self, *texts):
        for text in texts:
            self.assertNotIn(PRIVATE_SENTINEL, text)

    def test_canonical_payload_schema_flag_and_alias_conflict(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "data"
            database, _, _ = _create_legacy_v0b(data_dir)
            before = _database_snapshot(database)
            canonical_plan = root / "canonical-plan.json"

            exit_code, stdout, stderr = self.invoke(
                data_dir,
                "migrate",
                "--payload-schema",
                "1",
                "--dry-run",
                "--plan-out",
                str(canonical_plan),
            )

            self.assertEqual((exit_code, stderr), (0, ""))
            self.assertEqual(json.loads(stdout)["status"], "planned")
            self.assertTrue(canonical_plan.is_file())
            self.assertEqual(_database_snapshot(database), before)

            conflicting_plan = root / "must-not-exist.json"
            exit_code, stdout, stderr = self.invoke(
                data_dir,
                "migrate",
                "--payload-schema",
                "1",
                "--to",
                "1",
                "--dry-run",
                "--plan-out",
                str(conflicting_plan),
            )

            self.assertEqual(exit_code, 2)
            self.assertIn("不能同时使用", stderr)
            self.assertEqual(stdout, "")
            self.assertFalse(conflicting_plan.exists())
            self.assertEqual(_database_snapshot(database), before)

    def test_current_database_dry_run_reports_no_changes_without_plan_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "current"
            repository = Repository(data_dir)
            repository.initialize()
            before = _database_snapshot(repository.path)
            plan_path = root / "must-not-exist.json"

            exit_code, stdout, stderr = self.invoke(
                data_dir,
                "migrate",
                "--payload-schema",
                "1",
                "--dry-run",
                "--plan-out",
                str(plan_path),
            )

            self.assertEqual((exit_code, stderr), (0, ""))
            payload = json.loads(stdout)
            self.assertEqual(payload["status"], "no_changes")
            self.assertEqual(payload["source_database_version"], 3)
            self.assertFalse(plan_path.exists())
            self.assertEqual(_database_snapshot(repository.path), before)

    def test_migrate_status_reports_legacy_without_writing_and_list_remains_readable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "data"
            database, demand, creators = _create_legacy_v0b(data_dir)
            bytes_before = database.read_bytes()
            logical_before = _database_snapshot(database)
            files_before = sorted(path.name for path in data_dir.iterdir())

            exit_code, stdout, stderr = self.invoke(data_dir, "migrate", "status")

            self.assertEqual((exit_code, stderr), (0, ""))
            status_payload = json.loads(stdout)
            self.assertEqual(status_payload["code"], "MIGRATION_REQUIRED")
            self.assertEqual(status_payload["status"], "migration_required")
            self.assertEqual(status_payload["source_database_version"], 0)
            self.assertEqual(status_payload["target_database_version"], 3)
            self.assertEqual(status_payload["target_payload_schema_version"], 1)
            self.assert_private_payload_is_absent(stdout, stderr)
            self.assertEqual(database.read_bytes(), bytes_before)
            self.assertEqual(_database_snapshot(database), logical_before)
            self.assertEqual(sorted(path.name for path in data_dir.iterdir()), files_before)

            exit_code, stdout, stderr = self.invoke(data_dir, "list", "creator")
            self.assertEqual((exit_code, stderr), (0, ""))
            listed_ids = [item["id"] for item in json.loads(stdout)]
            self.assertEqual(listed_ids, sorted(creator["id"] for creator in creators))
            self.assertNotIn(demand["id"], stdout)
            self.assert_private_payload_is_absent(stdout)
            self.assertEqual(database.read_bytes(), bytes_before)
            self.assertEqual(_database_snapshot(database), logical_before)

    def test_dry_run_and_guarded_apply(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "data"
            database, _, _ = _create_legacy_v0b(data_dir)
            plan_path = root / "migration-plan.json"
            backup_dir = root / "backups"
            backup_dir.mkdir()
            bytes_before = database.read_bytes()
            logical_before = _database_snapshot(database)

            exit_code, stdout, stderr = self.dry_run(data_dir, plan_path)

            self.assertEqual((exit_code, stderr), (0, ""))
            self.assertTrue(plan_path.is_file())
            self.assertEqual(stat.S_IMODE(plan_path.stat().st_mode), 0o600)
            plan_text = plan_path.read_text(encoding="utf-8")
            plan = json.loads(plan_text)
            self.assertEqual(plan["plan_format_version"], 1)
            self.assertEqual(plan["source_database_version"], 0)
            self.assertEqual(plan["target_database_version"], 3)
            self.assertEqual(plan["target_payload_schema_version"], 1)
            self.assertEqual(plan["blockers"], [])
            self.assertRegex(plan["plan_id"], r"^[0-9a-f]{64}$")
            self.assertRegex(plan["source_fingerprint"], r"^[0-9a-f]{64}$")
            self.assertTrue(plan["migrations"])
            for migration in plan["migrations"]:
                self.assertIn("name", migration)
                self.assertRegex(migration["checksum_sha256"], r"^[0-9a-f]{64}$")
            self.assert_private_payload_is_absent(stdout, stderr, plan_text)
            self.assertEqual(database.read_bytes(), bytes_before)
            self.assertEqual(_database_snapshot(database), logical_before)
            self.assertEqual(sorted(path.name for path in data_dir.iterdir()), ["mvp.sqlite3"])

            exit_code, _, stderr = self.invoke(
                data_dir,
                "migrate",
                "--to",
                "1",
                "--apply",
                "--backup-dir",
                str(backup_dir),
            )
            self.assertEqual(exit_code, 2)
            self.assertIn("--plan", stderr)
            self.assertEqual(_database_snapshot(database), logical_before)
            self.assertEqual(list(backup_dir.iterdir()), [])

            exit_code, _, stderr = self.invoke(
                data_dir,
                "migrate",
                "--to",
                "1",
                "--apply",
                "--plan",
                str(plan_path),
            )
            self.assertEqual(exit_code, 2)
            self.assertIn("--backup-dir", stderr)
            self.assertEqual(_database_snapshot(database), logical_before)
            self.assertEqual(list(backup_dir.iterdir()), [])

            exit_code, stdout, stderr = self.apply(data_dir, plan_path, backup_dir)

            self.assertEqual((exit_code, stderr), (0, ""))
            self.assert_private_payload_is_absent(stdout, stderr)
            backup_files = _sqlite_backup_files(backup_dir)
            self.assertEqual(len(backup_files), 1)
            self.assertEqual(stat.S_IMODE(backup_files[0].stat().st_mode), 0o600)
            self.assertEqual(_database_snapshot(backup_files[0]), logical_before)
            manifests = [
                path
                for path in backup_dir.rglob("*")
                if path.is_file() and path not in backup_files
            ]
            self.assertTrue(manifests)
            for manifest in manifests:
                self.assert_private_payload_is_absent(manifest.read_text(encoding="utf-8"))

            with sqlite3.connect(str(database)) as connection:
                versions = [
                    row[0]
                    for row in connection.execute(
                        "SELECT version FROM schema_migrations ORDER BY version"
                    ).fetchall()
                ]
                payloads = [
                    json.loads(row[0])
                    for row in connection.execute(
                        "SELECT payload_json FROM entities ORDER BY kind, entity_id"
                    ).fetchall()
                ]
            self.assertEqual(versions, [1, 2, 3])
            self.assertTrue(all(payload["schema_version"] == 1 for payload in payloads))

    def test_apply_rejects_stale_plan_before_backup_and_does_not_disclose_changed_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "data"
            database, demand, _ = _create_legacy_v0b(data_dir)
            plan_path = root / "migration-plan.json"
            backup_dir = root / "backups"
            backup_dir.mkdir()
            exit_code, _, stderr = self.dry_run(data_dir, plan_path)
            self.assertEqual((exit_code, stderr), (0, ""))

            changed = copy.deepcopy(demand)
            changed["problem"]["desired_outcome"] = PRIVATE_SENTINEL
            changed["budget"]["maximum"] = 987654321
            with sqlite3.connect(str(database)) as connection:
                connection.execute(
                    """
                    UPDATE entities
                    SET payload_json = ?, updated_at = ?
                    WHERE kind = 'demand' AND entity_id = ?
                    """,
                    (
                        _canonical_json(changed),
                        "2026-08-02T00:00:00+00:00",
                        demand["id"],
                    ),
                )
            logical_after_change = _database_snapshot(database)

            exit_code, stdout, stderr = self.apply(data_dir, plan_path, backup_dir)

            self.assertEqual(exit_code, 2)
            self.assertIn("STALE_MIGRATION_PLAN", stdout + stderr)
            self.assert_private_payload_is_absent(stdout, stderr)
            self.assertNotIn("987654321", stdout + stderr)
            self.assertEqual(_database_snapshot(database), logical_after_change)
            self.assertEqual(list(backup_dir.iterdir()), [])
            with sqlite3.connect(str(database)) as connection:
                migration_table = connection.execute(
                    """
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'table' AND name = 'schema_migrations'
                    """
                ).fetchone()
            self.assertIsNone(migration_table)

    def test_legacy_write_commands_fail_with_migration_required_without_mutation(self):
        commands = ("init", "import", "match")
        for command in commands:
            with self.subTest(command=command), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                data_dir = root / "data"
                database, demand, _ = _create_legacy_v0b(data_dir)
                import_path = root / "creator-v1.json"
                creator = copy.deepcopy(load_sample("creators.json")[2])
                creator["schema_version"] = 1
                creator["skills"][0]["evidence_ref"] = PRIVATE_SENTINEL
                import_path.write_text(_canonical_json(creator), encoding="utf-8")
                logical_before = _database_snapshot(database)
                bytes_before = database.read_bytes()

                if command == "init":
                    arguments = ("init",)
                elif command == "import":
                    arguments = ("import", "creator", str(import_path))
                else:
                    arguments = ("match", demand["id"])
                exit_code, stdout, stderr = self.invoke(data_dir, *arguments)

                self.assertEqual(exit_code, 2)
                self.assertIn("MIGRATION_REQUIRED", stdout + stderr)
                self.assert_private_payload_is_absent(stdout, stderr)
                self.assertEqual(database.read_bytes(), bytes_before)
                self.assertEqual(_database_snapshot(database), logical_before)

    def test_blocked_dry_run_writes_only_a_redacted_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "data"
            database, _, creators = _create_legacy_v0b(data_dir)
            malformed = '{{"private_note":"{}","amount":987654321'.format(PRIVATE_SENTINEL)
            with sqlite3.connect(str(database)) as connection:
                connection.execute(
                    """
                    UPDATE entities SET payload_json = ?
                    WHERE kind = 'creator' AND entity_id = ?
                    """,
                    (malformed, creators[0]["id"]),
                )
            bytes_before = database.read_bytes()
            logical_before = _database_snapshot(database)
            plan_path = root / "blocked-plan.json"

            exit_code, stdout, stderr = self.dry_run(data_dir, plan_path)

            self.assertEqual(exit_code, 2)
            self.assertTrue(plan_path.is_file())
            self.assertEqual(stat.S_IMODE(plan_path.stat().st_mode), 0o600)
            plan_text = plan_path.read_text(encoding="utf-8")
            plan = json.loads(plan_text)
            self.assertTrue(plan["blockers"])
            self.assertTrue(all(blocker.get("code") for blocker in plan["blockers"]))
            self.assert_private_payload_is_absent(stdout, stderr, plan_text)
            self.assertNotIn("987654321", stdout + stderr + plan_text)
            self.assertNotIn("JSONDecodeError", stdout + stderr)
            self.assertNotIn("Traceback", stdout + stderr)
            self.assertEqual(database.read_bytes(), bytes_before)
            self.assertEqual(_database_snapshot(database), logical_before)

    def test_req_mig_008_malformed_sqlite_status_has_stable_safe_exit(self):
        """REQ-MIG-008: corrupt SQLite input never escapes as a raw exception."""

        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "data"
            data_dir.mkdir()
            database = data_dir / "mvp.sqlite3"
            sentinel = b"not a sqlite database; PRIVATE-MALFORMED-DB"
            database.write_bytes(sentinel)

            exit_code, stdout, stderr = self.invoke(data_dir, "migrate", "status")

            self.assertEqual(exit_code, 2)
            self.assertIn("MIGRATION_HISTORY_INVALID", stdout + stderr)
            self.assertNotIn("DatabaseError", stdout + stderr)
            self.assertNotIn("Traceback", stdout + stderr)
            self.assertNotIn("PRIVATE-MALFORMED-DB", stdout + stderr)
            self.assertEqual(database.read_bytes(), sentinel)

    def test_req_mig_005_malformed_resolution_has_stable_safe_exit(self):
        """REQ-MIG-005: malformed resolution scalars never escape as TypeError."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "data"
            database, _, _ = _create_legacy_v0b(data_dir)
            before = _database_snapshot(database)
            bytes_before = database.read_bytes()
            plan_path = root / "must-not-exist.json"
            resolutions_path = root / "malformed-resolutions.json"
            resolutions_path.write_text(
                _canonical_json(
                    {
                        "schema_version": 1,
                        "demand_status_resolutions": [
                            {
                                "demand_id": [PRIVATE_SENTINEL],
                                "from": "closed",
                                "to": "agreed",
                                "reason_code": "PROJECT_ESTABLISHED",
                                "evidence_ref": "external://migration-review-001",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            exit_code, stdout, stderr = self.invoke(
                data_dir,
                "migrate",
                "--payload-schema",
                "1",
                "--dry-run",
                "--plan-out",
                str(plan_path),
                "--resolutions",
                str(resolutions_path),
            )

            rendered = stdout + stderr
            self.assertEqual(exit_code, 2)
            self.assertIn("INVALID_DEMAND_STATUS_RESOLUTION", rendered)
            self.assertNotIn("TypeError", rendered)
            self.assertNotIn("Traceback", rendered)
            self.assertNotIn(PRIVATE_SENTINEL, rendered)
            self.assertFalse(plan_path.exists())
            self.assertEqual(database.read_bytes(), bytes_before)
            self.assertEqual(_database_snapshot(database), before)


if __name__ == "__main__":
    unittest.main()
