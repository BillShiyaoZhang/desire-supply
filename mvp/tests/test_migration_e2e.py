import copy
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from helpers import load_sample
from test_cli_migrations import _apply, _create_legacy_v0b, _dry_run, _invoke


class MigrationCutoverE2ETests(unittest.TestCase):
    def test_legacy_to_v1_cutover(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "data"
            database, demand, _ = _create_legacy_v0b(data_dir)
            plan_path = root / "migration-plan.json"
            backup_dir = root / "backups"
            backup_dir.mkdir()

            exit_code, _, stderr = _dry_run(data_dir, plan_path)
            self.assertEqual((exit_code, stderr), (0, ""))
            exit_code, stdout, stderr = _apply(data_dir, plan_path, backup_dir)
            self.assertEqual((exit_code, stderr), (0, ""))
            self.assertNotIn("MIGRATION_REQUIRED", stdout)

            exit_code, stdout, stderr = _invoke(data_dir, "migrate", "status")
            self.assertEqual((exit_code, stderr), (0, ""))
            status_payload = json.loads(stdout)
            self.assertEqual(status_payload["status"], "current")
            self.assertEqual(status_payload["target_database_version"], 3)
            self.assertEqual(status_payload["target_payload_schema_version"], 1)

            creator = copy.deepcopy(load_sample("creators.json")[2])
            creator["schema_version"] = 1
            import_path = root / "creator-v1.json"
            import_path.write_text(
                json.dumps(creator, ensure_ascii=False),
                encoding="utf-8",
            )
            exit_code, _, stderr = _invoke(
                data_dir,
                "import",
                "creator",
                str(import_path),
            )
            self.assertEqual((exit_code, stderr), (0, ""))

            exit_code, stdout, stderr = _invoke(data_dir, "list", "creator")
            self.assertEqual((exit_code, stderr), (0, ""))
            self.assertIn(creator["id"], [item["id"] for item in json.loads(stdout)])

            exit_code, stdout, stderr = _invoke(data_dir, "match", demand["id"])
            self.assertEqual((exit_code, stderr), (0, ""))
            match_payload = json.loads(stdout)
            self.assertEqual(match_payload["demand_id"], demand["id"])
            self.assertGreater(match_payload["recommendation_id"], 0)
            self.assertTrue(match_payload["recommended"])

            with sqlite3.connect(str(database)) as connection:
                row = connection.execute(
                    """
                    SELECT input_snapshot_json
                    FROM recommendations
                    WHERE id = ?
                    """,
                    (match_payload["recommendation_id"],),
                ).fetchone()
            self.assertIsNotNone(row)
            snapshot = json.loads(row[0])
            self.assertEqual(snapshot["schema_version"], 1)
            self.assertEqual(snapshot["demand"]["schema_version"], 1)
            self.assertTrue(
                all(item["schema_version"] == 1 for item in snapshot["creators"])
            )


if __name__ == "__main__":
    unittest.main()
