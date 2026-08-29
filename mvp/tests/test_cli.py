import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from desire_mvp.cli import main
from desire_mvp.repository import Repository

from helpers import ROOT, load_sample


class CliImportTests(unittest.TestCase):
    def invoke(self, data_dir, kind, import_path):
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
                        "import",
                        kind,
                        str(import_path),
                    ]
                )
            except SystemExit as exc:
                return exc.code, stdout.getvalue(), stderr.getvalue()
        return 0, stdout.getvalue(), stderr.getvalue()

    def assert_rejected_batch_writes_nothing(self, records, private_value=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "data"
            import_path = root / "creators.json"
            import_path.write_text(
                json.dumps(records, ensure_ascii=False),
                encoding="utf-8",
            )

            stderr = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as raised:
                    main(
                        [
                            "--data-dir",
                            str(data_dir),
                            "--config-dir",
                            str(ROOT / "config"),
                            "import",
                            "creator",
                            str(import_path),
                        ]
                    )
            self.assertEqual(raised.exception.code, 2)
            if private_value is not None:
                self.assertNotIn(str(private_value), stderr.getvalue())

            repository = Repository(data_dir)
            repository.initialize()
            self.assertEqual(repository.list_entities("creator"), [])

    def test_batch_import_with_later_identity_field_writes_nothing(self):
        records = [load_sample("creators.json")[0], load_sample("creators.json")[1]]
        records[1]["contact"] = {"email": "person@example.invalid"}
        self.assert_rejected_batch_writes_nothing(records)

    def test_batch_import_with_later_unknown_taxonomy_writes_nothing(self):
        records = [load_sample("creators.json")[0], load_sample("creators.json")[1]]
        records[1]["skills"][0]["tag"] = "unknown-skill"
        self.assert_rejected_batch_writes_nothing(records)

    def test_batch_import_with_duplicate_id_writes_nothing(self):
        records = [load_sample("creators.json")[0], load_sample("creators.json")[1]]
        records[1]["id"] = records[0]["id"]
        self.assert_rejected_batch_writes_nothing(records)

    def test_batch_import_rejects_non_string_id_without_disclosing_private_floor(self):
        records = [load_sample("creators.json")[0], load_sample("creators.json")[1]]
        records[1]["id"] = 42
        private_floor = records[1]["compensation"]["minimum_project"]
        self.assert_rejected_batch_writes_nothing(records, private_floor)

    def test_batch_import_error_does_not_echo_object_id_contents(self):
        records = [load_sample("creators.json")[0]]
        secret = "secret-id@example.invalid"
        records[0]["id"] = {"email": secret}
        self.assert_rejected_batch_writes_nothing(records, secret)

    def test_batch_import_error_does_not_echo_contact_like_string_id(self):
        records = [load_sample("creators.json")[0]]
        secret = "person@example.invalid"
        records[0]["id"] = secret
        self.assert_rejected_batch_writes_nothing(records, secret)

    def test_batch_import_error_does_not_echo_numeric_phone_id(self):
        records = [load_sample("creators.json")[0]]
        secret = "13800138000"
        records[0]["id"] = secret
        self.assert_rejected_batch_writes_nothing(records, secret)

    def test_failed_record_never_echoes_even_valid_looking_id(self):
        records = [load_sample("creators.json")[0]]
        public_looking_id = records[0]["id"]
        records[0]["skills"][0]["tag"] = "unknown-skill"
        self.assert_rejected_batch_writes_nothing(records, public_looking_id)

    def test_prohibited_field_path_cannot_echo_user_controlled_key(self):
        records = [load_sample("creators.json")[0]]
        private_key = records[0]["id"]
        records[0][private_key] = {"email": "hidden@example.invalid"}
        self.assert_rejected_batch_writes_nothing(records, private_key)

    def test_empty_batch_fails_without_creating_data_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "data"
            import_path = root / "empty.json"
            import_path.write_text("[]", encoding="utf-8")
            exit_code, _, _ = self.invoke(data_dir, "creator", import_path)
            self.assertEqual(exit_code, 2)
            self.assertFalse(data_dir.exists())

    def test_valid_batch_preserves_id_order_and_persists_every_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "data"
            import_path = root / "creators.json"
            records = [load_sample("creators.json")[1], load_sample("creators.json")[0]]
            import_path.write_text(json.dumps(records), encoding="utf-8")
            exit_code, stdout, stderr = self.invoke(data_dir, "creator", import_path)
            self.assertEqual((exit_code, stderr), (0, ""))
            payload = json.loads(stdout)
            self.assertEqual(payload["imported"], [records[0]["id"], records[1]["id"]])
            self.assertEqual(payload["count"], 2)
            self.assertEqual(len(Repository(data_dir).list_entities("creator")), 2)

    def test_unconfirmed_demand_can_be_saved_as_not_match_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "data"
            import_path = root / "demand.json"
            demand = load_sample("demands.json")[0]
            demand["decision_authority_confirmed"] = False
            demand["funding_commitment"] = False
            import_path.write_text(json.dumps(demand), encoding="utf-8")
            exit_code, _, stderr = self.invoke(data_dir, "demand", import_path)
            self.assertEqual((exit_code, stderr), (0, ""))
            self.assertEqual(
                Repository(data_dir).get_entity("demand", demand["id"])["funding_commitment"],
                False,
            )

    def test_failed_batch_does_not_overwrite_existing_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "data"
            repository = Repository(data_dir)
            repository.initialize()
            existing = load_sample("creators.json")[0]
            repository.put_entity("creator", existing)

            changed = load_sample("creators.json")[0]
            changed["availability"]["weekly_hours"] = 99
            invalid = load_sample("creators.json")[1]
            invalid["skills"][0]["tag"] = "unknown-skill"
            import_path = root / "creators.json"
            import_path.write_text(json.dumps([changed, invalid]), encoding="utf-8")
            exit_code, _, _ = self.invoke(data_dir, "creator", import_path)
            self.assertEqual(exit_code, 2)
            self.assertEqual(repository.get_entity("creator", existing["id"]), existing)


class CliOutcomePrivacyTests(unittest.TestCase):
    def test_failed_outcome_never_echoes_invalid_project_id(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "data"
            outcome_path = root / "outcome.json"
            secret = "person@example.invalid"
            outcome = load_sample("outcome.json")
            outcome["project_id"] = secret
            outcome_path.write_text(json.dumps(outcome), encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()

            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as raised:
                    main(
                        [
                            "--data-dir",
                            str(data_dir),
                            "--config-dir",
                            str(ROOT / "config"),
                            "outcome",
                            secret,
                            "--file",
                            str(outcome_path),
                        ]
                    )

            self.assertEqual(raised.exception.code, 2)
            self.assertNotIn(secret, stdout.getvalue() + stderr.getvalue())
            self.assertFalse(data_dir.exists())


if __name__ == "__main__":
    unittest.main()
