"""Credential lifecycle boundaries, using no live database or real secrets."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
import io
from pathlib import Path
import re
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("prepare_local_matching_workflow", ROOT / "scripts/prepare_local_matching_workflow.py")
workflow = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(workflow)
NOW = datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc)


class _Connection:
    def __init__(self):
        self.statements = []
        self.password_changes = []
        self.password = None
        self.expiry = None
        self.memberships = 0
        self.role_flags = (workflow.SYSTEM_ROLE, True, False, False, False, False, False)
        self.pgconn = SimpleNamespace(change_password=self.change_password)
        self.commit_ack_lost = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def change_password(self, role, material):
        self.password_changes.append(role)
        self.password = bytes(material)

    def execute(self, query, parameters=None):
        query = query if isinstance(query, str) else query.as_string()
        self.statements.append(query)
        if "SELECT rolname,rolcanlogin" in query:
            result = self.role_flags
        elif "pg_auth_members" in query:
            result = (self.memberships,)
        elif "rolpassword IS NOT NULL" in query:
            result = (self.password is not None, self.password is not None, self.expiry)
        else:
            result = None
        if query.startswith("ALTER ROLE"):
            self.expiry = datetime.fromisoformat(re.search(r"VALID UNTIL '([^']+)'", query)[1])
        if query == "COMMIT" and self.commit_ack_lost:
            self.commit_ack_lost = False
            raise RuntimeError("simulated acknowledgement loss")
        return SimpleNamespace(fetchone=lambda: result)


class _Login:
    def __init__(self, role):
        self.role = role

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, query):
        return SimpleNamespace(fetchone=lambda: (self.role, self.role, "desire", 18,
            True, False, False, False, False, False))


class LocalMatchingWorkflowCredentialTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="workflow-credentials-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir(mode=0o700)
        for index, name in enumerate(workflow.SOURCE_FILES):
            path = self.source / name
            path.write_bytes(bytes([65 + index]) * 48)
            path.chmod(0o600)
        self.output = self.root / "workflow-secrets"
        self.connection = _Connection()
        self.settings = SimpleNamespace(host="db", port=5432, database="desire", admin_password="Z" * 48)
        self.logins = []
        self.dbapi = SimpleNamespace(connect=self.connect)
        from desire_platform.deployment import migrations
        for name in ("_assert_admin_preflight", "_acquire_provisioning_lock", "_release_provisioning_lock", "_verify_catalogs"):
            patcher = patch.object(migrations, name)
            patcher.start()
            self.addCleanup(patcher.stop)
        admin = patch.object(migrations, "_admin_connection", return_value=self.connection)
        admin.start()
        self.addCleanup(admin.stop)

    def connect(self, **fields):
        self.logins.append(fields["user"])
        if fields["user"] == workflow.SYSTEM_ROLE:
            if fields["password"].encode("ascii") != self.connection.password:
                raise RuntimeError("sensitive adapter detail must not escape")
        return _Login(fields["user"])

    def prepare(self):
        return workflow.prepare_credentials(source_directory=self.source, output_directory=self.output,
            settings=self.settings, now=NOW, dbapi=self.dbapi)

    def test_initial_prepare_and_repeat_preserve_files_and_only_change_one_password(self):
        self.assertFalse(self.prepare())
        original = {path.name: path.read_bytes() for path in self.output.iterdir()}
        self.assertEqual(set(original), set(workflow.CREDENTIAL_FILES))
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in self.output.iterdir()))
        for name in workflow.SOURCE_FILES:
            self.assertEqual(original[name], (self.source / name).read_bytes())
        self.assertTrue(self.prepare())
        self.assertEqual(original, {path.name: path.read_bytes() for path in self.output.iterdir()})
        self.assertEqual(self.connection.password_changes, [b"demand_system"])
        self.assertEqual(self.logins, ["demand_self", "trust_decision", "demand_system"] * 2)
        sql = "\n".join(self.connection.statements)
        for forbidden in ("GRANT", "CREATE ROLE", "pg_terminate_backend", "ALTER ROLE \"demand_self\"", "ALTER ROLE \"trust_decision\""):
            self.assertNotIn(forbidden, sql)

    def test_commit_acknowledgement_loss_retries_saved_material_without_rotation(self):
        self.connection.commit_ack_lost = True
        with self.assertRaises(RuntimeError):
            self.prepare()
        saved = (self.output / workflow.SYSTEM_FILE).read_bytes()
        self.assertTrue(self.prepare())
        self.assertEqual((self.output / workflow.SYSTEM_FILE).read_bytes(), saved)
        self.assertEqual(self.connection.password_changes, [b"demand_system"])

    def test_complete_files_before_uncommitted_failure_can_install_the_same_password(self):
        with patch.object(self.connection.pgconn, "change_password", side_effect=RuntimeError("temporary failure")):
            with self.assertRaises(RuntimeError):
                self.prepare()
        saved = (self.output / workflow.SYSTEM_FILE).read_bytes()
        self.assertIsNone(self.connection.password)
        self.assertFalse(self.prepare())
        self.assertEqual(self.connection.password, saved)

    def test_unmanaged_existing_password_is_never_overwritten(self):
        self.connection.password = b"external-existing-password-1234567890"
        self.connection.expiry = NOW + timedelta(days=10)
        with self.assertRaisesRegex(workflow.WorkflowCredentialError, "UNMANAGED"):
            self.prepare()
        self.assertFalse(self.output.exists())
        self.assertEqual(self.connection.password_changes, [])

    def test_role_membership_drift_blocks_before_files_or_password_change(self):
        self.connection.memberships = 1
        with self.assertRaisesRegex(workflow.WorkflowCredentialError, "ROLE_DRIFT"):
            self.prepare()
        self.assertFalse(self.output.exists())
        self.assertEqual(self.connection.password_changes, [])

    def test_changed_source_does_not_overwrite_an_existing_workflow_secret(self):
        self.prepare()
        original = (self.output / workflow.SOURCE_FILES[0]).read_bytes()
        (self.source / workflow.SOURCE_FILES[0]).write_bytes(b"changed" * 8)
        with self.assertRaisesRegex(workflow.WorkflowCredentialError, "SOURCE_CREDENTIAL_DRIFT"):
            self.prepare()
        self.assertEqual((self.output / workflow.SOURCE_FILES[0]).read_bytes(), original)
        self.assertEqual(self.connection.password_changes, [b"demand_system"])

    def test_wrong_saved_password_fails_login_without_rotation(self):
        self.prepare()
        (self.output / workflow.SYSTEM_FILE).write_bytes(b"incorrect" * 6)
        with self.assertRaisesRegex(workflow.WorkflowCredentialError, "LOGIN_FAILED"):
            self.prepare()
        self.assertEqual(self.connection.password_changes, [b"demand_system"])

    def test_symlink_and_group_readable_source_are_rejected_before_mutation(self):
        path = self.source / workflow.SOURCE_FILES[0]
        path.chmod(0o640)
        with self.assertRaises(workflow.WorkflowCredentialError):
            self.prepare()
        path.chmod(0o600)
        moved = self.source / "moved"
        path.rename(moved)
        path.symlink_to(moved)
        with self.assertRaises(OSError):
            self.prepare()
        self.assertEqual(self.connection.password_changes, [])

    def test_cli_sanitizes_unexpected_errors(self):
        output = io.StringIO()
        with patch("desire_platform.deployment.migrations.load_settings", side_effect=RuntimeError("do-not-print-credential")):
            with patch("sys.stdout", output):
                status = workflow.main(["--database", "desire", "--admin-password-file", "/run/secrets/admin",
                    "--source-secret-directory", str(self.source), "--output-directory", str(self.output)])
        self.assertEqual(status, 1)
        self.assertNotIn("do-not-print-credential", output.getvalue())
        self.assertIn("WORKFLOW_CREDENTIAL_PREPARATION_FAILED", output.getvalue())


if __name__ == "__main__":
    unittest.main()
