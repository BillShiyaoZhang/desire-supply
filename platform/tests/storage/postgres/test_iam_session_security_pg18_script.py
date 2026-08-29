from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = PLATFORM_ROOT / "scripts/test_iam_session_security_pg18.sh"


class IamSessionSecurityPg18ScriptTest(unittest.TestCase):
    def test_script_is_syntax_valid_and_uses_an_isolated_pinned_pg18(self) -> None:
        completed = subprocess.run(
            ("/bin/sh", "-n", str(SCRIPT)),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout)
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("postgres:18.4-alpine@sha256:", source)
        self.assertIn("--publish 127.0.0.1::5432", source)
        self.assertIn("DESIRE_IAM_TEST_POSTGRES_EPHEMERAL=1", source)
        self.assertIn(
            "test_iam_http_session_security_postgres_red.py",
            source,
        )
        self.assertIn("docker rm --force \"$container_id\"", source)
        self.assertNotIn("docker compose", source)
        self.assertNotIn("docker volume", source)

    def test_external_ephemeral_pg18_dsn_runs_the_same_gate_without_docker(self) -> None:
        with tempfile.TemporaryDirectory(prefix="iam-0024-script-") as temporary:
            root = Path(temporary)
            capture = root / "arguments.txt"
            fake_python = root / "python"
            fake_python.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$@\" > \"$IAM_0024_TEST_CAPTURE\"\n",
                encoding="utf-8",
            )
            fake_python.chmod(0o700)
            environment = dict(os.environ)
            environment.update(
                {
                    "DESIRE_PLATFORM_TEST_PYTHON": str(fake_python),
                    "DESIRE_IAM_TEST_POSTGRES_DSN": (
                        "postgresql://ephemeral-admin:secret@127.0.0.1:6543/postgres"
                    ),
                    "DESIRE_IAM_TEST_POSTGRES_EPHEMERAL": "1",
                    "IAM_0024_TEST_CAPTURE": str(capture),
                }
            )
            completed = subprocess.run(
                ("/bin/sh", str(SCRIPT)),
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=environment,
            )
            captured_arguments = (
                capture.read_text(encoding="utf-8") if capture.is_file() else ""
            )
        self.assertEqual(completed.returncode, 0, completed.stdout)
        self.assertIn(
            "tests/storage/postgres/test_iam_http_session_security_postgres_red.py",
            captured_arguments,
        )
        self.assertNotIn("secret", completed.stdout)

    def test_external_pg18_dsn_requires_explicit_ephemeral_acknowledgement(self) -> None:
        environment = dict(os.environ)
        environment.update(
            {
                "DESIRE_IAM_TEST_POSTGRES_DSN": (
                    "postgresql://ephemeral-admin:secret@127.0.0.1:6543/postgres"
                ),
                "DESIRE_IAM_TEST_POSTGRES_EPHEMERAL": "0",
            }
        )
        completed = subprocess.run(
            ("/bin/sh", str(SCRIPT)),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=environment,
        )
        self.assertEqual(completed.returncode, 78, completed.stdout)
        self.assertIn("IAM_0024_TEST_EXTERNAL_POSTGRES_NOT_EPHEMERAL", completed.stdout)
        self.assertNotIn("secret", completed.stdout)

    def test_unavailable_docker_fails_with_a_stable_closed_result(self) -> None:
        with tempfile.TemporaryDirectory(prefix="iam-0024-no-docker-") as temporary:
            root = Path(temporary)
            fake_docker = root / "docker"
            fake_docker.write_text("#!/bin/sh\nexit 42\n", encoding="utf-8")
            fake_docker.chmod(0o700)
            environment = dict(os.environ)
            environment.pop("DESIRE_IAM_TEST_POSTGRES_DSN", None)
            environment.pop("DESIRE_IAM_TEST_POSTGRES_EPHEMERAL", None)
            environment["PATH"] = str(root) + os.pathsep + environment["PATH"]
            completed = subprocess.run(
                ("/bin/sh", str(SCRIPT)),
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=environment,
            )
        self.assertEqual(completed.returncode, 69, completed.stdout)
        self.assertEqual(
            completed.stdout.strip(),
            '{"code":"IAM_0024_TEST_POSTGRES_UNAVAILABLE","status":"BLOCKED"}',
        )


if __name__ == "__main__":
    unittest.main()
