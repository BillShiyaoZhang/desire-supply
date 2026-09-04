"""Exercise local lifecycle decisions without accessing a real Docker daemon."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SERVICES = ["db", "synthetic-oidc", "edge", "api", "matching-runtime", "web"]


class DockerLocalLifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="desire-docker-local-")
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name).resolve()
        (self.repo / "scripts").mkdir()
        self.script = self.repo / "scripts/docker-local.sh"
        shutil.copyfile(ROOT / "scripts/docker-local.sh", self.script)
        self.state = self.repo / ".local/desire-supply-local"
        self.state.mkdir(parents=True)
        (self.state / "initialized").touch()
        self.log = self.repo / "calls.jsonl"
        self.environment = {
            **os.environ,
            "PATH": f"{self.repo}:{os.environ['PATH']}",
            "FAKE_DOCKER_LOG": str(self.log),
            "DESIRE_LOCAL_PROJECT": "desire-supply-local",
        }
        fake = self.repo / "docker"
        fake.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            "args = sys.argv[1:]\n"
            "with open(os.environ['FAKE_DOCKER_LOG'], 'a') as stream:\n"
            "    stream.write(json.dumps({'args': args, 'password_file': os.environ.get('DESIRE_DB_PASSWORD_FILE'), 'image_tag': os.environ.get('DESIRE_IMAGE_TAG')}) + '\\n')\n"
            "if '--quiet' in args and 'ps' in args and args[-1] != os.environ.get('FAKE_MISSING_SERVICE'):\n"
            "    print('existing-container-' + args[-1])\n"
            "if 'up' in args and args[-1] == os.environ.get('FAKE_UNHEALTHY_SERVICE'):\n"
            "    sys.exit(1)\n"
        )
        fake.chmod(0o755)

    def run_local(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", str(self.script), *arguments],
            cwd=self.repo,
            env=self.environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def calls(self) -> list[dict]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_repeated_init_preserves_credentials_without_running_docker(self) -> None:
        credential = self.state / "db_superuser_password.txt"
        credential.write_text("already-initialized-secret")
        result = self.run_local("init")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(credential.read_text(), "already-initialized-secret")
        self.assertEqual(self.calls(), [])

    def test_resume_waits_for_dependencies_without_rerunning_initialization(self) -> None:
        (self.state / "started").touch()
        result = self.run_local("up")
        self.assertEqual(result.returncode, 0, result.stderr)
        starts = [call["args"] for call in self.calls() if "up" in call["args"]]
        self.assertEqual([args[-1] for args in starts], SERVICES)
        for args in starts:
            for flag in ("--no-deps", "--no-recreate", "--no-build", "--wait"):
                self.assertIn(flag, args)

    def test_missing_container_blocks_resume_before_starting_anything(self) -> None:
        (self.state / "started").touch()
        self.environment["FAKE_MISSING_SERVICE"] = "api"
        self.assertNotEqual(self.run_local("up").returncode, 0)
        self.assertFalse(any("up" in call["args"] for call in self.calls()))

    def test_failed_database_readiness_prevents_starting_dependents(self) -> None:
        (self.state / "started").touch()
        self.environment["FAKE_UNHEALTHY_SERVICE"] = "db"
        self.assertNotEqual(self.run_local("up").returncode, 0)
        starts = [call["args"][-1] for call in self.calls() if "up" in call["args"]]
        self.assertEqual(starts, ["db"])

    def test_incomplete_first_start_is_not_automatically_replayed(self) -> None:
        (self.state / "start-attempted").touch()
        self.assertNotEqual(self.run_local("up").returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_stop_preserves_volumes_and_clears_other_deployment_pointers(self) -> None:
        self.environment["DESIRE_DB_PASSWORD_FILE"] = "/other/deployment/password"
        self.environment["DESIRE_IMAGE_TAG"] = "other-deployment"
        self.assertEqual(self.run_local("stop").returncode, 0)
        call, = self.calls()
        self.assertEqual(call["args"][-1], "stop")
        self.assertNotIn("--volumes", call["args"])
        self.assertIsNone(call["password_file"])
        self.assertIsNone(call["image_tag"])
        self.assertIn(str(self.state / "compose.env"), call["args"])

    def test_development_uses_its_own_project_and_database_password(self) -> None:
        self.assertEqual(self.run_local("dev-status").returncode, 0)
        call, = self.calls()
        self.assertIn("desire-supply-local-dev", call["args"])
        self.assertEqual(call["password_file"], str(self.state / "dev-db-password"))

    def test_matching_keeps_admin_credentials_out_of_business_command(self) -> None:
        result = self.run_local("match", "organization-id", "demand-id", "15", "request-id")
        self.assertEqual(result.returncode, 0, result.stderr)
        provision, command = [call["args"] for call in self.calls()]
        self.assertIn("/tools/prepare_local_matching_workflow.py", provision)
        self.assertIn("desire_platform.internal_pilot.matching_workflow", command)
        self.assertEqual(command[command.index("--organization-id") + 1], "organization-id")
        self.assertEqual(command[command.index("--request-id") + 1], "request-id")
        self.assertFalse(any("superuser" in value or "runtime-secrets" in value for value in command))
        mounts = [command[index + 1] for index, value in enumerate(command) if value == "--mount"]
        self.assertEqual(len(mounts), 1)
        self.assertIn("workflow-secrets", mounts[0])
        self.assertTrue(mounts[0].endswith(",readonly"))

    def test_matching_requires_an_exact_target_before_any_provisioning(self) -> None:
        self.assertNotEqual(self.run_local("match", "demand-id").returncode, 0)
        self.assertEqual(self.calls(), [])


if __name__ == "__main__":
    unittest.main()
