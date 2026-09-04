"""Focused contracts for the private-server source-readiness bridge."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check_private_server_source_readiness.py"
SCHEMA = ROOT / "deploy/private-server-source-readiness-v1.schema.json"
WORKFLOW = ROOT / ".github/workflows/private-server-runtime-release.yml"
CI = ROOT / ".github/workflows/ci.yml"
RUNBOOK = ROOT / "docs/operations/private-server-runtime-release.md"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "private_server_source_readiness_test", SCRIPT
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("source-readiness module cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _git(repository: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ("git", "-C", str(repository), *arguments),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env={
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+00:00",
            "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+00:00",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        },
        timeout=30,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr.decode("utf-8", "replace"))
    return completed.stdout


class PrivateServerSourceReadinessTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = _load_module()

    def _repository(
        self,
        *,
        missing: str | None = None,
        link_target: str = "src/desire_platform/contracts",
        link_cycle: bool = False,
    ) -> Path:
        temporary = tempfile.TemporaryDirectory(prefix="desire-source-readiness-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve() / "repository"
        root.mkdir(mode=0o700)
        root.chmod(0o700)
        _git(root, "init", "--quiet")
        _git(root, "config", "user.name", "Source Readiness Test")
        _git(root, "config", "user.email", "source-readiness@example.invalid")
        for index, relative in enumerate(sorted(self.module.REQUIRED_TRACKED_PATHS)):
            if relative == missing:
                continue
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"fixture:{index}:{relative}\n".encode("utf-8"))
            path.chmod(0o644)
        contracts = root / "platform/src/desire_platform/contracts"
        contracts.mkdir(parents=True, exist_ok=True)
        (contracts / "schema.txt").write_bytes(b"contract\n")
        compatibility = root / "platform/contracts"
        compatibility.symlink_to(link_target)
        if link_cycle:
            (root / "platform/loop-a").symlink_to("loop-b")
            (root / "platform/loop-b").symlink_to("loop-a")
        _git(root, "add", "--all")
        _git(root, "commit", "--quiet", "--no-gpg-sign", "-m", "source")
        return root

    def test_clean_exact_head_is_bound_without_mutating_git(self) -> None:
        repository = self._repository()
        before = _git(repository, "status", "--porcelain=v1", "-z")

        first = self.module.check_repository(repository)
        second = self.module.check_repository(repository)

        self.assertEqual(before, b"")
        self.assertEqual(_git(repository, "status", "--porcelain=v1", "-z"), b"")
        self.assertFalse((repository / ".git/index.lock").exists())
        self.assertEqual(first, second)
        self.assertTrue((repository / "platform/contracts").is_symlink())
        self.assertEqual(
            set(first),
            {
                "authority",
                "ci_verified",
                "execution_permitted",
                "format",
                "git_object_format",
                "head",
                "head_tree",
                "member_count",
                "production_authorized",
                "remote_ref_verified",
                "source_bytes",
                "source_sha256",
                "status",
                "working_tree",
            },
        )
        self.assertEqual(first["status"], self.module.READY_STATUS)
        self.assertEqual(first["working_tree"], "EXACT_HEAD")
        self.assertEqual(first["authority"], "NOT_AUTHORITY")
        self.assertFalse(first["ci_verified"])
        self.assertFalse(first["remote_ref_verified"])
        self.assertFalse(first["execution_permitted"])
        self.assertFalse(first["production_authorized"])
        self.assertRegex(first["source_sha256"], r"^[0-9a-f]{64}$")

    def test_tracked_and_untracked_changes_are_both_dirty_without_path_reflection(self) -> None:
        for kind in ("tracked", "untracked"):
            with self.subTest(kind=kind):
                repository = self._repository()
                secret_marker = "sensitive-marker-must-not-be-reflected"
                if kind == "tracked":
                    target = repository / sorted(self.module.REQUIRED_TRACKED_PATHS)[0]
                    target.write_text(secret_marker, encoding="utf-8")
                else:
                    (repository / "untracked-private-value.txt").write_text(
                        secret_marker, encoding="utf-8"
                    )
                with self.assertRaises(self.module.SourceReadinessError) as raised:
                    self.module.check_repository(repository)
                self.assertEqual(raised.exception.code, self.module.DIRTY)
                self.assertNotIn(secret_marker, str(raised.exception))

    def test_every_required_path_must_be_a_tracked_head_blob(self) -> None:
        missing = "Dockerfile"
        repository = self._repository(missing=missing)
        with self.assertRaises(self.module.SourceReadinessError) as raised:
            self.module.check_repository(repository)
        self.assertEqual(raised.exception.code, self.module.REQUIRED_PATHS_MISSING)
        self.assertNotIn(missing, str(raised.exception))

    def test_blob_or_mode_mismatch_is_rejected_even_if_status_is_forged_clean(self) -> None:
        repository = self._repository()
        target = repository / "Dockerfile"
        target.write_bytes(b"different worktree bytes\n")
        with mock.patch.object(self.module, "_worktree_status", return_value=b""):
            with self.assertRaises(self.module.SourceReadinessError) as raised:
                self.module.check_repository(repository)
        self.assertEqual(raised.exception.code, self.module.SOURCE_MISMATCH)

    def test_symlink_target_mismatch_escape_dangling_and_cycle_are_rejected(self) -> None:
        mismatched = self._repository()
        compatibility = mismatched / "platform/contracts"
        compatibility.unlink()
        compatibility.symlink_to("src/desire_platform")
        with mock.patch.object(self.module, "_worktree_status", return_value=b""):
            with self.assertRaises(self.module.SourceReadinessError) as raised:
                self.module.check_repository(mismatched)
        self.assertEqual(raised.exception.code, self.module.SOURCE_MISMATCH)

        for label, target, cycle in (
            ("escape", "../../../outside", False),
            ("dangling", "src/desire_platform/missing", False),
            ("cycle", "src/desire_platform/contracts", True),
        ):
            with self.subTest(label=label):
                repository = self._repository(
                    link_target=target,
                    link_cycle=cycle,
                )
                with self.assertRaises(self.module.SourceReadinessError) as raised:
                    self.module.check_repository(repository)
                self.assertEqual(raised.exception.code, self.module.SOURCE_MISMATCH)

    def test_optional_receipt_is_outside_repo_exclusive_and_mode_0600(self) -> None:
        repository = self._repository()
        document = self.module.check_repository(repository)
        raw = self.module._canonical(document)
        output_parent = repository.parent / "receipts"
        output_parent.mkdir(mode=0o700)
        output_parent.chmod(0o700)
        output = output_parent / "source-readiness.json"

        self.module._write_new_receipt(output, repository, raw)

        self.assertEqual(output.read_bytes(), raw)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        with self.assertRaises(self.module.SourceReadinessError) as raised:
            self.module._write_new_receipt(output, repository, b"replacement\n")
        self.assertEqual(raised.exception.code, self.module.OUTPUT_INVALID)
        self.assertEqual(output.read_bytes(), raw)
        inside_parent = repository / "receipts"
        inside_parent.mkdir(mode=0o700)
        inside_parent.chmod(0o700)
        with self.assertRaises(self.module.SourceReadinessError):
            self.module._write_new_receipt(
                inside_parent / "forbidden.json", repository, raw
            )

    def test_cli_failure_is_stable_non_reflective_and_never_checks_current_dirty_repo(self) -> None:
        marker = "raw-sensitive-cli-value"
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = self.module.main(
                ("--unknown", marker), stdout=stdout, stderr=stderr
            )
        self.assertEqual(status, 78)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            json.loads(stderr.getvalue()),
            {"code": self.module.INVALID, "status": "BLOCKED"},
        )
        self.assertNotIn(marker, stderr.getvalue())

    def test_schema_workflows_and_runbook_bind_the_gate_without_granting_authority(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        properties = schema["properties"]
        self.assertEqual(properties["status"]["const"], self.module.READY_STATUS)
        self.assertEqual(properties["authority"]["const"], "NOT_AUTHORITY")
        self.assertFalse(properties["ci_verified"]["const"])
        self.assertFalse(properties["remote_ref_verified"]["const"])
        self.assertFalse(properties["execution_permitted"]["const"])
        self.assertFalse(properties["production_authorized"]["const"])
        invocation = "python -B scripts/check_private_server_source_readiness.py"
        self.assertIn(invocation, WORKFLOW.read_text(encoding="utf-8"))
        self.assertIn(invocation, CI.read_text(encoding="utf-8"))
        runbook = RUNBOOK.read_text(encoding="utf-8")
        self.assertIn("SOURCE_READINESS_VERIFIED_NOT_AUTHORITY", runbook)
        self.assertIn("PRIVATE_SERVER_SOURCE_READINESS_DIRTY", runbook)
        self.assertIn("private-server-source-readiness-v1.schema.json", runbook)
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            "- name: Verify the current-head v29 static contract",
            workflow,
        )
        self.assertIn(
            "python -B scripts/verify_current_head_v29.py",
            workflow,
        )
        ci = CI.read_text(encoding="utf-8")
        v17 = "python -B scripts/verify_current_head_v17.py"
        v18 = "python -B scripts/verify_current_head_v18.py"
        v19 = "python -B scripts/verify_current_head_v19.py"
        v20 = "python -B scripts/verify_current_head_v20.py"
        v21 = "python -B scripts/verify_current_head_v21.py"
        v22 = "python -B scripts/verify_current_head_v22.py"
        v23 = "python -B scripts/verify_current_head_v23.py"
        v24 = "python -B scripts/verify_current_head_v24.py"
        v25 = "python -B scripts/verify_current_head_v25.py"
        v26 = "python -B scripts/verify_current_head_v26.py"
        v27 = "python -B scripts/verify_current_head_v27.py"
        v29 = "python -B scripts/verify_current_head_v29.py"
        self.assertEqual(ci.count(v17), 0)
        self.assertEqual(ci.count(v18), 0)
        self.assertEqual(ci.count(v19), 0)
        self.assertEqual(ci.count(v20), 0)
        self.assertEqual(ci.count(v21), 0)
        self.assertEqual(ci.count(v22), 0)
        self.assertEqual(ci.count(v23), 0)
        self.assertEqual(ci.count(v24), 0)
        self.assertEqual(ci.count(v25), 0)
        self.assertEqual(ci.count(v26), 0)
        self.assertEqual(ci.count(v27), 0)
        self.assertEqual(ci.count(v29), 1)
        for relative in (
            "docs/operations/current-head-v16.md",
            "docs/operations/current-head-v17.md",
            "docs/operations/current-head-v18.md",
            "docs/operations/current-head-v19.md",
            "docs/operations/current-head-v20.md",
            "docs/operations/current-head-v21.md",
            "docs/operations/current-head-v22.md",
            "docs/operations/current-head-v23.md",
            "docs/operations/current-head-v24.md",
            "docs/operations/current-head-v25.md",
            "docs/operations/current-head-v26.md",
            "docs/operations/current-head-v27.md",
            "deploy/postgres-backup-restore.sh",
            "deploy/postgres-core-facts.sql",
            "deploy/postgres-operations.compose.yaml",
            "deploy/postgres-backup-restore-v25.sh",
            "deploy/postgres-core-facts-v25.sql",
            "deploy/postgres-operations-v25.compose.yaml",
            "deploy/postgres-backup-restore-v26.sh",
            "deploy/postgres-core-facts-v26.sql",
            "deploy/postgres-operations-v26.compose.yaml",
            "deploy/postgres-backup-restore-v27.sh",
            "deploy/postgres-core-facts-v27.sql",
            "deploy/postgres-operations-v27.compose.yaml",
            "scripts/verify_current_head_v16.py",
            "scripts/verify_current_head_v17.py",
            "scripts/verify_current_head_v18.py",
            "scripts/verify_current_head_v19.py",
            "scripts/verify_current_head_v20.py",
            "scripts/verify_current_head_v21.py",
            "scripts/verify_current_head_v22.py",
            "scripts/verify_current_head_v23.py",
            "scripts/verify_current_head_v24.py",
            "scripts/verify_current_head_v25.py",
            "scripts/verify_current_head_v26.py",
            "scripts/verify_current_head_v27.py",
            "tests/deployment/fixtures/current-head-v16/demand-manifest.json",
            "tests/deployment/fixtures/current-head-v16/trust-manifest.json",
            "tests/deployment/fixtures/current-head-v16/trust-runner-pins.txt",
            "tests/deployment/fixtures/current-head-v17/demand-manifest.json",
            "tests/deployment/fixtures/current-head-v17/trust-manifest.json",
            "tests/deployment/fixtures/current-head-v17/trust-runner-pins.txt",
            "tests/deployment/fixtures/current-head-v18/iam-manifest.json",
            "tests/deployment/fixtures/current-head-v18/demand-manifest.json",
            "tests/deployment/fixtures/current-head-v18/trust-manifest.json",
            "tests/deployment/fixtures/current-head-v18/trust-runner-pins.txt",
            "tests/deployment/fixtures/current-head-v19/iam-manifest.json",
            "tests/deployment/fixtures/current-head-v19/demand-manifest.json",
            "tests/deployment/fixtures/current-head-v19/trust-manifest.json",
            "tests/deployment/fixtures/current-head-v19/trust-runner-pins.txt",
            "tests/deployment/fixtures/current-head-v20/iam-manifest.json",
            "tests/deployment/fixtures/current-head-v20/demand-manifest.json",
            "tests/deployment/fixtures/current-head-v20/trust-manifest.json",
            "tests/deployment/fixtures/current-head-v20/trust-runner-pins.txt",
            "tests/deployment/fixtures/current-head-v21/iam-manifest.json",
            "tests/deployment/fixtures/current-head-v21/demand-manifest.json",
            "tests/deployment/fixtures/current-head-v21/trust-manifest.json",
            "tests/deployment/fixtures/current-head-v21/trust-runner-pins.txt",
            "tests/deployment/fixtures/current-head-v22/iam-manifest.json",
            "tests/deployment/fixtures/current-head-v22/demand-manifest.json",
            "tests/deployment/fixtures/current-head-v22/trust-manifest.json",
            "tests/deployment/fixtures/current-head-v22/trust-runner-pins.txt",
            "tests/deployment/fixtures/current-head-v23/iam-manifest.json",
            "tests/deployment/fixtures/current-head-v23/demand-manifest.json",
            "tests/deployment/fixtures/current-head-v23/trust-manifest.json",
            "tests/deployment/fixtures/current-head-v23/trust-runner-pins.txt",
            "tests/deployment/fixtures/current-head-v24/iam-manifest.json",
            "tests/deployment/fixtures/current-head-v24/demand-manifest.json",
            "tests/deployment/fixtures/current-head-v24/trust-manifest.json",
            "tests/deployment/fixtures/current-head-v24/trust-runner-pins.txt",
            "tests/deployment/fixtures/current-head-v25/iam-manifest.json",
            "tests/deployment/fixtures/current-head-v25/demand-manifest.json",
            "tests/deployment/fixtures/current-head-v25/trust-manifest.json",
            "tests/deployment/fixtures/current-head-v25/trust-runner-pins.txt",
            "tests/deployment/fixtures/current-head-v26/iam-manifest.json",
            "tests/deployment/fixtures/current-head-v26/demand-manifest.json",
            "tests/deployment/fixtures/current-head-v26/trust-manifest.json",
            "tests/deployment/fixtures/current-head-v26/trust-runner-pins.txt",
            "tests/deployment/fixtures/current-head-v27/schema-pins.json",
            "tests/deployment/test_current_head_v16_contract.py",
            "tests/deployment/test_current_head_v17_contract.py",
            "tests/deployment/test_current_head_v18_contract.py",
            "tests/deployment/test_current_head_v19_contract.py",
            "tests/deployment/test_current_head_v20_contract.py",
            "tests/deployment/test_current_head_v21_contract.py",
            "tests/deployment/test_current_head_v22_contract.py",
            "tests/deployment/test_current_head_v23_contract.py",
            "tests/deployment/test_current_head_v24_contract.py",
            "tests/deployment/test_current_head_v25_contract.py",
            "tests/deployment/test_current_head_v26_contract.py",
            "tests/deployment/test_current_head_v27_contract.py",
            "tests/deployment/test_postgres_operations_v25.py",
            "tests/deployment/test_postgres_operations_v26.py",
            "tests/deployment/test_postgres_operations_v27.py",
        ):
            self.assertIn(relative, self.module.REQUIRED_TRACKED_PATHS)

    def test_module_has_no_network_docker_or_git_mutation_capability(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for forbidden in (
            "import socket",
            "import urllib",
            "import requests",
            "docker.from_env",
            "os.remove(",
            "os.unlink(",
            "shutil.rmtree(",
            '"add",',
            '"commit",',
            '"push",',
            '"checkout",',
            '"reset",',
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
