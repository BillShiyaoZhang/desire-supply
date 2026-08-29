"""Deterministic, object-only source snapshot contracts for runtime release."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zlib


ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = ROOT / "scripts/private_server_runtime_release_source.py"
SPEC = importlib.util.spec_from_file_location("private_server_runtime_release_source", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
SOURCE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SOURCE
SPEC.loader.exec_module(SOURCE)


def _git(repository: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env={
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        },
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr.decode("utf-8", "replace"))
    return completed.stdout


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


class RuntimeReleaseSourceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        os.chmod(self.root, 0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _repository(
        self,
        label: str = "repository",
        *,
        link_target: str = "src/desire_platform/contracts",
        link_cycle: bool = False,
    ) -> Path:
        repository = self.root / label
        repository.mkdir(mode=0o755)
        _git(repository, "init", "--quiet")
        _git(repository, "config", "user.name", "Release Test")
        _git(repository, "config", "user.email", "release@example.invalid")
        (repository / "Dockerfile").write_bytes(b"FROM scratch\n")
        (repository / "alpha.txt").write_bytes(b"alpha from commit\n")
        (repository / "binary.dat").write_bytes(b"\x00\xff\x80source-bytes\n")
        (repository / "bin").mkdir()
        executable = repository / "bin/run"
        executable.write_bytes(b"#!/bin/sh\nexit 0\n")
        executable.chmod(0o755)
        (repository / "docs").mkdir()
        (repository / "docs/\N{LATIN SMALL LETTER E WITH ACUTE}.txt").write_bytes(
            b"nfc path\n"
        )
        long_directory = repository / ("p" * 80)
        long_directory.mkdir()
        (long_directory / (("n" * 30) + ".txt")).write_bytes(b"ustar split\n")
        contracts = repository / "platform/src/desire_platform/contracts"
        contracts.mkdir(parents=True)
        (contracts / "schema.txt").write_bytes(b"contract\n")
        (repository / "platform/contracts").symlink_to(link_target)
        if link_cycle:
            (repository / "platform/loop-a").symlink_to("loop-b")
            (repository / "platform/loop-b").symlink_to("loop-a")
        _git(repository, "add", "--all")
        _git(repository, "commit", "--quiet", "--no-gpg-sign", "-m", "source")
        return repository

    def _commit(self, repository: Path) -> str:
        return _git(repository, "rev-parse", "HEAD").decode("ascii").strip()

    def _outputs(self, label: str = "output") -> dict[str, Path]:
        directory = self.root / label
        directory.mkdir(mode=0o700)
        return {
            "snapshot_output": directory / "source.tar",
            "context_output": directory / "context",
            "dockerfile_set_output": directory / "dockerfiles.json",
            "facts_output": directory / "facts.json",
        }

    def _create(
        self,
        repository: Path,
        commit: str,
        label: str = "output",
    ) -> tuple[object, dict[str, Path]]:
        outputs = self._outputs(label)
        result = SOURCE.create_source_snapshot(
            repository=repository,
            commit=commit,
            **outputs,
        )
        return result, outputs

    def _hash_object(self, repository: Path, kind: str, raw: bytes) -> str:
        stored = kind.encode("ascii") + b" " + str(len(raw)).encode("ascii") + b"\x00" + raw
        object_id = hashlib.sha1(stored).hexdigest()
        object_directory = repository / ".git/objects" / object_id[:2]
        object_directory.mkdir(mode=0o755, exist_ok=True)
        object_path = object_directory / object_id[2:]
        if not object_path.exists():
            object_path.write_bytes(zlib.compress(stored))
        return object_id

    def _raw_commit(self, repository: Path, tree_id: str) -> str:
        raw = (
            f"tree {tree_id}\n"
            "author Release Test <release@example.invalid> 0 +0000\n"
            "committer Release Test <release@example.invalid> 0 +0000\n"
            "\nsource\n"
        ).encode("ascii")
        return self._hash_object(repository, "commit", raw)

    def _tree_with_entry(
        self,
        repository: Path,
        *,
        mode: bytes,
        name: bytes,
        object_id: str | None = None,
    ) -> str:
        dockerfile_id = self._hash_object(repository, "blob", b"FROM scratch\n")
        target_id = object_id or self._hash_object(repository, "blob", b"unsafe\n")
        raw = (
            b"100644 Dockerfile\x00"
            + bytes.fromhex(dockerfile_id)
            + mode
            + b" "
            + name
            + b"\x00"
            + bytes.fromhex(target_id)
        )
        tree_id = self._hash_object(repository, "tree", raw)
        return self._raw_commit(repository, tree_id)

    def test_exact_commit_creates_canonical_ustar_context_dockerfiles_and_facts(self) -> None:
        repository = self._repository()
        commit = self._commit(repository)
        committed_dockerfile = (repository / "Dockerfile").read_bytes()
        (repository / "Dockerfile").write_bytes(b"FROM dirty-worktree\n")
        (repository / "untracked-secret.txt").write_bytes(b"must not appear\n")

        result, outputs = self._create(repository, commit)

        snapshot = outputs["snapshot_output"].read_bytes()
        facts_raw = outputs["facts_output"].read_bytes()
        dockerfile_set_raw = outputs["dockerfile_set_output"].read_bytes()
        facts = json.loads(facts_raw)
        dockerfile_digest = hashlib.sha256(committed_dockerfile).hexdigest()
        expected_set = {
            slot: {"dockerfile_sha256": dockerfile_digest, "target": target}
            for slot, target in SOURCE.DOCKERFILE_TARGETS.items()
        }
        self.assertEqual(dockerfile_set_raw, _canonical(expected_set))
        self.assertEqual(
            facts,
            {
                "commit": commit,
                "dockerfile_digest_set": {
                    "sha256": hashlib.sha256(dockerfile_set_raw).hexdigest(),
                    "size": len(dockerfile_set_raw),
                },
                "format": SOURCE.FORMAT,
                "snapshot": {
                    "member_count": result.member_count,
                    "sha256": hashlib.sha256(snapshot).hexdigest(),
                    "size": len(snapshot),
                },
                "tree_sha256": hashlib.sha256(
                    _git(repository, "cat-file", "tree", f"{commit}^{{tree}}")
                ).hexdigest(),
            },
        )
        self.assertEqual(facts_raw, _canonical(facts))
        self.assertEqual(result.raw, facts_raw)

        with tarfile.open(fileobj=io.BytesIO(snapshot), mode="r:") as archive:
            members = archive.getmembers()
            names = [member.name for member in members]
            self.assertEqual(names, sorted(names, key=lambda item: item.encode("utf-8")))
            self.assertNotIn("untracked-secret.txt", names)
            self.assertEqual(len(names), result.member_count)
            by_name = {member.name: member for member in members}
            self.assertEqual(by_name["Dockerfile"].mode, 0o644)
            self.assertEqual(by_name["bin"].mode, 0o755)
            self.assertTrue(by_name["bin"].isdir())
            self.assertEqual(by_name["bin/run"].mode, 0o755)
            self.assertTrue(by_name["platform/contracts"].issym())
            self.assertEqual(by_name["platform/contracts"].mode, 0o777)
            self.assertEqual(
                by_name["platform/contracts"].linkname,
                "src/desire_platform/contracts",
            )
            self.assertEqual(archive.extractfile("Dockerfile").read(), committed_dockerfile)
            for member in members:
                self.assertEqual(
                    (member.uid, member.gid, member.mtime, member.uname, member.gname),
                    (0, 0, 0, "", ""),
                )
                self.assertFalse(member.pax_headers)
                self.assertIn(
                    member.type,
                    (tarfile.REGTYPE, tarfile.DIRTYPE, tarfile.SYMTYPE),
                )
                self.assertEqual(snapshot[member.offset + 257 : member.offset + 265], b"ustar\x0000")
            final_offset = max(
                member.offset_data + ((member.size + 511) // 512) * 512
                for member in members
            )
        self.assertEqual(snapshot[final_offset:], b"\x00" * 1024)

        context = outputs["context_output"]
        self.assertEqual((context / "Dockerfile").read_bytes(), committed_dockerfile)
        self.assertEqual((context / "alpha.txt").read_bytes(), b"alpha from commit\n")
        self.assertEqual((context / "binary.dat").read_bytes(), b"\x00\xff\x80source-bytes\n")
        self.assertFalse((context / "untracked-secret.txt").exists())
        self.assertEqual(stat.S_IMODE(context.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((context / "bin").stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((context / "alpha.txt").stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE((context / "bin/run").stat().st_mode), 0o755)
        self.assertTrue((context / "platform/contracts").is_symlink())
        self.assertEqual(
            os.readlink(context / "platform/contracts"),
            "src/desire_platform/contracts",
        )
        self.assertEqual(
            (context / "platform/contracts/schema.txt").read_bytes(), b"contract\n"
        )
        self.assertEqual(stat.S_IMODE(outputs["snapshot_output"].stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE(outputs["dockerfile_set_output"].stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE(outputs["facts_output"].stat().st_mode), 0o600)

    def test_snapshot_is_byte_identical_across_outputs_and_checkout_mutations(self) -> None:
        repository = self._repository()
        commit = self._commit(repository)
        _first, first = self._create(repository, commit, "first")
        (repository / "alpha.txt").write_bytes(b"dirty\n")
        (repository / "bin/run").chmod(0o644)
        _second, second = self._create(repository, commit, "second")

        for key in ("snapshot_output", "dockerfile_set_output", "facts_output"):
            self.assertEqual(first[key].read_bytes(), second[key].read_bytes())
        for relative in ("Dockerfile", "alpha.txt", "bin/run", "docs/\N{LATIN SMALL LETTER E WITH ACUTE}.txt"):
            self.assertEqual(
                (first["context_output"] / relative).read_bytes(),
                (second["context_output"] / relative).read_bytes(),
            )

    def test_replacement_ref_and_external_smudge_filter_cannot_change_exact_object_bytes(self) -> None:
        repository = self._repository()
        first_commit = self._commit(repository)
        first_dockerfile = (repository / "Dockerfile").read_bytes()
        (repository / "Dockerfile").write_bytes(b"FROM replacement\n")
        _git(repository, "add", "Dockerfile")
        _git(repository, "commit", "--quiet", "--no-gpg-sign", "-m", "replacement")
        second_commit = self._commit(repository)
        _git(repository, "replace", first_commit, second_commit)
        marker = self.root / "filter-was-run"
        _git(repository, "config", "filter.evil.smudge", f"/usr/bin/touch {marker}")
        _git(repository, "config", "filter.evil.required", "true")

        _result, outputs = self._create(repository, first_commit)

        self.assertEqual(
            (outputs["context_output"] / "Dockerfile").read_bytes(),
            first_dockerfile,
        )
        self.assertFalse(marker.exists())
        self.assertEqual(json.loads(outputs["facts_output"].read_bytes())["commit"], first_commit)

    def test_rejects_gitlink_and_every_noncanonical_git_mode(self) -> None:
        repository = self._repository()
        commit_id = self._commit(repository)
        cases = (
            (b"160000", b"submodule", commit_id),
            (b"100600", b"special", None),
        )
        for index, (mode, name, object_id) in enumerate(cases):
            with self.subTest(mode=mode):
                unsafe_commit = self._tree_with_entry(
                    repository,
                    mode=mode,
                    name=name,
                    object_id=object_id,
                )
                outputs = self._outputs(f"mode-{index}")
                with self.assertRaisesRegex(
                    SOURCE.SourceSnapshotError,
                    f"^{SOURCE.ERROR_CODE}$",
                ):
                    SOURCE.create_source_snapshot(
                        repository=repository,
                        commit=unsafe_commit,
                        **outputs,
                    )
                self.assertTrue(all(not path.exists() for path in outputs.values()))

    def test_rejects_escaping_dangling_non_nfc_and_cyclic_symlinks(self) -> None:
        cases = (
            ("escaping", "../../../outside", False),
            ("dangling", "src/desire_platform/missing", False),
            (
                "non-nfc",
                "src/desire_platform/e\N{COMBINING ACUTE ACCENT}",
                False,
            ),
            ("cycle", "src/desire_platform/contracts", True),
        )
        for label, target, cycle in cases:
            with self.subTest(label=label):
                repository = self._repository(
                    f"repository-{label}",
                    link_target=target,
                    link_cycle=cycle,
                )
                outputs = self._outputs(f"symlink-{label}")
                with self.assertRaisesRegex(
                    SOURCE.SourceSnapshotError,
                    f"^{SOURCE.ERROR_CODE}$",
                ):
                    SOURCE.create_source_snapshot(
                        repository=repository,
                        commit=self._commit(repository),
                        **outputs,
                    )
                self.assertTrue(all(not output.exists() for output in outputs.values()))

    def test_rejects_non_utf8_non_nfc_unsafe_and_ustar_impossible_paths(self) -> None:
        repository = self._repository()
        invalid_names = (
            b"\xff.txt",
            "e\N{COMBINING ACUTE ACCENT}.txt".encode("utf-8"),
            b"..",
            b".git",
            b"back\\slash",
            b"control\x1f",
            b"x" * 101,
        )
        for index, name in enumerate(invalid_names):
            with self.subTest(name=name):
                unsafe_commit = self._tree_with_entry(
                    repository,
                    mode=b"100644",
                    name=name,
                )
                outputs = self._outputs(f"path-{index}")
                with self.assertRaises(SOURCE.SourceSnapshotError):
                    SOURCE.create_source_snapshot(
                        repository=repository,
                        commit=unsafe_commit,
                        **outputs,
                    )
                self.assertTrue(all(not path.exists() for path in outputs.values()))

    def test_rejects_local_alternate_object_database_without_reading_it(self) -> None:
        repository = self._repository()
        commit = self._commit(repository)
        alternate = repository / ".git/objects/info/alternates"
        alternate.write_text(str(self.root / "other-objects") + "\n", encoding="utf-8")
        outputs = self._outputs()

        with self.assertRaises(SOURCE.SourceSnapshotError):
            SOURCE.create_source_snapshot(repository=repository, commit=commit, **outputs)

        self.assertTrue(all(not path.exists() for path in outputs.values()))

    def test_preexisting_or_non_owner_only_outputs_fail_before_any_write(self) -> None:
        repository = self._repository()
        commit = self._commit(repository)
        outputs = self._outputs("collision")
        outputs["snapshot_output"].write_bytes(b"preserve")
        outputs["snapshot_output"].chmod(0o600)

        with self.assertRaises(SOURCE.SourceSnapshotError):
            SOURCE.create_source_snapshot(repository=repository, commit=commit, **outputs)

        self.assertEqual(outputs["snapshot_output"].read_bytes(), b"preserve")
        self.assertFalse(outputs["context_output"].exists())
        self.assertFalse(outputs["dockerfile_set_output"].exists())
        self.assertFalse(outputs["facts_output"].exists())

        weak_parent = self.root / "weak-output"
        weak_parent.mkdir(mode=0o755)
        weak = {
            "snapshot_output": weak_parent / "source.tar",
            "context_output": weak_parent / "context",
            "dockerfile_set_output": weak_parent / "dockerfiles.json",
            "facts_output": weak_parent / "facts.json",
        }
        with self.assertRaises(SOURCE.SourceSnapshotError):
            SOURCE.create_source_snapshot(repository=repository, commit=commit, **weak)
        self.assertTrue(all(not path.exists() for path in weak.values()))

    def test_cli_is_exact_non_overwriting_and_has_one_stable_failure(self) -> None:
        repository = self._repository()
        commit = self._commit(repository)
        outputs = self._outputs("cli")
        arguments = (
            "create",
            "--repository",
            str(repository),
            "--commit",
            commit,
            "--snapshot-output",
            str(outputs["snapshot_output"]),
            "--context-output",
            str(outputs["context_output"]),
            "--dockerfile-set-output",
            str(outputs["dockerfile_set_output"]),
            "--facts-output",
            str(outputs["facts_output"]),
        )
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = SOURCE.main(arguments)
        self.assertEqual(status, 0)
        self.assertEqual(stderr.getvalue(), "")
        success = json.loads(stdout.getvalue())
        self.assertEqual(
            success,
            {
                "authority": SOURCE.AUTHORITY,
                "commit": commit,
                "facts_sha256": hashlib.sha256(outputs["facts_output"].read_bytes()).hexdigest(),
                "status": SOURCE.STATUS,
            },
        )

        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = SOURCE.main(arguments)
        self.assertEqual(status, 78)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            json.loads(stderr.getvalue()),
            {
                "authority": SOURCE.AUTHORITY,
                "code": SOURCE.ERROR_CODE,
                "execution_permitted": False,
                "production_authorized": False,
                "status": "BLOCKED",
            },
        )

    def test_commit_must_be_exact_lowercase_sha1_commit_and_paths_absolute(self) -> None:
        repository = self._repository()
        commit = self._commit(repository)
        blob = self._hash_object(repository, "blob", b"not a commit")
        for index, candidate in enumerate((commit.upper(), commit[:39], blob)):
            with self.subTest(commit=candidate):
                outputs = self._outputs(f"commit-{index}")
                with self.assertRaises(SOURCE.SourceSnapshotError):
                    SOURCE.create_source_snapshot(
                        repository=repository,
                        commit=candidate,
                        **outputs,
                    )
                self.assertTrue(all(not path.exists() for path in outputs.values()))

        outputs = self._outputs("relative")
        outputs["facts_output"] = Path("facts.json")
        with self.assertRaises(SOURCE.SourceSnapshotError):
            SOURCE.create_source_snapshot(repository=repository, commit=commit, **outputs)

    def test_implementation_closes_git_network_filter_and_docker_escape_hatches(self) -> None:
        source = SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertIn('"--no-replace-objects"', source)
        self.assertIn('"GIT_NO_LAZY_FETCH": "1"', source)
        self.assertIn('"protocol.allow=never"', source)
        self.assertIn('"core.attributesFile=/dev/null"', source)
        self.assertNotIn("shell=True", source)
        self.assertNotRegex(
            source,
            r"subprocess\.(?:run|Popen)\([^\n]{0,300}[\"']docker[\"']",
        )


if __name__ == "__main__":
    unittest.main()
