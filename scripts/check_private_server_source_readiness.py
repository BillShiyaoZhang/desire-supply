#!/usr/bin/env python3
"""Bind one clean checkout byte-for-byte to its exact Git HEAD.

This is a read-only, local source-readiness gate.  It does not contact a
remote, run tests, call Docker, grant release authority, or mutate Git.  An
optional receipt is exclusive-created outside the repository with mode 0600.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import unicodedata
from typing import Any, Mapping, NoReturn, Sequence, TextIO


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FORMAT = "desire-private-server-source-readiness-v1"
READY_STATUS = "SOURCE_READINESS_VERIFIED_NOT_AUTHORITY"
AUTHORITY = "NOT_AUTHORITY"

INVALID = "PRIVATE_SERVER_SOURCE_READINESS_INVALID"
DIRTY = "PRIVATE_SERVER_SOURCE_READINESS_DIRTY"
REQUIRED_PATHS_MISSING = "PRIVATE_SERVER_SOURCE_READINESS_REQUIRED_PATHS_MISSING"
SOURCE_MISMATCH = "PRIVATE_SERVER_SOURCE_READINESS_SOURCE_MISMATCH"
OUTPUT_INVALID = "PRIVATE_SERVER_SOURCE_READINESS_OUTPUT_INVALID"

MAX_MEMBERS = 200_000
MAX_SOURCE_BYTES = 4 * 1024 * 1024 * 1024
MAX_GIT_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_STATUS_BYTES = 16 * 1024 * 1024
MAX_LINK_TARGET_BYTES = 100
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_OUTPUT_LEAF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,191}$")
_VCS_COMPONENTS = frozenset((".git", ".hg", ".svn"))

# These are the minimum deploy, workflow, current-head, and developer-entry
# files that must be present as regular tracked blobs in the selected HEAD.
# The binding below still covers every tracked file, not just this allowlist.
REQUIRED_TRACKED_PATHS = frozenset(
    (
        ".devcontainer/devcontainer.json",
        ".dockerignore",
        ".github/workflows/ci.yml",
        ".github/workflows/private-server-runtime-release.yml",
        "Dockerfile",
        "compose.dev.yaml",
        "compose.yaml",
        "deploy/Caddyfile",
        "deploy/Caddyfile.real-oidc",
        "deploy/devcontainer-entrypoint.sh",
        "deploy/devcontainer-post-create.sh",
        "deploy/devcontainer-runtime-closure.sh",
        "deploy/devcontainer-toolchain-check.sh",
        "deploy/private-server-real-oidc-egress-guard.py",
        "deploy/private-server-real-oidc.compose.yaml",
        "deploy/private-server-runtime-release-bundle-v1.md",
        "deploy/private-server-runtime-release-v1.schema.json",
        "deploy/private-server-source-readiness-v1.schema.json",
        "deploy/private-server.compose.yaml",
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
        "deploy/postgres-backup-restore-v28.sh",
        "deploy/postgres-backup-restore-v29.sh",
        "deploy/postgres-core-facts-v28.sql",
        "deploy/postgres-core-facts-v29.sql",
        "deploy/postgres-operations-v28.compose.yaml",
        "deploy/postgres-operations-v29.compose.yaml",
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
        "docs/operations/current-head-v28.md",
        "docs/operations/current-head-v29.md",
        "docs/operations/private-server-internal-sandbox.md",
        "docs/operations/private-server-real-oidc.md",
        "docs/operations/private-server-runtime-release.md",
        "platform/pyproject.toml",
        "platform/src/desire_platform/__init__.py",
        "platform/uv.lock",
        "scripts/activate_private_server_ingress.py",
        "scripts/activate_private_server_real_oidc.py",
        "scripts/check_private_server_source_readiness.py",
        "scripts/fetch_pinned_postgres_release_evidence.py",
        "scripts/manage_private_server_ingress.py",
        "scripts/manage_private_server_real_oidc.py",
        "scripts/preflight_private_server_real_oidc.py",
        "scripts/prepare_private_server_runtime_release.py",
        "scripts/private_server_release_inputs.py",
        "scripts/private_server_runtime_release.py",
        "scripts/private_server_runtime_release_source.py",
        "scripts/verify_container_stack.py",
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
        "scripts/verify_current_head_v28.py",
        "scripts/verify_current_head_v29.py",
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
        "tests/deployment/fixtures/current-head-v28/schema-pins.json",
        "tests/deployment/fixtures/current-head-v29/schema-pins.json",
    "tests/deployment/fixtures/current-head-v29/iam-manifest.json",
    "tests/deployment/fixtures/current-head-v29/trust-manifest.json",
    "tests/deployment/fixtures/current-head-v29/matching-manifest.json",
        "tests/deployment/fixtures/current-head-v28/matching-v3-manifest.json",
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
        "tests/deployment/test_current_head_v28_contract.py",
        "tests/deployment/test_current_head_v29_contract.py",
        "tests/deployment/test_postgres_operations_v25.py",
        "tests/deployment/test_postgres_operations_v26.py",
        "tests/deployment/test_postgres_operations_v27.py",
        "tests/deployment/test_postgres_operations_v28.py",
        "tests/deployment/test_postgres_operations_v29.py",
        "tests/deployment/test_private_server_runtime_release_source.py",
        "tests/deployment/test_private_server_runtime_release_workflow.py",
        "tests/deployment/test_private_server_source_readiness.py",
        "web/app/page.tsx",
        "web/package-lock.json",
        "web/package.json",
    )
)


@dataclass(frozen=True)
class SourceReadinessError(RuntimeError):
    """Stable, non-reflective readiness failure."""

    code: str
    exit_code: int = 1

    def __post_init__(self) -> None:
        RuntimeError.__init__(self, self.code)


@dataclass(frozen=True)
class _TreeEntry:
    mode: str
    object_id: str
    path: str
    path_bytes: bytes


def _blocked(code: str, *, exit_code: int = 1) -> NoReturn:
    raise SourceReadinessError(code, exit_code)


def _canonical(value: Mapping[str, Any]) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _blocked(INVALID, exit_code=78)


def _git_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def _safe_repository(repository: Path) -> Path:
    if not isinstance(repository, Path) or not repository.is_absolute():
        _blocked(INVALID, exit_code=78)
    try:
        visible = os.stat(repository, follow_symlinks=False)
        resolved = repository.resolve(strict=True)
    except OSError:
        _blocked(INVALID, exit_code=78)
    if (
        resolved != repository
        or not stat.S_ISDIR(visible.st_mode)
        or visible.st_uid != os.geteuid()
        or stat.S_IMODE(visible.st_mode) & 0o022
    ):
        _blocked(INVALID, exit_code=78)
    return resolved


def _git_executable() -> str:
    candidate = shutil.which("git", path=_git_environment()["PATH"])
    if not candidate:
        _blocked(INVALID, exit_code=78)
    try:
        resolved = Path(candidate).resolve(strict=True)
        metadata = resolved.stat()
    except OSError:
        _blocked(INVALID, exit_code=78)
    if not resolved.is_absolute() or not stat.S_ISREG(metadata.st_mode):
        _blocked(INVALID, exit_code=78)
    return str(resolved)


def _git_capture(
    repository: Path,
    arguments: Sequence[str],
    *,
    maximum: int = MAX_GIT_OUTPUT_BYTES,
) -> bytes:
    command = (
        _git_executable(),
        "--no-pager",
        "--no-replace-objects",
        "-c",
        "protocol.allow=never",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "submodule.recurse=false",
        "-C",
        str(repository),
        *arguments,
    )
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
            env=_git_environment(),
        )
    except (OSError, subprocess.SubprocessError):
        _blocked(INVALID, exit_code=78)
    if (
        completed.returncode != 0
        or len(completed.stdout) > maximum
    ):
        _blocked(INVALID, exit_code=78)
    return completed.stdout


def _one_line(raw: bytes) -> str:
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1 or b"\x00" in raw:
        _blocked(INVALID, exit_code=78)
    try:
        value = raw[:-1].decode("utf-8", "strict")
    except UnicodeError:
        _blocked(INVALID, exit_code=78)
    if not value or unicodedata.normalize("NFC", value) != value:
        _blocked(INVALID, exit_code=78)
    return value


def _repository_identity(repository: Path) -> tuple[str, str]:
    top = Path(
        _one_line(
            _git_capture(
                repository,
                ("rev-parse", "--path-format=absolute", "--show-toplevel"),
            )
        )
    )
    if top != repository:
        _blocked(INVALID, exit_code=78)
    if _one_line(_git_capture(repository, ("rev-parse", "--show-object-format"))) != "sha1":
        _blocked(INVALID, exit_code=78)
    head = _one_line(_git_capture(repository, ("rev-parse", "--verify", "HEAD^{commit}")))
    tree = _one_line(_git_capture(repository, ("rev-parse", "--verify", "HEAD^{tree}")))
    if _SHA1.fullmatch(head) is None or _SHA1.fullmatch(tree) is None:
        _blocked(INVALID, exit_code=78)
    return head, tree


def _worktree_status(repository: Path) -> bytes:
    return _git_capture(
        repository,
        (
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ),
        maximum=MAX_STATUS_BYTES,
    )


def _safe_path(raw: bytes) -> tuple[str, bytes]:
    if not raw or raw.startswith(b"/") or b"//" in raw or b"\\" in raw:
        _blocked(SOURCE_MISMATCH)
    components = raw.split(b"/")
    values: list[str] = []
    for component in components:
        if not component:
            _blocked(SOURCE_MISMATCH)
        try:
            value = component.decode("utf-8", "strict")
        except UnicodeError:
            _blocked(SOURCE_MISMATCH)
        if (
            value in (".", "..")
            or value in _VCS_COMPONENTS
            or unicodedata.normalize("NFC", value) != value
            or any(unicodedata.category(character).startswith("C") for character in value)
        ):
            _blocked(SOURCE_MISMATCH)
        if value.encode("utf-8") != component:
            _blocked(SOURCE_MISMATCH)
        values.append(value)
    return "/".join(values), raw


def _tree_entries(repository: Path) -> tuple[_TreeEntry, ...]:
    raw = _git_capture(
        repository,
        ("ls-tree", "-r", "-z", "--full-tree", "HEAD"),
    )
    if not raw or not raw.endswith(b"\x00"):
        _blocked(INVALID, exit_code=78)
    entries: list[_TreeEntry] = []
    seen: set[bytes] = set()
    for record in raw[:-1].split(b"\x00"):
        try:
            header, path_raw = record.split(b"\t", 1)
            mode_raw, kind_raw, object_raw = header.split(b" ")
        except ValueError:
            _blocked(INVALID, exit_code=78)
        if (
            mode_raw not in (b"100644", b"100755", b"120000")
            or kind_raw != b"blob"
            or len(object_raw) != 40
            or re.fullmatch(rb"[0-9a-f]{40}", object_raw) is None
            or path_raw in seen
        ):
            _blocked(SOURCE_MISMATCH)
        seen.add(path_raw)
        path, encoded = _safe_path(path_raw)
        entries.append(
            _TreeEntry(
                mode=mode_raw.decode("ascii"),
                object_id=object_raw.decode("ascii"),
                path=path,
                path_bytes=encoded,
            )
        )
    if not 1 <= len(entries) <= MAX_MEMBERS:
        _blocked(SOURCE_MISMATCH)
    entries.sort(key=lambda item: item.path_bytes)
    return tuple(entries)


def _safe_parent_directories(repository: Path, relative: str, cache: set[str]) -> None:
    current = repository
    parts = relative.split("/")[:-1]
    prefix: list[str] = []
    for part in parts:
        prefix.append(part)
        key = "/".join(prefix)
        if key in cache:
            current /= part
            continue
        current /= part
        try:
            metadata = os.stat(current, follow_symlinks=False)
        except OSError:
            _blocked(SOURCE_MISMATCH)
        if not stat.S_ISDIR(metadata.st_mode):
            _blocked(SOURCE_MISMATCH)
        cache.add(key)


def _read_bound_file(repository: Path, entry: _TreeEntry, cache: set[str]) -> bytes:
    _safe_parent_directories(repository, entry.path, cache)
    path = repository / entry.path
    if entry.mode == "120000":
        try:
            before = os.stat(path, follow_symlinks=False)
            target = os.readlink(path)
            after = os.stat(path, follow_symlinks=False)
            content = target.encode("utf-8", "strict")
        except (OSError, UnicodeError):
            _blocked(SOURCE_MISMATCH)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if (
            not stat.S_ISLNK(before.st_mode)
            or before.st_nlink != 1
            or any(
                getattr(before, field) != getattr(after, field)
                for field in stable_fields
            )
            or before.st_size != len(content)
        ):
            _blocked(SOURCE_MISMATCH)
        object_id = hashlib.sha1(
            b"blob " + str(len(content)).encode("ascii") + b"\x00" + content
        ).hexdigest()
        if object_id != entry.object_id:
            _blocked(SOURCE_MISMATCH)
        return content

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        _blocked(SOURCE_MISMATCH)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 0
            or stat.S_IMODE(before.st_mode) != int(entry.mode[-3:], 8)
        ):
            _blocked(SOURCE_MISMATCH)
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            value = os.read(descriptor, min(1024 * 1024, remaining))
            if not value:
                _blocked(SOURCE_MISMATCH)
            chunks.append(value)
            remaining -= len(value)
        if os.read(descriptor, 1):
            _blocked(SOURCE_MISMATCH)
        after = os.fstat(descriptor)
        visible = os.stat(path, follow_symlinks=False)
    except OSError:
        _blocked(SOURCE_MISMATCH)
    finally:
        os.close(descriptor)
    stable_fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
        _blocked(SOURCE_MISMATCH)
    if any(getattr(after, field) != getattr(visible, field) for field in stable_fields[:5]):
        _blocked(SOURCE_MISMATCH)
    content = b"".join(chunks)
    object_id = hashlib.sha1(
        b"blob " + str(len(content)).encode("ascii") + b"\x00" + content
    ).hexdigest()
    if object_id != entry.object_id:
        _blocked(SOURCE_MISMATCH)
    return content


def _resolved_link_target(path: str, raw: bytes) -> str:
    if not raw or len(raw) > MAX_LINK_TARGET_BYTES or b"\x00" in raw:
        _blocked(SOURCE_MISMATCH)
    try:
        target = raw.decode("utf-8", "strict")
    except UnicodeError:
        _blocked(SOURCE_MISMATCH)
    if (
        unicodedata.normalize("NFC", target) != target
        or target.startswith("/")
        or "\\" in target
        or any(unicodedata.category(character).startswith("C") for character in target)
    ):
        _blocked(SOURCE_MISMATCH)

    resolved = path.split("/")[:-1]
    for component in target.split("/"):
        if component in ("", "."):
            continue
        if component == "..":
            if not resolved:
                _blocked(SOURCE_MISMATCH)
            resolved.pop()
            continue
        encoded = component.encode("utf-8")
        if component in _VCS_COMPONENTS or not 0 < len(encoded) <= 100:
            _blocked(SOURCE_MISMATCH)
        resolved.append(component)
    if not resolved:
        _blocked(SOURCE_MISMATCH)
    return "/".join(resolved)


def _validate_symlinks(
    entries: Sequence[_TreeEntry], contents: Mapping[str, bytes]
) -> None:
    kinds: dict[str, str] = {}
    for entry in entries:
        components = entry.path.split("/")
        for index in range(1, len(components)):
            directory = "/".join(components[:index])
            existing = kinds.setdefault(directory, "directory")
            if existing != "directory":
                _blocked(SOURCE_MISMATCH)
        kind = "symlink" if entry.mode == "120000" else "file"
        if entry.path in kinds:
            _blocked(SOURCE_MISMATCH)
        kinds[entry.path] = kind

    links = {
        entry.path: _resolved_link_target(entry.path, contents[entry.path])
        for entry in entries
        if entry.mode == "120000"
    }
    for name, destination in links.items():
        if destination not in kinds:
            _blocked(SOURCE_MISMATCH)
        seen = {name}
        current = destination
        while kinds[current] == "symlink":
            if current in seen:
                _blocked(SOURCE_MISMATCH)
            seen.add(current)
            current = links[current]
            if current not in kinds:
                _blocked(SOURCE_MISMATCH)


def check_repository(repository: Path = REPOSITORY_ROOT) -> dict[str, Any]:
    """Return a closed, non-authoritative binding for one exact clean HEAD."""

    repository = _safe_repository(Path(repository))
    head, tree = _repository_identity(repository)
    if _worktree_status(repository):
        _blocked(DIRTY)
    entries = _tree_entries(repository)
    entries_by_path = {entry.path: entry for entry in entries}
    if any(
        path not in entries_by_path or entries_by_path[path].mode == "120000"
        for path in REQUIRED_TRACKED_PATHS
    ):
        _blocked(REQUIRED_PATHS_MISSING)

    digest = hashlib.sha256()
    digest.update(b"desire-private-server-source-readiness-v1\x00")
    total = 0
    parent_cache: set[str] = set()
    contents: dict[str, bytes] = {}
    for entry in entries:
        content = _read_bound_file(repository, entry, parent_cache)
        contents[entry.path] = content
        total += len(content)
        if total > MAX_SOURCE_BYTES:
            _blocked(SOURCE_MISMATCH)
        digest.update(entry.mode.encode("ascii") + b"\x00")
        digest.update(entry.path_bytes + b"\x00")
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(hashlib.sha256(content).digest())

    _validate_symlinks(entries, contents)

    final_head, final_tree = _repository_identity(repository)
    if (final_head, final_tree) != (head, tree) or _worktree_status(repository):
        _blocked(SOURCE_MISMATCH)
    return {
        "authority": AUTHORITY,
        "ci_verified": False,
        "execution_permitted": False,
        "format": FORMAT,
        "git_object_format": "sha1",
        "head": head,
        "head_tree": tree,
        "member_count": len(entries),
        "production_authorized": False,
        "remote_ref_verified": False,
        "source_bytes": total,
        "source_sha256": digest.hexdigest(),
        "status": READY_STATUS,
        "working_tree": "EXACT_HEAD",
    }


def _output_target(value: Path, repository: Path) -> tuple[Path, str]:
    if not value.is_absolute() or _OUTPUT_LEAF.fullmatch(value.name) is None:
        _blocked(OUTPUT_INVALID, exit_code=78)
    try:
        parent = value.parent.resolve(strict=True)
        metadata = os.stat(value.parent, follow_symlinks=False)
    except OSError:
        _blocked(OUTPUT_INVALID, exit_code=78)
    try:
        parent.relative_to(repository)
    except ValueError:
        pass
    else:
        _blocked(OUTPUT_INVALID, exit_code=78)
    if (
        parent != value.parent
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        _blocked(OUTPUT_INVALID, exit_code=78)
    try:
        os.stat(value, follow_symlinks=False)
    except FileNotFoundError:
        return parent, value.name
    except OSError:
        _blocked(OUTPUT_INVALID, exit_code=78)
    _blocked(OUTPUT_INVALID, exit_code=78)


def _write_new_receipt(target: Path, repository: Path, content: bytes) -> None:
    parent, leaf = _output_target(target, repository)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        directory = os.open(parent, directory_flags)
    except OSError:
        _blocked(OUTPUT_INVALID, exit_code=78)
    descriptor = -1
    try:
        descriptor = os.open(
            leaf,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory,
        )
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise OSError
            offset += written
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size != len(content)
        ):
            raise OSError
    except OSError:
        _blocked(OUTPUT_INVALID, exit_code=78)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory)


def _arguments(argv: Sequence[str]) -> Path | None:
    values = tuple(argv)
    if not values:
        return None
    if len(values) == 2 and values[0] == "--output":
        return Path(values[1])
    _blocked(INVALID, exit_code=78)


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    try:
        output = _arguments(tuple(sys.argv[1:] if argv is None else argv))
        if output is not None:
            _output_target(output, REPOSITORY_ROOT)
        document = check_repository(REPOSITORY_ROOT)
        raw = _canonical(document)
        if output is not None:
            _write_new_receipt(output, REPOSITORY_ROOT, raw)
        stdout.write(raw.decode("ascii"))
        return 0
    except SourceReadinessError as error:
        stderr.write(
            _canonical({"code": error.code, "status": "BLOCKED"}).decode("ascii")
        )
        return error.exit_code
    except Exception:
        stderr.write(
            _canonical({"code": INVALID, "status": "BLOCKED"}).decode("ascii")
        )
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
