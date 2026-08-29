#!/usr/bin/env python3
"""Create an offline, deterministic source snapshot from one exact Git commit.

The helper reads commit, tree, and blob objects through ``git cat-file``.  It
never copies the checkout, invokes a content filter, resolves a replacement
object, contacts a remote, runs Docker, or grants release authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import unicodedata
from types import MappingProxyType
from typing import Any, BinaryIO, Dict, List, Mapping, NoReturn, Optional, Sequence, Tuple


FORMAT = "desire-private-server-runtime-release-source-facts-v1"
ERROR_CODE = "PRIVATE_SERVER_RUNTIME_RELEASE_SOURCE_INVALID"
STATUS = "SOURCE_SNAPSHOT_CREATED_NOT_AUTHORITY"
AUTHORITY = "NOT_AUTHORITY"

DOCKERFILE_NAME = "Dockerfile"
DOCKERFILE_TARGETS: Mapping[str, str] = MappingProxyType(
    {
        "platform": "platform-runtime",
        "web": "web-runtime",
        "edge": "edge-runtime",
        "oidc-egress-guard": "oidc-egress-guard-runtime",
    }
)

MAX_MEMBERS = 200_000
MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024 * 1024
MAX_OBJECT_BYTES = MAX_SNAPSHOT_BYTES
_MAX_BATCH_HEADER_BYTES = 256
_MAX_TREE_DEPTH = 256
_MAX_LINK_TARGET_BYTES = 100
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_OBJECT_ID = re.compile(rb"^[0-9a-f]{40}$")
_OUTPUT_LEAF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,191}$")
_VCS_COMPONENTS = frozenset((".git", ".hg", ".svn"))


class SourceSnapshotError(RuntimeError):
    """Stable, non-reflective failure for an unsafe source or output."""

    def __init__(self) -> None:
        super().__init__(ERROR_CODE)


def _invalid() -> NoReturn:
    raise SourceSnapshotError()


def _canonical(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _invalid()


def _git_environment() -> Dict[str, str]:
    # A deliberately closed environment prevents caller-selected repositories,
    # alternates, replacement refs, prompts, optional locks, and lazy fetching.
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


def _git_prefix(repository: Path) -> List[str]:
    return [
        "git",
        "--no-pager",
        "--no-replace-objects",
        "-c",
        "protocol.allow=never",
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "submodule.recurse=false",
        "-C",
        str(repository),
    ]


def _git_capture(repository: Path, arguments: Sequence[str]) -> bytes:
    try:
        completed = subprocess.run(
            [*_git_prefix(repository), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_git_environment(),
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        _invalid()
    if completed.returncode != 0:
        _invalid()
    return completed.stdout


def _one_git_line(raw: bytes) -> str:
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1 or b"\x00" in raw:
        _invalid()
    try:
        value = raw[:-1].decode("utf-8", "strict")
    except UnicodeError:
        _invalid()
    if not value or unicodedata.normalize("NFC", value) != value:
        _invalid()
    return value


def _safe_repository(value: Path) -> Tuple[Path, Path]:
    if not isinstance(value, Path) or not value.is_absolute():
        _invalid()
    try:
        resolved = value.resolve(strict=True)
        visible = os.stat(value, follow_symlinks=False)
    except OSError:
        _invalid()
    if (
        resolved != value
        or not stat.S_ISDIR(visible.st_mode)
        or visible.st_uid != os.geteuid()
        or stat.S_IMODE(visible.st_mode) & 0o022
    ):
        _invalid()

    top_level = Path(
        _one_git_line(
            _git_capture(resolved, ("rev-parse", "--path-format=absolute", "--show-toplevel"))
        )
    )
    if top_level != resolved:
        _invalid()
    if _one_git_line(_git_capture(resolved, ("rev-parse", "--show-object-format"))) != "sha1":
        _invalid()

    common_value = _one_git_line(
        _git_capture(resolved, ("rev-parse", "--path-format=absolute", "--git-common-dir"))
    )
    common = Path(common_value)
    if not common.is_absolute():
        common = resolved / common
    try:
        common_resolved = common.resolve(strict=True)
        common_stat = os.stat(common, follow_symlinks=False)
    except OSError:
        _invalid()
    if (
        common_resolved != common
        or not stat.S_ISDIR(common_stat.st_mode)
        or common_stat.st_uid != os.geteuid()
        or stat.S_IMODE(common_stat.st_mode) & 0o022
    ):
        _invalid()

    objects = common / "objects"
    try:
        objects_stat = os.stat(objects, follow_symlinks=False)
    except OSError:
        _invalid()
    if (
        not stat.S_ISDIR(objects_stat.st_mode)
        or objects_stat.st_uid != os.geteuid()
        or stat.S_IMODE(objects_stat.st_mode) & 0o022
    ):
        _invalid()
    for alternate_name in ("alternates", "http-alternates"):
        try:
            os.stat(objects / "info" / alternate_name, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError:
            _invalid()
        _invalid()
    return resolved, common


def _read_limited_line(stream: BinaryIO) -> bytes:
    raw = stream.readline(_MAX_BATCH_HEADER_BYTES + 1)
    if not raw or len(raw) > _MAX_BATCH_HEADER_BYTES or not raw.endswith(b"\n"):
        _invalid()
    return raw[:-1]


class _GitObjectReader:
    def __init__(self, repository: Path) -> None:
        try:
            self._process = subprocess.Popen(
                [*_git_prefix(repository), "cat-file", "--batch"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=_git_environment(),
            )
        except OSError:
            _invalid()
        if self._process.stdin is None or self._process.stdout is None:
            self._abort()
            _invalid()
        self._stdin = self._process.stdin
        self._stdout = self._process.stdout
        self._closed = False

    def _abort(self) -> None:
        process = getattr(self, "_process", None)
        if process is not None and process.poll() is None:
            process.kill()
            try:
                process.wait(timeout=5)
            except subprocess.SubprocessError:
                pass
        for stream_name in ("_stdin", "_stdout"):
            stream = getattr(self, stream_name, None)
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass

    def read(self, object_id: str, expected_type: str) -> bytes:
        if self._closed or _COMMIT.fullmatch(object_id) is None:
            _invalid()
        try:
            self._stdin.write(object_id.encode("ascii") + b"\n")
            self._stdin.flush()
            header = _read_limited_line(self._stdout)
            parts = header.split(b" ")
            if (
                len(parts) != 3
                or parts[0] != object_id.encode("ascii")
                or parts[1] != expected_type.encode("ascii")
                or not parts[2].isdigit()
            ):
                _invalid()
            size = int(parts[2])
            if size < 0 or size > MAX_OBJECT_BYTES:
                _invalid()
            raw = self._stdout.read(size)
            terminator = self._stdout.read(1)
        except (BrokenPipeError, OSError, ValueError):
            _invalid()
        if len(raw) != size or terminator != b"\n":
            _invalid()
        digest = hashlib.sha1(
            expected_type.encode("ascii") + b" " + str(size).encode("ascii") + b"\x00" + raw
        ).hexdigest()
        if digest != object_id:
            _invalid()
        return raw

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._stdin.close()
            return_code = self._process.wait(timeout=10)
        except (OSError, subprocess.SubprocessError):
            self._abort()
            _invalid()
        try:
            self._stdout.close()
        except OSError:
            _invalid()
        if return_code != 0:
            _invalid()

    def __enter__(self) -> "_GitObjectReader":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if exc_type is None:
            self.close()
        else:
            self._closed = True
            self._abort()


@dataclass(frozen=True)
class _Member:
    path: str
    path_bytes: bytes
    kind: str
    mode: int
    content: bytes


def _resolved_link_target(path: str, raw: bytes) -> Tuple[str, str]:
    if not raw or len(raw) > _MAX_LINK_TARGET_BYTES or b"\x00" in raw:
        _invalid()
    try:
        target = raw.decode("utf-8", "strict")
    except UnicodeError:
        _invalid()
    if (
        unicodedata.normalize("NFC", target) != target
        or target.startswith("/")
        or "\\" in target
        or any(unicodedata.category(character).startswith("C") for character in target)
    ):
        _invalid()

    resolved = path.split("/")[:-1]
    for component in target.split("/"):
        if component in ("", "."):
            continue
        if component == "..":
            if not resolved:
                _invalid()
            resolved.pop()
            continue
        encoded = component.encode("utf-8")
        if (
            component in _VCS_COMPONENTS
            or not 0 < len(encoded) <= 100
            or encoded.decode("utf-8", "strict") != component
        ):
            _invalid()
        resolved.append(component)
    if not resolved:
        _invalid()
    return target, "/".join(resolved)


def _validated_link_destinations(members: Sequence[_Member]) -> Dict[str, str]:
    entries = {member.path: member.kind for member in members}
    if len(entries) != len(members):
        _invalid()
    links: Dict[str, str] = {}
    for member in members:
        if member.kind == "symlink":
            _target, destination = _resolved_link_target(member.path, member.content)
            links[member.path] = destination

    final_destinations: Dict[str, str] = {}
    for name, destination in links.items():
        if destination not in entries:
            _invalid()
        seen = {name}
        current = destination
        while entries[current] == "symlink":
            if current in seen:
                _invalid()
            seen.add(current)
            current = links[current]
            if current not in entries:
                _invalid()
        final_destinations[name] = current
    return final_destinations


def _safe_component(raw: bytes) -> Tuple[str, bytes]:
    if not raw or b"/" in raw or b"\\" in raw or b"\x00" in raw:
        _invalid()
    try:
        value = raw.decode("utf-8", "strict")
    except UnicodeError:
        _invalid()
    if (
        value in (".", "..")
        or value in _VCS_COMPONENTS
        or unicodedata.normalize("NFC", value) != value
        or any(unicodedata.category(character).startswith("C") for character in value)
    ):
        _invalid()
    encoded = value.encode("utf-8")
    if encoded != raw:
        _invalid()
    return value, encoded


def _ustar_fields(path: bytes) -> Tuple[bytes, bytes]:
    if not path or len(path) > 255 or path.startswith(b"/") or b"//" in path:
        _invalid()
    if len(path) <= 100:
        return path, b""
    if b"/" not in path:
        _invalid()
    prefix, name = path.rsplit(b"/", 1)
    if not name or len(name) > 100 or not prefix or len(prefix) > 155:
        _invalid()
    return name, prefix


def _parse_tree_entries(raw: bytes) -> List[Tuple[str, bytes, str]]:
    entries: List[Tuple[str, bytes, str]] = []
    seen: set[bytes] = set()
    offset = 0
    while offset < len(raw):
        space = raw.find(b" ", offset)
        if space < 0:
            _invalid()
        mode_raw = raw[offset:space]
        name_end = raw.find(b"\x00", space + 1)
        if name_end < 0 or name_end + 21 > len(raw):
            _invalid()
        name_raw = raw[space + 1 : name_end]
        object_raw = raw[name_end + 1 : name_end + 21]
        offset = name_end + 21
        if (
            mode_raw not in (b"40000", b"100644", b"100755", b"120000")
            or name_raw in seen
        ):
            _invalid()
        seen.add(name_raw)
        _safe_component(name_raw)
        object_id = object_raw.hex()
        if _COMMIT.fullmatch(object_id) is None:
            _invalid()
        entries.append((mode_raw.decode("ascii"), name_raw, object_id))
    if offset != len(raw):
        _invalid()
    return entries


def _commit_tree(raw: bytes) -> str:
    first_line = raw.partition(b"\n")[0]
    if len(first_line) != 45 or not first_line.startswith(b"tree "):
        _invalid()
    object_raw = first_line[5:]
    if _OBJECT_ID.fullmatch(object_raw) is None:
        _invalid()
    return object_raw.decode("ascii")


def _load_members(reader: _GitObjectReader, root_tree: str) -> Tuple[bytes, List[_Member]]:
    members: List[_Member] = []
    member_paths: set[bytes] = set()
    active_trees: set[str] = set()
    root_raw = reader.read(root_tree, "tree")

    def visit(tree_id: str, tree_raw: bytes, parents: Tuple[Tuple[str, bytes], ...]) -> None:
        if len(parents) > _MAX_TREE_DEPTH or tree_id in active_trees:
            _invalid()
        active_trees.add(tree_id)
        try:
            for mode, raw_name, object_id in _parse_tree_entries(tree_raw):
                name, encoded_name = _safe_component(raw_name)
                components = (*parents, (name, encoded_name))
                path = "/".join(component[0] for component in components)
                path_bytes = b"/".join(component[1] for component in components)
                _ustar_fields(path_bytes)
                if path_bytes in member_paths:
                    _invalid()
                member_paths.add(path_bytes)
                if len(member_paths) > MAX_MEMBERS:
                    _invalid()
                if mode == "40000":
                    members.append(_Member(path, path_bytes, "directory", 0o755, b""))
                    child_raw = reader.read(object_id, "tree")
                    visit(object_id, child_raw, components)
                elif mode == "120000":
                    content = reader.read(object_id, "blob")
                    members.append(
                        _Member(path, path_bytes, "symlink", 0o777, content)
                    )
                else:
                    content = reader.read(object_id, "blob")
                    members.append(
                        _Member(
                            path,
                            path_bytes,
                            "file",
                            0o755 if mode == "100755" else 0o644,
                            content,
                        )
                    )
        finally:
            active_trees.remove(tree_id)

    visit(root_tree, root_raw, ())
    members.sort(key=lambda item: item.path_bytes)
    if not members:
        _invalid()
    _validated_link_destinations(members)
    return root_raw, members


def _octal(value: int, width: int) -> bytes:
    if value < 0:
        _invalid()
    encoded = ("%0*o" % (width - 1, value)).encode("ascii")
    if len(encoded) != width - 1:
        _invalid()
    return encoded + b"\x00"


def _tar_header(member: _Member) -> bytes:
    name, prefix = _ustar_fields(member.path_bytes)
    size = len(member.content) if member.kind == "file" else 0
    header = bytearray(512)
    header[0 : len(name)] = name
    header[100:108] = _octal(member.mode, 8)
    header[108:116] = _octal(0, 8)
    header[116:124] = _octal(0, 8)
    header[124:136] = _octal(size, 12)
    header[136:148] = _octal(0, 12)
    header[148:156] = b"        "
    if member.kind == "file":
        header[156:157] = b"0"
    elif member.kind == "directory":
        header[156:157] = b"5"
    elif member.kind == "symlink":
        if len(member.content) > _MAX_LINK_TARGET_BYTES:
            _invalid()
        header[156:157] = b"2"
        header[157 : 157 + len(member.content)] = member.content
    else:
        _invalid()
    header[257:263] = b"ustar\x00"
    header[263:265] = b"00"
    header[329:337] = _octal(0, 8)
    header[337:345] = _octal(0, 8)
    header[345 : 345 + len(prefix)] = prefix
    checksum = sum(header)
    checksum_field = ("%06o" % checksum).encode("ascii") + b"\x00 "
    if len(checksum_field) != 8:
        _invalid()
    header[148:156] = checksum_field
    return bytes(header)


def _snapshot(members: Sequence[_Member]) -> bytes:
    output = bytearray()
    for member in members:
        output.extend(_tar_header(member))
        if member.kind == "file":
            output.extend(member.content)
            padding = (-len(member.content)) % 512
            if padding:
                output.extend(b"\x00" * padding)
        if len(output) + 1024 > MAX_SNAPSHOT_BYTES:
            _invalid()
    output.extend(b"\x00" * 1024)
    if len(output) > MAX_SNAPSHOT_BYTES:
        _invalid()
    return bytes(output)


def _dockerfile_set(members: Sequence[_Member]) -> bytes:
    dockerfiles = [
        member
        for member in members
        if member.path_bytes == b"Dockerfile" and member.kind == "file"
    ]
    if len(dockerfiles) != 1:
        _invalid()
    digest = hashlib.sha256(dockerfiles[0].content).hexdigest()
    return _canonical(
        {
            slot: {"dockerfile_sha256": digest, "target": target}
            for slot, target in DOCKERFILE_TARGETS.items()
        }
    )


def _safe_output_path(value: Path) -> Path:
    if (
        not isinstance(value, Path)
        or not value.is_absolute()
        or _OUTPUT_LEAF.fullmatch(value.name) is None
    ):
        _invalid()
    try:
        resolved_parent = value.parent.resolve(strict=True)
        parent_stat = os.stat(value.parent, follow_symlinks=False)
    except OSError:
        _invalid()
    if (
        resolved_parent != value.parent
        or not stat.S_ISDIR(parent_stat.st_mode)
        or parent_stat.st_uid != os.geteuid()
        or stat.S_IMODE(parent_stat.st_mode) != 0o700
    ):
        _invalid()
    return value


def _open_output_parent(value: Path) -> int:
    candidate = _safe_output_path(value)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(candidate.parent, flags)
        opened = os.fstat(descriptor)
    except OSError:
        _invalid()
    if (
        not stat.S_ISDIR(opened.st_mode)
        or opened.st_uid != os.geteuid()
        or stat.S_IMODE(opened.st_mode) != 0o700
    ):
        os.close(descriptor)
        _invalid()
    return descriptor


def _require_absent(value: Path) -> None:
    parent = _open_output_parent(value)
    try:
        try:
            os.stat(value.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError:
            _invalid()
        _invalid()
    finally:
        os.close(parent)


def _write_all(descriptor: int, raw: bytes) -> None:
    view = memoryview(raw)
    offset = 0
    try:
        while offset < len(view):
            written = os.write(descriptor, view[offset : offset + 1024 * 1024])
            if written <= 0:
                _invalid()
            offset += written
    except OSError:
        _invalid()


def _write_new_file(value: Path, raw: bytes, mode: int) -> None:
    parent = _open_output_parent(value)
    descriptor = -1
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(value.name, flags, mode, dir_fd=parent)
        os.fchmod(descriptor, mode)
        _write_all(descriptor, raw)
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
        visible = os.stat(value.name, dir_fd=parent, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != mode
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
            or opened.st_size != len(raw)
            or (opened.st_dev, opened.st_ino) != (visible.st_dev, visible.st_ino)
        ):
            _invalid()
        os.fsync(parent)
    except SourceSnapshotError:
        raise
    except OSError:
        _invalid()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


def _open_context_parent(root: int, components: Sequence[str]) -> int:
    try:
        descriptor = os.dup(root)
        for component in components:
            next_descriptor = os.open(
                component,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or stat.S_IMODE(opened.st_mode) != 0o700
                or opened.st_uid != os.geteuid()
            ):
                os.close(descriptor)
                _invalid()
        return descriptor
    except SourceSnapshotError:
        raise
    except OSError:
        _invalid()


def _materialize_context(value: Path, members: Sequence[_Member]) -> None:
    parent = _open_output_parent(value)
    root = -1
    final_link_destinations = _validated_link_destinations(members)
    members_by_path = {member.path: member for member in members}
    try:
        os.mkdir(value.name, 0o700, dir_fd=parent)
        root = os.open(
            value.name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent,
        )
        os.fchmod(root, 0o700)
        for member in members:
            components = member.path.split("/")
            member_parent = _open_context_parent(root, components[:-1])
            try:
                if member.kind == "directory":
                    os.mkdir(components[-1], 0o700, dir_fd=member_parent)
                    child = os.open(
                        components[-1],
                        os.O_RDONLY
                        | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=member_parent,
                    )
                    try:
                        os.fchmod(child, 0o700)
                    finally:
                        os.close(child)
                elif member.kind == "file":
                    descriptor = os.open(
                        components[-1],
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                        member.mode,
                        dir_fd=member_parent,
                    )
                    try:
                        os.fchmod(descriptor, member.mode)
                        _write_all(descriptor, member.content)
                        os.fsync(descriptor)
                        opened = os.fstat(descriptor)
                        if (
                            not stat.S_ISREG(opened.st_mode)
                            or stat.S_IMODE(opened.st_mode) != member.mode
                            or opened.st_uid != os.geteuid()
                            or opened.st_nlink != 1
                            or opened.st_size != len(member.content)
                        ):
                            _invalid()
                    finally:
                        os.close(descriptor)
                elif member.kind == "symlink":
                    target, _destination = _resolved_link_target(
                        member.path, member.content
                    )
                    os.symlink(target, components[-1], dir_fd=member_parent)
                    visible = os.stat(
                        components[-1],
                        dir_fd=member_parent,
                        follow_symlinks=False,
                    )
                    observed_target = os.readlink(
                        components[-1], dir_fd=member_parent
                    )
                    if (
                        not stat.S_ISLNK(visible.st_mode)
                        or visible.st_uid != os.geteuid()
                        or visible.st_nlink != 1
                        or observed_target != target
                    ):
                        _invalid()
                else:
                    _invalid()
                os.fsync(member_parent)
            finally:
                os.close(member_parent)

        for member in members:
            if member.kind != "symlink":
                continue
            components = member.path.split("/")
            member_parent = _open_context_parent(root, components[:-1])
            try:
                visible = os.stat(
                    components[-1],
                    dir_fd=member_parent,
                    follow_symlinks=False,
                )
                target, _destination = _resolved_link_target(
                    member.path, member.content
                )
                if (
                    not stat.S_ISLNK(visible.st_mode)
                    or visible.st_uid != os.geteuid()
                    or visible.st_nlink != 1
                    or os.readlink(components[-1], dir_fd=member_parent) != target
                ):
                    _invalid()
            finally:
                os.close(member_parent)
            followed = os.stat(member.path, dir_fd=root, follow_symlinks=True)
            final_member = members_by_path[final_link_destinations[member.path]]
            if final_member.kind == "directory":
                if (
                    not stat.S_ISDIR(followed.st_mode)
                    or stat.S_IMODE(followed.st_mode) != 0o700
                ):
                    _invalid()
            elif (
                final_member.kind != "file"
                or not stat.S_ISREG(followed.st_mode)
                or stat.S_IMODE(followed.st_mode) != final_member.mode
                or followed.st_nlink != 1
            ):
                _invalid()
        opened_root = os.fstat(root)
        visible_root = os.stat(value.name, dir_fd=parent, follow_symlinks=False)
        if (
            not stat.S_ISDIR(opened_root.st_mode)
            or stat.S_IMODE(opened_root.st_mode) != 0o700
            or opened_root.st_uid != os.geteuid()
            or (opened_root.st_dev, opened_root.st_ino)
            != (visible_root.st_dev, visible_root.st_ino)
        ):
            _invalid()
        os.fsync(root)
        os.fsync(parent)
    except SourceSnapshotError:
        raise
    except OSError:
        _invalid()
    finally:
        if root >= 0:
            os.close(root)
        os.close(parent)


@dataclass(frozen=True)
class SourceSnapshotFacts:
    raw: bytes
    commit: str
    tree_sha256: str
    snapshot_sha256: str
    snapshot_size: int
    member_count: int
    dockerfile_digest_set_sha256: str
    dockerfile_digest_set_size: int


def create_source_snapshot(
    *,
    repository: Path,
    commit: str,
    snapshot_output: Path,
    context_output: Path,
    dockerfile_set_output: Path,
    facts_output: Path,
) -> SourceSnapshotFacts:
    """Create four new, commit-bound outputs without reading checkout content."""

    if not isinstance(commit, str) or _COMMIT.fullmatch(commit) is None:
        _invalid()
    repository, _common = _safe_repository(repository)
    outputs = (
        _safe_output_path(snapshot_output),
        _safe_output_path(context_output),
        _safe_output_path(dockerfile_set_output),
        _safe_output_path(facts_output),
    )
    if len({str(value) for value in outputs}) != len(outputs):
        _invalid()
    for output in outputs:
        _require_absent(output)

    with _GitObjectReader(repository) as reader:
        commit_raw = reader.read(commit, "commit")
        tree_id = _commit_tree(commit_raw)
        root_tree_raw, members = _load_members(reader, tree_id)

    snapshot_raw = _snapshot(members)
    dockerfile_set_raw = _dockerfile_set(members)
    facts_document = {
        "commit": commit,
        "dockerfile_digest_set": {
            "sha256": hashlib.sha256(dockerfile_set_raw).hexdigest(),
            "size": len(dockerfile_set_raw),
        },
        "format": FORMAT,
        "snapshot": {
            "member_count": len(members),
            "sha256": hashlib.sha256(snapshot_raw).hexdigest(),
            "size": len(snapshot_raw),
        },
        "tree_sha256": hashlib.sha256(root_tree_raw).hexdigest(),
    }
    facts_raw = _canonical(facts_document)

    _write_new_file(snapshot_output, snapshot_raw, 0o400)
    _write_new_file(dockerfile_set_output, dockerfile_set_raw, 0o400)
    _materialize_context(context_output, members)
    _write_new_file(facts_output, facts_raw, 0o600)
    return SourceSnapshotFacts(
        raw=facts_raw,
        commit=commit,
        tree_sha256=facts_document["tree_sha256"],
        snapshot_sha256=facts_document["snapshot"]["sha256"],
        snapshot_size=facts_document["snapshot"]["size"],
        member_count=facts_document["snapshot"]["member_count"],
        dockerfile_digest_set_sha256=facts_document["dockerfile_digest_set"]["sha256"],
        dockerfile_digest_set_size=facts_document["dockerfile_digest_set"]["size"],
    )


create = create_source_snapshot


def _emit(stream: Any, value: Mapping[str, Any]) -> None:
    stream.write(_canonical(value).decode("ascii"))


def _failure() -> int:
    _emit(
        sys.stderr,
        {
            "authority": AUTHORITY,
            "code": ERROR_CODE,
            "execution_permitted": False,
            "production_authorized": False,
            "status": "BLOCKED",
        },
    )
    return 78


def main(arguments: Optional[Sequence[str]] = None) -> int:
    values = tuple(sys.argv[1:] if arguments is None else arguments)
    try:
        if (
            len(values) == 13
            and values[0] == "create"
            and values[1] == "--repository"
            and values[3] == "--commit"
            and values[5] == "--snapshot-output"
            and values[7] == "--context-output"
            and values[9] == "--dockerfile-set-output"
            and values[11] == "--facts-output"
        ):
            result = create_source_snapshot(
                repository=Path(values[2]),
                commit=values[4],
                snapshot_output=Path(values[6]),
                context_output=Path(values[8]),
                dockerfile_set_output=Path(values[10]),
                facts_output=Path(values[12]),
            )
            _emit(
                sys.stdout,
                {
                    "authority": AUTHORITY,
                    "commit": result.commit,
                    "facts_sha256": hashlib.sha256(result.raw).hexdigest(),
                    "status": STATUS,
                },
            )
            return 0
        return _failure()
    except SourceSnapshotError:
        return _failure()


if __name__ == "__main__":
    raise SystemExit(main())
