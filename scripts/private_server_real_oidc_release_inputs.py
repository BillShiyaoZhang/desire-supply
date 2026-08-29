#!/usr/bin/env python3
"""Create and verify one immutable real-OIDC private-server input snapshot.

The source tree is read through an anchored directory descriptor.  Every source
file is opened with ``O_NOFOLLOW`` and its identity is checked before and after
the read.  The resulting attempt tree contains only exact-byte copies; mounted
files are world-readable *inside* an otherwise non-traversable 0700 attempt
root because Docker Compose implements local file configs/secrets as bind
mounts.  No secret value is returned, printed, or placed in an environment or
command argument.

This module only stages files and runs ``docker compose config``.  It never
contacts the Docker daemon and has no lifecycle command.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from types import MappingProxyType, ModuleType
from typing import Any, Callable, Iterator, Mapping, NoReturn, Optional, Sequence, TextIO


_ROOT = Path(__file__).resolve().parents[1]
_MAX_CONFIG = 256 * 1024
_MAX_SECRET = 4 * 1024
_MAX_TLS = 1024 * 1024
_MAX_COMPOSE = 4 * 1024 * 1024
_PROJECT = re.compile(
    r"^desire-real-oidc-(?:[a-z0-9]|[a-z0-9][a-z0-9-]{0,38}[a-z0-9])$"
)
_IMAGE_TAG = re.compile(
    r"^sha-[0-9a-f]{40}-(?:amd64|arm64)-r[1-9][0-9]*-a[1-9][0-9]*$"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_PINNED_REPOSITORY_SOURCE_SHA256 = {
    "Dockerfile": (
        "6d16a0a7179dcf62fe7cdf2b2a76b39b1d1db8c450ea2d1df35ed0ec84b14677"
    ),
    "deploy/private-server-real-oidc-egress-guard.py": (
        "fcae74d7f5ec8b720803af8eb3837108b88bb4c673b930f51dbec0207e70dd58"
    ),
    "scripts/private_server_real_oidc_compose_contract.py": (
        "42bd782687af13d798e6c8dd8da379efefb243ad2a6d50daa3d18a74b4bee061"
    ),
    "platform/src/desire_platform/runtime/config.py": (
        "110c58ab5ae3db4ac6925134a2dfd3bfde2d5ea50d16b6437ece9f3641b57533"
    ),
    "platform/src/desire_platform/internal_pilot/secrets.py": (
        "3568af4beb3fc8f4eb4813f36f1e051ff68b6bec513bdc0434d2317d27430862"
    ),
    "scripts/private_server_release_inputs.py": (
        "7cad99cca3b8e339de351d098d78a76858b77280d378db7edbac4dfbc7b18d63"
    ),
}

def _current_contract_sets():
    """Derive mutable-head inventories from the real profile's closed contract."""

    path = _ROOT / "scripts/private_server_real_oidc_compose_contract.py"
    name = "_desire_real_oidc_contract_inventory"
    try:
        raw = path.read_bytes()
        if (
            hashlib.sha256(raw).hexdigest()
            != _PINNED_REPOSITORY_SOURCE_SHA256[
                "scripts/private_server_real_oidc_compose_contract.py"
            ]
        ):
            raise RuntimeError
        module = ModuleType(name)
        module.__file__ = str(path)
        sys.modules[name] = module
        exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
        bundle = frozenset(module._BUNDLE_SECRET_NAMES)
        identities = frozenset(module._IDENTITY_SOURCE_NAMES)
        if not bundle or len(identities) != 20:
            raise RuntimeError
        return bundle, identities
    except BaseException as error:
        raise RuntimeError("PRIVATE_SERVER_REAL_OIDC_INPUT_SNAPSHOT_INVALID") from error


_BUNDLE_SECRET_NAMES, _IDENTITY_NAMES = _current_contract_sets()
_SOURCE_CONFIG_NAMES = frozenset(
    (
        "deployment.json",
        "runtime-config.json",
        "secret-manifest.json",
        "matching-deployment.json",
        "matching-runtime-config.json",
        "matching-secret-manifest.json",
        "online-credentials-deployment.json",
        "online-credentials-runtime-config.json",
        "online-credentials-secret-manifest.json",
    )
)
_STAGED_CONFIG_NAMES = _SOURCE_CONFIG_NAMES | frozenset(
    ("identity-bootstrap-template.json", "Caddyfile.real-oidc")
)
_STANDALONE = frozenset(("db-password", "taxonomy-workload", "taxonomy-hmac"))
_REPOSITORY_SOURCES = (
    "Dockerfile",
    "compose.yaml",
    "deploy/private-server.compose.yaml",
    "deploy/private-server-real-oidc.compose.yaml",
    "deploy/private-server-real-oidc-egress-guard.py",
    "deploy/Caddyfile.real-oidc",
    "platform/examples/internal-sandbox-identity-bootstrap-template-v1.json",
    "scripts/private_server_real_oidc_compose_contract.py",
    "scripts/private_server_release_inputs.py",
    "platform/src/desire_platform/runtime/config.py",
    "platform/src/desire_platform/internal_pilot/secrets.py",
)
_REPOSITORY_SNAPSHOT_NAMES = {
    "Dockerfile": "Dockerfile",
    "compose.yaml": "compose.yaml",
    "deploy/private-server.compose.yaml": "private-server.compose.yaml",
    "deploy/private-server-real-oidc.compose.yaml": (
        "private-server-real-oidc.compose.yaml"
    ),
    "deploy/private-server-real-oidc-egress-guard.py": (
        "private-server-real-oidc-egress-guard.py"
    ),
}
_ROOT_ENTRIES = frozenset(
    (
        "bundle",
        "identity-sources",
        "tls",
        "db-password",
        "taxonomy-workload",
        "taxonomy-hmac",
        "compose.ipam.yaml",
        "repository",
        "resolved.compose.json",
        "snapshot-manifest.json",
    )
)
_MOUNTED_PATHS = frozenset(
    {f"bundle/config/{name}" for name in _STAGED_CONFIG_NAMES}
    | {f"bundle/runtime-secrets/{name}" for name in _BUNDLE_SECRET_NAMES}
    | {f"identity-sources/{name}" for name in _IDENTITY_NAMES}
    | {f"tls/{name}" for name in ("edge-tls-chain.pem", "edge-tls-key.pem")}
    | set(_STANDALONE)
)

READY = '{"status":"PRIVATE_SERVER_REAL_OIDC_INPUT_SNAPSHOT_READY"}\n'
VERIFIED = '{"status":"PRIVATE_SERVER_REAL_OIDC_INPUT_SNAPSHOT_VERIFIED"}\n'
BLOCKED = (
    '{"code":"PRIVATE_SERVER_REAL_OIDC_INPUT_SNAPSHOT_INVALID",'
    '"status":"BLOCKED"}\n'
)


class PrivateServerRealOidcReleaseInputError(RuntimeError):
    """Stable, non-reflective snapshot failure."""

    def __init__(self) -> None:
        super().__init__("PRIVATE_SERVER_REAL_OIDC_INPUT_SNAPSHOT_INVALID")


@dataclass(frozen=True, repr=False)
class RealOidcReviewedInputs:
    project_name: str
    pilot_hostname: str
    oidc_issuer: str
    oidc_client_id: str
    oidc_pinned_public_ipv4: str
    db_data_ipv4: str
    image_tag: str
    ingress_ip: str

    def __repr__(self) -> str:
        return "RealOidcReviewedInputs(<reviewed-non-secret-metadata>)"


@dataclass(frozen=True, repr=False)
class RealOidcReleaseInputSnapshot:
    attempt_root: Path
    project_name: str
    snapshot_sha256: str
    manifest_device: int
    manifest_inode: int
    compose_sha256: str
    oidc_pinned_public_ipv4: str
    db_data_ipv4: str
    oidc_egress_projection_sha256: str
    image_references: tuple[str, ...]

    def __repr__(self) -> str:
        return (
            "RealOidcReleaseInputSnapshot("
            f"attempt_root={str(self.attempt_root)!r}, "
            f"project_name={self.project_name!r}, "
            f"snapshot_sha256={self.snapshot_sha256!r}, "
            f"compose_sha256={self.compose_sha256!r}, material=<redacted>)"
        )


@dataclass(frozen=True, repr=False)
class _Record:
    relative: str
    value: bytes
    device: int
    inode: int
    mode: int
    size: int


class _DuplicateKey(ValueError):
    pass


def _invalid() -> NoReturn:
    raise PrivateServerRealOidcReleaseInputError()


def _pairs(values):
    result = {}
    for key, value in values:
        if not isinstance(key, str) or key in result:
            raise _DuplicateKey()
        result[key] = value
    return result


def _json(raw: bytes) -> Any:
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= _MAX_COMPOSE:
            _invalid()
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs,
            parse_float=lambda _value: _invalid(),
            parse_constant=lambda _value: _invalid(),
        )
    except PrivateServerRealOidcReleaseInputError:
        raise
    except BaseException:
        _invalid()


def _canonical_json(value: Any) -> bytes:
    try:
        return (
            json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("ascii")
    except BaseException:
        _invalid()


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _egress_projection_bytes(db_data_ipv4: str, oidc_ipv4: str) -> bytes:
    try:
        database = ipaddress.ip_address(db_data_ipv4)
        provider = ipaddress.ip_address(oidc_ipv4)
    except ValueError:
        _invalid()
    if (
        not isinstance(database, ipaddress.IPv4Address)
        or str(database) != db_data_ipv4
        or not any(database in network for network in _RFC1918)
        or database.is_loopback
        or database.is_multicast
        or database.is_unspecified
        or not isinstance(provider, ipaddress.IPv4Address)
        or str(provider) != oidc_ipv4
        or not provider.is_global
        or provider.is_private
        or provider.is_loopback
        or provider.is_link_local
        or provider.is_multicast
        or provider.is_reserved
        or provider.is_unspecified
    ):
        _invalid()
    descriptor = {
        "database": {"ipv4": db_data_ipv4, "port": 5432, "verdict": "ALLOW"},
        "dns": {"tcp_port": 53, "udp_port": 53, "verdict": "REJECT"},
        "established_related": "ALLOW",
        "ipv4_other": "REJECT",
        "ipv6": "REJECT",
        "loopback": "ALLOW",
        "oidc": {"ipv4": oidc_ipv4, "port": 443, "verdict": "ALLOW"},
        "output_policy": "DROP",
        "schema": "desire-real-oidc-egress-projection-v1",
    }
    return (
        json.dumps(
            descriptor, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        )
        + "\n"
    ).encode("ascii")


def _egress_projection_sha256(db_data_ipv4: str, oidc_ipv4: str) -> str:
    return _sha(_egress_projection_bytes(db_data_ipv4, oidc_ipv4))


def _same(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _within(left: Path, right: Path) -> bool:
    try:
        left.relative_to(right)
    except ValueError:
        return False
    return True


def _canonical_directory(path: Path, *, mode: int, empty: bool = False) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or str(path) == "/":
        _invalid()
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
        names = os.listdir(path)
    except (OSError, RuntimeError):
        _invalid()
    if (
        resolved != path
        or path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != mode
        or metadata.st_uid != os.geteuid()
        or (empty and names)
    ):
        _invalid()
    return path


@contextmanager
def _open_root(path: Path, *, mode: int, empty: bool = False) -> Iterator[int]:
    canonical = _canonical_directory(path, mode=mode, empty=empty)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(canonical, flags)
    except OSError:
        _invalid()
    try:
        before = os.fstat(descriptor)
        visible = canonical.lstat()
        if not _same(before, visible):
            _invalid()
        yield descriptor
        after = os.fstat(descriptor)
        visible_after = canonical.lstat()
        if (
            not _same(before, after)
            or not _same(after, visible_after)
            or stat.S_IMODE(after.st_mode) != mode
            or after.st_uid != os.geteuid()
        ):
            _invalid()
    except OSError:
        _invalid()
    finally:
        os.close(descriptor)


def _open_child(parent_fd: int, name: str, *, mode: int) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
        opened = os.fstat(descriptor)
        visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        _invalid()
    if (
        not _same(opened, visible)
        or not stat.S_ISDIR(opened.st_mode)
        or stat.S_IMODE(opened.st_mode) != mode
        or opened.st_uid != os.geteuid()
    ):
        os.close(descriptor)
        _invalid()
    return descriptor


def _exact_entries(descriptor: int, expected: frozenset[str]) -> None:
    try:
        names = os.listdir(descriptor)
    except OSError:
        _invalid()
    if len(names) != len(expected) or frozenset(names) != expected:
        _invalid()


def _read_at(
    parent_fd: int,
    name: str,
    *,
    relative: str,
    mode: int,
    maximum: int,
) -> _Record:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError:
        _invalid()
    try:
        before = os.fstat(descriptor)
        visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not _same(before, visible)
            or not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != mode
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum
        ):
            _invalid()
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                _invalid()
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            _invalid()
        after = os.fstat(descriptor)
        visible_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        stable_before = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_gid,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        stable_after = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if stable_before != stable_after or not _same(after, visible_after):
            _invalid()
        value = b"".join(chunks)
        return _Record(
            relative=relative,
            value=value,
            device=before.st_dev,
            inode=before.st_ino,
            mode=stat.S_IMODE(before.st_mode),
            size=before.st_size,
        )
    except OSError:
        _invalid()
    finally:
        os.close(descriptor)


def _read_source_tree(root: Path) -> Mapping[str, _Record]:
    records = {}
    with _open_root(root, mode=0o700) as root_fd:
        _exact_entries(
            root_fd,
            frozenset(
                (
                    "bundle",
                    "identity-sources",
                    "tls",
                    "db-password",
                    "taxonomy-workload",
                    "taxonomy-hmac",
                    "compose.ipam.yaml",
                )
            ),
        )
        for name in sorted(_STANDALONE | frozenset(("compose.ipam.yaml",))):
            maximum = _MAX_COMPOSE if name == "compose.ipam.yaml" else _MAX_SECRET
            records[name] = _read_at(
                root_fd, name, relative=name, mode=0o600, maximum=maximum
            )

        bundle_fd = _open_child(root_fd, "bundle", mode=0o700)
        try:
            _exact_entries(bundle_fd, frozenset(("config", "runtime-secrets")))
            config_fd = _open_child(bundle_fd, "config", mode=0o700)
            try:
                _exact_entries(config_fd, _SOURCE_CONFIG_NAMES)
                for name in sorted(_SOURCE_CONFIG_NAMES):
                    relative = "bundle/config/" + name
                    records[relative] = _read_at(
                        config_fd,
                        name,
                        relative=relative,
                        mode=0o600,
                        maximum=_MAX_CONFIG,
                    )
            finally:
                os.close(config_fd)
            secrets_fd = _open_child(bundle_fd, "runtime-secrets", mode=0o700)
            try:
                _exact_entries(secrets_fd, _BUNDLE_SECRET_NAMES)
                for name in sorted(_BUNDLE_SECRET_NAMES):
                    relative = "bundle/runtime-secrets/" + name
                    records[relative] = _read_at(
                        secrets_fd,
                        name,
                        relative=relative,
                        mode=0o600,
                        maximum=_MAX_SECRET,
                    )
            finally:
                os.close(secrets_fd)
        finally:
            os.close(bundle_fd)

        identity_fd = _open_child(root_fd, "identity-sources", mode=0o700)
        try:
            _exact_entries(identity_fd, _IDENTITY_NAMES)
            for name in sorted(_IDENTITY_NAMES):
                relative = "identity-sources/" + name
                records[relative] = _read_at(
                    identity_fd,
                    name,
                    relative=relative,
                    mode=0o600,
                    maximum=512,
                )
        finally:
            os.close(identity_fd)

        tls_fd = _open_child(root_fd, "tls", mode=0o700)
        try:
            _exact_entries(tls_fd, frozenset(("edge-tls-chain.pem", "edge-tls-key.pem")))
            for name in ("edge-tls-chain.pem", "edge-tls-key.pem"):
                relative = "tls/" + name
                records[relative] = _read_at(
                    tls_fd,
                    name,
                    relative=relative,
                    mode=0o600,
                    maximum=_MAX_TLS,
                )
        finally:
            os.close(tls_fd)

    expected_count = (
        3
        + 1
        + len(_SOURCE_CONFIG_NAMES)
        + len(_BUNDLE_SECRET_NAMES)
        + len(_IDENTITY_NAMES)
        + 2
    )
    if len(records) != expected_count:
        _invalid()
    identities = {(item.device, item.inode) for item in records.values()}
    if len(identities) != len(records):
        _invalid()
    return MappingProxyType(records)


def _read_repository_sources(repository: Path) -> Mapping[str, _Record]:
    repository = _canonical_directory(repository, mode=stat.S_IMODE(repository.stat().st_mode))
    records = {}
    for relative in _REPOSITORY_SOURCES:
        path = repository / relative
        try:
            parent = path.parent.resolve(strict=True)
        except (OSError, RuntimeError):
            _invalid()
        if parent != path.parent or not _within(path, repository):
            _invalid()
        try:
            parent_fd = os.open(
                parent,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
        except OSError:
            _invalid()
        try:
            metadata = path.lstat()
            mode = stat.S_IMODE(metadata.st_mode)
            if mode & 0o022:
                _invalid()
            records[relative] = _read_at(
                parent_fd,
                path.name,
                relative=relative,
                mode=mode,
                maximum=_MAX_COMPOSE,
            )
        finally:
            os.close(parent_fd)
    for relative, expected_sha256 in _PINNED_REPOSITORY_SOURCE_SHA256.items():
        if _sha(records[relative].value) != expected_sha256:
            _invalid()
    return MappingProxyType(records)


def _mkdir_at(parent_fd: int, name: str, *, mode: int = 0o700) -> int:
    try:
        os.mkdir(name, mode=mode, dir_fd=parent_fd)
        return _open_child(parent_fd, name, mode=mode)
    except OSError:
        _invalid()


def _write_at(parent_fd: int, name: str, value: bytes, *, mode: int) -> os.stat_result:
    if type(value) is not bytes or not value:
        _invalid()
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=parent_fd)
    except OSError:
        _invalid()
    try:
        offset = 0
        while offset < len(value):
            written = os.write(descriptor, value[offset:])
            if written <= 0:
                _invalid()
            offset += written
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
        metadata = os.fstat(descriptor)
        visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not _same(metadata, visible)
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or metadata.st_size != len(value)
        ):
            _invalid()
        return metadata
    except OSError:
        _invalid()
    finally:
        os.close(descriptor)


def _stage_metadata(
    relative: str,
    value: bytes,
    metadata: os.stat_result,
    source: _Record,
    *,
    source_kind: str,
) -> Mapping[str, Any]:
    return {
        "sha256": _sha(value),
        "size": len(value),
        "mode": "0444",
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "source": {
            "kind": source_kind,
            "relative_path": source.relative,
            "sha256": _sha(source.value),
            "size": source.size,
            "mode": format(source.mode, "04o"),
            "device": source.device,
            "inode": source.inode,
        },
    }


def _load_snapshot_module(name: str, path: Path, value: bytes) -> ModuleType:
    try:
        module = ModuleType(name)
        module.__file__ = str(path)
        sys.modules[name] = module
        exec(compile(value, str(path), "exec"), module.__dict__)
        return module
    except BaseException:
        sys.modules.pop(name, None)
        _invalid()


def _load_contract(path: Path, value: bytes) -> ModuleType:
    return _load_snapshot_module(
        "_desire_verified_real_oidc_compose_contract", path, value
    )


def _load_production_parsers(
    repository: Path, repository_source: Mapping[str, _Record]
):
    """Load the exact production parser bytes bound into this snapshot."""

    runtime_relative = "platform/src/desire_platform/runtime/config.py"
    secret_relative = "platform/src/desire_platform/internal_pilot/secrets.py"
    module_names = (
        "desire_platform",
        "desire_platform.runtime",
        "desire_platform.runtime.config",
        "_desire_real_oidc_secret_parser",
    )
    missing = object()
    previous = {name: sys.modules.get(name, missing) for name in module_names}
    try:
        package = ModuleType("desire_platform")
        package.__path__ = []
        runtime_package = ModuleType("desire_platform.runtime")
        runtime_package.__path__ = []
        sys.modules["desire_platform"] = package
        sys.modules["desire_platform.runtime"] = runtime_package
        runtime_module = ModuleType("desire_platform.runtime.config")
        runtime_module.__file__ = str(repository / runtime_relative)
        runtime_module.__package__ = "desire_platform.runtime"
        sys.modules["desire_platform.runtime.config"] = runtime_module
        exec(
            compile(
                repository_source[runtime_relative].value,
                runtime_module.__file__,
                "exec",
                dont_inherit=True,
            ),
            runtime_module.__dict__,
        )
        package.runtime = runtime_package
        runtime_package.config = runtime_module
        secret_module = ModuleType("_desire_real_oidc_secret_parser")
        secret_module.__file__ = str(repository / secret_relative)
        secret_module.__package__ = ""
        sys.modules[secret_module.__name__] = secret_module
        exec(
            compile(
                repository_source[secret_relative].value,
                secret_module.__file__,
                "exec",
                dont_inherit=True,
            ),
            secret_module.__dict__,
        )
        parse_runtime = getattr(runtime_module, "parse_runtime_config", None)
        parse_manifest = getattr(secret_module, "parse_file_secret_manifest", None)
        if not callable(parse_runtime) or not callable(parse_manifest):
            _invalid()
        return parse_runtime, parse_manifest
    except PrivateServerRealOidcReleaseInputError:
        raise
    except BaseException:
        _invalid()
    finally:
        for name in reversed(module_names):
            value = previous[name]
            if value is missing:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value


def _closed_material(value: bytes, *, minimum: int, maximum: int) -> None:
    if (
        type(value) is not bytes
        or not minimum <= len(value) <= maximum
        or not any(value)
        or any(token in value for token in (b"\x00", b"\r", b"\n"))
    ):
        _invalid()


def _validate_source_semantics(
    source: Mapping[str, _Record],
    *,
    repository: Path,
    repository_source: Mapping[str, _Record],
) -> None:
    """Close runtime/manifest/material mappings before staging mount copies."""

    try:
        deployment = _json(source["bundle/config/deployment.json"].value)
        if not isinstance(deployment, dict):
            _invalid()
        # The snapshotted Compose contract performs the current full deployment
        # validation (including evolving real-OIDC network binding fields).
        generator_relative = "scripts/private_server_release_inputs.py"
        generator_record = repository_source[generator_relative]
        generator = _load_snapshot_module(
            "_desire_real_oidc_release_generator",
            repository / generator_relative,
            generator_record.value,
        )
        parse_runtime, parse_manifest = _load_production_parsers(
            repository, repository_source
        )
        entry_groups = (
            generator._validate_runtime_and_manifest(
                runtime_raw=source["bundle/config/runtime-config.json"].value,
                manifest_raw=source[
                    "bundle/config/secret-manifest.json"
                ].value,
                parse_runtime=parse_runtime,
                parse_manifest=parse_manifest,
                capabilities=tuple(generator._API_CAPABILITIES),
                key_files=tuple(generator._API_KEY_FILES),
                expected_instance_id="api-0001",
                expected_process_kind="web-api",
            ),
            generator._validate_runtime_and_manifest(
                runtime_raw=source[
                    "bundle/config/matching-runtime-config.json"
                ].value,
                manifest_raw=source[
                    "bundle/config/matching-secret-manifest.json"
                ].value,
                parse_runtime=parse_runtime,
                parse_manifest=parse_manifest,
                capabilities=tuple(
                    generator._MATCHING_RUNTIME_CAPABILITIES
                ),
                key_files=tuple(generator._MATCHING_RUNTIME_KEY_FILES),
                expected_instance_id="matching-runtime-0001",
                expected_process_kind="domain-process",
            ),
            generator._validate_runtime_and_manifest(
                runtime_raw=source[
                    "bundle/config/online-credentials-runtime-config.json"
                ].value,
                manifest_raw=source[
                    "bundle/config/online-credentials-secret-manifest.json"
                ].value,
                parse_runtime=parse_runtime,
                parse_manifest=parse_manifest,
                capabilities=tuple(generator._ONLINE_CAPABILITIES),
                key_files=(),
                expected_instance_id="online-credentials-0001",
                expected_process_kind="migration",
            ),
        )
        if (
            frozenset(generator._BUNDLE_SECRET_FILES)
            != _BUNDLE_SECRET_NAMES
            or frozenset(
                item.file_name
                for entries in entry_groups
                for item in entries
            )
            != _BUNDLE_SECRET_NAMES
        ):
            _invalid()

        secret_material = []
        entries_by_name = {
            entry.file_name: entry
            for entries in entry_groups
            for entry in entries
        }
        for file_name in sorted(_BUNDLE_SECRET_NAMES):
            entry = entries_by_name[file_name]
            material = source[
                "bundle/runtime-secrets/" + file_name
            ].value
            minimum = 24 if entry.kind == "DATABASE_CREDENTIAL" else 32
            _closed_material(material, minimum=minimum, maximum=_MAX_SECRET)
            if entry.purpose == "OIDC_PROTOCOL_AEAD" and len(material) != 32:
                _invalid()
            secret_material.append(material)

        db_password = source["db-password"].value
        taxonomy_workload = source["taxonomy-workload"].value
        taxonomy_hmac = source["taxonomy-hmac"].value
        tls_key = source["tls/edge-tls-key.pem"].value
        _closed_material(db_password, minimum=32, maximum=256)
        _closed_material(taxonomy_workload, minimum=32, maximum=256)
        if len(taxonomy_hmac) != 32 or not any(taxonomy_hmac):
            _invalid()
        if not 32 <= len(tls_key) <= _MAX_TLS or not any(tls_key) or b"\x00" in tls_key:
            _invalid()
        protected_material = secret_material + [
            db_password,
            taxonomy_workload,
            taxonomy_hmac,
            tls_key,
        ]
        material_digests = [
            hashlib.sha256(value).digest() for value in protected_material
        ]
        expected_material_count = len(_BUNDLE_SECRET_NAMES) + 4
        if (
            len(material_digests) != expected_material_count
            or len(set(material_digests)) != expected_material_count
        ):
            _invalid()

        accounts = sorted(
            name[:-8] for name in _IDENTITY_NAMES if name.endswith(".subject")
        )
        subjects = []
        emails = []
        for account in accounts:
            subject_raw = source[f"identity-sources/{account}.subject"].value
            email_raw = source[f"identity-sources/{account}.email"].value
            try:
                subject = subject_raw.decode("utf-8", errors="strict")
                email = email_raw.decode("utf-8", errors="strict")
            except UnicodeError:
                _invalid()
            if (
                subject != subject.strip()
                or email != email.strip()
                or not subject
                or not email
                or "@" not in email
                or any(
                    ord(character) < 0x20 or ord(character) == 0x7F
                    for character in subject + email
                )
            ):
                _invalid()
            subjects.append(subject)
            emails.append(email.casefold())
        if len(subjects) != 10 or len(set(subjects)) != 10 or len(set(emails)) != 10:
            _invalid()
    except PrivateServerRealOidcReleaseInputError:
        raise
    except BaseException:
        _invalid()


def _checked_compose(result: object) -> bytes:
    returncode = getattr(result, "returncode", None)
    stdout = getattr(result, "stdout", None)
    stderr = getattr(result, "stderr", None)
    if isinstance(stdout, str):
        stdout = stdout.encode("utf-8")
    if isinstance(stderr, str):
        stderr = stderr.encode("utf-8")
    if (
        type(returncode) is not int
        or returncode != 0
        or type(stdout) is not bytes
        or type(stderr) is not bytes
        or stderr
        or not 0 < len(stdout) <= _MAX_COMPOSE
    ):
        _invalid()
    document = _json(stdout)
    if not isinstance(document, dict):
        _invalid()
    return _canonical_json(document)


def _default_compose_runner(
    command: Sequence[str], environment: Mapping[str, str]
) -> object:
    return subprocess.run(
        list(command),
        cwd="/",
        env=dict(environment),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )


def _reviewed_document(reviewed: RealOidcReviewedInputs) -> Mapping[str, str]:
    if (
        not isinstance(reviewed, RealOidcReviewedInputs)
        or _PROJECT.fullmatch(reviewed.project_name) is None
        or _IMAGE_TAG.fullmatch(reviewed.image_tag) is None
    ):
        _invalid()
    for value in (
        reviewed.pilot_hostname,
        reviewed.oidc_issuer,
        reviewed.oidc_client_id,
        reviewed.oidc_pinned_public_ipv4,
        reviewed.db_data_ipv4,
        reviewed.ingress_ip,
    ):
        if (
            not isinstance(value, str)
            or not value
            or value != value.strip()
            or not value.isascii()
            or "\x00" in value
        ):
            _invalid()
    try:
        pinned = ipaddress.ip_address(reviewed.oidc_pinned_public_ipv4)
    except ValueError:
        _invalid()
    if (
        not isinstance(pinned, ipaddress.IPv4Address)
        or not pinned.is_global
        or str(pinned) != reviewed.oidc_pinned_public_ipv4
    ):
        _invalid()
    try:
        database = ipaddress.ip_address(reviewed.db_data_ipv4)
    except ValueError:
        _invalid()
    if (
        not isinstance(database, ipaddress.IPv4Address)
        or str(database) != reviewed.db_data_ipv4
        or not any(database in network for network in _RFC1918)
        or database.is_loopback
        or database.is_multicast
        or database.is_unspecified
    ):
        _invalid()
    return {
        "project_name": reviewed.project_name,
        "pilot_hostname": reviewed.pilot_hostname,
        "oidc_issuer": reviewed.oidc_issuer,
        "oidc_client_id": reviewed.oidc_client_id,
        "oidc_pinned_public_ipv4": reviewed.oidc_pinned_public_ipv4,
        "db_data_ipv4": reviewed.db_data_ipv4,
        "image_tag": reviewed.image_tag,
        "ingress_ip": reviewed.ingress_ip,
    }


def stage_real_oidc_release_inputs(
    *,
    input_root: Path,
    attempt_root: Path,
    reviewed: RealOidcReviewedInputs,
    repository_root: Path = _ROOT,
    compose_runner: Callable[[Sequence[str], Mapping[str, str]], object] = _default_compose_runner,
) -> RealOidcReleaseInputSnapshot:
    """Copy one closed source tree and bind its canonical Compose document."""

    try:
        reviewed_values = _reviewed_document(reviewed)
        source_root = _canonical_directory(input_root, mode=0o700)
        stage_root = _canonical_directory(attempt_root, mode=0o700, empty=True)
        repository = repository_root.resolve(strict=True)
        try:
            stage_parent = stage_root.parent.resolve(strict=True)
            stage_parent_metadata = stage_parent.stat()
        except (OSError, RuntimeError):
            _invalid()
        if (
            stage_root.name != reviewed.project_name
            or stage_parent != stage_root.parent
            or not stat.S_ISDIR(stage_parent_metadata.st_mode)
            or stage_parent_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(stage_parent_metadata.st_mode) != 0o700
            or source_root == stage_root
            or _within(source_root, stage_root)
            or _within(stage_root, source_root)
            or _within(source_root, repository)
            or _within(repository, source_root)
            or _within(stage_root, repository)
            or _within(repository, stage_root)
        ):
            _invalid()
        source = _read_source_tree(source_root)
        repository_source = _read_repository_sources(repository)
        contract_record = repository_source[
            "scripts/private_server_real_oidc_compose_contract.py"
        ]
        contract = _load_contract(
            repository / contract_record.relative, contract_record.value
        )
        guard_record = repository_source[
            "deploy/private-server-real-oidc-egress-guard.py"
        ]
        guard = _load_snapshot_module(
            "_desire_verified_real_oidc_egress_guard",
            repository / guard_record.relative,
            guard_record.value,
        )
        if (
            frozenset(contract._BUNDLE_SECRET_NAMES) != _BUNDLE_SECRET_NAMES
            or frozenset(contract._IDENTITY_SOURCE_NAMES) != _IDENTITY_NAMES
            or not callable(getattr(contract, "oidc_egress_projection_sha256", None))
            or not callable(getattr(guard, "projection_sha256", None))
            or not callable(getattr(guard, "canonical_projection", None))
        ):
            _invalid()
        projection_sha256 = _egress_projection_sha256(
            reviewed.db_data_ipv4, reviewed.oidc_pinned_public_ipv4
        )
        if (
            contract.oidc_egress_projection_sha256(
                reviewed.db_data_ipv4, reviewed.oidc_pinned_public_ipv4
            )
            != projection_sha256
            or contract.oidc_egress_projection_bytes(
                reviewed.db_data_ipv4, reviewed.oidc_pinned_public_ipv4
            )
            != _egress_projection_bytes(
                reviewed.db_data_ipv4, reviewed.oidc_pinned_public_ipv4
            )
            or
            guard.projection_sha256(
                reviewed.db_data_ipv4, reviewed.oidc_pinned_public_ipv4
            )
            != projection_sha256
            or guard.canonical_projection(
                reviewed.db_data_ipv4, reviewed.oidc_pinned_public_ipv4
            )
            != contract.oidc_egress_projection_bytes(
                reviewed.db_data_ipv4, reviewed.oidc_pinned_public_ipv4
            )
        ):
            _invalid()
        _validate_source_semantics(
            source,
            repository=repository,
            repository_source=repository_source,
        )
        mounted = {}

        with _open_root(stage_root, mode=0o700, empty=True) as stage_fd:
            bundle_fd = _mkdir_at(stage_fd, "bundle")
            identity_fd = _mkdir_at(stage_fd, "identity-sources")
            tls_fd = _mkdir_at(stage_fd, "tls")
            repository_fd = _mkdir_at(stage_fd, "repository")
            config_fd = _mkdir_at(bundle_fd, "config")
            secret_fd = _mkdir_at(bundle_fd, "runtime-secrets")
            try:
                for name in sorted(_SOURCE_CONFIG_NAMES):
                    relative = "bundle/config/" + name
                    record = source[relative]
                    metadata = _write_at(config_fd, name, record.value, mode=0o444)
                    mounted[relative] = _stage_metadata(
                        relative, record.value, metadata, record, source_kind="operator"
                    )
                injected = (
                    (
                        "identity-bootstrap-template.json",
                        "platform/examples/internal-sandbox-identity-bootstrap-template-v1.json",
                    ),
                    ("Caddyfile.real-oidc", "deploy/Caddyfile.real-oidc"),
                )
                for name, repository_relative in injected:
                    relative = "bundle/config/" + name
                    record = repository_source[repository_relative]
                    metadata = _write_at(config_fd, name, record.value, mode=0o444)
                    mounted[relative] = _stage_metadata(
                        relative,
                        record.value,
                        metadata,
                        record,
                        source_kind="repository",
                    )
                for name in sorted(_BUNDLE_SECRET_NAMES):
                    relative = "bundle/runtime-secrets/" + name
                    record = source[relative]
                    metadata = _write_at(secret_fd, name, record.value, mode=0o444)
                    mounted[relative] = _stage_metadata(
                        relative, record.value, metadata, record, source_kind="operator"
                    )
                for name in sorted(_IDENTITY_NAMES):
                    relative = "identity-sources/" + name
                    record = source[relative]
                    metadata = _write_at(identity_fd, name, record.value, mode=0o444)
                    mounted[relative] = _stage_metadata(
                        relative, record.value, metadata, record, source_kind="operator"
                    )
                for name in ("edge-tls-chain.pem", "edge-tls-key.pem"):
                    relative = "tls/" + name
                    record = source[relative]
                    metadata = _write_at(tls_fd, name, record.value, mode=0o444)
                    mounted[relative] = _stage_metadata(
                        relative, record.value, metadata, record, source_kind="operator"
                    )
                for name in sorted(_STANDALONE):
                    record = source[name]
                    metadata = _write_at(stage_fd, name, record.value, mode=0o444)
                    mounted[name] = _stage_metadata(
                        name, record.value, metadata, record, source_kind="operator"
                    )
                ipam = source["compose.ipam.yaml"]
                _write_at(stage_fd, "compose.ipam.yaml", ipam.value, mode=0o444)
                for repository_relative, snapshot_name in _REPOSITORY_SNAPSHOT_NAMES.items():
                    record = repository_source[repository_relative]
                    _write_at(repository_fd, snapshot_name, record.value, mode=0o444)

                if frozenset(mounted) != _MOUNTED_PATHS:
                    _invalid()
                staged_inodes = {
                    (item["device"], item["inode"]) for item in mounted.values()
                }
                if len(staged_inodes) != len(mounted):
                    _invalid()

                for descriptor in (config_fd, secret_fd, bundle_fd, identity_fd, tls_fd, repository_fd):
                    os.fchmod(descriptor, 0o555)

                compose_files = (
                    stage_root / "repository/compose.yaml",
                    stage_root / "repository/private-server.compose.yaml",
                    stage_root / "compose.ipam.yaml",
                    stage_root / "repository/private-server-real-oidc.compose.yaml",
                )
                command = (
                    "/usr/bin/docker",
                    "compose",
                    "--project-directory",
                    str(repository),
                    "--project-name",
                    reviewed.project_name,
                    "-f",
                    str(compose_files[0]),
                    "-f",
                    str(compose_files[1]),
                    "-f",
                    str(compose_files[2]),
                    "-f",
                    str(compose_files[3]),
                    "config",
                    "--format",
                    "json",
                )
                environment = MappingProxyType(
                    {
                        "PATH": "/usr/local/bin:/usr/bin:/bin",
                        "HOME": "/nonexistent",
                        "LANG": "C.UTF-8",
                        "LC_ALL": "C.UTF-8",
                        "DESIRE_REAL_OIDC_PROJECT_NAME": reviewed.project_name,
                        "DESIRE_REAL_OIDC_PILOT_HOSTNAME": reviewed.pilot_hostname,
                        "DESIRE_REAL_OIDC_BUNDLE_DIR": str(stage_root / "bundle"),
                        "DESIRE_REAL_OIDC_IDENTITY_SOURCE_DIR": str(
                            stage_root / "identity-sources"
                        ),
                        "DESIRE_REAL_OIDC_TLS_DIR": str(stage_root / "tls"),
                        "DESIRE_REAL_OIDC_DB_PASSWORD_FILE": str(
                            stage_root / "db-password"
                        ),
                        "DESIRE_REAL_OIDC_TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE": str(
                            stage_root / "taxonomy-workload"
                        ),
                        "DESIRE_REAL_OIDC_TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE": str(
                            stage_root / "taxonomy-hmac"
                        ),
                        "DESIRE_PRIVATE_INGRESS_IP": reviewed.ingress_ip,
                        "DESIRE_REAL_OIDC_DB_DATA_IPV4": reviewed.db_data_ipv4,
                        "DESIRE_REAL_OIDC_PINNED_PUBLIC_IPV4": (
                            reviewed.oidc_pinned_public_ipv4
                        ),
                        "DESIRE_REAL_OIDC_EGRESS_PROJECTION_SHA256": (
                            projection_sha256
                        ),
                        "DESIRE_IMAGE_TAG": reviewed.image_tag,
                    }
                )
                canonical_compose = _checked_compose(compose_runner(command, environment))
                contract.validate_private_server_real_oidc_compose(
                    canonical_compose,
                    reviewed=contract.ReviewedRealOidcInputs(
                        project_name=reviewed.project_name,
                        pilot_hostname=reviewed.pilot_hostname,
                        oidc_issuer=reviewed.oidc_issuer,
                        oidc_client_id=reviewed.oidc_client_id,
                        oidc_pinned_public_ipv4=reviewed.oidc_pinned_public_ipv4,
                        db_data_ipv4=reviewed.db_data_ipv4,
                        image_tag=reviewed.image_tag,
                        bundle_dir=str(stage_root / "bundle"),
                        identity_source_dir=str(stage_root / "identity-sources"),
                        tls_dir=str(stage_root / "tls"),
                        ingress_ip=reviewed.ingress_ip,
                    ),
                    repository_root=str(repository),
                )
                compose_metadata = _write_at(
                    stage_fd, "resolved.compose.json", canonical_compose, mode=0o400
                )
                compose_document = _json(canonical_compose)
                services = compose_document.get("services")
                if not isinstance(services, dict):
                    _invalid()
                image_references = tuple(
                    sorted(
                        {
                            service.get("image")
                            for service in services.values()
                            if isinstance(service, dict)
                        }
                    )
                )
                if (
                    len(image_references) != 5
                    or any(not isinstance(value, str) or not value for value in image_references)
                ):
                    _invalid()

                source_inventory = {
                    name: {
                        "sha256": _sha(record.value),
                        "size": record.size,
                        "mode": format(record.mode, "04o"),
                        "device": record.device,
                        "inode": record.inode,
                    }
                    for name, record in sorted(source.items())
                }
                source_tree_sha256 = _sha(_canonical_json(source_inventory))
                repository_inventory = {
                    name: {
                        "sha256": _sha(record.value),
                        "size": record.size,
                        "mode": format(record.mode, "04o"),
                    }
                    for name, record in sorted(repository_source.items())
                }
                manifest = {
                    "format": "desire-real-oidc-release-input-snapshot-v1",
                    "project": reviewed.project_name,
                    "reviewed": reviewed_values,
                    "source_tree_sha256": source_tree_sha256,
                    "source_inventory": source_inventory,
                    "repository_sources": repository_inventory,
                    "mounted_sources": mounted,
                    "compose": {
                        "relative_path": "resolved.compose.json",
                        "sha256": _sha(canonical_compose),
                        "size": len(canonical_compose),
                        "mode": "0400",
                        "device": compose_metadata.st_dev,
                        "inode": compose_metadata.st_ino,
                    },
                    "oidc_egress_projection": {
                        "format": "desire-real-oidc-egress-projection-v1",
                        "sha256": projection_sha256,
                        "db_data_ipv4": reviewed.db_data_ipv4,
                        "db_port": 5432,
                        "oidc_pinned_public_ipv4": (
                            reviewed.oidc_pinned_public_ipv4
                        ),
                        "oidc_port": 443,
                        "output_policy": "DROP",
                        "dns": "REJECT",
                        "ipv6": "REJECT",
                        "ipv4_other": "REJECT",
                    },
                    "image_references": list(image_references),
                    "rollback": {
                        "postgres_volume": reviewed.project_name + "_postgres-data",
                        "policy": "PRESERVE_VOLUME",
                    },
                }
                manifest_raw = _canonical_json(manifest)
                manifest_metadata = _write_at(
                    stage_fd, "snapshot-manifest.json", manifest_raw, mode=0o400
                )
                _exact_entries(stage_fd, _ROOT_ENTRIES)
            finally:
                for descriptor in (
                    config_fd,
                    secret_fd,
                    repository_fd,
                    tls_fd,
                    identity_fd,
                    bundle_fd,
                ):
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass

        return RealOidcReleaseInputSnapshot(
            attempt_root=stage_root,
            project_name=reviewed.project_name,
            snapshot_sha256=_sha(manifest_raw),
            manifest_device=manifest_metadata.st_dev,
            manifest_inode=manifest_metadata.st_ino,
            compose_sha256=_sha(canonical_compose),
            oidc_pinned_public_ipv4=reviewed.oidc_pinned_public_ipv4,
            db_data_ipv4=reviewed.db_data_ipv4,
            oidc_egress_projection_sha256=projection_sha256,
            image_references=image_references,
        )
    except PrivateServerRealOidcReleaseInputError:
        raise
    except BaseException:
        _invalid()


def _read_stage_file(
    root_fd: int, relative: str, *, mode: int, maximum: int
) -> _Record:
    parts = relative.split("/")
    if any(not part or part in (".", "..") for part in parts):
        _invalid()
    descriptor = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            next_descriptor = _open_child(descriptor, part, mode=0o555)
            os.close(descriptor)
            descriptor = next_descriptor
        return _read_at(
            descriptor,
            parts[-1],
            relative=relative,
            mode=mode,
            maximum=maximum,
        )
    finally:
        os.close(descriptor)


def load_real_oidc_release_snapshot(
    attempt_root: Path,
) -> tuple[RealOidcReleaseInputSnapshot, Mapping[str, Any], bytes]:
    """Re-open and verify every immutable file named by a snapshot manifest."""

    try:
        root = _canonical_directory(attempt_root, mode=0o700)
        try:
            parent = root.parent.resolve(strict=True)
            parent_metadata = parent.stat()
        except (OSError, RuntimeError):
            _invalid()
        if (
            parent != root.parent
            or not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(parent_metadata.st_mode) != 0o700
        ):
            _invalid()
        with _open_root(root, mode=0o700) as root_fd:
            _exact_entries(root_fd, _ROOT_ENTRIES)
            manifest_record = _read_at(
                root_fd,
                "snapshot-manifest.json",
                relative="snapshot-manifest.json",
                mode=0o400,
                maximum=_MAX_COMPOSE,
            )
            manifest = _json(manifest_record.value)
            expected_keys = frozenset(
                (
                    "format",
                    "project",
                    "reviewed",
                    "source_tree_sha256",
                    "source_inventory",
                    "repository_sources",
                    "mounted_sources",
                    "compose",
                    "oidc_egress_projection",
                    "image_references",
                    "rollback",
                )
            )
            if (
                not isinstance(manifest, dict)
                or frozenset(manifest) != expected_keys
                or manifest.get("format")
                != "desire-real-oidc-release-input-snapshot-v1"
                or _PROJECT.fullmatch(manifest.get("project", "")) is None
                or _SHA256.fullmatch(manifest.get("source_tree_sha256", "")) is None
                or _canonical_json(manifest) != manifest_record.value
                or root.name != manifest.get("project")
            ):
                _invalid()
            source_inventory = manifest.get("source_inventory")
            expected_source_paths = (
                {"compose.ipam.yaml", *_STANDALONE}
                | {f"bundle/config/{name}" for name in _SOURCE_CONFIG_NAMES}
                | {
                    f"bundle/runtime-secrets/{name}"
                    for name in _BUNDLE_SECRET_NAMES
                }
                | {f"identity-sources/{name}" for name in _IDENTITY_NAMES}
                | {"tls/edge-tls-chain.pem", "tls/edge-tls-key.pem"}
            )
            if (
                not isinstance(source_inventory, dict)
                or frozenset(source_inventory) != frozenset(expected_source_paths)
                or _sha(_canonical_json(source_inventory))
                != manifest["source_tree_sha256"]
            ):
                _invalid()
            for item in source_inventory.values():
                if (
                    not isinstance(item, dict)
                    or frozenset(item)
                    != frozenset(("sha256", "size", "mode", "device", "inode"))
                    or _SHA256.fullmatch(item.get("sha256", "")) is None
                    or type(item.get("size")) is not int
                    or item["size"] <= 0
                    or item.get("mode") != "0600"
                    or type(item.get("device")) is not int
                    or type(item.get("inode")) is not int
                ):
                    _invalid()
            repository_sources = manifest.get("repository_sources")
            if (
                not isinstance(repository_sources, dict)
                or frozenset(repository_sources) != frozenset(_REPOSITORY_SOURCES)
            ):
                _invalid()
            for item in repository_sources.values():
                if (
                    not isinstance(item, dict)
                    or frozenset(item) != frozenset(("sha256", "size", "mode"))
                    or _SHA256.fullmatch(item.get("sha256", "")) is None
                    or type(item.get("size")) is not int
                    or item["size"] <= 0
                    or not isinstance(item.get("mode"), str)
                ):
                    _invalid()
            mounted = manifest.get("mounted_sources")
            if not isinstance(mounted, dict) or frozenset(mounted) != _MOUNTED_PATHS:
                _invalid()
            observed_inodes = set()
            for relative, expected in mounted.items():
                if not isinstance(expected, dict):
                    _invalid()
                record = _read_stage_file(root_fd, relative, mode=0o444, maximum=_MAX_TLS)
                if (
                    expected.get("sha256") != _sha(record.value)
                    or expected.get("size") != record.size
                    or expected.get("mode") != "0444"
                    or expected.get("device") != record.device
                    or expected.get("inode") != record.inode
                    or frozenset(expected)
                    != frozenset(("sha256", "size", "mode", "device", "inode", "source"))
                    or not isinstance(expected.get("source"), dict)
                ):
                    _invalid()
                source = expected["source"]
                if (
                    frozenset(source)
                    != frozenset(
                        (
                            "kind",
                            "relative_path",
                            "sha256",
                            "size",
                            "mode",
                            "device",
                            "inode",
                        )
                    )
                    or source.get("kind") not in ("operator", "repository")
                    or _SHA256.fullmatch(source.get("sha256", "")) is None
                    or source.get("sha256") != expected.get("sha256")
                    or source.get("size") != expected.get("size")
                    or type(source.get("device")) is not int
                    or type(source.get("inode")) is not int
                ):
                    _invalid()
                observed_inodes.add((record.device, record.inode))
            if len(observed_inodes) != len(mounted):
                _invalid()
            bundle_descriptor = _open_child(root_fd, "bundle", mode=0o555)
            try:
                _exact_entries(
                    bundle_descriptor, frozenset(("config", "runtime-secrets"))
                )
            finally:
                os.close(bundle_descriptor)
            # Close-directory inventory checks use short-lived descriptors below.
            for relative, names in (
                ("bundle/config", _STAGED_CONFIG_NAMES),
                ("bundle/runtime-secrets", _BUNDLE_SECRET_NAMES),
                ("identity-sources", _IDENTITY_NAMES),
                ("tls", frozenset(("edge-tls-chain.pem", "edge-tls-key.pem"))),
                (
                    "repository",
                    frozenset(_REPOSITORY_SNAPSHOT_NAMES.values()),
                ),
            ):
                descriptor = os.dup(root_fd)
                try:
                    for part in relative.split("/"):
                        next_descriptor = _open_child(descriptor, part, mode=0o555)
                        os.close(descriptor)
                        descriptor = next_descriptor
                    _exact_entries(descriptor, names)
                finally:
                    os.close(descriptor)
            ipam = _read_at(
                root_fd,
                "compose.ipam.yaml",
                relative="compose.ipam.yaml",
                mode=0o444,
                maximum=_MAX_COMPOSE,
            )
            del ipam
            staged_repository = {}
            for name in _REPOSITORY_SNAPSHOT_NAMES.values():
                record = _read_stage_file(
                    root_fd,
                    "repository/" + name,
                    mode=0o444,
                    maximum=_MAX_COMPOSE,
                )
                source_relative = next(
                    key
                    for key, value in _REPOSITORY_SNAPSHOT_NAMES.items()
                    if value == name
                )
                observed_sha256 = _sha(record.value)
                pinned_sha256 = _PINNED_REPOSITORY_SOURCE_SHA256.get(
                    source_relative
                )
                if (
                    repository_sources[source_relative]["sha256"]
                    != observed_sha256
                    or pinned_sha256 is not None
                    and observed_sha256 != pinned_sha256
                ):
                    _invalid()
                staged_repository[source_relative] = record
            compose = _read_at(
                root_fd,
                "resolved.compose.json",
                relative="resolved.compose.json",
                mode=0o400,
                maximum=_MAX_COMPOSE,
            )
            compose_info = manifest.get("compose")
            if (
                not isinstance(compose_info, dict)
                or frozenset(compose_info)
                != frozenset(("relative_path", "sha256", "size", "mode", "device", "inode"))
                or compose_info.get("relative_path") != "resolved.compose.json"
                or compose_info.get("sha256") != _sha(compose.value)
                or compose_info.get("size") != compose.size
                or compose_info.get("mode") != "0400"
                or compose_info.get("device") != compose.device
                or compose_info.get("inode") != compose.inode
            ):
                _invalid()
            document = _json(compose.value)
            if _canonical_json(document) != compose.value:
                _invalid()
            services = document.get("services") if isinstance(document, dict) else None
            images = tuple(
                sorted(
                    {
                        service.get("image")
                        for service in services.values()
                        if isinstance(service, dict)
                    }
                )
            ) if isinstance(services, dict) else ()
            if list(images) != manifest.get("image_references") or len(images) != 5:
                _invalid()
            reviewed = manifest.get("reviewed")
            if (
                not isinstance(reviewed, dict)
                or frozenset(reviewed)
                != frozenset(
                    (
                        "project_name",
                        "pilot_hostname",
                        "oidc_issuer",
                        "oidc_client_id",
                        "oidc_pinned_public_ipv4",
                        "db_data_ipv4",
                        "image_tag",
                        "ingress_ip",
                    )
                )
                or reviewed.get("project_name") != manifest.get("project")
            ):
                _invalid()
            if "deploy/private-server-real-oidc-egress-guard.py" not in staged_repository:
                _invalid()
            projection_sha256 = _egress_projection_sha256(
                reviewed["db_data_ipv4"], reviewed["oidc_pinned_public_ipv4"]
            )
            projection = manifest.get("oidc_egress_projection")
            if projection != {
                "format": "desire-real-oidc-egress-projection-v1",
                "sha256": projection_sha256,
                "db_data_ipv4": reviewed["db_data_ipv4"],
                "db_port": 5432,
                "oidc_pinned_public_ipv4": reviewed[
                    "oidc_pinned_public_ipv4"
                ],
                "oidc_port": 443,
                "output_policy": "DROP",
                "dns": "REJECT",
                "ipv6": "REJECT",
                "ipv4_other": "REJECT",
            }:
                _invalid()
            rollback = manifest.get("rollback")
            if rollback != {
                "postgres_volume": manifest["project"] + "_postgres-data",
                "policy": "PRESERVE_VOLUME",
            }:
                _invalid()
            snapshot = RealOidcReleaseInputSnapshot(
                attempt_root=root,
                project_name=manifest["project"],
                snapshot_sha256=_sha(manifest_record.value),
                manifest_device=manifest_record.device,
                manifest_inode=manifest_record.inode,
                compose_sha256=_sha(compose.value),
                oidc_pinned_public_ipv4=reviewed["oidc_pinned_public_ipv4"],
                db_data_ipv4=reviewed["db_data_ipv4"],
                oidc_egress_projection_sha256=projection_sha256,
                image_references=images,
            )
            return snapshot, MappingProxyType(manifest), compose.value
    except PrivateServerRealOidcReleaseInputError:
        raise
    except BaseException:
        _invalid()


def _cli_reviewed(arguments) -> RealOidcReviewedInputs:
    return RealOidcReviewedInputs(
        project_name=arguments.project,
        pilot_hostname=arguments.pilot_hostname,
        oidc_issuer=arguments.oidc_issuer,
        oidc_client_id=arguments.oidc_client_id,
        oidc_pinned_public_ipv4=arguments.oidc_pinned_public_ipv4,
        db_data_ipv4=arguments.db_data_ipv4,
        image_tag=arguments.image_tag,
        ingress_ip=arguments.ingress_ip,
    )


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    import argparse

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--action", choices=("check", "stage"), default="check")
    parser.add_argument("--attempt-root")
    parser.add_argument("--input-root")
    parser.add_argument("--project")
    parser.add_argument("--pilot-hostname")
    parser.add_argument("--oidc-issuer")
    parser.add_argument("--oidc-client-id")
    parser.add_argument("--oidc-pinned-public-ipv4")
    parser.add_argument("--db-data-ipv4")
    parser.add_argument("--image-tag")
    parser.add_argument("--ingress-ip")
    try:
        arguments = parser.parse_args(tuple(sys.argv[1:] if argv is None else argv))
        if not arguments.attempt_root:
            _invalid()
        attempt = Path(arguments.attempt_root)
        if arguments.action == "check":
            if any(
                value is not None
                for value in (
                    arguments.input_root,
                    arguments.project,
                    arguments.pilot_hostname,
                    arguments.oidc_issuer,
                    arguments.oidc_client_id,
                    arguments.oidc_pinned_public_ipv4,
                    arguments.db_data_ipv4,
                    arguments.image_tag,
                    arguments.ingress_ip,
                )
            ):
                _invalid()
            load_real_oidc_release_snapshot(attempt)
            stdout.write(VERIFIED)
            return 0
        if any(
            value is None
            for value in (
                arguments.input_root,
                arguments.project,
                arguments.pilot_hostname,
                arguments.oidc_issuer,
                arguments.oidc_client_id,
                arguments.oidc_pinned_public_ipv4,
                arguments.db_data_ipv4,
                arguments.image_tag,
                arguments.ingress_ip,
            )
        ):
            _invalid()
        stage_real_oidc_release_inputs(
            input_root=Path(arguments.input_root),
            attempt_root=attempt,
            reviewed=_cli_reviewed(arguments),
        )
        stdout.write(READY)
        return 0
    except (PrivateServerRealOidcReleaseInputError, SystemExit):
        stdout.write(BLOCKED)
        return 2
    except BaseException:
        stdout.write(BLOCKED)
        return 2
    finally:
        del stderr


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = (
    "PrivateServerRealOidcReleaseInputError",
    "RealOidcReleaseInputSnapshot",
    "RealOidcReviewedInputs",
    "load_real_oidc_release_snapshot",
    "stage_real_oidc_release_inputs",
)
