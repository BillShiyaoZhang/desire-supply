#!/usr/bin/env python3
"""Receipt-bound lifecycle control for one activated private INTERNAL_SANDBOX."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from types import MappingProxyType
from typing import Callable, Mapping, NoReturn, Optional, Sequence, TextIO


_ROOT = Path(__file__).resolve().parents[1]
_ATTEMPTS_ROOT = Path("/var/lib/desire/private-ingress-attempts")
_DOCKER = "/usr/bin/docker"
_SS = "/usr/bin/ss"
_DOCKER_ENDPOINT = "unix:///var/run/docker.sock"
_COMPOSE_VERSION = "5.3.1\n"
_COMPOSE_PLUGIN_PATHS = frozenset(
    (
        "/usr/local/lib/docker/cli-plugins/docker-compose",
        "/usr/local/libexec/docker/cli-plugins/docker-compose",
        "/usr/lib/docker/cli-plugins/docker-compose",
        "/usr/libexec/docker/cli-plugins/docker-compose",
    )
)
_TRUSTED_PATH = "/usr/sbin:/usr/bin"
_MAX_FILE = 4 * 1024 * 1024
_MAX_OUTPUT = 4 * 1024 * 1024
_MAX_CONTAINERS = 1024
_CONSUMER_FORMAT = (
    '{"Id":{{json .Id}},"Mounts":{{json .Mounts}},'
    '"Networks":{{json .NetworkSettings.Networks}}}'
)

_PROJECT = re.compile(
    r"^desire-private-ingress-(?:[a-z0-9]|[a-z0-9][a-z0-9-]{0,38}[a-z0-9])$"
)
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FROZEN_PROJECTS = frozenset(
    {"desire-supply-e2e-ten-account-v13", "desire-restore-verify-v13drill01"}
)
_RFC1918 = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)

_PERSISTENT = (
    "db", "synthetic-oidc", "edge", "matching-runtime", "api", "web",
)
_STOP_ORDER = tuple(reversed(_PERSISTENT))
_ONE_SHOTS = (
    "migrate",
    "taxonomy-seed",
    "online-credentials-reconcile",
    "online-credentials-verify",
    "identity-bootstrap",
)
_SERVICES = _PERSISTENT + _ONE_SHOTS
_NETWORKS = ("app", "data", "ingress", "oidc-backend")
_INTERNAL_NETWORKS = frozenset(("app", "data", "oidc-backend"))
_SERVICE_NETWORKS = {
    "db": frozenset(("data",)),
    "migrate": frozenset(("data",)),
    "taxonomy-seed": frozenset(("data",)),
    "online-credentials-reconcile": frozenset(("data",)),
    "online-credentials-verify": frozenset(("data",)),
    "identity-bootstrap": frozenset(("data",)),
    "synthetic-oidc": frozenset(("oidc-backend",)),
    "matching-runtime": frozenset(("data",)),
    "api": frozenset(("app", "data")),
    "web": frozenset(("app",)),
    "edge": frozenset(("app", "ingress", "oidc-backend")),
}
_STOP_SECONDS = {
    "web": 30,
    "api": 20,
    "matching-runtime": 30,
    "edge": 30,
    "synthetic-oidc": 30,
    "db": 60,
}

_BUNDLE_CONFIG_FILES = (
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

_CONFIG_NAMES = frozenset(
    (
        "internal-sandbox-deployment",
        "internal-sandbox-runtime-config",
        "internal-sandbox-secret-manifest",
        "internal-sandbox-matching-deployment",
        "internal-sandbox-matching-runtime-config",
        "internal-sandbox-matching-secret-manifest",
        "internal-sandbox-online-credentials-deployment",
        "internal-sandbox-online-credentials-runtime-config",
        "internal-sandbox-online-credentials-secret-manifest",
        "internal-sandbox-identity-template",
        "internal-sandbox-root-ca",
        "internal-sandbox-edge-tls-chain",
    )
)
_RUNTIME_SECRETS = frozenset(
    (
        "db-iam-app-v1", "db-iam-session-authenticator-v1",
        "db-iam-onboarding-v1", "db-profile-app-v1", "db-demand-self-v1",
        "db-demand-review-v1", "db-demand-finance-v1", "db-trust-self-v1",
        "db-trust-officer-v1", "db-trust-appeal-v1", "db-trust-decision-v1",
        "db-matching-creator-v1", "db-matching-selector-v1",
        "db-matching-assignment-v1", "db-matching-review-v1",
        "db-demand-matching-v1", "db-profile-matcher-v1",
        "db-matching-worker-v1", "db-matching-coordinator-v1",
        "key-oidc-state-v1", "key-oidc-browser-binding-v1", "key-oidc-nonce-v1",
        "key-session-handle-v1", "key-csrf-v1", "key-oidc-protocol-aead-v1",
        "key-oidc-subject-digest-v1", "key-oidc-recipient-binding-v1",
        "key-oidc-client-secret-v1", "key-editor-id-derivation-v1",
        "key-profile-idempotency-v1", "key-profile-payload-hash-v1",
        "key-demand-idempotency-v1", "key-demand-idempotency-retained-2025-12",
        "key-demand-payload-hash-v1", "key-demand-payload-retained-2025-12",
        "key-demand-client-reference-v1", "key-iam-receipt-idempotency-hmac-2026-01",
        "key-iam-receipt-payload-hmac-2026-01", "key-access-invitation-token-v1",
        "key-iam-read-cursor-v1", "key-trust-idempotency-v1",
        "key-trust-payload-hash-v1", "key-trust-sealed-note-v1",
        "key-trust-report-cursor-v1",
        "key-matching-idempotency-v1", "key-matching-payload-v1",
        "key-matching-read-cursor-v1",
        "key-matching-worker-idempotency-v1",
        "key-matching-worker-payload-hash-v1",
        "key-matching-worker-lease-digest-v1",
        "key-matching-coordinator-idempotency-v1",
        "key-matching-coordinator-payload-hash-v1",
        "key-matching-coordinator-lease-digest-v1",
    )
)
_SECRET_NAMES = _RUNTIME_SECRETS | frozenset(
    ("db_superuser_password", "taxonomy_seed_workload_credential",
     "taxonomy_seed_receipt_hmac_key", "edge-tls-key")
)
_IDENTITY_FILES = frozenset(
    f"{account}.{field}"
    for account in (
        "access_admin_01", "appeal_reviewer_01", "creator_01",
        "demand_owner_01", "finance_operator_01", "finance_operator_02",
        "operations_reviewer_01", "org_admin_01", "trust_officer_01",
        "trust_officer_02",
    )
    for field in ("email", "subject")
)
_SOURCE_SHA256 = {
    "compose.yaml": "325919f3066d9d2eaa1dd943fac35fd55bde0e9005d178ee0c1211e04e224ddd",
    "deploy/private-server.compose.yaml": "7a13f5b635496e08b84cf9b19e53c3f494d44fd9d5dde07c807136a2eaeef282",
    "platform/examples/internal-sandbox-identity-bootstrap-template-v1.json": "b7f5326f75f17eb97cec77d92f963fe6af6755a26a1acf7af8944f33ee6ba942",
    "scripts/preflight_private_server_ingress.py": "b3533fcd50766e714efc1dd5b3cba4159d7921593c3ee9478dafe302cc8f2b97",
    "scripts/private_server_compose_contract.py": "1b19dec455d36a853a3cc1365e8d0110008414f2c73b2c2aae4348cb401c62d5",
    "scripts/private_server_release_inputs.py": "7cad99cca3b8e339de351d098d78a76858b77280d378db7edbac4dfbc7b18d63",
}
_SNAPSHOT_NAMES = frozenset(
    (
        "compose.env.snapshot", "compose.ipam.yaml.snapshot",
        "compose.yaml.snapshot", "private-server.compose.yaml.snapshot",
        "internal-sandbox-identity-bootstrap-template-v1.json",
    )
)

BLOCKED = '{"code":"PRIVATE_SERVER_INGRESS_MANAGEMENT_INVALID","status":"BLOCKED"}\n'
PARTIAL = '{"code":"PRIVATE_SERVER_INGRESS_MANAGEMENT_PARTIAL_POSSIBLE","status":"BLOCKED"}\n'
HEALTHY = '{"status":"PRIVATE_SERVER_INGRESS_HEALTHY"}\n'
STOPPED = '{"status":"PRIVATE_SERVER_INGRESS_STOPPED"}\n'
RECOVERABLE = '{"status":"PRIVATE_SERVER_INGRESS_RECOVERABLE"}\n'
DEGRADED = '{"status":"PRIVATE_SERVER_INGRESS_DEGRADED"}\n'
RECOVERED = '{"status":"PRIVATE_SERVER_INGRESS_RECOVERED"}\n'


class PrivateServerIngressManagementError(RuntimeError):
    pass


class PrivateServerIngressManagementPartialPossibleError(RuntimeError):
    pass


class _ClosedArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        del message
        _invalid()


def _invalid() -> NoReturn:
    raise PrivateServerIngressManagementError()


def _exact_project(value: str) -> str:
    if (
        not isinstance(value, str) or value in _FROZEN_PROJECTS
        or "v13" in value or _PROJECT.fullmatch(value) is None
    ):
        _invalid()
    return value


def _same(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _open_directory(path: Path, *, owner: int, mode: int) -> int:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        _invalid()
    descriptor = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        current = path.lstat()
    except OSError:
        if descriptor is not None:
            os.close(descriptor)
        _invalid()
    if (
        not stat.S_ISDIR(opened.st_mode) or stat.S_IMODE(opened.st_mode) != mode
        or opened.st_uid != owner or not _same(opened, current)
    ):
        os.close(descriptor)
        _invalid()
    return descriptor


def _open_child_directory(
    parent_fd: int, name: str, *, owner: int, mode: Optional[int] = None,
) -> int:
    if (
        not isinstance(name, str) or not name or name in (".", "..")
        or "/" in name or "\x00" in name
    ):
        _invalid()
    descriptor = None
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        opened = os.fstat(descriptor)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        if descriptor is not None:
            os.close(descriptor)
        _invalid()
    observed_mode = stat.S_IMODE(opened.st_mode)
    if (
        not stat.S_ISDIR(opened.st_mode) or opened.st_uid != owner
        or observed_mode & 0o022 or (mode is not None and observed_mode != mode)
        or not _same(opened, current)
    ):
        os.close(descriptor)
        _invalid()
    return descriptor


def _relative_parts(relative: Path) -> tuple:
    if not isinstance(relative, Path) or relative.is_absolute():
        _invalid()
    parts = relative.parts
    if not parts or any(part in ("", ".", "..") or "/" in part or "\x00" in part for part in parts):
        _invalid()
    return parts


def _open_relative_directory(
    root_fd: int, relative: Path, *, owner: int, mode: Optional[int] = None,
) -> int:
    parts = _relative_parts(relative)
    current_fd = os.dup(root_fd)
    try:
        for index, part in enumerate(parts):
            child_fd = _open_child_directory(
                current_fd, part, owner=owner,
                mode=mode if index + 1 == len(parts) else None,
            )
            os.close(current_fd)
            current_fd = child_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _list_relative_directory(root_fd: int, relative: Path, *, owner: int, mode: int) -> frozenset:
    descriptor = _open_relative_directory(root_fd, relative, owner=owner, mode=mode)
    try:
        names = os.listdir(descriptor)
    except OSError:
        os.close(descriptor)
        _invalid()
    os.close(descriptor)
    if any(not isinstance(name, str) or not name or "/" in name or "\x00" in name for name in names):
        _invalid()
    return frozenset(names)


def _read_relative_file(
    root_fd: int, relative: Path, *, owner: int, mode: int,
    maximum: int = _MAX_FILE,
) -> bytes:
    parts = _relative_parts(relative)
    parent_fd = os.dup(root_fd)
    descriptor = None
    try:
        for part in parts[:-1]:
            child_fd = _open_child_directory(parent_fd, part, owner=owner)
            os.close(parent_fd)
            parent_fd = child_fd
        descriptor = os.open(
            parts[-1], os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd,
        )
        before = os.fstat(descriptor)
        current = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != mode
            or before.st_uid != owner or before.st_nlink != 1
            or not 0 < before.st_size <= maximum or not _same(before, current)
        ):
            _invalid()
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                _invalid()
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            _invalid()
        after = os.fstat(descriptor)
        final = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or not _same(after, final)
        ):
            _invalid()
        return b"".join(chunks)
    except OSError:
        _invalid()
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)


def _validate_directory(path: Path, *, owner: int, mode: int) -> None:
    descriptor = _open_directory(path, owner=owner, mode=mode)
    os.close(descriptor)


def _read_file(path: Path, *, owner: int, mode: int, maximum: int = _MAX_FILE) -> bytes:
    try:
        descriptor = os.open(
            path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        current = path.lstat()
    except OSError:
        _invalid()
    try:
        if (
            not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != mode
            or before.st_uid != owner or before.st_nlink != 1
            or not 0 < before.st_size <= maximum or path.is_symlink()
            or not _same(before, current)
        ):
            _invalid()
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                _invalid()
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            _invalid()
        after = os.fstat(descriptor)
        final = path.lstat()
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or not _same(after, final)
        ):
            _invalid()
        return b"".join(chunks)
    except OSError:
        _invalid()
    finally:
        os.close(descriptor)


class _DuplicateKey(ValueError):
    pass


def _closed_json(raw: bytes):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise _DuplicateKey()
            result[key] = value
        return result

    def number(_value):
        raise _DuplicateKey()

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs,
            parse_float=number, parse_constant=number,
        )
    except (UnicodeError, ValueError, TypeError, RecursionError):
        _invalid()
    return value


def _canonical_receipt(raw: bytes, keys: frozenset):
    value = _closed_json(raw)
    if not isinstance(value, dict) or frozenset(value) != keys:
        _invalid()
    try:
        canonical = json.dumps(
            value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode("ascii") + b"\n"
    except (TypeError, ValueError, UnicodeError):
        _invalid()
    if raw != canonical:
        _invalid()
    return value


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _safe_static_sources(*, owner: int) -> None:
    for relative, expected in _SOURCE_SHA256.items():
        path = _ROOT / relative
        try:
            metadata = path.lstat()
        except OSError:
            _invalid()
        if metadata.st_mode & 0o022:
            _invalid()
        mode = stat.S_IMODE(metadata.st_mode)
        if _sha(_read_file(path, owner=owner, mode=mode)) != expected:
            _invalid()


def _tree_digest(
    attempt: Path, attempt_fd: int, config: Mapping[str, object],
    expected: str, owner: int,
) -> None:
    stage = attempt / "release-inputs"
    configs = config.get("configs")
    if not isinstance(configs, dict):
        _invalid()
    deployment = configs.get("internal-sandbox-deployment")
    if not isinstance(deployment, dict) or not isinstance(deployment.get("file"), str):
        _invalid()
    deployment_path = Path(deployment["file"])
    try:
        relative = deployment_path.relative_to(stage)
    except ValueError:
        _invalid()
    if len(relative.parts) != 3 or relative.parts[1:] != ("config", "deployment.json"):
        _invalid()
    bundle = relative.parts[0]
    if re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", bundle) is None:
        _invalid()

    directory_modes = {
        Path("."): 0o700,
        Path("internal-sandbox-identity-sources"): 0o755,
        Path("internal-sandbox-tls"): 0o700,
        Path(bundle): 0o700,
        Path(bundle) / "config": 0o700,
        Path(bundle) / "runtime-secrets": 0o700,
    }
    source_modes = {}
    for name in (
        "compose.env", "compose.ipam.yaml", "db_superuser_password.txt",
        "taxonomy_seed_workload_credential", "taxonomy_seed_receipt_hmac_key",
        "oidc-client-secret",
    ):
        source_modes[Path(name)] = 0o600
    for name in _IDENTITY_FILES:
        source_modes[Path("internal-sandbox-identity-sources") / name] = 0o444
    source_modes.update(
        {
            Path("internal-sandbox-tls/root-ca.pem"): 0o444,
            Path("internal-sandbox-tls/edge-tls-chain.pem"): 0o444,
            Path("internal-sandbox-tls/edge-tls-key.pem"): 0o400,
        }
    )
    for name in _BUNDLE_CONFIG_FILES:
        source_modes[Path(bundle) / "config" / name] = 0o600
    for name in _RUNTIME_SECRETS:
        source_modes[Path(bundle) / "runtime-secrets" / name] = 0o600

    expected_children = {relative: set() for relative in directory_modes}
    for relative in directory_modes:
        if relative != Path("."):
            expected_children[relative.parent].add(relative.name)
    for relative in source_modes:
        expected_children[relative.parent].add(relative.name)
    for relative, mode in directory_modes.items():
        anchored = Path("release-inputs") if relative == Path(".") else Path("release-inputs") / relative
        names = _list_relative_directory(
            attempt_fd, anchored, owner=owner, mode=mode,
        )
        if names != frozenset(expected_children[relative]):
            _invalid()

    records = {}
    private = frozenset((Path("compose.env"), Path("compose.ipam.yaml"), Path("oidc-client-secret")))
    for relative, source_mode in source_modes.items():
        staged_mode = 0o600 if relative in private else 0o444
        records[relative] = _read_relative_file(
            attempt_fd, Path("release-inputs") / relative,
            owner=owner, mode=staged_mode,
        )

    digest = hashlib.sha256(b"desire-private-server-release-input-tree-v1\x00")

    def add(value: bytes) -> None:
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)

    for relative, mode in sorted(directory_modes.items(), key=lambda item: item[0].as_posix()):
        add(b"D"); add(relative.as_posix().encode("utf-8")); add(f"{mode:04o}".encode("ascii"))
    for relative, value in sorted(records.items(), key=lambda item: item[0].as_posix()):
        add(b"F"); add(relative.as_posix().encode("utf-8"))
        add(f"{source_modes[relative]:04o}".encode("ascii"))
        add(len(value).to_bytes(8, "big")); add(hashlib.sha256(value).digest())
    if digest.hexdigest() != expected:
        _invalid()

    if records[Path("compose.env")] != _read_relative_file(
        attempt_fd, Path("compose.env.snapshot"), owner=owner, mode=0o600,
    ):
        _invalid()
    if records[Path("compose.ipam.yaml")] != _read_relative_file(
        attempt_fd, Path("compose.ipam.yaml.snapshot"), owner=owner, mode=0o600,
    ):
        _invalid()


@dataclass(frozen=True)
class _Context:
    project: str
    attempt: Path
    bind_ip: str
    image_ids: Mapping[str, str]
    container_ids: Mapping[str, str]
    config_hashes: Mapping[str, str]
    network_ids: Mapping[str, str]
    security_projection_sha256: Mapping[str, str]
    volume_name: str
    config: Mapping[str, object]
    environment: Mapping[str, str]


def _load_context(project: str, attempts_root: Path, owner: int, source_owner: int) -> tuple:
    root_fd = _open_directory(attempts_root, owner=owner, mode=0o700)
    attempt = attempts_root / project
    attempt_fd = None
    try:
        fcntl.flock(root_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        attempt_fd = _open_child_directory(
            root_fd, project, owner=owner, mode=0o700,
        )
        fcntl.flock(attempt_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        if attempt_fd is not None:
            try:
                os.close(attempt_fd)
            except OSError:
                pass
        try:
            os.close(root_fd)
        except OSError:
            pass
        raise

    try:
        claimed = _read_relative_file(
            attempt_fd, Path("activation.receipt.json"), owner=owner, mode=0o600,
        )
        if claimed != (
            '{"format":"desire-private-ingress-attempt-v1",'
            f'"project":"{project}","status":"CLAIMED"}}\n'
        ).encode("ascii"):
            _invalid()
        if _read_relative_file(
            attempt_fd, Path("up-invoked.receipt.json"), owner=owner, mode=0o600,
        ) != b'{"status":"UP_INVOKED"}\n':
            _invalid()

        activation = _canonical_receipt(
            _read_relative_file(
                attempt_fd, Path("activation-complete.receipt.json"),
                owner=owner, mode=0o600,
            ),
            frozenset(("bind_ip", "compose_plugin", "compose_sha256",
                       "config_hashes", "container_ids", "format", "image_ids",
                       "input_tree_sha256", "network_ids", "project",
                       "security_projection_sha256", "snapshot_sha256",
                       "source_sha256", "status", "volume_name")),
        )
        if (
            activation["format"] != "desire-private-ingress-activation-v2"
            or activation["status"] != "ACTIVATED" or activation["project"] != project
            or not isinstance(activation["compose_sha256"], str)
            or _SHA256.fullmatch(activation["compose_sha256"]) is None
            or not isinstance(activation["input_tree_sha256"], str)
            or _SHA256.fullmatch(activation["input_tree_sha256"]) is None
            or activation["source_sha256"] != _SOURCE_SHA256
        ):
            _invalid()
        try:
            bind = ipaddress.ip_address(activation["bind_ip"])
        except (TypeError, ValueError):
            _invalid()
        if (
            not isinstance(bind, ipaddress.IPv4Address) or str(bind) != activation["bind_ip"]
            or bind.is_loopback or not any(bind in network for network in _RFC1918)
        ):
            _invalid()
        images = activation["image_ids"]
        compose_plugin = activation["compose_plugin"]
        if (
            not isinstance(images, dict) or frozenset(images) != frozenset(("edge", "platform", "postgres", "web"))
            or any(not isinstance(value, str) or _IMAGE_ID.fullmatch(value) is None for value in images.values())
            or len(set(images.values())) != 4
        ):
            _invalid()
        if (
            not isinstance(compose_plugin, dict)
            or frozenset(compose_plugin) != frozenset(("path", "sha256", "version"))
            or compose_plugin.get("path") not in _COMPOSE_PLUGIN_PATHS
            or compose_plugin.get("version") != _COMPOSE_VERSION.rstrip("\n")
            or not isinstance(compose_plugin.get("sha256"), str)
            or _SHA256.fullmatch(compose_plugin["sha256"]) is None
        ):
            _invalid()
        container_ids = activation["container_ids"]
        config_hashes = activation["config_hashes"]
        network_ids = activation["network_ids"]
        security_projection_sha256 = activation["security_projection_sha256"]
        volume_name = f"{project}_postgres-data"
        if (
            not isinstance(container_ids, dict)
            or frozenset(container_ids) != frozenset(_SERVICES)
            or any(
                not isinstance(value, str) or _CONTAINER_ID.fullmatch(value) is None
                for value in container_ids.values()
            )
            or len(set(container_ids.values())) != len(_SERVICES)
            or not isinstance(config_hashes, dict)
            or frozenset(config_hashes) != frozenset(_SERVICES)
            or any(
                not isinstance(value, str) or _SHA256.fullmatch(value) is None
                for value in config_hashes.values()
            )
            or not isinstance(network_ids, dict)
            or frozenset(network_ids) != frozenset(_NETWORKS)
            or any(
                not isinstance(value, str) or _CONTAINER_ID.fullmatch(value) is None
                for value in network_ids.values()
            )
            or len(set(network_ids.values())) != len(_NETWORKS)
            or not isinstance(security_projection_sha256, dict)
            or frozenset(security_projection_sha256) != frozenset(_SERVICES)
            or any(
                not isinstance(value, str) or _SHA256.fullmatch(value) is None
                for value in security_projection_sha256.values()
            )
            or activation["volume_name"] != volume_name
        ):
            _invalid()

        snapshots = activation["snapshot_sha256"]
        if not isinstance(snapshots, dict) or frozenset(snapshots) != _SNAPSHOT_NAMES:
            _invalid()
        for name, expected in snapshots.items():
            mode = 0o444 if name.startswith("internal-sandbox-identity") else 0o600
            if not isinstance(expected, str) or _SHA256.fullmatch(expected) is None:
                _invalid()
            if _sha(_read_relative_file(
                attempt_fd, Path(name), owner=owner, mode=mode,
            )) != expected:
                _invalid()
        if (
            snapshots["compose.yaml.snapshot"] != _SOURCE_SHA256["compose.yaml"]
            or snapshots["private-server.compose.yaml.snapshot"] != _SOURCE_SHA256["deploy/private-server.compose.yaml"]
            or snapshots["internal-sandbox-identity-bootstrap-template-v1.json"]
            != _SOURCE_SHA256["platform/examples/internal-sandbox-identity-bootstrap-template-v1.json"]
        ):
            _invalid()

        resolved = _read_relative_file(
            attempt_fd, Path("resolved.compose.json"), owner=owner, mode=0o600,
        )
        if _sha(resolved) != activation["compose_sha256"] or not resolved.endswith(b"\n"):
            _invalid()
        config = _closed_json(resolved)
        if not isinstance(config, dict):
            _invalid()
        _validate_config(config, project=project, bind_ip=str(bind), images=images, attempt=attempt)

        release = _canonical_receipt(
            _read_relative_file(
                attempt_fd, Path("release-lock.receipt.json"),
                owner=owner, mode=0o600,
            ),
            frozenset(("compose_sha256", "format", "image_ids", "input_tree_sha256", "project")),
        )
        if release != {
            "compose_sha256": activation["compose_sha256"],
            "format": "desire-private-ingress-release-lock-v1",
            "image_ids": sorted(images.values()),
            "input_tree_sha256": activation["input_tree_sha256"],
            "project": project,
        }:
            _invalid()
        _tree_digest(
            attempt, attempt_fd, config, activation["input_tree_sha256"], owner,
        )

        docker_config_fd = _open_relative_directory(
            attempt_fd, Path("docker-config"), owner=owner, mode=0o700,
        )
        os.close(docker_config_fd)
        if _list_relative_directory(
            attempt_fd, Path("docker-config"), owner=owner, mode=0o700,
        ) != frozenset(("config.json",)):
            _invalid()
        if _read_relative_file(
            attempt_fd, Path("docker-config/config.json"), owner=owner, mode=0o600,
        ) != b"{}\n":
            _invalid()
        _safe_static_sources(owner=source_owner)
        _verify_visible_attempt(
            attempts_root, root_fd, project, attempt_fd,
            owner=owner,
        )
        environment = MappingProxyType(
            {
                "PATH": _TRUSTED_PATH, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                "DOCKER_HOST": _DOCKER_ENDPOINT,
                "DOCKER_CONFIG": str(attempt / "docker-config"),
                "COMPOSE_DISABLE_ENV_FILE": "true",
                "DESIRE_PRIVATE_INGRESS_IP": str(bind),
            }
        )
        return _Context(
            project, attempt, str(bind), MappingProxyType(dict(images)),
            MappingProxyType(dict(container_ids)),
            MappingProxyType(dict(config_hashes)),
            MappingProxyType(dict(network_ids)),
            MappingProxyType(dict(security_projection_sha256)),
            volume_name, config, environment,
        ), root_fd, attempt_fd
    except BaseException:
        os.close(attempt_fd)
        os.close(root_fd)
        raise


def _verify_visible_attempt(
    attempts_root: Path, root_fd: int, project: str, attempt_fd: int,
    *, owner: int,
) -> None:
    try:
        root_opened = os.fstat(root_fd)
        root_visible = attempts_root.lstat()
        attempt_opened = os.fstat(attempt_fd)
        attempt_visible = os.stat(project, dir_fd=root_fd, follow_symlinks=False)
    except OSError:
        _invalid()
    if (
        not _same(root_opened, root_visible)
        or not stat.S_ISDIR(root_opened.st_mode)
        or stat.S_IMODE(root_opened.st_mode) != 0o700
        or root_opened.st_uid != owner
        or not _same(attempt_opened, attempt_visible)
        or not stat.S_ISDIR(attempt_opened.st_mode)
        or stat.S_IMODE(attempt_opened.st_mode) != 0o700
        or attempt_opened.st_uid != owner
    ):
        _invalid()


def _validate_config(config, *, project: str, bind_ip: str, images: Mapping[str, str], attempt: Path) -> None:
    if frozenset(config) != frozenset(("configs", "name", "networks", "secrets", "services", "volumes")) or config.get("name") != project:
        _invalid()
    services = config.get("services")
    networks = config.get("networks")
    volumes = config.get("volumes")
    configs = config.get("configs")
    secrets = config.get("secrets")
    if (
        not isinstance(services, dict) or frozenset(services) != frozenset(_SERVICES)
        or not isinstance(networks, dict) or frozenset(networks) != frozenset(_NETWORKS)
        or volumes != {"postgres-data": {"name": f"{project}_postgres-data"}}
        or not isinstance(configs, dict) or frozenset(configs) != _CONFIG_NAMES
        or not isinstance(secrets, dict) or frozenset(secrets) != _SECRET_NAMES
    ):
        _invalid()
    expected_images = {name: images["platform"] for name in _SERVICES}
    expected_images.update({"db": images["postgres"], "edge": images["edge"], "web": images["web"]})
    for name, service in services.items():
        if not isinstance(service, dict) or service.get("image") != expected_images[name]:
            _invalid()
        service_networks = service.get("networks")
        if not isinstance(service_networks, dict) or frozenset(service_networks) != _SERVICE_NETWORKS[name]:
            _invalid()
    for name in _ONE_SHOTS + ("synthetic-oidc",):
        environment = services[name].get("environment")
        if (
            not isinstance(environment, dict)
            or environment.get("DESIRE_DEPLOYMENT_MODE") != "INTERNAL_SANDBOX"
            or environment.get("DESIRE_EXTERNAL_PARTICIPANTS_ENABLED") != "false"
        ):
            _invalid()
    if services["matching-runtime"].get("environment") != {
        "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE": (
            "/run/desire/matching-deployment.json"
        ),
        "DESIRE_MATCHING_RUNTIME_HEALTH_FILE": "/run/matching-runtime/healthy",
    }:
        _invalid()
    ports = services["edge"].get("ports")
    if not isinstance(ports, list) or len(ports) != 2:
        _invalid()
    observed = set()
    for port in ports:
        if (
            not isinstance(port, dict) or port.get("target") != 443
            or port.get("published") != "443" or port.get("protocol") != "tcp"
            or port.get("mode") != "ingress" or not isinstance(port.get("host_ip"), str)
        ):
            _invalid()
        observed.add(port["host_ip"])
    if observed != {"127.0.0.1", bind_ip}:
        _invalid()
    for name, network in networks.items():
        internal = network.get("internal", False)
        if (
            not isinstance(network, dict) or network.get("name") != f"{project}_{name}"
            or type(internal) is not bool
            or internal is not (name in _INTERNAL_NETWORKS)
            or not isinstance(network.get("ipam"), dict)
        ):
            _invalid()
    template = configs["internal-sandbox-identity-template"]
    if template != {"file": str(attempt / "internal-sandbox-identity-bootstrap-template-v1.json"),
                    "name": f"{project}_internal-sandbox-identity-template"}:
        _invalid()
    deployment_item = configs["internal-sandbox-deployment"]
    if not isinstance(deployment_item, dict) or not isinstance(deployment_item.get("file"), str):
        _invalid()
    deployment_path = Path(deployment_item["file"])
    release = attempt / "release-inputs"
    try:
        deployment_relative = deployment_path.relative_to(release)
    except ValueError:
        _invalid()
    if len(deployment_relative.parts) != 3 or deployment_relative.parts[1:] != ("config", "deployment.json"):
        _invalid()
    bundle = release / deployment_relative.parts[0]
    expected_config_files = {
        "internal-sandbox-deployment": bundle / "config/deployment.json",
        "internal-sandbox-runtime-config": bundle / "config/runtime-config.json",
        "internal-sandbox-secret-manifest": bundle / "config/secret-manifest.json",
        "internal-sandbox-matching-deployment": (
            bundle / "config/matching-deployment.json"
        ),
        "internal-sandbox-matching-runtime-config": (
            bundle / "config/matching-runtime-config.json"
        ),
        "internal-sandbox-matching-secret-manifest": (
            bundle / "config/matching-secret-manifest.json"
        ),
        "internal-sandbox-online-credentials-deployment": (
            bundle / "config/online-credentials-deployment.json"
        ),
        "internal-sandbox-online-credentials-runtime-config": (
            bundle / "config/online-credentials-runtime-config.json"
        ),
        "internal-sandbox-online-credentials-secret-manifest": (
            bundle / "config/online-credentials-secret-manifest.json"
        ),
        "internal-sandbox-identity-template": attempt / "internal-sandbox-identity-bootstrap-template-v1.json",
        "internal-sandbox-root-ca": release / "internal-sandbox-tls/root-ca.pem",
        "internal-sandbox-edge-tls-chain": release / "internal-sandbox-tls/edge-tls-chain.pem",
    }
    expected_secret_files = {
        **{name: bundle / "runtime-secrets" / name for name in _RUNTIME_SECRETS},
        "db_superuser_password": release / "db_superuser_password.txt",
        "taxonomy_seed_workload_credential": release / "taxonomy_seed_workload_credential",
        "taxonomy_seed_receipt_hmac_key": release / "taxonomy_seed_receipt_hmac_key",
        "edge-tls-key": release / "internal-sandbox-tls/edge-tls-key.pem",
    }
    for collection, expected_files in ((configs, expected_config_files), (secrets, expected_secret_files)):
        for name, item in collection.items():
            if (
                not isinstance(item, dict) or frozenset(item) != frozenset(("file", "name"))
                or item["name"] != f"{project}_{name}"
                or item["file"] != str(expected_files[name])
            ):
                _invalid()
    identity_volumes = services["identity-bootstrap"].get("volumes")
    if (
        not isinstance(identity_volumes, list) or len(identity_volumes) != 1
        or not isinstance(identity_volumes[0], dict)
        or identity_volumes[0].get("source")
        != str(release / "internal-sandbox-identity-sources")
    ):
        _invalid()


def _checked_stdout(result: object) -> str:
    code = getattr(result, "returncode", None)
    stdout = getattr(result, "stdout", None)
    stderr = getattr(result, "stderr", None)
    if (
        type(code) is not int or code != 0 or not isinstance(stdout, str) or stderr != ""
        or len(stdout.encode("utf-8")) > _MAX_OUTPUT or "\x00" in stdout
    ):
        _invalid()
    return stdout


def _mutation_result(result: object) -> None:
    code = getattr(result, "returncode", None)
    stdout = getattr(result, "stdout", None)
    stderr = getattr(result, "stderr", None)
    if (
        type(code) is not int or code != 0 or not isinstance(stdout, str)
        or not isinstance(stderr, str) or "\x00" in stdout or "\x00" in stderr
        or len(stdout.encode("utf-8")) > _MAX_OUTPUT
        or len(stderr.encode("utf-8")) > _MAX_OUTPUT
    ):
        raise PrivateServerIngressManagementPartialPossibleError()


def _bound_mutation_result(result: object, expected_stdout: str) -> None:
    _mutation_result(result)
    if getattr(result, "stdout", None) != expected_stdout or getattr(result, "stderr", None) != "":
        raise PrivateServerIngressManagementPartialPossibleError()


def _wait_healthy(
    run: Callable[[Sequence[str]], object], identifier: str, image_id: str,
    *, attempts: int = 121,
) -> None:
    docker = (_DOCKER, "--host", _DOCKER_ENDPOINT)
    for index in range(attempts):
        try:
            raw = _checked_stdout(run(docker + ("container", "inspect", identifier)))
            document = _closed_json(raw.encode("utf-8"))
        except BaseException as error:
            raise PrivateServerIngressManagementPartialPossibleError() from error
        if (
            not isinstance(document, list) or len(document) != 1
            or not isinstance(document[0], dict) or document[0].get("Id") != identifier
            or document[0].get("Image") != image_id
            or not isinstance(document[0].get("State"), dict)
        ):
            raise PrivateServerIngressManagementPartialPossibleError()
        state = document[0]["State"]
        health = state.get("Health")
        if (
            state.get("Status") == "running" and state.get("Running") is True
            and state.get("Paused") is False and state.get("Restarting") is False
            and state.get("Dead") is False and isinstance(health, dict)
            and health.get("Status") == "healthy"
        ):
            return
        if (
            state.get("Status") != "running" or state.get("Running") is not True
            or state.get("Paused") is not False or state.get("Restarting") is not False
            or state.get("Dead") is not False or not isinstance(health, dict)
            or health.get("Status") not in ("starting", "unhealthy")
        ):
            raise PrivateServerIngressManagementPartialPossibleError()
        if index + 1 < attempts:
            time.sleep(1)
    raise PrivateServerIngressManagementPartialPossibleError()


@dataclass(frozen=True)
class _Live:
    containers: Mapping[str, Mapping[str, object]]
    classification: str


def _security_projection_sha256(container: Mapping[str, object]) -> str:
    config = container.get("Config")
    host_config = container.get("HostConfig")
    mounts = container.get("Mounts")
    if (
        not isinstance(config, dict)
        or not isinstance(host_config, dict)
        or not isinstance(mounts, list)
    ):
        _invalid()
    try:
        normalized_mounts = []
        destinations = set()
        for mount in mounts:
            if not isinstance(mount, dict):
                _invalid()
            destination = mount.get("Destination")
            if (
                not isinstance(destination, str) or not destination
                or destination in destinations
            ):
                _invalid()
            destinations.add(destination)
            encoded = json.dumps(
                mount, ensure_ascii=True, separators=(",", ":"), sort_keys=True,
            ).encode("ascii")
            normalized_mounts.append((destination, encoded, mount))
        normalized_mounts.sort(key=lambda item: (item[0], item[1]))
        canonical = json.dumps(
            {
                "Config": config,
                "HostConfig": host_config,
                "Mounts": [item[2] for item in normalized_mounts],
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _invalid()
    return hashlib.sha256(canonical).hexdigest()


def _closed_string_sequence(value: object) -> tuple:
    if value is None:
        return ()
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) or not item for item in value)
        or len(value) != len(set(value))
    ):
        _invalid()
    return tuple(sorted(value))


def _security_options(value: object) -> tuple:
    normalized = []
    for option in _closed_string_sequence(value):
        if option == "no-new-privileges=true":
            option = "no-new-privileges:true"
        normalized.append(option)
    return tuple(sorted(normalized))


def _validate_critical_projection(
    container: Mapping[str, object], canonical: Mapping[str, object],
    *, project: str, service: str,
) -> None:
    config = container["Config"]
    host_config = container["HostConfig"]
    if not isinstance(config, dict) or not isinstance(host_config, dict):
        _invalid()

    restart = canonical.get("restart", "no")
    restart_policy = host_config.get("RestartPolicy")
    read_only = canonical.get("read_only", False)
    logging = canonical.get("logging")
    expected_log_config = (
        {
            "Type": logging.get("driver"),
            "Config": logging.get("options"),
        }
        if isinstance(logging, dict)
        and set(logging) == {"driver", "options"}
        and isinstance(logging.get("options"), dict)
        else None
    )
    if (
        restart not in ("no", "unless-stopped")
        or type(read_only) is not bool
        or not isinstance(restart_policy, dict)
        or frozenset(restart_policy) != frozenset(("Name", "MaximumRetryCount"))
        or restart_policy.get("Name") != restart
        or type(restart_policy.get("MaximumRetryCount")) is not int
        or restart_policy.get("MaximumRetryCount") != 0
        or host_config.get("Privileged") is not False
        or host_config.get("ReadonlyRootfs") is not read_only
        or host_config.get("AutoRemove") is not False
        or host_config.get("PublishAllPorts") is not False
        or expected_log_config
        != {
            "Type": "local",
            "Config": {
                "compress": "true",
                "max-file": "3",
                "max-size": "10m",
            },
        }
        or host_config.get("LogConfig") != expected_log_config
    ):
        _invalid()

    expected_cap_drop = _closed_string_sequence(canonical.get("cap_drop"))
    if (
        _closed_string_sequence(host_config.get("CapAdd")) != ()
        or _closed_string_sequence(host_config.get("CapDrop")) != expected_cap_drop
        or _security_options(host_config.get("SecurityOpt"))
        != _security_options(canonical.get("security_opt"))
    ):
        _invalid()

    if (
        host_config.get("PidMode") not in ("", "private")
        or host_config.get("IpcMode") not in ("", "private")
        or host_config.get("UTSMode") not in ("", "private")
        or host_config.get("NetworkMode")
        not in {f"{project}_{name}" for name in _SERVICE_NETWORKS[service]}
    ):
        _invalid()

    command = canonical.get("command")
    if command is not None and config.get("Cmd") != command:
        _invalid()
    entrypoint = canonical.get("entrypoint")
    if entrypoint is not None and config.get("Entrypoint") != entrypoint:
        _invalid()
    user = canonical.get("user")
    if user is not None and config.get("User") != user:
        _invalid()

    canonical_environment = canonical.get("environment", {})
    live_environment = config.get("Env")
    if not isinstance(canonical_environment, dict) or not isinstance(live_environment, list):
        _invalid()
    observed_environment = {}
    for entry in live_environment:
        if not isinstance(entry, str) or "=" not in entry:
            _invalid()
        key, value = entry.split("=", 1)
        if not key or key in observed_environment:
            _invalid()
        observed_environment[key] = value
    if any(
        not isinstance(key, str) or not isinstance(value, str)
        or observed_environment.get(key) != value
        for key, value in canonical_environment.items()
    ):
        _invalid()

    healthcheck = canonical.get("healthcheck")
    if healthcheck is not None:
        live_healthcheck = config.get("Healthcheck")
        if (
            not isinstance(healthcheck, dict)
            or not isinstance(healthcheck.get("test"), list)
            or not isinstance(live_healthcheck, dict)
            or live_healthcheck.get("Test") != healthcheck["test"]
        ):
            _invalid()


def _inspect_live(context: _Context, run: Callable[[Sequence[str]], object]) -> _Live:
    docker = (_DOCKER, "--host", _DOCKER_ENDPOINT)
    for image_id in sorted(context.image_ids.values()):
        if _checked_stdout(run(docker + ("image", "inspect", "--format", "{{.Id}}", image_id))) != image_id + "\n":
            _invalid()
    names = tuple(f"{context.project}-{service}-1" for service in _SERVICES)
    containers_raw = _closed_json(_checked_stdout(run(docker + ("container", "inspect") + names)).encode("utf-8"))
    if not isinstance(containers_raw, list) or len(containers_raw) != len(_SERVICES):
        _invalid()
    by_service = {}
    expected_images = {name: context.image_ids["platform"] for name in _SERVICES}
    expected_images.update({"db": context.image_ids["postgres"], "edge": context.image_ids["edge"], "web": context.image_ids["web"]})
    for item in containers_raw:
        if not isinstance(item, dict) or not isinstance(item.get("Name"), str):
            _invalid()
        name = item["Name"]
        if not name.startswith(f"/{context.project}-") or not name.endswith("-1"):
            _invalid()
        service = name[len(context.project) + 2:-2]
        if service not in _SERVICES or service in by_service:
            _invalid()
        identifier = item.get("Id")
        config = item.get("Config")
        host_config = item.get("HostConfig")
        state = item.get("State")
        network_settings = item.get("NetworkSettings")
        if (
            not isinstance(identifier, str) or _CONTAINER_ID.fullmatch(identifier) is None
            or identifier != context.container_ids[service]
            or item.get("Image") != expected_images[service]
            or not isinstance(config, dict) or config.get("Image") != expected_images[service]
            or not isinstance(host_config, dict) or not isinstance(state, dict)
            or not isinstance(network_settings, dict)
        ):
            _invalid()
        if _security_projection_sha256(item) != context.security_projection_sha256[service]:
            _invalid()
        canonical_service = context.config["services"][service]
        if not isinstance(canonical_service, dict):
            _invalid()
        _validate_critical_projection(
            item, canonical_service, project=context.project, service=service,
        )
        labels = config.get("Labels")
        required_labels = {
            "com.docker.compose.project": context.project,
            "com.docker.compose.service": service,
            "com.docker.compose.container-number": "1",
            "com.docker.compose.config-hash": context.config_hashes[service],
            "com.docker.compose.oneoff": "False",
            "com.docker.compose.image": expected_images[service],
            "com.docker.compose.project.config_files": str(context.attempt / "resolved.compose.json"),
            "com.docker.compose.project.working_dir": str(_ROOT),
            "com.docker.compose.version": _COMPOSE_VERSION.rstrip("\n"),
        }
        if not isinstance(labels, dict) or any(labels.get(key) != value for key, value in required_labels.items()):
            _invalid()
        attached = network_settings.get("Networks")
        if not isinstance(attached, dict) or frozenset(attached) != frozenset(f"{context.project}_{value}" for value in _SERVICE_NETWORKS[service]):
            _invalid()
        for physical_name, attachment in attached.items():
            logical = physical_name[len(context.project) + 1:]
            canonical_network = context.config["networks"][logical]
            canonical_ipam = canonical_network.get("ipam") if isinstance(canonical_network, dict) else None
            canonical_configs = canonical_ipam.get("config") if isinstance(canonical_ipam, dict) else None
            if (
                not isinstance(canonical_configs, list) or len(canonical_configs) != 1
                or not isinstance(canonical_configs[0], dict)
            ):
                _invalid()
            _validate_network_attachment(
                attachment,
                expected_network_id=context.network_ids[logical],
                expected_subnet=canonical_configs[0].get("subnet"),
                running=state.get("Status") == "running",
            )
        configured_ports = host_config.get("PortBindings")
        if service == "edge":
            if not isinstance(configured_ports, dict) or frozenset(configured_ports) != frozenset(("443/tcp",)):
                _invalid()
            _exact_edge_bindings(configured_ports.get("443/tcp"), context.bind_ip)
        elif configured_ports not in (None, {}):
            _invalid()

        ports = network_settings.get("Ports")
        status_value = state.get("Status")
        if status_value == "exited":
            if ports not in (None, {}):
                _invalid()
        elif status_value == "running":
            if not isinstance(ports, dict):
                _invalid()
            if service == "edge":
                if "443/tcp" not in ports:
                    _invalid()
                _exact_edge_bindings(ports["443/tcp"], context.bind_ip)
            for key, bindings in ports.items():
                if service == "edge" and key == "443/tcp":
                    continue
                if bindings not in (None, []):
                    _invalid()
        else:
            _invalid()
        by_service[service] = item
    if frozenset(by_service) != frozenset(_SERVICES):
        _invalid()
    if len({item["Id"] for item in by_service.values()}) != len(_SERVICES):
        _invalid()

    for service in _ONE_SHOTS:
        state = by_service[service]["State"]
        if (
            state.get("Status") != "exited" or state.get("Running") is not False
            or state.get("Paused") is not False or state.get("Restarting") is not False
            or state.get("Dead") is not False or type(state.get("ExitCode")) is not int
            or state.get("ExitCode") != 0
        ):
            _invalid()

    states = {}
    degraded = False
    for service in _PERSISTENT:
        state = by_service[service]["State"]
        status_value = state.get("Status")
        if status_value == "running":
            if (
                state.get("Running") is not True or state.get("Paused") is not False
                or state.get("Restarting") is not False or state.get("Dead") is not False
            ):
                _invalid()
            health = state.get("Health")
            if not isinstance(health, dict) or health.get("Status") not in ("healthy", "starting", "unhealthy"):
                _invalid()
            if health["Status"] != "healthy":
                degraded = True
            states[service] = "running"
        elif status_value == "exited":
            if (
                state.get("Running") is not False or state.get("Paused") is not False
                or state.get("Restarting") is not False or state.get("Dead") is not False
                or type(state.get("ExitCode")) is not int
            ):
                _invalid()
            states[service] = "stopped"
        else:
            _invalid()

    network_names = tuple(f"{context.project}_{name}" for name in _NETWORKS)
    network_raw = _closed_json(_checked_stdout(run(docker + ("network", "inspect") + network_names)).encode("utf-8"))
    if not isinstance(network_raw, list) or len(network_raw) != len(_NETWORKS):
        _invalid()
    observed_networks = set()
    for item in network_raw:
        if not isinstance(item, dict) or not isinstance(item.get("Name"), str):
            _invalid()
        name = item["Name"]
        if not name.startswith(f"{context.project}_"):
            _invalid()
        logical = name[len(context.project) + 1:]
        labels = item.get("Labels")
        internal = item.get("Internal")
        if (
            logical not in _NETWORKS or logical in observed_networks or not isinstance(labels, dict)
            or labels.get("com.docker.compose.project") != context.project
            or labels.get("com.docker.compose.network") != logical
            or type(internal) is not bool
            or internal is not (logical in _INTERNAL_NETWORKS)
            or item.get("Driver") != "bridge" or item.get("Scope") != "local"
        ):
            _invalid()
        identifier = item.get("Id")
        ipam = item.get("IPAM")
        canonical_ipam = context.config["networks"][logical]["ipam"]
        canonical_configs = canonical_ipam.get("config") if isinstance(canonical_ipam, dict) else None
        live_configs = ipam.get("Config") if isinstance(ipam, dict) else None
        if (
            not isinstance(identifier, str) or _CONTAINER_ID.fullmatch(identifier) is None
            or identifier != context.network_ids[logical]
            or not isinstance(canonical_configs, list) or len(canonical_configs) != 1
            or not isinstance(canonical_configs[0], dict)
            or not isinstance(live_configs, list) or len(live_configs) != 1
            or not isinstance(live_configs[0], dict)
            or live_configs[0].get("Subnet") != canonical_configs[0].get("subnet")
        ):
            _invalid()
        observed_networks.add(logical)
    if observed_networks != set(_NETWORKS):
        _invalid()

    volume_name = context.volume_name
    volume_raw = _closed_json(_checked_stdout(run(docker + ("volume", "inspect", volume_name))).encode("utf-8"))
    if not isinstance(volume_raw, list) or len(volume_raw) != 1 or not isinstance(volume_raw[0], dict):
        _invalid()
    volume = volume_raw[0]
    labels = volume.get("Labels")
    if (
        volume.get("Name") != volume_name or not isinstance(labels, dict)
        or volume.get("Driver") != "local" or volume.get("Scope") != "local"
        or labels.get("com.docker.compose.project") != context.project
        or labels.get("com.docker.compose.volume") != "postgres-data"
    ):
        _invalid()
    mounts = by_service["db"].get("Mounts")
    if not isinstance(mounts, list) or sum(
        isinstance(item, dict) and item.get("Type") == "volume"
        and item.get("Name") == volume_name and item.get("Destination") == "/var/lib/postgresql/data"
        and item.get("RW") is True
        for item in mounts
    ) != 1:
        _invalid()

    project_label = f"label=com.docker.compose.project={context.project}"
    container_rows = _resource_rows(
        _checked_stdout(
            run(
                docker
                + (
                    "container", "ls", "--all", "--no-trunc", "--filter",
                    project_label, "--format", "{{.ID}} {{.Names}}",
                )
            )
        ),
        with_id=True,
    )
    expected_container_rows = frozenset(
        (item["Id"], item["Name"].removeprefix("/"))
        for item in by_service.values()
    )
    if container_rows != expected_container_rows:
        _invalid()

    network_rows = _resource_rows(
        _checked_stdout(
            run(
                docker
                + (
                    "network", "ls", "--no-trunc", "--filter", project_label,
                    "--format", "{{.ID}} {{.Name}}",
                )
            )
        ),
        with_id=True,
    )
    expected_network_rows = frozenset(
        (item["Id"], item["Name"]) for item in network_raw
    )
    if network_rows != expected_network_rows:
        _invalid()

    volume_rows = _resource_rows(
        _checked_stdout(
            run(
                docker
                + (
                    "volume", "ls", "--filter", project_label, "--format",
                    "{{.Name}}",
                )
            )
        ),
        with_id=False,
    )
    if volume_rows != frozenset((volume_name,)):
        _invalid()

    all_container_ids = _resource_ids(
        _checked_stdout(
            run(
                docker
                + (
                    "container", "ls", "--all", "--no-trunc", "--quiet",
                )
            )
        )
    )
    if not all_container_ids or len(all_container_ids) > _MAX_CONTAINERS:
        _invalid()
    projections = _consumer_projections(
        _checked_stdout(
            run(
                docker
                + ("container", "inspect", "--format", _CONSUMER_FORMAT)
                + tuple(sorted(all_container_ids))
            )
        ),
        expected_ids=all_container_ids,
    )
    expected_network_consumers = {
        f"{context.project}_{logical}": frozenset(
            by_service[service]["Id"]
            for service in _SERVICES
            if logical in _SERVICE_NETWORKS[service]
        )
        for logical in _NETWORKS
    }
    observed_network_consumers = {
        name: set() for name in expected_network_consumers
    }
    observed_volume_consumers = set()
    for identifier, projection in projections.items():
        networks = projection["Networks"]
        mounts = projection["Mounts"]
        for name in networks:
            if name in observed_network_consumers:
                observed_network_consumers[name].add(identifier)
        for mount in mounts:
            if (
                isinstance(mount, dict) and mount.get("Type") == "volume"
                and mount.get("Name") == volume_name
            ):
                observed_volume_consumers.add(identifier)
    if (
        any(
            frozenset(observed_network_consumers[name]) != expected
            for name, expected in expected_network_consumers.items()
        )
        or frozenset(observed_volume_consumers)
        != frozenset((by_service["db"]["Id"],))
    ):
        _invalid()

    listeners = _listener_set(_checked_stdout(run((_SS, "-H", "-ltn"))), context.bind_ip)
    edge_running = states["edge"] == "running"
    if listeners != ({"127.0.0.1", context.bind_ip} if edge_running else set()):
        _invalid()
    if degraded:
        classification = "DEGRADED"
    elif all(value == "running" for value in states.values()):
        classification = "HEALTHY"
    elif all(value == "stopped" for value in states.values()):
        classification = "STOPPED"
    else:
        classification = "RECOVERABLE"
    return _Live(MappingProxyType(by_service), classification)


def _validate_network_attachment(
    value: object, *, expected_network_id: str, expected_subnet: object,
    running: bool,
) -> None:
    if not isinstance(value, dict) or value.get("NetworkID") != expected_network_id:
        _invalid()
    endpoint = value.get("EndpointID")
    address = value.get("IPAddress")
    prefix = value.get("IPPrefixLen")
    if endpoint in (None, "") and address in (None, "") and prefix in (None, 0):
        if running:
            _invalid()
        return
    if (
        not isinstance(endpoint, str) or _CONTAINER_ID.fullmatch(endpoint) is None
        or not isinstance(address, str) or not isinstance(prefix, int)
        or type(prefix) is not int
    ):
        _invalid()
    try:
        network = ipaddress.ip_network(expected_subnet, strict=True)
        observed = ipaddress.ip_address(address)
    except (TypeError, ValueError):
        _invalid()
    if (
        not isinstance(network, ipaddress.IPv4Network)
        or not isinstance(observed, ipaddress.IPv4Address)
        or observed not in network or prefix != network.prefixlen
    ):
        _invalid()


def _exact_edge_bindings(value: object, bind_ip: str) -> None:
    if not isinstance(value, list) or len(value) != 2:
        _invalid()
    observed = set()
    for entry in value:
        if (
            not isinstance(entry, dict)
            or frozenset(entry) != frozenset(("HostIp", "HostPort"))
            or not isinstance(entry.get("HostIp"), str)
            or entry.get("HostPort") != "443"
        ):
            _invalid()
        observed.add((entry["HostIp"], entry["HostPort"]))
    if observed != {("127.0.0.1", "443"), (bind_ip, "443")}:
        _invalid()


def _resource_rows(output: str, *, with_id: bool) -> frozenset:
    rows = []
    for line in output.splitlines():
        if not line or line != line.strip():
            _invalid()
        if with_id:
            identifier, separator, name = line.partition(" ")
            if (
                separator != " " or not name or " " in name
                or _CONTAINER_ID.fullmatch(identifier) is None
            ):
                _invalid()
            rows.append((identifier, name))
        else:
            if any(character.isspace() for character in line):
                _invalid()
            rows.append(line)
    if len(rows) != len(set(rows)):
        _invalid()
    return frozenset(rows)


def _resource_ids(output: str) -> frozenset:
    values = output.splitlines()
    if any(
        not value or value != value.strip()
        or _CONTAINER_ID.fullmatch(value) is None
        for value in values
    ) or len(values) != len(set(values)):
        _invalid()
    return frozenset(values)


def _consumer_projections(output: str, *, expected_ids: frozenset) -> Mapping[str, Mapping[str, object]]:
    result = {}
    for line in output.splitlines():
        if not line or line != line.strip():
            _invalid()
        value = _closed_json(line.encode("utf-8"))
        if not isinstance(value, dict) or frozenset(value) != frozenset(("Id", "Mounts", "Networks")):
            _invalid()
        identifier = value["Id"]
        mounts = value["Mounts"]
        networks = value["Networks"]
        if (
            not isinstance(identifier, str) or _CONTAINER_ID.fullmatch(identifier) is None
            or identifier in result or not isinstance(mounts, list)
            or not isinstance(networks, dict)
            or any(not isinstance(name, str) for name in networks)
        ):
            _invalid()
        result[identifier] = value
    if frozenset(result) != expected_ids:
        _invalid()
    return MappingProxyType(result)


def _listener_set(output: str, bind_ip: str) -> set:
    # Match activation preflight: target/loopback are exclusive and wildcard :443
    # is forbidden, while an unrelated service on another concrete host IP is
    # outside this project's lifecycle boundary and may coexist.
    observed = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) != 5 or fields[0] != "LISTEN" or not fields[1].isdigit() or not fields[2].isdigit():
            _invalid()
        endpoint = fields[3]
        if endpoint.startswith("["):
            closing = endpoint.find("]")
            if closing < 1 or endpoint[closing + 1:closing + 2] != ":":
                _invalid()
            address, port = endpoint[1:closing], endpoint[closing + 2:]
        else:
            address, separator, port = endpoint.rpartition(":")
            if not separator:
                _invalid()
        if port != "443":
            continue
        if address in ("*", "0.0.0.0", "::", "[::]"):
            _invalid()
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            _invalid()
        if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
            parsed = parsed.ipv4_mapped
        text = str(parsed)
        if text in ("127.0.0.1", bind_ip):
            if text in observed:
                _invalid()
            observed.add(text)
    return observed


def _default_runner(command: Sequence[str], environment: Mapping[str, str]):
    timeout = 180 if "stop" in command else 30
    return subprocess.run(
        list(command), cwd=_ROOT, env=environment, check=False,
        capture_output=True, text=True, encoding="utf-8", errors="strict", timeout=timeout,
    )


def _validate_executable(path_text: str) -> None:
    path = Path(path_text)
    try:
        metadata = path.lstat()
    except OSError:
        _invalid()
    if (
        not path.is_absolute() or path.is_symlink() or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0 or metadata.st_mode & 0o022
        or metadata.st_mode & 0o111 == 0
    ):
        _invalid()


def _validate_trusted_directory_chain(
    path: Path, *, expected_owner: int, stop: Path,
) -> None:
    current = path
    while True:
        try:
            metadata = current.lstat()
        except OSError:
            _invalid()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != expected_owner
            or metadata.st_mode & 0o022
            or current.is_symlink()
        ):
            _invalid()
        if current == stop:
            return
        if current == Path("/") or stop not in (current, *current.parents):
            _invalid()
        current = current.parent


def _validate_trusted_executable_chain(
    path: Path, *, expected_owner: int, trusted_root: Path,
) -> None:
    if not path.is_absolute() or not trusted_root.is_absolute():
        _invalid()
    seen = set()
    current = path
    for _index in range(17):
        _validate_trusted_directory_chain(
            current.parent, expected_owner=expected_owner, stop=trusted_root,
        )
        try:
            metadata = current.lstat()
        except OSError:
            _invalid()
        identity = (metadata.st_dev, metadata.st_ino)
        if identity in seen or metadata.st_uid != expected_owner:
            _invalid()
        seen.add(identity)
        if stat.S_ISLNK(metadata.st_mode):
            try:
                target_text = os.readlink(current)
            except OSError:
                _invalid()
            if not target_text or "\x00" in target_text:
                _invalid()
            target = Path(target_text)
            if not target.is_absolute():
                target = current.parent / target
            current = Path(os.path.normpath(str(target)))
            if not current.is_absolute():
                _invalid()
            continue
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_mode & 0o022
            or metadata.st_mode & 0o111 == 0
        ):
            _invalid()
        return
    _invalid()


def _validate_runtime() -> None:
    if sys.flags.isolated != 1:
        _invalid()
    _validate_trusted_executable_chain(
        Path(sys.executable), expected_owner=0, trusted_root=Path("/"),
    )
    for executable in (_DOCKER, _SS):
        _validate_executable(executable)


def manage(
    *, action: str, project: str, attempts_root: Path, owner: int,
    source_owner: int, command_runner: Callable[[Sequence[str], Mapping[str, str]], object],
) -> str:
    context, root_lock_fd, attempt_lock_fd = _load_context(
        project, attempts_root, owner, source_owner,
    )
    invoked = False
    try:
        def run(command):
            return command_runner(tuple(command), context.environment)

        _verify_visible_attempt(
            attempts_root, root_lock_fd, project, attempt_lock_fd, owner=owner,
        )
        live = _inspect_live(context, run)
        if action == "status":
            _verify_visible_attempt(
                attempts_root, root_lock_fd, project, attempt_lock_fd, owner=owner,
            )
            return {"HEALTHY": HEALTHY, "STOPPED": STOPPED,
                    "RECOVERABLE": RECOVERABLE, "DEGRADED": DEGRADED}[live.classification]
        if action == "recover":
            if live.classification == "DEGRADED":
                _invalid()
            for service in _PERSISTENT:
                if live.containers[service]["State"]["Status"] != "exited":
                    continue
                identifier = live.containers[service]["Id"]
                image_id = live.containers[service]["Image"]
                _verify_visible_attempt(
                    attempts_root, root_lock_fd, project, attempt_lock_fd,
                    owner=owner,
                )
                invoked = True
                try:
                    result = run(
                        (_DOCKER, "--host", _DOCKER_ENDPOINT, "container", "start", identifier)
                    )
                except BaseException as error:
                    raise PrivateServerIngressManagementPartialPossibleError() from error
                _bound_mutation_result(result, identifier + "\n")
                _wait_healthy(run, identifier, image_id)
            _verify_visible_attempt(
                attempts_root, root_lock_fd, project, attempt_lock_fd, owner=owner,
            )
            final = _inspect_live(context, run)
            if final.classification != "HEALTHY":
                if invoked:
                    raise PrivateServerIngressManagementPartialPossibleError()
                _invalid()
            return RECOVERED
        if action == "stop":
            for service in _STOP_ORDER:
                if live.containers[service]["State"]["Status"] != "running":
                    continue
                identifier = live.containers[service]["Id"]
                _verify_visible_attempt(
                    attempts_root, root_lock_fd, project, attempt_lock_fd,
                    owner=owner,
                )
                invoked = True
                try:
                    result = run(
                        (_DOCKER, "--host", _DOCKER_ENDPOINT, "container", "stop",
                         "--timeout", str(_STOP_SECONDS[service]), identifier)
                    )
                except BaseException as error:
                    raise PrivateServerIngressManagementPartialPossibleError() from error
                _bound_mutation_result(result, identifier + "\n")
            _verify_visible_attempt(
                attempts_root, root_lock_fd, project, attempt_lock_fd, owner=owner,
            )
            final = _inspect_live(context, run)
            if final.classification != "STOPPED":
                if invoked:
                    raise PrivateServerIngressManagementPartialPossibleError()
                _invalid()
            return STOPPED
        _invalid()
    except PrivateServerIngressManagementPartialPossibleError:
        raise
    except BaseException as error:
        if invoked:
            raise PrivateServerIngressManagementPartialPossibleError() from error
        raise
    finally:
        os.close(attempt_lock_fd)
        os.close(root_lock_fd)


def main(
    argv: Optional[Sequence[str]] = None, *, stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr, platform_name: Optional[str] = None,
    command_runner: Optional[Callable[[Sequence[str], Mapping[str, str]], object]] = None,
    attempts_root: Optional[Path] = None,
) -> int:
    parser = _ClosedArgumentParser(add_help=False)
    parser.add_argument("action", choices=("status", "recover", "stop"))
    parser.add_argument("--project-name", required=True)
    try:
        arguments = parser.parse_args(argv)
        if (sys.platform if platform_name is None else platform_name) != "linux":
            _invalid()
        project = _exact_project(arguments.project_name)
        injected = command_runner is not None
        selected_root = _ATTEMPTS_ROOT if attempts_root is None else attempts_root
        if not injected and attempts_root is None:
            if os.geteuid() != 0:
                _invalid()
            _validate_runtime()
        result = manage(
            action=arguments.action, project=project, attempts_root=selected_root,
            owner=0 if attempts_root is None else os.geteuid(),
            source_owner=0 if not injected else os.geteuid(),
            command_runner=_default_runner if command_runner is None else command_runner,
        )
    except PrivateServerIngressManagementPartialPossibleError:
        stderr.write(PARTIAL)
        return 75
    except BaseException:
        stderr.write(BLOCKED)
        return 78
    stdout.write(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
