#!/usr/bin/env python3
"""Safely prepare and operate one local-only INTERNAL_SANDBOX trial.

The manager deliberately has no delete, down, destroy, prune, recreate, pull,
or remove operation.  A prepared root and a fresh-start attempt are consumed
coordinates: failures are retained for inspection instead of being cleaned up
or retried.  Resume and stop act only on container IDs captured after a fully
validated fresh start.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
from typing import Any, Callable, Mapping, NoReturn, Sequence, TextIO
from urllib.parse import parse_qs, urlencode, urlsplit


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILE = REPOSITORY_ROOT / "compose.yaml"
METADATA_DIRECTORY = ".local-internal-sandbox"
PREPARE_ATTEMPT = "prepare-attempt.json"
PREPARED_RECEIPT = "prepared-receipt.json"
START_ATTEMPT = "start-attempt.json"
START_RECEIPT = "start-receipt.json"
RECEIPT_SCHEMA = "desire-local-internal-sandbox-trial-v1"

PERSISTENT_SERVICES = (
    "db",
    "synthetic-oidc",
    "edge",
    "matching-runtime",
    "api",
    "web",
)
STOP_ORDER = (
    "web",
    "api",
    "matching-runtime",
    "edge",
    "synthetic-oidc",
    "db",
)
ONE_SHOT_SERVICES = (
    "migrate",
    "taxonomy-seed",
    "online-credentials-reconcile",
    "online-credentials-verify",
    "identity-bootstrap",
)
SERVICES = PERSISTENT_SERVICES + ONE_SHOT_SERVICES
NETWORKS = ("ingress", "oidc-backend", "app", "data")
SERVICE_NETWORKS = {
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
    "edge": frozenset(("app", "oidc-backend", "ingress")),
}
CATALOGS = frozenset(
    ("demand", "iam", "matching", "profile", "taxonomy", "trust")
)
FIXED_DOMAIN = "example.test"
SYNTHETIC_CLIENT_ID = "desire-internal-sandbox"
SYNTHETIC_SIGNING_KEY_ID = "internal-sandbox-synthetic-rs256-v1"
POSTGRES_IMAGE = (
    "postgres:18.4-alpine@sha256:"
    "9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15"
)
BOUNDED_LOGGING = {
    "driver": "local",
    "options": {
        "compress": "true",
        "max-file": "3",
        "max-size": "10m",
    },
}
DOCKER_LOG_CONFIG = {
    "Type": "local",
    "Config": {
        "compress": "true",
        "max-file": "3",
        "max-size": "10m",
    },
}
SYNTHETIC_BOOTSTRAP_ACCOUNT_CODES = (
    "access_admin_01",
    "appeal_reviewer_01",
    "creator_01",
    "demand_owner_01",
    "finance_operator_01",
    "finance_operator_02",
    "operations_reviewer_01",
    "org_admin_01",
    "trust_officer_01",
    "trust_officer_02",
)
SYNTHETIC_PROVIDER_ONLY_ACCOUNT_CODES = ("invited_demand_owner_02",)
SYNTHETIC_CHOOSER_ACCOUNT_CODES = (
    SYNTHETIC_BOOTSTRAP_ACCOUNT_CODES + SYNTHETIC_PROVIDER_ONLY_ACCOUNT_CODES
)
EXPECTED_COMMANDS: Mapping[str, list[str]] = {
    "db": ["postgres"],
    "migrate": ["python", "-m", "desire_platform.deployment"],
    "taxonomy-seed": [
        "python",
        "-m",
        "desire_platform.deployment.synthetic_taxonomy_seed",
        "apply",
    ],
    "online-credentials-reconcile": [
        "python",
        "-m",
        "desire_platform.deployment.online_credentials",
        "reconcile",
    ],
    "online-credentials-verify": [
        "python",
        "-m",
        "desire_platform.deployment.online_credentials",
        "verify",
    ],
    "identity-bootstrap": [
        "python",
        "-m",
        "desire_platform.deployment.identity_bootstrap_orchestrator",
        "run",
    ],
    "synthetic-oidc": ["python", "-m", "desire_platform.synthetic_oidc"],
    "matching-runtime": [
        "python",
        "-m",
        "desire_platform.matching.runtime_process",
    ],
    "api": ["python", "-m", "desire_platform.internal_pilot.api_server"],
    "web": [
        "./node_modules/.bin/vinext",
        "start",
        "--hostname",
        "0.0.0.0",
        "--port",
        "3000",
    ],
    "edge": [
        "/usr/bin/caddy",
        "run",
        "--config",
        "/etc/caddy/Caddyfile",
        "--adapter",
        "caddyfile",
    ],
}
EXPECTED_USERS = {
    **{service: "10001:10001" for service in SERVICES if service not in {"db", "web", "edge"}},
    "db": "",
    "web": "node",
    "edge": "10001:10001",
}
EXPECTED_STOP_EXIT_CODES = {
    "db": frozenset((0,)),
    "synthetic-oidc": frozenset((0, 143)),
    "edge": frozenset((0,)),
    "matching-runtime": frozenset((0, 143)),
    "api": frozenset((0, 143)),
    "web": frozenset((0, 143)),
}
MAXIMUM_OUTPUT_BYTES = 4 * 1024 * 1024
MAXIMUM_INPUT_TREE_BYTES = 32 * 1024 * 1024
MAXIMUM_BUILD_SOURCE_BYTES = 128 * 1024 * 1024

_PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
_TAG = re.compile(r"^[a-z0-9][a-z0-9._-]{0,95}$")
_CONTEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_RESOURCE_ID = re.compile(r"^[0-9a-f]{64}$")
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_UUID = re.compile(
    r"^(?!0{8}-0{4}-0{4}-0{4}-0{12}$)"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}$"
)


class LocalInternalSandboxError(RuntimeError):
    """Stable non-reflective management failure."""

    def __init__(
        self,
        code: str = "LOCAL_INTERNAL_SANDBOX_INVALID",
        *,
        exit_code: int = 78,
    ) -> None:
        self.code = code
        self.exit_code = exit_code
        super().__init__(code)


class _ClosedArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        del message
        _invalid()


@dataclass(frozen=True)
class Coordinates:
    root: Path
    project_name: str
    image_tag: str
    domain: str
    ingress_cidr: str
    oidc_cidr: str
    app_cidr: str
    data_cidr: str
    bundle_name: str
    deployment_id: str
    release_id: str

    @property
    def metadata(self) -> Path:
        return self.root / METADATA_DIRECTORY

    @property
    def bundle(self) -> Path:
        return self.root / self.bundle_name

    @property
    def tls(self) -> Path:
        return self.root / "internal-sandbox-tls"

    def as_dict(self) -> dict[str, Any]:
        return {
            "app_cidr": self.app_cidr,
            "bundle_name": self.bundle_name,
            "data_cidr": self.data_cidr,
            "deployment_id": self.deployment_id,
            "domain": self.domain,
            "image_tag": self.image_tag,
            "ingress_cidr": self.ingress_cidr,
            "oidc_cidr": self.oidc_cidr,
            "project_name": self.project_name,
            "release_id": self.release_id,
            "repository_root": str(REPOSITORY_ROOT),
            "root": str(self.root),
        }


@dataclass(frozen=True)
class DockerRuntime:
    executable: str
    context: str
    environment: Mapping[str, str]


Runner = Callable[..., subprocess.CompletedProcess[str]]


def _invalid() -> NoReturn:
    raise LocalInternalSandboxError()


def _partial() -> NoReturn:
    raise LocalInternalSandboxError(
        "LOCAL_INTERNAL_SANDBOX_PARTIAL_POSSIBLE", exit_code=75
    )


def _json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _invalid()
        value[key] = item
    return value


def _parse_json(value: str) -> Any:
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAXIMUM_OUTPUT_BYTES:
        _invalid()
    try:
        return json.loads(value, object_pairs_hook=_json_pairs)
    except (json.JSONDecodeError, UnicodeError):
        _invalid()


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def _write_new_json(path: Path, value: Mapping[str, Any]) -> None:
    data = _canonical_json(value)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        written = 0
        while written < len(data):
            count = os.write(descriptor, data[written:])
            if count <= 0:
                _invalid()
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _closed_bytes(path: Path, *, maximum: int = 1024 * 1024) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        _invalid()
    try:
        file_stat = os.fstat(descriptor)
        path_stat = path.lstat()
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or stat.S_IMODE(file_stat.st_mode) != 0o600
            or file_stat.st_nlink != 1
            or not 1 <= file_stat.st_size <= maximum
            or path.is_symlink()
            or (file_stat.st_dev, file_stat.st_ino)
            != (path_stat.st_dev, path_stat.st_ino)
        ):
            _invalid()
        data = b""
        while len(data) <= maximum:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - len(data)))
            if not chunk:
                break
            data += chunk
        if not data or len(data) > maximum or os.read(descriptor, 1):
            _invalid()
        final = path.lstat()
        if (final.st_dev, final.st_ino) != (file_stat.st_dev, file_stat.st_ino):
            _invalid()
        return data
    except OSError:
        _invalid()
    finally:
        os.close(descriptor)


def _closed_json(path: Path) -> tuple[dict[str, Any], str]:
    data = _closed_bytes(path)
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        _invalid()
    parsed = _parse_json(text)
    if not isinstance(parsed, dict) or _canonical_json(parsed) != data:
        _invalid()
    return parsed, hashlib.sha256(data).hexdigest()


def _closed_generated_json(path: Path) -> dict[str, Any]:
    data = _closed_bytes(path)
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        _invalid()
    parsed = _parse_json(text)
    if not isinstance(parsed, dict):
        _invalid()
    return parsed


def _coordinates(arguments: argparse.Namespace, *, must_exist: bool) -> Coordinates:
    raw_root = Path(arguments.root)
    if not raw_root.is_absolute() or raw_root.name in ("", ".", ".."):
        _invalid()
    try:
        parent = raw_root.parent.resolve(strict=True)
    except OSError:
        _invalid()
    root = parent / raw_root.name
    root_text = str(root)
    if (
        root != raw_root
        or not 1 <= len(root_text) <= 1024
        or "'" in root_text
        or "\\" in root_text
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in root_text)
    ):
        _invalid()
    try:
        repository_relative = root.relative_to(REPOSITORY_ROOT)
    except ValueError:
        repository_relative = None
    if (
        repository_relative is not None
        and (not repository_relative.parts or repository_relative.parts[0] != "secrets")
    ):
        _invalid()
    if must_exist:
        try:
            metadata = root.lstat()
        except OSError:
            _invalid()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or root.is_symlink()
            or root.resolve(strict=True) != root
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            _invalid()
    elif root.exists() or root.is_symlink():
        _invalid()

    if _PROJECT.fullmatch(arguments.project_name) is None:
        _invalid()
    if _TAG.fullmatch(arguments.image_tag) is None:
        _invalid()
    if arguments.domain != FIXED_DOMAIN:
        _invalid()
    cidrs = _cidrs(
        arguments.ingress_cidr,
        arguments.oidc_cidr,
        arguments.app_cidr,
        arguments.data_cidr,
    )
    bundle_name = f"internal-sandbox-bundle-{arguments.image_tag}"
    if len(bundle_name) > 128:
        _invalid()
    return Coordinates(
        root=root,
        project_name=arguments.project_name,
        image_tag=arguments.image_tag,
        domain=arguments.domain,
        ingress_cidr=cidrs[0],
        oidc_cidr=cidrs[1],
        app_cidr=cidrs[2],
        data_cidr=cidrs[3],
        bundle_name=bundle_name,
        deployment_id=f"local-{arguments.project_name}",
        release_id=f"local-{arguments.image_tag}",
    )


def _cidrs(*values: str) -> tuple[str, str, str, str]:
    private = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    )
    networks: list[ipaddress.IPv4Network] = []
    for value in values:
        try:
            network = ipaddress.ip_network(value, strict=True)
        except (TypeError, ValueError):
            _invalid()
        if (
            not isinstance(network, ipaddress.IPv4Network)
            or network.prefixlen != 24
            or not any(network.subnet_of(item) for item in private)
        ):
            _invalid()
        networks.append(network)
    if len(set(networks)) != 4:
        _invalid()
    return tuple(str(item) for item in networks)  # type: ignore[return-value]


def _base_environment() -> dict[str, str]:
    home = os.environ.get("HOME")
    if not home or not Path(home).is_absolute():
        _invalid()
    return {
        "HOME": home,
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
    }


def _execute(
    command: Sequence[str],
    *,
    environment: Mapping[str, str],
    timeout: int,
    runner: Runner,
    allow_failure: bool = False,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = runner(
            list(command),
            cwd=str(REPOSITORY_ROOT),
            env=dict(environment),
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except BaseException:
        _invalid()
    if (
        not isinstance(completed.stdout, str)
        or not isinstance(completed.stderr, str)
        or len(completed.stdout.encode("utf-8")) > MAXIMUM_OUTPUT_BYTES
        or len(completed.stderr.encode("utf-8")) > MAXIMUM_OUTPUT_BYTES
    ):
        _invalid()
    if not allow_failure and completed.returncode != 0:
        _invalid()
    return completed


def _docker_runtime(*, runner: Runner) -> DockerRuntime:
    base = _base_environment()
    executable = shutil.which("docker", path=base["PATH"])
    if not executable or not Path(executable).is_absolute():
        _invalid()
    executable = str(Path(executable).resolve(strict=True))
    shown = _execute(
        (executable, "context", "show"),
        environment=base,
        timeout=30,
        runner=runner,
    ).stdout.strip()
    if _CONTEXT.fullmatch(shown) is None:
        _invalid()
    inspected = _execute(
        (
            executable,
            "context",
            "inspect",
            shown,
            "--format",
            "{{json .Endpoints.docker.Host}}",
        ),
        environment=base,
        timeout=30,
        runner=runner,
    ).stdout.strip()
    endpoint = _parse_json(inspected)
    if not isinstance(endpoint, str):
        _invalid()
    parsed = urlsplit(endpoint)
    if (
        parsed.scheme != "unix"
        or not parsed.path.startswith("/")
        or parsed.netloc
        or parsed.query
        or parsed.fragment
    ):
        _invalid()
    environment = dict(base)
    environment["DOCKER_CONTEXT"] = shown
    return DockerRuntime(executable, shown, environment)


def _docker(
    runtime: DockerRuntime,
    arguments: Sequence[str],
    *,
    runner: Runner,
    timeout: int = 60,
    allow_failure: bool = False,
) -> subprocess.CompletedProcess[str]:
    return _execute(
        (runtime.executable, *arguments),
        environment=runtime.environment,
        timeout=timeout,
        runner=runner,
        allow_failure=allow_failure,
    )


def _compose_arguments(coordinates: Coordinates, *arguments: str) -> tuple[str, ...]:
    return (
        "compose",
        "--project-name",
        coordinates.project_name,
        "--env-file",
        str(coordinates.root / "compose.env"),
        "-f",
        str(COMPOSE_FILE),
        "-f",
        str(coordinates.root / "compose.ipam.yaml"),
        *arguments,
    )


def _compose(
    runtime: DockerRuntime,
    coordinates: Coordinates,
    *arguments: str,
    runner: Runner,
    timeout: int = 180,
) -> subprocess.CompletedProcess[str]:
    return _docker(
        runtime,
        _compose_arguments(coordinates, *arguments),
        runner=runner,
        timeout=timeout,
    )


def _repository_sha256() -> str:
    try:
        metadata = COMPOSE_FILE.lstat()
    except OSError:
        _invalid()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or COMPOSE_FILE.is_symlink()
        or COMPOSE_FILE.resolve(strict=True) != COMPOSE_FILE
        or metadata.st_size > 2 * 1024 * 1024
    ):
        _invalid()
    return hashlib.sha256(COMPOSE_FILE.read_bytes()).hexdigest()


def _excluded_build_source(relative: Path) -> bool:
    excluded_directories = {
        ".git",
        ".github",
        ".devcontainer",
        ".local",
        ".venv",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        "node_modules",
        ".next",
        "dist",
        ".wrangler",
    }
    if any(part in excluded_directories for part in relative.parts):
        return True
    name = relative.name
    return (
        name == ".DS_Store"
        or (name == ".env" or name.startswith(".env."))
        and name != ".env.example"
        or name.endswith((".pyc", ".pyo", ".tsbuildinfo"))
    )


def _build_source_sha256() -> str:
    """Hash the closed source set copied by the three trial image targets."""

    roots = (
        Path(".dockerignore"),
        Path("Dockerfile"),
        Path("deploy/Caddyfile"),
        Path("platform/README.md"),
        Path("platform/pyproject.toml"),
        Path("platform/uv.lock"),
        Path("platform/src"),
        Path("web"),
    )
    digest = hashlib.sha256()
    total = 0
    pending = [REPOSITORY_ROOT / item for item in reversed(roots)]
    while pending:
        path = pending.pop()
        try:
            relative = path.relative_to(REPOSITORY_ROOT)
            metadata = path.lstat()
        except (OSError, ValueError):
            _invalid()
        if _excluded_build_source(relative):
            continue
        if path.is_symlink():
            _invalid()
        mode = stat.S_IMODE(metadata.st_mode)
        encoded_relative = relative.as_posix().encode("utf-8")
        if stat.S_ISDIR(metadata.st_mode):
            digest.update(
                b"D\0" + encoded_relative + b"\0" + oct(mode).encode("ascii") + b"\0"
            )
            try:
                children = sorted(path.iterdir(), key=lambda item: item.name, reverse=True)
            except OSError:
                _invalid()
            pending.extend(children)
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            _invalid()
        total += metadata.st_size
        if metadata.st_size < 0 or total > MAXIMUM_BUILD_SOURCE_BYTES:
            _invalid()
        try:
            content = path.read_bytes()
        except OSError:
            _invalid()
        if len(content) != metadata.st_size:
            _invalid()
        digest.update(
            b"F\0" + encoded_relative + b"\0" + oct(mode).encode("ascii") + b"\0"
        )
        digest.update(hashlib.sha256(content).digest())
    return digest.hexdigest()


def _git_evidence(*, runner: Runner) -> dict[str, Any]:
    environment = _base_environment()
    executable = shutil.which("git", path=environment["PATH"])
    if not executable or not Path(executable).is_absolute():
        _invalid()
    try:
        executable = str(Path(executable).resolve(strict=True))
    except OSError:
        _invalid()
    head = _execute(
        (executable, "rev-parse", "--verify", "HEAD"),
        environment=environment,
        timeout=30,
        runner=runner,
    ).stdout.strip()
    if re.fullmatch(r"[0-9a-f]{40,64}", head) is None:
        _invalid()
    status = _execute(
        (
            executable,
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
        ),
        environment=environment,
        timeout=30,
        runner=runner,
    ).stdout
    tracked_diff = _execute(
        (
            executable,
            "diff",
            "--binary",
            "--full-index",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "HEAD",
            "--",
        ),
        environment=environment,
        timeout=30,
        runner=runner,
    ).stdout
    untracked = _execute(
        (
            executable,
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
        ),
        environment=environment,
        timeout=30,
        runner=runner,
    ).stdout
    untracked_digest = hashlib.sha256()
    total = 0
    paths = untracked.split("\0")
    if paths[-1:] != [""] or len(paths) != len(set(paths)):
        _invalid()
    for value in sorted(paths[:-1]):
        relative = Path(value)
        if (
            not value
            or relative.is_absolute()
            or ".." in relative.parts
            or relative.as_posix() != value
        ):
            _invalid()
        path = REPOSITORY_ROOT / relative
        try:
            metadata = path.lstat()
        except OSError:
            _invalid()
        encoded = value.encode("utf-8")
        if stat.S_ISLNK(metadata.st_mode):
            try:
                content = os.readlink(path).encode("utf-8")
            except (OSError, UnicodeError):
                _invalid()
            kind = b"L"
        elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
            try:
                content = path.read_bytes()
            except OSError:
                _invalid()
            if len(content) != metadata.st_size:
                _invalid()
            kind = b"F"
        else:
            _invalid()
        total += len(content)
        if total > MAXIMUM_BUILD_SOURCE_BYTES:
            _invalid()
        untracked_digest.update(kind + b"\0" + encoded + b"\0")
        untracked_digest.update(hashlib.sha256(content).digest())
    return {
        "diff_sha256": hashlib.sha256(tracked_diff.encode("utf-8")).hexdigest(),
        "dirty": bool(status),
        "head": head,
        "status_sha256": hashlib.sha256(status.encode("utf-8")).hexdigest(),
        "untracked_sha256": untracked_digest.hexdigest(),
    }


def _source_binding(*, runner: Runner) -> dict[str, Any]:
    return {
        "build_source_sha256": _build_source_sha256(),
        "git": _git_evidence(runner=runner),
    }


def _validate_source_binding(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {"build_source_sha256", "git"}:
        _invalid()
    git = value.get("git")
    if (
        _SHA256.fullmatch(str(value.get("build_source_sha256"))) is None
        or not isinstance(git, dict)
        or set(git)
        != {
            "diff_sha256",
            "dirty",
            "head",
            "status_sha256",
            "untracked_sha256",
        }
        or type(git.get("dirty")) is not bool
        or re.fullmatch(r"[0-9a-f]{40,64}", str(git.get("head"))) is None
        or _SHA256.fullmatch(str(git.get("diff_sha256"))) is None
        or _SHA256.fullmatch(str(git.get("status_sha256"))) is None
        or _SHA256.fullmatch(str(git.get("untracked_sha256"))) is None
    ):
        _invalid()


def _project_inventory(
    runtime: DockerRuntime, coordinates: Coordinates, *, runner: Runner
) -> dict[str, frozenset[str]]:
    label = f"label=com.docker.compose.project={coordinates.project_name}"
    values: dict[str, frozenset[str]] = {}
    for kind, command in (
        (
            "containers",
            ("container", "ls", "-aq", "--no-trunc", "--filter", label),
        ),
        (
            "networks",
            ("network", "ls", "-q", "--no-trunc", "--filter", label),
        ),
        ("volumes", ("volume", "ls", "-q", "--filter", label)),
    ):
        output = _docker(runtime, command, runner=runner).stdout
        identifiers = tuple(line.strip() for line in output.splitlines() if line.strip())
        if any(any(character.isspace() for character in item) for item in identifiers):
            _invalid()
        values[kind] = frozenset(identifiers)
    return values


def _project_unused(
    runtime: DockerRuntime, coordinates: Coordinates, *, runner: Runner
) -> None:
    if any(_project_inventory(runtime, coordinates, runner=runner).values()):
        _invalid()
    names = [f"{coordinates.project_name}-{service}-1" for service in SERVICES]
    names.extend(
        f"{coordinates.project_name}_{service}_1" for service in SERVICES
    )
    for kind, candidates in (
        ("container", names),
        ("network", [f"{coordinates.project_name}_{name}" for name in NETWORKS]),
        ("volume", [f"{coordinates.project_name}_postgres-data"]),
    ):
        for name in candidates:
            inspected = _docker(
                runtime,
                (kind, "inspect", name),
                runner=runner,
                allow_failure=True,
            )
            if inspected.returncode == 0:
                _invalid()


def _image_tags_unused(
    runtime: DockerRuntime, coordinates: Coordinates, *, runner: Runner
) -> None:
    for reference in (
        f"desire-supply-platform:{coordinates.image_tag}",
        f"desire-supply-web:{coordinates.image_tag}",
        f"desire-supply-edge:{coordinates.image_tag}",
    ):
        inspected = _docker(
            runtime,
            ("image", "inspect", reference),
            runner=runner,
            allow_failure=True,
        )
        if inspected.returncode == 0:
            _invalid()


def _cidrs_unused(
    runtime: DockerRuntime, coordinates: Coordinates, *, runner: Runner
) -> None:
    output = _docker(runtime, ("network", "ls", "-q"), runner=runner).stdout
    identifiers = tuple(line.strip() for line in output.splitlines() if line.strip())
    if not identifiers:
        return
    inspected = _docker(
        runtime,
        ("network", "inspect", *identifiers),
        runner=runner,
    )
    documents = _parse_json(inspected.stdout)
    if not isinstance(documents, list) or len(documents) != len(set(identifiers)):
        _invalid()
    proposed = tuple(
        ipaddress.ip_network(value)
        for value in (
            coordinates.ingress_cidr,
            coordinates.oidc_cidr,
            coordinates.app_cidr,
            coordinates.data_cidr,
        )
    )
    for document in documents:
        if not isinstance(document, dict):
            _invalid()
        ipam = document.get("IPAM")
        configurations = ipam.get("Config", []) if isinstance(ipam, dict) else []
        if configurations is None:
            configurations = []
        if not isinstance(configurations, list):
            _invalid()
        for configuration in configurations:
            subnet = configuration.get("Subnet") if isinstance(configuration, dict) else None
            if not isinstance(subnet, str):
                continue
            try:
                existing = ipaddress.ip_network(subnet, strict=False)
            except ValueError:
                continue
            if isinstance(existing, ipaddress.IPv4Network) and any(
                existing.overlaps(candidate) for candidate in proposed
            ):
                _invalid()


def _port_unused() -> None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(0.5)
            if connection.connect_ex(("127.0.0.1", 443)) == 0:
                _invalid()
    except LocalInternalSandboxError:
        raise
    except OSError:
        _invalid()


def _create_private_directory(path: Path) -> None:
    os.mkdir(path, 0o700)
    os.chmod(path, 0o700)
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or path.is_symlink()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        _invalid()


def _helper_environment(*, python_path: str | None = None) -> dict[str, str]:
    environment = _base_environment()
    if python_path is not None:
        environment["PYTHONPATH"] = python_path
    return environment


def _validate_deployment_document(
    document: Mapping[str, Any], coordinates: Coordinates
) -> None:
    if set(document) != {
        "bind",
        "deployment_mode",
        "external_participants_enabled",
        "internal_bff_origin",
        "oidc",
        "postgres",
        "runtime_config_path",
        "schema_name",
        "secret_manifest_path",
        "secret_root",
        "system_actor_id",
    }:
        _invalid()
    oidc = document.get("oidc")
    if (
        document.get("schema_name")
        != "desire-internal-sandbox-deployment-v1"
        or document.get("deployment_mode") != "INTERNAL_SANDBOX"
        or document.get("external_participants_enabled") is not False
        or document.get("internal_bff_origin") != "http://api:8000"
        or document.get("runtime_config_path") != "/run/desire/runtime-config.json"
        or document.get("secret_manifest_path")
        != "/run/desire/secret-manifest.json"
        or document.get("secret_root") != "/run/secrets"
        or document.get("postgres")
        != {
            "database": "desire",
            "host": "db",
            "port": 5432,
            "transport_security": "TRUSTED_CONTAINER_NETWORK",
        }
        or document.get("bind") != {"host": "0.0.0.0", "port": 8000}
        or _UUID.fullmatch(str(document.get("system_actor_id"))) is None
        or not isinstance(oidc, dict)
        or set(oidc)
        != {
            "allowed_signing_algorithms",
            "client_id",
            "client_secret_key_id",
            "clock_skew_seconds",
            "issuer",
            "maximum_response_bytes",
            "metadata_ttl_seconds",
            "network_binding",
            "redirect_uri",
            "request_timeout_seconds",
            "subject_digest_key_id",
        }
        or oidc.get("issuer") != f"https://identity.{coordinates.domain}"
        or oidc.get("client_id") != SYNTHETIC_CLIENT_ID
        or oidc.get("client_secret_key_id") != "oidc-client-secret-v1"
        or oidc.get("redirect_uri")
        != f"https://pilot.{coordinates.domain}/v1/auth/oidc/callback"
        or oidc.get("allowed_signing_algorithms") != ["RS256"]
        or oidc.get("metadata_ttl_seconds") != 300
        or oidc.get("request_timeout_seconds") != 3
        or oidc.get("maximum_response_bytes") != 262_144
        or oidc.get("clock_skew_seconds") != 30
        or oidc.get("subject_digest_key_id") != "oidc-subject-digest-v1"
        or oidc.get("network_binding")
        != {"mode": "SYSTEM_DNS_SYNTHETIC", "pinned_public_ipv4": None}
    ):
        _invalid()


def _validate_generated_bundle(coordinates: Coordinates) -> None:
    _validate_deployment_document(
        _closed_generated_json(coordinates.bundle / "config" / "deployment.json"),
        coordinates,
    )


def _helper(
    command: Sequence[str],
    *,
    expected_status: str,
    environment: Mapping[str, str],
    runner: Runner,
    timeout: int = 120,
) -> None:
    result = _execute(
        command,
        environment=environment,
        timeout=timeout,
        runner=runner,
    )
    document = _parse_json(result.stdout)
    if not isinstance(document, dict) or document.get("status") != expected_status:
        _invalid()


def _platform_python(value: str | None) -> str:
    candidate = (
        REPOSITORY_ROOT / "platform" / ".venv" / "bin" / "python"
        if value is None
        else Path(value)
    )
    if not candidate.is_absolute():
        _invalid()
    try:
        resolved = candidate.resolve(strict=True)
        metadata = resolved.stat()
    except OSError:
        _invalid()
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        _invalid()
    # Keep the venv-facing path: resolving its interpreter symlink would lose
    # pyvenv.cfg discovery and therefore the closed platform dependencies.
    return str(candidate)


def _prepare_helpers(
    coordinates: Coordinates,
    *,
    platform_python: str,
    runner: Runner,
) -> None:
    scripts = REPOSITORY_ROOT / "scripts"
    system_environment = _helper_environment()
    _helper(
        (
            sys.executable,
            "-B",
            str(scripts / "prepare_internal_sandbox_inputs.py"),
            "create",
            "--output-root",
            str(coordinates.root),
        ),
        expected_status="INTERNAL_SANDBOX_INPUTS_CREATED",
        environment=system_environment,
        runner=runner,
    )
    _helper(
        (
            sys.executable,
            "-B",
            str(scripts / "manage_internal_sandbox_tls.py"),
            "create",
            "--output-dir",
            str(coordinates.tls),
        ),
        expected_status="INTERNAL_SANDBOX_TLS_CREATED",
        environment=system_environment,
        runner=runner,
    )
    _helper(
        (
            platform_python,
            "-B",
            "-m",
            "desire_platform.deployment.internal_sandbox_bundle",
            "create",
            "--output-dir",
            str(coordinates.bundle),
            "--oidc-issuer",
            f"https://identity.{coordinates.domain}",
            "--oidc-client-id",
            SYNTHETIC_CLIENT_ID,
            "--oidc-redirect-uri",
            f"https://pilot.{coordinates.domain}/v1/auth/oidc/callback",
            "--oidc-client-secret-file",
            str(coordinates.root / "oidc-client-secret"),
            "--oidc-network-binding-mode",
            "SYSTEM_DNS_SYNTHETIC",
            "--deployment-id",
            coordinates.deployment_id,
            "--release-id",
            coordinates.release_id,
        ),
        expected_status="INTERNAL_SANDBOX_BUNDLE_CREATED",
        environment=_helper_environment(
            python_path=str(REPOSITORY_ROOT / "platform" / "src")
        ),
        runner=runner,
    )
    _helper(
        (
            sys.executable,
            "-B",
            str(scripts / "prepare_internal_sandbox_compose_inputs.py"),
            "create",
            "--input-root",
            str(coordinates.root),
            "--image-tag",
            coordinates.image_tag,
            "--bundle-dir-name",
            coordinates.bundle_name,
            "--ingress-subnet",
            coordinates.ingress_cidr,
            "--oidc-subnet",
            coordinates.oidc_cidr,
            "--app-subnet",
            coordinates.app_cidr,
            "--data-subnet",
            coordinates.data_cidr,
        ),
        expected_status="INTERNAL_SANDBOX_COMPOSE_INPUTS_CREATED",
        environment=system_environment,
        runner=runner,
    )


def _verify_helpers(coordinates: Coordinates, *, runner: Runner) -> None:
    scripts = REPOSITORY_ROOT / "scripts"
    environment = _helper_environment()
    _helper(
        (
            sys.executable,
            "-B",
            str(scripts / "prepare_internal_sandbox_inputs.py"),
            "verify",
            "--input-root",
            str(coordinates.root),
        ),
        expected_status="INTERNAL_SANDBOX_INPUTS_VERIFIED",
        environment=environment,
        runner=runner,
    )
    _helper(
        (
            sys.executable,
            "-B",
            str(scripts / "manage_internal_sandbox_tls.py"),
            "verify",
            "--input-dir",
            str(coordinates.tls),
        ),
        expected_status="INTERNAL_SANDBOX_TLS_VERIFIED",
        environment=environment,
        runner=runner,
    )
    _helper(
        (
            sys.executable,
            "-B",
            str(scripts / "prepare_internal_sandbox_compose_inputs.py"),
            "verify",
            "--input-root",
            str(coordinates.root),
            "--image-tag",
            coordinates.image_tag,
            "--bundle-dir-name",
            coordinates.bundle_name,
            "--ingress-subnet",
            coordinates.ingress_cidr,
            "--oidc-subnet",
            coordinates.oidc_cidr,
            "--app-subnet",
            coordinates.app_cidr,
            "--data-subnet",
            coordinates.data_cidr,
        ),
        expected_status="INTERNAL_SANDBOX_COMPOSE_INPUTS_VERIFIED",
        environment=environment,
        runner=runner,
    )


def _input_tree_sha256(coordinates: Coordinates) -> str:
    expected_root_entries = {
        "db_superuser_password.txt",
        "taxonomy_seed_workload_credential",
        "taxonomy_seed_receipt_hmac_key",
        "oidc-client-secret",
        "internal-sandbox-identity-sources",
        "internal-sandbox-tls",
        coordinates.bundle_name,
        "compose.env",
        "compose.ipam.yaml",
        METADATA_DIRECTORY,
    }
    try:
        if {path.name for path in coordinates.root.iterdir()} != expected_root_entries:
            _invalid()
    except OSError:
        _invalid()
    roots = tuple(
        coordinates.root / name
        for name in sorted(expected_root_entries - {METADATA_DIRECTORY})
    )
    digest = hashlib.sha256()
    total = 0
    for root in roots:
        pending = [root]
        while pending:
            path = pending.pop()
            try:
                metadata = path.lstat()
            except OSError:
                _invalid()
            if path.is_symlink():
                _invalid()
            relative = path.relative_to(coordinates.root).as_posix().encode("utf-8")
            mode = stat.S_IMODE(metadata.st_mode)
            if stat.S_ISDIR(metadata.st_mode):
                digest.update(b"D\0" + relative + b"\0" + oct(mode).encode("ascii") + b"\0")
                try:
                    children = sorted(path.iterdir(), key=lambda item: item.name, reverse=True)
                except OSError:
                    _invalid()
                pending.extend(children)
            elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                if metadata.st_size < 0:
                    _invalid()
                total += metadata.st_size
                if total > MAXIMUM_INPUT_TREE_BYTES:
                    _invalid()
                digest.update(b"F\0" + relative + b"\0" + oct(mode).encode("ascii") + b"\0")
                try:
                    data = path.read_bytes()
                except OSError:
                    _invalid()
                if len(data) != metadata.st_size:
                    _invalid()
                digest.update(hashlib.sha256(data).digest())
            else:
                _invalid()
    return digest.hexdigest()


def _prepared_document(
    coordinates: Coordinates,
    *,
    input_sha256: str,
    compose_sha256: str,
    source_binding: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "compose_sha256": compose_sha256,
        "coordinates": coordinates.as_dict(),
        "input_tree_sha256": input_sha256,
        "schema": RECEIPT_SCHEMA,
        "source_binding": dict(source_binding),
        "status": "PREPARED",
    }


def _validate_coordinate_receipt(
    document: Mapping[str, Any], coordinates: Coordinates, *, status: str
) -> None:
    if (
        set(document) != {"coordinates", "schema", "status"}
        or document.get("schema") != RECEIPT_SCHEMA
        or document.get("status") != status
        or document.get("coordinates") != coordinates.as_dict()
    ):
        _invalid()


def _load_prepared(
    coordinates: Coordinates,
    *,
    runner: Runner,
    verify_current: bool = True,
) -> tuple[dict[str, Any], str]:
    metadata = coordinates.metadata
    try:
        info = metadata.lstat()
    except OSError:
        _invalid()
    if (
        not stat.S_ISDIR(info.st_mode)
        or metadata.is_symlink()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        _invalid()
    attempt, _attempt_sha = _closed_json(metadata / PREPARE_ATTEMPT)
    _validate_coordinate_receipt(attempt, coordinates, status="PREPARING")
    document, receipt_sha = _closed_json(metadata / PREPARED_RECEIPT)
    if (
        set(document)
        != {
            "compose_sha256",
            "coordinates",
            "input_tree_sha256",
            "schema",
            "source_binding",
            "status",
        }
        or document.get("schema") != RECEIPT_SCHEMA
        or document.get("status") != "PREPARED"
        or document.get("coordinates") != coordinates.as_dict()
        or _SHA256.fullmatch(str(document.get("compose_sha256"))) is None
        or _SHA256.fullmatch(str(document.get("input_tree_sha256"))) is None
    ):
        _invalid()
    _validate_source_binding(document.get("source_binding"))
    if verify_current:
        if (
            document["compose_sha256"] != _repository_sha256()
            or document["source_binding"] != _source_binding(runner=runner)
        ):
            _invalid()
        _validate_generated_bundle(coordinates)
        _verify_helpers(coordinates, runner=runner)
        if document["input_tree_sha256"] != _input_tree_sha256(coordinates):
            _invalid()
    return document, receipt_sha


def _validate_compose_config(document: Any, coordinates: Coordinates) -> None:
    if not isinstance(document, dict) or document.get("name") != coordinates.project_name:
        _invalid()
    services = document.get("services")
    networks = document.get("networks")
    if (
        not isinstance(services, dict)
        or set(services) != set(SERVICES)
        or not isinstance(networks, dict)
        or set(networks) != set(NETWORKS)
    ):
        _invalid()
    expected_images = {
        **{
            service: f"desire-supply-platform:{coordinates.image_tag}"
            for service in SERVICES
            if service not in {"db", "web", "edge"}
        },
        "web": f"desire-supply-web:{coordinates.image_tag}",
        "edge": f"desire-supply-edge:{coordinates.image_tag}",
    }
    expected_images["db"] = POSTGRES_IMAGE
    expected_compose_commands = {
        service: command
        for service, command in EXPECTED_COMMANDS.items()
        if service not in {"db", "web", "edge"}
    }
    internal_environment_services = {
        "migrate",
        "taxonomy-seed",
        "online-credentials-reconcile",
        "online-credentials-verify",
        "identity-bootstrap",
        "synthetic-oidc",
    }
    for service, definition in services.items():
        if not isinstance(definition, dict):
            _invalid()
        if definition.get("logging") != BOUNDED_LOGGING:
            _invalid()
        ports = definition.get("ports", [])
        if service != "edge" and ports:
            _invalid()
        if service in expected_images and definition.get("image") != expected_images[service]:
            _invalid()
        if (
            definition.get("user") is not None
            or definition.get("entrypoint") is not None
            or definition.get("cap_add") not in (None, [])
            or definition.get("devices") not in (None, [])
            or definition.get("device_cgroup_rules") not in (None, [])
            or definition.get("group_add") not in (None, [])
            or definition.get("privileged") not in (None, False)
            or definition.get("pid") is not None
            or definition.get("ipc") is not None
        ):
            _invalid()
        expected_command = expected_compose_commands.get(service)
        if definition.get("command") != expected_command:
            _invalid()
        expected_tmpfs = ["/tmp:rw,noexec,nosuid,nodev,size=64m"]
        if service == "identity-bootstrap":
            expected_tmpfs.append(
                "/run/identity-bootstrap:rw,noexec,nosuid,nodev,size=1m,"
                "uid=10001,gid=10001,mode=0700"
            )
        if service == "matching-runtime":
            expected_tmpfs.append(
                "/run/matching-runtime:rw,noexec,nosuid,nodev,size=64k,"
                "uid=10001,gid=10001,mode=0700"
            )
        expected_restart = (
            "unless-stopped" if service == "matching-runtime" else "no"
        )
        if service != "db" and (
            definition.get("read_only") is not True
            or definition.get("init") is not True
            or definition.get("restart") != expected_restart
            or definition.get("cap_drop") != ["ALL"]
            or definition.get("security_opt") != ["no-new-privileges=true"]
            or definition.get("tmpfs") != expected_tmpfs
        ):
            _invalid()
        if service in internal_environment_services:
            environment = definition.get("environment")
            if (
                not isinstance(environment, dict)
                or environment.get("DESIRE_DEPLOYMENT_MODE") != "INTERNAL_SANDBOX"
                or environment.get("DESIRE_EXTERNAL_PARTICIPANTS_ENABLED")
                != "false"
            ):
                _invalid()
        if service == "matching-runtime" and definition.get("environment") != {
            "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE": (
                "/run/desire/matching-deployment.json"
            ),
            "DESIRE_MATCHING_RUNTIME_HEALTH_FILE": (
                "/run/matching-runtime/healthy"
            ),
        }:
            _invalid()
    if (
        services["db"].get("restart") != "unless-stopped"
        or services["db"].get("read_only") is not None
        or services["db"].get("init") is not None
        or services["db"].get("cap_drop") is not None
        or services["db"].get("security_opt") is not None
        or services["db"].get("tmpfs")
        != ["/var/lib/postgresql:rw,nosuid,nodev,noexec,size=1m"]
    ):
        _invalid()
    expected_db_volume = [
        {
            "type": "volume",
            "source": "postgres-data",
            "target": "/var/lib/postgresql/data",
            "volume": {},
        }
    ]
    expected_identity_volume = [
        {
            "type": "bind",
            "source": str(coordinates.root / "internal-sandbox-identity-sources"),
            "target": "/run/identity-sources",
            "read_only": True,
            "bind": {"create_host_path": False},
        }
    ]
    for service, definition in services.items():
        expected_volumes = (
            expected_db_volume
            if service == "db"
            else expected_identity_volume
            if service == "identity-bootstrap"
            else None
        )
        if definition.get("volumes") != expected_volumes:
            _invalid()
    volumes = document.get("volumes")
    if volumes != {
        "postgres-data": {"name": f"{coordinates.project_name}_postgres-data"}
    }:
        _invalid()
    if services["edge"].get("ports") != [
        {
            "mode": "ingress",
            "host_ip": "127.0.0.1",
            "target": 443,
            "published": "443",
            "protocol": "tcp",
        }
    ]:
        _invalid()
    expected_cidrs = {
        "ingress": coordinates.ingress_cidr,
        "oidc-backend": coordinates.oidc_cidr,
        "app": coordinates.app_cidr,
        "data": coordinates.data_cidr,
    }
    for name, cidr in expected_cidrs.items():
        network = networks[name]
        if not isinstance(network, dict):
            _invalid()
        ipam = network.get("ipam")
        if not isinstance(ipam, dict) or ipam.get("config") != [{"subnet": cidr}]:
            _invalid()
        if name != "ingress" and network.get("internal") is not True:
            _invalid()
        if name == "ingress" and network.get("internal") is True:
            _invalid()
    edge_networks = services["edge"].get("networks")
    app_network = edge_networks.get("app") if isinstance(edge_networks, dict) else None
    aliases = app_network.get("aliases", []) if isinstance(app_network, dict) else []
    if f"identity.{coordinates.domain}" not in aliases:
        _invalid()
    _validate_resolved_attachments(document, coordinates)


def _resolved_config(
    runtime: DockerRuntime, coordinates: Coordinates, *, runner: Runner
) -> dict[str, Any]:
    completed = _compose(
        runtime,
        coordinates,
        "config",
        "--format",
        "json",
        runner=runner,
    )
    document = _parse_json(completed.stdout)
    _validate_compose_config(document, coordinates)
    return document


def _image_id(
    runtime: DockerRuntime, reference: str, *, runner: Runner
) -> str:
    output = _docker(
        runtime,
        ("image", "inspect", "--format", "{{.Id}}", reference),
        runner=runner,
    ).stdout.strip()
    if _IMAGE_ID.fullmatch(output) is None:
        _invalid()
    return output


def _application_image_ids(
    runtime: DockerRuntime, coordinates: Coordinates, *, runner: Runner
) -> dict[str, str]:
    return {
        "platform": _image_id(
            runtime,
            f"desire-supply-platform:{coordinates.image_tag}",
            runner=runner,
        ),
        "web": _image_id(
            runtime,
            f"desire-supply-web:{coordinates.image_tag}",
            runner=runner,
        ),
        "edge": _image_id(
            runtime,
            f"desire-supply-edge:{coordinates.image_tag}",
            runner=runner,
        ),
    }


def _expected_service_image_ids(application: Mapping[str, str]) -> dict[str, str]:
    if set(application) != {"platform", "web", "edge"}:
        _invalid()
    return {
        **{
            service: application["platform"]
            for service in SERVICES
            if service not in {"db", "web", "edge"}
        },
        "web": application["web"],
        "edge": application["edge"],
    }


def _validate_application_image_tags(
    runtime: DockerRuntime,
    coordinates: Coordinates,
    service_image_ids: Mapping[str, str],
    *,
    runner: Runner,
) -> None:
    expected = _expected_service_image_ids(
        _application_image_ids(runtime, coordinates, runner=runner)
    )
    for service, image_id in expected.items():
        if service_image_ids.get(service) != image_id:
            _invalid()


def _service_id(
    runtime: DockerRuntime,
    coordinates: Coordinates,
    service: str,
    *,
    runner: Runner,
) -> str:
    output = _compose(
        runtime,
        coordinates,
        "ps",
        "--all",
        "--quiet",
        service,
        runner=runner,
    ).stdout
    identifiers = tuple(line.strip() for line in output.splitlines() if line.strip())
    if len(identifiers) != 1 or _RESOURCE_ID.fullmatch(identifiers[0]) is None:
        _invalid()
    return identifiers[0]


def _inspect_containers(
    runtime: DockerRuntime, identifiers: Sequence[str], *, runner: Runner
) -> dict[str, dict[str, Any]]:
    if len(identifiers) != len(set(identifiers)) or not identifiers:
        _invalid()
    documents = _parse_json(
        _docker(
            runtime,
            ("container", "inspect", *identifiers),
            runner=runner,
        ).stdout
    )
    if not isinstance(documents, list) or len(documents) != len(identifiers):
        _invalid()
    result: dict[str, dict[str, Any]] = {}
    for document in documents:
        identifier = document.get("Id") if isinstance(document, dict) else None
        if (
            not isinstance(identifier, str)
            or identifier not in identifiers
            or identifier in result
        ):
            _invalid()
        result[identifier] = document
    return result


def _validate_resolved_attachments(
    document: Mapping[str, Any], coordinates: Coordinates
) -> None:
    expected_configs = {
        "internal-sandbox-deployment": coordinates.bundle / "config" / "deployment.json",
        "internal-sandbox-runtime-config": coordinates.bundle / "config" / "runtime-config.json",
        "internal-sandbox-secret-manifest": coordinates.bundle / "config" / "secret-manifest.json",
        "internal-sandbox-matching-deployment": (
            coordinates.bundle / "config" / "matching-deployment.json"
        ),
        "internal-sandbox-matching-runtime-config": (
            coordinates.bundle / "config" / "matching-runtime-config.json"
        ),
        "internal-sandbox-matching-secret-manifest": (
            coordinates.bundle / "config" / "matching-secret-manifest.json"
        ),
        "internal-sandbox-online-credentials-deployment": (
            coordinates.bundle / "config" / "online-credentials-deployment.json"
        ),
        "internal-sandbox-online-credentials-runtime-config": (
            coordinates.bundle
            / "config"
            / "online-credentials-runtime-config.json"
        ),
        "internal-sandbox-online-credentials-secret-manifest": (
            coordinates.bundle
            / "config"
            / "online-credentials-secret-manifest.json"
        ),
        "internal-sandbox-identity-template": (
            REPOSITORY_ROOT
            / "platform/examples/internal-sandbox-identity-bootstrap-template-v1.json"
        ),
        "internal-sandbox-root-ca": coordinates.tls / "root-ca.pem",
        "internal-sandbox-edge-tls-chain": coordinates.tls / "edge-tls-chain.pem",
    }
    expected_secrets = {
        "db_superuser_password": coordinates.root / "db_superuser_password.txt",
        "taxonomy_seed_workload_credential": (
            coordinates.root / "taxonomy_seed_workload_credential"
        ),
        "taxonomy_seed_receipt_hmac_key": (
            coordinates.root / "taxonomy_seed_receipt_hmac_key"
        ),
        "edge-tls-key": coordinates.tls / "edge-tls-key.pem",
    }
    services = document.get("services")
    if not isinstance(services, dict):
        _invalid()
    referenced_secrets: set[str] = set()
    for definition in services.values():
        if not isinstance(definition, dict):
            _invalid()
        for attachment in definition.get("secrets") or []:
            source = attachment.get("source") if isinstance(attachment, dict) else None
            if not isinstance(source, str) or not source:
                _invalid()
            referenced_secrets.add(source)
    runtime_names = referenced_secrets - set(expected_secrets)
    expected_secrets.update(
        {
            name: coordinates.bundle / "runtime-secrets" / name
            for name in runtime_names
        }
    )
    for kind, expected in (
        ("configs", expected_configs),
        ("secrets", expected_secrets),
    ):
        observed = document.get(kind)
        if not isinstance(observed, dict) or set(observed) != set(expected):
            _invalid()
        for name, path in expected.items():
            if observed.get(name) != {
                "name": f"{coordinates.project_name}_{name}",
                "file": str(path),
            }:
                _invalid()


def _expected_live_mounts(
    resolved: Mapping[str, Any], coordinates: Coordinates, service: str
) -> list[tuple[str, str, str, bool]]:
    services = resolved.get("services")
    if not isinstance(services, dict) or not isinstance(services.get(service), dict):
        _invalid()
    definition = services[service]
    expected: list[tuple[str, str, str, bool]] = []
    for volume in definition.get("volumes") or []:
        if not isinstance(volume, dict):
            _invalid()
        if volume.get("type") == "volume":
            expected.append(
                (
                    "volume",
                    f"{coordinates.project_name}_{volume.get('source')}",
                    str(volume.get("target")),
                    not bool(volume.get("read_only", False)),
                )
            )
        elif volume.get("type") == "bind":
            expected.append(
                (
                    "bind",
                    str(volume.get("source")),
                    str(volume.get("target")),
                    not bool(volume.get("read_only", False)),
                )
            )
        else:
            _invalid()
    for kind in ("configs", "secrets"):
        catalog = resolved.get(kind)
        if not isinstance(catalog, dict):
            _invalid()
        for attachment in definition.get(kind) or []:
            if not isinstance(attachment, dict):
                _invalid()
            source_name = attachment.get("source")
            source = catalog.get(source_name)
            if not isinstance(source_name, str) or not isinstance(source, dict):
                _invalid()
            target = attachment.get("target")
            if not isinstance(target, str) or not target:
                _invalid()
            if kind == "secrets" and not target.startswith("/"):
                target = "/run/secrets/" + target
            expected.append(("bind", str(source.get("file")), target, False))
    if (
        any(
            mount_type not in {"bind", "volume"}
            or not source
            or not destination.startswith("/")
            or destination == "/"
            for mount_type, source, destination, _rw in expected
        )
        or len({item[2] for item in expected}) != len(expected)
    ):
        _invalid()
    return sorted(expected)


def _live_mounts(document: Mapping[str, Any]) -> list[tuple[str, str, str, bool]]:
    mounts = document.get("Mounts")
    if not isinstance(mounts, list):
        _invalid()
    normalized: list[tuple[str, str, str, bool]] = []
    for mount in mounts:
        if not isinstance(mount, dict) or type(mount.get("RW")) is not bool:
            _invalid()
        mount_type = mount.get("Type")
        source = mount.get("Name") if mount_type == "volume" else mount.get("Source")
        destination = mount.get("Destination")
        if (
            mount_type not in {"bind", "volume"}
            or not isinstance(source, str)
            or not source
            or not isinstance(destination, str)
            or not destination.startswith("/")
            or destination == "/"
        ):
            _invalid()
        normalized.append((mount_type, source, destination, mount["RW"]))
    if len({item[2] for item in normalized}) != len(normalized):
        _invalid()
    return sorted(normalized)


def _security_sequence(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) or not item for item in value)
        or len(value) != len(set(value))
    ):
        _invalid()
    return tuple(sorted(value))


def _security_options(value: Any) -> tuple[str, ...]:
    result = []
    for item in _security_sequence(value):
        if item == "no-new-privileges=true":
            item = "no-new-privileges:true"
        result.append(item)
    return tuple(sorted(result))


def _security_projection_sha256(document: Mapping[str, Any]) -> str:
    config = document.get("Config")
    host = document.get("HostConfig")
    mounts = document.get("Mounts")
    if not isinstance(config, dict) or not isinstance(host, dict) or not isinstance(mounts, list):
        _invalid()
    try:
        ordered_mounts = sorted(
            mounts,
            key=lambda item: (
                str(item.get("Destination")) if isinstance(item, dict) else "",
                json.dumps(item, ensure_ascii=True, separators=(",", ":"), sort_keys=True),
            ),
        )
        canonical = json.dumps(
            {"Config": config, "HostConfig": host, "Mounts": ordered_mounts},
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _invalid()
    return hashlib.sha256(canonical).hexdigest()


def _validate_container(
    document: Mapping[str, Any],
    *,
    coordinates: Coordinates,
    service: str,
    image_id: str,
    resolved: Mapping[str, Any] | None = None,
    expected_security_sha256: str | None = None,
    strict_state: bool = True,
) -> str:
    config = document.get("Config")
    host = document.get("HostConfig")
    state = document.get("State")
    network_settings = document.get("NetworkSettings")
    if not all(isinstance(item, dict) for item in (config, host, state, network_settings)):
        _invalid()
    labels = config.get("Labels")
    expected_reference = (
        POSTGRES_IMAGE
        if service == "db"
        else f"desire-supply-web:{coordinates.image_tag}"
        if service == "web"
        else f"desire-supply-edge:{coordinates.image_tag}"
        if service == "edge"
        else f"desire-supply-platform:{coordinates.image_tag}"
    )
    if (
        not isinstance(labels, dict)
        or labels.get("com.docker.compose.project") != coordinates.project_name
        or labels.get("com.docker.compose.service") != service
        or config.get("Image") != expected_reference
        or config.get("User") != EXPECTED_USERS[service]
        or config.get("Cmd") != EXPECTED_COMMANDS[service]
        or document.get("Image") != image_id
        or type(document.get("RestartCount")) is not int
        or document.get("RestartCount") < 0
        or (strict_state and document.get("RestartCount") != 0)
    ):
        _invalid()
    bindings = host.get("PortBindings") or {}
    expected_binding = {"443/tcp": [{"HostIp": "127.0.0.1", "HostPort": "443"}]}
    if (service == "edge" and bindings != expected_binding) or (
        service != "edge" and bindings
    ):
        _invalid()
    restart = host.get("RestartPolicy")
    expected_restart = (
        "unless-stopped" if service in {"db", "matching-runtime"} else "no"
    )
    expected_read_only = service != "db"
    expected_cap_drop = () if service == "db" else ("ALL",)
    expected_security_opt = () if service == "db" else ("no-new-privileges:true",)
    expected_network_modes = {
        f"{coordinates.project_name}_{name}" for name in SERVICE_NETWORKS[service]
    }
    if (
        not isinstance(restart, dict)
        or restart.get("Name") != expected_restart
        or restart.get("MaximumRetryCount") != 0
        or host.get("Privileged") is not False
        or host.get("ReadonlyRootfs") is not expected_read_only
        or host.get("AutoRemove") is not False
        or host.get("PublishAllPorts") is not False
        or host.get("Init") not in ((None, False) if service == "db" else (True,))
        or _security_sequence(host.get("CapAdd")) != ()
        or _security_sequence(host.get("CapDrop")) != expected_cap_drop
        or _security_options(host.get("SecurityOpt")) != expected_security_opt
        or host.get("LogConfig") != DOCKER_LOG_CONFIG
        or host.get("Devices") not in (None, [])
        or host.get("DeviceRequests") not in (None, [])
        or host.get("GroupAdd") not in (None, [])
        or host.get("NetworkMode") not in expected_network_modes
        or host.get("PidMode") not in ("", "private")
        or host.get("IpcMode") not in ("", "private")
        or host.get("UTSMode") not in ("", "private")
        or host.get("UsernsMode") not in ("", None)
    ):
        _invalid()
    live_mounts = _live_mounts(document)
    if resolved is not None and live_mounts != _expected_live_mounts(
        resolved, coordinates, service
    ):
        _invalid()
    security_sha256 = _security_projection_sha256(document)
    if (
        expected_security_sha256 is not None
        and security_sha256 != expected_security_sha256
    ):
        _invalid()
    attached = network_settings.get("Networks")
    expected_networks = {
        f"{coordinates.project_name}_{name}" for name in SERVICE_NETWORKS[service]
    }
    if not isinstance(attached, dict) or set(attached) != expected_networks:
        _invalid()
    status_value = state.get("Status")
    if not strict_state:
        if status_value in {"exited", "dead"}:
            return "STOPPED"
        if status_value in {"created", "running", "restarting", "paused", "removing"}:
            return "RUNNING"
        _invalid()
    if service in ONE_SHOT_SERVICES:
        if (
            status_value != "exited"
            or state.get("ExitCode") != 0
        ):
            _invalid()
        return "ONE_SHOT_GREEN"
    if status_value == "running":
        health = state.get("Health")
        if not isinstance(health, dict) or health.get("Status") != "healthy":
            _invalid()
        return "RUNNING"
    if (
        status_value == "exited"
        and state.get("ExitCode") in EXPECTED_STOP_EXIT_CODES[service]
    ):
        return "STOPPED"
    _invalid()


def _validate_one_shot_log(service: str, value: str) -> dict[str, Any]:
    lines = value.splitlines()
    if len(lines) != 1 or not lines[0] or lines[0] != lines[0].strip():
        _invalid()
    document = _parse_json(lines[0])
    if not isinstance(document, dict):
        _invalid()
    if service == "migrate":
        if (
            set(document) != {"catalogs", "preflights", "status"}
            or document.get("status") != "SCHEMA_READY"
        ):
            _invalid()
        catalogs = document.get("catalogs")
        if not isinstance(catalogs, dict) or set(catalogs) != CATALOGS:
            _invalid()
        for report in catalogs.values():
            if not isinstance(report, dict) or set(report) != {
                "applied_versions",
                "skipped_versions",
            }:
                _invalid()
            applied = report["applied_versions"]
            skipped = report["skipped_versions"]
            if (
                not isinstance(applied, list)
                or not applied
                or any(type(item) is not int or item < 0 for item in applied)
                or applied != sorted(set(applied))
                or skipped != []
            ):
                _invalid()
        preflights = document.get("preflights")
        if (
            not isinstance(preflights, dict)
            or set(preflights) != {"iam42_organization_public_name"}
        ):
            _invalid()
        public_name = preflights["iam42_organization_public_name"]
        count_fields = (
            "edge_whitespace_count",
            "forbidden_codepoint_count",
            "inspected_organization_count",
            "invalid_organization_count",
            "length_violation_count",
            "non_nfc_count",
        )
        if (
            not isinstance(public_name, dict)
            or set(public_name)
            != {
                *count_fields,
                "predicate_version",
                "relation_state",
                "status",
            }
            or public_name.get("predicate_version")
            != "iam42-organization-public-name-v1"
            or public_name.get("relation_state") not in {"ABSENT", "PRESENT"}
            or public_name.get("status") != "PASSED"
            or any(
                type(public_name.get(field)) is not int
                or public_name[field] < 0
                for field in count_fields
            )
            or public_name.get("invalid_organization_count") != 0
            or any(public_name[field] != 0 for field in count_fields[:2])
            or any(public_name[field] != 0 for field in count_fields[4:])
            or (
                public_name.get("relation_state") == "ABSENT"
                and public_name.get("inspected_organization_count") != 0
            )
        ):
            _invalid()
    elif service == "taxonomy-seed":
        if (
            set(document)
            != {"manifest_sha256", "replayed", "status", "taxonomy_bundle_id"}
            or document.get("status") != "INTERNAL_SANDBOX_TAXONOMY_SEED_READY"
            or document.get("replayed") is not False
            or _SHA256.fullmatch(str(document.get("manifest_sha256"))) is None
            or _UUID.fullmatch(str(document.get("taxonomy_bundle_id"))) is None
        ):
            _invalid()
    elif service in {"online-credentials-reconcile", "online-credentials-verify"}:
        expected = "RECONCILE" if service.endswith("reconcile") else "VERIFY"
        if (
            set(document) != {"action", "online_role_count", "status"}
            or document.get("action") != expected
            or type(document.get("online_role_count")) is not int
            or document["online_role_count"] <= 0
            or document.get("status") != "ONLINE_CREDENTIALS_READY"
        ):
            _invalid()
    elif service == "identity-bootstrap":
        if (
            set(document)
            != {"apply_outcome", "manifest_sha256", "status", "verify_outcome"}
            or document.get("apply_outcome") != "APPLIED"
            or document.get("verify_outcome") != "VERIFIED"
            or document.get("status") != "IDENTITY_BOOTSTRAP_ORCHESTRATION_READY"
            or _SHA256.fullmatch(str(document.get("manifest_sha256"))) is None
        ):
            _invalid()
    else:
        _invalid()
    return document


def _one_shot_logs(
    runtime: DockerRuntime, coordinates: Coordinates, *, runner: Runner
) -> dict[str, str]:
    digests: dict[str, str] = {}
    for service in ONE_SHOT_SERVICES:
        output = _compose(
            runtime,
            coordinates,
            "logs",
            "--no-color",
            "--no-log-prefix",
            service,
            runner=runner,
        ).stdout
        _validate_one_shot_log(service, output)
        digests[service] = hashlib.sha256(output.encode("utf-8")).hexdigest()
    return digests


def _curl_executable() -> tuple[str, Mapping[str, str]]:
    environment = _base_environment()
    executable = shutil.which("curl", path=environment["PATH"])
    if not executable or not Path(executable).is_absolute():
        _invalid()
    try:
        resolved = Path(executable).resolve(strict=True)
        metadata = resolved.stat()
    except OSError:
        _invalid()
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        _invalid()
    return str(resolved), environment


def _https_get(
    coordinates: Coordinates,
    *,
    hostname: str,
    path: str,
    accept: str,
    query: str | None = None,
    runner: Runner,
) -> str:
    if (
        hostname
        not in {
            f"identity.{coordinates.domain}",
            f"pilot.{coordinates.domain}",
        }
        or not path.startswith("/")
        or "//" in path
        or any(character in path for character in ("?", "#", "\\"))
        or (
            query is not None
            and (
                not query
                or len(query) > 4096
                or any(character in query for character in ("?", "#", "\\"))
                or not query.isascii()
            )
        )
        or accept not in {"application/json", "text/html"}
    ):
        _invalid()
    executable, environment = _curl_executable()
    return _execute(
        (
            executable,
            "--silent",
            "--show-error",
            "--fail",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--connect-timeout",
            "3",
            "--max-time",
            "10",
            "--noproxy",
            "*",
            "--cacert",
            str(coordinates.tls / "root-ca.pem"),
            "--resolve",
            f"{hostname}:443:127.0.0.1",
            "--header",
            f"Accept: {accept}",
            f"https://{hostname}{path}" + ("?" + query if query is not None else ""),
        ),
        environment=environment,
        timeout=15,
        runner=runner,
    ).stdout


def _authorization_readiness(
    coordinates: Coordinates, *, runner: Runner
) -> None:
    hostname = f"identity.{coordinates.domain}"
    callback = f"https://pilot.{coordinates.domain}/v1/auth/oidc/callback"
    state = "s" * 43
    nonce = "n" * 43
    verifier = "v" * 43
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    query = urlencode(
        (
            ("client_id", SYNTHETIC_CLIENT_ID),
            ("redirect_uri", callback),
            ("response_type", "code"),
            ("scope", "openid email"),
            ("state", state),
            ("nonce", nonce),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
        )
    )
    chooser = _https_get(
        coordinates,
        hostname=hostname,
        path="/authorize",
        accept="text/html",
        query=query,
        runner=runner,
    )
    handles = re.findall(
        r'<input type="hidden" name="request_handle" value="([A-Za-z0-9_-]{43})">',
        chooser,
    )
    account_codes = re.findall(
        r'<button type="submit" name="account_code" value="([a-z0-9_]+)">',
        chooser,
    )
    if (
        handles == []
        or len(handles) != 1
        or tuple(account_codes) != SYNTHETIC_CHOOSER_ACCOUNT_CODES
    ):
        _invalid()
    handle = handles[0]

    executable, environment = _curl_executable()
    common = (
        executable,
        "--silent",
        "--show-error",
        "--fail",
        "--proto",
        "=https",
        "--tlsv1.2",
        "--connect-timeout",
        "3",
        "--max-time",
        "10",
        "--noproxy",
        "*",
        "--cacert",
        str(coordinates.tls / "root-ca.pem"),
        "--resolve",
        f"{hostname}:443:127.0.0.1",
    )
    redirect = _execute(
        (
            *common,
            "--request",
            "POST",
            "--data-urlencode",
            f"request_handle={handle}",
            "--data-urlencode",
            "account_code=creator_01",
            "--output",
            "/dev/null",
            "--write-out",
            "%{redirect_url}",
            f"https://{hostname}/authorize",
        ),
        environment=environment,
        timeout=15,
        runner=runner,
    ).stdout
    parsed = urlsplit(redirect)
    try:
        redirect_query = parse_qs(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=True,
        )
    except ValueError:
        _invalid()
    if (
        parsed.scheme != "https"
        or parsed.netloc != f"pilot.{coordinates.domain}"
        or parsed.path != "/v1/auth/oidc/callback"
        or parsed.fragment
        or set(redirect_query) != {"code", "state"}
        or redirect_query.get("state") != [state]
        or len(redirect_query.get("code", [])) != 1
        or re.fullmatch(r"[A-Za-z0-9_-]{43}", redirect_query["code"][0]) is None
    ):
        _invalid()
    code = redirect_query["code"][0]
    token = _parse_json(
        _execute(
            (
                *common,
                "--header",
                "Accept: application/json",
                "--request",
                "POST",
                "--data-urlencode",
                "grant_type=authorization_code",
                "--data-urlencode",
                f"code={code}",
                "--data-urlencode",
                f"redirect_uri={callback}",
                "--data-urlencode",
                f"client_id={SYNTHETIC_CLIENT_ID}",
                "--data-urlencode",
                (
                    "client_secret@"
                    + str(
                        coordinates.bundle
                        / "runtime-secrets/key-oidc-client-secret-v1"
                    )
                ),
                "--data-urlencode",
                f"code_verifier={verifier}",
                f"https://{hostname}/token",
            ),
            environment=environment,
            timeout=15,
            runner=runner,
        ).stdout
    )
    if (
        not isinstance(token, dict)
        or set(token) != {"access_token", "expires_in", "id_token", "token_type"}
        or re.fullmatch(r"[A-Za-z0-9_-]{43}", str(token.get("access_token"))) is None
        or token.get("expires_in") != 300
        or token.get("token_type") != "Bearer"
        or not isinstance(token.get("id_token"), str)
        or len(token["id_token"].split(".")) != 3
        or any(
            _BASE64URL.fullmatch(part) is None
            for part in token["id_token"].split(".")
        )
    ):
        _invalid()


def _browser_auth_readiness(
    runtime: DockerRuntime,
    coordinates: Coordinates,
    *,
    api_container_id: str,
    exercise_authorization: bool,
    runner: Runner,
) -> None:
    api_health = _parse_json(
        _docker(
            runtime,
            (
                "container",
                "exec",
                api_container_id,
                "python",
                "-c",
                (
                    "import urllib.request;print(urllib.request.urlopen("
                    "'http://127.0.0.1:8000/health/ready',timeout=2)"
                    ".read().decode())"
                ),
            ),
            runner=runner,
            timeout=10,
        ).stdout
    )
    if api_health != {
        "deployment_mode": "INTERNAL_SANDBOX",
        "external_participants": "DISABLED",
        "g1": "NO-GO",
        "g2": "NO-GO",
        "status": "READY",
    }:
        _invalid()

    identity_hostname = f"identity.{coordinates.domain}"
    issuer = f"https://{identity_hostname}"
    discovery = _parse_json(
        _https_get(
            coordinates,
            hostname=identity_hostname,
            path="/.well-known/openid-configuration",
            accept="application/json",
            runner=runner,
        )
    )
    if discovery != {
        "authorization_endpoint": issuer + "/authorize",
        "code_challenge_methods_supported": ["S256"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "issuer": issuer,
        "jwks_uri": issuer + "/jwks",
        "response_types_supported": ["code"],
        "scopes_supported": ["openid", "email"],
        "subject_types_supported": ["public"],
        "token_endpoint": issuer + "/token",
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
    }:
        _invalid()
    jwks = _parse_json(
        _https_get(
            coordinates,
            hostname=identity_hostname,
            path="/jwks",
            accept="application/json",
            runner=runner,
        )
    )
    keys = jwks.get("keys") if isinstance(jwks, dict) and set(jwks) == {"keys"} else None
    if not isinstance(keys, list) or len(keys) != 1 or not isinstance(keys[0], dict):
        _invalid()
    key = keys[0]
    if (
        set(key) != {"alg", "e", "kid", "kty", "n", "use"}
        or key.get("alg") != "RS256"
        or key.get("e") != "AQAB"
        or key.get("kid") != SYNTHETIC_SIGNING_KEY_ID
        or key.get("kty") != "RSA"
        or key.get("use") != "sig"
        or _BASE64URL.fullmatch(str(key.get("n"))) is None
        or not 300 <= len(key["n"]) <= 512
    ):
        _invalid()
    if exercise_authorization:
        _authorization_readiness(coordinates, runner=runner)
    homepage = _https_get(
        coordinates,
        hostname=f"pilot.{coordinates.domain}",
        path="/",
        accept="text/html",
        runner=runner,
    )
    if (
        "<!DOCTYPE html" not in homepage
        or "<html" not in homepage
        or "</html>" not in homepage
        or "愿作" not in homepage
    ):
        _invalid()


def _network_receipt(
    runtime: DockerRuntime, coordinates: Coordinates, *, runner: Runner
) -> dict[str, str]:
    result: dict[str, str] = {}
    expected_cidrs = dict(
        zip(
            NETWORKS,
            (
                coordinates.ingress_cidr,
                coordinates.oidc_cidr,
                coordinates.app_cidr,
                coordinates.data_cidr,
            ),
        )
    )
    for name in NETWORKS:
        docker_name = f"{coordinates.project_name}_{name}"
        documents = _parse_json(
            _docker(runtime, ("network", "inspect", docker_name), runner=runner).stdout
        )
        if not isinstance(documents, list) or len(documents) != 1:
            _invalid()
        document = documents[0]
        labels = document.get("Labels") if isinstance(document, dict) else None
        identifier = document.get("Id") if isinstance(document, dict) else None
        ipam = document.get("IPAM") if isinstance(document, dict) else None
        if (
            not isinstance(labels, dict)
            or labels.get("com.docker.compose.project") != coordinates.project_name
            or labels.get("com.docker.compose.network") != name
            or not isinstance(identifier, str)
            or _RESOURCE_ID.fullmatch(identifier) is None
            or not isinstance(ipam, dict)
        ):
            _invalid()
        configurations = ipam.get("Config")
        if (
            not isinstance(configurations, list)
            or len(configurations) != 1
            or not isinstance(configurations[0], dict)
            or configurations[0].get("Subnet") != expected_cidrs[name]
        ):
            _invalid()
        result[name] = identifier
    return result


def _volume_receipt(
    runtime: DockerRuntime, coordinates: Coordinates, *, runner: Runner
) -> dict[str, Any]:
    name = f"{coordinates.project_name}_postgres-data"
    documents = _parse_json(
        _docker(runtime, ("volume", "inspect", name), runner=runner).stdout
    )
    if not isinstance(documents, list) or len(documents) != 1:
        _invalid()
    document = documents[0]
    labels = document.get("Labels") if isinstance(document, dict) else None
    created = document.get("CreatedAt") if isinstance(document, dict) else None
    if (
        not isinstance(document, dict)
        or document.get("Name") != name
        or document.get("Driver") != "local"
        or document.get("Scope") != "local"
        or document.get("Options") not in (None, {})
        or not isinstance(labels, dict)
        or labels.get("com.docker.compose.project") != coordinates.project_name
        or labels.get("com.docker.compose.volume") != "postgres-data"
        or not isinstance(created, str)
        or not created
    ):
        _invalid()
    return {
        "created_at": created,
        "driver": "local",
        "name": name,
        "options": {},
        "scope": "local",
    }


def _capture_started(
    runtime: DockerRuntime,
    coordinates: Coordinates,
    *,
    prepared_receipt_sha256: str,
    image_ids: Mapping[str, str],
    resolved: Mapping[str, Any],
    runner: Runner,
) -> dict[str, Any]:
    container_ids = {
        service: _service_id(runtime, coordinates, service, runner=runner)
        for service in SERVICES
    }
    if len(set(container_ids.values())) != len(SERVICES):
        _invalid()
    documents = _inspect_containers(
        runtime, tuple(container_ids.values()), runner=runner
    )
    service_image_ids: dict[str, str] = {}
    security_sha256: dict[str, str] = {}
    for service, identifier in container_ids.items():
        image_id = documents[identifier].get("Image")
        if not isinstance(image_id, str) or _IMAGE_ID.fullmatch(image_id) is None:
            _invalid()
        expected = image_ids.get(service)
        if expected is not None and image_id != expected:
            _invalid()
        service_image_ids[service] = image_id
        state = _validate_container(
            documents[identifier],
            coordinates=coordinates,
            service=service,
            image_id=image_id,
            resolved=resolved,
        )
        if service in PERSISTENT_SERVICES and state != "RUNNING":
            _invalid()
        security_sha256[service] = _security_projection_sha256(documents[identifier])
    logs = _one_shot_logs(runtime, coordinates, runner=runner)
    networks = _network_receipt(runtime, coordinates, runner=runner)
    volume = _volume_receipt(runtime, coordinates, runner=runner)
    inventory = _project_inventory(runtime, coordinates, runner=runner)
    if (
        inventory["containers"] != frozenset(container_ids.values())
        or inventory["networks"] != frozenset(networks.values())
        or inventory["volumes"] != frozenset((volume["name"],))
    ):
        _invalid()
    _browser_auth_readiness(
        runtime,
        coordinates,
        api_container_id=container_ids["api"],
        exercise_authorization=True,
        runner=runner,
    )
    return {
        "container_ids": container_ids,
        "coordinates": coordinates.as_dict(),
        "image_ids": service_image_ids,
        "network_ids": networks,
        "one_shot_log_sha256": logs,
        "prepared_receipt_sha256": prepared_receipt_sha256,
        "schema": RECEIPT_SCHEMA,
        "security_sha256": security_sha256,
        "status": "STARTED",
        "volume": volume,
    }


def _load_start_receipt(
    coordinates: Coordinates, *, prepared_receipt_sha256: str
) -> dict[str, Any]:
    _load_start_attempt(
        coordinates, prepared_receipt_sha256=prepared_receipt_sha256
    )
    document, _sha = _closed_json(coordinates.metadata / START_RECEIPT)
    expected_keys = {
        "container_ids",
        "coordinates",
        "image_ids",
        "network_ids",
        "one_shot_log_sha256",
        "prepared_receipt_sha256",
        "schema",
        "security_sha256",
        "status",
        "volume",
    }
    if (
        set(document) != expected_keys
        or document.get("schema") != RECEIPT_SCHEMA
        or document.get("status") != "STARTED"
        or document.get("coordinates") != coordinates.as_dict()
        or document.get("prepared_receipt_sha256") != prepared_receipt_sha256
        or not isinstance(document.get("container_ids"), dict)
        or set(document["container_ids"]) != set(SERVICES)
        or len(set(document["container_ids"].values())) != len(SERVICES)
        or any(
            _RESOURCE_ID.fullmatch(str(value)) is None
            for value in document["container_ids"].values()
        )
        or not isinstance(document.get("image_ids"), dict)
        or set(document["image_ids"]) != set(SERVICES)
        or any(_IMAGE_ID.fullmatch(str(value)) is None for value in document["image_ids"].values())
        or not isinstance(document.get("security_sha256"), dict)
        or set(document["security_sha256"]) != set(SERVICES)
        or any(
            _SHA256.fullmatch(str(value)) is None
            for value in document["security_sha256"].values()
        )
        or not isinstance(document.get("network_ids"), dict)
        or set(document["network_ids"]) != set(NETWORKS)
        or any(
            _RESOURCE_ID.fullmatch(str(value)) is None
            for value in document["network_ids"].values()
        )
        or not isinstance(document.get("one_shot_log_sha256"), dict)
        or set(document["one_shot_log_sha256"]) != set(ONE_SHOT_SERVICES)
        or any(
            _SHA256.fullmatch(str(value)) is None
            for value in document["one_shot_log_sha256"].values()
        )
        or not isinstance(document.get("volume"), dict)
        or set(document["volume"])
        != {"created_at", "driver", "name", "options", "scope"}
        or document["volume"].get("driver") != "local"
        or document["volume"].get("scope") != "local"
        or document["volume"].get("options") != {}
    ):
        _invalid()
    return document


def _load_start_attempt(
    coordinates: Coordinates, *, prepared_receipt_sha256: str
) -> dict[str, Any]:
    document, _sha = _closed_json(coordinates.metadata / START_ATTEMPT)
    if (
        set(document)
        != {
            "coordinates",
            "prepared_receipt_sha256",
            "schema",
            "status",
        }
        or document.get("schema") != RECEIPT_SCHEMA
        or document.get("status") != "STARTING"
        or document.get("coordinates") != coordinates.as_dict()
        or document.get("prepared_receipt_sha256")
        != prepared_receipt_sha256
    ):
        _invalid()
    return document


def _live_state(
    runtime: DockerRuntime,
    coordinates: Coordinates,
    receipt: Mapping[str, Any],
    *,
    runner: Runner,
) -> tuple[str, dict[str, str]]:
    container_ids = receipt["container_ids"]
    image_ids = receipt["image_ids"]
    security_sha256 = receipt["security_sha256"]
    if (
        not isinstance(container_ids, dict)
        or not isinstance(image_ids, dict)
        or not isinstance(security_sha256, dict)
    ):
        _invalid()
    current_ids = {
        service: _service_id(runtime, coordinates, service, runner=runner)
        for service in SERVICES
    }
    if current_ids != container_ids:
        _invalid()
    documents = _inspect_containers(
        runtime, tuple(container_ids.values()), runner=runner
    )
    states: dict[str, str] = {}
    for service, identifier in container_ids.items():
        states[service] = _validate_container(
            documents[identifier],
            coordinates=coordinates,
            service=service,
            image_id=image_ids[service],
            expected_security_sha256=security_sha256[service],
        )
    if _one_shot_logs(runtime, coordinates, runner=runner) != receipt["one_shot_log_sha256"]:
        _invalid()
    _validate_application_image_tags(
        runtime,
        coordinates,
        image_ids,
        runner=runner,
    )
    if _network_receipt(runtime, coordinates, runner=runner) != receipt["network_ids"]:
        _invalid()
    if _volume_receipt(runtime, coordinates, runner=runner) != receipt["volume"]:
        _invalid()
    inventory = _project_inventory(runtime, coordinates, runner=runner)
    if (
        inventory["containers"] != frozenset(container_ids.values())
        or inventory["networks"] != frozenset(receipt["network_ids"].values())
        or inventory["volumes"] != frozenset((receipt["volume"]["name"],))
    ):
        _invalid()
    persistent = [states[name] for name in PERSISTENT_SERVICES]
    if all(value == "RUNNING" for value in persistent):
        overall = "HEALTHY"
    elif all(value == "STOPPED" for value in persistent):
        overall = "STOPPED"
    else:
        overall = "RECOVERABLE"
    if overall == "HEALTHY":
        _browser_auth_readiness(
            runtime,
            coordinates,
            api_container_id=container_ids["api"],
            exercise_authorization=False,
            runner=runner,
        )
    return overall, states


def _containment_state(
    runtime: DockerRuntime,
    coordinates: Coordinates,
    receipt: Mapping[str, Any],
    *,
    runner: Runner,
) -> tuple[str, dict[str, str]]:
    """Validate immutable identity/security while tolerating broken readiness."""

    container_ids = receipt.get("container_ids")
    image_ids = receipt.get("image_ids")
    security_sha256 = receipt.get("security_sha256")
    if not all(isinstance(item, dict) for item in (container_ids, image_ids, security_sha256)):
        _invalid()
    identifiers = tuple(container_ids[service] for service in PERSISTENT_SERVICES)
    documents = _inspect_containers(runtime, identifiers, runner=runner)
    states: dict[str, str] = {}
    for service in PERSISTENT_SERVICES:
        identifier = container_ids[service]
        states[service] = _validate_container(
            documents[identifier],
            coordinates=coordinates,
            service=service,
            image_id=image_ids[service],
            expected_security_sha256=security_sha256[service],
            strict_state=False,
        )
    values = tuple(states.values())
    if all(value == "STOPPED" for value in values):
        return "STOPPED", states
    if all(value == "RUNNING" for value in values):
        return "ACTIVE", states
    return "MIXED", states


def prepare(
    coordinates: Coordinates,
    *,
    platform_python: str,
    runner: Runner,
) -> str:
    compose_sha = _repository_sha256()
    source_binding = _source_binding(runner=runner)
    runtime = _docker_runtime(runner=runner)
    _project_unused(runtime, coordinates, runner=runner)
    _image_tags_unused(runtime, coordinates, runner=runner)
    _cidrs_unused(runtime, coordinates, runner=runner)
    _port_unused()
    _create_private_directory(coordinates.root)
    _create_private_directory(coordinates.metadata)
    _write_new_json(
        coordinates.metadata / PREPARE_ATTEMPT,
        {
            "coordinates": coordinates.as_dict(),
            "schema": RECEIPT_SCHEMA,
            "status": "PREPARING",
        },
    )
    _prepare_helpers(
        coordinates,
        platform_python=platform_python,
        runner=runner,
    )
    _validate_generated_bundle(coordinates)
    _verify_helpers(coordinates, runner=runner)
    input_sha = _input_tree_sha256(coordinates)
    if source_binding != _source_binding(runner=runner):
        _invalid()
    _write_new_json(
        coordinates.metadata / PREPARED_RECEIPT,
        _prepared_document(
            coordinates,
            input_sha256=input_sha,
            compose_sha256=compose_sha,
            source_binding=source_binding,
        ),
    )
    return "LOCAL_INTERNAL_SANDBOX_PREPARED"


def start(
    coordinates: Coordinates,
    *,
    wait_timeout: int,
    runner: Runner,
) -> str:
    prepared, prepared_sha = _load_prepared(coordinates, runner=runner)
    for path in (
        coordinates.metadata / START_ATTEMPT,
        coordinates.metadata / START_RECEIPT,
    ):
        if path.exists() or path.is_symlink():
            _invalid()
    runtime = _docker_runtime(runner=runner)
    _project_unused(runtime, coordinates, runner=runner)
    _image_tags_unused(runtime, coordinates, runner=runner)
    _cidrs_unused(runtime, coordinates, runner=runner)
    _port_unused()
    _resolved_config(runtime, coordinates, runner=runner)
    _write_new_json(
        coordinates.metadata / START_ATTEMPT,
        {
            "coordinates": coordinates.as_dict(),
            "prepared_receipt_sha256": prepared_sha,
            "schema": RECEIPT_SCHEMA,
            "status": "STARTING",
        },
    )
    try:
        _compose(
            runtime,
            coordinates,
            "build",
            "api",
            "web",
            "edge",
            runner=runner,
            timeout=max(wait_timeout, 600),
        )
        image_ids = _expected_service_image_ids(
            _application_image_ids(runtime, coordinates, runner=runner)
        )
        if prepared["source_binding"] != _source_binding(runner=runner):
            _invalid()
        resolved = _resolved_config(runtime, coordinates, runner=runner)
        _compose(
            runtime,
            coordinates,
            "up",
            "--no-build",
            "--pull",
            "never",
            "-d",
            "--wait",
            "--wait-timeout",
            str(wait_timeout),
            runner=runner,
            timeout=wait_timeout + 60,
        )
        receipt = _capture_started(
            runtime,
            coordinates,
            prepared_receipt_sha256=prepared_sha,
            image_ids=image_ids,
            resolved=resolved,
            runner=runner,
        )
        _write_new_json(coordinates.metadata / START_RECEIPT, receipt)
    except LocalInternalSandboxError:
        _partial()
    except BaseException:
        _partial()
    return "LOCAL_INTERNAL_SANDBOX_STARTED"


def status(
    coordinates: Coordinates,
    *,
    runner: Runner,
) -> str:
    prepared_path = coordinates.metadata / PREPARED_RECEIPT
    if not prepared_path.exists():
        attempt, _sha = _closed_json(coordinates.metadata / PREPARE_ATTEMPT)
        _validate_coordinate_receipt(attempt, coordinates, status="PREPARING")
        return "PREPARATION_INCOMPLETE"
    _prepared, prepared_sha = _load_prepared(coordinates, runner=runner)
    runtime = _docker_runtime(runner=runner)
    started_path = coordinates.metadata / START_RECEIPT
    attempt_path = coordinates.metadata / START_ATTEMPT
    if not started_path.exists():
        inventory = _project_inventory(runtime, coordinates, runner=runner)
        if attempt_path.exists() or attempt_path.is_symlink():
            _load_start_attempt(
                coordinates, prepared_receipt_sha256=prepared_sha
            )
            return "START_INCOMPLETE"
        if any(inventory.values()):
            return "START_INCOMPLETE"
        return "PREPARED"
    receipt = _load_start_receipt(
        coordinates, prepared_receipt_sha256=prepared_sha
    )
    state, _states = _live_state(
        runtime, coordinates, receipt, runner=runner
    )
    return state


def _wait_healthy(
    runtime: DockerRuntime,
    coordinates: Coordinates,
    *,
    service: str,
    identifier: str,
    image_id: str,
    security_sha256: str,
    wait_timeout: int,
    runner: Runner,
) -> None:
    deadline = time.monotonic() + wait_timeout
    while True:
        document = _inspect_containers(runtime, (identifier,), runner=runner)[identifier]
        state = _validate_container(
            document,
            coordinates=coordinates,
            service=service,
            image_id=image_id,
            expected_security_sha256=security_sha256,
            strict_state=False,
        )
        status_value = document.get("State", {}).get("Status")
        health = document.get("State", {}).get("Health", {}).get("Status")
        if state != "RUNNING" or status_value != "running" or health not in {
            "starting",
            "healthy",
        }:
            _partial()
        if health == "healthy":
            return
        if time.monotonic() >= deadline:
            _partial()
        time.sleep(0.5)


def resume(
    coordinates: Coordinates,
    *,
    wait_timeout: int,
    runner: Runner,
) -> str:
    _prepared, prepared_sha = _load_prepared(coordinates, runner=runner)
    receipt = _load_start_receipt(
        coordinates, prepared_receipt_sha256=prepared_sha
    )
    runtime = _docker_runtime(runner=runner)
    live, states = _live_state(runtime, coordinates, receipt, runner=runner)
    if live == "HEALTHY":
        return "LOCAL_INTERNAL_SANDBOX_RESUMED"
    if live not in {"STOPPED", "RECOVERABLE"}:
        _invalid()
    changed = False
    try:
        for service in PERSISTENT_SERVICES:
            if states[service] == "RUNNING":
                continue
            if service == "edge":
                _port_unused()
            identifier = receipt["container_ids"][service]
            changed = True
            _docker(
                runtime,
                ("container", "start", identifier),
                runner=runner,
                timeout=60,
            )
            _wait_healthy(
                runtime,
                coordinates,
                service=service,
                identifier=identifier,
                image_id=receipt["image_ids"][service],
                security_sha256=receipt["security_sha256"][service],
                wait_timeout=wait_timeout,
                runner=runner,
            )
        final, _states = _live_state(
            runtime, coordinates, receipt, runner=runner
        )
        if final != "HEALTHY":
            _partial()
    except LocalInternalSandboxError as error:
        if changed or error.exit_code == 75:
            _partial()
        raise
    except BaseException:
        if changed:
            _partial()
        _invalid()
    return "LOCAL_INTERNAL_SANDBOX_RESUMED"


def stop(
    coordinates: Coordinates,
    *,
    runner: Runner,
) -> str:
    _prepared, prepared_sha = _load_prepared(
        coordinates, runner=runner, verify_current=False
    )
    receipt = _load_start_receipt(
        coordinates, prepared_receipt_sha256=prepared_sha
    )
    runtime = _docker_runtime(runner=runner)
    live, states = _containment_state(runtime, coordinates, receipt, runner=runner)
    if live == "STOPPED":
        return "LOCAL_INTERNAL_SANDBOX_STOPPED"
    if live not in {"ACTIVE", "MIXED"}:
        _invalid()
    changed = False
    try:
        for service in STOP_ORDER:
            if states[service] == "STOPPED":
                continue
            identifier = receipt["container_ids"][service]
            timeout = (
                "60"
                if service == "db"
                else "30"
                if service == "matching-runtime"
                else "20"
                if service == "api"
                else "10"
            )
            changed = True
            _docker(
                runtime,
                ("container", "stop", "--time", timeout, identifier),
                runner=runner,
                timeout=int(timeout) + 30,
            )
        final, _states = _containment_state(
            runtime, coordinates, receipt, runner=runner
        )
        if final != "STOPPED":
            _partial()
    except LocalInternalSandboxError as error:
        if changed or error.exit_code == 75:
            _partial()
        raise
    except BaseException:
        if changed:
            _partial()
        _invalid()
    return "LOCAL_INTERNAL_SANDBOX_STOPPED"


def _add_coordinates(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--root", required=True)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--image-tag", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--ingress-cidr", required=True)
    parser.add_argument("--oidc-cidr", required=True)
    parser.add_argument("--app-cidr", required=True)
    parser.add_argument("--data-cidr", required=True)


def _positive_timeout(value: str) -> int:
    try:
        parsed = int(value, 10)
    except (TypeError, ValueError):
        _invalid()
    if not 10 <= parsed <= 600:
        _invalid()
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = _ClosedArgumentParser(
        prog="python3 -B scripts/manage_local_internal_sandbox.py"
    )
    subcommands = parser.add_subparsers(
        dest="command", required=True, parser_class=_ClosedArgumentParser
    )
    prepare_parser = subcommands.add_parser("prepare")
    status_parser = subcommands.add_parser("status")
    start_parser = subcommands.add_parser("start")
    resume_parser = subcommands.add_parser("resume")
    stop_parser = subcommands.add_parser("stop")
    for subparser in (
        prepare_parser,
        status_parser,
        start_parser,
        resume_parser,
        stop_parser,
    ):
        _add_coordinates(subparser)
    prepare_parser.add_argument("--platform-python")
    start_parser.add_argument(
        "--wait-timeout", type=_positive_timeout, default=180
    )
    resume_parser.add_argument(
        "--wait-timeout", type=_positive_timeout, default=180
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    runner: Runner = subprocess.run,
) -> int:
    try:
        arguments = _parser().parse_args(argv)
        coordinates = _coordinates(
            arguments, must_exist=arguments.command != "prepare"
        )
        if arguments.command == "prepare":
            result = prepare(
                coordinates,
                platform_python=_platform_python(arguments.platform_python),
                runner=runner,
            )
            payload = {"status": result}
        elif arguments.command == "start":
            result = start(
                coordinates,
                wait_timeout=arguments.wait_timeout,
                runner=runner,
            )
            payload = {"status": result}
        elif arguments.command == "resume":
            result = resume(
                coordinates,
                wait_timeout=arguments.wait_timeout,
                runner=runner,
            )
            payload = {"status": result}
        elif arguments.command == "stop":
            payload = {"status": stop(coordinates, runner=runner)}
        else:
            payload = {
                "project_state": status(coordinates, runner=runner),
                "status": "LOCAL_INTERNAL_SANDBOX_STATUS",
            }
        stdout.write(
            json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n"
        )
        return 0
    except LocalInternalSandboxError as error:
        stderr.write(
            json.dumps(
                {"code": error.code, "status": "BLOCKED"},
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        )
        return error.exit_code
    except Exception:
        stderr.write(
            '{"code":"LOCAL_INTERNAL_SANDBOX_INVALID","status":"BLOCKED"}\n'
        )
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
