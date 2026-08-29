#!/usr/bin/env python3
"""Fail-closed, fresh-only activation of the private INTERNAL_SANDBOX ingress."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from types import MappingProxyType
from types import ModuleType
from typing import Callable, Mapping, NoReturn, Optional, Sequence, TextIO


_ROOT = Path(__file__).resolve().parents[1]
_BASE_COMPOSE = _ROOT / "compose.yaml"
_PRIVATE_OVERLAY = _ROOT / "deploy" / "private-server.compose.yaml"
_IDENTITY_TEMPLATE = (
    _ROOT
    / "platform"
    / "examples"
    / "internal-sandbox-identity-bootstrap-template-v1.json"
)
_RELEASE_INPUT_HELPER = _ROOT / "scripts" / "private_server_release_inputs.py"
_COMPOSE_CONTRACT_HELPER = (
    _ROOT / "scripts" / "private_server_compose_contract.py"
)
_ATTEMPTS_ROOT = Path("/var/lib/desire/private-ingress-attempts")
_DOCKER_EXECUTABLE = "/usr/bin/docker"
_IP_EXECUTABLE = "/usr/sbin/ip"
_SS_EXECUTABLE = "/usr/bin/ss"
_DOCKER_ENDPOINT = "unix:///var/run/docker.sock"
_TRUSTED_PATH = "/usr/sbin:/usr/bin"
_TRUSTED_LOCALE = "C.UTF-8"
_PREFLIGHT_PATH = Path(__file__).resolve().with_name(
    "preflight_private_server_ingress.py"
)

READY = '{"status":"PRIVATE_SERVER_INGRESS_ACTIVATED"}\n'
BLOCKED = (
    '{"code":"PRIVATE_SERVER_INGRESS_ACTIVATION_INVALID",'
    '"status":"BLOCKED"}\n'
)
PARTIAL = (
    '{"code":"PRIVATE_SERVER_INGRESS_PARTIAL_POSSIBLE",'
    '"status":"BLOCKED"}\n'
)
_COMPOSE_VERSION = "5.3.1\n"
_MAX_OUTPUT = 1024 * 1024
_MAX_INPUT = 64 * 1024
_MAX_STATIC_INPUT = 1024 * 1024
_MAX_COMPOSE_PLUGIN = 256 * 1024 * 1024
_COMPOSE_PLUGIN_PATHS = (
    (
        "/usr/local/lib/docker/cli-plugins/docker-compose",
        "/usr/local/libexec/docker/cli-plugins/docker-compose",
        "/usr/lib/docker/cli-plugins/docker-compose",
        "/usr/libexec/docker/cli-plugins/docker-compose",
    )
)
_STATIC_SOURCE_DIGESTS = {
    _BASE_COMPOSE: "325919f3066d9d2eaa1dd943fac35fd55bde0e9005d178ee0c1211e04e224ddd",
    _PRIVATE_OVERLAY: (
        "7a13f5b635496e08b84cf9b19e53c3f494d44fd9d5dde07c807136a2eaeef282"
    ),
    _IDENTITY_TEMPLATE: (
        "b7f5326f75f17eb97cec77d92f963fe6af6755a26a1acf7af8944f33ee6ba942"
    ),
    _RELEASE_INPUT_HELPER: (
        "7cad99cca3b8e339de351d098d78a76858b77280d378db7edbac4dfbc7b18d63"
    ),
    _COMPOSE_CONTRACT_HELPER: (
        "1b19dec455d36a853a3cc1365e8d0110008414f2c73b2c2aae4348cb401c62d5"
    ),
    _PREFLIGHT_PATH: (
        "b3533fcd50766e714efc1dd5b3cba4159d7921593c3ee9478dafe302cc8f2b97"
    ),
}
_PROJECT = re.compile(
    r"^desire-private-ingress-(?:[a-z0-9]|[a-z0-9][a-z0-9-]{0,38}[a-z0-9])$"
)
_FROZEN_PROJECTS = frozenset(
    {
        "desire-supply-e2e-ten-account-v13",
        "desire-restore-verify-v13drill01",
    }
)
_SERVICES = frozenset(
    {
        "api",
        "db",
        "edge",
        "identity-bootstrap",
        "migrate",
        "matching-runtime",
        "online-credentials-reconcile",
        "online-credentials-verify",
        "synthetic-oidc",
        "taxonomy-seed",
        "web",
    }
)
_ADMIN_SERVICES = frozenset(
    {
        "identity-bootstrap",
        "migrate",
        "online-credentials-reconcile",
        "online-credentials-verify",
        "synthetic-oidc",
        "taxonomy-seed",
    }
)
_SERVICE_NETWORKS = {
    "db": frozenset({"data"}),
    "migrate": frozenset({"data"}),
    "taxonomy-seed": frozenset({"data"}),
    "online-credentials-reconcile": frozenset({"data"}),
    "online-credentials-verify": frozenset({"data"}),
    "identity-bootstrap": frozenset({"data"}),
    "synthetic-oidc": frozenset({"oidc-backend"}),
    "matching-runtime": frozenset({"data"}),
    "api": frozenset({"app", "data"}),
    "web": frozenset({"app"}),
    "edge": frozenset({"app", "oidc-backend", "ingress"}),
}
_INTERNAL_NETWORKS = frozenset({"app", "data", "oidc-backend"})
_ENV_KEYS = (
    "DESIRE_IMAGE_TAG",
    "DESIRE_DB_PASSWORD_FILE",
    "DESIRE_TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE",
    "DESIRE_TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE",
    "DESIRE_IDENTITY_SOURCE_DIR",
    "DESIRE_INTERNAL_SANDBOX_TLS_DIR",
    "DESIRE_INTERNAL_SANDBOX_BUNDLE_DIR",
)
_ENV_PATH_NAMES = (
    "db_superuser_password.txt",
    "taxonomy_seed_workload_credential",
    "taxonomy_seed_receipt_hmac_key",
    "internal-sandbox-identity-sources",
    "internal-sandbox-tls",
)
_SAFE_TOKEN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_SAFE_UNQUOTED_PATH = re.compile(r"^/[A-Za-z0-9._~+/-]+$")
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_RESOURCE_ID = re.compile(r"^[0-9a-f]{64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_POSTGRES_IMAGE_REF = (
    "postgres:18.4-alpine@sha256:"
    "9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15"
)
_IPAM_DOCUMENT = re.compile(
    rb"networks:\n"
    rb"  ingress:\n    ipam:\n      config:\n        - subnet: ([0-9./]+)\n"
    rb"  oidc-backend:\n    ipam:\n      config:\n        - subnet: ([0-9./]+)\n"
    rb"  app:\n    ipam:\n      config:\n        - subnet: ([0-9./]+)\n"
    rb"  data:\n    ipam:\n      config:\n        - subnet: ([0-9./]+)\n"
)
_RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_FROZEN_SUBNETS = frozenset(
    ipaddress.ip_network(value)
    for value in (
        "172.16.227.0/24",
        "172.16.228.0/24",
        "172.16.229.0/24",
        "172.16.231.0/24",
        "172.16.232.0/24",
    )
)
_FROZEN_BYTE_TOKENS = tuple(
    value.encode("ascii")
    for value in (
        "v13",
        "desire-supply-e2e-ten-account-v13",
        "e2e-ten-account-v13-iam37-demand10-trust7",
        "internal-sandbox-bundle-iam37-demand10-trust7",
        "v13drill01",
        "172.16.227.0/24",
        "172.16.228.0/24",
        "172.16.229.0/24",
        "172.16.231.0/24",
        "172.16.232.0/24",
    )
)
_ACTIVATION_CONTAINER_FORMAT = (
    '{"Config":{{json .Config}},"HostConfig":{{json .HostConfig}},'
    '"Id":{{json .Id}},"Mounts":{{json .Mounts}},'
    '"Name":{{json .Name}}}'
)
_ACTIVATION_NETWORK_FORMAT = '{"Id":{{json .Id}},"Name":{{json .Name}}}'
_ACTIVATION_VOLUME_FORMAT = '{"Name":{{json .Name}}}'


class PrivateServerIngressActivationError(RuntimeError):
    """Stable, non-reflective activation failure."""

    def __init__(self) -> None:
        super().__init__("PRIVATE_SERVER_INGRESS_ACTIVATION_INVALID")


class PrivateServerIngressPartialPossibleError(RuntimeError):
    """The one allowed up call may have changed daemon state."""

    def __init__(self) -> None:
        super().__init__("PRIVATE_SERVER_INGRESS_PARTIAL_POSSIBLE")


class _ClosedArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        del message
        _invalid()


def _invalid() -> NoReturn:
    raise PrivateServerIngressActivationError()


def _exact_project(value: str) -> str:
    if (
        not isinstance(value, str)
        or value in _FROZEN_PROJECTS
        or "v13" in value
        or _PROJECT.fullmatch(value) is None
    ):
        _invalid()
    return value


def _absolute_file(value: str) -> Path:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\x00" in value
    ):
        _invalid()
    path = Path(value)
    lowered = value.lower().encode("utf-8")
    if not path.is_absolute() or any(
        token in lowered for token in _FROZEN_BYTE_TOKENS
    ):
        _invalid()
    return path


def _read_closed_file(path: Path, *, expected_owner: int) -> bytes:
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
            or file_stat.st_uid != expected_owner
            or file_stat.st_nlink != 1
            or not 0 < file_stat.st_size <= _MAX_INPUT
            or path.is_symlink()
            or (file_stat.st_dev, file_stat.st_ino)
            != (path_stat.st_dev, path_stat.st_ino)
        ):
            _invalid()
        chunks = []
        remaining = file_stat.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                _invalid()
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            _invalid()
        value = b"".join(chunks)
        final = os.fstat(descriptor)
        final_path = path.lstat()
        if (
            len(value) != file_stat.st_size
            or (final.st_dev, final.st_ino, final.st_size)
            != (file_stat.st_dev, file_stat.st_ino, file_stat.st_size)
            or (final.st_dev, final.st_ino)
            != (final_path.st_dev, final_path.st_ino)
        ):
            _invalid()
        return value
    except OSError:
        _invalid()
    finally:
        os.close(descriptor)


def _read_static_source(
    path: Path,
    *,
    expected_owner: int,
    expected_digest: str,
) -> bytes:
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
            or file_stat.st_uid != expected_owner
            or file_stat.st_mode & 0o022
            or file_stat.st_nlink != 1
            or not 0 < file_stat.st_size <= _MAX_STATIC_INPUT
            or path.is_symlink()
            or (file_stat.st_dev, file_stat.st_ino)
            != (path_stat.st_dev, path_stat.st_ino)
        ):
            _invalid()
        chunks = []
        remaining = file_stat.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                _invalid()
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            _invalid()
        final = os.fstat(descriptor)
        final_path = path.lstat()
        if (
            (final.st_dev, final.st_ino, final.st_size)
            != (file_stat.st_dev, file_stat.st_ino, file_stat.st_size)
            or (final.st_dev, final.st_ino)
            != (final_path.st_dev, final_path.st_ino)
        ):
            _invalid()
        value = b"".join(chunks)
        if hashlib.sha256(value).hexdigest() != expected_digest:
            _invalid()
        return value
    except OSError:
        _invalid()
    finally:
        os.close(descriptor)


def _module_from_verified_bytes(name: str, path: Path, value: bytes) -> ModuleType:
    if not isinstance(value, bytes) or not value:
        _invalid()
    module = ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = ""
    sys.modules[name] = module
    try:
        code = compile(value, str(path), "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        _invalid()
    return module


def _verified_release_helpers(
    release_input_bytes: bytes,
    compose_contract_bytes: bytes,
):
    release_module = _module_from_verified_bytes(
        "_desire_private_server_release_inputs",
        _RELEASE_INPUT_HELPER,
        release_input_bytes,
    )
    compose_module = _module_from_verified_bytes(
        "_desire_private_server_compose_contract",
        _COMPOSE_CONTRACT_HELPER,
        compose_contract_bytes,
    )
    stager = getattr(release_module, "stage_private_server_release_inputs", None)
    builder = getattr(
        compose_module,
        "build_canonical_private_server_compose",
        None,
    )
    if not callable(stager) or not callable(builder):
        _invalid()
    return stager, builder


def _verified_preflight_helper(preflight_bytes: bytes) -> ModuleType:
    module = _module_from_verified_bytes(
        "_desire_private_server_preflight",
        _PREFLIGHT_PATH,
        preflight_bytes,
    )
    for name in (
        "_exact_rfc1918_address",
        "_collect_interfaces",
        "_collect_listeners",
        "validate_private_server_ingress",
    ):
        if not callable(getattr(module, name, None)):
            _invalid()
    return module


def _validate_input_root(
    env_path: Path,
    ipam_path: Path,
    *,
    expected_owner: int,
) -> Path:
    if (
        env_path.name != "compose.env"
        or ipam_path.name != "compose.ipam.yaml"
        or env_path.parent != ipam_path.parent
    ):
        _invalid()
    root = env_path.parent
    try:
        root_stat = root.lstat()
        resolved = root.resolve(strict=True)
    except OSError:
        _invalid()
    if (
        not stat.S_ISDIR(root_stat.st_mode)
        or stat.S_IMODE(root_stat.st_mode) != 0o700
        or root_stat.st_uid != expected_owner
        or root.is_symlink()
        or resolved != root
    ):
        _invalid()
    return root


def _unquoted_path(value: str) -> str:
    if value.startswith("'") and value.endswith("'") and len(value) > 2:
        value = value[1:-1]
    if not value.startswith("/") or any(
        character in value for character in ("'", "\\", "\x00", "\r", "\n")
    ):
        _invalid()
    return value


def _dotenv_path(path: Path) -> str:
    value = str(path)
    if any(character in value for character in ("\x00", "\r", "\n")):
        _invalid()
    if _SAFE_UNQUOTED_PATH.fullmatch(value) is not None:
        return value
    if "'" in value or "\\" in value:
        _invalid()
    return f"'{value}'"


def _validate_env_bytes(value: bytes, *, root: Path) -> tuple[str, str]:
    if any(token in value.lower() for token in _FROZEN_BYTE_TOKENS):
        _invalid()
    try:
        text = value.decode("utf-8")
    except UnicodeError:
        _invalid()
    if not text.endswith("\n"):
        _invalid()
    parsed = []
    for line in text.splitlines():
        key, separator, item = line.partition("=")
        if separator != "=" or not item:
            _invalid()
        parsed.append((key, item))
    if tuple(key for key, _ in parsed) != _ENV_KEYS:
        _invalid()
    image_tag = parsed[0][1]
    if _SAFE_TOKEN.fullmatch(image_tag) is None:
        _invalid()
    for index, expected_name in enumerate(_ENV_PATH_NAMES, start=1):
        if _unquoted_path(parsed[index][1]) != str(root / expected_name):
            _invalid()
    bundle_path = Path(_unquoted_path(parsed[-1][1]))
    if bundle_path.parent != root or _SAFE_TOKEN.fullmatch(bundle_path.name) is None:
        _invalid()
    pointers = (
        image_tag,
        *(_dotenv_path(root / name) for name in _ENV_PATH_NAMES),
        _dotenv_path(bundle_path),
    )
    expected = "".join(
        f"{key}={item}\n" for key, item in zip(_ENV_KEYS, pointers)
    ).encode("utf-8")
    if value != expected:
        _invalid()
    return image_tag, bundle_path.name


def _validate_ipam_bytes(value: bytes) -> dict[str, str]:
    match = _IPAM_DOCUMENT.fullmatch(value)
    if match is None or any(
        token in value.lower() for token in _FROZEN_BYTE_TOKENS
    ):
        _invalid()
    observed = []
    for raw in match.groups():
        try:
            network = ipaddress.ip_network(raw.decode("ascii"), strict=True)
        except (UnicodeError, ValueError):
            _invalid()
        if (
            not isinstance(network, ipaddress.IPv4Network)
            or network.prefixlen != 24
            or not any(network.subnet_of(private) for private in _RFC1918)
            or network in _FROZEN_SUBNETS
        ):
            _invalid()
        observed.append(network)
    if len(set(observed)) != 4:
        _invalid()
    ingress, oidc_backend, app, data = observed
    return {
        "ingress": str(ingress),
        "oidc-backend": str(oidc_backend),
        "app": str(app),
        "data": str(data),
    }


def _locked_images(
    image_tag: str,
    expected: Mapping[str, str],
) -> dict[str, str]:
    references = {
        "platform": f"desire-supply-platform:{image_tag}",
        "web": f"desire-supply-web:{image_tag}",
        "edge": f"desire-supply-edge:{image_tag}",
        "postgres": _POSTGRES_IMAGE_REF,
    }
    if not isinstance(expected, Mapping) or set(expected) != set(references):
        _invalid()
    result = {}
    for name, reference in references.items():
        image_id = expected.get(name)
        if not isinstance(image_id, str) or _IMAGE_ID.fullmatch(image_id) is None:
            _invalid()
        result[reference] = image_id
    if len(set(result.values())) != len(result):
        _invalid()
    return result


def _verify_locked_images(
    run: Callable[[Sequence[str]], object],
    docker: Sequence[str],
    image_ref_to_id: Mapping[str, str],
    *,
    inspect_ids: bool,
) -> None:
    values = (
        sorted(image_ref_to_id.values())
        if inspect_ids
        else sorted(image_ref_to_id)
    )
    for value in values:
        expected = value if inspect_ids else image_ref_to_id[value]
        output = _checked_stdout(
            run(
                tuple(docker)
                + ("image", "inspect", "--format", "{{.Id}}", value)
            )
        )
        if output != expected + "\n":
            _invalid()


def _validate_executable(path_text: str) -> None:
    path = Path(path_text)
    if not path.is_absolute():
        _invalid()
    try:
        executable = path.lstat()
    except OSError:
        _invalid()
    if (
        not stat.S_ISREG(executable.st_mode)
        or executable.st_uid != 0
        or executable.st_mode & 0o022
        or executable.st_mode & 0o111 == 0
        or path.is_symlink()
    ):
        _invalid()


def _validate_production_executables() -> None:
    for path in (_DOCKER_EXECUTABLE, _IP_EXECUTABLE, _SS_EXECUTABLE):
        _validate_executable(path)


def _compose_plugin_digest(path: Path, *, expected_owner: int) -> str:
    flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = None
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        visible = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_owner
            or before.st_mode & 0o022
            or before.st_mode & 0o111 == 0
            or before.st_nlink != 1
            or not 0 < before.st_size <= _MAX_COMPOSE_PLUGIN
            or path.is_symlink()
            or (before.st_dev, before.st_ino) != (visible.st_dev, visible.st_ino)
        ):
            _invalid()
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                _invalid()
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            _invalid()
        after = os.fstat(descriptor)
        final = path.lstat()
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or (after.st_dev, after.st_ino) != (final.st_dev, final.st_ino)
        ):
            _invalid()
    except OSError:
        _invalid()
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return digest.hexdigest()


def _validate_plugin_directory_chain(
    path: Path, *, expected_owner: int, stop: Path,
) -> None:
    current = path
    while True:
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            current = current.parent
            continue
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
        _validate_plugin_directory_chain(
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


def _compose_plugin_identity(
    *, validate_system_path: bool, expected_owner: int,
    search_paths: Optional[Sequence[Path]],
) -> dict[str, str]:
    if validate_system_path:
        paths = tuple(Path(value) for value in _COMPOSE_PLUGIN_PATHS)
        trusted_root = Path("/")
    else:
        if (
            not isinstance(search_paths, Sequence)
            or isinstance(search_paths, (str, bytes))
            or not search_paths
        ):
            _invalid()
        paths = tuple(search_paths)
        if any(not isinstance(path, Path) for path in paths):
            _invalid()
        try:
            trusted_root = Path(os.path.commonpath([str(path.parent) for path in paths]))
        except (TypeError, ValueError):
            _invalid()
    if (
        len(paths) != len(set(paths))
        or any(not path.is_absolute() or path.name != "docker-compose" for path in paths)
    ):
        _invalid()

    candidates = []
    for path in paths:
        _validate_plugin_directory_chain(
            path.parent, expected_owner=expected_owner, stop=trusted_root,
        )
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            _invalid()
        candidates.append(path)
    if len(candidates) != 1:
        _invalid()
    path = candidates[0]
    digest = _compose_plugin_digest(path, expected_owner=expected_owner)
    return {
        "path": str(path),
        "sha256": digest,
        "version": _COMPOSE_VERSION.rstrip("\n"),
    }


def _verify_compose_plugin_identity(
    identity: Mapping[str, str], *, expected_owner: int,
    validate_system_path: bool, search_paths: Optional[Sequence[Path]],
) -> None:
    current = _compose_plugin_identity(
        validate_system_path=validate_system_path,
        expected_owner=expected_owner,
        search_paths=search_paths,
    )
    if current != identity:
        _invalid()


def _validate_docker_config_closed(
    attempt_fd: int, *, expected_owner: int,
) -> None:
    directory_fd = None
    config_fd = None
    try:
        directory_fd = os.open(
            "docker-config",
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=attempt_fd,
        )
        directory_stat = os.fstat(directory_fd)
        visible_directory = os.stat(
            "docker-config", dir_fd=attempt_fd, follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(directory_stat.st_mode)
            or stat.S_IMODE(directory_stat.st_mode) != 0o700
            or directory_stat.st_uid != expected_owner
            or (directory_stat.st_dev, directory_stat.st_ino)
            != (visible_directory.st_dev, visible_directory.st_ino)
            or set(os.listdir(directory_fd)) != {"config.json"}
        ):
            _invalid()
        config_fd = os.open(
            "config.json",
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        config_stat = os.fstat(config_fd)
        visible_config = os.stat(
            "config.json", dir_fd=directory_fd, follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(config_stat.st_mode)
            or stat.S_IMODE(config_stat.st_mode) != 0o600
            or config_stat.st_uid != expected_owner
            or config_stat.st_nlink != 1
            or config_stat.st_size != 3
            or (config_stat.st_dev, config_stat.st_ino)
            != (visible_config.st_dev, visible_config.st_ino)
            or os.read(config_fd, 4) != b"{}\n"
            or os.read(config_fd, 1)
        ):
            _invalid()
    except OSError:
        _invalid()
    finally:
        if config_fd is not None:
            os.close(config_fd)
        if directory_fd is not None:
            os.close(directory_fd)


def _validate_python_runtime() -> None:
    if sys.flags.isolated != 1:
        _invalid()
    _validate_trusted_executable_chain(
        Path(sys.executable), expected_owner=0, trusted_root=Path("/"),
    )


def _open_attempts_root(path: Path, *, expected_owner: int) -> int:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        _invalid()
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
        root_stat = os.fstat(descriptor)
        path_stat = path.lstat()
    except OSError:
        _invalid()
    if (
        not stat.S_ISDIR(root_stat.st_mode)
        or stat.S_IMODE(root_stat.st_mode) != 0o700
        or root_stat.st_uid != expected_owner
        or (root_stat.st_dev, root_stat.st_ino)
        != (path_stat.st_dev, path_stat.st_ino)
    ):
        os.close(descriptor)
        _invalid()
    return descriptor


def _write_snapshot(
    directory_fd: int,
    name: str,
    value: bytes,
    *,
    expected_owner: int,
    mode: int = 0o600,
) -> None:
    if (
        not isinstance(value, bytes)
        or not value
        or "/" in name
        or name in (".", "..")
        or mode not in (0o444, 0o600)
    ):
        _invalid()
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(name, flags, mode, dir_fd=directory_fd)
        os.fchmod(descriptor, mode)
        offset = 0
        while offset < len(value):
            written = os.write(descriptor, value[offset:])
            if written <= 0:
                _invalid()
            offset += written
        os.fsync(descriptor)
        written_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(written_stat.st_mode)
            or stat.S_IMODE(written_stat.st_mode) != mode
            or written_stat.st_uid != expected_owner
            or written_stat.st_nlink != 1
            or written_stat.st_size != len(value)
        ):
            _invalid()
    except OSError:
        _invalid()
    finally:
        try:
            os.close(descriptor)
        except (OSError, UnboundLocalError):
            pass
    try:
        os.fsync(directory_fd)
    except OSError:
        _invalid()


def _claim_attempt(
    attempts_root: Path,
    project: str,
    *,
    expected_owner: int,
) -> tuple[Path, int]:
    root_fd = _open_attempts_root(attempts_root, expected_owner=expected_owner)
    try:
        try:
            os.mkdir(project, 0o700, dir_fd=root_fd)
            os.fsync(root_fd)
        except OSError:
            _invalid()
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        attempt_fd = os.open(project, flags, dir_fd=root_fd)
        os.fchmod(attempt_fd, 0o700)
        attempt_stat = os.fstat(attempt_fd)
        if (
            not stat.S_ISDIR(attempt_stat.st_mode)
            or stat.S_IMODE(attempt_stat.st_mode) != 0o700
            or attempt_stat.st_uid != expected_owner
        ):
            os.close(attempt_fd)
            _invalid()
        receipt = (
            '{"format":"desire-private-ingress-attempt-v1",'
            f'"project":"{project}","status":"CLAIMED"}}\n'
        ).encode("ascii")
        _write_snapshot(
            attempt_fd,
            "activation.receipt.json",
            receipt,
            expected_owner=expected_owner,
        )
        return attempts_root / project, attempt_fd
    except OSError:
        _invalid()
    finally:
        os.close(root_fd)


def _create_docker_config(
    attempt_fd: int,
    attempt_path: Path,
    *,
    expected_owner: int,
) -> Path:
    try:
        os.mkdir("docker-config", 0o700, dir_fd=attempt_fd)
        os.fsync(attempt_fd)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        docker_config_fd = os.open("docker-config", flags, dir_fd=attempt_fd)
        os.fchmod(docker_config_fd, 0o700)
        config_stat = os.fstat(docker_config_fd)
        if (
            config_stat.st_uid != expected_owner
            or stat.S_IMODE(config_stat.st_mode) != 0o700
        ):
            _invalid()
        _write_snapshot(
            docker_config_fd,
            "config.json",
            b"{}\n",
            expected_owner=expected_owner,
        )
        os.close(docker_config_fd)
        return attempt_path / "docker-config"
    except OSError:
        _invalid()


def _create_attempt_directory(
    attempt_fd: int,
    attempt_path: Path,
    name: str,
    *,
    expected_owner: int,
) -> Path:
    if not isinstance(name, str) or "/" in name or name in ("", ".", ".."):
        _invalid()
    descriptor = None
    try:
        os.mkdir(name, 0o700, dir_fd=attempt_fd)
        os.fsync(attempt_fd)
        descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=attempt_fd,
        )
        os.fchmod(descriptor, 0o700)
        metadata = os.fstat(descriptor)
        current = os.stat(name, dir_fd=attempt_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_uid != expected_owner
            or (metadata.st_dev, metadata.st_ino)
            != (current.st_dev, current.st_ino)
        ):
            _invalid()
        os.fsync(descriptor)
        return attempt_path / name
    except OSError:
        _invalid()
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _clean_environment(
    source: Mapping[str, str],
    bind_ip: str,
    *,
    docker_config: Path,
):
    if not isinstance(source, Mapping):
        _invalid()
    if any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in source.items()
    ):
        _invalid()
    cleaned = {
        "PATH": _TRUSTED_PATH,
        "LANG": _TRUSTED_LOCALE,
        "LC_ALL": _TRUSTED_LOCALE,
        "DOCKER_HOST": _DOCKER_ENDPOINT,
        "DOCKER_CONFIG": str(docker_config),
        "COMPOSE_DISABLE_ENV_FILE": "true",
        "DESIRE_PRIVATE_INGRESS_IP": bind_ip,
    }
    return MappingProxyType(cleaned)


def _checked_stdout(result: object) -> str:
    returncode = getattr(result, "returncode", None)
    stdout = getattr(result, "stdout", None)
    stderr = getattr(result, "stderr", None)
    if (
        type(returncode) is not int
        or returncode != 0
        or not isinstance(stdout, str)
        or stderr != ""
        or len(stdout.encode("utf-8")) > _MAX_OUTPUT
        or "\x00" in stdout
    ):
        _invalid()
    return stdout


def _validate_config(output: str, *, project: str, bind_ip: str) -> dict:
    try:
        document = json.loads(output)
    except (json.JSONDecodeError, UnicodeError):
        _invalid()
    if not isinstance(document, dict) or document.get("name") != project:
        _invalid()
    services = document.get("services")
    networks = document.get("networks")
    volumes = document.get("volumes")
    if not isinstance(services, dict) or set(services) != _SERVICES:
        _invalid()
    if not isinstance(networks, dict) or set(networks) != {
        "app",
        "data",
        "oidc-backend",
        "ingress",
    }:
        _invalid()
    if not isinstance(volumes, dict) or set(volumes) != {"postgres-data"}:
        _invalid()

    for name, service in services.items():
        if not isinstance(service, dict):
            _invalid()
        if "container_name" in service:
            _invalid()
        service_networks = service.get("networks")
        if (
            not isinstance(service_networks, dict)
            or set(service_networks) != _SERVICE_NETWORKS[name]
        ):
            _invalid()
        ports = service.get("ports", [])
        if not isinstance(ports, list) or (name != "edge" and ports):
            _invalid()
        if name in _ADMIN_SERVICES:
            environment = service.get("environment")
            if not isinstance(environment, dict) or (
                environment.get("DESIRE_DEPLOYMENT_MODE") != "INTERNAL_SANDBOX"
                or environment.get("DESIRE_EXTERNAL_PARTICIPANTS_ENABLED") != "false"
            ):
                _invalid()
        if name == "matching-runtime" and service.get("environment") != {
            "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE": (
                "/run/desire/matching-deployment.json"
            ),
            "DESIRE_MATCHING_RUNTIME_HEALTH_FILE": (
                "/run/matching-runtime/healthy"
            ),
        }:
            _invalid()

    edge_ports = services["edge"].get("ports")
    if not isinstance(edge_ports, list) or len(edge_ports) != 2:
        _invalid()
    observed = set()
    for port in edge_ports:
        if (
            not isinstance(port, dict)
            or port.get("target") != 443
            or port.get("published") != "443"
            or port.get("protocol") != "tcp"
            or port.get("mode") != "ingress"
        ):
            _invalid()
        host_ip = port.get("host_ip")
        if not isinstance(host_ip, str):
            _invalid()
        observed.add(host_ip)
    if observed != {"127.0.0.1", bind_ip}:
        _invalid()

    for name, network in networks.items():
        if not isinstance(network, dict) or network.get("external", False) is not False:
            _invalid()
        internal = network.get("internal", False)
        if type(internal) is not bool or internal != (name in _INTERNAL_NETWORKS):
            _invalid()
        if network.get("name") != f"{project}_{name}":
            _invalid()
    volume = volumes["postgres-data"]
    if (
        not isinstance(volume, dict)
        or volume.get("external", False) is not False
        or volume.get("name") != f"{project}_postgres-data"
    ):
        _invalid()
    return document


def _validate_up_result(result: object) -> None:
    returncode = getattr(result, "returncode", None)
    stdout = getattr(result, "stdout", None)
    stderr = getattr(result, "stderr", None)
    if (
        type(returncode) is not int
        or returncode != 0
        or not isinstance(stdout, str)
        or not isinstance(stderr, str)
        or len(stdout.encode("utf-8")) > _MAX_OUTPUT
        or len(stderr.encode("utf-8")) > _MAX_OUTPUT
        or "\x00" in stdout
        or "\x00" in stderr
    ):
        raise PrivateServerIngressPartialPossibleError()


def _closed_json_lines(output: str) -> list[dict]:
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    result = []
    for line in output.splitlines():
        if not line or line != line.strip():
            _invalid()
        try:
            value = json.loads(line, object_pairs_hook=pairs)
        except (json.JSONDecodeError, UnicodeError, TypeError, ValueError):
            _invalid()
        if not isinstance(value, dict):
            _invalid()
        result.append(value)
    return result


def _compose_hashes(output: str) -> dict[str, str]:
    result = {}
    expected_services = tuple(sorted(_SERVICES))
    lines = output.splitlines()
    if len(lines) != len(expected_services):
        _invalid()
    for expected_service, line in zip(expected_services, lines):
        service, separator, digest = line.partition(" ")
        if (
            separator != " " or service != expected_service
            or not digest or " " in digest
            or _SHA256.fullmatch(digest) is None
        ):
            _invalid()
        result[service] = digest
    return result


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


def _capture_activation_resources(
    run: Callable[[Sequence[str]], object],
    run_compose: Callable[[Sequence[str]], object],
    docker: Sequence[str],
    resolved_compose: Sequence[str], project: str,
) -> tuple[dict[str, str], dict[str, str], dict[str, str], dict[str, str], str]:
    # `config --hash *` is the authoritative hash projection of the exact
    # permanent resolved model passed to `up`; live labels are accepted only
    # when all eleven agree with it.
    authoritative_hashes = _compose_hashes(
        _checked_stdout(
            run_compose(tuple(resolved_compose) + ("config", "--hash", "*"))
        )
    )
    container_names = tuple(f"{project}-{service}-1" for service in sorted(_SERVICES))
    containers = _closed_json_lines(
        _checked_stdout(
            run(
                tuple(docker)
                + ("container", "inspect", "--format", _ACTIVATION_CONTAINER_FORMAT)
                + container_names
            )
        )
    )
    if len(containers) != len(_SERVICES):
        _invalid()
    container_ids = {}
    config_hashes = {}
    security_projection_sha256 = {}
    for item in containers:
        if set(item) != {"Config", "HostConfig", "Id", "Mounts", "Name"}:
            _invalid()
        name = item["Name"]
        identifier = item["Id"]
        config = item["Config"]
        labels = config.get("Labels") if isinstance(config, dict) else None
        config_hash = (
            labels.get("com.docker.compose.config-hash")
            if isinstance(labels, dict)
            else None
        )
        if (
            not isinstance(name, str) or not name.startswith(f"/{project}-")
            or not name.endswith("-1") or not isinstance(identifier, str)
            or _RESOURCE_ID.fullmatch(identifier) is None
            or not isinstance(config_hash, str) or _SHA256.fullmatch(config_hash) is None
        ):
            _invalid()
        service = name[len(project) + 2:-2]
        if service not in _SERVICES or service in container_ids:
            _invalid()
        container_ids[service] = identifier
        config_hashes[service] = config_hash
        security_projection_sha256[service] = _security_projection_sha256(item)
    if (
        set(container_ids) != _SERVICES
        or len(set(container_ids.values())) != len(_SERVICES)
        or config_hashes != authoritative_hashes
    ):
        _invalid()

    network_names = tuple(f"{project}_{name}" for name in ("app", "data", "ingress", "oidc-backend"))
    networks = _closed_json_lines(
        _checked_stdout(
            run(
                tuple(docker)
                + ("network", "inspect", "--format", _ACTIVATION_NETWORK_FORMAT)
                + network_names
            )
        )
    )
    if len(networks) != 4:
        _invalid()
    network_ids = {}
    for item in networks:
        if set(item) != {"Id", "Name"}:
            _invalid()
        name = item["Name"]
        identifier = item["Id"]
        if (
            not isinstance(name, str) or not name.startswith(f"{project}_")
            or not isinstance(identifier, str) or _RESOURCE_ID.fullmatch(identifier) is None
        ):
            _invalid()
        logical = name[len(project) + 1:]
        if logical not in ("app", "data", "ingress", "oidc-backend") or logical in network_ids:
            _invalid()
        network_ids[logical] = identifier
    if len(network_ids) != 4 or len(set(network_ids.values())) != 4:
        _invalid()

    volume_name = f"{project}_postgres-data"
    volumes = _closed_json_lines(
        _checked_stdout(
            run(
                tuple(docker)
                + ("volume", "inspect", "--format", _ACTIVATION_VOLUME_FORMAT, volume_name)
            )
        )
    )
    if volumes != [{"Name": volume_name}]:
        _invalid()
    return (
        container_ids,
        authoritative_hashes,
        network_ids,
        security_projection_sha256,
        volume_name,
    )


def _default_command_runner(command: Sequence[str], environment: Mapping[str, str]):
    timeout = 900 if tuple(command)[-6:-5] == ("up",) else 30
    return subprocess.run(
        list(command),
        cwd=_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        timeout=timeout,
    )


def activate_private_server_ingress(
    *,
    project_name: str,
    env_file: str,
    ipam_overlay: str,
    bind_ip: str,
    command_runner: Callable[[Sequence[str], Mapping[str, str]], object],
    environ: Mapping[str, str],
    platform_name: str,
    attempts_root: Path,
    attempt_owner: int,
    validate_executables: bool,
    expected_image_ids: Mapping[str, str],
    approved_input_tree_sha256: str,
    release_input_stager: Optional[Callable[..., object]],
    compose_contract_builder: Optional[Callable[..., object]],
    compose_plugin_paths: Optional[Sequence[Path]],
) -> None:
    if platform_name != "linux":
        _invalid()
    project = _exact_project(project_name)
    if (
        not isinstance(approved_input_tree_sha256, str)
        or _SHA256.fullmatch(approved_input_tree_sha256) is None
    ):
        _invalid()
    attempt_path, attempt_fd = _claim_attempt(
        attempts_root,
        project,
        expected_owner=attempt_owner,
    )
    try:
        if validate_executables:
            _validate_production_executables()
        docker_config = _create_docker_config(
            attempt_fd,
            attempt_path,
            expected_owner=attempt_owner,
        )
        env_path = _absolute_file(env_file)
        ipam_path = _absolute_file(ipam_overlay)
        input_root = _validate_input_root(
            env_path,
            ipam_path,
            expected_owner=attempt_owner,
        )
        env_bytes = _read_closed_file(
            env_path,
            expected_owner=attempt_owner,
        )
        ipam_bytes = _read_closed_file(
            ipam_path,
            expected_owner=attempt_owner,
        )
        image_tag, bundle_name = _validate_env_bytes(env_bytes, root=input_root)
        subnets = _validate_ipam_bytes(ipam_bytes)
        image_ref_to_id = _locked_images(image_tag, expected_image_ids)
        source_owner = 0 if validate_executables else os.geteuid()
        static_bytes = {
            path: _read_static_source(
                path,
                expected_owner=source_owner,
                expected_digest=digest,
            )
            for path, digest in _STATIC_SOURCE_DIGESTS.items()
        }
        base_bytes = static_bytes[_BASE_COMPOSE]
        private_bytes = static_bytes[_PRIVATE_OVERLAY]
        if (release_input_stager is None) != (compose_contract_builder is None):
            _invalid()
        if release_input_stager is None:
            release_input_stager, compose_contract_builder = (
                _verified_release_helpers(
                    static_bytes[_RELEASE_INPUT_HELPER],
                    static_bytes[_COMPOSE_CONTRACT_HELPER],
                )
            )
        if not callable(release_input_stager) or not callable(
            compose_contract_builder
        ):
            _invalid()
        preflight = _verified_preflight_helper(static_bytes[_PREFLIGHT_PATH])
        snapshots = (
            ("compose.env.snapshot", env_bytes),
            ("compose.yaml.snapshot", base_bytes),
            ("private-server.compose.yaml.snapshot", private_bytes),
            ("compose.ipam.yaml.snapshot", ipam_bytes),
        )
        for name, value in snapshots:
            _write_snapshot(
                attempt_fd,
                name,
                value,
                expected_owner=attempt_owner,
            )

        release_stage = _create_attempt_directory(
            attempt_fd,
            attempt_path,
            "release-inputs",
            expected_owner=attempt_owner,
        )
        template_snapshot_name = _IDENTITY_TEMPLATE.name
        _write_snapshot(
            attempt_fd,
            template_snapshot_name,
            static_bytes[_IDENTITY_TEMPLATE],
            expected_owner=attempt_owner,
            mode=0o444,
        )
        release_snapshot = release_input_stager(
            input_root=input_root,
            bundle_name=bundle_name,
            attempt_stage_root=release_stage,
        )
        if (
            getattr(release_snapshot, "tree_sha256", None)
            != approved_input_tree_sha256
        ):
            _invalid()
        source_to_staged = getattr(
            release_snapshot,
            "source_to_staged",
            None,
        )
        if not isinstance(source_to_staged, Mapping):
            _invalid()
        closed_sources = dict(source_to_staged)
        staged_env = closed_sources.get(env_path)
        staged_ipam = closed_sources.get(ipam_path)
        if (
            not isinstance(staged_env, Path)
            or not isinstance(staged_ipam, Path)
            or _read_closed_file(
                staged_env,
                expected_owner=attempt_owner,
            )
            != env_bytes
            or _read_closed_file(
                staged_ipam,
                expected_owner=attempt_owner,
            )
            != ipam_bytes
        ):
            _invalid()
        closed_sources[_IDENTITY_TEMPLATE] = (
            attempt_path / template_snapshot_name
        )

        target = str(preflight._exact_rfc1918_address(bind_ip))
        environment = _clean_environment(
            environ,
            target,
            docker_config=docker_config,
        )

        def run(command: Sequence[str]):
            return command_runner(tuple(command), environment)

        def host_facts_run(command: Sequence[str]):
            command_tuple = tuple(command)
            if command_tuple[:1] == ("ip",):
                command_tuple = (_IP_EXECUTABLE,) + command_tuple[1:]
            elif command_tuple[:1] == ("ss",):
                command_tuple = (_SS_EXECUTABLE,) + command_tuple[1:]
            else:
                _invalid()
            return run(command_tuple)

        interfaces = preflight._collect_interfaces(host_facts_run)
        listeners = preflight._collect_listeners(host_facts_run)
        preflight.validate_private_server_ingress(
            target,
            interfaces=interfaces,
            listeners=listeners,
        )

        docker = (_DOCKER_EXECUTABLE, "--host", _DOCKER_ENDPOINT)
        compose_plugin_owner = 0 if validate_executables else attempt_owner
        compose_search_paths = None if validate_executables else compose_plugin_paths
        compose_plugin = _compose_plugin_identity(
            validate_system_path=validate_executables,
            expected_owner=compose_plugin_owner,
            search_paths=compose_search_paths,
        )

        def verify_compose_boundary() -> None:
            # DOCKER_CONFIG has higher plugin-search precedence than system
            # directories.  Close it and re-enumerate the complete supported
            # system search set immediately around every Compose invocation.
            _validate_docker_config_closed(
                attempt_fd, expected_owner=attempt_owner,
            )
            _verify_compose_plugin_identity(
                compose_plugin,
                expected_owner=compose_plugin_owner,
                validate_system_path=validate_executables,
                search_paths=compose_search_paths,
            )
            _validate_docker_config_closed(
                attempt_fd, expected_owner=attempt_owner,
            )

        def run_compose(command: Sequence[str]):
            verify_compose_boundary()
            try:
                return run(command)
            finally:
                verify_compose_boundary()

        if _checked_stdout(
            run_compose(docker + ("compose", "version", "--short"))
        ) != _COMPOSE_VERSION:
            _invalid()
        _verify_locked_images(
            run,
            docker,
            image_ref_to_id,
            inspect_ids=False,
        )
        compose_config = docker + (
            "compose",
            "--project-name",
            project,
            "--project-directory",
            str(_ROOT),
            "--env-file",
            str(attempt_path / "compose.env.snapshot"),
            "-f",
            str(attempt_path / "compose.yaml.snapshot"),
            "-f",
            str(attempt_path / "private-server.compose.yaml.snapshot"),
            "-f",
            str(attempt_path / "compose.ipam.yaml.snapshot"),
        )
        config = _checked_stdout(
            run_compose(compose_config + ("config", "--format", "json"))
        )
        built = compose_contract_builder(
            config,
            project=project,
            bind_ip=target,
            subnets=subnets,
            image_tag=image_tag,
            source_to_staged=closed_sources,
            image_ref_to_id=image_ref_to_id,
        )
        if (
            not isinstance(built, tuple)
            or len(built) != 2
            or not isinstance(built[0], bytes)
            or not isinstance(built[1], dict)
            or not built[0].endswith(b"\n")
            or len(built[0]) > 2 * 1024 * 1024
        ):
            _invalid()
        canonical_config, config_document = built
        _write_snapshot(
            attempt_fd,
            "resolved.compose.json",
            canonical_config,
            expected_owner=attempt_owner,
        )

        resolved_compose = docker + (
            "compose",
            "--project-name",
            project,
            "--project-directory",
            str(_ROOT),
            "-f",
            str(attempt_path / "resolved.compose.json"),
        )
        round_trip = _checked_stdout(
            run_compose(resolved_compose + ("config", "--format", "json"))
        )
        round_trip_document = _validate_config(
            round_trip,
            project=project,
            bind_ip=target,
        )
        if round_trip_document != config_document:
            _invalid()

        compose_sha256 = hashlib.sha256(canonical_config).hexdigest()
        release_receipt = json.dumps(
            {
                "compose_sha256": compose_sha256,
                "format": "desire-private-ingress-release-lock-v1",
                "image_ids": sorted(image_ref_to_id.values()),
                "input_tree_sha256": approved_input_tree_sha256,
                "project": project,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii") + b"\n"
        _write_snapshot(
            attempt_fd,
            "release-lock.receipt.json",
            release_receipt,
            expected_owner=attempt_owner,
        )

        label = f"label=com.docker.compose.project={project}"
        resource_commands = [
            docker
            + (
                "container",
                "ls",
                "--all",
                "--quiet",
                "--filter",
                label,
            ),
            docker + ("network", "ls", "--quiet", "--filter", label),
            docker + ("volume", "ls", "--quiet", "--filter", label),
        ]
        for service in sorted(_SERVICES):
            resource_commands.append(
                docker
                + (
                    "container",
                    "ls",
                    "--all",
                    "--quiet",
                    "--filter",
                    f"name=^/{project}-{service}-1$",
                )
            )
        for network in ("app", "data", "ingress", "oidc-backend"):
            resource_commands.append(
                docker
                + (
                    "network",
                    "ls",
                    "--quiet",
                    "--filter",
                    f"name=^{project}_{network}$",
                )
            )
        resource_commands.append(
            docker
            + (
                "volume",
                "ls",
                "--quiet",
                "--filter",
                f"name=^{project}_postgres-data$",
            )
        )
        for command in resource_commands:
            if _checked_stdout(run(command)) != "":
                _invalid()

        _verify_locked_images(
            run,
            docker,
            image_ref_to_id,
            inspect_ids=True,
        )

        _write_snapshot(
            attempt_fd,
            "up-invoked.receipt.json",
            b'{"status":"UP_INVOKED"}\n',
            expected_owner=attempt_owner,
        )
        # The marker permanently records that activation reached the final
        # launch boundary.  A discovery/config drift caught by this pre-gate
        # still means the runner was never entered and therefore remains an
        # INVALID (78), not a partial launch.
        verify_compose_boundary()
        try:
            try:
                up_result = run(
                    resolved_compose
                    + (
                        "up",
                        "-d",
                        "--no-build",
                        "--pull",
                        "never",
                        "--wait",
                    )
                )
            finally:
                verify_compose_boundary()
            _validate_up_result(up_result)
            (
                activated_container_ids,
                activated_config_hashes,
                activated_network_ids,
                activated_security_projection_sha256,
                activated_volume_name,
            ) = _capture_activation_resources(
                run, run_compose, docker, resolved_compose, project,
            )
            _write_snapshot(
                attempt_fd,
                "activation-complete.receipt.json",
                json.dumps(
                    {
                        "bind_ip": target,
                        "compose_sha256": compose_sha256,
                        "compose_plugin": compose_plugin,
                        "config_hashes": activated_config_hashes,
                        "container_ids": activated_container_ids,
                        "format": "desire-private-ingress-activation-v2",
                        "image_ids": {
                            name: expected_image_ids[name]
                            for name in ("edge", "platform", "postgres", "web")
                        },
                        "input_tree_sha256": approved_input_tree_sha256,
                        "network_ids": activated_network_ids,
                        "project": project,
                        "security_projection_sha256": (
                            activated_security_projection_sha256
                        ),
                        "snapshot_sha256": {
                            name: hashlib.sha256(value).hexdigest()
                            for name, value in (
                                ("compose.env.snapshot", env_bytes),
                                ("compose.ipam.yaml.snapshot", ipam_bytes),
                                ("compose.yaml.snapshot", base_bytes),
                                (
                                    template_snapshot_name,
                                    static_bytes[_IDENTITY_TEMPLATE],
                                ),
                                (
                                    "private-server.compose.yaml.snapshot",
                                    private_bytes,
                                ),
                            )
                        },
                        "source_sha256": {
                            str(path.relative_to(_ROOT)): digest
                            for path, digest in sorted(
                                _STATIC_SOURCE_DIGESTS.items(),
                                key=lambda item: str(item[0]),
                            )
                        },
                        "status": "ACTIVATED",
                        "volume_name": activated_volume_name,
                    },
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("ascii")
                + b"\n",
                expected_owner=attempt_owner,
            )
        except PrivateServerIngressPartialPossibleError:
            raise
        except BaseException as error:
            raise PrivateServerIngressPartialPossibleError() from error
    finally:
        os.close(attempt_fd)


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    platform_name: Optional[str] = None,
    command_runner: Optional[
        Callable[[Sequence[str], Mapping[str, str]], object]
    ] = None,
    environ: Optional[Mapping[str, str]] = None,
    attempts_root: Optional[Path] = None,
    release_input_stager: Optional[Callable[..., object]] = None,
    compose_contract_builder: Optional[Callable[..., object]] = None,
    compose_plugin_paths: Optional[Sequence[Path]] = None,
) -> int:
    parser = _ClosedArgumentParser(add_help=False)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--env-file", required=True)
    parser.add_argument("--ipam-overlay", required=True)
    parser.add_argument("--bind-ip", required=True)
    parser.add_argument("--platform-image-id", required=True)
    parser.add_argument("--web-image-id", required=True)
    parser.add_argument("--edge-image-id", required=True)
    parser.add_argument("--postgres-image-id", required=True)
    parser.add_argument("--input-tree-sha256", required=True)
    try:
        arguments = parser.parse_args(argv)
        selected_attempts_root = (
            _ATTEMPTS_ROOT if attempts_root is None else attempts_root
        )
        injected_runner = command_runner is not None
        if not injected_runner and attempts_root is None:
            if os.geteuid() != 0:
                _invalid()
            _validate_python_runtime()
        activate_private_server_ingress(
            project_name=arguments.project_name,
            env_file=arguments.env_file,
            ipam_overlay=arguments.ipam_overlay,
            bind_ip=arguments.bind_ip,
            command_runner=(
                _default_command_runner if command_runner is None else command_runner
            ),
            environ=os.environ if environ is None else environ,
            platform_name=sys.platform if platform_name is None else platform_name,
            attempts_root=selected_attempts_root,
            attempt_owner=0 if attempts_root is None else os.geteuid(),
            validate_executables=not injected_runner,
            expected_image_ids={
                "platform": arguments.platform_image_id,
                "web": arguments.web_image_id,
                "edge": arguments.edge_image_id,
                "postgres": arguments.postgres_image_id,
            },
            approved_input_tree_sha256=arguments.input_tree_sha256,
            release_input_stager=release_input_stager,
            compose_contract_builder=compose_contract_builder,
            compose_plugin_paths=compose_plugin_paths,
        )
    except PrivateServerIngressPartialPossibleError:
        stderr.write(PARTIAL)
        return 75
    except BaseException:
        stderr.write(BLOCKED)
        return 78
    stdout.write(READY)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
