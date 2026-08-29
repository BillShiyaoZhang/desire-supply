#!/usr/bin/env python3
"""Collect a safe post-create projection without starting any container.

The default action writes an exact, absolute, read-only Docker command plan.
Only the explicit ``collect`` action invokes an injectable command runner.
Raw Docker inspect responses are bounded and validated in memory and are
never persisted or reflected.  The resulting receipt is evidence of one
historical observation, not authority to start or otherwise mutate Docker.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import posixpath
import re
import stat
import subprocess
import sys
from types import MappingProxyType
from typing import Any, Callable, Mapping, NoReturn, Optional, Sequence, TextIO


_ACTIVATION_HELPER = Path(__file__).resolve().with_name(
    "activate_private_server_real_oidc.py"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_EXPOSED_PORT = re.compile(
    r"^(?P<port>[1-9][0-9]{0,4})/(?P<protocol>tcp|udp|sctp)$"
)
_ENVIRONMENT_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ZERO_DOCKER_TIME = re.compile(
    r"^0001-01-01T00:00:00(?:\.0{1,9})?Z$"
)
_PROXY_ENVIRONMENT_KEYS = frozenset(
    ("http_proxy", "https_proxy", "ftp_proxy", "no_proxy", "all_proxy")
)
_HEALTHCHECK_FIELDS = (
    "Test",
    "Interval",
    "Timeout",
    "Retries",
    "StartPeriod",
    "StartInterval",
)
_MAX_INVENTORY_STDOUT = 256 * 1024
_MAX_INSPECT_STDOUT = 4 * 1024 * 1024
_CLOSED_ENVIRONMENT = MappingProxyType(
    {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "HOME": "/nonexistent",
        "DOCKER_CONFIG": "/nonexistent",
    }
)

PLAN_READY = (
    '{"authority":"NOT_AUTHORITY","status":'
    '"PRIVATE_SERVER_REAL_OIDC_POST_CREATE_COLLECTION_PLAN_READY_NOT_EXECUTED"}\n'
)
COLLECTED = (
    '{"authority":"NOT_AUTHORITY","status":'
    '"PRIVATE_SERVER_REAL_OIDC_POST_CREATE_COLLECTED_VALIDATED"}\n'
)
CHECKED = (
    '{"authority":"NOT_AUTHORITY","status":'
    '"PRIVATE_SERVER_REAL_OIDC_POST_CREATE_EVIDENCE_CHECKED"}\n'
)
BLOCKED = (
    '{"code":"PRIVATE_SERVER_REAL_OIDC_POST_CREATE_COLLECTOR_INVALID",'
    '"status":"BLOCKED"}\n'
)


def _load_activation():
    name = "_desire_real_oidc_activation_for_post_create_collector"
    spec = importlib.util.spec_from_file_location(name, _ACTIVATION_HELPER)
    if spec is None or spec.loader is None:
        raise RuntimeError("PRIVATE_SERVER_REAL_OIDC_POST_CREATE_COLLECTOR_INVALID")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_activation = _load_activation()
_preflight = _activation._preflight
_release = _activation._release


class PrivateServerRealOidcPostCreateCollectorError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("PRIVATE_SERVER_REAL_OIDC_POST_CREATE_COLLECTOR_INVALID")


@dataclass(frozen=True, repr=False)
class RealOidcPostCreateCollectionPlan:
    raw: bytes
    sha256: str
    project_name: str
    create_plan_sha256: str
    commands: tuple[tuple[str, ...], ...]

    def __repr__(self) -> str:
        return (
            "RealOidcPostCreateCollectionPlan("
            f"sha256={self.sha256!r}, project_name={self.project_name!r}, "
            "authority='NOT_AUTHORITY', commands=<redacted>)"
        )


@dataclass(frozen=True, repr=False)
class CollectedEvidenceSeal:
    path: Path
    sha256: str
    device: int
    inode: int
    size: int

    def __repr__(self) -> str:
        return (
            "CollectedEvidenceSeal("
            f"path={str(self.path)!r}, sha256={self.sha256!r}, "
            "material=<redacted>)"
        )


class _DuplicateKey(ValueError):
    pass


def _invalid() -> NoReturn:
    raise PrivateServerRealOidcPostCreateCollectorError()


def _pairs(values):
    result = {}
    for key, value in values:
        if not isinstance(key, str) or key in result:
            raise _DuplicateKey()
        result[key] = value
    return result


def _canonical(value: Any) -> bytes:
    try:
        return (
            json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("ascii")
    except BaseException:
        _invalid()


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _closed(value: Any, keys) -> Mapping[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != frozenset(keys):
        _invalid()
    return value


def _json_object(raw: bytes) -> Mapping[str, Any]:
    try:
        if type(raw) is not bytes or not raw or b"\x00" in raw:
            _invalid()
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs,
            parse_float=lambda _value: _invalid(),
            parse_constant=lambda _value: _invalid(),
        )
        if not isinstance(value, dict):
            _invalid()
        return value
    except PrivateServerRealOidcPostCreateCollectorError:
        raise
    except BaseException:
        _invalid()


def _json_lines(raw: bytes, *, keys: tuple[str, ...]) -> tuple[Mapping[str, Any], ...]:
    try:
        if type(raw) is not bytes or b"\x00" in raw:
            _invalid()
        text = raw.decode("utf-8", errors="strict")
        if text and not text.endswith("\n"):
            _invalid()
        rows = []
        for line in text.splitlines():
            if not line or len(line.encode("utf-8")) > 64 * 1024:
                _invalid()
            rows.append(_closed(_json_object(line.encode("utf-8")), keys))
        return tuple(rows)
    except PrivateServerRealOidcPostCreateCollectorError:
        raise
    except BaseException:
        _invalid()


def _purpose_sha256(purpose: str, value: Any) -> str:
    if not isinstance(purpose, str) or not purpose:
        _invalid()
    return _sha(
        _canonical(
            {
                "format": "desire-real-oidc-collected-safe-projection-digest-v1",
                "purpose": purpose,
                "value": value,
            }
        )
    )


def _parse_create_plan(raw: bytes, *, snapshot) -> Mapping[str, Any]:
    try:
        return _activation._validated_create_plan(raw, snapshot=snapshot)
    except BaseException:
        _invalid()


def build_collection_plan(
    *, attempt_root: Path, create_plan_raw: bytes
) -> RealOidcPostCreateCollectionPlan:
    """Build the exact read-only collection plan; do not invoke Docker."""

    try:
        snapshot, _manifest, _compose = _release.load_real_oidc_release_snapshot(
            attempt_root
        )
        create_plan = _parse_create_plan(create_plan_raw, snapshot=snapshot)
        commands = _preflight.post_create_inspect_commands(snapshot)
        document = {
            "format": "desire-real-oidc-post-create-collection-plan-v1",
            "status": "PLANNED_NOT_EXECUTED",
            "authority": "NOT_AUTHORITY",
            "action": "COLLECT_POST_CREATE_INSPECT",
            "project": snapshot.project_name,
            "snapshot": {
                "sha256": snapshot.snapshot_sha256,
                "manifest_device": snapshot.manifest_device,
                "manifest_inode": snapshot.manifest_inode,
                "compose_sha256": snapshot.compose_sha256,
                "oidc_pinned_public_ipv4": snapshot.oidc_pinned_public_ipv4,
                "db_data_ipv4": snapshot.db_data_ipv4,
                "oidc_egress_projection_sha256": (
                    snapshot.oidc_egress_projection_sha256
                ),
            },
            "create_plan_sha256": _sha(create_plan_raw),
            "bound_image_ids": dict(create_plan["image_ids"]),
            "docker": {
                "endpoint": _preflight._DOCKER_ENDPOINT,
                "command_count": len(commands),
                "commands_sha256": _preflight.post_create_inspect_commands_sha256(
                    snapshot
                ),
            },
            "collection_binding_sha256": (
                _preflight.post_create_collection_binding_sha256(
                    snapshot,
                    create_plan_sha256=_sha(create_plan_raw),
                    image_ids=create_plan["image_ids"],
                )
            ),
            "commands": [list(command) for command in commands],
            "expected_inventory": {
                "containers": len(_preflight._SERVICES),
                "distinct_images": 5,
                "networks": 4,
                "volumes": 1,
                "stable_discovery_passes": 2,
            },
            "collection_contract": {
                "runner_invoked": False,
                "shell_allowed": False,
                "retries_allowed": False,
                "raw_inspect_persisted": False,
                "raw_inspect_reflected": False,
                "baseline_projection_validation_required": True,
            },
            "execution": {
                "implemented": False,
                "permitted": False,
                "authority": "NOT_AUTHORITY",
                "docker_mutation_allowed": False,
                "start_allowed": False,
                "execute_blockers": list(_preflight._START_EXECUTE_BLOCKERS),
            },
        }
        raw = _canonical(dict(document))
        return RealOidcPostCreateCollectionPlan(
            raw=raw,
            sha256=_sha(raw),
            project_name=snapshot.project_name,
            create_plan_sha256=_sha(create_plan_raw),
            commands=commands,
        )
    except PrivateServerRealOidcPostCreateCollectorError:
        raise
    except (
        _release.PrivateServerRealOidcReleaseInputError,
        _activation.PrivateServerRealOidcActivationError,
        _preflight.PrivateServerRealOidcPreflightError,
    ):
        _invalid()
    except BaseException:
        _invalid()


def _default_runner(command: Sequence[str], environment: Mapping[str, str]):
    return subprocess.run(
        tuple(command),
        cwd="/",
        env=dict(environment),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )


def _run_observations(
    commands: tuple[tuple[str, ...], ...],
    runner: Callable[[Sequence[str], Mapping[str, str]], Any],
) -> tuple[bytes, ...]:
    try:
        expected_count = len(_preflight._SERVICES) + 16
        if not callable(runner) or len(commands) != expected_count:
            _invalid()
        outputs = []
        inventory_indexes = frozenset(
            (0, 1, 2, expected_count - 3, expected_count - 2, expected_count - 1)
        )
        for index, command in enumerate(commands):
            if tuple(command[:3]) != (
                "/usr/bin/docker",
                "--host",
                _preflight._DOCKER_ENDPOINT,
            ):
                _invalid()
            result = runner(command, _CLOSED_ENVIRONMENT)
            returncode = getattr(result, "returncode", None)
            stdout = getattr(result, "stdout", None)
            stderr = getattr(result, "stderr", None)
            limit = (
                _MAX_INVENTORY_STDOUT
                if index in inventory_indexes
                else _MAX_INSPECT_STDOUT
            )
            if (
                type(returncode) is not int
                or returncode != 0
                or type(stdout) is not bytes
                or not 0 <= len(stdout) <= limit
                or type(stderr) is not bytes
                or stderr != b""
                or b"\x00" in stdout
            ):
                _invalid()
            outputs.append(stdout)
        if len(outputs) != len(commands):
            _invalid()
        return tuple(outputs)
    except PrivateServerRealOidcPostCreateCollectorError:
        raise
    except BaseException:
        _invalid()


def _required_labels(project: str, service: str) -> Mapping[str, str]:
    return {
        "com.docker.compose.project": project,
        "com.docker.compose.service": service,
        "com.docker.compose.oneoff": "False",
        "com.docker.compose.container-number": "1",
    }


def _dependency_label_projection(
    raw: Optional[str], expected: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    if raw is None:
        if expected:
            _invalid()
        return []
    if not isinstance(raw, str):
        _invalid()
    if not raw:
        if expected:
            _invalid()
        return []
    values = []
    for token in raw.split(","):
        parts = token.split(":")
        if len(parts) != 3 or parts[2] not in ("true", "false"):
            _invalid()
        service, condition, restart = parts
        if not service or not condition:
            _invalid()
        values.append(
            {
                "service": service,
                "condition": condition,
                "restart": restart == "true",
            }
        )
    values.sort(key=lambda item: item["service"])
    if len({item["service"] for item in values}) != len(values):
        _invalid()
    if values != list(expected):
        _invalid()
    return values


def _safe_labels(
    raw: Any,
    *,
    project: str,
    service: Optional[str] = None,
    logical: Optional[str] = None,
    expected_service: Optional[Mapping[str, Any]] = None,
    expected_image_id: Optional[str] = None,
    expected_image_labels: Optional[Mapping[str, str]] = None,
) -> Mapping[str, Any]:
    if not isinstance(raw, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in raw.items()
    ):
        _invalid()
    if service is not None:
        if not isinstance(expected_service, Mapping) or not isinstance(
            expected_image_labels, Mapping
        ):
            _invalid()
        if any(key.startswith("com.docker.compose.") for key in expected_image_labels):
            _invalid()
        observed_image_labels = {
            key: value
            for key, value in raw.items()
            if not key.startswith("com.docker.compose.")
        }
        compose_labels = {
            key: value
            for key, value in raw.items()
            if key.startswith("com.docker.compose.")
        }
        if observed_image_labels != dict(expected_image_labels):
            _invalid()
        required = _required_labels(project, service)
        config_hash = compose_labels.get("com.docker.compose.config-hash")
        paths = expected_service["compose_label_paths"]
        expected_path_labels = {
            "com.docker.compose.project.config_files": paths["config_files"],
            "com.docker.compose.project.working_dir": paths["working_dir"],
        }
        expected_non_path_labels = {
            "com.docker.compose.image": expected_image_id,
            "com.docker.compose.version": _preflight._COMPOSE_VERSION,
        }
        allowed = frozenset(required) | frozenset(expected_path_labels) | frozenset(
            expected_non_path_labels
        ) | frozenset(
            (
                "com.docker.compose.config-hash",
                "com.docker.compose.depends_on",
            )
        )
        if (
            frozenset(compose_labels) != allowed
            or _SHA256.fullmatch(config_hash or "") is None
            or any(
                compose_labels.get(key) != value for key, value in required.items()
            )
            or any(
                compose_labels.get(key) != value
                for key, value in expected_path_labels.items()
            )
            or any(
                compose_labels.get(key) != value
                for key, value in expected_non_path_labels.items()
            )
        ):
            _invalid()
        dependencies = _dependency_label_projection(
            compose_labels.get("com.docker.compose.depends_on"),
            expected_service["depends_on"],
        )
        return MappingProxyType(
            {
                "required": dict(required),
                "safe_compose": {
                    "config_hash_shape_valid": True,
                    "image_id": expected_image_id,
                    "compose_version": _preflight._COMPOSE_VERSION,
                    "depends_on": dependencies,
                    "path_labels_match": True,
                    "image_labels_match": True,
                },
            }
        )
    elif logical is not None:
        required = {
            "com.docker.compose.project": project,
            "com.docker.compose.network": logical,
        }
    else:
        required = {
            "com.docker.compose.project": project,
            "com.docker.compose.volume": "postgres-data",
        }
    if any(raw.get(key) != value for key, value in required.items()):
        _invalid()
    if any(not key.startswith("com.docker.compose.") for key in raw):
        _invalid()
    return MappingProxyType(required)


def _created_state(raw: Any, restart_count: Any) -> Mapping[str, Any]:
    state = raw if isinstance(raw, dict) else None
    if state is None:
        _invalid()
    typed_booleans = (
        state.get("Running"),
        state.get("Paused"),
        state.get("Restarting"),
        state.get("OOMKilled"),
        state.get("Dead"),
    )
    if (
        not isinstance(state.get("Status"), str)
        or any(type(value) is not bool for value in typed_booleans)
        or type(state.get("Pid")) is not int
        or type(state.get("ExitCode")) is not int
        or type(restart_count) is not int
        or not isinstance(state.get("Error"), str)
    ):
        _invalid()
    expected = {
        "status": state.get("Status"),
        "running": state.get("Running"),
        "paused": state.get("Paused"),
        "restarting": state.get("Restarting"),
        "oom_killed": state.get("OOMKilled"),
        "dead": state.get("Dead"),
        "pid": state.get("Pid"),
        "exit_code": state.get("ExitCode"),
        "error_empty": state.get("Error") == "",
        "restart_count": restart_count,
    }
    if expected != {
        "status": "created",
        "running": False,
        "paused": False,
        "restarting": False,
        "oom_killed": False,
        "dead": False,
        "pid": 0,
        "exit_code": 0,
        "error_empty": True,
        "restart_count": 0,
    }:
        _invalid()
    started = state.get("StartedAt")
    finished = state.get("FinishedAt")
    if (
        not isinstance(started, str)
        or _ZERO_DOCKER_TIME.fullmatch(started) is None
        or not isinstance(finished, str)
        or _ZERO_DOCKER_TIME.fullmatch(finished) is None
    ):
        _invalid()
    return MappingProxyType(expected)


def _volume_mountpoint(
    raw: Mapping[str, Any], *, expected_name: str
) -> str:
    mountpoint = raw.get("Mountpoint")
    if (
        raw.get("Name") != expected_name
        or raw.get("Driver") != "local"
        or raw.get("Scope") != "local"
        or not isinstance(mountpoint, str)
        or not mountpoint.startswith("/")
        or mountpoint == "/"
        or "\x00" in mountpoint
        or posixpath.normpath(mountpoint) != mountpoint
    ):
        _invalid()
    return mountpoint


def _safe_mounts(
    raw: Any,
    expected: Sequence[Mapping[str, Any]],
    *,
    volume_mountpoint: str,
) -> list[dict]:
    if not isinstance(raw, list) or len(raw) != len(expected):
        _invalid()
    by_destination = {}
    for item in raw:
        if not isinstance(item, dict):
            _invalid()
        destination = item.get("Destination")
        if not isinstance(destination, str) or destination in by_destination:
            _invalid()
        by_destination[destination] = item
    safe = []
    for value in expected:
        item = by_destination.get(value["destination"])
        if item is None or item.get("Type") != value["type"]:
            _invalid()
        if value["type"] == "bind":
            source = item.get("Source")
            if (
                frozenset(item)
                != frozenset(
                    ("Type", "Source", "Destination", "Mode", "RW", "Propagation")
                )
                or source != value["raw_source"]
                or source in ("/var/run/docker.sock", "/run/docker.sock")
                or item.get("Mode") != ""
                or item.get("RW") is not False
                or item.get("Propagation") != "rprivate"
            ):
                _invalid()
        else:
            if (
                frozenset(item)
                != frozenset(
                    (
                        "Type",
                        "Name",
                        "Source",
                        "Destination",
                        "Driver",
                        "Mode",
                        "RW",
                        "Propagation",
                    )
                )
                or item.get("Name") != value["raw_source"]
                or item.get("Source") != volume_mountpoint
                or item.get("Driver") != "local"
                or item.get("Mode") != "rw"
                or item.get("RW") is not True
                or item.get("Propagation") != ""
            ):
                _invalid()
        safe.append(
            {
                "type": value["type"],
                "destination": value["destination"],
                "read_only": value["read_only"],
                "source_kind": value["source_kind"],
                "source_name": value["source_name"],
            }
        )
    return safe


def _safe_host_config_mounts(
    host: Mapping[str, Any], expected: Sequence[Mapping[str, Any]]
) -> int:
    expected_binds = [value for value in expected if value["type"] == "bind"]
    if not expected_binds:
        # mount.Mount is omitempty in the current API model.
        if "Mounts" in host:
            _invalid()
        return 0
    raw = host.get("Mounts")
    if not isinstance(raw, list) or len(raw) != len(expected_binds):
        _invalid()
    by_target = {}
    for item in raw:
        if not isinstance(item, dict):
            _invalid()
        target = item.get("Target")
        if not isinstance(target, str) or target in by_target:
            _invalid()
        by_target[target] = item
    for value in expected_binds:
        expected_item = {
            "Type": "bind",
            "Source": value["raw_source"],
            "Target": value["destination"],
            "ReadOnly": True,
        }
        if value["host_config_bind_options_present"]:
            expected_item["BindOptions"] = {}
        if by_target.get(value["destination"]) != expected_item:
            _invalid()
    return len(expected_binds)


def _safe_host_config_binds(
    host: Mapping[str, Any], expected: Sequence[Mapping[str, Any]]
) -> int:
    if "Binds" not in host:
        _invalid()
    expected_volumes = [value for value in expected if value["type"] == "volume"]
    if not expected_volumes:
        if host["Binds"] is not None:
            _invalid()
        return 0
    if len(expected_volumes) != 1 or expected_volumes[0]["read_only"]:
        _invalid()
    volume = expected_volumes[0]
    expected_bind = (
        f"{volume['raw_source']}:{volume['destination']}:rw"
    )
    if host["Binds"] != [expected_bind]:
        _invalid()
    return 1


def _sort_port_keys(values: Sequence[str]) -> list[str]:
    return sorted(
        values,
        key=lambda value: (
            int(value.split("/", 1)[0]),
            value.split("/", 1)[1],
        ),
    )


def _safe_config_ports(raw: Any) -> list[str]:
    values = {} if raw is None else raw
    if not isinstance(values, dict):
        _invalid()
    normalized = []
    for key, value in values.items():
        match = _EXPOSED_PORT.fullmatch(key) if isinstance(key, str) else None
        if (
            match is None
            or int(match.group("port")) > 65535
            or not isinstance(value, dict)
            or value
        ):
            _invalid()
        normalized.append(key)
    if len(normalized) != len(set(normalized)):
        _invalid()
    return _sort_port_keys(normalized)


def _safe_config_volume_targets(raw: Any) -> list[str]:
    values = {} if raw is None else raw
    if not isinstance(values, dict):
        _invalid()
    normalized = []
    for target, value in values.items():
        if (
            not isinstance(target, str)
            or not target.startswith("/")
            or target == "/"
            or "\x00" in target
            or posixpath.normpath(target) != target
            or not isinstance(value, dict)
            or value
        ):
            _invalid()
        normalized.append(target)
    if len(normalized) != len(set(normalized)):
        _invalid()
    return sorted(normalized)


def _safe_created_ports(raw: Any) -> None:
    # Current Moby intentionally renders an allocated empty PortMap for a
    # never-started container.  Effective exposure remains in Config; runtime
    # port-map entries are populated only while connecting/starting.
    if raw != {}:
        _invalid()


def _safe_tmpfs(raw: Any, expected: Sequence[Mapping[str, Any]]) -> list[dict]:
    values = {} if raw is None else raw
    if not isinstance(values, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in values.items()
    ):
        _invalid()
    expected_map = {item["destination"]: item["options"] for item in expected}
    if values != expected_map:
        _invalid()
    return [dict(item) for item in expected]


def _safe_ports(raw: Any, expected: Sequence[Mapping[str, Any]]) -> list[dict]:
    bindings = {} if raw is None else raw
    if not isinstance(bindings, dict):
        _invalid()
    expected_keys = {
        f"{item['container_port']}/{item['protocol']}" for item in expected
    }
    if frozenset(bindings) != expected_keys:
        _invalid()
    normalized = []
    for key, values in bindings.items():
        if (
            not isinstance(key, str)
            or "/" not in key
            or not isinstance(values, list)
            or not values
        ):
            _invalid()
        container_text, protocol = key.split("/", 1)
        try:
            container_port = int(container_text)
        except ValueError:
            _invalid()
        for item in values:
            if not isinstance(item, dict):
                _invalid()
            host_ip = item.get("HostIp")
            host_port = item.get("HostPort")
            if not isinstance(host_ip, str) or not isinstance(host_port, str):
                _invalid()
            normalized.append(
                {
                    "container_port": container_port,
                    "protocol": protocol,
                    "host_ip": host_ip,
                    "host_port": host_port,
                }
            )
    normalized.sort(
        key=lambda value: (
            value["container_port"],
            value["protocol"],
            value["host_ip"],
            value["host_port"],
        )
    )
    if len({_canonical(value) for value in normalized}) != len(normalized):
        _invalid()
    if normalized != list(expected):
        _invalid()
    return normalized


def _safe_desired_network_config(
    raw: Any,
    *,
    expected: Mapping[str, Any],
) -> Mapping[str, Any]:
    values = raw if isinstance(raw, dict) else None
    if values is None:
        _invalid()
    expected_physical = {
        item["network_name"]: (logical, item)
        for logical, item in expected.items()
    }
    if frozenset(values) != frozenset(expected_physical):
        _invalid()
    projected = {}
    for physical, item in values.items():
        if not isinstance(item, dict):
            _invalid()
        logical, expected_item = expected_physical[physical]
        aliases = item.get("Aliases")
        if not isinstance(aliases, list) or any(
            not isinstance(value, str) or not value for value in aliases
        ):
            _invalid()
        if len(set(aliases)) != len(aliases):
            _invalid()
        # Before start this is desired endpoint configuration, not a libnetwork
        # endpoint. If DNSNames is rendered, it may only repeat desired aliases;
        # accepting a container-ID addition would fabricate runtime membership.
        dns_names = item.get("DNSNames")
        if dns_names is not None:
            if not isinstance(dns_names, list) or any(
                not isinstance(value, str) or not value for value in dns_names
            ):
                _invalid()
            if len(set(dns_names)) != len(dns_names):
                _invalid()
            if sorted(dns_names) != expected_item["aliases"]:
                _invalid()
        if sorted(aliases) != expected_item["aliases"]:
            _invalid()
        if "NetworkID" not in item or item["NetworkID"] != "":
            _invalid()
        if "IPAMConfig" not in item:
            _invalid()
        ipam = item["IPAMConfig"]
        if expected_item["ipam_config_present"] is False and ipam is None:
            requested = None
        elif expected_item["ipam_config_present"] is True and isinstance(
            ipam, dict
        ):
            if frozenset(ipam) != frozenset(("IPv4Address", "IPv6Address")):
                _invalid()
            expected_ipv4 = expected_item["requested_ipv4"] or ""
            if (
                ipam["IPv4Address"] != expected_ipv4
                or ipam["IPv6Address"] != ""
            ):
                _invalid()
            requested = expected_item["requested_ipv4"]
        else:
            _invalid()
        if requested != expected_item["requested_ipv4"]:
            _invalid()
        projected[logical] = {
            "requested_ipv4": requested,
            "ipam_config_present": expected_item["ipam_config_present"],
            "aliases": list(expected_item["aliases"]),
            "runtime_network_id_unassigned": True,
        }
    return MappingProxyType(projected)


def _environment_map(
    raw: Any, *, allow_absent: bool = False
) -> Mapping[str, str]:
    if raw is None and allow_absent:
        return MappingProxyType({})
    if not isinstance(raw, list):
        _invalid()
    result = {}
    for value in raw:
        if (
            not isinstance(value, str)
            or "\x00" in value
            or "=" not in value
        ):
            _invalid()
        key, item = value.split("=", 1)
        if (
            _ENVIRONMENT_KEY.fullmatch(key) is None
            or key in result
            or key.casefold() in _PROXY_ENVIRONMENT_KEYS
        ):
            _invalid()
        result[key] = item
    return MappingProxyType(result)


def _healthcheck_config(raw: Any, *, present: bool) -> Optional[Mapping[str, Any]]:
    if not present:
        return None
    if not isinstance(raw, dict) or not set(raw).issubset(_HEALTHCHECK_FIELDS):
        _invalid()
    test = raw.get("Test", [])
    if "Test" in raw and (
        not isinstance(test, list)
        or not test
        or test[0] not in ("NONE", "CMD", "CMD-SHELL")
        or (test[0] == "NONE" and len(test) != 1)
        or (test[0] == "CMD" and len(test) < 2)
        or (test[0] == "CMD-SHELL" and len(test) != 2)
        or any(
            not isinstance(part, str) or not part or "\x00" in part
            for part in test
        )
    ):
        _invalid()
    result = {"Test": list(test)}
    for field in ("Interval", "Timeout", "StartPeriod", "StartInterval"):
        item = raw.get(field, 0)
        if (
            type(item) is not int
            or item < 0
            or (field in raw and item < 1_000_000)
        ):
            _invalid()
        result[field] = item
    retries = raw.get("Retries", 0)
    if type(retries) is not int or retries < 0 or ("Retries" in raw and retries == 0):
        _invalid()
    result["Retries"] = retries
    return MappingProxyType(result)


def _healthcheck_field_presence(
    value: Optional[Mapping[str, Any]],
) -> Mapping[str, bool]:
    return MappingProxyType(
        {
            field: bool(value is not None and value[field])
            for field in _HEALTHCHECK_FIELDS
        }
    )


def _effective_environment(
    compose_environment: Mapping[str, str],
    image_environment: Mapping[str, str],
) -> tuple[Mapping[str, str], Mapping[str, Any]]:
    effective = dict(image_environment)
    effective.update(compose_environment)
    override_count = len(set(compose_environment).intersection(image_environment))
    inherited_count = len(image_environment) - override_count
    if not compose_environment:
        source = "IMAGE_INHERITED" if image_environment else "EMPTY"
    elif inherited_count:
        source = "COMPOSE_WITH_IMAGE_DEFAULTS"
    else:
        source = "COMPOSE_EXPLICIT"
    return (
        MappingProxyType(effective),
        MappingProxyType(
            {
                "source": source,
                "image_entry_count": len(image_environment),
                "compose_entry_count": len(compose_environment),
                "compose_override_count": override_count,
                "inherited_image_entry_count": inherited_count,
                "effective_entry_count": len(effective),
                "exact_map_match": True,
                "proxy_keys_absent": True,
            }
        ),
    )


def _effective_healthcheck(
    compose_healthcheck: Optional[Mapping[str, Any]],
    image_healthcheck: Optional[Mapping[str, Any]],
) -> tuple[Optional[Mapping[str, Any]], Mapping[str, Any]]:
    field_sources = {}
    if compose_healthcheck is None and image_healthcheck is None:
        effective = None
    else:
        effective_value = {}
        for field in _HEALTHCHECK_FIELDS:
            compose_value = (
                compose_healthcheck[field]
                if compose_healthcheck is not None
                else [] if field == "Test" else 0
            )
            image_value = (
                image_healthcheck[field]
                if image_healthcheck is not None
                else [] if field == "Test" else 0
            )
            if compose_value:
                effective_value[field] = (
                    list(compose_value) if field == "Test" else compose_value
                )
                field_sources[field] = "COMPOSE_EXPLICIT"
            elif image_value:
                effective_value[field] = (
                    list(image_value) if field == "Test" else image_value
                )
                field_sources[field] = "IMAGE_INHERITED"
            else:
                effective_value[field] = [] if field == "Test" else 0
                field_sources[field] = "UNSET_ZERO"
        effective = MappingProxyType(effective_value)
    if effective is None:
        source = "ABSENT"
        field_sources = {field: "ABSENT" for field in _HEALTHCHECK_FIELDS}
    elif compose_healthcheck is None:
        source = "IMAGE_INHERITED"
    elif any(value == "IMAGE_INHERITED" for value in field_sources.values()):
        source = "COMPOSE_WITH_IMAGE_DEFAULTS"
    else:
        source = "COMPOSE_EXPLICIT"
    return (
        effective,
        MappingProxyType(
            {
                "source": source,
                "field_sources": MappingProxyType(dict(field_sources)),
                "matches_effective": True,
                "unknown_fields_absent": True,
            }
        ),
    )


def _process_sequence(raw: Any) -> Optional[list[str]]:
    if raw is None:
        return None
    if (
        not isinstance(raw, list)
        or not raw
        or any(not isinstance(value, str) or not value or "\x00" in value for value in raw)
    ):
        _invalid()
    return list(raw)


def _security_sequence(raw: Any) -> list[str]:
    if raw is None:
        return []
    if (
        not isinstance(raw, list)
        or any(not isinstance(value, str) or not value for value in raw)
        or len(raw) != len(set(raw))
    ):
        _invalid()
    return sorted(raw)


def _security_options(raw: Any) -> list[str]:
    values = []
    for value in _security_sequence(raw):
        if value == "no-new-privileges=true":
            value = "no-new-privileges:true"
        values.append(value)
    return sorted(values)


def _image_process_defaults(raw: Mapping[str, Any]) -> Mapping[str, Any]:
    config = raw.get("Config")
    if not isinstance(config, dict):
        _invalid()
    user = config.get("User")
    working_dir = config.get("WorkingDir", "")
    stop_signal = config.get("StopSignal", "")
    labels = config.get("Labels")
    if labels is None:
        labels = {}
    if (
        not isinstance(user, str)
        or "\x00" in user
        or not isinstance(working_dir, str)
        or "\x00" in working_dir
        or (working_dir and not working_dir.startswith("/"))
        or not isinstance(stop_signal, str)
        or "\x00" in stop_signal
    ):
        _invalid()
    if (
        not isinstance(labels, dict)
        or any(
            not isinstance(key, str)
            or not isinstance(value, str)
            or key.startswith("com.docker.compose.")
            for key, value in labels.items()
        )
    ):
        _invalid()
    # StopTimeout is a create-time container option, not an image default;
    # current image inspect omits it and Moby's image merge never inherits it.
    if "StopTimeout" in config:
        _invalid()
    environment = _environment_map(config.get("Env"), allow_absent=True)
    healthcheck = _healthcheck_config(
        config.get("Healthcheck"), present="Healthcheck" in config
    )
    return MappingProxyType(
        {
            "cmd": _process_sequence(config.get("Cmd")),
            "entrypoint": _process_sequence(config.get("Entrypoint")),
            "user": user,
            "working_dir": working_dir,
            "stop_signal": stop_signal,
            "labels": MappingProxyType(dict(labels)),
            "environment": environment,
            "healthcheck": healthcheck,
            "exposed_ports": _safe_config_ports(config.get("ExposedPorts")),
            "volume_targets": _safe_config_volume_targets(config.get("Volumes")),
        }
    )


def _effective_process(
    expected: Mapping[str, Any], image_defaults: Mapping[str, Any]
) -> Mapping[str, Any]:
    command_override = expected["command_override"]
    entrypoint_override = expected["entrypoint_override"]
    user_override = expected["user_override"]
    working_dir_override = expected["working_dir_override"]
    stop_signal_override = expected["stop_signal_override"]
    return MappingProxyType(
        {
            "cmd": (
                list(command_override)
                if command_override is not None
                else image_defaults["cmd"]
            ),
            "entrypoint": (
                list(entrypoint_override)
                if entrypoint_override is not None
                else image_defaults["entrypoint"]
            ),
            "user": user_override if user_override is not None else image_defaults["user"],
            "working_dir": (
                working_dir_override
                if working_dir_override is not None
                else image_defaults["working_dir"]
            ),
            "stop_signal": (
                stop_signal_override
                if stop_signal_override is not None
                else image_defaults["stop_signal"]
            ),
            "cmd_source": "COMPOSE_EXPLICIT" if command_override is not None else "IMAGE_INHERITED",
            "entrypoint_source": (
                "COMPOSE_EXPLICIT"
                if entrypoint_override is not None
                else "IMAGE_INHERITED"
            ),
            "user_source": "COMPOSE_EXPLICIT" if user_override is not None else "IMAGE_INHERITED",
            "working_dir_source": (
                "COMPOSE_EXPLICIT"
                if working_dir_override is not None
                else "IMAGE_INHERITED"
            ),
            "stop_signal_source": (
                "COMPOSE_EXPLICIT"
                if stop_signal_override is not None
                else "IMAGE_INHERITED"
            ),
        }
    )


def _container_projection(
    *,
    service: str,
    raw: Mapping[str, Any],
    expected: Mapping[str, Any],
    project: str,
    image_ids: Mapping[str, str],
    container_ids: Mapping[str, str],
    volume_mountpoint: str,
    image_process_defaults: Mapping[str, Mapping[str, Any]],
) -> Mapping[str, Any]:
    identifier = raw.get("Id")
    if (
        _CONTAINER_ID.fullmatch(identifier or "") is None
        or identifier != container_ids[service]
        or raw.get("Name") != "/" + expected["name"]
        or raw.get("Image") != image_ids[expected["image_reference"]]
    ):
        _invalid()
    config = raw.get("Config")
    host = raw.get("HostConfig")
    network_settings = raw.get("NetworkSettings")
    if not isinstance(config, dict) or not isinstance(host, dict) or not isinstance(network_settings, dict):
        _invalid()
    if config.get("Image") != expected["image_reference"]:
        _invalid()
    image_defaults = image_process_defaults[expected["image_reference"]]
    label_projection = _safe_labels(
        config.get("Labels"),
        project=project,
        service=service,
        expected_service=expected,
        expected_image_id=image_ids[expected["image_reference"]],
        expected_image_labels=image_defaults["labels"],
    )
    process = _effective_process(expected, image_defaults)
    if (
        config.get("Cmd") != process["cmd"]
        or config.get("Entrypoint") != process["entrypoint"]
        or config.get("User") != process["user"]
        or config.get("WorkingDir", "") != process["working_dir"]
        or config.get("StopSignal", "") != process["stop_signal"]
    ):
        _invalid()
    effective_environment, environment_projection = _effective_environment(
        expected["environment"], image_defaults["environment"]
    )
    container_environment = _environment_map(config.get("Env"))
    if dict(container_environment) != dict(effective_environment):
        _invalid()
    effective_healthcheck, healthcheck_projection = _effective_healthcheck(
        expected["healthcheck_override"], image_defaults["healthcheck"]
    )
    container_healthcheck = _healthcheck_config(
        config.get("Healthcheck"), present="Healthcheck" in config
    )
    if (
        (container_healthcheck is None) != (effective_healthcheck is None)
        or container_healthcheck is not None
        and dict(container_healthcheck) != dict(effective_healthcheck)
    ):
        _invalid()
    stop_timeout_seconds = expected["stop_timeout_seconds"]
    if stop_timeout_seconds is None:
        if "StopTimeout" in config:
            _invalid()
        stop_timeout_projection = {
            "present": False,
            "source": "ABSENT",
            "matches_effective": True,
        }
    else:
        if (
            "StopTimeout" not in config
            or type(config["StopTimeout"]) is not int
            or config["StopTimeout"] != stop_timeout_seconds
        ):
            _invalid()
        stop_timeout_projection = {
            "present": True,
            "source": "COMPOSE_EXPLICIT",
            "matches_effective": True,
        }
    published_port_keys = {
        f"{item['container_port']}/{item['protocol']}"
        for item in expected["ports"]
    }
    effective_exposed_ports = _sort_port_keys(
        set(image_defaults["exposed_ports"]) | published_port_keys
    )
    if _safe_config_ports(config.get("ExposedPorts")) != effective_exposed_ports:
        _invalid()
    image_volume_targets = image_defaults["volume_targets"]
    if _safe_config_volume_targets(config.get("Volumes")) != image_volume_targets:
        _invalid()
    explicit_mount_targets = {
        value["destination"] for value in expected["mounts"]
    } | {value["destination"] for value in expected["tmpfs"]}
    if len(explicit_mount_targets) != len(expected["mounts"]) + len(
        expected["tmpfs"]
    ) or not set(image_volume_targets).issubset(explicit_mount_targets):
        _invalid()
    state = _created_state(raw.get("State"), raw.get("RestartCount"))
    expected_network_mode = expected["network_mode"]
    if service == "api":
        expected_network_mode = expected_network_mode.format(
            guard_container_id=container_ids["oidc-egress-guard"]
        )
    if host.get("NetworkMode") != expected_network_mode:
        _invalid()
    if (
        host.get("Privileged") is not False
        or host.get("AutoRemove") is not False
        or host.get("PublishAllPorts") is not False
        or host.get("ReadonlyRootfs") is not expected["read_only_rootfs"]
        or host.get("Devices") not in (None, [])
        or host.get("DeviceRequests") not in (None, [])
        or host.get("GroupAdd") not in (None, [])
        or host.get("PidMode") not in ("", "private")
        or host.get("IpcMode") not in ("", "private")
        or host.get("UTSMode") not in ("", "private")
        or host.get("UsernsMode") != ""
    ):
        _invalid()
    cap_add = _security_sequence(host.get("CapAdd"))
    cap_drop = _security_sequence(host.get("CapDrop"))
    security_opt = _security_options(host.get("SecurityOpt"))
    expected_security_opt = _security_options(expected["security_opt"])
    restart_policy = host.get("RestartPolicy")
    sysctls = host.get("Sysctls")
    if sysctls is None:
        sysctls = {}
    extra_hosts = host.get("ExtraHosts")
    normalized_extra_hosts = _security_sequence(extra_hosts)
    expected_extra_hosts = sorted(expected["api_extra_hosts"] or [])
    if (
        cap_add != expected["cap_add"]
        or cap_drop != expected["cap_drop"]
        or security_opt != expected_security_opt
        or not isinstance(restart_policy, dict)
        or frozenset(restart_policy) != frozenset(("Name", "MaximumRetryCount"))
        or restart_policy.get("Name") != expected["restart"]
        or type(restart_policy.get("MaximumRetryCount")) is not int
        or restart_policy.get("MaximumRetryCount") != 0
        or not isinstance(sysctls, dict)
        or sysctls != expected["sysctls"]
        or host.get("Init") is not expected["init"]
        or normalized_extra_hosts != expected_extra_hosts
    ):
        _invalid()
    mounts = _safe_mounts(
        raw.get("Mounts"),
        expected["mounts"],
        volume_mountpoint=volume_mountpoint,
    )
    host_config_mount_count = _safe_host_config_mounts(host, expected["mounts"])
    host_config_bind_count = _safe_host_config_binds(host, expected["mounts"])
    tmpfs = _safe_tmpfs(host.get("Tmpfs"), expected["tmpfs"])
    ports = _safe_ports(host.get("PortBindings"), expected["ports"])
    api_extra_hosts_sha256 = None
    if service == "api":
        api_extra_hosts_sha256 = _purpose_sha256(
            "api-reviewed-db-extra-hosts", expected["api_extra_hosts"]
        )
    _safe_created_ports(network_settings.get("Ports"))
    desired_network_config = _safe_desired_network_config(
        network_settings.get("Networks"),
        expected=expected["desired_network_config"],
    )
    if service == "api" and desired_network_config != {}:
        _invalid()
    return MappingProxyType(
        {
            "id": identifier,
            "name": expected["name"],
            "image_reference": expected["image_reference"],
            "image_id": image_ids[expected["image_reference"]],
            "state": dict(state),
            "required_labels": dict(label_projection["required"]),
            "compose_label_projection": dict(label_projection["safe_compose"]),
            "mounts": mounts,
            "tmpfs": tmpfs,
            "mount_transport": {
                "top_mount_count": len(mounts),
                "top_mounts_match": True,
                "host_config_mount_count": host_config_mount_count,
                "host_config_mounts_match": True,
                "host_config_bind_count": host_config_bind_count,
                "host_config_binds_match": True,
                "named_volume_mountpoint_match_count": host_config_bind_count,
            },
            "network_mode": expected_network_mode,
            "desired_network_config": dict(desired_network_config),
            "port_bindings": ports,
            "runtime_metadata": {
                "effective_exposed_ports": effective_exposed_ports,
                "effective_exposed_port_count": len(effective_exposed_ports),
                "published_port_count": len(expected["ports"]),
                "image_volume_target_count": len(image_volume_targets),
                "image_volume_targets_explicitly_mounted": True,
                "container_exposed_ports_match": True,
                "container_volumes_match": True,
                "created_port_map_empty": True,
            },
            "security": {
                "privileged": False,
                "auto_remove": False,
                "publish_all_ports": False,
                "read_only_rootfs": expected["read_only_rootfs"],
                "devices": [],
                "device_requests": [],
                "supplementary_groups": [],
                "private_pid_mode": True,
                "private_ipc_mode": True,
                "private_uts_mode": True,
                "default_userns_mode": True,
                "api_extra_hosts_sha256": api_extra_hosts_sha256,
                "environment": dict(environment_projection),
                "healthcheck": {
                    **dict(healthcheck_projection),
                    "field_sources": dict(
                        healthcheck_projection["field_sources"]
                    ),
                },
                "stop_timeout": stop_timeout_projection,
                "process": {
                    "cmd_source": process["cmd_source"],
                    "entrypoint_source": process["entrypoint_source"],
                    "user_source": process["user_source"],
                    "working_dir_source": process["working_dir_source"],
                    "stop_signal_source": process["stop_signal_source"],
                    "cmd_matches_effective": True,
                    "entrypoint_matches_effective": True,
                    "user_matches_effective": True,
                    "working_dir_matches_effective": True,
                    "stop_signal_matches_effective": True,
                },
                "cap_add": cap_add,
                "cap_drop": cap_drop,
                "security_opt": security_opt,
                "restart_policy": dict(restart_policy),
                "sysctls": dict(sysctls),
                "init": expected["init"],
                "extra_hosts_match": True,
                "postgres_entrypoint_capability_exception": service == "db",
            },
        }
    )


def _network_projection(
    *,
    logical: str,
    raw: Mapping[str, Any],
    expected: Mapping[str, Any],
    project: str,
) -> Mapping[str, Any]:
    identifier = raw.get("Id")
    if (
        _CONTAINER_ID.fullmatch(identifier or "") is None
        or raw.get("Name") != expected["name"]
        or raw.get("Driver") != "bridge"
        or raw.get("Scope") != "local"
        or raw.get("Internal") is not expected["internal"]
        or raw.get("EnableIPv6") is not False
    ):
        _invalid()
    required_labels = _safe_labels(
        raw.get("Labels"), project=project, logical=logical
    )
    ipam = raw.get("IPAM")
    config = ipam.get("Config") if isinstance(ipam, dict) else None
    if not isinstance(config, list) or len(config) != 1 or not isinstance(config[0], dict):
        _invalid()
    if config[0].get("Subnet") != expected["subnet"]:
        _invalid()
    consumers = raw.get("Containers")
    if consumers != {}:
        _invalid()
    return MappingProxyType(
        {
            "id": identifier,
            "name": expected["name"],
            "driver": "bridge",
            "scope": "local",
            "internal": expected["internal"],
            "enable_ipv6": False,
            "subnet": expected["subnet"],
            "required_labels": dict(required_labels),
            "containers_empty": True,
        }
    )


def _volume_projection(
    raw: Mapping[str, Any], *, project: str, expected_name: str
) -> Mapping[str, Any]:
    _volume_mountpoint(raw, expected_name=expected_name)
    required_labels = _safe_labels(
        raw.get("Labels"), project=project
    )
    options = raw.get("Options")
    if options is None:
        options = {}
    if not isinstance(options, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in options.items()
    ):
        _invalid()
    if options != {}:
        _invalid()
    return MappingProxyType(
        {
            "name": expected_name,
            "driver": "local",
            "scope": "local",
            "required_labels": dict(required_labels),
        }
    )


def _inventory(
    raw: bytes, *, kind: str
) -> tuple[Mapping[str, Any], ...]:
    if kind == "container":
        return _json_lines(raw, keys=("Id", "Name"))
    if kind == "network":
        return _json_lines(raw, keys=("Id", "Name"))
    if kind == "volume":
        return _json_lines(raw, keys=("Name",))
    _invalid()


def _inventory_identity(rows: Sequence[Mapping[str, Any]], *, kind: str):
    if kind in ("container", "network"):
        result = []
        for row in rows:
            identifier = row.get("Id")
            name = row.get("Name")
            if (
                _CONTAINER_ID.fullmatch(identifier or "") is None
                or not isinstance(name, str)
                or not name
            ):
                _invalid()
            result.append((identifier, name))
        if len(set(result)) != len(result):
            _invalid()
        return tuple(sorted(result))
    if kind == "volume":
        names = []
        for row in rows:
            name = row.get("Name")
            if not isinstance(name, str) or not name:
                _invalid()
            names.append(name)
        if len(set(names)) != len(names):
            _invalid()
        return tuple(sorted(names))
    _invalid()


def _project_observations(
    *,
    snapshot,
    create_plan: Mapping[str, Any],
    outputs: tuple[bytes, ...],
) -> Mapping[str, Any]:
    try:
        service_count = len(_preflight._SERVICES)
        resource_count = len(_preflight.fresh_resource_names(snapshot.project_name))
        image_count = len(snapshot.image_references)
        container_start = 3
        network_start = container_start + service_count
        volume_index = network_start + resource_count
        image_start = volume_index + 1
        second_inventory_start = image_start + image_count
        expected_count = second_inventory_start + 3
        if len(outputs) != expected_count:
            _invalid()
        first_container_inventory = _inventory(outputs[0], kind="container")
        first_network_inventory = _inventory(outputs[1], kind="network")
        first_volume_inventory = _inventory(outputs[2], kind="volume")
        second_container_inventory = _inventory(
            outputs[second_inventory_start], kind="container"
        )
        second_network_inventory = _inventory(
            outputs[second_inventory_start + 1], kind="network"
        )
        second_volume_inventory = _inventory(
            outputs[second_inventory_start + 2], kind="volume"
        )
        for first, second, kind in (
            (first_container_inventory, second_container_inventory, "container"),
            (first_network_inventory, second_network_inventory, "network"),
            (first_volume_inventory, second_volume_inventory, "volume"),
        ):
            if _inventory_identity(first, kind=kind) != _inventory_identity(
                second, kind=kind
            ):
                _invalid()

        contract = _preflight._post_create_compose_contract(snapshot)
        service_names = _preflight.fresh_container_names(snapshot.project_name)
        resource_names = _preflight.fresh_resource_names(snapshot.project_name)
        volume_name = contract["volume_name"]

        raw_containers = {
            service: _json_object(outputs[container_start + index])
            for index, service in enumerate(_preflight._SERVICES)
        }
        raw_networks = {
            logical: _json_object(outputs[network_start + index])
            for index, logical in enumerate(resource_names)
        }
        raw_volume = _json_object(outputs[volume_index])
        volume_mountpoint = _volume_mountpoint(
            raw_volume, expected_name=volume_name
        )
        raw_images = {
            reference: _json_object(outputs[image_start + index])
            for index, reference in enumerate(snapshot.image_references)
        }

        container_ids = {}
        for service, raw in raw_containers.items():
            identifier = raw.get("Id")
            if (
                _CONTAINER_ID.fullmatch(identifier or "") is None
                or raw.get("Name") != "/" + service_names[service]
            ):
                _invalid()
            container_ids[service] = identifier
        if len(set(container_ids.values())) != service_count:
            _invalid()

        network_ids = {}
        for logical, raw in raw_networks.items():
            identifier = raw.get("Id")
            if (
                _CONTAINER_ID.fullmatch(identifier or "") is None
                or raw.get("Name") != resource_names[logical]
            ):
                _invalid()
            network_ids[logical] = identifier
        if len(set(network_ids.values())) != 4:
            _invalid()

        image_ids = create_plan["image_ids"]
        if len(set(image_ids.values())) != 5:
            _invalid()
        for reference, raw in raw_images.items():
            if raw.get("Id") != image_ids[reference]:
                _invalid()
        image_process_defaults = {
            reference: _image_process_defaults(raw)
            for reference, raw in raw_images.items()
        }
        image_runtime_metadata = {
            reference: {
                "exposed_ports": defaults["exposed_ports"],
                "exposed_port_count": len(defaults["exposed_ports"]),
                "volume_target_count": len(defaults["volume_targets"]),
                "environment_entry_count": len(defaults["environment"]),
                "healthcheck_present": defaults["healthcheck"] is not None,
                "healthcheck_field_presence": dict(
                    _healthcheck_field_presence(defaults["healthcheck"])
                ),
            }
            for reference, defaults in image_process_defaults.items()
        }
        reviewed_image_runtime_metadata = contract[
            "reviewed_image_runtime_metadata"
        ]
        if image_runtime_metadata != {
            reference: {
                "exposed_ports": value["exposed_ports"],
                "exposed_port_count": len(value["exposed_ports"]),
                "volume_target_count": len(value["volume_targets"]),
                "environment_entry_count": image_runtime_metadata[reference][
                    "environment_entry_count"
                ],
                "healthcheck_present": image_runtime_metadata[reference][
                    "healthcheck_present"
                ],
                "healthcheck_field_presence": image_runtime_metadata[reference][
                    "healthcheck_field_presence"
                ],
            }
            for reference, value in reviewed_image_runtime_metadata.items()
        } or any(
            image_process_defaults[reference]["volume_targets"]
            != value["volume_targets"]
            for reference, value in reviewed_image_runtime_metadata.items()
        ):
            _invalid()

        expected_container_inventory = tuple(
            sorted(
                (container_ids[service], service_names[service])
                for service in _preflight._SERVICES
            )
        )
        expected_network_inventory = tuple(
            sorted(
                (network_ids[logical], resource_names[logical])
                for logical in resource_names
            )
        )
        if (
            _inventory_identity(first_container_inventory, kind="container")
            != expected_container_inventory
            or _inventory_identity(first_network_inventory, kind="network")
            != expected_network_inventory
            or _inventory_identity(first_volume_inventory, kind="volume")
            != (volume_name,)
        ):
            _invalid()

        networks = {
            logical: _network_projection(
                logical=logical,
                raw=raw_networks[logical],
                expected=contract["networks"][logical],
                project=snapshot.project_name,
            )
            for logical in resource_names
        }
        if any(networks[logical]["id"] != network_ids[logical] for logical in networks):
            _invalid()

        containers = {
            service: _container_projection(
                service=service,
                raw=raw_containers[service],
                expected=contract["services"][service],
                project=snapshot.project_name,
                image_ids=image_ids,
                container_ids=container_ids,
                volume_mountpoint=volume_mountpoint,
                image_process_defaults=image_process_defaults,
            )
            for service in _preflight._SERVICES
        }
        if [
            service
            for service in _preflight._SERVICES
            if containers[service]["security"]["cap_add"] == ["NET_ADMIN"]
        ] != ["oidc-egress-guard"]:
            _invalid()
        guard_desired_networks = containers["oidc-egress-guard"][
            "desired_network_config"
        ]
        if (
            frozenset(guard_desired_networks)
            != frozenset(("app", "data", "oidc-egress"))
            or "api" not in guard_desired_networks["app"]["aliases"]
            or containers["db"]["desired_network_config"]["data"][
                "requested_ipv4"
            ]
            != snapshot.db_data_ipv4
            or containers["api"]["network_mode"]
            != "container:" + container_ids["oidc-egress-guard"]
            or containers["api"]["desired_network_config"] != {}
        ):
            _invalid()

        volume = _volume_projection(
            raw_volume, project=snapshot.project_name, expected_name=volume_name
        )
        project_objects = {
            "container_ids": sorted(container_ids.values()),
            "network_ids": sorted(network_ids.values()),
            "volume_names": [volume_name],
            "extra_container_ids": [],
            "extra_network_ids": [],
            "extra_volume_names": [],
        }
        projection = {
            "format": "desire-real-oidc-post-create-semantic-projection-v1",
            "containers": {key: dict(value) for key, value in containers.items()},
            "networks": {key: dict(value) for key, value in networks.items()},
            "postgres_volume": dict(volume),
            "images": dict(image_ids),
            "image_runtime_metadata": image_runtime_metadata,
            "project_objects": project_objects,
        }
        # Force serializability now, while the raw observations still exist;
        # only this safe projection may cross the collector boundary.
        _canonical(projection)
        return MappingProxyType(projection)
    except PrivateServerRealOidcPostCreateCollectorError:
        raise
    except BaseException:
        _invalid()


def _collected_evidence_document(
    *,
    snapshot,
    create_plan_raw: bytes,
    create_plan: Mapping[str, Any],
    collection_plan: RealOidcPostCreateCollectionPlan,
    projection: Mapping[str, Any],
) -> Mapping[str, Any]:
    try:
        containers, networks, volume, project_objects = (
            _preflight.collected_post_create_summaries(dict(projection))
        )
        container_ids = {
            service: containers[service]["id"] for service in _preflight._SERVICES
        }
        network_ids = {
            logical: networks[logical]["id"] for logical in networks
        }
        guard_reference = projection["containers"]["oidc-egress-guard"][
            "image_reference"
        ]
        binding_sha256 = _preflight.guard_binding_sha256(
            snapshot=snapshot,
            container_ids=container_ids,
        )
        guard = {
            "service": "oidc-egress-guard",
            "container_id": container_ids["oidc-egress-guard"],
            "image_id": create_plan["image_ids"][guard_reference],
            "api_container_id": container_ids["api"],
            "db_container_id": container_ids["db"],
            "api_network_mode": "container:" + container_ids["oidc-egress-guard"],
            "api_desired_network_config": {},
            "guard_desired_networks": ["app", "data", "oidc-egress"],
            "guard_app_aliases": ["api"],
            "db_data_ipv4": snapshot.db_data_ipv4,
            "oidc_pinned_public_ipv4": snapshot.oidc_pinned_public_ipv4,
            "oidc_egress_projection_sha256": (
                snapshot.oidc_egress_projection_sha256
            ),
            "binding_sha256": binding_sha256,
            "ruleset_state": "NOT_INSTALLED_NOT_STARTED",
        }
        projection_value = dict(projection)
        projection_sha256 = _purpose_sha256("semantic-projection", projection_value)
        artifacts = _preflight.post_create_artifact_sha256s(
            containers=containers,
            networks=networks,
            postgres_volume=volume,
            project_objects=project_objects,
            guard_binding=guard,
        )
        return MappingProxyType(
            {
                "format": "desire-real-oidc-post-create-evidence-v2",
                "status": "COLLECTED_BASELINE_PROJECTION_VALIDATED_NOT_AUTHORITY",
                "authority": "NOT_AUTHORITY",
                "action": "START_CREATED_CONTAINERS",
                "project": snapshot.project_name,
                "snapshot_sha256": snapshot.snapshot_sha256,
                "manifest_device": snapshot.manifest_device,
                "manifest_inode": snapshot.manifest_inode,
                "compose_sha256": snapshot.compose_sha256,
                "oidc_pinned_public_ipv4": snapshot.oidc_pinned_public_ipv4,
                "db_data_ipv4": snapshot.db_data_ipv4,
                "oidc_egress_projection_sha256": (
                    snapshot.oidc_egress_projection_sha256
                ),
                "create_plan_sha256": _sha(create_plan_raw),
                "docker": {
                    "endpoint": _preflight._DOCKER_ENDPOINT,
                    "reviewed_compose_version": _preflight._COMPOSE_VERSION,
                    "inspect_commands_sha256": (
                        _preflight.post_create_inspect_commands_sha256(snapshot)
                    ),
                },
                "collection": {
                    "status": "COLLECTED_ONCE_BASELINE_PROJECTION_VALIDATED",
                    "collection_binding_sha256": (
                        _preflight.post_create_collection_binding_sha256(
                            snapshot,
                            create_plan_sha256=_sha(create_plan_raw),
                            image_ids=create_plan["image_ids"],
                        )
                    ),
                    "command_count": len(collection_plan.commands),
                    "command_attempts": len(collection_plan.commands),
                    "stable_discovery_passes": 2,
                    "retries": 0,
                    "stderr_policy": "EMPTY_EACH_COMMAND",
                    "raw_inspect_persisted": False,
                    "raw_inspect_reflected": False,
                    "semantic_projection_sha256": projection_sha256,
                },
                "semantic_projection": projection_value,
                "containers": {key: dict(value) for key, value in containers.items()},
                "networks": {key: dict(value) for key, value in networks.items()},
                "postgres_volume": dict(volume),
                "project_objects": dict(project_objects),
                "guard_binding": guard,
                "checks": {
                    key: "COLLECTED_BASELINE_PROJECTION_VALIDATED"
                    for key in _preflight._POST_CREATE_CHECKS
                },
                "artifacts": dict(artifacts),
                "execute_blockers": list(
                    _preflight._COLLECTED_START_EXECUTE_BLOCKERS
                ),
            }
        )
    except PrivateServerRealOidcPostCreateCollectorError:
        raise
    except BaseException:
        _invalid()


def collect_post_create_evidence(
    *,
    attempt_root: Path,
    create_plan_raw: bytes,
    command_runner: Callable[[Sequence[str], Mapping[str, str]], Any],
):
    """Run the exact read-only plan once and return a validated v2 receipt."""

    try:
        snapshot, _manifest, _compose = _release.load_real_oidc_release_snapshot(
            attempt_root
        )
        create_plan = _parse_create_plan(create_plan_raw, snapshot=snapshot)
        collection_plan = build_collection_plan(
            attempt_root=attempt_root, create_plan_raw=create_plan_raw
        )
        if collection_plan.commands != _preflight.post_create_inspect_commands(snapshot):
            _invalid()
        outputs = _run_observations(collection_plan.commands, command_runner)
        projection = _project_observations(
            snapshot=snapshot, create_plan=create_plan, outputs=outputs
        )
        document = _collected_evidence_document(
            snapshot=snapshot,
            create_plan_raw=create_plan_raw,
            create_plan=create_plan,
            collection_plan=collection_plan,
            projection=projection,
        )
        raw = _canonical(dict(document))
        return _preflight.validate_post_create_evidence(
            raw,
            snapshot=snapshot,
            create_plan_sha256=_sha(create_plan_raw),
            image_ids=create_plan["image_ids"],
        )
    except PrivateServerRealOidcPostCreateCollectorError:
        raise
    except (
        _release.PrivateServerRealOidcReleaseInputError,
        _activation.PrivateServerRealOidcActivationError,
        _preflight.PrivateServerRealOidcPreflightError,
    ):
        _invalid()
    except BaseException:
        _invalid()


def _seal_output(path: Path, raw: bytes) -> CollectedEvidenceSeal:
    try:
        metadata = _activation._write_plan(path, raw)
        reopened = _activation._read_closed(path)
        visible = path.lstat()
        if (
            reopened != raw
            or (metadata.st_dev, metadata.st_ino)
            != (visible.st_dev, visible.st_ino)
            or not stat.S_ISREG(visible.st_mode)
            or stat.S_IMODE(visible.st_mode) != 0o400
            or visible.st_uid != os.geteuid()
            or visible.st_nlink != 1
            or visible.st_size != len(raw)
        ):
            _invalid()
        return CollectedEvidenceSeal(
            path=path,
            sha256=_sha(raw),
            device=metadata.st_dev,
            inode=metadata.st_ino,
            size=len(raw),
        )
    except PrivateServerRealOidcPostCreateCollectorError:
        raise
    except BaseException:
        _invalid()


def write_collection_plan(
    path: Path, plan: RealOidcPostCreateCollectionPlan
) -> CollectedEvidenceSeal:
    if not isinstance(plan, RealOidcPostCreateCollectionPlan):
        _invalid()
    return _seal_output(path, plan.raw)


def write_collected_evidence(path: Path, evidence) -> CollectedEvidenceSeal:
    if not isinstance(evidence, _preflight.RealOidcPostCreateEvidence):
        _invalid()
    if evidence.collection_status != "COLLECTED_BASELINE_PROJECTION_VALIDATED_NOT_AUTHORITY":
        _invalid()
    return _seal_output(path, evidence.raw)


def check_collected_evidence_file(
    *, attempt_root: Path, create_plan_raw: bytes, evidence_file: Path
):
    try:
        raw = _activation._read_closed(evidence_file)
        snapshot, _manifest, _compose = _release.load_real_oidc_release_snapshot(
            attempt_root
        )
        create_plan = _parse_create_plan(create_plan_raw, snapshot=snapshot)
        return _preflight.validate_post_create_evidence(
            raw,
            snapshot=snapshot,
            create_plan_sha256=_sha(create_plan_raw),
            image_ids=create_plan["image_ids"],
        )
    except PrivateServerRealOidcPostCreateCollectorError:
        raise
    except BaseException:
        _invalid()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Plan or collect a non-authoritative real-OIDC post-create projection."
    )
    parser.add_argument(
        "--action",
        choices=("plan", "collect", "check", "execute", "start"),
        default="plan",
    )
    parser.add_argument("--attempt-root", required=True)
    parser.add_argument("--create-plan-file", required=True)
    parser.add_argument("--output-file")
    parser.add_argument("--evidence-file")
    return parser


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    stdout: Optional[TextIO] = None,
    command_runner: Optional[
        Callable[[Sequence[str], Mapping[str, str]], Any]
    ] = None,
) -> int:
    output = stdout if stdout is not None else sys.stdout
    try:
        arguments = _parser().parse_args(argv)
        if arguments.action in ("execute", "start"):
            _invalid()
        attempt_root = Path(arguments.attempt_root)
        create_plan_file = Path(arguments.create_plan_file)
        if (
            not attempt_root.is_absolute()
            or not create_plan_file.is_absolute()
        ):
            _invalid()
        create_plan_raw = _activation._read_closed(create_plan_file)
        if arguments.action == "check":
            if arguments.output_file or not arguments.evidence_file:
                _invalid()
            evidence = check_collected_evidence_file(
                attempt_root=attempt_root,
                create_plan_raw=create_plan_raw,
                evidence_file=Path(arguments.evidence_file),
            )
            if evidence.collection_status != "COLLECTED_BASELINE_PROJECTION_VALIDATED_NOT_AUTHORITY":
                _invalid()
            output.write(CHECKED)
            return 0
        if not arguments.output_file or arguments.evidence_file:
            _invalid()
        output_path = Path(arguments.output_file)
        if not output_path.is_absolute():
            _invalid()
        if arguments.action == "plan":
            plan = build_collection_plan(
                attempt_root=attempt_root, create_plan_raw=create_plan_raw
            )
            write_collection_plan(output_path, plan)
            output.write(PLAN_READY)
            return 0
        runner = command_runner if command_runner is not None else _default_runner
        evidence = collect_post_create_evidence(
            attempt_root=attempt_root,
            create_plan_raw=create_plan_raw,
            command_runner=runner,
        )
        write_collected_evidence(output_path, evidence)
        output.write(COLLECTED)
        return 0
    except SystemExit:
        output.write(BLOCKED)
        return 2
    except BaseException:
        output.write(BLOCKED)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = (
    "PrivateServerRealOidcPostCreateCollectorError",
    "RealOidcPostCreateCollectionPlan",
    "CollectedEvidenceSeal",
    "build_collection_plan",
    "collect_post_create_evidence",
    "write_collection_plan",
    "write_collected_evidence",
    "check_collected_evidence_file",
    "main",
)
