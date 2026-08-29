#!/usr/bin/env python3
"""Validate reviewed live facts for a fresh real-OIDC activation plan.

The evidence format is intentionally a closed, canonical JSON receipt.  It
binds the immutable release snapshot, exact local image IDs, the future Docker
read-only query set, fresh project/network/volume absence, and hashes of the
provider, pinned application transport, TLS, browser, host-bind, and
ten-identity reviews.  Destination-firewall live enforcement remains an
explicit execute blocker.
Nothing in this module invokes Docker.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
from types import MappingProxyType
from typing import Any, Mapping, NoReturn, Optional, Sequence, TextIO


_ROOT = Path(__file__).resolve().parents[1]
_RELEASE_HELPER = Path(__file__).resolve().with_name(
    "private_server_real_oidc_release_inputs.py"
)
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EXPOSED_PORT = re.compile(
    r"^(?P<port>[1-9][0-9]{0,4})/(?P<protocol>tcp|udp|sctp)$"
)
_ENVIRONMENT_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
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
_REVIEWED_COMPOSE_HEALTHCHECKS = MappingProxyType(
    {
        "api": (
            (
                "CMD",
                "python",
                "-c",
                "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=2)",
            ),
            10_000_000_000,
            3_000_000_000,
            6,
            20_000_000_000,
            0,
        ),
        "db": (
            ("CMD-SHELL", "pg_isready -U postgres -d desire || exit 1"),
            5_000_000_000,
            3_000_000_000,
            20,
            10_000_000_000,
            0,
        ),
        "edge": (
            (
                "CMD",
                "wget",
                "--no-verbose",
                "--tries=1",
                "--spider",
                "http://127.0.0.1:8080/_edge/health",
            ),
            10_000_000_000,
            3_000_000_000,
            10,
            5_000_000_000,
            0,
        ),
        "matching-runtime": (
            (
                "CMD",
                "python",
                "-c",
                "from pathlib import Path; import time; p=Path('/run/matching-runtime/healthy'); raise SystemExit(0 if p.is_file() and time.time()-p.stat().st_mtime < 30 else 1)",
            ),
            10_000_000_000,
            3_000_000_000,
            3,
            20_000_000_000,
            0,
        ),
        "oidc-egress-guard": (
            (
                "CMD",
                "/usr/local/bin/desire-real-oidc-egress-guard",
                "check",
            ),
            5_000_000_000,
            3_000_000_000,
            3,
            1_000_000_000,
            0,
        ),
        "web": (
            (
                "CMD",
                "node",
                "-e",
                "fetch('http://127.0.0.1:3000/').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))",
            ),
            10_000_000_000,
            3_000_000_000,
            10,
            15_000_000_000,
            0,
        ),
    }
)
_REVIEWED_STOP_TIMEOUT_SECONDS = MappingProxyType(
    {"api": 20, "db": 60, "matching-runtime": 30}
)
_REVIEWED_COMPOSE_DURATIONS_NS = MappingProxyType(
    {
        "1s": 1_000_000_000,
        "3s": 3_000_000_000,
        "5s": 5_000_000_000,
        "10s": 10_000_000_000,
        "15s": 15_000_000_000,
        "20s": 20_000_000_000,
        "30s": 30_000_000_000,
        "1m0s": 60_000_000_000,
    }
)
_DOCKER_ENDPOINT = "unix:///var/run/docker.sock"
_COMPOSE_VERSION = "5.3.1"
_DOCKER = ("/usr/bin/docker", "--host", _DOCKER_ENDPOINT)
_INSPECT_JSON_FORMAT = "{{json .}}"
_CONTAINER_LIST_JSON_FORMAT = '{"Id":{{json .ID}},"Name":{{json .Names}}}'
_NETWORK_LIST_JSON_FORMAT = '{"Id":{{json .ID}},"Name":{{json .Name}}}'
_VOLUME_LIST_JSON_FORMAT = '{"Name":{{json .Name}}}'
_SERVICES = (
    "api",
    "db",
    "edge",
    "identity-bootstrap",
    "migrate",
    "matching-runtime",
    "oidc-egress-guard",
    "online-credentials-reconcile",
    "online-credentials-verify",
    "taxonomy-seed",
    "web",
)
_RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_ARTIFACTS = frozenset(
    (
        "host_bind",
        "provider",
        "pinned_oidc_transport",
        "tls",
        "browser_csp",
        "ten_identities",
    )
)
_CREATE_PLAN_BLOCKERS = (
    "TRUSTED_CREATE_ONLY_PROTOCOL_UNIMPLEMENTED",
    "RESOURCE_ORIGIN_ATTESTATION_UNIMPLEMENTED",
    "POST_CREATE_EVIDENCE_REQUIRED",
    "POST_CREATE_LIVE_INSPECT_COLLECTOR_UNIMPLEMENTED",
    "DESTINATION_FIREWALL_LIVE_ENFORCEMENT_UNIMPLEMENTED",
    "LIVE_READINESS_RUNNER_UNIMPLEMENTED",
)
_START_EXECUTE_BLOCKERS = (
    "TRUSTED_CREATE_ONLY_PROTOCOL_UNIMPLEMENTED",
    "RESOURCE_ORIGIN_ATTESTATION_UNIMPLEMENTED",
    "POST_CREATE_LIVE_INSPECT_COLLECTOR_UNIMPLEMENTED",
    "POST_CREATE_COLLECTOR_PROVENANCE_UNIMPLEMENTED",
    "DOCKER_SOCKET_EXCLUSIVE_BROKER_UNIMPLEMENTED",
    "EXECUTION_AUTHORIZATION_V2_UNIMPLEMENTED",
    "PRE_START_FULL_REINSPECTION_RUNNER_UNIMPLEMENTED",
    "POST_CREATE_SECURITY_PROJECTION_RULE_VALIDATOR_UNIMPLEMENTED",
    "DESTINATION_FIREWALL_LIVE_ENFORCEMENT_UNIMPLEMENTED",
    "GUARD_RULESET_INSTALL_AND_DENY_PROBES_UNIMPLEMENTED",
    "GUARD_RUNNING_HEALTHY_RULESET_GATE_RUNNER_UNIMPLEMENTED",
    "LIVE_READINESS_RUNNER_UNIMPLEMENTED",
)
_COLLECTED_START_EXECUTE_BLOCKERS = tuple(
    blocker
    for blocker in _START_EXECUTE_BLOCKERS
    if blocker != "POST_CREATE_LIVE_INSPECT_COLLECTOR_UNIMPLEMENTED"
)
_EXECUTE_BLOCKERS = _CREATE_PLAN_BLOCKERS
_POST_CREATE_CHECKS = frozenset(
    (
        "container_images",
        "container_labels",
        "mount_projection",
        "network_projection",
        "port_projection",
        "network_namespace_projection",
        "guard_binding_projection",
        "project_object_inventory",
    )
)

READY = '{"status":"PRIVATE_SERVER_REAL_OIDC_PREFLIGHT_VERIFIED"}\n'
BLOCKED = (
    '{"code":"PRIVATE_SERVER_REAL_OIDC_PREFLIGHT_INVALID",'
    '"status":"BLOCKED"}\n'
)


def _load_release_helper():
    name = "_desire_real_oidc_release_inputs_for_preflight"
    spec = importlib.util.spec_from_file_location(name, _RELEASE_HELPER)
    if spec is None or spec.loader is None:
        raise RuntimeError("PRIVATE_SERVER_REAL_OIDC_PREFLIGHT_INVALID")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_release = _load_release_helper()


def _validated_environment_map(value: Any) -> Mapping[str, str]:
    """Return one closed Compose environment map without reflecting values."""

    if not isinstance(value, dict):
        _invalid()
    result = {}
    for key, item in value.items():
        if (
            not isinstance(key, str)
            or _ENVIRONMENT_KEY.fullmatch(key) is None
            or not isinstance(item, str)
            or "\x00" in item
            or key.casefold() in _PROXY_ENVIRONMENT_KEYS
        ):
            _invalid()
        result[key] = item
    return MappingProxyType(result)


def _environment_merge_source(
    *,
    compose_entry_count: int,
    image_entry_count: int,
    inherited_image_entry_count: int,
) -> str:
    if (
        type(compose_entry_count) is not int
        or type(image_entry_count) is not int
        or type(inherited_image_entry_count) is not int
        or compose_entry_count < 0
        or image_entry_count < 0
        or not 0 <= inherited_image_entry_count <= image_entry_count
    ):
        _invalid()
    if compose_entry_count == 0:
        if inherited_image_entry_count != image_entry_count:
            _invalid()
        return "IMAGE_INHERITED" if image_entry_count else "EMPTY"
    if inherited_image_entry_count:
        return "COMPOSE_WITH_IMAGE_DEFAULTS"
    return "COMPOSE_EXPLICIT"


def _compose_duration_ns(value: Any) -> int:
    if not isinstance(value, str) or value not in _REVIEWED_COMPOSE_DURATIONS_NS:
        _invalid()
    return _REVIEWED_COMPOSE_DURATIONS_NS[value]


def _compose_healthcheck(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        _invalid()
    allowed = {
        "test",
        "interval",
        "timeout",
        "retries",
        "start_period",
        "start_interval",
    }
    required = {"test", "interval", "timeout", "retries", "start_period"}
    if not required.issubset(value) or not set(value).issubset(allowed):
        _invalid()
    test = value["test"]
    retries = value["retries"]
    if (
        not isinstance(test, list)
        or len(test) < 2
        or test[0] not in ("CMD", "CMD-SHELL")
        or (test[0] == "CMD-SHELL" and len(test) != 2)
        or any(not isinstance(part, str) or not part or "\x00" in part for part in test)
        or type(retries) is not int
        or retries <= 0
    ):
        _invalid()
    return MappingProxyType(
        {
            "Test": list(test),
            "Interval": _compose_duration_ns(value["interval"]),
            "Timeout": _compose_duration_ns(value["timeout"]),
            "Retries": retries,
            "StartPeriod": _compose_duration_ns(value["start_period"]),
            "StartInterval": (
                _compose_duration_ns(value["start_interval"])
                if "start_interval" in value
                else 0
            ),
        }
    )


class PrivateServerRealOidcPreflightError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("PRIVATE_SERVER_REAL_OIDC_PREFLIGHT_INVALID")


@dataclass(frozen=True, repr=False)
class RealOidcPreflightEvidence:
    raw: bytes
    sha256: str
    project_name: str
    snapshot_sha256: str
    compose_sha256: str
    image_ids: Mapping[str, str]
    fresh_check_commands_sha256: str

    def __repr__(self) -> str:
        return (
            "RealOidcPreflightEvidence("
            f"sha256={self.sha256!r}, project_name={self.project_name!r}, "
            "reviewed_material=<redacted>)"
        )


@dataclass(frozen=True, repr=False)
class RealOidcPostCreateEvidence:
    raw: bytes
    sha256: str
    project_name: str
    create_plan_sha256: str
    container_ids: Mapping[str, str]
    network_ids: Mapping[str, str]
    image_ids: Mapping[str, str]
    guard_binding_sha256: str
    execute_blockers: tuple[str, ...]
    collection_status: str

    def __repr__(self) -> str:
        return (
            "RealOidcPostCreateEvidence("
            f"sha256={self.sha256!r}, project_name={self.project_name!r}, "
            f"inspect_material=<redacted>, status={self.collection_status!r})"
        )


class _DuplicateKey(ValueError):
    pass


def _invalid() -> NoReturn:
    raise PrivateServerRealOidcPreflightError()


def _pairs(values):
    result = {}
    for key, value in values:
        if not isinstance(key, str) or key in result:
            raise _DuplicateKey()
        result[key] = value
    return result


def _parse(raw: bytes) -> Any:
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= 1024 * 1024:
            _invalid()
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs,
            parse_float=lambda _value: _invalid(),
            parse_constant=lambda _value: _invalid(),
        )
        if _canonical(value) != raw:
            _invalid()
        return value
    except PrivateServerRealOidcPreflightError:
        raise
    except BaseException:
        _invalid()


def _canonical(value: Any) -> bytes:
    try:
        return (
            json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("ascii")
    except BaseException:
        _invalid()


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _closed(value: Any, keys) -> Mapping[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != frozenset(keys):
        _invalid()
    return value


def _snapshot_contract(snapshot) -> None:
    try:
        if (
            not isinstance(snapshot.attempt_root, Path)
            or not snapshot.attempt_root.is_absolute()
            or not isinstance(snapshot.project_name, str)
            or not snapshot.project_name.startswith("desire-real-oidc-")
            or _SHA256.fullmatch(snapshot.snapshot_sha256) is None
            or _SHA256.fullmatch(snapshot.compose_sha256) is None
            or not isinstance(snapshot.oidc_pinned_public_ipv4, str)
            or snapshot.oidc_pinned_public_ipv4 != snapshot.oidc_pinned_public_ipv4.strip()
            or not isinstance(snapshot.db_data_ipv4, str)
            or snapshot.db_data_ipv4 != snapshot.db_data_ipv4.strip()
            or _SHA256.fullmatch(snapshot.oidc_egress_projection_sha256) is None
            or type(snapshot.manifest_device) is not int
            or type(snapshot.manifest_inode) is not int
            or not isinstance(snapshot.image_references, tuple)
            or len(snapshot.image_references) != 5
            or any(not isinstance(item, str) or not item for item in snapshot.image_references)
        ):
            _invalid()
        pinned = ipaddress.ip_address(snapshot.oidc_pinned_public_ipv4)
        db_data = ipaddress.ip_address(snapshot.db_data_ipv4)
        if (
            not isinstance(pinned, ipaddress.IPv4Address)
            or not pinned.is_global
            or str(pinned) != snapshot.oidc_pinned_public_ipv4
            or not isinstance(db_data, ipaddress.IPv4Address)
            or str(db_data) != snapshot.db_data_ipv4
            or not any(db_data in network for network in _RFC1918)
        ):
            _invalid()
    except (AttributeError, TypeError):
        _invalid()
    except ValueError:
        _invalid()


def fresh_resource_names(project: str) -> Mapping[str, str]:
    return MappingProxyType(
        {
            logical: project + "_" + logical
            for logical in ("app", "data", "ingress", "oidc-egress")
        }
    )


def fresh_container_names(project: str) -> Mapping[str, str]:
    return MappingProxyType(
        {service: project + "-" + service + "-1" for service in _SERVICES}
    )


def fresh_check_commands(snapshot) -> tuple[tuple[str, ...], ...]:
    """Return the exact read-only commands a future live collector must run."""

    try:
        _snapshot_contract(snapshot)
        project = snapshot.project_name
        label = "label=com.docker.compose.project=" + project
        docker = ("/usr/bin/docker", "--host", _DOCKER_ENDPOINT)
        commands = [
            docker + ("version", "--format", "{{json .Server}}"),
            docker + ("compose", "version", "--short"),
            docker
            + (
                "container",
                "ls",
                "--all",
                "--filter",
                label,
                "--format",
                "{{.ID}}",
            ),
            docker
            + ("network", "ls", "--filter", label, "--format", "{{.ID}}"),
            docker + ("volume", "ls", "--filter", label, "--format", "{{.Name}}"),
        ]
        for name in fresh_resource_names(project).values():
            commands.append(docker + ("network", "inspect", name))
        for name in fresh_container_names(project).values():
            commands.append(docker + ("container", "inspect", name))
        commands.append(docker + ("volume", "inspect", project + "_postgres-data"))
        for reference in snapshot.image_references:
            commands.append(
                docker + ("image", "inspect", "--format", "{{.Id}}", reference)
            )
        commands.extend(
            (
                ("/usr/sbin/ip", "-json", "address", "show", "up"),
                ("/usr/bin/ss", "-H", "-ltn"),
            )
        )
        return tuple(commands)
    except PrivateServerRealOidcPreflightError:
        raise
    except BaseException:
        _invalid()


def fresh_check_commands_sha256(snapshot) -> str:
    return _sha(_canonical([list(command) for command in fresh_check_commands(snapshot)]))


def post_create_inspect_commands(snapshot) -> tuple[tuple[str, ...], ...]:
    """Return the stable, read-only command contract for a live collector.

    The command set deliberately does not contain Compose or any Docker
    lifecycle/network mutation verb.  Every inspect command emits one JSON
    object; the three inventory commands emit zero or more JSON objects, one
    per line.  A collector runs the exact plan in order, including the final
    independent discovery pass, without retrying any failed observation.
    """

    try:
        _snapshot_contract(snapshot)
        project = snapshot.project_name
        project_filter = "label=com.docker.compose.project=" + project
        inventory_commands = [
            _DOCKER
            + (
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--filter",
                project_filter,
                "--format",
                _CONTAINER_LIST_JSON_FORMAT,
            ),
            _DOCKER
            + (
                "network",
                "ls",
                "--no-trunc",
                "--filter",
                project_filter,
                "--format",
                _NETWORK_LIST_JSON_FORMAT,
            ),
            _DOCKER
            + (
                "volume",
                "ls",
                "--filter",
                project_filter,
                "--format",
                _VOLUME_LIST_JSON_FORMAT,
            ),
        ]
        commands = list(inventory_commands)
        commands.extend(
            _DOCKER
            + (
                "container",
                "inspect",
                "--format",
                _INSPECT_JSON_FORMAT,
                name,
            )
            for name in fresh_container_names(project).values()
        )
        commands.extend(
            _DOCKER
            + (
                "network",
                "inspect",
                "--format",
                _INSPECT_JSON_FORMAT,
                name,
            )
            for name in fresh_resource_names(project).values()
        )
        commands.append(
            _DOCKER
            + (
                "volume",
                "inspect",
                "--format",
                _INSPECT_JSON_FORMAT,
                project + "_postgres-data",
            )
        )
        commands.extend(
            _DOCKER
            + (
                "image",
                "inspect",
                "--format",
                _INSPECT_JSON_FORMAT,
                reference,
            )
            for reference in snapshot.image_references
        )
        # A second discovery pass must match the first.  It is a stability
        # observation, not a retry; every command still runs exactly once.
        commands.extend(inventory_commands)
        if len(commands) != 6 + len(_SERVICES) + len(fresh_resource_names(project)) + 1 + len(snapshot.image_references):
            _invalid()
        forbidden = frozenset(
            (
                "start",
                "create",
                "update",
                "connect",
                "disconnect",
                "run",
                "up",
                "down",
                "restart",
                "remove",
                "rm",
            )
        )
        if any("compose" in command or forbidden.intersection(command) for command in commands):
            _invalid()
        return tuple(commands)
    except PrivateServerRealOidcPreflightError:
        raise
    except BaseException:
        _invalid()


def post_create_inspect_commands_sha256(snapshot) -> str:
    return _sha(
        _canonical(
            [list(command) for command in post_create_inspect_commands(snapshot)]
        )
    )


def post_create_collection_binding_sha256(
    snapshot, *, create_plan_sha256: str, image_ids: Mapping[str, str]
) -> str:
    try:
        _snapshot_contract(snapshot)
        if (
            _SHA256.fullmatch(create_plan_sha256) is None
            or not isinstance(image_ids, Mapping)
            or frozenset(image_ids) != frozenset(snapshot.image_references)
            or any(_IMAGE_ID.fullmatch(value) is None for value in image_ids.values())
            or len(set(image_ids.values())) != 5
        ):
            _invalid()
        return _sha(
            _canonical(
                {
                    "format": "desire-real-oidc-post-create-collection-binding-v1",
                    "project": snapshot.project_name,
                    "snapshot_sha256": snapshot.snapshot_sha256,
                    "manifest_device": snapshot.manifest_device,
                    "manifest_inode": snapshot.manifest_inode,
                    "compose_sha256": snapshot.compose_sha256,
                    "create_plan_sha256": create_plan_sha256,
                    "image_ids": dict(image_ids),
                    "inspect_commands_sha256": post_create_inspect_commands_sha256(
                        snapshot
                    ),
                    "command_count": len(post_create_inspect_commands(snapshot)),
                    "stable_discovery_passes": 2,
                }
            )
        )
    except PrivateServerRealOidcPreflightError:
        raise
    except BaseException:
        _invalid()


def image_lock_sha256(image_ids: Mapping[str, str]) -> str:
    try:
        return _sha(_canonical(dict(image_ids)))
    except PrivateServerRealOidcPreflightError:
        raise
    except BaseException:
        _invalid()


def validate_preflight_evidence(
    raw: bytes, *, snapshot
) -> RealOidcPreflightEvidence:
    """Validate one canonical reviewed evidence receipt against a snapshot."""

    try:
        _snapshot_contract(snapshot)
        document = _closed(
            _parse(raw),
            (
                "format",
                "status",
                "action",
                "project",
                "snapshot_sha256",
                "manifest_device",
                "manifest_inode",
                "compose_sha256",
                "oidc_pinned_public_ipv4",
                "db_data_ipv4",
                "oidc_egress_projection_sha256",
                "docker",
                "fresh",
                "images",
                "checks",
                "artifacts",
                "execute_blockers",
            ),
        )
        docker = _closed(
            document["docker"],
            ("endpoint", "compose_version", "fresh_check_commands_sha256"),
        )
        names = fresh_resource_names(snapshot.project_name)
        fresh = _closed(
            document["fresh"],
            (
                "project_containers",
                "project_networks",
                "project_volumes",
                "named_containers",
                "named_networks",
                "postgres_volume",
            ),
        )
        named_networks = _closed(fresh["named_networks"], names.keys())
        container_names = fresh_container_names(snapshot.project_name)
        named_containers = _closed(
            fresh["named_containers"], container_names.keys()
        )
        checks = _closed(document["checks"], _ARTIFACTS)
        artifacts = _closed(document["artifacts"], _ARTIFACTS)
        images = document["images"]
        expected_commands = fresh_check_commands_sha256(snapshot)
        if (
            document["format"] != "desire-real-oidc-preflight-evidence-v1"
            or document["status"] != "REVIEWED"
            or document["action"] != "ACTIVATE"
            or document["project"] != snapshot.project_name
            or document["snapshot_sha256"] != snapshot.snapshot_sha256
            or document["manifest_device"] != snapshot.manifest_device
            or document["manifest_inode"] != snapshot.manifest_inode
            or document["compose_sha256"] != snapshot.compose_sha256
            or document["oidc_pinned_public_ipv4"]
            != snapshot.oidc_pinned_public_ipv4
            or document["db_data_ipv4"] != snapshot.db_data_ipv4
            or document["oidc_egress_projection_sha256"]
            != snapshot.oidc_egress_projection_sha256
            or docker["endpoint"] != _DOCKER_ENDPOINT
            or docker["compose_version"] != _COMPOSE_VERSION
            or docker["fresh_check_commands_sha256"] != expected_commands
            or fresh["project_containers"] != []
            or fresh["project_networks"] != []
            or fresh["project_volumes"] != []
            or named_containers
            != {key: "ABSENT" for key in container_names}
            or named_networks != {key: "ABSENT" for key in names}
            or fresh["postgres_volume"] != "ABSENT"
            or checks != {key: "VERIFIED" for key in _ARTIFACTS}
            or any(
                not isinstance(value, str) or _SHA256.fullmatch(value) is None
                for value in artifacts.values()
            )
            or len(set(artifacts.values())) != len(artifacts)
            or not isinstance(images, dict)
            or frozenset(images) != frozenset(snapshot.image_references)
            or any(
                not isinstance(value, str) or _IMAGE_ID.fullmatch(value) is None
                for value in images.values()
            )
            or len(set(images.values())) != len(images)
            or document["execute_blockers"] != list(_CREATE_PLAN_BLOCKERS)
        ):
            _invalid()
        # The pilot bind must remain a canonical, non-loopback RFC1918 address.
        reviewed = document.get("project")
        del reviewed
        manifest, manifest_document, _compose = _release.load_real_oidc_release_snapshot(
            snapshot.attempt_root
        )
        reviewed_values = manifest_document.get("reviewed")
        try:
            ingress = ipaddress.ip_address(reviewed_values.get("ingress_ip"))
        except (ValueError, AttributeError):
            _invalid()
        if (
            not isinstance(ingress, ipaddress.IPv4Address)
            or ingress.is_loopback
            or not any(ingress in network for network in _RFC1918)
            or manifest.snapshot_sha256 != snapshot.snapshot_sha256
        ):
            _invalid()
        return RealOidcPreflightEvidence(
            raw=raw,
            sha256=_sha(raw),
            project_name=snapshot.project_name,
            snapshot_sha256=snapshot.snapshot_sha256,
            compose_sha256=snapshot.compose_sha256,
            image_ids=MappingProxyType(dict(images)),
            fresh_check_commands_sha256=expected_commands,
        )
    except PrivateServerRealOidcPreflightError:
        raise
    except _release.PrivateServerRealOidcReleaseInputError:
        _invalid()
    except BaseException:
        _invalid()


def _service_image_references(snapshot) -> Mapping[str, str]:
    try:
        reopened, _manifest, compose = _release.load_real_oidc_release_snapshot(
            snapshot.attempt_root
        )
        if reopened.snapshot_sha256 != snapshot.snapshot_sha256:
            _invalid()
        document = _release._json(compose)
        services = document.get("services") if isinstance(document, dict) else None
        if not isinstance(services, dict) or frozenset(services) != frozenset(_SERVICES):
            _invalid()
        result = {}
        for service, value in services.items():
            if not isinstance(value, dict):
                _invalid()
            reference = value.get("image")
            if reference not in snapshot.image_references:
                _invalid()
            result[service] = reference
        if frozenset(result.values()) != frozenset(snapshot.image_references):
            _invalid()
        networks = document.get("networks")
        data = networks.get("data") if isinstance(networks, dict) else None
        ipam = data.get("ipam") if isinstance(data, dict) else None
        config = ipam.get("config") if isinstance(ipam, dict) else None
        if not isinstance(config, list) or len(config) != 1:
            _invalid()
        subnet = config[0].get("subnet") if isinstance(config[0], dict) else None
        network = ipaddress.ip_network(subnet, strict=True)
        db_data = ipaddress.ip_address(snapshot.db_data_ipv4)
        if (
            not isinstance(network, ipaddress.IPv4Network)
            or network.prefixlen != 24
            or db_data not in network
            or db_data in (network.network_address, network.broadcast_address)
        ):
            _invalid()
        return MappingProxyType(result)
    except PrivateServerRealOidcPreflightError:
        raise
    except _release.PrivateServerRealOidcReleaseInputError:
        _invalid()
    except BaseException:
        _invalid()


def _post_create_compose_contract(snapshot) -> Mapping[str, Any]:
    """Project the sealed Compose file into the live-inspect expectations.

    ``raw_source`` values are retained only for an in-memory collector to
    compare bind mounts.  They must never be copied into a receipt or CLI
    output.
    """

    try:
        _snapshot_contract(snapshot)
        reopened, _manifest, compose_raw = _release.load_real_oidc_release_snapshot(
            snapshot.attempt_root
        )
        if (
            reopened.snapshot_sha256 != snapshot.snapshot_sha256
            or reopened.compose_sha256 != snapshot.compose_sha256
        ):
            _invalid()
        compose = _release._json(compose_raw)
        if not isinstance(compose, dict):
            _invalid()
        services = compose.get("services")
        networks = compose.get("networks")
        volumes = compose.get("volumes")
        configs = compose.get("configs")
        secrets = compose.get("secrets")
        if (
            not isinstance(services, dict)
            or frozenset(services) != frozenset(_SERVICES)
            or not isinstance(networks, dict)
            or frozenset(networks)
            != frozenset(("app", "data", "ingress", "oidc-egress"))
            or not isinstance(volumes, dict)
            or frozenset(volumes) != frozenset(("postgres-data",))
            or not isinstance(configs, dict)
            or not isinstance(secrets, dict)
        ):
            _invalid()

        network_contract = {}
        for logical, item in networks.items():
            if not isinstance(item, dict):
                _invalid()
            physical = item.get("name")
            ipam = item.get("ipam")
            config = ipam.get("config") if isinstance(ipam, dict) else None
            if (
                physical != fresh_resource_names(snapshot.project_name)[logical]
                or not isinstance(config, list)
                or len(config) != 1
                or not isinstance(config[0], dict)
                or frozenset(config[0]) != frozenset(("subnet",))
            ):
                _invalid()
            subnet = ipaddress.ip_network(config[0]["subnet"], strict=True)
            if not isinstance(subnet, ipaddress.IPv4Network) or subnet.prefixlen != 24:
                _invalid()
            network_contract[logical] = {
                "name": physical,
                "internal": item.get("internal", False) is True,
                "subnet": str(subnet),
            }

        volume_item = volumes["postgres-data"]
        volume_name = (
            volume_item.get("name") if isinstance(volume_item, dict) else None
        )
        if volume_name != snapshot.project_name + "_postgres-data":
            _invalid()

        def file_source(values: Mapping[str, Any], logical: str) -> str:
            item = values.get(logical)
            source = item.get("file") if isinstance(item, dict) else None
            if not isinstance(source, str):
                _invalid()
            path = Path(source)
            if not path.is_absolute() or path.resolve(strict=True) != path:
                _invalid()
            return source

        def process_sequence(value: Any) -> Optional[list[str]]:
            if value is None:
                return None
            if (
                not isinstance(value, list)
                or not value
                or any(not isinstance(part, str) or not part or "\x00" in part for part in value)
            ):
                _invalid()
            return list(value)

        def security_sequence(value: Any) -> list[str]:
            if value is None:
                return []
            if (
                not isinstance(value, list)
                or any(not isinstance(part, str) or not part for part in value)
                or len(value) != len(set(value))
            ):
                _invalid()
            return sorted(value)

        def dependency_projection(value: Any) -> list[dict[str, Any]]:
            dependencies = {} if value is None else value
            if not isinstance(dependencies, dict):
                _invalid()
            projected = []
            for dependency, settings in dependencies.items():
                if dependency not in _SERVICES or not isinstance(settings, dict):
                    _invalid()
                if frozenset(settings) not in (
                    frozenset(("condition", "required")),
                    frozenset(("condition", "required", "restart")),
                ):
                    _invalid()
                condition = settings.get("condition")
                required = settings.get("required")
                restart = settings.get("restart", False)
                if (
                    condition
                    not in (
                        "service_started",
                        "service_healthy",
                        "service_completed_successfully",
                    )
                    or required is not True
                    or type(restart) is not bool
                ):
                    _invalid()
                projected.append(
                    {
                        "service": dependency,
                        "condition": condition,
                        "restart": restart,
                    }
                )
            projected.sort(key=lambda item: item["service"])
            return projected

        service_contract = {}
        for service in _SERVICES:
            item = services[service]
            if not isinstance(item, dict):
                _invalid()
            image_reference = item.get("image")
            if image_reference not in snapshot.image_references:
                _invalid()
            name = fresh_container_names(snapshot.project_name)[service]
            mounts = []
            for config in item.get("configs") or []:
                if not isinstance(config, dict):
                    _invalid()
                logical = config.get("source")
                destination = config.get("target")
                if (
                    not isinstance(logical, str)
                    or not isinstance(destination, str)
                    or not destination.startswith("/")
                ):
                    _invalid()
                mounts.append(
                    {
                        "type": "bind",
                        "destination": destination,
                        "read_only": True,
                        "source_kind": "config",
                        "source_name": logical,
                        "raw_source": file_source(configs, logical),
                        "host_config_bind_options_present": False,
                    }
                )
            for secret in item.get("secrets") or []:
                if isinstance(secret, str):
                    logical = secret
                    target = secret
                elif isinstance(secret, dict):
                    logical = secret.get("source")
                    target = secret.get("target", logical)
                else:
                    _invalid()
                if not isinstance(logical, str) or not isinstance(target, str):
                    _invalid()
                destination = (
                    target if target.startswith("/") else "/run/secrets/" + target
                )
                mounts.append(
                    {
                        "type": "bind",
                        "destination": destination,
                        "read_only": True,
                        "source_kind": "secret",
                        "source_name": logical,
                        "raw_source": file_source(secrets, logical),
                        "host_config_bind_options_present": True,
                    }
                )
            for volume in item.get("volumes") or []:
                if not isinstance(volume, dict):
                    _invalid()
                kind = volume.get("type")
                source = volume.get("source")
                destination = volume.get("target")
                read_only = volume.get("read_only", False) is True
                if (
                    kind not in ("bind", "volume")
                    or not isinstance(source, str)
                    or not isinstance(destination, str)
                    or not destination.startswith("/")
                ):
                    _invalid()
                if kind == "bind":
                    source_path = Path(source)
                    if (
                        not source_path.is_absolute()
                        or source_path.resolve(strict=True) != source_path
                    ):
                        _invalid()
                    mounts.append(
                        {
                            "type": "bind",
                            "destination": destination,
                            "read_only": read_only,
                            "source_kind": "bind",
                            "source_name": "identity-sources",
                            "raw_source": source,
                            "host_config_bind_options_present": True,
                        }
                    )
                else:
                    if source != "postgres-data" or volume_name is None:
                        _invalid()
                    mounts.append(
                        {
                            "type": "volume",
                            "destination": destination,
                            "read_only": read_only,
                            "source_kind": "volume",
                            "source_name": "postgres-data",
                            "raw_source": volume_name,
                        }
                    )
            mounts.sort(
                key=lambda value: (
                    value["destination"],
                    value["type"],
                    value["source_kind"],
                    value["source_name"],
                )
            )
            if len({value["destination"] for value in mounts}) != len(mounts):
                _invalid()

            tmpfs = []
            for value in item.get("tmpfs") or []:
                if not isinstance(value, str) or not value.startswith("/"):
                    _invalid()
                destination, separator, options = value.partition(":")
                tmpfs.append(
                    {
                        "destination": destination,
                        "options": options if separator else "",
                    }
                )
            tmpfs.sort(key=lambda value: value["destination"])
            if len({value["destination"] for value in tmpfs}) != len(tmpfs):
                _invalid()

            configured_networks = item.get("networks")
            if service == "api":
                if configured_networks not in (None, {}):
                    _invalid()
                network_mode = "container:{guard_container_id}"
                desired_network_config = {}
            else:
                if not isinstance(configured_networks, dict) or not configured_networks:
                    _invalid()
                desired_network_config = {}
                for logical, settings in configured_networks.items():
                    if logical not in network_contract or settings is not None and not isinstance(settings, dict):
                        _invalid()
                    ipam_config_present = settings is not None
                    settings = settings or {}
                    aliases = settings.get("aliases", [])
                    if not isinstance(aliases, list) or any(
                        not isinstance(value, str) or not value for value in aliases
                    ):
                        _invalid()
                    expected_aliases = sorted(set((name, service, *aliases)))
                    requested_ipv4 = settings.get("ipv4_address")
                    if requested_ipv4 is not None and not isinstance(requested_ipv4, str):
                        _invalid()
                    desired_network_config[logical] = {
                        "network_name": network_contract[logical]["name"],
                        "aliases": expected_aliases,
                        "requested_ipv4": requested_ipv4,
                        "ipam_config_present": ipam_config_present,
                    }
                first_logical = next(iter(configured_networks))
                network_mode = network_contract[first_logical]["name"]

            ports = []
            for port in item.get("ports") or []:
                if not isinstance(port, dict):
                    _invalid()
                target = port.get("target")
                published = port.get("published")
                host_ip = port.get("host_ip")
                protocol = port.get("protocol", "tcp")
                if (
                    type(target) is not int
                    or not isinstance(published, str)
                    or not isinstance(host_ip, str)
                    or protocol not in ("tcp", "udp")
                ):
                    _invalid()
                ports.append(
                    {
                        "container_port": target,
                        "protocol": protocol,
                        "host_ip": host_ip,
                        "host_port": published,
                    }
                )
            ports.sort(
                key=lambda value: (
                    value["container_port"],
                    value["protocol"],
                    value["host_ip"],
                    value["host_port"],
                )
            )
            environment = _validated_environment_map(item.get("environment"))
            guard_environment = None
            if service == "oidc-egress-guard":
                expected_keys = (
                    "DESIRE_REAL_OIDC_DB_DATA_IPV4",
                    "DESIRE_REAL_OIDC_PINNED_PUBLIC_IPV4",
                    "DESIRE_REAL_OIDC_EGRESS_PROJECTION_SHA256",
                )
                guard_environment = {
                    key: environment.get(key) for key in expected_keys
                }
                if guard_environment != {
                    "DESIRE_REAL_OIDC_DB_DATA_IPV4": snapshot.db_data_ipv4,
                    "DESIRE_REAL_OIDC_PINNED_PUBLIC_IPV4": (
                        snapshot.oidc_pinned_public_ipv4
                    ),
                    "DESIRE_REAL_OIDC_EGRESS_PROJECTION_SHA256": (
                        snapshot.oidc_egress_projection_sha256
                    ),
                }:
                    _invalid()
            compose_healthcheck = None
            if service in _REVIEWED_COMPOSE_HEALTHCHECKS:
                if "healthcheck" not in item:
                    _invalid()
                compose_healthcheck = _compose_healthcheck(item["healthcheck"])
                reviewed_healthcheck = _REVIEWED_COMPOSE_HEALTHCHECKS[service]
                if (
                    tuple(compose_healthcheck["Test"]) != reviewed_healthcheck[0]
                    or tuple(
                        compose_healthcheck[field]
                        for field in _HEALTHCHECK_FIELDS[1:]
                    )
                    != reviewed_healthcheck[1:]
                ):
                    _invalid()
            elif "healthcheck" in item:
                _invalid()
            stop_timeout_seconds = _REVIEWED_STOP_TIMEOUT_SECONDS.get(service)
            if stop_timeout_seconds is None:
                if "stop_grace_period" in item:
                    _invalid()
            else:
                if "stop_grace_period" not in item:
                    _invalid()
                duration_ns = _compose_duration_ns(item["stop_grace_period"])
                if duration_ns != stop_timeout_seconds * 1_000_000_000:
                    _invalid()
            api_extra_hosts = None
            if service == "api":
                extra_hosts = item.get("extra_hosts")
                if not isinstance(extra_hosts, list) or any(
                    not isinstance(value, str) or not value for value in extra_hosts
                ):
                    _invalid()
                api_extra_hosts = sorted(
                    value.replace("=", ":", 1) for value in extra_hosts
                )
                if api_extra_hosts != ["db:" + snapshot.db_data_ipv4]:
                    _invalid()
            command = process_sequence(item.get("command"))
            entrypoint = process_sequence(item.get("entrypoint"))
            user = item.get("user")
            if user is not None and (
                not isinstance(user, str) or not user or "\x00" in user
            ):
                _invalid()
            working_dir = item.get("working_dir")
            if working_dir is not None and (
                not isinstance(working_dir, str)
                or not working_dir.startswith("/")
                or "\x00" in working_dir
            ):
                _invalid()
            stop_signal = item.get("stop_signal")
            if stop_signal is not None and (
                not isinstance(stop_signal, str)
                or not stop_signal
                or "\x00" in stop_signal
            ):
                _invalid()
            cap_add = security_sequence(item.get("cap_add"))
            cap_drop = security_sequence(item.get("cap_drop"))
            security_opt = security_sequence(item.get("security_opt"))
            if service == "oidc-egress-guard":
                if cap_add != ["NET_ADMIN"]:
                    _invalid()
            elif cap_add:
                _invalid()
            if service == "db":
                # The upstream Postgres entrypoint remains an explicit runtime
                # compatibility exception until it is exercised against the
                # target Engine.  The exception is closed, not permissive.
                if cap_drop or security_opt:
                    _invalid()
            elif cap_drop != ["ALL"] or security_opt != [
                "no-new-privileges=true"
            ]:
                _invalid()
            restart = item.get("restart")
            if restart != (
                "unless-stopped"
                if service in ("db", "matching-runtime")
                else "no"
            ):
                _invalid()
            init = item.get("init")
            if init is not (None if service == "db" else True):
                _invalid()
            sysctls = item.get("sysctls")
            if sysctls is None:
                sysctls = {}
            if not isinstance(sysctls, dict) or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in sysctls.items()
            ):
                _invalid()
            if sysctls != (
                {"net.ipv4.ip_unprivileged_port_start": "0"}
                if service == "edge"
                else {}
            ):
                _invalid()
            service_contract[service] = {
                "name": name,
                "image_reference": image_reference,
                "read_only_rootfs": item.get("read_only", False) is True,
                "network_mode": network_mode,
                "desired_network_config": desired_network_config,
                "mounts": mounts,
                "tmpfs": tmpfs,
                "ports": ports,
                "environment": dict(environment),
                "guard_environment": guard_environment,
                "healthcheck_override": (
                    dict(compose_healthcheck)
                    if compose_healthcheck is not None
                    else None
                ),
                "stop_timeout_seconds": stop_timeout_seconds,
                "api_extra_hosts": api_extra_hosts,
                "command_override": command,
                "entrypoint_override": entrypoint,
                "user_override": user,
                "working_dir_override": working_dir,
                "stop_signal_override": stop_signal,
                "cap_add": cap_add,
                "cap_drop": cap_drop,
                "security_opt": security_opt,
                "restart": restart,
                "sysctls": dict(sysctls),
                "init": init,
                "depends_on": dependency_projection(item.get("depends_on")),
                "compose_label_paths": {
                    "config_files": str(
                        snapshot.attempt_root / "resolved.compose.json"
                    ),
                    "working_dir": str(snapshot.attempt_root),
                },
            }

        if service_contract["db"]["desired_network_config"]["data"]["requested_ipv4"] != snapshot.db_data_ipv4:
            _invalid()
        if "api" not in service_contract["oidc-egress-guard"]["desired_network_config"]["app"]["aliases"]:
            _invalid()
        reviewed_image_runtime_metadata = {}
        for service, reviewed in {
            "api": {"exposed_ports": ["8000/tcp"], "volume_targets": []},
            "db": {
                "exposed_ports": ["5432/tcp"],
                "volume_targets": ["/var/lib/postgresql"],
            },
            "edge": {
                "exposed_ports": ["443/tcp", "8080/tcp"],
                "volume_targets": [],
            },
            "oidc-egress-guard": {
                "exposed_ports": [],
                "volume_targets": [],
            },
            "web": {"exposed_ports": ["3000/tcp"], "volume_targets": []},
        }.items():
            reference = service_contract[service]["image_reference"]
            previous = reviewed_image_runtime_metadata.get(reference)
            if previous is not None and previous != reviewed:
                _invalid()
            reviewed_image_runtime_metadata[reference] = reviewed
        if frozenset(reviewed_image_runtime_metadata) != frozenset(
            snapshot.image_references
        ):
            _invalid()
        return MappingProxyType(
            {
                "services": service_contract,
                "networks": network_contract,
                "volume_name": volume_name,
                "reviewed_image_runtime_metadata": (
                    reviewed_image_runtime_metadata
                ),
            }
        )
    except PrivateServerRealOidcPreflightError:
        raise
    except _release.PrivateServerRealOidcReleaseInputError:
        _invalid()
    except BaseException:
        _invalid()


def guard_binding_sha256(
    *,
    snapshot,
    container_ids: Mapping[str, str],
) -> str:
    try:
        if (
            not isinstance(container_ids, Mapping)
            or frozenset(container_ids) != frozenset(_SERVICES)
            or any(
                _CONTAINER_ID.fullmatch(value) is None
                for value in container_ids.values()
            )
            or len(set(container_ids.values())) != len(_SERVICES)
        ):
            _invalid()
        return _sha(
            _canonical(
                {
                    "format": "desire-real-oidc-guard-binding-v2",
                    "project": snapshot.project_name,
                    "api_container_id": container_ids["api"],
                    "db_container_id": container_ids["db"],
                    "guard_container_id": container_ids["oidc-egress-guard"],
                    "api_network_mode": (
                        "container:" + container_ids["oidc-egress-guard"]
                    ),
                    "api_desired_network_config": {},
                    "guard_desired_networks": ["app", "data", "oidc-egress"],
                    "guard_app_aliases": ["api"],
                    "db_data_ipv4": snapshot.db_data_ipv4,
                    "oidc_pinned_public_ipv4": snapshot.oidc_pinned_public_ipv4,
                    "oidc_egress_projection_sha256": (
                        snapshot.oidc_egress_projection_sha256
                    ),
                }
            )
        )
    except PrivateServerRealOidcPreflightError:
        raise
    except BaseException:
        _invalid()


def _projection_sha256(kind: str, value: Any) -> str:
    if kind not in _POST_CREATE_CHECKS:
        _invalid()
    return _sha(
        _canonical(
            {
                "format": "desire-real-oidc-post-create-projection-v1",
                "kind": kind,
                "value": value,
            }
        )
    )


def post_create_artifact_sha256s(
    *,
    containers: Mapping[str, Any],
    networks: Mapping[str, Any],
    postgres_volume: Mapping[str, Any],
    project_objects: Mapping[str, Any],
    guard_binding: Mapping[str, Any],
) -> Mapping[str, str]:
    """Bind every reviewed inspect summary into purpose-separated digests."""

    try:
        if (
            not isinstance(containers, Mapping)
            or frozenset(containers) != frozenset(_SERVICES)
            or not isinstance(networks, Mapping)
            or not isinstance(postgres_volume, Mapping)
            or not isinstance(project_objects, Mapping)
            or not isinstance(guard_binding, Mapping)
        ):
            _invalid()
        values = {
            "container_images": {
                service: {
                    "id": containers[service]["id"],
                    "image_reference": containers[service]["image_reference"],
                    "image_id": containers[service]["image_id"],
                }
                for service in _SERVICES
            },
            "container_labels": {
                service: {
                    "id": containers[service]["id"],
                    "required_labels": containers[service]["required_labels"],
                    "labels_sha256": containers[service]["labels_sha256"],
                }
                for service in _SERVICES
            },
            "mount_projection": {
                service: {
                    "id": containers[service]["id"],
                    "sha256": containers[service]["mounts_sha256"],
                }
                for service in _SERVICES
            },
            "network_projection": {
                "containers": {
                    service: {
                        "id": containers[service]["id"],
                        "sha256": containers[service]["networks_sha256"],
                    }
                    for service in _SERVICES
                },
                "networks": dict(networks),
            },
            "port_projection": {
                service: {
                    "id": containers[service]["id"],
                    "sha256": containers[service]["ports_sha256"],
                }
                for service in _SERVICES
            },
            "network_namespace_projection": {
                service: {
                    "id": containers[service]["id"],
                    "sha256": containers[service]["netns_sha256"],
                }
                for service in _SERVICES
            },
            "guard_binding_projection": dict(guard_binding),
            "project_object_inventory": {
                "project_objects": dict(project_objects),
                "postgres_volume": dict(postgres_volume),
                "container_inspect_sha256": {
                    service: containers[service]["inspect_sha256"]
                    for service in _SERVICES
                },
            },
        }
        return MappingProxyType(
            {kind: _projection_sha256(kind, values[kind]) for kind in values}
        )
    except PrivateServerRealOidcPreflightError:
        raise
    except BaseException:
        _invalid()


def collected_post_create_summaries(
    semantic_projection: Mapping[str, Any],
) -> tuple[
    Mapping[str, Any],
    Mapping[str, Any],
    Mapping[str, Any],
    Mapping[str, Any],
]:
    """Derive the legacy-compatible safe summaries from a v2 projection."""

    try:
        projection = _closed(
            semantic_projection,
            (
                "format",
                "containers",
                "networks",
                "postgres_volume",
                "images",
                "image_runtime_metadata",
                "project_objects",
            ),
        )
        if projection["format"] != "desire-real-oidc-post-create-semantic-projection-v1":
            _invalid()
        projected_containers = _closed(projection["containers"], _SERVICES)
        containers = {}
        for service in _SERVICES:
            item = projected_containers[service]
            if not isinstance(item, dict):
                _invalid()
            required_labels = item.get("required_labels")
            containers[service] = {
                "id": item.get("id"),
                "name": item.get("name"),
                "image_reference": item.get("image_reference"),
                "image_id": item.get("image_id"),
                "state": "CREATED_NOT_STARTED",
                "required_labels": required_labels,
                "labels_sha256": _projection_sha256(
                    "container_labels",
                    {
                        "service": service,
                        "required_labels": required_labels,
                    },
                ),
                "mounts_sha256": _projection_sha256(
                    "mount_projection",
                    {
                        "service": service,
                        "mounts": item.get("mounts"),
                        "tmpfs": item.get("tmpfs"),
                        "mount_transport": item.get("mount_transport"),
                        "image_volume_target_count": item.get(
                            "runtime_metadata", {}
                        ).get("image_volume_target_count"),
                        "image_volume_targets_explicitly_mounted": item.get(
                            "runtime_metadata", {}
                        ).get("image_volume_targets_explicitly_mounted"),
                        "container_volumes_match": item.get(
                            "runtime_metadata", {}
                        ).get("container_volumes_match"),
                    },
                ),
                "networks_sha256": _projection_sha256(
                    "network_projection",
                    {
                        "service": service,
                        "desired_network_config": item.get(
                            "desired_network_config"
                        ),
                    },
                ),
                "ports_sha256": _projection_sha256(
                    "port_projection",
                    {
                        "service": service,
                        "port_bindings": item.get("port_bindings"),
                        "effective_exposed_ports": item.get(
                            "runtime_metadata", {}
                        ).get("effective_exposed_ports"),
                        "container_exposed_ports_match": item.get(
                            "runtime_metadata", {}
                        ).get("container_exposed_ports_match"),
                        "created_port_map_empty": item.get(
                            "runtime_metadata", {}
                        ).get("created_port_map_empty"),
                    },
                ),
                "netns_sha256": _projection_sha256(
                    "network_namespace_projection",
                    {
                        "service": service,
                        "network_mode": item.get("network_mode"),
                    },
                ),
                "inspect_sha256": _sha(
                    _canonical(
                        {
                            "format": "desire-real-oidc-safe-container-inspect-v1",
                            "service": service,
                            "value": item,
                        }
                    )
                ),
            }

        projected_networks = _closed(
            projection["networks"],
            ("app", "data", "ingress", "oidc-egress"),
        )
        networks = {}
        for logical in ("app", "data", "ingress", "oidc-egress"):
            item = projected_networks[logical]
            if not isinstance(item, dict):
                _invalid()
            networks[logical] = {
                "id": item.get("id"),
                "name": item.get("name"),
                "inspect_sha256": _sha(
                    _canonical(
                        {
                            "format": "desire-real-oidc-safe-network-inspect-v1",
                            "logical": logical,
                            "value": item,
                        }
                    )
                ),
            }

        projected_volume = projection["postgres_volume"]
        if not isinstance(projected_volume, dict):
            _invalid()
        volume = {
            "name": projected_volume.get("name"),
            "state": "PRESENT_PRESERVE",
            "inspect_sha256": _sha(
                _canonical(
                    {
                        "format": "desire-real-oidc-safe-volume-inspect-v1",
                        "value": projected_volume,
                    }
                )
            ),
        }
        objects = projection["project_objects"]
        if not isinstance(objects, dict):
            _invalid()
        return (
            MappingProxyType(containers),
            MappingProxyType(networks),
            MappingProxyType(volume),
            MappingProxyType(dict(objects)),
        )
    except PrivateServerRealOidcPreflightError:
        raise
    except BaseException:
        _invalid()


def _collected_purpose_sha256(purpose: str, value: Any) -> str:
    try:
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
    except PrivateServerRealOidcPreflightError:
        raise
    except BaseException:
        _invalid()


def _safe_exposed_port_list(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) != len(set(value)):
        _invalid()
    normalized = []
    for item in value:
        match = _EXPOSED_PORT.fullmatch(item) if isinstance(item, str) else None
        if match is None or int(match.group("port")) > 65535:
            _invalid()
        normalized.append(item)
    expected_order = sorted(
        normalized,
        key=lambda item: (
            int(item.split("/", 1)[0]),
            item.split("/", 1)[1],
        ),
    )
    if normalized != expected_order:
        _invalid()
    return normalized


def _validate_collected_semantic_projection(
    value: Any,
    *,
    snapshot,
    image_ids: Mapping[str, str],
) -> tuple[Mapping[str, Any], Mapping[str, str], Mapping[str, str]]:
    projection = _closed(
        value,
        (
            "format",
            "containers",
            "networks",
            "postgres_volume",
            "images",
            "image_runtime_metadata",
            "project_objects",
        ),
    )
    if (
        projection["format"]
        != "desire-real-oidc-post-create-semantic-projection-v1"
        or projection["images"] != dict(image_ids)
    ):
        _invalid()
    contract = _post_create_compose_contract(snapshot)
    raw_image_runtime = _closed(
        projection["image_runtime_metadata"], image_ids.keys()
    )
    image_runtime_metadata = {}
    for reference in image_ids:
        item = _closed(
            raw_image_runtime[reference],
            (
                "exposed_ports",
                "exposed_port_count",
                "volume_target_count",
                "environment_entry_count",
                "healthcheck_present",
                "healthcheck_field_presence",
            ),
        )
        exposed_ports = _safe_exposed_port_list(item["exposed_ports"])
        healthcheck_field_presence = _closed(
            item["healthcheck_field_presence"], _HEALTHCHECK_FIELDS
        )
        reviewed = contract["reviewed_image_runtime_metadata"][reference]
        if (
            type(item["exposed_port_count"]) is not int
            or item["exposed_port_count"] != len(exposed_ports)
            or type(item["volume_target_count"]) is not int
            or not 0 <= item["volume_target_count"] <= 64
            or type(item["environment_entry_count"]) is not int
            or not 0 <= item["environment_entry_count"] <= 512
            or type(item["healthcheck_present"]) is not bool
            or any(type(present) is not bool for present in healthcheck_field_presence.values())
            or not item["healthcheck_present"]
            and any(healthcheck_field_presence.values())
            or exposed_ports != reviewed["exposed_ports"]
            or item["volume_target_count"] != len(reviewed["volume_targets"])
        ):
            _invalid()
        image_runtime_metadata[reference] = {
            **dict(item),
            "healthcheck_field_presence": dict(healthcheck_field_presence),
        }
    containers = _closed(projection["containers"], _SERVICES)
    container_ids = {}
    expected_state = {
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
    }
    for service in _SERVICES:
        item = _closed(
            containers[service],
            (
                "id",
                "name",
                "image_reference",
                "image_id",
                "state",
                "required_labels",
                "compose_label_projection",
                "mounts",
                "tmpfs",
                "mount_transport",
                "network_mode",
                "desired_network_config",
                "port_bindings",
                "runtime_metadata",
                "security",
            ),
        )
        expected = contract["services"][service]
        identifier = item["id"]
        expected_labels = {
            "com.docker.compose.project": snapshot.project_name,
            "com.docker.compose.service": service,
            "com.docker.compose.oneoff": "False",
            "com.docker.compose.container-number": "1",
        }
        compose_labels = _closed(
            item["compose_label_projection"],
            (
                "config_hash_shape_valid",
                "image_id",
                "compose_version",
                "depends_on",
                "path_labels_match",
                "image_labels_match",
            ),
        )
        expected_process = {
            "cmd_source": (
                "COMPOSE_EXPLICIT"
                if expected["command_override"] is not None
                else "IMAGE_INHERITED"
            ),
            "entrypoint_source": (
                "COMPOSE_EXPLICIT"
                if expected["entrypoint_override"] is not None
                else "IMAGE_INHERITED"
            ),
            "user_source": (
                "COMPOSE_EXPLICIT"
                if expected["user_override"] is not None
                else "IMAGE_INHERITED"
            ),
            "working_dir_source": (
                "COMPOSE_EXPLICIT"
                if expected["working_dir_override"] is not None
                else "IMAGE_INHERITED"
            ),
            "stop_signal_source": (
                "COMPOSE_EXPLICIT"
                if expected["stop_signal_override"] is not None
                else "IMAGE_INHERITED"
            ),
            "cmd_matches_effective": True,
            "entrypoint_matches_effective": True,
            "user_matches_effective": True,
            "working_dir_matches_effective": True,
            "stop_signal_matches_effective": True,
        }
        security = _closed(
            item["security"],
            (
                "privileged",
                "auto_remove",
                "publish_all_ports",
                "read_only_rootfs",
                "devices",
                "device_requests",
                "supplementary_groups",
                "private_pid_mode",
                "private_ipc_mode",
                "private_uts_mode",
                "default_userns_mode",
                "api_extra_hosts_sha256",
                "environment",
                "healthcheck",
                "stop_timeout",
                "process",
                "cap_add",
                "cap_drop",
                "security_opt",
                "restart_policy",
                "sysctls",
                "init",
                "extra_hosts_match",
                "postgres_entrypoint_capability_exception",
            ),
        )
        image_metadata = image_runtime_metadata[expected["image_reference"]]
        environment_projection = _closed(
            security["environment"],
            (
                "source",
                "image_entry_count",
                "compose_entry_count",
                "compose_override_count",
                "inherited_image_entry_count",
                "effective_entry_count",
                "exact_map_match",
                "proxy_keys_absent",
            ),
        )
        image_environment_count = image_metadata["environment_entry_count"]
        compose_environment_count = len(expected["environment"])
        override_count = environment_projection["compose_override_count"]
        if (
            type(override_count) is not int
            or not 0 <= override_count <= min(
                image_environment_count, compose_environment_count
            )
        ):
            _invalid()
        inherited_environment_count = image_environment_count - override_count
        effective_environment_count = (
            image_environment_count + compose_environment_count - override_count
        )
        environment_source = _environment_merge_source(
            compose_entry_count=compose_environment_count,
            image_entry_count=image_environment_count,
            inherited_image_entry_count=inherited_environment_count,
        )
        expected_environment_projection = {
            "source": environment_source,
            "image_entry_count": image_environment_count,
            "compose_entry_count": compose_environment_count,
            "compose_override_count": override_count,
            "inherited_image_entry_count": inherited_environment_count,
            "effective_entry_count": effective_environment_count,
            "exact_map_match": True,
            "proxy_keys_absent": True,
        }
        healthcheck_projection = _closed(
            security["healthcheck"],
            (
                "source",
                "field_sources",
                "matches_effective",
                "unknown_fields_absent",
            ),
        )
        healthcheck_field_sources = _closed(
            healthcheck_projection["field_sources"], _HEALTHCHECK_FIELDS
        )
        compose_healthcheck = expected["healthcheck_override"]
        image_healthcheck_present = image_metadata["healthcheck_present"]
        image_healthcheck_fields = image_metadata[
            "healthcheck_field_presence"
        ]
        if compose_healthcheck is None and not image_healthcheck_present:
            healthcheck_source = "ABSENT"
            expected_healthcheck_field_sources = {
                field: "ABSENT" for field in _HEALTHCHECK_FIELDS
            }
        else:
            expected_healthcheck_field_sources = {}
            for field in _HEALTHCHECK_FIELDS:
                if compose_healthcheck is not None and compose_healthcheck[field]:
                    source = "COMPOSE_EXPLICIT"
                elif image_healthcheck_fields[field]:
                    source = "IMAGE_INHERITED"
                else:
                    source = "UNSET_ZERO"
                expected_healthcheck_field_sources[field] = source
            if compose_healthcheck is None:
                healthcheck_source = "IMAGE_INHERITED"
            elif "IMAGE_INHERITED" in expected_healthcheck_field_sources.values():
                healthcheck_source = "COMPOSE_WITH_IMAGE_DEFAULTS"
            else:
                healthcheck_source = "COMPOSE_EXPLICIT"
        expected_healthcheck_projection = {
            "source": healthcheck_source,
            "field_sources": expected_healthcheck_field_sources,
            "matches_effective": True,
            "unknown_fields_absent": True,
        }
        stop_timeout_projection = _closed(
            security["stop_timeout"],
            ("present", "source", "matches_effective"),
        )
        expected_stop_timeout_projection = (
            {
                "present": False,
                "source": "ABSENT",
                "matches_effective": True,
            }
            if expected["stop_timeout_seconds"] is None
            else {
                "present": True,
                "source": "COMPOSE_EXPLICIT",
                "matches_effective": True,
            }
        )
        expected_security_opt = sorted(
            "no-new-privileges:true"
            if value == "no-new-privileges=true"
            else value
            for value in expected["security_opt"]
        )
        safe_mounts = [
            {
                key: mount[key]
                for key in (
                    "type",
                    "destination",
                    "read_only",
                    "source_kind",
                    "source_name",
                )
            }
            for mount in expected["mounts"]
        ]
        expected_host_config_mount_count = sum(
            mount["type"] == "bind" for mount in expected["mounts"]
        )
        expected_host_config_bind_count = sum(
            mount["type"] == "volume" for mount in expected["mounts"]
        )
        expected_mount_transport = {
            "top_mount_count": len(expected["mounts"]),
            "top_mounts_match": True,
            "host_config_mount_count": expected_host_config_mount_count,
            "host_config_mounts_match": True,
            "host_config_bind_count": expected_host_config_bind_count,
            "host_config_binds_match": True,
            "named_volume_mountpoint_match_count": (
                expected_host_config_bind_count
            ),
        }
        expected_mode = expected["network_mode"]
        if service == "api":
            # Filled after all IDs have been parsed below.
            expected_mode = None
        published_port_keys = {
            f"{port['container_port']}/{port['protocol']}"
            for port in expected["ports"]
        }
        effective_exposed_ports = sorted(
            set(image_metadata["exposed_ports"]) | published_port_keys,
            key=lambda port: (
                int(port.split("/", 1)[0]),
                port.split("/", 1)[1],
            ),
        )
        expected_runtime_metadata = {
            "effective_exposed_ports": effective_exposed_ports,
            "effective_exposed_port_count": len(effective_exposed_ports),
            "published_port_count": len(expected["ports"]),
            "image_volume_target_count": image_metadata["volume_target_count"],
            "image_volume_targets_explicitly_mounted": True,
            "container_exposed_ports_match": True,
            "container_volumes_match": True,
            "created_port_map_empty": True,
        }
        if (
            _CONTAINER_ID.fullmatch(identifier or "") is None
            or item["name"] != expected["name"]
            or item["image_reference"] != expected["image_reference"]
            or item["image_id"] != image_ids[expected["image_reference"]]
            or item["state"] != expected_state
            or item["required_labels"] != expected_labels
            or compose_labels
            != {
                "config_hash_shape_valid": True,
                "image_id": image_ids[expected["image_reference"]],
                "compose_version": _COMPOSE_VERSION,
                "depends_on": expected["depends_on"],
                "path_labels_match": True,
                "image_labels_match": True,
            }
            or item["mounts"] != safe_mounts
            or item["tmpfs"] != expected["tmpfs"]
            or item["mount_transport"] != expected_mount_transport
            or (service != "api" and item["network_mode"] != expected_mode)
            or item["port_bindings"] != expected["ports"]
            or item["runtime_metadata"] != expected_runtime_metadata
            or security
            != {
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
                "api_extra_hosts_sha256": (
                    _collected_purpose_sha256(
                        "api-reviewed-db-extra-hosts", expected["api_extra_hosts"]
                    )
                    if service == "api"
                    else None
                ),
                "environment": expected_environment_projection,
                "healthcheck": expected_healthcheck_projection,
                "stop_timeout": expected_stop_timeout_projection,
                "process": expected_process,
                "cap_add": expected["cap_add"],
                "cap_drop": expected["cap_drop"],
                "security_opt": expected_security_opt,
                "restart_policy": {
                    "Name": expected["restart"],
                    "MaximumRetryCount": 0,
                },
                "sysctls": expected["sysctls"],
                "init": expected["init"],
                "extra_hosts_match": True,
                "postgres_entrypoint_capability_exception": service == "db",
            }
        ):
            _invalid()
        container_ids[service] = identifier
    if len(set(container_ids.values())) != len(_SERVICES):
        _invalid()

    networks = _closed(
        projection["networks"], ("app", "data", "ingress", "oidc-egress")
    )
    network_ids = {}
    for logical in ("app", "data", "ingress", "oidc-egress"):
        item = _closed(
            networks[logical],
            (
                "id",
                "name",
                "driver",
                "scope",
                "internal",
                "enable_ipv6",
                "subnet",
                "required_labels",
                "containers_empty",
            ),
        )
        expected = contract["networks"][logical]
        identifier = item["id"]
        if (
            _CONTAINER_ID.fullmatch(identifier or "") is None
            or item["name"] != expected["name"]
            or item["driver"] != "bridge"
            or item["scope"] != "local"
            or item["internal"] is not expected["internal"]
            or item["enable_ipv6"] is not False
            or item["subnet"] != expected["subnet"]
            or item["required_labels"]
            != {
                "com.docker.compose.project": snapshot.project_name,
                "com.docker.compose.network": logical,
            }
            or item["containers_empty"] is not True
        ):
            _invalid()
        network_ids[logical] = identifier
    if len(set(network_ids.values())) != 4:
        _invalid()

    for service in _SERVICES:
        item = containers[service]
        expected = contract["services"][service]
        if service == "api":
            if (
                item["network_mode"]
                != "container:" + container_ids["oidc-egress-guard"]
                or item["desired_network_config"] != {}
            ):
                _invalid()
            continue
        desired_network_config = _closed(
            item["desired_network_config"], expected["desired_network_config"]
        )
        for logical, expected_endpoint in expected[
            "desired_network_config"
        ].items():
            endpoint = _closed(
                desired_network_config[logical],
                (
                    "requested_ipv4",
                    "ipam_config_present",
                    "aliases",
                    "runtime_network_id_unassigned",
                ),
            )
            if endpoint != {
                "requested_ipv4": expected_endpoint["requested_ipv4"],
                "ipam_config_present": expected_endpoint[
                    "ipam_config_present"
                ],
                "aliases": expected_endpoint["aliases"],
                "runtime_network_id_unassigned": True,
            }:
                _invalid()

    if (
        containers["db"]["desired_network_config"]["data"]["requested_ipv4"]
        != snapshot.db_data_ipv4
        or "api"
        not in containers["oidc-egress-guard"]["desired_network_config"][
            "app"
        ]["aliases"]
    ):
        _invalid()

    volume = _closed(
        projection["postgres_volume"],
        (
            "name",
            "driver",
            "scope",
            "required_labels",
        ),
    )
    if (
        volume["name"] != contract["volume_name"]
        or volume["driver"] != "local"
        or volume["scope"] != "local"
        or volume["required_labels"]
        != {
            "com.docker.compose.project": snapshot.project_name,
            "com.docker.compose.volume": "postgres-data",
        }
    ):
        _invalid()
    objects = _closed(
        projection["project_objects"],
        (
            "container_ids",
            "network_ids",
            "volume_names",
            "extra_container_ids",
            "extra_network_ids",
            "extra_volume_names",
        ),
    )
    if objects != {
        "container_ids": sorted(container_ids.values()),
        "network_ids": sorted(network_ids.values()),
        "volume_names": [contract["volume_name"]],
        "extra_container_ids": [],
        "extra_network_ids": [],
        "extra_volume_names": [],
    }:
        _invalid()
    return projection, MappingProxyType(container_ids), MappingProxyType(network_ids)


def _validate_collected_post_create_evidence(
    raw: bytes,
    document: Mapping[str, Any],
    *,
    snapshot,
    create_plan_sha256: str,
    image_ids: Mapping[str, str],
) -> RealOidcPostCreateEvidence:
    document = _closed(
        document,
        (
            "format",
            "status",
            "authority",
            "action",
            "project",
            "snapshot_sha256",
            "manifest_device",
            "manifest_inode",
            "compose_sha256",
            "oidc_pinned_public_ipv4",
            "db_data_ipv4",
            "oidc_egress_projection_sha256",
            "create_plan_sha256",
            "docker",
            "collection",
            "semantic_projection",
            "containers",
            "networks",
            "postgres_volume",
            "project_objects",
            "guard_binding",
            "checks",
            "artifacts",
            "execute_blockers",
        ),
    )
    docker = _closed(
        document["docker"],
        ("endpoint", "reviewed_compose_version", "inspect_commands_sha256"),
    )
    collection = _closed(
        document["collection"],
        (
            "status",
            "collection_binding_sha256",
            "command_count",
            "command_attempts",
            "stable_discovery_passes",
            "retries",
            "stderr_policy",
            "raw_inspect_persisted",
            "raw_inspect_reflected",
            "semantic_projection_sha256",
        ),
    )
    projection, container_ids, network_ids = _validate_collected_semantic_projection(
        document["semantic_projection"], snapshot=snapshot, image_ids=image_ids
    )
    containers, networks, volume, objects = collected_post_create_summaries(
        projection
    )
    guard_reference = projection["containers"]["oidc-egress-guard"][
        "image_reference"
    ]
    binding_sha256 = guard_binding_sha256(
        snapshot=snapshot,
        container_ids=container_ids,
    )
    guard = {
        "service": "oidc-egress-guard",
        "container_id": container_ids["oidc-egress-guard"],
        "image_id": image_ids[guard_reference],
        "api_container_id": container_ids["api"],
        "db_container_id": container_ids["db"],
        "api_network_mode": "container:" + container_ids["oidc-egress-guard"],
        "api_desired_network_config": {},
        "guard_desired_networks": ["app", "data", "oidc-egress"],
        "guard_app_aliases": ["api"],
        "db_data_ipv4": snapshot.db_data_ipv4,
        "oidc_pinned_public_ipv4": snapshot.oidc_pinned_public_ipv4,
        "oidc_egress_projection_sha256": snapshot.oidc_egress_projection_sha256,
        "binding_sha256": binding_sha256,
        "ruleset_state": "NOT_INSTALLED_NOT_STARTED",
    }
    expected_binding = post_create_collection_binding_sha256(
        snapshot, create_plan_sha256=create_plan_sha256, image_ids=image_ids
    )
    expected_artifacts = post_create_artifact_sha256s(
        containers=containers,
        networks=networks,
        postgres_volume=volume,
        project_objects=objects,
        guard_binding=guard,
    )
    if (
        document["format"] != "desire-real-oidc-post-create-evidence-v2"
        or document["status"]
        != "COLLECTED_BASELINE_PROJECTION_VALIDATED_NOT_AUTHORITY"
        or document["authority"] != "NOT_AUTHORITY"
        or document["action"] != "START_CREATED_CONTAINERS"
        or document["project"] != snapshot.project_name
        or document["snapshot_sha256"] != snapshot.snapshot_sha256
        or document["manifest_device"] != snapshot.manifest_device
        or document["manifest_inode"] != snapshot.manifest_inode
        or document["compose_sha256"] != snapshot.compose_sha256
        or document["oidc_pinned_public_ipv4"]
        != snapshot.oidc_pinned_public_ipv4
        or document["db_data_ipv4"] != snapshot.db_data_ipv4
        or document["oidc_egress_projection_sha256"]
        != snapshot.oidc_egress_projection_sha256
        or document["create_plan_sha256"] != create_plan_sha256
        or docker
        != {
            "endpoint": _DOCKER_ENDPOINT,
            "reviewed_compose_version": _COMPOSE_VERSION,
            "inspect_commands_sha256": post_create_inspect_commands_sha256(
                snapshot
            ),
        }
        or collection
        != {
            "status": "COLLECTED_ONCE_BASELINE_PROJECTION_VALIDATED",
            "collection_binding_sha256": expected_binding,
            "command_count": len(post_create_inspect_commands(snapshot)),
            "command_attempts": len(post_create_inspect_commands(snapshot)),
            "stable_discovery_passes": 2,
            "retries": 0,
            "stderr_policy": "EMPTY_EACH_COMMAND",
            "raw_inspect_persisted": False,
            "raw_inspect_reflected": False,
            "semantic_projection_sha256": _collected_purpose_sha256(
                "semantic-projection", projection
            ),
        }
        or document["containers"] != dict(containers)
        or document["networks"] != dict(networks)
        or document["postgres_volume"] != dict(volume)
        or document["project_objects"] != dict(objects)
        or document["guard_binding"] != guard
        or document["checks"]
        != {
            key: "COLLECTED_BASELINE_PROJECTION_VALIDATED"
            for key in _POST_CREATE_CHECKS
        }
        or document["artifacts"] != dict(expected_artifacts)
        or document["execute_blockers"]
        != list(_COLLECTED_START_EXECUTE_BLOCKERS)
    ):
        _invalid()
    return RealOidcPostCreateEvidence(
        raw=raw,
        sha256=_sha(raw),
        project_name=snapshot.project_name,
        create_plan_sha256=create_plan_sha256,
        container_ids=container_ids,
        network_ids=network_ids,
        image_ids=MappingProxyType(dict(image_ids)),
        guard_binding_sha256=binding_sha256,
        execute_blockers=tuple(_COLLECTED_START_EXECUTE_BLOCKERS),
        collection_status="COLLECTED_BASELINE_PROJECTION_VALIDATED_NOT_AUTHORITY",
    )


def validate_post_create_evidence(
    raw: bytes,
    *,
    snapshot,
    create_plan_sha256: str,
    image_ids: Mapping[str, str],
) -> RealOidcPostCreateEvidence:
    """Validate a closed, reviewed create-only Docker inspect projection."""

    try:
        _snapshot_contract(snapshot)
        if _SHA256.fullmatch(create_plan_sha256) is None:
            _invalid()
        if (
            not isinstance(image_ids, Mapping)
            or frozenset(image_ids) != frozenset(snapshot.image_references)
            or any(_IMAGE_ID.fullmatch(value) is None for value in image_ids.values())
            or len(set(image_ids.values())) != 5
        ):
            _invalid()
        service_images = _service_image_references(snapshot)
        parsed = _parse(raw)
        if (
            isinstance(parsed, dict)
            and parsed.get("format")
            == "desire-real-oidc-post-create-evidence-v2"
        ):
            return _validate_collected_post_create_evidence(
                raw,
                parsed,
                snapshot=snapshot,
                create_plan_sha256=create_plan_sha256,
                image_ids=image_ids,
            )
        document = _closed(
            parsed,
            (
                "format",
                "status",
                "action",
                "project",
                "snapshot_sha256",
                "manifest_device",
                "manifest_inode",
                "compose_sha256",
                "oidc_pinned_public_ipv4",
                "db_data_ipv4",
                "oidc_egress_projection_sha256",
                "create_plan_sha256",
                "docker",
                "containers",
                "networks",
                "postgres_volume",
                "project_objects",
                "guard_binding",
                "checks",
                "artifacts",
                "execute_blockers",
            ),
        )
        docker = _closed(document["docker"], ("endpoint", "compose_version"))
        containers = _closed(document["containers"], _SERVICES)
        container_ids = {}
        inspect_hashes = set()
        for service in _SERVICES:
            item = _closed(
                containers[service],
                (
                    "id",
                    "name",
                    "image_reference",
                    "image_id",
                    "state",
                    "required_labels",
                    "labels_sha256",
                    "mounts_sha256",
                    "networks_sha256",
                    "ports_sha256",
                    "netns_sha256",
                    "inspect_sha256",
                ),
            )
            labels = _closed(
                item["required_labels"],
                (
                    "com.docker.compose.project",
                    "com.docker.compose.service",
                    "com.docker.compose.oneoff",
                    "com.docker.compose.container-number",
                ),
            )
            reference = service_images[service]
            expected_labels_sha256 = _projection_sha256(
                "container_labels",
                {"service": service, "required_labels": dict(labels)},
            )
            if (
                _CONTAINER_ID.fullmatch(item.get("id", "")) is None
                or item["name"]
                != snapshot.project_name + "-" + service + "-1"
                or item["image_reference"] != reference
                or item["image_id"] != image_ids[reference]
                or item["state"] != "CREATED_NOT_STARTED"
                or labels
                != {
                    "com.docker.compose.project": snapshot.project_name,
                    "com.docker.compose.service": service,
                    "com.docker.compose.oneoff": "False",
                    "com.docker.compose.container-number": "1",
                }
                or item["labels_sha256"] != expected_labels_sha256
                or any(
                    _SHA256.fullmatch(item.get(field, "")) is None
                    for field in (
                        "labels_sha256",
                        "mounts_sha256",
                        "networks_sha256",
                        "ports_sha256",
                        "netns_sha256",
                        "inspect_sha256",
                    )
                )
            ):
                _invalid()
            container_ids[service] = item["id"]
            inspect_hashes.add(item["inspect_sha256"])
        if len(set(container_ids.values())) != len(_SERVICES) or len(inspect_hashes) != len(_SERVICES):
            _invalid()

        resource_names = fresh_resource_names(snapshot.project_name)
        networks = _closed(document["networks"], resource_names.keys())
        network_ids = {}
        for logical, expected_name in resource_names.items():
            item = _closed(networks[logical], ("id", "name", "inspect_sha256"))
            if (
                _CONTAINER_ID.fullmatch(item.get("id", "")) is None
                or item["name"] != expected_name
                or _SHA256.fullmatch(item.get("inspect_sha256", "")) is None
            ):
                _invalid()
            network_ids[logical] = item["id"]
        if len(set(network_ids.values())) != len(resource_names):
            _invalid()

        volume = _closed(
            document["postgres_volume"],
            ("name", "state", "inspect_sha256"),
        )
        volume_name = snapshot.project_name + "_postgres-data"
        objects = _closed(
            document["project_objects"],
            (
                "container_ids",
                "network_ids",
                "volume_names",
                "extra_container_ids",
                "extra_network_ids",
                "extra_volume_names",
            ),
        )
        guard = _closed(
            document["guard_binding"],
            (
                "service",
                "container_id",
                "image_id",
                "api_container_id",
                "db_container_id",
                "api_network_mode",
                "api_desired_network_config",
                "guard_desired_networks",
                "guard_app_aliases",
                "db_data_ipv4",
                "oidc_pinned_public_ipv4",
                "oidc_egress_projection_sha256",
                "binding_sha256",
                "ruleset_state",
            ),
        )
        expected_guard_binding = guard_binding_sha256(
            snapshot=snapshot,
            container_ids=container_ids,
        )
        checks = _closed(document["checks"], _POST_CREATE_CHECKS)
        artifacts = _closed(document["artifacts"], _POST_CREATE_CHECKS)
        guard_reference = service_images["oidc-egress-guard"]
        if (
            document["format"]
            != "desire-real-oidc-post-create-evidence-v1"
            or document["status"] != "REVIEWED_NOT_EXECUTED"
            or document["action"] != "START_CREATED_CONTAINERS"
            or document["project"] != snapshot.project_name
            or document["snapshot_sha256"] != snapshot.snapshot_sha256
            or document["manifest_device"] != snapshot.manifest_device
            or document["manifest_inode"] != snapshot.manifest_inode
            or document["compose_sha256"] != snapshot.compose_sha256
            or document["oidc_pinned_public_ipv4"]
            != snapshot.oidc_pinned_public_ipv4
            or document["db_data_ipv4"] != snapshot.db_data_ipv4
            or document["oidc_egress_projection_sha256"]
            != snapshot.oidc_egress_projection_sha256
            or document["create_plan_sha256"] != create_plan_sha256
            or docker
            != {"endpoint": _DOCKER_ENDPOINT, "compose_version": _COMPOSE_VERSION}
            or volume
            != {
                "name": volume_name,
                "state": "PRESENT_PRESERVE",
                "inspect_sha256": volume.get("inspect_sha256"),
            }
            or _SHA256.fullmatch(volume.get("inspect_sha256", "")) is None
            or objects["container_ids"] != sorted(container_ids.values())
            or objects["network_ids"] != sorted(network_ids.values())
            or objects["volume_names"] != [volume_name]
            or objects["extra_container_ids"] != []
            or objects["extra_network_ids"] != []
            or objects["extra_volume_names"] != []
            or guard
            != {
                "service": "oidc-egress-guard",
                "container_id": container_ids["oidc-egress-guard"],
                "image_id": image_ids[guard_reference],
                "api_container_id": container_ids["api"],
                "db_container_id": container_ids["db"],
                "api_network_mode": (
                    "container:" + container_ids["oidc-egress-guard"]
                ),
                "api_desired_network_config": {},
                "guard_desired_networks": ["app", "data", "oidc-egress"],
                "guard_app_aliases": ["api"],
                "db_data_ipv4": snapshot.db_data_ipv4,
                "oidc_pinned_public_ipv4": snapshot.oidc_pinned_public_ipv4,
                "oidc_egress_projection_sha256": (
                    snapshot.oidc_egress_projection_sha256
                ),
                "binding_sha256": expected_guard_binding,
                "ruleset_state": "NOT_INSTALLED_NOT_STARTED",
            }
            or checks != {key: "REVIEWED" for key in _POST_CREATE_CHECKS}
            or artifacts
            != post_create_artifact_sha256s(
                containers=containers,
                networks=networks,
                postgres_volume=volume,
                project_objects=objects,
                guard_binding=guard,
            )
            or document["execute_blockers"] != list(_START_EXECUTE_BLOCKERS)
        ):
            _invalid()
        return RealOidcPostCreateEvidence(
            raw=raw,
            sha256=_sha(raw),
            project_name=snapshot.project_name,
            create_plan_sha256=create_plan_sha256,
            container_ids=MappingProxyType(container_ids),
            network_ids=MappingProxyType(network_ids),
            image_ids=MappingProxyType(dict(image_ids)),
            guard_binding_sha256=expected_guard_binding,
            execute_blockers=tuple(_START_EXECUTE_BLOCKERS),
            collection_status="REVIEWED_NOT_EXECUTED",
        )
    except PrivateServerRealOidcPreflightError:
        raise
    except _release.PrivateServerRealOidcReleaseInputError:
        _invalid()
    except BaseException:
        _invalid()


def _read_closed(path: Path) -> bytes:
    if not isinstance(path, Path) or not path.is_absolute() or str(path) == "/":
        _invalid()
    try:
        if path.resolve(strict=True) != path:
            _invalid()
    except (OSError, RuntimeError):
        _invalid()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        _invalid()
    try:
        before = os.fstat(descriptor)
        visible = path.lstat()
        if (
            (before.st_dev, before.st_ino) != (visible.st_dev, visible.st_ino)
            or not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) not in (0o400, 0o600)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or not 0 < before.st_size <= 1024 * 1024
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
        visible_after = path.lstat()
        stable_before = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
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
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if (
            stable_before != stable_after
            or (after.st_dev, after.st_ino)
            != (visible_after.st_dev, visible_after.st_ino)
        ):
            _invalid()
        return b"".join(chunks)
    except OSError:
        _invalid()
    finally:
        os.close(descriptor)


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    import argparse

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--attempt-root")
    parser.add_argument("--evidence-file")
    try:
        arguments = parser.parse_args(tuple(sys.argv[1:] if argv is None else argv))
        if not arguments.attempt_root or not arguments.evidence_file:
            _invalid()
        snapshot, _manifest, _compose = _release.load_real_oidc_release_snapshot(
            Path(arguments.attempt_root)
        )
        evidence_path = Path(arguments.evidence_file)
        if not evidence_path.is_absolute():
            _invalid()
        validate_preflight_evidence(_read_closed(evidence_path), snapshot=snapshot)
        stdout.write(READY)
        return 0
    except (PrivateServerRealOidcPreflightError, SystemExit):
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
    "PrivateServerRealOidcPreflightError",
    "RealOidcPostCreateEvidence",
    "RealOidcPreflightEvidence",
    "fresh_check_commands",
    "fresh_check_commands_sha256",
    "fresh_container_names",
    "fresh_resource_names",
    "guard_binding_sha256",
    "image_lock_sha256",
    "post_create_artifact_sha256s",
    "collected_post_create_summaries",
    "post_create_collection_binding_sha256",
    "post_create_inspect_commands",
    "post_create_inspect_commands_sha256",
    "validate_preflight_evidence",
    "validate_post_create_evidence",
)
