#!/usr/bin/env python3
"""Build, but never execute, two real-OIDC activation plan phases.

The default action only checks an immutable snapshot.  ``create-plan`` emits
one Compose ``create`` command and starts no process.  ``start-plan`` seals an
exact-container-ID skeleton only after reviewed post-create evidence.  No
action here executes Docker.  A separate collector can form a baseline-only
NOT_AUTHORITY receipt; complete security projection, pre-start reinspection,
guard rules/health gates, and service readiness remain explicit blockers.
"""

from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
from types import MappingProxyType
from typing import Any, Mapping, NoReturn, Optional, Sequence, TextIO
from uuid import UUID


_PREFLIGHT_HELPER = Path(__file__).resolve().with_name(
    "preflight_private_server_real_oidc.py"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DOCKER = ("/usr/bin/docker", "--host", "unix:///var/run/docker.sock")

CHECKED = '{"status":"PRIVATE_SERVER_REAL_OIDC_ACTIVATION_CHECKED"}\n'
CREATE_PLANNED = (
    '{"status":"PRIVATE_SERVER_REAL_OIDC_CREATE_PLAN_READY_NOT_EXECUTED"}\n'
)
START_STAGED = (
    '{"status":"PRIVATE_SERVER_REAL_OIDC_START_PLAN_SEALED_NOT_EXECUTED"}\n'
)
PLANNED = CREATE_PLANNED
BLOCKED = (
    '{"code":"PRIVATE_SERVER_REAL_OIDC_ACTIVATION_INVALID",'
    '"status":"BLOCKED"}\n'
)


def _load_preflight():
    name = "_desire_real_oidc_preflight_for_activation"
    spec = importlib.util.spec_from_file_location(name, _PREFLIGHT_HELPER)
    if spec is None or spec.loader is None:
        raise RuntimeError("PRIVATE_SERVER_REAL_OIDC_ACTIVATION_INVALID")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_preflight = _load_preflight()
_release = _preflight._release


class PrivateServerRealOidcActivationError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("PRIVATE_SERVER_REAL_OIDC_ACTIVATION_INVALID")


@dataclass(frozen=True, repr=False)
class RealOidcActivationPlan:
    raw: bytes
    sha256: str
    project_name: str
    snapshot_sha256: str
    compose_sha256: str
    action: str
    plan_nonce: str

    def __repr__(self) -> str:
        return (
            "RealOidcActivationPlan("
            f"sha256={self.sha256!r}, project_name={self.project_name!r}, "
            f"action={self.action!r}, commands=<redacted>, status='NOT_EXECUTED')"
        )


@dataclass(frozen=True, repr=False)
class NonceClaim:
    path: Path
    sha256: str
    device: int
    inode: int

    def __repr__(self) -> str:
        return f"NonceClaim(path={str(self.path)!r}, sha256={self.sha256!r})"


@dataclass(frozen=True, repr=False)
class ExecutionStageSeal:
    root: Path
    manifest_sha256: str
    manifest_device: int
    manifest_inode: int

    def __repr__(self) -> str:
        return (
            "ExecutionStageSeal("
            f"root={str(self.root)!r}, manifest_sha256={self.manifest_sha256!r}, "
            "status='SEALED_NOT_EXECUTED')"
        )


class _DuplicateKey(ValueError):
    pass


def _invalid() -> NoReturn:
    raise PrivateServerRealOidcActivationError()


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


def _parse_canonical(raw: bytes) -> Mapping[str, Any]:
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= 1024 * 1024:
            _invalid()
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs,
            parse_float=lambda _value: _invalid(),
            parse_constant=lambda _value: _invalid(),
        )
        if not isinstance(value, dict) or _canonical(value) != raw:
            _invalid()
        return value
    except PrivateServerRealOidcActivationError:
        raise
    except BaseException:
        _invalid()


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _closed(value: Any, keys) -> Mapping[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != frozenset(keys):
        _invalid()
    return value


def _authorization(
    raw: bytes, *, snapshot, evidence
) -> tuple[Mapping[str, Any], str]:
    document = _closed(
        _parse_canonical(raw),
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
            "evidence_sha256",
            "image_lock_sha256",
            "fresh_check_commands_sha256",
            "plan_nonce",
            "one_time",
            "rollback_policy",
        ),
    )
    try:
        nonce = UUID(document["plan_nonce"])
    except (ValueError, TypeError, AttributeError):
        _invalid()
    if (
        nonce.version != 4
        or str(nonce) != document["plan_nonce"]
        or document["format"] != "desire-real-oidc-activation-authorization-v1"
        or document["status"] != "APPROVED"
        or document["action"] != "CREATE_CONTAINERS"
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
        or document["evidence_sha256"] != evidence.sha256
        or document["image_lock_sha256"]
        != _preflight.image_lock_sha256(evidence.image_ids)
        or document["fresh_check_commands_sha256"]
        != evidence.fresh_check_commands_sha256
        or document["one_time"] is not True
        or document["rollback_policy"] != "PRESERVE_POSTGRES_VOLUME"
    ):
        _invalid()
    return MappingProxyType(document), _sha(raw)


def _compose_prefix(snapshot) -> tuple[str, ...]:
    return _DOCKER + (
        "compose",
        "--project-name",
        snapshot.project_name,
        "--file",
        str(snapshot.attempt_root / "resolved.compose.json"),
    )


def _create_command(snapshot) -> tuple[str, ...]:
    compose = _compose_prefix(snapshot)
    command = compose + ("create", "--no-build", "--pull", "never")
    forbidden = frozenset(
        ("up", "run", "start", "restart", "down", "--volumes", "-v", "rm")
    )
    if forbidden.intersection(command):
        _invalid()
    return command


def build_activation_plan(
    *,
    attempt_root: Path,
    authorization_raw: bytes,
    evidence_raw: bytes,
) -> RealOidcActivationPlan:
    """Return one create-only, zero-start NOT_EXECUTED plan."""

    try:
        snapshot, _manifest, _compose = _release.load_real_oidc_release_snapshot(
            attempt_root
        )
        evidence = _preflight.validate_preflight_evidence(
            evidence_raw, snapshot=snapshot
        )
        authorization, authorization_sha256 = _authorization(
            authorization_raw, snapshot=snapshot, evidence=evidence
        )
        resources = _preflight.fresh_resource_names(snapshot.project_name)
        plan_document = {
            "format": "desire-real-oidc-create-plan-v1",
            "status": "PLANNED_NOT_EXECUTED",
            "action": "CREATE_CONTAINERS",
            "project": snapshot.project_name,
            "plan_nonce": authorization["plan_nonce"],
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
            "authorization_sha256": authorization_sha256,
            "evidence_sha256": evidence.sha256,
            "image_lock_sha256": _preflight.image_lock_sha256(evidence.image_ids),
            "image_ids": dict(evidence.image_ids),
            "fresh_resources": {
                "networks": dict(resources),
                "postgres_volume": snapshot.project_name + "_postgres-data",
                "required_state": "ABSENT",
            },
            "read_only_preflight_commands": [
                list(command) for command in _preflight.fresh_check_commands(snapshot)
            ],
            "create_command": list(_create_command(snapshot)),
            "execution": {
                "implemented": False,
                "permitted": False,
                "phase": "CREATE_ONLY_ZERO_START",
                "process_start_allowed": False,
                "image_ids_reviewed": True,
                "image_ids_enforced": False,
                "post_create_image_id_verification_required": True,
                "execute_blockers": list(_preflight._CREATE_PLAN_BLOCKERS),
            },
            "rollback": {
                "policy": "PRESERVE_POSTGRES_VOLUME",
                "delete_volume_command_allowed": False,
                "manager": "manage_private_server_real_oidc.py",
            },
        }
        raw = _canonical(plan_document)
        serialized = raw.decode("ascii")
        for forbidden in (
            "provider_access_token",
            "provider_refresh_token",
            "provider_id_token",
            "authorization_code",
            "oidc-client-secret",
            '"down"',
            '"--volumes"',
            '"-v"',
            '"run"',
            '"start"',
        ):
            if forbidden in serialized:
                _invalid()
        return RealOidcActivationPlan(
            raw=raw,
            sha256=_sha(raw),
            project_name=snapshot.project_name,
            snapshot_sha256=snapshot.snapshot_sha256,
            compose_sha256=snapshot.compose_sha256,
            action="CREATE_CONTAINERS",
            plan_nonce=authorization["plan_nonce"],
        )
    except PrivateServerRealOidcActivationError:
        raise
    except (
        _release.PrivateServerRealOidcReleaseInputError,
        _preflight.PrivateServerRealOidcPreflightError,
    ):
        _invalid()
    except BaseException:
        _invalid()


def _validated_create_plan(raw: bytes, *, snapshot) -> Mapping[str, Any]:
    document = _closed(
        _parse_canonical(raw),
        (
            "format",
            "status",
            "action",
            "project",
            "plan_nonce",
            "snapshot",
            "authorization_sha256",
            "evidence_sha256",
            "image_lock_sha256",
            "image_ids",
            "fresh_resources",
            "read_only_preflight_commands",
            "create_command",
            "execution",
            "rollback",
        ),
    )
    snapshot_value = _closed(
        document["snapshot"],
        (
            "sha256",
            "manifest_device",
            "manifest_inode",
            "compose_sha256",
            "oidc_pinned_public_ipv4",
            "db_data_ipv4",
            "oidc_egress_projection_sha256",
        ),
    )
    resources = _preflight.fresh_resource_names(snapshot.project_name)
    image_ids = document["image_ids"]
    try:
        nonce = UUID(document["plan_nonce"])
    except (TypeError, ValueError, AttributeError):
        _invalid()
    if (
        document["format"] != "desire-real-oidc-create-plan-v1"
        or document["status"] != "PLANNED_NOT_EXECUTED"
        or document["action"] != "CREATE_CONTAINERS"
        or document["project"] != snapshot.project_name
        or nonce.version != 4
        or str(nonce) != document["plan_nonce"]
        or snapshot_value
        != {
            "sha256": snapshot.snapshot_sha256,
            "manifest_device": snapshot.manifest_device,
            "manifest_inode": snapshot.manifest_inode,
            "compose_sha256": snapshot.compose_sha256,
            "oidc_pinned_public_ipv4": snapshot.oidc_pinned_public_ipv4,
            "db_data_ipv4": snapshot.db_data_ipv4,
            "oidc_egress_projection_sha256": (
                snapshot.oidc_egress_projection_sha256
            ),
        }
        or _SHA256.fullmatch(document.get("authorization_sha256", "")) is None
        or _SHA256.fullmatch(document.get("evidence_sha256", "")) is None
        or not isinstance(image_ids, dict)
        or frozenset(image_ids) != frozenset(snapshot.image_references)
        or any(
            _preflight._IMAGE_ID.fullmatch(value) is None
            for value in image_ids.values()
        )
        or len(set(image_ids.values())) != 5
        or document["image_lock_sha256"]
        != _preflight.image_lock_sha256(image_ids)
        or document["fresh_resources"]
        != {
            "networks": dict(resources),
            "postgres_volume": snapshot.project_name + "_postgres-data",
            "required_state": "ABSENT",
        }
        or document["read_only_preflight_commands"]
        != [
            list(command)
            for command in _preflight.fresh_check_commands(snapshot)
        ]
        or document["create_command"] != list(_create_command(snapshot))
        or document["execution"]
        != {
            "implemented": False,
            "permitted": False,
            "phase": "CREATE_ONLY_ZERO_START",
            "process_start_allowed": False,
            "image_ids_reviewed": True,
            "image_ids_enforced": False,
            "post_create_image_id_verification_required": True,
            "execute_blockers": list(_preflight._CREATE_PLAN_BLOCKERS),
        }
        or document["rollback"]
        != {
            "policy": "PRESERVE_POSTGRES_VOLUME",
            "delete_volume_command_allowed": False,
            "manager": "manage_private_server_real_oidc.py",
        }
    ):
        _invalid()
    return MappingProxyType(document)


def _start_authorization(
    raw: bytes,
    *,
    snapshot,
    create_plan_sha256: str,
    post_create_evidence,
) -> tuple[Mapping[str, Any], str]:
    value = _closed(
        _parse_canonical(raw),
        (
            "format",
            "status",
            "authority",
            "legacy_execution_accepted",
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
            "post_create_evidence_sha256",
            "guard_binding_sha256",
            "plan_nonce",
            "one_time",
            "rollback_policy",
        ),
    )
    try:
        nonce = UUID(value["plan_nonce"])
    except (TypeError, ValueError, AttributeError):
        _invalid()
    if (
        value["format"] != "desire-real-oidc-start-authorization-v1"
        or value["status"] != "APPROVED"
        or value["authority"] != "NOT_AUTHORITY"
        or value["legacy_execution_accepted"] is not False
        or value["action"] != "START_CREATED_CONTAINERS"
        or value["project"] != snapshot.project_name
        or value["snapshot_sha256"] != snapshot.snapshot_sha256
        or value["manifest_device"] != snapshot.manifest_device
        or value["manifest_inode"] != snapshot.manifest_inode
        or value["compose_sha256"] != snapshot.compose_sha256
        or value["oidc_pinned_public_ipv4"] != snapshot.oidc_pinned_public_ipv4
        or value["db_data_ipv4"] != snapshot.db_data_ipv4
        or value["oidc_egress_projection_sha256"]
        != snapshot.oidc_egress_projection_sha256
        or value["create_plan_sha256"] != create_plan_sha256
        or value["post_create_evidence_sha256"] != post_create_evidence.sha256
        or value["guard_binding_sha256"]
        != post_create_evidence.guard_binding_sha256
        or nonce.version != 4
        or str(nonce) != value["plan_nonce"]
        or value["one_time"] is not True
        or value["rollback_policy"] != "PRESERVE_POSTGRES_VOLUME"
    ):
        _invalid()
    return MappingProxyType(value), _sha(raw)


def _start_commands(container_ids: Mapping[str, str]) -> tuple[tuple[str, ...], ...]:
    try:
        if frozenset(container_ids) != frozenset(_preflight._SERVICES):
            _invalid()
        docker = _DOCKER + ("container",)
        commands = [
            docker + ("start", container_ids["oidc-egress-guard"]),
            docker + ("start", container_ids["db"]),
        ]
        for service in (
            "migrate",
            "taxonomy-seed",
            "online-credentials-reconcile",
            "online-credentials-verify",
            "identity-bootstrap",
        ):
            commands.append(docker + ("start", container_ids[service]))
            commands.append(docker + ("wait", container_ids[service]))
        commands.extend(
            (
                docker + ("start", container_ids["matching-runtime"]),
                docker + ("start", container_ids["api"]),
                docker + ("start", container_ids["web"]),
                docker + ("start", container_ids["edge"]),
            )
        )
        forbidden = frozenset(
            ("compose", "create", "up", "run", "--rm", "rm", "restart")
        )
        if any(forbidden.intersection(command) for command in commands):
            _invalid()
        return tuple(commands)
    except PrivateServerRealOidcActivationError:
        raise
    except BaseException:
        _invalid()


def build_start_plan(
    *,
    attempt_root: Path,
    create_plan_raw: bytes,
    post_create_evidence_raw: bytes,
    authorization_raw: bytes,
) -> RealOidcActivationPlan:
    """Build a container-ID-only start skeleton; never execute it."""

    try:
        snapshot, _manifest, _compose = _release.load_real_oidc_release_snapshot(
            attempt_root
        )
        create_plan = _validated_create_plan(create_plan_raw, snapshot=snapshot)
        create_plan_sha256 = _sha(create_plan_raw)
        post_create = _preflight.validate_post_create_evidence(
            post_create_evidence_raw,
            snapshot=snapshot,
            create_plan_sha256=create_plan_sha256,
            image_ids=create_plan["image_ids"],
        )
        authorization, authorization_sha256 = _start_authorization(
            authorization_raw,
            snapshot=snapshot,
            create_plan_sha256=create_plan_sha256,
            post_create_evidence=post_create,
        )
        post_create_document = _parse_canonical(post_create_evidence_raw)
        commands = _start_commands(post_create.container_ids)
        one_shot_ids = {
            service: post_create.container_ids[service]
            for service in (
                "migrate",
                "taxonomy-seed",
                "online-credentials-reconcile",
                "online-credentials-verify",
                "identity-bootstrap",
            )
        }
        document = {
            "format": "desire-real-oidc-start-plan-v1",
            "status": "SEALED_PLAN_NOT_EXECUTED",
            "authority": "NOT_AUTHORITY",
            "legacy_execution_accepted": False,
            "action": "START_CREATED_CONTAINERS",
            "project": snapshot.project_name,
            "plan_nonce": authorization["plan_nonce"],
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
            "create_plan_sha256": create_plan_sha256,
            "post_create_evidence_sha256": post_create.sha256,
            "post_create_collection_status": post_create.collection_status,
            "authorization_sha256": authorization_sha256,
            "guard_binding_sha256": post_create.guard_binding_sha256,
            "bound_container_ids": dict(post_create.container_ids),
            "bound_network_ids": dict(post_create.network_ids),
            "bound_image_ids": dict(post_create.image_ids),
            "bound_post_create_projection_sha256s": dict(
                post_create_document["artifacts"]
            ),
            "bound_postgres_volume": dict(
                post_create_document["postgres_volume"]
            ),
            "start_commands": [list(command) for command in commands],
            "one_shot_wait_contract": {
                service: {
                    "container_id": identifier,
                    "required_wait_stdout": "0\n",
                    "required_exit_code": 0,
                }
                for service, identifier in one_shot_ids.items()
            },
            "pre_start_reinspection": {
                "required": True,
                "implemented": False,
                "timing": "IMMEDIATELY_BEFORE_EACH_EXACT_ID_START",
                "compare_to_post_create_evidence_sha256": post_create.sha256,
                "required_projections": [
                    "ALL_EXACT_CONTAINER_IDS_AND_IMAGE_IDS",
                    "ALL_CONTAINER_LABELS_MOUNTS_NETWORKS_PORTS_NETNS",
                    "ALL_EXACT_NETWORK_IDS_AND_CONFIGURATION",
                    "POSTGRES_VOLUME_IDENTITY_AND_CONFIGURATION",
                    "EXACT_PROJECT_OBJECT_INVENTORY_WITH_NO_EXTRAS",
                    "GUARD_BINDING_AND_SECURITY_PROJECTION",
                ],
                "mismatch_policy": "FAIL_CLOSED_BEFORE_START",
            },
            "guard_start_gate": {
                "implemented": False,
                "container_id": post_create.container_ids[
                    "oidc-egress-guard"
                ],
                "timing": "AFTER_GUARD_START_BEFORE_DB_OR_ANY_DEPENDENT",
                "required_state_running": True,
                "required_health_status": "healthy",
                "required_ruleset_projection_sha256": (
                    snapshot.oidc_egress_projection_sha256
                ),
                "required_deny_probes": True,
                "mismatch_policy": "FAIL_CLOSED_BEFORE_DEPENDENT_START",
            },
            "readiness_gates": [
                (
                    "PRE_START_EXACT_CONTAINER_NETWORK_VOLUME_IMAGE_"
                    "REINSPECTION_MATCHES_SEALED_EVIDENCE"
                ),
                (
                    "GUARD_EXACT_ID_RUNNING_HEALTHY_AND_RULESET_VERIFIED_"
                    "BEFORE_ANY_DEPENDENT_START"
                ),
                "DB_HEALTHY",
                "ALL_ONE_SHOTS_EXITED_ZERO",
                "MATCHING_RUNTIME_HEALTHY",
                "API_READY_WITH_PINNED_OIDC",
                "WEB_READY",
                "EDGE_READY_AND_INGRESS_LAST",
            ],
            "execution": {
                "implemented": False,
                "permitted": False,
                "commands_use_exact_container_ids": True,
                "subsequent_compose_mutation_allowed": False,
                "container_image_ids_bound": True,
                "old_post_create_evidence_is_continuing_authority": False,
                "pre_start_full_reinspection_required": True,
                "pre_start_full_reinspection_implemented": False,
                "guard_running_healthy_ruleset_gate_implemented": False,
                "execute_blockers": list(post_create.execute_blockers),
            },
            "rollback": {
                "policy": "PRESERVE_POSTGRES_VOLUME",
                "delete_volume_command_allowed": False,
                "manager": "manage_private_server_real_oidc.py",
            },
        }
        raw = _canonical(document)
        for forbidden in (
            b'"compose"',
            b'"create"',
            b'"up"',
            b'"run"',
            b'"--rm"',
            b'"restart"',
            b'"down"',
            b'"--volumes"',
        ):
            if forbidden in raw:
                _invalid()
        return RealOidcActivationPlan(
            raw=raw,
            sha256=_sha(raw),
            project_name=snapshot.project_name,
            snapshot_sha256=snapshot.snapshot_sha256,
            compose_sha256=snapshot.compose_sha256,
            action="START_CREATED_CONTAINERS",
            plan_nonce=authorization["plan_nonce"],
        )
    except PrivateServerRealOidcActivationError:
        raise
    except (
        _release.PrivateServerRealOidcReleaseInputError,
        _preflight.PrivateServerRealOidcPreflightError,
    ):
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
        value = b"".join(chunks)
        if (
            len(value) != before.st_size
            or (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_uid,
                before.st_nlink,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_uid,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            or (after.st_dev, after.st_ino)
            != (visible_after.st_dev, visible_after.st_ino)
        ):
            _invalid()
        return value
    except OSError:
        _invalid()
    finally:
        os.close(descriptor)


def _write_plan(path: Path, raw: bytes) -> os.stat_result:
    if not isinstance(path, Path) or not path.is_absolute():
        _invalid()
    try:
        parent = path.parent.resolve(strict=True)
        metadata = parent.stat()
    except (OSError, RuntimeError):
        _invalid()
    if (
        parent != path.parent
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
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
        descriptor = os.open(path, flags, 0o400)
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                _invalid()
            offset += written
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
        metadata = os.fstat(descriptor)
        visible = path.lstat()
        if (
            (metadata.st_dev, metadata.st_ino)
            != (visible.st_dev, visible.st_ino)
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or metadata.st_size != len(raw)
        ):
            _invalid()
        return metadata
    except OSError:
        _invalid()
    finally:
        try:
            os.close(descriptor)
        except (OSError, UnboundLocalError):
            pass


def _private_directory(path: Path, *, mode: int, empty: bool = False) -> Path:
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


def consume_plan_nonce(
    *, claim_root: Path, plan_nonce: str, action: str, plan_sha256: str
) -> NonceClaim:
    """Persistently consume one UUIDv4 nonce with O_EXCL; never execute a plan."""

    try:
        root = _private_directory(claim_root, mode=0o700)
        nonce = UUID(plan_nonce)
        if (
            nonce.version != 4
            or str(nonce) != plan_nonce
            or action not in ("CREATE_CONTAINERS", "START_CREATED_CONTAINERS")
            or _SHA256.fullmatch(plan_sha256) is None
        ):
            _invalid()
        raw = _canonical(
            {
                "format": "desire-real-oidc-plan-nonce-claim-v1",
                "status": "CONSUMED_NOT_EXECUTED",
                "action": action,
                "plan_nonce": plan_nonce,
                "plan_sha256": plan_sha256,
            }
        )
        path = root / ("nonce-" + plan_nonce + ".json")
        metadata = _write_plan(path, raw)
        return NonceClaim(
            path=path,
            sha256=_sha(raw),
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )
    except PrivateServerRealOidcActivationError:
        raise
    except BaseException:
        _invalid()


def _write_stage_file(
    root_fd: int, name: str, raw: bytes, *, mode: int = 0o400
) -> Mapping[str, Any]:
    if (
        not isinstance(name, str)
        or "/" in name
        or name in ("", ".", "..")
        or type(raw) is not bytes
        or not raw
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
        descriptor = os.open(name, flags, 0o400, dir_fd=root_fd)
    except OSError:
        _invalid()
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                _invalid()
            offset += written
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
        metadata = os.fstat(descriptor)
        visible = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if (
            (metadata.st_dev, metadata.st_ino)
            != (visible.st_dev, visible.st_ino)
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or metadata.st_size != len(raw)
        ):
            _invalid()
        return MappingProxyType(
            {
                "sha256": _sha(raw),
                "size": len(raw),
                "mode": format(mode, "04o"),
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
            }
        )
    except OSError:
        _invalid()
    finally:
        os.close(descriptor)


def seal_execution_stage(
    *,
    stage_root: Path,
    start_plan: RealOidcActivationPlan,
    create_plan_raw: bytes,
    post_create_evidence_raw: bytes,
    start_authorization_raw: bytes,
    nonce_claim: NonceClaim,
) -> ExecutionStageSeal:
    """Descriptor-seal start inputs under one exclusive, non-executable root."""

    root_fd = None
    lock_fd = None
    try:
        if (
            not isinstance(start_plan, RealOidcActivationPlan)
            or start_plan.action != "START_CREATED_CONTAINERS"
            or not isinstance(nonce_claim, NonceClaim)
        ):
            _invalid()
        start_document = _parse_canonical(start_plan.raw)
        create_document = _parse_canonical(create_plan_raw)
        post_create_document = _parse_canonical(post_create_evidence_raw)
        authorization_document = _parse_canonical(start_authorization_raw)
        if (
            _sha(start_plan.raw) != start_plan.sha256
            or start_document.get("format") != "desire-real-oidc-start-plan-v1"
            or start_document.get("authority") != "NOT_AUTHORITY"
            or start_document.get("legacy_execution_accepted") is not False
            or start_document.get("action") != "START_CREATED_CONTAINERS"
            or start_document.get("project") != start_plan.project_name
            or start_document.get("plan_nonce") != start_plan.plan_nonce
            or start_document.get("create_plan_sha256") != _sha(create_plan_raw)
            or start_document.get("post_create_evidence_sha256")
            != _sha(post_create_evidence_raw)
            or start_document.get("authorization_sha256")
            != _sha(start_authorization_raw)
            or create_document.get("format") != "desire-real-oidc-create-plan-v1"
            or post_create_document.get("format")
            not in (
                "desire-real-oidc-post-create-evidence-v1",
                "desire-real-oidc-post-create-evidence-v2",
            )
            or authorization_document.get("format")
            != "desire-real-oidc-start-authorization-v1"
            or authorization_document.get("authority") != "NOT_AUTHORITY"
            or authorization_document.get("legacy_execution_accepted") is not False
            or authorization_document.get("plan_nonce") != start_plan.plan_nonce
        ):
            _invalid()
        root = _private_directory(stage_root, mode=0o700, empty=True)
        try:
            parent = root.parent.resolve(strict=True)
            parent_metadata = parent.stat()
        except (OSError, RuntimeError):
            _invalid()
        if (
            parent != root.parent
            or stat.S_IMODE(parent_metadata.st_mode) != 0o700
            or parent_metadata.st_uid != os.geteuid()
            or root.name != "execution-" + start_plan.plan_nonce
        ):
            _invalid()
        claim_raw = _read_closed(nonce_claim.path)
        claim = _closed(
            _parse_canonical(claim_raw),
            ("format", "status", "action", "plan_nonce", "plan_sha256"),
        )
        if (
            _sha(claim_raw) != nonce_claim.sha256
            or claim
            != {
                "format": "desire-real-oidc-plan-nonce-claim-v1",
                "status": "CONSUMED_NOT_EXECUTED",
                "action": "START_CREATED_CONTAINERS",
                "plan_nonce": start_plan.plan_nonce,
                "plan_sha256": start_plan.sha256,
            }
        ):
            _invalid()
        root_fd = os.open(
            root,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened_root = os.fstat(root_fd)
        visible_root = root.lstat()
        if (
            (opened_root.st_dev, opened_root.st_ino)
            != (visible_root.st_dev, visible_root.st_ino)
            or not stat.S_ISDIR(opened_root.st_mode)
            or stat.S_IMODE(opened_root.st_mode) != 0o700
            or opened_root.st_uid != os.geteuid()
        ):
            _invalid()
        lock_flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        lock_fd = os.open("exclusive.lock", lock_flags, 0o400, dir_fd=root_fd)
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        lock_raw = _canonical(
            {
                "format": "desire-real-oidc-execution-stage-lock-v1",
                "status": "EXCLUSIVE_SEAL_NOT_EXECUTED",
                "plan_nonce": start_plan.plan_nonce,
                "start_plan_sha256": start_plan.sha256,
            }
        )
        offset = 0
        while offset < len(lock_raw):
            written = os.write(lock_fd, lock_raw[offset:])
            if written <= 0:
                _invalid()
            offset += written
        os.fsync(lock_fd)
        os.fchmod(lock_fd, 0o400)
        lock_metadata = os.fstat(lock_fd)
        lock_visible = os.stat(
            "exclusive.lock", dir_fd=root_fd, follow_symlinks=False
        )
        if (
            (lock_metadata.st_dev, lock_metadata.st_ino)
            != (lock_visible.st_dev, lock_visible.st_ino)
            or not stat.S_ISREG(lock_metadata.st_mode)
            or stat.S_IMODE(lock_metadata.st_mode) != 0o400
            or lock_metadata.st_uid != os.geteuid()
            or lock_metadata.st_nlink != 1
            or lock_metadata.st_size != len(lock_raw)
        ):
            _invalid()
        artifacts = {
            "exclusive.lock": {
                "sha256": _sha(lock_raw),
                "size": len(lock_raw),
                "mode": "0400",
                "device": lock_metadata.st_dev,
                "inode": lock_metadata.st_ino,
            }
        }
        for name, raw in (
            ("create-plan.json", create_plan_raw),
            ("post-create-evidence.json", post_create_evidence_raw),
            ("start-authorization.json", start_authorization_raw),
            ("start-plan.json", start_plan.raw),
            ("nonce-claim.json", claim_raw),
        ):
            artifacts[name] = dict(_write_stage_file(root_fd, name, raw))
        manifest_raw = _canonical(
            {
                "format": "desire-real-oidc-execution-stage-v1",
                "status": "SEALED_NOT_EXECUTED",
                "authority": "NOT_AUTHORITY",
                "legacy_execution_accepted": False,
                "project": start_plan.project_name,
                "snapshot_sha256": start_plan.snapshot_sha256,
                "compose_sha256": start_plan.compose_sha256,
                "plan_nonce": start_plan.plan_nonce,
                "start_plan_sha256": start_plan.sha256,
                "nonce_claim": {
                    "sha256": nonce_claim.sha256,
                    "device": nonce_claim.device,
                    "inode": nonce_claim.inode,
                },
                "artifacts": artifacts,
                "execution_permitted": False,
            }
        )
        manifest_metadata = _write_stage_file(
            root_fd, "execution-stage-manifest.json", manifest_raw
        )
        if frozenset(os.listdir(root_fd)) != frozenset(
            (*artifacts.keys(), "execution-stage-manifest.json")
        ):
            _invalid()
        os.fchmod(root_fd, 0o500)
        os.fsync(root_fd)
        sealed_root = os.fstat(root_fd)
        visible_sealed_root = root.lstat()
        if (
            (sealed_root.st_dev, sealed_root.st_ino)
            != (visible_sealed_root.st_dev, visible_sealed_root.st_ino)
            or stat.S_IMODE(sealed_root.st_mode) != 0o500
            or sealed_root.st_uid != os.geteuid()
        ):
            _invalid()
        return ExecutionStageSeal(
            root=root,
            manifest_sha256=_sha(manifest_raw),
            manifest_device=manifest_metadata["device"],
            manifest_inode=manifest_metadata["inode"],
        )
    except PrivateServerRealOidcActivationError:
        raise
    except BaseException:
        _invalid()
    finally:
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(lock_fd)
        if root_fd is not None:
            os.close(root_fd)


def load_execution_stage(stage_root: Path) -> ExecutionStageSeal:
    """Reopen and verify every inode in a sealed, non-executable start stage."""

    try:
        root = _private_directory(stage_root, mode=0o500)
        names = frozenset(
            (
                "exclusive.lock",
                "create-plan.json",
                "post-create-evidence.json",
                "start-authorization.json",
                "start-plan.json",
                "nonce-claim.json",
                "execution-stage-manifest.json",
            )
        )
        if frozenset(os.listdir(root)) != names:
            _invalid()
        manifest_raw = _read_closed(root / "execution-stage-manifest.json")
        manifest = _closed(
            _parse_canonical(manifest_raw),
            (
                "format",
                "status",
                "authority",
                "legacy_execution_accepted",
                "project",
                "snapshot_sha256",
                "compose_sha256",
                "plan_nonce",
                "start_plan_sha256",
                "nonce_claim",
                "artifacts",
                "execution_permitted",
            ),
        )
        artifacts = manifest["artifacts"]
        nonce_claim = _closed(
            manifest["nonce_claim"], ("sha256", "device", "inode")
        )
        if (
            manifest["format"] != "desire-real-oidc-execution-stage-v1"
            or manifest["status"] != "SEALED_NOT_EXECUTED"
            or manifest["authority"] != "NOT_AUTHORITY"
            or manifest["legacy_execution_accepted"] is not False
            or manifest["execution_permitted"] is not False
            or not isinstance(artifacts, dict)
            or frozenset(artifacts) != names - {"execution-stage-manifest.json"}
            or _SHA256.fullmatch(nonce_claim.get("sha256", "")) is None
            or type(nonce_claim.get("device")) is not int
            or type(nonce_claim.get("inode")) is not int
        ):
            _invalid()
        for name, expected in artifacts.items():
            raw = _read_closed(root / name)
            metadata = (root / name).stat()
            if (
                not isinstance(expected, dict)
                or frozenset(expected)
                != frozenset(("sha256", "size", "mode", "device", "inode"))
                or expected["sha256"] != _sha(raw)
                or expected["size"] != len(raw)
                or expected["mode"] != "0400"
                or expected["device"] != metadata.st_dev
                or expected["inode"] != metadata.st_ino
                or not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o400
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or metadata.st_size != len(raw)
            ):
                _invalid()
        start_raw = _read_closed(root / "start-plan.json")
        start_document = _parse_canonical(start_raw)
        create_raw = _read_closed(root / "create-plan.json")
        post_create_raw = _read_closed(root / "post-create-evidence.json")
        authorization_raw = _read_closed(root / "start-authorization.json")
        claim_raw = _read_closed(root / "nonce-claim.json")
        claim_document = _parse_canonical(claim_raw)
        if (
            manifest["start_plan_sha256"] != _sha(start_raw)
            or start_document.get("format") != "desire-real-oidc-start-plan-v1"
            or start_document.get("authority") != "NOT_AUTHORITY"
            or start_document.get("legacy_execution_accepted") is not False
            or start_document.get("project") != manifest["project"]
            or start_document.get("plan_nonce") != manifest["plan_nonce"]
            or start_document.get("create_plan_sha256") != _sha(create_raw)
            or start_document.get("post_create_evidence_sha256")
            != _sha(post_create_raw)
            or start_document.get("authorization_sha256")
            != _sha(authorization_raw)
            or claim_document.get("format")
            != "desire-real-oidc-plan-nonce-claim-v1"
            or claim_document.get("action") != "START_CREATED_CONTAINERS"
            or claim_document.get("plan_nonce") != manifest["plan_nonce"]
            or claim_document.get("plan_sha256") != _sha(start_raw)
            or nonce_claim["sha256"] != _sha(claim_raw)
        ):
            _invalid()
        manifest_metadata = (root / "execution-stage-manifest.json").stat()
        return ExecutionStageSeal(
            root=root,
            manifest_sha256=_sha(manifest_raw),
            manifest_device=manifest_metadata.st_dev,
            manifest_inode=manifest_metadata.st_ino,
        )
    except PrivateServerRealOidcActivationError:
        raise
    except BaseException:
        _invalid()


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    import argparse

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "--action",
        choices=("check", "create-plan", "start-plan", "execute"),
        default="check",
    )
    parser.add_argument("--attempt-root")
    parser.add_argument("--authorization-file")
    parser.add_argument("--evidence-file")
    parser.add_argument("--create-plan-file")
    parser.add_argument("--post-create-evidence-file")
    parser.add_argument("--plan-output")
    parser.add_argument("--nonce-claim-root")
    parser.add_argument("--execution-stage-root")
    try:
        arguments = parser.parse_args(tuple(sys.argv[1:] if argv is None else argv))
        if not arguments.attempt_root:
            _invalid()
        attempt_root = Path(arguments.attempt_root)
        if arguments.action == "check":
            if any(
                value is not None
                for value in (
                    arguments.authorization_file,
                    arguments.evidence_file,
                    arguments.create_plan_file,
                    arguments.post_create_evidence_file,
                    arguments.plan_output,
                    arguments.nonce_claim_root,
                    arguments.execution_stage_root,
                )
            ):
                _invalid()
            _release.load_real_oidc_release_snapshot(attempt_root)
            stdout.write(CHECKED)
            return 0
        if arguments.action == "execute":
            _invalid()
        if arguments.action == "create-plan":
            if (
                any(
                    value is None
                    for value in (
                        arguments.authorization_file,
                        arguments.evidence_file,
                        arguments.plan_output,
                        arguments.nonce_claim_root,
                    )
                )
                or arguments.create_plan_file is not None
                or arguments.post_create_evidence_file is not None
                or arguments.execution_stage_root is not None
            ):
                _invalid()
            plan = build_activation_plan(
                attempt_root=attempt_root,
                authorization_raw=_read_closed(
                    Path(arguments.authorization_file)
                ),
                evidence_raw=_read_closed(Path(arguments.evidence_file)),
            )
            consume_plan_nonce(
                claim_root=Path(arguments.nonce_claim_root),
                plan_nonce=plan.plan_nonce,
                action=plan.action,
                plan_sha256=plan.sha256,
            )
            _write_plan(Path(arguments.plan_output), plan.raw)
            stdout.write(CREATE_PLANNED)
            return 0
        if (
            any(
                value is None
                for value in (
                    arguments.authorization_file,
                    arguments.create_plan_file,
                    arguments.post_create_evidence_file,
                    arguments.nonce_claim_root,
                    arguments.execution_stage_root,
                )
            )
            or arguments.evidence_file is not None
            or arguments.plan_output is not None
        ):
            _invalid()
        create_plan_raw = _read_closed(Path(arguments.create_plan_file))
        post_create_raw = _read_closed(
            Path(arguments.post_create_evidence_file)
        )
        start_authorization_raw = _read_closed(
            Path(arguments.authorization_file)
        )
        plan = build_start_plan(
            attempt_root=attempt_root,
            create_plan_raw=create_plan_raw,
            post_create_evidence_raw=post_create_raw,
            authorization_raw=start_authorization_raw,
        )
        claim = consume_plan_nonce(
            claim_root=Path(arguments.nonce_claim_root),
            plan_nonce=plan.plan_nonce,
            action=plan.action,
            plan_sha256=plan.sha256,
        )
        seal_execution_stage(
            stage_root=Path(arguments.execution_stage_root),
            start_plan=plan,
            create_plan_raw=create_plan_raw,
            post_create_evidence_raw=post_create_raw,
            start_authorization_raw=start_authorization_raw,
            nonce_claim=claim,
        )
        stdout.write(START_STAGED)
        return 0
    except (PrivateServerRealOidcActivationError, SystemExit):
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
    "ExecutionStageSeal",
    "NonceClaim",
    "PrivateServerRealOidcActivationError",
    "RealOidcActivationPlan",
    "build_activation_plan",
    "build_start_plan",
    "consume_plan_nonce",
    "load_execution_stage",
    "seal_execution_stage",
)
