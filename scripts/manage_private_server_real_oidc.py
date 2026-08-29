#!/usr/bin/env python3
"""Build non-executing status/stop/rollback plans for one real-OIDC snapshot.

Only six persistent containers are eligible for stopping, in
Edge -> Web -> API -> Matching runtime -> OIDC egress guard -> DB order.  A plan requires reviewed
live ownership evidence and a one-time
authorization bound to the immutable snapshot.  PostgreSQL volume removal,
Compose ``down``, network removal, and all execution are unreachable.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping, NoReturn, Optional, Sequence, TextIO
from uuid import UUID


_ACTIVATION_HELPER = Path(__file__).resolve().with_name(
    "activate_private_server_real_oidc.py"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
_SERVICES = (
    "edge",
    "web",
    "api",
    "matching-runtime",
    "oidc-egress-guard",
    "db",
)
_NETWORKS = ("app", "data", "ingress", "oidc-egress")
_CHECKS = frozenset(
    (
        "resource_ownership",
        "security_projection",
        "volume_preservation",
        "external_ingress_revocation",
    )
)
_STOP_SECONDS = {
    "edge": 30,
    "web": 30,
    "api": 20,
    "matching-runtime": 30,
    "oidc-egress-guard": 20,
    "db": 60,
}
_DOCKER = ("/usr/bin/docker", "--host", "unix:///var/run/docker.sock")

CHECKED = '{"status":"PRIVATE_SERVER_REAL_OIDC_MANAGEMENT_CHECKED"}\n'
STATUS_PLANNED = (
    '{"status":"PRIVATE_SERVER_REAL_OIDC_STATUS_PLAN_READY_NOT_EXECUTED"}\n'
)
PLANNED = (
    '{"status":"PRIVATE_SERVER_REAL_OIDC_MANAGEMENT_PLAN_READY_NOT_EXECUTED"}\n'
)
BLOCKED = (
    '{"code":"PRIVATE_SERVER_REAL_OIDC_MANAGEMENT_INVALID",'
    '"status":"BLOCKED"}\n'
)


def _load_activation():
    name = "_desire_real_oidc_activation_for_management"
    spec = importlib.util.spec_from_file_location(name, _ACTIVATION_HELPER)
    if spec is None or spec.loader is None:
        raise RuntimeError("PRIVATE_SERVER_REAL_OIDC_MANAGEMENT_INVALID")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_activation = _load_activation()
_release = _activation._release


class PrivateServerRealOidcManagementError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("PRIVATE_SERVER_REAL_OIDC_MANAGEMENT_INVALID")


@dataclass(frozen=True, repr=False)
class RealOidcManagementPlan:
    raw: bytes
    sha256: str
    project_name: str
    action: str

    def __repr__(self) -> str:
        return (
            "RealOidcManagementPlan("
            f"sha256={self.sha256!r}, project_name={self.project_name!r}, "
            f"action={self.action!r}, commands=<redacted>, status='NOT_EXECUTED')"
        )


@dataclass(frozen=True, repr=False)
class ManagementNonceClaim:
    path: Path
    sha256: str
    device: int
    inode: int

    def __repr__(self) -> str:
        return (
            "ManagementNonceClaim("
            f"sha256={self.sha256!r}, status='CONSUMED_NOT_EXECUTED')"
        )


def build_status_plan(*, attempt_root: Path) -> RealOidcManagementPlan:
    """Build an exact read-only inspection plan without invoking Docker."""

    try:
        snapshot, _manifest, _compose = _release.load_real_oidc_release_snapshot(
            attempt_root
        )
        label = "label=com.docker.compose.project=" + snapshot.project_name
        containers = _activation._preflight.fresh_container_names(
            snapshot.project_name
        )
        networks = _activation._preflight.fresh_resource_names(
            snapshot.project_name
        )
        commands = [
            _DOCKER
            + (
                "container",
                "ls",
                "--all",
                "--filter",
                label,
                "--format",
                "{{json .}}",
            )
        ]
        commands.extend(
            _DOCKER + ("container", "inspect", name)
            for name in containers.values()
        )
        commands.append(
            _DOCKER
            + ("network", "ls", "--filter", label, "--format", "{{json .}}")
        )
        commands.extend(
            _DOCKER + ("network", "inspect", name)
            for name in networks.values()
        )
        commands.extend(
            (
                _DOCKER
                + ("volume", "ls", "--filter", label, "--format", "{{json .}}"),
                _DOCKER
                + (
                    "volume",
                    "inspect",
                    snapshot.project_name + "_postgres-data",
                ),
            )
        )
        commands.extend(
            _DOCKER + ("image", "inspect", "--format", "{{.Id}}", reference)
            for reference in snapshot.image_references
        )
        document = {
            "format": "desire-real-oidc-status-plan-v1",
            "status": "READ_ONLY_PLAN_NOT_EXECUTED",
            "action": "STATUS",
            "project": snapshot.project_name,
            "snapshot_sha256": snapshot.snapshot_sha256,
            "compose_sha256": snapshot.compose_sha256,
            "oidc_pinned_public_ipv4": snapshot.oidc_pinned_public_ipv4,
            "db_data_ipv4": snapshot.db_data_ipv4,
            "oidc_egress_projection_sha256": (
                snapshot.oidc_egress_projection_sha256
            ),
            "commands": [list(command) for command in commands],
            "execution": {
                "implemented": False,
                "permitted_operations": ["READ_ONLY_INSPECT"],
            },
        }
        raw = _canonical(document)
        for forbidden in (
            b'"stop"',
            b'"rm"',
            b'"down"',
            b'"up"',
            b'"start"',
            b'"restart"',
        ):
            if forbidden in raw:
                _invalid()
        return RealOidcManagementPlan(
            raw=raw,
            sha256=_sha(raw),
            project_name=snapshot.project_name,
            action="STATUS",
        )
    except PrivateServerRealOidcManagementError:
        raise
    except _release.PrivateServerRealOidcReleaseInputError:
        _invalid()
    except BaseException:
        _invalid()


class _DuplicateKey(ValueError):
    pass


def _invalid() -> NoReturn:
    raise PrivateServerRealOidcManagementError()


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


def _parse(raw: bytes) -> Mapping[str, Any]:
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
    except PrivateServerRealOidcManagementError:
        raise
    except BaseException:
        _invalid()


def _closed(value: Any, keys) -> Mapping[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != frozenset(keys):
        _invalid()
    return value


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _evidence(raw: bytes, *, snapshot, action: str):
    value = _closed(
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
            "activation_receipt_sha256",
            "guard_binding_sha256",
            "containers",
            "networks",
            "postgres_volume",
            "checks",
            "artifacts",
        ),
    )
    containers = _closed(value["containers"], _SERVICES)
    networks = _closed(value["networks"], _NETWORKS)
    volume = _closed(value["postgres_volume"], ("name", "state"))
    checks = _closed(value["checks"], _CHECKS)
    artifacts = _closed(value["artifacts"], _CHECKS)
    if (
        value["format"] != "desire-real-oidc-management-evidence-v1"
        or value["status"] != "REVIEWED"
        or value["action"] != action
        or value["project"] != snapshot.project_name
        or value["snapshot_sha256"] != snapshot.snapshot_sha256
        or value["manifest_device"] != snapshot.manifest_device
        or value["manifest_inode"] != snapshot.manifest_inode
        or value["compose_sha256"] != snapshot.compose_sha256
        or value["oidc_pinned_public_ipv4"]
        != snapshot.oidc_pinned_public_ipv4
        or value["db_data_ipv4"] != snapshot.db_data_ipv4
        or value["oidc_egress_projection_sha256"]
        != snapshot.oidc_egress_projection_sha256
        or _SHA256.fullmatch(value.get("activation_receipt_sha256", "")) is None
        or _SHA256.fullmatch(value.get("guard_binding_sha256", "")) is None
        or any(
            not isinstance(identifier, str)
            or _CONTAINER_ID.fullmatch(identifier) is None
            for identifier in containers.values()
        )
        or len(set(containers.values())) != len(containers)
        or any(
            not isinstance(identifier, str)
            or _CONTAINER_ID.fullmatch(identifier) is None
            for identifier in networks.values()
        )
        or len(set(networks.values())) != len(networks)
        or volume
        != {
            "name": snapshot.project_name + "_postgres-data",
            "state": "PRESENT_PRESERVE",
        }
        or checks != {key: "VERIFIED" for key in _CHECKS}
        or any(
            not isinstance(digest, str) or _SHA256.fullmatch(digest) is None
            for digest in artifacts.values()
        )
        or len(set(artifacts.values())) != len(artifacts)
    ):
        _invalid()
    return value, _sha(raw)


def _authorization(raw: bytes, *, snapshot, action: str, evidence, evidence_sha: str):
    value = _closed(
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
            "activation_receipt_sha256",
            "guard_binding_sha256",
            "evidence_sha256",
            "plan_nonce",
            "one_time",
            "rollback_policy",
        ),
    )
    try:
        nonce = UUID(value["plan_nonce"])
    except (ValueError, TypeError, AttributeError):
        _invalid()
    if (
        value["format"] != "desire-real-oidc-management-authorization-v1"
        or value["status"] != "APPROVED"
        or value["action"] != action
        or value["project"] != snapshot.project_name
        or value["snapshot_sha256"] != snapshot.snapshot_sha256
        or value["manifest_device"] != snapshot.manifest_device
        or value["manifest_inode"] != snapshot.manifest_inode
        or value["compose_sha256"] != snapshot.compose_sha256
        or value["oidc_pinned_public_ipv4"]
        != snapshot.oidc_pinned_public_ipv4
        or value["db_data_ipv4"] != snapshot.db_data_ipv4
        or value["oidc_egress_projection_sha256"]
        != snapshot.oidc_egress_projection_sha256
        or value["activation_receipt_sha256"]
        != evidence["activation_receipt_sha256"]
        or value["guard_binding_sha256"] != evidence["guard_binding_sha256"]
        or value["evidence_sha256"] != evidence_sha
        or nonce.version != 4
        or str(nonce) != value["plan_nonce"]
        or value["one_time"] is not True
        or value["rollback_policy"] != "PRESERVE_POSTGRES_VOLUME"
    ):
        _invalid()
    return value, _sha(raw)


def consume_management_nonce(
    *,
    claim_root: Path,
    plan: RealOidcManagementPlan,
    authorization_sha256: str,
    evidence_sha256: str,
) -> ManagementNonceClaim:
    """Persistently bind and consume one STOP/ROLLBACK authorization nonce."""

    try:
        root = _activation._private_directory(claim_root, mode=0o700)
        if not isinstance(plan, RealOidcManagementPlan):
            _invalid()
        document = _parse(plan.raw)
        try:
            nonce = UUID(document["plan_nonce"])
        except (KeyError, ValueError, TypeError, AttributeError):
            _invalid()
        if (
            plan.action not in ("STOP", "ROLLBACK")
            or document.get("format")
            != "desire-real-oidc-management-plan-v1"
            or document.get("status") != "PLANNED_NOT_EXECUTED"
            or document.get("action") != plan.action
            or document.get("project") != plan.project_name
            or _sha(plan.raw) != plan.sha256
            or nonce.version != 4
            or str(nonce) != document["plan_nonce"]
            or _SHA256.fullmatch(authorization_sha256) is None
            or _SHA256.fullmatch(evidence_sha256) is None
            or document.get("authorization_sha256") != authorization_sha256
            or document.get("evidence_sha256") != evidence_sha256
        ):
            _invalid()
        raw = _canonical(
            {
                "format": "desire-real-oidc-management-nonce-claim-v1",
                "status": "CONSUMED_NOT_EXECUTED",
                "action": plan.action,
                "project": plan.project_name,
                "plan_nonce": document["plan_nonce"],
                "plan_sha256": plan.sha256,
                "authorization_sha256": authorization_sha256,
                "evidence_sha256": evidence_sha256,
            }
        )
        path = root / ("management-nonce-" + document["plan_nonce"] + ".json")
        metadata = _activation._write_plan(path, raw)
        return ManagementNonceClaim(
            path=path,
            sha256=_sha(raw),
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )
    except PrivateServerRealOidcManagementError:
        raise
    except BaseException:
        _invalid()


def build_management_plan(
    *,
    action: str,
    attempt_root: Path,
    authorization_raw: bytes,
    evidence_raw: bytes,
    nonce_claim_root: Path,
) -> RealOidcManagementPlan:
    try:
        if action not in ("STOP", "ROLLBACK"):
            _invalid()
        snapshot, _manifest, _compose = _release.load_real_oidc_release_snapshot(
            attempt_root
        )
        evidence, evidence_sha = _evidence(
            evidence_raw, snapshot=snapshot, action=action
        )
        authorization, authorization_sha = _authorization(
            authorization_raw,
            snapshot=snapshot,
            action=action,
            evidence=evidence,
            evidence_sha=evidence_sha,
        )
        commands = [
            list(
                _DOCKER
                + (
                    "container",
                    "stop",
                    "--time",
                    str(_STOP_SECONDS[service]),
                    evidence["containers"][service],
                )
            )
            for service in _SERVICES
        ]
        document = {
            "format": "desire-real-oidc-management-plan-v1",
            "status": "PLANNED_NOT_EXECUTED",
            "action": action,
            "project": snapshot.project_name,
            "plan_nonce": authorization["plan_nonce"],
            "snapshot_sha256": snapshot.snapshot_sha256,
            "compose_sha256": snapshot.compose_sha256,
            "oidc_pinned_public_ipv4": snapshot.oidc_pinned_public_ipv4,
            "db_data_ipv4": snapshot.db_data_ipv4,
            "oidc_egress_projection_sha256": (
                snapshot.oidc_egress_projection_sha256
            ),
            "activation_receipt_sha256": evidence["activation_receipt_sha256"],
            "guard_binding_sha256": evidence["guard_binding_sha256"],
            "authorization_sha256": authorization_sha,
            "evidence_sha256": evidence_sha,
            "bound_container_ids": dict(evidence["containers"]),
            "bound_network_ids": dict(evidence["networks"]),
            "stop_commands": commands,
            "execution": {"implemented": False, "permitted": False},
            "rollback": {
                "postgres_volume": snapshot.project_name + "_postgres-data",
                "policy": "PRESERVE_POSTGRES_VOLUME",
                "delete_volume_command_allowed": False,
                "delete_network_command_allowed": False,
                "semantics": (
                    "EMERGENCY_STOP_SKELETON_NOT_VERSION_RESTORE"
                    if action == "ROLLBACK"
                    else "ORDERED_STOP_ONLY"
                ),
            },
        }
        raw = _canonical(document)
        forbidden = (
            b'"down"',
            b'"--volumes"',
            b'"volume","rm"',
            b'"network","rm"',
            b'"container","rm"',
        )
        if any(token in raw for token in forbidden):
            _invalid()
        plan = RealOidcManagementPlan(
            raw=raw,
            sha256=_sha(raw),
            project_name=snapshot.project_name,
            action=action,
        )
        consume_management_nonce(
            claim_root=nonce_claim_root,
            plan=plan,
            authorization_sha256=authorization_sha,
            evidence_sha256=evidence_sha,
        )
        return plan
    except PrivateServerRealOidcManagementError:
        raise
    except _release.PrivateServerRealOidcReleaseInputError:
        _invalid()
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
        choices=("status-plan", "check", "stop-plan", "rollback-plan", "execute"),
        default="status-plan",
    )
    parser.add_argument("--attempt-root")
    parser.add_argument("--authorization-file")
    parser.add_argument("--evidence-file")
    parser.add_argument("--plan-output")
    parser.add_argument("--nonce-claim-root")
    try:
        arguments = parser.parse_args(tuple(sys.argv[1:] if argv is None else argv))
        if not arguments.attempt_root:
            _invalid()
        attempt = Path(arguments.attempt_root)
        if arguments.action in ("status-plan", "check"):
            if any(
                item is not None
                for item in (
                    arguments.authorization_file,
                    arguments.evidence_file,
                    arguments.nonce_claim_root,
                )
            ):
                _invalid()
            if arguments.action == "check":
                if arguments.plan_output is not None:
                    _invalid()
                _release.load_real_oidc_release_snapshot(attempt)
                stdout.write(CHECKED)
                return 0
            plan = build_status_plan(attempt_root=attempt)
            if arguments.plan_output is not None:
                _activation._write_plan(Path(arguments.plan_output), plan.raw)
            stdout.write(STATUS_PLANNED)
            return 0
        if arguments.action == "execute":
            _invalid()
        if any(
            item is None
            for item in (
                arguments.authorization_file,
                arguments.evidence_file,
                arguments.plan_output,
                arguments.nonce_claim_root,
            )
        ):
            _invalid()
        action = "STOP" if arguments.action == "stop-plan" else "ROLLBACK"
        plan = build_management_plan(
            action=action,
            attempt_root=attempt,
            authorization_raw=_activation._read_closed(Path(arguments.authorization_file)),
            evidence_raw=_activation._read_closed(Path(arguments.evidence_file)),
            nonce_claim_root=Path(arguments.nonce_claim_root),
        )
        _activation._write_plan(Path(arguments.plan_output), plan.raw)
        stdout.write(PLANNED)
        return 0
    except (PrivateServerRealOidcManagementError, SystemExit):
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
    "ManagementNonceClaim",
    "PrivateServerRealOidcManagementError",
    "RealOidcManagementPlan",
    "build_management_plan",
    "build_status_plan",
    "consume_management_nonce",
)
