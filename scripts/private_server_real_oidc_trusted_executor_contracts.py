#!/usr/bin/env python3
"""Closed, offline contracts for a future real-OIDC trusted executor.

This module intentionally has no execution path.  It parses one create-intent
request which remains ``NOT_AUTHORITY`` and describes a create-only,
zero-start postcondition.  It never reads files, opens a Docker socket, runs a
process, claims a nonce or lease, or changes host/container state.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Mapping, NoReturn


_MAX_DOCUMENT_BYTES = 64 * 1024
_FORMAT = "desire-real-oidc-broker-create-intent-v1"
_STATUS = "VALIDATED_REQUEST_NOT_AUTHORITY"
_TEMPLATE_ID = "CREATE_BOUND_REAL_OIDC_RESOURCES_ZERO_START_V1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_IMAGE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,511}$")
_PROJECT = re.compile(
    r"^desire-real-oidc-(?:[a-z0-9]|[a-z0-9][a-z0-9-]{0,38}[a-z0-9])$"
)
_MAX_DESCRIPTOR_NUMBER = (1 << 63) - 1

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
_NETWORKS = ("app", "data", "ingress", "oidc-egress")

# These artifacts predate the trusted-executor boundary and are permanently
# non-executable.  The ingress below also detects them inside wrappers.
PERMANENTLY_REJECTED_LEGACY_FORMATS = (
    "desire-real-oidc-activation-authorization-v1",
    "desire-real-oidc-collected-safe-projection-digest-v1",
    "desire-real-oidc-create-plan-v1",
    "desire-real-oidc-execution-stage-lock-v1",
    "desire-real-oidc-execution-stage-v1",
    "desire-real-oidc-guard-binding-v2",
    "desire-real-oidc-management-authorization-v1",
    "desire-real-oidc-management-evidence-v1",
    "desire-real-oidc-management-nonce-claim-v1",
    "desire-real-oidc-management-plan-v1",
    "desire-real-oidc-plan-nonce-claim-v1",
    "desire-real-oidc-post-create-collection-binding-v1",
    "desire-real-oidc-post-create-collection-plan-v1",
    "desire-real-oidc-post-create-evidence-v1",
    "desire-real-oidc-post-create-evidence-v2",
    "desire-real-oidc-post-create-projection-v1",
    "desire-real-oidc-post-create-semantic-projection-v1",
    "desire-real-oidc-preflight-evidence-v1",
    "desire-real-oidc-safe-container-inspect-v1",
    "desire-real-oidc-safe-network-inspect-v1",
    "desire-real-oidc-safe-volume-inspect-v1",
    "desire-real-oidc-start-authorization-v1",
    "desire-real-oidc-start-plan-v1",
    "desire-real-oidc-status-plan-v1",
)
_LEGACY_FORMATS = frozenset(PERMANENTLY_REJECTED_LEGACY_FORMATS)

# The exact contract has no such field.  Scanning recursively makes that
# boundary explicit before any semantic interpretation is attempted.
_FORBIDDEN_FIELD_NAMES = frozenset(
    (
        "arg",
        "args",
        "argument",
        "arguments",
        "argv",
        "command",
        "commands",
        "cwd",
        "docker_socket",
        "endpoint",
        "env",
        "environment",
        "path",
        "paths",
        "socket",
        "socket_path",
        "working_directory",
    )
)


class TrustedExecutorContractError(RuntimeError):
    """Stable failure for malformed or unauthorized trusted-executor input."""

    def __init__(self) -> None:
        super().__init__("PRIVATE_SERVER_REAL_OIDC_TRUSTED_EXECUTOR_CONTRACT_INVALID")


class LegacyExecutionArtifactPermanentlyRejected(TrustedExecutorContractError):
    """Stable, non-upgradeable rejection of every legacy execution artifact."""

    def __init__(self) -> None:
        RuntimeError.__init__(
            self,
            "PRIVATE_SERVER_REAL_OIDC_LEGACY_EXECUTION_ARTIFACT_PERMANENTLY_REJECTED",
        )


@dataclass(frozen=True, repr=False)
class BrokerCreateIntent:
    """Immutable safe projection of a validated, non-authoritative request."""

    raw: bytes
    sha256: str
    project: str
    snapshot_sha256: str
    snapshot_manifest_sha256: str
    snapshot_manifest_device: int
    snapshot_manifest_inode: int
    compose_sha256: str
    images: tuple[tuple[str, str], ...]
    containers: tuple[tuple[str, str], ...]
    networks: tuple[tuple[str, str], ...]
    postgres_volume: str
    operation_template_id: str
    status: str
    authority: str

class _DuplicateKey(ValueError):
    pass


def _invalid() -> NoReturn:
    raise TrustedExecutorContractError()


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
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
        if type(raw) is not bytes or not 0 < len(raw) <= _MAX_DOCUMENT_BYTES:
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
    except TrustedExecutorContractError:
        raise
    except BaseException:
        _invalid()


def _closed(value: Any, keys: tuple[str, ...]) -> Mapping[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != frozenset(keys):
        _invalid()
    return value


def _scan_ingress(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in _FORBIDDEN_FIELD_NAMES:
                _invalid()
            if key == "format" and isinstance(item, str) and item in _LEGACY_FORMATS:
                raise LegacyExecutionArtifactPermanentlyRejected()
            _scan_ingress(item)
    elif isinstance(value, list):
        for item in value:
            _scan_ingress(item)


def _validated_descriptor_number(value: Any) -> int:
    if type(value) is not int or not 0 < value <= _MAX_DESCRIPTOR_NUMBER:
        _invalid()
    return value


def _validated_sha256(value: Any) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _invalid()
    return value


def _validated_resource_map(
    value: Any,
    *,
    logical_names: tuple[str, ...],
    expected_names: Mapping[str, str],
) -> tuple[tuple[str, str], ...]:
    resources = _closed(value, logical_names)
    result: list[tuple[str, str]] = []
    for logical_name in logical_names:
        item = _closed(resources[logical_name], ("name", "prestate"))
        if (
            item["name"] != expected_names[logical_name]
            or item["prestate"] != "ABSENT"
        ):
            _invalid()
        result.append((logical_name, item["name"]))
    return tuple(result)


def _validate_create_intent(
    document: Mapping[str, Any], *, raw: bytes
) -> BrokerCreateIntent:
    root = _closed(
        document,
        (
            "format",
            "status",
            "authority",
            "legacy_execution_accepted",
            "bindings",
            "images",
            "expected_prestate",
            "operation_template_id",
            "expected_postcondition",
            "rollback_policy",
        ),
    )
    bindings = _closed(
        root["bindings"],
        (
            "project",
            "snapshot_sha256",
            "snapshot_manifest",
            "compose_sha256",
        ),
    )
    manifest = _closed(
        bindings["snapshot_manifest"], ("sha256", "device", "inode")
    )
    project = bindings["project"]
    snapshot_sha256 = _validated_sha256(bindings["snapshot_sha256"])
    manifest_sha256 = _validated_sha256(manifest["sha256"])
    compose_sha256 = _validated_sha256(bindings["compose_sha256"])
    if (
        root["format"] != _FORMAT
        or root["status"] != _STATUS
        or root["authority"] != "NOT_AUTHORITY"
        or root["legacy_execution_accepted"] is not False
        or not isinstance(project, str)
        or _PROJECT.fullmatch(project) is None
        or manifest_sha256 != snapshot_sha256
        or root["operation_template_id"] != _TEMPLATE_ID
        or root["rollback_policy"] != "PRESERVE_POSTGRES_VOLUME"
    ):
        _invalid()
    manifest_device = _validated_descriptor_number(manifest["device"])
    manifest_inode = _validated_descriptor_number(manifest["inode"])

    images_value = root["images"]
    if not isinstance(images_value, list) or len(images_value) != 5:
        _invalid()
    images: list[tuple[str, str]] = []
    for value in images_value:
        item = _closed(value, ("reference", "id"))
        reference = item["reference"]
        identifier = item["id"]
        if (
            not isinstance(reference, str)
            or _IMAGE_REFERENCE.fullmatch(reference) is None
            or not isinstance(identifier, str)
            or _IMAGE_ID.fullmatch(identifier) is None
        ):
            _invalid()
        images.append((reference, identifier))
    if (
        tuple(reference for reference, _identifier in images)
        != tuple(sorted(reference for reference, _identifier in images))
        or len({reference for reference, _identifier in images}) != 5
        or len({identifier for _reference, identifier in images}) != 5
    ):
        _invalid()

    prestate = _closed(
        root["expected_prestate"],
        ("containers", "networks", "postgres_volume"),
    )
    expected_container_names = {
        service: project + "-" + service + "-1" for service in _SERVICES
    }
    expected_network_names = {
        logical: project + "_" + logical for logical in _NETWORKS
    }
    containers = _validated_resource_map(
        prestate["containers"],
        logical_names=_SERVICES,
        expected_names=expected_container_names,
    )
    networks = _validated_resource_map(
        prestate["networks"],
        logical_names=_NETWORKS,
        expected_names=expected_network_names,
    )
    volume = _closed(prestate["postgres_volume"], ("name", "prestate"))
    expected_volume = project + "_postgres-data"
    if volume != {"name": expected_volume, "prestate": "ABSENT"}:
        _invalid()

    postcondition = _closed(
        root["expected_postcondition"],
        (
            "state",
            "containers_created",
            "containers_started",
            "process_start_allowed",
            "post_create_reinspection_required",
        ),
    )
    if (
        postcondition["state"] != "CREATED_ZERO_START"
        or type(postcondition["containers_created"]) is not int
        or postcondition["containers_created"] != len(_SERVICES)
        or type(postcondition["containers_started"]) is not int
        or postcondition["containers_started"] != 0
        or postcondition["process_start_allowed"] is not False
        or postcondition["post_create_reinspection_required"] is not True
    ):
        _invalid()

    return BrokerCreateIntent(
        raw=raw,
        sha256=hashlib.sha256(raw).hexdigest(),
        project=project,
        snapshot_sha256=snapshot_sha256,
        snapshot_manifest_sha256=manifest_sha256,
        snapshot_manifest_device=manifest_device,
        snapshot_manifest_inode=manifest_inode,
        compose_sha256=compose_sha256,
        images=tuple(images),
        containers=containers,
        networks=networks,
        postgres_volume=expected_volume,
        operation_template_id=_TEMPLATE_ID,
        status=_STATUS,
        authority="NOT_AUTHORITY",
    )


def parse_trusted_executor_ingress(raw: bytes) -> BrokerCreateIntent:
    """Accept only the v1 create intent; reject legacy and unknown wrappers."""

    document = _parse_canonical(raw)
    _scan_ingress(document)
    if document.get("format") != _FORMAT:
        _invalid()
    return _validate_create_intent(document, raw=raw)


def parse_broker_create_intent(raw: bytes) -> BrokerCreateIntent:
    """Alias the only accepted trusted-executor ingress contract."""

    return parse_trusted_executor_ingress(raw)


__all__ = (
    "BrokerCreateIntent",
    "LegacyExecutionArtifactPermanentlyRejected",
    "PERMANENTLY_REJECTED_LEGACY_FORMATS",
    "TrustedExecutorContractError",
    "parse_broker_create_intent",
    "parse_trusted_executor_ingress",
)
