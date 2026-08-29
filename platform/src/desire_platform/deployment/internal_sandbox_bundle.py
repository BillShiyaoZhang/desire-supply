"""Create one purpose-separated INTERNAL_SANDBOX runtime bundle.

This deployment-only command writes a new directory atomically.  It never
overwrites an existing target, never prints secret material, and does not
install database credentials or contact PostgreSQL/OIDC.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import sys
import tempfile
from typing import Any, Callable, NoReturn, Optional, Sequence, TextIO
from uuid import UUID, uuid4

from desire_platform.internal_pilot.deployment_config import (
    OIDC_NETWORK_BINDING_PINNED_PUBLIC_IP,
    OIDC_NETWORK_BINDING_SYSTEM_DNS_SYNTHETIC,
    parse_internal_sandbox_deployment_config,
)
from desire_platform.internal_pilot.production_plan import (
    INTERNAL_SANDBOX_ARTIFACT_REQUIREMENTS,
    INTERNAL_SANDBOX_CAPABILITY_ROLES,
    INTERNAL_SANDBOX_DEMAND_IDEMPOTENCY_KEY_ID,
    INTERNAL_SANDBOX_DEMAND_IDEMPOTENCY_KEY_IDS,
    INTERNAL_SANDBOX_DEMAND_PAYLOAD_KEY_ID,
    INTERNAL_SANDBOX_DEMAND_PAYLOAD_KEY_IDS,
    INTERNAL_SANDBOX_KEY_PURPOSES,
    INTERNAL_SANDBOX_MATCHING_RUNTIME_CAPABILITY_ROLES,
    INTERNAL_SANDBOX_MATCHING_RUNTIME_KEY_PURPOSES,
    INTERNAL_SANDBOX_MATCHING_IDEMPOTENCY_KEY_ID,
    INTERNAL_SANDBOX_MATCHING_PAYLOAD_KEY_ID,
    INTERNAL_SANDBOX_MATCHING_READ_CURSOR_KEY_ID,
    INTERNAL_SANDBOX_TRUST_IDEMPOTENCY_KEY_ID,
    INTERNAL_SANDBOX_TRUST_PAYLOAD_KEY_ID,
    INTERNAL_SANDBOX_TRUST_REPORT_CURSOR_KEY_ID,
    INTERNAL_SANDBOX_TRUST_SEALED_NOTE_KEY_ID,
    INTERNAL_SANDBOX_ONLINE_CAPABILITY_ROLES,
)
from desire_platform.internal_pilot.secrets import parse_file_secret_manifest
from desire_platform.runtime.config import parse_runtime_config


_CONFIG_DIR = "config"
_SECRET_DIR = "runtime-secrets"
_DEPLOYMENT_PATH = "/run/desire/deployment.json"
_RUNTIME_PATH = "/run/desire/runtime-config.json"
_MANIFEST_PATH = "/run/desire/secret-manifest.json"
_MATCHING_RUNTIME_PATH = "/run/desire/matching-runtime-config.json"
_MATCHING_MANIFEST_PATH = "/run/desire/matching-secret-manifest.json"
_ONLINE_RUNTIME_PATH = "/run/desire/online-credentials-runtime-config.json"
_ONLINE_MANIFEST_PATH = "/run/desire/online-credentials-secret-manifest.json"
_CONTAINER_SECRET_ROOT = "/run/secrets"
_OIDC_CLIENT_KEY_ID = "oidc-client-secret-v1"
_OIDC_SUBJECT_KEY_ID = "oidc-subject-digest-v1"
_PLATFORM_USER_IDEMPOTENCY_KEY_ID = "iam-receipt-idempotency-hmac-2026-01"
_PLATFORM_USER_PAYLOAD_KEY_ID = "iam-receipt-payload-hmac-2026-01"
_ACTIVE_COMPOSE_KEY_FILE_NAMES = {
    "DEMAND_IDEMPOTENCY": "key-demand-idempotency-v1",
    "DEMAND_PAYLOAD_HASH": "key-demand-payload-hash-v1",
    "TRUST_IDEMPOTENCY": "key-trust-idempotency-v1",
    "TRUST_PAYLOAD_HASH": "key-trust-payload-hash-v1",
    "TRUST_SEALED_NOTE": "key-trust-sealed-note-v1",
    "TRUST_REPORT_CURSOR": "key-trust-report-cursor-v1",
    "MATCHING_IDEMPOTENCY": "key-matching-idempotency-v1",
    "MATCHING_PAYLOAD_HASH": "key-matching-payload-v1",
    "MATCHING_READ_CURSOR": "key-matching-read-cursor-v1",
}
_RETAINED_COMPOSE_KEY_FILE_NAMES = {
    (
        "DEMAND_IDEMPOTENCY",
        "demand-idempotency-retained-2025-12",
    ): "key-demand-idempotency-retained-2025-12",
    (
        "DEMAND_PAYLOAD_HASH",
        "demand-payload-retained-2025-12",
    ): "key-demand-payload-retained-2025-12",
}
_MATCHING_RUNTIME_KEY_IDS = {
    purpose: purpose.lower().replace("_", "-") + "-v1"
    for purpose in INTERNAL_SANDBOX_MATCHING_RUNTIME_KEY_PURPOSES
}


class InternalSandboxBundleError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class InternalSandboxBundleRequest:
    output_dir: Path
    oidc_issuer: str
    oidc_client_id: str
    oidc_redirect_uri: str
    oidc_client_secret_file: Path
    oidc_network_binding_mode: str
    oidc_pinned_public_ipv4: Optional[str]
    deployment_id: str
    release_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.output_dir, Path) or not isinstance(
            self.oidc_client_secret_file, Path
        ):
            raise TypeError("internal sandbox bundle paths are invalid")
        for value in (
            self.oidc_issuer,
            self.oidc_client_id,
            self.oidc_redirect_uri,
            self.oidc_network_binding_mode,
            self.deployment_id,
            self.release_id,
        ):
            if (
                not isinstance(value, str)
                or not value
                or value != value.strip()
                or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
            ):
                raise ValueError("internal sandbox bundle input is invalid")
        if self.oidc_network_binding_mode == OIDC_NETWORK_BINDING_SYSTEM_DNS_SYNTHETIC:
            if self.oidc_pinned_public_ipv4 is not None:
                raise ValueError("internal sandbox bundle input is invalid")
        elif self.oidc_network_binding_mode == OIDC_NETWORK_BINDING_PINNED_PUBLIC_IP:
            if (
                not isinstance(self.oidc_pinned_public_ipv4, str)
                or not self.oidc_pinned_public_ipv4
                or self.oidc_pinned_public_ipv4 != self.oidc_pinned_public_ipv4.strip()
            ):
                raise ValueError("internal sandbox bundle input is invalid")
        else:
            raise ValueError("internal sandbox bundle input is invalid")


@dataclass(frozen=True, repr=False)
class InternalSandboxBundleReport:
    output_dir: Path
    database_credential_count: int
    key_count: int
    secret_count: int
    system_actor_id: UUID

    def __repr__(self) -> str:
        return (
            "InternalSandboxBundleReport("
            f"output_dir={str(self.output_dir)!r}, "
            f"entry_count={self.secret_count}, material=<redacted>)"
        )


@dataclass(frozen=True)
class _BundleDocuments:
    api_runtime: dict[str, Any]
    api_manifest: dict[str, Any]
    matching_runtime: dict[str, Any]
    matching_manifest: dict[str, Any]
    online_runtime: dict[str, Any]
    online_manifest: dict[str, Any]
    deployment: dict[str, Any]
    matching_deployment: dict[str, Any]
    online_deployment: dict[str, Any]
    materials: dict[str, bytes]


def _random_material(_purpose: str, length: int) -> bytes:
    if length not in (32, 48, 64):
        raise ValueError("unsupported material length")
    raw_length = {32: 24, 48: 36, 64: 48}[length]
    value = base64.urlsafe_b64encode(secrets.token_bytes(raw_length))
    if len(value) != length:
        raise RuntimeError("random material length drifted")
    return value


def create_internal_sandbox_bundle(
    request: InternalSandboxBundleRequest,
    *,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    material_factory: Callable[[str, int], bytes] = _random_material,
    id_factory: Callable[[], UUID] = uuid4,
) -> InternalSandboxBundleReport:
    """Create a fresh bundle and atomically rename it into the requested path."""

    temporary: Optional[Path] = None
    try:
        if not isinstance(request, InternalSandboxBundleRequest):
            _blocked("INTERNAL_SANDBOX_BUNDLE_INPUT_INVALID")
        output = _new_canonical_target(request.output_dir)
        client_secret = _read_client_secret(request.oidc_client_secret_file)
        now = clock()
        if (
            not isinstance(now, datetime)
            or now.tzinfo is None
            or now.utcoffset() != timedelta(0)
        ):
            _blocked("INTERNAL_SANDBOX_BUNDLE_CLOCK_INVALID")
        now = now.replace(microsecond=0)
        system_actor_id = id_factory()
        if not isinstance(system_actor_id, UUID) or system_actor_id.int == 0:
            _blocked("INTERNAL_SANDBOX_BUNDLE_IDENTIFIER_INVALID")

        parent = output.parent
        temporary = Path(tempfile.mkdtemp(prefix=".desire-bundle-", dir=str(parent)))
        temporary.chmod(0o700)
        config_dir = temporary / _CONFIG_DIR
        secret_dir = temporary / _SECRET_DIR
        config_dir.mkdir(mode=0o700)
        secret_dir.mkdir(mode=0o700)

        documents = _build_documents(
            request=request,
            now=now,
            system_actor_id=system_actor_id,
            client_secret=client_secret,
            material_factory=material_factory,
        )
        if len(
            {
                hashlib.sha256(value).digest()
                for value in documents.materials.values()
            }
        ) != len(
            documents.materials
        ):
            _blocked("INTERNAL_SANDBOX_BUNDLE_SECRET_ALIAS")

        _write_json(config_dir / "deployment.json", documents.deployment)
        _write_json(config_dir / "runtime-config.json", documents.api_runtime)
        _write_json(config_dir / "secret-manifest.json", documents.api_manifest)
        _write_json(
            config_dir / "matching-runtime-config.json",
            documents.matching_runtime,
        )
        _write_json(
            config_dir / "matching-secret-manifest.json",
            documents.matching_manifest,
        )
        _write_json(
            config_dir / "online-credentials-runtime-config.json",
            documents.online_runtime,
        )
        _write_json(
            config_dir / "online-credentials-secret-manifest.json",
            documents.online_manifest,
        )
        _write_json(
            config_dir / "online-credentials-deployment.json",
            documents.online_deployment,
        )
        _write_json(
            config_dir / "matching-deployment.json",
            documents.matching_deployment,
        )
        for file_name, value in documents.materials.items():
            _write_bytes(secret_dir / file_name, value)

        # Reparse the exact bytes that the runtime will consume before the
        # atomic rename makes the bundle visible.
        parse_internal_sandbox_deployment_config(
            (config_dir / "deployment.json").read_bytes()
        )
        parsed_api_runtime = parse_runtime_config(
            (config_dir / "runtime-config.json").read_bytes()
        )
        parsed_api_entries = parse_file_secret_manifest(
            (config_dir / "secret-manifest.json").read_bytes()
        )
        parsed_matching_runtime = parse_runtime_config(
            (config_dir / "matching-runtime-config.json").read_bytes()
        )
        parsed_matching_entries = parse_file_secret_manifest(
            (config_dir / "matching-secret-manifest.json").read_bytes()
        )
        parsed_online_runtime = parse_runtime_config(
            (config_dir / "online-credentials-runtime-config.json").read_bytes()
        )
        parsed_online_entries = parse_file_secret_manifest(
            (
                config_dir / "online-credentials-secret-manifest.json"
            ).read_bytes()
        )
        parse_internal_sandbox_deployment_config(
            (config_dir / "online-credentials-deployment.json").read_bytes()
        )
        parse_internal_sandbox_deployment_config(
            (config_dir / "matching-deployment.json").read_bytes()
        )
        referenced_files = {
            item.file_name
            for entries in (
                parsed_api_entries,
                parsed_matching_entries,
                parsed_online_entries,
            )
            for item in entries
        }
        if (
            parsed_api_runtime.artifacts != INTERNAL_SANDBOX_ARTIFACT_REQUIREMENTS
            or tuple(item.purpose for item in parsed_api_runtime.key_requirements)
            != INTERNAL_SANDBOX_KEY_PURPOSES
            or parsed_matching_runtime.process.kind != "domain-process"
            or tuple(
                item.purpose
                for item in parsed_matching_runtime.key_requirements
            )
            != INTERNAL_SANDBOX_MATCHING_RUNTIME_KEY_PURPOSES
            or parsed_online_runtime.process.kind != "migration"
            or parsed_online_runtime.key_requirements
            or referenced_files != set(documents.materials)
        ):
            _blocked("INTERNAL_SANDBOX_BUNDLE_CONTRACT_INVALID")

        os.replace(temporary, output)
        temporary = None
        return InternalSandboxBundleReport(
            output_dir=output,
            database_credential_count=len(
                INTERNAL_SANDBOX_ONLINE_CAPABILITY_ROLES
            ),
            key_count=(
                len(documents.materials)
                - len(INTERNAL_SANDBOX_ONLINE_CAPABILITY_ROLES)
            ),
            secret_count=len(documents.materials),
            system_actor_id=system_actor_id,
        )
    except InternalSandboxBundleError:
        raise
    except BaseException:
        raise InternalSandboxBundleError("INTERNAL_SANDBOX_BUNDLE_CREATION_FAILED") from None
    finally:
        if temporary is not None:
            shutil.rmtree(temporary, ignore_errors=True)


def _build_documents(
    *,
    request: InternalSandboxBundleRequest,
    now: datetime,
    system_actor_id: UUID,
    client_secret: bytes,
    material_factory: Callable[[str, int], bytes],
) -> _BundleDocuments:
    if not callable(material_factory):
        _blocked("INTERNAL_SANDBOX_BUNDLE_RANDOM_SOURCE_INVALID")
    not_before = _utc(now - timedelta(minutes=5))
    not_after = _utc(now + timedelta(days=365))
    materials: dict[str, bytes] = {}
    profiles_by_capability: dict[str, dict[str, Any]] = {}
    entries_by_capability: dict[str, dict[str, Any]] = {}
    for capability_id, online_role in INTERNAL_SANDBOX_ONLINE_CAPABILITY_ROLES:
        slug = capability_id.lower().replace("_", "-")
        key_id = "v1"
        file_name = f"db-{slug}-{key_id}"
        credential_ref = f"secret://sandbox-db/{slug}#{key_id}"
        material = _material(material_factory, f"DATABASE_CREDENTIAL:{capability_id}", 48)
        materials[file_name] = material
        profiles_by_capability[capability_id] = {
            "capability_id": capability_id,
            "online_role": online_role,
            "credential_ref": credential_ref,
            "application_name": f"desire-{slug}",
            "max_pool_size": 4,
            "checkout_timeout_ms": 2_000,
            "statement_timeout_ms": 15_000,
            "lock_timeout_ms": 2_000,
            "idle_in_transaction_timeout_ms": 15_000,
        }
        entries_by_capability[capability_id] = _manifest_entry(
            kind="DATABASE_CREDENTIAL",
            file_name=file_name,
            credential_ref=credential_ref,
            purpose=f"DATABASE_CREDENTIAL:{capability_id}",
            key_id=key_id,
            not_before=not_before,
            not_after=not_after,
        )

    api_key_requirements = []
    api_key_entries = []
    key_ids: dict[str, str] = {}
    for purpose in INTERNAL_SANDBOX_KEY_PURPOSES:
        key_id = (
            _OIDC_CLIENT_KEY_ID
            if purpose == "OIDC_CLIENT_SECRET"
            else _OIDC_SUBJECT_KEY_ID
            if purpose == "OIDC_SUBJECT_DIGEST"
            else _PLATFORM_USER_IDEMPOTENCY_KEY_ID
            if purpose == "PLATFORM_USER_IDEMPOTENCY"
            else _PLATFORM_USER_PAYLOAD_KEY_ID
            if purpose == "PLATFORM_USER_PAYLOAD_HASH"
            else INTERNAL_SANDBOX_DEMAND_IDEMPOTENCY_KEY_ID
            if purpose == "DEMAND_IDEMPOTENCY"
            else INTERNAL_SANDBOX_DEMAND_PAYLOAD_KEY_ID
            if purpose == "DEMAND_PAYLOAD_HASH"
            else INTERNAL_SANDBOX_TRUST_IDEMPOTENCY_KEY_ID
            if purpose == "TRUST_IDEMPOTENCY"
            else INTERNAL_SANDBOX_TRUST_PAYLOAD_KEY_ID
            if purpose == "TRUST_PAYLOAD_HASH"
            else INTERNAL_SANDBOX_TRUST_SEALED_NOTE_KEY_ID
            if purpose == "TRUST_SEALED_NOTE"
            else INTERNAL_SANDBOX_TRUST_REPORT_CURSOR_KEY_ID
            if purpose == "TRUST_REPORT_CURSOR"
            else INTERNAL_SANDBOX_MATCHING_IDEMPOTENCY_KEY_ID
            if purpose == "MATCHING_IDEMPOTENCY"
            else INTERNAL_SANDBOX_MATCHING_PAYLOAD_KEY_ID
            if purpose == "MATCHING_PAYLOAD_HASH"
            else INTERNAL_SANDBOX_MATCHING_READ_CURSOR_KEY_ID
            if purpose == "MATCHING_READ_CURSOR"
            else purpose.lower().replace("_", "-") + "-v1"
        )
        key_ids[purpose] = key_id
        retained_key_ids = (
            INTERNAL_SANDBOX_DEMAND_IDEMPOTENCY_KEY_IDS
            if purpose == "DEMAND_IDEMPOTENCY"
            else INTERNAL_SANDBOX_DEMAND_PAYLOAD_KEY_IDS
            if purpose == "DEMAND_PAYLOAD_HASH"
            else (key_id,)
        )
        api_key_requirements.append(
            {
                "purpose": purpose,
                "active_key_id": key_id,
                "retained_key_ids": list(retained_key_ids),
            }
        )
        for retained_key_id in retained_key_ids:
            file_name = _key_file_name(
                purpose=purpose,
                active_key_id=key_id,
                key_id=retained_key_id,
            )
            value = (
                client_secret
                if purpose == "OIDC_CLIENT_SECRET"
                else _material(
                    material_factory,
                    (
                        purpose
                        if retained_key_id == key_id
                        else f"{purpose}:{retained_key_id}"
                    ),
                    32 if purpose == "OIDC_PROTOCOL_AEAD" else 48,
                )
            )
            materials[file_name] = value
            api_key_entries.append(
                _manifest_entry(
                    kind="KEY",
                    file_name=file_name,
                    credential_ref=None,
                    purpose=purpose,
                    key_id=retained_key_id,
                    not_before=not_before,
                    not_after=not_after,
                    status=(
                        "ACTIVE" if retained_key_id == key_id else "VERIFY_ONLY"
                    ),
                )
            )

    matching_key_requirements = []
    matching_key_entries = []
    for purpose in INTERNAL_SANDBOX_MATCHING_RUNTIME_KEY_PURPOSES:
        key_id = _MATCHING_RUNTIME_KEY_IDS[purpose]
        file_name = "key-" + key_id
        materials[file_name] = _material(material_factory, purpose, 48)
        matching_key_requirements.append(
            {
                "purpose": purpose,
                "active_key_id": key_id,
                "retained_key_ids": [key_id],
            }
        )
        matching_key_entries.append(
            _manifest_entry(
                kind="KEY",
                file_name=file_name,
                credential_ref=None,
                purpose=purpose,
                key_id=key_id,
                not_before=not_before,
                not_after=not_after,
            )
        )

    artifact_documents = [
        {"artifact_id": item.artifact_id, "sha256": item.sha256}
        for item in INTERNAL_SANDBOX_ARTIFACT_REQUIREMENTS
    ]
    budgets = {
        "startup_timeout_ms": 30_000,
        "readiness_timeout_ms": 3_000,
        "shutdown_timeout_ms": 15_000,
    }
    api_capabilities = tuple(item[0] for item in INTERNAL_SANDBOX_CAPABILITY_ROLES)
    matching_capabilities = tuple(
        item[0] for item in INTERNAL_SANDBOX_MATCHING_RUNTIME_CAPABILITY_ROLES
    )
    online_capabilities = tuple(
        item[0] for item in INTERNAL_SANDBOX_ONLINE_CAPABILITY_ROLES
    )
    api_runtime = {
        "schema_name": "desire-runtime-config-v1",
        "identity": {
            "environment_id": "internal-sandbox",
            "deployment_id": request.deployment_id,
            "release_id": request.release_id,
            "region": "trusted-container-network",
            "instance_id": "api-0001",
        },
        "process": {
            "kind": "web-api",
            "capability_ids": list(api_capabilities),
        },
        "artifacts": artifact_documents,
        "database_profiles": [
            profiles_by_capability[item] for item in api_capabilities
        ],
        "key_requirements": api_key_requirements,
        "budgets": budgets,
    }
    matching_runtime = {
        "schema_name": "desire-runtime-config-v1",
        "identity": {
            "environment_id": "internal-sandbox",
            "deployment_id": request.deployment_id,
            "release_id": request.release_id,
            "region": "trusted-container-network",
            "instance_id": "matching-runtime-0001",
        },
        "process": {
            "kind": "domain-process",
            "capability_ids": list(matching_capabilities),
        },
        "artifacts": artifact_documents,
        "database_profiles": [
            profiles_by_capability[item] for item in matching_capabilities
        ],
        "key_requirements": matching_key_requirements,
        "budgets": budgets,
    }
    online_runtime = {
        "schema_name": "desire-runtime-config-v1",
        "identity": {
            "environment_id": "internal-sandbox",
            "deployment_id": request.deployment_id,
            "release_id": request.release_id,
            "region": "trusted-container-network",
            "instance_id": "online-credentials-0001",
        },
        "process": {
            "kind": "migration",
            "capability_ids": list(online_capabilities),
        },
        "artifacts": artifact_documents,
        "database_profiles": [
            profiles_by_capability[item] for item in online_capabilities
        ],
        "key_requirements": [],
        "budgets": budgets,
    }
    api_manifest = {
        "schema_name": "desire-file-secret-manifest-v1",
        "entries": [
            entries_by_capability[item] for item in api_capabilities
        ]
        + api_key_entries,
    }
    matching_manifest = {
        "schema_name": "desire-file-secret-manifest-v1",
        "entries": [
            entries_by_capability[item] for item in matching_capabilities
        ]
        + matching_key_entries,
    }
    online_manifest = {
        "schema_name": "desire-file-secret-manifest-v1",
        "entries": [
            entries_by_capability[item] for item in online_capabilities
        ],
    }
    deployment = {
        "schema_name": "desire-internal-sandbox-deployment-v1",
        "deployment_mode": "INTERNAL_SANDBOX",
        "external_participants_enabled": False,
        "internal_bff_origin": "http://api:8000",
        "runtime_config_path": _RUNTIME_PATH,
        "secret_manifest_path": _MANIFEST_PATH,
        "secret_root": _CONTAINER_SECRET_ROOT,
        "postgres": {
            "host": "db",
            "port": 5432,
            "database": "desire",
            "transport_security": "TRUSTED_CONTAINER_NETWORK",
        },
        "oidc": {
            "issuer": request.oidc_issuer,
            "client_id": request.oidc_client_id,
            "client_secret_key_id": key_ids["OIDC_CLIENT_SECRET"],
            "redirect_uri": request.oidc_redirect_uri,
            "allowed_signing_algorithms": ["RS256"],
            "metadata_ttl_seconds": 300,
            "request_timeout_seconds": 3,
            "maximum_response_bytes": 262_144,
            "clock_skew_seconds": 30,
            "subject_digest_key_id": key_ids["OIDC_SUBJECT_DIGEST"],
            "network_binding": {
                "mode": request.oidc_network_binding_mode,
                "pinned_public_ipv4": request.oidc_pinned_public_ipv4,
            },
        },
        "system_actor_id": str(system_actor_id),
        "bind": {"host": "0.0.0.0", "port": 8_000},
    }
    online_deployment = {
        **deployment,
        "runtime_config_path": _ONLINE_RUNTIME_PATH,
        "secret_manifest_path": _ONLINE_MANIFEST_PATH,
    }
    matching_deployment = {
        **deployment,
        "runtime_config_path": _MATCHING_RUNTIME_PATH,
        "secret_manifest_path": _MATCHING_MANIFEST_PATH,
    }
    return _BundleDocuments(
        api_runtime=api_runtime,
        api_manifest=api_manifest,
        matching_runtime=matching_runtime,
        matching_manifest=matching_manifest,
        online_runtime=online_runtime,
        online_manifest=online_manifest,
        deployment=deployment,
        matching_deployment=matching_deployment,
        online_deployment=online_deployment,
        materials=materials,
    )


def _key_file_name(*, purpose: str, active_key_id: str, key_id: str) -> str:
    if key_id == active_key_id:
        return _ACTIVE_COMPOSE_KEY_FILE_NAMES.get(purpose, "key-" + key_id)
    file_name = _RETAINED_COMPOSE_KEY_FILE_NAMES.get((purpose, key_id))
    if file_name is None:
        _blocked("INTERNAL_SANDBOX_BUNDLE_CONTRACT_INVALID")
    return file_name


def _manifest_entry(
    *,
    kind: str,
    file_name: str,
    credential_ref: Optional[str],
    purpose: str,
    key_id: str,
    not_before: str,
    not_after: str,
    status: str = "ACTIVE",
) -> dict[str, Any]:
    return {
        "kind": kind,
        "file_name": file_name,
        "credential_ref": credential_ref,
        "purpose": purpose,
        "key_id": key_id,
        "not_before": not_before,
        "not_after": not_after,
        "status": status,
    }


def _material(
    factory: Callable[[str, int], bytes], purpose: str, length: int
) -> bytes:
    value = factory(purpose, length)
    if (
        type(value) is not bytes
        or len(value) != length
        or not any(value)
        or any(token in value for token in (b"\x00", b"\r", b"\n"))
    ):
        _blocked("INTERNAL_SANDBOX_BUNDLE_RANDOM_SOURCE_INVALID")
    return value


def _new_canonical_target(path: Path) -> Path:
    if not path.is_absolute() or path.exists() or path.is_symlink():
        _blocked("INTERNAL_SANDBOX_BUNDLE_TARGET_EXISTS")
    try:
        parent = path.parent.resolve(strict=True)
    except OSError:
        _blocked("INTERNAL_SANDBOX_BUNDLE_TARGET_INVALID")
    if not parent.is_dir() or parent.is_symlink() or path != parent / path.name:
        _blocked("INTERNAL_SANDBOX_BUNDLE_TARGET_INVALID")
    return path


def _read_client_secret(path: Path) -> bytes:
    try:
        if not path.is_absolute() or path.is_symlink():
            raise OSError
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
        if (
            resolved != path
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise OSError
        raw = resolved.read_bytes()
    except OSError:
        _blocked("INTERNAL_SANDBOX_BUNDLE_CLIENT_SECRET_INVALID")
    if (
        not 32 <= len(raw) <= 4_096
        or not any(raw)
        or any(token in raw for token in (b"\x00", b"\r", b"\n"))
    ):
        _blocked("INTERNAL_SANDBOX_BUNDLE_CLIENT_SECRET_INVALID")
    return raw


def _write_json(path: Path, value: Any) -> None:
    _write_bytes(
        path,
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=False).encode(
            "ascii"
        ),
    )


def _write_bytes(path: Path, value: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        written = 0
        while written < len(value):
            count = os.write(descriptor, value[written:])
            if count <= 0:
                raise OSError
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _blocked(code: str) -> NoReturn:
    raise InternalSandboxBundleError(code)


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    material_factory: Callable[[str, int], bytes] = _random_material,
) -> int:
    output_stream = sys.stdout if stdout is None else stdout
    error_stream = sys.stderr if stderr is None else stderr
    parser = argparse.ArgumentParser(
        prog="python -m desire_platform.deployment.internal_sandbox_bundle"
    )
    subparsers = parser.add_subparsers(dest="action", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("--output-dir", required=True)
    create.add_argument("--oidc-issuer", required=True)
    create.add_argument("--oidc-client-id", required=True)
    create.add_argument("--oidc-redirect-uri", required=True)
    create.add_argument("--oidc-client-secret-file", required=True)
    create.add_argument(
        "--oidc-network-binding-mode",
        required=True,
        choices=(
            OIDC_NETWORK_BINDING_SYSTEM_DNS_SYNTHETIC,
            OIDC_NETWORK_BINDING_PINNED_PUBLIC_IP,
        ),
    )
    create.add_argument("--oidc-pinned-public-ipv4")
    create.add_argument("--deployment-id", required=True)
    create.add_argument("--release-id", required=True)
    arguments = parser.parse_args(argv)
    try:
        report = create_internal_sandbox_bundle(
            InternalSandboxBundleRequest(
                output_dir=Path(arguments.output_dir),
                oidc_issuer=arguments.oidc_issuer,
                oidc_client_id=arguments.oidc_client_id,
                oidc_redirect_uri=arguments.oidc_redirect_uri,
                oidc_client_secret_file=Path(arguments.oidc_client_secret_file),
                oidc_network_binding_mode=arguments.oidc_network_binding_mode,
                oidc_pinned_public_ipv4=arguments.oidc_pinned_public_ipv4,
                deployment_id=arguments.deployment_id,
                release_id=arguments.release_id,
            ),
            clock=clock,
            material_factory=material_factory,
        )
    except InternalSandboxBundleError as error:
        error_stream.write(
            json.dumps(
                {"code": error.code, "status": "BLOCKED"},
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        )
        return 78
    except BaseException:
        error_stream.write(
            '{"code":"INTERNAL_SANDBOX_BUNDLE_CREATION_FAILED","status":"BLOCKED"}\n'
        )
        return 78
    output_stream.write(
        json.dumps(
            {
                "database_credential_count": report.database_credential_count,
                "key_count": report.key_count,
                "output_dir": str(report.output_dir),
                "secret_count": report.secret_count,
                "status": "INTERNAL_SANDBOX_BUNDLE_CREATED",
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = (
    "InternalSandboxBundleError",
    "InternalSandboxBundleReport",
    "InternalSandboxBundleRequest",
    "create_internal_sandbox_bundle",
    "main",
)
