#!/usr/bin/env python3
"""Pure release-grade closure for the private-server Compose document."""

from __future__ import annotations

import copy
import ipaddress
import json
import os
from pathlib import PurePosixPath
import re
from typing import Any, Mapping, NoReturn


_MAX_JSON_BYTES = 2 * 1024 * 1024
_PROJECT = re.compile(
    r"^desire-private-ingress-(?:[a-z0-9]|[a-z0-9][a-z0-9-]{0,38}[a-z0-9])$"
)
_SAFE_TOKEN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_PATH = re.compile(r"^/[A-Za-z0-9._~+/-]+$")
_POSTGRES_REF = (
    "postgres:18.4-alpine@sha256:"
    "9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15"
)
_TOP_LEVEL = frozenset(
    {
        "configs",
        "name",
        "networks",
        "secrets",
        "services",
        "volumes",
        "x-deployment-admin",
        "x-hardened",
        "x-identity-configs",
        "x-identity-bootstrap-secrets",
        "x-matching-runtime-configs",
        "x-matching-runtime-secrets",
        "x-online-credential-configs",
        "x-online-database-secrets",
        "x-runtime-configs",
        "x-runtime-secrets",
    }
)
_CANONICAL_TOP_LEVEL = frozenset(
    {"configs", "name", "networks", "secrets", "services", "volumes"}
)
_EXTENSION_TYPES = {
    "x-deployment-admin": dict,
    "x-hardened": dict,
    "x-identity-configs": list,
    "x-identity-bootstrap-secrets": list,
    "x-matching-runtime-configs": list,
    "x-matching-runtime-secrets": list,
    "x-online-credential-configs": list,
    "x-online-database-secrets": list,
    "x-runtime-configs": list,
    "x-runtime-secrets": list,
}
_SERVICE_NAMES = frozenset(
    {
        "api",
        "db",
        "edge",
        "identity-bootstrap",
        "matching-runtime",
        "migrate",
        "online-credentials-reconcile",
        "online-credentials-verify",
        "synthetic-oidc",
        "taxonomy-seed",
        "web",
    }
)
_NETWORK_NAMES = frozenset({"app", "data", "ingress", "oidc-backend"})
_INTERNAL_NETWORKS = frozenset({"app", "data", "oidc-backend"})
_SYNTHETIC_OIDC_NETWORK_BINDING = {
    "mode": "SYSTEM_DNS_SYNTHETIC",
    "pinned_public_ipv4": None,
}
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
_API_RUNTIME_SECRETS = (
    "db-iam-app-v1",
    "db-iam-session-authenticator-v1",
    "db-iam-onboarding-v1",
    "db-profile-app-v1",
    "db-demand-self-v1",
    "db-demand-review-v1",
    "db-demand-finance-v1",
    "db-trust-self-v1",
    "db-trust-officer-v1",
    "db-trust-appeal-v1",
    "db-trust-decision-v1",
    "db-matching-creator-v1",
    "db-matching-selector-v1",
    "db-matching-assignment-v1",
    "db-matching-review-v1",
    "key-oidc-state-v1",
    "key-oidc-browser-binding-v1",
    "key-oidc-nonce-v1",
    "key-session-handle-v1",
    "key-csrf-v1",
    "key-oidc-protocol-aead-v1",
    "key-oidc-subject-digest-v1",
    "key-oidc-recipient-binding-v1",
    "key-oidc-client-secret-v1",
    "key-editor-id-derivation-v1",
    "key-profile-idempotency-v1",
    "key-profile-payload-hash-v1",
    "key-demand-idempotency-v1",
    "key-demand-idempotency-retained-2025-12",
    "key-demand-payload-hash-v1",
    "key-demand-payload-retained-2025-12",
    "key-demand-client-reference-v1",
    "key-iam-receipt-idempotency-hmac-2026-01",
    "key-iam-receipt-payload-hmac-2026-01",
    "key-access-invitation-token-v1",
    "key-iam-read-cursor-v1",
    "key-trust-idempotency-v1",
    "key-trust-payload-hash-v1",
    "key-trust-sealed-note-v1",
    "key-trust-report-cursor-v1",
    "key-matching-idempotency-v1",
    "key-matching-payload-v1",
    "key-matching-read-cursor-v1",
)
_MATCHING_RUNTIME_SECRETS = (
    "db-demand-matching-v1",
    "db-profile-matcher-v1",
    "db-trust-decision-v1",
    "db-matching-worker-v1",
    "db-matching-coordinator-v1",
    "key-matching-worker-idempotency-v1",
    "key-matching-worker-payload-hash-v1",
    "key-matching-worker-lease-digest-v1",
    "key-matching-coordinator-idempotency-v1",
    "key-matching-coordinator-payload-hash-v1",
    "key-matching-coordinator-lease-digest-v1",
)
_ONLINE_RUNTIME_SECRETS = _API_RUNTIME_SECRETS + tuple(
    name for name in _MATCHING_RUNTIME_SECRETS if name not in _API_RUNTIME_SECRETS
)
_RUNTIME_SECRETS = _API_RUNTIME_SECRETS
_CONFIG_NAMES = (
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
_SECRET_NAMES = (
    "db_superuser_password",
    "taxonomy_seed_workload_credential",
    "taxonomy_seed_receipt_hmac_key",
    "edge-tls-key",
) + _ONLINE_RUNTIME_SECRETS
_IDENTITY_FILES = frozenset(
    {
        "access_admin_01.email",
        "access_admin_01.subject",
        "appeal_reviewer_01.email",
        "appeal_reviewer_01.subject",
        "creator_01.email",
        "creator_01.subject",
        "demand_owner_01.email",
        "demand_owner_01.subject",
        "finance_operator_01.email",
        "finance_operator_01.subject",
        "finance_operator_02.email",
        "finance_operator_02.subject",
        "operations_reviewer_01.email",
        "operations_reviewer_01.subject",
        "org_admin_01.email",
        "org_admin_01.subject",
        "trust_officer_01.email",
        "trust_officer_01.subject",
        "trust_officer_02.email",
        "trust_officer_02.subject",
    }
)
_RAW_SERVICE_KEYS = {
    "api": frozenset(
        {
            "build",
            "cap_drop",
            "command",
            "configs",
            "depends_on",
            "entrypoint",
            "environment",
            "healthcheck",
            "image",
            "init",
            "networks",
            "read_only",
            "restart",
            "secrets",
            "security_opt",
            "stop_grace_period",
            "tmpfs",
        }
    ),
    "db": frozenset(
        {
            "command",
            "entrypoint",
            "environment",
            "healthcheck",
            "image",
            "networks",
            "restart",
            "secrets",
            "shm_size",
            "stop_grace_period",
            "tmpfs",
            "volumes",
        }
    ),
    "edge": frozenset(
        {
            "build",
            "cap_drop",
            "command",
            "configs",
            "depends_on",
            "entrypoint",
            "healthcheck",
            "image",
            "init",
            "networks",
            "ports",
            "read_only",
            "restart",
            "secrets",
            "security_opt",
            "sysctls",
            "tmpfs",
        }
    ),
    "identity-bootstrap": frozenset(
        {
            "cap_drop",
            "command",
            "configs",
            "depends_on",
            "entrypoint",
            "environment",
            "image",
            "init",
            "networks",
            "read_only",
            "restart",
            "secrets",
            "security_opt",
            "tmpfs",
            "volumes",
        }
    ),
    "migrate": frozenset(
        {
            "build",
            "cap_drop",
            "command",
            "depends_on",
            "entrypoint",
            "environment",
            "image",
            "init",
            "networks",
            "read_only",
            "restart",
            "secrets",
            "security_opt",
            "tmpfs",
        }
    ),
    "matching-runtime": frozenset(
        {
            "cap_drop",
            "command",
            "configs",
            "depends_on",
            "entrypoint",
            "environment",
            "healthcheck",
            "image",
            "init",
            "networks",
            "read_only",
            "restart",
            "secrets",
            "security_opt",
            "stop_grace_period",
            "tmpfs",
        }
    ),
    "online-credentials-reconcile": frozenset(
        {
            "cap_drop",
            "command",
            "configs",
            "depends_on",
            "entrypoint",
            "environment",
            "image",
            "init",
            "networks",
            "read_only",
            "restart",
            "secrets",
            "security_opt",
            "tmpfs",
        }
    ),
    "online-credentials-verify": frozenset(
        {
            "cap_drop",
            "command",
            "configs",
            "depends_on",
            "entrypoint",
            "environment",
            "image",
            "init",
            "networks",
            "read_only",
            "restart",
            "secrets",
            "security_opt",
            "tmpfs",
        }
    ),
    "synthetic-oidc": frozenset(
        {
            "cap_drop",
            "command",
            "entrypoint",
            "environment",
            "healthcheck",
            "image",
            "init",
            "networks",
            "read_only",
            "restart",
            "secrets",
            "security_opt",
            "tmpfs",
        }
    ),
    "taxonomy-seed": frozenset(
        {
            "cap_drop",
            "command",
            "depends_on",
            "entrypoint",
            "environment",
            "image",
            "init",
            "networks",
            "read_only",
            "restart",
            "secrets",
            "security_opt",
            "tmpfs",
        }
    ),
    "web": frozenset(
        {
            "build",
            "cap_drop",
            "command",
            "depends_on",
            "entrypoint",
            "environment",
            "healthcheck",
            "image",
            "init",
            "networks",
            "read_only",
            "restart",
            "security_opt",
            "tmpfs",
        }
    ),
}
_HARDENED_SERVICES = _SERVICE_NAMES - {"db"}
_COMMON_TMPFS = ["/tmp:rw,noexec,nosuid,nodev,size=64m"]
_BOUNDED_LOGGING = {
    "driver": "local",
    "options": {
        "compress": "true",
        "max-file": "3",
        "max-size": "10m",
    },
}
_RAW_SERVICE_KEYS = {
    name: keys | frozenset(("logging",))
    for name, keys in _RAW_SERVICE_KEYS.items()
}


class PrivateServerComposeContractError(RuntimeError):
    """Stable error for a non-canonical or open Compose document."""

    def __init__(self) -> None:
        super().__init__("PRIVATE_SERVER_COMPOSE_CONTRACT_INVALID")


def _invalid() -> NoReturn:
    raise PrivateServerComposeContractError()


def validate_synthetic_oidc_network_binding(value: object) -> None:
    """Close the mutable-head synthetic deployment's OIDC network mode."""

    if (
        not isinstance(value, dict)
        or set(value) != {"mode", "pinned_public_ipv4"}
        or value != _SYNTHETIC_OIDC_NETWORK_BINDING
    ):
        _invalid()


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if not isinstance(key, str) or key in document:
            _invalid()
        document[key] = value
    return document


def _parse_document(value: str | bytes) -> dict[str, Any]:
    if isinstance(value, bytes):
        if not 0 < len(value) <= _MAX_JSON_BYTES or b"\x00" in value:
            _invalid()
        try:
            text = value.decode("utf-8", errors="strict")
        except UnicodeError:
            _invalid()
    elif isinstance(value, str):
        if (
            not value
            or "\x00" in value
            or len(value.encode("utf-8")) > _MAX_JSON_BYTES
        ):
            _invalid()
        text = value
    else:
        _invalid()
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=lambda unused: _invalid(),
        )
    except (json.JSONDecodeError, UnicodeError, RecursionError, TypeError):
        _invalid()
    if not isinstance(parsed, dict):
        _invalid()
    return parsed


def _exact_project(value: str) -> str:
    if not isinstance(value, str) or _PROJECT.fullmatch(value) is None or "v13" in value:
        _invalid()
    return value


def _safe_token(value: str) -> str:
    if (
        not isinstance(value, str)
        or _SAFE_TOKEN.fullmatch(value) is None
        or value in {"latest", "local"}
        or "v13" in value
    ):
        _invalid()
    return value


def _safe_absolute_path(value: str) -> str:
    if (
        not isinstance(value, str)
        or _SAFE_PATH.fullmatch(value) is None
        or "//" in value
    ):
        _invalid()
    path = PurePosixPath(value)
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        _invalid()
    if str(path) != value:
        _invalid()
    return value


def _exact_bind_ip(value: str) -> ipaddress.IPv4Address:
    if not isinstance(value, str) or value != value.strip():
        _invalid()
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        _invalid()
    if (
        not isinstance(address, ipaddress.IPv4Address)
        or str(address) != value
        or address.is_unspecified
        or address.is_loopback
        or not any(address in private for private in _RFC1918)
    ):
        _invalid()
    return address


def _exact_subnets(
    value: Mapping[str, str], *, bind_ip: ipaddress.IPv4Address
) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != _NETWORK_NAMES:
        _invalid()
    observed: list[ipaddress.IPv4Network] = []
    result: dict[str, str] = {}
    for name in ("app", "data", "ingress", "oidc-backend"):
        raw = value.get(name)
        if not isinstance(raw, str) or raw != raw.strip():
            _invalid()
        try:
            network = ipaddress.ip_network(raw, strict=True)
        except ValueError:
            _invalid()
        if (
            not isinstance(network, ipaddress.IPv4Network)
            or str(network) != raw
            or network.prefixlen != 24
            or network in _FROZEN_SUBNETS
            or bind_ip in network
            or not any(network.subnet_of(private) for private in _RFC1918)
        ):
            _invalid()
        observed.append(network)
        result[name] = raw
    if len(set(observed)) != 4:
        _invalid()
    return result


def _depends(name: str, condition: str) -> dict[str, dict[str, Any]]:
    return {name: {"condition": condition, "required": True}}


def _runtime_configs() -> list[dict[str, str]]:
    return _configs(
        "internal-sandbox-deployment",
        "internal-sandbox-runtime-config",
        "internal-sandbox-secret-manifest",
    )


def _matching_runtime_configs() -> list[dict[str, str]]:
    return _configs(
        "internal-sandbox-matching-deployment",
        "internal-sandbox-matching-runtime-config",
        "internal-sandbox-matching-secret-manifest",
    )


def _online_credential_configs() -> list[dict[str, str]]:
    return _configs(
        "internal-sandbox-online-credentials-deployment",
        "internal-sandbox-online-credentials-runtime-config",
        "internal-sandbox-online-credentials-secret-manifest",
    )


def _configs(*names: str) -> list[dict[str, str]]:
    targets = {
        "internal-sandbox-deployment": "/run/desire/deployment.json",
        "internal-sandbox-runtime-config": "/run/desire/runtime-config.json",
        "internal-sandbox-secret-manifest": "/run/desire/secret-manifest.json",
        "internal-sandbox-matching-deployment": (
            "/run/desire/matching-deployment.json"
        ),
        "internal-sandbox-matching-runtime-config": (
            "/run/desire/matching-runtime-config.json"
        ),
        "internal-sandbox-matching-secret-manifest": (
            "/run/desire/matching-secret-manifest.json"
        ),
        "internal-sandbox-online-credentials-deployment": (
            "/run/desire/online-credentials-deployment.json"
        ),
        "internal-sandbox-online-credentials-runtime-config": (
            "/run/desire/online-credentials-runtime-config.json"
        ),
        "internal-sandbox-online-credentials-secret-manifest": (
            "/run/desire/online-credentials-secret-manifest.json"
        ),
        "internal-sandbox-identity-template": (
            "/run/desire/identity-bootstrap-template.json"
        ),
        "internal-sandbox-root-ca": "/run/desire-tls/root-ca.pem",
        "internal-sandbox-edge-tls-chain": (
            "/run/desire-tls/edge-tls-chain.pem"
        ),
    }
    return [
        {"source": name, "target": targets[name], "mode": "0444"}
        for name in names
    ]


def _runtime_secrets() -> list[dict[str, str]]:
    return [{"source": name, "target": name} for name in _API_RUNTIME_SECRETS]


def _matching_runtime_secrets() -> list[dict[str, str]]:
    return [
        {"source": name, "target": name}
        for name in _MATCHING_RUNTIME_SECRETS
    ]


def _online_database_secrets() -> list[dict[str, str]]:
    return [
        {"source": "db_superuser_password", "target": "db_superuser_password"}
    ] + [
        {"source": name, "target": name}
        for name in _ONLINE_RUNTIME_SECRETS
        if name.startswith("db-")
    ]


def _identity_bootstrap_secrets() -> list[dict[str, str]]:
    return [
        {"source": "db_superuser_password", "target": "db_superuser_password"},
        {
            "source": "key-oidc-subject-digest-v1",
            "target": "key-oidc-subject-digest-v1",
        },
        {
            "source": "key-oidc-recipient-binding-v1",
            "target": "key-oidc-recipient-binding-v1",
        },
    ]


def _admin_environment() -> dict[str, str]:
    return {
        "DESIRE_DATABASE_ADMIN_USER": "postgres",
        "DESIRE_DATABASE_HOST": "db",
        "DESIRE_DATABASE_NAME": "desire",
        "DESIRE_DATABASE_PASSWORD_FILE": "/run/secrets/db_superuser_password",
        "DESIRE_DEPLOYMENT_MODE": "INTERNAL_SANDBOX",
        "DESIRE_EXTERNAL_PARTICIPANTS_ENABLED": "false",
    }


def _expected_commands() -> dict[str, Any]:
    return {
        "api": [
            "python",
            "-m",
            "desire_platform.internal_pilot.api_server",
        ],
        "db": None,
        "edge": None,
        "identity-bootstrap": [
            "python",
            "-m",
            "desire_platform.deployment.identity_bootstrap_orchestrator",
            "run",
        ],
        "migrate": ["python", "-m", "desire_platform.deployment"],
        "matching-runtime": [
            "python",
            "-m",
            "desire_platform.matching.runtime_process",
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
        "synthetic-oidc": ["python", "-m", "desire_platform.synthetic_oidc"],
        "taxonomy-seed": [
            "python",
            "-m",
            "desire_platform.deployment.synthetic_taxonomy_seed",
            "apply",
        ],
        "web": None,
    }


def _expected_environments() -> dict[str, dict[str, str]]:
    deployment = _admin_environment()
    taxonomy = dict(deployment)
    taxonomy.update(
        {
            "DESIRE_TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE": (
                "/run/secrets/taxonomy_seed_receipt_hmac_key"
            ),
            "DESIRE_TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE": (
                "/run/secrets/taxonomy_seed_workload_credential"
            ),
        }
    )
    online = dict(deployment)
    online["DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE"] = (
        "/run/desire/online-credentials-deployment.json"
    )
    identity = dict(deployment)
    identity["DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE"] = (
        "/run/desire/deployment.json"
    )
    identity.update(
        {
            "DESIRE_INTERNAL_SANDBOX_IDENTITY_BOOTSTRAP_OUTPUT_FILE": (
                "/run/identity-bootstrap/manifest.json"
            ),
            "DESIRE_INTERNAL_SANDBOX_IDENTITY_BOOTSTRAP_SOURCE_ROOT": (
                "/run/identity-sources"
            ),
            "DESIRE_INTERNAL_SANDBOX_IDENTITY_BOOTSTRAP_TEMPLATE_FILE": (
                "/run/desire/identity-bootstrap-template.json"
            ),
            "DESIRE_INTERNAL_SANDBOX_IDENTITY_BOOTSTRAP_TEMPLATE_SHA256": (
                "b7f5326f75f17eb97cec77d92f963fe6af6755a26a1acf7af8944f33ee6ba942"
            ),
        }
    )
    return {
        "api": {
            "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE": (
                "/run/desire/deployment.json"
            ),
            "SSL_CERT_FILE": "/run/desire-tls/root-ca.pem",
        },
        "db": {
            "PGDATA": "/var/lib/postgresql/data/pgdata",
            "POSTGRES_DB": "desire",
            "POSTGRES_PASSWORD_FILE": "/run/secrets/db_superuser_password",
            "POSTGRES_USER": "postgres",
        },
        "identity-bootstrap": identity,
        "migrate": deployment,
        "matching-runtime": {
            "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE": (
                "/run/desire/matching-deployment.json"
            ),
            "DESIRE_MATCHING_RUNTIME_HEALTH_FILE": (
                "/run/matching-runtime/healthy"
            ),
        },
        "online-credentials-reconcile": online,
        "online-credentials-verify": online,
        "synthetic-oidc": {
            "DESIRE_DEPLOYMENT_MODE": "INTERNAL_SANDBOX",
            "DESIRE_EXTERNAL_PARTICIPANTS_ENABLED": "false",
            "DESIRE_SYNTHETIC_OIDC_CLIENT_SECRET_FILE": (
                "/run/secrets/key-oidc-client-secret-v1"
            ),
        },
        "taxonomy-seed": taxonomy,
        "web": {
            "DESIRE_LOOPBACK_BASE_URL": "http://api:8000",
            "NODE_ENV": "production",
        },
    }


def _expected_dependencies() -> dict[str, dict[str, Any]]:
    return {
        "api": {
            "edge": {"condition": "service_healthy", "required": True},
            "identity-bootstrap": {
                "condition": "service_completed_successfully",
                "required": True,
            },
        },
        "edge": _depends("synthetic-oidc", "service_healthy"),
        "identity-bootstrap": _depends(
            "online-credentials-verify", "service_completed_successfully"
        ),
        "migrate": _depends("db", "service_healthy"),
        "matching-runtime": _depends(
            "identity-bootstrap", "service_completed_successfully"
        ),
        "online-credentials-reconcile": _depends(
            "taxonomy-seed", "service_completed_successfully"
        ),
        "online-credentials-verify": _depends(
            "online-credentials-reconcile", "service_completed_successfully"
        ),
        "taxonomy-seed": _depends("migrate", "service_completed_successfully"),
        "web": _depends("api", "service_healthy"),
    }


def _expected_healthchecks() -> dict[str, dict[str, Any]]:
    return {
        "api": {
            "test": [
                "CMD",
                "python",
                "-c",
                (
                    "import urllib.request; urllib.request.urlopen("
                    "'http://127.0.0.1:8000/health/ready', timeout=2)"
                ),
            ],
            "timeout": "3s",
            "interval": "10s",
            "retries": 6,
            "start_period": "20s",
        },
        "db": {
            "test": ["CMD-SHELL", "pg_isready -U postgres -d desire || exit 1"],
            "timeout": "3s",
            "interval": "5s",
            "retries": 20,
            "start_period": "10s",
        },
        "matching-runtime": {
            "test": [
                "CMD",
                "python",
                "-c",
                (
                    "from pathlib import Path; import time; "
                    "p=Path('/run/matching-runtime/healthy'); "
                    "raise SystemExit(0 if p.is_file() and "
                    "time.time()-p.stat().st_mtime < 30 else 1)"
                ),
            ],
            "timeout": "3s",
            "interval": "10s",
            "retries": 3,
            "start_period": "20s",
        },
        "edge": {
            "test": [
                "CMD",
                "wget",
                "--no-verbose",
                "--tries=1",
                "--spider",
                "http://127.0.0.1:8080/_edge/health",
            ],
            "timeout": "3s",
            "interval": "10s",
            "retries": 10,
            "start_period": "5s",
        },
        "synthetic-oidc": {
            "test": [
                "CMD",
                "python",
                "-c",
                (
                    "import urllib.request; urllib.request.urlopen("
                    "'http://127.0.0.1:8081/health/ready', timeout=2)"
                ),
            ],
            "timeout": "3s",
            "interval": "5s",
            "retries": 10,
            "start_period": "5s",
        },
        "web": {
            "test": [
                "CMD",
                "node",
                "-e",
                (
                    "fetch('http://127.0.0.1:3000/').then(r=>{if(!r.ok)"
                    "process.exit(1)}).catch(()=>process.exit(1))"
                ),
            ],
            "timeout": "3s",
            "interval": "10s",
            "retries": 10,
            "start_period": "15s",
        },
    }


def _expected_service_configs() -> dict[str, list[dict[str, str]]]:
    return {
        "api": _configs(
            "internal-sandbox-deployment",
            "internal-sandbox-runtime-config",
            "internal-sandbox-secret-manifest",
            "internal-sandbox-root-ca",
        ),
        "edge": _configs("internal-sandbox-edge-tls-chain"),
        "identity-bootstrap": _configs(
            "internal-sandbox-deployment",
            "internal-sandbox-runtime-config",
            "internal-sandbox-secret-manifest",
            "internal-sandbox-identity-template",
        ),
        "matching-runtime": _matching_runtime_configs(),
        "online-credentials-reconcile": _online_credential_configs(),
        "online-credentials-verify": _online_credential_configs(),
    }


def _expected_service_secrets() -> dict[str, list[dict[str, str]]]:
    db_password_path = [
        {
            "source": "db_superuser_password",
            "target": "/run/secrets/db_superuser_password",
        }
    ]
    return {
        "api": _runtime_secrets(),
        "db": db_password_path,
        "edge": [
            {
                "source": "edge-tls-key",
                "target": "/run/secrets/edge-tls-key.pem",
                "uid": "10001",
                "gid": "10001",
                "mode": "0400",
            }
        ],
        "identity-bootstrap": _identity_bootstrap_secrets(),
        "matching-runtime": _matching_runtime_secrets(),
        "migrate": db_password_path,
        "online-credentials-reconcile": _online_database_secrets(),
        "online-credentials-verify": _online_database_secrets(),
        "synthetic-oidc": [
            {
                "source": "key-oidc-client-secret-v1",
                "target": "key-oidc-client-secret-v1",
            }
        ],
        "taxonomy-seed": db_password_path
        + [
            {
                "source": "taxonomy_seed_workload_credential",
                "target": "/run/secrets/taxonomy_seed_workload_credential",
            },
            {
                "source": "taxonomy_seed_receipt_hmac_key",
                "target": "/run/secrets/taxonomy_seed_receipt_hmac_key",
            },
        ],
    }


def _validate_named_files(
    document: object,
    *,
    expected_names: tuple[str, ...],
    project: str,
) -> dict[str, str]:
    if not isinstance(document, dict) or set(document) != set(expected_names):
        _invalid()
    observed: dict[str, str] = {}
    for name in expected_names:
        item = document.get(name)
        if (
            not isinstance(item, dict)
            or set(item) != {"name", "file"}
            or item.get("name") != f"{project}_{name}"
        ):
            _invalid()
        observed[name] = _safe_absolute_path(item.get("file"))
    if len(set(observed.values())) != len(observed):
        _invalid()
    return observed


def _validate_source_layout(
    configs: Mapping[str, str],
    secrets: Mapping[str, str],
    identity_source: str,
) -> None:
    deployment = PurePosixPath(configs["internal-sandbox-deployment"])
    bundle = deployment.parent.parent
    if (
        deployment.name != "deployment.json"
        or deployment.parent.name != "config"
        or PurePosixPath(configs["internal-sandbox-runtime-config"])
        != deployment.parent / "runtime-config.json"
        or PurePosixPath(configs["internal-sandbox-secret-manifest"])
        != deployment.parent / "secret-manifest.json"
        or PurePosixPath(configs["internal-sandbox-matching-deployment"])
        != deployment.parent / "matching-deployment.json"
        or PurePosixPath(
            configs["internal-sandbox-matching-runtime-config"]
        )
        != deployment.parent / "matching-runtime-config.json"
        or PurePosixPath(
            configs["internal-sandbox-matching-secret-manifest"]
        )
        != deployment.parent / "matching-secret-manifest.json"
        or PurePosixPath(
            configs["internal-sandbox-online-credentials-deployment"]
        )
        != deployment.parent / "online-credentials-deployment.json"
        or PurePosixPath(
            configs["internal-sandbox-online-credentials-runtime-config"]
        )
        != deployment.parent / "online-credentials-runtime-config.json"
        or PurePosixPath(
            configs["internal-sandbox-online-credentials-secret-manifest"]
        )
        != deployment.parent / "online-credentials-secret-manifest.json"
    ):
        _invalid()
    for name in _ONLINE_RUNTIME_SECRETS:
        if PurePosixPath(secrets[name]) != bundle / "runtime-secrets" / name:
            _invalid()
    root_ca = PurePosixPath(configs["internal-sandbox-root-ca"])
    tls = root_ca.parent
    if (
        root_ca.name != "root-ca.pem"
        or PurePosixPath(configs["internal-sandbox-edge-tls-chain"])
        != tls / "edge-tls-chain.pem"
        or PurePosixPath(secrets["edge-tls-key"]) != tls / "edge-tls-key.pem"
    ):
        _invalid()
    input_root = PurePosixPath(secrets["db_superuser_password"]).parent
    if (
        PurePosixPath(secrets["db_superuser_password"]).name
        != "db_superuser_password.txt"
        or PurePosixPath(secrets["taxonomy_seed_workload_credential"])
        != input_root / "taxonomy_seed_workload_credential"
        or PurePosixPath(secrets["taxonomy_seed_receipt_hmac_key"])
        != input_root / "taxonomy_seed_receipt_hmac_key"
        or bundle.parent != input_root
        or tls.parent != input_root
        or PurePosixPath(identity_source)
        != input_root / "internal-sandbox-identity-sources"
        or PurePosixPath(configs["internal-sandbox-identity-template"]).name
        != "internal-sandbox-identity-bootstrap-template-v1.json"
    ):
        _invalid()


def _validate_networks(
    document: object,
    *,
    project: str,
    subnets: Mapping[str, str],
) -> None:
    if not isinstance(document, dict) or set(document) != _NETWORK_NAMES:
        _invalid()
    for name in _NETWORK_NAMES:
        network = document.get(name)
        expected_keys = {"name", "ipam"} | (
            {"internal"} if name in _INTERNAL_NETWORKS else set()
        )
        if (
            not isinstance(network, dict)
            or set(network) != expected_keys
            or network.get("name") != f"{project}_{name}"
            or (
                name in _INTERNAL_NETWORKS
                and network.get("internal") is not True
            )
            or network.get("ipam")
            != {"config": [{"subnet": subnets[name]}]}
        ):
            _invalid()


def _validate_builds(services: Mapping[str, Any]) -> None:
    expected_targets = {
        "api": "platform-runtime",
        "edge": "edge-runtime",
        "migrate": "platform-runtime",
        "web": "web-runtime",
    }
    contexts: set[str] = set()
    for name, target in expected_targets.items():
        build = services[name].get("build")
        if (
            not isinstance(build, dict)
            or set(build) != {"context", "dockerfile", "target"}
            or build.get("dockerfile") != "Dockerfile"
            or build.get("target") != target
        ):
            _invalid()
        contexts.add(_safe_absolute_path(build.get("context")))
    if len(contexts) != 1:
        _invalid()


def _validate_services(
    services: object,
    *,
    bind_ip: str,
    image_tag: str,
    identity_source: str,
) -> dict[str, str]:
    if not isinstance(services, dict) or set(services) != _SERVICE_NAMES:
        _invalid()
    for name in _SERVICE_NAMES:
        service = services.get(name)
        if not isinstance(service, dict) or set(service) != _RAW_SERVICE_KEYS[name]:
            _invalid()
        if service.get("entrypoint") is not None:
            _invalid()
        if service.get("logging") != _BOUNDED_LOGGING:
            _invalid()
    _validate_builds(services)

    platform_ref = f"desire-supply-platform:{image_tag}"
    web_ref = f"desire-supply-web:{image_tag}"
    edge_ref = f"desire-supply-edge:{image_tag}"
    images = {
        **{name: platform_ref for name in _SERVICE_NAMES - {"db", "edge", "web"}},
        "db": _POSTGRES_REF,
        "edge": edge_ref,
        "web": web_ref,
    }
    for name, reference in images.items():
        if services[name].get("image") != reference:
            _invalid()

    commands = _expected_commands()
    environments = _expected_environments()
    dependencies = _expected_dependencies()
    healthchecks = _expected_healthchecks()
    service_configs = _expected_service_configs()
    service_secrets = _expected_service_secrets()
    for name, command in commands.items():
        if services[name].get("command") != command:
            _invalid()
    for name in _SERVICE_NAMES:
        if ("environment" in services[name]) != (name in environments):
            _invalid()
        if name in environments and services[name]["environment"] != environments[name]:
            _invalid()
        if ("depends_on" in services[name]) != (name in dependencies):
            _invalid()
        if name in dependencies and services[name]["depends_on"] != dependencies[name]:
            _invalid()
        if ("healthcheck" in services[name]) != (name in healthchecks):
            _invalid()
        if name in healthchecks and services[name]["healthcheck"] != healthchecks[name]:
            _invalid()
        if ("configs" in services[name]) != (name in service_configs):
            _invalid()
        if name in service_configs and services[name]["configs"] != service_configs[name]:
            _invalid()
        if ("secrets" in services[name]) != (name in service_secrets):
            _invalid()
        if name in service_secrets and services[name]["secrets"] != service_secrets[name]:
            _invalid()

    for name in _HARDENED_SERVICES:
        service = services[name]
        expected_tmpfs = list(_COMMON_TMPFS)
        if name == "identity-bootstrap":
            expected_tmpfs += [
                "/run/identity-bootstrap:rw,noexec,nosuid,nodev,size=1m,"
                "uid=10001,gid=10001,mode=0700"
            ]
        elif name == "matching-runtime":
            expected_tmpfs += [
                "/run/matching-runtime:rw,noexec,nosuid,nodev,size=64k,"
                "uid=10001,gid=10001,mode=0700"
            ]
        expected_restart = (
            "unless-stopped" if name == "matching-runtime" else "no"
        )
        if (
            service.get("cap_drop") != ["ALL"]
            or service.get("init") is not True
            or service.get("read_only") is not True
            or service.get("restart") != expected_restart
            or service.get("security_opt") != ["no-new-privileges=true"]
            or service.get("tmpfs") != expected_tmpfs
        ):
            _invalid()

    expected_networks = {
        "api": {"app": None, "data": None},
        "db": {"data": None},
        "edge": {
            "app": {"aliases": ["identity.example.test"]},
            "ingress": None,
            "oidc-backend": None,
        },
        "identity-bootstrap": {"data": None},
        "migrate": {"data": None},
        "matching-runtime": {"data": None},
        "online-credentials-reconcile": {"data": None},
        "online-credentials-verify": {"data": None},
        "synthetic-oidc": {"oidc-backend": None},
        "taxonomy-seed": {"data": None},
        "web": {"app": None},
    }
    for name, networks in expected_networks.items():
        if services[name].get("networks") != networks:
            _invalid()

    expected_ports = [
        {
            "mode": "ingress",
            "host_ip": "127.0.0.1",
            "target": 443,
            "published": "443",
            "protocol": "tcp",
        },
        {
            "name": "private-rfc1918-https",
            "mode": "ingress",
            "host_ip": bind_ip,
            "target": 443,
            "published": "443",
            "protocol": "tcp",
        },
    ]
    if services["edge"].get("ports") != expected_ports:
        _invalid()

    db = services["db"]
    if (
        db.get("restart") != "unless-stopped"
        or db.get("shm_size") != "134217728"
        or db.get("stop_grace_period") != "1m0s"
        or db.get("tmpfs")
        != ["/var/lib/postgresql:rw,nosuid,nodev,noexec,size=1m"]
        or db.get("volumes")
        != [
            {
                "type": "volume",
                "source": "postgres-data",
                "target": "/var/lib/postgresql/data",
                "volume": {},
            }
        ]
    ):
        _invalid()
    if services["api"].get("stop_grace_period") != "20s":
        _invalid()
    if services["matching-runtime"].get("stop_grace_period") != "30s":
        _invalid()
    if services["edge"].get("sysctls") != {
        "net.ipv4.ip_unprivileged_port_start": "0"
    }:
        _invalid()
    identity_volumes = services["identity-bootstrap"].get("volumes")
    if identity_volumes != [
        {
            "type": "bind",
            "source": identity_source,
            "target": "/run/identity-sources",
            "read_only": True,
            "bind": {"create_host_path": False},
        }
    ]:
        _invalid()
    return images


def _mapping_path(value: object) -> str:
    if isinstance(value, os.PathLike):
        try:
            value = os.fspath(value)
        except TypeError:
            _invalid()
    return _safe_absolute_path(value)


def _mapping(
    value: Mapping[str | os.PathLike[str], str | os.PathLike[str]],
) -> dict[str, str]:
    if not isinstance(value, Mapping):
        _invalid()
    result: dict[str, str] = {}
    for key, item in value.items():
        source = _mapping_path(key)
        staged = _mapping_path(item)
        if source in result:
            _invalid()
        result[source] = staged
    if len(set(result.values())) != len(result):
        _invalid()
    return result


def _is_within(path: PurePosixPath, root: PurePosixPath) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _close_staged_mapping(
    staged: Mapping[str, str],
    *,
    configs: Mapping[str, str],
    secrets: Mapping[str, str],
    identity_source: str,
) -> str:
    input_root = PurePosixPath(secrets["db_superuser_password"]).parent
    identity = PurePosixPath(identity_source)
    template_source = PurePosixPath(
        configs["internal-sandbox-identity-template"]
    )
    identity_files = {
        str(identity / name) for name in _IDENTITY_FILES
    }
    required = set(configs.values()) | set(secrets.values()) | identity_files
    metadata = {
        str(input_root / "compose.env"),
        str(input_root / "compose.ipam.yaml"),
        str(input_root / "oidc-client-secret"),
    }
    observed = set(staged)
    if observed not in (required, required | metadata):
        _invalid()

    password_source = str(input_root / "db_superuser_password.txt")
    stage_root = PurePosixPath(staged[password_source]).parent
    if (
        stage_root == input_root
        or _is_within(stage_root, input_root)
        or _is_within(input_root, stage_root)
        or stage_root.parent == PurePosixPath("/")
    ):
        _invalid()
    for source in observed - {str(template_source)}:
        source_path = PurePosixPath(source)
        if not _is_within(source_path, input_root):
            _invalid()
        relative = source_path.relative_to(input_root)
        if PurePosixPath(staged[source]) != stage_root / relative:
            _invalid()

    template_staged = PurePosixPath(staged[str(template_source)])
    if (
        _is_within(template_source, input_root)
        or template_staged == template_source
        or template_staged.name != template_source.name
        or not _is_within(template_staged, stage_root.parent)
        or _is_within(template_staged, input_root)
    ):
        _invalid()
    return str(stage_root / identity.relative_to(input_root))


def _image_ids(
    value: Mapping[str, str], *, image_tag: str
) -> dict[str, str]:
    expected = {
        f"desire-supply-platform:{image_tag}",
        f"desire-supply-web:{image_tag}",
        f"desire-supply-edge:{image_tag}",
        _POSTGRES_REF,
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        _invalid()
    result: dict[str, str] = {}
    for reference in expected:
        image_id = value.get(reference)
        if not isinstance(image_id, str) or _IMAGE_ID.fullmatch(image_id) is None:
            _invalid()
        result[reference] = image_id
    if len(set(result.values())) != len(result):
        _invalid()
    return result


def build_canonical_private_server_compose(
    raw_config_json: str | bytes,
    *,
    project: str,
    bind_ip: str,
    subnets: Mapping[str, str],
    image_tag: str,
    source_to_staged: Mapping[
        str | os.PathLike[str], str | os.PathLike[str]
    ],
    image_ref_to_id: Mapping[str, str],
) -> tuple[bytes, dict[str, Any]]:
    """Validate the exact resolved stack and return immutable-ID JSON bytes."""

    selected_project = _exact_project(project)
    target = _exact_bind_ip(bind_ip)
    selected_subnets = _exact_subnets(subnets, bind_ip=target)
    selected_tag = _safe_token(image_tag)
    staged = _mapping(source_to_staged)
    image_ids = _image_ids(image_ref_to_id, image_tag=selected_tag)
    document = _parse_document(raw_config_json)
    if set(document) != _TOP_LEVEL or document.get("name") != selected_project:
        _invalid()
    for name, expected_type in _EXTENSION_TYPES.items():
        if type(document.get(name)) is not expected_type:
            _invalid()
    if document.get("x-hardened") != {
        "cap_drop": ["ALL"],
        "init": True,
        "logging": _BOUNDED_LOGGING,
        "read_only": True,
        "restart": "no",
        "security_opt": ["no-new-privileges=true"],
        "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=64m"],
    }:
        _invalid()

    _validate_networks(
        document.get("networks"),
        project=selected_project,
        subnets=selected_subnets,
    )
    volumes = document.get("volumes")
    if volumes != {
        "postgres-data": {"name": f"{selected_project}_postgres-data"}
    }:
        _invalid()
    configs = _validate_named_files(
        document.get("configs"),
        expected_names=_CONFIG_NAMES,
        project=selected_project,
    )
    secrets = _validate_named_files(
        document.get("secrets"),
        expected_names=_SECRET_NAMES,
        project=selected_project,
    )
    services = document.get("services")
    if not isinstance(services, dict):
        _invalid()
    identity = services.get("identity-bootstrap")
    if not isinstance(identity, dict):
        _invalid()
    identity_volumes = identity.get("volumes")
    if not isinstance(identity_volumes, list) or len(identity_volumes) != 1:
        _invalid()
    identity_volume = identity_volumes[0]
    if not isinstance(identity_volume, dict):
        _invalid()
    identity_source = _safe_absolute_path(identity_volume.get("source"))
    _validate_source_layout(configs, secrets, identity_source)
    service_images = _validate_services(
        services,
        bind_ip=str(target),
        image_tag=selected_tag,
        identity_source=identity_source,
    )

    staged_identity_source = _close_staged_mapping(
        staged,
        configs=configs,
        secrets=secrets,
        identity_source=identity_source,
    )

    canonical = copy.deepcopy(document)
    for name in _EXTENSION_TYPES:
        del canonical[name]
    if set(canonical) != _CANONICAL_TOP_LEVEL:
        _invalid()
    for resource_name in ("configs", "secrets"):
        for item in canonical[resource_name].values():
            item["file"] = staged[item["file"]]
    canonical["services"]["identity-bootstrap"]["volumes"][0]["source"] = (
        staged_identity_source
    )
    for service_name, reference in service_images.items():
        canonical["services"][service_name]["image"] = image_ids[reference]
        canonical["services"][service_name].pop("build", None)

    try:
        value = (
            json.dumps(
                canonical,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            + b"\n"
        )
    except (UnicodeError, TypeError, ValueError, RecursionError):
        _invalid()
    if len(value) > _MAX_JSON_BYTES or b"$" in value or b"\x00" in value:
        _invalid()
    return value, canonical


__all__ = (
    "PrivateServerComposeContractError",
    "build_canonical_private_server_compose",
    "validate_synthetic_oidc_network_binding",
)
