"""Pure contracts for the release-grade private-server Compose closure."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "private_server_compose_contract.py"
PROJECT = "desire-private-ingress-20260824-a1"
BIND_IP = "10.23.4.15"
IMAGE_TAG = "private-release-a1"
SUBNETS = {
    "ingress": "10.240.1.0/24",
    "oidc-backend": "10.240.2.0/24",
    "app": "10.240.3.0/24",
    "data": "10.240.4.0/24",
}
PLATFORM_REF = f"desire-supply-platform:{IMAGE_TAG}"
WEB_REF = f"desire-supply-web:{IMAGE_TAG}"
EDGE_REF = f"desire-supply-edge:{IMAGE_TAG}"
POSTGRES_REF = (
    "postgres:18.4-alpine@sha256:"
    "9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15"
)
IMAGE_IDS = {
    PLATFORM_REF: "sha256:" + "1" * 64,
    WEB_REF: "sha256:" + "2" * 64,
    EDGE_REF: "sha256:" + "3" * 64,
    POSTGRES_REF: "sha256:" + "4" * 64,
}
BOUNDED_LOGGING = {
    "driver": "local",
    "options": {"compress": "true", "max-file": "3", "max-size": "10m"},
}

API_RUNTIME_SECRETS = (
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
MATCHING_RUNTIME_SECRETS = (
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
RUNTIME_SECRETS = API_RUNTIME_SECRETS + tuple(
    name for name in MATCHING_RUNTIME_SECRETS if name not in API_RUNTIME_SECRETS
)
IDENTITY_FILES = (
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
)
CONFIG_NAMES = (
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
SECRET_NAMES = (
    "db_superuser_password",
    "taxonomy_seed_workload_credential",
    "taxonomy_seed_receipt_hmac_key",
    "edge-tls-key",
) + RUNTIME_SECRETS


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "private_server_compose_contract", SCRIPT
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("compose contract cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _depends(name: str, condition: str) -> dict:
    return {name: {"condition": condition, "required": True}}


def _configs(*names: str) -> list[dict]:
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


def _runtime_secrets() -> list[dict]:
    return [{"source": name, "target": name} for name in API_RUNTIME_SECRETS]


def _matching_runtime_secrets() -> list[dict]:
    return [
        {"source": name, "target": name}
        for name in MATCHING_RUNTIME_SECRETS
    ]


def _online_database_secrets() -> list[dict]:
    return [
        {"source": "db_superuser_password", "target": "db_superuser_password"}
    ] + [
        {"source": name, "target": name}
        for name in RUNTIME_SECRETS
        if name.startswith("db-")
    ]


def _identity_bootstrap_secrets() -> list[dict]:
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


def _admin_environment() -> dict:
    return {
        "DESIRE_DATABASE_ADMIN_USER": "postgres",
        "DESIRE_DATABASE_HOST": "db",
        "DESIRE_DATABASE_NAME": "desire",
        "DESIRE_DATABASE_PASSWORD_FILE": "/run/secrets/db_superuser_password",
        "DESIRE_DEPLOYMENT_MODE": "INTERNAL_SANDBOX",
        "DESIRE_EXTERNAL_PARTICIPANTS_ENABLED": "false",
    }


def _hardened(**values) -> dict:
    document = {
        "cap_drop": ["ALL"],
        "entrypoint": None,
        "image": PLATFORM_REF,
        "init": True,
        "logging": copy.deepcopy(BOUNDED_LOGGING),
        "read_only": True,
        "restart": "no",
        "security_opt": ["no-new-privileges=true"],
        "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=64m"],
    }
    document.update(values)
    return document


def _build(target: str) -> dict:
    return {
        "context": "/srv/desire/release",
        "dockerfile": "Dockerfile",
        "target": target,
    }


def _services(identity_source: str) -> dict:
    db = {
        "command": None,
        "entrypoint": None,
        "environment": {
            "PGDATA": "/var/lib/postgresql/data/pgdata",
            "POSTGRES_DB": "desire",
            "POSTGRES_PASSWORD_FILE": "/run/secrets/db_superuser_password",
            "POSTGRES_USER": "postgres",
        },
        "healthcheck": {
            "test": ["CMD-SHELL", "pg_isready -U postgres -d desire || exit 1"],
            "timeout": "3s",
            "interval": "5s",
            "retries": 20,
            "start_period": "10s",
        },
        "image": POSTGRES_REF,
        "logging": copy.deepcopy(BOUNDED_LOGGING),
        "networks": {"data": None},
        "restart": "unless-stopped",
        "secrets": [
            {
                "source": "db_superuser_password",
                "target": "/run/secrets/db_superuser_password",
            }
        ],
        "shm_size": "134217728",
        "stop_grace_period": "1m0s",
        "tmpfs": ["/var/lib/postgresql:rw,nosuid,nodev,noexec,size=1m"],
        "volumes": [
            {
                "type": "volume",
                "source": "postgres-data",
                "target": "/var/lib/postgresql/data",
                "volume": {},
            }
        ],
    }
    migrate = _hardened(
        build=_build("platform-runtime"),
        command=["python", "-m", "desire_platform.deployment"],
        depends_on=_depends("db", "service_healthy"),
        environment=_admin_environment(),
        networks={"data": None},
        secrets=[
            {
                "source": "db_superuser_password",
                "target": "/run/secrets/db_superuser_password",
            }
        ],
    )
    taxonomy_environment = _admin_environment()
    taxonomy_environment.update(
        {
            "DESIRE_TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE": (
                "/run/secrets/taxonomy_seed_receipt_hmac_key"
            ),
            "DESIRE_TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE": (
                "/run/secrets/taxonomy_seed_workload_credential"
            ),
        }
    )
    taxonomy = _hardened(
        command=[
            "python",
            "-m",
            "desire_platform.deployment.synthetic_taxonomy_seed",
            "apply",
        ],
        depends_on=_depends("migrate", "service_completed_successfully"),
        environment=taxonomy_environment,
        networks={"data": None},
        secrets=[
            {
                "source": "db_superuser_password",
                "target": "/run/secrets/db_superuser_password",
            },
            {
                "source": "taxonomy_seed_workload_credential",
                "target": "/run/secrets/taxonomy_seed_workload_credential",
            },
            {
                "source": "taxonomy_seed_receipt_hmac_key",
                "target": "/run/secrets/taxonomy_seed_receipt_hmac_key",
            },
        ],
    )
    online_configs = _configs(
        "internal-sandbox-online-credentials-deployment",
        "internal-sandbox-online-credentials-runtime-config",
        "internal-sandbox-online-credentials-secret-manifest",
    )
    reconcile_environment = _admin_environment()
    reconcile_environment["DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE"] = (
        "/run/desire/online-credentials-deployment.json"
    )
    reconcile = _hardened(
        command=[
            "python",
            "-m",
            "desire_platform.deployment.online_credentials",
            "reconcile",
        ],
        configs=online_configs,
        depends_on=_depends("taxonomy-seed", "service_completed_successfully"),
        environment=reconcile_environment,
        networks={"data": None},
        secrets=_online_database_secrets(),
    )
    verify = copy.deepcopy(reconcile)
    verify["command"][-1] = "verify"
    verify["depends_on"] = _depends(
        "online-credentials-reconcile", "service_completed_successfully"
    )
    identity_environment = _admin_environment()
    identity_environment.update(
        {
            "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE": (
                "/run/desire/deployment.json"
            ),
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
    identity = _hardened(
        command=[
            "python",
            "-m",
            "desire_platform.deployment.identity_bootstrap_orchestrator",
            "run",
        ],
        configs=_configs(
            "internal-sandbox-deployment",
            "internal-sandbox-runtime-config",
            "internal-sandbox-secret-manifest",
            "internal-sandbox-identity-template",
        ),
        depends_on=_depends(
            "online-credentials-verify", "service_completed_successfully"
        ),
        environment=identity_environment,
        networks={"data": None},
        secrets=_identity_bootstrap_secrets(),
        tmpfs=[
            "/tmp:rw,noexec,nosuid,nodev,size=64m",
            (
                "/run/identity-bootstrap:rw,noexec,nosuid,nodev,size=1m,"
                "uid=10001,gid=10001,mode=0700"
            ),
        ],
        volumes=[
            {
                "type": "bind",
                "source": identity_source,
                "target": "/run/identity-sources",
                "read_only": True,
                "bind": {"create_host_path": False},
            }
        ],
    )
    synthetic = _hardened(
        command=["python", "-m", "desire_platform.synthetic_oidc"],
        environment={
            "DESIRE_DEPLOYMENT_MODE": "INTERNAL_SANDBOX",
            "DESIRE_EXTERNAL_PARTICIPANTS_ENABLED": "false",
            "DESIRE_SYNTHETIC_OIDC_CLIENT_SECRET_FILE": (
                "/run/secrets/key-oidc-client-secret-v1"
            ),
        },
        healthcheck={
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
        networks={"oidc-backend": None},
        secrets=[
            {
                "source": "key-oidc-client-secret-v1",
                "target": "key-oidc-client-secret-v1",
            }
        ],
    )
    api = _hardened(
        build=_build("platform-runtime"),
        command=[
            "python",
            "-m",
            "desire_platform.internal_pilot.api_server",
        ],
        configs=_configs(
            "internal-sandbox-deployment",
            "internal-sandbox-runtime-config",
            "internal-sandbox-secret-manifest",
            "internal-sandbox-root-ca",
        ),
        depends_on={
            "edge": {"condition": "service_healthy", "required": True},
            "identity-bootstrap": {
                "condition": "service_completed_successfully",
                "required": True,
            },
        },
        environment={
            "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE": (
                "/run/desire/deployment.json"
            ),
            "SSL_CERT_FILE": "/run/desire-tls/root-ca.pem",
        },
        healthcheck={
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
        networks={"app": None, "data": None},
        secrets=_runtime_secrets(),
        stop_grace_period="20s",
    )
    matching_runtime = _hardened(
        command=[
            "python",
            "-m",
            "desire_platform.matching.runtime_process",
        ],
        configs=_configs(
            "internal-sandbox-matching-deployment",
            "internal-sandbox-matching-runtime-config",
            "internal-sandbox-matching-secret-manifest",
        ),
        depends_on=_depends(
            "identity-bootstrap", "service_completed_successfully"
        ),
        environment={
            "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE": (
                "/run/desire/matching-deployment.json"
            ),
            "DESIRE_MATCHING_RUNTIME_HEALTH_FILE": (
                "/run/matching-runtime/healthy"
            ),
        },
        healthcheck={
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
        networks={"data": None},
        restart="unless-stopped",
        secrets=_matching_runtime_secrets(),
        stop_grace_period="30s",
        tmpfs=[
            "/tmp:rw,noexec,nosuid,nodev,size=64m",
            (
                "/run/matching-runtime:rw,noexec,nosuid,nodev,size=64k,"
                "uid=10001,gid=10001,mode=0700"
            ),
        ],
    )
    web = _hardened(
        build=_build("web-runtime"),
        command=None,
        depends_on=_depends("api", "service_healthy"),
        environment={
            "DESIRE_LOOPBACK_BASE_URL": "http://api:8000",
            "NODE_ENV": "production",
        },
        healthcheck={
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
        image=WEB_REF,
        networks={"app": None},
    )
    edge = _hardened(
        build=_build("edge-runtime"),
        command=None,
        configs=_configs("internal-sandbox-edge-tls-chain"),
        depends_on=_depends("synthetic-oidc", "service_healthy"),
        healthcheck={
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
        image=EDGE_REF,
        networks={
            "app": {"aliases": ["identity.example.test"]},
            "ingress": None,
            "oidc-backend": None,
        },
        ports=[
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
                "host_ip": BIND_IP,
                "target": 443,
                "published": "443",
                "protocol": "tcp",
            },
        ],
        secrets=[
            {
                "source": "edge-tls-key",
                "target": "/run/secrets/edge-tls-key.pem",
                "uid": "10001",
                "gid": "10001",
                "mode": "0400",
            }
        ],
        sysctls={"net.ipv4.ip_unprivileged_port_start": "0"},
    )
    return {
        "api": api,
        "db": db,
        "edge": edge,
        "identity-bootstrap": identity,
        "migrate": migrate,
        "matching-runtime": matching_runtime,
        "online-credentials-reconcile": reconcile,
        "online-credentials-verify": verify,
        "synthetic-oidc": synthetic,
        "taxonomy-seed": taxonomy,
        "web": web,
    }


def _raw_config() -> tuple[dict, dict[str, str]]:
    config_sources = {
        "internal-sandbox-deployment": "/srv/desire/input/bundle/config/deployment.json",
        "internal-sandbox-runtime-config": "/srv/desire/input/bundle/config/runtime-config.json",
        "internal-sandbox-secret-manifest": "/srv/desire/input/bundle/config/secret-manifest.json",
        "internal-sandbox-matching-deployment": (
            "/srv/desire/input/bundle/config/matching-deployment.json"
        ),
        "internal-sandbox-matching-runtime-config": (
            "/srv/desire/input/bundle/config/matching-runtime-config.json"
        ),
        "internal-sandbox-matching-secret-manifest": (
            "/srv/desire/input/bundle/config/matching-secret-manifest.json"
        ),
        "internal-sandbox-online-credentials-deployment": (
            "/srv/desire/input/bundle/config/online-credentials-deployment.json"
        ),
        "internal-sandbox-online-credentials-runtime-config": (
            "/srv/desire/input/bundle/config/online-credentials-runtime-config.json"
        ),
        "internal-sandbox-online-credentials-secret-manifest": (
            "/srv/desire/input/bundle/config/online-credentials-secret-manifest.json"
        ),
        "internal-sandbox-identity-template": (
            "/srv/desire/release/"
            "internal-sandbox-identity-bootstrap-template-v1.json"
        ),
        "internal-sandbox-root-ca": (
            "/srv/desire/input/internal-sandbox-tls/root-ca.pem"
        ),
        "internal-sandbox-edge-tls-chain": (
            "/srv/desire/input/internal-sandbox-tls/edge-tls-chain.pem"
        ),
    }
    secret_sources = {
        "db_superuser_password": "/srv/desire/input/db_superuser_password.txt",
        "taxonomy_seed_workload_credential": (
            "/srv/desire/input/taxonomy_seed_workload_credential"
        ),
        "taxonomy_seed_receipt_hmac_key": (
            "/srv/desire/input/taxonomy_seed_receipt_hmac_key"
        ),
        "edge-tls-key": (
            "/srv/desire/input/internal-sandbox-tls/edge-tls-key.pem"
        ),
    }
    secret_sources.update(
        {
            name: f"/srv/desire/input/bundle/runtime-secrets/{name}"
            for name in RUNTIME_SECRETS
        }
    )
    identity_source = "/srv/desire/input/internal-sandbox-identity-sources"
    input_root = "/srv/desire/input"
    stage_root = "/srv/desire/attempt/staged"
    input_files = {
        *secret_sources.values(),
        *(
            source
            for name, source in config_sources.items()
            if name != "internal-sandbox-identity-template"
        ),
        f"{input_root}/compose.env",
        f"{input_root}/compose.ipam.yaml",
        f"{input_root}/oidc-client-secret",
        *(f"{identity_source}/{name}" for name in IDENTITY_FILES),
    }
    source_to_staged = {
        source: stage_root + source.removeprefix(input_root)
        for source in input_files
    }
    template_source = config_sources["internal-sandbox-identity-template"]
    source_to_staged[template_source] = (
        "/srv/desire/attempt/release-assets/"
        "internal-sandbox-identity-bootstrap-template-v1.json"
    )
    document = {
        "name": PROJECT,
        "services": _services(identity_source),
        "networks": {
            name: {
                "name": f"{PROJECT}_{name}",
                "ipam": {"config": [{"subnet": SUBNETS[name]}]},
                **({"internal": True} if name != "ingress" else {}),
            }
            for name in ("app", "data", "ingress", "oidc-backend")
        },
        "volumes": {
            "postgres-data": {"name": f"{PROJECT}_postgres-data"}
        },
        "configs": {
            name: {"name": f"{PROJECT}_{name}", "file": source}
            for name, source in config_sources.items()
        },
        "secrets": {
            name: {"name": f"{PROJECT}_{name}", "file": source}
            for name, source in secret_sources.items()
        },
        "x-deployment-admin": {},
        "x-hardened": {
            "cap_drop": ["ALL"],
            "init": True,
            "logging": copy.deepcopy(BOUNDED_LOGGING),
            "read_only": True,
            "restart": "no",
            "security_opt": ["no-new-privileges=true"],
            "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=64m"],
        },
        "x-identity-configs": [],
        "x-identity-bootstrap-secrets": [],
        "x-matching-runtime-configs": [],
        "x-matching-runtime-secrets": [],
        "x-online-credential-configs": [],
        "x-online-database-secrets": [],
        "x-runtime-configs": [],
        "x-runtime-secrets": [],
    }
    return document, source_to_staged


class PrivateServerComposeContractTest(unittest.TestCase):
    def test_synthetic_oidc_network_binding_is_exact_and_non_public(self) -> None:
        self.assertIsNone(
            self.module.validate_synthetic_oidc_network_binding(
                {
                    "mode": "SYSTEM_DNS_SYNTHETIC",
                    "pinned_public_ipv4": None,
                }
            )
        )
        for mutation in (
            {"mode": "PINNED_PUBLIC_IP", "pinned_public_ipv4": "8.8.8.8"},
            {
                "mode": "SYSTEM_DNS_SYNTHETIC",
                "pinned_public_ipv4": "8.8.8.8",
            },
            {"mode": "SYSTEM_DNS_SYNTHETIC"},
        ):
            with self.subTest(mutation=mutation):
                with self.assertRaises(
                    self.module.PrivateServerComposeContractError
                ):
                    self.module.validate_synthetic_oidc_network_binding(mutation)

    @classmethod
    def setUpClass(cls) -> None:
        cls.module = _load_module()

    def _close(self, document: dict, mapping: dict[str, str] | None = None):
        if mapping is None:
            _, mapping = _raw_config()
        return self.module.build_canonical_private_server_compose(
            json.dumps(document),
            project=PROJECT,
            bind_ip=BIND_IP,
            subnets=SUBNETS,
            image_tag=IMAGE_TAG,
            source_to_staged=mapping,
            image_ref_to_id=IMAGE_IDS,
        )

    def test_valid_config_is_rewritten_to_deterministic_canonical_json(self) -> None:
        raw, mapping = _raw_config()
        value, document = self._close(raw, mapping)
        self.assertEqual(
            value,
            json.dumps(
                document,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            + b"\n",
        )
        self.assertEqual(
            set(document),
            {"name", "services", "networks", "volumes", "configs", "secrets"},
        )
        self.assertNotIn(b'"build"', value)
        self.assertNotIn(IMAGE_TAG.encode("ascii"), value)
        self.assertEqual(document["services"]["api"]["image"], IMAGE_IDS[PLATFORM_REF])
        self.assertEqual(document["services"]["web"]["image"], IMAGE_IDS[WEB_REF])
        self.assertEqual(document["services"]["edge"]["image"], IMAGE_IDS[EDGE_REF])
        self.assertEqual(document["services"]["db"]["image"], IMAGE_IDS[POSTGRES_REF])
        for resource in ("configs", "secrets"):
            for item in document[resource].values():
                self.assertIn(item["file"], mapping.values())
        identity_volume = document["services"]["identity-bootstrap"]["volumes"][0]
        self.assertEqual(
            identity_volume["source"],
            "/srv/desire/attempt/staged/internal-sandbox-identity-sources",
        )
        for service in document["services"].values():
            self.assertEqual(service["logging"], BOUNDED_LOGGING)

    def test_bounded_logging_is_exact_and_cannot_be_disabled(self) -> None:
        mutations = (
            lambda value: value.pop("logging"),
            lambda value: value["logging"].update(driver="json-file"),
            lambda value: value["logging"]["options"].update(
                {"max-size": "100m"}
            ),
            lambda value: value["logging"]["options"].update({"max-file": 3}),
            lambda value: value["logging"]["options"].update(
                {"compress": "false"}
            ),
            lambda value: value["logging"]["options"].update(
                {"unreviewed": "true"}
            ),
        )
        for mutate in mutations:
            document, _ = _raw_config()
            mutate(document["services"]["api"])
            with self.subTest(document=document), self.assertRaises(
                self.module.PrivateServerComposeContractError
            ):
                self._close(document)

    def test_dangerous_service_and_image_mutations_are_rejected(self) -> None:
        mutations = []
        privileged, _ = _raw_config()
        privileged["services"]["api"]["privileged"] = True
        mutations.append(privileged)
        root_bind, _ = _raw_config()
        root_bind["services"]["web"]["volumes"] = [
            {"type": "bind", "source": "/", "target": "/host"}
        ]
        mutations.append(root_bind)
        attacker_image, _ = _raw_config()
        attacker_image["services"]["api"]["image"] = "attacker.invalid/root:latest"
        mutations.append(attacker_image)
        cap_add, _ = _raw_config()
        cap_add["services"]["edge"]["cap_add"] = ["NET_ADMIN"]
        mutations.append(cap_add)
        for document in mutations:
            with self.subTest(document=document):
                with self.assertRaises(
                    self.module.PrivateServerComposeContractError
                ):
                    self._close(document)

    def test_public_wildcard_or_extra_ports_are_rejected(self) -> None:
        values = ("0.0.0.0", "203.0.113.10", "10.23.4.16")
        for host_ip in values:
            document, _ = _raw_config()
            document["services"]["edge"]["ports"][1]["host_ip"] = host_ip
            with self.subTest(host_ip=host_ip):
                with self.assertRaises(
                    self.module.PrivateServerComposeContractError
                ):
                    self._close(document)
        document, _ = _raw_config()
        document["services"]["edge"]["ports"].append(
            {
                "mode": "ingress",
                "host_ip": "0.0.0.0",
                "target": 8443,
                "published": "8443",
                "protocol": "tcp",
            }
        )
        with self.assertRaises(self.module.PrivateServerComposeContractError):
            self._close(document)

    def test_top_level_network_volume_and_paths_are_exact(self) -> None:
        mutations = []
        extra, _ = _raw_config()
        extra["include"] = ["/hostile.yaml"]
        mutations.append(extra)
        wrong_name, _ = _raw_config()
        wrong_name["networks"]["app"]["name"] = "shared-app"
        mutations.append(wrong_name)
        wrong_subnet, _ = _raw_config()
        wrong_subnet["networks"]["data"]["ipam"]["config"][0]["subnet"] = (
            "10.250.4.0/24"
        )
        mutations.append(wrong_subnet)
        external, _ = _raw_config()
        external["networks"]["ingress"]["external"] = True
        mutations.append(external)
        shared_volume, _ = _raw_config()
        shared_volume["volumes"]["postgres-data"]["name"] = "shared-data"
        mutations.append(shared_volume)
        wrong_config_path, _ = _raw_config()
        wrong_config_path["configs"]["internal-sandbox-deployment"]["file"] = (
            "/srv/desire/attacker/deployment.json"
        )
        mutations.append(wrong_config_path)
        for document in mutations:
            with self.subTest(document=document):
                with self.assertRaises(
                    self.module.PrivateServerComposeContractError
                ):
                    self._close(document)

    def test_source_mapping_and_image_id_mapping_are_closed(self) -> None:
        document, mapping = _raw_config()
        missing_mapping = dict(mapping)
        missing_mapping.pop("/srv/desire/input/db_superuser_password.txt")
        with self.assertRaises(self.module.PrivateServerComposeContractError):
            self._close(document, missing_mapping)

        hostile_mapping = dict(mapping)
        hostile_mapping[next(iter(hostile_mapping))] = "/srv/../etc/passwd"
        with self.assertRaises(self.module.PrivateServerComposeContractError):
            self._close(document, hostile_mapping)

        redirected_mapping = dict(mapping)
        redirected_mapping["/srv/desire/input/db_superuser_password.txt"] = (
            "/etc/db_superuser_password.txt"
        )
        with self.assertRaises(self.module.PrivateServerComposeContractError):
            self._close(document, redirected_mapping)

        path_mapping = {Path(source): Path(staged) for source, staged in mapping.items()}
        self._close(document, path_mapping)

        image_ids = dict(IMAGE_IDS)
        image_ids[PLATFORM_REF] = "desire-supply-platform:mutable"
        with self.assertRaises(self.module.PrivateServerComposeContractError):
            self.module.build_canonical_private_server_compose(
                json.dumps(document),
                project=PROJECT,
                bind_ip=BIND_IP,
                subnets=SUBNETS,
                image_tag=IMAGE_TAG,
                source_to_staged=mapping,
                image_ref_to_id=image_ids,
            )


if __name__ == "__main__":
    unittest.main()
