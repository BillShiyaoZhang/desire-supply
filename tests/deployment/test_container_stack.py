"""Static acceptance tests for the deployable INTERNAL_SANDBOX boundary.

These tests deliberately use ``docker compose config`` only.  They do not
start containers or contact a registry; they prove the closed startup graph
and secret/network boundary before an operator runs the external preflights.
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
VERIFY_PATH = ROOT / "scripts" / "verify_container_stack.py"

API_SECRET_NAMES = (
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

MATCHING_RUNTIME_SECRET_NAMES = (
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

ONLINE_SECRET_NAMES = API_SECRET_NAMES + tuple(
    name for name in MATCHING_RUNTIME_SECRET_NAMES if name not in API_SECRET_NAMES
)

ONLINE_DATABASE_SECRET_NAMES = (
    "db_superuser_password",
    *(name for name in ONLINE_SECRET_NAMES if name.startswith("db-")),
)

IDENTITY_BOOTSTRAP_SECRET_NAMES = (
    "db_superuser_password",
    "key-oidc-subject-digest-v1",
    "key-oidc-recipient-binding-v1",
)

DEPLOYMENT_SERVICES = (
    "migrate",
    "taxonomy-seed",
    "online-credentials-reconcile",
    "online-credentials-verify",
    "identity-bootstrap",
)

POSTGRES_PARENT_TMPFS = (
    "/var/lib/postgresql:rw,nosuid,nodev,noexec,size=1m"
)
DEVCONTAINER_EXECUTABLE_TMPFS = "/tmp:rw,exec,nosuid,nodev,size=64m"
POSTGRES_CHILD_DATA = "/var/lib/postgresql/data"
POSTGRES_CHILD_PGDATA = "/var/lib/postgresql/data/pgdata"
BOUNDED_LOCAL_LOGGING = {
    "driver": "local",
    "options": {
        "compress": "true",
        "max-file": "3",
        "max-size": "10m",
    },
}
BASE_LOGGED_SERVICES = (
    "db",
    "migrate",
    "taxonomy-seed",
    "online-credentials-reconcile",
    "online-credentials-verify",
    "identity-bootstrap",
    "synthetic-oidc",
    "api",
    "matching-runtime",
    "web",
    "edge",
)
REAL_OIDC_COMPOSE_ENVIRONMENT = {
    "DESIRE_REAL_OIDC_PROJECT_NAME": "desire-real-oidc-logging-contract",
    "DESIRE_PRIVATE_INGRESS_IP": "192.168.50.10",
    "DESIRE_REAL_OIDC_DB_DATA_IPV4": "172.29.25.10",
    "DESIRE_REAL_OIDC_PINNED_PUBLIC_IPV4": "8.8.8.8",
    "DESIRE_REAL_OIDC_EGRESS_PROJECTION_SHA256": "logging-contract",
    "DESIRE_REAL_OIDC_PILOT_HOSTNAME": "pilot.example.org",
    "DESIRE_REAL_OIDC_BUNDLE_DIR": "/tmp/desire-real-oidc-logging-bundle",
    "DESIRE_REAL_OIDC_IDENTITY_SOURCE_DIR": (
        "/tmp/desire-real-oidc-logging-identities"
    ),
    "DESIRE_REAL_OIDC_TLS_DIR": "/tmp/desire-real-oidc-logging-tls",
    "DESIRE_REAL_OIDC_DB_PASSWORD_FILE": (
        "/tmp/desire-real-oidc-logging-db-password"
    ),
    "DESIRE_REAL_OIDC_TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE": (
        "/tmp/desire-real-oidc-logging-taxonomy-workload"
    ),
    "DESIRE_REAL_OIDC_TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE": (
        "/tmp/desire-real-oidc-logging-taxonomy-hmac"
    ),
}


def _secret_sources(service: dict) -> tuple[str, ...]:
    return tuple(item["source"] for item in service.get("secrets", []))


def _secret_targets(service: dict) -> tuple[str, ...]:
    return tuple(item["target"] for item in service.get("secrets", []))


def _depends_on(service: dict) -> dict[str, str]:
    return {
        name: value["condition"]
        for name, value in service.get("depends_on", {}).items()
    }


def _assert_exact_bounded_local_logging(
    test_case: unittest.TestCase,
    services: dict,
    service_names: tuple[str, ...],
) -> None:
    for service_name in service_names:
        with test_case.subTest(service=service_name):
            service = services[service_name]
            test_case.assertIn("logging", service)
            logging = service["logging"]
            test_case.assertEqual(logging, BOUNDED_LOCAL_LOGGING)
            for option_name in ("compress", "max-file", "max-size"):
                test_case.assertIs(type(logging["options"][option_name]), str)


def _load_verifier():
    spec = importlib.util.spec_from_file_location("verify_container_stack", VERIFY_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("container verifier cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _compose_config(
    *files: str,
    project_name: str | None = None,
    environment: dict[str, str] | None = None,
) -> dict:
    command = ["docker", "compose"]
    if project_name is not None:
        command.extend(("--project-name", project_name))
    for filename in files:
        command.extend(("-f", filename))
    command.extend(("config", "--format", "json"))
    command_environment = os.environ.copy()
    if environment is not None:
        command_environment.update(environment)
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=command_environment,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


class ContainerStackContractTest(unittest.TestCase):
    def test_resolved_services_use_exact_bounded_local_logging(self) -> None:
        base_services = _compose_config("compose.yaml")["services"]
        _assert_exact_bounded_local_logging(
            self,
            base_services,
            BASE_LOGGED_SERVICES,
        )

        development_services = _compose_config(
            "compose.yaml", "compose.dev.yaml"
        )["services"]
        _assert_exact_bounded_local_logging(
            self,
            development_services,
            ("devcontainer",),
        )

        real_oidc_services = _compose_config(
            "compose.yaml",
            "deploy/private-server.compose.yaml",
            "deploy/private-server-real-oidc.compose.yaml",
            environment=REAL_OIDC_COMPOSE_ENVIRONMENT,
        )["services"]
        _assert_exact_bounded_local_logging(
            self,
            real_oidc_services,
            ("oidc-egress-guard",),
        )

    def test_required_artifacts_and_multistage_targets_exist(self) -> None:
        required = (
            "Dockerfile",
            "compose.yaml",
            "compose.dev.yaml",
            ".dockerignore",
            ".devcontainer/devcontainer.json",
            "deploy/Caddyfile",
            "deploy/devcontainer-entrypoint.sh",
            "deploy/devcontainer-post-create.sh",
            "deploy/devcontainer-runtime-closure.sh",
            "deploy/devcontainer-toolchain-check.sh",
            "scripts/manage_internal_sandbox_tls.py",
            "scripts/preflight_docker_hub_manifests.py",
            "scripts/run_internal_sandbox_e2e.py",
            "scripts/smoke_web_container.sh",
            "platform/src/desire_platform/deployment/migrations.py",
            "platform/src/desire_platform/deployment/identity_bootstrap_orchestrator.py",
            "platform/src/desire_platform/synthetic_oidc/__main__.py",
            "docs/operations/container-deployment.md",
            "docs/development/dev-container.md",
        )
        for relative in required:
            with self.subTest(path=relative):
                self.assertTrue((ROOT / relative).is_file())

        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        for stage in (
            "platform-builder",
            "platform-runtime",
            "web-builder",
            "web-runtime",
            "edge-runtime",
            "devcontainer",
        ):
            with self.subTest(stage=stage):
                self.assertIn(f" AS {stage}", dockerfile)
        self.assertNotIn(":latest", dockerfile)
        self.assertIn("./platform[server]", dockerfile)
        self.assertIn("desire-supply-platform[server]", dockerfile)
        self.assertIn("RUN npm ci --ignore-scripts --no-audit", dockerfile)
        self.assertNotIn("RUN npm audit", dockerfile)
        self.assertIn(
            'CMD ["python", "-m", "desire_platform.internal_pilot.api_server"]',
            dockerfile,
        )
        self.assertNotIn("blocked_runtime.py", dockerfile)

    def test_base_compose_is_closed_internal_sandbox(self) -> None:
        self.assertEqual(len(API_SECRET_NAMES), 43)
        self.assertEqual(len(MATCHING_RUNTIME_SECRET_NAMES), 11)
        self.assertEqual(len(ONLINE_SECRET_NAMES), 53)
        self.assertEqual(len(set(ONLINE_SECRET_NAMES)), 53)
        self.assertEqual(_load_verifier().API_SECRETS, API_SECRET_NAMES)
        self.assertEqual(
            _load_verifier().MATCHING_RUNTIME_SECRETS,
            MATCHING_RUNTIME_SECRET_NAMES,
        )
        self.assertEqual(_load_verifier().ONLINE_SECRETS, ONLINE_SECRET_NAMES)
        config = _compose_config("compose.yaml")
        self.assertEqual(
            set(config["services"]),
            {
                "db",
                "migrate",
                "taxonomy-seed",
                "online-credentials-reconcile",
                "online-credentials-verify",
                "identity-bootstrap",
                "synthetic-oidc",
                "api",
                "matching-runtime",
                "web",
                "edge",
            },
        )
        services = config["services"]

        self.assertRegex(
            services["db"]["image"],
            r"^postgres:18\.[0-9]+-alpine@sha256:[0-9a-f]{64}$",
        )
        self.assertEqual(
            services["db"]["environment"]["POSTGRES_PASSWORD_FILE"],
            "/run/secrets/db_superuser_password",
        )
        self.assertNotIn("POSTGRES_PASSWORD", services["db"]["environment"])
        self.assertEqual(
            services["db"]["environment"]["PGDATA"],
            POSTGRES_CHILD_PGDATA,
        )
        self.assertEqual(services["db"]["tmpfs"], [POSTGRES_PARENT_TMPFS])
        self.assertEqual(len(services["db"]["volumes"]), 1)
        database_mount = services["db"]["volumes"][0]
        self.assertEqual(database_mount["type"], "volume")
        self.assertEqual(database_mount["target"], POSTGRES_CHILD_DATA)
        self.assertEqual(
            database_mount["source"],
            "postgres-data",
        )

        for service_name in DEPLOYMENT_SERVICES:
            environment = services[service_name]["environment"]
            self.assertEqual(environment["DESIRE_DEPLOYMENT_MODE"], "INTERNAL_SANDBOX")
            self.assertEqual(environment["DESIRE_EXTERNAL_PARTICIPANTS_ENABLED"], "false")
            self.assertEqual(
                environment["DESIRE_DATABASE_PASSWORD_FILE"],
                "/run/secrets/db_superuser_password",
            )
        self.assertEqual(
            services["api"]["environment"],
            {
                "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE": (
                    "/run/desire/deployment.json"
                ),
                "SSL_CERT_FILE": (
                    "/run/desire-tls/root-ca.pem"
                ),
            },
        )
        self.assertEqual(
            services["api"]["command"],
            ["python", "-m", "desire_platform.internal_pilot.api_server"],
        )
        self.assertEqual(
            services["matching-runtime"]["command"],
            ["python", "-m", "desire_platform.matching.runtime_process"],
        )
        self.assertEqual(
            services["web"]["environment"]["DESIRE_LOOPBACK_BASE_URL"],
            "http://api:8000",
        )

        published = {
            service_name: service.get("ports", [])
            for service_name, service in services.items()
            if service.get("ports")
        }
        self.assertEqual(set(published), {"edge"})
        edge_port = published["edge"][0]
        self.assertEqual(edge_port["host_ip"], "127.0.0.1")
        self.assertEqual(edge_port["target"], 443)

        self.assertTrue(config["networks"]["app"]["internal"])
        self.assertTrue(config["networks"]["data"]["internal"])
        self.assertTrue(config["networks"]["oidc-backend"]["internal"])
        self.assertFalse(config["networks"]["ingress"].get("internal", False))
        self.assertNotIn("edge", services["db"]["networks"])
        self.assertNotIn("data", services["edge"]["networks"])
        self.assertIn("ingress", services["edge"]["networks"])
        for service_name in ("db", "migrate", "api", "web"):
            self.assertNotIn("ingress", services[service_name]["networks"])
        self.assertEqual(set(services["api"]["networks"]), {"app", "data"})
        self.assertEqual(set(services["matching-runtime"]["networks"]), {"data"})
        for service_name, expected in {
            "db": {"data"},
            "migrate": {"data"},
            "taxonomy-seed": {"data"},
            "online-credentials-reconcile": {"data"},
            "online-credentials-verify": {"data"},
            "identity-bootstrap": {"data"},
            "synthetic-oidc": {"oidc-backend"},
            "web": {"app"},
            "edge": {"app", "oidc-backend", "ingress"},
        }.items():
            self.assertEqual(set(services[service_name]["networks"]), expected)

        synthetic = services["synthetic-oidc"]
        self.assertEqual(
            synthetic["command"],
            ["python", "-m", "desire_platform.synthetic_oidc"],
        )
        self.assertEqual(
            synthetic["environment"],
            {
                "DESIRE_DEPLOYMENT_MODE": "INTERNAL_SANDBOX",
                "DESIRE_EXTERNAL_PARTICIPANTS_ENABLED": "false",
                "DESIRE_SYNTHETIC_OIDC_CLIENT_SECRET_FILE": (
                    "/run/secrets/key-oidc-client-secret-v1"
                ),
            },
        )
        self.assertEqual(_secret_sources(synthetic), ("key-oidc-client-secret-v1",))
        self.assertEqual(_secret_targets(synthetic), ("key-oidc-client-secret-v1",))
        self.assertNotIn("ports", synthetic)

        self.assertEqual(
            set(config["secrets"]),
            {
                "db_superuser_password",
                "taxonomy_seed_workload_credential",
                "taxonomy_seed_receipt_hmac_key",
                "edge-tls-key",
                *ONLINE_SECRET_NAMES,
            },
        )
        self.assertEqual(
            set(config["configs"]),
            {
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
            },
        )
        self.assertEqual(_secret_sources(services["api"]), API_SECRET_NAMES)
        self.assertEqual(_secret_targets(services["api"]), API_SECRET_NAMES)
        self.assertNotIn("db_superuser_password", _secret_sources(services["api"]))
        self.assertEqual(
            tuple(item["target"] for item in services["api"]["configs"]),
            (
                "/run/desire/deployment.json",
                "/run/desire/runtime-config.json",
                "/run/desire/secret-manifest.json",
                "/run/desire-tls/root-ca.pem",
            ),
        )
        self.assertEqual(
            _secret_sources(services["matching-runtime"]),
            MATCHING_RUNTIME_SECRET_NAMES,
        )
        self.assertEqual(
            _secret_targets(services["matching-runtime"]),
            MATCHING_RUNTIME_SECRET_NAMES,
        )
        self.assertEqual(
            tuple(
                item["target"]
                for item in services["matching-runtime"]["configs"]
            ),
            (
                "/run/desire/matching-deployment.json",
                "/run/desire/matching-runtime-config.json",
                "/run/desire/matching-secret-manifest.json",
            ),
        )
        self.assertFalse(services["matching-runtime"].get("ports"))
        for service_name in (
            "api",
            "matching-runtime",
            "web",
            "edge",
            "synthetic-oidc",
            *DEPLOYMENT_SERVICES,
        ):
            service = services[service_name]
            self.assertTrue(service["read_only"], service_name)
            self.assertIn("ALL", service["cap_drop"], service_name)
            self.assertIn("no-new-privileges=true", service["security_opt"], service_name)

    def test_deployment_jobs_are_exactly_ordered_before_real_api(self) -> None:
        services = _compose_config("compose.yaml")["services"]
        api_health = " ".join(services["api"]["healthcheck"]["test"])
        self.assertIn("/health/ready", api_health)
        schema_command = " ".join(services["migrate"]["command"])
        self.assertEqual(schema_command, "python -m desire_platform.deployment")
        self.assertEqual(
            " ".join(services["taxonomy-seed"]["command"]),
            "python -m desire_platform.deployment.synthetic_taxonomy_seed apply",
        )
        self.assertEqual(
            " ".join(services["online-credentials-reconcile"]["command"]),
            "python -m desire_platform.deployment.online_credentials reconcile",
        )
        self.assertEqual(
            " ".join(services["online-credentials-verify"]["command"]),
            "python -m desire_platform.deployment.online_credentials verify",
        )
        self.assertEqual(
            " ".join(services["identity-bootstrap"]["command"]),
            "python -m desire_platform.deployment.identity_bootstrap_orchestrator run",
        )
        self.assertEqual(_depends_on(services["migrate"]), {"db": "service_healthy"})
        self.assertEqual(
            _depends_on(services["taxonomy-seed"]),
            {"migrate": "service_completed_successfully"},
        )
        self.assertEqual(
            _depends_on(services["online-credentials-reconcile"]),
            {"taxonomy-seed": "service_completed_successfully"},
        )
        self.assertEqual(
            _depends_on(services["online-credentials-verify"]),
            {"online-credentials-reconcile": "service_completed_successfully"},
        )
        self.assertEqual(
            _depends_on(services["identity-bootstrap"]),
            {"online-credentials-verify": "service_completed_successfully"},
        )
        self.assertEqual(
            _depends_on(services["api"]),
            {
                "identity-bootstrap": "service_completed_successfully",
                "edge": "service_healthy",
            },
        )
        self.assertEqual(
            _depends_on(services["matching-runtime"]),
            {"identity-bootstrap": "service_completed_successfully"},
        )
        self.assertEqual(
            _depends_on(services["edge"]),
            {"synthetic-oidc": "service_healthy"},
        )
        self.assertEqual(_depends_on(services["synthetic-oidc"]), {})
        self.assertEqual(_depends_on(services["web"]), {"api": "service_healthy"})
        self.assertNotIn("web", services["edge"].get("depends_on", {}))

        self.assertNotIn("volumes", services["api"])
        self.assertNotIn("volumes", services["matching-runtime"])
        self.assertNotIn("volumes", services["edge"])
        self.assertEqual(
            tuple(item["target"] for item in services["edge"]["configs"]),
            ("/run/desire-tls/edge-tls-chain.pem",),
        )
        self.assertEqual(
            _secret_targets(services["edge"]),
            ("/run/secrets/edge-tls-key.pem",),
        )

        for name in ("online-credentials-reconcile", "online-credentials-verify"):
            self.assertEqual(
                _secret_sources(services[name]),
                ONLINE_DATABASE_SECRET_NAMES,
            )
            self.assertEqual(
                _secret_targets(services[name]),
                ONLINE_DATABASE_SECRET_NAMES,
            )
        self.assertEqual(
            _secret_sources(services["identity-bootstrap"]),
            IDENTITY_BOOTSTRAP_SECRET_NAMES,
        )
        self.assertEqual(
            _secret_targets(services["identity-bootstrap"]),
            IDENTITY_BOOTSTRAP_SECRET_NAMES,
        )
        self.assertEqual(len(services["identity-bootstrap"].get("volumes", [])), 1)
        identity_sources = services["identity-bootstrap"]["volumes"][0]
        self.assertEqual(identity_sources["type"], "bind")
        self.assertEqual(identity_sources["target"], "/run/identity-sources")
        self.assertTrue(identity_sources["read_only"])
        self.assertFalse(identity_sources["bind"]["create_host_path"])

    def test_devcontainer_overlay_is_reproducible_and_does_not_publish_db(self) -> None:
        config = _compose_config("compose.yaml", "compose.dev.yaml")
        self.assertEqual(config["name"], "desire-supply-devcontainer")
        self.assertIn("devcontainer", config["services"])
        service = config["services"]["devcontainer"]
        self.assertEqual(service["build"]["target"], "devcontainer")
        self.assertNotIn("ports", service)
        self.assertIn("data", service["networks"])
        self.assertIn("dev-egress", service["networks"])
        expected_subnets = {
            "app": "172.16.221.0/24",
            "data": "172.16.222.0/24",
            "dev-egress": "172.16.223.0/24",
        }
        for network_name, expected_subnet in expected_subnets.items():
            network = config["networks"][network_name]
            self.assertEqual(
                network["ipam"]["config"],
                [{"subnet": expected_subnet}],
            )
            self.assertNotIn("gateway", network["ipam"]["config"][0])
        self.assertTrue(config["networks"]["app"]["internal"])
        self.assertTrue(config["networks"]["data"]["internal"])
        self.assertFalse(config["networks"]["dev-egress"].get("internal", False))

        overridden = _compose_config(
            "compose.yaml",
            "compose.dev.yaml",
            project_name="desire-supply-devcontainer-audit-20260819-v5",
            environment={
                "COMPOSE_PROJECT_NAME": "hostile-project-name",
                "DESIRE_DEVCONTAINER_APP_SUBNET": "10.251.221.0/24",
                "DESIRE_DEVCONTAINER_DATA_SUBNET": "10.251.222.0/24",
                "DESIRE_DEVCONTAINER_EGRESS_SUBNET": "10.251.223.0/24",
            },
        )
        self.assertEqual(
            overridden["name"],
            "desire-supply-devcontainer-audit-20260819-v5",
        )
        self.assertEqual(
            {
                name: overridden["networks"][name]["ipam"]["config"][0][
                    "subnet"
                ]
                for name in expected_subnets
            },
            {
                "app": "10.251.221.0/24",
                "data": "10.251.222.0/24",
                "dev-egress": "10.251.223.0/24",
            },
        )
        self.assertEqual(
            service["environment"]["DESIRE_IAM_TEST_POSTGRES_EPHEMERAL"],
            "1",
        )
        self.assertEqual(
            service["environment"]["PGPASSFILE"],
            "/tmp/desire-pgpass",
        )
        self.assertEqual(
            service["entrypoint"],
            ["/usr/local/bin/desire-devcontainer-entrypoint"],
        )
        self.assertIn(
            "db_superuser_password",
            {secret["source"] for secret in service["secrets"]},
        )
        self.assertEqual(
            service["tmpfs"],
            [
                DEVCONTAINER_EXECUTABLE_TMPFS,
                "/var/lib/postgresql:rw,nosuid,nodev,noexec,size=1m",
            ],
        )
        base_compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
        self.assertIn(
            "/tmp:rw,noexec,nosuid,nodev,size=64m",
            base_compose,
        )
        self.assertNotIn(DEVCONTAINER_EXECUTABLE_TMPFS, base_compose)
        self.assertFalse(service.get("privileged", False))
        self.assertNotIn("security_opt", service)
        self.assertNotIn("cap_drop", service)
        self.assertNotIn("docker.sock", json.dumps(service.get("volumes", [])))
        self.assertFalse(config["services"]["db"].get("ports"))
        development_db = config["services"]["db"]
        self.assertEqual(development_db["tmpfs"], [POSTGRES_PARENT_TMPFS])
        self.assertEqual(development_db["environment"]["PGDATA"], POSTGRES_CHILD_PGDATA)
        self.assertEqual(len(development_db["volumes"]), 1)
        self.assertEqual(development_db["volumes"][0]["type"], "volume")
        self.assertEqual(development_db["volumes"][0]["target"], POSTGRES_CHILD_DATA)
        self.assertEqual(
            development_db["volumes"][0]["source"],
            "postgres-data",
        )

        devcontainer = json.loads(
            (ROOT / ".devcontainer" / "devcontainer.json").read_text(encoding="utf-8")
        )
        self.assertEqual(devcontainer["service"], "devcontainer")
        self.assertEqual(devcontainer["workspaceFolder"], "/workspace")
        self.assertEqual(devcontainer["containerUser"], "node")
        self.assertEqual(devcontainer["remoteUser"], "node")
        self.assertIs(devcontainer["updateRemoteUserUID"], True)
        self.assertEqual(
            devcontainer["postCreateCommand"],
            "cd /workspace/mvp && uv sync --locked && "
            "/usr/local/bin/desire-devcontainer-post-create",
        )
        self.assertEqual(
            devcontainer["initializeCommand"],
            'if [ -n "${COMPOSE_PROJECT_NAME:-}" ]; then '
            "printf '%s\\n' 'BLOCKED:DEVCONTAINER_COMPOSE_PROJECT_NAME' >&2; "
            "exit 64; fi; exit 0",
        )
        self.assertEqual(
            devcontainer["dockerComposeFile"],
            ["../compose.yaml", "../compose.dev.yaml"],
        )
        self.assertIn("db", devcontainer["runServices"])

        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        for writable_target in (
            "/home/node/.cache/uv",
            "/home/node/.npm",
            "/workspace/platform/.venv",
            "/workspace/mvp/.venv",
            "/workspace/web/node_modules",
        ):
            self.assertIn(writable_target, dockerfile)
        self.assertIn("install -d -o node -g node", dockerfile)
        self.assertIn("groupadd --gid 1000 node", dockerfile)
        self.assertIn(
            "useradd --uid 1000 --gid node --create-home "
            "--home-dir /home/node --shell /bin/bash node",
            dockerfile,
        )
        self.assertIn("node ALL=(root) NOPASSWD:ALL", dockerfile)
        self.assertIn("visudo -cf /etc/sudoers.d/node", dockerfile)

        mounts = {item["target"]: item for item in service["volumes"]}
        self.assertEqual(mounts["/workspace/mvp/.venv"]["type"], "volume")

        post_create = (ROOT / "deploy" / "devcontainer-post-create.sh").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("verify_container_stack.py", post_create)
        self.assertIn("uv sync --locked --extra test --extra server", post_create)
        self.assertIn("npm ci --ignore-scripts --no-audit", post_create)
        self.assertNotIn("\nnpm ci\n", post_create)
        self.assertIn("DEVCONTAINER_DEPENDENCIES_READY", post_create)

        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        dev_docs = (ROOT / "docs" / "development" / "dev-container.md").read_text(
            encoding="utf-8"
        )
        for source in (ci, dev_docs):
            self.assertNotIn("PYTHONPATH=src:tests", source)
            self.assertNotIn("PYTHONPATH: src:tests", source)
        self.assertIn("PYTHONPATH: src\n", ci)
        self.assertIn("PYTHONPATH=src ", dev_docs)
        self.assertIn(
            "python3 -m unittest discover -s tests -t . -v",
            ci,
        )
        self.assertIn(
            "python -m unittest discover -s tests -t . -v",
            dev_docs,
        )

    def test_verifier_rejects_postgres_anonymous_parent_volume_risk(self) -> None:
        verifier = _load_verifier()
        safe_services = {
            "db": {
                "environment": {"PGDATA": POSTGRES_CHILD_PGDATA},
                "tmpfs": [POSTGRES_PARENT_TMPFS],
                "volumes": [
                    {
                        "type": "volume",
                        "source": "audit_postgres-data",
                        "target": POSTGRES_CHILD_DATA,
                    }
                ],
            }
        }
        self.assertEqual(
            verifier._postgres_parent_volume_failures(
                safe_services,
                required_services=("db",),
                child_volume_services=("db",),
            ),
            (),
        )

        missing_parent_cover = json.loads(json.dumps(safe_services))
        del missing_parent_cover["db"]["tmpfs"]
        self.assertIn(
            "postgres-parent-tmpfs-open:db",
            verifier._postgres_parent_volume_failures(
                missing_parent_cover,
                required_services=("db",),
                child_volume_services=("db",),
            ),
        )

        moved_named_volume = json.loads(json.dumps(safe_services))
        moved_named_volume["db"]["volumes"][0]["target"] = "/var/lib/postgresql"
        moved_failures = verifier._postgres_parent_volume_failures(
            moved_named_volume,
            required_services=("db",),
            child_volume_services=("db",),
        )
        self.assertIn("postgres-parent-volume-open:db", moved_failures)
        self.assertIn("postgres-child-volume-open:db", moved_failures)

        wrong_tmpfs = json.loads(json.dumps(safe_services))
        wrong_tmpfs["db"]["tmpfs"] = ["/var/lib/postgresql:size=1m"]
        self.assertIn(
            "postgres-parent-tmpfs-open:db",
            verifier._postgres_parent_volume_failures(
                wrong_tmpfs,
                required_services=("db",),
                child_volume_services=("db",),
            ),
        )

    def test_repository_verifier_accepts_the_current_stack(self) -> None:
        verifier = _load_verifier()
        self.assertEqual(verifier.verify(ROOT), ())

    def test_startup_graph_is_acyclic_and_rejects_the_old_edge_web_cycle(self) -> None:
        verifier = _load_verifier()
        services = _compose_config("compose.yaml")["services"]
        self.assertFalse(verifier._dependency_graph_has_cycle(services))

        cyclic = {name: dict(service) for name, service in services.items()}
        cyclic["edge"] = dict(cyclic["edge"])
        cyclic["edge"]["depends_on"] = {
            "web": {"condition": "service_healthy"}
        }
        self.assertTrue(verifier._dependency_graph_has_cycle(cyclic))

    def test_caddy_terminates_two_exact_tls_hosts_and_closes_oidc_headers(self) -> None:
        caddyfile = (ROOT / "deploy" / "Caddyfile").read_text(encoding="utf-8")
        self.assertIn("https://identity.example.test", caddyfile)
        self.assertIn("https://pilot.example.test", caddyfile)
        self.assertGreaterEqual(
            caddyfile.count(
                "tls /run/desire-tls/edge-tls-chain.pem "
                "/run/secrets/edge-tls-key.pem"
            ),
            2,
        )
        self.assertIn("reverse_proxy synthetic-oidc:8081", caddyfile)
        self.assertIn("header_up Host identity.example.test", caddyfile)
        self.assertIn("header_up X-Forwarded-Host identity.example.test", caddyfile)
        self.assertIn("header_up X-Forwarded-Proto https", caddyfile)
        self.assertIn("header_up -Forwarded", caddyfile)
        self.assertNotIn("header_up -X-Forwarded-Proto", caddyfile)
        self.assertIn("header_up Host pilot.example.test", caddyfile)
        self.assertIn("header_up X-Forwarded-Host pilot.example.test", caddyfile)
        self.assertIn("reverse_proxy web:3000", caddyfile)
        self.assertNotIn("auto_https off", caddyfile)


if __name__ == "__main__":
    unittest.main()
