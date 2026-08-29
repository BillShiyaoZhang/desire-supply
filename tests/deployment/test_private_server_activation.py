"""Offline contracts for atomic fresh private-server ingress activation."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "activate_private_server_ingress.py"
RUNBOOK = ROOT / "docs" / "operations" / "private-server-internal-sandbox.md"
PROJECT = "desire-private-ingress-20260824-a1"
BIND_IP = "10.23.4.15"
READY = '{"status":"PRIVATE_SERVER_INGRESS_ACTIVATED"}\n'
BLOCKED = (
    '{"code":"PRIVATE_SERVER_INGRESS_ACTIVATION_INVALID",'
    '"status":"BLOCKED"}\n'
)
PARTIAL = (
    '{"code":"PRIVATE_SERVER_INGRESS_PARTIAL_POSSIBLE",'
    '"status":"BLOCKED"}\n'
)
PLATFORM_REF = "desire-supply-platform:immutable"
WEB_REF = "desire-supply-web:immutable"
EDGE_REF = "desire-supply-edge:immutable"
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
APPROVED_TREE_SHA256 = "a" * 64

SERVICES = {
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
CONTAINER_IDS = {
    service: f"{index:x}" * 64
    for index, service in enumerate(sorted(SERVICES), start=1)
}
CONFIG_HASHES = {
    service: hashlib.sha256(f"config:{service}".encode("ascii")).hexdigest()
    for service in SERVICES
}
NETWORK_IDS = {
    name: f"{index:x}" * 64
    for index, name in enumerate(
        ("app", "data", "ingress", "oidc-backend"), start=11
    )
}


def _activation_container(service: str, *, config_hash: str | None = None) -> dict:
    return {
        "Config": {
            "Cmd": ["run", service],
            "Env": ["PATH=/usr/bin"],
            "Image": IMAGE_IDS[PLATFORM_REF],
            "Labels": {
                "com.docker.compose.config-hash": (
                    CONFIG_HASHES[service] if config_hash is None else config_hash
                )
            },
        },
        "HostConfig": {
            "Privileged": False,
            "RestartPolicy": {
                "MaximumRetryCount": 0,
                "Name": "unless-stopped" if service == "matching-runtime" else "no",
            },
        },
        "Id": CONTAINER_IDS[service],
        "Mounts": [],
        "Name": f"/{PROJECT}-{service}-1",
    }
ADMIN_SERVICES = {
    "identity-bootstrap",
    "migrate",
    "online-credentials-reconcile",
    "online-credentials-verify",
    "synthetic-oidc",
    "taxonomy-seed",
}
SERVICE_NETWORKS = {
    "db": {"data"},
    "migrate": {"data"},
    "taxonomy-seed": {"data"},
    "online-credentials-reconcile": {"data"},
    "online-credentials-verify": {"data"},
    "identity-bootstrap": {"data"},
    "synthetic-oidc": {"oidc-backend"},
    "matching-runtime": {"data"},
    "api": {"app", "data"},
    "web": {"app"},
    "edge": {"app", "oidc-backend", "ingress"},
}


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "activate_private_server_ingress", SCRIPT
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("activation module cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _config() -> dict:
    services = {}
    for name in SERVICES:
        service = {"networks": {network: None for network in SERVICE_NETWORKS[name]}}
        if name in ADMIN_SERVICES:
            service["environment"] = {
                "DESIRE_DEPLOYMENT_MODE": "INTERNAL_SANDBOX",
                "DESIRE_EXTERNAL_PARTICIPANTS_ENABLED": "false",
            }
        if name == "matching-runtime":
            service["environment"] = {
                "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE": (
                    "/run/desire/matching-deployment.json"
                ),
                "DESIRE_MATCHING_RUNTIME_HEALTH_FILE": (
                    "/run/matching-runtime/healthy"
                ),
            }
            service["restart"] = "unless-stopped"
        services[name] = service
    services["edge"]["ports"] = [
        {
            "target": 443,
            "published": "443",
            "host_ip": "127.0.0.1",
            "protocol": "tcp",
            "mode": "ingress",
        },
        {
            "name": "private-rfc1918-https",
            "target": 443,
            "published": "443",
            "host_ip": BIND_IP,
            "protocol": "tcp",
            "mode": "ingress",
        },
    ]
    return {
        "name": PROJECT,
        "services": services,
        "networks": {
            "app": {"internal": True, "name": f"{PROJECT}_app"},
            "data": {"internal": True, "name": f"{PROJECT}_data"},
            "oidc-backend": {
                "internal": True,
                "name": f"{PROJECT}_oidc-backend",
            },
            "ingress": {"name": f"{PROJECT}_ingress"},
        },
        "volumes": {
            "postgres-data": {"name": f"{PROJECT}_postgres-data"},
        },
    }


class PrivateServerActivationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = _load_module()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.attempt_temporaries = []
        root = Path(self.temporary.name).resolve(strict=True)
        primary_plugins = root / "compose-plugins-primary"
        secondary_plugins = root / "compose-plugins-secondary"
        primary_plugins.mkdir(mode=0o700)
        secondary_plugins.mkdir(mode=0o700)
        self.compose_plugin = primary_plugins / "docker-compose"
        self.second_compose_plugin = secondary_plugins / "docker-compose"
        self.compose_plugin_paths = (
            self.compose_plugin,
            self.second_compose_plugin,
        )
        self.compose_plugin.write_bytes(b"fake compose plugin\n")
        self.compose_plugin.chmod(0o555)
        self.env_file = root / "compose.env"
        self.ipam = root / "compose.ipam.yaml"
        self.env_file.write_text(
            "DESIRE_IMAGE_TAG=immutable\n"
            f"DESIRE_DB_PASSWORD_FILE={root}/db_superuser_password.txt\n"
            "DESIRE_TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE="
            f"{root}/taxonomy_seed_workload_credential\n"
            "DESIRE_TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE="
            f"{root}/taxonomy_seed_receipt_hmac_key\n"
            f"DESIRE_IDENTITY_SOURCE_DIR={root}/internal-sandbox-identity-sources\n"
            f"DESIRE_INTERNAL_SANDBOX_TLS_DIR={root}/internal-sandbox-tls\n"
            "DESIRE_INTERNAL_SANDBOX_BUNDLE_DIR="
            f"{root}/internal-sandbox-bundle-private\n",
            encoding="utf-8",
        )
        self.ipam.write_text(
            "networks:\n"
            "  ingress:\n    ipam:\n      config:\n        - subnet: 10.240.1.0/24\n"
            "  oidc-backend:\n    ipam:\n      config:\n"
            "        - subnet: 10.240.2.0/24\n"
            "  app:\n    ipam:\n      config:\n        - subnet: 10.240.3.0/24\n"
            "  data:\n    ipam:\n      config:\n        - subnet: 10.240.4.0/24\n",
            encoding="ascii",
        )
        self.env_file.chmod(0o600)
        self.ipam.chmod(0o600)

    def tearDown(self) -> None:
        for temporary in reversed(self.attempt_temporaries):
            temporary.cleanup()
        self.temporary.cleanup()

    def _argv(self, project: str = PROJECT) -> list[str]:
        return [
            "--project-name",
            project,
            "--env-file",
            str(self.env_file),
            "--ipam-overlay",
            str(self.ipam),
            "--bind-ip",
            BIND_IP,
            "--platform-image-id",
            IMAGE_IDS[PLATFORM_REF],
            "--web-image-id",
            IMAGE_IDS[WEB_REF],
            "--edge-image-id",
            IMAGE_IDS[EDGE_REF],
            "--postgres-image-id",
            IMAGE_IDS[POSTGRES_REF],
            "--input-tree-sha256",
            APPROVED_TREE_SHA256,
        ]

    def _new_attempts_root(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.attempt_temporaries.append(temporary)
        root = Path(temporary.name)
        root.chmod(0o700)
        return root

    def _run(
        self,
        config: dict | None = None,
        *,
        resource_output=None,
        up_code=0,
        attempts_root: Path | None = None,
        mutate_sources_after_config: bool = False,
        roundtrip_config: dict | None = None,
        compose_version: str = "5.3.1\n",
        up_exception: bool = False,
        image_inspect_overrides: dict[str, str] | None = None,
        staged_tree_sha256: str = APPROVED_TREE_SHA256,
        staged_env_bytes: bytes | None = None,
        staged_ipam_bytes: bytes | None = None,
        capture_drift: str | None = None,
        plugin_drift: str | None = None,
    ):
        if attempts_root is None:
            attempts_root = self._new_attempts_root()
        self.last_attempts_root = attempts_root
        calls = []
        document = _config() if config is None else config
        config_calls = 0
        plugin_drift_applied = False

        def inject_plugin_drift() -> None:
            nonlocal plugin_drift_applied
            if plugin_drift_applied:
                return
            if plugin_drift in ("docker-config-pre", "docker-config-post"):
                directory = (
                    attempts_root / PROJECT / "docker-config" / "cli-plugins"
                )
                directory.mkdir(mode=0o700)
                plugin = directory / "docker-compose"
                plugin.write_bytes(b"hostile higher-precedence compose plugin\n")
                plugin.chmod(0o555)
            elif plugin_drift in (
                "system-marker", "system-pre", "system-post",
            ):
                self.second_compose_plugin.write_bytes(
                    b"hostile second system compose plugin\n"
                )
                self.second_compose_plugin.chmod(0o555)
            else:
                self.fail(f"unknown plugin drift: {plugin_drift!r}")
            plugin_drift_applied = True

        def runner(command, environment):
            nonlocal config_calls
            command = tuple(command)
            calls.append((command, dict(environment)))
            if command == ("/usr/sbin/ip", "-json", "address", "show", "up"):
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=(
                        '[{"ifname":"eth0","flags":["UP"],'
                        '"addr_info":[{"family":"inet","local":"10.23.4.15"}]}]'
                    ),
                    stderr="",
                )
            if command == ("/usr/bin/ss", "-H", "-ltn"):
                return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
            if (
                plugin_drift in ("docker-config-pre", "system-pre")
                and command[3:4] == ("compose",)
            ):
                inject_plugin_drift()
            if (
                plugin_drift in ("docker-config-post", "system-post")
                and command[-1:] == ("--wait",)
            ):
                inject_plugin_drift()
            if command[-3:] == ("compose", "version", "--short"):
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=compose_version,
                    stderr="",
                )
            if command[3:5] == ("image", "inspect"):
                value = command[-1]
                image_id = IMAGE_IDS.get(value, value)
                if image_inspect_overrides is not None:
                    image_id = image_inspect_overrides.get(value, image_id)
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=image_id + "\n",
                    stderr="",
                )
            if command[-3:] == ("config", "--format", "json"):
                config_calls += 1
                if mutate_sources_after_config and config_calls == 1:
                    self.env_file.write_text("HOSTILE=1\n", encoding="ascii")
                    self.ipam.write_text(
                        "services:\n  api:\n    command: [hostile]\n",
                        encoding="ascii",
                    )
                selected = (
                    roundtrip_config
                    if config_calls == 2 and roundtrip_config is not None
                    else document
                )
                return subprocess.CompletedProcess(
                    command, 0, stdout=json.dumps(selected), stderr=""
                )
            if command[-3:] == ("config", "--hash", "*"):
                output = "".join(
                    f"{service} {CONFIG_HASHES[service]}\n"
                    for service in sorted(SERVICES)
                )
                return subprocess.CompletedProcess(
                    command, 0, stdout=output, stderr=""
                )
            if command[3:5] == ("container", "inspect") and "--format" in command:
                values = []
                for service in sorted(SERVICES):
                    config_hash = CONFIG_HASHES[service]
                    if capture_drift == "config-hash" and service == "api":
                        config_hash = "f" * 64
                    container = _activation_container(
                        service, config_hash=config_hash,
                    )
                    if capture_drift == "container-id" and service == "api":
                        container["Id"] = "not-an-id"
                    values.append(
                        json.dumps(
                            container,
                            separators=(",", ":"),
                            sort_keys=True,
                        )
                    )
                return subprocess.CompletedProcess(
                    command, 0, stdout="\n".join(values) + "\n", stderr=""
                )
            if command[3:5] == ("network", "inspect") and "--format" in command:
                values = [
                    json.dumps(
                        {"Id": NETWORK_IDS[name], "Name": f"{PROJECT}_{name}"},
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                    for name in ("app", "data", "ingress", "oidc-backend")
                ]
                return subprocess.CompletedProcess(
                    command, 0, stdout="\n".join(values) + "\n", stderr=""
                )
            if command[3:5] == ("volume", "inspect") and "--format" in command:
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=json.dumps(
                        {"Name": f"{PROJECT}_postgres-data"},
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                    + "\n",
                    stderr="",
                )
            if command[3:5] == ("container", "ls"):
                output = (
                    resource_output[1]
                    if resource_output
                    and (
                        resource_output[0] == "container"
                        or resource_output[0] in command[-1]
                    )
                    else ""
                )
                return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")
            if command[3:5] == ("network", "ls"):
                output = (
                    resource_output[1]
                    if resource_output
                    and (
                        resource_output[0] == "network"
                        or resource_output[0] in command[-1]
                    )
                    else ""
                )
                return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")
            if command[3:5] == ("volume", "ls"):
                output = (
                    resource_output[1]
                    if resource_output
                    and (
                        resource_output[0] == "volume"
                        or resource_output[0] in command[-1]
                    )
                    else ""
                )
                return subprocess.CompletedProcess(
                    command, 0, stdout=output, stderr=""
                )
            if command[-6:] == (
                "up",
                "-d",
                "--no-build",
                "--pull",
                "never",
                "--wait",
            ):
                if up_exception:
                    raise TimeoutError("untrusted timeout detail")
                return subprocess.CompletedProcess(
                    command,
                    up_code,
                    stdout="untrusted output",
                    stderr="untrusted progress",
                )
            self.fail(f"unexpected command: {command!r}")

        stdout = io.StringIO()
        stderr = io.StringIO()

        def release_input_stager(**arguments):
            self.assertEqual(arguments["input_root"], self.env_file.parent)
            self.assertEqual(arguments["bundle_name"], "internal-sandbox-bundle-private")
            self.assertEqual(
                arguments["attempt_stage_root"],
                attempts_root / PROJECT / "release-inputs",
            )
            staged_env = arguments["attempt_stage_root"] / "compose.env"
            staged_ipam = arguments["attempt_stage_root"] / "compose.ipam.yaml"
            staged_env.write_bytes(
                self.env_file.read_bytes()
                if staged_env_bytes is None
                else staged_env_bytes
            )
            staged_ipam.write_bytes(
                self.ipam.read_bytes()
                if staged_ipam_bytes is None
                else staged_ipam_bytes
            )
            staged_env.chmod(0o600)
            staged_ipam.chmod(0o600)
            return SimpleNamespace(
                tree_sha256=staged_tree_sha256,
                source_to_staged={
                    self.env_file: staged_env,
                    self.ipam: staged_ipam,
                },
            )

        def compose_contract_builder(raw, **arguments):
            selected = self.module._validate_config(
                raw,
                project=arguments["project"],
                bind_ip=arguments["bind_ip"],
            )
            value = (
                json.dumps(
                    selected,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("ascii")
                + b"\n"
            )
            return value, selected

        original_write_snapshot = self.module._write_snapshot

        def write_snapshot_then_drift(directory_fd, name, value, **arguments):
            result = original_write_snapshot(
                directory_fd, name, value, **arguments,
            )
            if (
                plugin_drift == "system-marker"
                and name == "up-invoked.receipt.json"
            ):
                inject_plugin_drift()
            return result

        if plugin_drift == "system-marker":
            self.module._write_snapshot = write_snapshot_then_drift
        try:
            result = self.module.main(
                self._argv(),
                stdout=stdout,
                stderr=stderr,
                platform_name="linux",
                command_runner=runner,
                attempts_root=attempts_root,
                release_input_stager=release_input_stager,
                compose_contract_builder=compose_contract_builder,
                compose_plugin_paths=self.compose_plugin_paths,
                environ={
                    "PATH": "/usr/bin",
                    "LANG": "C",
                    "COMPOSE_FILE": "/hostile/compose.yaml",
                    "COMPOSE_PROJECT_NAME": "hostile",
                    "DOCKER_HOST": "tcp://hostile:2375",
                    "DOCKER_CONTEXT": "hostile",
                    "DESIRE_IMAGE_TAG": "hostile",
                    "DESIRE_PRIVATE_INGRESS_IP": "10.99.99.99",
                    "RANDOM_SECRET": "must-not-reach-child-processes",
                },
            )
        finally:
            self.module._write_snapshot = original_write_snapshot
            if plugin_drift in (
                "system-marker", "system-pre", "system-post",
            ):
                self.second_compose_plugin.unlink(missing_ok=True)
        return result, stdout.getvalue(), stderr.getvalue(), calls

    def test_exact_sanitized_sequence_reaches_up_once(self) -> None:
        result, stdout, stderr, calls = self._run()
        self.assertEqual((result, stdout, stderr), (0, READY, ""))
        attempt = self.last_attempts_root / PROJECT
        docker = (
            "/usr/bin/docker",
            "--host",
            "unix:///var/run/docker.sock",
        )
        config_prefix = docker + (
            "compose",
            "--project-name",
            PROJECT,
            "--project-directory",
            str(ROOT),
            "--env-file",
            str(attempt / "compose.env.snapshot"),
            "-f",
            str(attempt / "compose.yaml.snapshot"),
            "-f",
            str(attempt / "private-server.compose.yaml.snapshot"),
            "-f",
            str(attempt / "compose.ipam.yaml.snapshot"),
        )
        resolved_prefix = docker + (
            "compose",
            "--project-name",
            PROJECT,
            "--project-directory",
            str(ROOT),
            "-f",
            str(attempt / "resolved.compose.json"),
        )
        label = f"label=com.docker.compose.project={PROJECT}"
        expected = [
            ("/usr/sbin/ip", "-json", "address", "show", "up"),
            ("/usr/bin/ss", "-H", "-ltn"),
            docker + ("compose", "version", "--short"),
        ]
        for reference in sorted(IMAGE_IDS):
            expected.append(
                docker
                + ("image", "inspect", "--format", "{{.Id}}", reference)
            )
        expected.extend(
            [
                config_prefix + ("config", "--format", "json"),
                resolved_prefix + ("config", "--format", "json"),
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
        )
        for service in sorted(SERVICES):
            expected.append(
                docker
                + (
                    "container",
                    "ls",
                    "--all",
                    "--quiet",
                    "--filter",
                    f"name=^/{PROJECT}-{service}-1$",
                )
            )
        for network in ("app", "data", "ingress", "oidc-backend"):
            expected.append(
                docker
                + (
                    "network",
                    "ls",
                    "--quiet",
                    "--filter",
                    f"name=^{PROJECT}_{network}$",
                )
            )
        expected.append(
            docker
            + (
                "volume",
                "ls",
                "--quiet",
                "--filter",
                f"name=^{PROJECT}_postgres-data$",
            )
        )
        for image_id in sorted(IMAGE_IDS.values()):
            expected.append(
                docker
                + ("image", "inspect", "--format", "{{.Id}}", image_id)
            )
        expected.append(
            resolved_prefix
            + (
                "up",
                "-d",
                "--no-build",
                "--pull",
                "never",
                "--wait",
            )
        )
        expected.extend(
            [
                resolved_prefix + ("config", "--hash", "*"),
                docker
                + ("container", "inspect", "--format", self.module._ACTIVATION_CONTAINER_FORMAT)
                + tuple(f"{PROJECT}-{service}-1" for service in sorted(SERVICES)),
                docker
                + ("network", "inspect", "--format", self.module._ACTIVATION_NETWORK_FORMAT)
                + tuple(
                    f"{PROJECT}_{name}"
                    for name in ("app", "data", "ingress", "oidc-backend")
                ),
                docker
                + (
                    "volume", "inspect", "--format",
                    self.module._ACTIVATION_VOLUME_FORMAT,
                    f"{PROJECT}_postgres-data",
                ),
            ]
        )
        self.assertEqual([call[0] for call in calls], expected)
        expected_environment = {
            "PATH": "/usr/sbin:/usr/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "DOCKER_HOST": "unix:///var/run/docker.sock",
            "DOCKER_CONFIG": str(attempt / "docker-config"),
            "COMPOSE_DISABLE_ENV_FILE": "true",
            "DESIRE_PRIVATE_INGRESS_IP": BIND_IP,
        }
        self.assertTrue(
            all(environment == expected_environment for _, environment in calls)
        )
        self.assertEqual(
            (attempt / "resolved.compose.json").read_bytes(),
            (
                json.dumps(
                    _config(),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8"),
        )
        self.assertEqual(
            stat.S_IMODE(attempt.stat().st_mode),
            0o700,
        )
        for name in (
            "activation.receipt.json",
            "compose.env.snapshot",
            "compose.yaml.snapshot",
            "private-server.compose.yaml.snapshot",
            "compose.ipam.yaml.snapshot",
            "resolved.compose.json",
            "release-lock.receipt.json",
            "internal-sandbox-identity-bootstrap-template-v1.json",
            "up-invoked.receipt.json",
            "activation-complete.receipt.json",
        ):
            expected_mode = (
                0o444
                if name == "internal-sandbox-identity-bootstrap-template-v1.json"
                else 0o600
            )
            self.assertEqual(
                stat.S_IMODE((attempt / name).stat().st_mode),
                expected_mode,
            )
        activation = json.loads(
            (attempt / "activation-complete.receipt.json").read_text(
                encoding="ascii"
            )
        )
        self.assertEqual(
            {
                "config_hashes": activation["config_hashes"],
                "compose_plugin": activation["compose_plugin"],
                "container_ids": activation["container_ids"],
                "format": activation["format"],
                "network_ids": activation["network_ids"],
                "security_projection_sha256": activation[
                    "security_projection_sha256"
                ],
                "volume_name": activation["volume_name"],
            },
            {
                "config_hashes": CONFIG_HASHES,
                "compose_plugin": {
                    "path": str(self.compose_plugin),
                    "sha256": hashlib.sha256(
                        self.compose_plugin.read_bytes()
                    ).hexdigest(),
                    "version": "5.3.1",
                },
                "container_ids": CONTAINER_IDS,
                "format": "desire-private-ingress-activation-v2",
                "network_ids": NETWORK_IDS,
                "security_projection_sha256": {
                    service: self.module._security_projection_sha256(
                        _activation_container(service)
                    )
                    for service in SERVICES
                },
                "volume_name": f"{PROJECT}_postgres-data",
            },
        )

    def test_post_up_identity_or_authoritative_hash_drift_is_partial(self) -> None:
        for drift in ("container-id", "config-hash"):
            with self.subTest(drift=drift):
                result, stdout, stderr, calls = self._run(capture_drift=drift)
                self.assertEqual((result, stdout, stderr), (75, "", PARTIAL))
                self.assertEqual(
                    sum(command[-1:] == ("--wait",) for command, _ in calls),
                    1,
                )
                self.assertFalse(
                    (
                        self.last_attempts_root
                        / PROJECT
                        / "activation-complete.receipt.json"
                    ).exists()
                )

    def test_security_projection_normalizes_mount_order_but_not_content(self) -> None:
        container = _activation_container("api")
        container["Mounts"] = [
            {
                "Destination": "/run/config",
                "RW": False,
                "Source": "/safe/config",
                "Type": "bind",
            },
            {
                "Destination": "/run/secrets/key",
                "RW": False,
                "Source": "/safe/key",
                "Type": "bind",
            },
        ]
        expected = self.module._security_projection_sha256(container)
        reversed_container = json.loads(json.dumps(container))
        reversed_container["Mounts"].reverse()
        self.assertEqual(
            self.module._security_projection_sha256(reversed_container),
            expected,
        )
        reversed_container["Mounts"][0]["RW"] = True
        self.assertNotEqual(
            self.module._security_projection_sha256(reversed_container),
            expected,
        )

    def test_release_tree_and_image_ids_are_exactly_locked(self) -> None:
        attempts_root = self._new_attempts_root()
        result, stdout, stderr, calls = self._run(
            staged_tree_sha256="b" * 64,
            attempts_root=attempts_root,
        )
        self.assertEqual((result, stdout, stderr), (78, "", BLOCKED))
        self.assertEqual(calls, [])
        self.assertTrue(
            (attempts_root / PROJECT / "activation.receipt.json").is_file()
        )
        second, second_stdout, second_stderr, second_calls = self._run(
            attempts_root=attempts_root,
        )
        self.assertEqual(
            (second, second_stdout, second_stderr),
            (78, "", BLOCKED),
        )
        self.assertEqual(second_calls, [])

        result, stdout, stderr, calls = self._run(
            image_inspect_overrides={PLATFORM_REF: "sha256:" + "9" * 64},
        )
        self.assertEqual((result, stdout, stderr), (78, "", BLOCKED))
        self.assertFalse(any(call[0][-3:] == ("config", "--format", "json") for call in calls))
        self.assertFalse(any(call[0][-1:] == ("--wait",) for call in calls))

        result, stdout, stderr, calls = self._run(
            image_inspect_overrides={IMAGE_IDS[PLATFORM_REF]: "sha256:" + "9" * 64},
        )
        self.assertEqual((result, stdout, stderr), (78, "", BLOCKED))
        self.assertFalse(any(call[0][-1:] == ("--wait",) for call in calls))

    def test_approved_tree_cannot_swap_env_or_ipam_between_reads(self) -> None:
        original_env = self.env_file.read_bytes()
        original_ipam = self.ipam.read_bytes()
        for argument, value in (
            (
                "staged_env_bytes",
                original_env.replace(b"DESIRE_IMAGE_TAG=immutable", b"DESIRE_IMAGE_TAG=other"),
            ),
            (
                "staged_ipam_bytes",
                original_ipam.replace(b"10.240.1.0/24", b"10.241.1.0/24"),
            ),
        ):
            with self.subTest(argument=argument):
                result, stdout, stderr, calls = self._run(**{argument: value})
                self.assertEqual((result, stdout, stderr), (78, "", BLOCKED))
                self.assertEqual(calls, [])

    def test_hash_verified_production_helpers_are_loadable(self) -> None:
        stager, builder = self.module._verified_release_helpers(
            self.module._RELEASE_INPUT_HELPER.read_bytes(),
            self.module._COMPOSE_CONTRACT_HELPER.read_bytes(),
        )
        self.assertTrue(callable(stager))
        self.assertTrue(callable(builder))

    def test_hostile_or_mismatched_config_never_reaches_up(self) -> None:
        mutations = []
        wrong_bind = _config()
        wrong_bind["services"]["edge"]["ports"][1]["host_ip"] = "10.23.4.16"
        mutations.append(wrong_bind)
        api_port = _config()
        api_port["services"]["api"]["ports"] = [{"target": 8000, "published": "8000"}]
        mutations.append(api_port)
        external = _config()
        external["services"]["migrate"]["environment"][
            "DESIRE_EXTERNAL_PARTICIPANTS_ENABLED"
        ] = "true"
        mutations.append(external)
        network = _config()
        network["networks"]["app"]["internal"] = False
        mutations.append(network)
        wrong_project = _config()
        wrong_project["name"] = "another-project"
        mutations.append(wrong_project)
        for document in mutations:
            with self.subTest(document=document):
                result, stdout, stderr, calls = self._run(document)
                self.assertEqual((result, stdout, stderr), (78, "", BLOCKED))
                self.assertFalse(any(call[0][-1:] == ("--wait",) for call in calls))

    def test_config_to_up_uses_only_permanent_resolved_snapshot(self) -> None:
        original_env = self.env_file.read_bytes()
        original_ipam = self.ipam.read_bytes()
        result, stdout, stderr, calls = self._run(
            mutate_sources_after_config=True
        )
        self.assertEqual((result, stdout, stderr), (0, READY, ""))
        attempt = self.last_attempts_root / PROJECT
        self.assertEqual(
            (attempt / "compose.env.snapshot").read_bytes(),
            original_env,
        )
        self.assertEqual(
            (attempt / "compose.ipam.yaml.snapshot").read_bytes(),
            original_ipam,
        )
        up = [command for command, _ in calls if command[-1:] == ("--wait",)]
        self.assertEqual(len(up), 1)
        self.assertIn(str(attempt / "resolved.compose.json"), up[0])
        for forbidden in (
            str(self.env_file),
            str(self.ipam),
            str(attempt / "compose.env.snapshot"),
            str(attempt / "compose.yaml.snapshot"),
            str(attempt / "private-server.compose.yaml.snapshot"),
            str(attempt / "compose.ipam.yaml.snapshot"),
        ):
            self.assertNotIn(forbidden, up[0])

    def test_compose_version_and_roundtrip_drift_block_before_up(self) -> None:
        result, stdout, stderr, calls = self._run(compose_version="5.3.2\n")
        self.assertEqual((result, stdout, stderr), (78, "", BLOCKED))
        self.assertFalse(any(call[0][-1:] == ("--wait",) for call in calls))

        drift = _config()
        drift["x-roundtrip-drift"] = True
        result, stdout, stderr, calls = self._run(roundtrip_config=drift)
        self.assertEqual((result, stdout, stderr), (78, "", BLOCKED))
        self.assertFalse(any(call[0][-1:] == ("--wait",) for call in calls))

    def test_compose_plugin_discovery_drift_is_closed_around_up(self) -> None:
        for drift in ("docker-config-pre", "system-pre"):
            with self.subTest(drift=drift):
                result, stdout, stderr, calls = self._run(plugin_drift=drift)
                self.assertEqual((result, stdout, stderr), (78, "", BLOCKED))
                self.assertFalse(
                    any(call[0][-1:] == ("--wait",) for call in calls)
                )
                self.assertFalse(
                    (
                        self.last_attempts_root
                        / PROJECT
                        / "activation-complete.receipt.json"
                    ).exists()
                )

        for drift in ("docker-config-post", "system-post"):
            with self.subTest(drift=drift):
                result, stdout, stderr, calls = self._run(plugin_drift=drift)
                self.assertEqual((result, stdout, stderr), (75, "", PARTIAL))
                self.assertEqual(
                    sum(call[0][-1:] == ("--wait",) for call in calls), 1
                )
                attempt = self.last_attempts_root / PROJECT
                self.assertTrue((attempt / "up-invoked.receipt.json").is_file())
                self.assertFalse(
                    (attempt / "activation-complete.receipt.json").exists()
                )

        result, stdout, stderr, calls = self._run(
            plugin_drift="system-marker"
        )
        self.assertEqual((result, stdout, stderr), (78, "", BLOCKED))
        self.assertEqual(
            sum(call[0][-1:] == ("--wait",) for call in calls), 0
        )
        attempt = self.last_attempts_root / PROJECT
        self.assertTrue((attempt / "up-invoked.receipt.json").is_file())
        self.assertFalse(
            (attempt / "activation-complete.receipt.json").exists()
        )

    def test_trusted_python_symlink_chain_is_closed(self) -> None:
        root = Path(self.temporary.name).resolve(strict=True) / "trusted-python"
        bin_directory = root / "bin"
        link_directory = root / "links"
        library_directory = root / "lib"
        root.mkdir(mode=0o700)
        bin_directory.mkdir(mode=0o700)
        link_directory.mkdir(mode=0o700)
        library_directory.mkdir(mode=0o700)
        target = library_directory / "python3.14"
        target.write_bytes(b"trusted test interpreter\n")
        target.chmod(0o555)
        intermediate = link_directory / "python-current"
        intermediate.symlink_to("../lib/python3.14")
        launcher = bin_directory / "python3"
        launcher.symlink_to("../links/python-current")

        self.module._validate_trusted_executable_chain(
            launcher,
            expected_owner=os.geteuid(),
            trusted_root=root,
        )

        link_directory.chmod(0o777)
        with self.assertRaises(
            self.module.PrivateServerIngressActivationError
        ):
            self.module._validate_trusted_executable_chain(
                launcher,
                expected_owner=os.geteuid(),
                trusted_root=root,
            )

        link_directory.chmod(0o700)
        target.chmod(0o775)
        with self.assertRaises(
            self.module.PrivateServerIngressActivationError
        ):
            self.module._validate_trusted_executable_chain(
                launcher,
                expected_owner=os.geteuid(),
                trusted_root=root,
            )

    def test_attempt_claim_is_global_once_and_failure_is_permanent(self) -> None:
        attempts_root = self._new_attempts_root()
        result, stdout, stderr, calls = self._run(
            up_code=1,
            attempts_root=attempts_root,
        )
        self.assertEqual((result, stdout, stderr), (75, "", PARTIAL))
        self.assertEqual(sum(call[0][-1:] == ("--wait",) for call in calls), 1)
        attempt = attempts_root / PROJECT
        self.assertTrue((attempt / "activation.receipt.json").is_file())
        self.assertTrue((attempt / "resolved.compose.json").is_file())
        self.assertFalse((attempt / "activation-complete.receipt.json").exists())

        second, second_stdout, second_stderr, second_calls = self._run(
            attempts_root=attempts_root,
        )
        self.assertEqual((second, second_stdout, second_stderr), (78, "", BLOCKED))
        self.assertEqual(second_calls, [])

    def test_attempt_root_mode_and_symlink_are_rejected_without_commands(self) -> None:
        wrong_mode = self._new_attempts_root()
        wrong_mode.chmod(0o755)
        result, stdout, stderr, calls = self._run(attempts_root=wrong_mode)
        self.assertEqual((result, stdout, stderr), (78, "", BLOCKED))
        self.assertEqual(calls, [])

        parent = self._new_attempts_root()
        real = parent / "real"
        real.mkdir(mode=0o700)
        linked = parent / "linked"
        linked.symlink_to(real, target_is_directory=True)
        result, stdout, stderr, calls = self._run(attempts_root=linked)
        self.assertEqual((result, stdout, stderr), (78, "", BLOCKED))
        self.assertEqual(calls, [])

    def test_any_existing_project_resource_blocks_before_up(self) -> None:
        for resource in ("container", "network", "volume"):
            with self.subTest(resource=resource):
                result, stdout, stderr, calls = self._run(
                    resource_output=(resource, "deadbeef\n")
                )
                self.assertEqual((result, stdout, stderr), (78, "", BLOCKED))
                self.assertFalse(any(call[0][-1:] == ("--wait",) for call in calls))

    def test_unlabelled_default_named_resources_block_before_up(self) -> None:
        for name in (
            f"{PROJECT}_postgres-data",
            f"{PROJECT}_app",
            f"{PROJECT}-db-1",
        ):
            with self.subTest(name=name):
                result, stdout, stderr, calls = self._run(
                    resource_output=(name, "deadbeef\n")
                )
                self.assertEqual((result, stdout, stderr), (78, "", BLOCKED))
                self.assertFalse(any(call[0][-1:] == ("--wait",) for call in calls))

    def test_up_failure_is_non_reflective_and_never_retried(self) -> None:
        result, stdout, stderr, calls = self._run(up_code=1)
        self.assertEqual((result, stdout, stderr), (75, "", PARTIAL))
        self.assertEqual(sum(call[0][-1:] == ("--wait",) for call in calls), 1)
        self.assertNotIn("untrusted", stderr)

        result, stdout, stderr, calls = self._run(up_exception=True)
        self.assertEqual((result, stdout, stderr), (75, "", PARTIAL))
        self.assertEqual(sum(call[0][-1:] == ("--wait",) for call in calls), 1)
        self.assertNotIn("untrusted", stderr)

    def test_hostile_ipam_overlay_never_reaches_config_or_up(self) -> None:
        self.ipam.write_text(
            "services:\n  api:\n    command: [hostile]\n",
            encoding="ascii",
        )
        self.ipam.chmod(0o600)
        calls = []
        stdout = io.StringIO()
        stderr = io.StringIO()
        result = self.module.main(
            self._argv(),
            stdout=stdout,
            stderr=stderr,
            platform_name="linux",
            command_runner=lambda command, environment: calls.append(command),
            environ={},
            attempts_root=self._new_attempts_root(),
        )
        self.assertEqual(
            (result, stdout.getvalue(), stderr.getvalue()),
            (78, "", BLOCKED),
        )
        self.assertEqual(calls, [])

    def _assert_inputs_block_before_commands(self) -> None:
        calls = []
        stdout = io.StringIO()
        stderr = io.StringIO()
        result = self.module.main(
            self._argv(),
            stdout=stdout,
            stderr=stderr,
            platform_name="linux",
            command_runner=lambda command, environment: calls.append(command),
            environ={},
            attempts_root=self._new_attempts_root(),
        )
        self.assertEqual(
            (result, stdout.getvalue(), stderr.getvalue()),
            (78, "", BLOCKED),
        )
        self.assertEqual(calls, [])

    def test_input_mode_symlink_hardlink_and_v13_content_are_closed(self) -> None:
        self.env_file.chmod(0o644)
        self._assert_inputs_block_before_commands()

        self.env_file.chmod(0o600)
        alias = self.ipam.parent / "ipam-hardlink"
        os.link(self.ipam, alias)
        self._assert_inputs_block_before_commands()
        alias.unlink()

        original = self.ipam.read_bytes()
        target = self.ipam.parent / "ipam-target"
        target.write_bytes(original)
        target.chmod(0o600)
        self.ipam.unlink()
        self.ipam.symlink_to(target)
        self._assert_inputs_block_before_commands()

    def test_v13_env_and_frozen_cidr_are_closed_before_commands(self) -> None:
        value = self.env_file.read_text(encoding="ascii")
        self.env_file.write_text(
            value.replace("DESIRE_IMAGE_TAG=immutable", "DESIRE_IMAGE_TAG=v13"),
            encoding="ascii",
        )
        self.env_file.chmod(0o600)
        self._assert_inputs_block_before_commands()

        self.env_file.write_text(value, encoding="ascii")
        self.env_file.chmod(0o600)
        ipam = self.ipam.read_text(encoding="ascii")
        self.ipam.write_text(
            ipam.replace("10.240.1.0/24", "172.16.232.0/24"),
            encoding="ascii",
        )
        self.ipam.chmod(0o600)
        self._assert_inputs_block_before_commands()

    def test_dotenv_paths_are_exact_canonical_preparer_bytes(self) -> None:
        root = Path("/tmp/${A:-v}${B:-13}")
        raw = (
            "DESIRE_IMAGE_TAG=immutable\n"
            f"DESIRE_DB_PASSWORD_FILE={root}/db_superuser_password.txt\n"
            "DESIRE_TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE="
            f"{root}/taxonomy_seed_workload_credential\n"
            "DESIRE_TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE="
            f"{root}/taxonomy_seed_receipt_hmac_key\n"
            f"DESIRE_IDENTITY_SOURCE_DIR={root}/internal-sandbox-identity-sources\n"
            f"DESIRE_INTERNAL_SANDBOX_TLS_DIR={root}/internal-sandbox-tls\n"
            "DESIRE_INTERNAL_SANDBOX_BUNDLE_DIR="
            f"{root}/internal-sandbox-bundle-private\n"
        ).encode("ascii")
        with self.assertRaises(self.module.PrivateServerIngressActivationError):
            self.module._validate_env_bytes(raw, root=root)

    def test_static_compose_sources_are_hash_pinned(self) -> None:
        for path, expected in self.module._STATIC_SOURCE_DIGESTS.items():
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected)

    def test_project_coordinate_is_closed_and_fresh_only(self) -> None:
        hostile = (
            "desire-supply",
            "desire-supply-e2e-ten-account-v13",
            "desire-private-ingress-v13-new",
            "desire-private-ingress-Upper",
            "desire-private-ingress-../../escape",
        )
        for project in hostile:
            with self.subTest(project=project):
                calls = []
                stdout = io.StringIO()
                stderr = io.StringIO()
                result = self.module.main(
                    self._argv(project),
                    stdout=stdout,
                    stderr=stderr,
                    platform_name="linux",
                    command_runner=lambda command, environment: calls.append(command),
                    environ={},
                )
                self.assertEqual(
                    (result, stdout.getvalue(), stderr.getvalue()),
                    (78, "", BLOCKED),
                )
                self.assertEqual(calls, [])

    def test_runbook_exposes_only_the_fresh_atomic_activator(self) -> None:
        text = RUNBOOK.read_text(encoding="utf-8")
        self.assertIn("activate_private_server_ingress.py", text)
        self.assertIn("fresh activate", text)
        self.assertIn("不是 restart", text)
        self.assertIn("/usr/bin/python3 -I -B", text)
        self.assertIn("Docker Compose `5.3.1`", text)
        self.assertIn("PRIVATE_SERVER_INGRESS_PARTIAL_POSSIBLE", text)
        self.assertIn("/var/lib/desire/private-ingress-attempts", text)
        self.assertIn("每一条\n  Compose 命令调用前后", text)
        self.assertIn("`DOCKER_CONFIG` 必须精确只含 `config.json`", text)
        self.assertIn("/opt/desire-supply", text)
        self.assertIn("不能由待执行的 activator 自证", text)
        self.assertIn("`/usr/bin/python3` 可以是受信任的系统 symlink", text)
        for option in (
            "--platform-image-id",
            "--web-image-id",
            "--edge-image-id",
            "--postgres-image-id",
            "--input-tree-sha256",
        ):
            self.assertIn(option, text)
        self.assertIn("private_server_release_inputs.py measure", text)
        self.assertIn("private_server_release_inputs.py verify", text)
        self.assertIn("PRIVATE_SERVER_RELEASE_INPUTS_MEASURED_NOT_AUTHORITY", text)
        self.assertIn("PRIVATE_SERVER_RELEASE_INPUTS_VERIFIED_NOT_AUTHORITY", text)
        self.assertIn("不会占用 project/attempt", text)
        self.assertNotIn("docker compose up", text)


if __name__ == "__main__":
    unittest.main()
