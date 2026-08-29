"""Closed fake-daemon contracts for activated private ingress lifecycle control."""

from __future__ import annotations

import hashlib
import importlib.util
import ipaddress
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "manage_private_server_ingress.py"
PROJECT = "desire-private-ingress-20260824-a1"
BIND_IP = "10.23.4.15"
IMAGES = {
    "platform": "sha256:" + "1" * 64,
    "web": "sha256:" + "2" * 64,
    "edge": "sha256:" + "3" * 64,
    "postgres": "sha256:" + "4" * 64,
}


def _load_module():
    spec = importlib.util.spec_from_file_location("manage_private_server_ingress", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("management module cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write(path: Path, value: bytes, mode: int) -> None:
    path.write_bytes(value)
    path.chmod(mode)


def _canonical(value) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii") + b"\n"


class PrivateServerManagementTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = _load_module()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.attempts = Path(self.temporary.name).resolve(strict=True)
        self.attempts.chmod(0o700)
        self.attempt = self.attempts / PROJECT
        self.attempt.mkdir(mode=0o700)
        self.container_ids = {
            name: f"{index:x}" * 64
            for index, name in enumerate(self.module._SERVICES, start=1)
        }
        self.config_hashes = {
            name: hashlib.sha256(f"config:{name}".encode("ascii")).hexdigest()
            for name in self.module._SERVICES
        }
        self.network_ids = {
            name: f"{index:x}" * 64
            for index, name in enumerate(self.module._NETWORKS, start=11)
        }
        self.missing_service = None
        self.missing_resource = None
        self.drift_service = None
        self.identity_drift = None
        self.attachment_network_drift = None
        self.port_drift = None
        self.security_drift = None
        self.internal_drift = False
        self.listener_drift = None
        self.rogue_resource = None
        self.config = self._build_attempt()
        self.states = {name: "running" for name in self.module._PERSISTENT}
        self.health = {name: "healthy" for name in self.module._PERSISTENT}
        self.calls = []
        self.fail_mutation_number = None
        self.mutation_count = 0
        self.fail_final_inspect = False
        self.full_inspect_count = 0

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _build_attempt(self):
        docker_config = self.attempt / "docker-config"
        docker_config.mkdir(mode=0o700)
        _write(docker_config / "config.json", b"{}\n", 0o600)

        stage = self.attempt / "release-inputs"
        stage.mkdir(mode=0o700)
        identity = stage / "internal-sandbox-identity-sources"
        identity.mkdir(mode=0o755)
        tls = stage / "internal-sandbox-tls"
        tls.mkdir(mode=0o700)
        bundle_name = "internal-sandbox-bundle-private"
        bundle = stage / bundle_name
        bundle.mkdir(mode=0o700)
        config_dir = bundle / "config"
        config_dir.mkdir(mode=0o700)
        secret_dir = bundle / "runtime-secrets"
        secret_dir.mkdir(mode=0o700)

        root_files = (
            "compose.env", "compose.ipam.yaml", "db_superuser_password.txt",
            "taxonomy_seed_workload_credential", "taxonomy_seed_receipt_hmac_key",
            "oidc-client-secret",
        )
        for index, name in enumerate(root_files):
            mode = 0o600 if name in ("compose.env", "compose.ipam.yaml", "oidc-client-secret") else 0o444
            _write(stage / name, f"root-{index}\n".encode("ascii"), mode)
        for index, name in enumerate(sorted(self.module._IDENTITY_FILES)):
            _write(identity / name, f"identity-{index}\n".encode("ascii"), 0o444)
        for index, name in enumerate(("root-ca.pem", "edge-tls-chain.pem", "edge-tls-key.pem")):
            _write(tls / name, f"tls-{index}\n".encode("ascii"), 0o444)
        for index, name in enumerate(self.module._BUNDLE_CONFIG_FILES):
            _write(config_dir / name, f"config-{index}\n".encode("ascii"), 0o444)
        for index, name in enumerate(sorted(self.module._RUNTIME_SECRETS)):
            _write(secret_dir / name, f"secret-{index}\n".encode("ascii"), 0o444)

        config_files = {
            "internal-sandbox-deployment": config_dir / "deployment.json",
            "internal-sandbox-runtime-config": config_dir / "runtime-config.json",
            "internal-sandbox-secret-manifest": config_dir / "secret-manifest.json",
            "internal-sandbox-matching-deployment": config_dir / "matching-deployment.json",
            "internal-sandbox-matching-runtime-config": config_dir / "matching-runtime-config.json",
            "internal-sandbox-matching-secret-manifest": config_dir / "matching-secret-manifest.json",
            "internal-sandbox-online-credentials-deployment": config_dir / "online-credentials-deployment.json",
            "internal-sandbox-online-credentials-runtime-config": config_dir / "online-credentials-runtime-config.json",
            "internal-sandbox-online-credentials-secret-manifest": config_dir / "online-credentials-secret-manifest.json",
            "internal-sandbox-identity-template": self.attempt / "internal-sandbox-identity-bootstrap-template-v1.json",
            "internal-sandbox-root-ca": tls / "root-ca.pem",
            "internal-sandbox-edge-tls-chain": tls / "edge-tls-chain.pem",
        }
        secret_files = {
            **{name: secret_dir / name for name in self.module._RUNTIME_SECRETS},
            "db_superuser_password": stage / "db_superuser_password.txt",
            "taxonomy_seed_workload_credential": stage / "taxonomy_seed_workload_credential",
            "taxonomy_seed_receipt_hmac_key": stage / "taxonomy_seed_receipt_hmac_key",
            "edge-tls-key": tls / "edge-tls-key.pem",
        }
        services = {}
        for name in self.module._SERVICES:
            image = IMAGES["platform"]
            if name == "db":
                image = IMAGES["postgres"]
            elif name == "edge":
                image = IMAGES["edge"]
            elif name == "web":
                image = IMAGES["web"]
            service = {
                "image": image,
                "logging": {
                    "driver": "local",
                    "options": {
                        "compress": "true",
                        "max-file": "3",
                        "max-size": "10m",
                    },
                },
                "networks": {network: None for network in self.module._SERVICE_NETWORKS[name]},
            }
            if name == "db":
                service["restart"] = "unless-stopped"
                service["volumes"] = [
                    {
                        "source": "postgres-data",
                        "target": "/var/lib/postgresql/data",
                        "type": "volume",
                    }
                ]
            else:
                service.update(
                    {
                        "cap_drop": ["ALL"],
                        "init": True,
                        "read_only": True,
                        "restart": "no",
                        "security_opt": ["no-new-privileges=true"],
                    }
                )
                if name == "matching-runtime":
                    service["restart"] = "unless-stopped"
            if name in self.module._ONE_SHOTS + ("synthetic-oidc",):
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
                service["command"] = [
                    "python", "-m", "desire_platform.matching.runtime_process",
                ]
            if name in self.module._ONE_SHOTS + ("synthetic-oidc", "api"):
                service["command"] = ["run", name]
            if name in self.module._PERSISTENT:
                service["healthcheck"] = {"test": ["CMD", "health", name]}
            services[name] = service
        services["edge"]["ports"] = [
            {"host_ip": "127.0.0.1", "mode": "ingress", "protocol": "tcp", "published": "443", "target": 443},
            {"host_ip": BIND_IP, "mode": "ingress", "protocol": "tcp", "published": "443", "target": 443},
        ]
        services["identity-bootstrap"]["volumes"] = [
            {"source": str(identity), "target": "/run/identity-sources", "type": "bind"}
        ]
        subnets = {"app": "10.240.3.0/24", "data": "10.240.4.0/24",
                   "ingress": "10.240.1.0/24", "oidc-backend": "10.240.2.0/24"}
        config = {
            "configs": {name: {"file": str(path), "name": f"{PROJECT}_{name}"} for name, path in config_files.items()},
            "name": PROJECT,
            "networks": {
                name: {
                    **({"internal": True} if name in self.module._INTERNAL_NETWORKS else {}),
                    "ipam": {"config": [{"subnet": subnets[name]}]},
                    "name": f"{PROJECT}_{name}",
                }
                for name in self.module._NETWORKS
            },
            "secrets": {name: {"file": str(path), "name": f"{PROJECT}_{name}"} for name, path in secret_files.items()},
            "services": services,
            "volumes": {"postgres-data": {"name": f"{PROJECT}_postgres-data"}},
        }
        self.config = config

        snapshots = {
            "compose.env.snapshot": (stage / "compose.env").read_bytes(),
            "compose.ipam.yaml.snapshot": (stage / "compose.ipam.yaml").read_bytes(),
            "compose.yaml.snapshot": (ROOT / "compose.yaml").read_bytes(),
            "private-server.compose.yaml.snapshot": (ROOT / "deploy/private-server.compose.yaml").read_bytes(),
            "internal-sandbox-identity-bootstrap-template-v1.json": (
                ROOT / "platform/examples/internal-sandbox-identity-bootstrap-template-v1.json"
            ).read_bytes(),
        }
        for name, value in snapshots.items():
            _write(self.attempt / name, value, 0o444 if name.startswith("internal-sandbox-identity") else 0o600)
        resolved = _canonical(config)
        _write(self.attempt / "resolved.compose.json", resolved, 0o600)

        input_sha = self._tree_sha(bundle_name)
        security_projection_sha256 = {
            name: self.module._security_projection_sha256(
                self._security_fields(name)
            )
            for name in self.module._SERVICES
        }
        activation = {
            "bind_ip": BIND_IP,
            "compose_plugin": {
                "path": "/usr/libexec/docker/cli-plugins/docker-compose",
                "sha256": "c" * 64,
                "version": "5.3.1",
            },
            "compose_sha256": hashlib.sha256(resolved).hexdigest(),
            "config_hashes": self.config_hashes,
            "container_ids": self.container_ids,
            "format": "desire-private-ingress-activation-v2",
            "image_ids": IMAGES,
            "input_tree_sha256": input_sha,
            "network_ids": self.network_ids,
            "project": PROJECT,
            "security_projection_sha256": security_projection_sha256,
            "snapshot_sha256": {name: hashlib.sha256(value).hexdigest() for name, value in snapshots.items()},
            "source_sha256": self.module._SOURCE_SHA256,
            "status": "ACTIVATED",
            "volume_name": f"{PROJECT}_postgres-data",
        }
        release = {
            "compose_sha256": activation["compose_sha256"],
            "format": "desire-private-ingress-release-lock-v1",
            "image_ids": sorted(IMAGES.values()),
            "input_tree_sha256": input_sha,
            "project": PROJECT,
        }
        _write(
            self.attempt / "activation.receipt.json",
            (f'{{"format":"desire-private-ingress-attempt-v1","project":"{PROJECT}","status":"CLAIMED"}}\n').encode("ascii"),
            0o600,
        )
        _write(self.attempt / "up-invoked.receipt.json", b'{"status":"UP_INVOKED"}\n', 0o600)
        _write(self.attempt / "activation-complete.receipt.json", _canonical(activation), 0o600)
        _write(self.attempt / "release-lock.receipt.json", _canonical(release), 0o600)
        return config

    def _tree_sha(self, bundle: str) -> str:
        stage = self.attempt / "release-inputs"
        directories = {
            Path("."): 0o700,
            Path("internal-sandbox-identity-sources"): 0o755,
            Path("internal-sandbox-tls"): 0o700,
            Path(bundle): 0o700,
            Path(bundle) / "config": 0o700,
            Path(bundle) / "runtime-secrets": 0o700,
        }
        modes = {}
        for name in (
            "compose.env", "compose.ipam.yaml", "db_superuser_password.txt",
            "taxonomy_seed_workload_credential", "taxonomy_seed_receipt_hmac_key",
            "oidc-client-secret",
        ):
            modes[Path(name)] = 0o600
        for name in self.module._IDENTITY_FILES:
            modes[Path("internal-sandbox-identity-sources") / name] = 0o444
        modes.update({Path("internal-sandbox-tls/root-ca.pem"): 0o444,
                      Path("internal-sandbox-tls/edge-tls-chain.pem"): 0o444,
                      Path("internal-sandbox-tls/edge-tls-key.pem"): 0o400})
        for name in self.module._BUNDLE_CONFIG_FILES:
            modes[Path(bundle) / "config" / name] = 0o600
        for name in self.module._RUNTIME_SECRETS:
            modes[Path(bundle) / "runtime-secrets" / name] = 0o600
        digest = hashlib.sha256(b"desire-private-server-release-input-tree-v1\x00")

        def add(value):
            digest.update(len(value).to_bytes(8, "big")); digest.update(value)

        for relative, mode in sorted(directories.items(), key=lambda item: item[0].as_posix()):
            add(b"D"); add(relative.as_posix().encode()); add(f"{mode:04o}".encode())
        for relative, mode in sorted(modes.items(), key=lambda item: item[0].as_posix()):
            value = (stage / relative).read_bytes()
            add(b"F"); add(relative.as_posix().encode()); add(f"{mode:04o}".encode())
            add(len(value).to_bytes(8, "big")); add(hashlib.sha256(value).digest())
        return digest.hexdigest()

    def _security_fields(self, service: str):
        canonical = self.config["services"][service]
        image = canonical["image"]
        configured_ports = {}
        if service == "edge":
            configured_ports = {"443/tcp": [
                {"HostIp": "127.0.0.1", "HostPort": "443"},
                {"HostIp": BIND_IP, "HostPort": "443"},
            ]}
            if self.port_drift == "missing":
                configured_ports = {}
            elif self.port_drift == "extra":
                configured_ports["8443/tcp"] = [{"HostIp": BIND_IP, "HostPort": "8443"}]
            elif self.port_drift == "duplicate":
                configured_ports["443/tcp"][1] = dict(configured_ports["443/tcp"][0])
            elif self.port_drift == "bad":
                configured_ports["443/tcp"][1] = {"HostIp": "10.23.4.16", "HostPort": "443"}
        labels = {
            "com.docker.compose.config-hash": self.config_hashes[service],
            "com.docker.compose.image": image,
            "com.docker.compose.project": PROJECT,
            "com.docker.compose.service": service,
            "com.docker.compose.container-number": "1",
            "com.docker.compose.oneoff": "False",
            "com.docker.compose.project.config_files": str(self.attempt / "resolved.compose.json"),
            "com.docker.compose.project.working_dir": str(ROOT),
            "com.docker.compose.version": "5.3.1",
        }
        if self.drift_service == service:
            labels["com.docker.compose.project"] = "hostile"
        if self.identity_drift == "config-hash" and service == "api":
            labels["com.docker.compose.config-hash"] = "f" * 64
        environment = ["PATH=/usr/bin"] + [
            f"{key}={value}"
            for key, value in sorted(canonical.get("environment", {}).items())
        ]
        config = {"Env": environment, "Image": image, "Labels": labels}
        if "command" in canonical:
            config["Cmd"] = list(canonical["command"])
        if "healthcheck" in canonical:
            config["Healthcheck"] = {
                "Test": list(canonical["healthcheck"]["test"])
            }
        host_config = {
            "AutoRemove": False,
            "CapAdd": None,
            "CapDrop": canonical.get("cap_drop"),
            "IpcMode": "private",
            "LogConfig": {
                "Type": canonical["logging"]["driver"],
                "Config": dict(canonical["logging"]["options"]),
            },
            "NetworkMode": f"{PROJECT}_{sorted(self.module._SERVICE_NETWORKS[service])[0]}",
            "PidMode": "",
            "PortBindings": configured_ports,
            "Privileged": False,
            "PublishAllPorts": False,
            "ReadonlyRootfs": canonical.get("read_only", False),
            "RestartPolicy": {
                "MaximumRetryCount": 0,
                "Name": canonical.get("restart", "no"),
            },
            "SecurityOpt": (
                ["no-new-privileges:true"]
                if canonical.get("security_opt")
                else None
            ),
            "UTSMode": "",
        }
        mounts = []
        if service == "db":
            mounts.append(
                {
                    "Destination": "/var/lib/postgresql/data",
                    "Name": f"{PROJECT}_postgres-data",
                    "RW": True,
                    "Type": "volume",
                }
            )
        if service == "identity-bootstrap":
            volume = canonical["volumes"][0]
            mounts.append(
                {
                    "Destination": volume["target"],
                    "RW": False,
                    "Source": volume["source"],
                    "Type": "bind",
                }
            )
        if self.security_drift == "restart" and service == "migrate":
            host_config["RestartPolicy"] = {
                "MaximumRetryCount": 0, "Name": "always",
            }
        elif self.security_drift == "privileged" and service == "api":
            host_config["Privileged"] = True
        elif self.security_drift == "host-network" and service == "api":
            host_config["NetworkMode"] = "host"
        elif self.security_drift == "command" and service == "migrate":
            config["Cmd"] = ["admin", "shell"]
        elif self.security_drift == "healthcheck" and service == "api":
            config["Healthcheck"] = {"Test": ["NONE"]}
        elif self.security_drift == "mount" and service == "api":
            mounts.append(
                {
                    "Destination": "/var/run/docker.sock",
                    "RW": True,
                    "Source": "/var/run/docker.sock",
                    "Type": "bind",
                }
            )
        elif self.security_drift == "logging" and service == "api":
            host_config["LogConfig"]["Config"]["max-size"] = "100m"
        return {"Config": config, "HostConfig": host_config, "Mounts": mounts}

    def _container(self, service: str):
        image = self.config["services"][service]["image"]
        running = service in self.module._PERSISTENT and self.states[service] == "running"
        if service in self.module._ONE_SHOTS:
            state = {"Status": "exited", "Running": False, "Paused": False,
                     "Restarting": False, "Dead": False, "ExitCode": 0}
        elif running:
            state = {"Status": "running", "Running": True, "Paused": False,
                     "Restarting": False, "Dead": False, "ExitCode": 0,
                     "Health": {"Status": self.health[service]}}
        else:
            state = {"Status": "exited", "Running": False, "Paused": False,
                     "Restarting": False, "Dead": False, "ExitCode": 0,
                     "Health": {"Status": "healthy"}}
        index = self.module._SERVICES.index(service) + 1
        security = self._security_fields(service)
        ports = None if not running else {}
        if service == "edge" and running:
            configured = security["HostConfig"]["PortBindings"]
            ports = {
                key: [dict(value) for value in bindings]
                for key, bindings in configured.items()
            }
            if self.port_drift == "missing":
                ports = {"8080/tcp": None}
        attachments = {}
        for network_name in self.module._SERVICE_NETWORKS[service]:
            attachment = {"NetworkID": self.network_ids[network_name]}
            if (
                self.attachment_network_drift == (service, network_name)
            ):
                attachment["NetworkID"] = "f" * 64
            if running:
                subnet = self.config["networks"][network_name]["ipam"]["config"][0]["subnet"]
                network = ipaddress.ip_network(subnet)
                attachment.update(
                    {
                        "EndpointID": hashlib.sha256(
                            f"endpoint:{service}:{network_name}".encode("ascii")
                        ).hexdigest(),
                        "IPAddress": str(network.network_address + index + 10),
                        "IPPrefixLen": network.prefixlen,
                    }
                )
            else:
                attachment.update({"EndpointID": "", "IPAddress": "", "IPPrefixLen": 0})
            attachments[f"{PROJECT}_{network_name}"] = attachment
        identifier = self.container_ids[service]
        if self.identity_drift == "container-id" and service == "api":
            identifier = "f" * 64
        return {
            "Id": identifier,
            "Name": f"/{PROJECT}-{service}-1",
            "Image": image,
            "Config": security["Config"],
            "HostConfig": security["HostConfig"],
            "State": state,
            "NetworkSettings": {
                "Networks": attachments,
                "Ports": ports,
            },
            "Mounts": security["Mounts"],
        }

    def _runner(self, command, environment):
        command = tuple(command)
        self.calls.append((command, dict(environment)))
        docker = ("/usr/bin/docker", "--host", "unix:///var/run/docker.sock")
        if command == docker + ("compose", "version", "--short"):
            return subprocess.CompletedProcess(command, 0, stdout="5.3.1\n", stderr="")
        if command[3:5] == ("image", "inspect"):
            if self.missing_resource == "image":
                return subprocess.CompletedProcess(command, 1, stdout="", stderr="missing")
            return subprocess.CompletedProcess(command, 0, stdout=command[-1] + "\n", stderr="")
        if command[3:5] == ("container", "inspect"):
            if "--format" in command:
                identifiers = command[command.index("--format") + 2:]
                lines = []
                for identifier in identifiers:
                    known = next(
                        (
                            name for name in self.module._SERVICES
                            if self._container(name)["Id"] == identifier
                        ),
                        None,
                    )
                    if known is not None:
                        container = self._container(known)
                        networks = container["NetworkSettings"]["Networks"]
                        mounts = container["Mounts"]
                    elif self.rogue_resource == "network-consumer":
                        networks = {f"{PROJECT}_data": {}}
                        mounts = []
                    elif self.rogue_resource == "volume-consumer":
                        networks = {}
                        mounts = [{"Type": "volume", "Name": f"{PROJECT}_postgres-data"}]
                    else:
                        networks = {}
                        mounts = []
                    lines.append(json.dumps({"Id": identifier, "Mounts": mounts, "Networks": networks}))
                return subprocess.CompletedProcess(
                    command, 0, stdout="\n".join(lines) + "\n", stderr=""
                )
            if len(command) == 6 and self.module._CONTAINER_ID.fullmatch(command[-1]) is not None:
                service = next(
                    name for name in self.module._PERSISTENT
                    if self._container(name)["Id"] == command[-1]
                )
                return subprocess.CompletedProcess(
                    command, 0, stdout=json.dumps([self._container(service)]), stderr=""
                )
            self.full_inspect_count += 1
            if self.fail_final_inspect and self.full_inspect_count > 1:
                return subprocess.CompletedProcess(command, 1, stdout="unknown", stderr="unknown")
            values = [self._container(name) for name in self.module._SERVICES if name != self.missing_service]
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps(values), stderr="")
        if command[3:5] == ("network", "inspect"):
            values = []
            for index, name in enumerate(self.module._NETWORKS, start=11):
                if self.missing_resource == "network" and name == "ingress":
                    continue
                subnet = self.config["networks"][name]["ipam"]["config"][0]["subnet"]
                values.append({
                    "Id": self.network_ids[name], "Name": f"{PROJECT}_{name}",
                    "Driver": "bridge", "Scope": "local",
                    "Internal": (
                        int(name in self.module._INTERNAL_NETWORKS)
                        if self.internal_drift
                        else name in self.module._INTERNAL_NETWORKS
                    ),
                    "IPAM": {"Config": [{"Subnet": subnet, "Gateway": subnet.replace("0/24", "1")} ]},
                    "Labels": {"com.docker.compose.project": PROJECT,
                               "com.docker.compose.network": name},
                })
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps(values), stderr="")
        if command[3:5] == ("volume", "inspect"):
            value = [] if self.missing_resource == "volume" else [{"Name": f"{PROJECT}_postgres-data", "Driver": "local", "Scope": "local",
                      "Labels": {"com.docker.compose.project": PROJECT,
                                 "com.docker.compose.volume": "postgres-data"}}]
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps(value), stderr="")
        if command[3:5] == ("container", "ls"):
            if "--quiet" in command:
                self.assertNotIn("--filter", command)
                identifiers = [self._container(name)["Id"] for name in self.module._SERVICES]
                if self.rogue_resource in ("container", "network-consumer", "volume-consumer"):
                    identifiers.append("f" * 64)
                return subprocess.CompletedProcess(
                    command, 0, stdout="\n".join(identifiers) + "\n", stderr=""
                )
            rows = [
                f'{self._container(name)["Id"]} {PROJECT}-{name}-1'
                for name in self.module._SERVICES
            ]
            if self.rogue_resource == "container":
                rows.append(f'{"f" * 64} {PROJECT}-rogue-1')
            return subprocess.CompletedProcess(command, 0, stdout="\n".join(rows) + "\n", stderr="")
        if command[3:5] == ("network", "ls"):
            rows = [f'{self.network_ids[name]} {PROJECT}_{name}'
                    for name in self.module._NETWORKS]
            if self.rogue_resource == "network":
                rows.append(f'{"f" * 64} {PROJECT}_rogue')
            return subprocess.CompletedProcess(command, 0, stdout="\n".join(rows) + "\n", stderr="")
        if command[3:5] == ("volume", "ls"):
            rows = [f"{PROJECT}_postgres-data"]
            if self.rogue_resource == "volume":
                rows.append(f"{PROJECT}_rogue")
            return subprocess.CompletedProcess(command, 0, stdout="\n".join(rows) + "\n", stderr="")
        if command == ("/usr/bin/ss", "-H", "-ltn"):
            output = ""
            if self.states["edge"] == "running":
                output = (
                    "LISTEN 0 4096 127.0.0.1:443 0.0.0.0:*\n"
                    f"LISTEN 0 4096 {BIND_IP}:443 0.0.0.0:*\n"
                )
                if self.listener_drift == "missing-loopback":
                    output = f"LISTEN 0 4096 {BIND_IP}:443 0.0.0.0:*\n"
                elif self.listener_drift == "missing-target":
                    output = "LISTEN 0 4096 127.0.0.1:443 0.0.0.0:*\n"
                elif self.listener_drift == "duplicate":
                    output += f"LISTEN 0 4096 {BIND_IP}:443 0.0.0.0:*\n"
                elif self.listener_drift == "wildcard":
                    output += "LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*\n"
                elif self.listener_drift == "third-concrete":
                    output += "LISTEN 0 4096 10.23.4.99:443 0.0.0.0:*\n"
            return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")
        if command[3:5] == ("container", "start"):
            self.mutation_count += 1
            identifier = command[-1]
            service = next(
                name for name in self.module._PERSISTENT
                if self._container(name)["Id"] == identifier
            )
            if self.fail_mutation_number == self.mutation_count:
                return subprocess.CompletedProcess(command, 1, stdout="unknown", stderr="unknown")
            self.states[service] = "running"
            self.health[service] = "healthy"
            return subprocess.CompletedProcess(command, 0, stdout=identifier + "\n", stderr="")
        if command[3:5] == ("container", "stop"):
            self.mutation_count += 1
            identifier = command[-1]
            service = next(
                name for name in self.module._PERSISTENT
                if self._container(name)["Id"] == identifier
            )
            if self.fail_mutation_number == self.mutation_count:
                return subprocess.CompletedProcess(command, 1, stdout="unknown", stderr="unknown")
            self.states[service] = "exited"
            return subprocess.CompletedProcess(command, 0, stdout=identifier + "\n", stderr="")
        self.fail(f"unexpected command: {command!r}")

    def _main(self, action: str):
        stdout = io.StringIO()
        stderr = io.StringIO()
        result = self.module.main(
            [action, "--project-name", PROJECT], stdout=stdout, stderr=stderr,
            platform_name="linux", command_runner=self._runner, attempts_root=self.attempts,
        )
        return result, stdout.getvalue(), stderr.getvalue()

    def _assert_attempt_unlocked(self) -> None:
        for path in (self.attempts, self.attempt):
            descriptor = os.open(path, os.O_RDONLY)
            try:
                self.module.fcntl.flock(
                    descriptor,
                    self.module.fcntl.LOCK_EX | self.module.fcntl.LOCK_NB,
                )
                self.module.fcntl.flock(descriptor, self.module.fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def test_status_is_strictly_read_only_and_healthy(self) -> None:
        self.assertEqual(self._main("status"), (0, self.module.HEALTHY, ""))
        commands = [command for command, _ in self.calls]
        docker = ("/usr/bin/docker", "--host", "unix:///var/run/docker.sock")
        self.assertEqual(
            commands,
            [docker + ("image", "inspect", "--format", "{{.Id}}", image_id)
               for image_id in sorted(IMAGES.values())]
            + [docker + ("container", "inspect")
               + tuple(f"{PROJECT}-{name}-1" for name in self.module._SERVICES)]
            + [docker + ("network", "inspect")
               + tuple(f"{PROJECT}_{name}" for name in self.module._NETWORKS)]
            + [docker + ("volume", "inspect", f"{PROJECT}_postgres-data")]
            + [docker + ("container", "ls", "--all", "--no-trunc", "--filter",
                         f"label=com.docker.compose.project={PROJECT}",
                         "--format", "{{.ID}} {{.Names}}")]
            + [docker + ("network", "ls", "--no-trunc", "--filter",
                         f"label=com.docker.compose.project={PROJECT}",
                         "--format", "{{.ID}} {{.Name}}")]
            + [docker + ("volume", "ls", "--filter",
                         f"label=com.docker.compose.project={PROJECT}",
                         "--format", "{{.Name}}")]
            + [docker + ("container", "ls", "--all", "--no-trunc", "--quiet")]
            + [docker + ("container", "inspect", "--format", self.module._CONSUMER_FORMAT)
               + tuple(sorted(self._container(name)["Id"] for name in self.module._SERVICES))]
            + [("/usr/bin/ss", "-H", "-ltn")],
        )
        self.assertFalse(any("up" in command or "start" in command or "stop" in command or "down" in command for command in commands))
        expected_environment = {
            "PATH": "/usr/sbin:/usr/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "DOCKER_HOST": "unix:///var/run/docker.sock",
            "DOCKER_CONFIG": str(self.attempt / "docker-config"),
            "COMPOSE_DISABLE_ENV_FILE": "true", "DESIRE_PRIVATE_INGRESS_IP": BIND_IP,
        }
        self.assertTrue(all(environment == expected_environment for _, environment in self.calls))

    def test_status_reports_stopped_recoverable_and_degraded_without_mutation(self) -> None:
        for name in self.module._PERSISTENT:
            self.states[name] = "exited"
        self.assertEqual(self._main("status"), (0, self.module.STOPPED, ""))
        self.calls.clear()
        self.states["db"] = "running"
        self.assertEqual(self._main("status"), (0, self.module.RECOVERABLE, ""))
        self.calls.clear()
        self.states["synthetic-oidc"] = "running"
        self.health["synthetic-oidc"] = "unhealthy"
        self.assertEqual(self._main("status"), (0, self.module.DEGRADED, ""))
        self.assertFalse(any("up" in command or "start" in command or "stop" in command for command, _ in self.calls))

    def test_recover_uses_exact_dependency_order_and_never_runs_one_shots(self) -> None:
        for name in self.module._PERSISTENT:
            self.states[name] = "exited"
        self.assertEqual(self._main("recover"), (0, self.module.RECOVERED, ""))
        mutations = [command for command, _ in self.calls if command[3:5] == ("container", "start")]
        self.assertEqual(
            mutations,
            [(
                "/usr/bin/docker", "--host", "unix:///var/run/docker.sock",
                "container", "start", f"{self.module._SERVICES.index(name) + 1:x}" * 64,
            ) for name in self.module._PERSISTENT],
        )
        self.assertFalse(any(name in command for command in mutations for name in self.module._ONE_SHOTS))

    def test_stop_uses_exact_reverse_order_ids_without_removal(self) -> None:
        self.assertEqual(self._main("stop"), (0, self.module.STOPPED, ""))
        mutations = [command for command, _ in self.calls if command[3:5] == ("container", "stop")]
        expected = []
        for service in self.module._STOP_ORDER:
            expected.append((
                "/usr/bin/docker", "--host", "unix:///var/run/docker.sock",
                "container", "stop", "--timeout", str(self.module._STOP_SECONDS[service]),
                f"{self.module._SERVICES.index(service) + 1:x}" * 64,
            ))
        self.assertEqual(mutations, expected)
        self.assertFalse(any(any(token in command for token in ("down", "rm", "remove", "prune")) for command in mutations))

    def test_missing_drift_or_failed_one_shot_blocks_before_mutation(self) -> None:
        for mode in ("missing", "drift", "one-shot"):
            with self.subTest(mode=mode):
                self.calls.clear()
                self.missing_service = "api" if mode == "missing" else None
                self.drift_service = "api" if mode == "drift" else None
                original = self._container
                if mode == "one-shot":
                    def failed(service):
                        item = original(service)
                        if service == "migrate":
                            item["State"]["ExitCode"] = 1
                        return item
                    self._container = failed
                self.assertEqual(self._main("recover"), (78, "", self.module.BLOCKED))
                self.assertFalse(any("up" in command or "start" in command or "stop" in command for command, _ in self.calls))
                self._container = original

        self.missing_service = None
        self.drift_service = None
        for resource in ("image", "network", "volume"):
            with self.subTest(resource=resource):
                self.calls.clear()
                self.missing_resource = resource
                self.assertEqual(self._main("recover"), (78, "", self.module.BLOCKED))
                self.assertFalse(
                    any("start" in command or "stop" in command for command, _ in self.calls)
                )
        self.missing_resource = None

    def test_original_identity_hash_and_network_id_drift_block_before_mutation(self) -> None:
        for drift in ("container-id", "config-hash"):
            with self.subTest(drift=drift):
                self.calls.clear()
                self.identity_drift = drift
                self.assertEqual(
                    self._main("recover"), (78, "", self.module.BLOCKED)
                )
                self.assertFalse(
                    any(
                        command[3:5] in (("container", "start"), ("container", "stop"))
                        for command, _ in self.calls
                    )
                )
        self.identity_drift = None

        self.calls.clear()
        self.attachment_network_drift = ("edge", "ingress")
        self.assertEqual(self._main("recover"), (78, "", self.module.BLOCKED))
        self.assertFalse(
            any(
                command[3:5] in (("container", "start"), ("container", "stop"))
                for command, _ in self.calls
            )
        )
        self.attachment_network_drift = None

    def test_boolean_one_shot_exit_code_blocks_before_mutation(self) -> None:
        original = self._container

        def boolean_exit(service):
            item = original(service)
            if service == "migrate":
                item["State"]["ExitCode"] = False
            return item

        self._container = boolean_exit
        try:
            self.assertEqual(self._main("recover"), (78, "", self.module.BLOCKED))
            self.assertFalse(
                any(
                    command[3:5] in (("container", "start"), ("container", "stop"))
                    for command, _ in self.calls
                )
            )
        finally:
            self._container = original

    def test_critical_projection_or_boolean_network_drift_blocks_before_mutation(self) -> None:
        for drift in (
            "restart", "privileged", "host-network", "command",
            "healthcheck", "mount", "logging",
        ):
            with self.subTest(drift=drift):
                self.calls.clear()
                self.security_drift = drift
                self.assertEqual(
                    self._main("recover"), (78, "", self.module.BLOCKED)
                )
                self.assertFalse(
                    any(
                        command[3:5] in (("container", "start"), ("container", "stop"))
                        for command, _ in self.calls
                    )
                )
        self.security_drift = None

        self.calls.clear()
        self.internal_drift = True
        self.assertEqual(self._main("recover"), (78, "", self.module.BLOCKED))
        self.assertFalse(
            any(
                command[3:5] in (("container", "start"), ("container", "stop"))
                for command, _ in self.calls
            )
        )
        self.internal_drift = False

    def test_security_projection_normalizes_mount_order_but_not_content(self) -> None:
        container = self._security_fields("identity-bootstrap")
        container["Mounts"].append(
            {
                "Destination": "/run/secrets/example",
                "RW": False,
                "Source": "/safe/example",
                "Type": "bind",
            }
        )
        expected = self.module._security_projection_sha256(container)
        container["Mounts"].reverse()
        self.assertEqual(
            self.module._security_projection_sha256(container), expected
        )
        container["Mounts"][0]["Source"] = "/hostile/example"
        self.assertNotEqual(
            self.module._security_projection_sha256(container), expected
        )

    def test_listener_boundary_is_exact_but_allows_unrelated_concrete_ip(self) -> None:
        for drift in (
            "missing-loopback", "missing-target", "duplicate", "wildcard",
        ):
            with self.subTest(drift=drift):
                self.calls.clear()
                self.listener_drift = drift
                self.assertEqual(
                    self._main("status"), (78, "", self.module.BLOCKED)
                )
                self.assertFalse(
                    any(
                        command[3:5] in (("container", "start"), ("container", "stop"))
                        for command, _ in self.calls
                    )
                )
        self.calls.clear()
        self.listener_drift = "third-concrete"
        self.assertEqual(self._main("status"), (0, self.module.HEALTHY, ""))
        self.listener_drift = None

    def test_missing_extra_duplicate_or_bad_edge_binding_blocks_before_mutation(self) -> None:
        for drift in ("missing", "extra", "duplicate", "bad"):
            with self.subTest(drift=drift):
                self.calls.clear()
                self.port_drift = drift
                self.assertEqual(self._main("recover"), (78, "", self.module.BLOCKED))
                self.assertFalse(
                    any("start" in command or "stop" in command for command, _ in self.calls)
                )
        self.port_drift = None

    def test_rogue_resource_or_unlabelled_consumer_blocks_before_mutation(self) -> None:
        for resource in (
            "container", "network", "volume", "network-consumer",
            "volume-consumer",
        ):
            with self.subTest(resource=resource):
                self.calls.clear()
                self.rogue_resource = resource
                self.assertEqual(self._main("recover"), (78, "", self.module.BLOCKED))
                self.assertFalse(
                    any("start" in command or "stop" in command for command, _ in self.calls)
                )
        self.rogue_resource = None

    def test_unknown_recover_result_is_partial_and_stops_sequence(self) -> None:
        for name in self.module._PERSISTENT:
            self.states[name] = "exited"
        self.fail_mutation_number = 1
        self.assertEqual(self._main("recover"), (75, "", self.module.PARTIAL))
        self.assertEqual(sum(command[3:5] == ("container", "start") for command, _ in self.calls), 1)

        self.calls.clear()
        self.mutation_count = 0
        self.fail_mutation_number = 1
        for name in self.module._PERSISTENT:
            self.states[name] = "running"
        self.assertEqual(self._main("stop"), (75, "", self.module.PARTIAL))
        self.assertEqual(sum(command[3:5] == ("container", "stop") for command, _ in self.calls), 1)

    def test_unknown_final_audit_after_mutation_is_partial(self) -> None:
        for name in self.module._PERSISTENT:
            self.states[name] = "exited"
        self.fail_final_inspect = True
        self.assertEqual(self._main("recover"), (75, "", self.module.PARTIAL))
        self.assertEqual(self.full_inspect_count, 2)
        self._assert_attempt_unlocked()

        self.calls.clear()
        self.full_inspect_count = 0
        self.assertEqual(self._main("stop"), (75, "", self.module.PARTIAL))
        self.assertEqual(self.full_inspect_count, 2)
        self._assert_attempt_unlocked()

    def test_receipt_or_staged_tree_tamper_blocks_without_docker(self) -> None:
        for mode in ("receipt", "tree"):
            with self.subTest(mode=mode):
                self.calls.clear()
                if mode == "receipt":
                    receipt = self.attempt / "activation-complete.receipt.json"
                    value = json.loads(receipt.read_text(encoding="ascii"))
                    value["bind_ip"] = "10.23.4.16"
                    _write(receipt, _canonical(value), 0o600)
                else:
                    target = self.attempt / "release-inputs" / "db_superuser_password.txt"
                    target.chmod(0o600)
                    _write(target, b"drift\n", 0o444)
                self.assertEqual(self._main("status"), (78, "", self.module.BLOCKED))
                self.assertEqual(self.calls, [])
                if mode == "receipt":
                    self.temporary.cleanup()
                    self.temporary = tempfile.TemporaryDirectory()
                    self.attempts = Path(self.temporary.name).resolve(strict=True)
                    self.attempts.chmod(0o700)
                    self.attempt = self.attempts / PROJECT
                    self.attempt.mkdir(mode=0o700)
                    self.config = self._build_attempt()

    def test_v1_or_nonclosed_unsafe_receipt_is_rejected_before_docker(self) -> None:
        receipt = self.attempt / "activation-complete.receipt.json"
        original = receipt.read_bytes()
        value = json.loads(original)
        variants = []

        v1 = dict(value)
        v1["format"] = "desire-private-ingress-activation-v1"
        variants.append(_canonical(v1))
        missing = dict(value)
        missing.pop("security_projection_sha256")
        variants.append(_canonical(missing))
        extra = dict(value)
        extra["unexpected"] = True
        variants.append(_canonical(extra))
        bad_digest = json.loads(json.dumps(value))
        bad_digest["security_projection_sha256"]["api"] = "not-a-digest"
        variants.append(_canonical(bad_digest))
        variants.append(
            original.replace(
                b'"status":"ACTIVATED"',
                b'"status":"ACTIVATED","status":"ACTIVATED"',
            )
        )

        for raw in variants:
            with self.subTest(raw=raw[:48]):
                self.calls.clear()
                _write(receipt, raw, 0o600)
                self.assertEqual(
                    self._main("status"), (78, "", self.module.BLOCKED)
                )
                self.assertEqual(self.calls, [])
        _write(receipt, original, 0o600)

        receipt.chmod(0o644)
        self.calls.clear()
        self.assertEqual(self._main("status"), (78, "", self.module.BLOCKED))
        self.assertEqual(self.calls, [])
        receipt.chmod(0o600)

        hardlink = self.attempt / "activation-complete.hardlink"
        os.link(receipt, hardlink)
        self.calls.clear()
        self.assertEqual(self._main("status"), (78, "", self.module.BLOCKED))
        self.assertEqual(self.calls, [])
        hardlink.unlink()

        target = self.attempt / "activation-complete.target"
        receipt.rename(target)
        receipt.symlink_to(target.name)
        self.calls.clear()
        try:
            self.assertEqual(
                self._main("status"), (78, "", self.module.BLOCKED)
            )
            self.assertEqual(self.calls, [])
        finally:
            receipt.unlink()
            target.rename(receipt)

    def test_docker_config_children_and_attempt_path_replacement_fail_closed(self) -> None:
        _write(self.attempt / "docker-config" / "unexpected", b"x\n", 0o600)
        self.assertEqual(self._main("status"), (78, "", self.module.BLOCKED))
        self.assertEqual(self.calls, [])
        (self.attempt / "docker-config" / "unexpected").unlink()

        original_read = self.module._read_relative_file
        swapped = False
        backup = self.attempts / f"{PROJECT}-locked-backup"

        def swap_then_read(root_fd, relative, **arguments):
            nonlocal swapped
            if not swapped:
                swapped = True
                self.attempt.rename(backup)
                shutil.copytree(backup, self.attempt, copy_function=shutil.copy2)
            return original_read(root_fd, relative, **arguments)

        self.calls.clear()
        self.module._read_relative_file = swap_then_read
        try:
            self.assertEqual(self._main("status"), (78, "", self.module.BLOCKED))
            self.assertEqual(self.calls, [])
            self._assert_attempt_unlocked()
        finally:
            self.module._read_relative_file = original_read

    def test_trusted_python_symlink_chain_is_closed(self) -> None:
        root = self.attempts / "trusted-python"
        bin_directory = root / "bin"
        link_directory = root / "links"
        library_directory = root / "lib"
        root.mkdir(mode=0o700)
        bin_directory.mkdir(mode=0o700)
        link_directory.mkdir(mode=0o700)
        library_directory.mkdir(mode=0o700)
        target = library_directory / "python3.14"
        _write(target, b"trusted test interpreter\n", 0o555)
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
        with self.assertRaises(self.module.PrivateServerIngressManagementError):
            self.module._validate_trusted_executable_chain(
                launcher,
                expected_owner=os.geteuid(),
                trusted_root=root,
            )

        link_directory.chmod(0o700)
        target.chmod(0o775)
        with self.assertRaises(self.module.PrivateServerIngressManagementError):
            self.module._validate_trusted_executable_chain(
                launcher,
                expected_owner=os.geteuid(),
                trusted_root=root,
            )


if __name__ == "__main__":
    unittest.main()
