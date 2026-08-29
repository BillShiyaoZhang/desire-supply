"""Focused contracts for the non-destructive local sandbox trial manager."""

from __future__ import annotations

import argparse
from contextlib import ExitStack
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "manage_local_internal_sandbox.py"
RESOURCE_IDS = {
    name: f"{index:064x}"
    for index, name in enumerate(
        (
            "db",
            "synthetic-oidc",
            "edge",
            "matching-runtime",
            "api",
            "web",
            "migrate",
            "taxonomy-seed",
            "online-credentials-reconcile",
            "online-credentials-verify",
            "identity-bootstrap",
        ),
        start=1,
    )
}


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "manage_local_internal_sandbox", SCRIPT
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("local sandbox manager cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _arguments(root: Path, **overrides: str) -> argparse.Namespace:
    values = {
        "root": str(root),
        "project_name": "desire-local-current-trial-01",
        "image_tag": "local-current-trial-01",
        "domain": "example.test",
        "ingress_cidr": "172.28.240.0/24",
        "oidc_cidr": "172.28.241.0/24",
        "app_cidr": "172.28.242.0/24",
        "data_cidr": "172.28.243.0/24",
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def _cli(root: Path, command: str = "prepare") -> list[str]:
    return [
        command,
        "--root",
        str(root),
        "--project-name",
        "desire-local-current-trial-01",
        "--image-tag",
        "local-current-trial-01",
        "--domain",
        "example.test",
        "--ingress-cidr",
        "172.28.240.0/24",
        "--oidc-cidr",
        "172.28.241.0/24",
        "--app-cidr",
        "172.28.242.0/24",
        "--data-cidr",
        "172.28.243.0/24",
    ]


def _completed(command, stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


class LocalInternalSandboxManagerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = _load_module()

    def test_synthetic_chooser_accounts_keep_bootstrap_and_invitee_distinct(
        self,
    ) -> None:
        self.assertEqual(
            self.module.SYNTHETIC_BOOTSTRAP_ACCOUNT_CODES,
            (
                "access_admin_01",
                "appeal_reviewer_01",
                "creator_01",
                "demand_owner_01",
                "finance_operator_01",
                "finance_operator_02",
                "operations_reviewer_01",
                "org_admin_01",
                "trust_officer_01",
                "trust_officer_02",
            ),
        )
        self.assertEqual(
            self.module.SYNTHETIC_PROVIDER_ONLY_ACCOUNT_CODES,
            ("invited_demand_owner_02",),
        )
        self.assertEqual(
            self.module.SYNTHETIC_CHOOSER_ACCOUNT_CODES,
            self.module.SYNTHETIC_BOOTSTRAP_ACCOUNT_CODES
            + self.module.SYNTHETIC_PROVIDER_ONLY_ACCOUNT_CODES,
        )
        self.assertTrue(
            set(self.module.SYNTHETIC_BOOTSTRAP_ACCOUNT_CODES).isdisjoint(
                self.module.SYNTHETIC_PROVIDER_ONLY_ACCOUNT_CODES
            )
        )

    def test_coordinates_are_explicit_private_and_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="desire-local-manager-") as directory:
            parent = Path(directory).resolve()
            coordinates = self.module._coordinates(
                _arguments(parent / "trial"), must_exist=False
            )
            self.assertEqual(coordinates.domain, "example.test")
            self.assertEqual(
                coordinates.bundle_name,
                "internal-sandbox-bundle-local-current-trial-01",
            )
            for mutation in (
                {"domain": "public.example.com"},
                {"oidc_cidr": "172.28.240.0/24"},
                {"data_cidr": "8.8.8.0/24"},
                {"project_name": "../another-project"},
                {"image_tag": "mutable/latest"},
            ):
                with self.subTest(mutation=mutation):
                    with self.assertRaises(
                        self.module.LocalInternalSandboxError
                    ):
                        self.module._coordinates(
                            _arguments(parent / "trial", **mutation),
                            must_exist=False,
                        )

    def test_prepare_never_adopts_or_overwrites_an_existing_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="desire-local-manager-") as directory:
            root = Path(directory).resolve() / "trial"
            root.mkdir(mode=0o700)
            marker = root / "keep"
            marker.write_text("unchanged", encoding="ascii")
            called = False

            def forbidden_runner(*args, **kwargs):
                nonlocal called
                called = True
                raise AssertionError("Docker must not be called")

            stdout = io.StringIO()
            stderr = io.StringIO()
            self.assertEqual(
                self.module.main(
                    _cli(root),
                    stdout=stdout,
                    stderr=stderr,
                    runner=forbidden_runner,
                ),
                78,
            )
            self.assertFalse(called)
            self.assertEqual(marker.read_text(encoding="ascii"), "unchanged")
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(
                stderr.getvalue(),
                '{"code":"LOCAL_INTERNAL_SANDBOX_INVALID","status":"BLOCKED"}\n',
            )

    def test_cidr_preflight_accepts_docker_null_ipam_but_remains_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="desire-local-manager-") as directory:
            coordinates = self.module._coordinates(
                _arguments(Path(directory).resolve() / "trial"),
                must_exist=False,
            )
            runtime = self.module.DockerRuntime(
                "/usr/bin/docker", "default", {}
            )

            def runner_for(documents):
                def runner(command, **kwargs):
                    del kwargs
                    if "inspect" in command:
                        return _completed(command, json.dumps(documents))
                    return _completed(command, "network-one\nnetwork-two\n")

                return runner

            self.module._cidrs_unused(
                runtime,
                coordinates,
                runner=runner_for(
                    [
                        {"IPAM": {"Config": None}},
                        {"IPAM": {"Config": [{"Subnet": "172.20.0.0/16"}]}},
                    ]
                ),
            )
            for documents in (
                [{"IPAM": {"Config": {}}}, {"IPAM": {"Config": None}}],
                [
                    {
                        "IPAM": {
                            "Config": [{"Subnet": coordinates.ingress_cidr}]
                        }
                    },
                    {"IPAM": {"Config": None}},
                ],
            ):
                with self.subTest(documents=documents), self.assertRaises(
                    self.module.LocalInternalSandboxError
                ):
                    self.module._cidrs_unused(
                        runtime,
                        coordinates,
                        runner=runner_for(documents),
                    )

    def test_project_inventory_uses_full_container_and_network_ids(self) -> None:
        with tempfile.TemporaryDirectory(prefix="desire-local-manager-") as directory:
            coordinates = self.module._coordinates(
                _arguments(Path(directory).resolve() / "trial"),
                must_exist=False,
            )
            runtime = self.module.DockerRuntime(
                "/usr/bin/docker", "default", {}
            )
            calls: list[tuple[str, ...]] = []
            container_id = "a" * 64
            network_id = "b" * 64
            volume_name = f"{coordinates.project_name}_postgres-data"

            def runner(command, **kwargs):
                del kwargs
                calls.append(tuple(command))
                if "container" in command:
                    return _completed(command, container_id + "\n")
                if "network" in command:
                    return _completed(command, network_id + "\n")
                return _completed(command, volume_name + "\n")

            self.assertEqual(
                self.module._project_inventory(
                    runtime,
                    coordinates,
                    runner=runner,
                ),
                {
                    "containers": frozenset((container_id,)),
                    "networks": frozenset((network_id,)),
                    "volumes": frozenset((volume_name,)),
                },
            )
            self.assertIn("--no-trunc", calls[0])
            self.assertIn("--no-trunc", calls[1])
            self.assertNotIn("--no-trunc", calls[2])

    def test_prepare_helper_chain_reuses_all_four_closed_generators(self) -> None:
        with tempfile.TemporaryDirectory(prefix="desire-local-manager-") as directory:
            coordinates = self.module._coordinates(
                _arguments(Path(directory).resolve() / "trial"),
                must_exist=False,
            )
            calls: list[list[str]] = []

            def runner(command, **kwargs):
                calls.append(command)
                joined = " ".join(command)
                if "prepare_internal_sandbox_inputs.py" in joined:
                    status = "INTERNAL_SANDBOX_INPUTS_CREATED"
                elif "manage_internal_sandbox_tls.py" in joined:
                    status = "INTERNAL_SANDBOX_TLS_CREATED"
                elif "internal_sandbox_bundle" in joined:
                    status = "INTERNAL_SANDBOX_BUNDLE_CREATED"
                elif "prepare_internal_sandbox_compose_inputs.py" in joined:
                    status = "INTERNAL_SANDBOX_COMPOSE_INPUTS_CREATED"
                else:
                    raise AssertionError(joined)
                return _completed(command, json.dumps({"status": status}) + "\n")

            self.module._prepare_helpers(
                coordinates,
                platform_python=str(ROOT / "platform" / ".venv" / "bin" / "python"),
                runner=runner,
            )
            self.assertEqual(len(calls), 4)
            combined = [item for call in calls for item in call]
            self.assertIn("SYSTEM_DNS_SYNTHETIC", combined)
            self.assertIn("https://identity.example.test", combined)
            self.assertIn(
                "https://pilot.example.test/v1/auth/oidc/callback", combined
            )
            self.assertIn("--ingress-subnet", combined)
            self.assertIn("--data-subnet", combined)

    def _valid_config(self, coordinates):
        services = {}
        for service in self.module.SERVICES:
            definition = {
                "logging": {
                    "driver": "local",
                    "options": {
                        "compress": "true",
                        "max-file": "3",
                        "max-size": "10m",
                    },
                },
                "networks": {},
            }
            if service == "db":
                definition.update(
                    {
                        "image": self.module.POSTGRES_IMAGE,
                        "restart": "unless-stopped",
                        "tmpfs": [
                            "/var/lib/postgresql:rw,nosuid,nodev,noexec,size=1m"
                        ],
                        "volumes": [
                            {
                                "type": "volume",
                                "source": "postgres-data",
                                "target": "/var/lib/postgresql/data",
                                "volume": {},
                            }
                        ],
                    }
                )
            else:
                definition.update(
                    {
                        "cap_drop": ["ALL"],
                        "init": True,
                        "read_only": True,
                        "restart": "no",
                        "security_opt": ["no-new-privileges=true"],
                        "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=64m"],
                    }
                )
                if service == "matching-runtime":
                    definition["restart"] = "unless-stopped"
            if service not in {"db", "web", "edge"}:
                definition["command"] = self.module.EXPECTED_COMMANDS[service]
            if service in {
                "migrate",
                "taxonomy-seed",
                "online-credentials-reconcile",
                "online-credentials-verify",
                "identity-bootstrap",
                "synthetic-oidc",
            }:
                definition["environment"] = {
                    "DESIRE_DEPLOYMENT_MODE": "INTERNAL_SANDBOX",
                    "DESIRE_EXTERNAL_PARTICIPANTS_ENABLED": "false",
                }
            if service == "matching-runtime":
                definition["environment"] = {
                    "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE": (
                        "/run/desire/matching-deployment.json"
                    ),
                    "DESIRE_MATCHING_RUNTIME_HEALTH_FILE": (
                        "/run/matching-runtime/healthy"
                    ),
                }
            if service not in {"db", "web", "edge"}:
                definition["image"] = (
                    f"desire-supply-platform:{coordinates.image_tag}"
                )
            elif service == "web":
                definition["image"] = f"desire-supply-web:{coordinates.image_tag}"
            elif service == "edge":
                definition["image"] = f"desire-supply-edge:{coordinates.image_tag}"
            services[service] = definition
        services["identity-bootstrap"]["tmpfs"].append(
            "/run/identity-bootstrap:rw,noexec,nosuid,nodev,size=1m,"
            "uid=10001,gid=10001,mode=0700"
        )
        services["matching-runtime"]["tmpfs"].append(
            "/run/matching-runtime:rw,noexec,nosuid,nodev,size=64k,"
            "uid=10001,gid=10001,mode=0700"
        )
        services["identity-bootstrap"]["volumes"] = [
            {
                "type": "bind",
                "source": str(
                    coordinates.root / "internal-sandbox-identity-sources"
                ),
                "target": "/run/identity-sources",
                "read_only": True,
                "bind": {"create_host_path": False},
            }
        ]
        services["edge"]["ports"] = [
            {
                "mode": "ingress",
                "host_ip": "127.0.0.1",
                "target": 443,
                "published": "443",
                "protocol": "tcp",
            }
        ]
        services["edge"]["networks"] = {
            "app": {"aliases": ["identity.example.test"]},
            "ingress": None,
            "oidc-backend": None,
        }
        networks = {}
        for name, cidr in zip(
            self.module.NETWORKS,
            (
                coordinates.ingress_cidr,
                coordinates.oidc_cidr,
                coordinates.app_cidr,
                coordinates.data_cidr,
            ),
        ):
            networks[name] = {"ipam": {"config": [{"subnet": cidr}]}}
            if name != "ingress":
                networks[name]["internal"] = True
        return {
            "name": coordinates.project_name,
            "networks": networks,
            "services": services,
            "volumes": {
                "postgres-data": {
                    "name": f"{coordinates.project_name}_postgres-data"
                }
            },
        }

    def test_resolved_compose_config_allows_only_loopback_443(self) -> None:
        with tempfile.TemporaryDirectory(prefix="desire-local-manager-") as directory:
            coordinates = self.module._coordinates(
                _arguments(Path(directory).resolve() / "trial"),
                must_exist=False,
            )
            document = self._valid_config(coordinates)
            with mock.patch.object(
                self.module, "_validate_resolved_attachments"
            ):
                self.module._validate_compose_config(document, coordinates)
            document["services"]["edge"]["ports"][0]["host_ip"] = "0.0.0.0"
            with mock.patch.object(
                self.module, "_validate_resolved_attachments"
            ), self.assertRaises(self.module.LocalInternalSandboxError):
                self.module._validate_compose_config(document, coordinates)

    def test_resolved_compose_rejects_added_capability_and_root_mount(self) -> None:
        with tempfile.TemporaryDirectory(prefix="desire-local-manager-") as directory:
            coordinates = self.module._coordinates(
                _arguments(Path(directory).resolve() / "trial"),
                must_exist=False,
            )
            for mutation in ("capability", "root-mount"):
                document = self._valid_config(coordinates)
                if mutation == "capability":
                    document["services"]["api"]["cap_add"] = ["SYS_ADMIN"]
                else:
                    document["services"]["api"]["volumes"] = [
                        {
                            "type": "bind",
                            "source": "/",
                            "target": "/host",
                        }
                    ]
                with self.subTest(mutation=mutation), mock.patch.object(
                    self.module, "_validate_resolved_attachments"
                ), self.assertRaises(self.module.LocalInternalSandboxError):
                    self.module._validate_compose_config(document, coordinates)

    def test_resolved_compose_rejects_missing_or_drifted_logging(self) -> None:
        with tempfile.TemporaryDirectory(prefix="desire-local-manager-") as directory:
            coordinates = self.module._coordinates(
                _arguments(Path(directory).resolve() / "trial"),
                must_exist=False,
            )
            mutations = (
                lambda value: value.pop("logging"),
                lambda value: value["logging"].update(driver="json-file"),
                lambda value: value["logging"]["options"].update(
                    {"max-size": "100m"}
                ),
                lambda value: value["logging"]["options"].update(
                    {"max-file": 3}
                ),
                lambda value: value["logging"]["options"].update(
                    {"compress": "false"}
                ),
            )
            for mutate in mutations:
                document = self._valid_config(coordinates)
                mutate(document["services"]["api"])
                with self.subTest(mutation=mutate), mock.patch.object(
                    self.module, "_validate_resolved_attachments"
                ), self.assertRaises(self.module.LocalInternalSandboxError):
                    self.module._validate_compose_config(document, coordinates)

    def test_generated_bundle_is_pinned_to_the_synthetic_browser_client(self) -> None:
        with tempfile.TemporaryDirectory(prefix="desire-local-manager-") as directory:
            coordinates = self.module._coordinates(
                _arguments(Path(directory).resolve() / "trial"),
                must_exist=False,
            )
            document = {
                "bind": {"host": "0.0.0.0", "port": 8000},
                "deployment_mode": "INTERNAL_SANDBOX",
                "external_participants_enabled": False,
                "internal_bff_origin": "http://api:8000",
                "oidc": {
                    "allowed_signing_algorithms": ["RS256"],
                    "client_id": "desire-internal-sandbox",
                    "client_secret_key_id": "oidc-client-secret-v1",
                    "clock_skew_seconds": 30,
                    "issuer": "https://identity.example.test",
                    "maximum_response_bytes": 262144,
                    "metadata_ttl_seconds": 300,
                    "network_binding": {
                        "mode": "SYSTEM_DNS_SYNTHETIC",
                        "pinned_public_ipv4": None,
                    },
                    "redirect_uri": (
                        "https://pilot.example.test/v1/auth/oidc/callback"
                    ),
                    "request_timeout_seconds": 3,
                    "subject_digest_key_id": "oidc-subject-digest-v1",
                },
                "postgres": {
                    "database": "desire",
                    "host": "db",
                    "port": 5432,
                    "transport_security": "TRUSTED_CONTAINER_NETWORK",
                },
                "runtime_config_path": "/run/desire/runtime-config.json",
                "schema_name": "desire-internal-sandbox-deployment-v1",
                "secret_manifest_path": "/run/desire/secret-manifest.json",
                "secret_root": "/run/secrets",
                "system_actor_id": "50000000-0000-4000-8000-000000000002",
            }
            self.module._validate_deployment_document(document, coordinates)
            document["oidc"]["client_id"] = "desire-internal-pilot"
            with self.assertRaises(self.module.LocalInternalSandboxError):
                self.module._validate_deployment_document(document, coordinates)

    def test_browser_readiness_checks_api_discovery_jwks_and_homepage(self) -> None:
        with tempfile.TemporaryDirectory(prefix="desire-local-manager-") as directory:
            coordinates = self.module._coordinates(
                _arguments(Path(directory).resolve() / "trial"),
                must_exist=False,
            )
            runtime = self.module.DockerRuntime(
                "/usr/bin/docker", "default", {}
            )
            api_health = {
                "deployment_mode": "INTERNAL_SANDBOX",
                "external_participants": "DISABLED",
                "g1": "NO-GO",
                "g2": "NO-GO",
                "status": "READY",
            }
            issuer = "https://identity.example.test"
            discovery = {
                "authorization_endpoint": issuer + "/authorize",
                "code_challenge_methods_supported": ["S256"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "issuer": issuer,
                "jwks_uri": issuer + "/jwks",
                "response_types_supported": ["code"],
                "scopes_supported": ["openid", "email"],
                "subject_types_supported": ["public"],
                "token_endpoint": issuer + "/token",
                "token_endpoint_auth_methods_supported": [
                    "client_secret_post"
                ],
            }
            jwks = {
                "keys": [
                    {
                        "alg": "RS256",
                        "e": "AQAB",
                        "kid": "internal-sandbox-synthetic-rs256-v1",
                        "kty": "RSA",
                        "n": "a" * 342,
                        "use": "sig",
                    }
                ]
            }
            with ExitStack() as stack:
                stack.enter_context(
                    mock.patch.object(
                        self.module,
                        "_docker",
                        return_value=_completed([], json.dumps(api_health)),
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.module,
                        "_https_get",
                        side_effect=(
                            json.dumps(discovery),
                            json.dumps(jwks),
                            "<!DOCTYPE html><html>愿作</html>",
                        ),
                    )
                )
                self.module._browser_auth_readiness(
                    runtime,
                    coordinates,
                    api_container_id="a" * 64,
                    exercise_authorization=False,
                    runner=mock.Mock(),
                )

    def test_authorization_readiness_uses_pinned_client_callback_and_secret_file(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="desire-local-manager-") as directory:
            coordinates = self.module._coordinates(
                _arguments(Path(directory).resolve() / "trial"),
                must_exist=False,
            )
            handle = "h" * 43
            chooser = (
                '<input type="hidden" name="request_handle" value="'
                + handle
                + '">'
                + "".join(
                    '<button type="submit" name="account_code" value="'
                    + code
                    + '">'
                    for code in self.module.SYNTHETIC_CHOOSER_ACCOUNT_CODES
                )
            )
            redirect = (
                "https://pilot.example.test/v1/auth/oidc/callback?code="
                + "c" * 43
                + "&state="
                + "s" * 43
            )
            token = json.dumps(
                {
                    "access_token": "a" * 43,
                    "expires_in": 300,
                    "id_token": "a.b.c",
                    "token_type": "Bearer",
                }
            )
            executed: list[tuple[str, ...]] = []

            def execute(command, **kwargs):
                del kwargs
                executed.append(tuple(command))
                output = redirect if len(executed) == 1 else token
                return _completed(command, output)

            with mock.patch.object(
                self.module, "_https_get", return_value=chooser
            ) as get, mock.patch.object(
                self.module,
                "_curl_executable",
                return_value=("/usr/bin/curl", {}),
            ), mock.patch.object(self.module, "_execute", side_effect=execute):
                self.module._authorization_readiness(
                    coordinates, runner=mock.Mock()
                )
            query = get.call_args.kwargs["query"]
            self.assertIn("client_id=desire-internal-sandbox", query)
            self.assertIn(
                "redirect_uri=https%3A%2F%2Fpilot.example.test%2Fv1%2Fauth%2Foidc%2Fcallback",
                query,
            )
            token_command = executed[1]
            self.assertIn("client_id=desire-internal-sandbox", token_command)
            self.assertIn(
                "client_secret@"
                + str(
                    coordinates.bundle
                    / "runtime-secrets/key-oidc-client-secret-v1"
                ),
                token_command,
            )

    def test_authorization_readiness_rejects_missing_or_twelfth_chooser_account(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="desire-local-manager-") as directory:
            coordinates = self.module._coordinates(
                _arguments(Path(directory).resolve() / "trial"),
                must_exist=False,
            )
            handle = "h" * 43

            def chooser(codes):
                return (
                    '<input type="hidden" name="request_handle" value="'
                    + handle
                    + '">'
                    + "".join(
                        '<button type="submit" name="account_code" value="'
                        + code
                        + '">'
                        for code in codes
                    )
                )

            cases = (
                self.module.SYNTHETIC_BOOTSTRAP_ACCOUNT_CODES,
                self.module.SYNTHETIC_CHOOSER_ACCOUNT_CODES
                + ("arbitrary_account_12",),
            )
            for codes in cases:
                with self.subTest(codes=codes):
                    with mock.patch.object(
                        self.module,
                        "_https_get",
                        return_value=chooser(codes),
                    ), mock.patch.object(
                        self.module, "_execute"
                    ) as execute:
                        with self.assertRaises(
                            self.module.LocalInternalSandboxError
                        ):
                            self.module._authorization_readiness(
                                coordinates, runner=mock.Mock()
                            )
                    execute.assert_not_called()

    def _safe_api_container(self, coordinates):
        image_id = "sha256:" + "d" * 64
        document = {
            "Config": {
                "Cmd": self.module.EXPECTED_COMMANDS["api"],
                "Image": f"desire-supply-platform:{coordinates.image_tag}",
                "Labels": {
                    "com.docker.compose.project": coordinates.project_name,
                    "com.docker.compose.service": "api",
                },
                "User": "10001:10001",
            },
            "HostConfig": {
                "AutoRemove": False,
                "CapAdd": None,
                "CapDrop": ["ALL"],
                "DeviceRequests": None,
                "Devices": None,
                "GroupAdd": None,
                "Init": True,
                "IpcMode": "private",
                "LogConfig": {
                    "Type": "local",
                    "Config": {
                        "compress": "true",
                        "max-file": "3",
                        "max-size": "10m",
                    },
                },
                "NetworkMode": f"{coordinates.project_name}_app",
                "PidMode": "",
                "PortBindings": {},
                "Privileged": False,
                "PublishAllPorts": False,
                "ReadonlyRootfs": True,
                "RestartPolicy": {"MaximumRetryCount": 0, "Name": "no"},
                "SecurityOpt": ["no-new-privileges:true"],
                "UTSMode": "",
                "UsernsMode": "",
            },
            "Image": image_id,
            "Mounts": [],
            "NetworkSettings": {
                "Networks": {
                    f"{coordinates.project_name}_app": {},
                    f"{coordinates.project_name}_data": {},
                }
            },
            "RestartCount": 0,
            "State": {"Health": {"Status": "healthy"}, "Status": "running"},
        }
        return document, image_id

    def test_live_security_rejects_capability_and_writable_root_bind(self) -> None:
        with tempfile.TemporaryDirectory(prefix="desire-local-manager-") as directory:
            coordinates = self.module._coordinates(
                _arguments(Path(directory).resolve() / "trial"),
                must_exist=False,
            )
            document, image_id = self._safe_api_container(coordinates)
            security = self.module._security_projection_sha256(document)
            self.assertEqual(
                self.module._validate_container(
                    document,
                    coordinates=coordinates,
                    service="api",
                    image_id=image_id,
                    expected_security_sha256=security,
                ),
                "RUNNING",
            )
            document["HostConfig"]["CapAdd"] = ["SYS_ADMIN"]
            with self.assertRaises(self.module.LocalInternalSandboxError):
                self.module._validate_container(
                    document,
                    coordinates=coordinates,
                    service="api",
                    image_id=image_id,
                    expected_security_sha256=security,
                )

            document, image_id = self._safe_api_container(coordinates)
            document["HostConfig"]["LogConfig"]["Config"]["max-size"] = "100m"
            security = self.module._security_projection_sha256(document)
            with self.assertRaises(self.module.LocalInternalSandboxError):
                self.module._validate_container(
                    document,
                    coordinates=coordinates,
                    service="api",
                    image_id=image_id,
                    expected_security_sha256=security,
                )

            document, image_id = self._safe_api_container(coordinates)
            security = self.module._security_projection_sha256(document)
            document["State"] = {"ExitCode": 143, "Status": "exited"}
            self.assertEqual(
                self.module._validate_container(
                    document,
                    coordinates=coordinates,
                    service="api",
                    image_id=image_id,
                    expected_security_sha256=security,
                ),
                "STOPPED",
            )
            document["State"] = {"ExitCode": 137, "Status": "exited"}
            with self.assertRaises(self.module.LocalInternalSandboxError):
                self.module._validate_container(
                    document,
                    coordinates=coordinates,
                    service="api",
                    image_id=image_id,
                    expected_security_sha256=security,
                )

    def test_containment_validation_tolerates_unhealthy_and_failed_exit(self) -> None:
        with tempfile.TemporaryDirectory(prefix="desire-local-manager-") as directory:
            coordinates = self.module._coordinates(
                _arguments(Path(directory).resolve() / "trial"),
                must_exist=False,
            )
            document, image_id = self._safe_api_container(coordinates)
            security = self.module._security_projection_sha256(document)
            document["State"]["Health"]["Status"] = "unhealthy"
            self.assertEqual(
                self.module._validate_container(
                    document,
                    coordinates=coordinates,
                    service="api",
                    image_id=image_id,
                    expected_security_sha256=security,
                    strict_state=False,
                ),
                "RUNNING",
            )
            document["State"] = {"ExitCode": 17, "Status": "exited"}
            self.assertEqual(
                self.module._validate_container(
                    document,
                    coordinates=coordinates,
                    service="api",
                    image_id=image_id,
                    expected_security_sha256=security,
                    strict_state=False,
                ),
                "STOPPED",
            )
            document, image_id = self._safe_api_container(coordinates)
            document["Mounts"] = [
                {
                    "Destination": "/host",
                    "RW": True,
                    "Source": "/",
                    "Type": "bind",
                }
            ]
            with self.assertRaises(self.module.LocalInternalSandboxError):
                self.module._validate_container(
                    document,
                    coordinates=coordinates,
                    service="api",
                    image_id=image_id,
                    expected_security_sha256=security,
                )

    def test_one_shot_logs_are_one_line_exact_and_fresh(self) -> None:
        migrations = {
            "catalogs": {
                name: {"applied_versions": [0], "skipped_versions": []}
                for name in self.module.CATALOGS
            },
            "preflights": {
                "iam42_organization_public_name": {
                    "edge_whitespace_count": 0,
                    "forbidden_codepoint_count": 0,
                    "inspected_organization_count": 0,
                    "invalid_organization_count": 0,
                    "length_violation_count": 0,
                    "non_nfc_count": 0,
                    "predicate_version": "iam42-organization-public-name-v1",
                    "relation_state": "ABSENT",
                    "status": "PASSED",
                }
            },
            "status": "SCHEMA_READY",
        }
        valid = {
            "migrate": migrations,
            "taxonomy-seed": {
                "manifest_sha256": "a" * 64,
                "replayed": False,
                "status": "INTERNAL_SANDBOX_TAXONOMY_SEED_READY",
                "taxonomy_bundle_id": "50000000-0000-4000-8000-000000000001",
            },
            "online-credentials-reconcile": {
                "action": "RECONCILE",
                "online_role_count": 19,
                "status": "ONLINE_CREDENTIALS_READY",
            },
            "online-credentials-verify": {
                "action": "VERIFY",
                "online_role_count": 19,
                "status": "ONLINE_CREDENTIALS_READY",
            },
            "identity-bootstrap": {
                "apply_outcome": "APPLIED",
                "manifest_sha256": "b" * 64,
                "status": "IDENTITY_BOOTSTRAP_ORCHESTRATION_READY",
                "verify_outcome": "VERIFIED",
            },
        }
        for service, document in valid.items():
            with self.subTest(service=service):
                self.module._validate_one_shot_log(
                    service,
                    json.dumps(document, separators=(",", ":"), sort_keys=True),
                )
        replayed = dict(valid["taxonomy-seed"])
        replayed["replayed"] = True
        with self.assertRaises(self.module.LocalInternalSandboxError):
            self.module._validate_one_shot_log(
                "taxonomy-seed", json.dumps(replayed)
            )
        with self.assertRaises(self.module.LocalInternalSandboxError):
            self.module._validate_one_shot_log(
                "migrate", json.dumps(migrations) + "\n" + json.dumps(migrations)
            )
        with self.assertRaises(self.module.LocalInternalSandboxError):
            self.module._validate_one_shot_log(
                "migrate", json.dumps(migrations) + "\n\n"
            )
        invalid_preflight = json.loads(json.dumps(migrations))
        invalid_preflight["preflights"]["iam42_organization_public_name"][
            "invalid_organization_count"
        ] = 1
        with self.assertRaises(self.module.LocalInternalSandboxError):
            self.module._validate_one_shot_log(
                "migrate", json.dumps(invalid_preflight)
            )

    def test_start_is_single_use_and_runs_config_build_then_waiting_up(self) -> None:
        with tempfile.TemporaryDirectory(prefix="desire-local-manager-") as directory:
            root = Path(directory).resolve() / "trial"
            root.mkdir(mode=0o700)
            metadata = root / self.module.METADATA_DIRECTORY
            metadata.mkdir(mode=0o700)
            coordinates = self.module.Coordinates(
                root=root,
                project_name="desire-local-current-trial-01",
                image_tag="local-current-trial-01",
                domain="example.test",
                ingress_cidr="172.28.240.0/24",
                oidc_cidr="172.28.241.0/24",
                app_cidr="172.28.242.0/24",
                data_cidr="172.28.243.0/24",
                bundle_name="internal-sandbox-bundle-local-current-trial-01",
                deployment_id="local-desire-local-current-trial-01",
                release_id="local-local-current-trial-01",
            )
            runtime = self.module.DockerRuntime(
                "/usr/bin/docker", "default", {}
            )
            compose_calls: list[tuple[str, ...]] = []

            def compose(*args, **kwargs):
                compose_calls.append(tuple(args[2:]))
                return _completed(args, "")

            capture = {"schema": self.module.RECEIPT_SCHEMA, "status": "STARTED"}
            source_binding = {
                "build_source_sha256": "b" * 64,
                "git": {
                    "diff_sha256": "e" * 64,
                    "dirty": True,
                    "head": "c" * 40,
                    "status_sha256": "d" * 64,
                    "untracked_sha256": "f" * 64,
                },
            }
            with ExitStack() as stack:
                stack.enter_context(
                    mock.patch.object(
                        self.module,
                        "_load_prepared",
                        return_value=(
                            {"source_binding": source_binding},
                            "a" * 64,
                        ),
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.module,
                        "_source_binding",
                        return_value=source_binding,
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.module, "_docker_runtime", return_value=runtime
                    )
                )
                for name in (
                    "_project_unused",
                    "_image_tags_unused",
                    "_cidrs_unused",
                    "_port_unused",
                ):
                    stack.enter_context(mock.patch.object(self.module, name))
                stack.enter_context(
                    mock.patch.object(
                        self.module, "_resolved_config", return_value={}
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.module,
                        "_image_id",
                        return_value="sha256:" + "c" * 64,
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.module, "_compose", side_effect=compose
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.module, "_capture_started", return_value=capture
                    )
                )
                self.assertEqual(
                    self.module.start(
                        coordinates, wait_timeout=123, runner=mock.Mock()
                    ),
                    "LOCAL_INTERNAL_SANDBOX_STARTED",
                )
            self.assertEqual(
                compose_calls,
                [
                    ("build", "api", "web", "edge"),
                    (
                        "up",
                        "--no-build",
                        "--pull",
                        "never",
                        "-d",
                        "--wait",
                        "--wait-timeout",
                        "123",
                    ),
                ],
            )
            self.assertTrue((metadata / self.module.START_ATTEMPT).is_file())
            self.assertTrue((metadata / self.module.START_RECEIPT).is_file())
            with mock.patch.object(
                self.module, "_load_prepared", return_value=({}, "a" * 64)
            ):
                with self.assertRaises(self.module.LocalInternalSandboxError):
                    self.module.start(
                        coordinates, wait_timeout=123, runner=mock.Mock()
                    )

    def test_start_fails_closed_when_build_source_changes_after_prepare(self) -> None:
        with tempfile.TemporaryDirectory(prefix="desire-local-manager-") as directory:
            root = Path(directory).resolve() / "trial"
            root.mkdir(mode=0o700)
            (root / self.module.METADATA_DIRECTORY).mkdir(mode=0o700)
            coordinates = self.module.Coordinates(
                root=root,
                project_name="desire-local-current-trial-01",
                image_tag="local-current-trial-01",
                domain="example.test",
                ingress_cidr="172.28.240.0/24",
                oidc_cidr="172.28.241.0/24",
                app_cidr="172.28.242.0/24",
                data_cidr="172.28.243.0/24",
                bundle_name="internal-sandbox-bundle-local-current-trial-01",
                deployment_id="local-desire-local-current-trial-01",
                release_id="local-local-current-trial-01",
            )
            old_binding = {
                "build_source_sha256": "a" * 64,
                "git": {
                    "diff_sha256": "d" * 64,
                    "dirty": True,
                    "head": "b" * 40,
                    "status_sha256": "c" * 64,
                    "untracked_sha256": "e" * 64,
                },
            }
            changed_binding = {
                **old_binding,
                "build_source_sha256": "d" * 64,
            }
            runtime = self.module.DockerRuntime("/usr/bin/docker", "default", {})
            compose_calls: list[tuple[str, ...]] = []

            def compose(_runtime, _coordinates, *arguments, **kwargs):
                del kwargs
                compose_calls.append(tuple(arguments))
                return _completed(arguments)

            with ExitStack() as stack:
                stack.enter_context(
                    mock.patch.object(
                        self.module,
                        "_load_prepared",
                        return_value=(
                            {"source_binding": old_binding},
                            "e" * 64,
                        ),
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.module, "_docker_runtime", return_value=runtime
                    )
                )
                for name in (
                    "_project_unused",
                    "_image_tags_unused",
                    "_cidrs_unused",
                    "_port_unused",
                ):
                    stack.enter_context(mock.patch.object(self.module, name))
                stack.enter_context(
                    mock.patch.object(
                        self.module, "_resolved_config", return_value={}
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.module,
                        "_application_image_ids",
                        return_value={
                            "platform": "sha256:" + "1" * 64,
                            "web": "sha256:" + "2" * 64,
                            "edge": "sha256:" + "3" * 64,
                        },
                    )
                )
                stack.enter_context(
                    mock.patch.object(self.module, "_compose", side_effect=compose)
                )
                stack.enter_context(
                    mock.patch.object(
                        self.module,
                        "_source_binding",
                        return_value=changed_binding,
                    )
                )
                with self.assertRaisesRegex(
                    self.module.LocalInternalSandboxError,
                    "LOCAL_INTERNAL_SANDBOX_PARTIAL_POSSIBLE",
                ):
                    self.module.start(
                        coordinates, wait_timeout=123, runner=mock.Mock()
                    )
            self.assertEqual(compose_calls, [("build", "api", "web", "edge")])

    def test_stop_and_resume_touch_only_bound_persistent_container_ids(self) -> None:
        with tempfile.TemporaryDirectory(prefix="desire-local-manager-") as directory:
            root = Path(directory).resolve() / "trial"
            root.mkdir(mode=0o700)
            coordinates = self.module.Coordinates(
                root=root,
                project_name="desire-local-current-trial-01",
                image_tag="local-current-trial-01",
                domain="example.test",
                ingress_cidr="172.28.240.0/24",
                oidc_cidr="172.28.241.0/24",
                app_cidr="172.28.242.0/24",
                data_cidr="172.28.243.0/24",
                bundle_name="internal-sandbox-bundle-local-current-trial-01",
                deployment_id="local-desire-local-current-trial-01",
                release_id="local-local-current-trial-01",
            )
            receipt = {
                "container_ids": RESOURCE_IDS,
                "image_ids": {
                    name: "sha256:" + "d" * 64 for name in RESOURCE_IDS
                },
                "security_sha256": {
                    name: "e" * 64 for name in RESOURCE_IDS
                },
            }
            runtime = self.module.DockerRuntime(
                "/usr/bin/docker", "default", {}
            )
            commands: list[tuple[str, ...]] = []

            def docker(_runtime, arguments, **kwargs):
                commands.append(tuple(arguments))
                return _completed(arguments)

            running = {
                name: "RUNNING" for name in self.module.PERSISTENT_SERVICES
            }
            stopped = {
                name: "STOPPED" for name in self.module.PERSISTENT_SERVICES
            }
            common = (
                mock.patch.object(
                    self.module, "_load_prepared", return_value=({}, "a" * 64)
                ),
                mock.patch.object(
                    self.module, "_load_start_receipt", return_value=receipt
                ),
                mock.patch.object(
                    self.module, "_docker_runtime", return_value=runtime
                ),
                mock.patch.object(self.module, "_docker", side_effect=docker),
            )
            with common[0], common[1], common[2], common[3], mock.patch.object(
                self.module,
                "_containment_state",
                side_effect=(("ACTIVE", running), ("STOPPED", stopped)),
            ):
                self.assertEqual(
                    self.module.stop(coordinates, runner=mock.Mock()),
                    "LOCAL_INTERNAL_SANDBOX_STOPPED",
                )
            self.assertEqual(
                [command[-1] for command in commands],
                [RESOURCE_IDS[name] for name in self.module.STOP_ORDER],
            )
            self.assertTrue(
                all(command[:2] == ("container", "stop") for command in commands)
            )
            commands.clear()
            with ExitStack() as stack:
                stack.enter_context(
                    mock.patch.object(
                        self.module,
                        "_load_prepared",
                        return_value=({}, "a" * 64),
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.module, "_load_start_receipt", return_value=receipt
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.module, "_docker_runtime", return_value=runtime
                    )
                )
                stack.enter_context(
                    mock.patch.object(self.module, "_docker", side_effect=docker)
                )
                stack.enter_context(
                    mock.patch.object(self.module, "_port_unused")
                )
                stack.enter_context(
                    mock.patch.object(self.module, "_wait_healthy")
                )
                stack.enter_context(
                    mock.patch.object(
                        self.module,
                        "_live_state",
                        side_effect=(("STOPPED", stopped), ("HEALTHY", running)),
                    )
                )
                self.assertEqual(
                    self.module.resume(
                        coordinates, wait_timeout=120, runner=mock.Mock()
                    ),
                    "LOCAL_INTERNAL_SANDBOX_RESUMED",
                )
            self.assertEqual(
                commands,
                [
                    ("container", "start", RESOURCE_IDS[name])
                    for name in self.module.PERSISTENT_SERVICES
                ],
            )
            self.assertTrue(
                set(RESOURCE_IDS[name] for name in self.module.ONE_SHOT_SERVICES)
                .isdisjoint(command[-1] for command in commands)
            )


if __name__ == "__main__":
    unittest.main()
