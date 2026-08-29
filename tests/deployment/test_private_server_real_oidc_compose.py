from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/private_server_real_oidc_compose_contract.py"
SPEC = importlib.util.spec_from_file_location(
    "private_server_real_oidc_compose_contract", SCRIPT
)
assert SPEC is not None and SPEC.loader is not None
contract = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = contract
SPEC.loader.exec_module(contract)


PROJECT = "desire-real-oidc-contract01"
PILOT_HOST = "pilot.example.org"
ISSUER = "https://login.example.org/tenant"
CLIENT_ID = "desire-private-pilot"
PINNED_PUBLIC_IPV4 = "8.8.8.8"
DB_DATA_IPV4 = "172.29.25.10"
IMAGE_TAG = "sha-" + "a" * 40 + "-amd64-r123-a1"
INGRESS_IP = "192.168.50.10"


def _write(path: Path, value: bytes, mode: int = 0o444) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    path.chmod(mode)


def _replace_staged_json(path: Path, value: dict) -> None:
    path.chmod(0o600)
    path.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")
    path.chmod(0o444)


class _Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.bundle = self.root / "reviewed-bundle"
        self.identity = self.root / "reviewed-identities"
        self.tls = self.root / "reviewed-tls"
        self.db_password = self.root / "db-password"
        self.taxonomy_workload = self.root / "taxonomy-workload"
        self.taxonomy_hmac = self.root / "taxonomy-hmac"
        self.ipam = self.root / "compose.ipam.yaml"
        self._build_inputs()
        self.environment = self._environment()
        self.raw = self._resolve()
        self.document = json.loads(self.raw)
        self.reviewed = contract.ReviewedRealOidcInputs(
            project_name=PROJECT,
            pilot_hostname=PILOT_HOST,
            oidc_issuer=ISSUER,
            oidc_client_id=CLIENT_ID,
            oidc_pinned_public_ipv4=PINNED_PUBLIC_IPV4,
            db_data_ipv4=DB_DATA_IPV4,
            image_tag=IMAGE_TAG,
            bundle_dir=str(self.bundle),
            identity_source_dir=str(self.identity),
            tls_dir=str(self.tls),
            ingress_ip=INGRESS_IP,
        )

    def _build_inputs(self) -> None:
        self.root.chmod(0o700)
        deployment = {
            "schema_name": "desire-internal-sandbox-deployment-v1",
            "deployment_mode": "INTERNAL_SANDBOX",
            "external_participants_enabled": False,
            "internal_bff_origin": "http://api:8000",
            "runtime_config_path": "/run/desire/runtime-config.json",
            "secret_manifest_path": "/run/desire/secret-manifest.json",
            "secret_root": "/run/secrets",
            "postgres": {
                "host": "db",
                "port": 5432,
                "database": "desire",
                "transport_security": "TRUSTED_CONTAINER_NETWORK",
            },
            "oidc": {
                "issuer": ISSUER,
                "client_id": CLIENT_ID,
                "client_secret_key_id": "oidc-client-secret-v1",
                "redirect_uri": (
                    "https://" + PILOT_HOST + "/v1/auth/oidc/callback"
                ),
                "allowed_signing_algorithms": ["RS256"],
                "metadata_ttl_seconds": 300,
                "request_timeout_seconds": 3,
                "maximum_response_bytes": 262144,
                "clock_skew_seconds": 30,
                "subject_digest_key_id": "oidc-subject-digest-v1",
                "network_binding": {
                    "mode": "PINNED_PUBLIC_IP",
                    "pinned_public_ipv4": PINNED_PUBLIC_IPV4,
                },
            },
            "system_actor_id": "10000000-0000-4000-8000-000000000001",
            "bind": {"host": "0.0.0.0", "port": 8000},
        }
        _write(
            self.bundle / "config/deployment.json",
            json.dumps(deployment, separators=(",", ":")).encode("ascii"),
        )
        _write(self.bundle / "config/runtime-config.json", b"{}")
        _write(self.bundle / "config/secret-manifest.json", b"{}")
        matching_deployment = {
            **deployment,
            "runtime_config_path": "/run/desire/matching-runtime-config.json",
            "secret_manifest_path": "/run/desire/matching-secret-manifest.json",
        }
        _write(
            self.bundle / "config/matching-deployment.json",
            json.dumps(matching_deployment, separators=(",", ":")).encode(
                "ascii"
            ),
        )
        _write(self.bundle / "config/matching-runtime-config.json", b"{}")
        _write(self.bundle / "config/matching-secret-manifest.json", b"{}")
        online_deployment = {
            **deployment,
            "runtime_config_path": (
                "/run/desire/online-credentials-runtime-config.json"
            ),
            "secret_manifest_path": (
                "/run/desire/online-credentials-secret-manifest.json"
            ),
        }
        _write(
            self.bundle / "config/online-credentials-deployment.json",
            json.dumps(online_deployment, separators=(",", ":")).encode(
                "ascii"
            ),
        )
        _write(
            self.bundle / "config/online-credentials-runtime-config.json",
            b"{}",
        )
        _write(
            self.bundle / "config/online-credentials-secret-manifest.json",
            b"{}",
        )
        _write(
            self.bundle / "config/identity-bootstrap-template.json",
            (
                ROOT
                / "platform/examples/internal-sandbox-identity-bootstrap-template-v1.json"
            ).read_bytes(),
        )
        _write(
            self.bundle / "config/Caddyfile.real-oidc",
            (ROOT / "deploy/Caddyfile.real-oidc").read_bytes(),
        )
        for name in contract._BUNDLE_SECRET_NAMES:
            _write(self.bundle / "runtime-secrets" / name, b"x" * 48)
        for name in contract._IDENTITY_SOURCE_NAMES:
            _write(
                self.identity / name,
                ("reviewed:" + name).encode("ascii"),
                0o444,
            )
        self.identity.chmod(0o555)
        _write(self.tls / "edge-tls-chain.pem", b"reviewed-chain")
        _write(self.tls / "edge-tls-key.pem", b"reviewed-key")
        _write(self.db_password, b"db-password")
        _write(self.taxonomy_workload, b"taxonomy-workload")
        _write(self.taxonomy_hmac, b"taxonomy-hmac")
        (self.bundle / "config").chmod(0o555)
        (self.bundle / "runtime-secrets").chmod(0o555)
        self.bundle.chmod(0o555)
        self.tls.chmod(0o555)
        _write(
            self.ipam,
            b"""networks:
  ingress:
    ipam:
      config:
        - subnet: 172.29.23.0/24
  oidc-egress:
    ipam:
      config:
        - subnet: 172.29.26.0/24
  app:
    ipam:
      config:
        - subnet: 172.29.24.0/24
  data:
    ipam:
      config:
        - subnet: 172.29.25.0/24
""",
            0o644,
        )

    def _environment(self) -> dict[str, str]:
        environment = os.environ.copy()
        environment.update(
            {
                "DESIRE_REAL_OIDC_PROJECT_NAME": PROJECT,
                "DESIRE_REAL_OIDC_PILOT_HOSTNAME": PILOT_HOST,
                "DESIRE_REAL_OIDC_BUNDLE_DIR": str(self.bundle),
                "DESIRE_REAL_OIDC_IDENTITY_SOURCE_DIR": str(self.identity),
                "DESIRE_REAL_OIDC_TLS_DIR": str(self.tls),
                "DESIRE_REAL_OIDC_DB_PASSWORD_FILE": str(self.db_password),
                "DESIRE_REAL_OIDC_TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE": str(
                    self.taxonomy_workload
                ),
                "DESIRE_REAL_OIDC_TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE": str(
                    self.taxonomy_hmac
                ),
                "DESIRE_PRIVATE_INGRESS_IP": INGRESS_IP,
                "DESIRE_REAL_OIDC_DB_DATA_IPV4": DB_DATA_IPV4,
                "DESIRE_REAL_OIDC_PINNED_PUBLIC_IPV4": PINNED_PUBLIC_IPV4,
                "DESIRE_REAL_OIDC_EGRESS_PROJECTION_SHA256": (
                    contract.oidc_egress_projection_sha256(
                        DB_DATA_IPV4, PINNED_PUBLIC_IPV4
                    )
                ),
                "DESIRE_IMAGE_TAG": IMAGE_TAG,
            }
        )
        return environment

    def compose_command(self) -> list[str]:
        return [
            "docker",
            "compose",
            "-f",
            str(ROOT / "compose.yaml"),
            "-f",
            str(ROOT / "deploy/private-server.compose.yaml"),
            "-f",
            str(self.ipam),
            "-f",
            str(ROOT / "deploy/private-server-real-oidc.compose.yaml"),
            "config",
            "--format",
            "json",
        ]

    def _resolve(self) -> bytes:
        result = subprocess.run(
            self.compose_command(),
            cwd=ROOT,
            env=self.environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(result.stderr.decode("utf-8", errors="replace"))
        return result.stdout

    def validate(self, document: dict | None = None, reviewed=None) -> None:
        raw = self.raw if document is None else json.dumps(document).encode("ascii")
        contract.validate_private_server_real_oidc_compose(
            raw,
            reviewed=self.reviewed if reviewed is None else reviewed,
            repository_root=str(ROOT),
        )


class PrivateServerRealOidcComposeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="real-oidc-contract-")
        self.addCleanup(self.temporary.cleanup)
        self.fixture = _Fixture(Path(self.temporary.name))

    def test_four_layer_merge_is_closed_and_validator_accepts_it(self) -> None:
        self.fixture.validate()
        document = self.fixture.document
        self.assertEqual(set(document["services"]), contract._SERVICE_NAMES)
        self.assertNotIn("synthetic-oidc", document["services"])
        self.assertEqual(set(document["networks"]), contract._NETWORK_NAMES)
        self.assertEqual(
            document["services"]["api"]["network_mode"],
            "service:oidc-egress-guard",
        )
        self.assertNotIn("networks", document["services"]["api"])
        self.assertEqual(document["services"]["api"]["extra_hosts"], ["db=" + DB_DATA_IPV4])
        guard = document["services"]["oidc-egress-guard"]
        self.assertEqual(guard["cap_add"], ["NET_ADMIN"])
        self.assertNotIn("secrets", guard)
        self.assertEqual(guard["networks"]["app"]["aliases"], ["api"])
        self.assertEqual(
            set(guard["networks"]), {"app", "data", "oidc-egress"}
        )
        self.assertEqual(
            document["services"]["db"]["networks"]["data"]["ipv4_address"],
            DB_DATA_IPV4,
        )
        for name, service in document["services"].items():
            self.assertEqual(
                service["logging"],
                {
                    "driver": "local",
                    "options": {
                        "compress": "true",
                        "max-file": "3",
                        "max-size": "10m",
                    },
                },
            )
            if name != "oidc-egress-guard":
                self.assertNotIn("oidc-egress", service.get("networks", {}))
        self.assertNotIn("depends_on", document["services"]["edge"])
        identity = document["services"]["identity-bootstrap"]
        self.assertEqual(
            {item["source"] for item in identity["secrets"]},
            {
                "db_superuser_password",
                "key-oidc-subject-digest-v1",
                "key-oidc-recipient-binding-v1",
            },
        )
        self.assertNotIn("key-oidc-client-secret-v1", identity["secrets"])
        self.assertEqual(
            document["configs"]["internal-sandbox-identity-template"]["file"],
            str(self.fixture.bundle / "config/identity-bootstrap-template.json"),
        )
        self.assertEqual(
            document["configs"]["real-oidc-caddyfile"]["file"],
            str(self.fixture.bundle / "config/Caddyfile.real-oidc"),
        )

    def test_rejects_missing_or_drifted_bounded_logging(self) -> None:
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
        for service_name in ("api", "db", "oidc-egress-guard"):
            for mutate in mutations:
                document = copy.deepcopy(self.fixture.document)
                mutate(document["services"][service_name])
                with self.subTest(
                    service=service_name, mutation=mutate
                ), self.assertRaises(
                    contract.PrivateServerRealOidcComposeContractError
                ):
                    self.fixture.validate(document)

    def test_required_real_inputs_never_fall_back_to_repository_defaults(self) -> None:
        required_names = (
            "DESIRE_REAL_OIDC_PROJECT_NAME",
            "DESIRE_REAL_OIDC_PILOT_HOSTNAME",
            "DESIRE_REAL_OIDC_BUNDLE_DIR",
            "DESIRE_REAL_OIDC_IDENTITY_SOURCE_DIR",
            "DESIRE_REAL_OIDC_TLS_DIR",
            "DESIRE_REAL_OIDC_DB_PASSWORD_FILE",
            "DESIRE_REAL_OIDC_TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE",
            "DESIRE_REAL_OIDC_TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE",
            "DESIRE_REAL_OIDC_DB_DATA_IPV4",
            "DESIRE_REAL_OIDC_PINNED_PUBLIC_IPV4",
            "DESIRE_REAL_OIDC_EGRESS_PROJECTION_SHA256",
        )
        for name in required_names:
            environment = dict(self.fixture.environment)
            environment.pop(name)
            result = subprocess.run(
                self.fixture.compose_command(),
                cwd=ROOT,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            combined = result.stdout + result.stderr
            with self.subTest(missing=name):
                self.assertNotEqual(result.returncode, 0)
                self.assertIn((name + " is required").encode("ascii"), combined)
                self.assertNotIn(b"secrets/internal-sandbox-bundle", combined)
        overlay = (ROOT / "deploy/private-server-real-oidc.compose.yaml").read_text()
        for name in required_names:
            self.assertIn("${" + name + ":?", overlay)
            self.assertNotIn("${" + name + ":-", overlay)

        environment = dict(self.fixture.environment)
        environment.pop("DESIRE_IMAGE_TAG")
        result = subprocess.run(
            self.fixture.compose_command(),
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        with self.assertRaises(contract.PrivateServerRealOidcComposeContractError):
            self.fixture.validate(json.loads(result.stdout))

    def test_rejects_network_ca_bootstrap_and_unsafe_runtime_mutations(self) -> None:
        mutations = []

        def mutate_api_egress(document):
            document["services"]["edge"]["networks"]["oidc-egress"] = None

        mutations.append(mutate_api_egress)

        def mutate_ca(document):
            document["services"]["api"]["environment"]["SSL_CERT_FILE"] = (
                "/run/desire-tls/root-ca.pem"
            )

        mutations.append(mutate_ca)

        def mutate_bootstrap(document):
            document["services"]["identity-bootstrap"]["command"] = [
                "python",
                "-m",
                "desire_platform.deployment.identity_bootstrap_orchestrator",
                "run",
            ]

        mutations.append(mutate_bootstrap)

        def expose_client_secret(document):
            document["services"]["identity-bootstrap"]["secrets"].append(
                {
                    "source": "key-oidc-client-secret-v1",
                    "target": "key-oidc-client-secret-v1",
                }
            )

        mutations.append(expose_client_secret)

        def publish_api(document):
            document["services"]["api"]["ports"] = [
                {"target": 8000, "published": "8000", "protocol": "tcp"}
            ]

        mutations.append(publish_api)

        def add_unreviewed_edge_port_field(document):
            document["services"]["edge"]["ports"][0]["app_protocol"] = "https"

        mutations.append(add_unreviewed_edge_port_field)

        def privileged(document):
            document["services"]["api"]["privileged"] = True

        mutations.append(privileged)

        def host_pid(document):
            document["services"]["api"]["pid"] = "host"

        mutations.append(host_pid)

        def docker_socket(document):
            document["services"]["api"]["volumes"] = [
                {
                    "type": "bind",
                    "source": "/var/run/docker.sock",
                    "target": "/var/run/docker.sock",
                }
            ]

        mutations.append(docker_socket)

        def host_gateway(document):
            document["services"]["api"]["extra_hosts"] = [
                "host.docker.internal:host-gateway"
            ]

        mutations.append(host_gateway)

        def attach_admin_secret_to_api(document):
            document["services"]["api"]["secrets"].append(
                {
                    "source": "db_superuser_password",
                    "target": "db_superuser_password",
                }
            )

        mutations.append(attach_admin_secret_to_api)

        def arbitrary_api_bind(document):
            document["services"]["api"]["volumes"] = [
                {
                    "type": "bind",
                    "source": str(self.fixture.root),
                    "target": "/run/host-input",
                    "read_only": True,
                }
            ]

        mutations.append(arbitrary_api_bind)

        def remove_read_only(document):
            document["services"]["api"]["read_only"] = False

        mutations.append(remove_read_only)

        def add_capability(document):
            document["services"]["edge"]["cap_add"] = ["NET_ADMIN"]

        mutations.append(add_capability)

        def remove_guard_capability(document):
            document["services"]["oidc-egress-guard"]["cap_add"] = []

        mutations.append(remove_guard_capability)

        def widen_guard_capabilities(document):
            document["services"]["oidc-egress-guard"]["cap_add"].append(
                "NET_RAW"
            )

        mutations.append(widen_guard_capabilities)

        def give_guard_application_secret(document):
            document["services"]["oidc-egress-guard"]["secrets"] = [
                {"source": "key-oidc-client-secret-v1", "target": "client-secret"}
            ]

        mutations.append(give_guard_application_secret)

        def replace_guard_projection_digest(document):
            document["services"]["oidc-egress-guard"]["environment"][
                "DESIRE_REAL_OIDC_EGRESS_PROJECTION_SHA256"
            ] = "0" * 64

        mutations.append(replace_guard_projection_digest)

        def replace_guard_provider_ip(document):
            document["services"]["oidc-egress-guard"]["environment"][
                "DESIRE_REAL_OIDC_PINNED_PUBLIC_IPV4"
            ] = "1.1.1.1"

        mutations.append(replace_guard_provider_ip)

        def remove_guard_api_alias(document):
            document["services"]["oidc-egress-guard"]["networks"]["app"] = {}

        mutations.append(remove_guard_api_alias)

        def bypass_guard_namespace(document):
            document["services"]["api"]["network_mode"] = "bridge"

        mutations.append(bypass_guard_namespace)

        def change_api_database_host_mapping(document):
            document["services"]["api"]["extra_hosts"] = ["db=172.29.25.11"]

        mutations.append(change_api_database_host_mapping)

        def change_static_db_address(document):
            document["services"]["db"]["networks"]["data"][
                "ipv4_address"
            ] = "172.29.25.11"

        mutations.append(change_static_db_address)

        def weaken_tls_secret_mode(document):
            document["services"]["edge"]["secrets"][0]["mode"] = "0444"

        mutations.append(weaken_tls_secret_mode)

        def reuse_external_database_volume(document):
            document["volumes"]["postgres-data"] = {
                "external": True,
                "name": "existing-production-data",
            }

        mutations.append(reuse_external_database_volume)

        def run_api_as_root(document):
            document["services"]["api"]["user"] = "0:0"

        mutations.append(run_api_as_root)

        def replace_reconcile_entrypoint(document):
            document["services"]["online-credentials-reconcile"]["entrypoint"] = [
                "/bin/sh",
                "-c",
            ]

        mutations.append(replace_reconcile_entrypoint)

        def replace_reconcile_command(document):
            document["services"]["online-credentials-reconcile"]["command"] = [
                "python",
                "-c",
                "print('unexpected')",
            ]

        mutations.append(replace_reconcile_command)

        def unconfine_db_seccomp(document):
            document["services"]["db"]["security_opt"] = ["seccomp=unconfined"]

        mutations.append(unconfine_db_seccomp)

        def replace_api_image(document):
            document["services"]["api"]["image"] = "attacker.invalid/api:latest"

        mutations.append(replace_api_image)

        def reuse_shared_data_network(document):
            document["networks"]["data"]["name"] = "existing-shared-network"

        mutations.append(reuse_shared_data_network)

        def omit_reviewed_egress_ipam(document):
            document["networks"]["oidc-egress"]["ipam"] = {}

        mutations.append(omit_reviewed_egress_ipam)

        def widen_app_subnet(document):
            document["networks"]["app"]["ipam"]["config"][0]["subnet"] = (
                "172.29.0.0/16"
            )

        mutations.append(widen_app_subnet)

        def overlap_data_with_app(document):
            document["networks"]["data"]["ipam"]["config"][0]["subnet"] = (
                document["networks"]["app"]["ipam"]["config"][0]["subnet"]
            )

        mutations.append(overlap_data_with_app)

        def overlap_ingress_with_host_lan(document):
            document["networks"]["ingress"]["ipam"]["config"][0]["subnet"] = (
                "192.168.50.0/24"
            )

        mutations.append(overlap_ingress_with_host_lan)

        for mutate in mutations:
            with self.subTest(mutation=mutate.__name__):
                document = copy.deepcopy(self.fixture.document)
                mutate(document)
                with self.assertRaises(
                    contract.PrivateServerRealOidcComposeContractError
                ):
                    self.fixture.validate(document)

    def test_rejects_synthetic_service_provider_secret_and_external_participants(self) -> None:
        document = copy.deepcopy(self.fixture.document)
        document["services"]["synthetic-oidc"] = {}
        with self.assertRaises(contract.PrivateServerRealOidcComposeContractError):
            self.fixture.validate(document)

        document = copy.deepcopy(self.fixture.document)
        document["secrets"]["provider-refresh-token"] = {
            "name": PROJECT + "_provider-refresh-token",
            "file": str(self.fixture.root / "provider-refresh-token"),
        }
        with self.assertRaises(contract.PrivateServerRealOidcComposeContractError):
            self.fixture.validate(document)

        deployment_path = self.fixture.bundle / "config/deployment.json"
        deployment = json.loads(deployment_path.read_text())
        deployment["external_participants_enabled"] = True
        _replace_staged_json(deployment_path, deployment)
        with self.assertRaises(contract.PrivateServerRealOidcComposeContractError):
            self.fixture.validate()
        deployment["external_participants_enabled"] = False
        deployment["system_actor_id"] = "20000000-0000-4000-8000-000000000002"
        _replace_staged_json(deployment_path, deployment)
        with self.assertRaises(contract.PrivateServerRealOidcComposeContractError):
            self.fixture.validate()

    def test_rejects_unreviewed_binding_and_bad_project_names(self) -> None:
        for field, value in (
            ("pilot_hostname", "other.example.org"),
            ("oidc_issuer", "https://other.example.org/tenant"),
            ("oidc_client_id", "other-client"),
            ("oidc_pinned_public_ipv4", "1.1.1.1"),
            ("db_data_ipv4", "172.29.25.11"),
            ("image_tag", "real-oidc-other-release"),
            ("image_tag", "local"),
            ("project_name", "desire-private-ingress-production"),
            ("project_name", "desire-supply"),
        ):
            facts = dict(self.fixture.reviewed.__dict__)
            facts[field] = value
            reviewed = contract.ReviewedRealOidcInputs(**facts)
            with self.subTest(field=field):
                with self.assertRaises(
                    contract.PrivateServerRealOidcComposeContractError
                ):
                    self.fixture.validate(reviewed=reviewed)

        for address in (
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "192.168.1.1",
            "::1",
            "8.8.8.8 ",
            "008.008.008.008",
        ):
            with self.subTest(pinned_public_ipv4=address):
                with self.assertRaises(
                    contract.PrivateServerRealOidcComposeContractError
                ):
                    contract._global_public_ipv4(address)

        for address in (
            "172.29.25.0",
            "172.29.25.1",
            "172.29.25.255",
            "10.0.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "8.8.8.8",
            "::1",
            "172.29.25.010",
        ):
            facts = dict(self.fixture.reviewed.__dict__)
            facts["db_data_ipv4"] = address
            reviewed = contract.ReviewedRealOidcInputs(**facts)
            with self.subTest(db_data_ipv4=address):
                with self.assertRaises(
                    contract.PrivateServerRealOidcComposeContractError
                ):
                    self.fixture.validate(reviewed=reviewed)

    def test_rejects_ip_literals_as_dns_names(self) -> None:
        for hostname in (
            "127.0.0.1",
            "169.254.169.254",
            "10.0.0.1",
            "192.168.1.10",
            "127.1",
            "0x7f.0.0.1",
        ):
            with self.subTest(hostname=hostname):
                with self.assertRaises(
                    contract.PrivateServerRealOidcComposeContractError
                ):
                    contract._dns_name(hostname)
                with self.assertRaises(
                    contract.PrivateServerRealOidcComposeContractError
                ):
                    contract._issuer("https://" + hostname)

    def test_rejects_symlink_and_oversized_identity_inputs(self) -> None:
        symlink = self.fixture.root / "bundle-link"
        symlink.symlink_to(self.fixture.bundle, target_is_directory=True)
        facts = dict(self.fixture.reviewed.__dict__)
        facts["bundle_dir"] = str(symlink)
        reviewed = contract.ReviewedRealOidcInputs(**facts)
        with self.assertRaises(contract.PrivateServerRealOidcComposeContractError):
            self.fixture.validate(reviewed=reviewed)

        source = self.fixture.identity / sorted(contract._IDENTITY_SOURCE_NAMES)[0]
        source.chmod(0o600)
        source.write_bytes(b"x" * 513)
        source.chmod(0o444)
        with self.assertRaises(contract.PrivateServerRealOidcComposeContractError):
            self.fixture.validate()

    def test_rejects_secret_source_aliases_across_security_domains(self) -> None:
        aliases = (
            self.fixture.bundle / "runtime-secrets/key-oidc-client-secret-v1",
            self.fixture.tls / "edge-tls-key.pem",
            self.fixture.taxonomy_workload,
        )
        for source in aliases:
            document = copy.deepcopy(self.fixture.document)
            document["secrets"]["db_superuser_password"]["file"] = str(source)
            with self.subTest(source=source.name):
                with self.assertRaises(
                    contract.PrivateServerRealOidcComposeContractError
                ):
                    self.fixture.validate(document)

    def test_rejects_replaceable_or_hardlinked_identity_sources(self) -> None:
        source = self.fixture.identity / sorted(contract._IDENTITY_SOURCE_NAMES)[0]

        source.chmod(0o646)
        with self.assertRaises(contract.PrivateServerRealOidcComposeContractError):
            self.fixture.validate()
        source.chmod(0o444)

        outside_link = self.fixture.root / "identity-hardlink"
        os.link(source, outside_link)
        with self.assertRaises(contract.PrivateServerRealOidcComposeContractError):
            self.fixture.validate()
        outside_link.unlink()

        for mode in (0o600, 0o750, 0o755):
            self.fixture.root.chmod(mode)
            with self.subTest(parent_mode=oct(mode)):
                with self.assertRaises(
                    contract.PrivateServerRealOidcComposeContractError
                ):
                    self.fixture.validate()
        self.fixture.root.chmod(0o700)

    def test_rejects_unreadable_or_replaceable_staged_mount_inputs(self) -> None:
        for mounted in (
            self.fixture.bundle
            / "runtime-secrets/key-oidc-client-secret-v1",
            self.fixture.bundle / "config/identity-bootstrap-template.json",
            self.fixture.bundle / "config/Caddyfile.real-oidc",
        ):
            mounted.chmod(0o600)
            with self.subTest(mounted=mounted.name):
                with self.assertRaises(
                    contract.PrivateServerRealOidcComposeContractError
                ):
                    self.fixture.validate()
            mounted.chmod(0o444)

        self.fixture.bundle.chmod(0o755)
        with self.assertRaises(contract.PrivateServerRealOidcComposeContractError):
            self.fixture.validate()
        self.fixture.bundle.chmod(0o555)

        runtime_root = self.fixture.bundle / "runtime-secrets"
        runtime_root.chmod(0o755)
        _write(runtime_root / "provider-refresh-token", b"must-not-be-present")
        runtime_root.chmod(0o555)
        with self.assertRaises(contract.PrivateServerRealOidcComposeContractError):
            self.fixture.validate()

    def test_cli_failure_is_stable_and_does_not_reflect_raw_input(self) -> None:
        marker = "raw-provider-code-MUST-NOT-REFLECT"
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                str(SCRIPT),
                "--project-name",
                marker,
                "--pilot-hostname",
                PILOT_HOST,
                "--oidc-issuer",
                ISSUER,
                "--oidc-client-id",
                CLIENT_ID,
                "--oidc-pinned-public-ipv4",
                PINNED_PUBLIC_IPV4,
                "--db-data-ipv4",
                DB_DATA_IPV4,
                "--image-tag",
                IMAGE_TAG,
                "--bundle-dir",
                str(self.fixture.bundle),
                "--identity-source-dir",
                str(self.fixture.identity),
                "--tls-dir",
                str(self.fixture.tls),
                "--ingress-ip",
                INGRESS_IP,
            ],
            cwd=ROOT,
            input=self.fixture.raw,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        combined = result.stdout + result.stderr
        self.assertEqual(result.returncode, 78)
        self.assertNotIn(marker.encode("ascii"), combined)
        self.assertEqual(
            result.stderr,
            b'{"code":"PRIVATE_SERVER_REAL_OIDC_COMPOSE_INVALID","status":"BLOCKED"}\n',
        )

    def test_real_profile_is_not_wired_into_historical_activators(self) -> None:
        for relative in (
            "scripts/activate_private_server_ingress.py",
            "scripts/manage_private_server_ingress.py",
            "scripts/private_server_compose_contract.py",
            "deploy/private-server.compose.yaml",
        ):
            self.assertNotIn(
                "private-server-real-oidc.compose.yaml",
                (ROOT / relative).read_text(encoding="utf-8"),
                relative,
            )
        caddy = (ROOT / "deploy/Caddyfile.real-oidc").read_text()
        self.assertNotIn("identity.example.test", caddy)
        self.assertNotIn("synthetic-oidc", caddy)
        self.assertNotIn("reverse_proxy synthetic", caddy)
        self.assertIn(
            'Strict-Transport-Security "max-age=31536000"', caddy
        )
        self.assertIn(
            'Permissions-Policy "camera=(), geolocation=(), microphone=()"',
            caddy,
        )
        self.assertNotIn("Content-Security-Policy", caddy)


if __name__ == "__main__":
    unittest.main()
