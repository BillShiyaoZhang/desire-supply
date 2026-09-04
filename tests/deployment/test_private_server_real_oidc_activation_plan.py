"""Offline mutation contracts for the real-OIDC snapshot and activation plan."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]


def _module(name: str, relative: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


release = _module(
    "test_real_oidc_release_inputs",
    "scripts/private_server_real_oidc_release_inputs.py",
)
preflight = _module(
    "test_real_oidc_preflight",
    "scripts/preflight_private_server_real_oidc.py",
)
activate = _module(
    "test_real_oidc_activate",
    "scripts/activate_private_server_real_oidc.py",
)
manage = _module(
    "test_real_oidc_manage",
    "scripts/manage_private_server_real_oidc.py",
)

from tests.deployment import test_private_server_real_oidc_compose as compose_fixture
from tests.deployment import test_private_server_release_inputs as legacy_fixture


PROJECT = "desire-real-oidc-activation01"
PILOT_HOST = "pilot.example.org"
ISSUER = "https://login.example.org/tenant"
CLIENT_ID = "desire-private-pilot"
PINNED_PUBLIC_IPV4 = "8.8.8.8"
DB_DATA_IPV4 = "172.29.25.10"
IMAGE_TAG = "sha-" + "a" * 40 + "-amd64-r123-a1"
INGRESS_IP = "192.168.50.10"


def _write(path: Path, value: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    path.chmod(mode)


def _canonical(value) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


class _Fixture:
    def __init__(self, parent: Path) -> None:
        self.parent = parent.resolve(strict=True)
        self.parent.chmod(0o700)
        self.input_root = self.parent / "operator-input"
        self.attempts = self.parent / "attempts"
        self.attempt = self.attempts / PROJECT
        self.seed_root = self.parent / "compose-seed"
        for path in (self.input_root, self.attempts, self.seed_root):
            path.mkdir(mode=0o700)
        self.attempt.mkdir(mode=0o700)

        self.legacy = legacy_fixture.PrivateServerReleaseInputTest("runTest")
        self.legacy.setUp()
        self.seed = compose_fixture._Fixture(self.seed_root)
        self._build_source()
        self.reviewed = release.RealOidcReviewedInputs(
            project_name=PROJECT,
            pilot_hostname=PILOT_HOST,
            oidc_issuer=ISSUER,
            oidc_client_id=CLIENT_ID,
            oidc_pinned_public_ipv4=PINNED_PUBLIC_IPV4,
            db_data_ipv4=DB_DATA_IPV4,
            image_tag=IMAGE_TAG,
            ingress_ip=INGRESS_IP,
        )

    def close(self) -> None:
        self.legacy.tearDown()

    def _build_source(self) -> None:
        legacy_config = (
            self.legacy.input_root / self.legacy.bundle_name / "config"
        )
        bundle = self.input_root / "bundle"
        config = bundle / "config"
        materials = bundle / "runtime-secrets"
        config.mkdir(parents=True, mode=0o700)
        materials.mkdir(mode=0o700)
        bundle.chmod(0o700)
        for name in release._SOURCE_CONFIG_NAMES:
            source_root = (
                self.seed.bundle / "config"
                if name.endswith("deployment.json")
                else legacy_config
            )
            _write(config / name, (source_root / name).read_bytes())

        entries_by_name = {}
        for manifest_name in (
            "secret-manifest.json",
            "matching-secret-manifest.json",
            "online-credentials-secret-manifest.json",
        ):
            manifest = json.loads(
                (config / manifest_name).read_text(encoding="ascii")
            )
            for entry in manifest["entries"]:
                entries_by_name[entry["file_name"]] = entry
        if set(entries_by_name) != set(release._BUNDLE_SECRET_NAMES):
            raise AssertionError("real OIDC fixture secret inventory drifted")
        for entry in entries_by_name.values():
            length = 32 if entry["purpose"] == "OIDC_PROTOCOL_AEAD" else 48
            material = hashlib.sha512(
                ("real-material:" + entry["file_name"]).encode("ascii")
            ).hexdigest()[:length].encode("ascii")
            _write(materials / entry["file_name"], material)

        identity = self.input_root / "identity-sources"
        identity.mkdir(mode=0o700)
        accounts = sorted(
            name[:-8]
            for name in release._IDENTITY_NAMES
            if name.endswith(".subject")
        )
        for account in accounts:
            _write(identity / f"{account}.subject", f"provider:{account}".encode())
            _write(identity / f"{account}.email", f"{account}@example.org".encode())

        tls = self.input_root / "tls"
        tls.mkdir(mode=0o700)
        _write(tls / "edge-tls-chain.pem", b"reviewed-chain-" + b"C" * 64)
        _write(tls / "edge-tls-key.pem", b"reviewed-private-key-" + b"K" * 64)
        _write(self.input_root / "db-password", b"D" * 48)
        _write(self.input_root / "taxonomy-workload", b"W" * 48)
        _write(self.input_root / "taxonomy-hmac", b"H" * 32)
        _write(self.input_root / "compose.ipam.yaml", self.seed.ipam.read_bytes())

    def stage(self):
        def static_compose_runner(command, environment):
            if tuple(command[:2]) != ("/usr/bin/docker", "compose"):
                raise AssertionError("stager must use the reviewed Docker Compose plugin")
            # Only macOS needs the Docker Desktop standalone shim. Linux must
            # exercise the production command under the original clean environment.
            # These static config commands never change the daemon lifecycle.
            actual = tuple(command)
            if sys.platform == "darwin":
                actual = ("/usr/local/bin/docker-compose",) + tuple(command[2:])
            return subprocess.run(
                actual,
                cwd="/",
                env=dict(environment),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

        return release.stage_real_oidc_release_inputs(
            input_root=self.input_root,
            attempt_root=self.attempt,
            reviewed=self.reviewed,
            repository_root=ROOT,
            compose_runner=static_compose_runner,
        )

    def evidence(self, snapshot) -> dict:
        image_ids = {
            reference: "sha256:"
            + hashlib.sha256(("image:" + reference).encode()).hexdigest()
            for reference in snapshot.image_references
        }
        return {
            "format": "desire-real-oidc-preflight-evidence-v1",
            "status": "REVIEWED",
            "action": "ACTIVATE",
            "project": PROJECT,
            "snapshot_sha256": snapshot.snapshot_sha256,
            "manifest_device": snapshot.manifest_device,
            "manifest_inode": snapshot.manifest_inode,
            "compose_sha256": snapshot.compose_sha256,
            "oidc_pinned_public_ipv4": snapshot.oidc_pinned_public_ipv4,
            "db_data_ipv4": snapshot.db_data_ipv4,
            "oidc_egress_projection_sha256": (
                snapshot.oidc_egress_projection_sha256
            ),
            "docker": {
                "endpoint": "unix:///var/run/docker.sock",
                "compose_version": "5.3.1",
                "fresh_check_commands_sha256": preflight.fresh_check_commands_sha256(
                    snapshot
                ),
            },
            "fresh": {
                "project_containers": [],
                "project_networks": [],
                "project_volumes": [],
                "named_containers": {
                    key: "ABSENT"
                    for key in preflight.fresh_container_names(PROJECT)
                },
                "named_networks": {
                    key: "ABSENT"
                    for key in preflight.fresh_resource_names(PROJECT)
                },
                "postgres_volume": "ABSENT",
            },
            "images": image_ids,
            "checks": {key: "VERIFIED" for key in preflight._ARTIFACTS},
            "artifacts": {
                key: hashlib.sha256(("artifact:" + key).encode()).hexdigest()
                for key in preflight._ARTIFACTS
            },
            "execute_blockers": list(preflight._EXECUTE_BLOCKERS),
        }

    def authorization(self, snapshot, evidence_raw: bytes) -> dict:
        evidence = preflight.validate_preflight_evidence(
            evidence_raw, snapshot=snapshot
        )
        return {
            "format": "desire-real-oidc-activation-authorization-v1",
            "status": "APPROVED",
            "action": "CREATE_CONTAINERS",
            "project": PROJECT,
            "snapshot_sha256": snapshot.snapshot_sha256,
            "manifest_device": snapshot.manifest_device,
            "manifest_inode": snapshot.manifest_inode,
            "compose_sha256": snapshot.compose_sha256,
            "oidc_pinned_public_ipv4": snapshot.oidc_pinned_public_ipv4,
            "db_data_ipv4": snapshot.db_data_ipv4,
            "oidc_egress_projection_sha256": (
                snapshot.oidc_egress_projection_sha256
            ),
            "evidence_sha256": evidence.sha256,
            "image_lock_sha256": preflight.image_lock_sha256(evidence.image_ids),
            "fresh_check_commands_sha256": evidence.fresh_check_commands_sha256,
            "plan_nonce": "0f4b3930-3e14-4be8-a92e-66e6bf139d36",
            "one_time": True,
            "rollback_policy": "PRESERVE_POSTGRES_VOLUME",
        }

    def post_create_evidence(
        self, snapshot, create_plan_raw: bytes
    ) -> dict:
        create_plan = json.loads(create_plan_raw)
        _snapshot, _manifest, compose_raw = release.load_real_oidc_release_snapshot(
            self.attempt
        )
        services = json.loads(compose_raw)["services"]
        container_ids = {
            service: hashlib.sha256(("container:" + service).encode()).hexdigest()
            for service in preflight._SERVICES
        }
        containers = {}
        for service in preflight._SERVICES:
            labels = {
                "com.docker.compose.project": PROJECT,
                "com.docker.compose.service": service,
                "com.docker.compose.oneoff": "False",
                "com.docker.compose.container-number": "1",
            }
            reference = services[service]["image"]
            containers[service] = {
                "id": container_ids[service],
                "name": PROJECT + "-" + service + "-1",
                "image_reference": reference,
                "image_id": create_plan["image_ids"][reference],
                "state": "CREATED_NOT_STARTED",
                "required_labels": labels,
                "labels_sha256": preflight._projection_sha256(
                    "container_labels",
                    {"service": service, "required_labels": labels},
                ),
                "mounts_sha256": hashlib.sha256(
                    ("mounts:" + service).encode()
                ).hexdigest(),
                "networks_sha256": hashlib.sha256(
                    ("networks:" + service).encode()
                ).hexdigest(),
                "ports_sha256": hashlib.sha256(
                    ("ports:" + service).encode()
                ).hexdigest(),
                "netns_sha256": hashlib.sha256(
                    ("netns:" + service).encode()
                ).hexdigest(),
                "inspect_sha256": hashlib.sha256(
                    ("inspect:" + service).encode()
                ).hexdigest(),
            }
        network_ids = {
            logical: hashlib.sha256(("network:" + logical).encode()).hexdigest()
            for logical in preflight.fresh_resource_names(PROJECT)
        }
        networks = {
            logical: {
                "id": network_ids[logical],
                "name": name,
                "inspect_sha256": hashlib.sha256(
                    ("network-inspect:" + logical).encode()
                ).hexdigest(),
            }
            for logical, name in preflight.fresh_resource_names(PROJECT).items()
        }
        volume = {
            "name": PROJECT + "_postgres-data",
            "state": "PRESENT_PRESERVE",
            "inspect_sha256": hashlib.sha256(b"volume-inspect").hexdigest(),
        }
        project_objects = {
            "container_ids": sorted(container_ids.values()),
            "network_ids": sorted(network_ids.values()),
            "volume_names": [PROJECT + "_postgres-data"],
            "extra_container_ids": [],
            "extra_network_ids": [],
            "extra_volume_names": [],
        }
        guard = {
            "service": "oidc-egress-guard",
            "container_id": container_ids["oidc-egress-guard"],
            "image_id": containers["oidc-egress-guard"]["image_id"],
            "api_container_id": container_ids["api"],
            "db_container_id": container_ids["db"],
            "api_network_mode": (
                "container:" + container_ids["oidc-egress-guard"]
            ),
            "api_desired_network_config": {},
            "guard_desired_networks": ["app", "data", "oidc-egress"],
            "guard_app_aliases": ["api"],
            "db_data_ipv4": snapshot.db_data_ipv4,
            "oidc_pinned_public_ipv4": snapshot.oidc_pinned_public_ipv4,
            "oidc_egress_projection_sha256": (
                snapshot.oidc_egress_projection_sha256
            ),
            "binding_sha256": preflight.guard_binding_sha256(
                snapshot=snapshot,
                container_ids=container_ids,
            ),
            "ruleset_state": "NOT_INSTALLED_NOT_STARTED",
        }
        return {
            "format": "desire-real-oidc-post-create-evidence-v1",
            "status": "REVIEWED_NOT_EXECUTED",
            "action": "START_CREATED_CONTAINERS",
            "project": PROJECT,
            "snapshot_sha256": snapshot.snapshot_sha256,
            "manifest_device": snapshot.manifest_device,
            "manifest_inode": snapshot.manifest_inode,
            "compose_sha256": snapshot.compose_sha256,
            "oidc_pinned_public_ipv4": snapshot.oidc_pinned_public_ipv4,
            "db_data_ipv4": snapshot.db_data_ipv4,
            "oidc_egress_projection_sha256": (
                snapshot.oidc_egress_projection_sha256
            ),
            "create_plan_sha256": hashlib.sha256(create_plan_raw).hexdigest(),
            "docker": {
                "endpoint": "unix:///var/run/docker.sock",
                "compose_version": "5.3.1",
            },
            "containers": containers,
            "networks": networks,
            "postgres_volume": volume,
            "project_objects": project_objects,
            "guard_binding": guard,
            "checks": {
                key: "REVIEWED" for key in preflight._POST_CREATE_CHECKS
            },
            "artifacts": dict(
                preflight.post_create_artifact_sha256s(
                    containers=containers,
                    networks=networks,
                    postgres_volume=volume,
                    project_objects=project_objects,
                    guard_binding=guard,
                )
            ),
            "execute_blockers": list(preflight._START_EXECUTE_BLOCKERS),
        }

    def start_authorization(
        self, snapshot, create_plan_raw: bytes, post_create_raw: bytes
    ) -> dict:
        post_create = preflight.validate_post_create_evidence(
            post_create_raw,
            snapshot=snapshot,
            create_plan_sha256=hashlib.sha256(create_plan_raw).hexdigest(),
            image_ids=json.loads(create_plan_raw)["image_ids"],
        )
        return {
            "format": "desire-real-oidc-start-authorization-v1",
            "status": "APPROVED",
            "authority": "NOT_AUTHORITY",
            "legacy_execution_accepted": False,
            "action": "START_CREATED_CONTAINERS",
            "project": PROJECT,
            "snapshot_sha256": snapshot.snapshot_sha256,
            "manifest_device": snapshot.manifest_device,
            "manifest_inode": snapshot.manifest_inode,
            "compose_sha256": snapshot.compose_sha256,
            "oidc_pinned_public_ipv4": snapshot.oidc_pinned_public_ipv4,
            "db_data_ipv4": snapshot.db_data_ipv4,
            "oidc_egress_projection_sha256": (
                snapshot.oidc_egress_projection_sha256
            ),
            "create_plan_sha256": hashlib.sha256(create_plan_raw).hexdigest(),
            "post_create_evidence_sha256": post_create.sha256,
            "guard_binding_sha256": post_create.guard_binding_sha256,
            "plan_nonce": "4e9be838-f949-42b6-aa76-3f9fe1b16d8f",
            "one_time": True,
            "rollback_policy": "PRESERVE_POSTGRES_VOLUME",
        }

    def management_documents(
        self, snapshot, *, action: str, plan_nonce: str
    ) -> tuple[bytes, bytes]:
        evidence = {
            "format": "desire-real-oidc-management-evidence-v1",
            "status": "REVIEWED",
            "action": action,
            "project": PROJECT,
            "snapshot_sha256": snapshot.snapshot_sha256,
            "manifest_device": snapshot.manifest_device,
            "manifest_inode": snapshot.manifest_inode,
            "compose_sha256": snapshot.compose_sha256,
            "oidc_pinned_public_ipv4": snapshot.oidc_pinned_public_ipv4,
            "db_data_ipv4": snapshot.db_data_ipv4,
            "oidc_egress_projection_sha256": (
                snapshot.oidc_egress_projection_sha256
            ),
            "activation_receipt_sha256": hashlib.sha256(
                b"activation-receipt"
            ).hexdigest(),
            "guard_binding_sha256": hashlib.sha256(
                b"management-guard-binding"
            ).hexdigest(),
            "containers": {
                service: hashlib.sha256(("container:" + service).encode()).hexdigest()
                for service in manage._SERVICES
            },
            "networks": {
                network: hashlib.sha256(("network:" + network).encode()).hexdigest()
                for network in manage._NETWORKS
            },
            "postgres_volume": {
                "name": PROJECT + "_postgres-data",
                "state": "PRESENT_PRESERVE",
            },
            "checks": {key: "VERIFIED" for key in manage._CHECKS},
            "artifacts": {
                key: hashlib.sha256(("management:" + key).encode()).hexdigest()
                for key in manage._CHECKS
            },
        }
        evidence_raw = _canonical(evidence)
        authorization = {
            "format": "desire-real-oidc-management-authorization-v1",
            "status": "APPROVED",
            "action": action,
            "project": PROJECT,
            "snapshot_sha256": snapshot.snapshot_sha256,
            "manifest_device": snapshot.manifest_device,
            "manifest_inode": snapshot.manifest_inode,
            "compose_sha256": snapshot.compose_sha256,
            "oidc_pinned_public_ipv4": snapshot.oidc_pinned_public_ipv4,
            "db_data_ipv4": snapshot.db_data_ipv4,
            "oidc_egress_projection_sha256": (
                snapshot.oidc_egress_projection_sha256
            ),
            "activation_receipt_sha256": evidence["activation_receipt_sha256"],
            "guard_binding_sha256": evidence["guard_binding_sha256"],
            "evidence_sha256": hashlib.sha256(evidence_raw).hexdigest(),
            "plan_nonce": plan_nonce,
            "one_time": True,
            "rollback_policy": "PRESERVE_POSTGRES_VOLUME",
        }
        return evidence_raw, _canonical(authorization)


class PrivateServerRealOidcActivationPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="real-activation-")
        parent = Path(self.temporary.name).resolve(strict=True)
        parent.chmod(0o700)
        self.fixture = _Fixture(parent)

    def tearDown(self) -> None:
        self.fixture.close()
        self.temporary.cleanup()

    def test_production_contract_and_parsers_are_byte_pinned(self) -> None:
        for relative, expected_sha256 in (
            release._PINNED_REPOSITORY_SOURCE_SHA256.items()
        ):
            with self.subTest(relative=relative):
                self.assertEqual(
                    hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
                    expected_sha256,
                )
        runtime_parser = "platform/src/desire_platform/runtime/config.py"
        with mock.patch.dict(
            release._PINNED_REPOSITORY_SOURCE_SHA256,
            {runtime_parser: "0" * 64},
        ):
            with self.assertRaises(release.PrivateServerRealOidcReleaseInputError):
                self.fixture.stage()

    def test_descriptor_snapshot_binds_all_mounts_compose_and_images(self) -> None:
        snapshot = self.fixture.stage()
        reopened, manifest, compose = release.load_real_oidc_release_snapshot(
            self.fixture.attempt
        )
        self.assertEqual(snapshot, reopened)
        self.assertEqual(
            len(manifest["mounted_sources"]), len(release._MOUNTED_PATHS)
        )
        self.assertEqual(
            set(manifest["mounted_sources"]), release._MOUNTED_PATHS
        )
        self.assertEqual(stat.S_IMODE(self.fixture.attempt.stat().st_mode), 0o700)
        self.assertEqual(
            stat.S_IMODE(
                (self.fixture.attempt / "snapshot-manifest.json").stat().st_mode
            ),
            0o400,
        )
        for relative, item in manifest["mounted_sources"].items():
            path = self.fixture.attempt / relative
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o444)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), item["sha256"])
            self.assertEqual(path.stat().st_ino, item["inode"])
        self.assertEqual(hashlib.sha256(compose).hexdigest(), snapshot.compose_sha256)
        self.assertEqual(len(snapshot.image_references), 5)
        self.assertIn(
            "desire-supply-oidc-egress-guard:" + IMAGE_TAG,
            snapshot.image_references,
        )
        self.assertEqual(snapshot.db_data_ipv4, DB_DATA_IPV4)
        self.assertEqual(
            snapshot.oidc_egress_projection_sha256,
            "db403c2c6ae304f328b9da6efd9349d7b710434b0b5aaa48b676a0b7fec7402e",
        )
        self.assertNotIn("provider:", repr(snapshot))

    def test_reviewed_evidence_and_approval_form_not_executed_plan(self) -> None:
        snapshot = self.fixture.stage()
        evidence_raw = _canonical(self.fixture.evidence(snapshot))
        authorization_raw = _canonical(
            self.fixture.authorization(snapshot, evidence_raw)
        )
        plan = activate.build_activation_plan(
            attempt_root=self.fixture.attempt,
            authorization_raw=authorization_raw,
            evidence_raw=evidence_raw,
        )
        document = json.loads(plan.raw)
        self.assertEqual(document["format"], "desire-real-oidc-create-plan-v1")
        self.assertEqual(document["action"], "CREATE_CONTAINERS")
        self.assertEqual(document["status"], "PLANNED_NOT_EXECUTED")
        self.assertFalse(document["execution"]["implemented"])
        self.assertFalse(document["execution"]["permitted"])
        self.assertFalse(document["execution"]["image_ids_enforced"])
        self.assertEqual(
            document["execution"]["execute_blockers"],
            list(preflight._CREATE_PLAN_BLOCKERS),
        )
        self.assertEqual(document["rollback"]["policy"], "PRESERVE_POSTGRES_VOLUME")
        commands = document["read_only_preflight_commands"]
        inspected_containers = {
            command[-1]
            for command in commands
            if command[3:5] == ["container", "inspect"]
        }
        self.assertEqual(
            inspected_containers,
            set(preflight.fresh_container_names(PROJECT).values()),
        )
        self.assertEqual(
            document["create_command"][-4:],
            ["create", "--no-build", "--pull", "never"],
        )
        self.assertEqual(len(document["image_ids"]), 5)
        self.assertEqual(len(set(document["image_ids"].values())), 5)
        self.assertIn(
            ["/usr/sbin/ip", "-json", "address", "show", "up"],
            document["read_only_preflight_commands"],
        )
        for mutation in ("create", "read_only"):
            changed = copy.deepcopy(document)
            if mutation == "create":
                changed["create_command"][-4:] = ["up", "--detach"]
            else:
                changed["read_only_preflight_commands"][-2][-1] = "down"
            with self.subTest(mutation=mutation):
                with self.assertRaises(activate.PrivateServerRealOidcActivationError):
                    activate._validated_create_plan(
                        _canonical(changed), snapshot=snapshot
                    )
        serialized = plan.raw.decode("ascii")
        self.assertNotIn('"down"', serialized)
        self.assertNotIn('"--volumes"', serialized)
        self.assertNotIn('"run"', serialized)
        self.assertNotIn('"start"', serialized)
        self.assertNotIn("provider:access_admin", serialized)

    def test_source_alias_manifest_identity_and_attempt_mutations_fail_closed(self) -> None:
        material = (
            self.fixture.input_root
            / "bundle/runtime-secrets/key-oidc-state-v1"
        )
        other = (
            self.fixture.input_root
            / "bundle/runtime-secrets/key-oidc-nonce-v1"
        )
        other.write_bytes(material.read_bytes())
        with self.assertRaises(release.PrivateServerRealOidcReleaseInputError):
            self.fixture.stage()

        self.tearDown()
        self.setUp()
        manifest_path = self.fixture.input_root / "bundle/config/secret-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["entries"] = manifest["entries"][:-1]
        _write(manifest_path, json.dumps(manifest, separators=(",", ":")).encode())
        with self.assertRaises(release.PrivateServerRealOidcReleaseInputError):
            self.fixture.stage()

        self.tearDown()
        self.setUp()
        manifest_path = self.fixture.input_root / "bundle/config/secret-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        first_name = manifest["entries"][0]["file_name"]
        manifest["entries"][0]["file_name"] = manifest["entries"][1]["file_name"]
        manifest["entries"][1]["file_name"] = first_name
        _write(manifest_path, json.dumps(manifest, separators=(",", ":")).encode())
        with self.assertRaises(release.PrivateServerRealOidcReleaseInputError):
            self.fixture.stage()

        self.tearDown()
        self.setUp()
        runtime_path = self.fixture.input_root / "bundle/config/runtime-config.json"
        runtime = json.loads(runtime_path.read_text())
        runtime["budgets"]["startup_timeout_ms"] = 31_000
        _write(runtime_path, json.dumps(runtime, separators=(",", ":")).encode())
        with self.assertRaises(release.PrivateServerRealOidcReleaseInputError):
            self.fixture.stage()

        self.tearDown()
        self.setUp()
        subject = self.fixture.input_root / "identity-sources/access_admin_01.subject"
        duplicate = self.fixture.input_root / "identity-sources/creator_01.subject"
        duplicate.write_bytes(subject.read_bytes())
        with self.assertRaises(release.PrivateServerRealOidcReleaseInputError):
            self.fixture.stage()

        self.tearDown()
        self.setUp()
        wrong = self.fixture.attempts / "desire-real-oidc-wrong"
        wrong.mkdir(mode=0o700)
        with self.assertRaises(release.PrivateServerRealOidcReleaseInputError):
            release.stage_real_oidc_release_inputs(
                input_root=self.fixture.input_root,
                attempt_root=wrong,
                reviewed=self.fixture.reviewed,
                repository_root=ROOT,
            )

    def test_symlink_hardlink_extra_and_staged_inode_mutations_fail_closed(self) -> None:
        subject = self.fixture.input_root / "identity-sources/access_admin_01.subject"
        subject.unlink()
        subject.symlink_to(
            self.fixture.input_root / "identity-sources/access_admin_01.email"
        )
        with self.assertRaises(release.PrivateServerRealOidcReleaseInputError):
            self.fixture.stage()

        self.tearDown()
        self.setUp()
        material = self.fixture.input_root / "bundle/runtime-secrets/db-iam-app-v1"
        os.link(material, self.fixture.parent / "material-hardlink")
        with self.assertRaises(release.PrivateServerRealOidcReleaseInputError):
            self.fixture.stage()

        self.tearDown()
        self.setUp()
        _write(self.fixture.input_root / "unexpected", b"x")
        with self.assertRaises(release.PrivateServerRealOidcReleaseInputError):
            self.fixture.stage()

        self.tearDown()
        self.setUp()
        self.fixture.stage()
        target = self.fixture.attempt / "identity-sources/access_admin_01.subject"
        target.chmod(0o600)
        target.write_bytes(b"provider:replacement")
        target.chmod(0o444)
        with self.assertRaises(release.PrivateServerRealOidcReleaseInputError):
            release.load_real_oidc_release_snapshot(self.fixture.attempt)

    def test_forged_staged_guard_and_rehashed_manifest_never_execute(self) -> None:
        self.fixture.stage()
        marker = self.fixture.parent / "forged-guard-executed"
        staged_guard = (
            self.fixture.attempt
            / "repository/private-server-real-oidc-egress-guard.py"
        )
        forged = (
            b"from pathlib import Path\n"
            + b"Path("
            + repr(str(marker)).encode("ascii")
            + b").write_text('executed')\n"
        )
        staged_guard.chmod(0o600)
        staged_guard.write_bytes(forged)
        staged_guard.chmod(0o444)

        manifest_path = self.fixture.attempt / "snapshot-manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        item = manifest["repository_sources"][
            "deploy/private-server-real-oidc-egress-guard.py"
        ]
        item["sha256"] = hashlib.sha256(forged).hexdigest()
        item["size"] = len(forged)
        manifest_path.chmod(0o600)
        manifest_path.write_bytes(_canonical(manifest))
        manifest_path.chmod(0o400)

        with self.assertRaises(release.PrivateServerRealOidcReleaseInputError):
            release.load_real_oidc_release_snapshot(self.fixture.attempt)
        self.assertFalse(marker.exists())

    def test_evidence_and_authorization_mutations_fail_closed(self) -> None:
        snapshot = self.fixture.stage()
        base = self.fixture.evidence(snapshot)
        mutations = []
        value = copy.deepcopy(base)
        value["fresh"]["named_containers"]["api"] = "PRESENT"
        mutations.append(value)
        value = copy.deepcopy(base)
        value["fresh"]["project_networks"] = ["rogue"]
        mutations.append(value)
        value = copy.deepcopy(base)
        value["images"][next(iter(value["images"]))] = "sha256:" + "g" * 64
        mutations.append(value)
        value = copy.deepcopy(base)
        image_names = list(value["images"])
        value["images"][image_names[1]] = value["images"][image_names[0]]
        mutations.append(value)
        value = copy.deepcopy(base)
        value["docker"]["fresh_check_commands_sha256"] = "0" * 64
        mutations.append(value)
        value = copy.deepcopy(base)
        value["manifest_inode"] += 1
        mutations.append(value)
        for value in mutations:
            with self.subTest(mutation=value):
                with self.assertRaises(preflight.PrivateServerRealOidcPreflightError):
                    preflight.validate_preflight_evidence(
                        _canonical(value), snapshot=snapshot
                    )

        evidence_raw = _canonical(base)
        authorization = self.fixture.authorization(snapshot, evidence_raw)
        for key, bad in (
            ("status", "PENDING"),
            ("action", "STOP"),
            ("compose_sha256", "0" * 64),
            ("evidence_sha256", "1" * 64),
            ("image_lock_sha256", "2" * 64),
            ("rollback_policy", "DELETE_VOLUME"),
        ):
            mutated = dict(authorization)
            mutated[key] = bad
            with self.subTest(key=key):
                with self.assertRaises(activate.PrivateServerRealOidcActivationError):
                    activate.build_activation_plan(
                        attempt_root=self.fixture.attempt,
                        authorization_raw=_canonical(mutated),
                        evidence_raw=evidence_raw,
                    )

    def test_post_create_evidence_and_start_plan_bind_exact_ids_and_order(self) -> None:
        snapshot = self.fixture.stage()
        evidence_raw = _canonical(self.fixture.evidence(snapshot))
        create_plan = activate.build_activation_plan(
            attempt_root=self.fixture.attempt,
            authorization_raw=_canonical(
                self.fixture.authorization(snapshot, evidence_raw)
            ),
            evidence_raw=evidence_raw,
        )
        post_create_raw = _canonical(
            self.fixture.post_create_evidence(snapshot, create_plan.raw)
        )
        start_plan = activate.build_start_plan(
            attempt_root=self.fixture.attempt,
            create_plan_raw=create_plan.raw,
            post_create_evidence_raw=post_create_raw,
            authorization_raw=_canonical(
                self.fixture.start_authorization(
                    snapshot, create_plan.raw, post_create_raw
                )
            ),
        )
        document = json.loads(start_plan.raw)
        ids = json.loads(post_create_raw)["project_objects"]["container_ids"]
        self.assertEqual(document["format"], "desire-real-oidc-start-plan-v1")
        self.assertEqual(document["authority"], "NOT_AUTHORITY")
        self.assertFalse(document["legacy_execution_accepted"])
        self.assertEqual(document["action"], "START_CREATED_CONTAINERS")
        self.assertFalse(document["execution"]["implemented"])
        self.assertFalse(document["execution"]["permitted"])
        self.assertFalse(
            document["execution"]["old_post_create_evidence_is_continuing_authority"]
        )
        self.assertTrue(
            document["execution"]["pre_start_full_reinspection_required"]
        )
        self.assertFalse(
            document["execution"]["pre_start_full_reinspection_implemented"]
        )
        self.assertEqual(
            document["execution"]["execute_blockers"],
            list(preflight._START_EXECUTE_BLOCKERS),
        )
        for blocker in (
            "POST_CREATE_COLLECTOR_PROVENANCE_UNIMPLEMENTED",
            "DOCKER_SOCKET_EXCLUSIVE_BROKER_UNIMPLEMENTED",
            "EXECUTION_AUTHORIZATION_V2_UNIMPLEMENTED",
        ):
            self.assertIn(blocker, document["execution"]["execute_blockers"])
        bound = document["bound_container_ids"]
        commands = document["start_commands"]
        self.assertEqual(commands[0][-1], bound["oidc-egress-guard"])
        self.assertEqual(commands[1][-1], bound["db"])
        one_shots = (
            "migrate",
            "taxonomy-seed",
            "online-credentials-reconcile",
            "online-credentials-verify",
            "identity-bootstrap",
        )
        offset = 2
        for service in one_shots:
            self.assertEqual(commands[offset][-2:], ["start", bound[service]])
            self.assertEqual(commands[offset + 1][-2:], ["wait", bound[service]])
            self.assertEqual(
                document["one_shot_wait_contract"][service][
                    "required_wait_stdout"
                ],
                "0\n",
            )
            offset += 2
        self.assertEqual(
            [command[-1] for command in commands[-4:]],
            [
                bound["matching-runtime"],
                bound["api"],
                bound["web"],
                bound["edge"],
            ],
        )
        self.assertTrue(all(command[-1] in ids for command in commands))
        self.assertEqual(
            document["guard_start_gate"]["container_id"],
            bound["oidc-egress-guard"],
        )
        self.assertFalse(document["guard_start_gate"]["implemented"])
        self.assertEqual(
            document["pre_start_reinspection"]["timing"],
            "IMMEDIATELY_BEFORE_EACH_EXACT_ID_START",
        )
        serialized = start_plan.raw.decode("ascii")
        for forbidden in ('"compose"', '"create"', '"up"', '"run"', '"--rm"'):
            self.assertNotIn(forbidden, serialized)

    def test_post_create_and_start_authorization_mutations_fail_closed(self) -> None:
        snapshot = self.fixture.stage()
        evidence_raw = _canonical(self.fixture.evidence(snapshot))
        create_plan = activate.build_activation_plan(
            attempt_root=self.fixture.attempt,
            authorization_raw=_canonical(
                self.fixture.authorization(snapshot, evidence_raw)
            ),
            evidence_raw=evidence_raw,
        )
        base = self.fixture.post_create_evidence(snapshot, create_plan.raw)
        mutations = []
        value = copy.deepcopy(base)
        value["containers"]["api"]["image_id"] = "sha256:" + "f" * 64
        mutations.append(value)
        value = copy.deepcopy(base)
        value["containers"]["api"]["required_labels"][
            "com.docker.compose.service"
        ] = "edge"
        value["artifacts"] = dict(
            preflight.post_create_artifact_sha256s(
                containers=value["containers"],
                networks=value["networks"],
                postgres_volume=value["postgres_volume"],
                project_objects=value["project_objects"],
                guard_binding=value["guard_binding"],
            )
        )
        mutations.append(value)
        value = copy.deepcopy(base)
        value["project_objects"]["extra_container_ids"] = ["a" * 64]
        mutations.append(value)
        value = copy.deepcopy(base)
        value["networks"]["app"]["id"] = value["networks"]["data"]["id"]
        mutations.append(value)
        value = copy.deepcopy(base)
        value["containers"]["api"]["netns_sha256"] = "0" * 64
        mutations.append(value)
        value = copy.deepcopy(base)
        value["guard_binding"]["binding_sha256"] = "1" * 64
        mutations.append(value)
        value = copy.deepcopy(base)
        value["guard_binding"]["api_network_mode"] = "bridge"
        value["guard_binding"]["binding_sha256"] = hashlib.sha256(
            _canonical(
                {
                    "format": "desire-real-oidc-guard-binding-v2",
                    "project": PROJECT,
                    "api_container_id": value["guard_binding"][
                        "api_container_id"
                    ],
                    "db_container_id": value["guard_binding"]["db_container_id"],
                    "guard_container_id": value["guard_binding"]["container_id"],
                    "api_network_mode": "bridge",
                    "api_desired_network_config": {},
                    "guard_desired_networks": ["app", "data", "oidc-egress"],
                    "guard_app_aliases": ["api"],
                    "db_data_ipv4": snapshot.db_data_ipv4,
                    "oidc_pinned_public_ipv4": (
                        snapshot.oidc_pinned_public_ipv4
                    ),
                    "oidc_egress_projection_sha256": (
                        snapshot.oidc_egress_projection_sha256
                    ),
                }
            )
        ).hexdigest()
        value["artifacts"] = dict(
            preflight.post_create_artifact_sha256s(
                containers=value["containers"],
                networks=value["networks"],
                postgres_volume=value["postgres_volume"],
                project_objects=value["project_objects"],
                guard_binding=value["guard_binding"],
            )
        )
        mutations.append(value)
        for blocker in (
            "POST_CREATE_COLLECTOR_PROVENANCE_UNIMPLEMENTED",
            "DOCKER_SOCKET_EXCLUSIVE_BROKER_UNIMPLEMENTED",
            "EXECUTION_AUTHORIZATION_V2_UNIMPLEMENTED",
        ):
            value = copy.deepcopy(base)
            value["execute_blockers"].remove(blocker)
            mutations.append(value)
        for index, value in enumerate(mutations):
            with self.subTest(index=index):
                with self.assertRaises(preflight.PrivateServerRealOidcPreflightError):
                    preflight.validate_post_create_evidence(
                        _canonical(value),
                        snapshot=snapshot,
                        create_plan_sha256=create_plan.sha256,
                        image_ids=json.loads(create_plan.raw)["image_ids"],
                    )

        post_create_raw = _canonical(base)
        authorization = self.fixture.start_authorization(
            snapshot, create_plan.raw, post_create_raw
        )
        for key, bad in (
            ("status", "PENDING"),
            ("authority", "EXECUTION_AUTHORITY"),
            ("legacy_execution_accepted", True),
            ("create_plan_sha256", "0" * 64),
            ("post_create_evidence_sha256", "1" * 64),
            ("guard_binding_sha256", "2" * 64),
            ("oidc_egress_projection_sha256", "3" * 64),
        ):
            value = dict(authorization)
            value[key] = bad
            with self.subTest(key=key):
                with self.assertRaises(activate.PrivateServerRealOidcActivationError):
                    activate.build_start_plan(
                        attempt_root=self.fixture.attempt,
                        create_plan_raw=create_plan.raw,
                        post_create_evidence_raw=post_create_raw,
                        authorization_raw=_canonical(value),
                    )

    def test_nonce_claim_and_descriptor_sealed_stage_are_one_time(self) -> None:
        snapshot = self.fixture.stage()
        evidence_raw = _canonical(self.fixture.evidence(snapshot))
        create_plan = activate.build_activation_plan(
            attempt_root=self.fixture.attempt,
            authorization_raw=_canonical(
                self.fixture.authorization(snapshot, evidence_raw)
            ),
            evidence_raw=evidence_raw,
        )
        post_create_raw = _canonical(
            self.fixture.post_create_evidence(snapshot, create_plan.raw)
        )
        start_authorization_raw = _canonical(
            self.fixture.start_authorization(
                snapshot, create_plan.raw, post_create_raw
            )
        )
        start_plan = activate.build_start_plan(
            attempt_root=self.fixture.attempt,
            create_plan_raw=create_plan.raw,
            post_create_evidence_raw=post_create_raw,
            authorization_raw=start_authorization_raw,
        )
        claims = self.fixture.parent / "nonce-claims"
        claims.mkdir(mode=0o700)
        claim = activate.consume_plan_nonce(
            claim_root=claims,
            plan_nonce=start_plan.plan_nonce,
            action=start_plan.action,
            plan_sha256=start_plan.sha256,
        )
        self.assertEqual(stat.S_IMODE(claim.path.stat().st_mode), 0o400)
        self.assertEqual(claim.path.stat().st_nlink, 1)
        with self.assertRaises(activate.PrivateServerRealOidcActivationError):
            activate.consume_plan_nonce(
                claim_root=claims,
                plan_nonce=start_plan.plan_nonce,
                action=start_plan.action,
                plan_sha256=start_plan.sha256,
            )

        stages = self.fixture.parent / "execution-stages"
        stages.mkdir(mode=0o700)
        stage_root = stages / ("execution-" + start_plan.plan_nonce)
        stage_root.mkdir(mode=0o700)
        sealed = activate.seal_execution_stage(
            stage_root=stage_root,
            start_plan=start_plan,
            create_plan_raw=create_plan.raw,
            post_create_evidence_raw=post_create_raw,
            start_authorization_raw=start_authorization_raw,
            nonce_claim=claim,
        )
        self.assertEqual(sealed, activate.load_execution_stage(stage_root))
        stage_manifest = json.loads(
            (stage_root / "execution-stage-manifest.json").read_bytes()
        )
        self.assertEqual(stage_manifest["authority"], "NOT_AUTHORITY")
        self.assertFalse(stage_manifest["legacy_execution_accepted"])
        self.assertFalse(stage_manifest["execution_permitted"])
        self.assertEqual(stat.S_IMODE(stage_root.stat().st_mode), 0o500)
        self.assertEqual(
            set(path.name for path in stage_root.iterdir()),
            {
                "exclusive.lock",
                "create-plan.json",
                "post-create-evidence.json",
                "start-authorization.json",
                "start-plan.json",
                "nonce-claim.json",
                "execution-stage-manifest.json",
            },
        )
        (stage_root / "start-plan.json").chmod(0o600)
        with self.assertRaises(activate.PrivateServerRealOidcActivationError):
            activate.load_execution_stage(stage_root)

    def test_cli_defaults_to_check_and_execute_is_unreachable(self) -> None:
        self.fixture.stage()
        output = io.StringIO()
        result = activate.main(
            ("--attempt-root", str(self.fixture.attempt)), stdout=output
        )
        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue(), activate.CHECKED)

        output = io.StringIO()
        result = activate.main(
            (
                "--action",
                "execute",
                "--attempt-root",
                str(self.fixture.attempt),
            ),
            stdout=output,
        )
        self.assertEqual(result, 2)
        self.assertEqual(output.getvalue(), activate.BLOCKED)

    def test_cli_uses_closed_descriptor_inputs_and_exclusive_private_plan(self) -> None:
        snapshot = self.fixture.stage()
        evidence_raw = _canonical(self.fixture.evidence(snapshot))
        authorization_raw = _canonical(
            self.fixture.authorization(snapshot, evidence_raw)
        )
        evidence_path = self.fixture.parent / "activation-evidence.json"
        authorization_path = self.fixture.parent / "activation-authorization.json"
        plan_path = self.fixture.parent / "activation-plan.json"
        claims = self.fixture.parent / "nonce-claims"
        claims.mkdir(mode=0o700)
        _write(evidence_path, evidence_raw, 0o600)
        _write(authorization_path, authorization_raw, 0o400)

        output = io.StringIO()
        result = activate.main(
            (
                "--action",
                "create-plan",
                "--attempt-root",
                str(self.fixture.attempt),
                "--authorization-file",
                str(authorization_path),
                "--evidence-file",
                str(evidence_path),
                "--plan-output",
                str(plan_path),
                "--nonce-claim-root",
                str(claims),
            ),
            stdout=output,
        )
        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue(), activate.PLANNED)
        self.assertEqual(stat.S_IMODE(plan_path.stat().st_mode), 0o400)
        self.assertEqual(plan_path.stat().st_nlink, 1)

        output = io.StringIO()
        result = activate.main(
            (
                "--action",
                "create-plan",
                "--attempt-root",
                str(self.fixture.attempt),
                "--authorization-file",
                str(authorization_path),
                "--evidence-file",
                str(evidence_path),
                "--plan-output",
                str(plan_path),
                "--nonce-claim-root",
                str(claims),
            ),
            stdout=output,
        )
        self.assertEqual(result, 2)
        self.assertEqual(output.getvalue(), activate.BLOCKED)

        evidence_path.chmod(0o644)
        output = io.StringIO()
        result = preflight.main(
            (
                "--attempt-root",
                str(self.fixture.attempt),
                "--evidence-file",
                str(evidence_path),
            ),
            stdout=output,
        )
        self.assertEqual(result, 2)
        self.assertEqual(output.getvalue(), preflight.BLOCKED)
        evidence_path.chmod(0o600)

        evidence_alias = self.fixture.parent / "activation-evidence-alias.json"
        os.link(evidence_path, evidence_alias)
        output = io.StringIO()
        result = preflight.main(
            (
                "--attempt-root",
                str(self.fixture.attempt),
                "--evidence-file",
                str(evidence_path),
            ),
            stdout=output,
        )
        self.assertEqual(result, 2)
        self.assertEqual(output.getvalue(), preflight.BLOCKED)

    def test_start_plan_cli_only_seals_offline_inputs(self) -> None:
        snapshot = self.fixture.stage()
        evidence_raw = _canonical(self.fixture.evidence(snapshot))
        create_plan = activate.build_activation_plan(
            attempt_root=self.fixture.attempt,
            authorization_raw=_canonical(
                self.fixture.authorization(snapshot, evidence_raw)
            ),
            evidence_raw=evidence_raw,
        )
        post_create_raw = _canonical(
            self.fixture.post_create_evidence(snapshot, create_plan.raw)
        )
        start_authorization_raw = _canonical(
            self.fixture.start_authorization(
                snapshot, create_plan.raw, post_create_raw
            )
        )
        create_path = self.fixture.parent / "create-plan-for-start.json"
        post_create_path = self.fixture.parent / "post-create-evidence.json"
        authorization_path = self.fixture.parent / "start-authorization.json"
        _write(create_path, create_plan.raw, 0o400)
        _write(post_create_path, post_create_raw, 0o400)
        _write(authorization_path, start_authorization_raw, 0o400)
        claims = self.fixture.parent / "start-nonce-claims"
        stages = self.fixture.parent / "start-stages"
        claims.mkdir(mode=0o700)
        stages.mkdir(mode=0o700)
        nonce = self.fixture.start_authorization(
            snapshot, create_plan.raw, post_create_raw
        )["plan_nonce"]
        stage_root = stages / ("execution-" + nonce)
        stage_root.mkdir(mode=0o700)

        output = io.StringIO()
        result = activate.main(
            (
                "--action",
                "start-plan",
                "--attempt-root",
                str(self.fixture.attempt),
                "--authorization-file",
                str(authorization_path),
                "--create-plan-file",
                str(create_path),
                "--post-create-evidence-file",
                str(post_create_path),
                "--nonce-claim-root",
                str(claims),
                "--execution-stage-root",
                str(stage_root),
            ),
            stdout=output,
        )
        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue(), activate.START_STAGED)
        self.assertEqual(stat.S_IMODE(stage_root.stat().st_mode), 0o500)
        activate.load_execution_stage(stage_root)

        output = io.StringIO()
        result = activate.main(
            (
                "--action",
                "execute",
                "--attempt-root",
                str(self.fixture.attempt),
                "--execution-stage-root",
                str(stage_root),
            ),
            stdout=output,
        )
        self.assertEqual(result, 2)
        self.assertEqual(output.getvalue(), activate.BLOCKED)

    def test_stop_and_rollback_plans_bind_ids_and_preserve_volume(self) -> None:
        snapshot = self.fixture.stage()
        for action in ("STOP", "ROLLBACK"):
            claim_root = self.fixture.parent / (
                "management-claims-" + action.lower()
            )
            claim_root.mkdir(mode=0o700)
            evidence = {
                "format": "desire-real-oidc-management-evidence-v1",
                "status": "REVIEWED",
                "action": action,
                "project": PROJECT,
                "snapshot_sha256": snapshot.snapshot_sha256,
                "manifest_device": snapshot.manifest_device,
                "manifest_inode": snapshot.manifest_inode,
                "compose_sha256": snapshot.compose_sha256,
                "oidc_pinned_public_ipv4": snapshot.oidc_pinned_public_ipv4,
                "db_data_ipv4": snapshot.db_data_ipv4,
                "oidc_egress_projection_sha256": (
                    snapshot.oidc_egress_projection_sha256
                ),
                "activation_receipt_sha256": hashlib.sha256(
                    b"activation-receipt"
                ).hexdigest(),
                "guard_binding_sha256": hashlib.sha256(
                    b"management-guard-binding"
                ).hexdigest(),
                "containers": {
                    service: hashlib.sha256(("container:" + service).encode()).hexdigest()
                    for service in manage._SERVICES
                },
                "networks": {
                    network: hashlib.sha256(("network:" + network).encode()).hexdigest()
                    for network in manage._NETWORKS
                },
                "postgres_volume": {
                    "name": PROJECT + "_postgres-data",
                    "state": "PRESENT_PRESERVE",
                },
                "checks": {key: "VERIFIED" for key in manage._CHECKS},
                "artifacts": {
                    key: hashlib.sha256(("management:" + key).encode()).hexdigest()
                    for key in manage._CHECKS
                },
            }
            evidence_raw = _canonical(evidence)
            authorization = {
                "format": "desire-real-oidc-management-authorization-v1",
                "status": "APPROVED",
                "action": action,
                "project": PROJECT,
                "snapshot_sha256": snapshot.snapshot_sha256,
                "manifest_device": snapshot.manifest_device,
                "manifest_inode": snapshot.manifest_inode,
                "compose_sha256": snapshot.compose_sha256,
                "oidc_pinned_public_ipv4": snapshot.oidc_pinned_public_ipv4,
                "db_data_ipv4": snapshot.db_data_ipv4,
                "oidc_egress_projection_sha256": (
                    snapshot.oidc_egress_projection_sha256
                ),
                "activation_receipt_sha256": evidence[
                    "activation_receipt_sha256"
                ],
                "guard_binding_sha256": evidence["guard_binding_sha256"],
                "evidence_sha256": hashlib.sha256(evidence_raw).hexdigest(),
                "plan_nonce": "e9546984-23d0-48bc-b9a4-330c2bbc8f6a",
                "one_time": True,
                "rollback_policy": "PRESERVE_POSTGRES_VOLUME",
            }
            plan = manage.build_management_plan(
                action=action,
                attempt_root=self.fixture.attempt,
                authorization_raw=_canonical(authorization),
                evidence_raw=evidence_raw,
                nonce_claim_root=claim_root,
            )
            document = json.loads(plan.raw)
            with self.subTest(action=action):
                self.assertEqual(document["action"], action)
                self.assertEqual(
                    [command[-1] for command in document["stop_commands"]],
                    [
                        evidence["containers"][service]
                        for service in (
                            "edge",
                            "web",
                            "api",
                            "matching-runtime",
                            "oidc-egress-guard",
                            "db",
                        )
                    ],
                )
                self.assertEqual(
                    document["bound_container_ids"]["oidc-egress-guard"],
                    evidence["containers"]["oidc-egress-guard"],
                )
                self.assertEqual(
                    document["rollback"]["policy"], "PRESERVE_POSTGRES_VOLUME"
                )
                self.assertFalse(document["execution"]["implemented"])
                expected_semantics = (
                    "EMERGENCY_STOP_SKELETON_NOT_VERSION_RESTORE"
                    if action == "ROLLBACK"
                    else "ORDERED_STOP_ONLY"
                )
                self.assertEqual(
                    document["rollback"]["semantics"], expected_semantics
                )
                self.assertNotIn('"down"', plan.raw.decode())
                self.assertNotIn('"volume","rm"', plan.raw.decode())
                claim_path = claim_root / (
                    "management-nonce-"
                    + authorization["plan_nonce"]
                    + ".json"
                )
                claim = json.loads(claim_path.read_bytes())
                self.assertEqual(claim["action"], action)
                self.assertEqual(claim["plan_sha256"], plan.sha256)
                self.assertEqual(stat.S_IMODE(claim_path.stat().st_mode), 0o400)
                self.assertEqual(claim_path.stat().st_nlink, 1)

            bad = dict(authorization)
            bad["rollback_policy"] = "DELETE_VOLUME"
            with self.assertRaises(manage.PrivateServerRealOidcManagementError):
                manage.build_management_plan(
                    action=action,
                    attempt_root=self.fixture.attempt,
                    authorization_raw=_canonical(bad),
                    evidence_raw=evidence_raw,
                    nonce_claim_root=claim_root,
                )

    def test_management_nonce_is_persistent_operation_bound_and_fail_closed(self) -> None:
        snapshot = self.fixture.stage()
        nonce = "11111111-1111-4111-8111-111111111111"
        evidence_raw, authorization_raw = self.fixture.management_documents(
            snapshot, action="STOP", plan_nonce=nonce
        )
        claim_root = self.fixture.parent / "management-replay-claims"
        claim_root.mkdir(mode=0o700)
        plan = manage.build_management_plan(
            action="STOP",
            attempt_root=self.fixture.attempt,
            authorization_raw=authorization_raw,
            evidence_raw=evidence_raw,
            nonce_claim_root=claim_root,
        )
        claim_path = claim_root / ("management-nonce-" + nonce + ".json")
        claim_raw = claim_path.read_bytes()
        claim = json.loads(claim_raw)
        plan_document = json.loads(plan.raw)
        self.assertEqual(
            claim,
            {
                "format": "desire-real-oidc-management-nonce-claim-v1",
                "status": "CONSUMED_NOT_EXECUTED",
                "action": "STOP",
                "project": PROJECT,
                "plan_nonce": nonce,
                "plan_sha256": plan.sha256,
                "authorization_sha256": plan_document["authorization_sha256"],
                "evidence_sha256": plan_document["evidence_sha256"],
            },
        )
        with self.assertRaises(
            manage.PrivateServerRealOidcManagementError
        ) as replay:
            manage.build_management_plan(
                action="STOP",
                attempt_root=self.fixture.attempt,
                authorization_raw=authorization_raw,
                evidence_raw=evidence_raw,
                nonce_claim_root=claim_root,
            )
        self.assertEqual(
            str(replay.exception), "PRIVATE_SERVER_REAL_OIDC_MANAGEMENT_INVALID"
        )
        self.assertEqual(claim_path.read_bytes(), claim_raw)

        rollback_evidence, rollback_authorization = (
            self.fixture.management_documents(
                snapshot, action="ROLLBACK", plan_nonce=nonce
            )
        )
        with self.assertRaises(manage.PrivateServerRealOidcManagementError):
            manage.build_management_plan(
                action="ROLLBACK",
                attempt_root=self.fixture.attempt,
                authorization_raw=rollback_authorization,
                evidence_raw=rollback_evidence,
                nonce_claim_root=claim_root,
            )
        self.assertEqual(claim_path.read_bytes(), claim_raw)

        wrong_binding_root = self.fixture.parent / "management-wrong-binding"
        wrong_binding_root.mkdir(mode=0o700)
        with self.assertRaises(manage.PrivateServerRealOidcManagementError):
            manage.consume_management_nonce(
                claim_root=wrong_binding_root,
                plan=plan,
                authorization_sha256="0" * 64,
                evidence_sha256=plan_document["evidence_sha256"],
            )
        self.assertEqual(list(wrong_binding_root.iterdir()), [])
        wrong_operation = manage.RealOidcManagementPlan(
            raw=plan.raw,
            sha256=plan.sha256,
            project_name=plan.project_name,
            action="ROLLBACK",
        )
        with self.assertRaises(manage.PrivateServerRealOidcManagementError):
            manage.consume_management_nonce(
                claim_root=wrong_binding_root,
                plan=wrong_operation,
                authorization_sha256=plan_document["authorization_sha256"],
                evidence_sha256=plan_document["evidence_sha256"],
            )
        self.assertEqual(list(wrong_binding_root.iterdir()), [])

        for kind, nonce_value in (
            ("symlink", "22222222-2222-4222-8222-222222222222"),
            ("hardlink", "33333333-3333-4333-8333-333333333333"),
        ):
            root = self.fixture.parent / ("management-" + kind + "-claims")
            root.mkdir(mode=0o700)
            path = root / ("management-nonce-" + nonce_value + ".json")
            target = self.fixture.parent / ("management-" + kind + "-target")
            _write(target, b"sentinel", 0o400)
            if kind == "symlink":
                path.symlink_to(target)
            else:
                os.link(target, path)
            candidate_evidence, candidate_authorization = (
                self.fixture.management_documents(
                    snapshot, action="STOP", plan_nonce=nonce_value
                )
            )
            with self.subTest(kind=kind):
                with self.assertRaises(manage.PrivateServerRealOidcManagementError):
                    manage.build_management_plan(
                        action="STOP",
                        attempt_root=self.fixture.attempt,
                        authorization_raw=candidate_authorization,
                        evidence_raw=candidate_evidence,
                        nonce_claim_root=root,
                    )
                self.assertEqual(target.read_bytes(), b"sentinel")

        permission_nonce = "44444444-4444-4444-8444-444444444444"
        permission_evidence, permission_authorization = (
            self.fixture.management_documents(
                snapshot, action="STOP", plan_nonce=permission_nonce
            )
        )
        permission_root = self.fixture.parent / "management-permission-claims"
        permission_root.mkdir(mode=0o755)
        with self.assertRaises(manage.PrivateServerRealOidcManagementError):
            manage.build_management_plan(
                action="STOP",
                attempt_root=self.fixture.attempt,
                authorization_raw=permission_authorization,
                evidence_raw=permission_evidence,
                nonce_claim_root=permission_root,
            )

        evidence_path = self.fixture.parent / "management-cli-evidence.json"
        authorization_path = self.fixture.parent / "management-cli-authorization.json"
        plan_path = self.fixture.parent / "management-cli-plan.json"
        _write(evidence_path, permission_evidence, 0o400)
        _write(authorization_path, permission_authorization, 0o400)
        output = io.StringIO()
        result = manage.main(
            (
                "--action",
                "stop-plan",
                "--attempt-root",
                str(self.fixture.attempt),
                "--authorization-file",
                str(authorization_path),
                "--evidence-file",
                str(evidence_path),
                "--plan-output",
                str(plan_path),
                "--nonce-claim-root",
                str(permission_root),
            ),
            stdout=output,
        )
        self.assertEqual(result, 2)
        self.assertEqual(output.getvalue(), manage.BLOCKED)
        self.assertNotIn(permission_nonce, output.getvalue())
        self.assertFalse(plan_path.exists())

    def test_default_manager_status_plan_is_read_only_and_exact(self) -> None:
        self.fixture.stage()
        plan = manage.build_status_plan(attempt_root=self.fixture.attempt)
        document = json.loads(plan.raw)
        self.assertEqual(document["action"], "STATUS")
        self.assertEqual(document["status"], "READ_ONLY_PLAN_NOT_EXECUTED")
        commands = document["commands"]
        self.assertEqual(
            {
                command[-1]
                for command in commands
                if command[3:5] == ["container", "inspect"]
            },
            set(preflight.fresh_container_names(PROJECT).values()),
        )
        self.assertEqual(
            {
                command[-1]
                for command in commands
                if command[3:5] == ["network", "inspect"]
            },
            set(preflight.fresh_resource_names(PROJECT).values()),
        )
        self.assertIn(
            [
                "/usr/bin/docker",
                "--host",
                "unix:///var/run/docker.sock",
                "volume",
                "inspect",
                PROJECT + "_postgres-data",
            ],
            commands,
        )
        for forbidden in ('"stop"', '"rm"', '"down"', '"up"'):
            self.assertNotIn(forbidden, plan.raw.decode())
        output = io.StringIO()
        result = manage.main(
            ("--attempt-root", str(self.fixture.attempt)), stdout=output
        )
        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue(), manage.STATUS_PLANNED)

    def test_legacy_synthetic_tools_reject_real_project_namespace(self) -> None:
        old_activate = _module(
            "test_old_private_activate",
            "scripts/activate_private_server_ingress.py",
        )
        old_manage = _module(
            "test_old_private_manage",
            "scripts/manage_private_server_ingress.py",
        )
        with self.assertRaises(old_activate.PrivateServerIngressActivationError):
            old_activate._exact_project(PROJECT)
        with self.assertRaises(old_manage.PrivateServerIngressManagementError):
            old_manage._exact_project(PROJECT)
        old_source = (ROOT / "scripts/activate_private_server_ingress.py").read_text()
        self.assertNotIn("private-server-real-oidc.compose.yaml", old_source)


if __name__ == "__main__":
    unittest.main()
