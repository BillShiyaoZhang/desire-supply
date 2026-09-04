"""Strict construction tests for the dedicated Matching process wiring."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from uuid import UUID

from desire_platform.deployment.internal_sandbox_bundle import (
    InternalSandboxBundleRequest,
    _build_documents,
)
from desire_platform.internal_pilot.deployment_config import (
    DEPLOYMENT_CONFIG_POINTER_ENV,
)
from desire_platform.internal_pilot.postgres_pool import RoleBoundPsycopgPool
from desire_platform.matching.adapters.postgres import (
    MatchingCoordinatorProcess,
    MatchingWorkerProcess,
)
from desire_platform.matching.runtime_process import (
    build_matching_runtime_process_plan as build_runtime_process_plan,
)
from desire_platform.matching.runtime_wiring import (
    MATCHING_RUNTIME_HEALTH_ENV,
    MATCHING_WORKER_AUTHORITY_MARKER_HEX,
    MATCHING_WORKER_AUTHORITY_MARKER_SHA256,
    MATCHING_WORKER_WORKLOAD_ID,
    MatchingRuntimeConstruction,
    MatchingRuntimeWiringError,
    _RuntimeDependencyReadiness,
    _build_matching_runtime_process_plan,
    _coordinator_authority_marker,
    _expected_runtime_dependency_snapshot,
)
SYSTEM_ACTOR_ID = UUID("49000000-0000-4000-8000-000000000001")


class _DbApi:
    @staticmethod
    def connect(**_values):
        raise AssertionError("wiring must not connect during construction")


class _Runner:
    def run_once(self) -> bool:
        return False


class _ReadinessCursor:
    def __init__(self, row) -> None:
        self._row = row

    def fetchone(self):
        return self._row

    def fetchmany(self, size):
        if size != 2:
            raise AssertionError
        return [self._row]


class _ReadinessConnection:
    def __init__(self, *, role: str, snapshot: tuple[object, ...]) -> None:
        self.role = role
        self.snapshot = snapshot

    def execute(self, statement, parameters=()):
        if "set_config" in statement:
            # Actual PostgreSQL 18 results, including canonical whole seconds.
            normalized = {
                "50ms": "50ms", "1000ms": "1s", "2500ms": "2500ms", "30000ms": "30s"
            }
            return _ReadinessCursor((normalized[parameters[0]],))
        if "server_version_num" in statement:
            return _ReadinessCursor((self.role, self.role, 18))
        if "pg_catalog.pg_proc" in statement:
            return _ReadinessCursor(
                (
                    "matching_schema_owner",
                    True,
                    ["search_path=pg_catalog, matching"],
                    True,
                    True,
                    True,
                    True,
                )
            )
        if "read_runtime_dependency_snapshot_v1" in statement:
            return _ReadinessCursor(self.snapshot)
        raise AssertionError("unexpected readiness statement")


class _ReadinessPool:
    def __init__(self, connection: _ReadinessConnection) -> None:
        self.connection = connection
        self.released = 0
        self.discarded = 0

    def checkout(self):
        return self.connection

    def release(self, connection) -> None:
        if connection is not self.connection:
            raise AssertionError
        self.released += 1

    def discard(self, connection) -> None:
        if connection is not self.connection:
            raise AssertionError
        self.discarded += 1


def _material(purpose: str, length: int) -> bytes:
    seed = hashlib.sha512(("matching-test:" + purpose).encode("ascii")).hexdigest()
    value = (seed * 2).encode("ascii")[:length]
    if len(value) != length:
        raise AssertionError
    return value


class _BundleFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="desire-matching-wiring-"
        )
        self.root = Path(self.temporary.name).resolve()
        self.config = self.root / "config"
        self.secrets = self.root / "secrets"
        self.health_dir = self.root / "health"
        self.config.mkdir()
        self.secrets.mkdir()
        self.health_dir.mkdir()
        request = InternalSandboxBundleRequest(
            output_dir=self.root / "unused-output",
            oidc_issuer="https://issuer.example.test",
            oidc_client_id="matching-wiring-test",
            oidc_redirect_uri=(
                "https://pilot.example.test/v1/auth/oidc/callback"
            ),
            oidc_client_secret_file=self.root / "unused-client-secret",
            oidc_network_binding_mode="SYSTEM_DNS_SYNTHETIC",
            oidc_pinned_public_ipv4=None,
            deployment_id="matching-wiring-deployment",
            release_id="matching-wiring-release",
        )
        documents = _build_documents(
            request=request,
            now=datetime(2026, 8, 29, tzinfo=timezone.utc),
            system_actor_id=SYSTEM_ACTOR_ID,
            client_secret=_material("oidc-client", 48),
            material_factory=_material,
        )
        self.runtime_document = deepcopy(documents.matching_runtime)
        self.manifest_document = deepcopy(documents.matching_manifest)
        self.deployment_document = deepcopy(documents.matching_deployment)
        self.runtime_path = self.config / "matching-runtime.json"
        self.manifest_path = self.config / "matching-manifest.json"
        self.deployment_path = self.config / "matching-deployment.json"
        self.deployment_document.update(
            runtime_config_path=str(self.runtime_path),
            secret_manifest_path=str(self.manifest_path),
            secret_root=str(self.secrets),
        )
        for file_name, material in documents.materials.items():
            (self.secrets / file_name).write_bytes(material)
        self.write_documents()

    @property
    def environment(self) -> dict[str, str]:
        return {
            DEPLOYMENT_CONFIG_POINTER_ENV: str(self.deployment_path),
            MATCHING_RUNTIME_HEALTH_ENV: str(self.health_dir / "healthy"),
            "PATH": "/usr/bin",
        }

    def write_documents(self) -> None:
        for path, document in (
            (self.runtime_path, self.runtime_document),
            (self.manifest_path, self.manifest_document),
            (self.deployment_path, self.deployment_document),
        ):
            path.write_bytes(
                json.dumps(
                    document,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("ascii")
            )

    def close(self) -> None:
        self.temporary.cleanup()


class MatchingRuntimeWiringTest(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = _BundleFixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def _build(self, factory):
        return _build_matching_runtime_process_plan(
            environment=self.fixture.environment,
            read_bytes=None,
            dbapi=_DbApi,
            process_factory=factory,
        )

    def test_exact_bundle_builds_five_role_plan_with_frozen_authorities(self) -> None:
        captured: list[MatchingRuntimeConstruction] = []
        worker = _Runner()
        coordinator = _Runner()

        def factory(value: MatchingRuntimeConstruction):
            captured.append(value)
            return worker, coordinator

        plan = self._build(factory)
        construction = captured[0]

        self.assertIs(plan.worker, worker)
        self.assertIs(plan.coordinator, coordinator)
        self.assertEqual(
            construction.worker_context.workload_id,
            MATCHING_WORKER_WORKLOAD_ID,
        )
        self.assertEqual(
            construction.worker_context.authority_marker_sha256,
            MATCHING_WORKER_AUTHORITY_MARKER_SHA256,
        )
        self.assertEqual(
            construction.coordinator_context.workload_id,
            SYSTEM_ACTOR_ID,
        )
        self.assertEqual(
            construction.coordinator_context.authority_marker_sha256,
            _coordinator_authority_marker(SYSTEM_ACTOR_ID),
        )
        self.assertNotEqual(
            construction.worker_context.workload_id,
            construction.coordinator_context.workload_id,
        )
        self.assertEqual(
            tuple(purpose for purpose, _carrier in construction.key_carriers),
            (
                "MATCHING_WORKER_IDEMPOTENCY",
                "MATCHING_WORKER_PAYLOAD_HASH",
                "MATCHING_WORKER_LEASE_DIGEST",
                "MATCHING_COORDINATOR_IDEMPOTENCY",
                "MATCHING_COORDINATOR_PAYLOAD_HASH",
                "MATCHING_COORDINATOR_LEASE_DIGEST",
            ),
        )
        self.assertEqual(
            construction.default_rule.bundle_id,
            "53000000-0000-4000-8000-000000000001",
        )
        pools = tuple(
            item
            for item in plan.managed_resources
            if isinstance(item, RoleBoundPsycopgPool)
        )
        self.assertEqual(len(pools), 5)
        carriers = tuple(
            carrier for _purpose, carrier in construction.key_carriers
        )

        plan.close()

        self.assertTrue(all(pool._closed for pool in pools))
        self.assertTrue(all(carrier._destroyed for carrier in carriers))
        self.assertTrue(
            all(not any(carrier.material) for carrier in carriers)
        )

    def test_public_builder_constructs_processes_with_zeroizable_role_keys(self) -> None:
        plan = build_runtime_process_plan(
            environment=self.fixture.environment,
            dbapi=_DbApi,
        )

        self.assertIsInstance(plan.worker, MatchingWorkerProcess)
        self.assertIsInstance(plan.coordinator, MatchingCoordinatorProcess)
        self.assertIs(plan.tick_readiness, plan.managed_resources[0])
        self.assertEqual(
            sum(
                isinstance(resource, _RuntimeDependencyReadiness)
                for resource in plan.managed_resources
            ),
            1,
        )
        self.assertEqual(plan.worker._context.workload_id, MATCHING_WORKER_WORKLOAD_ID)
        self.assertEqual(plan.coordinator._context.workload_id, SYSTEM_ACTOR_ID)
        self.assertIsNot(plan.worker._keys, plan.coordinator._keys)
        self.assertEqual(
            (
                plan.worker._keys.identity_key_id,
                plan.worker._keys.payload_hash_key_id,
                plan.worker._keys.lease_digest_key_id,
                plan.coordinator._keys.identity_key_id,
                plan.coordinator._keys.payload_hash_key_id,
                plan.coordinator._keys.lease_digest_key_id,
            ),
            (
                "matching-worker-idempotency-v1",
                "matching-worker-payload-hash-v1",
                "matching-worker-lease-digest-v1",
                "matching-coordinator-idempotency-v1",
                "matching-coordinator-payload-hash-v1",
                "matching-coordinator-lease-digest-v1",
            ),
        )
        materials = (
            plan.worker._keys.identity_key,
            plan.worker._keys.payload_hash_key,
            plan.worker._keys.lease_digest_key,
            plan.coordinator._keys.identity_key,
            plan.coordinator._keys.payload_hash_key,
            plan.coordinator._keys.lease_digest_key,
        )
        self.assertTrue(all(isinstance(value, bytearray) for value in materials))
        self.assertEqual(len({id(value) for value in materials}), 6)
        plan.close()

        self.assertTrue(all(not any(value) for value in materials))

    def test_factory_failure_closes_adapters_pools_then_secrets(self) -> None:
        captured: list[MatchingRuntimeConstruction] = []

        def factory(value: MatchingRuntimeConstruction):
            captured.append(value)
            raise RuntimeError("private factory detail")

        with self.assertRaises(MatchingRuntimeWiringError) as raised:
            self._build(factory)

        self.assertEqual(
            raised.exception.code, "MATCHING_RUNTIME_COMPOSITION_INVALID"
        )
        construction = captured[0]
        self.assertTrue(construction.worker_runtime._gateway.closed)
        self.assertTrue(construction.coordinator_runtime._gateway.closed)
        self.assertTrue(construction.demand_delivery._closed)
        self.assertTrue(construction.trust_decision._closed)
        self.assertTrue(
            all(
                carrier._destroyed and not any(carrier.material)
                for _purpose, carrier in construction.key_carriers
            )
        )

    def test_only_pointer_and_health_desire_environment_are_allowed(self) -> None:
        environment = dict(self.fixture.environment)
        environment["DESIRE_UNREVIEWED_OVERRIDE"] = "enabled"
        called = False

        def factory(_value):
            nonlocal called
            called = True
            return _Runner(), _Runner()

        with self.assertRaises(MatchingRuntimeWiringError):
            _build_matching_runtime_process_plan(
                environment=environment,
                read_bytes=None,
                dbapi=_DbApi,
                process_factory=factory,
            )

        self.assertFalse(called)

    def test_capability_key_and_artifact_drift_fail_before_factory(self) -> None:
        mutations = []

        def capability(document):
            document["process"]["capability_ids"][0:2] = reversed(
                document["process"]["capability_ids"][0:2]
            )

        mutations.append(capability)

        def key(document):
            document["key_requirements"][0]["active_key_id"] = "drift-v1"
            document["key_requirements"][0]["retained_key_ids"] = [
                "drift-v1"
            ]

        mutations.append(key)

        def artifact(document):
            document["artifacts"][0]["sha256"] = "0" * 64

        mutations.append(artifact)

        original = deepcopy(self.fixture.runtime_document)
        for mutate in mutations:
            with self.subTest(mutate=mutate.__name__):
                self.fixture.runtime_document = deepcopy(original)
                mutate(self.fixture.runtime_document)
                self.fixture.write_documents()
                called = False

                def factory(_value):
                    nonlocal called
                    called = True
                    return _Runner(), _Runner()

                with self.assertRaises(MatchingRuntimeWiringError):
                    self._build(factory)
                self.assertFalse(called)

    def test_manifest_cannot_swap_files_between_key_purposes(self) -> None:
        entries = self.fixture.manifest_document["entries"]
        first, second = entries[-2:]
        first["file_name"], second["file_name"] = (
            second["file_name"],
            first["file_name"],
        )
        self.fixture.write_documents()
        called = False

        def factory(_value):
            nonlocal called
            called = True
            return _Runner(), _Runner()

        with self.assertRaises(MatchingRuntimeWiringError):
            self._build(factory)

        self.assertFalse(called)

    def test_exact_runtime_dependency_snapshot_accepts_both_process_roles(self) -> None:
        snapshot = _expected_runtime_dependency_snapshot()
        worker_pool = _ReadinessPool(
            _ReadinessConnection(role="matching_worker", snapshot=snapshot)
        )
        coordinator_pool = _ReadinessPool(
            _ReadinessConnection(
                role="matching_coordinator", snapshot=snapshot
            )
        )
        readiness = _RuntimeDependencyReadiness(
            pools=(
                ("matching_worker", worker_pool),
                ("matching_coordinator", coordinator_pool),
            )
        )

        for timeout_ms in (50, 1_000, 2_500, 30_000):
            with self.subTest(timeout_ms=timeout_ms):
                readiness.check_readiness(timeout_ms=timeout_ms)

        self.assertEqual(worker_pool.released, 4)
        self.assertEqual(coordinator_pool.released, 4)
        self.assertEqual(worker_pool.discarded, 0)
        self.assertEqual(coordinator_pool.discarded, 0)
        self.assertEqual(len(snapshot), 33)

    def test_stale_runtime_dependency_metadata_is_rejected(self) -> None:
        current = _expected_runtime_dependency_snapshot()
        mutations = {
            "matching_head": (1, current[1] - 1),
            "matching_manifest": (5, b"m" * 32),
            "iam_head": (7, current[7] - 1),
            "iam_contract": (10, b"i" * 32),
            "demand_head": (12, current[12] - 1),
            "demand_manifest": (16, b"d" * 32),
            "profile_head": (18, current[18] - 1),
            "profile_required_iam": (21, current[21] - 1),
            "profile_manifest": (22, b"p" * 32),
            "trust_head": (24, current[24] - 1),
            "trust_iam_dependency": (29, b"u" * 32),
            "trust_demand_dependency": (30, b"t" * 32),
            "trust_combined_contract": (31, b"c" * 32),
            "trust_manifest": (32, b"r" * 32),
        }
        for label, (index, replacement) in mutations.items():
            with self.subTest(label=label):
                values = list(current)
                values[index] = replacement
                worker_pool = _ReadinessPool(
                    _ReadinessConnection(
                        role="matching_worker", snapshot=tuple(values)
                    )
                )
                coordinator_pool = _ReadinessPool(
                    _ReadinessConnection(
                        role="matching_coordinator", snapshot=current
                    )
                )
                readiness = _RuntimeDependencyReadiness(
                    pools=(
                        ("matching_worker", worker_pool),
                        ("matching_coordinator", coordinator_pool),
                    )
                )

                with self.assertRaisesRegex(
                    RuntimeError,
                    "MATCHING_SCHEMA_DEPENDENCY_UNAVAILABLE",
                ):
                    readiness.check_readiness(timeout_ms=1_000)

                self.assertEqual(worker_pool.released, 0)
                self.assertEqual(worker_pool.discarded, 1)
                self.assertEqual(coordinator_pool.released, 0)

    def test_health_file_cannot_be_placed_below_secret_root(self) -> None:
        health_parent = self.fixture.secrets / "health"
        health_parent.mkdir()
        environment = dict(self.fixture.environment)
        environment[MATCHING_RUNTIME_HEALTH_ENV] = str(
            health_parent / "healthy"
        )

        with self.assertRaises(MatchingRuntimeWiringError):
            _build_matching_runtime_process_plan(
                environment=environment,
                read_bytes=None,
                dbapi=_DbApi,
                process_factory=lambda _value: (_Runner(), _Runner()),
            )

    def test_deployment_system_actor_cannot_replace_demand_workload(self) -> None:
        self.fixture.deployment_document["system_actor_id"] = str(
            MATCHING_WORKER_WORKLOAD_ID
        )
        self.fixture.write_documents()
        called = False

        def factory(_value):
            nonlocal called
            called = True
            return _Runner(), _Runner()

        with self.assertRaises(MatchingRuntimeWiringError):
            self._build(factory)

        self.assertFalse(called)

    def test_worker_marker_is_frozen_and_coordinator_marker_is_release_stable(self) -> None:
        self.assertEqual(
            MATCHING_WORKER_AUTHORITY_MARKER_SHA256.hex(),
            MATCHING_WORKER_AUTHORITY_MARKER_HEX,
        )
        first = _coordinator_authority_marker(SYSTEM_ACTOR_ID)
        second = _coordinator_authority_marker(SYSTEM_ACTOR_ID)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 32)
        self.assertNotEqual(first, MATCHING_WORKER_AUTHORITY_MARKER_SHA256)
        with self.assertRaises(ValueError):
            _coordinator_authority_marker(MATCHING_WORKER_WORKLOAD_ID)


if __name__ == "__main__":
    unittest.main()
