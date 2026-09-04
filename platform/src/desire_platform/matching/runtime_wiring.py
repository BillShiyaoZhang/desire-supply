"""Fail-closed production wiring for the dedicated Matching process.

The container supplies two ambient facts: one deployment pointer and one
heartbeat path.  Everything else is read from the reviewed deployment bundle.
This module validates the exact domain-process contract, resolves only its five
role credentials and six purpose-separated keys, then constructs the worker
and coordinator behind a small factory seam.  Secret carriers remain alive
until every adapter and pool has closed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Tuple
from uuid import UUID

import psycopg

from desire_platform.creator_profile.adapters.postgres import (
    CreatorProfilePostgresSettings,
    PsycopgCreatorProfileMatcherRepository,
)
from desire_platform.creator_profile.adapters.postgres.migrations import (
    PROFILE_REQUIRED_IAM_SCHEMA_VERSION,
    PROFILE_REVIEWED_MANIFEST_SHA256,
    PROFILE_SCHEMA_HEAD_VERSION,
)
from desire_platform.demand.adapters.postgres import (
    DemandMatchingRuntimeSettings,
    DemandPostgresSettings,
    PsycopgDemandMatchingRepository,
    PsycopgDemandMatchingRuntime,
)
from desire_platform.demand.adapters.postgres.migrations import (
    DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
    DEMAND_REVIEWED_MANIFEST_SHA256,
    DEMAND_SCHEMA_HEAD_VERSION,
)
from desire_platform.identity_access.adapters.postgres.migrations import (
    IAM_REVIEWED_MANIFEST_SHA256,
    IAM_SCHEMA_HEAD_VERSION,
)
from desire_platform.internal_pilot.deployment_config import (
    DEPLOYMENT_CONFIG_POINTER_ENV,
    InternalSandboxDeploymentConfiguration,
    _read_regular_config_file,
    load_internal_sandbox_deployment_config_pointer,
)
from desire_platform.internal_pilot.postgres_pool import (
    PsycopgRoleBoundPoolFactory,
)
from desire_platform.internal_pilot.production_plan import (
    INTERNAL_SANDBOX_ARTIFACT_REQUIREMENTS,
    INTERNAL_SANDBOX_MATCHING_RUNTIME_CAPABILITY_ROLES,
    INTERNAL_SANDBOX_MATCHING_RUNTIME_KEY_PURPOSES,
    _ARTIFACT_LOCATIONS,
)
from desire_platform.internal_pilot.secrets import (
    FileSecretCarrier,
    FileSecretManifestEntry,
    FilesystemSecretProvider,
    ManagedRuntimeSecrets,
    parse_file_secret_manifest,
)
from desire_platform.matching.adapters.postgres import (
    MatchingOperationalPostgresSettings,
    MatchingWorkloadContext,
    PsycopgMatchingCoordinatorRuntime,
    PsycopgMatchingWorkerRuntime,
)
from desire_platform.matching.adapters.postgres.migrations import (
    MATCHING_REQUIRED_IAM_SCHEMA_VERSION,
    MATCHING_REVIEWED_MANIFEST_SHA256,
    MATCHING_SCHEMA_HEAD_VERSION,
)
from desire_platform.matching.engine_v1 import (
    LoadedMatchingRuleReleaseV1,
    load_default_rule_release_v1,
)
from desire_platform.runtime.artifacts import PackageArtifactVerifier
from desire_platform.runtime.config import (
    DatabaseProfile,
    RuntimeConfiguration,
    parse_runtime_config,
)
from desire_platform.trust_safety.adapters.postgres import (
    PsycopgTrustDemandSafetyHoldProvider,
    TrustPostgresGatewaySettings,
)
from desire_platform.trust_safety.adapters.postgres.migrations import (
    TRUST_REQUIRED_DEMAND_CONTRACT_SHA256,
    TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
    TRUST_REQUIRED_IAM_CONTRACT_SHA256,
    TRUST_REQUIRED_IAM_SCHEMA_VERSION,
    TRUST_REVIEWED_COMBINED_CONTRACT_SHA256,
    TRUST_REVIEWED_MANIFEST_SHA256,
    TRUST_SCHEMA_HEAD_VERSION,
)

from .runtime_process import MatchingRuntimeProcessPlan


MATCHING_WORKER_WORKLOAD_ID = UUID(
    "48000000-0000-4000-8000-000000000001"
)
MATCHING_WORKER_AUTHORITY_MARKER_SHA256 = hashlib.sha256(
    b"exact-demand-match-request-allowlist"
).digest()
MATCHING_WORKER_AUTHORITY_MARKER_HEX = (
    "18400bdb73bc15d2e01028897107a1cef"
    "ef0429a3e27110097b648832a346f2c"
)
MATCHING_RUNTIME_HEALTH_ENV = "DESIRE_MATCHING_RUNTIME_HEALTH_FILE"

_COORDINATOR_MARKER_DOMAIN = b"desire:matching:coordinator-authority:v1\x00"
_EXPECTED_ENVIRONMENT_ID = "internal-sandbox"
_EXPECTED_REGION = "trusted-container-network"
_EXPECTED_INSTANCE_ID = "matching-runtime-0001"
_EXPECTED_KEY_IDS = {
    purpose: purpose.lower().replace("_", "-") + "-v1"
    for purpose in INTERNAL_SANDBOX_MATCHING_RUNTIME_KEY_PURPOSES
}
_RUNTIME_DEPENDENCY_SIGNATURE = (
    "matching_api.read_runtime_dependency_snapshot_v1()"
)


class MatchingRuntimeWiringError(RuntimeError):
    """Stable construction failure that never reflects secret/config bytes."""

    def __init__(self) -> None:
        self.code = "MATCHING_RUNTIME_COMPOSITION_INVALID"
        super().__init__(self.code)


@dataclass(frozen=True, repr=False)
class MatchingRuntimeConstruction:
    """Closed input to the operational process factory.

    Keeping this seam explicit insulates deployment wiring from the low-level
    request DTOs used inside one worker tick.  It is also the single place that
    the operational process API needs to be adapted while Matching v3 evolves.
    """

    runtime_config: RuntimeConfiguration
    worker_context: MatchingWorkloadContext
    coordinator_context: MatchingWorkloadContext
    key_carriers: Tuple[Tuple[str, FileSecretCarrier], ...] = field(repr=False)
    default_rule: LoadedMatchingRuleReleaseV1 = field(repr=False)
    worker_runtime: PsycopgMatchingWorkerRuntime = field(repr=False)
    coordinator_runtime: PsycopgMatchingCoordinatorRuntime = field(repr=False)
    demand_delivery: PsycopgDemandMatchingRuntime = field(repr=False)
    demand_capture: PsycopgDemandMatchingRepository = field(repr=False)
    profile_capture: PsycopgCreatorProfileMatcherRepository = field(repr=False)
    trust_decision: PsycopgTrustDemandSafetyHoldProvider = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.runtime_config, RuntimeConfiguration)
            or not isinstance(self.worker_context, MatchingWorkloadContext)
            or not isinstance(self.coordinator_context, MatchingWorkloadContext)
            or self.worker_context.workload_id != MATCHING_WORKER_WORKLOAD_ID
            or not hmac.compare_digest(
                self.worker_context.authority_marker_sha256,
                MATCHING_WORKER_AUTHORITY_MARKER_SHA256,
            )
            or self.coordinator_context.workload_id
            == self.worker_context.workload_id
            or not hmac.compare_digest(
                self.coordinator_context.authority_marker_sha256,
                _coordinator_authority_marker(
                    self.coordinator_context.workload_id
                ),
            )
            or tuple(purpose for purpose, _carrier in self.key_carriers)
            != INTERNAL_SANDBOX_MATCHING_RUNTIME_KEY_PURPOSES
            or any(
                not isinstance(carrier, FileSecretCarrier)
                for _purpose, carrier in self.key_carriers
            )
            or not isinstance(self.default_rule, LoadedMatchingRuleReleaseV1)
            or not isinstance(self.worker_runtime, PsycopgMatchingWorkerRuntime)
            or not isinstance(
                self.coordinator_runtime, PsycopgMatchingCoordinatorRuntime
            )
            or not isinstance(self.demand_delivery, PsycopgDemandMatchingRuntime)
            or not isinstance(self.demand_capture, PsycopgDemandMatchingRepository)
            or not isinstance(
                self.profile_capture, PsycopgCreatorProfileMatcherRepository
            )
            or not isinstance(
                self.trust_decision, PsycopgTrustDemandSafetyHoldProvider
            )
        ):
            raise TypeError("Matching runtime construction is unavailable")


@dataclass(frozen=True)
class _FixedProgram:
    pool: Any = field(repr=False)
    role: str
    owner: str
    signature: str
    search_path: Tuple[str, ...]


class _RuntimeDependencyReadiness:
    """Exact cross-schema compatibility snapshot through one definer."""

    def __init__(self, *, pools: Tuple[Tuple[str, Any], ...]) -> None:
        if (
            not isinstance(pools, tuple)
            or tuple(role for role, _pool in pools)
            != ("matching_worker", "matching_coordinator")
            or len({id(pool) for _role, pool in pools}) != 2
        ):
            raise TypeError("Matching dependency readiness is unavailable")
        self._pools = pools
        self._closed = False

    def check_readiness(self, *, timeout_ms: int) -> None:
        if (
            self._closed
            or type(timeout_ms) is not int
            or not 50 <= timeout_ms <= 30_000
        ):
            raise RuntimeError("MATCHING_SCHEMA_DEPENDENCY_UNAVAILABLE")
        expected = _expected_runtime_dependency_snapshot()
        for role, pool in self._pools:
            connection = None
            disposed = False
            try:
                connection = pool.checkout()
                timeout_value = f"{timeout_ms}ms"
                configured = connection.execute(
                    "SELECT pg_catalog.set_config"
                    "('statement_timeout',%s,false)",
                    (timeout_value,),
                ).fetchone()
                # PostgreSQL returns canonical units: 1000ms becomes 1s.
                expected_timeout = (
                    f"{timeout_ms // 1000}s" if timeout_ms % 1000 == 0 else timeout_value
                )
                if configured != (expected_timeout,):
                    raise RuntimeError
                identity = connection.execute(
                    "SELECT session_user,current_user,"
                    "current_setting('server_version_num')::integer/10000"
                ).fetchone()
                if identity != (role, role, 18):
                    raise RuntimeError
                metadata = connection.execute(
                    "SELECT owner.rolname,procedure.prosecdef,"
                    "procedure.proconfig,procedure.provolatile='s',"
                    "has_function_privilege(session_user,procedure.oid,'EXECUTE'),"
                    "NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(COALESCE("
                    "procedure.proacl,pg_catalog.acldefault('f',"
                    "procedure.proowner))) public_acl WHERE public_acl.grantee=0 "
                    "AND public_acl.privilege_type='EXECUTE'),"
                    "NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(COALESCE("
                    "procedure.proacl,pg_catalog.acldefault('f',"
                    "procedure.proowner))) acl LEFT JOIN pg_catalog.pg_roles grantee "
                    "ON grantee.oid=acl.grantee WHERE acl.privilege_type='EXECUTE' "
                    "AND acl.grantee<>procedure.proowner AND (grantee.rolname IS NULL "
                    "OR grantee.rolname NOT IN "
                    "('matching_worker','matching_coordinator'))) "
                    "FROM pg_catalog.pg_proc procedure "
                    "JOIN pg_catalog.pg_roles owner ON owner.oid=procedure.proowner "
                    "WHERE procedure.oid=pg_catalog.to_regprocedure(%s)",
                    (_RUNTIME_DEPENDENCY_SIGNATURE,),
                ).fetchone()
                if metadata != (
                    "matching_schema_owner",
                    True,
                    ["search_path=pg_catalog, matching"],
                    True,
                    True,
                    True,
                    True,
                ):
                    raise RuntimeError
                snapshots = connection.execute(
                    "SELECT * FROM matching_api."
                    "read_runtime_dependency_snapshot_v1()"
                ).fetchmany(2)
                if snapshots != [expected]:
                    raise RuntimeError
                pool.release(connection)
                disposed = True
            except BaseException:
                if connection is not None and not disposed:
                    try:
                        pool.discard(connection)
                    except BaseException:
                        pass
                raise RuntimeError(
                    "MATCHING_SCHEMA_DEPENDENCY_UNAVAILABLE"
                ) from None

    def close(self) -> None:
        self._closed = True


class _CaptureAndTrustReadiness:
    """Readiness/lifecycle owner for adapters without their own probe."""

    def __init__(
        self,
        *,
        programs: Tuple[_FixedProgram, ...],
        trust_decision: PsycopgTrustDemandSafetyHoldProvider,
    ) -> None:
        if (
            not isinstance(programs, tuple)
            or len(programs) != 3
            or len({id(item.pool) for item in programs}) != 3
            or not isinstance(
                trust_decision, PsycopgTrustDemandSafetyHoldProvider
            )
        ):
            raise TypeError("Matching capture readiness is unavailable")
        self._programs = programs
        self._trust_decision = trust_decision
        self._closed = False

    def check_readiness(self, *, timeout_ms: int) -> None:
        if (
            self._closed
            or type(timeout_ms) is not int
            or not 50 <= timeout_ms <= 30_000
        ):
            raise RuntimeError("MATCHING_CAPTURE_DEPENDENCY_UNAVAILABLE")
        for program in self._programs:
            connection = None
            disposed = False
            try:
                connection = program.pool.checkout()
                timeout_value = f"{timeout_ms}ms"
                configured = connection.execute(
                    "SELECT pg_catalog.set_config"
                    "('statement_timeout',%s,false)",
                    (timeout_value,),
                ).fetchone()
                expected_timeout = (
                    f"{timeout_ms // 1000}s" if timeout_ms % 1000 == 0 else timeout_value
                )
                if configured != (expected_timeout,):
                    raise RuntimeError
                identity = connection.execute(
                    "SELECT session_user,current_user,"
                    "current_setting('server_version_num')::integer/10000"
                ).fetchone()
                if identity != (program.role, program.role, 18):
                    raise RuntimeError
                row = connection.execute(
                    "SELECT procedure.oid IS NOT NULL,owner.rolname,"
                    "procedure.prosecdef,procedure.proconfig,"
                    "has_function_privilege(session_user,procedure.oid,'EXECUTE'),"
                    "NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(COALESCE("
                    "procedure.proacl,pg_catalog.acldefault('f',"
                    "procedure.proowner))) acl WHERE acl.grantee=0 "
                    "AND acl.privilege_type='EXECUTE') "
                    "FROM pg_catalog.pg_proc procedure "
                    "JOIN pg_catalog.pg_roles owner "
                    "ON owner.oid=procedure.proowner "
                    "WHERE procedure.oid=to_regprocedure(%s)",
                    (program.signature,),
                ).fetchone()
                expected_path = [
                    "search_path=" + ", ".join(program.search_path)
                ]
                if row != (
                    True,
                    program.owner,
                    True,
                    expected_path,
                    True,
                    True,
                ):
                    raise RuntimeError
                program.pool.release(connection)
                disposed = True
            except BaseException:
                if connection is not None and not disposed:
                    try:
                        program.pool.discard(connection)
                    except BaseException:
                        pass
                raise RuntimeError(
                    "MATCHING_CAPTURE_DEPENDENCY_UNAVAILABLE"
                ) from None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._trust_decision.close()
        except BaseException:
            pass


ProcessFactory = Callable[
    [MatchingRuntimeConstruction], Tuple[Any, Any]
]


def build_matching_runtime_process_plan(
    *,
    environment: Mapping[str, str],
    read_bytes: Optional[Callable[[str], bytes]] = None,
    dbapi: Any = None,
) -> MatchingRuntimeProcessPlan:
    """Build the exact five-role Matching process without connecting yet."""

    return _build_matching_runtime_process_plan(
        environment=environment,
        read_bytes=read_bytes,
        dbapi=psycopg if dbapi is None else dbapi,
        process_factory=_build_operational_processes,
    )


def _build_matching_runtime_process_plan(
    *,
    environment: Mapping[str, str],
    read_bytes: Optional[Callable[[str], bytes]],
    dbapi: Any,
    process_factory: ProcessFactory,
) -> MatchingRuntimeProcessPlan:
    managed: list[Any] = []
    issued: list[FileSecretCarrier] = []
    try:
        deployment, health_file = _load_process_environment(
            environment=environment,
            read_bytes=read_bytes,
        )
        reader = _read_regular_config_file if read_bytes is None else read_bytes
        if not callable(reader):
            raise TypeError
        runtime = parse_runtime_config(
            _read_exact(reader, deployment.runtime_config_path)
        )
        _validate_runtime_contract(runtime)
        if PurePosixPath(deployment.secret_root) in PurePosixPath(
            str(health_file)
        ).parents:
            raise ValueError

        verifier = PackageArtifactVerifier(locations=_ARTIFACT_LOCATIONS)
        for artifact in runtime.artifacts:
            verifier.verify(artifact)
        default_rule = load_default_rule_release_v1()

        entries = parse_file_secret_manifest(
            _read_exact(reader, deployment.secret_manifest_path)
        )
        _validate_manifest(runtime, entries)
        provider = FilesystemSecretProvider(
            allowed_root=Path(deployment.secret_root),
            entries=entries,
        )
        credentials: Dict[str, FileSecretCarrier] = {}
        for profile in runtime.database_profiles:
            carrier = provider.resolve_credential(profile)
            issued.append(carrier)
            credentials[profile.capability_id] = carrier
        keys: Dict[str, FileSecretCarrier] = {}
        for requirement in runtime.key_requirements:
            carrier = provider.resolve_key(
                requirement.purpose, requirement.active_key_id
            )
            issued.append(carrier)
            keys[requirement.purpose] = carrier
        _validate_secret_material(issued, keys)

        secrets = ManagedRuntimeSecrets(
            carriers=tuple(issued),
            clock=lambda: datetime.now(timezone.utc),
        )
        managed.append(secrets)

        pool_factory = PsycopgRoleBoundPoolFactory(
            endpoint=deployment.postgres,
            dbapi=dbapi,
            allowed_roles=tuple(
                role
                for _capability, role
                in INTERNAL_SANDBOX_MATCHING_RUNTIME_CAPABILITY_ROLES
            ),
        )
        profiles = {
            profile.capability_id: profile
            for profile in runtime.database_profiles
        }
        pools: Dict[str, Any] = {}
        for capability, _role in INTERNAL_SANDBOX_MATCHING_RUNTIME_CAPABILITY_ROLES:
            pool = pool_factory.create(
                profiles[capability], credentials[capability]
            )
            managed.append(pool)
            pools[capability] = pool

        dependency_readiness = _RuntimeDependencyReadiness(
            pools=(
                ("matching_worker", pools["MATCHING_WORKER"]),
                ("matching_coordinator", pools["MATCHING_COORDINATOR"]),
            )
        )
        managed.append(dependency_readiness)

        demand_profile = profiles["DEMAND_MATCHING"]
        profile_profile = profiles["PROFILE_MATCHER"]
        trust_profile = profiles["TRUST_DECISION"]
        worker_profile = profiles["MATCHING_WORKER"]
        coordinator_profile = profiles["MATCHING_COORDINATOR"]

        demand_delivery = PsycopgDemandMatchingRuntime(
            delivery_connections=pools["DEMAND_MATCHING"],
            coordinator_connections=pools["MATCHING_COORDINATOR"],
            settings=DemandMatchingRuntimeSettings(
                lock_timeout_ms=demand_profile.lock_timeout_ms,
                statement_timeout_ms=demand_profile.statement_timeout_ms,
                idle_in_transaction_timeout_ms=(
                    demand_profile.idle_in_transaction_timeout_ms
                ),
            ),
        )
        demand_capture = PsycopgDemandMatchingRepository(
            connections=pools["DEMAND_MATCHING"],
            settings=DemandPostgresSettings(
                lock_timeout_ms=demand_profile.lock_timeout_ms,
                statement_timeout_ms=demand_profile.statement_timeout_ms,
                idle_in_transaction_timeout_ms=(
                    demand_profile.idle_in_transaction_timeout_ms
                ),
            ),
        )
        profile_capture = PsycopgCreatorProfileMatcherRepository(
            connections=pools["PROFILE_MATCHER"],
            settings=CreatorProfilePostgresSettings(
                lock_timeout_ms=profile_profile.lock_timeout_ms,
                statement_timeout_ms=profile_profile.statement_timeout_ms,
                idle_in_transaction_timeout_ms=(
                    profile_profile.idle_in_transaction_timeout_ms
                ),
            ),
        )
        trust_decision = PsycopgTrustDemandSafetyHoldProvider(
            decision_connections=pools["TRUST_DECISION"],
            settings=TrustPostgresGatewaySettings(
                lock_timeout_ms=trust_profile.lock_timeout_ms,
                statement_timeout_ms=trust_profile.statement_timeout_ms,
                idle_in_transaction_timeout_ms=(
                    trust_profile.idle_in_transaction_timeout_ms
                ),
            ),
        )
        capture_readiness = _CaptureAndTrustReadiness(
            programs=(
                _FixedProgram(
                    pool=pools["DEMAND_MATCHING"],
                    role="demand_matching",
                    owner="demand_schema_owner",
                    signature=(
                        "demand.capture_match_inputs_v1"
                        "(uuid,uuid,uuid[],bytea)"
                    ),
                    search_path=("pg_catalog", "demand"),
                ),
                _FixedProgram(
                    pool=pools["PROFILE_MATCHER"],
                    role="profile_matcher",
                    owner="profile_schema_owner",
                    signature=(
                        "profile_api."
                        "discover_and_capture_derived_creator_match_inputs_v1"
                        "(uuid,uuid,bytea,bytea,bytea)"
                    ),
                    search_path=("pg_catalog", "profile", "iam_api"),
                ),
                _FixedProgram(
                    pool=pools["TRUST_DECISION"],
                    role="trust_decision",
                    owner="trust_schema_owner",
                    signature=(
                        "trust_api.evaluate_demand_hold_v1"
                        "(uuid,uuid,uuid,bigint,uuid,bytea,text,text)"
                    ),
                    search_path=("pg_catalog", "trust"),
                ),
            ),
            trust_decision=trust_decision,
        )
        managed.extend((capture_readiness, demand_delivery))

        worker_runtime = PsycopgMatchingWorkerRuntime(
            connections=pools["MATCHING_WORKER"],
            settings=_matching_settings(worker_profile),
        )
        managed.append(worker_runtime)
        coordinator_runtime = PsycopgMatchingCoordinatorRuntime(
            connections=pools["MATCHING_COORDINATOR"],
            settings=_matching_settings(coordinator_profile),
        )
        managed.append(coordinator_runtime)

        worker_context = MatchingWorkloadContext(
            workload_id=MATCHING_WORKER_WORKLOAD_ID,
            authority_marker_sha256=(
                MATCHING_WORKER_AUTHORITY_MARKER_SHA256
            ),
        )
        coordinator_context = MatchingWorkloadContext(
            workload_id=deployment.system_actor_id,
            authority_marker_sha256=_coordinator_authority_marker(
                deployment.system_actor_id
            ),
        )
        construction = MatchingRuntimeConstruction(
            runtime_config=runtime,
            worker_context=worker_context,
            coordinator_context=coordinator_context,
            key_carriers=tuple(
                (purpose, keys[purpose])
                for purpose in INTERNAL_SANDBOX_MATCHING_RUNTIME_KEY_PURPOSES
            ),
            default_rule=default_rule,
            worker_runtime=worker_runtime,
            coordinator_runtime=coordinator_runtime,
            demand_delivery=demand_delivery,
            demand_capture=demand_capture,
            profile_capture=profile_capture,
            trust_decision=trust_decision,
        )
        if not callable(process_factory):
            raise TypeError
        worker, coordinator = process_factory(construction)
        if (
            worker is coordinator
            or not callable(getattr(worker, "run_once", None))
            or not callable(getattr(coordinator, "run_once", None))
        ):
            raise TypeError
        return MatchingRuntimeProcessPlan(
            worker=worker,
            coordinator=coordinator,
            managed_resources=tuple(managed),
            tick_readiness=secrets,
            health_file=health_file,
            readiness_timeout_ms=runtime.budgets.readiness_timeout_ms,
            shutdown_timeout_ms=runtime.budgets.shutdown_timeout_ms,
        )
    except MatchingRuntimeWiringError:
        _cleanup(managed, issued)
        raise
    except BaseException:
        _cleanup(managed, issued)
        raise MatchingRuntimeWiringError() from None


def _build_operational_processes(
    construction: MatchingRuntimeConstruction,
) -> Tuple[Any, Any]:
    """Adapt the final Matching v3 process API in one delayed-import seam."""

    # The process classes are landing with Matching v3.  This explicit import
    # keeps config parsing and lifecycle tests independent from that module and
    # makes a missing production process fail closed instead of substituting a
    # no-op worker.
    from desire_platform.matching.adapters.postgres.operational_runtime import (
        MatchingCoordinatorProcess,
        MatchingOperationalKeyRing,
        MatchingWorkerProcess,
    )

    key_values = {
        purpose: carrier
        for purpose, carrier in construction.key_carriers
    }
    worker_keys = MatchingOperationalKeyRing(
        identity_key_id=key_values["MATCHING_WORKER_IDEMPOTENCY"].key_id,
        identity_key=key_values["MATCHING_WORKER_IDEMPOTENCY"].material,
        payload_hash_key_id=key_values[
            "MATCHING_WORKER_PAYLOAD_HASH"
        ].key_id,
        payload_hash_key=key_values["MATCHING_WORKER_PAYLOAD_HASH"].material,
        lease_digest_key_id=key_values[
            "MATCHING_WORKER_LEASE_DIGEST"
        ].key_id,
        lease_digest_key=key_values["MATCHING_WORKER_LEASE_DIGEST"].material,
    )
    coordinator_keys = MatchingOperationalKeyRing(
        identity_key_id=key_values[
            "MATCHING_COORDINATOR_IDEMPOTENCY"
        ].key_id,
        identity_key=key_values[
            "MATCHING_COORDINATOR_IDEMPOTENCY"
        ].material,
        payload_hash_key_id=key_values[
            "MATCHING_COORDINATOR_PAYLOAD_HASH"
        ].key_id,
        payload_hash_key=key_values[
            "MATCHING_COORDINATOR_PAYLOAD_HASH"
        ].material,
        lease_digest_key_id=key_values[
            "MATCHING_COORDINATOR_LEASE_DIGEST"
        ].key_id,
        lease_digest_key=key_values[
            "MATCHING_COORDINATOR_LEASE_DIGEST"
        ].material,
    )
    worker = MatchingWorkerProcess(
        runtime=construction.worker_runtime,
        demand_delivery=construction.demand_delivery,
        demand_capture=construction.demand_capture,
        profile_capture=construction.profile_capture,
        context=construction.worker_context,
        coordinator_context=construction.coordinator_context,
        keys=worker_keys,
        default_rule=construction.default_rule,
    )
    coordinator = MatchingCoordinatorProcess(
        runtime=construction.coordinator_runtime,
        context=construction.coordinator_context,
        keys=coordinator_keys,
        trust_evidence=construction.trust_decision,
    )
    return worker, coordinator


def _load_process_environment(
    *,
    environment: Mapping[str, str],
    read_bytes: Optional[Callable[[str], bytes]],
) -> Tuple[InternalSandboxDeploymentConfiguration, Path]:
    if not isinstance(environment, Mapping):
        raise TypeError
    desire_keys = tuple(
        sorted(
            key
            for key in environment
            if isinstance(key, str) and key.startswith("DESIRE_")
        )
    )
    expected = tuple(
        sorted((DEPLOYMENT_CONFIG_POINTER_ENV, MATCHING_RUNTIME_HEALTH_ENV))
    )
    if desire_keys != expected:
        raise ValueError
    pointer = environment.get(DEPLOYMENT_CONFIG_POINTER_ENV)
    health = environment.get(MATCHING_RUNTIME_HEALTH_ENV)
    if (
        not isinstance(pointer, str)
        or not isinstance(health, str)
        or not health
        or health != health.strip()
        or len(health) > 4_096
    ):
        raise ValueError
    health_file = Path(health)
    if not health_file.is_absolute() or health_file.name != "healthy":
        raise ValueError
    deployment = load_internal_sandbox_deployment_config_pointer(
        environment={DEPLOYMENT_CONFIG_POINTER_ENV: pointer},
        read_bytes=read_bytes,
    )
    return deployment, health_file


def _validate_runtime_contract(runtime: RuntimeConfiguration) -> None:
    if (
        runtime.schema_name != "desire-runtime-config-v1"
        or runtime.identity.environment_id != _EXPECTED_ENVIRONMENT_ID
        or runtime.identity.region != _EXPECTED_REGION
        or runtime.identity.instance_id != _EXPECTED_INSTANCE_ID
        or runtime.process.kind != "domain-process"
        or runtime.process.capability_ids
        != tuple(
            capability
            for capability, _role
            in INTERNAL_SANDBOX_MATCHING_RUNTIME_CAPABILITY_ROLES
        )
        or runtime.artifacts != INTERNAL_SANDBOX_ARTIFACT_REQUIREMENTS
        or tuple(
            (profile.capability_id, profile.online_role)
            for profile in runtime.database_profiles
        )
        != INTERNAL_SANDBOX_MATCHING_RUNTIME_CAPABILITY_ROLES
        or tuple(
            requirement.purpose
            for requirement in runtime.key_requirements
        )
        != INTERNAL_SANDBOX_MATCHING_RUNTIME_KEY_PURPOSES
    ):
        raise ValueError
    for requirement in runtime.key_requirements:
        expected_key = _EXPECTED_KEY_IDS[requirement.purpose]
        if (
            requirement.active_key_id != expected_key
            or requirement.retained_key_ids != (expected_key,)
        ):
            raise ValueError


def _validate_manifest(
    runtime: RuntimeConfiguration,
    entries: Tuple[FileSecretManifestEntry, ...],
) -> None:
    expected = tuple(
        (
            "DATABASE_CREDENTIAL",
            "db-"
            + profile.capability_id.lower().replace("_", "-")
            + "-"
            + profile.credential_ref.rsplit("#", 1)[1],
            profile.credential_ref,
            f"DATABASE_CREDENTIAL:{profile.capability_id}",
            profile.credential_ref.rsplit("#", 1)[1],
        )
        for profile in runtime.database_profiles
    ) + tuple(
        (
            "KEY",
            "key-" + requirement.active_key_id,
            None,
            requirement.purpose,
            requirement.active_key_id,
        )
        for requirement in runtime.key_requirements
    )
    actual = tuple(
        (
            entry.kind,
            entry.file_name,
            entry.credential_ref,
            entry.purpose,
            entry.key_id,
        )
        for entry in entries
    )
    if actual != expected or any(entry.status != "ACTIVE" for entry in entries):
        raise ValueError


def _validate_secret_material(
    carriers: Sequence[FileSecretCarrier],
    keys: Mapping[str, FileSecretCarrier],
) -> None:
    if (
        len(carriers) != 11
        or len({id(item) for item in carriers}) != len(carriers)
        or len(
            {
                hashlib.sha256(bytes(item.material)).digest()
                for item in carriers
            }
        )
        != len(carriers)
        or tuple(keys) != INTERNAL_SANDBOX_MATCHING_RUNTIME_KEY_PURPOSES
    ):
        raise ValueError
    for purpose, carrier in keys.items():
        if (
            carrier.purpose != purpose
            or carrier.key_id != _EXPECTED_KEY_IDS[purpose]
            or carrier.status != "ACTIVE"
            or len(carrier.material) < 32
            or not any(carrier.material)
        ):
            raise ValueError


def _matching_settings(
    profile: DatabaseProfile,
) -> MatchingOperationalPostgresSettings:
    return MatchingOperationalPostgresSettings(
        lock_timeout_ms=profile.lock_timeout_ms,
        statement_timeout_ms=profile.statement_timeout_ms,
        idle_in_transaction_timeout_ms=(
            profile.idle_in_transaction_timeout_ms
        ),
    )


def _expected_runtime_dependency_snapshot() -> Tuple[Any, ...]:
    artifact_sha256 = {
        requirement.artifact_id: bytes.fromhex(requirement.sha256)
        for requirement in INTERNAL_SANDBOX_ARTIFACT_REQUIREMENTS
    }
    iam_combined = hashlib.sha256(
        b"iam-v1-contract\x00"
        + artifact_sha256["iam-openapi-v1"]
        + artifact_sha256["iam-events-v1"]
        + IAM_REVIEWED_MANIFEST_SHA256
    ).digest()
    return (
        MATCHING_SCHEMA_HEAD_VERSION,
        MATCHING_SCHEMA_HEAD_VERSION,
        MATCHING_SCHEMA_HEAD_VERSION,
        MATCHING_SCHEMA_HEAD_VERSION,
        MATCHING_REQUIRED_IAM_SCHEMA_VERSION,
        MATCHING_REVIEWED_MANIFEST_SHA256,
        IAM_SCHEMA_HEAD_VERSION,
        IAM_SCHEMA_HEAD_VERSION,
        IAM_SCHEMA_HEAD_VERSION,
        IAM_SCHEMA_HEAD_VERSION,
        iam_combined,
        DEMAND_SCHEMA_HEAD_VERSION,
        DEMAND_SCHEMA_HEAD_VERSION,
        DEMAND_SCHEMA_HEAD_VERSION,
        DEMAND_SCHEMA_HEAD_VERSION,
        DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
        DEMAND_REVIEWED_MANIFEST_SHA256,
        PROFILE_SCHEMA_HEAD_VERSION,
        PROFILE_SCHEMA_HEAD_VERSION,
        PROFILE_SCHEMA_HEAD_VERSION,
        PROFILE_SCHEMA_HEAD_VERSION,
        PROFILE_REQUIRED_IAM_SCHEMA_VERSION,
        PROFILE_REVIEWED_MANIFEST_SHA256,
        TRUST_SCHEMA_HEAD_VERSION,
        TRUST_SCHEMA_HEAD_VERSION,
        TRUST_SCHEMA_HEAD_VERSION,
        TRUST_SCHEMA_HEAD_VERSION,
        TRUST_REQUIRED_IAM_SCHEMA_VERSION,
        TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
        TRUST_REQUIRED_IAM_CONTRACT_SHA256,
        TRUST_REQUIRED_DEMAND_CONTRACT_SHA256,
        TRUST_REVIEWED_COMBINED_CONTRACT_SHA256,
        TRUST_REVIEWED_MANIFEST_SHA256,
    )


def _coordinator_authority_marker(system_actor_id: UUID) -> bytes:
    if (
        not isinstance(system_actor_id, UUID)
        or system_actor_id.int == 0
        or system_actor_id == MATCHING_WORKER_WORKLOAD_ID
    ):
        raise ValueError("Matching coordinator identity is invalid")
    return hashlib.sha256(
        _COORDINATOR_MARKER_DOMAIN + system_actor_id.bytes
    ).digest()


def _read_exact(reader: Callable[[str], bytes], path: str) -> bytes:
    raw = reader(path)
    if type(raw) is not bytes:
        raise TypeError
    return raw


def _cleanup(
    managed: Sequence[Any], issued: Sequence[FileSecretCarrier]
) -> None:
    for resource in reversed(tuple(managed)):
        try:
            resource.close()
        except BaseException:
            pass
    for carrier in reversed(tuple(issued)):
        try:
            carrier.destroy()
        except BaseException:
            pass


__all__ = [
    "MATCHING_RUNTIME_HEALTH_ENV",
    "MATCHING_WORKER_AUTHORITY_MARKER_HEX",
    "MATCHING_WORKER_AUTHORITY_MARKER_SHA256",
    "MATCHING_WORKER_WORKLOAD_ID",
    "MatchingRuntimeConstruction",
    "MatchingRuntimeWiringError",
    "build_matching_runtime_process_plan",
]
