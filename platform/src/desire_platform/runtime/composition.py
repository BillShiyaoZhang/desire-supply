"""Framework-neutral, fail-closed production composition kernel."""

import hashlib
import hmac
import math
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Optional, Sequence, Tuple

from .config import (
    ArtifactRequirement,
    RuntimeConfiguration,
    RuntimeConfigurationError,
    _validate_runtime_configuration_instance,
)


class RuntimeState(str, Enum):
    NEW = "NEW"
    BUILDING = "BUILDING"
    READY = "READY"
    STOPPING = "STOPPING"
    CLOSED = "CLOSED"
    FAILED = "FAILED"


@dataclass(frozen=True)
class RuntimeCapabilityContract:
    capability_id: str
    component_id: str
    database_role: Optional[str]


@dataclass(frozen=True)
class RuntimeBuildContract:
    schema_name: str
    process_kind: str
    capabilities: Tuple[RuntimeCapabilityContract, ...]
    artifacts: Tuple[ArtifactRequirement, ...]
    required_key_purposes: Tuple[str, ...]


@dataclass(frozen=True)
class ComponentFactoryBinding:
    component_id: str
    factory: Any


@dataclass(frozen=True)
class RuntimeBindings:
    clock: Any
    artifact_verifier: Any
    secret_provider: Any
    pool_factory: Any
    component_factories: Tuple[ComponentFactoryBinding, ...]
    entrypoint_factory: Any


class RuntimeCompositionError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, repr=False)
class RuntimeAssemblyContext:
    config: RuntimeConfiguration
    pools: Tuple[Tuple[str, Any], ...]
    keys: Tuple[Tuple[str, str, Any], ...]
    components: Tuple[Tuple[str, Any], ...]

    def __repr__(self) -> str:
        return (
            "RuntimeAssemblyContext("
            f"process={self.config.process.kind!r}, resources=<redacted>)"
        )


def _callable_attribute(value: Any, attribute: str) -> bool:
    return callable(getattr(value, attribute, None))


def _validate_contract(
    config: RuntimeConfiguration,
    contract: RuntimeBuildContract,
    bindings: RuntimeBindings,
) -> None:
    if not isinstance(config, RuntimeConfiguration):
        raise RuntimeCompositionError("RUNTIME_CONTRACT_MISMATCH")
    if not isinstance(contract, RuntimeBuildContract):
        raise RuntimeCompositionError("RUNTIME_CONTRACT_MISMATCH")
    if not isinstance(bindings, RuntimeBindings):
        raise RuntimeCompositionError("RUNTIME_CONTRACT_MISMATCH")
    try:
        _validate_runtime_configuration_instance(config)
    except RuntimeConfigurationError:
        raise RuntimeCompositionError("RUNTIME_CONTRACT_MISMATCH") from None
    if (
        config.schema_name != contract.schema_name
        or config.process.kind != contract.process_kind
        or tuple(config.process.capability_ids)
        != tuple(capability.capability_id for capability in contract.capabilities)
        or tuple(config.artifacts) != tuple(contract.artifacts)
        or tuple(requirement.purpose for requirement in config.key_requirements)
        != tuple(contract.required_key_purposes)
    ):
        raise RuntimeCompositionError("RUNTIME_CONTRACT_MISMATCH")

    capability_ids = tuple(
        capability.capability_id for capability in contract.capabilities
    )
    component_ids = tuple(capability.component_id for capability in contract.capabilities)
    if (
        len(capability_ids) != len(frozenset(capability_ids))
        or len(component_ids) != len(frozenset(component_ids))
        or any(not capability_id for capability_id in capability_ids)
        or any(not component_id for component_id in component_ids)
    ):
        raise RuntimeCompositionError("RUNTIME_CONTRACT_MISMATCH")

    database_contracts = tuple(
        capability
        for capability in contract.capabilities
        if capability.database_role is not None
    )
    if tuple(profile.capability_id for profile in config.database_profiles) != tuple(
        capability.capability_id for capability in database_contracts
    ):
        raise RuntimeCompositionError("RUNTIME_CONTRACT_MISMATCH")
    if any(
        profile.online_role != capability.database_role
        for profile, capability in zip(config.database_profiles, database_contracts)
    ):
        raise RuntimeCompositionError("RUNTIME_CONTRACT_MISMATCH")

    binding_ids = tuple(binding.component_id for binding in bindings.component_factories)
    if binding_ids != component_ids or len(binding_ids) != len(frozenset(binding_ids)):
        raise RuntimeCompositionError("RUNTIME_CONTRACT_MISMATCH")
    if not all(
        (
            _callable_attribute(bindings.clock, "utc_now"),
            _callable_attribute(bindings.clock, "monotonic"),
            _callable_attribute(bindings.artifact_verifier, "verify"),
            _callable_attribute(bindings.secret_provider, "resolve_credential"),
            _callable_attribute(bindings.secret_provider, "resolve_key"),
            _callable_attribute(bindings.pool_factory, "create"),
            _callable_attribute(bindings.entrypoint_factory, "create"),
        )
    ) or any(
        not _callable_attribute(binding.factory, "create")
        for binding in bindings.component_factories
    ):
        raise RuntimeCompositionError("RUNTIME_CONTRACT_MISMATCH")


def _require_managed_resource(resource: Any) -> Any:
    if not (
        _callable_attribute(resource, "check_readiness")
        and _callable_attribute(resource, "close")
    ):
        raise TypeError("managed runtime resource contract is unavailable")
    return resource


def _require_secret(secret: Any) -> Any:
    if not _callable_attribute(secret, "destroy"):
        raise TypeError("destructible secret carrier contract is unavailable")
    return secret


def _require_utc(value: Any) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise TypeError("UTC runtime clock is unavailable")
    try:
        offset = value.utcoffset()
    except BaseException:
        raise TypeError("UTC runtime clock is unavailable") from None
    if offset != timedelta(0):
        raise TypeError("UTC runtime clock is unavailable")
    return value


def _require_monotonic(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("monotonic runtime clock is unavailable")
    result = float(value)
    if not math.isfinite(result):
        raise TypeError("monotonic runtime clock is unavailable")
    return result


class _StartupClock:
    def __init__(self, clock: Any, timeout_ms: int) -> None:
        self._clock = clock
        self._last_utc = _require_utc(clock.utc_now())
        self._last_monotonic = _require_monotonic(clock.monotonic())
        if type(timeout_ms) is not int or timeout_ms <= 0:
            raise TypeError("startup timeout is unavailable")
        self._deadline = self._last_monotonic + timeout_ms / 1000.0

    def utc_now(self) -> datetime:
        current = _require_utc(self._clock.utc_now())
        if current < self._last_utc:
            raise TypeError("UTC runtime clock moved backwards")
        self._last_utc = current
        return current

    def check(self) -> float:
        current = _require_monotonic(self._clock.monotonic())
        if current < self._last_monotonic or current >= self._deadline:
            raise TimeoutError("runtime startup deadline unavailable")
        self._last_monotonic = current
        return current

    def readiness_budget_ms(self, configured_ms: int) -> int:
        current = self.check()
        if type(configured_ms) is not int or configured_ms <= 0:
            raise TypeError("readiness timeout is unavailable")
        remaining = int(
            math.floor((self._deadline - current) * 1000.0 + 1e-9)
        )
        if remaining <= 0:
            raise TimeoutError("runtime startup deadline unavailable")
        return min(configured_ms, remaining)


def _secret_window_is_valid(secret: Any, now: datetime) -> bool:
    try:
        not_before = _require_utc(secret.not_before)
        not_after = _require_utc(secret.not_after)
    except (AttributeError, TypeError):
        return False
    return not_before < not_after and not_before <= now < not_after


def _credential_binding(profile: Any) -> bytes:
    return hashlib.sha256(
        b"runtime-db-credential-v1\x00"
        + profile.capability_id.encode("utf-8")
        + b"\x00"
        + profile.online_role.encode("utf-8")
        + b"\x00"
        + profile.credential_ref.encode("utf-8")
    ).digest()


def _validate_credential_secret(secret: Any, profile: Any, now: datetime) -> None:
    expected_binding = _credential_binding(profile)
    try:
        actual_binding = bytes(secret.binding_sha256)
    except (AttributeError, TypeError, ValueError):
        raise TypeError("database credential binding is unavailable") from None
    if (
        getattr(secret, "purpose", None)
        != f"DATABASE_CREDENTIAL:{profile.capability_id}"
        or getattr(secret, "key_id", None)
        != profile.credential_ref.rsplit("#", 1)[1]
        or getattr(secret, "status", None) != "ACTIVE"
        or len(actual_binding) != 32
        or not hmac.compare_digest(actual_binding, expected_binding)
        or not _secret_window_is_valid(secret, now)
    ):
        raise TypeError("database credential facts are unavailable")


def _validate_key_secret(
    secret: Any,
    *,
    purpose: str,
    key_id: str,
    active_key_id: str,
    now: datetime,
) -> None:
    status = getattr(secret, "status", None)
    allowed_statuses = {"ACTIVE"} if key_id == active_key_id else {
        "ACTIVE",
        "VERIFY_ONLY",
    }
    if (
        getattr(secret, "purpose", None) != purpose
        or getattr(secret, "key_id", None) != key_id
        or status not in allowed_statuses
        or not _secret_window_is_valid(secret, now)
    ):
        raise TypeError("runtime key facts are unavailable")


def _close_ignoring_failure(resource: Any) -> None:
    try:
        resource.close()
    except BaseException:
        pass


def _destroy_ignoring_failure(secret: Any) -> None:
    try:
        secret.destroy()
    except BaseException:
        pass


def _cleanup_failed_startup(
    *,
    entrypoint: Any,
    components: Sequence[Tuple[str, Any]],
    pools: Sequence[Tuple[str, Any]],
    secrets: Sequence[Any],
) -> None:
    if entrypoint is not None:
        _close_ignoring_failure(entrypoint)
    for _, component in reversed(tuple(components)):
        _close_ignoring_failure(component)
    for _, pool in reversed(tuple(pools)):
        _close_ignoring_failure(pool)
    for secret in reversed(tuple(secrets)):
        _destroy_ignoring_failure(secret)


class RuntimeHandle:
    def __init__(
        self,
        *,
        entrypoint: Any,
        components: Tuple[Tuple[str, Any], ...],
        pools: Tuple[Tuple[str, Any], ...],
        secrets: Tuple[Any, ...],
    ) -> None:
        self._entrypoint = entrypoint
        self._components = components
        self._pools = pools
        self._secrets = secrets
        self._state = RuntimeState.READY
        self._close_failures: list[str] = []
        self._lock = threading.RLock()

    @property
    def state(self) -> RuntimeState:
        with self._lock:
            return self._state

    @property
    def ready(self) -> bool:
        with self._lock:
            return self._state is RuntimeState.READY

    @property
    def entrypoint(self) -> Any:
        return self._entrypoint

    @property
    def close_failures(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(self._close_failures)

    def check_readiness(self, timeout_ms: int) -> bool:
        if type(timeout_ms) is not int or timeout_ms <= 0:
            raise TypeError("readiness timeout is unavailable")
        with self._lock:
            if self._state not in (RuntimeState.READY, RuntimeState.FAILED):
                return False
            try:
                for _, pool in self._pools:
                    if pool.check_readiness(timeout_ms) is not None:
                        raise TypeError("pool readiness returned an open result")
                for _, component in self._components:
                    if component.check_readiness(timeout_ms) is not None:
                        raise TypeError("component readiness returned an open result")
                if self._entrypoint.check_readiness(timeout_ms) is not None:
                    raise TypeError("entrypoint readiness returned an open result")
            except BaseException:
                self._state = RuntimeState.FAILED
                return False
            self._state = RuntimeState.READY
            return True

    def close(self) -> None:
        with self._lock:
            if self._state in (RuntimeState.STOPPING, RuntimeState.CLOSED):
                return
            self._state = RuntimeState.STOPPING
            try:
                self._entrypoint.close()
            except BaseException:
                self._close_failures.append("ENTRYPOINT_CLOSE_FAILED")
            for component_id, component in reversed(self._components):
                try:
                    component.close()
                except BaseException:
                    self._close_failures.append(
                        f"COMPONENT_CLOSE_FAILED:{component_id}"
                    )
            for capability_id, pool in reversed(self._pools):
                try:
                    pool.close()
                except BaseException:
                    self._close_failures.append(f"POOL_CLOSE_FAILED:{capability_id}")
            for secret in reversed(self._secrets):
                try:
                    secret.destroy()
                except BaseException:
                    self._close_failures.append("SECRET_DESTROY_FAILED")
            self._state = RuntimeState.CLOSED

    def __repr__(self) -> str:
        return f"RuntimeHandle(state={self.state.value!r}, resources=<redacted>)"


def compose_runtime(
    *,
    config: RuntimeConfiguration,
    contract: RuntimeBuildContract,
    bindings: RuntimeBindings,
) -> RuntimeHandle:
    _validate_contract(config, contract, bindings)
    secrets: list[Any] = []
    pools: list[Tuple[str, Any]] = []
    components: list[Tuple[str, Any]] = []
    entrypoint: Any = None
    secret_identities: set[int] = set()
    resource_identities: set[int] = set()
    try:
        startup_clock = _StartupClock(bindings.clock, config.budgets.startup_timeout_ms)
        startup_clock.check()
        for artifact in config.artifacts:
            startup_clock.check()
            result = bindings.artifact_verifier.verify(artifact)
            if result is not None:
                raise TypeError("artifact verifier returned an open result")
            startup_clock.check()

        credential_secrets = []
        for profile in config.database_profiles:
            startup_clock.check()
            credential = _require_secret(
                bindings.secret_provider.resolve_credential(profile)
            )
            if id(credential) in secret_identities:
                raise TypeError("runtime secret carrier was aliased")
            secrets.append(credential)
            secret_identities.add(id(credential))
            _validate_credential_secret(
                credential,
                profile,
                startup_clock.utc_now(),
            )
            startup_clock.check()
            credential_secrets.append(credential)

        key_secrets: list[Tuple[str, str, Any]] = []
        for requirement in config.key_requirements:
            for key_id in requirement.retained_key_ids:
                startup_clock.check()
                secret = _require_secret(
                    bindings.secret_provider.resolve_key(requirement.purpose, key_id)
                )
                if id(secret) in secret_identities:
                    raise TypeError("runtime secret carrier was aliased")
                secrets.append(secret)
                secret_identities.add(id(secret))
                _validate_key_secret(
                    secret,
                    purpose=requirement.purpose,
                    key_id=key_id,
                    active_key_id=requirement.active_key_id,
                    now=startup_clock.utc_now(),
                )
                startup_clock.check()
                key_secrets.append((requirement.purpose, key_id, secret))

        for profile, credential in zip(
            config.database_profiles,
            credential_secrets,
        ):
            startup_clock.check()
            pool = _require_managed_resource(
                bindings.pool_factory.create(profile, credential)
            )
            if id(pool) in resource_identities:
                raise TypeError("runtime managed resource was aliased")
            pools.append((profile.capability_id, pool))
            resource_identities.add(id(pool))
            startup_clock.check()

        for binding in bindings.component_factories:
            context = RuntimeAssemblyContext(
                config=config,
                pools=tuple(pools),
                keys=tuple(key_secrets),
                components=tuple(components),
            )
            startup_clock.check()
            component = _require_managed_resource(binding.factory.create(context))
            if id(component) in resource_identities:
                raise TypeError("runtime managed resource was aliased")
            components.append((binding.component_id, component))
            resource_identities.add(id(component))
            startup_clock.check()

        for _, pool in pools:
            readiness_result = pool.check_readiness(
                startup_clock.readiness_budget_ms(
                    config.budgets.readiness_timeout_ms
                )
            )
            if readiness_result is not None:
                raise TypeError("pool readiness returned an open result")
            startup_clock.check()
        for _, component in components:
            readiness_result = component.check_readiness(
                startup_clock.readiness_budget_ms(
                    config.budgets.readiness_timeout_ms
                )
            )
            if readiness_result is not None:
                raise TypeError("component readiness returned an open result")
            startup_clock.check()

        entrypoint_context = RuntimeAssemblyContext(
            config=config,
            pools=tuple(pools),
            keys=tuple(key_secrets),
            components=tuple(components),
        )
        startup_clock.check()
        candidate_entrypoint = _require_managed_resource(
            bindings.entrypoint_factory.create(entrypoint_context)
        )
        if id(candidate_entrypoint) in resource_identities:
            raise TypeError("runtime managed resource was aliased")
        entrypoint = candidate_entrypoint
        resource_identities.add(id(entrypoint))
        startup_clock.check()
        readiness_result = entrypoint.check_readiness(
            startup_clock.readiness_budget_ms(config.budgets.readiness_timeout_ms)
        )
        if readiness_result is not None:
            raise TypeError("entrypoint readiness returned an open result")
        startup_clock.check()
        return RuntimeHandle(
            entrypoint=entrypoint,
            components=tuple(components),
            pools=tuple(pools),
            secrets=tuple(secrets),
        )
    except BaseException:
        _cleanup_failed_startup(
            entrypoint=entrypoint,
            components=components,
            pools=pools,
            secrets=secrets,
        )
        raise RuntimeCompositionError("RUNTIME_STARTUP_FAILED") from None
