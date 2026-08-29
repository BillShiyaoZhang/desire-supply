from __future__ import annotations

import hashlib
import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from typing import Optional

from desire_platform.runtime.composition import (
    ComponentFactoryBinding,
    RuntimeBindings,
    RuntimeBuildContract,
    RuntimeCapabilityContract,
    RuntimeCompositionError,
    RuntimeState,
    compose_runtime,
)
from desire_platform.runtime.config import (
    ArtifactRequirement,
    DatabaseProfile,
    KeyRequirement,
    ProcessConfiguration,
    RuntimeBudgets,
    RuntimeConfiguration,
    RuntimeIdentity,
)


RAW_SECRET = b"runtime-secret-sentinel-never-log"
NOW = datetime(2026, 8, 8, 8, 0, tzinfo=timezone.utc)


class _Clock:
    def __init__(self, *, now: datetime = NOW) -> None:
        self.now = now
        self.elapsed = 0.0

    def utc_now(self) -> datetime:
        return self.now

    def monotonic(self) -> float:
        return self.elapsed

    def advance(self, seconds: float) -> None:
        self.elapsed += seconds


def _credential_binding(profile: DatabaseProfile) -> bytes:
    return hashlib.sha256(
        b"runtime-db-credential-v1\x00"
        + profile.capability_id.encode("utf-8")
        + b"\x00"
        + profile.online_role.encode("utf-8")
        + b"\x00"
        + profile.credential_ref.encode("utf-8")
    ).digest()


def _config() -> RuntimeConfiguration:
    return RuntimeConfiguration(
        schema_name="desire-runtime-config-v1",
        identity=RuntimeIdentity(
            environment_id="production-cn",
            deployment_id="deploy-20260808",
            release_id="release-20260808-1",
            region="cn-east-1",
            instance_id="web-api-0001",
        ),
        process=ProcessConfiguration(
            kind="web-api",
            capability_ids=("IAM_HTTP", "PROFILE_SELF"),
        ),
        artifacts=(
            ArtifactRequirement("iam-openapi-v1", "a" * 64),
            ArtifactRequirement("profile-openapi-v1", "b" * 64),
        ),
        database_profiles=(
            DatabaseProfile(
                capability_id="IAM_HTTP",
                online_role="iam_app",
                credential_ref="secret://prod-db/iam-web#2026-08",
                application_name="desire-web-iam",
                max_pool_size=8,
                checkout_timeout_ms=500,
                statement_timeout_ms=5000,
                lock_timeout_ms=500,
                idle_in_transaction_timeout_ms=5000,
            ),
            DatabaseProfile(
                capability_id="PROFILE_SELF",
                online_role="profile_app",
                credential_ref="secret://prod-db/profile-web#2026-08",
                application_name="desire-web-profile",
                max_pool_size=4,
                checkout_timeout_ms=500,
                statement_timeout_ms=5000,
                lock_timeout_ms=500,
                idle_in_transaction_timeout_ms=5000,
            ),
        ),
        key_requirements=(
            KeyRequirement(
                purpose="SESSION_HANDLE",
                active_key_id="session-2026-08",
                retained_key_ids=("session-2026-07", "session-2026-08"),
            ),
            KeyRequirement(
                purpose="CSRF",
                active_key_id="csrf-2026-08",
                retained_key_ids=("csrf-2026-08",),
            ),
        ),
        budgets=RuntimeBudgets(
            startup_timeout_ms=30000,
            readiness_timeout_ms=2000,
            shutdown_timeout_ms=15000,
        ),
    )


def _contract() -> RuntimeBuildContract:
    return RuntimeBuildContract(
        schema_name="desire-runtime-config-v1",
        process_kind="web-api",
        capabilities=(
            RuntimeCapabilityContract("IAM_HTTP", "iam-http", "iam_app"),
            RuntimeCapabilityContract(
                "PROFILE_SELF", "profile-self", "profile_app"
            ),
        ),
        artifacts=(
            ArtifactRequirement("iam-openapi-v1", "a" * 64),
            ArtifactRequirement("profile-openapi-v1", "b" * 64),
        ),
        required_key_purposes=("SESSION_HANDLE", "CSRF"),
    )


class _ArtifactVerifier:
    def __init__(self, events: list[str], fail_on: Optional[str] = None) -> None:
        self.events = events
        self.fail_on = fail_on

    def verify(self, artifact: ArtifactRequirement) -> None:
        self.events.append(f"artifact:{artifact.artifact_id}")
        if artifact.artifact_id == self.fail_on:
            raise RuntimeError(RAW_SECRET.decode("ascii"))


class _Secret:
    def __init__(
        self,
        label: str,
        events: list[str],
        *,
        purpose: str,
        key_id: str,
        binding_sha256: Optional[bytes] = None,
        not_before: datetime = NOW - timedelta(days=1),
        not_after: datetime = NOW + timedelta(days=30),
        status: str = "ACTIVE",
    ) -> None:
        self.label = label
        self.events = events
        self.purpose = purpose
        self.key_id = key_id
        self.binding_sha256 = binding_sha256
        self.not_before = not_before
        self.not_after = not_after
        self.status = status
        self.material = bytearray(RAW_SECRET)
        self.destroyed = False

    def destroy(self) -> None:
        self.events.append(f"destroy:{self.label}")
        for index in range(len(self.material)):
            self.material[index] = 0
        self.destroyed = True

    def __repr__(self) -> str:
        return f"_Secret(label={self.label!r}, material=<redacted>)"


class _SecretProvider:
    def __init__(
        self,
        events: list[str],
        fail_label: Optional[str] = None,
        mutator: Optional[object] = None,
    ) -> None:
        self.events = events
        self.fail_label = fail_label
        self.mutator = mutator
        self.created: list[_Secret] = []

    def _finish(self, secret: _Secret) -> _Secret:
        if callable(self.mutator):
            secret = self.mutator(secret)
        if secret not in self.created:
            self.created.append(secret)
        return secret

    def resolve_credential(self, profile: DatabaseProfile) -> _Secret:
        label = f"credential:{profile.capability_id}"
        self.events.append(f"resolve:{label}")
        if label == self.fail_label:
            raise RuntimeError(RAW_SECRET.decode("ascii"))
        return self._finish(
            _Secret(
                label,
                self.events,
                purpose=f"DATABASE_CREDENTIAL:{profile.capability_id}",
                key_id=profile.credential_ref.rsplit("#", 1)[1],
                binding_sha256=_credential_binding(profile),
            )
        )

    def resolve_key(self, purpose: str, key_id: str) -> _Secret:
        label = f"key:{purpose}:{key_id}"
        self.events.append(f"resolve:{label}")
        if label == self.fail_label:
            raise RuntimeError(RAW_SECRET.decode("ascii"))
        return self._finish(
            _Secret(
                label,
                self.events,
                purpose=purpose,
                key_id=key_id,
            )
        )


class _Resource:
    def __init__(
        self,
        label: str,
        events: list[str],
        *,
        fail_readiness: bool = False,
        fail_close: bool = False,
    ) -> None:
        self.label = label
        self.events = events
        self.fail_readiness = fail_readiness
        self.fail_close = fail_close
        self.closed = False

    def check_readiness(self, timeout_ms: int) -> None:
        self.events.append(f"ready:{self.label}:{timeout_ms}")
        if self.fail_readiness:
            raise RuntimeError(RAW_SECRET.decode("ascii"))

    def close(self) -> None:
        self.events.append(f"close:{self.label}")
        self.closed = True
        if self.fail_close:
            raise RuntimeError(RAW_SECRET.decode("ascii"))

    def __repr__(self) -> str:
        return f"_Resource(label={self.label!r})"


class _PoolFactory:
    def __init__(self, events: list[str], fail_on: Optional[str] = None) -> None:
        self.events = events
        self.fail_on = fail_on

    def create(self, profile: DatabaseProfile, credential: _Secret) -> _Resource:
        self.events.append(f"create:pool:{profile.capability_id}")
        if profile.capability_id == self.fail_on:
            raise RuntimeError(RAW_SECRET.decode("ascii"))
        if credential.destroyed:
            raise AssertionError("credential destroyed before pool creation")
        return _Resource(f"pool:{profile.capability_id}", self.events)


class _ComponentFactory:
    def __init__(
        self,
        component_id: str,
        events: list[str],
        *,
        fail_create: bool = False,
        fail_readiness: bool = False,
        fail_close: bool = False,
    ) -> None:
        self.component_id = component_id
        self.events = events
        self.fail_create = fail_create
        self.fail_readiness = fail_readiness
        self.fail_close = fail_close

    def create(self, context: object) -> _Resource:
        self.events.append(f"create:component:{self.component_id}")
        if self.fail_create:
            raise RuntimeError(RAW_SECRET.decode("ascii"))
        self.last_context = context
        return _Resource(
            f"component:{self.component_id}",
            self.events,
            fail_readiness=self.fail_readiness,
            fail_close=self.fail_close,
        )


class _EntrypointFactory:
    def __init__(
        self,
        events: list[str],
        *,
        fail_create: bool = False,
        fail_readiness: bool = False,
        fail_close: bool = False,
    ) -> None:
        self.events = events
        self.fail_create = fail_create
        self.fail_readiness = fail_readiness
        self.fail_close = fail_close

    def create(self, context: object) -> _Resource:
        self.events.append("create:entrypoint")
        if self.fail_create:
            raise RuntimeError(RAW_SECRET.decode("ascii"))
        self.last_context = context
        return _Resource(
            "entrypoint",
            self.events,
            fail_readiness=self.fail_readiness,
            fail_close=self.fail_close,
        )


def _bindings(
    events: list[str],
    *,
    artifact_fail: Optional[str] = None,
    secret_fail: Optional[str] = None,
    pool_fail: Optional[str] = None,
    component_fail_create: Optional[str] = None,
    component_fail_readiness: Optional[str] = None,
    component_fail_close: Optional[str] = None,
    entrypoint_fail_create: bool = False,
    entrypoint_fail_readiness: bool = False,
    entrypoint_fail_close: bool = False,
    clock: Optional[_Clock] = None,
    secret_mutator: Optional[object] = None,
) -> tuple[RuntimeBindings, _SecretProvider]:
    secrets = _SecretProvider(events, secret_fail, secret_mutator)
    factories = tuple(
        ComponentFactoryBinding(
            component_id,
            _ComponentFactory(
                component_id,
                events,
                fail_create=component_id == component_fail_create,
                fail_readiness=component_id == component_fail_readiness,
                fail_close=component_id == component_fail_close,
            ),
        )
        for component_id in ("iam-http", "profile-self")
    )
    return (
        RuntimeBindings(
            clock=clock or _Clock(),
            artifact_verifier=_ArtifactVerifier(events, artifact_fail),
            secret_provider=secrets,
            pool_factory=_PoolFactory(events, pool_fail),
            component_factories=factories,
            entrypoint_factory=_EntrypointFactory(
                events,
                fail_create=entrypoint_fail_create,
                fail_readiness=entrypoint_fail_readiness,
                fail_close=entrypoint_fail_close,
            ),
        ),
        secrets,
    )


class RuntimeCompositionTests(unittest.TestCase):
    def test_contracts_are_frozen_and_exact_success_becomes_ready(self) -> None:
        contract = _contract()
        with self.assertRaises(FrozenInstanceError):
            contract.process_kind = "migration"  # type: ignore[misc]
        events: list[str] = []
        bindings, secrets = _bindings(events)
        try:
            handle = compose_runtime(
                config=_config(),
                contract=contract,
                bindings=bindings,
            )
        except RuntimeCompositionError as error:
            self.assertEqual(
                ("ready", None),
                ("error", error.code),
                "semantic RED: exact production bindings must become ready",
            )
            return
        self.assertEqual(handle.state, RuntimeState.READY)
        self.assertTrue(handle.ready)
        self.assertEqual(handle.entrypoint.label, "entrypoint")
        self.assertNotIn(RAW_SECRET.decode("ascii"), repr(handle))
        self.assertEqual(
            events,
            [
                "artifact:iam-openapi-v1",
                "artifact:profile-openapi-v1",
                "resolve:credential:IAM_HTTP",
                "resolve:credential:PROFILE_SELF",
                "resolve:key:SESSION_HANDLE:session-2026-07",
                "resolve:key:SESSION_HANDLE:session-2026-08",
                "resolve:key:CSRF:csrf-2026-08",
                "create:pool:IAM_HTTP",
                "create:pool:PROFILE_SELF",
                "create:component:iam-http",
                "create:component:profile-self",
                "ready:pool:IAM_HTTP:2000",
                "ready:pool:PROFILE_SELF:2000",
                "ready:component:iam-http:2000",
                "ready:component:profile-self:2000",
                "create:entrypoint",
                "ready:entrypoint:2000",
            ],
        )
        self.assertTrue(all(not secret.destroyed for secret in secrets.created))

    def test_config_build_contract_and_bindings_mismatch_fail_before_side_effects(self) -> None:
        config = _config()
        contract = _contract()
        mismatch_cases = []
        mismatch_cases.append(
            (
                RuntimeConfiguration(
                    **{
                        **config.__dict__,
                        "process": ProcessConfiguration(
                            "web-api", ("PROFILE_SELF", "IAM_HTTP")
                        ),
                    }
                ),
                contract,
                None,
            )
        )
        wrong_role_profiles = list(config.database_profiles)
        wrong_role_profiles[0] = DatabaseProfile(
            **{**wrong_role_profiles[0].__dict__, "online_role": "schema_owner"}
        )
        mismatch_cases.append(
            (
                RuntimeConfiguration(
                    **{
                        **config.__dict__,
                        "database_profiles": tuple(wrong_role_profiles),
                    }
                ),
                contract,
                None,
            )
        )
        mismatch_cases.append(
            (
                RuntimeConfiguration(
                    **{
                        **config.__dict__,
                        "artifacts": (config.artifacts[0],),
                    }
                ),
                contract,
                None,
            )
        )
        mismatch_cases.append(
            (
                RuntimeConfiguration(
                    **{
                        **config.__dict__,
                        "key_requirements": (config.key_requirements[0],),
                    }
                ),
                contract,
                None,
            )
        )
        for index, (candidate, expected_contract, _) in enumerate(mismatch_cases):
            with self.subTest(case=index):
                events: list[str] = []
                bindings, _ = _bindings(events)
                with self.assertRaises(RuntimeCompositionError) as raised:
                    compose_runtime(
                        config=candidate,
                        contract=expected_contract,
                        bindings=bindings,
                    )
                self.assertEqual(raised.exception.code, "RUNTIME_CONTRACT_MISMATCH")
                self.assertEqual(events, [])

        events = []
        bindings, _ = _bindings(events)
        bindings = RuntimeBindings(
            clock=bindings.clock,
            artifact_verifier=bindings.artifact_verifier,
            secret_provider=bindings.secret_provider,
            pool_factory=bindings.pool_factory,
            component_factories=bindings.component_factories[:1],
            entrypoint_factory=bindings.entrypoint_factory,
        )
        with self.assertRaises(RuntimeCompositionError) as raised:
            compose_runtime(config=config, contract=contract, bindings=bindings)
        self.assertEqual(raised.exception.code, "RUNTIME_CONTRACT_MISMATCH")
        self.assertEqual(events, [])

    def test_each_startup_failure_cleans_all_constructed_resources_in_reverse(self) -> None:
        scenarios = (
            ("artifact", {"artifact_fail": "profile-openapi-v1"}),
            ("secret", {"secret_fail": "key:SESSION_HANDLE:session-2026-08"}),
            ("pool", {"pool_fail": "PROFILE_SELF"}),
            ("component-create", {"component_fail_create": "profile-self"}),
            ("component-ready", {"component_fail_readiness": "profile-self"}),
            ("entrypoint-create", {"entrypoint_fail_create": True}),
            ("entrypoint-ready", {"entrypoint_fail_readiness": True}),
        )
        for name, options in scenarios:
            with self.subTest(scenario=name):
                events: list[str] = []
                bindings, secrets = _bindings(events, **options)
                with self.assertRaises(RuntimeCompositionError) as raised:
                    compose_runtime(
                        config=_config(),
                        contract=_contract(),
                        bindings=bindings,
                    )
                self.assertEqual(raised.exception.code, "RUNTIME_STARTUP_FAILED")
                self.assertNotIn(RAW_SECRET.decode("ascii"), repr(raised.exception))
                self.assertTrue(all(secret.destroyed for secret in secrets.created))
                close_events = [event for event in events if event.startswith("close:")]
                if "create:entrypoint" in events and name == "entrypoint-ready":
                    self.assertEqual(close_events[0], "close:entrypoint")
                component_closes = [
                    event for event in close_events if event.startswith("close:component:")
                ]
                self.assertEqual(
                    component_closes,
                    sorted(component_closes, reverse=True),
                )
                pool_closes = [
                    event for event in close_events if event.startswith("close:pool:")
                ]
                self.assertEqual(pool_closes, sorted(pool_closes, reverse=True))
                destroy_events = [
                    event for event in events if event.startswith("destroy:")
                ]
                self.assertEqual(
                    destroy_events,
                    [f"destroy:{secret.label}" for secret in reversed(secrets.created)],
                )

    def test_close_is_reverse_order_idempotent_and_continues_after_close_failure(self) -> None:
        events: list[str] = []
        bindings, secrets = _bindings(
            events,
            component_fail_close="profile-self",
            entrypoint_fail_close=True,
        )
        try:
            handle = compose_runtime(
                config=_config(),
                contract=_contract(),
                bindings=bindings,
            )
        except RuntimeCompositionError as error:
            self.assertEqual(
                ("ready", None),
                ("error", error.code),
                "semantic RED: close behavior requires a successfully built runtime",
            )
            return
        events.clear()
        handle.close()
        self.assertEqual(handle.state, RuntimeState.CLOSED)
        self.assertFalse(handle.ready)
        self.assertEqual(
            events[:5],
            [
                "close:entrypoint",
                "close:component:profile-self",
                "close:component:iam-http",
                "close:pool:PROFILE_SELF",
                "close:pool:IAM_HTTP",
            ],
        )
        self.assertEqual(
            handle.close_failures,
            ("ENTRYPOINT_CLOSE_FAILED", "COMPONENT_CLOSE_FAILED:profile-self"),
        )
        self.assertTrue(all(secret.destroyed for secret in secrets.created))
        first_events = list(events)
        handle.close()
        self.assertEqual(events, first_events)

    def test_secret_metadata_window_binding_and_carrier_identity_fail_closed(self) -> None:
        def mutate_named(label: str, attribute: str, value: object):
            def mutate(secret: _Secret) -> _Secret:
                if secret.label == label:
                    setattr(secret, attribute, value)
                return secret

            return mutate

        shared: list[Optional[_Secret]] = [None]

        def reuse_key_carrier(secret: _Secret) -> _Secret:
            if not secret.label.startswith("key:"):
                return secret
            if shared[0] is None:
                shared[0] = secret
            return shared[0]

        cases = (
            mutate_named(
                "credential:IAM_HTTP",
                "purpose",
                "DATABASE_CREDENTIAL:PROFILE_SELF",
            ),
            mutate_named("credential:IAM_HTTP", "key_id", "wrong-version"),
            mutate_named("credential:IAM_HTTP", "binding_sha256", b"x" * 32),
            mutate_named("key:SESSION_HANDLE:session-2026-08", "purpose", "CSRF"),
            mutate_named("key:SESSION_HANDLE:session-2026-08", "key_id", "wrong"),
            mutate_named(
                "key:SESSION_HANDLE:session-2026-08",
                "status",
                "VERIFY_ONLY",
            ),
            mutate_named(
                "key:SESSION_HANDLE:session-2026-07",
                "not_after",
                NOW,
            ),
            mutate_named(
                "key:SESSION_HANDLE:session-2026-07",
                "not_before",
                NOW + timedelta(seconds=1),
            ),
            mutate_named(
                "key:SESSION_HANDLE:session-2026-07",
                "not_before",
                NOW.replace(tzinfo=None),
            ),
            mutate_named(
                "key:SESSION_HANDLE:session-2026-07",
                "not_before",
                NOW.astimezone(timezone(timedelta(hours=8))),
            ),
            reuse_key_carrier,
        )
        for index, mutator in enumerate(cases):
            with self.subTest(case=index):
                shared[0] = None
                events: list[str] = []
                bindings, secrets = _bindings(events, secret_mutator=mutator)
                try:
                    handle = compose_runtime(
                        config=_config(),
                        contract=_contract(),
                        bindings=bindings,
                    )
                except RuntimeCompositionError as error:
                    self.assertEqual(error.code, "RUNTIME_STARTUP_FAILED")
                    self.assertNotIn(RAW_SECRET.decode("ascii"), repr(error))
                    self.assertTrue(all(secret.destroyed for secret in secrets.created))
                else:
                    handle.close()
                    self.fail("semantic RED: malformed or aliased secret was accepted")

    def test_pool_and_component_capabilities_cannot_alias_one_resource(self) -> None:
        class ReusingPoolFactory:
            def __init__(self, events: list[str]) -> None:
                self.events = events
                self.resource: Optional[_Resource] = None

            def create(self, profile: DatabaseProfile, credential: _Secret) -> _Resource:
                del credential
                self.events.append(f"create:pool:{profile.capability_id}")
                if self.resource is None:
                    self.resource = _Resource("pool:shared", self.events)
                return self.resource

        class ReusingComponentFactory:
            def __init__(self, events: list[str]) -> None:
                self.events = events
                self.resource: Optional[_Resource] = None

            def create(self, context: object) -> _Resource:
                del context
                self.events.append("create:component:shared")
                if self.resource is None:
                    self.resource = _Resource("component:shared", self.events)
                return self.resource

        for kind in ("pool", "component"):
            with self.subTest(kind=kind):
                events: list[str] = []
                bindings, _ = _bindings(events)
                if kind == "pool":
                    bindings = RuntimeBindings(
                        clock=bindings.clock,
                        artifact_verifier=bindings.artifact_verifier,
                        secret_provider=bindings.secret_provider,
                        pool_factory=ReusingPoolFactory(events),
                        component_factories=bindings.component_factories,
                        entrypoint_factory=bindings.entrypoint_factory,
                    )
                else:
                    shared_factory = ReusingComponentFactory(events)
                    bindings = RuntimeBindings(
                        clock=bindings.clock,
                        artifact_verifier=bindings.artifact_verifier,
                        secret_provider=bindings.secret_provider,
                        pool_factory=bindings.pool_factory,
                        component_factories=(
                            ComponentFactoryBinding("iam-http", shared_factory),
                            ComponentFactoryBinding("profile-self", shared_factory),
                        ),
                        entrypoint_factory=bindings.entrypoint_factory,
                    )
                try:
                    handle = compose_runtime(
                        config=_config(), contract=_contract(), bindings=bindings
                    )
                except RuntimeCompositionError as error:
                    self.assertEqual(error.code, "RUNTIME_STARTUP_FAILED")
                else:
                    handle.close()
                    self.fail("semantic RED: capability resources were aliased")

    def test_utc_and_monotonic_startup_deadlines_are_enforced(self) -> None:
        invalid_clocks = (
            _Clock(now=NOW.replace(tzinfo=None)),
            _Clock(now=NOW.astimezone(timezone(timedelta(hours=8)))),
        )
        for clock in invalid_clocks:
            with self.subTest(now=repr(clock.now)):
                events: list[str] = []
                bindings, _ = _bindings(events, clock=clock)
                try:
                    handle = compose_runtime(
                        config=_config(), contract=_contract(), bindings=bindings
                    )
                except RuntimeCompositionError as error:
                    self.assertEqual(error.code, "RUNTIME_STARTUP_FAILED")
                    self.assertEqual(events, [])
                else:
                    handle.close()
                    self.fail("semantic RED: invalid UTC clock was accepted")

        clock = _Clock()

        class AdvancingVerifier(_ArtifactVerifier):
            def verify(self, artifact: ArtifactRequirement) -> None:
                super().verify(artifact)
                clock.advance(0.100)

        config = RuntimeConfiguration(
            **{
                **_config().__dict__,
                "budgets": RuntimeBudgets(
                    startup_timeout_ms=100,
                    readiness_timeout_ms=2000,
                    shutdown_timeout_ms=100,
                ),
            }
        )
        events = []
        bindings, secrets = _bindings(events, clock=clock)
        bindings = RuntimeBindings(
            clock=clock,
            artifact_verifier=AdvancingVerifier(events),
            secret_provider=bindings.secret_provider,
            pool_factory=bindings.pool_factory,
            component_factories=bindings.component_factories,
            entrypoint_factory=bindings.entrypoint_factory,
        )
        try:
            handle = compose_runtime(config=config, contract=_contract(), bindings=bindings)
        except RuntimeCompositionError as error:
            self.assertEqual(error.code, "RUNTIME_STARTUP_FAILED")
            self.assertEqual(events, ["artifact:iam-openapi-v1"])
            self.assertEqual(secrets.created, [])
        else:
            handle.close()
            self.fail("semantic RED: exclusive startup deadline was ignored")

    def test_readiness_receives_only_the_remaining_startup_budget(self) -> None:
        clock = _Clock()

        class AdvancingVerifier(_ArtifactVerifier):
            def verify(self, artifact: ArtifactRequirement) -> None:
                super().verify(artifact)
                if artifact.artifact_id == "iam-openapi-v1":
                    clock.advance(0.025)

        config = RuntimeConfiguration(
            **{
                **_config().__dict__,
                "budgets": RuntimeBudgets(
                    startup_timeout_ms=100,
                    readiness_timeout_ms=2000,
                    shutdown_timeout_ms=100,
                ),
            }
        )
        events: list[str] = []
        bindings, _ = _bindings(events, clock=clock)
        bindings = RuntimeBindings(
            clock=clock,
            artifact_verifier=AdvancingVerifier(events),
            secret_provider=bindings.secret_provider,
            pool_factory=bindings.pool_factory,
            component_factories=bindings.component_factories,
            entrypoint_factory=bindings.entrypoint_factory,
        )
        handle = compose_runtime(config=config, contract=_contract(), bindings=bindings)
        try:
            readiness = [event for event in events if event.startswith("ready:")]
            self.assertEqual(
                readiness,
                [
                    "ready:pool:IAM_HTTP:75",
                    "ready:pool:PROFILE_SELF:75",
                    "ready:component:iam-http:75",
                    "ready:component:profile-self:75",
                    "ready:entrypoint:75",
                ],
                "semantic RED: readiness received a fresh budget instead of remaining time",
            )
        finally:
            handle.close()

    def test_manually_constructed_invalid_facts_cannot_bypass_the_parser(self) -> None:
        base_config = _config()
        base_contract = _contract()
        active_not_retained = RuntimeConfiguration(
            **{
                **base_config.__dict__,
                "key_requirements": (
                    KeyRequirement(
                        purpose="SESSION_HANDLE",
                        active_key_id="session-2026-08",
                        retained_key_ids=("session-2026-07",),
                    ),
                    base_config.key_requirements[1],
                ),
            }
        )
        duplicate_retained = RuntimeConfiguration(
            **{
                **base_config.__dict__,
                "key_requirements": (
                    KeyRequirement(
                        purpose="SESSION_HANDLE",
                        active_key_id="session-2026-08",
                        retained_key_ids=("session-2026-08", "session-2026-08"),
                    ),
                    base_config.key_requirements[1],
                ),
            }
        )
        shared_profiles = list(base_config.database_profiles)
        shared_profiles[1] = DatabaseProfile(
            **{
                **shared_profiles[1].__dict__,
                "credential_ref": shared_profiles[0].credential_ref,
            }
        )
        shared_credential = RuntimeConfiguration(
            **{**base_config.__dict__, "database_profiles": tuple(shared_profiles)}
        )
        invalid_artifact = ArtifactRequirement("iam-openapi-v1", "not-a-digest")
        invalid_artifacts = (invalid_artifact, base_config.artifacts[1])
        invalid_artifact_config = RuntimeConfiguration(
            **{**base_config.__dict__, "artifacts": invalid_artifacts}
        )
        invalid_artifact_contract = RuntimeBuildContract(
            **{**base_contract.__dict__, "artifacts": invalid_artifacts}
        )
        cases = (
            (active_not_retained, base_contract),
            (duplicate_retained, base_contract),
            (shared_credential, base_contract),
            (invalid_artifact_config, invalid_artifact_contract),
        )
        for index, (config, contract) in enumerate(cases):
            with self.subTest(case=index):
                events: list[str] = []
                bindings, _ = _bindings(events)
                try:
                    handle = compose_runtime(
                        config=config,
                        contract=contract,
                        bindings=bindings,
                    )
                except RuntimeCompositionError as error:
                    self.assertEqual(error.code, "RUNTIME_CONTRACT_MISMATCH")
                    self.assertEqual(events, [])
                else:
                    handle.close()
                    self.fail("semantic RED: a manually-invalid config bypassed parsing")

    def test_false_or_open_readiness_result_cannot_publish_ready(self) -> None:
        class FalseReadyResource(_Resource):
            def check_readiness(self, timeout_ms: int) -> bool:
                self.events.append(f"ready:{self.label}:{timeout_ms}")
                return False

        class FalseReadyPoolFactory(_PoolFactory):
            def create(
                self, profile: DatabaseProfile, credential: _Secret
            ) -> _Resource:
                del credential
                self.events.append(f"create:pool:{profile.capability_id}")
                return FalseReadyResource(f"pool:{profile.capability_id}", self.events)

        events: list[str] = []
        bindings, _ = _bindings(events)
        bindings = RuntimeBindings(
            clock=bindings.clock,
            artifact_verifier=bindings.artifact_verifier,
            secret_provider=bindings.secret_provider,
            pool_factory=FalseReadyPoolFactory(events),
            component_factories=bindings.component_factories,
            entrypoint_factory=bindings.entrypoint_factory,
        )
        try:
            handle = compose_runtime(
                config=_config(), contract=_contract(), bindings=bindings
            )
        except RuntimeCompositionError as error:
            self.assertEqual(error.code, "RUNTIME_STARTUP_FAILED")
        else:
            handle.close()
            self.fail("semantic RED: false readiness was treated as READY")


if __name__ == "__main__":
    unittest.main()
