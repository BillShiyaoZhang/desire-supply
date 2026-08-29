from __future__ import annotations

import io
import importlib.util
import json
import os
import sys
import unittest
from unittest.mock import patch
from uuid import UUID

import desire_platform.internal_pilot.api_server as api_server_module
from desire_platform.internal_pilot.api_server import (
    DEFAULT_DEPENDENCY_FACTORY,
    InternalSandboxApiServerPlan,
    main,
)
from desire_platform.internal_pilot.deployment_config import (
    InternalSandboxBindSettings,
    InternalSandboxDeploymentConfiguration,
    InternalSandboxOidcNetworkBinding,
    InternalSandboxOidcSettings,
    OIDC_NETWORK_BINDING_SYSTEM_DNS_SYNTHETIC,
)
from desire_platform.internal_pilot.postgres_pool import PostgresEndpointSettings
from desire_platform.internal_pilot.runtime import (
    InternalSandboxApiApplication,
    InternalSandboxRuntime,
)


class _Application:
    async def __call__(self, scope, receive, send):
        del scope, receive, send


class _Resource:
    def __init__(self, *, fails: bool = False) -> None:
        self.fails = fails
        self.closed = False

    def check_readiness(self, *, timeout_ms):
        if self.closed or self.fails or timeout_ms < 1:
            raise RuntimeError("sensitive dependency detail")
        return None

    def close(self):
        self.closed = True


def _runtime(resource: _Resource) -> InternalSandboxRuntime:
    return InternalSandboxRuntime(
        application=_Application(),
        managed_resources=(resource,),
        readiness_timeout_ms=500,
    )


def _plan(resource: _Resource) -> InternalSandboxApiServerPlan:
    return InternalSandboxApiServerPlan(
        runtime=_runtime(resource),
        graceful_shutdown_timeout_seconds=15,
        deployment=InternalSandboxDeploymentConfiguration(
            schema_name="desire-internal-sandbox-deployment-v1",
            deployment_mode="INTERNAL_SANDBOX",
            external_participants_enabled=False,
            internal_bff_origin="http://api:8000",
            runtime_config_path="/run/desire/runtime-config.json",
            secret_manifest_path="/run/desire/secret-manifest.json",
            secret_root="/run/secrets",
            postgres=PostgresEndpointSettings(
                host="db",
                port=5432,
                database="desire",
                transport_security="TRUSTED_CONTAINER_NETWORK",
            ),
            oidc=InternalSandboxOidcSettings(
                issuer="https://identity.example.test/tenant",
                client_id="desire-internal-sandbox",
                client_secret_key_id="client-v1",
                redirect_uri="https://pilot.example.test/v1/auth/oidc/callback",
                allowed_signing_algorithms=("RS256",),
                metadata_ttl_seconds=300,
                request_timeout_seconds=3,
                maximum_response_bytes=262_144,
                clock_skew_seconds=30,
                subject_digest_key_id="subject-v1",
                network_binding=InternalSandboxOidcNetworkBinding(
                    mode=OIDC_NETWORK_BINDING_SYSTEM_DNS_SYNTHETIC,
                    pinned_public_ipv4=None,
                ),
            ),
            system_actor_id=UUID("10000000-0000-4000-8000-000000000001"),
            bind=InternalSandboxBindSettings(host="0.0.0.0", port=8000),
        ),
    )


class InternalSandboxApiServerTests(unittest.TestCase):
    def test_module_entrypoint_accepts_the_production_plan_type(self) -> None:
        module_name = "desire_platform.internal_pilot.__entrypoint_test__"
        spec = importlib.util.spec_from_file_location(
            module_name,
            api_server_module.__file__,
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        entrypoint_module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = entrypoint_module
        self.addCleanup(sys.modules.pop, module_name, None)
        spec.loader.exec_module(entrypoint_module)
        resource = _Resource()
        calls = []
        stderr = io.StringIO()

        result = entrypoint_module.main(
            [],
            dependency_factory=lambda: _plan(resource),
            server_runner=lambda *args, **kwargs: calls.append((args, kwargs)),
            stderr=stderr,
        )

        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(len(calls), 1)
        self.assertTrue(resource.closed)

    def test_default_cli_uses_the_closed_production_factory(self) -> None:
        self.assertTrue(callable(DEFAULT_DEPENDENCY_FACTORY))
        self.assertEqual(
            DEFAULT_DEPENDENCY_FACTORY.__name__,
            "_default_dependency_factory",
        )

    def test_default_cli_without_the_single_pointer_exits_before_server(self) -> None:
        stderr = io.StringIO()
        calls = []
        with patch.dict(os.environ, {}, clear=True):
            result = main(
                [],
                server_runner=lambda *args, **kwargs: calls.append((args, kwargs)),
                stderr=stderr,
            )

        self.assertEqual(result, 78)
        self.assertEqual(calls, [])
        self.assertEqual(
            json.loads(stderr.getvalue()),
            {"code": "INTERNAL_SANDBOX_STARTUP_FAILED", "status": "BLOCKED"},
        )

    def test_missing_composition_exits_before_importing_or_calling_server(self) -> None:
        stderr = io.StringIO()
        calls = []

        result = main(
            [],
            dependency_factory=None,
            server_runner=lambda *args, **kwargs: calls.append((args, kwargs)),
            stderr=stderr,
        )

        self.assertEqual(result, 78)
        self.assertEqual(calls, [])
        self.assertEqual(
            json.loads(stderr.getvalue()),
            {
                "code": "INTERNAL_SANDBOX_COMPOSITION_UNAVAILABLE",
                "status": "BLOCKED",
            },
        )

    def test_readiness_failure_never_calls_server_or_reflects_error(self) -> None:
        stderr = io.StringIO()
        resource = _Resource(fails=True)
        calls = []

        result = main(
            [],
            dependency_factory=lambda: _plan(resource),
            server_runner=lambda *args, **kwargs: calls.append((args, kwargs)),
            stderr=stderr,
        )

        self.assertEqual(result, 78)
        self.assertEqual(calls, [])
        self.assertTrue(resource.closed)
        self.assertNotIn("sensitive dependency detail", stderr.getvalue())

    def test_preflights_before_server_and_uses_closed_uvicorn_settings(self) -> None:
        stderr = io.StringIO()
        resource = _Resource()
        calls = []

        def server_runner(application, **settings):
            calls.append((application, settings, resource.closed))

        result = main(
            [],
            dependency_factory=lambda: _plan(resource),
            server_runner=server_runner,
            stderr=stderr,
        )

        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(len(calls), 1)
        application, settings, was_closed = calls[0]
        self.assertIsInstance(application, InternalSandboxApiApplication)
        self.assertFalse(was_closed)
        self.assertEqual(
            settings,
            {
                "host": "0.0.0.0",
                "port": 8000,
                "access_log": False,
                "log_level": "warning",
                "proxy_headers": False,
                "server_header": False,
                "lifespan": "on",
                "timeout_graceful_shutdown": 15,
            },
        )
        self.assertTrue(resource.closed)

    def test_graceful_shutdown_timeout_is_closed(self) -> None:
        resource = _Resource()
        base = _plan(resource)
        for candidate in (True, 0, 301, 1.5):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                InternalSandboxApiServerPlan(
                    deployment=base.deployment,
                    runtime=base.runtime,
                    graceful_shutdown_timeout_seconds=candidate,
                )

    def test_factory_failure_is_stable_and_secret_free(self) -> None:
        stderr = io.StringIO()

        def fail():
            raise RuntimeError("postgres://admin:secret@example.test/db")

        result = main(
            [],
            dependency_factory=fail,
            server_runner=lambda *_args, **_kwargs: None,
            stderr=stderr,
        )

        self.assertEqual(result, 78)
        self.assertNotIn("secret", stderr.getvalue().lower())
        self.assertEqual(
            json.loads(stderr.getvalue())["code"],
            "INTERNAL_SANDBOX_STARTUP_FAILED",
        )


if __name__ == "__main__":
    unittest.main()
