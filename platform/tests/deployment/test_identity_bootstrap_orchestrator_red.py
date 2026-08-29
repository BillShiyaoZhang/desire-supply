"""Closed one-process handoff from identity manifest generation to bootstrap."""

from __future__ import annotations

from datetime import datetime, timezone
from io import StringIO
from types import SimpleNamespace

import pytest

from desire_platform.deployment.identity_bootstrap_manifest import (
    IDENTITY_BOOTSTRAP_OUTPUT_FILE_ENV,
    IDENTITY_BOOTSTRAP_SOURCE_ROOT_ENV,
    IDENTITY_BOOTSTRAP_TEMPLATE_FILE_ENV,
    IDENTITY_BOOTSTRAP_TEMPLATE_SHA256_ENV,
    IdentityBootstrapManifestGenerationError,
)
from desire_platform.deployment.identity_bootstrap_orchestrator import (
    InternalSandboxIdentityBootstrapOrchestrationError,
    main,
    orchestrate_internal_sandbox_identity_bootstrap,
)
from desire_platform.internal_pilot.deployment_config import (
    DEPLOYMENT_CONFIG_POINTER_ENV,
)


NOW = datetime(2026, 8, 13, 12, 0, tzinfo=timezone.utc)
MANIFEST_SHA256 = "a" * 64


def _environment() -> dict[str, str]:
    return {
        "DESIRE_DEPLOYMENT_MODE": "INTERNAL_SANDBOX",
        "DESIRE_EXTERNAL_PARTICIPANTS_ENABLED": "false",
        "DESIRE_DATABASE_HOST": "db",
        "DESIRE_DATABASE_NAME": "desire",
        "DESIRE_DATABASE_ADMIN_USER": "postgres",
        "DESIRE_DATABASE_PASSWORD_FILE": "/run/secrets/db_superuser_password",
        DEPLOYMENT_CONFIG_POINTER_ENV: "/run/desire/deployment.json",
        IDENTITY_BOOTSTRAP_TEMPLATE_FILE_ENV: (
            "/run/desire/identity-bootstrap-template.json"
        ),
        IDENTITY_BOOTSTRAP_TEMPLATE_SHA256_ENV: "b" * 64,
        IDENTITY_BOOTSTRAP_SOURCE_ROOT_ENV: "/run/identity-sources",
        IDENTITY_BOOTSTRAP_OUTPUT_FILE_ENV: (
            "/run/identity-bootstrap/manifest.json"
        ),
    }


@pytest.mark.parametrize("apply_outcome", ("APPLIED", "ROTATED", "REPLAYED"))
def test_orchestrator_uses_in_process_digest_handoff_and_exact_sub_environments(
    apply_outcome: str,
) -> None:
    calls: list[object] = []
    generated = SimpleNamespace(manifest_sha256=MANIFEST_SHA256)
    manifest = SimpleNamespace(manifest_sha256=bytes.fromhex(MANIFEST_SHA256))
    deployment = SimpleNamespace(system_actor_id="system-actor")
    inputs = SimpleNamespace(
        settings="admin-settings",
        deployment=deployment,
        manifest=manifest,
    )
    applied = SimpleNamespace(
        manifest_sha256=MANIFEST_SHA256,
        outcome=SimpleNamespace(value=apply_outcome),
    )
    verified = SimpleNamespace(
        manifest_sha256=MANIFEST_SHA256,
        outcome=SimpleNamespace(value="VERIFIED"),
    )

    def generate(*, environment, now):
        calls.append(("generate", dict(environment), now))
        assert set(environment) == {
            DEPLOYMENT_CONFIG_POINTER_ENV,
            IDENTITY_BOOTSTRAP_TEMPLATE_FILE_ENV,
            IDENTITY_BOOTSTRAP_TEMPLATE_SHA256_ENV,
            IDENTITY_BOOTSTRAP_SOURCE_ROOT_ENV,
            IDENTITY_BOOTSTRAP_OUTPUT_FILE_ENV,
        }
        return generated

    def load(environment, **_values):
        calls.append(("load", dict(environment)))
        assert environment[
            "DESIRE_INTERNAL_SANDBOX_IDENTITY_BOOTSTRAP_MANIFEST_SHA256"
        ] == MANIFEST_SHA256
        assert environment[
            "DESIRE_INTERNAL_SANDBOX_IDENTITY_BOOTSTRAP_MANIFEST_FILE"
        ] == "/run/identity-bootstrap/manifest.json"
        assert IDENTITY_BOOTSTRAP_TEMPLATE_FILE_ENV not in environment
        assert IDENTITY_BOOTSTRAP_SOURCE_ROOT_ENV not in environment
        return inputs

    def apply(**values):
        calls.append(("apply", values))
        return applied

    def verify(**values):
        calls.append(("verify", values))
        return verified

    report = orchestrate_internal_sandbox_identity_bootstrap(
        environment=_environment(),
        clock=lambda: NOW,
        generate_manifest=generate,
        load_bootstrap_inputs=load,
        apply_bootstrap=apply,
        verify_bootstrap=verify,
        dbapi="dbapi",
    )

    assert [item[0] for item in calls] == ["generate", "load", "apply", "verify"]
    assert report.manifest_sha256 == MANIFEST_SHA256
    assert report.apply_outcome == apply_outcome
    assert report.verify_outcome == "VERIFIED"
    for operation, values in calls[2:]:
        assert operation in ("apply", "verify")
        assert values == {
            "settings": "admin-settings",
            "manifest": manifest,
            "system_actor_id": "system-actor",
            "now": NOW,
            "dbapi": "dbapi",
        }


def test_orchestrator_rejects_open_environment_before_any_side_effect() -> None:
    called = False

    def generate(**_values):
        nonlocal called
        called = True
        raise AssertionError("must not generate")

    environment = _environment()
    environment["DESIRE_UNREVIEWED_OPTION"] = "open"
    with pytest.raises(InternalSandboxIdentityBootstrapOrchestrationError) as caught:
        orchestrate_internal_sandbox_identity_bootstrap(
            environment=environment,
            clock=lambda: NOW,
            generate_manifest=generate,
        )
    assert caught.value.code == "IDENTITY_BOOTSTRAP_ORCHESTRATION_INVALID"
    assert called is False


def test_manifest_failure_cannot_reach_any_database_mutation() -> None:
    mutations: list[str] = []

    def fail_generate(**_values):
        raise IdentityBootstrapManifestGenerationError()

    def mutation(**_values):
        mutations.append("called")
        raise AssertionError("database mutation must remain unreachable")

    with pytest.raises(InternalSandboxIdentityBootstrapOrchestrationError) as caught:
        orchestrate_internal_sandbox_identity_bootstrap(
            environment=_environment(),
            clock=lambda: NOW,
            generate_manifest=fail_generate,
            load_bootstrap_inputs=mutation,
            apply_bootstrap=mutation,
            verify_bootstrap=mutation,
        )
    assert caught.value.code == "IDENTITY_BOOTSTRAP_ORCHESTRATION_INVALID"
    assert mutations == []


def test_cli_failure_is_non_reflective_and_never_prints_raw_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_identity = "sandbox-creator-owner-01@example.test"

    def fail(**_values):
        raise RuntimeError(raw_identity)

    monkeypatch.setattr(
        "desire_platform.deployment.identity_bootstrap_orchestrator."
        "orchestrate_internal_sandbox_identity_bootstrap",
        fail,
    )
    stdout = StringIO()
    stderr = StringIO()
    assert main(
        ["run"],
        environment=_environment(),
        stdout=stdout,
        stderr=stderr,
        clock=lambda: NOW,
    ) == 78
    assert stdout.getvalue() == ""
    assert "IDENTITY_BOOTSTRAP_ORCHESTRATION_FAILED" in stderr.getvalue()
    assert raw_identity not in stderr.getvalue()


def test_cli_success_prints_only_digest_and_closed_outcomes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = SimpleNamespace(
        manifest_sha256=MANIFEST_SHA256,
        apply_outcome="REPLAYED",
        verify_outcome="VERIFIED",
    )
    monkeypatch.setattr(
        "desire_platform.deployment.identity_bootstrap_orchestrator."
        "orchestrate_internal_sandbox_identity_bootstrap",
        lambda **_values: report,
    )
    stdout = StringIO()
    stderr = StringIO()
    assert main(
        ["run"],
        environment=_environment(),
        stdout=stdout,
        stderr=stderr,
        clock=lambda: NOW,
    ) == 0
    assert stderr.getvalue() == ""
    assert stdout.getvalue() == (
        '{"apply_outcome":"REPLAYED","manifest_sha256":"'
        + MANIFEST_SHA256
        + '","status":"IDENTITY_BOOTSTRAP_ORCHESTRATION_READY",'
        '"verify_outcome":"VERIFIED"}\n'
    )
    assert "sandbox:" not in stdout.getvalue()
    assert "@example.test" not in stdout.getvalue()
