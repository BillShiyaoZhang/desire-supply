"""One-process closure tests for preprovisioned OIDC identities."""

from __future__ import annotations

from datetime import datetime, timezone
from io import StringIO
from types import SimpleNamespace

import pytest

from desire_platform.deployment.identity_bootstrap import (
    IDENTITY_BOOTSTRAP_MANIFEST_FILE_ENV,
    IDENTITY_BOOTSTRAP_MANIFEST_SHA256_ENV,
)
from desire_platform.deployment.preprovisioned_identity_bootstrap_manifest import (
    PREPROVISIONED_IDENTITY_BOOTSTRAP_OUTPUT_FILE_ENV,
    PREPROVISIONED_IDENTITY_BOOTSTRAP_SOURCE_ROOT_ENV,
    PREPROVISIONED_IDENTITY_BOOTSTRAP_TEMPLATE_FILE_ENV,
    PREPROVISIONED_IDENTITY_BOOTSTRAP_TEMPLATE_SHA256_ENV,
    PreprovisionedIdentityBootstrapManifestGenerationError,
)
from desire_platform.deployment.preprovisioned_identity_bootstrap_orchestrator import (
    PreprovisionedIdentityBootstrapOrchestrationError,
    main,
    orchestrate_preprovisioned_identity_bootstrap,
)
from desire_platform.internal_pilot.deployment_config import (
    DEPLOYMENT_CONFIG_POINTER_ENV,
)


NOW = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)
MANIFEST_SHA256 = "a" * 64


def _environment() -> dict[str, str]:
    return {
        "DESIRE_DEPLOYMENT_MODE": "INTERNAL_SANDBOX",
        "DESIRE_EXTERNAL_PARTICIPANTS_ENABLED": "false",
        "DESIRE_DATABASE_HOST": "db",
        "DESIRE_DATABASE_NAME": "desire",
        "DESIRE_DATABASE_ADMIN_USER": "postgres",
        "DESIRE_DATABASE_PASSWORD_FILE": "/run/secrets/db-password",
        DEPLOYMENT_CONFIG_POINTER_ENV: "/run/desire/deployment.json",
        PREPROVISIONED_IDENTITY_BOOTSTRAP_TEMPLATE_FILE_ENV: (
            "/run/desire/identity-template.json"
        ),
        PREPROVISIONED_IDENTITY_BOOTSTRAP_TEMPLATE_SHA256_ENV: "b" * 64,
        PREPROVISIONED_IDENTITY_BOOTSTRAP_SOURCE_ROOT_ENV: (
            "/run/preprovisioned-identities"
        ),
        PREPROVISIONED_IDENTITY_BOOTSTRAP_OUTPUT_FILE_ENV: (
            "/run/identity-bootstrap/manifest.json"
        ),
    }


@pytest.mark.parametrize("apply_outcome", ("APPLIED", "ROTATED", "REPLAYED"))
def test_orchestrator_hands_digest_to_existing_load_apply_verify_closure(
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
            PREPROVISIONED_IDENTITY_BOOTSTRAP_TEMPLATE_FILE_ENV,
            PREPROVISIONED_IDENTITY_BOOTSTRAP_TEMPLATE_SHA256_ENV,
            PREPROVISIONED_IDENTITY_BOOTSTRAP_SOURCE_ROOT_ENV,
            PREPROVISIONED_IDENTITY_BOOTSTRAP_OUTPUT_FILE_ENV,
        }
        return generated

    def load(environment):
        calls.append(("load", dict(environment)))
        assert environment[IDENTITY_BOOTSTRAP_MANIFEST_SHA256_ENV] == (
            MANIFEST_SHA256
        )
        assert environment[IDENTITY_BOOTSTRAP_MANIFEST_FILE_ENV] == (
            "/run/identity-bootstrap/manifest.json"
        )
        assert PREPROVISIONED_IDENTITY_BOOTSTRAP_SOURCE_ROOT_ENV not in environment
        assert (
            PREPROVISIONED_IDENTITY_BOOTSTRAP_TEMPLATE_FILE_ENV not in environment
        )
        return inputs

    def apply(**values):
        calls.append(("apply", values))
        return applied

    def verify(**values):
        calls.append(("verify", values))
        return verified

    report = orchestrate_preprovisioned_identity_bootstrap(
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


def test_orchestrator_rejects_unknown_or_synthetic_environment_before_generation() -> None:
    called = False

    def generate(**_values):
        nonlocal called
        called = True
        raise AssertionError("must not generate")

    for unknown in (
        "DESIRE_UNREVIEWED_OPTION",
        "DESIRE_INTERNAL_SANDBOX_IDENTITY_BOOTSTRAP_SOURCE_ROOT",
    ):
        environment = _environment()
        environment[unknown] = "raw-secret-location"
        with pytest.raises(
            PreprovisionedIdentityBootstrapOrchestrationError
        ) as caught:
            orchestrate_preprovisioned_identity_bootstrap(
                environment=environment,
                clock=lambda: NOW,
                generate_manifest=generate,
            )
        assert caught.value.code == (
            "PREPROVISIONED_IDENTITY_BOOTSTRAP_ORCHESTRATION_INVALID"
        )
    assert called is False


def test_generation_failure_cannot_reach_load_or_database_mutation() -> None:
    mutations: list[str] = []
    raw_identity = "private-person@example.test"

    def fail_generate(**_values):
        raise PreprovisionedIdentityBootstrapManifestGenerationError()

    def mutation(**_values):
        mutations.append(raw_identity)
        raise AssertionError("mutation must remain unreachable")

    with pytest.raises(
        PreprovisionedIdentityBootstrapOrchestrationError
    ) as caught:
        orchestrate_preprovisioned_identity_bootstrap(
            environment=_environment(),
            clock=lambda: NOW,
            generate_manifest=fail_generate,
            load_bootstrap_inputs=mutation,
            apply_bootstrap=mutation,
            verify_bootstrap=mutation,
        )
    assert caught.value.code == (
        "PREPROVISIONED_IDENTITY_BOOTSTRAP_ORCHESTRATION_INVALID"
    )
    assert mutations == []
    assert raw_identity not in repr(caught.value)


def test_cli_is_digest_only_on_success_and_non_reflective_on_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = SimpleNamespace(
        manifest_sha256=MANIFEST_SHA256,
        apply_outcome="REPLAYED",
        verify_outcome="VERIFIED",
    )
    target = (
        "desire_platform.deployment."
        "preprovisioned_identity_bootstrap_orchestrator."
        "orchestrate_preprovisioned_identity_bootstrap"
    )
    monkeypatch.setattr(target, lambda **_values: report)
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
    payload = stdout.getvalue()
    assert MANIFEST_SHA256 in payload
    assert "REPLAYED" in payload
    assert "VERIFIED" in payload
    assert "@" not in payload
    assert "subject" not in payload.casefold()

    raw_identity = "private-person@example.test"

    def fail(**_values):
        raise RuntimeError(raw_identity)

    monkeypatch.setattr(target, fail)
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
    assert raw_identity not in stderr.getvalue()
    assert "ORCHESTRATION_FAILED" in stderr.getvalue()
