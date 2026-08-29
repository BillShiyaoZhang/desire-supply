"""One-process INTERNAL_SANDBOX identity bootstrap orchestration.

Compose cannot safely interpolate the digest of a generated manifest into a
later service environment.  This deployment-only boundary therefore performs
the closed handoff in one process: generate the digest-only manifest, re-open
and parse that exact file through the production bootstrap loader, apply it,
and verify it.  Raw fictional subject/email inputs and the generated manifest
remain on container tmpfs; neither material nor the digest is passed through a
shell command line.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hmac
import json
import os
import re
import sys
from typing import Any, Callable, Mapping, NoReturn, Optional, Sequence, TextIO

import psycopg

from desire_platform.internal_pilot.deployment_config import (
    DEPLOYMENT_CONFIG_POINTER_ENV,
)

from .identity_bootstrap import (
    IDENTITY_BOOTSTRAP_MANIFEST_FILE_ENV,
    IDENTITY_BOOTSTRAP_MANIFEST_SHA256_ENV,
    IdentityBootstrapError,
    apply_internal_sandbox_identity_bootstrap,
    load_identity_bootstrap_inputs,
    verify_internal_sandbox_identity_bootstrap,
)
from .identity_bootstrap_manifest import (
    IDENTITY_BOOTSTRAP_OUTPUT_FILE_ENV,
    IDENTITY_BOOTSTRAP_SOURCE_ROOT_ENV,
    IDENTITY_BOOTSTRAP_TEMPLATE_FILE_ENV,
    IDENTITY_BOOTSTRAP_TEMPLATE_SHA256_ENV,
    IdentityBootstrapManifestGenerationError,
    generate_identity_bootstrap_manifest_file,
)


_ADMIN_ENVIRONMENT = frozenset(
    (
        "DESIRE_DEPLOYMENT_MODE",
        "DESIRE_EXTERNAL_PARTICIPANTS_ENABLED",
        "DESIRE_DATABASE_HOST",
        "DESIRE_DATABASE_NAME",
        "DESIRE_DATABASE_ADMIN_USER",
        "DESIRE_DATABASE_PASSWORD_FILE",
    )
)
_GENERATOR_ENVIRONMENT = frozenset(
    (
        DEPLOYMENT_CONFIG_POINTER_ENV,
        IDENTITY_BOOTSTRAP_TEMPLATE_FILE_ENV,
        IDENTITY_BOOTSTRAP_TEMPLATE_SHA256_ENV,
        IDENTITY_BOOTSTRAP_SOURCE_ROOT_ENV,
        IDENTITY_BOOTSTRAP_OUTPUT_FILE_ENV,
    )
)
_ALLOWED_DESIRE_ENVIRONMENT = _ADMIN_ENVIRONMENT | _GENERATOR_ENVIRONMENT
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_APPLY_OUTCOMES = frozenset(("APPLIED", "ROTATED", "REPLAYED"))


class InternalSandboxIdentityBootstrapOrchestrationError(RuntimeError):
    """Stable, non-reflective failure at the deployment orchestration edge."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class InternalSandboxIdentityBootstrapOrchestrationReport:
    manifest_sha256: str
    apply_outcome: str
    verify_outcome: str

    def __post_init__(self) -> None:
        if (
            _SHA256.fullmatch(self.manifest_sha256) is None
            or self.apply_outcome not in _APPLY_OUTCOMES
            or self.verify_outcome != "VERIFIED"
        ):
            raise ValueError("identity bootstrap orchestration report is invalid")


def _invalid() -> NoReturn:
    raise InternalSandboxIdentityBootstrapOrchestrationError(
        "IDENTITY_BOOTSTRAP_ORCHESTRATION_INVALID"
    )


def _failed() -> NoReturn:
    raise InternalSandboxIdentityBootstrapOrchestrationError(
        "IDENTITY_BOOTSTRAP_ORCHESTRATION_FAILED"
    )


def orchestrate_internal_sandbox_identity_bootstrap(
    *,
    environment: Mapping[str, str],
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    generate_manifest: Callable[..., Any] = generate_identity_bootstrap_manifest_file,
    load_bootstrap_inputs: Callable[..., Any] = load_identity_bootstrap_inputs,
    apply_bootstrap: Callable[..., Any] = apply_internal_sandbox_identity_bootstrap,
    verify_bootstrap: Callable[..., Any] = verify_internal_sandbox_identity_bootstrap,
    dbapi: Any = psycopg,
) -> InternalSandboxIdentityBootstrapOrchestrationReport:
    """Generate, apply and verify one exact manifest without a shell handoff."""

    phase = "CONFIGURATION"
    try:
        if not isinstance(environment, Mapping) or not all(
            callable(item)
            for item in (
                clock,
                generate_manifest,
                load_bootstrap_inputs,
                apply_bootstrap,
                verify_bootstrap,
            )
        ):
            _invalid()
        desire_keys = frozenset(
            key
            for key in environment
            if isinstance(key, str) and key.startswith("DESIRE_")
        )
        if desire_keys != _ALLOWED_DESIRE_ENVIRONMENT:
            _invalid()
        values = {key: environment[key] for key in _ALLOWED_DESIRE_ENVIRONMENT}
        if (
            values["DESIRE_DEPLOYMENT_MODE"] != "INTERNAL_SANDBOX"
            or values["DESIRE_EXTERNAL_PARTICIPANTS_ENABLED"] != "false"
            or values["DESIRE_DATABASE_HOST"] != "db"
        ):
            _invalid()
        now = clock()
        if (
            not isinstance(now, datetime)
            or now.tzinfo is None
            or now.utcoffset() != timedelta(0)
        ):
            _invalid()

        phase = "GENERATE"
        generator_environment = {
            key: values[key] for key in _GENERATOR_ENVIRONMENT
        }
        generated = generate_manifest(
            environment=generator_environment,
            now=now,
        )
        digest = getattr(generated, "manifest_sha256", None)
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            _invalid()

        phase = "LOAD"
        bootstrap_environment = {
            key: values[key] for key in _ADMIN_ENVIRONMENT
        }
        bootstrap_environment[DEPLOYMENT_CONFIG_POINTER_ENV] = values[
            DEPLOYMENT_CONFIG_POINTER_ENV
        ]
        bootstrap_environment[IDENTITY_BOOTSTRAP_MANIFEST_FILE_ENV] = values[
            IDENTITY_BOOTSTRAP_OUTPUT_FILE_ENV
        ]
        bootstrap_environment[IDENTITY_BOOTSTRAP_MANIFEST_SHA256_ENV] = digest
        inputs = load_bootstrap_inputs(bootstrap_environment)
        manifest = getattr(inputs, "manifest", None)
        manifest_digest = getattr(manifest, "manifest_sha256", None)
        if (
            type(manifest_digest) is not bytes
            or len(manifest_digest) != 32
            or not hmac.compare_digest(manifest_digest.hex(), digest)
        ):
            _invalid()
        common = {
            "settings": getattr(inputs, "settings", None),
            "manifest": manifest,
            "system_actor_id": getattr(
                getattr(inputs, "deployment", None), "system_actor_id", None
            ),
            "now": now,
            "dbapi": dbapi,
        }

        phase = "APPLY"
        applied = apply_bootstrap(**common)
        apply_outcome = getattr(getattr(applied, "outcome", None), "value", None)
        apply_digest = getattr(applied, "manifest_sha256", None)
        if (
            apply_outcome not in _APPLY_OUTCOMES
            or not isinstance(apply_digest, str)
            or not hmac.compare_digest(apply_digest, digest)
        ):
            _failed()

        phase = "VERIFY"
        verified = verify_bootstrap(**common)
        verify_outcome = getattr(
            getattr(verified, "outcome", None), "value", None
        )
        verify_digest = getattr(verified, "manifest_sha256", None)
        if (
            verify_outcome != "VERIFIED"
            or not isinstance(verify_digest, str)
            or not hmac.compare_digest(verify_digest, digest)
        ):
            _failed()
        return InternalSandboxIdentityBootstrapOrchestrationReport(
            manifest_sha256=digest,
            apply_outcome=apply_outcome,
            verify_outcome=verify_outcome,
        )
    except InternalSandboxIdentityBootstrapOrchestrationError:
        raise
    except (IdentityBootstrapManifestGenerationError, IdentityBootstrapError):
        if phase in ("CONFIGURATION", "GENERATE", "LOAD"):
            _invalid()
        _failed()
    except BaseException:
        if phase in ("CONFIGURATION", "GENERATE", "LOAD"):
            _invalid()
        _failed()


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    environment: Optional[Mapping[str, str]] = None,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    dbapi: Any = psycopg,
) -> int:
    parser = argparse.ArgumentParser(
        prog=(
            "python -m "
            "desire_platform.deployment.identity_bootstrap_orchestrator"
        )
    )
    parser.add_argument("action", choices=("run",))
    parser.parse_args(argv)
    values = os.environ if environment is None else environment
    try:
        report = orchestrate_internal_sandbox_identity_bootstrap(
            environment=values,
            clock=clock,
            dbapi=dbapi,
        )
    except InternalSandboxIdentityBootstrapOrchestrationError as error:
        stderr.write(
            json.dumps(
                {"code": error.code, "status": "BLOCKED"},
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        )
        return 78
    except BaseException:
        stderr.write(
            '{"code":"IDENTITY_BOOTSTRAP_ORCHESTRATION_FAILED",'
            '"status":"BLOCKED"}\n'
        )
        return 78
    stdout.write(
        json.dumps(
            {
                "apply_outcome": report.apply_outcome,
                "manifest_sha256": report.manifest_sha256,
                "status": "IDENTITY_BOOTSTRAP_ORCHESTRATION_READY",
                "verify_outcome": report.verify_outcome,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = (
    "InternalSandboxIdentityBootstrapOrchestrationError",
    "InternalSandboxIdentityBootstrapOrchestrationReport",
    "main",
    "orchestrate_internal_sandbox_identity_bootstrap",
)
