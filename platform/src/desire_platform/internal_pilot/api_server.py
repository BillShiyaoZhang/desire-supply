"""Fail-closed command-line host for the internal sandbox ASGI composition.

The default factory loads one explicit deployment pointer and builds the
reviewed PostgreSQL/OIDC/editor registry.  Any incomplete configuration,
artifact, seed, schema or online dependency exits with ``EX_CONFIG`` before
Uvicorn is imported or called.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Callable, Optional, Sequence, TextIO

from .api_server_plan import InternalSandboxApiServerPlan
from .runtime import InternalSandboxApiApplication, InternalSandboxRuntime


EX_SOFTWARE = 70
EX_CONFIG = 78
_UNSET = object()


def _default_dependency_factory() -> InternalSandboxApiServerPlan:
    # Lazy import keeps CLI argument/config failures independent from the
    # optional server/JOSE implementations and avoids a module cycle with the
    # plan value type above.
    from .production_plan import build_internal_sandbox_server_plan

    return build_internal_sandbox_server_plan(environment=os.environ)


DEFAULT_DEPENDENCY_FACTORY: Callable[
    [], InternalSandboxApiServerPlan
] = _default_dependency_factory


def _parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        prog="python -m desire_platform.internal_pilot.api_server"
    )


def _blocked(stderr: TextIO, code: str, *, exit_code: int) -> int:
    stderr.write(
        json.dumps(
            {"code": code, "status": "BLOCKED"},
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )
    stderr.flush()
    return exit_code


def _default_server_runner(application: Any, **settings: Any) -> None:
    # Importing the optional server dependency happens only after every
    # configuration/dependency/readiness check has succeeded.
    try:
        import uvicorn
    except (ImportError, ModuleNotFoundError):
        raise RuntimeError("ASGI_SERVER_UNAVAILABLE") from None
    config = uvicorn.Config(application, **settings)
    server = uvicorn.Server(config)
    server.run()
    if not server.started:
        raise RuntimeError("ASGI_SERVER_STARTUP_FAILED")


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    dependency_factory: Any = _UNSET,
    server_runner: Optional[Callable[..., Any]] = None,
    stderr: TextIO = sys.stderr,
) -> int:
    _parser().parse_args(argv)
    factory = (
        DEFAULT_DEPENDENCY_FACTORY
        if dependency_factory is _UNSET
        else dependency_factory
    )
    if factory is None or not callable(factory):
        return _blocked(
            stderr,
            "INTERNAL_SANDBOX_COMPOSITION_UNAVAILABLE",
            exit_code=EX_CONFIG,
        )

    runtime: Optional[InternalSandboxRuntime] = None
    plan: Optional[InternalSandboxApiServerPlan] = None
    try:
        candidate = factory()
        if not isinstance(candidate, InternalSandboxApiServerPlan):
            raise TypeError("dependency factory returned an open object")
        plan = candidate
        runtime = candidate.runtime
        if not runtime.check_readiness():
            raise RuntimeError("internal sandbox runtime is not ready")
    except BaseException:
        if runtime is not None:
            runtime.close()
        return _blocked(
            stderr,
            "INTERNAL_SANDBOX_STARTUP_FAILED",
            exit_code=EX_CONFIG,
        )

    claimed = False

    def claim_runtime() -> InternalSandboxRuntime:
        nonlocal claimed
        if claimed:
            raise RuntimeError("internal sandbox runtime was already claimed")
        claimed = True
        if runtime is None:
            raise RuntimeError("internal sandbox runtime is unavailable")
        return runtime

    application = InternalSandboxApiApplication(builder=claim_runtime)
    runner = server_runner or _default_server_runner
    if plan is None:
        runtime.close()
        return _blocked(
            stderr,
            "INTERNAL_SANDBOX_STARTUP_FAILED",
            exit_code=EX_CONFIG,
        )
    bind = plan.deployment.bind
    try:
        runner(
            application,
            host=bind.host,
            port=bind.port,
            access_log=False,
            log_level="warning",
            proxy_headers=False,
            server_header=False,
            lifespan="on",
            timeout_graceful_shutdown=(
                plan.graceful_shutdown_timeout_seconds
            ),
        )
    except KeyboardInterrupt:
        return 0
    except BaseException:
        return _blocked(
            stderr,
            "INTERNAL_SANDBOX_SERVER_FAILED",
            exit_code=EX_SOFTWARE,
        )
    finally:
        runtime.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "DEFAULT_DEPENDENCY_FACTORY",
    "InternalSandboxApiServerPlan",
    "main",
]
