"""Shared immutable value type for the internal sandbox server plan.

Keeping this type outside the executable ``api_server`` module is required:
Python executes that module as ``__main__`` for ``python -m``, while the
production builder imports it by its package name.  A dataclass defined in the
executable module would therefore have two distinct runtime identities.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .deployment_config import InternalSandboxDeploymentConfiguration
from .runtime import InternalSandboxRuntime


@dataclass(frozen=True)
class InternalSandboxApiServerPlan:
    deployment: InternalSandboxDeploymentConfiguration
    runtime: InternalSandboxRuntime = field(repr=False)
    graceful_shutdown_timeout_seconds: int

    def __post_init__(self) -> None:
        if not isinstance(self.deployment, InternalSandboxDeploymentConfiguration):
            raise TypeError("internal sandbox deployment is unavailable")
        if not isinstance(self.runtime, InternalSandboxRuntime):
            raise TypeError("internal sandbox runtime is unavailable")
        if (
            type(self.graceful_shutdown_timeout_seconds) is not int
            or not 1 <= self.graceful_shutdown_timeout_seconds <= 300
        ):
            raise ValueError("internal sandbox shutdown timeout is invalid")


__all__ = ["InternalSandboxApiServerPlan"]
