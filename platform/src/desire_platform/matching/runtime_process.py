"""Crash-safe host for the dedicated Matching worker and coordinator.

The database adapters deliberately expose one bounded ``run_once`` call.  This
module owns the process lifecycle around those calls: startup readiness,
signal-driven shutdown, bounded retry, and the file heartbeat consumed by the
container health check.  Concrete dependency construction lives behind the
default factory so the lifecycle can be tested without PostgreSQL or secrets.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import signal
import stat
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Mapping, Optional, Sequence, TextIO, Tuple


EX_SOFTWARE = 70
EX_CONFIG = 78
_MAX_CONSECUTIVE_FAILURES = 5
_DEFAULT_IDLE_SECONDS = 0.25
_MAX_BACKOFF_SECONDS = 4.0
_HEALTH_ENV = "DESIRE_MATCHING_RUNTIME_HEALTH_FILE"
_DEPLOYMENT_ENV = "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE"


class MatchingRuntimeProcessError(RuntimeError):
    """Stable process error that never includes configuration or secret bytes."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class MatchingRuntimeProcessPlan:
    """Closed set of dependencies owned by one dedicated process."""

    worker: Any = field(repr=False)
    coordinator: Any = field(repr=False)
    managed_resources: Tuple[Any, ...] = field(repr=False)
    tick_readiness: Any = field(repr=False)
    health_file: Path
    readiness_timeout_ms: int
    shutdown_timeout_ms: int
    idle_seconds: float = _DEFAULT_IDLE_SECONDS

    def __post_init__(self) -> None:
        if self.worker is self.coordinator or any(
            not callable(getattr(value, "run_once", None))
            for value in (self.worker, self.coordinator)
        ):
            raise ValueError("Matching process runners are unavailable")
        if (
            not isinstance(self.managed_resources, tuple)
            or not self.managed_resources
            or len({id(value) for value in self.managed_resources})
            != len(self.managed_resources)
            or any(
                not callable(getattr(value, "check_readiness", None))
                or not callable(getattr(value, "close", None))
                for value in self.managed_resources
            )
        ):
            raise ValueError("Matching managed resources are unavailable")
        if (
            not any(
                resource is self.tick_readiness
                for resource in self.managed_resources
            )
            or not callable(
                getattr(self.tick_readiness, "check_readiness", None)
            )
        ):
            raise ValueError("Matching tick readiness is unavailable")
        _validate_health_file(self.health_file)
        for value, lower, upper in (
            (self.readiness_timeout_ms, 50, 30_000),
            (self.shutdown_timeout_ms, 100, 300_000),
        ):
            if type(value) is not int or not lower <= value <= upper:
                raise ValueError("Matching process budget is invalid")
        if (
            isinstance(self.idle_seconds, bool)
            or not isinstance(self.idle_seconds, (int, float))
            or not 0.01 <= float(self.idle_seconds) <= 5.0
        ):
            raise ValueError("Matching process poll interval is invalid")

    def check_readiness(self) -> None:
        """Prove every role-bound dependency before publishing health."""

        for resource in self.managed_resources:
            resource.check_readiness(timeout_ms=self.readiness_timeout_ms)

    def check_tick_readiness(self) -> None:
        """Revalidate expiring process authority before each observable step."""

        try:
            self.tick_readiness.check_readiness(
                timeout_ms=self.readiness_timeout_ms
            )
        except BaseException:
            raise MatchingRuntimeProcessError(
                "MATCHING_RUNTIME_AUTHORITY_UNAVAILABLE"
            ) from None

    def close(self) -> None:
        """Close in reverse construction order; attempt every cleanup."""

        for resource in reversed(self.managed_resources):
            try:
                resource.close()
            except BaseException:
                continue


@dataclass(frozen=True)
class MatchingRuntimeLoopResult:
    status: str
    cycles: int
    consecutive_failures: int

    def __post_init__(self) -> None:
        if (
            self.status not in {"STOPPED", "FAILED"}
            or type(self.cycles) is not int
            or self.cycles < 0
            or type(self.consecutive_failures) is not int
            or self.consecutive_failures < 0
        ):
            raise ValueError("Matching runtime loop result is invalid")


def run_matching_runtime_loop(
    *,
    plan: MatchingRuntimeProcessPlan,
    stop_event: Any,
    sleeper: Callable[[float], Any] = time.sleep,
    stderr: TextIO = sys.stderr,
) -> MatchingRuntimeLoopResult:
    """Run worker then coordinator ticks until stopped or retry is exhausted."""

    if not isinstance(plan, MatchingRuntimeProcessPlan):
        raise TypeError("Matching runtime plan is unavailable")
    if not callable(getattr(stop_event, "is_set", None)) or not callable(
        getattr(stop_event, "set", None)
    ):
        raise TypeError("Matching stop event is unavailable")
    if not callable(sleeper) or not callable(getattr(stderr, "write", None)):
        raise TypeError("Matching runtime host dependency is unavailable")

    cycles = 0
    consecutive_failures = 0
    degraded_reported = False
    while not stop_event.is_set():
        try:
            plan.check_tick_readiness()
            worker_tick = plan.worker.run_once()
            _validate_tick(worker_tick)
            plan.check_tick_readiness()
            coordinator_tick = plan.coordinator.run_once()
            _validate_tick(coordinator_tick)
            plan.check_tick_readiness()
            _write_health(plan.health_file)
            cycles += 1
            consecutive_failures = 0
            degraded_reported = False
            if not (_tick_worked(worker_tick) or _tick_worked(coordinator_tick)):
                sleeper(float(plan.idle_seconds))
        except BaseException as error:
            consecutive_failures += 1
            _remove_health(plan.health_file)
            if not degraded_reported:
                _write_status(
                    stderr,
                    code="MATCHING_RUNTIME_TICK_FAILED",
                    status="DEGRADED",
                )
                degraded_reported = True
            if (
                isinstance(error, MatchingRuntimeProcessError)
                and error.code == "MATCHING_RUNTIME_AUTHORITY_UNAVAILABLE"
            ):
                return MatchingRuntimeLoopResult(
                    status="FAILED",
                    cycles=cycles,
                    consecutive_failures=consecutive_failures,
                )
            if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
                return MatchingRuntimeLoopResult(
                    status="FAILED",
                    cycles=cycles,
                    consecutive_failures=consecutive_failures,
                )
            sleeper(
                min(
                    _MAX_BACKOFF_SECONDS,
                    float(plan.idle_seconds)
                    * (2 ** (consecutive_failures - 1)),
                )
            )
    return MatchingRuntimeLoopResult(
        status="STOPPED",
        cycles=cycles,
        consecutive_failures=consecutive_failures,
    )


def build_matching_runtime_process_plan(
    *,
    environment: Mapping[str, str],
    read_bytes: Optional[Callable[[str], bytes]] = None,
    dbapi: Any = None,
) -> MatchingRuntimeProcessPlan:
    """Build the real role-bound process without starting its polling loop.

    The concrete builder is kept in a small companion module because it owns
    secret carriers and PostgreSQL pools.  Importing the lifecycle host alone
    therefore has no configuration, secret, or database side effects.
    """

    from .runtime_wiring import build_matching_runtime_process_plan as build

    return build(environment=environment, read_bytes=read_bytes, dbapi=dbapi)


def _default_dependency_factory() -> MatchingRuntimeProcessPlan:
    return build_matching_runtime_process_plan(environment=os.environ)


DEFAULT_DEPENDENCY_FACTORY: Callable[[], MatchingRuntimeProcessPlan] = (
    _default_dependency_factory
)


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    dependency_factory: Optional[Callable[[], MatchingRuntimeProcessPlan]] = None,
    stop_event: Optional[Any] = None,
    sleeper: Callable[[float], Any] = time.sleep,
    stderr: TextIO = sys.stderr,
) -> int:
    argparse.ArgumentParser(
        prog="python -m desire_platform.matching.runtime_process"
    ).parse_args(argv)
    factory = dependency_factory or DEFAULT_DEPENDENCY_FACTORY
    if not callable(factory):
        _write_status(
            stderr,
            code="MATCHING_RUNTIME_COMPOSITION_UNAVAILABLE",
            status="BLOCKED",
        )
        return EX_CONFIG

    plan: Optional[MatchingRuntimeProcessPlan] = None
    event = stop_event or threading.Event()
    restore_signals: Tuple[Tuple[int, Any], ...] = ()
    try:
        candidate = factory()
        if not isinstance(candidate, MatchingRuntimeProcessPlan):
            raise TypeError
        plan = candidate
        # A container restart can preserve the tmpfs heartbeat long enough for
        # the health probe to observe an earlier process.  Withdraw it before
        # any readiness work so only this process can publish READY again.
        _remove_health(plan.health_file)
        plan.check_readiness()
        restore_signals = _install_signal_handlers(event)
        result = run_matching_runtime_loop(
            plan=plan,
            stop_event=event,
            sleeper=sleeper,
            stderr=stderr,
        )
        if result.status == "FAILED":
            _write_status(
                stderr,
                code="MATCHING_RUNTIME_RETRY_EXHAUSTED",
                status="BLOCKED",
            )
            return EX_SOFTWARE
        return 0
    except KeyboardInterrupt:
        return 0
    except BaseException:
        _write_status(
            stderr,
            code="MATCHING_RUNTIME_STARTUP_FAILED",
            status="BLOCKED",
        )
        return EX_CONFIG
    finally:
        for signum, previous in restore_signals:
            try:
                signal.signal(signum, previous)
            except BaseException:
                continue
        if plan is not None:
            _remove_health(plan.health_file)
            plan.close()


def _validate_health_file(path: Any) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or path.name != "healthy":
        raise ValueError("Matching health path is invalid")
    try:
        parent = path.parent.resolve(strict=True)
        metadata = parent.stat()
    except OSError:
        raise ValueError("Matching health directory is unavailable") from None
    if (
        parent != path.parent
        or not stat.S_ISDIR(metadata.st_mode)
        or path.parent.is_symlink()
        or Path("/run/secrets") in path.parents
    ):
        raise ValueError("Matching health directory is unavailable")
    return path


def _write_health(path: Path) -> None:
    _validate_health_file(path)
    descriptor = -1
    temporary = ""
    try:
        descriptor, temporary = tempfile.mkstemp(
            prefix=".matching-heartbeat-",
            dir=str(path.parent),
        )
        os.fchmod(descriptor, 0o600)
        payload = b'{"status":"READY"}\n'
        written = os.write(descriptor, payload)
        if written != len(payload):
            raise OSError
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        temporary = ""
    except OSError:
        raise MatchingRuntimeProcessError("MATCHING_HEALTH_WRITE_FAILED") from None
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def _remove_health(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except (OSError, TypeError, ValueError):
        return


def _validate_tick(value: Any) -> None:
    if value is None:
        raise MatchingRuntimeProcessError("MATCHING_RUNTIME_TICK_INVALID")
    if isinstance(value, bool):
        return
    status = getattr(value, "status", None)
    if not isinstance(status, str) or not status or len(status) > 64:
        raise MatchingRuntimeProcessError("MATCHING_RUNTIME_TICK_INVALID")


def _tick_worked(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    for attribute in ("worked", "work_performed", "claimed"):
        candidate = getattr(value, attribute, None)
        if isinstance(candidate, bool):
            return candidate
    return getattr(value, "status", "IDLE") not in {"IDLE", "EMPTY", "NO_WORK"}


def _install_signal_handlers(stop_event: Any) -> Tuple[Tuple[int, Any], ...]:
    if threading.current_thread() is not threading.main_thread():
        return ()
    previous = []

    def request_stop(_signum: int, _frame: Any) -> None:
        stop_event.set()

    for signum in (signal.SIGTERM, signal.SIGINT):
        old = signal.getsignal(signum)
        signal.signal(signum, request_stop)
        previous.append((signum, old))
    return tuple(previous)


def _write_status(stderr: TextIO, *, code: str, status: str) -> None:
    stderr.write(
        json.dumps(
            {"code": code, "status": status},
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )
    stderr.flush()


if __name__ == "__main__":
    # The wiring module imports this module's plan class by its package name.
    # Dispatch through that same module when invoked with python -m, so the
    # __main__ copy does not reject an otherwise valid plan via isinstance.
    from desire_platform.matching.runtime_process import main as package_main

    raise SystemExit(package_main())


__all__ = [
    "DEFAULT_DEPENDENCY_FACTORY",
    "EX_CONFIG",
    "EX_SOFTWARE",
    "MatchingRuntimeLoopResult",
    "MatchingRuntimeProcessError",
    "MatchingRuntimeProcessPlan",
    "build_matching_runtime_process_plan",
    "main",
    "run_matching_runtime_loop",
]
