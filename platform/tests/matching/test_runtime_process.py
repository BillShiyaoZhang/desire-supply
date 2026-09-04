"""Lifecycle gates for the dedicated Matching runtime host."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import io
from pathlib import Path
import runpy
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import warnings

from desire_platform.matching import runtime_process
from desire_platform.internal_pilot.secrets import (
    FileSecretCarrier,
    ManagedRuntimeSecrets,
)
from desire_platform.matching.runtime_process import (
    EX_CONFIG,
    EX_SOFTWARE,
    MatchingRuntimeProcessPlan,
    main,
    run_matching_runtime_loop,
)


@dataclass(frozen=True)
class _Tick:
    status: str
    worked: bool


class _Runner:
    def __init__(self, values: list[object]) -> None:
        self.values = values
        self.calls = 0

    def run_once(self):
        self.calls += 1
        value = self.values[min(self.calls - 1, len(self.values) - 1)]
        if isinstance(value, BaseException):
            raise value
        return value


class _Resource:
    def __init__(self, *, readiness_error: BaseException | None = None) -> None:
        self.readiness_error = readiness_error
        self.readiness_calls: list[int] = []
        self.closed = 0

    def check_readiness(self, *, timeout_ms: int) -> None:
        self.readiness_calls.append(timeout_ms)
        if self.readiness_error is not None:
            raise self.readiness_error

    def close(self) -> None:
        self.closed += 1


class MatchingRuntimeProcessTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="desire-matching-runtime-"
        )
        self.health = Path(self.temporary.name).resolve() / "healthy"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _plan(
        self,
        *,
        worker: _Runner,
        coordinator: _Runner,
        resources: tuple[_Resource, ...] | None = None,
    ) -> MatchingRuntimeProcessPlan:
        managed = resources or (_Resource(),)
        return MatchingRuntimeProcessPlan(
            worker=worker,
            coordinator=coordinator,
            managed_resources=managed,
            tick_readiness=managed[0],
            health_file=self.health,
            readiness_timeout_ms=1_000,
            shutdown_timeout_ms=2_000,
            idle_seconds=0.01,
        )

    def test_idle_cycle_atomically_publishes_health_and_stops(self) -> None:
        stop = threading.Event()
        sleeps: list[float] = []

        def sleep(value: float) -> None:
            sleeps.append(value)
            stop.set()

        result = run_matching_runtime_loop(
            plan=self._plan(
                worker=_Runner([_Tick("IDLE", False)]),
                coordinator=_Runner([_Tick("IDLE", False)]),
            ),
            stop_event=stop,
            sleeper=sleep,
            stderr=io.StringIO(),
        )

        self.assertEqual(result.status, "STOPPED")
        self.assertEqual(result.cycles, 1)
        self.assertEqual(sleeps, [0.01])
        self.assertEqual(self.health.read_bytes(), b'{"status":"READY"}\n')
        self.assertEqual(list(self.health.parent.glob(".matching-heartbeat-*")), [])

    def test_module_entrypoint_accepts_the_package_factory_plan(self) -> None:
        resource = _Resource()
        plan = self._plan(
            worker=_Runner([_Tick("IDLE", False)]),
            coordinator=_Runner([_Tick("IDLE", False)]),
            resources=(resource,),
        )
        stopped = threading.Event()
        stopped.set()
        with (
            patch.object(runtime_process, "DEFAULT_DEPENDENCY_FACTORY", return_value=plan),
            patch.object(threading, "Event", return_value=stopped),
            patch.object(sys, "argv", ["desire_platform.matching.runtime_process"]),
            warnings.catch_warnings(),
        ):
            # runpy warns because the test already imported the canonical module.
            warnings.simplefilter("ignore", RuntimeWarning)
            with self.assertRaises(SystemExit) as result:
                runpy.run_module("desire_platform.matching.runtime_process", run_name="__main__")
        self.assertEqual(result.exception.code, 0)
        self.assertEqual(resource.readiness_calls, [1_000])
        self.assertEqual(resource.closed, 1)

    def test_five_failures_remove_health_and_return_stable_failure(self) -> None:
        self.health.write_text("stale", encoding="utf-8")
        errors = [RuntimeError("secret payload must not appear")] * 5
        stderr = io.StringIO()
        sleeps: list[float] = []
        result = run_matching_runtime_loop(
            plan=self._plan(
                worker=_Runner(errors),
                coordinator=_Runner([_Tick("IDLE", False)]),
            ),
            stop_event=threading.Event(),
            sleeper=sleeps.append,
            stderr=stderr,
        )

        self.assertEqual(result.status, "FAILED")
        self.assertEqual(result.consecutive_failures, 5)
        self.assertFalse(self.health.exists())
        self.assertEqual(sleeps, [0.01, 0.02, 0.04, 0.08])
        self.assertEqual(
            stderr.getvalue(),
            '{"code":"MATCHING_RUNTIME_TICK_FAILED","status":"DEGRADED"}\n',
        )
        self.assertNotIn("secret payload", stderr.getvalue())

    def test_readiness_failure_is_generic_and_closes_every_resource(self) -> None:
        first = _Resource(readiness_error=RuntimeError("db detail"))
        second = _Resource()
        plan = self._plan(
            worker=_Runner([_Tick("IDLE", False)]),
            coordinator=_Runner([_Tick("IDLE", False)]),
            resources=(first, second),
        )
        stderr = io.StringIO()
        self.health.write_bytes(b'{"status":"READY"}\n')

        result = main(
            [],
            dependency_factory=lambda: plan,
            stop_event=threading.Event(),
            sleeper=lambda _seconds: None,
            stderr=stderr,
        )

        self.assertEqual(result, EX_CONFIG)
        self.assertEqual(first.closed, 1)
        self.assertEqual(second.closed, 1)
        self.assertFalse(self.health.exists())
        self.assertEqual(
            stderr.getvalue(),
            '{"code":"MATCHING_RUNTIME_STARTUP_FAILED","status":"BLOCKED"}\n',
        )
        self.assertNotIn("db detail", stderr.getvalue())

    def test_pre_stopped_main_checks_readiness_then_closes_cleanly(self) -> None:
        resource = _Resource()
        plan = self._plan(
            worker=_Runner([_Tick("IDLE", False)]),
            coordinator=_Runner([_Tick("IDLE", False)]),
            resources=(resource,),
        )
        stop = threading.Event()
        stop.set()

        result = main(
            [],
            dependency_factory=lambda: plan,
            stop_event=stop,
            stderr=io.StringIO(),
        )

        self.assertEqual(result, 0)
        self.assertEqual(resource.readiness_calls, [1_000])
        self.assertEqual(resource.closed, 1)
        self.assertFalse(self.health.exists())

    def test_secret_expiry_between_ticks_stops_before_coordinator_and_zeroizes(self) -> None:
        initial = datetime(2026, 8, 29, tzinfo=timezone.utc)
        current = [initial]
        carrier = FileSecretCarrier(
            purpose="MATCHING_WORKER_IDEMPOTENCY",
            key_id="matching-worker-idempotency-v1",
            not_before=initial - timedelta(minutes=1),
            not_after=initial + timedelta(seconds=1),
            status="ACTIVE",
            material=bytearray(b"k" * 48),
        )
        secrets = ManagedRuntimeSecrets(
            carriers=(carrier,),
            clock=lambda: current[0],
        )

        class ExpiringWorker:
            calls = 0

            def run_once(self):
                self.calls += 1
                current[0] = carrier.not_after
                return _Tick("IDLE", False)

        worker = ExpiringWorker()
        coordinator = _Runner([_Tick("IDLE", False)])
        plan = MatchingRuntimeProcessPlan(
            worker=worker,
            coordinator=coordinator,
            managed_resources=(secrets,),
            tick_readiness=secrets,
            health_file=self.health,
            readiness_timeout_ms=1_000,
            shutdown_timeout_ms=2_000,
            idle_seconds=0.01,
        )
        sleeps: list[float] = []

        result = main(
            [],
            dependency_factory=lambda: plan,
            stop_event=threading.Event(),
            sleeper=sleeps.append,
            stderr=io.StringIO(),
        )

        self.assertEqual(result, EX_SOFTWARE)
        self.assertEqual(worker.calls, 1)
        self.assertEqual(coordinator.calls, 0)
        self.assertEqual(sleeps, [])
        self.assertFalse(self.health.exists())
        self.assertTrue(carrier._destroyed)
        self.assertFalse(any(carrier.material))

    def test_secret_expiry_after_coordinator_prevents_health_refresh(self) -> None:
        initial = datetime(2026, 8, 29, tzinfo=timezone.utc)
        current = [initial]
        carrier = FileSecretCarrier(
            purpose="MATCHING_COORDINATOR_IDEMPOTENCY",
            key_id="matching-coordinator-idempotency-v1",
            not_before=initial - timedelta(minutes=1),
            not_after=initial + timedelta(seconds=1),
            status="ACTIVE",
            material=bytearray(b"c" * 48),
        )
        secrets = ManagedRuntimeSecrets(
            carriers=(carrier,), clock=lambda: current[0]
        )

        class ExpiringCoordinator:
            calls = 0

            def run_once(self):
                self.calls += 1
                current[0] = carrier.not_after
                return _Tick("IDLE", False)

        worker = _Runner([_Tick("IDLE", False)])
        coordinator = ExpiringCoordinator()
        plan = MatchingRuntimeProcessPlan(
            worker=worker,
            coordinator=coordinator,
            managed_resources=(secrets,),
            tick_readiness=secrets,
            health_file=self.health,
            readiness_timeout_ms=1_000,
            shutdown_timeout_ms=2_000,
            idle_seconds=0.01,
        )

        result = main(
            [],
            dependency_factory=lambda: plan,
            stop_event=threading.Event(),
            sleeper=lambda _seconds: self.fail("expiry must not retry"),
            stderr=io.StringIO(),
        )

        self.assertEqual(result, EX_SOFTWARE)
        self.assertEqual(worker.calls, 1)
        self.assertEqual(coordinator.calls, 1)
        self.assertFalse(self.health.exists())
        self.assertTrue(carrier._destroyed)
        self.assertFalse(any(carrier.material))

    def test_health_path_rejects_symlinked_parent_and_secret_tree(self) -> None:
        link = Path(self.temporary.name) / "link"
        target = Path(self.temporary.name) / "target"
        target.mkdir()
        link.symlink_to(target, target_is_directory=True)
        resource = _Resource()
        with self.assertRaises(ValueError):
            MatchingRuntimeProcessPlan(
                worker=_Runner([True]),
                coordinator=_Runner([True]),
                managed_resources=(resource,),
                tick_readiness=resource,
                health_file=link / "healthy",
                readiness_timeout_ms=1_000,
                shutdown_timeout_ms=2_000,
            )


if __name__ == "__main__":
    unittest.main()
