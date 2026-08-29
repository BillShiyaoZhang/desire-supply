"""Deterministic, rollback-capable IAM unit of work for application tests."""

from __future__ import annotations

from typing import Any, Mapping, Optional


class FaultInjector:
    """Counts instrumented writes and may fail at one deterministic checkpoint."""

    def __init__(
        self,
        fail_on_write: Optional[int] = None,
        fail_on_checkpoint: Optional[str] = None,
    ) -> None:
        if fail_on_write is not None and fail_on_checkpoint is not None:
            raise ValueError("choose an ordinal or named fault, not both")
        self.fail_on_write = fail_on_write
        self.fail_on_checkpoint = fail_on_checkpoint
        self.write_count = 0
        self.checkpoint_names: list[str] = []

    def before_write(self, checkpoint: str) -> None:
        """Fail immediately before the configured write mutates working state."""

        if not checkpoint or checkpoint in self.checkpoint_names:
            raise AssertionError("write checkpoints must be non-empty and unique")
        self.write_count += 1
        self.checkpoint_names.append(checkpoint)
        if (
            self.fail_on_write == self.write_count
            or self.fail_on_checkpoint == checkpoint
        ):
            raise RuntimeError("injected IAM write failure")


class InMemoryIamStore:
    """Owns isolated mutable tables while exposing copy-only test snapshots."""

    def __init__(self) -> None:
        self._tables: dict[str, dict[Any, Any]] = {}

    def seed(self, **tables: Mapping[Any, Any]) -> None:
        for name, values in tables.items():
            self._tables.setdefault(name, {}).update(_clone_mutable(dict(values)))

    def snapshot(self) -> dict[str, dict[Any, Any]]:
        return _clone_mutable(self._tables)


class MemoryUnitOfWorkFactory:
    """Creates isolated units that publish their working copy only on commit."""

    def __init__(self, *, store: InMemoryIamStore, fault_injector: FaultInjector) -> None:
        self.store = store
        self.fault_injector = fault_injector
        self.lock_calls: list[tuple[str, tuple[Any, ...]]] = []

    def begin(self) -> "MemoryUnitOfWork":
        return MemoryUnitOfWork(
            store=self.store,
            fault_injector=self.fault_injector,
            lock_calls=self.lock_calls,
        )


class MemoryUnitOfWork:
    """Single-use copy-on-write transaction with instrumented fact writes."""

    def __init__(
        self,
        *,
        store: InMemoryIamStore,
        fault_injector: FaultInjector,
        lock_calls: list[tuple[str, tuple[Any, ...]]],
    ) -> None:
        self._store = store
        self._fault_injector = fault_injector
        self._lock_calls = lock_calls
        self.tables = store.snapshot()
        self._committed = False

    def __enter__(self) -> "MemoryUnitOfWork":
        return self

    def __exit__(self, exception_type, exception, traceback) -> bool:
        if exception_type is None and self._committed:
            self._store._tables = self.tables
        return False

    def put(
        self,
        table: str,
        key: Any,
        value: Any,
        *,
        checkpoint: str,
    ) -> None:
        self._fault_injector.before_write(checkpoint)
        self.tables.setdefault(table, {})[key] = _clone_mutable(value)

    def lock(self, table: str, keys) -> None:
        normalized = tuple(keys)
        if len(normalized) > 1 and tuple(sorted(normalized)) != normalized:
            raise AssertionError("same-level IAM locks must be sorted")
        self._lock_calls.append((table, normalized))

    def get(self, table: str, key: Any) -> Any:
        return self.tables.get(table, {}).get(key)

    def values(self, table: str):
        return tuple(self.tables.get(table, {}).values())

    def commit(self) -> None:
        self._committed = True


def _clone_mutable(value):
    """Copy mutable fact containers while sharing immutable domain value objects."""

    if isinstance(value, dict):
        return {key: _clone_mutable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_clone_mutable(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_clone_mutable(item) for item in value)
    if isinstance(value, set):
        return {_clone_mutable(item) for item in value}
    return value
