"""Narrow ports used by IAM authority-lifecycle application handlers."""

from __future__ import annotations

from datetime import datetime
from typing import Any, ContextManager, Mapping, Protocol, Sequence


class LifecycleStorageUnavailableError(Exception):
    """A defined storage dependency failed before COMMIT was sent."""


class LifecycleCommitOutcomeUnknownError(Exception):
    """The database outcome became unknown after COMMIT was sent."""


class LifecycleClock(Protocol):
    def now(self) -> datetime: ...


class LifecycleIdSource(Protocol):
    def new_id(self, kind: str) -> str: ...


class LifecycleSchemaValidator(Protocol):
    def validate(self, value: Mapping[str, Any]) -> None: ...


class AuthorityLifecycleReadStore(Protocol):
    def snapshot(self) -> Mapping[str, Mapping[str, Any]]: ...


class AuthorityLifecycleUnitOfWork(Protocol):
    tables: Mapping[str, Mapping[str, Any]]

    def lock(self, table: str, keys: Sequence[str]) -> None: ...

    def get(self, table: str, key: str) -> Any: ...

    def values(self, table: str) -> Sequence[Any]: ...

    def put(self, table: str, key: str, value: Any, *, checkpoint: str) -> None: ...

    def commit(self) -> None: ...


class AuthorityLifecycleUnitOfWorkFactory(Protocol):
    store: AuthorityLifecycleReadStore

    def begin(self) -> ContextManager[AuthorityLifecycleUnitOfWork]: ...


__all__ = [
    "AuthorityLifecycleUnitOfWork",
    "AuthorityLifecycleUnitOfWorkFactory",
    "AuthorityLifecycleReadStore",
    "LifecycleClock",
    "LifecycleCommitOutcomeUnknownError",
    "LifecycleIdSource",
    "LifecycleSchemaValidator",
    "LifecycleStorageUnavailableError",
]
