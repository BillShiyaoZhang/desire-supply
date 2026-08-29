"""Narrow ports for current-policy acceptance and consent-grant commands."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, ContextManager, Mapping, Optional, Protocol, Sequence


class PolicyConsentStorageUnavailableError(Exception):
    """A defined storage dependency failed before COMMIT was sent."""


class PolicyConsentCommitOutcomeUnknownError(Exception):
    """The connection failed after COMMIT was sent and the outcome is unknown."""


class PolicyConsentKeyUnavailableError(Exception):
    """A configured active or retained cryptographic key is unavailable."""


class PolicyConsentSchemaUnavailableError(Exception):
    """A required closed event or safe-response schema cannot be applied."""


@dataclass(frozen=True)
class PolicyConsentTelemetryEvent:
    """Closed, value-free telemetry emitted after an application outcome."""

    operation_id: str
    outcome_code: str
    replayed: bool
    change_count_bucket: str
    latency_bucket: str
    trace_id: str


class PolicyConsentClock(Protocol):
    def now(self) -> datetime: ...


class PolicyConsentIdSource(Protocol):
    def new_id(self, kind: str) -> str: ...


class PolicyConsentKeyring(Protocol):
    idempotency_key_digest_key_id: str
    payload_hash_key_id: str

    def keyed_digest_hex(self, *, key_id: str, canonical_bytes: bytes) -> str: ...


class PolicyConsentSchemaValidator(Protocol):
    def validate(self, value: Mapping[str, Any], schema_name: str = "") -> None: ...


class PolicyConsentTelemetryPort(Protocol):
    def record(self, event: PolicyConsentTelemetryEvent) -> None: ...


class PolicyConsentCommandReadStore(Protocol):
    def snapshot(self) -> Mapping[str, Mapping[Any, Any]]: ...


class PolicyConsentCommandUnitOfWork(Protocol):
    """Operation-scoped transactional port; it exposes no arbitrary SQL seam."""

    tables: Mapping[str, Mapping[Any, Any]]

    def lock(self, table: str, keys: Sequence[Any]) -> None: ...

    def get(self, table: str, key: Any) -> Any: ...

    def values(self, table: str) -> Sequence[Any]: ...

    def put(self, table: str, key: Any, value: Any, *, checkpoint: str) -> None: ...

    def commit(self) -> None: ...


class PolicyConsentCommandUnitOfWorkFactory(Protocol):
    store: PolicyConsentCommandReadStore

    def begin(self) -> ContextManager[PolicyConsentCommandUnitOfWork]: ...


__all__ = [
    "PolicyConsentClock",
    "PolicyConsentCommandReadStore",
    "PolicyConsentCommandUnitOfWork",
    "PolicyConsentCommandUnitOfWorkFactory",
    "PolicyConsentCommitOutcomeUnknownError",
    "PolicyConsentIdSource",
    "PolicyConsentKeyUnavailableError",
    "PolicyConsentKeyring",
    "PolicyConsentSchemaUnavailableError",
    "PolicyConsentSchemaValidator",
    "PolicyConsentStorageUnavailableError",
    "PolicyConsentTelemetryEvent",
    "PolicyConsentTelemetryPort",
]
