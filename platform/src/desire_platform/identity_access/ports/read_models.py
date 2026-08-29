"""Immutable, operation-specific ports for IAM application read models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import (
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
    Union,
)

from .access_invitation_capability import VerifiedAccessInvitationCapability


FrozenFactScalar = Union[None, bool, int, str, bytes, datetime]


@dataclass(frozen=True)
class FrozenFactObject:
    items: Tuple[Tuple[str, "FrozenFactValue"], ...] = field(repr=False)


@dataclass(frozen=True)
class FrozenFactArray:
    items: Tuple["FrozenFactValue", ...] = field(repr=False)


FrozenFactValue = Union[FrozenFactScalar, FrozenFactObject, FrozenFactArray]


class ReadModelStorageUnavailableError(Exception):
    """A defined read dependency failed before returning any facts."""


class ReadModelCursorInvalidError(Exception):
    """An opaque cursor is invalid, expired, or bound to another query."""


class ReadModelCursorUnavailableError(Exception):
    """A retained cursor key or codec implementation is unavailable."""


class SessionBootstrapCsrfUnavailableError(Exception):
    """The exact retained CSRF material cannot be used."""


@dataclass(frozen=True)
class ReadModelSnapshot:
    """One bounded read-only transaction result.

    ``facts`` may contain internal validation evidence, so it is deliberately
    excluded from repr.  A handler must project a separate closed safe result.
    """

    transaction_time: datetime
    statement_count: int
    facts: FrozenFactObject = field(repr=False)

    @classmethod
    def from_mapping(
        cls,
        *,
        transaction_time: datetime,
        statement_count: int,
        facts: Mapping[str, object],
    ) -> "ReadModelSnapshot":
        return cls(
            transaction_time=transaction_time,
            statement_count=statement_count,
            facts=_freeze_fact_object(facts),
        )

    def facts_copy(self) -> dict[str, object]:
        """Return a detached mutable copy for an application validator."""

        return thaw_fact_object(self.facts)


@dataclass(frozen=True)
class ReadPageWindow:
    limit: int
    snapshot_at: Optional[datetime] = None
    after_created_at: Optional[datetime] = None
    after_id: Optional[str] = None


@dataclass(frozen=True)
class ReadModelCursorClaims:
    version: str
    key_id: str
    operation_id: str
    actor_user_id: str
    organization_id: Optional[str]
    page_limit: int
    query_shape_digest: str
    snapshot_at: datetime
    after_created_at: datetime
    after_id: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class SessionBootstrapCsrfMaterial:
    session_id: str
    generation: int
    csrf_salt: bytes = field(repr=False)
    csrf_key_id: str = field(repr=False)
    csrf_digest: bytes = field(repr=False)


@dataclass(frozen=True)
class ReadModelTelemetryEvent:
    operation_id: str
    outcome_code: str
    authenticated: bool
    cursor_present: bool
    row_count_bucket: str
    latency_bucket: str
    trace_id: str


class ReadModelClock(Protocol):
    def now(self) -> datetime: ...


class ReadModelCursorCodec(Protocol):
    active_key_id: str

    def decode(self, raw_cursor: str) -> ReadModelCursorClaims: ...

    def encode(self, claims: ReadModelCursorClaims) -> str: ...


class SessionBootstrapCsrfPort(Protocol):
    def derive(
        self,
        *,
        raw_session_handle: str,
        material: SessionBootstrapCsrfMaterial,
    ) -> str: ...


class ReadModelTelemetryPort(Protocol):
    def record(self, event: ReadModelTelemetryEvent) -> None: ...


class IamReadModelRepository(Protocol):
    """Named query methods; implementations must not expose generic SQL/filter APIs."""

    def read_session_bootstrap(
        self, *, actor_user_id: str, session_id: str
    ) -> ReadModelSnapshot: ...

    def read_invitation_preview(
        self, *, capability: VerifiedAccessInvitationCapability
    ) -> ReadModelSnapshot: ...

    def read_public_policy_bundle(
        self, *, policy_bundle_id: str
    ) -> ReadModelSnapshot: ...

    def read_me(
        self, *, actor_user_id: str, session_id: str
    ) -> ReadModelSnapshot: ...

    def list_my_consent_grants(
        self,
        *,
        actor_user_id: str,
        session_id: str,
        window: ReadPageWindow,
    ) -> ReadModelSnapshot: ...

    def list_my_sessions(
        self,
        *,
        actor_user_id: str,
        session_id: str,
        window: ReadPageWindow,
    ) -> ReadModelSnapshot: ...

    def read_organization_summary(
        self,
        *,
        actor_user_id: str,
        session_id: str,
        organization_id: str,
    ) -> ReadModelSnapshot: ...

    def list_organization_access_invitations(
        self,
        *,
        actor_user_id: str,
        session_id: str,
        organization_id: str,
        window: ReadPageWindow,
    ) -> ReadModelSnapshot: ...

    def list_organization_memberships(
        self,
        *,
        actor_user_id: str,
        session_id: str,
        organization_id: str,
        window: ReadPageWindow,
    ) -> ReadModelSnapshot: ...


def _freeze_fact_object(value: Mapping[str, object]) -> FrozenFactObject:
    return FrozenFactObject(
        tuple((str(key), _freeze_fact_value(item)) for key, item in value.items())
    )


def _freeze_fact_value(value: object) -> FrozenFactValue:
    if value is None or isinstance(value, (bool, int, str, bytes, datetime)):
        return value
    if isinstance(value, Mapping):
        return _freeze_fact_object(value)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return FrozenFactArray(tuple(_freeze_fact_value(item) for item in value))
    raise TypeError("read-model facts must use immutable supported values")


def thaw_fact_object(value: FrozenFactObject) -> dict[str, object]:
    return {key: _thaw_fact_value(item) for key, item in value.items}


def freeze_fact_object(value: Mapping[str, object]) -> FrozenFactObject:
    """Freeze a closed application projection without exposing internals."""

    return _freeze_fact_object(value)


def _thaw_fact_value(value: FrozenFactValue) -> object:
    if isinstance(value, FrozenFactObject):
        return thaw_fact_object(value)
    if isinstance(value, FrozenFactArray):
        return [_thaw_fact_value(item) for item in value.items]
    return value


__all__ = [
    "FrozenFactArray",
    "FrozenFactObject",
    "IamReadModelRepository",
    "ReadModelClock",
    "ReadModelCursorClaims",
    "ReadModelCursorCodec",
    "ReadModelCursorInvalidError",
    "ReadModelCursorUnavailableError",
    "ReadModelSnapshot",
    "ReadModelStorageUnavailableError",
    "ReadModelTelemetryEvent",
    "ReadModelTelemetryPort",
    "ReadPageWindow",
    "SessionBootstrapCsrfMaterial",
    "SessionBootstrapCsrfPort",
    "SessionBootstrapCsrfUnavailableError",
    "freeze_fact_object",
    "thaw_fact_object",
]
