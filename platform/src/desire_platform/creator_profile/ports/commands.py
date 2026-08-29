"""Closed dependency ports for Creator Profile command orchestration."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import (
    TYPE_CHECKING,
    Any,
    ContextManager,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
)

if TYPE_CHECKING:
    from ..application.commands import CreatorProfileActorContext


class CreatorProfileStorageUnavailableError(Exception):
    """Storage failed before COMMIT was sent."""


class CreatorProfileCommitOutcomeUnknownError(Exception):
    """COMMIT was sent but its durable result was not acknowledged."""


class CreatorProfileAuthorityUnavailableError(Exception):
    """The exact IAM authority projection could not be obtained safely."""


class CreatorProfileSafetyHoldUnavailableError(Exception):
    """The required SafetyHold decision could not be obtained safely."""


@dataclass(frozen=True)
class CreatorProfileAuthority:
    actor_user_id: str
    session_id: str = field(repr=False)
    user_status: str
    session_status: str
    session_family_status: str
    creator_grant_id: str
    creator_grant_version: int
    policy_selector_digest: str
    policy_bundle_id: str
    policy_requirements_satisfied: bool
    authority_marker_sha256: str


class CreatorProfileHoldDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class CreatorProfileSafetyHoldResult:
    decision: CreatorProfileHoldDecision
    profile_id: str
    prospective_aggregate_version: int
    content_sha256: str
    actor_user_id: str
    policy_version: str
    evaluated_at: datetime
    valid_until: datetime


class CreatorProfileAuthorityPort(Protocol):
    def authorize(
        self,
        *,
        actor: CreatorProfileActorContext,
        operation: str,
    ) -> CreatorProfileAuthority: ...


class CreatorProfileSafetyHoldPort(Protocol):
    def evaluate(
        self,
        *,
        actor_user_id: str,
        action: str,
        profile_id: str,
        prospective_aggregate_version: int,
        content_sha256: str,
        policy_version: str,
    ) -> CreatorProfileSafetyHoldResult: ...


class CreatorProfileClock(Protocol):
    def now(self) -> datetime: ...


class CreatorProfileIdSource(Protocol):
    def new_id(self, kind: str) -> str: ...


class CreatorProfileReceiptKeyring(Protocol):
    idempotency_key_digest_key_id: str
    payload_hash_key_id: str

    def keyed_digest(self, key_id: str, value: bytes) -> str: ...


class CreatorProfileSchemaValidator(Protocol):
    def validate(self, value: Mapping[str, Any], schema_name: str) -> None: ...


class CreatorProfileUnitOfWork(Protocol):
    def lock(self, resource: str, keys: Sequence[str]) -> None: ...

    def get(self, collection: str, key: str) -> Any: ...

    def values(self, collection: str) -> Tuple[Any, ...]: ...

    def put(
        self,
        collection: str,
        key: str,
        value: Any,
        *,
        checkpoint: str,
    ) -> None: ...

    def commit(self) -> None: ...


class CreatorProfileReadStore(Protocol):
    def snapshot(self) -> Mapping[str, Mapping[str, Any]]: ...


class CreatorProfileUnitOfWorkFactory(Protocol):
    store: CreatorProfileReadStore

    def begin(self) -> ContextManager[CreatorProfileUnitOfWork]: ...


__all__ = [
    "CreatorProfileAuthority",
    "CreatorProfileAuthorityPort",
    "CreatorProfileAuthorityUnavailableError",
    "CreatorProfileClock",
    "CreatorProfileCommitOutcomeUnknownError",
    "CreatorProfileHoldDecision",
    "CreatorProfileIdSource",
    "CreatorProfileReadStore",
    "CreatorProfileReceiptKeyring",
    "CreatorProfileSafetyHoldPort",
    "CreatorProfileSafetyHoldResult",
    "CreatorProfileSafetyHoldUnavailableError",
    "CreatorProfileSchemaValidator",
    "CreatorProfileStorageUnavailableError",
    "CreatorProfileUnitOfWork",
    "CreatorProfileUnitOfWorkFactory",
]
