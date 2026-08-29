"""Deeply immutable command facts for Creator Profile v1."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Tuple

from ..domain.model import (
    ArchiveReasonCode,
    CreatorProfile,
    PauseReasonCode,
    ProfileContent,
    ProfileVersion,
)


@dataclass(frozen=True)
class CreatorProfileActorContext:
    actor_user_id: str
    session_id: str = field(repr=False)
    correlation_id: str
    causation_id: str
    trace_id: str
    original_actor_id: Optional[str]


@dataclass(frozen=True)
class CreateCreatorProfileCommand:
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class SaveCreatorProfileDraftCommand:
    profile_id: str
    expected_version: int
    taxonomy_bundle_id: str
    based_on_profile_version_id: Optional[str]
    content: ProfileContent = field(repr=False)
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class PublishCreatorProfileVersionCommand:
    profile_id: str
    profile_version_id: str
    expected_version: int
    confirmed: bool
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class PauseCreatorProfileCommand:
    profile_id: str
    expected_version: int
    reason_code: PauseReasonCode
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class ResumeCreatorProfileCommand:
    profile_id: str
    expected_version: int
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class ArchiveCreatorProfileCommand:
    profile_id: str
    expected_version: int
    reason_code: ArchiveReasonCode
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class CreatorProfileCommandResult:
    profile: CreatorProfile
    affected_versions: Tuple[ProfileVersion, ...]
    replayed: bool
    event_types: Tuple[str, ...]
    completed_at: datetime
