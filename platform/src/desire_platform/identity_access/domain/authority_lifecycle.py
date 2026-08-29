"""Closed command values for IAM authority-reducing lifecycle operations.

The value shapes are intentionally importable before behavior exists.  The
application handlers remain fail-closed until their semantic RED suite is made
green against the authority-lifecycle design.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional


@dataclass(frozen=True)
class LifecycleActorContext:
    actor_user_id: str
    current_session_id: str
    original_actor_id: Optional[str]
    correlation_id: str
    causation_id: str
    trace_id: str


@dataclass(frozen=True)
class LifecycleReason:
    reason_code: str
    reason_note: Optional[str] = field(default=None, repr=False)


@dataclass(frozen=True)
class RevokeAccessInvitationCommand:
    invitation_id: str
    expected_version: int
    idempotency_key: str = field(repr=False)
    reason: LifecycleReason


@dataclass(frozen=True)
class WithdrawConsentGrantCommand:
    consent_grant_id: str
    expected_version: int
    idempotency_key: str = field(repr=False)
    reason: LifecycleReason


@dataclass(frozen=True)
class RevokeSessionCommand:
    session_id: str
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class SuspendMembershipCommand:
    membership_id: str
    expected_version: int
    idempotency_key: str = field(repr=False)
    reason: LifecycleReason


@dataclass(frozen=True)
class ResumeMembershipCommand:
    membership_id: str
    expected_version: int
    idempotency_key: str = field(repr=False)
    reason: LifecycleReason


@dataclass(frozen=True)
class RevokeMembershipCommand:
    membership_id: str
    expected_version: int
    idempotency_key: str = field(repr=False)
    reason: LifecycleReason


@dataclass(frozen=True)
class SuspendUserCommand:
    user_id: str
    expected_version: int
    idempotency_key: str = field(repr=False)
    reason: LifecycleReason


@dataclass(frozen=True)
class ResumeUserCommand:
    user_id: str
    expected_version: int
    idempotency_key: str = field(repr=False)
    reason: LifecycleReason


@dataclass(frozen=True)
class RevokeAllSessionsCommand:
    user_id: str
    expected_version: int
    idempotency_key: str = field(repr=False)
    reason: LifecycleReason


@dataclass(frozen=True)
class RevokeReplayedSessionFamilyCommand:
    security_event_id: str
    replayed_session_id: str
    session_family_id: str
    user_id: str


@dataclass(frozen=True)
class LifecycleCommandResult:
    replayed: bool
    http_status: int
    safe_response: Optional[Mapping[str, Any]]
    clear_current_session_cookie: bool = False


__all__ = [
    "LifecycleActorContext",
    "LifecycleCommandResult",
    "LifecycleReason",
    "ResumeMembershipCommand",
    "ResumeUserCommand",
    "RevokeAccessInvitationCommand",
    "RevokeMembershipCommand",
    "RevokeReplayedSessionFamilyCommand",
    "RevokeSessionCommand",
    "RevokeAllSessionsCommand",
    "SuspendMembershipCommand",
    "SuspendUserCommand",
    "WithdrawConsentGrantCommand",
]
