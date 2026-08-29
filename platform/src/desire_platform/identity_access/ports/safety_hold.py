"""Closed Trust safety-hold port and strict deterministic test adapter."""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class HoldDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    UNAVAILABLE = "UNAVAILABLE"


class SafetyHoldUnavailableError(Exception):
    """The provider could not return a decision through its defined boundary."""


@dataclass(frozen=True)
class SafetyHoldQuery:
    actor_id: str
    action: str
    target_type: str
    target_id: str
    target_version: int
    organization_id: Optional[str]
    policy_version: str


@dataclass(frozen=True)
class SafetyHoldDecisionResult:
    """Short-lived result bound to one exact authority-increasing target fact."""

    decision: HoldDecision
    action: str
    target_type: str
    target_id: str
    target_version: int
    organization_id: Optional[str]
    policy_version: str
    evaluated_at: datetime
    valid_until: datetime


class StrictFakeSafetyHold:
    """Records exact calls and returns one configured, exact decision result."""

    def __init__(
        self,
        *,
        decision: HoldDecision,
        evaluated_at: Optional[datetime] = None,
        valid_until: Optional[datetime] = None,
    ) -> None:
        self.decision = decision
        # Explicit times are preferred.  Wide defaults retain the small public
        # fake constructor used by contract tests without consulting a real clock.
        self.evaluated_at = evaluated_at or datetime.min.replace(tzinfo=timezone.utc)
        self.valid_until = valid_until or datetime.max.replace(tzinfo=timezone.utc)
        self.calls: list[SafetyHoldQuery] = []

    def decide(self, query: SafetyHoldQuery) -> SafetyHoldDecisionResult:
        self.calls.append(query)
        return SafetyHoldDecisionResult(
            decision=self.decision,
            action=query.action,
            target_type=query.target_type,
            target_id=query.target_id,
            target_version=query.target_version,
            organization_id=query.organization_id,
            policy_version=query.policy_version,
            evaluated_at=self.evaluated_at,
            valid_until=self.valid_until,
        )

    def evaluate(
        self,
        *,
        actor_id: str,
        action: str,
        target_type: str,
        target_id: str,
        target_version: int,
        organization_id: Optional[str],
        policy_version: str,
    ) -> SafetyHoldDecisionResult:
        return self.decide(
            SafetyHoldQuery(
                actor_id=actor_id,
                action=action,
                target_type=target_type,
                target_id=target_id,
                target_version=target_version,
                organization_id=organization_id,
                policy_version=policy_version,
            )
        )
