"""I/O-free IAM role, relationship, state, MFA, and hold policy."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import FrozenSet, Optional

from .errors import IamError
from ..ports.safety_hold import HoldDecision


class Action(str, Enum):
    ISSUE_ACCESS_INVITATION = "ISSUE_ACCESS_INVITATION"
    ACCEPT_ACCESS_INVITATION = "ACCEPT_ACCESS_INVITATION"
    REVOKE_ACCESS_INVITATION = "REVOKE_ACCESS_INVITATION"
    SUSPEND_MEMBERSHIP = "SUSPEND_MEMBERSHIP"
    RESUME_MEMBERSHIP = "RESUME_MEMBERSHIP"
    REVOKE_MEMBERSHIP = "REVOKE_MEMBERSHIP"
    LOGOUT = "LOGOUT"
    REVOKE_SESSION = "REVOKE_SESSION"
    WITHDRAW_CONSENT = "WITHDRAW_CONSENT"


class UserStatus(str, Enum):
    PENDING_ENROLLMENT = "PENDING_ENROLLMENT"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    CLOSED = "CLOSED"


class OrganizationStatus(str, Enum):
    PENDING_ADMIN = "PENDING_ADMIN"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    CLOSED = "CLOSED"


class MembershipStatus(str, Enum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"


class Role(str, Enum):
    CREATOR = "CREATOR"
    ORG_ADMIN = "ORG_ADMIN"
    DEMAND_OWNER = "DEMAND_OWNER"
    SYSTEM = "SYSTEM"


@dataclass(frozen=True)
class ActorAuthorization:
    user_id: str
    user_status: UserStatus
    account_roles: FrozenSet[Role]
    membership_organization_id: Optional[str]
    membership_status: Optional[MembershipStatus]
    membership_roles: FrozenSet[Role]
    mfa_authenticated_at: Optional[datetime]


@dataclass(frozen=True)
class ResourceAuthorization:
    organization_id: str
    organization_status: OrganizationStatus
    target_membership_id: str
    target_membership_status: MembershipStatus
    target_membership_roles: FrozenSet[Role]
    active_org_admin_count: int


@dataclass(frozen=True)
class AuthorizationPolicy:
    mfa_max_age: timedelta

    def require(
        self,
        *,
        action: Action,
        actor: ActorAuthorization,
        resource: Optional[ResourceAuthorization],
        target_role: Optional[Role],
        hold_decision: HoldDecision,
        now: datetime,
    ) -> None:
        self_service = {
            Action.LOGOUT,
            Action.REVOKE_SESSION,
            Action.WITHDRAW_CONSENT,
        }
        if action in self_service:
            return

        if action == Action.ACCEPT_ACCESS_INVITATION:
            _require_authority_increase_allowed(hold_decision)
            if actor.user_status not in (
                UserStatus.PENDING_ENROLLMENT,
                UserStatus.ACTIVE,
            ):
                raise IamError("RESOURCE_NOT_FOUND")
            return

        organization_actions = {
            Action.ISSUE_ACCESS_INVITATION,
            Action.REVOKE_ACCESS_INVITATION,
            Action.SUSPEND_MEMBERSHIP,
            Action.RESUME_MEMBERSHIP,
            Action.REVOKE_MEMBERSHIP,
        }
        if action not in organization_actions or resource is None:
            raise IamError("RESOURCE_NOT_FOUND")

        same_active_admin_scope = (
            actor.user_status == UserStatus.ACTIVE
            and actor.membership_organization_id == resource.organization_id
            and actor.membership_status == MembershipStatus.ACTIVE
            and Role.ORG_ADMIN in actor.membership_roles
            and resource.organization_status == OrganizationStatus.ACTIVE
        )
        if not same_active_admin_scope:
            raise IamError("RESOURCE_NOT_FOUND")

        _require_recent_mfa(
            authenticated_at=actor.mfa_authenticated_at,
            now=now,
            maximum_age=self.mfa_max_age,
        )

        if action == Action.ISSUE_ACCESS_INVITATION:
            if target_role not in (Role.ORG_ADMIN, Role.DEMAND_OWNER):
                raise IamError("ROLE_SCOPE_VIOLATION")
            _require_authority_increase_allowed(hold_decision)
            return

        if action == Action.RESUME_MEMBERSHIP:
            if resource.target_membership_status != MembershipStatus.SUSPENDED:
                raise IamError("RESOURCE_NOT_FOUND")
            _require_authority_increase_allowed(hold_decision)
            return

        if action == Action.SUSPEND_MEMBERSHIP:
            if resource.target_membership_status != MembershipStatus.ACTIVE:
                raise IamError("RESOURCE_NOT_FOUND")
            _require_not_last_admin(resource)
            return

        if action == Action.REVOKE_MEMBERSHIP:
            if resource.target_membership_status not in (
                MembershipStatus.ACTIVE,
                MembershipStatus.SUSPENDED,
            ):
                raise IamError("RESOURCE_NOT_FOUND")
            _require_not_last_admin(resource)
            return

        if action == Action.REVOKE_ACCESS_INVITATION:
            return

        raise IamError("RESOURCE_NOT_FOUND")


def _require_authority_increase_allowed(decision: HoldDecision) -> None:
    if decision == HoldDecision.BLOCK:
        raise IamError("SAFETY_HOLD_BLOCKED")
    if decision == HoldDecision.UNAVAILABLE:
        raise IamError("SAFETY_DECISION_UNAVAILABLE")
    if decision != HoldDecision.ALLOW:
        raise IamError("SAFETY_DECISION_UNAVAILABLE")


def _require_recent_mfa(
    *,
    authenticated_at: Optional[datetime],
    now: datetime,
    maximum_age: timedelta,
) -> None:
    if authenticated_at is None:
        raise IamError("MFA_STEP_UP_REQUIRED")
    if now.tzinfo is None or authenticated_at.tzinfo is None:
        raise IamError("MFA_STEP_UP_REQUIRED")
    age = now - authenticated_at
    if age < timedelta(0) or age >= maximum_age:
        raise IamError("MFA_STEP_UP_REQUIRED")


def _require_not_last_admin(resource: ResourceAuthorization) -> None:
    if (
        Role.ORG_ADMIN in resource.target_membership_roles
        and resource.active_org_admin_count <= 1
    ):
        raise IamError("LAST_ACTIVE_ORG_ADMIN")
