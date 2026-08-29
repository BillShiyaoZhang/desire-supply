"""Semantic RED tests for IAM tenant authorization and safety holds.

Expected production API:

``desire_platform.identity_access.domain.authorization`` exports the closed enums
and immutable policy inputs below plus ``AuthorizationPolicy.require``. A denial
raises ``IamError`` with a stable code; success returns ``None``. The policy inputs
contain only facts already loaded by an application service and never perform I/O.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from desire_platform.identity_access.domain.authorization import (
    Action,
    ActorAuthorization,
    AuthorizationPolicy,
    MembershipStatus,
    OrganizationStatus,
    ResourceAuthorization,
    Role,
    UserStatus,
)
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.ports.safety_hold import HoldDecision


class IamAuthorizationPolicyTestCase(unittest.TestCase):
    """TEST-UNIT-TENANT-001 and pure TEST-APP-HOLD-IAM-001 policy cases."""

    def setUp(self) -> None:
        self.now = datetime(2026, 8, 7, 12, 0, tzinfo=timezone.utc)
        self.policy = AuthorizationPolicy(mfa_max_age=timedelta(minutes=10))

    def actor(self, **overrides) -> ActorAuthorization:
        values = {
            "user_id": "user_admin_0001",
            "user_status": UserStatus.ACTIVE,
            "account_roles": frozenset(),
            "membership_organization_id": "org_alpha_0001",
            "membership_status": MembershipStatus.ACTIVE,
            "membership_roles": frozenset({Role.ORG_ADMIN}),
            "mfa_authenticated_at": self.now - timedelta(minutes=5),
        }
        values.update(overrides)
        return ActorAuthorization(**values)

    def resource(self, **overrides) -> ResourceAuthorization:
        values = {
            "organization_id": "org_alpha_0001",
            "organization_status": OrganizationStatus.ACTIVE,
            "target_membership_id": "membership_target_0001",
            "target_membership_status": MembershipStatus.ACTIVE,
            "target_membership_roles": frozenset({Role.DEMAND_OWNER}),
            "active_org_admin_count": 2,
        }
        values.update(overrides)
        return ResourceAuthorization(**values)

    def require(
        self,
        action: Action,
        *,
        actor: ActorAuthorization | None = None,
        resource: ResourceAuthorization | None = None,
        target_role: Role | None = None,
        hold_decision: HoldDecision = HoldDecision.ALLOW,
    ) -> None:
        self.assertIsNone(
            self.policy.require(
                action=action,
                actor=actor or self.actor(),
                resource=resource,
                target_role=target_role,
                hold_decision=hold_decision,
                now=self.now,
            )
        )

    def assert_denied(
        self,
        expected_code: str,
        action: Action,
        *,
        actor: ActorAuthorization | None = None,
        resource: ResourceAuthorization | None = None,
        target_role: Role | None = None,
        hold_decision: HoldDecision = HoldDecision.ALLOW,
    ) -> None:
        with self.assertRaises(IamError) as raised:
            self.policy.require(
                action=action,
                actor=actor or self.actor(),
                resource=resource,
                target_role=target_role,
                hold_decision=hold_decision,
                now=self.now,
            )
        self.assertEqual(raised.exception.code, expected_code)

    def test_active_same_org_admin_with_fresh_mfa_can_manage_invites_and_members(self):
        management_cases = (
            (
                Action.ISSUE_ACCESS_INVITATION,
                self.resource(),
                Role.DEMAND_OWNER,
            ),
            (Action.REVOKE_ACCESS_INVITATION, self.resource(), None),
            (Action.SUSPEND_MEMBERSHIP, self.resource(), None),
            (
                Action.RESUME_MEMBERSHIP,
                self.resource(target_membership_status=MembershipStatus.SUSPENDED),
                None,
            ),
            (Action.REVOKE_MEMBERSHIP, self.resource(), None),
        )

        for action, resource, target_role in management_cases:
            with self.subTest(action=action):
                self.require(
                    action,
                    resource=resource,
                    target_role=target_role,
                )

    def test_same_role_across_org_is_default_deny_and_non_disclosing(self):
        cross_org_actor = self.actor(
            membership_organization_id="org_other_0002"
        )

        for action in (
            Action.ISSUE_ACCESS_INVITATION,
            Action.REVOKE_ACCESS_INVITATION,
            Action.SUSPEND_MEMBERSHIP,
            Action.RESUME_MEMBERSHIP,
            Action.REVOKE_MEMBERSHIP,
        ):
            resource = self.resource(
                target_membership_status=(
                    MembershipStatus.SUSPENDED
                    if action == Action.RESUME_MEMBERSHIP
                    else MembershipStatus.ACTIVE
                )
            )
            with self.subTest(action=action):
                self.assert_denied(
                    "RESOURCE_NOT_FOUND",
                    action,
                    actor=cross_org_actor,
                    resource=resource,
                    target_role=(
                        Role.DEMAND_OWNER
                        if action == Action.ISSUE_ACCESS_INVITATION
                        else None
                    ),
                )

    def test_creator_demand_owner_and_no_relation_are_default_deny(self):
        unauthorized_actors = (
            self.actor(
                account_roles=frozenset({Role.CREATOR}),
                membership_roles=frozenset(),
            ),
            self.actor(membership_roles=frozenset({Role.DEMAND_OWNER})),
            self.actor(
                membership_organization_id=None,
                membership_status=None,
                membership_roles=frozenset(),
            ),
        )

        for unauthorized_actor in unauthorized_actors:
            with self.subTest(actor=unauthorized_actor):
                self.assert_denied(
                    "RESOURCE_NOT_FOUND",
                    Action.ISSUE_ACCESS_INVITATION,
                    actor=unauthorized_actor,
                    resource=self.resource(),
                    target_role=Role.DEMAND_OWNER,
                )

    def test_adjacent_user_org_and_actor_membership_states_are_non_disclosing(self):
        adjacent_user_statuses = (
            UserStatus.PENDING_ENROLLMENT,
            UserStatus.SUSPENDED,
            UserStatus.CLOSED,
        )
        for status in adjacent_user_statuses:
            with self.subTest(user_status=status):
                self.assert_denied(
                    "RESOURCE_NOT_FOUND",
                    Action.SUSPEND_MEMBERSHIP,
                    actor=self.actor(user_status=status),
                    resource=self.resource(),
                )

        adjacent_org_statuses = (
            OrganizationStatus.PENDING_ADMIN,
            OrganizationStatus.SUSPENDED,
            OrganizationStatus.CLOSED,
        )
        for status in adjacent_org_statuses:
            with self.subTest(organization_status=status):
                self.assert_denied(
                    "RESOURCE_NOT_FOUND",
                    Action.SUSPEND_MEMBERSHIP,
                    resource=self.resource(organization_status=status),
                )

        for status in (MembershipStatus.SUSPENDED, MembershipStatus.REVOKED, None):
            with self.subTest(actor_membership_status=status):
                self.assert_denied(
                    "RESOURCE_NOT_FOUND",
                    Action.SUSPEND_MEMBERSHIP,
                    actor=self.actor(membership_status=status),
                    resource=self.resource(),
                )

    def test_last_active_org_admin_cannot_be_suspended_or_revoked(self):
        last_admin = self.resource(
            target_membership_roles=frozenset({Role.ORG_ADMIN}),
            active_org_admin_count=1,
        )

        for action in (Action.SUSPEND_MEMBERSHIP, Action.REVOKE_MEMBERSHIP):
            with self.subTest(action=action):
                self.assert_denied(
                    "LAST_ACTIVE_ORG_ADMIN",
                    action,
                    resource=last_admin,
                )

        not_last_admin = self.resource(
            target_membership_roles=frozenset({Role.ORG_ADMIN}),
            active_org_admin_count=2,
        )
        self.require(Action.SUSPEND_MEMBERSHIP, resource=not_last_admin)
        self.require(Action.REVOKE_MEMBERSHIP, resource=not_last_admin)

    def test_all_org_admin_mutations_require_recent_mfa(self):
        management_cases = (
            (
                Action.ISSUE_ACCESS_INVITATION,
                self.resource(),
                Role.DEMAND_OWNER,
            ),
            (Action.REVOKE_ACCESS_INVITATION, self.resource(), None),
            (Action.SUSPEND_MEMBERSHIP, self.resource(), None),
            (
                Action.RESUME_MEMBERSHIP,
                self.resource(target_membership_status=MembershipStatus.SUSPENDED),
                None,
            ),
            (Action.REVOKE_MEMBERSHIP, self.resource(), None),
        )
        actors_without_recent_mfa = (
            self.actor(mfa_authenticated_at=None),
            self.actor(mfa_authenticated_at=self.now - timedelta(minutes=11)),
        )

        for actor in actors_without_recent_mfa:
            for action, resource, target_role in management_cases:
                with self.subTest(actor=actor, action=action):
                    self.assert_denied(
                        "MFA_STEP_UP_REQUIRED",
                        action,
                        actor=actor,
                        resource=resource,
                        target_role=target_role,
                    )

    def test_org_admin_can_invite_org_roles_but_not_user_or_platform_roles(self):
        for allowed_role in (Role.ORG_ADMIN, Role.DEMAND_OWNER):
            with self.subTest(role=allowed_role):
                self.require(
                    Action.ISSUE_ACCESS_INVITATION,
                    resource=self.resource(),
                    target_role=allowed_role,
                )

        for forbidden_role in (Role.CREATOR, Role.SYSTEM):
            with self.subTest(role=forbidden_role):
                self.assert_denied(
                    "ROLE_SCOPE_VIOLATION",
                    Action.ISSUE_ACCESS_INVITATION,
                    resource=self.resource(),
                    target_role=forbidden_role,
                )

    def test_hold_block_and_unavailable_fail_closed_for_authority_increase(self):
        authority_increasing_cases = (
            (
                Action.ISSUE_ACCESS_INVITATION,
                self.resource(),
                Role.DEMAND_OWNER,
            ),
            (Action.ACCEPT_ACCESS_INVITATION, self.resource(), None),
            (
                Action.RESUME_MEMBERSHIP,
                self.resource(target_membership_status=MembershipStatus.SUSPENDED),
                None,
            ),
        )

        for decision in (HoldDecision.BLOCK, HoldDecision.UNAVAILABLE):
            for action, resource, target_role in authority_increasing_cases:
                with self.subTest(decision=decision, action=action):
                    self.assert_denied(
                        (
                            "SAFETY_HOLD_BLOCKED"
                            if decision == HoldDecision.BLOCK
                            else "SAFETY_DECISION_UNAVAILABLE"
                        ),
                        action,
                        resource=resource,
                        target_role=target_role,
                        hold_decision=decision,
                    )

    def test_hold_does_not_block_privacy_or_authority_reduction(self):
        self_service_actor = self.actor(
            membership_organization_id=None,
            membership_status=None,
            membership_roles=frozenset(),
            mfa_authenticated_at=None,
        )
        self_service_actions = (
            Action.LOGOUT,
            Action.REVOKE_SESSION,
            Action.WITHDRAW_CONSENT,
        )
        organization_safety_actions = (
            Action.REVOKE_ACCESS_INVITATION,
            Action.SUSPEND_MEMBERSHIP,
            Action.REVOKE_MEMBERSHIP,
        )

        for decision in (HoldDecision.BLOCK, HoldDecision.UNAVAILABLE):
            for action in self_service_actions:
                with self.subTest(decision=decision, action=action):
                    self.require(
                        action,
                        actor=self_service_actor,
                        hold_decision=decision,
                    )
            for action in organization_safety_actions:
                with self.subTest(decision=decision, action=action):
                    self.require(
                        action,
                        resource=self.resource(),
                        hold_decision=decision,
                    )

    def test_mfa_ten_minute_deadline_is_exclusive(self):
        just_fresh = self.actor(
            mfa_authenticated_at=self.now - timedelta(minutes=10) + timedelta(microseconds=1)
        )
        at_deadline = self.actor(
            mfa_authenticated_at=self.now - timedelta(minutes=10)
        )
        stale = self.actor(
            mfa_authenticated_at=self.now - timedelta(minutes=10, microseconds=1)
        )

        self.require(
            Action.ISSUE_ACCESS_INVITATION,
            actor=just_fresh,
            resource=self.resource(),
            target_role=Role.DEMAND_OWNER,
        )
        for actor in (at_deadline, stale):
            with self.subTest(mfa_authenticated_at=actor.mfa_authenticated_at):
                self.assert_denied(
                    "MFA_STEP_UP_REQUIRED",
                    Action.ISSUE_ACCESS_INVITATION,
                    actor=actor,
                    resource=self.resource(),
                    target_role=Role.DEMAND_OWNER,
                )


if __name__ == "__main__":
    unittest.main()
