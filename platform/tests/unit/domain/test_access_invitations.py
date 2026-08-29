"""TEST-UNIT-IAM-001 semantic RED tests for AccessInvitation."""

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
import unittest

from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.domain.invitations import (
    AccessInvitation,
    InvitationBindingEvidence,
    InvitationPurpose,
    InvitationStatus,
    TargetRole,
    TargetScope,
)


class FixedUtcClock:
    """Deterministic server UTC clock used by domain tests."""

    def __init__(self, current: datetime):
        if current.tzinfo is None or current.utcoffset() != timedelta(0):
            raise ValueError("FixedUtcClock requires an aware UTC datetime")
        self._current = current

    def now(self) -> datetime:
        return self._current

    def advance(self, delta: timedelta) -> None:
        self._current += delta


class AccessInvitationTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FixedUtcClock(
            datetime(2026, 8, 7, 9, 30, tzinfo=timezone.utc)
        )

    def assert_iam_error(self, expected_code, operation) -> None:
        with self.assertRaises(IamError) as raised:
            operation()
        self.assertEqual(raised.exception.code, expected_code)

    def creator_invitation(self, **overrides) -> AccessInvitation:
        values = {
            "invitation_id": "inv_creator_001",
            "purpose": InvitationPurpose.CREATOR_ENROLLMENT,
            "target_scope": TargetScope.USER,
            "target_role": TargetRole.CREATOR,
            "organization_id": None,
            "is_initial_admin": False,
            "recipient_contact_id": "contact_creator_001",
            "issued_policy_bundle_id": "bundle_creator_v1",
            "policy_selector_digest": "f" * 64,
            "status": InvitationStatus.ISSUED,
            "expires_at": self.clock.now() + timedelta(days=7),
            "aggregate_version": 1,
        }
        values.update(overrides)
        return AccessInvitation(**values)

    def organization_invitation(self, **overrides) -> AccessInvitation:
        values = {
            "invitation_id": "inv_org_001",
            "purpose": InvitationPurpose.ORGANIZATION_MEMBERSHIP,
            "target_scope": TargetScope.ORGANIZATION,
            "target_role": TargetRole.DEMAND_OWNER,
            "organization_id": "org_example_001",
            "is_initial_admin": False,
            "recipient_contact_id": "contact_org_001",
            "issued_policy_bundle_id": "bundle_org_v1",
            "policy_selector_digest": "e" * 64,
            "status": InvitationStatus.ISSUED,
            "expires_at": self.clock.now() + timedelta(days=7),
            "aggregate_version": 1,
        }
        values.update(overrides)
        return AccessInvitation(**values)

    @staticmethod
    def binding_for(invitation: AccessInvitation) -> InvitationBindingEvidence:
        return InvitationBindingEvidence(
            invitation_id=invitation.invitation_id,
            recipient_contact_id=invitation.recipient_contact_id,
            invitation_version=invitation.aggregate_version,
        )

    def test_req_iam_001_accepts_only_the_three_legal_single_role_targets(self):
        """Creator, organization member, and initial admin targets are exact."""

        invitations = (
            self.creator_invitation(),
            self.organization_invitation(target_role=TargetRole.DEMAND_OWNER),
            self.organization_invitation(target_role=TargetRole.ORG_ADMIN),
            self.organization_invitation(
                target_role=TargetRole.ORG_ADMIN,
                is_initial_admin=True,
            ),
        )

        for invitation in invitations:
            with self.subTest(
                purpose=invitation.purpose,
                role=invitation.target_role,
                initial=invitation.is_initial_admin,
            ):
                self.assertEqual(invitation.status, InvitationStatus.ISSUED)
                self.assertEqual(invitation.aggregate_version, 1)

    def test_req_iam_001_rejects_illegal_purpose_scope_role_org_combinations(self):
        """Purpose is a closed discriminator for scope, role, org, and initial admin."""

        invalid_factories = (
            lambda: self.creator_invitation(target_scope=TargetScope.ORGANIZATION),
            lambda: self.creator_invitation(target_role=TargetRole.ORG_ADMIN),
            lambda: self.creator_invitation(organization_id="org_forbidden"),
            lambda: self.creator_invitation(is_initial_admin=True),
            lambda: self.creator_invitation(target_role=None),
            lambda: self.organization_invitation(target_scope=TargetScope.USER),
            lambda: self.organization_invitation(target_role=TargetRole.CREATOR),
            lambda: self.organization_invitation(organization_id=None),
            lambda: self.organization_invitation(
                target_role=TargetRole.DEMAND_OWNER,
                is_initial_admin=True,
            ),
            lambda: self.organization_invitation(target_scope=None),
        )

        for factory in invalid_factories:
            with self.subTest(factory=factory):
                self.assert_iam_error("INVALID_INVITATION_TARGET", factory)

    def test_req_iam_001_accept_deadline_is_exclusive_and_expire_is_inclusive(self):
        """At expires_at equality, accept fails and expire may materialize EXPIRED."""

        deadline = self.clock.now() + timedelta(minutes=10)
        invitation = self.creator_invitation(expires_at=deadline)
        evidence = self.binding_for(invitation)

        accepted = invitation.accept(
            now=deadline - timedelta(microseconds=1),
            expected_version=1,
            evidence=evidence,
        )
        self.assertEqual(accepted.status, InvitationStatus.ACCEPTED)

        self.assert_iam_error(
            "ACCESS_INVITATION_EXPIRED",
            lambda: invitation.accept(
                now=deadline,
                expected_version=1,
                evidence=evidence,
            ),
        )
        self.assert_iam_error(
            "ACCESS_INVITATION_NOT_EXPIRED",
            lambda: invitation.expire(
                now=deadline - timedelta(microseconds=1),
                expected_version=1,
            ),
        )

        expired = invitation.expire(now=deadline, expected_version=1)
        self.assertEqual(expired.status, InvitationStatus.EXPIRED)
        self.assertEqual(expired.aggregate_version, 2)
        self.assertEqual(invitation.status, InvitationStatus.ISSUED)
        self.assertEqual(invitation.aggregate_version, 1)

    def test_req_iam_001_accept_requires_exact_invitation_contact_and_version_binding(self):
        """Onboarding evidence cannot cross invitation, contact, or version boundaries."""

        invitation = self.creator_invitation()
        wrong_evidence = (
            InvitationBindingEvidence(
                invitation_id="inv_other",
                recipient_contact_id=invitation.recipient_contact_id,
                invitation_version=1,
            ),
            InvitationBindingEvidence(
                invitation_id=invitation.invitation_id,
                recipient_contact_id="contact_other",
                invitation_version=1,
            ),
            InvitationBindingEvidence(
                invitation_id=invitation.invitation_id,
                recipient_contact_id=invitation.recipient_contact_id,
                invitation_version=2,
            ),
        )

        for evidence in wrong_evidence:
            with self.subTest(evidence=evidence):
                self.assert_iam_error(
                    "ACCESS_INVITATION_BINDING_MISMATCH",
                    lambda evidence=evidence: invitation.accept(
                        now=self.clock.now(),
                        expected_version=1,
                        evidence=evidence,
                    ),
                )

        self.assert_iam_error(
            "PRECONDITION_FAILED",
            lambda: invitation.accept(
                now=self.clock.now(),
                expected_version=2,
                evidence=self.binding_for(invitation),
            ),
        )

        accepted = invitation.accept(
            now=self.clock.now(),
            expected_version=1,
            evidence=self.binding_for(invitation),
        )
        self.assertEqual(accepted.status, InvitationStatus.ACCEPTED)
        self.assertEqual(accepted.aggregate_version, 2)

    def test_req_iam_001_each_issued_invitation_reaches_exactly_one_terminal_state(self):
        """Every terminal state is monotonic and cannot be revived or exchanged."""

        issued = self.creator_invitation()
        terminals = (
            issued.accept(
                now=self.clock.now(),
                expected_version=1,
                evidence=self.binding_for(issued),
            ),
            issued.revoke(now=self.clock.now(), expected_version=1),
            issued.expire(now=issued.expires_at, expected_version=1),
        )

        self.assertEqual(
            {item.status for item in terminals},
            {
                InvitationStatus.ACCEPTED,
                InvitationStatus.REVOKED,
                InvitationStatus.EXPIRED,
            },
        )
        for terminal in terminals:
            with self.subTest(status=terminal.status):
                self.assertEqual(terminal.aggregate_version, 2)
                terminal_evidence = InvitationBindingEvidence(
                    invitation_id=terminal.invitation_id,
                    recipient_contact_id=terminal.recipient_contact_id,
                    invitation_version=terminal.aggregate_version,
                )
                operations = (
                    lambda terminal=terminal, evidence=terminal_evidence: terminal.accept(
                        now=self.clock.now(),
                        expected_version=2,
                        evidence=evidence,
                    ),
                    lambda terminal=terminal: terminal.revoke(
                        now=self.clock.now(), expected_version=2
                    ),
                    lambda terminal=terminal: terminal.expire(
                        now=terminal.expires_at, expected_version=2
                    ),
                )
                for operation in operations:
                    self.assert_iam_error(
                        "ACCESS_INVITATION_NOT_ISSUED", operation
                    )

        self.assertEqual(issued.status, InvitationStatus.ISSUED)
        self.assertEqual(issued.aggregate_version, 1)

    def test_req_iam_001_transition_versions_are_exactly_monotonic(self):
        """Each legal transition returns a new immutable value at version +1."""

        invitation = self.organization_invitation()
        revoked = invitation.revoke(now=self.clock.now(), expected_version=1)

        self.assertIsNot(revoked, invitation)
        self.assertEqual(revoked.aggregate_version, invitation.aggregate_version + 1)
        self.assertEqual(invitation.status, InvitationStatus.ISSUED)
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            invitation.status = InvitationStatus.REVOKED

        for operation in (
            lambda: invitation.revoke(now=self.clock.now(), expected_version=9),
            lambda: invitation.expire(now=invitation.expires_at, expected_version=9),
        ):
            self.assert_iam_error("PRECONDITION_FAILED", operation)


if __name__ == "__main__":
    unittest.main()
