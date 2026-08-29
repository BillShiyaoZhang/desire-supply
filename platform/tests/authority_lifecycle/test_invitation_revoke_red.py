"""TEST-APP-INVITATION-REVOKE-001 semantic RED."""

from dataclasses import replace
from datetime import timedelta
import unittest

from desire_platform.identity_access.domain.authority_lifecycle import LifecycleReason
from tests.support.iam_authority_lifecycle_builders import (
    ACTOR_MEMBERSHIP_ID,
    ACTOR_ROLE_GRANT_ID,
    ACTOR_SESSION_ID,
    INVITATION_ID,
    NOW,
    invitation_admin_dto,
    invitation_revoke_fixture,
    invoke_fixture,
)


class RevokeAccessInvitationSemanticRedTest(unittest.TestCase):
    def test_current_nonissuer_admin_atomically_revokes_and_emits_closed_event(self) -> None:
        fixture = invitation_revoke_fixture()
        observation = invoke_fixture(fixture)
        snapshot = observation.after
        events = list(snapshot["outbox_events"].values())

        checks = {
            "success": observation.error_code is None,
            "no escaped exception": observation.escaped_exception is None,
            "terminal status": snapshot["invitations"][INVITATION_ID]["status"] == "REVOKED",
            "aggregate version": snapshot["invitations"][INVITATION_ID]["aggregate_version"] == 2,
            "one receipt": len(snapshot["command_receipts"]) == 1,
            "one audit": len(snapshot["audit_events"]) == 1,
            "one outbox": len(events) == 1,
            "safe dto": getattr(observation.result, "safe_response", None) == invitation_admin_dto(),
            "hold not called": fixture.hold.calls == [],
            "event validator called": len(fixture.event_validator.calls) == 1,
            "dto validator called": len(fixture.response_validator.calls) == 1,
        }
        for label, condition in checks.items():
            with self.subTest(label=label):
                self.assertTrue(condition)
        for event in events:
            fixture.event_validator.validate(event)

    def test_unauthorized_cross_tenant_and_non_mfa_attempts_are_zero_write(self) -> None:
        cases = (
            ("membership suspended", "RESOURCE_NOT_FOUND", "memberships", ACTOR_MEMBERSHIP_ID, {"status": "SUSPENDED"}),
            ("admin grant revoked", "RESOURCE_NOT_FOUND", "membership_role_grants", ACTOR_ROLE_GRANT_ID, {"revoked_at": NOW}),
            ("password only", "MFA_STEP_UP_REQUIRED", "sessions", ACTOR_SESSION_ID, {"amr_codes": ("pwd",), "acr_code": "urn:synthetic:acr:password"}),
            ("stale mfa", "MFA_STEP_UP_REQUIRED", "sessions", ACTOR_SESSION_ID, {"auth_time": NOW - timedelta(minutes=10)}),
            ("other organization", "RESOURCE_NOT_FOUND", "invitations", INVITATION_ID, {"organization_id": "organization_other1"}),
            ("creator invitation", "RESOURCE_NOT_FOUND", "invitations", INVITATION_ID, {"purpose": "CREATOR_ENROLLMENT", "organization_id": None, "target_scope": "USER", "target_role": "CREATOR"}),
        )
        for label, expected, table, key, changes in cases:
            fixture = invitation_revoke_fixture()
            fixture.store.replace_fact(table, key, **changes)
            observation = invoke_fixture(fixture)
            with self.subTest(case=label):
                self.assertEqual(observation.error_code, expected)
                self.assertEqual(observation.before, observation.after)
                self.assertEqual(fixture.hold.calls, [])

    def test_adjacent_state_and_stale_version_are_distinct_after_relationship(self) -> None:
        for status in ("ACCEPTED", "REVOKED", "EXPIRED"):
            fixture = invitation_revoke_fixture()
            fixture.store.replace_fact("invitations", INVITATION_ID, status=status)
            observation = invoke_fixture(fixture)
            with self.subTest(status=status):
                self.assertEqual(observation.error_code, "INVALID_STATE_TRANSITION")
                self.assertEqual(observation.before, observation.after)

        fixture = invitation_revoke_fixture()
        fixture.command = replace(fixture.command, expected_version=9)
        observation = invoke_fixture(fixture)
        self.assertEqual(observation.error_code, "PRECONDITION_FAILED")
        self.assertEqual(observation.before, observation.after)

    def test_same_receipt_replays_once_and_changed_payload_conflicts(self) -> None:
        fixture = invitation_revoke_fixture()
        first = invoke_fixture(fixture)
        first_snapshot = fixture.store.snapshot()
        replay = invoke_fixture(fixture)
        fixture.command = replace(
            fixture.command,
            reason=LifecycleReason("DIFFERENT_REASON", "another private note"),
        )
        conflict = invoke_fixture(fixture)

        with self.subTest(phase="first"):
            self.assertIsNone(first.error_code)
        with self.subTest(phase="replay"):
            self.assertIsNone(replay.error_code)
            self.assertTrue(getattr(replay.result, "replayed", False))
            self.assertEqual(replay.after, first_snapshot)
        with self.subTest(phase="changed payload"):
            self.assertEqual(conflict.error_code, "IDEMPOTENCY_KEY_REUSED")
            self.assertEqual(conflict.after, first_snapshot)

    def test_every_write_fault_rolls_back_all_invitation_facts(self) -> None:
        checkpoints = (
            "invitation.receipt_in_progress",
            "invitation.aggregate",
            "invitation.audit",
            "invitation.outbox",
            "invitation.receipt_completed",
        )
        for checkpoint in checkpoints:
            fixture = invitation_revoke_fixture(fail_on_checkpoint=checkpoint)
            observation = invoke_fixture(fixture)
            with self.subTest(checkpoint=checkpoint):
                self.assertEqual(observation.error_code, "SERVICE_UNAVAILABLE")
                self.assertEqual(observation.before, observation.after)

    def test_commit_unknown_never_guesses_rollback(self) -> None:
        fixture = invitation_revoke_fixture(commit_mode="unknown_landed")
        observation = invoke_fixture(fixture)
        with self.subTest(check="stable outcome"):
            self.assertEqual(observation.error_code, "COMMAND_OUTCOME_UNKNOWN")
        with self.subTest(check="landed terminal fact"):
            self.assertEqual(
                observation.after["invitations"][INVITATION_ID]["status"],
                "REVOKED",
            )
        with self.subTest(check="landed completed receipt"):
            self.assertEqual(len(observation.after["command_receipts"]), 1)


if __name__ == "__main__":
    unittest.main()
