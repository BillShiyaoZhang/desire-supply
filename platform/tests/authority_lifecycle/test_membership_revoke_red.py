"""TEST-APP-MEMBERSHIP-REVOKE-001 semantic RED."""

from dataclasses import replace
import unittest

from desire_platform.identity_access.ports.safety_hold import HoldDecision
from tests.support.iam_authority_lifecycle_builders import (
    ACTOR_MEMBERSHIP_ID,
    ACTOR_ROLE_GRANT_ID,
    NOW,
    SECOND_ADMIN_ROLE_GRANT_ID,
    TARGET_MEMBERSHIP_ID,
    TARGET_ROLE_GRANT_ID,
    ConfigurableSafetyHold,
    invoke_fixture,
    membership_admin_dto,
    membership_fixture,
)


class RevokeMembershipSemanticRedTest(unittest.TestCase):
    def test_happy_path_revokes_membership_and_every_role_in_one_transaction(self) -> None:
        hold = ConfigurableSafetyHold(decision=HoldDecision.BLOCK)
        fixture = membership_fixture("revoke", hold=hold)
        before = fixture.store.snapshot()
        observation = invoke_fixture(fixture)
        after = observation.after
        events = list(after["outbox_events"].values())
        target_grant = after["membership_role_grants"][TARGET_ROLE_GRANT_ID]
        checks = {
            "success": observation.error_code is None,
            "membership revoked": after["memberships"][TARGET_MEMBERSHIP_ID]["status"] == "REVOKED",
            "membership version": after["memberships"][TARGET_MEMBERSHIP_ID]["aggregate_version"] == 3,
            "role revoked": target_grant["revoked_at"] is not None,
            "role version": target_grant["aggregate_version"] == 2,
            "sessions unchanged": before["sessions"] == after["sessions"],
            "one receipt": len(after["command_receipts"]) == 1,
            "one audit": len(after["audit_events"]) == 1,
            "membership plus role events": len(events) == 2,
            "safe dto retains explanatory label": getattr(observation.result, "safe_response", None) == membership_admin_dto("REVOKED", ["DEMAND_OWNER"]),
            "blocked hold ignored without call": hold.calls == [],
            "both events validated": len(fixture.event_validator.calls) == 2,
            "dto validated": len(fixture.response_validator.calls) == 1,
        }
        for label, condition in checks.items():
            with self.subTest(label=label):
                self.assertTrue(condition)
        for event in events:
            fixture.event_validator.validate(event)

    def test_unauthorized_cross_tenant_and_terminal_target_are_zero_write(self) -> None:
        cases = (
            ("actor suspended", "RESOURCE_NOT_FOUND", "memberships", ACTOR_MEMBERSHIP_ID, {"status": "SUSPENDED"}),
            ("actor role revoked", "RESOURCE_NOT_FOUND", "membership_role_grants", ACTOR_ROLE_GRANT_ID, {"revoked_at": NOW}),
            ("cross tenant", "RESOURCE_NOT_FOUND", "memberships", TARGET_MEMBERSHIP_ID, {"organization_id": "organization_other1"}),
            ("terminal", "INVALID_STATE_TRANSITION", "memberships", TARGET_MEMBERSHIP_ID, {"status": "REVOKED"}),
        )
        for label, expected, table, key, changes in cases:
            fixture = membership_fixture("revoke")
            fixture.store.replace_fact(table, key, **changes)
            observation = invoke_fixture(fixture)
            with self.subTest(case=label):
                self.assertEqual(observation.error_code, expected)
                self.assertEqual(observation.before, observation.after)
                self.assertEqual(fixture.hold.calls, [])

    def test_last_active_admin_guard_only_counts_active_target_membership(self) -> None:
        fixture = membership_fixture("revoke")
        fixture.command = replace(
            fixture.command,
            membership_id=ACTOR_MEMBERSHIP_ID,
            expected_version=2,
        )
        fixture.store.replace_fact(
            "membership_role_grants",
            SECOND_ADMIN_ROLE_GRANT_ID,
            revoked_at=NOW,
        )
        blocked = invoke_fixture(fixture)
        with self.subTest(case="self is last active admin"):
            self.assertEqual(blocked.error_code, "LAST_ACTIVE_ORG_ADMIN")
            self.assertEqual(blocked.before, blocked.after)

        fixture = membership_fixture("revoke")
        fixture.store.replace_fact("memberships", TARGET_MEMBERSHIP_ID, status="SUSPENDED")
        fixture.store.replace_fact(
            "membership_role_grants",
            TARGET_ROLE_GRANT_ID,
            role_code="ORG_ADMIN",
        )
        fixture.store.replace_fact(
            "membership_role_grants",
            SECOND_ADMIN_ROLE_GRANT_ID,
            revoked_at=NOW,
        )
        allowed = invoke_fixture(fixture)
        with self.subTest(case="suspended admin is not active admin"):
            self.assertIsNone(allowed.error_code)
            self.assertEqual(
                allowed.after["memberships"][TARGET_MEMBERSHIP_ID]["status"],
                "REVOKED",
            )

    def test_stale_etag_replay_faults_and_commit_unknown_are_closed(self) -> None:
        fixture = membership_fixture("revoke")
        fixture.command = replace(fixture.command, expected_version=99)
        stale = invoke_fixture(fixture)
        self.assertEqual(stale.error_code, "PRECONDITION_FAILED")
        self.assertEqual(stale.before, stale.after)

        fixture = membership_fixture("revoke")
        first = invoke_fixture(fixture)
        committed = fixture.store.snapshot()
        replay = invoke_fixture(fixture)
        with self.subTest(phase="first"):
            self.assertIsNone(first.error_code)
        with self.subTest(phase="replay"):
            self.assertIsNone(replay.error_code)
            self.assertTrue(getattr(replay.result, "replayed", False))
            self.assertEqual(replay.after, committed)

        for checkpoint in (
            "membership.receipt_in_progress",
            "membership.role.0",
            "membership.aggregate",
            "membership.audit",
            "membership.outbox.0",
            "membership.outbox.1",
            "membership.receipt_completed",
        ):
            fixture = membership_fixture("revoke", fail_on_checkpoint=checkpoint)
            failed = invoke_fixture(fixture)
            with self.subTest(checkpoint=checkpoint):
                self.assertEqual(failed.error_code, "SERVICE_UNAVAILABLE")
                self.assertEqual(failed.before, failed.after)

        fixture = membership_fixture("revoke", commit_mode="unknown_landed")
        unknown = invoke_fixture(fixture)
        self.assertEqual(unknown.error_code, "COMMAND_OUTCOME_UNKNOWN")
        self.assertEqual(
            unknown.after["memberships"][TARGET_MEMBERSHIP_ID]["status"],
            "REVOKED",
        )


if __name__ == "__main__":
    unittest.main()
