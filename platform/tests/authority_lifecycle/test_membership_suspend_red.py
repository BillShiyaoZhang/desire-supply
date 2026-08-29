"""TEST-APP-MEMBERSHIP-SUSPEND-001 semantic RED."""

from dataclasses import replace
import unittest

from tests.support.iam_authority_lifecycle_builders import (
    ACTOR_MEMBERSHIP_ID,
    ACTOR_ROLE_GRANT_ID,
    ORGANIZATION_ID,
    SECOND_ADMIN_ROLE_GRANT_ID,
    TARGET_MEMBERSHIP_ID,
    invoke_fixture,
    membership_admin_dto,
    membership_fixture,
)


class SuspendMembershipSemanticRedTest(unittest.TestCase):
    def test_happy_path_suspends_membership_but_preserves_roles_and_sessions(self) -> None:
        fixture = membership_fixture("suspend")
        before = fixture.store.snapshot()
        observation = invoke_fixture(fixture)
        after = observation.after
        events = list(after["outbox_events"].values())
        checks = {
            "success": observation.error_code is None,
            "membership suspended": after["memberships"][TARGET_MEMBERSHIP_ID]["status"] == "SUSPENDED",
            "version increment": after["memberships"][TARGET_MEMBERSHIP_ID]["aggregate_version"] == 3,
            "roles unchanged": before["membership_role_grants"] == after["membership_role_grants"],
            "sessions unchanged": before["sessions"] == after["sessions"],
            "one receipt": len(after["command_receipts"]) == 1,
            "one audit": len(after["audit_events"]) == 1,
            "one event": len(events) == 1,
            "safe dto": getattr(observation.result, "safe_response", None) == membership_admin_dto("SUSPENDED", ["DEMAND_OWNER"]),
            "hold untouched": fixture.hold.calls == [],
            "event validated": len(fixture.event_validator.calls) == 1,
            "dto validated": len(fixture.response_validator.calls) == 1,
        }
        for label, condition in checks.items():
            with self.subTest(label=label):
                self.assertTrue(condition)
        for event in events:
            fixture.event_validator.validate(event)

    def test_unauthorized_cross_tenant_and_adjacent_states_are_zero_write(self) -> None:
        cases = (
            ("actor grant revoked", "RESOURCE_NOT_FOUND", "membership_role_grants", ACTOR_ROLE_GRANT_ID, {"revoked_at": fixture_time()}),
            ("actor membership suspended", "RESOURCE_NOT_FOUND", "memberships", ACTOR_MEMBERSHIP_ID, {"status": "SUSPENDED"}),
            ("cross tenant target", "RESOURCE_NOT_FOUND", "memberships", TARGET_MEMBERSHIP_ID, {"organization_id": "organization_other1"}),
            ("already suspended", "INVALID_STATE_TRANSITION", "memberships", TARGET_MEMBERSHIP_ID, {"status": "SUSPENDED"}),
            ("revoked terminal", "INVALID_STATE_TRANSITION", "memberships", TARGET_MEMBERSHIP_ID, {"status": "REVOKED"}),
        )
        for label, expected, table, key, changes in cases:
            fixture = membership_fixture("suspend")
            fixture.store.replace_fact(table, key, **changes)
            observation = invoke_fixture(fixture)
            with self.subTest(case=label):
                self.assertEqual(observation.error_code, expected)
                self.assertEqual(observation.before, observation.after)
                self.assertEqual(fixture.hold.calls, [])

    def test_last_active_admin_is_blocked_but_self_suspend_with_successor_is_allowed(self) -> None:
        fixture = membership_fixture("suspend")
        fixture.command = replace(
            fixture.command,
            membership_id=ACTOR_MEMBERSHIP_ID,
            expected_version=2,
        )
        fixture.store.replace_fact(
            "membership_role_grants",
            SECOND_ADMIN_ROLE_GRANT_ID,
            revoked_at=fixture_time(),
        )
        blocked = invoke_fixture(fixture)
        with self.subTest(case="last active admin"):
            self.assertEqual(blocked.error_code, "LAST_ACTIVE_ORG_ADMIN")
            self.assertEqual(blocked.before, blocked.after)

        fixture = membership_fixture("suspend")
        fixture.command = replace(
            fixture.command,
            membership_id=ACTOR_MEMBERSHIP_ID,
            expected_version=2,
        )
        allowed = invoke_fixture(fixture)
        with self.subTest(case="second active admin remains"):
            self.assertIsNone(allowed.error_code)
            self.assertEqual(
                allowed.after["memberships"][ACTOR_MEMBERSHIP_ID]["status"],
                "SUSPENDED",
            )

    def test_stale_etag_replay_and_fault_rollback_are_stable(self) -> None:
        fixture = membership_fixture("suspend")
        fixture.command = replace(fixture.command, expected_version=99)
        stale = invoke_fixture(fixture)
        self.assertEqual(stale.error_code, "PRECONDITION_FAILED")
        self.assertEqual(stale.before, stale.after)

        fixture = membership_fixture("suspend")
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
            "membership.aggregate",
            "membership.audit",
            "membership.outbox",
            "membership.receipt_completed",
        ):
            fixture = membership_fixture("suspend", fail_on_checkpoint=checkpoint)
            failed = invoke_fixture(fixture)
            with self.subTest(checkpoint=checkpoint):
                self.assertEqual(failed.error_code, "SERVICE_UNAVAILABLE")
                self.assertEqual(failed.before, failed.after)


def fixture_time():
    from tests.support.iam_authority_lifecycle_builders import NOW

    return NOW


if __name__ == "__main__":
    unittest.main()
