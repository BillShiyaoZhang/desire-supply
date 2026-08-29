"""TEST-APP-MEMBERSHIP-RESUME-001 semantic RED."""

from dataclasses import replace
import unittest

from desire_platform.identity_access.ports.safety_hold import HoldDecision
from tests.support.iam_authority_lifecycle_builders import (
    ACTOR_MEMBERSHIP_ID,
    ACTOR_ROLE_GRANT_ID,
    HOLD_POLICY_VERSION,
    NOW,
    ORGANIZATION_ID,
    TARGET_MEMBERSHIP_ID,
    TARGET_ROLE_GRANT_ID,
    ConfigurableSafetyHold,
    invoke_fixture,
    membership_admin_dto,
    membership_fixture,
)


class ResumeMembershipSemanticRedTest(unittest.TestCase):
    def test_happy_path_uses_exact_hold_and_restores_existing_roles_atomically(self) -> None:
        fixture = membership_fixture("resume")
        before = fixture.store.snapshot()
        observation = invoke_fixture(fixture)
        after = observation.after
        events = list(after["outbox_events"].values())
        checks = {
            "success": observation.error_code is None,
            "membership active": after["memberships"][TARGET_MEMBERSHIP_ID]["status"] == "ACTIVE",
            "version increment": after["memberships"][TARGET_MEMBERSHIP_ID]["aggregate_version"] == 3,
            "roles reused": before["membership_role_grants"] == after["membership_role_grants"],
            "one exact hold": len(fixture.hold.calls) == 1,
            "one receipt": len(after["command_receipts"]) == 1,
            "one audit": len(after["audit_events"]) == 1,
            "one event": len(events) == 1,
            "safe dto": getattr(observation.result, "safe_response", None) == membership_admin_dto("ACTIVE", ["DEMAND_OWNER"]),
            "event validated": len(fixture.event_validator.calls) == 1,
            "dto validated": len(fixture.response_validator.calls) == 1,
        }
        for label, condition in checks.items():
            with self.subTest(label=label):
                self.assertTrue(condition)
        if fixture.hold.calls:
            query = fixture.hold.calls[0]
            expected = {
                "actor_id": fixture.actor.actor_user_id,
                "action": "ResumeMembership",
                "target_type": "Membership",
                "target_id": TARGET_MEMBERSHIP_ID,
                "target_version": 2,
                "organization_id": ORGANIZATION_ID,
                "policy_version": HOLD_POLICY_VERSION,
            }
            self.assertEqual(query, expected)
        for event in events:
            fixture.event_validator.validate(event)

    def test_hold_block_unavailable_mismatch_and_deadline_fail_before_uow(self) -> None:
        cases = (
            ("block", ConfigurableSafetyHold(decision=HoldDecision.BLOCK), "SAFETY_HOLD_BLOCKED"),
            ("unavailable", ConfigurableSafetyHold(decision=HoldDecision.UNAVAILABLE), "SAFETY_DECISION_UNAVAILABLE"),
            ("wrong id", ConfigurableSafetyHold(overrides={"target_id": "membership_other_01"}), "SAFETY_DECISION_UNAVAILABLE"),
            ("wrong version", ConfigurableSafetyHold(overrides={"target_version": 3}), "SAFETY_DECISION_UNAVAILABLE"),
            ("wrong org", ConfigurableSafetyHold(overrides={"organization_id": "organization_other1"}), "SAFETY_DECISION_UNAVAILABLE"),
            ("wrong policy", ConfigurableSafetyHold(overrides={"policy_version": "safety-hold-v2"}), "SAFETY_DECISION_UNAVAILABLE"),
            ("expired equal", ConfigurableSafetyHold(overrides={"valid_until": NOW}), "SAFETY_DECISION_UNAVAILABLE"),
            ("future evaluation", ConfigurableSafetyHold(overrides={"evaluated_at": NOW.replace(second=1)}), "SAFETY_DECISION_UNAVAILABLE"),
        )
        for label, hold, expected in cases:
            fixture = membership_fixture("resume", hold=hold)
            observation = invoke_fixture(fixture)
            with self.subTest(case=label):
                self.assertEqual(observation.error_code, expected)
                self.assertEqual(fixture.uow_factory.begin_count, 0)
                self.assertEqual(observation.before, observation.after)

    def test_unauthorized_cross_tenant_adjacent_and_roleless_targets_are_zero_write(self) -> None:
        cases = (
            ("actor membership suspended", "RESOURCE_NOT_FOUND", "memberships", ACTOR_MEMBERSHIP_ID, {"status": "SUSPENDED"}),
            ("actor grant revoked", "RESOURCE_NOT_FOUND", "membership_role_grants", ACTOR_ROLE_GRANT_ID, {"revoked_at": NOW}),
            ("cross tenant", "RESOURCE_NOT_FOUND", "memberships", TARGET_MEMBERSHIP_ID, {"organization_id": "organization_other1"}),
            ("organization suspended", "RESOURCE_NOT_FOUND", "organizations", ORGANIZATION_ID, {"status": "SUSPENDED"}),
            ("already active", "INVALID_STATE_TRANSITION", "memberships", TARGET_MEMBERSHIP_ID, {"status": "ACTIVE"}),
            ("revoked", "INVALID_STATE_TRANSITION", "memberships", TARGET_MEMBERSHIP_ID, {"status": "REVOKED"}),
            ("all roles revoked", "INVALID_STATE_TRANSITION", "membership_role_grants", TARGET_ROLE_GRANT_ID, {"revoked_at": NOW}),
        )
        for label, expected, table, key, changes in cases:
            fixture = membership_fixture("resume")
            fixture.store.replace_fact(table, key, **changes)
            observation = invoke_fixture(fixture)
            with self.subTest(case=label):
                self.assertEqual(observation.error_code, expected)
                self.assertEqual(observation.before, observation.after)

    def test_locked_version_drift_discards_allow_and_reevaluates_outside_uow(self) -> None:
        hold = ConfigurableSafetyHold()
        fixture = membership_fixture("resume", hold=hold)

        def drift(call_count, _query):
            if call_count == 1:
                fixture.store.replace_fact(
                    "memberships",
                    TARGET_MEMBERSHIP_ID,
                    aggregate_version=3,
                )

        hold.after_evaluate = drift
        observation = invoke_fixture(fixture)
        checks = {
            "old allow not used": observation.error_code == "PRECONDITION_FAILED",
            "reevaluated": len(hold.calls) == 2,
            "no receipt": observation.after["command_receipts"] == {},
            "no audit": observation.after["audit_events"] == {},
            "no outbox": observation.after["outbox_events"] == {},
            "external drift remains": observation.after["memberships"][TARGET_MEMBERSHIP_ID]["aggregate_version"] == 3,
        }
        for label, condition in checks.items():
            with self.subTest(label=label):
                self.assertTrue(condition)

    def test_stale_etag_replay_faults_and_commit_unknown_are_closed(self) -> None:
        fixture = membership_fixture("resume")
        fixture.command = replace(fixture.command, expected_version=99)
        stale = invoke_fixture(fixture)
        self.assertEqual(stale.error_code, "PRECONDITION_FAILED")
        self.assertEqual(stale.before, stale.after)

        fixture = membership_fixture("resume")
        first = invoke_fixture(fixture)
        committed = fixture.store.snapshot()
        replay = invoke_fixture(fixture)
        with self.subTest(phase="first"):
            self.assertIsNone(first.error_code)
        with self.subTest(phase="replay"):
            self.assertIsNone(replay.error_code)
            self.assertTrue(getattr(replay.result, "replayed", False))
            self.assertEqual(replay.after, committed)
            self.assertEqual(len(fixture.hold.calls), 1)

        for checkpoint in (
            "membership.receipt_in_progress",
            "membership.aggregate",
            "membership.audit",
            "membership.outbox",
            "membership.receipt_completed",
        ):
            fixture = membership_fixture("resume", fail_on_checkpoint=checkpoint)
            failed = invoke_fixture(fixture)
            with self.subTest(checkpoint=checkpoint):
                self.assertEqual(failed.error_code, "SERVICE_UNAVAILABLE")
                self.assertEqual(failed.before, failed.after)

        fixture = membership_fixture("resume", commit_mode="unknown_landed")
        unknown = invoke_fixture(fixture)
        self.assertEqual(unknown.error_code, "COMMAND_OUTCOME_UNKNOWN")
        self.assertEqual(
            unknown.after["memberships"][TARGET_MEMBERSHIP_ID]["status"],
            "ACTIVE",
        )


if __name__ == "__main__":
    unittest.main()
