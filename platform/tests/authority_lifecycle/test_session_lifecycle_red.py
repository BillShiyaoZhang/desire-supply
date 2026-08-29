"""TEST-APP-SESSION-LIFECYCLE-001 and TEST-AUTH-SESSION-REPLAY-001 RED."""

import unittest

from tests.support.iam_authority_lifecycle_builders import (
    ACTOR_FAMILY_ID,
    ACTOR_SESSION_ID,
    TARGET_FAMILY_ID,
    TARGET_SESSION_ID,
    invoke_fixture,
    replayed_family_fixture,
    session_revoke_fixture,
)


class RevokeSessionSemanticRedTest(unittest.TestCase):
    def test_revoke_other_owned_session_is_immediate_and_does_not_logout_current(self) -> None:
        fixture = session_revoke_fixture()
        observation = invoke_fixture(fixture)
        after = observation.after
        events = list(after["outbox_events"].values())
        checks = {
            "success": observation.error_code is None,
            "http 204": getattr(observation.result, "http_status", None) == 204,
            "empty response": getattr(observation.result, "safe_response", "missing") is None,
            "target revoked": after["sessions"][TARGET_SESSION_ID]["status"] == "REVOKED",
            "current active": after["sessions"][ACTOR_SESSION_ID]["status"] == "ACTIVE",
            "target family active": after["session_families"][TARGET_FAMILY_ID]["status"] == "ACTIVE",
            "no cookie clear": not getattr(observation.result, "clear_current_session_cookie", True),
            "one receipt": len(after["command_receipts"]) == 1,
            "one audit": len(after["audit_events"]) == 1,
            "one event": len(events) == 1,
            "hold untouched": fixture.hold.calls == [],
            "event validated": len(fixture.event_validator.calls) == 1,
        }
        for label, condition in checks.items():
            with self.subTest(label=label):
                self.assertTrue(condition)
        for event in events:
            fixture.event_validator.validate(event)

    def test_revoke_current_session_marks_cookie_for_clear_without_family_revocation(self) -> None:
        fixture = session_revoke_fixture(current=True)
        observation = invoke_fixture(fixture)
        checks = {
            "success": observation.error_code is None,
            "current revoked": observation.after["sessions"][ACTOR_SESSION_ID]["status"] == "REVOKED",
            "current family remains active": observation.after["session_families"][ACTOR_FAMILY_ID]["status"] == "ACTIVE",
            "clear cookie": getattr(observation.result, "clear_current_session_cookie", False),
            "other session remains active": observation.after["sessions"][TARGET_SESSION_ID]["status"] == "ACTIVE",
        }
        for label, condition in checks.items():
            with self.subTest(label=label):
                self.assertTrue(condition)

    def test_cross_user_and_unknown_session_are_non_disclosing(self) -> None:
        fixture = session_revoke_fixture()
        fixture.store.replace_fact("sessions", TARGET_SESSION_ID, user_id="user_other_000001")
        other = invoke_fixture(fixture)
        with self.subTest(case="other user"):
            self.assertEqual(other.error_code, "RESOURCE_NOT_FOUND")
            self.assertEqual(other.before, other.after)

        fixture = session_revoke_fixture()
        del fixture.store._tables["sessions"][TARGET_SESSION_ID]
        missing = invoke_fixture(fixture)
        with self.subTest(case="missing"):
            self.assertEqual(missing.error_code, "RESOURCE_NOT_FOUND")
            self.assertEqual(missing.before, missing.after)

    def test_already_terminal_new_key_is_success_without_duplicate_domain_event(self) -> None:
        for terminal in ("REVOKED", "EXPIRED"):
            fixture = session_revoke_fixture()
            fixture.store.replace_fact("sessions", TARGET_SESSION_ID, status=terminal)
            observation = invoke_fixture(fixture)
            with self.subTest(status=terminal, check="success"):
                self.assertIsNone(observation.error_code)
            with self.subTest(status=terminal, check="204"):
                self.assertEqual(getattr(observation.result, "http_status", None), 204)
            with self.subTest(status=terminal, check="no duplicate event"):
                self.assertEqual(len(observation.after["outbox_events"]), 0)
            with self.subTest(status=terminal, check="receipt plus audit"):
                self.assertEqual(len(observation.after["command_receipts"]), 1)
                self.assertEqual(len(observation.after["audit_events"]), 1)

    def test_same_key_replay_is_zero_write_and_command_has_no_if_match(self) -> None:
        fixture = session_revoke_fixture()
        self.assertFalse(hasattr(fixture.command, "expected_version"))
        first = invoke_fixture(fixture)
        committed = fixture.store.snapshot()
        replay = invoke_fixture(fixture)
        with self.subTest(phase="first"):
            self.assertIsNone(first.error_code)
        with self.subTest(phase="replay"):
            self.assertIsNone(replay.error_code)
            self.assertTrue(getattr(replay.result, "replayed", False))
            self.assertEqual(replay.after, committed)

    def test_write_faults_roll_back_exact_session_receipt_audit_and_event(self) -> None:
        checkpoints = (
            "session.receipt_in_progress",
            "session.aggregate",
            "session.audit",
            "session.outbox",
            "session.receipt_completed",
        )
        for checkpoint in checkpoints:
            fixture = session_revoke_fixture(fail_on_checkpoint=checkpoint)
            observation = invoke_fixture(fixture)
            with self.subTest(checkpoint=checkpoint):
                self.assertEqual(observation.error_code, "SERVICE_UNAVAILABLE")
                self.assertEqual(observation.before, observation.after)

    def test_landed_commit_unknown_keeps_monotonic_terminal_fact(self) -> None:
        fixture = session_revoke_fixture(commit_mode="unknown_landed")
        observation = invoke_fixture(fixture)
        with self.subTest(check="unknown result"):
            self.assertEqual(observation.error_code, "COMMAND_OUTCOME_UNKNOWN")
        with self.subTest(check="terminal persisted"):
            self.assertEqual(
                observation.after["sessions"][TARGET_SESSION_ID]["status"],
                "REVOKED",
            )


class ReplayedSessionFamilySemanticRedTest(unittest.TestCase):
    def test_verified_old_handle_replay_revokes_exact_family_successor_only(self) -> None:
        fixture = replayed_family_fixture()
        observation = invoke_fixture(fixture)
        after = observation.after
        events = list(after["outbox_events"].values())
        checks = {
            "success": observation.error_code is None,
            "family revoked": after["session_families"][TARGET_FAMILY_ID]["status"] == "REVOKED",
            "successor revoked": after["sessions"][TARGET_SESSION_ID]["status"] == "REVOKED",
            "other family active": after["session_families"][ACTOR_FAMILY_ID]["status"] == "ACTIVE",
            "current browser active": after["sessions"][ACTOR_SESSION_ID]["status"] == "ACTIVE",
            "one successor event": len(events) == 1,
            "security audit": len(after["audit_events"]) == 1,
            "no public receipt": len(after["command_receipts"]) == 0,
            "hold untouched": fixture.hold.calls == [],
            "event validated": len(fixture.event_validator.calls) == 1,
        }
        for label, condition in checks.items():
            with self.subTest(label=label):
                self.assertTrue(condition)
        for event in events:
            fixture.event_validator.validate(event)

    def test_same_security_event_or_terminal_family_never_emits_twice(self) -> None:
        fixture = replayed_family_fixture()
        first = invoke_fixture(fixture)
        committed = fixture.store.snapshot()
        replay = invoke_fixture(fixture)
        with self.subTest(phase="first"):
            self.assertIsNone(first.error_code)
        with self.subTest(phase="repeat"):
            self.assertIsNone(replay.error_code)
            self.assertEqual(replay.after, committed)
            self.assertEqual(len(replay.after["outbox_events"]), 1)

    def test_family_replay_fault_rolls_back_family_and_successor_together(self) -> None:
        checkpoints = (
            "replay.security_event",
            "replay.family",
            "replay.session.0",
            "replay.audit",
            "replay.outbox.0",
        )
        for checkpoint in checkpoints:
            fixture = replayed_family_fixture(fail_on_checkpoint=checkpoint)
            observation = invoke_fixture(fixture)
            with self.subTest(checkpoint=checkpoint):
                self.assertEqual(observation.error_code, "SERVICE_UNAVAILABLE")
                self.assertEqual(observation.before, observation.after)


if __name__ == "__main__":
    unittest.main()
