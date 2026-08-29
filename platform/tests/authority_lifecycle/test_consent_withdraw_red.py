"""TEST-APP-CONSENT-WITHDRAW-001 semantic RED."""

from dataclasses import replace
import hashlib
import hmac
import json
import unittest

from tests.support.iam_authority_lifecycle_builders import (
    ACTOR_USER_ID,
    CONSENT_GRANT_ID,
    REASON_NOTE_SENTINEL,
    consent_grant_dto,
    consent_withdraw_fixture,
    invoke_fixture,
)


class WithdrawConsentGrantSemanticRedTest(unittest.TestCase):
    def test_owner_withdrawal_is_append_only_atomic_and_purpose_scoped(self) -> None:
        fixture = consent_withdraw_fixture()
        before = fixture.store.snapshot()
        observation = invoke_fixture(fixture)
        after = observation.after
        grant = after["consent_grants"][CONSENT_GRANT_ID]
        events = list(after["outbox_events"].values())

        checks = {
            "success": observation.error_code is None,
            "withdrawn status": grant["status"] == "WITHDRAWN",
            "version increment": grant["aggregate_version"] == 2,
            "one append-only withdrawal": len(after["consent_withdrawals"]) == 1,
            "grant retained": CONSENT_GRANT_ID in after["consent_grants"],
            "one receipt": len(after["command_receipts"]) == 1,
            "one audit": len(after["audit_events"]) == 1,
            "one event": len(events) == 1,
            "safe dto": getattr(observation.result, "safe_response", None) == consent_grant_dto(),
            "other facts retained": set(before["memberships"]) == set(after["memberships"]),
            "sessions retained": before["sessions"] == after["sessions"],
            "hold not called": fixture.hold.calls == [],
            "event validated": len(fixture.event_validator.calls) == 1,
            "dto validated": len(fixture.response_validator.calls) == 1,
        }
        for label, condition in checks.items():
            with self.subTest(label=label):
                self.assertTrue(condition)
        for event in events:
            fixture.event_validator.validate(event)

    def test_other_user_and_missing_grant_are_non_disclosing_and_zero_write(self) -> None:
        fixture = consent_withdraw_fixture()
        fixture.store.replace_fact(
            "consent_grants",
            CONSENT_GRANT_ID,
            user_id="user_other_000001",
        )
        other = invoke_fixture(fixture)
        with self.subTest(case="other user"):
            self.assertEqual(other.error_code, "RESOURCE_NOT_FOUND")
            self.assertEqual(other.before, other.after)

        fixture = consent_withdraw_fixture()
        del fixture.store._tables["consent_grants"][CONSENT_GRANT_ID]
        missing = invoke_fixture(fixture)
        with self.subTest(case="missing"):
            self.assertEqual(missing.error_code, "RESOURCE_NOT_FOUND")
            self.assertEqual(missing.before, missing.after)

    def test_withdrawn_and_expired_are_adjacent_states_but_stale_etag_is_412(self) -> None:
        for status in ("WITHDRAWN", "EXPIRED"):
            fixture = consent_withdraw_fixture()
            fixture.store.replace_fact("consent_grants", CONSENT_GRANT_ID, status=status)
            observation = invoke_fixture(fixture)
            with self.subTest(status=status):
                self.assertEqual(observation.error_code, "INVALID_STATE_TRANSITION")
                self.assertEqual(observation.before, observation.after)

        fixture = consent_withdraw_fixture()
        fixture.command = replace(fixture.command, expected_version=8)
        stale = invoke_fixture(fixture)
        self.assertEqual(stale.error_code, "PRECONDITION_FAILED")
        self.assertEqual(stale.before, stale.after)

    def test_replay_is_zero_write_and_never_reconsults_hold(self) -> None:
        fixture = consent_withdraw_fixture()
        first = invoke_fixture(fixture)
        committed = fixture.store.snapshot()
        replay = invoke_fixture(fixture)
        checks = {
            "first success": first.error_code is None,
            "replay success": replay.error_code is None,
            "replayed flag": getattr(replay.result, "replayed", False),
            "zero new writes": replay.after == committed,
            "hold untouched": fixture.hold.calls == [],
        }
        for label, condition in checks.items():
            with self.subTest(label=label):
                self.assertTrue(condition)

    def test_receipt_payload_binds_the_published_http_path(self) -> None:
        fixture = consent_withdraw_fixture()
        observation = invoke_fixture(fixture)
        self.assertIsNone(observation.error_code)
        receipt = next(iter(observation.after["command_receipts"].values()))
        note_digest = hmac.new(
            b"p" * 32,
            b"iam-lifecycle-reason-note-v1\x00" + REASON_NOTE_SENTINEL.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        projection = {
            "body": {
                "reason": {
                    "reason_code": "USER_WITHDREW_CONSENT",
                    "reason_note_digest": note_digest,
                }
            },
            "canonicalization_version": "restricted-canonical-json-v1",
            "command_name": "WithdrawConsentGrant",
            "command_version": 1,
            "http_method": "POST",
            "if_match_version": 1,
            "path": f"/v1/me/consents/{CONSENT_GRANT_ID}/withdraw",
            "target_id": CONSENT_GRANT_ID,
            "target_kind": "ConsentGrant",
        }
        canonical = json.dumps(
            projection,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        expected = hmac.new(b"p" * 32, canonical, hashlib.sha256).hexdigest()
        self.assertEqual(receipt["payload_hash"], expected)

    def test_each_fault_checkpoint_rolls_back_grant_withdrawal_audit_and_event(self) -> None:
        checkpoints = (
            "consent.receipt_in_progress",
            "consent.withdrawal",
            "consent.aggregate",
            "consent.audit",
            "consent.outbox",
            "consent.receipt_completed",
        )
        for checkpoint in checkpoints:
            fixture = consent_withdraw_fixture(fail_on_checkpoint=checkpoint)
            observation = invoke_fixture(fixture)
            with self.subTest(checkpoint=checkpoint):
                self.assertEqual(observation.error_code, "SERVICE_UNAVAILABLE")
                self.assertEqual(observation.before, observation.after)

    def test_commit_unknown_is_recovered_only_through_same_receipt(self) -> None:
        fixture = consent_withdraw_fixture(commit_mode="unknown_landed")
        unknown = invoke_fixture(fixture)
        with self.subTest(check="unknown"):
            self.assertEqual(unknown.error_code, "COMMAND_OUTCOME_UNKNOWN")
        with self.subTest(check="landed"):
            self.assertEqual(
                unknown.after["consent_grants"][CONSENT_GRANT_ID]["status"],
                "WITHDRAWN",
            )
            self.assertEqual(len(unknown.after["consent_withdrawals"]), 1)


if __name__ == "__main__":
    unittest.main()
