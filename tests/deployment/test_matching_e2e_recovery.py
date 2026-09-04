"""Private command recovery checks; the workflow itself runs against real HTTP."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import run_internal_sandbox_matching_e2e as runner


class ReviewClaimRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        os.chmod(self.root, 0o700)
        self.headers = {
            "Accept": "application/json", "Content-Type": "application/json",
            "X-Workspace-Id": "operations:test", "X-CSRF-Token": "test-original-csrf",
            "Idempotency-Key": "internal-sandbox-e2e-6cd4ece5-ce8c-459f-8b02-fcc1a2d4f603",
        }
        self.reviewer = SimpleNamespace(workspace_id="operations:test", csrf_token="test-original-csrf")

    def write(self, path, text):
        runner.base._write_new(path, text.encode(), mode=0o600)

    def pending(self, headers=None):
        self.write(self.root / "pending-review-claim.json", json.dumps({
            "method": "POST", "path": "/v1/app/matching-review/queue/claim",
            "body": {}, "headers": self.headers if headers is None else headers,
        }))

    def legacy(self, *, code="COMMAND_OUTCOME_UNKNOWN", status=503):
        role = runner.base._role_root(self.root, "operations_reviewer_01")
        self.write(role / "0057-response", json.dumps({"code": code}))
        self.write(role / "0058-response-headers", f"HTTP/1.1 {status} Outcome\r\n\r\n")
        os.chmod(role / "0057-response", 0o644)
        os.chmod(role / "0058-response-headers", 0o644)
        self.write(role / "0059-request-headers", "".join(f"{key}: {value}\n" for key, value in self.headers.items()))
        self.write(role / "0060-request-body", "{}")

    def test_pending_command_reuses_original_key_and_headers(self):
        self.pending()
        self.assertEqual(runner._review_claim_headers(self.root, self.reviewer), self.headers)

    def test_legacy_unknown_response_recovers_exact_private_command(self):
        self.legacy()
        self.assertEqual(runner._review_claim_headers(self.root, self.reviewer), self.headers)

    def test_new_session_cannot_replay_with_old_authority(self):
        self.pending()
        self.reviewer.csrf_token = "test-new-session-csrf"
        with self.assertRaisesRegex(runner.CheckError, "RESUME_COMMAND_BINDING_INVALID"):
            runner._review_claim_headers(self.root, self.reviewer)

    def test_other_workspace_or_conditional_write_cannot_be_replayed(self):
        for headers in ({**self.headers, "X-Workspace-Id": "operations:other"},
                        {**self.headers, "If-Match": '"v1"'}):
            with self.subTest(header_names=sorted(headers)):
                self.pending(headers)
                with self.assertRaisesRegex(runner.CheckError, "RESUME_COMMAND_BINDING_INVALID"):
                    runner._review_claim_headers(self.root, self.reviewer)
                (self.root / "pending-review-claim.json").unlink()

    def test_legacy_success_cannot_be_misclassified_as_unknown(self):
        self.legacy(code="CREATED", status=201)
        with self.assertRaisesRegex(runner.CheckError, "RESUME_COMMAND_OUTCOME_INVALID"):
            runner._review_claim_headers(self.root, self.reviewer)

    def created_evidence(self, *, same_demand=True):
        identifiers = [f"00000000-0000-4000-8000-{number:012d}" for number in range(1, 8)]
        demand, attempt, run, invitation, selection, review_id, selector_id = identifiers
        review_role = runner.base._role_root(self.root, "operations_reviewer_01")
        owner_role = runner.base._role_root(self.root, "demand_owner_01")
        expires = "2026-09-04T07:46:41Z"
        self.write(review_role / "0001-response", json.dumps({
            "assignment_id": review_id, "attempt_id": attempt, "match_run_id": run,
            "expires_at": expires, "status": "ACTIVE",
        }))
        self.write(review_role / "0004-response", json.dumps({
            "invitation_id": invitation, "attempt_id": attempt, "match_run_id": run,
            "status": "CREATED", "aggregate_version": 1, "snapshot_sha256": "a" * 64,
        }))
        self.write(review_role / "0008-response", json.dumps({"code": "INVITATION_ALREADY_EXISTS"}))
        self.write(owner_role / "0001-response", json.dumps({
            "demand_id": demand if same_demand else invitation, "attempt_id": attempt,
            "candidate_selector_assignment_id": selector_id, "selection_id": selection,
            "status": "ACTIVE", "selection_status": "OPEN", "expires_at": expires,
        }))
        return {"demand_id": demand}

    def test_known_create_recovery_retains_public_binding_without_old_headers(self):
        target = self.created_evidence()
        recovered = runner._known_created_invitation(self.root, target)
        self.assertEqual(recovered["demand_id"], target["demand_id"])
        self.assertEqual(recovered["first_create_status"], "CREATED")
        self.assertFalse({"headers", "csrf_token", "session_id", "idempotency_key"}.intersection(recovered))

    def test_known_create_recovery_rejects_other_demand(self):
        target = self.created_evidence(same_demand=False)
        with self.assertRaisesRegex(runner.CheckError, "CREATED_RECOVERY_BINDING_INVALID"):
            runner._known_created_invitation(self.root, target)

    def sent_evidence(self, *, changed_replay=False):
        target = self.created_evidence()
        role = self.root / "operations_reviewer_01"
        self.write(role / "0000-response", "<!DOCTYPE html><title>Sign in</title>")
        created = json.loads((role / "0004-response").read_text())
        (role / "0008-response").unlink()
        self.write(role / "0008-response", json.dumps(created))
        sent = {**created, "status": "SENT", "aggregate_version": 2}
        self.write(role / "0012-response", json.dumps(sent))
        self.write(role / "0016-response", json.dumps({**sent, "snapshot_sha256": "b" * 64} if changed_replay else sent))
        return target

    def test_sent_recovery_preserves_successful_create_and_publish_replays(self):
        target = self.sent_evidence()
        known = runner._known_sent_invitation(self.root, target)
        self.assertTrue(known["create_exact_replay_verified"])
        self.assertTrue(known["publish_exact_replay_verified"])
        self.assertEqual(known["demand_id"], target["demand_id"])
        self.assertFalse({"headers", "csrf_token", "session_id", "idempotency_key"}.intersection(known))

    def test_sent_recovery_rejects_changed_publish_replay(self):
        target = self.sent_evidence(changed_replay=True)
        with self.assertRaisesRegex(runner.CheckError, "SENT_RECOVERY_PUBLISH_NOT_CONFIRMED"):
            runner._known_sent_invitation(self.root, target)

    def test_sent_recovery_rejects_different_target(self):
        target = self.sent_evidence()
        target["demand_id"] = "00000000-0000-4000-8000-000000000009"
        with self.assertRaisesRegex(runner.CheckError, "SENT_RECOVERY_TARGET_INVALID"):
            runner._known_sent_invitation(self.root, target)

    def test_pending_choice_recovery_requires_accepted_exact_invitation(self):
        target = self.sent_evidence()
        known = runner._known_sent_invitation(self.root, target)
        creator = runner.base._role_root(self.root, "creator_01")
        self.write(creator / "0001-response", "")
        accepted = {"invitation_id": known["invitation_id"], "snapshot_sha256": known["snapshot_sha256"],
                    "aggregate_version": 3, "status": "ACCEPTED", "response_status": "ACCEPTED"}
        choice = {"selection_id": known["selection_id"], "attempt_id": known["attempt_id"],
                  "chosen_invitation_id": known["invitation_id"], "status": "PENDING_CHOICE"}
        for number in (20, 24):
            self.write(creator / f"{number:04d}-response", json.dumps(accepted))
            self.write(self.root / "demand_owner_01" / f"{number:04d}-response", json.dumps(choice))
        self.assertEqual(runner._known_pending_choice(self.root, target)["selection_id"], known["selection_id"])
        (creator / "0024-response").unlink()
        self.write(creator / "0024-response", json.dumps({**accepted, "snapshot_sha256": "b" * 64}))
        with self.assertRaisesRegex(runner.CheckError, "PENDING_CHOICE_RECOVERY_NOT_CONFIRMED"):
            runner._known_pending_choice(self.root, target)


if __name__ == "__main__":
    unittest.main()
