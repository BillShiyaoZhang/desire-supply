"""Semantic RED for immutable Matching, Invitation and Selection behavior."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import timedelta
from decimal import Decimal
import json
import unittest

from desire_platform.matching.domain import (
    CandidateSelectorAssignment,
    CandidateSelectorAssignmentStatus,
    CandidateSelectorRoleCode,
    CandidateEligibility,
    Invitation,
    InvitationResponseKind,
    InvitationStatus,
    InvitationWithdrawal,
    MATCHING_DOMAIN_BEHAVIOR_NOT_AVAILABLE,
    MatchCandidate,
    MatchRunStatus,
    MatchingAttempt,
    MatchingAttemptStatus,
    MatchingDomainBehaviorNotAvailable,
    SelectionStatus,
    canonical_candidate_result_bytes,
    candidate_result_sha256,
    deterministic_rank_and_hash,
    invitation_is_expired,
    selection_invitation_set_sha256,
    validate_match_candidate,
    validate_candidate_selector_assignment,
)
from tests.support.matching_builders import (
    NOW,
    SHA,
    attempt,
    candidate,
    invitation,
    run,
    selection,
)


class MatchingDomainSemanticRedTests(unittest.TestCase):
    def _semantic(self, label: str, callback):
        try:
            return callback()
        except MatchingDomainBehaviorNotAvailable as error:
            self.assertEqual(str(error), MATCHING_DOMAIN_BEHAVIOR_NOT_AVAILABLE)
            self.fail(f"semantic RED: {label}")

    def test_attempt_open_transitions_and_terminals_are_exact(self) -> None:
        opened, queued = self._semantic(
            "MatchingAttempt must OPEN with QUEUED run and terminal states cannot reopen",
            lambda: MatchingAttempt.open(
                attempt_id="matching_attempt_0000001",
                run_id="matching_run_0000000001",
                organization_id="organization_0000000001",
                demand_id="demand_object_000000001",
                demand_version_id="demand_version_00000001",
                matching_request_id="matching_request_000001",
                funding_id="funding_object_00000001",
                input_baseline_sha256=SHA,
                attempt_no=1,
                now=NOW,
            ),
        )
        self.assertEqual(opened.status, MatchingAttemptStatus.OPEN)
        self.assertEqual(queued.status, MatchRunStatus.QUEUED)

    def test_match_run_lease_fencing_and_failed_terminal_are_exact(self) -> None:
        started = self._semantic(
            "QUEUED run starts only under exact lease and FAILED never returns to RUNNING",
            lambda: run().start(worker_id="worker_00000000000001", lease_token="lease-token", fencing_generation=1, lease_until=NOW + timedelta(minutes=5), now=NOW),
        )
        self.assertEqual(started.status, MatchRunStatus.RUNNING)

    def test_invitation_state_machine_only_allows_sent_response_once(self) -> None:
        accepted, response = self._semantic(
            "SENT invitation accepts once against exact snapshot and becomes terminal",
            lambda: invitation().respond(
                response_id="response_object_0000001",
                creator_user_id="creator_user_000000001",
                response_kind=InvitationResponseKind.ACCEPTED,
                snapshot_sha256="b" * 64,
                reason_code=None,
                note=None,
                now=NOW + timedelta(days=1),
            ),
        )
        self.assertEqual(accepted.status, InvitationStatus.ACCEPTED)
        self.assertEqual(response.response_kind, InvitationResponseKind.ACCEPTED)

    def test_accepted_creator_can_withdraw_only_before_selection_intent(self) -> None:
        accepted, response = invitation().respond(
            response_id="response_object_0000001",
            creator_user_id="creator_user_000000001",
            response_kind=InvitationResponseKind.ACCEPTED,
            snapshot_sha256="b" * 64,
            reason_code=None,
            note=None,
            now=NOW + timedelta(hours=1),
        )

        withdrawn, withdrawal = self._semantic(
            "ACCEPTED invitation can become WITHDRAWN only while Selection is OPEN and has no intent",
            lambda: accepted.withdraw(
                withdrawal_id="withdrawal_object_00001",
                accepted_response_id=response.response_id,
                creator_user_id="creator_user_000000001",
                snapshot_sha256="b" * 64,
                selection_status=SelectionStatus.OPEN,
                selection_intent_recorded=False,
                reason_code="CREATOR_UNAVAILABLE",
                note="private withdrawal explanation",
                now=NOW + timedelta(hours=2),
            ),
        )

        self.assertEqual(withdrawn.status, InvitationStatus.WITHDRAWN)
        self.assertIsInstance(withdrawal, InvitationWithdrawal)
        self.assertEqual(withdrawal.accepted_response_id, response.response_id)
        self.assertNotIn("private withdrawal explanation", repr(withdrawal))

        with self.assertRaisesRegex(ValueError, "SELECTION_ALREADY_IN_PROGRESS"):
            accepted.withdraw(
                withdrawal_id="withdrawal_object_00002",
                accepted_response_id=response.response_id,
                creator_user_id="creator_user_000000001",
                snapshot_sha256="b" * 64,
                selection_status=SelectionStatus.OPEN,
                selection_intent_recorded=True,
                reason_code="CREATOR_UNAVAILABLE",
                note=None,
                now=NOW + timedelta(hours=2),
            )

    def test_candidate_selector_assignment_is_an_exact_immutable_scoped_fact(self) -> None:
        assignment = CandidateSelectorAssignment(
            assignment_id="selector_assignment_00001",
            aggregate_version=3,
            status=CandidateSelectorAssignmentStatus.ACTIVE,
            role_code=CandidateSelectorRoleCode.CANDIDATE_SELECTOR,
            assigned_user_id="actor_user_00000000001",
            organization_id="organization_0000000001",
            demand_id="demand_object_000000001",
            selection_id="matching_selection_00001",
            assigned_at=NOW - timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=5),
        )

        validate_candidate_selector_assignment(assignment, database_now=NOW)
        self.assertEqual(
            assignment.role_code.value,
            "CANDIDATE_SELECTOR",
        )
        with self.assertRaises(FrozenInstanceError):
            assignment.status = CandidateSelectorAssignmentStatus.RELEASED  # type: ignore[misc]

        for changed in (
            replace(assignment, status=CandidateSelectorAssignmentStatus.RELEASED),
            replace(assignment, role_code="DEMAND_OWNER"),
            replace(assignment, expires_at=NOW),
            replace(assignment, aggregate_version=0),
        ):
            with self.subTest(changed=changed):
                with self.assertRaisesRegex(ValueError, "CANDIDATE_SELECTOR_ASSIGNMENT_INACTIVE"):
                    validate_candidate_selector_assignment(
                        changed,
                        database_now=NOW,
                    )

    def test_selection_requires_accepted_invitation_and_terminals_do_not_reopen(self) -> None:
        selected = self._semantic(
            "OPEN Selection chooses one ACCEPTED invitation and SELECTED is terminal",
            lambda: selection().choose(
                invitation=invitation(status=InvitationStatus.ACCEPTED),
                invitation_set=(invitation(status=InvitationStatus.ACCEPTED),),
                expected_invitation_set_sha256=SHA,
                actor_id="owner_user_0000000001",
                selection_basis_code="ALGORITHM_TOP",
                now=NOW,
            ),
        )
        self.assertEqual(selected.status, SelectionStatus.SELECTED)

    def test_open_selection_refreshes_invitation_set_with_a_new_version(self) -> None:
        refreshed = self._semantic(
            "OPEN Selection refreshes its optimistic invitation-set binding",
            lambda: selection().refresh_invitation_set(
                current_invitation_set_sha256="c" * 64,
                now=NOW + timedelta(seconds=1),
            ),
        )
        self.assertEqual(refreshed.status, SelectionStatus.OPEN)
        self.assertEqual(refreshed.aggregate_version, 2)
        self.assertEqual(refreshed.current_invitation_set_sha256, "c" * 64)

    def test_selection_invitation_set_hash_is_closed_current_and_permutation_invariant(self) -> None:
        sent = invitation(invitation_id="business_invitation_sent_001")
        accepted = invitation(
            invitation_id="business_invitation_accept1",
            status=InvitationStatus.ACCEPTED,
            aggregate_version=3,
        )
        created = invitation(
            invitation_id="business_invitation_draft01",
            status=InvitationStatus.CREATED,
            aggregate_version=1,
            sent_at=None,
        )

        expected = selection_invitation_set_sha256(
            attempt_id=sent.attempt_id,
            run_id=sent.match_run_id,
            invitations=(sent, accepted, created),
        )
        permuted = selection_invitation_set_sha256(
            attempt_id=sent.attempt_id,
            run_id=sent.match_run_id,
            invitations=(created, accepted, sent),
        )
        without_draft = selection_invitation_set_sha256(
            attempt_id=sent.attempt_id,
            run_id=sent.match_run_id,
            invitations=(accepted, sent),
        )
        status_changed = selection_invitation_set_sha256(
            attempt_id=sent.attempt_id,
            run_id=sent.match_run_id,
            invitations=(
                replace(sent, status=InvitationStatus.DECLINED, aggregate_version=3),
                accepted,
            ),
        )

        self.assertEqual(expected, permuted)
        self.assertEqual(expected, without_draft)
        self.assertNotEqual(expected, status_changed)

    def test_selection_invitation_set_hash_rejects_mixed_scope_and_duplicates(self) -> None:
        current = invitation(invitation_id="business_invitation_scope01")
        invalid_sets = (
            (current, replace(current, invitation_id="business_invitation_scope02", attempt_id="matching_attempt_other001")),
            (current, replace(current, invitation_id="business_invitation_scope03", match_run_id="matching_run_other00001")),
            (current, current),
        )

        for invitation_set in invalid_sets:
            with self.subTest(invitation_set=invitation_set):
                with self.assertRaisesRegex(ValueError, "MATCH_INPUT_CHANGED"):
                    selection_invitation_set_sha256(
                        attempt_id=current.attempt_id,
                        run_id=current.match_run_id,
                        invitations=invitation_set,
                    )

    def test_invitation_expiry_equality_is_expired(self) -> None:
        value = invitation(expires_at=NOW)
        expired = self._semantic(
            "expires_at <= database_now is expired even before scheduler writes EXPIRED",
            lambda: invitation_is_expired(invitation=value, database_now=NOW),
        )
        self.assertTrue(expired)

    def test_eligible_candidate_requires_six_scores_total_and_rank(self) -> None:
        value = candidate(eligible=True)
        self._semantic(
            "ELIGIBLE requires empty reasons, six ordered Decimal scores, total and positive rank",
            lambda: validate_match_candidate(value),
        )
        self.assertEqual(value.eligibility, CandidateEligibility.ELIGIBLE)

    def test_excluded_candidate_requires_all_ordered_reasons_and_no_scores(self) -> None:
        value = candidate(eligible=False)
        self._semantic(
            "EXCLUDED requires at least one rule-ordered reason and null score/rank",
            lambda: validate_match_candidate(value),
        )
        self.assertIsNone(value.total_score)

    def test_candidate_scores_are_decimal_and_canonical_json_strings(self) -> None:
        value = candidate(score="80.00")
        encoded = self._semantic(
            "candidate score facts use Decimal and JSON 0.00..100.00 strings, never float",
            lambda: canonical_candidate_result_bytes(value),
        )
        decoded = json.loads(encoded)
        self.assertIsInstance(value.total_score, Decimal)
        self.assertEqual(decoded["total_score"], "80.00")

    def test_rank_and_ordered_hash_are_permutation_invariant(self) -> None:
        first = candidate(creator_user_id="creator_user_000000002", score="90.00")
        second = candidate(creator_user_id="creator_user_000000001", score="80.00")
        expected = self._semantic(
            "input permutation cannot change ranked bytes or ordered result hash",
            lambda: deterministic_rank_and_hash(candidates=(first, second), matching_rule_bundle_id="matching_bundle_00000001", input_set_sha256=SHA),
        )
        actual = deterministic_rank_and_hash(candidates=(second, first), matching_rule_bundle_id="matching_bundle_00000001", input_set_sha256=SHA)
        self.assertEqual(expected, actual)

    def test_equal_unrounded_scores_tie_break_by_opaque_creator_utf8_bytes(self) -> None:
        later = candidate(creator_user_id="creator_user_000000002", score="80.00")
        earlier = candidate(creator_user_id="creator_user_000000001", score="80.00")
        ranked, _ = self._semantic(
            "equal unrounded totals tie by opaque creator ID UTF-8 bytes",
            lambda: deterministic_rank_and_hash(candidates=(later, earlier), matching_rule_bundle_id="matching_bundle_00000001", input_set_sha256=SHA),
        )
        self.assertEqual(tuple(item.creator_user_id for item in ranked), (earlier.creator_user_id, later.creator_user_id))

    def test_candidate_hash_excludes_its_own_digest_and_is_repeatable(self) -> None:
        value = candidate()
        digest = self._semantic(
            "candidate hash covers the closed shape excluding candidate_result_sha256",
            lambda: candidate_result_sha256(value),
        )
        self.assertEqual(digest, candidate_result_sha256(value))

    def test_private_floor_value_is_not_representable_in_candidate_or_repr(self) -> None:
        value = candidate(eligible=False)
        self._semantic(
            "BELOW_PRIVATE_FLOOR persists only reason/boolean evidence and no floor value",
            lambda: validate_match_candidate(value),
        )
        self.assertNotIn("floor_amount", repr(value).lower())
        self.assertNotIn("private_floor", MatchCandidate.__dataclass_fields__)

    def test_published_facts_and_commands_are_immutable(self) -> None:
        value = attempt()
        with self.assertRaises(FrozenInstanceError):
            value.status = MatchingAttemptStatus.CANCELLED  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
