"""Focused semantic TDD regressions from the IAM acceptance review.

The established fourteen application tests remain the compatibility baseline.
These cases close process-stable receipt hashing, existing-user STEP_UP,
authorization resurrection, Session cryptographic persistence, and terminal
invitation non-disclosure gaps.  Every case imports the real public handler; no
failure is expected to come from a missing module or an unconditional constructor
TypeError.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import replace
import hashlib
import unittest

from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.domain.invitations import InvitationStatus
from tests.support.iam_application_builders import (
    PILOT_ENDS_AT,
    RECEIPT_CANONICALIZATION_VERSION,
    RESEARCH_CONSENT_HASH,
    AcceptanceFixture,
    active_creator_step_up_acceptance_fixture,
    canonical_accept_payload_bytes,
    creator_acceptance_fixture,
    existing_demand_owner_acceptance_fixture,
)


class AcceptAccessInvitationReauditTest(unittest.TestCase):
    def test_receipt_uses_versioned_keys_for_both_canonical_digests(self) -> None:
        """Receipt identity and payload hashes remain verifiable after restart."""

        fixture = creator_acceptance_fixture()
        fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        receipt = next(
            iter(fixture.store.snapshot()["command_receipts"].values())
        )

        self.assertEqual(
            receipt.get("idempotency_key_digest_key_id"),
            fixture.keyring.idempotency_key_digest_key_id,
        )
        self.assertEqual(
            receipt.get("payload_hash_key_id"),
            fixture.keyring.payload_hash_key_id,
        )
        self.assertEqual(
            receipt.get("canonicalization_version"),
            RECEIPT_CANONICALIZATION_VERSION,
        )
        self.assertEqual(
            receipt["idempotency_key_digest"],
            fixture.keyring.idempotency_key_digest(
                fixture.command.idempotency_key
            ),
        )
        self.assertEqual(
            receipt["payload_hash"],
            fixture.keyring.accept_payload_hash(fixture.command),
        )
        self.assertNotEqual(
            receipt["payload_hash"],
            hashlib.sha256(
                canonical_accept_payload_bytes(fixture.command)
            ).hexdigest(),
            "receipt payload material must be keyed, not a public SHA-256",
        )

    def test_completed_receipt_survives_handler_restart_and_new_entropy(self) -> None:
        """A new process finds the old receipt by stable key version, not entropy."""

        fixture = creator_acceptance_fixture()
        first = fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        fresh_actor = fixture.seed_fresh_unbound_login()
        before_replay = fixture.store.snapshot()
        hold_calls_before = len(fixture.hold.calls)

        restarted = fixture.restarted_handler(
            entropy_seed=b"deliberately-unrelated-process-entropy-v99"
        )
        replay = None
        error = None
        try:
            replay = restarted.handle(actor=fresh_actor, command=fixture.command)
        except IamError as caught:
            error = caught

        problems = []
        if error is not None:
            problems.append(
                "new handler could not locate completed receipt: %s" % error.code
            )
        if replay is None:
            problems.append("no replay result returned")
        if replay is not None:
            if not replay.replayed:
                problems.append("result was a new execution rather than a replay")
            if replay.safe_response != first.safe_response:
                problems.append("replayed safe response changed")
            if replay.session_rotation is not None:
                problems.append("receipt replay reconstructed Session secrets")
        if fixture.store.snapshot() != before_replay:
            problems.append("receipt replay mutated the shared store")
        if len(fixture.hold.calls) != hold_calls_before:
            problems.append("receipt replay re-evaluated the safety hold")
        if problems:
            self.fail("; ".join(problems))

    def test_active_user_exact_step_up_accepts_non_initial_demand_owner(self) -> None:
        """A later organization invitation neither reactivates User nor Organization."""

        fixture = existing_demand_owner_acceptance_fixture()
        before = fixture.store.snapshot()
        self.assertEqual(before["users"][fixture.ids.user_id]["status"], "ACTIVE")
        self.assertEqual(
            before["auth_transactions"][fixture.ids.auth_transaction_id]["purpose"],
            "STEP_UP",
        )
        self.assertEqual(
            before["organizations"][fixture.ids.organization_id]["status"],
            "ACTIVE",
        )

        result = fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        snapshot = fixture.store.snapshot()

        self.assertFalse(result.replayed)
        expected_user = dict(before["users"][fixture.ids.user_id])
        expected_user["aggregate_version"] += 1
        self.assertEqual(snapshot["users"][fixture.ids.user_id], expected_user)
        self.assertEqual(
            result.safe_response["me"]["aggregate_version"],
            expected_user["aggregate_version"],
        )
        self.assertEqual(
            result.safe_response["me"]["entity_tag"],
            '"v%d"' % expected_user["aggregate_version"],
        )
        self.assertEqual(
            snapshot["organizations"][fixture.ids.organization_id],
            before["organizations"][fixture.ids.organization_id],
        )
        membership = snapshot["memberships"][fixture.ids.membership_id]
        self.assertEqual(membership["status"], "ACTIVE")
        self.assertEqual(membership["user_id"], fixture.ids.user_id)
        self.assertEqual(
            membership["organization_id"], fixture.ids.organization_id
        )
        role = snapshot["membership_role_grants"][
            fixture.ids.membership_role_grant_id
        ]
        self.assertEqual(role["target_role"], "DEMAND_OWNER")
        self.assertEqual(role["membership_id"], fixture.ids.membership_id)
        self.assertEqual(snapshot["user_role_grants"], {})
        self.assertEqual(
            Counter(
                event["event_type"]
                for event in snapshot["outbox_events"].values()
            ),
            Counter(
                {
                    "PolicyAccepted": 2,
                    "PolicyRequirementsSatisfied": 1,
                    "MembershipActivated": 1,
                    "MembershipRoleGranted": 1,
                    "AccessInvitationAccepted": 1,
                }
            ),
        )

    def test_existing_creator_authority_rejects_zero_writes(self) -> None:
        """A new invitation cannot create a second active CREATOR grant."""

        fixture = active_creator_step_up_acceptance_fixture()
        self._seed_existing_creator_role(fixture)
        self._assert_rejected_without_effects(
            fixture,
            command=fixture.command,
            expected_code="INVALID_STATE_TRANSITION",
        )

    def test_exact_policy_and_active_consent_are_reused_while_missing_policy_is_added(
        self,
    ) -> None:
        """Append-only evidence is reused exactly without duplicate facts/events."""

        fixture = active_creator_step_up_acceptance_fixture()
        existing_acceptance_id = self._seed_existing_policy_acceptance(fixture)
        existing_consent_id = self._seed_existing_active_consent(fixture)
        before = fixture.store.snapshot()

        fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        snapshot = fixture.store.snapshot()

        self.assertEqual(
            snapshot["policy_acceptances"][existing_acceptance_id],
            before["policy_acceptances"][existing_acceptance_id],
        )
        self.assertEqual(len(snapshot["policy_acceptances"]), 2)
        self.assertEqual(
            {
                acceptance["policy_document_id"]
                for acceptance in snapshot["policy_acceptances"].values()
            },
            {
                fixture.ids.terms_document_id,
                fixture.ids.privacy_document_id,
            },
        )
        self.assertEqual(
            snapshot["consent_grants"],
            {existing_consent_id: before["consent_grants"][existing_consent_id]},
        )
        event_types = Counter(
            event["event_type"] for event in snapshot["outbox_events"].values()
        )
        self.assertEqual(event_types["PolicyAccepted"], 1)
        self.assertEqual(event_types["ConsentGranted"], 0)
        self.assertEqual(event_types["PolicyRequirementsSatisfied"], 1)
        policy_event = next(
            event
            for event in snapshot["outbox_events"].values()
            if event["event_type"] == "PolicyAccepted"
        )
        self.assertEqual(
            policy_event["payload"]["policy_document_id"],
            fixture.ids.privacy_document_id,
        )
        expected_user = dict(before["users"][fixture.ids.user_id])
        expected_user["aggregate_version"] += 1
        self.assertEqual(snapshot["users"][fixture.ids.user_id], expected_user)

    def test_same_organization_membership_in_every_state_blocks_reactivation(self) -> None:
        """Invitation accept is not the missing ReinstateMembership command."""

        for status in ("ACTIVE", "SUSPENDED", "REVOKED"):
            with self.subTest(membership_status=status):
                fixture = existing_demand_owner_acceptance_fixture()
                membership_id = "membership_preexisting_%s" % status.lower()
                fixture.store.seed(
                    memberships={
                        membership_id: {
                            "membership_id": membership_id,
                            "organization_id": fixture.ids.organization_id,
                            "user_id": fixture.ids.user_id,
                            "status": status,
                            "aggregate_version": 7,
                            "access_invitation_id": "access_invitation_historical_009",
                            "activated_at": fixture.clock.now(),
                        }
                    }
                )
                self._assert_rejected_without_effects(
                    fixture,
                    command=fixture.command,
                    expected_code="MEMBERSHIP_ALREADY_EXISTS",
                )

    def test_successor_persists_versioned_handle_and_deterministic_csrf_facts(self) -> None:
        """Only raw response secrets leave the transaction; all validators persist."""

        fixture = creator_acceptance_fixture()
        result = fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        snapshot = fixture.store.snapshot()
        successor = snapshot["sessions"][fixture.ids.successor_session_id]
        rotation = result.session_rotation
        self.assertIsNotNone(rotation)
        if rotation is None:
            return

        required = {
            "handle_digest",
            "handle_digest_key_id",
            "csrf_salt",
            "csrf_key_id",
            "csrf_digest",
            "rotation_reason",
            "aggregate_version",
        }
        missing = sorted(required - set(successor))
        self.assertEqual(missing, [], "successor Session omitted persisted facts")
        if missing:
            return

        self.assertEqual(successor["rotation_reason"], "INVITATION_ACCEPT")
        self.assertEqual(successor["aggregate_version"], 1)
        self.assertEqual(
            successor["handle_digest_key_id"],
            fixture.keyring.session_handle_digest_key_id,
        )
        self.assertEqual(
            successor["handle_digest"],
            fixture.keyring.session_handle_digest(rotation.raw_session_handle),
        )
        self.assertNotEqual(
            successor["handle_digest"],
            hashlib.sha256(rotation.raw_session_handle.encode("ascii")).hexdigest(),
            "Session handles require a keyed digest",
        )
        self.assertEqual(successor["csrf_key_id"], fixture.keyring.csrf_key_id)
        expected_csrf = fixture.keyring.derive_csrf_token(
            raw_session_handle=rotation.raw_session_handle,
            csrf_salt=successor["csrf_salt"],
            session_id=successor["session_id"],
            generation=successor["generation"],
            key_id=successor["csrf_key_id"],
        )
        self.assertEqual(rotation.csrf_token, expected_csrf)
        self.assertEqual(
            successor["csrf_digest"],
            fixture.keyring.csrf_digest(
                csrf_token=rotation.csrf_token,
                key_id=successor["csrf_key_id"],
            ),
        )

        persisted = repr(snapshot)
        self.assertNotIn(rotation.raw_session_handle, persisted)
        self.assertNotIn(rotation.csrf_token, persisted)
        self.assertNotIn("raw_session_handle", successor)
        self.assertNotIn("csrf_token", successor)

    def test_terminal_or_expired_exact_bound_invitation_is_non_disclosing(self) -> None:
        """Without a receipt, exact binding cannot reveal terminal/deadline state."""

        cases = (
            ("expired", self._expire_invitation),
            ("accepted", lambda fixture: self._terminal_invitation(
                fixture, InvitationStatus.ACCEPTED
            )),
            ("revoked", lambda fixture: self._terminal_invitation(
                fixture, InvitationStatus.REVOKED
            )),
        )
        for name, mutate in cases:
            with self.subTest(invitation_state=name):
                fixture = creator_acceptance_fixture()
                command = mutate(fixture)
                self._assert_rejected_without_effects(
                    fixture,
                    command=command,
                    expected_code="ACCESS_INVITATION_UNAVAILABLE",
                )

    @staticmethod
    def _seed_existing_creator_role(fixture: AcceptanceFixture) -> None:
        fixture.store.seed(
            user_role_grants={
                "user_role_grant_existing_creator_009": {
                    "user_role_grant_id": "user_role_grant_existing_creator_009",
                    "user_id": fixture.ids.user_id,
                    "target_role": "CREATOR",
                    "access_invitation_id": "access_invitation_historical_009",
                    "granted_at": fixture.clock.now(),
                    "revoked_at": None,
                    "aggregate_version": 1,
                }
            }
        )

    @staticmethod
    def _seed_existing_policy_acceptance(fixture: AcceptanceFixture) -> str:
        acceptance_id = "policy_acceptance_existing_terms_009"
        terms = fixture.policy_bundle.documents[0]
        fixture.store.seed(
            policy_acceptances={
                acceptance_id: {
                    "policy_acceptance_id": acceptance_id,
                    "user_id": fixture.ids.user_id,
                    "policy_bundle_id": fixture.ids.policy_bundle_id,
                    "policy_document_id": terms.document_id,
                    "policy_document_sha256": terms.content_sha256,
                    "legal_effect": terms.legal_effect.value,
                    "accepted_at": fixture.clock.now(),
                }
            }
        )
        return acceptance_id

    @staticmethod
    def _seed_existing_active_consent(fixture: AcceptanceFixture) -> str:
        consent_grant_id = "consent_grant_existing_research_009"
        fixture.store.seed(
            consent_grants={
                consent_grant_id: {
                    "consent_grant_id": consent_grant_id,
                    "user_id": fixture.ids.user_id,
                    "status": "ACTIVE",
                    "aggregate_version": 1,
                    "consent_offer_id": fixture.ids.research_offer_id,
                    "consent_offer_version": 1,
                    "policy_bundle_id": fixture.ids.policy_bundle_id,
                    "purpose": "PILOT_RESEARCH",
                    "scope_type": "PLATFORM_PARTICIPATION",
                    "scope_id": None,
                    "data_categories": ("PROFILE", "MATCHING", "RESEARCH"),
                    "recipient_reference": fixture.ids.research_controller_id,
                    "supporting_policy_document_id": (
                        fixture.ids.research_document_id
                    ),
                    "supporting_document_sha256": RESEARCH_CONSENT_HASH,
                    "granted_at": fixture.clock.now(),
                    "expires_at": PILOT_ENDS_AT,
                }
            }
        )
        return consent_grant_id

    @staticmethod
    def _expire_invitation(fixture: AcceptanceFixture):
        expired = replace(fixture.invitation, expires_at=fixture.clock.now())
        fixture.store.seed(invitations={fixture.ids.invitation_id: expired})
        return fixture.command

    @staticmethod
    def _terminal_invitation(
        fixture: AcceptanceFixture,
        status: InvitationStatus,
    ):
        terminal = replace(
            fixture.invitation,
            status=status,
            aggregate_version=fixture.invitation.aggregate_version + 1,
        )
        transaction = dict(
            fixture.store.snapshot()["auth_transactions"][
                fixture.ids.auth_transaction_id
            ]
        )
        transaction["invitation_version"] = terminal.aggregate_version
        fixture.store.seed(
            invitations={fixture.ids.invitation_id: terminal},
            auth_transactions={fixture.ids.auth_transaction_id: transaction},
        )
        return replace(
            fixture.command,
            expected_version=terminal.aggregate_version,
        )

    def _assert_rejected_without_effects(
        self,
        fixture: AcceptanceFixture,
        *,
        command,
        expected_code: str,
    ) -> None:
        before = fixture.store.snapshot()
        writes_before = fixture.fault_injector.write_count
        hold_calls_before = len(fixture.hold.calls)
        error = None
        try:
            fixture.handler.handle(actor=fixture.actor, command=command)
        except IamError as caught:
            error = caught

        problems = []
        if error is None:
            problems.append("handler granted duplicate or unavailable authority")
        elif error.code != expected_code:
            problems.append(
                "unsafe/disclosing error code %s (expected %s)"
                % (error.code, expected_code)
            )
        if fixture.store.snapshot() != before:
            problems.append("rejected command changed persisted facts")
        if fixture.fault_injector.write_count != writes_before:
            problems.append("rejected command reached an instrumented write")
        if len(fixture.hold.calls) != hold_calls_before:
            problems.append("pre-existing/unavailable authority reached safety hold")
        if problems:
            self.fail("; ".join(problems))


if __name__ == "__main__":
    unittest.main()
