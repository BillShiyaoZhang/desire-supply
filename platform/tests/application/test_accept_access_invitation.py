"""TEST-APP-IAM-003 and TEST-APP-HOLD-IAM-001 semantic TDD regression tests.

These tests define the application transaction before its production modules
exist.  They intentionally exercise the public handler with a real in-memory unit
of work; the support fixture only seeds already-established OIDC and policy facts.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import replace
import inspect
import json
import unittest

from desire_platform.identity_access.adapters.memory import FaultInjector
from desire_platform.identity_access.application.access_invitations import (
    AcceptAccessInvitationCommand,
)
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.domain.invitations import InvitationStatus
from desire_platform.identity_access.ports.safety_hold import HoldDecision
from tests.support.iam_application_builders import (
    HOLD_POLICY_VERSION,
    PILOT_ENDS_AT,
    PRIVACY_HASH,
    RESEARCH_CONSENT_HASH,
    TERMS_HASH,
    AcceptanceFixture,
    creator_acceptance_fixture,
    initial_admin_acceptance_fixture,
)


class AcceptAccessInvitationApplicationTest(unittest.TestCase):
    """Acceptance is one fail-closed, replay-safe authorization transaction."""

    def assert_iam_error(self, expected_code, operation) -> None:
        with self.assertRaises(IamError) as raised:
            operation()
        self.assertEqual(raised.exception.code, expected_code)

    def test_command_is_closed_and_cannot_claim_identity_scope_role_or_token(self):
        """Actor and server-derived invitation facts never enter the command body."""

        signature = inspect.signature(AcceptAccessInvitationCommand)
        self.assertEqual(
            tuple(signature.parameters),
            (
                "invitation_id",
                "expected_version",
                "idempotency_key",
                "policy_bundle_id",
                "policy_acceptances",
                "consent_grants",
            ),
        )
        self.assertFalse(
            any(
                parameter.kind == inspect.Parameter.VAR_KEYWORD
                for parameter in signature.parameters.values()
            )
        )
        forbidden = {
            "user_id",
            "actor_id",
            "session_id",
            "organization_id",
            "target_role",
            "role",
            "access_token",
            "invitation_token",
            "token",
            "cookie",
            "csrf_token",
        }
        self.assertTrue(forbidden.isdisjoint(signature.parameters))

    def test_creator_accepts_as_one_exact_atomic_authorization_change(self):
        """Creator acceptance writes exact policy/consent, role, rotation and evidence."""

        fixture = creator_acceptance_fixture()
        self._assert_exact_onboarding_seed(fixture)

        result = fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        snapshot = fixture.store.snapshot()

        user = snapshot["users"][fixture.ids.user_id]
        self.assertEqual(user["status"], "ACTIVE")
        self.assertEqual(user["aggregate_version"], 2)

        invitation = snapshot["invitations"][fixture.ids.invitation_id]
        self.assertEqual(invitation.status, InvitationStatus.ACCEPTED)
        self.assertEqual(
            invitation.aggregate_version,
            fixture.invitation.aggregate_version + 1,
        )

        self.assertEqual(
            snapshot["user_role_grants"],
            {
                fixture.ids.user_role_grant_id: {
                    "user_role_grant_id": fixture.ids.user_role_grant_id,
                    "user_id": fixture.ids.user_id,
                    "target_role": "CREATOR",
                    "source_invitation_id": fixture.ids.invitation_id,
                    "policy_selector_digest": fixture.policy_selector_digest,
                    "granted_by_kind": "USER",
                    "granted_by_id": fixture.ids.user_id,
                    "granted_at": fixture.clock.now(),
                    "revoked_at": None,
                    "revocation_reason_code": None,
                    "aggregate_version": 1,
                }
            },
        )
        self.assertEqual(snapshot["memberships"], {})
        self.assertEqual(snapshot["membership_role_grants"], {})
        self._assert_exact_policy_acceptances(snapshot, fixture)

        self.assertEqual(len(snapshot["consent_grants"]), 1)
        consent = snapshot["consent_grants"][fixture.ids.consent_grant_id]
        self.assertEqual(
            {
                "consent_grant_id": consent["consent_grant_id"],
                "user_id": consent["user_id"],
                "status": consent["status"],
                "aggregate_version": consent["aggregate_version"],
                "consent_offer_id": consent["consent_offer_id"],
                "consent_offer_version": consent["consent_offer_version"],
                "policy_bundle_id": consent["policy_bundle_id"],
                "purpose": consent["purpose"],
                "scope_type": consent["scope_type"],
                "scope_id": consent["scope_id"],
                "data_categories": tuple(consent["data_categories"]),
                "recipient_reference": consent["recipient_reference"],
                "supporting_policy_document_id": consent[
                    "supporting_policy_document_id"
                ],
                "supporting_document_sha256": consent[
                    "supporting_document_sha256"
                ],
                "granted_at": consent["granted_at"],
                "expires_at": consent["expires_at"],
            },
            {
                "consent_grant_id": fixture.ids.consent_grant_id,
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
                "supporting_policy_document_id": fixture.ids.research_document_id,
                "supporting_document_sha256": RESEARCH_CONSENT_HASH,
                "granted_at": fixture.clock.now(),
                "expires_at": PILOT_ENDS_AT,
            },
        )

        self._assert_session_was_rotated_and_binding_cleared(
            snapshot, fixture, result
        )
        self._assert_common_evidence(
            snapshot,
            fixture,
            result,
            organization_id=None,
            expected_event_types=Counter(
                {
                    "PolicyAccepted": 2,
                    "ConsentGranted": 1,
                    "UserActivated": 1,
                    "UserRoleGranted": 1,
                    "AccessInvitationAccepted": 1,
                }
            ),
        )

    def test_initial_org_admin_acceptance_activates_relationship_and_org_together(self):
        """Initial admin has one Membership role and activates its pending Organization."""

        fixture = initial_admin_acceptance_fixture()
        self._assert_exact_onboarding_seed(fixture)

        result = fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        snapshot = fixture.store.snapshot()

        self.assertEqual(snapshot["users"][fixture.ids.user_id]["status"], "ACTIVE")
        self.assertEqual(
            snapshot["organizations"][fixture.ids.organization_id]["status"],
            "ACTIVE",
        )
        self.assertEqual(
            snapshot["organizations"][fixture.ids.organization_id][
                "aggregate_version"
            ],
            2,
        )
        self.assertEqual(
            snapshot["memberships"],
            {
                fixture.ids.membership_id: {
                    "membership_id": fixture.ids.membership_id,
                    "organization_id": fixture.ids.organization_id,
                    "user_id": fixture.ids.user_id,
                    "status": "ACTIVE",
                    "aggregate_version": 1,
                    "access_invitation_id": fixture.ids.invitation_id,
                    "activated_at": fixture.clock.now(),
                }
            },
        )
        self.assertEqual(
            snapshot["membership_role_grants"],
            {
                fixture.ids.membership_role_grant_id: {
                    "membership_role_grant_id": fixture.ids.membership_role_grant_id,
                    "membership_id": fixture.ids.membership_id,
                    "user_id": fixture.ids.user_id,
                    "organization_id": fixture.ids.organization_id,
                    "target_role": "ORG_ADMIN",
                    "source_invitation_id": fixture.ids.invitation_id,
                    "policy_selector_digest": fixture.policy_selector_digest,
                    "granted_by_kind": "USER",
                    "granted_by_id": fixture.ids.user_id,
                    "granted_at": fixture.clock.now(),
                    "revoked_at": None,
                    "revocation_reason_code": None,
                    "aggregate_version": 1,
                }
            },
        )
        self.assertEqual(snapshot["user_role_grants"], {})
        self.assertEqual(snapshot["consent_grants"], {})
        self._assert_exact_policy_acceptances(snapshot, fixture)

        invitation = snapshot["invitations"][fixture.ids.invitation_id]
        self.assertEqual(invitation.status, InvitationStatus.ACCEPTED)
        self._assert_session_was_rotated_and_binding_cleared(
            snapshot, fixture, result
        )
        self._assert_common_evidence(
            snapshot,
            fixture,
            result,
            organization_id=fixture.ids.organization_id,
            expected_event_types=Counter(
                {
                    "PolicyAccepted": 2,
                    "UserActivated": 1,
                    "MembershipActivated": 1,
                    "MembershipRoleGranted": 1,
                    "OrganizationActivated": 1,
                    "AccessInvitationAccepted": 1,
                }
            ),
        )

    def test_every_creator_write_checkpoint_rolls_the_full_snapshot_back(self):
        """A fault at every instrumented creator write leaves no receipt or partial fact."""

        self._assert_every_write_checkpoint_rolls_back(creator_acceptance_fixture)

    def test_every_initial_admin_write_checkpoint_rolls_the_full_snapshot_back(self):
        """Organization, Membership and role writes share the same rollback boundary."""

        self._assert_every_write_checkpoint_rolls_back(
            initial_admin_acceptance_fixture
        )

    def test_same_key_and_hash_replay_is_safe_but_changed_payload_conflicts(self):
        """Receipt replay is exact-principal/hash scoped and cannot duplicate any fact."""

        fixture = creator_acceptance_fixture()
        first = fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        after_first = fixture.store.snapshot()
        hold_calls_after_first = len(fixture.hold.calls)

        successor_actor = fixture.actor_for_session(
            first.session_rotation.session_id
        )
        replay = fixture.handler.handle(
            actor=successor_actor,
            command=fixture.command,
        )

        self.assertTrue(replay.replayed)
        self.assertEqual(replay.safe_response, first.safe_response)
        self.assertIsNone(replay.session_rotation)
        self.assertEqual(fixture.store.snapshot(), after_first)
        self.assertEqual(len(fixture.hold.calls), hold_calls_after_first)

        changed_payload = replace(fixture.command, consent_grants=())
        before_conflict = fixture.store.snapshot()
        self.assert_iam_error(
            "IDEMPOTENCY_KEY_REUSED",
            lambda: fixture.handler.handle(
                actor=successor_actor,
                command=changed_payload,
            ),
        )
        self.assertEqual(fixture.store.snapshot(), before_conflict)
        self.assertEqual(len(fixture.hold.calls), hold_calls_after_first)

    def test_hold_block_and_unavailability_fail_closed_before_any_write(self):
        """Accept is an escalation: both negative hold outcomes leave zero IAM writes."""

        cases = (
            (
                creator_acceptance_fixture,
                HoldDecision.BLOCK,
                "SAFETY_HOLD_BLOCKED",
            ),
            (
                initial_admin_acceptance_fixture,
                HoldDecision.UNAVAILABLE,
                "SAFETY_DECISION_UNAVAILABLE",
            ),
        )
        for fixture_factory, decision, expected_error in cases:
            with self.subTest(decision=decision):
                fixture = fixture_factory(hold_decision=decision)
                before = fixture.store.snapshot()

                self.assert_iam_error(
                    expected_error,
                    lambda: fixture.handler.handle(
                        actor=fixture.actor,
                        command=fixture.command,
                    ),
                )

                self.assertEqual(fixture.store.snapshot(), before)
                self.assertEqual(fixture.fault_injector.write_count, 0)
                self._assert_exact_hold_call(fixture)

    def test_completed_receipt_replays_for_same_user_new_unbound_session_only(self):
        """Recovery precedes onboarding guards but never reconstructs cookie or CSRF."""

        fixture = creator_acceptance_fixture()
        first = fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        fresh_actor = fixture.seed_fresh_unbound_login()
        before_replay = fixture.store.snapshot()

        fresh_session = before_replay["sessions"][fixture.ids.fresh_login_session_id]
        self.assertEqual(fresh_session["status"], "ACTIVE")
        self.assertIsNone(fresh_session["verified_contact_point_id"])
        self.assertIsNone(fresh_session["verified_for_invitation_id"])
        self.assertIsNone(fresh_session["auth_transaction_id"])

        replay = fixture.handler.handle(actor=fresh_actor, command=fixture.command)

        self.assertTrue(replay.replayed)
        self.assertEqual(replay.safe_response, first.safe_response)
        self.assertIsNone(replay.session_rotation)
        self.assertEqual(fixture.store.snapshot(), before_replay)
        self.assertEqual(len(fixture.hold.calls), 1)
        self._assert_safe_body_has_no_transport_secrets(replay.safe_response)

        receipt = next(iter(before_replay["command_receipts"].values()))
        self.assertEqual(receipt["response_body"], replay.safe_response)
        self._assert_safe_body_has_no_transport_secrets(receipt["response_body"])
        persisted_receipt = repr(receipt)
        self.assertNotIn(first.session_rotation.raw_session_handle, persisted_receipt)
        self.assertNotIn(first.session_rotation.csrf_token, persisted_receipt)

    def _assert_exact_onboarding_seed(self, fixture: AcceptanceFixture) -> None:
        snapshot = fixture.store.snapshot()
        ids = fixture.ids
        self.assertEqual(snapshot["users"][ids.user_id]["status"], "PENDING_ENROLLMENT")
        self.assertEqual(
            snapshot["invitations"][ids.invitation_id].status,
            InvitationStatus.ISSUED,
        )
        self.assertIs(
            snapshot["policy_bundles"][ids.policy_bundle_id],
            fixture.policy_bundle,
        )
        selector = (
            fixture.invitation.purpose.value,
            fixture.invitation.target_role.value,
        )
        self.assertEqual(
            snapshot["current_policy_bundles"][selector],
            ids.policy_bundle_id,
        )

        family = snapshot["session_families"][ids.session_family_id]
        session = snapshot["sessions"][ids.session_id]
        transaction = snapshot["auth_transactions"][ids.auth_transaction_id]
        self.assertEqual(family["status"], "ACTIVE")
        self.assertEqual(family["current_generation"], 1)
        self.assertEqual(session["status"], "ACTIVE")
        self.assertEqual(session["user_id"], ids.user_id)
        self.assertEqual(session["verified_contact_point_id"], ids.contact_point_id)
        self.assertEqual(session["verified_for_invitation_id"], ids.invitation_id)
        self.assertEqual(session["auth_transaction_id"], ids.auth_transaction_id)
        self.assertEqual(transaction["status"], "SUCCEEDED")
        self.assertEqual(transaction["expected_user_id"], ids.user_id)
        self.assertEqual(
            transaction["expected_contact_point_id"], ids.contact_point_id
        )
        self.assertEqual(transaction["invitation_id"], ids.invitation_id)
        self.assertEqual(
            transaction["invitation_version"],
            fixture.command.expected_version,
        )

    def _assert_exact_policy_acceptances(self, snapshot, fixture) -> None:
        self.assertEqual(
            set(snapshot["policy_acceptances"]),
            {
                fixture.ids.terms_acceptance_id,
                fixture.ids.privacy_acceptance_id,
            },
        )
        actual = {
            (
                acceptance["user_id"],
                acceptance["policy_bundle_id"],
                acceptance["policy_document_id"],
                acceptance["policy_document_sha256"],
                acceptance["legal_effect"],
                acceptance["accepted_at"],
            )
            for acceptance in snapshot["policy_acceptances"].values()
        }
        self.assertEqual(
            actual,
            {
                (
                    fixture.ids.user_id,
                    fixture.ids.policy_bundle_id,
                    fixture.ids.terms_document_id,
                    TERMS_HASH,
                    "CONTRACT_ACCEPTANCE",
                    fixture.clock.now(),
                ),
                (
                    fixture.ids.user_id,
                    fixture.ids.policy_bundle_id,
                    fixture.ids.privacy_document_id,
                    PRIVACY_HASH,
                    "NOTICE_ACKNOWLEDGEMENT",
                    fixture.clock.now(),
                ),
            },
        )

    def _assert_session_was_rotated_and_binding_cleared(
        self, snapshot, fixture, result
    ) -> None:
        self.assertFalse(result.replayed)
        self.assertIsNotNone(result.session_rotation)
        self.assertEqual(
            result.session_rotation.session_id,
            fixture.ids.successor_session_id,
        )
        self.assertIsInstance(result.session_rotation.raw_session_handle, str)
        self.assertTrue(result.session_rotation.raw_session_handle)
        self.assertIsInstance(result.session_rotation.csrf_token, str)
        self.assertTrue(result.session_rotation.csrf_token)

        predecessor = snapshot["sessions"][fixture.ids.session_id]
        successor = snapshot["sessions"][fixture.ids.successor_session_id]
        family = snapshot["session_families"][fixture.ids.session_family_id]
        self.assertEqual(predecessor["status"], "REVOKED")
        self.assertEqual(successor["status"], "ACTIVE")
        self.assertEqual(successor["user_id"], fixture.ids.user_id)
        self.assertEqual(
            successor["session_family_id"], fixture.ids.session_family_id
        )
        self.assertEqual(successor["generation"], 2)
        self.assertEqual(successor["predecessor_session_id"], fixture.ids.session_id)
        self.assertIsNone(successor["verified_contact_point_id"])
        self.assertIsNone(successor["verified_for_invitation_id"])
        self.assertIsNone(successor["auth_transaction_id"])
        self.assertEqual(family["current_generation"], 2)
        self.assertEqual(family["aggregate_version"], 2)
        active_in_family = [
            session
            for session in snapshot["sessions"].values()
            if session["session_family_id"] == fixture.ids.session_family_id
            and session["status"] == "ACTIVE"
        ]
        self.assertEqual(active_in_family, [successor])

    def _assert_common_evidence(
        self,
        snapshot,
        fixture,
        result,
        *,
        organization_id,
        expected_event_types,
    ) -> None:
        self.assertIsInstance(result.safe_response, dict)
        self._assert_safe_body_has_no_transport_secrets(result.safe_response)
        self._assert_exact_hold_call(fixture)

        self.assertEqual(len(snapshot["command_receipts"]), 1)
        receipt = next(iter(snapshot["command_receipts"].values()))
        self.assertEqual(receipt["status"], "COMPLETED")
        self.assertEqual(receipt["principal_kind"], "USER")
        self.assertEqual(receipt["principal_id"], fixture.ids.user_id)
        self.assertEqual(receipt["command_name"], "AcceptAccessInvitation")
        self.assertEqual(receipt["command_version"], 1)
        self.assertTrue(receipt["idempotency_key_digest"])
        self.assertTrue(receipt["payload_hash"])
        self.assertEqual(receipt["response_schema_version"], 1)
        self.assertEqual(receipt["response_body"], result.safe_response)
        self.assertNotIn("idempotency_key", receipt)

        self.assertEqual(len(snapshot["audit_events"]), 1)
        audit = next(iter(snapshot["audit_events"].values()))
        self.assertEqual(audit["actor_id"], fixture.ids.user_id)
        self.assertEqual(audit["action"], "AcceptAccessInvitation")
        self.assertEqual(audit["target_type"], "AccessInvitation")
        self.assertEqual(audit["target_id"], fixture.ids.invitation_id)
        self.assertEqual(audit["organization_id"], organization_id)
        self.assertEqual(audit["result"], "SUCCEEDED")
        self.assertEqual(audit["occurred_at"], fixture.clock.now())

        outbox = snapshot["outbox_events"]
        self.assertEqual(
            Counter(event["event_type"] for event in outbox.values()),
            expected_event_types,
        )
        self.assertEqual(
            {event["actor_id"] for event in outbox.values()},
            {fixture.ids.user_id},
        )
        self.assertEqual(
            {event["organization_id"] for event in outbox.values()},
            {organization_id},
        )

        persisted = repr(
            {
                "receipt": receipt,
                "audit": audit,
                "outbox": outbox,
            }
        )
        self.assertNotIn(fixture.command.idempotency_key, persisted)
        self.assertNotIn(fixture.ids.contact_point_id, repr(outbox))
        self.assertNotIn(fixture.ids.auth_transaction_id, repr(outbox))
        self.assertNotIn(result.session_rotation.raw_session_handle, persisted)
        self.assertNotIn(result.session_rotation.csrf_token, persisted)

    def _assert_exact_hold_call(self, fixture: AcceptanceFixture) -> None:
        self.assertEqual(len(fixture.hold.calls), 1)
        call = fixture.hold.calls[0]
        self.assertEqual(call.actor_id, fixture.ids.user_id)
        self.assertEqual(call.action, "AcceptAccessInvitation")
        self.assertEqual(call.target_type, "AccessInvitation")
        self.assertEqual(call.target_id, fixture.ids.invitation_id)
        self.assertEqual(call.organization_id, fixture.invitation.organization_id)
        self.assertEqual(call.policy_version, HOLD_POLICY_VERSION)

    def _assert_every_write_checkpoint_rolls_back(self, fixture_factory) -> None:
        probe = fixture_factory()
        probe.handler.handle(actor=probe.actor, command=probe.command)
        write_count = probe.fault_injector.write_count
        self.assertGreater(write_count, 0)

        for write_number in range(1, write_count + 1):
            with self.subTest(write_number=write_number, total=write_count):
                injector = FaultInjector(fail_on_write=write_number)
                fixture = fixture_factory(fault_injector=injector)
                before = fixture.store.snapshot()

                with self.assertRaises(RuntimeError):
                    fixture.handler.handle(
                        actor=fixture.actor,
                        command=fixture.command,
                    )

                self.assertEqual(injector.write_count, write_number)
                self.assertEqual(fixture.store.snapshot(), before)

    def _assert_safe_body_has_no_transport_secrets(self, body) -> None:
        encoded = json.dumps(body, sort_keys=True, default=str).lower()
        for forbidden_name in (
            "set-cookie",
            "set_cookie",
            "cookie",
            "csrf",
            "raw_session_handle",
            "session_handle",
        ):
            self.assertNotIn(forbidden_name, encoded)


if __name__ == "__main__":
    unittest.main()
