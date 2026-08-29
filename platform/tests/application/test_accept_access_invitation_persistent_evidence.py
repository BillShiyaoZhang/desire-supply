"""Persistent evidence TDD for ``AcceptAccessInvitation``.

The PostgreSQL design gives PolicyAcceptance and ConsentGrant more durable
authentication provenance than their public events.  These tests keep that
provenance tied to the locked predecessor Session and command receipt while
leaving the closed machine-event payloads unchanged.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Mapping
import unittest

from tests.support.iam_application_builders import (
    PILOT_ENDS_AT,
    RESEARCH_CONSENT_HASH,
    creator_acceptance_fixture,
)


class AcceptAccessInvitationPersistentEvidenceTest(unittest.TestCase):
    def test_new_policy_acceptances_persist_auth_and_command_evidence(self) -> None:
        """Each append-only acceptance records its exact authentication ceremony."""

        fixture = creator_acceptance_fixture()
        predecessor = fixture.store.snapshot()["sessions"][fixture.ids.session_id]

        fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        snapshot = fixture.store.snapshot()

        self.assertEqual(len(snapshot["policy_acceptances"]), 2)
        for acceptance in snapshot["policy_acceptances"].values():
            with self.subTest(document_id=acceptance["policy_document_id"]):
                self.assertEqual(
                    self._policy_evidence(acceptance),
                    {
                        "session_id": fixture.ids.session_id,
                        "auth_transaction_id": fixture.ids.auth_transaction_id,
                        "auth_time": predecessor["auth_time"],
                        "acr_code": predecessor["acr_code"],
                        "amr_codes": tuple(predecessor["amr_codes"]),
                        "source_action": "ACCESS_INVITATION_ACCEPT",
                        "command_id": fixture.ids.command_receipt_id,
                        "correlation_id": fixture.actor.correlation_id,
                        "aggregate_version": 1,
                        "created_at": fixture.clock.now(),
                    },
                )
                self.assertEqual(acceptance["created_at"].utcoffset(), timedelta(0))

    def test_new_consent_grant_preserves_derived_authority_and_evidence(self) -> None:
        """Consent provenance is persisted without replacing offer-derived authority."""

        fixture = creator_acceptance_fixture()
        predecessor = fixture.store.snapshot()["sessions"][fixture.ids.session_id]

        fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        consent = fixture.store.snapshot()["consent_grants"][
            fixture.ids.consent_grant_id
        ]

        self.assertEqual(
            self._consent_evidence(consent),
            {
                "session_id": fixture.ids.session_id,
                "auth_transaction_id": fixture.ids.auth_transaction_id,
                "auth_time": predecessor["auth_time"],
                "acr_code": predecessor["acr_code"],
                "amr_codes": tuple(predecessor["amr_codes"]),
                "command_id": fixture.ids.command_receipt_id,
                "correlation_id": fixture.actor.correlation_id,
                "created_at": fixture.clock.now(),
                "updated_at": fixture.clock.now(),
            },
        )
        self.assertEqual(consent["created_at"].utcoffset(), timedelta(0))
        self.assertEqual(consent["updated_at"].utcoffset(), timedelta(0))
        self.assertEqual(
            {
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

    def test_exact_historical_evidence_is_reused_without_session_rebinding(self) -> None:
        """An exact old fact remains valid evidence from its original Session."""

        fixture = creator_acceptance_fixture()
        historical_at = fixture.clock.now() - timedelta(days=30)
        terms = fixture.policy_bundle.documents[0]
        acceptance_id = "policy_acceptance_historical_terms_009"
        consent_id = "consent_grant_historical_research_009"
        historical_acceptance = {
            "policy_acceptance_id": acceptance_id,
            "user_id": fixture.ids.user_id,
            "policy_bundle_id": fixture.ids.policy_bundle_id,
            "policy_document_id": terms.document_id,
            "policy_document_sha256": terms.content_sha256,
            "legal_effect": terms.legal_effect.value,
            "accepted_at": historical_at,
            "session_id": "session_historical_policy_009",
            "auth_transaction_id": "auth_tx_historical_policy_009",
            "auth_time": historical_at - timedelta(minutes=2),
            "acr_code": "urn:desire:acr:mfa",
            "amr_codes": ("pwd", "otp"),
            "source_action": "POLICY_ACCEPT",
            "command_id": "command_receipt_historical_policy_009",
            "correlation_id": "correlation_historical_policy_009",
            "aggregate_version": 1,
            "created_at": historical_at,
        }
        historical_consent = {
            "consent_grant_id": consent_id,
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
            "granted_at": historical_at,
            "expires_at": PILOT_ENDS_AT,
            "session_id": "session_historical_consent_009",
            "auth_transaction_id": "auth_tx_historical_consent_009",
            "auth_time": historical_at - timedelta(minutes=2),
            "acr_code": "urn:desire:acr:mfa",
            "amr_codes": ("pwd", "otp"),
            "command_id": "command_receipt_historical_consent_009",
            "correlation_id": "correlation_historical_consent_009",
            "created_at": historical_at,
            "updated_at": historical_at,
        }
        fixture.store.seed(
            policy_acceptances={acceptance_id: historical_acceptance},
            consent_grants={consent_id: historical_consent},
        )

        fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        snapshot = fixture.store.snapshot()

        self.assertEqual(snapshot["policy_acceptances"][acceptance_id], historical_acceptance)
        self.assertEqual(snapshot["consent_grants"], {consent_id: historical_consent})
        self.assertNotEqual(
            historical_acceptance["session_id"], fixture.ids.session_id
        )
        self.assertNotEqual(historical_consent["session_id"], fixture.ids.session_id)

    def test_machine_events_exclude_internal_auth_and_command_evidence(self) -> None:
        """Durable database evidence does not widen either closed event payload."""

        fixture = creator_acceptance_fixture()
        fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        events = fixture.store.snapshot()["outbox_events"].values()
        policy_payloads = [
            event["payload"] for event in events if event["event_type"] == "PolicyAccepted"
        ]
        consent_payload = next(
            event["payload"] for event in events if event["event_type"] == "ConsentGranted"
        )

        expected_policy_keys = {
            "policy_acceptance_id",
            "user_id",
            "policy_bundle_id",
            "policy_document_id",
            "policy_document_sha256",
            "legal_effect",
        }
        self.assertEqual(
            [set(payload) for payload in policy_payloads],
            [expected_policy_keys, expected_policy_keys],
        )
        self.assertEqual(
            set(consent_payload),
            {
                "consent_grant_id",
                "user_id",
                "status",
                "granted_at",
                "derived_authorization",
            },
        )
        forbidden = {
            "session_id",
            "auth_transaction_id",
            "auth_time",
            "acr_code",
            "amr_codes",
            "source_action",
            "command_id",
            "correlation_id",
            "created_at",
            "updated_at",
        }
        self.assertTrue(forbidden.isdisjoint(consent_payload))
        self.assertTrue(
            all(forbidden.isdisjoint(payload) for payload in policy_payloads)
        )

    @staticmethod
    def _policy_evidence(acceptance: Mapping[str, Any]) -> Mapping[str, Any]:
        names = (
            "session_id",
            "auth_transaction_id",
            "auth_time",
            "acr_code",
            "amr_codes",
            "source_action",
            "command_id",
            "correlation_id",
            "aggregate_version",
            "created_at",
        )
        return {name: acceptance.get(name) for name in names}

    @staticmethod
    def _consent_evidence(consent: Mapping[str, Any]) -> Mapping[str, Any]:
        names = (
            "session_id",
            "auth_transaction_id",
            "auth_time",
            "acr_code",
            "amr_codes",
            "command_id",
            "correlation_id",
            "created_at",
            "updated_at",
        )
        return {name: consent.get(name) for name in names}


if __name__ == "__main__":
    unittest.main()
