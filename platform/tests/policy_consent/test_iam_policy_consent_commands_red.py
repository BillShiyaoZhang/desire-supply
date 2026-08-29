"""TEST-APP-POLICY-CONSENT-001 semantic RED for the two SELF commands."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from datetime import timedelta, timezone
from typing import Any, Mapping
import unittest

from desire_platform.identity_access.application.policy_consent_commands import (
    AcceptCurrentPoliciesCommand,
    PolicyConsentCommandResult,
    PolicyRequirementReference,
    PolicyRequirementScopeType,
)
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.domain.policies import (
    ConsentOfferChoice,
    PolicyAcceptance,
    PolicyBundleStatus,
)
from tests.support.iam_policy_consent_command_builders import (
    ACTOR_USER_ID,
    ALPHA_BUNDLE_ID,
    ALPHA_SELECTOR_DIGEST,
    AUTH_TRANSACTION_ID,
    BETA_BUNDLE_ID,
    BETA_SELECTOR_DIGEST,
    CREATOR_BUNDLE_ID,
    CREATOR_SELECTOR_DIGEST,
    NOW,
    OLD_RECEIPT_IDENTITY_KEY_ID,
    OLD_RECEIPT_PAYLOAD_KEY_ID,
    ORGANIZATION_ALPHA_ID,
    ORGANIZATION_BETA_ID,
    OTHER_USER_ID,
    PILOT_NOT_AFTER,
    SESSION_FAMILY_ID,
    SESSION_ID,
    UNKNOWN_SELECTOR_DIGEST,
    contains_secret,
    creator_accept_command,
    expected_accept_body,
    expected_creator_accept_body,
    expected_existing_grant_body,
    expected_grant_body,
    policy_consent_command_fixture,
    seed_completed_receipt,
    seed_exact_active_grant,
)


def _observe(handler: Any, actor: Any, command: Any) -> dict[str, Any]:
    try:
        result = handler.handle(actor=actor, command=command)
    except IamError as error:
        return {"kind": "error", "code": error.code}
    return {
        "kind": "ok",
        "operation_id": result.operation_id,
        "replayed": result.replayed,
        "http_status": result.http_status,
        "body": result.body_copy(),
        "response_entity_tag": result.response_entity_tag,
        "current_user_entity_tag": result.current_user_entity_tag,
    }


def _error(code: str) -> dict[str, str]:
    return {"kind": "error", "code": code}


def _success(
    *,
    operation_id: str,
    http_status: int,
    body: Mapping[str, Any],
    response_entity_tag: str,
    current_user_entity_tag: str,
    replayed: bool = False,
) -> dict[str, Any]:
    return {
        "kind": "ok",
        "operation_id": operation_id,
        "replayed": replayed,
        "http_status": http_status,
        "body": deepcopy(dict(body)),
        "response_entity_tag": response_entity_tag,
        "current_user_entity_tag": current_user_entity_tag,
    }


def _event_types(snapshot: Mapping[str, Mapping[Any, Any]]) -> list[str]:
    return sorted(
        event.get("event_type", "")
        for event in snapshot.get("outbox_events", {}).values()
        if isinstance(event, Mapping)
    )


def _call_and_require_no_write(
    fixture: Any,
    *,
    handler: Any,
    command: Any,
) -> dict[str, Any]:
    before = fixture.store.snapshot()
    observation = _observe(handler, fixture.actor, command)
    if fixture.store.snapshot() != before:
        raise AssertionError("a rejected policy/consent command wrote partial state")
    return observation


class IamPolicyConsentCommandSemanticRedTests(unittest.TestCase):
    def test_command_values_are_immutable_secret_safe_and_handler_is_executable(self) -> None:
        fixture = policy_consent_command_fixture()

        with self.assertRaises(FrozenInstanceError):
            fixture.accept_command.expected_user_version = 99
        with self.assertRaises(FrozenInstanceError):
            fixture.grant_command.policy_bundle_id = ALPHA_BUNDLE_ID
        self.assertNotIn(fixture.accept_command.idempotency_key, repr(fixture.accept_command))
        self.assertNotIn(fixture.grant_command.idempotency_key, repr(fixture.grant_command))

        result = PolicyConsentCommandResult(
            operation_id="acceptCurrentPolicies",
            replayed=False,
            http_status=200,
            json_body={"safe": ["value"]},
            response_entity_tag='"v8"',
            current_user_entity_tag='"v8"',
        )
        copied = result.body_copy()
        copied["safe"].append("mutated")
        self.assertEqual(result.body_copy(), {"safe": ["value"]})
        self.assertNotIn("value", repr(result))

        observation = _observe(
            fixture.accept_handler,
            fixture.actor,
            fixture.accept_command,
        )
        self.assertEqual(observation.get("kind"), "ok")
        self.assertEqual(observation.get("operation_id"), "acceptCurrentPolicies")
        self.assertEqual(fixture.uow_factory.begin_count, 1)
        self.assertTrue(fixture.id_source.calls)

    def test_accept_selects_exact_beta_requirement_not_first_grant(self) -> None:
        fixture = policy_consent_command_fixture()
        observation = _observe(
            fixture.accept_handler,
            fixture.actor,
            fixture.accept_command,
        )
        snapshot = fixture.store.snapshot()
        checks = {
            "closed-result": (
                observation,
                _success(
                    operation_id="acceptCurrentPolicies",
                    http_status=200,
                    body=expected_accept_body(),
                    response_entity_tag='"v8"',
                    current_user_entity_tag='"v8"',
                ),
            ),
            "user-version-once": (
                snapshot["users"][ACTOR_USER_ID]["aggregate_version"],
                8,
            ),
            "one-new-acceptance": (len(snapshot["policy_acceptances"]), 3),
            "receipt-and-audit": (
                (len(snapshot["command_receipts"]), len(snapshot["audit_events"])),
                (1, 1),
            ),
            "closed-events": (
                _event_types(snapshot),
                ["PolicyAccepted", "PolicyRequirementsSatisfied"],
            ),
            "exact-beta-not-alpha": (
                observation.get("body"), expected_accept_body()
            ),
        }
        for name, (actual, expected) in checks.items():
            with self.subTest(check=name):
                self.assertEqual(actual, expected)

    def test_grant_uses_current_creator_requirement_and_derives_generic_null_scope(self) -> None:
        fixture = policy_consent_command_fixture()
        observation = _observe(
            fixture.grant_handler,
            fixture.actor,
            fixture.grant_command,
        )
        snapshot = fixture.store.snapshot()
        event_payloads = [
            event.get("payload")
            for event in snapshot["outbox_events"].values()
            if event.get("event_type") == "ConsentGranted"
        ]
        expected_derived = {
            "purpose": "PILOT_RESEARCH",
            "scope_type": "PLATFORM_PARTICIPATION",
            "scope_id": None,
            "data_categories": ["PROFILE", "MATCHING", "RESEARCH"],
        }
        derived = []
        for payload in event_payloads:
            authorization = payload.get("derived_authorization", {})
            derived.append(
                {
                    name: authorization.get(name)
                    for name in expected_derived
                }
            )
        checks = {
            "closed-result": (
                observation,
                _success(
                    operation_id="grantConsent",
                    http_status=201,
                    body=expected_grant_body(),
                    response_entity_tag='"v1"',
                    current_user_entity_tag='"v8"',
                ),
            ),
            "one-grant": (len(snapshot["consent_grants"]), 1),
            "user-version-once": (
                snapshot["users"][ACTOR_USER_ID]["aggregate_version"],
                8,
            ),
            "historical-policy-evidence-reused": (
                len(snapshot["policy_acceptances"]), 2
            ),
            "receipt-and-audit": (
                (len(snapshot["command_receipts"]), len(snapshot["audit_events"])),
                (1, 1),
            ),
            "one-consent-event": (_event_types(snapshot), ["ConsentGranted"]),
            "derived-scope": (derived, [expected_derived]),
        }
        for name, (actual, expected) in checks.items():
            with self.subTest(check=name):
                self.assertEqual(actual, expected)

    def test_authority_reference_is_exact_and_adjacent_authority_is_not_disclosed(self) -> None:
        cases: list[tuple[str, Any, Any, Any, str]] = []

        fixture = policy_consent_command_fixture()
        command = replace(
            fixture.accept_command,
            policy_requirement=replace(
                fixture.accept_command.policy_requirement,
                selector_digest=UNKNOWN_SELECTOR_DIGEST,
            ),
        )
        cases.append(("unknown-selector", fixture, fixture.accept_handler, command, "RESOURCE_NOT_FOUND"))

        fixture = policy_consent_command_fixture()
        command = replace(
            fixture.accept_command,
            policy_requirement=PolicyRequirementReference(
                selector_digest=ALPHA_SELECTOR_DIGEST,
                scope_type=PolicyRequirementScopeType.ORGANIZATION_ROLE,
                scope_id=ORGANIZATION_BETA_ID,
            ),
        )
        cases.append(("selector-scope-cross-product", fixture, fixture.accept_handler, command, "RESOURCE_NOT_FOUND"))

        fixture = policy_consent_command_fixture()
        fixture.store.replace_fact(
            "memberships", "membership_policy_beta_0002", status="SUSPENDED"
        )
        cases.append(("inactive-membership", fixture, fixture.accept_handler, fixture.accept_command, "RESOURCE_NOT_FOUND"))

        fixture = policy_consent_command_fixture()
        fixture.store.replace_fact(
            "membership_role_grants",
            "membership_role_grant_beta_0002",
            revoked_at=NOW - timedelta(seconds=1),
        )
        cases.append(("revoked-role", fixture, fixture.accept_handler, fixture.accept_command, "RESOURCE_NOT_FOUND"))

        fixture = policy_consent_command_fixture()
        fixture.store.replace_fact(
            "organizations", ORGANIZATION_BETA_ID, status="SUSPENDED"
        )
        cases.append(("inactive-organization", fixture, fixture.accept_handler, fixture.accept_command, "RESOURCE_NOT_FOUND"))

        fixture = policy_consent_command_fixture()
        fixture.store.replace_fact(
            "invitations", "invitation_beta_source_0002", status="REVOKED"
        )
        cases.append(("corrupt-source-invitation", fixture, fixture.accept_handler, fixture.accept_command, "POLICY_CONFIGURATION_UNAVAILABLE"))

        fixture = policy_consent_command_fixture()
        fixture.store.replace_fact(
            "membership_role_grants",
            "membership_role_grant_beta_0002",
            user_id=OTHER_USER_ID,
        )
        cases.append(("cross-user-role", fixture, fixture.accept_handler, fixture.accept_command, "RESOURCE_NOT_FOUND"))

        fixture = policy_consent_command_fixture()
        fixture.store.remove_fact("user_role_grants", "user_role_grant_creator_policy_0001")
        cases.append(("grant-without-creator-authority", fixture, fixture.grant_handler, fixture.grant_command, "RESOURCE_NOT_FOUND"))

        for name, fixture, handler, command, expected_code in cases:
            with self.subTest(case=name):
                self.assertEqual(
                    _call_and_require_no_write(
                        fixture,
                        handler=handler,
                        command=command,
                    ),
                    _error(expected_code),
                )

    def test_current_session_user_and_key_evidence_fail_closed_before_writes(self) -> None:
        cases: list[tuple[str, Any, Any, str]] = []

        fixture = policy_consent_command_fixture()
        fixture.store.replace_fact("session_families", SESSION_FAMILY_ID, status="REVOKED")
        cases.append(("revoked-family", fixture, fixture.accept_handler, "AUTHENTICATION_REQUIRED"))

        fixture = policy_consent_command_fixture()
        fixture.store.replace_fact("sessions", SESSION_ID, idle_expires_at=NOW)
        cases.append(("idle-deadline-equality", fixture, fixture.grant_handler, "SESSION_EXPIRED"))

        fixture = policy_consent_command_fixture()
        fixture.store.replace_fact("users", ACTOR_USER_ID, status="SUSPENDED")
        cases.append(("suspended-user", fixture, fixture.accept_handler, "AUTHENTICATION_REQUIRED"))

        fixture = policy_consent_command_fixture()
        fixture.store.replace_fact("auth_transactions", AUTH_TRANSACTION_ID, status="FAILED")
        cases.append(("failed-auth-transaction", fixture, fixture.grant_handler, "AUTHENTICATION_REQUIRED"))

        fixture = policy_consent_command_fixture()
        fixture.keyring.remove_key(fixture.keyring.payload_hash_key_id)
        cases.append(("active-receipt-key-unavailable", fixture, fixture.accept_handler, "SERVICE_UNAVAILABLE"))

        fixture = policy_consent_command_fixture()
        fixture.clock.current = NOW.replace(tzinfo=None)
        cases.append(("naive-server-clock", fixture, fixture.grant_handler, "SERVICE_UNAVAILABLE"))

        fixture = policy_consent_command_fixture()
        actor = replace(fixture.actor, actor_user_id=OTHER_USER_ID)
        before = fixture.store.snapshot()
        observation = _observe(fixture.accept_handler, actor, fixture.accept_command)
        self.assertEqual(fixture.store.snapshot(), before)
        cases.append(("cross-user-actor", fixture, fixture.accept_handler, "AUTHENTICATION_REQUIRED"))
        # Preserve the actor-specific observation instead of invoking the normal actor.
        with self.subTest(case="cross-user-actor"):
            self.assertEqual(observation, _error("AUTHENTICATION_REQUIRED"))

        for name, fixture, handler, expected_code in cases[:-1]:
            command = (
                fixture.accept_command
                if handler is fixture.accept_handler
                else fixture.grant_command
            )
            with self.subTest(case=name):
                self.assertEqual(
                    _call_and_require_no_write(
                        fixture,
                        handler=handler,
                        command=command,
                    ),
                    _error(expected_code),
                )

    def test_user_if_match_current_pointer_and_lock_race_are_not_guessed(self) -> None:
        cases: list[tuple[str, Any, AcceptCurrentPoliciesCommand, str]] = []

        fixture = policy_consent_command_fixture()
        cases.append(("stale-user-version", fixture, replace(fixture.accept_command, expected_user_version=6), "PRECONDITION_FAILED"))

        fixture = policy_consent_command_fixture()
        cases.append(("stale-presented-bundle", fixture, replace(fixture.accept_command, policy_bundle_id=ALPHA_BUNDLE_ID), "POLICY_BUNDLE_CHANGED"))

        fixture = policy_consent_command_fixture()
        fixture.store.replace_fact("policy_selectors", BETA_SELECTOR_DIGEST, current_bundle_id=None)
        cases.append(("missing-current-pointer", fixture, fixture.accept_command, "POLICY_CONFIGURATION_UNAVAILABLE"))

        fixture = policy_consent_command_fixture()
        fixture.store.replace_fact("policy_selectors", BETA_SELECTOR_DIGEST, current_bundle_id=ALPHA_BUNDLE_ID)
        cases.append(("pointer-to-other-selector", fixture, fixture.accept_command, "POLICY_CONFIGURATION_UNAVAILABLE"))

        fixture = policy_consent_command_fixture()
        bundle = fixture.store.snapshot()["policy_bundles"][BETA_BUNDLE_ID]
        fixture.store.set_fact(
            "policy_bundles",
            BETA_BUNDLE_ID,
            replace(bundle, effective_at=NOW + timedelta(seconds=1)),
        )
        cases.append(("future-current", fixture, fixture.accept_command, "POLICY_CONFIGURATION_UNAVAILABLE"))

        fixture = policy_consent_command_fixture()
        bundle = fixture.store.snapshot()["policy_bundles"][BETA_BUNDLE_ID]
        fixture.store.set_fact(
            "policy_bundles",
            BETA_BUNDLE_ID,
            replace(bundle, status=PolicyBundleStatus.SUPERSEDED),
        )
        cases.append(("non-active-current", fixture, fixture.accept_command, "POLICY_CONFIGURATION_UNAVAILABLE"))

        fixture = policy_consent_command_fixture()
        old_bundle = fixture.store.snapshot()["policy_bundles"][BETA_BUNDLE_ID]
        upgraded_id = "policy_bundle_org_beta_current_0002"
        upgraded = replace(
            old_bundle,
            policy_bundle_id=upgraded_id,
            release_manifest_sha256="9" * 64,
            publication_command_id="publication_beta_bundle_upgrade_0002",
            created_at=NOW,
            updated_at=NOW,
        )
        superseded = replace(
            old_bundle,
            status=PolicyBundleStatus.SUPERSEDED,
            effective_until=NOW,
            superseded_by_bundle_id=upgraded_id,
            updated_at=NOW,
        )

        def change_current_on_begin(_count: int) -> None:
            fixture.store.set_fact("policy_bundles", BETA_BUNDLE_ID, superseded)
            fixture.store.set_fact("policy_bundles", upgraded_id, upgraded)
            fixture.store.replace_fact(
                "policy_selectors", BETA_SELECTOR_DIGEST, current_bundle_id=upgraded_id
            )

        fixture.uow_factory.before_begin = change_current_on_begin
        with self.subTest(case="current-changes-before-lock"):
            self.assertEqual(
                _observe(
                    fixture.accept_handler,
                    fixture.actor,
                    fixture.accept_command,
                ),
                _error("POLICY_BUNDLE_CHANGED"),
            )
            self.assertEqual(fixture.uow_factory.write_values, [])
            self.assertEqual(fixture.uow_factory.write_checkpoints, [])
            raced_snapshot = fixture.store.snapshot()
            self.assertEqual(
                raced_snapshot["policy_selectors"][BETA_SELECTOR_DIGEST][
                    "current_bundle_id"
                ],
                upgraded_id,
            )
            self.assertEqual(
                raced_snapshot["policy_bundles"][BETA_BUNDLE_ID].status,
                PolicyBundleStatus.SUPERSEDED,
            )
            self.assertIn(upgraded_id, raced_snapshot["policy_bundles"])
            self.assertEqual(raced_snapshot["command_receipts"], {})
            self.assertEqual(raced_snapshot["audit_events"], {})
            self.assertEqual(raced_snapshot["outbox_events"], {})

        for name, fixture, command, expected_code in cases:
            with self.subTest(case=name):
                self.assertEqual(
                    _call_and_require_no_write(
                        fixture,
                        handler=fixture.accept_handler,
                        command=command,
                    ),
                    _error(expected_code),
                )

    def test_policy_and_offer_inputs_are_exact_closed_sets(self) -> None:
        cases: list[tuple[str, Any, Any, Any, str]] = []

        fixture = policy_consent_command_fixture()
        item = fixture.accept_command.policy_acceptances[0]
        cases.append(("duplicate-required-document", fixture, fixture.accept_handler, replace(fixture.accept_command, policy_acceptances=(item, item)), "INVALID_REQUEST"))

        fixture = policy_consent_command_fixture()
        cases.append(("missing-required-document", fixture, fixture.accept_handler, replace(fixture.accept_command, policy_acceptances=()), "POLICY_ACCEPTANCE_REQUIRED"))

        fixture = policy_consent_command_fixture()
        false_item = replace(fixture.accept_command.policy_acceptances[0], affirmed=False)
        cases.append(("non-affirmative-policy", fixture, fixture.accept_handler, replace(fixture.accept_command, policy_acceptances=(false_item,)), "POLICY_ACCEPTANCE_REQUIRED"))

        fixture = policy_consent_command_fixture()
        wrong_hash = replace(fixture.accept_command.policy_acceptances[0], content_sha256="0" * 64)
        cases.append(("wrong-policy-hash", fixture, fixture.accept_handler, replace(fixture.accept_command, policy_acceptances=(wrong_hash,)), "INVALID_REQUEST"))

        fixture = policy_consent_command_fixture()
        extra = PolicyAcceptance(
            document_id="policy_document_extra_unknown_0001",
            content_sha256="e" * 64,
            affirmed=True,
        )
        cases.append(("extra-policy-document", fixture, fixture.accept_handler, replace(fixture.accept_command, policy_acceptances=fixture.accept_command.policy_acceptances + (extra,)), "INVALID_REQUEST"))

        for field_name, changed_value in (
            ("consent_offer_id", "consent_offer_unknown_other_0002"),
            ("document_id", "policy_document_wrong_consent_0002"),
            ("content_sha256", "0" * 64),
            ("affirmed", False),
        ):
            fixture = policy_consent_command_fixture()
            choice = replace(fixture.grant_command.consent_choice, **{field_name: changed_value})
            cases.append((f"wrong-offer-{field_name}", fixture, fixture.grant_handler, replace(fixture.grant_command, consent_choice=choice), "INVALID_REQUEST"))

        fixture = policy_consent_command_fixture()
        fixture.store.remove_fact("policy_acceptances", "policy_acceptance_creator_privacy_0001")
        cases.append(("grant-missing-current-required-evidence", fixture, fixture.grant_handler, fixture.grant_command, "POLICY_ACCEPTANCE_REQUIRED"))

        fixture = policy_consent_command_fixture()
        fixture.clock.current = PILOT_NOT_AFTER
        fixture.store.replace_fact(
            "sessions",
            SESSION_ID,
            idle_expires_at=PILOT_NOT_AFTER + timedelta(minutes=30),
            absolute_expires_at=PILOT_NOT_AFTER + timedelta(hours=8),
        )
        cases.append(("offer-deadline-equality", fixture, fixture.grant_handler, fixture.grant_command, "INVALID_REQUEST"))

        fixture = policy_consent_command_fixture()
        bundle = fixture.store.snapshot()["policy_bundles"][CREATOR_BUNDLE_ID]
        corrupt_offer = deepcopy(bundle.consent_offers[0])
        object.__setattr__(corrupt_offer, "scope_type", "ORGANIZATION")
        corrupt_bundle = deepcopy(bundle)
        object.__setattr__(corrupt_bundle, "consent_offers", (corrupt_offer,))
        fixture.store.set_fact("policy_bundles", CREATOR_BUNDLE_ID, corrupt_bundle)
        cases.append(("unsupported-published-scope", fixture, fixture.grant_handler, fixture.grant_command, "POLICY_CONFIGURATION_UNAVAILABLE"))

        for name, fixture, handler, command, expected_code in cases:
            with self.subTest(case=name):
                self.assertEqual(
                    _call_and_require_no_write(
                        fixture,
                        handler=handler,
                        command=command,
                    ),
                    _error(expected_code),
                )

    def test_historical_acceptance_and_exact_active_grant_are_reused_without_extension(self) -> None:
        fixture = policy_consent_command_fixture()
        command = creator_accept_command(fixture)
        accept_observation = _observe(fixture.accept_handler, fixture.actor, command)
        accept_snapshot = fixture.store.snapshot()
        accept_checks = {
            "historical-source-success": (
                accept_observation,
                _success(
                    operation_id="acceptCurrentPolicies",
                    http_status=200,
                    body=expected_creator_accept_body(),
                    response_entity_tag='"v7"',
                    current_user_entity_tag='"v7"',
                ),
            ),
            "no-new-acceptance": (len(accept_snapshot["policy_acceptances"]), 2),
            "no-user-version-change": (
                accept_snapshot["users"][ACTOR_USER_ID]["aggregate_version"], 7
            ),
            "no-duplicate-events": (_event_types(accept_snapshot), []),
            "receipt-audit-only": (
                (len(accept_snapshot["command_receipts"]), len(accept_snapshot["audit_events"])),
                (1, 1),
            ),
        }
        for name, (actual, expected) in accept_checks.items():
            with self.subTest(accept_reuse=name):
                self.assertEqual(actual, expected)

        fixture = policy_consent_command_fixture()
        existing = seed_exact_active_grant(fixture)
        grant_observation = _observe(fixture.grant_handler, fixture.actor, fixture.grant_command)
        grant_snapshot = fixture.store.snapshot()
        grant_checks = {
            "exact-grant-result": (
                grant_observation,
                _success(
                    operation_id="grantConsent",
                    http_status=201,
                    body=expected_existing_grant_body(existing),
                    response_entity_tag='"v1"',
                    current_user_entity_tag='"v7"',
                ),
            ),
            "one-existing-grant": (len(grant_snapshot["consent_grants"]), 1),
            "deadline-not-extended": (
                grant_snapshot["consent_grants"][existing["consent_grant_id"]]["expires_at"],
                existing["expires_at"],
            ),
            "no-user-version-change": (
                grant_snapshot["users"][ACTOR_USER_ID]["aggregate_version"], 7
            ),
            "no-duplicate-events": (_event_types(grant_snapshot), []),
            "receipt-audit-only": (
                (len(grant_snapshot["command_receipts"]), len(grant_snapshot["audit_events"])),
                (1, 1),
            ),
        }
        for name, (actual, expected) in grant_checks.items():
            with self.subTest(grant_reuse=name):
                self.assertEqual(actual, expected)

        fixture = policy_consent_command_fixture()
        seed_exact_active_grant(
            fixture,
            recipient_reference="another-internal-recipient-reference",
        )
        with self.subTest(grant_reuse="conflicting-active-authority"):
            self.assertEqual(
                _call_and_require_no_write(
                    fixture,
                    handler=fixture.grant_handler,
                    command=fixture.grant_command,
                ),
                _error("INVALID_STATE_TRANSITION"),
            )

        fixture = policy_consent_command_fixture()
        old = seed_exact_active_grant(
            fixture,
            grant_id="consent_grant_expired_history_0001",
            granted_at=NOW - timedelta(days=365),
            expires_at=NOW,
        )
        expired_observation = _observe(
            fixture.grant_handler, fixture.actor, fixture.grant_command
        )
        expired_snapshot = fixture.store.snapshot()
        expired_checks = {
            "new-grant-created": (
                expired_observation,
                _success(
                    operation_id="grantConsent",
                    http_status=201,
                    body=expected_grant_body(),
                    response_entity_tag='"v1"',
                    current_user_entity_tag='"v8"',
                ),
            ),
            "history-plus-new": (len(expired_snapshot["consent_grants"]), 2),
            "old-materialized-expired": (
                expired_snapshot["consent_grants"][old["consent_grant_id"]]["status"],
                "EXPIRED",
            ),
            "one-new-event": (_event_types(expired_snapshot), ["ConsentGranted"]),
        }
        for name, (actual, expected) in expired_checks.items():
            with self.subTest(expired_regrant=name):
                self.assertEqual(actual, expected)

    def test_completed_receipt_replay_is_bound_keyed_and_still_authenticates_session(self) -> None:
        fixture = policy_consent_command_fixture()
        seed_completed_receipt(
            fixture,
            command=fixture.accept_command,
            response_body=expected_accept_body(),
            response_entity_tag='"v8"',
            current_user_entity_tag='"v8"',
        )
        before = fixture.store.snapshot()
        replay = _observe(fixture.accept_handler, fixture.actor, fixture.accept_command)
        checks = {
            "exact-replay": (
                replay,
                _success(
                    operation_id="acceptCurrentPolicies",
                    http_status=200,
                    body=expected_accept_body(),
                    response_entity_tag='"v8"',
                    current_user_entity_tag='"v8"',
                    replayed=True,
                ),
            ),
            "zero-replay-write": (fixture.store.snapshot(), before),
            "zero-uow": (fixture.uow_factory.begin_count, 0),
        }
        for name, (actual, expected) in checks.items():
            with self.subTest(case=name):
                self.assertEqual(actual, expected)

        fixture = policy_consent_command_fixture()
        seed_completed_receipt(
            fixture,
            command=fixture.accept_command,
            response_body=expected_accept_body(),
            response_entity_tag='"v8"',
            current_user_entity_tag='"v8"',
        )
        changed = replace(fixture.accept_command, policy_bundle_id=ALPHA_BUNDLE_ID)
        with self.subTest(case="same-key-different-payload"):
            self.assertEqual(
                _call_and_require_no_write(
                    fixture,
                    handler=fixture.accept_handler,
                    command=changed,
                ),
                _error("IDEMPOTENCY_KEY_REUSED"),
            )

        fixture = policy_consent_command_fixture()
        seed_completed_receipt(
            fixture,
            command=fixture.grant_command,
            response_body=expected_grant_body(grant_id="consent_grant_receipt_replay_0001"),
            response_entity_tag='"v1"',
            current_user_entity_tag='"v8"',
            identity_key_id=OLD_RECEIPT_IDENTITY_KEY_ID,
            payload_key_id=OLD_RECEIPT_PAYLOAD_KEY_ID,
        )
        fixture.restart_handlers()
        with self.subTest(case="retained-old-keys-after-restart"):
            self.assertEqual(
                _observe(fixture.grant_handler, fixture.actor, fixture.grant_command),
                _success(
                    operation_id="grantConsent",
                    http_status=201,
                    body=expected_grant_body(grant_id="consent_grant_receipt_replay_0001"),
                    response_entity_tag='"v1"',
                    current_user_entity_tag='"v8"',
                    replayed=True,
                ),
            )

        fixture.keyring.remove_key(OLD_RECEIPT_PAYLOAD_KEY_ID)
        fixture.restart_handlers()
        with self.subTest(case="missing-retained-payload-key"):
            self.assertEqual(
                _call_and_require_no_write(
                    fixture,
                    handler=fixture.grant_handler,
                    command=fixture.grant_command,
                ),
                _error("SERVICE_UNAVAILABLE"),
            )

        fixture = policy_consent_command_fixture()
        receipt = seed_completed_receipt(
            fixture,
            command=fixture.accept_command,
            response_body={**expected_accept_body(), "scope_id": ORGANIZATION_ALPHA_ID},
            response_entity_tag='"v8"',
            current_user_entity_tag='"v8"',
        )
        fixture.store.set_fact("command_receipts", receipt["command_receipt_id"], receipt)
        with self.subTest(case="receipt-response-wrong-scope-binding"):
            self.assertEqual(
                _call_and_require_no_write(
                    fixture,
                    handler=fixture.accept_handler,
                    command=fixture.accept_command,
                ),
                _error("SERVICE_UNAVAILABLE"),
            )

        fixture = policy_consent_command_fixture()
        seed_completed_receipt(
            fixture,
            command=fixture.accept_command,
            response_body=expected_accept_body(),
            response_entity_tag='"v8"',
            current_user_entity_tag='"v8"',
        )
        fixture.store.replace_fact("session_families", SESSION_FAMILY_ID, status="REVOKED")
        with self.subTest(case="replay-still-requires-current-session"):
            self.assertEqual(
                _call_and_require_no_write(
                    fixture,
                    handler=fixture.accept_handler,
                    command=fixture.accept_command,
                ),
                _error("AUTHENTICATION_REQUIRED"),
            )

    def test_each_write_fault_rolls_back_and_commit_unknown_is_not_retried(self) -> None:
        checkpoint_cases = {
            "accept": (
                (
                    "accept.receipt_in_progress",
                    "accept.policy_acceptance.0001",
                    "accept.user",
                    "accept.audit",
                    "accept.outbox.policy_accepted.0001",
                    "accept.outbox.requirements_satisfied",
                    "accept.receipt_completed",
                ),
                "accept_handler",
                "accept_command",
            ),
            "grant": (
                (
                    "grant.receipt_in_progress",
                    "grant.consent_grant",
                    "grant.user",
                    "grant.audit",
                    "grant.outbox.consent_granted",
                    "grant.receipt_completed",
                ),
                "grant_handler",
                "grant_command",
            ),
        }
        for operation, (checkpoints, handler_name, command_name) in checkpoint_cases.items():
            for checkpoint in checkpoints:
                fixture = policy_consent_command_fixture(fail_on_checkpoint=checkpoint)
                before = fixture.store.snapshot()
                observation = _observe(
                    getattr(fixture, handler_name),
                    fixture.actor,
                    getattr(fixture, command_name),
                )
                with self.subTest(operation=operation, checkpoint=checkpoint, assertion="error"):
                    self.assertEqual(observation, _error("SERVICE_UNAVAILABLE"))
                with self.subTest(operation=operation, checkpoint=checkpoint, assertion="rollback"):
                    self.assertEqual(fixture.store.snapshot(), before)

        for commit_mode, expected_code in (
            ("unavailable", "SERVICE_UNAVAILABLE"),
            ("unknown_not_landed", "COMMAND_OUTCOME_UNKNOWN"),
            ("unknown_landed", "COMMAND_OUTCOME_UNKNOWN"),
        ):
            fixture = policy_consent_command_fixture(commit_mode=commit_mode)
            observation = _observe(
                fixture.grant_handler,
                fixture.actor,
                fixture.grant_command,
            )
            with self.subTest(commit_mode=commit_mode, assertion="error"):
                self.assertEqual(observation, _error(expected_code))
            with self.subTest(commit_mode=commit_mode, assertion="one-commit"):
                self.assertEqual(fixture.uow_factory.commit_count, 1)

    def test_closed_events_audit_receipt_and_telemetry_never_leak_secret_facts(self) -> None:
        fixture = policy_consent_command_fixture()
        beta_bundle = fixture.store.snapshot()["policy_bundles"][BETA_BUNDLE_ID]
        document = beta_bundle.documents[0]
        envelope = {
            "schema_version": 1,
            "occurred_at": NOW.isoformat().replace("+00:00", "Z"),
            "actor_kind": "USER",
            "actor_id": ACTOR_USER_ID,
            "original_actor_id": None,
            "correlation_id": fixture.actor.correlation_id,
            "causation_id": "command_receipt_policy_consent_0001",
            "trace_id": fixture.actor.trace_id,
        }
        events = (
            {
                **envelope,
                "event_id": "outbox_policy_accepted_0001",
                "event_type": "PolicyAccepted",
                "aggregate_type": "PolicyAcceptance",
                "aggregate_id": "policy_acceptance_new_beta_0001",
                "aggregate_version": 1,
                "organization_id": ORGANIZATION_BETA_ID,
                "payload": {
                    "policy_acceptance_id": "policy_acceptance_new_beta_0001",
                    "user_id": ACTOR_USER_ID,
                    "policy_bundle_id": BETA_BUNDLE_ID,
                    "policy_document_id": document.document_id,
                    "policy_document_sha256": document.content_sha256,
                    "legal_effect": document.legal_effect.value,
                },
            },
            {
                **envelope,
                "event_id": "outbox_requirement_satisfied_0001",
                "event_type": "PolicyRequirementsSatisfied",
                "aggregate_type": "User",
                "aggregate_id": ACTOR_USER_ID,
                "aggregate_version": 8,
                "organization_id": ORGANIZATION_BETA_ID,
                "payload": {
                    "user_id": ACTOR_USER_ID,
                    "policy_bundle_id": BETA_BUNDLE_ID,
                },
            },
        )
        for event in events:
            with self.subTest(event_type=event["event_type"]):
                fixture.event_validator.validate(event)
                self.assertFalse(contains_secret(event))

        accept_fixture = policy_consent_command_fixture()
        accept_result = _observe(
            accept_fixture.accept_handler,
            accept_fixture.actor,
            accept_fixture.accept_command,
        )
        grant_fixture = policy_consent_command_fixture()
        grant_result = _observe(
            grant_fixture.grant_handler,
            grant_fixture.actor,
            grant_fixture.grant_command,
        )
        for name, active_fixture, result in (
            ("accept", accept_fixture, accept_result),
            ("grant", grant_fixture, grant_result),
        ):
            writes = active_fixture.uow_factory.write_values
            with self.subTest(operation=name, assertion="semantic-success"):
                self.assertEqual(result.get("kind"), "ok")
            with self.subTest(operation=name, assertion="instrumented-writes"):
                self.assertTrue(writes)
            with self.subTest(operation=name, assertion="secret-free-result"):
                self.assertFalse(contains_secret(result))
            with self.subTest(operation=name, assertion="secret-free-writes"):
                self.assertFalse(contains_secret(writes))
            with self.subTest(operation=name, assertion="schema-validation-used"):
                self.assertGreater(
                    len(active_fixture.event_validator.calls)
                    + len(active_fixture.response_validator.calls),
                    0,
                )


if __name__ == "__main__":
    unittest.main()
