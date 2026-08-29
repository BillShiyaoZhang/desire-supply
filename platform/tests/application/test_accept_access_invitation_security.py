"""Security/contract TDD regression tests for AcceptAccessInvitation.

The primary application tests prove the happy-path transaction.  This module
closes replay, exact-binding, fault-instrumentation, outbox-envelope, and safe
response gaps without adding behavior to the production handler.
"""

from __future__ import annotations

from datetime import timedelta
import inspect
import json
from pathlib import Path
import re
from typing import Any, Callable, Mapping, Sequence
import unittest

import yaml

from desire_platform.identity_access.adapters.memory import FaultInjector
from desire_platform.identity_access.application.access_invitations import ActorContext
from desire_platform.identity_access.domain.errors import IamError
from tests.support.iam_application_builders import (
    AcceptanceFixture,
    creator_acceptance_fixture,
    initial_admin_acceptance_fixture,
    policy_bundle_fixture,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[2]
EVENT_SCHEMA_PATH = PLATFORM_ROOT / "contracts" / "events" / "iam-v1.schema.json"
OPENAPI_PATH = PLATFORM_ROOT / "contracts" / "api" / "iam-v1.openapi.yaml"


class _ContractAssertion:
    """Small assertion adapter for the JSON-Schema vocabulary used here.

    It deliberately validates only selected concrete schemas rather than
    attempting to replace a general Draft 2020-12 implementation.  The covered
    keywords are the ones used by the IAM acceptance DTO and emitted events.
    """

    def __init__(self, case: unittest.TestCase, document: Mapping[str, Any]) -> None:
        self.case = case
        self.document = document

    def assert_valid(self, instance: Any, schema: Mapping[str, Any], path: str = "$") -> None:
        reference = schema.get("$ref")
        if reference is not None:
            self.assert_valid(instance, self._resolve(reference), path)

        for index, child in enumerate(schema.get("allOf", ())):
            self.assert_valid(instance, child, f"{path}.allOf[{index}]")

        if "oneOf" in schema:
            matches = 0
            errors = []
            for child in schema["oneOf"]:
                try:
                    self.assert_valid(instance, child, path)
                except AssertionError as error:
                    errors.append(str(error))
                else:
                    matches += 1
            self.case.assertEqual(
                matches,
                1,
                f"{path}: expected exactly one oneOf match; errors={errors}",
            )

        if "const" in schema:
            self.case.assertEqual(instance, schema["const"], f"{path}: const")
        if "enum" in schema:
            self.case.assertIn(instance, schema["enum"], f"{path}: enum")

        expected_type = schema.get("type")
        if expected_type == "object":
            self.case.assertIsInstance(instance, dict, f"{path}: object")
        elif expected_type == "array":
            self.case.assertIsInstance(instance, list, f"{path}: array")
        elif expected_type == "string":
            self.case.assertIsInstance(instance, str, f"{path}: string")
        elif expected_type == "integer":
            self.case.assertIsInstance(instance, int, f"{path}: integer")
            self.case.assertNotIsInstance(instance, bool, f"{path}: integer")
        elif expected_type == "boolean":
            self.case.assertIsInstance(instance, bool, f"{path}: boolean")
        elif expected_type == "null":
            self.case.assertIsNone(instance, f"{path}: null")

        object_keywords = {"required", "properties", "additionalProperties"}
        if isinstance(instance, dict) and object_keywords.intersection(schema):
            required = set(schema.get("required", ()))
            self.case.assertLessEqual(required, set(instance), f"{path}: required")
            properties = schema.get("properties", {})
            if schema.get("additionalProperties") is False:
                self.case.assertLessEqual(
                    set(instance),
                    set(properties),
                    f"{path}: additional properties",
                )
            for name, child in properties.items():
                if name in instance:
                    self.assert_valid(instance[name], child, f"{path}.{name}")

        if isinstance(instance, list):
            if "minItems" in schema:
                self.case.assertGreaterEqual(len(instance), schema["minItems"], path)
            if "maxItems" in schema:
                self.case.assertLessEqual(len(instance), schema["maxItems"], path)
            if schema.get("uniqueItems"):
                encoded = [
                    json.dumps(item, sort_keys=True, separators=(",", ":"))
                    for item in instance
                ]
                self.case.assertEqual(len(encoded), len(set(encoded)), f"{path}: unique")
            for index, item in enumerate(instance):
                self.assert_valid(item, schema.get("items", {}), f"{path}[{index}]")

        if isinstance(instance, str):
            if "minLength" in schema:
                self.case.assertGreaterEqual(len(instance), schema["minLength"], path)
            if "maxLength" in schema:
                self.case.assertLessEqual(len(instance), schema["maxLength"], path)
            if "pattern" in schema:
                self.case.assertRegex(instance, re.compile(schema["pattern"]), path)
            if schema.get("format") == "date-time":
                # The event contract additionally carries an explicit Z pattern.
                # This check excludes arbitrary strings even where OpenAPI only
                # declares the standard date-time format.
                normalized = instance[:-1] + "+00:00" if instance.endswith("Z") else instance
                from datetime import datetime

                try:
                    datetime.fromisoformat(normalized)
                except ValueError as error:
                    self.case.fail(f"{path}: invalid date-time: {error}")

        if isinstance(instance, int) and not isinstance(instance, bool):
            if "minimum" in schema:
                self.case.assertGreaterEqual(instance, schema["minimum"], path)
            if "maximum" in schema:
                self.case.assertLessEqual(instance, schema["maximum"], path)

        condition = schema.get("if")
        if condition is not None and self._matches(instance, condition):
            self.assert_valid(instance, schema.get("then", {}), f"{path}.then")

    def _matches(self, instance: Any, schema: Mapping[str, Any]) -> bool:
        try:
            self.assert_valid(instance, schema)
        except AssertionError:
            return False
        return True

    def _resolve(self, reference: str) -> Mapping[str, Any]:
        self.case.assertTrue(reference.startswith("#/"), reference)
        current: Any = self.document
        for encoded in reference[2:].split("/"):
            part = encoded.replace("~1", "/").replace("~0", "~")
            self.case.assertIsInstance(current, dict, reference)
            self.case.assertIn(part, current, reference)
            current = current[part]
        self.case.assertIsInstance(current, dict, reference)
        return current


class AcceptAccessInvitationSecurityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.event_contract = json.loads(EVENT_SCHEMA_PATH.read_text(encoding="utf-8"))
        cls.openapi = yaml.safe_load(OPENAPI_PATH.read_text(encoding="utf-8"))

    def test_completed_receipt_replay_requires_same_active_user_and_session(self) -> None:
        """Receipt recovery cannot bypass current principal and status checks."""

        cases = (
            ("other-active-user", self._other_user_replay_case, {"ACCESS_INVITATION_UNAVAILABLE"}),
            (
                "same-suspended-user",
                self._suspended_user_replay_case,
                {"AUTHENTICATION_REQUIRED", "ACCESS_INVITATION_UNAVAILABLE"},
            ),
            ("unknown-session", self._unknown_session_replay_case, {"AUTHENTICATION_REQUIRED"}),
        )
        for name, prepare, expected_codes in cases:
            with self.subTest(case=name):
                fixture, actor = prepare()
                self._assert_fails_without_writes_or_hold(
                    fixture,
                    actor,
                    expected_codes=expected_codes,
                )

    def test_exact_binding_and_current_policy_fail_before_authorization(self) -> None:
        """Invitation/contact/auth evidence and selector mismatches leave zero facts."""

        cases: Sequence[tuple[str, Callable[[AcceptanceFixture], None], set[str]]] = (
            (
                "session-other-invitation",
                lambda fixture: self._replace_session(
                    fixture,
                    verified_for_invitation_id="access_invitation_other_002",
                ),
                {"ACCESS_INVITATION_BINDING_MISMATCH", "ACCESS_INVITATION_UNAVAILABLE"},
            ),
            (
                "session-other-contact",
                self._bind_session_to_other_verified_contact,
                {"ACCESS_INVITATION_BINDING_MISMATCH", "ACCESS_INVITATION_UNAVAILABLE"},
            ),
            (
                "auth-transaction-other-version",
                lambda fixture: self._replace_auth_transaction(
                    fixture,
                    invitation_version=fixture.command.expected_version + 1,
                ),
                {"ACCESS_INVITATION_BINDING_MISMATCH", "ACCESS_INVITATION_UNAVAILABLE"},
            ),
            (
                "superseded-current-policy-selector",
                self._replace_current_policy_selector,
                {"POLICY_BUNDLE_CHANGED"},
            ),
        )
        for name, mutate, expected_codes in cases:
            with self.subTest(case=name):
                fixture = creator_acceptance_fixture()
                mutate(fixture)
                self._assert_fails_without_writes_or_hold(
                    fixture,
                    fixture.actor,
                    expected_codes=expected_codes,
                )

    def test_fault_injector_records_every_stable_semantic_checkpoint(self) -> None:
        """The rollback sweep cannot turn green with an uninstrumented fact write."""

        cases = (
            (creator_acceptance_fixture, self._creator_checkpoints()),
            (initial_admin_acceptance_fixture, self._initial_admin_checkpoints()),
        )
        for factory, expected in cases:
            with self.subTest(factory=factory.__name__):
                fixture = factory()
                fixture.handler.handle(actor=fixture.actor, command=fixture.command)
                actual = tuple(
                    getattr(fixture.fault_injector, "checkpoint_names", ())
                )
                self.assertEqual(actual, expected)
                self.assertEqual(fixture.fault_injector.write_count, len(expected))
                self.assertEqual(len(actual), len(set(actual)))

    def test_each_named_checkpoint_can_inject_an_atomic_rollback(self) -> None:
        """Every required checkpoint is independently addressable by stable name."""

        self.assertIn(
            "fail_on_checkpoint",
            inspect.signature(FaultInjector).parameters,
            "FaultInjector needs named failure injection; ordinal-only faults hide missing writes",
        )
        for checkpoint in self._creator_checkpoints():
            with self.subTest(checkpoint=checkpoint):
                injector = FaultInjector(fail_on_checkpoint=checkpoint)
                fixture = creator_acceptance_fixture(fault_injector=injector)
                before = fixture.store.snapshot()
                with self.assertRaises(RuntimeError):
                    fixture.handler.handle(actor=fixture.actor, command=fixture.command)
                self.assertEqual(fixture.store.snapshot(), before)
                self.assertEqual(injector.checkpoint_names[-1], checkpoint)

    def test_outbox_events_conform_to_closed_machine_contract_without_secrets(self) -> None:
        """Every accept fact carries its exact safe payload and full v1 envelope."""

        for factory in (creator_acceptance_fixture, initial_admin_acceptance_fixture):
            with self.subTest(factory=factory.__name__):
                fixture = factory()
                result = fixture.handler.handle(
                    actor=fixture.actor,
                    command=fixture.command,
                )
                events = list(fixture.store.snapshot()["outbox_events"].values())
                self.assertTrue(events)
                validator = _ContractAssertion(self, self.event_contract)
                for event in events:
                    definition = self._event_definition(event)
                    validator.assert_valid(
                        event,
                        {"$ref": f"#/$defs/{definition}"},
                        f"outbox.{event.get('event_id', '<missing>')}",
                    )
                    self._assert_event_has_no_onboarding_secret(event, fixture, result)

    def test_safe_response_matches_access_invitation_acceptance_dto(self) -> None:
        """Receipt-safe JSON is exactly the public OpenAPI acceptance projection."""

        schema = self.openapi["components"]["schemas"][
            "AccessInvitationAcceptanceDto"
        ]
        for factory in (creator_acceptance_fixture, initial_admin_acceptance_fixture):
            with self.subTest(factory=factory.__name__):
                fixture = factory()
                result = fixture.handler.handle(
                    actor=fixture.actor,
                    command=fixture.command,
                )
                _ContractAssertion(self, self.openapi).assert_valid(
                    result.safe_response,
                    schema,
                    "safe_response",
                )
                self.assertEqual(
                    result.safe_response["invitation"]["invitation_id"],
                    fixture.ids.invitation_id,
                )
                self.assertEqual(
                    result.safe_response["invitation"]["status"],
                    "ACCEPTED",
                )
                self.assertEqual(
                    result.safe_response["me"]["user_id"],
                    fixture.ids.user_id,
                )
                self.assertEqual(result.safe_response["me"]["status"], "ACTIVE")
                self._assert_no_secret_names_or_values(
                    result.safe_response,
                    fixture,
                    result,
                )

    def _other_user_replay_case(self) -> tuple[AcceptanceFixture, ActorContext]:
        fixture = creator_acceptance_fixture()
        fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        user_id = "user_other_active_0002"
        family_id = "session_family_other_0002"
        session_id = "session_other_active_0002"
        fixture.store.seed(
            users={
                user_id: {
                    "user_id": user_id,
                    "status": "ACTIVE",
                    "aggregate_version": 2,
                    "stable_handle": "other-active-user",
                }
            },
            session_families={
                family_id: {
                    "session_family_id": family_id,
                    "user_id": user_id,
                    "status": "ACTIVE",
                    "current_generation": 1,
                    "aggregate_version": 1,
                }
            },
            sessions={
                session_id: {
                    "session_id": session_id,
                    "session_family_id": family_id,
                    "user_id": user_id,
                    "generation": 1,
                    "predecessor_session_id": None,
                    "status": "ACTIVE",
                    "verified_contact_point_id": None,
                    "verified_for_invitation_id": None,
                    "auth_transaction_id": None,
                    "auth_time": fixture.clock.now() - timedelta(minutes=2),
                    "acr_code": "urn:desire:acr:mfa",
                    "amr_codes": ("pwd", "otp"),
                    "created_at": fixture.clock.now() - timedelta(minutes=2),
                    "last_activity_at": fixture.clock.now() - timedelta(minutes=1),
                    "idle_expires_at": fixture.clock.now() + timedelta(minutes=29),
                    "absolute_expires_at": fixture.clock.now() + timedelta(hours=8),
                    "updated_at": fixture.clock.now(),
                    "handle_digest": "digest-only-other-active-session",
                    "handle_digest_key_id": (
                        fixture.keyring.session_handle_digest_key_id
                    ),
                    "csrf_salt": b"s" * 32,
                    "csrf_key_id": fixture.keyring.csrf_key_id,
                    "csrf_digest": "digest-only-other-active-csrf",
                    "rotation_reason": "OIDC_LOGIN",
                    "aggregate_version": 1,
                }
            },
        )
        return fixture, ActorContext(
            actor_id=user_id,
            session_id=session_id,
            original_actor_id=None,
            correlation_id="correlation_other_0002",
            causation_id="causation_other_0002",
            trace_id="trace_other_user_0002",
        )

    def _suspended_user_replay_case(self) -> tuple[AcceptanceFixture, ActorContext]:
        fixture = creator_acceptance_fixture()
        fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        actor = fixture.seed_fresh_unbound_login()
        user = dict(fixture.store.snapshot()["users"][fixture.ids.user_id])
        user["status"] = "SUSPENDED"
        user["aggregate_version"] += 1
        fixture.store.seed(users={fixture.ids.user_id: user})
        return fixture, actor

    def _unknown_session_replay_case(self) -> tuple[AcceptanceFixture, ActorContext]:
        fixture = creator_acceptance_fixture()
        fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        return fixture, fixture.actor_for_session("session_unknown_replay_0099")

    def _assert_fails_without_writes_or_hold(
        self,
        fixture: AcceptanceFixture,
        actor: ActorContext,
        *,
        expected_codes: set[str],
    ) -> None:
        before = fixture.store.snapshot()
        writes_before = fixture.fault_injector.write_count
        hold_calls_before = len(fixture.hold.calls)
        with self.assertRaises(IamError) as raised:
            fixture.handler.handle(actor=actor, command=fixture.command)
        self.assertIn(raised.exception.code, expected_codes)
        self.assertEqual(fixture.store.snapshot(), before)
        self.assertEqual(fixture.fault_injector.write_count, writes_before)
        self.assertEqual(len(fixture.hold.calls), hold_calls_before)

    def _replace_session(self, fixture: AcceptanceFixture, **changes: Any) -> None:
        session = dict(fixture.store.snapshot()["sessions"][fixture.ids.session_id])
        session.update(changes)
        fixture.store.seed(sessions={fixture.ids.session_id: session})

    def _replace_auth_transaction(
        self, fixture: AcceptanceFixture, **changes: Any
    ) -> None:
        transaction = dict(
            fixture.store.snapshot()["auth_transactions"][
                fixture.ids.auth_transaction_id
            ]
        )
        transaction.update(changes)
        fixture.store.seed(
            auth_transactions={fixture.ids.auth_transaction_id: transaction}
        )

    def _bind_session_to_other_verified_contact(
        self, fixture: AcceptanceFixture
    ) -> None:
        other_contact_id = "contact_same_digest_0002"
        fixture.store.seed(
            contact_points={
                other_contact_id: {
                    "contact_point_id": other_contact_id,
                    "user_id": fixture.ids.user_id,
                    "type": "EMAIL",
                    "status": "VERIFIED",
                    "blind_digest": "same-synthetic-digest-does-not-authorize",
                }
            }
        )
        self._replace_session(
            fixture,
            verified_contact_point_id=other_contact_id,
        )

    def _replace_current_policy_selector(self, fixture: AcceptanceFixture) -> None:
        now = fixture.clock.now()
        selector = (
            fixture.invitation.purpose.value,
            fixture.invitation.target_role.value,
        )
        selector_fact = dict(
            fixture.store.snapshot()["policy_selectors"][
                fixture.policy_selector_digest
            ]
        )
        selector_fact["current_bundle_id"] = fixture.ids.current_policy_bundle_id
        selector_fact["aggregate_version"] += 1
        fixture.store.seed(
            policy_bundles={
                fixture.ids.policy_bundle_id: policy_bundle_fixture(
                    fixture.ids,
                    policy_bundle_id=fixture.ids.policy_bundle_id,
                    selector_digest=fixture.policy_selector_digest,
                    status="SUPERSEDED",
                    effective_at=now - timedelta(days=2),
                    effective_until=now,
                ),
                fixture.ids.current_policy_bundle_id: policy_bundle_fixture(
                    fixture.ids,
                    policy_bundle_id=fixture.ids.current_policy_bundle_id,
                    selector_digest=fixture.policy_selector_digest,
                    status="ACTIVE",
                    effective_at=now,
                    effective_until=None,
                ),
            },
            policy_selectors={
                fixture.policy_selector_digest: selector_fact,
            },
            current_policy_bundles={
                selector: fixture.ids.current_policy_bundle_id,
            },
        )

    @staticmethod
    def _creator_checkpoints() -> tuple[str, ...]:
        return (
            "command_receipt.pending",
            "policy_acceptance.0",
            "policy_acceptance.1",
            "consent_grant.0",
            "user.activate",
            "user_role_grant.create",
            "access_invitation.accept",
            "session.predecessor.revoke",
            "session_family.rotate",
            "session.successor.create",
            "audit_event.succeeded",
            "outbox.PolicyAccepted.0",
            "outbox.PolicyAccepted.1",
            "outbox.ConsentGranted.0",
            "outbox.UserActivated.0",
            "outbox.UserRoleGranted.0",
            "outbox.AccessInvitationAccepted.0",
            "command_receipt.complete",
        )

    @staticmethod
    def _initial_admin_checkpoints() -> tuple[str, ...]:
        return (
            "command_receipt.pending",
            "policy_acceptance.0",
            "policy_acceptance.1",
            "user.activate",
            "membership.activate",
            "membership_role_grant.create",
            "organization.activate",
            "access_invitation.accept",
            "session.predecessor.revoke",
            "session_family.rotate",
            "session.successor.create",
            "audit_event.succeeded",
            "outbox.PolicyAccepted.0",
            "outbox.PolicyAccepted.1",
            "outbox.UserActivated.0",
            "outbox.MembershipActivated.0",
            "outbox.MembershipRoleGranted.0",
            "outbox.OrganizationActivated.0",
            "outbox.AccessInvitationAccepted.0",
            "command_receipt.complete",
        )

    @staticmethod
    def _event_definition(event: Mapping[str, Any]) -> str:
        event_type = event.get("event_type")
        if event_type == "AccessInvitationAccepted":
            return (
                "CreatorAccessInvitationAcceptedEvent"
                if event.get("organization_id") is None
                else "OrganizationAccessInvitationAcceptedEvent"
            )
        definitions = {
            "PolicyAccepted": "PolicyAcceptedEvent",
            "ConsentGranted": "ConsentGrantedEvent",
            "UserActivated": "UserActivatedEvent",
            "UserRoleGranted": "UserRoleGrantedEvent",
            "MembershipActivated": "MembershipActivatedEvent",
            "MembershipRoleGranted": "MembershipRoleGrantedEvent",
            "OrganizationActivated": "OrganizationActivatedEvent",
        }
        if event_type not in definitions:
            raise AssertionError(f"unexpected accept event type: {event_type!r}")
        return definitions[event_type]

    def _assert_event_has_no_onboarding_secret(
        self, event: Mapping[str, Any], fixture: AcceptanceFixture, result: Any
    ) -> None:
        self._assert_no_secret_names_or_values(event, fixture, result)

    def _assert_no_secret_names_or_values(
        self, value: Any, fixture: AcceptanceFixture, result: Any
    ) -> None:
        encoded = json.dumps(value, sort_keys=True, default=str).lower()
        forbidden_names = (
            "recipient",
            "contact",
            "auth_transaction",
            "session_handle",
            "raw_session",
            "csrf",
            "cookie",
            "capability_token",
            "access_invitation_token",
        )
        for forbidden in forbidden_names:
            self.assertNotIn(f'"{forbidden}', encoded)
        forbidden_values = (
            fixture.ids.contact_point_id,
            fixture.ids.auth_transaction_id,
            fixture.ids.session_id,
            fixture.ids.successor_session_id,
            result.session_rotation.raw_session_handle,
            result.session_rotation.csrf_token,
            fixture.command.idempotency_key,
        )
        for forbidden in forbidden_values:
            self.assertNotIn(forbidden.lower(), encoded)


if __name__ == "__main__":
    unittest.main()
