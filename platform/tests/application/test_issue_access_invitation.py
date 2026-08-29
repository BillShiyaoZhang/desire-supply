"""IssueAccessInvitation RED for authoritative selector and issued bundle facts."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, fields, replace
from datetime import timedelta
import unittest

from desire_platform.identity_access.application.issue_access_invitations import (
    IssueAccessInvitationCommand,
    IssueAccessInvitationResult,
    RecipientInput,
)
from desire_platform.identity_access.application.policy_publication import (
    PolicySelectorFacts,
)
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.domain.invitations import (
    AccessInvitation,
    InvitationPurpose,
    InvitationStatus,
    TargetRole,
    TargetScope,
)
from desire_platform.identity_access.domain.policies import PolicyBundleStatus
from tests.support.iam_policy_issue_builders import (
    UTC_NOW,
    CreatorEnrollmentPolicy,
    creator_issue_fixture,
    organization_issue_fixture,
    policy_selector_digest,
)


class IssueAccessInvitationSemanticRedTest(unittest.TestCase):
    def test_command_is_closed_and_cannot_claim_selector_or_issuer_facts(self) -> None:
        """Only recipient, role, deadline and path/version controls are input."""

        fixture = organization_issue_fixture()
        self.assertEqual(
            [field.name for field in fields(IssueAccessInvitationCommand)],
            [
                "organization_id",
                "expected_organization_version",
                "recipient",
                "target_role",
                "expires_at",
                "idempotency_key",
            ],
        )
        self.assertEqual(
            [field.name for field in fields(RecipientInput)],
            ["type", "value"],
        )
        command_fields = {
            field.name for field in fields(IssueAccessInvitationCommand)
        }
        self.assertFalse(
            command_fields
            & {
                "purpose",
                "target_scope",
                "jurisdiction",
                "locale",
                "policy_selector_digest",
                "issued_policy_bundle_id",
                "current_policy_bundle_id",
                "is_initial_admin",
                "issuer_id",
                "created_at",
                "token_nonce",
                "token_key_id",
            }
        )
        self.assertNotIn(fixture.command.recipient.value, repr(fixture.command))
        self.assertNotIn(
            fixture.command.idempotency_key,
            repr(fixture.command),
        )
        with self.assertRaises(FrozenInstanceError):
            fixture.command.target_role = TargetRole.ORG_ADMIN
        self.assertNotIn(
            "access_invitation_token",
            repr(
                IssueAccessInvitationResult(
                    replayed=False,
                    invitation={},
                    access_invitation_token="raw-secret",
                    join_fragment_url="/join#raw-secret",
                )
            ),
        )

    def test_creator_and_organization_issue_freeze_authoritative_selector_current(
        self,
    ) -> None:
        """Both legal shapes persist exact digest plus the current issued bundle."""

        cases = (
            (
                "creator",
                creator_issue_fixture,
                InvitationPurpose.CREATOR_ENROLLMENT,
                TargetScope.USER,
                None,
                TargetRole.CREATOR,
                1,
                [],
                None,
                [("policy_selectors", None)],
            ),
            (
                "organization",
                organization_issue_fixture,
                InvitationPurpose.ORGANIZATION_MEMBERSHIP,
                TargetScope.ORGANIZATION,
                "organization_issue_target_001",
                TargetRole.DEMAND_OWNER,
                0,
                [
                    {
                        "jurisdiction": "CN",
                        "access_purpose": "ORGANIZATION_MEMBERSHIP",
                        "target_role": "DEMAND_OWNER",
                        "policy_version": (
                            "organization-locale-fallback-v1"
                        ),
                    }
                ],
                "organization_issue_target_001",
                [
                    ("organizations", "organization_issue_target_001"),
                    ("policy_selectors", None),
                ],
            ),
        )
        for (
            name,
            factory,
            expected_purpose,
            expected_scope,
            expected_organization_id,
            expected_role,
            expected_platform_calls,
            expected_locale_calls,
            expected_hold_organization,
            expected_locks,
        ) in cases:
            with self.subTest(case=name):
                fixture = factory()
                # The exact digest is substituted below because the test table
                # keeps its expected lock shape readable.
                expected_locks = [
                    (
                        table,
                        fixture.selector_digest if key is None else key,
                    )
                    for table, key in expected_locks
                ]
                result, code = self._invoke(fixture)
                snapshot = fixture.store.snapshot()
                invitation = next(
                    iter(snapshot.get("invitations", {}).values()), None
                )
                contact = next(
                    iter(snapshot.get("contact_points", {}).values()), {}
                )
                receipt = next(
                    iter(snapshot.get("command_receipts", {}).values()), {}
                )
                hold_call = (
                    fixture.hold.calls[0] if fixture.hold.calls else None
                )
                safe_receipt = repr(receipt)

                self.assertEqual(
                    {
                        "code": code,
                        "replayed": getattr(result, "replayed", None),
                        "purpose": self._enum_attr(invitation, "purpose"),
                        "scope": self._enum_attr(invitation, "target_scope"),
                        "role": self._enum_attr(invitation, "target_role"),
                        "organization_id": getattr(
                            invitation, "organization_id", None
                        ),
                        "initial_admin": getattr(
                            invitation, "is_initial_admin", None
                        ),
                        "selector_digest": getattr(
                            invitation, "policy_selector_digest", None
                        ),
                        "issued_bundle": getattr(
                            invitation, "issued_policy_bundle_id", None
                        ),
                        "status": self._enum_attr(invitation, "status"),
                        "created_at": getattr(invitation, "created_at", None),
                        "aggregate_version": getattr(
                            invitation, "aggregate_version", None
                        ),
                        "token_key_id": getattr(
                            invitation, "token_key_id", None
                        ),
                        "nonce_present": bool(
                            getattr(invitation, "nonce", None)
                        ),
                        "contact_type": contact.get("type"),
                        "contact_id": getattr(
                            invitation, "recipient_contact_id", None
                        ),
                        "platform_calls": fixture.platform_policy.calls,
                        "locale_calls": fixture.locale_resolver.calls,
                        "hold_calls": len(fixture.hold.calls),
                        "hold_action": (
                            None if hold_call is None else hold_call.action
                        ),
                        "hold_organization": (
                            None
                            if hold_call is None
                            else hold_call.organization_id
                        ),
                        "hold_policy": (
                            None
                            if hold_call is None
                            else hold_call.policy_version
                        ),
                        "locks": fixture.uow_factory.lock_calls,
                        "commits": fixture.uow_factory.commit_count,
                        "receipt_count": len(
                            snapshot.get("command_receipts", {})
                        ),
                        "audit_count": len(snapshot.get("audit_events", {})),
                        "events": self._event_types(snapshot),
                        "token_returned": bool(
                            getattr(result, "access_invitation_token", "")
                        ),
                        "raw_locator_persisted": (
                            fixture.command.recipient.value in repr(snapshot)
                        ),
                        "raw_token_in_receipt": (
                            getattr(result, "access_invitation_token", "")
                            in safe_receipt
                            if result is not None
                            else False
                        ),
                    },
                    {
                        "code": None,
                        "replayed": False,
                        "purpose": expected_purpose.value,
                        "scope": expected_scope.value,
                        "role": expected_role.value,
                        "organization_id": expected_organization_id,
                        "initial_admin": False,
                        "selector_digest": fixture.selector_digest,
                        "issued_bundle": (
                            fixture.current_bundle.policy_bundle_id
                        ),
                        "status": InvitationStatus.ISSUED.value,
                        "created_at": UTC_NOW,
                        "aggregate_version": 1,
                        "token_key_id": fixture.token_codec.key_id,
                        "nonce_present": True,
                        "contact_type": "EMAIL",
                        "contact_id": "contact_point_issue_001",
                        "platform_calls": expected_platform_calls,
                        "locale_calls": expected_locale_calls,
                        "hold_calls": 1,
                        "hold_action": "IssueAccessInvitation",
                        "hold_organization": expected_hold_organization,
                        "hold_policy": "safety-hold-v1",
                        "locks": expected_locks,
                        "commits": 1,
                        "receipt_count": 1,
                        "audit_count": 1,
                        "events": ["AccessInvitationIssued"],
                        "token_returned": True,
                        "raw_locator_persisted": False,
                        "raw_token_in_receipt": False,
                    },
                )

    def test_invalid_selector_pointer_status_or_window_fails_before_hold_and_writes(
        self,
    ) -> None:
        """Issue never falls back to a bundle guessed from role or recency."""

        cases = (
            "missing-selector",
            "selector-row-digest-mismatch",
            "missing-current-pointer",
            "missing-current-bundle",
            "cross-selector-bundle",
            "draft-current",
            "future-current",
            "effective-until-equal",
            "multiple-effective-candidates",
        )
        for case in cases:
            with self.subTest(case=case):
                fixture = organization_issue_fixture()
                self._invalidate_policy_configuration(fixture, case)
                before = fixture.store.snapshot()
                _result, code = self._invoke(fixture)
                self.assertEqual(
                    {
                        "code": code,
                        "unchanged": fixture.store.snapshot() == before,
                        "hold_calls": len(fixture.hold.calls),
                        "writes": fixture.uow_factory.write_calls,
                        "commits": fixture.uow_factory.commit_count,
                    },
                    {
                        "code": "POLICY_CONFIGURATION_UNAVAILABLE",
                        "unchanged": True,
                        "hold_calls": 0,
                        "writes": [],
                        "commits": 0,
                    },
                )

    def test_org_jurisdiction_platform_defaults_and_locale_policy_are_authoritative(
        self,
    ) -> None:
        """Changing an authority source cannot silently reuse a stale selector."""

        cases = (
            "organization-jurisdiction-changed",
            "locale-policy-unavailable",
            "creator-platform-default-changed",
        )
        for case in cases:
            with self.subTest(case=case):
                if case == "creator-platform-default-changed":
                    fixture = creator_issue_fixture()
                    fixture.platform_policy.value = CreatorEnrollmentPolicy(
                        policy_version="creator-enrollment-defaults-v2",
                        jurisdiction="EU",
                        locale="fr",
                        aggregate_version=5,
                    )
                else:
                    fixture = organization_issue_fixture(
                        locale_unavailable=(
                            case == "locale-policy-unavailable"
                        )
                    )
                    if case == "organization-jurisdiction-changed":
                        fixture.store._tables["organizations"][
                            fixture.command.organization_id
                        ]["jurisdiction"] = "DE"
                before = fixture.store.snapshot()
                _result, code = self._invoke(fixture)
                locale_call = (
                    fixture.locale_resolver.calls[0]
                    if fixture.locale_resolver.calls
                    else None
                )
                self.assertEqual(
                    {
                        "code": code,
                        "unchanged": fixture.store.snapshot() == before,
                        "hold_calls": len(fixture.hold.calls),
                        "writes": fixture.uow_factory.write_calls,
                        "platform_calls": fixture.platform_policy.calls,
                        "resolved_jurisdiction": (
                            None
                            if locale_call is None
                            else locale_call["jurisdiction"]
                        ),
                    },
                    {
                        "code": "POLICY_CONFIGURATION_UNAVAILABLE",
                        "unchanged": True,
                        "hold_calls": 0,
                        "writes": [],
                        "platform_calls": (
                            1
                            if case == "creator-platform-default-changed"
                            else 0
                        ),
                        "resolved_jurisdiction": (
                            None
                            if case == "creator-platform-default-changed"
                            else (
                                "DE"
                                if case
                                == "organization-jurisdiction-changed"
                                else "CN"
                            )
                        ),
                    },
                )

    def test_completed_receipt_reconstructs_capability_without_persisting_it(
        self,
    ) -> None:
        """Same key/hash rebuilds one token; changed payload cannot reuse it."""

        fixture = creator_issue_fixture()
        binding = fixture.recipient_binding.bind(
            contact_type=fixture.command.recipient.type.value,
            locator=fixture.command.recipient.value,
        )
        identity_digest = fixture.receipt_codec.identity_digest(
            fixture.command.idempotency_key
        )
        payload_hash = fixture.receipt_codec.payload_hash(
            command=fixture.command,
            recipient_binding_digest=binding["binding_digest"],
        )
        fixture.recipient_binding.calls.clear()
        fixture.receipt_codec.identity_calls.clear()
        fixture.receipt_codec.payload_calls.clear()

        invitation = AccessInvitation(
            invitation_id="access_invitation_issue_001",
            purpose=InvitationPurpose.CREATOR_ENROLLMENT,
            target_scope=TargetScope.USER,
            target_role=TargetRole.CREATOR,
            organization_id=None,
            is_initial_admin=False,
            recipient_contact_id="contact_point_issue_001",
            issued_policy_bundle_id=fixture.current_bundle.policy_bundle_id,
            policy_selector_digest=fixture.selector_digest,
            status=InvitationStatus.ISSUED,
            expires_at=fixture.command.expires_at,
            aggregate_version=1,
            created_at=UTC_NOW,
            masked_recipient_label=binding["masked_recipient_label"],
        )
        object.__setattr__(invitation, "nonce", "nonce_issue_001")
        object.__setattr__(
            invitation,
            "token_key_id",
            fixture.token_codec.key_id,
        )
        receipt_key = (
            "SYSTEM",
            fixture.actor.actor_id,
            "IssueAccessInvitation",
            1,
            identity_digest,
        )
        safe_invitation = {
            "invitation_id": invitation.invitation_id,
            "purpose": invitation.purpose.value,
            "organization_id": None,
            "target_role": invitation.target_role.value,
            "masked_recipient_label": binding["masked_recipient_label"],
            "is_initial_admin": False,
            "status": invitation.status.value,
            "expires_at": invitation.expires_at,
            "created_at": invitation.created_at,
            "required_policy_bundle_id": (
                invitation.issued_policy_bundle_id
            ),
            "aggregate_version": 1,
            "entity_tag": '"AccessInvitation:1"',
        }
        fixture.store.seed(
            contact_points={
                invitation.recipient_contact_id: {
                    "contact_point_id": invitation.recipient_contact_id,
                    **binding,
                }
            },
            invitations={invitation.invitation_id: invitation},
            command_receipts={
                receipt_key: {
                    "principal_kind": "SYSTEM",
                    "principal_id": fixture.actor.actor_id,
                    "command_name": "IssueAccessInvitation",
                    "command_version": 1,
                    "idempotency_key_digest": identity_digest,
                    "idempotency_digest_key_id": fixture.receipt_codec.key_id,
                    "payload_hash": payload_hash,
                    "status": "COMPLETED",
                    "response_body": {"invitation": safe_invitation},
                    "reconstruction_metadata": {
                        "invitation_id": invitation.invitation_id,
                        "token_key_id": fixture.token_codec.key_id,
                    },
                }
            },
        )
        before = fixture.store.snapshot()
        replay_result, replay_code = self._invoke(fixture)

        fixture.command = replace(
            fixture.command,
            expires_at=fixture.command.expires_at + timedelta(days=1),
        )
        _changed_result, changed_code = self._invoke(fixture)
        receipt_repr = repr(
            next(
                iter(
                    fixture.store.snapshot().get(
                        "command_receipts", {}
                    ).values()
                )
            )
        )

        self.assertEqual(
            {
                "replay_code": replay_code,
                "replayed": getattr(replay_result, "replayed", None),
                "token": getattr(
                    replay_result, "access_invitation_token", None
                ),
                "changed_code": changed_code,
                "unchanged": fixture.store.snapshot() == before,
                "writes": fixture.uow_factory.write_calls,
                "token_calls": len(fixture.token_codec.calls),
                "raw_token_persisted": "test-capability." in receipt_repr,
                "raw_key_persisted": (
                    fixture.command.idempotency_key in receipt_repr
                ),
                "raw_locator_persisted": (
                    fixture.command.recipient.value in receipt_repr
                ),
            },
            {
                "replay_code": None,
                "replayed": True,
                "token": (
                    "test-capability.access_invitation_issue_001."
                    "nonce_issue_001"
                ),
                "changed_code": "IDEMPOTENCY_KEY_REUSED",
                "unchanged": True,
                "writes": [],
                "token_calls": 1,
                "raw_token_persisted": False,
                "raw_key_persisted": False,
                "raw_locator_persisted": False,
            },
        )

    @staticmethod
    def _invoke(fixture):
        try:
            return (
                fixture.handler.handle(
                    actor=fixture.actor,
                    command=fixture.command,
                ),
                None,
            )
        except IamError as error:
            return None, error.code

    @staticmethod
    def _enum_attr(value, name: str):
        attribute = getattr(value, name, None)
        return getattr(attribute, "value", attribute)

    @staticmethod
    def _event_types(snapshot) -> list[str]:
        return sorted(
            event.get("event_type")
            for event in snapshot.get("outbox_events", {}).values()
            if isinstance(event, dict) and event.get("event_type") is not None
        )

    @staticmethod
    def _invalidate_policy_configuration(fixture, case: str) -> None:
        selectors = fixture.store._tables["policy_selectors"]
        bundles = fixture.store._tables["policy_bundles"]
        selector = selectors[fixture.selector_digest]
        bundle = bundles[fixture.current_bundle.policy_bundle_id]

        if case == "missing-selector":
            selectors.pop(fixture.selector_digest)
        elif case == "selector-row-digest-mismatch":
            selector["selector_digest"] = "f" * 64
        elif case == "missing-current-pointer":
            selector["current_bundle_id"] = None
        elif case == "missing-current-bundle":
            bundles.pop(fixture.current_bundle.policy_bundle_id)
        elif case == "cross-selector-bundle":
            object.__setattr__(bundle, "selector_digest", "e" * 64)
        elif case == "draft-current":
            object.__setattr__(bundle, "status", PolicyBundleStatus.DRAFT)
        elif case == "future-current":
            object.__setattr__(
                bundle,
                "effective_at",
                UTC_NOW + timedelta(seconds=1),
            )
        elif case == "effective-until-equal":
            object.__setattr__(bundle, "effective_until", UTC_NOW)
        elif case == "multiple-effective-candidates":
            competing = replace(
                bundle,
                policy_bundle_id="policy_bundle_issue_competing_002",
            )
            bundles[competing.policy_bundle_id] = competing
        else:  # pragma: no cover - closed test table
            raise AssertionError("unknown invalid policy case: %s" % case)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
