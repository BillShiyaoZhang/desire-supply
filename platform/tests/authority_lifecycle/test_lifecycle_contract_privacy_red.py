"""Closed DTO/event and recursive privacy obligations for lifecycle commands."""

import unittest

from tests.support.iam_authority_lifecycle_builders import (
    ACTOR_USER_ID,
    CONSENT_GRANT_ID,
    CONTACT_SENTINEL,
    INVITATION_ID,
    ORGANIZATION_ID,
    POLICY_BUNDLE_ID,
    RAW_SESSION_SENTINEL,
    REASON_NOTE_SENTINEL,
    TARGET_FAMILY_ID,
    TARGET_MEMBERSHIP_ID,
    TARGET_ROLE_GRANT_ID,
    TARGET_SESSION_ID,
    ClosedSchemaValidator,
    consent_grant_dto,
    consent_withdraw_fixture,
    invitation_admin_dto,
    invitation_revoke_fixture,
    membership_admin_dto,
    membership_fixture,
    recursive_contains,
    session_revoke_fixture,
)


def envelope(event_type, aggregate_type, aggregate_id, aggregate_version, organization_id, payload):
    return {
        "event_id": f"event_{event_type.lower()}_0001",
        "event_type": event_type,
        "schema_version": 1,
        "occurred_at": "2026-08-08T09:00:00Z",
        "aggregate_type": aggregate_type,
        "aggregate_id": aggregate_id,
        "aggregate_version": aggregate_version,
        "actor_kind": "USER",
        "actor_id": ACTOR_USER_ID,
        "original_actor_id": None,
        "correlation_id": "correlation_auth_01",
        "causation_id": "causation_auth_001",
        "trace_id": "trace_authority_001",
        "organization_id": organization_id,
        "payload": payload,
    }


def closed_event_examples():
    invitation_binding = {
        "invitation_id": INVITATION_ID,
        "bound_invitation_version": 1,
        "issued_policy_bundle_id": POLICY_BUNDLE_ID,
        "purpose": "ORGANIZATION_MEMBERSHIP",
        "target_scope": "ORGANIZATION",
        "target_role": "DEMAND_OWNER",
        "is_initial_admin": False,
    }
    derived_consent = {
        "consent_offer_id": "consent_offer_0001",
        "consent_offer_version": 1,
        "policy_bundle_id": POLICY_BUNDLE_ID,
        "purpose": "PILOT_RESEARCH",
        "scope_type": "PLATFORM_PARTICIPATION",
        "scope_id": None,
        "data_categories": ["PROFILE", "MATCHING", "RESEARCH"],
        "supporting_policy_document_id": "policy_document_01",
        "supporting_document_sha256": "b" * 64,
        "expires_at": "2026-11-16T09:00:00Z",
    }
    member_payload = {
        "membership_id": TARGET_MEMBERSHIP_ID,
        "user_id": "user_target_00001",
    }
    return (
        envelope(
            "AccessInvitationRevoked",
            "AccessInvitation",
            INVITATION_ID,
            2,
            ORGANIZATION_ID,
            {"invitation_binding": invitation_binding, "status": "REVOKED"},
        ),
        envelope(
            "ConsentWithdrawn",
            "ConsentGrant",
            CONSENT_GRANT_ID,
            2,
            None,
            {
                "consent_grant_id": CONSENT_GRANT_ID,
                "user_id": ACTOR_USER_ID,
                "status": "WITHDRAWN",
                "effective_at": "2026-08-08T09:00:00Z",
                "derived_authorization": derived_consent,
            },
        ),
        envelope(
            "SessionRevoked",
            "Session",
            TARGET_SESSION_ID,
            2,
            None,
            {
                "session_id": TARGET_SESSION_ID,
                "session_family_id": TARGET_FAMILY_ID,
                "user_id": ACTOR_USER_ID,
                "status": "REVOKED",
            },
        ),
        envelope(
            "MembershipSuspended",
            "Membership",
            TARGET_MEMBERSHIP_ID,
            3,
            ORGANIZATION_ID,
            {**member_payload, "status": "SUSPENDED"},
        ),
        envelope(
            "MembershipResumed",
            "Membership",
            TARGET_MEMBERSHIP_ID,
            3,
            ORGANIZATION_ID,
            {**member_payload, "status": "ACTIVE"},
        ),
        envelope(
            "MembershipRevoked",
            "Membership",
            TARGET_MEMBERSHIP_ID,
            3,
            ORGANIZATION_ID,
            {**member_payload, "status": "REVOKED"},
        ),
        envelope(
            "MembershipRolesRevoked",
            "Membership",
            TARGET_MEMBERSHIP_ID,
            3,
            ORGANIZATION_ID,
            {
                **member_payload,
                "membership_role_grant_id": TARGET_ROLE_GRANT_ID,
                "target_role": "DEMAND_OWNER",
            },
        ),
    )


class LifecycleClosedContractTest(unittest.TestCase):
    def test_all_public_safe_dtos_validate_directly_against_openapi(self) -> None:
        validator = ClosedSchemaValidator.for_openapi()
        examples = (
            ("AccessInvitationAdminDto", invitation_admin_dto()),
            ("ConsentGrantDto", consent_grant_dto()),
            ("MembershipAdminDto", membership_admin_dto("SUSPENDED", ["DEMAND_OWNER"])),
            ("MembershipAdminDto", membership_admin_dto("ACTIVE", ["DEMAND_OWNER"])),
            ("MembershipAdminDto", membership_admin_dto("REVOKED", ["DEMAND_OWNER"])),
        )
        for schema_name, value in examples:
            with self.subTest(schema=schema_name, status=value.get("status")):
                validator.validate(value, schema_name)

    def test_every_lifecycle_event_validates_directly_against_closed_iam_schema(self) -> None:
        validator = ClosedSchemaValidator.for_events()
        for event in closed_event_examples():
            with self.subTest(event_type=event["event_type"]):
                validator.validate(event)

    def test_raw_protocol_and_operator_secrets_are_absent_recursively(self) -> None:
        fixtures = (
            invitation_revoke_fixture(),
            consent_withdraw_fixture(),
            session_revoke_fixture(),
            membership_fixture("suspend"),
            membership_fixture("resume"),
            membership_fixture("revoke"),
        )
        sentinels = (
            REASON_NOTE_SENTINEL,
            RAW_SESSION_SENTINEL,
            CONTACT_SENTINEL,
        )
        values = [event for event in closed_event_examples()]
        values.extend(
            (
                invitation_admin_dto(),
                consent_grant_dto(),
                membership_admin_dto("REVOKED", ["DEMAND_OWNER"]),
            )
        )
        for fixture in fixtures:
            values.append(fixture.store.snapshot())
            command_repr = repr(fixture.command)
            with self.subTest(command=type(fixture.command).__name__, carrier="repr"):
                self.assertNotIn(REASON_NOTE_SENTINEL, command_repr)
                self.assertNotIn("idem_authority_00000001", command_repr)
        for index, value in enumerate(values):
            for sentinel in sentinels:
                with self.subTest(value=index, sentinel=sentinel):
                    self.assertFalse(recursive_contains(value, sentinel))


if __name__ == "__main__":
    unittest.main()
