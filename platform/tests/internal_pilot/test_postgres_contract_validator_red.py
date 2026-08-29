from __future__ import annotations

from copy import deepcopy
import unittest

from desire_platform.internal_pilot.contract_validation import (
    DemandPostgresContractValidator,
    IamPostgresContractValidator,
    PostgresContractConfigurationError,
    PostgresContractValidationError,
    ProfilePostgresContractValidator,
)
from tests.support.iam_application_builders import (
    existing_demand_owner_acceptance_fixture,
)
from tests.support.iam_authority_lifecycle_builders import (
    invitation_admin_dto,
    membership_admin_dto,
)


ID = "10000000-0000-4000-8000-000000000001"
OTHER_ID = "20000000-0000-4000-8000-000000000002"
NOW = "2026-08-12T08:00:00Z"


def profile_event():
    return {
        "event_id": ID,
        "event_type": "CreatorProfileCreated",
        "schema_version": 1,
        "occurred_at": NOW,
        "aggregate_type": "CreatorProfile",
        "aggregate_id": ID,
        "aggregate_version": 1,
        "actor_kind": "USER",
        "actor_id": OTHER_ID,
        "original_actor_id": None,
        "correlation_id": ID,
        "causation_id": OTHER_ID,
        "trace_id": ID,
        "organization_id": None,
        "payload": {
            "profile_id": ID,
            "owner_user_id": OTHER_ID,
            "status": "DRAFT",
        },
    }


def demand_event():
    return {
        "event_id": ID,
        "event_type": "DemandCreated",
        "schema_version": 1,
        "occurred_at": NOW,
        "aggregate_type": "Demand",
        "aggregate_id": ID,
        "aggregate_version": 1,
        "actor_kind": "USER",
        "actor_id": OTHER_ID,
        "original_actor_id": None,
        "correlation_id": ID,
        "causation_id": OTHER_ID,
        "trace_id": ID,
        "organization_id": OTHER_ID,
        "payload": {
            "demand_id": ID,
            "organization_id": OTHER_ID,
            "status": "DRAFT",
            "demand_version_id": OTHER_ID,
        },
    }


def iam_event():
    return {
        "event_id": ID,
        "event_type": "UserSuspended",
        "schema_version": 1,
        "occurred_at": NOW,
        "aggregate_type": "User",
        "aggregate_id": ID,
        "aggregate_version": 2,
        "actor_kind": "USER",
        "actor_id": OTHER_ID,
        "original_actor_id": None,
        "correlation_id": ID,
        "causation_id": OTHER_ID,
        "trace_id": ID,
        "organization_id": None,
        "payload": {"user_id": ID, "status": "SUSPENDED"},
    }


class PackagedPostgresContractValidatorTests(unittest.TestCase):
    def test_iam_validates_full_event_and_frozen_platform_user_response(self) -> None:
        validator = IamPostgresContractValidator()

        self.assertIsNone(validator.validate(iam_event()))
        self.assertIsNone(
            validator.validate(
                {
                    "user_id": ID,
                    "display_handle": "sandbox_creator",
                    "status": "SUSPENDED",
                    "aggregate_version": 2,
                    "entity_tag": '"v2"',
                    "revoked_session_count": 1,
                    "revoked_session_family_count": 1,
                },
                "PlatformUserAdminDto",
            )
        )
        with self.assertRaises(PostgresContractValidationError):
            validator.validate({**iam_event(), "contact": "never@example.test"})

    def test_iam_validates_only_the_reviewed_organization_admin_dtos(self) -> None:
        validator = IamPostgresContractValidator()
        acceptance = existing_demand_owner_acceptance_fixture()
        accepted = acceptance.handler.handle(
            actor=acceptance.actor,
            command=acceptance.command,
        )

        examples = (
            ("AccessInvitationAdminDto", invitation_admin_dto()),
            (
                "MembershipAdminDto",
                membership_admin_dto("SUSPENDED", ["DEMAND_OWNER"]),
            ),
            ("AccessInvitationAcceptanceDto", accepted.safe_response),
            (
                "OrganizationSummaryDto",
                {
                    "organization_id": ID,
                    "public_name": "Desire Sandbox Organization (Updated)",
                    "type": "BUSINESS",
                    "status": "ACTIVE",
                    "aggregate_version": 2,
                    "entity_tag": '"v2"',
                },
            ),
        )
        for schema_name, value in examples:
            with self.subTest(schema_name=schema_name):
                self.assertIsNone(validator.validate(value, schema_name))
                with self.assertRaises(PostgresContractValidationError):
                    validator.validate(
                        {**value, "secret_sentinel": "must-not-escape"},
                        schema_name,
                    )

    def test_rfc3339_validation_is_stable_for_every_fractional_width(self) -> None:
        validator = IamPostgresContractValidator()
        timestamps = (
            "2026-08-12T08:00:00.1Z",
            "2026-08-12T08:00:00.12Z",
            "2026-08-12T08:00:00.12345Z",
            "2026-08-12T08:00:00.123456Z",
            "2026-08-12T08:00:00.123456789Z",
        )

        for timestamp in timestamps:
            with self.subTest(timestamp=timestamp):
                event = iam_event()
                event["occurred_at"] = timestamp
                self.assertIsNone(validator.validate(event))

        invitation = invitation_admin_dto()
        invitation["created_at"] = "2026-08-12T16:00:00.12345+08:00"
        invitation["expires_at"] = "2026-08-12T02:30:00.123456789-05:30"
        self.assertIsNone(
            validator.validate(invitation, "AccessInvitationAdminDto")
        )

        for invalid_offset in ("+00:60", "-00:60", "+24:00", "-00:00"):
            with self.subTest(invalid_offset=invalid_offset):
                invalid = invitation_admin_dto()
                invalid["created_at"] = (
                    "2026-08-12T08:00:00.12345" + invalid_offset
                )
                with self.assertRaises(PostgresContractValidationError):
                    validator.validate(invalid, "AccessInvitationAdminDto")

    def test_profile_validates_exact_event_definition_and_internal_safe_response(self) -> None:
        validator = ProfilePostgresContractValidator()

        self.assertIsNone(
            validator.validate(profile_event(), "CreatorProfileCreatedEvent")
        )
        self.assertIsNone(
            validator.validate(
                {
                    "profile_id": ID,
                    "aggregate_version": 1,
                    "status": "DRAFT",
                },
                "CreatorProfileCommandResponse",
            )
        )
        self.assertNotIn(ID, repr(validator))

    def test_demand_validates_exact_event_contract_and_internal_safe_response(self) -> None:
        validator = DemandPostgresContractValidator()

        self.assertIsNone(validator.validate(demand_event(), "demand-v1"))
        self.assertIsNone(
            validator.validate(
                {
                    "aggregate_version": 1,
                    "demand_id": ID,
                    "demand_version_id": OTHER_ID,
                    "status": "DRAFT",
                },
                "DemandDto",
            )
        )

    def test_rejects_unknown_schema_extra_property_boolean_integer_and_event_drift(self) -> None:
        profile = ProfilePostgresContractValidator()
        demand = DemandPostgresContractValidator()
        invalid = []

        extra = profile_event()
        extra["raw_contact"] = "never-log@example.test"
        invalid.append((profile, extra, "CreatorProfileCreatedEvent"))
        wrong_payload = profile_event()
        wrong_payload["payload"]["status"] = "ACTIVE"
        invalid.append((profile, wrong_payload, "CreatorProfileCreatedEvent"))
        boolean_version = demand_event()
        boolean_version["aggregate_version"] = True
        invalid.append((demand, boolean_version, "demand-v1"))
        mismatched_type = demand_event()
        mismatched_type["event_type"] = "DemandSubmitted"
        invalid.append((demand, mismatched_type, "demand-v1"))
        non_rfc3339_timestamp = profile_event()
        non_rfc3339_timestamp["occurred_at"] = "2026-08-12 08:00:00Z"
        invalid.append(
            (
                profile,
                non_rfc3339_timestamp,
                "CreatorProfileCreatedEvent",
            )
        )
        invalid.append((demand, demand_event(), "unreviewed-schema"))

        for validator, value, schema_name in invalid:
            with self.subTest(schema_name=schema_name, value=value):
                with self.assertRaises(PostgresContractValidationError) as raised:
                    validator.validate(value, schema_name)
                self.assertEqual(raised.exception.code, "CONTRACT_VALIDATION_FAILED")
                self.assertNotIn("never-log@example.test", str(raised.exception))

    def test_rejects_packaged_resource_digest_drift(self) -> None:
        def drift(path: str) -> bytes:
            del path
            return b"{}"

        for constructor in (
            IamPostgresContractValidator,
            ProfilePostgresContractValidator,
            DemandPostgresContractValidator,
        ):
            with self.subTest(constructor=constructor.__name__):
                with self.assertRaises(PostgresContractConfigurationError) as raised:
                    constructor(resource_loader=drift)
                self.assertEqual(
                    raised.exception.code,
                    "CONTRACT_CONFIGURATION_UNAVAILABLE",
                )


if __name__ == "__main__":
    unittest.main()
