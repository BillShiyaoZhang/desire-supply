"""Machine-contract gates for exact IAM policy/consent command authority."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import json
import unittest

import yaml


PLATFORM_ROOT = Path(__file__).resolve().parents[2]
OPENAPI_PATH = PLATFORM_ROOT / "contracts" / "api" / "iam-v1.openapi.yaml"
EVENT_SCHEMA_PATH = PLATFORM_ROOT / "contracts" / "events" / "iam-v1.schema.json"


def _load_openapi() -> dict[str, Any]:
    with OPENAPI_PATH.open(encoding="utf-8") as source:
        document = yaml.safe_load(source)
    if not isinstance(document, dict):
        raise AssertionError("OpenAPI root must be an object")
    return document


class IamPolicyConsentCommandContractTests(unittest.TestCase):
    def test_requirement_reference_is_closed_and_scope_shape_is_machine_checked(self) -> None:
        schemas = _load_openapi()["components"]["schemas"]
        reference = schemas["PolicyRequirementReferenceInput"]

        self.assertEqual(reference["type"], "object")
        self.assertIs(reference["additionalProperties"], False)
        self.assertEqual(
            set(reference["required"]),
            {"selector_digest", "scope_type", "scope_id"},
        )
        self.assertEqual(
            set(reference["properties"]),
            {"selector_digest", "scope_type", "scope_id"},
        )
        self.assertEqual(
            reference["properties"]["selector_digest"],
            {"$ref": "#/components/schemas/ContentSha256"},
        )
        self.assertEqual(
            reference["properties"]["scope_type"],
            {"$ref": "#/components/schemas/PolicyRequirementScopeType"},
        )
        variants = reference["oneOf"]
        self.assertEqual(len(variants), 2)
        self.assertEqual(
            {
                variant["properties"]["scope_type"]["const"]
                for variant in variants
            },
            {"USER_ROLE", "ORGANIZATION_ROLE"},
        )
        user_variant = next(
            variant
            for variant in variants
            if variant["properties"]["scope_type"]["const"] == "USER_ROLE"
        )
        organization_variant = next(
            variant
            for variant in variants
            if variant["properties"]["scope_type"]["const"]
            == "ORGANIZATION_ROLE"
        )
        self.assertEqual(user_variant["properties"]["scope_id"], {"type": "null"})
        self.assertEqual(
            organization_variant["properties"]["scope_id"],
            {"$ref": "#/components/schemas/OpaqueId"},
        )

    def test_accept_and_grant_require_exact_authority_and_current_bundle(self) -> None:
        document = _load_openapi()
        schemas = document["components"]["schemas"]

        accept = schemas["AcceptPoliciesRequest"]
        self.assertEqual(accept["type"], "object")
        self.assertIs(accept["additionalProperties"], False)
        self.assertEqual(
            set(accept["required"]),
            {"policy_requirement", "policy_bundle_id", "policy_acceptances"},
        )
        self.assertEqual(
            set(accept["properties"]),
            {"policy_requirement", "policy_bundle_id", "policy_acceptances"},
        )
        self.assertEqual(
            accept["properties"]["policy_requirement"],
            {"$ref": "#/components/schemas/PolicyRequirementReferenceInput"},
        )

        grant = schemas["GrantConsentRequest"]
        self.assertNotIn("allOf", grant)
        self.assertEqual(grant["type"], "object")
        self.assertIs(grant["additionalProperties"], False)
        self.assertEqual(
            set(grant["required"]),
            {
                "policy_requirement",
                "policy_bundle_id",
                "consent_offer_id",
                "document_id",
                "content_sha256",
                "affirmed",
            },
        )
        self.assertEqual(set(grant["properties"]), set(grant["required"]))
        self.assertEqual(
            grant["properties"]["policy_requirement"],
            {"$ref": "#/components/schemas/PolicyRequirementReferenceInput"},
        )
        self.assertEqual(grant["properties"]["affirmed"], {"type": "boolean", "const": True})
        for forbidden in (
            "purpose",
            "scope_type",
            "scope_id",
            "organization_id",
            "project_id",
            "recipient_reference",
            "recipient_id",
            "data_categories",
            "expires_at",
        ):
            self.assertNotIn(forbidden, grant["properties"])

        for path, operation_id, response_etag_target in (
            ("/v1/me/policy-acceptances", "acceptCurrentPolicies", "User"),
            ("/v1/me/consents", "grantConsent", "ConsentGrant"),
        ):
            with self.subTest(operation_id=operation_id):
                operation = document["paths"][path]["post"]
                self.assertEqual(operation["operationId"], operation_id)
                self.assertEqual(operation["x-concurrency-target"], "User")
                self.assertEqual(
                    operation["x-response-etag-target"], response_etag_target
                )
                parameter_refs = {
                    parameter.get("$ref")
                    for parameter in operation["parameters"]
                    if isinstance(parameter, dict)
                }
                self.assertIn(
                    "#/components/parameters/IfMatch", parameter_refs
                )
                self.assertIn(
                    "#/components/parameters/IdempotencyKey", parameter_refs
                )
                self.assertTrue(
                    {"400", "403", "409", "412", "503"}.issubset(
                        operation["responses"]
                    )
                )

        wire_error_codes = set(schemas["ErrorCode"]["enum"])
        self.assertTrue(
            {
                "INVALID_REQUEST",
                "POLICY_ACCEPTANCE_REQUIRED",
                "RESOURCE_NOT_FOUND",
                "IDEMPOTENCY_KEY_REUSED",
                "POLICY_BUNDLE_CHANGED",
                "INVALID_STATE_TRANSITION",
                "PRECONDITION_FAILED",
                "POLICY_CONFIGURATION_UNAVAILABLE",
                "COMMAND_OUTCOME_UNKNOWN",
                "SERVICE_UNAVAILABLE",
            }.issubset(wire_error_codes)
        )
        self.assertTrue(
            {
                "COMMAND_IN_PROGRESS",
                "POLICY_DOCUMENT_MISMATCH",
                "CONSENT_OFFER_MISMATCH",
                "CONSENT_OFFER_EXPIRED",
            }.isdisjoint(wire_error_codes)
        )

    def test_v1_grant_scope_is_server_derived_generic_pilot_only(self) -> None:
        document = _load_openapi()
        operation = document["paths"]["/v1/me/consents"]["post"]
        self.assertEqual(
            operation["x-consent-scope-derivation"],
            "PLATFORM_PARTICIPATION_NULL_SCOPE",
        )
        self.assertEqual(
            operation["x-supported-consent-purposes"], ["PILOT_RESEARCH"]
        )
        self.assertEqual(
            operation["x-policy-bundle-binding"], "EXACT_CURRENT_FOR_REQUIREMENT"
        )

        accepted = document["paths"]["/v1/me/policy-acceptances"]["post"]
        self.assertEqual(
            accepted["x-policy-bundle-binding"],
            "EXACT_CURRENT_FOR_REQUIREMENT",
        )

    def test_events_distinguish_coarse_requirement_invalidation_from_consent_scope(self) -> None:
        with EVENT_SCHEMA_PATH.open(encoding="utf-8") as source:
            definitions = json.load(source)["$defs"]

        satisfied = definitions["PolicyRequirementsSatisfiedPayload"]
        self.assertEqual(
            set(satisfied["properties"]), {"user_id", "policy_bundle_id"}
        )
        self.assertIn("invalidation", satisfied["description"].lower())
        self.assertIn("must re-read", satisfied["description"].lower())

        derived = definitions["DerivedConsentAuthorization"]
        self.assertTrue(
            {
                "purpose",
                "scope_type",
                "scope_id",
                "data_categories",
                "supporting_policy_document_id",
                "supporting_document_sha256",
                "expires_at",
            }.issubset(derived["required"])
        )
        self.assertNotIn("recipient_reference", derived["properties"])
        self.assertNotIn("recipient_ref", derived["properties"])


if __name__ == "__main__":
    unittest.main()
