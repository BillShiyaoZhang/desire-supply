from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import hashlib
import json
import unittest

from desire_platform.demand.ports.commands import DemandRuleRequirement
from desire_platform.internal_pilot.synthetic_seed import (
    INTERNAL_SANDBOX_SYNTHETIC_SEED_SHA256,
    InternalSandboxSyntheticSeedError,
    InternalSandboxSyntheticSeedPlan,
    load_internal_sandbox_synthetic_seed,
    parse_internal_sandbox_synthetic_seed,
)


TAXONOMY_BUNDLE_ID = "50000000-0000-4000-8000-000000000001"


def document():
    return {
        "account_slots": [
            {
                "invitation_purpose": "CREATOR_ENROLLMENT",
                "provisioning_commands": [
                    "PublishPolicyBundle",
                    "IssueAccessInvitation",
                    "AcceptAccessInvitation",
                ],
                "role_codes": ["CREATOR"],
                "slot_code": "CREATOR",
            },
            {
                "invitation_purpose": "ORGANIZATION_MEMBERSHIP",
                "provisioning_commands": [
                    "PublishPolicyBundle",
                    "IssueAccessInvitation",
                    "AcceptAccessInvitation",
                ],
                "role_codes": ["DEMAND_OWNER"],
                "slot_code": "DEMAND_OWNER",
            },
        ],
        "blockers": [],
        "business_drafts": [
            {
                "contains_real_data": False,
                "create_command": "CreateCreatorProfile",
                "funds_amount_minor": 0,
                "owner_slot_code": "CREATOR",
                "resource_kind": "CREATOR_PROFILE",
                "taxonomy_bundle_id": TAXONOMY_BUNDLE_ID,
            },
            {
                "contains_real_data": False,
                "create_command": "CreateDemand",
                "funds_amount_minor": 0,
                "owner_slot_code": "DEMAND_OWNER",
                "resource_kind": "DEMAND",
                "taxonomy_bundle_id": TAXONOMY_BUNDLE_ID,
            },
        ],
        "demand_rule_requirement": {
            "budget_rule_bundle_id": "51000000-0000-4000-8000-000000000001",
            "composite_rule_requirement_id": "55000000-0000-4000-8000-000000000001",
            "effective_at": "2020-01-01T00:00:00Z",
            "effective_until": "2100-01-01T00:00:00Z",
            "matching_rule_bundle_id": "53000000-0000-4000-8000-000000000001",
            "reason_code_bundle_id": "54000000-0000-4000-8000-000000000001",
            "requirement_sha256": "98ba1470ec6171ad33a9a8123cd855278241ac607f87ef4226b1f4f4a3bb88e3",
            "risk_rule_bundle_id": "52000000-0000-4000-8000-000000000001",
            "taxonomy_bundle_id": TAXONOMY_BUNDLE_ID,
        },
        "deployment_mode": "INTERNAL_SANDBOX",
        "external_side_effects_enabled": False,
        "fixture_id": "internal-sandbox-g1-synthetic-v1",
        "operation_sequence": [
            "PublishTaxonomyBundle",
            "CaptureTaxonomyConsumerRelease",
            "ApplyTaxonomyBundleToConsumer",
            "PublishPolicyBundle",
            "IssueAccessInvitation",
            "AcceptAccessInvitation",
            "CreateCreatorProfile",
            "CreateDemand",
        ],
        "real_funds": False,
        "real_person_data": False,
        "required_runtime_inputs": [
            "TAXONOMY_WORKLOAD_CREDENTIAL",
            "TAXONOMY_RECEIPT_HMAC_KEY",
            "IAM_POLICY_PUBLICATION_EVIDENCE",
            "INVITATION_TOKEN_MATERIAL",
            "OIDC_SANDBOX_BINDING",
            "COMMAND_IDEMPOTENCY_KEYS",
        ],
        "schema_name": "desire-internal-sandbox-synthetic-seed-v1",
        "synthetic": True,
        "taxonomy": {
            "bundle_id": TAXONOMY_BUNDLE_ID,
            "consumer_codes": ["DEMAND", "MATCHING", "PROFILE"],
            "family_code": "PLATFORM_WORK_V1",
            "release_manifest_sha256": "edd4b5bfc1c827080316c043420bfb42a2d3dd3c6eadd1fb65987e812d4836af",
            "selector_digest": "5d98033bf58eb10d03ebc301c1be971e53e23810d7ab77f644b7ff916a610931",
            "semantic_version": "1.0.0",
        },
        "taxonomy_seed_authority": {
            "authority_valid_until": "2100-01-01T00:00:00Z",
            "consumer_authorization_digest": "b1fc57d727ca30377601e05afd5eccdb787b59f82072a027a203934696496d33",
            "consumer_code": "PROFILE",
            "consumer_job_id": "internal_sandbox_profile_seed_job_v1",
            "credential_binding_mode": "RUNTIME_SHA256",
            "workload_attestation_sha256": "997cd36982083be3fd8f38e0069c2c20b342b1e89ba8e1225ce402fdfd46e501",
            "workload_principal_id": "internal_sandbox_taxonomy_seed_v1",
        },
    }


def encode(value) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )


class InternalSandboxSyntheticSeedTests(unittest.TestCase):
    def test_packaged_manifest_is_digest_pinned_immutable_and_synthetic_only(self) -> None:
        plan = load_internal_sandbox_synthetic_seed()

        self.assertIsInstance(plan, InternalSandboxSyntheticSeedPlan)
        self.assertEqual(plan.fixture_id, "internal-sandbox-g1-synthetic-v1")
        self.assertEqual(plan.manifest_sha256, INTERNAL_SANDBOX_SYNTHETIC_SEED_SHA256.hex())
        self.assertEqual(plan.taxonomy_bundle_id, TAXONOMY_BUNDLE_ID)
        self.assertEqual(plan.rule_requirement.taxonomy_bundle_id, TAXONOMY_BUNDLE_ID)
        self.assertEqual(
            plan.account_slot_codes,
            ("CREATOR", "DEMAND_OWNER"),
        )
        self.assertEqual(
            plan.business_resource_kinds,
            ("CREATOR_PROFILE", "DEMAND"),
        )
        self.assertEqual(plan.blockers, ())
        self.assertTrue(plan.is_executable)
        with self.assertRaises(FrozenInstanceError):
            plan.fixture_id = "changed"
        serialized = repr(plan).lower()
        for forbidden in ("email", "password", "oidc subject", "raw key"):
            self.assertNotIn(forbidden, serialized)

    def test_plan_validates_the_exact_authoritative_demand_policy_projection(self) -> None:
        plan = parse_internal_sandbox_synthetic_seed(
            encode(document()), expected_sha256=hashlib.sha256(encode(document())).digest()
        )
        requirement = DemandRuleRequirement(
            taxonomy_bundle_id=TAXONOMY_BUNDLE_ID,
            budget_rule_bundle_id="51000000-0000-4000-8000-000000000001",
            risk_rule_bundle_id="52000000-0000-4000-8000-000000000001",
            matching_rule_bundle_id="53000000-0000-4000-8000-000000000001",
            reason_code_bundle_id="54000000-0000-4000-8000-000000000001",
            composite_rule_requirement_id="55000000-0000-4000-8000-000000000001",
            effective_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
            effective_until=datetime(2100, 1, 1, tzinfo=timezone.utc),
            requirement_sha256="98ba1470ec6171ad33a9a8123cd855278241ac607f87ef4226b1f4f4a3bb88e3",
        )

        self.assertIsNone(plan.validate_rule_requirement(requirement))
        with self.assertRaises(InternalSandboxSyntheticSeedError) as raised:
            plan.validate_rule_requirement(
                DemandRuleRequirement(
                    **{
                        **requirement.__dict__,
                        "taxonomy_bundle_id": "50000000-0000-4000-8000-000000000002",
                    }
                )
            )
        self.assertEqual(raised.exception.code, "INTERNAL_SANDBOX_SYNTHETIC_SEED_BLOCKED")
        self.assertIsNone(plan.require_executable())

    def test_parser_rejects_real_data_funds_side_effects_drift_and_open_shapes(self) -> None:
        invalid = []
        for path, value in (
            (("synthetic",), False),
            (("real_person_data",), True),
            (("real_funds",), True),
            (("external_side_effects_enabled",), True),
            (("taxonomy", "bundle_id"), "50000000-0000-4000-8000-000000000002"),
            (("demand_rule_requirement", "requirement_sha256"), "0" * 64),
            (("account_slots", 0, "role_codes"), ["CREATOR", "ORG_ADMIN"]),
            (("business_drafts", 1, "funds_amount_minor"), 1),
            (("operation_sequence",), ["INSERT_ACTIVE_TAXONOMY"]),
            (("blockers",), ["OPEN_BLOCKER"]),
            (("taxonomy", "release_manifest_sha256"), "0" * 64),
            (("taxonomy_seed_authority", "consumer_code"), "DEMAND"),
        ):
            candidate = deepcopy(document())
            target = candidate
            for segment in path[:-1]:
                target = target[segment]
            target[path[-1]] = value
            invalid.append(candidate)
        unknown = deepcopy(document())
        unknown["email"] = "synthetic@example.invalid"
        invalid.append(unknown)

        for candidate in invalid:
            with self.subTest(candidate=candidate):
                raw = encode(candidate)
                with self.assertRaises(InternalSandboxSyntheticSeedError) as raised:
                    parse_internal_sandbox_synthetic_seed(
                        raw,
                        expected_sha256=hashlib.sha256(raw).digest(),
                    )
                self.assertEqual(
                    raised.exception.code,
                    "INVALID_INTERNAL_SANDBOX_SYNTHETIC_SEED",
                )
                self.assertNotIn("example.invalid", str(raised.exception))

        canonical = encode(document())
        duplicate = canonical.replace(
            b'"synthetic":true', b'"synthetic":true,"synthetic":true'
        )
        floating = canonical.replace(b'"funds_amount_minor":0', b'"funds_amount_minor":0.0', 1)
        for raw in (duplicate, floating, canonical[:-1], canonical + b"\n"):
            with self.assertRaises(InternalSandboxSyntheticSeedError):
                parse_internal_sandbox_synthetic_seed(
                    raw,
                    expected_sha256=hashlib.sha256(raw).digest(),
                )


if __name__ == "__main__":
    unittest.main()
