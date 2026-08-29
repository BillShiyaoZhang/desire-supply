"""Executable contract gates for Matching, Invitation and Selection v1."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Iterator
import unittest

from tests.contract.test_demand_contracts import (
    _SchemaViolation,
    _load,
    _resolve,
    _validate,
    _walk_refs,
)
from tests.support.matching_contract_builders import (
    COMPONENTS,
    HARD_FILTERS,
    candidate_result,
    event,
    input_manifest,
    invitation_disclosure,
    rule_release,
    run_input,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[2]
OPENAPI_PATH = PLATFORM_ROOT / "contracts/api/matching-v1.openapi.yaml"
EVENT_PATH = PLATFORM_ROOT / "contracts/events/matching-v1.schema.json"
DOMAIN_PATHS = (
    PLATFORM_ROOT / "contracts/domain/matching-rule-release-v1.schema.json",
    PLATFORM_ROOT / "contracts/domain/match-input-manifest-v1.schema.json",
    PLATFORM_ROOT / "contracts/domain/match-run-input-v1.schema.json",
    PLATFORM_ROOT / "contracts/domain/match-candidate-result-v1.schema.json",
    PLATFORM_ROOT / "contracts/domain/invitation-disclosure-v1.schema.json",
)

EVENT_TYPES = (
    "MatchingAttemptOpened", "MatchRunQueued", "MatchRunStarted",
    "MatchRunCompleted", "MatchRunFailed", "MatchRunSuperseded",
    "InvitationCreated", "InvitationSent", "InvitationAccepted",
    "InvitationDeclined", "InvitationWithdrawn", "InvitationRevoked", "InvitationExpired",
    "SelectionOpened", "SelectionInvitationSetChanged", "SelectionIntentRecorded", "SelectionCloseIntentRecorded", "SelectionMade", "SelectionClosedWithoutChoice",
    "SelectionCancelled", "MatchingAttemptSelected",
    "MatchingAttemptClosedWithoutSelection", "MatchingAttemptInvalidated",
    "MatchingAttemptCancelled", "CandidateSelectorAssigned",
    "MatchingRulePublished", "MatchJobClaimed", "MatchRunRetryScheduled",
    "SelectionCompletionClaimed", "SelectionCompletionFailed",
    "SelectionCompletionRetryScheduled", "MatchingReviewAssignmentClaimed",
    "MatchingReviewAssignmentReleased",
)

BANNED_FRAGMENTS = (
    "private_floor_amount", "floor_amount", "score_input", "contact", "session_id",
    "idempotency_key", "decline_note", "review_note", "provider_locator",
    "evidence_locator", "excluded_creator", "protected_attribute",
)


def _property_names(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        properties = value.get("properties")
        if isinstance(properties, dict):
            yield from properties
        for child in value.values():
            yield from _property_names(child)
    elif isinstance(value, list):
        for child in value:
            yield from _property_names(child)


def _assert_valid(test: unittest.TestCase, path: Path, instance: Any) -> None:
    document = _load(path)
    _validate(document, path, document, instance)


def _assert_invalid(test: unittest.TestCase, path: Path, instance: Any) -> None:
    document = _load(path)
    with test.assertRaises(_SchemaViolation):
        _validate(document, path, document, instance)


class MatchingContractTests(unittest.TestCase):
    def test_all_matching_contracts_are_independent_and_refs_resolve(self) -> None:
        paths = (OPENAPI_PATH, EVENT_PATH, *DOMAIN_PATHS)
        for path in paths:
            with self.subTest(path=path.name):
                document = _load(path)
                self.assertIsInstance(document, dict)
                for reference in _walk_refs(document):
                    _resolve(document, path, reference)

    def test_openapi_publishes_exact_v1_routes_without_worker_or_complete_selection(self) -> None:
        document = _load(OPENAPI_PATH)
        self.assertEqual(document["openapi"], "3.1.0")
        self.assertEqual(
            set(document["paths"]),
            {
                "/v1/me/matching-invitations",
                "/v1/me/matching-invitations/{invitation_id}",
                "/v1/me/matching-invitations/{invitation_id}/accept",
                "/v1/me/matching-invitations/{invitation_id}/decline",
                "/v1/me/matching-invitations/{invitation_id}/withdraw",
                "/v1/organizations/{organization_id}/demands/{demand_id}/matching-attempts",
                "/v1/organizations/{organization_id}/matching-attempts/{attempt_id}/selection",
                "/v1/organizations/{organization_id}/selections/{selection_id}/choose",
                "/v1/organizations/{organization_id}/selections/{selection_id}/close",
                "/v1/operations/match-runs/{match_run_id}/invitations",
                "/v1/operations/matching-invitations/{invitation_id}/publish",
                "/v1/operations/matching-attempts/{attempt_id}/invalidate",
            },
        )
        operations = {
            operation["operationId"].lower()
            for path_item in document["paths"].values()
            for method, operation in path_item.items()
            if method in {"get", "post", "put", "patch", "delete"}
        }
        self.assertNotIn("completeselection", operations)
        self.assertNotIn("startmatchrun", operations)

    def test_openapi_mutations_are_closed_keyed_etagged_and_csrf_bound(self) -> None:
        document = _load(OPENAPI_PATH)
        schemas = document["components"]["schemas"]
        etag_pattern = '^"v[1-9][0-9]*"$'
        self.assertEqual(
            document["components"]["parameters"]["IfMatch"]["schema"][
                "pattern"
            ],
            etag_pattern,
        )
        for response_name in (
            "RecipientInvitationRead",
            "ReviewerInvitationRead",
            "AttemptRead",
            "SelectionRead",
        ):
            self.assertEqual(
                document["components"]["responses"][response_name]["headers"]
                ["ETag"]["schema"]["pattern"],
                etag_pattern,
            )
        request_names = {
            "AcceptInvitationRequest", "DeclineInvitationRequest",
            "WithdrawInvitationRequest",
            "ChooseSelectionRequest", "CloseSelectionRequest",
            "CreateInvitationRequest", "PublishInvitationRequest",
            "InvalidateAttemptRequest",
        }
        for name in request_names:
            self.assertIs(schemas[name]["additionalProperties"], False, name)
        for path_item in document["paths"].values():
            operation = path_item.get("post")
            if operation is None:
                continue
            parameter_refs = {item.get("$ref") for item in operation["parameters"]}
            self.assertIn("#/components/parameters/IdempotencyKey", parameter_refs)
            self.assertIn("#/components/parameters/IfMatch", parameter_refs)
            self.assertIn("#/components/parameters/CsrfToken", parameter_refs)
            self.assertTrue(operation["x-error-codes"])

    def test_public_contract_cannot_represent_matching_private_facts(self) -> None:
        documents = [_load(OPENAPI_PATH), _load(EVENT_PATH)]
        documents.extend(_load(path) for path in DOMAIN_PATHS[2:])
        names = {name.lower() for document in documents for name in _property_names(document)}
        for banned in BANNED_FRAGMENTS:
            with self.subTest(banned=banned):
                self.assertFalse(any(banned in name for name in names))
        self.assertNotIn("rank", {name.lower() for name in _property_names(_load(OPENAPI_PATH))})
        self.assertNotIn("score", {name.lower() for name in _property_names(_load(EVENT_PATH))})

    def test_recipient_and_selector_reads_are_human_usable_without_ranking_leaks(self) -> None:
        document = _load(OPENAPI_PATH)
        schemas = document["components"]["schemas"]
        recipient = schemas["RecipientInvitationDto"]
        self.assertEqual(
            recipient["properties"]["disclosure"]["$ref"],
            "../domain/invitation-disclosure-v1.schema.json",
        )
        self.assertIn("WITHDRAWN", recipient["properties"]["status"]["enum"])
        selection = schemas["SelectionDto"]
        self.assertIn("candidate_selector_assignment_id", selection["required"])
        self.assertIn("candidate_selector_assignment_version", selection["required"])
        self.assertIn("accepted_invitations", selection["required"])
        for request_name in ("ChooseSelectionRequest", "CloseSelectionRequest"):
            request = schemas[request_name]
            self.assertTrue(
                {
                    "candidate_selector_assignment_id",
                    "candidate_selector_assignment_version",
                }.issubset(request["required"])
            )
        candidate = schemas["SelectionCandidateDto"]
        self.assertEqual(
            set(candidate["properties"]),
            {
                "invitation_id",
                "creator_display_handle",
                "profile_id",
                "profile_version_id",
                "accepted_at",
                "capability_summary",
            },
        )
        names = {name.lower() for name in _property_names(candidate)}
        self.assertNotIn("rank", names)
        self.assertNotIn("score", names)

    def test_rule_release_is_closed_integer_weighted_and_complete(self) -> None:
        path = DOMAIN_PATHS[0]
        valid = rule_release()
        _assert_valid(self, path, valid)
        self.assertEqual(tuple(row["code"] for row in valid["hard_filters"]), HARD_FILTERS)
        self.assertEqual(tuple(row["ordinal"] for row in valid["hard_filters"]), tuple(range(1, 16)))
        self.assertEqual(tuple((row["code"], row["weight_bps"]) for row in valid["components"]), COMPONENTS)
        self.assertEqual(sum(row["weight_bps"] for row in valid["components"]), 10000)
        for mutation in (
            lambda value: value.update(signature="secret"),
            lambda value: value["components"][0].update(weight_bps=True),
            lambda value: value["hard_filters"].pop(),
        ):
            broken = deepcopy(valid)
            mutation(broken)
            _assert_invalid(self, path, broken)

    def test_input_manifest_accepts_zero_candidates_but_is_closed(self) -> None:
        path = DOMAIN_PATHS[1]
        _assert_valid(self, path, input_manifest())
        _assert_valid(self, path, input_manifest(empty=True))
        broken = input_manifest()
        broken["ordered_candidates"][0]["contact"] = "forbidden@example.invalid"
        _assert_invalid(self, path, broken)

    def test_private_run_input_uses_exact_values_and_rejects_bool_as_integer(self) -> None:
        path = DOMAIN_PATHS[2]
        _assert_valid(self, path, run_input())
        _assert_valid(self, path, run_input(empty=True))
        for member, value in (("private_floor_amount_minor", 12345), ("contact", "secret")):
            broken = run_input()
            broken["profiles"][0][member] = value
            _assert_invalid(self, path, broken)
        broken = run_input()
        broken["profiles"][0]["interest_intensity"] = True
        _assert_invalid(self, path, broken)

    def test_candidate_result_conditionals_and_score_strings_are_closed(self) -> None:
        path = DOMAIN_PATHS[3]
        _assert_valid(self, path, candidate_result(eligible=True))
        _assert_valid(self, path, candidate_result(eligible=False))
        broken = candidate_result(eligible=True)
        broken["total_score"] = 80.0
        _assert_invalid(self, path, broken)
        broken = candidate_result(eligible=False)
        broken["rank"] = 1
        _assert_invalid(self, path, broken)
        broken = candidate_result(eligible=True)
        broken["private_floor_amount_minor"] = 100000
        _assert_invalid(self, path, broken)

    def test_invitation_disclosure_is_closed_and_offered_range_is_integer(self) -> None:
        path = DOMAIN_PATHS[4]
        _assert_valid(self, path, invitation_disclosure())
        for location, key, value in (
            ("root", "rank", 1),
            ("offer", "private_floor_amount_minor", 99999),
            ("offer", "minimum_amount_minor", True),
        ):
            broken = invitation_disclosure()
            target = broken if location == "root" else broken[location]
            target[key] = value
            _assert_invalid(self, path, broken)

    def test_event_schema_accepts_all_closed_event_types(self) -> None:
        for event_type in EVENT_TYPES:
            with self.subTest(event_type=event_type):
                _assert_valid(self, EVENT_PATH, event(event_type))
                broken = event(event_type)
                broken["payload"]["status"] = "WRONG_STATUS"
                _assert_invalid(self, EVENT_PATH, broken)

    def test_events_reject_extra_money_score_note_and_secret_fields(self) -> None:
        for field, value in (
            ("minimum_amount_minor", 100), ("total_score", "99.00"),
            ("note", "private"), ("idempotency_key", "raw-secret"),
        ):
            broken = event("InvitationSent")
            broken["payload"][field] = value
            with self.subTest(field=field):
                _assert_invalid(self, EVENT_PATH, broken)


if __name__ == "__main__":
    unittest.main()
