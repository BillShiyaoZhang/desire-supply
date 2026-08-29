"""Executable machine-contract gates for Demand v1.

The tests import no production Demand package.  A deliberately small Draft
2020-12 evaluator exercises the schema keywords used by the committed fixtures
so closed objects, primitive types, conditionals, enums, and references remain
an executable boundary without adding a runtime schema dependency.
"""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import re
from typing import Any, Iterator
import unittest

import yaml


PLATFORM_ROOT = Path(__file__).resolve().parents[2]
OPENAPI_PATH = PLATFORM_ROOT / "contracts/api/demand-v1.openapi.yaml"
EVENT_PATH = PLATFORM_ROOT / "contracts/events/demand-v1.schema.json"
CONTENT_PATH = PLATFORM_ROOT / "contracts/domain/demand-content-v1.schema.json"


class _UniqueKeyLoader(yaml.SafeLoader):
    """Reject YAML mappings whose later key would otherwise replace a value."""


def _construct_unique_mapping(
    loader: _UniqueKeyLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise AssertionError(
                f"duplicate YAML key {key!r} at line {key_node.start_mark.line + 1}"
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _unique_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AssertionError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


_DOCUMENTS: dict[Path, dict[str, Any]] = {}


def _load(path: Path) -> dict[str, Any]:
    path = path.resolve()
    cached = _DOCUMENTS.get(path)
    if cached is not None:
        return cached
    with path.open(encoding="utf-8") as source:
        loaded = (
            yaml.load(source, Loader=_UniqueKeyLoader)
            if path.suffix == ".yaml"
            else json.load(source, object_pairs_hook=_unique_json_pairs)
        )
    if not isinstance(loaded, dict):
        raise AssertionError(f"contract root is not an object: {path}")
    _DOCUMENTS[path] = loaded
    return loaded


def _fragment(document: dict[str, Any], fragment: str) -> Any:
    if fragment in ("", "#"):
        return document
    if not fragment.startswith("#/"):
        raise AssertionError(f"unsupported JSON pointer: {fragment}")
    current: Any = document
    for encoded in fragment[2:].split("/"):
        part = encoded.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or part not in current:
            raise AssertionError(f"unresolved JSON pointer: {fragment}")
        current = current[part]
    return current


def _resolve(
    document: dict[str, Any],
    document_path: Path,
    reference: str,
) -> tuple[dict[str, Any], Path, Any]:
    if reference.startswith("#"):
        return document, document_path, _fragment(document, reference)
    relative, separator, fragment = reference.partition("#")
    target_path = (document_path.parent / relative).resolve()
    target_document = _load(target_path)
    return (
        target_document,
        target_path,
        _fragment(target_document, "#" + fragment if separator else "#"),
    )


def _walk_refs(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        reference = value.get("$ref")
        if isinstance(reference, str):
            yield reference
        for child in value.values():
            yield from _walk_refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_refs(child)


class _SchemaViolation(AssertionError):
    pass


def _matches(
    document: dict[str, Any],
    document_path: Path,
    schema: Any,
    value: Any,
) -> bool:
    try:
        _validate(document, document_path, schema, value)
    except _SchemaViolation:
        return False
    return True


def _validate(
    document: dict[str, Any],
    document_path: Path,
    schema: Any,
    value: Any,
    path: str = "$",
) -> None:
    if not isinstance(schema, dict):
        return
    reference = schema.get("$ref")
    if isinstance(reference, str):
        target_document, target_path, target = _resolve(
            document, document_path, reference
        )
        _validate(target_document, target_path, target, value, path)

    for member in schema.get("allOf", []):
        _validate(document, document_path, member, value, path)
    if "oneOf" in schema:
        count = sum(
            _matches(document, document_path, member, value)
            for member in schema["oneOf"]
        )
        if count != 1:
            raise _SchemaViolation(f"{path}: expected one schema, got {count}")
    if "if" in schema:
        branch = "then" if _matches(document, document_path, schema["if"], value) else "else"
        if branch in schema:
            _validate(document, document_path, schema[branch], value, path)

    if "const" in schema and value != schema["const"]:
        raise _SchemaViolation(f"{path}: const mismatch")
    if "enum" in schema and value not in schema["enum"]:
        raise _SchemaViolation(f"{path}: enum mismatch")

    expected_type = schema.get("type")
    type_matches = {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }
    if isinstance(expected_type, str) and not type_matches.get(expected_type, True):
        raise _SchemaViolation(f"{path}: expected {expected_type}")

    if isinstance(value, dict):
        required = set(schema.get("required", []))
        missing = required.difference(value)
        if missing:
            raise _SchemaViolation(f"{path}: missing {sorted(missing)}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            unknown = set(value).difference(properties)
            if unknown:
                raise _SchemaViolation(f"{path}: unknown {sorted(unknown)}")
        maximum = schema.get("maxProperties")
        if isinstance(maximum, int) and len(value) > maximum:
            raise _SchemaViolation(f"{path}: too many properties")
        for name, child_schema in properties.items():
            if name in value:
                _validate(document, document_path, child_schema, value[name], f"{path}.{name}")

    if isinstance(value, list):
        minimum = schema.get("minItems")
        maximum = schema.get("maxItems")
        if isinstance(minimum, int) and len(value) < minimum:
            raise _SchemaViolation(f"{path}: too few items")
        if isinstance(maximum, int) and len(value) > maximum:
            raise _SchemaViolation(f"{path}: too many items")
        if schema.get("uniqueItems") is True:
            encoded = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in value]
            if len(encoded) != len(set(encoded)):
                raise _SchemaViolation(f"{path}: duplicate items")
        for index, item in enumerate(value):
            _validate(document, document_path, schema.get("items", {}), item, f"{path}[{index}]")

    if isinstance(value, str):
        minimum = schema.get("minLength")
        maximum = schema.get("maxLength")
        if isinstance(minimum, int) and len(value) < minimum:
            raise _SchemaViolation(f"{path}: string too short")
        if isinstance(maximum, int) and len(value) > maximum:
            raise _SchemaViolation(f"{path}: string too long")
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.search(pattern, value) is None:
            raise _SchemaViolation(f"{path}: pattern mismatch")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if minimum is not None and value < minimum:
            raise _SchemaViolation(f"{path}: below minimum")
        if maximum is not None and value > maximum:
            raise _SchemaViolation(f"{path}: above maximum")


def _valid_content() -> dict[str, Any]:
    return {
        "problem": {
            "background": "Reduce energy waste in community buildings.",
            "domain_code": "DOMAIN.ENERGY",
            "problem_type_codes": ["PROBLEM.EFFICIENCY"],
            "target_user_category_codes": ["USER.COMMUNITY_MANAGER"],
            "desired_outcomes": ["A reproducible energy reduction plan."],
        },
        "scope": {
            "deliverables": [{"item_id": "energy_plan", "description": "Validated plan and evidence summary."}],
            "out_of_scope": ["Building construction."],
        },
        "acceptance": {
            "criteria": [{"criterion_id": "measurable", "description": "Recommendations include measurable baselines."}],
            "response_days": 10,
            "owner_role_code": "DEMAND_OWNER",
        },
        "skills": {
            "must_have": [{"skill_code": "SKILL.ENERGY_ANALYSIS", "minimum_level_code": "ADVANCED"}],
            "nice_to_have": [{"skill_code": "SKILL.FACILITATION", "minimum_level_code": "WORKING"}],
        },
        "matching": {
            "problem_codes": ["PROBLEM.EFFICIENCY"],
            "domain_codes": ["DOMAIN.ENERGY"],
            "task_codes": ["TASK.RESEARCH"],
        },
        "schedule": {
            "start_date": "2026-09-01",
            "due_date": "2026-10-31",
            "estimated_days": 30,
            "weekly_hours": 20,
            "duration_weeks": 8,
        },
        "budget": {
            "minimum_amount_minor": 100000,
            "maximum_amount_minor": 200000,
            "direct_cost_amount_minor": 20000,
            "currency": "CNY",
        },
        "milestone_plan": {
            "items": [
                {"item_id": "discovery", "label": "Discovery", "percent": 40},
                {"item_id": "plan", "label": "Final plan", "percent": 60},
            ]
        },
        "risk": {
            "uncertainty_code": "MEDIUM",
            "urgency_code": "LOW",
            "dependency_codes": ["DEPENDENCY.DATA_ACCESS"],
            "data_sensitivity": "HIGH",
            "data_handling_plan": "Use minimized synthetic extracts and controlled access.",
        },
        "ai": {
            "allowed": True,
            "required": False,
            "data_model_policy": "Only approved regional models may process minimized extracts.",
            "human_review_code": "ALWAYS",
        },
        "collaboration": {
            "languages": ["zh-CN", "en"],
            "work_mode": "HYBRID",
            "feedback_cadence": "WEEKLY",
            "team_preference": "SMALL_TEAM",
        },
        "location": {
            "demand_region_code": "CN-SH",
            "allowed_creator_region_codes": ["CN-SH", "CN-ZJ"],
        },
        "declarations": {
            "decision_authority": True,
            "data_rights": True,
            "procurement_intent": True,
        },
    }


class DemandMachineContractTests(unittest.TestCase):
    """TEST-CONTRACT-DEMAND-001 and TEST-EVENT-DEMAND-001."""

    def test_all_contract_documents_have_unique_keys_and_resolvable_references(self) -> None:
        for path in (OPENAPI_PATH, EVENT_PATH, CONTENT_PATH):
            document = _load(path)
            for reference in _walk_refs(document):
                _resolve(document, path, reference)

    def test_openapi_operation_and_header_matrix_is_exact(self) -> None:
        document = _load(OPENAPI_PATH)
        operations = {
            (path, method): operation["operationId"]
            for path, item in document["paths"].items()
            for method, operation in item.items()
            if method in {"get", "post"}
        }
        self.assertEqual(
            set(operations.values()),
            {
                "createDemand",
                "getDemand",
                "createDemandVersion",
                "submitDemand",
                "cancelDemand",
                "getAssignedDemand",
                "releaseDemandReviewAssignment",
                "requestDemandChanges",
                "verifyDemand",
                "requestInitialDemandFunding",
                "requestDemandMatching",
            },
        )
        for (path, method), _operation_id in operations.items():
            operation = document["paths"][path][method]
            if method == "post":
                refs = {parameter.get("$ref") for parameter in operation["parameters"]}
                self.assertIn("#/components/parameters/IdempotencyKey", refs)
                if operation["operationId"] != "createDemand":
                    self.assertIn("#/components/parameters/IfMatch", refs)
            for response in operation["responses"].values():
                reference = response.get("$ref")
                self.assertIsInstance(reference, str)

        responses = document["components"]["responses"]
        for name in ("DemandCreated", "DemandUpdated", "DemandRead", "DemandReviewRead", "Error"):
            self.assertEqual(
                responses[name]["headers"]["Cache-Control"],
                {"$ref": "#/components/headers/CacheControl"},
            )

    def test_request_objects_are_closed_and_cannot_accept_server_authority_or_facts(self) -> None:
        schemas = _load(OPENAPI_PATH)["components"]["schemas"]
        request_names = (
            "CreateDemandRequest",
            "CreateDemandVersionRequest",
            "ReleaseDemandReviewAssignmentRequest",
            "RequestDemandChangesRequest",
            "VerifyDemandRequest",
            "CancelDemandRequest",
            "EmptyCommandRequest",
        )
        forbidden = {
            "actor_id",
            "user_id",
            "session_id",
            "organization_id",
            "role",
            "status",
            "aggregate_version",
            "content_sha256",
            "funding_status",
            "matching_status",
            "provider_evidence",
            "server_time",
        }
        for name in request_names:
            schema = schemas[name]
            self.assertEqual(schema["type"], "object")
            self.assertIs(schema["additionalProperties"], False)
            self.assertTrue(forbidden.isdisjoint(schema.get("properties", {})))
        self.assertEqual(schemas["EmptyCommandRequest"]["maxProperties"], 0)

    def test_review_assignment_release_contract_is_closed_and_returns_demand_update(self) -> None:
        document = _load(OPENAPI_PATH)
        operation = document["paths"][
            "/v1/operations/demand-review-assignments/{assignment_id}/release"
        ]["post"]
        self.assertEqual(operation["operationId"], "releaseDemandReviewAssignment")
        self.assertEqual(
            operation["requestBody"]["content"]["application/json"]["schema"],
            {"$ref": "#/components/schemas/ReleaseDemandReviewAssignmentRequest"},
        )
        self.assertEqual(operation["responses"]["200"], {"$ref": "#/components/responses/DemandUpdated"})

        request = document["components"]["schemas"]["ReleaseDemandReviewAssignmentRequest"]
        self.assertEqual(request["required"], ["reason_code"])
        self.assertEqual(
            request["properties"]["reason_code"]["enum"],
            ["CONFLICT_DECLARED", "WORKLOAD_RELEASE"],
        )
        self.assertIs(request["additionalProperties"], False)

    def test_content_schema_accepts_complete_and_partial_drafts_but_rejects_shape_attacks(self) -> None:
        document = _load(CONTENT_PATH)
        schema = document
        surface = {
            "demand_schema_version": 1,
            "canonicalization_version": "demand-content-json-v1",
            "demand_id": "demand_contract_000001",
            "version_no": 1,
            "taxonomy_bundle_id": "taxonomy_bundle_000001",
            "content": _valid_content(),
        }
        _validate(document, CONTENT_PATH, schema, surface)
        partial = deepcopy(surface)
        partial["content"] = {"problem": surface["content"]["problem"]}
        _validate(document, CONTENT_PATH, schema, partial)

        invalid_cases = []
        unknown = deepcopy(surface)
        unknown["content"]["provider_payload"] = "secret"
        invalid_cases.append(unknown)
        nested_unknown = deepcopy(surface)
        nested_unknown["content"]["budget"]["payment_token"] = "secret"
        invalid_cases.append(nested_unknown)
        bool_amount = deepcopy(surface)
        bool_amount["content"]["budget"]["minimum_amount_minor"] = True
        invalid_cases.append(bool_amount)
        bool_percent = deepcopy(surface)
        bool_percent["content"]["milestone_plan"]["items"][0]["percent"] = True
        invalid_cases.append(bool_percent)
        ai_required_but_denied = deepcopy(surface)
        ai_required_but_denied["content"]["ai"].update({"required": True, "allowed": False})
        invalid_cases.append(ai_required_but_denied)
        high_without_plan = deepcopy(surface)
        high_without_plan["content"]["risk"]["data_handling_plan"] = None
        invalid_cases.append(high_without_plan)
        for invalid in invalid_cases:
            with self.assertRaises(_SchemaViolation):
                _validate(document, CONTENT_PATH, schema, invalid)

    def test_content_group_matrix_and_static_bounds_are_frozen(self) -> None:
        definitions = _load(CONTENT_PATH)["$defs"]
        content = definitions["DemandContent"]
        self.assertEqual(
            set(content["properties"]),
            {"problem", "scope", "acceptance", "skills", "matching", "schedule", "budget", "milestone_plan", "risk", "ai", "collaboration", "location", "declarations"},
        )
        self.assertNotIn("required", content)
        self.assertEqual(definitions["Text4000"]["maxLength"], 4000)
        self.assertEqual(definitions["Text2000"]["maxLength"], 2000)
        for field in ("minimum_amount_minor", "maximum_amount_minor", "direct_cost_amount_minor"):
            self.assertEqual(definitions["Budget"]["properties"][field]["type"], "integer")
        self.assertEqual(definitions["MilestonePlanItem"]["properties"]["percent"]["maximum"], 100)

    def test_event_envelopes_and_payloads_are_closed_and_privacy_minimal(self) -> None:
        document = _load(EVENT_PATH)
        definitions = document["$defs"]
        expected = {
            "DemandCreated", "DemandVersionCreated", "DemandSubmitted", "DemandReviewClaimed", "DemandReviewAssignmentReleased", "DemandChangesRequested", "DemandVerified", "DemandFundingRequested", "DemandFundingReviewClaimed", "DemandFundingEvidenceConfirmed", "DemandFunded", "DemandFundingReviewAssignmentReleased", "DemandFundingReviewFindingSubmitted", "DemandFundingReset", "MatchingRequested", "DemandMatchingClosedWithoutSelection", "DemandMatched", "DemandCancelled", "DemandExpired"
        }
        self.assertEqual(set(definitions["EventType"]["enum"]), expected)
        self.assertIs(definitions["EventEnvelope"]["additionalProperties"], False)
        forbidden_payload_fields = {
            "content", "background", "description", "budget", "amount", "currency", "client_reference", "legacy_source_ref", "assignment_user_id", "review_note", "provider_evidence", "idempotency_key", "session_id", "csrf_token"
        }
        payload_definitions = [
            value
            for name, value in definitions.items()
            if name.endswith("Payload") and isinstance(value, dict)
        ]
        for payload in payload_definitions:
            if "properties" in payload:
                self.assertIs(payload["additionalProperties"], False)
                self.assertTrue(forbidden_payload_fields.isdisjoint(payload["properties"]))

    def test_demand10_finance_event_payloads_match_closed_producer_shapes(self) -> None:
        document = _load(EVENT_PATH)

        def envelope(event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
            return {
                "event_id": "event_demand10_0001",
                "event_type": event_type,
                "schema_version": 1,
                "occurred_at": "2026-08-19T12:00:00Z",
                "aggregate_type": "Demand",
                "aggregate_id": "demand_demand10_001",
                "aggregate_version": 5,
                "actor_kind": "USER",
                "actor_id": "finance_actor_00001",
                "original_actor_id": None,
                "correlation_id": "correlation_000001",
                "causation_id": "causation_0000001",
                "trace_id": "trace_demand10_001",
                "organization_id": "organization_000001",
                "payload": payload,
            }

        common = {
            "demand_id": "demand_demand10_001",
            "demand_version_id": "demand_version_0001",
            "funding_requirement_id": "funding_review_00001",
        }
        events = (
            envelope("DemandFundingRequested", {
                **common,
                "status": "FUNDING_PENDING",
            }),
            envelope("DemandFundingReviewClaimed", {
                **common,
                "confirmation_count": 0,
                "status": "FUNDING_PENDING",
            }),
            envelope("DemandFundingReviewAssignmentReleased", {
                **common,
                "reason_code": "WORKLOAD_RELEASE",
                "status": "FUNDING_PENDING",
            }),
            envelope("DemandFundingReviewFindingSubmitted", {
                **common,
                "disposition": "REJECTED",
                "reason_codes": ["BUDGET_PLAN_UNACCEPTABLE"],
                "required_field_codes": ["BUDGET"],
                "revoked_peer_assignment_count": 1,
                "status": "NEEDS_CHANGES",
            }),
        )
        for event in events:
            _validate(document, EVENT_PATH, document, event)
        invalid = deepcopy(events[-1])
        invalid["payload"].update({
            "disposition": "DISCREPANCY",
            "status": "NEEDS_CHANGES",
        })
        with self.assertRaises(_SchemaViolation):
            _validate(document, EVENT_PATH, document, invalid)

    def test_review_assignment_release_event_has_exact_public_payload(self) -> None:
        document = _load(EVENT_PATH)
        event = {
            "event_id": "event_release_000001",
            "event_type": "DemandReviewAssignmentReleased",
            "schema_version": 1,
            "occurred_at": "2026-08-26T12:00:00Z",
            "aggregate_type": "Demand",
            "aggregate_id": "demand_release_00001",
            "aggregate_version": 4,
            "actor_kind": "USER",
            "actor_id": "reviewer_actor_001",
            "original_actor_id": None,
            "correlation_id": "correlation_000001",
            "causation_id": "causation_release_01",
            "trace_id": "trace_release_0001",
            "organization_id": "organization_000001",
            "payload": {
                "demand_id": "demand_release_00001",
                "demand_version_id": "demand_version_0001",
                "assignment_id": "assignment_release01",
                "reason_code": "CONFLICT_DECLARED",
                "status": "SUBMITTED",
            },
        }
        _validate(document, EVENT_PATH, document, event)

        for field, value in (
            ("reason_code", "ASSIGNMENT_EXPIRED"),
            ("status", "NEEDS_CHANGES"),
            ("reviewer_user_id", "reviewer_actor_001"),
        ):
            invalid = deepcopy(event)
            invalid["payload"][field] = value
            with self.subTest(field=field), self.assertRaises(_SchemaViolation):
                _validate(document, EVENT_PATH, document, invalid)

    def test_error_codes_are_the_closed_design_set(self) -> None:
        codes = set(_load(OPENAPI_PATH)["components"]["schemas"]["ErrorCode"]["enum"])
        self.assertEqual(
            codes,
            {"INVALID_REQUEST", "AUTHENTICATION_REQUIRED", "SESSION_EXPIRED", "ACCESS_DENIED", "SAFETY_HOLD_BLOCKED", "RESOURCE_NOT_FOUND", "DEMAND_ALREADY_EXISTS", "INVALID_STATE_TRANSITION", "IDEMPOTENCY_KEY_REUSED", "TAXONOMY_BUNDLE_CHANGED", "FUNDING_FACT_CHANGED", "MATCHING_RULE_BUNDLE_CHANGED", "PRECONDITION_FAILED", "DEMAND_VALIDATION_FAILED", "POLICY_ACCEPTANCE_REQUIRED", "REVIEW_CONFLICT", "FUNDING_REQUIRED", "POLICY_CONFIGURATION_UNAVAILABLE", "SERVICE_UNAVAILABLE"},
        )


if __name__ == "__main__":
    unittest.main()
