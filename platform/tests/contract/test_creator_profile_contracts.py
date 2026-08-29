"""Executable contracts for Creator Profile v1.

The checks intentionally import no production package.  A small closed-schema
evaluator covers the Draft 2020-12 keywords exercised by the fixtures so
unknown-field, enum, visibility, type, and event-envelope behavior remains
executable without adding a runtime JSON Schema dependency.
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
OPENAPI_PATH = PLATFORM_ROOT / "contracts/api/profile-v1.openapi.yaml"
EVENT_PATH = PLATFORM_ROOT / "contracts/events/profile-v1.schema.json"
VERSION_PATH = PLATFORM_ROOT / "contracts/domain/profile-version-v1.schema.json"


class _UniqueKeyLoader(yaml.SafeLoader):
    """Reject YAML mappings whose later key would silently overwrite a value."""


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
    with path.open(encoding="utf-8") as contract_file:
        if path.suffix == ".yaml":
            loaded = yaml.load(contract_file, Loader=_UniqueKeyLoader)
        else:
            loaded = json.load(contract_file, object_pairs_hook=_unique_json_pairs)
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
    if not separator:
        fragment = ""
    target_path = (document_path.parent / relative).resolve()
    target_document = _load(target_path)
    return target_document, target_path, _fragment(target_document, "#" + fragment)


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
        matches = sum(
            _matches(document, document_path, member, value)
            for member in schema["oneOf"]
        )
        if matches != 1:
            raise _SchemaViolation(f"{path}: expected exactly one schema, got {matches}")
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
        for name, child_schema in properties.items():
            if name in value:
                _validate(
                    document,
                    document_path,
                    child_schema,
                    value[name],
                    f"{path}.{name}",
                )

    if isinstance(value, list):
        minimum = schema.get("minItems")
        maximum = schema.get("maxItems")
        if isinstance(minimum, int) and len(value) < minimum:
            raise _SchemaViolation(f"{path}: too few items")
        if isinstance(maximum, int) and len(value) > maximum:
            raise _SchemaViolation(f"{path}: too many items")
        if schema.get("uniqueItems") is True:
            encoded = [
                json.dumps(item, sort_keys=True, separators=(",", ":"))
                for item in value
            ]
            if len(encoded) != len(set(encoded)):
                raise _SchemaViolation(f"{path}: duplicate items")
        for index, item in enumerate(value):
            _validate(
                document,
                document_path,
                schema.get("items", {}),
                item,
                f"{path}[{index}]",
            )

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
    metadata = {
        "visibility": "MATCH_ONLY",
        "source_kind": "SELF_ASSERTED",
        "evidence_ids": [],
    }
    private_metadata = {**metadata, "visibility": "PRIVATE"}
    return {
        "interests": [
            {
                "problem_code": "PROBLEM.CLIMATE",
                "domain_code": "DOMAIN.ENERGY",
                "task_code": "TASK.RESEARCH",
                "strength": 4,
                **metadata,
            }
        ],
        "skills": [
            {"skill_code": "SKILL.RESEARCH", "proficiency": 3, **metadata}
        ],
        "availability": {
            "available_from": "2026-08-09",
            "weekly_hours": 20,
            "duration_weeks": 12,
            "timezone": "Asia/Shanghai",
            **metadata,
        },
        "collaboration": {
            "languages": [
                {"language_code": "zh-CN", **metadata},
                {"language_code": "en", **metadata},
            ],
            "work_modes": [{"work_mode": "REMOTE", **metadata}],
            "feedback_cadence": {
                "feedback_cadence": "WEEKLY",
                **metadata,
            },
            "team_preference": {"team_preference": "SMALL_TEAM", **metadata},
        },
        "compensation": {
            "minimum_project_amount_minor": 100000,
            "currency": "CNY",
            "direct_cost_amount_minor": 20000,
            **private_metadata,
        },
        "boundaries": {
            "prohibited_domains": [
                {"code": "DOMAIN.GAMBLING", **private_metadata}
            ],
            "prohibited_tasks": [
                {"code": "TASK.SURVEILLANCE", **private_metadata}
            ],
            "allowed_data_sensitivity": {
                "data_sensitivity": "CONFIDENTIAL",
                **private_metadata,
            },
        },
        "location": {
            "region_code": "CN-SH",
            "visibility": "PUBLIC",
            "source_kind": "SELF_ASSERTED",
            "evidence_ids": [],
        },
        "conflicts": [
            {"organization_id": "organization_conflict_0001", **private_metadata}
        ],
        "ai": {
            "allowed": True,
            "requires_ai": False,
            "human_review_code": "REQUIRED",
            "prohibited_case_codes": ["AI.BIOMETRIC_SURVEILLANCE"],
            **metadata,
        },
    }


def _valid_version() -> dict[str, Any]:
    return {
        "profile_schema_version": 1,
        "canonicalization_version": "profile-version-json-v1",
        "profile_id": "profile_creator_0000001",
        "version_no": 1,
        "taxonomy_bundle_id": "taxonomy_bundle_000001",
        "content": _valid_content(),
    }


def _event(event_type: str) -> dict[str, Any]:
    common = {
        "event_id": "event_profile_0000001",
        "event_type": event_type,
        "schema_version": 1,
        "occurred_at": "2026-08-08T10:00:00Z",
        "aggregate_type": "CreatorProfile",
        "aggregate_id": "profile_creator_0000001",
        "aggregate_version": 2,
        "actor_kind": "USER",
        "actor_id": "user_creator_00000001",
        "original_actor_id": None,
        "correlation_id": "correlation_profile_001",
        "causation_id": "causation_profile_0001",
        "trace_id": "trace_profile_00000001",
        "organization_id": None,
    }
    if event_type == "CreatorProfileCreated":
        common["aggregate_version"] = 1
        common["payload"] = {
            "profile_id": "profile_creator_0000001",
            "owner_user_id": "user_creator_00000001",
            "status": "DRAFT",
        }
    elif event_type == "CreatorProfilePublished":
        common["payload"] = {
            "profile_id": "profile_creator_0000001",
            "profile_version_id": "profile_version_000001",
            "version_no": 1,
            "content_sha256": "a" * 64,
            "taxonomy_bundle_id": "taxonomy_bundle_000001",
            "status": "ACTIVE",
        }
    else:
        status = {
            "CreatorProfilePaused": "PAUSED",
            "CreatorProfileResumed": "ACTIVE",
            "CreatorProfileArchived": "ARCHIVED",
        }[event_type]
        common["payload"] = {
            "profile_id": "profile_creator_0000001",
            "owner_user_id": "user_creator_00000001",
            "status": status,
        }
    return common


class CreatorProfileOpenApiContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = _load(OPENAPI_PATH)
        cls.schemas = cls.contract["components"]["schemas"]

    def operation(self, path: str, method: str) -> dict[str, Any]:
        return self.contract["paths"][path][method]

    def parameter_names(self, operation: dict[str, Any]) -> set[str]:
        return {
            parameter["$ref"].rsplit("/", 1)[-1]
            for parameter in operation.get("parameters", [])
        }

    def response(self, operation: dict[str, Any], status: str) -> dict[str, Any]:
        reference = operation["responses"][status]["$ref"]
        return _resolve(self.contract, OPENAPI_PATH, reference)[2]

    def test_openapi_31_and_every_local_or_domain_reference_resolves(self) -> None:
        self.assertEqual(self.contract["openapi"], "3.1.0")
        self.assertEqual(
            self.contract["jsonSchemaDialect"],
            "https://json-schema.org/draft/2020-12/schema",
        )
        references = list(_walk_refs(self.contract))
        self.assertTrue(references)
        for reference in references:
            with self.subTest(reference=reference):
                _resolve(self.contract, OPENAPI_PATH, reference)

    def test_exact_path_and_operation_surface_is_seven_operations(self) -> None:
        self.assertEqual(
            set(self.contract["paths"]),
            {
                "/v1/me/creator-profile",
                "/v1/me/creator-profile/drafts",
                "/v1/me/creator-profile/drafts/{profile_version_id}/publish",
                "/v1/me/creator-profile/pause",
                "/v1/me/creator-profile/resume",
                "/v1/me/creator-profile/archive",
            },
        )
        operation_ids = [
            operation["operationId"]
            for path_item in self.contract["paths"].values()
            for method, operation in path_item.items()
            if method in {"get", "post", "put", "patch", "delete"}
        ]
        self.assertEqual(len(operation_ids), 7)
        self.assertEqual(len(set(operation_ids)), 7)

    def test_write_headers_freeze_create_exception_and_five_if_match_commands(self) -> None:
        writes = [
            (path, method, operation)
            for path, path_item in self.contract["paths"].items()
            for method, operation in path_item.items()
            if method == "post"
        ]
        self.assertEqual(len(writes), 6)
        for path, _method, operation in writes:
            names = self.parameter_names(operation)
            with self.subTest(path=path):
                self.assertTrue({"IdempotencyKey", "CsrfToken"}.issubset(names))
                if path == "/v1/me/creator-profile":
                    self.assertNotIn("IfMatch", names)
                else:
                    self.assertIn("IfMatch", names)

    def test_success_and_error_responses_are_no_store_traceable_and_etagged(self) -> None:
        for path, path_item in self.contract["paths"].items():
            for method, operation in path_item.items():
                if method not in {"get", "post"}:
                    continue
                for status in operation["responses"]:
                    response = self.response(operation, status)
                    with self.subTest(path=path, method=method, status=status):
                        self.assertIn("Cache-Control", response["headers"])
                        self.assertIn("X-Trace-Id", response["headers"])
                success = next(
                    status for status in operation["responses"] if status.startswith("2")
                )
                self.assertIn("ETag", self.response(operation, success)["headers"])

    def test_request_objects_are_closed_and_cannot_author_identity_or_server_facts(self) -> None:
        requests = {
            name: schema
            for name, schema in self.schemas.items()
            if name.endswith("Request")
        }
        self.assertEqual(len(requests), 6)
        forbidden = {
            "actor_id",
            "actor_user_id",
            "owner_user_id",
            "session_id",
            "role",
            "status",
            "aggregate_version",
            "content_sha256",
            "asserted_at",
            "confirmed_at",
            "legacy_source_ref",
        }
        for name, schema in requests.items():
            with self.subTest(schema=name):
                self.assertIs(schema["additionalProperties"], False)
                self.assertTrue(forbidden.isdisjoint(schema.get("properties", {})))
        with self.assertRaises(_SchemaViolation):
            _validate(
                self.contract,
                OPENAPI_PATH,
                self.schemas["CreateCreatorProfileRequest"],
                {"actor_user_id": "user_attacker_000001"},
            )
        with self.assertRaises(_SchemaViolation):
            _validate(
                self.contract,
                OPENAPI_PATH,
                self.schemas["PauseCreatorProfileRequest"],
                {"reason_code": "OWNER_REQUEST", "reason_note": "private"},
            )

    def test_all_typed_openapi_component_objects_are_closed(self) -> None:
        typed_objects = {
            name: schema
            for name, schema in self.schemas.items()
            if schema.get("type") == "object"
        }
        self.assertTrue(typed_objects)
        for name, schema in typed_objects.items():
            with self.subTest(schema=name):
                self.assertIs(schema.get("additionalProperties"), False)
                self.assertLessEqual(
                    set(schema.get("required", [])),
                    set(schema.get("properties", {})),
                )

    def test_profile_error_codes_and_http_response_vocabularies_are_exact(self) -> None:
        self.assertEqual(
            set(self.schemas["ProfileErrorCode"]["enum"]),
            {
                "INVALID_REQUEST",
                "AUTHENTICATION_REQUIRED",
                "SESSION_EXPIRED",
                "ACCESS_DENIED",
                "SAFETY_HOLD_BLOCKED",
                "RESOURCE_NOT_FOUND",
                "PROFILE_ALREADY_EXISTS",
                "INVALID_STATE_TRANSITION",
                "IDEMPOTENCY_KEY_REUSED",
                "TAXONOMY_BUNDLE_CHANGED",
                "POLICY_BUNDLE_CHANGED",
                "PRECONDITION_FAILED",
                "PROFILE_VALIDATION_FAILED",
                "POLICY_ACCEPTANCE_REQUIRED",
                "POLICY_CONFIGURATION_UNAVAILABLE",
                "SERVICE_UNAVAILABLE",
            },
        )
        response_codes = set()
        for response in self.contract["components"]["responses"].values():
            response_codes.update(response.get("x-error-codes", []))
        self.assertTrue(response_codes.issubset(set(self.schemas["ProfileErrorCode"]["enum"])))

    def test_profile_lifecycle_evidence_and_reason_enums_are_closed(self) -> None:
        self.assertEqual(
            self.schemas["CreatorProfileStatus"]["enum"],
            ["DRAFT", "ACTIVE", "PAUSED", "ARCHIVED"],
        )
        self.assertEqual(
            self.schemas["ProfileVersionStatus"]["enum"],
            ["DRAFT", "PUBLISHED", "SUPERSEDED", "DISCARDED", "RETIRED"],
        )
        self.assertEqual(
            self.schemas["CapabilityEvidenceStatus"]["enum"],
            ["SELF_ASSERTED", "PENDING_VERIFICATION", "VERIFIED", "REJECTED", "EXPIRED", "WITHDRAWN"],
        )
        self.assertEqual(
            self.schemas["PauseReasonCode"]["enum"],
            ["OWNER_REQUEST", "TEMPORARY_UNAVAILABILITY", "SAFETY_REVIEW"],
        )
        self.assertEqual(
            self.schemas["ArchiveReasonCode"]["enum"],
            ["OWNER_REQUEST", "ACCOUNT_CLOSURE", "SAFETY_REVIEW"],
        )

    def test_secret_locator_provider_and_legacy_fields_are_not_representable(self) -> None:
        property_names = {
            property_name
            for schema in self.schemas.values()
            if isinstance(schema, dict)
            for property_name in schema.get("properties", {})
        }
        forbidden = {
            "storage_locator",
            "evidence_locator",
            "provider_token",
            "provider_response",
            "provider_subject",
            "contact_locator",
            "exact_address",
            "raw_payload",
            "idempotency_key",
            "csrf_token",
            "session_secret",
            "legacy_source_ref",
        }
        self.assertEqual(property_names.intersection(forbidden), set())
        evidence_fields = set(self.schemas["CapabilityEvidenceDto"]["properties"])
        self.assertEqual(
            evidence_fields,
            {
                "evidence_id",
                "evidence_kind",
                "object_label",
                "claimed_skill_codes",
                "status",
                "verified_at",
                "expires_at",
                "aggregate_version",
            },
        )


class CreatorProfileVersionContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = _load(VERSION_PATH)

    def assert_valid(self, value: Any) -> None:
        _validate(self.contract, VERSION_PATH, self.contract, value)

    def assert_invalid(self, value: Any) -> None:
        with self.assertRaises(_SchemaViolation):
            self.assert_valid(value)

    def test_canonical_root_and_all_named_content_objects_are_closed(self) -> None:
        self.assertEqual(
            set(self.contract["required"]),
            {
                "profile_schema_version",
                "canonicalization_version",
                "profile_id",
                "version_no",
                "taxonomy_bundle_id",
                "content",
            },
        )
        self.assertIs(self.contract["additionalProperties"], False)
        for name, schema in self.contract["$defs"].items():
            if schema.get("type") == "object":
                with self.subTest(schema=name):
                    self.assertIs(schema.get("additionalProperties"), False)

    def test_valid_complete_content_and_incomplete_closed_draft_both_validate(self) -> None:
        self.assert_valid(_valid_version())
        draft = _valid_version()
        draft["content"].update(
            {
                "interests": [],
                "skills": [],
                "availability": None,
                "compensation": None,
                "boundaries": None,
                "location": None,
                "ai": None,
            }
        )
        self.assert_valid(draft)

    def test_unknown_root_group_and_nested_fields_are_rejected(self) -> None:
        for name, mutate in (
            ("root", lambda value: value.__setitem__("content_sha256", "a" * 64)),
            ("content", lambda value: value["content"].__setitem__("biography", "secret")),
            ("item", lambda value: value["content"]["skills"][0].__setitem__("provider_token", "secret")),
        ):
            with self.subTest(case=name):
                value = _valid_version()
                mutate(value)
                self.assert_invalid(value)

    def test_visibility_source_evidence_and_ai_limits_are_machine_enforced(self) -> None:
        invalid_values = []
        interest_public = _valid_version()
        interest_public["content"]["interests"][0]["visibility"] = "PUBLIC"
        invalid_values.append(interest_public)
        compensation_public = _valid_version()
        compensation_public["content"]["compensation"]["visibility"] = "MATCH_ONLY"
        invalid_values.append(compensation_public)
        verified_without_evidence = _valid_version()
        verified_without_evidence["content"]["skills"][0]["source_kind"] = "VERIFIED_EVIDENCE"
        invalid_values.append(verified_without_evidence)
        self_with_evidence = _valid_version()
        self_with_evidence["content"]["skills"][0]["evidence_ids"] = ["evidence_profile_000001"]
        invalid_values.append(self_with_evidence)
        requires_disallowed_ai = _valid_version()
        requires_disallowed_ai["content"]["ai"].update({"allowed": False, "requires_ai": True})
        invalid_values.append(requires_disallowed_ai)
        for index, value in enumerate(invalid_values):
            with self.subTest(case=index):
                self.assert_invalid(value)

    def test_integer_contract_rejects_boolean_strength_capacity_and_money(self) -> None:
        for path in ("strength", "proficiency", "weekly_hours", "amount"):
            value = _valid_version()
            if path == "strength":
                value["content"]["interests"][0]["strength"] = True
            elif path == "proficiency":
                value["content"]["skills"][0]["proficiency"] = True
            elif path == "weekly_hours":
                value["content"]["availability"]["weekly_hours"] = True
            else:
                value["content"]["compensation"]["minimum_project_amount_minor"] = True
            with self.subTest(path=path):
                self.assert_invalid(value)


class CreatorProfileEventContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = _load(EVENT_PATH)
        cls.definitions = cls.contract["$defs"]

    def assert_valid(self, value: Any) -> None:
        _validate(self.contract, EVENT_PATH, self.contract, value)

    def assert_invalid(self, value: Any) -> None:
        with self.assertRaises(_SchemaViolation):
            self.assert_valid(value)

    def test_draft_2020_12_refs_event_vocabulary_and_variants_are_exact(self) -> None:
        self.assertEqual(
            self.contract["$schema"],
            "https://json-schema.org/draft/2020-12/schema",
        )
        for reference in _walk_refs(self.contract):
            _resolve(self.contract, EVENT_PATH, reference)
        self.assertEqual(
            set(self.definitions["EventType"]["enum"]),
            {
                "CreatorProfileCreated",
                "CreatorProfilePublished",
                "CreatorProfilePaused",
                "CreatorProfileResumed",
                "CreatorProfileArchived",
            },
        )
        self.assertEqual(len(self.contract["oneOf"]), 5)

    def test_envelope_and_every_typed_payload_object_are_closed(self) -> None:
        for name, schema in self.definitions.items():
            if schema.get("type") == "object":
                with self.subTest(schema=name):
                    self.assertIs(schema.get("additionalProperties"), False)
                    self.assertLessEqual(
                        set(schema.get("required", [])),
                        set(schema.get("properties", {})),
                    )
        envelope = self.definitions["EventEnvelope"]
        self.assertEqual(envelope["properties"]["organization_id"]["type"], "null")
        self.assertEqual(envelope["properties"]["aggregate_type"]["const"], "CreatorProfile")

    def test_all_five_envelope_payload_pairs_validate(self) -> None:
        for event_type in self.definitions["EventType"]["enum"]:
            with self.subTest(event_type=event_type):
                self.assert_valid(_event(event_type))

    def test_unknown_envelope_payload_and_wrong_status_are_rejected(self) -> None:
        unknown_envelope = _event("CreatorProfileCreated")
        unknown_envelope["raw_payload"] = {"skills": ["secret"]}
        unknown_payload = _event("CreatorProfilePublished")
        unknown_payload["payload"]["compensation"] = {"currency": "CNY"}
        wrong_status = _event("CreatorProfilePaused")
        wrong_status["payload"]["status"] = "ACTIVE"
        for value in (unknown_envelope, unknown_payload, wrong_status):
            self.assert_invalid(value)

    def test_event_contract_cannot_represent_private_profile_or_protocol_fields(self) -> None:
        property_names = {
            property_name
            for schema in self.definitions.values()
            if isinstance(schema, dict)
            for property_name in schema.get("properties", {})
        }
        forbidden_fragments = (
            "skill",
            "availability",
            "compensation",
            "boundar",
            "conflict",
            "evidence",
            "legacy",
            "locator",
            "token",
            "cookie",
            "csrf",
            "session",
            "minimum_project",
            "currency",
            "raw_",
        )
        violations = {
            name
            for name in property_names
            if any(fragment in name for fragment in forbidden_fragments)
        }
        self.assertEqual(violations, set())
        self.assertEqual(
            set(self.definitions["CreatorProfilePublishedPayload"]["properties"]),
            {
                "profile_id",
                "profile_version_id",
                "version_no",
                "content_sha256",
                "taxonomy_bundle_id",
                "status",
            },
        )


if __name__ == "__main__":
    unittest.main()
