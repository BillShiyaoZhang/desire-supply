from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from importlib import resources
import json
from pathlib import Path
import re
from typing import Any
from uuid import UUID

import yaml


ROOT = Path(__file__).resolve().parents[2] / "contracts"
OPENAPI = ROOT / "api/trust-v1.openapi.yaml"
EVENTS = ROOT / "events/trust-v1.schema.json"
REPORT = ROOT / "domain/trust-report-v1.schema.json"
TRIAGE = ROOT / "domain/trust-triage-v1.schema.json"


class _UniqueYamlLoader(yaml.SafeLoader):
    pass


def _unique_yaml(
    loader: _UniqueYamlLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        assert key not in result, f"duplicate YAML key: {key}"
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueYamlLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _unique_yaml,
)


def _unique_json(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        assert key not in result, f"duplicate JSON key: {key}"
        result[key] = value
    return result


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text("utf-8"), object_pairs_hook=_unique_json)
    assert isinstance(value, dict)
    return value


def _walk(value: Any):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


class _SchemaViolation(AssertionError):
    pass


def _document(path: Path) -> dict[str, Any]:
    if path.suffix == ".yaml":
        value = yaml.load(path.read_text("utf-8"), Loader=_UniqueYamlLoader)
        assert isinstance(value, dict)
        return value
    return _json(path)


def _fragment(document: dict[str, Any], pointer: str) -> Any:
    if pointer in ("", "#"):
        return document
    if not pointer.startswith("#/"):
        raise AssertionError(f"unsupported JSON pointer: {pointer}")
    value: Any = document
    for encoded in pointer[2:].split("/"):
        key = encoded.replace("~1", "/").replace("~0", "~")
        if not isinstance(value, dict) or key not in value:
            raise AssertionError(f"unresolved JSON pointer: {pointer}")
        value = value[key]
    return value


def _resolve(
    document: dict[str, Any],
    document_path: Path,
    reference: str,
) -> tuple[dict[str, Any], Path, Any]:
    if reference.startswith("#"):
        return document, document_path, _fragment(document, reference)
    relative, separator, fragment = reference.partition("#")
    target_path = (document_path.parent / relative).resolve()
    target = _document(target_path)
    pointer = "#" + fragment if separator else "#"
    return target, target_path, _fragment(target, pointer)


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
        target_document, target_path, target_schema = _resolve(
            document, document_path, reference
        )
        _validate(target_document, target_path, target_schema, value, path)

    if "oneOf" in schema:
        matches = sum(
            _matches(document, document_path, choice, value)
            for choice in schema["oneOf"]
        )
        if matches != 1:
            raise _SchemaViolation(f"{path}: expected exactly one branch")
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
        "null": value is None,
    }
    if isinstance(expected_type, str) and not type_matches.get(expected_type, True):
        raise _SchemaViolation(f"{path}: expected {expected_type}")

    if isinstance(value, dict):
        properties = schema.get("properties", {})
        missing = set(schema.get("required", ())).difference(value)
        if missing:
            raise _SchemaViolation(f"{path}: missing {sorted(missing)}")
        if schema.get("additionalProperties") is False:
            unknown = set(value).difference(properties)
            if unknown:
                raise _SchemaViolation(f"{path}: unknown {sorted(unknown)}")
        maximum = schema.get("maxProperties")
        if isinstance(maximum, int) and len(value) > maximum:
            raise _SchemaViolation(f"{path}: too many properties")
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
        if schema.get("format") == "uuid":
            try:
                parsed = UUID(value)
            except (AttributeError, ValueError):
                raise _SchemaViolation(f"{path}: invalid UUID") from None
            if parsed.int == 0 or str(parsed) != value:
                raise _SchemaViolation(f"{path}: non-canonical UUID")
        if schema.get("format") == "date-time":
            try:
                parsed_time = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except (AttributeError, ValueError):
                raise _SchemaViolation(f"{path}: invalid date-time") from None
            if parsed_time.tzinfo is None or parsed_time.utcoffset() is None:
                raise _SchemaViolation(f"{path}: date-time lacks offset")

    if isinstance(value, int) and not isinstance(value, bool):
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if isinstance(minimum, int) and value < minimum:
            raise _SchemaViolation(f"{path}: below minimum")
        if isinstance(maximum, int) and value > maximum:
            raise _SchemaViolation(f"{path}: above maximum")


def _assert_valid(document: dict[str, Any], path: Path, value: Any) -> None:
    _validate(document, path, document, value)


def _assert_rejected(document: dict[str, Any], path: Path, value: Any) -> None:
    try:
        _validate(document, path, document, value)
    except _SchemaViolation:
        return
    raise AssertionError("instance unexpectedly matched the closed contract")


def _assert_schema_valid(
    document: dict[str, Any],
    path: Path,
    schema: dict[str, Any],
    value: Any,
) -> None:
    _validate(document, path, schema, value)


def _assert_schema_rejected(
    document: dict[str, Any],
    path: Path,
    schema: dict[str, Any],
    value: Any,
) -> None:
    try:
        _validate(document, path, schema, value)
    except _SchemaViolation:
        return
    raise AssertionError("instance unexpectedly matched the closed schema")


def _request_schema(api: dict[str, Any], path: str, method: str) -> dict[str, Any]:
    schema = api["paths"][path][method]["requestBody"]["content"][
        "application/json"
    ]["schema"]
    assert isinstance(schema, dict)
    return schema


def _response(
    api: dict[str, Any], path: str, method: str, status: str
) -> dict[str, Any]:
    response = api["paths"][path][method]["responses"][status]
    assert isinstance(response, dict)
    reference = response.get("$ref")
    if isinstance(reference, str):
        _document_value, _document_path, response = _resolve(
            api, OPENAPI, reference
        )
    assert isinstance(response, dict)
    return response


def _valid_report() -> dict[str, Any]:
    return {
        "category": "WORKFLOW_INTEGRITY",
        "demand_id": "10000000-0000-4000-8000-000000000001",
        "demand_version_id": "10000000-0000-4000-8000-000000000002",
        "evidence_reference_ids": ["10000000-0000-4000-8000-000000000003"],
        "impact_codes": ["WORKFLOW_INTEGRITY_RISK"],
        "incident_ended_at": None,
        "incident_started_at": "2026-08-18T08:00:00Z",
        "requested_protection_codes": ["PAUSE_MATCHING"],
    }


def _valid_triage() -> dict[str, Any]:
    return {
        "investigation_step_codes": ["CHECK_DEMAND_VERSION"],
        "issue_codes": ["WORKFLOW_INTEGRITY_GAP"],
        "jurisdiction_code": "PLATFORM_INTERNAL",
        "priority_code": "P1",
        "proposed_hold_actions": ["REQUEST_MATCHING"],
        "proposed_hold_ttl_minutes": 120,
        "restricted_note": "Restricted synthetic triage observation",
        "severity_code": "HIGH",
    }


def _valid_event() -> dict[str, Any]:
    return {
        "actor_id": "20000000-0000-4000-8000-000000000007",
        "actor_kind": "USER",
        "aggregate_id": "20000000-0000-4000-8000-000000000002",
        "aggregate_type": "SafetyCase",
        "aggregate_version": 3,
        "causation_id": "20000000-0000-4000-8000-000000000008",
        "correlation_id": "20000000-0000-4000-8000-000000000009",
        "event_id": "20000000-0000-4000-8000-000000000001",
        "event_type": "SafetyHoldPlaced",
        "occurred_at": "2026-08-18T08:30:00Z",
        "organization_id": "20000000-0000-4000-8000-000000000004",
        "original_actor_id": None,
        "payload": {
            "action_codes": ["REQUEST_MATCHING"],
            "case_id": "20000000-0000-4000-8000-000000000002",
            "case_status": "IN_REVIEW",
            "expires_at": "2026-08-18T10:30:00Z",
            "hold_id": "20000000-0000-4000-8000-000000000003",
            "hold_status": "ACTIVE",
            "hold_version": 1
        },
        "schema_version": 1,
        "trace_id": "20000000-0000-4000-8000-000000000010",
    }


def test_trust_contract_artifacts_exist_and_are_closed() -> None:
    for path in (OPENAPI, EVENTS, REPORT, TRIAGE):
        assert path.is_file(), path
        assert path.read_bytes().endswith(b"\n")

    api = yaml.load(OPENAPI.read_text("utf-8"), Loader=_UniqueYamlLoader)
    assert api["openapi"] == "3.1.0"
    assert api["info"]["title"] == "Desire Trust API"
    assert set(api["paths"]) == {
        "/v1/app/trust/reports",
        "/v1/app/trust/reports/{report_id}",
        "/v1/app/trust/queue",
        "/v1/app/trust/queue/{case_id}/claim",
        "/v1/app/trust/assignments",
        "/v1/app/trust/history",
        "/v1/app/trust/assigned-holds/{hold_id}",
        "/v1/app/trust/hold-release-queue",
        "/v1/app/trust/hold-release-queue/{hold_id}/claim",
        "/v1/app/trust/cases/{case_id}",
        "/v1/app/trust/cases/{case_id}/assignment/release",
        "/v1/app/trust/cases/{case_id}/triage-draft",
        "/v1/app/trust/cases/{case_id}/triage-publish",
        "/v1/app/trust/cases/{case_id}/holds",
        "/v1/app/trust/holds/{hold_id}/release",
        "/v1/app/trust/cases/{case_id}/decisions",
    }
    forbidden = {
        "actor",
        "actor_id",
        "actor_user_id",
        "assignment_id",
        "duty_code",
        "duty_grant_id",
        "organization_id",
        "reporter_user_id",
        "role",
        "session_id",
    }
    for node in _walk(api.get("components", {}).get("schemas", {})):
        if isinstance(node, dict) and isinstance(node.get("properties"), dict):
            assert forbidden.isdisjoint(node["properties"])
            assert node.get("additionalProperties") is False
    for node in _walk(api):
        if isinstance(node, dict) and isinstance(node.get("$ref"), str):
            _resolve(api, OPENAPI, node["$ref"])

    security = api["components"]["securitySchemes"]
    assert set(security) == {"sessionCookie"}
    assert security["sessionCookie"]["name"] == "__Host-ds_session"

    queue_item = api["components"]["schemas"]["QueueItem"]
    assert "case_id" in queue_item["required"]
    assert queue_item["properties"]["case_id"] == {
        "$ref": "#/components/schemas/Uuid"
    }
    assignment_item = api["components"]["schemas"]["ActiveAssignmentItem"]
    assert assignment_item["additionalProperties"] is False
    assert set(assignment_item["properties"]) == {
        "assignment_expires_at",
        "assignment_purpose",
        "case_id",
        "hold_id",
    }
    assert set(assignment_item["required"]) == set(
        assignment_item["properties"]
    )
    assert assignment_item["properties"]["assignment_purpose"]["enum"] == [
        "CASE_TRIAGE",
        "HOLD_RELEASE",
    ]
    triage_assignment = {
        "assignment_expires_at": "2026-08-19T12:00:00Z",
        "assignment_purpose": "CASE_TRIAGE",
        "case_id": "20000000-0000-4000-8000-000000000001",
        "hold_id": None,
    }
    hold_assignment = {
        **triage_assignment,
        "assignment_purpose": "HOLD_RELEASE",
        "hold_id": "20000000-0000-4000-8000-000000000002",
    }
    _assert_schema_valid(api, OPENAPI, assignment_item, triage_assignment)
    _assert_schema_valid(api, OPENAPI, assignment_item, hold_assignment)
    _assert_schema_rejected(
        api, OPENAPI, assignment_item, {**triage_assignment, "hold_id": hold_assignment["hold_id"]}
    )
    _assert_schema_rejected(
        api, OPENAPI, assignment_item, {**hold_assignment, "hold_id": None}
    )
    history_operation = api["paths"]["/v1/app/trust/history"]["get"]
    assert history_operation["parameters"] == [
        {"$ref": "#/components/parameters/WorkspaceId"}
    ]
    assert "requestBody" not in history_operation
    assert set(history_operation["responses"]) == {"200", "401", "404", "503"}
    history_item = api["components"]["schemas"][
        "CompletedAssignmentHistoryItem"
    ]
    assert history_item["additionalProperties"] is False
    assert set(history_item["required"]) == set(history_item["properties"])
    assert set(history_item["properties"]) == {
        "case_id",
        "decided_at",
        "outcome_code",
    }
    history_projection = api["components"]["schemas"][
        "CompletedAssignmentHistoryProjection"
    ]
    assert history_projection["additionalProperties"] is False
    assert set(history_projection["required"]) == set(
        history_projection["properties"]
    )
    history = {
        "entity_tag": '"trust-7-0123456789abcdef01234567"',
        "has_more": False,
        "items": [
            {
                "case_id": "20000000-0000-4000-8000-000000000001",
                "decided_at": "2026-08-19T12:00:00Z",
                "outcome_code": "PROTECTION_MAINTAINED",
            }
        ],
    }
    _assert_schema_valid(api, OPENAPI, history_projection, history)
    _assert_schema_rejected(
        api,
        OPENAPI,
        history_projection,
        {
            **history,
            "items": [
                {
                    **history["items"][0],
                    "assignment_id": "20000000-0000-4000-8000-000000000002",
                }
            ],
        },
    )
    assigned_hold = api["components"]["schemas"]["AssignedHoldReleaseProjection"]
    assert assigned_hold["additionalProperties"] is False
    assert set(assigned_hold["required"]) == set(assigned_hold["properties"])
    assert set(assigned_hold["properties"]) == {
        "action_codes",
        "assignment_expires_at",
        "case_id",
        "case_status",
        "effective_at",
        "entity_tag",
        "expires_at",
        "hold_id",
        "hold_status",
        "reason_code",
    }
    assert assigned_hold["properties"]["case_status"]["const"] == "IN_REVIEW"
    assert assigned_hold["properties"]["hold_status"]["const"] == "ACTIVE"


def test_report_and_triage_schemas_are_structured_and_secret_safe() -> None:
    report = _json(REPORT)
    triage = _json(TRIAGE)
    assert report["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert triage["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert report["additionalProperties"] is False
    assert triage["additionalProperties"] is False
    assert set(report["properties"]) == {
        "category",
        "demand_id",
        "demand_version_id",
        "evidence_reference_ids",
        "impact_codes",
        "incident_ended_at",
        "incident_started_at",
        "requested_protection_codes",
    }
    assert set(triage["properties"]) == {
        "investigation_step_codes",
        "issue_codes",
        "jurisdiction_code",
        "priority_code",
        "proposed_hold_actions",
        "proposed_hold_ttl_minutes",
        "restricted_note",
        "severity_code",
    }
    serialized = json.dumps((report, triage), sort_keys=True)
    for forbidden in (
        '"narrative"',
        '"note"',
        '"contact"',
        '"reporter_user_id"',
        '"assignee_user_id"',
    ):
        assert forbidden not in serialized

    api = _document(OPENAPI)
    safe_triage = api["components"]["schemas"]["SafeTriageContent"]
    assert "restricted_note" not in safe_triage["properties"]
    assert {"sealed_note_reference", "sealed_note_sha256"}.issubset(
        safe_triage["properties"]
    )
    assert triage["properties"]["restricted_note"]["writeOnly"] is True


def test_event_contract_exposes_only_safe_closed_envelopes() -> None:
    events = _json(EVENTS)
    assert events["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert events["additionalProperties"] is False
    assert events["properties"]["event_type"]["enum"] == [
        "SafetyHoldPlaced",
        "SafetyHoldReleased",
        "TrustCaseAssignmentReleased",
        "TrustCaseClaimed",
        "TrustCaseOutcomePublished",
        "TrustHoldReleaseClaimed",
        "TrustReportSubmitted",
        "TrustTriageDraftSaved",
        "TrustTriagePublished",
    ]
    payload = events["$defs"]["Payload"]
    assert payload["additionalProperties"] is False
    assert set(payload["properties"]) == {
        "action_codes",
        "appeal_deadline",
        "appeal_eligible",
        "appeal_eligibility_code",
        "assignment_expires_at",
        "assignment_id",
        "case_id",
        "case_status",
        "content_sha256",
        "demand_id",
        "demand_version_id",
        "expires_at",
        "hold_id",
        "hold_status",
        "hold_version",
        "organization_id",
        "outcome_code",
        "outcome_version",
        "outcome_version_id",
        "report_id",
        "triage_draft_version",
        "triage_version",
    }
    serialized = json.dumps(events, sort_keys=True)
    for forbidden in (
        "reporter",
        "narrative",
        "sealed_note",
        "evidence_reference",
        "officer_user",
    ):
        assert forbidden not in serialized


def test_trust_contracts_are_packaged_resources() -> None:
    package = resources.files("desire_platform.contracts")
    for relative, expected in (
        ("api/trust-v1.openapi.yaml", OPENAPI),
        ("events/trust-v1.schema.json", EVENTS),
        ("domain/trust-report-v1.schema.json", REPORT),
        ("domain/trust-triage-v1.schema.json", TRIAGE),
    ):
        resource = package.joinpath(relative)
        assert resource.is_file()
        assert resource.read_bytes() == expected.read_bytes()


def test_report_and_triage_instances_accept_only_closed_structured_inputs() -> None:
    report_schema = _json(REPORT)
    triage_schema = _json(TRIAGE)
    report = _valid_report()
    triage = _valid_triage()
    _assert_valid(report_schema, REPORT, report)
    _assert_valid(triage_schema, TRIAGE, triage)

    for field in ("unexpected", "actor_id", "role", "narrative"):
        invalid_report = deepcopy(report)
        invalid_report[field] = "must-not-cross-the-contract"
        _assert_rejected(report_schema, REPORT, invalid_report)

        invalid_triage = deepcopy(triage)
        invalid_triage[field] = "must-not-cross-the-contract"
        _assert_rejected(triage_schema, TRIAGE, invalid_triage)

    invalid_report_codes = (
        ("category", "FREE_FORM_CATEGORY"),
        ("impact_codes", ["CUSTOM_IMPACT"]),
        ("requested_protection_codes", ["BLOCK_EVERYTHING"]),
    )
    for field, value in invalid_report_codes:
        invalid = deepcopy(report)
        invalid[field] = value
        _assert_rejected(report_schema, REPORT, invalid)

    invalid_triage_codes = (
        ("investigation_step_codes", ["READ_ALL_PRIVATE_DATA"]),
        ("issue_codes", ["FREE_FORM_ISSUE"]),
        ("jurisdiction_code", "UNKNOWN_JURISDICTION"),
        ("priority_code", "URGENTISH"),
        ("proposed_hold_actions", ["BLOCK_ACCOUNT"]),
        ("severity_code", "EXTREME"),
    )
    for field, value in invalid_triage_codes:
        invalid = deepcopy(triage)
        invalid[field] = value
        _assert_rejected(triage_schema, TRIAGE, invalid)


def test_openapi_write_bodies_are_executable_closed_schemas() -> None:
    api = _document(OPENAPI)
    write_examples = (
        ("/v1/app/trust/reports", "post", _valid_report()),
        ("/v1/app/trust/queue/{case_id}/claim", "post", {}),
        ("/v1/app/trust/hold-release-queue/{hold_id}/claim", "post", {}),
        (
            "/v1/app/trust/cases/{case_id}/assignment/release",
            "post",
            {"reason_code": "CONFLICT_DECLARED"},
        ),
        ("/v1/app/trust/cases/{case_id}/triage-draft", "put", _valid_triage()),
        (
            "/v1/app/trust/cases/{case_id}/triage-publish",
            "post",
            {"expected_draft_version": 2},
        ),
        (
            "/v1/app/trust/cases/{case_id}/holds",
            "post",
            {
                "action_codes": ["REQUEST_MATCHING"],
                "reason_code": "WORKFLOW_INTEGRITY_RISK",
                "ttl_minutes": 120,
            },
        ),
        (
            "/v1/app/trust/holds/{hold_id}/release",
            "post",
            {"reason_code": "RISK_MITIGATED"},
        ),
        (
            "/v1/app/trust/cases/{case_id}/decisions",
            "post",
            {
                "action_codes": ["REQUEST_MATCHING"],
                "outcome_code": "PROTECTION_MODIFIED",
                "reason_codes": ["RISK_MITIGATED"],
            },
        ),
    )
    for path, method, instance in write_examples:
        schema = _request_schema(api, path, method)
        _assert_schema_valid(api, OPENAPI, schema, instance)
        invalid = deepcopy(instance)
        invalid["actor_id"] = "30000000-0000-4000-8000-000000000099"
        _assert_schema_rejected(api, OPENAPI, schema, invalid)

    invalid_assignment_release = {"reason_code": "FREE_FORM_REASON"}
    _assert_schema_rejected(
        api,
        OPENAPI,
        _request_schema(api, write_examples[3][0], write_examples[3][1]),
        invalid_assignment_release,
    )
    invalid_hold = deepcopy(write_examples[6][2])
    invalid_hold["action_codes"] = ["BLOCK_ALL_DEMAND_ACTIONS"]
    _assert_schema_rejected(
        api,
        OPENAPI,
        _request_schema(api, write_examples[6][0], write_examples[6][1]),
        invalid_hold,
    )
    invalid_release = {"reason_code": "FREE_FORM_REASON"}
    _assert_schema_rejected(
        api,
        OPENAPI,
        _request_schema(api, write_examples[7][0], write_examples[7][1]),
        invalid_release,
    )
    invalid_outcome = deepcopy(write_examples[8][2])
    invalid_outcome["outcome_code"] = "OFFICER_DISCRETION"
    _assert_schema_rejected(
        api,
        OPENAPI,
        _request_schema(api, write_examples[8][0], write_examples[8][1]),
        invalid_outcome,
    )
    invalid_outcome = deepcopy(write_examples[8][2])
    invalid_outcome["narrative"] = "raw text must remain sealed"
    _assert_schema_rejected(
        api,
        OPENAPI,
        _request_schema(api, write_examples[8][0], write_examples[8][1]),
        invalid_outcome,
    )


def test_write_responses_are_receipt_safe_and_require_fresh_authorized_reads() -> None:
    api = _document(OPENAPI)
    write_responses = (
        ("/v1/app/trust/reports", "post", "201"),
        ("/v1/app/trust/queue/{case_id}/claim", "post", "201"),
        ("/v1/app/trust/hold-release-queue/{hold_id}/claim", "post", "201"),
        ("/v1/app/trust/cases/{case_id}/assignment/release", "post", "200"),
        ("/v1/app/trust/cases/{case_id}/triage-draft", "put", "200"),
        ("/v1/app/trust/cases/{case_id}/triage-publish", "post", "200"),
        ("/v1/app/trust/cases/{case_id}/holds", "post", "201"),
        ("/v1/app/trust/holds/{hold_id}/release", "post", "200"),
        ("/v1/app/trust/cases/{case_id}/decisions", "post", "201"),
    )
    result = {
        "aggregate_version": 4,
        "case_id": "10000000-0000-4000-8000-000000000010",
        "case_status": "IN_REVIEW",
        "completed_at": "2026-08-18T08:00:00Z",
        "event_types": ["TrustTriagePublished"],
        "hold_id": None,
        "hold_version": None,
        "outcome_version_id": None,
        "replayed": False,
        "report_id": None,
        "triage_draft_version": None,
        "triage_version": 1,
    }
    for path, method, status in write_responses:
        response = _response(api, path, method, status)
        assert "headers" not in response or "ETag" not in response["headers"]
        schema = response["content"]["application/json"]["schema"]
        _assert_schema_valid(api, OPENAPI, schema, {"data": result})
        for forbidden in (
            "assignment_id",
            "authority_marker_sha256",
            "restricted_note",
            "sealed_note_reference",
        ):
            invalid = {"data": {**result, forbidden: "must-not-leak"}}
            _assert_schema_rejected(api, OPENAPI, schema, invalid)


def test_reporter_read_includes_only_the_party_safe_outcome_projection() -> None:
    api = _document(OPENAPI)
    report = api["components"]["schemas"]["ReportProjection"]
    assert "outcome" in report["required"]
    outcome = report["properties"]["outcome"]
    assert outcome == {
        "oneOf": [
            {"$ref": "#/components/schemas/OutcomeProjection"},
            {"type": "null"},
        ]
    }
    serialized = json.dumps(outcome, sort_keys=True)
    for forbidden in (
        "actor_user_id",
        "assignment_id",
        "officer_user_id",
        "restricted_note",
        "sealed_note_reference",
    ):
        assert forbidden not in serialized


def test_openapi_requires_server_derived_session_workspace_and_write_guards() -> None:
    api = _document(OPENAPI)
    for path_item in api["paths"].values():
        for method, operation in path_item.items():
            if method not in {"get", "post", "put"}:
                continue
            assert operation["security"] == [{"sessionCookie": []}]
            parameter_refs = {
                parameter.get("$ref")
                for parameter in operation.get("parameters", ())
                if isinstance(parameter, dict)
            }
            assert "#/components/parameters/WorkspaceId" in parameter_refs
            if method in {"post", "put"}:
                assert "#/components/parameters/IdempotencyKey" in parameter_refs
                assert "#/components/parameters/CsrfToken" in parameter_refs
                if path_item is not api["paths"]["/v1/app/trust/reports"]:
                    assert "#/components/parameters/IfMatch" in parameter_refs


def test_event_instances_reject_secret_fields_and_open_codes() -> None:
    schema = _json(EVENTS)
    event = _valid_event()
    _assert_valid(schema, EVENTS, event)

    for field in ("unexpected", "reporter_user_id", "narrative", "officer_user_id"):
        invalid = deepcopy(event)
        invalid["payload"][field] = "must-not-cross-the-event-boundary"
        _assert_rejected(schema, EVENTS, invalid)

    invalid = deepcopy(event)
    invalid["event_type"] = "TrustOfficerFreeFormNotePublished"
    _assert_rejected(schema, EVENTS, invalid)

    invalid = deepcopy(event)
    invalid["payload"]["action_codes"] = ["BLOCK_EVERYTHING"]
    _assert_rejected(schema, EVENTS, invalid)

    invalid = deepcopy(event)
    invalid["payload"]["appeal_eligibility_code"] = "OFFICER_DISCRETION"
    _assert_rejected(schema, EVENTS, invalid)

    invalid = deepcopy(event)
    invalid["aggregate_type"] = "User"
    _assert_rejected(schema, EVENTS, invalid)
