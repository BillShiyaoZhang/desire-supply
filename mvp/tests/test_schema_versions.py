import copy
import json
import re
import sqlite3
import tempfile
import unittest
from pathlib import Path

from desire_mvp.config import load_config
from desire_mvp.migration_support import CURRENT_PAYLOAD_SCHEMA_VERSION
from desire_mvp.repository import Repository
from desire_mvp.schema import (
    SchemaContractError,
    SchemaVersionError,
    validate_payload_contract,
    validate_schema_version,
)
from desire_mvp.validation import validate_creator, validate_demand, validate_outcome

from helpers import ROOT, load_sample


_MISSING = object()


class SchemaVersionTests(unittest.TestCase):
    """TEST-UNIT-MIG-001 / REQ-MIG-001."""

    def setUp(self):
        self.config = load_config(ROOT / "config")

    def test_v1_is_explicit_and_strict(self):
        record = {"schema_version": 1, "id": "demand-demo-001"}
        before = copy.deepcopy(record)

        self.assertEqual(1, validate_schema_version(record))
        self.assertEqual(before, record)

        invalid_records = (
            ("missing", {"id": "demand-demo-001"}),
            ("legacy-zero", {"schema_version": 0}),
            ("false-is-not-an-integer-version", {"schema_version": False}),
            ("true-is-not-an-integer-version", {"schema_version": True}),
            ("numeric-string", {"schema_version": "1"}),
            ("future-version", {"schema_version": 2}),
        )
        for case, invalid in invalid_records:
            with self.subTest(case=case):
                invalid_before = copy.deepcopy(invalid)
                with self.assertRaises(SchemaVersionError) as raised:
                    validate_schema_version(invalid)
                self.assertEqual("UNSUPPORTED_SCHEMA_VERSION", raised.exception.code)
                self.assertEqual(invalid_before, invalid)

    def test_normal_validators_return_one_blocker_for_missing_or_wrong_version(self):
        cases = (
            ("demand", load_sample("demands.json")[0], validate_demand),
            ("creator", load_sample("creators.json")[0], validate_creator),
            ("outcome", load_sample("outcome.json"), validate_outcome),
        )
        for kind, sample, validator in cases:
            for version in (_MISSING, None, 0, False, True, "1", 2):
                with self.subTest(kind=kind, version=version):
                    record = copy.deepcopy(sample)
                    if version is _MISSING:
                        record.pop("schema_version")
                    else:
                        record["schema_version"] = version
                    before = copy.deepcopy(record)

                    result = validator(record, self.config)
                    version_issues = [
                        issue
                        for issue in result.issues
                        if issue.code == "UNSUPPORTED_SCHEMA_VERSION"
                    ]

                    self.assertEqual(1, len(version_issues))
                    self.assertEqual("BLOCKER", version_issues[0].level)
                    self.assertEqual("schema_version", version_issues[0].field)
                    self.assertFalse(result.ready)
                    self.assertEqual(before, record)

    def test_published_samples_and_json_schemas_are_explicit_v1(self):
        sample_records = (
            *load_sample("demands.json"),
            *load_sample("creators.json"),
            load_sample("outcome.json"),
        )
        self.assertTrue(sample_records)
        self.assertTrue(
            all(
                record.get("schema_version") == CURRENT_PAYLOAD_SCHEMA_VERSION
                for record in sample_records
            )
        )

        schema_dir = ROOT / "schemas"
        for kind in ("demand", "creator", "outcome"):
            with self.subTest(kind=kind):
                with (schema_dir / "{}-v1.schema.json".format(kind)).open(
                    "r", encoding="utf-8"
                ) as handle:
                    schema = json.load(handle)
                self.assertEqual("object", schema["type"])
                self.assertFalse(schema["additionalProperties"])
                self.assertIn("schema_version", schema["required"])
                self.assertEqual(
                    {"type": "integer", "const": CURRENT_PAYLOAD_SCHEMA_VERSION},
                    schema["properties"]["schema_version"],
                )

                identifier_pattern = re.compile(schema["$defs"]["identifier"]["pattern"])
                for value in ("demand-demo-001", "creator_A", "p-7"):
                    self.assertIsNotNone(identifier_pattern.fullmatch(value))
                for value in ("12345678", "demand-13800138000", "demand@email"):
                    self.assertIsNone(identifier_pattern.fullmatch(value))

    def test_runtime_rejects_unknown_fields_at_closed_schema_boundaries(self):
        cases = (
            (
                "demand-root",
                load_sample("demands.json")[0],
                validate_demand,
                lambda record: record.__setitem__("contact_email", "private@example.test"),
                "<unknown-field>",
            ),
            (
                "demand-list-item",
                load_sample("demands.json")[0],
                validate_demand,
                lambda record: record["payment"]["plan"][0].__setitem__("note", "extra"),
                "payment.plan[0].<unknown-field>",
            ),
            (
                "creator-nested",
                load_sample("creators.json")[0],
                validate_creator,
                lambda record: record["interests"].__setitem__("extra", True),
                "interests.<unknown-field>",
            ),
            (
                "creator-list-item",
                load_sample("creators.json")[0],
                validate_creator,
                lambda record: record["skills"][0].__setitem__("email", "private@example.test"),
                "skills[0].<unknown-field>",
            ),
            (
                "outcome-root",
                load_sample("outcome.json"),
                validate_outcome,
                lambda record: record.__setitem__("operator_note", "extra"),
                "<unknown-field>",
            ),
            (
                "outcome-list-item",
                load_sample("outcome.json"),
                validate_outcome,
                lambda record: record["milestones"][0].__setitem__("memo", "extra"),
                "milestones[0].<unknown-field>",
            ),
        )

        for case, sample, validator, mutate, expected_field in cases:
            with self.subTest(case=case):
                record = copy.deepcopy(sample)
                mutate(record)
                before = copy.deepcopy(record)

                result = validator(record, self.config)
                unknown = [issue for issue in result.issues if issue.code == "UNKNOWN_FIELD"]

                self.assertEqual([expected_field], [issue.field for issue in unknown])
                self.assertTrue(all(issue.level == "BLOCKER" for issue in unknown))
                self.assertFalse(result.ready)
                self.assertEqual(before, record)

    def test_static_contract_rejects_public_schema_scalar_and_boundary_violations(self):
        cases = (
            ("demand-enum", "demand", "demands.json", 0, lambda value: value.__setitem__("status", "future")),
            ("demand-empty-string", "demand", "demands.json", 0, lambda value: value["problem"].__setitem__("background", "")),
            ("demand-min-items", "demand", "demands.json", 0, lambda value: value["collaboration"].__setitem__("languages", [])),
            ("demand-exclusive-min", "demand", "demands.json", 0, lambda value: value["payment"]["plan"][0].__setitem__("percent", 0)),
            ("demand-date", "demand", "demands.json", 0, lambda value: value["schedule"].__setitem__("start_date", "2026-02-30")),
            ("demand-identifier", "demand", "demands.json", 0, lambda value: value.__setitem__("id", "13800138000")),
            ("creator-bool-number", "creator", "creators.json", 0, lambda value: value["skills"][0].__setitem__("proficiency", True)),
            ("creator-number-range", "creator", "creators.json", 0, lambda value: value["interests"].__setitem__("intensity", 5)),
            ("creator-location", "creator", "creators.json", 0, lambda value: value["location"].__setitem__("region", 123)),
            ("outcome-integer", "outcome", "outcome.json", None, lambda value: value.__setitem__("scope_changes", 1.5)),
            ("outcome-negative", "outcome", "outcome.json", None, lambda value: value["operator_hours"].__setitem__("matching", -1)),
            ("outcome-item-type", "outcome", "outcome.json", None, lambda value: value["milestones"][0].__setitem__("paid", "yes")),
        )
        for case, record_type, sample_name, index, mutate in cases:
            with self.subTest(case=case):
                loaded = load_sample(sample_name)
                record = copy.deepcopy(loaded if index is None else loaded[index])
                mutate(record)
                with self.assertRaises(SchemaContractError):
                    validate_payload_contract(record_type, record)

    def test_repository_static_contract_failure_is_zero_write(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Repository(Path(directory))
            repository.initialize()
            invalid = copy.deepcopy(load_sample("demands.json")[0])
            invalid["schedule"]["start_date"] = "2026-02-30"

            with self.assertRaises(SchemaContractError):
                repository.put_entity("demand", invalid)

            self.assertEqual(repository.list_entities("demand"), [])

    def test_validation_errors_never_reflect_unknown_keys_or_skill_tags(self):
        operator_secret = "person@example.invalid"
        outcome = copy.deepcopy(load_sample("outcome.json"))
        outcome["operator_hours"][operator_secret] = -1
        rendered = json.dumps(
            validate_outcome(outcome, self.config).to_dict(), ensure_ascii=False
        )
        self.assertNotIn(operator_secret, rendered)

        skill_secret = "private-health-note@example.invalid"
        creator = copy.deepcopy(load_sample("creators.json")[0])
        creator["skills"][0]["tag"] = skill_secret
        creator["skills"][0].pop("evidence_ref")
        rendered = json.dumps(
            validate_creator(creator, self.config).to_dict(), ensure_ascii=False
        )
        self.assertNotIn(skill_secret, rendered)

    def test_current_repository_reads_fail_closed_on_corrupt_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Repository(Path(directory))
            repository.initialize()
            demand = copy.deepcopy(load_sample("demands.json")[0])
            outcome = copy.deepcopy(load_sample("outcome.json"))
            repository.put_entity("demand", demand)
            repository.record_outcome(outcome)

            with sqlite3.connect(str(repository.path)) as connection:
                connection.execute(
                    "UPDATE entities SET payload_json=? WHERE kind='demand' AND entity_id=?",
                    (json.dumps({"schema_version": 1, "id": demand["id"]}), demand["id"]),
                )
                connection.execute(
                    "UPDATE outcomes SET payload_json=? WHERE project_id=?",
                    (json.dumps({"schema_version": 1}), outcome["project_id"]),
                )
                connection.commit()

            with self.assertRaises(SchemaContractError):
                repository.get_entity("demand", demand["id"])
            with self.assertRaises(SchemaContractError):
                repository.list_entities("demand")
            with self.assertRaises(SchemaContractError):
                repository.outcomes_for_pilot(outcome["pilot_id"])

    def test_controlled_references_and_closed_safety_event_projection(self):
        secret = "https://example.invalid/?person=private@example.invalid"

        demand = copy.deepcopy(load_sample("demands.json")[0])
        demand["funding_evidence_ref"] = secret
        with self.assertRaises(SchemaContractError):
            validate_payload_contract("demand", demand)
        demand_result = validate_demand(demand, self.config)
        self.assertIn("INVALID_EXTERNAL_REFERENCE", [item.code for item in demand_result.issues])
        self.assertNotIn(secret, json.dumps(demand_result.to_dict(), ensure_ascii=False))

        creator = copy.deepcopy(load_sample("creators.json")[0])
        creator["skills"][0]["evidence_ref"] = secret
        with self.assertRaises(SchemaContractError):
            validate_payload_contract("creator", creator)
        creator_result = validate_creator(creator, self.config)
        self.assertIn("INVALID_EXTERNAL_REFERENCE", [item.code for item in creator_result.issues])
        self.assertNotIn(secret, json.dumps(creator_result.to_dict(), ensure_ascii=False))

        outcome = copy.deepcopy(load_sample("outcome.json"))
        outcome["safety_events"] = [
            {"event_ref": "external://safety-event-demo-001", "severity": "high"}
        ]
        validate_payload_contract("outcome", outcome)
        self.assertTrue(validate_outcome(outcome, self.config).ready)

        unsafe_event = copy.deepcopy(outcome)
        unsafe_event["safety_events"][0]["event_ref"] = secret
        with self.assertRaises(SchemaContractError):
            validate_payload_contract("outcome", unsafe_event)
        unsafe_result = validate_outcome(unsafe_event, self.config)
        self.assertIn("INVALID_EXTERNAL_REFERENCE", [item.code for item in unsafe_result.issues])
        self.assertNotIn(secret, json.dumps(unsafe_result.to_dict(), ensure_ascii=False))

        unknown_field = copy.deepcopy(outcome)
        unknown_field["safety_events"][0]["private_email"] = "person@example.invalid"
        with self.assertRaises(SchemaContractError):
            validate_payload_contract("outcome", unknown_field)
        rendered = json.dumps(validate_outcome(unknown_field, self.config).to_dict())
        self.assertNotIn("private_email", rendered)
        self.assertNotIn("person@example.invalid", rendered)

        unknown_severity = copy.deepcopy(outcome)
        unknown_severity["safety_events"][0]["severity"] = "unknown"
        with self.assertRaises(SchemaContractError):
            validate_payload_contract("outcome", unknown_severity)
        self.assertIn(
            "UNKNOWN_ENUM",
            [item.code for item in validate_outcome(unknown_severity, self.config).issues],
        )

    def test_optional_funding_reference_empty_missing_and_null_semantics(self):
        for value, should_be_ready in (("", True), (None, False)):
            with self.subTest(value=value):
                demand = copy.deepcopy(load_sample("demands.json")[0])
                demand["funding_evidence_ref"] = value
                result = validate_demand(demand, self.config)
                self.assertEqual(result.ready, should_be_ready)
                codes = [item.code for item in result.issues]
                if should_be_ready:
                    self.assertEqual(codes, ["FUNDING_EVIDENCE_REFERENCE"])
                    validate_payload_contract("demand", demand)
                else:
                    self.assertIn("INVALID_EXTERNAL_REFERENCE", codes)
                    with self.assertRaises(SchemaContractError):
                        validate_payload_contract("demand", demand)

        missing = copy.deepcopy(load_sample("demands.json")[0])
        missing.pop("funding_evidence_ref", None)
        result = validate_demand(missing, self.config)
        self.assertTrue(result.ready)
        self.assertEqual(
            [item.code for item in result.issues],
            ["FUNDING_EVIDENCE_REFERENCE"],
        )
        validate_payload_contract("demand", missing)


if __name__ == "__main__":
    unittest.main()
