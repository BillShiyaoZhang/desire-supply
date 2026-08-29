import copy
import json
import math
import unittest

from desire_mvp.config import load_config
from desire_mvp.validation import validate_creator, validate_demand, validate_outcome

from helpers import ROOT, load_sample


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.config = load_config(ROOT / "config")

    @staticmethod
    def issue_codes(result):
        return {issue.code for issue in result.issues}

    def test_all_sample_records_are_match_ready(self):
        demands = load_sample("demands.json")
        creators = load_sample("creators.json")
        for demand in demands:
            self.assertTrue(validate_demand(demand, self.config).ready, demand["id"])
        for creator in creators:
            self.assertTrue(validate_creator(creator, self.config).ready, creator["id"])

    def test_demand_without_funding_or_acceptance_is_blocked(self):
        demand = copy.deepcopy(load_sample("demands.json")[0])
        demand["funding_commitment"] = False
        demand["acceptance"]["criteria"] = []
        result = validate_demand(demand, self.config)
        codes = {issue.code for issue in result.issues}
        self.assertFalse(result.ready)
        self.assertIn("FUNDING_UNCOMMITTED", codes)
        self.assertIn("MISSING_REQUIRED", codes)

    def test_high_sensitivity_requires_a_data_plan(self):
        demand = copy.deepcopy(load_sample("demands.json")[0])
        demand["risk"]["data_sensitivity"] = "high"
        demand["risk"]["data_handling_plan"] = ""
        result = validate_demand(demand, self.config)
        self.assertIn("MISSING_DATA_PLAN", {issue.code for issue in result.issues})

    def test_creator_skill_requires_verifiable_evidence(self):
        creator = copy.deepcopy(load_sample("creators.json")[0])
        creator["skills"][0]["evidence_ref"] = ""
        result = validate_creator(creator, self.config)
        self.assertFalse(result.ready)
        self.assertIn("MISSING_SKILL_EVIDENCE", {issue.code for issue in result.issues})

    def test_sample_outcome_is_ready_and_failed_outcome_needs_reason(self):
        outcome = load_sample("outcome.json")
        self.assertTrue(validate_outcome(outcome, self.config).ready)
        outcome = copy.deepcopy(outcome)
        outcome["status"] = "failed"
        outcome["failure_primary"] = None
        self.assertIn(
            "MISSING_FAILURE_REASON",
            self.issue_codes(validate_outcome(outcome, self.config)),
        )

    def test_demand_rejects_unknown_taxonomy_values(self):
        cases = (
            ("problem.domain", lambda value: value["problem"].update({"domain": "unknown-domain"})),
            ("matching.problem_types", lambda value: value["matching"].update({"problem_types": ["unknown-problem"]})),
            ("matching.domains", lambda value: value["matching"].update({"domains": ["unknown-domain"]})),
            ("matching.tasks", lambda value: value["matching"].update({"tasks": ["unknown-task"]})),
            ("skills.must_have", lambda value: value["skills"].update({"must_have": ["unknown-skill"]})),
            ("skills.nice_to_have", lambda value: value["skills"].update({"nice_to_have": ["unknown-skill"]})),
        )
        for field, mutate in cases:
            with self.subTest(field=field):
                demand = copy.deepcopy(load_sample("demands.json")[0])
                mutate(demand)
                self.assertIn(
                    "UNKNOWN_TAXONOMY",
                    self.issue_codes(validate_demand(demand, self.config)),
                )

    def test_creator_rejects_unknown_taxonomy_values(self):
        cases = (
            ("interests.problem_types", lambda value: value["interests"].update({"problem_types": ["unknown-problem"]})),
            ("interests.domains", lambda value: value["interests"].update({"domains": ["unknown-domain"]})),
            ("interests.tasks", lambda value: value["interests"].update({"tasks": ["unknown-task"]})),
            ("skills.tag", lambda value: value["skills"][0].update({"tag": "unknown-skill"})),
        )
        for field, mutate in cases:
            with self.subTest(field=field):
                creator = copy.deepcopy(load_sample("creators.json")[0])
                mutate(creator)
                self.assertIn(
                    "UNKNOWN_TAXONOMY",
                    self.issue_codes(validate_creator(creator, self.config)),
                )

    def test_demand_rejects_unknown_enums(self):
        cases = (
            ("status", lambda value: value.update({"status": "published"})),
            ("skills.level", lambda value: value["skills"].update({"level": "legendary"})),
            ("risk.uncertainty", lambda value: value["risk"].update({"uncertainty": "extreme"})),
            ("risk.urgency", lambda value: value["risk"].update({"urgency": "extreme"})),
            ("risk.external_dependencies", lambda value: value["risk"].update({"external_dependencies": "extreme"})),
            ("risk.data_sensitivity", lambda value: value["risk"].update({"data_sensitivity": "secret"})),
            ("budget.currency", lambda value: value["budget"].update({"currency": "USD"})),
            ("location.region", lambda value: value["location"].update({"region": "moon"})),
        )
        for field, mutate in cases:
            with self.subTest(field=field):
                demand = copy.deepcopy(load_sample("demands.json")[0])
                mutate(demand)
                self.assertIn(
                    "UNKNOWN_ENUM",
                    self.issue_codes(validate_demand(demand, self.config)),
                )

    def test_creator_and_outcome_reject_unknown_enums(self):
        creator_cases = (
            ("status", lambda value: value.update({"status": "unknown-status"})),
            ("data_sensitivity", lambda value: value["boundaries"].update({"allowed_data_sensitivity": ["secret"]})),
            ("currency", lambda value: value["compensation"].update({"currency": "USD"})),
        )
        for field, mutate in creator_cases:
            with self.subTest(entity="creator", field=field):
                creator = copy.deepcopy(load_sample("creators.json")[0])
                mutate(creator)
                self.assertIn(
                    "UNKNOWN_ENUM",
                    self.issue_codes(validate_creator(creator, self.config)),
                )

        outcome = copy.deepcopy(load_sample("outcome.json"))
        outcome.update({"status": "failed", "failure_primary": "NOT_A_FAILURE_CODE"})
        self.assertIn(
            "UNKNOWN_ENUM",
            self.issue_codes(validate_outcome(outcome, self.config)),
        )

    def test_legacy_terminal_status_values_are_rejected_from_v1(self):
        demand = copy.deepcopy(load_sample("demands.json")[0])
        demand["status"] = "closed"
        self.assertIn(
            "UNKNOWN_ENUM", self.issue_codes(validate_demand(demand, self.config))
        )

        creator = copy.deepcopy(load_sample("creators.json")[0])
        creator["status"] = "withdrawn"
        self.assertIn(
            "UNKNOWN_ENUM", self.issue_codes(validate_creator(creator, self.config))
        )

    def test_rejects_container_type_inversions(self):
        demand = copy.deepcopy(load_sample("demands.json")[0])
        demand["skills"]["must_have"] = "python"
        self.assertIn(
            "INVALID_TYPE",
            self.issue_codes(validate_demand(demand, self.config)),
        )

        creator = copy.deepcopy(load_sample("creators.json")[0])
        creator["skills"] = {"python": 4}
        self.assertIn(
            "INVALID_TYPE",
            self.issue_codes(validate_creator(creator, self.config)),
        )

        outcome = copy.deepcopy(load_sample("outcome.json"))
        outcome["creator_preference_confirmed"] = True
        self.assertIn(
            "INVALID_TYPE",
            self.issue_codes(validate_outcome(outcome, self.config)),
        )

        for invalid_status in ([], {}):
            with self.subTest(outcome_status=invalid_status):
                outcome = copy.deepcopy(load_sample("outcome.json"))
                outcome["status"] = invalid_status
                self.assertIn(
                    "UNKNOWN_ENUM",
                    self.issue_codes(validate_outcome(outcome, self.config)),
                )

        outcome = copy.deepcopy(load_sample("outcome.json"))
        outcome["willing_to_use_again"] = None
        self.assertIn(
            "INVALID_TYPE",
            self.issue_codes(validate_outcome(outcome, self.config)),
        )

    def test_rejects_booleans_and_non_finite_numbers_in_numeric_fields(self):
        demand = copy.deepcopy(load_sample("demands.json")[0])
        demand["schedule"]["estimated_days"] = True
        self.assertIn(
            "INVALID_TYPE",
            self.issue_codes(validate_demand(demand, self.config)),
        )

        creator = copy.deepcopy(load_sample("creators.json")[0])
        creator["skills"][0]["proficiency"] = False
        self.assertIn(
            "INVALID_TYPE",
            self.issue_codes(validate_creator(creator, self.config)),
        )

        for invalid in (math.nan, math.inf, -math.inf, 10**400):
            with self.subTest(value=invalid):
                demand = copy.deepcopy(load_sample("demands.json")[0])
                demand["budget"]["maximum"] = invalid
                self.assertIn(
                    "INVALID_TYPE",
                    self.issue_codes(validate_demand(demand, self.config)),
                )

    def test_rejects_invalid_identifier_and_text_types(self):
        cases = (
            (
                "demand.id",
                "demand",
                lambda value: value.update({"id": 42}),
            ),
            (
                "demand.problem.background",
                "demand",
                lambda value: value["problem"].update({"background": {"text": "nested"}}),
            ),
            (
                "demand.pilot_id",
                "demand",
                lambda value: value.update({"pilot_id": {"value": "pilot-demo"}}),
            ),
            (
                "demand.payment.plan",
                "demand",
                lambda value: value["payment"].update({"plan": ["forty percent"]}),
            ),
            (
                "creator.id",
                "creator",
                lambda value: value.update({"id": True}),
            ),
            (
                "creator.availability.timezone",
                "creator",
                lambda value: value["availability"].update({"timezone": ["Asia/Shanghai"]}),
            ),
            (
                "creator.skills.tag",
                "creator",
                lambda value: value["skills"][0].update({"tag": {"value": "python"}}),
            ),
        )
        for field, kind, mutate in cases:
            with self.subTest(field=field):
                filename = "demands.json" if kind == "demand" else "creators.json"
                record = copy.deepcopy(load_sample(filename)[0])
                mutate(record)
                result = (
                    validate_demand(record, self.config)
                    if kind == "demand"
                    else validate_creator(record, self.config)
                )
                self.assertIn("INVALID_TYPE", self.issue_codes(result))

    def test_completed_outcome_rejects_failure_reasons(self):
        outcome = copy.deepcopy(load_sample("outcome.json"))
        outcome["failure_primary"] = "QUALITY"
        outcome["failure_secondary"] = ["COMMUNICATION"]
        result = validate_outcome(outcome, self.config)
        self.assertFalse(result.ready)
        self.assertIn("CONTRADICTORY_OUTCOME", self.issue_codes(result))

    def test_explicit_null_and_empty_wrong_types_are_rejected(self):
        demand = copy.deepcopy(load_sample("demands.json")[0])
        demand["matching"] = ""
        self.assertIn(
            "INVALID_TYPE", self.issue_codes(validate_demand(demand, self.config))
        )

        for field in ("signed", "creator_preference_confirmed", "failure_secondary"):
            with self.subTest(field=field):
                outcome = copy.deepcopy(load_sample("outcome.json"))
                outcome[field] = None
                self.assertIn(
                    "INVALID_TYPE",
                    self.issue_codes(validate_outcome(outcome, self.config)),
                )

    def test_negative_amounts_and_capacity_are_rejected(self):
        demand_cases = (
            ("weekly_hours", lambda value: value["schedule"].update({"weekly_hours": -1})),
            ("direct_cost", lambda value: value["budget"].update({"direct_cost": -1})),
        )
        for field, mutate in demand_cases:
            with self.subTest(entity="demand", field=field):
                demand = copy.deepcopy(load_sample("demands.json")[0])
                mutate(demand)
                self.assertIn(
                    "INVALID_NUMBER",
                    self.issue_codes(validate_demand(demand, self.config)),
                )

        outcome_cases = (
            ("scope_changes", lambda value: value.update({"scope_changes": -1})),
            ("milestone.amount", lambda value: value["milestones"][0].update({"amount": -1})),
        )
        for field, mutate in outcome_cases:
            with self.subTest(entity="outcome", field=field):
                outcome = copy.deepcopy(load_sample("outcome.json"))
                mutate(outcome)
                self.assertIn(
                    "INVALID_NUMBER",
                    self.issue_codes(validate_outcome(outcome, self.config)),
                )

    def test_outcome_rejects_invalid_nested_types(self):
        cases = (
            ("creator_ids", lambda value: value.update({"creator_ids": [7]})),
            ("scope_changes", lambda value: value.update({"scope_changes": math.inf})),
            ("milestone.amount", lambda value: value["milestones"][0].update({"amount": True})),
            ("milestone.paid", lambda value: value["milestones"][0].update({"paid": "yes"})),
            ("creator_preference_confirmed", lambda value: value.update({"creator_preference_confirmed": [1]})),
            ("willing_to_use_again.creators", lambda value: value["willing_to_use_again"].update({"creators": ["yes"]})),
            ("operator_hours", lambda value: value["operator_hours"].update({"matching": False})),
            ("operator_hours.extra", lambda value: value["operator_hours"].update({"admin": math.inf})),
            ("safety_events", lambda value: value.update({"safety_events": ["raw incident"]})),
            ("failure_primary", lambda value: value.update({"failure_primary": {"code": "QUALITY"}})),
            ("failure_secondary", lambda value: value.update({"failure_secondary": [{"code": "QUALITY"}]})),
        )
        for field, mutate in cases:
            with self.subTest(field=field):
                outcome = copy.deepcopy(load_sample("outcome.json"))
                mutate(outcome)
                self.assertIn(
                    "INVALID_TYPE",
                    self.issue_codes(validate_outcome(outcome, self.config)),
                )

    def test_dates_require_strict_calendar_format(self):
        demand = copy.deepcopy(load_sample("demands.json")[0])
        demand["schedule"]["start_date"] = "20260818"
        self.assertIn(
            "INVALID_DATE", self.issue_codes(validate_demand(demand, self.config))
        )

        creator = copy.deepcopy(load_sample("creators.json")[0])
        creator["availability"]["available_from"] = "2026-W34-2"
        self.assertIn(
            "INVALID_DATE", self.issue_codes(validate_creator(creator, self.config))
        )

        outcome = copy.deepcopy(load_sample("outcome.json"))
        outcome["planned_start"] = "18-08-2026"
        self.assertIn(
            "INVALID_DATE", self.issue_codes(validate_outcome(outcome, self.config))
        )

    def test_identifier_syntax_rejects_contact_like_values(self):
        for identifier in ("person@example.invalid", "13800138000", "tel-13800138000"):
            with self.subTest(identifier=identifier):
                demand = copy.deepcopy(load_sample("demands.json")[0])
                demand["id"] = identifier
                self.assertIn(
                    "INVALID_IDENTIFIER",
                    self.issue_codes(validate_demand(demand, self.config)),
                )

        outcome = copy.deepcopy(load_sample("outcome.json"))
        outcome["creator_ids"] = [""]
        self.assertIn(
            "INVALID_IDENTIFIER",
            self.issue_codes(validate_outcome(outcome, self.config)),
        )

        creator = copy.deepcopy(load_sample("creators.json")[0])
        creator["conflicts"] = ["13800138000", "client-123456789"]
        self.assertIn(
            "INVALID_IDENTIFIER",
            self.issue_codes(validate_creator(creator, self.config)),
        )

    def test_cross_field_cardinality_dates_and_percentages(self):
        demand = copy.deepcopy(load_sample("demands.json")[0])
        demand["payment"]["plan"][1]["percent"] = 40
        self.assertIn(
            "INVALID_PERCENT_TOTAL",
            self.issue_codes(validate_demand(demand, self.config)),
        )

        creator = copy.deepcopy(load_sample("creators.json")[0])
        creator["skills"].append(copy.deepcopy(creator["skills"][0]))
        self.assertIn(
            "DUPLICATE_SKILL",
            self.issue_codes(validate_creator(creator, self.config)),
        )

        outcome = copy.deepcopy(load_sample("outcome.json"))
        outcome["creator_preference_confirmed"] = []
        outcome["actual_start"] = "2026-09-11"
        outcome["actual_finish"] = "2026-09-10"
        codes = self.issue_codes(validate_outcome(outcome, self.config))
        self.assertIn("CARDINALITY_MISMATCH", codes)
        self.assertIn("INVALID_DATE_RANGE", codes)

    def test_required_capacity_and_integer_counts(self):
        demand = copy.deepcopy(load_sample("demands.json")[0])
        demand["schedule"].pop("weekly_hours")
        demand["schedule"].pop("duration_weeks")
        self.assertIn(
            "MISSING_REQUIRED",
            self.issue_codes(validate_demand(demand, self.config)),
        )

        outcome = copy.deepcopy(load_sample("outcome.json"))
        outcome["scope_changes"] = 1.9
        self.assertIn(
            "INVALID_TYPE",
            self.issue_codes(validate_outcome(outcome, self.config)),
        )

    def test_conditionally_required_fields_are_not_unconditional_in_json_schema(self):
        with (ROOT / "schemas" / "demand-v1.schema.json").open(
            "r", encoding="utf-8"
        ) as handle:
            demand_schema = json.load(handle)
        with (ROOT / "schemas" / "creator-v1.schema.json").open(
            "r", encoding="utf-8"
        ) as handle:
            creator_schema = json.load(handle)

        cases = (
            (
                "demand.funding_evidence_ref",
                demand_schema["required"],
                "funding_evidence_ref",
            ),
            (
                "demand.risk.data_handling_plan",
                demand_schema["properties"]["risk"]["required"],
                "data_handling_plan",
            ),
            (
                "demand.ai.data_model_policy",
                demand_schema["properties"]["ai"]["required"],
                "data_model_policy",
            ),
            (
                "creator.ai.prohibited_cases",
                creator_schema["properties"]["ai"]["required"],
                "prohibited_cases",
            ),
        )
        for case, required_fields, field in cases:
            with self.subTest(case=case):
                self.assertNotIn(field, required_fields)

    def test_runtime_preserves_conditional_evidence_semantics(self):
        demand = copy.deepcopy(load_sample("demands.json")[0])
        demand.pop("funding_evidence_ref")
        result = validate_demand(demand, self.config)
        self.assertTrue(result.ready)
        self.assertIn("FUNDING_EVIDENCE_REFERENCE", self.issue_codes(result))

        demand = copy.deepcopy(load_sample("demands.json")[0])
        demand["risk"].pop("data_handling_plan")
        self.assertTrue(validate_demand(demand, self.config).ready)
        demand["risk"]["data_sensitivity"] = "high"
        self.assertIn(
            "MISSING_DATA_PLAN",
            self.issue_codes(validate_demand(demand, self.config)),
        )

        demand = copy.deepcopy(load_sample("demands.json")[0])
        demand["ai"].pop("data_model_policy")
        self.assertTrue(validate_demand(demand, self.config).ready)
        demand["risk"]["data_sensitivity"] = "restricted"
        self.assertIn(
            "MISSING_AI_DATA_POLICY",
            self.issue_codes(validate_demand(demand, self.config)),
        )

        creator = copy.deepcopy(load_sample("creators.json")[0])
        creator["ai"].pop("prohibited_cases")
        result = validate_creator(creator, self.config)
        self.assertTrue(result.ready)
        self.assertIn("AI_PROHIBITED_CASES", self.issue_codes(result))

    def test_all_other_public_schema_required_fields_are_runtime_blockers(self):
        demand_paths = (
            "matching",
            "collaboration",
            "skills.nice_to_have",
            "matching.problem_types",
            "matching.domains",
            "matching.tasks",
            "budget.minimum",
            "budget.direct_cost",
            "ai.required",
            "collaboration.languages",
            "collaboration.preferred_work_mode",
            "collaboration.feedback_frequency",
            "collaboration.team_preference",
            "location.allowed_creator_regions",
        )
        for path in demand_paths:
            with self.subTest(entity="demand", path=path):
                record = copy.deepcopy(load_sample("demands.json")[0])
                parent = record
                parts = path.split(".")
                for part in parts[:-1]:
                    parent = parent[part]
                parent.pop(parts[-1])

                result = validate_demand(record, self.config)
                blockers = [
                    issue
                    for issue in result.issues
                    if issue.level == "BLOCKER" and issue.field == path
                ]
                self.assertTrue(blockers, path)

        creator_paths = (
            "conflicts",
            "collaboration.team_preference",
            "compensation.direct_cost",
            "ai.requires_ai",
        )
        for path in creator_paths:
            with self.subTest(entity="creator", path=path):
                record = copy.deepcopy(load_sample("creators.json")[0])
                parent = record
                parts = path.split(".")
                for part in parts[:-1]:
                    parent = parent[part]
                parent.pop(parts[-1])

                result = validate_creator(record, self.config)
                blockers = [
                    issue
                    for issue in result.issues
                    if issue.level == "BLOCKER" and issue.field == path
                ]
                self.assertTrue(blockers, path)

    def test_non_empty_schema_array_is_enforced_at_runtime(self):
        demand = copy.deepcopy(load_sample("demands.json")[0])
        demand["collaboration"]["languages"] = []
        result = validate_demand(demand, self.config)
        self.assertTrue(
            any(
                issue.level == "BLOCKER"
                and issue.field == "collaboration.languages"
                for issue in result.issues
            )
        )

    def test_demand_unique_items_are_enforced_at_runtime(self):
        paths = (
            "problem.target_users",
            "scope.deliverables",
            "scope.out_of_scope",
            "acceptance.criteria",
            "skills.must_have",
            "skills.nice_to_have",
            "matching.problem_types",
            "matching.domains",
            "matching.tasks",
            "collaboration.languages",
            "location.allowed_creator_regions",
        )
        for path in paths:
            with self.subTest(path=path):
                record = copy.deepcopy(load_sample("demands.json")[0])
                values = record
                for part in path.split("."):
                    values = values[part]
                values.append(copy.deepcopy(values[0]))

                result = validate_demand(record, self.config)
                self.assertTrue(
                    any(
                        issue.level == "BLOCKER" and issue.field == path
                        for issue in result.issues
                    ),
                    path,
                )

    def test_creator_unique_items_are_enforced_at_runtime(self):
        paths = (
            "interests.problem_types",
            "interests.domains",
            "interests.tasks",
            "collaboration.languages",
            "boundaries.prohibited_domains",
            "boundaries.prohibited_tasks",
            "boundaries.allowed_data_sensitivity",
            "ai.prohibited_cases",
        )
        for path in paths:
            with self.subTest(path=path):
                record = copy.deepcopy(load_sample("creators.json")[0])
                values = record
                for part in path.split("."):
                    values = values[part]
                values.append(copy.deepcopy(values[0]))

                result = validate_creator(record, self.config)
                self.assertTrue(
                    any(
                        issue.level == "BLOCKER" and issue.field == path
                        for issue in result.issues
                    ),
                    path,
                )

        creator = copy.deepcopy(load_sample("creators.json")[0])
        creator["conflicts"] = ["client-demo-003", "client-demo-003"]
        result = validate_creator(creator, self.config)
        self.assertTrue(
            any(
                issue.level == "BLOCKER" and issue.field == "conflicts"
                for issue in result.issues
            )
        )

    def test_outcome_unique_items_are_enforced_at_runtime(self):
        cases = (
            (
                "creator_ids",
                lambda outcome: (
                    outcome.__setitem__(
                        "creator_ids", ["creator-demo-001", "creator-demo-001"]
                    ),
                    outcome.__setitem__(
                        "creator_preference_confirmed", [True, True]
                    ),
                    outcome["willing_to_use_again"].__setitem__(
                        "creators", [True, True]
                    ),
                ),
            ),
            (
                "failure_secondary",
                lambda outcome: (
                    outcome.__setitem__("status", "failed"),
                    outcome.__setitem__("failure_primary", "QUALITY"),
                    outcome.__setitem__(
                        "failure_secondary", ["COMMUNICATION", "COMMUNICATION"]
                    ),
                ),
            ),
        )
        for path, mutate in cases:
            with self.subTest(path=path):
                outcome = copy.deepcopy(load_sample("outcome.json"))
                mutate(outcome)
                result = validate_outcome(outcome, self.config)
                self.assertTrue(
                    any(
                        issue.level == "BLOCKER" and issue.field == path
                        for issue in result.issues
                    ),
                    path,
                )


if __name__ == "__main__":
    unittest.main()
