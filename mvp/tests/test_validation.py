import copy
import unittest

from desire_mvp.validation import validate_creator, validate_demand, validate_outcome

from helpers import load_sample


class ValidationTests(unittest.TestCase):
    def test_all_sample_records_are_match_ready(self):
        demands = load_sample("demands.json")
        creators = load_sample("creators.json")
        for demand in demands:
            self.assertTrue(validate_demand(demand).ready, demand["id"])
        for creator in creators:
            self.assertTrue(validate_creator(creator).ready, creator["id"])

    def test_demand_without_funding_or_acceptance_is_blocked(self):
        demand = copy.deepcopy(load_sample("demands.json")[0])
        demand["funding_commitment"] = False
        demand["acceptance"]["criteria"] = []
        result = validate_demand(demand)
        codes = {issue.code for issue in result.issues}
        self.assertFalse(result.ready)
        self.assertIn("FUNDING_UNCOMMITTED", codes)
        self.assertIn("MISSING_REQUIRED", codes)

    def test_high_sensitivity_requires_a_data_plan(self):
        demand = copy.deepcopy(load_sample("demands.json")[0])
        demand["risk"]["data_sensitivity"] = "high"
        demand["risk"]["data_handling_plan"] = ""
        result = validate_demand(demand)
        self.assertIn("MISSING_DATA_PLAN", {issue.code for issue in result.issues})

    def test_creator_skill_requires_verifiable_evidence(self):
        creator = copy.deepcopy(load_sample("creators.json")[0])
        creator["skills"][0]["evidence_ref"] = ""
        result = validate_creator(creator)
        self.assertFalse(result.ready)
        self.assertIn("MISSING_SKILL_EVIDENCE", {issue.code for issue in result.issues})

    def test_sample_outcome_is_ready_and_failed_outcome_needs_reason(self):
        outcome = load_sample("outcome.json")
        self.assertTrue(validate_outcome(outcome).ready)
        outcome = copy.deepcopy(outcome)
        outcome["status"] = "failed"
        outcome["failure_primary"] = None
        self.assertIn("MISSING_FAILURE_REASON", {issue.code for issue in validate_outcome(outcome).issues})


if __name__ == "__main__":
    unittest.main()
