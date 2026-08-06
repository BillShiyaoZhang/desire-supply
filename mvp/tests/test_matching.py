import copy
import unittest

from desire_mvp.config import load_config
from desire_mvp.matching import filter_candidate, rank_candidates

from helpers import ROOT, load_sample


class MatchingTests(unittest.TestCase):
    def setUp(self):
        self.config = load_config(ROOT / "config").matching
        self.demands = load_sample("demands.json")
        self.creators = load_sample("creators.json")

    def test_matching_is_deterministic_even_when_input_order_changes(self):
        first, excluded_first = rank_candidates(self.demands[0], self.creators, self.config)
        second, excluded_second = rank_candidates(self.demands[0], reversed(self.creators), self.config)
        self.assertEqual([item.to_dict() for item in first], [item.to_dict() for item in second])
        self.assertEqual(excluded_first, excluded_second)
        self.assertGreaterEqual(len(first), 2)

    def test_missing_required_skill_never_enters_ranking(self):
        demand = self.demands[0]
        creator = copy.deepcopy(self.creators[0])
        creator["id"] = "creator-no-python"
        creator["skills"] = [skill for skill in creator["skills"] if skill["tag"] != "python"]
        eligibility = filter_candidate(demand, creator, self.config)
        self.assertFalse(eligibility.eligible)
        self.assertIn("MISSING_MUST_HAVE_SKILL", {item["code"] for item in eligibility.reasons})

    def test_private_compensation_floor_is_a_hard_filter(self):
        creator = copy.deepcopy(self.creators[0])
        creator["compensation"]["minimum_project"] = 999999
        eligibility = filter_candidate(self.demands[0], creator, self.config)
        self.assertFalse(eligibility.eligible)
        self.assertIn("BELOW_PRIVATE_FLOOR", {item["code"] for item in eligibility.reasons})

    def test_explicit_boundary_is_a_hard_filter(self):
        creator = copy.deepcopy(self.creators[0])
        creator["boundaries"]["prohibited_domains"].append("nonprofit")
        eligibility = filter_candidate(self.demands[0], creator, self.config)
        self.assertIn("BOUNDARY_DOMAIN", {item["code"] for item in eligibility.reasons})

    def test_all_three_demands_have_at_least_one_eligible_creator(self):
        for demand in self.demands:
            ranked, _ = rank_candidates(demand, self.creators, self.config)
            self.assertTrue(ranked, demand["id"])


if __name__ == "__main__":
    unittest.main()

