import copy
import unittest

from desire_mvp.budget import assess_budget
from desire_mvp.config import load_config

from helpers import ROOT, load_sample


class BudgetTests(unittest.TestCase):
    def setUp(self):
        self.config = load_config(ROOT / "config").budget
        self.demand = load_sample("demands.json")[0]

    def test_sample_budget_is_green_and_traceable(self):
        result = assess_budget(self.demand, self.config)
        self.assertEqual(result.status, "GREEN")
        self.assertGreater(result.recommended_minimum, result.labor_baseline)
        self.assertEqual(result.config_version, "budget-v1")
        self.assertEqual(result.assumptions["estimated_days"], 10)

    def test_health_boundaries(self):
        demand = copy.deepcopy(self.demand)
        baseline = assess_budget(demand, self.config).recommended_minimum
        demand["budget"]["maximum"] = baseline * 0.79
        self.assertEqual(assess_budget(demand, self.config).status, "RED")
        demand["budget"]["maximum"] = baseline * 0.8
        self.assertEqual(assess_budget(demand, self.config).status, "YELLOW")
        demand["budget"]["maximum"] = baseline
        self.assertEqual(assess_budget(demand, self.config).status, "GREEN")

    def test_risk_buffer_is_capped(self):
        demand = copy.deepcopy(self.demand)
        demand["risk"].update({"uncertainty": "very_high", "urgency": "very_high", "external_dependencies": "very_high"})
        result = assess_budget(demand, self.config)
        self.assertEqual(result.risk_buffer_rate, 0.5)


if __name__ == "__main__":
    unittest.main()

