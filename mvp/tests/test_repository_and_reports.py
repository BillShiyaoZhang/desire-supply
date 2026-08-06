import tempfile
import unittest
from pathlib import Path

from desire_mvp.budget import assess_budget
from desire_mvp.config import load_config
from desire_mvp.matching import rank_candidates
from desire_mvp.reports import build_pilot_report, report_to_csv, report_to_markdown
from desire_mvp.repository import Repository

from helpers import ROOT, load_sample


class RepositoryAndReportTests(unittest.TestCase):
    def test_snapshot_survives_profile_changes_and_report_is_complete(self):
        configs = load_config(ROOT / "config")
        demands = load_sample("demands.json")
        creators = load_sample("creators.json")
        outcome = load_sample("outcome.json")
        with tempfile.TemporaryDirectory() as directory:
            repository = Repository(Path(directory))
            repository.initialize()
            for demand in demands:
                repository.put_entity("demand", demand)
            for creator in creators:
                repository.put_entity("creator", creator)
            demand = demands[0]
            ranked, excluded = rank_candidates(demand, creators, configs.matching)
            result = {"ranked": [item.to_dict() for item in ranked], "excluded": excluded, "invalid_creators": []}
            recommendation_id = repository.record_recommendation(
                demand,
                creators,
                configs.rule_version,
                result,
                assess_budget(demand, configs.budget).to_dict(),
            )
            selected = ranked[0].creator_id
            repository.record_decision(
                recommendation_id,
                demand["id"],
                demand["pilot_id"],
                selected,
                [selected],
                [{"creator_id": selected, "code": "ACCEPT"}],
                "ALGORITHM_TOP",
                None,
            )
            changed = dict(demand)
            changed["problem"] = dict(demand["problem"], desired_outcome="later edit")
            repository.put_entity("demand", changed)
            self.assertNotEqual(
                repository.latest_recommendation(demand["id"])["input_snapshot"]["demand"]["problem"]["desired_outcome"],
                "later edit",
            )
            outcome["creator_ids"] = [selected]
            repository.record_outcome(outcome)
            report = build_pilot_report(repository, "pilot-demo")
            self.assertEqual(report["metrics"]["funnel"]["completed"], 1)
            self.assertEqual(report["metrics"]["matching"]["top3_hits"], 1)
            self.assertIn("愿作 MVP 批次报告", report_to_markdown(report))
            self.assertIn("pilot_id,metric,value", report_to_csv(report))


if __name__ == "__main__":
    unittest.main()
