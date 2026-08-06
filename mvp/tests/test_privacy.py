import copy
import unittest

from desire_mvp.config import load_config
from desire_mvp.explanations import explain_candidate
from desire_mvp.matching import score_candidate
from desire_mvp.privacy import assert_external_output_safe, find_prohibited_identity_fields

from helpers import ROOT, load_sample


class PrivacyTests(unittest.TestCase):
    def setUp(self):
        self.demand = load_sample("demands.json")[0]
        self.creator = load_sample("creators.json")[0]
        self.config = load_config(ROOT / "config").matching

    def test_match_brief_does_not_leak_private_floor(self):
        score = score_candidate(self.demand, self.creator, self.config)
        brief = explain_candidate(self.demand, self.creator, score)
        assert_external_output_safe(brief.to_dict(), [self.creator])
        serialized = str(brief.to_dict())
        self.assertNotIn(str(self.creator["compensation"]["minimum_project"]), serialized)

    def test_leak_guard_detects_private_value(self):
        with self.assertRaises(ValueError):
            assert_external_output_safe(
                {"text": "底线是 {}".format(self.creator["compensation"]["minimum_project"])},
                [self.creator],
            )

    def test_identity_fields_are_rejected_at_any_depth(self):
        record = copy.deepcopy(self.creator)
        record["notes"] = {"email": "person@example.invalid"}
        self.assertEqual(find_prohibited_identity_fields(record), ["notes.email"])


if __name__ == "__main__":
    unittest.main()

