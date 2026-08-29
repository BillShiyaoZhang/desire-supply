import unittest

from desire_mvp.config import load_config
from desire_mvp.decisions import DecisionError, validate_decision

from helpers import ROOT


class DecisionTests(unittest.TestCase):
    def setUp(self):
        self.reasons = load_config(ROOT / "config").reason_codes
        self.recommendation = {
            "result": {
                "ranked": [
                    {"creator_id": "creator-1"},
                    {"creator_id": "creator-2"},
                ]
            }
        }

    def test_valid_decision_and_responses(self):
        validate_decision(
            self.recommendation,
            "creator-1",
            ["creator-1", "creator-2"],
            [
                {"creator_id": "creator-1", "code": "ACCEPT"},
                {"creator_id": "creator-2", "code": "CAPACITY"},
            ],
            "ALGORITHM_TOP",
            None,
            self.reasons,
        )

    def test_cannot_restore_hard_filtered_creator(self):
        with self.assertRaises(DecisionError):
            validate_decision(
                self.recommendation,
                "creator-filtered",
                ["creator-filtered"],
                [],
                "MISSING_CONTEXT",
                "interview context",
                self.reasons,
            )

    def test_other_response_requires_note(self):
        with self.assertRaises(DecisionError):
            validate_decision(
                self.recommendation,
                None,
                ["creator-1"],
                [{"creator_id": "creator-1", "code": "OTHER"}],
                "NO_MATCH",
                None,
                self.reasons,
            )

    def test_response_type_mutations_raise_decision_error(self):
        for field, invalid in (("code", []), ("code", {}), ("creator_id", {})):
            with self.subTest(field=field, invalid=invalid):
                response = {"creator_id": "creator-1", "code": "ACCEPT"}
                response[field] = invalid
                with self.assertRaises(DecisionError):
                    validate_decision(
                        self.recommendation,
                        None,
                        ["creator-1"],
                        [response],
                        "ALGORITHM_TOP",
                        None,
                        self.reasons,
                    )


if __name__ == "__main__":
    unittest.main()
