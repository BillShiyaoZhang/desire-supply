"""Contract checks for the real-brief fixture, without changing live data."""
from dataclasses import asdict
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from desire_platform.demand.domain import validate_demand_content
from desire_platform.internal_pilot.editor.content_choices import (
    internal_sandbox_editor_choices, validate_editor_choice_membership,
)
from desire_platform.internal_pilot.editor.sandbox_evidence import (
    _demand_is_synthetic, _freeze_demand_content,
)

spec = importlib.util.spec_from_file_location("pet_feed_simulation", Path(__file__).with_name("simulate.py"))
simulation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(simulation)


class PetFeedFixtureTest(unittest.TestCase):
    def test_original_stays_a_valid_partial_hardware_draft(self):
        content = simulation.original_content()
        validate_demand_content(_freeze_demand_content(content), for_submission=False)
        self.assertEqual(set(content), {"scope"})
        self.assertIn(simulation.compact_idea(), content["scope"]["deliverables"][0]["description"])

    def test_both_software_revisions_satisfy_real_submission_and_sandbox_policy(self):
        catalog = internal_sandbox_editor_choices()
        for refined in (False, True):
            with self.subTest(refined=refined):
                content = simulation.software_content(json.loads(json.dumps(asdict(catalog))),
                    original_id="85210ced-f3bc-4a37-b07a-ae98918f0755", refined=refined)
                validate_demand_content(_freeze_demand_content(content), for_submission=True)
                validate_editor_choice_membership(resource_type="DEMAND", content=content, choices=catalog)
                self.assertTrue(_demand_is_synthetic(content))
                self.assertEqual(content["budget"], {"minimum_amount_minor": 0,
                    "maximum_amount_minor": 0, "direct_cost_amount_minor": 0, "currency": "CNY"})
                self.assertEqual(sum(x["percent"] for x in content["milestone_plan"]["items"]), 100)
                self.assertIn("软件分析子需求", content["problem"]["background"])
                self.assertIn("真实检测方案待确认", content["acceptance"]["criteria"][2]["description"])

    def test_public_action_log_excludes_credentials_and_private_payloads(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "actions.json"
            response = simulation.base.HttpResult(200, {}, json.dumps({"data": {
                "status": "DRAFT", "object_id": "public-id", "csrf_token": "secret-value",
                "private_floor": 123, "content": {"token": "secret-value"},
            }}).encode())
            session = SimpleNamespace(account_code="demand_owner_01", role_codes=("DEMAND_OWNER",),
                client=SimpleNamespace(request=lambda **_: response))
            recorder = simulation.Recorder(path)
            recorder.attach(session)
            session.client.request(method="POST", path="/v1/app/demands", body={"secret": "secret-value"},
                headers={"Cookie": "secret-value", "X-CSRF-Token": "secret-value"})
            text = path.read_text()
            self.assertNotIn("secret-value", text)
            self.assertNotIn("private_floor", text)
            self.assertEqual(json.loads(text)[0]["result"], {"status": "DRAFT", "object_id": "public-id"})

    def test_error_envelopes_are_recorded_without_sensitive_details(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "actions.json"
            response = simulation.base.HttpResult(422, {}, json.dumps({"error": {
                "code": "EDITOR_CHOICE_UNAVAILABLE", "path": "/content/problem/domain_code",
                "details": {"private_note": "hidden"},
            }}).encode())
            session = SimpleNamespace(account_code="demand_owner_01", role_codes=("DEMAND_OWNER",),
                client=SimpleNamespace(request=lambda **_: response))
            recorder = simulation.Recorder(path)
            recorder.attach(session)
            session.client.request(method="PUT", path="/v1/app/demands/example/draft")
            self.assertEqual(json.loads(path.read_text())[0]["result"], {
                "code": "EDITOR_CHOICE_UNAVAILABLE", "path": "/content/problem/domain_code"})


if __name__ == "__main__":
    unittest.main()
