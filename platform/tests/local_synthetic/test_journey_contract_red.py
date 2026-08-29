import tempfile
import unittest
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Sequence, Tuple

from desire_platform.local_synthetic import LocalSyntheticError, LocalSyntheticService


PERSONAS: Tuple[str, ...] = (
    "creator-chen",
    "demand-owner",
    "acceptance-beneficiary",
    "case-operator",
    "payment-initiator",
    "finance-reconciler",
    "appeal-reviewer",
)

OPERATIONS: Tuple[str, ...] = (
    "accept_consent",
    "publish_profile",
    "submit_demand",
    "review_demand",
    "request_demand_funding",
    "reconcile_demand_funding",
    "run_matching",
    "respond_invitation",
    "complete_selection",
    "accept_agreement",
    "request_milestone_funding",
    "reconcile_milestone_funding",
    "start_project",
    "submit_delivery",
    "decide_delivery",
    "confirm_outcome",
    "request_payment",
    "advance_payment_provider",
    "reconcile_payment",
    "record_outcome",
    "submit_report",
    "decide_safety",
    "decide_appeal",
    "request_data_right",
    "exit_participation",
)

# J01 currently models the creator's explicit, purpose-bound consent. Agreement
# acceptance is deliberately repeated because the two parties must independently
# accept one AgreementVersion. The sequence therefore uses all 25 identifiers.
HAPPY_PATH: Tuple[Tuple[str, str], ...] = (
    ("creator-chen", "accept_consent"),
    ("creator-chen", "publish_profile"),
    ("demand-owner", "submit_demand"),
    ("case-operator", "review_demand"),
    ("payment-initiator", "request_demand_funding"),
    ("finance-reconciler", "reconcile_demand_funding"),
    ("case-operator", "run_matching"),
    ("creator-chen", "respond_invitation"),
    ("demand-owner", "complete_selection"),
    ("demand-owner", "accept_agreement"),
    ("creator-chen", "accept_agreement"),
    ("payment-initiator", "request_milestone_funding"),
    ("finance-reconciler", "reconcile_milestone_funding"),
    ("creator-chen", "start_project"),
    ("creator-chen", "submit_delivery"),
    ("acceptance-beneficiary", "decide_delivery"),
    ("acceptance-beneficiary", "confirm_outcome"),
    ("payment-initiator", "request_payment"),
    ("finance-reconciler", "advance_payment_provider"),
    ("finance-reconciler", "reconcile_payment"),
    ("demand-owner", "record_outcome"),
    ("creator-chen", "submit_report"),
    ("case-operator", "decide_safety"),
    ("appeal-reviewer", "decide_appeal"),
    ("creator-chen", "request_data_right"),
    ("creator-chen", "exit_participation"),
)

BOOTSTRAP_KEYS = {
    "session",
    "user",
    "workspaces",
    "current_workspace_id",
    "tasks",
    "workflow",
    "object",
    "allowed_operations",
    "csrf",
    "revision",
}

PREFERRED_CHOICES = {
    ("review_demand", "decision"): "APPROVE",
    ("reconcile_demand_funding", "result"): "SECURED",
    ("respond_invitation", "decision"): "ACCEPT",
    ("reconcile_milestone_funding", "result"): "SECURED",
    ("decide_delivery", "decision"): "ACCEPT",
    ("advance_payment_provider", "result"): "PROCESSING",
    ("reconcile_payment", "result"): "PAID",
    ("decide_safety", "decision"): "REMEDY",
    ("decide_appeal", "decision"): "MODIFY",
    ("request_data_right", "kind"): "ACCESS",
}


def _error_code(error: BaseException) -> Any:
    return getattr(error, "code", None)


class LocalSyntheticJourneyContractRedTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = str(
            Path(self._temporary_directory.name) / "local-synthetic.sqlite3"
        )
        self.service = LocalSyntheticService(self.database_path)

    def tearDown(self) -> None:
        service = getattr(self, "service", None)
        if service is not None:
            service.close()
        self._temporary_directory.cleanup()

    def _create_sessions(
        self, personas: Iterable[str] = PERSONAS
    ) -> Dict[str, MutableMapping[str, Any]]:
        sessions: Dict[str, MutableMapping[str, Any]] = {}
        for persona_id in personas:
            created = self.service.create_session(persona_id)
            self.assertEqual(set(created), {"cookie", "csrf", "session"})
            self.assertIsInstance(created["cookie"], str)
            self.assertTrue(created["cookie"])
            self.assertIsInstance(created["csrf"], str)
            self.assertTrue(created["csrf"])
            self.assertEqual(created["session"]["persona_id"], persona_id)
            sessions[persona_id] = dict(created)
        return sessions

    def _bootstrap(
        self, session: MutableMapping[str, Any]
    ) -> MutableMapping[str, Any]:
        bootstrap = self.service.bootstrap(session["cookie"])
        self.assertEqual(set(bootstrap), BOOTSTRAP_KEYS)
        session["csrf"] = bootstrap["csrf"]
        return bootstrap

    def _input_for(
        self, operation: str, allowed_operation: Mapping[str, Any]
    ) -> Dict[str, Any]:
        action_input: Dict[str, Any] = {}
        for field in allowed_operation["fields"]:
            if not field["required"]:
                continue
            options = field.get("options", [])
            preferred = PREFERRED_CHOICES.get((operation, field["name"]))
            if preferred is not None:
                values = {option["value"] for option in options}
                self.assertIn(preferred, values)
                action_input[field["name"]] = preferred
            elif field["type"] == "choice":
                self.assertTrue(options)
                action_input[field["name"]] = options[0]["value"]
            else:
                action_input[field["name"]] = "本地合成验收输入"
        return action_input

    def _payload_for(
        self,
        bootstrap: Mapping[str, Any],
        operation: str,
        idempotency_key: str = "",
    ) -> Dict[str, Any]:
        descriptors = {
            descriptor["operation"]: descriptor
            for descriptor in bootstrap["allowed_operations"]
        }
        self.assertIn(
            operation,
            descriptors,
            "%s must be exposed by the server at this journey state" % operation,
        )
        return {
            "operation": operation,
            "expected_revision": bootstrap["revision"],
            "idempotency_key": idempotency_key or str(uuid.uuid4()),
            "input": self._input_for(operation, descriptors[operation]),
        }

    def _execute_available(
        self,
        sessions: Mapping[str, MutableMapping[str, Any]],
        persona_id: str,
        operation: str,
    ) -> Any:
        session = sessions[persona_id]
        before = self._bootstrap(session)
        payload = self._payload_for(before, operation)
        receipt = self.service.execute(session["cookie"], session["csrf"], payload)
        after = self._bootstrap(session)
        self.assertGreater(after["revision"], before["revision"])
        return receipt

    def test_persona_allowlist_is_exactly_the_seven_synthetic_accounts(self) -> None:
        """FND-NOD-001; PRD-P1-003; UC-P1-001; ACC-G1-002."""
        listed = self.service.list_personas()
        self.assertEqual(set(listed), {"personas"})
        self.assertEqual(
            tuple(persona["persona_id"] for persona in listed["personas"]),
            PERSONAS,
        )
        self.assertEqual(len(set(PERSONAS)), 7)

        for persona_id in PERSONAS:
            created = self.service.create_session(persona_id)
            self.assertEqual(created["session"]["persona_id"], persona_id)

        with self.assertRaises(LocalSyntheticError) as raised:
            self.service.create_session("eighth-account")
        self.assertEqual(_error_code(raised.exception), "INVALID_PERSONA_ID")

    def test_bootstrap_matches_closed_web_shape_and_server_capabilities(self) -> None:
        """FND-HUM-002/FND-NOD-001; PRD-P1-003; UC-P1-001; ACC-G1-002."""
        sessions = self._create_sessions()
        capability_union = set()

        for persona_id in PERSONAS:
            bootstrap = self._bootstrap(sessions[persona_id])
            self.assertEqual(
                set(bootstrap["session"]),
                {"session_id", "persona_id", "expires_at"},
            )
            self.assertEqual(bootstrap["session"]["persona_id"], persona_id)
            self.assertEqual(set(bootstrap["user"]), {"user_id", "display_name"})
            self.assertTrue(bootstrap["workspaces"])
            for workspace in bootstrap["workspaces"]:
                self.assertEqual(
                    set(workspace),
                    {"workspace_id", "label", "kind", "authorities"},
                )
                self.assertIsInstance(workspace["authorities"], list)
            self.assertIn(
                bootstrap["current_workspace_id"],
                {workspace["workspace_id"] for workspace in bootstrap["workspaces"]},
            )
            self.assertEqual(set(bootstrap["workflow"]), {"current_stage", "stages"})
            self.assertEqual(
                tuple(stage["stage"] for stage in bootstrap["workflow"]["stages"]),
                tuple("J%02d" % number for number in range(1, 13)),
            )
            self.assertIsInstance(bootstrap["revision"], int)
            self.assertGreaterEqual(bootstrap["revision"], 0)
            self.assertTrue(bootstrap["csrf"])

            descriptors = {
                descriptor["operation"]: descriptor
                for descriptor in bootstrap["allowed_operations"]
            }
            if persona_id == "creator-chen":
                self.assertIn("accept_consent", descriptors)
            else:
                self.assertNotIn("accept_consent", descriptors)
            for descriptor in descriptors.values():
                self.assertEqual(
                    set(descriptor), {"operation", "label", "kind", "fields"}
                )
                self.assertIn(descriptor["operation"], OPERATIONS)
                for field in descriptor["fields"]:
                    self.assertIn(
                        set(field),
                        (
                            {"name", "label", "type", "required"},
                            {"name", "label", "type", "required", "options"},
                        ),
                    )

            for task in bootstrap["tasks"]:
                self.assertEqual(
                    set(task),
                    {
                        "task_id",
                        "title",
                        "summary",
                        "status",
                        "due_at",
                        "object_id",
                        "object_type",
                        "authority",
                        "allowed_operations",
                    },
                )
                self.assertLessEqual(set(task["allowed_operations"]), set(descriptors))
            capability_union.update(descriptors)

        case_operator = self._bootstrap(sessions["case-operator"])
        operator_authorities = {
            authority
            for workspace in case_operator["workspaces"]
            for authority in workspace["authorities"]
        }
        self.assertIn("LOCAL_FIXTURE_ADMIN", operator_authorities)
        self.assertEqual(capability_union, {"accept_consent"})

    def test_all_25_operations_complete_j01_to_j12_in_role_order(self) -> None:
        """FND-COL-001/008; PRD-P1-001..019; UC-P1-001..025; ACC-G1-002..017."""
        self.assertEqual({operation for _, operation in HAPPY_PATH}, set(OPERATIONS))
        self.assertEqual(len(set(OPERATIONS)), 25)
        sessions = self._create_sessions()

        for persona_id, operation in HAPPY_PATH:
            with self.subTest(persona_id=persona_id, operation=operation):
                self._execute_available(sessions, persona_id, operation)

        final_projection = self._bootstrap(sessions["case-operator"])
        self.assertNotIn(
            "UPCOMING",
            {stage["status"] for stage in final_projection["workflow"]["stages"]},
        )

    def test_stale_revision_is_rejected_without_a_second_write(self) -> None:
        """FND-COL-004; PRD-P1-004; UC-P1-010; ACC-G1-008."""
        sessions = self._create_sessions(("creator-chen",))
        session = sessions["creator-chen"]
        initial = self._bootstrap(session)
        first = self._payload_for(initial, "accept_consent")
        self.service.execute(session["cookie"], session["csrf"], first)
        current = self._bootstrap(session)
        stale = self._payload_for(current, "publish_profile")
        stale["expected_revision"] = initial["revision"]

        with self.assertRaises(LocalSyntheticError) as raised:
            self.service.execute(session["cookie"], session["csrf"], stale)
        self.assertEqual(_error_code(raised.exception), "REVISION_MISMATCH")
        self.assertEqual(
            self._bootstrap(session)["revision"], current["revision"]
        )

    def test_idempotency_replays_same_intent_and_rejects_changed_intent(self) -> None:
        """FND-COL-008; PRD-P1-011; UC-P1-015; ACC-G1-013."""
        sessions = self._create_sessions(("creator-chen",))
        session = sessions["creator-chen"]
        bootstrap = self._bootstrap(session)
        payload = self._payload_for(
            bootstrap, "accept_consent", idempotency_key=str(uuid.uuid4())
        )

        first = self.service.execute(session["cookie"], session["csrf"], payload)
        replay = self.service.execute(session["cookie"], session["csrf"], payload)
        self.assertEqual(replay, first)
        committed_revision = self._bootstrap(session)["revision"]

        changed_intent = dict(payload)
        changed_intent["expected_revision"] = payload["expected_revision"] + 1
        with self.assertRaises(LocalSyntheticError) as raised:
            self.service.execute(
                session["cookie"], session["csrf"], changed_intent
            )
        self.assertEqual(_error_code(raised.exception), "IDEMPOTENCY_KEY_REUSED")
        self.assertEqual(
            self._bootstrap(session)["revision"], committed_revision
        )

    def test_actor_and_authority_fields_are_rejected_at_any_depth(self) -> None:
        """FND-NOD-001; PRD-P1-003; UC-P1-004; ACC-G1-004."""
        sessions = self._create_sessions(("creator-chen",))
        session = sessions["creator-chen"]
        initial = self._bootstrap(session)

        forbidden_variants: Sequence[Tuple[str, Dict[str, Any]]] = (
            ("top-level actor", {"actor": "case-operator"}),
            ("top-level authority", {"authority": "local_fixture_admin"}),
            ("nested actor", {"input": {"actor": "case-operator"}}),
            ("nested authority", {"input": {"authority": "payment_reconciler"}}),
        )
        for label, mutation in forbidden_variants:
            with self.subTest(label=label):
                payload = self._payload_for(initial, "accept_consent")
                if "input" in mutation:
                    payload["input"].update(mutation["input"])
                else:
                    payload.update(mutation)
                with self.assertRaises(LocalSyntheticError) as raised:
                    self.service.execute(
                        session["cookie"], session["csrf"], payload
                    )
                self.assertEqual(
                    _error_code(raised.exception), "FORBIDDEN_INPUT_FIELD"
                )

        self.assertEqual(self._bootstrap(session)["revision"], initial["revision"])

    def test_committed_projection_and_session_survive_service_restart(self) -> None:
        """FND-REP-001; PRD-P1-014; UC-P1-025; ACC-G1-017."""
        sessions = self._create_sessions(("creator-chen",))
        session = sessions["creator-chen"]
        before = self._bootstrap(session)
        self._execute_available(sessions, "creator-chen", "accept_consent")
        committed = self._bootstrap(session)
        self.assertGreater(committed["revision"], before["revision"])

        self.service.close()
        self.service = LocalSyntheticService(self.database_path)

        recovered = self.service.bootstrap(session["cookie"])
        self.assertEqual(recovered["revision"], committed["revision"])
        self.assertEqual(
            recovered["workflow"]["stages"], committed["workflow"]["stages"]
        )
        self.assertIn(
            "publish_profile",
            {
                descriptor["operation"]
                for descriptor in recovered["allowed_operations"]
            },
        )

    def test_server_rejects_operations_outside_session_authority(self) -> None:
        """FND-SEP-001; PRD-P1-003; UC-P1-015; ACC-G1-004."""
        sessions = self._create_sessions(
            ("payment-initiator", "case-operator")
        )
        probes = (
            ("payment-initiator", "reconcile_demand_funding"),
            ("case-operator", "decide_appeal"),
        )

        for persona_id, operation in probes:
            with self.subTest(persona_id=persona_id, operation=operation):
                session = sessions[persona_id]
                before = self._bootstrap(session)
                self.assertNotIn(
                    operation,
                    {
                        descriptor["operation"]
                        for descriptor in before["allowed_operations"]
                    },
                )
                payload = {
                    "operation": operation,
                    "expected_revision": before["revision"],
                    "idempotency_key": str(uuid.uuid4()),
                    "input": {},
                }
                with self.assertRaises(LocalSyntheticError) as raised:
                    self.service.execute(
                        session["cookie"], session["csrf"], payload
                    )
                self.assertEqual(_error_code(raised.exception), "ACCESS_DENIED")
                self.assertEqual(
                    self._bootstrap(session)["revision"], before["revision"]
                )


if __name__ == "__main__":
    unittest.main()
