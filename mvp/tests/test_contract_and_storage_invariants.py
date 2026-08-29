"""Red tests for fixed payload and row/payload identity invariants.

These checks deliberately live outside the migration fault-injection suites so
the static payload contract and storage-identity boundary can evolve without
coupling to migration transaction internals.
"""

import copy
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from desire_mvp.migrations import MigrationRunner
from desire_mvp.repository import Repository, canonical_json
from desire_mvp.schema import SchemaContractError, validate_payload_contract

from helpers import load_sample
from migration_fixtures import create_legacy_database


class FixedPayloadInvariantTests(unittest.TestCase):
    def assert_contract_rejects(self, record_type, record):
        before = copy.deepcopy(record)
        with self.assertRaises(SchemaContractError):
            validate_payload_contract(record_type, record)
        self.assertEqual(before, record)

    def test_demand_contract_rejects_fixed_cross_field_contradictions(self):
        cases = (
            (
                "payment-percent-total",
                lambda value: value["payment"]["plan"][0].__setitem__("percent", 1),
            ),
            (
                "schedule-range",
                lambda value: value["schedule"].update(
                    {"start_date": "2026-10-02", "due_date": "2026-10-01"}
                ),
            ),
            (
                "budget-range",
                lambda value: value["budget"].update(
                    {"minimum": value["budget"]["maximum"] + 1}
                ),
            ),
        )
        for case, mutate in cases:
            with self.subTest(case=case):
                demand = copy.deepcopy(load_sample("demands.json")[0])
                mutate(demand)
                self.assert_contract_rejects("demand", demand)

    def test_creator_contract_rejects_duplicate_skill_tags(self):
        creator = copy.deepcopy(load_sample("creators.json")[0])
        duplicate = copy.deepcopy(creator["skills"][0])
        duplicate["evidence_ref"] = "external://duplicate-skill-evidence"
        creator["skills"].append(duplicate)

        self.assert_contract_rejects("creator", creator)

    def test_outcome_contract_rejects_fixed_state_and_cardinality_contradictions(self):
        cases = (
            (
                "completed-without-payment",
                lambda value: value.__setitem__("real_payment", False),
            ),
            (
                "completed-with-failure",
                lambda value: value.update(
                    {
                        "failure_primary": "QUALITY",
                        "failure_secondary": ["COMMUNICATION"],
                    }
                ),
            ),
            (
                "failed-without-primary-failure",
                lambda value: value.update(
                    {"status": "failed", "failure_primary": None}
                ),
            ),
            (
                "preference-cardinality",
                lambda value: value.__setitem__(
                    "creator_preference_confirmed", []
                ),
            ),
            (
                "willingness-cardinality",
                lambda value: value["willing_to_use_again"].__setitem__(
                    "creators", []
                ),
            ),
            (
                "planned-date-range",
                lambda value: value.update(
                    {"planned_start": "2026-10-02", "planned_finish": "2026-10-01"}
                ),
            ),
            (
                "actual-date-range",
                lambda value: value.update(
                    {"actual_start": "2026-10-02", "actual_finish": "2026-10-01"}
                ),
            ),
        )
        for case, mutate in cases:
            with self.subTest(case=case):
                outcome = copy.deepcopy(load_sample("outcome.json"))
                mutate(outcome)
                self.assert_contract_rejects("outcome", outcome)


class StorageIdentityInvariantTests(unittest.TestCase):
    EXPECTED_BLOCKER = "LEGACY_ROW_METADATA_MISMATCH"

    def test_legacy_preflight_rejects_row_metadata_payload_mismatches(self):
        cases = (
            (
                "entity-id",
                "UPDATE entities SET entity_id=? WHERE kind='demand'",
                ("demand-row-shadow",),
            ),
            (
                "entity-pilot-id",
                "UPDATE entities SET pilot_id=? WHERE kind='demand'",
                ("pilot-row-shadow",),
            ),
            (
                "outcome-project-id",
                "UPDATE outcomes SET project_id=?",
                ("project-row-shadow",),
            ),
            (
                "outcome-pilot-id",
                "UPDATE outcomes SET pilot_id=?",
                ("pilot-row-shadow",),
            ),
            (
                "outcome-demand-id",
                "UPDATE outcomes SET demand_id=?",
                ("demand-row-shadow",),
            ),
            (
                "outcome-creator-ids",
                "UPDATE outcomes SET creator_ids_json=?",
                (json.dumps(["creator-row-shadow"]),),
            ),
        )
        for case, statement, params in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                data_dir = Path(directory) / "legacy"
                database_path = create_legacy_database(data_dir)
                with sqlite3.connect(str(database_path)) as connection:
                    connection.execute(statement, params)
                    connection.commit()

                plan = MigrationRunner(Repository(data_dir)).plan(target_version=1)

                self.assertEqual(
                    [(self.EXPECTED_BLOCKER, 1)],
                    [(item.code, item.count) for item in plan.blockers],
                )

    def test_current_repository_reads_reject_row_metadata_payload_mismatches(self):
        demand_template = load_sample("demands.json")[0]
        outcome_template = load_sample("outcome.json")

        for case in (
            "entity-id",
            "entity-pilot-id",
            "outcome-project-id",
            "outcome-pilot-id",
            "outcome-demand-id",
            "outcome-creator-ids",
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                repository = Repository(Path(directory))
                repository.initialize()
                demand = copy.deepcopy(demand_template)
                outcome = copy.deepcopy(outcome_template)
                repository.put_entity("demand", demand)
                repository.record_outcome(outcome)

                entity_lookup_id = demand["id"]
                outcome_lookup_pilot = outcome["pilot_id"]
                with sqlite3.connect(str(repository.path)) as connection:
                    if case == "entity-id":
                        entity_lookup_id = "demand-row-shadow"
                        connection.execute(
                            "UPDATE entities SET entity_id=? WHERE kind='demand'",
                            (entity_lookup_id,),
                        )
                    elif case == "entity-pilot-id":
                        outcome_lookup_pilot = outcome["pilot_id"]
                        connection.execute(
                            "UPDATE entities SET pilot_id=? WHERE kind='demand'",
                            ("pilot-row-shadow",),
                        )
                    elif case == "outcome-project-id":
                        connection.execute(
                            "UPDATE outcomes SET project_id=?",
                            ("project-row-shadow",),
                        )
                    elif case == "outcome-pilot-id":
                        outcome_lookup_pilot = "pilot-row-shadow"
                        connection.execute(
                            "UPDATE outcomes SET pilot_id=?",
                            (outcome_lookup_pilot,),
                        )
                    elif case == "outcome-demand-id":
                        connection.execute(
                            "UPDATE outcomes SET demand_id=?",
                            ("demand-row-shadow",),
                        )
                    else:
                        connection.execute(
                            "UPDATE outcomes SET creator_ids_json=?",
                            (canonical_json(["creator-row-shadow"]),),
                        )
                    connection.commit()

                with self.assertRaises(SchemaContractError) as raised:
                    if case == "entity-id":
                        repository.get_entity("demand", entity_lookup_id)
                    elif case == "entity-pilot-id":
                        repository.list_entities("demand", "pilot-row-shadow")
                    else:
                        repository.outcomes_for_pilot(outcome_lookup_pilot)
                self.assertEqual("INVALID_PAYLOAD_SCHEMA", raised.exception.code)


if __name__ == "__main__":
    unittest.main()
