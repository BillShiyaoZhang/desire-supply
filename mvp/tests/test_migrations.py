import copy
import unittest

from desire_mvp.migrations import (
    MigrationError,
    migrate_record_v0_to_v1,
)

from helpers import load_sample


def load_v0_sample(name, index=None):
    loaded = load_sample(name)
    record = copy.deepcopy(loaded if index is None else loaded[index])
    record.pop("schema_version", None)
    return record


def resolution(demand_id, target, reason, evidence="external://migration-review-001"):
    return {
        "demand_id": demand_id,
        "from": "closed",
        "to": target,
        "reason_code": reason,
        "evidence_ref": evidence,
    }


class RecordMigrationTests(unittest.TestCase):
    """TEST-UNIT-MIG-002 / REQ-MIG-002."""

    def assert_migration_error(self, expected_code, record, *, record_type="demand", resolutions=None):
        with self.assertRaises(MigrationError) as raised:
            migrate_record_v0_to_v1(
                record_type,
                record,
                resolutions=[] if resolutions is None else resolutions,
            )
        self.assertEqual(expected_code, raised.exception.code)

    def test_v0_to_v1_is_pure_and_explicit(self):
        source = load_v0_sample("demands.json", 0)
        source_before = copy.deepcopy(source)

        first = migrate_record_v0_to_v1("demand", source, resolutions=[])
        second = migrate_record_v0_to_v1(
            "demand",
            copy.deepcopy(source),
            resolutions=[],
        )

        self.assertEqual(source_before, source, "migration must not mutate its input")
        self.assertIsNot(first.record, source)
        self.assertIsNot(first.record["problem"], source["problem"])
        self.assertEqual(1, first.record["schema_version"])
        self.assertEqual(source, {key: value for key, value in first.record.items() if key != "schema_version"})
        self.assertTrue(first.changed)
        self.assertEqual(("SCHEMA_VERSION_ADDED",), tuple(first.change_codes))

        self.assertEqual(first.record, second.record)
        self.assertEqual(first.changed, second.changed)
        self.assertEqual(tuple(first.change_codes), tuple(second.change_codes))
        self.assertIsNone(first.resolution_code)
        self.assertIsNone(first.resolution_ref)

    def test_outcome_v0_only_gains_the_schema_version(self):
        source = load_v0_sample("outcome.json")
        before = copy.deepcopy(source)

        result = migrate_record_v0_to_v1("outcome", source, resolutions=[])

        self.assertEqual(before, source)
        self.assertEqual(1, result.record["schema_version"])
        self.assertEqual(before, {key: value for key, value in result.record.items() if key != "schema_version"})
        self.assertEqual(("SCHEMA_VERSION_ADDED",), tuple(result.change_codes))

    def test_creator_withdrawn_has_one_deterministic_mapping(self):
        source = load_v0_sample("creators.json", 0)
        source["status"] = "withdrawn"
        before = copy.deepcopy(source)

        result = migrate_record_v0_to_v1("creator", source, resolutions=[])

        self.assertEqual(before, source)
        self.assertEqual(1, result.record["schema_version"])
        self.assertEqual("inactive", result.record["status"])
        self.assertEqual(
            ("SCHEMA_VERSION_ADDED", "WITHDRAWN_TO_INACTIVE"),
            tuple(result.change_codes),
        )
        expected = copy.deepcopy(before)
        expected.update({"schema_version": 1, "status": "inactive"})
        self.assertEqual(expected, result.record)

    def test_closed_demand_requires_exactly_one_resolution(self):
        source = load_v0_sample("demands.json", 0)
        source["status"] = "closed"
        before = copy.deepcopy(source)

        self.assert_migration_error(
            "MISSING_DEMAND_STATUS_RESOLUTION",
            source,
            resolutions=[],
        )
        self.assertEqual(before, source)

    def test_closed_resolution_targets_reasons_and_evidence_are_controlled(self):
        legal_cases = (
            ("agreed", "PROJECT_ESTABLISHED"),
            ("cancelled", "NO_PROJECT_ESTABLISHED"),
            ("agreed", "OPERATOR_CORRECTION"),
            ("cancelled", "OPERATOR_CORRECTION"),
        )
        for target, reason_code in legal_cases:
            with self.subTest(target=target, reason_code=reason_code):
                source = load_v0_sample("demands.json", 0)
                source["status"] = "closed"
                resolutions = [resolution(source["id"], target, reason_code)]
                before_record = copy.deepcopy(source)
                before_resolutions = copy.deepcopy(resolutions)

                result = migrate_record_v0_to_v1(
                    "demand",
                    source,
                    resolutions=resolutions,
                )

                self.assertEqual(before_record, source)
                self.assertEqual(before_resolutions, resolutions)
                self.assertEqual(target, result.record["status"])
                self.assertEqual(1, result.record["schema_version"])
                self.assertEqual(reason_code, result.resolution_code)
                self.assertEqual("external://migration-review-001", result.resolution_ref)

        invalid_cases = (
            ("unknown-target", resolution("demand-demo-001", "closed", "OPERATOR_CORRECTION")),
            ("unknown-reason", resolution("demand-demo-001", "agreed", "UNKNOWN_REASON")),
            ("contradictory-agreed", resolution("demand-demo-001", "agreed", "NO_PROJECT_ESTABLISHED")),
            ("contradictory-cancelled", resolution("demand-demo-001", "cancelled", "PROJECT_ESTABLISHED")),
            ("empty-evidence", resolution("demand-demo-001", "agreed", "PROJECT_ESTABLISHED", evidence="")),
        )
        for case, invalid_resolution in invalid_cases:
            with self.subTest(case=case):
                source = load_v0_sample("demands.json", 0)
                source["status"] = "closed"
                before_record = copy.deepcopy(source)
                before_resolution = copy.deepcopy(invalid_resolution)

                self.assert_migration_error(
                    "INVALID_DEMAND_STATUS_RESOLUTION",
                    source,
                    resolutions=[invalid_resolution],
                )
                self.assertEqual(before_record, source)
                self.assertEqual(before_resolution, invalid_resolution)

    def test_unused_resolution_blocks_migration(self):
        source = load_v0_sample("demands.json", 0)
        before = copy.deepcopy(source)
        unused = resolution(source["id"], "agreed", "PROJECT_ESTABLISHED")

        self.assert_migration_error(
            "UNUSED_DEMAND_STATUS_RESOLUTION",
            source,
            resolutions=[unused],
        )
        self.assertEqual(before, source)

    def test_v1_is_identity_and_does_not_generate_migration_audit(self):
        source = copy.deepcopy(load_sample("demands.json")[0])
        source["schema_version"] = 1
        before = copy.deepcopy(source)

        result = migrate_record_v0_to_v1("demand", source, resolutions=[])

        self.assertIs(result.record, source, "v1 must not be copied or reserialized")
        self.assertEqual(before, source)
        self.assertFalse(result.changed)
        self.assertEqual((), tuple(result.change_codes))
        self.assertIsNone(result.resolution_code)
        self.assertIsNone(result.resolution_ref)

    def test_unknown_explicit_versions_are_not_converted(self):
        for version in (0, False, True, "1", 2):
            with self.subTest(version=version):
                source = copy.deepcopy(load_sample("demands.json")[0])
                source["schema_version"] = version
                before = copy.deepcopy(source)

                self.assert_migration_error(
                    "UNSUPPORTED_SCHEMA_VERSION",
                    source,
                    resolutions=[],
                )
                self.assertEqual(before, source)


if __name__ == "__main__":
    unittest.main()
