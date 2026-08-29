from __future__ import annotations

import unittest

from desire_platform.internal_pilot.schema_readiness import (
    PostgresSchemaCompatibilityReadiness,
    SchemaCompatibilityError,
    SchemaCompatibilityRequirement,
)


class Result:
    def __init__(self, row):
        self.row = row

    def fetchone(self):
        return self.row


class Connection:
    def __init__(self, rows):
        self.rows = rows
        self.statements = []

    def execute(self, statement):
        self.statements.append(statement)
        return Result(self.rows.get(statement))


class Pool:
    def __init__(self, rows):
        self.connection = Connection(rows)
        self.released = []
        self.discarded = []

    def checkout(self):
        return self.connection

    def release(self, connection):
        self.released.append(connection)

    def discard(self, connection):
        self.discarded.append(connection)


class SchemaCompatibilityReadinessTests(unittest.TestCase):
    def test_exact_component_views_are_checked_without_writes(self) -> None:
        requirements = (
            SchemaCompatibilityRequirement(
                component="iam",
                expected_schema_head=22,
                expected_contract_sha256=b"i" * 32,
                required_iam_schema_version=None,
            ),
            SchemaCompatibilityRequirement(
                component="profile",
                expected_schema_head=2,
                expected_contract_sha256=b"p" * 32,
                required_iam_schema_version=None,
            ),
            SchemaCompatibilityRequirement(
                component="demand",
                expected_schema_head=10,
                expected_contract_sha256=b"d" * 32,
                required_iam_schema_version=37,
                expected_idempotency_key_id="demand-idempotency-2026-01",
                expected_payload_key_id="demand-payload-2026-01",
                expected_retained_idempotency_key_ids=(
                    "demand-idempotency-2026-01",
                    "demand-idempotency-old",
                ),
                expected_retained_payload_key_ids=(
                    "demand-payload-2026-01",
                    "demand-payload-old",
                ),
            ),
            SchemaCompatibilityRequirement(
                component="trust",
                expected_schema_head=8,
                expected_contract_sha256=b"t" * 32,
                required_iam_schema_version=38,
                required_demand_schema_version=10,
                expected_iam_contract_sha256=b"i" * 32,
                expected_demand_contract_sha256=b"d" * 32,
                expected_combined_contract_sha256=b"c" * 32,
            ),
            SchemaCompatibilityRequirement(
                component="matching",
                expected_schema_head=2,
                expected_contract_sha256=b"m" * 32,
                required_iam_schema_version=43,
            ),
        )
        rows = {
            PostgresSchemaCompatibilityReadiness.statement_for("iam"): (
                "iam",
                22,
                22,
                22,
                22,
                b"i" * 32,
            ),
            PostgresSchemaCompatibilityReadiness.statement_for("profile"): (
                "profile",
                2,
                2,
                2,
                2,
                b"p" * 32,
            ),
            PostgresSchemaCompatibilityReadiness.statement_for("demand"): (
                "demand",
                10,
                10,
                10,
                10,
                37,
                b"d" * 32,
                "demand-idempotency-2026-01",
                "demand-payload-2026-01",
                ["demand-idempotency-2026-01", "demand-idempotency-old"],
                ["demand-payload-2026-01", "demand-payload-old"],
            ),
            PostgresSchemaCompatibilityReadiness.statement_for("trust"): (
                "trust",
                8,
                8,
                8,
                8,
                38,
                10,
                b"i" * 32,
                b"d" * 32,
                b"c" * 32,
                b"t" * 32,
            ),
            PostgresSchemaCompatibilityReadiness.statement_for("matching"): (
                "matching",
                2,
                2,
                2,
                2,
                43,
                b"m" * 32,
            ),
        }
        for requirement in requirements:
            with self.subTest(component=requirement.component):
                pool = Pool(rows)
                readiness = PostgresSchemaCompatibilityReadiness(
                    pool=pool,
                    requirement=requirement,
                )
                self.assertIsNone(readiness.check_readiness(timeout_ms=100))
                self.assertEqual(pool.released, [pool.connection])
                self.assertEqual(pool.discarded, [])
                self.assertFalse(
                    any(
                        token in pool.connection.statements[0].upper()
                        for token in ("INSERT", "UPDATE", "DELETE", "ALTER", "CREATE")
                    )
                )
                readiness.close()

    def test_drift_missing_row_and_database_error_fail_closed_and_discard(self) -> None:
        requirement = SchemaCompatibilityRequirement(
            component="profile",
            expected_schema_head=2,
            expected_contract_sha256=b"p" * 32,
            required_iam_schema_version=None,
        )
        statement = PostgresSchemaCompatibilityReadiness.statement_for("profile")
        for row in (
            None,
            ("profile", 1, 2, 2, 2, b"p" * 32),
            ("profile", 2, 2, 2, 2, b"x" * 32),
            ("demand", 2, 2, 2, 2, b"p" * 32),
        ):
            with self.subTest(row=row):
                pool = Pool({statement: row})
                readiness = PostgresSchemaCompatibilityReadiness(
                    pool=pool,
                    requirement=requirement,
                )
                with self.assertRaises(SchemaCompatibilityError) as raised:
                    readiness.check_readiness(timeout_ms=100)
                self.assertEqual(raised.exception.code, "SCHEMA_NOT_READY")
                self.assertEqual(pool.discarded, [pool.connection])
                self.assertNotIn((b"p" * 32).hex(), repr(raised.exception))

    def test_requirement_is_closed_and_hash_is_redacted(self) -> None:
        with self.assertRaises(ValueError):
            SchemaCompatibilityRequirement(
                component="taxonomy",
                expected_schema_head=1,
                expected_contract_sha256=b"x" * 32,
                required_iam_schema_version=None,
            )
        requirement = SchemaCompatibilityRequirement(
            component="iam",
            expected_schema_head=22,
            expected_contract_sha256=b"s" * 32,
            required_iam_schema_version=None,
        )
        self.assertNotIn((b"s" * 32).hex(), repr(requirement))

    def test_demand_runtime_receipt_key_drift_fails_readiness(self) -> None:
        requirement = SchemaCompatibilityRequirement(
            component="demand",
            expected_schema_head=5,
            expected_contract_sha256=b"d" * 32,
            required_iam_schema_version=25,
            expected_idempotency_key_id="demand-idempotency-2026-01",
            expected_payload_key_id="demand-payload-2026-01",
            expected_retained_idempotency_key_ids=(
                "demand-idempotency-2026-01",
            ),
            expected_retained_payload_key_ids=("demand-payload-2026-01",),
        )
        statement = PostgresSchemaCompatibilityReadiness.statement_for("demand")
        base = (
            "demand",
            5,
            5,
            5,
            5,
            25,
            b"d" * 32,
            "demand-idempotency-2026-01",
            "demand-payload-2026-01",
            ["demand-idempotency-2026-01"],
            ["demand-payload-2026-01"],
        )
        for row in (
            base[:7]
            + ("demand-idempotency-v1",)
            + base[8:],
            base[:8]
            + ("demand-payload-hash-v1",)
            + base[9:],
            base[:9] + (["demand-idempotency-old"],) + base[10:],
            base[:10] + (["demand-payload-old"],),
            base[:9]
            + (["demand-idempotency-2026-01", "demand-idempotency-extra"],)
            + base[10:],
            base[:10]
            + (["demand-payload-2026-01", "demand-payload-extra"],),
        ):
            with self.subTest(row=row):
                pool = Pool({statement: row})
                readiness = PostgresSchemaCompatibilityReadiness(
                    pool=pool,
                    requirement=requirement,
                )
                with self.assertRaises(SchemaCompatibilityError):
                    readiness.check_readiness(timeout_ms=100)
                self.assertEqual(pool.discarded, [pool.connection])

        rotated_requirement = SchemaCompatibilityRequirement(
            component="demand",
            expected_schema_head=5,
            expected_contract_sha256=b"d" * 32,
            required_iam_schema_version=25,
            expected_idempotency_key_id="demand-idempotency-2026-01",
            expected_payload_key_id="demand-payload-2026-01",
            expected_retained_idempotency_key_ids=(
                "demand-idempotency-2026-01",
                "demand-idempotency-old",
            ),
            expected_retained_payload_key_ids=(
                "demand-payload-2026-01",
                "demand-payload-old",
            ),
        )
        for retained_idempotency, retained_payload in (
            (
                ["demand-idempotency-old", "demand-idempotency-2026-01"],
                ["demand-payload-2026-01", "demand-payload-old"],
            ),
            (
                ["demand-idempotency-2026-01", "demand-idempotency-old"],
                ["demand-payload-old", "demand-payload-2026-01"],
            ),
            (
                ["demand-idempotency-2026-01"],
                ["demand-payload-2026-01", "demand-payload-old"],
            ),
        ):
            row = base[:9] + (retained_idempotency, retained_payload)
            with self.subTest(
                retained_idempotency=retained_idempotency,
                retained_payload=retained_payload,
            ):
                pool = Pool({statement: row})
                readiness = PostgresSchemaCompatibilityReadiness(
                    pool=pool,
                    requirement=rotated_requirement,
                )
                with self.assertRaises(SchemaCompatibilityError):
                    readiness.check_readiness(timeout_ms=100)

    def test_trust_dependency_and_combined_contract_drift_fail_readiness(self) -> None:
        requirement = SchemaCompatibilityRequirement(
            component="trust",
            expected_schema_head=1,
            expected_contract_sha256=b"t" * 32,
            required_iam_schema_version=36,
            required_demand_schema_version=8,
            expected_iam_contract_sha256=b"i" * 32,
            expected_demand_contract_sha256=b"d" * 32,
            expected_combined_contract_sha256=b"c" * 32,
        )
        statement = PostgresSchemaCompatibilityReadiness.statement_for("trust")
        base = (
            "trust",
            1,
            1,
            1,
            1,
            36,
            8,
            b"i" * 32,
            b"d" * 32,
            b"c" * 32,
            b"t" * 32,
        )
        for index, drifted in (
            (5, 35),
            (6, 7),
            (7, b"x" * 32),
            (8, b"x" * 32),
            (9, b"x" * 32),
            (10, b"x" * 32),
        ):
            row = base[:index] + (drifted,) + base[index + 1 :]
            with self.subTest(index=index):
                pool = Pool({statement: row})
                readiness = PostgresSchemaCompatibilityReadiness(
                    pool=pool,
                    requirement=requirement,
                )
                with self.assertRaises(SchemaCompatibilityError):
                    readiness.check_readiness(timeout_ms=100)
                self.assertEqual(pool.discarded, [pool.connection])


if __name__ == "__main__":
    unittest.main()
