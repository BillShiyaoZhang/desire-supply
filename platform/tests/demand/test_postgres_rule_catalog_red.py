from __future__ import annotations

from datetime import datetime, timezone
import unittest
from uuid import UUID

from psycopg.pq import TransactionStatus

from desire_platform.demand.adapters.postgres import PsycopgDemandRuleCatalog
from desire_platform.demand.adapters.postgres.migrations import (
    DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
    DEMAND_SCHEMA_HEAD_VERSION,
)
from desire_platform.demand.ports.commands import (
    DemandRuleCatalogUnavailableError,
    DemandRuleRequirement,
)


TAXONOMY_BUNDLE_ID = UUID("50000000-0000-4000-8000-000000000001")
BUDGET_RULE_BUNDLE_ID = UUID("51000000-0000-4000-8000-000000000001")
RISK_RULE_BUNDLE_ID = UUID("52000000-0000-4000-8000-000000000001")
MATCHING_RULE_BUNDLE_ID = UUID("53000000-0000-4000-8000-000000000001")
REASON_CODE_BUNDLE_ID = UUID("54000000-0000-4000-8000-000000000001")
COMPOSITE_RULE_REQUIREMENT_ID = UUID(
    "55000000-0000-4000-8000-000000000001"
)
ORGANIZATION_ID = "60000000-0000-4000-8000-000000000001"
DEMAND_ID = "61000000-0000-4000-8000-000000000001"
REQUIREMENT_SHA256 = bytes.fromhex(
    "98ba1470ec6171ad33a9a8123cd855278241ac607f87ef4226b1f4f4a3bb88e3"
)
EFFECTIVE_AT = datetime(2020, 1, 1, tzinfo=timezone.utc)
EFFECTIVE_UNTIL = datetime(2100, 1, 1, tzinfo=timezone.utc)
SERVER_NOW = datetime(2035, 1, 1, tzinfo=timezone.utc)


class Result:
    def __init__(self, *, row=None) -> None:
        self.row = row

    def fetchone(self):
        return self.row


class Info:
    transaction_status = TransactionStatus.IDLE


_UNSET = object()


class Connection:
    def __init__(self, *, policy_row=_UNSET, preflight_row=None, fail=False) -> None:
        self.autocommit = True
        self.info = Info()
        self.policy_row = valid_policy_row() if policy_row is _UNSET else policy_row
        self.preflight_row = preflight_row or (
            "demand_self",
            "demand_self",
            18,
            DEMAND_SCHEMA_HEAD_VERSION,
            DEMAND_SCHEMA_HEAD_VERSION,
            DEMAND_SCHEMA_HEAD_VERSION,
            DEMAND_SCHEMA_HEAD_VERSION,
            DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
        )
        self.fail = fail
        self.calls = []

    def execute(self, statement, parameters=None):
        self.calls.append((statement, parameters))
        if self.fail and "receipt_key_policy" in statement:
            raise RuntimeError("database details must be suppressed")
        if statement.startswith("BEGIN"):
            self.info.transaction_status = TransactionStatus.INTRANS
            return Result()
        if statement in {"COMMIT", "ROLLBACK"}:
            self.info.transaction_status = TransactionStatus.IDLE
            return Result()
        if "FROM demand.schema_compatibility" in statement:
            return Result(row=self.preflight_row)
        if "FROM demand.receipt_key_policy" in statement:
            return Result(row=self.policy_row)
        if "set_config" in statement:
            return Result(row=(parameters[1],))
        return Result()


class Source:
    def __init__(self, connection: Connection) -> None:
        self.connection = connection
        self.checked_out = []
        self.released = []
        self.discarded = []
        self.closed = False

    def checkout(self):
        self.checked_out.append(self.connection)
        return self.connection

    def release(self, connection):
        self.released.append(connection)

    def discard(self, connection):
        self.discarded.append(connection)

    def close(self):
        self.closed = True


def valid_policy_row():
    return (
        TAXONOMY_BUNDLE_ID,
        BUDGET_RULE_BUNDLE_ID,
        RISK_RULE_BUNDLE_ID,
        MATCHING_RULE_BUNDLE_ID,
        REASON_CODE_BUNDLE_ID,
        COMPOSITE_RULE_REQUIREMENT_ID,
        REQUIREMENT_SHA256,
        EFFECTIVE_AT,
        EFFECTIVE_UNTIL,
        SERVER_NOW,
    )


class PostgresDemandRuleCatalogTests(unittest.TestCase):
    def test_reads_one_current_exact_requirement_in_a_read_only_snapshot(self) -> None:
        connection = Connection()
        source = Source(connection)
        catalog = PsycopgDemandRuleCatalog(connections=source)

        result = catalog.current_requirement(
            organization_id=ORGANIZATION_ID,
            demand_id=DEMAND_ID,
            operation="SUBMIT_DEMAND",
        )

        self.assertIsInstance(result, DemandRuleRequirement)
        self.assertEqual(result.taxonomy_bundle_id, str(TAXONOMY_BUNDLE_ID))
        self.assertEqual(result.budget_rule_bundle_id, str(BUDGET_RULE_BUNDLE_ID))
        self.assertEqual(result.risk_rule_bundle_id, str(RISK_RULE_BUNDLE_ID))
        self.assertEqual(result.matching_rule_bundle_id, str(MATCHING_RULE_BUNDLE_ID))
        self.assertEqual(result.reason_code_bundle_id, str(REASON_CODE_BUNDLE_ID))
        self.assertEqual(
            result.composite_rule_requirement_id,
            str(COMPOSITE_RULE_REQUIREMENT_ID),
        )
        self.assertEqual(result.requirement_sha256, REQUIREMENT_SHA256.hex())
        self.assertEqual(result.effective_at, EFFECTIVE_AT)
        self.assertEqual(result.effective_until, EFFECTIVE_UNTIL)
        self.assertEqual(source.released, [connection])
        self.assertEqual(source.discarded, [])
        statements = tuple(call[0] for call in connection.calls)
        self.assertIn(
            "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY",
            statements,
        )
        policy_sql = next(
            statement for statement in statements if "receipt_key_policy" in statement
        )
        self.assertIn("transaction_timestamp()", policy_sql)
        self.assertNotIn("SELECT *", policy_sql.upper())
        self.assertFalse(
            any(
                token in statement.upper()
                for statement in statements
                for token in ("INSERT ", "UPDATE ", "DELETE ", "ALTER ", "CREATE ")
            )
        )

    def test_input_and_database_projection_drift_fail_closed(self) -> None:
        invalid_rows = (
            (None,),
            (valid_policy_row()[:-4] + (b"short",) + valid_policy_row()[-3:],),
            (
                (
                    TAXONOMY_BUNDLE_ID,
                    TAXONOMY_BUNDLE_ID,
                    *valid_policy_row()[2:],
                ),
            ),
            (
                valid_policy_row()[:7]
                + (EFFECTIVE_AT.replace(tzinfo=None),)
                + valid_policy_row()[8:],
            ),
            (
                valid_policy_row()[:8]
                + (datetime(2030, 1, 1, tzinfo=timezone.utc), SERVER_NOW),
            ),
        )
        for (row,) in invalid_rows:
            with self.subTest(row=row):
                connection = Connection(policy_row=row)
                source = Source(connection)
                catalog = PsycopgDemandRuleCatalog(connections=source)
                with self.assertRaises(DemandRuleCatalogUnavailableError):
                    catalog.current_requirement(
                        organization_id=ORGANIZATION_ID,
                        demand_id=DEMAND_ID,
                        operation="VERIFY_DEMAND",
                    )
                self.assertEqual(source.released, [])
                self.assertEqual(source.discarded, [connection])

        for organization_id, demand_id, operation in (
            ("not-a-uuid", DEMAND_ID, "SUBMIT_DEMAND"),
            (ORGANIZATION_ID, "not-a-uuid", "SUBMIT_DEMAND"),
            (ORGANIZATION_ID, DEMAND_ID, "CREATE_DEMAND"),
        ):
            with self.subTest(operation=operation):
                source = Source(Connection())
                catalog = PsycopgDemandRuleCatalog(connections=source)
                with self.assertRaises(DemandRuleCatalogUnavailableError):
                    catalog.current_requirement(
                        organization_id=organization_id,
                        demand_id=demand_id,
                        operation=operation,
                    )
                self.assertEqual(source.checked_out, [])

    def test_wrong_role_and_database_errors_are_secret_safe_and_discarded(self) -> None:
        for connection in (
            Connection(
                preflight_row=(
                    "demand_review",
                    "demand_review",
                    18,
                    2,
                    2,
                    2,
                    2,
                    21,
                )
            ),
            Connection(fail=True),
        ):
            source = Source(connection)
            catalog = PsycopgDemandRuleCatalog(connections=source)
            with self.assertRaises(DemandRuleCatalogUnavailableError) as raised:
                catalog.current_requirement(
                    organization_id=ORGANIZATION_ID,
                    demand_id=DEMAND_ID,
                    operation="REQUEST_MATCHING",
                )
            self.assertEqual(str(raised.exception), "Demand rule catalog unavailable")
            self.assertNotIn("database details", repr(raised.exception))
            self.assertEqual(source.discarded, [connection])

    def test_managed_readiness_is_bounded_and_close_does_not_close_borrowed_pool(self) -> None:
        source = Source(Connection())
        catalog = PsycopgDemandRuleCatalog(connections=source)

        self.assertIsNone(catalog.check_readiness(timeout_ms=250))
        self.assertEqual(len(source.released), 1)
        catalog.close()
        catalog.close()
        self.assertFalse(source.closed)
        with self.assertRaises(DemandRuleCatalogUnavailableError):
            catalog.check_readiness(timeout_ms=250)
        with self.assertRaises(ValueError):
            PsycopgDemandRuleCatalog(connections=Source(Connection())).check_readiness(
                timeout_ms=0
            )
        self.assertNotIn(REQUIREMENT_SHA256.hex(), repr(catalog))


if __name__ == "__main__":
    unittest.main()
