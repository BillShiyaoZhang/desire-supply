"""PostgreSQL 18 semantics for the command-shape-independent Trust base."""

from __future__ import annotations

from pathlib import Path
import unittest
from uuid import UUID

import psycopg

from tests.storage.postgres.postgres18_harness import TemporaryPostgres18


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
TRUST_MIGRATION = (
    PLATFORM_ROOT
    / "src/desire_platform/trust_safety/adapters/postgres/migrations"
    / "0001_expand__demand_safety_case_v1.sql"
)

BUSINESS_TABLES = (
    "reports",
    "cases",
    "case_assignments",
    "restricted_text_blobs",
    "case_assignment_releases",
    "triage_drafts",
    "triage_versions",
    "safety_holds",
    "case_outcome_versions",
    "receipt_key_policy",
    "sealed_text_key_policy",
    "command_receipts",
)


class TrustPostgresBaseTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()
        cls.database = cls.postgres.create_database()
        with psycopg.connect(
            cls.postgres.admin_conninfo(database="postgres"),
            autocommit=True,
        ) as connection:
            connection.execute(
                f'GRANT CREATE ON DATABASE "{cls.database}" '
                "TO trust_schema_owner"
            )
            connection.execute(
                "GRANT trust_schema_owner TO trust_migration_runner "
                "WITH INHERIT FALSE, SET TRUE"
            )
            connection.execute(
                "GRANT schema_owner TO trust_migration_runner "
                "WITH INHERIT FALSE, SET TRUE"
            )
        with cls._admin() as connection:
            connection.execute("SET ROLE schema_owner")
            connection.execute("CREATE SCHEMA audit AUTHORIZATION schema_owner")
            connection.execute("CREATE SCHEMA infra AUTHORIZATION schema_owner")
            connection.execute(
                "CREATE TABLE audit.audit_events ("
                "event_id uuid PRIMARY KEY,occurred_at timestamptz NOT NULL,"
                "actor_kind text NOT NULL,actor_id uuid NOT NULL,"
                "original_actor_id uuid NULL,action_code varchar(96) NOT NULL,"
                "target_kind varchar(64) NOT NULL,target_id uuid NOT NULL,"
                "organization_id uuid NULL,before_status varchar(64) NULL,"
                "after_status varchar(64) NULL,before_version bigint NULL,"
                "after_version bigint NULL,role_code varchar(128) NULL,"
                "purpose_code varchar(128) NULL,reason_code varchar(128) NULL,"
                "auth_strength_code varchar(128) NULL,result_code varchar(64) NOT NULL,"
                "command_id uuid NOT NULL,correlation_id uuid NOT NULL,"
                "causation_id uuid NOT NULL,trace_id uuid NOT NULL,"
                "safe_attributes jsonb NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE infra.outbox_events ("
                "event_id uuid PRIMARY KEY,event_type varchar(96) NOT NULL,"
                "schema_version integer NOT NULL,occurred_at timestamptz NOT NULL,"
                "aggregate_type varchar(64) NOT NULL,aggregate_id uuid NOT NULL,"
                "aggregate_version bigint NOT NULL,actor_kind text NOT NULL,"
                "actor_id uuid NOT NULL,original_actor_id uuid NULL,"
                "correlation_id uuid NOT NULL,causation_id uuid NOT NULL,"
                "trace_id uuid NOT NULL,organization_id uuid NULL,"
                "payload jsonb NOT NULL,delivery_status text NOT NULL,"
                "attempt_count integer NOT NULL,available_at timestamptz NOT NULL,"
                "lease_owner varchar(128) NULL,lease_until timestamptz NULL,"
                "published_at timestamptz NULL,last_error_code varchar(64) NULL,"
                "created_at timestamptz NOT NULL)"
            )
            connection.execute(
                "ALTER TABLE audit.audit_events ENABLE ROW LEVEL SECURITY"
            )
            connection.execute(
                "ALTER TABLE audit.audit_events FORCE ROW LEVEL SECURITY"
            )
            connection.execute(
                "ALTER TABLE infra.outbox_events ENABLE ROW LEVEL SECURITY"
            )
            connection.execute(
                "ALTER TABLE infra.outbox_events FORCE ROW LEVEL SECURITY"
            )
        with psycopg.connect(
            cls.postgres.conninfo(
                database=cls.database,
                user="trust_migration_runner",
            ),
            autocommit=False,
        ) as connection:
            connection.execute("SET ROLE trust_schema_owner")
            connection.execute(TRUST_MIGRATION.read_text(encoding="utf-8"))
            connection.commit()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.postgres.stop()

    @classmethod
    def _admin(cls):
        return psycopg.connect(
            cls.postgres.admin_conninfo(database=cls.database),
            autocommit=True,
        )

    def test_all_business_tables_force_rls_and_runtime_has_no_table_privilege(self) -> None:
        with self._admin() as connection:
            rows = connection.execute(
                "SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity "
                "FROM pg_catalog.pg_class AS c "
                "JOIN pg_catalog.pg_namespace AS n ON n.oid=c.relnamespace "
                "WHERE n.nspname='trust' AND c.relname=ANY(%s) "
                "ORDER BY c.relname",
                (list(BUSINESS_TABLES),),
            ).fetchall()
            self.assertEqual(
                rows,
                [(name, True, True) for name in sorted(BUSINESS_TABLES)],
            )
            privileges = connection.execute(
                "SELECT role_name,table_name,"
                "pg_catalog.has_table_privilege(role_name,'trust.'||table_name,"
                "'SELECT,INSERT,UPDATE,DELETE') "
                "FROM unnest(%s::text[]) AS role_name "
                "CROSS JOIN unnest(%s::text[]) AS table_name",
                (
                    ["trust_self", "trust_officer", "trust_appeal", "trust_decision"],
                    list(BUSINESS_TABLES),
                ),
            ).fetchall()
            self.assertTrue(privileges)
            self.assertTrue(all(row[2] is False for row in privileges))

    def test_online_role_cannot_read_internal_schema(self) -> None:
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="trust_self"),
            autocommit=True,
        ) as connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute("SELECT count(*) FROM trust.reports")

    def test_runtime_reads_exact_key_policy_only_through_fixed_projection(self) -> None:
        expected = (
            "trust-idempotency-2026-01",
            ["trust-idempotency-2026-01"],
            "trust-payload-2026-01",
            ["trust-payload-2026-01"],
            "trust-command-json-v1",
            ["trust-command-json-v1"],
            "trust-sealed-note-v1",
            ["trust-sealed-note-v1"],
        )
        for role in (
            "trust_self",
            "trust_officer",
            "trust_appeal",
            "trust_decision",
        ):
            with psycopg.connect(
                self.postgres.conninfo(database=self.database, user=role),
                autocommit=True,
            ) as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT * FROM trust_api.read_runtime_key_policy_v1()"
                    ).fetchone(),
                    expected,
                )
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    connection.execute(
                        "SELECT * FROM trust.receipt_key_policy"
                    )

    def test_receipt_key_policy_is_exactly_one_and_not_deletable(self) -> None:
        with self._admin() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT count(*) FROM trust.receipt_key_policy"
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT active_encryption_key_id,"
                    "retained_encryption_key_ids "
                    "FROM trust.sealed_text_key_policy"
                ).fetchone(),
                ("trust-sealed-note-v1", ["trust-sealed-note-v1"]),
            )
            with self.assertRaises(psycopg.errors.CheckViolation):
                connection.execute("DELETE FROM trust.sealed_text_key_policy")
            self.assertEqual(
                connection.execute(
                    "SELECT active_idempotency_key_id,"
                    "active_payload_key_id,retained_idempotency_key_ids,"
                    "retained_payload_key_ids "
                    "FROM trust.receipt_key_policy"
                ).fetchone(),
                (
                    "trust-idempotency-2026-01",
                    "trust-payload-2026-01",
                    ["trust-idempotency-2026-01"],
                    ["trust-payload-2026-01"],
                ),
            )
            with self.assertRaises(psycopg.errors.CheckViolation):
                connection.execute("DELETE FROM trust.receipt_key_policy")
            self.assertEqual(
                connection.execute(
                    "SELECT count(*) FROM trust.receipt_key_policy"
                ).fetchone()[0],
                1,
            )

    def test_completed_receipt_and_outcome_are_immutable(self) -> None:
        with self._admin() as connection:
            connection.execute(
                "INSERT INTO trust.command_receipts ("
                "receipt_id,principal_kind,principal_id,organization_id,"
                "command_domain,command_name,command_version,"
                "idempotency_key_digest_key_id,idempotency_key_digest,"
                "payload_hash_key_id,canonicalization_version,payload_hash,"
                "http_method,canonical_path,if_match_version,status,"
                "retain_until,created_at) VALUES ("
                "'71000000-0000-4000-8000-000000000001','USER',"
                "'71000000-0000-4000-8000-000000000002',"
                "'71000000-0000-4000-8000-000000000003',"
                "'TRUST_SAFETY','TEST_COMMAND',1,"
                "'trust-idempotency-2026-01',decode(repeat('11',32),'hex'),"
                "'trust-payload-2026-01','trust-command-json-v1',"
                "decode(repeat('22',32),'hex'),'POST','/v1/app/trust/test',NULL,"
                "'IN_PROGRESS',transaction_timestamp()+interval '30 days',"
                "transaction_timestamp())"
            )
            connection.execute(
                "UPDATE trust.command_receipts SET status='COMPLETED',"
                "response_http_status=200,response_schema_name='TrustResult',"
                "response_schema_version=1,response_entity_tag='trust-1-abc',"
                "safe_response=jsonb_build_object("
                "'aggregate_version',1,'assignment_id',NULL,'case_id',"
                "'71000000-0000-4000-8000-000000000004'::uuid,"
                "'case_status','OPEN','completed_at',"
                "trust.utc_timestamp_text_v1(transaction_timestamp()),"
                "'event_types',jsonb_build_array('TrustReportSubmitted'),"
                "'hold_id',NULL,'hold_version',NULL,'outcome_version_id',NULL,"
                "'report_id',NULL,'triage_draft_version',NULL,"
                "'triage_version',NULL),"
                "target_case_id='71000000-0000-4000-8000-000000000004',"
                "target_version=1,result_status='OPEN',"
                "event_types=ARRAY['TrustReportSubmitted']::text[],"
                "completed_at=transaction_timestamp() WHERE receipt_id="
                "'71000000-0000-4000-8000-000000000001'"
            )
            with self.assertRaises(psycopg.errors.CheckViolation):
                connection.execute(
                    "UPDATE trust.command_receipts SET result_status='DECIDED' "
                    "WHERE receipt_id='71000000-0000-4000-8000-000000000001'"
                )

            connection.execute("SET session_replication_role=replica")
            connection.execute(
                "INSERT INTO trust.case_outcome_versions ("
                "outcome_version_id,organization_id,case_id,outcome_version,"
                "outcome_code,reason_codes,action_codes,evidence_packet_version_id,"
                "evidence_packet_digest,source_digest,redaction_profile_code,"
                "appeal_eligible,appeal_eligibility_code,appeal_deadline,"
                "policy_version,decided_by_user_id,decision_assignment_id,"
                "decided_at,content_sha256) VALUES ("
                "'72000000-0000-4000-8000-000000000001',"
                "'72000000-0000-4000-8000-000000000002',"
                "'72000000-0000-4000-8000-000000000003',1,'NO_ACTION',"
                "ARRAY['NO_POLICY_BREACH']::text[],ARRAY[]::text[],"
                "'72000000-0000-4000-8000-000000000004',"
                "decode(repeat('33',32),'hex'),decode(repeat('44',32),'hex'),"
                "'PARTY_SAFE_V1',false,'NOT_ELIGIBLE',NULL,"
                "'trust-case-outcome-v1',"
                "'72000000-0000-4000-8000-000000000005',"
                "'72000000-0000-4000-8000-000000000006',"
                "transaction_timestamp(),decode(repeat('55',32),'hex'))"
            )
            connection.execute("SET session_replication_role=origin")
            with self.assertRaises(psycopg.errors.CheckViolation):
                connection.execute(
                    "UPDATE trust.case_outcome_versions SET outcome_code='DISMISSED' "
                    "WHERE outcome_version_id="
                    "'72000000-0000-4000-8000-000000000001'"
                )

    def test_hold_evaluation_binds_exact_target_content_action_and_policy(self) -> None:
        with self._admin() as connection:
            connection.execute("SET session_replication_role=replica")
            connection.execute(
                "INSERT INTO trust.safety_holds ("
                "hold_id,organization_id,case_id,demand_id,demand_version_id,"
                "triage_version,action_codes,reason_code,status,policy_version,"
                "issued_by_user_id,issue_assignment_id,effective_at,expires_at,"
                "aggregate_version,requires_independent_release,"
                "release_assignment_id,released_at,released_by_user_id,"
                "release_reason_code) VALUES ("
                "'73000000-0000-4000-8000-000000000001',"
                "'73000000-0000-4000-8000-000000000002',"
                "'73000000-0000-4000-8000-000000000003',"
                "'73000000-0000-4000-8000-000000000004',"
                "'73000000-0000-4000-8000-000000000005',1,"
                "ARRAY['SUBMIT_DEMAND']::text[],'WORKFLOW_INTEGRITY_RISK',"
                "'ACTIVE','trust-demand-hold-v1',"
                "'73000000-0000-4000-8000-000000000006',"
                "'73000000-0000-4000-8000-000000000007',"
                "transaction_timestamp()-interval '1 minute',"
                "transaction_timestamp()+interval '30 minutes',1,false,"
                "NULL,NULL,NULL,NULL)"
            )
            connection.execute("SET session_replication_role=origin")

        arguments = (
            "73000000-0000-4000-8000-000000000008",
            "73000000-0000-4000-8000-000000000002",
            "73000000-0000-4000-8000-000000000004",
            19,
            "73000000-0000-4000-8000-000000000005",
            bytes.fromhex("66" * 32),
            "SUBMIT_DEMAND",
            "demand-safety-hold-v1",
        )
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="trust_decision"),
            autocommit=True,
        ) as connection:
            blocked = connection.execute(
                "SELECT * FROM trust_api.evaluate_demand_hold_v1("
                "%s,%s,%s,%s,%s,%s,%s,%s)",
                arguments,
            ).fetchone()
            self.assertEqual(
                blocked[:8],
                (
                    UUID(arguments[0]),
                    UUID(arguments[1]),
                    UUID(arguments[2]),
                    arguments[3],
                    UUID(arguments[4]),
                    arguments[5],
                    arguments[6],
                    arguments[7],
                ),
            )
            self.assertEqual(blocked[8], "BLOCK")
            self.assertEqual(len(blocked[9]), 32)
            self.assertGreater(blocked[11], blocked[10])

            allowed = connection.execute(
                "SELECT * FROM trust_api.evaluate_demand_hold_v1("
                "%s,%s,%s,%s,%s,%s,%s,%s)",
                arguments[:6] + ("VERIFY_DEMAND", arguments[7]),
            ).fetchone()
            self.assertEqual(allowed[8], "ALLOW")
            self.assertEqual(len(allowed[9]), 32)
            self.assertGreater(allowed[11], allowed[10])

        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="demand_self"),
            autocommit=True,
        ) as connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    "SELECT * FROM trust_api.evaluate_demand_hold_v1("
                    "%s,%s,%s,%s,%s,%s,%s,%s)",
                    arguments,
                )


if __name__ == "__main__":
    unittest.main()
