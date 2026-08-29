"""Real PostgreSQL 18 gates for Demand15 Matching workflow programs."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import unittest
from uuid import UUID, uuid4

import psycopg

from desire_platform.demand.adapters.postgres.migrations import (
    DemandContractSources,
    DemandMigrationCatalog,
    DemandMigrationRunner,
    DemandMigrationSettings,
    PsycopgDemandMigrationDriver,
)
from desire_platform.identity_access.adapters.postgres.migrations import (
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
IAM_MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
DEMAND_MIGRATION_ROOT = (
    PLATFORM_ROOT / "src/desire_platform/demand/adapters/postgres/migrations"
)
class Demand15MatchingRuntimePostgres18Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()
        cls.database = cls.postgres.create_database()

        IamMigrationRunner(
            driver=PsycopgMigrationDriver(
                settings=PsycopgMigrationSettings(
                    conninfo=cls.postgres.conninfo(
                        database=cls.database,
                        user="iam_migration_runner",
                    ),
                    application_name="desire-demand15-iam-pg18",
                ),
                dbapi=psycopg,
            ),
            runner_version="demand15-iam-pg18/1",
        ).run(
            catalog=MigrationCatalog.load(IAM_MIGRATION_ROOT),
            contract_sources=IamContractSources(
                api_contract_bytes=(
                    PLATFORM_ROOT / "contracts/api/iam-v1.openapi.yaml"
                ).read_bytes(),
                event_contract_bytes=(
                    PLATFORM_ROOT / "contracts/events/iam-v1.schema.json"
                ).read_bytes(),
            ),
        )

        DemandMigrationRunner(
            driver=PsycopgDemandMigrationDriver(
                settings=DemandMigrationSettings(
                    conninfo=cls.postgres.conninfo(
                        database=cls.database,
                        user="demand_migration_runner",
                    ),
                    application_name="desire-demand15-base-pg18",
                ),
                dbapi=psycopg,
            ),
            runner_version="demand15-base-pg18/1",
        ).run(
            catalog=DemandMigrationCatalog.load(DEMAND_MIGRATION_ROOT),
            contract_sources=DemandContractSources(
                api_contract_bytes=(
                    PLATFORM_ROOT / "contracts/api/demand-v1.openapi.yaml"
                ).read_bytes(),
                event_contract_bytes=(
                    PLATFORM_ROOT / "contracts/events/demand-v1.schema.json"
                ).read_bytes(),
                content_contract_bytes=(
                    PLATFORM_ROOT
                    / "contracts/domain/demand-content-v1.schema.json"
                ).read_bytes(),
            ),
        )

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            if hasattr(cls, "database"):
                cls.postgres.drop_database(cls.database)
        finally:
            cls.postgres.stop()

    def test_migration_installs_only_fixed_role_bound_programs(self) -> None:
        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=True,
        ) as connection:
            row = connection.execute(
                "SELECT "
                "to_regprocedure('demand_api.claim_matching_requested_delivery_v1(uuid,bytea,text,bytea,integer)') IS NOT NULL,"
                "to_regprocedure('demand_api.execute_complete_selection_system_v1(uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,bigint,uuid,uuid,bigint,uuid,uuid,uuid,bytea,character varying,bytea,uuid,uuid,uuid)') IS NOT NULL,"
                "to_regprocedure('demand_api.execute_close_matching_without_selection_system_v1(uuid,uuid,uuid,uuid,uuid,uuid,uuid,bigint,uuid,uuid,bigint,uuid,uuid,uuid,bytea,text,bytea,uuid,uuid,uuid,text)') IS NOT NULL,"
                "has_table_privilege('demand_matching','demand.matching_requested_deliveries','SELECT'),"
                "has_function_privilege('demand_matching','demand_api.claim_matching_requested_delivery_v1(uuid,bytea,text,bytea,integer)','EXECUTE'),"
                "has_function_privilege('matching_coordinator','demand_api.execute_complete_selection_system_v1(uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,bigint,uuid,uuid,bigint,uuid,uuid,uuid,bytea,character varying,bytea,uuid,uuid,uuid)','EXECUTE')"
            ).fetchone()
        self.assertEqual(row, (True, True, True, False, True, False))

    def test_delivery_true_envelope_replay_fencing_and_cross_workload_denial(
        self,
    ) -> None:
        facts = self._seed_matching_demand()
        marker = facts["authorization_digest"]
        lease_digest = bytes.fromhex("91" * 32)
        gucs = self._delivery_gucs(facts["workload_id"], marker, "CLAIM")

        claimed = self._invoke(
            role="demand_matching",
            gucs=gucs,
            statement=(
                "SELECT * FROM demand_api.claim_matching_requested_delivery_v1("
                "%s,%s,%s,%s,%s)"
            ),
            parameters=(
                facts["workload_id"],
                marker,
                "demand-matching-delivery-lease-v1",
                lease_digest,
                60,
            ),
        )
        self.assertIsNotNone(claimed)
        assert claimed is not None
        self.assertEqual(claimed[4:9], (
            "MatchingRequested",
            1,
            "Demand",
            facts["demand_id"],
            6,
        ))
        self.assertEqual(claimed[9:13], (
            facts["original_actor_user_id"],
            facts["organization_id"],
            facts["demand_id"],
            facts["demand_version_id"],
        ))
        self.assertEqual(claimed[15:18], (
            6,
            facts["matching_request_id"],
            1,
        ))
        self.assertEqual(claimed[25], False)

        replay = self._invoke(
            role="demand_matching",
            gucs=gucs,
            statement=(
                "SELECT * FROM demand_api.claim_matching_requested_delivery_v1("
                "%s,%s,%s,%s,%s)"
            ),
            parameters=(
                facts["workload_id"], marker,
                "demand-matching-delivery-lease-v1", lease_digest, 60,
            ),
        )
        self.assertEqual(replay[:-1], claimed[:-1])
        self.assertEqual(replay[-1], True)

        retry_at = datetime.now(timezone.utc) + timedelta(seconds=30)
        failed = self._invoke(
            role="demand_matching",
            gucs=self._delivery_gucs(
                facts["workload_id"], marker, "FAIL"
            ),
            statement=(
                "SELECT * FROM demand_api.fail_matching_requested_delivery_v1("
                "%s,%s,%s,%s,%s,%s,%s)"
            ),
            parameters=(
                claimed[0], claimed[1], claimed[2],
                "demand-matching-delivery-lease-v1", lease_digest,
                "TRANSIENT_FAILURE", retry_at,
            ),
        )
        self.assertEqual(failed, ("AVAILABLE", 1, retry_at, False))

        other_workload = uuid4()
        with self.assertRaises(psycopg.Error) as denied:
            self._invoke(
                role="demand_matching",
                gucs=self._delivery_gucs(
                    other_workload, bytes.fromhex("92" * 32), "FAIL"
                ),
                statement=(
                    "SELECT * FROM demand_api."
                    "fail_matching_requested_delivery_v1("
                    "%s,%s,%s,%s,%s,%s,%s)"
                ),
                parameters=(
                    claimed[0], claimed[1], claimed[2],
                    "demand-matching-delivery-lease-v1", lease_digest,
                    "TRANSIENT_FAILURE", retry_at,
                ),
            )
        self.assertEqual(
            denied.exception.diag.message_primary,
            "DEMAND_MATCH_DELIVERY_ACCESS_DENIED",
        )

        exact_replay = self._invoke(
            role="demand_matching",
            gucs=self._delivery_gucs(facts["workload_id"], marker, "FAIL"),
            statement=(
                "SELECT * FROM demand_api.fail_matching_requested_delivery_v1("
                "%s,%s,%s,%s,%s,%s,%s)"
            ),
            parameters=(
                claimed[0], claimed[1], claimed[2],
                "demand-matching-delivery-lease-v1", lease_digest,
                "TRANSIENT_FAILURE", retry_at,
            ),
        )
        self.assertEqual(exact_replay, ("AVAILABLE", 1, retry_at, True))

    def test_delivery_preserves_direct_user_as_original_actor(self) -> None:
        facts = self._seed_matching_demand(actor_kind="USER")
        claimed = self._invoke(
            role="demand_matching",
            gucs=self._delivery_gucs(
                facts["workload_id"],
                facts["authorization_digest"],
                "CLAIM",
            ),
            statement=(
                "SELECT * FROM demand_api.claim_matching_requested_delivery_v1("
                "%s,%s,%s,%s,%s)"
            ),
            parameters=(
                facts["workload_id"],
                facts["authorization_digest"],
                "demand-matching-delivery-lease-v1",
                bytes.fromhex("93" * 32),
                60,
            ),
        )

        self.assertIsNotNone(claimed)
        assert claimed is not None
        self.assertEqual(claimed[9], facts["original_actor_user_id"])

    def test_completion_program_is_not_directly_callable_by_coordinator(self) -> None:
        facts = self._seed_matching_demand()
        command_id = uuid4()
        choose_receipt_id = uuid4()
        selection_id = uuid4()
        attempt_id = uuid4()
        invitation_id = uuid4()
        run_id = uuid4()
        actor_id = uuid4()
        coordinator_id = uuid4()
        coordinator_marker = bytes.fromhex("a3" * 32)
        payload_hash = bytes.fromhex("a4" * 32)
        event_id = uuid4()
        correlation_id = uuid4()
        trace_id = uuid4()
        parameters = (
            command_id, choose_receipt_id, selection_id, attempt_id,
            invitation_id, run_id, facts["organization_id"],
            facts["demand_id"], 6, facts["demand_version_id"],
            facts["matching_request_id"], 1, facts["funding_id"], actor_id,
            coordinator_id, coordinator_marker, "matching-payload-v1",
            payload_hash, event_id, correlation_id, trace_id,
        )
        statement = (
            "SELECT * FROM demand_api.execute_complete_selection_system_v1("
            + ",".join(["%s"] * 21)
            + ")"
        )
        gucs = self._coordinator_gucs(
            facts, command_id, actor_id, coordinator_id, coordinator_marker
        )
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self._invoke(
                role="matching_coordinator",
                gucs=gucs,
                statement=statement,
                parameters=parameters,
            )
        with self.assertRaises(psycopg.Error):
            self._invoke(
                role="demand_matching",
                gucs=gucs,
                statement=statement,
                parameters=parameters,
            )

        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=True,
        ) as connection:
            state = connection.execute(
                "SELECT root.status,root.aggregate_version,"
                "request.status,request.aggregate_version,"
                "(SELECT count(*) FROM audit.audit_events WHERE event_id=%s),"
                "(SELECT count(*) FROM infra.outbox_events WHERE event_id=%s) "
                "FROM demand.demands root JOIN demand.matching_requests request "
                "ON request.id=%s WHERE root.id=%s",
                (
                    event_id,
                    event_id,
                    facts["matching_request_id"],
                    facts["demand_id"],
                ),
            ).fetchone()
        self.assertEqual(state, ("MATCHING", 6, "OPEN", 1, 0, 0))

    def test_delivery_complete_is_exact_and_replay_safe(self) -> None:
        facts = self._seed_matching_demand()
        marker = facts["authorization_digest"]
        lease_digest = bytes.fromhex("c1" * 32)
        claimed = self._invoke(
            role="demand_matching",
            gucs=self._delivery_gucs(facts["workload_id"], marker, "CLAIM"),
            statement=(
                "SELECT * FROM demand_api.claim_matching_requested_delivery_v1("
                "%s,%s,%s,%s,%s)"
            ),
            parameters=(
                facts["workload_id"], marker,
                "demand-matching-delivery-lease-v1", lease_digest, 60,
            ),
        )
        assert claimed is not None
        matching_attempt_id = uuid4()
        parameters = (
            claimed[0], claimed[1], claimed[2],
            "demand-matching-delivery-lease-v1", lease_digest,
            matching_attempt_id,
        )
        gucs = self._delivery_gucs(
            facts["workload_id"], marker, "COMPLETE"
        )
        first = self._invoke(
            role="demand_matching",
            gucs=gucs,
            statement=(
                "SELECT * FROM demand_api."
                "complete_matching_requested_delivery_v1("
                "%s,%s,%s,%s,%s,%s)"
            ),
            parameters=parameters,
        )
        self.assertEqual(first, ("COMPLETED", 1, None, False))
        replay = self._invoke(
            role="demand_matching",
            gucs=gucs,
            statement=(
                "SELECT * FROM demand_api."
                "complete_matching_requested_delivery_v1("
                "%s,%s,%s,%s,%s,%s)"
            ),
            parameters=parameters,
        )
        self.assertEqual(replay, ("COMPLETED", 1, None, True))

    def test_close_program_is_not_directly_callable_by_coordinator(
        self,
    ) -> None:
        facts = self._seed_matching_demand()
        command_id = uuid4()
        close_receipt_id = uuid4()
        actor_id = uuid4()
        coordinator_id = uuid4()
        coordinator_marker = bytes.fromhex("b3" * 32)
        event_id = uuid4()
        correlation_id = uuid4()
        trace_id = uuid4()
        parameters = (
            command_id, close_receipt_id, uuid4(), uuid4(), uuid4(),
            facts["organization_id"], facts["demand_id"], 6,
            facts["demand_version_id"], facts["matching_request_id"], 1,
            facts["funding_id"], actor_id, coordinator_id,
            coordinator_marker, "matching-payload-v1", bytes.fromhex("b4" * 32),
            event_id, correlation_id, trace_id, "NO_ELIGIBLE_CANDIDATES",
        )
        statement = (
            "SELECT * FROM demand_api."
            "execute_close_matching_without_selection_system_v1("
            + ",".join(["%s"] * 21)
            + ")"
        )
        gucs = self._coordinator_gucs(
            facts, command_id, actor_id, coordinator_id, coordinator_marker
        )
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self._invoke(
                role="matching_coordinator",
                gucs=gucs,
                statement=statement,
                parameters=parameters,
            )
        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=True,
        ) as connection:
            state = connection.execute(
                "SELECT status,aggregate_version,current_matching_request_id "
                "FROM demand.demands WHERE id=%s",
                (facts["demand_id"],),
            ).fetchone()
            event = connection.execute(
                "SELECT event_type,payload FROM infra.outbox_events "
                "WHERE event_id=%s",
                (event_id,),
            ).fetchone()
        self.assertEqual(state, ("MATCHING", 6, facts["matching_request_id"]))
        self.assertIsNone(event)

    def _seed_matching_demand(
        self,
        *,
        actor_kind: str = "SYSTEM",
    ) -> dict[str, object]:
        if actor_kind not in {"USER", "SYSTEM"}:
            raise ValueError("test actor kind is invalid")
        now = datetime.now(timezone.utc)
        facts: dict[str, object] = {
            "organization_id": uuid4(),
            "demand_id": uuid4(),
            "creator_id": uuid4(),
            "demand_version_id": uuid4(),
            "submission_id": uuid4(),
            "assignment_id": uuid4(),
            "review_id": uuid4(),
            "funding_marker_id": uuid4(),
            "funding_id": uuid4(),
            "matching_request_id": uuid4(),
            "matching_event_id": uuid4(),
            "original_actor_user_id": uuid4(),
            "workload_id": uuid4(),
            "authorization_digest": bytes.fromhex("73" * 32),
        }
        digest = bytes.fromhex("71" * 32)
        rule_hash = bytes.fromhex("72" * 32)
        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=False,
        ) as connection:
            connection.execute("SET CONSTRAINTS ALL DEFERRED")
            connection.execute(
                "INSERT INTO demand.demands (id,organization_id,creator_user_id,"
                "client_reference_digest_key_id,client_reference_digest,status,"
                "aggregate_version,current_version_id,current_submission_id,"
                "current_review_id,verified_version_id,current_funding_marker_id,"
                "current_matching_request_id,expires_at,terminal_at,"
                "terminal_reason_code,created_at,updated_at) VALUES ("
                "%s,%s,%s,'test-key',%s,'DRAFT',1,%s,NULL,NULL,NULL,NULL,NULL,"
                "%s,NULL,NULL,%s,%s)",
                (
                    facts["demand_id"], facts["organization_id"],
                    facts["creator_id"], digest, facts["demand_version_id"],
                    now + timedelta(days=30), now, now,
                ),
            )
            connection.execute(
                "INSERT INTO demand.demand_versions (id,organization_id,demand_id,"
                "version_no,based_on_demand_version_id,demand_schema_version,"
                "canonicalization_version,taxonomy_bundle_id,canonical_version_bytes,"
                "content,content_sha256,created_by_user_id,created_at) VALUES ("
                "%s,%s,%s,1,NULL,1,'demand-content-json-v1',%s,%s,%s::jsonb,%s,%s,%s)",
                (
                    facts["demand_version_id"], facts["organization_id"],
                    facts["demand_id"], uuid4(), b"{}", "{}", digest,
                    facts["creator_id"], now,
                ),
            )
            connection.execute(
                "INSERT INTO demand.demand_submissions (id,organization_id,demand_id,"
                "demand_version_id,content_sha256,submitted_by_user_id,"
                "content_policy_version,content_policy_result_sha256,"
                "rule_requirement_sha256,submitted_at) VALUES ("
                "%s,%s,%s,%s,%s,%s,'policy-v1',%s,%s,%s)",
                (
                    facts["submission_id"], facts["organization_id"],
                    facts["demand_id"], facts["demand_version_id"], digest,
                    facts["creator_id"], digest, rule_hash, now,
                ),
            )
            connection.execute(
                "INSERT INTO demand.demand_review_assignments (id,organization_id,"
                "demand_id,submission_id,demand_version_id,reviewer_user_id,"
                "duty_grant_id,duty_grant_version,purpose_code,"
                "conflict_attestation_sha256,authority_marker_sha256,status,"
                "expires_at,aggregate_version,created_at,completed_at) VALUES ("
                "%s,%s,%s,%s,%s,%s,%s,1,'DEMAND_REVIEW',%s,%s,'COMPLETED',"
                "%s,2,%s,%s)",
                (
                    facts["assignment_id"], facts["organization_id"],
                    facts["demand_id"], facts["submission_id"],
                    facts["demand_version_id"], uuid4(), uuid4(), digest, digest,
                    now + timedelta(days=1), now, now,
                ),
            )
            connection.execute(
                "INSERT INTO demand.demand_reviews (id,organization_id,demand_id,"
                "submission_id,demand_version_id,content_sha256,assignment_id,"
                "reviewer_user_id,decision,reason_codes,required_field_codes,"
                "budget_health_code,risk_code,evidence_summary_sha256,"
                "rule_requirement_sha256,reviewed_at) VALUES ("
                "%s,%s,%s,%s,%s,%s,%s,%s,'VERIFIED',ARRAY[]::text[],"
                "ARRAY[]::text[],'HEALTHY','STANDARD',%s,%s,%s)",
                (
                    facts["review_id"], facts["organization_id"],
                    facts["demand_id"], facts["submission_id"],
                    facts["demand_version_id"], digest, facts["assignment_id"],
                    uuid4(), digest, rule_hash, now,
                ),
            )
            connection.execute(
                "INSERT INTO demand.demand_funding_markers (id,organization_id,"
                "demand_id,demand_version_id,funding_id,status,source_event_id,"
                "source_aggregate_version,amount_currency_sha256,"
                "verification_reference_sha256,occurred_at,created_at) VALUES ("
                "%s,%s,%s,%s,%s,'SECURED',%s,1,%s,%s,%s,%s)",
                (
                    facts["funding_marker_id"], facts["organization_id"],
                    facts["demand_id"], facts["demand_version_id"],
                    facts["funding_id"], uuid4(), digest, digest, now, now,
                ),
            )
            rule_ids = tuple(uuid4() for _ in range(6))
            connection.execute(
                "INSERT INTO demand.matching_requests (id,organization_id,demand_id,"
                "aggregate_version,status,demand_version_id,verified_review_id,"
                "funding_marker_id,funding_id,taxonomy_bundle_id,budget_rule_bundle_id,"
                "risk_rule_bundle_id,matching_rule_bundle_id,reason_code_bundle_id,"
                "composite_rule_requirement_id,matching_selector_digest,"
                "rule_requirement_sha256,budget_override_code,"
                "authorized_workload_principal_id,authorization_digest,"
                "requested_at,closed_at) VALUES ("
                "%s,%s,%s,1,'OPEN',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL,"
                "%s,%s,%s,NULL)",
                (
                    facts["matching_request_id"], facts["organization_id"],
                    facts["demand_id"], facts["demand_version_id"],
                    facts["review_id"], facts["funding_marker_id"],
                    facts["funding_id"], *rule_ids, digest, rule_hash,
                    facts["workload_id"], facts["authorization_digest"], now,
                ),
            )
            connection.execute(
                "UPDATE demand.demands SET status='MATCHING',aggregate_version=6,"
                "current_submission_id=%s,current_review_id=%s,verified_version_id=%s,"
                "current_funding_marker_id=%s,current_matching_request_id=%s,"
                "updated_at=%s WHERE id=%s",
                (
                    facts["submission_id"], facts["review_id"],
                    facts["demand_version_id"], facts["funding_marker_id"],
                    facts["matching_request_id"], now, facts["demand_id"],
                ),
            )
            connection.execute(
                "INSERT INTO infra.outbox_events (event_id,event_type,schema_version,"
                "occurred_at,aggregate_type,aggregate_id,aggregate_version,actor_kind,"
                "actor_id,original_actor_id,correlation_id,causation_id,trace_id,"
                "organization_id,payload,delivery_status,attempt_count,available_at,"
                "lease_owner,lease_until,published_at,last_error_code,created_at) "
                "VALUES (%s,'MatchingRequested',1,%s,'Demand',%s,6,%s,%s,"
                "%s,%s,%s,%s,%s,%s::jsonb,'PENDING',0,%s,NULL,NULL,NULL,NULL,%s)",
                (
                    facts["matching_event_id"], now, facts["demand_id"],
                    actor_kind,
                    (
                        facts["original_actor_user_id"]
                        if actor_kind == "USER"
                        else facts["workload_id"]
                    ),
                    (
                        None
                        if actor_kind == "USER"
                        else facts["original_actor_user_id"]
                    ),
                    uuid4(), uuid4(), uuid4(),
                    facts["organization_id"],
                    json.dumps({
                        "demand_id": str(facts["demand_id"]),
                        "demand_version_id": str(facts["demand_version_id"]),
                        "funding_id": str(facts["funding_id"]),
                        "matching_request_id": str(facts["matching_request_id"]),
                        "composite_rule_requirement_id": str(rule_ids[5]),
                        "status": "MATCHING",
                    }),
                    now,
                    now,
                ),
            )
        return facts

    @staticmethod
    def _delivery_gucs(
        workload_id: object,
        marker: object,
        operation: str,
    ) -> dict[str, str]:
        operation_name = {
            "CLAIM": "CLAIM_MATCHING_REQUESTED_DELIVERY",
            "FAIL": "FAIL_MATCHING_REQUESTED_DELIVERY",
            "COMPLETE": "COMPLETE_MATCHING_REQUESTED_DELIVERY",
        }[operation]
        assert isinstance(marker, bytes)
        return {
            "app.scope_kind": "DEMAND_MATCH_DELIVERY",
            "app.operation": operation_name,
            "app.workload_id": str(workload_id),
            "app.authority_marker_sha256": marker.hex(),
        }

    @staticmethod
    def _coordinator_gucs(
        facts: dict[str, object],
        command_id: UUID,
        actor_id: UUID,
        coordinator_id: UUID,
        marker: bytes,
    ) -> dict[str, str]:
        return {
            "app.scope_kind": "DEMAND_MATCHING_COORDINATOR",
            "app.operation": "COMPLETE_SELECTION",
            "app.actor_user_id": str(actor_id),
            "app.workload_id": str(coordinator_id),
            "app.organization_id": str(facts["organization_id"]),
            "app.demand_id": str(facts["demand_id"]),
            "app.command_id": str(command_id),
            "app.authority_marker_sha256": marker.hex(),
        }

    def _invoke(
        self,
        *,
        role: str,
        gucs: dict[str, str],
        statement: str,
        parameters: tuple[object, ...],
    ) -> tuple[object, ...] | None:
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user=role),
            autocommit=True,
        ) as connection:
            connection.execute("BEGIN")
            try:
                for name, value in gucs.items():
                    connection.execute(
                        "SELECT set_config(%s,%s,true)",
                        (name, value),
                    )
                row = connection.execute(statement, parameters).fetchone()
                connection.execute("COMMIT")
                return row
            except BaseException:
                connection.execute("ROLLBACK")
                raise


if __name__ == "__main__":
    unittest.main()
