"""Fresh-install Matching v3 operational behavior on real PostgreSQL 18."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest
from uuid import UUID

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
from desire_platform.matching.adapters.postgres.migrations import (
    MatchingContractSources,
    MatchingMigrationCatalog,
    MatchingMigrationRunner,
    MatchingMigrationSettings,
    PsycopgMatchingMigrationDriver,
)
from desire_platform.matching.engine_v1 import (
    compose_match_run_input_v1,
    load_default_rule_release_v1,
    load_rule_release_v1,
    normalize_match_run_input_v1,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18
from tests.support.matching_postgres_dependencies import (
    install_matching_runtime_dependencies,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
IAM_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
MATCHING_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/matching/adapters/postgres/migrations"
)
DEMAND_ROOT = (
    PLATFORM_ROOT / "src/desire_platform/demand/adapters/postgres/migrations"
)
WORKLOAD_ID = UUID("48000000-0000-4000-8000-000000000001")
ORGANIZATION_ID = UUID("49000000-0000-4000-8000-000000000001")
SECOND_ORGANIZATION_ID = UUID("49000000-0000-4000-8000-000000000002")
REVIEW_APPROVAL_ID = UUID("53000000-0000-4000-8000-000000000002")
AUTHORITY_MARKER = hashlib.sha256(
    b"exact-demand-match-request-allowlist"
).digest()


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


class MatchingV3RawApplyPostgres18Test(unittest.TestCase):
    def test_reviewed_v3_fresh_install_and_zero_candidate_close(self) -> None:
        postgres = TemporaryPostgres18().start()
        try:
            database = postgres.create_database()
            IamMigrationRunner(
                driver=PsycopgMigrationDriver(
                    settings=PsycopgMigrationSettings(
                        conninfo=postgres.conninfo(
                            database=database,
                            user="iam_migration_runner",
                        ),
                        application_name="matching-v3-raw-iam",
                    ),
                    dbapi=psycopg,
                ),
                runner_version="matching-v3-raw-iam/1",
            ).run(
                catalog=MigrationCatalog.load(IAM_ROOT),
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
                        conninfo=postgres.conninfo(
                            database=database,
                            user="demand_migration_runner",
                        ),
                        application_name="matching-v3-raw-demand15",
                    ),
                    dbapi=psycopg,
                ),
                runner_version="matching-v3-raw-demand15/1",
            ).run(
                catalog=DemandMigrationCatalog.load(DEMAND_ROOT),
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
            install_matching_runtime_dependencies(
                postgres=postgres,
                database=database,
                platform_root=PLATFORM_ROOT,
            )
            MatchingMigrationRunner(
                driver=PsycopgMatchingMigrationDriver(
                    settings=MatchingMigrationSettings(
                        conninfo=postgres.conninfo(
                            database=database,
                            user="matching_migration_runner",
                        ),
                        application_name="matching-v3-raw-v2",
                    ),
                    dbapi=psycopg,
                ),
                runner_version="matching-v3-raw-v2/1",
            ).run(
                catalog=MatchingMigrationCatalog.load(MATCHING_ROOT),
                contract_sources=MatchingContractSources(
                    api_contract_bytes=(
                        PLATFORM_ROOT / "contracts/api/matching-v1.openapi.yaml"
                    ).read_bytes(),
                    event_contract_bytes=(
                        PLATFORM_ROOT / "contracts/events/matching-v1.schema.json"
                    ).read_bytes(),
                    rule_contract_bytes=(
                        PLATFORM_ROOT
                        / "contracts/domain/matching-rule-release-v1.schema.json"
                    ).read_bytes(),
                    input_manifest_contract_bytes=(
                        PLATFORM_ROOT
                        / "contracts/domain/match-input-manifest-v1.schema.json"
                    ).read_bytes(),
                    run_input_contract_bytes=(
                        PLATFORM_ROOT
                        / "contracts/domain/match-run-input-v1.schema.json"
                    ).read_bytes(),
                    candidate_contract_bytes=(
                        PLATFORM_ROOT
                        / "contracts/domain/match-candidate-result-v1.schema.json"
                    ).read_bytes(),
                    disclosure_contract_bytes=(
                        PLATFORM_ROOT
                        / "contracts/domain/invitation-disclosure-v1.schema.json"
                    ).read_bytes(),
                ),
            )
            rule = load_default_rule_release_v1()
            manifest = psycopg.types.json.Jsonb(
                json.loads(rule.canonical_manifest_bytes.decode("utf-8"))
            )
            ids = tuple(
                UUID(f"54000000-0000-4000-8000-{value:012d}")
                for value in range(1, 7)
            )
            with psycopg.connect(
                postgres.conninfo(database=database, user="matching_worker")
            ) as connection:
                for key, value in (
                    ("app.scope_kind", "MATCHING_WORKER"),
                    ("app.operation", "PUBLISH_MATCHING_RULE"),
                    ("app.workload_id", str(WORKLOAD_ID)),
                    ("app.organization_id", str(ORGANIZATION_ID)),
                    ("app.authority_marker_sha256", AUTHORITY_MARKER.hex()),
                    ("app.command_id", str(ids[1])),
                ):
                    connection.execute(
                        "SELECT set_config(%s,%s,true)", (key, value)
                    )
                projection, replayed = connection.execute(
                    "SELECT safe_projection,replayed FROM "
                    "matching_api.publish_rule_bundle_v1("
                    "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,"
                    "%s,%s,%s,%s)",
                    (
                        WORKLOAD_ID,
                        ORGANIZATION_ID,
                        AUTHORITY_MARKER,
                        rule.canonical_manifest_bytes,
                        manifest,
                        bytes.fromhex(rule.canonical_manifest_sha256),
                        "packaged-deterministic-matcher-v1",
                        REVIEW_APPROVAL_ID,
                        1,
                        ids[0],
                        ids[1],
                        "matching-idempotency-v1",
                        hashlib.sha256(b"publish-default-rule").digest(),
                        "matching-payload-hash-v1",
                        hashlib.sha256(rule.canonical_manifest_bytes).digest(),
                        ids[2],
                        ids[3],
                        ids[4],
                        ids[5],
                    ),
                ).fetchone()
                self.assertFalse(replayed)
                self.assertEqual(projection["rule_bundle_id"], rule.bundle_id)
                self.assertEqual(
                    projection["canonical_manifest_sha256"],
                    rule.canonical_manifest_sha256,
                )

            second_ids = tuple(
                UUID(f"54000000-0000-4000-8000-{value:012d}")
                for value in range(7, 13)
            )
            with psycopg.connect(
                postgres.conninfo(database=database, user="matching_worker")
            ) as connection:
                for key, value in (
                    ("app.scope_kind", "MATCHING_WORKER"),
                    ("app.operation", "PUBLISH_MATCHING_RULE"),
                    ("app.workload_id", str(WORKLOAD_ID)),
                    ("app.organization_id", str(SECOND_ORGANIZATION_ID)),
                    ("app.authority_marker_sha256", AUTHORITY_MARKER.hex()),
                    ("app.command_id", str(second_ids[1])),
                ):
                    connection.execute(
                        "SELECT set_config(%s,%s,true)", (key, value)
                    )
                second_projection, second_replayed = connection.execute(
                    "SELECT safe_projection,replayed FROM "
                    "matching_api.publish_rule_bundle_v1("
                    + ",".join(("%s",) * 19)
                    + ")",
                    (
                        WORKLOAD_ID,
                        SECOND_ORGANIZATION_ID,
                        AUTHORITY_MARKER,
                        rule.canonical_manifest_bytes,
                        manifest,
                        bytes.fromhex(rule.canonical_manifest_sha256),
                        "packaged-deterministic-matcher-v1",
                        REVIEW_APPROVAL_ID,
                        1,
                        second_ids[0],
                        second_ids[1],
                        "matching-idempotency-v1",
                        hashlib.sha256(b"publish-default-rule-org-2").digest(),
                        "matching-payload-hash-v1",
                        hashlib.sha256(
                            b"org-2|" + rule.canonical_manifest_bytes
                        ).digest(),
                        second_ids[2],
                        second_ids[3],
                        second_ids[4],
                        second_ids[5],
                    ),
                ).fetchone()
                self.assertFalse(second_replayed)
                self.assertEqual(second_projection, projection)

            with psycopg.connect(
                postgres.admin_conninfo(database=database)
            ) as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT count(*),min(status),max(status) "
                        "FROM matching.rule_bundles WHERE id=%s",
                        (UUID(rule.bundle_id),),
                    ).fetchone(),
                    (1, "ACTIVE", "ACTIVE"),
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT aggregate_version FROM matching.rule_selectors "
                        "WHERE selector_digest=%s",
                        (bytes.fromhex(rule.selector_digest),),
                    ).fetchone(),
                    (1,),
                )

            with psycopg.connect(
                postgres.conninfo(database=database, user="matching_worker")
            ) as connection:
                for key, value in (
                    ("app.scope_kind", "MATCHING_WORKER"),
                    ("app.operation", "READ_MATCHING_RULE"),
                    ("app.workload_id", str(WORKLOAD_ID)),
                    ("app.organization_id", str(ORGANIZATION_ID)),
                    ("app.authority_marker_sha256", AUTHORITY_MARKER.hex()),
                    ("app.rule_bundle_id", rule.bundle_id),
                ):
                    connection.execute(
                        "SELECT set_config(%s,%s,true)", (key, value)
                    )
                stored = connection.execute(
                    "SELECT * FROM matching_api.read_rule_bundle_for_match_v1("
                    "%s,%s,%s,%s,%s)",
                    (
                        WORKLOAD_ID,
                        ORGANIZATION_ID,
                        AUTHORITY_MARKER,
                        UUID(rule.bundle_id),
                        bytes.fromhex(rule.selector_digest),
                    ),
                ).fetchone()
                self.assertIsNotNone(stored)
                loaded = load_rule_release_v1(
                    bytes(stored[2]),
                    expected_manifest_sha256=bytes(stored[4]).hex(),
                )
                self.assertEqual(loaded, rule)
                self.assertEqual(stored[3]["bundle_id"], rule.bundle_id)
                self.assertNotIn("signature_key_id", stored[3])
                self.assertNotIn("review_approval_id", stored[3])
                self.assertNotIn("published_by_workload_id", stored[3])

            now = datetime.now(timezone.utc)
            captured_at = now.isoformat().replace("+00:00", "Z")
            authorization_valid_until = now + timedelta(minutes=30)
            attempt_id = UUID("55000000-0000-4000-8000-000000000001")
            run_id = UUID("55000000-0000-4000-8000-000000000002")
            selection_id = UUID("55000000-0000-4000-8000-000000000003")
            job_id = UUID("55000000-0000-4000-8000-000000000004")
            demand_id = UUID("55000000-0000-4000-8000-000000000005")
            demand_version_id = UUID(
                "55000000-0000-4000-8000-000000000006"
            )
            matching_request_id = UUID(
                "55000000-0000-4000-8000-000000000007"
            )
            funding_id = UUID("55000000-0000-4000-8000-000000000008")
            source_event_id = UUID(
                "55000000-0000-4000-8000-000000000009"
            )
            source_authorization_digest = hashlib.sha256(
                b"demand-profile-capture-authorization"
            ).digest()
            lease_digest = hashlib.sha256(b"matching-worker-lease").digest()
            candidate_allowlist_sha256 = hashlib.sha256(b"[]").digest()
            demand_content_bytes = _canonical_json_bytes(
                {"schema_version": 1}
            )
            demand_content_sha256 = hashlib.sha256(
                demand_content_bytes
            ).digest()
            with psycopg.connect(
                postgres.admin_conninfo(database=database)
            ) as connection:
                connection.execute("SET CONSTRAINTS ALL DEFERRED")
                connection.execute(
                    "INSERT INTO matching.matching_attempts ("
                    "id,organization_id,demand_id,demand_version_id,"
                    "demand_content_sha256,demand_aggregate_version,"
                    "matching_request_id,matching_request_version,funding_id,"
                    "composite_rule_requirement_id,matching_rule_bundle_id,"
                    "selector_digest,source_event_id,attempt_no,status,"
                    "aggregate_version,current_match_run_id,selection_id,"
                    "input_baseline_sha256,system_workload_id,"
                    "system_authority_marker_sha256,created_at,updated_at,"
                    "terminal_at,source_authorization_digest) VALUES ("
                    "%s,%s,%s,%s,%s,1,%s,1,%s,%s,%s,%s,%s,1,'OPEN',1,"
                    "%s,NULL,%s,%s,%s,%s,%s,NULL,%s)",
                    (
                        attempt_id,
                        ORGANIZATION_ID,
                        demand_id,
                        demand_version_id,
                        demand_content_sha256,
                        matching_request_id,
                        funding_id,
                        UUID("55000000-0000-4000-8000-000000000010"),
                        UUID(rule.bundle_id),
                        bytes.fromhex(rule.selector_digest),
                        source_event_id,
                        run_id,
                        hashlib.sha256(b"input-baseline").digest(),
                        WORKLOAD_ID,
                        AUTHORITY_MARKER,
                        now,
                        now,
                        source_authorization_digest,
                    ),
                )
                connection.execute(
                    "INSERT INTO matching.match_runs ("
                    "id,organization_id,attempt_id,demand_id,run_no,status,"
                    "aggregate_version,matching_rule_bundle_id,"
                    "input_manifest_sha256,input_set_sha256,"
                    "ordered_result_sha256,candidate_count,eligible_count,"
                    "excluded_count,worker_id,lease_token_digest_key_id,"
                    "lease_token_digest,fencing_generation,lease_until,"
                    "supersedes_run_id,superseded_by_run_id,failure_code,"
                    "created_at,updated_at) VALUES ("
                    "%s,%s,%s,%s,1,'QUEUED',1,%s,NULL,NULL,NULL,NULL,NULL,"
                    "NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,%s,%s)",
                    (
                        run_id,
                        ORGANIZATION_ID,
                        attempt_id,
                        demand_id,
                        UUID(rule.bundle_id),
                        now,
                        now,
                    ),
                )
                connection.execute(
                    "INSERT INTO matching.selections ("
                    "id,organization_id,attempt_id,match_run_id,status,"
                    "aggregate_version,current_invitation_set_sha256,"
                    "chosen_invitation_id,chosen_invitation_status,"
                    "selection_basis_code,reason_code,decision_actor_id,"
                    "coordinator_workload_id,"
                    "coordinator_authority_marker_sha256,created_at,updated_at) "
                    "VALUES (%s,%s,%s,%s,'OPEN',1,%s,NULL,NULL,NULL,NULL,NULL,"
                    "%s,%s,%s,%s)",
                    (
                        selection_id,
                        ORGANIZATION_ID,
                        attempt_id,
                        run_id,
                        hashlib.sha256(b"empty-invitation-set").digest(),
                        WORKLOAD_ID,
                        AUTHORITY_MARKER,
                        now,
                        now,
                    ),
                )
                connection.execute(
                    "UPDATE matching.matching_attempts SET selection_id=%s "
                    "WHERE id=%s",
                    (selection_id, attempt_id),
                )
                connection.execute(
                    "INSERT INTO matching.match_jobs ("
                    "id,organization_id,attempt_id,match_run_id,job_kind,"
                    "status,workload_id,authority_marker_sha256,"
                    "lease_token_digest_key_id,lease_token_digest,"
                    "fencing_generation,available_at,lease_until,"
                    "attempt_count,created_at,completed_at) VALUES ("
                    "%s,%s,%s,%s,'RUN_MATCH','LEASED',%s,%s,%s,%s,1,%s,%s,"
                    "1,%s,NULL)",
                    (
                        job_id,
                        ORGANIZATION_ID,
                        attempt_id,
                        run_id,
                        WORKLOAD_ID,
                        AUTHORITY_MARKER,
                        "matching-worker-lease-v1",
                        lease_digest,
                        now,
                        authorization_valid_until,
                        now,
                    ),
                )

            demand_input = {
                "problem_type_codes": ["PROBLEM.EFFICIENCY"],
                "domain_codes": ["DOMAIN.ENERGY"],
                "task_codes": ["TASK.ANALYZE"],
                "must_have_skills": [],
                "nice_to_have_skills": [],
                "start_date": "2035-01-02",
                "due_date": "2035-02-28",
                "required_weekly_hours": 10,
                "required_duration_weeks": 6,
                "currency": "CNY",
                "minimum_amount_minor": 100000,
                "maximum_amount_minor": 200000,
                "allowed_region_codes": ["REGION.CN"],
                "required_language_codes": ["LANGUAGE.ZH"],
                "required_work_mode_code": "WORK_MODE.REMOTE",
                "data_sensitivity_code": "INTERNAL",
                "ai_use_code": "OPTIONAL",
                "budget_override_code": None,
            }
            manifest_references = {
                "attempt_id": str(attempt_id),
                "run_id": str(run_id),
                "organization_id": str(ORGANIZATION_ID),
                "demand_id": str(demand_id),
                "demand_version_id": str(demand_version_id),
                "demand_content_sha256": demand_content_sha256.hex(),
                "funding_id": str(funding_id),
                "matching_request_id": str(matching_request_id),
                "matching_request_version": 1,
                "matching_rule_bundle_id": rule.bundle_id,
                "selector_digest": rule.selector_digest,
                "rule_manifest_sha256": rule.canonical_manifest_sha256,
                "ordered_candidates": [],
                "captured_at": captured_at,
                "candidate_count": 0,
            }
            run_without_digest = {
                "schema_version": 1,
                "canonicalization_version": "match-run-input-json-v1",
                "attempt_id": str(attempt_id),
                "run_id": str(run_id),
                "demand_id": str(demand_id),
                "demand_version_id": str(demand_version_id),
                "matching_rule_bundle_id": rule.bundle_id,
                "demand": demand_input,
                "profiles": [],
            }
            canonical_input_set_bytes = _canonical_json_bytes(
                {
                    "manifest_references": manifest_references,
                    "run_input": run_without_digest,
                }
            )
            input_set_sha256 = hashlib.sha256(
                canonical_input_set_bytes
            ).hexdigest()
            engine_input = compose_match_run_input_v1(
                attempt_id=str(attempt_id),
                run_id=str(run_id),
                demand_id=str(demand_id),
                demand_version_id=str(demand_version_id),
                matching_rule_bundle_id=rule.bundle_id,
                input_set_sha256=input_set_sha256,
                demand=demand_input,
                profiles=(),
            )
            run_input = json.loads(engine_input.canonical_input_bytes)
            manifest_document = {
                "schema_version": 1,
                "canonicalization_version": "match-input-manifest-v1",
                **manifest_references,
                "input_set_sha256": input_set_sha256,
            }
            canonical_manifest_bytes = _canonical_json_bytes(
                manifest_document
            )
            source_capture = {
                "schema_version": 1,
                "canonicalization_version": (
                    "matching-source-capture-bundle-json-v1"
                ),
                "match_run_id": str(run_id),
                "workload_id": str(WORKLOAD_ID),
                "authorization_digest": source_authorization_digest.hex(),
                "demand": {
                    "matching_request_id": str(matching_request_id),
                    "demand_id": str(demand_id),
                    "demand_version_id": str(demand_version_id),
                    "content_sha256": demand_content_sha256.hex(),
                    "canonical_content_hex": demand_content_bytes.hex(),
                    "content": json.loads(demand_content_bytes),
                    "captured_at": captured_at,
                },
                "profile": {
                    "capture_contract_version": 2,
                    "status": "COMPLETED",
                    "captured_at": captured_at,
                    "authorization_valid_until": (
                        authorization_valid_until.isoformat().replace(
                            "+00:00", "Z"
                        )
                    ),
                    "candidate_count": 0,
                    "allowlist_sha256": candidate_allowlist_sha256.hex(),
                    "snapshots": [],
                },
            }
            canonical_source_capture_bytes = _canonical_json_bytes(
                source_capture
            )
            start_ids = tuple(
                UUID(f"56000000-0000-4000-8000-{value:012d}")
                for value in range(1, 7)
            )
            with psycopg.connect(
                postgres.conninfo(database=database, user="matching_worker")
            ) as connection:
                for key, value in (
                    ("app.scope_kind", "MATCHING_WORKER"),
                    ("app.operation", "START_MATCH_RUN"),
                    ("app.workload_id", str(WORKLOAD_ID)),
                    ("app.organization_id", str(ORGANIZATION_ID)),
                    ("app.authority_marker_sha256", AUTHORITY_MARKER.hex()),
                    ("app.command_id", str(start_ids[1])),
                    ("app.lease_token_digest_key_id", "matching-worker-lease-v1"),
                    ("app.lease_token_digest", lease_digest.hex()),
                ):
                    connection.execute(
                        "SELECT set_config(%s,%s,true)", (key, value)
                    )
                arguments = (
                    WORKLOAD_ID,
                    ORGANIZATION_ID,
                    AUTHORITY_MARKER,
                    job_id,
                    run_id,
                    1,
                    "matching-worker-lease-v1",
                    lease_digest,
                    canonical_manifest_bytes,
                    psycopg.types.json.Jsonb(manifest_document),
                    hashlib.sha256(canonical_manifest_bytes).digest(),
                    engine_input.canonical_input_bytes,
                    psycopg.types.json.Jsonb(run_input),
                    bytes.fromhex(engine_input.canonical_input_sha256),
                    canonical_input_set_bytes,
                    bytes.fromhex(input_set_sha256),
                    candidate_allowlist_sha256,
                    0,
                    canonical_source_capture_bytes,
                    psycopg.types.json.Jsonb(source_capture),
                    hashlib.sha256(canonical_source_capture_bytes).digest(),
                    authorization_valid_until,
                    start_ids[0],
                    start_ids[1],
                    "matching-idempotency-v1",
                    hashlib.sha256(b"start-match-run").digest(),
                    "matching-payload-hash-v1",
                    hashlib.sha256(
                        canonical_manifest_bytes
                        + engine_input.canonical_input_bytes
                        + canonical_source_capture_bytes
                    ).digest(),
                    start_ids[2],
                    start_ids[3],
                    start_ids[4],
                    start_ids[5],
                )
                projection, replayed = connection.execute(
                    "SELECT safe_projection,replayed FROM "
                    "matching_api.start_match_run_v1("
                    + ",".join(("%s",) * len(arguments))
                    + ")",
                    arguments,
                ).fetchone()
                self.assertFalse(replayed)
                self.assertEqual(projection["status"], "RUNNING")
                self.assertEqual(
                    projection["input_set_sha256"], input_set_sha256
                )
                self.assertEqual(
                    projection["run_input_sha256"],
                    engine_input.canonical_input_sha256,
                )
                self.assertNotEqual(
                    projection["input_set_sha256"],
                    projection["run_input_sha256"],
                )

            with psycopg.connect(
                postgres.admin_conninfo(database=database)
            ) as connection:
                persisted = connection.execute(
                    "SELECT canonical_run_input_bytes,run_input_sha256,"
                    "canonical_input_set_bytes,input_set_sha256 FROM "
                    "matching.match_run_inputs WHERE match_run_id=%s",
                    (run_id,),
                ).fetchone()
                self.assertEqual(bytes(persisted[0]), engine_input.canonical_input_bytes)
                self.assertEqual(
                    bytes(persisted[1]).hex(),
                    engine_input.canonical_input_sha256,
                )
                self.assertEqual(bytes(persisted[2]), canonical_input_set_bytes)
                self.assertEqual(bytes(persisted[3]).hex(), input_set_sha256)
                self.assertEqual(
                    normalize_match_run_input_v1(
                        bytes(persisted[0]),
                        expected_input_set_sha256=input_set_sha256,
                        expected_canonical_sha256=bytes(persisted[1]).hex(),
                    ),
                    engine_input,
                )
        finally:
            if "database" in locals():
                postgres.drop_database(database)
            postgres.stop()


if __name__ == "__main__":
    unittest.main()
