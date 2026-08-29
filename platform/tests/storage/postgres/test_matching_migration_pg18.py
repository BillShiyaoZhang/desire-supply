"""Real PostgreSQL 18 gates for Matching v1 constraints and FORCE RLS."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import unittest
from uuid import UUID

import psycopg

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
from desire_platform.matching.adapters.postgres.operational_runtime import (
    MatchingAssignmentContext,
    MatchingCandidateSelectorClaimRequest,
    MatchingOperationalCommandMaterial,
    MatchingRulePublicationRequest,
    MatchingWorkloadContext,
    PsycopgMatchingAssignmentRuntime,
    PsycopgMatchingCoordinatorRuntime,
    PsycopgMatchingWorkerRuntime,
    _expected_runtime_dependency_snapshot,
)
from desire_platform.matching.adapters.postgres.runtime import (
    CandidateSelectionMutation,
    CandidateSelectionOperation,
    CreatorInvitationMutation,
    CreatorInvitationOperation,
    MatchingCommandContext,
    MatchingCreatorContext,
    MatchingSelectorDiscoveryContext,
    MatchingSelectorContext,
    MatchingWriteMaterial,
    MatchingPostgresConfigurationError,
    PsycopgMatchingRuntime,
)
from desire_platform.matching.engine_v1 import load_default_rule_release_v1
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18
from tests.support.creator_profile_postgres_builders import (
    ACTOR_USER_ID as IAM_CREATOR_ID,
    SESSION_ID as IAM_CREATOR_SESSION_ID,
    seed_exact_creator_iam_authority,
)
from tests.support.matching_postgres_dependencies import (
    install_matching_runtime_dependencies,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
IAM_MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
MATCHING_MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/matching/adapters/postgres/migrations"
)
ORGANIZATION_ID = "61000000-0000-4000-8000-000000000001"
DEMAND_ID = "62000000-0000-4000-8000-000000000001"
DEMAND_VERSION_ID = "63000000-0000-4000-8000-000000000001"
MATCHING_REQUEST_ID = "64000000-0000-4000-8000-000000000001"
FUNDING_ID = "65000000-0000-4000-8000-000000000001"
RULE_ID = "66000000-0000-4000-8000-000000000001"
ATTEMPT_ID = "67000000-0000-4000-8000-000000000001"
RUN_ID = "68000000-0000-4000-8000-000000000001"
CREATOR_ID = str(IAM_CREATOR_ID)
PROFILE_ID = "6a000000-0000-4000-8000-000000000001"
PROFILE_VERSION_ID = "6b000000-0000-4000-8000-000000000001"
INVITATION_ID = "6c000000-0000-4000-8000-000000000001"
SNAPSHOT_ID = "6d000000-0000-4000-8000-000000000001"
SELECTION_ID = "6e000000-0000-4000-8000-000000000001"
SELECTOR_ID = CREATOR_ID
SELECTOR_SESSION_ID = "82000000-0000-4000-8000-000000000001"
SELECTOR_FAMILY_ID = "82000000-0000-4000-8000-000000000002"
SELECTOR_MEMBERSHIP_ID = "82000000-0000-4000-8000-000000000003"
SELECTOR_OPT_IN_RECEIPT_ID = "82000000-0000-4000-8000-000000000004"
SELECTOR_OPT_IN_COMMAND_ID = "82000000-0000-4000-8000-000000000005"
SELECTOR_MEMBERSHIP_ROLE_GRANT_ID = "82000000-0000-4000-8000-000000000006"
SELECTOR_ASSIGNMENT_ID = "70000000-0000-4000-8000-000000000001"
WORKLOAD_ID = "71000000-0000-4000-8000-000000000001"
JOB_ID = "72000000-0000-4000-8000-000000000001"
MARKER = bytes.fromhex("ab" * 32)
OTHER_MARKER = bytes.fromhex("cd" * 32)
HASH = bytes.fromhex("11" * 32)
OTHER_HASH = bytes.fromhex("22" * 32)


def _seed_exact_selector_iam_authority(
    connection,
    *,
    now: datetime,
    source_invitation_id: UUID,
) -> None:
    """Add one recent Session and ACTIVE membership for IAM44 opt-in."""

    created_at = now - timedelta(minutes=10)
    auth_time = now - timedelta(minutes=5)
    session_created_at = now - timedelta(minutes=4)
    last_activity_at = now - timedelta(minutes=1)
    connection.execute("SET LOCAL session_replication_role = 'replica'")
    connection.execute(
        "INSERT INTO iam.organizations ("
        "id,organization_type,public_name,jurisdiction,status,"
        "client_reference_namespace,client_reference,aggregate_version,"
        "created_at,updated_at) VALUES ("
        "%s,'BUSINESS','Matching selector fixture','CN','ACTIVE',"
        "'matching-pg18',%s,1,%s,%s)",
        (ORGANIZATION_ID, ORGANIZATION_ID, created_at, now),
    )
    connection.execute(
        "INSERT INTO iam.memberships ("
        "id,organization_id,user_id,status,source_invitation_id,"
        "aggregate_version,created_at,updated_at) VALUES ("
        "%s,%s,%s,'ACTIVE',%s,1,%s,%s)",
        (
            SELECTOR_MEMBERSHIP_ID,
            ORGANIZATION_ID,
            SELECTOR_ID,
            source_invitation_id,
            created_at,
            now,
        ),
    )
    connection.execute(
        "INSERT INTO iam.membership_role_grants ("
        "id,organization_id,membership_id,user_id,role_code,"
        "source_invitation_id,policy_selector_digest,granted_by_kind,"
        "granted_by_id,granted_at,revoked_at,revocation_reason_code,"
        "aggregate_version) VALUES ("
        "%s,%s,%s,%s,'DEMAND_OWNER',%s,%s,'SYSTEM',%s,%s,NULL,NULL,1)",
        (
            SELECTOR_MEMBERSHIP_ROLE_GRANT_ID,
            ORGANIZATION_ID,
            SELECTOR_MEMBERSHIP_ID,
            SELECTOR_ID,
            source_invitation_id,
            HASH,
            "82000000-0000-4000-8000-000000000007",
            created_at,
        ),
    )
    connection.execute(
        "INSERT INTO iam.session_families ("
        "id,user_id,status,current_generation,revoked_at,"
        "revocation_reason_code,aggregate_version,created_at,updated_at) "
        "VALUES (%s,%s,'ACTIVE',1,NULL,NULL,1,%s,%s)",
        (SELECTOR_FAMILY_ID, SELECTOR_ID, created_at, now),
    )
    connection.execute(
        "INSERT INTO iam.sessions ("
        "id,user_id,family_id,generation,predecessor_session_id,"
        "handle_digest,handle_digest_key_id,csrf_salt,csrf_key_id,csrf_digest,"
        "verified_contact_point_id,verified_at,verified_for_invitation_id,"
        "auth_transaction_id,auth_time,acr_code,amr_codes,created_at,"
        "last_activity_at,idle_expires_at,absolute_expires_at,updated_at,"
        "device_label,status,rotation_reason,revoked_at,"
        "revocation_reason_code,aggregate_version) VALUES ("
        "%s,%s,%s,1,NULL,%s,'matching-selector-session-v1',%s,"
        "'matching-selector-csrf-v1',%s,NULL,NULL,NULL,NULL,%s,'urn:pwd',"
        "ARRAY['pwd']::text[],%s,%s,%s,%s,%s,'Browser','ACTIVE','LOGIN',"
        "NULL,NULL,1)",
        (
            SELECTOR_SESSION_ID,
            SELECTOR_ID,
            SELECTOR_FAMILY_ID,
            hashlib.sha256(b"matching-selector-handle").digest(),
            hashlib.sha256(b"matching-selector-csrf-salt").digest(),
            hashlib.sha256(b"matching-selector-csrf").digest(),
            auth_time,
            session_created_at,
            last_activity_at,
            now + timedelta(minutes=30),
            now + timedelta(days=1),
            now,
        ),
    )


class _RuntimeConnections:
    def __init__(self, conninfo: str) -> None:
        self._conninfo = conninfo

    def checkout(self):
        return psycopg.connect(self._conninfo, autocommit=True)

    @staticmethod
    def release(connection) -> None:
        connection.close()

    @staticmethod
    def discard(connection) -> None:
        connection.close()


class MatchingMigrationPostgres18Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()
        cls.database = cls.postgres.create_database()

        iam_catalog = MigrationCatalog.load(IAM_MIGRATION_ROOT)
        IamMigrationRunner(
            driver=PsycopgMigrationDriver(
                settings=PsycopgMigrationSettings(
                    conninfo=cls.postgres.conninfo(
                        database=cls.database,
                        user="iam_migration_runner",
                    ),
                    application_name="desire-matching-pg18-iam",
                ),
                dbapi=psycopg,
            ),
            runner_version="matching-pg18-iam/1",
        ).run(
            catalog=iam_catalog,
            contract_sources=IamContractSources(
                api_contract_bytes=(
                    PLATFORM_ROOT / "contracts/api/iam-v1.openapi.yaml"
                ).read_bytes(),
                event_contract_bytes=(
                    PLATFORM_ROOT / "contracts/events/iam-v1.schema.json"
                ).read_bytes(),
            ),
        )
        with psycopg.connect(
            cls.postgres.admin_conninfo(database=cls.database),
            autocommit=False,
        ) as connection:
            now = datetime.now(timezone.utc)
            authority = seed_exact_creator_iam_authority(
                connection,
                now=now,
            )
            _seed_exact_selector_iam_authority(
                connection,
                now=now,
                source_invitation_id=authority.creator_invitation_id,
            )
        install_matching_runtime_dependencies(
            postgres=cls.postgres,
            database=cls.database,
            platform_root=PLATFORM_ROOT,
        )
        with psycopg.connect(
            cls.postgres.conninfo(
                database=cls.database, user="matching_creator"
            )
        ) as connection:
            for key, value in (
                ("app.scope_kind", "MATCHING_CREATOR"),
                ("app.operation", "LIST_MATCHING_INVITATIONS"),
                ("app.actor_user_id", CREATOR_ID),
                ("app.session_id", str(IAM_CREATOR_SESSION_ID)),
                ("app.organization_id", ""),
                ("app.invitation_id", ""),
                ("app.command_id", ""),
            ):
                connection.execute("SELECT set_config(%s,%s,true)", (key, value))
            authority = connection.execute(
                "SELECT * FROM iam_api."
                "resolve_matching_creator_authority_marker_v1("
                "%s,%s,'LIST_MATCHING_INVITATIONS',NULL,NULL)",
                (CREATOR_ID, IAM_CREATOR_SESSION_ID),
            ).fetchone()
        if authority is None:
            raise AssertionError("IAM46 Matching creator fixture is unavailable")
        cls.creator_marker = bytes(authority[4])
        with psycopg.connect(
            cls.postgres.conninfo(database=cls.database, user="iam_app")
        ) as connection:
            for key, value in (
                ("app.scope_kind", "EDITOR_PRINCIPAL"),
                ("app.actor_user_id", SELECTOR_ID),
                ("app.session_id", SELECTOR_SESSION_ID),
            ):
                connection.execute("SELECT set_config(%s,%s,true)", (key, value))
            selector_authority = connection.execute(
                "SELECT principal_marker_sha256 FROM "
                "iam_api.resolve_editor_principal_v1(%s,%s) "
                "WHERE organization_id=%s",
                (SELECTOR_ID, SELECTOR_SESSION_ID, ORGANIZATION_ID),
            ).fetchone()
        if selector_authority is None:
            raise AssertionError("IAM46 Matching selector fixture is unavailable")
        cls.selector_marker = bytes(selector_authority[0])

        cls.catalog = MatchingMigrationCatalog.load(MATCHING_MIGRATION_ROOT)
        cls.sources = MatchingContractSources(
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
        )
        cls.runner = MatchingMigrationRunner(
            driver=PsycopgMatchingMigrationDriver(
                settings=MatchingMigrationSettings(
                    conninfo=cls.postgres.conninfo(
                        database=cls.database,
                        user="matching_migration_runner",
                    ),
                    application_name="desire-matching-pg18",
                ),
                dbapi=psycopg,
            ),
            runner_version="matching-pg18/1",
        )
        cls.first_report = cls.runner.run(
            catalog=cls.catalog,
            contract_sources=cls.sources,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            if hasattr(cls, "database"):
                cls.postgres.drop_database(cls.database)
        finally:
            cls.postgres.stop()

    @classmethod
    def _admin(cls, database: str | None = None, *, autocommit: bool = True):
        return psycopg.connect(
            cls.postgres.admin_conninfo(database=database or cls.database),
            autocommit=autocommit,
        )

    @classmethod
    def _load_selector_marker(cls, database: str) -> bytes:
        with psycopg.connect(
            cls.postgres.conninfo(database=database, user="iam_app")
        ) as connection:
            for key, value in (
                ("app.scope_kind", "EDITOR_PRINCIPAL"),
                ("app.actor_user_id", SELECTOR_ID),
                ("app.session_id", SELECTOR_SESSION_ID),
            ):
                connection.execute("SELECT set_config(%s,%s,true)", (key, value))
            row = connection.execute(
                "SELECT principal_marker_sha256 FROM "
                "iam_api.resolve_editor_principal_v1(%s,%s) "
                "WHERE organization_id=%s",
                (SELECTOR_ID, SELECTOR_SESSION_ID, ORGANIZATION_ID),
            ).fetchone()
        if row is None:
            raise AssertionError("IAM46 Candidate Selector marker is unavailable")
        return bytes(row[0])

    @staticmethod
    def _seed_v2_upgrade_graph(connection, *, selector_marker: bytes) -> None:
        now = datetime.now(timezone.utc)
        rule = load_default_rule_release_v1()
        connection.execute(
            "INSERT INTO matching.rule_bundles ("
            "id,semantic_version,status,selector_digest,jurisdiction_code,"
            "locale,demand_type_code,taxonomy_family_code,engine_identifier,"
            "engine_major,engine_artifact_sha256,taxonomy_bundle_id,"
            "budget_rule_version,matching_rule_version,reason_code_version,"
            "explanation_template_version,canonical_manifest_sha256,"
            "signature_key_id,review_approval_id,review_approval_version,"
            "effective_at,effective_until,published_by_workload_id,"
            "published_authority_marker_sha256,created_at,updated_at) VALUES ("
            "%s,%s,'ACTIVE',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,"
            "'matching-rule-review-v1',%s,1,%s,%s,%s,%s,%s,%s)",
            (
                rule.bundle_id,
                rule.semantic_version,
                bytes.fromhex(rule.selector_digest),
                rule.jurisdiction_code,
                rule.locale,
                rule.demand_type_code,
                rule.taxonomy_family_code,
                rule.engine_identifier,
                rule.engine_major,
                bytes.fromhex(rule.engine_artifact_sha256),
                rule.taxonomy_bundle_id,
                rule.budget_rule_version,
                rule.matching_rule_version,
                rule.reason_code_version,
                rule.explanation_template_version,
                bytes.fromhex(rule.canonical_manifest_sha256),
                "9eabf3d2-614c-5d47-99c2-d752d62bfd76",
                rule.effective_at,
                rule.effective_until,
                WORKLOAD_ID,
                MARKER,
                now,
                now,
            ),
        )
        connection.execute(
            "INSERT INTO matching.rule_selectors ("
            "selector_digest,current_bundle_id,aggregate_version,updated_at) "
            "VALUES (%s,%s,1,%s)",
            (bytes.fromhex(rule.selector_digest), rule.bundle_id, now),
        )
        connection.execute(
            "INSERT INTO matching.matching_attempts ("
            "id,organization_id,demand_id,demand_version_id,"
            "demand_content_sha256,demand_aggregate_version,matching_request_id,"
            "matching_request_version,funding_id,composite_rule_requirement_id,"
            "matching_rule_bundle_id,selector_digest,source_event_id,attempt_no,"
            "status,aggregate_version,current_match_run_id,selection_id,"
            "input_baseline_sha256,system_workload_id,"
            "system_authority_marker_sha256,created_at,updated_at,terminal_at) "
            "VALUES (%s,%s,%s,%s,%s,7,%s,3,%s,%s,%s,%s,%s,1,'OPEN',1,%s,NULL,"
            "%s,%s,%s,%s,%s,NULL)",
            (
                ATTEMPT_ID,
                ORGANIZATION_ID,
                DEMAND_ID,
                DEMAND_VERSION_ID,
                HASH,
                MATCHING_REQUEST_ID,
                FUNDING_ID,
                "75000000-0000-4000-8000-000000000001",
                rule.bundle_id,
                bytes.fromhex(rule.selector_digest),
                "76000000-0000-4000-8000-000000000001",
                RUN_ID,
                HASH,
                WORKLOAD_ID,
                MARKER,
                now,
                now,
            ),
        )
        connection.execute(
            "INSERT INTO matching.match_runs ("
            "id,organization_id,attempt_id,demand_id,run_no,status,"
            "aggregate_version,matching_rule_bundle_id,input_manifest_sha256,"
            "input_set_sha256,ordered_result_sha256,candidate_count,eligible_count,"
            "excluded_count,worker_id,lease_token_digest_key_id,"
            "lease_token_digest,fencing_generation,lease_until,supersedes_run_id,"
            "superseded_by_run_id,failure_code,created_at,updated_at) VALUES ("
            "%s,%s,%s,%s,1,'COMPLETED',3,%s,%s,%s,%s,0,0,0,NULL,NULL,NULL,1,"
            "NULL,NULL,NULL,NULL,%s,%s)",
            (
                RUN_ID,
                ORGANIZATION_ID,
                ATTEMPT_ID,
                DEMAND_ID,
                rule.bundle_id,
                HASH,
                HASH,
                OTHER_HASH,
                now,
                now,
            ),
        )
        connection.execute(
            "INSERT INTO matching.selections ("
            "id,organization_id,attempt_id,match_run_id,status,aggregate_version,"
            "current_invitation_set_sha256,chosen_invitation_id,"
            "chosen_invitation_status,selection_basis_code,reason_code,"
            "decision_actor_id,coordinator_workload_id,"
            "coordinator_authority_marker_sha256,created_at,updated_at) VALUES ("
            "%s,%s,%s,%s,'OPEN',1,%s,NULL,NULL,NULL,NULL,NULL,%s,%s,%s,%s)",
            (
                SELECTION_ID,
                ORGANIZATION_ID,
                ATTEMPT_ID,
                RUN_ID,
                HASH,
                WORKLOAD_ID,
                MARKER,
                now,
                now,
            ),
        )
        connection.execute(
            "UPDATE matching.matching_attempts SET selection_id=%s WHERE id=%s",
            (SELECTION_ID, ATTEMPT_ID),
        )
        connection.execute(
            "INSERT INTO matching.candidate_selector_assignments ("
            "id,assignment_version,status,assignee_user_id,organization_id,"
            "demand_id,selection_id,authority_marker_sha256,assigned_at,"
            "expires_at,completed_at) VALUES ("
            "%s,1,'ACTIVE',%s,%s,%s,%s,%s,%s,%s,NULL)",
            (
                SELECTOR_ASSIGNMENT_ID,
                SELECTOR_ID,
                ORGANIZATION_ID,
                DEMAND_ID,
                SELECTION_ID,
                selector_marker,
                now,
                now + timedelta(hours=1),
            ),
        )
        connection.execute(
            "INSERT INTO matching.matching_review_assignments ("
            "id,organization_id,attempt_id,match_run_id,reviewer_user_id,"
            "duty_grant_id,duty_grant_version,purpose_code,"
            "conflict_attestation_sha256,authority_marker_sha256,status,"
            "aggregate_version,expires_at,created_at,completed_at) VALUES ("
            "%s,%s,%s,%s,%s,%s,1,'MATCH_RETRY',%s,%s,'ACTIVE',1,%s,%s,NULL)",
            (
                "83000000-0000-4000-8000-000000000001",
                ORGANIZATION_ID,
                ATTEMPT_ID,
                RUN_ID,
                "83000000-0000-4000-8000-000000000002",
                "83000000-0000-4000-8000-000000000003",
                HASH,
                OTHER_HASH,
                now + timedelta(hours=1),
                now,
            ),
        )

    def setUp(self) -> None:
        with self._admin(autocommit=False) as connection:
            connection.execute("TRUNCATE matching.rule_bundles CASCADE")
            self._seed_graph(connection)

    @classmethod
    def _seed_graph(cls, connection) -> None:
        now = datetime.now(timezone.utc)
        connection.execute(
            "INSERT INTO matching.rule_bundles ("
            "id,semantic_version,status,selector_digest,jurisdiction_code,"
            "locale,demand_type_code,taxonomy_family_code,engine_identifier,"
            "engine_major,engine_artifact_sha256,taxonomy_bundle_id,"
            "budget_rule_version,matching_rule_version,reason_code_version,"
            "explanation_template_version,canonical_manifest_sha256,"
            "signature_key_id,review_approval_id,review_approval_version,"
            "effective_at,effective_until,published_by_workload_id,"
            "published_authority_marker_sha256,created_at,updated_at) VALUES ("
            "%s,'1.0.0','ACTIVE',%s,'CN','zh-CN','STANDARD','GENERAL',"
            "'deterministic-matcher-v1',1,%s,%s,'budget-v1','matching-v1',"
            "'reason-v1','explanation-v1',%s,'test-key',%s,1,%s,%s,%s,%s,%s,%s)",
            (
                RULE_ID,
                HASH,
                HASH,
                "73000000-0000-4000-8000-000000000001",
                HASH,
                "74000000-0000-4000-8000-000000000001",
                now - timedelta(days=1),
                now + timedelta(days=30),
                WORKLOAD_ID,
                MARKER,
                now,
                now,
            ),
        )
        connection.execute(
            "INSERT INTO matching.rule_selectors ("
            "selector_digest,current_bundle_id,aggregate_version,updated_at) "
            "VALUES (%s,%s,1,%s)",
            (HASH, RULE_ID, now),
        )
        connection.execute(
            "INSERT INTO matching.matching_attempts ("
            "id,organization_id,demand_id,demand_version_id,"
            "demand_content_sha256,demand_aggregate_version,matching_request_id,"
            "matching_request_version,funding_id,composite_rule_requirement_id,"
            "matching_rule_bundle_id,selector_digest,source_event_id,attempt_no,"
            "status,aggregate_version,current_match_run_id,selection_id,"
            "input_baseline_sha256,system_workload_id,"
            "system_authority_marker_sha256,created_at,updated_at,terminal_at) "
            "VALUES (%s,%s,%s,%s,%s,7,%s,3,%s,%s,%s,%s,%s,1,'OPEN',1,%s,NULL,"
            "%s,%s,%s,%s,%s,NULL)",
            (
                ATTEMPT_ID,
                ORGANIZATION_ID,
                DEMAND_ID,
                DEMAND_VERSION_ID,
                HASH,
                MATCHING_REQUEST_ID,
                FUNDING_ID,
                "75000000-0000-4000-8000-000000000001",
                RULE_ID,
                HASH,
                "76000000-0000-4000-8000-000000000001",
                RUN_ID,
                HASH,
                WORKLOAD_ID,
                MARKER,
                now,
                now,
            ),
        )
        connection.execute(
            "INSERT INTO matching.match_runs ("
            "id,organization_id,attempt_id,demand_id,run_no,status,"
            "aggregate_version,matching_rule_bundle_id,input_manifest_sha256,"
            "input_set_sha256,ordered_result_sha256,candidate_count,eligible_count,"
            "excluded_count,worker_id,lease_token_digest_key_id,"
            "lease_token_digest,fencing_generation,lease_until,supersedes_run_id,"
            "superseded_by_run_id,failure_code,created_at,updated_at) VALUES ("
            "%s,%s,%s,%s,1,'COMPLETED',3,%s,%s,%s,%s,1,1,0,NULL,NULL,NULL,1,"
            "NULL,NULL,NULL,NULL,%s,%s)",
            (
                RUN_ID,
                ORGANIZATION_ID,
                ATTEMPT_ID,
                DEMAND_ID,
                RULE_ID,
                HASH,
                HASH,
                OTHER_HASH,
                now,
                now,
            ),
        )
        connection.execute(
            "INSERT INTO matching.match_candidates ("
            "attempt_id,match_run_id,creator_user_id,profile_id,profile_version_id,"
            "profile_content_sha256,evidence_version_digest,eligibility,"
            "exclusion_reason_codes,component_scores,total_score,rank,"
            "evidence_facts,candidate_result_sha256,created_at) VALUES ("
            "%s,%s,%s,%s,%s,%s,%s,'ELIGIBLE',ARRAY[]::text[],"
            "'[{}, {}, {}, {}, {}, {}]'::jsonb,88.00,1,'[]'::jsonb,%s,%s)",
            (
                ATTEMPT_ID,
                RUN_ID,
                CREATOR_ID,
                PROFILE_ID,
                PROFILE_VERSION_ID,
                HASH,
                OTHER_HASH,
                HASH,
                now,
            ),
        )
        connection.execute(
            "INSERT INTO matching.invitations ("
            "id,organization_id,attempt_id,match_run_id,creator_user_id,profile_id,"
            "profile_version_id,profile_content_sha256,candidate_eligibility,"
            "demand_id,demand_version_id,funding_id,matching_rule_bundle_id,"
            "disclosure_snapshot_id,snapshot_sha256,"
            "creator_authority_marker_sha256,candidate_evidence_version_digest,"
            "status,aggregate_version,expires_at,"
            "created_by_user_id,created_at,sent_at,responded_at,updated_at) VALUES ("
            "%s,%s,%s,%s,%s,%s,%s,%s,'ELIGIBLE',%s,%s,%s,%s,%s,%s,NULL,%s,"
            "'SENT',2,%s,%s,%s,%s,NULL,%s)",
            (
                INVITATION_ID,
                ORGANIZATION_ID,
                ATTEMPT_ID,
                RUN_ID,
                CREATOR_ID,
                PROFILE_ID,
                PROFILE_VERSION_ID,
                HASH,
                DEMAND_ID,
                DEMAND_VERSION_ID,
                FUNDING_ID,
                RULE_ID,
                SNAPSHOT_ID,
                HASH,
                OTHER_HASH,
                now + timedelta(days=7),
                SELECTOR_ID,
                now,
                now,
                now,
            ),
        )
        connection.execute(
            "INSERT INTO matching.invitation_disclosure_snapshots ("
            "id,invitation_id,organization_id,attempt_id,demand_id,demand_version_id,"
            "profile_id,profile_version_id,schema_version,canonicalization_version,"
            "canonical_snapshot_bytes,snapshot,demand_content_sha256,"
            "profile_content_sha256,snapshot_sha256,created_at) VALUES ("
            "%s,%s,%s,%s,%s,%s,%s,%s,1,'invitation-disclosure-json-v1',"
            "%s,'{}'::jsonb,%s,%s,%s,%s)",
            (
                SNAPSHOT_ID,
                INVITATION_ID,
                ORGANIZATION_ID,
                ATTEMPT_ID,
                DEMAND_ID,
                DEMAND_VERSION_ID,
                PROFILE_ID,
                PROFILE_VERSION_ID,
                b"{}",
                HASH,
                HASH,
                HASH,
                now,
            ),
        )
        connection.execute(
            "INSERT INTO matching.selections ("
            "id,organization_id,attempt_id,match_run_id,status,aggregate_version,"
            "current_invitation_set_sha256,chosen_invitation_id,"
            "chosen_invitation_status,selection_basis_code,reason_code,"
            "decision_actor_id,coordinator_workload_id,"
            "coordinator_authority_marker_sha256,created_at,updated_at) VALUES ("
            "%s,%s,%s,%s,'OPEN',1,%s,NULL,NULL,NULL,NULL,NULL,%s,%s,%s,%s)",
            (
                SELECTION_ID,
                ORGANIZATION_ID,
                ATTEMPT_ID,
                RUN_ID,
                HASH,
                WORKLOAD_ID,
                MARKER,
                now,
                now,
            ),
        )
        connection.execute(
            "UPDATE matching.matching_attempts SET selection_id=%s WHERE id=%s",
            (SELECTION_ID, ATTEMPT_ID),
        )
        connection.execute(
            "INSERT INTO matching.candidate_selector_opt_in_receipts ("
            "id,command_id,actor_user_id,session_id,organization_id,selection_id,"
            "demand_id,role_code,authority_marker_sha256,iam_evidence_sha256,"
            "valid_until,recorded_at) VALUES ("
            "%s,%s,%s,%s,%s,%s,%s,'CANDIDATE_SELECTOR',%s,%s,%s,%s)",
            (
                SELECTOR_OPT_IN_RECEIPT_ID,
                SELECTOR_OPT_IN_COMMAND_ID,
                SELECTOR_ID,
                SELECTOR_SESSION_ID,
                ORGANIZATION_ID,
                SELECTION_ID,
                DEMAND_ID,
                cls.selector_marker,
                OTHER_HASH,
                now + timedelta(hours=1),
                now,
            ),
        )
        connection.execute(
            "INSERT INTO matching.candidate_selector_assignments ("
            "id,assignment_version,status,assignee_user_id,organization_id,"
            "demand_id,selection_id,authority_marker_sha256,assigned_at,"
            "expires_at,completed_at,assignee_session_id,opt_in_receipt_id) "
            "VALUES (%s,1,'ACTIVE',%s,%s,%s,%s,%s,%s,%s,NULL,%s,%s)",
            (
                SELECTOR_ASSIGNMENT_ID,
                SELECTOR_ID,
                ORGANIZATION_ID,
                DEMAND_ID,
                SELECTION_ID,
                cls.selector_marker,
                now,
                now + timedelta(hours=1),
                SELECTOR_SESSION_ID,
                SELECTOR_OPT_IN_RECEIPT_ID,
            ),
        )
        connection.execute(
            "INSERT INTO matching.match_jobs ("
            "id,organization_id,attempt_id,match_run_id,job_kind,status,"
            "workload_id,authority_marker_sha256,lease_token_digest_key_id,"
            "lease_token_digest,fencing_generation,available_at,lease_until,"
            "attempt_count,created_at,completed_at) VALUES ("
            "%s,%s,%s,%s,'RUN_MATCH','AVAILABLE',%s,%s,NULL,NULL,1,%s,NULL,0,%s,NULL)",
            (
                JOB_ID,
                ORGANIZATION_ID,
                ATTEMPT_ID,
                RUN_ID,
                WORKLOAD_ID,
                MARKER,
                now,
                now,
            ),
        )

    def test_runner_is_forward_only_and_schema_is_force_rls(self) -> None:
        self.assertEqual(self.first_report.applied_versions, (1, 2, 3))
        replay = self.runner.run(catalog=self.catalog, contract_sources=self.sources)
        self.assertEqual(replay.applied_versions, ())
        self.assertEqual(replay.skipped_versions, (1, 2, 3))
        with self._admin() as connection:
            compatibility = connection.execute(
                "SELECT component,current_schema_version,schema_head_version,"
                "required_iam_schema_version FROM matching.schema_compatibility"
            ).fetchone()
            self.assertEqual(compatibility, ("matching", 3, 3, 46))
            rls = tuple(
                connection.execute(
                    "SELECT relname,relrowsecurity,relforcerowsecurity "
                    "FROM pg_catalog.pg_class AS relation "
                    "JOIN pg_catalog.pg_namespace AS namespace "
                    "ON namespace.oid=relation.relnamespace "
                    "WHERE namespace.nspname='matching' AND relkind='r' "
                    "ORDER BY relname"
                ).fetchall()
            )
            self.assertGreaterEqual(len(rls), 16)
            self.assertTrue(all(row[1:] == (True, True) for row in rls))

    def test_runtime_dependency_snapshot_is_exact_and_least_privileged(self) -> None:
        expected = _expected_runtime_dependency_snapshot()
        self.assertEqual(len(expected), 33)
        runtime_types = (
            ("matching_worker", PsycopgMatchingWorkerRuntime),
            ("matching_coordinator", PsycopgMatchingCoordinatorRuntime),
        )
        for role, runtime_type in runtime_types:
            with psycopg.connect(
                self.postgres.conninfo(database=self.database, user=role)
            ) as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT * FROM "
                        "matching_api.read_runtime_dependency_snapshot_v1()"
                    ).fetchone(),
                    expected,
                )
            runtime_type(
                connections=_RuntimeConnections(
                    self.postgres.conninfo(database=self.database, user=role)
                )
            ).check_readiness(1_000)

        with self._admin() as connection:
            privileges = connection.execute(
                "SELECT "
                "has_function_privilege('matching_worker',"
                "'matching_api.read_runtime_dependency_snapshot_v1()',"
                "'EXECUTE'),"
                "has_function_privilege('matching_coordinator',"
                "'matching_api.read_runtime_dependency_snapshot_v1()',"
                "'EXECUTE'),"
                "has_function_privilege('matching_review',"
                "'matching_api.read_runtime_dependency_snapshot_v1()',"
                "'EXECUTE'),"
                "has_table_privilege('matching_schema_owner',"
                "'profile.schema_compatibility','SELECT'),"
                "has_column_privilege('matching_schema_owner',"
                "'profile.schema_compatibility','current_schema_version',"
                "'SELECT'),"
                "has_table_privilege('matching_schema_owner',"
                "'profile.schema_migrations','SELECT'),"
                "has_table_privilege('matching_schema_owner',"
                "'profile.schema_contracts','SELECT'),"
                "has_table_privilege('matching_worker',"
                "'profile.schema_compatibility','SELECT')"
            ).fetchone()
            function = connection.execute(
                "SELECT owner.rolname,procedure.prosecdef,procedure.provolatile,"
                "procedure.proparallel,procedure.proconfig,"
                "NOT has_function_privilege('public',procedure.oid,'EXECUTE') "
                "FROM pg_catalog.pg_proc AS procedure "
                "JOIN pg_catalog.pg_roles AS owner "
                "ON owner.oid=procedure.proowner "
                "WHERE procedure.oid="
                "'matching_api.read_runtime_dependency_snapshot_v1()'::"
                "regprocedure"
            ).fetchone()
            profile_options = connection.execute(
                "SELECT reloptions FROM pg_catalog.pg_class "
                "WHERE oid='profile.schema_compatibility'::regclass"
            ).fetchone()[0]
        self.assertEqual(
            privileges,
            (True, True, False, False, True, False, False, False),
        )
        self.assertEqual(
            function,
            (
                "matching_schema_owner",
                True,
                "s",
                "u",
                ["search_path=pg_catalog, matching"],
                True,
            ),
        )
        self.assertIn("security_invoker=false", profile_options)

    def test_iam46_creator_fixture_resolves_for_matching(self) -> None:
        with psycopg.connect(
            self.postgres.conninfo(
                database=self.database, user="matching_creator"
            )
        ) as connection:
            for key, value in (
                ("app.scope_kind", "MATCHING_CREATOR"),
                ("app.operation", "LIST_MATCHING_INVITATIONS"),
                ("app.actor_user_id", CREATOR_ID),
                ("app.session_id", str(IAM_CREATOR_SESSION_ID)),
                ("app.organization_id", ""),
                ("app.invitation_id", ""),
                ("app.command_id", ""),
            ):
                connection.execute("SELECT set_config(%s,%s,true)", (key, value))
            row = connection.execute(
                "SELECT * FROM iam_api."
                "resolve_matching_creator_authority_marker_v1("
                "%s,%s,'LIST_MATCHING_INVITATIONS',NULL,NULL)",
                (CREATOR_ID, IAM_CREATOR_SESSION_ID),
            ).fetchone()
        self.assertIsNotNone(row)
        assert row is not None
        self.assertEqual(bytes(row[4]), self.creator_marker)

    def test_worker_and_coordinator_readiness_reject_stale_trust_metadata(self) -> None:
        with self._admin() as connection:
            trust22 = connection.execute(
                "DELETE FROM trust_meta.schema_migrations "
                "WHERE component='trust' AND version=22 "
                "RETURNING component,version,phase,name,checksum_sha256,"
                "manifest_sha256,runner_version,applied_at"
            ).fetchone()
        self.assertIsNotNone(trust22)
        try:
            for runtime_type, role in (
                (PsycopgMatchingWorkerRuntime, "matching_worker"),
                (PsycopgMatchingCoordinatorRuntime, "matching_coordinator"),
            ):
                runtime = runtime_type(
                    connections=_RuntimeConnections(
                        self.postgres.conninfo(
                            database=self.database, user=role
                        )
                    )
                )
                with self.assertRaises(MatchingPostgresConfigurationError):
                    runtime.check_readiness(1_000)
        finally:
            assert trust22 is not None
            with self._admin() as connection:
                connection.execute(
                    "INSERT INTO trust_meta.schema_migrations ("
                    "component,version,phase,name,checksum_sha256,"
                    "manifest_sha256,runner_version,applied_at) VALUES ("
                    "%s,%s,%s,%s,%s,%s,%s,%s)",
                    trust22,
                )

    def test_expiry_after_trust_evaluation_returns_stable_lease_lost(self) -> None:
        now = datetime.now(timezone.utc)
        completion_job_id = self._id(9, 1)
        intent_receipt_id = self._id(9, 2)
        lease_digest = bytes.fromhex("91" * 32)
        with self._admin(autocommit=False) as connection:
            connection.execute(
                "INSERT INTO matching.command_receipts ("
                "id,principal_kind,principal_id,organization_id,operation,"
                "command_version,canonicalization_version,identity_key_id,"
                "identity_digest,payload_hash_key_id,payload_hash,"
                "principal_authority_marker_sha256,http_method,canonical_path,"
                "target_kind,target_id,parent_kind,parent_id,if_match_version,"
                "status,response_http_status,response_schema_name,"
                "response_schema_version,response_entity_tag,safe_response_body,"
                "target_version,result_status,event_types,retain_until,"
                "created_at,completed_at) VALUES ("
                "%s,'SYSTEM',%s,%s,'SELECTION_INTENT',1,"
                "'matching-command-json-v1','intent-identity-v1',%s,"
                "'intent-payload-v1',%s,%s,'POST','/v1/internal/intent',"
                "'Selection',%s,NULL,NULL,NULL,'IN_PROGRESS',NULL,NULL,NULL,"
                "NULL,NULL,NULL,NULL,NULL,%s,%s,NULL)",
                (
                    intent_receipt_id,
                    WORKLOAD_ID,
                    ORGANIZATION_ID,
                    HASH,
                    OTHER_HASH,
                    MARKER,
                    SELECTION_ID,
                    now + timedelta(days=1),
                    now,
                ),
            )
            connection.execute(
                "INSERT INTO matching.selection_completion_jobs ("
                "id,organization_id,selection_id,attempt_id,match_run_id,"
                "intent_receipt_id,intent_kind,status,workload_id,"
                "authority_marker_sha256,lease_digest_key_id,lease_digest,"
                "fencing_generation,available_at,lease_until,attempt_count,"
                "last_failure_code,created_at,completed_at) VALUES ("
                "%s,%s,%s,%s,%s,%s,'CHOOSE','LEASED',%s,%s,"
                "'coordinator-lease-v1',%s,1,%s,%s,1,NULL,%s,NULL)",
                (
                    completion_job_id,
                    ORGANIZATION_ID,
                    SELECTION_ID,
                    ATTEMPT_ID,
                    RUN_ID,
                    intent_receipt_id,
                    WORKLOAD_ID,
                    MARKER,
                    lease_digest,
                    now - timedelta(minutes=1),
                    now - timedelta(seconds=1),
                    now - timedelta(minutes=1),
                ),
            )

        command_id = self._id(9, 3)
        arguments = (
            UUID(WORKLOAD_ID),
            MARKER,
            completion_job_id,
            1,
            "coordinator-lease-v1",
            lease_digest,
            bytes.fromhex("92" * 32),
            now,
            now + timedelta(seconds=15),
            self._id(9, 4),
            command_id,
            "completion-identity-v1",
            bytes.fromhex("93" * 32),
            "completion-payload-v1",
            bytes.fromhex("94" * 32),
            self._id(9, 5),
            self._id(9, 6),
            self._id(9, 7),
            self._id(9, 8),
            self._id(9, 9),
            self._id(9, 10),
        )
        with psycopg.connect(
            self.postgres.conninfo(
                database=self.database, user="matching_coordinator"
            )
        ) as connection:
            for key, value in (
                ("app.scope_kind", "MATCHING_COORDINATOR"),
                ("app.operation", "COMPLETE_SELECTION"),
                ("app.workload_id", WORKLOAD_ID),
                ("app.organization_id", ORGANIZATION_ID),
                ("app.selection_id", SELECTION_ID),
                ("app.target_id", str(completion_job_id)),
                ("app.command_id", str(command_id)),
                ("app.authority_marker_sha256", MARKER.hex()),
                ("app.lease_token_digest_key_id", "coordinator-lease-v1"),
                ("app.lease_token_digest", lease_digest.hex()),
            ):
                connection.execute("SELECT set_config(%s,%s,true)", (key, value))
            with self.assertRaises(psycopg.errors.RaiseException) as caught:
                connection.execute(
                    "SELECT * FROM matching_api.complete_claimed_selection_v1("
                    + ",".join(("%s",) * len(arguments))
                    + ")",
                    arguments,
                )
        self.assertEqual(caught.exception.diag.message_primary, "LEASE_LOST")

    def test_exact_v2_to_v3_upgrade_and_replay(self) -> None:
        database = self.postgres.create_database()
        try:
            IamMigrationRunner(
                driver=PsycopgMigrationDriver(
                    settings=PsycopgMigrationSettings(
                        conninfo=self.postgres.conninfo(
                            database=database,
                            user="iam_migration_runner",
                        ),
                        application_name="matching-v2-v3-upgrade-iam",
                    ),
                    dbapi=psycopg,
                ),
                runner_version="matching-v2-v3-upgrade-iam/1",
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
            with self._admin(database, autocommit=False) as connection:
                now = datetime.now(timezone.utc)
                iam_authority = seed_exact_creator_iam_authority(
                    connection,
                    now=now,
                )
                _seed_exact_selector_iam_authority(
                    connection,
                    now=now,
                    source_invitation_id=iam_authority.creator_invitation_id,
                )
            selector_marker = self._load_selector_marker(database)
            old_manifest_sha256 = bytes.fromhex(
                "b74f864c477e913fde021159f1719cd510c167c0fe3f9a6163899e786b5d49e3"
            )
            self.assertEqual(
                self.catalog.artifacts[1].descriptor.prefix_manifest_sha256,
                old_manifest_sha256,
            )
            with psycopg.connect(
                self.postgres.conninfo(
                    database=database,
                    user="matching_migration_runner",
                ),
                autocommit=True,
            ) as connection:
                connection.execute("SET ROLE matching_schema_owner")
                for artifact in self.catalog.artifacts[:2]:
                    descriptor = artifact.descriptor
                    connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED")
                    connection.execute(artifact.sql_bytes.decode("utf-8"))
                    connection.execute(
                        "INSERT INTO matching_meta.schema_migrations ("
                        "component,version,phase,name,checksum_sha256,"
                        "manifest_sha256,runner_version,applied_at) VALUES ("
                        "'matching',%s,%s,%s,%s,%s,'historical-v2/1',"
                        "transaction_timestamp())",
                        (
                            descriptor.version,
                            descriptor.phase.value,
                            descriptor.name,
                            descriptor.checksum_sha256,
                            descriptor.prefix_manifest_sha256,
                        ),
                    )
                    connection.execute("COMMIT")
                contract_hash = hashlib.sha256(b"historical-v2-contract").digest()
                connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED")
                connection.execute(
                    "INSERT INTO matching_meta.schema_contracts ("
                    "singleton_key,schema_head_version,min_app_compatible_version,"
                    "max_app_compatible_version,required_iam_schema_version,"
                    "api_contract_sha256,event_contract_sha256,rule_contract_sha256,"
                    "input_manifest_contract_sha256,run_input_contract_sha256,"
                    "candidate_contract_sha256,disclosure_contract_sha256,"
                    "migration_manifest_sha256,generated_at) VALUES ("
                    "true,2,2,2,43,%s,%s,%s,%s,%s,%s,%s,%s,"
                    "transaction_timestamp())",
                    (
                        contract_hash,
                        contract_hash,
                        contract_hash,
                        contract_hash,
                        contract_hash,
                        contract_hash,
                        contract_hash,
                        old_manifest_sha256,
                    ),
                )
                connection.execute("COMMIT")

            with self._admin(database, autocommit=False) as connection:
                self._seed_v2_upgrade_graph(
                    connection,
                    selector_marker=selector_marker,
                )

            install_matching_runtime_dependencies(
                postgres=self.postgres,
                database=database,
                platform_root=PLATFORM_ROOT,
            )
            runner = MatchingMigrationRunner(
                driver=PsycopgMatchingMigrationDriver(
                    settings=MatchingMigrationSettings(
                        conninfo=self.postgres.conninfo(
                            database=database,
                            user="matching_migration_runner",
                        ),
                        application_name="matching-v2-v3-upgrade",
                    ),
                    dbapi=psycopg,
                ),
                runner_version="matching-v2-v3-upgrade/1",
            )
            upgraded = runner.run(
                catalog=self.catalog,
                contract_sources=self.sources,
            )
            self.assertEqual(upgraded.applied_versions, (3,))
            self.assertEqual(upgraded.skipped_versions, (1, 2))

            selector_runtime = PsycopgMatchingRuntime(
                creator_connections=_RuntimeConnections(
                    self.postgres.conninfo(
                        database=database,
                        user="matching_creator",
                    )
                ),
                selector_connections=_RuntimeConnections(
                    self.postgres.conninfo(
                        database=database,
                        user="matching_selector",
                    )
                ),
            )
            discovery = MatchingSelectorDiscoveryContext(
                actor_user_id=UUID(SELECTOR_ID),
                session_id=UUID(SELECTOR_SESSION_ID),
                organization_id=UUID(ORGANIZATION_ID),
                authority_marker_sha256=selector_marker,
            )
            self.assertEqual(
                selector_runtime.list_selector_attempts(
                    context=discovery,
                    demand_id=UUID(DEMAND_ID),
                    limit=25,
                ).items,
                (),
            )

            assignment_material = MatchingOperationalCommandMaterial(
                command_id=self._id(10, 1),
                receipt_id=self._id(10, 2),
                identity_key_id="matching-idempotency-v1",
                identity_digest=hashlib.sha256(
                    b"v2-v3-selector-identity"
                ).digest(),
                payload_hash_key_id="matching-payload-v1",
                payload_hash=hashlib.sha256(
                    b"v2-v3-selector-payload"
                ).digest(),
                audit_event_id=self._id(10, 3),
                outbox_event_ids=(self._id(10, 4),),
                correlation_id=self._id(10, 5),
                trace_id=self._id(10, 6),
            )
            assignment_runtime = PsycopgMatchingAssignmentRuntime(
                connections=_RuntimeConnections(
                    self.postgres.conninfo(
                        database=database,
                        user="matching_assignment",
                    )
                )
            )
            assignment_request = MatchingCandidateSelectorClaimRequest(
                context=MatchingAssignmentContext(
                    actor_user_id=UUID(SELECTOR_ID),
                    session_id=UUID(SELECTOR_SESSION_ID),
                    organization_id=UUID(ORGANIZATION_ID),
                    principal_marker_sha256=selector_marker,
                ),
                demand_id=UUID(DEMAND_ID),
                assignment_id=UUID(
                    "70000000-0000-4000-8000-000000000002"
                ),
                material=assignment_material,
            )
            claimed = assignment_runtime.claim_candidate_selector(
                assignment_request
            )
            claimed_replay = assignment_runtime.claim_candidate_selector(
                assignment_request
            )
            self.assertEqual(claimed.status, "ACTIVE")
            self.assertFalse(claimed.replayed)
            self.assertTrue(claimed_replay.replayed)
            self.assertEqual(
                tuple(
                    item.attempt_id
                    for item in selector_runtime.list_selector_attempts(
                        context=discovery,
                        demand_id=UUID(DEMAND_ID),
                        limit=25,
                    ).items
                ),
                (UUID(ATTEMPT_ID),),
            )

            rule = load_default_rule_release_v1()
            publication_material = MatchingOperationalCommandMaterial(
                command_id=self._id(11, 1),
                receipt_id=self._id(11, 2),
                identity_key_id="matching-idempotency-v1",
                identity_digest=hashlib.sha256(
                    b"v2-v3-rule-identity"
                ).digest(),
                payload_hash_key_id="matching-payload-v1",
                payload_hash=hashlib.sha256(
                    b"v2-v3-rule-payload"
                ).digest(),
                audit_event_id=self._id(11, 3),
                outbox_event_ids=(self._id(11, 4),),
                correlation_id=self._id(11, 5),
                trace_id=self._id(11, 6),
            )
            worker_runtime = PsycopgMatchingWorkerRuntime(
                connections=_RuntimeConnections(
                    self.postgres.conninfo(
                        database=database,
                        user="matching_worker",
                    )
                )
            )
            publication_request = MatchingRulePublicationRequest(
                context=MatchingWorkloadContext(
                    workload_id=UUID(WORKLOAD_ID),
                    authority_marker_sha256=MARKER,
                ),
                organization_id=UUID(ORGANIZATION_ID),
                rule=rule,
                signature_key_id="matching-rule-review-v1",
                review_approval_id=UUID(
                    "9eabf3d2-614c-5d47-99c2-d752d62bfd76"
                ),
                review_approval_version=1,
                material=publication_material,
            )
            with self._admin(database, autocommit=False) as connection:
                connection.execute(
                    "UPDATE matching.rule_bundles SET "
                    "published_authority_marker_sha256=%s WHERE id=%s",
                    (OTHER_MARKER, rule.bundle_id),
                )
            with psycopg.connect(
                self.postgres.conninfo(database=database, user="matching_worker")
            ) as connection:
                for key, value in (
                    ("app.scope_kind", "MATCHING_WORKER"),
                    ("app.operation", "PUBLISH_MATCHING_RULE"),
                    ("app.workload_id", WORKLOAD_ID),
                    ("app.organization_id", ORGANIZATION_ID),
                    ("app.authority_marker_sha256", MARKER.hex()),
                    ("app.command_id", str(publication_material.command_id)),
                ):
                    connection.execute(
                        "SELECT set_config(%s,%s,true)",
                        (key, value),
                    )
                with self.assertRaises(psycopg.errors.RaiseException) as caught:
                    connection.execute(
                        "SELECT * FROM matching_api.publish_rule_bundle_v1("
                        + ",".join(("%s",) * 19)
                        + ")",
                        (
                            WORKLOAD_ID,
                            ORGANIZATION_ID,
                            MARKER,
                            rule.canonical_manifest_bytes,
                            psycopg.types.json.Jsonb(
                                json.loads(rule.canonical_manifest_bytes)
                            ),
                            bytes.fromhex(rule.canonical_manifest_sha256),
                            "matching-rule-review-v1",
                            "9eabf3d2-614c-5d47-99c2-d752d62bfd76",
                            1,
                            publication_material.receipt_id,
                            publication_material.command_id,
                            publication_material.identity_key_id,
                            publication_material.identity_digest,
                            publication_material.payload_hash_key_id,
                            publication_material.payload_hash,
                            publication_material.audit_event_id,
                            publication_material.outbox_event_ids[0],
                            publication_material.correlation_id,
                            publication_material.trace_id,
                        ),
                    )
            self.assertEqual(
                caught.exception.diag.message_primary,
                "MATCH_RULE_BUNDLE_CHANGED",
            )
            with self._admin(database, autocommit=False) as connection:
                connection.execute(
                    "UPDATE matching.rule_bundles SET "
                    "published_authority_marker_sha256=%s WHERE id=%s",
                    (MARKER, rule.bundle_id),
                )
            published = worker_runtime.publish_rule_bundle(publication_request)
            published_replay = worker_runtime.publish_rule_bundle(
                publication_request
            )
            self.assertEqual(published.rule_bundle_id, UUID(rule.bundle_id))
            self.assertFalse(published.replayed)
            self.assertTrue(published_replay.replayed)

            replayed = runner.run(
                catalog=self.catalog,
                contract_sources=self.sources,
            )
            self.assertEqual(replayed.applied_versions, ())
            self.assertEqual(replayed.skipped_versions, (1, 2, 3))
            with self._admin(database) as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT current_schema_version,schema_head_version,"
                        "required_iam_schema_version,migration_manifest_sha256 "
                        "FROM matching.schema_compatibility"
                    ).fetchone(),
                    (3, 3, 46, self.catalog.manifest_sha256),
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT status,assignment_version,completed_at IS NOT NULL,"
                        "assignee_session_id,opt_in_receipt_id FROM "
                        "matching.candidate_selector_assignments WHERE id=%s",
                        (SELECTOR_ASSIGNMENT_ID,),
                    ).fetchone(),
                    ("REVOKED", 2, True, None, None),
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT status,aggregate_version,completed_at IS NOT NULL,"
                        "reviewer_session_id,claim_receipt_id FROM "
                        "matching.matching_review_assignments WHERE id=%s",
                        ("83000000-0000-4000-8000-000000000001",),
                    ).fetchone(),
                    ("REVOKED", 2, True, None, None),
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT count(*),canonical_manifest_bytes,manifest,"
                        "invitation_limit FROM matching.rule_bundles WHERE id=%s "
                        "GROUP BY canonical_manifest_bytes,manifest,invitation_limit",
                        (rule.bundle_id,),
                    ).fetchone(),
                    (
                        1,
                        rule.canonical_manifest_bytes,
                        json.loads(rule.canonical_manifest_bytes),
                        rule.invitation_limit,
                    ),
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT safe_attributes->>'legacy_v2_release_backfilled' "
                        "FROM audit.audit_events WHERE event_id=%s",
                        (publication_material.audit_event_id,),
                    ).fetchone(),
                    ("true",),
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT bool_and(relation.relrowsecurity),"
                        "bool_and(relation.relforcerowsecurity) FROM "
                        "pg_catalog.pg_class AS relation JOIN "
                        "pg_catalog.pg_namespace AS namespace ON "
                        "namespace.oid=relation.relnamespace WHERE "
                        "namespace.nspname='matching' AND relation.relname IN ("
                        "'candidate_selector_assignments',"
                        "'matching_review_assignments')"
                    ).fetchone(),
                    (True, True),
                )
        finally:
            self.postgres.drop_database(database)

    def test_core_unique_check_and_composite_foreign_keys_reject_drift(self) -> None:
        with self._admin(autocommit=False) as connection:
            with self.assertRaises(psycopg.errors.CheckViolation):
                connection.execute(
                    "INSERT INTO matching.match_candidates ("
                    "attempt_id,match_run_id,creator_user_id,profile_id,"
                    "profile_version_id,profile_content_sha256,"
                    "evidence_version_digest,eligibility,exclusion_reason_codes,"
                    "component_scores,total_score,rank,evidence_facts,"
                    "candidate_result_sha256,created_at) VALUES ("
                    "%s,%s,%s,%s,%s,%s,%s,'EXCLUDED',ARRAY[]::text[],"
                    "'[]'::jsonb,NULL,NULL,'[]'::jsonb,%s,transaction_timestamp())",
                    (
                        ATTEMPT_ID,
                        RUN_ID,
                        "69000000-0000-4000-8000-000000000002",
                        "6a000000-0000-4000-8000-000000000002",
                        "6b000000-0000-4000-8000-000000000002",
                        HASH,
                        HASH,
                        HASH,
                    ),
                )
            connection.rollback()

        with self._admin(autocommit=False) as connection:
            with self.assertRaises(psycopg.errors.UniqueViolation):
                connection.execute(
                    "INSERT INTO matching.match_candidates ("
                    "attempt_id,match_run_id,creator_user_id,profile_id,"
                    "profile_version_id,profile_content_sha256,"
                    "evidence_version_digest,eligibility,exclusion_reason_codes,"
                    "component_scores,total_score,rank,evidence_facts,"
                    "candidate_result_sha256,created_at) VALUES ("
                    "%s,%s,%s,%s,%s,%s,%s,'ELIGIBLE',ARRAY[]::text[],"
                    "'[{}, {}, {}, {}, {}, {}]'::jsonb,77.00,1,'[]'::jsonb,%s,"
                    "transaction_timestamp())",
                    (
                        ATTEMPT_ID,
                        RUN_ID,
                        "69000000-0000-4000-8000-000000000002",
                        "6a000000-0000-4000-8000-000000000002",
                        "6b000000-0000-4000-8000-000000000002",
                        HASH,
                        HASH,
                        HASH,
                    ),
                )
            connection.rollback()

        with self._admin(autocommit=False) as connection:
            with self.assertRaises(psycopg.errors.ForeignKeyViolation):
                connection.execute(
                    "INSERT INTO matching.invitations ("
                    "id,organization_id,attempt_id,match_run_id,creator_user_id,"
                    "profile_id,profile_version_id,profile_content_sha256,"
                    "candidate_eligibility,demand_id,demand_version_id,funding_id,"
                    "matching_rule_bundle_id,disclosure_snapshot_id,snapshot_sha256,"
                    "creator_authority_marker_sha256,status,aggregate_version,"
                    "expires_at,created_by_user_id,created_at,sent_at,responded_at,"
                    "updated_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'ELIGIBLE',"
                    "%s,%s,%s,%s,%s,%s,%s,'CREATED',1,"
                    "transaction_timestamp()+interval '1 day',%s,"
                    "transaction_timestamp(),NULL,NULL,transaction_timestamp())",
                    (
                        "6c000000-0000-4000-8000-000000000002",
                        ORGANIZATION_ID,
                        ATTEMPT_ID,
                        RUN_ID,
                        "69000000-0000-4000-8000-000000000099",
                        PROFILE_ID,
                        PROFILE_VERSION_ID,
                        HASH,
                        DEMAND_ID,
                        DEMAND_VERSION_ID,
                        FUNDING_ID,
                        RULE_ID,
                        "6d000000-0000-4000-8000-000000000002",
                        HASH,
                        MARKER,
                        SELECTOR_ID,
                    ),
                )
            connection.rollback()

    def test_candidate_selector_requires_exact_active_unexpired_assignment(self) -> None:
        conninfo = self.postgres.conninfo(
            database=self.database,
            user="matching_selector",
        )
        with psycopg.connect(conninfo, autocommit=False) as connection:
            self.assertFalse(
                connection.execute(
                    "SELECT has_table_privilege(current_user,"
                    "'matching.selections','SELECT')"
                ).fetchone()[0]
            )
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    "SELECT count(*) FROM matching.selections"
                ).fetchone()

    def test_worker_requires_exact_live_job_lease_not_forged_gucs(self) -> None:
        conninfo = self.postgres.conninfo(
            database=self.database,
            user="matching_worker",
        )
        with psycopg.connect(conninfo, autocommit=False) as connection:
            self.assertFalse(
                connection.execute(
                    "SELECT has_table_privilege(current_user,"
                    "'matching.match_jobs','SELECT')"
                ).fetchone()[0]
            )
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    "SELECT count(*) FROM matching.match_jobs"
                ).fetchone()

    def test_candidate_selector_cannot_read_restricted_response_facts(self) -> None:
        conninfo = self.postgres.conninfo(
            database=self.database,
            user="matching_selector",
        )
        with psycopg.connect(conninfo, autocommit=False) as connection:
            privileges = connection.execute(
                "SELECT has_table_privilege(current_user,"
                "'matching.invitation_responses','SELECT'),"
                "has_table_privilege(current_user,"
                "'matching.invitation_withdrawals','SELECT')"
            ).fetchone()
            self.assertEqual(privileges, (False, False))
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    "SELECT restricted_note FROM matching.invitation_responses"
                ).fetchall()
            connection.rollback()
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    "SELECT restricted_note FROM matching.invitation_withdrawals"
                ).fetchall()

    def test_response_selection_and_withdrawal_are_single_exact_facts(self) -> None:
        now = datetime.now(timezone.utc)
        with self._admin(autocommit=False) as connection:
            connection.execute(
                "INSERT INTO matching.invitation_responses ("
                "id,invitation_id,creator_user_id,response_kind,snapshot_sha256,"
                "reason_code,restricted_note,responded_at) VALUES ("
                "%s,%s,%s,'ACCEPTED',%s,NULL,NULL,%s)",
                (
                    "77000000-0000-4000-8000-000000000001",
                    INVITATION_ID,
                    CREATOR_ID,
                    HASH,
                    now,
                ),
            )
            with self.assertRaises(psycopg.errors.UniqueViolation):
                connection.execute(
                    "INSERT INTO matching.invitation_responses ("
                    "id,invitation_id,creator_user_id,response_kind,snapshot_sha256,"
                    "reason_code,restricted_note,responded_at) VALUES ("
                    "%s,%s,%s,'ACCEPTED',%s,NULL,NULL,%s)",
                    (
                        "77000000-0000-4000-8000-000000000002",
                        INVITATION_ID,
                        CREATOR_ID,
                        HASH,
                        now,
                    ),
                )
            connection.rollback()

        with self._admin(autocommit=False) as connection:
            connection.execute(
                "UPDATE matching.selections SET status='SELECTED',"
                "aggregate_version=2,chosen_invitation_id=%s,"
                "chosen_invitation_status='ACCEPTED',"
                "selection_basis_code='FIT',decision_actor_id=%s,updated_at=%s "
                "WHERE id=%s",
                (INVITATION_ID, SELECTOR_ID, now, SELECTION_ID),
            )
            with self.assertRaises(psycopg.errors.ForeignKeyViolation):
                connection.execute("SET CONSTRAINTS ALL IMMEDIATE")
            connection.rollback()

        with self._admin(autocommit=False) as connection:
            connection.execute(
                "UPDATE matching.invitations SET status='WITHDRAWN',"
                "aggregate_version=3,responded_at=%s,updated_at=%s WHERE id=%s",
                (now, now, INVITATION_ID),
            )
            connection.execute(
                "INSERT INTO matching.invitation_withdrawals ("
                "id,invitation_id,creator_user_id,snapshot_sha256,reason_code,"
                "restricted_note,withdrawn_at) VALUES (%s,%s,%s,%s,'NO_LONGER_AVAILABLE',"
                "NULL,%s)",
                (
                    "78000000-0000-4000-8000-000000000001",
                    INVITATION_ID,
                    CREATOR_ID,
                    HASH,
                    now,
                ),
            )
        with self._admin(autocommit=False) as connection:
            with self.assertRaises(psycopg.errors.CheckViolation):
                connection.execute(
                    "UPDATE matching.invitation_withdrawals "
                    "SET reason_code='CHANGED' WHERE invitation_id=%s",
                    (INVITATION_ID,),
                )

    def test_runtime_reads_and_creator_accept_are_atomic_and_replay_safe(self) -> None:
        runtime = self._runtime()
        runtime.check_readiness(1_000)
        creator = self._creator_context()
        page = runtime.list_creator_invitations(context=creator, limit=25)
        self.assertEqual(tuple(item.invitation_id for item in page.items), (UUID(INVITATION_ID),))
        self.assertEqual(page.items[0].entity_tag, '"v2"')
        self.assertIsNotNone(
            runtime.read_creator_invitation(
                context=creator, invitation_id=UUID(INVITATION_ID)
            )
        )

        request = self._creator_request(
            operation=CreatorInvitationOperation.ACCEPT,
            ordinal=1,
        )
        result = runtime.accept_invitation(request)
        replay = runtime.accept_invitation(request)
        self.assertEqual(result.invitation.status, "ACCEPTED")
        self.assertEqual(result.invitation.aggregate_version, 3)
        self.assertFalse(result.replayed)
        self.assertEqual(replay, type(replay)(result.invitation, True))

        with self._admin() as connection:
            invitation = connection.execute(
                "SELECT status,aggregate_version FROM matching.invitations WHERE id=%s",
                (INVITATION_ID,),
            ).fetchone()
            selection = connection.execute(
                "SELECT aggregate_version,current_invitation_set_sha256 "
                "FROM matching.selections WHERE id=%s",
                (SELECTION_ID,),
            ).fetchone()
            counts = connection.execute(
                "SELECT (SELECT count(*) FROM matching.invitation_responses),"
                "(SELECT count(*) FROM matching.command_receipts WHERE id=%s),"
                "(SELECT count(*) FROM audit.audit_events WHERE event_id=%s),"
                "(SELECT count(*) FROM infra.outbox_events WHERE causation_id=%s)",
                (
                    str(request.material.receipt_id),
                    str(request.material.audit_event_id),
                    str(request.command.command_id),
                ),
            ).fetchone()
        self.assertEqual(invitation, ("ACCEPTED", 3))
        self.assertEqual(selection[0], 2)
        self.assertNotEqual(selection[1], HASH)
        self.assertEqual(counts, (1, 1, 1, 2))

    def test_runtime_selector_reads_and_choose_records_frozen_intent(self) -> None:
        runtime = self._runtime()
        accepted = runtime.accept_invitation(
            self._creator_request(
                operation=CreatorInvitationOperation.ACCEPT,
                ordinal=2,
            )
        )
        self.assertEqual(accepted.invitation.status, "ACCEPTED")
        selector = self._selector_context()
        attempts = runtime.list_selector_attempts(
            context=self._selector_discovery_context(),
            demand_id=UUID(DEMAND_ID),
            limit=25,
        )
        self.assertEqual(tuple(item.attempt_id for item in attempts.items), (UUID(ATTEMPT_ID),))
        wrong_authority = MatchingSelectorDiscoveryContext(
            actor_user_id=UUID(SELECTOR_ID),
            session_id=UUID("82000000-0000-4000-8000-000000000001"),
            organization_id=UUID(ORGANIZATION_ID),
            authority_marker_sha256=OTHER_MARKER,
        )
        self.assertEqual(
            runtime.list_selector_attempts(
                context=wrong_authority,
                demand_id=UUID(DEMAND_ID),
                limit=25,
            ).items,
            (),
        )
        self.assertIsNone(
            runtime.read_selection_by_attempt(
                context=wrong_authority,
                attempt_id=UUID(ATTEMPT_ID),
            )
        )
        discovered = runtime.read_selection_by_attempt(
            context=self._selector_discovery_context(),
            attempt_id=UUID(ATTEMPT_ID),
        )
        self.assertIsNotNone(discovered)
        assert discovered is not None
        self.assertEqual(
            discovered.candidate_selector_assignment_id,
            UUID(SELECTOR_ASSIGNMENT_ID),
        )
        selection = runtime.read_selection(context=selector)
        self.assertIsNotNone(selection)
        assert selection is not None
        self.assertEqual(len(selection.accepted_invitations), 1)

        request = self._selector_request(
            operation=CandidateSelectionOperation.CHOOSE,
            selection_version=selection.aggregate_version,
            invitation_set_sha256=bytes.fromhex(
                selection.current_invitation_set_sha256
            ),
            ordinal=3,
        )
        result = runtime.choose_creator(request)
        replay = runtime.choose_creator(request)
        self.assertEqual(result.selection.status, "PENDING_CHOICE")
        self.assertEqual(replay.selection.status, "PENDING_CHOICE")
        self.assertEqual(
            result.selection.aggregate_version,
            selection.aggregate_version + 1,
        )
        self.assertFalse(result.replayed)
        self.assertTrue(replay.replayed)
        post_choose = runtime.read_selection_by_id(
            context=self._selector_discovery_context(),
            selection_id=UUID(SELECTION_ID),
        )
        self.assertIsNotNone(post_choose)
        assert post_choose is not None
        self.assertEqual(post_choose.status, "PENDING_CHOICE")
        self.assertEqual(post_choose.candidate_selector_assignment_version, 1)
        with self._admin() as connection:
            intent = connection.execute(
                "SELECT status,selection_id,invitation_id,"
                "candidate_selector_assignment_id,"
                "candidate_selector_assignment_version,input_set_sha256,"
                "ordered_result_sha256,candidate_result_sha256 "
                "FROM matching.selection_intents"
            ).fetchone()
            outbox = connection.execute(
                "SELECT event_type FROM infra.outbox_events "
                "WHERE causation_id=%s",
                (str(request.command.command_id),),
            ).fetchall()
            durable_status = connection.execute(
                "SELECT status FROM matching.selections WHERE id=%s",
                (SELECTION_ID,),
            ).fetchone()
        self.assertEqual(intent[:5], (
            "READY", UUID(SELECTION_ID), UUID(INVITATION_ID),
            UUID(SELECTOR_ASSIGNMENT_ID), 1,
        ))
        self.assertTrue(all(len(value) == 32 for value in intent[5:]))
        self.assertEqual(durable_status, ("OPEN",))
        self.assertEqual(outbox, [("SelectionIntentRecorded",)])

    def test_runtime_creator_can_withdraw_before_selection_intent(self) -> None:
        runtime = self._runtime()
        runtime.accept_invitation(
            self._creator_request(
                operation=CreatorInvitationOperation.ACCEPT,
                ordinal=6,
            )
        )
        request = self._creator_request(
            operation=CreatorInvitationOperation.WITHDRAW,
            ordinal=7,
            expected_version=3,
        )
        result = runtime.withdraw_invitation(request)
        replay = runtime.withdraw_invitation(request)
        self.assertEqual(result.invitation.status, "WITHDRAWN")
        self.assertEqual(result.invitation.aggregate_version, 4)
        self.assertTrue(replay.replayed)
        selector_view = runtime.read_selection(context=self._selector_context())
        assert selector_view is not None
        self.assertEqual(selector_view.aggregate_version, 3)
        self.assertEqual(selector_view.accepted_invitations, ())
        with self._admin() as connection:
            facts = connection.execute(
                "SELECT (SELECT count(*) FROM matching.invitation_responses "
                "WHERE invitation_id=%s),"
                "(SELECT count(*) FROM matching.invitation_withdrawals "
                "WHERE invitation_id=%s),"
                "(SELECT count(*) FROM infra.outbox_events "
                "WHERE causation_id=%s)",
                (INVITATION_ID, INVITATION_ID, str(request.command.command_id)),
            ).fetchone()
        self.assertEqual(facts, (1, 1, 2))

    def test_runtime_close_records_durable_intent_before_coordinator(self) -> None:
        runtime = self._runtime()
        runtime.decline_invitation(
            self._creator_request(
                operation=CreatorInvitationOperation.DECLINE,
                ordinal=4,
            )
        )
        selector = self._selector_context()
        selection = runtime.read_selection(context=selector)
        assert selection is not None
        request = self._selector_request(
            operation=CandidateSelectionOperation.CLOSE,
            selection_version=selection.aggregate_version,
            invitation_set_sha256=bytes.fromhex(
                selection.current_invitation_set_sha256
            ),
            ordinal=5,
        )
        result = runtime.close_selection(request)
        replay = runtime.close_selection(request)
        self.assertEqual(result.selection.status, "PENDING_CLOSE")
        self.assertEqual(replay.selection.status, "PENDING_CLOSE")
        self.assertEqual(
            result.selection.aggregate_version,
            selection.aggregate_version + 1,
        )
        self.assertEqual(result.selection.candidate_selector_assignment_version, 1)
        self.assertTrue(replay.replayed)
        post_close = runtime.read_selection_by_id(
            context=self._selector_discovery_context(),
            selection_id=UUID(SELECTION_ID),
        )
        self.assertIsNotNone(post_close)
        assert post_close is not None
        self.assertEqual(post_close.status, "PENDING_CLOSE")
        self.assertEqual(post_close.candidate_selector_assignment_version, 1)
        with self._admin() as connection:
            terminal = connection.execute(
                "SELECT selection.status,attempt.status,assignment.status,"
                "assignment.assignment_version,attempt.terminal_at IS NOT NULL "
                "FROM matching.selections AS selection "
                "JOIN matching.matching_attempts AS attempt "
                "ON attempt.id=selection.attempt_id "
                "JOIN matching.candidate_selector_assignments AS assignment "
                "ON assignment.selection_id=selection.id "
                "WHERE selection.id=%s",
                (SELECTION_ID,),
            ).fetchone()
            events = tuple(
                row[0]
                for row in connection.execute(
                    "SELECT event_type FROM infra.outbox_events "
                    "WHERE causation_id=%s ORDER BY event_type",
                    (str(request.command.command_id),),
                ).fetchall()
            )
            durable_intent = connection.execute(
                "SELECT close_intent.status,job.status,job.intent_kind "
                "FROM matching.selection_close_intents AS close_intent "
                "JOIN matching.selection_completion_jobs AS job "
                "ON job.intent_receipt_id=close_intent.receipt_id "
                "WHERE close_intent.selection_id=%s",
                (SELECTION_ID,),
            ).fetchone()
        self.assertEqual(
            terminal,
            ("OPEN", "OPEN", "ACTIVE", 1, False),
        )
        self.assertEqual(durable_intent, ("READY", "AVAILABLE", "CLOSE"))
        self.assertEqual(events, ("SelectionCloseIntentRecorded",))

    def _runtime(self) -> PsycopgMatchingRuntime:
        return PsycopgMatchingRuntime(
            creator_connections=_RuntimeConnections(
                self.postgres.conninfo(
                    database=self.database, user="matching_creator"
                )
            ),
            selector_connections=_RuntimeConnections(
                self.postgres.conninfo(
                    database=self.database, user="matching_selector"
                )
            ),
        )

    @classmethod
    def _creator_context(cls) -> MatchingCreatorContext:
        return MatchingCreatorContext(
            actor_user_id=UUID(CREATOR_ID),
            session_id=IAM_CREATOR_SESSION_ID,
            authority_marker_sha256=cls.creator_marker,
        )

    @classmethod
    def _selector_context(cls) -> MatchingSelectorContext:
        return MatchingSelectorContext(
            actor_user_id=UUID(SELECTOR_ID),
            session_id=UUID(SELECTOR_SESSION_ID),
            organization_id=UUID(ORGANIZATION_ID),
            selection_id=UUID(SELECTION_ID),
            assignment_id=UUID(SELECTOR_ASSIGNMENT_ID),
            assignment_version=1,
            authority_marker_sha256=cls.selector_marker,
        )

    @classmethod
    def _selector_discovery_context(cls) -> MatchingSelectorDiscoveryContext:
        return MatchingSelectorDiscoveryContext(
            actor_user_id=UUID(SELECTOR_ID),
            session_id=UUID(SELECTOR_SESSION_ID),
            organization_id=UUID(ORGANIZATION_ID),
            authority_marker_sha256=cls.selector_marker,
        )

    def _creator_request(
        self,
        *,
        operation: CreatorInvitationOperation,
        ordinal: int,
        expected_version: int = 2,
    ) -> CreatorInvitationMutation:
        return CreatorInvitationMutation(
            operation=operation,
            creator=self._creator_context(),
            command=MatchingCommandContext(
                command_id=self._id(ordinal, 1),
                correlation_id=self._id(ordinal, 2),
                trace_id=self._id(ordinal, 3),
            ),
            organization_id=UUID(ORGANIZATION_ID),
            invitation_id=UUID(INVITATION_ID),
            expected_invitation_version=expected_version,
            expected_snapshot_sha256=HASH,
            reason_code=(
                None
                if operation is CreatorInvitationOperation.ACCEPT
                else "NOT_AVAILABLE"
            ),
            restricted_note=None,
            material=MatchingWriteMaterial(
                receipt_id=self._id(ordinal, 4),
                fact_id=self._id(ordinal, 5),
                audit_event_id=self._id(ordinal, 6),
                primary_outbox_event_id=self._id(ordinal, 7),
                secondary_outbox_event_id=self._id(ordinal, 8),
                identity_key_id="matching-idempotency-v1",
                identity_digest=bytes([ordinal]) * 32,
                payload_hash_key_id="matching-payload-v1",
                payload_hash=bytes([ordinal + 32]) * 32,
            ),
        )

    def _selector_request(
        self,
        *,
        operation: CandidateSelectionOperation,
        selection_version: int,
        invitation_set_sha256: bytes,
        ordinal: int,
    ) -> CandidateSelectionMutation:
        choose = operation is CandidateSelectionOperation.CHOOSE
        return CandidateSelectionMutation(
            operation=operation,
            selector=self._selector_context(),
            command=MatchingCommandContext(
                command_id=self._id(ordinal, 1),
                correlation_id=self._id(ordinal, 2),
                trace_id=self._id(ordinal, 3),
            ),
            expected_selection_version=selection_version,
            expected_invitation_set_sha256=invitation_set_sha256,
            invitation_id=UUID(INVITATION_ID) if choose else None,
            selection_basis_code="CAPABILITY_FIT" if choose else None,
            reason_code=None if choose else "NO_AVAILABLE_CREATOR",
            material=MatchingWriteMaterial(
                receipt_id=self._id(ordinal, 4),
                fact_id=self._id(ordinal, 5) if choose else None,
                audit_event_id=self._id(ordinal, 6),
                primary_outbox_event_id=self._id(ordinal, 7),
                secondary_outbox_event_id=(
                    None if choose else self._id(ordinal, 8)
                ),
                identity_key_id="matching-idempotency-v1",
                identity_digest=bytes([ordinal]) * 32,
                payload_hash_key_id="matching-payload-v1",
                payload_hash=bytes([ordinal + 32]) * 32,
            ),
        )

    @staticmethod
    def _id(ordinal: int, suffix: int) -> UUID:
        return UUID(f"9{ordinal:x}{suffix:x}00000-0000-4000-8000-000000000001")


if __name__ == "__main__":
    unittest.main()
