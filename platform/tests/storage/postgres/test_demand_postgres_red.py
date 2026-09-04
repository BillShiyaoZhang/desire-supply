"""Real PostgreSQL 18 semantic RED for Demand fixed UoWs and RLS.

The IAM dependency catalog is loaded dynamically and migrated on a real
server before the default-deny Demand seam is called.  Only the exact reviewed
Demand behavior sentinel becomes an observation; migration, driver, fixture,
SQL, ImportError, and programming defects remain test errors.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, dataclass, fields, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Mapping, Optional
import unittest

import psycopg

from desire_platform.demand.adapters.postgres import (
    DEMAND_POSTGRES_BEHAVIOR_NOT_AVAILABLE,
    DEMAND_POSTGRES_STATEMENT_PROFILES,
    DEMAND_POSTGRES_SUBMIT_WRITE_CHECKPOINTS,
    DEMAND_POSTGRES_WRITE_CHECKPOINTS,
    DemandPostgresBehaviorNotAvailable,
    DemandPostgresCommitOutcomeUnknownError,
    DemandPostgresConfigurationError,
    DemandPostgresDatabaseError,
    DemandPostgresMatchCaptureResult,
    DemandPostgresMatchInputSnapshot,
    DemandPostgresOperation,
    DemandPostgresSettings,
    DemandPostgresWriteCheckpoint,
    PsycopgDemandMatchingRepository,
    PsycopgDemandUnitOfWorkFactory,
)
from desire_platform.identity_access.adapters.postgres.migrations import (
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from desire_platform.internal_pilot.editor import (
    DemandCompletedReleaseReplayError,
    DemandCompletedReleaseReplayProbeRequest,
    EditorServiceError,
    PsycopgDemandCompletedVerifyReceiptProbe,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18
from tests.support.demand_postgres_builders import (
    ACTOR_USER_ID,
    ASSIGNMENT_ID,
    DEMAND_ID,
    DEMAND_VERSION_ID,
    MATCHING_REQUEST_ID,
    ORGANIZATION_ID,
    OTHER_DEMAND_ID,
    OTHER_ORGANIZATION_ID,
    RAW_IDEMPOTENCY_SENTINEL,
    RAW_SECRET_SENTINELS,
    REVIEWER_SESSION_ID,
    REVIEWER_USER_ID,
    SUBMISSION_ID,
    UTC_NOW,
    InjectedDemandPostgresWriteFailure,
    RaiseAtDemandCheckpoint,
    RecordingSchemaValidator,
    TrackingDemandConnectionSource,
    match_capture_request,
    match_capture_result,
    match_input_snapshot,
    postgres_command,
    reset_demand_postgres_state,
    seed_demand_operation_graph,
    seed_exact_demand_owner_iam_authority,
    with_scope,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
IAM_MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
DEMAND_MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/demand/adapters/postgres/migrations"
)


@dataclass(frozen=True)
class SemanticObservation:
    code: str
    replayed: bool = False


class RealPostgres18DemandSemanticRedTest(unittest.TestCase):
    """TEST-DB-DEMAND-001/RLS-001/UOW-001/MATCH-001."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()
        cls.database = cls.postgres.create_database()
        cls.catalog = MigrationCatalog.load(IAM_MIGRATION_ROOT)
        cls.contract_sources = IamContractSources(
            api_contract_bytes=(
                PLATFORM_ROOT / "contracts/api/iam-v1.openapi.yaml"
            ).read_bytes(),
            event_contract_bytes=(
                PLATFORM_ROOT / "contracts/events/iam-v1.schema.json"
            ).read_bytes(),
        )
        driver = PsycopgMigrationDriver(
            settings=PsycopgMigrationSettings(
                conninfo=cls.postgres.conninfo(
                    database=cls.database,
                    user="iam_migration_runner",
                ),
                application_name="desire-demand-pg-red",
            ),
            dbapi=psycopg,
        )
        cls.migration_report = IamMigrationRunner(
            driver=driver,
            runner_version="demand-pg-red/1",
        ).run(catalog=cls.catalog, contract_sources=cls.contract_sources)
        expected_versions = tuple(
            artifact.descriptor.version for artifact in cls.catalog.artifacts
        )
        if cls.migration_report.applied_versions != expected_versions:
            raise AssertionError("dynamic IAM migration catalog was not applied exactly")
        with cls._admin_class() as connection:
            iam_created_demand_schema = connection.execute(
                "SELECT pg_catalog.to_regnamespace('demand')::text"
            ).fetchone()[0]
        if iam_created_demand_schema is not None:
            raise AssertionError("the IAM catalog crossed into the Demand schema")

        # The independent Demand catalog is intentionally absent in this RED.
        # Keeping the load at this exact seam lets the same semantic assertions
        # consume a future reviewed catalog without registering one here or
        # smuggling Demand DDL into IAM.
        cls.demand_catalog = None
        cls.demand_migration_report = None
        demand_manifest = DEMAND_MIGRATION_ROOT / "manifest.json"
        if demand_manifest.is_file():
            from desire_platform.demand.adapters.postgres.migrations import (
                DemandContractSources,
                DemandMigrationCatalog,
                DemandMigrationRunner,
                DemandMigrationSettings,
                PsycopgDemandMigrationDriver,
            )

            cls.demand_catalog = DemandMigrationCatalog.load(DEMAND_MIGRATION_ROOT)
            cls.demand_migration_report = DemandMigrationRunner(
                driver=PsycopgDemandMigrationDriver(
                    settings=DemandMigrationSettings(
                        conninfo=cls.postgres.conninfo(
                            database=cls.database,
                            user="demand_migration_runner",
                        ),
                        application_name="desire-demand-pg-red-catalog",
                    ),
                    dbapi=psycopg,
                ),
                runner_version="demand-pg-red/1",
            ).run(
                catalog=cls.demand_catalog,
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
            demand_versions = tuple(
                artifact.descriptor.version
                for artifact in cls.demand_catalog.artifacts
            )
            if cls.demand_migration_report.applied_versions != demand_versions:
                raise AssertionError(
                    "dynamic Demand migration catalog was not applied exactly"
                )
        with cls._admin_class(autocommit=False) as connection:
            cls.iam_authority = seed_exact_demand_owner_iam_authority(
                connection,
                now=UTC_NOW,
            )
        with cls._admin_class() as connection:
            server_major, compatibility = connection.execute(
                "SELECT "
                "current_setting('server_version_num')::integer / 10000,"
                "(SELECT ROW(current_schema_version,schema_head_version)::text "
                " FROM infra.iam_schema_compatibility)"
            ).fetchone()
            ledger_versions = tuple(
                row[0]
                for row in connection.execute(
                    "SELECT version FROM infra.schema_migrations "
                    "WHERE component='iam' ORDER BY version"
                ).fetchall()
            )
            authority_facts = connection.execute(
                "SELECT "
                "(SELECT count(*) FROM iam.users WHERE id=%s AND status='ACTIVE'),"
                "(SELECT count(*) FROM iam.sessions WHERE id=%s AND status='ACTIVE'),"
                "(SELECT count(*) FROM iam.organizations WHERE id=%s AND status='ACTIVE'),"
                "(SELECT count(*) FROM iam.memberships "
                " WHERE id=%s AND organization_id=%s AND status='ACTIVE'),"
                "(SELECT count(*) FROM iam.membership_role_grants "
                " WHERE id=%s AND role_code='DEMAND_OWNER' AND revoked_at IS NULL),"
                "(SELECT count(*) FROM iam.policy_acceptances "
                " WHERE user_id=%s AND document_id=%s),"
                "(SELECT count(*) FROM iam.policy_bundles "
                " WHERE id=%s AND status='ACTIVE'),"
                "(SELECT count(*) FROM iam.user_role_grants WHERE user_id=%s)",
                (
                    cls.iam_authority.actor_user_id,
                    cls.iam_authority.session_id,
                    cls.iam_authority.organization_id,
                    cls.iam_authority.membership_id,
                    cls.iam_authority.organization_id,
                    cls.iam_authority.membership_role_grant_id,
                    cls.iam_authority.actor_user_id,
                    cls.iam_authority.required_document_id,
                    cls.iam_authority.policy_bundle_id,
                    cls.iam_authority.actor_user_id,
                ),
            ).fetchone()
        expected_head = expected_versions[-1]
        if server_major != 18:
            raise AssertionError("Demand RED did not start PostgreSQL 18")
        if compatibility != f"({expected_head},{expected_head})":
            raise AssertionError("IAM compatibility is not at the dynamic catalog head")
        if ledger_versions != expected_versions:
            raise AssertionError("IAM migration ledger differs from dynamic catalog")
        if authority_facts != (1, 1, 1, 1, 1, 1, 1, 0):
            raise AssertionError("exact DEMAND_OWNER IAM fixture is incomplete")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.postgres.drop_database(cls.database)
        cls.postgres.stop()

    @classmethod
    def _admin_class(cls, *, autocommit: bool = True):
        return psycopg.connect(
            cls.postgres.admin_conninfo(database=cls.database),
            autocommit=autocommit,
        )

    def setUp(self) -> None:
        self.sources: list[TrackingDemandConnectionSource] = []
        with self._admin_class(autocommit=False) as connection:
            reset_demand_postgres_state(connection)

    def tearDown(self) -> None:
        for source in self.sources:
            source.close()

    def _prepare(self, operation: DemandPostgresOperation) -> None:
        with self._admin_class(autocommit=False) as connection:
            reset_demand_postgres_state(connection)
            seed_demand_operation_graph(connection, operation)

    def _source(
        self,
        *,
        role: str = "demand_self",
        reuse_released: bool = False,
        lose_first_commit_ack: bool = False,
        startup_options: Optional[str] = None,
    ) -> TrackingDemandConnectionSource:
        conninfo = self.postgres.conninfo(database=self.database, user=role)
        if startup_options is not None:
            conninfo = psycopg.conninfo.make_conninfo(
                conninfo,
                options=startup_options,
            )
        source = TrackingDemandConnectionSource(
            conninfo,
            reuse_released=reuse_released,
            lose_first_commit_ack=lose_first_commit_ack,
        )
        self.sources.append(source)
        return source

    def _factory(
        self,
        *,
        source: Optional[TrackingDemandConnectionSource] = None,
        fault: Any = None,
        settings: Optional[DemandPostgresSettings] = None,
    ) -> PsycopgDemandUnitOfWorkFactory:
        return PsycopgDemandUnitOfWorkFactory(
            connections=source or self._source(),
            event_validator=RecordingSchemaValidator(),
            response_validator=RecordingSchemaValidator(),
            fault_injector=fault,
            settings=settings,
        )

    @staticmethod
    def _method_name(operation: DemandPostgresOperation) -> str:
        return {
            DemandPostgresOperation.CREATE: "execute_create",
            DemandPostgresOperation.CREATE_VERSION: "execute_create_version",
            DemandPostgresOperation.SUBMIT: "execute_submit",
            DemandPostgresOperation.REQUEST_CHANGES: "execute_request_changes",
            DemandPostgresOperation.VERIFY: "execute_verify",
            DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT: (
                "execute_release_review_assignment"
            ),
            DemandPostgresOperation.APPLY_FUNDING_SECURED: "execute_apply_funding_secured",
            DemandPostgresOperation.REQUEST_MATCHING: "execute_request_matching",
            DemandPostgresOperation.REQUEST_MATCHING_SYSTEM: (
                "execute_request_matching_system"
            ),
            DemandPostgresOperation.CANCEL_OWNER: "execute_cancel_owner",
            DemandPostgresOperation.CANCEL_REVIEW: "execute_cancel_review",
            DemandPostgresOperation.EXPIRE: "execute_expire",
        }[operation]

    def _observe(
        self,
        factory: PsycopgDemandUnitOfWorkFactory,
        operation: DemandPostgresOperation,
        request: Any,
    ) -> SemanticObservation:
        try:
            result = getattr(factory, self._method_name(operation))(request)
        except DemandPostgresBehaviorNotAvailable as error:
            if str(error) != DEMAND_POSTGRES_BEHAVIOR_NOT_AVAILABLE:
                raise
            return SemanticObservation(DEMAND_POSTGRES_BEHAVIOR_NOT_AVAILABLE)
        except DemandPostgresDatabaseError as error:
            return SemanticObservation(error.code)
        except DemandPostgresCommitOutcomeUnknownError as error:
            return SemanticObservation(error.code)
        except DemandPostgresConfigurationError:
            return SemanticObservation("SERVICE_UNAVAILABLE")
        except InjectedDemandPostgresWriteFailure:
            return SemanticObservation("INJECTED_WRITE_FAILURE")
        return SemanticObservation("SUCCEEDED", replayed=result.replayed)

    def _observe_match(
        self,
        repository: PsycopgDemandMatchingRepository,
        request: Any,
    ) -> SemanticObservation:
        return self._capture_match(repository, request)[0]

    def _capture_match(
        self,
        repository: PsycopgDemandMatchingRepository,
        request: Any,
    ) -> tuple[SemanticObservation, Optional[DemandPostgresMatchCaptureResult]]:
        try:
            result = repository.capture_match_inputs(request)
        except DemandPostgresBehaviorNotAvailable as error:
            if str(error) != DEMAND_POSTGRES_BEHAVIOR_NOT_AVAILABLE:
                raise
            return (
                SemanticObservation(DEMAND_POSTGRES_BEHAVIOR_NOT_AVAILABLE),
                None,
            )
        except DemandPostgresDatabaseError as error:
            return SemanticObservation(error.code), None
        return SemanticObservation("SUCCEEDED"), result

    def _schema_surface(self) -> Mapping[str, Any]:
        with self._admin_class() as connection:
            row = connection.execute(
                "SELECT "
                "pg_catalog.to_regclass('demand.demands')::text,"
                "pg_catalog.to_regclass('demand.demand_versions')::text,"
                "pg_catalog.to_regclass('demand.demand_submissions')::text,"
                "pg_catalog.to_regclass('demand.demand_reviews')::text,"
                "pg_catalog.to_regclass('demand.demand_funding_markers')::text,"
                "pg_catalog.to_regclass('demand.matching_requests')::text,"
                "pg_catalog.to_regclass('demand.source_inbox')::text,"
                "pg_catalog.to_regclass('demand.command_receipts')::text,"
                "pg_catalog.to_regrole('demand_self')::text,"
                "pg_catalog.to_regrole('demand_review')::text,"
                "pg_catalog.to_regrole('demand_finance')::text,"
                "pg_catalog.to_regrole('demand_matching')::text,"
                "pg_catalog.to_regrole('demand_system')::text"
            ).fetchone()
        keys = (
            "root", "versions", "submissions", "reviews", "funding",
            "matching_requests", "source_inbox", "receipts", "self_role",
            "review_role", "finance_role", "matching_role", "system_role",
        )
        return dict(zip(keys, row))

    def _security_surface(self) -> Mapping[str, Any]:
        with self._admin_class() as connection:
            roles = tuple(
                connection.execute(
                    "SELECT rolname,rolcanlogin,rolsuper,rolbypassrls,"
                    "rolinherit,rolcreatedb,rolcreaterole "
                    "FROM pg_catalog.pg_roles WHERE rolname LIKE 'demand\\_%' "
                    "ORDER BY rolname"
                ).fetchall()
            )
            relations = tuple(
                connection.execute(
                    "SELECT relation.relname,relation.relrowsecurity,"
                    "relation.relforcerowsecurity,owner.rolname "
                    "FROM pg_catalog.pg_class AS relation "
                    "JOIN pg_catalog.pg_namespace AS namespace "
                    "ON namespace.oid=relation.relnamespace "
                    "JOIN pg_catalog.pg_roles AS owner ON owner.oid=relation.relowner "
                    "WHERE namespace.nspname='demand' "
                    "AND relation.relkind IN ('r','p') ORDER BY relation.relname"
                ).fetchall()
            )
            public_schema_usage = connection.execute(
                "SELECT CASE WHEN pg_catalog.to_regnamespace('demand') IS NULL "
                "THEN NULL ELSE pg_catalog.has_schema_privilege("
                "'public',pg_catalog.to_regnamespace('demand'),'USAGE') END"
            ).fetchone()[0]
            public_executable_routines = connection.execute(
                "SELECT count(*) FROM pg_catalog.pg_proc AS routine "
                "JOIN pg_catalog.pg_namespace AS namespace "
                "ON namespace.oid=routine.pronamespace "
                "WHERE namespace.nspname='demand' AND "
                "pg_catalog.has_function_privilege('public',routine.oid,'EXECUTE')"
            ).fetchone()[0]
        return {
            "roles": roles,
            "relations": relations,
            "public_schema_usage": public_schema_usage,
            "public_executable_routines": public_executable_routines,
        }

    def test_contract_is_frozen_importable_secret_safe_and_default_deny(self) -> None:
        self.assertEqual(
            tuple(item.value for item in DEMAND_POSTGRES_SUBMIT_WRITE_CHECKPOINTS),
            (
                "receipt.pending",
                "submission.insert",
                "demand.root",
                "audit.insert",
                "outbox.state_changed",
                "receipt.completed",
            ),
        )
        self.assertGreater(
            len(DEMAND_POSTGRES_WRITE_CHECKPOINTS),
            len(DEMAND_POSTGRES_SUBMIT_WRITE_CHECKPOINTS),
        )
        self.assertEqual(
            set(DEMAND_POSTGRES_STATEMENT_PROFILES),
            set(DemandPostgresOperation),
        )
        for operation, profile in DEMAND_POSTGRES_STATEMENT_PROFILES.items():
            self.assertEqual(profile.operation, operation)
            self.assertEqual(profile.statement_budget, len(profile.statement_names))
            self.assertEqual(len(profile.query_shape_sha256), 64)
        owner_programs = (
            DemandPostgresOperation.CREATE,
            DemandPostgresOperation.CREATE_VERSION,
            DemandPostgresOperation.SUBMIT,
            DemandPostgresOperation.CANCEL_OWNER,
        )
        for operation in owner_programs:
            self.assertIn(
                "iam_api.lock_demand_owner_authority_v1",
                DEMAND_POSTGRES_STATEMENT_PROFILES[operation].statement_names,
            )
        self.assertNotIn(
            "iam_api.authorize_demand_owner_v1",
            {
                name
                for profile in DEMAND_POSTGRES_STATEMENT_PROFILES.values()
                for name in profile.statement_names
            },
        )
        settings = DemandPostgresSettings()
        self.assertEqual(
            (
                settings.self_role,
                settings.review_role,
                settings.finance_role,
                settings.matching_role,
                settings.system_role,
                settings.required_server_major,
            ),
            (
                "demand_self", "demand_review", "demand_finance",
                "demand_matching", "demand_system", 18,
            ),
        )
        with self.assertRaises(ValueError):
            DemandPostgresSettings(self_role="demand_schema_owner")
        with self.assertRaises(ValueError):
            DemandPostgresSettings(matching_role="demand_self")
        request = postgres_command(DemandPostgresOperation.SUBMIT)
        with self.assertRaises(FrozenInstanceError):
            request.expected_aggregate_version = 99  # type: ignore[misc]
        with self.assertRaises(ValueError):
            replace(request, reason_codes=("EXTRA_FIELD",))
        with self.assertRaises(ValueError):
            replace(
                request,
                content_policy=replace(
                    request.content_policy,
                    content_sha256=b"x" * 32,
                ),
            )
        rendered = repr(request)
        for sentinel in RAW_SECRET_SENTINELS:
            self.assertNotIn(sentinel, rendered)
        source = self._source()
        factory = self._factory(source=source)
        self.assertFalse(hasattr(factory, "execute"))
        self._prepare(DemandPostgresOperation.SUBMIT)
        observation = self._observe(
            factory,
            DemandPostgresOperation.SUBMIT,
            request,
        )
        self.assertEqual(
            (
                observation.code,
                observation.replayed,
                len(source.checked_out),
                len(source.released),
            ),
            ("SUCCEEDED", False, 1, 1),
        )

    def test_dynamic_iam_head_then_registered_demand_catalog_has_exact_surface(self) -> None:
        expected_head = self.catalog.artifacts[-1].descriptor.version
        self.assertEqual(self.migration_report.applied_versions[-1], expected_head)
        self.assertEqual(
            self._schema_surface(),
            {
                "root": "demand.demands",
                "versions": "demand.demand_versions",
                "submissions": "demand.demand_submissions",
                "reviews": "demand.demand_reviews",
                "funding": "demand.demand_funding_markers",
                "matching_requests": "demand.matching_requests",
                "source_inbox": "demand.source_inbox",
                "receipts": "demand.command_receipts",
                "self_role": "demand_self",
                "review_role": "demand_review",
                "finance_role": "demand_finance",
                "matching_role": "demand_matching",
                "system_role": "demand_system",
            },
            "semantic RED: independent Demand catalog/schema/roles are absent",
        )

    def test_ten_writer_happy_paths_persist_exact_root_graph_receipt_audit_and_outbox(self) -> None:
        for operation in DemandPostgresOperation:
            if operation is DemandPostgresOperation.CAPTURE_MATCH_INPUTS:
                continue
            with self.subTest(operation=operation.value):
                self._prepare(operation)
                role = DEMAND_POSTGRES_STATEMENT_PROFILES[operation].runtime_role
                source = self._source(role=role)
                observation = self._observe(
                    self._factory(source=source),
                    operation,
                    postgres_command(operation),
                )
                self.assertEqual(
                    (observation.code, observation.replayed, len(source.checked_out), len(source.released)),
                    ("SUCCEEDED", False, 1, 1),
                    "semantic RED: fixed Demand writer program is unavailable",
                )

    def test_root_client_identity_version_append_and_canonical_hash_are_database_enforced(self) -> None:
        for operation in (
            DemandPostgresOperation.CREATE,
            DemandPostgresOperation.CREATE_VERSION,
        ):
            with self.subTest(operation=operation.value):
                self._prepare(operation)
                observation = self._observe(
                    self._factory(),
                    operation,
                    postgres_command(operation),
                )
                self.assertEqual(observation.code, "SUCCEEDED")

    def test_submission_binds_content_policy_hold_rule_current_version_and_hash(self) -> None:
        request = postgres_command(DemandPostgresOperation.SUBMIT)
        cases = (
            (request, "SUCCEEDED"),
            (
                replace(
                    request,
                    content_policy=replace(
                        request.content_policy,
                        valid_until=UTC_NOW - timedelta(milliseconds=100),
                    ),
                ),
                "SERVICE_UNAVAILABLE",
            ),
            (
                replace(
                    request,
                    hold=replace(
                        request.hold,
                        valid_until=UTC_NOW - timedelta(milliseconds=100),
                    ),
                ),
                "SAFETY_HOLD_BLOCKED",
            ),
            (
                replace(
                    request,
                    rule_requirement=replace(
                        request.rule_requirement,
                        effective_until=UTC_NOW - timedelta(milliseconds=100),
                    ),
                ),
                "TAXONOMY_BUNDLE_CHANGED",
            ),
        )
        for candidate, expected in cases:
            with self.subTest(expected=expected):
                self._prepare(DemandPostgresOperation.SUBMIT)
                self.assertEqual(
                    self._observe(
                        self._factory(),
                        DemandPostgresOperation.SUBMIT,
                        candidate,
                    ).code,
                    expected,
                )

    def test_review_requires_exact_assignment_duty_separation_and_single_completion(self) -> None:
        cases = (
            (DemandPostgresOperation.REQUEST_CHANGES, postgres_command(DemandPostgresOperation.REQUEST_CHANGES), "SUCCEEDED"),
            (DemandPostgresOperation.VERIFY, postgres_command(DemandPostgresOperation.VERIFY), "SUCCEEDED"),
            (
                DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT,
                postgres_command(
                    DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT
                ),
                "SUCCEEDED",
            ),
            (
                DemandPostgresOperation.VERIFY,
                with_scope(
                    postgres_command(DemandPostgresOperation.VERIFY),
                    actor_id=uuid_from_int(0xEE),
                ),
                "RESOURCE_NOT_FOUND",
            ),
        )
        for operation, request, expected in cases:
            with self.subTest(operation=operation.value, expected=expected):
                self._prepare(operation)
                self.assertEqual(
                    self._observe(
                        self._factory(
                            source=self._source(role="demand_review")
                        ),
                        operation,
                        request,
                    ).code,
                    expected,
                )

    def test_review_assignment_release_persists_one_exact_atomic_fact_graph(self) -> None:
        operation = DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT
        self._prepare(operation)
        request = postgres_command(operation)

        result = self._factory(
            source=self._source(role="demand_review")
        ).execute_release_review_assignment(request)

        self.assertEqual(
            (
                result.replayed,
                result.status,
                result.aggregate_version,
                result.current_version_id,
                result.event_types,
                dict(result.safe_response),
            ),
            (
                False,
                "SUBMITTED",
                2,
                DEMAND_VERSION_ID,
                ("DemandReviewAssignmentReleased",),
                {
                    "aggregate_version": 2,
                    "demand_id": str(DEMAND_ID),
                    "demand_version_id": str(DEMAND_VERSION_ID),
                    "status": "SUBMITTED",
                },
            ),
        )
        with self._admin_class() as connection:
            root = connection.execute(
                "SELECT status,aggregate_version,current_version_id,"
                "current_submission_id,current_review_id,verified_version_id,"
                "current_funding_marker_id,current_matching_request_id,updated_at "
                "FROM demand.demands WHERE organization_id=%s AND id=%s",
                (ORGANIZATION_ID, DEMAND_ID),
            ).fetchone()
            assignment = connection.execute(
                "SELECT status,aggregate_version,completed_at "
                "FROM demand.demand_review_assignments WHERE id=%s",
                (ASSIGNMENT_ID,),
            ).fetchone()
            release = connection.execute(
                "SELECT id,organization_id,demand_id,submission_id,"
                "demand_version_id,assignment_id,reviewer_user_id,reason_code,"
                "authority_marker_sha256,released_at "
                "FROM demand.demand_review_assignment_releases WHERE id=%s",
                (request.scope.command_id,),
            ).fetchone()
            receipt = connection.execute(
                "SELECT status,response_http_status,response_schema_name,"
                "response_schema_version,response_entity_tag,safe_response_body,"
                "target_id,target_version,result_status,event_types,completed_at "
                "FROM demand.command_receipts WHERE receipt_id=%s",
                (request.scope.command_id,),
            ).fetchone()
            audit = connection.execute(
                "SELECT action_code,before_status,after_status,before_version,"
                "after_version,role_code,purpose_code,reason_code,result_code,"
                "command_id,occurred_at FROM audit.audit_events "
                "WHERE event_id=%s",
                (request.scope.audit_event_id,),
            ).fetchone()
            outbox = connection.execute(
                "SELECT event_type,aggregate_version,organization_id,payload,"
                "delivery_status,occurred_at FROM infra.outbox_events "
                "WHERE event_id=%s",
                (request.scope.outbox_event_ids[0],),
            ).fetchone()
            review_count = connection.execute(
                "SELECT count(*) FROM demand.demand_reviews "
                "WHERE assignment_id=%s",
                (ASSIGNMENT_ID,),
            ).fetchone()[0]

        self.assertEqual(
            root[:8],
            (
                "SUBMITTED",
                2,
                DEMAND_VERSION_ID,
                SUBMISSION_ID,
                None,
                None,
                None,
                None,
            ),
        )
        self.assertEqual(assignment[:2], ("REVOKED", 2))
        self.assertEqual(
            release[:8],
            (
                request.scope.command_id,
                ORGANIZATION_ID,
                DEMAND_ID,
                SUBMISSION_ID,
                DEMAND_VERSION_ID,
                ASSIGNMENT_ID,
                REVIEWER_USER_ID,
                "WORKLOAD_RELEASE",
            ),
        )
        self.assertEqual(release[8], request.scope.expected_authority_marker_sha256)
        self.assertEqual(
            receipt[:10],
            (
                "COMPLETED",
                200,
                "DemandDto",
                1,
                '"v2"',
                {
                    "aggregate_version": 2,
                    "demand_id": str(DEMAND_ID),
                    "demand_version_id": str(DEMAND_VERSION_ID),
                    "status": "SUBMITTED",
                },
                DEMAND_ID,
                2,
                "SUBMITTED",
                ["DemandReviewAssignmentReleased"],
            ),
        )
        self.assertEqual(
            audit[:10],
            (
                "ReleaseDemandReviewAssignment",
                "SUBMITTED",
                "SUBMITTED",
                1,
                2,
                "OPERATIONS_REVIEWER",
                "DEMAND_REVIEW",
                "WORKLOAD_RELEASE",
                "SUCCEEDED",
                request.scope.command_id,
            ),
        )
        self.assertEqual(
            outbox[:5],
            (
                "DemandReviewAssignmentReleased",
                2,
                ORGANIZATION_ID,
                {
                    "assignment_id": str(ASSIGNMENT_ID),
                    "demand_id": str(DEMAND_ID),
                    "demand_version_id": str(DEMAND_VERSION_ID),
                    "reason_code": "WORKLOAD_RELEASE",
                    "status": "SUBMITTED",
                },
                "PENDING",
            ),
        )
        self.assertEqual(review_count, 0)
        self.assertEqual(
            {
                root[8],
                assignment[2],
                release[9],
                receipt[10],
                audit[10],
                outbox[5],
            },
            {root[8]},
            "release root, lease, fact, receipt, audit and event must share one clock",
        )

        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="demand_review"),
            autocommit=True,
        ) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT count(*) FROM demand.demand_review_assignment_releases"
                ).fetchone()[0],
                0,
                "release facts must remain invisible without exact RLS context",
            )

        immutable_statements = (
            "UPDATE demand.demand_review_assignment_releases "
            "SET reason_code='CONFLICT_DECLARED' WHERE id=%s",
            "DELETE FROM demand.demand_review_assignment_releases WHERE id=%s",
        )
        for statement in immutable_statements:
            with self.subTest(immutable_statement=statement.split()[0]):
                with self._admin_class() as connection:
                    with self.assertRaises(psycopg.errors.CheckViolation) as denied:
                        connection.execute(statement, (request.scope.command_id,))
                    self.assertEqual(
                        denied.exception.diag.constraint_name,
                        "trg_demand_review_assignment_release_immutable",
                    )

    def test_review_assignment_release_rolls_back_at_every_write_checkpoint(self) -> None:
        operation = DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT
        checkpoints = (
            DemandPostgresWriteCheckpoint.RECEIPT_PENDING,
            DemandPostgresWriteCheckpoint.REVIEW_ASSIGNMENT_RELEASE,
            DemandPostgresWriteCheckpoint.REVIEW_ASSIGNMENT_RELEASE_FACT,
            DemandPostgresWriteCheckpoint.DEMAND_ROOT,
            DemandPostgresWriteCheckpoint.AUDIT,
            DemandPostgresWriteCheckpoint.OUTBOX_STATE_CHANGED,
            DemandPostgresWriteCheckpoint.RECEIPT_COMPLETED,
        )

        for checkpoint in checkpoints:
            with self.subTest(checkpoint=checkpoint.value):
                self._prepare(operation)
                before = self._release_database_snapshot()
                request = postgres_command(operation)
                observation = self._observe(
                    self._factory(
                        source=self._source(role="demand_review"),
                        fault=RaiseAtDemandCheckpoint(checkpoint),
                    ),
                    operation,
                    request,
                )
                after = self._release_database_snapshot()

                self.assertEqual(observation.code, "INJECTED_WRITE_FAILURE")
                self.assertEqual(after, before)
                retry = self._factory(
                    source=self._source(role="demand_review")
                ).execute_release_review_assignment(request)
                self.assertFalse(retry.replayed)

    def test_completed_release_receipt_replays_after_active_assignment_disappears(self) -> None:
        operation = DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT
        self._prepare(operation)
        request = postgres_command(operation)
        self._factory(
            source=self._source(role="demand_review")
        ).execute_release_review_assignment(request)

        identity_key = b"i" * 32
        payload_key = b"p" * 32
        canonical_payload = f"{operation.value}:{DEMAND_ID}:1".encode("utf-8")
        with self._admin_class() as connection:
            connection.execute(
                "UPDATE demand.command_receipts SET idempotency_key_digest=%s,"
                "payload_hash=%s WHERE receipt_id=%s",
                (
                    hmac.new(
                        identity_key,
                        RAW_IDEMPOTENCY_SENTINEL.encode("utf-8"),
                        hashlib.sha256,
                    ).digest(),
                    hmac.new(
                        payload_key,
                        canonical_payload,
                        hashlib.sha256,
                    ).digest(),
                    request.scope.command_id,
                ),
            )

        probe = PsycopgDemandCompletedVerifyReceiptProbe(
            connections=self._source(role="demand_review"),
            idempotency_keys=((
                "demand-idempotency-2026-01",
                identity_key,
            ),),
            payload_hash_keys=((
                "demand-payload-2026-01",
                payload_key,
            ),),
        )
        replay_request = DemandCompletedReleaseReplayProbeRequest(
            actor_user_id=REVIEWER_USER_ID,
            session_id=REVIEWER_SESSION_ID,
            command_id=request.scope.command_id,
            demand_id=DEMAND_ID,
            assignment_id=ASSIGNMENT_ID,
            expected_version=1,
            idempotency_key=RAW_IDEMPOTENCY_SENTINEL,
            canonical_payload=canonical_payload,
        )

        replay = probe.read_completed_release(replay_request)

        self.assertIsNotNone(replay)
        self.assertEqual(
            (
                replay.organization_id,
                replay.aggregate_version,
                replay.demand_version_id,
                replay.authority_marker_sha256,
            ),
            (
                ORGANIZATION_ID,
                2,
                DEMAND_VERSION_ID,
                request.scope.expected_authority_marker_sha256,
            ),
        )
        with self.assertRaises(DemandCompletedReleaseReplayError) as reused:
            probe.read_completed_release(
                replace(replay_request, canonical_payload=b"changed-release-payload")
            )
        self.assertEqual(reused.exception.code, "IDEMPOTENCY_KEY_REUSED")

    def _release_database_snapshot(self) -> tuple[Any, ...]:
        with self._admin_class() as connection:
            return (
                connection.execute(
                    "SELECT status,aggregate_version,current_version_id,"
                    "current_submission_id,current_review_id,updated_at "
                    "FROM demand.demands WHERE id=%s",
                    (DEMAND_ID,),
                ).fetchone(),
                connection.execute(
                    "SELECT status,aggregate_version,completed_at "
                    "FROM demand.demand_review_assignments WHERE id=%s",
                    (ASSIGNMENT_ID,),
                ).fetchone(),
                connection.execute(
                    "SELECT count(*) FROM demand.demand_review_assignment_releases"
                ).fetchone()[0],
                connection.execute(
                    "SELECT count(*) FROM demand.command_receipts"
                ).fetchone()[0],
                connection.execute(
                    "SELECT count(*) FROM demand.demand_reviews"
                ).fetchone()[0],
                connection.execute(
                    "SELECT count(*) FROM audit.audit_events"
                ).fetchone()[0],
                connection.execute(
                    "SELECT count(*) FROM infra.outbox_events"
                ).fetchone()[0],
            )

    def test_funding_source_inbox_is_authenticated_exact_and_deduplicated(self) -> None:
        operation = DemandPostgresOperation.APPLY_FUNDING_SECURED
        self._prepare(operation)
        request = postgres_command(operation)
        source = self._source(role="demand_finance")
        factory = self._factory(source=source)
        observations = (
            self._observe(factory, operation, request),
            self._observe(factory, operation, request),
            self._observe(
                factory,
                operation,
                replace(
                    request,
                    source_event=replace(
                        request.source_event,
                        envelope_sha256=b"z" * 32,
                    ),
                ),
            ),
        )
        self.assertEqual(
            tuple((item.code, item.replayed) for item in observations),
            (("SUCCEEDED", False), ("SUCCEEDED", True), ("FUNDING_FACT_CHANGED", False)),
        )

    def test_matching_capture_normalizes_locale_languages_for_profile_engine_contract(self) -> None:
        from desire_platform.matching.engine_v1 import (
            demand_postgres_snapshot_to_input_v1,
            evaluate_candidate_hard_filters_v1,
            load_default_rule_release_v1,
            normalize_match_run_input_v1,
        )

        self._prepare(DemandPostgresOperation.CAPTURE_MATCH_INPUTS)
        captured = PsycopgDemandMatchingRepository(
            connections=self._source(role="demand_matching")
        ).capture_match_inputs(match_capture_request())
        snapshot = captured.snapshots[0]
        original = json.loads(snapshot.canonical_demand_version_bytes)["content"]
        self.assertEqual(original["collaboration"]["languages"], ["zh-CN", "en"])
        self.assertEqual(snapshot.required_language_codes, ("LANGUAGE.EN", "LANGUAGE.ZH"))
        # Use the actual PostgreSQL capture in the unchanged deterministic
        # engine. Profile5 publishes root-language codes, including LANGUAGE.ZH.
        resource = PLATFORM_ROOT / "src/desire_platform/matching/resources/deterministic-matcher-v1.golden.json"
        document = json.loads(resource.read_text())["vectors"][0]["run_input"]
        document["demand"] = demand_postgres_snapshot_to_input_v1(snapshot)
        document["profiles"][0]["language_codes"] = ["LANGUAGE.ZH"]
        run_input = normalize_match_run_input_v1(document)
        rule = load_default_rule_release_v1()
        matching = evaluate_candidate_hard_filters_v1(
            demand=run_input.demand, profile=run_input.profiles[0], rule=rule,
        )
        mismatch = evaluate_candidate_hard_filters_v1(
            demand=run_input.demand,
            profile=replace(run_input.profiles[0], language_codes=("LANGUAGE.DE",)),
            rule=rule,
        )
        self.assertNotIn("LANGUAGE_MISMATCH", matching)
        self.assertIn("LANGUAGE_MISMATCH", mismatch)
        with self.assertRaises(ValueError):
            replace(snapshot, required_language_codes=("LANGUAGE.DE",))

    def test_matching_request_and_match_input_are_exact_closed_and_no_partial(self) -> None:
        self._prepare(DemandPostgresOperation.REQUEST_MATCHING)
        write = self._observe(
            self._factory(source=self._source(role="demand_review")),
            DemandPostgresOperation.REQUEST_MATCHING,
            postgres_command(DemandPostgresOperation.REQUEST_MATCHING),
        )
        matching_source = self._source(role="demand_matching")
        captured_before = datetime.now(timezone.utc)
        capture, result = self._capture_match(
            PsycopgDemandMatchingRepository(connections=matching_source),
            match_capture_request(),
        )
        captured_after = datetime.now(timezone.utc)
        missing = self._observe_match(
            PsycopgDemandMatchingRepository(
                connections=self._source(role="demand_matching")
            ),
            match_capture_request(request_ids=(MATCHING_REQUEST_ID, OTHER_DEMAND_ID)),
        )
        expected_snapshot = match_input_snapshot()
        expected_result = match_capture_result()
        with self.assertRaises(FrozenInstanceError):
            expected_snapshot.matching_request_status = "CLOSED"  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            expected_snapshot.must_have_skills[0].minimum_level = 1  # type: ignore[misc]
        with self.assertRaises(ValueError):
            replace(expected_snapshot, content_sha256=b"x" * 32)
        with self.assertRaises(ValueError):
            replace(
                expected_snapshot,
                canonical_demand_version_bytes=(
                    expected_snapshot.canonical_demand_version_bytes + b" "
                ),
            )
        with self.assertRaises(ValueError):
            replace(expected_result, snapshots=())
        with self.assertRaises(ValueError):
            replace(
                expected_result,
                snapshots=(
                    replace(
                        expected_snapshot,
                        captured_at=UTC_NOW + timedelta(microseconds=1),
                    ),
                ),
            )
        canonical = expected_snapshot.canonical_demand_version_bytes
        decoded = json.loads(canonical.decode("utf-8"))
        reencoded = json.dumps(
            decoded,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        self.assertTrue(reencoded == canonical)
        self.assertTrue(
            hashlib.sha256(canonical).digest()
            == expected_snapshot.content_sha256
        )
        expected_field_names = {
            "matching_request_id", "matching_request_version",
            "matching_request_status", "organization_id", "demand_id",
            "demand_status", "demand_version_id", "demand_version_no",
            "verification_decision", "content_sha256",
            "canonical_demand_version_bytes", "taxonomy_bundle_id",
            "funding_id", "funding_status", "composite_rule_requirement_id",
            "budget_rule_bundle_id", "risk_rule_bundle_id",
            "matching_rule_bundle_id", "reason_code_bundle_id",
            "matching_selector_digest", "rule_requirement_sha256",
            "problem_type_codes", "domain_codes", "task_codes",
            "must_have_skills", "nice_to_have_skills", "start_date",
            "due_date", "required_weekly_hours", "required_duration_weeks",
            "currency", "minimum_amount_minor", "maximum_amount_minor",
            "allowed_region_codes", "required_language_codes",
            "required_work_mode_code", "data_sensitivity_code",
            "ai_use_code", "budget_override_code", "captured_at",
        }
        self.assertEqual(
            {item.name for item in fields(DemandPostgresMatchInputSnapshot)},
            expected_field_names,
        )
        rendered = repr(expected_snapshot)
        self.assertEqual(
            repr(expected_snapshot.must_have_skills[0]),
            "DemandPostgresMatchSkillRequirement(<redacted>)",
        )
        for forbidden in RAW_SECRET_SENTINELS + (
            "Reduce energy waste",
            "100000",
            "200000",
            "APPROVED_EXCEPTION",
        ):
            with self.subTest(repr_forbidden=forbidden[:18]):
                self.assertNotIn(forbidden, rendered)

        actual_snapshot = (
            result.snapshots[0]
            if isinstance(result, DemandPostgresMatchCaptureResult)
            and len(result.snapshots) == 1
            else None
        )
        semantic_expectations = {
            "writer succeeded": write.code == "SUCCEEDED",
            "capture succeeded": capture.code == "SUCCEEDED",
            "missing input rejected atomically": missing.code == "RESOURCE_NOT_FOUND",
            "closed result type": isinstance(result, DemandPostgresMatchCaptureResult),
            "exact MatchRun": result is not None and result.match_run_id == expected_result.match_run_id,
            "exact request allowlist": (
                result is not None
                and result.requested_matching_request_ids
                == expected_result.requested_matching_request_ids
            ),
            "one complete snapshot": result is not None and len(result.snapshots) == 1,
            "two fixed statements": result is not None and result.statement_count == 2,
            "one checkout and release": (
                len(matching_source.checked_out),
                len(matching_source.released),
                len(matching_source.discarded),
            ) == (1, 1, 0),
            "read-only transaction": any(
                "BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY" in statement.upper()
                for statement in matching_source.trace
            ),
            "server transaction timestamp": any(
                "TRANSACTION_TIMESTAMP()" in statement.upper()
                for statement in matching_source.trace
            ),
            "captured_at UTC": (
                result is not None
                and result.captured_at.tzinfo is not None
                and result.captured_at.utcoffset() == timedelta(0)
            ),
            "captured_at server-call bounded": (
                result is not None
                and captured_before - timedelta(seconds=1)
                <= result.captured_at
                <= captured_after + timedelta(seconds=1)
            ),
            "captured_at equals probed PG transaction clock": (
                result is not None
                and len(matching_source.transaction_timestamps) == 1
                and result.captured_at
                == matching_source.transaction_timestamps[0]
            ),
            "one transaction clock for all rows": (
                result is not None
                and all(
                    item.captured_at == result.captured_at
                    for item in result.snapshots
                )
            ),
        }
        for label, satisfied in semantic_expectations.items():
            with self.subTest(output=label):
                self.assertTrue(satisfied)

        for item in fields(DemandPostgresMatchInputSnapshot):
            if item.name == "captured_at":
                continue
            satisfied = (
                actual_snapshot is not None
                and getattr(actual_snapshot, item.name)
                == getattr(expected_snapshot, item.name)
            )
            with self.subTest(snapshot_field=item.name):
                self.assertTrue(satisfied)

    def test_exact_iam_demand_owner_cross_tenant_and_forged_marker_fail_closed(self) -> None:
        operation = DemandPostgresOperation.CREATE
        cases = (
            (postgres_command(operation), "SUCCEEDED", None),
            (
                with_scope(
                    postgres_command(operation),
                    organization_id=OTHER_ORGANIZATION_ID,
                ),
                "RESOURCE_NOT_FOUND",
                "-c app.organization_id=%s -c app.actor_id=%s"
                % (self.iam_authority.organization_id, self.iam_authority.actor_user_id),
            ),
            (
                with_scope(
                    postgres_command(operation),
                    authority_marker=b"f" * 32,
                ),
                "RESOURCE_NOT_FOUND",
                "-c app.organization_id=%s -c app.actor_id=%s"
                % (self.iam_authority.organization_id, self.iam_authority.actor_user_id),
            ),
        )
        for request, expected, startup_options in cases:
            with self.subTest(expected=expected):
                self._prepare(operation)
                self.assertEqual(
                    self._observe(
                        self._factory(
                            source=self._source(startup_options=startup_options)
                        ),
                        operation,
                        request,
                    ).code,
                    expected,
                )

    def _matching_system_workflow(self, *, blocked: bool = False):
        from unittest.mock import Mock
        from desire_platform.demand.adapters.postgres import PsycopgDemandRuleCatalog
        from desire_platform.demand.ports.commands import DemandHoldDecision, DemandSafetyHoldResult
        from desire_platform.internal_pilot.contract_validation import DemandPostgresContractValidator
        from desire_platform.internal_pilot.matching_workflow import (
            MatchingSystemWorkflow, PsycopgMatchingWorkflowTargetReader,
        )

        # Trust's fixed reader has its own PostgreSQL integration suite. Here
        # inject its bounded result while exercising the real scoped reader,
        # rule catalog, contract validator, Demand14 writer and commit boundary.
        def hold(**fields):
            now = datetime.now(timezone.utc)
            return DemandSafetyHoldResult(**fields,
                decision=DemandHoldDecision.BLOCK if blocked else DemandHoldDecision.ALLOW,
                evaluated_at=now, valid_until=now + timedelta(seconds=15))

        source = self._source(role="demand_system")
        validator = DemandPostgresContractValidator()
        return MatchingSystemWorkflow(
            targets=PsycopgMatchingWorkflowTargetReader(connections=source),
            rules=PsycopgDemandRuleCatalog(connections=self._source(role="demand_self")),
            holds=Mock(evaluate=hold),
            writer=PsycopgDemandUnitOfWorkFactory(connections=source,
                event_validator=validator, response_validator=validator),
            idempotency_key=b"workflow-identity-key-v1-1234567890",
            payload_key=b"workflow-payload-key-v1-12345678901",
        )

    def test_explicit_system_workflow_creates_one_causally_bound_request_and_replays(self) -> None:
        from uuid import UUID
        from desire_platform.demand.adapters.postgres import DemandMatchingDeliveryContext, PsycopgDemandMatchingRuntime
        from desire_platform.internal_pilot.matching_workflow import MatchingWorkflowTarget, SYSTEM_WORKLOAD_ID
        self._prepare(DemandPostgresOperation.REQUEST_MATCHING_SYSTEM)
        target = MatchingWorkflowTarget(ORGANIZATION_ID, DEMAND_ID, 1, UUID(int=7855))
        workflow = self._matching_system_workflow()
        first = workflow.request(target)
        replay = workflow.request(target)
        self.assertEqual((first.status, first.aggregate_version, first.replayed), ("MATCHING", 2, False))
        self.assertEqual((replay.status, replay.aggregate_version, replay.replayed), ("MATCHING", 2, True))
        # A new hold may stop new work but cannot hide the committed receipt.
        held_replay = self._matching_system_workflow(blocked=True).request(target)
        self.assertTrue(held_replay.replayed)
        with self._admin_class() as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM demand.matching_requests").fetchone(), (1,))
            self.assertEqual(connection.execute("SELECT count(*) FROM demand.command_receipts").fetchone(), (1,))
            self.assertEqual(connection.execute(
                "SELECT e.actor_kind,e.actor_id,e.causation_id=f.source_event_id,e.original_actor_id "
                "FROM infra.outbox_events e JOIN demand.demand_funding_markers f "
                "ON f.demand_id=e.aggregate_id WHERE e.event_type='MatchingRequested'"
            ).fetchall(), [("SYSTEM", SYSTEM_WORKLOAD_ID, True, ACTOR_USER_ID)])
        delivery = PsycopgDemandMatchingRuntime(
            delivery_connections=self._source(role="demand_matching"),
            coordinator_connections=self._source(role="matching_coordinator"),
        ).claim_matching_requested_delivery(
            context=DemandMatchingDeliveryContext(workload_id=SYSTEM_WORKLOAD_ID,
                authority_marker_sha256=hashlib.sha256(b"exact-demand-match-request-allowlist").digest()),
            lease_digest_key_id="demand-matching-delivery-lease-v1",
            lease_digest=hashlib.sha256(b"explicit-workflow-delivery-lease").digest(), lease_seconds=30,
        )
        self.assertIsNotNone(delivery)
        self.assertEqual(delivery.original_actor_user_id, ACTOR_USER_ID)
        self.assertEqual(delivery.demand_id, DEMAND_ID)

    def test_explicit_system_workflow_wrong_org_blocked_hold_and_stale_version_write_nothing(self) -> None:
        from uuid import UUID
        from desire_platform.internal_pilot.matching_workflow import MatchingWorkflowError, MatchingWorkflowTarget
        self._prepare(DemandPostgresOperation.REQUEST_MATCHING_SYSTEM)
        target = MatchingWorkflowTarget(ORGANIZATION_ID, DEMAND_ID, 1, UUID(int=7856))
        with self.assertRaises(MatchingWorkflowError) as wrong_org:
            self._matching_system_workflow().request(replace(target, organization_id=OTHER_ORGANIZATION_ID))
        self.assertEqual(wrong_org.exception.code, "FUNDED_TARGET_NOT_FOUND")
        with self.assertRaises(MatchingWorkflowError) as blocked:
            self._matching_system_workflow(blocked=True).request(target)
        self.assertEqual(blocked.exception.code, "SAFETY_HOLD_BLOCKED")
        with self.assertRaises(DemandPostgresDatabaseError) as stale:
            self._matching_system_workflow().request(replace(target, expected_version=999))
        self.assertEqual(stale.exception.code, "PRECONDITION_FAILED")
        with self._admin_class() as connection:
            self.assertEqual(connection.execute(
                "SELECT (SELECT count(*) FROM demand.matching_requests),"
                "(SELECT count(*) FROM demand.command_receipts),"
                "(SELECT count(*) FROM infra.outbox_events)"
            ).fetchone(), (0, 0, 0))

    def test_explicit_system_workflow_same_key_changed_version_conflicts(self) -> None:
        from uuid import UUID
        from desire_platform.internal_pilot.matching_workflow import MatchingWorkflowTarget, MatchingWorkflowError
        self._prepare(DemandPostgresOperation.REQUEST_MATCHING_SYSTEM)
        workflow = self._matching_system_workflow()
        target = MatchingWorkflowTarget(ORGANIZATION_ID, DEMAND_ID, 1, UUID(int=7857))
        workflow.request(target)
        with self.assertRaises(MatchingWorkflowError) as conflict:
            workflow.request(replace(target, expected_version=2))
        self.assertEqual(conflict.exception.code, "IDEMPOTENCY_KEY_REUSED")

    def test_online_roles_force_rls_public_and_forged_guc_cannot_cross_paths(self) -> None:
        cases = (
            ("demand_self", DemandPostgresOperation.CREATE, "SUCCEEDED"),
            ("demand_review", DemandPostgresOperation.VERIFY, "SUCCEEDED"),
            ("demand_finance", DemandPostgresOperation.APPLY_FUNDING_SECURED, "SUCCEEDED"),
            ("demand_system", DemandPostgresOperation.EXPIRE, "SUCCEEDED"),
            (
                "demand_system",
                DemandPostgresOperation.REQUEST_MATCHING_SYSTEM,
                "SUCCEEDED",
            ),
            ("demand_review", DemandPostgresOperation.CREATE, "SERVICE_UNAVAILABLE"),
        )
        for role, operation, expected in cases:
            with self.subTest(role=role):
                self._prepare(operation)
                source = self._source(role=role)
                observation = self._observe(
                    self._factory(source=source),
                    operation,
                    postgres_command(operation),
                )
                self.assertEqual(
                    (observation.code, len(source.checked_out), len(source.released)),
                    (expected, 1, 1),
                )
        expected_relations = (
            "close_matching_without_selection_receipts",
            "command_receipts",
            "complete_selection_receipts",
            "demand_funding_markers",
            "demand_review_assignment_releases",
            "demand_review_assignments",
            "demand_reviews",
            "demand_submissions",
            "demand_versions",
            "demands",
            "manual_funding_assignment_releases",
            "manual_funding_confirmations",
            "manual_funding_findings",
            "manual_funding_receipts",
            "manual_funding_review_assignments",
            "manual_funding_review_cases",
            "matching_delivery_claim_receipts",
            "matching_requested_deliveries",
            "matching_requests",
            "matching_runtime_policy",
            "receipt_key_policy",
            "review_claim_receipts",
            "source_inbox",
        )
        expected_roles = tuple(
            (name, can_login, False, False, False, False, False)
            for name, can_login in (
                ("demand_finance", True),
                ("demand_matching", True),
                ("demand_migration_runner", True),
                ("demand_review", True),
                ("demand_schema_owner", False),
                ("demand_self", True),
                ("demand_system", True),
            )
        )
        self.assertEqual(
            self._security_surface(),
            {
                "roles": expected_roles,
                "relations": tuple(
                    (name, True, True, "demand_schema_owner")
                    for name in expected_relations
                ),
                "public_schema_usage": False,
                "public_executable_routines": 0,
            },
        )

    def test_same_key_concurrency_produces_one_effect_and_one_exact_replay(self) -> None:
        operation = DemandPostgresOperation.SUBMIT
        self._prepare(operation)
        request = postgres_command(operation)
        # Exercise wait-and-replay semantics even on a CPU-limited CI runner.
        settings = DemandPostgresSettings(lock_timeout_ms=10_000)
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = tuple(
                executor.submit(
                    self._observe,
                    self._factory(settings=settings),
                    operation,
                    request,
                )
                for _ in range(2)
            )
            observations = tuple(future.result() for future in futures)
        self.assertEqual(
            sorted((item.code, item.replayed) for item in observations),
            [("SUCCEEDED", False), ("SUCCEEDED", True)],
        )

    def test_different_keys_same_client_reference_concurrency_has_one_business_effect(self) -> None:
        operation = DemandPostgresOperation.CREATE
        self._prepare(operation)
        # The losing command must reach the client-reference uniqueness check.
        settings = DemandPostgresSettings(lock_timeout_ms=10_000)
        requests = (
            postgres_command(
                operation,
                idempotency_material="demand-key-one",
                command_variant=1,
            ),
            postgres_command(
                operation,
                idempotency_material="demand-key-two",
                command_variant=2,
            ),
        )
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = tuple(
                executor.submit(
                    self._observe,
                    self._factory(settings=settings),
                    operation,
                    request,
                )
                for request in requests
            )
            observations = tuple(future.result() for future in futures)
        self.assertEqual(
            sorted(item.code for item in observations),
            ["DEMAND_ALREADY_EXISTS", "SUCCEEDED"],
        )

    def test_expected_version_current_rule_and_hold_races_fail_with_zero_writes(self) -> None:
        submit = postgres_command(DemandPostgresOperation.SUBMIT)
        cases = (
            (
                postgres_command(DemandPostgresOperation.SUBMIT, expected_version=99),
                "PRECONDITION_FAILED",
            ),
            (
                replace(
                    submit,
                    hold=replace(
                        submit.hold,
                        valid_until=UTC_NOW - timedelta(milliseconds=100),
                    ),
                ),
                "SAFETY_HOLD_BLOCKED",
            ),
            (
                replace(
                    submit,
                    rule_requirement=replace(
                        submit.rule_requirement,
                        requirement_sha256=b"r" * 32,
                    ),
                ),
                "TAXONOMY_BUNDLE_CHANGED",
            ),
        )
        for request, expected in cases:
            with self.subTest(expected=expected):
                self._prepare(DemandPostgresOperation.SUBMIT)
                before = self._schema_surface()
                observation = self._observe(
                    self._factory(),
                    DemandPostgresOperation.SUBMIT,
                    request,
                )
                after = self._schema_surface()
                self.assertEqual((observation.code, after), (expected, before))

    def test_each_submit_write_checkpoint_rolls_back_all_business_and_infrastructure_facts(self) -> None:
        operation = DemandPostgresOperation.SUBMIT
        for checkpoint in DEMAND_POSTGRES_SUBMIT_WRITE_CHECKPOINTS:
            with self.subTest(checkpoint=checkpoint.value):
                self._prepare(operation)
                before = self._schema_surface()
                observation = self._observe(
                    self._factory(fault=RaiseAtDemandCheckpoint(checkpoint)),
                    operation,
                    postgres_command(operation),
                )
                after = self._schema_surface()
                self.assertEqual(
                    (observation.code, after),
                    ("INJECTED_WRITE_FAILURE", before),
                )

    def test_receipt_replay_payload_conflict_retained_keys_and_corruption_are_exact(self) -> None:
        operation = DemandPostgresOperation.SUBMIT
        self._prepare(operation)
        source = self._source(role="demand_self")
        factory = self._factory(source=source)
        request = postgres_command(operation)
        first = self._observe(factory, operation, request)
        replay = self._observe(factory, operation, request)
        changed = self._observe(
            factory,
            operation,
            postgres_command(operation, payload_label="changed-demand-payload"),
        )
        retained = replace(
            request,
            receipt=replace(
                request.receipt,
                idempotency_key_digest_key_id="demand-idempotency-retained-2025-12",
                idempotency_key_digest=b"i" * 32,
                payload_hash_key_id="demand-payload-retained-2025-12",
                payload_hash=b"p" * 32,
            ),
        )
        retained_replay = self._observe(factory, operation, retained)
        self.assertEqual(
            (
                (first.code, first.replayed),
                (replay.code, replay.replayed),
                changed.code,
                (retained_replay.code, retained_replay.replayed),
            ),
            (
                ("SUCCEEDED", False),
                ("SUCCEEDED", True),
                "IDEMPOTENCY_KEY_REUSED",
                ("SUCCEEDED", True),
            ),
        )

    def test_editor_choice_validation_runs_after_receipt_replay_only_for_new_work(
        self,
    ) -> None:
        operation = DemandPostgresOperation.CREATE_VERSION
        self._prepare(operation)
        request = postgres_command(operation)
        factory = self._factory()
        calls: list[str] = []

        first = factory.execute_create_version(
            request,
            before_mutation=lambda: calls.append("new"),
        )
        replay = factory.execute_create_version(
            request,
            before_mutation=lambda: self.fail(
                "completed receipt replay ran new choice validation"
            ),
        )

        self.assertEqual(
            (first.replayed, replay.replayed, calls),
            (False, True, ["new"]),
        )

    def test_editor_choice_rejection_rolls_back_and_preserves_the_exact_422(
        self,
    ) -> None:
        operation = DemandPostgresOperation.CREATE_VERSION
        self._prepare(operation)
        request = postgres_command(operation)
        factory = self._factory()
        rejection = EditorServiceError(
            status=422,
            code="EDITOR_CHOICE_UNAVAILABLE",
            path="/content/problem/domain_code",
        )

        def snapshot() -> tuple[Any, ...]:
            with self._admin_class() as connection:
                return (
                    connection.execute(
                        "SELECT status,aggregate_version,current_version_id "
                        "FROM demand.demands WHERE id=%s",
                        (DEMAND_ID,),
                    ).fetchone(),
                    connection.execute(
                        "SELECT count(*) FROM demand.demand_versions "
                        "WHERE demand_id=%s",
                        (DEMAND_ID,),
                    ).fetchone()[0],
                    connection.execute(
                        "SELECT count(*) FROM demand.command_receipts"
                    ).fetchone()[0],
                )

        before = snapshot()

        def reject() -> None:
            raise rejection

        with self.assertRaises(EditorServiceError) as captured:
            factory.execute_create_version(
                request,
                before_mutation=reject,
            )
        after_rejection = snapshot()
        retry = factory.execute_create_version(
            request,
            before_mutation=lambda: None,
        )

        self.assertIs(captured.exception, rejection)
        self.assertEqual(after_rejection, before)
        self.assertFalse(retry.replayed)

    def test_commit_sent_ack_loss_discards_connection_and_new_call_recovers(self) -> None:
        self._prepare(DemandPostgresOperation.SUBMIT)
        source = self._source(lose_first_commit_ack=True)
        operation = DemandPostgresOperation.SUBMIT
        observation = self._observe(
            self._factory(source=source),
            operation,
            postgres_command(operation),
        )
        self.assertEqual(
            (
                observation.code,
                len(source.checked_out),
                len(source.released),
                len(source.discarded),
            ),
            ("COMMAND_OUTCOME_UNKNOWN", 1, 0, 1),
        )
        recovery_source = self._source(role="demand_self")
        recovered = self._observe(
            self._factory(source=recovery_source),
            operation,
            postgres_command(operation),
        )
        self.assertEqual(
            (recovered.code, recovered.replayed),
            ("SUCCEEDED", True),
        )

    def test_pool_reset_wrong_role_and_secret_sentinels_are_closed(self) -> None:
        self._prepare(DemandPostgresOperation.CREATE)
        writer_source = self._source(role="demand_self", reuse_released=True)
        matching_source = self._source(role="demand_matching")
        request = postgres_command(DemandPostgresOperation.CREATE)
        first = self._observe(
                self._factory(source=writer_source),
                DemandPostgresOperation.CREATE,
                request,
            )
        second = self._observe(
                self._factory(source=writer_source),
                DemandPostgresOperation.CREATE,
                request,
            )
        self._prepare(DemandPostgresOperation.CAPTURE_MATCH_INPUTS)
        observations = (
            first,
            second,
            self._observe_match(
                PsycopgDemandMatchingRepository(connections=matching_source),
                match_capture_request(),
            ),
        )
        for index, observation in enumerate(observations):
            with self.subTest(call=index):
                self.assertEqual(observation.code, "SUCCEEDED")
        diagnostic = "\n".join(
            (
                repr(request),
                repr(match_capture_request()),
                repr(observations),
                json.dumps(self._schema_surface(), sort_keys=True),
                "\n".join(writer_source.trace),
            )
        )
        for sentinel in RAW_SECRET_SENTINELS:
            with self.subTest(sentinel=sentinel[:18]):
                self.assertNotIn(sentinel, diagnostic)


def uuid_from_int(value: int):
    import uuid

    return uuid.UUID(f"{value:08x}-0000-4000-8000-000000000001")


if __name__ == "__main__":
    unittest.main()
