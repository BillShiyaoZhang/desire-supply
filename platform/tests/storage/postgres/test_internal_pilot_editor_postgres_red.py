"""Real PostgreSQL 18 semantics for the internal-pilot composition repository."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from pathlib import Path
from typing import Optional
from uuid import UUID, uuid4
import unittest

import psycopg

from desire_platform.creator_profile.adapters.postgres import (
    CreatorProfilePostgresDatabaseError,
    CreatorProfilePostgresHoldEvidence,
    CreatorProfilePostgresOperation,
    PsycopgCreatorProfileUnitOfWorkFactory,
)
from desire_platform.creator_profile.adapters.postgres.migrations import (
    ProfileContractSources,
    ProfileMigrationCatalog,
    PsycopgCreatorProfileMigrationRunner,
)
from desire_platform.creator_profile.domain import canonical_profile_version_bytes
from desire_platform.demand.adapters.postgres import (
    DemandPostgresDatabaseError,
    DemandPostgresOperation,
    DemandPostgresSettings,
    PsycopgDemandUnitOfWorkFactory,
)
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
from desire_platform.internal_pilot.editor import (
    DemandReadAuthority,
    EditorPostgresKeys,
    EditorPsycopgConnectionSettings,
    EditorPrincipal,
    EditorServiceError,
    ProfileReadAuthority,
    PostgresEditorService,
    PsycopgDemandCompletedVerifyReceiptProbe,
    PsycopgEditorRepository,
    PsycopgEditorConnectionSource,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18
from tests.support.creator_profile_postgres_builders import (
    ACTOR_USER_ID,
    PROFILE_ID,
    SECOND_VERSION_ID,
    SESSION_ID,
    TAXONOMY_ID,
    TrackingProfileConnectionSource,
    RecordingSchemaValidator as ProfileSchemaValidator,
    content as profile_content,
    postgres_command as profile_command,
    reset_creator_profile_database,
    seed_exact_creator_iam_authority,
)
from tests.support.demand_postgres_builders import (
    ACTOR_USER_ID as DEMAND_ACTOR_USER_ID,
    ASSIGNMENT_ID,
    DEMAND_ID,
    DEMAND_VERSION_ID,
    ORGANIZATION_ID,
    REVIEWER_SESSION_ID,
    REVIEWER_USER_ID,
    REVIEWER_DUTY_GRANT_ID,
    SESSION_ID as DEMAND_SESSION_ID,
    TrackingDemandConnectionSource,
    RecordingSchemaValidator as DemandSchemaValidator,
    content_policy,
    hold,
    owner_authority_marker,
    postgres_command as demand_command,
    reset_demand_postgres_state,
    reviewer_authority_marker,
    rule_requirement,
    seed_demand_operation_graph,
    seed_exact_demand_owner_iam_authority,
)
from tests.support.demand_builders import valid_content_mapping


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
IAM_ROOT = PLATFORM_ROOT / "src/desire_platform/identity_access/adapters/postgres/migrations"
PROFILE_ROOT = PLATFORM_ROOT / "src/desire_platform/creator_profile/adapters/postgres/migrations"
DEMAND_ROOT = PLATFORM_ROOT / "src/desire_platform/demand/adapters/postgres/migrations"


def _migrate_iam(postgres: TemporaryPostgres18, database: str, label: str) -> None:
    catalog = MigrationCatalog.load(IAM_ROOT)
    report = IamMigrationRunner(
        driver=PsycopgMigrationDriver(
            settings=PsycopgMigrationSettings(
                conninfo=postgres.conninfo(database=database, user="iam_migration_runner"),
                application_name=f"editor-{label}-iam",
            ),
            dbapi=psycopg,
        ),
        runner_version=f"editor-{label}/1",
    ).run(
        catalog=catalog,
        contract_sources=IamContractSources(
            api_contract_bytes=(PLATFORM_ROOT / "contracts/api/iam-v1.openapi.yaml").read_bytes(),
            event_contract_bytes=(PLATFORM_ROOT / "contracts/events/iam-v1.schema.json").read_bytes(),
        ),
    )
    assert report.applied_versions == tuple(
        artifact.descriptor.version for artifact in catalog.artifacts
    )


def _editor_keys() -> EditorPostgresKeys:
    return EditorPostgresKeys(
        id_key=b"i" * 32,
        profile_idempotency_key=b"a" * 32,
        profile_payload_key=b"b" * 32,
        demand_idempotency_key=b"c" * 32,
        demand_payload_key=b"d" * 32,
        demand_client_reference_key=b"e" * 32,
    )


class _SystemClock:
    @staticmethod
    def now() -> datetime:
        return datetime.now(timezone.utc)


def _thaw_profile(value):
    if hasattr(value, "members"):
        return {key: _thaw_profile(child) for key, child in value.members}
    if isinstance(value, tuple):
        return [_thaw_profile(child) for child in value]
    return value


def _editor_profile_content() -> dict:
    content = _thaw_profile(profile_content())
    content["interests"][0].update(
        {
            "problem_code": "PROBLEM.OPERATIONS",
            "domain_code": "DOMAIN.SOFTWARE",
            "task_code": "TASK.ANALYSIS",
        }
    )
    content["skills"][0]["skill_code"] = "SKILL.SYSTEMS_ANALYSIS"
    content["boundaries"]["prohibited_domains"] = []
    content["boundaries"]["prohibited_tasks"] = []
    content["location"]["region_code"] = "CN"
    content["ai"]["prohibited_case_codes"] = []
    return content


def _editor_demand_content() -> dict:
    content = valid_content_mapping()
    content["problem"].update(
        {
            "domain_code": "DOMAIN.SOFTWARE",
            "problem_type_codes": ["PROBLEM.OPERATIONS"],
            "target_user_category_codes": ["SYNTHETIC_USER"],
        }
    )
    content["skills"]["must_have"][0]["skill_code"] = (
        "SKILL.SYSTEMS_ANALYSIS"
    )
    content["skills"]["nice_to_have"] = []
    content["matching"].update(
        {
            "problem_codes": ["PROBLEM.OPERATIONS"],
            "domain_codes": ["DOMAIN.SOFTWARE"],
            "task_codes": ["TASK.ANALYSIS"],
        }
    )
    content["risk"]["dependency_codes"] = []
    content["collaboration"]["languages"] = ["zh-CN"]
    content["location"].update(
        {
            "demand_region_code": "CN",
            "allowed_creator_region_codes": ["CN"],
        }
    )
    return content


class _ProfileAuthorities:
    def __init__(self, marker: bytes, targets=()) -> None:
        self.marker = marker
        self.targets = list(targets)

    def profile(self, *, principal, operation, profile_id):
        del principal
        if profile_id not in self.targets:
            self.targets.append(profile_id)
        return ProfileReadAuthority(self.marker, operation)

    def profile_targets(self, *, principal):
        del principal
        return tuple((item, ProfileReadAuthority(self.marker)) for item in self.targets)

    def demand(self, **kwargs):
        raise AssertionError(kwargs)

    def demand_targets(self, *, principal):
        del principal
        return ()


class _ProfileEvidence:
    def profile_hold(
        self,
        *,
        principal,
        action,
        profile_id,
        profile_version_no,
        taxonomy_bundle_id,
        prospective_aggregate_version,
        content_sha256,
        content,
        evaluated_at,
    ):
        assert action in {
            "PublishCreatorProfileVersion",
            "ResumeCreatorProfile",
        }
        assert isinstance(content, dict)
        assert profile_version_no >= 1
        assert isinstance(taxonomy_bundle_id, UUID)
        return CreatorProfilePostgresHoldEvidence(
            profile_id=profile_id,
            prospective_aggregate_version=prospective_aggregate_version,
            content_sha256=content_sha256,
            actor_user_id=UUID(principal.user_id),
            policy_version="creator-profile-hold-v1",
            evaluated_at=evaluated_at,
            valid_until=evaluated_at + timedelta(minutes=5),
        )


class _DemandAuthorities:
    def __init__(self, targets=()) -> None:
        self.targets = list(targets)

    def profile(self, **kwargs):
        raise AssertionError(kwargs)

    def profile_targets(self, *, principal):
        del principal
        return ()

    def demand(self, *, principal, operation, demand_id, assignment_id=None):
        target = UUID(demand_id)
        if demand_id not in self.targets:
            self.targets.append(demand_id)
        if operation in {
            DemandPostgresOperation.REQUEST_CHANGES,
            DemandPostgresOperation.VERIFY,
        }:
            assignment = UUID(assignment_id)
            marker = reviewer_authority_marker(
                operation, demand_id=target, assignment_id=assignment
            )
            return DemandReadAuthority(
                operation,
                marker,
                assignment,
                ORGANIZATION_ID,
            )
        marker = owner_authority_marker(operation, demand_id=target)
        return DemandReadAuthority(operation, marker)

    def demand_targets(self, *, principal):
        if "OPERATIONS_REVIEWER" in principal.role_codes:
            raise AssertionError("reviewer targets require an assignment")
        return tuple(
            (
                item,
                DemandReadAuthority(
                    DemandPostgresOperation.CREATE_VERSION,
                    owner_authority_marker(
                        DemandPostgresOperation.CREATE_VERSION,
                        demand_id=UUID(item),
                    ),
                ),
            )
            for item in self.targets
        )


class _DemandEvidence:
    def profile_hold(self, **kwargs):
        raise AssertionError(kwargs)

    def demand_content_policy(
        self,
        *,
        principal,
        demand_id,
        demand_version_id,
        demand_version_no,
        taxonomy_bundle_id,
        content_sha256,
        content,
        evaluated_at,
        organization_id,
    ):
        del principal, content, organization_id
        assert demand_version_no >= 1
        assert isinstance(taxonomy_bundle_id, UUID)
        return replace(
            content_policy(),
            demand_id=demand_id,
            demand_version_id=demand_version_id,
            content_sha256=content_sha256,
            evaluated_at=evaluated_at,
            valid_until=evaluated_at + timedelta(minutes=5),
        )

    def demand_hold(
        self,
        *,
        principal,
        demand_id,
        demand_version_id,
        prospective_aggregate_version,
        content_sha256,
        action,
        content_policy,
        evaluated_at,
        organization_id,
    ):
        assert action in {"SUBMIT_DEMAND", "VERIFY_DEMAND"}
        assert content_policy.demand_id == demand_id
        operation = (
            DemandPostgresOperation.SUBMIT
            if action == "SUBMIT_DEMAND"
            else DemandPostgresOperation.VERIFY
        )
        return replace(
            hold(
                operation,
                expected_version=prospective_aggregate_version - 1,
                actor_id=UUID(principal.user_id),
            ),
            organization_id=(
                UUID(principal.organization_id)
                if organization_id is None
                else organization_id
            ),
            demand_id=demand_id,
            demand_version_id=demand_version_id,
            content_sha256=content_sha256,
            evaluated_at=evaluated_at,
            valid_until=evaluated_at + timedelta(minutes=5),
        )

    def demand_rules(
        self,
        *,
        principal,
        demand_id,
        taxonomy_bundle_id,
        operation,
        evaluated_at,
        organization_id=None,
    ):
        del (
            principal,
            demand_id,
            taxonomy_bundle_id,
            operation,
            evaluated_at,
            organization_id,
        )
        return rule_requirement()


class RealPostgres18EditorProfileRepositoryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()
        cls.database = cls.postgres.create_database()
        _migrate_iam(cls.postgres, cls.database, "profile")
        with cls.admin(autocommit=False) as connection:
            cls.iam = seed_exact_creator_iam_authority(
                connection, now=datetime.now(timezone.utc)
            )
        catalog = ProfileMigrationCatalog.load(PROFILE_ROOT)
        PsycopgCreatorProfileMigrationRunner(
            conninfo=cls.postgres.conninfo(
                database=cls.database, user="profile_migration_runner"
            ),
            dbapi=psycopg,
            runner_version="editor-profile/1",
        ).run(
            catalog=catalog,
            contract_sources=ProfileContractSources(
                api_contract_bytes=(PLATFORM_ROOT / "contracts/api/profile-v1.openapi.yaml").read_bytes(),
                event_contract_bytes=(PLATFORM_ROOT / "contracts/events/profile-v1.schema.json").read_bytes(),
                domain_contract_bytes=(PLATFORM_ROOT / "contracts/domain/profile-version-v1.schema.json").read_bytes(),
            ),
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.postgres.drop_database(cls.database)
        cls.postgres.stop()

    @classmethod
    def admin(cls, *, autocommit: bool = True):
        return psycopg.connect(
            cls.postgres.admin_conninfo(database=cls.database),
            autocommit=autocommit,
        )

    def setUp(self) -> None:
        self.sources = []
        with self.admin(autocommit=False) as connection:
            reset_creator_profile_database(connection)

    def tearDown(self) -> None:
        for source in self.sources:
            source.close()

    def source(self) -> TrackingProfileConnectionSource:
        source = TrackingProfileConnectionSource(
            self.postgres.conninfo(database=self.database, user="profile_app")
        )
        self.sources.append(source)
        return source

    def repository(self) -> PsycopgEditorRepository:
        writer = self.source()
        reader = self.source()
        return PsycopgEditorRepository(
            profile_uow=PsycopgCreatorProfileUnitOfWorkFactory(
                connections=writer,
                event_validator=ProfileSchemaValidator(),
                response_validator=ProfileSchemaValidator(),
            ),
            demand_uows={},
            profile_reads=reader,
        )

    @property
    def principal(self) -> EditorPrincipal:
        return EditorPrincipal(
            user_id=str(ACTOR_USER_ID),
            session_id=str(SESSION_ID),
            organization_id=str(UUID("81000000-0000-4000-8000-000000000001")),
            role_codes=("CREATOR",),
        )

    def test_same_key_is_atomic_and_restart_projection_is_durable_and_rls_hidden(self) -> None:
        command = profile_command(CreatorProfilePostgresOperation.CREATE)
        repository = self.repository()
        with ThreadPoolExecutor(max_workers=2) as workers:
            results = tuple(workers.map(repository.execute_profile, (command, command)))
        self.assertEqual(sorted(result.replayed for result in results), [False, True])

        restarted = self.repository()
        dto = restarted.get_profile(
            principal=self.principal,
            profile_id=str(PROFILE_ID),
            authority=ProfileReadAuthority(self.iam.authority_marker_sha256),
        )
        self.assertEqual((dto.status, dto.revision, dto.versions), ("DRAFT", 1, ()))
        with self.admin() as connection:
            counts = connection.execute(
                "SELECT (SELECT count(*) FROM profile.creator_profiles),"
                "(SELECT count(*) FROM profile.command_receipts),"
                "(SELECT count(*) FROM audit.audit_events),"
                "(SELECT count(*) FROM infra.outbox_events)"
            ).fetchone()
        self.assertEqual(counts, (1, 1, 1, 1))

        with self.assertRaises(EditorServiceError) as hidden:
            restarted.get_profile(
                principal=self.principal,
                profile_id=str(PROFILE_ID),
                authority=ProfileReadAuthority(hashlib.sha256(b"wrong").digest()),
            )
        self.assertEqual(hidden.exception.code, "RESOURCE_NOT_FOUND")

    def test_distinct_key_concurrent_occ_has_one_winner_without_partial_receipt(self) -> None:
        repository = self.repository()
        repository.execute_profile(profile_command(CreatorProfilePostgresOperation.CREATE))
        with self.admin(autocommit=False) as connection:
            connection.execute(
                "INSERT INTO profile.taxonomy_bundle_markers "
                "(id,status,bundle_sha256,aggregate_version,updated_at) "
                "VALUES (%s,'ACTIVE',%s,1,transaction_timestamp())",
                (TAXONOMY_ID, hashlib.sha256(b"editor-taxonomy-v1").digest()),
            )
        first = profile_command(
            CreatorProfilePostgresOperation.SAVE_DRAFT,
            expected_version=1,
            idempotency_material="editor-profile-first-draft",
        )
        canonical = canonical_profile_version_bytes(
            profile_id=str(PROFILE_ID),
            version_no=1,
            taxonomy_bundle_id=str(TAXONOMY_ID),
            content=profile_content(),
        )
        first = replace(
            first,
            profile_version_id=SECOND_VERSION_ID,
            based_on_profile_version_id=None,
            canonical_profile_version_bytes=canonical,
            content_sha256=hashlib.sha256(canonical).digest(),
        )
        repository.execute_profile(first)
        contenders = tuple(
            replace(
                profile_command(
                    CreatorProfilePostgresOperation.SAVE_DRAFT,
                    expected_version=2,
                    idempotency_material=f"editor-profile-occ-{index}",
                ),
                profile_version_id=uuid4(),
                based_on_profile_version_id=SECOND_VERSION_ID,
            )
            for index in range(2)
        )

        def execute(command):
            try:
                return repository.execute_profile(command)
            except CreatorProfilePostgresDatabaseError as error:
                return error.code

        with ThreadPoolExecutor(max_workers=2) as workers:
            outcomes = tuple(workers.map(execute, contenders))
        self.assertEqual(sum(not isinstance(item, str) for item in outcomes), 1)
        self.assertEqual(sum(item == "PRECONDITION_FAILED" for item in outcomes), 1)
        with self.admin() as connection:
            counts = connection.execute(
                "SELECT (SELECT aggregate_version FROM profile.creator_profiles),"
                "(SELECT count(*) FROM profile.profile_versions),"
                "(SELECT count(*) FROM profile.command_receipts),"
                "(SELECT count(*) FROM audit.audit_events)"
            ).fetchone()
        self.assertEqual(counts, (3, 2, 3, 3))

    def test_http_compatible_service_create_edit_publish_and_restart_list(self) -> None:
        with self.admin(autocommit=False) as connection:
            connection.execute(
                "INSERT INTO profile.taxonomy_bundle_markers "
                "(id,status,bundle_sha256,aggregate_version,updated_at) "
                "VALUES (%s,'ACTIVE',%s,1,transaction_timestamp())",
                (TAXONOMY_ID, hashlib.sha256(b"editor-service-taxonomy").digest()),
            )
        authorities = _ProfileAuthorities(self.iam.authority_marker_sha256)
        service = PostgresEditorService(
            repository=self.repository(),
            authorities=authorities,
            evidence=_ProfileEvidence(),
            keys=_editor_keys(),
            clock=_SystemClock(),
        )
        principal = self.principal

        created = service.create_profile(
            principal=principal, idempotency_key="profile-service-create-0001"
        )
        self.assertEqual(
            service.create_profile(
                principal=principal,
                idempotency_key="profile-service-create-0001",
            ),
            created,
        )
        content = _editor_profile_content()
        drafted = service.save_profile_draft(
            principal=principal,
            profile_id=created.object_id,
            if_match=created.etag,
            base_version_id=None,
            taxonomy_bundle_id=str(TAXONOMY_ID),
            content=content,
            idempotency_key="profile-service-draft-0001",
        )
        self.assertEqual(
            service.save_profile_draft(
                principal=principal,
                profile_id=created.object_id,
                if_match=created.etag,
                base_version_id=None,
                taxonomy_bundle_id=str(TAXONOMY_ID),
                content=content,
                idempotency_key="profile-service-draft-0001",
            ),
            drafted,
        )
        changed_content = _editor_profile_content()
        changed_content["skills"][0]["skill_code"] = "SKILL.RESEARCH"
        with self.assertRaises(EditorServiceError) as changed_replay:
            service.save_profile_draft(
                principal=principal,
                profile_id=created.object_id,
                if_match=created.etag,
                base_version_id=None,
                taxonomy_bundle_id=str(TAXONOMY_ID),
                content=changed_content,
                idempotency_key="profile-service-draft-0001",
            )
        self.assertEqual(
            (changed_replay.exception.status, changed_replay.exception.code),
            (409, "IDEMPOTENCY_KEY_REUSED"),
        )
        published = service.publish_profile(
            principal=principal,
            profile_id=created.object_id,
            draft_version_id=drafted.current_version.version_id,
            if_match=drafted.etag,
            idempotency_key="profile-service-publish-0001",
        )
        self.assertEqual(
            service.publish_profile(
                principal=principal,
                profile_id=created.object_id,
                draft_version_id=drafted.current_version.version_id,
                if_match=drafted.etag,
                idempotency_key="profile-service-publish-0001",
            ),
            published,
        )

        self.assertEqual((published.status, published.revision), ("ACTIVE", 3))
        self.assertEqual(published.current_version.status, "PUBLISHED")
        self.assertEqual(published.current_version.content, content)
        with self.assertRaises(EditorServiceError) as second_publish:
            service.publish_profile(
                principal=principal,
                profile_id=created.object_id,
                draft_version_id=drafted.current_version.version_id,
                if_match=published.etag,
                idempotency_key="profile-service-second-publish-0001",
            )
        self.assertEqual(second_publish.exception.status, 404)
        with self.assertRaises(EditorServiceError) as unauthenticated_replay:
            service.publish_profile(
                principal=replace(principal, session_id=str(uuid4())),
                profile_id=created.object_id,
                draft_version_id=drafted.current_version.version_id,
                if_match=drafted.etag,
                idempotency_key="profile-service-publish-0001",
            )
        self.assertEqual(unauthenticated_replay.exception.status, 404)
        restarted = PostgresEditorService(
            repository=PsycopgEditorRepository(
                profile_uow=None,
                demand_uows={},
                profile_reads=PsycopgEditorConnectionSource(
                    settings=EditorPsycopgConnectionSettings(
                        conninfo=self.postgres.conninfo(
                            database=self.database, user="profile_app"
                        ),
                        expected_role="profile_app",
                        application_name="editor-profile-restart-read",
                    )
                ),
            ),
            authorities=_ProfileAuthorities(
                self.iam.authority_marker_sha256, targets=(created.object_id,)
            ),
            evidence=_ProfileEvidence(),
            keys=_editor_keys(),
            clock=_SystemClock(),
        )
        self.assertEqual(restarted.list_profiles(principal=principal), (published,))
        with self.admin() as connection:
            counts = connection.execute(
                "SELECT (SELECT count(*) FROM profile.creator_profiles),"
                "(SELECT count(*) FROM profile.profile_versions),"
                "(SELECT count(*) FROM profile.command_receipts),"
                "(SELECT count(*) FROM audit.audit_events),"
                "(SELECT count(*) FROM infra.outbox_events)"
            ).fetchone()
        self.assertEqual(counts, (1, 1, 3, 3, 2))


class RealPostgres18EditorDemandRepositoryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()
        cls.database = cls.postgres.create_database()
        _migrate_iam(cls.postgres, cls.database, "demand")
        with cls.admin(autocommit=False) as connection:
            seed_exact_demand_owner_iam_authority(
                connection, now=datetime.now(timezone.utc)
            )
        catalog = DemandMigrationCatalog.load(DEMAND_ROOT)
        DemandMigrationRunner(
            driver=PsycopgDemandMigrationDriver(
                settings=DemandMigrationSettings(
                    conninfo=cls.postgres.conninfo(
                        database=cls.database, user="demand_migration_runner"
                    ),
                    application_name="editor-demand-catalog",
                ),
                dbapi=psycopg,
            ),
            runner_version="editor-demand/1",
        ).run(
            catalog=catalog,
            contract_sources=DemandContractSources(
                api_contract_bytes=(PLATFORM_ROOT / "contracts/api/demand-v1.openapi.yaml").read_bytes(),
                event_contract_bytes=(PLATFORM_ROOT / "contracts/events/demand-v1.schema.json").read_bytes(),
                content_contract_bytes=(PLATFORM_ROOT / "contracts/domain/demand-content-v1.schema.json").read_bytes(),
            ),
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.postgres.drop_database(cls.database)
        cls.postgres.stop()

    @classmethod
    def admin(cls, *, autocommit: bool = True):
        return psycopg.connect(
            cls.postgres.admin_conninfo(database=cls.database),
            autocommit=autocommit,
        )

    def setUp(self) -> None:
        self.sources = []
        with self.admin(autocommit=False) as connection:
            reset_demand_postgres_state(connection)

    def tearDown(self) -> None:
        for source in self.sources:
            source.close()

    def source(self, role: str = "demand_self") -> TrackingDemandConnectionSource:
        source = TrackingDemandConnectionSource(
            self.postgres.conninfo(database=self.database, user=role)
        )
        self.sources.append(source)
        return source

    def repository(
        self, *, settings: Optional[DemandPostgresSettings] = None
    ) -> PsycopgEditorRepository:
        writer = self.source()
        reader = self.source()
        uow = PsycopgDemandUnitOfWorkFactory(
            connections=writer,
            event_validator=DemandSchemaValidator(),
            response_validator=DemandSchemaValidator(),
            settings=settings,
        )
        return PsycopgEditorRepository(
            profile_uow=None,
            demand_uows={
                DemandPostgresOperation.CREATE: uow,
                DemandPostgresOperation.CREATE_VERSION: uow,
            },
            demand_owner_reads=reader,
        )

    def _restore_verify_replay_authority(
        self,
        *,
        replacement_session_id: UUID,
        replacement_duty_id: UUID,
        receipt_key_policy,
    ) -> None:
        with self.admin(autocommit=False) as connection:
            connection.execute(
                "SET LOCAL session_replication_role = 'replica'"
            )
            connection.execute(
                "DELETE FROM iam.platform_duty_grants WHERE id=%s",
                (replacement_duty_id,),
            )
            connection.execute(
                "DELETE FROM iam.sessions WHERE id=%s",
                (replacement_session_id,),
            )
            connection.execute(
                "UPDATE iam.sessions SET status='ACTIVE',revoked_at=NULL,"
                "revocation_reason_code=NULL,aggregate_version=1,"
                "updated_at=transaction_timestamp() WHERE id=%s",
                (REVIEWER_SESSION_ID,),
            )
            connection.execute(
                "UPDATE iam.session_families SET current_generation=1,"
                "aggregate_version=1,updated_at=transaction_timestamp() "
                "WHERE id=(SELECT family_id FROM iam.sessions WHERE id=%s)",
                (REVIEWER_SESSION_ID,),
            )
            connection.execute(
                "UPDATE iam.platform_duty_grants SET revoked_at=NULL,"
                "revocation_reason_code=NULL,aggregate_version=1,"
                "updated_at=transaction_timestamp() WHERE id=%s",
                (REVIEWER_DUTY_GRANT_ID,),
            )
            connection.execute("SET LOCAL session_replication_role = 'origin'")
            connection.execute(
                "UPDATE demand.receipt_key_policy SET "
                "active_idempotency_key_id=%s,active_payload_key_id=%s,"
                "retained_idempotency_key_ids=%s,"
                "retained_payload_key_ids=%s,updated_at=%s "
                "WHERE singleton_key",
                receipt_key_policy,
            )

    @property
    def principal(self) -> EditorPrincipal:
        return EditorPrincipal(
            user_id=str(DEMAND_ACTOR_USER_ID),
            session_id=str(DEMAND_SESSION_ID),
            organization_id=str(ORGANIZATION_ID),
            role_codes=("DEMAND_OWNER",),
        )

    def test_same_key_restart_projection_and_actor_org_scope(self) -> None:
        command = demand_command(DemandPostgresOperation.CREATE)
        # Leave enough lock budget to observe replay on a CPU-limited runner.
        repository = self.repository(
            settings=DemandPostgresSettings(lock_timeout_ms=10_000)
        )
        with ThreadPoolExecutor(max_workers=2) as workers:
            results = tuple(workers.map(repository.execute_demand, (command, command)))
        self.assertEqual(sorted(result.replayed for result in results), [False, True])

        restarted = self.repository()
        dto = restarted.get_demand(
            principal=self.principal,
            demand_id=str(DEMAND_ID),
            authority=DemandReadAuthority(
                DemandPostgresOperation.CREATE,
                owner_authority_marker(DemandPostgresOperation.CREATE),
            ),
        )
        self.assertEqual((dto.status, dto.revision, len(dto.versions)), ("DRAFT", 1, 1))
        self.assertEqual(dto.current_version.version_id, dto.versions[0].version_id)
        with self.admin() as connection:
            counts = connection.execute(
                "SELECT (SELECT count(*) FROM demand.demands),"
                "(SELECT count(*) FROM demand.demand_versions),"
                "(SELECT count(*) FROM demand.command_receipts),"
                "(SELECT count(*) FROM audit.audit_events),"
                "(SELECT count(*) FROM infra.outbox_events)"
            ).fetchone()
        self.assertEqual(counts, (1, 1, 1, 1, 2))

        other_org = replace(
            self.principal,
            organization_id="81000000-0000-4000-8000-000000000002",
        )
        with self.assertRaises(EditorServiceError) as hidden:
            restarted.get_demand(
                principal=other_org,
                demand_id=str(DEMAND_ID),
                authority=DemandReadAuthority(
                    DemandPostgresOperation.CREATE,
                    owner_authority_marker(DemandPostgresOperation.CREATE),
                ),
            )
        self.assertEqual(hidden.exception.code, "RESOURCE_NOT_FOUND")

        with self.assertRaises(EditorServiceError) as stale_marker:
            restarted.get_demand(
                principal=self.principal,
                demand_id=str(DEMAND_ID),
                authority=DemandReadAuthority(
                    DemandPostgresOperation.CREATE,
                    hashlib.sha256(b"stale-owner-authority-marker").digest(),
                ),
            )
        self.assertEqual(stale_marker.exception.code, "RESOURCE_NOT_FOUND")

        non_owner = EditorPrincipal(
            user_id=str(REVIEWER_USER_ID),
            session_id=str(REVIEWER_SESSION_ID),
            organization_id=str(ORGANIZATION_ID),
            role_codes=("DEMAND_OWNER",),
        )
        with self.assertRaises(EditorServiceError) as non_owner_hidden:
            restarted.get_demand(
                principal=non_owner,
                demand_id=str(DEMAND_ID),
                authority=DemandReadAuthority(
                    DemandPostgresOperation.CREATE,
                    owner_authority_marker(DemandPostgresOperation.CREATE),
                ),
            )
        self.assertEqual(non_owner_hidden.exception.code, "RESOURCE_NOT_FOUND")

        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="demand_self"),
            autocommit=True,
        ) as runtime_connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                runtime_connection.execute(
                    "SELECT id FROM demand.demand_reviews LIMIT 1"
                ).fetchall()

    def test_distinct_key_concurrent_demand_occ_has_one_winner(self) -> None:
        # The losing command must reach OCC after the winner releases its lock.
        repository = self.repository(
            settings=DemandPostgresSettings(lock_timeout_ms=10_000)
        )
        repository.execute_demand(demand_command(DemandPostgresOperation.CREATE))
        contenders = tuple(
            replace(
                demand_command(
                    DemandPostgresOperation.CREATE_VERSION,
                    expected_version=1,
                    idempotency_material=f"editor-demand-occ-{index}",
                    command_variant=index + 1,
                ),
                demand_version_id=uuid4(),
            )
            for index in range(2)
        )

        def execute(command):
            try:
                return repository.execute_demand(command)
            except DemandPostgresDatabaseError as error:
                return error.code

        with ThreadPoolExecutor(max_workers=2) as workers:
            outcomes = tuple(workers.map(execute, contenders))
        self.assertEqual(sum(not isinstance(item, str) for item in outcomes), 1)
        self.assertEqual(sum(item == "PRECONDITION_FAILED" for item in outcomes), 1)
        with self.admin() as connection:
            counts = connection.execute(
                "SELECT (SELECT aggregate_version FROM demand.demands),"
                "(SELECT count(*) FROM demand.demand_versions),"
                "(SELECT count(*) FROM demand.command_receipts),"
                "(SELECT count(*) FROM audit.audit_events),"
                "(SELECT count(*) FROM infra.outbox_events)"
            ).fetchone()
        self.assertEqual(counts, (2, 2, 2, 2, 3))

    def test_verify_completed_receipt_replays_before_active_discovery_once(self) -> None:
        with self.admin(autocommit=False) as connection:
            seed_demand_operation_graph(connection, DemandPostgresOperation.VERIFY)

        review_uow = PsycopgDemandUnitOfWorkFactory(
            connections=self.source("demand_review"),
            event_validator=DemandSchemaValidator(),
            response_validator=DemandSchemaValidator(),
        )
        repository = PsycopgEditorRepository(
            profile_uow=None,
            demand_uows={DemandPostgresOperation.VERIFY: review_uow},
            demand_review_reads=self.source("demand_review"),
        )

        class Authorities(_DemandAuthorities):
            def __init__(self):
                super().__init__()
                self.calls = 0

            def demand(self, **facts):
                self.calls += 1
                return super().demand(**facts)

        authorities = Authorities()
        probe = PsycopgDemandCompletedVerifyReceiptProbe(
            connections=self.source("demand_review"),
            idempotency_keys=(("demand-idempotency-2026-01", b"c" * 32),),
            payload_hash_keys=(("demand-payload-2026-01", b"d" * 32),),
        )
        service = PostgresEditorService(
            repository=repository,
            authorities=authorities,
            evidence=_DemandEvidence(),
            keys=_editor_keys(),
            clock=_SystemClock(),
            completed_verify_receipts=probe,
        )
        reviewer = EditorPrincipal(
            user_id=str(REVIEWER_USER_ID),
            session_id=str(REVIEWER_SESSION_ID),
            organization_id=None,
            role_codes=("OPERATIONS_REVIEWER",),
        )
        current = repository.get_demand(
            principal=reviewer,
            demand_id=str(DEMAND_ID),
            authority=DemandReadAuthority(
                DemandPostgresOperation.VERIFY,
                reviewer_authority_marker(DemandPostgresOperation.VERIFY),
                ASSIGNMENT_ID,
                ORGANIZATION_ID,
            ),
        )
        request = dict(
            principal=reviewer,
            demand_id=str(DEMAND_ID),
            assignment_id=str(ASSIGNMENT_ID),
            if_match=current.etag,
            budget_health_code="HEALTHY",
            risk_code="STANDARD",
            evidence_codes=("SCOPE_COMPLETE", "ACCEPTANCE_TESTABLE"),
            idempotency_key="verify-completed-replay-0001",
        )

        first = service.verify_demand(**request)
        with self.admin() as connection:
            receipt_id = connection.execute(
                "SELECT receipt_id FROM demand.command_receipts"
            ).fetchone()[0]
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="demand_review"),
            autocommit=False,
        ) as connection:
            connection.execute(
                "SELECT set_config(%s,%s,true)",
                ("app.scope_kind", "DEMAND_VERIFY_REPLAY"),
            )
            connection.execute(
                "SELECT set_config(%s,%s,true)", ("app.operation", "VERIFY")
            )
            connection.execute(
                "SELECT set_config(%s,%s,true)",
                ("app.command_id", str(receipt_id)),
            )
            context = connection.execute(
                "SELECT session_user,current_user,"
                "current_setting('app.scope_kind',true),"
                "current_setting('app.operation',true),"
                "current_setting('app.command_id',true)"
            ).fetchone()
            self.assertEqual(
                connection.execute(
                    "SELECT receipt_id FROM demand.command_receipts "
                    "WHERE receipt_id=%s FOR SHARE",
                    (receipt_id,),
                ).fetchone(),
                (receipt_id,),
                context,
            )
            with self.assertRaisesRegex(
                psycopg.errors.InsufficientPrivilege,
                "DEMAND_VERIFY_REPLAY_IS_READ_ONLY",
            ):
                connection.execute(
                    "UPDATE demand.command_receipts "
                    "SET retain_until=retain_until WHERE receipt_id=%s",
                    (receipt_id,),
                )
            connection.rollback()
        replay = service.verify_demand(**request)

        self.assertEqual((first.status, first.revision), ("VERIFIED", 2))
        self.assertEqual(replay, first)
        self.assertEqual(authorities.calls, 1)
        with self.assertRaises(EditorServiceError) as changed_payload:
            service.verify_demand(**dict(request, if_match='"invalid"'))
        self.assertEqual(
            (changed_payload.exception.status, changed_payload.exception.code),
            (409, "IDEMPOTENCY_KEY_REUSED"),
        )

        for column, corrupt_value in (
            (
                "principal_id",
                UUID("10000000-0000-4000-8000-000000000099"),
            ),
            ("command_name", "VerifyDemandCorrupt"),
        ):
            with self.admin() as connection:
                original = connection.execute(
                    f"SELECT {column} FROM demand.command_receipts "
                    "WHERE receipt_id=%s",
                    (receipt_id,),
                ).fetchone()[0]
                connection.execute(
                    f"UPDATE demand.command_receipts SET {column}=%s "
                    "WHERE receipt_id=%s",
                    (corrupt_value, receipt_id),
                )
            with self.assertRaises(EditorServiceError) as corrupt:
                service.verify_demand(**request)
            self.assertEqual(
                (corrupt.exception.status, corrupt.exception.code),
                (503, "SERVICE_UNAVAILABLE"),
            )
            with self.admin() as connection:
                connection.execute(
                    f"UPDATE demand.command_receipts SET {column}=%s "
                    "WHERE receipt_id=%s",
                    (original, receipt_id),
                )

        replacement_session_id = UUID(
            "20000000-0000-4000-8000-000000000099"
        )
        replacement_duty_id = UUID(
            "23000000-0000-4000-8000-000000000099"
        )
        with self.admin() as connection:
            receipt_key_policy = connection.execute(
                "SELECT active_idempotency_key_id,active_payload_key_id,"
                "retained_idempotency_key_ids,retained_payload_key_ids,"
                "updated_at FROM demand.receipt_key_policy "
                "WHERE singleton_key"
            ).fetchone()
        self.assertIsNotNone(receipt_key_policy)
        self.addCleanup(
            self._restore_verify_replay_authority,
            replacement_session_id=replacement_session_id,
            replacement_duty_id=replacement_duty_id,
            receipt_key_policy=receipt_key_policy,
        )
        with self.admin() as connection:
            connection.execute(
                "UPDATE iam.sessions SET status='REVOKED',"
                "revoked_at=transaction_timestamp(),"
                "revocation_reason_code='ROTATED',"
                "aggregate_version=aggregate_version+1,"
                "updated_at=transaction_timestamp() WHERE id=%s",
                (REVIEWER_SESSION_ID,),
            )
            connection.execute(
                "UPDATE iam.session_families SET current_generation=2,"
                "aggregate_version=aggregate_version+1,"
                "updated_at=transaction_timestamp() WHERE id=("
                "SELECT family_id FROM iam.sessions WHERE id=%s)",
                (REVIEWER_SESSION_ID,),
            )
            connection.execute(
                "INSERT INTO iam.sessions ("
                "id,user_id,family_id,generation,predecessor_session_id,"
                "handle_digest,handle_digest_key_id,csrf_salt,csrf_key_id,"
                "csrf_digest,verified_contact_point_id,verified_at,"
                "verified_for_invitation_id,auth_transaction_id,auth_time,"
                "acr_code,amr_codes,created_at,last_activity_at,"
                "idle_expires_at,absolute_expires_at,updated_at,device_label,"
                "status,rotation_reason,revoked_at,revocation_reason_code,"
                "aggregate_version) SELECT %s,user_id,family_id,2,id,"
                "sha256(convert_to('replacement-session','UTF8')),"
                "handle_digest_key_id,"
                "sha256(convert_to('replacement-csrf-salt','UTF8')),"
                "csrf_key_id,sha256(convert_to('replacement-csrf','UTF8')),"
                "NULL,NULL,NULL,auth_transaction_id,auth_time,acr_code,"
                "amr_codes,transaction_timestamp(),transaction_timestamp(),"
                "transaction_timestamp()+interval '1 day',absolute_expires_at,"
                "transaction_timestamp(),device_label,'ACTIVE','LOGIN',"
                "NULL,NULL,1 FROM iam.sessions WHERE id=%s",
                (replacement_session_id, REVIEWER_SESSION_ID),
            )
        replacement_reviewer = replace(
            reviewer, session_id=str(replacement_session_id)
        )
        replacement_request = dict(request, principal=replacement_reviewer)
        self.assertEqual(service.verify_demand(**replacement_request), first)
        with self.assertRaises(EditorServiceError) as revoked_session:
            service.verify_demand(**request)
        self.assertEqual(
            (revoked_session.exception.status, revoked_session.exception.code),
            (404, "RESOURCE_NOT_FOUND"),
        )

        with self.admin() as connection:
            connection.execute(
                "UPDATE iam.platform_duty_grants SET "
                "revoked_at=transaction_timestamp(),"
                "revocation_reason_code='ADMIN_REVOKED',"
                "aggregate_version=aggregate_version+1,"
                "updated_at=transaction_timestamp() WHERE id=%s",
                (REVIEWER_DUTY_GRANT_ID,),
            )
        with self.assertRaises(EditorServiceError) as revoked_duty:
            service.verify_demand(**replacement_request)
        self.assertEqual(
            (revoked_duty.exception.status, revoked_duty.exception.code),
            (404, "RESOURCE_NOT_FOUND"),
        )

        with self.admin() as connection:
            connection.execute(
                "INSERT INTO iam.platform_duty_grants ("
                "id,user_id,duty_code,granted_by_kind,granted_by_id,granted_at,"
                "expires_at,revoked_at,revocation_reason_code,aggregate_version,"
                "created_at,updated_at) VALUES ("
                "%s,%s,'OPERATIONS_REVIEWER','SYSTEM',%s,"
                "transaction_timestamp(),NULL,NULL,NULL,1,"
                "transaction_timestamp(),transaction_timestamp())",
                (replacement_duty_id, REVIEWER_USER_ID, DEMAND_ACTOR_USER_ID),
            )
        self.assertEqual(service.verify_demand(**replacement_request), first)

        with self.admin() as connection:
            connection.execute(
                "UPDATE demand.receipt_key_policy SET "
                "active_idempotency_key_id='demand-idempotency-2026-02',"
                "active_payload_key_id='demand-payload-2026-02',"
                "retained_idempotency_key_ids=ARRAY["
                "'demand-idempotency-2026-02','demand-idempotency-2026-01'],"
                "retained_payload_key_ids=ARRAY["
                "'demand-payload-2026-02','demand-payload-2026-01'],"
                "updated_at=transaction_timestamp() WHERE singleton_key"
            )
        service._keys = replace(
            service._keys,
            demand_idempotency_key=b"f" * 32,
            demand_payload_key=b"g" * 32,
            demand_idempotency_key_id="demand-idempotency-2026-02",
            demand_payload_key_id="demand-payload-2026-02",
        )
        service._completed_verify_receipts = (
            PsycopgDemandCompletedVerifyReceiptProbe(
                connections=self.source("demand_review"),
                idempotency_keys=(
                    (
                        "demand-idempotency-2026-02",
                        service._keys.demand_idempotency_key,
                    ),
                ),
                payload_hash_keys=((
                    "demand-payload-2026-02",
                    service._keys.demand_payload_key,
                ),),
            )
        )
        with self.assertRaises(EditorServiceError) as omitted_retained_key:
            service.verify_demand(**replacement_request)
        self.assertEqual(
            (
                omitted_retained_key.exception.status,
                omitted_retained_key.exception.code,
            ),
            (503, "SERVICE_UNAVAILABLE"),
        )
        service._completed_verify_receipts = (
            PsycopgDemandCompletedVerifyReceiptProbe(
                connections=self.source("demand_review"),
                idempotency_keys=(
                    (
                        "demand-idempotency-2026-02",
                        service._keys.demand_idempotency_key,
                    ),
                    ("demand-idempotency-2026-01", b"c" * 32),
                ),
                payload_hash_keys=(
                    (
                        "demand-payload-2026-02",
                        service._keys.demand_payload_key,
                    ),
                    ("demand-payload-2026-01", b"d" * 32),
                ),
            )
        )
        self.assertEqual(service.verify_demand(**replacement_request), first)

        corrupt_policies = (
            (
                "retained_idempotency_key_ids",
                "ARRAY['demand-idempotency-2026-02',NULL]::text[]",
            ),
            (
                "retained_payload_key_ids",
                "ARRAY['demand-payload-2026-02',NULL]::text[]",
            ),
            (
                "retained_idempotency_key_ids",
                "ARRAY['demand-idempotency-2026-02',"
                "'demand-idempotency-2026-01',"
                "'demand-idempotency-2026-01']::text[]",
            ),
            (
                "retained_idempotency_key_ids",
                "'[0:1]={demand-idempotency-2026-02,"
                "demand-idempotency-2026-01}'::text[]",
            ),
            (
                "retained_payload_key_ids",
                "ARRAY['demand-payload-2026-02',"
                "'demand-payload-2026-01',"
                "'demand-idempotency-2026-01']::text[]",
            ),
        )
        for column, corrupt_expression in corrupt_policies:
            with self.subTest(
                column=column, corrupt_expression=corrupt_expression
            ):
                with self.admin() as connection:
                    connection.execute(
                        f"UPDATE demand.receipt_key_policy SET {column}="
                        f"{corrupt_expression},updated_at="
                        "transaction_timestamp() WHERE singleton_key"
                    )
                with self.assertRaises(EditorServiceError) as corrupt_policy:
                    service.verify_demand(**replacement_request)
                self.assertEqual(
                    (
                        corrupt_policy.exception.status,
                        corrupt_policy.exception.code,
                    ),
                    (503, "SERVICE_UNAVAILABLE"),
                )
                with self.admin() as connection:
                    connection.execute(
                        "UPDATE demand.receipt_key_policy SET "
                        "retained_idempotency_key_ids=ARRAY["
                        "'demand-idempotency-2026-02',"
                        "'demand-idempotency-2026-01'],"
                        "retained_payload_key_ids=ARRAY["
                        "'demand-payload-2026-02',"
                        "'demand-payload-2026-01'],"
                        "updated_at=transaction_timestamp() "
                        "WHERE singleton_key"
                    )
        self.assertEqual(authorities.calls, 1)
        with self.admin() as connection:
            counts = connection.execute(
                "SELECT (SELECT count(*) FROM demand.command_receipts),"
                "(SELECT count(*) FROM demand.demand_reviews),"
                "(SELECT count(*) FROM audit.audit_events),"
                "(SELECT count(*) FROM infra.outbox_events),"
                "(SELECT count(*) FROM demand.demand_review_assignments "
                "WHERE status='COMPLETED')"
            ).fetchone()
        self.assertEqual(counts, (1, 1, 1, 1, 1))

    def test_verify_in_progress_receipt_is_exact_outcome_unknown(self) -> None:
        with self.admin(autocommit=False) as connection:
            seed_demand_operation_graph(connection, DemandPostgresOperation.VERIFY)

        review_uow = PsycopgDemandUnitOfWorkFactory(
            connections=self.source("demand_review"),
            event_validator=DemandSchemaValidator(),
            response_validator=DemandSchemaValidator(),
        )
        repository = PsycopgEditorRepository(
            profile_uow=None,
            demand_uows={DemandPostgresOperation.VERIFY: review_uow},
            demand_review_reads=self.source("demand_review"),
        )

        class Authorities(_DemandAuthorities):
            def __init__(self):
                super().__init__()
                self.calls = 0

            def demand(self, **facts):
                self.calls += 1
                return super().demand(**facts)

        authorities = Authorities()
        probe = PsycopgDemandCompletedVerifyReceiptProbe(
            connections=self.source("demand_review"),
            idempotency_keys=(("demand-idempotency-2026-01", b"c" * 32),),
            payload_hash_keys=(("demand-payload-2026-01", b"d" * 32),),
        )
        service = PostgresEditorService(
            repository=repository,
            authorities=authorities,
            evidence=_DemandEvidence(),
            keys=_editor_keys(),
            clock=_SystemClock(),
            completed_verify_receipts=probe,
        )
        reviewer = EditorPrincipal(
            user_id=str(REVIEWER_USER_ID),
            session_id=str(REVIEWER_SESSION_ID),
            organization_id=None,
            role_codes=("OPERATIONS_REVIEWER",),
        )
        current = repository.get_demand(
            principal=reviewer,
            demand_id=str(DEMAND_ID),
            authority=DemandReadAuthority(
                DemandPostgresOperation.VERIFY,
                reviewer_authority_marker(DemandPostgresOperation.VERIFY),
                ASSIGNMENT_ID,
                ORGANIZATION_ID,
            ),
        )
        idempotency_key = "verify-in-progress-replay-0001"
        evidence_codes = ("SCOPE_COMPLETE", "ACCEPTANCE_TESTABLE")
        payload = {
            "assignment_id": str(ASSIGNMENT_ID),
            "budget_health_code": "HEALTHY",
            "demand_id": str(DEMAND_ID),
            "evidence_codes": tuple(sorted(evidence_codes)),
            "if_match": current.etag,
            "risk_code": "STANDARD",
        }
        canonical_payload = json.dumps(
            {"operation": "VerifyDemand", "payload": payload},
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        command_id = service._command_id(
            reviewer, "VERIFY_DEMAND", idempotency_key
        )
        with self.admin() as connection:
            connection.execute(
                "INSERT INTO demand.command_receipts ("
                "receipt_id,principal_kind,principal_id,organization_id,"
                "command_name,command_version,idempotency_key_digest_key_id,"
                "idempotency_key_digest,payload_hash_key_id,"
                "canonicalization_version,payload_hash,http_method,"
                "canonical_path,if_match_version,status,retain_until,created_at"
                ") VALUES (%s,'USER',%s,%s,'VerifyDemand',1,%s,%s,%s,"
                "'demand-command-json-v1',%s,'POST',%s,%s,'IN_PROGRESS',"
                "transaction_timestamp()+interval '1 day',"
                "transaction_timestamp())",
                (
                    command_id,
                    REVIEWER_USER_ID,
                    ORGANIZATION_ID,
                    "demand-idempotency-2026-01",
                    hmac.new(
                        b"c" * 32,
                        idempotency_key.encode("utf-8"),
                        hashlib.sha256,
                    ).digest(),
                    "demand-payload-2026-01",
                    hmac.new(
                        b"d" * 32,
                        canonical_payload,
                        hashlib.sha256,
                    ).digest(),
                    "/v1/operations/demand-review-assignments/"
                    f"{ASSIGNMENT_ID}/verify",
                    current.revision,
                ),
            )

        with self.assertRaises(EditorServiceError) as raised:
            service.verify_demand(
                principal=reviewer,
                demand_id=str(DEMAND_ID),
                assignment_id=str(ASSIGNMENT_ID),
                if_match=current.etag,
                budget_health_code="HEALTHY",
                risk_code="STANDARD",
                evidence_codes=evidence_codes,
                idempotency_key=idempotency_key,
            )
        self.assertEqual(
            (raised.exception.status, raised.exception.code),
            (503, "COMMAND_OUTCOME_UNKNOWN"),
        )
        self.assertEqual(authorities.calls, 0)

    def test_http_compatible_service_create_edit_submit_and_reviewer_findings(self) -> None:
        owner_write = self.source("demand_self")
        review_write = self.source("demand_review")
        owner_uow = PsycopgDemandUnitOfWorkFactory(
            connections=owner_write,
            event_validator=DemandSchemaValidator(),
            response_validator=DemandSchemaValidator(),
        )
        review_uow = PsycopgDemandUnitOfWorkFactory(
            connections=review_write,
            event_validator=DemandSchemaValidator(),
            response_validator=DemandSchemaValidator(),
        )
        repository = PsycopgEditorRepository(
            profile_uow=None,
            demand_uows={
                DemandPostgresOperation.CREATE: owner_uow,
                DemandPostgresOperation.CREATE_VERSION: owner_uow,
                DemandPostgresOperation.SUBMIT: owner_uow,
                DemandPostgresOperation.REQUEST_CHANGES: review_uow,
            },
            demand_owner_reads=self.source("demand_self"),
            demand_review_reads=self.source("demand_review"),
        )
        authorities = _DemandAuthorities()
        service = PostgresEditorService(
            repository=repository,
            authorities=authorities,
            evidence=_DemandEvidence(),
            keys=_editor_keys(),
            clock=_SystemClock(),
        )
        owner = self.principal
        content = _editor_demand_content()
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        created = service.create_demand(
            principal=owner,
            taxonomy_bundle_id="50000000-0000-4000-8000-000000000001",
            content=content,
            client_reference="internal-pilot-demand-service-0001",
            expires_at=expires_at,
            idempotency_key="demand-service-create-0001",
        )
        self.assertEqual(
            service.create_demand(
                principal=owner,
                taxonomy_bundle_id="50000000-0000-4000-8000-000000000001",
                content=content,
                client_reference="internal-pilot-demand-service-0001",
                expires_at=expires_at,
                idempotency_key="demand-service-create-0001",
            ).object_id,
            created.object_id,
        )
        edited_content = _editor_demand_content()
        edited_content["problem"]["background"] = (
            "Reduce energy waste with an editable, reviewed pilot plan."
        )
        drafted = service.save_demand_draft(
            principal=owner,
            demand_id=created.object_id,
            if_match=created.etag,
            base_version_id=created.current_version.version_id,
            taxonomy_bundle_id="50000000-0000-4000-8000-000000000001",
            content=edited_content,
            idempotency_key="demand-service-draft-0001",
        )
        self.assertEqual(
            service.save_demand_draft(
                principal=owner,
                demand_id=created.object_id,
                if_match=created.etag,
                base_version_id=created.current_version.version_id,
                taxonomy_bundle_id=str(TAXONOMY_ID),
                content=edited_content,
                idempotency_key="demand-service-draft-0001",
            ),
            drafted,
        )
        changed_content = _editor_demand_content()
        changed_content["problem"]["background"] = "A competing editor change."
        with self.assertRaises(EditorServiceError) as changed_replay:
            service.save_demand_draft(
                principal=owner,
                demand_id=created.object_id,
                if_match=created.etag,
                base_version_id=created.current_version.version_id,
                taxonomy_bundle_id=str(TAXONOMY_ID),
                content=changed_content,
                idempotency_key="demand-service-draft-0001",
            )
        self.assertEqual(
            (changed_replay.exception.status, changed_replay.exception.code),
            (409, "IDEMPOTENCY_KEY_REUSED"),
        )
        with self.assertRaises(EditorServiceError) as stale_write:
            service.save_demand_draft(
                principal=owner,
                demand_id=created.object_id,
                if_match=created.etag,
                base_version_id=created.current_version.version_id,
                taxonomy_bundle_id=str(TAXONOMY_ID),
                content=changed_content,
                idempotency_key="demand-service-stale-draft-0001",
            )
        self.assertEqual(
            (stale_write.exception.status, stale_write.exception.code),
            (412, "PRECONDITION_FAILED"),
        )
        self.assertEqual(stale_write.exception.etag, drafted.etag)
        self.assertEqual(stale_write.exception.details, {
            "current": {
                "version_id": drafted.current_version.version_id,
                "content": edited_content,
            },
            "base": {
                "version_id": created.current_version.version_id,
                "content": content,
            },
            "yours": {
                "version_id": created.current_version.version_id,
                "content": changed_content,
            },
        })
        submitted = service.submit_demand(
            principal=owner,
            demand_id=created.object_id,
            if_match=drafted.etag,
            idempotency_key="demand-service-submit-0001",
        )
        self.assertEqual(
            service.submit_demand(
                principal=owner,
                demand_id=created.object_id,
                if_match=drafted.etag,
                idempotency_key="demand-service-submit-0001",
            ),
            submitted,
        )
        self.assertEqual((submitted.status, submitted.revision), ("SUBMITTED", 3))
        with self.assertRaises(EditorServiceError) as second_submission:
            service.submit_demand(
                principal=owner,
                demand_id=created.object_id,
                if_match=submitted.etag,
                idempotency_key="demand-service-second-submit-0001",
            )
        self.assertEqual(
            (second_submission.exception.status, second_submission.exception.code),
            (409, "INVALID_STATE_TRANSITION"),
        )
        with self.assertRaises(EditorServiceError) as unauthenticated_replay:
            service.submit_demand(
                principal=replace(owner, session_id=str(uuid4())),
                demand_id=created.object_id,
                if_match=drafted.etag,
                idempotency_key="demand-service-submit-0001",
            )
        self.assertEqual(unauthenticated_replay.exception.status, 404)

        assignment_id = uuid4()
        target_id = UUID(created.object_id)
        review_marker = reviewer_authority_marker(
            DemandPostgresOperation.REQUEST_CHANGES,
            demand_id=target_id,
            assignment_id=assignment_id,
        )
        with self.admin(autocommit=False) as connection:
            submission_id, version_id = connection.execute(
                "SELECT current_submission_id,current_version_id "
                "FROM demand.demands WHERE id=%s",
                (target_id,),
            ).fetchone()
            connection.execute(
                "INSERT INTO demand.demand_review_assignments ("
                "id,organization_id,demand_id,submission_id,demand_version_id,"
                "reviewer_user_id,duty_grant_id,duty_grant_version,purpose_code,"
                "conflict_attestation_sha256,authority_marker_sha256,status,"
                "expires_at,aggregate_version,created_at,completed_at) VALUES ("
                "%s,%s,%s,%s,%s,%s,%s,1,'DEMAND_REVIEW',%s,%s,'ACTIVE',"
                "%s,1,transaction_timestamp(),NULL)",
                (
                    assignment_id,
                    ORGANIZATION_ID,
                    target_id,
                    submission_id,
                    version_id,
                    REVIEWER_USER_ID,
                    REVIEWER_DUTY_GRANT_ID,
                    hashlib.sha256(b"editor-review-conflict-attestation").digest(),
                    review_marker,
                    datetime.now(timezone.utc) + timedelta(hours=1),
                ),
            )
        reviewer = EditorPrincipal(
            user_id=str(REVIEWER_USER_ID),
            session_id=str(REVIEWER_SESSION_ID),
            # Independent platform-duty reviewers do not inherit an
            # organization workspace.  The exact assignment authority carries
            # the target organization into both the write and projection.
            organization_id=None,
            role_codes=("OPERATIONS_REVIEWER",),
        )
        reviewed = service.request_demand_changes(
            principal=reviewer,
            demand_id=created.object_id,
            assignment_id=str(assignment_id),
            if_match=submitted.etag,
            reason_codes=("SCOPE_UNCLEAR",),
            required_field_paths=("/scope",),
            idempotency_key="demand-service-findings-0001",
        )
        self.assertEqual((reviewed.status, reviewed.revision), ("NEEDS_CHANGES", 4))
        self.assertEqual(len(reviewed.findings), 1)
        self.assertEqual(reviewed.findings[0].required_field_paths, ("/scope",))

        restarted = PostgresEditorService(
            repository=PsycopgEditorRepository(
                profile_uow=None,
                demand_uows={},
                demand_owner_reads=PsycopgEditorConnectionSource(
                    settings=EditorPsycopgConnectionSettings(
                        conninfo=self.postgres.conninfo(
                            database=self.database, user="demand_self"
                        ),
                        expected_role="demand_self",
                        application_name="editor-demand-restart-read",
                    )
                ),
            ),
            authorities=_DemandAuthorities(targets=(created.object_id,)),
            evidence=_DemandEvidence(),
            keys=_editor_keys(),
            clock=_SystemClock(),
        )
        listed = restarted.list_demands(principal=owner)
        self.assertEqual((len(listed), listed[0].status, listed[0].revision), (1, "NEEDS_CHANGES", 4))
        self.assertEqual(len(listed[0].findings), 1)
        self.assertEqual(listed[0].findings[0].reason_codes, ("SCOPE_UNCLEAR",))
        self.assertEqual(listed[0].findings[0].required_field_paths, ("/scope",))
        with self.admin() as connection:
            counts = connection.execute(
                "SELECT (SELECT count(*) FROM demand.demands),"
                "(SELECT count(*) FROM demand.demand_versions),"
                "(SELECT count(*) FROM demand.demand_submissions),"
                "(SELECT count(*) FROM demand.demand_reviews),"
                "(SELECT count(*) FROM demand.command_receipts),"
                "(SELECT count(*) FROM audit.audit_events),"
                "(SELECT count(*) FROM infra.outbox_events)"
            ).fetchone()
        self.assertEqual(counts, (1, 2, 1, 1, 4, 4, 5))
