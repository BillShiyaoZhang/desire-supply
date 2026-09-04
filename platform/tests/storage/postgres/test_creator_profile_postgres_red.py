"""Real PostgreSQL 18 semantics for Creator Profile fixed UoWs and RLS.

The filename preserves the original TDD RED identity.  The IAM dependency and
independent Profile catalogs are loaded dynamically on a real server;
migration, driver, fixture, SQL, ImportError, and programming defects remain
test errors rather than semantic observations.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Optional
import unittest
import uuid

import psycopg

from desire_platform.creator_profile.adapters.postgres import (
    CREATOR_PROFILE_POSTGRES_PUBLISH_WRITE_CHECKPOINTS,
    CREATOR_PROFILE_POSTGRES_STATEMENT_PROFILES,
    CREATOR_PROFILE_POSTGRES_WRITE_CHECKPOINTS,
    PROFILE_POSTGRES_BEHAVIOR_NOT_AVAILABLE,
    CreatorProfilePostgresBehaviorNotAvailable,
    CreatorProfilePostgresCommitOutcomeUnknownError,
    CreatorProfilePostgresDatabaseError,
    CreatorProfilePostgresDerivedMatchInput,
    CreatorProfilePostgresMatchInput,
    CreatorProfilePostgresOperation,
    CreatorProfilePostgresSettings,
    CreatorProfilePostgresWriteCheckpoint,
    PsycopgCreatorProfileMatcherRepository,
    PsycopgCreatorProfileUnitOfWorkFactory,
)
from desire_platform.creator_profile.adapters.postgres.migrations import (
    ProfileContractSources,
    ProfileMigrationCatalog,
    PsycopgCreatorProfileMigrationRunner,
)
from desire_platform.identity_access.adapters.postgres.migrations import (
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from desire_platform.internal_pilot.editor import EditorServiceError
from desire_platform.matching.engine_v1 import _parse_profile_input
from desire_platform.creator_profile.domain import (
    ProfileContent,
    canonical_profile_version_bytes,
    freeze_profile_content,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18
from tests.support.creator_profile_postgres_builders import (
    ACTOR_USER_ID,
    OTHER_PROFILE_ID,
    OTHER_USER_ID,
    PROFILE_ID,
    RAW_SECRET_SENTINELS,
    SESSION_ID,
    SECOND_VERSION_ID,
    VERSION_ID,
    TAXONOMY_ID,
    RaiseAtProfileCheckpoint,
    RecordingSchemaValidator,
    TrackingProfileConnectionSource,
    content as profile_content,
    creator_profile_database_snapshot,
    derived_match_capture_request,
    match_capture_request,
    postgres_command,
    reset_creator_profile_database,
    seed_creator_profile_prestate,
    seed_exact_creator_iam_authority,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
IAM_MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
PROFILE_MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/creator_profile/adapters/postgres/migrations"
)


@dataclass(frozen=True)
class SemanticObservation:
    code: str
    replayed: bool = False


def _thaw_match_content(value: Any) -> Any:
    if isinstance(value, ProfileContent):
        return {key: _thaw_match_content(child) for key, child in value.members}
    if isinstance(value, tuple):
        return [_thaw_match_content(child) for child in value]
    return value


class RealPostgres18CreatorProfileSemanticRedTest(unittest.TestCase):
    """TEST-DB-PROFILE-001/RLS-001/UOW-001/MATCH-001."""

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
                application_name="desire-creator-profile-pg-red",
            ),
            dbapi=psycopg,
        )
        cls.migration_report = IamMigrationRunner(
            driver=driver,
            runner_version="creator-profile-pg-red/1",
        ).run(catalog=cls.catalog, contract_sources=cls.contract_sources)
        expected_versions = tuple(
            artifact.descriptor.version for artifact in cls.catalog.artifacts
        )
        if cls.migration_report.applied_versions != expected_versions:
            raise AssertionError("dynamic IAM migration catalog was not applied exactly")
        with cls._admin_class() as connection:
            profile_schema_before_profile_catalog = connection.execute(
                "SELECT pg_catalog.to_regnamespace('profile')::text"
            ).fetchone()[0]
        if profile_schema_before_profile_catalog is not None:
            raise AssertionError("IAM catalog must not install the Profile schema")
        with cls._admin_class(autocommit=False) as connection:
            cls.iam_authority = seed_exact_creator_iam_authority(
                connection,
                now=datetime.now(timezone.utc),
            )
        cls.profile_catalog = ProfileMigrationCatalog.load(PROFILE_MIGRATION_ROOT)
        cls.profile_migration_report = PsycopgCreatorProfileMigrationRunner(
            conninfo=cls.postgres.conninfo(
                database=cls.database,
                user="profile_migration_runner",
            ),
            dbapi=psycopg,
            runner_version="creator-profile-pg-green/1",
        ).run(
            catalog=cls.profile_catalog,
            contract_sources=ProfileContractSources(
                api_contract_bytes=(
                    PLATFORM_ROOT / "contracts/api/profile-v1.openapi.yaml"
                ).read_bytes(),
                event_contract_bytes=(
                    PLATFORM_ROOT / "contracts/events/profile-v1.schema.json"
                ).read_bytes(),
                domain_contract_bytes=(
                    PLATFORM_ROOT / "contracts/domain/profile-version-v1.schema.json"
                ).read_bytes(),
            ),
        )
        with cls._admin_class() as connection:
            server_major, compatibility, profile_schema = connection.execute(
                "SELECT "
                "current_setting('server_version_num')::integer / 10000,"
                "(SELECT ROW(current_schema_version,schema_head_version)::text "
                " FROM infra.iam_schema_compatibility),"
                "pg_catalog.to_regnamespace('profile')::text"
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
                "(SELECT count(*) FROM iam.user_role_grants "
                " WHERE id=%s AND role_code='CREATOR' AND revoked_at IS NULL),"
                "(SELECT count(*) FROM iam.policy_acceptances "
                " WHERE user_id=%s AND document_id=%s),"
                "(SELECT count(*) FROM iam.policy_bundles "
                " WHERE id=%s AND status='ACTIVE')",
                (
                    cls.iam_authority.actor_user_id,
                    cls.iam_authority.session_id,
                    cls.iam_authority.creator_grant_id,
                    cls.iam_authority.actor_user_id,
                    cls.iam_authority.required_document_id,
                    cls.iam_authority.policy_bundle_id,
                ),
            ).fetchone()
        expected_head = expected_versions[-1]
        if server_major != 18:
            raise AssertionError("Creator Profile RED did not start PostgreSQL 18")
        if compatibility != f"({expected_head},{expected_head})":
            raise AssertionError("IAM compatibility is not at the dynamic catalog head")
        if ledger_versions != expected_versions:
            raise AssertionError("IAM migration ledger differs from the dynamic catalog")
        if profile_schema != "profile":
            raise AssertionError("independent Profile schema was not migrated")
        if authority_facts != (1, 1, 1, 1, 1):
            raise AssertionError("exact Creator IAM fixture is incomplete")
        expected_profile_versions = tuple(
            artifact.descriptor.version
            for artifact in cls.profile_catalog.artifacts
        )
        if (
            cls.profile_migration_report.applied_versions
            != expected_profile_versions
        ):
            raise AssertionError(
                "dynamic Profile migration catalog was not applied exactly"
            )

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
        self.sources: list[TrackingProfileConnectionSource] = []
        with self._admin_class(autocommit=False) as connection:
            reset_creator_profile_database(connection)

    def tearDown(self) -> None:
        for source in self.sources:
            source.close()

    def _source(
        self,
        *,
        role: str = "profile_app",
        reuse_released: bool = False,
        lose_first_commit_ack: bool = False,
    ) -> TrackingProfileConnectionSource:
        source = TrackingProfileConnectionSource(
            self.postgres.conninfo(database=self.database, user=role),
            reuse_released=reuse_released,
            lose_first_commit_ack=lose_first_commit_ack,
        )
        self.sources.append(source)
        return source

    def _factory(
        self,
        *,
        source: Optional[TrackingProfileConnectionSource] = None,
        fault: Any = None,
    ) -> PsycopgCreatorProfileUnitOfWorkFactory:
        return PsycopgCreatorProfileUnitOfWorkFactory(
            connections=source or self._source(),
            event_validator=RecordingSchemaValidator(),
            response_validator=RecordingSchemaValidator(),
            fault_injector=fault,
        )

    def _seed(
        self,
        operation: CreatorProfilePostgresOperation,
        *,
        include_match_authorization: bool = False,
    ) -> None:
        with self._admin_class(autocommit=False) as connection:
            reset_creator_profile_database(connection)
            seed_creator_profile_prestate(
                connection,
                operation,
                include_match_authorization=include_match_authorization,
            )

    @staticmethod
    def _v4_id(label: str, index: int, kind: str) -> uuid.UUID:
        return uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"urn:desire:profile-v4:{label}:{index}:{kind}",
        )

    def _seed_eligible_creator_clones(
        self,
        *,
        label: str,
        count: int,
    ) -> tuple[uuid.UUID, ...]:
        users = tuple(self._v4_id(label, index, "user") for index in range(count))
        if not users:
            return ()
        with self._admin_class(autocommit=False) as connection:
            user_rows = []
            family_rows = []
            session_rows = []
            invitation_rows = []
            grant_rows = []
            acceptance_rows = []
            for index, user_id in enumerate(users):
                invitation_id = self._v4_id(label, index, "invitation")
                family_id = self._v4_id(label, index, "session-family")
                session_id = self._v4_id(label, index, "session")
                user_rows.append(
                    (
                        user_id,
                        f"profile_v4_{label}_{index}",
                        ACTOR_USER_ID,
                    )
                )
                family_rows.append(
                    (
                        family_id,
                        user_id,
                        self.iam_authority.session_family_id,
                    )
                )
                session_rows.append(
                    (
                        session_id,
                        user_id,
                        family_id,
                        hashlib.sha256(
                            f"profile-v4-session:{label}:{index}".encode("utf-8")
                        ).digest(),
                        SESSION_ID,
                    )
                )
                invitation_rows.append(
                    (
                        invitation_id,
                        hashlib.sha256(
                            f"profile-v4-token:{label}:{index}".encode("utf-8")
                        ).digest(),
                        user_id,
                        self.iam_authority.creator_invitation_id,
                    )
                )
                grant_rows.append(
                    (
                        self._v4_id(label, index, "grant"),
                        user_id,
                        invitation_id,
                        self.iam_authority.creator_grant_id,
                    )
                )
                acceptance_rows.append(
                    (
                        self._v4_id(label, index, "acceptance"),
                        user_id,
                        session_id,
                        self._v4_id(label, index, "accept-command"),
                        self._v4_id(label, index, "accept-correlation"),
                        ACTOR_USER_ID,
                    )
                )
            connection.cursor().executemany(
                "INSERT INTO iam.users ("
                "id,status,display_handle,aggregate_version,created_at,updated_at) "
                "SELECT %s,'ACTIVE',%s,source.aggregate_version,"
                "source.created_at,source.updated_at "
                "FROM iam.users AS source WHERE source.id=%s",
                user_rows,
            )
            connection.cursor().executemany(
                "INSERT INTO iam.session_families ("
                "id,user_id,status,current_generation,revoked_at,"
                "revocation_reason_code,aggregate_version,created_at,updated_at) "
                "SELECT %s,%s,source.status,source.current_generation,"
                "source.revoked_at,source.revocation_reason_code,"
                "source.aggregate_version,source.created_at,source.updated_at "
                "FROM iam.session_families AS source WHERE source.id=%s",
                family_rows,
            )
            connection.cursor().executemany(
                "INSERT INTO iam.sessions ("
                "id,user_id,family_id,generation,predecessor_session_id,"
                "handle_digest,handle_digest_key_id,csrf_salt,csrf_key_id,"
                "csrf_digest,verified_contact_point_id,verified_at,"
                "verified_for_invitation_id,auth_transaction_id,auth_time,"
                "acr_code,amr_codes,created_at,last_activity_at,idle_expires_at,"
                "absolute_expires_at,updated_at,device_label,status,"
                "rotation_reason,revoked_at,revocation_reason_code,"
                "aggregate_version) SELECT %s,%s,%s,source.generation,NULL,"
                "%s,source.handle_digest_key_id,source.csrf_salt,"
                "source.csrf_key_id,source.csrf_digest,NULL,NULL,NULL,"
                "source.auth_transaction_id,source.auth_time,source.acr_code,"
                "source.amr_codes,source.created_at,source.last_activity_at,"
                "source.idle_expires_at,source.absolute_expires_at,"
                "source.updated_at,source.device_label,source.status,"
                "source.rotation_reason,source.revoked_at,"
                "source.revocation_reason_code,source.aggregate_version "
                "FROM iam.sessions AS source WHERE source.id=%s",
                session_rows,
            )
            connection.cursor().executemany(
                "INSERT INTO iam.access_invitations ("
                "id,purpose,organization_id,target_scope,target_role,"
                "is_initial_admin,recipient_contact_id,masked_recipient_label,"
                "policy_selector_digest,issued_policy_bundle_id,status,"
                "expires_at,issuer_kind,issuer_user_id,token_nonce,token_key_id,"
                "accepted_by_user_id,terminal_at,terminal_reason_code,"
                "aggregate_version,created_at,updated_at) "
                "SELECT %s,source.purpose,source.organization_id,"
                "source.target_scope,source.target_role,source.is_initial_admin,"
                "source.recipient_contact_id,source.masked_recipient_label,"
                "source.policy_selector_digest,source.issued_policy_bundle_id,"
                "source.status,source.expires_at,source.issuer_kind,"
                "source.issuer_user_id,%s,source.token_key_id,%s,"
                "source.terminal_at,source.terminal_reason_code,"
                "source.aggregate_version,source.created_at,source.updated_at "
                "FROM iam.access_invitations AS source WHERE source.id=%s",
                invitation_rows,
            )
            connection.cursor().executemany(
                "INSERT INTO iam.user_role_grants ("
                "id,user_id,role_code,source_invitation_id,"
                "policy_selector_digest,granted_by_kind,granted_by_id,"
                "granted_at,revoked_at,revocation_reason_code,aggregate_version) "
                "SELECT %s,%s,source.role_code,%s,source.policy_selector_digest,"
                "source.granted_by_kind,source.granted_by_id,source.granted_at,"
                "source.revoked_at,source.revocation_reason_code,"
                "source.aggregate_version FROM iam.user_role_grants AS source "
                "WHERE source.id=%s",
                grant_rows,
            )
            connection.cursor().executemany(
                "INSERT INTO iam.policy_acceptances ("
                "id,user_id,document_id,content_sha256,bundle_id,accepted_at,"
                "session_id,auth_transaction_id,auth_time,acr_code,amr_codes,"
                "source_action,command_id,correlation_id,aggregate_version,"
                "created_at) SELECT %s,%s,source.document_id,"
                "source.content_sha256,source.bundle_id,source.accepted_at,"
                "%s,source.auth_transaction_id,source.auth_time,"
                "source.acr_code,source.amr_codes,source.source_action,%s,%s,"
                "source.aggregate_version,source.created_at "
                "FROM iam.policy_acceptances AS source WHERE source.user_id=%s",
                acceptance_rows,
            )
        return users

    def _replace_published_profile_content(
        self,
        *,
        profile_id: uuid.UUID,
        content: Mapping[str, Any],
    ) -> uuid.UUID:
        frozen = freeze_profile_content(content, for_publish=True)
        with self._admin_class() as connection:
            version_id, version_no, taxonomy_id = connection.execute(
                "SELECT version.id,version.version_no,version.taxonomy_bundle_id "
                "FROM profile.creator_profiles AS root "
                "JOIN profile.profile_versions AS version "
                "ON version.id=root.current_published_version_id "
                "WHERE root.id=%s",
                (profile_id,),
            ).fetchone()
            canonical = canonical_profile_version_bytes(
                profile_id=str(profile_id),
                version_no=int(version_no),
                taxonomy_bundle_id=str(taxonomy_id),
                content=frozen,
            )
            connection.execute(
                "ALTER TABLE profile.profile_versions "
                "DISABLE TRIGGER trg_profile_version_immutable"
            )
            connection.execute(
                "UPDATE profile.profile_versions SET canonical_content=%s,"
                "content=%s::jsonb,content_sha256=%s WHERE id=%s",
                (
                    canonical,
                    canonical.decode("utf-8"),
                    hashlib.sha256(canonical).digest(),
                    version_id,
                ),
            )
            connection.execute(
                "ALTER TABLE profile.profile_versions "
                "ENABLE TRIGGER trg_profile_version_immutable"
            )
        return version_id

    def _seed_published_profiles(
        self,
        *,
        label: str,
        owner_user_ids: tuple[uuid.UUID, ...],
    ) -> tuple[uuid.UUID, ...]:
        profile_ids = tuple(
            self._v4_id(label, index, "profile")
            for index in range(len(owner_user_ids))
        )
        now = datetime.now(timezone.utc)
        with self._admin_class(autocommit=False) as connection:
            connection.execute("SET CONSTRAINTS ALL DEFERRED")
            for index, (owner_user_id, profile_id) in enumerate(
                zip(owner_user_ids, profile_ids)
            ):
                version_id = self._v4_id(label, index, "version")
                canonical = canonical_profile_version_bytes(
                    profile_id=str(profile_id),
                    version_no=1,
                    taxonomy_bundle_id=str(TAXONOMY_ID),
                    content=profile_content(),
                )
                connection.execute(
                    "INSERT INTO profile.creator_profiles ("
                    "id,owner_user_id,status,aggregate_version,"
                    "current_draft_version_id,current_published_version_id,"
                    "paused_at,pause_reason_code,archived_at,archive_reason_code,"
                    "created_at,updated_at) VALUES ("
                    "%s,%s,'ACTIVE',2,NULL,%s,NULL,NULL,NULL,NULL,%s,%s)",
                    (
                        profile_id,
                        owner_user_id,
                        version_id,
                        now - timedelta(days=1),
                        now - timedelta(hours=1),
                    ),
                )
                connection.execute(
                    "INSERT INTO profile.profile_versions ("
                    "id,profile_id,version_no,status,based_on_profile_version_id,"
                    "schema_version,canonicalization_version,taxonomy_bundle_id,"
                    "canonical_content,content,content_sha256,created_by_user_id,"
                    "created_at,published_at,confirmed) VALUES ("
                    "%s,%s,1,'PUBLISHED',NULL,1,'profile-version-json-v1',"
                    "%s,%s,%s::jsonb,%s,%s,%s,%s,true)",
                    (
                        version_id,
                        profile_id,
                        TAXONOMY_ID,
                        canonical,
                        canonical.decode("utf-8"),
                        hashlib.sha256(canonical).digest(),
                        owner_user_id,
                        now - timedelta(hours=2),
                        now - timedelta(hours=1),
                    ),
                )
        return profile_ids

    @staticmethod
    def _method_name(operation: CreatorProfilePostgresOperation) -> str:
        return {
            CreatorProfilePostgresOperation.CREATE: "execute_create",
            CreatorProfilePostgresOperation.SAVE_DRAFT: "execute_save_draft",
            CreatorProfilePostgresOperation.PUBLISH: "execute_publish",
            CreatorProfilePostgresOperation.PAUSE: "execute_pause",
            CreatorProfilePostgresOperation.RESUME: "execute_resume",
            CreatorProfilePostgresOperation.ARCHIVE: "execute_archive",
        }[operation]

    def _observe(
        self,
        factory: PsycopgCreatorProfileUnitOfWorkFactory,
        operation: CreatorProfilePostgresOperation,
        request: Any,
    ) -> SemanticObservation:
        try:
            result = getattr(factory, self._method_name(operation))(request)
        except CreatorProfilePostgresBehaviorNotAvailable as error:
            if str(error) != PROFILE_POSTGRES_BEHAVIOR_NOT_AVAILABLE:
                raise
            return SemanticObservation(PROFILE_POSTGRES_BEHAVIOR_NOT_AVAILABLE)
        except CreatorProfilePostgresDatabaseError as error:
            return SemanticObservation(error.code)
        except CreatorProfilePostgresCommitOutcomeUnknownError as error:
            return SemanticObservation(error.code)
        return SemanticObservation("SUCCEEDED", replayed=result.replayed)

    def _observe_match(
        self,
        repository: PsycopgCreatorProfileMatcherRepository,
        request: Any,
    ) -> SemanticObservation:
        try:
            repository.capture_match_inputs(request)
        except CreatorProfilePostgresBehaviorNotAvailable as error:
            if str(error) != PROFILE_POSTGRES_BEHAVIOR_NOT_AVAILABLE:
                raise
            return SemanticObservation(PROFILE_POSTGRES_BEHAVIOR_NOT_AVAILABLE)
        except CreatorProfilePostgresDatabaseError as error:
            return SemanticObservation(error.code)
        return SemanticObservation("SUCCEEDED")

    def _observe_derived_match(
        self,
        repository: PsycopgCreatorProfileMatcherRepository,
        request: Any,
    ) -> SemanticObservation:
        try:
            repository.capture_derived_match_inputs(request)
        except CreatorProfilePostgresDatabaseError as error:
            return SemanticObservation(error.code)
        return SemanticObservation("SUCCEEDED")

    def _schema_surface(self) -> Mapping[str, Any]:
        with self._admin_class() as connection:
            row = connection.execute(
                "SELECT "
                "pg_catalog.to_regclass('profile.creator_profiles')::text,"
                "pg_catalog.to_regclass('profile.profile_versions')::text,"
                "pg_catalog.to_regclass('profile.command_receipts')::text,"
                "pg_catalog.to_regrole('profile_app')::text,"
                "pg_catalog.to_regrole('profile_matcher')::text"
            ).fetchone()
        return {
            "root": row[0],
            "versions": row[1],
            "receipts": row[2],
            "writer_role": row[3],
            "matcher_role": row[4],
        }

    def test_contract_is_frozen_importable_secret_safe_and_default_deny(self) -> None:
        self.assertEqual(
            tuple(item.value for item in CREATOR_PROFILE_POSTGRES_PUBLISH_WRITE_CHECKPOINTS),
            (
                "receipt.pending",
                "profile_version.superseded",
                "profile_version.published",
                "profile.root",
                "audit.profile_published",
                "outbox.profile_published",
                "receipt.completed",
            ),
        )
        self.assertGreater(
            len(CREATOR_PROFILE_POSTGRES_WRITE_CHECKPOINTS),
            len(CREATOR_PROFILE_POSTGRES_PUBLISH_WRITE_CHECKPOINTS),
        )
        self.assertEqual(
            set(CREATOR_PROFILE_POSTGRES_STATEMENT_PROFILES),
            set(CreatorProfilePostgresOperation),
        )
        for operation, profile in CREATOR_PROFILE_POSTGRES_STATEMENT_PROFILES.items():
            self.assertEqual(profile.operation, operation)
            self.assertEqual(profile.statement_budget, len(profile.statement_names))
            self.assertEqual(len(profile.query_shape_sha256), 64)
        settings = CreatorProfilePostgresSettings()
        self.assertEqual(
            (settings.writer_role, settings.matcher_role, settings.required_server_major),
            ("profile_app", "profile_matcher", 18),
        )
        with self.assertRaises(ValueError):
            CreatorProfilePostgresSettings(writer_role="profile_schema_owner")
        with self.assertRaises(ValueError):
            CreatorProfilePostgresSettings(matcher_role="profile_app")
        request = postgres_command(CreatorProfilePostgresOperation.PUBLISH)
        with self.assertRaises(FrozenInstanceError):
            request.expected_aggregate_version = 99  # type: ignore[misc]
        rendered = repr(request)
        for sentinel in RAW_SECRET_SENTINELS:
            self.assertNotIn(sentinel, rendered)
        source = self._source()
        factory = self._factory(source=source)
        self.assertFalse(hasattr(factory, "execute"))
        with self.assertRaises(ValueError):
            factory.execute_create(request)
        self.assertEqual(len(source.checked_out), 0)
        self._seed(CreatorProfilePostgresOperation.PUBLISH)
        observation = self._observe(
            factory,
            CreatorProfilePostgresOperation.PUBLISH,
            request,
        )
        self.assertEqual(
            (observation.code, len(source.checked_out)),
            ("SUCCEEDED", 1),
        )

    def test_dynamic_iam_head_has_no_unregistered_profile_schema(self) -> None:
        expected_head = self.catalog.artifacts[-1].descriptor.version
        self.assertEqual(
            self.migration_report.applied_versions[-1],
            expected_head,
        )
        self.assertEqual(
            self._schema_surface(),
            {
                "root": "profile.creator_profiles",
                "versions": "profile.profile_versions",
                "receipts": "profile.command_receipts",
                "writer_role": "profile_app",
                "matcher_role": "profile_matcher",
            },
            "semantic RED: independent Profile migration/roles are absent",
        )

    def test_six_happy_paths_match_memory_root_version_receipt_audit_and_outbox(self) -> None:
        for operation in (
            CreatorProfilePostgresOperation.CREATE,
            CreatorProfilePostgresOperation.SAVE_DRAFT,
            CreatorProfilePostgresOperation.PUBLISH,
            CreatorProfilePostgresOperation.PAUSE,
            CreatorProfilePostgresOperation.RESUME,
            CreatorProfilePostgresOperation.ARCHIVE,
        ):
            with self.subTest(operation=operation.value):
                self._seed(operation)
                observation = self._observe(
                    self._factory(),
                    operation,
                    postgres_command(operation),
                )
                self.assertEqual(
                    observation.code,
                    "SUCCEEDED",
                    "semantic RED: fixed Profile writer program is unavailable",
                )

    def test_owner_unique_and_same_owner_second_create_are_database_enforced(self) -> None:
        self._seed(CreatorProfilePostgresOperation.CREATE)
        cases = (
            (postgres_command(CreatorProfilePostgresOperation.CREATE), "SUCCEEDED"),
            (
                postgres_command(
                    CreatorProfilePostgresOperation.CREATE,
                    idempotency_material="second-create-key",
                ),
                "PROFILE_ALREADY_EXISTS",
            ),
        )
        factory = self._factory()
        for request, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(
                    self._observe(
                        factory,
                        CreatorProfilePostgresOperation.CREATE,
                        request,
                    ).code,
                    expected,
                )

    def test_single_draft_single_published_and_version_chain_are_enforced(self) -> None:
        cases = (
            (CreatorProfilePostgresOperation.SAVE_DRAFT, "SUCCEEDED"),
            (CreatorProfilePostgresOperation.PUBLISH, "SUCCEEDED"),
        )
        for operation, expected in cases:
            with self.subTest(operation=operation.value):
                self._seed(operation)
                self.assertEqual(
                    self._observe(
                        self._factory(),
                        operation,
                        postgres_command(operation),
                    ).code,
                    expected,
                    "semantic RED: Profile partial unique/version program is absent",
                )

    def test_published_canonical_hash_is_immutable_and_corruption_fails_closed(self) -> None:
        healthy = postgres_command(CreatorProfilePostgresOperation.PUBLISH)
        corrupt_hold = replace(
            healthy,
            hold=replace(healthy.hold, content_sha256=b"x" * 32),
        )
        for request, expected in (
            (healthy, "SUCCEEDED"),
            (corrupt_hold, "SERVICE_UNAVAILABLE"),
        ):
            with self.subTest(expected=expected):
                self._seed(CreatorProfilePostgresOperation.PUBLISH)
                self.assertEqual(
                    self._observe(
                        self._factory(),
                        CreatorProfilePostgresOperation.PUBLISH,
                        request,
                    ).code,
                    expected,
                )

    def test_exact_iam_authority_cross_user_and_forged_guc_fail_closed(self) -> None:
        base = postgres_command(CreatorProfilePostgresOperation.PUBLISH)
        cross_user = postgres_command(
            CreatorProfilePostgresOperation.PUBLISH,
            actor_user_id=OTHER_USER_ID,
        )
        forged_marker = replace(
            base,
            scope=replace(
                base.scope,
                expected_authority_marker_sha256=b"f" * 32,
            ),
        )
        for request, expected in (
            (base, "SUCCEEDED"),
            (cross_user, "RESOURCE_NOT_FOUND"),
            (forged_marker, "SERVICE_UNAVAILABLE"),
        ):
            with self.subTest(expected=expected):
                self._seed(CreatorProfilePostgresOperation.PUBLISH)
                self.assertEqual(
                    self._observe(
                        self._factory(),
                        CreatorProfilePostgresOperation.PUBLISH,
                        request,
                    ).code,
                    expected,
                )

    def test_matcher_capture_discovers_and_immutably_snapshots_candidates(self) -> None:
        self._seed(
            CreatorProfilePostgresOperation.CAPTURE_MATCH_INPUTS,
            include_match_authorization=True,
        )
        exact_request = match_capture_request()
        with self._admin_class() as connection:
            direct_iam_execute, legacy_execute, capture_execute = connection.execute(
                "SELECT "
                "pg_catalog.has_function_privilege("
                "'profile_matcher',"
                "'iam_api.is_creator_match_eligible_v1(uuid)','EXECUTE'),"
                "pg_catalog.has_function_privilege("
                "'profile_matcher',"
                "'profile_api.is_capture_candidate_eligible_v1(uuid,uuid,uuid,uuid,bytea)',"
                "'EXECUTE'),"
                "pg_catalog.has_function_privilege("
                "'profile_matcher',"
                "'profile_api."
                "discover_and_capture_creator_profile_match_inputs_v1"
                "(uuid,uuid,bytea)',"
                "'EXECUTE')"
            ).fetchone()
        self.assertEqual(
            (direct_iam_execute, legacy_execute, capture_execute),
            (False, False, True),
        )
        source = self._source(role="profile_matcher")
        repository = PsycopgCreatorProfileMatcherRepository(connections=source)
        positive_request = exact_request
        capture = repository.capture_match_inputs(positive_request)
        self.assertEqual(
            (
                capture.match_run_id,
                capture.workload_id,
                capture.capture_contract_version,
                capture.status,
                capture.candidate_count,
                capture.statement_count,
                capture.replayed,
                len(capture.snapshots),
            ),
            (
                positive_request.match_run_id,
                positive_request.workload_id,
                1,
                "COMPLETED",
                1,
                1,
                False,
                1,
            ),
        )
        snapshot = capture.snapshots[0]
        self.assertIsInstance(
            snapshot,
            CreatorProfilePostgresMatchInput,
            "semantic RED: MATCH_INPUT still discards the exact published content",
        )
        self.assertEqual(capture.captured_at.utcoffset(), timedelta(0))
        self.assertGreater(capture.authorization_valid_until, capture.captured_at)
        self.assertTrue(
            any(
                "discover_and_capture_creator_profile_match_inputs_v1"
                in statement
                for statement in source.trace
            ),
            "capture must use the one reviewed fixed database function",
        )
        self.assertEqual(
            (
                snapshot.creator_user_id,
                snapshot.profile_id,
                snapshot.profile_version_id,
                snapshot.version_no,
                snapshot.taxonomy_bundle_id,
            ),
            (ACTOR_USER_ID, PROFILE_ID, VERSION_ID, 1, TAXONOMY_ID),
        )
        content = _thaw_match_content(snapshot.content)
        self.assertEqual(
            set(content),
            {
                "interests",
                "skills",
                "availability",
                "collaboration",
                "compensation",
                "boundaries",
                "location",
                "conflicts",
                "ai",
            },
        )
        self.assertEqual(
            (
                content["compensation"]["minimum_project_amount_minor"],
                content["boundaries"]["prohibited_tasks"][0]["code"],
                content["boundaries"]["allowed_data_sensitivity"]["data_sensitivity"],
                content["conflicts"][0]["organization_id"],
                content["ai"]["human_review_code"],
            ),
            (
                100000,
                "TASK.SURVEILLANCE",
                "CONFIDENTIAL",
                "80000000-0000-4000-8000-000000000001",
                "REQUIRED",
            ),
        )
        canonical = canonical_profile_version_bytes(
            profile_id=str(snapshot.profile_id),
            version_no=snapshot.version_no,
            taxonomy_bundle_id=str(snapshot.taxonomy_bundle_id),
            content=snapshot.content,
        )
        self.assertEqual(hashlib.sha256(canonical).digest(), snapshot.content_sha256)
        with self.assertRaises(FrozenInstanceError):
            snapshot.content = ProfileContent(())  # type: ignore[misc]
        with self.assertRaises(TypeError):
            snapshot.content.members[0] = ("open", None)  # type: ignore[index]
        rendered = repr(capture) + repr(snapshot) + "\n".join(source.trace)
        for private_value in (
            '"minimum_project_amount_minor":100000',
            "TASK.SURVEILLANCE",
            "80000000-0000-4000-8000-000000000001",
            "creator@example.invalid",
        ):
            with self.subTest(private_repr=private_value):
                self.assertNotIn(private_value, rendered)
        encoded_content = json.dumps(content, separators=(",", ":"), sort_keys=True)
        for forbidden_locator in RAW_SECRET_SENTINELS[-2:]:
            with self.subTest(locator=forbidden_locator[:16]):
                self.assertNotIn(forbidden_locator, encoded_content)
        with self._admin_class() as connection:
            side_effect_counts = connection.execute(
                "SELECT "
                "(SELECT count(*) FROM profile.command_receipts),"
                "(SELECT count(*) FROM audit.audit_events),"
                "(SELECT count(*) FROM infra.outbox_events)"
            ).fetchone()
        self.assertEqual(side_effect_counts, (0, 0, 0))

        replay = repository.capture_match_inputs(positive_request)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.snapshots, capture.snapshots)
        self.assertEqual(
            self._observe_match(
                repository,
                replace(
                    match_capture_request(),
                    authorization_digest=b"f" * 32,
                ),
            ).code,
            "CAPTURE_BINDING_MISMATCH",
        )
        upper_trace = tuple(statement.upper() for statement in source.trace)
        self.assertEqual(
            upper_trace.count("BEGIN ISOLATION LEVEL REPEATABLE READ"),
            3,
        )
        with self._admin_class() as connection:
            connection.execute(
                "ALTER TABLE profile.profile_versions "
                "DISABLE TRIGGER trg_profile_version_immutable"
            )
            connection.execute(
                "UPDATE profile.profile_versions SET "
                "canonical_content=canonical_content||pg_catalog.decode('20','hex'),"
                "content_sha256=pg_catalog.sha256("
                "canonical_content||pg_catalog.decode('20','hex')) "
                "WHERE id=%s",
                (VERSION_ID,),
            )
            connection.execute(
                "ALTER TABLE profile.profile_versions "
                "ENABLE TRIGGER trg_profile_version_immutable"
            )
        corruption_source = self._source(role="profile_matcher")
        corrupted_source_request = replace(
            exact_request,
            match_run_id=uuid.uuid5(exact_request.match_run_id, "corrupt-source"),
            workload_id=uuid.uuid5(exact_request.workload_id, "corrupt-source"),
        )
        self.assertEqual(
            self._observe_match(
                PsycopgCreatorProfileMatcherRepository(
                    connections=corruption_source
                ),
                corrupted_source_request,
            ).code,
            "SERVICE_UNAVAILABLE",
            "stored non-JCS canonical bytes must fail the entire capture closed",
        )

    def test_derived_match_capture_returns_frozen_engine_profile_input(self) -> None:
        self._seed(CreatorProfilePostgresOperation.CAPTURE_DERIVED_MATCH_INPUTS)
        request = derived_match_capture_request()
        source = self._source(role="profile_matcher")
        repository = PsycopgCreatorProfileMatcherRepository(connections=source)
        capture = repository.capture_derived_match_inputs(request)
        self.assertEqual(
            (
                capture.match_run_id,
                capture.workload_id,
                capture.capture_contract_version,
                capture.status,
                capture.candidate_count,
                capture.replayed,
                capture.statement_count,
            ),
            (
                request.match_run_id,
                request.workload_id,
                2,
                "COMPLETED",
                1,
                False,
                1,
            ),
        )
        snapshot = capture.snapshots[0]
        self.assertIsInstance(snapshot, CreatorProfilePostgresDerivedMatchInput)
        derived = _thaw_match_content(snapshot.derived_input)
        self.assertEqual(
            derived,
            {
                "creator_user_id": str(ACTOR_USER_ID),
                "profile_id": str(PROFILE_ID),
                "profile_version_id": str(VERSION_ID),
                "profile_content_sha256": snapshot.profile_content_sha256.hex(),
                "evidence_version_digest": snapshot.evidence_version_digest.hex(),
                "status": "ACTIVE",
                "interest_problem_type_codes": ["PROBLEM.CLIMATE"],
                "interest_domain_codes": ["DOMAIN.ENERGY"],
                "interest_task_codes": ["TASK.RESEARCH"],
                "interest_intensity": 4,
                "prohibited_domain_codes": ["DOMAIN.GAMBLING"],
                "prohibited_task_codes": ["TASK.SURVEILLANCE"],
                "skills": [
                    {
                        "skill_code": "SKILL.RESEARCH",
                        "proficiency_level": 3,
                        "evidence_trust_level": 1,
                        "evidence_bucket": "SELF_ASSERTED",
                    }
                ],
                "available_from": "2026-08-09",
                "available_weekly_hours": 20,
                "available_duration_weeks": 12,
                "currency": "CNY",
                "within_offered_budget": True,
                "private_floor_evidence_digest": (
                    derived["private_floor_evidence_digest"]
                ),
                "allowed_data_sensitivity_codes": ["HIGH"],
                "ai_use_code": "OPTIONAL",
                "language_codes": ["LANGUAGE.ZH"],
                "work_mode_code": "WORK_MODE.REMOTE",
                "region_code": "REGION.CN",
                "location_eligible": True,
                "conflict_of_interest": False,
            },
        )
        self.assertEqual(len(derived["private_floor_evidence_digest"]), 64)
        parsed_engine_input = _parse_profile_input(derived)
        self.assertEqual(parsed_engine_input.profile_id, str(PROFILE_ID))
        self.assertEqual(
            hashlib.sha256(snapshot.canonical_derived_input_bytes).digest(),
            snapshot.derived_input_sha256,
        )
        replay = repository.capture_derived_match_inputs(request)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.snapshots, capture.snapshots)
        with self._admin_class() as connection:
            acl = connection.execute(
                "SELECT "
                "pg_catalog.has_table_privilege('profile_matcher',"
                "'profile.derived_match_raw_snapshots','SELECT'),"
                "pg_catalog.has_table_privilege('profile_matcher',"
                "'profile.derived_match_input_snapshots','SELECT'),"
                "pg_catalog.has_function_privilege('profile_matcher',"
                "'iam_api.resolve_profile_match_creator_eligibility_v1"
                "(uuid,uuid,uuid,bytea,bytea)','EXECUTE')"
            ).fetchone()
        self.assertEqual(acl, (False, False, False))

    def test_derived_context_is_canonical_and_replay_is_source_independent(self) -> None:
        request = derived_match_capture_request()
        with self.assertRaises(ValueError):
            replace(
                request,
                demand_match_context_bytes=request.demand_match_context_bytes + b" ",
                demand_match_context_sha256=hashlib.sha256(
                    request.demand_match_context_bytes + b" "
                ).digest(),
            )
        with self.assertRaises(ValueError):
            replace(request, demand_match_context_sha256=b"x" * 32)
        with self.assertRaises(ValueError):
            derived_match_capture_request(unreviewed_key="forbidden")
        with self.assertRaises(ValueError):
            derived_match_capture_request(minimum_amount_minor=True)

        self._seed(CreatorProfilePostgresOperation.CAPTURE_DERIVED_MATCH_INPUTS)
        repository = PsycopgCreatorProfileMatcherRepository(
            connections=self._source(role="profile_matcher")
        )
        first = repository.capture_derived_match_inputs(request)
        with self._admin_class() as connection:
            iam_user_before = connection.execute(
                "SELECT status,aggregate_version,updated_at FROM iam.users "
                "WHERE id=%s",
                (ACTOR_USER_ID,),
            ).fetchone()
            connection.execute(
                "UPDATE profile.creator_profiles SET status='PAUSED',"
                "aggregate_version=aggregate_version+1,"
                "paused_at=transaction_timestamp(),"
                "pause_reason_code='TEMPORARY_UNAVAILABILITY',"
                "updated_at=transaction_timestamp() WHERE id=%s",
                (PROFILE_ID,),
            )
            connection.execute(
                "UPDATE iam.users SET status='SUSPENDED',"
                "aggregate_version=aggregate_version+1,"
                "updated_at=transaction_timestamp() WHERE id=%s",
                (ACTOR_USER_ID,),
            )
            connection.execute(
                "ALTER TABLE profile.derived_match_capture_receipts "
                "DISABLE TRIGGER trg_profile_derived_match_capture_immutable"
            )
            connection.execute(
                "UPDATE profile.derived_match_capture_receipts SET "
                "captured_at=captured_at-interval '1 day',"
                "authorization_valid_until=captured_at-interval '1 hour' "
                "WHERE match_run_id=%s",
                (request.match_run_id,),
            )
            connection.execute(
                "ALTER TABLE profile.derived_match_capture_receipts "
                "ENABLE TRIGGER trg_profile_derived_match_capture_immutable"
            )
        replay = repository.capture_derived_match_inputs(request)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.snapshots, first.snapshots)
        self.assertLess(replay.authorization_valid_until, datetime.now(timezone.utc))

        changed_context = derived_match_capture_request(maximum_amount_minor=99999)
        mismatches = (
            replace(request, authorization_digest=b"f" * 32),
            replace(
                request,
                demand_match_context_bytes=(
                    changed_context.demand_match_context_bytes
                ),
                demand_match_context_sha256=(
                    changed_context.demand_match_context_sha256
                ),
            ),
            replace(
                request,
                workload_id=self._v4_id("derived-binding", 0, "workload"),
            ),
        )
        for mismatch in mismatches:
            with self.subTest(mismatch=mismatch.workload_id):
                self.assertEqual(
                    self._observe_derived_match(repository, mismatch).code,
                    "CAPTURE_BINDING_MISMATCH",
                )
        with self._admin_class() as connection:
            connection.execute(
                "ALTER TABLE iam.users DISABLE TRIGGER "
                "trg_user_state_transition"
            )
            connection.execute(
                "UPDATE iam.users SET status=%s,aggregate_version=%s,"
                "updated_at=%s WHERE id=%s",
                (*iam_user_before, ACTOR_USER_ID),
            )
            connection.execute(
                "ALTER TABLE iam.users ENABLE TRIGGER "
                "trg_user_state_transition"
            )

    def test_derived_capture_reuses_one_authorized_workload_across_runs(self) -> None:
        self._seed(CreatorProfilePostgresOperation.CAPTURE_DERIVED_MATCH_INPUTS)
        repository = PsycopgCreatorProfileMatcherRepository(
            connections=self._source(role="profile_matcher")
        )
        first_request = derived_match_capture_request()
        second_request = replace(
            first_request,
            match_run_id=self._v4_id("derived-next-run", 0, "run"),
        )

        first = repository.capture_derived_match_inputs(first_request)
        second = repository.capture_derived_match_inputs(second_request)

        self.assertFalse(first.replayed)
        self.assertFalse(second.replayed)
        self.assertEqual(first_request.workload_id, second_request.workload_id)
        self.assertNotEqual(first.match_run_id, second.match_run_id)
        self.assertEqual(
            tuple(item.creator_user_id for item in first.snapshots),
            tuple(item.creator_user_id for item in second.snapshots),
        )
        self.assertTrue(
            repository.capture_derived_match_inputs(second_request).replayed
        )
        with self._admin_class() as connection:
            bindings = connection.execute(
                "SELECT match_run_id,workload_id "
                "FROM profile.derived_match_capture_receipts "
                "ORDER BY match_run_id",
            ).fetchall()
        self.assertEqual(len(bindings), 2)
        self.assertEqual({row[1] for row in bindings}, {first_request.workload_id})

    def test_derived_private_budget_location_conflict_and_ai_branches(self) -> None:
        self._seed(CreatorProfilePostgresOperation.CAPTURE_DERIVED_MATCH_INPUTS)
        repository = PsycopgCreatorProfileMatcherRepository(
            connections=self._source(role="profile_matcher")
        )
        cases = (
            ({}, (True, True, False, "OPTIONAL")),
            (
                {"maximum_amount_minor": 99999},
                (False, True, False, "OPTIONAL"),
            ),
            (
                {"currency": "USD"},
                (False, True, False, "OPTIONAL"),
            ),
            (
                {"allowed_region_codes": ["REGION.US"]},
                (True, False, False, "OPTIONAL"),
            ),
            (
                {
                    "organization_id":
                        "80000000-0000-4000-8000-000000000001"
                },
                (True, True, True, "OPTIONAL"),
            ),
        )
        for index, (context, expected) in enumerate(cases):
            request = derived_match_capture_request(**context)
            request = replace(
                request,
                match_run_id=self._v4_id("derived-private", index, "run"),
                workload_id=self._v4_id(
                    "derived-private", index, "workload"
                ),
            )
            captured = repository.capture_derived_match_inputs(request)
            derived = _thaw_match_content(captured.snapshots[0].derived_input)
            self.assertEqual(
                (
                    derived["within_offered_budget"],
                    derived["location_eligible"],
                    derived["conflict_of_interest"],
                    derived["ai_use_code"],
                ),
                expected,
            )
            rendered = json.dumps(derived, separators=(",", ":"), sort_keys=True)
            self.assertNotIn("minimum_project_amount_minor", rendered)
            self.assertNotIn("safe_object_reference", rendered)

        content = _thaw_match_content(profile_content())
        content["ai"]["allowed"] = False
        self._replace_published_profile_content(
            profile_id=PROFILE_ID,
            content=content,
        )
        prohibited_request = replace(
            derived_match_capture_request(),
            match_run_id=self._v4_id("derived-ai", 0, "run"),
            workload_id=self._v4_id("derived-ai", 0, "workload"),
        )
        prohibited = repository.capture_derived_match_inputs(prohibited_request)
        self.assertEqual(
            _thaw_match_content(prohibited.snapshots[0].derived_input)[
                "ai_use_code"
            ],
            "PROHIBITED",
        )

    def test_derived_evidence_trust_buckets_and_private_provenance(self) -> None:
        self._seed(CreatorProfilePostgresOperation.CAPTURE_DERIVED_MATCH_INPUTS)
        content = _thaw_match_content(profile_content())
        evidence_ids = tuple(
            self._v4_id("derived-evidence", index, "evidence")
            for index in range(3)
        )
        content["skills"] = sorted([
            {
                "skill_code": "SKILL.LEGACY",
                "proficiency": 1,
                "visibility": "MATCH_ONLY",
                "source_kind": "LEGACY_UNVERIFIED",
                "evidence_ids": [],
            },
            {
                "skill_code": "SKILL.SELF",
                "proficiency": 2,
                "visibility": "MATCH_ONLY",
                "source_kind": "SELF_ASSERTED",
                "evidence_ids": [],
            },
            *(
                {
                    "skill_code": skill_code,
                    "proficiency": 4,
                    "visibility": "MATCH_ONLY",
                    "source_kind": "VERIFIED_EVIDENCE",
                    "evidence_ids": [str(evidence_id)],
                }
                for skill_code, evidence_id in zip(
                    ("SKILL.DOCUMENTED", "SKILL.REJECTED", "SKILL.VERIFIED"),
                    evidence_ids,
                )
            ),
        ], key=lambda item: item["skill_code"])
        version_id = self._replace_published_profile_content(
            profile_id=PROFILE_ID,
            content=content,
        )
        now = datetime.now(timezone.utc)
        statuses = ("EXPIRED", "REJECTED", "VERIFIED")
        with self._admin_class() as connection:
            for evidence_id, status in zip(evidence_ids, statuses):
                evidence_sha = hashlib.sha256(evidence_id.bytes).digest()
                connection.execute(
                    "INSERT INTO profile.capability_evidence ("
                    "id,owner_user_id,status,aggregate_version,"
                    "safe_object_reference,evidence_sha256,verified_at,"
                    "expires_at,created_at) VALUES ("
                    "%s,%s,%s,1,%s,%s,%s,%s,%s)",
                    (
                        evidence_id,
                        ACTOR_USER_ID,
                        status,
                        "opaque-evidence-" + evidence_id.hex,
                        evidence_sha,
                        now - timedelta(days=2),
                        now - timedelta(days=1)
                        if status == "EXPIRED"
                        else None,
                        now - timedelta(days=3),
                    ),
                )
                connection.execute(
                    "INSERT INTO profile.profile_version_evidence ("
                    "profile_id,profile_version_id,evidence_id,"
                    "evidence_version,safe_status,evidence_sha256) "
                    "VALUES (%s,%s,%s,1,%s,%s)",
                    (
                        PROFILE_ID,
                        version_id,
                        evidence_id,
                        status,
                        evidence_sha,
                    ),
                )
        capture = PsycopgCreatorProfileMatcherRepository(
            connections=self._source(role="profile_matcher")
        ).capture_derived_match_inputs(derived_match_capture_request())
        derived = _thaw_match_content(capture.snapshots[0].derived_input)
        trust = {
            skill["skill_code"]: (
                skill["evidence_trust_level"],
                skill["evidence_bucket"],
            )
            for skill in derived["skills"]
        }
        self.assertEqual(
            trust,
            {
                "SKILL.DOCUMENTED": (2, "DOCUMENTED"),
                "SKILL.LEGACY": (0, "NONE"),
                "SKILL.REJECTED": (0, "NONE"),
                "SKILL.SELF": (1, "SELF_ASSERTED"),
                "SKILL.VERIFIED": (4, "VERIFIED"),
            },
        )
        rendered = json.dumps(derived, separators=(",", ":"), sort_keys=True)
        for evidence_id in evidence_ids:
            self.assertNotIn(str(evidence_id), rendered)
            self.assertNotIn("opaque-evidence-" + evidence_id.hex, rendered)

    def test_derived_zero_taxonomy_limit_concurrency_and_corruption(self) -> None:
        zero_request = replace(
            derived_match_capture_request(),
            match_run_id=self._v4_id("derived-zero", 0, "run"),
            workload_id=self._v4_id("derived-zero", 0, "workload"),
        )
        zero = PsycopgCreatorProfileMatcherRepository(
            connections=self._source(role="profile_matcher")
        ).capture_derived_match_inputs(zero_request)
        self.assertEqual(
            (zero.status, zero.candidate_count, zero.snapshots, zero.replayed),
            ("COMPLETED", 0, (), False),
        )

        self._seed(CreatorProfilePostgresOperation.CAPTURE_DERIVED_MATCH_INPUTS)
        taxonomy_mismatch = replace(
            derived_match_capture_request(
                taxonomy_bundle_id=str(
                    self._v4_id("derived-taxonomy", 0, "bundle")
                )
            ),
            match_run_id=self._v4_id("derived-taxonomy", 0, "run"),
            workload_id=self._v4_id("derived-taxonomy", 0, "workload"),
        )
        self.assertEqual(
            self._observe_derived_match(
                PsycopgCreatorProfileMatcherRepository(
                    connections=self._source(role="profile_matcher")
                ),
                taxonomy_mismatch,
            ).code,
            "SERVICE_UNAVAILABLE",
        )

        request = replace(
            derived_match_capture_request(),
            match_run_id=self._v4_id("derived-concurrent", 0, "run"),
            workload_id=self._v4_id("derived-concurrent", 0, "workload"),
        )

        def invoke(_: int):
            return PsycopgCreatorProfileMatcherRepository(
                connections=self._source(role="profile_matcher")
            ).capture_derived_match_inputs(request)

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(executor.map(invoke, (0, 1)))
        self.assertEqual(sorted(result.replayed for result in results), [False, True])
        self.assertEqual(results[0].snapshots, results[1].snapshots)

        with self._admin_class() as connection:
            connection.execute(
                "ALTER TABLE profile.derived_match_input_snapshots "
                "DISABLE TRIGGER trg_profile_derived_match_input_immutable"
            )
            connection.execute(
                "UPDATE profile.derived_match_input_snapshots SET "
                "canonical_derived_input_bytes="
                "canonical_derived_input_bytes||decode('20','hex'),"
                "derived_input_sha256=sha256("
                "canonical_derived_input_bytes||decode('20','hex')) "
                "WHERE match_run_id=%s",
                (request.match_run_id,),
            )
            connection.execute(
                "ALTER TABLE profile.derived_match_input_snapshots "
                "ENABLE TRIGGER trg_profile_derived_match_input_immutable"
            )
        self.assertEqual(
            self._observe_derived_match(
                PsycopgCreatorProfileMatcherRepository(
                    connections=self._source(role="profile_matcher")
                ),
                request,
            ).code,
            "SERVICE_UNAVAILABLE",
        )

        self._seed(CreatorProfilePostgresOperation.CAPTURE_DERIVED_MATCH_INPUTS)
        users = self._seed_eligible_creator_clones(
            label="derived-limit",
            count=500,
        )
        self._seed_published_profiles(
            label="derived-limit",
            owner_user_ids=users,
        )
        limit_repository = PsycopgCreatorProfileMatcherRepository(
            connections=self._source(role="profile_matcher"),
            settings=CreatorProfilePostgresSettings(statement_timeout_ms=120_000),
        )
        limit_observation = self._observe_derived_match(
            limit_repository,
            derived_match_capture_request(),
        )
        self.assertEqual(
            limit_observation.code,
            "MATCH_CANDIDATE_LIMIT_EXCEEDED",
        )
        with self._admin_class() as connection:
            counts = connection.execute(
                "SELECT "
                "(SELECT count(*) FROM profile.derived_match_capture_receipts),"
                "(SELECT count(*) FROM profile.derived_match_raw_snapshots),"
                "(SELECT count(*) FROM profile.derived_match_input_snapshots)"
            ).fetchone()
        self.assertEqual(counts, (0, 0, 0))

    def test_derived_function_acl_guc_role_and_immutability_fail_closed(self) -> None:
        self._seed(CreatorProfilePostgresOperation.CAPTURE_DERIVED_MATCH_INPUTS)
        request = derived_match_capture_request()
        sql = (
            "SELECT * FROM profile_api."
            "discover_and_capture_derived_creator_match_inputs_v1("
            "%s,%s,%s,%s,%s)"
        )
        with psycopg.connect(
            self.postgres.conninfo(
                database=self.database,
                user="profile_matcher",
            ),
            autocommit=False,
        ) as connection:
            connection.execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    sql,
                    (
                        request.match_run_id,
                        request.workload_id,
                        request.authorization_digest,
                        request.demand_match_context_bytes,
                        request.demand_match_context_sha256,
                    ),
                )
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="profile_app"),
            autocommit=False,
        ) as connection:
            connection.execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    sql,
                    (
                        request.match_run_id,
                        request.workload_id,
                        request.authorization_digest,
                        request.demand_match_context_bytes,
                        request.demand_match_context_sha256,
                    ),
                )
        capture = PsycopgCreatorProfileMatcherRepository(
            connections=self._source(role="profile_matcher")
        ).capture_derived_match_inputs(request)
        self.assertEqual(capture.candidate_count, 1)
        with self._admin_class() as connection:
            with self.assertRaises(psycopg.errors.CheckViolation):
                connection.execute(
                    "UPDATE profile.derived_match_input_snapshots SET "
                    "derived_schema_version=1 WHERE match_run_id=%s",
                    (request.match_run_id,),
                )
            privileges = connection.execute(
                "SELECT "
                "pg_catalog.has_schema_privilege("
                "'profile_matcher','profile','USAGE'),"
                "pg_catalog.has_table_privilege("
                "'profile_matcher','profile.creator_profiles','SELECT'),"
                "pg_catalog.has_table_privilege("
                "'profile_matcher','profile.capability_evidence','SELECT')"
            ).fetchone()
        self.assertEqual(privileges, (False, False, False))

    def test_match_capture_zero_and_stable_discovery_exclusions(self) -> None:
        zero_request = replace(
            match_capture_request(),
            match_run_id=self._v4_id("zero", 0, "run"),
            workload_id=self._v4_id("zero", 0, "workload"),
        )
        zero = PsycopgCreatorProfileMatcherRepository(
            connections=self._source(role="profile_matcher")
        ).capture_match_inputs(zero_request)
        self.assertEqual(
            (zero.status, zero.candidate_count, zero.snapshots, zero.replayed),
            ("COMPLETED", 0, (), False),
        )

        self._seed(CreatorProfilePostgresOperation.CAPTURE_MATCH_INPUTS)
        eligible_users = self._seed_eligible_creator_clones(
            label="discovery",
            count=6,
        )
        profile_ids = self._seed_published_profiles(
            label="discovery",
            owner_user_ids=eligible_users,
        )
        ineligible_profile = self._seed_published_profiles(
            label="ineligible",
            owner_user_ids=(self._v4_id("ineligible", 0, "user"),),
        )[0]
        with self._admin_class() as connection:
            connection.execute(
                "UPDATE profile.creator_profiles SET status='PAUSED',"
                "aggregate_version=aggregate_version+1,"
                "paused_at=transaction_timestamp(),"
                "pause_reason_code='TEMPORARY_UNAVAILABILITY',"
                "updated_at=transaction_timestamp() WHERE id=%s",
                (profile_ids[3],),
            )
            connection.execute(
                "ALTER TABLE profile.creator_profiles "
                "DISABLE TRIGGER trg_creator_profile_transition"
            )
            connection.execute(
                "ALTER TABLE profile.profile_versions "
                "DISABLE TRIGGER trg_profile_version_immutable"
            )
            connection.execute(
                "UPDATE profile.creator_profiles SET status='DRAFT',"
                "current_draft_version_id=current_published_version_id,"
                "current_published_version_id=NULL,aggregate_version=3,"
                "updated_at=transaction_timestamp() WHERE id=%s",
                (profile_ids[4],),
            )
            connection.execute(
                "UPDATE profile.profile_versions SET status='DRAFT',"
                "published_at=NULL,confirmed=false WHERE profile_id=%s",
                (profile_ids[4],),
            )
            connection.execute(
                "UPDATE profile.profile_versions SET status='SUPERSEDED' "
                "WHERE profile_id=%s",
                (profile_ids[5],),
            )
            connection.execute(
                "ALTER TABLE profile.profile_versions "
                "ENABLE TRIGGER trg_profile_version_immutable"
            )
            connection.execute(
                "ALTER TABLE profile.creator_profiles "
                "ENABLE TRIGGER trg_creator_profile_transition"
            )
        capture = PsycopgCreatorProfileMatcherRepository(
            connections=self._source(role="profile_matcher")
        ).capture_match_inputs(match_capture_request())
        expected = tuple(sorted((PROFILE_ID,) + profile_ids[:3], key=lambda item: item.bytes))
        actual = tuple(snapshot.profile_id for snapshot in capture.snapshots)
        self.assertEqual(actual, expected)
        self.assertTrue(
            {profile_ids[3], profile_ids[4], profile_ids[5], ineligible_profile}
            .isdisjoint(actual)
        )

    def test_match_capture_fixed_ceiling_fails_without_truncation(self) -> None:
        self._seed(CreatorProfilePostgresOperation.CAPTURE_MATCH_INPUTS)
        users = self._seed_eligible_creator_clones(label="limit", count=500)
        self._seed_published_profiles(label="limit", owner_user_ids=users)
        repository = PsycopgCreatorProfileMatcherRepository(
            connections=self._source(role="profile_matcher"),
            # Match the derived-capture ceiling test's budget: this checks the
            # full 501-candidate permission path and atomic limit rejection.
            settings=CreatorProfilePostgresSettings(statement_timeout_ms=120_000),
        )
        self.assertEqual(
            self._observe_match(repository, match_capture_request()).code,
            "MATCH_CANDIDATE_LIMIT_EXCEEDED",
        )
        with self._admin_class() as connection:
            facts = connection.execute(
                "SELECT (SELECT count(*) FROM profile.match_capture_batches),"
                "(SELECT count(*) FROM profile.match_input_snapshots),"
                "(SELECT count(*) FROM profile.match_capture_authorizations)"
            ).fetchone()
        self.assertEqual(facts, (0, 0, 0), "the fixed ceiling must never truncate")

    def test_match_capture_concurrent_replay_and_binding_mismatch(self) -> None:
        self._seed(CreatorProfilePostgresOperation.CAPTURE_MATCH_INPUTS)
        request = match_capture_request()

        def invoke(_: int):
            return PsycopgCreatorProfileMatcherRepository(
                connections=self._source(role="profile_matcher")
            ).capture_match_inputs(request)

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(executor.map(invoke, (0, 1)))
        self.assertEqual(sorted(result.replayed for result in results), [False, True])
        self.assertEqual(results[0].snapshots, results[1].snapshots)
        repository = PsycopgCreatorProfileMatcherRepository(
            connections=self._source(role="profile_matcher")
        )
        mismatches = (
            replace(
                request,
                workload_id=self._v4_id("mismatch", 0, "workload"),
            ),
            replace(
                request,
                match_run_id=self._v4_id("mismatch", 0, "run"),
            ),
            replace(request, authorization_digest=b"m" * 32),
        )
        self.assertEqual(
            tuple(self._observe_match(repository, item).code for item in mismatches),
            ("CAPTURE_BINDING_MISMATCH",) * 3,
        )
        with self._admin_class() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT count(*) FROM profile.match_capture_batches"
                ).fetchone()[0],
                1,
            )

    def test_match_capture_replays_after_source_and_authorization_expiry(self) -> None:
        self._seed(CreatorProfilePostgresOperation.CAPTURE_MATCH_INPUTS)
        clone_user = self._seed_eligible_creator_clones(label="replay", count=1)[0]
        clone_profile = self._seed_published_profiles(
            label="replay",
            owner_user_ids=(clone_user,),
        )[0]
        request = replace(
            match_capture_request(),
            match_run_id=self._v4_id("replay", 0, "run"),
            workload_id=self._v4_id("replay", 0, "workload"),
        )
        repository = PsycopgCreatorProfileMatcherRepository(
            connections=self._source(role="profile_matcher")
        )
        first = repository.capture_match_inputs(request)
        self.assertIn(clone_profile, tuple(item.profile_id for item in first.snapshots))
        with self._admin_class(autocommit=False) as connection:
            connection.execute(
                "UPDATE profile.creator_profiles SET status='PAUSED',"
                "aggregate_version=aggregate_version+1,"
                "paused_at=transaction_timestamp(),"
                "pause_reason_code='TEMPORARY_UNAVAILABILITY',"
                "updated_at=transaction_timestamp() WHERE id=%s",
                (clone_profile,),
            )
            connection.execute(
                "UPDATE iam.users SET status='SUSPENDED',"
                "aggregate_version=aggregate_version+1,"
                "updated_at=transaction_timestamp() WHERE id=%s",
                (clone_user,),
            )
            connection.execute(
                "ALTER TABLE profile.match_capture_authorizations "
                "DISABLE TRIGGER trg_profile_match_authorization_immutable"
            )
            connection.execute(
                "UPDATE profile.match_capture_authorizations SET "
                "valid_until=created_at+interval '1 microsecond' "
                "WHERE match_run_id=%s AND workload_id=%s",
                (request.match_run_id, request.workload_id),
            )
            connection.execute(
                "ALTER TABLE profile.match_capture_authorizations "
                "ENABLE TRIGGER trg_profile_match_authorization_immutable"
            )
        replay = repository.capture_match_inputs(request)
        self.assertEqual(
            (
                replay.replayed,
                replay.captured_at,
                replay.allowlist_sha256,
                replay.snapshots,
            ),
            (
                True,
                first.captured_at,
                first.allowlist_sha256,
                first.snapshots,
            ),
        )

    def test_match_capture_repeatable_snapshot_prevents_mixed_eligibility(self) -> None:
        self._seed(CreatorProfilePostgresOperation.CAPTURE_MATCH_INPUTS)
        clone_user = self._seed_eligible_creator_clones(label="snapshot", count=1)[0]
        clone_profile = self._seed_published_profiles(
            label="snapshot",
            owner_user_ids=(clone_user,),
        )[0]
        request = replace(
            match_capture_request(),
            match_run_id=self._v4_id("snapshot", 0, "run"),
            workload_id=self._v4_id("snapshot", 0, "workload"),
        )
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="profile_matcher"),
            autocommit=False,
        ) as connection:
            connection.execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
            for name, value in (
                ("app.scope_kind", "PROFILE_MATCH_CAPTURE"),
                ("app.operation", "CAPTURE_MATCH_INPUTS"),
                ("app.match_run_id", str(request.match_run_id)),
                ("app.workload_id", str(request.workload_id)),
                (
                    "app.match_authorization_digest",
                    request.authorization_digest.hex(),
                ),
            ):
                connection.execute(
                    "SELECT pg_catalog.set_config(%s,%s,true)",
                    (name, value),
                )
            connection.execute("SELECT pg_catalog.txid_current_snapshot()")
            with self._admin_class(autocommit=False) as admin:
                admin.execute(
                    "UPDATE iam.users SET status='SUSPENDED',"
                    "aggregate_version=aggregate_version+1,"
                    "updated_at=transaction_timestamp() WHERE id=%s",
                    (clone_user,),
                )
            rows = connection.execute(
                "SELECT * FROM "
                "profile_api.discover_and_capture_creator_profile_match_inputs_v1("
                "%s,%s,%s)",
                (
                    request.match_run_id,
                    request.workload_id,
                    request.authorization_digest,
                ),
            ).fetchall()
        captured_ids = tuple(row[11] for row in rows if row[11] is not None)
        self.assertIn(clone_profile, captured_ids)

        next_request = replace(
            request,
            match_run_id=self._v4_id("snapshot", 1, "run"),
            workload_id=self._v4_id("snapshot", 1, "workload"),
        )
        next_capture = PsycopgCreatorProfileMatcherRepository(
            connections=self._source(role="profile_matcher")
        ).capture_match_inputs(next_request)
        self.assertNotIn(
            clone_profile,
            tuple(item.profile_id for item in next_capture.snapshots),
        )

    def test_match_capture_acl_role_scope_isolation_and_immutability(self) -> None:
        self._seed(CreatorProfilePostgresOperation.CAPTURE_MATCH_INPUTS)
        request = match_capture_request()
        repository = PsycopgCreatorProfileMatcherRepository(
            connections=self._source(role="profile_matcher")
        )
        repository.capture_match_inputs(request)
        with self._admin_class() as connection:
            privileges = connection.execute(
                "SELECT "
                "pg_catalog.has_schema_privilege('profile_matcher','profile','USAGE'),"
                "pg_catalog.has_table_privilege('profile_matcher',"
                "'profile.creator_profiles','SELECT'),"
                "pg_catalog.has_table_privilege('profile_matcher',"
                "'profile.match_capture_batches','SELECT'),"
                "pg_catalog.has_table_privilege('profile_matcher',"
                "'profile.match_input_snapshots','SELECT')"
            ).fetchone()
        self.assertEqual(privileges, (False, False, False, False))
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="profile_app"),
            autocommit=False,
        ) as connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    "SELECT * FROM "
                    "profile_api.discover_and_capture_creator_profile_match_inputs_v1("
                    "%s,%s,%s)",
                    (
                        request.match_run_id,
                        request.workload_id,
                        request.authorization_digest,
                    ),
                )
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="profile_matcher"),
            autocommit=False,
        ) as connection:
            connection.execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    "SELECT * FROM "
                    "profile_api.discover_and_capture_creator_profile_match_inputs_v1("
                    "%s,%s,%s)",
                    (
                        request.match_run_id,
                        request.workload_id,
                        request.authorization_digest,
                    ),
                )
        with self._admin_class(autocommit=False) as connection:
            with self.assertRaises(psycopg.errors.CheckViolation):
                connection.execute(
                    "UPDATE profile.match_capture_batches "
                    "SET status='COMPLETED' WHERE match_run_id=%s",
                    (request.match_run_id,),
                )

    def test_two_real_callers_concurrent_publish_produce_one_effect(self) -> None:
        self._seed(CreatorProfilePostgresOperation.PUBLISH)
        requests = (
            postgres_command(
                CreatorProfilePostgresOperation.PUBLISH,
                idempotency_material="concurrent-publish-key-a",
            ),
            postgres_command(
                CreatorProfilePostgresOperation.PUBLISH,
                idempotency_material="concurrent-publish-key-b",
            ),
        )

        def invoke(index: int) -> SemanticObservation:
            return self._observe(
                self._factory(),
                CreatorProfilePostgresOperation.PUBLISH,
                requests[index],
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            observations = tuple(executor.map(invoke, (0, 1)))
        self.assertEqual(
            sorted(item.code for item in observations),
            ["PRECONDITION_FAILED", "SUCCEEDED"],
            "semantic RED: two-connection Publish serialization is unavailable",
        )

    def test_active_profile_can_republish_without_unique_index_ordering(self) -> None:
        """A second publish must retire the old row before promoting the draft."""

        self._seed(CreatorProfilePostgresOperation.SAVE_DRAFT)
        factory = self._factory()
        saved = postgres_command(
            CreatorProfilePostgresOperation.SAVE_DRAFT,
            expected_version=2,
            idempotency_material="repeat-publish-save-draft",
        )
        self.assertEqual(
            self._observe(
                factory,
                CreatorProfilePostgresOperation.SAVE_DRAFT,
                saved,
            ).code,
            "SUCCEEDED",
        )
        publish = postgres_command(
            CreatorProfilePostgresOperation.PUBLISH,
            expected_version=3,
            idempotency_material="repeat-publish-promote-draft",
        )
        assert publish.hold is not None
        publish = replace(
            publish,
            profile_version_id=SECOND_VERSION_ID,
            hold=replace(
                publish.hold,
                prospective_aggregate_version=4,
                content_sha256=saved.content_sha256,
            ),
        )
        self.assertEqual(
            self._observe(
                factory,
                CreatorProfilePostgresOperation.PUBLISH,
                publish,
            ).code,
            "SUCCEEDED",
        )
        with self._admin_class() as connection:
            root = connection.execute(
                "SELECT aggregate_version,current_draft_version_id,"
                "current_published_version_id FROM profile.creator_profiles "
                "WHERE id=%s",
                (PROFILE_ID,),
            ).fetchone()
            versions = tuple(
                connection.execute(
                    "SELECT id,status FROM profile.profile_versions "
                    "WHERE profile_id=%s ORDER BY version_no",
                    (PROFILE_ID,),
                ).fetchall()
            )
        self.assertEqual(root, (4, None, SECOND_VERSION_ID))
        self.assertEqual(
            versions,
            ((VERSION_ID, "SUPERSEDED"), (SECOND_VERSION_ID, "PUBLISHED")),
        )

    def test_each_publish_checkpoint_rolls_back_root_version_receipt_audit_outbox(self) -> None:
        for checkpoint in CREATOR_PROFILE_POSTGRES_PUBLISH_WRITE_CHECKPOINTS:
            with self.subTest(checkpoint=checkpoint.value):
                self._seed(CreatorProfilePostgresOperation.PUBLISH)
                with self._admin_class() as connection:
                    before = creator_profile_database_snapshot(connection)
                source = self._source()
                observation = self._observe(
                    self._factory(
                        source=source,
                        fault=RaiseAtProfileCheckpoint(checkpoint),
                    ),
                    CreatorProfilePostgresOperation.PUBLISH,
                    postgres_command(CreatorProfilePostgresOperation.PUBLISH),
                )
                with self._admin_class() as connection:
                    after = creator_profile_database_snapshot(connection)
                self.assertEqual(
                    (observation.code, after, len(source.released), len(source.discarded)),
                    ("SERVICE_UNAVAILABLE", before, 1, 0),
                )

    def test_second_publish_failure_rolls_back_superseded_old_version_and_new_draft(self) -> None:
        checkpoints_after_supersede = (
            CreatorProfilePostgresWriteCheckpoint.PROFILE_VERSION_PUBLISHED,
            CreatorProfilePostgresWriteCheckpoint.PROFILE_ROOT,
            CreatorProfilePostgresWriteCheckpoint.AUDIT_PROFILE_PUBLISHED,
            CreatorProfilePostgresWriteCheckpoint.OUTBOX_PROFILE_PUBLISHED,
            CreatorProfilePostgresWriteCheckpoint.RECEIPT_COMPLETED,
        )
        for checkpoint in checkpoints_after_supersede:
            with self.subTest(checkpoint=checkpoint.value):
                self._seed(CreatorProfilePostgresOperation.SAVE_DRAFT)
                saved = postgres_command(
                    CreatorProfilePostgresOperation.SAVE_DRAFT,
                    expected_version=2,
                    idempotency_material="repeat-publish-rollback-save",
                )
                self.assertEqual(
                    self._observe(
                        self._factory(),
                        CreatorProfilePostgresOperation.SAVE_DRAFT,
                        saved,
                    ).code,
                    "SUCCEEDED",
                )
                publish = postgres_command(
                    CreatorProfilePostgresOperation.PUBLISH,
                    expected_version=3,
                    idempotency_material="repeat-publish-rollback-publish",
                )
                assert publish.hold is not None
                publish = replace(
                    publish,
                    profile_version_id=SECOND_VERSION_ID,
                    hold=replace(
                        publish.hold,
                        prospective_aggregate_version=4,
                        content_sha256=saved.content_sha256,
                    ),
                )
                with self._admin_class() as connection:
                    before = creator_profile_database_snapshot(connection)
                    versions_before = tuple(
                        connection.execute(
                            "SELECT id,status FROM profile.profile_versions "
                            "WHERE profile_id=%s ORDER BY version_no",
                            (PROFILE_ID,),
                        ).fetchall()
                    )
                self.assertEqual(
                    versions_before,
                    ((VERSION_ID, "PUBLISHED"), (SECOND_VERSION_ID, "DRAFT")),
                )
                source = self._source()
                observation = self._observe(
                    self._factory(
                        source=source,
                        fault=RaiseAtProfileCheckpoint(checkpoint),
                    ),
                    CreatorProfilePostgresOperation.PUBLISH,
                    publish,
                )
                with self._admin_class() as connection:
                    after = creator_profile_database_snapshot(connection)
                    versions_after = tuple(
                        connection.execute(
                            "SELECT id,status FROM profile.profile_versions "
                            "WHERE profile_id=%s ORDER BY version_no",
                            (PROFILE_ID,),
                        ).fetchall()
                    )
                self.assertEqual(
                    (
                        observation.code,
                        after,
                        versions_after,
                        len(source.released),
                        len(source.discarded),
                    ),
                    (
                        "SERVICE_UNAVAILABLE",
                        before,
                        versions_before,
                        1,
                        0,
                    ),
                )

    def test_receipt_replay_changed_payload_and_retained_identity_are_exact(self) -> None:
        self._seed(CreatorProfilePostgresOperation.PUBLISH)
        request = postgres_command(CreatorProfilePostgresOperation.PUBLISH)
        changed = postgres_command(
            CreatorProfilePostgresOperation.PUBLISH,
            expected_version=3,
        )
        factory = self._factory()
        cases = (
            (request, SemanticObservation("SUCCEEDED", replayed=False)),
            (request, SemanticObservation("SUCCEEDED", replayed=True)),
            (changed, SemanticObservation("IDEMPOTENCY_KEY_REUSED")),
        )
        for candidate, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(
                    self._observe(
                        factory,
                        CreatorProfilePostgresOperation.PUBLISH,
                        candidate,
                    ),
                    expected,
                )

    def test_editor_choice_validation_runs_after_receipt_replay_only_for_new_work(
        self,
    ) -> None:
        self._seed(CreatorProfilePostgresOperation.PUBLISH)
        request = postgres_command(CreatorProfilePostgresOperation.PUBLISH)
        factory = self._factory()
        calls: list[str] = []

        first = factory.execute_publish(
            request,
            before_mutation=lambda: calls.append("new"),
        )
        replay = factory.execute_publish(
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
        self._seed(CreatorProfilePostgresOperation.PUBLISH)
        request = postgres_command(CreatorProfilePostgresOperation.PUBLISH)
        factory = self._factory()
        rejection = EditorServiceError(
            status=422,
            code="EDITOR_CHOICE_UNAVAILABLE",
            path="/content/interests/0/domain_code",
        )
        with self._admin_class() as connection:
            before = creator_profile_database_snapshot(connection)

        def reject() -> None:
            raise rejection

        with self.assertRaises(EditorServiceError) as captured:
            factory.execute_publish(request, before_mutation=reject)
        with self._admin_class() as connection:
            after_rejection = creator_profile_database_snapshot(connection)
        retry = factory.execute_publish(request, before_mutation=lambda: None)

        self.assertIs(captured.exception, rejection)
        self.assertEqual(after_rejection, before)
        self.assertFalse(retry.replayed)

    def test_commit_sent_ack_loss_discards_connection_and_new_call_recovers(self) -> None:
        self._seed(CreatorProfilePostgresOperation.PUBLISH)
        source = self._source(lose_first_commit_ack=True)
        request = postgres_command(CreatorProfilePostgresOperation.PUBLISH)
        observation = self._observe(
            self._factory(source=source),
            CreatorProfilePostgresOperation.PUBLISH,
            request,
        )
        self.assertEqual(
            (
                observation.code,
                len(source.checked_out),
                len(source.released),
                len(source.discarded),
            ),
            ("COMMAND_OUTCOME_UNKNOWN", 1, 0, 1),
            "semantic RED: COMMIT_SENT physical disposition is unavailable",
        )

    def test_pool_scope_reset_wrong_role_and_secret_sentinel_are_closed(self) -> None:
        self._seed(
            CreatorProfilePostgresOperation.SAVE_DRAFT,
            include_match_authorization=True,
        )
        writer_source = self._source(reuse_released=True)
        matcher_source = self._source(role="profile_matcher")
        request = postgres_command(CreatorProfilePostgresOperation.SAVE_DRAFT)
        match_request = match_capture_request()
        observations = (
            self._observe(
                self._factory(source=writer_source),
                CreatorProfilePostgresOperation.SAVE_DRAFT,
                request,
            ),
            self._observe(
                self._factory(source=writer_source),
                CreatorProfilePostgresOperation.SAVE_DRAFT,
                request,
            ),
            self._observe_match(
                PsycopgCreatorProfileMatcherRepository(connections=matcher_source),
                match_request,
            ),
        )
        for index, observation in enumerate(observations):
            with self.subTest(call=index):
                self.assertEqual(observation.code, "SUCCEEDED", writer_source.trace)
        self.assertEqual(
            len(set(writer_source.backend_pids)),
            1,
            "semantic RED: same physical writer connection was not safely reused",
        )
        diagnostic = "\n".join(
            (
                repr(request),
                repr(match_request),
                repr(observations),
                json.dumps(self._schema_surface(), sort_keys=True),
            )
        )
        for sentinel in RAW_SECRET_SENTINELS:
            with self.subTest(sentinel=sentinel[:16]):
                self.assertNotIn(sentinel, diagnostic)


if __name__ == "__main__":
    unittest.main()
