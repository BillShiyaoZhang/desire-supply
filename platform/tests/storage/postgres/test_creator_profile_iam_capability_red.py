"""Direct-SQL TDD gate for the IAM capability consumed by Creator Profile."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import unittest
import uuid

import psycopg

from desire_platform.identity_access.adapters.postgres.migrations import (
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18
from tests.support.creator_profile_postgres_builders import (
    OTHER_USER_ID,
    seed_exact_creator_iam_authority,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
IAM_MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)


class CreatorProfileIamCapabilityDirectSqlTest(unittest.TestCase):
    """TEST-DB-PROFILE-IAM-CAPABILITY-001."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()
        cls.catalog = MigrationCatalog.load(IAM_MIGRATION_ROOT)
        cls.contract_sources = IamContractSources(
            api_contract_bytes=(
                PLATFORM_ROOT / "contracts/api/iam-v1.openapi.yaml"
            ).read_bytes(),
            event_contract_bytes=(
                PLATFORM_ROOT / "contracts/events/iam-v1.schema.json"
            ).read_bytes(),
        )

    def setUp(self) -> None:
        self.database = self.postgres.create_database()
        report = IamMigrationRunner(
            driver=PsycopgMigrationDriver(
                settings=PsycopgMigrationSettings(
                    conninfo=self.postgres.conninfo(
                        database=self.database,
                        user="iam_migration_runner",
                    ),
                    application_name="desire-profile-iam-capability",
                ),
                dbapi=psycopg,
            ),
            runner_version="creator-profile-iam-capability/1",
        ).run(
            catalog=self.catalog,
            contract_sources=self.contract_sources,
        )
        expected = tuple(
            artifact.descriptor.version for artifact in self.catalog.artifacts
        )
        if report.applied_versions != expected:
            raise AssertionError("IAM capability test did not apply exact catalog")
        with self._admin(autocommit=False) as connection:
            self.authority = seed_exact_creator_iam_authority(
                connection,
                now=datetime.now(timezone.utc),
            )

    def tearDown(self) -> None:
        self.postgres.drop_database(self.database)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.postgres.stop()

    def _admin(self, *, autocommit: bool = True):
        return psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=autocommit,
        )

    def _authority_marker(self, current_bundle_id: uuid.UUID) -> bytes:
        with self._admin() as connection:
            user_version, grant_version = connection.execute(
                "SELECT "
                "(SELECT aggregate_version FROM iam.users WHERE id=%s),"
                "(SELECT aggregate_version FROM iam.user_role_grants WHERE id=%s)",
                (self.authority.actor_user_id, self.authority.creator_grant_id),
            ).fetchone()
        material = "|".join(
            (
                str(self.authority.actor_user_id),
                str(self.authority.session_id),
                str(self.authority.creator_grant_id),
                self.authority.policy_selector_digest.hex(),
                str(current_bundle_id),
                str(user_version),
                str(grant_version),
            )
        )
        return hashlib.sha256(material.encode("utf-8")).digest()

    def _replace_current_bundle(
        self,
        *,
        document_id: uuid.UUID | None = None,
        document_hash: bytes | None = None,
        legal_effect: str = "CONTRACT_ACCEPTANCE",
        accept_current_document: bool = False,
    ) -> tuple[uuid.UUID, bytes]:
        now = datetime.now(timezone.utc)
        new_bundle_id = uuid.uuid4()
        selected_document_id = document_id or uuid.uuid4()
        selected_hash = document_hash or hashlib.sha256(
            ("replacement:" + str(selected_document_id)).encode("utf-8")
        ).digest()
        with self._admin(autocommit=False) as connection:
            connection.execute("SET CONSTRAINTS ALL DEFERRED")
            if document_id is None:
                connection.execute(
                    "INSERT INTO iam.policy_documents ("
                    "id,kind,locale,semantic_version,canonical_body,content_sha256,"
                    "legal_effect,jurisdiction,status,effective_at,"
                    "superseded_by_document_id,publication_command_id,created_at,updated_at"
                    ") VALUES (%s,'TERMS','zh-CN',%s,%s,%s,%s,'CN','ACTIVE',%s,"
                    "NULL,%s,%s,%s)",
                    (
                        selected_document_id,
                        "2.0." + str(selected_document_id.int % 100000),
                        "replacement Creator terms",
                        selected_hash,
                        legal_effect,
                        now - timedelta(minutes=1),
                        uuid.uuid4(),
                        now - timedelta(minutes=2),
                        now - timedelta(minutes=1),
                    ),
                )
            connection.execute(
                "INSERT INTO iam.policy_bundles ("
                "id,selector_digest,status,effective_at,effective_until,"
                "superseded_by_bundle_id,release_manifest_sha256,release_signature,"
                "release_signing_key_id,publication_command_id,aggregate_version,"
                "created_at,updated_at) VALUES ("
                "%s,%s,'DRAFT',NULL,NULL,NULL,%s,%s,'profile-capability-test-v1',"
                "%s,1,%s,%s)",
                (
                    new_bundle_id,
                    self.authority.policy_selector_digest,
                    hashlib.sha256(new_bundle_id.bytes).digest(),
                    b"reviewed-profile-capability-signature",
                    uuid.uuid4(),
                    now - timedelta(minutes=2),
                    now - timedelta(minutes=2),
                ),
            )
            connection.execute(
                "INSERT INTO iam.policy_bundle_documents "
                "(bundle_id,document_id,position,required) VALUES (%s,%s,1,true)",
                (new_bundle_id, selected_document_id),
            )
            connection.execute(
                "UPDATE iam.policy_bundles SET status='SUPERSEDED',"
                "effective_until=%s,superseded_by_bundle_id=%s,"
                "aggregate_version=aggregate_version+1,updated_at=%s WHERE id=%s",
                (now, new_bundle_id, now, self.authority.policy_bundle_id),
            )
            connection.execute(
                "UPDATE iam.policy_bundles SET status='ACTIVE',effective_at=%s,"
                "aggregate_version=2,updated_at=%s WHERE id=%s",
                (now, now, new_bundle_id),
            )
            connection.execute(
                "UPDATE iam.policy_selectors SET current_bundle_id=%s,"
                "aggregate_version=aggregate_version+1,updated_at=%s "
                "WHERE selector_digest=%s",
                (new_bundle_id, now, self.authority.policy_selector_digest),
            )
            if accept_current_document:
                connection.execute(
                    "INSERT INTO iam.policy_acceptances ("
                    "id,user_id,document_id,content_sha256,bundle_id,accepted_at,"
                    "session_id,auth_transaction_id,auth_time,acr_code,amr_codes,"
                    "source_action,command_id,correlation_id,aggregate_version,created_at"
                    ") SELECT %s,%s,%s,%s,%s,%s,%s,auth_transaction_id,auth_time,"
                    "acr_code,amr_codes,'POLICY_ACCEPT',%s,%s,1,%s "
                    "FROM iam.sessions WHERE id=%s",
                    (
                        uuid.uuid4(),
                        self.authority.actor_user_id,
                        selected_document_id,
                        selected_hash,
                        new_bundle_id,
                        now,
                        self.authority.session_id,
                        uuid.uuid4(),
                        uuid.uuid4(),
                        now,
                        self.authority.session_id,
                    ),
                )
        return new_bundle_id, self._authority_marker(new_bundle_id)

    def _lock_row(self, expected_marker: bytes):
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="profile_app"),
            autocommit=False,
        ) as connection:
            for name, value in (
                ("app.scope_kind", "PROFILE_SELF"),
                ("app.operation", "PUBLISH_PROFILE"),
                ("app.actor_user_id", str(self.authority.actor_user_id)),
                ("app.session_id", str(self.authority.session_id)),
            ):
                connection.execute(
                    "SELECT pg_catalog.set_config(%s,%s,true)",
                    (name, value),
                )
            return connection.execute(
                "SELECT user_id,creator_grant_id,current_bundle_id,"
                "authority_marker_sha256,marker_matches "
                "FROM iam_api.lock_creator_profile_self_v1(%s,%s,%s,%s)",
                (
                    self.authority.actor_user_id,
                    self.authority.session_id,
                    "PUBLISH_PROFILE",
                    expected_marker,
                ),
            ).fetchone()

    def test_writer_lock_returns_exact_persistent_creator_authority_marker(self) -> None:
        with self._admin() as connection:
            procedure = connection.execute(
                "SELECT pg_catalog.to_regprocedure("
                "'iam_api.lock_creator_profile_self_v1(uuid,uuid,text,bytea)'"
                ")::text"
            ).fetchone()[0]
            self.assertEqual(
                procedure,
                "iam_api.lock_creator_profile_self_v1(uuid,uuid,text,bytea)",
                "semantic RED: exact Creator Profile SELF IAM lock is absent",
            )
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="profile_app"),
            autocommit=False,
        ) as connection:
            for name, value in (
                ("app.scope_kind", "PROFILE_SELF"),
                ("app.operation", "PUBLISH_PROFILE"),
                ("app.actor_user_id", str(self.authority.actor_user_id)),
                ("app.session_id", str(self.authority.session_id)),
            ):
                connection.execute(
                    "SELECT pg_catalog.set_config(%s,%s,true)",
                    (name, value),
                )
            exact = connection.execute(
                "SELECT user_id,creator_grant_id,current_bundle_id,"
                "authority_marker_sha256,marker_matches "
                "FROM iam_api.lock_creator_profile_self_v1(%s,%s,%s,%s)",
                (
                    self.authority.actor_user_id,
                    self.authority.session_id,
                    "PUBLISH_PROFILE",
                    self.authority.authority_marker_sha256,
                ),
            ).fetchone()
            forged = connection.execute(
                "SELECT authority_marker_sha256,marker_matches "
                "FROM iam_api.lock_creator_profile_self_v1(%s,%s,%s,%s)",
                (
                    self.authority.actor_user_id,
                    self.authority.session_id,
                    "PUBLISH_PROFILE",
                    b"f" * 32,
                ),
            ).fetchone()
            cross_user = connection.execute(
                "SELECT count(*) "
                "FROM iam_api.lock_creator_profile_self_v1(%s,%s,%s,%s)",
                (
                    OTHER_USER_ID,
                    self.authority.session_id,
                    "PUBLISH_PROFILE",
                    b"f" * 32,
                ),
            ).fetchone()[0]
        self.assertEqual(
            exact,
            (
                self.authority.actor_user_id,
                self.authority.creator_grant_id,
                self.authority.policy_bundle_id,
                self.authority.authority_marker_sha256,
                True,
            ),
        )
        self.assertEqual(
            forged,
            (None, False),
            "marker mismatch must not disclose the computed authority marker",
        )
        self.assertEqual(cross_user, 0)

    def test_matcher_cannot_call_unbound_iam_eligibility_capability(self) -> None:
        with self._admin() as connection:
            procedure = connection.execute(
                "SELECT pg_catalog.to_regprocedure("
                "'iam_api.is_creator_match_eligible_v1(uuid)'"
                ")::text"
            ).fetchone()[0]
            self.assertEqual(
                procedure,
                "iam_api.is_creator_match_eligible_v1(uuid)",
                "semantic RED: matcher Creator eligibility projection is absent",
            )
        with self._admin() as connection:
            direct_execute = connection.execute(
                "SELECT pg_catalog.has_function_privilege("
                "'profile_matcher',"
                "'iam_api.is_creator_match_eligible_v1(uuid)','EXECUTE')"
            ).fetchone()[0]
            profile_owner_execute = connection.execute(
                "SELECT pg_catalog.has_function_privilege("
                "'profile_schema_owner',"
                "'iam_api.is_creator_match_eligible_v1(uuid)','EXECUTE')"
            ).fetchone()[0]
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="profile_matcher"),
            autocommit=False,
        ) as connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    "SELECT iam_api.is_creator_match_eligible_v1(%s)",
                    (self.authority.actor_user_id,),
                ).fetchone()
        self.assertIs(
            direct_execute,
            False,
            "semantic RED: profile_matcher can enumerate arbitrary IAM users",
        )
        self.assertIs(profile_owner_execute, True)

    def test_old_source_acceptance_satisfies_replacement_current_bundle(self) -> None:
        bundle_id, marker = self._replace_current_bundle(
            document_id=self.authority.required_document_id,
            document_hash=self.authority.required_document_sha256,
        )
        row = self._lock_row(marker)
        self.assertEqual(
            row,
            (
                self.authority.actor_user_id,
                self.authority.creator_grant_id,
                bundle_id,
                marker,
                True,
            ),
            "semantic RED: exact old-source acceptance must satisfy current requirements",
        )

    def test_wrong_current_legal_effect_is_hidden_even_with_exact_acceptance(self) -> None:
        _bundle_id, marker = self._replace_current_bundle(
            legal_effect="CONSENT_TEXT",
            accept_current_document=True,
        )
        self.assertIsNone(
            self._lock_row(marker),
            "current CONSENT_TEXT cannot satisfy Creator authority policy acceptance",
        )

    def test_wrong_current_document_hash_without_acceptance_is_hidden(self) -> None:
        _bundle_id, marker = self._replace_current_bundle()
        self.assertIsNone(
            self._lock_row(marker),
            "acceptance for another document/hash cannot satisfy current requirements",
        )


if __name__ == "__main__":
    unittest.main()
