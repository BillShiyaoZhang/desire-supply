"""Direct PostgreSQL 18 contract for the narrow Accept policy lock function."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any
import unittest
import uuid

import psycopg

from desire_platform.identity_access.adapters.postgres.accept_access_invitation import (
    PsycopgAcceptAccessInvitationUnitOfWorkFactory,
)
from desire_platform.identity_access.adapters.postgres.migrations import (
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from desire_platform.identity_access.domain.errors import IamError
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18
from tests.support.iam_authority_lifecycle_builders import ClosedSchemaValidator


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
POLICY_NAMES = (
    "rls_accept_lock_invitation_definer",
    "rls_accept_lock_selector_definer",
    "rls_accept_lock_bundle_definer",
    "rls_accept_lock_bundle_document_definer",
    "rls_accept_lock_document_definer",
    "rls_accept_lock_offer_definer",
    "rls_accept_lock_offer_category_definer",
)


class AcceptPolicyGraphLockContractRedTest(unittest.TestCase):
    """The online role reaches current policy locks only through one function."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()
        cls.catalog = MigrationCatalog.load(MIGRATION_ROOT)
        cls.contract_sources = IamContractSources(
            api_contract_bytes=(
                PLATFORM_ROOT / "contracts/api/iam-v1.openapi.yaml"
            ).read_bytes(),
            event_contract_bytes=(
                PLATFORM_ROOT / "contracts/events/iam-v1.schema.json"
            ).read_bytes(),
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.postgres.stop()

    def setUp(self) -> None:
        self.database = self.postgres.create_database()
        report = IamMigrationRunner(
            driver=PsycopgMigrationDriver(
                settings=PsycopgMigrationSettings(
                    conninfo=self.postgres.conninfo(
                        database=self.database,
                        user="iam_migration_runner",
                    ),
                    application_name="desire-iam-accept-policy-lock-red",
                ),
                dbapi=psycopg,
            ),
            runner_version="accept-policy-lock-red/1",
        ).run(catalog=self.catalog, contract_sources=self.contract_sources)
        self.assertEqual(
            report.applied_versions,
            tuple(artifact.descriptor.version for artifact in self.catalog.artifacts),
        )

        # Reuse the already constraint-complete Accept fixture without exposing
        # the imported TestCase as a second discovered test class in this module.
        from tests.storage.postgres.test_accept_access_invitation_uow_red import (
            RealPostgres18AcceptAccessInvitationUowRedTest,
        )

        support = RealPostgres18AcceptAccessInvitationUowRedTest
        with self._connect_admin() as connection:
            self.creator_policy = support._seed_policy(
                self,
                connection,
                purpose="CREATOR_ENROLLMENT",
                scope_type="USER_ROLE",
                role="CREATOR",
            )
        self.fixture = support._seed_accept_graph(self, kind="creator")
        self.request = support._request(self, self.fixture)

    def tearDown(self) -> None:
        self.postgres.drop_database(self.database)

    def _connect_admin(self, *, autocommit: bool = False):
        return psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=autocommit,
        )

    def _connect_onboarding(self, *, autocommit: bool = False):
        return psycopg.connect(
            self.postgres.conninfo(database=self.database, user="iam_onboarding"),
            autocommit=autocommit,
        )

    def _function_catalog_row(self):
        with self._connect_admin() as connection:
            return connection.execute(
                "SELECT function.prosecdef,function.provolatile,function.proparallel,"
                "owner.rolname,function.proconfig,"
                "NOT EXISTS (SELECT 1 FROM aclexplode(COALESCE(function.proacl,"
                "acldefault('f',function.proowner))) AS acl "
                "WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE'),"
                "EXISTS (SELECT 1 FROM aclexplode(COALESCE(function.proacl,"
                "acldefault('f',function.proowner))) AS acl "
                "JOIN pg_catalog.pg_roles AS grantee ON grantee.oid=acl.grantee "
                "WHERE grantee.rolname='iam_onboarding' "
                "AND acl.privilege_type='EXECUTE'),"
                "pg_catalog.pg_get_function_result(function.oid) "
                "FROM pg_catalog.pg_proc AS function "
                "JOIN pg_catalog.pg_namespace AS namespace "
                "ON namespace.oid=function.pronamespace "
                "JOIN pg_catalog.pg_roles AS owner ON owner.oid=function.proowner "
                "WHERE namespace.nspname='iam' "
                "AND function.oid=pg_catalog.to_regprocedure("
                "'iam.lock_accept_policy_graph_v1(uuid,bytea,uuid)')",
            ).fetchone()

    def _require_function(self) -> None:
        self.assertIsNotNone(
            self._function_catalog_row(),
            "semantic RED: the reviewed Accept policy lock function is unavailable",
        )

    def _set_exact_context(self, connection: Any, *, bundle_id=None) -> None:
        values = (
            ("app.scope_kind", "AUTH_PROTOCOL"),
            ("app.operation", "ACCEPT"),
            ("app.actor_user_id", str(self.fixture.actor_id)),
            ("app.target_user_id", str(self.fixture.actor_id)),
            ("app.target_invitation_id", str(self.fixture.invitation_id)),
            ("app.session_id", str(self.fixture.session_id)),
            ("app.session_family_id", str(self.fixture.session_family_id)),
            ("app.auth_transaction_id", str(self.fixture.auth_transaction_id)),
            ("app.command_id", str(self.request.scope.command_id)),
            (
                "app.policy_selector_digest",
                self.fixture.policy.selector_digest.hex(),
            ),
            (
                "app.policy_bundle_id",
                str(bundle_id or self.fixture.policy.bundle_id),
            ),
        )
        for name, value in values:
            connection.execute(
                "SELECT pg_catalog.set_config(%s,%s,true)",
                (name, value),
            )

    def _seed_acceptance(
        self,
        *,
        document_id,
        content_hash,
        bundle_id=None,
    ) -> uuid.UUID:
        acceptance_id = uuid.uuid4()
        now = self.request.hold.evaluated_at
        with self._connect_admin() as connection:
            session = connection.execute(
                "SELECT auth_transaction_id,auth_time,acr_code,amr_codes "
                "FROM iam.sessions WHERE id=%s",
                (self.fixture.session_id,),
            ).fetchone()
            connection.execute(
                "INSERT INTO iam.policy_acceptances ("
                "id,user_id,document_id,content_sha256,bundle_id,accepted_at,"
                "session_id,auth_transaction_id,auth_time,acr_code,amr_codes,"
                "source_action,command_id,correlation_id,aggregate_version,created_at"
                ") VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'POLICY_ACCEPT',"
                "%s,%s,1,%s)",
                (
                    acceptance_id,
                    self.fixture.actor_id,
                    document_id,
                    content_hash,
                    bundle_id or self.fixture.policy.bundle_id,
                    now,
                    self.fixture.session_id,
                    session[0],
                    session[1],
                    session[2],
                    session[3],
                    uuid.uuid4(),
                    uuid.uuid4(),
                    now,
                ),
            )
        return acceptance_id

    def _call_function(self, connection: Any, *, bundle_id=None):
        return connection.execute(
            "SELECT * FROM iam.lock_accept_policy_graph_v1(%s,%s,%s)",
            (
                self.fixture.invitation_id,
                self.fixture.policy.selector_digest,
                bundle_id or self.fixture.policy.bundle_id,
            ),
        ).fetchone()

    def test_forward_only_catalog_surface_and_acl_are_exact(self) -> None:
        self.assertIn(
            9,
            tuple(artifact.descriptor.version for artifact in self.catalog.artifacts),
            "semantic RED: forward-only Accept policy lock migration is absent",
        )
        row = self._function_catalog_row()
        self.assertIsNotNone(row)
        self.assertEqual(
            row[:7],
            (
                True,
                "v",
                "u",
                "schema_owner",
                ["search_path=pg_catalog, iam"],
                True,
                True,
            ),
        )
        for output_name in (
            "access_purpose text",
            "current_bundle_id uuid",
            "bundle_documents jsonb",
            "consent_offers jsonb",
        ):
            self.assertIn(output_name, row[7])

        with self._connect_admin() as connection:
            policies = tuple(
                row[0]
                for row in connection.execute(
                    "SELECT policyname FROM pg_catalog.pg_policies "
                    "WHERE schemaname='iam' AND policyname=ANY(%s) "
                    "ORDER BY policyname",
                    (list(POLICY_NAMES),),
                ).fetchall()
            )
            update_grants = connection.execute(
                "SELECT table_name FROM information_schema.role_table_grants "
                "WHERE grantee='iam_onboarding' AND privilege_type='UPDATE' "
                "AND table_schema='iam' AND table_name=ANY(%s)",
                (
                    [
                        "policy_selectors",
                        "policy_bundles",
                        "policy_bundle_documents",
                        "policy_documents",
                        "consent_offers",
                        "consent_offer_data_categories",
                    ],
                ),
            ).fetchall()
        self.assertEqual(policies, tuple(sorted(POLICY_NAMES)))
        self.assertEqual(update_grants, [])

    def test_exact_online_call_returns_closed_locked_graph(self) -> None:
        self._require_function()
        with self._connect_onboarding(autocommit=True) as connection:
            connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED")
            self._set_exact_context(connection)
            row = self._call_function(connection)
            self.assertIsNotNone(row)
            self.assertEqual(row[0:4], (
                "CREATOR_ENROLLMENT",
                "USER_ROLE",
                "CREATOR",
                self.fixture.policy.bundle_id,
            ))
            self.assertEqual(row[4], "ACTIVE")
            self.assertEqual(len(row[7]), 2)
            required = next(item for item in row[7] if item["required"])
            self.assertEqual(
                required,
                {
                    "document_id": str(self.fixture.policy.required_document_id),
                    "content_sha256": self.fixture.policy.required_document_hash.hex(),
                    "status": "ACTIVE",
                    "kind": "TERMS",
                    "legal_effect": "CONTRACT_ACCEPTANCE",
                    "required": True,
                    "position": 1,
                },
            )
            self.assertEqual(len(row[8]), 1)
            self.assertEqual(
                row[8][0]["consent_offer_id"],
                str(self.fixture.policy.consent_offer_id),
            )
            self.assertEqual(
                row[8][0]["categories"],
                ["PROFILE", "MATCHING", "RESEARCH"],
            )
            self.assertEqual(len(row[8][0]["canonical_offer_sha256"]), 64)
            self.assertEqual(row[8][0]["supporting_document_status"], "ACTIVE")
            self.assertEqual(row[8][0]["supporting_document_kind"], "CONSENT_TEXT")

            with self._connect_admin(autocommit=True) as publisher:
                publisher.execute("BEGIN")
                publisher.execute("SET LOCAL lock_timeout='200ms'")
                with self.assertRaises(psycopg.errors.LockNotAvailable):
                    publisher.execute(
                        "UPDATE iam.policy_selectors SET updated_at=updated_at "
                        "WHERE selector_digest=%s",
                        (self.fixture.policy.selector_digest,),
                    )
                publisher.execute("ROLLBACK")
            connection.execute("ROLLBACK")

    def test_prior_acceptance_reuse_rls_is_exact_and_read_only(self) -> None:
        required_id = self._seed_acceptance(
            document_id=self.fixture.policy.required_document_id,
            content_hash=self.fixture.policy.required_document_hash,
        )
        optional_id = self._seed_acceptance(
            document_id=self.fixture.policy.consent_document_id,
            content_hash=self.fixture.policy.consent_document_hash,
        )
        with self._connect_onboarding(autocommit=True) as connection:
            connection.execute("BEGIN")
            self._set_exact_context(connection)
            visible = connection.execute(
                "SELECT id FROM iam.policy_acceptances WHERE user_id=%s "
                "AND bundle_id=%s ORDER BY id",
                (self.fixture.actor_id, self.fixture.policy.bundle_id),
            ).fetchall()
            self.assertEqual(visible, [(required_id,)])
            self.assertNotIn(optional_id, {row[0] for row in visible})
            connection.execute(
                "SELECT pg_catalog.set_config('app.actor_user_id',%s,true)",
                (str(uuid.uuid4()),),
            )
            forged = connection.execute(
                "SELECT id FROM iam.policy_acceptances WHERE id=%s",
                (required_id,),
            ).fetchall()
            self.assertEqual(forged, [])
            connection.execute("ROLLBACK")

        with self._connect_admin() as connection:
            update_grant = connection.execute(
                "SELECT has_table_privilege('iam_onboarding',"
                "'iam.policy_acceptances','UPDATE')"
            ).fetchone()
        self.assertEqual(update_grant, (False,))

        with self._connect_admin() as publisher:
            current = publisher.execute(
                "SELECT current_bundle_id FROM iam.policy_selectors "
                "WHERE selector_digest=%s",
                (self.fixture.policy.selector_digest,),
            ).fetchone()
            self.assertEqual(current, (self.fixture.policy.bundle_id,))

    def test_prior_acceptance_reuses_old_source_only_through_healthy_current(self) -> None:
        """Identity is user/document/hash; the immutable source bundle is audit."""

        acceptance_id = self._seed_acceptance(
            document_id=self.fixture.policy.required_document_id,
            content_hash=self.fixture.policy.required_document_hash,
        )
        from tests.storage.postgres.test_accept_access_invitation_uow_red import (
            RealPostgres18AcceptAccessInvitationUowRedTest,
        )

        current = (
            RealPostgres18AcceptAccessInvitationUowRedTest._publish_replacement_policy(
                self,
                self.fixture.policy,
                reuse_required_document=True,
            )
        )
        with self._connect_onboarding(autocommit=True) as connection:
            connection.execute("BEGIN")
            self._set_exact_context(connection, bundle_id=current.bundle_id)
            visible = connection.execute(
                "SELECT id,bundle_id FROM iam.policy_acceptances WHERE id=%s",
                (acceptance_id,),
            ).fetchall()
            self.assertEqual(
                visible,
                [(acceptance_id, self.fixture.policy.bundle_id)],
            )
            connection.execute("ROLLBACK")

    def test_prior_acceptance_is_hidden_for_wrong_hash_or_legal_effect(self) -> None:
        acceptance_id = self._seed_acceptance(
            document_id=self.fixture.policy.required_document_id,
            content_hash=self.fixture.policy.required_document_hash,
        )
        from tests.storage.postgres.test_accept_access_invitation_uow_red import (
            RealPostgres18AcceptAccessInvitationUowRedTest,
        )

        different_current = (
            RealPostgres18AcceptAccessInvitationUowRedTest._publish_replacement_policy(
                self,
                self.fixture.policy,
            )
        )
        with self._connect_onboarding(autocommit=True) as connection:
            connection.execute("BEGIN")
            self._set_exact_context(
                connection,
                bundle_id=different_current.bundle_id,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT id FROM iam.policy_acceptances WHERE id=%s",
                    (acceptance_id,),
                ).fetchall(),
                [],
            )
            connection.execute("ROLLBACK")

        current_acceptance_id = self._seed_acceptance(
            document_id=different_current.required_document_id,
            content_hash=different_current.required_document_hash,
            bundle_id=different_current.bundle_id,
        )
        with self._connect_admin() as connection:
            connection.execute(
                "ALTER TABLE iam.policy_documents "
                "DISABLE TRIGGER trg_policy_document_immutable"
            )
            connection.execute(
                "ALTER TABLE iam.policy_documents "
                "DISABLE TRIGGER trg_policy_publication_consistent"
            )
            connection.execute(
                "UPDATE iam.policy_documents SET legal_effect='CONSENT_TEXT' "
                "WHERE id=%s",
                (different_current.required_document_id,),
            )
            connection.execute(
                "ALTER TABLE iam.policy_documents "
                "ENABLE TRIGGER trg_policy_document_immutable"
            )
            connection.execute(
                "ALTER TABLE iam.policy_documents "
                "ENABLE TRIGGER trg_policy_publication_consistent"
            )
        with self._connect_onboarding(autocommit=True) as connection:
            connection.execute("BEGIN")
            self._set_exact_context(
                connection,
                bundle_id=different_current.bundle_id,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT id FROM iam.policy_acceptances WHERE id=%s",
                    (current_acceptance_id,),
                ).fetchall(),
                [],
            )
            connection.execute("ROLLBACK")

    def test_prior_acceptance_is_hidden_for_inactive_or_future_current(self) -> None:
        acceptance_id = self._seed_acceptance(
            document_id=self.fixture.policy.required_document_id,
            content_hash=self.fixture.policy.required_document_hash,
        )

        def assert_hidden(*, status: str, effective_at: Any) -> None:
            with self._connect_admin() as connection:
                original = connection.execute(
                    "SELECT status,effective_at FROM iam.policy_bundles WHERE id=%s",
                    (self.fixture.policy.bundle_id,),
                ).fetchone()
                connection.execute(
                    "ALTER TABLE iam.policy_bundles "
                    "DISABLE TRIGGER trg_policy_bundle_immutable"
                )
                connection.execute(
                    "ALTER TABLE iam.policy_bundles "
                    "DISABLE TRIGGER trg_policy_publication_consistent"
                )
                connection.execute(
                    "UPDATE iam.policy_bundles SET status=%s,effective_at=%s "
                    "WHERE id=%s",
                    (status, effective_at, self.fixture.policy.bundle_id),
                )
                connection.execute(
                    "ALTER TABLE iam.policy_bundles "
                    "ENABLE TRIGGER trg_policy_bundle_immutable"
                )
                connection.execute(
                    "ALTER TABLE iam.policy_bundles "
                    "ENABLE TRIGGER trg_policy_publication_consistent"
                )

            with self._connect_onboarding(autocommit=True) as connection:
                connection.execute("BEGIN")
                self._set_exact_context(connection)
                self.assertEqual(
                    connection.execute(
                        "SELECT id FROM iam.policy_acceptances WHERE id=%s",
                        (acceptance_id,),
                    ).fetchall(),
                    [],
                )
                connection.execute("ROLLBACK")

            with self._connect_admin() as connection:
                connection.execute(
                    "ALTER TABLE iam.policy_bundles "
                    "DISABLE TRIGGER trg_policy_bundle_immutable"
                )
                connection.execute(
                    "ALTER TABLE iam.policy_bundles "
                    "DISABLE TRIGGER trg_policy_publication_consistent"
                )
                connection.execute(
                    "UPDATE iam.policy_bundles SET status=%s,effective_at=%s "
                    "WHERE id=%s",
                    (original[0], original[1], self.fixture.policy.bundle_id),
                )
                connection.execute(
                    "ALTER TABLE iam.policy_bundles "
                    "ENABLE TRIGGER trg_policy_bundle_immutable"
                )
                connection.execute(
                    "ALTER TABLE iam.policy_bundles "
                    "ENABLE TRIGGER trg_policy_publication_consistent"
                )

        assert_hidden(status="DRAFT", effective_at=None)
        assert_hidden(
            status="ACTIVE",
            effective_at=self.request.hold.evaluated_at + timedelta(days=1),
        )

    def test_public_wrong_role_missing_and_forged_scope_are_denied(self) -> None:
        self._require_function()
        with self._connect_admin() as connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                self._call_function(connection)

        with self._connect_onboarding(autocommit=True) as connection:
            connection.execute("BEGIN")
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                self._call_function(connection)
            connection.execute("ROLLBACK")

        with self._connect_onboarding(autocommit=True) as connection:
            connection.execute("BEGIN")
            forged_bundle = uuid.uuid4()
            self._set_exact_context(connection, bundle_id=forged_bundle)
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                self._call_function(connection)
            connection.execute("ROLLBACK")

    def test_inactive_required_document_is_returned_and_adapter_fails_closed(self) -> None:
        """Corruption cannot be filtered into a smaller apparently-valid graph."""

        self._require_function()
        with self._connect_admin() as connection:
            connection.execute(
                "ALTER TABLE iam.policy_documents DISABLE TRIGGER ALL"
            )
            connection.execute(
                "ALTER TABLE iam.policy_documents DROP CONSTRAINT "
                "ck_policy_document_lifecycle"
            )
            connection.execute(
                "UPDATE iam.policy_documents SET status='DRAFT' WHERE id=%s",
                (self.fixture.policy.required_document_id,),
            )
            connection.execute(
                "ALTER TABLE iam.policy_documents ENABLE TRIGGER ALL"
            )

        with self._connect_onboarding(autocommit=True) as connection:
            connection.execute("BEGIN")
            self._set_exact_context(connection)
            graph = self._call_function(connection)
            required = next(item for item in graph[7] if item["required"])
            self.assertEqual(required["status"], "DRAFT")
            connection.execute("ROLLBACK")

        from tests.storage.postgres.test_accept_access_invitation_uow_red import (
            TrackingRealConnectionSource,
        )

        source = TrackingRealConnectionSource(
            self.postgres.conninfo(
                database=self.database,
                user="iam_onboarding",
            )
        )
        factory = PsycopgAcceptAccessInvitationUnitOfWorkFactory(
            connections=source,
            event_validator=ClosedSchemaValidator.for_events(),
            response_validator=ClosedSchemaValidator.for_openapi(),
        )
        with self.assertRaises(IamError) as captured:
            factory.execute(self.request)
        self.assertEqual(
            captured.exception.code,
            "POLICY_CONFIGURATION_UNAVAILABLE",
        )
        with self._connect_admin() as connection:
            receipts = connection.execute(
                "SELECT count(*) FROM infra.command_receipts WHERE id=%s",
                (self.request.scope.command_id,),
            ).fetchone()[0]
        self.assertEqual(receipts, 0)

    def test_corrupt_canonical_offer_hash_is_recomputed_and_fails_closed(self) -> None:
        with self._connect_admin() as connection:
            connection.execute(
                "ALTER TABLE iam.consent_offers "
                "DISABLE TRIGGER trg_consent_offer_immutable"
            )
            connection.execute(
                "ALTER TABLE iam.consent_offers "
                "DISABLE TRIGGER trg_policy_publication_consistent"
            )
            connection.execute(
                "UPDATE iam.consent_offers SET canonical_offer_sha256=%s WHERE id=%s",
                (b"x" * 32, self.fixture.policy.consent_offer_id),
            )
            connection.execute(
                "ALTER TABLE iam.consent_offers "
                "ENABLE TRIGGER trg_consent_offer_immutable"
            )
            connection.execute(
                "ALTER TABLE iam.consent_offers "
                "ENABLE TRIGGER trg_policy_publication_consistent"
            )

        from tests.storage.postgres.test_accept_access_invitation_uow_red import (
            TrackingRealConnectionSource,
        )

        source = TrackingRealConnectionSource(
            self.postgres.conninfo(database=self.database, user="iam_onboarding")
        )
        factory = PsycopgAcceptAccessInvitationUnitOfWorkFactory(
            connections=source,
            event_validator=ClosedSchemaValidator.for_events(),
            response_validator=ClosedSchemaValidator.for_openapi(),
        )
        with self.assertRaises(IamError) as captured:
            factory.execute(self.request)
        self.assertEqual(
            captured.exception.code,
            "POLICY_CONFIGURATION_UNAVAILABLE",
        )
        with self._connect_admin() as connection:
            receipts = connection.execute(
                "SELECT count(*) FROM infra.command_receipts WHERE id=%s",
                (self.request.scope.command_id,),
            ).fetchone()[0]
        self.assertEqual(receipts, 0)

    def test_stale_candidate_differs_from_corrupt_current_error_mapping(self) -> None:
        from tests.storage.postgres.test_accept_access_invitation_uow_red import (
            TrackingRealConnectionSource,
        )

        def factory():
            source = TrackingRealConnectionSource(
                self.postgres.conninfo(
                    database=self.database,
                    user="iam_onboarding",
                )
            )
            return PsycopgAcceptAccessInvitationUnitOfWorkFactory(
                connections=source,
                event_validator=ClosedSchemaValidator.for_events(),
                response_validator=ClosedSchemaValidator.for_openapi(),
            )

        stale = replace(
            self.request,
            scope=replace(
                self.request.scope,
                policy_bundle_id=uuid.uuid4(),
            ),
        )
        with self.assertRaises(IamError) as captured:
            factory().execute(stale)
        self.assertEqual(captured.exception.code, "POLICY_BUNDLE_CHANGED")

        with self._connect_admin() as connection:
            connection.execute(
                "ALTER TABLE iam.policy_selectors "
                "DISABLE TRIGGER trg_policy_selector_immutable"
            )
            connection.execute(
                "ALTER TABLE iam.policy_selectors "
                "DISABLE TRIGGER trg_policy_publication_consistent"
            )
            connection.execute(
                "UPDATE iam.policy_selectors SET current_bundle_id=NULL "
                "WHERE selector_digest=%s",
                (self.fixture.policy.selector_digest,),
            )
            connection.execute(
                "ALTER TABLE iam.policy_selectors "
                "ENABLE TRIGGER trg_policy_publication_consistent"
            )
            connection.execute(
                "ALTER TABLE iam.policy_selectors "
                "ENABLE TRIGGER trg_policy_selector_immutable"
            )
        with self.assertRaises(IamError) as captured:
            factory().execute(self.request)
        self.assertEqual(
            captured.exception.code,
            "POLICY_CONFIGURATION_UNAVAILABLE",
        )
        with self._connect_admin() as connection:
            connection.execute(
                "ALTER TABLE iam.policy_selectors "
                "DISABLE TRIGGER trg_policy_selector_immutable"
            )
            connection.execute(
                "ALTER TABLE iam.policy_selectors "
                "DISABLE TRIGGER trg_policy_publication_consistent"
            )
            connection.execute(
                "UPDATE iam.policy_selectors SET current_bundle_id=%s "
                "WHERE selector_digest=%s",
                (
                    self.fixture.policy.bundle_id,
                    self.fixture.policy.selector_digest,
                ),
            )
            connection.execute(
                "SET CONSTRAINTS iam.fk_policy_selector_current_bundle IMMEDIATE"
            )
            connection.execute(
                "ALTER TABLE iam.policy_selectors "
                "ENABLE TRIGGER trg_policy_publication_consistent"
            )
            connection.execute(
                "ALTER TABLE iam.policy_selectors "
                "ENABLE TRIGGER trg_policy_selector_immutable"
            )

        with self._connect_admin() as connection:
            effective_at = connection.execute(
                "SELECT effective_at FROM iam.policy_bundles WHERE id=%s",
                (self.fixture.policy.bundle_id,),
            ).fetchone()[0]
            connection.execute(
                "ALTER TABLE iam.policy_bundles "
                "DISABLE TRIGGER trg_policy_bundle_immutable"
            )
            connection.execute(
                "ALTER TABLE iam.policy_bundles "
                "DISABLE TRIGGER trg_policy_publication_consistent"
            )
            connection.execute(
                "UPDATE iam.policy_bundles SET effective_at=%s WHERE id=%s",
                (
                    self.request.hold.evaluated_at + timedelta(days=1),
                    self.fixture.policy.bundle_id,
                ),
            )
            connection.execute(
                "ALTER TABLE iam.policy_bundles "
                "ENABLE TRIGGER trg_policy_bundle_immutable"
            )
            connection.execute(
                "ALTER TABLE iam.policy_bundles "
                "ENABLE TRIGGER trg_policy_publication_consistent"
            )
        with self.assertRaises(IamError) as captured:
            factory().execute(self.request)
        self.assertEqual(
            captured.exception.code,
            "POLICY_CONFIGURATION_UNAVAILABLE",
        )
        with self._connect_admin() as connection:
            connection.execute(
                "ALTER TABLE iam.policy_bundles "
                "DISABLE TRIGGER trg_policy_bundle_immutable"
            )
            connection.execute(
                "ALTER TABLE iam.policy_bundles "
                "DISABLE TRIGGER trg_policy_publication_consistent"
            )
            connection.execute(
                "UPDATE iam.policy_bundles SET effective_at=%s WHERE id=%s",
                (effective_at, self.fixture.policy.bundle_id),
            )
            connection.execute(
                "ALTER TABLE iam.policy_bundles "
                "ENABLE TRIGGER trg_policy_bundle_immutable"
            )
            connection.execute(
                "ALTER TABLE iam.policy_bundles "
                "ENABLE TRIGGER trg_policy_publication_consistent"
            )

        with self._connect_admin() as connection:
            receipts = connection.execute(
                "SELECT count(*) FROM infra.command_receipts WHERE id=%s",
                (self.request.scope.command_id,),
            ).fetchone()[0]
        self.assertEqual(receipts, 0)

    def test_online_role_still_cannot_take_direct_policy_row_locks(self) -> None:
        self._require_function()
        with self._connect_onboarding(autocommit=True) as connection:
            connection.execute("BEGIN")
            self._set_exact_context(connection)
            visible = connection.execute(
                "SELECT current_bundle_id FROM iam.policy_selectors "
                "WHERE selector_digest=%s",
                (self.fixture.policy.selector_digest,),
            ).fetchone()
            self.assertEqual(visible, (self.fixture.policy.bundle_id,))
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    "SELECT current_bundle_id FROM iam.policy_selectors "
                    "WHERE selector_digest=%s FOR SHARE",
                    (self.fixture.policy.selector_digest,),
                )
            connection.execute("ROLLBACK")


if __name__ == "__main__":
    unittest.main()
