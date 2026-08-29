"""TEST-PG-IAM-EDITOR-PRINCIPAL-001: authoritative workspace resolution."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, fields
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import unittest
from uuid import UUID, uuid4

import psycopg

from desire_platform.identity_access.adapters.postgres.editor_principal import (
    EditorWorkspaceListRequest,
    EditorPrincipalResolutionRequest,
    PsycopgEditorPrincipalResolver,
    ResolvedEditorWorkspace,
    WorkspaceKind,
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
from tests.support.demand_postgres_builders import (
    ACTOR_USER_ID,
    ORGANIZATION_ID,
    SESSION_ID,
    seed_exact_demand_owner_iam_authority,
)


ROOT = Path(__file__).resolve().parents[3]
MIGRATION = (
    ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
    / "0019_expand__editor_principal_resolver.sql"
)


def _uuid(value: int) -> UUID:
    return UUID(int=value)


class EditorPrincipalResolverContractRedTest(unittest.TestCase):
    def test_request_and_result_are_frozen_closed_and_password_free(self) -> None:
        request = EditorPrincipalResolutionRequest(
            actor_user_id=_uuid(1),
            session_id=_uuid(2),
            requested_workspace_id=None,
        )
        workspace = ResolvedEditorWorkspace(
            workspace_id="personal:%s" % request.actor_user_id,
            workspace_kind=WorkspaceKind.PERSONAL,
            user_id=request.actor_user_id,
            session_id=request.session_id,
            organization_id=None,
            membership_id=None,
            organization_role_codes=(),
            user_role_codes=("CREATOR",),
            platform_duty_codes=("OPERATIONS_REVIEWER",),
            principal_marker=b"m" * 32,
        )
        with self.assertRaises(FrozenInstanceError):
            workspace.workspace_id = "changed"  # type: ignore[misc]
        names = {field.name for value in (request, workspace) for field in fields(value)}
        self.assertNotIn("password", names)
        self.assertNotIn("organization_role", names)
        self.assertNotIn("requested_organization_id", names)
        self.assertNotIn("requested_role", names)
        self.assertNotIn("raw_session_handle", names)

    def test_selection_is_closed_and_client_cannot_select_role_or_organization(self) -> None:
        self.assertEqual(
            tuple(item.value for item in WorkspaceKind),
            ("ORGANIZATION", "PERSONAL", "PLATFORM"),
        )
        self.assertEqual(
            {field.name for field in fields(EditorPrincipalResolutionRequest)},
            {"actor_user_id", "session_id", "requested_workspace_id"},
        )
        self.assertEqual(
            {field.name for field in fields(ResolvedEditorWorkspace)},
            {
                "workspace_id",
                "workspace_kind",
                "user_id",
                "session_id",
                "organization_id",
                "membership_id",
                "organization_role_codes",
                "user_role_codes",
                "platform_duty_codes",
                "principal_marker",
            },
        )
        self.assertEqual(
            {
                name
                for name in dir(PsycopgEditorPrincipalResolver)
                if not name.startswith("_")
            },
            {"list_workspaces", "resolve"},
        )

    def test_migration_exposes_one_exact_definer_without_table_rls_broadening(self) -> None:
        sql = MIGRATION.read_text(encoding="utf-8")
        for fragment in (
            "EDITOR_PRINCIPAL",
            "iam_api.resolve_editor_principal_v1",
            "rls_editor_principal_user_definer",
            "rls_editor_principal_session_definer",
            "rls_editor_principal_membership_definer",
            "rls_editor_principal_platform_duty_definer",
            "principal_marker_sha256",
            "GRANT EXECUTE ON FUNCTION iam_api.resolve_editor_principal_v1",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, sql)
        self.assertNotIn("GRANT SELECT ON iam.memberships TO iam_app", sql)
        self.assertNotIn("password", sql.lower())


class _IamAppConnections:
    def __init__(self, conninfo: str) -> None:
        self._conninfo = conninfo

    def checkout(self):
        return psycopg.connect(self._conninfo, autocommit=True)

    def release(self, connection) -> None:
        connection.close()

    def discard(self, connection) -> None:
        connection.close()


class EditorPrincipalResolverRealPostgresTest(unittest.TestCase):
    """TEST-PG-IAM-EDITOR-PRINCIPAL-002: real PG18/RLS authority."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()
        cls.catalog = MigrationCatalog.load(MIGRATION.parent)
        cls.contract_sources = IamContractSources(
            api_contract_bytes=(ROOT / "contracts/api/iam-v1.openapi.yaml").read_bytes(),
            event_contract_bytes=(
                ROOT / "contracts/events/iam-v1.schema.json"
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
                    application_name="desire-editor-principal-test",
                ),
                dbapi=psycopg,
            ),
            runner_version="editor-principal-test/1",
        ).run(catalog=self.catalog, contract_sources=self.contract_sources)
        self.assertEqual(
            report.applied_versions,
            tuple(item.descriptor.version for item in self.catalog.artifacts),
        )
        self.now = datetime.now(timezone.utc)
        with self._admin(autocommit=False) as connection:
            self.authority = seed_exact_demand_owner_iam_authority(
                connection,
                now=self.now,
            )
            self.creator_grant_id, self.duty_grant_id = self._seed_personal_and_duty(
                connection
            )
            self.admin_organization_id = self._seed_second_org_admin(connection)
            self._install_marker_verifier_bridges(connection)
        self.resolver = PsycopgEditorPrincipalResolver(
            connections=_IamAppConnections(
                self.postgres.conninfo(database=self.database, user="iam_app")
            )
        )

    def tearDown(self) -> None:
        self.postgres.drop_database(self.database)

    def _admin(self, *, autocommit: bool = True):
        return psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=autocommit,
        )

    def _seed_personal_and_duty(self, connection):
        selector_digest = hashlib.sha256(b"editor-principal-creator-selector").digest()
        bundle_id = uuid4()
        invitation_id = uuid4()
        creator_grant_id = uuid4()
        duty_grant_id = uuid4()
        contact_id = connection.execute(
            "SELECT id FROM iam.contact_points WHERE user_id=%s ORDER BY id LIMIT 1",
            (ACTOR_USER_ID,),
        ).fetchone()[0]
        created_at = self.now - timedelta(days=10)
        accepted_at = self.now - timedelta(days=9)
        connection.execute(
            "INSERT INTO iam.policy_selectors ("
            "selector_digest,canonicalization_version,access_purpose,scope_type,"
            "target_role,jurisdiction,locale,current_bundle_id,aggregate_version,"
            "created_at,updated_at) VALUES ("
            "%s,'policy-selector-json-v1','CREATOR_ENROLLMENT','USER_ROLE',"
            "'CREATOR','CN','zh-CN',NULL,1,%s,%s)",
            (selector_digest, created_at, created_at),
        )
        connection.execute(
            "INSERT INTO iam.policy_bundles ("
            "id,selector_digest,status,effective_at,effective_until,"
            "superseded_by_bundle_id,release_manifest_sha256,release_signature,"
            "release_signing_key_id,publication_command_id,aggregate_version,"
            "created_at,updated_at) VALUES ("
            "%s,%s,'DRAFT',NULL,NULL,NULL,%s,%s,'editor-principal-test-v1',"
            "%s,1,%s,%s)",
            (
                bundle_id,
                selector_digest,
                hashlib.sha256(bundle_id.bytes).digest(),
                b"reviewed-editor-principal-test-signature",
                uuid4(),
                created_at,
                created_at,
            ),
        )
        connection.execute(
            "INSERT INTO iam.access_invitations ("
            "id,purpose,organization_id,target_scope,target_role,is_initial_admin,"
            "recipient_contact_id,masked_recipient_label,policy_selector_digest,"
            "issued_policy_bundle_id,status,expires_at,issuer_kind,issuer_user_id,"
            "token_nonce,token_key_id,accepted_by_user_id,terminal_at,"
            "terminal_reason_code,aggregate_version,created_at,updated_at) VALUES ("
            "%s,'CREATOR_ENROLLMENT',NULL,'USER','CREATOR',false,%s,"
            "'e***@example.invalid',%s,%s,'ACCEPTED',%s,'SYSTEM',NULL,%s,"
            "'editor-principal-token-v1',%s,%s,NULL,2,%s,%s)",
            (
                invitation_id,
                contact_id,
                selector_digest,
                bundle_id,
                self.now + timedelta(days=30),
                hashlib.sha256(invitation_id.bytes).digest(),
                ACTOR_USER_ID,
                accepted_at,
                created_at,
                accepted_at,
            ),
        )
        connection.execute(
            "INSERT INTO iam.user_role_grants ("
            "id,user_id,role_code,source_invitation_id,policy_selector_digest,"
            "granted_by_kind,granted_by_id,granted_at,revoked_at,"
            "revocation_reason_code,aggregate_version) VALUES ("
            "%s,%s,'CREATOR',%s,%s,'SYSTEM',%s,%s,NULL,NULL,1)",
            (
                creator_grant_id,
                ACTOR_USER_ID,
                invitation_id,
                selector_digest,
                uuid4(),
                accepted_at,
            ),
        )
        connection.execute(
            "INSERT INTO iam.platform_duty_grants ("
            "id,user_id,duty_code,granted_by_kind,granted_by_id,granted_at,"
            "expires_at,revoked_at,revocation_reason_code,aggregate_version,"
            "created_at,updated_at) VALUES ("
            "%s,%s,'OPERATIONS_REVIEWER','SYSTEM',%s,%s,%s,NULL,NULL,1,%s,%s)",
            (
                duty_grant_id,
                ACTOR_USER_ID,
                uuid4(),
                accepted_at,
                self.now + timedelta(days=30),
                created_at,
                accepted_at,
            ),
        )
        return creator_grant_id, duty_grant_id

    def _seed_second_org_admin(self, connection) -> UUID:
        organization_id = uuid4()
        membership_id = uuid4()
        selector_digest = hashlib.sha256(
            b"editor-principal-org-admin-selector"
        ).digest()
        bundle_id = uuid4()
        invitation_id = uuid4()
        contact_id = connection.execute(
            "SELECT id FROM iam.contact_points WHERE user_id=%s ORDER BY id LIMIT 1",
            (ACTOR_USER_ID,),
        ).fetchone()[0]
        created_at = self.now - timedelta(days=8)
        accepted_at = self.now - timedelta(days=7)
        connection.execute(
            "INSERT INTO iam.policy_selectors (selector_digest,"
            "canonicalization_version,access_purpose,scope_type,target_role,"
            "jurisdiction,locale,current_bundle_id,aggregate_version,created_at,"
            "updated_at) VALUES (%s,'policy-selector-json-v1',"
            "'ORGANIZATION_MEMBERSHIP','ORGANIZATION_ROLE','ORG_ADMIN','CN',"
            "'zh-CN',NULL,1,%s,%s)",
            (selector_digest, created_at, created_at),
        )
        connection.execute(
            "INSERT INTO iam.policy_bundles (id,selector_digest,status,effective_at,"
            "effective_until,superseded_by_bundle_id,release_manifest_sha256,"
            "release_signature,release_signing_key_id,publication_command_id,"
            "aggregate_version,created_at,updated_at) VALUES "
            "(%s,%s,'DRAFT',NULL,NULL,NULL,%s,%s,'editor-org-admin-v1',%s,1,%s,%s)",
            (
                bundle_id,
                selector_digest,
                hashlib.sha256(bundle_id.bytes).digest(),
                b"reviewed-editor-org-admin-signature",
                uuid4(),
                created_at,
                created_at,
            ),
        )
        connection.execute(
            "INSERT INTO iam.organizations (id,organization_type,public_name,"
            "jurisdiction,status,client_reference_namespace,client_reference,"
            "aggregate_version,created_at,updated_at) VALUES "
            "(%s,'BUSINESS','Second organization','CN','ACTIVE',"
            "'editor-principal',%s,1,%s,%s)",
            (organization_id, str(organization_id), created_at, accepted_at),
        )
        connection.execute(
            "INSERT INTO iam.access_invitations (id,purpose,organization_id,"
            "target_scope,target_role,is_initial_admin,recipient_contact_id,"
            "masked_recipient_label,policy_selector_digest,issued_policy_bundle_id,"
            "status,expires_at,issuer_kind,issuer_user_id,token_nonce,token_key_id,"
            "accepted_by_user_id,terminal_at,terminal_reason_code,aggregate_version,"
            "created_at,updated_at) VALUES (%s,'ORGANIZATION_MEMBERSHIP',%s,"
            "'ORGANIZATION','ORG_ADMIN',false,%s,'e***@example.invalid',%s,%s,"
            "'ACCEPTED',%s,'SYSTEM',NULL,%s,'editor-org-admin-token-v1',%s,%s,"
            "NULL,2,%s,%s)",
            (
                invitation_id,
                organization_id,
                contact_id,
                selector_digest,
                bundle_id,
                self.now + timedelta(days=30),
                hashlib.sha256(invitation_id.bytes).digest(),
                ACTOR_USER_ID,
                accepted_at,
                created_at,
                accepted_at,
            ),
        )
        connection.execute(
            "INSERT INTO iam.memberships (id,organization_id,user_id,status,"
            "source_invitation_id,aggregate_version,created_at,updated_at) VALUES "
            "(%s,%s,%s,'ACTIVE',%s,1,%s,%s)",
            (
                membership_id,
                organization_id,
                ACTOR_USER_ID,
                invitation_id,
                accepted_at,
                accepted_at,
            ),
        )
        connection.execute(
            "INSERT INTO iam.membership_role_grants (id,organization_id,"
            "membership_id,user_id,role_code,source_invitation_id,"
            "policy_selector_digest,granted_by_kind,granted_by_id,granted_at,"
            "revoked_at,revocation_reason_code,aggregate_version) VALUES "
            "(%s,%s,%s,%s,'ORG_ADMIN',%s,%s,'SYSTEM',%s,%s,NULL,NULL,1)",
            (
                uuid4(),
                organization_id,
                membership_id,
                ACTOR_USER_ID,
                invitation_id,
                selector_digest,
                uuid4(),
                accepted_at,
            ),
        )
        return organization_id

    @staticmethod
    def _install_marker_verifier_bridges(connection) -> None:
        connection.execute(
            "CREATE FUNCTION public.test_profile_verify_editor_marker("
            "uuid,uuid,bytea) RETURNS boolean LANGUAGE sql SECURITY DEFINER "
            "SET search_path=pg_catalog,iam_api AS "
            "'SELECT iam_api.verify_editor_principal_marker_v1($1,$2,$3)'"
        )
        connection.execute(
            "ALTER FUNCTION public.test_profile_verify_editor_marker(uuid,uuid,bytea) "
            "OWNER TO profile_schema_owner"
        )
        connection.execute(
            "REVOKE ALL ON FUNCTION public.test_profile_verify_editor_marker("
            "uuid,uuid,bytea) FROM PUBLIC"
        )
        connection.execute(
            "GRANT EXECUTE ON FUNCTION public.test_profile_verify_editor_marker("
            "uuid,uuid,bytea) TO profile_app,iam_app"
        )
        connection.execute(
            "CREATE FUNCTION public.test_demand_verify_editor_marker("
            "uuid,uuid,bytea) RETURNS boolean LANGUAGE sql SECURITY DEFINER "
            "SET search_path=pg_catalog,iam_api AS "
            "'SELECT iam_api.verify_editor_principal_marker_v1($1,$2,$3)'"
        )
        connection.execute(
            "ALTER FUNCTION public.test_demand_verify_editor_marker(uuid,uuid,bytea) "
            "OWNER TO demand_schema_owner"
        )
        connection.execute(
            "REVOKE ALL ON FUNCTION public.test_demand_verify_editor_marker("
            "uuid,uuid,bytea) FROM PUBLIC"
        )
        connection.execute(
            "GRANT EXECUTE ON FUNCTION public.test_demand_verify_editor_marker("
            "uuid,uuid,bytea) TO demand_self,demand_review"
        )

    def _request(self, workspace_id=None):
        return EditorPrincipalResolutionRequest(
            actor_user_id=ACTOR_USER_ID,
            session_id=SESSION_ID,
            requested_workspace_id=workspace_id,
        )

    def _verify(self, *, runtime_role, scope_kind, marker):
        actor_setting = (
            "app.actor_user_id" if runtime_role == "profile_app" else "app.actor_id"
        )
        bridge = (
            "public.test_profile_verify_editor_marker"
            if runtime_role == "profile_app"
            else "public.test_demand_verify_editor_marker"
        )
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user=runtime_role),
            autocommit=False,
        ) as connection:
            for name, value in (
                ("app.scope_kind", scope_kind),
                (actor_setting, str(ACTOR_USER_ID)),
                ("app.session_id", str(SESSION_ID)),
            ):
                connection.execute(
                    "SELECT pg_catalog.set_config(%s,%s,true)",
                    (name, value),
                )
            return connection.execute(
                "SELECT " + bridge + "(%s,%s,%s)",
                (ACTOR_USER_ID, SESSION_ID, marker),
            ).fetchone()[0]

    def test_resolver_derives_candidates_and_requires_opaque_workspace_selection(self) -> None:
        candidates = self.resolver.list_workspaces(
            EditorWorkspaceListRequest(
                actor_user_id=ACTOR_USER_ID,
                session_id=SESSION_ID,
            )
        )
        self.assertEqual(
            tuple(candidate.workspace_kind for candidate in candidates),
            (
                WorkspaceKind.ORGANIZATION,
                WorkspaceKind.ORGANIZATION,
                WorkspaceKind.PERSONAL,
                WorkspaceKind.PLATFORM,
            ),
        )
        with self.assertRaises(IamError) as raised:
            self.resolver.resolve(self._request())
        self.assertEqual(raised.exception.code, "WORKSPACE_REQUIRED")

        personal_id = "personal:%s" % ACTOR_USER_ID
        organization_id = "org:%s" % ORGANIZATION_ID
        platform_id = "platform:%s" % ACTOR_USER_ID
        personal = self.resolver.resolve(self._request(personal_id))
        organization = self.resolver.resolve(self._request(organization_id))
        platform = self.resolver.resolve(self._request(platform_id))

        self.assertEqual(personal.workspace_kind, WorkspaceKind.PERSONAL)
        self.assertIsNone(personal.organization_id)
        self.assertIsNone(personal.membership_id)
        self.assertEqual(personal.user_role_codes, ("CREATOR",))
        self.assertEqual(personal.organization_role_codes, ())
        self.assertEqual(personal.platform_duty_codes, ("OPERATIONS_REVIEWER",))
        self.assertEqual(organization.workspace_kind, WorkspaceKind.ORGANIZATION)
        self.assertEqual(organization.organization_id, ORGANIZATION_ID)
        self.assertEqual(organization.membership_id, self.authority.membership_id)
        self.assertEqual(organization.organization_role_codes, ("DEMAND_OWNER",))
        self.assertEqual(organization.user_role_codes, ("CREATOR",))
        self.assertEqual(platform.workspace_kind, WorkspaceKind.PLATFORM)
        self.assertIsNone(platform.organization_id)
        self.assertIsNone(platform.membership_id)
        self.assertEqual(platform.organization_role_codes, ())
        self.assertEqual(platform.user_role_codes, ("CREATOR",))
        self.assertEqual(platform.platform_duty_codes, ("OPERATIONS_REVIEWER",))
        self.assertEqual(
            organization.principal_marker,
            personal.principal_marker,
        )
        self.assertEqual(platform.principal_marker, personal.principal_marker)

        with self.assertRaises(IamError) as unknown:
            self.resolver.resolve(self._request("org:%s" % uuid4()))
        self.assertEqual(unknown.exception.code, "RESOURCE_NOT_FOUND")

    def test_organization_roles_are_scoped_to_the_selected_org_candidate(self) -> None:
        admin = self.resolver.resolve(
            self._request("org:%s" % self.admin_organization_id)
        )
        owner = self.resolver.resolve(
            self._request("org:%s" % ORGANIZATION_ID)
        )
        personal = self.resolver.resolve(
            self._request("personal:%s" % ACTOR_USER_ID)
        )
        platform = self.resolver.resolve(
            self._request("platform:%s" % ACTOR_USER_ID)
        )

        self.assertEqual(admin.organization_id, self.admin_organization_id)
        self.assertEqual(admin.organization_role_codes, ("ORG_ADMIN",))
        self.assertNotIn("DEMAND_OWNER", admin.organization_role_codes)
        self.assertEqual(owner.organization_id, ORGANIZATION_ID)
        self.assertEqual(owner.organization_role_codes, ("DEMAND_OWNER",))
        self.assertNotIn("ORG_ADMIN", owner.organization_role_codes)
        self.assertEqual(personal.organization_role_codes, ())
        self.assertEqual(platform.organization_role_codes, ())

    def test_marker_verifier_is_closed_revalidates_graph_and_has_no_table_grant(self) -> None:
        marker = self.resolver.resolve(
            self._request("personal:%s" % ACTOR_USER_ID)
        ).principal_marker
        self.assertTrue(
            self._verify(
                runtime_role="profile_app",
                scope_kind="PROFILE_SELF",
                marker=marker,
            )
        )
        self.assertTrue(
            self._verify(
                runtime_role="demand_self",
                scope_kind="DEMAND_OWNER",
                marker=marker,
            )
        )
        self.assertTrue(
            self._verify(
                runtime_role="demand_review",
                scope_kind="DEMAND_REVIEW",
                marker=marker,
            )
        )
        self.assertFalse(
            self._verify(
                runtime_role="profile_app",
                scope_kind="DEMAND_OWNER",
                marker=marker,
            )
        )

        with self._admin() as connection:
            acl = connection.execute(
                "SELECT "
                "pg_catalog.has_function_privilege('iam_app',"
                "'iam_api.verify_editor_principal_marker_v1(uuid,uuid,bytea)',"
                "'EXECUTE'),"
                "pg_catalog.has_function_privilege('profile_schema_owner',"
                "'iam_api.verify_editor_principal_marker_v1(uuid,uuid,bytea)',"
                "'EXECUTE'),"
                "pg_catalog.has_function_privilege('demand_schema_owner',"
                "'iam_api.verify_editor_principal_marker_v1(uuid,uuid,bytea)',"
                "'EXECUTE'),"
                "pg_catalog.has_table_privilege('profile_app','iam.users','SELECT'),"
                "pg_catalog.has_table_privilege('demand_self','iam.users','SELECT')"
            ).fetchone()
            connection.execute(
                "UPDATE iam.platform_duty_grants SET revoked_at=%s,"
                "revocation_reason_code='TEST_REVOKED',aggregate_version=2,updated_at=%s "
                "WHERE id=%s",
                (self.now, self.now, self.duty_grant_id),
            )
        self.assertEqual(acl, (False, True, True, False, False))
        self.assertFalse(
            self._verify(
                runtime_role="profile_app",
                scope_kind="PROFILE_SELF",
                marker=marker,
            )
        )

        refreshed = self.resolver.resolve(
            self._request("personal:%s" % ACTOR_USER_ID)
        )
        self.assertNotEqual(refreshed.principal_marker, marker)
        self.assertEqual(refreshed.platform_duty_codes, ())

        with self._admin(autocommit=False) as connection:
            connection.execute(
                "UPDATE iam.session_families SET status='REVOKED',revoked_at=%s,"
                "revocation_reason_code='TEST_REVOKED',aggregate_version=2,updated_at=%s "
                "WHERE id=%s",
                (self.now, self.now, self.authority.session_family_id),
            )
            connection.execute(
                "UPDATE iam.sessions SET status='REVOKED',revoked_at=%s,"
                "revocation_reason_code='TEST_REVOKED',aggregate_version=2,updated_at=%s "
                "WHERE id=%s",
                (self.now, self.now, SESSION_ID),
            )
        self.assertFalse(
            self._verify(
                runtime_role="demand_self",
                scope_kind="DEMAND_OWNER",
                marker=refreshed.principal_marker,
            )
        )

    def test_platform_only_principal_gets_one_platform_workspace_until_duty_expires(self) -> None:
        actor_id = uuid4()
        session_id = uuid4()
        family_id = uuid4()
        auth_transaction_id = uuid4()
        duty_id = uuid4()
        created_at = self.now - timedelta(days=1)
        with self._admin(autocommit=False) as connection:
            connection.execute(
                "INSERT INTO iam.users (id,status,display_handle,aggregate_version,"
                "created_at,updated_at) VALUES (%s,'ACTIVE','platform_only_editor',"
                "1,%s,%s)",
                (actor_id, created_at, created_at),
            )
            connection.execute(
                "INSERT INTO iam.auth_transactions (id,status,purpose,attempt,"
                "protocol_version,browser_binding_digest,browser_binding_key_id,"
                "initiating_session_id,initiating_user_id,expected_user_id,"
                "invitation_id,invitation_version,expected_contact_point_id,"
                "state_digest,state_digest_key_id,nonce_digest,nonce_digest_key_id,"
                "pkce_verifier_ciphertext,pkce_encryption_key_id,"
                "pkce_encryption_algorithm,redirect_uri,provider_error_class,deadline,"
                "succeeded_at,created_at,updated_at) VALUES (%s,'SUCCEEDED','LOGIN',1,"
                "1,%s,'editor-platform-v1',NULL,NULL,NULL,NULL,NULL,NULL,%s,"
                "'editor-platform-v1',%s,'editor-platform-v1',%s,"
                "'editor-platform-v1','AES_256_GCM_V1',"
                "'https://app.example.test/v1/auth/oidc/callback',NULL,%s,%s,%s,%s)",
                (
                    auth_transaction_id,
                    hashlib.sha256(b"platform-browser").digest(),
                    hashlib.sha256(b"platform-state").digest(),
                    hashlib.sha256(b"platform-nonce").digest(),
                    b"platform-pkce",
                    self.now + timedelta(hours=1),
                    created_at,
                    created_at,
                    created_at,
                ),
            )
            connection.execute(
                "INSERT INTO iam.session_families (id,user_id,status,"
                "current_generation,revoked_at,revocation_reason_code,"
                "aggregate_version,created_at,updated_at) VALUES "
                "(%s,%s,'ACTIVE',1,NULL,NULL,1,%s,%s)",
                (family_id, actor_id, created_at, created_at),
            )
            connection.execute(
                "INSERT INTO iam.sessions (id,user_id,family_id,generation,"
                "predecessor_session_id,handle_digest,handle_digest_key_id,csrf_salt,"
                "csrf_key_id,csrf_digest,verified_contact_point_id,verified_at,"
                "verified_for_invitation_id,auth_transaction_id,auth_time,acr_code,"
                "amr_codes,created_at,last_activity_at,idle_expires_at,"
                "absolute_expires_at,updated_at,device_label,status,rotation_reason,"
                "revoked_at,revocation_reason_code,aggregate_version) VALUES "
                "(%s,%s,%s,1,NULL,%s,'editor-platform-v1',%s,'editor-platform-v1',"
                "%s,NULL,NULL,NULL,%s,%s,'urn:desire:acr:mfa',ARRAY['otp']::text[],"
                "%s,%s,%s,%s,%s,'Browser','ACTIVE','LOGIN',NULL,NULL,1)",
                (
                    session_id,
                    actor_id,
                    family_id,
                    hashlib.sha256(b"platform-session").digest(),
                    hashlib.sha256(b"platform-csrf-salt").digest(),
                    hashlib.sha256(b"platform-csrf").digest(),
                    auth_transaction_id,
                    created_at,
                    created_at,
                    self.now,
                    self.now + timedelta(hours=1),
                    self.now + timedelta(days=1),
                    self.now,
                ),
            )
            connection.execute(
                "INSERT INTO iam.platform_duty_grants (id,user_id,duty_code,"
                "granted_by_kind,granted_by_id,granted_at,expires_at,revoked_at,"
                "revocation_reason_code,aggregate_version,created_at,updated_at) "
                "VALUES (%s,%s,'OPERATIONS_REVIEWER','SYSTEM',%s,%s,%s,NULL,NULL,"
                "1,%s,%s)",
                (
                    duty_id,
                    actor_id,
                    uuid4(),
                    created_at,
                    self.now + timedelta(minutes=30),
                    created_at,
                    created_at,
                ),
            )

        request = EditorPrincipalResolutionRequest(
            actor_user_id=actor_id,
            session_id=session_id,
            requested_workspace_id=None,
        )
        workspace = self.resolver.resolve(request)
        self.assertEqual(workspace.workspace_id, "platform:%s" % actor_id)
        self.assertEqual(workspace.workspace_kind, WorkspaceKind.PLATFORM)
        self.assertIsNone(workspace.organization_id)
        self.assertIsNone(workspace.membership_id)
        self.assertEqual(workspace.organization_role_codes, ())
        self.assertEqual(workspace.user_role_codes, ())
        self.assertEqual(workspace.platform_duty_codes, ("OPERATIONS_REVIEWER",))

        with self._admin() as connection:
            connection.execute(
                "UPDATE iam.platform_duty_grants SET expires_at=%s,"
                "aggregate_version=2,updated_at=%s WHERE id=%s",
                (self.now - timedelta(seconds=1), self.now, duty_id),
            )
        with self.assertRaises(IamError) as raised:
            self.resolver.resolve(request)
        self.assertEqual(raised.exception.code, "RESOURCE_NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
