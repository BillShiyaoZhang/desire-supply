"""Real PostgreSQL 18 evidence for controlled synthetic identity bootstrap."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import unittest
from uuid import UUID, uuid4

import psycopg

from desire_platform.deployment.identity_bootstrap import (
    BOOTSTRAP_ROLE,
    IdentityBootstrapError,
    IdentityBootstrapOutcome,
    _drain_and_clear_bootstrap_role,
    apply_internal_sandbox_identity_bootstrap,
    parse_internal_sandbox_identity_manifest,
    revoke_internal_sandbox_identity_bootstrap_access,
    verify_internal_sandbox_identity_bootstrap,
)
from desire_platform.deployment.migrations import DeploymentMigrationSettings
from desire_platform.identity_access.adapters.postgres.oidc_authentication import (
    OidcPostgresBeginRequest,
    OidcPostgresCallbackLookup,
    OidcPostgresExchangeClaim,
    OidcPostgresExistingLoginFinalize,
    OidcPostgresPurpose,
    OidcPostgresSessionResult,
    PsycopgOidcAuthenticationUnitOfWork,
)
from desire_platform.identity_access.adapters.postgres.migrations import (
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from desire_platform.identity_access.adapters.postgres.editor_principal import (
    EditorWorkspaceListRequest,
    PsycopgEditorPrincipalResolver,
    WorkspaceKind,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18
from tests.support.identity_bootstrap_builders import (
    canonical_manifest,
    identity_bootstrap_document,
)


NOW = datetime(2026, 8, 12, 8, 0, tzinfo=timezone.utc)
SYSTEM_ACTOR_ID = UUID("11111111-1111-4111-8111-111111111111")
PLATFORM_ROOT = Path(__file__).resolve().parents[2]
IAM_MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)


class _Connections:
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


class _DrainResult:
    def __init__(self, *, rows=(), row=None) -> None:
        self._rows = rows
        self._row = row

    def fetchall(self):
        return self._rows

    def fetchone(self):
        return self._row


class _DelayedDrainConnection:
    _PID = 987_654
    _WAIT_MILLISECONDS = 5_000

    def __init__(self, *, termination_succeeds: bool) -> None:
        self._active = True
        self._termination_succeeds = termination_succeeds
        self.terminate_parameters = []
        self.credential_cleared = False

    def execute(self, statement, parameters=None):
        rendered = str(statement)
        if "pg_stat_activity" in rendered:
            rows = ((self._PID,),) if self._active else ()
            return _DrainResult(rows=rows)
        if "pg_terminate_backend" in rendered:
            self.terminate_parameters.append(parameters)
            if (
                parameters == (self._PID, self._WAIT_MILLISECONDS)
                and self._termination_succeeds
            ):
                self._active = False
            return _DrainResult(row=(self._termination_succeeds,))
        if "ALTER ROLE" in rendered:
            self.credential_cleared = True
            return _DrainResult()
        raise AssertionError(f"unexpected session-drain statement: {rendered}")


class IdentityBootstrapSessionDrainContractTest(unittest.TestCase):
    def test_session_drain_waits_for_terminated_backend_before_rechecking(self) -> None:
        connection = _DelayedDrainConnection(termination_succeeds=True)

        _drain_and_clear_bootstrap_role(connection)

        self.assertEqual(
            connection.terminate_parameters,
            [
                (
                    _DelayedDrainConnection._PID,
                    _DelayedDrainConnection._WAIT_MILLISECONDS,
                )
            ],
        )
        self.assertTrue(connection.credential_cleared)

    def test_session_drain_timeout_clears_credential_and_fails_closed(self) -> None:
        connection = _DelayedDrainConnection(termination_succeeds=False)

        with self.assertRaises(IdentityBootstrapError) as caught:
            _drain_and_clear_bootstrap_role(connection)

        self.assertEqual(
            caught.exception.code,
            "IDENTITY_BOOTSTRAP_SESSION_DRAIN_FAILED",
        )
        self.assertEqual(
            connection.terminate_parameters,
            [
                (
                    _DelayedDrainConnection._PID,
                    _DelayedDrainConnection._WAIT_MILLISECONDS,
                )
            ],
        )
        self.assertTrue(connection.credential_cleared)


class IdentityBootstrapPostgresTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18(
            enable_tcp_password_auth=True,
        ).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.postgres.stop()

    def setUp(self) -> None:
        self.database = self.postgres.create_database()
        self.settings = DeploymentMigrationSettings(
            host=self.postgres.host,
            port=self.postgres.port,
            database=self.database,
            admin_user=self.postgres.admin_user,
            admin_password=self.postgres.admin_password,
        )
        IamMigrationRunner(
            driver=PsycopgMigrationDriver(
                settings=PsycopgMigrationSettings(
                    conninfo=self.postgres.conninfo(
                        database=self.database,
                        user="iam_migration_runner",
                    ),
                    application_name="desire-bootstrap-pg-test",
                ),
                dbapi=psycopg,
            ),
            runner_version="bootstrap-pg-test/1",
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
        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=True,
        ) as connection:
            for migration_role in (
                "iam_migration_runner",
                "profile_migration_runner",
                "demand_migration_runner",
                "matching_migration_runner",
                "trust_migration_runner",
                "taxonomy_migration_runner",
            ):
                connection.execute(
                    "ALTER ROLE " + migration_role + " PASSWORD NULL"
                )
        self.document = identity_bootstrap_document()
        self.manifest = self._manifest(self.document)

    def tearDown(self) -> None:
        self.postgres.drop_database(self.database)

    @staticmethod
    def _manifest(document):
        raw, digest = canonical_manifest(document)
        return parse_internal_sandbox_identity_manifest(
            raw,
            expected_sha256=digest,
            expected_issuer="https://id.example.test",
        )

    def _admin(self):
        return psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=True,
        )

    @staticmethod
    def _authority_snapshot(connection):
        tables = (
            "iam.users",
            "iam.external_identities",
            "iam.contact_points",
            "iam.organizations",
            "iam.access_invitations",
            "iam.memberships",
            "iam.user_role_grants",
            "iam.membership_role_grants",
            "iam.platform_duty_grants",
            "infra.iam_sandbox_bootstrap_state",
            "infra.iam_sandbox_bootstrap_accounts",
            "infra.iam_sandbox_bootstrap_runs",
            "infra.iam_sandbox_bootstrap_manifest_bridges",
            "infra.command_receipts",
            "audit.audit_events",
            "infra.outbox_events",
        )
        return tuple(
            (
                table,
                tuple(
                    row[0]
                    for row in connection.execute(
                        "SELECT row_to_json(exact_row)::text FROM "
                        f"(SELECT * FROM {table}) AS exact_row "
                        "ORDER BY row_to_json(exact_row)::text"
                    ).fetchall()
                ),
            )
            for table in tables
        )

    def _apply(self, manifest=None, password="temporary-bootstrap-password-material-v1"):
        return apply_internal_sandbox_identity_bootstrap(
            settings=self.settings,
            manifest=self.manifest if manifest is None else manifest,
            system_actor_id=SYSTEM_ACTOR_ID,
            now=NOW,
            password_factory=lambda: password,
        )

    def test_apply_replay_verify_is_audited_digest_only_and_no_session(self) -> None:
        report = self._apply()
        self.assertEqual(report.outcome, IdentityBootstrapOutcome.APPLIED)
        with self._admin() as connection:
            isolation_before = connection.execute(
                "SELECT id,revoked_at,revocation_reason_code,aggregate_version "
                "FROM iam.user_role_grants WHERE revoked_at IS NOT NULL "
                "ORDER BY id"
            ).fetchall()
        self.assertEqual(len(isolation_before), 9)
        self.assertEqual(
            {row[2] for row in isolation_before},
            {"BOOTSTRAP_ROLE_ISOLATION"},
        )
        replay = self._apply()
        self.assertEqual(replay.outcome, IdentityBootstrapOutcome.REPLAYED)
        verified = verify_internal_sandbox_identity_bootstrap(
            settings=self.settings,
            manifest=self.manifest,
            system_actor_id=SYSTEM_ACTOR_ID,
            now=NOW,
            password_factory=lambda: "temporary-bootstrap-password-material-v2",
        )
        self.assertEqual(verified.outcome, IdentityBootstrapOutcome.VERIFIED)

        with self._admin() as connection:
            isolation_after = connection.execute(
                "SELECT id,revoked_at,revocation_reason_code,aggregate_version "
                "FROM iam.user_role_grants WHERE revoked_at IS NOT NULL "
                "ORDER BY id"
            ).fetchall()
            counts = connection.execute(
                "SELECT (SELECT count(*) FROM iam.users),"
                "(SELECT count(*) FROM iam.external_identities WHERE status='ACTIVE'),"
                "(SELECT count(*) FROM iam.contact_points WHERE locator_ciphertext IS NULL),"
                "(SELECT count(*) FROM iam.sessions),"
                "(SELECT count(*) FROM iam.user_role_grants WHERE role_code='CREATOR' AND revoked_at IS NULL),"
                "(SELECT count(*) FROM iam.membership_role_grants WHERE role_code='DEMAND_OWNER' AND revoked_at IS NULL),"
                "(SELECT count(*) FROM iam.membership_role_grants WHERE role_code='ORG_ADMIN' AND revoked_at IS NULL),"
                "(SELECT count(*) FROM iam.platform_duty_grants WHERE revoked_at IS NULL),"
                "(SELECT count(*) FROM audit.audit_events WHERE action_code='ApplyInternalSandboxIdentityBootstrap'),"
                "(SELECT count(*) FROM infra.outbox_events WHERE event_type='UserActivated'),"
                "(SELECT count(*) FROM infra.command_receipts WHERE command_name='ApplyInternalSandboxIdentityBootstrap')"
            ).fetchone()
            handles = connection.execute(
                "SELECT display_handle FROM iam.users ORDER BY display_handle"
            ).fetchall()
            role_facts = connection.execute(
                "SELECT rolpassword FROM pg_catalog.pg_authid WHERE rolname=%s",
                (BOOTSTRAP_ROLE,),
            ).fetchone()
            memberships = connection.execute(
                "SELECT count(*) FROM pg_catalog.pg_auth_members AS m "
                "JOIN pg_catalog.pg_roles AS r ON r.oid=m.member "
                "WHERE r.rolname=%s",
                (BOOTSTRAP_ROLE,),
            ).fetchone()
            privileges = connection.execute(
                "SELECT "
                    "pg_catalog.has_function_privilege(%s,%s,'EXECUTE'),"
                    "pg_catalog.has_function_privilege(%s,%s,'EXECUTE'),"
                    "pg_catalog.has_function_privilege(%s,%s,'EXECUTE'),"
                    "pg_catalog.has_function_privilege(%s,%s,'EXECUTE'),"
                    "pg_catalog.has_function_privilege(%s,%s,'EXECUTE'),"
                    "pg_catalog.has_function_privilege(%s,%s,'EXECUTE')",
                (
                    BOOTSTRAP_ROLE,
                    "iam_api.manage_internal_sandbox_identity_bootstrap_v1("
                    "text,bytea,bytea,uuid,uuid,uuid,uuid,uuid,uuid,uuid)",
                    BOOTSTRAP_ROLE,
                    "iam_api.manage_internal_sandbox_identity_bootstrap_v2("
                    "text,bytea,bytea,uuid,uuid,uuid,uuid,uuid,uuid,uuid)",
                    BOOTSTRAP_ROLE,
                    "iam_api.manage_internal_sandbox_identity_bootstrap_v3("
                    "text,bytea,bytea,uuid,uuid,uuid,uuid,uuid,uuid,uuid)",
                    BOOTSTRAP_ROLE,
                    "iam_api.manage_internal_sandbox_identity_bootstrap_v4("
                    "text,bytea,bytea,uuid,uuid,uuid,uuid,uuid,uuid,uuid)",
                    BOOTSTRAP_ROLE,
                    "iam_api.manage_internal_sandbox_identity_bootstrap_v5("
                    "text,bytea,bytea,uuid,uuid,uuid,uuid,uuid,uuid,uuid)",
                    BOOTSTRAP_ROLE,
                    "iam_api.manage_internal_sandbox_identity_bootstrap_v6("
                    "text,bytea,bytea,uuid,uuid,uuid,uuid,uuid,uuid,uuid)",
                ),
            ).fetchone()
        self.assertEqual(isolation_after, isolation_before)
        self.assertEqual(counts, (10, 10, 10, 0, 1, 1, 1, 7, 2, 10, 2))
        self.assertEqual(
            handles,
            [
                ("sandbox_access_admin_01",),
                ("sandbox_appeal_reviewer_01",),
                ("sandbox_creator_01",),
                ("sandbox_demand_owner_01",),
                ("sandbox_finance_operator_01",),
                ("sandbox_finance_operator_02",),
                ("sandbox_operations_reviewer_01",),
                ("sandbox_org_admin_01",),
                ("sandbox_trust_officer_01",),
                ("sandbox_trust_officer_02",),
            ],
        )
        self.assertEqual(role_facts, (None,))
        self.assertEqual(memberships, (0,))
        self.assertEqual(
            privileges,
            (False, False, False, False, False, True),
        )

    def test_replay_and_verify_preserve_legally_corrected_public_names(self) -> None:
        self._apply()
        with self._admin() as connection:
            organizations = connection.execute(
                "SELECT id,aggregate_version FROM iam.organizations ORDER BY id"
            ).fetchall()
            self.assertEqual(len(organizations), 2)
            expected = {}
            for position, (organization_id, aggregate_version) in enumerate(
                organizations, start=1
            ):
                public_name = f"Corrected Sandbox Organization {position}"
                connection.execute(
                    "UPDATE iam.organizations SET public_name=%s,"
                    "aggregate_version=aggregate_version+1,"
                    "updated_at=transaction_timestamp() WHERE id=%s",
                    (public_name, organization_id),
                )
                expected[organization_id] = (
                    public_name,
                    aggregate_version + 1,
                )

        replay = self._apply(
            password="temporary-bootstrap-password-public-name-replay"
        )
        self.assertEqual(replay.outcome, IdentityBootstrapOutcome.REPLAYED)
        verified = verify_internal_sandbox_identity_bootstrap(
            settings=self.settings,
            manifest=self.manifest,
            system_actor_id=SYSTEM_ACTOR_ID,
            now=NOW,
            password_factory=lambda: (
                "temporary-bootstrap-password-public-name-verify"
            ),
        )
        self.assertEqual(verified.outcome, IdentityBootstrapOutcome.VERIFIED)
        with self._admin() as connection:
            current = connection.execute(
                "SELECT id,public_name,aggregate_version "
                "FROM iam.organizations ORDER BY id"
            ).fetchall()
        self.assertEqual(
            current,
            [
                (organization_id, *expected[organization_id])
                for organization_id, _aggregate_version in organizations
            ],
        )

    def test_formal_membership_growth_is_not_bootstrap_drift_and_is_zero_write(self) -> None:
        self._apply()
        org_admin = next(
            account
            for account in self.document["accounts"]
            if account["account_code"] == "org_admin_01"
        )
        organization_id = org_admin["organization_grant"]["organization_id"]
        membership_id = org_admin["organization_grant"]["membership_id"]
        user_id = org_admin["user_id"]
        contact_id = org_admin["contact_point"]["id"]
        extra_invitation_id = UUID("90000000-0000-4000-8000-000000000001")
        extra_grant_id = UUID("90000000-0000-4000-8000-000000000002")
        extra_organization_id = UUID("90000000-0000-4000-8000-000000000003")
        external_invitation_id = UUID("90000000-0000-4000-8000-000000000004")
        external_membership_id = UUID("90000000-0000-4000-8000-000000000005")
        external_grant_id = UUID("90000000-0000-4000-8000-000000000006")
        with self._admin() as connection:
            connection.execute(
                "INSERT INTO iam.access_invitations("
                "id,purpose,organization_id,target_scope,target_role,"
                "is_initial_admin,recipient_contact_id,masked_recipient_label,"
                "policy_selector_digest,issued_policy_bundle_id,status,"
                "expires_at,issuer_kind,issuer_user_id,token_nonce,token_key_id,"
                "accepted_by_user_id,terminal_at,terminal_reason_code,"
                "aggregate_version,created_at,updated_at) "
                "SELECT %s,'ORGANIZATION_MEMBERSHIP',%s,'ORGANIZATION',"
                "'DEMAND_OWNER',false,%s,'formal-invitation',selector_digest,"
                "%s,'ACCEPTED',transaction_timestamp()+interval '1 year',"
                "'SYSTEM',NULL,sha256(convert_to('formal-extra-same','UTF8')),"
                "'formal-invitation-v1',%s,transaction_timestamp(),NULL,2,"
                "transaction_timestamp(),transaction_timestamp() "
                "FROM iam.policy_selectors "
                "WHERE target_role='DEMAND_OWNER' AND jurisdiction='ZZ_INTERNAL'",
                (
                    extra_invitation_id,
                    organization_id,
                    contact_id,
                    self.document["policy"]["demand_owner_bundle_id"],
                    user_id,
                ),
            )
            connection.execute(
                "INSERT INTO iam.membership_role_grants("
                "id,organization_id,membership_id,user_id,role_code,"
                "source_invitation_id,policy_selector_digest,granted_by_kind,"
                "granted_by_id,granted_at,revoked_at,revocation_reason_code,"
                "aggregate_version) SELECT %s,%s,%s,%s,'DEMAND_OWNER',%s,"
                "selector_digest,'SYSTEM',%s,transaction_timestamp(),NULL,NULL,1 "
                "FROM iam.policy_selectors "
                "WHERE target_role='DEMAND_OWNER' AND jurisdiction='ZZ_INTERNAL'",
                (
                    extra_grant_id,
                    organization_id,
                    membership_id,
                    user_id,
                    extra_invitation_id,
                    SYSTEM_ACTOR_ID,
                ),
            )
            connection.execute(
                "INSERT INTO iam.organizations("
                "id,organization_type,public_name,jurisdiction,status,"
                "client_reference_namespace,client_reference,aggregate_version,"
                "created_at,updated_at) VALUES (%s,'BUSINESS',"
                "'Formal Extra Organization','ZZ_INTERNAL','ACTIVE',"
                "'formal-test','extra-org',2,transaction_timestamp(),"
                "transaction_timestamp())",
                (extra_organization_id,),
            )
            connection.execute(
                "INSERT INTO iam.access_invitations("
                "id,purpose,organization_id,target_scope,target_role,"
                "is_initial_admin,recipient_contact_id,masked_recipient_label,"
                "policy_selector_digest,issued_policy_bundle_id,status,"
                "expires_at,issuer_kind,issuer_user_id,token_nonce,token_key_id,"
                "accepted_by_user_id,terminal_at,terminal_reason_code,"
                "aggregate_version,created_at,updated_at) "
                "SELECT %s,'ORGANIZATION_MEMBERSHIP',%s,'ORGANIZATION',"
                "'ORG_ADMIN',false,%s,'formal-invitation',selector_digest,"
                "%s,'ACCEPTED',transaction_timestamp()+interval '1 year',"
                "'SYSTEM',NULL,sha256(convert_to('formal-extra-org','UTF8')),"
                "'formal-invitation-v1',%s,transaction_timestamp(),NULL,2,"
                "transaction_timestamp(),transaction_timestamp() "
                "FROM iam.policy_selectors "
                "WHERE target_role='ORG_ADMIN' AND jurisdiction='ZZ_INTERNAL'",
                (
                    external_invitation_id,
                    extra_organization_id,
                    contact_id,
                    self.document["policy"]["org_admin_bundle_id"],
                    user_id,
                ),
            )
            connection.execute(
                "INSERT INTO iam.memberships("
                "id,organization_id,user_id,status,source_invitation_id,"
                "aggregate_version,created_at,updated_at) VALUES "
                "(%s,%s,%s,'ACTIVE',%s,1,transaction_timestamp(),"
                "transaction_timestamp())",
                (
                    external_membership_id,
                    extra_organization_id,
                    user_id,
                    external_invitation_id,
                ),
            )
            connection.execute(
                "INSERT INTO iam.membership_role_grants("
                "id,organization_id,membership_id,user_id,role_code,"
                "source_invitation_id,policy_selector_digest,granted_by_kind,"
                "granted_by_id,granted_at,revoked_at,revocation_reason_code,"
                "aggregate_version) SELECT %s,%s,%s,%s,'ORG_ADMIN',%s,"
                "selector_digest,'SYSTEM',%s,transaction_timestamp(),NULL,NULL,1 "
                "FROM iam.policy_selectors "
                "WHERE target_role='ORG_ADMIN' AND jurisdiction='ZZ_INTERNAL'",
                (
                    external_grant_id,
                    extra_organization_id,
                    external_membership_id,
                    user_id,
                    external_invitation_id,
                    SYSTEM_ACTOR_ID,
                ),
            )
            before = self._authority_snapshot(connection)

        replay = self._apply(
            password="temporary-bootstrap-password-formal-replay"
        )
        verified = verify_internal_sandbox_identity_bootstrap(
            settings=self.settings,
            manifest=self.manifest,
            system_actor_id=SYSTEM_ACTOR_ID,
            now=NOW,
            password_factory=lambda: "temporary-bootstrap-password-formal-verify",
        )
        self.assertEqual(replay.outcome, IdentityBootstrapOutcome.REPLAYED)
        self.assertEqual(verified.outcome, IdentityBootstrapOutcome.VERIFIED)
        with self._admin() as connection:
            after = self._authority_snapshot(connection)
            growth = connection.execute(
                "SELECT "
                "(SELECT count(*) FROM iam.memberships "
                " WHERE user_id=%s AND status='ACTIVE'),"
                "(SELECT count(*) FROM iam.membership_role_grants "
                " WHERE user_id=%s AND revoked_at IS NULL)",
                (user_id, user_id),
            ).fetchone()
        self.assertEqual(after, before)
        self.assertEqual(growth, (2, 3))

    def test_hidden_org_admin_authority_field_drift_fails_closed(self) -> None:
        self._apply()
        org_admin = next(
            account
            for account in self.document["accounts"]
            if account["account_code"] == "org_admin_01"
        )
        cases = (
            (
                "iam.policy_bundles",
                "UPDATE iam.policy_bundles SET release_signing_key_id="
                "'drifted-key' WHERE id=%s",
                "UPDATE iam.policy_bundles SET release_signing_key_id="
                "'internal-sandbox-bootstrap-v4' WHERE id=%s",
                self.document["policy"]["org_admin_bundle_id"],
            ),
            (
                "iam.access_invitations",
                "UPDATE iam.access_invitations SET masked_recipient_label="
                "'drifted-label' WHERE id=%s",
                "UPDATE iam.access_invitations SET masked_recipient_label="
                "'sandbox-account' WHERE id=%s",
                org_admin["organization_grant"]["invitation_id"],
            ),
            (
                "iam.memberships",
                "UPDATE iam.memberships SET aggregate_version=2 WHERE id=%s",
                "UPDATE iam.memberships SET aggregate_version=1 WHERE id=%s",
                org_admin["organization_grant"]["membership_id"],
            ),
            (
                "iam.membership_role_grants",
                "UPDATE iam.membership_role_grants SET aggregate_version=2 "
                "WHERE id=%s",
                "UPDATE iam.membership_role_grants SET aggregate_version=1 "
                "WHERE id=%s",
                org_admin["organization_grant"]["grant_id"],
            ),
        )
        for table, drift_sql, restore_sql, target_id in cases:
            with self.subTest(table=table):
                with self._admin() as connection:
                    connection.execute(
                        f"ALTER TABLE {table} DISABLE TRIGGER USER"
                    )
                    connection.execute(drift_sql, (target_id,))
                    connection.execute(
                        f"ALTER TABLE {table} ENABLE TRIGGER USER"
                    )
                with self.assertRaises(IdentityBootstrapError):
                    verify_internal_sandbox_identity_bootstrap(
                        settings=self.settings,
                        manifest=self.manifest,
                        system_actor_id=SYSTEM_ACTOR_ID,
                        now=NOW,
                        password_factory=lambda: (
                            "temporary-bootstrap-password-hidden-drift"
                        ),
                    )
                with self._admin() as connection:
                    connection.execute(
                        f"ALTER TABLE {table} DISABLE TRIGGER USER"
                    )
                    connection.execute(restore_sql, (target_id,))
                    connection.execute(
                        f"ALTER TABLE {table} ENABLE TRIGGER USER"
                    )

    def test_demand_schema_owner_gets_only_stable_authority_resolver(self) -> None:
        with self._admin() as connection:
            privileges = connection.execute(
                "SELECT "
                "has_schema_privilege('demand_schema_owner','iam_api','USAGE'),"
                "has_function_privilege('demand_schema_owner',"
                "'iam_api.resolve_demand_owner_authority_marker_v1"
                "(uuid,uuid,uuid,text,uuid)','EXECUTE'),"
                "has_function_privilege('public',"
                "'iam_api.resolve_demand_owner_authority_marker_v1"
                "(uuid,uuid,uuid,text,uuid)','EXECUTE'),"
                "has_function_privilege('demand_review',"
                "'iam_api.resolve_demand_owner_authority_marker_v1"
                "(uuid,uuid,uuid,text,uuid)','EXECUTE'),"
                "has_function_privilege('demand_finance',"
                "'iam_api.resolve_demand_owner_authority_marker_v1"
                "(uuid,uuid,uuid,text,uuid)','EXECUTE'),"
                "has_function_privilege('demand_schema_owner',"
                "'iam_api.lock_demand_owner_authority_v1"
                "(uuid,uuid,uuid,text,uuid,bytea)','EXECUTE')"
            ).fetchone()
        self.assertEqual(privileges, (True, True, False, False, False, False))

    def test_apply_recovers_stale_bootstrap_password_and_backend_then_clears_new_password(self) -> None:
        stale_password = "stale-bootstrap-password-material-v1"
        invocation_password = "temporary-bootstrap-password-material-v7"
        with self._admin() as connection:
            connection.pgconn.change_password(
                BOOTSTRAP_ROLE.encode("ascii"),
                stale_password.encode("utf-8"),
            )
            connection.execute(
                "ALTER ROLE iam_sandbox_bootstrap VALID UNTIL 'infinity'"
            )
        stale = psycopg.connect(
            self.postgres.tcp_conninfo(
                database=self.database,
                user=BOOTSTRAP_ROLE,
                password=stale_password,
            ),
            autocommit=True,
        )
        try:
            report = self._apply(password=invocation_password)
            self.assertEqual(report.outcome, IdentityBootstrapOutcome.APPLIED)
            with self.assertRaises(psycopg.OperationalError):
                stale.execute("SELECT 1")
        finally:
            stale.close()

        for rejected_password in (stale_password, invocation_password):
            with self.assertRaises(psycopg.OperationalError):
                psycopg.connect(
                    self.postgres.tcp_conninfo(
                        database=self.database,
                        user=BOOTSTRAP_ROLE,
                        password=rejected_password,
                    ),
                    connect_timeout=2,
                )
        with self._admin() as connection:
            credential = connection.execute(
                "SELECT rolpassword,rolvaliduntil FROM pg_catalog.pg_authid "
                "WHERE rolname=%s",
                (BOOTSTRAP_ROLE,),
            ).fetchone()
            backends = connection.execute(
                "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE usename=%s",
                (BOOTSTRAP_ROLE,),
            ).fetchone()
        self.assertEqual(credential[0], None)
        self.assertEqual(backends, (0,))

    def test_ten_logins_resolve_one_mutually_exclusive_workspace_each(self) -> None:
        self._apply()
        resolver = PsycopgEditorPrincipalResolver(
            connections=_Connections(
                self.postgres.conninfo(database=self.database, user="iam_app")
            )
        )
        expected_kinds = {
            "ACCESS_ADMIN": WorkspaceKind.PLATFORM,
            "APPEAL_REVIEWER": WorkspaceKind.PLATFORM,
            "CREATOR": WorkspaceKind.PERSONAL,
            "DEMAND_OWNER": WorkspaceKind.ORGANIZATION,
            "FINANCE_OPERATOR": WorkspaceKind.PLATFORM,
            "OPERATIONS_REVIEWER": WorkspaceKind.PLATFORM,
            "ORG_ADMIN": WorkspaceKind.ORGANIZATION,
            "TRUST_OFFICER": WorkspaceKind.PLATFORM,
        }
        for account in self.manifest.accounts:
            with self.subTest(account=account.account_code):
                session = self._login(
                    account.subject_digest,
                    account.subject_digest_key_id,
                )
                workspaces = resolver.list_workspaces(
                    EditorWorkspaceListRequest(
                        actor_user_id=session.user_id,
                        session_id=session.session_id,
                    )
                )
                self.assertEqual(len(workspaces), 1)
                workspace = workspaces[0]
                self.assertEqual(
                    workspace.workspace_kind,
                    expected_kinds[account.effective_role_code],
                )
                effective_codes = (
                    workspace.organization_role_codes
                    + workspace.user_role_codes
                    + workspace.platform_duty_codes
                )
                self.assertEqual(
                    effective_codes,
                    (account.effective_role_code,),
                )

    def test_ten_bootstrapped_subjects_hit_existing_login_and_rotation_revokes_sessions(self) -> None:
        self._apply()
        sessions = []
        for account in self.manifest.accounts:
            sessions.append(self._login(account.subject_digest, account.subject_digest_key_id))
        self.assertEqual(
            {result.user_id for result in sessions},
            {account.user_id for account in self.manifest.accounts},
        )

        v2_document = identity_bootstrap_document(
            revision=2,
            previous_manifest_sha256=self.manifest.manifest_sha256.hex(),
            rotation_label="v2",
        )
        v2 = self._manifest(v2_document)
        rotated = self._apply(v2, "temporary-bootstrap-password-material-v3")
        self.assertEqual(rotated.outcome, IdentityBootstrapOutcome.ROTATED)
        with self._admin() as connection:
            identity_facts = connection.execute(
                "SELECT status,count(*) FROM iam.external_identities "
                "GROUP BY status ORDER BY status"
            ).fetchall()
            session_facts = connection.execute(
                "SELECT status,count(*) FROM iam.sessions GROUP BY status"
            ).fetchall()
            family_facts = connection.execute(
                "SELECT status,count(*) FROM iam.session_families GROUP BY status"
            ).fetchall()
        self.assertEqual(identity_facts, [("ACTIVE", 10), ("REVOKED", 10)])
        self.assertEqual(session_facts, [("REVOKED", 10)])
        self.assertEqual(family_facts, [("REVOKED", 10)])
        for account in v2.accounts:
            result = self._login(account.subject_digest, account.subject_digest_key_id)
            self.assertEqual(result.user_id, account.user_id)

    def test_partial_drift_wrong_role_rollback_and_revoke_are_fail_closed(self) -> None:
        with self._admin() as connection:
            first_user_id = self.manifest.accounts[0].user_id
            connection.execute(
                "INSERT INTO iam.users(id,status,display_handle,aggregate_version,created_at,updated_at) "
                "VALUES (%s,'ACTIVE','collision_user',1,%s,%s)",
                (first_user_id, NOW, NOW),
            )
        with self.assertRaises(IdentityBootstrapError):
            self._apply()
        with self._admin() as connection:
            rollback = connection.execute(
                "SELECT (SELECT count(*) FROM infra.iam_sandbox_bootstrap_state),"
                "(SELECT count(*) FROM iam.external_identities),"
                "(SELECT count(*) FROM audit.audit_events)"
            ).fetchone()
        self.assertEqual(rollback, (0, 0, 0))

        with self._admin() as connection:
            connection.execute("DELETE FROM iam.users WHERE id=%s", (first_user_id,))
        self._apply()
        with self._admin() as connection:
            connection.execute(
                "UPDATE iam.users SET display_handle='drifted_sandbox',"
                "aggregate_version=aggregate_version+1,"
                "updated_at=transaction_timestamp() WHERE id=%s",
                (first_user_id,),
            )
        with self.assertRaises(IdentityBootstrapError):
            verify_internal_sandbox_identity_bootstrap(
                settings=self.settings,
                manifest=self.manifest,
                system_actor_id=SYSTEM_ACTOR_ID,
                now=NOW,
                password_factory=lambda: "temporary-bootstrap-password-material-v4",
            )
        with self.assertRaises(IdentityBootstrapError):
            self._apply(
                password="temporary-bootstrap-password-replay-drift"
            )

        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="iam_app"),
            autocommit=True,
        ) as wrong_role:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                wrong_role.execute(
                    "SELECT * FROM iam_api.manage_internal_sandbox_identity_bootstrap_v1("
                    "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    (
                        "VERIFY",
                        self.manifest.canonical_bytes,
                        self.manifest.manifest_sha256,
                        uuid4(), uuid4(), uuid4(), SYSTEM_ACTOR_ID, uuid4(), uuid4(),
                        self.manifest.bootstrap_id,
                    ),
                )

        with self._admin() as connection:
            connection.execute(
                "UPDATE iam.users SET display_handle='sandbox_access_admin_01',"
                "aggregate_version=aggregate_version+1,"
                "updated_at=transaction_timestamp() WHERE id=%s",
                (first_user_id,),
            )
        revoked = revoke_internal_sandbox_identity_bootstrap_access(
            settings=self.settings,
            manifest=self.manifest,
            system_actor_id=SYSTEM_ACTOR_ID,
            now=NOW,
            password_factory=lambda: "temporary-bootstrap-password-material-v5",
        )
        self.assertEqual(revoked.outcome, IdentityBootstrapOutcome.REVOKED)
        repeated = revoke_internal_sandbox_identity_bootstrap_access(
            settings=self.settings,
            manifest=self.manifest,
            system_actor_id=SYSTEM_ACTOR_ID,
            now=NOW,
            password_factory=lambda: "temporary-bootstrap-password-material-v6",
        )
        self.assertEqual(repeated.outcome, IdentityBootstrapOutcome.ALREADY_REVOKED)
        with self._admin() as connection:
            closed = connection.execute(
                "SELECT (SELECT count(*) FROM iam.users WHERE status='SUSPENDED'),"
                "(SELECT count(*) FROM iam.external_identities WHERE status='ACTIVE'),"
                "(SELECT count(*) FROM iam.user_role_grants WHERE revoked_at IS NULL),"
                "(SELECT count(*) FROM iam.membership_role_grants WHERE revoked_at IS NULL),"
                "(SELECT count(*) FROM iam.platform_duty_grants WHERE revoked_at IS NULL)"
            ).fetchone()
        self.assertEqual(closed, (10, 0, 0, 0, 0))

    def _login(self, subject_digest: bytes, subject_key_id: str) -> OidcPostgresSessionResult:
        login_now = datetime.now(timezone.utc)
        connections = _Connections(
            self.postgres.conninfo(database=self.database, user="iam_onboarding")
        )
        uow = PsycopgOidcAuthenticationUnitOfWork(connections=connections)
        begin = OidcPostgresBeginRequest(
            auth_transaction_id=uuid4(),
            purpose=OidcPostgresPurpose.LOGIN,
            browser_binding_digest=hashlib.sha256(uuid4().bytes).digest(),
            browser_binding_key_id="oidc-browser-v1",
            initiating_session_id=None,
            initiating_user_id=None,
            expected_user_id=None,
            invitation_id=None,
            invitation_version=None,
            expected_contact_point_id=None,
            expected_contact_type=None,
            expected_contact_binding_digest=None,
            expected_contact_binding_key_id=None,
            state_digest=hashlib.sha256(uuid4().bytes).digest(),
            state_digest_key_id="oidc-state-v1",
            nonce_digest=hashlib.sha256(uuid4().bytes).digest(),
            nonce_digest_key_id="oidc-nonce-v1",
            nonce_ciphertext=b"reviewed-encrypted-nonce",
            nonce_encryption_key_id="oidc-nonce-aead-v1",
            pkce_verifier_ciphertext=b"reviewed-encrypted-verifier",
            pkce_encryption_key_id="oidc-pkce-aead-v1",
            pkce_code_challenge="A" * 43,
            provider_issuer="https://id.example.test",
            provider_audience="desire-internal-pilot",
            redirect_uri="https://app.example.test/v1/auth/oidc/callback",
            return_to="/app",
            security_policy_version="iam-security-v1",
            audit_event_id=uuid4(),
            system_actor_id=SYSTEM_ACTOR_ID,
            correlation_id=uuid4(),
            trace_id=uuid4(),
        )
        transaction = uow.begin(begin)
        callback = uow.read_callback(
            OidcPostgresCallbackLookup(
                state_digest=begin.state_digest,
                state_digest_key_id=begin.state_digest_key_id,
                browser_binding_digest=begin.browser_binding_digest,
                browser_binding_key_id=begin.browser_binding_key_id,
            )
        )
        owner = uuid4()
        uow.claim_exchange(
            OidcPostgresExchangeClaim(
                auth_transaction_id=callback.auth_transaction_id,
                exchange_owner_id=owner,
                invitation_id=None,
            )
        )
        result = uow.finalize_existing_login(
            OidcPostgresExistingLoginFinalize(
                auth_transaction_id=transaction.auth_transaction_id,
                exchange_owner_id=owner,
                provider_issuer="https://id.example.test",
                subject_digest=subject_digest,
                subject_digest_key_id=subject_key_id,
                new_session_family_id=uuid4(),
                new_session_id=uuid4(),
                handle_digest=hashlib.sha256(uuid4().bytes).digest(),
                handle_digest_key_id="session-handle-v1",
                csrf_salt=hashlib.sha256(uuid4().bytes).digest(),
                csrf_key_id="session-csrf-v1",
                csrf_digest=hashlib.sha256(uuid4().bytes).digest(),
                auth_time=login_now - timedelta(minutes=1),
                token_issued_at=login_now - timedelta(seconds=30),
                token_expires_at=login_now + timedelta(minutes=5),
                acr_code="urn:desire:acr:mfa",
                amr_codes=("otp",),
                audit_event_id=uuid4(),
                system_actor_id=SYSTEM_ACTOR_ID,
                correlation_id=uuid4(),
                trace_id=uuid4(),
            )
        )
        self.assertIsInstance(result, OidcPostgresSessionResult)
        return result


if __name__ == "__main__":
    unittest.main()
