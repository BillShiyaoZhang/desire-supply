"""PostgreSQL 18 proof for the reviewed IAM36 forward migration."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import unittest
from unittest import mock
from uuid import UUID, uuid4

import psycopg

from desire_platform.deployment.identity_bootstrap import (
    IdentityBootstrapOutcome,
    apply_internal_sandbox_identity_bootstrap,
    parse_internal_sandbox_identity_manifest,
    verify_internal_sandbox_identity_bootstrap,
)
from desire_platform.deployment.migrations import DeploymentMigrationSettings
from desire_platform.identity_access.adapters.postgres.current_session_logout import (
    CURRENT_SESSION_LOGOUT_FUNCTION_SIGNATURE,
)
from desire_platform.identity_access.adapters.postgres.oidc_authentication import (
    OidcPostgresBeginRequest,
    OidcPostgresCallbackLookup,
    OidcPostgresExchangeClaim,
    OidcPostgresExistingLoginFinalize,
    OidcPostgresPurpose,
    PsycopgOidcAuthenticationUnitOfWork,
)
from desire_platform.identity_access.adapters.postgres.migrations import (
    IAM_SCHEMA_HEAD_VERSION,
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18
from tests.support.identity_bootstrap_builders import (
    canonical_manifest,
    identity_bootstrap_document,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
SYSTEM_ACTOR_ID = UUID("11111111-1111-4111-8111-111111111111")
NOW = datetime(2026, 8, 18, 8, 0, tzinfo=timezone.utc)


class _Connections:
    def __init__(self, conninfo: str) -> None:
        self.conninfo = conninfo

    def checkout(self):
        return psycopg.connect(self.conninfo, autocommit=True)

    @staticmethod
    def release(connection) -> None:
        connection.close()

    @staticmethod
    def discard(connection) -> None:
        connection.close()


class Iam36PostgresRedTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18(enable_tcp_password_auth=True).start()
        cls.addClassCleanup(cls.postgres.stop)
        cls.catalog = MigrationCatalog.load(MIGRATION_ROOT)
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
        driver = PsycopgMigrationDriver(
            settings=PsycopgMigrationSettings(
                conninfo=self.postgres.conninfo(
                    database=self.database,
                    user="iam_migration_runner",
                ),
                application_name="desire-iam36-unpinned-red",
            ),
            dbapi=psycopg,
        )
        IamMigrationRunner(
            driver=driver,
            runner_version="iam36-unpinned-red/1",
        ).run(catalog=self.catalog, contract_sources=self.contract_sources)
        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=True,
        ) as connection:
            for migration_role in (
                "iam_migration_runner",
                "profile_migration_runner",
                "demand_migration_runner",
                "trust_migration_runner",
                "taxonomy_migration_runner",
            ):
                connection.execute(
                    "ALTER ROLE " + migration_role + " PASSWORD NULL"
                )
        self.deployment_settings = DeploymentMigrationSettings(
            host=self.postgres.host,
            port=self.postgres.port,
            database=self.database,
            admin_user=self.postgres.admin_user,
            admin_password=self.postgres.admin_password,
        )
        document = identity_bootstrap_document()
        raw, digest = canonical_manifest(document)
        self.bootstrap_document = document
        self.bootstrap_manifest = parse_internal_sandbox_identity_manifest(
            raw,
            expected_sha256=digest,
            expected_issuer="https://id.example.test",
        )

    def tearDown(self) -> None:
        self.postgres.drop_database(self.database)

    def _apply_bootstrap(self):
        return apply_internal_sandbox_identity_bootstrap(
            settings=self.deployment_settings,
            manifest=self.bootstrap_manifest,
            system_actor_id=SYSTEM_ACTOR_ID,
            now=NOW,
            password_factory=lambda: "iam36-bootstrap-password-material-v1",
        )

    def _login(self, account_code: str):
        account = next(
            value
            for value in self.bootstrap_manifest.accounts
            if value.account_code == account_code
        )
        login_now = datetime.now(timezone.utc)
        uow = PsycopgOidcAuthenticationUnitOfWork(
            connections=_Connections(
                self.postgres.conninfo(
                    database=self.database, user="iam_onboarding"
                )
            )
        )
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
            nonce_ciphertext=b"iam36-encrypted-nonce",
            nonce_encryption_key_id="oidc-nonce-aead-v1",
            pkce_verifier_ciphertext=b"iam36-encrypted-verifier",
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
        exchange_owner = uuid4()
        uow.claim_exchange(
            OidcPostgresExchangeClaim(
                auth_transaction_id=callback.auth_transaction_id,
                exchange_owner_id=exchange_owner,
                invitation_id=None,
            )
        )
        return uow.finalize_existing_login(
            OidcPostgresExistingLoginFinalize(
                auth_transaction_id=transaction.auth_transaction_id,
                exchange_owner_id=exchange_owner,
                provider_issuer="https://id.example.test",
                subject_digest=account.subject_digest,
                subject_digest_key_id=account.subject_digest_key_id,
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

    def _install_authority_wrappers(self) -> None:
        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=True,
        ) as connection:
            connection.execute(
                "CREATE SCHEMA trust_iam36_test AUTHORIZATION trust_schema_owner"
            )
            functions = (
                (
                    "reporter(uuid,uuid,uuid,text)",
                    "trust_schema_owner",
                    "trust_self",
                    "SELECT to_jsonb(authority) FROM "
                    "iam_api.resolve_trust_reporter_authority_v1($1,$2,$3,$4) "
                    "AS authority",
                ),
                (
                    "officer(uuid,uuid,text)",
                    "trust_schema_owner",
                    "trust_officer",
                    "SELECT to_jsonb(authority) FROM "
                    "iam_api.resolve_trust_officer_authority_v1($1,$2,$3) "
                    "AS authority",
                ),
                (
                    "appeal(uuid,uuid,text)",
                    "trust_schema_owner",
                    "trust_appeal",
                    "SELECT to_jsonb(authority) FROM "
                    "iam_api.resolve_appeal_reviewer_authority_v1($1,$2,$3) "
                    "AS authority",
                ),
                (
                    "reporter_marker(uuid,uuid,uuid,text,uuid,uuid,bigint)",
                    "demand_schema_owner",
                    "trust_self",
                    "SELECT to_jsonb(authority) FROM "
                    "iam_api.resolve_trust_reporter_authority_marker_v1("
                    "$1,$2,$3,$4,$5,$6,$7) AS authority",
                ),
                (
                    "officer_marker(uuid,uuid,text,uuid,bigint)",
                    "demand_schema_owner",
                    "trust_officer",
                    "SELECT to_jsonb(authority) FROM "
                    "iam_api.resolve_trust_officer_authority_marker_v1("
                    "$1,$2,$3,$4,$5) AS authority",
                ),
                (
                    "conflict(uuid,uuid,uuid,text,uuid,bigint,bytea)",
                    "demand_schema_owner",
                    "trust_officer",
                    "SELECT to_jsonb(authority) FROM "
                    "iam_api.resolve_trust_party_conflict_facts_v1("
                    "$1,$2,$3,$4,$5,$6,$7) AS authority",
                ),
            )
            for signature, owner, caller, body in functions:
                name, arguments = signature.split("(", 1)
                connection.execute(
                    "CREATE FUNCTION trust_iam36_test."
                    + name
                    + "("
                    + arguments
                    + " RETURNS jsonb LANGUAGE sql SECURITY DEFINER STABLE "
                    "SET search_path=pg_catalog,iam_api AS "
                    + psycopg.sql.Literal(body).as_string(connection)
                )
                connection.execute(
                    "ALTER FUNCTION trust_iam36_test."
                    + signature
                    + " OWNER TO "
                    + owner
                )
                connection.execute(
                    "REVOKE ALL ON FUNCTION trust_iam36_test."
                    + signature
                    + " FROM PUBLIC"
                )
                connection.execute(
                    "GRANT USAGE ON SCHEMA trust_iam36_test TO " + caller
                )
                connection.execute(
                    "GRANT EXECUTE ON FUNCTION trust_iam36_test."
                    + signature
                    + " TO "
                    + caller
                )

    def _logout(
        self,
        *,
        actor_user_id: UUID,
        session_id: UUID,
        command_id: UUID,
        audit_event_id: UUID,
        outbox_event_id: UUID,
        idempotency_digest: bytes,
        payload_hash: bytes,
    ):
        correlation_id = UUID("20000000-0000-4000-8000-000000000001")
        trace_id = UUID("20000000-0000-4000-8000-000000000002")
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="iam_app")
        ) as connection:
            for name, value in (
                ("app.scope_kind", "SELF"),
                ("app.operation", "REVOKE_CURRENT_SESSION"),
                ("app.actor_user_id", str(actor_user_id)),
                ("app.session_id", str(session_id)),
                ("app.target_session_id", str(session_id)),
                ("app.command_id", str(command_id)),
            ):
                connection.execute(
                    "SELECT set_config(%s,%s,true)", (name, value)
                )
            return connection.execute(
                "SELECT iam_api.revoke_current_session_v1("
                "%s,%s,%s,%s,%s,%s,%s,"
                "'iam-receipt-idempotency-hmac-2026-01',%s,"
                "'iam-receipt-payload-hmac-2026-01',"
                "'restricted-canonical-json-v1',%s,%s,%s)",
                (
                    actor_user_id,
                    session_id,
                    command_id,
                    correlation_id,
                    command_id,
                    trace_id,
                    idempotency_digest,
                    payload_hash,
                    datetime.now(timezone.utc) + timedelta(days=30),
                    audit_event_id,
                    outbox_event_id,
                ),
            ).fetchone()[0]

    def test_migration_applies_and_publishes_frozen_abis(self) -> None:
        expected = (
            CURRENT_SESSION_LOGOUT_FUNCTION_SIGNATURE,
            "iam_api.resolve_trust_reporter_authority_v1(uuid,uuid,uuid,text)",
            "iam_api.resolve_trust_officer_authority_v1(uuid,uuid,text)",
            "iam_api.resolve_appeal_reviewer_authority_v1(uuid,uuid,text)",
            "iam_api.resolve_trust_reporter_authority_marker_v1(uuid,uuid,uuid,text,uuid,uuid,bigint)",
            "iam_api.resolve_trust_officer_authority_marker_v1(uuid,uuid,text,uuid,bigint)",
            "iam_api.resolve_trust_party_conflict_facts_v1(uuid,uuid,uuid,text,uuid,bigint,bytea)",
        )
        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database)
        ) as connection:
            rows = connection.execute(
                "SELECT pg_catalog.to_regprocedure(item.signature)::text "
                "FROM unnest(%s::text[]) WITH ORDINALITY AS item(signature,slot) "
                "ORDER BY item.slot",
                (list(expected),),
            ).fetchall()
            compatibility = connection.execute(
                "SELECT current_schema_version,schema_head_version,"
                "min_app_compatible_version,max_app_compatible_version,"
                "octet_length(combined_contract_sha256),"
                "has_table_privilege('trust_migration_runner',"
                "'infra.iam_schema_compatibility','SELECT') "
                "FROM infra.iam_schema_compatibility"
            ).fetchone()
            privileges = connection.execute(
                "SELECT "
                "has_function_privilege('trust_schema_owner',%s,'EXECUTE'),"
                "has_function_privilege('trust_self',%s,'EXECUTE'),"
                "has_function_privilege('demand_schema_owner',%s,'EXECUTE'),"
                "has_function_privilege('trust_officer',%s,'EXECUTE'),"
                "has_function_privilege('iam_app',%s,'EXECUTE'),"
                "has_function_privilege('iam_session_authenticator',%s,'EXECUTE')",
                (
                    expected[1],
                    expected[1],
                    expected[4],
                    expected[5],
                    expected[0],
                    expected[0],
                ),
            ).fetchone()
            broad_trust_grants = connection.execute(
                "SELECT count(*) FROM information_schema.role_table_grants "
                "WHERE grantee='trust_schema_owner' "
                "AND table_schema IN ('iam','audit')"
            ).fetchone()
        self.assertEqual(tuple(row[0] for row in rows), expected)
        self.assertEqual(
            compatibility,
            (IAM_SCHEMA_HEAD_VERSION,) * 4 + (32, True),
        )
        self.assertEqual(
            privileges,
            (True, False, True, False, True, False),
        )
        self.assertEqual(broad_trust_grants, (0,))

    def test_ten_account_bootstrap_apply_replay_and_verify(self) -> None:
        def apply():
            return apply_internal_sandbox_identity_bootstrap(
                settings=self.deployment_settings,
                manifest=self.bootstrap_manifest,
                system_actor_id=SYSTEM_ACTOR_ID,
                now=NOW,
                password_factory=lambda: "iam36-bootstrap-password-material-v1",
            )

        applied = apply()
        replayed = apply()
        verified = verify_internal_sandbox_identity_bootstrap(
            settings=self.deployment_settings,
            manifest=self.bootstrap_manifest,
            system_actor_id=SYSTEM_ACTOR_ID,
            now=NOW,
            password_factory=lambda: "iam36-bootstrap-password-material-v2",
        )
        self.assertEqual(applied.outcome, IdentityBootstrapOutcome.APPLIED)
        self.assertEqual(replayed.outcome, IdentityBootstrapOutcome.REPLAYED)
        self.assertEqual(verified.outcome, IdentityBootstrapOutcome.VERIFIED)
        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database)
        ) as connection:
            facts = connection.execute(
                "SELECT "
                "(SELECT count(*) FROM iam.users),"
                "(SELECT count(*) FROM iam.user_role_grants "
                " WHERE role_code='CREATOR' AND revoked_at IS NULL),"
                "(SELECT count(*) FROM iam.user_role_grants "
                " WHERE role_code='CREATOR' AND revoked_at IS NOT NULL),"
                "(SELECT count(*) FROM iam.platform_duty_grants "
                " WHERE revoked_at IS NULL),"
                "(SELECT count(*) FROM iam.platform_duty_grants "
                " WHERE duty_code='TRUST_OFFICER' AND revoked_at IS NULL),"
                "(SELECT count(*) FROM iam.platform_duty_grants "
                " WHERE duty_code='APPEAL_REVIEWER' AND revoked_at IS NULL),"
                "(SELECT count(*) FROM infra.iam_sandbox_bootstrap_accounts),"
                "(SELECT account_count FROM infra.iam_sandbox_bootstrap_state)"
            ).fetchone()
        self.assertEqual(facts, (10, 1, 9, 7, 2, 1, 10, 10))

    def test_reporter_officer_appeal_and_conflict_authorities_fail_closed(self) -> None:
        self.assertEqual(
            self._apply_bootstrap().outcome,
            IdentityBootstrapOutcome.APPLIED,
        )
        reporter_session = self._login("demand_owner_01")
        officer_session = self._login("trust_officer_01")
        appeal_session = self._login("appeal_reviewer_01")
        reporter_document = next(
            value
            for value in self.bootstrap_document["accounts"]
            if value["account_code"] == "demand_owner_01"
        )
        officer_document = next(
            value
            for value in self.bootstrap_document["accounts"]
            if value["account_code"] == "trust_officer_01"
        )
        appeal_document = next(
            value
            for value in self.bootstrap_document["accounts"]
            if value["account_code"] == "appeal_reviewer_01"
        )
        organization_id = UUID(
            reporter_document["demand_owner_grant"]["organization_id"]
        )

        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=True,
        ) as connection:
            requirements = connection.execute(
                "SELECT document.id,document.content_sha256,bundle.id,"
                "session.auth_transaction_id,session.auth_time,"
                "session.acr_code,session.amr_codes "
                "FROM iam.policy_selectors AS selector "
                "JOIN iam.policy_bundles AS bundle "
                " ON bundle.id=selector.current_bundle_id "
                "JOIN iam.policy_bundle_documents AS item "
                " ON item.bundle_id=bundle.id AND item.required "
                "JOIN iam.policy_documents AS document "
                " ON document.id=item.document_id "
                "JOIN iam.sessions AS session ON session.id=%s "
                "WHERE selector.target_role='DEMAND_OWNER' "
                " AND selector.scope_type='ORGANIZATION_ROLE'",
                (reporter_session.session_id,),
            ).fetchall()
            self.assertGreaterEqual(len(requirements), 1)
            for (
                document_id,
                content_sha256,
                bundle_id,
                auth_transaction_id,
                auth_time,
                acr_code,
                amr_codes,
            ) in requirements:
                accepted_at = datetime.now(timezone.utc)
                connection.execute(
                    "INSERT INTO iam.policy_acceptances("
                    "id,user_id,document_id,content_sha256,bundle_id,"
                    "accepted_at,session_id,auth_transaction_id,auth_time,"
                    "acr_code,amr_codes,source_action,command_id,"
                    "correlation_id,aggregate_version,created_at) VALUES "
                    "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'POLICY_ACCEPT',"
                    "%s,%s,1,%s)",
                    (
                        uuid4(),
                        reporter_session.user_id,
                        document_id,
                        content_sha256,
                        bundle_id,
                        accepted_at,
                        reporter_session.session_id,
                        auth_transaction_id,
                        auth_time,
                        acr_code,
                        amr_codes,
                        uuid4(),
                        uuid4(),
                        accepted_at,
                    ),
                )
        self._install_authority_wrappers()

        reporter_grant = reporter_document["demand_owner_grant"]
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="trust_self")
        ) as connection:
            connection.execute("SELECT set_config('app.scope_kind','TRUST_REPORTER',true)")
            connection.execute("SELECT set_config('app.operation','SUBMIT_REPORT',true)")
            connection.execute(
                "SELECT set_config('app.actor_id',%s,true)",
                (str(reporter_session.user_id),),
            )
            connection.execute(
                "SELECT set_config('app.session_id',%s,true)",
                (str(reporter_session.session_id),),
            )
            connection.execute(
                "SELECT set_config('app.organization_id',%s,true)",
                (str(organization_id),),
            )
            reporter = connection.execute(
                "SELECT trust_iam36_test.reporter(%s,%s,%s,'SUBMIT_REPORT')",
                (
                    reporter_session.user_id,
                    reporter_session.session_id,
                    organization_id,
                ),
            ).fetchone()[0]
            self.assertTrue(reporter["policy_requirements_satisfied"])
            self.assertEqual(reporter["role_code"], "DEMAND_OWNER")
            marker = connection.execute(
                "SELECT trust_iam36_test.reporter_marker("
                "%s,%s,%s,'SUBMIT_REPORT',%s,%s,%s)",
                (
                    reporter_session.user_id,
                    reporter_session.session_id,
                    organization_id,
                    UUID(reporter_grant["membership_id"]),
                    UUID(reporter_grant["grant_id"]),
                    reporter["membership_role_grant_version"],
                ),
            ).fetchone()[0]
            self.assertEqual(
                marker,
                reporter["authority_marker_sha256"],
            )
            for operation in (
                "SUBMIT_REPORT",
                "READ_OWN_REPORT",
                "OPEN_APPEAL",
                "READ_OWN_APPEAL",
                "SAVE_APPEAL_DRAFT",
                "SUBMIT_APPEAL",
            ):
                connection.execute(
                    "SELECT set_config('app.operation',%s,true)",
                    (operation,),
                )
                accepted = connection.execute(
                    "SELECT trust_iam36_test.reporter(%s,%s,%s,%s)",
                    (
                        reporter_session.user_id,
                        reporter_session.session_id,
                        organization_id,
                        operation,
                    ),
                ).fetchone()[0]
                self.assertIsNotNone(accepted)
            connection.execute(
                "SELECT set_config('app.operation','SubmitSafetyReport',true)"
            )
            denied = connection.execute(
                "SELECT trust_iam36_test.reporter(%s,%s,%s,'SubmitSafetyReport')",
                (
                    reporter_session.user_id,
                    reporter_session.session_id,
                    organization_id,
                ),
            ).fetchone()[0]
            self.assertIsNone(denied)

        officer_duty = officer_document["platform_duty_grants"][0]
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="trust_officer")
        ) as connection:
            for name, value in (
                ("app.scope_kind", "TRUST_OFFICER"),
                ("app.operation", "CLAIM_CASE"),
                ("app.actor_id", str(officer_session.user_id)),
                ("app.session_id", str(officer_session.session_id)),
                ("app.organization_id", str(organization_id)),
            ):
                connection.execute(
                    "SELECT set_config(%s,%s,true)", (name, value)
                )
            officer = connection.execute(
                "SELECT trust_iam36_test.officer(%s,%s,'CLAIM_CASE')",
                (officer_session.user_id, officer_session.session_id),
            ).fetchone()[0]
            self.assertEqual(officer["duty_code"], "TRUST_OFFICER")
            marker = connection.execute(
                "SELECT trust_iam36_test.officer_marker("
                "%s,%s,'CLAIM_CASE',%s,%s)",
                (
                    officer_session.user_id,
                    officer_session.session_id,
                    UUID(officer_duty["grant_id"]),
                    officer["duty_grant_version"],
                ),
            ).fetchone()[0]
            self.assertEqual(
                marker,
                officer["authority_marker_sha256"],
            )
            conflict = connection.execute(
                "SELECT trust_iam36_test.conflict("
                "%s,%s,%s,'CLAIM_CASE',%s,%s,%s)",
                (
                    officer_session.user_id,
                    officer_session.session_id,
                    organization_id,
                    UUID(officer_duty["grant_id"]),
                    officer["duty_grant_version"],
                    bytes.fromhex(officer["authority_marker_sha256"][2:]),
                ),
            ).fetchone()[0]
            self.assertFalse(conflict["organization_membership_conflict"])
            wrong_version = connection.execute(
                "SELECT trust_iam36_test.officer_marker("
                "%s,%s,'CLAIM_CASE',%s,%s)",
                (
                    officer_session.user_id,
                    officer_session.session_id,
                    UUID(officer_duty["grant_id"]),
                    officer["duty_grant_version"] + 1,
                ),
            ).fetchone()[0]
            self.assertIsNone(wrong_version)
            for operation in (
                "CLAIM_CASE",
                "RELEASE_CASE_ASSIGNMENT",
                "SAVE_TRIAGE_DRAFT",
                "PUBLISH_TRIAGE",
                "PLACE_HOLD",
                "CLAIM_HOLD_RELEASE",
                "RELEASE_HOLD",
                "PUBLISH_OUTCOME",
                "LIST_CASE_QUEUE",
                "READ_ASSIGNED_CASE",
                "LIST_HOLD_RELEASE_QUEUE",
            ):
                connection.execute(
                    "SELECT set_config('app.operation',%s,true)",
                    (operation,),
                )
                accepted = connection.execute(
                    "SELECT trust_iam36_test.officer(%s,%s,%s)",
                    (
                        officer_session.user_id,
                        officer_session.session_id,
                        operation,
                    ),
                ).fetchone()[0]
                self.assertIsNotNone(accepted)

        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="trust_appeal")
        ) as connection:
            for name, value in (
                ("app.scope_kind", "TRUST_APPEAL"),
                ("app.operation", "DECIDE_APPEAL"),
                ("app.actor_id", str(appeal_session.user_id)),
                ("app.session_id", str(appeal_session.session_id)),
            ):
                connection.execute(
                    "SELECT set_config(%s,%s,true)", (name, value)
                )
            for operation in (
                "LIST_APPEAL_QUEUE",
                "READ_ASSIGNED_APPEAL",
                "CLAIM_APPEAL",
                "RELEASE_APPEAL_ASSIGNMENT",
                "SAVE_APPEAL_REVIEW_DRAFT",
                "DECIDE_APPEAL",
            ):
                connection.execute(
                    "SELECT set_config('app.operation',%s,true)",
                    (operation,),
                )
                appeal = connection.execute(
                    "SELECT trust_iam36_test.appeal(%s,%s,%s)",
                    (
                        appeal_session.user_id,
                        appeal_session.session_id,
                        operation,
                    ),
                ).fetchone()[0]
                self.assertEqual(appeal["duty_code"], "APPEAL_REVIEWER")
                self.assertEqual(
                    appeal["duty_grant_id"],
                    appeal_document["platform_duty_grants"][0]["grant_id"],
                )

    def test_current_session_logout_fresh_replay_terminal_and_expiry(self) -> None:
        self.assertEqual(
            self._apply_bootstrap().outcome,
            IdentityBootstrapOutcome.APPLIED,
        )
        target = self._login("creator_01")
        other = self._login("creator_01")
        command_id = uuid4()
        audit_event_id = uuid4()
        outbox_event_id = uuid4()
        idempotency_digest = hashlib.sha256(b"iam36-logout-key-1").digest()
        payload_hash = hashlib.sha256(b"{}").digest()
        fresh = self._logout(
            actor_user_id=target.user_id,
            session_id=target.session_id,
            command_id=command_id,
            audit_event_id=audit_event_id,
            outbox_event_id=outbox_event_id,
            idempotency_digest=idempotency_digest,
            payload_hash=payload_hash,
        )
        self.assertEqual(fresh["outcome"], "REVOKED")
        self.assertEqual(fresh["session_status"], "REVOKED")
        self.assertFalse(fresh["replayed"])
        self.assertTrue(fresh["clear_current_session_cookie"])
        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database)
        ) as connection:
            before_replay = connection.execute(
                "SELECT "
                "(SELECT status FROM iam.sessions WHERE id=%s),"
                "(SELECT status FROM iam.session_families WHERE id=%s),"
                "(SELECT count(*) FROM iam.sessions "
                " WHERE family_id=%s AND status='ACTIVE'),"
                "(SELECT status FROM iam.sessions WHERE id=%s),"
                "(SELECT status FROM iam.session_families WHERE id=%s),"
                "(SELECT count(*) FROM infra.command_receipts "
                " WHERE command_name='RevokeCurrentSession'),"
                "(SELECT count(*) FROM audit.audit_events "
                " WHERE action_code='RevokeCurrentSession'),"
                "(SELECT count(*) FROM infra.outbox_events "
                " WHERE event_type='SessionRevoked' AND aggregate_id=%s)",
                (
                    target.session_id,
                    target.session_family_id,
                    target.session_family_id,
                    other.session_id,
                    other.session_family_id,
                    target.session_id,
                ),
            ).fetchone()
        self.assertEqual(
            before_replay,
            ("REVOKED", "ACTIVE", 0, "ACTIVE", "ACTIVE", 1, 1, 1),
        )

        replayed = self._logout(
            actor_user_id=target.user_id,
            session_id=target.session_id,
            command_id=command_id,
            audit_event_id=audit_event_id,
            outbox_event_id=outbox_event_id,
            idempotency_digest=idempotency_digest,
            payload_hash=payload_hash,
        )
        self.assertEqual(replayed["outcome"], "REPLAYED")
        self.assertTrue(replayed["replayed"])
        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database)
        ) as connection:
            after_replay = connection.execute(
                "SELECT "
                "(SELECT count(*) FROM infra.command_receipts "
                " WHERE command_name='RevokeCurrentSession'),"
                "(SELECT count(*) FROM audit.audit_events "
                " WHERE action_code='RevokeCurrentSession'),"
                "(SELECT count(*) FROM infra.outbox_events "
                " WHERE event_type='SessionRevoked' AND aggregate_id=%s)",
                (target.session_id,),
            ).fetchone()
        self.assertEqual(after_replay, (1, 1, 1))

        with self.assertRaises(psycopg.errors.UniqueViolation) as reused:
            self._logout(
                actor_user_id=target.user_id,
                session_id=target.session_id,
                command_id=uuid4(),
                audit_event_id=uuid4(),
                outbox_event_id=uuid4(),
                idempotency_digest=idempotency_digest,
                payload_hash=hashlib.sha256(b'{"changed":true}').digest(),
            )
        self.assertEqual(
            reused.exception.diag.constraint_name,
            "ck_current_session_logout_idempotency_reused",
        )

        terminal = self._logout(
            actor_user_id=target.user_id,
            session_id=target.session_id,
            command_id=uuid4(),
            audit_event_id=uuid4(),
            outbox_event_id=uuid4(),
            idempotency_digest=hashlib.sha256(b"iam36-logout-key-2").digest(),
            payload_hash=payload_hash,
        )
        self.assertEqual(terminal["outcome"], "ALREADY_TERMINAL")
        self.assertEqual(terminal["session_status"], "REVOKED")

        expiring = self._login("creator_01")
        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=True,
        ) as connection:
            connection.execute(
                "UPDATE iam.sessions SET "
                "idle_expires_at=last_activity_at+interval '1 microsecond',"
                "aggregate_version=aggregate_version+1,"
                "updated_at=transaction_timestamp() WHERE id=%s",
                (expiring.session_id,),
            )
        expired = self._logout(
            actor_user_id=expiring.user_id,
            session_id=expiring.session_id,
            command_id=uuid4(),
            audit_event_id=uuid4(),
            outbox_event_id=uuid4(),
            idempotency_digest=hashlib.sha256(b"iam36-logout-key-3").digest(),
            payload_hash=payload_hash,
        )
        self.assertEqual(expired["outcome"], "EXPIRED")
        self.assertEqual(expired["session_status"], "EXPIRED")
        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database)
        ) as connection:
            terminal_facts = connection.execute(
                "SELECT "
                "(SELECT count(*) FROM infra.outbox_events "
                " WHERE event_type='SessionRevoked' AND aggregate_id=%s),"
                "(SELECT status FROM iam.session_families WHERE id=%s),"
                "(SELECT count(*) FROM iam.sessions "
                " WHERE family_id=%s AND status='ACTIVE')",
                (
                    expiring.session_id,
                    expiring.session_family_id,
                    expiring.session_family_id,
                ),
            ).fetchone()
        self.assertEqual(terminal_facts, (0, "ACTIVE", 0))


class Iam36PostgresLifecycleTest(unittest.TestCase):
    def test_postgres_cleanup_is_registered_before_later_class_setup(self) -> None:
        class _PostgresProbe:
            def __init__(self) -> None:
                self.stopped = False

            def start(self):
                return self

            def stop(self) -> None:
                self.stopped = True

        class _SetupProbe(Iam36PostgresRedTest):
            pass

        _SetupProbe._class_cleanups = []
        postgres = _PostgresProbe()
        with mock.patch(
            __name__ + ".TemporaryPostgres18",
            return_value=postgres,
        ), mock.patch.object(
            MigrationCatalog,
            "load",
            side_effect=RuntimeError("injected post-start setup failure"),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "injected post-start setup failure",
            ):
                _SetupProbe.setUpClass()

        _SetupProbe.doClassCleanups()
        self.assertTrue(postgres.stopped)


if __name__ == "__main__":
    unittest.main()
