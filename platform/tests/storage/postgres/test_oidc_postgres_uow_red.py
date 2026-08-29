"""TEST-PG-IAM-OIDC-001: real AuthTransaction/Session fixed programs."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import threading
import unittest
from uuid import UUID, uuid4

import psycopg

from desire_platform.identity_access.adapters.postgres.oidc_bundle import (
    build_postgres_iam_authentication_bundle,
)
from desire_platform.identity_access.adapters.postgres.oidc_authentication import (
    OidcPostgresAuthenticationRejected,
    OidcPostgresBeginRequest,
    OidcPostgresCallbackLookup,
    OidcPostgresExchangeClaim,
    OidcPostgresExchangeTerminal,
    OidcPostgresEnrollmentFinalize,
    OidcPostgresExistingLoginFinalize,
    OidcPostgresGenericStepUpFinalize,
    OidcPostgresInvitationStepUpFinalize,
    OidcPostgresStepUpSessionFacts,
    OidcPostgresPurpose,
    OidcPostgresTerminalOutcome,
    OidcPostgresTransaction,
    PsycopgOidcAuthenticationUnitOfWork,
)
from desire_platform.identity_access.adapters.postgres.migrations import (
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from desire_platform.identity_access.application.authentication import (
    BeginOidcAuthorizationCommand,
    CompleteOidcAuthenticationCommand,
    OidcBrowserContext,
    OidcSecurityPolicy,
)
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.ports.identity_provider import (
    AuthenticatedSubject,
    ProviderAuthorization,
)
from desire_platform.identity_access.ports.recipient_binding import (
    RecipientBindingTuple,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18


ROOT = Path(__file__).resolve().parents[3]
MIGRATION = (
    ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
    / "0020_expand__oidc_authentication_uow.sql"
)
ENROLLMENT_MIGRATION = (
    ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
    / "0039_expand__invitation_oidc_enrollment.sql"
)


def _uuid(value: int) -> UUID:
    return UUID(int=value)


class OidcPostgresContractRedTest(unittest.TestCase):
    def test_values_are_frozen_closed_and_contain_no_raw_protocol_secret(self) -> None:
        now = datetime.now(timezone.utc)
        begin = OidcPostgresBeginRequest(
            auth_transaction_id=_uuid(1),
            purpose=OidcPostgresPurpose.LOGIN,
            browser_binding_digest=b"b" * 32,
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
            state_digest=b"s" * 32,
            state_digest_key_id="oidc-state-v1",
            nonce_digest=b"n" * 32,
            nonce_digest_key_id="oidc-nonce-v1",
            nonce_ciphertext=b"encrypted-nonce",
            nonce_encryption_key_id="oidc-nonce-aead-v1",
            pkce_verifier_ciphertext=b"encrypted-verifier",
            pkce_encryption_key_id="oidc-pkce-aead-v1",
            pkce_code_challenge="A" * 43,
            provider_issuer="https://id.example.test",
            provider_audience="desire-internal-pilot",
            redirect_uri="https://app.example.test/v1/auth/oidc/callback",
            return_to="/app",
            security_policy_version="iam-security-v1",
            audit_event_id=_uuid(2),
            system_actor_id=_uuid(3),
            correlation_id=_uuid(4),
            trace_id=_uuid(5),
        )
        with self.assertRaises(FrozenInstanceError):
            begin.return_to = "/changed"  # type: ignore[misc]
        all_names = {
            field.name
            for value_type in (
                OidcPostgresBeginRequest,
                OidcPostgresCallbackLookup,
                OidcPostgresExchangeClaim,
                OidcPostgresExchangeTerminal,
                OidcPostgresExistingLoginFinalize,
                OidcPostgresEnrollmentFinalize,
                OidcPostgresGenericStepUpFinalize,
                OidcPostgresInvitationStepUpFinalize,
                OidcPostgresStepUpSessionFacts,
                OidcPostgresTransaction,
            )
            for field in fields(value_type)
        }
        for forbidden in (
            "password",
            "raw_state",
            "raw_browser_cookie",
            "raw_session_handle",
            "authorization_code",
            "access_token",
            "id_token",
            "refresh_token",
            "raw_subject",
        ):
            self.assertNotIn(forbidden, all_names)
        self.assertEqual(
            tuple(value.value for value in OidcPostgresPurpose),
            ("LOGIN", "ENROLLMENT", "STEP_UP"),
        )
        with self.assertRaises(ValueError):
            replace(
                begin,
                purpose=OidcPostgresPurpose.ENROLLMENT,
                invitation_id=_uuid(6),
                invitation_version=1,
                expected_contact_point_id=_uuid(7),
                expected_contact_type="PHONE",
                expected_contact_binding_digest=b"e" * 32,
                expected_contact_binding_key_id="contact-v1",
            )
        self.assertEqual(
            tuple(value.value for value in OidcPostgresTerminalOutcome),
            ("REJECTED", "MISCONFIGURED", "RESULT_UNKNOWN"),
        )

    def test_uow_public_surface_is_fixed_and_migration_extends_v2_evidence(self) -> None:
        self.assertEqual(
            {
                name
                for name in dir(PsycopgOidcAuthenticationUnitOfWork)
                if not name.startswith("_")
            },
            {
                "begin",
                "read_callback",
                "claim_exchange",
                "finish_exchange",
                "finalize_existing_login",
                "finalize_enrollment",
                "resolve_invitation_step_up_session",
                "finalize_invitation_step_up",
                "resolve_generic_step_up_session",
                "finalize_generic_step_up",
            },
        )
        sql = MIGRATION.read_text(encoding="utf-8")
        for marker in (
            "protocol_version = 2",
            "nonce_ciphertext",
            "expected_contact_binding_digest",
            "pkce_code_challenge",
            "provider_issuer",
            "security_policy_version",
            "exchange_owner_id",
            "aggregate_version",
            "iam_api.read_oidc_callback_v2",
            "iam_api.lock_oidc_identity_v2",
            "rls_oidc_callback_transaction_definer",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, sql)
        self.assertNotIn("password", sql.lower())

    def test_enrollment_program_is_invitation_exact_and_authority_free(self) -> None:
        sql = ENROLLMENT_MIGRATION.read_text(encoding="utf-8")
        for marker in (
            "iam_api.finalize_oidc_invitation_enrollment_v1",
            "purpose = 'ENROLLMENT'",
            "status = 'PENDING_ENROLLMENT'",
            "invitation_row.aggregate_version = exact_invitation_version",
            "exact_expected_contact_binding_digest",
            "exact_verified_contact_binding_digest",
            "identity.issuer = exact_provider_issuer",
            "identity.subject_digest = exact_subject_digest",
            "invitation_row.target_role = 'DEMAND_OWNER'",
            "rls_oidc_enrollment_recovery_session_select_definer_v1",
            "identity_locked := FOUND",
            "resolved_user_status = 'PENDING_ENROLLMENT'",
            "contact_row.user_id = resolved_user_id",
            "prior_session.rotation_reason = 'ENROLLMENT'",
            "set_config('app.actor_user_id', resolved_user_id::text, true)",
            "verified_for_invitation_id",
            "'ACTIVE','ENROLLMENT'",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, sql)
        for forbidden_write in (
            "INSERT INTO iam.memberships",
            "INSERT INTO iam.user_role_grants",
            "INSERT INTO iam.membership_role_grants",
        ):
            self.assertNotIn(forbidden_write, sql)

    def test_enrollment_contact_update_qualifies_user_id_predicate(self) -> None:
        sql = ENROLLMENT_MIGRATION.read_text(encoding="utf-8")
        update_start = sql.index("UPDATE iam.contact_points AS exact_contact")
        update_end = sql.index("IF NOT FOUND THEN", update_start)
        contact_update = sql[update_start:update_end]

        self.assertIn("SET user_id = resolved_user_id", contact_update)
        self.assertIn(
            "WHERE exact_contact.id = exact_expected_contact_point_id",
            contact_update,
        )
        self.assertIn(
            "AND exact_contact.user_id IS NULL",
            contact_update,
        )
        # SET targets cannot be alias-qualified in PostgreSQL.  Predicates can
        # and must be, because this RETURNS TABLE program also has a user_id
        # output variable in PL/pgSQL scope.
        self.assertNotIn("AND user_id IS NULL", contact_update)


class _Connections:
    def __init__(self, conninfo: str) -> None:
        self._conninfo = conninfo

    def checkout(self):
        return psycopg.connect(self._conninfo, autocommit=True)

    def release(self, connection) -> None:
        connection.close()

    def discard(self, connection) -> None:
        connection.close()


class _CommitAcknowledgementLostConnection:
    """Commit reaches PostgreSQL, but its acknowledgement never reaches the app."""

    def __init__(self, connection) -> None:
        self._connection = connection

    @property
    def info(self):
        return self._connection.info

    def execute(self, query, parameters=None):
        result = self._connection.execute(query, parameters)
        if query == "COMMIT":
            raise psycopg.OperationalError("simulated lost COMMIT acknowledgement")
        return result

    def close(self) -> None:
        self._connection.close()


class _CommitAcknowledgementLostConnections(_Connections):
    def checkout(self):
        return _CommitAcknowledgementLostConnection(
            psycopg.connect(self._conninfo, autocommit=True)
        )


class _BundleClock:
    def __init__(self, now):
        self._now = now

    def now(self):
        return self._now


class _BundleIds:
    def new_id(self, _kind):
        return uuid4()


class _BundleSecrets:
    def token_bytes(self, purpose, length):
        seed = hashlib.sha256(purpose.encode("ascii")).digest()
        return (seed * 2)[:length]


class _BundleKeyring:
    state_digest_key_id = "oidc-state-v1"
    retained_state_digest_key_ids = ("oidc-state-v1",)
    browser_binding_digest_key_id = "oidc-browser-v1"
    retained_browser_binding_digest_key_ids = ("oidc-browser-v1",)
    nonce_digest_key_id = "oidc-nonce-v1"
    retained_nonce_digest_key_ids = ("oidc-nonce-v1",)
    session_handle_digest_key_id = "session-handle-v1"
    csrf_key_id = "session-csrf-v1"

    def __init__(self):
        self._keys = {
            key_id: ("pg-bundle:" + key_id).encode("ascii")
            for key_id in (
                self.state_digest_key_id,
                self.browser_binding_digest_key_id,
                self.nonce_digest_key_id,
                self.session_handle_digest_key_id,
                self.csrf_key_id,
            )
        }

    def digest_text(self, *, key_id, value):
        import hmac

        return hmac.new(
            self._keys[key_id], value.encode("utf-8"), hashlib.sha256
        ).hexdigest()

    def keyed_digest_hex(self, *, key_id, canonical_bytes):
        import hmac

        return hmac.new(
            self._keys[key_id], canonical_bytes, hashlib.sha256
        ).hexdigest()


class _BundleSecretBox:
    key_id = "oidc-protocol-aead-v1"

    def encrypt(self, *, plaintext, key_id):
        if key_id != self.key_id:
            raise AssertionError("unexpected key")
        return b"sealed:" + plaintext.encode("utf-8")

    def decrypt(self, *, ciphertext, key_id):
        if key_id != self.key_id or not ciphertext.startswith(b"sealed:"):
            raise AssertionError("unexpected ciphertext")
        return ciphertext[7:].decode("utf-8")


class _BundleProvider:
    def __init__(self, *, subject_digest, now):
        self.subject_digest = subject_digest
        self.now = now
        self.begin_facts = None
        self.exchange_calls = 0

    def preflight(self, **_facts):
        return None

    def preflight_exchange(self, **_facts):
        return None

    def begin(self, **facts):
        self.begin_facts = facts
        return ProviderAuthorization(
            authorization_url="https://id.example.test/authorize?state=redacted",
            issuer="https://id.example.test",
            audience="desire-internal-pilot",
            redirect_uri="https://app.example.test/v1/auth/oidc/callback",
            code_challenge_method="S256",
        )

    def exchange(self, _request):
        self.exchange_calls += 1
        return AuthenticatedSubject(
            issuer="https://id.example.test",
            subject_digest=self.subject_digest.hex(),
            subject_digest_key_id="oidc-subject-v1",
            verified_recipient_binding=RecipientBindingTuple(
                contact_type="EMAIL",
                binding_digest=hashlib.sha256(b"person@example.test").hexdigest(),
                digest_key_id="contact-v1",
            ),
            auth_time=self.now - timedelta(minutes=1),
            acr_code="urn:desire:acr:mfa",
            amr_codes=("otp",),
            token_issued_at=self.now - timedelta(seconds=30),
            token_expires_at=self.now + timedelta(minutes=5),
        )


class OidcPostgresRealTest(unittest.TestCase):
    """Real PG18 LOGIN begin/callback/claim/finalize and restart evidence."""

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
                    application_name="desire-oidc-pg-test",
                ),
                dbapi=psycopg,
            ),
            runner_version="oidc-pg-test/1",
        ).run(catalog=self.catalog, contract_sources=self.contract_sources)
        self.assertEqual(
            report.applied_versions,
            tuple(item.descriptor.version for item in self.catalog.artifacts),
        )
        self.now = datetime.now(timezone.utc)
        self.user_id = uuid4()
        self.identity_id = uuid4()
        self.subject_digest = hashlib.sha256(b"existing-oidc-subject").digest()
        with self._admin(autocommit=False) as connection:
            connection.execute(
                "INSERT INTO iam.users (id,status,display_handle,aggregate_version,"
                "created_at,updated_at) VALUES (%s,'ACTIVE','oidc_existing_user',1,%s,%s)",
                (self.user_id, self.now - timedelta(days=1), self.now),
            )
            connection.execute(
                "INSERT INTO iam.external_identities ("
                "id,user_id,issuer,subject_digest,subject_digest_key_id,"
                "verified_at,status,created_at) VALUES ("
                "%s,%s,'https://id.example.test',%s,'oidc-subject-v1',%s,"
                "'ACTIVE',%s)",
                (
                    self.identity_id,
                    self.user_id,
                    self.subject_digest,
                    self.now,
                    self.now - timedelta(days=1),
                ),
            )
        self.connections = _Connections(
            self.postgres.conninfo(database=self.database, user="iam_onboarding")
        )
        self.uow = PsycopgOidcAuthenticationUnitOfWork(
            connections=self.connections
        )

    def tearDown(self) -> None:
        self.postgres.drop_database(self.database)

    def _admin(self, *, autocommit: bool = True):
        return psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=autocommit,
        )

    def _begin_request(self):
        return OidcPostgresBeginRequest(
            auth_transaction_id=uuid4(),
            purpose=OidcPostgresPurpose.LOGIN,
            browser_binding_digest=hashlib.sha256(b"browser").digest(),
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
            nonce_digest=hashlib.sha256(b"nonce").digest(),
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
            system_actor_id=uuid4(),
            correlation_id=uuid4(),
            trace_id=uuid4(),
        )

    def _seed_enrollment_invitation(self, *, target_role="DEMAND_OWNER"):
        created = self.now - timedelta(days=1)
        organization_id = uuid4()
        contact_id = uuid4()
        invitation_id = uuid4()
        selector_digest = hashlib.sha256(
            json.dumps(
                {
                    "access_purpose": "ORGANIZATION_MEMBERSHIP",
                    "scope_type": "ORGANIZATION_ROLE",
                    "target_role": target_role,
                    "jurisdiction": "CN",
                    "locale": "zh-CN",
                },
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        ).digest()
        policy_bundle_id = uuid4()
        policy_document_id = uuid4()
        policy_document_body = "OIDC enrollment terms"
        policy_document_hash = hashlib.sha256(
            policy_document_body.encode("utf-8")
        ).digest()
        publication_command_id = uuid4()
        contact_binding_digest = hashlib.sha256(
            ("oidc-enrollment-contact:" + target_role).encode("ascii")
        ).digest()
        with self._admin(autocommit=False) as connection:
            connection.execute(
                "INSERT INTO iam.organizations ("
                "id,organization_type,public_name,jurisdiction,status,"
                "client_reference_namespace,client_reference,aggregate_version,"
                "created_at,updated_at) VALUES ("
                "%s,'BUSINESS','OIDC enrollment fixture','CN','ACTIVE',"
                "'oidc-enrollment-test',%s,1,%s,%s)",
                (organization_id, str(organization_id), created, created),
            )
            connection.execute(
                "INSERT INTO iam.policy_selectors ("
                "selector_digest,canonicalization_version,access_purpose,"
                "scope_type,target_role,jurisdiction,locale,current_bundle_id,"
                "aggregate_version,created_at,updated_at) VALUES ("
                "%s,'policy-selector-json-v1','ORGANIZATION_MEMBERSHIP',"
                "'ORGANIZATION_ROLE',%s,'CN','zh-CN',NULL,1,%s,%s)",
                (
                    selector_digest,
                    target_role,
                    created,
                    created,
                ),
            )
            connection.execute(
                "INSERT INTO iam.policy_bundles ("
                "id,selector_digest,status,effective_at,effective_until,"
                "superseded_by_bundle_id,release_manifest_sha256,"
                "release_signature,release_signing_key_id,"
                "publication_command_id,aggregate_version,created_at,updated_at) "
                "VALUES (%s,%s,'DRAFT',NULL,NULL,NULL,%s,%s,"
                "'oidc-enrollment-policy-v1',%s,1,%s,%s)",
                (
                    policy_bundle_id,
                    selector_digest,
                    hashlib.sha256(b"oidc-enrollment-policy-manifest").digest(),
                    b"reviewed-enrollment-signature",
                    publication_command_id,
                    created,
                    created,
                ),
            )
            connection.execute(
                "INSERT INTO iam.policy_documents ("
                "id,kind,locale,semantic_version,canonical_body,content_sha256,"
                "legal_effect,jurisdiction,status,effective_at,"
                "superseded_by_document_id,publication_command_id,created_at,updated_at"
                ") VALUES (%s,'TERMS','zh-CN','1.0.0',%s,%s,"
                "'CONTRACT_ACCEPTANCE','CN','ACTIVE',%s,NULL,%s,%s,%s)",
                (
                    policy_document_id,
                    policy_document_body,
                    policy_document_hash,
                    created,
                    publication_command_id,
                    created,
                    created,
                ),
            )
            connection.execute(
                "INSERT INTO iam.policy_bundle_documents "
                "(bundle_id,document_id,position,required) VALUES (%s,%s,1,true)",
                (policy_bundle_id, policy_document_id),
            )
            connection.execute(
                "UPDATE iam.policy_bundles SET status='ACTIVE',effective_at=%s,"
                "aggregate_version=2,updated_at=%s WHERE id=%s",
                (created, created, policy_bundle_id),
            )
            connection.execute(
                "UPDATE iam.policy_selectors SET current_bundle_id=%s,"
                "aggregate_version=2,updated_at=%s WHERE selector_digest=%s",
                (policy_bundle_id, created, selector_digest),
            )
            connection.execute(
                "INSERT INTO iam.contact_points ("
                "id,user_id,contact_type,locator_ciphertext,"
                "locator_encryption_key_id,locator_encryption_algorithm,"
                "binding_digest,binding_digest_key_id,verified_at,"
                "retention_until,created_at,updated_at) VALUES ("
                "%s,NULL,'EMAIL',NULL,NULL,NULL,%s,'contact-v1',NULL,%s,%s,%s)",
                (
                    contact_id,
                    contact_binding_digest,
                    self.now + timedelta(days=30),
                    created,
                    created,
                ),
            )
            connection.execute(
                "INSERT INTO iam.access_invitations ("
                "id,purpose,organization_id,target_scope,target_role,"
                "is_initial_admin,recipient_contact_id,masked_recipient_label,"
                "policy_selector_digest,issued_policy_bundle_id,status,expires_at,"
                "issuer_kind,issuer_user_id,token_nonce,token_key_id,"
                "accepted_by_user_id,terminal_at,terminal_reason_code,"
                "aggregate_version,created_at,updated_at) VALUES ("
                "%s,'ORGANIZATION_MEMBERSHIP',%s,'ORGANIZATION',%s,false,"
                "%s,'n***@example.invalid',%s,%s,'ISSUED',%s,'SYSTEM',NULL,"
                "%s,'invitation-token-v1',NULL,NULL,NULL,1,%s,%s)",
                (
                    invitation_id,
                    organization_id,
                    target_role,
                    contact_id,
                    selector_digest,
                    policy_bundle_id,
                    self.now + timedelta(days=7),
                    hashlib.sha256(invitation_id.bytes).digest(),
                    created,
                    created,
                ),
            )
        return (
            organization_id,
            contact_id,
            invitation_id,
            contact_binding_digest,
        )

    def _begin_enrollment(
        self,
        *,
        invitation_id,
        contact_id,
        contact_binding_digest,
    ):
        request = OidcPostgresBeginRequest(
            auth_transaction_id=uuid4(),
            purpose=OidcPostgresPurpose.ENROLLMENT,
            browser_binding_digest=hashlib.sha256(b"enrollment-browser").digest(),
            browser_binding_key_id="oidc-browser-v1",
            initiating_session_id=None,
            initiating_user_id=None,
            expected_user_id=None,
            invitation_id=invitation_id,
            invitation_version=1,
            expected_contact_point_id=contact_id,
            expected_contact_type="EMAIL",
            expected_contact_binding_digest=contact_binding_digest,
            expected_contact_binding_key_id="contact-v1",
            state_digest=hashlib.sha256(uuid4().bytes).digest(),
            state_digest_key_id="oidc-state-v1",
            nonce_digest=hashlib.sha256(uuid4().bytes).digest(),
            nonce_digest_key_id="oidc-nonce-v1",
            nonce_ciphertext=b"reviewed-enrollment-nonce",
            nonce_encryption_key_id="oidc-nonce-aead-v1",
            pkce_verifier_ciphertext=b"reviewed-enrollment-verifier",
            pkce_encryption_key_id="oidc-pkce-aead-v1",
            pkce_code_challenge="C" * 43,
            provider_issuer="https://id.example.test",
            provider_audience="desire-internal-pilot",
            redirect_uri="https://app.example.test/v1/auth/oidc/callback",
            return_to="/join",
            security_policy_version="iam-security-v1",
            audit_event_id=uuid4(),
            system_actor_id=uuid4(),
            correlation_id=uuid4(),
            trace_id=uuid4(),
        )
        begun = self.uow.begin(request)
        exchange_owner_id = uuid4()
        self.uow.claim_exchange(
            OidcPostgresExchangeClaim(
                auth_transaction_id=request.auth_transaction_id,
                exchange_owner_id=exchange_owner_id,
                invitation_id=invitation_id,
            )
        )
        return request, exchange_owner_id, begun

    def _enrollment_finalize(
        self,
        *,
        begin_request,
        exchange_owner_id,
        contact_binding_digest,
    ):
        return OidcPostgresEnrollmentFinalize(
            auth_transaction_id=begin_request.auth_transaction_id,
            exchange_owner_id=exchange_owner_id,
            invitation_id=begin_request.invitation_id,
            invitation_version=1,
            expected_contact_point_id=begin_request.expected_contact_point_id,
            expected_contact_type="EMAIL",
            expected_contact_binding_digest=contact_binding_digest,
            expected_contact_binding_key_id="contact-v1",
            provider_issuer="https://id.example.test",
            subject_digest=hashlib.sha256(b"new-invited-subject").digest(),
            subject_digest_key_id="oidc-subject-v1",
            verified_contact_type="EMAIL",
            verified_contact_binding_digest=contact_binding_digest,
            verified_contact_binding_key_id="contact-v1",
            new_user_id=uuid4(),
            new_external_identity_id=uuid4(),
            new_session_family_id=uuid4(),
            new_session_id=uuid4(),
            handle_digest=hashlib.sha256(uuid4().bytes).digest(),
            handle_digest_key_id="session-handle-v1",
            csrf_salt=hashlib.sha256(uuid4().bytes).digest(),
            csrf_key_id="session-csrf-v1",
            csrf_digest=hashlib.sha256(uuid4().bytes).digest(),
            auth_time=self.now - timedelta(minutes=1),
            token_issued_at=self.now - timedelta(seconds=30),
            token_expires_at=self.now + timedelta(minutes=5),
            acr_code="urn:desire:acr:mfa",
            amr_codes=("otp",),
            audit_event_id=uuid4(),
            system_actor_id=uuid4(),
            correlation_id=uuid4(),
            trace_id=uuid4(),
        )

    def _assert_enrollment_recovery_facts(
        self,
        *,
        invitation_id,
        contact_id,
        first_finalize,
        recovery_finalize,
    ) -> None:
        subject_digest = hashlib.sha256(b"new-invited-subject").digest()
        with self._admin() as connection:
            facts = connection.execute(
                "SELECT "
                "(SELECT count(*) FROM iam.users WHERE id IN (%s,%s)),"
                "EXISTS (SELECT 1 FROM iam.users WHERE id=%s),"
                "(SELECT count(*) FROM iam.external_identities "
                " WHERE issuer='https://id.example.test' AND subject_digest=%s),"
                "(SELECT count(*) FROM iam.sessions "
                " WHERE verified_for_invitation_id=%s AND user_id=%s "
                " AND status='ACTIVE' AND rotation_reason='ENROLLMENT'),"
                "(SELECT count(DISTINCT family_id) FROM iam.sessions "
                " WHERE verified_for_invitation_id=%s AND user_id=%s),"
                "(SELECT count(*) FROM iam.auth_transactions "
                " WHERE invitation_id=%s AND purpose='ENROLLMENT' "
                " AND status='SUCCEEDED'),"
                "(SELECT count(*) FROM iam.memberships WHERE user_id=%s),"
                "(SELECT count(*) FROM iam.user_role_grants WHERE user_id=%s),"
                "(SELECT count(*) FROM iam.membership_role_grants WHERE user_id=%s),"
                "contact.user_id,contact.verified_at IS NOT NULL,"
                "invitation.status,invitation.aggregate_version "
                "FROM iam.contact_points AS contact "
                "JOIN iam.access_invitations AS invitation "
                "ON invitation.recipient_contact_id=contact.id "
                "WHERE contact.id=%s AND invitation.id=%s",
                (
                    first_finalize.new_user_id,
                    recovery_finalize.new_user_id,
                    recovery_finalize.new_user_id,
                    subject_digest,
                    invitation_id,
                    first_finalize.new_user_id,
                    invitation_id,
                    first_finalize.new_user_id,
                    invitation_id,
                    first_finalize.new_user_id,
                    first_finalize.new_user_id,
                    first_finalize.new_user_id,
                    contact_id,
                    invitation_id,
                ),
            ).fetchone()
        self.assertEqual(
            facts,
            (
                1,
                False,
                1,
                2,
                2,
                2,
                0,
                0,
                0,
                first_finalize.new_user_id,
                True,
                "ISSUED",
                1,
            ),
        )

    @staticmethod
    def _lookup(begin):
        return OidcPostgresCallbackLookup(
            state_digest=begin.state_digest,
            state_digest_key_id=begin.state_digest_key_id,
            browser_binding_digest=begin.browser_binding_digest,
            browser_binding_key_id=begin.browser_binding_key_id,
        )

    def test_existing_identity_login_survives_restart_and_replay_is_closed(self) -> None:
        begin_request = self._begin_request()
        begun = self.uow.begin(begin_request)
        self.assertEqual(begun.status.value, "PENDING")
        self.assertEqual(begun.aggregate_version, 1)

        restarted = PsycopgOidcAuthenticationUnitOfWork(
            connections=self.connections
        )
        found = restarted.read_callback(self._lookup(begin_request))
        self.assertEqual(found.auth_transaction_id, begin_request.auth_transaction_id)
        owner_id = uuid4()
        claimed = restarted.claim_exchange(
            OidcPostgresExchangeClaim(
                auth_transaction_id=found.auth_transaction_id,
                exchange_owner_id=owner_id,
                invitation_id=None,
            )
        )
        self.assertEqual((claimed.status.value, claimed.attempt), ("EXCHANGING", 1))
        with self.assertRaises(IamError) as duplicate_claim:
            self.uow.claim_exchange(
                OidcPostgresExchangeClaim(
                    auth_transaction_id=found.auth_transaction_id,
                    exchange_owner_id=uuid4(),
                    invitation_id=None,
                )
            )
        self.assertEqual(duplicate_claim.exception.code, "AUTH_TRANSACTION_INVALID")

        finalize = OidcPostgresExistingLoginFinalize(
            auth_transaction_id=found.auth_transaction_id,
            exchange_owner_id=owner_id,
            provider_issuer="https://id.example.test",
            subject_digest=self.subject_digest,
            subject_digest_key_id="oidc-subject-v1",
            new_session_family_id=uuid4(),
            new_session_id=uuid4(),
            handle_digest=hashlib.sha256(b"session-handle").digest(),
            handle_digest_key_id="session-handle-v1",
            csrf_salt=hashlib.sha256(b"csrf-salt").digest(),
            csrf_key_id="session-csrf-v1",
            csrf_digest=hashlib.sha256(b"csrf-token").digest(),
            auth_time=self.now - timedelta(minutes=1),
            token_issued_at=self.now - timedelta(seconds=30),
            token_expires_at=self.now + timedelta(minutes=5),
            acr_code="urn:desire:acr:mfa",
            amr_codes=("otp",),
            audit_event_id=uuid4(),
            system_actor_id=uuid4(),
            correlation_id=uuid4(),
            trace_id=uuid4(),
        )
        result = restarted.finalize_existing_login(finalize)
        self.assertEqual(result.user_id, self.user_id)
        self.assertEqual(result.user_status, "ACTIVE")
        self.assertEqual(result.generation, 1)
        with self.assertRaises(IamError):
            self.uow.finalize_existing_login(finalize)

        with self._admin() as connection:
            facts = connection.execute(
                "SELECT t.status,t.aggregate_version,s.status,s.rotation_reason,"
                "f.status,f.current_generation,"
                "(SELECT count(*) FROM audit.audit_events "
                " WHERE target_id=t.id AND action_code='CompleteOidcAuthentication') "
                "FROM iam.auth_transactions AS t "
                "JOIN iam.sessions AS s ON s.auth_transaction_id=t.id "
                "JOIN iam.session_families AS f ON f.id=s.family_id WHERE t.id=%s",
                (found.auth_transaction_id,),
            ).fetchone()
        self.assertEqual(facts, ("SUCCEEDED", 3, "ACTIVE", "LOGIN", "ACTIVE", 1, 1))

    def test_invited_demand_owner_enrollment_creates_identity_proof_without_authority(
        self,
    ) -> None:
        organization_id, contact_id, invitation_id, contact_digest = (
            self._seed_enrollment_invitation()
        )
        begin_request, owner_id, begun = self._begin_enrollment(
            invitation_id=invitation_id,
            contact_id=contact_id,
            contact_binding_digest=contact_digest,
        )
        self.assertEqual(
            (begun.status.value, begun.purpose.value, begun.invitation_id),
            ("PENDING", "ENROLLMENT", invitation_id),
        )
        finalize = self._enrollment_finalize(
            begin_request=begin_request,
            exchange_owner_id=owner_id,
            contact_binding_digest=contact_digest,
        )

        result = self.uow.finalize_enrollment(finalize)

        self.assertEqual(
            (
                result.user_id,
                result.user_status,
                result.session_id,
                result.session_family_id,
                result.generation,
            ),
            (
                finalize.new_user_id,
                "PENDING_ENROLLMENT",
                finalize.new_session_id,
                finalize.new_session_family_id,
                1,
            ),
        )
        with self._admin() as connection:
            facts = connection.execute(
                "SELECT u.status,e.status,c.user_id,c.verified_at IS NOT NULL,"
                "t.status,t.aggregate_version,s.status,s.rotation_reason,"
                "s.verified_for_invitation_id,f.status,f.current_generation,"
                "i.status,i.aggregate_version,"
                "(SELECT count(*) FROM iam.memberships WHERE user_id=u.id),"
                "(SELECT count(*) FROM iam.user_role_grants WHERE user_id=u.id),"
                "(SELECT count(*) FROM iam.membership_role_grants AS role_grant "
                " JOIN iam.memberships AS membership "
                " ON membership.id=role_grant.membership_id "
                " WHERE membership.user_id=u.id),"
                "(SELECT count(*) FROM audit.audit_events WHERE target_id=t.id "
                " AND action_code='CompleteOidcAuthentication') "
                "FROM iam.users AS u "
                "JOIN iam.external_identities AS e ON e.user_id=u.id "
                "JOIN iam.contact_points AS c ON c.user_id=u.id "
                "JOIN iam.auth_transactions AS t ON t.id=%s "
                "JOIN iam.sessions AS s ON s.auth_transaction_id=t.id "
                "JOIN iam.session_families AS f ON f.id=s.family_id "
                "JOIN iam.access_invitations AS i ON i.id=t.invitation_id "
                "WHERE u.id=%s AND i.organization_id=%s",
                (
                    begin_request.auth_transaction_id,
                    finalize.new_user_id,
                    organization_id,
                ),
            ).fetchone()
        self.assertEqual(
            facts,
            (
                "PENDING_ENROLLMENT",
                "ACTIVE",
                finalize.new_user_id,
                True,
                "SUCCEEDED",
                3,
                "ACTIVE",
                "ENROLLMENT",
                invitation_id,
                "ACTIVE",
                1,
                "ISSUED",
                1,
                0,
                0,
                0,
                1,
            ),
        )

    def test_lost_enrollment_response_recovers_same_user_with_fresh_session(
        self,
    ) -> None:
        _organization_id, contact_id, invitation_id, contact_digest = (
            self._seed_enrollment_invitation()
        )
        first_begin, first_owner, _first_begun = self._begin_enrollment(
            invitation_id=invitation_id,
            contact_id=contact_id,
            contact_binding_digest=contact_digest,
        )
        first_finalize = self._enrollment_finalize(
            begin_request=first_begin,
            exchange_owner_id=first_owner,
            contact_binding_digest=contact_digest,
        )
        discarded_result = self.uow.finalize_enrollment(first_finalize)
        self.assertEqual(discarded_result.user_id, first_finalize.new_user_id)

        recovery_begin, recovery_owner, _recovery_begun = self._begin_enrollment(
            invitation_id=invitation_id,
            contact_id=contact_id,
            contact_binding_digest=contact_digest,
        )
        recovery_finalize = self._enrollment_finalize(
            begin_request=recovery_begin,
            exchange_owner_id=recovery_owner,
            contact_binding_digest=contact_digest,
        )
        recovered = self.uow.finalize_enrollment(recovery_finalize)

        self.assertEqual(
            (
                recovered.user_id,
                recovered.user_status,
                recovered.session_id,
                recovered.session_family_id,
            ),
            (
                first_finalize.new_user_id,
                "PENDING_ENROLLMENT",
                recovery_finalize.new_session_id,
                recovery_finalize.new_session_family_id,
            ),
        )
        self.assertNotEqual(recovered.user_id, recovery_finalize.new_user_id)
        self._assert_enrollment_recovery_facts(
            invitation_id=invitation_id,
            contact_id=contact_id,
            first_finalize=first_finalize,
            recovery_finalize=recovery_finalize,
        )

    def test_lost_enrollment_commit_ack_recovers_without_duplicate_identity(
        self,
    ) -> None:
        _organization_id, contact_id, invitation_id, contact_digest = (
            self._seed_enrollment_invitation()
        )
        first_begin, first_owner, _first_begun = self._begin_enrollment(
            invitation_id=invitation_id,
            contact_id=contact_id,
            contact_binding_digest=contact_digest,
        )
        first_finalize = self._enrollment_finalize(
            begin_request=first_begin,
            exchange_owner_id=first_owner,
            contact_binding_digest=contact_digest,
        )
        ambiguous = PsycopgOidcAuthenticationUnitOfWork(
            connections=_CommitAcknowledgementLostConnections(
                self.postgres.conninfo(
                    database=self.database,
                    user="iam_onboarding",
                )
            )
        )
        with self.assertRaises(IamError) as unknown:
            ambiguous.finalize_enrollment(first_finalize)
        self.assertEqual(unknown.exception.code, "COMMAND_OUTCOME_UNKNOWN")

        recovery_begin, recovery_owner, _recovery_begun = self._begin_enrollment(
            invitation_id=invitation_id,
            contact_id=contact_id,
            contact_binding_digest=contact_digest,
        )
        recovery_finalize = self._enrollment_finalize(
            begin_request=recovery_begin,
            exchange_owner_id=recovery_owner,
            contact_binding_digest=contact_digest,
        )
        recovered = self.uow.finalize_enrollment(recovery_finalize)

        self.assertEqual(recovered.user_id, first_finalize.new_user_id)
        self.assertNotEqual(recovered.user_id, recovery_finalize.new_user_id)
        self._assert_enrollment_recovery_facts(
            invitation_id=invitation_id,
            contact_id=contact_id,
            first_finalize=first_finalize,
            recovery_finalize=recovery_finalize,
        )

    def test_anonymous_org_admin_enrollment_is_rejected_without_partial_writes(
        self,
    ) -> None:
        _organization_id, contact_id, invitation_id, contact_digest = (
            self._seed_enrollment_invitation(target_role="ORG_ADMIN")
        )
        begin_request, owner_id, _begun = self._begin_enrollment(
            invitation_id=invitation_id,
            contact_id=contact_id,
            contact_binding_digest=contact_digest,
        )
        finalize = self._enrollment_finalize(
            begin_request=begin_request,
            exchange_owner_id=owner_id,
            contact_binding_digest=contact_digest,
        )

        rejected = self.uow.finalize_enrollment(finalize)

        self.assertIsInstance(rejected, OidcPostgresAuthenticationRejected)
        with self._admin() as connection:
            facts = connection.execute(
                "SELECT t.status,t.provider_error_class,t.aggregate_version,"
                "c.user_id,c.verified_at,"
                "(SELECT count(*) FROM iam.users WHERE id=%s),"
                "(SELECT count(*) FROM iam.external_identities WHERE id=%s),"
                "(SELECT count(*) FROM iam.sessions WHERE auth_transaction_id=t.id),"
                "(SELECT count(*) FROM audit.audit_events WHERE target_id=t.id "
                " AND action_code='CompleteOidcAuthentication') "
                "FROM iam.auth_transactions AS t "
                "JOIN iam.contact_points AS c ON c.id=%s WHERE t.id=%s",
                (
                    finalize.new_user_id,
                    finalize.new_external_identity_id,
                    contact_id,
                    begin_request.auth_transaction_id,
                ),
            ).fetchone()
        self.assertEqual(
            facts,
            ("FAILED", "REJECTED", 3, None, None, 0, 0, 0, 1),
        )

    def test_wrong_browser_unknown_subject_and_direct_scans_fail_closed(self) -> None:
        begin_request = self._begin_request()
        begun = self.uow.begin(begin_request)
        wrong = OidcPostgresCallbackLookup(
            state_digest=begin_request.state_digest,
            state_digest_key_id=begin_request.state_digest_key_id,
            browser_binding_digest=hashlib.sha256(b"wrong-browser").digest(),
            browser_binding_key_id=begin_request.browser_binding_key_id,
        )
        with self.assertRaises(IamError) as wrong_binding:
            self.uow.read_callback(wrong)
        self.assertEqual(wrong_binding.exception.code, "AUTH_TRANSACTION_INVALID")
        owner_id = uuid4()
        self.uow.claim_exchange(
            OidcPostgresExchangeClaim(
                auth_transaction_id=begun.auth_transaction_id,
                exchange_owner_id=owner_id,
                invitation_id=None,
            )
        )
        unknown = OidcPostgresExistingLoginFinalize(
            auth_transaction_id=begun.auth_transaction_id,
            exchange_owner_id=owner_id,
            provider_issuer="https://id.example.test",
            subject_digest=hashlib.sha256(b"unknown-subject").digest(),
            subject_digest_key_id="oidc-subject-v1",
            new_session_family_id=uuid4(),
            new_session_id=uuid4(),
            handle_digest=hashlib.sha256(b"other-session").digest(),
            handle_digest_key_id="session-handle-v1",
            csrf_salt=hashlib.sha256(b"other-salt").digest(),
            csrf_key_id="session-csrf-v1",
            csrf_digest=hashlib.sha256(b"other-csrf").digest(),
            auth_time=self.now,
            token_issued_at=self.now - timedelta(seconds=30),
            token_expires_at=self.now + timedelta(minutes=5),
            acr_code="urn:desire:acr:mfa",
            amr_codes=("otp",),
            audit_event_id=uuid4(),
            system_actor_id=uuid4(),
            correlation_id=uuid4(),
            trace_id=uuid4(),
        )
        rejected = self.uow.finalize_existing_login(unknown)
        self.assertIsInstance(rejected, OidcPostgresAuthenticationRejected)
        self.assertEqual(rejected.reason_code, "AUTHENTICATION_REJECTED")
        with self._admin() as connection:
            rejected_facts = connection.execute(
                "SELECT status,provider_error_class,aggregate_version,"
                "(SELECT count(*) FROM audit.audit_events "
                "WHERE target_id=auth_transactions.id "
                "AND action_code='CompleteOidcAuthentication') "
                "FROM iam.auth_transactions WHERE id=%s",
                (begun.auth_transaction_id,),
            ).fetchone()
        self.assertEqual(rejected_facts, ("FAILED", "REJECTED", 3, 1))

        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="iam_onboarding"),
            autocommit=False,
        ) as connection:
            self.assertEqual(
                connection.execute("SELECT count(*) FROM iam.auth_transactions").fetchone(),
                (0,),
            )
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="iam_app"),
            autocommit=False,
        ) as connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    "SELECT * FROM iam_api.read_oidc_callback_v2(%s,%s,%s,%s)",
                    (
                        begin_request.state_digest_key_id,
                        begin_request.state_digest,
                        begin_request.browser_binding_key_id,
                        begin_request.browser_binding_digest,
                    ),
                ).fetchall()

    def test_finalize_cannot_switch_the_issuer_frozen_at_begin(self) -> None:
        alternate_digest = hashlib.sha256(b"alternate-issuer-subject").digest()
        alternate_user_id = uuid4()
        with self._admin(autocommit=False) as connection:
            connection.execute(
                "INSERT INTO iam.users (id,status,display_handle,aggregate_version,"
                "created_at,updated_at) VALUES ("
                "%s,'ACTIVE','alternate_oidc_user',1,%s,%s)",
                (alternate_user_id, self.now, self.now),
            )
            connection.execute(
                "INSERT INTO iam.external_identities ("
                "id,user_id,issuer,subject_digest,subject_digest_key_id,"
                "verified_at,status,created_at) VALUES ("
                "%s,%s,'https://other-id.example.test',%s,'oidc-subject-v1',"
                "%s,'ACTIVE',%s)",
                (
                    uuid4(),
                    alternate_user_id,
                    alternate_digest,
                    self.now,
                    self.now,
                ),
            )
        begun = self.uow.begin(self._begin_request())
        owner_id = uuid4()
        self.uow.claim_exchange(
            OidcPostgresExchangeClaim(
                auth_transaction_id=begun.auth_transaction_id,
                exchange_owner_id=owner_id,
                invitation_id=None,
            )
        )
        switched = OidcPostgresExistingLoginFinalize(
            auth_transaction_id=begun.auth_transaction_id,
            exchange_owner_id=owner_id,
            provider_issuer="https://other-id.example.test",
            subject_digest=alternate_digest,
            subject_digest_key_id="oidc-subject-v1",
            new_session_family_id=uuid4(),
            new_session_id=uuid4(),
            handle_digest=hashlib.sha256(b"issuer-switch-session").digest(),
            handle_digest_key_id="session-handle-v1",
            csrf_salt=hashlib.sha256(b"issuer-switch-salt").digest(),
            csrf_key_id="session-csrf-v1",
            csrf_digest=hashlib.sha256(b"issuer-switch-csrf").digest(),
            auth_time=self.now - timedelta(minutes=1),
            token_issued_at=self.now - timedelta(seconds=30),
            token_expires_at=self.now + timedelta(minutes=5),
            acr_code="urn:desire:acr:mfa",
            amr_codes=("otp",),
            audit_event_id=uuid4(),
            system_actor_id=uuid4(),
            correlation_id=uuid4(),
            trace_id=uuid4(),
        )
        rejected = self.uow.finalize_existing_login(switched)
        self.assertIsInstance(rejected, OidcPostgresAuthenticationRejected)
        with self._admin() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT count(*) FROM iam.sessions "
                    "WHERE auth_transaction_id=%s",
                    (begun.auth_transaction_id,),
                ).fetchone(),
                (0,),
            )

    def test_finalize_after_deadline_atomically_rejects_instead_of_stranding_exchange(self) -> None:
        begun = self.uow.begin(self._begin_request())
        owner_id = uuid4()
        self.uow.claim_exchange(
            OidcPostgresExchangeClaim(
                auth_transaction_id=begun.auth_transaction_id,
                exchange_owner_id=owner_id,
                invitation_id=None,
            )
        )
        # Advance only this fixture's immutable deadline without sleeping ten
        # minutes. Production code cannot perform this mutation.
        with self._admin(autocommit=False) as connection:
            connection.execute(
                "ALTER TABLE iam.auth_transactions DISABLE TRIGGER "
                "trg_auth_transaction_state"
            )
            connection.execute(
                "UPDATE iam.auth_transactions SET created_at=%s,deadline=%s "
                "WHERE id=%s",
                (
                    self.now - timedelta(minutes=20),
                    self.now - timedelta(minutes=10),
                    begun.auth_transaction_id,
                ),
            )
            connection.execute(
                "ALTER TABLE iam.auth_transactions ENABLE TRIGGER "
                "trg_auth_transaction_state"
            )

        rejected = self.uow.finalize_existing_login(
            OidcPostgresExistingLoginFinalize(
                auth_transaction_id=begun.auth_transaction_id,
                exchange_owner_id=owner_id,
                provider_issuer="https://id.example.test",
                subject_digest=self.subject_digest,
                subject_digest_key_id="oidc-subject-v1",
                new_session_family_id=uuid4(),
                new_session_id=uuid4(),
                handle_digest=hashlib.sha256(b"expired-session").digest(),
                handle_digest_key_id="session-handle-v1",
                csrf_salt=hashlib.sha256(b"expired-salt").digest(),
                csrf_key_id="session-csrf-v1",
                csrf_digest=hashlib.sha256(b"expired-csrf").digest(),
                auth_time=self.now - timedelta(minutes=1),
                token_issued_at=self.now - timedelta(seconds=30),
                token_expires_at=self.now + timedelta(minutes=5),
                acr_code="urn:desire:acr:mfa",
                amr_codes=("otp",),
                audit_event_id=uuid4(),
                system_actor_id=uuid4(),
                correlation_id=uuid4(),
                trace_id=uuid4(),
            )
        )
        self.assertIsInstance(rejected, OidcPostgresAuthenticationRejected)
        with self._admin() as connection:
            facts = connection.execute(
                "SELECT status,provider_error_class,aggregate_version,"
                "(SELECT count(*) FROM iam.sessions "
                "WHERE auth_transaction_id=auth_transactions.id) "
                "FROM iam.auth_transactions WHERE id=%s",
                (begun.auth_transaction_id,),
            ).fetchone()
        self.assertEqual(facts, ("FAILED", "REJECTED", 3, 0))

    def test_exchange_claim_is_single_winner_under_real_concurrency(self) -> None:
        begun = self.uow.begin(self._begin_request())
        barrier = threading.Barrier(2)

        def claim(owner_id):
            contender = PsycopgOidcAuthenticationUnitOfWork(
                connections=self.connections
            )
            barrier.wait(timeout=5)
            try:
                transaction = contender.claim_exchange(
                    OidcPostgresExchangeClaim(
                        auth_transaction_id=begun.auth_transaction_id,
                        exchange_owner_id=owner_id,
                        invitation_id=None,
                    )
                )
            except IamError as error:
                return ("ERROR", error.code)
            return ("CLAIMED", transaction.exchange_owner_id)

        owners = (uuid4(), uuid4())
        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = tuple(executor.map(claim, owners))
        self.assertEqual(
            sorted(outcome[0] for outcome in outcomes),
            ["CLAIMED", "ERROR"],
        )
        self.assertIn(("ERROR", "AUTH_TRANSACTION_INVALID"), outcomes)
        winner = next(value for status, value in outcomes if status == "CLAIMED")
        self.assertIn(winner, owners)

    def test_exchange_result_unknown_is_terminal_and_restart_safe(self) -> None:
        begun = self.uow.begin(self._begin_request())
        owner_id = uuid4()
        self.uow.claim_exchange(
            OidcPostgresExchangeClaim(
                auth_transaction_id=begun.auth_transaction_id,
                exchange_owner_id=owner_id,
                invitation_id=None,
            )
        )
        terminal = OidcPostgresExchangeTerminal(
            auth_transaction_id=begun.auth_transaction_id,
            exchange_owner_id=owner_id,
            invitation_id=None,
            outcome=OidcPostgresTerminalOutcome.RESULT_UNKNOWN,
            audit_event_id=uuid4(),
            system_actor_id=uuid4(),
            correlation_id=uuid4(),
            trace_id=uuid4(),
        )
        restarted = PsycopgOidcAuthenticationUnitOfWork(
            connections=self.connections
        )
        restarted.finish_exchange(terminal)
        with self.assertRaises(IamError) as replay:
            self.uow.finish_exchange(terminal)
        self.assertEqual(replay.exception.code, "AUTH_TRANSACTION_INVALID")
        with self._admin() as connection:
            facts = connection.execute(
                "SELECT status,provider_error_class,aggregate_version,"
                "(SELECT count(*) FROM audit.audit_events "
                "WHERE target_id=auth_transactions.id "
                "AND action_code='CompleteOidcAuthentication') "
                "FROM iam.auth_transactions WHERE id=%s",
                (begun.auth_transaction_id,),
            ).fetchone()
        self.assertEqual(facts, ("RESULT_UNKNOWN", "RESULT_UNKNOWN", 3, 1))

    def test_lost_commit_acknowledgement_is_reported_unknown_not_failed(self) -> None:
        begin_request = self._begin_request()
        ambiguous = PsycopgOidcAuthenticationUnitOfWork(
            connections=_CommitAcknowledgementLostConnections(
                self.postgres.conninfo(
                    database=self.database,
                    user="iam_onboarding",
                )
            )
        )
        with self.assertRaises(IamError) as outcome:
            ambiguous.begin(begin_request)
        self.assertEqual(outcome.exception.code, "COMMAND_OUTCOME_UNKNOWN")
        with self._admin() as connection:
            durable = connection.execute(
                "SELECT status,aggregate_version FROM iam.auth_transactions "
                "WHERE id=%s",
                (begin_request.auth_transaction_id,),
            ).fetchone()
        self.assertEqual(durable, ("PENDING", 1))

    def test_presenter_ready_bundle_establishes_real_pg_session_after_restart(self) -> None:
        provider = _BundleProvider(subject_digest=self.subject_digest, now=self.now)
        keyring = _BundleKeyring()
        secret_box = _BundleSecretBox()
        policy = OidcSecurityPolicy(
            policy_version="iam-security-v1",
            provider_issuer="https://id.example.test",
            provider_audience="desire-internal-pilot",
            redirect_uri="https://app.example.test/v1/auth/oidc/callback",
            allowed_return_to=("/app",),
        )
        begin_bundle = build_postgres_iam_authentication_bundle(
            oidc_uow=self.uow,
            provider=provider,
            protocol_keyring=keyring,
            protocol_secret_box=secret_box,
            session_keyring=keyring,
            clock=_BundleClock(self.now),
            id_source=_BundleIds(),
            secret_source=_BundleSecrets(),
            system_actor_id=uuid4(),
            security_policy=policy,
        )
        begun = begin_bundle.begin_oidc_authorization.handle(
            context=OidcBrowserContext(trace_id="bundle-begin"),
            command=BeginOidcAuthorizationCommand(return_to="/app"),
        )

        restarted_bundle = build_postgres_iam_authentication_bundle(
            oidc_uow=PsycopgOidcAuthenticationUnitOfWork(
                connections=self.connections
            ),
            provider=provider,
            protocol_keyring=keyring,
            protocol_secret_box=secret_box,
            session_keyring=keyring,
            clock=_BundleClock(self.now),
            id_source=_BundleIds(),
            secret_source=_BundleSecrets(),
            system_actor_id=uuid4(),
            security_policy=policy,
        )
        completed = restarted_bundle.complete_oidc_authorization.handle(
            context=OidcBrowserContext(
                raw_oidc_browser_cookie=begun.oidc_browser_cookie,
                trace_id="bundle-complete",
            ),
            command=CompleteOidcAuthenticationCommand(
                state=provider.begin_facts["state"],
                code="one-time-provider-code",
            ),
        )
        self.assertEqual(completed.user_id, str(self.user_id))
        self.assertEqual(completed.user_status, "ACTIVE")
        self.assertEqual(provider.exchange_calls, 1)
        with self._admin() as connection:
            facts = connection.execute(
                "SELECT t.status,s.status,f.status "
                "FROM iam.auth_transactions AS t "
                "JOIN iam.sessions AS s ON s.auth_transaction_id=t.id "
                "JOIN iam.session_families AS f ON f.id=s.family_id "
                "WHERE t.id=%s",
                (UUID(begun.auth_transaction_id),),
            ).fetchone()
        self.assertEqual(facts, ("SUCCEEDED", "ACTIVE", "ACTIVE"))

    def test_presenter_bundle_unknown_identity_is_atomically_rejected_after_one_exchange(self) -> None:
        provider = _BundleProvider(
            subject_digest=hashlib.sha256(b"unknown-provider-subject").digest(),
            now=self.now,
        )
        keyring = _BundleKeyring()
        secret_box = _BundleSecretBox()
        policy = OidcSecurityPolicy(
            policy_version="iam-security-v1",
            provider_issuer="https://id.example.test",
            provider_audience="desire-internal-pilot",
            redirect_uri="https://app.example.test/v1/auth/oidc/callback",
            allowed_return_to=("/app",),
        )
        bundle = build_postgres_iam_authentication_bundle(
            oidc_uow=self.uow,
            provider=provider,
            protocol_keyring=keyring,
            protocol_secret_box=secret_box,
            session_keyring=keyring,
            clock=_BundleClock(self.now),
            id_source=_BundleIds(),
            secret_source=_BundleSecrets(),
            system_actor_id=uuid4(),
            security_policy=policy,
        )
        begun = bundle.begin_oidc_authorization.handle(
            context=OidcBrowserContext(trace_id="unknown-begin"),
            command=BeginOidcAuthorizationCommand(return_to="/app"),
        )
        with self.assertRaises(IamError) as rejected:
            bundle.complete_oidc_authorization.handle(
                context=OidcBrowserContext(
                    raw_oidc_browser_cookie=begun.oidc_browser_cookie,
                    trace_id="unknown-complete",
                ),
                command=CompleteOidcAuthenticationCommand(
                    state=provider.begin_facts["state"],
                    code="one-time-provider-code",
                ),
            )
        self.assertEqual(rejected.exception.code, "AUTHENTICATION_REJECTED")
        self.assertEqual(provider.exchange_calls, 1)
        with self._admin() as connection:
            facts = connection.execute(
                "SELECT status,provider_error_class,aggregate_version,"
                "(SELECT count(*) FROM iam.sessions "
                "WHERE auth_transaction_id=auth_transactions.id),"
                "(SELECT count(*) FROM audit.audit_events "
                "WHERE target_id=auth_transactions.id "
                "AND action_code='CompleteOidcAuthentication') "
                "FROM iam.auth_transactions WHERE id=%s",
                (UUID(begun.auth_transaction_id),),
            ).fetchone()
        self.assertEqual(facts, ("FAILED", "REJECTED", 3, 0, 1))


if __name__ == "__main__":
    unittest.main()
