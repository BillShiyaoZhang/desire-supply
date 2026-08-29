"""Real PG18 contract joining reviewed OIDC preprovisioning to LOGIN.

The evidence deliberately crosses the deployment and online boundaries: the
reviewed-identity generator emits the digest-only manifest, the deployment
bootstrap applies it through its production database program, and the normal
PostgreSQL OIDC authentication bundle consumes claims from ClosedOidcProvider.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import secrets
import unittest
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid4

import psycopg

from desire_platform.deployment.identity_bootstrap import (
    IdentityBootstrapOutcome,
    apply_internal_sandbox_identity_bootstrap,
    parse_internal_sandbox_identity_manifest,
)
from desire_platform.deployment.migrations import DeploymentMigrationSettings
from desire_platform.deployment.preprovisioned_identity_bootstrap_manifest import (
    generate_preprovisioned_identity_bootstrap_manifest,
)
from desire_platform.identity_access.adapters.oidc import (
    ClosedOidcProvider,
    OidcProviderConfiguration,
)
from desire_platform.identity_access.adapters.postgres.migrations import (
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from desire_platform.identity_access.adapters.postgres.oidc_authentication import (
    PsycopgOidcAuthenticationUnitOfWork,
)
from desire_platform.identity_access.adapters.postgres.oidc_bundle import (
    build_postgres_iam_authentication_bundle,
)
from desire_platform.identity_access.application.authentication import (
    BeginOidcAuthorizationCommand,
    CompleteOidcAuthenticationCommand,
    OidcBrowserContext,
    OidcSecurityPolicy,
)
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.internal_pilot.runtime_crypto import (
    AesGcmProtocolSecretBox,
    HmacRecipientBinding,
    HmacRuntimeKeyring,
    RuntimeKeyMaterial,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
IAM_MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
TEMPLATE_PATH = (
    PLATFORM_ROOT
    / "examples/internal-sandbox-identity-bootstrap-template-v1.json"
)
ISSUER = "https://identity.example.test/tenant"
AUDIENCE = "desire-internal-pilot"
REDIRECT_URI = "https://pilot.example.test/v1/auth/oidc/callback"
SUBJECT_KEY_ID = "oidc-subject-digest-v1"
RECIPIENT_KEY_ID = "oidc-recipient-binding-v1"
SUBJECT_KEY = b"reviewed-subject-contract-key-v1"
RECIPIENT_KEY = b"reviewed-recipient-contract-key-v1"
SYSTEM_ACTOR_ID = UUID("11111111-1111-4111-8111-111111111111")


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


class _Clock:
    def __init__(self, now: datetime) -> None:
        self._now = now

    def now(self) -> datetime:
        return self._now


class _Ids:
    @staticmethod
    def new_id(_kind: str) -> UUID:
        return uuid4()


class _Secrets:
    @staticmethod
    def token_bytes(_purpose: str, length: int) -> bytes:
        return secrets.token_bytes(length)


class _OidcTransport:
    def __init__(self) -> None:
        self.token_exchange_count = 0

    @staticmethod
    def get_json(*, url: str, **_bounds):
        if url == ISSUER + "/.well-known/openid-configuration":
            return {
                "issuer": ISSUER,
                "authorization_endpoint": ISSUER + "/authorize",
                "token_endpoint": ISSUER + "/token",
                "jwks_uri": ISSUER + "/jwks",
                "code_challenge_methods_supported": ["S256"],
                "id_token_signing_alg_values_supported": ["RS256"],
            }
        if url == ISSUER + "/jwks":
            return {"keys": [{"kty": "RSA", "kid": "contract-key"}]}
        raise AssertionError("unexpected OIDC endpoint")

    def post_form_json(self, **_request):
        self.token_exchange_count += 1
        return {"token_type": "Bearer", "id_token": "header.payload.signature"}


class _ClaimsVerifier:
    def __init__(self, *, subject: str, email: str) -> None:
        self._subject = subject
        self._email = email

    def verify_id_token(self, **facts):
        now = facts["server_now"]
        return {
            "iss": facts["expected_issuer"],
            "sub": self._subject,
            "aud": facts["expected_audience"],
            "nonce": facts["expected_nonce"],
            "iat": int((now - timedelta(seconds=30)).timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
            "auth_time": int((now - timedelta(minutes=1)).timestamp()),
            "acr": "urn:desire:acr:mfa",
            "amr": ["pwd", "otp"],
            "email": self._email,
            "email_verified": True,
        }

    def __repr__(self) -> str:
        return "_ClaimsVerifier(identity=<redacted>)"


class PreprovisionedOidcLoginPostgresContractTest(unittest.TestCase):
    """A reviewed real-provider binding is LOGIN-only and default-deny."""

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
        IamMigrationRunner(
            driver=PsycopgMigrationDriver(
                settings=PsycopgMigrationSettings(
                    conninfo=self.postgres.conninfo(
                        database=self.database,
                        user="iam_migration_runner",
                    ),
                    application_name="preprovisioned-oidc-login-contract",
                ),
                dbapi=psycopg,
            ),
            runner_version="preprovisioned-oidc-login-contract/1",
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
        with self._admin() as connection:
            for role in (
                "iam_migration_runner",
                "profile_migration_runner",
                "demand_migration_runner",
                "trust_migration_runner",
                "taxonomy_migration_runner",
            ):
                connection.execute("ALTER ROLE " + role + " PASSWORD NULL")

        self.now = datetime.now(timezone.utc)
        self.settings = DeploymentMigrationSettings(
            host=self.postgres.host,
            port=self.postgres.port,
            database=self.database,
            admin_user=self.postgres.admin_user,
            admin_password=self.postgres.admin_password,
        )
        self.connections = _Connections(
            self.postgres.conninfo(
                database=self.database,
                user="iam_onboarding",
            )
        )

    def tearDown(self) -> None:
        self.postgres.drop_database(self.database)

    def _admin(self):
        return psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=True,
        )

    def _generate_manifest(self):
        template_bytes = TEMPLATE_PATH.read_bytes()
        template = json.loads(template_bytes.decode("ascii"))
        source_buffers = {}
        reviewed_identities = {}
        for account in template["accounts"]:
            code = account["account_code"]
            subject = "provider|reviewed-tenant|" + code
            email = "Reviewed+" + code + "@Example.INVALID"
            subject_file = account["external_identity"]["subject_file_name"]
            email_file = account["contact_point"]["verified_email_file_name"]
            source_buffers[subject_file] = bytearray(subject.encode("utf-8"))
            source_buffers[email_file] = bytearray(email.encode("utf-8"))
            reviewed_identities[code] = (subject, email)

        generated = generate_preprovisioned_identity_bootstrap_manifest(
            template_bytes=template_bytes,
            expected_template_sha256=hashlib.sha256(template_bytes).hexdigest(),
            issuer=ISSUER,
            subject_digest_key_id=SUBJECT_KEY_ID,
            subject_digest_key=bytearray(SUBJECT_KEY),
            recipient_binding_key_id=RECIPIENT_KEY_ID,
            recipient_binding_key=bytearray(RECIPIENT_KEY),
            read_source=lambda name: source_buffers[name],
        )
        self.assertTrue(all(not any(value) for value in source_buffers.values()))
        self.assertTrue(
            all(
                raw.encode("utf-8") not in generated.canonical_bytes
                for pair in reviewed_identities.values()
                for raw in pair
            )
        )
        manifest = parse_internal_sandbox_identity_manifest(
            generated.canonical_bytes,
            expected_sha256=generated.manifest_sha256,
            expected_issuer=ISSUER,
        )
        return manifest, reviewed_identities

    @staticmethod
    def _runtime_keyring() -> HmacRuntimeKeyring:
        identifiers = {
            "OIDC_STATE": "oidc-state-v1",
            "OIDC_BROWSER_BINDING": "oidc-browser-v1",
            "OIDC_NONCE": "oidc-nonce-v1",
            "SESSION_HANDLE": "session-handle-v1",
            "CSRF": "session-csrf-v1",
        }
        keys = tuple(
            RuntimeKeyMaterial(
                purpose=purpose,
                key_id=key_id,
                material=bytearray(
                    hashlib.sha256(
                        ("preprovisioned-login:" + purpose).encode("ascii")
                    ).digest()
                ),
            )
            for purpose, key_id in identifiers.items()
        )
        return HmacRuntimeKeyring(
            keys=keys,
            active_key_ids=identifiers,
            retained_key_ids={
                purpose: (key_id,) for purpose, key_id in identifiers.items()
            },
        )

    def _complete_login(self, *, subject: str, email: str):
        transport = _OidcTransport()
        self._last_oidc_transport = transport
        provider = ClosedOidcProvider(
            configuration=OidcProviderConfiguration(
                issuer=ISSUER,
                client_id=AUDIENCE,
                client_secret=bytearray(b"reviewed-client-secret-material-v1"),
                redirect_uri=REDIRECT_URI,
                allowed_signing_algorithms=("RS256",),
                metadata_ttl_seconds=300,
                request_timeout_seconds=3,
                maximum_response_bytes=262_144,
                clock_skew_seconds=30,
                subject_digest_key_id=SUBJECT_KEY_ID,
            ),
            transport=transport,
            token_verifier=_ClaimsVerifier(subject=subject, email=email),
            recipient_binding=HmacRecipientBinding(
                key=RuntimeKeyMaterial(
                    purpose="OIDC_RECIPIENT_BINDING",
                    key_id=RECIPIENT_KEY_ID,
                    material=bytearray(RECIPIENT_KEY),
                )
            ),
            subject_digest_key=bytearray(SUBJECT_KEY),
        )
        keyring = self._runtime_keyring()
        secret_box = AesGcmProtocolSecretBox(
            keys=(
                RuntimeKeyMaterial(
                    purpose="OIDC_PROTOCOL_AEAD",
                    key_id="oidc-protocol-aead-v1",
                    material=bytearray(
                        hashlib.sha256(b"preprovisioned-login:aead").digest()
                    ),
                ),
            ),
            active_key_id="oidc-protocol-aead-v1",
        )
        bundle = build_postgres_iam_authentication_bundle(
            oidc_uow=PsycopgOidcAuthenticationUnitOfWork(
                connections=self.connections
            ),
            provider=provider,
            protocol_keyring=keyring,
            protocol_secret_box=secret_box,
            session_keyring=keyring,
            clock=_Clock(self.now),
            id_source=_Ids(),
            secret_source=_Secrets(),
            system_actor_id=SYSTEM_ACTOR_ID,
            security_policy=OidcSecurityPolicy(
                policy_version="iam-security-v1",
                provider_issuer=ISSUER,
                provider_audience=AUDIENCE,
                redirect_uri=REDIRECT_URI,
                allowed_return_to=("/app",),
            ),
        )
        begun = bundle.begin_oidc_authorization.handle(
            context=OidcBrowserContext(trace_id="preprovisioned-login-begin"),
            command=BeginOidcAuthorizationCommand(return_to="/app"),
        )
        state_values = parse_qs(
            urlsplit(begun.authorization_url).query,
            strict_parsing=True,
        ).get("state", [])
        self.assertEqual(len(state_values), 1)
        completed = bundle.complete_oidc_authorization.handle(
            context=OidcBrowserContext(
                raw_oidc_browser_cookie=begun.oidc_browser_cookie,
                trace_id="preprovisioned-login-complete",
            ),
            command=CompleteOidcAuthenticationCommand(
                state=state_values[0],
                code="reviewed-one-time-provider-code",
            ),
        )
        self.assertEqual(transport.token_exchange_count, 1)
        return begun, completed

    def _authority_counts(self):
        with self._admin() as connection:
            return connection.execute(
                "SELECT (SELECT count(*) FROM iam.users),"
                "(SELECT count(*) FROM iam.external_identities),"
                "(SELECT count(*) FROM iam.sessions),"
                "(SELECT count(*) FROM iam.contact_points),"
                "(SELECT count(*) FROM iam.access_invitations),"
                "(SELECT count(*) FROM iam.auth_transactions "
                " WHERE purpose='ENROLLMENT')"
            ).fetchone()

    def test_preprovisioned_identity_logs_in_and_unknown_subject_cannot_signup(
        self,
    ) -> None:
        manifest, identities = self._generate_manifest()
        report = apply_internal_sandbox_identity_bootstrap(
            settings=self.settings,
            manifest=manifest,
            system_actor_id=SYSTEM_ACTOR_ID,
            now=self.now,
            password_factory=lambda: "preprovisioned-bootstrap-password-material-v1",
        )
        self.assertEqual(report.outcome, IdentityBootstrapOutcome.APPLIED)

        account = next(
            value
            for value in manifest.accounts
            if value.account_code == "access_admin_01"
        )
        known_subject, known_email = identities[account.account_code]
        _known_begin, completed = self._complete_login(
            subject=known_subject,
            email=known_email,
        )
        self.assertEqual(completed.user_id, str(account.user_id))
        self.assertEqual(completed.user_status, "ACTIVE")
        before_unknown = self._authority_counts()
        self.assertEqual(before_unknown[:3], (10, 10, 1))
        self.assertEqual(before_unknown[5], 0)

        unknown_subject = "provider|unreviewed-tenant|" + uuid4().hex
        unknown_email = uuid4().hex + "@Example.INVALID"
        with self.assertRaises(IamError) as rejected:
            self._complete_login(
                subject=unknown_subject,
                email=unknown_email,
            )
        self.assertEqual(rejected.exception.code, "AUTHENTICATION_REJECTED")
        self.assertEqual(self._last_oidc_transport.token_exchange_count, 1)
        self.assertEqual(self._authority_counts(), before_unknown)

        with self._admin() as connection:
            unknown_transaction = connection.execute(
                "SELECT purpose,status,provider_error_class,"
                "(SELECT count(*) FROM iam.sessions "
                " WHERE auth_transaction_id=auth_transactions.id) "
                "FROM iam.auth_transactions "
                "WHERE status='FAILED' "
                "ORDER BY created_at DESC,id DESC LIMIT 1"
            ).fetchone()
        self.assertEqual(
            unknown_transaction,
            ("LOGIN", "FAILED", "REJECTED", 0),
        )


if __name__ == "__main__":
    unittest.main()
