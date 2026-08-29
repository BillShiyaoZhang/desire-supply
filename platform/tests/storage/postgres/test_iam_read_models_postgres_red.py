"""TEST-DB-IAM-READ-001 semantic RED on real PostgreSQL 18.

The current canonical migration catalog and every synthetic fixture must be
valid before the production repository is called.  Only the exact reviewed
default-deny sentinel is translated into an assertion observation; migration,
fixture, psycopg, SQL, and programming failures remain test errors.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple
import unittest
import uuid

import psycopg
from psycopg import sql

from desire_platform.identity_access.adapters.postgres.migrations import (
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from desire_platform.identity_access.adapters.postgres.read_models import (
    POSTGRES_READ_MODEL_BEHAVIOR_NOT_AVAILABLE,
    PostgresReadModelBehaviorNotAvailable,
    PsycopgIamReadModelRepository,
    READ_STATEMENT_PROFILES,
)
from desire_platform.identity_access.application.read_models import (
    GetPolicyBundleHandler,
    GetPolicyBundleQuery,
    InspectAccessInvitationHandler,
    InspectAccessInvitationQuery,
)
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.ports.access_invitation_capability import (
    VerifiedAccessInvitationCapability,
)
from desire_platform.identity_access.ports.read_models import (
    ReadModelSnapshot,
    ReadPageWindow,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)

RAW_SESSION_HANDLE_SENTINEL = "READ-RAW-SESSION-DO-NOT-PERSIST-8d3b"
RAW_INVITATION_TOKEN_SENTINEL = "READ-RAW-INVITATION-DO-NOT-PERSIST-04a1"
RAW_CURSOR_SENTINEL = "READ-RAW-CURSOR-DO-NOT-PERSIST-a0ef"
RAW_CONTACT_SENTINEL = "read-secret-contact@example.invalid"
RAW_SUBJECT_SENTINEL = "READ-RAW-SUBJECT-DO-NOT-PERSIST-ef24"
RAW_CSRF_SENTINEL = "READ-RAW-CSRF-DO-NOT-PERSIST-cd19"
RAW_RECIPIENT_SENTINEL = "READ-RAW-RECIPIENT-DO-NOT-PERSIST-b19a"
RAW_POLICY_SIGNATURE_SENTINEL = "READ-RAW-SIGNATURE-DO-NOT-PERSIST-68af"
RAW_SENTINELS = (
    RAW_SESSION_HANDLE_SENTINEL,
    RAW_INVITATION_TOKEN_SENTINEL,
    RAW_CURSOR_SENTINEL,
    RAW_CONTACT_SENTINEL,
    RAW_SUBJECT_SENTINEL,
    RAW_CSRF_SENTINEL,
    RAW_RECIPIENT_SENTINEL,
    RAW_POLICY_SIGNATURE_SENTINEL,
)

PAGED_OPERATIONS = (
    "listMyConsentGrants",
    "listMySessions",
    "listOrganizationAccessInvitations",
    "listOrganizationMemberships",
)


def _new_id() -> uuid.UUID:
    return uuid.uuid4()


def _digest(label: str) -> bytes:
    return hashlib.sha256(label.encode("utf-8")).digest()


def _selector_digest(
    *, purpose: str, scope_type: str, role: str, locale: str
) -> bytes:
    canonical = json.dumps(
        {
            "access_purpose": purpose,
            "scope_type": scope_type,
            "target_role": role,
            "jurisdiction": "CN",
            "locale": locale,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).digest()


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class PolicyGraph:
    selector_digest: bytes = field(repr=False)
    bundle_id: uuid.UUID
    document_ids: Tuple[uuid.UUID, ...]
    document_hashes: Tuple[bytes, ...] = field(repr=False)
    offer_id: Optional[uuid.UUID]
    locale: str


@dataclass(frozen=True)
class ReadGraph:
    now: datetime
    actor_id: uuid.UUID
    other_user_id: uuid.UUID
    current_session_id: uuid.UUID
    old_session_id: uuid.UUID
    organization_id: uuid.UUID
    other_organization_id: uuid.UUID
    actor_membership_id: uuid.UUID
    target_membership_id: uuid.UUID
    issued_invitation_id: uuid.UUID
    actor_accepted_invitation_id: uuid.UUID
    target_accepted_invitation_id: uuid.UUID
    creator_invitation_id: uuid.UUID
    creator_policy: PolicyGraph
    organization_policy: PolicyGraph
    active_consent_id: uuid.UUID
    withdrawn_consent_id: uuid.UUID
    invitation_nonce_hex: str = field(repr=False)
    invitation_key_id: str = field(repr=False)
    invitation_format: str = field(repr=False)
    created_at_by_id: Mapping[uuid.UUID, datetime] = field(repr=False)


class FrozenClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


class ExactCapabilityVerifier:
    def __init__(
        self,
        *,
        invitation_id: uuid.UUID,
        nonce_hex: str,
        key_id: str,
        token_format: str,
        expires_at: datetime,
    ) -> None:
        self._capability = VerifiedAccessInvitationCapability(
            invitation_id=str(invitation_id),
            invitation_nonce=nonce_hex,
            token_key_id=key_id,
            token_format_version=token_format,
            expires_at=expires_at,
        )

    def verify(
        self, *, access_invitation_token: str, now: datetime
    ) -> VerifiedAccessInvitationCapability:
        if access_invitation_token != RAW_INVITATION_TOKEN_SENTINEL:
            raise ValueError("synthetic invitation token is invalid")
        if now >= self._capability.expires_at:
            raise ValueError("synthetic invitation token expired")
        return self._capability


class TrackingConnection:
    """Record SQL text without retaining bind values."""

    def __init__(self, raw: Any, trace: list[str]) -> None:
        self._raw = raw
        self._trace = trace

    def execute(self, query: Any, parameters: Any = None, *args: Any, **kwargs: Any):
        normalized = " ".join(str(query).strip().split())
        self._trace.append(normalized)
        return self._raw.execute(query, parameters, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._raw, name)


class ReusableTrackingConnectionSource:
    """One role-bound real connection, reusable only through ``release``."""

    def __init__(self, conninfo: str) -> None:
        self._conninfo = conninfo
        self._raw: Optional[Any] = None
        self._wrapped: Optional[TrackingConnection] = None
        self.trace: list[str] = []
        self.checkout_count = 0
        self.release_count = 0
        self.discard_count = 0
        self.backend_pids: list[int] = []

    def checkout(self) -> TrackingConnection:
        self.checkout_count += 1
        if self._raw is None or self._raw.closed:
            self._raw = psycopg.connect(self._conninfo, autocommit=True)
            self._wrapped = TrackingConnection(self._raw, self.trace)
        if self._wrapped is None:
            raise AssertionError("tracking connection wrapper is unavailable")
        self.backend_pids.append(self._raw.info.backend_pid)
        return self._wrapped

    def release(self, connection: Any) -> None:
        if connection is not self._wrapped:
            raise AssertionError("read repository released a foreign connection")
        self.release_count += 1

    def discard(self, connection: Any) -> None:
        if connection is not self._wrapped:
            raise AssertionError("read repository discarded a foreign connection")
        self.discard_count += 1
        if self._raw is not None:
            self._raw.close()

    def close(self) -> None:
        if self._raw is not None and not self._raw.closed:
            self._raw.close()


def _contains(value: object, expected: object) -> bool:
    if value == expected:
        return True
    if isinstance(value, Mapping):
        return any(_contains(item, expected) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains(item, expected) for item in value)
    return False


class RealPostgres18IamReadModelsRedTest(unittest.TestCase):
    """Nine IAM reads require fixed SQL, same-snapshot RLS, and pool hygiene."""

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
        cls.database = cls.postgres.create_database()
        report = IamMigrationRunner(
            driver=PsycopgMigrationDriver(
                settings=PsycopgMigrationSettings(
                    conninfo=cls.postgres.conninfo(
                        database=cls.database,
                        user="iam_migration_runner",
                    ),
                    application_name="desire-iam-read-model-pg18-red",
                ),
                dbapi=psycopg,
            ),
            runner_version="iam-read-model-pg18-red/1",
        ).run(catalog=cls.catalog, contract_sources=cls.contract_sources)
        expected_versions = tuple(
            artifact.descriptor.version for artifact in cls.catalog.artifacts
        )
        if report.applied_versions != expected_versions:
            raise AssertionError("current canonical migration catalog was not applied")
        if not expected_versions:
            raise AssertionError("read tests require a non-empty canonical catalog")
        with cls._connect_admin() as connection:
            cls.graph = cls._seed_read_graph(connection)

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            cls.postgres.drop_database(cls.database)
        finally:
            cls.postgres.stop()

    def setUp(self) -> None:
        self.app_source = ReusableTrackingConnectionSource(
            self.postgres.conninfo(database=self.database, user="iam_app")
        )
        self.onboarding_source = ReusableTrackingConnectionSource(
            self.postgres.conninfo(database=self.database, user="iam_onboarding")
        )
        self.repository = PsycopgIamReadModelRepository(
            app_connections=self.app_source,
            onboarding_connections=self.onboarding_source,
        )

    def tearDown(self) -> None:
        self.app_source.close()
        self.onboarding_source.close()

    @classmethod
    def _connect_admin(cls, *, autocommit: bool = False):
        return psycopg.connect(
            cls.postgres.admin_conninfo(database=cls.database),
            autocommit=autocommit,
        )

    def _connect_role(self, role: str, *, autocommit: bool = False):
        return psycopg.connect(
            self.postgres.conninfo(database=self.database, user=role),
            autocommit=autocommit,
        )

    @staticmethod
    def _set_context(connection: Any, values: Mapping[str, object]) -> None:
        for name, value in values.items():
            connection.execute(
                "SELECT pg_catalog.set_config(%s,%s,true)",
                ("app." + name, str(value)),
            )

    @classmethod
    def _seed_policy(
        cls,
        connection: Any,
        *,
        purpose: str,
        scope_type: str,
        role: str,
        locale: str,
        now: datetime,
        active: bool = True,
        include_offer: bool = False,
        hash_drift: bool = False,
    ) -> PolicyGraph:
        selector = _selector_digest(
            purpose=purpose,
            scope_type=scope_type,
            role=role,
            locale=locale,
        )
        bundle = _new_id()
        command = _new_id()
        suffix = uuid.uuid4().hex[:10]
        created_at = now - timedelta(days=10)
        effective_at = now - timedelta(days=9)
        primary_document = _new_id()
        primary_body = "Read model policy body " + suffix
        primary_hash = hashlib.sha256(primary_body.encode("utf-8")).digest()
        stored_primary_hash = (
            _digest("intentional-policy-hash-drift-" + suffix)
            if hash_drift
            else primary_hash
        )
        document_ids = [primary_document]
        document_hashes = [stored_primary_hash]
        offer_id: Optional[uuid.UUID] = None

        connection.execute(
            "INSERT INTO iam.policy_selectors ("
            "selector_digest,canonicalization_version,access_purpose,scope_type,"
            "target_role,jurisdiction,locale,current_bundle_id,aggregate_version,"
            "created_at,updated_at) VALUES ("
            "%s,'policy-selector-json-v1',%s,%s,%s,'CN',%s,NULL,1,%s,%s)",
            (selector, purpose, scope_type, role, locale, created_at, created_at),
        )
        connection.execute(
            "INSERT INTO iam.policy_documents ("
            "id,kind,locale,semantic_version,canonical_body,content_sha256,"
            "legal_effect,jurisdiction,status,effective_at,"
            "superseded_by_document_id,publication_command_id,created_at,updated_at"
            ") VALUES ("
            "%s,%s,%s,%s,%s,%s,'CONTRACT_ACCEPTANCE','CN','ACTIVE',%s,"
            "NULL,%s,%s,%s)",
            (
                primary_document,
                (
                    "COMMUNITY_TRANSACTION_COVENANT"
                    if scope_type == "ORGANIZATION_ROLE"
                    else "TERMS"
                ),
                locale,
                "1.0." + str(int(suffix[:4], 16)),
                primary_body,
                stored_primary_hash,
                effective_at,
                command,
                created_at,
                effective_at,
            ),
        )

        consent_document: Optional[uuid.UUID] = None
        consent_hash: Optional[bytes] = None
        if include_offer:
            consent_document = _new_id()
            consent_body = "Read model optional consent body " + suffix
            consent_hash = hashlib.sha256(consent_body.encode("utf-8")).digest()
            document_ids.append(consent_document)
            document_hashes.append(consent_hash)
            connection.execute(
                "INSERT INTO iam.policy_documents ("
                "id,kind,locale,semantic_version,canonical_body,content_sha256,"
                "legal_effect,jurisdiction,status,effective_at,"
                "superseded_by_document_id,publication_command_id,created_at,updated_at"
                ") VALUES ("
                "%s,'CONSENT_TEXT',%s,%s,%s,%s,'CONSENT_TEXT','CN','ACTIVE',%s,"
                "NULL,%s,%s,%s)",
                (
                    consent_document,
                    locale,
                    "1.1." + str(int(suffix[4:8], 16)),
                    consent_body,
                    consent_hash,
                    effective_at,
                    command,
                    created_at,
                    effective_at,
                ),
            )

        connection.execute(
            "INSERT INTO iam.policy_bundles ("
            "id,selector_digest,status,effective_at,effective_until,"
            "superseded_by_bundle_id,release_manifest_sha256,release_signature,"
            "release_signing_key_id,publication_command_id,aggregate_version,"
            "created_at,updated_at) VALUES ("
            "%s,%s,'DRAFT',NULL,NULL,NULL,%s,%s,'read-signing-key-v1',%s,1,%s,%s)",
            (
                bundle,
                selector,
                _digest("read-manifest-" + suffix),
                b"synthetic-reviewed-signature",
                command,
                created_at,
                created_at,
            ),
        )
        connection.execute(
            "INSERT INTO iam.policy_bundle_documents "
            "(bundle_id,document_id,position,required) VALUES (%s,%s,1,true)",
            (bundle, primary_document),
        )
        if consent_document is not None and consent_hash is not None:
            connection.execute(
                "INSERT INTO iam.policy_bundle_documents "
                "(bundle_id,document_id,position,required) VALUES (%s,%s,2,false)",
                (bundle, consent_document),
            )
            offer_id = _new_id()
            offer_not_after = now + timedelta(days=365)
            categories = ["PROFILE", "MATCHING", "RESEARCH"]
            offer_canonical = {
                "canonicalization_version": "consent-offer-json-v1",
                "consent_offer_id": str(offer_id),
                "consent_offer_version": 1,
                "policy_bundle_id": str(bundle),
                "purpose": "PILOT_RESEARCH",
                "scope_type": "PLATFORM_PARTICIPATION",
                "scope_derivation": "PLATFORM_PARTICIPATION_NULL_SCOPE",
                "data_categories": categories,
                "recipient_ref": "internal:read-research-controller",
                "recipient_label": "Reviewed read-model controller",
                "supporting_document_id": str(consent_document),
                "supporting_document_sha256": consent_hash.hex(),
                "expiry_rule": (
                    "EARLIER_OF_GRANTED_AT_PLUS_365_DAYS_OR_NOT_AFTER"
                ),
                "expiry_days": 365,
                "not_after": _timestamp(offer_not_after),
                "optional": True,
            }
            canonical_offer_hash = hashlib.sha256(
                json.dumps(
                    offer_canonical,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            ).digest()
            connection.execute(
                "INSERT INTO iam.consent_offers ("
                "id,bundle_id,offer_version,purpose,scope_type,scope_derivation,"
                "recipient_ref,recipient_label,document_id,document_content_sha256,"
                "expiry_rule,expiry_days,not_after,optional,canonical_offer_sha256,"
                "publication_command_id,created_at) VALUES ("
                "%s,%s,1,'PILOT_RESEARCH','PLATFORM_PARTICIPATION',"
                "'PLATFORM_PARTICIPATION_NULL_SCOPE',"
                "'internal:read-research-controller','Reviewed read-model controller',"
                "%s,%s,'EARLIER_OF_GRANTED_AT_PLUS_365_DAYS_OR_NOT_AFTER',"
                "365,%s,true,%s,%s,%s)",
                (
                    offer_id,
                    bundle,
                    consent_document,
                    consent_hash,
                    offer_not_after,
                    canonical_offer_hash,
                    command,
                    created_at,
                ),
            )
            for position, category in enumerate(categories, start=1):
                connection.execute(
                    "INSERT INTO iam.consent_offer_data_categories "
                    "(offer_id,category,position) VALUES (%s,%s,%s)",
                    (offer_id, category, position),
                )

        if active:
            connection.execute(
                "UPDATE iam.policy_bundles SET status='ACTIVE',effective_at=%s,"
                "aggregate_version=2,updated_at=%s WHERE id=%s",
                (effective_at, effective_at, bundle),
            )
            connection.execute(
                "UPDATE iam.policy_selectors SET current_bundle_id=%s,"
                "aggregate_version=2,updated_at=%s WHERE selector_digest=%s",
                (bundle, effective_at, selector),
            )
        return PolicyGraph(
            selector_digest=selector,
            bundle_id=bundle,
            document_ids=tuple(document_ids),
            document_hashes=tuple(document_hashes),
            offer_id=offer_id,
            locale=locale,
        )

    @classmethod
    def _seed_contact(
        cls,
        connection: Any,
        *,
        user_id: uuid.UUID,
        now: datetime,
        label: str,
    ) -> uuid.UUID:
        contact_id = _new_id()
        connection.execute(
            "INSERT INTO iam.contact_points ("
            "id,user_id,contact_type,locator_ciphertext,locator_encryption_key_id,"
            "locator_encryption_algorithm,binding_digest,binding_digest_key_id,"
            "verified_at,retention_until,created_at,updated_at) VALUES ("
            "%s,%s,'EMAIL',%s,'read-contact-aead-v1','AES_256_GCM_V1',"
            "%s,'read-contact-hmac-v1',%s,%s,%s,%s)",
            (
                contact_id,
                user_id,
                b"synthetic-aead-envelope-" + _digest(label)[:8],
                _digest("read-contact-binding-" + label),
                now - timedelta(days=100),
                now + timedelta(days=365),
                now - timedelta(days=100),
                now - timedelta(days=100),
            ),
        )
        return contact_id

    @classmethod
    def _seed_invitation(
        cls,
        connection: Any,
        *,
        invitation_id: uuid.UUID,
        contact_id: uuid.UUID,
        policy: PolicyGraph,
        now: datetime,
        created_at: datetime,
        organization_id: Optional[uuid.UUID],
        accepted_by: Optional[uuid.UUID],
        label: str,
    ) -> bytes:
        organization_shape = organization_id is not None
        status = "ACCEPTED" if accepted_by is not None else "ISSUED"
        nonce = _digest("read-invitation-nonce-" + label)
        terminal_at = (
            created_at + timedelta(hours=1) if accepted_by is not None else None
        )
        connection.execute(
            "INSERT INTO iam.access_invitations ("
            "id,purpose,organization_id,target_scope,target_role,is_initial_admin,"
            "recipient_contact_id,masked_recipient_label,policy_selector_digest,"
            "issued_policy_bundle_id,status,expires_at,issuer_kind,issuer_user_id,"
            "token_nonce,token_key_id,accepted_by_user_id,terminal_at,"
            "terminal_reason_code,aggregate_version,created_at,updated_at) VALUES ("
            "%s,%s,%s,%s,%s,false,%s,'r***@example.invalid',%s,%s,%s,%s,"
            "'SYSTEM',NULL,%s,'read-invitation-key-v1',%s,%s,NULL,%s,%s,%s)",
            (
                invitation_id,
                (
                    "ORGANIZATION_MEMBERSHIP"
                    if organization_shape
                    else "CREATOR_ENROLLMENT"
                ),
                organization_id,
                "ORGANIZATION" if organization_shape else "USER",
                "ORG_ADMIN" if organization_shape else "CREATOR",
                contact_id,
                policy.selector_digest,
                policy.bundle_id,
                status,
                now + timedelta(days=30),
                nonce,
                accepted_by,
                terminal_at,
                2 if accepted_by is not None else 1,
                created_at,
                terminal_at or created_at,
            ),
        )
        return nonce

    @classmethod
    def _seed_read_graph(cls, connection: Any) -> ReadGraph:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        actor_id = _new_id()
        other_user_id = _new_id()
        organization_id = _new_id()
        other_organization_id = _new_id()
        system_actor = _new_id()
        creator_policy = cls._seed_policy(
            connection,
            purpose="CREATOR_ENROLLMENT",
            scope_type="USER_ROLE",
            role="CREATOR",
            locale="en",
            now=now,
            include_offer=True,
        )
        organization_policy = cls._seed_policy(
            connection,
            purpose="ORGANIZATION_MEMBERSHIP",
            scope_type="ORGANIZATION_ROLE",
            role="ORG_ADMIN",
            locale="en",
            now=now,
        )
        connection.execute(
            "INSERT INTO iam.users "
            "(id,status,display_handle,aggregate_version,created_at,updated_at) "
            "VALUES (%s,'ACTIVE','read_actor',7,%s,%s),"
            "(%s,'ACTIVE','read_member',2,%s,%s)",
            (
                actor_id,
                now - timedelta(days=120),
                now - timedelta(days=1),
                other_user_id,
                now - timedelta(days=120),
                now - timedelta(days=2),
            ),
        )
        connection.execute(
            "INSERT INTO iam.organizations ("
            "id,organization_type,public_name,jurisdiction,status,"
            "client_reference_namespace,client_reference,aggregate_version,"
            "created_at,updated_at) VALUES ("
            "%s,'NONPROFIT','Synthetic Research Cooperative','CN','ACTIVE',"
            "'read-red',%s,4,%s,%s),"
            "(%s,'BUSINESS','Other Tenant','CN','ACTIVE','read-red',%s,1,%s,%s)",
            (
                organization_id,
                organization_id.hex,
                now - timedelta(days=100),
                now - timedelta(days=1),
                other_organization_id,
                other_organization_id.hex,
                now - timedelta(days=100),
                now - timedelta(days=1),
            ),
        )
        creator_contact = cls._seed_contact(
            connection, user_id=actor_id, now=now, label="creator"
        )
        actor_org_contact = cls._seed_contact(
            connection, user_id=actor_id, now=now, label="actor-org"
        )
        issued_contact = cls._seed_contact(
            connection, user_id=other_user_id, now=now, label="issued-org"
        )
        target_contact = cls._seed_contact(
            connection, user_id=other_user_id, now=now, label="target-org"
        )

        creator_invitation_id = _new_id()
        actor_accepted_invitation_id = _new_id()
        issued_invitation_id = _new_id()
        target_accepted_invitation_id = _new_id()
        cls._seed_invitation(
            connection,
            invitation_id=creator_invitation_id,
            contact_id=creator_contact,
            policy=creator_policy,
            now=now,
            created_at=now - timedelta(days=90),
            organization_id=None,
            accepted_by=actor_id,
            label="creator",
        )
        cls._seed_invitation(
            connection,
            invitation_id=actor_accepted_invitation_id,
            contact_id=actor_org_contact,
            policy=organization_policy,
            now=now,
            created_at=now - timedelta(days=31),
            organization_id=organization_id,
            accepted_by=actor_id,
            label="actor-org",
        )
        issued_nonce = cls._seed_invitation(
            connection,
            invitation_id=issued_invitation_id,
            contact_id=issued_contact,
            policy=organization_policy,
            now=now,
            created_at=now - timedelta(days=1),
            organization_id=organization_id,
            accepted_by=None,
            label="issued-org",
        )
        cls._seed_invitation(
            connection,
            invitation_id=target_accepted_invitation_id,
            contact_id=target_contact,
            policy=organization_policy,
            now=now,
            created_at=now - timedelta(days=61),
            organization_id=organization_id,
            accepted_by=other_user_id,
            label="target-org",
        )

        actor_membership_id = _new_id()
        target_membership_id = _new_id()
        connection.execute(
            "INSERT INTO iam.memberships ("
            "id,organization_id,user_id,status,source_invitation_id,"
            "aggregate_version,created_at,updated_at) VALUES ("
            "%s,%s,%s,'ACTIVE',%s,2,%s,%s),"
            "(%s,%s,%s,'SUSPENDED',%s,3,%s,%s)",
            (
                actor_membership_id,
                organization_id,
                actor_id,
                actor_accepted_invitation_id,
                now - timedelta(days=30),
                now - timedelta(days=1),
                target_membership_id,
                organization_id,
                other_user_id,
                target_accepted_invitation_id,
                now - timedelta(days=60),
                now - timedelta(days=2),
            ),
        )
        connection.execute(
            "INSERT INTO iam.user_role_grants ("
            "id,user_id,role_code,source_invitation_id,policy_selector_digest,"
            "granted_by_kind,granted_by_id,granted_at,revoked_at,"
            "revocation_reason_code,aggregate_version) VALUES ("
            "%s,%s,'CREATOR',%s,%s,'SYSTEM',%s,%s,NULL,NULL,1)",
            (
                _new_id(),
                actor_id,
                creator_invitation_id,
                creator_policy.selector_digest,
                system_actor,
                now - timedelta(days=89),
            ),
        )
        for membership_id, user_id, invitation_id, granted_at in (
            (
                actor_membership_id,
                actor_id,
                actor_accepted_invitation_id,
                now - timedelta(days=30),
            ),
            (
                target_membership_id,
                other_user_id,
                target_accepted_invitation_id,
                now - timedelta(days=60),
            ),
        ):
            connection.execute(
                "INSERT INTO iam.membership_role_grants ("
                "id,organization_id,membership_id,user_id,role_code,"
                "source_invitation_id,policy_selector_digest,granted_by_kind,"
                "granted_by_id,granted_at,revoked_at,revocation_reason_code,"
                "aggregate_version) VALUES ("
                "%s,%s,%s,%s,'ORG_ADMIN',%s,%s,'SYSTEM',%s,%s,NULL,NULL,1)",
                (
                    _new_id(),
                    organization_id,
                    membership_id,
                    user_id,
                    invitation_id,
                    organization_policy.selector_digest,
                    system_actor,
                    granted_at,
                ),
            )

        auth_transaction_id = _new_id()
        auth_created_at = now - timedelta(hours=8)
        connection.execute(
            "INSERT INTO iam.auth_transactions ("
            "id,status,purpose,attempt,protocol_version,browser_binding_digest,"
            "browser_binding_key_id,initiating_session_id,initiating_user_id,"
            "expected_user_id,invitation_id,invitation_version,"
            "expected_contact_point_id,state_digest,state_digest_key_id,"
            "nonce_digest,nonce_digest_key_id,pkce_verifier_ciphertext,"
            "pkce_encryption_key_id,pkce_encryption_algorithm,redirect_uri,"
            "provider_error_class,deadline,succeeded_at,created_at,updated_at) "
            "VALUES (%s,'SUCCEEDED','LOGIN',1,1,%s,'read-browser-hmac-v1',"
            "NULL,NULL,NULL,NULL,NULL,NULL,%s,'read-state-hmac-v1',%s,"
            "'read-nonce-hmac-v1',%s,'read-pkce-aead-v1','AES_256_GCM_V1',"
            "'https://app.example.test/v1/auth/oidc/callback',NULL,%s,%s,%s,%s)",
            (
                auth_transaction_id,
                _digest("read-browser-binding"),
                _digest("read-state"),
                _digest("read-nonce"),
                b"synthetic-pkce-envelope",
                now + timedelta(days=1),
                auth_created_at + timedelta(minutes=10),
                auth_created_at,
                auth_created_at + timedelta(minutes=10),
            ),
        )
        current_family_id = _new_id()
        old_family_id = _new_id()
        current_session_id = _new_id()
        old_session_id = _new_id()
        connection.execute(
            "INSERT INTO iam.session_families ("
            "id,user_id,status,current_generation,revoked_at,"
            "revocation_reason_code,aggregate_version,created_at,updated_at) "
            "VALUES (%s,%s,'ACTIVE',1,NULL,NULL,3,%s,%s),"
            "(%s,%s,'REVOKED',1,%s,'USER_LOGOUT',2,%s,%s)",
            (
                current_family_id,
                actor_id,
                now - timedelta(days=100),
                now - timedelta(hours=4),
                old_family_id,
                actor_id,
                now - timedelta(days=1),
                now - timedelta(days=100),
                now - timedelta(days=1),
            ),
        )
        current_created_at = now - timedelta(hours=4)
        auth_time = now - timedelta(hours=6)
        connection.execute(
            "INSERT INTO iam.sessions ("
            "id,user_id,family_id,generation,predecessor_session_id,handle_digest,"
            "handle_digest_key_id,csrf_salt,csrf_key_id,csrf_digest,"
            "verified_contact_point_id,verified_at,verified_for_invitation_id,"
            "auth_transaction_id,auth_time,acr_code,amr_codes,created_at,"
            "last_activity_at,idle_expires_at,absolute_expires_at,updated_at,"
            "device_label,status,rotation_reason,revoked_at,"
            "revocation_reason_code,aggregate_version) VALUES ("
            "%s,%s,%s,1,NULL,%s,'read-session-hmac-v1',%s,'read-csrf-hmac-v1',%s,"
            "NULL,NULL,NULL,%s,%s,'urn:desire:acr:mfa',ARRAY['pwd','otp']::text[],"
            "%s,%s,%s,%s,%s,'Browser','ACTIVE','LOGIN',NULL,NULL,3),"
            "(%s,%s,%s,1,NULL,%s,'read-session-hmac-v1',%s,'read-csrf-hmac-v1',%s,"
            "NULL,NULL,NULL,NULL,%s,'urn:desire:acr:mfa',ARRAY['pwd','otp']::text[],"
            "%s,%s,%s,%s,%s,'Mobile browser','REVOKED','LOGIN',%s,'USER_LOGOUT',2)",
            (
                current_session_id,
                actor_id,
                current_family_id,
                _digest("read-current-handle"),
                _digest("read-current-csrf-salt"),
                _digest("read-current-csrf"),
                auth_transaction_id,
                auth_time,
                current_created_at,
                now - timedelta(minutes=5),
                now + timedelta(minutes=30),
                now + timedelta(hours=12),
                now - timedelta(minutes=5),
                old_session_id,
                actor_id,
                old_family_id,
                _digest("read-old-handle"),
                _digest("read-old-csrf-salt"),
                _digest("read-old-csrf"),
                now - timedelta(days=3),
                now - timedelta(days=2),
                now - timedelta(days=2) + timedelta(minutes=10),
                now - timedelta(days=2) + timedelta(minutes=30),
                now - timedelta(days=1, hours=12),
                now - timedelta(days=1),
                now - timedelta(days=1),
            ),
        )

        policy_acceptance_id = _new_id()
        accepted_at = now - timedelta(minutes=30)
        connection.execute(
            "INSERT INTO iam.policy_acceptances ("
            "id,user_id,document_id,content_sha256,bundle_id,accepted_at,"
            "session_id,auth_transaction_id,auth_time,acr_code,amr_codes,"
            "source_action,command_id,correlation_id,aggregate_version,created_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'urn:desire:acr:mfa',"
            "ARRAY['pwd','otp']::text[],'POLICY_ACCEPT',%s,%s,1,%s)",
            (
                policy_acceptance_id,
                actor_id,
                creator_policy.document_ids[0],
                creator_policy.document_hashes[0],
                creator_policy.bundle_id,
                accepted_at,
                current_session_id,
                auth_transaction_id,
                auth_time,
                _new_id(),
                _new_id(),
                accepted_at,
            ),
        )
        if creator_policy.offer_id is None or len(creator_policy.document_ids) < 2:
            raise AssertionError("creator read policy requires one optional offer")
        active_consent_id = _new_id()
        withdrawn_consent_id = _new_id()
        active_granted_at = now - timedelta(minutes=40)
        withdrawn_granted_at = now - timedelta(hours=3)
        withdrawn_at = now - timedelta(hours=1)
        offer_not_after = now + timedelta(days=365)
        for grant_id, granted_at, status, withdrawn_value, version in (
            (active_consent_id, active_granted_at, "ACTIVE", None, 1),
            (
                withdrawn_consent_id,
                withdrawn_granted_at,
                "WITHDRAWN",
                withdrawn_at,
                2,
            ),
        ):
            expires_at = min(granted_at + timedelta(days=365), offer_not_after)
            connection.execute(
                "INSERT INTO iam.consent_grants ("
                "id,user_id,consent_offer_id,consent_offer_version,policy_bundle_id,"
                "purpose,scope_type,scope_id,recipient_ref,recipient_label,"
                "document_id,document_content_sha256,granted_at,expires_at,"
                "session_id,auth_transaction_id,auth_time,acr_code,amr_codes,"
                "command_id,correlation_id,status,withdrawn_at,aggregate_version,"
                "created_at,updated_at) VALUES ("
                "%s,%s,%s,1,%s,'PILOT_RESEARCH','PLATFORM_PARTICIPATION',NULL,"
                "'internal:read-research-controller','Reviewed read-model controller',"
                "%s,%s,%s,%s,%s,%s,%s,'urn:desire:acr:mfa',"
                "ARRAY['pwd','otp']::text[],%s,%s,%s,%s,%s,%s,%s)",
                (
                    grant_id,
                    actor_id,
                    creator_policy.offer_id,
                    creator_policy.bundle_id,
                    creator_policy.document_ids[1],
                    creator_policy.document_hashes[1],
                    granted_at,
                    expires_at,
                    current_session_id,
                    auth_transaction_id,
                    auth_time,
                    _new_id(),
                    _new_id(),
                    status,
                    withdrawn_value,
                    version,
                    granted_at,
                    withdrawn_value or granted_at,
                ),
            )
            for position, category in enumerate(
                ("PROFILE", "MATCHING", "RESEARCH"), start=1
            ):
                connection.execute(
                    "INSERT INTO iam.consent_grant_data_categories "
                    "(grant_id,category,position) VALUES (%s,%s,%s)",
                    (grant_id, category, position),
                )
        connection.execute(
            "INSERT INTO iam.consent_withdrawals ("
            "id,consent_grant_id,user_id,withdrawn_at,reason_code,command_id,"
            "correlation_id,created_at) VALUES (%s,%s,%s,%s,'USER_REQUEST',%s,%s,%s)",
            (
                _new_id(),
                withdrawn_consent_id,
                actor_id,
                withdrawn_at,
                _new_id(),
                _new_id(),
                withdrawn_at,
            ),
        )
        return ReadGraph(
            now=now,
            actor_id=actor_id,
            other_user_id=other_user_id,
            current_session_id=current_session_id,
            old_session_id=old_session_id,
            organization_id=organization_id,
            other_organization_id=other_organization_id,
            actor_membership_id=actor_membership_id,
            target_membership_id=target_membership_id,
            issued_invitation_id=issued_invitation_id,
            actor_accepted_invitation_id=actor_accepted_invitation_id,
            target_accepted_invitation_id=target_accepted_invitation_id,
            creator_invitation_id=creator_invitation_id,
            creator_policy=creator_policy,
            organization_policy=organization_policy,
            active_consent_id=active_consent_id,
            withdrawn_consent_id=withdrawn_consent_id,
            invitation_nonce_hex=issued_nonce.hex(),
            invitation_key_id="read-invitation-key-v1",
            invitation_format="access-invitation-token-v1",
            created_at_by_id={
                active_consent_id: active_granted_at,
                withdrawn_consent_id: withdrawn_granted_at,
                current_session_id: current_created_at,
                old_session_id: now - timedelta(days=2),
                issued_invitation_id: now - timedelta(days=1),
                actor_accepted_invitation_id: now - timedelta(days=31),
                target_accepted_invitation_id: now - timedelta(days=61),
                actor_membership_id: now - timedelta(days=30),
                target_membership_id: now - timedelta(days=60),
            },
        )

    def _capability(self, graph: Optional[ReadGraph] = None):
        selected = graph or self.graph
        return VerifiedAccessInvitationCapability(
            invitation_id=str(selected.issued_invitation_id),
            invitation_nonce=selected.invitation_nonce_hex,
            token_key_id=selected.invitation_key_id,
            token_format_version=selected.invitation_format,
            expires_at=selected.now + timedelta(days=30),
        )

    def _invoke(
        self,
        operation_id: str,
        *,
        window: Optional[ReadPageWindow] = None,
        actor_user_id: Optional[uuid.UUID] = None,
        organization_id: Optional[uuid.UUID] = None,
        policy_bundle_id: Optional[uuid.UUID] = None,
        capability: Optional[VerifiedAccessInvitationCapability] = None,
    ) -> ReadModelSnapshot:
        actor = actor_user_id or self.graph.actor_id
        organization = organization_id or self.graph.organization_id
        page = window or ReadPageWindow(limit=25)
        if operation_id == "getSessionBootstrap":
            return self.repository.read_session_bootstrap(
                actor_user_id=str(actor),
                session_id=str(self.graph.current_session_id),
            )
        if operation_id == "inspectAccessInvitation":
            return self.repository.read_invitation_preview(
                capability=capability or self._capability()
            )
        if operation_id == "getPolicyBundle":
            return self.repository.read_public_policy_bundle(
                policy_bundle_id=str(
                    policy_bundle_id or self.graph.creator_policy.bundle_id
                )
            )
        if operation_id == "getMe":
            return self.repository.read_me(
                actor_user_id=str(actor),
                session_id=str(self.graph.current_session_id),
            )
        if operation_id == "listMyConsentGrants":
            return self.repository.list_my_consent_grants(
                actor_user_id=str(actor),
                session_id=str(self.graph.current_session_id),
                window=page,
            )
        if operation_id == "listMySessions":
            return self.repository.list_my_sessions(
                actor_user_id=str(actor),
                session_id=str(self.graph.current_session_id),
                window=page,
            )
        if operation_id == "getOrganizationSummary":
            return self.repository.read_organization_summary(
                actor_user_id=str(actor),
                session_id=str(self.graph.current_session_id),
                organization_id=str(organization),
            )
        if operation_id == "listOrganizationAccessInvitations":
            return self.repository.list_organization_access_invitations(
                actor_user_id=str(actor),
                session_id=str(self.graph.current_session_id),
                organization_id=str(organization),
                window=page,
            )
        if operation_id == "listOrganizationMemberships":
            return self.repository.list_organization_memberships(
                actor_user_id=str(actor),
                session_id=str(self.graph.current_session_id),
                organization_id=str(organization),
                window=page,
            )
        raise AssertionError("unknown IAM read operation")

    def _observe_snapshot(self, operation_id: str, **kwargs: Any) -> Dict[str, Any]:
        try:
            snapshot = self._invoke(operation_id, **kwargs)
        except PostgresReadModelBehaviorNotAvailable as error:
            if str(error) != POSTGRES_READ_MODEL_BEHAVIOR_NOT_AVAILABLE:
                raise
            return {
                "kind": "behavior-not-available",
                "code": str(error),
            }
        if not isinstance(snapshot, ReadModelSnapshot):
            raise AssertionError("production repository returned a non-snapshot")
        facts = snapshot.facts_copy()
        anchors = {
            "actor": _contains(facts, str(self.graph.actor_id)),
            "session": _contains(facts, str(self.graph.current_session_id)),
            "organization": _contains(facts, str(self.graph.organization_id)),
            "invitation": _contains(facts, str(self.graph.issued_invitation_id)),
            "bundle": _contains(facts, str(self.graph.creator_policy.bundle_id)),
        }
        return {
            "kind": "ok",
            "statement_count": snapshot.statement_count,
            "fact_keys": tuple(sorted(facts)),
            "anchors": anchors,
        }

    def test_nine_operations_return_same_snapshot_closed_facts(self) -> None:
        expected_keys = {
            "getSessionBootstrap": ("family", "session", "user"),
            "inspectAccessInvitation": (
                "invitation",
                "organization",
                "policy",
                "recipient_binding",
            ),
            "getPolicyBundle": ("bundle", "documents", "offers", "selector"),
            "getMe": (
                "acceptances",
                "family",
                "memberships",
                "policies",
                "session",
                "source_invitations",
                "user",
                "user_role_grants",
            ),
            "listMyConsentGrants": ("actor", "rows", "snapshot_at"),
            "listMySessions": ("actor", "rows", "snapshot_at"),
            "getOrganizationSummary": ("actor", "organization"),
            "listOrganizationAccessInvitations": (
                "actor",
                "organization",
                "rows",
                "snapshot_at",
            ),
            "listOrganizationMemberships": (
                "actor",
                "organization",
                "rows",
                "snapshot_at",
            ),
        }
        expected_anchor_names = {
            "getSessionBootstrap": ("actor", "session"),
            "inspectAccessInvitation": ("organization", "invitation"),
            "getPolicyBundle": ("bundle",),
            "getMe": ("actor", "session", "organization", "bundle"),
            "listMyConsentGrants": ("actor", "session"),
            "listMySessions": ("actor", "session"),
            "getOrganizationSummary": ("actor", "session", "organization"),
            "listOrganizationAccessInvitations": (
                "actor",
                "session",
                "organization",
                "invitation",
            ),
            "listOrganizationMemberships": (
                "actor",
                "session",
                "organization",
            ),
        }
        for operation_id, profile in READ_STATEMENT_PROFILES.items():
            with self.subTest(operation_id=operation_id):
                expected_anchors = {
                    name: name in expected_anchor_names[operation_id]
                    for name in ("actor", "session", "organization", "invitation", "bundle")
                }
                self.assertEqual(
                    self._observe_snapshot(operation_id),
                    {
                        "kind": "ok",
                        "statement_count": profile.statement_budget,
                        "fact_keys": expected_keys[operation_id],
                        "anchors": expected_anchors,
                    },
                )

    def test_cross_user_organization_and_anonymous_bundle_are_not_visible(self) -> None:
        cases = (
            (
                "cross-user-self",
                {
                    "scope_kind": "SELF",
                    "operation": "LIST_MY_SESSIONS",
                    "actor_user_id": self.graph.actor_id,
                    "session_id": self.graph.current_session_id,
                },
                "SELECT id FROM iam.users WHERE id=%s",
                self.graph.other_user_id,
            ),
            (
                "forged-organization-authority",
                {
                    "scope_kind": "ORGANIZATION",
                    "operation": "LIST_ORGANIZATION_MEMBERSHIPS",
                    "actor_user_id": self.graph.actor_id,
                    "session_id": self.graph.current_session_id,
                    "organization_id": self.graph.other_organization_id,
                    "actor_membership_id": _new_id(),
                    "actor_membership_version": 1,
                    "actor_organization_role": "ORG_ADMIN",
                },
                "SELECT id FROM iam.organizations WHERE id=%s",
                self.graph.other_organization_id,
            ),
            (
                "wrong-anonymous-bundle",
                {
                    "scope_kind": "PUBLIC_POLICY_READ",
                    "operation": "READ_PUBLIC_POLICY_BUNDLE",
                    "policy_bundle_id": _new_id(),
                },
                "SELECT bundle_id FROM iam_api.public_policy_documents_v1",
                None,
            ),
        )
        for name, context, statement, parameter in cases:
            with self.subTest(case=name):
                with self._connect_role("iam_app") as connection:
                    self._set_context(connection, context)
                    rows = (
                        connection.execute(statement).fetchall()
                        if parameter is None
                        else connection.execute(statement, (parameter,)).fetchall()
                    )
                self.assertEqual(
                    rows,
                    [],
                    "same-role RLS exposed a cross-scope read-model root",
                )

    def test_v12_forward_surface_is_installed_from_the_canonical_catalog(self) -> None:
        with self._connect_admin() as connection:
            token_format_column = connection.execute(
                "SELECT data_type,is_nullable FROM information_schema.columns "
                "WHERE table_schema='iam' AND table_name='access_invitations' "
                "AND column_name='token_format_version'"
            ).fetchone()
            fixed_projections = tuple(
                row[0]
                for row in connection.execute(
                    "SELECT table_name FROM information_schema.views "
                    "WHERE table_schema='iam_api' AND table_name=ANY(%s) "
                    "ORDER BY table_name",
                    (
                        [
                            "read_session_bootstrap_v1",
                            "read_invitation_preview_v1",
                            "read_me_authority_policy_graph_v1",
                            "read_organization_memberships_page_v1",
                        ],
                    ),
                ).fetchall()
            )
            read_policies = tuple(
                row[0]
                for row in connection.execute(
                    "SELECT policyname FROM pg_catalog.pg_policies "
                    "WHERE schemaname='iam' AND policyname LIKE 'rls_read_%' "
                    "ORDER BY policyname"
                ).fetchall()
            )
        with self.subTest(gap="invitation-format-binding"):
            self.assertEqual(
                token_format_column,
                ("character varying", "NO"),
                "semantic RED: exact capability format is not persisted",
            )
        with self.subTest(gap="fixed-projections"):
            self.assertEqual(
                fixed_projections,
                (
                    "read_invitation_preview_v1",
                    "read_me_authority_policy_graph_v1",
                    "read_organization_memberships_page_v1",
                    "read_session_bootstrap_v1",
                ),
                "canonical read fixed projections are absent",
            )
        with self.subTest(gap="operation-specific-rls"):
            self.assertGreaterEqual(
                len(read_policies),
                9,
                "canonical read RLS cannot enforce all read operations",
            )

    def _observe_application_error(self, action: Any) -> Dict[str, str]:
        try:
            action()
        except PostgresReadModelBehaviorNotAvailable as error:
            if str(error) != POSTGRES_READ_MODEL_BEHAVIOR_NOT_AVAILABLE:
                raise
            return {"kind": "behavior-not-available", "code": str(error)}
        except IamError as error:
            return {"kind": "error", "code": error.code}
        return {"kind": "ok", "code": "OK"}

    def test_adjacent_status_orphan_and_hash_corruption_fail_closed(self) -> None:
        with self._connect_admin() as connection:
            draft = self._seed_policy(
                connection,
                purpose="CREATOR_ENROLLMENT",
                scope_type="USER_ROLE",
                role="CREATOR",
                locale="fr",
                now=self.graph.now,
                active=False,
            )
            corrupt = self._seed_policy(
                connection,
                purpose="CREATOR_ENROLLMENT",
                scope_type="USER_ROLE",
                role="CREATOR",
                locale="de",
                now=self.graph.now,
                active=True,
                hash_drift=True,
            )
            orphan_policy = self._seed_policy(
                connection,
                purpose="ORGANIZATION_MEMBERSHIP",
                scope_type="ORGANIZATION_ROLE",
                role="ORG_ADMIN",
                locale="fr",
                now=self.graph.now,
                active=False,
            )
            orphan_contact = self._seed_contact(
                connection,
                user_id=self.graph.other_user_id,
                now=self.graph.now,
                label="orphan-preview",
            )
            orphan_invitation_id = _new_id()
            orphan_nonce = self._seed_invitation(
                connection,
                invitation_id=orphan_invitation_id,
                contact_id=orphan_contact,
                policy=orphan_policy,
                now=self.graph.now,
                created_at=self.graph.now - timedelta(hours=2),
                organization_id=self.graph.other_organization_id,
                accepted_by=None,
                label="orphan-preview",
            )

        clock = FrozenClock(self.graph.now)
        public_handler = GetPolicyBundleHandler(
            repository=self.repository,
            clock=clock,
        )
        orphan_handler = InspectAccessInvitationHandler(
            repository=self.repository,
            clock=clock,
            invitation_capabilities=ExactCapabilityVerifier(
                invitation_id=orphan_invitation_id,
                nonce_hex=orphan_nonce.hex(),
                key_id="read-invitation-key-v1",
                token_format="access-invitation-token-v1",
                expires_at=self.graph.now + timedelta(days=30),
            ),
        )
        cases = (
            (
                "draft-status",
                lambda: public_handler.handle(
                    GetPolicyBundleQuery(policy_bundle_id=str(draft.bundle_id))
                ),
                "RESOURCE_NOT_FOUND",
            ),
            (
                "missing-current-pointer",
                lambda: orphan_handler.handle(
                    InspectAccessInvitationQuery(
                        access_invitation_token=RAW_INVITATION_TOKEN_SENTINEL
                    )
                ),
                "POLICY_CONFIGURATION_UNAVAILABLE",
            ),
            (
                "canonical-body-hash-drift",
                lambda: public_handler.handle(
                    GetPolicyBundleQuery(policy_bundle_id=str(corrupt.bundle_id))
                ),
                "POLICY_CONFIGURATION_UNAVAILABLE",
            ),
        )
        for name, action, expected_code in cases:
            with self.subTest(case=name):
                self.assertEqual(
                    self._observe_application_error(action),
                    {"kind": "error", "code": expected_code},
                )

    def test_fixed_statement_count_read_only_and_no_business_locks_or_writes(self) -> None:
        forbidden = (
            " INSERT ",
            " UPDATE ",
            " DELETE ",
            " MERGE ",
            " FOR UPDATE",
            " FOR SHARE",
            " ADVISORY_",
            " LOCK TABLE",
            " OFFSET ",
        )
        for operation_id, profile in READ_STATEMENT_PROFILES.items():
            self.app_source.trace.clear()
            self.onboarding_source.trace.clear()
            before_checkout = (
                self.app_source.checkout_count,
                self.onboarding_source.checkout_count,
            )
            observed = self._observe_snapshot(operation_id)
            trace = tuple(self.app_source.trace + self.onboarding_source.trace)
            normalized_trace = tuple(" " + item.upper() + " " for item in trace)
            with self.subTest(operation_id=operation_id):
                self.assertEqual(
                    (
                        observed.get("kind"),
                        observed.get("statement_count"),
                        (
                            self.app_source.checkout_count - before_checkout[0]
                            + self.onboarding_source.checkout_count
                            - before_checkout[1]
                        ),
                        any(
                            token in statement
                            for token in forbidden
                            for statement in normalized_trace
                        ),
                        any("READ ONLY" in statement for statement in normalized_trace),
                    ),
                    ("ok", profile.statement_budget, 1, False, True),
                )

    def _observe_page(
        self, operation_id: str, *, window: ReadPageWindow
    ) -> Dict[str, Any]:
        try:
            snapshot = self._invoke(operation_id, window=window)
        except PostgresReadModelBehaviorNotAvailable as error:
            if str(error) != POSTGRES_READ_MODEL_BEHAVIOR_NOT_AVAILABLE:
                raise
            return {"kind": "behavior-not-available", "code": str(error)}
        facts = snapshot.facts_copy()
        rows = facts.get("rows")
        if not isinstance(rows, list):
            raise AssertionError("paged snapshot has no closed rows list")
        return {
            "kind": "ok",
            "snapshot_binding_valid": (
                facts.get("snapshot_at") == window.snapshot_at
                if window.snapshot_at is not None
                else (
                    isinstance(facts.get("snapshot_at"), datetime)
                    and facts["snapshot_at"].utcoffset() == timedelta(0)
                    and facts["snapshot_at"] >= self.graph.now
                )
            ),
            "row_ids": tuple(str(row["sort_id"]) for row in rows),
            "statement_count": snapshot.statement_count,
        }

    def test_four_keyset_pages_use_snapshot_and_uuid_tuple_boundaries(self) -> None:
        ordered_ids = {
            "listMyConsentGrants": (
                self.graph.active_consent_id,
                self.graph.withdrawn_consent_id,
            ),
            "listMySessions": (
                self.graph.current_session_id,
                self.graph.old_session_id,
            ),
            "listOrganizationAccessInvitations": (
                self.graph.issued_invitation_id,
                self.graph.actor_accepted_invitation_id,
                self.graph.target_accepted_invitation_id,
            ),
            "listOrganizationMemberships": (
                self.graph.actor_membership_id,
                self.graph.target_membership_id,
            ),
        }
        for operation_id, ids in ordered_ids.items():
            first_window = ReadPageWindow(limit=1)
            first_expected = ids[:2]
            with self.subTest(operation_id=operation_id, page="first"):
                self.assertEqual(
                    self._observe_page(operation_id, window=first_window),
                    {
                        "kind": "ok",
                        "snapshot_binding_valid": True,
                        "row_ids": tuple(str(item) for item in first_expected),
                        "statement_count": READ_STATEMENT_PROFILES[
                            operation_id
                        ].statement_budget,
                    },
                )
            boundary_id = ids[0]
            second_window = ReadPageWindow(
                limit=1,
                snapshot_at=self.graph.now,
                after_created_at=self.graph.created_at_by_id[boundary_id],
                after_id=str(boundary_id),
            )
            second_expected = ids[1:3]
            with self.subTest(operation_id=operation_id, page="second"):
                self.assertEqual(
                    self._observe_page(operation_id, window=second_window),
                    {
                        "kind": "ok",
                        "snapshot_binding_valid": True,
                        "row_ids": tuple(str(item) for item in second_expected),
                        "statement_count": READ_STATEMENT_PROFILES[
                            operation_id
                        ].statement_budget,
                    },
                )

    def test_same_physical_connection_resets_every_scope_before_reuse(self) -> None:
        first = self._observe_snapshot("getMe")
        second = self._observe_snapshot("getPolicyBundle")
        pids = tuple(self.app_source.backend_pids)
        residual: Tuple[Optional[str], ...] = ()
        if self.app_source._raw is not None and not self.app_source._raw.closed:
            residual = tuple(
                row[0]
                for row in self.app_source._raw.execute(
                    "SELECT NULLIF(current_setting(setting_name,true),'') "
                    "FROM unnest(%s::text[]) AS names(setting_name) "
                    "ORDER BY setting_name",
                    (
                        [
                            "app.actor_user_id",
                            "app.operation",
                            "app.organization_id",
                            "app.policy_bundle_id",
                            "app.scope_kind",
                            "app.session_id",
                            "app.target_invitation_id",
                        ],
                    ),
                ).fetchall()
            )
        self.assertEqual(
            (
                first.get("kind"),
                second.get("kind"),
                self.app_source.checkout_count,
                self.app_source.release_count,
                self.app_source.discard_count,
                len(set(pids)) if pids else 0,
                residual,
            ),
            ("ok", "ok", 2, 2, 0, 1, (None,) * 7),
        )

    def test_secret_sentinels_never_enter_repr_trace_snapshot_or_database(self) -> None:
        capability = self._capability()
        observation = self._observe_snapshot(
            "inspectAccessInvitation", capability=capability
        )
        surfaces: Sequence[object] = (
            repr(self.repository),
            repr(capability),
            repr(observation),
            tuple(self.app_source.trace),
            tuple(self.onboarding_source.trace),
        )
        for sentinel in RAW_SENTINELS:
            with self.subTest(sentinel=sentinel):
                self.assertFalse(
                    any(sentinel in repr(surface) for surface in surfaces),
                    "raw read secret entered an ordinary diagnostic surface",
                )
        self._assert_database_has_no_raw_sentinel(RAW_SENTINELS)
        self.assertEqual(
            observation.get("kind"),
            "ok",
            "semantic RED: secret-safe production read snapshot is unavailable",
        )

    def _assert_database_has_no_raw_sentinel(
        self, sentinels: Iterable[str]
    ) -> None:
        with self._connect_admin() as connection:
            columns = connection.execute(
                "SELECT table_schema,table_name,column_name "
                "FROM information_schema.columns "
                "WHERE table_schema IN ('iam','infra','audit') "
                "AND data_type IN ('text','character varying','json','jsonb','bytea') "
                "ORDER BY table_schema,table_name,ordinal_position"
            ).fetchall()
            for schema_name, table_name, column_name in columns:
                statement = sql.SQL(
                    "SELECT EXISTS (SELECT 1 FROM {}.{} WHERE {}::text LIKE %s)"
                ).format(
                    sql.Identifier(schema_name),
                    sql.Identifier(table_name),
                    sql.Identifier(column_name),
                )
                for sentinel in sentinels:
                    found = connection.execute(
                        statement,
                        ("%" + sentinel + "%",),
                    ).fetchone()[0]
                    self.assertFalse(
                        found,
                        "%s.%s.%s contains a raw read sentinel"
                        % (schema_name, table_name, column_name),
                    )

    def test_registry_is_closed_immutable_and_has_no_generic_repository_api(self) -> None:
        self.assertEqual(tuple(READ_STATEMENT_PROFILES), tuple((
            "getSessionBootstrap",
            "inspectAccessInvitation",
            "getPolicyBundle",
            "getMe",
            "listMyConsentGrants",
            "listMySessions",
            "getOrganizationSummary",
            "listOrganizationAccessInvitations",
            "listOrganizationMemberships",
        )))
        for operation_id, profile in READ_STATEMENT_PROFILES.items():
            with self.subTest(operation_id=operation_id):
                self.assertEqual(profile.operation_id, operation_id)
                self.assertEqual(profile.statement_budget, len(profile.statement_names))
                self.assertEqual(len(profile.query_shape_digest), 64)
        for forbidden in ("get", "select", "execute", "query", "write", "lock"):
            self.assertFalse(hasattr(self.repository, forbidden))
        with self.assertRaises(TypeError):
            READ_STATEMENT_PROFILES["getMe"] = READ_STATEMENT_PROFILES["getMe"]


if __name__ == "__main__":
    unittest.main()
