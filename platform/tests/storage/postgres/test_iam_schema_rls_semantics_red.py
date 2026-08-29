"""Semantic RED evidence for the reviewed IAM schema on real PostgreSQL 18.

These tests intentionally exercise the checked-in migration catalog through the
production migration runner.  A failing assertion must describe a database
semantic mismatch; importing this module, provisioning PostgreSQL, migration,
and fixture construction are prerequisites rather than accepted RED reasons.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
from pathlib import Path
import threading
from typing import Any, Dict, Iterable, Optional, Sequence, Tuple
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
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)

RLS_RELATIONS = (
    ("iam", "policy_selectors"),
    ("iam", "policy_documents"),
    ("iam", "policy_bundles"),
    ("iam", "policy_bundle_documents"),
    ("iam", "consent_offers"),
    ("iam", "consent_offer_data_categories"),
    ("iam", "users"),
    ("iam", "external_identities"),
    ("iam", "contact_points"),
    ("iam", "organizations"),
    ("iam", "access_invitations"),
    ("iam", "memberships"),
    ("iam", "user_role_grants"),
    ("iam", "membership_role_grants"),
    ("iam", "platform_duty_grants"),
    ("iam", "auth_transactions"),
    ("iam", "session_families"),
    ("iam", "sessions"),
    ("iam", "policy_acceptances"),
    ("iam", "consent_grants"),
    ("iam", "consent_grant_data_categories"),
    ("iam", "consent_withdrawals"),
    ("infra", "command_receipts"),
    ("infra", "iam_receipt_key_policy"),
    ("audit", "audit_events"),
    ("infra", "outbox_events"),
    ("infra", "iam_sandbox_bootstrap_state"),
    ("infra", "iam_sandbox_bootstrap_accounts"),
    ("infra", "iam_sandbox_bootstrap_runs"),
)

ONLINE_ROLES = (
    "iam_app",
    "iam_session_authenticator",
    "iam_onboarding",
    "iam_system",
    "iam_outbox_worker",
)

SELF_SUMMARY_COLUMNS = (
    "user_id",
    "user_status",
    "display_handle",
    "user_aggregate_version",
    "membership_id",
    "membership_status",
    "membership_aggregate_version",
    "membership_role_codes",
    "organization_id",
    "organization_public_name",
    "organization_type",
    "organization_status",
    "organization_aggregate_version",
)

COOKIE_VIEW_COLUMNS = (
    "session_id",
    "user_id",
    "family_id",
    "generation",
    "session_status",
    "handle_digest_key_id",
    "handle_digest",
    "csrf_salt",
    "csrf_key_id",
    "csrf_digest",
    "auth_time",
    "acr_code",
    "amr_codes",
    "idle_expires_at",
    "absolute_expires_at",
    "verified_contact_point_id",
    "verified_at",
    "verified_for_invitation_id",
    "auth_transaction_id",
    "device_label",
    "session_aggregate_version",
    "family_status",
    "current_generation",
    "family_aggregate_version",
)


def _digest(label: str) -> bytes:
    return hashlib.sha256(label.encode("utf-8")).digest()


def _new_id() -> uuid.UUID:
    return uuid.uuid4()


class RealPostgres18IamSchemaRlsSemanticsRedTest(unittest.TestCase):
    """Execute reviewed IAM persistence invariants against a real PG18 server."""

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
        report = self._run_migrations()
        self.assertEqual(
            report.applied_versions,
            tuple(artifact.descriptor.version for artifact in self.catalog.artifacts),
        )

    def tearDown(self) -> None:
        self.postgres.drop_database(self.database)

    def _run_migrations(self):
        driver = PsycopgMigrationDriver(
            settings=PsycopgMigrationSettings(
                conninfo=self.postgres.conninfo(
                    database=self.database,
                    user="iam_migration_runner",
                ),
                application_name="desire-iam-pg18-semantic-red",
            ),
            dbapi=psycopg,
        )
        return IamMigrationRunner(
            driver=driver,
            runner_version="real-pg18-semantic-red/1",
        ).run(catalog=self.catalog, contract_sources=self.contract_sources)

    def _connect_admin(self, *, autocommit: bool = False):
        return psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=autocommit,
        )

    def _connect_role(self, role: str, *, autocommit: bool = False):
        return psycopg.connect(
            self.postgres.conninfo(database=self.database, user=role),
            autocommit=autocommit,
        )

    @staticmethod
    def _set_context(connection: Any, values: Dict[str, object]) -> None:
        for name, value in values.items():
            connection.execute(
                "SELECT pg_catalog.set_config(%s, %s, true)",
                ("app." + name, str(value)),
            )

    def _seed_public_policy_graph(self, connection: Any) -> Dict[str, object]:
        unique = uuid.uuid4().hex
        facts: Dict[str, object] = {
            "active_selector": _digest("active-selector-" + unique),
            "active_bundle": _new_id(),
            "active_document": _new_id(),
            "active_offer": _new_id(),
            "active_command": _new_id(),
            "draft_selector": _digest("draft-selector-" + unique),
            "draft_bundle": _new_id(),
            "draft_document": _new_id(),
            "draft_offer": _new_id(),
            "draft_command": _new_id(),
        }

        connection.execute(
            "INSERT INTO iam.policy_selectors ("
            "selector_digest,canonicalization_version,access_purpose,scope_type,"
            "target_role,jurisdiction,locale,current_bundle_id,aggregate_version,"
            "created_at,updated_at) VALUES ("
            "%s,'policy-selector-json-v1','CREATOR_ENROLLMENT','USER_ROLE',"
            "'CREATOR','CN','zh-CN',NULL,1,"
            "transaction_timestamp()-interval '2 days',"
            "transaction_timestamp()-interval '2 days')",
            (facts["active_selector"],),
        )
        connection.execute(
            "INSERT INTO iam.policy_documents ("
            "id,kind,locale,semantic_version,canonical_body,content_sha256,"
            "legal_effect,jurisdiction,status,effective_at,"
            "superseded_by_document_id,publication_command_id,created_at,updated_at"
            ") VALUES ("
            "%s,'CONSENT_TEXT','zh-CN','1.0.0','active public text',%s,"
            "'CONSENT_TEXT','CN','ACTIVE',transaction_timestamp()-interval '1 day',"
            "NULL,%s,transaction_timestamp()-interval '2 days',"
            "transaction_timestamp()-interval '1 day')",
            (
                facts["active_document"],
                _digest("active-document-" + unique),
                facts["active_command"],
            ),
        )
        connection.execute(
            "INSERT INTO iam.policy_bundles ("
            "id,selector_digest,status,effective_at,effective_until,"
            "superseded_by_bundle_id,release_manifest_sha256,release_signature,"
            "release_signing_key_id,publication_command_id,aggregate_version,"
            "created_at,updated_at) VALUES ("
            "%s,%s,'DRAFT',NULL,NULL,NULL,%s,%s,'policy-signing-v1',%s,1,"
            "transaction_timestamp()-interval '2 days',"
            "transaction_timestamp()-interval '2 days')",
            (
                facts["active_bundle"],
                facts["active_selector"],
                _digest("active-manifest-" + unique),
                b"reviewed-signature",
                facts["active_command"],
            ),
        )
        connection.execute(
            "INSERT INTO iam.policy_bundle_documents "
            "(bundle_id,document_id,position,required) VALUES (%s,%s,1,true)",
            (facts["active_bundle"], facts["active_document"]),
        )
        connection.execute(
            "INSERT INTO iam.consent_offers ("
            "id,bundle_id,offer_version,purpose,scope_type,scope_derivation,"
            "recipient_ref,recipient_label,document_id,document_content_sha256,"
            "expiry_rule,expiry_days,not_after,optional,canonical_offer_sha256,"
            "publication_command_id,created_at) VALUES ("
            "%s,%s,1,'PILOT_RESEARCH','PLATFORM_PARTICIPATION',"
            "'PLATFORM_PARTICIPATION_NULL_SCOPE','internal:active-recipient',"
            "'Reviewed research recipient',%s,%s,'FIXED_NOT_AFTER',NULL,"
            "transaction_timestamp()+interval '365 days',true,%s,%s,"
            "transaction_timestamp()-interval '1 day')",
            (
                facts["active_offer"],
                facts["active_bundle"],
                facts["active_document"],
                _digest("active-document-" + unique),
                _digest("active-offer-" + unique),
                facts["active_command"],
            ),
        )
        connection.execute(
            "INSERT INTO iam.consent_offer_data_categories "
            "(offer_id,category,position) VALUES (%s,'RESEARCH',1)",
            (facts["active_offer"],),
        )
        connection.execute(
            "UPDATE iam.policy_bundles SET status='ACTIVE',"
            "effective_at=transaction_timestamp()-interval '1 day',"
            "aggregate_version=2,updated_at=transaction_timestamp() WHERE id=%s",
            (facts["active_bundle"],),
        )
        connection.execute(
            "UPDATE iam.policy_selectors SET current_bundle_id=%s,"
            "aggregate_version=2,updated_at=transaction_timestamp() "
            "WHERE selector_digest=%s",
            (facts["active_bundle"], facts["active_selector"]),
        )

        connection.execute(
            "INSERT INTO iam.policy_selectors ("
            "selector_digest,canonicalization_version,access_purpose,scope_type,"
            "target_role,jurisdiction,locale,current_bundle_id,aggregate_version,"
            "created_at,updated_at) VALUES ("
            "%s,'policy-selector-json-v1','ORGANIZATION_MEMBERSHIP',"
            "'ORGANIZATION_ROLE','ORG_ADMIN','CN','zh-CN',NULL,1,"
            "transaction_timestamp()-interval '2 days',"
            "transaction_timestamp()-interval '2 days')",
            (facts["draft_selector"],),
        )
        connection.execute(
            "INSERT INTO iam.policy_documents ("
            "id,kind,locale,semantic_version,canonical_body,content_sha256,"
            "legal_effect,jurisdiction,status,effective_at,"
            "superseded_by_document_id,publication_command_id,created_at,updated_at"
            ") VALUES ("
            "%s,'CONSENT_TEXT','zh-CN','2.0.0','draft bundle child text',%s,"
            "'CONSENT_TEXT','CN','ACTIVE',transaction_timestamp()-interval '1 day',"
            "NULL,%s,transaction_timestamp()-interval '2 days',"
            "transaction_timestamp()-interval '1 day')",
            (
                facts["draft_document"],
                _digest("draft-document-" + unique),
                facts["draft_command"],
            ),
        )
        connection.execute(
            "INSERT INTO iam.policy_bundles ("
            "id,selector_digest,status,effective_at,effective_until,"
            "superseded_by_bundle_id,release_manifest_sha256,release_signature,"
            "release_signing_key_id,publication_command_id,aggregate_version,"
            "created_at,updated_at) VALUES ("
            "%s,%s,'DRAFT',NULL,NULL,NULL,%s,%s,'policy-signing-v1',%s,1,"
            "transaction_timestamp()-interval '2 days',"
            "transaction_timestamp()-interval '2 days')",
            (
                facts["draft_bundle"],
                facts["draft_selector"],
                _digest("draft-manifest-" + unique),
                b"reviewed-draft-signature",
                facts["draft_command"],
            ),
        )
        connection.execute(
            "INSERT INTO iam.policy_bundle_documents "
            "(bundle_id,document_id,position,required) VALUES (%s,%s,1,true)",
            (facts["draft_bundle"], facts["draft_document"]),
        )
        connection.execute(
            "INSERT INTO iam.consent_offers ("
            "id,bundle_id,offer_version,purpose,scope_type,scope_derivation,"
            "recipient_ref,recipient_label,document_id,document_content_sha256,"
            "expiry_rule,expiry_days,not_after,optional,canonical_offer_sha256,"
            "publication_command_id,created_at) VALUES ("
            "%s,%s,1,'PILOT_RESEARCH','PLATFORM_PARTICIPATION',"
            "'PLATFORM_PARTICIPATION_NULL_SCOPE','internal:draft-recipient',"
            "'Draft-only recipient',%s,%s,'FIXED_NOT_AFTER',NULL,"
            "transaction_timestamp()+interval '365 days',true,%s,%s,"
            "transaction_timestamp()-interval '1 day')",
            (
                facts["draft_offer"],
                facts["draft_bundle"],
                facts["draft_document"],
                _digest("draft-document-" + unique),
                _digest("draft-offer-" + unique),
                facts["draft_command"],
            ),
        )
        connection.execute(
            "INSERT INTO iam.consent_offer_data_categories "
            "(offer_id,category,position) VALUES (%s,'RESEARCH',1)",
            (facts["draft_offer"],),
        )
        return facts

    def _seed_identity_graph(
        self,
        connection: Any,
        facts: Dict[str, object],
    ) -> None:
        facts.update(
            {
                "actor": _new_id(),
                "other_user": _new_id(),
                "contact": _new_id(),
                "other_contact": _new_id(),
                "active_org": _new_id(),
                "second_active_org": _new_id(),
                "suspended_org": _new_id(),
                "creator_invitation": _new_id(),
                "active_membership_invitation": _new_id(),
                "suspended_membership_invitation": _new_id(),
                "suspended_org_invitation": _new_id(),
                "unused_same_org_invitation": _new_id(),
                "unused_cross_org_invitation": _new_id(),
                "active_membership": _new_id(),
                "suspended_membership": _new_id(),
                "suspended_org_membership": _new_id(),
                "active_membership_role": _new_id(),
                "suspended_membership_role": _new_id(),
                "suspended_org_role": _new_id(),
                "creator_role": _new_id(),
            }
        )
        connection.execute(
            "INSERT INTO iam.users "
            "(id,status,display_handle,aggregate_version,created_at,updated_at) "
            "VALUES "
            "(%s,'ACTIVE','active_actor',1,transaction_timestamp()-interval '3 days',"
            "transaction_timestamp()-interval '3 days'),"
            "(%s,'ACTIVE','other_actor',1,transaction_timestamp()-interval '3 days',"
            "transaction_timestamp()-interval '3 days')",
            (facts["actor"], facts["other_user"]),
        )
        connection.execute(
            "INSERT INTO iam.external_identities ("
            "id,user_id,issuer,subject_digest,subject_digest_key_id,verified_at,"
            "status,created_at) VALUES ("
            "%s,%s,'https://issuer.invalid',%s,'subject-hmac-v1',"
            "transaction_timestamp()-interval '2 days','ACTIVE',"
            "transaction_timestamp()-interval '3 days')",
            (_new_id(), facts["actor"], _digest("subject-" + str(facts["actor"]))),
        )
        connection.execute(
            "INSERT INTO iam.contact_points ("
            "id,user_id,contact_type,locator_ciphertext,locator_encryption_key_id,"
            "locator_encryption_algorithm,binding_digest,binding_digest_key_id,"
            "verified_at,retention_until,created_at,updated_at) VALUES "
            "(%s,%s,'EMAIL',NULL,NULL,NULL,%s,'contact-hmac-v1',"
            "transaction_timestamp()-interval '2 days',"
            "transaction_timestamp()+interval '365 days',"
            "transaction_timestamp()-interval '3 days',transaction_timestamp()),"
            "(%s,%s,'EMAIL',NULL,NULL,NULL,%s,'contact-hmac-v1',"
            "transaction_timestamp()-interval '2 days',"
            "transaction_timestamp()+interval '365 days',"
            "transaction_timestamp()-interval '3 days',transaction_timestamp())",
            (
                facts["contact"],
                facts["actor"],
                _digest("contact-actor-" + str(facts["actor"])),
                facts["other_contact"],
                facts["other_user"],
                _digest("contact-other-" + str(facts["other_user"])),
            ),
        )
        connection.execute(
            "INSERT INTO iam.organizations ("
            "id,organization_type,public_name,jurisdiction,status,"
            "client_reference_namespace,client_reference,aggregate_version,"
            "created_at,updated_at) VALUES "
            "(%s,'BUSINESS','Active Org','CN','ACTIVE','semantic-red',%s,1,"
            "transaction_timestamp()-interval '3 days',transaction_timestamp()),"
            "(%s,'NONPROFIT','Second Active Org','CN','ACTIVE','semantic-red',%s,1,"
            "transaction_timestamp()-interval '3 days',transaction_timestamp()),"
            "(%s,'COMMUNITY','Suspended Org','CN','SUSPENDED','semantic-red',%s,1,"
            "transaction_timestamp()-interval '3 days',transaction_timestamp())",
            (
                facts["active_org"],
                "active-" + uuid.uuid4().hex,
                facts["second_active_org"],
                "second-" + uuid.uuid4().hex,
                facts["suspended_org"],
                "suspended-" + uuid.uuid4().hex,
            ),
        )

        self._insert_accepted_invitation(
            connection,
            invitation_id=facts["creator_invitation"],
            actor_id=facts["actor"],
            contact_id=facts["contact"],
            selector_digest=facts["active_selector"],
            bundle_id=facts["active_bundle"],
            organization_id=None,
            target_role="CREATOR",
        )
        organization_invitation_specs = (
            ("active_membership_invitation", "active_org"),
            ("suspended_membership_invitation", "second_active_org"),
            ("suspended_org_invitation", "suspended_org"),
            ("unused_same_org_invitation", "active_org"),
            ("unused_cross_org_invitation", "second_active_org"),
        )
        for invitation_key, organization_key in organization_invitation_specs:
            self._insert_accepted_invitation(
                connection,
                invitation_id=facts[invitation_key],
                actor_id=facts["actor"],
                contact_id=facts["contact"],
                selector_digest=facts["draft_selector"],
                bundle_id=facts["draft_bundle"],
                organization_id=facts[organization_key],
                target_role="ORG_ADMIN",
            )

        connection.execute(
            "INSERT INTO iam.memberships ("
            "id,organization_id,user_id,status,source_invitation_id,"
            "aggregate_version,created_at,updated_at) VALUES "
            "(%s,%s,%s,'ACTIVE',%s,1,transaction_timestamp()-interval '1 day',"
            "transaction_timestamp()),"
            "(%s,%s,%s,'SUSPENDED',%s,1,transaction_timestamp()-interval '1 day',"
            "transaction_timestamp()),"
            "(%s,%s,%s,'ACTIVE',%s,1,transaction_timestamp()-interval '1 day',"
            "transaction_timestamp())",
            (
                facts["active_membership"],
                facts["active_org"],
                facts["actor"],
                facts["active_membership_invitation"],
                facts["suspended_membership"],
                facts["second_active_org"],
                facts["actor"],
                facts["suspended_membership_invitation"],
                facts["suspended_org_membership"],
                facts["suspended_org"],
                facts["actor"],
                facts["suspended_org_invitation"],
            ),
        )
        connection.execute(
            "INSERT INTO iam.user_role_grants ("
            "id,user_id,role_code,source_invitation_id,policy_selector_digest,"
            "granted_by_kind,granted_by_id,granted_at,revoked_at,"
            "revocation_reason_code,aggregate_version) VALUES ("
            "%s,%s,'CREATOR',%s,%s,'SYSTEM',%s,transaction_timestamp()-interval '1 day',"
            "NULL,NULL,1)",
            (
                facts["creator_role"],
                facts["actor"],
                facts["creator_invitation"],
                facts["active_selector"],
                _new_id(),
            ),
        )
        membership_role_specs = (
            (
                "active_membership_role",
                "active_org",
                "active_membership",
                "active_membership_invitation",
            ),
            (
                "suspended_membership_role",
                "second_active_org",
                "suspended_membership",
                "suspended_membership_invitation",
            ),
            (
                "suspended_org_role",
                "suspended_org",
                "suspended_org_membership",
                "suspended_org_invitation",
            ),
        )
        for role_key, organization_key, membership_key, invitation_key in (
            membership_role_specs
        ):
            connection.execute(
                "INSERT INTO iam.membership_role_grants ("
                "id,organization_id,membership_id,user_id,role_code,"
                "source_invitation_id,policy_selector_digest,granted_by_kind,"
                "granted_by_id,granted_at,revoked_at,revocation_reason_code,"
                "aggregate_version) VALUES ("
                "%s,%s,%s,%s,'ORG_ADMIN',%s,%s,'SYSTEM',%s,"
                "transaction_timestamp()-interval '1 day',NULL,NULL,1)",
                (
                    facts[role_key],
                    facts[organization_key],
                    facts[membership_key],
                    facts["actor"],
                    facts[invitation_key],
                    facts["draft_selector"],
                    _new_id(),
                ),
            )

    @staticmethod
    def _insert_accepted_invitation(
        connection: Any,
        *,
        invitation_id: object,
        actor_id: object,
        contact_id: object,
        selector_digest: object,
        bundle_id: object,
        organization_id: Optional[object],
        target_role: str,
    ) -> None:
        if organization_id is None:
            purpose = "CREATOR_ENROLLMENT"
            target_scope = "USER"
        else:
            purpose = "ORGANIZATION_MEMBERSHIP"
            target_scope = "ORGANIZATION"
        connection.execute(
            "INSERT INTO iam.access_invitations ("
            "id,purpose,organization_id,target_scope,target_role,is_initial_admin,"
            "recipient_contact_id,masked_recipient_label,policy_selector_digest,"
            "issued_policy_bundle_id,status,expires_at,issuer_kind,issuer_user_id,"
            "token_nonce,token_key_id,accepted_by_user_id,terminal_at,"
            "terminal_reason_code,aggregate_version,created_at,updated_at) VALUES ("
            "%s,%s,%s,%s,%s,false,%s,'a***@example.invalid',%s,%s,'ACCEPTED',"
            "transaction_timestamp()+interval '30 days','SYSTEM',NULL,%s,"
            "'invitation-token-v1',%s,transaction_timestamp(),NULL,2,"
            "transaction_timestamp()-interval '1 day',transaction_timestamp())",
            (
                invitation_id,
                purpose,
                organization_id,
                target_scope,
                target_role,
                contact_id,
                selector_digest,
                bundle_id,
                _digest("invitation-nonce-" + str(invitation_id)),
                actor_id,
            ),
        )

    def _seed_session_graph(
        self,
        connection: Any,
        facts: Dict[str, object],
    ) -> None:
        facts.update(
            {
                "family": _new_id(),
                "old_session": _new_id(),
                "current_session": _new_id(),
                "old_handle": _digest("old-handle-" + uuid.uuid4().hex),
                "current_handle": _digest("current-handle-" + uuid.uuid4().hex),
                "other_family": _new_id(),
                "other_session": _new_id(),
                "other_handle": _digest("other-handle-" + uuid.uuid4().hex),
            }
        )
        connection.execute(
            "INSERT INTO iam.session_families ("
            "id,user_id,status,current_generation,revoked_at,"
            "revocation_reason_code,aggregate_version,created_at,updated_at) VALUES "
            "(%s,%s,'ACTIVE',2,NULL,NULL,1,"
            "transaction_timestamp()-interval '4 hours',transaction_timestamp()),"
            "(%s,%s,'ACTIVE',1,NULL,NULL,1,"
            "transaction_timestamp()-interval '4 hours',transaction_timestamp())",
            (
                facts["family"],
                facts["actor"],
                facts["other_family"],
                facts["actor"],
            ),
        )
        self._insert_session(
            connection,
            session_id=facts["old_session"],
            user_id=facts["actor"],
            family_id=facts["family"],
            generation=1,
            predecessor_session_id=None,
            handle_digest=facts["old_handle"],
            status="REVOKED",
            rotation_reason="LOGIN",
        )
        self._insert_session(
            connection,
            session_id=facts["current_session"],
            user_id=facts["actor"],
            family_id=facts["family"],
            generation=2,
            predecessor_session_id=facts["old_session"],
            handle_digest=facts["current_handle"],
            status="ACTIVE",
            rotation_reason="STEP_UP",
        )
        self._insert_session(
            connection,
            session_id=facts["other_session"],
            user_id=facts["actor"],
            family_id=facts["other_family"],
            generation=1,
            predecessor_session_id=None,
            handle_digest=facts["other_handle"],
            status="ACTIVE",
            rotation_reason="LOGIN",
        )

    @staticmethod
    def _insert_session(
        connection: Any,
        *,
        session_id: object,
        user_id: object,
        family_id: object,
        generation: int,
        predecessor_session_id: Optional[object],
        handle_digest: object,
        status: str,
        rotation_reason: str,
    ) -> None:
        revoked_at_expression = (
            "transaction_timestamp()" if status != "ACTIVE" else "NULL"
        )
        reason_expression = "'TEST_REVOKED'" if status != "ACTIVE" else "NULL"
        connection.execute(
            "INSERT INTO iam.sessions ("
            "id,user_id,family_id,generation,predecessor_session_id,handle_digest,"
            "handle_digest_key_id,csrf_salt,csrf_key_id,csrf_digest,"
            "verified_contact_point_id,verified_at,verified_for_invitation_id,"
            "auth_transaction_id,auth_time,acr_code,amr_codes,created_at,"
            "last_activity_at,idle_expires_at,absolute_expires_at,updated_at,"
            "device_label,status,rotation_reason,revoked_at,revocation_reason_code,"
            "aggregate_version) VALUES ("
            "%s,%s,%s,%s,%s,%s,'session-hmac-v1',%s,'csrf-hmac-v1',%s,"
            "NULL,NULL,NULL,NULL,transaction_timestamp()-interval '3 hours',"
            "'urn:desire:acr:baseline',ARRAY['pwd']::text[],"
            "transaction_timestamp()-interval '2 hours',"
            "transaction_timestamp()-interval '1 hour',"
            "transaction_timestamp()+interval '1 hour',"
            "transaction_timestamp()+interval '22 hours',transaction_timestamp(),"
            "'Browser',%s,%s,"
            + revoked_at_expression
            + ","
            + reason_expression
            + ",1)",
            (
                session_id,
                user_id,
                family_id,
                generation,
                predecessor_session_id,
                handle_digest,
                _digest("csrf-salt-" + str(session_id)),
                _digest("csrf-digest-" + str(session_id)),
                status,
                rotation_reason,
            ),
        )

    def _seed_operational_rows(
        self,
        connection: Any,
        facts: Dict[str, object],
    ) -> None:
        facts.update(
            {
                "receipt": _new_id(),
                "audit_event": _new_id(),
                "outbox_event": _new_id(),
            }
        )
        connection.execute(
            "INSERT INTO infra.command_receipts ("
            "id,principal_kind,principal_id,command_name,command_version,"
            "idempotency_key_digest,idempotency_key_digest_key_id,payload_hash,"
            "payload_hash_key_id,canonicalization_version,target_kind,target_id,"
            "http_method,canonical_path,if_match_version,status,"
            "response_schema_version,safe_response_body,reconstruction_metadata,"
            "created_at,retain_until,completed_at) VALUES ("
            "%s,'USER',%s,'SemanticProbe',1,%s,'receipt-idem-v1',%s,"
            "'receipt-payload-v1','restricted-canonical-json-v1','User',%s,"
            "'POST','/v1/semantic-probe',1,'COMPLETED',1,'{}'::jsonb,NULL,"
            "transaction_timestamp()-interval '1 hour',"
            "transaction_timestamp()+interval '30 days',transaction_timestamp())",
            (
                facts["receipt"],
                facts["actor"],
                _digest("receipt-idem-" + str(facts["receipt"])),
                _digest("receipt-payload-" + str(facts["receipt"])),
                facts["actor"],
            ),
        )
        connection.execute(
            "INSERT INTO audit.audit_events ("
            "event_id,occurred_at,actor_kind,actor_id,original_actor_id,"
            "action_code,target_kind,target_id,organization_id,before_status,"
            "after_status,before_version,after_version,role_code,purpose_code,"
            "reason_code,auth_strength_code,result_code,command_id,correlation_id,"
            "causation_id,trace_id,safe_attributes) VALUES ("
            "%s,transaction_timestamp(),'USER',%s,NULL,'SemanticProbe','User',%s,"
            "NULL,NULL,'ACTIVE',NULL,1,NULL,NULL,NULL,NULL,'SUCCEEDED',"
            "%s,%s,%s,%s,'{}'::jsonb)",
            (
                facts["audit_event"],
                facts["actor"],
                facts["actor"],
                facts["receipt"],
                _new_id(),
                facts["receipt"],
                _new_id(),
            ),
        )
        connection.execute(
            "INSERT INTO infra.outbox_events ("
            "event_id,event_type,schema_version,occurred_at,aggregate_type,"
            "aggregate_id,aggregate_version,actor_kind,actor_id,original_actor_id,"
            "correlation_id,causation_id,trace_id,organization_id,payload,"
            "delivery_status,attempt_count,available_at,lease_owner,lease_until,"
            "published_at,last_error_code,created_at) VALUES ("
            "%s,'UserSemanticProbed',1,transaction_timestamp(),'User',%s,1,"
            "'USER',%s,NULL,%s,%s,%s,NULL,'{}'::jsonb,'PENDING',0,"
            "transaction_timestamp(),NULL,NULL,NULL,NULL,transaction_timestamp())",
            (
                facts["outbox_event"],
                facts["actor"],
                facts["actor"],
                _new_id(),
                facts["receipt"],
                _new_id(),
            ),
        )

    def _seed_full_graph(self) -> Dict[str, object]:
        with self._connect_admin() as connection:
            facts = self._seed_public_policy_graph(connection)
            self._seed_identity_graph(connection, facts)
            self._seed_session_graph(connection, facts)
            self._seed_operational_rows(connection, facts)
        return facts

    def _capture_statement_outcome(
        self,
        statement: object,
        parameters: Sequence[object] = (),
    ) -> Tuple[str, Optional[str]]:
        connection = self._connect_admin()
        try:
            connection.execute(statement, parameters)
            connection.commit()
            return ("COMMITTED", None)
        except psycopg.Error as error:
            connection.rollback()
            return (error.sqlstate or "UNKNOWN", error.diag.constraint_name)
        finally:
            connection.close()

    def test_public_policy_profile_requires_visible_exact_parent_bundle(self) -> None:
        """TEST-DB-RLS-IAM-001.C04: child views inherit parent eligibility."""
        with self._connect_admin() as connection:
            facts = self._seed_public_policy_graph(connection)

        with self._connect_role("iam_app") as connection:
            self._set_context(
                connection,
                {
                    "scope_kind": "PUBLIC_POLICY_READ",
                    "policy_bundle_id": facts["active_bundle"],
                },
            )
            document_cursor = connection.execute(
                "SELECT * FROM iam_api.public_policy_documents_v1"
            )
            active_documents = document_cursor.fetchall()
            document_columns = tuple(item.name for item in document_cursor.description)
            offer_cursor = connection.execute(
                "SELECT * FROM iam_api.public_consent_offers_v1"
            )
            active_offers = offer_cursor.fetchall()
            offer_columns = tuple(item.name for item in offer_cursor.description)
            selector_rows = connection.execute(
                "SELECT selector_digest FROM iam.policy_selectors"
            ).fetchall()
            evidence_rows = connection.execute(
                "SELECT id FROM iam.policy_acceptances"
            ).fetchall()

        self.assertEqual(len(active_documents), 1)
        self.assertEqual(active_documents[0][0], facts["active_bundle"])
        self.assertEqual(active_documents[0][3], facts["active_document"])
        self.assertEqual(
            document_columns,
            (
                "bundle_id",
                "position",
                "required",
                "document_id",
                "kind",
                "locale",
                "semantic_version",
                "canonical_body",
                "content_sha256",
                "legal_effect",
                "jurisdiction",
                "effective_at",
            ),
        )
        self.assertEqual(len(active_offers), 1)
        self.assertEqual(active_offers[0][0], facts["active_bundle"])
        self.assertEqual(active_offers[0][1], facts["active_offer"])
        self.assertEqual(
            offer_columns,
            (
                "bundle_id",
                "consent_offer_id",
                "offer_version",
                "purpose",
                "scope_type",
                "recipient_label",
                "document_id",
                "document_content_sha256",
                "expiry_rule",
                "not_after",
                "canonical_offer_sha256",
                "optional",
            ),
        )
        self.assertNotIn("recipient_ref", offer_columns)
        self.assertNotIn("publication_command_id", offer_columns)
        self.assertEqual(selector_rows, [])
        self.assertEqual(evidence_rows, [])

        with self._connect_role("iam_app") as connection:
            self._set_context(
                connection,
                {
                    "scope_kind": "PUBLIC_POLICY_READ",
                    "policy_bundle_id": facts["draft_bundle"],
                },
            )
            draft_bundle_rows = connection.execute(
                "SELECT id FROM iam.policy_bundles"
            ).fetchall()
            draft_document_rows = connection.execute(
                "SELECT bundle_id,document_id "
                "FROM iam_api.public_policy_documents_v1"
            ).fetchall()
            draft_offer_rows = connection.execute(
                "SELECT bundle_id,consent_offer_id "
                "FROM iam_api.public_consent_offers_v1"
            ).fetchall()

        self.assertEqual(
            (draft_bundle_rows, draft_document_rows, draft_offer_rows),
            ([], [], []),
            "PUBLIC_POLICY_READ leaked child rows for a DRAFT exact bundle",
        )

    def test_sql_public_has_no_iam_privileges_and_is_not_the_public_profile(self) -> None:
        """The SQL pseudo-role PUBLIC remains distinct from anonymous HTTP."""
        with self._connect_admin() as connection:
            schema_public_acl = connection.execute(
                "SELECT namespace.nspname "
                "FROM pg_catalog.pg_namespace AS namespace "
                "CROSS JOIN LATERAL pg_catalog.aclexplode(namespace.nspacl) AS acl "
                "WHERE namespace.nspname = ANY(%s) AND acl.grantee = 0 "
                "ORDER BY namespace.nspname",
                (["iam", "iam_api", "infra", "audit"],),
            ).fetchall()
            relation_public_acl = connection.execute(
                "SELECT namespace.nspname, relation.relname "
                "FROM pg_catalog.pg_class AS relation "
                "JOIN pg_catalog.pg_namespace AS namespace "
                "ON namespace.oid=relation.relnamespace "
                "CROSS JOIN LATERAL pg_catalog.aclexplode(relation.relacl) AS acl "
                "WHERE namespace.nspname = ANY(%s) AND acl.grantee = 0 "
                "ORDER BY namespace.nspname,relation.relname",
                (["iam", "iam_api", "infra", "audit"],),
            ).fetchall()
            function_public_acl = connection.execute(
                "SELECT namespace.nspname, procedure.proname "
                "FROM pg_catalog.pg_proc AS procedure "
                "JOIN pg_catalog.pg_namespace AS namespace "
                "ON namespace.oid=procedure.pronamespace "
                "CROSS JOIN LATERAL pg_catalog.aclexplode(procedure.proacl) AS acl "
                "WHERE namespace.nspname = ANY(%s) AND acl.grantee = 0 "
                "ORDER BY namespace.nspname,procedure.proname",
                (["iam", "iam_api", "infra", "audit"],),
            ).fetchall()
            app_view_grants = connection.execute(
                "SELECT table_schema,table_name,privilege_type "
                "FROM information_schema.role_table_grants "
                "WHERE grantee='iam_app' AND table_schema='iam_api' "
                "AND table_name IN "
                "('public_policy_documents_v1','public_consent_offers_v1') "
                "ORDER BY table_name,privilege_type"
            ).fetchall()

        self.assertEqual(schema_public_acl, [])
        self.assertEqual(relation_public_acl, [])
        self.assertEqual(function_public_acl, [])
        self.assertEqual(
            app_view_grants,
            [
                ("iam_api", "public_consent_offers_v1", "SELECT"),
                ("iam_api", "public_policy_documents_v1", "SELECT"),
            ],
        )

    def _read_self_summary(
        self,
        *,
        actor_id: object,
        session_id: object,
    ) -> Tuple[str, Tuple[str, ...], list]:
        with self._connect_role("iam_app") as connection:
            self._set_context(
                connection,
                {
                    "scope_kind": "SELF",
                    "operation": "ME_SELF_SUMMARY",
                    "actor_user_id": actor_id,
                    "session_id": session_id,
                },
            )
            try:
                cursor = connection.execute(
                    "SELECT * FROM iam_api.read_me_self_summary()"
                )
                return (
                    "OK",
                    tuple(item.name for item in cursor.description),
                    cursor.fetchall(),
                )
            except psycopg.Error as error:
                return (error.sqlstate or "UNKNOWN", (), [])

    def test_self_summary_function_executes_with_its_reviewed_column_grants(self) -> None:
        """The SECURITY DEFINER projection must not fail at relation privilege."""
        facts = self._seed_full_graph()
        outcome, columns, rows = self._read_self_summary(
            actor_id=facts["actor"],
            session_id=facts["current_session"],
        )
        self.assertEqual(
            outcome,
            "OK",
            "read_me_self_summary() lacks a column privilege required by its "
            "reviewed SQL body",
        )
        self.assertEqual(columns, SELF_SUMMARY_COLUMNS)
        self.assertGreaterEqual(len(rows), 1)

    def test_self_summary_uses_exact_session_and_excludes_suspended_scopes(self) -> None:
        """TEST-DB-RLS-IAM-001.C02: closed allowlist and ACTIVE scopes only."""
        facts = self._seed_full_graph()

        wrong_outcome, wrong_columns, wrong_rows = self._read_self_summary(
            actor_id=facts["actor"],
            session_id=_new_id(),
        )
        self.assertEqual(wrong_outcome, "OK")
        self.assertEqual(wrong_columns, SELF_SUMMARY_COLUMNS)
        self.assertEqual(wrong_rows, [])

        outcome, columns, rows = self._read_self_summary(
            actor_id=facts["actor"],
            session_id=facts["current_session"],
        )
        expected = [
            (
                facts["actor"],
                "ACTIVE",
                "active_actor",
                1,
                facts["active_membership"],
                "ACTIVE",
                1,
                ["ORG_ADMIN"],
                facts["active_org"],
                "Active Org",
                "BUSINESS",
                "ACTIVE",
                1,
            )
        ]
        self.assertEqual(outcome, "OK")
        self.assertEqual(columns, SELF_SUMMARY_COLUMNS)
        self.assertEqual(
            rows,
            expected,
            "self-summary included SUSPENDED membership/organization scope",
        )

    def test_self_summary_rejects_suspended_user_even_with_live_session(self) -> None:
        """A stale ACTIVE session cannot reopen a SUSPENDED User projection."""
        facts = self._seed_full_graph()
        with self._connect_admin() as connection:
            connection.execute(
                "UPDATE iam.users SET status='SUSPENDED',"
                "aggregate_version=aggregate_version+1,"
                "updated_at=transaction_timestamp() WHERE id=%s",
                (facts["actor"],),
            )

        outcome, columns, rows = self._read_self_summary(
            actor_id=facts["actor"],
            session_id=facts["current_session"],
        )
        self.assertEqual(outcome, "OK")
        self.assertEqual(columns, SELF_SUMMARY_COLUMNS)
        self.assertEqual(
            rows,
            [],
            "self-summary returned a SUSPENDED User through a still-live session",
        )

    def test_session_authenticator_exact_digest_view_and_table_denylist(self) -> None:
        """TEST-DB-RLS-IAM-001.C00: exact cookie facts and no business reads."""
        facts = self._seed_full_graph()
        with self._connect_role("iam_session_authenticator") as connection:
            self._set_context(
                connection,
                {
                    "scope_kind": "SESSION_AUTHENTICATE",
                    "operation": "RESOLVE_COOKIE",
                    "session_handle_digest_key_id": "session-hmac-v1",
                    "session_handle_digest": bytes(facts["current_handle"]).hex(),
                    "session_id": facts["other_session"],
                    "session_family_id": facts["other_family"],
                    "actor_user_id": facts["other_user"],
                },
            )
            cursor = connection.execute(
                "SELECT *,"
                "generation=current_generation AS is_current_generation,"
                "transaction_timestamp()<idle_expires_at AS idle_valid,"
                "transaction_timestamp()<absolute_expires_at AS absolute_valid "
                "FROM iam_api.resolve_cookie_session_v1"
            )
            rows = cursor.fetchall()
            columns = tuple(item.name for item in cursor.description)

        self.assertEqual(columns[: len(COOKIE_VIEW_COLUMNS)], COOKIE_VIEW_COLUMNS)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], facts["current_session"])
        self.assertEqual(rows[0][2], facts["family"])
        self.assertEqual(rows[0][4], "ACTIVE")
        self.assertEqual(rows[0][21], "ACTIVE")
        self.assertEqual(rows[0][3], rows[0][22])
        self.assertEqual(rows[0][-3:], (True, True, True))

        with self._connect_role("iam_session_authenticator") as connection:
            self._set_context(
                connection,
                {
                    "scope_kind": "SESSION_AUTHENTICATE",
                    "operation": "RESOLVE_COOKIE",
                    "session_handle_digest_key_id": "wrong-key",
                    "session_handle_digest": bytes(facts["current_handle"]).hex(),
                    "session_id": facts["current_session"],
                    "session_family_id": facts["family"],
                    "actor_user_id": facts["actor"],
                },
            )
            wrong_key_rows = connection.execute(
                "SELECT session_id FROM iam_api.resolve_cookie_session_v1"
            ).fetchall()
        self.assertEqual(wrong_key_rows, [])

        forbidden_queries = (
            "SELECT id FROM iam.users LIMIT 1",
            "SELECT id FROM iam.organizations LIMIT 1",
            "SELECT selector_digest FROM iam.policy_selectors LIMIT 1",
            "SELECT id FROM infra.command_receipts LIMIT 1",
            "SELECT event_id FROM audit.audit_events LIMIT 1",
            "SELECT event_id FROM infra.outbox_events LIMIT 1",
        )
        outcomes = []
        for statement in forbidden_queries:
            with self._connect_role(
                "iam_session_authenticator", autocommit=True
            ) as connection:
                try:
                    rows = connection.execute(statement).fetchall()
                    outcomes.append("VISIBLE" if rows else "EMPTY")
                except psycopg.Error as error:
                    outcomes.append(error.sqlstate)
        # IAM0024 deliberately grants only ``users.id/status`` so the
        # security-invoker cookie view can resolve an exact digest. Without
        # the exact Session digest context, FORCE RLS makes that direct read
        # empty; every other business table remains privilege-denied.
        self.assertEqual(
            outcomes,
            ["EMPTY"] + ["42501"] * (len(forbidden_queries) - 1),
        )

    def test_replay_scope_cannot_be_forged_with_arbitrary_family_and_dummy_handle(self) -> None:
        """Old-handle replay authority must derive from an exact revoked handle."""
        facts = self._seed_full_graph()
        with self._connect_role("iam_session_authenticator") as connection:
            self._set_context(
                connection,
                {
                    "scope_kind": "SESSION_AUTHENTICATE",
                    "operation": "REVOKE_REPLAYED_FAMILY",
                    "actor_user_id": facts["actor"],
                    "session_id": _new_id(),
                    "session_family_id": facts["other_family"],
                    "session_handle_digest_key_id": "dummy-key",
                    "session_handle_digest": _digest("dummy-handle").hex(),
                },
            )
            forged_reads = connection.execute(
                "SELECT id FROM iam.sessions ORDER BY id"
            ).fetchall()
            try:
                forged_updates = connection.execute(
                    "UPDATE iam.sessions SET aggregate_version=aggregate_version+1,"
                    "updated_at=updated_at+interval '1 microsecond' "
                    "WHERE family_id=%s RETURNING id",
                    (facts["other_family"],),
                ).fetchall()
            except psycopg.Error as error:
                forged_updates = [(error.sqlstate,)]
            connection.rollback()

        self.assertEqual(
            forged_reads,
            [],
            "replay scope accepted arbitrary family/session IDs without an exact "
            "revoked digest+key match",
        )
        self.assertIn(forged_updates, ([], [("42501",)]))

    def test_exact_revoked_handle_sees_only_its_own_replay_family(self) -> None:
        """A legitimate replay handle reaches its family and no adjacent family."""
        facts = self._seed_full_graph()
        with self._connect_role("iam_session_authenticator") as connection:
            self._set_context(
                connection,
                {
                    "scope_kind": "SESSION_AUTHENTICATE",
                    "operation": "REVOKE_REPLAYED_FAMILY",
                    "actor_user_id": facts["actor"],
                    "session_id": facts["old_session"],
                    "session_family_id": facts["family"],
                    "session_handle_digest_key_id": "session-hmac-v1",
                    "session_handle_digest": bytes(facts["old_handle"]).hex(),
                },
            )
            family_rows = connection.execute(
                "SELECT id FROM iam.session_families ORDER BY id"
            ).fetchall()
            session_rows = connection.execute(
                "SELECT id FROM iam.sessions ORDER BY id"
            ).fetchall()

        self.assertEqual(family_rows, [(facts["family"],)])
        self.assertEqual(
            {row[0] for row in session_rows},
            {facts["old_session"], facts["current_session"]},
        )

    def test_onboarding_context_rejects_cross_user_and_cross_org_forgery(self) -> None:
        """TEST-AUTH-ONBOARDING-001.DB01: all ACCEPT facts bind together."""
        facts = self._seed_full_graph()
        with self._connect_role("iam_onboarding") as connection:
            self._set_context(
                connection,
                {
                    "scope_kind": "AUTH_PROTOCOL",
                    "operation": "ACCEPT",
                    "actor_user_id": facts["other_user"],
                    "target_user_id": facts["other_user"],
                    "target_invitation_id": facts["active_membership_invitation"],
                    "organization_id": facts["second_active_org"],
                    "session_id": _new_id(),
                    "session_family_id": _new_id(),
                    "auth_transaction_id": _new_id(),
                    "command_id": _new_id(),
                },
            )
            user_rows = connection.execute(
                "SELECT id FROM iam.users ORDER BY id"
            ).fetchall()
            organization_rows = connection.execute(
                "SELECT id FROM iam.organizations ORDER BY id"
            ).fetchall()
            invitation_rows = connection.execute(
                "SELECT id FROM iam.access_invitations ORDER BY id"
            ).fetchall()

        self.assertEqual(
            (user_rows, organization_rows, invitation_rows),
            ([], [], []),
            "AUTH_PROTOCOL ACCEPT GUCs were not tied to one exact "
            "Invitation/Session/AuthTransaction/User/Organization graph",
        )

    def test_all_25_tables_force_rls_and_no_scope_direct_sql_is_fail_closed(self) -> None:
        """Catalog flags plus online-role SELECT/UPDATE/DELETE behavior."""
        self._seed_full_graph()
        with self._connect_admin() as connection:
            forced = connection.execute(
                "SELECT namespace.nspname,relation.relname "
                "FROM pg_catalog.pg_class AS relation "
                "JOIN pg_catalog.pg_namespace AS namespace "
                "ON namespace.oid=relation.relnamespace "
                "WHERE (namespace.nspname,relation.relname) IN ("
                "SELECT * FROM unnest(%s::text[],%s::text[])) "
                "AND relation.relrowsecurity AND relation.relforcerowsecurity",
                (
                    [item[0] for item in RLS_RELATIONS],
                    [item[1] for item in RLS_RELATIONS],
                ),
            ).fetchall()
            first_columns = dict(
                connection.execute(
                    "SELECT namespace.nspname||'.'||relation.relname,attribute.attname "
                    "FROM pg_catalog.pg_class AS relation "
                    "JOIN pg_catalog.pg_namespace AS namespace "
                    "ON namespace.oid=relation.relnamespace "
                    "JOIN LATERAL ("
                    "SELECT candidate.attname FROM pg_catalog.pg_attribute AS candidate "
                    "WHERE candidate.attrelid=relation.oid AND candidate.attnum>0 "
                    "AND NOT candidate.attisdropped ORDER BY candidate.attnum LIMIT 1"
                    ") AS attribute ON true "
                    "WHERE (namespace.nspname,relation.relname) IN ("
                    "SELECT * FROM unnest(%s::text[],%s::text[]))",
                    (
                        [item[0] for item in RLS_RELATIONS],
                        [item[1] for item in RLS_RELATIONS],
                    ),
                ).fetchall()
            )
        self.assertEqual(set(forced), set(RLS_RELATIONS))

        violations = []
        metadata_readers = {
            "iam_app",
            "iam_session_authenticator",
            "iam_onboarding",
            "iam_system",
        }
        for role in ONLINE_ROLES:
            for schema_name, table_name in RLS_RELATIONS:
                relation_key = schema_name + "." + table_name
                column_name = first_columns[relation_key]
                select_outcome = self._probe_role_statement(
                    role,
                    sql.SQL("SELECT {} FROM {}.{} LIMIT 2").format(
                        sql.Identifier(column_name),
                        sql.Identifier(schema_name),
                        sql.Identifier(table_name),
                    ),
                    fetch=True,
                )
                expected_singleton = (
                    relation_key == "infra.iam_receipt_key_policy"
                    and role in metadata_readers
                )
                if expected_singleton:
                    if not (
                        select_outcome[0] == "ROWS"
                        and len(select_outcome[1]) == 1
                    ):
                        violations.append((role, relation_key, "SELECT", select_outcome))
                elif not (
                    select_outcome[0] == "42501"
                    or (select_outcome[0] == "ROWS" and select_outcome[1] == [])
                ):
                    violations.append((role, relation_key, "SELECT", select_outcome))

                update_outcome = self._probe_role_statement(
                    role,
                    sql.SQL("UPDATE {}.{} SET {}={} RETURNING {}").format(
                        sql.Identifier(schema_name),
                        sql.Identifier(table_name),
                        sql.Identifier(column_name),
                        sql.Identifier(column_name),
                        sql.Identifier(column_name),
                    ),
                    fetch=True,
                )
                if not (
                    update_outcome[0] == "42501"
                    or (update_outcome[0] == "ROWS" and update_outcome[1] == [])
                ):
                    violations.append((role, relation_key, "UPDATE", update_outcome))

                delete_outcome = self._probe_role_statement(
                    role,
                    sql.SQL("DELETE FROM {}.{} RETURNING {}").format(
                        sql.Identifier(schema_name),
                        sql.Identifier(table_name),
                        sql.Identifier(column_name),
                    ),
                    fetch=True,
                )
                if not (
                    delete_outcome[0] == "42501"
                    or (delete_outcome[0] == "ROWS" and delete_outcome[1] == [])
                ):
                    violations.append((role, relation_key, "DELETE", delete_outcome))

        self.assertEqual(violations, [])

    def _probe_role_statement(
        self,
        role: str,
        statement: object,
        *,
        fetch: bool,
    ) -> Tuple[str, object]:
        with self._connect_role(role, autocommit=True) as connection:
            try:
                cursor = connection.execute(statement)
                return ("ROWS", cursor.fetchall() if fetch else cursor.rowcount)
            except psycopg.Error as error:
                return (error.sqlstate or "UNKNOWN", error.diag.constraint_name)

    def test_audit_receipt_and_outbox_triggers_enforce_immutable_facts(self) -> None:
        """TEST-EVENT-AUDIT-IAM-001.C01: history/envelopes cannot be rewritten."""
        facts = self._seed_full_graph()
        audit_update = self._capture_statement_outcome(
            "UPDATE audit.audit_events SET result_code='REWRITTEN' "
            "WHERE event_id=%s",
            (facts["audit_event"],),
        )
        audit_delete = self._capture_statement_outcome(
            "DELETE FROM audit.audit_events WHERE event_id=%s",
            (facts["audit_event"],),
        )
        receipt_identity_update = self._capture_statement_outcome(
            "UPDATE infra.command_receipts SET target_id=%s WHERE id=%s",
            (_new_id(), facts["receipt"]),
        )
        receipt_completed_update = self._capture_statement_outcome(
            "UPDATE infra.command_receipts SET safe_response_body="
            "'{\"rewritten\":true}'::jsonb WHERE id=%s",
            (facts["receipt"],),
        )
        outbox_payload_update = self._capture_statement_outcome(
            "UPDATE infra.outbox_events SET payload='{\"rewritten\":true}'::jsonb "
            "WHERE event_id=%s",
            (facts["outbox_event"],),
        )
        outbox_delete = self._capture_statement_outcome(
            "DELETE FROM infra.outbox_events WHERE event_id=%s",
            (facts["outbox_event"],),
        )

        self.assertEqual(
            audit_update,
            ("23514", "trg_audit_event_append_only"),
        )
        self.assertEqual(
            audit_delete,
            ("23514", "trg_audit_event_append_only"),
        )
        self.assertEqual(
            receipt_identity_update,
            ("23514", "trg_command_receipt_transition"),
        )
        self.assertEqual(
            receipt_completed_update,
            ("23514", "trg_command_receipt_transition"),
        )
        self.assertEqual(
            outbox_payload_update,
            ("23514", "trg_outbox_envelope_immutable"),
        )
        self.assertEqual(
            outbox_delete,
            ("23514", "trg_outbox_envelope_immutable"),
        )

        connection = self._connect_admin()
        try:
            lease_token = _new_id()
            cursor = connection.execute(
                "UPDATE infra.outbox_events SET delivery_status='LEASED',"
                "attempt_count=attempt_count+1,lease_owner='semantic-worker',"
                "leased_at=transaction_timestamp(),lease_token=%s,"
                "lease_until=transaction_timestamp()+interval '5 minutes' "
                "WHERE event_id=%s RETURNING event_id",
                (lease_token, facts["outbox_event"]),
            )
            transport_rows = cursor.fetchall()
            connection.rollback()
        finally:
            connection.close()
        self.assertEqual(transport_rows, [(facts["outbox_event"],)])

    def test_composite_fk_and_partial_unique_constraints_reject_mixed_graphs(self) -> None:
        """Contact non-unique plus invitation/session/role exact composite facts."""
        facts = self._seed_full_graph()

        with self._connect_admin() as connection:
            duplicate_contact = _new_id()
            connection.execute(
                "INSERT INTO iam.contact_points ("
                "id,user_id,contact_type,locator_ciphertext,locator_encryption_key_id,"
                "locator_encryption_algorithm,binding_digest,binding_digest_key_id,"
                "verified_at,retention_until,created_at,updated_at) "
                "SELECT %s,user_id,contact_type,locator_ciphertext,"
                "locator_encryption_key_id,locator_encryption_algorithm,"
                "binding_digest,binding_digest_key_id,verified_at,retention_until,"
                "created_at,updated_at FROM iam.contact_points WHERE id=%s",
                (duplicate_contact, facts["contact"]),
            )
            duplicate_count = connection.execute(
                "SELECT count(*) FROM iam.contact_points AS candidate "
                "JOIN iam.contact_points AS original "
                "ON candidate.contact_type=original.contact_type "
                "AND candidate.binding_digest_key_id=original.binding_digest_key_id "
                "AND candidate.binding_digest=original.binding_digest "
                "WHERE original.id=%s",
                (facts["contact"],),
            ).fetchone()[0]
        self.assertEqual(duplicate_count, 2)

        invitation_selector_mismatch = self._capture_statement_outcome(
            "INSERT INTO iam.access_invitations ("
            "id,purpose,organization_id,target_scope,target_role,is_initial_admin,"
            "recipient_contact_id,masked_recipient_label,policy_selector_digest,"
            "issued_policy_bundle_id,status,expires_at,issuer_kind,issuer_user_id,"
            "token_nonce,token_key_id,accepted_by_user_id,terminal_at,"
            "terminal_reason_code,aggregate_version,created_at,updated_at) "
            "SELECT %s,purpose,organization_id,target_scope,target_role,"
            "is_initial_admin,recipient_contact_id,masked_recipient_label,"
            "policy_selector_digest,%s,status,expires_at,issuer_kind,issuer_user_id,"
            "token_nonce,token_key_id,accepted_by_user_id,terminal_at,"
            "terminal_reason_code,aggregate_version,created_at,updated_at "
            "FROM iam.access_invitations WHERE id=%s",
            (
                _new_id(),
                facts["active_bundle"],
                facts["active_membership_invitation"],
            ),
        )
        self.assertEqual(
            invitation_selector_mismatch,
            ("23503", "fk_invitation_issued_bundle_selector"),
        )

        auth_contact_mismatch = self._capture_statement_outcome(
            "INSERT INTO iam.auth_transactions ("
            "id,status,purpose,attempt,protocol_version,browser_binding_digest,"
            "browser_binding_key_id,initiating_session_id,initiating_user_id,"
            "expected_user_id,invitation_id,invitation_version,"
            "expected_contact_point_id,state_digest,state_digest_key_id,"
            "nonce_digest,nonce_digest_key_id,pkce_verifier_ciphertext,"
            "pkce_encryption_key_id,pkce_encryption_algorithm,redirect_uri,"
            "provider_error_class,deadline,succeeded_at,created_at,updated_at) "
            "VALUES (%s,'PENDING','ENROLLMENT',0,1,%s,'browser-hmac-v1',"
            "NULL,NULL,NULL,%s,2,%s,%s,'state-hmac-v1',%s,'nonce-hmac-v1',"
            "%s,'pkce-aead-v1','AES_256_GCM_V1','https://app.invalid/callback',"
            "NULL,transaction_timestamp()+interval '10 minutes',NULL,"
            "transaction_timestamp(),transaction_timestamp())",
            (
                _new_id(),
                _digest("browser-mismatch-" + uuid.uuid4().hex),
                facts["active_membership_invitation"],
                facts["other_contact"],
                _digest("state-mismatch-" + uuid.uuid4().hex),
                _digest("nonce-mismatch-" + uuid.uuid4().hex),
                b"encrypted-pkce",
            ),
        )
        self.assertEqual(
            auth_contact_mismatch,
            ("23503", "fk_auth_transaction_invitation_contact"),
        )

        cross_family_predecessor = self._capture_statement_outcome(
            "INSERT INTO iam.sessions ("
            "id,user_id,family_id,generation,predecessor_session_id,handle_digest,"
            "handle_digest_key_id,csrf_salt,csrf_key_id,csrf_digest,"
            "verified_contact_point_id,verified_at,verified_for_invitation_id,"
            "auth_transaction_id,auth_time,acr_code,amr_codes,created_at,"
            "last_activity_at,idle_expires_at,absolute_expires_at,updated_at,"
            "device_label,status,rotation_reason,revoked_at,revocation_reason_code,"
            "aggregate_version) SELECT "
            "%s,user_id,%s,2,%s,%s,handle_digest_key_id,%s,csrf_key_id,%s,"
            "NULL,NULL,NULL,NULL,auth_time,acr_code,amr_codes,created_at,"
            "last_activity_at,idle_expires_at,absolute_expires_at,updated_at,"
            "device_label,'REVOKED','STEP_UP',transaction_timestamp(),"
            "'TEST_REVOKED',1 FROM iam.sessions WHERE id=%s",
            (
                _new_id(),
                facts["other_family"],
                facts["current_session"],
                _digest("cross-family-handle-" + uuid.uuid4().hex),
                _digest("cross-family-salt-" + uuid.uuid4().hex),
                _digest("cross-family-csrf-" + uuid.uuid4().hex),
                facts["current_session"],
            ),
        )
        self.assertEqual(
            cross_family_predecessor,
            ("23503", "fk_session_predecessor_family"),
        )

        cross_org_role_source = self._capture_statement_outcome(
            "INSERT INTO iam.membership_role_grants ("
            "id,organization_id,membership_id,user_id,role_code,"
            "source_invitation_id,policy_selector_digest,granted_by_kind,"
            "granted_by_id,granted_at,revoked_at,revocation_reason_code,"
            "aggregate_version) VALUES ("
            "%s,%s,%s,%s,'ORG_ADMIN',%s,%s,'SYSTEM',%s,"
            "transaction_timestamp(),transaction_timestamp(),'TEST_REVOKED',1)",
            (
                _new_id(),
                facts["active_org"],
                facts["active_membership"],
                facts["actor"],
                facts["unused_cross_org_invitation"],
                facts["draft_selector"],
                _new_id(),
            ),
        )
        self.assertEqual(
            cross_org_role_source,
            ("23503", "fk_membership_role_source"),
        )

        second_active_role = self._capture_statement_outcome(
            "INSERT INTO iam.membership_role_grants ("
            "id,organization_id,membership_id,user_id,role_code,"
            "source_invitation_id,policy_selector_digest,granted_by_kind,"
            "granted_by_id,granted_at,revoked_at,revocation_reason_code,"
            "aggregate_version) VALUES ("
            "%s,%s,%s,%s,'ORG_ADMIN',%s,%s,'SYSTEM',%s,"
            "transaction_timestamp(),NULL,NULL,1)",
            (
                _new_id(),
                facts["active_org"],
                facts["active_membership"],
                facts["actor"],
                facts["unused_same_org_invitation"],
                facts["draft_selector"],
                _new_id(),
            ),
        )
        self.assertEqual(
            second_active_role,
            ("23505", "ux_membership_role_active"),
        )

        second_active_session = self._capture_statement_outcome(
            "INSERT INTO iam.sessions ("
            "id,user_id,family_id,generation,predecessor_session_id,handle_digest,"
            "handle_digest_key_id,csrf_salt,csrf_key_id,csrf_digest,"
            "verified_contact_point_id,verified_at,verified_for_invitation_id,"
            "auth_transaction_id,auth_time,acr_code,amr_codes,created_at,"
            "last_activity_at,idle_expires_at,absolute_expires_at,updated_at,"
            "device_label,status,rotation_reason,revoked_at,revocation_reason_code,"
            "aggregate_version) SELECT "
            "%s,user_id,family_id,3,%s,%s,handle_digest_key_id,%s,csrf_key_id,%s,"
            "NULL,NULL,NULL,NULL,auth_time,acr_code,amr_codes,created_at,"
            "last_activity_at,idle_expires_at,absolute_expires_at,updated_at,"
            "device_label,'ACTIVE','STEP_UP',NULL,NULL,1 "
            "FROM iam.sessions WHERE id=%s",
            (
                _new_id(),
                facts["current_session"],
                _digest("second-active-handle-" + uuid.uuid4().hex),
                _digest("second-active-salt-" + uuid.uuid4().hex),
                _digest("second-active-csrf-" + uuid.uuid4().hex),
                facts["current_session"],
            ),
        )
        self.assertEqual(
            second_active_session,
            ("23505", "ux_session_one_active_family"),
        )

    def test_deferred_session_family_insert_reports_constraint_semantics(self) -> None:
        """IAM36 permits an active family to have zero active sessions."""
        facts = self._seed_full_graph()
        family_connection = self._connect_admin()
        try:
            family_connection.execute(
                "INSERT INTO iam.session_families ("
                "id,user_id,status,current_generation,revoked_at,"
                "revocation_reason_code,aggregate_version,created_at,updated_at) "
                "VALUES (%s,%s,'ACTIVE',1,NULL,NULL,1,"
                "transaction_timestamp(),transaction_timestamp())",
                (_new_id(), facts["actor"]),
            )
            family_insert_was_deferred = True
            try:
                family_connection.execute("SET CONSTRAINTS ALL IMMEDIATE")
                family_outcome = ("COMMITTED", None)
            except psycopg.Error as error:
                family_outcome = (error.sqlstate, error.diag.constraint_name)
            family_connection.rollback()
        finally:
            family_connection.close()
        self.assertTrue(family_insert_was_deferred)
        self.assertEqual(
            family_outcome,
            ("COMMITTED", None),
        )

    def test_deferred_policy_publication_cycle_rejects_missing_required_artifact(
        self,
    ) -> None:
        """The circular selector/bundle FK waits, then final consistency rejects."""
        self._seed_full_graph()
        publication_connection = self._connect_admin()
        publication_bundle = _new_id()
        publication_selector = _digest("inconsistent-selector-" + uuid.uuid4().hex)
        try:
            publication_connection.execute(
                "INSERT INTO iam.policy_selectors ("
                "selector_digest,canonicalization_version,access_purpose,scope_type,"
                "target_role,jurisdiction,locale,current_bundle_id,"
                "aggregate_version,created_at,updated_at) VALUES ("
                "%s,'policy-selector-json-v1','ORGANIZATION_MEMBERSHIP',"
                "'ORGANIZATION_ROLE','DEMAND_OWNER','CN','zh-CN',%s,1,"
                "transaction_timestamp(),transaction_timestamp())",
                (publication_selector, publication_bundle),
            )
            publication_connection.execute(
                "INSERT INTO iam.policy_bundles ("
                "id,selector_digest,status,effective_at,effective_until,"
                "superseded_by_bundle_id,release_manifest_sha256,release_signature,"
                "release_signing_key_id,publication_command_id,aggregate_version,"
                "created_at,updated_at) VALUES ("
                "%s,%s,'ACTIVE',transaction_timestamp(),NULL,NULL,%s,%s,"
                "'policy-signing-v1',%s,1,transaction_timestamp(),"
                "transaction_timestamp())",
                (
                    publication_bundle,
                    publication_selector,
                    _digest("inconsistent-manifest-" + uuid.uuid4().hex),
                    b"signature",
                    _new_id(),
                ),
            )
            publication_cycle_inserted = True
            try:
                publication_connection.execute("SET CONSTRAINTS ALL IMMEDIATE")
                publication_outcome = ("COMMITTED", None)
            except psycopg.Error as error:
                publication_outcome = (error.sqlstate, error.diag.constraint_name)
            publication_connection.rollback()
        finally:
            publication_connection.close()
        self.assertTrue(publication_cycle_inserted)
        self.assertEqual(
            publication_outcome,
            ("23514", "trg_policy_publication_consistent"),
        )

    def test_deferred_activation_rejects_cross_user_invitation_source(self) -> None:
        """Activation source validation runs against the final transaction graph."""
        facts = self._seed_full_graph()
        activation_connection = self._connect_admin()
        try:
            activation_connection.execute(
                "INSERT INTO iam.memberships ("
                "id,organization_id,user_id,status,source_invitation_id,"
                "aggregate_version,created_at,updated_at) VALUES ("
                "%s,%s,%s,'ACTIVE',%s,1,transaction_timestamp(),"
                "transaction_timestamp())",
                (
                    _new_id(),
                    facts["active_org"],
                    facts["other_user"],
                    facts["unused_same_org_invitation"],
                ),
            )
            activation_insert_was_deferred = True
            try:
                activation_connection.execute("SET CONSTRAINTS ALL IMMEDIATE")
                activation_outcome = ("COMMITTED", None)
            except psycopg.Error as error:
                activation_outcome = (error.sqlstate, error.diag.constraint_name)
            activation_connection.rollback()
        finally:
            activation_connection.close()
        self.assertTrue(activation_insert_was_deferred)
        self.assertEqual(
            activation_outcome,
            ("23514", "trg_activation_matches_accepted_invitation"),
        )

    def test_two_transactions_claim_at_most_one_receipt(self) -> None:
        """TEST-DB-IAM-RECEIPT-001.C02 uses a real speculative unique wait."""
        facts = self._seed_full_graph()
        receipt_identity = {
            "principal": facts["actor"],
            "digest": _digest("concurrent-receipt-" + uuid.uuid4().hex),
            "payload": _digest("concurrent-payload-" + uuid.uuid4().hex),
        }
        receipt_barrier = threading.Barrier(2)
        receipt_ids = (_new_id(), _new_id())
        with ThreadPoolExecutor(max_workers=2) as executor:
            receipt_outcomes = tuple(
                executor.map(
                    lambda receipt_id: self._race_receipt_claim(
                        barrier=receipt_barrier,
                        receipt_id=receipt_id,
                        identity=receipt_identity,
                    ),
                    receipt_ids,
                )
            )
        self.assertEqual(
            sorted(item[0] for item in receipt_outcomes),
            ["CLAIMED", "REPLAYED"],
        )
        self.assertTrue(all(item[1] == "COMPLETED" for item in receipt_outcomes))
        with self._connect_admin() as connection:
            receipt_rows = connection.execute(
                "SELECT id,status FROM infra.command_receipts "
                "WHERE principal_kind='USER' AND principal_id=%s "
                "AND command_name='ConcurrentSemanticProbe' "
                "AND command_version=1 AND idempotency_key_digest=%s",
                (receipt_identity["principal"], receipt_identity["digest"]),
            ).fetchall()
        self.assertEqual(len(receipt_rows), 1)
        self.assertEqual(receipt_rows[0][1], "COMPLETED")

    def test_two_transactions_accept_at_most_one_invitation(self) -> None:
        """TEST-DB-IAM-004.C04: one terminal Invitation CAS wins."""
        facts = self._seed_full_graph()
        issued_invitation = _new_id()
        with self._connect_admin() as connection:
            self._insert_issued_invitation(
                connection,
                invitation_id=issued_invitation,
                facts=facts,
            )
        invitation_barrier = threading.Barrier(2)
        with ThreadPoolExecutor(max_workers=2) as executor:
            invitation_outcomes = tuple(
                executor.map(
                    lambda actor_id: self._race_invitation_accept(
                        barrier=invitation_barrier,
                        invitation_id=issued_invitation,
                        actor_id=actor_id,
                    ),
                    (facts["actor"], facts["other_user"]),
                )
            )
        self.assertEqual(sorted(invitation_outcomes), ["ACCEPTED", "LOST"])
        with self._connect_admin() as connection:
            invitation_row = connection.execute(
                "SELECT status,accepted_by_user_id,aggregate_version "
                "FROM iam.access_invitations WHERE id=%s",
                (issued_invitation,),
            ).fetchone()
        self.assertEqual(invitation_row[0], "ACCEPTED")
        self.assertIn(invitation_row[1], (facts["actor"], facts["other_user"]))
        self.assertEqual(invitation_row[2], 2)

    def test_two_transactions_create_at_most_one_session_successor(self) -> None:
        """TEST-DB-SESSION-001.C01: one predecessor rotation can commit."""
        facts = self._seed_full_graph()
        successor_family, predecessor = self._seed_single_active_session(facts)
        successor_barrier = threading.Barrier(2)
        successor_ids = (_new_id(), _new_id())
        with ThreadPoolExecutor(max_workers=2) as executor:
            successor_outcomes = tuple(
                executor.map(
                    lambda successor_id: self._race_session_successor(
                        barrier=successor_barrier,
                        family_id=successor_family,
                        predecessor_id=predecessor,
                        user_id=facts["actor"],
                        successor_id=successor_id,
                    ),
                    successor_ids,
                )
            )
        self.assertEqual(
            sorted(item[0] for item in successor_outcomes),
            ["LOST", "SUCCEEDED"],
        )
        with self._connect_admin() as connection:
            session_rows = connection.execute(
                "SELECT generation,status,predecessor_session_id "
                "FROM iam.sessions WHERE family_id=%s ORDER BY generation",
                (successor_family,),
            ).fetchall()
            family_row = connection.execute(
                "SELECT current_generation,status FROM iam.session_families "
                "WHERE id=%s",
                (successor_family,),
            ).fetchone()
        self.assertEqual(
            session_rows,
            [(1, "REVOKED", None), (2, "ACTIVE", predecessor)],
        )
        self.assertEqual(family_row, (2, "ACTIVE"))

    def _race_receipt_claim(
        self,
        *,
        barrier: threading.Barrier,
        receipt_id: uuid.UUID,
        identity: Dict[str, object],
    ) -> Tuple[str, str]:
        connection = self._connect_admin()
        try:
            connection.execute("SET LOCAL lock_timeout='5s'")
            barrier.wait(timeout=10)
            returned = connection.execute(
                "INSERT INTO infra.command_receipts ("
                "id,principal_kind,principal_id,command_name,command_version,"
                "idempotency_key_digest,idempotency_key_digest_key_id,payload_hash,"
                "payload_hash_key_id,canonicalization_version,target_kind,target_id,"
                "http_method,canonical_path,if_match_version,status,"
                "response_schema_version,safe_response_body,reconstruction_metadata,"
                "created_at,retain_until,completed_at) VALUES ("
                "%s,'USER',%s,'ConcurrentSemanticProbe',1,%s,'receipt-idem-v1',"
                "%s,'receipt-payload-v1','restricted-canonical-json-v1','User',%s,"
                "'POST','/v1/concurrent-semantic-probe',1,'IN_PROGRESS',NULL,NULL,"
                "NULL,transaction_timestamp(),"
                "transaction_timestamp()+interval '30 days',NULL) "
                "ON CONFLICT DO NOTHING RETURNING id",
                (
                    receipt_id,
                    identity["principal"],
                    identity["digest"],
                    identity["payload"],
                    identity["principal"],
                ),
            ).fetchone()
            if returned is not None:
                connection.execute(
                    "UPDATE infra.command_receipts SET status='COMPLETED',"
                    "response_schema_version=1,safe_response_body='{}'::jsonb,"
                    "completed_at=transaction_timestamp() WHERE id=%s",
                    (receipt_id,),
                )
                connection.commit()
                return ("CLAIMED", "COMPLETED")
            replay = connection.execute(
                "SELECT status FROM infra.command_receipts "
                "WHERE principal_kind='USER' AND principal_id=%s "
                "AND command_name='ConcurrentSemanticProbe' AND command_version=1 "
                "AND idempotency_key_digest=%s FOR UPDATE",
                (identity["principal"], identity["digest"]),
            ).fetchone()
            connection.commit()
            return ("REPLAYED", replay[0] if replay else "MISSING")
        except psycopg.Error as error:
            connection.rollback()
            return (
                "DB_ERROR_" + (error.sqlstate or "UNKNOWN"),
                error.diag.constraint_name or "NONE",
            )
        finally:
            connection.close()

    @staticmethod
    def _insert_issued_invitation(
        connection: Any,
        *,
        invitation_id: uuid.UUID,
        facts: Dict[str, object],
    ) -> None:
        connection.execute(
            "INSERT INTO iam.access_invitations ("
            "id,purpose,organization_id,target_scope,target_role,is_initial_admin,"
            "recipient_contact_id,masked_recipient_label,policy_selector_digest,"
            "issued_policy_bundle_id,status,expires_at,issuer_kind,issuer_user_id,"
            "token_nonce,token_key_id,accepted_by_user_id,terminal_at,"
            "terminal_reason_code,aggregate_version,created_at,updated_at) VALUES ("
            "%s,'CREATOR_ENROLLMENT',NULL,'USER','CREATOR',false,%s,"
            "'a***@example.invalid',%s,%s,'ISSUED',"
            "transaction_timestamp()+interval '30 days','SYSTEM',NULL,%s,"
            "'invitation-token-v1',NULL,NULL,NULL,1,transaction_timestamp(),"
            "transaction_timestamp())",
            (
                invitation_id,
                facts["contact"],
                facts["active_selector"],
                facts["active_bundle"],
                _digest("race-invitation-" + str(invitation_id)),
            ),
        )

    def _race_invitation_accept(
        self,
        *,
        barrier: threading.Barrier,
        invitation_id: uuid.UUID,
        actor_id: object,
    ) -> str:
        connection = self._connect_admin()
        try:
            connection.execute("SET LOCAL lock_timeout='5s'")
            barrier.wait(timeout=10)
            row = connection.execute(
                "UPDATE iam.access_invitations SET status='ACCEPTED',"
                "accepted_by_user_id=%s,terminal_at=transaction_timestamp(),"
                "aggregate_version=aggregate_version+1,"
                "updated_at=transaction_timestamp() "
                "WHERE id=%s AND status='ISSUED' RETURNING id",
                (actor_id, invitation_id),
            ).fetchone()
            connection.commit()
            return "ACCEPTED" if row else "LOST"
        except psycopg.Error as error:
            connection.rollback()
            return "DB_ERROR_" + (error.sqlstate or "UNKNOWN")
        finally:
            connection.close()

    def _seed_single_active_session(
        self,
        facts: Dict[str, object],
    ) -> Tuple[uuid.UUID, uuid.UUID]:
        family_id = _new_id()
        session_id = _new_id()
        with self._connect_admin() as connection:
            connection.execute(
                "INSERT INTO iam.session_families ("
                "id,user_id,status,current_generation,revoked_at,"
                "revocation_reason_code,aggregate_version,created_at,updated_at) "
                "VALUES (%s,%s,'ACTIVE',1,NULL,NULL,1,"
                "transaction_timestamp()-interval '2 hours',"
                "transaction_timestamp())",
                (family_id, facts["actor"]),
            )
            self._insert_session(
                connection,
                session_id=session_id,
                user_id=facts["actor"],
                family_id=family_id,
                generation=1,
                predecessor_session_id=None,
                handle_digest=_digest("race-predecessor-" + str(session_id)),
                status="ACTIVE",
                rotation_reason="LOGIN",
            )
        return family_id, session_id

    def _race_session_successor(
        self,
        *,
        barrier: threading.Barrier,
        family_id: uuid.UUID,
        predecessor_id: uuid.UUID,
        user_id: object,
        successor_id: uuid.UUID,
    ) -> Tuple[str, Optional[str]]:
        connection = self._connect_admin()
        try:
            connection.execute("SET LOCAL lock_timeout='5s'")
            barrier.wait(timeout=10)
            predecessor = connection.execute(
                "UPDATE iam.sessions SET status='REVOKED',"
                "revoked_at=transaction_timestamp(),"
                "revocation_reason_code='ROTATED_BY_INVITATION_ACCEPT',"
                "aggregate_version=aggregate_version+1,"
                "updated_at=transaction_timestamp() "
                "WHERE id=%s AND family_id=%s AND status='ACTIVE' RETURNING id",
                (predecessor_id, family_id),
            ).fetchone()
            if predecessor is None:
                connection.rollback()
                return ("LOST", None)
            family = connection.execute(
                "UPDATE iam.session_families SET current_generation=2,"
                "aggregate_version=aggregate_version+1,"
                "updated_at=transaction_timestamp() "
                "WHERE id=%s AND status='ACTIVE' AND current_generation=1 "
                "RETURNING id",
                (family_id,),
            ).fetchone()
            if family is None:
                connection.rollback()
                return ("LOST", None)
            self._insert_session(
                connection,
                session_id=successor_id,
                user_id=user_id,
                family_id=family_id,
                generation=2,
                predecessor_session_id=predecessor_id,
                handle_digest=_digest("race-successor-" + str(successor_id)),
                status="ACTIVE",
                rotation_reason="INVITATION_ACCEPT",
            )
            connection.commit()
            return ("SUCCEEDED", None)
        except psycopg.Error as error:
            connection.rollback()
            return (
                "DB_ERROR_" + (error.sqlstate or "UNKNOWN"),
                error.diag.constraint_name,
            )
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
