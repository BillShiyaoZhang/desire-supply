"""Real PostgreSQL 18 coverage for the reviewed IAM0035 ORG_ADMIN program."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, replace
import hashlib
from pathlib import Path
from typing import Any, Mapping
import unittest
from uuid import UUID, uuid4

import psycopg

from desire_platform.identity_access.adapters.postgres.organization_admin import (
    OrganizationAdminPostgresDatabaseRequest,
    OrganizationAdminPostgresGeneratedIds,
    OrganizationAdminPostgresInvitationMaterial,
    OrganizationAdminPostgresIssueHoldEvidence,
    OrganizationAdminPostgresOperation,
    OrganizationAdminPostgresReceiptMaterial,
    OrganizationAdminPostgresResumeHoldEvidence,
    OrganizationAdminPostgresScope,
    PsycopgOrganizationAdminTargetResolver,
    PsycopgOrganizationAdminUnitOfWorkFactory,
)
from desire_platform.internal_pilot.contract_validation import (
    IamPostgresContractValidator,
)
from desire_platform.identity_access.adapters.postgres.oidc_authentication import (
    OidcPostgresBeginRequest,
    OidcPostgresExchangeClaim,
    OidcPostgresGenericStepUpFinalize,
    OidcPostgresInvitationStepUpFinalize,
    OidcPostgresPurpose,
    PsycopgOidcAuthenticationUnitOfWork,
)
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.adapters.postgres.migrations import (
    IAM_SCHEMA_HEAD_VERSION,
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18


ROOT = Path(__file__).resolve().parents[3]
MIGRATIONS = (
    ROOT / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
def _digest(label: str) -> bytes:
    return hashlib.sha256(label.encode("ascii")).digest()


class _Connections:
    def __init__(self, conninfo: str) -> None:
        self._conninfo = conninfo

    def checkout(self):
        return psycopg.connect(self._conninfo, autocommit=True)

    @staticmethod
    def release(connection: Any) -> None:
        connection.close()

    @staticmethod
    def discard(connection: Any) -> None:
        connection.close()


class _SchemaRecorder:
    def __init__(self) -> None:
        self.calls: list[tuple[dict[str, Any], str | None]] = []

    def validate(
        self, value: Mapping[str, Any], schema_name: str | None = None
    ) -> None:
        if not isinstance(value, Mapping):
            raise AssertionError("database contract value must be an object")
        self.calls.append((dict(value), schema_name))


@dataclass(frozen=True)
class _Seed:
    now: datetime
    organization_id: UUID
    actor_user_id: UUID
    actor_family_id: UUID
    actor_session_id: UUID
    actor_membership_id: UUID
    actor_grant_id: UUID
    target_user_id: UUID
    target_membership_id: UUID
    target_grant_id: UUID
    actor_source_invitation_id: UUID
    target_source_invitation_id: UUID


class OrganizationAdminPostgres18RedTest(unittest.TestCase):
    """Fresh-schema proof before command-level fixtures are exercised."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()
        cls.catalog = MigrationCatalog.load(MIGRATIONS)
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

    def tearDown(self) -> None:
        self.postgres.drop_database(self.database)

    def _apply_head(self) -> tuple[int, ...]:
        runner = IamMigrationRunner(
            driver=PsycopgMigrationDriver(
                settings=PsycopgMigrationSettings(
                    conninfo=self.postgres.conninfo(
                        database=self.database,
                        user="iam_migration_runner",
                    ),
                    application_name="organization-admin-pg18-red",
                ),
                dbapi=psycopg,
            ),
            runner_version="organization-admin-pg18-red/1",
        )
        report = runner.run(
            catalog=self.catalog,
            contract_sources=self.contract_sources,
        )
        return report.applied_versions

    def _admin(self, *, autocommit: bool = False):
        return psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=autocommit,
        )

    def _runtime(self) -> _Connections:
        return _Connections(
            self.postgres.conninfo(database=self.database, user="iam_app")
        )

    def _factory(self) -> PsycopgOrganizationAdminUnitOfWorkFactory:
        validator = IamPostgresContractValidator()
        return PsycopgOrganizationAdminUnitOfWorkFactory(
            connections=self._runtime(),
            event_validator=validator,
            response_validator=validator,
        )

    @staticmethod
    def _receipt(label: str, now: datetime) -> OrganizationAdminPostgresReceiptMaterial:
        command_id = UUID(bytes=_digest("command-" + label)[:16], version=4)
        identity = _digest("idempotency-" + label)
        payload = _digest("payload-" + label)
        return OrganizationAdminPostgresReceiptMaterial(
            receipt_id=command_id,
            idempotency_key_digest=identity,
            idempotency_key_digest_key_id=(
                "iam-receipt-idempotency-hmac-2026-01"
            ),
            payload_hash=payload,
            payload_hash_key_id="iam-receipt-payload-hmac-2026-01",
            retain_until=now + timedelta(days=31),
            idempotency_candidates=((
                "iam-receipt-idempotency-hmac-2026-01",
                identity,
            ),),
            payload_hash_candidates=((
                "iam-receipt-payload-hmac-2026-01",
                payload,
            ),),
        )

    @classmethod
    def _lifecycle_request(
        cls,
        *,
        seed: _Seed,
        operation: OrganizationAdminPostgresOperation,
        target_id: UUID,
        expected_version: int,
        label: str,
        resume_hold: OrganizationAdminPostgresResumeHoldEvidence | None = None,
        receipt: OrganizationAdminPostgresReceiptMaterial | None = None,
    ) -> OrganizationAdminPostgresDatabaseRequest:
        receipt = receipt or cls._receipt(label, seed.now)
        secondary = (
            uuid4()
            if operation is OrganizationAdminPostgresOperation.REVOKE_MEMBERSHIP
            else None
        )
        return OrganizationAdminPostgresDatabaseRequest(
            operation=operation,
            scope=OrganizationAdminPostgresScope(
                actor_user_id=seed.actor_user_id,
                current_session_id=seed.actor_session_id,
                organization_id=seed.organization_id,
                target_id=target_id,
                command_id=receipt.receipt_id,
                correlation_id=uuid4(),
                causation_id=receipt.receipt_id,
                trace_id=uuid4(),
                original_actor_id=None,
            ),
            receipt=receipt,
            expected_version=expected_version,
            generated_ids=OrganizationAdminPostgresGeneratedIds(
                audit_event_id=uuid4(),
                outbox_event_id=uuid4(),
                secondary_outbox_event_id=secondary,
                recipient_contact_id=None,
            ),
            invitation=None,
            resume_hold=resume_hold,
            reason_code="ACCESS_REVIEW",
        )

    def _seed_organization(self) -> _Seed:
        """Install one active admin and one active DEMAND_OWNER member.

        The fixture uses replica mode only while installing the already-valid
        historical aggregates.  IAM0034 itself runs with all constraints and
        lifecycle triggers enabled through the ordinary ``iam_app`` role.
        """

        now = datetime.now(timezone.utc).replace(microsecond=0)
        created = now - timedelta(days=2)
        session_created = now - timedelta(minutes=2)
        organization_id = uuid4()
        actor_user_id = uuid4()
        actor_family_id = uuid4()
        actor_session_id = uuid4()
        actor_membership_id = uuid4()
        actor_source_invitation_id = uuid4()
        actor_contact_id = uuid4()
        actor_grant_id = uuid4()
        target_user_id = uuid4()
        target_membership_id = uuid4()
        target_source_invitation_id = uuid4()
        target_contact_id = uuid4()
        target_grant_id = uuid4()
        policies = {
            "ORG_ADMIN": (_digest("org-admin-selector"), uuid4()),
            "DEMAND_OWNER": (_digest("demand-owner-selector"), uuid4()),
        }
        with self._admin() as connection:
            connection.execute("SET LOCAL session_replication_role = 'replica'")
            connection.execute(
                "INSERT INTO iam.organizations ("
                "id,organization_type,public_name,jurisdiction,status,"
                "client_reference_namespace,client_reference,aggregate_version,"
                "created_at,updated_at) VALUES ("
                "%s,'BUSINESS','PG18 ORG_ADMIN fixture','CN','ACTIVE',"
                "'pg18-org-admin',%s,1,%s,%s)",
                (organization_id, str(organization_id), created, created),
            )
            for role, (selector_digest, bundle_id) in policies.items():
                connection.execute(
                    "INSERT INTO iam.policy_selectors ("
                    "selector_digest,canonicalization_version,access_purpose,"
                    "scope_type,target_role,jurisdiction,locale,current_bundle_id,"
                    "aggregate_version,created_at,updated_at) VALUES ("
                    "%s,'policy-selector-json-v1','ORGANIZATION_MEMBERSHIP',"
                    "'ORGANIZATION_ROLE',%s,'CN','zh-CN',%s,1,%s,%s)",
                    (selector_digest, role, bundle_id, created, created),
                )
                connection.execute(
                    "INSERT INTO iam.policy_bundles ("
                    "id,selector_digest,status,effective_at,effective_until,"
                    "superseded_by_bundle_id,release_manifest_sha256,"
                    "release_signature,release_signing_key_id,"
                    "publication_command_id,aggregate_version,created_at,updated_at) "
                    "VALUES (%s,%s,'ACTIVE',%s,NULL,NULL,%s,%s,"
                    "'pg18-policy-signing-v1',%s,1,%s,%s)",
                    (
                        bundle_id,
                        selector_digest,
                        created,
                        _digest("manifest-" + role),
                        b"pg18-reviewed-signature",
                        uuid4(),
                        created,
                        created,
                    ),
                )
            for user_id, handle in (
                (actor_user_id, "pg18_actor_admin"),
                (target_user_id, "pg18_target_member"),
            ):
                connection.execute(
                    "INSERT INTO iam.users ("
                    "id,status,display_handle,aggregate_version,created_at,updated_at) "
                    "VALUES (%s,'ACTIVE',%s,1,%s,%s)",
                    (user_id, handle, created, created),
                )
            for (
                user_id,
                contact_id,
                invitation_id,
                membership_id,
                grant_id,
                role,
            ) in (
                (
                    actor_user_id,
                    actor_contact_id,
                    actor_source_invitation_id,
                    actor_membership_id,
                    actor_grant_id,
                    "ORG_ADMIN",
                ),
                (
                    target_user_id,
                    target_contact_id,
                    target_source_invitation_id,
                    target_membership_id,
                    target_grant_id,
                    "DEMAND_OWNER",
                ),
            ):
                selector_digest, bundle_id = policies[role]
                connection.execute(
                    "INSERT INTO iam.contact_points ("
                    "id,user_id,contact_type,locator_ciphertext,"
                    "locator_encryption_key_id,locator_encryption_algorithm,"
                    "binding_digest,binding_digest_key_id,verified_at,"
                    "retention_until,created_at,updated_at) VALUES ("
                    "%s,%s,'EMAIL',NULL,NULL,NULL,%s,'pg18-contact-v1',%s,NULL,%s,%s)",
                    (
                        contact_id,
                        user_id,
                        _digest("contact-" + role),
                        created,
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
                    "%s,'p***@example.invalid',%s,%s,'ACCEPTED',%s,"
                    "'SYSTEM',NULL,%s,'pg18-invitation-token-v1',%s,%s,NULL,2,%s,%s)",
                    (
                        invitation_id,
                        organization_id,
                        role,
                        contact_id,
                        selector_digest,
                        bundle_id,
                        created + timedelta(days=7),
                        _digest("nonce-" + role),
                        user_id,
                        created + timedelta(hours=1),
                        created,
                        created + timedelta(hours=1),
                    ),
                )
                connection.execute(
                    "INSERT INTO iam.memberships ("
                    "id,organization_id,user_id,status,source_invitation_id,"
                    "aggregate_version,created_at,updated_at) "
                    "VALUES (%s,%s,%s,'ACTIVE',%s,1,%s,%s)",
                    (
                        membership_id,
                        organization_id,
                        user_id,
                        invitation_id,
                        created + timedelta(hours=1),
                        created + timedelta(hours=1),
                    ),
                )
                connection.execute(
                    "INSERT INTO iam.membership_role_grants ("
                    "id,organization_id,membership_id,user_id,role_code,"
                    "source_invitation_id,policy_selector_digest,granted_by_kind,"
                    "granted_by_id,granted_at,revoked_at,revocation_reason_code,"
                    "aggregate_version) VALUES ("
                    "%s,%s,%s,%s,%s,%s,%s,'SYSTEM',%s,%s,NULL,NULL,1)",
                    (
                        grant_id,
                        organization_id,
                        membership_id,
                        user_id,
                        role,
                        invitation_id,
                        selector_digest,
                        uuid4(),
                        created + timedelta(hours=1),
                    ),
                )
            connection.execute(
                "INSERT INTO iam.session_families ("
                "id,user_id,status,current_generation,revoked_at,"
                "revocation_reason_code,aggregate_version,created_at,updated_at) "
                "VALUES (%s,%s,'ACTIVE',1,NULL,NULL,1,%s,%s)",
                (actor_family_id, actor_user_id, created, now),
            )
            connection.execute(
                "INSERT INTO iam.sessions ("
                "id,user_id,family_id,generation,predecessor_session_id,"
                "handle_digest,handle_digest_key_id,csrf_salt,csrf_key_id,"
                "csrf_digest,verified_contact_point_id,verified_at,"
                "verified_for_invitation_id,auth_transaction_id,auth_time,"
                "acr_code,amr_codes,created_at,last_activity_at,idle_expires_at,"
                "absolute_expires_at,updated_at,device_label,status,rotation_reason,"
                "revoked_at,revocation_reason_code,aggregate_version) VALUES ("
                "%s,%s,%s,1,NULL,%s,'pg18-session-handle-v1',%s,"
                "'pg18-session-csrf-v1',%s,NULL,NULL,NULL,NULL,%s,"
                "'urn:desire:acr:mfa',ARRAY['otp']::text[],%s,%s,%s,%s,%s,"
                "'Browser','ACTIVE','LOGIN',NULL,NULL,1)",
                (
                    actor_session_id,
                    actor_user_id,
                    actor_family_id,
                    _digest("actor-session-handle"),
                    _digest("actor-csrf-salt"),
                    _digest("actor-csrf"),
                    session_created - timedelta(seconds=1),
                    session_created,
                    now - timedelta(seconds=10),
                    now + timedelta(minutes=30),
                    now + timedelta(hours=8),
                    now,
                ),
            )
        return _Seed(
            now=now,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            actor_family_id=actor_family_id,
            actor_session_id=actor_session_id,
            actor_membership_id=actor_membership_id,
            actor_grant_id=actor_grant_id,
            target_user_id=target_user_id,
            target_membership_id=target_membership_id,
            target_grant_id=target_grant_id,
            actor_source_invitation_id=actor_source_invitation_id,
            target_source_invitation_id=target_source_invitation_id,
        )

    def test_fresh_zero_through_iam0036_applies_on_postgresql_18(self) -> None:
        self.assertEqual(
            self._apply_head(), tuple(range(IAM_SCHEMA_HEAD_VERSION + 1))
        )

    def test_suspend_exact_replay_and_authority_revocation_between_transactions(self) -> None:
        self.assertEqual(
            self._apply_head(), tuple(range(IAM_SCHEMA_HEAD_VERSION + 1))
        )
        seed = self._seed_organization()
        factory = self._factory()
        stale = self._lifecycle_request(
            seed=seed,
            operation=OrganizationAdminPostgresOperation.SUSPEND_MEMBERSHIP,
            target_id=seed.target_membership_id,
            expected_version=2,
            label="negative-stale",
        )
        with self.assertRaises(IamError) as stale_error:
            factory.execute_suspend_membership(stale)
        self.assertEqual(stale_error.exception.code, "PRECONDITION_FAILED")

        request = self._lifecycle_request(
            seed=seed,
            operation=OrganizationAdminPostgresOperation.SUSPEND_MEMBERSHIP,
            target_id=seed.target_membership_id,
            expected_version=1,
            label="suspend-target",
        )

        first = factory.execute_suspend_membership(request)
        self.assertFalse(first.replayed)
        self.assertEqual(first.safe_response["status"], "SUSPENDED")
        self.assertEqual(first.safe_response["aggregate_version"], 2)
        replay = factory.execute_suspend_membership(request)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.safe_response, first.safe_response)

        resolver = PsycopgOrganizationAdminTargetResolver(
            connections=self._runtime()
        )
        self.assertEqual(
            resolver.resolve(
                actor_user_id=str(seed.actor_user_id),
                session_id=str(seed.actor_session_id),
                target_id=str(seed.target_membership_id),
                operation="SuspendMembership",
            ),
            str(seed.organization_id),
        )
        with self._admin() as connection:
            connection.execute("SET LOCAL session_replication_role = 'replica'")
            connection.execute(
                "UPDATE iam.membership_role_grants SET revoked_at=%s,"
                "revocation_reason_code='ACCESS_REVIEW',aggregate_version=2 "
                "WHERE id=%s",
                (seed.now, seed.actor_grant_id),
            )
        with self.assertRaises(Exception) as raised:
            factory.execute_suspend_membership(request)
        self.assertEqual(getattr(raised.exception, "code", None), "RESOURCE_NOT_FOUND")

        with self._admin() as connection:
            facts = connection.execute(
                "SELECT (SELECT count(*) FROM infra.command_receipts "
                "WHERE id=%s),"
                "(SELECT count(*) FROM audit.audit_events WHERE command_id=%s),"
                "(SELECT count(*) FROM infra.outbox_events WHERE causation_id=%s),"
                "(SELECT status FROM iam.memberships WHERE id=%s)",
                (
                    request.scope.command_id,
                    request.scope.command_id,
                    request.scope.command_id,
                    seed.target_membership_id,
                ),
            ).fetchone()
        self.assertEqual(facts, (1, 1, 1, "SUSPENDED"))

    def test_all_five_commands_form_one_restart_safe_authority_chain(self) -> None:
        self.assertEqual(
            self._apply_head(), tuple(range(IAM_SCHEMA_HEAD_VERSION + 1))
        )
        seed = self._seed_organization()
        factory = self._factory()
        resolver = PsycopgOrganizationAdminTargetResolver(
            connections=self._runtime()
        )

        issue_receipt = self._receipt("issue-invitation", seed.now)
        issue_resolution = resolver.resolve_issue(
            actor_user_id=str(seed.actor_user_id),
            session_id=str(seed.actor_session_id),
            organization_id=str(seed.organization_id),
            target_role="DEMAND_OWNER",
            idempotency_candidates=issue_receipt.idempotency_candidates,
            payload_hash_candidates=issue_receipt.payload_hash_candidates,
        )
        self.assertFalse(issue_resolution.replayed)
        self.assertEqual(issue_resolution.target_version, 1)
        invitation_id = uuid4()
        contact_id = uuid4()
        issue_request = OrganizationAdminPostgresDatabaseRequest(
            operation=OrganizationAdminPostgresOperation.ISSUE_ACCESS_INVITATION,
            scope=OrganizationAdminPostgresScope(
                actor_user_id=seed.actor_user_id,
                current_session_id=seed.actor_session_id,
                organization_id=seed.organization_id,
                target_id=invitation_id,
                command_id=issue_receipt.receipt_id,
                correlation_id=uuid4(),
                causation_id=issue_receipt.receipt_id,
                trace_id=uuid4(),
                original_actor_id=None,
            ),
            receipt=issue_receipt,
            expected_version=1,
            generated_ids=OrganizationAdminPostgresGeneratedIds(
                audit_event_id=uuid4(),
                outbox_event_id=uuid4(),
                secondary_outbox_event_id=None,
                recipient_contact_id=contact_id,
            ),
            invitation=OrganizationAdminPostgresInvitationMaterial(
                recipient_contact_id=contact_id,
                recipient_binding_digest=_digest("new-recipient-binding"),
                recipient_binding_digest_key_id="recipient-binding-2026-01",
                masked_recipient_label="n***@example.invalid",
                target_role="DEMAND_OWNER",
                expires_at=seed.now + timedelta(days=7),
                token_nonce=_digest("new-invitation-nonce"),
                token_key_id="invitation-token-2026-01",
                token_format_version="access-invitation-token-v1",
            ),
            issue_hold=OrganizationAdminPostgresIssueHoldEvidence(
                action="IssueAccessInvitation",
                target_type="AccessInvitation",
                target_id=invitation_id,
                target_version=1,
                organization_id=seed.organization_id,
                policy_version="iam-organization-invitation-issue-hold-v1",
                evaluated_at=seed.now,
                valid_until=seed.now + timedelta(minutes=5),
                snapshot_digest=issue_resolution.snapshot_digest,
            ),
        )
        issued = factory.execute_issue_access_invitation(issue_request)
        self.assertFalse(issued.replayed)
        self.assertEqual(issued.safe_response["status"], "ISSUED")
        with self._admin() as connection:
            persisted_expires_at = connection.execute(
                "SELECT payload->>'expires_at' FROM infra.outbox_events "
                "WHERE event_id=%s AND event_type='AccessInvitationIssued'",
                (issue_request.generated_ids.outbox_event_id,),
            ).fetchone()
        self.assertIsNotNone(persisted_expires_at)
        self.assertRegex(persisted_expires_at[0], r"Z\Z")
        self.assertEqual(
            factory.execute_issue_access_invitation(issue_request).safe_response,
            issued.safe_response,
        )

        revoke_invitation = self._lifecycle_request(
            seed=seed,
            operation=(
                OrganizationAdminPostgresOperation.REVOKE_ACCESS_INVITATION
            ),
            target_id=invitation_id,
            expected_version=1,
            label="revoke-invitation",
        )
        revoked_invitation = factory.execute_revoke_access_invitation(
            revoke_invitation
        )
        self.assertEqual(revoked_invitation.safe_response["status"], "REVOKED")
        self.assertTrue(
            factory.execute_revoke_access_invitation(
                revoke_invitation
            ).replayed
        )

        suspend = self._lifecycle_request(
            seed=seed,
            operation=OrganizationAdminPostgresOperation.SUSPEND_MEMBERSHIP,
            target_id=seed.target_membership_id,
            expected_version=1,
            label="chain-suspend",
        )
        suspended = factory.execute_suspend_membership(suspend)
        self.assertEqual(suspended.safe_response["status"], "SUSPENDED")

        resume_receipt = self._receipt("chain-resume", seed.now)
        resume_resolution = resolver.resolve_resume(
            actor_user_id=str(seed.actor_user_id),
            session_id=str(seed.actor_session_id),
            target_id=str(seed.target_membership_id),
            idempotency_key_digest=resume_receipt.idempotency_key_digest,
            idempotency_key_digest_key_id=(
                resume_receipt.idempotency_key_digest_key_id
            ),
            payload_hash=resume_receipt.payload_hash,
            payload_hash_key_id=resume_receipt.payload_hash_key_id,
            idempotency_candidates=resume_receipt.idempotency_candidates,
            payload_hash_candidates=resume_receipt.payload_hash_candidates,
        )
        self.assertFalse(resume_resolution.replayed)
        self.assertEqual(resume_resolution.target_version, 2)
        resume = self._lifecycle_request(
            seed=seed,
            operation=OrganizationAdminPostgresOperation.RESUME_MEMBERSHIP,
            target_id=seed.target_membership_id,
            expected_version=2,
            label="chain-resume",
            receipt=resume_receipt,
            resume_hold=OrganizationAdminPostgresResumeHoldEvidence(
                action="ResumeMembership",
                target_type="Membership",
                target_id=seed.target_membership_id,
                target_version=2,
                organization_id=seed.organization_id,
                policy_version="iam-membership-resume-hold-v1",
                evaluated_at=seed.now,
                valid_until=seed.now + timedelta(minutes=5),
                snapshot_digest=resume_resolution.snapshot_digest,
            ),
        )
        resumed = factory.execute_resume_membership(resume)
        self.assertEqual(resumed.safe_response["status"], "ACTIVE")
        self.assertTrue(factory.execute_resume_membership(resume).replayed)

        revoke_membership = self._lifecycle_request(
            seed=seed,
            operation=OrganizationAdminPostgresOperation.REVOKE_MEMBERSHIP,
            target_id=seed.target_membership_id,
            expected_version=3,
            label="chain-revoke-member",
        )
        revoked_member = factory.execute_revoke_membership(revoke_membership)
        self.assertEqual(revoked_member.safe_response["status"], "REVOKED")
        self.assertTrue(
            factory.execute_revoke_membership(revoke_membership).replayed
        )

        with self._admin() as connection:
            facts = connection.execute(
                "SELECT (SELECT count(*) FROM infra.command_receipts "
                "WHERE principal_id=%s AND status='COMPLETED'),"
                "(SELECT count(*) FROM audit.audit_events "
                "WHERE actor_id=%s AND result_code='SUCCEEDED'),"
                "(SELECT count(*) FROM infra.outbox_events "
                "WHERE actor_id=%s),"
                "(SELECT status FROM iam.memberships WHERE id=%s),"
                "(SELECT count(*) FROM iam.membership_role_grants "
                "WHERE membership_id=%s AND revoked_at IS NOT NULL)",
                (
                    seed.actor_user_id,
                    seed.actor_user_id,
                    seed.actor_user_id,
                    seed.target_membership_id,
                    seed.target_membership_id,
                ),
            ).fetchone()
        self.assertEqual(facts, (5, 5, 6, "REVOKED", 1))

    def test_payload_conflict_stale_occ_and_self_management_are_zero_write(self) -> None:
        self.assertEqual(
            self._apply_head(), tuple(range(IAM_SCHEMA_HEAD_VERSION + 1))
        )
        seed = self._seed_organization()
        factory = self._factory()
        stale = self._lifecycle_request(
            seed=seed,
            operation=OrganizationAdminPostgresOperation.SUSPEND_MEMBERSHIP,
            target_id=seed.target_membership_id,
            expected_version=2,
            label="negative-stale",
        )
        with self.assertRaises(IamError) as stale_error:
            factory.execute_suspend_membership(stale)
        self.assertEqual(stale_error.exception.code, "PRECONDITION_FAILED")

        request = self._lifecycle_request(
            seed=seed,
            operation=OrganizationAdminPostgresOperation.SUSPEND_MEMBERSHIP,
            target_id=seed.target_membership_id,
            expected_version=1,
            label="negative-base",
        )
        factory.execute_suspend_membership(request)

        changed_payload = _digest("negative-base-changed-payload")
        conflict = replace(
            request,
            receipt=replace(
                request.receipt,
                payload_hash=changed_payload,
                payload_hash_candidates=((
                    "iam-receipt-payload-hmac-2026-01",
                    changed_payload,
                ),),
            ),
        )
        with self.assertRaises(IamError) as conflict_error:
            factory.execute_suspend_membership(conflict)
        self.assertEqual(conflict_error.exception.code, "IDEMPOTENCY_KEY_REUSED")

        self_target = self._lifecycle_request(
            seed=seed,
            operation=OrganizationAdminPostgresOperation.SUSPEND_MEMBERSHIP,
            target_id=seed.actor_membership_id,
            expected_version=1,
            label="negative-self",
        )
        with self.assertRaises(IamError) as self_error:
            factory.execute_suspend_membership(self_target)
        self.assertEqual(self_error.exception.code, "SELF_MANAGEMENT_FORBIDDEN")

        with self._admin() as connection:
            facts = connection.execute(
                "SELECT (SELECT count(*) FROM infra.command_receipts "
                "WHERE principal_id=%s),"
                "(SELECT count(*) FROM audit.audit_events WHERE actor_id=%s),"
                "(SELECT count(*) FROM infra.outbox_events WHERE actor_id=%s)",
                (
                    seed.actor_user_id,
                    seed.actor_user_id,
                    seed.actor_user_id,
                ),
            ).fetchone()
        self.assertEqual(facts, (1, 1, 1))

    def test_cross_organization_target_is_undisclosed_and_zero_write(self) -> None:
        self.assertEqual(
            self._apply_head(), tuple(range(IAM_SCHEMA_HEAD_VERSION + 1))
        )
        seed = self._seed_organization()
        foreign_organization_id = uuid4()
        with self._admin() as connection:
            connection.execute("SET LOCAL session_replication_role = 'replica'")
            connection.execute(
                "INSERT INTO iam.organizations ("
                "id,organization_type,public_name,jurisdiction,status,"
                "client_reference_namespace,client_reference,aggregate_version,"
                "created_at,updated_at) VALUES ("
                "%s,'BUSINESS','Foreign PG18 fixture','CN','ACTIVE',"
                "'pg18-org-admin',%s,1,%s,%s)",
                (
                    foreign_organization_id,
                    str(foreign_organization_id),
                    seed.now - timedelta(days=1),
                    seed.now - timedelta(days=1),
                ),
            )
            connection.execute(
                "UPDATE iam.access_invitations SET organization_id=%s "
                "WHERE id=%s",
                (foreign_organization_id, seed.target_source_invitation_id),
            )
            connection.execute(
                "UPDATE iam.memberships SET organization_id=%s WHERE id=%s",
                (foreign_organization_id, seed.target_membership_id),
            )
            connection.execute(
                "UPDATE iam.membership_role_grants SET organization_id=%s "
                "WHERE id=%s",
                (foreign_organization_id, seed.target_grant_id),
            )

        resolver = PsycopgOrganizationAdminTargetResolver(
            connections=self._runtime()
        )
        with self.assertRaises(IamError) as lookup_error:
            resolver.resolve(
                actor_user_id=str(seed.actor_user_id),
                session_id=str(seed.actor_session_id),
                target_id=str(seed.target_membership_id),
                operation="SuspendMembership",
            )
        self.assertEqual(lookup_error.exception.code, "RESOURCE_NOT_FOUND")

        request = self._lifecycle_request(
            seed=seed,
            operation=OrganizationAdminPostgresOperation.SUSPEND_MEMBERSHIP,
            target_id=seed.target_membership_id,
            expected_version=1,
            label="cross-organization-target",
        )
        with self.assertRaises(IamError) as command_error:
            self._factory().execute_suspend_membership(request)
        self.assertEqual(command_error.exception.code, "RESOURCE_NOT_FOUND")
        with self._admin() as connection:
            facts = connection.execute(
                "SELECT (SELECT count(*) FROM infra.command_receipts "
                "WHERE principal_id=%s),"
                "(SELECT count(*) FROM audit.audit_events WHERE actor_id=%s),"
                "(SELECT count(*) FROM infra.outbox_events WHERE actor_id=%s),"
                "(SELECT status FROM iam.memberships WHERE id=%s)",
                (
                    seed.actor_user_id,
                    seed.actor_user_id,
                    seed.actor_user_id,
                    seed.target_membership_id,
                ),
            ).fetchone()
        self.assertEqual(facts, (0, 0, 0, "ACTIVE"))

    def test_generic_step_up_rotates_one_family_and_revokes_the_old_session(self) -> None:
        self.assertEqual(
            self._apply_head(), tuple(range(IAM_SCHEMA_HEAD_VERSION + 1))
        )
        seed = self._seed_organization()
        subject_digest = _digest("generic-step-up-subject")
        provider_issuer = "https://identity.example.test"
        with self._admin() as connection:
            connection.execute(
                "INSERT INTO iam.external_identities ("
                "id,user_id,issuer,subject_digest,subject_digest_key_id,"
                "verified_at,status,created_at) VALUES ("
                "%s,%s,%s,%s,'oidc-subject-v1',%s,'ACTIVE',%s)",
                (
                    uuid4(),
                    seed.actor_user_id,
                    provider_issuer,
                    subject_digest,
                    seed.now - timedelta(days=1),
                    seed.now - timedelta(days=1),
                ),
            )
        uow = PsycopgOidcAuthenticationUnitOfWork(
            connections=_Connections(
                self.postgres.conninfo(
                    database=self.database,
                    user="iam_onboarding",
                )
            )
        )
        transaction_id = uuid4()
        begin = OidcPostgresBeginRequest(
            auth_transaction_id=transaction_id,
            purpose=OidcPostgresPurpose.STEP_UP,
            browser_binding_digest=_digest("generic-step-up-browser"),
            browser_binding_key_id="oidc-browser-v1",
            initiating_session_id=seed.actor_session_id,
            initiating_user_id=seed.actor_user_id,
            expected_user_id=seed.actor_user_id,
            invitation_id=None,
            invitation_version=None,
            expected_contact_point_id=None,
            expected_contact_type=None,
            expected_contact_binding_digest=None,
            expected_contact_binding_key_id=None,
            state_digest=_digest("generic-step-up-state"),
            state_digest_key_id="oidc-state-v1",
            nonce_digest=_digest("generic-step-up-nonce"),
            nonce_digest_key_id="oidc-nonce-v1",
            nonce_ciphertext=b"reviewed-generic-step-up-nonce",
            nonce_encryption_key_id="oidc-nonce-aead-v1",
            pkce_verifier_ciphertext=b"reviewed-generic-step-up-verifier",
            pkce_encryption_key_id="oidc-pkce-aead-v1",
            pkce_code_challenge="A" * 43,
            provider_issuer=provider_issuer,
            provider_audience="desire-internal-pilot",
            redirect_uri="https://pilot.example.test/v1/auth/oidc/callback",
            return_to="/app",
            security_policy_version="iam-security-v1",
            audit_event_id=uuid4(),
            system_actor_id=uuid4(),
            correlation_id=uuid4(),
            trace_id=uuid4(),
        )
        begun = uow.begin(begin)
        self.assertEqual((begun.status.value, begun.purpose.value), ("PENDING", "STEP_UP"))
        exchange_owner_id = uuid4()
        uow.claim_exchange(
            OidcPostgresExchangeClaim(
                auth_transaction_id=transaction_id,
                exchange_owner_id=exchange_owner_id,
                invitation_id=None,
            )
        )
        resolved = uow.resolve_generic_step_up_session(
            auth_transaction_id=transaction_id,
            expected_user_id=seed.actor_user_id,
            initiating_session_id=seed.actor_session_id,
        )
        self.assertEqual(
            (
                resolved.user_id,
                resolved.initiating_session_id,
                resolved.session_family_id,
                resolved.current_generation,
            ),
            (
                seed.actor_user_id,
                seed.actor_session_id,
                seed.actor_family_id,
                1,
            ),
        )
        new_session_id = uuid4()
        finalized = uow.finalize_generic_step_up(
            OidcPostgresGenericStepUpFinalize(
                auth_transaction_id=transaction_id,
                exchange_owner_id=exchange_owner_id,
                expected_user_id=seed.actor_user_id,
                initiating_session_id=seed.actor_session_id,
                session_family_id=seed.actor_family_id,
                predecessor_generation=1,
                provider_issuer=provider_issuer,
                subject_digest=subject_digest,
                subject_digest_key_id="oidc-subject-v1",
                new_session_id=new_session_id,
                handle_digest=_digest("generic-step-up-new-session"),
                handle_digest_key_id="session-handle-v1",
                csrf_salt=_digest("generic-step-up-csrf-salt"),
                csrf_key_id="session-csrf-v1",
                csrf_digest=_digest("generic-step-up-csrf"),
                auth_time=seed.now - timedelta(seconds=5),
                token_issued_at=seed.now - timedelta(seconds=4),
                token_expires_at=seed.now + timedelta(minutes=5),
                acr_code="urn:desire:acr:synthetic-internal-sandbox:mfa",
                amr_codes=("mfa", "synthetic"),
                audit_event_id=uuid4(),
                system_actor_id=uuid4(),
                correlation_id=uuid4(),
                trace_id=uuid4(),
            )
        )
        self.assertEqual(
            (
                finalized.session_id,
                finalized.session_family_id,
                finalized.user_id,
                finalized.user_status,
                finalized.generation,
            ),
            (
                new_session_id,
                seed.actor_family_id,
                seed.actor_user_id,
                "ACTIVE",
                2,
            ),
        )
        with self._admin() as connection:
            facts = connection.execute(
                "SELECT t.status,t.aggregate_version,f.status,f.current_generation,"
                "old.status,old.revocation_reason_code,old.aggregate_version,"
                "new.status,new.rotation_reason,new.predecessor_session_id,"
                "new.generation,new.auth_transaction_id "
                "FROM iam.auth_transactions AS t "
                "JOIN iam.session_families AS f ON f.id=%s "
                "JOIN iam.sessions AS old ON old.id=%s "
                "JOIN iam.sessions AS new ON new.id=%s "
                "WHERE t.id=%s",
                (
                    seed.actor_family_id,
                    seed.actor_session_id,
                    new_session_id,
                    transaction_id,
                ),
            ).fetchone()
        self.assertEqual(
            facts,
            (
                "SUCCEEDED",
                3,
                "ACTIVE",
                2,
                "REVOKED",
                "STEP_UP_ROTATED",
                2,
                "ACTIVE",
                "STEP_UP",
                seed.actor_session_id,
                2,
                transaction_id,
            ),
        )

    def test_invitation_step_up_preserves_contact_binding_and_rotates_session(self) -> None:
        self.assertEqual(
            self._apply_head(), tuple(range(IAM_SCHEMA_HEAD_VERSION + 1))
        )
        seed = self._seed_organization()
        subject_digest = _digest("invitation-step-up-subject")
        provider_issuer = "https://identity.example.test"
        invitation_id = uuid4()
        contact_id = uuid4()
        contact_type = "EMAIL"
        contact_binding_digest = _digest("new-issued-recipient-binding")
        contact_binding_key_id = "recipient-binding-2026-01"
        with self._admin() as connection:
            policy_facts = connection.execute(
                "SELECT source.policy_selector_digest,"
                "source.issued_policy_bundle_id "
                "FROM iam.access_invitations AS source "
                "WHERE source.id=%s",
                (seed.actor_source_invitation_id,),
            ).fetchone()
            self.assertIsNotNone(policy_facts)
            selector_digest, policy_bundle_id = policy_facts
            connection.execute(
                "INSERT INTO iam.external_identities ("
                "id,user_id,issuer,subject_digest,subject_digest_key_id,"
                "verified_at,status,created_at) VALUES ("
                "%s,%s,%s,%s,'oidc-subject-v1',%s,'ACTIVE',%s)",
                (
                    uuid4(),
                    seed.actor_user_id,
                    provider_issuer,
                    subject_digest,
                    seed.now - timedelta(days=1),
                    seed.now - timedelta(days=1),
                ),
            )
            connection.execute(
                "INSERT INTO iam.contact_points ("
                "id,user_id,contact_type,locator_ciphertext,"
                "locator_encryption_key_id,locator_encryption_algorithm,"
                "binding_digest,binding_digest_key_id,verified_at,"
                "retention_until,created_at,updated_at) VALUES ("
                "%s,NULL,'EMAIL',NULL,NULL,NULL,%s,%s,NULL,%s,%s,%s)",
                (
                    contact_id,
                    contact_binding_digest,
                    contact_binding_key_id,
                    seed.now + timedelta(days=7),
                    seed.now,
                    seed.now,
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
                "%s,'ORGANIZATION_MEMBERSHIP',%s,'ORGANIZATION','DEMAND_OWNER',"
                "false,%s,'p***@example.invalid',%s,%s,'ISSUED',%s,'USER',%s,"
                "%s,'pg18-invitation-token-v1',NULL,NULL,NULL,1,%s,%s)",
                (
                    invitation_id,
                    seed.organization_id,
                    contact_id,
                    selector_digest,
                    policy_bundle_id,
                    seed.now + timedelta(days=7),
                    seed.actor_user_id,
                    _digest("invitation-step-up-token-nonce"),
                    seed.now,
                    seed.now,
                ),
            )

        uow = PsycopgOidcAuthenticationUnitOfWork(
            connections=_Connections(
                self.postgres.conninfo(
                    database=self.database,
                    user="iam_onboarding",
                )
            )
        )
        transaction_id = uuid4()
        begun = uow.begin(
            OidcPostgresBeginRequest(
                auth_transaction_id=transaction_id,
                purpose=OidcPostgresPurpose.STEP_UP,
                browser_binding_digest=_digest("invitation-step-up-browser"),
                browser_binding_key_id="oidc-browser-v1",
                initiating_session_id=seed.actor_session_id,
                initiating_user_id=seed.actor_user_id,
                expected_user_id=seed.actor_user_id,
                invitation_id=invitation_id,
                invitation_version=1,
                expected_contact_point_id=contact_id,
                expected_contact_type=contact_type,
                expected_contact_binding_digest=contact_binding_digest,
                expected_contact_binding_key_id=contact_binding_key_id,
                state_digest=_digest("invitation-step-up-state"),
                state_digest_key_id="oidc-state-v1",
                nonce_digest=_digest("invitation-step-up-nonce"),
                nonce_digest_key_id="oidc-nonce-v1",
                nonce_ciphertext=b"reviewed-invitation-step-up-nonce",
                nonce_encryption_key_id="oidc-nonce-aead-v1",
                pkce_verifier_ciphertext=(
                    b"reviewed-invitation-step-up-verifier"
                ),
                pkce_encryption_key_id="oidc-pkce-aead-v1",
                pkce_code_challenge="B" * 43,
                provider_issuer=provider_issuer,
                provider_audience="desire-internal-pilot",
                redirect_uri="https://pilot.example.test/v1/auth/oidc/callback",
                return_to="/join",
                security_policy_version="iam-security-v1",
                audit_event_id=uuid4(),
                system_actor_id=uuid4(),
                correlation_id=uuid4(),
                trace_id=uuid4(),
            )
        )
        self.assertEqual((begun.status.value, begun.purpose.value), ("PENDING", "STEP_UP"))
        exchange_owner_id = uuid4()
        uow.claim_exchange(
            OidcPostgresExchangeClaim(
                auth_transaction_id=transaction_id,
                exchange_owner_id=exchange_owner_id,
                invitation_id=invitation_id,
            )
        )
        resolved = uow.resolve_invitation_step_up_session(
            auth_transaction_id=transaction_id,
            invitation_id=invitation_id,
            expected_user_id=seed.actor_user_id,
            initiating_session_id=seed.actor_session_id,
        )
        self.assertEqual(
            (
                resolved.user_id,
                resolved.initiating_session_id,
                resolved.session_family_id,
                resolved.current_generation,
            ),
            (
                seed.actor_user_id,
                seed.actor_session_id,
                seed.actor_family_id,
                1,
            ),
        )
        with self._admin() as connection:
            frozen_facts = connection.execute(
                "SELECT t.protocol_version,t.purpose,t.attempt,t.status,"
                "t.aggregate_version,t.exchange_owner_id,t.provider_issuer,"
                "t.expected_user_id,t.initiating_user_id,t.initiating_session_id,"
                "t.invitation_id,t.invitation_version,t.expected_contact_point_id,"
                "t.expected_contact_type,t.expected_contact_binding_digest,"
                "t.expected_contact_binding_key_id,i.status,i.aggregate_version,"
                "i.recipient_contact_id,c.contact_type,c.binding_digest,"
                "c.binding_digest_key_id,c.user_id,s.status,s.generation,"
                "s.family_id,f.status,f.current_generation,"
                "EXISTS (SELECT 1 FROM iam.external_identities AS identity "
                "JOIN iam.users AS account ON account.id=identity.user_id "
                "WHERE identity.issuer=%s AND identity.subject_digest=%s "
                "AND identity.subject_digest_key_id='oidc-subject-v1' "
                "AND identity.status='ACTIVE' AND identity.user_id=%s "
                "AND account.status='ACTIVE') "
                "FROM iam.auth_transactions AS t "
                "JOIN iam.access_invitations AS i ON i.id=t.invitation_id "
                "JOIN iam.contact_points AS c ON c.id=i.recipient_contact_id "
                "JOIN iam.sessions AS s ON s.id=t.initiating_session_id "
                "JOIN iam.session_families AS f ON f.id=s.family_id "
                "WHERE t.id=%s",
                (
                    provider_issuer,
                    subject_digest,
                    seed.actor_user_id,
                    transaction_id,
                ),
            ).fetchone()
        self.assertEqual(
            frozen_facts,
            (
                2,
                "STEP_UP",
                1,
                "EXCHANGING",
                2,
                exchange_owner_id,
                provider_issuer,
                seed.actor_user_id,
                seed.actor_user_id,
                seed.actor_session_id,
                invitation_id,
                1,
                contact_id,
                contact_type,
                contact_binding_digest,
                contact_binding_key_id,
                "ISSUED",
                1,
                contact_id,
                contact_type,
                contact_binding_digest,
                contact_binding_key_id,
                None,
                "ACTIVE",
                1,
                seed.actor_family_id,
                "ACTIVE",
                1,
                True,
            ),
        )
        new_session_id = uuid4()
        finalized = uow.finalize_invitation_step_up(
            OidcPostgresInvitationStepUpFinalize(
                auth_transaction_id=transaction_id,
                exchange_owner_id=exchange_owner_id,
                invitation_id=invitation_id,
                invitation_version=1,
                expected_contact_point_id=contact_id,
                expected_contact_type=contact_type,
                expected_contact_binding_digest=contact_binding_digest,
                expected_contact_binding_key_id=contact_binding_key_id,
                expected_user_id=seed.actor_user_id,
                initiating_session_id=seed.actor_session_id,
                session_family_id=seed.actor_family_id,
                predecessor_generation=1,
                provider_issuer=provider_issuer,
                subject_digest=subject_digest,
                subject_digest_key_id="oidc-subject-v1",
                verified_contact_type=contact_type,
                verified_contact_binding_digest=contact_binding_digest,
                verified_contact_binding_key_id=contact_binding_key_id,
                new_session_id=new_session_id,
                handle_digest=_digest("invitation-step-up-new-session"),
                handle_digest_key_id="session-handle-v1",
                csrf_salt=_digest("invitation-step-up-csrf-salt"),
                csrf_key_id="session-csrf-v1",
                csrf_digest=_digest("invitation-step-up-csrf"),
                auth_time=seed.now - timedelta(seconds=5),
                token_issued_at=seed.now - timedelta(seconds=4),
                token_expires_at=seed.now + timedelta(minutes=5),
                acr_code="urn:desire:acr:synthetic-internal-sandbox:mfa",
                amr_codes=("mfa", "synthetic"),
                audit_event_id=uuid4(),
                system_actor_id=uuid4(),
                correlation_id=uuid4(),
                trace_id=uuid4(),
            )
        )
        self.assertEqual(
            (
                finalized.session_id,
                finalized.session_family_id,
                finalized.user_id,
                finalized.generation,
            ),
            (
                new_session_id,
                seed.actor_family_id,
                seed.actor_user_id,
                2,
            ),
        )
        with self._admin() as connection:
            facts = connection.execute(
                "SELECT t.status,f.current_generation,old.status,"
                "old.revocation_reason_code,new.status,new.rotation_reason,"
                "new.predecessor_session_id,new.verified_contact_point_id,"
                "new.verified_for_invitation_id,new.generation,"
                "contact.user_id,contact.verified_at IS NOT NULL "
                "FROM iam.auth_transactions AS t "
                "JOIN iam.session_families AS f ON f.id=%s "
                "JOIN iam.sessions AS old ON old.id=%s "
                "JOIN iam.sessions AS new ON new.id=%s "
                "JOIN iam.contact_points AS contact "
                "ON contact.id=new.verified_contact_point_id WHERE t.id=%s",
                (
                    seed.actor_family_id,
                    seed.actor_session_id,
                    new_session_id,
                    transaction_id,
                ),
            ).fetchone()
        self.assertEqual(
            facts,
            (
                "SUCCEEDED",
                2,
                "REVOKED",
                "STEP_UP_ROTATED",
                "ACTIVE",
                "STEP_UP",
                seed.actor_session_id,
                contact_id,
                invitation_id,
                2,
                seed.actor_user_id,
                True,
            ),
        )


if __name__ == "__main__":
    unittest.main()
