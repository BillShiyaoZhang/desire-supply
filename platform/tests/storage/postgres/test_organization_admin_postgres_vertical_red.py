"""Semantic RED for the PostgreSQL-only ORG_ADMIN command boundary.

The existing IAM HTTP contract already exposes this surface.  These tests
freeze the production adapter shape before IAM0034 makes the database program
available.  They intentionally reject a generic SQL executor or an in-memory
fallback: callers may invoke only the six reviewed operations.
"""

from __future__ import annotations

from dataclasses import fields, replace
from datetime import datetime, timedelta, timezone
import inspect
import unittest
from uuid import UUID

from psycopg.pq import TransactionStatus

from desire_platform.identity_access.adapters.postgres.organization_admin import (
    ORGANIZATION_ADMIN_POSTGRES_OPERATIONS,
    OrganizationAdminPostgresConfigurationError,
    OrganizationAdminPostgresDatabaseRequest,
    OrganizationAdminPostgresDatabaseResult,
    OrganizationAdminPostgresGeneratedIds,
    OrganizationAdminPostgresInvitationMaterial,
    OrganizationAdminPostgresIssueResolution,
    OrganizationAdminPostgresOperation,
    OrganizationAdminPostgresReceiptMaterial,
    OrganizationAdminPostgresScope,
    PsycopgOrganizationAdminUnitOfWorkFactory,
)
from desire_platform.identity_access.adapters.postgres.organization_admin_handlers import (
    HmacOrganizationInvitationTokenCodec,
    InternalSandboxOrganizationInvitationIssueSafetyHold,
    OrganizationAdminKeys,
    PostgresIssueOrganizationAccessInvitationHandler,
    PostgresRevokeAccessInvitationHandler,
    PostgresRevokeMembershipHandler,
    PostgresSuspendMembershipHandler,
)
from desire_platform.identity_access.adapters.postgres.organization_public_name import (
    PostgresUpdateOrganizationPublicNameHandler,
    PsycopgOrganizationPublicNameUnitOfWorkFactory,
)
from desire_platform.identity_access.application.organization_profile import (
    OrganizationPublicNameActorContext,
    OrganizationPublicNameReasonCode,
    UpdateOrganizationPublicNameCommand,
)
from desire_platform.identity_access.application.issue_access_invitations import (
    InvitationIssuerContext,
    IssueAccessInvitationCommand,
    IssuerKind,
    RecipientContactType,
    RecipientInput,
)
from desire_platform.identity_access.domain.invitations import TargetRole
from desire_platform.identity_access.domain.errors import IamError, IamPreconditionFailed
from desire_platform.identity_access.domain.authority_lifecycle import (
    LifecycleActorContext,
    LifecycleReason,
    RevokeAccessInvitationCommand,
    RevokeMembershipCommand,
    SuspendMembershipCommand,
)
from desire_platform.identity_access.ports.recipient_binding import (
    RecipientBindingTuple,
)


UTC_NOW = datetime(2026, 8, 16, 8, 0, tzinfo=timezone.utc)


def _id(value: int) -> UUID:
    return UUID(int=value)


def _lifecycle_actor() -> LifecycleActorContext:
    return LifecycleActorContext(
        actor_user_id=str(_id(1)),
        current_session_id=str(_id(2)),
        original_actor_id=None,
        correlation_id=str(_id(6)),
        causation_id=str(_id(5)),
        trace_id=str(_id(7)),
    )


class OrganizationAdminPostgresVerticalRedTest(unittest.TestCase):
    def test_operation_registry_is_closed_to_the_six_canonical_writes(self) -> None:
        self.assertEqual(
            tuple(item.value for item in ORGANIZATION_ADMIN_POSTGRES_OPERATIONS),
            (
                "IssueAccessInvitation",
                "RevokeAccessInvitation",
                "SuspendMembership",
                "ResumeMembership",
                "RevokeMembership",
                "UpdateOrganizationPublicName",
            ),
        )
        public = {
            name
            for name, value in inspect.getmembers(
                PsycopgOrganizationAdminUnitOfWorkFactory,
                predicate=inspect.isfunction,
            )
            if not name.startswith("_")
        }
        self.assertEqual(
            public,
            {
                "execute_issue_access_invitation",
                "execute_revoke_access_invitation",
                "execute_suspend_membership",
                "execute_resume_membership",
                "execute_revoke_membership",
                "execute_update_organization_public_name",
            },
        )
        self.assertNotIn("execute", public)
        self.assertNotIn("query", public)

    def test_public_name_handler_binds_same_org_mfa_receipt_and_safe_result(self) -> None:
        requests = []
        keys = OrganizationAdminKeys(
            idempotency_key=b"i" * 32,
            payload_hash_key=b"p" * 32,
            invitation_token_keys=(("invitation-token-2026-01", b"k" * 32),),
            active_invitation_token_key_id="invitation-token-2026-01",
        )
        uow = PsycopgOrganizationPublicNameUnitOfWorkFactory(
            connections=_NoCheckoutConnections(),
            event_validator=_Validator(),
            response_validator=_Validator(),
        )

        def execute(request):
            requests.append(request)
            return OrganizationAdminPostgresDatabaseResult(
                operation=(
                    OrganizationAdminPostgresOperation.UPDATE_ORGANIZATION_PUBLIC_NAME
                ),
                replayed=False,
                safe_response={
                    "organization_id": str(request.scope.organization_id),
                    "public_name": request.public_name,
                    "type": "BUSINESS",
                    "status": "ACTIVE",
                    "aggregate_version": request.expected_version + 1,
                    "entity_tag": f'"v{request.expected_version + 1}"',
                },
                response_entity_tag=f'"v{request.expected_version + 1}"',
            )

        uow.execute = execute
        handler = PostgresUpdateOrganizationPublicNameHandler(
            uow_factory=uow,
            keys=keys,
            clock=_Clock(),
            id_source=_FreshIds(),
        )
        actor = OrganizationPublicNameActorContext(
            actor_user_id=str(_id(1)),
            current_session_id=str(_id(2)),
            original_actor_id=None,
            correlation_id=str(_id(6)),
            causation_id=str(_id(5)),
            trace_id=str(_id(7)),
            auth_time=UTC_NOW - timedelta(minutes=5),
            acr_code="urn:desire:acr:synthetic-internal-sandbox:mfa",
            amr_codes=("mfa", "synthetic"),
        )
        command = UpdateOrganizationPublicNameCommand(
            organization_id=str(_id(3)),
            expected_version=4,
            public_name="新的公开组织名",
            reason_code=(
                OrganizationPublicNameReasonCode.PUBLIC_NAME_CORRECTION
            ),
            idempotency_key="org-admin-public-name-0001",
        )

        result = handler.handle(actor=actor, command=command)

        self.assertFalse(result.replayed)
        self.assertEqual(result.organization["public_name"], command.public_name)
        self.assertEqual(len(requests), 1)
        request = requests[0]
        self.assertEqual(
            request.operation,
            OrganizationAdminPostgresOperation.UPDATE_ORGANIZATION_PUBLIC_NAME,
        )
        self.assertEqual(request.scope.target_id, request.scope.organization_id)
        self.assertEqual(request.public_name, command.public_name)
        self.assertEqual(request.reason_code, "PUBLIC_NAME_CORRECTION")
        self.assertIsNone(request.invitation)
        self.assertIsNone(request.issue_hold)
        self.assertIsNone(request.resume_hold)
        self.assertIsNone(request.generated_ids.recipient_contact_id)
        self.assertIsNone(request.generated_ids.secondary_outbox_event_id)
        self.assertEqual(request.receipt.retain_until - UTC_NOW, timedelta(days=31))

        stale_mfa = replace(actor, auth_time=UTC_NOW - timedelta(minutes=10))
        with self.assertRaises(IamError) as caught:
            handler.handle(actor=stale_mfa, command=command)
        self.assertEqual(caught.exception.code, "MFA_STEP_UP_REQUIRED")
        self.assertEqual(len(requests), 1)

    def test_public_name_request_rejects_cross_org_and_format_controls(self) -> None:
        base = self._revoke_membership_request()
        with self.assertRaises(ValueError):
            OrganizationAdminPostgresDatabaseRequest(
                operation=(
                    OrganizationAdminPostgresOperation.UPDATE_ORGANIZATION_PUBLIC_NAME
                ),
                scope=base.scope,
                receipt=base.receipt,
                expected_version=base.expected_version,
                generated_ids=replace(
                    base.generated_ids, secondary_outbox_event_id=None
                ),
                invitation=None,
                reason_code="PUBLIC_NAME_CORRECTION",
                public_name="Invisible\u200bName",
            )

    def test_public_name_stale_result_exposes_only_validated_current_etag(self) -> None:
        base = self._revoke_membership_request()
        request = OrganizationAdminPostgresDatabaseRequest(
            operation=(
                OrganizationAdminPostgresOperation.UPDATE_ORGANIZATION_PUBLIC_NAME
            ),
            scope=replace(
                base.scope,
                target_id=base.scope.organization_id,
            ),
            receipt=base.receipt,
            expected_version=base.expected_version,
            generated_ids=replace(
                base.generated_ids,
                secondary_outbox_event_id=None,
            ),
            invitation=None,
            reason_code="PUBLIC_NAME_CORRECTION",
            public_name="Reviewed public name",
        )

        for payload in (
            {
                "decision_code": "PRECONDITION_FAILED",
                "current_entity_tag": '"v8"',
            },
            {
                "decision_code": "PRECONDITION_FAILED",
                "current_entity_tag": 'W/"v8"',
            },
            {
                "decision_code": "PRECONDITION_FAILED",
                "current_entity_tag": '"v8"',
                "unexpected": True,
            },
        ):
            with self.subTest(payload=payload):
                uow = PsycopgOrganizationPublicNameUnitOfWorkFactory(
                    connections=_ConnectionSource((_Connection(payload),)),
                    event_validator=_Validator(),
                    response_validator=_Validator(),
                )
                if payload == {
                    "decision_code": "PRECONDITION_FAILED",
                    "current_entity_tag": '"v8"',
                }:
                    with self.assertRaises(IamPreconditionFailed) as caught:
                        uow.execute(request)
                    self.assertEqual(caught.exception.entity_tag, '"v8"')
                else:
                    with self.assertRaises(IamError) as caught:
                        uow.execute(request)
                    self.assertEqual(caught.exception.code, "SERVICE_UNAVAILABLE")

    def test_request_contains_only_server_coordinates_and_keyed_material(self) -> None:
        self.assertEqual(
            tuple(field.name for field in fields(OrganizationAdminPostgresScope)),
            (
                "actor_user_id",
                "current_session_id",
                "organization_id",
                "target_id",
                "command_id",
                "correlation_id",
                "causation_id",
                "trace_id",
                "original_actor_id",
            ),
        )
        self.assertEqual(
            tuple(
                field.name
                for field in fields(OrganizationAdminPostgresInvitationMaterial)
            ),
            (
                "recipient_contact_id",
                "recipient_binding_digest",
                "recipient_binding_digest_key_id",
                "masked_recipient_label",
                "target_role",
                "expires_at",
                "token_nonce",
                "token_key_id",
                "token_format_version",
            ),
        )
        forbidden = {
            "recipient",
            "recipient_email",
            "raw_idempotency_key",
            "access_invitation_token",
            "csrf_token",
            "session_handle",
            "policy_selector_digest",
            "policy_bundle_id",
            "issuer_role",
        }
        names = {
            field.name
            for owner in (
                OrganizationAdminPostgresScope,
                OrganizationAdminPostgresInvitationMaterial,
                OrganizationAdminPostgresReceiptMaterial,
                OrganizationAdminPostgresGeneratedIds,
                OrganizationAdminPostgresDatabaseRequest,
            )
            for field in fields(owner)
        }
        self.assertTrue(forbidden.isdisjoint(names))

    def test_issue_and_membership_shapes_cannot_be_confused(self) -> None:
        scope = OrganizationAdminPostgresScope(
            actor_user_id=_id(1),
            current_session_id=_id(2),
            organization_id=_id(3),
            target_id=_id(4),
            command_id=_id(5),
            correlation_id=_id(6),
            causation_id=_id(5),
            trace_id=_id(7),
            original_actor_id=None,
        )
        receipt = OrganizationAdminPostgresReceiptMaterial(
            receipt_id=_id(5),
            idempotency_key_digest=b"i" * 32,
            idempotency_key_digest_key_id="iam-receipt-idempotency-hmac-2026-01",
            payload_hash=b"p" * 32,
            payload_hash_key_id="iam-receipt-payload-hmac-2026-01",
            retain_until=datetime(2026, 9, 15, 8, 0, tzinfo=timezone.utc),
        )
        generated = OrganizationAdminPostgresGeneratedIds(
            audit_event_id=_id(8),
            outbox_event_id=_id(9),
            recipient_contact_id=_id(10),
        )
        invitation = OrganizationAdminPostgresInvitationMaterial(
            recipient_contact_id=_id(10),
            recipient_binding_digest=b"r" * 32,
            recipient_binding_digest_key_id="recipient-binding-2026-01",
            masked_recipient_label="n***@example.invalid",
            target_role="DEMAND_OWNER",
            expires_at=datetime(2026, 8, 23, 8, 0, tzinfo=timezone.utc),
            token_nonce=b"t" * 32,
            token_key_id="invitation-token-2026-01",
            token_format_version="access-invitation-token-v1",
        )
        request = OrganizationAdminPostgresDatabaseRequest(
            operation=OrganizationAdminPostgresOperation.ISSUE_ACCESS_INVITATION,
            scope=scope,
            receipt=receipt,
            expected_version=1,
            generated_ids=generated,
            invitation=invitation,
            reason_code=None,
        )
        self.assertEqual(request.scope.target_id, _id(4))
        with self.assertRaises(ValueError):
            OrganizationAdminPostgresDatabaseRequest(
                operation=OrganizationAdminPostgresOperation.SUSPEND_MEMBERSHIP,
                scope=scope,
                receipt=receipt,
                expected_version=1,
                generated_ids=generated,
                invitation=invitation,
                reason_code="ACCESS_REVIEW",
            )

    def test_capability_replay_is_byte_identical_and_never_enters_safe_dto(self) -> None:
        request = self._issue_request()
        response = {
            "invitation_id": str(request.scope.target_id),
            "purpose": "ORGANIZATION_MEMBERSHIP",
            "organization_id": str(request.scope.organization_id),
            "target_role": "DEMAND_OWNER",
            "masked_recipient_label": "n***@example.invalid",
            "is_initial_admin": False,
            "status": "ISSUED",
            "expires_at": "2026-08-23T08:00:00Z",
            "created_at": "2026-08-16T08:00:00Z",
            "required_policy_bundle_id": str(_id(91)),
            "aggregate_version": 1,
            "entity_tag": '"v1"',
        }
        reconstruction = {
            "nonce": (b"t" * 32).hex(),
            "token_key_id": "invitation-token-2026-01",
            "token_format_version": "access-invitation-token-v1",
            "expires_at": "2026-08-23T08:00:00Z",
        }
        validator = _Validator()
        source = _ConnectionSource(
            (
                _Connection(
                    {
                        "decision_code": "AUTHORIZED",
                        "replayed": False,
                        "safe_response": response,
                        "response_entity_tag": '"v1"',
                        "capability_reconstruction": reconstruction,
                        "outbox_event": {
                            "event_id": str(_id(9)),
                            "event_type": "AccessInvitationIssued",
                        },
                        "secondary_outbox_event": None,
                    }
                ),
                _Connection(
                    {
                        "decision_code": "AUTHORIZED",
                        "replayed": True,
                        "safe_response": response,
                        "response_entity_tag": '"v1"',
                        "capability_reconstruction": reconstruction,
                        "outbox_event": None,
                    }
                ),
            )
        )
        uow = PsycopgOrganizationAdminUnitOfWorkFactory(
            connections=source,
            event_validator=validator,
            response_validator=validator,
        )
        first = uow.execute_issue_access_invitation(request)
        replay = uow.execute_issue_access_invitation(request)
        self.assertFalse(first.replayed)
        self.assertTrue(replay.replayed)
        self.assertEqual(
            first.capability_reconstruction,
            replay.capability_reconstruction,
        )
        forbidden = {"nonce", "token_nonce", "token_key_id", "binding_digest"}
        self.assertTrue(forbidden.isdisjoint(first.safe_response))
        self.assertTrue(forbidden.isdisjoint(validator.responses[0]))

        keys = OrganizationAdminKeys(
            idempotency_key=b"i" * 32,
            payload_hash_key=b"p" * 32,
            invitation_token_keys=(("invitation-token-2026-01", b"k" * 32),),
            active_invitation_token_key_id="invitation-token-2026-01",
        )
        codec = HmacOrganizationInvitationTokenCodec(keys=keys)
        tokens = tuple(
            codec.issue(
                invitation_id=response["invitation_id"],
                nonce=bytes.fromhex(item.capability_reconstruction["nonce"]),
                expires_at=datetime.fromisoformat(
                    item.capability_reconstruction["expires_at"].replace(
                        "Z", "+00:00"
                    )
                ),
                token_key_id=item.capability_reconstruction["token_key_id"],
                token_format_version=item.capability_reconstruction[
                    "token_format_version"
                ],
            )
            for item in (first, replay)
        )
        self.assertEqual(tokens[0], tokens[1])
        self.assertNotIn(reconstruction["nonce"], tokens[0])
        verified = codec.verify(
            access_invitation_token=tokens[0], now=UTC_NOW
        )
        self.assertEqual(verified.invitation_id, response["invitation_id"])

    def test_membership_roles_revoked_rejection_rolls_back_before_commit(self) -> None:
        request = self._revoke_membership_request()
        connection = _Connection(self._revoke_database_payload(request))
        source = _ConnectionSource((connection,))
        validator = _RejectMembershipRolesRevokedValidator()
        uow = PsycopgOrganizationAdminUnitOfWorkFactory(
            connections=source,
            event_validator=validator,
            response_validator=_Validator(),
        )

        with self.assertRaises(OrganizationAdminPostgresConfigurationError):
            uow.execute_revoke_membership(request)

        self.assertEqual(
            tuple(event["event_type"] for event in validator.events),
            ("MembershipRevoked", "MembershipRolesRevoked"),
        )
        self.assertIn("ROLLBACK", connection.statements)
        self.assertNotIn("COMMIT", connection.statements)
        self.assertEqual(source.released, [connection])
        self.assertEqual(source.discarded, [])

    def test_fresh_revoke_validates_both_events_before_commit(self) -> None:
        request = self._revoke_membership_request()
        connection = _Connection(self._revoke_database_payload(request))
        source = _ConnectionSource((connection,))
        validator = _Validator()
        result = PsycopgOrganizationAdminUnitOfWorkFactory(
            connections=source,
            event_validator=validator,
            response_validator=_Validator(),
        ).execute_revoke_membership(request)

        self.assertFalse(result.replayed)
        self.assertEqual(
            tuple(event["event_type"] for event in validator.events),
            ("MembershipRevoked", "MembershipRolesRevoked"),
        )
        self.assertIn("COMMIT", connection.statements)
        self.assertNotIn("ROLLBACK", connection.statements)

    def test_revoke_rejects_missing_non_mapping_or_extra_event_shapes(self) -> None:
        request = self._revoke_membership_request()
        cases = {}
        missing = self._revoke_database_payload(request)
        del missing["secondary_outbox_event"]
        cases["missing secondary"] = missing
        not_an_event = self._revoke_database_payload(request)
        not_an_event["secondary_outbox_event"] = [
            not_an_event["secondary_outbox_event"]
        ]
        cases["secondary sequence"] = not_an_event
        extra = self._revoke_database_payload(request)
        extra["tertiary_outbox_event"] = {
            "event_type": "MembershipRolesRevoked"
        }
        cases["extra event slot"] = extra

        for label, payload in cases.items():
            with self.subTest(label=label):
                connection = _Connection(payload)
                source = _ConnectionSource((connection,))
                uow = PsycopgOrganizationAdminUnitOfWorkFactory(
                    connections=source,
                    event_validator=_Validator(),
                    response_validator=_Validator(),
                )
                with self.assertRaises(IamError) as caught:
                    uow.execute_revoke_membership(request)
                self.assertEqual(caught.exception.code, "SERVICE_UNAVAILABLE")
                self.assertIn("ROLLBACK", connection.statements)
                self.assertNotIn("COMMIT", connection.statements)

    def test_invitation_token_rotation_retains_only_explicit_old_keys(self) -> None:
        old_key_id = "invitation-token-2026-01"
        new_key_id = "invitation-token-2026-02"
        old_codec = HmacOrganizationInvitationTokenCodec(
            keys=OrganizationAdminKeys(
                idempotency_key=b"i" * 32,
                payload_hash_key=b"p" * 32,
                invitation_token_keys=((old_key_id, b"o" * 32),),
                active_invitation_token_key_id=old_key_id,
            )
        )
        old_token = old_codec.issue(
            invitation_id=str(_id(4)),
            nonce=b"n" * 32,
            expires_at=datetime(2026, 8, 23, 8, 0, tzinfo=timezone.utc),
            token_key_id=old_key_id,
        )
        retained_codec = HmacOrganizationInvitationTokenCodec(
            keys=OrganizationAdminKeys(
                idempotency_key=b"i" * 32,
                payload_hash_key=b"p" * 32,
                invitation_token_keys=(
                    (new_key_id, b"q" * 32),
                    (old_key_id, b"o" * 32),
                ),
                active_invitation_token_key_id=new_key_id,
            )
        )
        self.assertEqual(
            retained_codec.verify(
                access_invitation_token=old_token,
                now=UTC_NOW,
            ).token_key_id,
            old_key_id,
        )
        removed_codec = HmacOrganizationInvitationTokenCodec(
            keys=OrganizationAdminKeys(
                idempotency_key=b"i" * 32,
                payload_hash_key=b"p" * 32,
                invitation_token_keys=((new_key_id, b"q" * 32),),
                active_invitation_token_key_id=new_key_id,
            )
        )
        with self.assertRaises(ValueError):
            removed_codec.verify(access_invitation_token=old_token, now=UTC_NOW)
        with self.assertRaises(ValueError):
            OrganizationAdminKeys(
                idempotency_key=b"i" * 32,
                payload_hash_key=b"p" * 32,
                invitation_token_keys=(
                    (old_key_id, b"o" * 32),
                    (new_key_id, b"q" * 32),
                ),
                active_invitation_token_key_id=new_key_id,
            )

    def test_synthetic_mfa_and_fresh_generated_ids_preserve_exact_issue_replay(self) -> None:
        response = {
            "invitation_id": str(_id(40)),
            "purpose": "ORGANIZATION_MEMBERSHIP",
            "organization_id": str(_id(3)),
            "target_role": "DEMAND_OWNER",
            "masked_recipient_label": "p***@example.test",
            "is_initial_admin": False,
            "status": "ISSUED",
            "expires_at": "2026-08-23T08:00:00Z",
            "created_at": "2026-08-16T08:00:00Z",
            "required_policy_bundle_id": str(_id(91)),
            "aggregate_version": 1,
            "entity_tag": '"v1"',
        }
        reconstruction = {
            "nonce": (b"z" * 32).hex(),
            "token_key_id": "invitation-token-2026-01",
            "token_format_version": "access-invitation-token-v1",
            "expires_at": response["expires_at"],
        }
        connections = (
            _Connection(
                {
                    "decision_code": "AUTHORIZED",
                    "replayed": False,
                    "safe_response": response,
                    "response_entity_tag": '"v1"',
                    "capability_reconstruction": reconstruction,
                    "outbox_event": {
                        "event_id": str(_id(9)),
                        "event_type": "AccessInvitationIssued",
                    },
                    "secondary_outbox_event": None,
                }
            ),
            _Connection(
                {
                    "decision_code": "AUTHORIZED",
                    "replayed": True,
                    "safe_response": response,
                    "response_entity_tag": '"v1"',
                    "capability_reconstruction": reconstruction,
                    "outbox_event": None,
                }
            ),
        )
        source = _ConnectionSource(connections)
        keys = OrganizationAdminKeys(
            idempotency_key=b"i" * 32,
            payload_hash_key=b"p" * 32,
            invitation_token_keys=(("invitation-token-2026-01", b"k" * 32),),
            active_invitation_token_key_id="invitation-token-2026-01",
        )
        ids = _FreshIds()
        secrets = _FreshSecrets()
        handler = PostgresIssueOrganizationAccessInvitationHandler(
            uow_factory=PsycopgOrganizationAdminUnitOfWorkFactory(
                connections=source,
                event_validator=_Validator(),
                response_validator=_Validator(),
            ),
            target_resolver=_IssueResolver(
                safe_response=response,
                capability_reconstruction=reconstruction,
            ),
            safety_hold=InternalSandboxOrganizationInvitationIssueSafetyHold(
                deployment_mode="INTERNAL_SANDBOX", clock=_Clock()
            ),
            safety_hold_policy_version=(
                "iam-organization-invitation-issue-hold-v1"
            ),
            recipient_binding=_RecipientBinding(),
            token_codec=HmacOrganizationInvitationTokenCodec(keys=keys),
            keys=keys,
            clock=_Clock(),
            id_source=ids,
            secret_source=secrets,
        )
        actor = InvitationIssuerContext(
            actor_kind=IssuerKind.USER,
            actor_id=str(_id(1)),
            session_id=str(_id(2)),
            original_actor_id=None,
            correlation_id=str(_id(6)),
            causation_id=str(_id(5)),
            trace_id=str(_id(7)),
            auth_time=datetime(2026, 8, 16, 7, 55, tzinfo=timezone.utc),
            acr_code="urn:desire:acr:synthetic-internal-sandbox:mfa",
            amr_codes=("mfa", "synthetic"),
        )
        command = IssueAccessInvitationCommand(
            organization_id=str(_id(3)),
            expected_organization_version=1,
            recipient=RecipientInput(
                type=RecipientContactType.EMAIL,
                value="person@example.test",
            ),
            target_role=TargetRole.DEMAND_OWNER,
            expires_at=datetime(2026, 8, 23, 8, 0, tzinfo=timezone.utc),
            idempotency_key="org-admin-replay-0001",
        )
        first = handler.handle(actor=actor, command=command)
        replay = handler.handle(actor=actor, command=command)
        self.assertFalse(first.replayed)
        self.assertTrue(replay.replayed)
        self.assertEqual(first.access_invitation_token, replay.access_invitation_token)
        self.assertEqual(first.join_fragment_url, replay.join_fragment_url)
        # The completed receipt is returned before any second-pass UoW, UUID,
        # or nonce source is touched.
        self.assertEqual(len(source.released), 1)
        self.assertEqual(len(source._connections), 1)
        self.assertEqual(ids._next, 105)
        self.assertEqual(secrets._next, 1)

    def test_three_base_lifecycle_handlers_capture_server_time_and_execute(self) -> None:
        keys = OrganizationAdminKeys(
            idempotency_key=b"i" * 32,
            payload_hash_key=b"p" * 32,
            invitation_token_keys=(("invitation-token-2026-01", b"k" * 32),),
            active_invitation_token_key_id="invitation-token-2026-01",
        )
        actor = LifecycleActorContext(
            actor_user_id=str(_id(1)),
            current_session_id=str(_id(2)),
            original_actor_id=None,
            correlation_id=str(_id(6)),
            causation_id=str(_id(5)),
            trace_id=str(_id(7)),
        )
        reason = LifecycleReason(reason_code="ACCESS_REVIEW")
        cases = (
            (
                PostgresRevokeAccessInvitationHandler,
                OrganizationAdminPostgresOperation.REVOKE_ACCESS_INVITATION,
                "execute_revoke_access_invitation",
                RevokeAccessInvitationCommand(
                    invitation_id=str(_id(30)),
                    expected_version=2,
                    idempotency_key="org-admin-revoke-invitation-0001",
                    reason=reason,
                ),
                "invitation_id",
            ),
            (
                PostgresSuspendMembershipHandler,
                OrganizationAdminPostgresOperation.SUSPEND_MEMBERSHIP,
                "execute_suspend_membership",
                SuspendMembershipCommand(
                    membership_id=str(_id(31)),
                    expected_version=2,
                    idempotency_key="org-admin-suspend-membership-0001",
                    reason=reason,
                ),
                "membership_id",
            ),
            (
                PostgresRevokeMembershipHandler,
                OrganizationAdminPostgresOperation.REVOKE_MEMBERSHIP,
                "execute_revoke_membership",
                RevokeMembershipCommand(
                    membership_id=str(_id(32)),
                    expected_version=2,
                    idempotency_key="org-admin-revoke-membership-0001",
                    reason=reason,
                ),
                "membership_id",
            ),
        )
        for handler_type, operation, entrypoint, command, id_field in cases:
            with self.subTest(operation=operation.value):
                requests = []
                uow = PsycopgOrganizationAdminUnitOfWorkFactory(
                    connections=_NoCheckoutConnections(),
                    event_validator=_Validator(),
                    response_validator=_Validator(),
                )

                def execute(request, *, expected_operation=operation):
                    requests.append(request)
                    target_id = str(request.scope.target_id)
                    safe_response = {
                        id_field: target_id,
                        "organization_id": str(request.scope.organization_id),
                        "status": "REVOKED",
                        "aggregate_version": 3,
                        "entity_tag": '"v3"',
                    }
                    return OrganizationAdminPostgresDatabaseResult(
                        operation=expected_operation,
                        replayed=False,
                        safe_response=safe_response,
                        response_entity_tag='"v3"',
                    )

                setattr(uow, entrypoint, execute)
                handler = handler_type(
                    uow_factory=uow,
                    target_resolver=_LifecycleResolver(),
                    keys=keys,
                    clock=_Clock(),
                    id_source=_FreshIds(),
                )
                result = handler.handle(actor=actor, command=command)
                self.assertFalse(result.replayed)
                self.assertEqual(result.http_status, 200)
                self.assertEqual(len(requests), 1)
                self.assertEqual(requests[0].operation, operation)
                self.assertEqual(requests[0].receipt.retain_until - UTC_NOW, timedelta(days=31))
                self.assertIsNone(requests[0].resume_hold)

    def test_base_lifecycle_operation_rejects_a_different_command_type(self) -> None:
        keys = OrganizationAdminKeys(
            idempotency_key=b"i" * 32,
            payload_hash_key=b"p" * 32,
            invitation_token_keys=(("invitation-token-2026-01", b"k" * 32),),
            active_invitation_token_key_id="invitation-token-2026-01",
        )
        resolver = _LifecycleResolver()
        handler = PostgresSuspendMembershipHandler(
            uow_factory=PsycopgOrganizationAdminUnitOfWorkFactory(
                connections=_NoCheckoutConnections(),
                event_validator=_Validator(),
                response_validator=_Validator(),
            ),
            target_resolver=resolver,
            keys=keys,
            clock=_Clock(),
            id_source=_FreshIds(),
        )
        with self.assertRaises(IamError) as caught:
            handler.handle(
                actor=_lifecycle_actor(),
                command=RevokeMembershipCommand(
                    membership_id=str(_id(32)),
                    expected_version=2,
                    idempotency_key="org-admin-command-confusion-0001",
                    reason=LifecycleReason(reason_code="ACCESS_REVIEW"),
                ),
            )
        self.assertEqual(caught.exception.code, "INVALID_REQUEST")
        self.assertFalse(hasattr(resolver, "query"))

    def test_private_reason_note_changes_receipt_payload_without_entering_request(self) -> None:
        requests = []
        keys = OrganizationAdminKeys(
            idempotency_key=b"i" * 32,
            payload_hash_key=b"p" * 32,
            invitation_token_keys=(("invitation-token-2026-01", b"k" * 32),),
            active_invitation_token_key_id="invitation-token-2026-01",
        )
        uow = PsycopgOrganizationAdminUnitOfWorkFactory(
            connections=_NoCheckoutConnections(),
            event_validator=_Validator(),
            response_validator=_Validator(),
        )

        def execute(request):
            requests.append(request)
            return OrganizationAdminPostgresDatabaseResult(
                operation=OrganizationAdminPostgresOperation.SUSPEND_MEMBERSHIP,
                replayed=False,
                safe_response={
                    "membership_id": str(request.scope.target_id),
                    "organization_id": str(request.scope.organization_id),
                    "status": "SUSPENDED",
                    "aggregate_version": 3,
                    "entity_tag": '"v3"',
                },
                response_entity_tag='"v3"',
            )

        uow.execute_suspend_membership = execute
        handler = PostgresSuspendMembershipHandler(
            uow_factory=uow,
            target_resolver=_LifecycleResolver(),
            keys=keys,
            clock=_Clock(),
            id_source=_FreshIds(),
        )
        for note in ("private-note-a", "private-note-b"):
            handler.handle(
                actor=_lifecycle_actor(),
                command=SuspendMembershipCommand(
                    membership_id=str(_id(31)),
                    expected_version=2,
                    idempotency_key="org-admin-note-conflict-0001",
                    reason=LifecycleReason(
                        reason_code="ACCESS_REVIEW", reason_note=note
                    ),
                ),
            )
        self.assertNotEqual(
            requests[0].receipt.payload_hash, requests[1].receipt.payload_hash
        )
        self.assertNotIn("private-note-a", repr(requests[0]))
        self.assertNotIn("private-note-b", repr(requests[1]))

    @staticmethod
    def _revoke_membership_request() -> OrganizationAdminPostgresDatabaseRequest:
        return OrganizationAdminPostgresDatabaseRequest(
            operation=OrganizationAdminPostgresOperation.REVOKE_MEMBERSHIP,
            scope=OrganizationAdminPostgresScope(
                actor_user_id=_id(1),
                current_session_id=_id(2),
                organization_id=_id(3),
                target_id=_id(32),
                command_id=_id(5),
                correlation_id=_id(6),
                causation_id=_id(5),
                trace_id=_id(7),
                original_actor_id=None,
            ),
            receipt=OrganizationAdminPostgresReceiptMaterial(
                receipt_id=_id(5),
                idempotency_key_digest=b"i" * 32,
                idempotency_key_digest_key_id=(
                    "iam-receipt-idempotency-hmac-2026-01"
                ),
                payload_hash=b"p" * 32,
                payload_hash_key_id="iam-receipt-payload-hmac-2026-01",
                retain_until=datetime(
                    2026, 9, 15, 8, 0, tzinfo=timezone.utc
                ),
            ),
            expected_version=2,
            generated_ids=OrganizationAdminPostgresGeneratedIds(
                audit_event_id=_id(8),
                outbox_event_id=_id(9),
                secondary_outbox_event_id=_id(11),
                recipient_contact_id=None,
            ),
            invitation=None,
            reason_code="ACCESS_REVIEW",
        )

    @staticmethod
    def _revoke_database_payload(
        request: OrganizationAdminPostgresDatabaseRequest,
    ) -> dict:
        return {
            "decision_code": "AUTHORIZED",
            "replayed": False,
            "safe_response": {
                "membership_id": str(request.scope.target_id),
                "organization_id": str(request.scope.organization_id),
                "status": "REVOKED",
                "aggregate_version": 3,
                "entity_tag": '"v3"',
            },
            "response_entity_tag": '"v3"',
            "outbox_event": {
                "event_id": str(request.generated_ids.outbox_event_id),
                "event_type": "MembershipRevoked",
            },
            "secondary_outbox_event": {
                "event_id": str(
                    request.generated_ids.secondary_outbox_event_id
                ),
                "event_type": "MembershipRolesRevoked",
            },
            "capability_reconstruction": None,
        }

    @staticmethod
    def _issue_request() -> OrganizationAdminPostgresDatabaseRequest:
        return OrganizationAdminPostgresDatabaseRequest(
            operation=OrganizationAdminPostgresOperation.ISSUE_ACCESS_INVITATION,
            scope=OrganizationAdminPostgresScope(
                actor_user_id=_id(1),
                current_session_id=_id(2),
                organization_id=_id(3),
                target_id=_id(4),
                command_id=_id(5),
                correlation_id=_id(6),
                causation_id=_id(5),
                trace_id=_id(7),
                original_actor_id=None,
            ),
            receipt=OrganizationAdminPostgresReceiptMaterial(
                receipt_id=_id(5),
                idempotency_key_digest=b"i" * 32,
                idempotency_key_digest_key_id=(
                    "iam-receipt-idempotency-hmac-2026-01"
                ),
                payload_hash=b"p" * 32,
                payload_hash_key_id="iam-receipt-payload-hmac-2026-01",
                retain_until=datetime(
                    2026, 9, 15, 8, 0, tzinfo=timezone.utc
                ),
            ),
            expected_version=1,
            generated_ids=OrganizationAdminPostgresGeneratedIds(
                audit_event_id=_id(8),
                outbox_event_id=_id(9),
                recipient_contact_id=_id(10),
            ),
            invitation=OrganizationAdminPostgresInvitationMaterial(
                recipient_contact_id=_id(10),
                recipient_binding_digest=b"r" * 32,
                recipient_binding_digest_key_id="recipient-binding-2026-01",
                masked_recipient_label="n***@example.invalid",
                target_role="DEMAND_OWNER",
                expires_at=datetime(
                    2026, 8, 23, 8, 0, tzinfo=timezone.utc
                ),
                token_nonce=b"t" * 32,
                token_key_id="invitation-token-2026-01",
                token_format_version="access-invitation-token-v1",
            ),
            reason_code=None,
        )


class _Cursor:
    def __init__(self, row):
        self._row = row

    def fetchone(self):
        return self._row


class _Info:
    transaction_status = TransactionStatus.IDLE


class _Connection:
    autocommit = True

    def __init__(self, result):
        self.info = _Info()
        self._result = result
        self._settings = {}
        self.parameters = None
        self.statements = []

    def execute(self, sql, parameters=None):
        self.statements.append(sql)
        if sql.startswith("SELECT current_user,session_user,current_setting('server_version_num')"):
            return _Cursor(("iam_app", "iam_app", 180000))
        if sql.startswith("BEGIN"):
            self.info.transaction_status = TransactionStatus.INTRANS
            return _Cursor(None)
        if sql in {"COMMIT", "ROLLBACK"}:
            self.info.transaction_status = TransactionStatus.IDLE
            return _Cursor(None)
        if sql.startswith("SELECT pg_catalog.set_config"):
            self._settings[parameters[0]] = parameters[1]
            return _Cursor((parameters[1],))
        if sql.startswith("SELECT current_setting"):
            return _Cursor((self._settings.get(parameters[0], ""),))
        if sql.startswith("SELECT iam_api.execute_organization_admin_v3"):
            self.parameters = parameters
            return _Cursor((self._result,))
        if sql == "RESET ALL":
            self._settings = {}
            return _Cursor(None)
        if sql == "DISCARD TEMP":
            return _Cursor(None)
        if sql.startswith("SELECT current_user,session_user,current_setting('app.scope_kind'"):
            return _Cursor(("iam_app", "iam_app", None))
        if sql.startswith("SET LOCAL"):
            return _Cursor(None)
        raise AssertionError(sql)


class _ConnectionSource:
    def __init__(self, connections):
        self._connections = list(connections)
        self.released = []
        self.discarded = []

    def checkout(self):
        return self._connections.pop(0)

    def release(self, connection):
        self.released.append(connection)

    def discard(self, connection):
        self.discarded.append(connection)


class _NoCheckoutConnections:
    def checkout(self):
        raise AssertionError("handler unit test must not checkout PostgreSQL")

    def release(self, _connection):
        raise AssertionError

    def discard(self, _connection):
        raise AssertionError


class _LifecycleResolver:
    def resolve(self, **query):
        self.query = query
        return str(_id(3))


class _IssueResolver:
    def __init__(self, *, safe_response, capability_reconstruction):
        self._calls = 0
        self._safe_response = safe_response
        self._capability_reconstruction = capability_reconstruction

    def resolve_issue(self, **_query):
        self._calls += 1
        replayed = self._calls > 1
        return OrganizationAdminPostgresIssueResolution(
            organization_id=_id(3),
            target_version=1,
            snapshot_digest=b"s" * 32,
            replayed=replayed,
            safe_response=(self._safe_response if replayed else None),
            response_entity_tag='"v1"' if replayed else None,
            capability_reconstruction=(
                self._capability_reconstruction if replayed else None
            ),
        )


class _Validator:
    def __init__(self):
        self.responses = []
        self.events = []

    def validate(self, value, schema_name=None):
        if schema_name is None:
            self.events.append(dict(value))
        else:
            self.responses.append(dict(value))


class _RejectMembershipRolesRevokedValidator(_Validator):
    def validate(self, value, schema_name=None):
        super().validate(value, schema_name)
        if (
            schema_name is None
            and value.get("event_type") == "MembershipRolesRevoked"
        ):
            raise ValueError("MembershipRolesRevoked rejected")


class _Clock:
    def now(self):
        return UTC_NOW


class _FreshIds:
    def __init__(self):
        self._next = 100

    def new_id(self, _purpose):
        value = _id(self._next)
        self._next += 1
        return value


class _FreshSecrets:
    def __init__(self):
        self._next = 0

    def token_bytes(self, purpose, length):
        assert (purpose, length) == ("access-invitation-nonce", 32)
        self._next += 1
        return bytes((self._next,)) * 32


class _RecipientBinding:
    def bind_verified(self, *, contact_type, verified_locator):
        assert (contact_type, verified_locator) == ("EMAIL", "person@example.test")
        return RecipientBindingTuple(
            contact_type="EMAIL",
            binding_digest=(b"r" * 32).hex(),
            digest_key_id="recipient-binding-2026-01",
        )


if __name__ == "__main__":
    unittest.main()
