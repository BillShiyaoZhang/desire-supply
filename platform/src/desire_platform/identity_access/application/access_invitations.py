"""AcceptAccessInvitation application transaction boundary."""

from __future__ import annotations

import base64
from contextlib import ExitStack
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import json
from typing import Any, Dict, Mapping, Optional, Tuple

from ..domain.errors import IamError
from ..domain.invitations import (
    AccessInvitation,
    InvitationBindingEvidence,
    InvitationPurpose,
    TargetRole,
)
from ..domain.policies import ConsentOfferChoice, PolicyAcceptance
from ..ports.safety_hold import (
    HoldDecision,
    SafetyHoldDecisionResult,
    SafetyHoldUnavailableError,
)
from ..security.cryptography import (
    KeyUnavailableError,
    RECEIPT_CANONICALIZATION_VERSION,
    accept_payload_hash,
    csrf_digest,
    derive_csrf_token,
    idempotency_key_digest,
    require_key_material,
    session_handle_digest,
)


SESSION_IDLE_TTL = timedelta(minutes=30)


@dataclass(frozen=True)
class AcceptAccessInvitationCommand:
    invitation_id: str
    expected_version: int
    idempotency_key: str
    policy_bundle_id: str
    policy_acceptances: Tuple[PolicyAcceptance, ...]
    consent_grants: Tuple[ConsentOfferChoice, ...]


@dataclass(frozen=True)
class ActorContext:
    actor_id: str
    session_id: str
    original_actor_id: Optional[str]
    correlation_id: str
    causation_id: str
    trace_id: str


@dataclass(frozen=True)
class SessionRotation:
    session_id: str
    raw_session_handle: str = field(repr=False)
    csrf_token: str = field(repr=False)


@dataclass(frozen=True)
class AcceptAccessInvitationResult:
    replayed: bool
    safe_response: Dict[str, Any]
    session_rotation: Optional[SessionRotation]


class AcceptAccessInvitationHandler:
    """Atomically accepts exact invitation, policy, consent, and Session facts."""

    def __init__(
        self,
        *,
        uow_factory,
        safety_hold,
        safety_hold_policy_version: str,
        clock,
        id_source,
        secret_source,
        keyring,
    ) -> None:
        self._uow_factory = uow_factory
        self._safety_hold = safety_hold
        self._safety_hold_policy_version = safety_hold_policy_version
        self._clock = clock
        self._id_source = id_source
        self._secret_source = secret_source
        self._keyring = keyring

    def handle(
        self,
        *,
        actor: ActorContext,
        command: AcceptAccessInvitationCommand,
    ) -> AcceptAccessInvitationResult:
        now = self._clock.now()
        _require_aware_datetime(now)
        snapshot = self._uow_factory.store.snapshot()
        current_session = self._require_current_session(
            snapshot,
            actor=actor,
            now=now,
        )

        try:
            require_key_material(
                self._keyring,
                key_ids=(
                    self._keyring.idempotency_key_digest_key_id,
                    self._keyring.payload_hash_key_id,
                    self._keyring.session_handle_digest_key_id,
                    self._keyring.csrf_key_id,
                    current_session.get("handle_digest_key_id"),
                    current_session.get("csrf_key_id"),
                ),
            )
            idempotency_digest = idempotency_key_digest(
                self._keyring,
                command.idempotency_key,
            )
            payload_hash = accept_payload_hash(self._keyring, command)
        except KeyUnavailableError as error:
            raise IamError("SERVICE_UNAVAILABLE") from error
        receipt = _find_receipt(
            snapshot,
            actor_id=actor.actor_id,
            idempotency_key_digest=idempotency_digest,
        )
        if receipt is not None:
            user = snapshot.get("users", {}).get(actor.actor_id)
            if user is None or user.get("status") != "ACTIVE":
                raise IamError("AUTHENTICATION_REQUIRED")
            if receipt["payload_hash"] != payload_hash:
                raise IamError("IDEMPOTENCY_KEY_REUSED")
            if receipt["status"] != "COMPLETED":
                raise IamError("COMMAND_IN_PROGRESS")
            return AcceptAccessInvitationResult(
                replayed=True,
                safe_response=_copy_json(receipt["response_body"]),
                session_rotation=None,
            )

        invitation = self._require_new_execution_guards(
            snapshot,
            actor=actor,
            command=command,
            now=now,
        )
        hold_result = self._evaluate_safety_hold(
            actor=actor,
            invitation=invitation,
            now=now,
        )

        receipt_id = self._id_source.new_id("command_receipt")
        with ExitStack() as transaction_stack:
            uow = transaction_stack.enter_context(self._uow_factory.begin())
            tables = uow.tables
            self._require_current_session(tables, actor=actor, now=now)
            locked_invitation = tables.get("invitations", {}).get(
                command.invitation_id
            )
            if (
                locked_invitation is None
                or locked_invitation.aggregate_version
                != hold_result.target_version
            ):
                # Release every database lock before consulting the provider.
                # The old ALLOW is not a capability for a different aggregate
                # version, even when the request's If-Match is now stale.
                transaction_stack.close()
                return self._finish_after_hold_target_drift(
                    actor=actor,
                    command=command,
                    now=now,
                )
            invitation = self._require_new_execution_guards(
                tables,
                actor=actor,
                command=command,
                now=now,
            )
            current_bundle = _require_current_policy_bundle_for_invitation(
                tables,
                invitation=invitation,
                now=now,
            )
            evaluation = current_bundle.evaluate(
                now=now,
                presented_bundle_id=command.policy_bundle_id,
                policy_acceptances=command.policy_acceptances,
                consent_choices=command.consent_grants,
            )

            pending_receipt = {
                "command_receipt_id": receipt_id,
                "status": "PENDING",
                "principal_kind": "USER",
                "principal_id": actor.actor_id,
                "command_name": "AcceptAccessInvitation",
                "command_version": 1,
                "idempotency_key_digest": idempotency_digest,
                "idempotency_key_digest_key_id": (
                    self._keyring.idempotency_key_digest_key_id
                ),
                "payload_hash": payload_hash,
                "payload_hash_key_id": self._keyring.payload_hash_key_id,
                "canonicalization_version": RECEIPT_CANONICALIZATION_VERSION,
            }
            uow.put(
                "command_receipts",
                receipt_id,
                pending_receipt,
                checkpoint="command_receipt.pending",
            )

            event_records = []
            for acceptance_index, acceptance in enumerate(
                evaluation.policy_acceptances
            ):
                document = next(
                    document
                    for document in tables["policy_bundles"][
                        command.policy_bundle_id
                    ].documents
                    if document.document_id == acceptance.document_id
                )
                existing_for_document = [
                    existing
                    for existing in tables.get("policy_acceptances", {}).values()
                    if existing.get("user_id") == actor.actor_id
                    and existing.get("policy_bundle_id")
                    == command.policy_bundle_id
                    and existing.get("policy_document_id") == document.document_id
                ]
                if any(
                    existing.get("policy_document_sha256")
                    == document.content_sha256
                    and existing.get("legal_effect") == document.legal_effect.value
                    for existing in existing_for_document
                ):
                    continue
                if existing_for_document:
                    raise IamError("POLICY_BUNDLE_CHANGED")
                acceptance_id = self._id_source.new_id("policy_acceptance")
                acceptance_fact = {
                    "policy_acceptance_id": acceptance_id,
                    "user_id": actor.actor_id,
                    "policy_bundle_id": command.policy_bundle_id,
                    "policy_document_id": document.document_id,
                    "policy_document_sha256": document.content_sha256,
                    "legal_effect": document.legal_effect.value,
                    "accepted_at": now,
                    "session_id": actor.session_id,
                    "auth_transaction_id": tables["sessions"][
                        actor.session_id
                    ]["auth_transaction_id"],
                    "auth_time": tables["sessions"][actor.session_id]["auth_time"],
                    "acr_code": tables["sessions"][actor.session_id]["acr_code"],
                    "amr_codes": tuple(
                        tables["sessions"][actor.session_id]["amr_codes"]
                    ),
                    "source_action": "ACCESS_INVITATION_ACCEPT",
                    "command_id": receipt_id,
                    "correlation_id": actor.correlation_id,
                    "aggregate_version": 1,
                    "created_at": now,
                }
                uow.put(
                    "policy_acceptances",
                    acceptance_id,
                    acceptance_fact,
                    checkpoint="policy_acceptance.%d" % acceptance_index,
                )
                event_records.append(
                    _event_record(
                        event_type="PolicyAccepted",
                        aggregate_type="PolicyAcceptance",
                        aggregate_id=acceptance_id,
                        aggregate_version=1,
                        payload={
                            key: acceptance_fact[key]
                            for key in (
                                "policy_acceptance_id",
                                "user_id",
                                "policy_bundle_id",
                                "policy_document_id",
                                "policy_document_sha256",
                                "legal_effect",
                            )
                        },
                    )
                )

            for consent_index, authorization in enumerate(
                evaluation.consent_authorizations
            ):
                existing_active_consents = [
                    existing
                    for existing in tables.get("consent_grants", {}).values()
                    if existing.get("user_id") == actor.actor_id
                    and existing.get("status") == "ACTIVE"
                    and existing.get("purpose") == authorization.purpose.value
                    and existing.get("scope_type") == authorization.scope_type.value
                    and existing.get("scope_id") == authorization.scope_id
                ]
                if any(
                    _consent_matches_authorization(existing, authorization)
                    for existing in existing_active_consents
                ):
                    continue
                if existing_active_consents:
                    raise IamError("INVALID_STATE_TRANSITION")
                consent_grant_id = self._id_source.new_id("consent_grant")
                consent_fact = {
                    "consent_grant_id": consent_grant_id,
                    "user_id": actor.actor_id,
                    "status": "ACTIVE",
                    "aggregate_version": 1,
                    "consent_offer_id": authorization.consent_offer_id,
                    "consent_offer_version": authorization.consent_offer_version,
                    "policy_bundle_id": authorization.policy_bundle_id,
                    "purpose": authorization.purpose.value,
                    "scope_type": authorization.scope_type.value,
                    "scope_id": authorization.scope_id,
                    "data_categories": tuple(
                        category.value for category in authorization.data_categories
                    ),
                    "recipient_reference": authorization.recipient_reference,
                    "supporting_policy_document_id": (
                        authorization.supporting_policy_document_id
                    ),
                    "supporting_document_sha256": (
                        authorization.supporting_document_sha256
                    ),
                    "granted_at": now,
                    "expires_at": authorization.expires_at,
                    "session_id": actor.session_id,
                    "auth_transaction_id": tables["sessions"][
                        actor.session_id
                    ]["auth_transaction_id"],
                    "auth_time": tables["sessions"][actor.session_id]["auth_time"],
                    "acr_code": tables["sessions"][actor.session_id]["acr_code"],
                    "amr_codes": tuple(
                        tables["sessions"][actor.session_id]["amr_codes"]
                    ),
                    "command_id": receipt_id,
                    "correlation_id": actor.correlation_id,
                    "created_at": now,
                    "updated_at": now,
                }
                uow.put(
                    "consent_grants",
                    consent_grant_id,
                    consent_fact,
                    checkpoint="consent_grant.%d" % consent_index,
                )
                event_records.append(
                    _event_record(
                        event_type="ConsentGranted",
                        aggregate_type="ConsentGrant",
                        aggregate_id=consent_grant_id,
                        aggregate_version=1,
                        payload={
                            "consent_grant_id": consent_grant_id,
                            "user_id": actor.actor_id,
                            "status": "ACTIVE",
                            "granted_at": _timestamp(now),
                            "derived_authorization": {
                                "consent_offer_id": authorization.consent_offer_id,
                                "consent_offer_version": (
                                    authorization.consent_offer_version
                                ),
                                "policy_bundle_id": authorization.policy_bundle_id,
                                "purpose": authorization.purpose.value,
                                "scope_type": authorization.scope_type.value,
                                "scope_id": authorization.scope_id,
                                "data_categories": [
                                    category.value
                                    for category in authorization.data_categories
                                ],
                                "supporting_policy_document_id": (
                                    authorization.supporting_policy_document_id
                                ),
                                "supporting_document_sha256": (
                                    authorization.supporting_document_sha256
                                ),
                                "expires_at": _timestamp(authorization.expires_at),
                            },
                        },
                    )
                )

            user = tables["users"][actor.actor_id]
            if user["status"] == "PENDING_ENROLLMENT":
                active_user = dict(user)
                active_user["status"] = "ACTIVE"
                active_user["aggregate_version"] = user["aggregate_version"] + 1
                uow.put(
                    "users",
                    actor.actor_id,
                    active_user,
                    checkpoint="user.activate",
                )
                event_records.append(
                    _event_record(
                        event_type="UserActivated",
                        aggregate_type="User",
                        aggregate_id=actor.actor_id,
                        aggregate_version=active_user["aggregate_version"],
                        payload={
                            "user_id": actor.actor_id,
                            "status": "ACTIVE",
                            "access_invitation_id": invitation.invitation_id,
                        },
                    )
                )
            else:
                active_user = dict(user)
                active_user["aggregate_version"] = user["aggregate_version"] + 1
                uow.put(
                    "users",
                    actor.actor_id,
                    active_user,
                    checkpoint="user.authorization_version",
                )
                event_records.append(
                    _event_record(
                        event_type="PolicyRequirementsSatisfied",
                        aggregate_type="User",
                        aggregate_id=actor.actor_id,
                        aggregate_version=active_user["aggregate_version"],
                        payload={
                            "user_id": actor.actor_id,
                            "policy_bundle_id": invitation.issued_policy_bundle_id,
                        },
                    )
                )

            activated_scope, activation = self._grant_invited_authority(
                uow,
                tables=tables,
                invitation=invitation,
                actor_id=actor.actor_id,
                now=now,
                event_records=event_records,
            )

            accepted_invitation = invitation.accept(
                now=now,
                expected_version=command.expected_version,
                evidence=InvitationBindingEvidence(
                    invitation_id=invitation.invitation_id,
                    recipient_contact_id=invitation.recipient_contact_id,
                    invitation_version=command.expected_version,
                ),
            )
            uow.put(
                "invitations",
                accepted_invitation.invitation_id,
                accepted_invitation,
                checkpoint="access_invitation.accept",
            )
            event_records.append(
                _event_record(
                    event_type="AccessInvitationAccepted",
                    aggregate_type="AccessInvitation",
                    aggregate_id=accepted_invitation.invitation_id,
                    aggregate_version=accepted_invitation.aggregate_version,
                    payload={
                        "invitation_binding": {
                            "invitation_id": invitation.invitation_id,
                            "bound_invitation_version": command.expected_version,
                            "issued_policy_bundle_id": (
                                invitation.issued_policy_bundle_id
                            ),
                            "purpose": invitation.purpose.value,
                            "target_scope": invitation.target_scope.value,
                            "target_role": invitation.target_role.value,
                            "is_initial_admin": invitation.is_initial_admin,
                        },
                        "status": "ACCEPTED",
                        "accepted_user_id": actor.actor_id,
                        "activation": activation,
                    },
                )
            )

            rotation = self._rotate_session(
                uow,
                tables=tables,
                actor=actor,
                now=now,
            )
            safe_response = _acceptance_safe_response(
                tables,
                invitation=accepted_invitation,
                actor_id=actor.actor_id,
                activated_scope=activated_scope,
                now=now,
            )

            audit_event_id = self._id_source.new_id("audit_event")
            uow.put(
                "audit_events",
                audit_event_id,
                {
                    "audit_event_id": audit_event_id,
                    "actor_id": actor.actor_id,
                    "original_actor_id": actor.original_actor_id,
                    "action": "AcceptAccessInvitation",
                    "target_type": "AccessInvitation",
                    "target_id": invitation.invitation_id,
                    "organization_id": invitation.organization_id,
                    "result": "SUCCEEDED",
                    "correlation_id": actor.correlation_id,
                    "causation_id": actor.causation_id,
                    "trace_id": actor.trace_id,
                    "auth_strength_code": tables["sessions"][
                        actor.session_id
                    ]["acr_code"],
                    "occurred_at": now,
                },
                checkpoint="audit_event.succeeded",
            )
            event_occurrences: Dict[str, int] = {}
            for event_record in event_records:
                event_type = event_record["event_type"]
                occurrence = event_occurrences.get(event_type, 0)
                event_occurrences[event_type] = occurrence + 1
                event_id = self._id_source.new_id("outbox_event")
                uow.put(
                    "outbox_events",
                    event_id,
                    _event_envelope(
                        event_id=event_id,
                        event_record=event_record,
                        actor=actor,
                        organization_id=invitation.organization_id,
                        occurred_at=now,
                    ),
                    checkpoint="outbox.%s.%d" % (event_type, occurrence),
                )

            completed_receipt = dict(pending_receipt)
            completed_receipt.update(
                {
                    "status": "COMPLETED",
                    "response_schema_version": 1,
                    "response_body": _copy_json(safe_response),
                    "completed_at": now,
                }
            )
            uow.put(
                "command_receipts",
                receipt_id,
                completed_receipt,
                checkpoint="command_receipt.complete",
            )
            uow.commit()

        return AcceptAccessInvitationResult(
            replayed=False,
            safe_response=safe_response,
            session_rotation=rotation,
        )

    def _evaluate_safety_hold(
        self,
        *,
        actor: ActorContext,
        invitation: AccessInvitation,
        now: datetime,
    ) -> SafetyHoldDecisionResult:
        query = {
            "actor_id": actor.actor_id,
            "action": "AcceptAccessInvitation",
            "target_type": "AccessInvitation",
            "target_id": invitation.invitation_id,
            "target_version": invitation.aggregate_version,
            "organization_id": invitation.organization_id,
            "policy_version": self._safety_hold_policy_version,
        }
        try:
            result = self._safety_hold.evaluate(**query)
        except SafetyHoldUnavailableError as error:
            raise IamError("SAFETY_DECISION_UNAVAILABLE") from error

        expected_result = {
            key: query[key]
            for key in (
                "action",
                "target_type",
                "target_id",
                "target_version",
                "organization_id",
                "policy_version",
            )
        }
        valid = (
            isinstance(result, SafetyHoldDecisionResult)
            and isinstance(result.decision, HoldDecision)
            and all(
                getattr(result, key) == expected
                for key, expected in expected_result.items()
            )
            and _is_utc_datetime(result.evaluated_at)
            and _is_utc_datetime(result.valid_until)
            and result.evaluated_at <= now < result.valid_until
        )
        if not valid or result.decision == HoldDecision.UNAVAILABLE:
            raise IamError("SAFETY_DECISION_UNAVAILABLE")
        if result.decision == HoldDecision.BLOCK:
            raise IamError("SAFETY_HOLD_BLOCKED")
        if result.decision != HoldDecision.ALLOW:
            raise IamError("SAFETY_DECISION_UNAVAILABLE")
        return result

    def _finish_after_hold_target_drift(
        self,
        *,
        actor: ActorContext,
        command: AcceptAccessInvitationCommand,
        now: datetime,
    ) -> AcceptAccessInvitationResult:
        """Re-authorize the new target version outside the abandoned UoW."""

        snapshot = self._uow_factory.store.snapshot()
        self._require_current_session(snapshot, actor=actor, now=now)
        invitation = snapshot.get("invitations", {}).get(command.invitation_id)
        if (
            invitation is None
            or invitation.status.value != "ISSUED"
            or now >= invitation.expires_at
        ):
            raise IamError("ACCESS_INVITATION_UNAVAILABLE")
        self._evaluate_safety_hold(actor=actor, invitation=invitation, now=now)

        # This re-runs all exact binding and If-Match guards after the fresh
        # decision.  A changed version therefore resolves as the public 412 and
        # can never consume either the old or new decision to write facts.
        self._require_new_execution_guards(
            snapshot,
            actor=actor,
            command=command,
            now=now,
        )
        raise AssertionError("version drift recheck unexpectedly remained executable")

    def _require_current_session(
        self,
        tables: Mapping[str, Mapping[Any, Any]],
        *,
        actor: ActorContext,
        now: datetime,
    ) -> Mapping[str, Any]:
        session = tables.get("sessions", {}).get(actor.session_id)
        if (
            session is None
            or session.get("status") != "ACTIVE"
            or session.get("user_id") != actor.actor_id
        ):
            raise IamError("AUTHENTICATION_REQUIRED")
        family = tables.get("session_families", {}).get(
            session.get("session_family_id")
        )
        if (
            family is None
            or family.get("status") != "ACTIVE"
            or family.get("user_id") != actor.actor_id
            or family.get("current_generation") != session.get("generation")
        ):
            raise IamError("AUTHENTICATION_REQUIRED")
        required_times = {
            name: session.get(name)
            for name in (
                "auth_time",
                "created_at",
                "last_activity_at",
                "idle_expires_at",
                "absolute_expires_at",
                "updated_at",
            )
        }
        if not all(_is_utc_datetime(value) for value in required_times.values()):
            raise IamError("SERVICE_UNAVAILABLE")
        if (
            not isinstance(session.get("acr_code"), str)
            or not session.get("acr_code")
            or not isinstance(session.get("amr_codes"), (list, tuple))
            or not session.get("amr_codes")
            or not all(
                isinstance(method, str) and method
                for method in session.get("amr_codes", ())
            )
            or required_times["auth_time"] > now
            or not (
                required_times["created_at"]
                <= required_times["last_activity_at"]
                < required_times["idle_expires_at"]
                <= required_times["absolute_expires_at"]
            )
            or required_times["updated_at"] < required_times["created_at"]
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        if any(
            now >= required_times[name]
            for name in (
                "idle_expires_at",
                "absolute_expires_at",
            )
        ):
            raise IamError("SESSION_EXPIRED")
        return session

    def _require_new_execution_guards(
        self,
        tables: Mapping[str, Mapping[Any, Any]],
        *,
        actor: ActorContext,
        command: AcceptAccessInvitationCommand,
        now: datetime,
    ) -> AccessInvitation:
        invitation = tables.get("invitations", {}).get(command.invitation_id)
        user = tables.get("users", {}).get(actor.actor_id)
        if invitation is None or user is None:
            raise IamError("ACCESS_INVITATION_UNAVAILABLE")
        invitation_contact = tables.get("contact_points", {}).get(
            invitation.recipient_contact_id
        )
        if (
            invitation_contact is None
            or invitation_contact.get("user_id") != actor.actor_id
        ):
            raise IamError("ACCESS_INVITATION_UNAVAILABLE")
        session = tables["sessions"][actor.session_id]
        if (
            session.get("verified_for_invitation_id") != invitation.invitation_id
            or session.get("verified_contact_point_id")
            != invitation.recipient_contact_id
        ):
            raise IamError("ACCESS_INVITATION_UNAVAILABLE")
        transaction = tables.get("auth_transactions", {}).get(
            session.get("auth_transaction_id")
        )
        if (
            transaction is None
            or transaction.get("status") != "SUCCEEDED"
            or transaction.get("purpose") not in ("ENROLLMENT", "STEP_UP")
            or transaction.get("expected_user_id") != actor.actor_id
            or transaction.get("expected_contact_point_id")
            != invitation.recipient_contact_id
            or transaction.get("invitation_id") != invitation.invitation_id
            or transaction.get("invitation_version") != command.expected_version
        ):
            raise IamError("ACCESS_INVITATION_UNAVAILABLE")
        if invitation_contact.get("status") != "VERIFIED":
            raise IamError("ACCESS_INVITATION_UNAVAILABLE")
        if user.get("status") not in ("PENDING_ENROLLMENT", "ACTIVE"):
            raise IamError("ACCESS_INVITATION_UNAVAILABLE")
        if invitation.status.value != "ISSUED" or now >= invitation.expires_at:
            raise IamError("ACCESS_INVITATION_UNAVAILABLE")

        if invitation.target_role == TargetRole.CREATOR and any(
            grant.get("user_id") == actor.actor_id
            and grant.get("target_role") == TargetRole.CREATOR.value
            and grant.get("revoked_at") is None
            for grant in tables.get("user_role_grants", {}).values()
        ):
            raise IamError("INVALID_STATE_TRANSITION")

        current_bundle = _require_current_policy_bundle_for_invitation(
            tables,
            invitation=invitation,
            now=now,
        )
        if command.policy_bundle_id != current_bundle.policy_bundle_id:
            raise IamError("POLICY_BUNDLE_CHANGED")

        if invitation.purpose == InvitationPurpose.ORGANIZATION_MEMBERSHIP:
            organization = tables.get("organizations", {}).get(
                invitation.organization_id
            )
            if organization is None:
                raise IamError("ACCESS_INVITATION_UNAVAILABLE")
            expected_status = "PENDING_ADMIN" if invitation.is_initial_admin else "ACTIVE"
            if organization.get("status") != expected_status:
                raise IamError("ACCESS_INVITATION_UNAVAILABLE")
            if any(
                membership.get("organization_id") == invitation.organization_id
                and membership.get("user_id") == actor.actor_id
                for membership in tables.get("memberships", {}).values()
            ):
                raise IamError("MEMBERSHIP_ALREADY_EXISTS")

        invitation.accept(
            now=now,
            expected_version=command.expected_version,
            evidence=InvitationBindingEvidence(
                invitation_id=invitation.invitation_id,
                recipient_contact_id=invitation.recipient_contact_id,
                invitation_version=command.expected_version,
            ),
        )
        return invitation

    def _grant_invited_authority(
        self,
        uow,
        *,
        tables: Mapping[str, Mapping[Any, Any]],
        invitation: AccessInvitation,
        actor_id: str,
        now: datetime,
        event_records: list,
    ) -> Tuple[str, Dict[str, Any]]:
        if invitation.target_role == TargetRole.CREATOR:
            grant_id = self._id_source.new_id("user_role_grant")
            uow.put(
                "user_role_grants",
                grant_id,
                {
                    "user_role_grant_id": grant_id,
                    "user_id": actor_id,
                    "target_role": invitation.target_role.value,
                    "source_invitation_id": invitation.invitation_id,
                    "policy_selector_digest": invitation.policy_selector_digest,
                    "granted_by_kind": "USER",
                    "granted_by_id": actor_id,
                    "granted_at": now,
                    "revoked_at": None,
                    "revocation_reason_code": None,
                    "aggregate_version": 1,
                },
                checkpoint="user_role_grant.create",
            )
            event_records.append(
                _event_record(
                    event_type="UserRoleGranted",
                    aggregate_type="UserRoleGrant",
                    aggregate_id=grant_id,
                    aggregate_version=1,
                    payload={
                        "user_role_grant_id": grant_id,
                        "user_id": actor_id,
                        "target_role": invitation.target_role.value,
                        "access_invitation_id": invitation.invitation_id,
                    },
                )
            )
            return (
                "USER_ROLE",
                {"kind": "USER_ROLE", "user_role_grant_id": grant_id},
            )

        membership_id = self._id_source.new_id("membership")
        uow.put(
            "memberships",
            membership_id,
            {
                "membership_id": membership_id,
                "organization_id": invitation.organization_id,
                "user_id": actor_id,
                "status": "ACTIVE",
                "aggregate_version": 1,
                "access_invitation_id": invitation.invitation_id,
                "activated_at": now,
            },
            checkpoint="membership.activate",
        )
        event_records.append(
            _event_record(
                event_type="MembershipActivated",
                aggregate_type="Membership",
                aggregate_id=membership_id,
                aggregate_version=1,
                payload={
                    "membership_id": membership_id,
                    "user_id": actor_id,
                    "status": "ACTIVE",
                    "access_invitation_id": invitation.invitation_id,
                },
            )
        )
        role_grant_id = self._id_source.new_id("membership_role_grant")
        uow.put(
            "membership_role_grants",
            role_grant_id,
            {
                "membership_role_grant_id": role_grant_id,
                "membership_id": membership_id,
                "user_id": actor_id,
                "organization_id": invitation.organization_id,
                "target_role": invitation.target_role.value,
                "source_invitation_id": invitation.invitation_id,
                "policy_selector_digest": invitation.policy_selector_digest,
                "granted_by_kind": "USER",
                "granted_by_id": actor_id,
                "granted_at": now,
                "revoked_at": None,
                "revocation_reason_code": None,
                "aggregate_version": 1,
            },
            checkpoint="membership_role_grant.create",
        )
        event_records.append(
            _event_record(
                event_type="MembershipRoleGranted",
                aggregate_type="MembershipRoleGrant",
                aggregate_id=role_grant_id,
                aggregate_version=1,
                payload={
                    "membership_role_grant_id": role_grant_id,
                    "membership_id": membership_id,
                    "user_id": actor_id,
                    "target_role": invitation.target_role.value,
                    "access_invitation_id": invitation.invitation_id,
                },
            )
        )
        if invitation.is_initial_admin:
            organization = dict(tables["organizations"][invitation.organization_id])
            organization["status"] = "ACTIVE"
            organization["aggregate_version"] += 1
            uow.put(
                "organizations",
                invitation.organization_id,
                organization,
                checkpoint="organization.activate",
            )
            event_records.append(
                _event_record(
                    event_type="OrganizationActivated",
                    aggregate_type="Organization",
                    aggregate_id=invitation.organization_id,
                    aggregate_version=organization["aggregate_version"],
                    payload={
                        "organization_id": invitation.organization_id,
                        "status": "ACTIVE",
                        "access_invitation_id": invitation.invitation_id,
                        "initial_admin_membership_id": membership_id,
                    },
                )
            )
        return (
            "ORGANIZATION_MEMBERSHIP",
            {
                "kind": "ORGANIZATION_MEMBERSHIP",
                "membership_id": membership_id,
                "membership_role_grant_id": role_grant_id,
            },
        )

    def _rotate_session(
        self,
        uow,
        *,
        tables: Mapping[str, Mapping[Any, Any]],
        actor: ActorContext,
        now: datetime,
    ) -> SessionRotation:
        predecessor = dict(tables["sessions"][actor.session_id])
        family_id = predecessor["session_family_id"]
        family = dict(tables["session_families"][family_id])
        successor_id = self._id_source.new_id("session")
        raw_bytes = self._secret_source.token_bytes("session-handle", 32)
        raw_handle = base64.urlsafe_b64encode(raw_bytes).rstrip(b"=").decode("ascii")
        csrf_salt = self._secret_source.token_bytes("csrf-salt", 32)

        predecessor["status"] = "REVOKED"
        predecessor["revoked_at"] = now
        uow.put(
            "sessions",
            actor.session_id,
            predecessor,
            checkpoint="session.predecessor.revoke",
        )
        family["current_generation"] += 1
        family["aggregate_version"] += 1
        uow.put(
            "session_families",
            family_id,
            family,
            checkpoint="session_family.rotate",
        )
        try:
            csrf_token = derive_csrf_token(
                self._keyring,
                raw_session_handle=raw_handle,
                csrf_salt=csrf_salt,
                session_id=successor_id,
                generation=family["current_generation"],
                key_id=self._keyring.csrf_key_id,
            )
            handle_digest = session_handle_digest(self._keyring, raw_handle)
            successor_csrf_digest = csrf_digest(
                self._keyring,
                csrf_token=csrf_token,
                key_id=self._keyring.csrf_key_id,
            )
        except KeyUnavailableError as error:
            raise IamError("SERVICE_UNAVAILABLE") from error
        successor = {
            "session_id": successor_id,
            "session_family_id": family_id,
            "user_id": actor.actor_id,
            "generation": family["current_generation"],
            "predecessor_session_id": actor.session_id,
            "status": "ACTIVE",
            "verified_contact_point_id": None,
            "verified_for_invitation_id": None,
            "auth_transaction_id": None,
            "auth_time": predecessor["auth_time"],
            "acr_code": predecessor["acr_code"],
            "amr_codes": tuple(predecessor["amr_codes"]),
            "created_at": now,
            "last_activity_at": now,
            "idle_expires_at": min(
                now + SESSION_IDLE_TTL,
                predecessor["absolute_expires_at"],
            ),
            "absolute_expires_at": predecessor["absolute_expires_at"],
            "updated_at": now,
            "handle_digest": handle_digest,
            "handle_digest_key_id": (
                self._keyring.session_handle_digest_key_id
            ),
            "csrf_salt": csrf_salt,
            "csrf_key_id": self._keyring.csrf_key_id,
            "csrf_digest": successor_csrf_digest,
            "rotation_reason": "INVITATION_ACCEPT",
            "aggregate_version": 1,
        }
        uow.put(
            "sessions",
            successor_id,
            successor,
            checkpoint="session.successor.create",
        )
        return SessionRotation(
            session_id=successor_id,
            raw_session_handle=raw_handle,
            csrf_token=csrf_token,
        )


def _find_receipt(
    tables: Mapping[str, Mapping[Any, Any]],
    *,
    actor_id: str,
    idempotency_key_digest: str,
) -> Optional[Mapping[str, Any]]:
    for receipt in tables.get("command_receipts", {}).values():
        if (
            receipt.get("principal_kind") == "USER"
            and receipt.get("principal_id") == actor_id
            and receipt.get("command_name") == "AcceptAccessInvitation"
            and receipt.get("command_version") == 1
            and receipt.get("idempotency_key_digest") == idempotency_key_digest
        ):
            return receipt
    return None


def _copy_json(value: Mapping[str, Any]) -> Dict[str, Any]:
    return json.loads(json.dumps(value, sort_keys=True, default=str))


def _consent_matches_authorization(existing, authorization) -> bool:
    return (
        existing.get("consent_offer_id") == authorization.consent_offer_id
        and existing.get("consent_offer_version")
        == authorization.consent_offer_version
        and existing.get("policy_bundle_id") == authorization.policy_bundle_id
        and existing.get("data_categories")
        == tuple(category.value for category in authorization.data_categories)
        and existing.get("recipient_reference")
        == authorization.recipient_reference
        and existing.get("supporting_policy_document_id")
        == authorization.supporting_policy_document_id
        and existing.get("supporting_document_sha256")
        == authorization.supporting_document_sha256
        and existing.get("expires_at") == authorization.expires_at
    )


def _event_record(
    *,
    event_type: str,
    aggregate_type: str,
    aggregate_id: str,
    aggregate_version: int,
    payload: Mapping[str, Any],
) -> Dict[str, Any]:
    return {
        "event_type": event_type,
        "aggregate_type": aggregate_type,
        "aggregate_id": aggregate_id,
        "aggregate_version": aggregate_version,
        "payload": dict(payload),
    }


def _event_envelope(
    *,
    event_id: str,
    event_record: Mapping[str, Any],
    actor: ActorContext,
    organization_id: Optional[str],
    occurred_at: datetime,
) -> Dict[str, Any]:
    return {
        "event_id": event_id,
        "event_type": event_record["event_type"],
        "schema_version": 1,
        "occurred_at": _timestamp(occurred_at),
        "aggregate_type": event_record["aggregate_type"],
        "aggregate_id": event_record["aggregate_id"],
        "aggregate_version": event_record["aggregate_version"],
        "actor_kind": "USER",
        "actor_id": actor.actor_id,
        "original_actor_id": actor.original_actor_id,
        "correlation_id": actor.correlation_id,
        "causation_id": actor.causation_id,
        "trace_id": actor.trace_id,
        "organization_id": organization_id,
        "payload": _copy_json(event_record["payload"]),
    }


def _acceptance_safe_response(
    tables: Mapping[str, Mapping[Any, Any]],
    *,
    invitation: AccessInvitation,
    actor_id: str,
    activated_scope: str,
    now: datetime,
) -> Dict[str, Any]:
    if invitation.created_at is None or invitation.masked_recipient_label is None:
        raise IamError("ACCESS_INVITATION_UNAVAILABLE")
    user = tables["users"][actor_id]

    active_user_grants = [
        grant
        for grant in tables.get("user_role_grants", {}).values()
        if user.get("status") == "ACTIVE"
        and grant.get("user_id") == actor_id
        and grant.get("revoked_at") is None
    ]
    for grant in active_user_grants:
        _require_role_grant_source(
            tables,
            grant=grant,
            actor_id=actor_id,
            scope_type="USER_ROLE",
            membership=None,
        )
    user_roles = sorted({grant["target_role"] for grant in active_user_grants})
    membership_dtos = []
    membership_scopes = []
    for membership in sorted(
        (
            item
            for item in tables.get("memberships", {}).values()
            if item["user_id"] == actor_id
        ),
        key=lambda item: item["membership_id"],
    ):
        organization = tables["organizations"][membership["organization_id"]]
        active_membership_grants = [
            grant
            for grant in tables.get("membership_role_grants", {}).values()
            if grant["membership_id"] == membership["membership_id"]
            and grant.get("revoked_at") is None
        ]
        roles = sorted(
            {grant["target_role"] for grant in active_membership_grants}
        )
        membership_dtos.append(
            {
                "membership_id": membership["membership_id"],
                "organization": {
                    "organization_id": organization["organization_id"],
                    "public_name": organization["public_name"],
                    "type": organization["organization_type"],
                    "status": organization["status"],
                    "aggregate_version": organization["aggregate_version"],
                    "entity_tag": _entity_tag(organization["aggregate_version"]),
                },
                "status": membership["status"],
                "roles": roles,
                "aggregate_version": membership["aggregate_version"],
                "entity_tag": _entity_tag(membership["aggregate_version"]),
            }
        )
        if (
            user.get("status") == "ACTIVE"
            and membership.get("status") == "ACTIVE"
            and organization.get("status") == "ACTIVE"
        ):
            for grant in active_membership_grants:
                _require_role_grant_source(
                    tables,
                    grant=grant,
                    actor_id=actor_id,
                    scope_type="ORGANIZATION_ROLE",
                    membership=membership,
                )
                membership_scopes.append(
                    (
                        grant.get("policy_selector_digest"),
                        grant["target_role"],
                        "ORGANIZATION_ROLE",
                        membership["organization_id"],
                    )
                )

    policy_scopes = [
        (
            grant.get("policy_selector_digest"),
            grant["target_role"],
            "USER_ROLE",
            None,
        )
        for grant in active_user_grants
    ] + membership_scopes
    policy_requirements = [
        _policy_requirement(
            tables,
            actor_id=actor_id,
            selector_digest=selector_digest,
            role=role,
            scope_type=scope_type,
            scope_id=scope_id,
            now=now,
        )
        for selector_digest, role, scope_type, scope_id in sorted(
            policy_scopes,
            key=lambda item: (item[0] or "", item[1], item[2], item[3] or ""),
        )
    ]

    current_invitation_bundle = _require_current_policy_bundle_for_invitation(
        tables,
        invitation=invitation,
        now=now,
    )

    return {
        "invitation": {
            "invitation_id": invitation.invitation_id,
            "purpose": invitation.purpose.value,
            "organization_id": invitation.organization_id,
            "target_role": invitation.target_role.value,
            "masked_recipient_label": invitation.masked_recipient_label,
            "is_initial_admin": invitation.is_initial_admin,
            "status": invitation.status.value,
            "expires_at": _timestamp(invitation.expires_at),
            "created_at": _timestamp(invitation.created_at),
            "required_policy_bundle_id": current_invitation_bundle.policy_bundle_id,
            "aggregate_version": invitation.aggregate_version,
            "entity_tag": _entity_tag(invitation.aggregate_version),
        },
        "me": {
            "user_id": actor_id,
            "status": user["status"],
            "display_handle": user["stable_handle"],
            "user_roles": user_roles,
            "memberships": membership_dtos,
            "policy_requirements": policy_requirements,
            "aggregate_version": user["aggregate_version"],
            "entity_tag": _entity_tag(user["aggregate_version"]),
        },
        "activated_scope": activated_scope,
    }


def _policy_requirement(
    tables: Mapping[str, Mapping[Any, Any]],
    *,
    actor_id: str,
    selector_digest: str,
    role: str,
    scope_type: str,
    scope_id: Optional[str],
    now: datetime,
) -> Dict[str, Any]:
    selector, bundle = _require_current_policy_bundle(
        tables,
        selector_digest=selector_digest,
        now=now,
    )
    if (
        selector.get("target_role") != role
        or selector.get("scope_type") != scope_type
        or (scope_type == "USER_ROLE" and scope_id is not None)
    ):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    if scope_type == "ORGANIZATION_ROLE":
        organization = tables.get("organizations", {}).get(scope_id)
        if (
            organization is None
            or organization.get("jurisdiction") != selector.get("jurisdiction")
        ):
            raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    bundle_id = bundle.policy_bundle_id
    documents_by_id = {
        document.document_id: document for document in bundle.documents
    }
    accepted_document_ids = set()
    for acceptance in tables.get("policy_acceptances", {}).values():
        document = documents_by_id.get(acceptance.get("policy_document_id"))
        if (
            document is not None
            and acceptance.get("user_id") == actor_id
            and acceptance.get("policy_bundle_id") == bundle_id
            and acceptance.get("policy_document_sha256")
            == document.content_sha256
            and acceptance.get("legal_effect") == document.legal_effect.value
        ):
            accepted_document_ids.add(document.document_id)
    required_document_ids = set(bundle.required_document_ids)
    missing_document_ids = sorted(required_document_ids - accepted_document_ids)
    return {
        "selector_digest": selector_digest,
        "purpose": selector["access_purpose"],
        "role": role,
        "scope_type": scope_type,
        "scope_id": scope_id,
        "satisfied": not missing_document_ids,
        "required_policy_bundle_id": bundle_id,
        "missing_document_ids": missing_document_ids,
    }


def _require_role_grant_source(
    tables: Mapping[str, Mapping[Any, Any]],
    *,
    grant: Mapping[str, Any],
    actor_id: str,
    scope_type: str,
    membership: Optional[Mapping[str, Any]],
) -> AccessInvitation:
    source_id = grant.get("source_invitation_id")
    source = tables.get("invitations", {}).get(source_id)
    common_valid = (
        isinstance(source, AccessInvitation)
        and source.status.value == "ACCEPTED"
        and grant.get("user_id") == actor_id
        and grant.get("target_role") == source.target_role.value
        and grant.get("policy_selector_digest")
        == source.policy_selector_digest
        and grant.get("granted_by_kind") in ("USER", "SYSTEM")
        and isinstance(grant.get("granted_by_id"), str)
        and bool(grant.get("granted_by_id"))
        and type(grant.get("aggregate_version")) is int
        and grant.get("aggregate_version") >= 1
        and grant.get("revoked_at") is None
        and grant.get("revocation_reason_code") is None
    )
    if not common_valid:
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    if scope_type == "USER_ROLE":
        valid_scope = (
            membership is None
            and source.purpose == InvitationPurpose.CREATOR_ENROLLMENT
            and source.target_scope.value == "USER"
            and source.organization_id is None
        )
    else:
        valid_scope = (
            membership is not None
            and source.purpose == InvitationPurpose.ORGANIZATION_MEMBERSHIP
            and source.target_scope.value == "ORGANIZATION"
            and source.organization_id == membership.get("organization_id")
            and grant.get("organization_id")
            == membership.get("organization_id")
            and grant.get("membership_id") == membership.get("membership_id")
            and grant.get("user_id") == membership.get("user_id")
        )
    if not valid_scope:
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    return source


def _require_current_policy_bundle_for_invitation(
    tables: Mapping[str, Mapping[Any, Any]],
    *,
    invitation: AccessInvitation,
    now: datetime,
):
    selector, bundle = _require_current_policy_bundle(
        tables,
        selector_digest=invitation.policy_selector_digest,
        now=now,
    )
    expected_scope_type = (
        "USER_ROLE"
        if invitation.purpose == InvitationPurpose.CREATOR_ENROLLMENT
        else "ORGANIZATION_ROLE"
    )
    if (
        selector.get("access_purpose") != invitation.purpose.value
        or selector.get("scope_type") != expected_scope_type
        or selector.get("target_role") != invitation.target_role.value
    ):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    if invitation.organization_id is not None:
        organization = tables.get("organizations", {}).get(
            invitation.organization_id
        )
        if (
            organization is None
            or organization.get("jurisdiction") != selector.get("jurisdiction")
        ):
            raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    return bundle


def _require_current_policy_bundle(
    tables: Mapping[str, Mapping[Any, Any]],
    *,
    selector_digest: str,
    now: datetime,
):
    if not _is_sha256(selector_digest):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    selector = tables.get("policy_selectors", {}).get(selector_digest)
    if not isinstance(selector, Mapping):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    current_bundle_id = selector.get("current_bundle_id")
    valid_selector = (
        selector.get("selector_digest") == selector_digest
        and selector.get("canonicalization_version") == "policy-selector-json-v1"
        and isinstance(selector.get("access_purpose"), str)
        and selector.get("access_purpose")
        and selector.get("scope_type") in ("USER_ROLE", "ORGANIZATION_ROLE")
        and isinstance(selector.get("target_role"), str)
        and selector.get("target_role")
        and isinstance(selector.get("jurisdiction"), str)
        and selector.get("jurisdiction")
        and isinstance(selector.get("locale"), str)
        and selector.get("locale")
        and type(selector.get("aggregate_version")) is int
        and selector.get("aggregate_version") > 0
        and isinstance(current_bundle_id, str)
        and bool(current_bundle_id)
    )
    if not valid_selector:
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    bundle = tables.get("policy_bundles", {}).get(current_bundle_id)
    if bundle is None:
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    status = getattr(getattr(bundle, "status", None), "value", None)
    effective_at = getattr(bundle, "effective_at", None)
    effective_until = getattr(bundle, "effective_until", None)
    if (
        getattr(bundle, "policy_bundle_id", None) != current_bundle_id
        or getattr(bundle, "selector_digest", None) != selector_digest
        or status != "ACTIVE"
        or not _is_utc_datetime(effective_at)
        or effective_at > now
        or (
            effective_until is not None
            and (
                not _is_utc_datetime(effective_until)
                or now >= effective_until
            )
        )
    ):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    return selector, bundle


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def _entity_tag(aggregate_version: int) -> str:
    return '"v%d"' % aggregate_version


def _timestamp(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    _require_aware_datetime(value)
    return value.isoformat().replace("+00:00", "Z")


def _is_utc_datetime(value: Any) -> bool:
    return (
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() == timedelta(0)
    )


def _require_aware_datetime(value: datetime) -> None:
    if not _is_utc_datetime(value):
        raise IamError("SERVICE_UNAVAILABLE")
