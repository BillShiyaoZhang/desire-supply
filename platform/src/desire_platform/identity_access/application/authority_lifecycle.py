"""Fail-closed IAM authority, consent, and session lifecycle commands.

The handlers in this module deliberately operate on the narrow mapping/UoW
port used by the IAM application layer.  Every public command claims and
completes its receipt in the same transaction as the aggregate, audit, and
closed outbox event writes.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import re
from typing import Any, Mapping, Optional, Sequence

from ..domain.authority_lifecycle import (
    LifecycleActorContext,
    LifecycleCommandResult,
    ResumeMembershipCommand,
    RevokeAccessInvitationCommand,
    RevokeMembershipCommand,
    RevokeReplayedSessionFamilyCommand,
    RevokeSessionCommand,
    SuspendMembershipCommand,
    WithdrawConsentGrantCommand,
)
from ..domain.errors import IamError
from ..ports.authority_lifecycle import (
    LifecycleCommitOutcomeUnknownError,
    LifecycleStorageUnavailableError,
)
from ..ports.safety_hold import (
    HoldDecision,
    SafetyHoldDecisionResult,
    SafetyHoldUnavailableError,
)


AUTHORITY_LIFECYCLE_BEHAVIOR_NOT_AVAILABLE = (
    "IAM_AUTHORITY_LIFECYCLE_BEHAVIOR_NOT_AVAILABLE"
)
_CANONICALIZATION_VERSION = "restricted-canonical-json-v1"
_REASON_CODE = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
_MFA_WINDOW = timedelta(minutes=10)


class _LifecycleHandler:
    def __init__(
        self,
        *,
        uow_factory: Any,
        clock: Any,
        id_source: Any,
        keyring: Any,
        event_validator: Any,
        safe_response_validator: Any,
        safety_hold: Optional[Any] = None,
        safety_hold_policy_version: Optional[str] = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._id_source = id_source
        self._keyring = keyring
        self._event_validator = event_validator
        self._safe_response_validator = safe_response_validator
        self._safety_hold = safety_hold
        self._safety_hold_policy_version = safety_hold_policy_version

    def _snapshot(self) -> Mapping[str, Mapping[str, Any]]:
        try:
            return self._uow_factory.store.snapshot()
        except Exception as error:
            raise IamError("SERVICE_UNAVAILABLE") from error

    def _now(self) -> datetime:
        try:
            now = self._clock.now()
        except Exception as error:
            raise IamError("SERVICE_UNAVAILABLE") from error
        if not _is_utc(now):
            raise IamError("SERVICE_UNAVAILABLE")
        return now

    def _receipt_material(
        self,
        *,
        actor: LifecycleActorContext,
        command: Any,
        command_name: str,
        target_type: str,
        target_id: str,
        path: str,
        expected_version: Optional[int],
        body: Mapping[str, Any],
        session: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        _require_identifier(target_id)
        raw_key = getattr(command, "idempotency_key", None)
        if not isinstance(raw_key, str) or not raw_key:
            raise IamError("INVALID_REQUEST")
        key_ids = (
            getattr(self._keyring, "idempotency_key_digest_key_id", None),
            getattr(self._keyring, "payload_hash_key_id", None),
            session.get("handle_digest_key_id"),
            session.get("csrf_key_id"),
        )
        for key_id in dict.fromkeys(key_ids):
            if not isinstance(key_id, str) or not key_id:
                raise IamError("SERVICE_UNAVAILABLE")
            _keyed_digest(self._keyring, key_id, b"lifecycle-key-preflight-v1")

        digest_key_id = self._keyring.idempotency_key_digest_key_id
        payload_key_id = self._keyring.payload_hash_key_id
        idempotency_digest = _keyed_digest(
            self._keyring,
            digest_key_id,
            _canonical_bytes(
                {
                    "domain": "iam-lifecycle-idempotency-key-v1",
                    "idempotency_key": raw_key,
                }
            ),
        )
        payload_hash = _keyed_digest(
            self._keyring,
            payload_key_id,
            _canonical_bytes(
                {
                    "body": body,
                    "canonicalization_version": _CANONICALIZATION_VERSION,
                    "command_name": command_name,
                    "command_version": 1,
                    "http_method": "DELETE" if command_name == "RevokeSession" else "POST",
                    "if_match_version": expected_version,
                    "path": path,
                    "target_id": target_id,
                    "target_kind": target_type,
                }
            ),
        )
        return {
            "principal_kind": "USER",
            "principal_id": actor.actor_user_id,
            "command_name": command_name,
            "command_version": 1,
            "idempotency_key_digest": idempotency_digest,
            "idempotency_key_digest_key_id": digest_key_id,
            "payload_hash": payload_hash,
            "payload_hash_key_id": payload_key_id,
            "canonicalization_version": _CANONICALIZATION_VERSION,
            "target_type": target_type,
            "target_id": target_id,
        }

    def _receipt(
        self,
        tables: Mapping[str, Mapping[str, Any]],
        material: Mapping[str, Any],
    ) -> Optional[Mapping[str, Any]]:
        matches = [
            receipt
            for receipt in tables.get("command_receipts", {}).values()
            if all(
                receipt.get(name) == material[name]
                for name in (
                    "principal_kind",
                    "principal_id",
                    "command_name",
                    "command_version",
                    "idempotency_key_digest",
                )
            )
        ]
        if len(matches) > 1:
            raise IamError("SERVICE_UNAVAILABLE")
        if not matches:
            return None
        receipt = matches[0]
        if receipt.get("payload_hash") != material["payload_hash"]:
            raise IamError("IDEMPOTENCY_KEY_REUSED")
        for name in (
            "idempotency_key_digest_key_id",
            "payload_hash_key_id",
            "canonicalization_version",
            "target_type",
            "target_id",
        ):
            if receipt.get(name) != material[name]:
                raise IamError("SERVICE_UNAVAILABLE")
        if receipt.get("status") == "PENDING":
            raise IamError("COMMAND_IN_PROGRESS")
        if receipt.get("status") != "COMPLETED":
            raise IamError("SERVICE_UNAVAILABLE")
        return receipt

    def _pending_receipt(
        self,
        material: Mapping[str, Any],
        *,
        receipt_id: str,
        now: datetime,
    ) -> dict[str, Any]:
        return {
            "command_receipt_id": receipt_id,
            **deepcopy(dict(material)),
            "status": "PENDING",
            "created_at": now,
        }

    def _complete_receipt(
        self,
        pending: Mapping[str, Any],
        *,
        response_body: Mapping[str, Any],
        response_schema: str,
        now: datetime,
    ) -> dict[str, Any]:
        return {
            **deepcopy(dict(pending)),
            "status": "COMPLETED",
            "response_schema": response_schema,
            "response_schema_version": 1,
            "response_body": deepcopy(dict(response_body)),
            "completed_at": now,
        }

    def _commit(self, uow: Any) -> None:
        try:
            uow.commit()
        except LifecycleCommitOutcomeUnknownError as error:
            raise IamError("COMMAND_OUTCOME_UNKNOWN") from error
        except LifecycleStorageUnavailableError as error:
            raise IamError("SERVICE_UNAVAILABLE") from error
        except IamError:
            raise
        except Exception as error:
            # Once COMMIT has been sent, an unclassified adapter exception is
            # never proof that the transaction rolled back.
            raise IamError("COMMAND_OUTCOME_UNKNOWN") from error

    def _put(
        self,
        uow: Any,
        table: str,
        key: str,
        value: Mapping[str, Any],
        checkpoint: str,
    ) -> None:
        try:
            uow.put(table, key, value, checkpoint=checkpoint)
        except LifecycleStorageUnavailableError as error:
            raise IamError("SERVICE_UNAVAILABLE") from error

    def _validate_event(self, event: Mapping[str, Any]) -> None:
        try:
            self._event_validator.validate(event)
        except Exception as error:
            raise IamError("SERVICE_UNAVAILABLE") from error

    def _validate_response(
        self, response: Mapping[str, Any], schema_name: str
    ) -> None:
        try:
            self._safe_response_validator.validate(response, schema_name)
        except Exception as error:
            raise IamError("SERVICE_UNAVAILABLE") from error


class RevokeAccessInvitationHandler(_LifecycleHandler):
    def handle(
        self,
        *,
        actor: LifecycleActorContext,
        command: RevokeAccessInvitationCommand,
    ) -> LifecycleCommandResult:
        now = self._now()
        snapshot = self._snapshot()
        session = _require_current_session(snapshot, actor=actor, now=now)
        reason_body = _reason_body(self._keyring, command.reason)
        material = self._receipt_material(
            actor=actor,
            command=command,
            command_name="RevokeAccessInvitation",
            target_type="AccessInvitation",
            target_id=command.invitation_id,
            path=f"/v1/access-invitations/{command.invitation_id}/revoke",
            expected_version=command.expected_version,
            body={"reason": reason_body},
            session=session,
        )
        receipt = self._receipt(snapshot, material)
        invitation = _require_organization_invitation(snapshot, command.invitation_id)
        _require_org_admin(
            snapshot,
            actor=actor,
            organization_id=invitation["organization_id"],
            now=now,
            require_mfa=True,
        )
        if receipt is not None:
            response = _receipt_response(receipt, "AccessInvitationAdminDto")
            expected = _invitation_dto(snapshot, invitation)
            if response != expected:
                raise IamError("SERVICE_UNAVAILABLE")
            self._validate_response(response, "AccessInvitationAdminDto")
            return LifecycleCommandResult(True, 200, response)
        if invitation.get("status") != "ISSUED" or now >= invitation.get("expires_at"):
            raise IamError("INVALID_STATE_TRANSITION")
        if invitation.get("aggregate_version") != command.expected_version:
            raise IamError("PRECONDITION_FAILED")

        receipt_id = self._id_source.new_id("command_receipt")
        pending = self._pending_receipt(material, receipt_id=receipt_id, now=now)
        try:
            with self._uow_factory.begin() as uow:
                _lock_receipt(uow, material)
                _lock_actor(uow, snapshot, actor)
                uow.lock("invitations", (command.invitation_id,))
                uow.lock("organizations", (invitation["organization_id"],))
                membership, grant = _org_admin_rows(
                    snapshot, actor.actor_user_id, invitation["organization_id"]
                )
                uow.lock("memberships", (membership["membership_id"],))
                uow.lock(
                    "membership_role_grants",
                    (grant["membership_role_grant_id"],),
                )
                uow.lock("policy_selectors", (invitation["policy_selector_digest"],))
                tables = uow.tables
                locked_session = _require_current_session(tables, actor=actor, now=now)
                locked = _require_organization_invitation(tables, command.invitation_id)
                _require_org_admin(
                    tables,
                    actor=actor,
                    organization_id=locked["organization_id"],
                    now=now,
                    require_mfa=True,
                )
                if locked.get("status") != "ISSUED" or now >= locked.get("expires_at"):
                    raise IamError("INVALID_STATE_TRANSITION")
                if locked.get("aggregate_version") != command.expected_version:
                    raise IamError("PRECONDITION_FAILED")
                self._put(
                    uow,
                    "command_receipts",
                    receipt_id,
                    pending,
                    "invitation.receipt_in_progress",
                )
                updated = deepcopy(locked)
                updated.update(
                    {
                        "status": "REVOKED",
                        "terminal_at": now,
                        "reason_code": command.reason.reason_code,
                        "aggregate_version": locked["aggregate_version"] + 1,
                    }
                )
                self._put(
                    uow,
                    "invitations",
                    command.invitation_id,
                    updated,
                    "invitation.aggregate",
                )
                response = _invitation_dto(tables, updated)
                self._validate_response(response, "AccessInvitationAdminDto")
                audit_id = self._id_source.new_id("audit_event")
                self._put(
                    uow,
                    "audit_events",
                    audit_id,
                    _audit(
                        audit_id=audit_id,
                        actor=actor,
                        action="RevokeAccessInvitation",
                        target_type="AccessInvitation",
                        target_id=command.invitation_id,
                        organization_id=updated["organization_id"],
                        auth_strength=locked_session["acr_code"],
                        reason_code=command.reason.reason_code,
                        before_status="ISSUED",
                        after_status="REVOKED",
                        before_version=locked["aggregate_version"],
                        after_version=updated["aggregate_version"],
                        occurred_at=now,
                    ),
                    "invitation.audit",
                )
                event_id = self._id_source.new_id("outbox_event")
                event = _event(
                    event_id=event_id,
                    event_type="AccessInvitationRevoked",
                    aggregate_type="AccessInvitation",
                    aggregate_id=command.invitation_id,
                    aggregate_version=updated["aggregate_version"],
                    actor=actor,
                    organization_id=updated["organization_id"],
                    occurred_at=now,
                    payload={
                        "invitation_binding": {
                            "invitation_id": updated["invitation_id"],
                            "bound_invitation_version": locked["aggregate_version"],
                            "issued_policy_bundle_id": updated["issued_policy_bundle_id"],
                            "purpose": updated["purpose"],
                            "target_scope": updated["target_scope"],
                            "target_role": updated["target_role"],
                            "is_initial_admin": updated["is_initial_admin"],
                        },
                        "status": "REVOKED",
                    },
                )
                self._validate_event(event)
                self._put(
                    uow,
                    "outbox_events",
                    event_id,
                    event,
                    "invitation.outbox",
                )
                completed = self._complete_receipt(
                    pending,
                    response_body=response,
                    response_schema="AccessInvitationAdminDto",
                    now=now,
                )
                self._put(
                    uow,
                    "command_receipts",
                    receipt_id,
                    completed,
                    "invitation.receipt_completed",
                )
                self._commit(uow)
        except LifecycleStorageUnavailableError as error:
            raise IamError("SERVICE_UNAVAILABLE") from error
        return LifecycleCommandResult(False, 200, response)


class WithdrawConsentGrantHandler(_LifecycleHandler):
    def handle(
        self,
        *,
        actor: LifecycleActorContext,
        command: WithdrawConsentGrantCommand,
    ) -> LifecycleCommandResult:
        now = self._now()
        snapshot = self._snapshot()
        session = _require_current_session(snapshot, actor=actor, now=now)
        material = self._receipt_material(
            actor=actor,
            command=command,
            command_name="WithdrawConsentGrant",
            target_type="ConsentGrant",
            target_id=command.consent_grant_id,
            path=f"/v1/me/consents/{command.consent_grant_id}/withdraw",
            expected_version=command.expected_version,
            body={"reason": _reason_body(self._keyring, command.reason)},
            session=session,
        )
        receipt = self._receipt(snapshot, material)
        grant = _owned(snapshot, "consent_grants", command.consent_grant_id, actor.actor_user_id)
        if receipt is not None:
            response = _receipt_response(receipt, "ConsentGrantDto")
            if response != _consent_dto(grant):
                raise IamError("SERVICE_UNAVAILABLE")
            self._validate_response(response, "ConsentGrantDto")
            return LifecycleCommandResult(True, 200, response)
        if grant.get("status") != "ACTIVE" or now >= grant.get("expires_at"):
            raise IamError("INVALID_STATE_TRANSITION")
        if grant.get("aggregate_version") != command.expected_version:
            raise IamError("PRECONDITION_FAILED")
        receipt_id = self._id_source.new_id("command_receipt")
        pending = self._pending_receipt(material, receipt_id=receipt_id, now=now)
        try:
            with self._uow_factory.begin() as uow:
                _lock_receipt(uow, material)
                _lock_actor(uow, snapshot, actor)
                uow.lock("consent_grants", (command.consent_grant_id,))
                existing_withdrawals = sorted(
                    key
                    for key, item in snapshot.get("consent_withdrawals", {}).items()
                    if item.get("consent_grant_id") == command.consent_grant_id
                )
                uow.lock("consent_withdrawals", tuple(existing_withdrawals))
                tables = uow.tables
                locked_session = _require_current_session(tables, actor=actor, now=now)
                locked = _owned(
                    tables,
                    "consent_grants",
                    command.consent_grant_id,
                    actor.actor_user_id,
                )
                if locked.get("status") != "ACTIVE" or now >= locked.get("expires_at"):
                    raise IamError("INVALID_STATE_TRANSITION")
                if locked.get("aggregate_version") != command.expected_version:
                    raise IamError("PRECONDITION_FAILED")
                self._put(
                    uow,
                    "command_receipts",
                    receipt_id,
                    pending,
                    "consent.receipt_in_progress",
                )
                withdrawal_id = self._id_source.new_id("consent_withdrawal")
                self._put(
                    uow,
                    "consent_withdrawals",
                    withdrawal_id,
                    {
                        "consent_withdrawal_id": withdrawal_id,
                        "consent_grant_id": command.consent_grant_id,
                        "user_id": actor.actor_user_id,
                        "effective_at": now,
                        "reason_code": command.reason.reason_code,
                    },
                    "consent.withdrawal",
                )
                updated = deepcopy(locked)
                updated.update(
                    {
                        "status": "WITHDRAWN",
                        "withdrawn_at": now,
                        "aggregate_version": locked["aggregate_version"] + 1,
                    }
                )
                self._put(
                    uow,
                    "consent_grants",
                    command.consent_grant_id,
                    updated,
                    "consent.aggregate",
                )
                response = _consent_dto(updated)
                self._validate_response(response, "ConsentGrantDto")
                audit_id = self._id_source.new_id("audit_event")
                self._put(
                    uow,
                    "audit_events",
                    audit_id,
                    _audit(
                        audit_id=audit_id,
                        actor=actor,
                        action="WithdrawConsentGrant",
                        target_type="ConsentGrant",
                        target_id=command.consent_grant_id,
                        organization_id=None,
                        auth_strength=locked_session["acr_code"],
                        reason_code=command.reason.reason_code,
                        before_status="ACTIVE",
                        after_status="WITHDRAWN",
                        before_version=locked["aggregate_version"],
                        after_version=updated["aggregate_version"],
                        occurred_at=now,
                    ),
                    "consent.audit",
                )
                event_id = self._id_source.new_id("outbox_event")
                event = _event(
                    event_id=event_id,
                    event_type="ConsentWithdrawn",
                    aggregate_type="ConsentGrant",
                    aggregate_id=command.consent_grant_id,
                    aggregate_version=updated["aggregate_version"],
                    actor=actor,
                    organization_id=None,
                    occurred_at=now,
                    payload={
                        "consent_grant_id": updated["consent_grant_id"],
                        "user_id": updated["user_id"],
                        "status": "WITHDRAWN",
                        "effective_at": _timestamp(now),
                        "derived_authorization": _derived_consent(updated),
                    },
                )
                self._validate_event(event)
                self._put(uow, "outbox_events", event_id, event, "consent.outbox")
                completed = self._complete_receipt(
                    pending,
                    response_body=response,
                    response_schema="ConsentGrantDto",
                    now=now,
                )
                self._put(
                    uow,
                    "command_receipts",
                    receipt_id,
                    completed,
                    "consent.receipt_completed",
                )
                self._commit(uow)
        except LifecycleStorageUnavailableError as error:
            raise IamError("SERVICE_UNAVAILABLE") from error
        return LifecycleCommandResult(False, 200, response)


class RevokeSessionHandler(_LifecycleHandler):
    def handle(
        self,
        *,
        actor: LifecycleActorContext,
        command: RevokeSessionCommand,
    ) -> LifecycleCommandResult:
        now = self._now()
        snapshot = self._snapshot()
        current = _require_current_session(snapshot, actor=actor, now=now)
        material = self._receipt_material(
            actor=actor,
            command=command,
            command_name="RevokeSession",
            target_type="Session",
            target_id=command.session_id,
            path=f"/v1/me/sessions/{command.session_id}",
            expected_version=None,
            body={},
            session=current,
        )
        receipt = self._receipt(snapshot, material)
        target = _owned(snapshot, "sessions", command.session_id, actor.actor_user_id)
        if receipt is not None:
            if _receipt_response(receipt, "Empty204") != {}:
                raise IamError("SERVICE_UNAVAILABLE")
            return LifecycleCommandResult(
                True,
                204,
                None,
                command.session_id == actor.current_session_id,
            )
        receipt_id = self._id_source.new_id("command_receipt")
        pending = self._pending_receipt(material, receipt_id=receipt_id, now=now)
        try:
            with self._uow_factory.begin() as uow:
                _lock_receipt(uow, material)
                uow.lock("users", (actor.actor_user_id,))
                families = sorted(
                    {
                        current["session_family_id"],
                        target["session_family_id"],
                    }
                )
                uow.lock("session_families", tuple(families))
                uow.lock(
                    "sessions",
                    tuple(sorted({actor.current_session_id, command.session_id})),
                )
                tables = uow.tables
                locked_current = _require_current_session(tables, actor=actor, now=now)
                locked = _owned(tables, "sessions", command.session_id, actor.actor_user_id)
                self._put(
                    uow,
                    "command_receipts",
                    receipt_id,
                    pending,
                    "session.receipt_in_progress",
                )
                status = locked.get("status")
                active_by_deadline = _session_deadlines_open(locked, now)
                changed = status == "ACTIVE"
                updated = deepcopy(locked)
                if changed:
                    if active_by_deadline:
                        updated.update(
                            {
                                "status": "REVOKED",
                                "revoked_at": now,
                                "revocation_reason_code": (
                                    "USER_LOGOUT_CURRENT_SESSION"
                                    if command.session_id == actor.current_session_id
                                    else "USER_REVOKED_SESSION"
                                ),
                                "aggregate_version": locked["aggregate_version"] + 1,
                            }
                        )
                    else:
                        updated.update(
                            {
                                "status": "EXPIRED",
                                "expired_at": now,
                                "aggregate_version": locked["aggregate_version"] + 1,
                            }
                        )
                    self._put(
                        uow,
                        "sessions",
                        command.session_id,
                        updated,
                        "session.aggregate",
                    )
                audit_id = self._id_source.new_id("audit_event")
                self._put(
                    uow,
                    "audit_events",
                    audit_id,
                    _audit(
                        audit_id=audit_id,
                        actor=actor,
                        action="RevokeSession",
                        target_type="Session",
                        target_id=command.session_id,
                        organization_id=None,
                        auth_strength=locked_current["acr_code"],
                        reason_code=(
                            "USER_LOGOUT_CURRENT_SESSION"
                            if command.session_id == actor.current_session_id
                            else "USER_REVOKED_SESSION"
                        ),
                        before_status=status,
                        after_status=updated.get("status"),
                        before_version=locked.get("aggregate_version"),
                        after_version=updated.get("aggregate_version"),
                        occurred_at=now,
                    ),
                    "session.audit",
                )
                if changed and updated.get("status") == "REVOKED":
                    event_id = self._id_source.new_id("outbox_event")
                    event = _event(
                        event_id=event_id,
                        event_type="SessionRevoked",
                        aggregate_type="Session",
                        aggregate_id=command.session_id,
                        aggregate_version=updated["aggregate_version"],
                        actor=actor,
                        organization_id=None,
                        occurred_at=now,
                        payload={
                            "session_id": updated["session_id"],
                            "session_family_id": updated["session_family_id"],
                            "user_id": updated["user_id"],
                            "status": "REVOKED",
                        },
                    )
                    self._validate_event(event)
                    self._put(
                        uow,
                        "outbox_events",
                        event_id,
                        event,
                        "session.outbox",
                    )
                completed = self._complete_receipt(
                    pending,
                    response_body={},
                    response_schema="Empty204",
                    now=now,
                )
                self._put(
                    uow,
                    "command_receipts",
                    receipt_id,
                    completed,
                    "session.receipt_completed",
                )
                self._commit(uow)
        except LifecycleStorageUnavailableError as error:
            raise IamError("SERVICE_UNAVAILABLE") from error
        return LifecycleCommandResult(
            False,
            204,
            None,
            command.session_id == actor.current_session_id,
        )


class RevokeReplayedSessionFamilyHandler(_LifecycleHandler):
    def handle(
        self,
        *,
        command: RevokeReplayedSessionFamilyCommand,
    ) -> LifecycleCommandResult:
        now = self._now()
        snapshot = self._snapshot()
        marker = snapshot.get("security_events", {}).get(command.security_event_id)
        if marker is not None:
            if not _security_event_matches(marker, command):
                raise IamError("SERVICE_UNAVAILABLE")
            return LifecycleCommandResult(True, 204, None)
        family = snapshot.get("session_families", {}).get(command.session_family_id)
        replayed = snapshot.get("sessions", {}).get(command.replayed_session_id)
        if (
            family is None
            or replayed is None
            or family.get("user_id") != command.user_id
            or replayed.get("user_id") != command.user_id
            or replayed.get("session_family_id") != command.session_family_id
            or replayed.get("status") not in {"REVOKED", "EXPIRED"}
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        if family.get("status") == "REVOKED":
            return LifecycleCommandResult(False, 204, None)
        family_session_ids = sorted(
            key
            for key, item in snapshot.get("sessions", {}).items()
            if item.get("session_family_id") == command.session_family_id
        )
        try:
            with self._uow_factory.begin() as uow:
                uow.lock("security_events", (command.security_event_id,))
                uow.lock("session_families", (command.session_family_id,))
                uow.lock("sessions", tuple(family_session_ids))
                tables = uow.tables
                if tables.get("security_events", {}).get(command.security_event_id):
                    return LifecycleCommandResult(True, 204, None)
                locked_family = tables.get("session_families", {}).get(
                    command.session_family_id
                )
                locked_replayed = tables.get("sessions", {}).get(
                    command.replayed_session_id
                )
                if (
                    locked_family is None
                    or locked_replayed is None
                    or locked_family.get("user_id") != command.user_id
                    or locked_replayed.get("user_id") != command.user_id
                    or locked_replayed.get("session_family_id")
                    != command.session_family_id
                    or locked_replayed.get("status") not in {"REVOKED", "EXPIRED"}
                ):
                    raise IamError("SERVICE_UNAVAILABLE")
                marker = {
                    "security_event_id": command.security_event_id,
                    "event_type": "REPLAYED_SESSION_HANDLE",
                    "session_family_id": command.session_family_id,
                    "replayed_session_id": command.replayed_session_id,
                    "user_id": command.user_id,
                    "occurred_at": now,
                }
                self._put(
                    uow,
                    "security_events",
                    command.security_event_id,
                    marker,
                    "replay.security_event",
                )
                updated_family = deepcopy(locked_family)
                updated_family.update(
                    {
                        "status": "REVOKED",
                        "revoked_at": now,
                        "revocation_reason_code": "REPLAYED_SESSION_HANDLE",
                        "aggregate_version": locked_family["aggregate_version"] + 1,
                    }
                )
                self._put(
                    uow,
                    "session_families",
                    command.session_family_id,
                    updated_family,
                    "replay.family",
                )
                successors = sorted(
                    (
                        deepcopy(item)
                        for item in tables.get("sessions", {}).values()
                        if item.get("session_family_id") == command.session_family_id
                        and item.get("status") == "ACTIVE"
                    ),
                    key=lambda item: item["session_id"],
                )
                updated_sessions = []
                for index, successor in enumerate(successors):
                    successor.update(
                        {
                            "status": "REVOKED",
                            "revoked_at": now,
                            "revocation_reason_code": "REPLAYED_SESSION_HANDLE",
                            "aggregate_version": successor["aggregate_version"] + 1,
                        }
                    )
                    self._put(
                        uow,
                        "sessions",
                        successor["session_id"],
                        successor,
                        f"replay.session.{index}",
                    )
                    updated_sessions.append(successor)
                audit_id = self._id_source.new_id("audit_event")
                self._put(
                    uow,
                    "audit_events",
                    audit_id,
                    {
                        "audit_event_id": audit_id,
                        "actor_kind": "SYSTEM",
                        "actor_id": "system_session_security",
                        "action": "RevokeReplayedSessionFamily",
                        "target_type": "SessionFamily",
                        "target_id": command.session_family_id,
                        "user_id": command.user_id,
                        "reason_code": "REPLAYED_SESSION_HANDLE",
                        "result": "SUCCEEDED",
                        "occurred_at": now,
                    },
                    "replay.audit",
                )
                for index, successor in enumerate(updated_sessions):
                    event_id = self._id_source.new_id("outbox_event")
                    event = _system_event(
                        event_id=event_id,
                        event_type="SessionRevoked",
                        aggregate_type="Session",
                        aggregate_id=successor["session_id"],
                        aggregate_version=successor["aggregate_version"],
                        security_event_id=command.security_event_id,
                        occurred_at=now,
                        payload={
                            "session_id": successor["session_id"],
                            "session_family_id": successor["session_family_id"],
                            "user_id": successor["user_id"],
                            "status": "REVOKED",
                        },
                    )
                    self._validate_event(event)
                    self._put(
                        uow,
                        "outbox_events",
                        event_id,
                        event,
                        f"replay.outbox.{index}",
                    )
                self._commit(uow)
        except LifecycleStorageUnavailableError as error:
            raise IamError("SERVICE_UNAVAILABLE") from error
        return LifecycleCommandResult(False, 204, None)


class _MembershipLifecycleHandler(_LifecycleHandler):
    _action = ""
    _event_type = ""
    _from_statuses: frozenset[str] = frozenset()
    _to_status = ""

    def _handle(
        self,
        *,
        actor: LifecycleActorContext,
        command: Any,
    ) -> LifecycleCommandResult:
        now = self._now()
        snapshot = self._snapshot()
        session = _require_current_session(snapshot, actor=actor, now=now)
        material = self._receipt_material(
            actor=actor,
            command=command,
            command_name=self._action,
            target_type="Membership",
            target_id=command.membership_id,
            path=_membership_path(self._action, command.membership_id),
            expected_version=command.expected_version,
            body={"reason": _reason_body(self._keyring, command.reason)},
            session=session,
        )
        receipt = self._receipt(snapshot, material)
        target, roles = self._guards(
            snapshot,
            actor=actor,
            command=command,
            now=now,
            check_state=receipt is None,
            check_version=receipt is None,
        )
        if receipt is not None:
            response = _receipt_response(receipt, "MembershipAdminDto")
            _require_membership_receipt_binding(response, target, roles)
            self._validate_response(response, "MembershipAdminDto")
            return LifecycleCommandResult(True, 200, response)

        hold_result = None
        if self._action == "ResumeMembership":
            hold_result = self._evaluate_resume_hold(
                actor=actor,
                target=target,
                now=now,
            )

        receipt_id = self._id_source.new_id("command_receipt")
        pending = self._pending_receipt(material, receipt_id=receipt_id, now=now)
        drifted = False
        try:
            with self._uow_factory.begin() as uow:
                self._lock_membership_rows(
                    uow,
                    snapshot,
                    actor=actor,
                    target=target,
                    roles=roles,
                    material=material,
                )
                tables = uow.tables
                locked_target = tables.get("memberships", {}).get(
                    command.membership_id
                )
                if (
                    hold_result is not None
                    and (
                        locked_target is None
                        or locked_target.get("aggregate_version")
                        != hold_result.target_version
                        or locked_target.get("organization_id")
                        != hold_result.organization_id
                    )
                ):
                    drifted = True
                else:
                    locked_target, locked_roles = self._guards(
                        tables,
                        actor=actor,
                        command=command,
                        now=now,
                        check_state=True,
                        check_version=True,
                    )
                    response = self._write_membership_transaction(
                        uow,
                        tables=tables,
                        actor=actor,
                        command=command,
                        now=now,
                        target=locked_target,
                        roles=locked_roles,
                        pending=pending,
                        receipt_id=receipt_id,
                    )
                    self._commit(uow)
        except LifecycleStorageUnavailableError as error:
            raise IamError("SERVICE_UNAVAILABLE") from error
        if drifted:
            self._finish_resume_after_drift(actor=actor, command=command, now=now)
            raise AssertionError("resume drift recheck unexpectedly executable")
        return LifecycleCommandResult(False, 200, response)

    def _guards(
        self,
        tables: Mapping[str, Mapping[str, Any]],
        *,
        actor: LifecycleActorContext,
        command: Any,
        now: datetime,
        check_state: bool,
        check_version: bool,
    ) -> tuple[Mapping[str, Any], list[Mapping[str, Any]]]:
        target = tables.get("memberships", {}).get(command.membership_id)
        if target is None or not isinstance(target.get("organization_id"), str):
            raise IamError("RESOURCE_NOT_FOUND")
        _require_org_admin(
            tables,
            actor=actor,
            organization_id=target["organization_id"],
            now=now,
            require_mfa=True,
        )
        if target.get("organization_id") not in tables.get("organizations", {}):
            raise IamError("RESOURCE_NOT_FOUND")
        roles = _membership_roles(tables, target)
        historical_roles = _membership_all_roles(tables, target)
        completed_revoke_shape = (
            not check_state
            and self._action == "RevokeMembership"
            and target.get("status") == "REVOKED"
        )
        if not roles:
            if completed_revoke_shape and len(historical_roles) == 1:
                roles = historical_roles
            elif len(historical_roles) == 1:
                raise IamError("INVALID_STATE_TRANSITION")
            else:
                raise IamError("SERVICE_UNAVAILABLE")
        if len(roles) > 1:
            raise IamError("SERVICE_UNAVAILABLE")
        if check_state and target.get("status") not in self._from_statuses:
            raise IamError("INVALID_STATE_TRANSITION")
        if check_version and target.get("aggregate_version") != command.expected_version:
            raise IamError("PRECONDITION_FAILED")
        if self._action in {"SuspendMembership", "RevokeMembership"}:
            _guard_last_active_admin(tables, target=target, roles=roles)
        return target, roles

    def _evaluate_resume_hold(
        self,
        *,
        actor: LifecycleActorContext,
        target: Mapping[str, Any],
        now: datetime,
    ) -> SafetyHoldDecisionResult:
        if self._safety_hold is None or not isinstance(
            self._safety_hold_policy_version, str
        ):
            raise IamError("SAFETY_DECISION_UNAVAILABLE")
        query = {
            "actor_id": actor.actor_user_id,
            "action": "ResumeMembership",
            "target_type": "Membership",
            "target_id": target["membership_id"],
            "target_version": target["aggregate_version"],
            "organization_id": target["organization_id"],
            "policy_version": self._safety_hold_policy_version,
        }
        try:
            result = self._safety_hold.evaluate(**query)
        except SafetyHoldUnavailableError as error:
            raise IamError("SAFETY_DECISION_UNAVAILABLE") from error
        except IamError:
            raise
        except Exception as error:
            raise IamError("SAFETY_DECISION_UNAVAILABLE") from error
        expected = {
            name: query[name]
            for name in (
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
            and all(getattr(result, name) == value for name, value in expected.items())
            and _is_utc(result.evaluated_at)
            and _is_utc(result.valid_until)
            and result.evaluated_at <= now < result.valid_until
        )
        if not valid or result.decision == HoldDecision.UNAVAILABLE:
            raise IamError("SAFETY_DECISION_UNAVAILABLE")
        if result.decision == HoldDecision.BLOCK:
            raise IamError("SAFETY_HOLD_BLOCKED")
        if result.decision != HoldDecision.ALLOW:
            raise IamError("SAFETY_DECISION_UNAVAILABLE")
        return result

    def _finish_resume_after_drift(
        self,
        *,
        actor: LifecycleActorContext,
        command: ResumeMembershipCommand,
        now: datetime,
    ) -> None:
        snapshot = self._snapshot()
        target, _ = self._guards(
            snapshot,
            actor=actor,
            command=command,
            now=now,
            check_state=True,
            check_version=False,
        )
        self._evaluate_resume_hold(actor=actor, target=target, now=now)
        if target.get("aggregate_version") != command.expected_version:
            raise IamError("PRECONDITION_FAILED")
        raise IamError("PRECONDITION_FAILED")

    def _lock_membership_rows(
        self,
        uow: Any,
        snapshot: Mapping[str, Mapping[str, Any]],
        *,
        actor: LifecycleActorContext,
        target: Mapping[str, Any],
        roles: Sequence[Mapping[str, Any]],
        material: Mapping[str, Any],
    ) -> None:
        _lock_receipt(uow, material)
        _lock_actor(uow, snapshot, actor)
        organization_id = target["organization_id"]
        uow.lock("organizations", (organization_id,))
        actor_membership, actor_grant = _org_admin_rows(
            snapshot, actor.actor_user_id, organization_id
        )
        uow.lock("memberships", (actor_membership["membership_id"],))
        uow.lock(
            "membership_role_grants",
            (actor_grant["membership_role_grant_id"],),
        )
        uow.lock("memberships", (target["membership_id"],))
        uow.lock(
            "membership_role_grants",
            tuple(sorted(role["membership_role_grant_id"] for role in roles)),
        )
        active_admin_memberships, active_admin_grants = _active_admin_rows(
            snapshot, organization_id
        )
        uow.lock("memberships", tuple(sorted(active_admin_memberships)))
        uow.lock("membership_role_grants", tuple(sorted(active_admin_grants)))

    def _write_membership_transaction(
        self,
        uow: Any,
        *,
        tables: Mapping[str, Mapping[str, Any]],
        actor: LifecycleActorContext,
        command: Any,
        now: datetime,
        target: Mapping[str, Any],
        roles: Sequence[Mapping[str, Any]],
        pending: Mapping[str, Any],
        receipt_id: str,
    ) -> Mapping[str, Any]:
        self._put(
            uow,
            "command_receipts",
            receipt_id,
            pending,
            "membership.receipt_in_progress",
        )
        original_roles = [role["role_code"] for role in roles]
        updated_roles: list[Mapping[str, Any]] = []
        if self._action == "RevokeMembership":
            for index, role in enumerate(
                sorted(roles, key=lambda item: item["membership_role_grant_id"])
            ):
                updated_role = deepcopy(role)
                updated_role.update(
                    {
                        "revoked_at": now,
                        "revocation_reason_code": command.reason.reason_code,
                        "aggregate_version": role["aggregate_version"] + 1,
                    }
                )
                self._put(
                    uow,
                    "membership_role_grants",
                    role["membership_role_grant_id"],
                    updated_role,
                    f"membership.role.{index}",
                )
                updated_roles.append(updated_role)
        updated = deepcopy(target)
        updated.update(
            {
                "status": self._to_status,
                "status_changed_at": now,
                "reason_code": command.reason.reason_code,
                "aggregate_version": target["aggregate_version"] + 1,
            }
        )
        self._put(
            uow,
            "memberships",
            target["membership_id"],
            updated,
            "membership.aggregate",
        )
        response = _membership_dto(updated, original_roles)
        self._validate_response(response, "MembershipAdminDto")
        current_session = tables["sessions"][actor.current_session_id]
        audit_id = self._id_source.new_id("audit_event")
        self._put(
            uow,
            "audit_events",
            audit_id,
            _audit(
                audit_id=audit_id,
                actor=actor,
                action=self._action,
                target_type="Membership",
                target_id=target["membership_id"],
                organization_id=target["organization_id"],
                auth_strength=current_session["acr_code"],
                reason_code=command.reason.reason_code,
                before_status=target["status"],
                after_status=updated["status"],
                before_version=target["aggregate_version"],
                after_version=updated["aggregate_version"],
                occurred_at=now,
            ),
            "membership.audit",
        )
        event_id = self._id_source.new_id("outbox_event")
        event = _event(
            event_id=event_id,
            event_type=self._event_type,
            aggregate_type="Membership",
            aggregate_id=target["membership_id"],
            aggregate_version=updated["aggregate_version"],
            actor=actor,
            organization_id=target["organization_id"],
            occurred_at=now,
            payload={
                "membership_id": target["membership_id"],
                "user_id": target["user_id"],
                "status": updated["status"],
            },
        )
        self._validate_event(event)
        outbox_checkpoint = (
            "membership.outbox.0"
            if self._action == "RevokeMembership"
            else "membership.outbox"
        )
        self._put(uow, "outbox_events", event_id, event, outbox_checkpoint)
        if self._action == "RevokeMembership":
            for index, role in enumerate(updated_roles, start=1):
                role_event_id = self._id_source.new_id("outbox_event")
                role_event = _event(
                    event_id=role_event_id,
                    event_type="MembershipRolesRevoked",
                    aggregate_type="Membership",
                    aggregate_id=target["membership_id"],
                    aggregate_version=updated["aggregate_version"],
                    actor=actor,
                    organization_id=target["organization_id"],
                    occurred_at=now,
                    payload={
                        "membership_id": target["membership_id"],
                        "user_id": target["user_id"],
                        "membership_role_grant_id": role[
                            "membership_role_grant_id"
                        ],
                        "target_role": role["role_code"],
                    },
                )
                self._validate_event(role_event)
                self._put(
                    uow,
                    "outbox_events",
                    role_event_id,
                    role_event,
                    f"membership.outbox.{index}",
                )
        completed = self._complete_receipt(
            pending,
            response_body=response,
            response_schema="MembershipAdminDto",
            now=now,
        )
        self._put(
            uow,
            "command_receipts",
            receipt_id,
            completed,
            "membership.receipt_completed",
        )
        return response


class SuspendMembershipHandler(_MembershipLifecycleHandler):
    _action = "SuspendMembership"
    _event_type = "MembershipSuspended"
    _from_statuses = frozenset({"ACTIVE"})
    _to_status = "SUSPENDED"

    def handle(
        self,
        *,
        actor: LifecycleActorContext,
        command: SuspendMembershipCommand,
    ) -> LifecycleCommandResult:
        return self._handle(actor=actor, command=command)


class ResumeMembershipHandler(_MembershipLifecycleHandler):
    _action = "ResumeMembership"
    _event_type = "MembershipResumed"
    _from_statuses = frozenset({"SUSPENDED"})
    _to_status = "ACTIVE"

    def handle(
        self,
        *,
        actor: LifecycleActorContext,
        command: ResumeMembershipCommand,
    ) -> LifecycleCommandResult:
        return self._handle(actor=actor, command=command)


class RevokeMembershipHandler(_MembershipLifecycleHandler):
    _action = "RevokeMembership"
    _event_type = "MembershipRevoked"
    _from_statuses = frozenset({"ACTIVE", "SUSPENDED"})
    _to_status = "REVOKED"

    def handle(
        self,
        *,
        actor: LifecycleActorContext,
        command: RevokeMembershipCommand,
    ) -> LifecycleCommandResult:
        return self._handle(actor=actor, command=command)


def _require_identifier(value: Any) -> None:
    if not isinstance(value, str) or not (16 <= len(value) <= 128):
        raise IamError("INVALID_REQUEST")


def _is_utc(value: Any) -> bool:
    return (
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() == timedelta(0)
    )


def _timestamp(value: datetime) -> str:
    if not _is_utc(value):
        raise IamError("SERVICE_UNAVAILABLE")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_bytes(value: Any) -> bytes:
    def normalize(item: Any) -> Any:
        if isinstance(item, Mapping):
            return {str(key): normalize(child) for key, child in item.items()}
        if isinstance(item, tuple):
            return [normalize(child) for child in item]
        if isinstance(item, list):
            return [normalize(child) for child in item]
        if isinstance(item, datetime):
            return _timestamp(item)
        if isinstance(item, float):
            raise IamError("INVALID_REQUEST")
        return item

    return json.dumps(
        normalize(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _keyed_digest(keyring: Any, key_id: str, value: bytes) -> str:
    try:
        keyed = getattr(keyring, "keyed_digest_hex", None)
        if callable(keyed):
            result = keyed(key_id=key_id, canonical_bytes=value)
        else:
            key = keyring.get_key(key_id)
            if not isinstance(key, bytes) or len(key) < 16:
                raise ValueError("invalid key material")
            result = hmac.new(key, value, hashlib.sha256).hexdigest()
    except Exception as error:
        raise IamError("SERVICE_UNAVAILABLE") from error
    if not isinstance(result, str) or re.fullmatch(r"[a-f0-9]{64}", result) is None:
        raise IamError("SERVICE_UNAVAILABLE")
    return result


def _reason_body(keyring: Any, reason: Any) -> Mapping[str, Any]:
    code = getattr(reason, "reason_code", None)
    note = getattr(reason, "reason_note", None)
    if not isinstance(code, str) or _REASON_CODE.fullmatch(code) is None:
        raise IamError("INVALID_REQUEST")
    if note is not None and (not isinstance(note, str) or len(note) > 2000):
        raise IamError("INVALID_REQUEST")
    note_digest = None
    if note is not None:
        note_digest = _keyed_digest(
            keyring,
            keyring.payload_hash_key_id,
            b"iam-lifecycle-reason-note-v1\x00" + note.encode("utf-8"),
        )
    return {"reason_code": code, "reason_note_digest": note_digest}


def _session_deadlines_open(session: Mapping[str, Any], now: datetime) -> bool:
    idle = session.get("idle_expires_at")
    absolute = session.get("absolute_expires_at")
    if not _is_utc(idle) or not _is_utc(absolute):
        raise IamError("SERVICE_UNAVAILABLE")
    return now < idle and now < absolute


def _require_current_session(
    tables: Mapping[str, Mapping[str, Any]],
    *,
    actor: LifecycleActorContext,
    now: datetime,
) -> Mapping[str, Any]:
    session = tables.get("sessions", {}).get(actor.current_session_id)
    if (
        session is None
        or session.get("user_id") != actor.actor_user_id
        or session.get("status") != "ACTIVE"
    ):
        raise IamError("AUTHENTICATION_REQUIRED")
    if not _session_deadlines_open(session, now):
        raise IamError("SESSION_EXPIRED")
    family = tables.get("session_families", {}).get(session.get("session_family_id"))
    user = tables.get("users", {}).get(actor.actor_user_id)
    if (
        family is None
        or family.get("user_id") != actor.actor_user_id
        or family.get("status") != "ACTIVE"
        or family.get("current_generation") != session.get("generation")
        or user is None
        or user.get("status") != "ACTIVE"
    ):
        raise IamError("AUTHENTICATION_REQUIRED")
    return session


def _require_recent_mfa(session: Mapping[str, Any], now: datetime) -> None:
    auth_time = session.get("auth_time")
    acr = session.get("acr_code")
    amr = session.get("amr_codes")
    valid_method = isinstance(amr, (list, tuple)) and any(
        method in {"otp", "mfa", "webauthn", "hwk"} for method in amr
    )
    if (
        not _is_utc(auth_time)
        or auth_time > now
        or now - auth_time >= _MFA_WINDOW
        or not isinstance(acr, str)
        or "mfa" not in acr.lower()
        or not valid_method
    ):
        raise IamError("MFA_STEP_UP_REQUIRED")


def _org_admin_rows(
    tables: Mapping[str, Mapping[str, Any]],
    user_id: str,
    organization_id: str,
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    memberships = [
        item
        for item in tables.get("memberships", {}).values()
        if item.get("user_id") == user_id
        and item.get("organization_id") == organization_id
        and item.get("status") == "ACTIVE"
    ]
    if len(memberships) != 1:
        raise IamError("RESOURCE_NOT_FOUND")
    membership = memberships[0]
    grants = [
        item
        for item in tables.get("membership_role_grants", {}).values()
        if item.get("membership_id") == membership.get("membership_id")
        and item.get("organization_id") == organization_id
        and item.get("user_id") == user_id
        and item.get("role_code") == "ORG_ADMIN"
        and item.get("revoked_at") is None
    ]
    if len(grants) != 1:
        raise IamError("RESOURCE_NOT_FOUND")
    return membership, grants[0]


def _require_org_admin(
    tables: Mapping[str, Mapping[str, Any]],
    *,
    actor: LifecycleActorContext,
    organization_id: str,
    now: datetime,
    require_mfa: bool,
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    session = _require_current_session(tables, actor=actor, now=now)
    organization = tables.get("organizations", {}).get(organization_id)
    if organization is None or organization.get("status") != "ACTIVE":
        raise IamError("RESOURCE_NOT_FOUND")
    membership, grant = _org_admin_rows(
        tables, actor.actor_user_id, organization_id
    )
    if require_mfa:
        _require_recent_mfa(session, now)
    return membership, grant


def _require_organization_invitation(
    tables: Mapping[str, Mapping[str, Any]], invitation_id: str
) -> Mapping[str, Any]:
    invitation = tables.get("invitations", {}).get(invitation_id)
    if (
        invitation is None
        or invitation.get("purpose") != "ORGANIZATION_MEMBERSHIP"
        or invitation.get("target_scope") != "ORGANIZATION"
        or not isinstance(invitation.get("organization_id"), str)
        or invitation.get("is_initial_admin") is True
    ):
        raise IamError("RESOURCE_NOT_FOUND")
    return invitation


def _owned(
    tables: Mapping[str, Mapping[str, Any]],
    table: str,
    key: str,
    user_id: str,
) -> Mapping[str, Any]:
    item = tables.get(table, {}).get(key)
    if item is None or item.get("user_id") != user_id:
        raise IamError("RESOURCE_NOT_FOUND")
    return item


def _lock_receipt(uow: Any, material: Mapping[str, Any]) -> None:
    uow.lock(
        "command_receipts",
        (
            "%s:%s:%s:%s"
            % (
                material["principal_id"],
                material["command_name"],
                material["command_version"],
                material["idempotency_key_digest"],
            ),
        ),
    )


def _lock_actor(
    uow: Any,
    tables: Mapping[str, Mapping[str, Any]],
    actor: LifecycleActorContext,
) -> None:
    session = tables["sessions"][actor.current_session_id]
    uow.lock("session_families", (session["session_family_id"],))
    uow.lock("sessions", (actor.current_session_id,))
    uow.lock("users", (actor.actor_user_id,))


def _receipt_response(receipt: Mapping[str, Any], schema: str) -> Mapping[str, Any]:
    if (
        receipt.get("response_schema") != schema
        or receipt.get("response_schema_version") != 1
        or not isinstance(receipt.get("response_body"), Mapping)
    ):
        raise IamError("SERVICE_UNAVAILABLE")
    return deepcopy(dict(receipt["response_body"]))


def _invitation_dto(
    tables: Mapping[str, Mapping[str, Any]], invitation: Mapping[str, Any]
) -> dict[str, Any]:
    selector = tables.get("policy_selectors", {}).get(
        invitation.get("policy_selector_digest")
    )
    if selector is None:
        raise IamError("SERVICE_UNAVAILABLE")
    current_bundle_id = selector.get("current_bundle_id")
    bundle = tables.get("policy_bundles", {}).get(current_bundle_id)
    if (
        bundle is None
        or bundle.get("selector_digest") != invitation.get("policy_selector_digest")
        or bundle.get("status") != "ACTIVE"
    ):
        raise IamError("SERVICE_UNAVAILABLE")
    version = invitation.get("aggregate_version")
    return {
        "invitation_id": invitation["invitation_id"],
        "purpose": invitation["purpose"],
        "organization_id": invitation["organization_id"],
        "target_role": invitation["target_role"],
        "masked_recipient_label": invitation["masked_recipient_label"],
        "is_initial_admin": invitation["is_initial_admin"],
        "status": invitation["status"],
        "expires_at": _timestamp(invitation["expires_at"]),
        "created_at": _timestamp(invitation["created_at"]),
        "required_policy_bundle_id": current_bundle_id,
        "aggregate_version": version,
        "entity_tag": f'"v{version}"',
    }


def _consent_dto(grant: Mapping[str, Any]) -> dict[str, Any]:
    version = grant.get("aggregate_version")
    return {
        "consent_grant_id": grant["consent_grant_id"],
        "consent_offer_id": grant["consent_offer_id"],
        "purpose": grant["purpose"],
        "scope_type": grant["scope_type"],
        "scope_id": grant["scope_id"],
        "data_categories": list(grant["data_categories"]),
        "recipient_label": grant["recipient_label"],
        "document_id": grant["document_id"],
        "content_sha256": grant["content_sha256"],
        "granted_at": _timestamp(grant["granted_at"]),
        "expires_at": _timestamp(grant["expires_at"]),
        "status": grant["status"],
        "aggregate_version": version,
        "entity_tag": f'"v{version}"',
    }


def _derived_consent(grant: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "consent_offer_id": grant["consent_offer_id"],
        "consent_offer_version": grant["consent_offer_version"],
        "policy_bundle_id": grant["policy_bundle_id"],
        "purpose": grant["purpose"],
        "scope_type": grant["scope_type"],
        "scope_id": grant["scope_id"],
        "data_categories": list(grant["data_categories"]),
        "supporting_policy_document_id": grant["document_id"],
        "supporting_document_sha256": grant["content_sha256"],
        "expires_at": _timestamp(grant["expires_at"]),
    }


def _audit(
    *,
    audit_id: str,
    actor: LifecycleActorContext,
    action: str,
    target_type: str,
    target_id: str,
    organization_id: Optional[str],
    auth_strength: str,
    reason_code: str,
    before_status: str,
    after_status: str,
    before_version: int,
    after_version: int,
    occurred_at: datetime,
) -> dict[str, Any]:
    return {
        "audit_event_id": audit_id,
        "actor_id": actor.actor_user_id,
        "original_actor_id": actor.original_actor_id,
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "organization_id": organization_id,
        "auth_strength_code": auth_strength,
        "reason_code": reason_code,
        "before_status": before_status,
        "after_status": after_status,
        "before_version": before_version,
        "after_version": after_version,
        "result": "SUCCEEDED",
        "correlation_id": actor.correlation_id,
        "causation_id": actor.causation_id,
        "trace_id": actor.trace_id,
        "occurred_at": occurred_at,
    }


def _event(
    *,
    event_id: str,
    event_type: str,
    aggregate_type: str,
    aggregate_id: str,
    aggregate_version: int,
    actor: LifecycleActorContext,
    organization_id: Optional[str],
    occurred_at: datetime,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "event_type": event_type,
        "schema_version": 1,
        "occurred_at": _timestamp(occurred_at),
        "aggregate_type": aggregate_type,
        "aggregate_id": aggregate_id,
        "aggregate_version": aggregate_version,
        "actor_kind": "USER",
        "actor_id": actor.actor_user_id,
        "original_actor_id": actor.original_actor_id,
        "correlation_id": actor.correlation_id,
        "causation_id": actor.causation_id,
        "trace_id": actor.trace_id,
        "organization_id": organization_id,
        "payload": deepcopy(dict(payload)),
    }


def _system_event(
    *,
    event_id: str,
    event_type: str,
    aggregate_type: str,
    aggregate_id: str,
    aggregate_version: int,
    security_event_id: str,
    occurred_at: datetime,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "event_type": event_type,
        "schema_version": 1,
        "occurred_at": _timestamp(occurred_at),
        "aggregate_type": aggregate_type,
        "aggregate_id": aggregate_id,
        "aggregate_version": aggregate_version,
        "actor_kind": "SYSTEM",
        "actor_id": "system_session_security",
        "original_actor_id": None,
        "correlation_id": security_event_id,
        "causation_id": security_event_id,
        "trace_id": security_event_id,
        "organization_id": None,
        "payload": deepcopy(dict(payload)),
    }


def _security_event_matches(
    marker: Mapping[str, Any], command: RevokeReplayedSessionFamilyCommand
) -> bool:
    return all(
        marker.get(name) == getattr(command, name)
        for name in (
            "security_event_id",
            "replayed_session_id",
            "session_family_id",
            "user_id",
        )
    )


def _membership_path(action: str, membership_id: str) -> str:
    suffix = {
        "SuspendMembership": "suspend",
        "ResumeMembership": "resume",
        "RevokeMembership": "revoke",
    }.get(action)
    if suffix is None:
        raise IamError("SERVICE_UNAVAILABLE")
    return f"/v1/memberships/{membership_id}/{suffix}"


def _membership_roles(
    tables: Mapping[str, Mapping[str, Any]], target: Mapping[str, Any]
) -> list[Mapping[str, Any]]:
    return sorted(
        (
            role
            for role in tables.get("membership_role_grants", {}).values()
            if role.get("membership_id") == target.get("membership_id")
            and role.get("organization_id") == target.get("organization_id")
            and role.get("user_id") == target.get("user_id")
            and role.get("revoked_at") is None
            and role.get("role_code") in {"ORG_ADMIN", "DEMAND_OWNER"}
        ),
        key=lambda role: role["membership_role_grant_id"],
    )


def _membership_all_roles(
    tables: Mapping[str, Mapping[str, Any]], target: Mapping[str, Any]
) -> list[Mapping[str, Any]]:
    return sorted(
        (
            role
            for role in tables.get("membership_role_grants", {}).values()
            if role.get("membership_id") == target.get("membership_id")
            and role.get("organization_id") == target.get("organization_id")
            and role.get("user_id") == target.get("user_id")
            and role.get("role_code") in {"ORG_ADMIN", "DEMAND_OWNER"}
        ),
        key=lambda role: role["membership_role_grant_id"],
    )


def _active_admin_rows(
    tables: Mapping[str, Mapping[str, Any]], organization_id: str
) -> tuple[list[str], list[str]]:
    active_memberships = {
        membership["membership_id"]: membership
        for membership in tables.get("memberships", {}).values()
        if membership.get("organization_id") == organization_id
        and membership.get("status") == "ACTIVE"
    }
    grant_ids = []
    membership_ids = set()
    for role in tables.get("membership_role_grants", {}).values():
        membership_id = role.get("membership_id")
        if (
            membership_id in active_memberships
            and role.get("organization_id") == organization_id
            and role.get("user_id")
            == active_memberships[membership_id].get("user_id")
            and role.get("role_code") == "ORG_ADMIN"
            and role.get("revoked_at") is None
        ):
            membership_ids.add(membership_id)
            grant_ids.append(role["membership_role_grant_id"])
    return sorted(membership_ids), sorted(grant_ids)


def _guard_last_active_admin(
    tables: Mapping[str, Mapping[str, Any]],
    *,
    target: Mapping[str, Any],
    roles: Sequence[Mapping[str, Any]],
) -> None:
    target_is_active_admin = (
        target.get("status") == "ACTIVE"
        and any(role.get("role_code") == "ORG_ADMIN" for role in roles)
    )
    if not target_is_active_admin:
        return
    active_memberships, _ = _active_admin_rows(tables, target["organization_id"])
    if len(active_memberships) <= 1:
        raise IamError("LAST_ACTIVE_ORG_ADMIN")


def _membership_dto(
    membership: Mapping[str, Any], roles: Sequence[str]
) -> dict[str, Any]:
    if not roles or len(set(roles)) != len(roles):
        raise IamError("SERVICE_UNAVAILABLE")
    version = membership.get("aggregate_version")
    return {
        "membership_id": membership["membership_id"],
        "organization_id": membership["organization_id"],
        "user_id": membership["user_id"],
        "display_handle": membership["display_handle"],
        "status": membership["status"],
        "roles": list(roles),
        "aggregate_version": version,
        "entity_tag": f'"v{version}"',
    }


def _require_membership_receipt_binding(
    response: Mapping[str, Any],
    membership: Mapping[str, Any],
    current_roles: Sequence[Mapping[str, Any]],
) -> None:
    version = membership.get("aggregate_version")
    expected = {
        "membership_id": membership.get("membership_id"),
        "organization_id": membership.get("organization_id"),
        "user_id": membership.get("user_id"),
        "display_handle": membership.get("display_handle"),
        "status": membership.get("status"),
        "aggregate_version": version,
        "entity_tag": f'"v{version}"',
    }
    if any(response.get(name) != value for name, value in expected.items()):
        raise IamError("SERVICE_UNAVAILABLE")
    roles = response.get("roles")
    if (
        not isinstance(roles, list)
        or not roles
        or len(roles) != len(set(roles))
        or any(role not in {"ORG_ADMIN", "DEMAND_OWNER"} for role in roles)
    ):
        raise IamError("SERVICE_UNAVAILABLE")
    if membership.get("status") != "REVOKED":
        expected_roles = [role["role_code"] for role in current_roles]
        if roles != expected_roles:
            raise IamError("SERVICE_UNAVAILABLE")


__all__ = [
    "AUTHORITY_LIFECYCLE_BEHAVIOR_NOT_AVAILABLE",
    "ResumeMembershipHandler",
    "RevokeAccessInvitationHandler",
    "RevokeMembershipHandler",
    "RevokeReplayedSessionFamilyHandler",
    "RevokeSessionHandler",
    "SuspendMembershipHandler",
    "WithdrawConsentGrantHandler",
]
