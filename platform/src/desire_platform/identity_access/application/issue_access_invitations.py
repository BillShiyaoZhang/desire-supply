"""Default-deny application contract for issuing AccessInvitations.

The command deliberately contains only request facts.  Purpose, scope,
jurisdiction, locale, selector identity, current bundle, issuer authority,
timestamps, capability material, and initial-admin status are server facts and
therefore cannot be authored through this object.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import Enum
import hashlib
import inspect
import json
import unicodedata
from typing import Any, Dict, Mapping, Optional, Tuple

from ..domain.errors import IamError
from ..domain.invitations import (
    AccessInvitation,
    InvitationPurpose,
    InvitationStatus,
    TargetRole,
    TargetScope,
)
from ..ports.safety_hold import (
    HoldDecision,
    SafetyHoldDecisionResult,
    SafetyHoldUnavailableError,
)
from ..security.cryptography import KeyUnavailableError


INVITATION_TOKEN_FORMAT_VERSION = "access-invitation-token-v1"


class IssuerKind(str, Enum):
    SYSTEM = "SYSTEM"
    USER = "USER"


class RecipientContactType(str, Enum):
    EMAIL = "EMAIL"


@dataclass(frozen=True)
class SystemOperationCredential:
    """Closed authenticated workload authority for one Issue operation."""

    credential_id: str
    system_id: str
    operation: str
    allowed_purposes: Tuple[str, ...]
    status: str
    valid_from: datetime
    valid_until: datetime


@dataclass(frozen=True)
class RecipientInput:
    type: RecipientContactType
    value: str = field(repr=False)


@dataclass(frozen=True)
class IssueAccessInvitationCommand:
    organization_id: Optional[str]
    expected_organization_version: Optional[int]
    recipient: RecipientInput
    target_role: TargetRole
    expires_at: datetime
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class InvitationIssuerContext:
    actor_kind: IssuerKind
    actor_id: str
    session_id: Optional[str]
    original_actor_id: Optional[str]
    correlation_id: str
    causation_id: str
    trace_id: str
    auth_time: datetime
    acr_code: str
    amr_codes: Tuple[str, ...]


@dataclass(frozen=True)
class IssueAccessInvitationResult:
    replayed: bool
    invitation: Dict[str, Any]
    access_invitation_token: str = field(repr=False)
    join_fragment_url: str = field(repr=False)


class IssueAccessInvitationHandler:
    """Issue one exact, server-authoritative invitation capability atomically."""

    def __init__(
        self,
        *,
        uow_factory,
        clock,
        platform_enrollment_policy,
        locale_resolver,
        safety_hold,
        safety_hold_policy_version: str,
        release_token_codec,
        recipient_binding,
        receipt_codec,
        id_source,
        secret_source,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._platform_enrollment_policy = platform_enrollment_policy
        self._locale_resolver = locale_resolver
        self._safety_hold = safety_hold
        self._safety_hold_policy_version = safety_hold_policy_version
        self._release_token_codec = release_token_codec
        self._recipient_binding = recipient_binding
        self._receipt_codec = receipt_codec
        self._id_source = id_source
        self._secret_source = secret_source

    def handle(
        self,
        *,
        actor: InvitationIssuerContext,
        command: IssueAccessInvitationCommand,
    ) -> IssueAccessInvitationResult:
        now = self._clock.now()
        _require_server_time(now)
        _require_command_shape(command, now=now)
        actor_kind = _require_actor_shape(actor, now=now)
        _require_system_operation_credential(
            actor,
            actor_kind=actor_kind,
            command=command,
            now=now,
        )

        binding = self._bind_recipient(command)
        identity_digest = self._receipt_codec.identity_digest(
            command.idempotency_key
        )
        payload_hash = self._receipt_codec.payload_hash(
            command=command,
            recipient_binding_digest=binding["binding_digest"],
        )
        if not _is_sha256(identity_digest) or not _is_sha256(payload_hash):
            raise IamError("SERVICE_UNAVAILABLE")
        receipt_key = _receipt_key(
            actor_kind=actor_kind,
            actor_id=actor.actor_id,
            identity_digest=identity_digest,
        )

        snapshot = self._uow_factory.store.snapshot()
        receipt = _find_receipt(snapshot, receipt_key=receipt_key)
        if receipt is not None:
            return self._replay_receipt(
                tables=snapshot,
                actor=actor,
                actor_kind=actor_kind,
                receipt=receipt,
                identity_digest=identity_digest,
                payload_hash=payload_hash,
                binding=binding,
                command=command,
                now=now,
            )

        invitation_id = self._id_source.new_id("access_invitation")
        plan = self._derive_plan(
            snapshot,
            actor=actor,
            actor_kind=actor_kind,
            command=command,
            invitation_id=invitation_id,
            now=now,
        )
        hold_result = self._evaluate_safety_hold(
            actor=actor,
            target=plan.hold_target,
            now=now,
        )
        capability = self._prepare_capability(
            invitation_id=invitation_id,
            expires_at=command.expires_at,
        )

        for attempt in range(2):
            try:
                return self._execute_issue_transaction(
                    actor=actor,
                    actor_kind=actor_kind,
                    command=command,
                    binding=binding,
                    identity_digest=identity_digest,
                    payload_hash=payload_hash,
                    receipt_key=receipt_key,
                    invitation_id=invitation_id,
                    plan=plan,
                    hold_result=hold_result,
                    capability=capability,
                    now=now,
                )
            except _IssuePlanDrift:
                if attempt > 0:
                    raise IamError("PRECONDITION_FAILED")
                snapshot = self._uow_factory.store.snapshot()
                plan = self._derive_plan(
                    snapshot,
                    actor=actor,
                    actor_kind=actor_kind,
                    command=command,
                    invitation_id=invitation_id,
                    now=now,
                )
                hold_result = self._evaluate_safety_hold(
                    actor=actor,
                    target=plan.hold_target,
                    now=now,
                )
        raise AssertionError("unreachable Issue transaction retry state")

    def _execute_issue_transaction(
        self,
        *,
        actor: InvitationIssuerContext,
        actor_kind: IssuerKind,
        command: IssueAccessInvitationCommand,
        binding: Mapping[str, str],
        identity_digest: str,
        payload_hash: str,
        receipt_key: Tuple[str, str, str, int, str],
        invitation_id: str,
        plan: "_IssuePlan",
        hold_result: SafetyHoldDecisionResult,
        capability: "_CapabilityMaterial",
        now: datetime,
    ) -> IssueAccessInvitationResult:
        with self._uow_factory.begin() as uow:
            tables = uow.tables
            concurrent_receipt = _find_receipt(
                tables,
                receipt_key=receipt_key,
            )
            if concurrent_receipt is not None:
                return self._replay_receipt(
                    tables=tables,
                    actor=actor,
                    actor_kind=actor_kind,
                    receipt=concurrent_receipt,
                    identity_digest=identity_digest,
                    payload_hash=payload_hash,
                    binding=binding,
                    command=command,
                    now=now,
                )
            if invitation_id in tables.get("invitations", {}):
                raise IamError("SERVICE_UNAVAILABLE")

            locked_plan = plan
            if (
                plan.user_authority is not None
                and plan.user_authority.strict_persisted
            ):
                locked_authority, organization = self._lock_user_authority(
                    uow,
                    tables=tables,
                    actor=actor,
                    command=command,
                    plan=plan,
                    now=now,
                )
                if locked_authority != plan.user_authority:
                    raise _IssuePlanDrift()
                locked_plan = replace(
                    plan,
                    user_authority=locked_authority,
                )
                self._require_locked_organization_facts(
                    organization,
                    command=command,
                    plan=plan,
                )
            elif plan.organization_id is not None:
                organization = uow.lock(
                    "organizations",
                    plan.organization_id,
                )
                if (
                    isinstance(organization, Mapping)
                    and organization.get("aggregate_version")
                    != command.expected_organization_version
                ):
                    raise _IssuePlanDrift()
                self._require_locked_organization(
                    tables,
                    actor=actor,
                    actor_kind=actor_kind,
                    command=command,
                    plan=plan,
                    organization=organization,
                    now=now,
                )

            selector = uow.lock(
                "policy_selectors",
                plan.selector_digest,
            )
            locked_bundle = None
            if (
                plan.user_authority is not None
                and plan.user_authority.strict_persisted
                and isinstance(selector, Mapping)
            ):
                locked_bundle = uow.lock(
                    "policy_bundles",
                    selector.get("current_bundle_id"),
                )
            current_bundle = _require_current_policy_bundle(
                tables,
                selector_digest=plan.selector_digest,
                expected_facts=plan.selector_facts,
                now=now,
                locked_selector=selector,
                locked_bundle=locked_bundle,
            )
            if (
                current_bundle.policy_bundle_id != plan.current_bundle_id
                or selector.get("aggregate_version")
                != plan.selector_version
                or current_bundle != plan.current_bundle_snapshot
            ):
                raise _IssuePlanDrift()
            locked_plan = replace(
                locked_plan,
                current_bundle_id=current_bundle.policy_bundle_id,
            )
            _require_system_operation_credential(
                actor,
                actor_kind=actor_kind,
                command=command,
                now=now,
            )
            _require_current_hold_result(
                hold_result,
                target=plan.hold_target,
                policy_version=self._safety_hold_policy_version,
                now=now,
            )

            result = self._write_issue(
                uow,
                actor=actor,
                actor_kind=actor_kind,
                command=command,
                binding=binding,
                identity_digest=identity_digest,
                payload_hash=payload_hash,
                receipt_key=receipt_key,
                invitation_id=invitation_id,
                plan=locked_plan,
                capability=capability,
                now=now,
            )
            uow.commit()
            return result

    def _prepare_capability(
        self,
        *,
        invitation_id: str,
        expires_at: datetime,
    ) -> "_CapabilityMaterial":
        nonce_bytes = self._secret_source.token_bytes(
            purpose="access_invitation_nonce",
            length=32,
        )
        if not isinstance(nonce_bytes, bytes) or len(nonce_bytes) != 32:
            raise IamError("SERVICE_UNAVAILABLE")
        nonce = nonce_bytes.hex()
        token_key_id = getattr(self._release_token_codec, "key_id", None)
        token_format_version = getattr(
            self._release_token_codec,
            "format_version",
            INVITATION_TOKEN_FORMAT_VERSION,
        )
        if (
            not isinstance(token_key_id, str)
            or not token_key_id
            or not isinstance(token_format_version, str)
            or token_format_version != INVITATION_TOKEN_FORMAT_VERSION
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        token = _issue_invitation_token(
            self._release_token_codec,
            invitation_id=invitation_id,
            nonce=nonce,
            expires_at=expires_at,
            token_key_id=token_key_id,
            token_format_version=token_format_version,
        )
        return _CapabilityMaterial(
            nonce=nonce,
            token_key_id=token_key_id,
            token_format_version=token_format_version,
            token=token,
        )

    def _lock_user_authority(
        self,
        uow,
        *,
        tables: Mapping[str, Mapping[Any, Any]],
        actor: InvitationIssuerContext,
        command: IssueAccessInvitationCommand,
        plan: "_IssuePlan",
        now: datetime,
    ) -> Tuple["_UserAuthority", Mapping[str, Any]]:
        expected = plan.user_authority
        if expected is None or not expected.strict_persisted:
            raise AssertionError("persisted USER authority lock requested without facts")
        family = uow.lock("session_families", expected.session_family_id)
        session = uow.lock("sessions", expected.session_id)
        user = uow.lock("users", expected.user_id)
        organization = uow.lock("organizations", plan.organization_id)
        membership = uow.lock("memberships", expected.membership_id)
        role_grant = uow.lock(
            "membership_role_grants",
            expected.role_grant_id,
        )
        authority = _require_exact_persisted_user_authority(
            actor=actor,
            organization_id=plan.organization_id,
            now=now,
            user=user,
            family=family,
            session=session,
            membership=membership,
            role_grant=role_grant,
        )
        if not isinstance(organization, Mapping):
            raise IamError("RESOURCE_NOT_FOUND")
        return authority, organization

    @staticmethod
    def _require_locked_organization_facts(
        organization: Mapping[str, Any],
        *,
        command: IssueAccessInvitationCommand,
        plan: "_IssuePlan",
    ) -> None:
        if (
            organization.get("organization_id") != plan.organization_id
            or organization.get("status") != "ACTIVE"
        ):
            raise IamError("RESOURCE_NOT_FOUND")
        if (
            organization.get("aggregate_version")
            != command.expected_organization_version
        ):
            raise _IssuePlanDrift()
        if (
            _canonical_selector_text(organization.get("jurisdiction"))
            != plan.selector_facts.jurisdiction
        ):
            raise _IssuePlanDrift()

    def _bind_recipient(
        self,
        command: IssueAccessInvitationCommand,
    ) -> Dict[str, str]:
        binding = self._recipient_binding.bind(
            contact_type=command.recipient.type.value,
            locator=command.recipient.value,
        )
        if not isinstance(binding, Mapping):
            raise IamError("SERVICE_UNAVAILABLE")
        required = {
            "type": command.recipient.type.value,
            "locator_ciphertext": binding.get("locator_ciphertext"),
            "binding_digest": binding.get("binding_digest"),
            "digest_key_id": binding.get("digest_key_id"),
            "masked_recipient_label": binding.get("masked_recipient_label"),
        }
        if (
            binding.get("type") != command.recipient.type.value
            or not isinstance(required["locator_ciphertext"], str)
            or not required["locator_ciphertext"]
            or not _is_sha256(required["binding_digest"])
            or not isinstance(required["digest_key_id"], str)
            or not required["digest_key_id"]
            or not isinstance(required["masked_recipient_label"], str)
            or not 3 <= len(required["masked_recipient_label"]) <= 80
            or command.recipient.value in repr(required)
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        return required

    def _derive_plan(
        self,
        tables: Mapping[str, Mapping[Any, Any]],
        *,
        actor: InvitationIssuerContext,
        actor_kind: IssuerKind,
        command: IssueAccessInvitationCommand,
        invitation_id: str,
        now: datetime,
    ) -> "_IssuePlan":
        user_authority = None
        if command.organization_id is None:
            if (
                command.expected_organization_version is not None
                or command.target_role != TargetRole.CREATOR
                or actor_kind != IssuerKind.SYSTEM
            ):
                raise IamError("INVALID_REQUEST")
            policy = self._platform_enrollment_policy.current()
            if (
                not isinstance(getattr(policy, "policy_version", None), str)
                or not policy.policy_version
                or type(getattr(policy, "aggregate_version", None)) is not int
                or policy.aggregate_version < 1
            ):
                raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
            jurisdiction = _canonical_selector_text(
                getattr(policy, "jurisdiction", None)
            )
            locale = _canonical_selector_text(getattr(policy, "locale", None))
            selector_facts = _SelectorFacts(
                access_purpose=InvitationPurpose.CREATOR_ENROLLMENT,
                scope_type="USER_ROLE",
                target_role=TargetRole.CREATOR,
                jurisdiction=jurisdiction,
                locale=locale,
            )
            organization_id = None
            is_initial_admin = False
        else:
            if (
                type(command.expected_organization_version) is not int
                or command.expected_organization_version < 1
                or command.target_role
                not in (TargetRole.ORG_ADMIN, TargetRole.DEMAND_OWNER)
            ):
                raise IamError("INVALID_REQUEST")
            organization = tables.get("organizations", {}).get(
                command.organization_id
            )
            user_authority = self._require_organization_authority(
                tables,
                actor=actor,
                actor_kind=actor_kind,
                command=command,
                organization=organization,
                now=now,
            )
            jurisdiction = _canonical_selector_text(
                organization.get("jurisdiction")
            )
            try:
                locale_value = self._locale_resolver.resolve(
                    jurisdiction=jurisdiction,
                    access_purpose=(
                        InvitationPurpose.ORGANIZATION_MEMBERSHIP.value
                    ),
                    target_role=command.target_role.value,
                )
            except IamError:
                raise
            locale = _canonical_selector_text(locale_value)
            selector_facts = _SelectorFacts(
                access_purpose=InvitationPurpose.ORGANIZATION_MEMBERSHIP,
                scope_type="ORGANIZATION_ROLE",
                target_role=command.target_role,
                jurisdiction=jurisdiction,
                locale=locale,
            )
            organization_id = command.organization_id
            is_initial_admin = (
                organization.get("status") == "PENDING_ADMIN"
                and actor_kind == IssuerKind.SYSTEM
                and command.target_role == TargetRole.ORG_ADMIN
            )

        selector_digest = _selector_digest(selector_facts)
        current_bundle = _require_current_policy_bundle(
            tables,
            selector_digest=selector_digest,
            expected_facts=selector_facts,
            now=now,
        )
        selector = tables.get("policy_selectors", {}).get(selector_digest)
        if not isinstance(selector, Mapping):
            raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
        return _IssuePlan(
            purpose=selector_facts.access_purpose,
            target_scope=(
                TargetScope.USER
                if organization_id is None
                else TargetScope.ORGANIZATION
            ),
            target_role=selector_facts.target_role,
            organization_id=organization_id,
            is_initial_admin=is_initial_admin,
            selector_facts=selector_facts,
            selector_digest=selector_digest,
            selector_version=selector["aggregate_version"],
            current_bundle_id=current_bundle.policy_bundle_id,
            current_bundle_snapshot=current_bundle,
            hold_target=_HoldTarget(
                target_type="AccessInvitation",
                target_id=invitation_id,
                target_version=1,
                organization_id=organization_id,
            ),
            user_authority=user_authority,
        )

    def _require_organization_authority(
        self,
        tables: Mapping[str, Mapping[Any, Any]],
        *,
        actor: InvitationIssuerContext,
        actor_kind: IssuerKind,
        command: IssueAccessInvitationCommand,
        organization: Any,
        now: datetime,
        check_expected_version: bool = True,
    ) -> Optional["_UserAuthority"]:
        if not isinstance(organization, Mapping):
            raise IamError("RESOURCE_NOT_FOUND")
        if (
            organization.get("organization_id") != command.organization_id
            or type(organization.get("aggregate_version")) is not int
            or organization.get("aggregate_version") < 1
        ):
            raise IamError("RESOURCE_NOT_FOUND")
        if check_expected_version and (
            organization["aggregate_version"]
            != command.expected_organization_version
        ):
            raise IamError("PRECONDITION_FAILED")
        status = organization.get("status")
        if status == "PENDING_ADMIN":
            if not (
                actor_kind == IssuerKind.SYSTEM
                and command.target_role == TargetRole.ORG_ADMIN
            ):
                raise IamError("RESOURCE_NOT_FOUND")
            if any(
                invitation.organization_id == command.organization_id
                and invitation.is_initial_admin
                and invitation.status == InvitationStatus.ISSUED
                for invitation in tables.get("invitations", {}).values()
                if isinstance(invitation, AccessInvitation)
            ):
                raise IamError("INVALID_STATE_TRANSITION")
            return None
        if status != "ACTIVE":
            raise IamError("RESOURCE_NOT_FOUND")
        if actor_kind == IssuerKind.SYSTEM:
            # SYSTEM is closed to creator enrollment and the one
            # PENDING_ADMIN initial-admin path.  It cannot impersonate an
            # organization administrator for an ACTIVE tenant.
            raise IamError("RESOURCE_NOT_FOUND")
        if actor_kind != IssuerKind.USER or not actor.session_id:
            raise IamError("AUTHENTICATION_REQUIRED")
        if _has_persisted_user_auth_surface(tables):
            return _resolve_persisted_user_authority(
                tables,
                actor=actor,
                organization_id=command.organization_id,
                now=now,
            )
        return _resolve_legacy_user_authority(
            tables,
            actor=actor,
            organization_id=command.organization_id,
            now=now,
        )

    def _require_locked_organization(
        self,
        tables: Mapping[str, Mapping[Any, Any]],
        *,
        actor: InvitationIssuerContext,
        actor_kind: IssuerKind,
        command: IssueAccessInvitationCommand,
        plan: "_IssuePlan",
        organization: Any,
        now: datetime,
    ) -> None:
        self._require_organization_authority(
            tables,
            actor=actor,
            actor_kind=actor_kind,
            command=command,
            organization=organization,
            now=now,
        )
        if (
            _canonical_selector_text(organization.get("jurisdiction"))
            != plan.selector_facts.jurisdiction
        ):
            raise _IssuePlanDrift()

    def _evaluate_safety_hold(
        self,
        *,
        actor: InvitationIssuerContext,
        target: "_HoldTarget",
        now: datetime,
    ) -> SafetyHoldDecisionResult:
        query = {
            "actor_id": actor.actor_id,
            "action": "IssueAccessInvitation",
            "target_type": target.target_type,
            "target_id": target.target_id,
            "target_version": target.target_version,
            "organization_id": target.organization_id,
            "policy_version": self._safety_hold_policy_version,
        }
        try:
            result = self._safety_hold.evaluate(**query)
        except SafetyHoldUnavailableError as error:
            raise IamError("SAFETY_DECISION_UNAVAILABLE") from error
        _require_current_hold_result(
            result,
            target=target,
            policy_version=self._safety_hold_policy_version,
            now=now,
        )
        return result

    def _replay_receipt(
        self,
        *,
        tables: Mapping[str, Mapping[Any, Any]],
        actor: InvitationIssuerContext,
        actor_kind: IssuerKind,
        receipt: Mapping[str, Any],
        identity_digest: str,
        payload_hash: str,
        binding: Mapping[str, str],
        command: IssueAccessInvitationCommand,
        now: datetime,
    ) -> IssueAccessInvitationResult:
        valid_identity = (
            receipt.get("principal_kind") == actor_kind.value
            and receipt.get("principal_id") == actor.actor_id
            and receipt.get("command_name") == "IssueAccessInvitation"
            and receipt.get("command_version") == 1
            and receipt.get("idempotency_key_digest") == identity_digest
        )
        if not valid_identity:
            raise IamError("SERVICE_UNAVAILABLE")
        if receipt.get("payload_hash") != payload_hash:
            raise IamError("IDEMPOTENCY_KEY_REUSED")
        if receipt.get("status") != "COMPLETED":
            raise IamError("COMMAND_IN_PROGRESS")
        response_body = receipt.get("response_body")
        reconstruction = receipt.get("reconstruction_metadata")
        if (
            not isinstance(response_body, Mapping)
            or not isinstance(response_body.get("invitation"), Mapping)
            or not isinstance(reconstruction, Mapping)
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        invitation_id = reconstruction.get("invitation_id")
        invitation = tables.get("invitations", {}).get(invitation_id)
        strict_protocol = _supports_explicit_token_selection(
            self._release_token_codec
        )
        if (
            not isinstance(invitation, AccessInvitation)
            or invitation.invitation_id != invitation_id
            or response_body["invitation"].get("invitation_id")
            != invitation_id
            or reconstruction.get("token_key_id")
            != getattr(invitation, "token_key_id", None)
            or not isinstance(getattr(invitation, "nonce", None), str)
            or not invitation.nonce
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        token_format_version = (
            invitation.token_format_version
            or INVITATION_TOKEN_FORMAT_VERSION
        )
        if strict_protocol:
            if (
                set(response_body) != {"invitation"}
                or not isinstance(invitation.token_format_version, str)
                or invitation.token_format_version
                != INVITATION_TOKEN_FORMAT_VERSION
                or not _is_sha256(invitation.nonce)
            ):
                raise IamError("SERVICE_UNAVAILABLE")
            expected_metadata = {
                "kind": "AccessInvitationCapability",
                "version": 1,
                "invitation_id": invitation.invitation_id,
                "invitation_version": 1,
                "token_format_version": token_format_version,
                "token_key_id": invitation.token_key_id,
            }
            expected_target = {
                "target_type": "AccessInvitation",
                "target_id": invitation.invitation_id,
                "target_version": 1,
            }
            actual_target = {
                key: receipt.get(key) for key in expected_target
            }
            if (
                dict(reconstruction) != expected_metadata
                or actual_target != expected_target
            ):
                raise IamError("SERVICE_UNAVAILABLE")
            if not _receipt_creation_binding_matches(
                tables,
                actor=actor,
                actor_kind=actor_kind,
                command=command,
                binding=binding,
                invitation=invitation,
                safe_invitation=response_body["invitation"],
            ):
                raise IamError("SERVICE_UNAVAILABLE")

        if actor_kind == IssuerKind.USER:
            organization = tables.get("organizations", {}).get(
                invitation.organization_id
            )
            self._require_organization_authority(
                tables,
                actor=actor,
                actor_kind=actor_kind,
                command=command,
                organization=organization,
                now=now,
                check_expected_version=False,
            )
        _require_system_operation_credential(
            actor,
            actor_kind=actor_kind,
            command=command,
            now=now,
        )
        token = _issue_invitation_token(
            self._release_token_codec,
            invitation_id=invitation.invitation_id,
            nonce=invitation.nonce,
            expires_at=invitation.expires_at,
            token_key_id=invitation.token_key_id,
            token_format_version=token_format_version,
        )
        return IssueAccessInvitationResult(
            replayed=True,
            invitation=deepcopy(dict(response_body["invitation"])),
            access_invitation_token=token,
            join_fragment_url="/join#" + token,
        )

    def _write_issue(
        self,
        uow,
        *,
        actor: InvitationIssuerContext,
        actor_kind: IssuerKind,
        command: IssueAccessInvitationCommand,
        binding: Mapping[str, str],
        identity_digest: str,
        payload_hash: str,
        receipt_key: Tuple[str, str, str, int, str],
        invitation_id: str,
        plan: "_IssuePlan",
        capability: "_CapabilityMaterial",
        now: datetime,
    ) -> IssueAccessInvitationResult:
        contact_point_id = self._id_source.new_id("contact_point")
        receipt_id = self._id_source.new_id("command_receipt")
        audit_event_id = self._id_source.new_id("audit_event")
        outbox_event_id = self._id_source.new_id("outbox_event")

        invitation = AccessInvitation(
            invitation_id=invitation_id,
            purpose=plan.purpose,
            target_scope=plan.target_scope,
            target_role=plan.target_role,
            organization_id=plan.organization_id,
            is_initial_admin=plan.is_initial_admin,
            recipient_contact_id=contact_point_id,
            issued_policy_bundle_id=plan.current_bundle_id,
            policy_selector_digest=plan.selector_digest,
            status=InvitationStatus.ISSUED,
            expires_at=command.expires_at,
            aggregate_version=1,
            created_at=now,
            masked_recipient_label=binding["masked_recipient_label"],
            issuer_kind=actor_kind.value,
            issuer_id=actor.actor_id,
            nonce=capability.nonce,
            token_key_id=capability.token_key_id,
            token_format_version=capability.token_format_version,
            updated_at=now,
        )
        safe_invitation = _safe_invitation(
            invitation,
            required_policy_bundle_id=plan.current_bundle_id,
        )
        pending_receipt = {
            "command_receipt_id": receipt_id,
            "principal_kind": actor_kind.value,
            "principal_id": actor.actor_id,
            "command_name": "IssueAccessInvitation",
            "command_version": 1,
            "idempotency_key_digest": identity_digest,
            "idempotency_digest_key_id": getattr(
                self._receipt_codec, "key_id", None
            ),
            "payload_hash": payload_hash,
            "target_type": "AccessInvitation",
            "target_id": invitation_id,
            "target_version": 1,
            "status": "PENDING",
            "created_at": now,
        }
        uow.put(
            "command_receipts",
            receipt_key,
            pending_receipt,
            checkpoint="command_receipt.pending",
        )
        uow.put(
            "contact_points",
            contact_point_id,
            {
                "contact_point_id": contact_point_id,
                "type": binding["type"],
                "locator_ciphertext": binding["locator_ciphertext"],
                "binding_digest": binding["binding_digest"],
                "binding_digest_key_id": binding["digest_key_id"],
                "status": "UNVERIFIED",
                "created_at": now,
                "aggregate_version": 1,
            },
            checkpoint="contact_point.create",
        )
        uow.put(
            "invitations",
            invitation_id,
            invitation,
            checkpoint="access_invitation.issue",
        )
        uow.put(
            "audit_events",
            audit_event_id,
            {
                "audit_event_id": audit_event_id,
                "actor_kind": actor_kind.value,
                "actor_id": actor.actor_id,
                "original_actor_id": actor.original_actor_id,
                "action": "IssueAccessInvitation",
                "target_type": "AccessInvitation",
                "target_id": invitation_id,
                "organization_id": plan.organization_id,
                "result": "SUCCEEDED",
                "before_status": None,
                "after_status": InvitationStatus.ISSUED.value,
                "aggregate_version": 1,
                "role": plan.target_role.value,
                "purpose": plan.purpose.value,
                "auth_strength_code": (
                    plan.user_authority.acr_code
                    if plan.user_authority is not None
                    else actor.acr_code
                ),
                "correlation_id": actor.correlation_id,
                "causation_id": actor.causation_id,
                "trace_id": actor.trace_id,
                "occurred_at": now,
            },
            checkpoint="audit_event.succeeded",
        )
        uow.put(
            "outbox_events",
            outbox_event_id,
            {
                "event_id": outbox_event_id,
                "event_type": "AccessInvitationIssued",
                "schema_version": 1,
                "occurred_at": _timestamp(now),
                "aggregate_type": "AccessInvitation",
                "aggregate_id": invitation_id,
                "aggregate_version": 1,
                "actor_kind": actor_kind.value,
                "actor_id": actor.actor_id,
                "original_actor_id": actor.original_actor_id,
                "correlation_id": actor.correlation_id,
                "causation_id": actor.causation_id,
                "trace_id": actor.trace_id,
                "organization_id": plan.organization_id,
                "payload": {
                    "invitation_binding": {
                        "invitation_id": invitation_id,
                        "bound_invitation_version": 1,
                        "issued_policy_bundle_id": plan.current_bundle_id,
                        "purpose": plan.purpose.value,
                        "target_scope": plan.target_scope.value,
                        "target_role": plan.target_role.value,
                        "is_initial_admin": plan.is_initial_admin,
                    },
                    "status": InvitationStatus.ISSUED.value,
                    "expires_at": _timestamp(command.expires_at),
                },
            },
            checkpoint="outbox.AccessInvitationIssued.0",
        )
        completed_receipt = dict(pending_receipt)
        completed_receipt.update(
            {
                "status": "COMPLETED",
                "response_schema_version": 1,
                "response_body": {
                    "invitation": deepcopy(safe_invitation),
                },
                "reconstruction_metadata": {
                    "kind": "AccessInvitationCapability",
                    "version": 1,
                    "invitation_id": invitation_id,
                    "invitation_version": 1,
                    "token_format_version": capability.token_format_version,
                    "token_key_id": capability.token_key_id,
                },
                "completed_at": now,
            }
        )
        uow.put(
            "command_receipts",
            receipt_key,
            completed_receipt,
            checkpoint="command_receipt.complete",
        )
        return IssueAccessInvitationResult(
            replayed=False,
            invitation=safe_invitation,
            access_invitation_token=capability.token,
            join_fragment_url="/join#" + capability.token,
        )


@dataclass(frozen=True)
class _SelectorFacts:
    access_purpose: InvitationPurpose
    scope_type: str
    target_role: TargetRole
    jurisdiction: str
    locale: str


@dataclass(frozen=True)
class _HoldTarget:
    target_type: str
    target_id: str
    target_version: int
    organization_id: Optional[str]


@dataclass(frozen=True)
class _IssuePlan:
    purpose: InvitationPurpose
    target_scope: TargetScope
    target_role: TargetRole
    organization_id: Optional[str]
    is_initial_admin: bool
    selector_facts: _SelectorFacts
    selector_digest: str
    selector_version: int
    current_bundle_id: str
    current_bundle_snapshot: Any
    hold_target: _HoldTarget
    user_authority: Optional["_UserAuthority"]


@dataclass(frozen=True)
class _UserAuthority:
    strict_persisted: bool
    user_id: str
    session_family_id: Optional[str]
    session_id: Optional[str]
    membership_id: str
    role_grant_id: str
    auth_time: datetime
    acr_code: str
    amr_codes: Tuple[str, ...]
    user_version: Optional[int]
    family_version: Optional[int]
    session_version: Optional[int]
    membership_version: Optional[int]


@dataclass(frozen=True)
class _CapabilityMaterial:
    nonce: str = field(repr=False)
    token_key_id: str
    token_format_version: str
    token: str = field(repr=False)


class _IssuePlanDrift(Exception):
    """A pre-hold authority/policy snapshot changed after locks were taken."""


def _require_command_shape(
    command: IssueAccessInvitationCommand,
    *,
    now: datetime,
) -> None:
    try:
        contact_type = RecipientContactType(command.recipient.type)
        target_role = TargetRole(command.target_role)
    except (AttributeError, TypeError, ValueError) as error:
        raise IamError("INVALID_REQUEST") from error
    if (
        contact_type != RecipientContactType.EMAIL
        or target_role != command.target_role
        or not isinstance(command.recipient.value, str)
        or not command.recipient.value.strip()
        or not isinstance(command.idempotency_key, str)
        or not command.idempotency_key
        or not _is_utc_datetime(command.expires_at)
        or command.expires_at <= now
        or command.expires_at > now + timedelta(days=30)
    ):
        raise IamError("INVALID_REQUEST")


def _require_actor_shape(
    actor: InvitationIssuerContext,
    *,
    now: datetime,
) -> IssuerKind:
    try:
        actor_kind = IssuerKind(actor.actor_kind)
    except (TypeError, ValueError) as error:
        raise IamError("AUTHENTICATION_REQUIRED") from error
    if (
        not isinstance(actor.actor_id, str)
        or not actor.actor_id
        or not all(
            isinstance(value, str) and value
            for value in (
                actor.correlation_id,
                actor.causation_id,
                actor.trace_id,
                actor.acr_code,
            )
        )
        or not _is_utc_datetime(actor.auth_time)
        or actor.auth_time > now
        or not isinstance(actor.amr_codes, tuple)
        or any(not isinstance(value, str) or not value for value in actor.amr_codes)
        or (actor_kind == IssuerKind.USER and not actor.session_id)
        or (actor_kind == IssuerKind.SYSTEM and actor.session_id is not None)
    ):
        raise IamError("AUTHENTICATION_REQUIRED")
    return actor_kind


def _require_system_operation_credential(
    actor: Any,
    *,
    actor_kind: IssuerKind,
    command: IssueAccessInvitationCommand,
    now: datetime,
) -> None:
    if actor_kind != IssuerKind.SYSTEM:
        return
    # Older authenticated adapters construct InvitationIssuerContext itself.
    # Credential-aware adapters expose the closed credential explicitly; once
    # present, absence or any mismatch is default-deny.
    if not hasattr(actor, "operation_credential"):
        return
    credential = getattr(actor, "operation_credential", None)
    expected_purpose = (
        InvitationPurpose.CREATOR_ENROLLMENT.value
        if command.organization_id is None
        else InvitationPurpose.ORGANIZATION_MEMBERSHIP.value
    )
    valid = (
        credential is not None
        and isinstance(getattr(credential, "credential_id", None), str)
        and bool(credential.credential_id)
        and getattr(credential, "system_id", None) == actor.actor_id
        and getattr(credential, "operation", None) == "IssueAccessInvitation"
        and isinstance(getattr(credential, "allowed_purposes", None), tuple)
        and expected_purpose in credential.allowed_purposes
        and getattr(credential, "status", None) == "ACTIVE"
        and _is_utc_datetime(getattr(credential, "valid_from", None))
        and _is_utc_datetime(getattr(credential, "valid_until", None))
        and credential.valid_from <= now < credential.valid_until
    )
    if not valid:
        raise IamError("AUTHENTICATION_REQUIRED")


def _supports_explicit_token_selection(codec: Any) -> bool:
    try:
        parameters = inspect.signature(codec.issue).parameters
    except (TypeError, ValueError, AttributeError):
        return False
    return (
        "token_key_id" in parameters
        and "token_format_version" in parameters
    )


def _issue_invitation_token(
    codec: Any,
    *,
    invitation_id: str,
    nonce: str,
    expires_at: datetime,
    token_key_id: str,
    token_format_version: str,
) -> str:
    try:
        if _supports_explicit_token_selection(codec):
            token = codec.issue(
                invitation_id=invitation_id,
                nonce=nonce,
                expires_at=expires_at,
                token_key_id=token_key_id,
                token_format_version=token_format_version,
            )
        else:
            if getattr(codec, "key_id", None) != token_key_id:
                raise KeyUnavailableError("legacy invitation-token key unavailable")
            token = codec.issue(
                invitation_id=invitation_id,
                nonce=nonce,
                expires_at=expires_at,
            )
    except KeyUnavailableError as error:
        raise IamError("SERVICE_UNAVAILABLE") from error
    if not isinstance(token, str) or not token:
        raise IamError("SERVICE_UNAVAILABLE")
    return token


def _receipt_creation_binding_matches(
    tables: Mapping[str, Mapping[Any, Any]],
    *,
    actor: Any,
    actor_kind: IssuerKind,
    command: IssueAccessInvitationCommand,
    binding: Mapping[str, str],
    invitation: AccessInvitation,
    safe_invitation: Mapping[str, Any],
) -> bool:
    contact = tables.get("contact_points", {}).get(
        invitation.recipient_contact_id
    )
    contact_key_id = (
        contact.get("binding_digest_key_id")
        if isinstance(contact, Mapping)
        else None
    )
    if contact_key_id is None and isinstance(contact, Mapping):
        contact_key_id = contact.get("digest_key_id")
    expected_safe = _safe_invitation_at_issue(invitation)
    return (
        invitation.issuer_kind == actor_kind.value
        and invitation.issuer_id == actor.actor_id
        and invitation.organization_id == command.organization_id
        and invitation.target_role == command.target_role
        and invitation.expires_at == command.expires_at
        and invitation.created_at is not None
        and invitation.masked_recipient_label
        == binding.get("masked_recipient_label")
        and isinstance(contact, Mapping)
        and contact.get("contact_point_id") == invitation.recipient_contact_id
        and contact.get("type") == binding.get("type")
        and contact.get("locator_ciphertext")
        == binding.get("locator_ciphertext")
        and contact.get("binding_digest") == binding.get("binding_digest")
        and contact_key_id == binding.get("digest_key_id")
        and contact.get("status") == "UNVERIFIED"
        and contact.get("aggregate_version") == 1
        and _is_utc_datetime(contact.get("created_at"))
        and contact.get("created_at") == invitation.created_at
        and dict(safe_invitation) == expected_safe
    )


def _safe_invitation_at_issue(invitation: AccessInvitation) -> Dict[str, Any]:
    if invitation.created_at is None:
        return {}
    return {
        "invitation_id": invitation.invitation_id,
        "purpose": invitation.purpose.value,
        "organization_id": invitation.organization_id,
        "target_role": invitation.target_role.value,
        "masked_recipient_label": invitation.masked_recipient_label,
        "is_initial_admin": invitation.is_initial_admin,
        "status": InvitationStatus.ISSUED.value,
        "expires_at": _timestamp(invitation.expires_at),
        "created_at": _timestamp(invitation.created_at),
        "required_policy_bundle_id": invitation.issued_policy_bundle_id,
        "aggregate_version": 1,
        "entity_tag": '"v1"',
    }


def _receipt_key(
    *,
    actor_kind: IssuerKind,
    actor_id: str,
    identity_digest: str,
) -> Tuple[str, str, str, int, str]:
    return (
        actor_kind.value,
        actor_id,
        "IssueAccessInvitation",
        1,
        identity_digest,
    )


def _find_receipt(
    tables: Mapping[str, Mapping[Any, Any]],
    *,
    receipt_key: Tuple[str, str, str, int, str],
) -> Optional[Mapping[str, Any]]:
    receipts = tables.get("command_receipts", {})
    direct = receipts.get(receipt_key)
    if isinstance(direct, Mapping):
        return direct
    expected = {
        "principal_kind": receipt_key[0],
        "principal_id": receipt_key[1],
        "command_name": receipt_key[2],
        "command_version": receipt_key[3],
        "idempotency_key_digest": receipt_key[4],
    }
    matches = [
        receipt
        for receipt in receipts.values()
        if isinstance(receipt, Mapping)
        and all(receipt.get(key) == value for key, value in expected.items())
    ]
    if len(matches) > 1:
        raise IamError("SERVICE_UNAVAILABLE")
    return matches[0] if matches else None


def _canonical_selector_text(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    normalized = unicodedata.normalize("NFC", value)
    if not normalized:
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    return normalized


def _selector_digest(facts: _SelectorFacts) -> str:
    payload = {
        "access_purpose": facts.access_purpose.value,
        "scope_type": facts.scope_type,
        "target_role": facts.target_role.value,
        "jurisdiction": facts.jurisdiction,
        "locale": facts.locale,
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _require_current_policy_bundle(
    tables: Mapping[str, Mapping[Any, Any]],
    *,
    selector_digest: str,
    expected_facts: _SelectorFacts,
    now: datetime,
    locked_selector: Any = None,
    locked_bundle: Any = None,
):
    selector = (
        locked_selector
        if locked_selector is not None
        else tables.get("policy_selectors", {}).get(selector_digest)
    )
    if not isinstance(selector, Mapping):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    current_bundle_id = selector.get("current_bundle_id")
    valid_selector = (
        selector.get("selector_digest") == selector_digest
        and selector.get("canonicalization_version")
        == "policy-selector-json-v1"
        and selector.get("access_purpose")
        == expected_facts.access_purpose.value
        and selector.get("scope_type") == expected_facts.scope_type
        and selector.get("target_role") == expected_facts.target_role.value
        and selector.get("jurisdiction") == expected_facts.jurisdiction
        and selector.get("locale") == expected_facts.locale
        and type(selector.get("aggregate_version")) is int
        and selector.get("aggregate_version") > 0
        and isinstance(current_bundle_id, str)
        and bool(current_bundle_id)
    )
    if not valid_selector:
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")

    effective = []
    for key, candidate in tables.get("policy_bundles", {}).items():
        if getattr(candidate, "selector_digest", None) != selector_digest:
            continue
        if _enum_value(getattr(candidate, "status", None)) != "ACTIVE":
            continue
        effective_at = getattr(candidate, "effective_at", None)
        effective_until = getattr(candidate, "effective_until", None)
        if (
            not _is_utc_datetime(effective_at)
            or (
                effective_until is not None
                and not _is_utc_datetime(effective_until)
            )
        ):
            raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
        if effective_at <= now and (
            effective_until is None or now < effective_until
        ):
            if (
                getattr(candidate, "policy_bundle_id", None) != key
                or not isinstance(key, str)
            ):
                raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
            effective.append(candidate)
    if len(effective) != 1:
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    bundle = effective[0]
    if bundle.policy_bundle_id != current_bundle_id:
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    if locked_bundle is not None and locked_bundle is not bundle:
        if (
            getattr(locked_bundle, "policy_bundle_id", None)
            != bundle.policy_bundle_id
        ):
            raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    return bundle


def _has_persisted_user_auth_surface(
    tables: Mapping[str, Mapping[Any, Any]],
) -> bool:
    return any(
        table in tables
        for table in ("users", "session_families", "sessions")
    )


def _resolve_persisted_user_authority(
    tables: Mapping[str, Mapping[Any, Any]],
    *,
    actor: Any,
    organization_id: str,
    now: datetime,
) -> _UserAuthority:
    session = tables.get("sessions", {}).get(actor.session_id)
    if not isinstance(session, Mapping):
        raise IamError("AUTHENTICATION_REQUIRED")
    user = tables.get("users", {}).get(actor.actor_id)
    if not isinstance(user, Mapping):
        raise IamError("AUTHENTICATION_REQUIRED")
    family_id = session.get("session_family_id")
    family = tables.get("session_families", {}).get(family_id)
    if not isinstance(family, Mapping):
        raise IamError("AUTHENTICATION_REQUIRED")

    memberships = [
        membership
        for key, membership in tables.get("memberships", {}).items()
        if isinstance(membership, Mapping)
        and membership.get("membership_id") == key
        and membership.get("organization_id") == organization_id
        and membership.get("user_id") == actor.actor_id
    ]
    if len(memberships) != 1:
        raise IamError("RESOURCE_NOT_FOUND")
    membership = memberships[0]
    grants = [
        grant
        for key, grant in tables.get("membership_role_grants", {}).items()
        if isinstance(grant, Mapping)
        and grant.get("membership_role_grant_id") == key
        and grant.get("membership_id") == membership.get("membership_id")
        and grant.get("organization_id") == organization_id
        and grant.get("user_id") == actor.actor_id
        and grant.get("role", grant.get("target_role"))
        == TargetRole.ORG_ADMIN.value
    ]
    if len(grants) != 1:
        raise IamError("RESOURCE_NOT_FOUND")
    return _require_exact_persisted_user_authority(
        actor=actor,
        organization_id=organization_id,
        now=now,
        user=user,
        family=family,
        session=session,
        membership=membership,
        role_grant=grants[0],
    )


def _require_exact_persisted_user_authority(
    *,
    actor: Any,
    organization_id: str,
    now: datetime,
    user: Any,
    family: Any,
    session: Any,
    membership: Any,
    role_grant: Any,
) -> _UserAuthority:
    if not all(isinstance(value, Mapping) for value in (user, family, session)):
        raise IamError("AUTHENTICATION_REQUIRED")
    if not all(isinstance(value, Mapping) for value in (membership, role_grant)):
        raise IamError("RESOURCE_NOT_FOUND")
    if (
        user.get("user_id") != actor.actor_id
        or session.get("session_id") != actor.session_id
        or session.get("user_id") != actor.actor_id
        or family.get("session_family_id")
        != session.get("session_family_id")
        or family.get("user_id") != actor.actor_id
    ):
        raise IamError("AUTHENTICATION_REQUIRED")
    if user.get("status") != "ACTIVE":
        raise IamError("AUTHENTICATION_REQUIRED")
    if session.get("status") != "ACTIVE" or family.get("status") != "ACTIVE":
        raise IamError("SESSION_EXPIRED")

    required_times = (
        session.get("auth_time"),
        session.get("created_at"),
        session.get("last_activity_at"),
        session.get("idle_expires_at"),
        session.get("absolute_expires_at"),
        session.get("updated_at"),
    )
    if not all(_is_utc_datetime(value) for value in required_times):
        raise IamError("SERVICE_UNAVAILABLE")
    auth_time, created_at, last_activity, idle_deadline, absolute_deadline, updated = (
        required_times
    )
    if (
        auth_time > now
        or auth_time > created_at
        or created_at > last_activity
        or last_activity >= idle_deadline
        or idle_deadline > absolute_deadline
        or last_activity > updated
        or updated < created_at
        or updated >= absolute_deadline
        or now >= idle_deadline
        or now >= absolute_deadline
    ):
        if now >= idle_deadline or now >= absolute_deadline:
            raise IamError("SESSION_EXPIRED")
        raise IamError("SERVICE_UNAVAILABLE")
    if (
        type(session.get("generation")) is not int
        or type(family.get("current_generation")) is not int
        or session.get("generation") != family.get("current_generation")
    ):
        raise IamError("SESSION_EXPIRED")
    acr_code = session.get("acr_code")
    amr_codes = session.get("amr_codes")
    if (
        not isinstance(acr_code, str)
        or not isinstance(amr_codes, tuple)
        or any(not isinstance(value, str) or not value for value in amr_codes)
    ):
        raise IamError("SERVICE_UNAVAILABLE")
    if (
        now - auth_time >= timedelta(minutes=10)
        or acr_code != "urn:desire:acr:mfa"
        or "otp" not in amr_codes
    ):
        raise IamError("MFA_STEP_UP_REQUIRED")
    if (
        membership.get("organization_id") != organization_id
        or membership.get("user_id") != actor.actor_id
        or membership.get("status") != "ACTIVE"
        or role_grant.get("membership_id")
        != membership.get("membership_id")
        or role_grant.get("organization_id") != organization_id
        or role_grant.get("user_id") != actor.actor_id
        or role_grant.get("role", role_grant.get("target_role"))
        != TargetRole.ORG_ADMIN.value
        or role_grant.get("revoked_at") is not None
    ):
        raise IamError("RESOURCE_NOT_FOUND")
    for row in (user, family, session, membership):
        if (
            type(row.get("aggregate_version")) is not int
            or row.get("aggregate_version") < 1
        ):
            raise IamError("SERVICE_UNAVAILABLE")
    role_grant_id = role_grant.get("membership_role_grant_id")
    if not isinstance(role_grant_id, str) or not role_grant_id:
        raise IamError("SERVICE_UNAVAILABLE")
    return _UserAuthority(
        strict_persisted=True,
        user_id=actor.actor_id,
        session_family_id=family["session_family_id"],
        session_id=session["session_id"],
        membership_id=membership["membership_id"],
        role_grant_id=role_grant_id,
        auth_time=auth_time,
        acr_code=acr_code,
        amr_codes=tuple(amr_codes),
        user_version=user["aggregate_version"],
        family_version=family["aggregate_version"],
        session_version=session["aggregate_version"],
        membership_version=membership["aggregate_version"],
    )


def _resolve_legacy_user_authority(
    tables: Mapping[str, Mapping[Any, Any]],
    *,
    actor: Any,
    organization_id: str,
    now: datetime,
) -> _UserAuthority:
    memberships = [
        membership
        for membership in tables.get("memberships", {}).values()
        if isinstance(membership, Mapping)
        and membership.get("organization_id") == organization_id
        and membership.get("user_id") == actor.actor_id
        and membership.get("status") == "ACTIVE"
    ]
    if len(memberships) != 1:
        raise IamError("RESOURCE_NOT_FOUND")
    membership = memberships[0]
    grants = [
        grant
        for grant in tables.get("membership_role_grants", {}).values()
        if isinstance(grant, Mapping)
        and grant.get("membership_id") == membership.get("membership_id")
        and grant.get("revoked_at") is None
        and grant.get("role", grant.get("target_role"))
        == TargetRole.ORG_ADMIN.value
    ]
    if len(grants) != 1:
        raise IamError("RESOURCE_NOT_FOUND")
    if (
        now - actor.auth_time >= timedelta(minutes=10)
        or actor.acr_code != "urn:desire:acr:mfa"
        or "otp" not in actor.amr_codes
    ):
        raise IamError("MFA_STEP_UP_REQUIRED")
    return _UserAuthority(
        strict_persisted=False,
        user_id=actor.actor_id,
        session_family_id=None,
        session_id=actor.session_id,
        membership_id=membership["membership_id"],
        role_grant_id=grants[0]["membership_role_grant_id"],
        auth_time=actor.auth_time,
        acr_code=actor.acr_code,
        amr_codes=tuple(actor.amr_codes),
        user_version=None,
        family_version=None,
        session_version=None,
        membership_version=membership.get("aggregate_version"),
    )


def _membership_has_active_admin_grant(
    tables: Mapping[str, Mapping[Any, Any]],
    *,
    membership: Mapping[str, Any],
    actor_id: str,
    organization_id: str,
) -> bool:
    membership_id = membership.get("membership_id")
    return any(
        isinstance(grant, Mapping)
        and grant.get("membership_id") == membership_id
        and grant.get("organization_id") in (None, organization_id)
        and grant.get("user_id") in (None, actor_id)
        and grant.get("revoked_at") is None
        and grant.get("role", grant.get("target_role")) == TargetRole.ORG_ADMIN.value
        for grant in tables.get("membership_role_grants", {}).values()
    )


def _require_current_hold_result(
    result: Any,
    *,
    target: _HoldTarget,
    policy_version: str,
    now: datetime,
) -> None:
    valid = (
        isinstance(result, SafetyHoldDecisionResult)
        and isinstance(result.decision, HoldDecision)
        and result.action == "IssueAccessInvitation"
        and result.target_type == target.target_type
        and result.target_id == target.target_id
        and result.target_version == target.target_version
        and result.organization_id == target.organization_id
        and result.policy_version == policy_version
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


def _safe_invitation(
    invitation: AccessInvitation,
    *,
    required_policy_bundle_id: str,
) -> Dict[str, Any]:
    return {
        "invitation_id": invitation.invitation_id,
        "purpose": invitation.purpose.value,
        "organization_id": invitation.organization_id,
        "target_role": invitation.target_role.value,
        "masked_recipient_label": invitation.masked_recipient_label,
        "is_initial_admin": invitation.is_initial_admin,
        "status": invitation.status.value,
        "expires_at": _timestamp(invitation.expires_at),
        "created_at": _timestamp(invitation.created_at),
        "required_policy_bundle_id": required_policy_bundle_id,
        "aggregate_version": invitation.aggregate_version,
        "entity_tag": '"v%d"' % invitation.aggregate_version,
    }


def _enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def _is_utc_datetime(value: Any) -> bool:
    return (
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() == timedelta(0)
    )


def _require_server_time(value: Any) -> None:
    if not _is_utc_datetime(value):
        raise IamError("SERVICE_UNAVAILABLE")


def _timestamp(value: datetime) -> str:
    _require_server_time(value)
    return value.isoformat().replace("+00:00", "Z")
