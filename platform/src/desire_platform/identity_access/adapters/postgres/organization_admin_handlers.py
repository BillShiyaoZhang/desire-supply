"""Presenter-ready ORG_ADMIN handlers backed only by fixed PostgreSQL UoWs."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import re
from typing import Any, Mapping, Optional, Protocol, Tuple
from uuid import UUID

from ...application.issue_access_invitations import (
    INVITATION_TOKEN_FORMAT_VERSION,
    InvitationIssuerContext,
    IssueAccessInvitationCommand,
    IssueAccessInvitationResult,
    IssuerKind,
    RecipientContactType,
)
from ...domain.authority_lifecycle import (
    LifecycleActorContext,
    LifecycleCommandResult,
    ResumeMembershipCommand,
    RevokeAccessInvitationCommand,
    RevokeMembershipCommand,
    SuspendMembershipCommand,
)
from ...domain.errors import IamError
from ...ports.access_invitation_capability import VerifiedAccessInvitationCapability
from ...ports.safety_hold import (
    HoldDecision,
    SafetyHoldDecisionResult,
    SafetyHoldUnavailableError,
)
from .organization_admin import (
    OrganizationAdminPostgresCommitOutcomeUnknownError,
    OrganizationAdminPostgresConfigurationError,
    OrganizationAdminPostgresDatabaseRequest,
    OrganizationAdminPostgresDatabaseResult,
    OrganizationAdminPostgresGeneratedIds,
    OrganizationAdminPostgresInvitationMaterial,
    OrganizationAdminPostgresIssueHoldEvidence,
    OrganizationAdminPostgresIssueResolution,
    OrganizationAdminPostgresOperation,
    OrganizationAdminPostgresReceiptMaterial,
    OrganizationAdminPostgresResumeHoldEvidence,
    OrganizationAdminPostgresResumeResolution,
    OrganizationAdminPostgresSafetyDecisionStaleError,
    OrganizationAdminPostgresScope,
    PsycopgOrganizationAdminUnitOfWorkFactory,
)


_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]{15,127}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{80,4096}$")
_CANONICALIZATION = "restricted-canonical-json-v1"
_RETAIN_FOR = timedelta(days=31)
_MFA_WINDOW = timedelta(minutes=10)
_MFA_ACR_CODES = frozenset(
    (
        "urn:desire:acr:mfa",
        "urn:desire:acr:synthetic-internal-sandbox:mfa",
    )
)
_MFA_AMR_CODES = frozenset(("hwk", "mfa", "otp", "webauthn"))
_RESUME_HOLD_POLICY_VERSION = "iam-membership-resume-hold-v1"
_ISSUE_HOLD_POLICY_VERSION = "iam-organization-invitation-issue-hold-v1"
_RESUME_HOLD_TTL = timedelta(minutes=1)
_ISSUE_HOLD_TTL = timedelta(minutes=1)
_RESUME_RESOLUTION_ATTEMPTS = 2
_ISSUE_RESOLUTION_ATTEMPTS = 2


class OrganizationAdminClock(Protocol):
    def now(self) -> datetime: ...


class OrganizationAdminIdSource(Protocol):
    def new_id(self, purpose: str) -> UUID: ...


class InternalSandboxMembershipResumeSafetyHold:
    """Purpose-closed synthetic ALLOW source used only by the local sandbox."""

    policy_version = _RESUME_HOLD_POLICY_VERSION

    def __init__(self, *, deployment_mode: str, clock: OrganizationAdminClock) -> None:
        if deployment_mode != "INTERNAL_SANDBOX" or not callable(
            getattr(clock, "now", None)
        ):
            raise ValueError("Membership resume hold is restricted to INTERNAL_SANDBOX")
        self._clock = clock
        self._closed = False

    def evaluate(self, **query: Any) -> SafetyHoldDecisionResult:
        if self._closed:
            raise SafetyHoldUnavailableError("membership resume hold is closed")
        if (
            query.get("action") != "ResumeMembership"
            or query.get("target_type") != "Membership"
            or query.get("policy_version") != self.policy_version
            or not isinstance(query.get("target_version"), int)
            or query["target_version"] < 1
        ):
            raise SafetyHoldUnavailableError("membership resume hold query is invalid")
        try:
            UUID(str(query["actor_id"]))
            UUID(str(query["target_id"]))
            UUID(str(query["organization_id"]))
        except (KeyError, TypeError, ValueError):
            raise SafetyHoldUnavailableError(
                "membership resume hold query is invalid"
            ) from None
        now = _utc(self._clock.now())
        return SafetyHoldDecisionResult(
            decision=HoldDecision.ALLOW,
            action="ResumeMembership",
            target_type="Membership",
            target_id=str(query["target_id"]),
            target_version=query["target_version"],
            organization_id=str(query["organization_id"]),
            policy_version=self.policy_version,
            evaluated_at=now,
            valid_until=now + _RESUME_HOLD_TTL,
        )

    def check_readiness(self, *, timeout_ms: int) -> None:
        if self._closed or not isinstance(timeout_ms, int) or timeout_ms < 1:
            raise RuntimeError("Membership resume hold is unavailable")

    def close(self) -> None:
        self._closed = True


class InternalSandboxOrganizationInvitationIssueSafetyHold:
    """Purpose-closed synthetic ALLOW source for organization invitations."""

    policy_version = _ISSUE_HOLD_POLICY_VERSION

    def __init__(self, *, deployment_mode: str, clock: OrganizationAdminClock) -> None:
        if deployment_mode != "INTERNAL_SANDBOX" or not callable(
            getattr(clock, "now", None)
        ):
            raise ValueError("Invitation issue hold is restricted to INTERNAL_SANDBOX")
        self._clock = clock
        self._closed = False

    def evaluate(self, **query: Any) -> SafetyHoldDecisionResult:
        if self._closed:
            raise SafetyHoldUnavailableError("invitation issue hold is closed")
        if (
            query.get("action") != "IssueAccessInvitation"
            or query.get("target_type") != "AccessInvitation"
            or query.get("policy_version") != self.policy_version
            or not isinstance(query.get("target_version"), int)
            or isinstance(query.get("target_version"), bool)
            or query["target_version"] != 1
            or query.get("target_id") == query.get("organization_id")
        ):
            raise SafetyHoldUnavailableError("invitation issue hold query is invalid")
        try:
            UUID(str(query["actor_id"]))
            UUID(str(query["target_id"]))
            UUID(str(query["organization_id"]))
        except (KeyError, TypeError, ValueError):
            raise SafetyHoldUnavailableError(
                "invitation issue hold query is invalid"
            ) from None
        now = _utc(self._clock.now())
        return SafetyHoldDecisionResult(
            decision=HoldDecision.ALLOW,
            action="IssueAccessInvitation",
            target_type="AccessInvitation",
            target_id=str(query["target_id"]),
            target_version=query["target_version"],
            organization_id=str(query["organization_id"]),
            policy_version=self.policy_version,
            evaluated_at=now,
            valid_until=now + _ISSUE_HOLD_TTL,
        )

    def check_readiness(self, *, timeout_ms: int) -> None:
        if self._closed or not isinstance(timeout_ms, int) or timeout_ms < 1:
            raise RuntimeError("Invitation issue hold is unavailable")

    def close(self) -> None:
        self._closed = True


@dataclass(frozen=True, repr=False)
class OrganizationAdminKeys:
    idempotency_key: bytes | bytearray = field(repr=False)
    payload_hash_key: bytes | bytearray = field(repr=False)
    invitation_token_keys: Tuple[Tuple[str, bytes | bytearray], ...] = field(
        repr=False
    )
    active_invitation_token_key_id: str
    idempotency_key_id: str = "iam-receipt-idempotency-hmac-2026-01"
    payload_hash_key_id: str = "iam-receipt-payload-hmac-2026-01"
    idempotency_keyring: Tuple[Tuple[str, bytes | bytearray], ...] = field(
        default=(), repr=False
    )
    payload_hash_keyring: Tuple[Tuple[str, bytes | bytearray], ...] = field(
        default=(), repr=False
    )

    def __post_init__(self) -> None:
        materials = (self.idempotency_key, self.payload_hash_key)
        if any(
            not isinstance(value, (bytes, bytearray))
            or len(value) < 32
            or not any(value)
            for value in materials
        ):
            raise ValueError("organization administration receipt keys are unavailable")
        if hmac.compare_digest(*materials):
            raise ValueError("organization administration receipt keys must not alias")
        idempotency_registry = self.idempotency_keyring or (
            (self.idempotency_key_id, self.idempotency_key),
        )
        payload_registry = self.payload_hash_keyring or (
            (self.payload_hash_key_id, self.payload_hash_key),
        )
        for label, registry, active_id, active_material in (
            (
                "idempotency",
                idempotency_registry,
                self.idempotency_key_id,
                self.idempotency_key,
            ),
            (
                "payload",
                payload_registry,
                self.payload_hash_key_id,
                self.payload_hash_key,
            ),
        ):
            if (
                not 1 <= len(registry) <= 4
                or registry[0][0] != active_id
                or not hmac.compare_digest(bytes(registry[0][1]), bytes(active_material))
                or len({key_id for key_id, _material in registry}) != len(registry)
                or any(
                    _KEY_ID.fullmatch(key_id) is None
                    or not isinstance(material, (bytes, bytearray))
                    or len(material) < 32
                    or not any(material)
                    for key_id, material in registry
                )
            ):
                raise ValueError(
                    f"organization administration {label} keyring is invalid"
                )
        if any(
            hmac.compare_digest(bytes(left), bytes(right))
            for _left_id, left in idempotency_registry
            for _right_id, right in payload_registry
        ):
            raise ValueError("organization administration receipt purposes must not alias")
        registry = dict(self.invitation_token_keys)
        if (
            not 1 <= len(registry) <= 4
            or len(registry) != len(self.invitation_token_keys)
            or self.active_invitation_token_key_id not in registry
            or self.invitation_token_keys[0][0]
            != self.active_invitation_token_key_id
            or any(
                _KEY_ID.fullmatch(key_id) is None
                or not isinstance(material, (bytes, bytearray))
                or len(material) < 32
                or not any(material)
                for key_id, material in registry.items()
            )
            or any(_KEY_ID.fullmatch(value) is None for value in (self.idempotency_key_id, self.payload_hash_key_id))
        ):
            raise ValueError("organization invitation token registry is invalid")
        object.__setattr__(self, "idempotency_keyring", idempotency_registry)
        object.__setattr__(self, "payload_hash_keyring", payload_registry)


class HmacOrganizationInvitationTokenCodec:
    """Deterministic v1 capability codec with explicit retained-key routing."""

    format_version = INVITATION_TOKEN_FORMAT_VERSION

    def __init__(self, *, keys: OrganizationAdminKeys) -> None:
        if not isinstance(keys, OrganizationAdminKeys):
            raise TypeError("organization invitation token keys are unavailable")
        self._keys = dict(keys.invitation_token_keys)
        self.key_id = keys.active_invitation_token_key_id

    def issue(
        self,
        *,
        invitation_id: str,
        nonce: bytes,
        expires_at: datetime,
        token_key_id: str,
        token_format_version: str = INVITATION_TOKEN_FORMAT_VERSION,
    ) -> str:
        invitation = _uuid(invitation_id, "invitation")
        if not isinstance(nonce, bytes) or len(nonce) != 32:
            raise ValueError("organization invitation nonce is invalid")
        expires = _utc(expires_at)
        if token_format_version != self.format_version:
            raise ValueError("organization invitation token format is unavailable")
        key = self._keys.get(token_key_id)
        if key is None:
            raise LookupError("organization invitation token key is unavailable")
        payload = {
            "e": expires.isoformat().replace("+00:00", "Z"),
            "f": token_format_version,
            "i": str(invitation),
            "k": token_key_id,
            "n": nonce.hex(),
        }
        body = _canonical(payload)
        signature = hmac.new(key, b"desire:iam:invitation-token:v1\x00" + body, hashlib.sha256).digest()
        return _b64(body + signature)

    def verify(
        self, *, access_invitation_token: str, now: datetime
    ) -> VerifiedAccessInvitationCapability:
        current = _utc(now)
        if not isinstance(access_invitation_token, str) or _TOKEN.fullmatch(access_invitation_token) is None:
            raise ValueError("organization invitation token is invalid")
        try:
            sealed = _unb64(access_invitation_token)
            body, signature = sealed[:-32], sealed[-32:]
            payload = json.loads(body.decode("utf-8"))
            if not isinstance(payload, dict) or set(payload) != {"e", "f", "i", "k", "n"} or _canonical(payload) != body:
                raise ValueError
            key = self._keys[payload["k"]]
            expected = hmac.new(key, b"desire:iam:invitation-token:v1\x00" + body, hashlib.sha256).digest()
            if not hmac.compare_digest(expected, signature):
                raise ValueError
            invitation = _uuid(payload["i"], "invitation")
            nonce = bytes.fromhex(payload["n"])
            expires = datetime.fromisoformat(payload["e"].replace("Z", "+00:00"))
            if len(nonce) != 32 or payload["f"] != self.format_version or expires <= current:
                raise ValueError
        except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError):
            raise ValueError("organization invitation token is invalid") from None
        return VerifiedAccessInvitationCapability(
            invitation_id=str(invitation),
            invitation_nonce=nonce.hex(),
            expires_at=expires,
            token_key_id=payload["k"],
            token_format_version=payload["f"],
        )


class PostgresIssueOrganizationAccessInvitationHandler:
    def __init__(
        self,
        *,
        uow_factory: PsycopgOrganizationAdminUnitOfWorkFactory,
        target_resolver: Any,
        safety_hold: Any,
        safety_hold_policy_version: str,
        recipient_binding: Any,
        token_codec: HmacOrganizationInvitationTokenCodec,
        keys: OrganizationAdminKeys,
        clock: OrganizationAdminClock,
        id_source: OrganizationAdminIdSource,
        secret_source: Any,
    ) -> None:
        if not isinstance(uow_factory, PsycopgOrganizationAdminUnitOfWorkFactory):
            raise TypeError("organization administration PostgreSQL UoW is unavailable")
        if not callable(getattr(target_resolver, "resolve_issue", None)):
            raise TypeError("organization invitation issue resolver is unavailable")
        if not callable(getattr(safety_hold, "evaluate", None)):
            raise TypeError("organization invitation issue SafetyHold is unavailable")
        if safety_hold_policy_version != _ISSUE_HOLD_POLICY_VERSION:
            raise ValueError("organization invitation issue SafetyHold policy is unavailable")
        if not callable(getattr(recipient_binding, "bind_verified", None)):
            raise TypeError("organization invitation recipient binding is unavailable")
        if not isinstance(token_codec, HmacOrganizationInvitationTokenCodec):
            raise TypeError("organization invitation token codec is unavailable")
        if not isinstance(keys, OrganizationAdminKeys):
            raise TypeError("organization administration keys are unavailable")
        if any(not callable(getattr(owner, method, None)) for owner, method in ((clock, "now"), (id_source, "new_id"), (secret_source, "token_bytes"))):
            raise TypeError("organization administration runtime sources are unavailable")
        self._uow_factory = uow_factory
        self._resolver = target_resolver
        self._safety_hold = safety_hold
        self._safety_hold_policy_version = safety_hold_policy_version
        self._recipient_binding = recipient_binding
        self._token_codec = token_codec
        self._keys = keys
        self._clock = clock
        self._ids = id_source
        self._secrets = secret_source

    def handle(
        self,
        *,
        actor: InvitationIssuerContext,
        command: IssueAccessInvitationCommand,
    ) -> IssueAccessInvitationResult:
        now = _utc(self._clock.now())
        if (
            not isinstance(actor, InvitationIssuerContext)
            or actor.actor_kind is not IssuerKind.USER
            or not isinstance(command, IssueAccessInvitationCommand)
            or command.organization_id is None
            or command.expected_organization_version is None
            or command.recipient.type is not RecipientContactType.EMAIL
            or command.target_role.value not in {"ORG_ADMIN", "DEMAND_OWNER"}
            or not command.recipient.value.strip()
            or command.expires_at <= now
            or command.expires_at > now + timedelta(days=30)
        ):
            raise IamError("INVALID_REQUEST")
        _require_recent_mfa(actor, now)
        if not isinstance(command.idempotency_key, str) or _IDEMPOTENCY_KEY.fullmatch(command.idempotency_key) is None:
            raise IamError("INVALID_REQUEST")
        bind_candidates = getattr(
            self._recipient_binding, "bind_verified_candidates", None
        )
        if callable(bind_candidates):
            bindings = bind_candidates(
                contact_type="EMAIL", verified_locator=command.recipient.value
            )
        else:
            bindings = (
                self._recipient_binding.bind_verified(
                    contact_type="EMAIL", verified_locator=command.recipient.value
                ),
            )
        if (
            not isinstance(bindings, tuple)
            or not 1 <= len(bindings) <= 4
            or len({item.digest_key_id for item in bindings}) != len(bindings)
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        binding = bindings[0]
        binding_digest = bytes.fromhex(binding.binding_digest)
        payload = {
            "organization_id": command.organization_id,
            "recipient_binding_digest": binding.binding_digest,
            "target_role": command.target_role.value,
            "expires_at": _timestamp(command.expires_at),
        }
        candidate_payloads = tuple(
            (
                key_id,
                {
                    **payload,
                    "recipient_binding_digest": candidate.binding_digest,
                },
            )
            for candidate in bindings
            for key_id, _material in self._keys.payload_hash_keyring
        )
        receipt_candidates = _receipt_digest_candidates(
            operation=OrganizationAdminPostgresOperation.ISSUE_ACCESS_INVITATION,
            organization_id=command.organization_id,
            target_id=command.organization_id,
            expected_version=command.expected_organization_version,
            idempotency_key=command.idempotency_key,
            payload=payload,
            candidate_payloads=candidate_payloads,
            keys=self._keys,
        )
        invitation_id: Optional[UUID] = None
        contact_id: Optional[UUID] = None
        invitation_material: Optional[
            OrganizationAdminPostgresInvitationMaterial
        ] = None
        for attempt in range(_ISSUE_RESOLUTION_ATTEMPTS):
            resolution = self._resolver.resolve_issue(
                actor_user_id=actor.actor_id,
                session_id=actor.session_id,
                organization_id=command.organization_id,
                target_role=command.target_role.value,
                idempotency_candidates=receipt_candidates[0],
                payload_hash_candidates=receipt_candidates[1],
            )
            if not isinstance(resolution, OrganizationAdminPostgresIssueResolution):
                raise IamError("SERVICE_UNAVAILABLE")
            if resolution.replayed:
                replay = OrganizationAdminPostgresDatabaseResult(
                    operation=(
                        OrganizationAdminPostgresOperation.ISSUE_ACCESS_INVITATION
                    ),
                    replayed=True,
                    safe_response=dict(resolution.safe_response or {}),
                    response_entity_tag=resolution.response_entity_tag or "",
                    capability_reconstruction=dict(
                        resolution.capability_reconstruction or {}
                    ),
                )
                try:
                    self._uow_factory.response_validator.validate(
                        replay.safe_response, "AccessInvitationAdminDto"
                    )
                except BaseException:
                    raise IamError("SERVICE_UNAVAILABLE") from None
                return self._render_result(replay)
            if resolution.target_version != command.expected_organization_version:
                raise IamError("PRECONDITION_FAILED")
            if invitation_material is None:
                invitation_id = _new(self._ids, "access_invitation")
                contact_id = _new(self._ids, "contact_point")
                nonce = self._secrets.token_bytes(
                    "access-invitation-nonce", 32
                )
                if not isinstance(nonce, bytes) or len(nonce) != 32:
                    raise IamError("SERVICE_UNAVAILABLE")
                invitation_material = OrganizationAdminPostgresInvitationMaterial(
                    recipient_contact_id=contact_id,
                    recipient_binding_digest=binding_digest,
                    recipient_binding_digest_key_id=binding.digest_key_id,
                    masked_recipient_label=_mask_email(command.recipient.value),
                    target_role=command.target_role.value,
                    expires_at=command.expires_at,
                    token_nonce=nonce,
                    token_key_id=self._token_codec.key_id,
                    token_format_version=INVITATION_TOKEN_FORMAT_VERSION,
                )
            evidence, validation_now = self._evaluate_issue_hold(
                actor=actor,
                resolution=resolution,
                invitation_id=invitation_id,
            )
            if invitation_id is None or contact_id is None:
                raise IamError("SERVICE_UNAVAILABLE")
            request = _request(
                operation=OrganizationAdminPostgresOperation.ISSUE_ACCESS_INVITATION,
                actor_user_id=actor.actor_id,
                session_id=actor.session_id,
                organization_id=command.organization_id,
                target_id=str(invitation_id),
                command_id=_new(self._ids, "command_receipt"),
                correlation_id=actor.correlation_id,
                trace_id=actor.trace_id,
                original_actor_id=actor.original_actor_id,
                expected_version=command.expected_organization_version,
                idempotency_key=command.idempotency_key,
                payload=payload,
                candidate_payloads=candidate_payloads,
                keys=self._keys,
                now=validation_now,
                ids=self._ids,
                invitation=invitation_material,
                issue_hold=evidence,
                resume_hold=None,
                reason_code=None,
                recipient_contact_id=contact_id,
            )
            try:
                result = self._uow_factory.execute_issue_access_invitation(request)
            except OrganizationAdminPostgresSafetyDecisionStaleError:
                if attempt + 1 < _ISSUE_RESOLUTION_ATTEMPTS:
                    continue
                raise IamError("PRECONDITION_FAILED") from None
            except OrganizationAdminPostgresCommitOutcomeUnknownError:
                raise IamError("COMMAND_OUTCOME_UNKNOWN") from None
            except OrganizationAdminPostgresConfigurationError:
                raise IamError("SERVICE_UNAVAILABLE") from None
            break
        else:
            raise IamError("PRECONDITION_FAILED")
        return self._render_result(result)

    def _render_result(
        self, result: OrganizationAdminPostgresDatabaseResult
    ) -> IssueAccessInvitationResult:
        safe = dict(result.safe_response)
        # This private database result is distinct from safe_response and has
        # already been excluded from DTO validation, receipts and public JSON.
        token_facts = result.capability_reconstruction
        if not isinstance(token_facts, Mapping):
            raise IamError("SERVICE_UNAVAILABLE")
        token = self._token_codec.issue(
            invitation_id=safe["invitation_id"],
            nonce=bytes.fromhex(token_facts["nonce"]),
            expires_at=datetime.fromisoformat(token_facts["expires_at"].replace("Z", "+00:00")),
            token_key_id=token_facts["token_key_id"],
            token_format_version=token_facts["token_format_version"],
        )
        return IssueAccessInvitationResult(
            replayed=result.replayed,
            invitation=safe,
            access_invitation_token=token,
            join_fragment_url=f"/join#access_invitation_token={token}",
        )

    def _evaluate_issue_hold(
        self,
        *,
        actor: InvitationIssuerContext,
        resolution: OrganizationAdminPostgresIssueResolution,
        invitation_id: UUID,
    ) -> tuple[OrganizationAdminPostgresIssueHoldEvidence, datetime]:
        query = {
            "actor_id": actor.actor_id,
            "action": "IssueAccessInvitation",
            "target_type": "AccessInvitation",
            "target_id": str(invitation_id),
            "target_version": 1,
            "organization_id": str(resolution.organization_id),
            "policy_version": self._safety_hold_policy_version,
        }
        try:
            result = self._safety_hold.evaluate(**query)
        except BaseException:
            raise IamError("SAFETY_DECISION_UNAVAILABLE") from None
        if not isinstance(result, SafetyHoldDecisionResult):
            raise IamError("SAFETY_DECISION_UNAVAILABLE")
        if (
            result.action != query["action"]
            or result.target_type != query["target_type"]
            or result.target_id != query["target_id"]
            or result.target_version != query["target_version"]
            or result.organization_id != query["organization_id"]
            or result.policy_version != query["policy_version"]
            or not isinstance(result.evaluated_at, datetime)
            or not isinstance(result.valid_until, datetime)
        ):
            raise IamError("SAFETY_DECISION_UNAVAILABLE")
        try:
            evaluated_at = _utc(result.evaluated_at)
            valid_until = _utc(result.valid_until)
            validation_now = _utc(self._clock.now())
        except IamError:
            raise IamError("SAFETY_DECISION_UNAVAILABLE") from None
        if evaluated_at > validation_now or validation_now >= valid_until:
            raise IamError("SAFETY_DECISION_UNAVAILABLE")
        if result.decision is HoldDecision.BLOCK:
            raise IamError("SAFETY_HOLD_BLOCKED")
        if result.decision is not HoldDecision.ALLOW:
            raise IamError("SAFETY_DECISION_UNAVAILABLE")
        return OrganizationAdminPostgresIssueHoldEvidence(
            action=result.action,
            target_type=result.target_type,
            target_id=invitation_id,
            target_version=result.target_version,
            organization_id=resolution.organization_id,
            policy_version=result.policy_version,
            evaluated_at=evaluated_at,
            valid_until=valid_until,
            snapshot_digest=resolution.snapshot_digest,
        ), validation_now


class _PostgresOrganizationLifecycleHandler:
    operation: OrganizationAdminPostgresOperation
    command_type: type

    def __init__(
        self,
        *,
        uow_factory: PsycopgOrganizationAdminUnitOfWorkFactory,
        target_resolver: Any,
        keys: OrganizationAdminKeys,
        clock: OrganizationAdminClock,
        id_source: OrganizationAdminIdSource,
    ) -> None:
        if not isinstance(uow_factory, PsycopgOrganizationAdminUnitOfWorkFactory):
            raise TypeError("organization administration PostgreSQL UoW is unavailable")
        if not callable(getattr(target_resolver, "resolve", None)):
            raise TypeError("organization administration target resolver is unavailable")
        self._uow_factory = uow_factory
        self._resolver = target_resolver
        self._keys = keys
        self._clock = clock
        self._ids = id_source

    def handle(self, *, actor: LifecycleActorContext, command: Any) -> LifecycleCommandResult:
        if not isinstance(actor, LifecycleActorContext) or not isinstance(
            command, self.command_type
        ):
            raise IamError("INVALID_REQUEST")
        now = _utc(self._clock.now())
        target_id = _lifecycle_target(command)
        organization_id = self._resolver.resolve(
            actor_user_id=actor.actor_user_id,
            session_id=actor.current_session_id,
            target_id=target_id,
            operation=self.operation.value,
        )
        command_id = _new(self._ids, "command_receipt")
        payload_candidates = _reason_payload_candidates(self._keys, command.reason)
        payload = payload_candidates[0][1]
        request = _request(
            operation=self.operation,
            actor_user_id=actor.actor_user_id,
            session_id=actor.current_session_id,
            organization_id=organization_id,
            target_id=target_id,
            command_id=command_id,
            correlation_id=actor.correlation_id,
            trace_id=actor.trace_id,
            original_actor_id=actor.original_actor_id,
            expected_version=command.expected_version,
            idempotency_key=command.idempotency_key,
            payload=payload,
            candidate_payloads=payload_candidates,
            keys=self._keys,
            now=now,
            ids=self._ids,
            invitation=None,
            resume_hold=None,
            reason_code=command.reason.reason_code,
            recipient_contact_id=None,
        )
        executor = {
            OrganizationAdminPostgresOperation.REVOKE_ACCESS_INVITATION: self._uow_factory.execute_revoke_access_invitation,
            OrganizationAdminPostgresOperation.SUSPEND_MEMBERSHIP: self._uow_factory.execute_suspend_membership,
            OrganizationAdminPostgresOperation.RESUME_MEMBERSHIP: self._uow_factory.execute_resume_membership,
            OrganizationAdminPostgresOperation.REVOKE_MEMBERSHIP: self._uow_factory.execute_revoke_membership,
        }[self.operation]
        try:
            result = executor(request)
        except OrganizationAdminPostgresCommitOutcomeUnknownError:
            raise IamError("COMMAND_OUTCOME_UNKNOWN") from None
        except OrganizationAdminPostgresConfigurationError:
            raise IamError("SERVICE_UNAVAILABLE") from None
        return LifecycleCommandResult(result.replayed, 200, result.safe_response)


class PostgresRevokeAccessInvitationHandler(_PostgresOrganizationLifecycleHandler):
    operation = OrganizationAdminPostgresOperation.REVOKE_ACCESS_INVITATION
    command_type = RevokeAccessInvitationCommand


class PostgresSuspendMembershipHandler(_PostgresOrganizationLifecycleHandler):
    operation = OrganizationAdminPostgresOperation.SUSPEND_MEMBERSHIP
    command_type = SuspendMembershipCommand


class PostgresResumeMembershipHandler(_PostgresOrganizationLifecycleHandler):
    operation = OrganizationAdminPostgresOperation.RESUME_MEMBERSHIP

    def __init__(
        self,
        *,
        uow_factory: PsycopgOrganizationAdminUnitOfWorkFactory,
        target_resolver: Any,
        safety_hold: Any,
        safety_hold_policy_version: str,
        keys: OrganizationAdminKeys,
        clock: OrganizationAdminClock,
        id_source: OrganizationAdminIdSource,
    ) -> None:
        super().__init__(
            uow_factory=uow_factory,
            target_resolver=target_resolver,
            keys=keys,
            clock=clock,
            id_source=id_source,
        )
        if not callable(getattr(target_resolver, "resolve_resume", None)):
            raise TypeError("organization resume resolver is unavailable")
        if not callable(getattr(safety_hold, "evaluate", None)):
            raise TypeError("organization resume SafetyHold is unavailable")
        if safety_hold_policy_version != _RESUME_HOLD_POLICY_VERSION:
            raise ValueError("organization resume SafetyHold policy is unavailable")
        self._safety_hold = safety_hold
        self._safety_hold_policy_version = safety_hold_policy_version

    def handle(
        self, *, actor: LifecycleActorContext, command: Any
    ) -> LifecycleCommandResult:
        if not isinstance(command, ResumeMembershipCommand):
            raise IamError("INVALID_REQUEST")
        now = _utc(self._clock.now())
        target_id = _lifecycle_target(command)
        payload_candidates = _reason_payload_candidates(self._keys, command.reason)
        payload = payload_candidates[0][1]
        receipt_candidates = _receipt_digest_candidates(
            operation=self.operation,
            organization_id=None,
            target_id=target_id,
            expected_version=command.expected_version,
            idempotency_key=command.idempotency_key,
            payload=payload,
            candidate_payloads=payload_candidates,
            keys=self._keys,
        )
        idempotency_digest = receipt_candidates[0][0][1]
        payload_hash = receipt_candidates[1][0][1]
        for attempt in range(_RESUME_RESOLUTION_ATTEMPTS):
            now = _utc(self._clock.now())
            resolution = self._resolver.resolve_resume(
                actor_user_id=actor.actor_user_id,
                session_id=actor.current_session_id,
                target_id=target_id,
                idempotency_key_digest=idempotency_digest,
                idempotency_key_digest_key_id=self._keys.idempotency_key_id,
                payload_hash=payload_hash,
                payload_hash_key_id=self._keys.payload_hash_key_id,
                idempotency_candidates=receipt_candidates[0],
                payload_hash_candidates=receipt_candidates[1],
            )
            if not isinstance(
                resolution, OrganizationAdminPostgresResumeResolution
            ):
                raise IamError("SERVICE_UNAVAILABLE")
            evidence = None
            if not resolution.replayed:
                if resolution.target_version != command.expected_version:
                    raise IamError("PRECONDITION_FAILED")
                evidence, now = self._evaluate_resume_hold(
                    actor=actor,
                    target_id=target_id,
                    resolution=resolution,
                )
            request = _request(
                operation=self.operation,
                actor_user_id=actor.actor_user_id,
                session_id=actor.current_session_id,
                organization_id=str(resolution.organization_id),
                target_id=target_id,
                command_id=_new(self._ids, "command_receipt"),
                correlation_id=actor.correlation_id,
                trace_id=actor.trace_id,
                original_actor_id=actor.original_actor_id,
                expected_version=command.expected_version,
                idempotency_key=command.idempotency_key,
                payload=payload,
                candidate_payloads=payload_candidates,
                keys=self._keys,
                now=now,
                ids=self._ids,
                invitation=None,
                resume_hold=evidence,
                reason_code=command.reason.reason_code,
                recipient_contact_id=None,
            )
            try:
                result = self._uow_factory.execute_resume_membership(request)
            except OrganizationAdminPostgresSafetyDecisionStaleError:
                if attempt + 1 < _RESUME_RESOLUTION_ATTEMPTS:
                    continue
                raise IamError("PRECONDITION_FAILED") from None
            except OrganizationAdminPostgresCommitOutcomeUnknownError:
                raise IamError("COMMAND_OUTCOME_UNKNOWN") from None
            except OrganizationAdminPostgresConfigurationError:
                raise IamError("SERVICE_UNAVAILABLE") from None
            return LifecycleCommandResult(result.replayed, 200, result.safe_response)
        raise IamError("PRECONDITION_FAILED")

    def _evaluate_resume_hold(
        self,
        *,
        actor: LifecycleActorContext,
        target_id: str,
        resolution: OrganizationAdminPostgresResumeResolution,
    ) -> tuple[OrganizationAdminPostgresResumeHoldEvidence, datetime]:
        query = {
            "actor_id": actor.actor_user_id,
            "action": "ResumeMembership",
            "target_type": "Membership",
            "target_id": target_id,
            "target_version": resolution.target_version,
            "organization_id": str(resolution.organization_id),
            "policy_version": self._safety_hold_policy_version,
        }
        try:
            result = self._safety_hold.evaluate(**query)
        except (SafetyHoldUnavailableError, IamError):
            raise IamError("SAFETY_DECISION_UNAVAILABLE") from None
        except BaseException:
            raise IamError("SAFETY_DECISION_UNAVAILABLE") from None
        if not isinstance(result, SafetyHoldDecisionResult):
            raise IamError("SAFETY_DECISION_UNAVAILABLE")
        if (
            result.action != query["action"]
            or result.target_type != query["target_type"]
            or result.target_id != query["target_id"]
            or result.target_version != query["target_version"]
            or result.organization_id != query["organization_id"]
            or result.policy_version != query["policy_version"]
            or not isinstance(result.evaluated_at, datetime)
            or not isinstance(result.valid_until, datetime)
        ):
            raise IamError("SAFETY_DECISION_UNAVAILABLE")
        try:
            evaluated_at = _utc(result.evaluated_at)
            valid_until = _utc(result.valid_until)
            validation_now = _utc(self._clock.now())
        except IamError:
            raise IamError("SAFETY_DECISION_UNAVAILABLE") from None
        if evaluated_at > validation_now or validation_now >= valid_until:
            raise IamError("SAFETY_DECISION_UNAVAILABLE")
        if result.decision is HoldDecision.BLOCK:
            raise IamError("SAFETY_HOLD_BLOCKED")
        if result.decision is not HoldDecision.ALLOW:
            raise IamError("SAFETY_DECISION_UNAVAILABLE")
        return OrganizationAdminPostgresResumeHoldEvidence(
            action=result.action,
            target_type=result.target_type,
            target_id=_uuid(result.target_id, "resume hold target"),
            target_version=result.target_version,
            organization_id=_uuid(
                result.organization_id, "resume hold organization"
            ),
            policy_version=result.policy_version,
            evaluated_at=evaluated_at,
            valid_until=valid_until,
            snapshot_digest=resolution.snapshot_digest,
        ), validation_now


class PostgresRevokeMembershipHandler(_PostgresOrganizationLifecycleHandler):
    operation = OrganizationAdminPostgresOperation.REVOKE_MEMBERSHIP
    command_type = RevokeMembershipCommand


def _request(
    *,
    operation: OrganizationAdminPostgresOperation,
    actor_user_id: str,
    session_id: Optional[str],
    organization_id: str,
    target_id: str,
    command_id: UUID,
    correlation_id: str,
    trace_id: str,
    original_actor_id: Optional[str],
    expected_version: int,
    idempotency_key: str,
    payload: Mapping[str, Any],
    candidate_payloads: Optional[Tuple[Tuple[str, Mapping[str, Any]], ...]] = None,
    keys: OrganizationAdminKeys,
    now: datetime,
    ids: OrganizationAdminIdSource,
    invitation: Optional[OrganizationAdminPostgresInvitationMaterial],
    issue_hold: Optional[OrganizationAdminPostgresIssueHoldEvidence] = None,
    resume_hold: Optional[OrganizationAdminPostgresResumeHoldEvidence],
    reason_code: Optional[str],
    recipient_contact_id: Optional[UUID],
    public_name: Optional[str] = None,
) -> OrganizationAdminPostgresDatabaseRequest:
    if session_id is None or _IDEMPOTENCY_KEY.fullmatch(idempotency_key) is None:
        raise IamError("INVALID_REQUEST")
    identity_candidates, payload_candidates = _receipt_digest_candidates(
        operation=operation,
        organization_id=organization_id,
        target_id=target_id,
        expected_version=expected_version,
        idempotency_key=idempotency_key,
        payload=payload,
        candidate_payloads=candidate_payloads,
        keys=keys,
    )
    identity = identity_candidates[0][1]
    payload_hash = payload_candidates[0][1]
    return OrganizationAdminPostgresDatabaseRequest(
        operation=operation,
        scope=OrganizationAdminPostgresScope(
            actor_user_id=_uuid(actor_user_id, "actor"),
            current_session_id=_uuid(session_id, "session"),
            organization_id=_uuid(organization_id, "organization"),
            target_id=_uuid(target_id, "target"),
            command_id=command_id,
            correlation_id=_uuid(correlation_id, "correlation"),
            causation_id=command_id,
            trace_id=_uuid(trace_id, "trace"),
            original_actor_id=(
                _uuid(original_actor_id, "original actor") if original_actor_id else None
            ),
        ),
        receipt=OrganizationAdminPostgresReceiptMaterial(
            receipt_id=command_id,
            idempotency_key_digest=identity,
            idempotency_key_digest_key_id=keys.idempotency_key_id,
            payload_hash=payload_hash,
            payload_hash_key_id=keys.payload_hash_key_id,
            retain_until=now + _RETAIN_FOR,
            idempotency_candidates=identity_candidates,
            payload_hash_candidates=payload_candidates,
        ),
        expected_version=expected_version,
        generated_ids=OrganizationAdminPostgresGeneratedIds(
            audit_event_id=_new(ids, "audit_event"),
            outbox_event_id=_new(ids, "outbox_event"),
            recipient_contact_id=recipient_contact_id,
            secondary_outbox_event_id=(
                _new(ids, "membership_roles_revoked_outbox_event")
                if operation
                is OrganizationAdminPostgresOperation.REVOKE_MEMBERSHIP
                else None
            ),
        ),
        invitation=invitation,
        issue_hold=issue_hold,
        resume_hold=resume_hold,
        reason_code=reason_code,
        public_name=public_name,
    )


def _receipt_digests(
    *,
    operation: OrganizationAdminPostgresOperation,
    organization_id: Optional[str],
    target_id: str,
    expected_version: int,
    idempotency_key: str,
    payload: Mapping[str, Any],
    keys: OrganizationAdminKeys,
) -> tuple[bytes, bytes]:
    identities, payloads = _receipt_digest_candidates(
        operation=operation,
        organization_id=organization_id,
        target_id=target_id,
        expected_version=expected_version,
        idempotency_key=idempotency_key,
        payload=payload,
        candidate_payloads=None,
        keys=keys,
    )
    return identities[0][1], payloads[0][1]


def _receipt_digest_candidates(
    *,
    operation: OrganizationAdminPostgresOperation,
    organization_id: Optional[str],
    target_id: str,
    expected_version: int,
    idempotency_key: str,
    payload: Mapping[str, Any],
    candidate_payloads: Optional[Tuple[Tuple[str, Mapping[str, Any]], ...]],
    keys: OrganizationAdminKeys,
) -> tuple[Tuple[Tuple[str, bytes], ...], Tuple[Tuple[str, bytes], ...]]:
    if (
        not isinstance(operation, OrganizationAdminPostgresOperation)
        or not isinstance(idempotency_key, str)
        or _IDEMPOTENCY_KEY.fullmatch(idempotency_key) is None
    ):
        raise IamError("INVALID_REQUEST")
    identities = tuple(
        (
            key_id,
            hmac.new(
                material,
                b"desire:iam:org-admin:idempotency:v1\x00"
                + idempotency_key.encode("utf-8"),
                hashlib.sha256,
            ).digest(),
        )
        for key_id, material in keys.idempotency_keyring
    )
    material_by_key = dict(keys.payload_hash_keyring)
    payload_inputs = (
        candidate_payloads
        if candidate_payloads is not None
        else tuple((key_id, payload) for key_id in material_by_key)
    )
    if (
        not 1 <= len(payload_inputs) <= 16
        or payload_inputs[0][0] != keys.payload_hash_key_id
        or {key_id for key_id, _candidate in payload_inputs}
        != set(material_by_key)
        or any(
            key_id not in material_by_key or not isinstance(candidate, Mapping)
            for key_id, candidate in payload_inputs
        )
    ):
        raise IamError("SERVICE_UNAVAILABLE")
    payloads = tuple(
        (
            key_id,
            hmac.new(
                material_by_key[key_id],
                b"desire:iam:org-admin:payload:v1\x00"
                + _canonical(
                    {
                        "operation": operation.value,
                        "organization_id": (
                            organization_id
                            if operation
                            is OrganizationAdminPostgresOperation.ISSUE_ACCESS_INVITATION
                            else None
                        ),
                        "target_id": (
                            None
                            if operation
                            is OrganizationAdminPostgresOperation.ISSUE_ACCESS_INVITATION
                            else target_id
                        ),
                        "expected_version": expected_version,
                        "payload": candidate,
                    }
                ),
                hashlib.sha256,
            ).digest(),
        )
        for key_id, candidate in payload_inputs
    )
    if len(set(payloads)) != len(payloads):
        raise IamError("SERVICE_UNAVAILABLE")
    return identities, payloads


def _reason_payload(keys: OrganizationAdminKeys, reason: Any) -> Mapping[str, Any]:
    return _reason_payload_candidates(keys, reason)[0][1]


def _reason_payload_candidates(
    keys: OrganizationAdminKeys, reason: Any
) -> Tuple[Tuple[str, Mapping[str, Any]], ...]:
    code = getattr(reason, "reason_code", None)
    note = getattr(reason, "reason_note", None)
    if not isinstance(code, str) or re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", code) is None:
        raise IamError("INVALID_REQUEST")
    if note is not None and (
        not isinstance(note, str) or len(note) > 2_000
    ):
        raise IamError("INVALID_REQUEST")
    return tuple(
        (
            key_id,
            {
                "reason_code": code,
                "reason_note_digest": (
                    hmac.new(
                        material,
                        b"iam-lifecycle-reason-note-v1\x00"
                        + note.encode("utf-8"),
                        hashlib.sha256,
                    ).hexdigest()
                    if note is not None
                    else None
                ),
            },
        )
        for key_id, material in keys.payload_hash_keyring
    )


def _require_recent_mfa(actor: InvitationIssuerContext, now: datetime) -> None:
    if (
        actor.session_id is None
        or actor.acr_code not in _MFA_ACR_CODES
        or _MFA_AMR_CODES.isdisjoint(actor.amr_codes)
        or actor.auth_time > now
        or now - actor.auth_time >= _MFA_WINDOW
    ):
        raise IamError("MFA_STEP_UP_REQUIRED")


def _lifecycle_target(command: Any) -> str:
    if isinstance(command, RevokeAccessInvitationCommand):
        return command.invitation_id
    if isinstance(command, (SuspendMembershipCommand, ResumeMembershipCommand, RevokeMembershipCommand)):
        return command.membership_id
    raise IamError("INVALID_REQUEST")


def _mask_email(value: str) -> str:
    normalized = value.strip().casefold()
    local, separator, domain = normalized.partition("@")
    if not separator or not local or not domain or len(normalized) > 254:
        raise IamError("INVALID_REQUEST")
    masked = f"{local[0]}***@{domain}"
    if len(masked) > 80:
        masked = f"{local[0]}***@masked.invalid"
    return masked


def _new(source: OrganizationAdminIdSource, purpose: str) -> UUID:
    value = source.new_id(purpose)
    if isinstance(value, UUID) and value.int:
        return value
    try:
        parsed = UUID(str(value))
    except (TypeError, ValueError, AttributeError):
        raise IamError("SERVICE_UNAVAILABLE") from None
    if not parsed.int:
        raise IamError("SERVICE_UNAVAILABLE")
    return parsed


def _uuid(value: Any, label: str) -> UUID:
    try:
        parsed = value if isinstance(value, UUID) else UUID(str(value))
    except (TypeError, ValueError, AttributeError):
        raise IamError("INVALID_REQUEST") from None
    if not parsed.int:
        raise IamError("INVALID_REQUEST")
    return parsed


def _utc(value: Any) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None or value.utcoffset().total_seconds() != 0:
        raise IamError("SERVICE_UNAVAILABLE")
    return value


def _timestamp(value: datetime) -> str:
    return _utc(value).isoformat().replace("+00:00", "Z")


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode((value + "=" * (-len(value) % 4)).encode("ascii"))


__all__ = [
    "HmacOrganizationInvitationTokenCodec",
    "InternalSandboxMembershipResumeSafetyHold",
    "InternalSandboxOrganizationInvitationIssueSafetyHold",
    "OrganizationAdminKeys",
    "PostgresIssueOrganizationAccessInvitationHandler",
    "PostgresResumeMembershipHandler",
    "PostgresRevokeAccessInvitationHandler",
    "PostgresRevokeMembershipHandler",
    "PostgresSuspendMembershipHandler",
]
